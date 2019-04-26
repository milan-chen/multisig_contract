#include <eosio.msig/eosio.msig.hpp>
#include <eosiolib/action.hpp>
#include <eosiolib/permission.hpp>
#include <eosiolib/crypto.hpp>

// eos 多重签名(提案)合约 v1.6.0
namespace eosio {

time_point current_time_point() {
   const static time_point ct{ microseconds{ static_cast<int64_t>( current_time() ) } };
   return ct;
}

// 发起提案
void multisig::propose( ignore<name> proposer, ignore<name> proposal_name, ignore<std::vector<permission_level>> requested, ignore<transaction> trx ) {
   name _proposer; // 提案人
   name _proposal_name; // 提案名称
   std::vector<permission_level> _requested; // 提案通过所需权限
   transaction_header _trx_header; // 提案交易的具体内容

   _ds >> _proposer >> _proposal_name >> _requested;

   // 解析input参数
   const char* trx_pos = _ds.pos();
   size_t size    = _ds.remaining();
   _ds >> _trx_header;

   // 检查调用者是否有所指定的`proposer`的权限，大部分action都会做类似的检查
   require_auth( _proposer );
   check( _trx_header.expiration >= eosio::time_point_sec(current_time_point()), "transaction expired" );
   //check( trx_header.actions.size() > 0, "transaction must have at least one action" );
	
   // 创建proptable，用于存储提案的相关信息
   proposals proptable( _self, _proposer.value );
   // 不能同名
   check( proptable.find( _proposal_name.value ) == proptable.end(), "proposal with the same name exists" );

   // 检查请求的权限是否可以满足
   auto packed_requested = pack(_requested);
   auto res = ::check_transaction_authorization( trx_pos, size, (const char*)0, 0, packed_requested.data(), packed_requested.size());
   check( res > 0, "transaction authorization failed" );

   std::vector<char> pkd_trans;
   pkd_trans.resize(size);
   memcpy((char*)pkd_trans.data(), trx_pos, size);
   // 存储提案的名字和提案中交易的信息
   proptable.emplace( _proposer, [&]( auto& prop ) {
      prop.proposal_name       = _proposal_name;
      prop.packed_transaction  = pkd_trans;
   });
   // approvals有两个表，记录了提案的审批状态
   approvals apptable(  _self, _proposer.value );
   apptable.emplace( _proposer, [&]( auto& a ) {
      a.proposal_name       = _proposal_name;
	  // requested_approvals表记录了未审批状态
      a.requested_approvals.reserve( _requested.size() );
      for ( auto& level : _requested ) {
         a.requested_approvals.push_back( approval{ level, time_point{ microseconds{0} } } );
      }
   });
}

// 通过提案
void multisig::approve( name proposer, name proposal_name, permission_level level, const eosio::binary_extension<eosio::checksum256>& proposal_hash )  {
   require_auth( level );
	
   // 验证提案的合法性
   if( proposal_hash ) {
      proposals proptable( _self, proposer.value );
      auto& prop = proptable.get( proposal_name.value, "proposal not found" );
	  // 提案hash的算法
      assert_sha256( prop.packed_transaction.data(), prop.packed_transaction.size(), *proposal_hash );
   }

   approvals apptable(  _self, proposer.value );
   auto apps_it = apptable.find( proposal_name.value );
   if ( apps_it != apptable.end() ) {
      auto itr = std::find_if( apps_it->requested_approvals.begin(), apps_it->requested_approvals.end(), [&](const approval& a) { return a.level == level; } );
      check( itr != apps_it->requested_approvals.end(), "approval is not on the list of requested approvals" );

      apptable.modify( apps_it, proposer, [&]( auto& a ) {
		    // provided_approvals表记录了已审批状态的提案
            a.provided_approvals.push_back( approval{ level, current_time_point() } );
            a.requested_approvals.erase( itr );
         });
   } else {
      old_approvals old_apptable(  _self, proposer.value );
      auto& apps = old_apptable.get( proposal_name.value, "proposal not found" );

      auto itr = std::find( apps.requested_approvals.begin(), apps.requested_approvals.end(), level );
      check( itr != apps.requested_approvals.end(), "approval is not on the list of requested approvals" );

      old_apptable.modify( apps, proposer, [&]( auto& a ) {
            a.provided_approvals.push_back( level );
            a.requested_approvals.erase( itr );
         });
   }
}

// 不通过提案
void multisig::unapprove( name proposer, name proposal_name, permission_level level ) {
   require_auth( level );

   approvals apptable(  _self, proposer.value );
   auto apps_it = apptable.find( proposal_name.value );
   if ( apps_it != apptable.end() ) {
	  // 查找 provided_approvals 表中通过的权限中，是否有和传入permission匹配项。
	  // 若有匹配项，将此权限加入requested_approvals 表，即表示该权限还没通过此提案，并从 provided_approvals 表中移除该权限。
      auto itr = std::find_if( apps_it->provided_approvals.begin(), apps_it->provided_approvals.end(), [&](const approval& a) { return a.level == level; } );
      check( itr != apps_it->provided_approvals.end(), "no approval previously granted" );
      apptable.modify( apps_it, proposer, [&]( auto& a ) {
            a.requested_approvals.push_back( approval{ level, current_time_point() } );
            a.provided_approvals.erase( itr );
         });
   } else {
      old_approvals old_apptable(  _self, proposer.value );
      auto& apps = old_apptable.get( proposal_name.value, "proposal not found" );
      auto itr = std::find( apps.provided_approvals.begin(), apps.provided_approvals.end(), level );
      check( itr != apps.provided_approvals.end(), "no approval previously granted" );
      old_apptable.modify( apps, proposer, [&]( auto& a ) {
            a.requested_approvals.push_back( level );
            a.provided_approvals.erase( itr );
         });
   }
}

// 取消提案
void multisig::cancel( name proposer, name proposal_name, name canceler ) {
   require_auth( canceler );

   proposals proptable( _self, proposer.value );
   auto& prop = proptable.get( proposal_name.value, "proposal not found" );
   // 首先，先查找表获取提案内容。如果canceler账户和提案账户不同，则在提案交易过期之前，canceler都不能取消提案。
   if( canceler != proposer ) {
      check( unpack<transaction_header>( prop.packed_transaction ).expiration < eosio::time_point_sec(current_time_point()), "cannot cancel until expiration" );
   }
   proptable.erase(prop);
	
   // 能取消，将提案从表中移除。
   //remove from new table
   approvals apptable(  _self, proposer.value );
   auto apps_it = apptable.find( proposal_name.value );
   if ( apps_it != apptable.end() ) {
      apptable.erase(apps_it);
   } else {
      old_approvals old_apptable(  _self, proposer.value );
      auto apps_it = old_apptable.find( proposal_name.value );
      check( apps_it != old_apptable.end(), "proposal not found" );
      old_apptable.erase(apps_it);
   }
}

// 执行提案
void multisig::exec( name proposer, name proposal_name, name executer ) {
   // 执行帐户executer
   require_auth( executer );

   proposals proptable( _self, proposer.value );
   auto& prop = proptable.get( proposal_name.value, "proposal not found" );
   transaction_header trx_header;
   datastream<const char*> ds( prop.packed_transaction.data(), prop.packed_transaction.size() );
   ds >> trx_header;
   // 首先，需要做前置检查，检查交易是否过期
   check( trx_header.expiration >= eosio::time_point_sec(current_time_point()), "transaction expired" );

   approvals apptable(  _self, proposer.value );
   // 查询 provided_approvals 表获取通过提案交易的权限们，对比 inv_table 表，如果权限不在 inv_table 表中或者 last_invalidation_time 
   // 已经小于当前时间，代表权限有效，放入approvals表中。inv_table 表的用途在下一个invalidate方法中介绍
   auto apps_it = apptable.find( proposal_name.value );
   std::vector<permission_level> approvals;
   invalidations inv_table( _self, _self.value );
   if ( apps_it != apptable.end() ) {
      approvals.reserve( apps_it->provided_approvals.size() );
      for ( auto& p : apps_it->provided_approvals ) {
         auto it = inv_table.find( p.level.actor.value );
         if ( it == inv_table.end() || it->last_invalidation_time < p.time ) {
            approvals.push_back(p.level);
         }
      }
      apptable.erase(apps_it);
   } else {
      old_approvals old_apptable(  _self, proposer.value );
      auto& apps = old_apptable.get( proposal_name.value, "proposal not found" );
      for ( auto& level : apps.provided_approvals ) {
         auto it = inv_table.find( level.actor.value );
         if ( it == inv_table.end() ) {
            approvals.push_back( level );
         }
      }
      old_apptable.erase(apps);
   }
   // 最后，执行提案。
   auto packed_provided_approvals = pack(approvals);
   auto res = ::check_transaction_authorization( prop.packed_transaction.data(), prop.packed_transaction.size(),
                                                 (const char*)0, 0,
                                                 packed_provided_approvals.data(), packed_provided_approvals.size()
                                                 );
   check( res > 0, "transaction authorization failed" );
   // 如果交易执行权限检验无误，会发起一个defer延迟合约，去执行提案交易。
   send_deferred( (uint128_t(proposer.value) << 64) | proposal_name.value, executer.value,
                  prop.packed_transaction.data(), prop.packed_transaction.size() );

   proptable.erase(prop);
}

// 撤回对之前所有该账户通过、但未被最终执行的提案的通过授权
// 如果account之前通过的提案还未执行，就可以使用该方法将提案一键设置为无效。
// 这个方法主要是解决：账户权限变更时，之前通过但未执行的提案一旦执行会盗取账户权限的问题，详见issue: https://github.com/EOSIO/eosio.contracts/issues/53
void multisig::invalidate( name account ) {
   require_auth( account );
   // inv_table 是用来存放权限的，它的两个字段 account 和last_invalidation_time 分别是账户名和账户权限最近失效时间。
   // last_invalidation_time 时间之前，account的提案批准权限都不可用，在该时间之后account的提案批准权限才能生效。
   // 因此，如果想使account之前审批通过的所有提案都失效的话，就将 last_invalidation_time 设置为当前时间即可。
   // exec方法在执行之前会检查 inv_table，则包含在 inv_table 中的account，即便批准了该提案，该批准也会作废。
   invalidations inv_table( _self, _self.value );
   auto it = inv_table.find( account.value );
   if ( it == inv_table.end() ) {
      inv_table.emplace( account, [&](auto& i) {
            i.account = account;
            i.last_invalidation_time = current_time_point();
         });
   } else {
      inv_table.modify( it, account, [&](auto& i) {
            i.last_invalidation_time = current_time_point();
         });
   }
}

} /// namespace eosio

EOSIO_DISPATCH( eosio::multisig, (propose)(approve)(unapprove)(cancel)(exec)(invalidate) )