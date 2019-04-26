pragma solidity ^0.4.7;

// 多重签名（钱包交易）
contract MultiSigWallet{
	// 交易发起者
    address private owner;
	// 签名者
    mapping (address => uint8) private managers;
	
	// 判断权限
    modifier isOwner{
        require(owner == msg.sender);
        _;
    }

    modifier isManager{
        require(
            msg.sender == owner || managers[msg.sender] == 1);
        _;
    }
    
	// 最少需要集齐3个签名数量
    uint constant MIN_SIGNATURES = 3;
	// 交易所引
    uint private transactionIdx;
	
	// 交易结构
    struct Transaction {
		// 发起者
        address from;
		// 接受者
        address to;
		// 转账数量
        uint amount;
		// 签名数量
        uint8 signatureCount;
		// 签名详情
        mapping (address => uint8) signatures;
    }
    
	// 交易字典（交易ID-> tx）
    mapping (uint => Transaction) private transactions;
	// pending队列中的交易列表
    uint[] private pendingTransactions;
    
    constructor() public{
        owner = msg.sender;
    }
    
    event DepositFunds(address from, uint amount);
    event TransferFunds(address to, uint amount);
	
	// 创建交易事件
    event TransactionCreated(
        address from,
        address to,
        uint amount,
        uint transactionId
        );
    
    function addManager(address manager) public isOwner{
        managers[manager] = 1;
    }
    
    function removeManager(address manager) public isOwner{
        managers[manager] = 0;
    }
    
    function () public payable{
		// 触发预转账事件（尚未签名）
        emit DepositFunds(msg.sender, msg.value);
    }
    
	// 发起交易入口
    function withdraw(uint amount) isManager public{
        transferTo(msg.sender, amount);
    }
	// 发起交易的实现
    function transferTo(address to,  uint amount) isManager public{
        require(address(this).balance >= amount);
        uint transactionId = transactionIdx++;
        
        Transaction memory transaction;
        transaction.from = msg.sender;
        transaction.to = to;
        transaction.amount = amount;
		// 此时签名数量为0
        transaction.signatureCount = 0;
        transactions[transactionId] = transaction;
        pendingTransactions.push(transactionId);
		// 交易创建事件
        emit TransactionCreated(msg.sender, to, amount, transactionId);
    }
    
	// 获取pengding队列中的交易列表
    function getPendingTransactions() public isManager view returns(uint[]){
        return pendingTransactions;
    }
    
	// 签名（入参 交易ID）
    function signTransaction(uint transactionId) public isManager{
        Transaction storage transaction = transactions[transactionId];
        require(0x0 != transaction.from);
        require(msg.sender != transaction.from);
        require(transaction.signatures[msg.sender]!=1);
        transaction.signatures[msg.sender] = 1;
        transaction.signatureCount++;
        
		// 如果符合条件就放行
        if(transaction.signatureCount >= MIN_SIGNATURES){
            require(address(this).balance >= transaction.amount);
			// 放行 转账 执行交易
            transaction.to.transfer(transaction.amount);
			// 触发转账成功事件
            emit TransferFunds(transaction.to, transaction.amount);
			// 将此笔交易从pending队列中移除
            deleteTransactions(transactionId);
        }
    }
    
	// 移除交易
    function deleteTransactions(uint transacionId) public isManager{
        uint8 replace = 0;
        for(uint i = 0; i< pendingTransactions.length; i++){
            if(1==replace){
                pendingTransactions[i-1] = pendingTransactions[i];
            }else if(transacionId == pendingTransactions[i]){
                replace = 1;
            }
        } 
        delete pendingTransactions[pendingTransactions.length - 1];
        pendingTransactions.length--;
        delete transactions[transacionId];
    }
    
    function walletBalance() public isManager view returns(uint){
        return address(this).balance;
    }
}
