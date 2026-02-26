// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/**
 * @title VulnerableBank - 一个存在重入漏洞的银行合约
 * @notice 这个合约仅用于教育目的，展示经典的重入攻击漏洞
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;
    
    // 存款函数
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // 取款函数 - 存在重入漏洞！
    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        
        // 漏洞：在更新状态之前进行外部调用
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");
        
        // 状态更新在外部调用之后 - 这是问题所在！
        balances[msg.sender] -= _amount;
    }
}