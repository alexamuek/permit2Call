// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Моковый ERC20 токен для тестирования
contract MockERC20 is ERC20 {
    constructor() ERC20("Mock", "MOCK") {
        _mint(msg.sender, 1e27); // Минтим много токенов для инициатора
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount); // Функция для минтать токенов любому адресу
    }
}