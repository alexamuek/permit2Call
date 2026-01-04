// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./interfaces/IEnvelopOracle.sol";
// Моковый оракул для симуляции цен
contract MockOracle is IEnvelopOracle {
    uint256 public price;

    function setPrice(uint256 _price) external {
        price = _price;
    }

    function getIndexPrice(address) external pure override returns (uint256) {
        return 0; // Для этого метода возвращаем 0, так как он не используется в данном тесте
    }

    function getIndexPrice(CompactAsset[] calldata _portfolio)
        external
        view
        override
        returns (uint256)
    {
        // Если есть элементы в портфолио, добавляем их сумму к базовой цене
        if (_portfolio.length > 0) {
            return price + _portfolio[0].amount;
        }
        return price; // Иначе возвращаем базовую цену
    }
}