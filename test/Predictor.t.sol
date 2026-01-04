// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console2.sol"; 

import "../src/Predicter.sol";
import "../src/MockOracle.sol";
import "../src/MockERC20.sol";
// ВОЗВРАЩАЕМ ИМПОРТ:
import "../src/interfaces/ISignatureTransfer.sol"; 
import "../src/interfaces/IEnvelopOracle.sol";

// Интерфейс для получения DOMAIN_SEPARATOR из Permit2
interface IYUPermit2 {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

contract PredicterTest_fork_1 is Test {
    MockERC20 internal token;
    MockOracle internal oracle; 
    Predicter internal predicter;

    uint256 public constant userYesPrKey = 0x1bbde125e133d7b485f332b8125b891ea2fbb6a957e758db72e6539d46e2cd71;
    address public constant userYes = 0x7EC0BF0a4D535Ea220c6bD961e352B752906D568; 
    address internal creator = address(0xC0FFEE);
    address internal feeBeneficiary = address(0xFEEBEEF);
    
    IYUPermit2 public permit2;

    // ПРОВЕРЯЕМ СТРОКИ TYPEHASH:
    bytes32 internal constant TOKEN_PERMISSIONS_TYPEHASH = keccak256("TokenPermissions(address token,uint256 amount)");
    bytes32 internal constant PERMIT_TRANSFER_FROM_TYPEHASH = keccak256("PermitTransferFrom(TokenPermissions permitted,uint256 nonce,uint48 deadline)");
    
    // Добавление логов для проверки строк TYPEHASH
    string internal constant TOKEN_PERMISSIONS_TYPEHASH_STR = "TokenPermissions(address token,uint256 amount)";
    string internal constant PERMIT_TRANSFER_FROM_TYPEHASH_STR = "PermitTransferFrom(TokenPermissions permitted,uint256 nonce,uint48 deadline)";

    uint256 internal constant SECP256K1_N_HALF = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    uint48 internal predictionExpirationTime; 

    function setUp() public {
        vm.roll(block.timestamp + 100); 

        token = new MockERC20();
        oracle = new MockOracle(); 
        predicter = new Predicter(feeBeneficiary, address(oracle)); 

        permit2 = IYUPermit2(predicter.PERMIT2());
        
        vm.deal(userYes, 1 ether); 
        vm.deal(creator, 1 ether);

        vm.startPrank(address(this)); 
        token.mint(userYes, 1_000 ether);
        vm.stopPrank();

        console2.log("Permit2 address: %s", vm.toString(address(permit2))); 
        console2.log("ChainId:", block.chainid); 
        console2.log("UserYes address: %s", vm.toString(userYes));         
        console2.log("Predicter address: %s", vm.toString(address(predicter))); 
        console2.log("MockERC20 address: %s", vm.toString(address(token)));   
        
        // Логирование используемых строк TYPEHASH
        console2.log("TOKEN_PERMISSIONS_TYPEHASH_STR:", TOKEN_PERMISSIONS_TYPEHASH_STR);
        console2.log("PERMIT_TRANSFER_FROM_TYPEHASH_STR:", PERMIT_TRANSFER_FROM_TYPEHASH_STR);


        vm.startPrank(userYes);
        token.approve(address(permit2), type(uint256).max); 
        vm.stopPrank();

        vm.startPrank(creator);
        Predicter.Prediction memory newPrediction = Predicter.Prediction(
            CompactAsset(address(token), 100 ether), 
            CompactAsset(address(token), 1500), 
            uint40(block.timestamp + 3600), 
            0, 
            new CompactAsset[](0)
        );
        predicter.createPrediction(newPrediction);
        vm.stopPrank();
        
        (,, uint40 tempExpirationTime, ) = predicter.predictions(creator); 
        predictionExpirationTime = uint48(tempExpirationTime); 
        console2.log("Prediction expirationTime:", predictionExpirationTime);
    }

    // Вспомогательная функция для хэширования TokenPermissions
    function _hashTokenPermissions(ISignatureTransfer.TokenPermissions memory tp)
        private
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                TOKEN_PERMISSIONS_TYPEHASH,
                tp.token,
                tp.amount
            )
        );
    }

    // Функция для хэширования PermitTransferFrom
    function _hashPermitTransferFrom(ISignatureTransfer.PermitTransferFrom memory permit_)
        private
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                PERMIT_TRANSFER_FROM_TYPEHASH,
                _hashTokenPermissions(permit_.permitted), // <-- Использование вспомогательной функции
                permit_.nonce,
                permit_.deadline
            )
        );
    }

    function _getEIP712Digest(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }


    function test_voteWithPermit2_success() public {
        uint256 strikeAmount = 100 ether; 
        address predictionCreator = creator; 
        bool agreeVote = true;

        vm.roll(block.timestamp + 60);

        uint256 permitNonce = 0; 

        // ИСПРАВЛЕНИЕ: Используем структуры из ISignatureTransfer.sol как положено
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: address(token),
                amount: strikeAmount 
            }),
            nonce: permitNonce,
            deadline: predictionExpirationTime 
        });

        ISignatureTransfer.SignatureTransferDetails memory transferDetails = ISignatureTransfer.SignatureTransferDetails({
            to: address(predicter),         
            requestedAmount: strikeAmount   
        });

        bytes32 domainSeparator = permit2.DOMAIN_SEPARATOR();        
        
        bytes32 structHash = _hashPermitTransferFrom(permit);
        
        bytes32 digest = _getEIP712Digest(domainSeparator, structHash);

        console2.log("Our Calculated structHash: %x", uint256(structHash)); 
        console2.log("Our Calculated digest to sign: %x", uint256(digest));       

        (uint8 v_raw, bytes32 r, bytes32 s) = vm.sign(userYesPrKey, digest);
        
        uint8 v = v_raw; 

        if (uint256(s) > SECP256K1_N_HALF) {
            s = bytes32(SECP256K1_N - uint256(s));
            v = (v == 27) ? 28 : 27; 
        }
        
        bytes memory signature = abi.encodePacked(r, s, v);
        
        uint256 initialUserTokenBalance = token.balanceOf(userYes);
        uint256 initialPredicterTokenBalance = token.balanceOf(address(predicter));
        uint256 initialYesTokenId = (uint256(uint160(predictionCreator)) << 96) | (agreeVote ? 1 : 0);
        uint256 initialUser6909Balance = predicter.balanceOf(userYes, initialYesTokenId);
        uint256 initialTotalYesSupply = predicter.totalSupply(initialYesTokenId);

        vm.startPrank(userYes);
        predicter.voteWithPermit2(
            predictionCreator,
            agreeVote,
            permit,
            transferDetails,
            signature
        );
        vm.stopPrank();

        assertEq(token.balanceOf(userYes), initialUserTokenBalance - strikeAmount, "User token balance should decrease");
        assertEq(token.balanceOf(address(predicter)), initialPredicterTokenBalance + strikeAmount, "Predicter token balance should increase");
        
        assertEq(predicter.balanceOf(userYes, initialYesTokenId), initialUser6909Balance + strikeAmount, "User should have minted ERC6909 tokens");
        assertEq(predicter.totalSupply(initialYesTokenId), initialTotalYesSupply + strikeAmount, "Total supply of yes tokens should increase");
    }
}
