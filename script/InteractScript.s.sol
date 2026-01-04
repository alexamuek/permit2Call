// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import "../lib/forge-std/src/StdJson.sol";
import "../src/Predicter.sol";
import "../src/MockOracle.sol";
import "../src/MockERC20.sol";

/// Deploy and init actions
contract InteractScript is Script {
    using stdJson for string;

    bytes32 public constant _TOKEN_PERMISSIONS_TYPEHASH = keccak256("TokenPermissions(address token,uint256 amount)");
    bytes32 public constant _PERMIT_TRANSFER_FROM_TYPEHASH = keccak256(
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
    );

    function getPermitTransferSignature(
        ISignatureTransfer.PermitTransferFrom memory permit,
        uint256 privateKey,
        bytes32 domainSeparator,
        address _predicter
    ) internal view returns (bytes memory sig) {
        bytes32 tokenPermissions = keccak256(abi.encode(_TOKEN_PERMISSIONS_TYPEHASH, permit.permitted));
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        _PERMIT_TRANSFER_FROM_TYPEHASH, tokenPermissions, _predicter, permit.nonce, permit.deadline
                    )
                )
            )
        );
        console2.log('msgHash');
        console2.logBytes32(msgHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        return bytes.concat(r, s, bytes1(v));
    }

    function run() public {
        console2.log("Chain id: %s", vm.toString(block.chainid));
        
        MockERC20 token = MockERC20(0xa9b1a94d8ddBa49193e50174D4f87ee108F5e4cD);
        MockOracle oracle = MockOracle(0x60c0A71A991aAe273c4ACD017Bb03d4FfdFb4996);
        Predicter predicter = Predicter(0xC0A672740b2b2Da1CC8fA4BefaFcaF4901e42A42);

        uint256 strikeAmount = 1 ether; 
        address predictionCreator = 0xf315B9006C20913D6D8498BDf657E778d4Ddf2c4; 
        uint256  fromPrivateKey = vm.envUint("DEV_PRIVATE_KEY");
        bool agreeVote = true;
        uint256 permitNonce = 4; //change nonce
        uint256 expiration = uint256(block.timestamp + 365 days);

        /*
        // create prediction
        vm.startBroadcast();
        uint96 strikeAmount96 = 1 ether; 
        uint96 predictedAmount96 = 100;
        uint96 portfolioAmount96 = 1 ether;
        CompactAsset[] memory portfolio = new CompactAsset[](1);
        portfolio[0] = CompactAsset({token: address(token), amount: portfolioAmount96});
        Predicter.Prediction memory newPrediction = Predicter.Prediction(
            CompactAsset(address(token), strikeAmount96), 
            CompactAsset(address(token), predictedAmount96), 
            uint40(block.timestamp + 36000000), 
            0, 
            portfolio
        );
        predicter.createPrediction(newPrediction);
        vm.stopBroadcast();*/


        vm.startBroadcast();
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: address(token),
                amount: strikeAmount 
            }),
            nonce: permitNonce,
            deadline: 4359431218 
        });

        ISignatureTransfer.SignatureTransferDetails memory transferDetails = ISignatureTransfer.SignatureTransferDetails({
            to: address(predicter),         
            requestedAmount: strikeAmount   
        });

        bytes32 DOMAIN_SEPARATOR = 0x8a6e6e19bdfb3db3409910416b47c2f8fc28b49488d6555c7fceaa4479135bc3;
        console2.log('DOMAIN_SEPARATOR');
        console2.logBytes32(DOMAIN_SEPARATOR);
        bytes memory signature = getPermitTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR, address(predicter));
        
        predicter.voteWithPermit2(
            predictionCreator,
            true,
            permit,
            transferDetails,
            signature
        );
        vm.stopBroadcast();   

    }
}

//to run vote with permit2
/*forge script script/InteractScript.s.sol:InteractScript --rpc-url arbitrum  --account secret2 --sender 0x5992Fe461F81C8E0aFFA95b831E50e9b3854BA0E --broadcast -vvvv*/




