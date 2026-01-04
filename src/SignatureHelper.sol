//import "../lib/forge-std/src/StdJson.sol";
import "./interfaces/ISignatureTransfer.sol";
import "./interfaces/IEIP712.sol";
import "forge-std/Test.sol";

contract SignatureHelper is Test {

	bytes32 public constant _TOKEN_PERMISSIONS_TYPEHASH = keccak256("TokenPermissions(address token,uint256 amount)");
    bytes32 public constant _PERMIT_TRANSFER_FROM_TYPEHASH = keccak256(
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
    );

    //bytes32 public DOMAIN_SEPARATOR = 0x8a6e6e19bdfb3db3409910416b47c2f8fc28b49488d6555c7fceaa4479135bc3;

    function getPermitTransferSignature(
        ISignatureTransfer.PermitTransferFrom memory permit,
        uint256 privateKey,
        address spender,
        address permit2
    ) internal view returns (bytes memory sig) {
        bytes32 DOMAIN_SEPARATOR = IEIP712(permit2).DOMAIN_SEPARATOR();
        bytes32 tokenPermissions = keccak256(abi.encode(_TOKEN_PERMISSIONS_TYPEHASH, permit.permitted));
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        _PERMIT_TRANSFER_FROM_TYPEHASH, tokenPermissions, spender, permit.nonce, permit.deadline
                    )
                )
            )
        );
        console2.log('msgHash');
        console2.logBytes32(msgHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        return bytes.concat(r, s, bytes1(v));
    }
}