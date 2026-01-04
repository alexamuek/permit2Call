//import "../lib/forge-std/src/StdJson.sol";
import "./interfaces/ISignatureTransfer.sol";
import "./interfaces/IEIP712.sol";

contract SignatureHelper {

	bytes32 public constant _TOKEN_PERMISSIONS_TYPEHASH = keccak256("TokenPermissions(address token,uint256 amount)");
    bytes32 public constant _PERMIT_TRANSFER_FROM_TYPEHASH = keccak256(
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
    );

    function getDomainSeparator(address permit2) public view returns (bytes32 domainSeparator) {
        domainSeparator = IEIP712(permit2).DOMAIN_SEPARATOR();
    }

    function getPermitDigest(
        ISignatureTransfer.PermitTransferFrom memory permit,
        address spender,
        address permit2
    ) public view returns (bytes32 msgHash) {
        bytes32 DOMAIN_SEPARATOR = getDomainSeparator(permit2);
        bytes32 tokenPermissions = keccak256(abi.encode(_TOKEN_PERMISSIONS_TYPEHASH, permit.permitted));
        msgHash = keccak256(
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
    }
}