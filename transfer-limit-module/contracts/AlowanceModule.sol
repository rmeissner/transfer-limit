pragma solidity >=0.5.0 <0.7.0;

import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";
import "@gnosis.pm/safe-contracts/contracts/common/SignatureDecoder.sol";
import "@gnosis.pm/safe-contracts/contracts/interfaces/ISignatureValidator.sol";

interface GnosisSafe {
    /// @dev Allows a Module to execute a Safe transaction without any further confirmations.
    /// @param to Destination address of module transaction.
    /// @param value Ether value of module transaction.
    /// @param data Data payload of module transaction.
    /// @param operation Operation type of module transaction.
    function execTransactionFromModule(address to, uint256 value, bytes calldata data, Enum.Operation operation)
        external
        returns (bool success);
}

contract AllowanceModule is SignatureDecoder, ISignatureValidatorConstants {

    string public constant NAME = "Allowance Module";
    string public constant VERSION = "0.1.0";

    //keccak256(
    //    "EIP712Domain(address verifyingContract)"
    //);
    bytes32 public constant DOMAIN_SEPARATOR_TYPEHASH = 0x035aff83d86937d35b32e04f0ddc6ff469290eef2f1b692d8a815c89404d4749;

    // TODO: Fix hardcode hash
    bytes32 public constant ALLOWANCE_TRANSFER_TYPEHASH = keccak256(
        "AllowanceTransfer(address safe,address token,uint96 amount,address paymentToken,uint96 payment,uint16 nonce)"
    );

    // Safe -> Delegate -> Allowance
    mapping(address => mapping (address => mapping(address => Allowance))) public allowances;
    mapping(address => mapping (address => address[])) public tokens;
    mapping(address => mapping (uint48 => Delegate)) public delegates;
    mapping(address => uint48) public delegatesStart;
    bytes32 public domainSeparator;

    struct Delegate {
        address delegate;
        uint48 prev;
        uint48 next;
    }

    struct Allowance {
        uint96 amount;
        uint96 spent;
        uint16 resetTimeMin; // reset time span is 65k minutes
        uint32 lastTransferMin;
        uint16 nonce;
    }

    event AddDelegate(address safe, address delegate);
    event RemoveDelegate(address safe, address delegate);
    event ExecuteAllowanceTransfer(address safe, address delegate, address token, address to, uint96 value);
    event SetAllowance(address safe, address delegate, address token, uint96 allowanceAmount, uint16 resetTime);

    constructor() public {
        domainSeparator = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, this));
    }

    /// @dev Allows to update the allowance for a specified token. This can only be done via a Safe transaction.
    /// @param delegate Delegate whose allowance should be updated.
    /// @param token Token contract address.
    /// @param allowanceAmount allowance in smallest token unit.
    /// @param resetTimeMin Time after which the allowance should reset
    function setAllowance(address delegate, address token, uint96 allowanceAmount, uint16 resetTimeMin)
        public
    {
        require(delegates[msg.sender][uint48(delegate)].delegate == delegate, "delegates[msg.sender][uint48(delegate)].delegate == delegate");
        Allowance memory allowance = getAllowance(msg.sender, delegate, token);
        if (allowance.nonce == 0) { // New token
            allowance.nonce = 1; // Nonce should never be 0 once allowance has been activated
            tokens[msg.sender][delegate].push(token);
        }
        allowance.resetTimeMin = resetTimeMin;
        allowance.amount = allowanceAmount;
        updateAllowance(msg.sender, delegate, token, allowance);
        emit SetAllowance(msg.sender, delegate, token, allowanceAmount, resetTimeMin);
    }

    function getAllowance(address safe, address delegate, address token) private view returns (Allowance memory allowance) {
        allowance = allowances[safe][delegate][token];
        // solium-disable-next-line security/no-block-members
        if (allowance.resetTimeMin > 0 && allowance.lastTransferMin <= uint32(now / 60) - allowance.resetTimeMin) {
            allowance.spent = 0;
        }
        return allowance;
    }

    function updateAllowance(address safe, address delegate, address token, Allowance memory allowance) private {
        allowances[safe][delegate][token] = allowance;
    }

    function resetAllowance(address delegate, address token) public {
        Allowance memory allowance = getAllowance(msg.sender, delegate, token);
        allowance.spent = 0;
        updateAllowance(msg.sender, delegate, token, allowance);
    }

    function executeAllowanceTransfer(
        GnosisSafe safe,
        address token,
        address payable to,
        uint96 amount,
        address paymentToken,
        uint96 payment,
        address delegate,
        bytes memory signature
    ) public {
        // Get current state
        Allowance memory allowance = getAllowance(address(safe), delegate, token);
        bytes memory transferHashData = generateTransferHashData(address(safe), token, to, amount, paymentToken, payment, allowance.nonce);
        // Update state
        allowance.nonce = allowance.nonce + 1;
        uint96 newSpent = allowance.spent + amount;
        // Check new spent amount and overflow
        require(newSpent > allowance.spent && newSpent <= allowance.amount, "newSpent > allowance.spent && newSpent <= allowance.amount");
        allowance.spent = newSpent;
        // solium-disable-next-line security/no-block-members
        allowance.lastTransferMin = uint32(now / 60);
        if (payment > 0) {
            // Use updated allowance if token and paymentToken are the same
            Allowance memory paymentAllowance = paymentToken == token ? allowance : getAllowance(address(safe), delegate, paymentToken);
            newSpent = paymentAllowance.spent + payment;
            // Check new spent amount and overflowf
            require(newSpent > paymentAllowance.spent && newSpent <= paymentAllowance.amount, "newSpent > paymentAllowance.spent && newSpent <= paymentAllowance.amount");
            paymentAllowance.spent = newSpent;
            // solium-disable-next-line security/no-block-members
            paymentAllowance.lastTransferMin = uint32(now / 60);
            // Update payment allowance if different from allowance
            if (paymentToken != token) updateAllowance(address(safe), delegate, paymentToken, paymentAllowance);
        }
        updateAllowance(address(safe), delegate, token, allowance);
        // Check signature (this contains a potential call -> EIP-1271)
        checkSignature(delegate, signature, transferHashData, safe);
        // Perform
        if (payment > 0) {
            // Transfer payment
            // solium-disable-next-line security/no-tx-origin
            transfer(safe, paymentToken, tx.origin, payment);
        }
        // Transfer token
        transfer(safe, token, to, amount);
        emit ExecuteAllowanceTransfer(address(safe), delegate, token, to, amount);
    }

    function generateTransferHashData(
        address safe,
        address token,
        address to,
        uint96 amount,
        address paymentToken,
        uint96 payment,
        uint16 nonce
    ) private view returns (bytes memory) {
        bytes32 transferHash = keccak256(
            abi.encode(ALLOWANCE_TRANSFER_TYPEHASH, safe, token, to, amount, paymentToken, payment, nonce)
        );
        return abi.encodePacked(byte(0x19), byte(0x01), domainSeparator, transferHash);
    }

    function generateTransferHash(
        address safe,
        address token,
        address to,
        uint96 amount,
        address paymentToken,
        uint96 payment,
        uint16 nonce
    ) public view returns (bytes32) {
        return keccak256(generateTransferHashData(
            safe, token, to, amount, paymentToken, payment, nonce
        ));
    }

    function checkSignature(address expectedDelegate, bytes memory signature, bytes memory transferHashData, GnosisSafe safe) private {
        address signer = recoverSignature(signature, transferHashData);
        require(
            expectedDelegate == signer && delegates[address(safe)][uint48(signer)].delegate == signer,
            "expectedDelegate == signer && delegates[address(safe)][uint48(signer)].delegate == signer"
        );
    }

    function recoverSignature(bytes memory signature, bytes memory transferHashData) private view returns (address owner) {
        // If there is no signature data msg.sender should be used
        if (signature.length == 0) return msg.sender;
        // Check that the provided signature data is not too short
        require(signature.length >= 65, "signatures.length >= 65");
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = signatureSplit(signature, 0);
        // If v is 0 then it is a contract signature
        if (v == 0) {
            // When handling contract signatures the address of the contract is encoded into r
            owner = address(uint256(r));
            bytes memory contractSignature;
            // solium-disable-next-line security/no-inline-assembly
            assembly {
                // The signature data for contract signatures is appended to the concatenated signatures and the offset is stored in s
                contractSignature := add(add(signature, s), 0x20)
            }
            require(
                ISignatureValidator(owner).isValidSignature(transferHashData, contractSignature) == EIP1271_MAGIC_VALUE,
                "Could not validate EIP-1271 signature"
            );
        } else if (v > 30) {
            // To support eth_sign and similar we adjust v and hash the transferHashData with the Ethereum message prefix before applying ecrecover
            owner = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(transferHashData))), v - 4, r, s);
        } else {
            // Use ecrecover with the messageHash for EOA signatures
            owner = ecrecover(keccak256(transferHashData), v, r, s);
        }
    }

    function transfer(GnosisSafe safe, address token, address payable to, uint96 amount) private {
        if (token == address(0)) {
            // solium-disable-next-line security/no-send
            require(safe.execTransactionFromModule(to, amount, "", Enum.Operation.Call), "Could not execute ether transfer");
        } else {
            bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", to, amount);
            require(safe.execTransactionFromModule(token, 0, data, Enum.Operation.Call), "Could not execute token transfer");
        }
    }

    function getTokens(address safe, address delegate) public view returns (address[] memory) {
        return tokens[safe][delegate];
    }

    function getTokenAllowance(address safe, address delegate, address token) public view returns (uint256[5] memory) {
        Allowance memory allowance = getAllowance(safe, delegate, token);
        return [
            uint256(allowance.amount),
            uint256(allowance.spent),
            uint256(allowance.resetTimeMin),
            uint256(allowance.lastTransferMin),
            uint256(allowance.nonce)
        ];
    }

    function addDelegate(address delegate) public {
        require(delegate != address(0), "Invalid delegate address");
        uint48 index = uint48(delegate);
        require(delegates[msg.sender][index].delegate == address(0), "Delegate already exists");
        uint48 startIndex = delegatesStart[msg.sender];
        delegates[msg.sender][index] = Delegate(delegate, 0, startIndex);
        delegates[msg.sender][startIndex].prev = index;
        delegatesStart[msg.sender] = index;
        emit AddDelegate(msg.sender, delegate);
    }

    function removeDelegate(address delegate) public {
        Delegate memory current = delegates[msg.sender][uint48(delegate)];
        require(current.delegate != address(0), "Delegate does not exists");
        address[] storage delegateTokens = tokens[msg.sender][delegate];
        for (uint256 i = 0; i < delegateTokens.length; i++) {
            address token = delegateTokens[i];
            // Set all allowance params except the nonce to 0
            Allowance memory allowance = getAllowance(msg.sender, delegate, token);
            allowance.amount = 0;
            allowance.spent = 0;
            allowance.resetTimeMin = 0;
            allowance.lastTransferMin = 0;
            updateAllowance(msg.sender, delegate, token, allowance);
        }
        delegates[msg.sender][current.prev].next = current.next;
        delegates[msg.sender][current.next].prev = current.prev;
        emit RemoveDelegate(msg.sender, delegate);
    }

    function getDelegates(address safe, uint48 start, uint8 pageSize) public view returns (address[] memory results, uint48 next) {
        results = new address[](pageSize);
        uint8 i = 0;
        uint48 initialIndex = (start != 0) ? start : delegatesStart[safe];
        Delegate memory current = delegates[safe][initialIndex];
        while(current.delegate != address(0) && i < pageSize) {
            results[i] = current.delegate;
            i++;
            current = delegates[safe][current.next];
        }
        next = uint48(current.delegate);
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            mstore(results, i)
        }
    }
}