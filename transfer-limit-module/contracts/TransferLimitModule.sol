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

    function isOwner(address owner)
        external
        view
        returns (bool);
}

contract TransferLimitModule is SignatureDecoder, ISignatureValidatorConstants {

    string public constant NAME = "Transfer Limit Module";
    string public constant VERSION = "0.1.0";

    //keccak256(
    //    "EIP712Domain(address verifyingContract)"
    //);
    bytes32 public constant DOMAIN_SEPARATOR_TYPEHASH = 0x035aff83d86937d35b32e04f0ddc6ff469290eef2f1b692d8a815c89404d4749;

    // TODO: Fix hardcode hash
    bytes32 public constant LIMIT_TRANSFER_TYPEHASH = keccak256(
        "LimitTransfer(address safe,address token,uint96 amount,address paymentToken,uint96 payment,uint16 nonce)"
    );

    // dailyLimits mapping maps token address to daily limit settings.
    mapping(address => mapping (address => Limit)) public limitDetails;
    mapping(address => address[]) public tokens;
    mapping(address => mapping (uint48 => Delegate)) public delegates;
    mapping(address => uint48) public delegatesStart;
    bytes32 public domainSeparator;

    struct Delegate {
        address delegate;
        uint48 prev;
        uint48 next;
    }

    struct Limit {
        uint96 amount;
        uint96 spent;
        uint16 resetTimeMin; // reset time span is 65k minutes
        uint32 lastResetMin;
        uint16 nonce;
    }

    event AddDelegate(address account, address delegate);
    event RemoveDelegate(address account, address delegate);
    event ExecuteLimitTransfer(address account, address token, address to, uint96 value);
    event SetLimit(address account, address token, uint96 limitAmount, uint16 resetTime);

    constructor() public {
        domainSeparator = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, this));
        // 1 572 085 200
        // 4.133.894.400 seconds => 68.898.240 min
    }

    /// @dev Allows to update the limit for a specified token. This can only be done via a Safe transaction.
    /// @param token Token contract address.
    /// @param limitAmount Limit in smallest token unit.
    /// @param resetTimeMin Time after which the limit should reset
    function setLimit(address token, uint96 limitAmount, uint16 resetTimeMin)
        public
    {
        require(resetTimeMin > 0, "resetTimeMin > 0");
        Limit memory limit = getLimit(msg.sender, token);
        if (limit.resetTimeMin == 0) { // New token
            // solium-disable-next-line security/no-block-members
            limit.lastResetMin = uint32(now / 60);
            tokens[msg.sender].push(token);
        }
        limit.resetTimeMin = resetTimeMin;
        limit.amount = limitAmount;
        updateLimit(msg.sender, token, limit);
        emit SetLimit(msg.sender, token, limitAmount, resetTimeMin);
    }

    function getLimit(address account, address token) private view returns (Limit memory limit) {
        limit = limitDetails[account][token];
        // solium-disable-next-line security/no-block-members
        uint32 currentMin = uint32(now / 60);
        if (limit.lastResetMin <= currentMin - limit.resetTimeMin) {
            limit.spent = 0;
            limit.lastResetMin = currentMin;
        }
        return limit;
    }

    function updateLimit(address account, address token, Limit memory limit) private {
        limitDetails[account][token] = limit;
    }

    function resetLimit(address token) public {
        Limit memory limit = getLimit(msg.sender, token);
        limit.spent = 0;
        updateLimit(msg.sender, token, limit);
    }

    function executeLimitTransfer(
        GnosisSafe safe,
        address token,
        address payable to,
        uint96 amount,
        address paymentToken,
        uint96 payment,
        bytes memory signature
    ) public {
        // Get current state
        Limit memory limit = getLimit(address(safe), token);
        bytes memory transferHashData = generateTransferHashData(address(safe), token, to, amount, paymentToken, payment, limit.nonce);
        // Update state
        limit.nonce = limit.nonce + 1;
        uint96 newSpent = limit.spent + amount;
        // Check new spent amount and overflow
        require(newSpent > limit.spent && newSpent <= limit.amount, "newSpent > limit.spent && newSpent <= limit.amount");
        limit.spent = newSpent;
        if (payment > 0) {
            // Use updated limit if token and paymentToken are the same
            Limit memory paymentLimit = paymentToken == token ? limit : getLimit(address(safe), paymentToken);
            newSpent = paymentLimit.spent + payment;
            // Check new spent amount and overflow
            require(newSpent > paymentLimit.spent && newSpent <= paymentLimit.amount, "newSpent > paymentLimit.spent && newSpent <= paymentLimit.amount");
            paymentLimit.spent = newSpent;
            // Update payment limit if different from limit
            if (paymentToken != token) updateLimit(address(safe), paymentToken, paymentLimit);
        }
        updateLimit(address(safe), token, limit);
        // Check signature (this contains a potential call -> EIP-1271)
        checkSignature(signature, transferHashData, safe);
        // Perform
        if (payment > 0) {
            // Transfer payment
            // solium-disable-next-line security/no-tx-origin
            transfer(safe, paymentToken, tx.origin, payment);
        }
        // Transfer token
        transfer(safe, token, to, amount);
        emit ExecuteLimitTransfer(address(safe), token, to, amount);
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
        bytes32 transferLimitHash = keccak256(
            abi.encode(LIMIT_TRANSFER_TYPEHASH, safe, token, to, amount, paymentToken, payment, nonce)
        );
        return abi.encodePacked(byte(0x19), byte(0x01), domainSeparator, transferLimitHash);
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

    function checkSignature(bytes memory signature, bytes memory transferHashData, GnosisSafe safe) private {
        address signer = recoverSignature(signature, transferHashData);
        require(
            delegates[address(safe)][uint48(signer)].delegate == signer || safe.isOwner(signer),
            "delegates[msg.sender][uint48(signer)].delegate == signer || safe.isOwner(signer)"
        );
    }

    function recoverSignature(bytes memory signature, bytes memory transferHashData) private returns (address owner) {
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
            owner = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", transferHashData)), v - 4, r, s);
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

    function getTokens(address account) public view returns (address[] memory) {
        return tokens[account];
    }

    function getTokenLimit(address account, address token) public view returns (uint256[5] memory) {
        Limit memory limit = getLimit(account, token);
        return [
            uint256(limit.amount),
            uint256(limit.spent),
            uint256(limit.resetTimeMin),
            uint256(limit.lastResetMin),
            uint256(limit.nonce)
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
        delegates[msg.sender][current.prev].next = current.next;
        delegates[msg.sender][current.next].prev = current.prev;
        emit RemoveDelegate(msg.sender, delegate);
    }

    function getDelegates(address account, uint48 start, uint8 pageSize) public view returns (address[] memory results, uint48 next) {
        results = new address[](pageSize);
        uint8 i = 0;
        uint48 initialIndex = (start != 0) ? start : delegatesStart[account];
        Delegate memory current = delegates[account][initialIndex];
        while(current.delegate != address(0) && i < pageSize) {
            results[i] = current.delegate;
            i++;
            current = delegates[account][current.next];
        }
        next = uint48(current.delegate);
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            mstore(results, i)
        }
    }
}