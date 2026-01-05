// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

/**
 * @title SuirifyRegistry
 * @notice Registry for tracking EVM addresses that have created Sui-based SSI
 * @dev This contract stores the mapping between EVM addresses and their Sui identities
 */
contract SuirifyRegistry {
    struct SuiIdentity {
        bytes32 suiAddress;      // Sui address (32 bytes)
        uint256 chainId;         // EVM chain ID where registration occurred
        uint256 createdAt;       // Block timestamp
        bool isActive;           // Status flag
        bytes32 attestationId;   // Reference to Sui attestation
    }

    struct FeeStatus {
        bool paid;               // Whether fee paid for chainId
        uint256 amount;          // Amount paid (wei)
        uint256 paidAt;          // Block timestamp
    }
    
    /// @notice Mapping from EVM address to their Sui identity
    mapping(address => SuiIdentity) public identities;
    
    /// @notice Reverse mapping: Sui address to EVM address
    mapping(bytes32 => address) public suiToEvm;

    /// @notice Tracks fee payment per user per chain
    mapping(address => mapping(uint256 => FeeStatus)) public feePayments;

    /// @notice Fee configuration per chain
    mapping(uint256 => uint256) public feeByChain; // chainId => wei
    
    /// @notice Total number of registered identities
    uint256 public totalRegistrations;
    
    /// @notice Relayer address (authorized to register identities)
    address public relayer;

    /// @notice Treasury address for fee withdrawals
    address public treasury;
    
    /// @notice Events
    event IdentityRegistered(
        address indexed evmAddress,
        bytes32 indexed suiAddress,
        uint256 chainId,
        bytes32 attestationId
    );
    
    event IdentityRevoked(
        address indexed evmAddress,
        bytes32 indexed suiAddress
    );
    
    event RelayerUpdated(
        address indexed oldRelayer,
        address indexed newRelayer
    );

    event TreasuryUpdated(address indexed oldTreasury, address indexed newTreasury);

    event FeeSet(uint256 indexed chainId, uint256 amountWei);

    event FeePaid(
        address indexed payer,
        uint256 indexed chainId,
        uint256 amountWei,
        uint256 timestamp
    );
    
    /// @notice Errors
    error OnlyRelayer();
    error AlreadyRegistered();
    error NotRegistered();
    error InvalidAddress();
    error IncorrectFee();
    
    modifier onlyRelayer() {
        if (msg.sender != relayer) revert OnlyRelayer();
        _;
    }
    
    constructor(address _relayer, address _treasury) {
        if (_relayer == address(0)) revert InvalidAddress();
        if (_treasury == address(0)) revert InvalidAddress();
        relayer = _relayer;
        treasury = _treasury;
    }
    
    /**
     * @notice Configure fee for a specific chainId (in wei)
     */
    function setFee(uint256 chainId, uint256 amountWei) external onlyRelayer {
        feeByChain[chainId] = amountWei;
        emit FeeSet(chainId, amountWei);
    }

    /**
     * @notice Pay the mint/bridge fee for the given chainId
     */
    function payFee(uint256 chainId) external payable {
        uint256 requiredFee = feeByChain[chainId];
        if (requiredFee == 0 || msg.value < requiredFee) revert IncorrectFee();

        feePayments[msg.sender][chainId] = FeeStatus({
            paid: true,
            amount: msg.value,
            paidAt: block.timestamp
        });

        emit FeePaid(msg.sender, chainId, msg.value, block.timestamp);
    }

    /**
     * @notice Check if fee is paid for a user/chainId
     */
    function hasPaid(address user, uint256 chainId) external view returns (bool) {
        return feePayments[user][chainId].paid;
    }

    /**
     * @notice Withdraw collected fees to treasury
     */
    function withdrawFees(uint256 amount, address to) external onlyRelayer {
        address target = to == address(0) ? treasury : to;
        if (target == address(0)) revert InvalidAddress();
        (bool ok, ) = target.call{value: amount}("");
        require(ok, "Transfer failed");
    }

    /**
     * @notice Update treasury address
     */
    function updateTreasury(address newTreasury) external onlyRelayer {
        if (newTreasury == address(0)) revert InvalidAddress();
        address old = treasury;
        treasury = newTreasury;
        emit TreasuryUpdated(old, newTreasury);
    }
    
    /**
     * @notice Register a new EVM → Sui identity mapping
     * @param evmAddress The EVM address being registered
     * @param suiAddress The derived Sui address (32 bytes)
     * @param attestationId The Sui attestation object ID
     */
    function registerIdentity(
        address evmAddress,
        bytes32 suiAddress,
        bytes32 attestationId
    ) external onlyRelayer {
        if (evmAddress == address(0)) revert InvalidAddress();
        if (identities[evmAddress].isActive) revert AlreadyRegistered();
        
        identities[evmAddress] = SuiIdentity({
            suiAddress: suiAddress,
            chainId: block.chainid,
            createdAt: block.timestamp,
            isActive: true,
            attestationId: attestationId
        });
        
        suiToEvm[suiAddress] = evmAddress;
        totalRegistrations++;
        
        emit IdentityRegistered(
            evmAddress,
            suiAddress,
            block.chainid,
            attestationId
        );
    }
    
    /**
     * @notice Revoke an identity registration
     * @param evmAddress The EVM address to revoke
     */
    function revokeIdentity(address evmAddress) external onlyRelayer {
        SuiIdentity storage identity = identities[evmAddress];
        if (!identity.isActive) revert NotRegistered();
        
        bytes32 suiAddress = identity.suiAddress;
        identity.isActive = false;
        
        delete suiToEvm[suiAddress];
        
        emit IdentityRevoked(evmAddress, suiAddress);
    }
    
    /**
     * @notice Check if an EVM address has a registered identity
     */
    function hasIdentity(address evmAddress) external view returns (bool) {
        return identities[evmAddress].isActive;
    }
    
    /**
     * @notice Get identity details for an EVM address
     */
    function getIdentity(address evmAddress) 
        external 
        view 
        returns (SuiIdentity memory) 
    {
        return identities[evmAddress];
    }
    
    /**
     * @notice Get EVM address from Sui address
     */
    function getEvmAddress(bytes32 suiAddress) 
        external 
        view 
        returns (address) 
    {
        return suiToEvm[suiAddress];
    }
    
    /**
     * @notice Update relayer address
     */
    function updateRelayer(address newRelayer) external onlyRelayer {
        if (newRelayer == address(0)) revert InvalidAddress();
        
        address oldRelayer = relayer;
        relayer = newRelayer;
        
        emit RelayerUpdated(oldRelayer, newRelayer);
    }
}
