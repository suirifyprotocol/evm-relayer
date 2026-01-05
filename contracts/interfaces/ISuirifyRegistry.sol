// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

interface ISuirifyRegistry {
    struct SuiIdentity {
        bytes32 suiAddress;
        uint256 chainId;
        uint256 createdAt;
        bool isActive;
        bytes32 attestationId;
    }

    function payFee(uint256 chainId) external payable;
    function hasPaid(address user, uint256 chainId) external view returns (bool);
    function setFee(uint256 chainId, uint256 amountWei) external;
    function withdrawFees(uint256 amount, address to) external;
    function updateTreasury(address newTreasury) external;
    
    function registerIdentity(
        address evmAddress,
        bytes32 suiAddress,
        bytes32 attestationId
    ) external;
    
    function revokeIdentity(address evmAddress) external;
    function hasIdentity(address evmAddress) external view returns (bool);
    function getIdentity(address evmAddress) external view returns (SuiIdentity memory);
    function getEvmAddress(bytes32 suiAddress) external view returns (address);
}
