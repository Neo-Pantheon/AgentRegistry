// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

// Custom Errors for more detailed error handling
error ZeroAddress(string parameter);
error InvalidAgentType(uint8 provided, uint8 maxAllowed);
error StringTooShort(string paramName, uint256 minLength, uint256 actualLength);
error StringTooLong(string paramName, uint256 maxLength, uint256 actualLength);
error InvalidTier(uint8 provided, uint8 minAllowed, uint8 maxAllowed);
error TiersNotAscending();
error PercentageTooHigh(uint256 provided, uint256 maxAllowed);
error NFTCountMustBePositive();
error NotAgentOwner(uint256 agentId, address sender, address actualOwner);
error AgentNotActive(uint256 agentId);
error NoOwnershipToken(uint256 agentId);
error InsufficientFunds(uint256 required, uint256 available);
error TransferFailed(string reason);
error RateLimitExceeded(address user, uint256 agentId, uint64 cooldownPeriod);
error NotAuthorized(address sender, uint256 tokenId);
error CallExecutionFailed();
error TokenOperationFailed(string operation);
error NoTierAccess(address user, uint256 agentId);
error InterfaceValidationFailed(address contractAddress, bytes4 interfaceId);
error InvalidTokenBoundAccount(address account);

// Interface definitions with proper interface IDs for validation
interface IERC6551Account {
    // Function to receive Ether
    receive() external payable;
    
    // Returns the token associated with this account
    function token() external view returns (uint256 chainId, address tokenContract, uint256 tokenId);
    
    // Executes a transaction from the account
    function executeCall(address to, uint256 value, bytes calldata data) external payable returns (bytes memory);
    
    // ERC-165 interface ID for ERC6551Account
    // keccak256("IERC6551Account") = 0x6faff5f1
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

interface ITBAgentNFT {
    function createAgent(address to, uint256 agentId, uint8 agentType, string calldata name, string calldata symbol, string calldata customURI) external returns (uint256);
    function createOwnershipToken(address to, uint256 agentId, uint8 agentType, string memory name, string memory symbol, string memory customURI) external returns (uint256);
    function getAgentOwnershipToken(uint256 agentId) external view returns (uint256);
    function getTokenBoundAccount(uint256 tokenId) external view returns (address);
    function recordUsage(uint256 agentId, address user) external returns (bool);
    function distributeRevenue(uint256 agentId, uint256 amount) external returns (bool);
    function ownerOf(uint256 tokenId) external view returns (address);
    function transferFrom(address from, address to, uint256 tokenId) external;
    function approvedRegistry() external view returns (address);
    function symbolOfToken(uint256 tokenId) external view returns (string memory);
    
    // ERC-165 interface ID for TBAgentNFT
    // Example ID, actual implementation should calculate this from the interface definition
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

contract TBAgentRegistry is Ownable, ReentrancyGuard, Pausable {
    using Counters for Counters.Counter;
    address public registry;
    
    // Variables (previously constants)
    uint256 public creationFee = 25000 * 10**18; // 25,000 NEOX
    uint256 public usageFee = 10 * 10**18;      // 10 NEOX per use
    uint8 public nftCount = 12;                 // Default 12 NFTs per agent
    
    // Deployment tiers (made into variables)
    uint8 public tierBasic = 1;
    uint8 public tierAdvanced = 2;
    uint8 public tierPremium = 3;
    
    // Fee distribution
    uint256 public creatorPercentage = 70; // 70% to creator
    uint256 public platformPercentage = 30; // 30% to platform
    
    // Tier costs
    uint256 public basicTierCost = 100 * 10**18;    // 100 NEOX
    uint256 public advancedTierCost = 500 * 10**18; // 500 NEOX
    uint256 public premiumTierCost = 2000 * 10**18; // 2000 NEOX
    
    // Rate limiting
    uint64 public creationCooldown = 1 hours;  // Cooldown between agent creations
    uint64 public usageCooldown = 5 minutes;   // Cooldown between agent usage
    uint64 public tierPurchaseCooldown = 1 days; // Cooldown between tier purchases
    
    // Interface IDs for validation
    bytes4 private constant IERC6551Account_ID = 0x6faff5f1; // Calculate this from the interface
    bytes4 private constant ITBAgentNFT_ID = 0x123abc45; // Replace with actual interface ID
    
    // Counters
    Counters.Counter private _agentIdCounter;
    
    // Contracts
    IERC20 public neoxToken;
    ITBAgentNFT public agentNFT;
    
    // Withdrawal pattern
    mapping(address => uint256) public pendingWithdrawals;
    
    // Agent struct
    struct Agent {
        string name;
        string symbol;
        uint8 agentType;  // 0=Builder, 1=Researcher, 2=Socialite
        address creator;
        uint256 createdAt;
        uint256 usageCount;
        string personality;
        string modelConfig;
        bool active;
        string customURI;  // Custom token URI
    }
    
    // Rate Limiting structures
    struct UserRateLimits {
        uint64 lastCreationTime;
        mapping(uint256 => uint64) lastAgentUsageTime;
        mapping(uint256 => uint64) lastTierPurchaseTime;
        uint256 agentCreationCount24h;
        uint64 last24hReset;
    }
    
    // Delegation structures
    mapping(uint256 => mapping(address => bool)) private _tokenIdOperatorApprovals;
    mapping(address => bool) private _globalOperators;
    
    // Mappings
    mapping(uint256 => Agent) public agents;
    mapping(address => uint256[]) public creatorAgents;
    mapping(address => mapping(uint256 => uint8)) public userTiers; // user => agentId => tier
    mapping(address => UserRateLimits) private _userRateLimits;
    
    // Constants for rate limiting
    uint256 private constant MAX_AGENT_CREATIONS_24H = 5;
    uint64 private constant SECONDS_IN_24H = 86400;
    
    // Events
    event AgentCreated(uint256 indexed agentId, address indexed creator, uint8 agentType, string name, string customURI);
    event AgentUsed(uint256 indexed agentId, address indexed user, uint8 tier);
    event TierPurchased(uint256 indexed agentId, address indexed user, uint8 tier);
    event AgentOwnershipTransferred(uint256 indexed agentId, address indexed previousOwner, address indexed newOwner, uint256 ownershipTokenId);
    event DelegationApproved(uint256 indexed tokenId, address indexed operator, bool approved);
    event GlobalOperatorSet(address indexed operator, bool approved);
    event NEOXTransferred(uint256 indexed agentId, address indexed recipient, uint256 amount);
    event NFTTransferred(uint256 indexed agentId, address indexed nftContract, address indexed recipient, uint256 tokenId);
    event WithdrawalRequested(address indexed recipient, uint256 amount);
    event WithdrawalCompleted(address indexed recipient, uint256 amount);
    event RevenueDistributionFailed(uint256 indexed agentId, uint256 amount, string reason);
    event EmergencyWithdraw(address indexed recipient, uint256 amount);
    event FeesUpdated(uint256 newCreationFee, uint256 newUsageFee);
    event TierCostsUpdated(uint256 newBasicCost, uint256 newAdvancedCost, uint256 newPremiumCost);
    event NFTCountUpdated(uint8 newNFTCount);
    event FeeDistributionUpdated(uint256 newCreatorPercentage, uint256 newPlatformPercentage);
    event TierValuesUpdated(uint8 newBasicTier, uint8 newAdvancedTier, uint8 newPremiumTier);
    event RateLimitsUpdated(uint64 newCreationCooldown, uint64 newUsageCooldown, uint64 newTierPurchaseCooldown);
    event InterfaceValidated(address contractAddress, bytes4 interfaceId);
    
    constructor(address _neoxToken, address _agentNFT) Ownable(msg.sender) {
        if (_neoxToken == address(0)) revert ZeroAddress("NEOX token");
        if (_agentNFT == address(0)) revert ZeroAddress("Agent NFT");
        
        neoxToken = IERC20(_neoxToken);
        agentNFT = ITBAgentNFT(_agentNFT);
        
        // Validate interfaces
        _validateInterface(_agentNFT, ITBAgentNFT_ID);
    }
    
    // ========================
    // Interface Validation
    // ========================
    
    /**
     * @dev Validates that a contract supports a specific interface
     * @param contractAddress The address of the contract to validate
     * @param interfaceId The interface ID to check
     */
    function _validateInterface(address contractAddress, bytes4 interfaceId) internal {
        try IERC165(contractAddress).supportsInterface(interfaceId) returns (bool supported) {
            if (!supported) {
                revert InterfaceValidationFailed(contractAddress, interfaceId);
            }
            emit InterfaceValidated(contractAddress, interfaceId);
        } catch {
            revert InterfaceValidationFailed(contractAddress, interfaceId);
        }
    }
    
    /**
     * @dev Validates that an account implements the ERC6551Account interface
     * @param account The token bound account to validate
     */
    function _validateTokenBoundAccount(address account) internal view {
        if (account == address(0)) {
            revert ZeroAddress("Token bound account");
        }
        
        try IERC165(account).supportsInterface(IERC6551Account_ID) returns (bool supported) {
            if (!supported) {
                revert InvalidTokenBoundAccount(account);
            }
        } catch {
            revert InvalidTokenBoundAccount(account);
        }
    }
    
    // ========================
    // Configuration Functions
    // ========================
    
    /**
     * @dev Update fees for creation and usage
     * @param _creationFee New fee for creating an agent
     * @param _usageFee New fee for using an agent
     */
    function updateFees(uint256 _creationFee, uint256 _usageFee) external onlyOwner {
        creationFee = _creationFee;
        usageFee = _usageFee;
        emit FeesUpdated(_creationFee, _usageFee);
    }
    
    /**
     * @dev Update costs for different tiers
     * @param _basicTierCost Cost for basic tier
     * @param _advancedTierCost Cost for advanced tier
     * @param _premiumTierCost Cost for premium tier
     */
    function updateTierCosts(uint256 _basicTierCost, uint256 _advancedTierCost, uint256 _premiumTierCost) external onlyOwner {
        basicTierCost = _basicTierCost;
        advancedTierCost = _advancedTierCost;
        premiumTierCost = _premiumTierCost;
        emit TierCostsUpdated(_basicTierCost, _advancedTierCost, _premiumTierCost);
    }
    
    /**
     * @dev Update number of NFTs created per agent
     * @param _nftCount New NFT count per agent
     */
    function updateNFTCount(uint8 _nftCount) external onlyOwner {
        if (_nftCount == 0) revert NFTCountMustBePositive();
        nftCount = _nftCount;
        emit NFTCountUpdated(_nftCount);
    }
    
    /**
     * @dev Update fee distribution between creators and platform
     * @param _creatorPercentage Percentage of fees given to creators (0-100)
     */
    function updateFeeDistribution(uint256 _creatorPercentage) external onlyOwner {
        if (_creatorPercentage > 100) revert PercentageTooHigh(_creatorPercentage, 100);
        creatorPercentage = _creatorPercentage;
        platformPercentage = 100 - _creatorPercentage;
        emit FeeDistributionUpdated(_creatorPercentage, platformPercentage);
    }
    
    /**
     * @dev Update tier values
     * @param _tierBasic Value for basic tier
     * @param _tierAdvanced Value for advanced tier
     * @param _tierPremium Value for premium tier
     */
    function updateTierValues(uint8 _tierBasic, uint8 _tierAdvanced, uint8 _tierPremium) external onlyOwner {
        if (!(_tierBasic < _tierAdvanced && _tierAdvanced < _tierPremium)) {
            revert TiersNotAscending();
        }
        tierBasic = _tierBasic;
        tierAdvanced = _tierAdvanced;
        tierPremium = _tierPremium;
        emit TierValuesUpdated(_tierBasic, _tierAdvanced, _tierPremium);
    }
    
    /**
     * @dev Update rate limiting parameters
     * @param _creationCooldown Cooldown between agent creations
     * @param _usageCooldown Cooldown between agent usages
     * @param _tierPurchaseCooldown Cooldown between tier purchases
     */
    function updateRateLimits(
        uint64 _creationCooldown,
        uint64 _usageCooldown,
        uint64 _tierPurchaseCooldown
    ) external onlyOwner {
        creationCooldown = _creationCooldown;
        usageCooldown = _usageCooldown;
        tierPurchaseCooldown = _tierPurchaseCooldown;
        emit RateLimitsUpdated(_creationCooldown, _usageCooldown, _tierPurchaseCooldown);
    }
    
    // ========================
    // Rate Limiting Functions
    // ========================
    
    /**
     * @dev Check and update creation rate limits
     * @param user Address to check
     */
    function _checkCreationRateLimit(address user) internal {
        UserRateLimits storage limits = _userRateLimits[user];
        
        // Check cooldown period
        if (block.timestamp < limits.lastCreationTime + creationCooldown) {
            revert RateLimitExceeded(user, 0, creationCooldown);
        }
        
        // Check 24h limit
        if (block.timestamp >= limits.last24hReset + SECONDS_IN_24H) {
            // Reset 24h counter
            limits.agentCreationCount24h = 1;
            limits.last24hReset = uint64(block.timestamp);
        } else {
            // Increment counter and check limit
            limits.agentCreationCount24h++;
            if (limits.agentCreationCount24h > MAX_AGENT_CREATIONS_24H) {
                revert RateLimitExceeded(user, 0, uint64(limits.last24hReset + SECONDS_IN_24H - block.timestamp));
            }
        }
        
        // Update last creation time
        limits.lastCreationTime = uint64(block.timestamp);
    }
    
    /**
     * @dev Check and update usage rate limit
     * @param user Address to check
     * @param agentId Agent ID being used
     */
    function _checkUsageRateLimit(address user, uint256 agentId) internal {
        UserRateLimits storage limits = _userRateLimits[user];
        uint64 lastUsage = limits.lastAgentUsageTime[agentId];
        
        if (block.timestamp < lastUsage + usageCooldown) {
            revert RateLimitExceeded(user, agentId, usageCooldown);
        }
        
        limits.lastAgentUsageTime[agentId] = uint64(block.timestamp);
    }
    
    /**
     * @dev Check and update tier purchase rate limit
     * @param user Address to check
     * @param agentId Agent ID for which tier is being purchased
     */
    function _checkTierPurchaseRateLimit(address user, uint256 agentId) internal {
        UserRateLimits storage limits = _userRateLimits[user];
        uint64 lastPurchase = limits.lastTierPurchaseTime[agentId];
        
        if (block.timestamp < lastPurchase + tierPurchaseCooldown) {
            revert RateLimitExceeded(user, agentId, tierPurchaseCooldown);
        }
        
        limits.lastTierPurchaseTime[agentId] = uint64(block.timestamp);
    }
    
    // ========================
    // Emergency Controls
    // ========================
    
    function pause() external onlyOwner {
        _pause();
    }
    
    function unpause() external onlyOwner {
        _unpause();
    }
    
    /**
     * @dev Emergency withdrawal of all tokens
     * @param recipient Address to receive tokens
     */
    function emergencyWithdraw(address recipient) external onlyOwner {
        if (recipient == address(0)) revert ZeroAddress("Recipient");
        
        uint256 balance = neoxToken.balanceOf(address(this));
        if (balance == 0) revert InsufficientFunds(1, 0);
        
        bool success = neoxToken.transfer(recipient, balance);
        if (!success) revert TransferFailed("Emergency withdrawal failed");
        
        emit EmergencyWithdraw(recipient, balance);
    }
    
    // ========================
    // Main Functions
    // ========================
    
    /**
     * @dev Create a new AI Agent with NFTs & Ownership Token
     * @param name Agent name
     * @param symbol Token symbol
     * @param agentType Agent type (0=Builder, 1=Researcher, 2=Socialite)
     * @param personality Agent personality description
     * @param modelConfig Model configuration
     * @param customURI Custom token URI
     * @return agentId The ID of the created agent
     */
    function createAgent(
        string memory name,
        string memory symbol,
        uint8 agentType,
        string memory personality,
        string memory modelConfig,
        string memory customURI
    ) external nonReentrant whenNotPaused returns (uint256) {
        // Validate inputs
        uint256 nameLength = bytes(name).length;
        if (nameLength < 3) revert StringTooShort("name", 3, nameLength);
        
        uint256 symbolLength = bytes(symbol).length;
        if (symbolLength < 2) revert StringTooShort("symbol", 2, symbolLength);
        if (symbolLength > 6) revert StringTooLong("symbol", 6, symbolLength);
        
        if (agentType > 2) revert InvalidAgentType(agentType, 2);
        
        if (bytes(customURI).length == 0) revert StringTooShort("customURI", 1, 0);

        // Check rate limits
        _checkCreationRateLimit(msg.sender);

        // Collect creation fee with proper checks
        bool feeCollected = neoxToken.transferFrom(msg.sender, address(this), creationFee);
        if (!feeCollected) revert TransferFailed("Creation fee collection failed");

        // Generate agent ID
        uint256 agentId = _agentIdCounter.current();
        _agentIdCounter.increment();

        // Store agent data
        agents[agentId] = Agent({
            name: name,
            symbol: symbol,
            agentType: agentType,
            creator: msg.sender,
            createdAt: block.timestamp,
            usageCount: 0,
            personality: personality,
            modelConfig: modelConfig,
            active: true,
            customURI: customURI
        });

        // Track creator's agents
        creatorAgents[msg.sender].push(agentId);

        // Mint NFTs to creator (regular revenue-sharing NFTs)
        for (uint8 i = 0; i < nftCount; i++) {
            try agentNFT.createAgent(
                msg.sender,
                agentId,
                agentType,
                name,
                symbol,
                customURI
            ) returns (uint256) {
                // NFT created successfully
            } catch Error(string memory reason) {
                revert TokenOperationFailed(reason);
            } catch {
                revert TokenOperationFailed("Agent NFT creation failed");
            }
        }

        // Mint special ERC6551 ownership NFT to creator
        uint256 ownershipTokenId;
        try agentNFT.createOwnershipToken(
            msg.sender,
            agentId,
            agentType,
            name,
            symbol,
            customURI
        ) returns (uint256 tokenId) {
            ownershipTokenId = tokenId;
        } catch Error(string memory reason) {
            revert TokenOperationFailed(reason);
        } catch {
            revert TokenOperationFailed("Ownership token creation failed");
        }

        // Auto-grant the creator premium tier access
        userTiers[msg.sender][agentId] = tierPremium;

        emit AgentCreated(agentId, msg.sender, agentType, name, customURI);

        return agentId;
    }
    
    /**
     * @dev Transfer ownership of an agent to a new owner
     * @param agentId Agent ID to transfer
     * @param newOwner Address of the new owner
     */
    function transferAgentOwnership(uint256 agentId, address newOwner) external nonReentrant whenNotPaused {
        // Validate inputs
        if (!agents[agentId].active) revert AgentNotActive(agentId);
        if (newOwner == address(0)) revert ZeroAddress("New owner");
        
        // Get the ownership token ID
        uint256 ownershipTokenId = agentNFT.getAgentOwnershipToken(agentId);
        if (ownershipTokenId == 0) revert NoOwnershipToken(agentId);
        
        // Check that the sender is the current owner of the ownership token
        address currentOwner = agentNFT.ownerOf(ownershipTokenId);
        if (currentOwner != msg.sender) revert NotAgentOwner(agentId, msg.sender, currentOwner);
        
        // Transfer the ownership token to the new owner
        try agentNFT.transferFrom(msg.sender, newOwner, ownershipTokenId) {
            // Transfer successful
        } catch Error(string memory reason) {
            revert TokenOperationFailed(reason);
        } catch {
            revert TokenOperationFailed("Token transfer failed");
        }
        
        // Update the agent creator
        address previousOwner = agents[agentId].creator;
        agents[agentId].creator = newOwner;
        
        // Update creator's agents list (remove from old owner)
        _removeAgentFromCreator(previousOwner, agentId);
        
        // Add to new owner's agents list
        creatorAgents[newOwner].push(agentId);
        
        // Grant premium tier access to the new owner
        userTiers[newOwner][agentId] = tierPremium;
        
        emit AgentOwnershipTransferred(agentId, previousOwner, newOwner, ownershipTokenId);
    }
    
    /**
     * @dev Helper function to remove agent from creator's list
     * @param creator Address of creator
     * @param agentId Agent ID to remove
     */
    function _removeAgentFromCreator(address creator, uint256 agentId) internal {
        uint256[] storage creatorAgentsList = creatorAgents[creator];
        for (uint256 i = 0; i < creatorAgentsList.length; i++) {
            if (creatorAgentsList[i] == agentId) {
                // Swap and pop to avoid gaps in array (gas efficient)
                if (i < creatorAgentsList.length - 1) {
                    creatorAgentsList[i] = creatorAgentsList[creatorAgentsList.length - 1];
                }
                creatorAgentsList.pop();
                break;
            }
        }
    }
    
    /**
     * @dev Get token bound account address for an agent
     * @param agentId Agent ID
     * @return Address of the token bound account
     */
    function getAgentTokenBoundAccount(uint256 agentId) external view returns (address) {
        uint256 ownershipTokenId = agentNFT.getAgentOwnershipToken(agentId);
        if (ownershipTokenId == 0) revert NoOwnershipToken(agentId);
        
        address account = agentNFT.getTokenBoundAccount(ownershipTokenId);
        if (account == address(0)) revert InvalidTokenBoundAccount(account);
        
        return account;
    }
    
    // ========================
    // Delegation Management
    // ========================
    
    /**
     * @dev Approve an address to serve as a delegate for a token
     * @param tokenId Token ID to delegate
     * @param operator Address to approve as delegate
     * @param approved Approval status
     */
    function setDelegationApproval(uint256 tokenId, address operator, bool approved) external whenNotPaused {
        if (operator == address(0)) revert ZeroAddress("Operator");
        
        address tokenOwner = agentNFT.ownerOf(tokenId);
        if (tokenOwner != msg.sender) revert NotAgentOwner(0, msg.sender, tokenOwner);
        
        _tokenIdOperatorApprovals[tokenId][operator] = approved;
        emit DelegationApproved(tokenId, operator, approved);
    }
    
    /**
     * @dev Set a global operator that can operate on behalf of any token
     * @param operator Address to set as global operator
     * @param approved Approval status
     */
    function setGlobalOperator(address operator, bool approved) external onlyOwner {
        if (operator == address(0)) revert ZeroAddress("Operator");
        _globalOperators[operator] = approved;
        emit GlobalOperatorSet(operator, approved);
    }
    
    /**
     * @dev Check if an address is approved to operate on behalf of a token
     * @param tokenId Token ID
     * @param operator Address to check
     * @return bool True if approved
     */
    function isDelegationApproved(uint256 tokenId, address operator) public view returns (bool) {
        return _tokenIdOperatorApprovals[tokenId][operator] || _globalOperators[operator];
    }
    
    // ========================
    // Agent Execution Functions
    // ========================
    
    /**
     * @dev Execute a call from an agent's token bound account
     * @param agentId Agent ID
     * @param to Destination address
     * @param value ETH value to send
     * @param data Call data
     * @return bytes Return data from the call
     */
    function executeFromAgent(
        uint256 agentId,
        address to,
        uint256 value,
        bytes memory data
    ) public whenNotPaused returns (bytes memory) {
        if (to == address(0)) revert ZeroAddress("Recipient");
        
        // Fetch the ownership token ID from the agentNFT contract
        uint256 ownershipTokenId = agentNFT.getAgentOwnershipToken(agentId);
        if (ownershipTokenId == 0) revert NoOwnershipToken(agentId);

        // Get the token owner
        address tokenOwner = agentNFT.ownerOf(ownershipTokenId);
        
        // Authentication check
        bool isAuthorized = 
            msg.sender == tokenOwner || // Token owner
            msg.sender == owner() || // Contract owner
            msg.sender == agentNFT.approvedRegistry() || // Approved registry
            isDelegationApproved(ownershipTokenId, msg.sender); // Delegated operator
            
        if (!isAuthorized) revert NotAuthorized(msg.sender, ownershipTokenId);
        
        // Get the account associated with the ownership token
        address payable account = payable(agentNFT.getTokenBoundAccount(ownershipTokenId));
        _validateTokenBoundAccount(account);
        
        // Execute the call to the specified address
        bytes memory result;
        try IERC6551Account(account).executeCall(to, value, data) returns (bytes memory returnData) {
            result = returnData;
            if (result.length == 0) revert CallExecutionFailed();
        } catch Error(string memory reason) {
            revert TokenOperationFailed(reason);
        } catch {
            revert CallExecutionFailed();
        }
        
        return result;
    }
    
    /**
     * @dev Transfer NEOX tokens from an agent's account
     * @param agentId Agent ID
     * @param recipient Recipient address
     * @param amount Amount to transfer
     * @return bytes Return data from the call
     */
    function executeNEOXTransfer(
        uint256 agentId, 
        address recipient, 
        uint256 amount
    ) external whenNotPaused returns (bytes memory) {
        if (recipient == address(0)) revert ZeroAddress("Recipient");
        if (amount == 0) revert InsufficientFunds(1, 0);
        
        // Get the NEOX token address
        address neoxTokenAddress = address(neoxToken);
        
        // Encode the transfer function call: transfer(address to, uint256 amount)
        bytes memory data = abi.encodeWithSignature(
            "transfer(address,uint256)",
            recipient,
            amount
        );
        
        // Execute the call via the agent's token bound account
        bytes memory result = executeFromAgent(agentId, neoxTokenAddress, 0, data);
        
        // Verify transfer success
        bool success;
        // Use a safer approach to decode the result
        if (result.length > 0) {
            // Standard ERC20 transfer returns bool
            (success) = abi.decode(result, (bool));
        } else {
            success = false;
        }
        
        if (!success) revert TokenOperationFailed("Token transfer failed");
        
        emit NEOXTransferred(agentId, recipient, amount);
        
        return result;
    }
    
    /**
     * @dev Transfer NFT from an agent's account
     * @param agentId Agent ID
     * @param nftContract NFT contract address
     * @param recipient Recipient address
     * @param tokenId Token ID to transfer
     * @return bytes Return data from the call
     */
    function executeNFTTransfer(
        uint256 agentId, 
        address nftContract, 
        address recipient, 
        uint256 tokenId
    ) external whenNotPaused returns (bytes memory) {
        if (nftContract == address(0)) revert ZeroAddress("NFT contract");
        if (recipient == address(0)) revert ZeroAddress("Recipient");
        
        // Get the agent's token bound account address
        address agentAccount;
        {
            uint256 ownershipTokenId = agentNFT.getAgentOwnershipToken(agentId);
            if (ownershipTokenId == 0) revert NoOwnershipToken(agentId);
            
            agentAccount = agentNFT.getTokenBoundAccount(ownershipTokenId);
            _validateTokenBoundAccount(agentAccount);
        }
        
        // Encode the transferFrom function call: transferFrom(address from, address to, uint256 tokenId)
        bytes memory data = abi.encodeWithSignature(
            "transferFrom(address,address,uint256)",
            agentAccount, // from: the agent's account
            recipient,    // to: the recipient
            tokenId       // tokenId: the NFT ID
        );
        
        // Execute the call via the agent's token bound account
        bytes memory result = executeFromAgent(agentId, nftContract, 0, data);
        if (result.length == 0) revert TokenOperationFailed("NFT transfer failed");
        
        emit NFTTransferred(agentId, nftContract, recipient, tokenId);
        
        return result;
    }
    
    // ========================
    // Purchase and Usage
    // ========================
    
    /**
     * @dev Purchase tier access to an agent
     * @param agentId Agent ID
     * @param tier Tier level to purchase (1-3)
     */
    function purchaseTier(uint256 agentId, uint8 tier) external nonReentrant whenNotPaused {
        if (!agents[agentId].active) revert AgentNotActive(agentId);
        if (tier < tierBasic || tier > tierPremium) revert InvalidTier(tier, tierBasic, tierPremium);
        
        // Check rate limit
        _checkTierPurchaseRateLimit(msg.sender, agentId);
        
        uint256 tierCost;
        if (tier == tierBasic) {
            tierCost = basicTierCost;
        } else if (tier == tierAdvanced) {
            tierCost = advancedTierCost;
        } else if (tier == tierPremium) {
            tierCost = premiumTierCost;
        }
        
        // Collect tier fee
        bool feeTransferred = neoxToken.transferFrom(msg.sender, address(this), tierCost);
        if (!feeTransferred) revert TransferFailed("Tier fee transfer failed");
        
        // Calculate fee distribution
        uint256 creatorAmount = (tierCost * creatorPercentage) / 100;
        uint256 platformAmount = tierCost - creatorAmount;
        
        // Add platform fees to pending withdrawals
        pendingWithdrawals[owner()] += platformAmount;
        
        // Distribute to NFT holders
        try agentNFT.distributeRevenue(agentId, creatorAmount) returns (bool success) {
            if (!success) {
                // If distribution returns false, add to pending withdrawals for manual claiming
                pendingWithdrawals[agents[agentId].creator] += creatorAmount;
                emit RevenueDistributionFailed(agentId, creatorAmount, "Distribution returned false");
            }
        } catch Error(string memory reason) {
            // If distribution reverts with reason, add to pending withdrawals
            pendingWithdrawals[agents[agentId].creator] += creatorAmount;
            emit RevenueDistributionFailed(agentId, creatorAmount, reason);
        } catch {
            // If distribution reverts without reason, add to pending withdrawals
            pendingWithdrawals[agents[agentId].creator] += creatorAmount;
            emit RevenueDistributionFailed(agentId, creatorAmount, "Distribution reverted");
        }
        
        // Grant tier access
        userTiers[msg.sender][agentId] = tier;
        
        emit TierPurchased(agentId, msg.sender, tier);
    }
    
    /**
     * @dev Use an agent (requires tier access)
     * @param agentId Agent ID
     */
    function useAgent(uint256 agentId) external nonReentrant whenNotPaused {
        if (!agents[agentId].active) revert AgentNotActive(agentId);
        
        // Check tier access
        uint8 tier = userTiers[msg.sender][agentId];
        if (tier == 0) revert NoTierAccess(msg.sender, agentId);
        
        // Check rate limit
        _checkUsageRateLimit(msg.sender, agentId);
        
        // Collect usage fee
        bool feeTransferred = neoxToken.transferFrom(msg.sender, address(this), usageFee);
        if (!feeTransferred) revert TransferFailed("Usage fee transfer failed");
        
        // Track usage
        agents[agentId].usageCount++;
        
        // Record usage in NFT contract
        bool recordSuccess;
        try agentNFT.recordUsage(agentId, msg.sender) returns (bool success) {
            recordSuccess = success;
            if (!recordSuccess) revert TokenOperationFailed("Usage recording returned false");
        } catch Error(string memory reason) {
            revert TokenOperationFailed(reason);
        } catch {
            revert TokenOperationFailed("Usage recording failed");
        }
        
        // Calculate fee distribution
        uint256 creatorAmount = (usageFee * creatorPercentage) / 100;
        uint256 platformAmount = usageFee - creatorAmount;
        
        // Add platform fees to pending withdrawals
        pendingWithdrawals[owner()] += platformAmount;
        
        // Distribute to NFT holders
        try agentNFT.distributeRevenue(agentId, creatorAmount) returns (bool success) {
            if (!success) {
                // If distribution returns false, add to pending withdrawals for manual claiming
                pendingWithdrawals[agents[agentId].creator] += creatorAmount;
                emit RevenueDistributionFailed(agentId, creatorAmount, "Distribution returned false");
            }
        } catch Error(string memory reason) {
            // If distribution reverts with reason, add to pending withdrawals
            pendingWithdrawals[agents[agentId].creator] += creatorAmount;
            emit RevenueDistributionFailed(agentId, creatorAmount, reason);
        } catch {
            // If distribution reverts without reason, add to pending withdrawals
            pendingWithdrawals[agents[agentId].creator] += creatorAmount;
            emit RevenueDistributionFailed(agentId, creatorAmount, "Distribution reverted");
        }
        
        emit AgentUsed(agentId, msg.sender, tier);
    }
    
    // ========================
    // Withdrawal Pattern
    // ========================
    
    /**
     * @dev Request withdrawal of pending fees
     */
    function requestWithdrawal() external nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        if (amount == 0) revert InsufficientFunds(1, 0);
        
        // Reset pending withdrawal before transfer to prevent reentrancy
        pendingWithdrawals[msg.sender] = 0;
        
        // Transfer tokens to the user
        bool success = neoxToken.transfer(msg.sender, amount);
        if (!success) revert TransferFailed("Withdrawal transfer failed");
        
        emit WithdrawalCompleted(msg.sender, amount);
    }
    
    /**
     * @dev View pending withdrawal amount
     * @param user Address to check
     * @return Amount of tokens available for withdrawal
     */
    function getPendingWithdrawal(address user) external view returns (uint256) {
        return pendingWithdrawals[user];
    }
    
    // ========================
    // View Functions
    // ========================
    
    /**
     * @dev Get ownership token ID for an agent
     * @param agentId Agent ID
     * @return Ownership token ID
     */
    function getAgentOwnershipToken(uint256 agentId) external view returns (uint256) {
        return agentNFT.getAgentOwnershipToken(agentId);
    }
    
    /**
     * @dev Get agent details
     * @param agentId Agent ID
     * @return Agent struct
     */
    function getAgent(uint256 agentId) external view returns (Agent memory) {
        return agents[agentId];
    }
    
    /**
     * @dev Check if an address is a global operator
     * @param operator Address to check
     * @return bool True if global operator
     */
    function isGlobalOperator(address operator) external view returns (bool) {
        return _globalOperators[operator];
    }
    
    /**
     * @dev Get creator agents with pagination
     * @param creator Creator address
     * @param offset Pagination offset
     * @param limit Pagination limit
     * @return Array of agent IDs
     */
    function getCreatorAgents(address creator, uint256 offset, uint256 limit) external view returns (uint256[] memory) {
        uint256[] storage allAgents = creatorAgents[creator];
        
        // Bound check
        if (offset >= allAgents.length) {
            return new uint256[](0);
        }
        
        // Determine actual count to return
        uint256 count = (offset + limit > allAgents.length) ? 
                        (allAgents.length - offset) : 
                        limit;
        
        uint256[] memory result = new uint256[](count);
        
        // Copy results with pagination
        for (uint256 i = 0; i < count; i++) {
            result[i] = allAgents[offset + i];
        }
        
        return result;
    }
    
    /**
     * @dev Get rate limit information for a user
     * @param user User address
     * @param agentId Agent ID
     * @return creationTime Last creation time
     * @return usageTime Last usage time
     * @return purchaseTime Last tier purchase time
     * @return creationCount24h Agent creation count in last 24h
     * @return resetTime Time of last 24h counter reset
     */
    function getUserRateLimits(address user, uint256 agentId) external view returns (
        uint64 creationTime,
        uint64 usageTime,
        uint64 purchaseTime,
        uint256 creationCount24h,
        uint64 resetTime
    ) {
        UserRateLimits storage limits = _userRateLimits[user];
        
        return (
            limits.lastCreationTime,
            limits.lastAgentUsageTime[agentId],
            limits.lastTierPurchaseTime[agentId],
            limits.agentCreationCount24h,
            limits.last24hReset
        );
    }
}
