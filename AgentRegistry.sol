// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol"; // Added SafeERC20
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
error ValidationFailed(string parameter, string reason);
error ResultValidationFailed(string operation, bytes reason);
error InvalidParameter(string name, string reason);
error RateLimitNotElapsed(address user, uint256 agentId, uint256 lastUsed, uint256 cooldown);

interface IERC6551Account {
    receive() external payable;
    function token() external view returns (uint256 chainId, address tokenContract, uint256 tokenId);
    function executeCall(address to, uint256 value, bytes calldata data) external payable returns (bytes memory);
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
}

contract TBAgentRegistry is Ownable, ReentrancyGuard, Pausable {
    using Counters for Counters.Counter;
    using SafeERC20 for IERC20; // Using SafeERC20 now
    address public registry;
    
    // Variables (previously constants)
    uint256 public creationFee = 25000 * 10**18; // 25,000 NEOX
    uint256 public usageFee = 10 * 10**18;      // 10 NEOX per use
    uint256 public nftCount = 12;                 // Default 12 NFTs per agent
    
    // Deployment tiers (made into variables)
    uint256 public tierBasic = 1;
    uint256 public tierAdvanced = 2;
    uint256 public tierPremium = 3;
    
    // Fee distribution
    uint256 public creatorPercentage = 70; // 70% to creator
    uint256 public platformPercentage = 30; // 30% to platform
    
    // Tier costs
    uint256 public basicTierCost = 100 * 10**18;    // 100 NEOX
    uint256 public advancedTierCost = 500 * 10**18; // 500 NEOX
    uint256 public premiumTierCost = 2000 * 10**18; // 2000 NEOX
    
    // Rate limiting
    uint256 public usageCooldown = 5 minutes; // Default cooldown period between uses
    
    // Counters
    Counters.Counter private _agentIdCounter;
    
    // Contracts
    IERC20 public neoxToken;
    ITBAgentNFT public agentNFT;
    
    // Accepted ERC20 tokens
    mapping(address => bool) public acceptedTokens;
    address[] public acceptedTokensList;
    
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
    
    // Rate limiting structure
    struct UsageData {
        uint256 lastUsageTime;
        uint256 totalUsage;
    }
    
    // Delegation structures
    mapping(uint256 => mapping(address => bool)) private _tokenIdOperatorApprovals;
    mapping(address => bool) private _globalOperators;
    
    // Mappings
    mapping(uint256 => Agent) public agents;
    mapping(address => uint256[]) public creatorAgents;
    mapping(address => mapping(uint256 => uint8)) public userTiers; // user => agentId => tier
    mapping(address => mapping(uint256 => UsageData)) public usageHistory; // Rate limiting data
    
    // Events
    event AgentCreated(uint256 indexed agentId, address indexed creator, uint8 agentType, string name, string customURI);
    event AgentUsed(uint256 indexed agentId, address indexed user, uint8 tier, uint256 timestamp);
    event TierPurchased(uint256 indexed agentId, address indexed user, uint8 tier, uint256 amount);
    event AgentOwnershipTransferred(uint256 indexed agentId, address indexed previousOwner, address indexed newOwner, uint256 ownershipTokenId);
    event DelegationApproved(uint256 indexed tokenId, address indexed operator, bool approved);
    event GlobalOperatorSet(address indexed operator, bool approved);
    event NEOXTransferred(uint256 indexed agentId, address indexed recipient, uint256 amount, bool success);
    event NFTTransferred(uint256 indexed agentId, address indexed nftContract, address indexed recipient, uint256 tokenId);
    event WithdrawalRequested(address indexed recipient, uint256 amount);
    event WithdrawalCompleted(address indexed recipient, uint256 amount);
    event RevenueDistributionFailed(uint256 indexed agentId, uint256 amount, address fallbackRecipient);
    event EmergencyWithdraw(address indexed recipient, uint256 amount);
    event FeesUpdated(uint256 newCreationFee, uint256 newUsageFee);
    event TierCostsUpdated(uint256 newBasicCost, uint256 newAdvancedCost, uint256 newPremiumCost);
    event NFTCountUpdated(uint8 newNFTCount);
    event FeeDistributionUpdated(uint256 newCreatorPercentage, uint256 newPlatformPercentage);
    event TierValuesUpdated(uint8 newBasicTier, uint8 newAdvancedTier, uint8 newPremiumTier);
    event RateLimitUpdated(uint256 newCooldownPeriod);
    event AgentConfigurationUpdated(uint256 indexed agentId, string field, string newValue);
    event AgentStatusChanged(uint256 indexed agentId, bool active);
    event AgentRateLimitExceeded(address indexed user, uint256 indexed agentId, uint256 lastUsage, uint256 cooldownPeriod);
    event OperationAttempted(string operation, address indexed user, bool success);
    event ValidationError(string parameter, string reason);
    event DelegationStatusCheck(uint256 tokenId, address operator, bool status);
    event TokenAdded(address indexed tokenAddress, string tokenSymbol);
    event TokenRemoved(address indexed tokenAddress, string tokenSymbol);
    
    constructor(address _neoxToken, address _agentNFT) Ownable(msg.sender) {
        if (_neoxToken == address(0)) revert ZeroAddress("neoxToken");
        if (_agentNFT == address(0)) revert ZeroAddress("agentNFT");
        
        neoxToken = IERC20(_neoxToken);
        agentNFT = ITBAgentNFT(_agentNFT);
        
        // Add the NEOX token as an accepted token by default
        acceptedTokens[_neoxToken] = true;
        acceptedTokensList.push(_neoxToken);
        
        emit OperationAttempted("Constructor", msg.sender, true);
    }
    
    // Validate string inputs
    function _validateString(string memory value, string memory paramName, uint256 minLength, uint256 maxLength) internal pure {
        uint256 length = bytes(value).length;
        if (length < minLength) revert StringTooShort(paramName, minLength, length);
        if (maxLength > 0 && length > maxLength) revert StringTooLong(paramName, maxLength, length);
    }
    
    // Validate address inputs 
    function _validateAddress(address value, string memory paramName) internal pure {
        if (value == address(0)) revert ZeroAddress(paramName);
    }
    
    // Validate numeric range
    function _validateRange(uint256 value, string memory paramName, uint256 min, uint256 max) internal pure {
        if (value < min) revert InvalidParameter(paramName, "Value too low");
        if (max > 0 && value > max) revert InvalidParameter(paramName, "Value too high");
    }
    
    // ========================
    // ERC20 Token Management
    // ========================
    
    /**
     * @dev Add an ERC20 token to the list of accepted tokens
     * @param tokenAddress The address of the ERC20 token contract
     */
    function addAcceptedToken(address tokenAddress) external onlyOwner {
        _validateAddress(tokenAddress, "tokenAddress");
        
        // Check if token is already accepted
        if (acceptedTokens[tokenAddress]) revert ValidationFailed("tokenAddress", "Token already accepted");
        
        // Try to get token symbol (basic validation that it's an ERC20)
        string memory symbol;
        try IERC20Metadata(tokenAddress).symbol() returns (string memory s) {
            symbol = s;
        } catch {
            revert InterfaceValidationFailed(tokenAddress, IERC20Metadata.symbol.selector);
        }
        
        // Add token to accepted list
        acceptedTokens[tokenAddress] = true;
        acceptedTokensList.push(tokenAddress);
        
        emit TokenAdded(tokenAddress, symbol);
        emit OperationAttempted("addAcceptedToken", msg.sender, true);
    }
    
    /**
     * @dev Remove an ERC20 token from the list of accepted tokens
     * @param tokenAddress The address of the ERC20 token to remove
     */
    function removeAcceptedToken(address tokenAddress) external onlyOwner {
        // Cannot remove the primary NEOX token
        if (tokenAddress == address(neoxToken)) revert ValidationFailed("tokenAddress", "Cannot remove primary token");
        
        // Check if token is currently accepted
        if (!acceptedTokens[tokenAddress]) revert ValidationFailed("tokenAddress", "Token not in accepted list");
        
        // Try to get token symbol for the event
        string memory symbol;
        try IERC20Metadata(tokenAddress).symbol() returns (string memory s) {
            symbol = s;
        } catch {
            symbol = "UNKNOWN";
        }
        
        // Remove from mapping
        acceptedTokens[tokenAddress] = false;
        
        // Remove from array
        for (uint256 i = 0; i < acceptedTokensList.length; i++) {
            if (acceptedTokensList[i] == tokenAddress) {
                // Swap with the last element and pop (gas efficient)
                if (i < acceptedTokensList.length - 1) {
                    acceptedTokensList[i] = acceptedTokensList[acceptedTokensList.length - 1];
                }
                acceptedTokensList.pop();
                break;
            }
        }
        
        emit TokenRemoved(tokenAddress, symbol);
        emit OperationAttempted("removeAcceptedToken", msg.sender, true);
    }
    
    /**
     * @dev Get the list of all accepted tokens
     * @return List of accepted token addresses
     */
    function getAcceptedTokens() external view returns (address[] memory) {
        return acceptedTokensList;
    }
    
    /**
     * @dev Check if a token is accepted
     * @param tokenAddress The token address to check
     * @return True if the token is accepted
     */
    function isTokenAccepted(address tokenAddress) external view returns (bool) {
        return acceptedTokens[tokenAddress];
    }
    
    /**
     * @dev Execute a transfer of any accepted ERC20 token from agent wallet
     * @param agentId The agent ID
     * @param tokenAddress The ERC20 token address
     * @param recipient The recipient address
     * @param amount The amount to transfer
     */
    function executeTokenTransfer(
        uint256 agentId,
        address tokenAddress,
        address recipient,
        uint256 amount
    ) external whenNotPaused returns (bytes memory) {
        _validateAddress(tokenAddress, "tokenAddress");
        _validateAddress(recipient, "recipient");
        _validateRange(amount, "amount", 1, 0);
        
        // Check if token is accepted
        if (!acceptedTokens[tokenAddress]) revert ValidationFailed("tokenAddress", "Token not accepted");
        
        // Encode the transfer function call: transfer(address to, uint256 amount)
        bytes memory data = abi.encodeWithSignature(
            "transfer(address,uint256)",
            recipient,
            amount
        );
        
        // Execute the call via the agent's token bound account
        bytes memory result = executeFromAgent(agentId, tokenAddress, 0, data);
        
        // Verify transfer success
        bool success = abi.decode(result, (bool));
        if (!success) revert TokenOperationFailed("transfer");
        
        // Get token symbol if possible
        string memory symbol;
        try IERC20Metadata(tokenAddress).symbol() returns (string memory s) {
            symbol = s;
        } catch {
            symbol = "UNKNOWN";
        }
        
        emit NEOXTransferred(agentId, recipient, amount, success);
        emit OperationAttempted("executeTokenTransfer", msg.sender, true);
        
        return result;
    }
    
    function updateFees(uint256 _creationFee, uint256 _usageFee) external onlyOwner {
        _validateRange(_creationFee, "creationFee", 0, 0);
        _validateRange(_usageFee, "usageFee", 0, 0);
        
        creationFee = _creationFee;
        usageFee = _usageFee;
        
        emit FeesUpdated(_creationFee, _usageFee);
        emit OperationAttempted("updateFees", msg.sender, true);
    }
    
    function updateTierCosts(uint256 _basicTierCost, uint256 _advancedTierCost, uint256 _premiumTierCost) external onlyOwner {
        _validateRange(_basicTierCost, "basicTierCost", 0, 0);
        _validateRange(_advancedTierCost, "advancedTierCost", _basicTierCost, 0);
        _validateRange(_premiumTierCost, "premiumTierCost", _advancedTierCost, 0);
        
        basicTierCost = _basicTierCost;
        advancedTierCost = _advancedTierCost;
        premiumTierCost = _premiumTierCost;
        
        emit TierCostsUpdated(_basicTierCost, _advancedTierCost, _premiumTierCost);
        emit OperationAttempted("updateTierCosts", msg.sender, true);
    }
    
    function updateNFTCount(uint8 _nftCount) external onlyOwner {
        if (_nftCount == 0) revert NFTCountMustBePositive();
        
        nftCount = _nftCount;
        
        emit NFTCountUpdated(_nftCount);
        emit OperationAttempted("updateNFTCount", msg.sender, true);
    }
    
    function updateFeeDistribution(uint256 _creatorPercentage) external onlyOwner {
        if (_creatorPercentage > 100) revert PercentageTooHigh(_creatorPercentage, 100);
        
        creatorPercentage = _creatorPercentage;
        platformPercentage = 100 - _creatorPercentage;
        
        emit FeeDistributionUpdated(_creatorPercentage, platformPercentage);
        emit OperationAttempted("updateFeeDistribution", msg.sender, true);
    }
    
    function updateTierValues(uint8 _tierBasic, uint8 _tierAdvanced, uint8 _tierPremium) external onlyOwner {
        if (!(_tierBasic < _tierAdvanced && _tierAdvanced < _tierPremium)) revert TiersNotAscending();
        
        tierBasic = _tierBasic;
        tierAdvanced = _tierAdvanced;
        tierPremium = _tierPremium;
        
        emit TierValuesUpdated(_tierBasic, _tierAdvanced, _tierPremium);
        emit OperationAttempted("updateTierValues", msg.sender, true);
    }
    
    function updateRateLimit(uint256 _usageCooldown) external onlyOwner {
        usageCooldown = _usageCooldown;
        
        emit RateLimitUpdated(_usageCooldown);
        emit OperationAttempted("updateRateLimit", msg.sender, true);
    }
    
    // ========================
    // Emergency Controls
    // ========================
    
    function pause() external onlyOwner {
        _pause();
        emit OperationAttempted("pause", msg.sender, true);
    }
    
    function unpause() external onlyOwner {
        _unpause();
        emit OperationAttempted("unpause", msg.sender, true);
    }
    
    function emergencyWithdraw(address recipient) external onlyOwner {
        _validateAddress(recipient, "recipient");
        
        uint256 balance = neoxToken.balanceOf(address(this));
        if (balance == 0) revert InsufficientFunds(1, 0);
        
        neoxToken.safeTransfer(recipient, balance);
        
        emit EmergencyWithdraw(recipient, balance);
        emit OperationAttempted("emergencyWithdraw", msg.sender, true);
    }
    
    // ========================
    // Main Functions
    // ========================
    
    // Create The AI Agent NFTs & Ownership NFT Token (agentType is 0 = Builder, 1 = Researcher, 2 = Socialite)
    function createAgent(
        string memory name,
        string memory symbol,
        uint8 agentType,
        string memory personality,
        string memory modelConfig,
        string memory customURI
    ) external nonReentrant whenNotPaused returns (uint256) {
        // Enhanced input validation
        _validateString(name, "name", 3, 50);
        _validateString(symbol, "symbol", 2, 6);
        _validateString(customURI, "customURI", 1, 256);
        _validateString(personality, "personality", 1, 1000);
        _validateString(modelConfig, "modelConfig", 1, 1000);
        
        if (agentType > 2) revert InvalidAgentType(agentType, 2);

        // Collect creation fee with proper checks using SafeERC20
        neoxToken.safeTransferFrom(msg.sender, address(this), creationFee);

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
            agentNFT.createAgent(
                msg.sender,
                agentId,
                agentType,
                name,
                symbol,
                customURI
            );
        }

        // Mint special ERC6551 ownership NFT to creator and store the ID
        uint256 ownershipTokenId = agentNFT.createOwnershipToken(
            msg.sender,
            agentId,
            agentType,
            name,
            symbol,
            customURI
        );
        
        // Emit an event with the ownership token ID for tracking
        emit AgentOwnershipTransferred(agentId, address(0), msg.sender, ownershipTokenId);

        // Auto-grant the creator premium tier access
        userTiers[msg.sender][agentId] = uint8(tierPremium);

        emit AgentCreated(agentId, msg.sender, agentType, name, customURI);
        emit OperationAttempted("createAgent", msg.sender, true);

        return agentId;
    }
    
    // Transfer Agent Ownership
    function transferAgentOwnership(uint256 agentId, address newOwner) external nonReentrant whenNotPaused {
        if (!agents[agentId].active) revert AgentNotActive(agentId);
        _validateAddress(newOwner, "newOwner");
        
        // Get the ownership token ID
        uint256 ownershipTokenId = agentNFT.getAgentOwnershipToken(agentId);
        if (ownershipTokenId == 0) revert NoOwnershipToken(agentId);
        
        // Check that the sender is the current owner of the ownership token
        address currentOwner = agentNFT.ownerOf(ownershipTokenId);
        if (currentOwner != msg.sender) revert NotAgentOwner(agentId, msg.sender, currentOwner);
        
        // Transfer the ownership token to the new owner
        agentNFT.transferFrom(msg.sender, newOwner, ownershipTokenId);
        
        // Update the agent creator
        address previousOwner = agents[agentId].creator;
        agents[agentId].creator = newOwner;
        
        // Update creator's agents list (remove from old owner)
        _removeAgentFromCreator(previousOwner, agentId);
        
        // Add to new owner's agents list
        creatorAgents[newOwner].push(agentId);
        
        // Grant premium tier access to the new owner
        userTiers[newOwner][agentId] = uint8(tierPremium);
        
        emit AgentOwnershipTransferred(agentId, previousOwner, newOwner, ownershipTokenId);
        emit OperationAttempted("transferAgentOwnership", msg.sender, true);
    }
    
    // Helper function to remove agent from creator's list
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
    
    // Get Ownership NFT wallet address
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
    
    // Approve an Address to Serve as a Delegate
    function setDelegationApproval(uint256 tokenId, address operator, bool approved) external whenNotPaused {
        _validateAddress(operator, "operator");
        
        address tokenOwner = agentNFT.ownerOf(tokenId);
        if (tokenOwner != msg.sender) revert NotAuthorized(msg.sender, tokenId);
        
        _tokenIdOperatorApprovals[tokenId][operator] = approved;
        
        emit DelegationApproved(tokenId, operator, approved);
        emit OperationAttempted("setDelegationApproval", msg.sender, true);
    }
    
    // Set an Address to Operate on the Agent Ownership NFT's Behalf
    function setGlobalOperator(address operator, bool approved) external onlyOwner {
        _validateAddress(operator, "operator");
        
        _globalOperators[operator] = approved;
        
        emit GlobalOperatorSet(operator, approved);
        emit OperationAttempted("setGlobalOperator", msg.sender, true);
    }
    
    // Check if an Address is Approved To Operate on Agent Ownership NFT's Behalf
    function isDelegationApproved(uint256 tokenId, address operator) public view returns (bool) {
        return _tokenIdOperatorApprovals[tokenId][operator] || _globalOperators[operator];
    }
    
    // Non-view version that emits an event - can be used when event emission is desired
    function checkAndLogDelegationStatus(uint256 tokenId, address operator) public returns (bool) {
        bool status = isDelegationApproved(tokenId, operator);
        emit DelegationStatusCheck(tokenId, operator, status);
        return status;
    }
    
    // ========================
    // Agent Execution Functions
    // ========================
    
    // Execute a Call from the Ownership NFT Wallet
    function executeFromAgent(
        uint256 agentId,
        address to,
        uint256 value,
        bytes memory data
    ) public whenNotPaused returns (bytes memory) {
        _validateAddress(to, "to");
        
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
        if (account == address(0)) revert InvalidTokenBoundAccount(account);
        
        // Execute the call to the specified address
        bytes memory result;
        try IERC6551Account(account).executeCall(to, value, data) returns (bytes memory ret) {
            result = ret;
            if (result.length == 0) revert ResultValidationFailed("executeCall", result);
        } catch Error(string memory reason) {
            revert CallExecutionFailed();
        } catch (bytes memory reason) {
            revert ResultValidationFailed("executeCall", reason);
        }
        
        emit OperationAttempted("executeFromAgent", msg.sender, true);
        
        return result;
    }
    
    // Transfer NEOX tokens from Agent Ownership NFT wallet to another wallet or contract address
    function executeNEOXTransfer(
        uint256 agentId, 
        address recipient, 
        uint256 amount
    ) external whenNotPaused returns (bytes memory) {
        _validateAddress(recipient, "recipient");
        _validateRange(amount, "amount", 1, 0);
        
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
        bool success = abi.decode(result, (bool));
        if (!success) revert TokenOperationFailed("transfer");
        
        emit NEOXTransferred(agentId, recipient, amount, success);
        emit OperationAttempted("executeNEOXTransfer", msg.sender, true);
        
        return result;
    }
    
    // ========================
    // Purchase and Usage
    // ========================
    
    // Purchase Tier Access to an Agent (Tiers 1 - 3)
    function purchaseTier(uint256 agentId, uint8 tier) external nonReentrant whenNotPaused {
        if (!agents[agentId].active) revert AgentNotActive(agentId);
        
        if (tier < tierBasic || tier > tierPremium) {
            revert InvalidTier(tier, uint8(tierBasic), uint8(tierPremium));
        }
        
        uint256 tierCost;
        if (tier == tierBasic) {
            tierCost = basicTierCost;
        } else if (tier == tierAdvanced) {
            tierCost = advancedTierCost;
        } else if (tier == tierPremium) {
            tierCost = premiumTierCost;
        }
        
        // Collect tier fee using SafeERC20
        neoxToken.safeTransferFrom(msg.sender, address(this), tierCost);
        
        // Calculate fee distribution
        uint256 creatorAmount = (tierCost * creatorPercentage) / 100;
        uint256 platformAmount = tierCost - creatorAmount;
        
        // Add platform fees to pending withdrawals
        pendingWithdrawals[owner()] += platformAmount;
        
        // Distribute to NFT holders
        bool distributionSuccess = agentNFT.distributeRevenue(agentId, creatorAmount);
        if (!distributionSuccess) {
            // If distribution fails, add to pending withdrawals for manual claiming
            pendingWithdrawals[agents[agentId].creator] += creatorAmount;
            emit RevenueDistributionFailed(agentId, creatorAmount, agents[agentId].creator);
        }
        
        // Grant tier access
        userTiers[msg.sender][agentId] = tier;
        
        emit TierPurchased(agentId, msg.sender, tier, tierCost);
        emit OperationAttempted("purchaseTier", msg.sender, true);
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
        UsageData storage userData = usageHistory[msg.sender][agentId];
        uint256 lastUsed = userData.lastUsageTime;
        if (lastUsed > 0 && block.timestamp < lastUsed + usageCooldown) {
            emit AgentRateLimitExceeded(msg.sender, agentId, lastUsed, usageCooldown);
            revert RateLimitNotElapsed(msg.sender, agentId, lastUsed, usageCooldown);
        }
        
        // Update usage data
        userData.lastUsageTime = block.timestamp;
        userData.totalUsage += 1;
        
        // Collect usage fee using SafeERC20
        neoxToken.safeTransferFrom(msg.sender, address(this), usageFee);
        
        // Track usage
        agents[agentId].usageCount++;
        
        // Record usage in NFT contract
        bool recordSuccess = agentNFT.recordUsage(agentId, msg.sender);
        if (!recordSuccess) revert TokenOperationFailed("recordUsage");
        
        // Calculate fee distribution
        uint256 creatorAmount = (usageFee * creatorPercentage) / 100;
        uint256 platformAmount = usageFee - creatorAmount;
        
        // Add platform fees to pending withdrawals
        pendingWithdrawals[owner()] += platformAmount;
        
        // Distribute to NFT holders
        bool distributionSuccess = agentNFT.distributeRevenue(agentId, creatorAmount);
        if (!distributionSuccess) {
            // If distribution fails, add to pending withdrawals for manual claiming
            pendingWithdrawals[agents[agentId].creator] += creatorAmount;
            emit RevenueDistributionFailed(agentId, creatorAmount, agents[agentId].creator);
        }
        
        emit AgentUsed(agentId, msg.sender, tier, block.timestamp);
        emit OperationAttempted("useAgent", msg.sender, true);
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
        
        // Transfer tokens to the user using SafeERC20
        emit WithdrawalRequested(msg.sender, amount);
        
        neoxToken.safeTransfer(msg.sender, amount);
        
        emit WithdrawalCompleted(msg.sender, amount);
        emit OperationAttempted("requestWithdrawal", msg.sender, true);
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
    
    // Get Ownership Token NFT ID
    function getAgentOwnershipToken(uint256 agentId) external view returns (uint256) {
        return agentNFT.getAgentOwnershipToken(agentId);
    }
    
    // Get Agent NFT Details
    function getAgent(uint256 agentId) external view returns (Agent memory) {
        return agents[agentId];
    }
    
    // Check if Address is a Global Operator
    function isGlobalOperator(address operator) external view returns (bool) {
        return _globalOperators[operator];
    }
    
    // Get rate limiting data for a user and agent
    function getUserAgentUsageData(address user, uint256 agentId) external view returns (uint256 lastUsed, uint256 totalUsage, bool canUseNow) {
        UsageData memory data = usageHistory[user][agentId];
        return (
            data.lastUsageTime,
            data.totalUsage,
            data.lastUsageTime == 0 || block.timestamp >= data.lastUsageTime + usageCooldown
        );
    }
    
    // Get creator agents with pagination
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
    
    // Update agent configuration items
    function updateAgentConfiguration(
        uint256 agentId, 
        string memory customURI,
        string memory personality,
        string memory modelConfig
    ) external nonReentrant whenNotPaused {
        // Validate inputs
        _validateString(customURI, "customURI", 1, 256);
        _validateString(personality, "personality", 1, 1000);
        _validateString(modelConfig, "modelConfig", 1, 1000);
        
        // Check ownership
        uint256 ownershipTokenId = agentNFT.getAgentOwnershipToken(agentId);
        if (ownershipTokenId == 0) revert NoOwnershipToken(agentId);
        
        address currentOwner = agentNFT.ownerOf(ownershipTokenId);
        if (currentOwner != msg.sender) revert NotAgentOwner(agentId, msg.sender, currentOwner);
        
        // Update agent configuration
        Agent storage agent = agents[agentId];
        
        agent.customURI = customURI;
        agent.personality = personality;
        agent.modelConfig = modelConfig;
        
        emit AgentConfigurationUpdated(agentId, "customURI", customURI);
        emit AgentConfigurationUpdated(agentId, "personality", personality);
        emit AgentConfigurationUpdated(agentId, "modelConfig", modelConfig);
        emit OperationAttempted("updateAgentConfiguration", msg.sender, true);
    }
    
    // Activate or deactivate an agent
    function setAgentStatus(uint256 agentId, bool active) external nonReentrant whenNotPaused {
        // Check ownership
        uint256 ownershipTokenId = agentNFT.getAgentOwnershipToken(agentId);
        if (ownershipTokenId == 0) revert NoOwnershipToken(agentId);
        
        address currentOwner = agentNFT.ownerOf(ownershipTokenId);
        if (currentOwner != msg.sender && msg.sender != owner()) revert NotAuthorized(msg.sender, ownershipTokenId);
        
        // Update status
        agents[agentId].active = active;
        
        emit AgentStatusChanged(agentId, active);
        emit OperationAttempted("setAgentStatus", msg.sender, true);
    }
}
