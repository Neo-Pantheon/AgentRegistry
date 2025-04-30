// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

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
    address public registry;
    
    // Constants
    uint256 public creationFee = 25000 * 10**18; // 25,000 NEOX
    uint256 public usageFee = 10 * 10**18;      // 10 NEOX per use
    uint8 public constant NFT_COUNT = 12;       // Fixed at 12 NFTs per agent
    
    // Deployment tiers
    uint8 public constant TIER_BASIC = 1;
    uint8 public constant TIER_ADVANCED = 2;
    uint8 public constant TIER_PREMIUM = 3;
    
    // Fee distribution
    uint256 public creatorPercentage = 70; // 70% to creator
    uint256 public platformPercentage = 30; // 30% to platform
    
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
    
    // Delegation structures
    mapping(uint256 => mapping(address => bool)) private _tokenIdOperatorApprovals;
    mapping(address => bool) private _globalOperators;
    
    // Mappings
    mapping(uint256 => Agent) public agents;
    mapping(address => uint256[]) public creatorAgents;
    mapping(address => mapping(uint256 => uint8)) public userTiers; // user => agentId => tier
    
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
    event RevenueDistributionFailed(uint256 indexed agentId, uint256 amount);
    event EmergencyWithdraw(address indexed recipient, uint256 amount);
    
    constructor(address _neoxToken, address _agentNFT) Ownable(msg.sender) {
        require(_neoxToken != address(0), "Zero address for NEOX token");
        require(_agentNFT != address(0), "Zero address for agent NFT");
        
        neoxToken = IERC20(_neoxToken);
        agentNFT = ITBAgentNFT(_agentNFT);
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
    
    function emergencyWithdraw(address recipient) external onlyOwner {
        require(recipient != address(0), "Zero address recipient");
        uint256 balance = neoxToken.balanceOf(address(this));
        require(balance > 0, "No tokens to withdraw");
        
        bool success = neoxToken.transfer(recipient, balance);
        require(success, "Token transfer failed");
        
        emit EmergencyWithdraw(recipient, balance);
    }
    
    // ========================
    // Main Functions
    // ========================
    
    // Create The AI Agent 12 NFTs & Ownership NFT Token (agentType is 0 = Builder, 1 = Researcher, 2 = Socialite)
    function createAgent(
        string memory name,
        string memory symbol,
        uint8 agentType,
        string memory personality,
        string memory modelConfig,
        string memory customURI
    ) external nonReentrant whenNotPaused returns (uint256) {
        require(bytes(name).length >= 3, "Name too short");
        require(bytes(symbol).length >= 2 && bytes(symbol).length <= 6, "Invalid symbol length");
        require(agentType <= 2, "Invalid agent type");
        require(bytes(customURI).length > 0, "Custom URI cannot be empty");

        // Collect creation fee with proper checks
        require(neoxToken.transferFrom(msg.sender, address(this), creationFee), "Fee collection failed");

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

        // Mint exactly 12 NFTs to creator (regular revenue-sharing NFTs)
        for (uint8 i = 0; i < NFT_COUNT; i++) {
            agentNFT.createAgent(
                msg.sender,
                agentId,
                agentType,
                name,
                symbol,
                customURI
            );
        }

        // Mint special ERC6551 ownership NFT to creator
        uint256 ownershipTokenId = agentNFT.createOwnershipToken(
            msg.sender,
            agentId,
            agentType,
            name,
            symbol,
            customURI
        );

        // Auto-grant the creator premium tier access
        userTiers[msg.sender][agentId] = TIER_PREMIUM;

        emit AgentCreated(agentId, msg.sender, agentType, name, customURI);

        return agentId;
    }
    
    // Transfer Agent Ownership
    function transferAgentOwnership(uint256 agentId, address newOwner) external nonReentrant whenNotPaused {
        require(agents[agentId].active, "Agent not active");
        require(newOwner != address(0), "Invalid address");
        
        // Get the ownership token ID
        uint256 ownershipTokenId = agentNFT.getAgentOwnershipToken(agentId);
        require(ownershipTokenId > 0, "No ownership token");
        
        // Check that the sender is the current owner of the ownership token
        require(agentNFT.ownerOf(ownershipTokenId) == msg.sender, "Not the owner");
        
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
        userTiers[newOwner][agentId] = TIER_PREMIUM;
        
        emit AgentOwnershipTransferred(agentId, previousOwner, newOwner, ownershipTokenId);
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
        require(ownershipTokenId > 0, "No ownership token");
        return agentNFT.getTokenBoundAccount(ownershipTokenId);
    }
    
    // ========================
    // Delegation Management
    // ========================
    
    // Approve an Address to Serve as a Delegate
    function setDelegationApproval(uint256 tokenId, address operator, bool approved) external whenNotPaused {
        require(operator != address(0), "Zero address operator");
        require(agentNFT.ownerOf(tokenId) == msg.sender, "Not token owner");
        _tokenIdOperatorApprovals[tokenId][operator] = approved;
        emit DelegationApproved(tokenId, operator, approved);
    }
    
    // Set an Address to Operate on the Agent Ownership NFT's Behalf
    function setGlobalOperator(address operator, bool approved) external onlyOwner {
        require(operator != address(0), "Zero address operator");
        _globalOperators[operator] = approved;
        emit GlobalOperatorSet(operator, approved);
    }
    
    // Check if an Address is Approved To Operate on Agent Ownership NFT's Behalf
    function isDelegationApproved(uint256 tokenId, address operator) public view returns (bool) {
        return _tokenIdOperatorApprovals[tokenId][operator] || _globalOperators[operator];
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
        require(to != address(0), "Zero address recipient");
        
        // Fetch the ownership token ID from the agentNFT contract
        uint256 ownershipTokenId = agentNFT.getAgentOwnershipToken(agentId);
        require(ownershipTokenId > 0, "No ownership token");

        // Get the token owner
        address tokenOwner = agentNFT.ownerOf(ownershipTokenId);
        
        // Authentication check
        bool isAuthorized = 
            msg.sender == tokenOwner || // Token owner
            msg.sender == owner() || // Contract owner
            msg.sender == agentNFT.approvedRegistry() || // Approved registry
            isDelegationApproved(ownershipTokenId, msg.sender); // Delegated operator
            
        require(isAuthorized, "Not authorized");
        
        // Get the account associated with the ownership token
        address payable account = payable(agentNFT.getTokenBoundAccount(ownershipTokenId));
        require(account != address(0), "Invalid token bound account");
        
        // Execute the call to the specified address
        bytes memory result = IERC6551Account(account).executeCall(to, value, data);
        require(result.length > 0, "Call execution failed");
        
        return result;
    }
    
    // Transfer NEOX tokens from Agent Ownership NFT wallet to another wallet or contract address
    function executeNEOXTransfer(
        uint256 agentId, 
        address recipient, 
        uint256 amount
    ) external whenNotPaused returns (bytes memory) {
        require(recipient != address(0), "Zero address recipient");
        require(amount > 0, "Zero amount");
        
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
        require(success, "Transfer failed");
        
        emit NEOXTransferred(agentId, recipient, amount);
        
        return result;
    }
    
    // Transfer NFT from Agent Ownership NFT wallet to another wallet or contract address
    function executeNFTTransfer(
        uint256 agentId, 
        address nftContract, 
        address recipient, 
        uint256 tokenId
    ) external whenNotPaused returns (bytes memory) {
        require(nftContract != address(0), "Zero address NFT contract");
        require(recipient != address(0), "Zero address recipient");
        
        // Get the agent's token bound account address
        address agentAccount;
        {
            uint256 ownershipTokenId = agentNFT.getAgentOwnershipToken(agentId);
            require(ownershipTokenId > 0, "No ownership token");
            agentAccount = agentNFT.getTokenBoundAccount(ownershipTokenId);
            require(agentAccount != address(0), "Invalid token bound account");
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
        require(result.length > 0, "NFT transfer failed");
        
        emit NFTTransferred(agentId, nftContract, recipient, tokenId);
        
        return result;
    }
    
    // ========================
    // Purchase and Usage
    // ========================
    
    // Purchase Tier Access to an Agent (Tiers 1 - 3)
    function purchaseTier(uint256 agentId, uint8 tier) external nonReentrant whenNotPaused {
        require(agents[agentId].active, "Agent not active");
        require(tier >= TIER_BASIC && tier <= TIER_PREMIUM, "Invalid tier");
        
        uint256 tierCost;
        if (tier == TIER_BASIC) {
            tierCost = 100 * 10**18; // 100 NEOX
        } else if (tier == TIER_ADVANCED) {
            tierCost = 500 * 10**18; // 500 NEOX
        } else if (tier == TIER_PREMIUM) {
            tierCost = 2000 * 10**18; // 2000 NEOX
        }
        
        // Collect tier fee
        require(neoxToken.transferFrom(msg.sender, address(this), tierCost), "Fee transfer failed");
        
        // Calculate fee distribution
        uint256 creatorAmount = (tierCost * creatorPercentage) / 100;
        uint256 platformAmount = tierCost - creatorAmount;
        
        // Add platform fees to pending withdrawals
        pendingWithdrawals[owner()] += platformAmount;
        
        // Distribute to NFT holders (70%)
        bool distributionSuccess = agentNFT.distributeRevenue(agentId, creatorAmount);
        if (!distributionSuccess) {
            // If distribution fails, add to pending withdrawals for manual claiming
            pendingWithdrawals[agents[agentId].creator] += creatorAmount;
            emit RevenueDistributionFailed(agentId, creatorAmount);
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
        require(agents[agentId].active, "Agent not active");
        
        // Check tier access
        uint8 tier = userTiers[msg.sender][agentId];
        require(tier > 0, "No tier access");
        
        // Collect usage fee
        require(neoxToken.transferFrom(msg.sender, address(this), usageFee), "Fee transfer failed");
        
        // Track usage
        agents[agentId].usageCount++;
        
        // Record usage in NFT contract
        bool recordSuccess = agentNFT.recordUsage(agentId, msg.sender);
        require(recordSuccess, "Usage recording failed");
        
        // Calculate fee distribution
        uint256 creatorAmount = (usageFee * creatorPercentage) / 100;
        uint256 platformAmount = usageFee - creatorAmount;
        
        // Add platform fees to pending withdrawals
        pendingWithdrawals[owner()] += platformAmount;
        
        // Distribute to NFT holders (70%)
        bool distributionSuccess = agentNFT.distributeRevenue(agentId, creatorAmount);
        if (!distributionSuccess) {
            // If distribution fails, add to pending withdrawals for manual claiming
            pendingWithdrawals[agents[agentId].creator] += creatorAmount;
            emit RevenueDistributionFailed(agentId, creatorAmount);
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
        require(amount > 0, "No funds to withdraw");
        
        // Reset pending withdrawal before transfer to prevent reentrancy
        pendingWithdrawals[msg.sender] = 0;
        
        // Transfer tokens to the user
        bool success = neoxToken.transfer(msg.sender, amount);
        require(success, "Transfer failed");
        
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
}
