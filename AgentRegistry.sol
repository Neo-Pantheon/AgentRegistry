// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./TBAgentNFT.sol";

interface ITBAgentNFT {
    function createAgent(address to, uint256 agentId, uint8 agentType, string calldata name, string calldata symbol, string calldata customURI) external returns (uint256);
    function createOwnershipToken(address to, uint256 agentId, uint8 agentType, string memory name, string memory symbol, string memory customURI) external returns (uint256);
    function getAgentOwnershipToken(uint256 agentId) external view returns (uint256);
    function getTokenBoundAccount(uint256 tokenId) external view returns (address);
    function recordUsage(uint256 agentId, address user) external;
    function distributeRevenue(uint256 agentId, uint256 amount) external;
    function ownerOf(uint256 tokenId) external view returns (address);
    function transferFrom(address from, address to, uint256 tokenId) external;
    function approvedRegistry() external view returns (address);
}

contract TBAgentRegistry is Ownable {
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
    TBAgentNFT public agentNFT;
    
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
    
    // Mappings
    mapping(uint256 => Agent) public agents;
    mapping(address => uint256[]) public creatorAgents;
    mapping(address => mapping(uint256 => uint8)) public userTiers; // user => agentId => tier
    
    // Events
    event AgentCreated(uint256 indexed agentId, address indexed creator, uint8 agentType, string name, string customURI);
    event AgentUsed(uint256 indexed agentId, address indexed user, uint8 tier);
    event TierPurchased(uint256 indexed agentId, address indexed user, uint8 tier);
    event AgentOwnershipTransferred(uint256 indexed agentId, address indexed previousOwner, address indexed newOwner, uint256 ownershipTokenId);
    
    constructor(address _neoxToken, address _agentNFT) Ownable(msg.sender) {
        neoxToken = IERC20(_neoxToken);
        agentNFT = TBAgentNFT(_agentNFT);
    }
    
    /**
     * @dev Create a new agent
     * @param name Agent name
     * @param symbol Agent symbol
     * @param agentType Agent type (0=Builder, 1=Researcher, 2=Socialite)
     * @param personality Agent personality
     * @param modelConfig AI model configuration
     * @param customURI Custom token URI for the NFT metadata
     * @return agentId Newly created agent ID
     */
    function createAgent(
        string memory name,
        string memory symbol,
        uint8 agentType,
        string memory personality,
        string memory modelConfig,
        string memory customURI
    ) external returns (uint256) {
        require(bytes(name).length >= 3, "Name too short");
        require(bytes(symbol).length >= 2 && bytes(symbol).length <= 6, "Invalid symbol length");
        require(agentType <= 2, "Invalid agent type");
        require(bytes(customURI).length > 0, "Custom URI cannot be empty");

        // Collect creation fee
        neoxToken.transferFrom(msg.sender, address(this), creationFee);

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

        // Mint special ERC6551 ownership NFT to creator first
        uint256 ownershipTokenId = agentNFT.createOwnershipToken(
            msg.sender,
            agentId,
            agentType,
            name,
            symbol,
            customURI
        );

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

        // Auto-grant the creator premium tier access
        userTiers[msg.sender][agentId] = TIER_PREMIUM;

        emit AgentCreated(agentId, msg.sender, agentType, name, customURI);

        return agentId;
    }
    
    /**
     * @dev Transfer ownership of an agent to a new address
     * @param agentId Agent ID
     * @param newOwner Address of the new owner
     */
    function transferAgentOwnership(uint256 agentId, address newOwner) external {
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
        uint256[] storage creatorAgentsList = creatorAgents[previousOwner];
        for (uint256 i = 0; i < creatorAgentsList.length; i++) {
            if (creatorAgentsList[i] == agentId) {
                creatorAgentsList[i] = creatorAgentsList[creatorAgentsList.length - 1];
                creatorAgentsList.pop();
                break;
            }
        }
        
        // Add to new owner's agents list
        creatorAgents[newOwner].push(agentId);
        
        // Grant premium tier access to the new owner
        userTiers[newOwner][agentId] = TIER_PREMIUM;
        
        emit AgentOwnershipTransferred(agentId, previousOwner, newOwner, ownershipTokenId);
    }
    
    /**
     * @dev Get the token bound account address for an agent
     * @param agentId Agent ID
     * @return The address of the token bound account
     */
    function getAgentTokenBoundAccount(uint256 agentId) external view returns (address) {
        uint256 ownershipTokenId = agentNFT.getAgentOwnershipToken(agentId);
        require(ownershipTokenId > 0, "No ownership token");
        return agentNFT.getTokenBoundAccount(ownershipTokenId);
    }
    
    /**
     * @dev Execute a call from the agent's token bound account
     * @param agentId Agent ID
     * @param to Target address
     * @param value ETH value
     * @param data Call data
     * @param nftContract The nftContract address as a parameter
     * @return Result of the call
     */
    function executeFromAgent(
        uint256 agentId,
        address to,
        uint256 value,
        bytes calldata data,
        address nftContract
    ) external returns (bytes memory) {
        // Fetch the ownership token ID from the agentNFT contract
        uint256 ownershipTokenId = TBAgentNFT(nftContract).getAgentOwnershipToken(agentId);
        require(ownershipTokenId > 0, "No ownership token");

        // Access the approved registry from the nftContract (TBAgentNFT)
        TBAgentNFT agentNFT = TBAgentNFT(nftContract);
        address approvedRegistry = agentNFT.approvedRegistry();

        // Ensure that msg.sender is either the owner of the contract or the approved registry
        require(
            msg.sender == owner() || msg.sender == approvedRegistry, "Not token owner"
        );

        // Get the account associated with the ownership token
        address payable account = payable(agentNFT.getTokenBoundAccount(ownershipTokenId));
    
        // Execute the call to the specified address
        return IERC6551Account(account).executeCall(to, value, data);
    }

    /**
     * @dev Purchase tier access to an agent
     * @param agentId Agent ID
     * @param tier Tier level (1-3)
     */
    function purchaseTier(uint256 agentId, uint8 tier) external {
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
        neoxToken.transferFrom(msg.sender, address(this), tierCost);
        
        // Distribute to NFT holders (70%)
        uint256 creatorAmount = (tierCost * creatorPercentage) / 100;
        agentNFT.distributeRevenue(agentId, creatorAmount);
        
        // Grant tier access
        userTiers[msg.sender][agentId] = tier;
        
        emit TierPurchased(agentId, msg.sender, tier);
    }
    
    /**
     * @dev Use an agent (requires tier access)
     * @param agentId Agent ID
     */
    function useAgent(uint256 agentId) external {
        require(agents[agentId].active, "Agent not active");
        
        // Check tier access
        uint8 tier = userTiers[msg.sender][agentId];
        require(tier > 0, "No tier access");
        
        // Collect usage fee
        neoxToken.transferFrom(msg.sender, address(this), usageFee);
        
        // Track usage
        agents[agentId].usageCount++;
        
        // Record usage in NFT contract
        agentNFT.recordUsage(agentId, msg.sender);
        
        // Distribute to NFT holders (70%)
        uint256 creatorAmount = (usageFee * creatorPercentage) / 100;
        agentNFT.distributeRevenue(agentId, creatorAmount);
        
        emit AgentUsed(agentId, msg.sender, tier);
    }
    
    /**
     * @dev Get the ownership token ID for an agent
     * @param agentId Agent ID
     * @return tokenId Ownership NFT token ID
     */
    function getAgentOwnershipToken(uint256 agentId) external view returns (uint256) {
        return agentNFT.getAgentOwnershipToken(agentId);
    }
    
    /**
     * @dev Get complete agent details including owner data
     * @param agentId Agent ID
     * @return agent Agent data structure
     */
    function getAgent(uint256 agentId) external view returns (Agent memory) {
        return agents[agentId];
    }
    
    /**
     * @dev Get the current agent ID counter value
     * @return Current agent ID counter value
     */
    function getCurrentAgentId() external view returns (uint256) {
        return _agentIdCounter.current();
    }
    
    /**
     * @dev Get the ownership token wallet address for an agent
     * @param agentId Agent ID
     * @return The address of the ownership token wallet
     */
    function getOwnershipTokenWalletAddress(uint256 agentId) external view returns (address) {
        uint256 ownershipTokenId = agentNFT.getAgentOwnershipToken(agentId);
        require(ownershipTokenId > 0, "No ownership token found for agent");
        address walletAddress = agentNFT.getTokenBoundAccount(ownershipTokenId);
        require(walletAddress != address(0), "Invalid wallet address");
        return walletAddress;
    }
}
