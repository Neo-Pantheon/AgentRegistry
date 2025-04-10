// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./AgentNFT.sol";

contract AgentRegistry is Ownable {
    using Counters for Counters.Counter;
    
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
    AgentNFT public agentNFT;
    
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
    
    constructor(address _neoxToken, address _agentNFT) Ownable(msg.sender) {
        neoxToken = IERC20(_neoxToken);
        agentNFT = AgentNFT(_agentNFT);
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
        
        // Mint exactly 12 NFTs to creator
        for (uint8 i = 0; i < NFT_COUNT; i++) {
            agentNFT.createAgent(msg.sender, agentId, agentType, name, symbol, customURI);
        }
        
        // Auto-grant the creator premium tier access
        userTiers[msg.sender][agentId] = TIER_PREMIUM;
        
        emit AgentCreated(agentId, msg.sender, agentType, name, customURI);
        
        return agentId;
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
     * @dev Get complete agent details including configuration
     * @param agentId Agent ID
     */
    function getAgentDetails(uint256 agentId) external view returns (
        string memory name,
        string memory symbol,
        uint8 agentType,
        address creator,
        uint256 createdAt,
        uint256 usageCount,
        bool active,
        string memory customURI,
        string memory personality,
        string memory modelConfig
    ) {
        Agent storage agent = agents[agentId];
        require(agent.createdAt > 0, "Agent does not exist");
        
        return (
            agent.name,
            agent.symbol,
            agent.agentType,
            agent.creator,
            agent.createdAt,
            agent.usageCount,
            agent.active,
            agent.customURI,
            agent.personality,
            agent.modelConfig
        );
    }
    
    /**
     * @dev Get all agents created by an address
     * @param creator Creator address
     */
    function getCreatorAgents(address creator) external view returns (uint256[] memory) {
        return creatorAgents[creator];
    }
    
    /**
     * @dev Set fees (owner only)
     * @param _creationFee New creation fee
     * @param _usageFee New usage fee
     */
    function setFees(uint256 _creationFee, uint256 _usageFee) external onlyOwner {
        creationFee = _creationFee;
        usageFee = _usageFee;
    }
    
    /**
     * @dev Set fee distribution (owner only)
     * @param _creatorPercentage Percentage to creator (0-100)
     */
    function setFeeDistribution(uint256 _creatorPercentage) external onlyOwner {
        require(_creatorPercentage <= 100, "Invalid percentage");
        creatorPercentage = _creatorPercentage;
        platformPercentage = 100 - _creatorPercentage;
    }
    
    /**
     * @dev Withdraw platform fees (owner only)
     */
    function withdrawFees() external onlyOwner {
        uint256 balance = neoxToken.balanceOf(address(this));
        neoxToken.transfer(owner(), balance);
    }
}
