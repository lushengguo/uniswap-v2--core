pragma solidity =0.5.16;

import './interfaces/IUniswapV2Factory.sol';
import './UniswapV2Pair.sol';

// factory存在的必要性说明：
// 1.提供创建pair的方式，在去中心化的系统里，任何人都可以调用createPair
// 2.可以在getPair里看流动性池是否是由这个工厂创建的 
//   因为流动性池是另一个合约地址 这个合约地址的生成规则是固定的 
//   如果新出现了一个币叫dio coin 有恶意攻击的人仿造了流动性池(eth,dio)的接口 创建了合约 
//   如果有factory 用户就可以检查这个合约地址是否是一个有效的uniswap的流动性池
//   没有的话大家就没发验证 当然这样也不能防止有人直接跳过factory访问流动性池
// 
// 简单来说就是这个类用来创建两种token的映射
// 比如这个合约刚部署到链上的时候 里面是空的 找不到token的映射关系
// 用户想直接调用addLiqudity方法添加流动性是不行的
// 所以用户需要先调用createPair方法创建这一对token的pair
contract UniswapV2Factory is IUniswapV2Factory {
    // 这是一个地址，表示当前协议手续费的接收者。
    // 当流动性提供者移除流动性时，如果协议启用了手续费功能，部分手续费将被铸造为额外的 LP 代币，并分配给 feeTo 地址。
    // 如果 feeTo 设置为 address(0)，意味着当前协议未启用手续费分成，所有手续费收入全部归流动性提供者所有。
    //
    // 当 Uniswap V2 部署后，开发团队通常会设置 feeToSetter 为自己的地址，初始控制权限在团队手中。
    // 如果协议手续费分成被启用，feeTo 将接收所有分成产生的收益。
    // 随着协议的成熟，feeToSetter 和 feeTo 的控制权通常会转交给社区治理合约。
    // 社区可以通过投票决定：
    // 1. 是否启用协议分成。
    // 2. 将 feeTo 设置为特定的公共地址（例如，协议国库、DAO 等）。
    //
    // feeTo 可能的角色
    // 1.开发团队地址：用于早期开发阶段的费用补偿。
    // 2.治理合约：社区投票控制。
    // 3.公益地址：协议捐赠或支持生态发展的资金池。
    address public feeTo;

    // 这是一个地址，表示可以设置 feeTo 地址的管理员。
    // 只有 feeToSetter 拥有权限更改 feeTo 地址。
    // 通过这个机制，Uniswap 的开发团队或治理社区可以管理协议手续费的接收者。
    address public feeToSetter;

    mapping(address => mapping(address => address)) public getPair;
    address[] public allPairs;

    event PairCreated(address indexed token0, address indexed token1, address pair, uint);

    // 这玩意一般只会被构造一次 绑定了一个流动性池
    // 也不是说其他人不能创建流动性池 只是开发人员花了很大力气才把流动性池做起来
    // 你自己创建一个也没人来跟你玩
    constructor(address _feeToSetter) public {
        feeToSetter = _feeToSetter;
    }

    function allPairsLength() external view returns (uint) {
        return allPairs.length;
    }

    function createPair(address tokenA, address tokenB) external returns (address pair) {
        require(tokenA != tokenB, 'UniswapV2: IDENTICAL_ADDRESSES');
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        // 因为前面排序了 所以token0是更小的那个 如果token0不是0地址 那么token1也不是0地址
        require(token0 != address(0), 'UniswapV2: ZERO_ADDRESS');
        require(getPair[token0][token1] == address(0), 'UniswapV2: PAIR_EXISTS'); // single check is sufficient

        // creationCode 是 UniswapV2Pair 合约的字节码，用于部署新合约。
        bytes memory bytecode = type(UniswapV2Pair).creationCode;

        // salt 是一个通过 keccak256 生成的哈希值，它基于 token0 和 token1 的地址。
        // 目的：通过 salt 保证同一对代币的交易对地址是可预测和唯一的。
        bytes32 salt = keccak256(abi.encodePacked(token0, token1));
        assembly {
            // create2(value, bytecode, size, salt)
            // value: 用于创建合约时转移的以太币（此处为 0）。
            // bytecode: 合约的创建代码。
            // size: 合约字节码的长度。
            // salt: 唯一的种子，用于生成合约地址。
            //
            // 为什么使用 create2:
            // 可预测性: 给定相同的 salt 和字节码，生成的合约地址总是相同的。
            // 防止重复创建: 如果尝试用相同的 salt 再次部署，会失败（合约地址已存在）。
            // 确定性: 合约地址的生成可以通过链上或链下计算，从而不需要预先部署即可知道地址。
            // 
            // 不管任何人 使用相同的代码 最后指向的流动池的合约地址都是同一个
            pair := create2(0, add(bytecode, 32), mload(bytecode), salt)
        }

        // 这东西代表一个流动性池 里面有两种token
        // 流动池的构造函数记录了factory的地址 
        // 所以开发人员用创建了Factory，然后创建流动性池，然后大家来用
        // 其他人用同样的代码创建Factory是没用的 因为算出来的流动性池地址是同一个 所以create2会失败
        // 如果改了代码 那么流动性池的地址也会改变 没人认你这一套
        IUniswapV2Pair(pair).initialize(token0, token1);

        getPair[token0][token1] = pair;
        getPair[token1][token0] = pair; // populate mapping in the reverse direction
        allPairs.push(pair);
        emit PairCreated(token0, token1, pair, allPairs.length);
    }

    function setFeeTo(address _feeTo) external {
        require(msg.sender == feeToSetter, 'UniswapV2: FORBIDDEN');
        feeTo = _feeTo;
    }

    function setFeeToSetter(address _feeToSetter) external {
        require(msg.sender == feeToSetter, 'UniswapV2: FORBIDDEN');
        feeToSetter = _feeToSetter;
    }
}
