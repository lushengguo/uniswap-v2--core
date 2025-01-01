pragma solidity =0.5.16;

import './interfaces/IUniswapV2ERC20.sol';
import './libraries/SafeMath.sol';

contract UniswapV2ERC20 is IUniswapV2ERC20 {
    using SafeMath for uint;

    string public constant name = 'Uniswap V2';
    string public constant symbol = 'UNI-V2';
    uint8 public constant decimals = 18;

    // LP是给流动性提供者提供的那一部分手续费 不直接给他们代币 而是给他们铸造一种token叫LP
    // 这里的lpTotal指的是总量
    uint public totalSupply;
    // 每个用户的LP数量
    mapping(address => uint) public balanceOf;
    // 用户给当前合约授权的额度 这个额度指的是实际的代币数量
    mapping(address => mapping(address => uint)) public allowance;

    bytes32 public DOMAIN_SEPARATOR;
    // keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 public constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

    // 用户的nonce 用来防止重放攻击 只在permit的时候用到
    mapping(address => uint) public nonces;

    // 在 Solidity 中，event 和 emit 用于记录链上的事件，这些事件可以供外部应用程序（如前端界面或其他合约）监听和响应。
    // 事件是合约执行过程中的一种重要机制，它们不会修改区块链的状态，但是可以让外部监听者（例如 DApp）接收到合约执行时发生的关键事件。
    //
    // 事件可以包含多个参数，并且这些参数通常会被标记为 indexed，这是为了提高搜索效率。
    // Solidity 支持最多三个 indexed 参数，允许通过这些参数对事件进行过滤和索引。
    //
    // 触发事件会写日志到区块链里面 这些日志可以被外部应用程序监听到
    event Approval(address indexed owner, address indexed spender, uint value);
    event Transfer(address indexed from, address indexed to, uint value);

    constructor() public {
        uint chainId;
        assembly {
            // 以太坊有很多测试网络和私链 为了避免A网络的签名在B网络上重放 需要在签名中包含 chainId
            chainId := chainid
        }

        // from chatgpt:
        // 生成一个 EIP-712 域分隔符（DOMAIN_SEPARATOR）。
        // EIP-712 是一种标准，用于在以太坊中签署结构化数据，它允许用户签署以太坊消息，
        // 而不仅仅是签署原始字符串。这样可以防止签名被误用或被篡改，并且可以提供额外的上下文信息。
        //
        // DOMAIN_SEPARATOR 用于区分不同的签名环境。通过在结构化数据签名时包含该分隔符，
        // 可以确保即使两个合约有相同的结构，也不会互相混淆或发生签名重放攻击。
        // 这个分隔符（DOMAIN_SEPARATOR）通常在生成签名时用于加密和验证数据，防止签名信息被篡改。
        // 因为签名数据包含了链 ID 和合约地址，所以即使数据内容相同，签名的目的地（即链和合约）不同也会生成不同的签名。
        //
        // why:
        // 1. EIP-712 兼容性：通过为结构化数据签名生成域分隔符，该合约遵循 EIP-712 标准，确保数据签名是有效且不会被滥用。
        // 2. 避免签名重放攻击：包括 chainId 和 verifyingContract（合约地址）在 DOMAIN_SEPARATOR 中，
        //    确保签名仅适用于特定链和特定合约，从而防止签名在不同链或不同合约中被重放。
        // 3. 防篡改：在签署的消息中包含 DOMAIN_SEPARATOR 使得攻击者无法伪造合法的签名或将签名应用于不同的环境（例如从 Ropsten 网络转到主网）。
        //
        // 我的理解就是加了个namespace 用来区分不同的签名环境 防止了下面几个入参相关的重放攻击 这个namespace也会包含在签名里
        // 至于同一个domain sepertor下的重放攻击 是由用户签名保障的 每笔交易里含用户的nonce/trade id
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
                keccak256(bytes(name)),
                keccak256(bytes('1')),
                chainId,
                address(this)
            )
        );
    }

    // 铸币 币名叫LP 铸造一些仅在合约内有效的代币 用于证明他所提供的流动性占所有流动性的比例
    // 这个比例在提现的时候会用到 提取他所提供的流动性等价的代币和成比例的手续费
    function _mint(address to, uint value) internal {
        totalSupply = totalSupply.add(value);
        balanceOf[to] = balanceOf[to].add(value);
        emit Transfer(address(0), to, value);
    }

    // 销毁LP 用来套现
    function _burn(address from, uint value) internal {
        balanceOf[from] = balanceOf[from].sub(value);
        totalSupply = totalSupply.sub(value);
        emit Transfer(from, address(0), value);
    }

    function _approve(address owner, address spender, uint value) private {
        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    function _transfer(address from, address to, uint value) private {
        balanceOf[from] = balanceOf[from].sub(value);
        balanceOf[to] = balanceOf[to].add(value);
        emit Transfer(from, to, value);
    }

    // 授权其他的合约/用户可以花费自己的token
    // 这个函数是ERC20的标准函数
    // 与之对应的是transferFrom 这两个函数本身保障了用户的资金安全
    // _approve里只是对这个数据做了一个缓存到allowance
    //
    // 比如用户要提供流动性 就要先approve给这个合约一些token
    // 然后调用addLiquidity 这时候合约会调用transferFrom把用户的token转到合约
    function approve(address spender, uint value) external returns (bool) {
        _approve(msg.sender, spender, value);
        return true;
    }

    function transfer(address to, uint value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint value) external returns (bool) {
        // uint(-1)是个magic number 代表不限制额度 所以也不需要把授权额度降低
        if (allowance[from][msg.sender] != uint(-1)) {
            allowance[from][msg.sender] = allowance[from][msg.sender].sub(value);
        }
        _transfer(from, to, value);
        return true;
    }

    // from chatgpt:
    // 函数使用了 EIP-2612 标准，它允许用户通过签名而不是交易来授权其他地址（spender）转移他们的代币。
    // 通过这种方式，用户不需要支付交易的 Gas 费来进行授权。
    // -> v r s 可以证明ower就是用户本人
    //
    // approve的时候需要提供汽油费 这个函数不需要提供汽油费
    function permit(
        address owner,
        address spender,
        uint value,
        uint deadline,
        // 这些是 ECDSA 签名的三个部分（即签名的恢复值和两个哈希值）。
        // v 是签名的恢复标识符（0 或 1），r 和 s 是签名的两个哈希值。
        // 这三个参数是用户用私钥签名的结果。
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(deadline >= block.timestamp, 'UniswapV2: EXPIRED');
        bytes32 digest = keccak256(
            abi.encodePacked(
                // \x19\x01 是 EIP-191 标准的一部分，它指定了消息格式的版本。
                '\x19\x01',
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        // PERMIT_TYPEHASH 是一个常量，表示授权签名的类型哈希。
                        PERMIT_TYPEHASH,
                        owner,
                        spender,
                        value,
                        // nonces[owner]++ 是 owner 地址的签名使用计数器，确保每个签名的唯一性，防止重放攻击。
                        // 这里++会修改nonces[owner]的值 如果下面的require失败了 合约里的数据都会回滚
                        // 所以不用担心这里数据状态变更
                        nonces[owner]++,
                        deadline
                    )
                )
            )
        );

        // 用户在本地用一模一样的方法生成了digest 然后用私钥签名、推算出v r s
        // v r s可以反推出地址
        // hint: 私钥可以计算出公钥 公钥可以计算出地址
        // 因为这个函数不用提供汽油费 所以要用签名来证明自己是这个地址的拥有者
        address recoveredAddress = ecrecover(digest, v, r, s);

        // address(0)是一个特殊的地址 代表无效地址
        require(recoveredAddress != address(0) && recoveredAddress == owner, 'UniswapV2: INVALID_SIGNATURE');
        _approve(owner, spender, value);
    }
}
