pragma solidity =0.5.16;

import './interfaces/IUniswapV2Pair.sol';
import './UniswapV2ERC20.sol';
import './libraries/Math.sol';
import './libraries/UQ112x112.sol';
import './interfaces/IERC20.sol';
import './interfaces/IUniswapV2Factory.sol';
import './interfaces/IUniswapV2Callee.sol';

contract UniswapV2Pair is IUniswapV2Pair, UniswapV2ERC20 {
    using SafeMath for uint;
    using UQ112x112 for uint224;

    uint public constant MINIMUM_LIQUIDITY = 10 ** 3;
    bytes4 private constant SELECTOR = bytes4(keccak256(bytes('transfer(address,uint256)')));

    address public factory;
    address public token0;
    address public token1;

    uint112 private reserve0; // uses single storage slot, accessible via getReserves
    uint112 private reserve1; // uses single storage slot, accessible via getReserves
    uint32 private blockTimestampLast; // uses single storage slot, accessible via getReserves

    uint public price0CumulativeLast;
    uint public price1CumulativeLast;
    uint public kLast; // reserve0 * reserve1, as of immediately after the most recent liquidity event

    uint private unlocked = 1;
    // lock用于mark一个函数 在一次函数调用的时候只能被调用一次
    // 避免重入攻击 肖臻课上说过有黑客利用漏洞 让合约内函数调用自己的某个函数
    // 比如合约给自己转钱的时候 如果没有实现transfer 就会调用一个用户提供的fallback函数
    // 在自己的这个函数里再调用目标合约的某个函数
    // 这样就可以通过递归多次修改合约状态
    //
    // 这个函数是一个modifier 用于修饰函数
    // 修饰器是 Solidity 的一种特殊语法，用于在函数执行前或执行后执行一些操作。
    modifier lock() {
        require(unlocked == 1, 'UniswapV2: LOCKED');
        unlocked = 0;
        // 在一个修饰符中，_; 被用来指定修饰符中的代码应当在何时执行被修饰的函数体。
        _;
        unlocked = 1;
    }

    function getReserves() public view returns (uint112 reserve0, uint112 reserve1, uint32 oldBlockTimestampLast) {
        reserve0 = reserve0;
        reserve1 = reserve1;
        oldBlockTimestampLast = blockTimestampLast;
    }

    function _safeTransfer(address token, address to, uint value) private {
        // token.call 是一个低级调用，它直接调用目标代币合约的 transfer 方法。
        // 返回值：
        // success：表示调用是否成功（合约是否返回了 true）。
        // data：目标合约的返回数据。
        //
        // bytes4 private constant SELECTOR = bytes4(keccak256(bytes('transfer(address,uint256)')));
        // selector相当于用来定位一个函数的唯一标识符
        // 这一大堆其实就是吊用了token的transfer
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(SELECTOR, to, value));

        // ERC20 标准规定 transfer 方法返回一个布尔值（true 表示转账成功）。
        // 有些老版本的 ERC20 合约并不返回值，因此 data.length == 0 用于兼容这种情况。
        require(success && (data.length == 0 || abi.decode(data, (bool))), 'UniswapV2: TRANSFER_FAILED');
    }

    event Mint(address indexed sender, uint amount0, uint amount1);
    event Burn(address indexed sender, uint amount0, uint amount1, address indexed to);
    event Swap(
        address indexed sender,
        uint amount0In,
        uint amount1In,
        uint amount0Out,
        uint amount1Out,
        address indexed to
    );
    event Sync(uint112 reserve0, uint112 reserve1);

    constructor() public {
        factory = msg.sender;
    }

    // called once by the factory at time of deployment
    function initialize(address _token0, address _token1) external {
        // 因为factory里面会记录一些pair的信息 如果不是从factory创建的
        // factory里就不会包含这部分信息 从factory再次创建会失败 因为地址冲突 - 地址是通过固定的规则生成的
        //
        // 这里有个潜在的攻击方式 因为factory代码是公开的 所以对于两个token 有人可以提前算出pair的地址
        // 然后用create0提前占用这个地址 这样子factory在调用create0的时候就必然失败
        // 攻击者付出了gas但没有实际的收益 但会影响到uniswap创建流动性池
        require(msg.sender == factory, 'UniswapV2: FORBIDDEN'); // sufficient check
        token0 = _token0;
        token1 = _token1;
    }

    // update reserves and, on the first call per block, price accumulators
    function _update(uint balance0, uint balance1, uint112 reserve0, uint112 reserve1) private {
        require(balance0 <= uint112(-1) && balance1 <= uint112(-1), 'UniswapV2: OVERFLOW');

        // 相当于block.timestamp % (2 ^ 32)
        // block.timestamp是uint256
        // block.timestamp 是由矿工设置的，具有一定程度的不确定性
        uint32 blockTimestamp = uint32(block.timestamp % 2 ** 32);

        // 如果溢出 10 - ( 2^32 - 1) = 10 + 1 = 11
        uint32 timeElapsed = blockTimestamp - blockTimestampLast; // overflow is desired

        if (timeElapsed > 0 && reserve0 != 0 && reserve1 != 0) {
            // * never overflows, and + overflow is desired

            // UQ112x112.encode()
            // 用于固定点数运算的编码方式，表示一个 112.112 位的定点数，用来实现更高精度的价格计算
            //
            // uint price0 = UQ112x112.encode(reserve1).uqdiv(reserve0);
            // uint price1 = UQ112x112.encode(reserve0).uqdiv(reserve1);
            // price0：表示 1 个 token0 值多少 token1。
            // price1：表示 1 个 token1 值多少 token0。
            // price0CumulativeLast += price0 * timeElapsed;
            // price1CumulativeLast += price1 * timeElapsed;
            // 这样可以记录每秒钟的价格变化。
            // 通过 priceCumulative 的变化量可以计算时间加权平均价格（TWAP）。
            //
            // 这个值是给外部用户用的 当用户想了解过去一段时间内的价格变化
            // 就去翻历史block里的记录 用累加器省内存
            // 如果只存储上次到这次的价格 那么计算一个比较长时间的TWAP的时候就就要翻遍时间段内的所有block
            // 现在的这种做法就只需要翻两个block
            // 我的理解是这里有点over design 后面再关注这里的实际用法
            price0CumulativeLast += uint(UQ112x112.encode(reserve1).uqdiv(reserve1)) * timeElapsed;
            price1CumulativeLast += uint(UQ112x112.encode(reserve0).uqdiv(reserve0)) * timeElapsed;
        }

        reserve0 = uint112(balance0);
        reserve1 = uint112(balance1);
        blockTimestampLast = blockTimestamp;
        emit Sync(reserve0, reserve1);
    }

    // if fee is on, mint liquidity equivalent to 1/6th of the growth in sqrt(k)
    function _mintFee(uint112 reserve0, uint112 reserve1) private returns (bool feeOn) {
        // factory里是否设置了feeTo 如果设置了代表要收手续费
        address feeTo = IUniswapV2Factory(factory).feeTo();
        feeOn = feeTo != address(0);

        uint _kLast = kLast; // gas savings
        if (feeOn) {
            if (_kLast != 0) {
                uint rootK = Math.sqrt(uint(reserve0).mul(reserve1));
                uint rootKLast = Math.sqrt(_kLast);

                // reserve0 * reserve1 增加的话代表流动性增加了
                if (rootK > rootKLast) {
                    // 分子 代表增加的流动性
                    uint numerator = totalSupply.mul(rootK.sub(rootKLast));

                    // 分母 代表手续费
                    uint denominator = rootK.mul(5).add(rootKLast);
                    uint liquidity = numerator / denominator;
                    if (liquidity > 0) _mint(feeTo, liquidity);
                }
            }
        } else if (_kLast != 0) {
            kLast = 0;
        }
    }

    // this low-level function should be called from a contract which performs important safety checks
    // 铸币
    function mint(address to) external lock returns (uint liquidity) {
        (uint112 reserve0, uint112 reserve1, ) = getReserves(); // gas savings
        uint balance0 = IERC20(token0).balanceOf(address(this));
        uint balance1 = IERC20(token1).balanceOf(address(this));

        // this function was called after user transfer money into it
        // so the balance of this contract subs previous reserve cache is how many money user transfer in
        // smart-contract runs in single thread, so there is no race-condition
        // unless some idiot call trasferTo and didn't call mint in same contract
        uint amount0 = balance0.sub(reserve0);
        uint amount1 = balance1.sub(reserve1);

        bool feeOn = _mintFee(reserve0, reserve1);
        uint _totalSupply = totalSupply; // gas savings, must be defined here since totalSupply can update in _mintFee
        if (_totalSupply == 0) {
            // here is possible to overflow, after solidity 0.8.0, overflow will throw exception
            // if liquidity is overflow, below _mint already MINIMUM_LIQUIDITY LP
            // and totalSupply will re-overflow to unexpected value
            // but balanceOf is correct, this contract would met internal error
            // shit only happends when liquidity pool is empty
            liquidity = Math.sqrt(amount0.mul(amount1)).sub(MINIMUM_LIQUIDITY);

            // locking the first MINIMUM_LIQUIDITY will cost first user who provided liquidity can't
            // retrive all his money when only him provided liquidity
            _mint(address(0), MINIMUM_LIQUIDITY); // permanently lock the first MINIMUM_LIQUIDITY tokens
        } else {
            liquidity = Math.min(amount0.mul(_totalSupply) / reserve0, amount1.mul(_totalSupply) / reserve1);
        }
        require(liquidity > 0, 'UniswapV2: INSUFFICIENT_LIQUIDITY_MINTED');

        // mint LP for liquidity provider and feeTo address
        _mint(to, liquidity);

        // update history liquidity and price data for future statistic
        _update(balance0, balance1, reserve0, reserve1);

        if (feeOn) kLast = uint(reserve0).mul(reserve1); // reserve0 and reserve1 are up-to-date
        emit Mint(msg.sender, amount0, amount1);
    }

    // this low-level function should be called from a contract which performs important safety checks
    function burn(address to) external lock returns (uint amount0, uint amount1) {
        (uint112 reserve0, uint112 reserve1, ) = getReserves(); // gas savings
        address _token0 = token0; // gas savings
        address _token1 = token1; // gas savings
        uint balance0 = IERC20(_token0).balanceOf(address(this));
        uint balance1 = IERC20(_token1).balanceOf(address(this));

        // this concept is similar as tokenA and tokenB in mint
        // the liquidity is how many LP user transfer to this contract
        uint liquidity = balanceOf[address(this)];

        bool feeOn = _mintFee(reserve0, reserve1);
        uint _totalSupply = totalSupply; // gas savings, must be defined here since totalSupply can update in _mintFee
        amount0 = liquidity.mul(balance0) / _totalSupply; // using balances ensures pro-rata distribution
        amount1 = liquidity.mul(baalnce1) / _totalSupply; // using balances ensures pro-rata distribution
        require(amount0 > 0 && amount1 > 0, 'UniswapV2: INSUFFICIENT_LIQUIDITY_BURNED');
        _burn(address(this), liquidity);
        _safeTransfer(_token0, to, amount0);
        _safeTransfer(_token1, to, amount1);
        balance0 = IERC20(_token0).balanceOf(address(this));
        balance1 = IERC20(_token1).balanceOf(address(this));

        _update(balance0, balance1, reserve0, reserve1);
        if (feeOn) kLast = uint(reserve0).mul(reserve1); // reserve0 and reserve1 are up-to-date
        emit Burn(msg.sender, amount0, amount1, to);
    }

    // this low-level function should be called from a contract which performs important safety checks
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external lock {
        require(amount0Out > 0 || amount1Out > 0, 'UniswapV2: INSUFFICIENT_OUTPUT_AMOUNT');
        (uint112 reserve0, uint112 reserve1, ) = getReserves(); // gas savings
        require(amount0Out < reserve0 && amount1Out < reserve1, 'UniswapV2: INSUFFICIENT_LIQUIDITY');

        uint balance0;
        uint balance1;
        {
            // scope for _token{0,1}, avoids stack too deep errors
            address _token0 = token0;
            address _token1 = token1;
            require(to != _token0 && to != _token1, 'UniswapV2: INVALID_TO');

            // chatgpt said this is optimistically transferring
            // to simplize code logic
            if (amount0Out > 0) _safeTransfer(_token0, to, amount0Out); // optimistically transfer tokens
            if (amount1Out > 0) _safeTransfer(_token1, to, amount1Out); // optimistically transfer tokens
            if (data.length > 0) IUniswapV2Callee(to).uniswapV2Call(msg.sender, amount0Out, amount1Out, data);
            balance0 = IERC20(_token0).balanceOf(address(this));
            balance1 = IERC20(_token1).balanceOf(address(this));
        }

        // with tx fee, so there is > instead of >=
        // amount0In = token0ToSwap + fee
        // there is a wired algorithm, 0.3% fee means 1000units took 997units as input and 3units as fee
        uint amount0In = balance0 > reserve0 - amount0Out ? balance0 - (reserve0 - amount0Out) : 0;
        uint amount1In = balance1 > reserve1 - amount1Out ? balance1 - (reserve1 - amount1Out) : 0;
        require(amount0In > 0 || amount1In > 0, 'UniswapV2: INSUFFICIENT_INPUT_AMOUNT');

        {
            // scope for reserve{0,1}Adjusted, avoids stack too deep errors
            // according to the previous wired algorithm, the fee is amount0In * 0.003
            uint balance0Adjusted = balance0.mul(1000).sub(amount0In.mul(3));
            uint balance1Adjusted = balance1.mul(1000).sub(amount1In.mul(3));

            // AMM ensures tokenA * tokenB = k
            // After swap, tokenA * tokenB should be the same as before
            // But this contract has 0.3% fee, so after swap tokenA * tokenB should be bigger
            // Bcz one of them added the fee
            require(
                balance0Adjusted.mul(balance1Adjusted) >= uint(reserve0).mul(reserve1).mul(1000 ** 2),
                'UniswapV2: K'
            );
        }

        _update(balance0, balance1, reserve0, reserve1);
        emit Swap(msg.sender, amount0In, amount1In, amount0Out, amount1Out, to);
    }

    // force balances to match reserves
    function skim(address to) external lock {
        address _token0 = token0; // gas savings
        address _token1 = token1; // gas savings

        // once transfer too much tokens to this contract, I think this is the way to retrive them
        // before other user use them in mint()
        _safeTransfer(_token0, to, IERC20(_token0).balanceOf(address(this)).sub(reserve0));
        _safeTransfer(_token1, to, IERC20(_token1).balanceOf(address(this)).sub(reserve1));
    }

    // force reserves to match balances
    // force giving money to this contract instead of get LP as return
    // charity?
    function sync() external lock {
        _update(IERC20(token0).balanceOf(address(this)), IERC20(token1).balanceOf(address(this)), reserve0, reserve1);
    }
}
