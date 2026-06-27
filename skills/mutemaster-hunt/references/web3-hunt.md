# Web3 Bug Hunting — MuteMaster Protocol

PoC templates: `~/Desktop/reference/poc_templates.md`
Web3 resources: `~/Desktop/reference/web3_resources.md`

---

## 2025/2026 Web3 Threat Landscape

- **$1.83 billion** stolen from access control exploits in H1 2025 alone
- **Cross-chain bridges** = 40% of all Web3 exploits in 2025 — highest attack surface
- **AI-driven exploits** up 1,025% — attackers using LLMs to find insecure APIs + inference setups
- **Uniswap V4 hooks** — first major exploit: $12M loss from hook vulnerability class
- **Immunefi Q1 2025**: 197 incidents, $1.6B+ losses across DeFi/NFT/L1

New priority: Cross-chain bridges and hook-based protocols are the highest-yield targets in 2025.

---

## 60-Second Triage Filter

Before spending any time on a function, answer these 9 questions. If yes to any, it's Priority 1:

1. **Can a zero-permission attacker call this?** → Priority 1
2. **Does it touch token balances, mint/burn, or move ETH?** → Priority 1
3. **External call BEFORE state update?** → Reentrancy (T2)
4. **`initialize()` with no guard?** → Uninitialized proxy (T1)
5. **Price read from spot AMM (`getReserves()` or `slot0()`)?** → Oracle manipulation (T3)
6. **Signature verified without nonce/chainId?** → Replay attack (T4)
7. **`delegatecall` with user-controlled input?** → Arbitrary delegatecall
8. **Cross-chain message validation — who can send messages?** → Bridge forgery (T8)
9. **Hook function (`beforeSwap`, `afterSwap`) — is caller validated?** → Uniswap V4 hook exploit

If none → check access control modifiers on all state-changing functions → then math in `unchecked{}` blocks.

---

## Bug Classes by Payout

| Class | Detection Signal | Template | Real Payout |
|---|---|---|---|
| Uninitialized Proxy | `cast storage $IMPL 0x0` returns 0 | T1 | $10M (Wormhole) |
| Reentrancy | External call before state update in same function | T2 | $800K (Fei Protocol) |
| Oracle Manipulation | `getReserves()` or `slot0()` used as price source | T3 | $1M (Belt Finance) |
| Signature Replay | No nonce or chainId in signed payload | T4 | $3M (OpenSea) |
| Access Control | State-changing function lacks `onlyOwner`/modifier | T5 | $1.63B (2025 total) |
| Share Inflation (ERC4626) | First depositor can donate to vault before others | T6 | $50K–$200K |
| Infinite Mint | Mint function without corresponding lock/collateral check | T7 | $6M (Aurora) |
| Bridge Forgery | Validator set manipulable by attacker | T8 | $625M (Ronin) |
| Cross-Chain Relay | Message validation bypassable across chains? | — | 40% of 2025 exploits |
| Hook Exploit (V4) | Uniswap V4 hook — caller not validated? | — | $12M (2025) |

---

## Hunt Sequence

### Step 1 — Map (15 minutes max)

```bash
# Is it a proxy? (EIP-1967 slot)
cast storage $ADDR 0x360894a13ba1a3210667c828492db98dca3e2076c6378af953958bef740b0

# Is the implementation initialized? (slot 0)
cast storage $IMPL 0x0000000000000000000000000000000000000000000000000000000000000000
# Returns 0x0 → CRITICAL: uninitialized proxy

# What tokens does it hold? (that's the prize)
cast balance $CONTRACT --ether
cast call $CONTRACT "totalAssets()(uint256)" | cast to-unit ether

# External protocols called?
grep -r "IERC20\|IUniswap\|IChainlink\|IAave\|ICompound" src/
# → oracle/AMM/bridge = primary attack surface

# unchecked{} blocks?
grep -rn "unchecked" src/
# → review each for overflow

# DELEGATECALL?
grep -rn "delegatecall" src/
# → trace what address it calls and who controls it
```

### Step 2 — Hunt Priority (in order)

1. **`initialize()` on implementation** → 2 min check
   ```bash
   grep -rn "function initialize" src/
   grep -rn "initializer\|Initializable" src/
   # If no modifier: CRITICAL uninitialized proxy
   ```

2. **External/public functions without access modifier**
   ```bash
   slither . --checklist 2>&1 | grep -E "(suicidal|controlled-delegatecall|arbitrary-send)"
   grep -rn "function.*public\|function.*external" src/ | grep -v "view\|pure\|onlyOwner\|onlyRole\|whenNotPaused"
   ```

3. **Token transfer paths** → trace from entry point to `transfer()`/`transferFrom()`/`_mint()`

4. **Every oracle read** → spot price or TWAP?
   ```bash
   grep -rn "getReserves\|slot0\|latestAnswer\|latestRoundData" src/
   # getReserves() or slot0 = manipulable → Oracle manipulation
   # latestAnswer with no staleness check = price manipulation
   ```

5. **Signature verifications** → what's in the signed payload?
   ```bash
   grep -rn "ecrecover\|SignatureChecker\|ECDSA.recover" src/
   # Check: is nonce included? Is chainId included?
   # Missing either = replay attack
   ```

6. **All external calls** → state update before or after?
   ```bash
   grep -rn "\.call\|\.transfer\|\.send\|safeTransfer" src/
   # Pattern: external call BEFORE state.balance = 0 → reentrancy
   ```

7. **Math in `unchecked{}`**
   ```bash
   grep -B5 -A20 "unchecked" src/
   # Look for subtraction that could underflow
   # uint256 x = a - b (where b > a possible) → underflow to max uint
   ```

### Step 3 — Critical Finding Protocol

STOP EVERYTHING when you find something.

Structure your finding:
> "The `[FUNCTION]` in `[CONTRACT]` allows `[WHO - e.g., any caller]` to `[DO WHAT - e.g., drain all ETH]` because `[ROOT CAUSE - e.g., no reentrancy guard and external call precedes state update]`"
> "TVL at risk: ~$[AMOUNT] from `[CONTRACT ADDRESS]`"

Then immediately:
```bash
# 1. Verify TVL
cast balance $CONTRACT --ether
cast call $CONTRACT "totalAssets()(uint256)" | cast to-unit ether

# 2. Build PoC (fork mainnet)
forge test --match-test testExploit -vvvv \
  --fork-url $ETH_RPC_URL --fork-block-number $BLOCK

# 3. PoC must pass: assertGt(attackerBalanceAfter, attackerBalanceBefore)

# 4. Write report → submit to Immunefi
```

---

## Full Toolchain

```bash
# Check proxy implementation slot (EIP-1967)
cast storage $ADDR 0x360894a13ba1a3210667c828492db98dca3e2076c6378af953958bef740b0

# Check if implementation is initialized
cast storage $IMPL 0x0000000000000000000000000000000000000000000000000000000000000000

# Replay any transaction with full trace
cast run $TX_HASH --trace

# Check TVL
cast balance $CONTRACT --ether
cast call $CONTRACT "totalAssets()(uint256)" | cast to-unit ether
cast call $CONTRACT "totalSupply()(uint256)" | cast to-unit ether

# Static analysis (slither)
slither . --checklist 2>&1 | grep -E "(HIGH|MEDIUM)"
slither . --print human-summary
slither . --detect reentrancy-eth,reentrancy-no-eth,suicidal,uninitialized-state

# Foundry fork test
forge test --match-test testExploit -vvvv \
  --fork-url $ETH_RPC_URL \
  --fork-block-number $BLOCK

# Decode function selector
cast 4byte 0xa9059cbb   # → transfer(address,uint256)

# ABI decode calldata
cast calldata-decode "transfer(address,uint256)" 0x...

# Get all events from contract
cast logs --from-block 0 --address $CONTRACT

# Simulate a call as any address
cast call $CONTRACT "balanceOf(address)(uint256)" $ADDRESS --from $ATTACKER

# Send transaction on fork
cast send $CONTRACT "attack()" --private-key $PRIVATE_KEY --rpc-url $FORK_URL
```

---

## Foundry PoC Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IVulnerableContract {
    function withdraw(uint256 amount) external;
    function deposit() external payable;
}

contract ExploitTest is Test {
    IVulnerableContract target;
    address attacker = makeAddr("attacker");

    function setUp() public {
        // Fork mainnet at specific block
        vm.createSelectFork(vm.envString("ETH_RPC_URL"), BLOCK_NUMBER);
        target = IVulnerableContract(TARGET_ADDRESS);
        vm.deal(attacker, 1 ether);
    }

    function testExploit() public {
        uint256 balanceBefore = attacker.balance;

        vm.startPrank(attacker);
        // --- EXPLOIT LOGIC HERE ---

        vm.stopPrank();

        uint256 balanceAfter = attacker.balance;
        assertGt(balanceAfter, balanceBefore, "Exploit failed");
        console.log("Profit:", balanceAfter - balanceBefore);
    }

    // Reentrancy callback
    receive() external payable {
        if (address(target).balance > 0) {
            target.withdraw(1 ether);
        }
    }
}
```

---

## Common Vulnerability Patterns

### Reentrancy
```solidity
// VULNERABLE: external call before state update
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success,) = msg.sender.call{value: amount}(""); // ← CALL FIRST
    balances[msg.sender] -= amount;                        // ← STATE AFTER
}

// Your PoC: call withdraw() from a contract with a receive() that calls withdraw() again
```

### Uninitialized Proxy
```bash
# Check implementation contract
cast storage $IMPL_ADDR 0x0  # → 0x0 means uninitialized
# Call initialize() yourself → you become the owner
cast send $IMPL_ADDR "initialize(address)" $YOUR_ADDRESS
```

### Oracle Manipulation (Flash Loan)
```
1. Flash loan large amount of token A
2. Swap to manipulate getReserves() / slot0 price
3. Call vulnerable function that uses manipulated price
4. Profit: borrow/mint at wrong price
5. Repay flash loan
```

### Signature Replay
```python
# If no nonce in signed message:
# 1. Capture valid signature from tx
# 2. Replay same signature on different network or same network again
# 3. Execute same action multiple times with one signature
```
