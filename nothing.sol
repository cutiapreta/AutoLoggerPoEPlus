# details:

https://github.com/chainflip-io/chainflip-eth-contracts/blob/master/contracts/
https://github.com/chainflip-io/chainflip-backend

a cross chain CCM call into `ScUtils.cfReceive()` makes `msg.sender` equal to the chainflip vault, and the backend/runtime then treats that Vault address as the authenticated state chain account, that creates a shared state chain account:

```solidity
AccountId32(CF_VAULT) =
0x000000000000000000000000f5e10380213880111522dd0efd3dbb45b9f62bcc
```

any user who can initiate a public CCM swap to ethereum `ScUtils` can cause a decoded `EthereumSCApi` call to be dispatched as that account, if FLIP was credited to that shared account through the vulnerable `ScUtils` CCM `to == SC_GATEWAY` path, an attacker can redeem that account's redeemable FLIP to their own ethereum address

attacker is not redeeming only their own deposit; the bug merges independent users' cross chain deposits into one Vault derived State Chain account and then lets anyone act as that account


- `ScUtils` contract at:
   - `0x13ad793e7b75eaacee34b69792552f086b301380`
   
## Source-level proof

| Component | Confirmed behavior |
|---|---|
| contracts/ScUtils.sol::cfReceive | cfReceive is onlyCfVault, so during CCM execution msg.sender == CF_VAULT. In the to == SC_GATEWAY branch it emits DepositToScGatewayAndScCall(msg.sender, address(0), amount, data). Uploaded source: ScUtils.sol:114-136, 165-168. |
| ScUtils.sol safe funding branch | The to == address(this) branch is separate and safe for direct account funding: it calls StateChainGateway.fundStateChainAccount(bytes32(data), amount) and does not execute arbitrary EthereumSCApi. Uploaded source: ScUtils.sol:123-130. |
| engine/src/witness/eth_elections.rs | The witnesser ignores signer, takes event sender, sets caller = sender, and derives caller_account_id = sender.into_account_id_32(). Uploaded source: eth_elections.rs:332-350, 352-374, 381-403, 410-423. |
| runtime/.../witnessing/ethereum_elections.rs | EthereumScUtilsWitnessing forwards the witnessed call to pallet_cf_funding::execute_sc_call(...) with the derived caller_account_id. Uploaded source: ethereum_elections.rs:352-405. |
| pallets/cf-funding/src/lib.rs::execute_sc_call | For FlipToSCGateway, it credits caller_account_id, then decodes the bytes and dispatches them as RuntimeOrigin::signed(caller_account_id.clone()). Uploaded source: lib.rs:903-968. |
| runtime/.../ethereum_sc_calls.rs | EthereumSCApi::Delegation::Undelegate maps to Validator::undelegate, and EthereumSCApi::Delegation::Redeem maps to Funding::redeem. Uploaded source: ethereum_sc_calls.rs:40-52, 97-123. |
| chains/src/evm.rs::ToAccountId32 | Ethereum address is converted into a State Chain AccountId32 by prefixing 12 zero bytes. Uploaded source: evm.rs:665-672. |
| pallets/cf-funding/src/lib.rs::redeem | redeem uses the signed State Chain account as authority, then creates a threshold-signed registerRedemption to the attacker-supplied Ethereum address. Uploaded source: lib.rs:647-720. |

The exact authentication failure is here:

```
caller: sender,
caller_account_id: sender.into_account_id_32(),
```

For direct calls to ScUtils.depositToScGateway() this is fine because sender == user EOA.

For CCM calls to ScUtils.cfReceive() this is wrong because sender == CF_VAULT.

## Why this is not intended behavior

Chainflip's docs say CCM lets users send an arbitrary payload along with a swap, and that the message is passed unmodified to the receiver contract. For EVM CCM, Chainflip's Vault transfers the destination token and then calls the receiver's cfReceive; the docs explicitly warn that receiver contracts should normally restrict cfReceive to only the Vault.

So msg.sender == Vault inside cfReceive is expected at the contract layer.

The bug is at the backend/runtime interpretation layer: the engine treats that contract-layer sender as the user's State Chain identity. Chainflip's delegation docs say the Ethereum address is used to create the State Chain account for delegation, which is valid for a user EOA, not for the shared protocol Vault address.

Also, ScUtils.sol itself shows the intended safe CCM funding path: to == address(this) means "fund this explicit State Chain account pubkey," while to == SC_GATEWAY means "deposit and emit arbitrary SC call." The backend conflates the latter with a user-owned account even though the event sender is the Vault.

## Exploit sketch: unprivileged transaction sequence

No validator key, governance key, Vault key, or victim key is required. The attacker only needs the ability to initiate normal public CCM swaps with a chosen message and gasBudget, which Chainflip docs support for swap flows.

### Step 1 — victim creates the shared-balance condition

A victim performs the documented ScUtils CCM "swap + delegation" style flow:

```
Destination chain: Ethereum
Receiver: ScUtils
Destination asset: FLIP
CCM message: abi.encode(
    SC_GATEWAY,
    SCALE(EthereumSCApi::Delegation::Delegate { operator, increase })
)
```

The Ethereum Vault calls:

```
ScUtils.cfReceive(..., message, FLIP, victimAmount)
```

Inside cfReceive:

```
require(msg.sender == CF_VAULT);
...
emit DepositToScGatewayAndScCall(msg.sender, address(0), amount, data);
```

So the event is:

```
sender = CF_VAULT
signer = address(0)
amount = victimAmount
scCall = victim delegation call
```

The engine witnesses it as:

```
caller = CF_VAULT
caller_account_id = 0x000000000000000000000000f5e10380213880111522dd0efd3dbb45b9f62bcc
deposit = FlipToSCGateway(victimAmount)
call = victim scCall
```

The runtime credits the victim's FLIP to the Vault-derived State Chain account and dispatches the victim's delegation call as that same shared account.

### Step 2 — attacker undelegates the shared account

The attacker initiates a small public CCM swap to Ethereum ScUtils with a chosen EthereumSCApi payload:

```
Destination chain: Ethereum
Receiver: ScUtils
Destination asset: FLIP
CCM message: abi.encode(
    SC_GATEWAY,
    SCALE(EthereumSCApi::Delegation::Undelegate { decrease: Max })
)
```

Again, cfReceive() emits sender = CF_VAULT.

The backend dispatches:

```
Validator::undelegate(Max)
origin = signed(AccountId32(CF_VAULT))
```

If the shared account's FLIP is delegated, the attacker waits through Chainflip's real bonding window. Chainflip docs state that delegated funds remain bonded until the end of the following auction, with a maximum bonding period of three days.

If the shared account already has redeemable/liquid FLIP, this undelegate step is unnecessary.

### Step 3 — attacker redeems to their Ethereum address

The attacker sends another public CCM swap with:

```
Destination chain: Ethereum
Receiver: ScUtils
Destination asset: FLIP
CCM message: abi.encode(
    SC_GATEWAY,
    SCALE(EthereumSCApi::Delegation::Redeem {
        amount: Max,
        address: attacker_eth_address,
        executor: None
    })
)
```

The runtime dispatches:

```
Funding::redeem(Max, attacker_eth_address, None)
origin = signed(AccountId32(CF_VAULT))
```

Funding::redeem creates a threshold-signed StateChainGateway.registerRedemption for the shared Vault-derived State Chain account. Chainflip's docs confirm that a State Chain redemption request causes the authority set to sign and broadcast registerRedemption, with the Ethereum address specified by the request as the recipient.

### Step 4 — redemption execution after delay

The StateChainGateway has a real 2-day delay before the claim can be executed, and unexecuted redemptions expire after 144 hours on mainnet. After the delay, the redemption can be executed and FLIP is transferred to the attacker's Ethereum address.

## Exact impact

Primary impact: theft of all redeemable FLIP credited to:

0x000000000000000000000000f5e10380213880111522dd0efd3dbb45b9f62bcc

where that balance came from ScUtils CCM to == SC_GATEWAY deposit-and-call flows.

Secondary impacts:

- Unauthorized undelegation of the shared Vault-derived account.
- Unauthorized redemption requests from that account.
- Cross-user balance mixing: multiple victims using the same CCM path are credited to the same Vault-mapped State Chain account.
- Forced disruption of delegation state even before final theft, because the attacker can dispatch Undelegate as the shared account.

Direct financial incentive exists, so this is not an out-of-scope pure DoS issue; Chainflip's policy says issues with direct financial incentive are treated as impact-relevant, while no-incentive DoS is downgraded/out of scope.

Impact boundary: this does not drain all Chainflip Vault liquidity and does not drain normal State Chain accounts. The stolen amount is bounded to FLIP that has been credited to the Vault-derived State Chain account via the vulnerable ScUtils CCM deposit-and-call path.

## Severity

Critical.

Reason: an unprivileged attacker can cause the protocol to authenticate them as a shared protocol-derived State Chain account and redeem other users' FLIP to an attacker-controlled Ethereum address. That is direct theft of user funds, not merely griefing, mis-accounting, or temporary DoS.

## Is the time window realistic?

Yes.

There are two timing layers:

- Delegation unlock window: if the shared account's FLIP is delegated, the attacker can first submit Undelegate(Max) and wait until the end of the following auction; Chainflip documents this as at most three days.
- Gateway redemption window: after Redeem(Max, attacker) is accepted, the Gateway imposes a 2-day execution delay, and the claim expires after 144 hours if not executed.

These delays make the theft observable and give governance/safe mode a chance to intervene, but they do not invalidate the bug. Safe Mode can stop witness extrinsics and egress processing during an incident, but that is an emergency mitigation, not a normal authorization check.
