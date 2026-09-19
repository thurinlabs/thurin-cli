# thurin

Your online identity, from a terminal. Look up any identity on [Thurin.id](https://thurin.id), and attest, update, or revoke your own claim on the PGPRegistry, with every check run before a single unit of gas is spent.

Two rules it never breaks: **it is not a wallet** (create, import, list, export keystores; no balances, no transfers), and **it never holds a PGP secret** (every PGP operation is your own `gpg`; passphrases go through pinentry).

A [Thurin Labs](https://thurinlabs.id) project. MIT.

## Install

```bash
npm install -g @thurinlabs/thurin
# or run without installing:
npx @thurinlabs/thurin status bendoubleu.eth
```

Needs Node 20+ and GnuPG 2.2+ on the machine for anything involving a key.

## Look something up

```
$ thurin status thurinlabs.eth
thurinlabs.eth  0x539C7e1E454296Dc150B95a0acCC05bCa3b33538  (mainnet)
claims      1 total · 1 active · 0 revoked
fingerprint 08B9374FDFBEC67EFFA24E669D3D86E35361EF7B  ✓ verified
name        Thurin Labs
name        Thurin Labs <hello@thurin.id>
key         Ed25519 · created 2026-09-12 · expires 2028-09-11
proofs
  ✓ GitHub     thurinlabs
  ✓ DNS        thurin.id
  ✓ DNS        thurinlabs.id
  ✓ Codeberg   thurinlabs
efp         2 followers · 0 following
```

Accepts an ENS name, an address, a PGP fingerprint, or a 16-character key ID. `--json` prints the same as data. Exit code 1 means the identity has no verified claim.

## Attest, in three commands

```bash
thurin key create thurin            # an Ed25519 key with a published name and no email
thurin wallet create identity       # a fresh address; the 12 words are shown once
thurin attest                       # signs the statement with gpg, checks everything, publishes
```

The address needs a little ETH for the fee. Already have a key and a wallet? `thurin attest --key <fingerprint> --account <keystore name>`, or `--account path/to/any-v3-keystore.json` (Foundry's `~/.foundry/keystores/*` work as they are). `THURIN_PRIVATE_KEY` in the environment also works, for scripts.

Before publishing, `attest` exports a minimal copy of your key, leaves out every name that contains an email (pass `--include-email` to keep them), signs `I control the Ethereum address: 0x…` with your key, verifies that signature against the export exactly the way thurin.id will, checks the size limits and that no active claim already exists, and shows you what goes on-chain. Then it asks once and sends.

## Change your claim

```bash
thurin update-key          # after adding a proof notation to your key: same fingerprint, new notations, no new signature
thurin reattest            # revoke the current claim and publish a new key in one transaction
thurin revoke              # mark the claim inactive (it stays in chain history)
```

Adding a proof to a key is one gpg line; see the [GnuPG guide](https://docs.thurin.id/#/guides/gnupg).

## Your ETH is on a Ledger or a phone

Then the CLI can't send the transaction, but it can still do the PGP half:

```bash
thurin attest --no-key --owner yourname.eth      # or --owner 0x…
```

It signs, exports, and runs every check, then prints a `thurin.id/attest#…` link instead of sending. Open that link where the wallet is, connect the address you named, and publish. The signed statement and key travel in the part of the link after `#`, which browsers never send to any server, so nothing passes through Thurin. `reattest` and `update-key` take `--no-key` too. No keystore, password, or ETH is needed on this machine.

## Your address has no ETH

Then sign a permission slip instead of a transaction:

```bash
thurin attest --authorize                  # keystore signs typed data (free); prints a link anyone can publish
thurin attest --authorize --deadline 1d    # default is 7d
thurin attest --authorize --out auth.json  # a file instead of a link, for scripts
```

The link opens on thurin.id/attest, where *any* wallet can publish it and pay the fee; the claim lands under your address, not theirs. Or someone with a funded keystore runs `thurin submit <link or file>`. `reattest`, `update-key`, and `revoke` take `--authorize` too. Before handing it out, the CLI proves the signature recovers to your address and simulates the call against the registry.

Know the edge: an address with no ETH can't recall a slip, so the deadline is your only safety. It is printed every time, and a slip can be used once.

## Run a relayer

A relayer is `thurin submit` behind an HTTP port: it accepts the same JSON a hand-off link carries, runs the same checks, and pays for the `…For` call from a hot keystore, within limits you set.

```bash
thurin wallet create hot                      # fund it with pocket money
thurin relay --account hot --budget 0.01      # ETH per day; also --free-attests 1, --per-hour 10, --port 8787
```

Then `thurin attest --authorize --relayer https://relay.example` publishes without a link, and `"relayer"` in `~/.config/thurin/config.json` makes that the default (`--no-relayer` gets a link anyway). `GET /` reports the budget and what's been spent.

This is the one command that spends unattended. It spends gas only, one transaction at a time, never more than the budget per rolling day, and refuses calls over 3M gas (`--max-gas`). Treat the key as pocket money: a drained relayer loses its budget, not anyone's identity. Put nginx or another TLS proxy in front; it listens on localhost by default and trusts `X-Forwarded-For` for rate limits.

## Keys

```bash
thurin key list                      # your keys, which have a published name, how many proofs
thurin key add-name <fpr> thurin     # give an email-only key a name to publish under
thurin key export <fpr>              # the minimal armored export
thurin key fetch bendoubleu.eth      # the key stored on-chain for an identity; --import puts it in your keyring
thurin key default <fpr>
```

## Wallet (not a wallet)

```bash
thurin wallet create <name>          # BIP-39 mnemonic → V3 keystore under ~/.config/thurin/keystores
thurin wallet import <name>          # a private key, a mnemonic, or --from <keystore.json>
thurin wallet list
thurin wallet export <name>          # the encrypted V3 file; --private-key prints the key (it warns)
thurin wallet default <name>
```

Keystores are the same format `cast`, geth, and every wallet import. `--password-file <path>` (mode 0600) for non-interactive use.

## Networks

`--network mainnet|sepolia|local` (local = a running anvil), `--rpc <url>` for your own node. Defaults live in `~/.config/thurin/config.json`. The registry is at `0x9302E02e2869e129aC8516fE5eFFd51EA3082c09` on every network.

## What's next

`init` (one guided run), `keyserver` (an HKP server for gpg backed by the chain), and `--anon`, `init` (one guided run), `keyserver` (an HKP server for gpg backed by the chain), and `--anon`. See the [roadmap](https://docs.thurin.id/#/roadmap).

## Development

```bash
git clone https://github.com/thurinlabs/identity-kit && (cd identity-kit && npm install && npm run build)
git clone https://github.com/thurinlabs/thurin-cli && cd thurin-cli && npm install
npm run dev -- status thurinlabs.eth
npm test
```
