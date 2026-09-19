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

`authorize` and `submit` (attest from an address that has never held ETH), `init` (one guided run), `keyserver` (an HKP server for gpg backed by the chain), and `--anon`. See the [roadmap](https://docs.thurin.id/#/roadmap).

## Development

```bash
git clone https://github.com/thurinlabs/identity-kit && (cd identity-kit && npm install && npm run build)
git clone https://github.com/thurinlabs/thurin-cli && cd thurin-cli && npm install
npm run dev -- status thurinlabs.eth
npm test
```
