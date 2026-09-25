# thurin

Your PGP key on your Ethereum address, from a terminal. Look anyone up on [Thurin.id](https://thurin.id), and add, change, or end your own claim. Every check runs before any gas is spent.

Two rules: **it is not a wallet** (it makes, imports, lists, and exports keystores; no balances, no transfers), and **it never holds a PGP secret or makes keys** (every PGP step is your own `gpg`; passphrases go through pinentry).

Full reference: [docs.thurin.id/#/cli](https://docs.thurin.id/#/cli). A [Thurin Labs](https://thurinlabs.id) project. MIT.

## Install

```bash
npm install -g @thurinlabs/thurin
# or without installing:
npx @thurinlabs/thurin status thurinlabs.eth
```

Node 20 or newer, and GnuPG 2.2 or newer for anything that touches a key. Releases are signed: [how to check one](https://docs.thurin.id/#/guides/verify-release).

`thurin --help` is one screen; `thurin help <command>` has the rest.

## Look someone up

```
$ thurin status thurinlabs.eth
thurinlabs.eth  0x539C7e1E454296Dc150B95a0acCC05bCa3b33538  (mainnet)
claims      1 total · 1 active · 0 revoked
fingerprint 08B9374FDFBEC67EFFA24E669D3D86E35361EF7B  ✓ verified
name        Thurin Labs
key         Ed25519 · created 2026-09-12 · expires 2028-09-11
proofs
  ✓ GitHub     thurinlabs
  ✓ DNS        thurin.id
  ✓ DNS        thurinlabs.id
  ✓ Codeberg   thurinlabs
```

It takes an ENS name, an address, a fingerprint, or a 16-character key ID. Exit code 1 means no verified claim. When a claim doesn't count, the line says why: `✗ key expired`, `✗ key revoked`, `✗ key compromised`, `✗ doesn't verify`, and so on.

## Add your key

```bash
gpg --quick-gen-key "Your Name" ed25519 sign 2y   # gpg makes the key; leave the email off
thurin wallet create identity                      # a fresh address; the 12 words are shown once
thurin attest --key <fingerprint>
```

The address needs a little ETH for the fee. `--account` takes a keystore name or a path to any V3 keystore (Foundry's work as they are); `THURIN_PRIVATE_KEY` works for scripts.

Before it asks, `attest` exports a minimal copy of the key without names that contain an email (`--include-email` keeps them), has gpg sign `I control the Ethereum address: 0x…`, checks it the way thurin.id will, and shows what goes on-chain.

## Change or end a claim

```bash
thurin update-key                            # new names or proofs, same key, no new signature
thurin reattest --key <new>                  # replace the claim in one transaction; records move with it
thurin reattest --key <new> --compromised    # the old key was stolen: mark it in the same transaction
thurin revoke --reason retired               # or compromised, other, or none
thurin revoke 0 --reason compromised         # found out later: mark a revoked or replaced claim, once
```

**Compromised is final:** this address can never claim that key again. `--drop-records` leaves records on the old claim. Adding a proof to a key is one gpg line: [the guide](https://docs.thurin.id/#/guides/gnupg).

## No ETH on this machine

```bash
thurin attest --no-key --owner you.eth       # your ETH wallet is elsewhere: prints a link to publish from it
thurin attest --authorize                    # no ETH anywhere: a free permission anyone can publish and pay for
thurin attest --authorize --out auth.json    # the same as a file
thurin submit auth.json                      # publish someone's permission from a funded keystore
```

A `--no-key` link carries the key and signature after the `#`, which browsers never send to a server. A permission can be used once, before its deadline (default 7 days, `--deadline 1d`), and can't be recalled without ETH, so the deadline is printed every time. `reattest`, `update-key`, `revoke`, and `record set` take both flags.

The Ethereum key elsewhere too? `--signer "<cmd>"` hands the typed data to any program that signs it, and `--sign-out slip.json` then `thurin authorize finish slip.json --signature 0x…` crosses an air gap. The PGP key elsewhere? `--statement` prints the line to sign and `--key-file pub.gpg --statement-file s.sig` brings it back.

## Records

```bash
thurin record get thurinlabs.eth               # every record on the claim
thurin record get thurinlabs.eth canary        # one value, so it pipes into gpg --verify
thurin record set security "mailto:security@example.com"
thurin record clear security
thurin record add-release "thurin-cli 0.13.0" SHA256SUMS --url https://github.com/thurinlabs/thurin-cli/releases/tag/v0.13.0
```

A name without a dot gets `thurin.` in front. Values are up to 1 KB. What the names mean: [Records](https://docs.thurin.id/#/records).

## ENS

```bash
thurin ens check ben.thurinlabs.eth             # does the name's id.thurin record match its claim?
thurin ens link ben.thurinlabs.eth              # set it from the keystore
thurin ens link ben.thurinlabs.eth --calldata   # print the transaction for the wallet that manages the name
```

## Keys and wallets

```bash
thurin key list                      # your keys, with the names and proofs that would be published
thurin key export <fingerprint>      # the minimal armored export
thurin key fetch thurinlabs.eth      # the key stored on-chain; --import adds it to your keyring
thurin wallet create | import | list | export | default <name>
```

Keystores are the V3 format `cast`, geth, and most wallets import. `--password-file <path>` for scripts.

## Be a keyserver

```bash
thurin keyserver                     # hkp://127.0.0.1:11371
gpg --keyserver hkp://127.0.0.1:11371 --recv-keys 08B9374FDFBEC67EFFA24E669D3D86E35361EF7B
```

It answers gpg from the registry: no database, no uploads, no email search. Put it in `~/.gnupg/dirmngr.conf` and `--refresh-keys` picks up revocations. A fetch by full fingerprint checks itself, so a keyserver can withhold a key but never swap one. Thurin runs one at `hkps://keys.thurin.id`.

## Run a relayer

```bash
thurin wallet create hot                     # fund it with pocket money
thurin relay --account hot --budget 0.01     # ETH per day
```

It takes permissions over HTTP, runs the same checks as `submit`, and pays from the hot keystore: within the daily budget, one free `attest` per address (`--free-attests`), 10 requests an hour per caller (`--per-hour`), and 6M gas per transaction (`--max-gas`). It's the one command that spends without asking. Put a TLS proxy in front; it listens on localhost. People use it with `--relayer <url>`.

## Networks

`--network mainnet|sepolia|local` (local is anvil on 8545), `--rpc <url>` for your own node. Defaults live in `~/.config/thurin/config.json`. The registry is `0xFa6956c11163517249f8A67F5560a4406B519451`, the same address on Ethereum mainnet and Sepolia.

Exit codes: 0 ok · 1 a check failed · 2 usage · 3 chain or network error.

## Development

```bash
git clone https://github.com/thurinlabs/thurin-cli && cd thurin-cli && npm install
npm run dev -- status thurinlabs.eth
npm test
```
