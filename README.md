# Layer 2 Sidechain Solution for Nervos Network

Axon is a layer 2 sidechain solution for Nervos Network.


## Run Centralized Crosschain Demo

```bash
# run local ckb dev chain

# ckb version used: v0.33.0-pre1
# https://github.com/nervosnetwork/ckb/releases/tag/v0.33.0-pre1
# Download on Mac: wget https://github.com/nervosnetwork/ckb/releases/download/v0.33.0-pre1/ckb_v0.33.0-pre1_x86_64-apple-darwin.zip
# unzip and add the binary path to system PATH
$ cd /path/where/you/want/to/put/ckb-data
$ ckb init -c dev -C ckb-data --ba-arg 0x5a7487f529b8b8fd4d4a57c12dc0c70f7958a196
$ ckb run -C ckb-data
$ ckb miner -C ckb-data
# you can edit the ckb-data/ckb.toml logger config as below to show ckb-script debug info
# [logger]
# filter = "info,ckb-script=debug"

# muta chain
# open another terminal
$ git clone https://github.com/mkxbl/muta
$ git checkout axon-single-operator
$ cd muta
$ cargo build --release --example muta-chain
$ ./target/release/examples/muta-chain

# compile the ckb contracts
# open another terminal
$ cd axon/ckb-contracts-rust
$ capsule build
$ capsule test

# run demo
# open another terminal
$ cd axon/demo
$ yarn
$ make demo
```