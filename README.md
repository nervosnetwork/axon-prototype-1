# Layer 2 Sidechain Solution for Nervos Network

Axon is a layer 2 sidechain solution for Nervos Network.


## Run Centralized Crosschain Demo

```bash
# run local ckb dev chain

# ckb version used: v0.30.1
# https://github.com/nervosnetwork/ckb/releases/tag/v0.30.1
# Download on Mac: wget https://github.com/nervosnetwork/ckb/releases/download/v0.30.1/ckb_v0.30.1_x86_64-apple-darwin.zip
# unzip and add the binary path to system PATH
$ ckb init -c dev -C ckb-data --ba-arg 0x5a7487f529b8b8fd4d4a57c12dc0c70f7958a196
$ ckb run -C ckb-data
$ ckb miner -C ckb-data

# you can edit the ckb-data/ckb.toml logger config as below to show ckb-script debug info
# [logger]
# filter = "info,ckb-script=debug"

# compile the ckb contracts
$ make install-tools
$ make generate-protocol
$ make all-via-docker

# run demo
$ cd demo
$ yarn
# install https://github.com/xxuejie/moleculec-es
$ go get github.com/xxuejie/moleculec-es/cmd/moleculec-es
$ go install github.com/xxuejie/moleculec-es/cmd/moleculec-es
# add the $GOPATH/bin to $PATH, continue if the cmd below success
$ which moleculec-es
# generate schema
$ make schema
# run the demo
$ make demo
```