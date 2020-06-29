#!/usr/bin/env node

const CKB = require("@nervosnetwork/ckb-sdk-core").default;
const utils = require("@nervosnetwork/ckb-sdk-utils");
const ECPair = require("@nervosnetwork/ckb-sdk-utils/lib/ecpair");
const process = require("process");
const fs = require("fs");
const _ = require("lodash");
const cc = require("../build/centralized_crosschain");
const toolkit = require("ckb-js-toolkit");
const Reader = toolkit.Reader;

// const duktapeBinary = fs.readFileSync("./deps/load0");
// const duktapeHash = blake2b(duktapeBinary);
const simpleUdtBinary = fs.readFileSync("./deps/simple_udt");
const simpleUdtHash = blake2b(simpleUdtBinary);
const crosschainTypescript = fs.readFileSync("../ckb-contracts/build/centralized_crosschain_typescript");
// const crosschainTypescript = fs.readFileSync("./deps/always_success");
const crosschainTypescriptHash = blake2b(crosschainTypescript);
const crosschainLockscript = fs.readFileSync("../ckb-contracts/build/centralized_crosschain_lockscript");
const crosschainLockscriptHash = blake2b(crosschainLockscript);

const privateKey =
  "0xd00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc";
const bPrivKey =
  "0xd00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2b0";
const nodeUrl = "http://127.0.0.1:8114/";
const configPath = "./build/config.json";
let config = {};
try {
  config = JSON.parse(fs.readFileSync(configPath));
} catch (err) {
  console.error("config not exit yet");
}
const fee = 100000000n;

const ckb = new CKB(nodeUrl);

process.on("exit", code => {
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  console.log(`About to exit with code: ${code}, save config success`);
});

function blake2b(buffer) {
  return utils
    .blake2b(32, null, null, utils.PERSONAL)
    .update(buffer)
    .digest("binary");
}

function str2hex(str) {
  var arr1 = ["0x"];
  for (var n = 0, l = str.length; n < l; n++) {
    var hex = Number(str.charCodeAt(n)).toString(16);
    arr1.push(hex);
  }
  return arr1.join("");
}

function LittleEndianHexToNum(hex) {
  if (hex.startsWith("0x")) {
    hex = hex.slice(2);
  }
  let num = BigInt(0);
  for (let c = 0; c < hex.length; c += 2) {
    num += BigInt(parseInt(hex.substr(c, 2), 16) * 2 ** (4 * c));
  }
  return num;
}

function signMsg(msg, sk) {
  sk = sk || privateKey;
  const msgHash = blake2b(utils.hexToBytes(msg));
  const msgHashHex = utils.bytesToHex(msgHash);
  const key = new ECPair.default(privateKey, {compressed: true});
  const pk = key.getPublicKey('hex');
  const sig = key.signRecoverable( msgHashHex ).toString();
  console.log({sig, sk, pk, msgHashHex, msg})
  return sig;
}

async function deploy(code_list) {
  const secp256k1Dep = await ckb.loadSecp256k1Dep();
  const publicKey = ckb.utils.privateKeyToPublicKey(privateKey);
  const publicKeyHash = `0x${ckb.utils.blake160(publicKey, "hex")}`;
  const lockScript = {
    hashType: secp256k1Dep.hashType,
    codeHash: secp256k1Dep.codeHash,
    args: publicKeyHash
  };
  const lockHash = ckb.utils.scriptToHash(lockScript);

  const unspentCells = await ckb.loadCells({
    lockHash
  });
  const totalCapacity = unspentCells.reduce(
    (sum, cell) => sum + BigInt(cell.capacity),
    BigInt(0)
  );

  // For simplicity, we will just use 1 CKB as fee. On a real setup you
  // might not want to do this.
  const capacity_list = code_list.map(
    code => BigInt(code.length) * 100000000n + 4100000000n
  );
  //   console.log(capacity_list);
  const outputs = capacity_list.map(capacity => {
    return {
      lock: {
        codeHash:
          "0x0000000000000000000000000000000000000000000000000000000000000000",
        hashType: "data",
        args: "0x"
      },
      type: null,
      capacity: "0x" + capacity.toString(16)
    };
  });

  outputs.push({
    lock: lockScript,
    type: null,
    capacity: "0x" + (totalCapacity - _.sum(capacity_list) - fee).toString(16)
  });
  const outputsData = code_list.map(code => utils.bytesToHex(code));
  outputsData.push("0x");

  const transaction = {
    version: "0x0",
    cellDeps: [
      {
        outPoint: secp256k1Dep.outPoint,
        depType: "depGroup"
      }
    ],
    headerDeps: [],
    inputs: unspentCells.map(cell => ({
      previousOutput: cell.outPoint,
      since: "0x0"
    })),
    outputs,
    witnesses: [
      {
        lock: "",
        inputType: "",
        outputType: ""
      }
    ],
    outputsData
  };
  const signedTransaction = ckb.signTransaction(privateKey)(transaction);

  const txHash = await ckb.rpc.sendTransaction(
    signedTransaction,
    "passthrough"
  );
  config.deployTxHash = txHash;
  console.log(`deployTxHash: ${txHash}`);
}

async function createCrosschainCell() {
  const secp256k1Dep = await ckb.loadSecp256k1Dep();

  const publicKey = ckb.utils.privateKeyToPublicKey(privateKey);
  const publicKeyHash = `0x${ckb.utils.blake160(publicKey, "hex")}`;

  const lockScript = {
    hashType: secp256k1Dep.hashType,
    codeHash: secp256k1Dep.codeHash,
    args: publicKeyHash
  };
  const lockHash = ckb.utils.scriptToHash(lockScript);

  const unspentCells = await ckb.loadCells({
    lockHash
  });
  const totalCapacity = unspentCells.reduce(
    (sum, cell) => sum + BigInt(cell.capacity),
    BigInt(0)
  );

  const CellCapacity = 20000000000000n;

  //   console.log(unspentCells[0]);
  const argsObj = unspentCells[0].outPoint;
  console.log(argsObj);
  const args_ab = cc.SerializeOutPoint({
    tx_hash: new Reader(argsObj.txHash),
    index: intToUint32(argsObj.index),
  })
  const args = (new Reader(args_ab)).serializeJson();

  // init cell data as pubkey hash of validator
  const cc_data_raw = {
    pubkey_hash: new Reader(publicKeyHash),
  }
  const cc_data_ab = cc.SerializeCrosschainData(cc_data_raw);
  const cc_data_reader = new Reader(cc_data_ab);
  const cellData = cc_data_reader.serializeJson();
  config.crosschainCellData = cellData;
  console.log({argsObj, args, publicKeyHash, cellData});

  config.crosschainTypescript = {
    codeHash: utils.bytesToHex(crosschainTypescriptHash),
    hashType: "data",
    args
  };
  config.crosschainLockscript = {
    codeHash: utils.bytesToHex(crosschainLockscriptHash),
    hashType: "data",
    args: utils.scriptToHash(config.crosschainTypescript)
  };
  // const { witness, witness_hex } = gen_witness();
  const transaction = {
    version: "0x0",
    cellDeps: [
      {
        outPoint: {
          txHash: config.deployTxHash,
          index: "0x1"
        },
        depType: "code"
      },
      {
        outPoint: {
          txHash: config.deployTxHash,
          index: "0x2"
        },
        depType: "code"
      },
      {
        outPoint: secp256k1Dep.outPoint,
        depType: "depGroup"
      }
    ],
    headerDeps: [],
    inputs: unspentCells.map(cell => ({
      previousOutput: cell.outPoint,
      since: "0x0"
    })),
    outputs: [
      {
        lock: lockScript,
        type: null,
        capacity: "0x" + (totalCapacity - fee - CellCapacity).toString(16)
      },
      {
        type: config.crosschainTypescript,
        lock: config.crosschainLockscript,
        capacity: "0x" + CellCapacity.toString(16)
      }
    ],
    witnesses: [
      {
        lock: "",
        inputType: "",
        outputType: ""
      },
    ],
    outputsData: ["0x", cellData]
  };
  //   console.log(JSON.stringify(transaction, null, 2))
  const signedTransaction = ckb.signTransaction(privateKey)(transaction);
  // console.log(JSON.stringify(signedTransaction, null, 2))
  // console.log({ witness_len: witness_hex.length / 2 - 1 })

  const txHash = await ckb.rpc.sendTransaction(
    signedTransaction,
    "passthrough"
  );
  console.log(`createCrosschainCell hash: ${txHash}`);
  config.createCrosschainCellTxHash = txHash;
}

async function issueSUDT() {
  const secp256k1Dep = await ckb.loadSecp256k1Dep();

  // admin
  const publicKey = ckb.utils.privateKeyToPublicKey(privateKey);
  const publicKeyHash = `0x${ckb.utils.blake160(publicKey, "hex")}`;
  const lockScript = {
    hashType: secp256k1Dep.hashType,
    codeHash: secp256k1Dep.codeHash,
    args: publicKeyHash
  };
  const lockHash = ckb.utils.scriptToHash(lockScript);

  // user b
  const bPubKey = ckb.utils.privateKeyToPublicKey(bPrivKey);
  const bPubKeyHash = `0x${ckb.utils.blake160(bPubKey, "hex")}`;
  const bLockScript = {
    hashType: secp256k1Dep.hashType,
    codeHash: secp256k1Dep.codeHash,
    args: bPubKeyHash
  };
  const bLockHash = ckb.utils.scriptToHash(bLockScript);

  const unspentCells = await ckb.loadCells({
    lockHash
  });
  const totalCapacity = unspentCells.reduce(
    (sum, cell) => sum + BigInt(cell.capacity),
    BigInt(0)
  );
  config.udtScript = {
    codeHash: utils.bytesToHex(simpleUdtHash),
    hashType: "data",
    args: lockHash
  };
  const CellCapacity = 20000000000000n;

  const transaction = {
    version: "0x0",
    cellDeps: [
      {
        outPoint: {
          txHash: config.deployTxHash,
          index: "0x0"
        },
        depType: "code"
      },
      {
        outPoint: secp256k1Dep.outPoint,
        depType: "depGroup"
      }
    ],
    headerDeps: [],
    inputs: unspentCells.map(cell => ({
      previousOutput: cell.outPoint,
      since: "0x0"
    })),
    outputs: [
      {
        lock: lockScript,
        type: null,
        capacity: "0x" + (totalCapacity - fee - CellCapacity).toString(16)
      },
      {
        lock: bLockScript,
        type: config.udtScript,
        capacity: "0x" + CellCapacity.toString(16)
      }
    ],
    witnesses: [
      {
        lock: "",
        inputType: "",
        outputType: ""
      }
    ],
    outputsData: [
      "0x",
      utils.toHexInLittleEndian("0x" + Number(100000000).toString(16), 16)
    ]
  };
  const signedTransaction = ckb.signTransaction(privateKey)(transaction);
  //   console.log(JSON.stringify(signedTransaction, null, 2))

  const txHash = await ckb.rpc.sendTransaction(
    signedTransaction,
    "passthrough"
  );
  config.issueTxHash = txHash;
  console.log(`issue sudt hash: ${txHash}`);
}

async function lockToCrosschainContract() {
  const secp256k1Dep = await ckb.loadSecp256k1Dep();

  // user b
  const bPubKey = ckb.utils.privateKeyToPublicKey(bPrivKey);
  const bPubKeyHash = `0x${ckb.utils.blake160(bPubKey, "hex")}`;
  const bLockScript = {
    hashType: secp256k1Dep.hashType,
    codeHash: secp256k1Dep.codeHash,
    args: bPubKeyHash
  };
  const bLockHash = ckb.utils.scriptToHash(bLockScript);
  //   const mutaCrosschainMsg = {
  //     to: "0x",
  //     amount: 100,
  //   };
  //   const mutaCrosschainMsgWitness = str2hex(JSON.stringify(mutaCrosschainMsg));
  const mutaCrosschainMsgWitness = "0xcff1002107105460941f797828f468667aa1a2db";

  const CellCapacity = 200000000000n;

  const transaction = {
    version: "0x0",
    cellDeps: [
      {
        outPoint: {
          txHash: config.deployTxHash,
          index: "0x0"
        },
        depType: "code"
      },
      {
        outPoint: secp256k1Dep.outPoint,
        depType: "depGroup"
      }
    ],
    headerDeps: [],
    inputs: [
      {
        previousOutput: {
          txHash: config.issueTxHash,
          index: "0x1"
        },
        since: "0x0"
      }
    ],
    outputs: [
      {
        lock: config.crosschainLockscript,
        type: config.udtScript,
        capacity: "0x" + (CellCapacity - 2n * fee).toString(16)
      }
    ],
    witnesses: [
      {
        lock: "",
        inputType: "",
        outputType: ""
      },
      mutaCrosschainMsgWitness
    ],
    outputsData: [
      utils.toHexInLittleEndian("0x" + Number(100000000).toString(16), 16)
    ]
  };
  // console.log(JSON.stringify(transaction, null, 2));
  const signedTransaction = ckb.signTransaction(bPrivKey)(transaction);
  // console.log(JSON.stringify(signedTransaction, null, 2));

  const txHash = await ckb.rpc.sendTransaction(
    signedTransaction,
    "passthrough"
  );
  console.log(`lockToCrosschain hash: ${txHash}`);
  config.lockToCrosschainTxHash = txHash;
  return txHash;
}

async function unlockCrosschainContract() {
  const secp256k1Dep = await ckb.loadSecp256k1Dep();
  // read from the crosschain cell data
  const fee_rate = 100000n;
  const { witness, witness_hex } = gen_witness();
  const balance = new Object();
  const assetBalanceSum = {};
  const blocks = witness.messages;
  for (let i = 0; i < blocks.length; i++) {
    const events = blocks[i].events;
    for (let j = 0; j < events.length; j++) {
      const event = events[j];
      let asset = balance[event.asset_id] || {};
      asset[event.ckb_receiver] =
        asset[event.ckb_receiver] || BigInt(0) + BigInt(event.amount);
      balance[event.asset_id] = asset;
      assetBalanceSum[event.asset_id] =
        (assetBalanceSum[event.asset_id] || BigInt(0)) + BigInt(event.amount);

      console.log({ event, assetBalanceSum });
    }
  }

  // const fee_receiver = witness.fee_receiver;
  const fee_receiver = '0x0000000000000000000000000000000000000000000000000000000000000005';
  for (let asset_id in balance) {
    let fee_total = BigInt(0);
    let asset = balance[asset_id];
    for (let receiver in asset) {
      let fee = (asset[receiver] * fee_rate) / 100000000n;
      fee_total += fee;
      asset[receiver] -= fee;
    }
    asset[fee_receiver] = fee_total;
  }
  console.log({ balance, assetBalanceSum });

  const crosschainLockCells = await ckb.loadCells({
    lockHash: ckb.utils.scriptToHash(config.crosschainLockscript)
  });
  // console.log(JSON.stringify(crosschainLockCells, null, 2));

  const crosschainCell = _.find(
    crosschainLockCells,
    c => c.type.codeHash === config.crosschainTypescript.codeHash
  );
  // console.log(crosschainCell);

  const inputs = [
    {
      previousOutput: crosschainCell.outPoint,
      since: "0x0"
    }
  ];
  let totalCapacity = BigInt(crosschainCell.capacity);
  const udtHashHex = utils.bytesToHex(simpleUdtHash);
  const backToCrosschainBalance = {};
  console.log({ assetBalanceSum });
  for (let i = 0; i < crosschainLockCells.length; i++) {
    const c = crosschainLockCells[i];
    const udtArgs = c.type.args;
    if (c.type.codeHash !== udtHashHex || assetBalanceSum[udtArgs] === null) {
      continue;
    }
    const cellInfo = await ckb.rpc.getLiveCell(c.outPoint, true);
    // console.log(cellInfo);
    const amountRaw = cellInfo.cell.data.content;
    const amount = LittleEndianHexToNum(amountRaw);
    console.log(amount);
    totalCapacity += BigInt(cellInfo.cell.output.capacity);
    inputs.push({
      previousOutput: c.outPoint,
      since: "0x0"
    });
    if (amount >= assetBalanceSum[udtArgs]) {
      backToCrosschainBalance[udtArgs] = amount - assetBalanceSum[udtArgs];
      assetBalanceSum[udtArgs] = null;
    } else {
      assetBalanceSum[udtArgs] -= amount;
    }
  }
  // console.log({ backToCrosschainBalance });

  // console.log(totalCapacity);

  const outputs = [
    {
      lock: crosschainCell.lock,
      type: crosschainCell.type
    }
  ];
  // TODO: transform the crosschain cell data
  const outputsData = [config.crosschainCellData];

  const udtCellCapacity = 16n * 100000000n + 14100000000n;
  for (const [asset_id, asset] of Object.entries(balance)) {
    let asset = balance[asset_id];
    for (const [receiver, amount] of Object.entries(asset)) {
      let amount = asset[receiver];
      outputs.push({
        lock: {
          args: receiver,
          hashType: secp256k1Dep.hashType,
          codeHash: secp256k1Dep.codeHash
        },
        type: {
          hashType: "data",
          codeHash: utils.bytesToHex(simpleUdtHash),
          args: asset_id
        }
      });
      outputsData.push(utils.toHexInLittleEndian(amount, 16));
    }
  }
  for (const [asset_id, backAmount] of Object.entries(
    backToCrosschainBalance
  )) {
    outputs.push({
      lock: config.crosschainLockscript,
      type: {
        hashType: "data",
        codeHash: utils.bytesToHex(simpleUdtHash),
        args: asset_id
      }
    });
    outputsData.push(utils.toHexInLittleEndian(backAmount, 16));
  }
  for (let i = 0; i < outputs.length; i++) {
    if (i === 0) {
      outputs[i].capacity =
        "0x" +
        (
          totalCapacity -
          udtCellCapacity * BigInt(outputs.length - 1) -
          fee
        ).toString(16);
    } else {
      outputs[i].capacity = "0x" + udtCellCapacity.toString(16);
    }
  }
  // console.log({ outputsData, outputs });
  // console.log(outputsData.slice(1).map(a => LittleEndianHexToNum(a)));
  // console.log(_.sum(outputsData.slice(1).map(a => LittleEndianHexToNum(a))));

  const transaction = {
    version: "0x0",
    cellDeps: [
      {
        outPoint: {
          txHash: config.deployTxHash,
          index: "0x0"
        },
        depType: "code"
      },
      {
        outPoint: {
          txHash: config.deployTxHash,
          index: "0x1"
        },
        depType: "code"
      },
      {
        outPoint: {
          txHash: config.deployTxHash,
          index: "0x2"
        },
        depType: "code"
      },
      {
        outPoint: secp256k1Dep.outPoint,
        depType: "depGroup"
      }
    ],
    headerDeps: [],
    inputs,
    outputs,
    // TODO: witness should encode to molecula
    witnesses: [witness_hex],
    outputsData
    // outputsData: [
    //   utils.toHexInLittleEndian("0x" + Number(100000000).toString(16), 16)
    // ]
  };
  console.log(JSON.stringify(transaction, null, 2));
  const txHash = await ckb.rpc.sendTransaction(transaction, "passthrough");
  console.log(`lockToCrosschain hash: ${txHash}`);
  config.unlockTxHash = txHash;
  return txHash;
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitForTx(txHash) {
  while (true) {
    const tx = await ckb.rpc.getTransaction(txHash);
    try {
      console.log(`tx ${txHash} status: ${tx.txStatus.status}`);
      if (tx.txStatus.status === "committed") {
        return;
      }
    } catch (e) {
      console.log({ e, tx, txHash });
    }
    await delay(1000);
  }
}

function bigintToUint64(n) {
  const buf = Buffer.allocUnsafe(8);
  buf.writeBigInt64LE(n, 0);
  return (new Uint8Array(buf)).buffer;
}

function intToUint32(n) {
  const buf = Buffer.allocUnsafe(4);
  buf.writeInt32LE(n, 0);
  return (new Uint8Array(buf)).buffer;
}

function gen_witness() {
  const witness = {
    messages: [
      {
        header: {
          height: 100n,
        },
        events: [
          {
            asset_id:
                "0x32e555f3ff8e135cece1351a6a2971518392c1e30375c1e006ad0ce8eac07947",
            ckb_receiver:
                "0x0000000000000000000000000000000000000000000000000000000000000001",
            amount: 10000n,
          },
          {
            asset_id:
                "0x32e555f3ff8e135cece1351a6a2971518392c1e30375c1e006ad0ce8eac07947",
            ckb_receiver:
                "0x0000000000000000000000000000000000000000000000000000000000000002",
            amount: 20000n,
          }
        ],
      }
    ],
    proof: "0x0800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009",
  };


  const messages_ab = cc.SerializeMessageVec(witness.messages.map(a => transformMessage(a)));
  const messages_hex = (new Reader(messages_ab)).serializeJson();

  witness.proof = signMsg(messages_hex);

  const witness_transformed = transformWitness(witness);
  const witness_ab = cc.SerializeCrosschainWitness(witness_transformed);
  const witness_reader = new Reader(witness_ab);
  const witness_hex = witness_reader.serializeJson();
  const result = {witness, witness_ab, witness_reader, witness_hex};
  console.log({result, messages_hex, proof: witness.proof});
  return result;
}

function transformEvent(event) {
  return {
    asset_id: new Reader(event.asset_id),
    ckb_receiver: new Reader(event.ckb_receiver),
    amount: bigintToUint64(event.amount),
  }
}

function transformMessage(message) {
  console.log({message});
  return {
    header: {
      height: bigintToUint64(message.header.height),
    },
    events: message.events.map(a => transformEvent(a)),
  }
}

function transformWitness(witness) {
  return {
    messages: witness.messages.map(a => transformMessage(a)),
    proof: new Reader(witness.proof)
  }
}

async function main() {
  const binaryList = [
    simpleUdtBinary,
    crosschainTypescript,
    crosschainLockscript
  ];
  await deploy(binaryList);
  await waitForTx(config.deployTxHash);
  await createCrosschainCell();
  await waitForTx(config.createCrosschainCellTxHash);
  await issueSUDT();
  await waitForTx(config.issueTxHash);
  await lockToCrosschainContract();
  await waitForTx(config.lockToCrosschainTxHash);
  await unlockCrosschainContract();
  await waitForTx(config.unlockTxHash);
  await delay(5000);
  const tx = await ckb.rpc.getTransaction(config.unlockTxHash);
  console.log(JSON.stringify(tx, null, 2));
}

main();
