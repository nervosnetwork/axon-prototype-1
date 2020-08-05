#!/usr/bin/env node

const CKB = require("@nervosnetwork/ckb-sdk-core").default;
const utils = require("@nervosnetwork/ckb-sdk-utils");
const ECPair = require("@nervosnetwork/ckb-sdk-utils/lib/ecpair");
const fetch = require("node-fetch");
const fs = require("fs");
const path = require("path");
const _ = require("lodash");
const toml = require('toml');
const json2toml = require('json2toml');

const simpleUdtBinary = fs.readFileSync(path.join(__dirname, "../deps/simple_udt"));
const simpleUdtHash = blake2b(simpleUdtBinary);
const crosschainTypescript = fs.readFileSync(path.join(__dirname, "../../ckb-contracts-rust/build/debug/crosschain-v2"));
const crosschainTypescriptHash = blake2b(crosschainTypescript);
const crosschainLockscript = fs.readFileSync(path.join(__dirname, "../../ckb-contracts-rust/build/debug/lockscript"));
const crosschainLockscriptHash = blake2b(crosschainLockscript);


const bPrivKey =
  "0xd00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2b0";

const relayerConfigPath = path.join(__dirname, "../../relayer-rust/relayer_config.json");
const relayerConfigPathToml = path.join(__dirname, "../../relayer-rust/relayer_config.toml");
// const relayerConfig = JSON.parse(fs.readFileSync(relayerConfigPath));
const relayerConfig = {
  ckb:{
    url: "http://192.168.10.2:8114",
    url_indexer: "http://192.168.10.2:8116",
    privateKey: "0xd00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc",
  },
  muta:{
    endpoint: "http://192.168.10.2:8000/graphql",
    address: "0x016cbd9ee47a255a6f68882918dcdd9e14e6bee1",
    privateKey: "0x30269d47fcf602b889243722b666881bf953f1213228363d34cf04ddcd51dfd2"
  },
};

const privateKey = relayerConfig.ckb.privateKey;
const nodeUrl = relayerConfig.ckb.url;
const inquirer = require("inquirer")

let config = {};
const fee = 100000000n;
const ckb = new CKB(nodeUrl);

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

function snakifyKeys(fields) {
  // because this function can receive map of ArrayNodes, we have to do this
  let jsonFields = JSON.parse(JSON.stringify(fields));

  for (let key in jsonFields) {
    if (jsonFields[key] instanceof Object) {
      // we need to go deeper!
      jsonFields[key] = snakifyKeys(jsonFields[key]);
    }

    let snakeKey = key.replace(/\.?([A-Z]+)/g, function(x, y) {return '_' + y.toLowerCase();}).replace(/^_/, '');
    jsonFields[snakeKey] = jsonFields[key];
    // remove the unwanted camelCase key
    if (snakeKey !== key) {
      delete jsonFields[key];
    }
  }
  return jsonFields;
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

  const unspentCells = (await ckb.loadCells({
    lockHash
  })).filter(cell => !cell.type
  );

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

  // crosschain-v2
  config.validatorsLockscript = lockScript

  const unspentCells = (await ckb.loadCells({
    lockHash
  })).filter(cell => !cell.type
  );

  const totalCapacity = unspentCells.reduce(
    (sum, cell) => sum + BigInt(cell.capacity),
    BigInt(0)
  );

  const CellCapacity = 20000000000000n;
  // init cell data in crosschain-v2, just used as placeholder
  const cellData = "0x";
  config.crosschainCellData = cellData;
  config.crosschainTypescript = {
    codeHash: utils.bytesToHex(crosschainTypescriptHash),
    hashType: "data",
    args: lockHash
  };
  config.crosschainLockscript = {
    codeHash: utils.bytesToHex(crosschainLockscriptHash),
    hashType: "data",
    args: utils.scriptToHash(config.crosschainTypescript)
  };
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
        lock: config.validatorsLockscript,
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
  const signedTransaction = ckb.signTransaction(privateKey)(transaction);
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

  const unspentCells = (await ckb.loadCells({
    lockHash
  })).filter(cell => !cell.type);

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

async function lockToCrosschainContract(amount) {
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
  const mutaCrosschainMsgWitness = relayerConfig.muta.address;

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
      utils.toHexInLittleEndian("0x" + Number(amount).toString(16), 16)
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
    await delay(3000);
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

async function storeConfigToRelayer(config) {
  // store sudt_id that was arg of udtScript.args
  if (!relayerConfig.sudtIDs){
    relayerConfig.sudtIDs = []
  }
  if (relayerConfig.sudtIDs.indexOf(config.udtScript.args) === -1) {
    relayerConfig.sudtIDs.push( config.udtScript.args );
  }

  // calcute scriptHash
  config.crosschainLockscriptHash = utils.scriptToHash(config.crosschainLockscript)
  config.crosschainTypescriptHash = utils.scriptToHash(config.crosschainTypescript)
  config.udtScriptHash = utils.scriptToHash(config.udtScript)

  // store config to relayerConfig
  for (const key in config) {
    relayerConfig.ckb[key] = config[key]
  }
  fs.writeFileSync(relayerConfigPath, JSON.stringify(relayerConfig, null, 2));
  fs.writeFileSync(relayerConfigPathToml, json2toml(snakifyKeys(relayerConfig)));
  await delay(2000)
}

async function waitForLockToLockscript() {
  const questions = [
    {
      type: 'input',
      name: 'lockscript',
      message:
          `relay_config generated, please start the relayer\nEnter return to lock sudt to crosschain lockscript`,
      validate: (value) => {
        return true;
      }
    }
  ];

  await inquirer.prompt(questions).then(answers => ({}));
}

async function waitForBurnSudt() {
  const questions = [
    {
      type: 'input',
      name: 'burnSudt',
      message: `Enter return to send burn_sudt to muta, then unlocking the sudt from ckb`,
      validate: (value) => {
        return true;
      }
    }
  ];

  await inquirer.prompt(questions).then(answers => ({}));
}

async function get_tip_height() {
  const height = await fetch(relayerConfig.muta.endpoint, {
    "headers": {
      "accept": "*/*",
      "accept-language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,lb;q=0.6",
      "content-type": "application/json"
    },
    "referrer": "http://0.0.0.0:8000/graphiql",
    "referrerPolicy": "no-referrer-when-downgrade",
    "body": "{\"operationName\":null,\"variables\":{},\"query\":\"{\\n  getBlock(height: null) {\\n    header {\\n      height\\n    }\\n  }\\n}\\n\"}",
    "method": "POST",
    "mode": "cors",
    "credentials": "omit"
  }).then(res => res.json()).then(json => json.data.getBlock.header.height).then(height => parseInt(height, 16) + 19).then(height => '0x' + height.toString(16)).then(height => {
    return height
  });

  return height;
}

async function get_tx_receipt(txHash) {
  const res = await fetch(relayerConfig.muta.endpoint, {
    "headers": {
      "accept": "*/*",
      "accept-language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,lb;q=0.6",
      "content-type": "application/json"
    },
    "referrer": "http://0.0.0.0:8000/graphiql",
    "referrerPolicy": "no-referrer-when-downgrade",
    "body": `{\"operationName\":null,\"variables\":{},\"query\":\"{\\n  getReceipt(txHash: \\\"${txHash}\\\") {\\n    height\\n    response {\\n      serviceName\\n      response {\\n        code\\n        succeedData\\n        errorMessage\\n      }\\n    }\\n    events {\\n      data\\n      topic\\n      service\\n    }\\n  }\\n}\\n\"}`,
    "method": "POST",
    "mode": "cors"
  });
  const data = (await res.json()).data
  return data ? data.getReceipt : null
}

async function burn_sudt(tip_height, amount) {
  const sudtId = config.udtScript.args
  let txHash = await fetch(relayerConfig.muta.endpoint, {
    "headers": {
      "accept": "*/*",
      "accept-language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,lb;q=0.6",
      "content-type": "application/json"
    },
    "referrer": "http://0.0.0.0:8000/graphiql",
    "referrerPolicy": "no-referrer-when-downgrade",
    "body": `{\"operationName\":\"burn_sudt\",\"variables\":{},\"query\":\"mutation burn_sudt {\\n  unsafeSendTransaction(inputRaw: {serviceName: \\\"ckb_sudt\\\", method: \\\"burn_sudt\\\", payload: \\\"{\\\\\\\"id\\\\\\\": \\\\\\"${sudtId}\\\\\\", \\\\\\\"receiver\\\\\\\": \\\\\\\"0xaaaade6c26706c095dcacde9e5c34b0b6160f3b8fe76264a1fa8f0bde756b191\\\\\\\", \\\\\\\"amount\\\\\\\": ${amount}\\\", timeout: \\\"${tip_height}\\\", nonce: \\\"0x9db2d7efe2b61a88827e4836e2775d913a442ed2f9096ca1233e479607c27cf7\\\", chainId: \\\"0xb6a4d7da21443f5e816e8700eea87610e6d769657d6b8ec73028457bf2ca4036\\\", cyclesPrice: \\\"0x9\\\", cyclesLimit: \\\"0x99999\\\"}, inputPrivkey: \\\"0x30269d47fcf602b889243722b666881bf953f1213228363d34cf04ddcd51dfd2\\\")\\n}\\n\"}`,
    "method": "POST",
    "mode": "cors"
  }).then(res => res.json()).then(json => {
    return json.data.unsafeSendTransaction;
  });

  return txHash;
}

async function get_block_hook_receipt(height) {
  await fetch(relayerConfig.muta.endpoint, {
    "headers": {
      "accept": "*/*",
      "accept-language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,lb;q=0.6",
      "content-type": "application/json"
    },
    "referrer": "http://0.0.0.0:8000/graphiql",
    "referrerPolicy": "no-referrer-when-downgrade",
    "body": `{\"operationName\":null,\"variables\":{},\"query\":\"{\\n  getBlockHookReceipt(height: \\\"${height}\\\") {\\n    height\\n    events {\\n      data\\n      topic\\n      service\\n    }\\n    stateRoot\\n  }\\n}\\n\"}`,
    "method": "POST",
    "mode": "cors",
    "credentials": "omit"
  }).then(res => res.json()).then(json => json.data.getBlockHookReceipt).then(console.log);
}

async function burnSudtToMuta(amount) {
  // muta crosschain to ckb
  let tip_height = await get_tip_height();
  console.log("user call ckb-sudt to burn sudt and get burn-sudt-proof:\n");

  console.log("sending tx and get txHash:\n");
  const txHash = await burn_sudt(tip_height, amount);
  console.log(txHash);
}

async function getUdtAmountFromCkb(lockHash, sudt_id) {
  const unspentCells = (await ckb.loadCells({
    lockHash
  })).filter(cell => cell.type && cell.type.args === sudt_id);

  let sum = 0n;
  for (let i = 0; i < unspentCells.length; i++) {
    let cell = unspentCells[i];
    const cellInfo = await ckb.rpc.getLiveCell(cell.outPoint, true);
    // console.log(cellInfo);
    const amountRaw = cellInfo.cell.data.content;
    const amount = LittleEndianHexToNum(amountRaw);
    sum += amount;
  }
  return sum;
}

async function getUdtAmountFromMuta(sudt_id, address) {
  const res = await fetch(relayerConfig.muta.endpoint, {
    "headers": {
      "accept": "*/*",
      "accept-language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,lb;q=0.6",
      "content-type": "application/json"
    },
    "referrer": "http://0.0.0.0:8000/graphiql",
    "referrerPolicy": "no-referrer-when-downgrade",
    "body": `{"operationName":null,"variables":{},"query":"{\\n  queryService(cyclesLimit: \\"0x123456\\", cyclesPrice: \\"0x123456\\", caller: \\"0x016cbd9ee47a255a6f68882918dcdd9e14e6bee1\\", serviceName: \\"ckb_sudt\\", method: \\"get_balance\\", payload: \\"{\\\\\\"id\\\\\\":\\\\\\"${sudt_id}\\\\\\",\\\\\\"user\\\\\\":\\\\\\"${address}\\\\\\"}\\") {\\n    code\\n    succeedData\\n    errorMessage\\n  }\\n}\\n"}`,
    "method": "POST",
    "mode": "cors"
  });

  const data = (await res.json()).data
  if (!data) {
    return null;
  }

  console.log( data.queryService.succeedData );
  const obj = JSON.parse( data.queryService.succeedData );
  return BigInt(obj.balance);
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

  await storeConfigToRelayer(config)


  const lockhash = relayerConfig.ckb.crosschainLockscriptHash;
  const sudt_id = relayerConfig.ckb.udtScript.args;
  const amount = 100000000;
  console.log("sudt_id: " + sudt_id);
  console.log("lockhash: " + lockhash, "  balance: "+ await getUdtAmountFromCkb(lockhash, sudt_id));
  console.log("lock amount to crosschain: " + amount );
  await waitForLockToLockscript()
  await lockToCrosschainContract(amount);

  await waitForTx(config.lockToCrosschainTxHash);
  console.log("lockhash: " + lockhash, "  balance: "+ await getUdtAmountFromCkb(lockhash, sudt_id));

  console.log("\nmuta balance: ");
  await getUdtAmountFromMuta(sudt_id, relayerConfig.muta.address);

  await waitForBurnSudt()

  const burn_amount = 3;
  await burnSudtToMuta(burn_amount);

  console.log("burn sudt amount from muta to ckb: " + burn_amount);
  console.log("waiting for burnSudtTx committed on muta")
  await delay(5000);
  console.log("\nmuta balance: ");
  await getUdtAmountFromMuta(sudt_id, relayerConfig.muta.address);

  console.log("lockhash: " + lockhash, "  balance: "+ await getUdtAmountFromCkb(lockhash, sudt_id));
}

module.exports = {main, burnSudtToMuta}
