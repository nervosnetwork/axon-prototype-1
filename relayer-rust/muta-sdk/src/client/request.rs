pub const GET_TRANSACTION_QUERY: &str = r#"
query RpcTransaction($txHash: Hash!) {
    getTransaction(txHash: $txHash) {
      chainId
      cyclesLimit
      cyclesPrice
      nonce
      timeout
      serviceName
      method
      payload
      txHash
      pubkey
      signature 
    }
  }
"#;

pub const GET_BLOCK_QUERY: &str = r#"
query RpcBlock($height: Uint64) {
    getBlock(height: $height) {
      header {
        chainId
        height
        execHeight
        preHash
        timestamp
        orderRoot
        confirmRoot
        stateRoot
        receiptRoot
        cyclesUsed
        proposer
        proof {
          height
          round
          blockHash
          signature
          bitmap
        }
        validatorVersion
        validators {
          address
          proposeWeight
          voteWeight
        }
      }
      orderedTxHashes
      hash
    }
  }
"#;

pub const GET_RECEIPT_QUERY: &str = r#"
query RpcReceipt($txHash: Hash!) {
    getReceipt(txHash: $txHash) {
      stateRoot
      height    
      txHash   
      cyclesUsed
      events {
        service
        topic
        data
      }   
      response {
        serviceName
        method
        response {
          code
          succeedData
          errorMessage
        }
      }
    }
  }
"#;

pub const GET_BLOCK_HOOK_QUERY: &str = r#"
query RpcBlockHookReceipt($height: Uint64!) {
    getBlockHookReceipt(height: $height) {
      height
      stateRoot
      events {
        service
        topic
        data
      }   
    }
  }
"#;

pub const SERVICE_QUERY: &str = r#"
query RpcService($height: Uint64, $cyclesLimit: Uint64, $cyclesPrice: Uint64, $caller: Address!, $serviceName: String!, $method: String!, $payload: String!) {
    queryService(height: $height, cyclesLimit: $cyclesLimit, cyclesPrice: $cyclesPrice, caller: $caller, serviceName: $serviceName, method: $method, payload: $payload) {
      code
      succeedData
      errorMessage   
    }
  }
"#;

pub const SEND_TRANSACTION: &str = r#"
mutation RpcSendTransaction($input_raw: InputRawTransaction!, $input_encryption: InputTransactionEncryption) {
    sendTransaction(input_raw: $input_raw, $input_encryption: input_encryption)
  }
"#;
