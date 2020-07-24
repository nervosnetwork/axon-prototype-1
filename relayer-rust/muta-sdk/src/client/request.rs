pub const GET_TRANSACTION_QUERY: &str = r#"
query RpcTransaction($txHash: Hash!) {
    getTransaction(txHash: $txHash) {
      chainId
      cyclesLimit
      cyclesPrice
      nonce
      timeout
      sender
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
        prevHash
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
