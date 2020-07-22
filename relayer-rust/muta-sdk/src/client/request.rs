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
