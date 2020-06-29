#include "blake2b.h"
#include "blockchain.h"
#include "ckb_syscalls.h"
#include "centralized_crosschain.h"
#include "secp256k1_helper.h"

#define BLAKE2B_BLOCK_SIZE 32
#define SCRIPT_SIZE 32768

#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SCRIPT_TOO_LONG -21
#define ERROR_WITNESS_TOO_LONG -22
#define ERROR_DATA_TOO_LONG -23
#define ERROR_OUT_DATA_TOO_LONG -24
#define ERROR_OUT_DATA_INVALID -25
#define ERROR_INVALID_ARGS -26
#define ERROR_LOAD_INPUT_FAILED -27
#define ERROR_OVERFLOWING -31
#define ERROR_1ST_CELL_TYPE_HASH_NOT_MATCH -32
#define ERROR_LOAD_INPUT -33
#define ERROR_SECP_RECOVER_PUBKEY -51
#define ERROR_SECP_PARSE_SIGNATURE -52
#define ERROR_SECP_SERIALIZE_PUBKEY -53
#define ERROR_PUBKEY_BLAKE160_HASH -54

// Common definitions here, one important limitation, is that this lock script
// only works with scripts and witnesses that are no larger than 32KB. We
// believe this should be enough for most cases.
//
// Here we are also employing a common convention: we append the recovery ID to
// the end of the 64-byte compact recoverable signature.
#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 33
#define TEMP_SIZE 32768
#define RECID_INDEX 64
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define MAX_DATA_SIZE 32768
#define SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65

// Compile-time guard against buffer abuse
#if (MAX_WITNESS_SIZE > TEMP_SIZE) || (SCRIPT_SIZE > TEMP_SIZE)
#error "Temp buffer is not big enough!"
#endif

#define ERROR_GROUP_OUTPUT_INVALID -100
#define ERROR_GROUP_INPUT_INVALID -101
#define ERROR_CAPACITY_INVALID -102
#define ERROR_VALIDATOR_SIGNATURE_INVALID -103

void bin2hex(uint8_t *bin, uint32_t len, char *out) {
  uint8_t i;
  for (i = 0; i < len; i++) {
    out[i * 2] = "0123456789abcdef"[bin[i] >> 4];
    out[i * 2 + 1] = "0123456789abcdef"[bin[i] & 0x0F];
  }
  out[len * 2] = '\0';
}

void dump_bytes(uint8_t *buf, uint32_t len) {
  char buffer[1024] = {0};
  bin2hex(buf, len, buffer);
  ckb_debug(buffer);
}

void dump_mol_s(mol_seg_t t) { dump_bytes(t.ptr, t.size); }

int get_cell_num(size_t cell_type) {
  int ret;
  int i = 0;
  uint8_t buffer[MAX_DATA_SIZE];
  uint64_t len = 1;

  while (1) {
    ret = ckb_load_cell_data(buffer, &len, 0, i, cell_type);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    i += 1;
  }
  return i;
}

int verify_transfer(unsigned char *script) {
  /*
   * First, ensures that the input capacity is not less than output capacity in
   * typescript groups for the input and output cells.
   */
  uint64_t input_capacity = 0, output_capacity = 0;
  uint64_t len = 8;
  int ret =
      ckb_load_cell_by_field((uint8_t *)&input_capacity, &len, 0, 0,
                             CKB_SOURCE_GROUP_INPUT, CKB_CELL_FIELD_CAPACITY);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  len = 8;
  ret =
      ckb_load_cell_by_field((uint8_t *)&output_capacity, &len, 0, 0,
                             CKB_SOURCE_GROUP_OUTPUT, CKB_CELL_FIELD_CAPACITY);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  if (input_capacity > output_capacity) {
    return ERROR_CAPACITY_INVALID;
  }

  /*
   * ensure data does not change
   *
   */
  // load data
  unsigned char out_data[MAX_DATA_SIZE];
  uint64_t out_data_len = MAX_DATA_SIZE;
  ckb_debug("load output data");
  ret = ckb_load_cell_data(out_data, &out_data_len, 0, 0,
                           CKB_SOURCE_GROUP_OUTPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (out_data_len > MAX_DATA_SIZE) {
    return ERROR_OUT_DATA_TOO_LONG;
  }
  unsigned char data[MAX_DATA_SIZE];
  uint64_t data_len = MAX_DATA_SIZE;
  ckb_debug("load input data");
  ret = ckb_load_cell_data(data, &data_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (data_len > MAX_DATA_SIZE) {
    return ERROR_DATA_TOO_LONG;
  }
  // check input data and output data are the same
  if (data_len != out_data_len || memcmp(data, out_data, data_len) != 0) {
    return ERROR_OUT_DATA_INVALID;
  }
  mol_seg_t data_seg;
  data_seg.ptr = data;
  data_seg.size = data_len;

  /*
   * verify signature
   */
  // load witness
  unsigned char witness[MAX_WITNESS_SIZE];
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ckb_debug("load witness");
  ret = ckb_load_witness(witness, &witness_len, 0, 0, CKB_SOURCE_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_TOO_LONG;
  }
  mol_seg_t witness_seg;
  witness_seg.ptr = witness;
  witness_seg.size = witness_len;

  if (MolReader_CrosschainWitness_verify(&witness_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  mol_seg_t messages_seg =
      MolReader_CrosschainWitness_get_messages(&witness_seg);
  // mol_seg_t messages_seg_raw = MolReader_Bytes_raw_bytes(&messages_seg);
  mol_seg_t proof_seg = MolReader_CrosschainWitness_get_proof(&witness_seg);
  ckb_debug("proof");
  dump_mol_s(proof_seg);

  // messages blake2b hash
  unsigned char message[BLAKE2B_BLOCK_SIZE] = {0};
  // message[0] = 0x31;
  // message[1] = 0x32;
  // message[2] = 0x33;
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  // blake2b_update(&blake2b_ctx, message, 3);
  blake2b_update(&blake2b_ctx, messages_seg.ptr, messages_seg.size);
  blake2b_final(&blake2b_ctx, message, BLAKE2B_BLOCK_SIZE);
  ckb_debug("messageHash");
  dump_bytes(message, BLAKE2B_BLOCK_SIZE);

  // extract pubkey hash from data
  // dump_mol_s(data_seg);
  if (MolReader_CrosschainData_verify(&data_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  mol_seg_t pubkey_hash_seg =
      MolReader_CrosschainData_get_pubkey_hash(&data_seg);
  // mol_seg_t pubkey_hash_seg_raw =
  // MolReader_Bytes_raw_bytes(&pubkey_hash_seg);
  ckb_debug("pubkey_hash from data");
  dump_mol_s(pubkey_hash_seg);

  // We are using bitcoin's [secp256k1
  // library](https://github.com/bitcoin-core/secp256k1) for signature
  // verification here. To the best of our knowledge, this is an unmatched
  // advantage of CKB: you can ship cryptographic algorithm within your smart
  // contract, you don't have to wait for the foundation to ship a new
  // cryptographic algorithm. You can just build and ship your own.
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  ret = ckb_secp256k1_custom_load_data(secp_data);
  if (ret != 0) {
    return ret;
  }
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }
  ckb_debug("sig");
  dump_bytes(message, 32);
  dump_mol_s(proof_seg);
  unsigned int compress = SECP256K1_EC_COMPRESSED;
  dump_bytes((uint8_t *)&compress, sizeof(compress));

  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
          &context, &signature, proof_seg.ptr, proof_seg.ptr[RECID_INDEX]) ==
      0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }
  // From the recoverable signature, we can derive the public key used.
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
    return ERROR_SECP_RECOVER_PUBKEY;
  }

  dump_bytes((uint8_t *)pubkey.data, 64);

  // Let's serialize the signature first, then generate the blake2b hash.
  uint8_t temp[TEMP_SIZE];
  size_t pubkey_size = PUBKEY_SIZE;
  if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                    SECP256K1_EC_COMPRESSED) != 1) {
    return ERROR_SECP_SERIALIZE_PUBKEY;
  }
  ckb_debug("pubkey");
  dump_bytes(temp, pubkey_size);

  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, temp, pubkey_size);
  blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

  ckb_debug("pubkey hash");
  dump_bytes(temp, BLAKE2B_BLOCK_SIZE);

  if (memcmp(pubkey_hash_seg.ptr, temp, BLAKE160_SIZE) != 0) {
    return ERROR_PUBKEY_BLAKE160_HASH;
  }

  // return ERROR_VALIDATOR_SIGNATURE_INVALID;
  ckb_debug("finish verify");
  return CKB_SUCCESS;
}

int verify_init() {
  ckb_debug("crosschain cell init start");
  const uint8_t outpoint_size = 36;
  // load script
  unsigned char script[SCRIPT_SIZE];
  uint64_t len = SCRIPT_SIZE;
  int ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size != outpoint_size) {
    return ERROR_ARGUMENTS_LEN;
  }
  // check outpoint
  uint8_t outpoint[36] = {0};
  len = 36;
  ret = ckb_load_input_by_field(&outpoint, &len, 0, 0, CKB_SOURCE_INPUT,
                                CKB_INPUT_FIELD_OUT_POINT);
  if (ret != CKB_SUCCESS) {
    return ERROR_LOAD_INPUT_FAILED;
  }
  // ensure args equal outpoint
  if (memcmp(outpoint, args_bytes_seg.ptr, outpoint_size) != 0) {
    return ERROR_INVALID_ARGS;
  }
  ckb_debug("crosschain cell init success");
  return CKB_SUCCESS;
}

int main() {
  unsigned char script[SCRIPT_SIZE];
  uint64_t len = SCRIPT_SIZE;

  // get myself script
  int ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }

  int input_group_num = get_cell_num(CKB_SOURCE_GROUP_INPUT);
  int output_group_num = get_cell_num(CKB_SOURCE_GROUP_OUTPUT);
  if (output_group_num != 1) {
    return ERROR_GROUP_OUTPUT_INVALID;
  }
  if (input_group_num != 0 && input_group_num != 1) {
    return ERROR_GROUP_INPUT_INVALID;
  }

  // init type
  if (input_group_num == 0) {
    return verify_init();
  }

  // transfer type
  return verify_transfer(script);
}