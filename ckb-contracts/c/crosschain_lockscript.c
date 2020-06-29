#include "blockchain.h"
#include "ckb_syscalls.h"

#define BLAKE2B_BLOCK_SIZE 32
#define SCRIPT_SIZE 32768

#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SCRIPT_TOO_LONG -21
#define ERROR_OVERFLOWING -51
#define ERROR_1ST_CELL_TYPE_HASH_NOT_MATCH -52
#define ERROR_LOAD_INPUT -53

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
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size != BLAKE2B_BLOCK_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  uint8_t buffer[BLAKE2B_BLOCK_SIZE];
  uint64_t len2 = BLAKE2B_BLOCK_SIZE;

  // get TYPE_HASH in tx.inputs[0], cmp it with Script.Args
  // rule of crosschain typescript
  ret = ckb_checked_load_cell_by_field(buffer, &len2, 0, 0, CKB_SOURCE_INPUT,
                                       CKB_CELL_FIELD_TYPE_HASH);
  if (ret == CKB_INDEX_OUT_OF_BOUND) {
    return ERROR_LOAD_INPUT;
  }
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len2 != BLAKE2B_BLOCK_SIZE) {
    return ERROR_ENCODING;
  }
  if (memcmp(buffer, args_bytes_seg.ptr, BLAKE2B_BLOCK_SIZE) == 0) {
    return 0;
  }
  return ERROR_1ST_CELL_TYPE_HASH_NOT_MATCH;
}
