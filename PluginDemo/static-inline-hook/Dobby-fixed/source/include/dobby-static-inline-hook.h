#include "dobby.h"

typedef struct {
  size_t hook_vaddr;
  size_t code_vaddr;
  size_t code_size;
  size_t original_vaddr;
  size_t instrument_vaddr;

  void *target_replace;
  void *instrument_handler;
} StaticInlineHookBlock;

int dobby_create_instrument_bridge(void *targetData);

bool dobby_static_inline_hook(StaticInlineHookBlock *hookBlock, StaticInlineHookBlock *hookBlockRVA, uint64_t funcRVA,
                              void *funcData, uint64_t targetRVA, void *targetData, uint64_t InstrumentBridgeRVA);
