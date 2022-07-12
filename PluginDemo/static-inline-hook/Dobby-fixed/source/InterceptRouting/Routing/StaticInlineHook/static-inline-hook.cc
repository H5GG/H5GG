
#include "dobby_internal.h"

#include "dobby-static-inline-hook.h"

#include "Interceptor.h"
#include "InterceptRouting/InterceptRouting.h"

#include "TrampolineBridge/ClosureTrampolineBridge/AssemblyClosureTrampoline.h"

int dobby_create_instrument_bridge(void *targetData) {
  CodeBufferBase *bridge = get_closure_bridge_static();
  memcpy(targetData, bridge->getRawBuffer(), bridge->getSize());
  return bridge->getSize();
}

bool dobby_static_inline_hook(StaticInlineHookBlock *hookBlock, StaticInlineHookBlock *hookBlockRVA, uint64_t funcRVA,
                              void *funcData, uint64_t targetRVA, void *targetData, uint64_t InstrumentBridgeRVA) {

  hookBlock->code_vaddr = targetRVA;

  hookBlock->hook_vaddr = funcRVA;

  CodeBufferBase *trampoline_buffer = GenerateTrampolineCode((void *)funcRVA, (void *)targetRVA);

  int hdrsize = GenerateCheckCode(targetData, (void *)targetRVA, &hookBlockRVA->target_replace);

  targetRVA += hdrsize;
  *(uint64_t *)&targetData += hdrsize;
  hookBlock->code_size += hdrsize;

  // generate original code
  AssemblyCodeChunk *origin = AssemblyCodeBuilder::FinalizeFromAddress(funcRVA, trampoline_buffer->getSize());
  // generate the relocated code
  AssemblyCodeChunk *relocated = AssemblyCodeBuilder::FinalizeFromAddress(targetRVA, 0);

  CodeBufferBase *origin_code = GenRelocateCodeAndBranchStatic(funcData, origin, relocated);

  memcpy(targetData, origin_code->getRawBuffer(), origin_code->getSize());

  void *origin_vaddr = (void *)targetRVA;

  hookBlock->original_vaddr = (uint64_t)origin_vaddr;

  targetRVA += origin_code->getSize();
  *(uint64_t *)&targetData += origin_code->getSize();
  hookBlock->code_size += origin_code->getSize();

  CodeBufferBase *InstrumentTrampoline = ClosureTrampoline::CreateClosureTrampolineStatic(
      (void *)targetRVA, &hookBlockRVA->instrument_handler, (void *)InstrumentBridgeRVA, origin_vaddr);

  memcpy(targetData, InstrumentTrampoline->getRawBuffer(), InstrumentTrampoline->getSize());

  hookBlock->instrument_vaddr = targetRVA;
  hookBlock->code_size += InstrumentTrampoline->getSize();

  //last, copy trampoline code
  memcpy(funcData, trampoline_buffer->getRawBuffer(), trampoline_buffer->getSize());

  return true;
}
