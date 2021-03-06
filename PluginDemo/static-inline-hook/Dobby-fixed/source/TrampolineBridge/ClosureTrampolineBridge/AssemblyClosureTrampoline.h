#ifndef ASSEMBLY_CLOSURE_TRAMPOLINE_H
#define ASSEMBLY_CLOSURE_TRAMPOLINE_H

#include "dobby_internal.h"

#ifdef ENABLE_CLOSURE_TRAMPOLINE_TEMPLATE
#ifdef __cplusplus
extern "C" {
#endif //__cplusplus
void closure_trampoline_template();
void closure_bridge_template();
#ifdef __cplusplus
}
#endif //__cplusplus
#endif

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

typedef struct _ClosureTrampolineEntry {
  void *address;
  int size;
  void *carry_handler;
  void *carry_data;
} ClosureTrampolineEntry;

void *get_closure_bridge();
CodeBufferBase *get_closure_bridge_static();

#ifdef __cplusplus
}
#endif //__cplusplus

class ClosureTrampoline {
private:
  static LiteMutableArray *trampolines_;

public:
  static ClosureTrampolineEntry *CreateClosureTrampoline(void *carry_data, void *carry_handler);

  static CodeBufferBase *CreateClosureTrampolineStatic(void *address, void *handler_pointer_address,
                                                       void *bridge_address, void *origin_address);
};

#endif
