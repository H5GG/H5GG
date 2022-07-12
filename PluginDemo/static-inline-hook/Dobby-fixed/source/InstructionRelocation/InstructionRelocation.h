#include "dobby_internal.h"

void GenRelocateCodeAndBranch(void *buffer, AssemblyCodeChunk *origin, AssemblyCodeChunk *relocated);

CodeBufferBase *GenRelocateCodeAndBranchStatic(void *buffer, AssemblyCodeChunk *origin, AssemblyCodeChunk *relocated);
int GenerateCheckCode(void *buffer, void *address, void *data);
CodeBufferBase *GenerateTrampolineCode(void *src, void *dst);
