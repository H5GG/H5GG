#include <libgen.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <mach-o/fixup-chains.h>
#include <mach/vm_page_size.h>
#include <Foundation/Foundation.h>

#pragma GCC diagnostic ignored "-Warc-performSelector-leaks"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wincomplete-implementation"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-W#warnings"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"

#include "static-inline.h"

#define STATIC_HOOK_CODEPAGE_SIZE PAGE_SIZE
#define STATIC_HOOK_DATAPAGE_SIZE PAGE_SIZE

uint64_t va2rva(struct mach_header_64* header, uint64_t va)
{
    uint64_t rva = va;
    
    uint64_t header_vaddr = -1;
    struct load_command* lc = (struct load_command*)((UInt64)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
        
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 * seg = (struct segment_command_64 *)lc;
            
            if(seg->fileoff==0 && seg->filesize>0)
            {
                if(header_vaddr != -1) {
                    NSLog(@"multi header mapping! %s", seg->segname);
                    return 0;
                }
                header_vaddr = seg->vmaddr;
            }
        }
        
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    if(header_vaddr != -1) {
        NSLog(@"header_vaddr=%p", header_vaddr);
        rva -= header_vaddr;
    }
    
    NSLog(@"va2rva %p=>%p", va, rva);
    
    return rva;
}

void* rva2data(struct mach_header_64* header, uint64_t rva)
{
    uint64_t header_vaddr = -1;
    struct load_command* lc = (struct load_command*)((UInt64)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
        
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 * seg = (struct segment_command_64 *)lc;
            
            if(seg->fileoff==0 && seg->filesize>0)
            {
                if(header_vaddr != -1) {
                    NSLog(@"multi header mapping! %s", seg->segname);
                    return NULL;
                }
                header_vaddr = seg->vmaddr;
            }
        }
        
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    if(header_vaddr != -1) {
        NSLog(@"header_vaddr=%p", header_vaddr);
        rva += header_vaddr;
    }
    
    //struct load_command*
    lc = (struct load_command*)((UInt64)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {

        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 * seg = (struct segment_command_64 *) lc;
            
            uint64_t seg_vmaddr_start = seg->vmaddr;
            uint64_t seg_vmaddr_end   = seg_vmaddr_start + seg->vmsize;
            if ((uint64_t)rva >= seg_vmaddr_start && (uint64_t)rva < seg_vmaddr_end)
            {
              // some section like '__bss', '__common'
              uint64_t offset = (uint64_t)rva - seg_vmaddr_start;
              if (offset > seg->filesize)
                return NULL;
                
                printf("vaddr=%p offset=%p\n", rva, seg->fileoff + offset);
              return (void*)((uint64_t)header + seg->fileoff + offset);
            }
        }

        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    return NULL;
}


NSMutableData* load_macho_data(NSString* path)
{
    NSMutableData* macho = [NSMutableData dataWithContentsOfFile:path];
    if(!macho) return nil;
    
    UInt32 magic = *(uint32_t*)macho.mutableBytes;
    if(magic==FAT_CIGAM)
    {
        struct fat_header* fathdr = (struct fat_header*)macho.mutableBytes;
        struct fat_arch* archdr = (struct fat_arch*)((UInt64)fathdr + sizeof(*fathdr));
        NSLog(@"add_hook_section nfat_arch=%d", NXSwapLong(fathdr->nfat_arch));
        if(NXSwapLong(fathdr->nfat_arch) != 1) {
            NSLog(@"macho has too many arch!");
            return nil;
        }
        
        if(NXSwapLong(archdr->cputype) != CPU_TYPE_ARM64 || archdr->cpusubtype!=0) {
            NSLog(@"macho arch not support!");
            return nil;
        }
        NSLog(@"subarch=%x %x", NXSwapLong(archdr->offset), NXSwapLong(archdr->size));
        macho = [NSMutableData dataWithData:
                 [macho subdataWithRange:NSMakeRange(NXSwapLong(archdr->offset), NXSwapLong(archdr->size))]];
        
    } else if(magic==FAT_CIGAM_64)
    {
        struct fat_header* fathdr = (struct fat_header*)macho.mutableBytes;
        struct fat_arch_64* archdr = (struct fat_arch_64*)((UInt64)fathdr + sizeof(*fathdr));
        NSLog(@"macho nfat_arch=%d", NXSwapLong(fathdr->nfat_arch));
        if(NXSwapLong(fathdr->nfat_arch) != 1) {
            NSLog(@"macho has too many arch!");
            return nil;
        }
        
        if(NXSwapLong(archdr->cputype) != CPU_TYPE_ARM64 || archdr->cpusubtype!=0) {
            NSLog(@"macho arch not support!");
            return nil;
        }
        NSLog(@"subarch=%x %x", NXSwapLong(archdr->offset), NXSwapLong(archdr->size));
        macho = [NSMutableData dataWithData:
                 [macho subdataWithRange:NSMakeRange(NXSwapLong(archdr->offset), NXSwapLong(archdr->size))]];
        
    } else if(magic != MH_MAGIC_64) {
        NSLog(@"macho arch not support!");
        return nil;
    }
    
    return macho;
}

NSMutableData* add_hook_section(NSMutableData* macho)
{
    struct mach_header_64* header = (struct mach_header_64*)macho.mutableBytes;
    NSLog(@"macho %x %x", header->magic, macho.length);
    
    uint64_t vm_end = 0;
    uint64_t min_section_offset = 0;
    struct segment_command_64* linkedit_seg = NULL;
    
    struct load_command* lc = (struct load_command*)((UInt64)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
        NSLog(@"macho load cmd=%d", lc->cmd);
        
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 * seg = (struct segment_command_64 *) lc;
            
            printf("segment: %s file=%x:%x vm=%p:%p\n", seg->segname, seg->fileoff, seg->filesize, seg->vmaddr, seg->vmsize);
            
            if(strcmp(seg->segname,SEG_LINKEDIT)==0)
                linkedit_seg = seg;
            else
            if(seg->vmsize && vm_end<(seg->vmaddr+seg->vmsize))
                vm_end = seg->vmaddr+seg->vmsize;
            
            struct section_64* sec = (struct section_64*)((uint64_t)seg+sizeof(*seg));
            for(int j=0; j<seg->nsects; j++)
            {
                printf("section[%d] = %s/%s offset=%x vm=%p:%p", j, sec[j].segname, sec[j].sectname,
                      sec[j].offset, sec[j].addr, sec[j].size);
                
                if(min_section_offset < sec[j].offset)
                    min_section_offset = sec[j].offset;
            }
        }
        
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    if(!min_section_offset || !vm_end || !linkedit_seg) {
        NSLog(@"cannot parse macho file!");
        return nil;
    }
    
    NSLog(@"min_section_offset=%x vm_end=%p", min_section_offset, vm_end);
    
    NSRange linkedit_range = NSMakeRange(linkedit_seg->fileoff, linkedit_seg->filesize);
    NSData* linkedit_data = [macho subdataWithRange:linkedit_range];
    [macho replaceBytesInRange:linkedit_range withBytes:nil length:0];
    
    
    struct segment_command_64 text_seg = {
        .cmd = LC_SEGMENT_64,
        .cmdsize=sizeof(struct segment_command_64)+sizeof(struct section_64),
        .segname = {"__HOOK_TEXT"},
        .vmaddr = vm_end,
        .vmsize = STATIC_HOOK_CODEPAGE_SIZE,
        .fileoff = macho.length,
        .filesize = STATIC_HOOK_CODEPAGE_SIZE,
        .maxprot = VM_PROT_READ|VM_PROT_EXECUTE,
        .initprot = VM_PROT_READ|VM_PROT_EXECUTE,
        .nsects = 1,
        .flags = 0
    };
    struct section_64 text_sec = {
        .segname = {"__HOOK_TEXT"},
        .sectname = {"__hook_text"},
        .addr = text_seg.vmaddr,
        .size = text_seg.vmsize,
        .offset = (uint32_t)text_seg.fileoff,
        .align = 0,
        .reloff = 0,
        .nreloc = 0,
        .flags = S_ATTR_PURE_INSTRUCTIONS|S_ATTR_SOME_INSTRUCTIONS,
        .reserved1 = 0, .reserved2 = 0, .reserved3 = 0
    };
    
    struct segment_command_64 data_seg = {
        .cmd = LC_SEGMENT_64,
        .cmdsize=sizeof(struct segment_command_64)+sizeof(struct section_64),
        .segname = {"__HOOK_DATA"},
        .vmaddr = text_seg.vmaddr+text_seg.vmsize,
        .vmsize = STATIC_HOOK_CODEPAGE_SIZE,
        .fileoff = text_seg.fileoff+text_seg.filesize,
        .filesize = STATIC_HOOK_CODEPAGE_SIZE,
        .maxprot = VM_PROT_READ|VM_PROT_WRITE,
        .initprot = VM_PROT_READ|VM_PROT_WRITE,
        .nsects = 1,
        .flags = 0
    };
    struct section_64 data_sec = {
        .segname = {"__HOOK_DATA"},
        .sectname = {"__hook_data"},
        .addr = data_seg.vmaddr,
        .size = data_seg.vmsize,
        .offset = (uint32_t)data_seg.fileoff,
        .align = 0,
        .reloff = 0,
        .nreloc = 0,
        .flags = 0, //S_ZEROFILL,
        .reserved1 = 0, .reserved2 = 0, .reserved3 = 0
    };
    
    uint64_t linkedit_cmd_offset = (uint64_t)linkedit_seg - ((uint64_t)header+sizeof(*header));
    unsigned char* cmds = (unsigned char*)malloc(header->sizeofcmds);
    memcpy(cmds, (unsigned char*)header+sizeof(*header), header->sizeofcmds);
    unsigned char* patch = (unsigned char*)header +sizeof(*header) + linkedit_cmd_offset;
    
    memcpy(patch, &text_seg, sizeof(text_seg));
    patch += sizeof(text_seg);
    memcpy(patch, &text_sec, sizeof(text_sec));
    patch += sizeof(text_sec);

    memcpy(patch, &data_seg, sizeof(data_seg));
    patch += sizeof(data_seg);
    memcpy(patch, &data_sec, sizeof(data_sec));
    patch += sizeof(data_sec);
    
    memcpy(patch, cmds+linkedit_cmd_offset, header->sizeofcmds-linkedit_cmd_offset);
    
    linkedit_seg = (struct segment_command_64*)patch;
    
    header->ncmds += 2;
    header->sizeofcmds += text_seg.cmdsize + data_seg.cmdsize;
    
    linkedit_seg->fileoff = macho.length+text_seg.filesize+data_seg.filesize;
    linkedit_seg->vmaddr = vm_end+text_seg.vmsize+data_seg.vmsize;
    
    struct linkedit_data_command *chainedFixups = NULL;
    
    // fix load_command
    struct load_command *load_cmd = (struct load_command *)((uint64_t)header + sizeof(*header));
    for (int i = 0; i < header->ncmds;
         i++, load_cmd = (struct load_command *)((uint64_t)load_cmd + load_cmd->cmdsize))
    {
        uint64_t fixoffset = text_seg.filesize+data_seg.filesize;// + linkedit_seg->filesize;
        
      switch (load_cmd->cmd)
      {
          case LC_DYLD_INFO:
          case LC_DYLD_INFO_ONLY:
          {
            struct dyld_info_command *tmp = (struct dyld_info_command *)load_cmd;
            tmp->rebase_off += fixoffset;
            tmp->bind_off += fixoffset;
            if (tmp->weak_bind_off)
              tmp->weak_bind_off += fixoffset;
            if (tmp->lazy_bind_off)
              tmp->lazy_bind_off += fixoffset;
            if (tmp->export_off)
              tmp->export_off += fixoffset;
            NSLog(@"[-] fix LC_DYLD_INFO_ done\n");
          } break;
              
          case LC_SYMTAB:
          {
            struct symtab_command *tmp = (struct symtab_command *)load_cmd;
            if (tmp->symoff)
              tmp->symoff += fixoffset;
            if (tmp->stroff)
              tmp->stroff += fixoffset;
            NSLog(@"[-] fix LC_SYMTAB done\n");
          } break;
              
          case LC_DYSYMTAB:
          {
            struct dysymtab_command *tmp = (struct dysymtab_command *)load_cmd;
            if (tmp->tocoff)
              tmp->tocoff += fixoffset;
            if (tmp->modtaboff)
              tmp->modtaboff += fixoffset;
            if (tmp->extrefsymoff)
              tmp->extrefsymoff += fixoffset;
            if (tmp->indirectsymoff)
              tmp->indirectsymoff += fixoffset;
            if (tmp->extreloff)
              tmp->extreloff += fixoffset;
            if (tmp->locreloff)
              tmp->locreloff += fixoffset;
            NSLog(@"[-] fix LC_DYSYMTAB done\n");
          } break;
              
          case LC_FUNCTION_STARTS:
          case LC_DATA_IN_CODE:
          case LC_CODE_SIGNATURE:
          case LC_SEGMENT_SPLIT_INFO:
          case LC_DYLIB_CODE_SIGN_DRS:
          case LC_LINKER_OPTIMIZATION_HINT:
          case LC_DYLD_EXPORTS_TRIE:
          case LC_DYLD_CHAINED_FIXUPS:
          {
            struct linkedit_data_command *tmp = (struct linkedit_data_command *)load_cmd;
              if(load_cmd->cmd==LC_DYLD_CHAINED_FIXUPS) chainedFixups=tmp;
            if (tmp->dataoff) tmp->dataoff += fixoffset;
            NSLog(@"[-] fix linkedit_data_command done\n");
          } break;
      }
    }
    
    if(min_section_offset < (sizeof(struct mach_header_64)+header->sizeofcmds)) {
        NSLog(@"macho header has no enough space!");
        return nil;
    }
    
    unsigned char* codepage = (unsigned char*)malloc(text_seg.vmsize);
    memset(codepage, 0xFF, text_seg.vmsize);
    [macho appendBytes:codepage length:text_seg.vmsize];
    free(codepage);
    
    unsigned char* datapage = (unsigned char*)malloc(data_seg.vmsize);
    memset(datapage, 0, data_seg.vmsize);
    //for(int i=0;i<data_seg.vmsize;i++) datapage[i]=i;
    [macho appendBytes:datapage length:data_seg.vmsize];
    free(datapage);
    
    [macho appendData:linkedit_data];
    
    if(chainedFixups)
   {
       NSLog(@"chainedFixups %p %x", chainedFixups->dataoff, chainedFixups->datasize);
       
       uint32_t offsetInLinkedit   = chainedFixups->dataoff - linkedit_seg->fileoff;
       uintptr_t linkeditStartAddr = (uint64_t)header + linkedit_seg->fileoff;
       
       const dyld_chained_fixups_header* chainsHeader = (dyld_chained_fixups_header*)(linkeditStartAddr + offsetInLinkedit);
       NSLog(@"chainsHeader offset=%x version=%d starts_offset=%x", offsetInLinkedit, chainsHeader->fixups_version, chainsHeader->starts_offset);
       
       const dyld_chained_starts_in_image* startsInfo = (dyld_chained_starts_in_image*)((uint8_t*)chainsHeader + chainsHeader->starts_offset);
       NSLog(@"startsInfo seg_count=%d", startsInfo->seg_count);
       
       int startsInfoNewSize = sizeof(dyld_chained_starts_in_image) + sizeof(startsInfo->seg_info_offset)*(startsInfo->seg_count - 1 + 2);
       
       NSMutableData* append = [NSMutableData dataWithLength:startsInfoNewSize];
       dyld_chained_starts_in_image* startsInfoNew = (dyld_chained_starts_in_image*)append.mutableBytes;
       bzero(startsInfoNew, startsInfoNewSize);
       *startsInfoNew = *startsInfo;
       startsInfoNew->seg_count += 2;
       
       for (uint32_t i=0; i < startsInfo->seg_count; ++i) {
           uint32_t segInfoOffset = startsInfo->seg_info_offset[i];
           NSLog(@"segInfoOffset[%d] %x", i, segInfoOffset);
           // 0 offset means this segment has no fixups
           if ( segInfoOffset == 0 )
               continue;
           
           startsInfoNew->seg_info_offset[i] = append.length;
           
           const dyld_chained_starts_in_segment* segInfo = (dyld_chained_starts_in_segment*)((uint8_t*)startsInfo + segInfoOffset);
           NSLog(@"segInfo[%d] page_count=%d segment_offset=%p max_valid_pointer=%p",i, segInfo->page_count, segInfo->segment_offset, segInfo->max_valid_pointer);
           
           int segInfoSize = sizeof(dyld_chained_starts_in_segment);
           if(segInfo->page_count) segInfoSize += sizeof(segInfo->page_start)*(segInfo->page_count - 1);
           
           [append appendBytes:segInfo length:segInfoSize];
       }
       NSLog(@"startsInfo new size=%x", append.length);
       [macho appendData:append];
       linkedit_seg->filesize += append.length;
       linkedit_seg->vmsize += (append.length+PAGE_SIZE-1)&(~(PAGE_SIZE-1));;
   }
    
    NSLog(@"macho file size=%x", macho.length);
    
    return macho;
}

bool hex2bytes(char* bytes, unsigned char* buffer)
{
    size_t len=strlen(bytes);
    for(int i=0; i<len; i++) {
        char _byte = bytes[i];
        if(_byte>='0' && _byte<='9')
            _byte -= '0';
        else if(_byte>='a' && _byte<='f')
            _byte -= 'a'-10;
        else if(_byte>='A' && _byte<='F')
            _byte -= 'A'-10;
        else
            return false;
        
        buffer[i/2] &= (i+1)%2 ? 0x0F : 0xF0;
        buffer[i/2] |= _byte << (((i+1)%2)*4);
        
    }
    return true;
}

uint64_t calc_patch_hash(uint64_t vaddr, char* patch)
{
    return [[[NSString stringWithUTF8String:patch] lowercaseString] hash] ^ vaddr;
}

NSString* StaticInlineHookPatch(char* machoPath, uint64_t vaddr, char* patch)
{
    static NSMutableDictionary* gStaticInlineHookMachO = [[NSMutableDictionary alloc] init];
    
    NSString* path = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:[NSString stringWithUTF8String:machoPath]];
        
    NSString* newPath = gStaticInlineHookMachO[path];
    
    NSMutableData* macho=nil;

    if(newPath) {
        macho = load_macho_data(newPath);
        if(!macho) return [NSString stringWithFormat:@"找不到文件(can't find file):\n%@", newPath];
    } else {
        macho = load_macho_data(path);
        if(!macho) return [NSString stringWithFormat:@"无法读取文件(can't read file):\n%@", path];
    }
    
    uint32_t cryptid = 0;
    struct mach_header_64* header = NULL;
    struct segment_command_64* text_seg = NULL;
    struct segment_command_64* data_seg = NULL;
    
    while(true) {
        
        header = (struct mach_header_64*)macho.mutableBytes;
        NSLog(@"macho %x %x", header->magic, macho.length);
        
        struct load_command* lc = (struct load_command*)((UInt64)header + sizeof(*header));
        for (int i = 0; i < header->ncmds; i++) {
            if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 * seg = (struct segment_command_64 *) lc;
                if(strcmp(seg->segname,"__HOOK_TEXT")==0)
                    text_seg = seg;
                if(strcmp(seg->segname,"__HOOK_DATA")==0)
                    data_seg = seg;
            }
            if(lc->cmd == LC_ENCRYPTION_INFO_64) {
                struct encryption_info_command_64* info = (struct encryption_info_command_64*)lc;
                if(cryptid==0) cryptid = info->cryptid;
            }
            lc = (struct load_command *) ((char *)lc + lc->cmdsize);
        }
        
        if(text_seg && data_seg) {
            NSLog(@"hook section found!");
            break;
        }
        
        macho = add_hook_section(macho);
        if(!macho) {
            return @"add_hook_section error!";
        }
    }
    
    if(cryptid != 0) {
        return @"该app程序未砸壳!\nthis app is not decrypted!";
    }
    
    if(!text_seg || !data_seg) {
        return @"无法解析machO文件!\ncan not parse machO file!";
    }
    
    uint64_t funcRVA = vaddr & ~(4-1);
    void *funcData = rva2data(header, funcRVA);
    //*(uint32_t*)funcData = 0x58000020; //ldr x0, #4 test
    
    if(!funcData) {
        return @"无效的地址!\nInvalid offset!";
    }
    
    
    void* patch_bytes=NULL; uint64_t patch_size=0;
    
    if(patch && patch[0]) {
        uint64_t patch_end = vaddr + (strlen(patch)+1)/2;
        uint64_t code_end = (patch_end+4-1) & ~(4-1);
        
        patch_size = code_end - funcRVA;
        
        NSLog(@"codepath %p %s : %p~%p~%p %x", vaddr, patch, funcRVA, patch_end, code_end, patch_size);
        
        NSMutableData* patchBytes = [[NSMutableData alloc] initWithLength:patch_size];
        patch_bytes = patchBytes.mutableBytes;
        
        memcpy(patch_bytes, funcData, patch_size);
        
        if(!hex2bytes(patch, (uint8_t*)patch_bytes+vaddr%4))
            return @"修补字节码格式有误!\nThe bytes to patch are incorrect!";

    } else if(vaddr % 4) {
        return @"地址未对齐!\nThe offset is not aligned!";
    }
    
    
    uint64_t targetRVA = va2rva(header, text_seg->vmaddr);
    void* targetData = rva2data(header, targetRVA);
    
    
    uint64_t InstrumentBridgeRVA = targetRVA;
    
    uint64_t dataRVA = va2rva(header, data_seg->vmaddr);
    void* dataData = rva2data(header, dataRVA);
    
    StaticInlineHookBlock* hookBlock = (StaticInlineHookBlock*)dataData;
    StaticInlineHookBlock* hookBlockRVA = NULL;
    for(int i=0; i<STATIC_HOOK_CODEPAGE_SIZE/sizeof(StaticInlineHookBlock); i++)
    {
        if(hookBlock[i].hook_vaddr==funcRVA)
        {
            if(patch && patch[0] && hookBlock[i].patch_hash!=calc_patch_hash(vaddr, patch))
                return @"修补字节发生变化, 请恢复为原始文件再试!\nThe bytes to patch have changed, please revert to original file and try again";
            
            if(newPath)
                return @"该地址已修补, 请将APP的Documents/static-inline-hook目录中的修补文件替换到ipa中的.app目录并重新签名安装!\nThe offset is already patched! Please replace the patched file in the APP's Documents/static-inline-hook directory to the .app directory in the ipa and re-sign and reinstall!";
            
            return @"该HOOK地址已修补!\nThe offset to hook is already patched!";
        }
        
        if( funcRVA>hookBlock[i].hook_vaddr &&
           ( funcRVA < (hookBlock[i].hook_vaddr+hookBlock[i].hook_size) || funcRVA < (hookBlock[i].hook_vaddr+hookBlock[i].patch_size) )
          ) {
            return @"该地址已被占用!\nThe offset is occupied!";
        }
        
        if(hookBlock[i].hook_vaddr==0)
        {
            hookBlock = &hookBlock[i];
            hookBlockRVA = (StaticInlineHookBlock*)(dataRVA + i*sizeof(StaticInlineHookBlock));
            
            if(i == 0)
            {
                int codesize = dobby_create_instrument_bridge(targetData);
                
                targetRVA += codesize;
                *(uint64_t*)&targetData += codesize;
            }
            else
            {
                StaticInlineHookBlock* lastBlock = hookBlock - 1;
                targetRVA = lastBlock->code_vaddr + lastBlock->code_size;
                targetData = rva2data(header, targetRVA);
            }
            
            printf("found empty StaticInlineHookBlock %d %p=>%p\n", i, targetRVA, targetData);
            
            break;
        }
    }
    
    if(!hookBlockRVA) {
        return @"超过最大可用数量!\nHOOK count full!";
    }
    
    printf("func: %p=>%p target: %p=>%p\n", funcRVA, funcData, targetRVA, targetData);
    
    if(!dobby_static_inline_hook(hookBlock, hookBlockRVA, funcRVA, funcData, targetRVA, targetData,
                                 InstrumentBridgeRVA, patch_bytes, patch_size))
    {
        return @"无法修补该地址!\ncan not patch the offset";
    }
    
    if(patch && patch[0]) {
        hookBlock->patch_size = patch_size;
        hookBlock->patch_hash = calc_patch_hash(vaddr, patch);
    }
    
    NSString* savePath = [NSString stringWithFormat:@"%@/Documents/static-inline-hook/%s", NSHomeDirectory(), machoPath];
    [NSFileManager.defaultManager createDirectoryAtPath:[NSString stringWithUTF8String:dirname((char*)savePath.UTF8String)] withIntermediateDirectories:YES attributes:nil error:nil];
    
    if(![macho writeToFile:savePath atomically:NO])
        return @"无法写入文件!\ncan not write to file!";
    
    int ldid_main(int argc, char *argv[]);
    const char* ldidargs[] = {"ldid", "-S", savePath.UTF8String};
    ldid_main(sizeof(ldidargs)/sizeof(ldidargs[0]), (char**)ldidargs);
    
    gStaticInlineHookMachO[path] = savePath;
    return @"未签名该地址, 修补文件将生成在APP的Documents/static-inline-hook目录中, 请将该目录中所有文件替换到ipa中的.app目录并重新签名安装!\nThe offset has not been patched, the patched file will be generated in the Documents/static-inline-hook directory of the APP, please replace all the files in this directory to the .app directory in the ipa and re-sign and reinstall!";
}


void* find_module_by_path(char* machoPath)
{
    NSString* path = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:[NSString stringWithUTF8String:machoPath]];
    
    for(int i=0; i< _dyld_image_count(); i++) {

        const char* fpath = _dyld_get_image_name(i);
        void* baseaddr = (void*)_dyld_get_image_header(i);
        void* slide = (void*)_dyld_get_image_vmaddr_slide(i); //no use
        
        if([path isEqualToString:[NSString stringWithUTF8String:fpath]])
            return baseaddr;
    }
    
    return NULL;
}

StaticInlineHookBlock* find_hook_block(void* base, uint64_t vaddr)
{
    struct segment_command_64* text_seg = NULL;
    struct segment_command_64* data_seg = NULL;
    
    struct mach_header_64* header = (struct mach_header_64*)base;
    
    struct load_command* lc = (struct load_command*)((UInt64)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 * seg = (struct segment_command_64 *) lc;
            if(strcmp(seg->segname,"__HOOK_TEXT")==0)
                text_seg = seg;
            if(strcmp(seg->segname,"__HOOK_DATA")==0)
                data_seg = seg;
        }
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    if(!text_seg || !data_seg) {
        NSLog(@"cannot parse hook info!");
        return NULL;
    }
    
    StaticInlineHookBlock* hookBlock = (StaticInlineHookBlock*)((uint64_t)header + va2rva(header, data_seg->vmaddr));
    for(int i=0; i<STATIC_HOOK_CODEPAGE_SIZE/sizeof(StaticInlineHookBlock); i++)
    {
        if(hookBlock[i].hook_vaddr == (uint64_t)vaddr)
        {
            NSLog(@"found hook block %d for %llX", i, vaddr);
            return &hookBlock[i];
        }
    }
    
    return NULL;
}

void* StaticInlineHookFunction(char* machoPath, uint64_t vaddr, void* replace)
{
    void* base = find_module_by_path(machoPath);
    if(!base) {
        NSLog(@"cannot find module!");
        return NULL;
    }
    
    StaticInlineHookBlock* hookBlock = find_hook_block(base, vaddr);
    if(!hookBlock) {
        NSLog(@"cannot find hook block!");
        return NULL;
    }
    
    hookBlock->target_replace = replace;
    return (void*)((uint64_t)base + hookBlock->original_vaddr);
}

BOOL StaticInlineHookInstrument(char* machoPath, uint64_t vaddr, void(*callback)(RegisterContext*))
{
    void* base = find_module_by_path(machoPath);
    if(!base) {
        NSLog(@"cannot find module!");
        return NO;
    }
    
    StaticInlineHookBlock* hookBlock = find_hook_block(base, vaddr);
    if(!hookBlock) {
        NSLog(@"cannot find hook block!");
        return NO;
    }
    
    hookBlock->instrument_handler = (void*)callback;
    hookBlock->target_replace = (void*)((uint64_t)base + hookBlock->instrument_vaddr);
    
    return YES;
}

BOOL ActiveCodePatch(char* machoPath, uint64_t vaddr, char* patch)
{
    void* base = find_module_by_path(machoPath);
    if(!base) {
        NSLog(@"cannot find module!");
        return NO;
    }
    
    StaticInlineHookBlock* hookBlock = find_hook_block(base, vaddr&~3);
    if(!hookBlock) {
        NSLog(@"cannot find hook block!");
        return NO;
    }
    
    if(hookBlock->patch_hash != calc_patch_hash(vaddr, patch)) {
        NSLog(@"code patch bytes changed!");
        return NO;
    }
    
    hookBlock->target_replace = (void*)((uint64_t)base + hookBlock->patched_vaddr);
    
    return YES;
}

BOOL DeactiveCodePatch(char* machoPath, uint64_t vaddr, char* patch)
{
    void* base = find_module_by_path(machoPath);
    if(!base) {
        NSLog(@"cannot find module!");
        return NO;
    }
    
    StaticInlineHookBlock* hookBlock = find_hook_block(base, vaddr&~3);
    if(!hookBlock) {
        NSLog(@"cannot find hook block!");
        return NO;
    }
    
    if(hookBlock->patch_hash != calc_patch_hash(vaddr, patch)) {
        NSLog(@"code patch bytes changed!");
        return NO;
    }
    
    hookBlock->target_replace = NULL;
    
    return YES;
}
