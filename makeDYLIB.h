//
//  makeDYLIB.h
//  h5gg
//
//  Created by admin on 24/4/2022.
//

#ifndef makeDYLIB_h
#define makeDYLIB_h

#include "incbin.h"
#include <mach-o/fat.h>
#include <mach-o/loader.h>


INCBIN(H5ICON_STUB_FILE, "H5ICON_STUB_FILE");
INCBIN(H5MENU_STUB_FILE, "H5MENU_STUB_FILE");

NSString* makeDYLIB(NSString* iconfile, NSString* htmlurl)
{
    struct dl_info di={0};
    dladdr((void*)makeDYLIB, &di);
    
    NSMutableData* dylib = [NSMutableData dataWithContentsOfFile:[NSString stringWithUTF8String:di.dli_fname]];
    NSData* icon = [NSData dataWithContentsOfFile:iconfile];
    NSData* html;
    
    if([[htmlurl lowercaseString] hasPrefix:@"http"])
        html = [htmlurl dataUsingEncoding:NSUTF8StringEncoding];
    else
        html = [NSData dataWithContentsOfFile:htmlurl];
    
    if(!dylib || !icon || !html)
        return @"制作失败\n\n无法读取数据!";
    
    if(icon.length>=gH5ICON_STUB_FILESize)
        return @"制作失败\n\n图标文件超过512KB";
    
    if(html.length>=gH5MENU_STUB_FILESize)
        return @"制作失败\n\nH5文件超过2MB";
    
    NSData *pattern = [[NSString stringWithUTF8String:(char*)gH5ICON_STUB_FILEData] dataUsingEncoding:NSUTF8StringEncoding];
    NSRange range = [dylib rangeOfData:pattern options:0 range:NSMakeRange(0, dylib.length)];
    if(range.location == NSNotFound)
        return @"制作失败\n\n当前已经是定制版本";
    
    [dylib replaceBytesInRange:NSMakeRange(range.location, icon.length) withBytes:icon.bytes];
    
    NSData *pattern2 = [[NSString stringWithUTF8String:(char*)gH5MENU_STUB_FILEData] dataUsingEncoding:NSUTF8StringEncoding];
    NSRange range2 = [dylib rangeOfData:pattern2 options:0 range:NSMakeRange(0, dylib.length)];
    if(range2.location == NSNotFound)
        return @"制作失败\n\n当前已经是定制版本";
    
    [dylib replaceBytesInRange:NSMakeRange(range2.location, html.length) withBytes:html.bytes];
    
    
//    void (^stripsign)(struct mach_header_64*) = ^(struct mach_header_64* header) {
//        struct load_command* lc = (struct load_command*)((UInt64)header + sizeof(*header));
//        for (uint32_t i = 0; i < header->ncmds; i++) {
//            NSLog(@"makeDYLIB cmd=%d", lc->cmd);
//            if (lc->cmd == LC_CODE_SIGNATURE) {
//                lc->cmd = LC_NOTE;
//            }
//            lc = (struct load_command *) ((char *)lc + lc->cmdsize);
//        }
//    };
//
//    UInt32 magic = *(uint32_t*)dylib.mutableBytes;
//    if(magic==FAT_CIGAM)
//    {
//        struct fat_header* fathdr = (struct fat_header*)dylib.mutableBytes;
//        struct fat_arch_64* archdr = (struct fat_arch_64*)((UInt64)fathdr + sizeof(*fathdr));
//        NSLog(@"makeDYLIB nfat_arch=%d", NXSwapLong(fathdr->nfat_arch));
//        for(int n=0; n<NXSwapLong(fathdr->nfat_arch);n++)
//        {
//            stripsign((struct mach_header_64*)((UInt64)dylib.mutableBytes + NXSwapLong(archdr->offset)));
//            archdr = (struct fat_arch_64*)((UInt64)archdr +  + sizeof(*archdr));
//        }
//    } else if(magic==MH_MAGIC_64) {
//        stripsign((struct mach_header_64*)dylib.mutableBytes);
//    } else {
//        return [NSString stringWithFormat:@"制作失败\n\n文件格式无法识别"];
//    }
    
    NSString* filePath = [NSString stringWithFormat:@"%@/Documents/H5GG.dylib", NSHomeDirectory()];
    
    if(![dylib writeToFile:filePath atomically:NO])
        return [NSString stringWithFormat:@"制作失败\n\n无法写入文件到%@", NSHomeDirectory()];
    
    int ldid_main(int argc, char *argv[]);
    const char* ldidargs[] = {"ldid", "-S", filePath.UTF8String};
    ldid_main(sizeof(ldidargs)/sizeof(ldidargs[0]), (char**)ldidargs);
    
    return [NSString stringWithFormat:@"制作成功!\n\n专属H5GG.dylib已生成在当前App的Documents数据目录:\n\n%@", filePath];
}


#endif /* makeDYLIB_h */
