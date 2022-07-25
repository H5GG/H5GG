//
//  makeDYLIB.h
//  h5gg
//
//  Created by admin on 24/4/2022.
//

#ifndef makeDYLIB_h
#define makeDYLIB_h

#include "incbin.h"
#include <sys/stat.h>

INCBIN(H5ICON_STUB_FILE, "H5ICON_STUB_FILE");
INCBIN(H5MENU_STUB_FILE, "H5MENU_STUB_FILE");

NSString* makeDYLIB(NSString* iconfile, NSString* htmlurl)
{
    struct dl_info di={0};
    dladdr((void*)makeDYLIB, &di);
    
    NSString* libpath = [NSString stringWithUTF8String:di.dli_fname];
    
    NSMutableData* dylib = [NSMutableData dataWithContentsOfFile:libpath];
    if(!dylib)
        return [NSString stringWithFormat:Localized(@"制作失败\n\n无法读取文件:\n%@"), libpath];
    
    NSData* icon = [NSData dataWithContentsOfFile:iconfile];
    if(!dylib)
        return [NSString stringWithFormat:Localized(@"制作失败\n\n无法读取文件:\n%@"), iconfile];
    
    NSData* html = [NSData dataWithContentsOfFile:htmlurl];
    if(!dylib)
        return [NSString stringWithFormat:Localized(@"制作失败\n\n无法读取文件:\n%@"), htmlurl];
        
    
    if(icon.length>=gH5ICON_STUB_FILESize)
        return Localized(@"制作失败\n\n图标文件超过512KB");
    
    if(html.length>=gH5MENU_STUB_FILESize)
        return Localized(@"制作失败\n\nH5文件超过2MB");
    
    NSData *pattern = [[NSString stringWithUTF8String:(char*)gH5ICON_STUB_FILEData] dataUsingEncoding:NSUTF8StringEncoding];
    if(!pattern)
        return Localized(@"制作失败\n\n当前已经是定制版本, 请使用原版H5GG制作插件");
        
    NSRange range = [dylib rangeOfData:pattern options:0 range:NSMakeRange(0, dylib.length)];
    if(range.location == NSNotFound)
        return Localized(@"制作失败\n\n当前已经是定制版本, 请使用原版H5GG制作插件");
    
    [dylib replaceBytesInRange:NSMakeRange(range.location, icon.length) withBytes:icon.bytes];
    
    NSData *pattern2 = [[NSString stringWithUTF8String:(char*)gH5MENU_STUB_FILEData] dataUsingEncoding:NSUTF8StringEncoding];
    if(!pattern2)
        return Localized(@"制作失败\n\n当前已经是定制版本, 请使用原版H5GG制作插件");
    
    NSRange range2 = [dylib rangeOfData:pattern2 options:0 range:NSMakeRange(0, dylib.length)];
    if(range2.location == NSNotFound)
        return Localized(@"制作失败\n\n当前已经是定制版本, 请使用原版H5GG制作插件");
    
    [dylib replaceBytesInRange:NSMakeRange(range2.location, html.length) withBytes:html.bytes];
    
    NSString* savePath = [NSString stringWithFormat:@"%@/Documents/H5GG.dylib", NSHomeDirectory()];
    
    if(g_systemapp_runmode || g_standalone_runmode)
        savePath = @"/var/tmp/H5GG.dylib"; /* var/mobile/Documents 可能为root所有而写入失败 */
    
    NSError* error=nil;
    if(![dylib writeToFile:savePath options:0 error:&error])
        return [NSString stringWithFormat:Localized(@"制作失败\n\n无法写入文件到%@\n\n%@"), savePath, error];
    
    int ldid_main(int argc, char *argv[]);
    const char* ldidargs[] = {"ldid", "-S", savePath.UTF8String};
    ldid_main(sizeof(ldidargs)/sizeof(ldidargs[0]), (char**)ldidargs);
    
    return [NSString stringWithFormat:
            Localized(@"制作成功!\n\n专属H5GG.dylib已生成在当前App的Documents数据目录:\n%@"), savePath];
}


#endif /* makeDYLIB_h */
