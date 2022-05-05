//
//  makeDYLIB.h
//  h5gg
//
//  Created by admin on 24/4/2022.
//

#ifndef makeDYLIB_h
#define makeDYLIB_h

#include "incbin.h"

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
    
    if(![dylib writeToFile:[NSString stringWithFormat:@"%@/Documents/H5GG.dylib", NSHomeDirectory()] atomically:NO])
        return [NSString stringWithFormat:@"制作失败\n\n无法写入文件到", NSHomeDirectory()];
    
    return [NSString stringWithFormat:@"制作成功!\n\n专属H5GG.dylib已生成在当前App的Documents数据目录:\n\n%@/Documents/H5GG.dylib", NSHomeDirectory()];
}


#endif /* makeDYLIB_h */
