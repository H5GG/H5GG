//
//  h5gg.h
//  h5gg
//
//  Created by admin on 11/3/2022.
//

/** 强烈提醒: 请不要修改此JS接口, 以保持js脚本的兼容性 */
/** Strong reminder: Please do not modify this JS interface to maintain the compatibility of js scripts */

#ifndef h5gg_h
#define h5gg_h

extern FloatMenu* floatH5;

//导入JavaScriptCore框架头文件
#include <libgen.h>
#include <sys/stat.h>
#include <sys/mount.h>
#import <JavaScriptCore/JavaScriptCore.h>
//导入JJ内存搜索引擎头文件(专为H5GG定制)
#include "MemScan.h"
#include "TopShow.h"
#include "crossproc.h"

@protocol h5ggJSExport <JSExport>

JSExportAs(searchNumber, -(void)searchNumber:(NSString*)value param2:(NSString*)type param3:(NSString*)memoryFrom param4:(NSString*)memoryTo);

JSExportAs(searchNearby, -(void)searchNearby:(NSString*)value param2:(NSString*)type param3:(NSString*)range);

JSExportAs(getValue, -(NSString*)getValue:(NSString*)address param2:(NSString*)type);
JSExportAs(setValue, -(BOOL)setValue:(NSString*)address param2:(NSString*)value param3:(NSString*)type);

JSExportAs(editAll, -(int)editAll:(NSString*)value param3:(NSString*)type);

JSExportAs(getResults, -(NSArray*)getResults:(int)maxCount param1:(int)skipCount);

-(long)getResultsCount;
-(void)clearResults;

-(void)setFloatTolerance:(NSString*)value;

-(NSArray*)getLocalScripts;
-(void)pickScriptFile:(JSValue*)callback;

-(NSArray*)getRangesList:(JSValue*)filter;

-(JSValue*)getProcList:(JSValue*)filter;
-(BOOL)setTargetProc:(pid_t)pid;

JSExportAs(loadPlugin, -(NSObject*)loadPlugin:(NSString*)className path:(NSString*)dylib);

-(void)make;

@end

@interface h5ggEngine : NSObject <h5ggJSExport>
@property JJMemoryEngine* engine;
@property NSString* lastSearchType;
@property BOOL firstSearchDone;
@property pid_t targetpid;
@property task_port_t targetport;
@end

@implementation h5ggEngine

-(instancetype)init {
    if (self = [super init]) {
        self.firstSearchDone = FALSE;
        
        if(g_standalone_runmode) {
            self.targetpid=0;
            self.targetport=MACH_PORT_NULL;
        } else {
            self.targetpid = getpid();
            self.targetport = mach_task_self();
        }
        
        self.engine = new JJMemoryEngine(self.targetport);
    }
    return self;
}

-(JSValue*)getProcList:(JSValue*)filter {
    
    NSArray* allproc = getRunningProcess();
    if(!allproc)
        return [JSValue valueWithNullInContext:[JSContext currentContext]];
    
    NSMutableArray* newarr = [[NSMutableArray alloc] init];
    
    for(NSDictionary* proc in allproc)
    {
        char path[PATH_MAX]={0};
        
        if(!proc_pidpath([[proc valueForKey:@"pid"] intValue], path, sizeof(path)))
            continue;
        
        if(strstr(path, "/private/var/")!=path && strstr(path, "/var/")!=path)
            continue;

//        if(![[NSString stringWithUTF8String:dirname(path)] hasSuffix:@".app"])
//            continue;
        
        if(strstr(path, "/Application/")==NULL)
            continue;
        
        NSLog(@"allproc=%@, %@, %s", [proc valueForKey:@"pid"], [proc valueForKey:@"name"], path);
        
        if([filter isUndefined] || [[filter toString] isEqualToString:[proc valueForKey:@"name"]])
            [newarr addObject:proc];
    }
    return [JSValue valueWithObject:newarr inContext:[JSContext currentContext]];
}

-(BOOL)setTargetProc:(pid_t)pid {
    
    if(self.targetport!=MACH_PORT_NULL && self.targetport!=mach_task_self())
        mach_port_deallocate(mach_task_self(), self.targetport);
    
    self.targetpid = 0;
    self.targetport = MACH_PORT_NULL;
    [self clearResults];
    
    task_port_t _target_task=0;
    kern_return_t ret = task_for_pid(mach_task_self(), pid, &_target_task);
    NSLog(@"task_for_pid=%d %p %d %s!", pid, ret, _target_task, mach_error_string(ret));
    if(ret==KERN_SUCCESS) {
        self.targetpid = pid;
        self.targetport = _target_task;
        return YES;
    }
    
    return NO;
}

-(void)setFloatTolerance:(NSString*)value
{
    char* pvaluerr=NULL;
    float d = strtof([value UTF8String], &pvaluerr);
    
    if(value.length==0 || (pvaluerr && pvaluerr[0]) || d<0) {
        [floatH5 alert:@"浮点误差格式错误"];
        return;
    }
    NSLog(@"SetFloatTolerance=%f", d);
    self.engine->SetFloatTolerance(d);
}

-(void)clearResults {
    self.firstSearchDone = FALSE;
    if(self.engine) delete self.engine;
    self.engine = new JJMemoryEngine(self.targetport);
}

-(long)getResultsCount {
    return self.engine->getResultsCount();
}

-(NSArray*)getResults:(int)maxCount param1:(int)skipCount {
    NSMutableArray* resultArr = [[NSMutableArray alloc] init];
    
    map<void*,int8_t> results;

    try {

        results = self.engine->getResultsAndTypes(maxCount, skipCount);

    } catch(std::bad_alloc) {
        [floatH5 alert:@"错误:内存不足!"];
    }
    
    for(map<void*,int8_t>::iterator it = results.begin(); it != results.end(); ++it) {
        void* address = it->first;
        int8_t jjtype = it->second;
        
        if(jjtype==0) jjtype = [self ggtype2jjtype:self.lastSearchType];
        
        NSString* ggtype = [self jjtype2ggtype:jjtype];
        
        UInt8 valuebuf[8]={0};
        self.engine->JJReadMemory(valuebuf, (UInt64)address, jjtype);
        
        [resultArr addObject:@{
            @"address": [NSString stringWithFormat:@"0x%llX", address ],
            @"value": [self formartValue:valuebuf byType:ggtype],
            @"type" : ggtype,
        }];
    }
    
    return resultArr;
}


-(int)ggtype2jjtype:(NSString*)type
{
    if([type isEqualToString:@"I8"])
        return JJ_Search_Type_SByte;
    else if([type isEqualToString:@"U8"])
        return JJ_Search_Type_UByte;
    else if([type isEqualToString:@"I16"])
        return JJ_Search_Type_SShort;
    else if([type isEqualToString:@"U16"])
        return JJ_Search_Type_UShort;
    else if([type isEqualToString:@"I32"])
        return JJ_Search_Type_SInt;
    else if([type isEqualToString:@"U32"])
        return JJ_Search_Type_UInt;
    else if([type isEqualToString:@"I64"])
        return JJ_Search_Type_SLong;
    else if([type isEqualToString:@"U64"])
        return JJ_Search_Type_ULong;
    else if([type isEqualToString:@"F32"])
        return JJ_Search_Type_Float;
    else if([type isEqualToString:@"F64"])
        return JJ_Search_Type_Double;
    
    return 0;
}

-(NSString*)jjtype2ggtype:(int)jjtype
{
    switch(jjtype) {
        case JJ_Search_Type_SByte:
            return @"I8";
        case JJ_Search_Type_UByte:
            return @"U8";
        case JJ_Search_Type_SShort:
            return @"I16";
        case JJ_Search_Type_UShort:
            return @"U16";
        case JJ_Search_Type_SInt:
            return @"I32";
        case JJ_Search_Type_UInt:
            return @"U32";
        case JJ_Search_Type_SLong:
            return @"I64";
        case JJ_Search_Type_ULong:
            return @"U64";
        case JJ_Search_Type_Float:
            return @"F32";
        case JJ_Search_Type_Double:
            return @"F64";
    }
    
    return @"";
}

-(NSString*)formartValue:(void*)value byType:(NSString*)type
{
    if([type isEqualToString:@"I8"])
        return [NSString stringWithFormat:@"%d", (int)*(int8_t*)value];
    else if([type isEqualToString:@"U8"])
       return [NSString stringWithFormat:@"%u", (unsigned int)*(UInt8*)value];
    else if([type isEqualToString:@"I16"])
        return [NSString stringWithFormat:@"%d", (int)*(int16_t*)value];
    else if([type isEqualToString:@"U16"])
        return [NSString stringWithFormat:@"%u", (unsigned int)*(UInt16*)value];
    else if([type isEqualToString:@"I32"])
       return [NSString stringWithFormat:@"%d", *(int32_t*)value];
    else if([type isEqualToString:@"U32"])
       return [NSString stringWithFormat:@"%u", *(UInt32*)value];
    else if([type isEqualToString:@"I64"])
        return [NSString stringWithFormat:@"%lld", *(int64_t*)value];
    else if([type isEqualToString:@"U64"])
        return [NSString stringWithFormat:@"%llu", *(UInt64*)value];
    
    else if([type isEqualToString:@"F32"]) {
        NSString* fmt = *(uint32_t*)value&&fabs(*(float*)value) < 1.0 ? @"%g" : @"%f";
       return [NSString stringWithFormat:fmt, *(float*)value];
    } else if([type isEqualToString:@"F64"]) {
        NSString* fmt = *(uint64_t*)value&&fabs(*(double*)value) < 1.0 ? @"%g" : @"%f";
        return [NSString stringWithFormat:fmt, *(double*)value];
    } else {
        [floatH5 alert:@"不支持的数值类型"];
        return nil;
    }
}

-(int)parseValue:(void*)valuebuf from:(NSString*)value byType:(NSString*)type
{
    char* pvaluerr=NULL;
    int JJType = 0;
    
    if([type isEqualToString:@"I8"]) {
       *(int8_t*)valuebuf = (int8_t)strtol([value UTF8String], &pvaluerr, 10);
        JJType = JJ_Search_Type_SByte;
    } else if([type isEqualToString:@"U8"]) {
       *(UInt8*)valuebuf = (UInt8)strtoul([value UTF8String], &pvaluerr, 10);
        JJType = JJ_Search_Type_UByte;
    } else if([type isEqualToString:@"I16"]) {
       *(int16_t*)valuebuf = (int16_t)strtol([value UTF8String], &pvaluerr, 10);
        JJType = JJ_Search_Type_SShort;
    } else if([type isEqualToString:@"U16"]) {
       *(UInt16*)valuebuf = (UInt16)strtoul([value UTF8String], &pvaluerr, 10);
        JJType = JJ_Search_Type_UShort;
    } else if([type isEqualToString:@"I32"]) {
       *(int32_t*)valuebuf = (int32_t)strtol([value UTF8String], &pvaluerr, 10);
        JJType = JJ_Search_Type_SInt;
    } else if([type isEqualToString:@"U32"]) {
       *(UInt32*)valuebuf = (UInt32)strtoul([value UTF8String], &pvaluerr, 10);
        JJType = JJ_Search_Type_UInt;
    } else if([type isEqualToString:@"I64"]) {
       *(int64_t*)valuebuf = strtol([value UTF8String], &pvaluerr, 10);
        JJType = JJ_Search_Type_SLong;
    } else if([type isEqualToString:@"U64"]) {
       *(UInt64*)valuebuf = strtoul([value UTF8String], &pvaluerr, 10);
        JJType = JJ_Search_Type_ULong;
    } else if([type isEqualToString:@"F32"]) {
       *(float*)valuebuf = strtof([value UTF8String], &pvaluerr);
        JJType = JJ_Search_Type_Float;
    } else if([type isEqualToString:@"F64"]) {
       *(double*)valuebuf = strtod([value UTF8String], &pvaluerr);
        JJType = JJ_Search_Type_Double;
    } else {
        [floatH5 alert:@"不支持的数值类型"];
        return 0;
    }
    
    if(pvaluerr && pvaluerr[0]) {
        [floatH5 alert:@"数值格式错误或与类型不匹配"];
        return 0;
    }
    
    return JJType;
}

-(int)parseSearchValue:(void*)valuebuf from:(NSString*)value byType:(NSString*)type
{
    NSString *pattern = @"^([^~]+)~([^~]+)$";
    NSRegularExpression *regex = [[NSRegularExpression alloc] initWithPattern:pattern options:0 error:nil];
    NSTextCheckingResult *result = [regex firstMatchInString:value options:0 range:NSMakeRange(0, value.length)];
    NSLog(@"firstMatchInString rangeCount=%d %@", [result numberOfRanges], result);
    
    if([result numberOfRanges] != 3) {
        int jjtype = [self parseValue:valuebuf from:value byType:type];
        if(!jjtype) return 0;
        int len = JJ_Search_Type_Len[jjtype];
        void* valuebuf2 = (void*)((uint64_t)valuebuf + len);
        memcpy(valuebuf2, valuebuf, len);
        return jjtype;
    }
    
    
    NSString* value1 = [value substringWithRange:[result rangeAtIndex:1]];
    NSString* value2 = [value substringWithRange:[result rangeAtIndex:2]];
    
    NSLog(@"value1=%@ value2=%@", value1, value2);
    
    int jjtype = [self ggtype2jjtype:type];
    if(!jjtype) return 0;
    
    int len = JJ_Search_Type_Len[jjtype];
    
    if(![self parseValue:valuebuf from:value1 byType:type])
        return 0;
    
    void* valuebuf2 = (void*)((uint64_t)valuebuf + len);
    
    if(![self parseValue:valuebuf2 from:value2 byType:type])
        return 0;
    
    return jjtype;
}

-(void)searchNumber:(NSString*)value param2:(NSString*)type param3:(NSString*)memoryFrom    param4:(NSString*)memoryTo
{
    NSLog(@"searchNumber=%@:%@ [%@:%@]", type, value, memoryFrom, memoryTo);
    
    if(!([value length] && [type length] && [memoryFrom length] && [memoryTo length])) {
        [floatH5 alert:@"数值搜索:参数有误"];
        return;
    }
    
    UInt8 valuebuf[8*2];
    
    int jjtype = [self parseSearchValue:valuebuf from:value byType:type];
    if(!jjtype) {
        //[floatH5 alert:@"数值搜索:类型格式错误!"];
        return;
    }
    
    if(![memoryFrom hasPrefix:@"0x"] || ![memoryTo hasPrefix:@"0x"]) {
        [floatH5 alert:@"搜索范围需以0x开头十六进制数"];
        return;
    }
    
    char* pvaluerr=NULL;
    AddrRange range = {
        strtoul([memoryFrom UTF8String], &pvaluerr, 16),
        strtoul([memoryTo UTF8String], &pvaluerr, 16)
    };
    
    if((pvaluerr && pvaluerr[0]) || !range.end) {
        [floatH5 alert:@"内存搜索范围格式错误"];
        return;
    }
    
    if(self.firstSearchDone && self.engine->getResultsCount()==0) {
        [floatH5 alert:@"改善搜索失败: 当前列表为空, 请清除后再重新开始搜索"];
        return;
    }
    
    NSLog(@"searchNumber=%d [%p:%p] %p-%s", jjtype, range.start, range.end, pvaluerr, pvaluerr);
    
    try {
        
        self.engine->JJScanMemory(range, valuebuf, jjtype);
        
    } catch(std::bad_alloc) {
        [floatH5 alert:@"错误:内存不足!"];
    }
    
    self.firstSearchDone = TRUE;
    self.lastSearchType = type;
}

-(void)searchNearby:(NSString*)value param2:(NSString*)type param3:(NSString*)range
{
    NSLog(@"searchNearby=%@:%@ [%@]", type, value, range);
    
    if(!([value length] && [type length] && [range length])) {
        [floatH5 alert:@"邻近搜索:参数有误"];
        return;
    }
    
    if(![range hasPrefix:@"0x"]) {
        [floatH5 alert:@"邻近范围需以0x开头十六进制数"];
        return;
    }
    
    UInt8 valuebuf[8*2];
    
    int jjtype = [self parseSearchValue:valuebuf from:value byType:type];
    if(!jjtype) {
        //[floatH5 alert:@"邻近搜索:类型格式错误!"];
        return;
    }
    
    char* pvaluerr=NULL;
    size_t searchRange = strtoul([range UTF8String], &pvaluerr, 16);
    
    if((pvaluerr && pvaluerr[0]) || !searchRange) {
        [floatH5 alert:@"邻近范围格式错误"];
        return;
    }
    
    if(searchRange<2 || searchRange>4096) {
        [floatH5 alert:@"邻近范围只能在2~4096之间"];
        return;
    }
    
    if(self.engine->getResultsCount()==0) {
        [floatH5 alert:@"临近搜索错误: 当前列表为空, 请清除后再重新开始搜索"];
        return;
    }
    
    try {
        
        self.engine->JJNearBySearch(searchRange, valuebuf, jjtype);
        
    } catch(std::bad_alloc) {
        [floatH5 alert:@"错误:内存不足!"];
    }

    self.lastSearchType = type;
}

-(NSString*)getValue:(NSString*)address param2:(NSString*)type
{
    NSLog(@"getValue %@ %@", address, type);
    
    
    int jjtype = [self ggtype2jjtype:type];
    if(!jjtype) {
        //[floatH5 alert:@"读取失败:类型格式错误!"];
        return @"";
    }
    
    char* pvaluerr=NULL;
    UInt64 addr = strtoul([address UTF8String], &pvaluerr, [address hasPrefix:@"0x"] ? 16 : 10);
    
    if((pvaluerr && pvaluerr[0]) || !addr) {
        [floatH5 alert:@"读取失败:地址格式有误!"];
        return @"";
    }
    
    UInt8 valuebuf[8];
    if(!self.engine->JJReadMemory(valuebuf, addr, jjtype)) {
        //[floatH5 alert:@"读取失败:可能地址已失效"];
        return @"";
    }
    
    return [self formartValue:valuebuf byType:type];
}

-(BOOL)setValue:(NSString*)address param2:(NSString*)value param3:(NSString*)type
{
    UInt8 valuebuf[8];
    
    int jjtype = [self parseValue:valuebuf from:value byType:type];
    if(!jjtype) {
        //[floatH5 alert:@"修改失败:类型格式错误!"];
        return FALSE;
    }
    
    char* pvaluerr=NULL;
    UInt64 addr = strtoul([address UTF8String], &pvaluerr, [address hasPrefix:@"0x"] ? 16 : 10);
    
    if((pvaluerr && pvaluerr[0]) || !addr) {
        [floatH5 alert:@"修改失败:地址格式有误!"];
        return FALSE;
    }
    
    return self.engine->JJWriteMemory((void*)addr, valuebuf, jjtype);
}

-(int)editAll:(NSString*)value param3:(NSString*)type
{
    UInt8 valuebuf[8];

    int jjtype = [self parseValue:valuebuf from:value byType:type];
    if(!jjtype) {
        //[floatH5 alert:@"修改全部: 类型格式错误!"];
        return 0;
    }
    
    if(self.engine->getResultsCount()==0) {
        [floatH5 alert:@"修改全部: 结果列表为空!"];
        return 0;
    }
    
    return self.engine->JJWriteAll(valuebuf, jjtype);
}

-(NSArray*)getRangesList:(JSValue*)filter
{
    if(self.targetpid!=getpid())
        return getRangesList2(self.targetport, [filter isUndefined] ? nil:[filter toString]);
    
    NSMutableArray* results = [[NSMutableArray alloc] init];
        
    for(int i=0; i< _dyld_image_count(); i++) {

        const char* name = _dyld_get_image_name(i);
        void* baseaddr = (void*)_dyld_get_image_header(i);
        void* slide = (void*)_dyld_get_image_vmaddr_slide(i); //no use
        
        NSLog(@"getRangesList[%d] %p %p %s", i, baseaddr, slide, name);
        
        if([filter isUndefined]
            || (i==0 && [[filter toString] isEqual:@"0"])
            || [[filter toString] isEqual:[NSString stringWithUTF8String:basename((char*)name) ]]
        ){
            [results addObject:@{
                @"name" : [NSString stringWithUTF8String:name],
                @"start" : [NSString stringWithFormat:@"0x%llX", baseaddr],
                @"end" : [NSString stringWithFormat:@"0x%llX",
                          (uint64_t)baseaddr+getMachoVMSize(self.targetport,(uint64_t)baseaddr) ],
                //@"type" : @"rwxp",
            }];
            
            if(i==0 && [[filter toString] isEqual:@"0"]) break;
        }
    }
    
    return results;
}



-(NSArray*)getLocalScripts
{
    NSMutableArray* results = [[NSMutableArray alloc] init];
    
    NSString *docDir = [NSString stringWithFormat:@"%@/Documents", NSHomeDirectory()];

    NSArray* files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:docDir error:nil];

    for(NSString* file in files) {
        if([[file lowercaseString] hasSuffix:@".js"] || [[file lowercaseString] hasSuffix:@".html"])
            [results addObject:@{
                @"name": file,
                @"path": [NSString pathWithComponents:@[docDir, file]],
            }];
    }

    NSLog(@"scripts in Documents=%@ %@", docDir, files);
    
    NSString* appDir = [[NSBundle mainBundle] bundlePath];
     files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:appDir error:nil];
    
    for(NSString* file in files) {
        if([[file lowercaseString] hasSuffix:@".js"] || [[file lowercaseString] hasSuffix:@".html"])
            [results addObject:@{
                @"name": file,
                @"path": [NSString pathWithComponents:@[appDir, file]],
            }];
    }
    
    NSLog(@"scripts in .app =%@ %@", appDir, files);
    
    return results;
}

-(void)threadcall:(void(^)())block {
    NSLog(@"threadcall=%p", block);
    block();
}

-(void)pickScriptFile:(JSValue*)callback {
    NSLog(@"pickScriptFile=%@", callback);
    
    NSThread *webThread = [NSThread currentThread];
    
    [TopShow filePicker:@[@"public.executable", @"public.html"] callback:^(NSString* path){
        
        [self performSelector:@selector(threadcall:) onThread:webThread withObject:^{
            
            [callback callWithArguments:@[path]];
            
        } waitUntilDone:NO];
        
    }];
}

#define CS_VALID                    0x00000001  /* dynamically valid */
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */

#define CS_OPS_STATUS           0       /* csops  operations *//* return status */
extern "C" int csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);

-(void)make {

//    struct statfs buf;
//    statfs("/", &buf);
//    NSLog(@"%s", buf.f_mntfromname);
//    const char* prefix = "com.apple.os.update-";
//    if(strstr(buf.f_mntfromname, prefix))
    
    uint32_t g_csops_flags = 0;
    csops(getpid(), 0, &g_csops_flags, 0);
    NSLog(@"csops=%x", g_csops_flags);
    uint32_t normalstate = CS_VALID|CS_HARD|CS_KILL;
    if((g_csops_flags&normalstate) == normalstate)
    {
        if(![floatH5 confirm:@"你的设备未越狱! 你可以将:\n悬浮按钮图标文件 H5Icon.png\n悬浮菜单H5文件  H5Menu.html\n打包进ipa中的.app目录中即可自动加载!\n\n是否需要继续制作dylib ?"])
            return;
    }
    
    
    NSThread *webThread = [NSThread currentThread];
    
    [floatH5 alert:@"制作自己专属的dylib\n\n第一步: 选择悬浮按钮图标文件"];
    
    void (^make)(NSString* icon, NSString* html) = ^(NSString* icon, NSString* html) {
        
        if(!html.length || !icon.length) return;
        
        NSString* makeDYLIB(NSString* iconfile, NSString* htmlfile);
        [floatH5 alert:makeDYLIB(icon, html)];
    };
    
    [TopShow filePicker:@[@"public.image"] callback:^(NSString *icon) {
        
        if(!icon.length) return;
        
        [self performSelector:@selector(threadcall:) onThread:webThread withObject:^{
            
            [floatH5 alert:@"第二步: 选择默认加载的html文件"];
            
//            BOOL choice = [floatH5 confirm:@"第二步: 设置H5悬浮菜单\n\n请问是否需要使用网络H5链接, 否则使用本地html文件"];
//
//            if(choice) {
//                NSString* html = [floatH5 prompt:@"请输入以http或https开头的H5链接地址" defaultText:@""];
//                if(html) make(icon, html);
//            } else
                [TopShow filePicker:@[@"public.html"] callback:^(NSString *html) {
                    [self performSelector:@selector(threadcall:) onThread:webThread withObject:^{
                        make(icon, html);
                    } waitUntilDone:NO];
                }];
            
        } waitUntilDone:NO];
        
    }];
}

-(NSObject*)loadPlugin:(NSString*)className path:(NSString*)dylib
{
    static NSMutableDictionary* cache = [[NSMutableDictionary alloc] init];
    
    NSObject* pluginObject = [cache objectForKey:className];
    if(pluginObject) return pluginObject;
    
    if(![dylib hasPrefix:@"/"])
        dylib = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:dylib];
    
    if(access(dylib.UTF8String, F_OK) != 0)
        return nil;
        
    chmod(dylib.UTF8String, 0755);
    
    if(!dlopen(dylib.UTF8String, RTLD_NOW))
        return nil;
    
    Class pluginClass = NSClassFromString(className);
    if(!pluginClass) return nil;
    
    pluginObject = [pluginClass new];
    
    [cache setObject:pluginObject forKey:className];
    
    return pluginObject;
}

@end

#endif /* h5gg_h */
