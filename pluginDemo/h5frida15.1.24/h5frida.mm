#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <JavaScriptCore/JavaScriptCore.h>
#import <UIKit/UIKit.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <spawn.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include "version.h"
#include "frida-core-15.1.24.h"
#include "fishhook.h"
#include "static-inline.h"

#define INCBIN_SILENCE_BITCODE_WARNING
#include "incbin.h"

INCTXT(H5FRIDA_JS, "h5frida.js");

#pragma GCC diagnostic ignored "-Wunguarded-availability-new"

//定义JS函数接口
@protocol h5fridaJSExport <JSExport>
//frida
-(double)pluginVersion;
-(NSString*)coreVersion;

-(BOOL)loadGadget:(NSString*)dylib;
//ios系统app如果设置了suid位, 会导致无法调用FileBroswer(白屏)
//-(BOOL)installServer:(NSString*)debfile;
//-(BOOL)uninstallServer:(NSString*)package;

JSExportAs(ActiveCodePatch,
            -(BOOL)Active:(NSString*)machoPath Code:(uint64_t)vaddr Patch:(NSString*)patch);
JSExportAs(DeactiveCodePatch,
            -(BOOL)Deactive:(NSString*)machoPath Code:(uint64_t)vaddr Patch:(NSString*)patch);
JSExportAs(ApplyCodePatch,
           -(NSString*)Apply:(NSString*)machoPath Code:(uint64_t)vaddr Patch:(NSString*)patch);


-(NSObject*)attach:(int)pid;
-(NSArray*)enumerate_processes;
-(NSDictionary*)get_frontmost_application;

@end

@protocol h5fridaSessionJSExport <JSExport>
//session
-(BOOL)detach;
-(BOOL)is_detached;
-(NSObject*)create_script:(NSString*)code;
JSExportAs(on, -(void)on:(NSString*)event withAction:(JSValue*)callback);
@end

@protocol h5fridaScriptJSExport <JSExport>
//script
-(BOOL)load;
-(BOOL)unload;
-(BOOL)eternalize;
-(BOOL)is_destroyed;
-(void)post:(id)data;
-(NSArray*)list_exports;
JSExportAs(call, -(NSObject*)call:(NSString*)name withArgs:(NSArray*)args);
JSExportAs(on, -(void)on:(NSString*)event withAction:(JSValue*)callback);
@end

@interface fridaObject : NSObject
@end

@implementation fridaObject
-(void)threadcall:(void(^)(void))block {
    block();
}
@end

//定义插件类
@interface h5frida : fridaObject <h5fridaJSExport>
@property FridaDeviceManager * manager;
@property FridaDevice * local_device;
@property NSMutableDictionary* sessions;
@end

@interface h5fridaSession : fridaObject <h5fridaSessionJSExport>
@property pid_t processID;
@property NSThread* jsthread;
@property JSValue* on_detached;
@property FridaSession * session;
@property NSMutableDictionary* scripts;
@end

@interface h5fridaScript : fridaObject <h5fridaScriptJSExport>
@property NSThread* jsthread;
@property JSValue* on_message;
@property FridaScript* script;
@property BOOL is_loaded;
@property id rpc_result;
@property UInt64 rpc_request_id;
@property dispatch_semaphore_t rpc_semaphore;
@end

static void on_detached (FridaSession * session, FridaSessionDetachReason reason, FridaCrash * crash, gpointer user_data)
{
    gchar * reason_str = g_enum_to_string (FRIDA_TYPE_SESSION_DETACH_REASON, reason);
    g_print ("on_detached: reason=%s crash=%p\n", reason_str, crash);

    h5fridaSession* s = (__bridge id)user_data;
    for(id key in s.scripts)
    {
        h5fridaScript* script = s.scripts[key];
        
        script.rpc_result=nil;
        dispatch_semaphore_signal(script.rpc_semaphore);
    }
    
    if(s.on_detached) {
        NSString* r=[NSString stringWithUTF8String:reason_str];
        [s performSelector:@selector(threadcall:) onThread:s.jsthread withObject:^{
            [s.on_detached callWithArguments:@[r]];
        } waitUntilDone:NO];
    }
    
    g_free (reason_str);
}

static void on_message (FridaScript * script, const gchar * message, GBytes * data, gpointer user_data)
{
    h5fridaScript* s = (__bridge id)user_data;
    NSData* jsonData = [[NSString stringWithUTF8String:message] dataUsingEncoding:NSUTF8StringEncoding];
    
    NSError* error=NULL;
    NSDictionary* msg = [NSJSONSerialization JSONObjectWithData:jsonData options:NSJSONReadingMutableContainers error:&error];
    
    NSString* type = msg[@"type"];
    id payload = msg[@"payload"];
    
    NSLog(@"[msg] %@", msg);
    
    if([type isEqualToString:@"send"] && [payload isKindOfClass:NSArray.class] &&
       [payload count]>0 && ![payload[0] isEqual:NSNull.null] && [payload[0] isEqualToString:@"frida:rpc"])
    {
        NSLog(@"rpc msg!!!!!!!");
        UInt64 request_id = [payload[1] unsignedLongValue];
        NSString* status =  payload[2];
        
        g_assert(request_id==s.rpc_request_id);
        
        s.rpc_result = nil;
        
        if([status isEqualToString:@"ok"]) {
            s.rpc_result = payload[3];
        } else if([status isEqualToString:@"error"]) {
            msg = @{@"type":@"error", @"info":[payload subarrayWithRange:NSMakeRange(3, [payload count]-3)]};
        }
        
        dispatch_semaphore_signal(s.rpc_semaphore);
        if([status isEqualToString:@"ok"]) return;
    }
    
    if(s.on_message) {
        [s performSelector:@selector(threadcall:) onThread:s.jsthread withObject:^{
            [s.on_message callWithArguments:@[msg]];
        } waitUntilDone:NO];
    }
    
    NSLog(@"on_message done.");
}


extern char **environ;
NSData *lastSystemOutput=nil;

int runCommandv(const char *cmd, int argc, const char * const* argv, void (^unrestrict)(pid_t)) {
    pid_t pid;
    posix_spawn_file_actions_t *actions = NULL;
    posix_spawn_file_actions_t actionsStruct;
    int out_pipe[2];
    bool valid_pipe = false;
    posix_spawnattr_t *attr = NULL;
    posix_spawnattr_t attrStruct;
    
    NSMutableString *cmdstr = [NSMutableString stringWithCString:cmd encoding:NSUTF8StringEncoding];
    for (int i=1; i<argc; i++) {
        //[cmdstr appendFormat:@" \"%s\"", argv[i]];
        [cmdstr appendFormat:@" %s", argv[i]];
    }
    
    valid_pipe = pipe(out_pipe) == ERR_SUCCESS;
    if (valid_pipe && posix_spawn_file_actions_init(&actionsStruct) == ERR_SUCCESS) {
        actions = &actionsStruct;
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 1);
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 2);
        posix_spawn_file_actions_addclose(actions, out_pipe[0]);
        posix_spawn_file_actions_addclose(actions, out_pipe[1]);
    }
    
    if (unrestrict && posix_spawnattr_init(&attrStruct) == ERR_SUCCESS) {
        attr = &attrStruct;
        posix_spawnattr_setflags(attr, POSIX_SPAWN_START_SUSPENDED);
    }
    
    int rv = posix_spawn(&pid, cmd, actions, attr, (char *const *)argv, environ);
    NSLog(@"%s(%d) command: %@", __FUNCTION__, pid, cmdstr);
    
    if (unrestrict) {
        unrestrict(pid);
        kill(pid, SIGCONT);
    }
    
    if (valid_pipe) {
        close(out_pipe[1]);
    }
    
    if (rv == ERR_SUCCESS) {
        if (valid_pipe) {
            NSMutableData *outData = [NSMutableData new];
            char c;
            char s[2] = {0, 0};
            NSMutableString *line = [NSMutableString new];
            while (read(out_pipe[0], &c, 1) == 1) {
                [outData appendBytes:&c length:1];
                if (c == '\n') {
                    NSLog(@"%s(%d): %@", __FUNCTION__, pid, line);
                    [line setString:@""];
                } else {
                    s[0] = c;
                    [line appendString:@(s)];
                }
            }
            if ([line length] > 0) {
                NSLog(@"%s(%d): %@", __FUNCTION__, pid, line);
            }
            lastSystemOutput = [outData copy];
        }
        if (waitpid(pid, &rv, 0) == -1) {
            NSLog(@"ERROR: Waitpid failed, %s", strerror(rv));
        } else {
            NSLog(@"%s(%d) completed with exit status %d", __FUNCTION__, pid, WEXITSTATUS(rv));
        }
        
    } else {
        NSLog(@"%s(%d): ERROR posix_spawn failed (%d): %s", __FUNCTION__, pid, rv, strerror(rv));
        rv <<= 8; // Put error into WEXITSTATUS
    }
    if (valid_pipe) {
        close(out_pipe[0]);
    }
    return rv;
}

int runCommand(const char *cmd, ...) {
    va_list ap, ap2;
    int argc = 1;
    
    va_start(ap, cmd);
    va_copy(ap2, ap);
    
    while (va_arg(ap, const char *) != NULL) {
        argc++;
    }
    va_end(ap);
    
    const char *argv[argc+1];
    argv[0] = cmd;
    for (int i=1; i<argc; i++) {
        argv[i] = va_arg(ap2, const char *);
    }
    va_end(ap2);
    argv[argc] = NULL;
    
    int rv = runCommandv(cmd, argc, argv, NULL);
    return WEXITSTATUS(rv);
}


//实现插件接口函数
@implementation h5frida
//-(instancetype)initWithEval:(JSValue*(^)(NSString*))eval {
-(instancetype)init {
    if (self = [super init])
    {
        self.sessions = [[NSMutableDictionary alloc] init];
        
        frida_init ();
        
        self.manager = frida_device_manager_new ();
        
        GError * error = NULL;
        FridaDeviceList *devices = frida_device_manager_enumerate_devices_sync (self.manager, NULL, &error);
        g_assert (error == NULL);

        self.local_device = NULL;
        gint num_devices = frida_device_list_size (devices);
        for (gint i = 0; i != num_devices; i++)
        {
          FridaDevice * device = frida_device_list_get (devices, i);

          g_print ("[*] Found device: \"%s\" type=%d\n", frida_device_get_name (device), frida_device_get_dtype(device));

          if (frida_device_get_dtype (device) == FRIDA_DEVICE_TYPE_REMOTE)
              self.local_device = g_object_ref (device);

          g_object_unref (device);
        }
        g_assert (self.local_device != NULL);

        frida_unref (devices);
        devices = NULL;
    }
    return self;
}


-(BOOL)installServer:(NSString*)debfile {
    
    NSLog(@"uid=%d gid=%d setuid=%d", getuid(), getgid(), setuid(0));
    
    if(![debfile hasPrefix:@"/"])
        debfile = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:debfile];
    
    int ret = runCommand("/usr/bin/dpkg", "-i", debfile.UTF8String,  NULL);
    
    NSLog(@"installServer=%d", ret);
    
    if(ret !=0) return NO;
    
    while(true)
    {
        BOOL loaded = NO;
        for(NSDictionary* item in [self enumerate_processes])
        {
            if([item[@"pid"] intValue] ==-1 && ![item[@"name"] isEqualToString:@"Gadget"])
            {
                loaded = YES;
                break;
            }
        }
        
        if(loaded) break;
    
        sleep(1);
    }
    
    return YES;
}

-(BOOL)uninstallServer:(NSString*)package {
    
    int ret = runCommand("/usr/bin/dpkg", "-P", package.UTF8String,  NULL);
    
    NSLog(@"uninstallServer=%d", ret);
    
    return ret==0? YES:NO;
}

-(BOOL)loadGadget:(NSString*)dylib
{
    if(![dylib hasPrefix:@"/"])
        dylib = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:dylib];
    
    if(access(dylib.UTF8String, F_OK) != 0)
        return NO;
        
    chmod(dylib.UTF8String, 0755);
    
    if(!dlopen(dylib.UTF8String, RTLD_NOW))
        return NO;
    
    while(true)
    {
        BOOL loaded = NO;
        for(NSDictionary* item in [self enumerate_processes])
        {
            if([item[@"pid"] intValue] ==-1 && [item[@"name"] isEqualToString:@"Gadget"])
            {
                loaded = YES;
                break;
            }
        }
        
        if(loaded) break;
    
        sleep(1);
    }
    
    return YES;
}

-(double)pluginVersion {
    return H5FRIDA_PLUGIN_VERSION;
}

-(NSString*)coreVersion {
    return [NSString stringWithUTF8String:FRIDA_CORE_VERSION];
}

-(NSObject*)attach:(int)pid
{
    if(pid==-1) pid=getpid();
    
    h5fridaSession* cache = [self.sessions objectForKey:[NSNumber numberWithInt:pid]];
    if(cache && cache.session && ![cache is_detached]) return cache;
    
    GError * error = NULL;
    FridaSession* session = frida_device_attach_sync (self.local_device, pid, (FridaSessionOptions*)FRIDA_REALM_NATIVE, NULL, &error);
    if (!session || error != NULL)
        return nil;
    
    if (frida_session_is_detached (session))
        return nil;
    
    h5fridaSession* s = [[h5fridaSession alloc] init];
    s.processID = pid;
    s.session = session;
    
    g_signal_connect (session, "detached", G_CALLBACK (on_detached), (__bridge void*)s);
    
    [self.sessions setObject:s forKey:[NSNumber numberWithInt:pid]];
    
    return s;
}

-(NSArray*)enumerate_processes
{
    NSMutableArray* procs = [[NSMutableArray alloc] init];
    
    GError * error = NULL;
    FridaProcessList* result = frida_device_enumerate_processes_sync (self.local_device, NULL, g_cancellable_get_current (), &error);
    if(result) {
        gint result_length = frida_process_list_size (result);
        g_print("process count=%d\n", result_length);
        for(int i=0; i<result_length; i++)
        {
            FridaProcess* p=frida_process_list_get (result, i);
            g_print("process[%d] %s\n", frida_process_get_pid(p), frida_process_get_name(p));
            int pid = frida_process_get_pid(p);
            [procs addObject:@{
                @"pid": [NSNumber numberWithInt:pid==getpid()?-1:pid],
                @"name":[NSString stringWithUTF8String:frida_process_get_name(p)]
            }];
        }
    }
    
    if(error) {
        g_printerr ("Failed to attach: %s\n", error->message);
        g_error_free (error);
    }
    
    return procs;
}

-(NSDictionary*)get_frontmost_application {
    NSDictionary* appinfo = nil;
    
    FridaFrontmostQueryOptions * options = frida_frontmost_query_options_new();
    frida_frontmost_query_options_set_scope (options, FRIDA_SCOPE_FULL);
    
    GError * error = NULL;
    FridaApplication * result = frida_device_get_frontmost_application_sync (self.local_device, options, g_cancellable_get_current (), &error);
    
    g_object_unref (options);
    
    if(result) {
        const gchar * identifier = frida_application_get_identifier (result);
        const gchar * name = frida_application_get_name (result);
        guint pid = frida_application_get_pid (result);
        
        appinfo = @{
            @"identifier" : [NSString stringWithUTF8String:identifier],
            @"name" : [NSString stringWithUTF8String:name],
            @"pid" : [NSNumber numberWithInt:pid]
        };
        
        g_object_unref(result);
    }
    
    if(error) {
            g_printerr ("Failed to get_frontmost_application: %s\n", error->message);
            g_error_free (error);
    }
    
    return appinfo;
}

/*-----------------------------------------------------------------------*/
/*-----------------------------------------------------------------------*/

-(BOOL)Active:(NSString*)machoPath Code:(uint64_t)vaddr Patch:(NSString*)patch
{
    return ActiveCodePatch((char*)machoPath.UTF8String, vaddr, (char*)patch.UTF8String);
}

-(BOOL)Deactive:(NSString*)machoPath Code:(uint64_t)vaddr Patch:(NSString*)patch
{
    return DeactiveCodePatch((char*)machoPath.UTF8String, vaddr, (char*)patch.UTF8String);
}

-(NSString*)Apply:(NSString*)machoPath Code:(uint64_t)vaddr Patch:(NSString*)patch
{
    return StaticInlineHookPatch((char*)machoPath.UTF8String, vaddr, (char*)patch.UTF8String);
}

/*-----------------------------------------------------------------------*/

+(NSString*)staticInline:(char*)machoPath Hook:(uint64_t)vaddr Patch:(char*)patch
{
    return StaticInlineHookPatch(machoPath, vaddr, patch);
}

+(void*)staticInline:(char*)machoPath Hook:(uint64_t)vaddr Function:(void*)replace
{
    return StaticInlineHookFunction(machoPath, vaddr, replace);
}

+(BOOL)staticInline:(char*)machoPath Hook:(uint64_t)vaddr Instrument:(void(*)(RegisterContext*))callback
{
    return StaticInlineHookInstrument(machoPath, vaddr, callback);
}

+(void*)fish:(char*)funcname hook:(void*)newfunc
{
    void* oldfunc=NULL;

    struct rebinding bind={0};
    bind.name = funcname;
    bind.replacement = newfunc;
    bind.replaced = &oldfunc;

    rebind_symbols(&bind, 1);

    NSLog(@"fishhook %s %p : %p\n", funcname, newfunc, oldfunc);

    return oldfunc;
}

/*-----------------------------------------------------------------------*/
/*-----------------------------------------------------------------------*/

@end

@implementation h5fridaSession

-(instancetype)init {
    if (self = [super init])
    {
        self.jsthread=NULL;
        self.on_detached=NULL;
        self.scripts = [[NSMutableDictionary alloc] init];
    }
    return self;
}

-(BOOL)detach
{
    if([self is_detached])
        return YES;
    
    GError * error = NULL;
    frida_session_detach_sync (self.session, NULL, &error);
    if(error) {
        g_printerr ("Failed to detach session: %s\n", error->message);
        g_error_free (error);
        return NO;
    }
    frida_unref (self.session); self.session=NULL;
    g_print ("[*] Detached\n");
    return YES;
}

-(BOOL)is_detached
{
    return !self.session || frida_session_is_detached (self.session);
}

-(NSObject*)create_script:(NSString*)code {
    
    if([self is_detached]) return nil;
    
    if(self.processID==getpid()) {
        NSString* fixedScript = [NSString stringWithUTF8String:gH5FRIDA_JSData];
        fixedScript = [fixedScript stringByReplacingOccurrencesOfString:@"\n" withString:@""];
        fixedScript = [fixedScript stringByReplacingOccurrencesOfString:@"\r" withString:@""];
        //NSLog(@"FIXED_H5FRIDA_JS=%@", fixedScript);
        
        code = [fixedScript stringByAppendingString:code];
    }
    
    h5fridaScript* cache = [self.scripts objectForKey:[NSNumber numberWithUnsignedInteger:code.hash]];
    if(cache && cache.script) return cache;
    
    FridaScriptOptions * options = frida_script_options_new ();
    frida_script_options_set_name (options, "frida_script");
    frida_script_options_set_runtime (options, FRIDA_SCRIPT_RUNTIME_QJS);

    GError * error = NULL;
    FridaScript* script = frida_session_create_script_sync (self.session, code.UTF8String, options, NULL, &error);
    g_clear_object (&options);
    
    if(error) {
        g_printerr ("Failed to create script: %s\n", error->message);
        g_error_free (error);
        return nil;
    }
    
    h5fridaScript* s = [[h5fridaScript alloc] init];
    s.script = script;
    
    g_signal_connect (script, "message", G_CALLBACK (on_message), (__bridge void*)s);
    
    [self.scripts setObject:s forKey:[NSNumber numberWithUnsignedInteger:code.hash]];
    
    return s;
}

-(void)on:(NSString*)event withAction:(JSValue*)callback {
    self.jsthread = NSThread.currentThread;
    if([event isEqualToString:@"detached"]) {
        self.on_detached = callback;
    }
}

@end


@implementation h5fridaScript

-(instancetype)init {
    if (self = [super init])
    {
        self.is_loaded = NO;
        self.jsthread=NULL;
        self.on_message=NULL;
        self.rpc_semaphore = dispatch_semaphore_create(0);
    }
    return self;
}

-(BOOL)is_destroyed {
    return !self.script || frida_script_is_destroyed(self.script);
}

-(BOOL)load {
    if(!self.script)
        return NO;
    
    if(self.is_loaded)
        return YES;
    
    GError * error = NULL;
    frida_script_load_sync (self.script, NULL, &error);
    if(error) {
        g_printerr ("Failed to load script: %s\n", error->message);
        g_error_free (error);
        return NO;
    }
    g_print ("[*] Script loaded\n");
    self.is_loaded = YES;
    return YES;
}

-(BOOL)unload {
    
    if([self is_destroyed])
        return YES;
    
    GError * error = NULL;
    frida_script_unload_sync (self.script, NULL, &error);
    if(error) {
        g_printerr ("Failed to unload script: %s\n", error->message);
        g_error_free (error);
        return NO;
    }
    
    //script will destroy if unload
    frida_unref (self.script);
    self.script=NULL;
    
    g_print ("[*] Unloaded\n");
    return YES;
}

-(BOOL)eternalize {
    if([self is_destroyed])
        return NO;
    
    GError * error = NULL;
    frida_script_eternalize_sync (self.script, g_cancellable_get_current (), &error);
    if(error) {
        g_printerr ("Failed to eternalize script: %s\n", error->message);
        g_error_free (error);
        return NO;
    }
    return YES;
}

-(void)post:(id)data {

    if([self is_destroyed])
        return;
    
    NSError *error = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:data options:0 error:&error];

    if ([jsonData length] && error == nil)
    {
        NSString* jsonstr = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
        NSLog(@"frida post=%@", jsonstr);
        frida_script_post (self.script, jsonstr.UTF8String, NULL);
    }
}

-(void)on:(NSString*)event withAction:(JSValue*)callback {
    self.jsthread = NSThread.currentThread;
    if([event isEqualToString:@"message"])
    {
        self.on_message = callback;
    }
}

-(NSArray*)list_exports {
    
    if([self is_destroyed])
        return nil;
    
    [self post:@[@"frida:rpc", [NSNumber numberWithUnsignedLong:++self.rpc_request_id], @"list"]];
    
    dispatch_semaphore_wait(self.rpc_semaphore, DISPATCH_TIME_FOREVER);
    
    return self.rpc_result;
}

-(NSObject*)call:(NSString*)name withArgs:(NSArray*)args {
    
    if([self is_destroyed])
        return nil;
    
    NSArray* data = @[@"frida:rpc", [NSNumber numberWithUnsignedLong:++self.rpc_request_id], @"call", name];
    if(args) data = [data arrayByAddingObject:args];
    [self post:data];
    
    dispatch_semaphore_wait(self.rpc_semaphore, DISPATCH_TIME_FOREVER);
    
    return self.rpc_result;
}

@end
