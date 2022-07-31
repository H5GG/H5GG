#import <SystemConfiguration/SystemConfiguration.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <pthread.h>
#include <dlfcn.h>

#include "Localized.h"

//忽略一些警告
#pragma GCC diagnostic ignored "-Warc-retain-cycles"

#pragma GCC diagnostic ignored "-Warc-performSelector-leaks"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wincomplete-implementation"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-W#warnings"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wmissing-braces"


bool g_dylib_runmode = false;
bool g_testapp_runmode = false;
bool g_commonapp_runmode = false;
bool g_systemapp_runmode = false;
bool g_standalone_runmode = false;

#include "globalview/globalview.h"

GVData StaticGVSharedData = GVDataDefault;
GVData* PGVSharedData = &StaticGVSharedData;

//使用incbin库用于嵌入其他资源文件
#include "incbin.h"

#include "makeDYLIB.h"

#include "makeWindow.h"

#include "FloatWindow.h"

//引入悬浮按钮头文件
#include "FloatButton.h"
//引入悬浮菜单头文件
#include "FloatMenu.h"

//引入h5gg的JS引擎头文件
#include "h5gg.h"

//嵌入图标文件
INCBIN(Icon, "icon.png");
//嵌入菜单H5文件
INCTXT(Menu, "Index.html");
INCTXT(MenuEn, "Index-en.html");

INCTXT(H5GG_JQUERY_FILE, "jquery.min.js");

//定义悬浮按钮和悬浮菜单全局变量, 防止被自动释放
UIWindow* floatWindow=NULL;
FloatButton* floatBtn=NULL;
FloatMenu* floatH5=NULL;
h5ggEngine* h5gg = NULL;

NSThread* gWebThread=NULL;
JSValue* gButtonAction=NULL;
JSValue* gLayoutAction=NULL;

void onScreenLayoutChange(CGSize size)
{
    NSLog(@"onScreenLayoutChange=%@", NSStringFromCGSize(size));
    if(gLayoutAction) [h5gg performSelector:@selector(threadcall:) onThread:gWebThread withObject:^{
        [gLayoutAction callWithArguments:@[
            [NSNumber numberWithDouble:size.width],
            [NSNumber numberWithDouble:size.height],
        ]];
    } waitUntilDone:NO];
}

#define NotificationChange CFSTR("com.apple.springboard.lockstate") //锁屏或下滑通知界面
#define NotificationLocked CFSTR("com.apple.springboard.lockcomplete") //锁屏或下滑通知界面
#define NotificationBlankedScreen CFSTR("com.apple.springboard.hasBlankedScreen") //黑屏
#define NotificationDisplayStatus CFSTR("com.apple.iokit.hid.displayStatus")

static void screenLockStateChanged(CFNotificationCenterRef center,void* observer,CFStringRef name, const void*object, CFDictionaryRef userInfo)
{
    NSLog(@"SetGlobalView=lock state changed. %@ %@", name, userInfo);
    NSString* lockstate = (__bridge NSString*)name;
    if ([lockstate isEqualToString:(__bridge  NSString*)NotificationDisplayStatus]) {
        NSLog(@"SetGlobalView=locked.");
        if(PGVSharedData->viewHosted) {
            NSLog(@"SetGlobalView=locked.exit");
            exit(0);
        }
    }
}

UIWindow* appWindow = nil;

extern "C" __attribute__ ((visibility ("default")))
void SetGlobalView(char* dylib, UInt64 GVDataOffset)
{
    NSLog(@"SetGlobalView=%x, %s", GVDataOffset, dylib);
    
    pid_t sbpid = pid_for_name("SpringBoard");
    NSLog(@"SetGlobalView=sbpid=%d", sbpid);
    if(!sbpid) return;
    
    task_port_t sbtask=0;
    kern_return_t ret = task_for_pid(mach_task_self(), sbpid, &sbtask);
    NSLog(@"SetGlobalView=task_for_pid=%d %p %d %s!", sbpid, ret, sbtask, mach_error_string(ret));
    if(ret!=KERN_SUCCESS) return;
    
    NSArray* modules = getRangesList2(sbpid, sbtask, [NSString stringWithUTF8String:basename(dylib)]);
    NSLog(@"SetGlobalView=modules=%@", modules);
    if(modules.count!=1) return;
    
    UInt64 modulebase = 0;
    [[NSScanner scannerWithString:modules[0][@"start"]] scanHexLongLong:&modulebase];
    
    NSLog(@"SetGlobalView=dylib=%p:%@, %@", modulebase, modules[0][@"start"], modules[0][@"name"]);
    
    UInt64 address = modulebase + GVDataOffset;
    
    UInt64 mapbase = (uint64_t)address & ~PAGE_MASK;
    size_t mapsize = address + sizeof(GVData) - mapbase;
    mapsize = (mapsize+PAGE_MASK) & ~PAGE_MASK;
    
    NSLog(@"SetGlobalView=%p,%p,%x", address, mapbase, mapsize);
    
    vm_prot_t cur_prot=0;
    vm_prot_t max_prot=0;
    vm_address_t buffer=0;
    kern_return_t kr = vm_remap(mach_task_self(), &buffer, mapsize, 0, VM_FLAGS_ANYWHERE,
                                sbtask, mapbase, false, &cur_prot, &max_prot, VM_INHERIT_NONE);
    
    NSLog(@"SetGlobalView=readmem=%p, %d %s", buffer, kr, mach_error_string(kr));
    if(kr!=KERN_SUCCESS) return;
    
    PGVSharedData = (GVData*)(buffer + (address-mapbase));
    NSLog(@"SetGlobalView=%p", PGVSharedData);
    
    PGVSharedData->enable = YES;
    
    
    NSString* iconstub = [NSString stringWithUTF8String:(char*)gH5ICON_STUB_FILEData];
    if(iconstub.hash!=0x1fdd7fff7d401bd2 && gH5ICON_STUB_FILESize<=sizeof(PGVSharedData->buttonImageData)) {
        PGVSharedData->buttonImageSize = gH5ICON_STUB_FILESize;
        memcpy(PGVSharedData->buttonImageData, gH5ICON_STUB_FILEData, gH5ICON_STUB_FILESize);
    } else {
        PGVSharedData->buttonImageSize = gIconSize;
        memcpy(PGVSharedData->buttonImageData, gIconData, gIconSize);
    }
    
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, screenLockStateChanged, NotificationDisplayStatus, NULL, CFNotificationSuspensionBehaviorDeliverImmediately);

    dispatch_async(dispatch_get_main_queue(), ^{
        static NSTimer* timer = [NSTimer scheduledTimerWithTimeInterval:0.1 repeats:YES block:^(NSTimer*t){
            
            if(PGVSharedData->enable && PGVSharedData->customButtonAction && PGVSharedData->floatBtnClick)
            {
                NSLog(@"SetGlobalView=customButtonAction=%d", PGVSharedData->floatBtnClick);
                
                PGVSharedData->floatBtnClick = NO;
                
                [h5gg performSelector:@selector(threadcall:) onThread:gWebThread withObject:^{
                    [gButtonAction callWithArguments:nil];
                } waitUntilDone:NO];
            }
            
            static BOOL appWindowHandled = NO;
            if(!appWindowHandled && PGVSharedData->viewHosted && appWindow)
            {
                appWindowHandled = YES;
                
                void showFloatWindow(bool show);
                showFloatWindow(true);//悬浮之后强制显示H5
                
                NSLog(@"SetGlobalView=appWindow=%@\n delegateWindow=%@\n windows=%@\n keyWindow=%@", appWindow, UIApplication.sharedApplication.delegate.window, UIApplication.sharedApplication.windows, UIApplication.sharedApplication.keyWindow);
                
                NSMutableArray* appWindows = [@[appWindow] mutableCopy];
                
                //适配定制版APP会创建一个新窗口, 默认的会被隐藏, 但是app的自动旋转是跟随默认的那个窗口
                //但是这里怎么保证那个新的窗口已经创建出来了???这个时机问题不好把握
                UIWindow* firstWin = UIApplication.sharedApplication.windows[0];
                if(firstWin!=appWindow && firstWin.isHidden
                   && [NSStringFromClass(firstWin.class) isEqualToString:@"UIWindow"]
                   && [NSStringFromClass(firstWin.rootViewController.class) isEqualToString:@"ViewController"])
                    [appWindows addObject:firstWin];

                for(UIWindow* win in appWindows)
                {
                    win.alpha = 0; //works fine
                    win.opaque = NO; //no effect
                    win.backgroundColor = [UIColor clearColor]; //no effect
                    //[win setHidden:YES]; //不可见不会自动旋转, FloatWindow无法跟随
                    
                    win.rootViewController = [[AppWinController alloc] initWithBind:win.rootViewController];
                }
            }
            
            static long long lastOrientation=0;
            if(
               //floatWindow && 这里不判断, 让无网络提示的TopShow也可以自动旋转, 反正后面floatWindow出来的时候已经开始跟着globalview转了
               PGVSharedData->viewHosted && lastOrientation!=PGVSharedData->curOrientation) {
                NSLog(@"SetGlobalView=rotate=%d=>%d", lastOrientation, PGVSharedData->curOrientation);
                lastOrientation=PGVSharedData->curOrientation;
                
                for(UIWindow* win in UIApplication.sharedApplication.windows) {
                    win.layer.masksToBounds = YES;
                    [win private_updateToInterfaceOrientation:(UIInterfaceOrientation)PGVSharedData->curOrientation animated:NO];
                }
            }
            
            if(appWindowHandled && !PGVSharedData->appLoaded && UIApplication.sharedApplication.statusBarOrientation==PGVSharedData->curOrientation)
            {
                NSLog(@"SetGlobalView=appLoaded");
                PGVSharedData->appLoaded = YES;
            }
        }];
    });
}

FloatMenu* initFloatMenu(UIWindow* win)
{
    //创建悬浮菜单, 设置位置=居中  尺寸=380宽x屏幕高(最大400)
    CGRect MenuRect = CGRectMake(0, 0, 370, 370);
    MenuRect.origin.x = (win.frame.size.width-MenuRect.size.width)/2;
    MenuRect.origin.y = (win.frame.size.height-MenuRect.size.height)/2;
    
    FloatMenu* floatH5 = [[FloatMenu alloc] initWithFrame:MenuRect];
    
    PGVSharedData->floatMenuRect = floatH5.frame;
        
    //创建并初始化h5gg内存搜索引擎
    h5gg = [[h5ggEngine alloc] init];
    //将h5gg内存搜索引擎添加到H5的JS环境中以便JS可以调用
    [floatH5 setAction:@"h5gg" callback:h5gg];
    
    //隐藏悬浮菜单, 已废弃, 保持旧版API兼容
    [floatH5 setAction:@"closeMenu" callback:^{
        [floatH5 alert:@"closeMenu已废弃请勿调用"];
    }];
    //设置网络图标, 已废弃, 保持旧版API兼容
    [floatH5 setAction:@"setFloatButton" callback:^{
        [floatH5 alert:@"setFloatButton已废弃请勿调用"];
    }];
    //设置悬浮窗位置尺寸, 已废弃, 保持旧版API兼容性
    [floatH5 setAction:@"setFloatWindow" callback:^{
        [floatH5 alert:@"setFloatButton已废弃请勿调用"];
    }];
    
    //给H5菜单添加一个JS函数setButtonImage用于设置网络图标
    [floatH5 setAction:@"setButtonImage" callback:^(NSString* url) {
        NSURL* imageUrl = [NSURL URLWithString:url];
        NSData* data = [NSData dataWithContentsOfURL:imageUrl];
        NSLog(@"setFloatButton=%@", data);
        //通过主线程执行下面的代码
        dispatch_async(dispatch_get_main_queue(), ^{
            if(data) {
                floatBtn.image = [UIImage imageWithData:data];
                if(data.length<=sizeof(PGVSharedData->buttonImageData)) {
                    PGVSharedData->buttonImageSize = data.length;
                    [data getBytes:PGVSharedData->buttonImageData length:data.length];
                }
            }
        });
        return data?YES:NO;
    }];
    
    [floatH5 setAction:@"setButtonAction" callback:^(JSValue* callback) {
        gButtonAction = callback;
        gWebThread = [NSThread currentThread];
        PGVSharedData->customButtonAction = YES;
    }];
    
    //给H5菜单添加一个JS函数setFloatWindow用于设置悬浮窗位置尺寸
    [floatH5 setAction:@"setWindowRect" callback:^(int x, int y, int w, int h) {
        //通过主线程执行下面的代码
        dispatch_async(dispatch_get_main_queue(), ^{
            CGFloat tx = x==-1&&y==-1 ? floatH5.frame.origin.x : x;
            CGFloat ty = x==-1&&y==-1 ? floatH5.frame.origin.y : y;
            floatH5.frame = CGRectMake(tx,ty,w,h);
            PGVSharedData->floatMenuRect = floatH5.frame;
        });
    }];
    
    [floatH5 setAction:@"setWindowDrag" callback:^(int x, int y, int w, int h) {
        //通过主线程执行下面的代码
        dispatch_async(dispatch_get_main_queue(), ^{
            [floatH5 setDragRect: CGRectMake(x,y,w,h)];
        });
    }];
    
    [floatH5 setAction:@"setWindowTouch" callback:^(int x, int y, int w, int h) {
        NSLog(@"setWindowTouch %d %d %d %d", x, y, w, h);
        if((y==0&&w==0&&h==0) && (x==0||x==1)) {
            floatH5.touchableAll = x==1;
            floatH5.touchableRect = CGRectZero;
        } else {
            floatH5.touchableAll = NO;
            floatH5.touchableRect = CGRectMake(x,y,w,h);
        }
        PGVSharedData->touchableAll = floatH5.touchableAll;
        PGVSharedData->touchableRect = floatH5.touchableRect;
        dispatch_async(dispatch_get_main_queue(), ^{
            floatH5.userInteractionEnabled = floatH5.touchableAll;
        });
    }];
    
    void showFloatWindow(bool show);
     [floatH5 setAction:@"setWindowVisible" callback:^(bool visible) {
         NSLog(@"setWindowVisible=%d", visible);
         if(PGVSharedData->enable && PGVSharedData->viewHosted) {
             PGVSharedData->setWindowVisible = YES;
             PGVSharedData->windowVisibleState = visible;
             
             //visible = YES;
             return;
         }
        //通过主线程执行下面的代码
        dispatch_async(dispatch_get_main_queue(), ^{
            showFloatWindow(visible);
        });
    }];
    
    [floatH5 setAction:@"setLayoutAction" callback:^(JSValue* callback) {
        gLayoutAction = callback;
        gWebThread = [NSThread currentThread];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            onScreenLayoutChange(win.frame.size);
        });
    }];
    
    floatH5.reloadAction = ^{
        NSLog(@"reloadAction!");
        gWebThread = nil;
        gButtonAction = nil;
        gLayoutAction = nil;
    };
    
    
    /* 三种加载方式任选其一 */

    NSString* htmlstub = [NSString stringWithUTF8String:(char*)gH5MENU_STUB_FILEData];
    NSLog(@"html stub hash=%p", [htmlstub hash]);
    
    //ipa的.app目录中的H5文件名
    NSString* h5file = [[NSBundle mainBundle] pathForResource:@"H5Menu" ofType:@"html"];
    
    if([htmlstub hash] != 0xc25ce928da0ca2de) {
        //第一优先级: 从网址加载H5
        if([[htmlstub lowercaseString] hasPrefix:@"http"])
            [floatH5 loadRequest:[[NSURLRequest alloc] initWithURL:[NSURL URLWithString:htmlstub]]];
        else {
            NSString* jquery = [NSString stringWithUTF8String:gH5GG_JQUERY_FILEData];
            htmlstub = [htmlstub stringByReplacingOccurrencesOfString:@"var h5gg_jquery_stub;" withString:jquery];
            [floatH5 loadHTMLString:htmlstub baseURL:[NSURL URLWithString:@"Index"]];
        }
    } else if([[NSFileManager defaultManager] fileExistsAtPath:h5file]) {
        //第二优先级: 从文件加载H5
        [floatH5 loadRequest:[[NSURLRequest alloc] initWithURL:[NSURL URLWithString:h5file]]];
    } else {
        //第三优先级: 从dylib加载H5
        NSString* h5gghtml = [getLLCode() isEqualToString:@"zh"] ? [NSString stringWithUTF8String:gMenuData] : [NSString stringWithUTF8String:gMenuEnData];
        NSString* jquery = [NSString stringWithUTF8String:gH5GG_JQUERY_FILEData];
        h5gghtml = [h5gghtml stringByReplacingOccurrencesOfString:@"var h5gg_jquery_stub;" withString:jquery];
        [floatH5 loadHTMLString:h5gghtml baseURL:[NSURL URLWithString:@"Index"]];
    }
    
    return floatH5;
}

void showFloatWindowContinue(bool show)
{
    if(!floatWindow) {
        
        FloatController* rootVC = [[FloatController alloc] init];
        
        rootVC.onResizeCallback = ^(CGSize size) {
            NSLog(@"FloatWindow onSizeChange=%@ => %@", NSStringFromCGSize(floatWindow.frame.size), NSStringFromCGSize(size));
            //if(!CGRectEqualToRect(newRect, floatWindow.frame))
                onScreenLayoutChange(size);
        };
        
        //获取窗口
        floatWindow = makeWindow(NSStringFromClass(FloatWindow.class));
        floatWindow.windowLevel = UIWindowLevelAlert - 1; //比Alert低一级, 防止UIWebView的alert显示到下层去了
        floatWindow.rootViewController = rootVC;
        
        NSLog(@"FloatWindow=size=%@, %@, %@", NSStringFromCGRect(floatWindow.frame), NSStringFromCGRect(UIScreen.mainScreen.bounds), NSStringFromCGRect(UIScreen.mainScreen.nativeBounds));
        
        
        floatH5 = initFloatMenu(floatWindow);
        
        //添加H5悬浮菜单到窗口上
        [floatWindow addSubview:floatH5];
    }
    
    if(show)
    {
        [floatWindow addSubview:floatBtn];
        [floatWindow setHidden:NO];
        //[floatWindow makeKeyAndVisible]; //makeKeyAndVisible会影响APP本身的窗口层级,容易引发BUG
        //floatBtn.keepFront = NO; //floatWindow可能会被APP不可预料的覆盖, 如果悬浮按钮依然不能点击....
        [floatH5 setHidden:NO];
        
        static dispatch_once_t predicate;
         dispatch_once(&predicate, ^{
             //因为在makeKeyAndVisible之前就addSubView了, 所以需要加view移到前台才有响应
             [floatWindow bringSubviewToFront:floatH5];
             //第一次如果悬浮窗口全屏会遮挡按钮无响应, 重置一次前台
             [floatWindow bringSubviewToFront:floatBtn];
         });
    } else {
        [UIApplication.sharedApplication.keyWindow addSubview:floatBtn];
        [floatWindow setHidden:YES];
        //floatBtn.keepFront = YES;
    }
}

void showFloatWindow(bool show)
{
    if(!floatWindow)
    {
        SCNetworkReachabilityFlags flags;
        SCNetworkReachabilityRef reachability = SCNetworkReachabilityCreateWithName(NULL, "www.baidu.com");
        if(!SCNetworkReachabilityGetFlags(reachability, &flags) || (flags & kSCNetworkReachabilityFlagsReachable)==0)
        {
            if(floatBtn) {
                floatBtn.keepFront = NO;
                floatBtn.keepWindow = YES;
            }
            
            [TopShow present:^(TopShow* controller){
                NSString* tips = g_standalone_runmode ? Localized(@"请尝试修复当前APP联网权限") : Localized(@"页面可能无法正确加载");

                UIAlertController *alert = [UIAlertController alertControllerWithTitle:Localized(@"网络异常") message:tips preferredStyle:UIAlertControllerStyleAlert];

                [alert addAction:[UIAlertAction actionWithTitle:Localized(@"继续启动") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                    [controller dismiss];
                    
                    if(floatBtn) {
                        floatBtn.keepFront = YES;
                        floatBtn.keepWindow = NO;
                    }
                    
                    showFloatWindowContinue(show);
                }]];
                return alert;
            }];
            
            return;
        }
        CFRelease(reachability);
    }
    
    showFloatWindowContinue(show);
}

void initFloatButton(void (^callback)(void))
{
    //获取窗口
    UIWindow *window = [UIApplication sharedApplication].keyWindow;
    
    //创建悬浮按钮
    floatBtn = [[FloatButton alloc] init];
    
    if(g_testapp_runmode)
        floatBtn.center = CGPointMake(150, 60);
    
    UIImage* iconImage=nil;
    
    NSString* iconstub = [NSString stringWithUTF8String:(char*)gH5ICON_STUB_FILEData];
    NSLog(@"icon stub hash=%p", [iconstub hash]);
    
    //ipa的.app目录中的图标文件名
    NSString* iconfile = [[NSBundle mainBundle] pathForResource:@"H5Icon" ofType:@"png"];
    
    if([iconstub hash] != 0x1fdd7fff7d401bd2) {
        //第一优先级:
        NSData* iconData = [[NSData alloc] initWithBytes:gH5ICON_STUB_FILEData length:gH5ICON_STUB_FILESize];
        iconImage = [[UIImage alloc] initWithData:iconData];
    } else if([[NSFileManager defaultManager] fileExistsAtPath:iconfile]) {
        //第二优先级: 从文件加载图标
        iconImage = [UIImage imageNamed:iconfile];
    } else {
        //第三优先级: 从dylib加载图标
        NSData* iconData = [[NSData alloc] initWithBytes:gIconData length:gIconSize];
        iconImage = [[UIImage alloc] initWithData:iconData];
    }
    
    //设置悬浮按钮图标
    [floatBtn setIcon:iconImage];
    
    //设置悬浮按钮点击处理, 点击时反转显示隐藏的状态
    [floatBtn setAction:callback];
    
    //将悬浮按钮添加到窗口上
    [window addSubview:floatBtn];
}

void initload()
{
    if(g_standalone_runmode)
    {
        appWindow = UIApplication.sharedApplication.keyWindow;
    }
    
    NSString* app_package = [[NSBundle mainBundle] bundleIdentifier];
    if(app_package.hash==0xa8f1ac9df8696cea || app_package.hash==0xa8f1aca37f747aea)
        return; //UIWebView冲突
    
    NSString* htmlstub = [NSString stringWithUTF8String:(char*)gH5MENU_STUB_FILEData];
    if(app_package.hash==0xccca3dc699edf771 && [htmlstub hash]==0xc25ce928da0ca2de) {
        [TopShow alert:@"风险提示" message:@"建议卸载通用版, 使用跨进程版."];
    }
    
    if(g_standalone_runmode) {
        showFloatWindow(true); //直接加载悬浮按钮和悬浮窗口
        
        if(NSBundle.mainBundle.infoDictionary[@"UIRequiresFullScreen"])
        {
            if(!PGVSharedData->enable)
                [TopShow alert:Localized(@"悬浮模块加载失败") message:Localized(@"请检查你的越狱基板是否安装并启用, 也可能被其他插件禁用或干扰!")];
        }
        
    } else {
        //三方app中第一次点击图标时再加载H5菜单,防止部分APP不兼容H5导致闪退卡死
         initFloatButton(^(void) {
             if(gButtonAction) {
                 [h5gg performSelector:@selector(threadcall:) onThread:gWebThread withObject:^{
                     [gButtonAction callWithArguments:nil];
                 } waitUntilDone:NO];
             } else {
                 bool show = floatWindow ? floatWindow.isHidden : YES;
                 NSLog(@"ButtonShowWindow=%d", show);
                 showFloatWindow(show);
             }
         });
        
    }
}


static void* thread_running(void* arg)
{
    //等一秒, 等系统框架初始化完
    sleep(1);
    
    //通过主线程执行下面的代码
    dispatch_async(dispatch_get_main_queue(), ^{
        __block NSTimer* timer = [NSTimer scheduledTimerWithTimeInterval:0.5 repeats:YES block:^(NSTimer*t){
            
            if(UIApplication.sharedApplication && UIApplication.sharedApplication.keyWindow) {
                [timer invalidate];
                initload();
            }
        }];
    });
    
    return 0;
}

extern "C" {
int memorystatus_control(uint32_t command, pid_t pid, uint32_t flags, void *buffer, size_t buffersize);
}

//初始化函数, 插件加载后系统自动调用
static void __attribute__((constructor)) _init_()
{
    struct dl_info di={0};
    dladdr((void*)_init_, &di);

    NSString* app_path = [[NSBundle mainBundle] bundlePath];
    NSString* app_package = [[NSBundle mainBundle] bundleIdentifier];
    
    NSLog(@"H5GGLoad:%d %d hash:%p app_path=%@\nfirst module header=%p slide=%p current=%p\nmodule=%s\n",
          getuid(), getgid(), [app_package hash], app_path,
          _dyld_get_image_header(0), _dyld_get_image_vmaddr_slide(0),
          di.dli_fbase, di.dli_fname);
    
    //判断是APP程序加载插件(排除后台程序和APP扩展)
    if(![app_path hasSuffix:@".app"]) return;
    
    task_port_t task=0;
    if(task_for_pid(mach_task_self(), getpid(), &task)==KERN_SUCCESS)
        g_standalone_runmode = true;

    
    if([app_package isEqualToString:@"com.test.h5gg"])
        g_testapp_runmode = true;
    
    if([[NSString stringWithUTF8String:di.dli_fname] hasSuffix:@".dylib"])
        g_dylib_runmode = true;
    
    if([app_path containsString:@"/var/"]||[app_path containsString:@"/Application/"])
        g_commonapp_runmode = true;
    
    if(g_testapp_runmode && g_dylib_runmode)
        return;
    
    //判断是普通版还是跨进程版, 防止混用
    if(g_standalone_runmode && g_dylib_runmode)
    {
        NSString* plistPath = [NSString stringWithUTF8String:di.dli_fname];
        char* p = (char*)plistPath.UTF8String + strlen(di.dli_fname) - 5;
        strcpy(p, "plist");
        
        NSDictionary* plist = [[NSDictionary alloc] initWithContentsOfFile:plistPath];
        NSLog(@"plist=%@\n%@\n%@\n%@", plistPath, plist, plist[@"Filter"], plist[@"Filter"][@"Bundles"]);
        if(plist) {
            for(NSString* bundleId in plist[@"Filter"][@"Bundles"]) {
                if([bundleId isEqualToString:app_package]) {
                    g_systemapp_runmode = true;
                    break;
                }
            }
            
            if(!g_systemapp_runmode) for(NSString* bundleId in plist[@"Filter"][@"Bundles"]) {
                NSBundle* test = [NSBundle bundleWithIdentifier:bundleId];
                NSLog(@"filter bundle id=%@, %@, %d", bundleId, test, [test isLoaded]);
                if(test && ![bundleId isEqualToString:app_package]) {
                    NSLog(@"found common bundle inject! this deb is not a crossproc version!");
                    return;
                }
            }

        }
    }
    
    if(g_standalone_runmode||g_commonapp_runmode)
    {
        pthread_t thread;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_create(&thread, &attr, thread_running, nil);
        
//        /* Set active memory limit = inactive memory limit, both non-fatal    */
//        #define MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK   5
//        memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK, getpid (), 1024, NULL, 0); //igg
//        /* Set active memory limit = inactive memory limit, both fatal    */
//        #define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT          6
//        memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, getpid (), 256, NULL, 0); //the other way
        
    }
}
