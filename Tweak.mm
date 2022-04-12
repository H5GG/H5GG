#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <pthread.h>
#include <dlfcn.h>
#import <SystemConfiguration/SystemConfiguration.h>

//忽略一些警告
#pragma GCC diagnostic ignored "-Warc-retain-cycles"

#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wincomplete-implementation"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-W#warnings"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wformat"

extern "C" {
int memorystatus_control(uint32_t command, pid_t pid, uint32_t flags, void *buffer, size_t buffersize);
}


//引入悬浮按钮头文件
#include "FloatButton.h"
//引入悬浮菜单头文件
#include "FloatMenu.h"

//引入h5gg的JS引擎头文件
#include "h5gg.h"

//使用incbin库用于嵌入其他资源文件
#include "incbin.h"

//嵌入图标文件
INCBIN(Icon, "icon.png");
//嵌入菜单H5文件
INCTXT(Menu, "Menu.html");

INCTXT(H5GG_JQUERY_FILE, "jquery.min.js");

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


#import <sys/sysctl.h>
NSArray* getRunningProcess()
{
    //指定名字参数，按照顺序第一个元素指定本请求定向到内核的哪个子系统，第二个及其后元素依次细化指定该系统的某个部分。
    //CTL_KERN，KERN_PROC,KERN_PROC_ALL 正在运行的所有进程
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL ,0};
    
    size_t miblen = 4;
    //值-结果参数：函数被调用时，size指向的值指定该缓冲区的大小；函数返回时，该值给出内核存放在该缓冲区中的数据量
    //如果这个缓冲不够大，函数就返回ENOMEM错误
    size_t size;
    //返回0，成功；返回-1，失败
    int st = sysctl(mib, miblen, NULL, &size, NULL, 0);
    NSLog(@"allproc=%d, %s", st, strerror(errno));
    
    struct kinfo_proc * process = NULL;
    struct kinfo_proc * newprocess = NULL;
    do
    {
        size += size / 10;
        newprocess = (struct kinfo_proc *)realloc(process, size);
        if (!newprocess)
        {
            if (process)
            {
                free(process);
                process = NULL;
            }
            return nil;
        }
        
        process = newprocess;
        st = sysctl(mib, miblen, process, &size, NULL, 0);
        NSLog(@"allproc=%d, %s", st, strerror(errno));
    } while (st == -1 && errno == ENOMEM);
    
    if (st == 0)
    {
        if (size % sizeof(struct kinfo_proc) == 0)
        {
            int nprocess = size / sizeof(struct kinfo_proc);
            if (nprocess)
            {
                NSMutableArray * array = [[NSMutableArray alloc] init];
                for (int i = nprocess - 1; i >= 0; i--)
                {
                    [array addObject:@{
                        @"pid": [NSNumber numberWithInt:process[i].kp_proc.p_pid],
                        @"name": [NSString stringWithUTF8String:process[i].kp_proc.p_comm]
                    }];
                }
                
                free(process);
                process = NULL;
                NSLog(@"allproc=%d, %@", array.count, array);
                return array;
            }
        }
    }
    
    return nil;
}

pid_t pid_for_name(const char* name)
{
    NSArray* allproc = getRunningProcess();
    for(NSDictionary* proc in allproc)
    {
        if([[proc valueForKey:@"name"] isEqualToString:[NSString stringWithUTF8String:name]])
            return [[proc valueForKey:@"pid"] intValue];
    }
    return 0;
}


//定义悬浮按钮和悬浮菜单全局变量, 防止被自动释放
UIWindow* floatWindow=NULL;
FloatButton* floatBtn=NULL;
FloatMenu* floatH5=NULL;
h5ggEngine* h5gg = NULL;

@interface FloatController : UIViewController
@end

@implementation FloatController

static UIWindow* FloatController_lastKeyWindow=nil;

-(instancetype)init {
    self = [super init];
    if(self) {
        FloatController_lastKeyWindow = [UIApplication sharedApplication].keyWindow;
    }
    return self;
}

//如果不定义旋转相关委托函数, 并且屏幕锁定开关没有打开, 则UIAlertController会跟随陀螺仪旋转, 并且界面全部卡死
//主要是supportedInterfaceOrientations返回的支持方向集合, 如果原window不支持竖屏, 新window旋转为横屏, 则原window会卡死

- (BOOL)shouldAutorotate {
    NSLog(@"FloatWindow shouldAutorotate=%d", [FloatController_lastKeyWindow.rootViewController shouldAutorotate]);
    return [FloatController_lastKeyWindow.rootViewController shouldAutorotate];
}

-(UIInterfaceOrientation)interfaceOrientation {
    NSLog(@"FloatWindow interfaceOrientation=%d", [FloatController_lastKeyWindow.rootViewController interfaceOrientation]);
    return [FloatController_lastKeyWindow.rootViewController interfaceOrientation];
}
-(BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)toInterfaceOrientation
{
    NSLog(@"FloatWindow shouldAutorotateToInterfaceOrientation=%d", toInterfaceOrientation);
    return [FloatController_lastKeyWindow.rootViewController shouldAutorotateToInterfaceOrientation:toInterfaceOrientation];
}

- (UIInterfaceOrientationMask)supportedInterfaceOrientations {
    NSLog(@"FloatWindow supportedInterfaceOrientations=%d", [FloatController_lastKeyWindow.rootViewController supportedInterfaceOrientations]);
    return [FloatController_lastKeyWindow.rootViewController supportedInterfaceOrientations];
}

-(UIInterfaceOrientation) preferredInterfaceOrientationForPresentation {
    NSLog(@"FloatWindow preferredInterfaceOrientationForPresentation=%d", [FloatController_lastKeyWindow.rootViewController preferredInterfaceOrientationForPresentation]);

    NSLog(@"orientation=%d statusBarOrientation=%d", [[UIDevice currentDevice] orientation], [UIApplication sharedApplication].statusBarOrientation);

    return [FloatController_lastKeyWindow.rootViewController preferredInterfaceOrientationForPresentation];
}

@end

UIWindow* makeWindow()
{
    UIWindow* w = nil;
    
    if (@available(iOS 13.0, *)) {
        UIWindowScene* theScene=nil;
        for (UIWindowScene* windowScene in [UIApplication sharedApplication].connectedScenes) {
            NSLog(@"windowScene=%@ %@ state=%d", windowScene, windowScene.windows, windowScene.activationState);
            if(!theScene && windowScene.activationState==UISceneActivationStateForegroundInactive)
                theScene = windowScene;
            if (windowScene.activationState == UISceneActivationStateForegroundActive) {
                theScene = windowScene;
                break;
            }
        }
        w = [[UIWindow alloc] initWithWindowScene:theScene];
    }else{
        w = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    }
    
    return w;
}

void initFloatMenu()
{
    //获取窗口
    floatWindow = makeWindow();
    floatWindow.windowLevel = UIWindowLevelAlert - 1;
    floatWindow.rootViewController = [[FloatController alloc] init];
    
    //[floatWindow makeKeyAndVisible];
    
    //创建悬浮菜单, 设置位置=居中  尺寸=380宽x屏幕高(最大400)
    CGRect MenuRect = CGRectMake(0, 0, 380, floatWindow.frame.size.height);
    if(MenuRect.size.height>600) MenuRect.size.height = 600;
    MenuRect.origin.x = (floatWindow.frame.size.width-MenuRect.size.width)/2;
    MenuRect.origin.y = (floatWindow.frame.size.height-MenuRect.size.height)/2;
    
    floatH5 = [[FloatMenu alloc] initWithFrame:MenuRect];
    
    if([[[NSBundle mainBundle] bundlePath] hasPrefix:@"/Applications/"])
        floatH5.alpha = 0.9;
    
    //创建并初始化h5gg内存搜索引擎
    h5gg = [[h5ggEngine alloc] init];
    //将h5gg内存搜索引擎添加到H5的JS环境中以便JS可以调用
    [floatH5 setAction:@"h5gg" callback:h5gg];
    
    //给H5菜单添加一个JS函数closeMenu用于点击X时隐藏菜单
    [floatH5 setAction:@"closeMenu" callback:^(void) {
        //通过主线程执行下面的代码
        dispatch_async(dispatch_get_main_queue(), ^{
            void toggleWindow();toggleWindow();
        });
    }];
    
    //给H5菜单添加一个JS函数setFloatButton用于设置网络图标
    [floatH5 setAction:@"setFloatButton" callback:^(NSString* url) {
        NSURL* imageUrl = [NSURL URLWithString:url];
        NSData* data = [NSData dataWithContentsOfURL:imageUrl];
        NSLog(@"setFloatButton=%@", data);
        //通过主线程执行下面的代码
        dispatch_async(dispatch_get_main_queue(), ^{
            if(data) floatBtn.image = [UIImage imageWithData:data];
        });
        return data?YES:NO;
    }];
    
    //给H5菜单添加一个JS函数setFloatWindow用于设置悬浮窗位置尺寸
    [floatH5 setAction:@"setFloatWindow" callback:^(int x, int y, int h, int w) {
        //通过主线程执行下面的代码
        dispatch_async(dispatch_get_main_queue(), ^{
            floatH5.frame = CGRectMake(x,y,h,w);
        });
    }];
    
    [floatH5 setAction:@"setWindowDrag" callback:^(int x, int y, int h, int w) {
        //通过主线程执行下面的代码
        dispatch_async(dispatch_get_main_queue(), ^{
            [floatH5 setDragRect: CGRectMake(x,y,h,w)];
        });
    }];
    
    /* 三种加载方式任选其一 */
    
    
    NSString* htmlstub = [NSString stringWithUTF8String:(char*)gH5MENU_STUB_FILEData];
    NSLog(@"html stub hash=%p", [htmlstub hash]);
    
    //ipa的.app目录中的H5文件名
    NSString* h5file = [[NSBundle mainBundle] pathForResource:@"H5Menu" ofType:@"html"];
    
    if([htmlstub hash] != 0xc25ce928da0ca2de) {
        //第一优先级: 从网址加载H5
        if([[htmlstub lowercaseString] hasPrefix:@"http"])
            [floatH5 loadRequest:[[NSURLRequest alloc] initWithURL:[NSURL URLWithString:htmlstub]]];
        else
            [floatH5 loadHTMLString:htmlstub baseURL:[NSURL URLWithString:@"html@dylib"]];
    } else if([[NSFileManager defaultManager] fileExistsAtPath:h5file]) {
        //第二优先级: 从文件加载H5
        [floatH5 loadRequest:[[NSURLRequest alloc] initWithURL:[NSURL URLWithString:h5file]]];
    } else {
        //第三优先级: 从dylib加载H5
        NSString* h5gghtml = [NSString stringWithUTF8String:gMenuData];
        NSString* jquery = [NSString stringWithUTF8String:gH5GG_JQUERY_FILEData];
        h5gghtml = [h5gghtml stringByReplacingOccurrencesOfString:@"var h5gg_jquery_stub;" withString:jquery];
        [floatH5 loadHTMLString:h5gghtml baseURL:[NSURL URLWithString:@"html@dylib"]];
    }

    //添加H5悬浮菜单到窗口上
    [floatWindow addSubview:floatH5];
}


void toggleWindow2();
void toggleWindow()
{
    if(floatWindow) {
        toggleWindow2();
        return;
    }
    
    SCNetworkReachabilityFlags flags;
    SCNetworkReachabilityRef reachability = SCNetworkReachabilityCreateWithName(NULL, "www.baidu.com");
    if(!SCNetworkReachabilityGetFlags(reachability, &flags) || (flags & kSCNetworkReachabilityFlagsReachable)==0)
    {
        NSString* tips = @"H5GG可能无法正确加载!";
        if([[[NSBundle mainBundle] bundlePath] hasPrefix:@"/Applications/"])
            tips = @"请尝试使用以下越狱插件修复联网权限:\n\n<连个锤子>\n\n<FixNets>\n\n<NetworkManage>\n";
        
        [TopShow present:^{
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"没有网络" message:tips preferredStyle:UIAlertControllerStyleAlert];

            [alert addAction:[UIAlertAction actionWithTitle:@"继续启动" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                [TopShow dismiss];
                
                toggleWindow2();
            }]];
            return alert;
        }];
        
        return;
    }
    CFRelease(reachability);
    
    toggleWindow2();
}

void toggleWindow2()
{
    //第一次点击图标时再加载H5菜单,防止部分APP不兼容H5导致闪退卡死
    if(!floatWindow) {
        initFloatMenu();
    }
    
    if(!floatWindow) return;
    
    if(floatWindow.isHidden) {
        FloatController_lastKeyWindow = [UIApplication sharedApplication].keyWindow;
        
        [floatWindow makeKeyAndVisible];
        [floatWindow addSubview:floatBtn];
        floatBtn.keepFront = NO;
        [floatH5 setHidden:NO];
        
        static dispatch_once_t predicate;
         dispatch_once(&predicate, ^{
             //因为在makeKeyAndVisible之前就addSubView了, 所以需要加view移到前台才有响应
             [floatWindow bringSubviewToFront:floatH5];
             
//
//             floatWindow.clipsToBounds = TRUE;
//             //floatH5.bounds = CGRectMake(-floatH5.frame.origin.x, -floatH5.frame.origin.y, floatH5.bounds.size.width, floatH5.bounds.size.height);;
//             //floatH5.frame = CGRectMake(0, 0, floatH5.frame.size.width, floatH5.frame.size.height);
//                #define angle2Rad(angle) ((angle) / 180.0 * M_PI)
//             floatH5.transform = CGAffineTransformMakeRotation((angle2Rad(90)));
//             //floatWindow.frame = CGRectMake(0, 0, floatWindow.frame.size.height, floatWindow.frame.size.width);
//             NSLog(@"superview=%@", FloatController_lastKeyWindow.superview);
             
         });
    } else {
        [floatWindow setHidden:YES];
        [FloatController_lastKeyWindow makeKeyAndVisible];
        [FloatController_lastKeyWindow addSubview:floatBtn];
        floatBtn.keepFront = YES;
        
        FloatController_lastKeyWindow = nil;
    }
}

void loadFloatButtonAndMenu()
{
    //获取窗口
    UIWindow *window = [UIApplication sharedApplication].keyWindow;
    
    //创建悬浮按钮
    floatBtn = [[FloatButton alloc] init];
    
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
    [floatBtn setAction:^(void) {
        toggleWindow();
    }];
    
    //将悬浮按钮添加到窗口上
    [window addSubview:floatBtn];
}

void* thread_running(void* arg)
{
    //等一秒, 等系统框架初始化完
    sleep(1);
    
    //通过主线程执行下面的代码
    dispatch_async(dispatch_get_main_queue(), ^{
        
        NSString* app_path = [[NSBundle mainBundle] bundlePath];
        if([app_path hasPrefix:@"/Applications/"])
        {
            if(getRunningProcess()==nil) return;
        }
        
        NSString* app_package = [[NSBundle mainBundle] bundleIdentifier];
        if(app_package.hash == 0xccca3dc699edf771) {
            [TopShow alert:@"风险提示!" message:@"建议卸载当前deb, 使用H5GG跨进程版!"];
        }
        
        //加载悬浮按钮和悬浮窗口
        loadFloatButtonAndMenu();
        
        if([[[NSBundle mainBundle] bundlePath] hasPrefix:@"/Applications/"])
            toggleWindow();
        
    });
    
    return 0;
}

//初始化函数, 插件加载后系统自动调用
static void __attribute__((constructor)) _init_()
{
    struct dl_info di={0};
    dladdr((void*)_init_, &di);

    NSString* app_path = [[NSBundle mainBundle] bundlePath];
    NSString* app_package = [[NSBundle mainBundle] bundleIdentifier];
    
    NSLog(@"%d %d %p header=%p slide=%p %base=%p\nmodule=%s\napp_path=%@ ", getuid(), getgid(), [app_package hash],
          _dyld_get_image_header(0),
          _dyld_get_image_vmaddr_slide(0),
          di.dli_fbase, di.dli_fname, app_path);

    if([app_package isEqualToString:@"com.test.h5gg"] && [[NSString stringWithUTF8String:di.dli_fname] hasSuffix:@".dylib"])return;
    
    //判断是APP程序加载插件(排除后台程序和APP扩展)
    if(![app_path hasSuffix:@".app"]) return;
    
    //判断是普通版还是跨进程版, 防止混用
    if([app_path hasPrefix:@"/Applications/"] && [[NSString stringWithUTF8String:di.dli_fname] hasSuffix:@".dylib"])
    {
        NSString* plistPath = [NSString stringWithUTF8String:di.dli_fname];
        char* p = (char*)plistPath.UTF8String + strlen(di.dli_fname) - 5;
        strcpy(p, "plist");
        
        NSDictionary* plist = [[NSDictionary alloc] initWithContentsOfFile:plistPath];
        NSLog(@"plist=%@\n%@\n%@\n%@", plistPath, plist, plist[@"Filter"], plist[@"Filter"][@"Bundles"]);
        if(plist) {
            for(NSString* bundleId in plist[@"Filter"][@"Bundles"]) {
                NSBundle* test = [NSBundle bundleWithIdentifier:bundleId];
                NSLog(@"filter bundle id=%@, %@, %d", bundleId, test, [test isLoaded]);
                if(test && ![bundleId isEqualToString:app_package]) {
                    NSLog(@"found common bundle inject! this deb is not a crossproc version!");
                    return;
                }
            }
        }
    }
    
    
    if(
       ([app_path hasPrefix:@"/Applications/"]) ||
       ([app_path containsString:@"/var/"] ||  [app_path containsString:@"/Application/"]) //只对三方APP生效
        //||  [app_package isEqualToString:@"com.apple.springboard"] //或者是指定APP的包名
    )
    {
        pthread_t thread;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_create(&thread, &attr, thread_running, nil);
        
        /* Set active memory limit = inactive memory limit, both non-fatal    */
        #define MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK   5
        //memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK, getpid (), 1024, NULL, 0); //igg
        /* Set active memory limit = inactive memory limit, both fatal    */
        #define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT          6
        //memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, getpid (), 256, NULL, 0); //the other way
    }
}


