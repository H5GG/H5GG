#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wincomplete-implementation"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-W#warnings"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wnullability-completeness"

#import <UIKit/UIKit.h>
#import <pthread.h>
#include <dlfcn.h>
#include <libgen.h>

#include "ContextHostManager.h"
#include "globalview.h"
#include "libAPAppView.h"
#include "../FloatButton.h"
#include "../makeWindow.h"
#include "../incbin.h"

bool g_dismiss_on_switchapp = true;
bool g_dismiss_on_backtohome = true;

//嵌入图标文件
INCBIN(Icon, "../icon.png");

NSString* g_pinnedBundleId = nil;
UIImage* g_pinnedBundleIcon = nil;

GVData GVSharedData = GVDataDefault;

FloatButton* floatBtn;
APAppView* appView=nil;
UIView* hostView = nil;
UIWindow* GlobalView=nil;

UIViewController *getViewControllerWithView(UIView *view){
    UIResponder *responder = view;
    while ((responder = [responder nextResponder]))
        if ([responder isKindOfClass: [UIViewController class]])
            return (UIViewController *)responder;
    return nil;
}

void alphaHostView(UIView* view)
{
    if(view.opaque) {
        view.opaque = NO;
        view.backgroundColor=[UIColor clearColor];
    }
    for(UIView* subview in view.subviews)
    {
        alphaHostView(subview);
    }
}

void handleHostView(UIView* view, CGRect newFrame)
{
    UIViewController* vc = getViewControllerWithView(view);
    NSLog(@"GlobalView=handleHostView=%@(%@) : %@",
            NSStringFromClass(view.class), vc?NSStringFromClass(vc.class):@"", NSStringFromClass(view.class));

    if([NSStringFromClass(view.class) isEqualToString:@"SBHomeGrabberView"]) {
        //[view setHidden:YES]; //carsh
        //[view removeFromSuperview]; //no effact
        view.alpha=0; //works fine
        return;
    }

    //这里subviews可能还没初始化完
    //由于hostView启动时会根据屏幕显示方向初始化布局, 而不是当前设备方向, 所以强制调整一下布局尺寸
    if(view.frame.origin.x==newFrame.origin.x
    &&view.frame.origin.y==newFrame.origin.y
    && view.frame.size.width==newFrame.size.height
    && view.frame.size.height==newFrame.size.width
    ) {
        NSLog(@"GlobalView=forceRotation=%@", view);
        view.frame = newFrame;
    }

    for(UIView* subview in view.subviews)
    {
        handleHostView(subview, newFrame);
    }
}


@interface GVWindow : UIWindow
@end

@implementation GVWindow
// default returns YES if point is in bounds
- (BOOL)pointInside:(CGPoint)point withEvent:(nullable UIEvent *)event;
{
    //NSLog(@"touchtest floatwin pointInside=%@, %@", NSStringFromCGPoint(point), event);
    int count = (int)self.subviews.count;
    for (int i = count - 1; i >= 0;i-- ) {
        UIView *childV = self.subviews[i];
        // 把当前坐标系上的点转换成子控件坐标系上的点.
        CGPoint childP = [self convertPoint:point toView:childV];
        UIView *fitView = [childV hitTest:childP withEvent:event];
        if(fitView) {
            //NSLog(@"FloatWindow pointInside=%@", fitView);

            if(childV==hostView) {
                if(GVSharedData.touchableAll) {
                    return CGRectContainsPoint(GVSharedData.floatMenuRect, childP);
                } else {
                    return CGRectContainsPoint(GVSharedData.touchableRect, childP);
                }
            }

            return YES;
        }
    }
    return NO;
}

-(void)setHidden:(BOOL)hidden
{
    [super setHidden:hidden];
    
    NSLog(@"FloatWindow setHidden=%d", hidden);

    if(hidden==NO)
    {
        //移除vc自动创建的全屏view (ipad模式还会有多层superview)
        UIView* superview = self.rootViewController.view;
        while(superview && ![superview isKindOfClass:UIWindow.class])
        {
            [superview setHidden:YES];
            superview = superview.superview;
        }
    }
}

@end

@interface GVController : UIViewController
@end

void dumpview(int i, UIView* view)
{
   for(int j=0; j<view.subviews.count; j++)
   {
       UIView* subView = view.subviews[j];

       NSString* tag=@"";
       for(int a=0;a<i;a++) tag = [tag stringByAppendingString:@"--"];
        NSLog(@"GlobalView=dumpview=%@ %d, %@:%@",tag, subView.isHidden, NSStringFromCGRect(subView.frame), NSStringFromClass(subView.class));
       
       //dumpview(i+1, subView);
   }
}


@interface SBApplicationProcessState
@property(readonly, nonatomic) int pid;
@end
@interface SBApplication()
 @property SBApplicationProcessState* processState;
@end

// @interface SBApplication
// @property NSString *bundleIdentifier;
// @property NSString *displayIdentifier;//14系统没有这个?
// @property NSString *displayName;
// @property SBApplicationProcessState* processState;
// - (id)mainScene;
// @end

// @interface SpringBoard  : UIApplication
// -(SBApplication*)_accessibilityFrontMostApplication;
// -(void)_relaunchSpringBoardNow;
// -(BOOL)isLocked;
// -(long long)activeInterfaceOrientation;
// -(long long)_currentNonFlatDeviceOrientation;
// -(void)_returnToHomescreenWithCompletion:(/*^block*/id)arg1 ;
// @end


@implementation GVController
- (BOOL)shouldAutorotate {
    NSString *deviceType = [UIDevice currentDevice].model;
    if([deviceType isEqualToString:@"iPad"]) return YES;
    return UIDevice.currentDevice.orientation==UIDeviceOrientationPortraitUpsideDown ? NO:YES;
}

- (UIInterfaceOrientationMask)supportedInterfaceOrientations {
    SpringBoard* sbapp = (SpringBoard*)[UIApplication sharedApplication];
    return (UIInterfaceOrientationMask)(1<<sbapp.activeInterfaceOrientation);
}

-(UIInterfaceOrientation) preferredInterfaceOrientationForPresentation {
    SpringBoard* sbapp = (SpringBoard*)[UIApplication sharedApplication];
    return (UIInterfaceOrientation)sbapp.activeInterfaceOrientation;
}

- (void)viewWillTransitionToSize:(CGSize)size withTransitionCoordinator:(id <UIViewControllerTransitionCoordinator>)coordinator
{
    [super viewWillTransitionToSize:size withTransitionCoordinator:coordinator];

    // NSLog(@"GlobalView=resize=%f,%f : %@", size.width, size.height, self.view);

    // if (size.width==self.view.frame.size.width && size.height==self.view.frame.size.height)
    //     return;
}
@end

Class AXBackgrounderManager;
@interface AXBackgrounderManagerClass : NSObject
+(void)setForeground:(id)app WithBool:(BOOL)enable;
+(BOOL)isForeground:(id)app;
+(void)setForegroundSceneID:(id)app WithBool:(BOOL)enable;
//12
+(void)setDictionary:(NSString*)bundleId WithBool:(BOOL)enable;
@end

//如果每次隐藏就stop横屏切换时如果键盘弹出状态会变半屏
// void toggleGlobalView()
// {
//     if(hostView==nil)
//     {
//         //*
//         hostView = [appView viewForBundleID:g_pinnedBundleId];
//         NSLog(@"GlobalView=APAppView=%@", hostView);
//         handleHostView(hostView, GlobalView.frame);
//         [GlobalView addSubview:hostView];

//         if(![AXBackgrounderManager isForeground:g_pinnedBundleId])
//             [AXBackgrounderManager setForeground:g_pinnedBundleId WithBool:YES];

//     } else {
//         [appView stopAppView];
//         [hostView removeFromSuperview];
//         hostView = nil;
//     }
// }

void toggleGlobalView()
{
    static UIAlertController *alertloading = nil;

    static NSTimer* timer = [NSTimer scheduledTimerWithTimeInterval:0.1 repeats:YES block:^(NSTimer*t) {
                
        if(hostView) {
            GVSharedData.viewHosted = YES;
            alphaHostView(hostView);

            //ios12这个横屏时会乱转frame{{-128,128},{1024,768}} bounds{{0,0},{768,1024}} transform{{0,1,-1,0},{0,0}}
            //打回原形=>frame{{0,0},{768,1024}}
            if(!CGAffineTransformIsIdentity(hostView.transform)) {
                hostView.transform = CGAffineTransformIdentity;
            }
            //ios11修改transform之后位置不对, 需要手动调整
            if(hostView.frame.origin.x!=0 || hostView.frame.origin.y!=0) {
                hostView.frame = CGRectMake(0, 0, hostView.frame.size.width, hostView.frame.size.height);
            }

            SBApplication *appToHost = applicationForID(g_pinnedBundleId);
            //NSLog(@"GlobalView=appToHost=%@", appToHost);
            bool running = appToHost && appToHost.processState;

            if(!running)
            {
                NSLog(@"GlobalView=monitor=%d", running);
                GVSharedData = GVDataDefault;
                [hostView removeFromSuperview];

                if (@available(iOS 13, *)) {
                    [appView stopAppView];
                } else {
                    [ContextHostManager.sharedInstance stopHostingView:hostView forBundleId:g_pinnedBundleId];
                }

                hostView = nil;
            }
            else if(!hostView.superview && GVSharedData.enable && GVSharedData.appLoaded) {
                NSLog(@"GlobalView=apploaded");
                if(alertloading) {
                    [GlobalView.rootViewController dismissViewControllerAnimated:YES completion:nil];
                    alertloading = nil;
                }
                [GlobalView addSubview:hostView];
            }
        }
    }];

    if(hostView==nil)
    {
        BOOL running = GVSharedData.enable;
        static NSTimer* timer2 = nil;

        if (@available(iOS 13, *)) {

            GVSharedData.followCurrentOrientation = YES;

            hostView = [appView viewForBundleID:g_pinnedBundleId];
            handleHostView(hostView, GlobalView.frame);
            NSLog(@"GlobalView=APAppView=%@", hostView);
            
            [AXBackgrounderManager setForeground:g_pinnedBundleId WithBool:YES];
        } else {
            hostView = [ContextHostManager.sharedInstance hostViewForBundleID:g_pinnedBundleId];
            
            if(!hostView) running = false;

            timer2 = [NSTimer scheduledTimerWithTimeInterval:0.1 repeats:YES block:^(NSTimer*t) {
                hostView = [ContextHostManager.sharedInstance hostViewForBundleID:g_pinnedBundleId];
                if(hostView) {
                    NSLog(@"GlobalView=gothostview=%@", hostView);

                    [AXBackgrounderManager setDictionary:g_pinnedBundleId WithBool:YES];

                    [timer2 invalidate];
                    timer2 = nil;
                }
            }];
        }

        if(running)
        {
            [GlobalView addSubview:hostView];
        }
        else
        {
            alertloading = [UIAlertController alertControllerWithTitle:@"正在启动" message:@"" preferredStyle:UIAlertControllerStyleAlert];
            [alertloading addAction:[UIAlertAction actionWithTitle:@". . ." style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
                alertloading = nil;
                if(timer2) {
                    [timer2 invalidate];
                    timer2 = nil;
                }
            }]];
            [GlobalView.rootViewController presentViewController:alertloading animated:YES completion:nil];
        }
        return;
    }

    if(hostView.superview)
        [hostView setHidden:!hostView.isHidden];
}

void initload()
{
    void* backgrounder=NULL;
    if (@available(iOS 13, *)) {
        backgrounder=dlopen("/Library/MobileSubstrate/DynamicLibraries/libH5GG.B.dylib", RTLD_NOW);
    } else {
        backgrounder=dlopen("/Library/MobileSubstrate/DynamicLibraries/libH5GG.B12.dylib", RTLD_NOW);
    }

    AXBackgrounderManager = NSClassFromString(@"AXBackgrounderManager");
    NSLog(@"GlobalView=backgrounder=%p, %@", backgrounder, AXBackgrounderManager);

    GlobalView = makeWindow(NSStringFromClass(GVWindow.class));
    //GlobalView.alpha = 0.8;
    //GlobalView.opaque = NO;
    //GlobalView.clipsToBounds = YES;
    //GlobalView.frame = CGRectMake(0,0, 375, 800);
    GlobalView.layer.masksToBounds = YES;
    GlobalView.backgroundColor=[UIColor clearColor];
    GlobalView.windowLevel = UIWindowLevelStatusBar + 1;
    GlobalView.rootViewController = [[GVController alloc] init];
    
    if (@available(iOS 13, *)) {
        appView = [[APAppView alloc] init];
    }

    floatBtn = [[FloatButton alloc] init];
    floatBtn.keepWindow = YES;

    if(!g_pinnedBundleIcon) {
        NSData* iconData = [[NSData alloc] initWithBytes:gIconData length:gIconSize];
        g_pinnedBundleIcon = [[UIImage alloc] initWithData:iconData];
    }
    [floatBtn setIcon:g_pinnedBundleIcon];

    [floatBtn setAction:^(void) {
        NSLog(@"GlobalView=clickbutton");
        if(GVSharedData.enable && GVSharedData.customButtonAction)
        {
            if(!hostView) {
                toggleGlobalView();
                return;
            }

            if(hostView.isHidden) {
                [hostView setHidden:NO];
                return;
            }

            GVSharedData.floatBtnClick = YES;

        } else {
            toggleGlobalView();
        }
    }];

    [GlobalView addSubview:floatBtn]; 
    //[GlobalView makeKeyAndVisible];
    [GlobalView setHidden:NO];

    //处理前台app变化时
    static NSTimer* timer = [NSTimer scheduledTimerWithTimeInterval:0.1 repeats:YES block:^(NSTimer*t){
        SpringBoard* sbapp = (SpringBoard*)[UIApplication sharedApplication];

        //NSLog(@"GlobalView=activeInterfaceOrientation=%d, front=%@", sbapp.activeInterfaceOrientation, sbapp._accessibilityFrontMostApplication);

        static id lastApp = sbapp._accessibilityFrontMostApplication;
        if(lastApp!=sbapp._accessibilityFrontMostApplication) {
            NSLog(@"GlobalView appchange=%@ => %@", lastApp, sbapp._accessibilityFrontMostApplication);
            if(hostView && !hostView.isHidden) {
                if( (g_dismiss_on_switchapp && lastApp && sbapp._accessibilityFrontMostApplication)
                || (g_dismiss_on_backtohome && !sbapp._accessibilityFrontMostApplication))
                    toggleGlobalView();
            }
            lastApp = sbapp._accessibilityFrontMostApplication;
        }

        static long long lastOrientation=sbapp.activeInterfaceOrientation;
        GVSharedData.curOrientation = (UIInterfaceOrientation)sbapp.activeInterfaceOrientation;
        if(lastOrientation!=sbapp.activeInterfaceOrientation) {
            NSLog(@"GlobalView=rotate=%d=>%d", lastOrientation, sbapp.activeInterfaceOrientation);
            lastOrientation=sbapp.activeInterfaceOrientation;
            [GlobalView private_updateToInterfaceOrientation:(UIInterfaceOrientation)sbapp.activeInterfaceOrientation animated:YES];
        }

        if(GVSharedData.buttonImageSize) {
            NSData* iconData = [[NSData alloc] initWithBytes:GVSharedData.buttonImageData length:GVSharedData.buttonImageSize];
            g_pinnedBundleIcon = [[UIImage alloc] initWithData:iconData];
            [floatBtn setIcon:g_pinnedBundleIcon];
            GVSharedData.buttonImageSize = 0;
        }


        SBApplication *appToHost = applicationForID(g_pinnedBundleId);
        bool running = appToHost && appToHost.processState;
        if(floatBtn.isHidden!=!running) [floatBtn setHidden:!running];
    }];
}

static void* thread_running(void* arg)
{
    //等一下, 等系统框架初始化完
    sleep(2);
    
    //通过主线程执行下面的代码
    dispatch_async(dispatch_get_main_queue(), ^{
        __block NSTimer* timer = [NSTimer scheduledTimerWithTimeInterval:1 repeats:YES block:^(NSTimer*t){

            if(UIApplication.sharedApplication && UIApplication.sharedApplication.keyWindow) {
                [timer invalidate];
                initload();
            }
        }];
    });
    
    return 0;
}

static void __attribute__((constructor)) _init_()
{
    struct dl_info di={0};
    dladdr((void*)_init_, &di);

    if([NSBundle.mainBundle.bundleIdentifier isEqualToString:@"com.apple.springboard"])
    {
        // NSString* infoPath = [NSString stringWithFormat:@"%s/Info.plist", dirname((char*)di.dli_fname)];
        // if(infoPath) {
        //     NSDictionary* info = [[NSDictionary alloc] initWithContentsOfFile:infoPath];
        //     if(info)
        //         g_pinnedBundleId = info[@"CFBundleIdentifier"];
        // }

        NSString* plistPath = [NSString stringWithUTF8String:di.dli_fname];
        char* p = (char*)plistPath.UTF8String + strlen(di.dli_fname) - 5;
        strcpy(p, "plist");
        
        NSDictionary* plist = [[NSDictionary alloc] initWithContentsOfFile:plistPath];
        NSLog(@"plist=%@\n%@\n%@\n%@", plistPath, plist, plist[@"Filter"], plist[@"Filter"][@"Bundles"]);
        if(plist && [plist[@"Filter"][@"Bundles"] count]<=2) {
            for(NSString* bundleId in plist[@"Filter"][@"Bundles"]) {
                if([bundleId isEqualToString:@"com.apple.springboard"]) 
                {
                    pthread_t thread;
                    pthread_attr_t attr;
                    pthread_attr_init(&attr);
                    pthread_create(&thread, &attr, thread_running, nil);
                } else {
                    g_pinnedBundleId = bundleId;
                }
            }
        }
    } else {
        void (*SetGlobalView)(char* dylib, UInt64 GVDataOffset);
        *(void**)&SetGlobalView = dlsym(RTLD_DEFAULT, "SetGlobalView");
        SetGlobalView((char*)di.dli_fname, (UInt64)&GVSharedData-(UInt64)di.dli_fbase);
    }
}
