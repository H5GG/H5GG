#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wincomplete-implementation"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-W#warnings"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wformat"

#import <UIKit/UIKit.h>
#import <pthread.h>
#include <dlfcn.h>
#include <libgen.h>

#include "libAPAppView.h"

NSString* g_pinnedBundleId = @"com.shadow.h5ggapp";

extern UIView* floatBtn;
extern UIWindow* makeWindow();
extern void initFloatButton(void (^callback)(void));
extern void setButtonKeepWindow(BOOL keep);

@interface GVWindow : UIWindow
@end

@implementation GVWindow
// recursively calls -pointInside:withEvent:. point is in the receiver's coordinate system
//-(nullable UIView *)hitTest:(CGPoint)point withEvent:(nullable UIEvent *)event /
//{
//
//}
// default returns YES if point is in bounds
- (BOOL)pointInside:(CGPoint)point withEvent:(nullable UIEvent *)event;
{
    int count = (int)self.subviews.count;
    for (int i = count - 1; i >= 0;i-- ) {
        UIView *childV = self.subviews[i];
        // 把当前坐标系上的点转换成子控件坐标系上的点.
        CGPoint childP = [self convertPoint:point toView:childV];
        UIView *fitView = [childV hitTest:childP withEvent:event];
        if(fitView) {
            //NSLog(@"GVWindow pointInside=%@", fitView);
            return YES;
        }
    }
    return NO;
}

@end

@interface GVController : UIViewController
@end

@implementation GVController
UIView* contextView=nil;
static UIWindow* GlobalView=nil;
-(instancetype)init {
    self = [super init];
    if(self) {
        //contextView = [[UIView alloc] initWithFrame:[UIScreen mainScreen].bounds];
        //[[ContextHostManager sharedInstance] setSceneDelegate:self];
    }
    return self;
}
- (BOOL)shouldAutorotate {
    return UIDevice.currentDevice.orientation==UIDeviceOrientationPortraitUpsideDown ? NO:YES;
}

- (UIInterfaceOrientationMask)supportedInterfaceOrientations {
    return UIInterfaceOrientationMaskAllButUpsideDown;
}

-(UIInterfaceOrientation) preferredInterfaceOrientationForPresentation {
    return UIInterfaceOrientationPortrait;
}

@end


@interface AXBackgrounderManager : NSObject
+(void)setForeground:(id)app WithBool:(BOOL)addOrRemove;
+(BOOL)isForeground:(id)app;
+(void)setForegroundSceneID:(id)app WithBool:(BOOL)addOrRemove;
@end

APAppView* appView=nil;
UIView* hostView = nil;

void handleHostView(UIView* parent)
{
    for(UIView* subview in parent.subviews)
    {
        NSLog(@"GlobalView=handleHostView=%@:%@", NSStringFromClass(parent.class), NSStringFromClass(subview.class));
        if([NSStringFromClass(subview.class) isEqualToString:@"SBHomeGrabberView"]) {
            //[subview setHidden:YES]; //carsh
            //[subview removeFromSuperview]; //no effact
            subview.alpha=0; //works fine
        } else {
            subview.opaque = NO;
            subview.backgroundColor=[UIColor clearColor];
            handleHostView(subview);
        }
    }
}

void toggleGlobalView()
{
    if(hostView==nil)
    {
        //*
        hostView = [appView viewForBundleID:g_pinnedBundleId];
        handleHostView(hostView);
        [GlobalView addSubview:hostView];
        NSLog(@"GlobalView=APAppView=%@", hostView);

        if(![AXBackgrounderManager isForeground:g_pinnedBundleId])
            [AXBackgrounderManager setForeground:g_pinnedBundleId WithBool:YES];

    } else {
        [appView stopAppView];
        [hostView removeFromSuperview];
        hostView = nil;
    }
}

static void* thread_running(void* arg)
{
    sleep(5);

    dispatch_async(dispatch_get_main_queue(), ^{

        GlobalView = makeWindow();
        //GlobalView.alpha = 0.8;
        //GlobalView.opaque = NO;
        GlobalView.clipsToBounds = YES;
        //GlobalView.frame = CGRectMake(0,0, 375, 800);
        GlobalView.backgroundColor=[UIColor clearColor];
        GlobalView.windowLevel = UIWindowLevelStatusBar + 1;
        GlobalView.rootViewController = [[GVController alloc] init];
        
        appView = [[APAppView alloc] init];

        initFloatButton(^(void) {
            void toggleGlobalView();
            toggleGlobalView();
        });

        [GlobalView makeKeyAndVisible];
        [GlobalView addSubview:floatBtn];

        //移除vc自动创建的全屏view (ipad模式还会有多层superview)
        UIView* superview = GlobalView.rootViewController.view;
        while(superview && superview!=GlobalView)
        {
            [superview setHidden:YES];
            superview = superview.superview;
        }

        setButtonKeepWindow(YES);

    });
    
    return 0;
}

static void __attribute__((constructor)) _init_()
{
    if([NSBundle.mainBundle.bundleIdentifier isEqualToString:@"com.apple.springboard"])
    {
        struct dl_info di={0};
        dladdr((void*)_init_, &di);

        NSString* infoPath = [NSString stringWithFormat:@"%s/Info.plist", dirname((char*)di.dli_fname)];
        if(infoPath) {
            NSDictionary* info = [[NSDictionary alloc] initWithContentsOfFile:infoPath];
            if(info)
                g_pinnedBundleId = info[@"CFBundleIdentifier"];
        }

        NSString* plistPath = [NSString stringWithUTF8String:di.dli_fname];
        char* p = (char*)plistPath.UTF8String + strlen(di.dli_fname) - 5;
        strcpy(p, "plist");
        
        NSDictionary* plist = [[NSDictionary alloc] initWithContentsOfFile:plistPath];
        NSLog(@"plist=%@\n%@\n%@\n%@", plistPath, plist, plist[@"Filter"], plist[@"Filter"][@"Bundles"]);
        if(plist) {
            for(NSString* bundleId in plist[@"Filter"][@"Bundles"]) {
                if([bundleId isEqualToString:@"com.apple.springboard"]) 
                {
                    
                pthread_t thread;
                pthread_attr_t attr;
                pthread_attr_init(&attr);
                pthread_create(&thread, &attr, thread_running, nil);


                    break;
                }
            }
        }

    }
}