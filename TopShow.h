//
//  TopMsg.h
//  h5gg
//
//  Created by admin on 21/3/2022.
//

#ifndef TopMsg_h
#define TopMsg_h

#include <objc/runtime.h>

#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wobjc-protocol-method-implementation"
#pragma GCC diagnostic ignored "-Wnullability-completeness"

@interface TopShow : UIViewController <UIDocumentPickerDelegate>
@property NSString* pickedfile;
@property void(^pickedfile_notify)();
@end

@implementation TopShow

static UIWindow* TopShow_lastKeyWindow = nil;
static UIWindow* TopShow_alertWindow = nil;

//如果不定义旋转相关委托函数, 并且屏幕锁定开关没有打开, 则UIAlertController会跟随陀螺仪旋转, 并且界面全部卡死
//主要是supportedInterfaceOrientations返回的支持方向集合, 如果原window不支持竖屏, 新window旋转为横屏, 则原window会卡死

-(UIInterfaceOrientation)interfaceOrientation {
    NSLog(@"TopShow interfaceOrientation=%d", [TopShow_lastKeyWindow.rootViewController interfaceOrientation]);
    return [TopShow_lastKeyWindow.rootViewController interfaceOrientation];
}
-(BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)toInterfaceOrientation
{
    NSLog(@"TopShow shouldAutorotateToInterfaceOrientation=%d", toInterfaceOrientation);
    return [TopShow_lastKeyWindow.rootViewController shouldAutorotateToInterfaceOrientation:toInterfaceOrientation];
}
//上面两个废弃方法似乎没啥作用

- (BOOL)shouldAutorotate {
    NSLog(@"TopShow shouldAutorotate=%d", [TopShow_lastKeyWindow.rootViewController shouldAutorotate]);
    return [TopShow_lastKeyWindow.rootViewController shouldAutorotate];
}
- (UIInterfaceOrientationMask)supportedInterfaceOrientations {
    NSLog(@"TopShow supportedInterfaceOrientations=%d", [TopShow_lastKeyWindow.rootViewController supportedInterfaceOrientations]);
    return [TopShow_lastKeyWindow.rootViewController supportedInterfaceOrientations];
}

-(UIInterfaceOrientation) preferredInterfaceOrientationForPresentation {
    NSLog(@"TopShow preferredInterfaceOrientationForPresentation=%d", [TopShow_lastKeyWindow.rootViewController preferredInterfaceOrientationForPresentation]);

    NSLog(@"orientation=%d statusBarOrientation=%d", [[UIDevice currentDevice] orientation], [UIApplication sharedApplication].statusBarOrientation);

    return [TopShow_lastKeyWindow.rootViewController preferredInterfaceOrientationForPresentation];
}

void printClass(NSObject* obj)
{
    for(Class clz=obj.class; clz!=NSObject.class; clz = class_getSuperclass(clz))
        NSLog(@"delegate=%@", clz);
}

+(void)present:(UIViewController*(^)(void))alert {
    void (^submit)() = ^{
        
    TopShow_lastKeyWindow = [UIApplication sharedApplication].keyWindow;
    
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
        TopShow_alertWindow = [[UIWindow alloc] initWithWindowScene:theScene];
    }else{
        TopShow_alertWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    }
    
    NSLog(@"sharedApplication=%@ %@", [UIApplication sharedApplication], [[UIApplication sharedApplication] superclass]);
    printClass(UIApplication.sharedApplication.delegate);
    NSLog(@"TopShow_lastKeyWindow=%@", TopShow_lastKeyWindow);
    NSLog(@"TopShow_alertWindow=%@", TopShow_alertWindow);
    NSLog(@"last supportedInterfaceOrientations=%d", [TopShow_lastKeyWindow.rootViewController supportedInterfaceOrientations]);
    
    TopShow_alertWindow.rootViewController = [[TopShow alloc] init];
    TopShow_alertWindow.windowLevel = UIWindowLevelAlert + 1;
    [TopShow_alertWindow makeKeyAndVisible];

    //等待下一轮再显示, 不然rootViewController的viewDidAppear还没调用就viewWillDisappear了
    dispatch_async(dispatch_get_main_queue(), ^() {
        [TopShow_alertWindow.rootViewController presentViewController:alert() animated:YES completion:nil];
    });
        
    };
    
    if([NSThread isMainThread])
        submit();
    else
        dispatch_async(dispatch_get_main_queue(), submit);
}

+(void)dismiss {
    NSLog(@"TopShow dismiss on %d", [NSThread isMainThread]);
    
    [TopShow_alertWindow setHidden:YES];
    
    [TopShow_lastKeyWindow makeKeyAndVisible];
    
    TopShow_alertWindow = nil;
}

+(void)alert:(NSString*)title message:(NSString*)message
{
    [self present:^() {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];

        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            [self dismiss];
        }]];
        
        return alert;
    }];
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {
    NSLog(@"documentPickerWasCancelled=%@", controller);
    [TopShow dismiss];
}

- (void)_documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentAtURL:(NSURL *)url {
    NSLog(@"didPickDocumentAtURL %@", url);
    
    BOOL canAccessingResource = [url startAccessingSecurityScopedResource];
    NSLog(@"canAccessingResource=%d", canAccessingResource);
    
    [TopShow dismiss];
    
    self.pickedfile = [url path];
    self.pickedfile_notify();
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray <NSURL *>*)urls {
    NSLog(@"didPickDocumentAtURLs %@", urls);
    [self _documentPicker:controller didPickDocumentAtURL:urls[0]];
}

+(void)filePicker:(NSArray*)types callback:(void(^)(NSString*))callback
{
    [self present:^(void) {

        //似乎有个人还是不行, 先加回static试试? 还是不行,就算移动到app目录也不行, 奇奇怪怪???
        TopShow* filePickerCallback = [[TopShow alloc] init];
        
        //因为delegate是弱引用, 所以整个block保持他自己
        filePickerCallback.pickedfile_notify = ^(){
            callback(filePickerCallback.pickedfile);
        };
        
        //UIDocumentMenuViewController需要iCloud权限, UIDocumentPickerViewController这个似乎不用
        UIDocumentPickerViewController* documentPicker = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:types inMode:UIDocumentPickerModeImport]; //UIDocumentPickerModeOpen部分APP不回调
        NSLog(@"modalPresentationStyle=%d", documentPicker.modalPresentationStyle);
        //documentPicker.modalPresentationStyle = UIModalPresentationOverFullScreen; //默认似乎是UIModalPresentationPageSheet, 绝对不能用UIModalPresentationFullScreen会卡死一天一夜!!!!
        documentPicker.delegate = filePickerCallback; //弱引用
        return documentPicker;
    }];
}

@end


#endif /* TopMsg_h */
