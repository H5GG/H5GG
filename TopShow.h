//
//  TopMsg.h
//  h5gg
//
//  Created by admin on 21/3/2022.
//

#ifndef TopMsg_h
#define TopMsg_h

#include <objc/runtime.h>
#include "makeWindow.h"

#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wobjc-protocol-method-implementation"
#pragma GCC diagnostic ignored "-Wnullability-completeness"

@interface TopShow : UIViewController <UIDocumentPickerDelegate>
@property UIWindow* lastKeyWindow;
@property UIWindow* alertWindow;
@property NSString* pickedfile;
@property void(^pickedfile_notify)();
@end

@implementation TopShow


//如果不定义旋转相关委托函数, 并且没有锁定屏幕旋转, 则UIAlertController会跟随陀螺仪旋转, 并且界面全部卡死
//主要是supportedInterfaceOrientations返回的支持方向集合, 如果原window不支持竖屏, 新window旋转为横屏, 则原window会卡死

- (BOOL)shouldAutorotate {
    BOOL should = self.lastKeyWindow.rootViewController.shouldAutorotate;
    NSLog(@"TopShow shouldAutorotate=%d", should);
    return should;
}
- (UIInterfaceOrientationMask)supportedInterfaceOrientations {
    UIInterfaceOrientationMask mask = self.lastKeyWindow.rootViewController.supportedInterfaceOrientations;
    NSLog(@"TopShow supportedInterfaceOrientations=%d", mask);
    return mask;
}

-(UIInterfaceOrientation) preferredInterfaceOrientationForPresentation {
    UIInterfaceOrientation preferred = self.lastKeyWindow.rootViewController.preferredInterfaceOrientationForPresentation;
    NSLog(@"TopShow preferredInterfaceOrientationForPresentation=%d : %d,%d", preferred,
          [[UIDevice currentDevice] orientation], [UIApplication sharedApplication].statusBarOrientation);
    
    return preferred;
}

+(void)present:(UIViewController*(^)(TopShow* controller))alert {
    void (^submit)() = ^(){
        TopShow* rootVC = [TopShow new];
        
        rootVC.lastKeyWindow = [UIApplication sharedApplication].keyWindow;
        NSLog(@"TopShow follow keyWindow=%@", rootVC.lastKeyWindow);
        
        rootVC.alertWindow = makeWindow(NSStringFromClass(UIWindow.class));
    
        rootVC.alertWindow.rootViewController = rootVC;
        //显示在系统的普通Alert之上, //UIWindowLevelStatusBar=1000, UIWindowLevelAlert=2000
        rootVC.alertWindow.windowLevel = UIWindowLevelAlert + 1;
        //makeKeyAndVisible会影响APP本身的窗口层级,容易引发BUG //[rootVC.alertWindow makeKeyAndVisible];
        [rootVC.alertWindow setHidden:NO];

        //等待下一轮再显示, 不然rootViewController的viewDidAppear还没调用就viewWillDisappear了
        dispatch_async(dispatch_get_main_queue(), ^() {
            [rootVC presentViewController:alert(rootVC) animated:YES completion:nil];
        });
    };
    
    if([NSThread isMainThread])
        submit();
    else
        dispatch_async(dispatch_get_main_queue(), submit);
}

-(void)dismiss {
    NSLog(@"TopShow dismiss on %d", [NSThread isMainThread]);
    
    [self.alertWindow setHidden:YES];
    self.lastKeyWindow = nil;
    self.alertWindow = nil;
}

+(void)alert:(NSString*)title message:(NSString*)message
{
    [self present:^(TopShow* controller) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];

        [alert addAction:[UIAlertAction actionWithTitle:Localized(@"确定") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            [controller dismiss];
        }]];
        
        return alert;
    }];
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {
    NSLog(@"documentPickerWasCancelled=%@", controller);
    [self dismiss];
}

- (void)_documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentAtURL:(NSURL *)url {
    NSLog(@"didPickDocumentAtURL %@", url);
    
    BOOL canAccessingResource = [url startAccessingSecurityScopedResource];
    NSLog(@"canAccessingResource=%d", canAccessingResource);
    
    [self dismiss];
    
    self.pickedfile = [url path];
    self.pickedfile_notify();
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray <NSURL *>*)urls {
    NSLog(@"didPickDocumentAtURLs %@", urls);
    [self _documentPicker:controller didPickDocumentAtURL:urls[0]];
}

+(void)filePicker:(NSArray*)types callback:(void(^)(NSString*))callback
{
    [self present:^(TopShow* controller) {

        //似乎有个人还是不行, 先加回static试试? 还是不行,就算移动到app目录也不行, 奇奇怪怪???
        TopShow* filePickerCallback = controller;// [[TopShow alloc] init];
        
        //因为delegate是弱引用, 所以整个block保持他自己
        filePickerCallback.pickedfile_notify = ^(){
            callback(filePickerCallback.pickedfile);
        };
        
        //https://www.jianshu.com/p/d6fe1e7af9b6
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
