//
//  ModalShow.h
//  h5gg
//
//  Created by admin on 21/3/2022.
//

#ifndef ModalShow_h
#define ModalShow_h

#include <objc/runtime.h>

#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wobjc-protocol-method-implementation"
#pragma GCC diagnostic ignored "-Wnullability-completeness"

@interface ModalShow : NSObject
+(void)alert:(NSString*)title message:(NSString*)message;
+(BOOL)confirm:(NSString*)message;
+(NSString*)prompt:(NSString*)text defaultText:(NSString*)defaultText;
@end

@implementation ModalShow

static dispatch_semaphore_t semaphore;

extern "C"  {
    NSRunLoop* WebThreadNSRunLoop(void);
    void* objc_autoreleasePoolPush();
    void WebThreadUnlock(void);
    void WebThreadLockPopModal(void);
    
    void (*WebThreadUnlockFromAnyThread)(void);
}

+(void)present:(UIViewController*(^)(void))alert InWindow:(UIWindow*)window {
    
    NSLog(@"ModalShow present[%d] %@", [NSThread isMainThread], [NSThread currentThread].name);
    
    semaphore = dispatch_semaphore_create(0);
    
    void(^submit)() = ^{
        NSLog(@"ModalShow running[%d] %@", [NSThread isMainThread], [NSThread currentThread].name);
        [window.rootViewController presentViewController:alert() animated:YES completion:nil];
    };
    
    //NSLog(@"env=%@ %d",  [UIDevice currentDevice].systemVersion, [NSProcessInfo processInfo].isMacCatalystApp);
    
    if([NSThread isMainThread])
    {
        submit();
        while(dispatch_semaphore_wait(semaphore, DISPATCH_TIME_NOW))
            [[NSRunLoop currentRunLoop] runMode:[[NSRunLoop currentRunLoop] currentMode] beforeDate:[NSDate distantFuture]];
    } else {
        dispatch_async(dispatch_get_main_queue(), submit);
        
        *(void**)&WebThreadUnlockFromAnyThread = dlsym(RTLD_DEFAULT, "WebThreadUnlockFromAnyThread");
        
        if([[NSThread currentThread].name isEqualToString:@"WebThread"])
            WebThreadUnlockFromAnyThread();
        
        dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    }

    NSLog(@"ModalShow dismiss!");
}

+(void)dismiss {
    dispatch_semaphore_signal(semaphore);
}

+(void)alert:(NSString*)title message:(NSString*)message InWindow:(UIWindow*)window
{
    [self present:^() {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];

        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            [self dismiss];
        }]];
        
        return alert;
    }  InWindow:window ];
}

+(BOOL)confirm:(NSString*)message InWindow:(UIWindow*)window
{
    __block BOOL result = NO;
    
    [self present:^() {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"提示" message:message preferredStyle:UIAlertControllerStyleAlert];

        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            result = YES;
            [self dismiss];
        }]];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
            result = NO;
            [self dismiss];
        }]];
    
        return alert;
    }  InWindow:window ];
    
    return result;
}

+(NSString*)prompt:(NSString*)text defaultText:(NSString*)defaultText InWindow:(UIWindow*)window {
    __block NSString* result;
    
    [self present:^() {
        
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:nil message:text preferredStyle:UIAlertControllerStyleAlert];
        
        [alert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
            textField.text = defaultText;
        }];

        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            result = alert.textFields.lastObject.text;
            [self dismiss];
        }]];
    
        return alert;
    } InWindow:window ];
    
    return result;
}

@end


#endif /* ModalShow_h */
