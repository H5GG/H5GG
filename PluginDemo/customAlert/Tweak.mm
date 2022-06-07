#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <JavaScriptCore/JavaScriptCore.h>
#import <UIKit/UIKit.h>

#pragma GCC diagnostic ignored "-Wunguarded-availability-new"

//定义JS函数接口
@protocol MyJSExport <JSExport>

-(void)alert0; //无参数直接定义
-(void)alert1:(NSString*)msg; //一个参数直接定义
JSExportAs(alert2, -(void)alert2:(NSString*)title msg:(NSString*)msg); //超过一个参数用JSExportAs定义
JSExportAs(choice, -(void)choice:(NSArray*)items callback:(JSValue*)jsfunc); //超过一个参数用JSExportAs定义

@end

//定义插件类
@interface MyAlert : NSObject <MyJSExport>
@property UIWindow* myWindow;
@property JSValue* jscallback;
@property NSThread* jsthread;
@end

//实现插件接口函数
@implementation MyAlert

-(instancetype)init {
    if (self = [super init])
    {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (NSClassFromString(@"UIWindowScene")) {
                UIWindowScene* theScene=nil;
                for (UIWindowScene* windowScene in [UIApplication sharedApplication].connectedScenes) {
                    if(!theScene && windowScene.activationState==UISceneActivationStateForegroundInactive)
                        theScene = windowScene;
                    if (windowScene.activationState == UISceneActivationStateForegroundActive) {
                        theScene = windowScene;
                        break;
                    }
                }
                self.myWindow = [[UIWindow alloc] initWithWindowScene:theScene];
            }else{
                self.myWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
            }

            self.myWindow.windowLevel = UIWindowLevelAlert;
            self.myWindow.rootViewController = [[UIViewController alloc] init];
        });
    }
    return self;
}

-(void)threadcall:(void(^)())block {
    block();
}

-(void)choice:(NSArray*)items callback:(JSValue*)jsfunc
{
    self.jscallback = jsfunc;
    self.jsthread = NSThread.currentThread;

    //通过主线程执行下面的代码
    dispatch_async(dispatch_get_main_queue(), ^{

       UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"提示" message:@"请选择" preferredStyle:UIAlertControllerStyleAlert];
        
        for(NSString* item in items)
        {
            [alert addAction:[UIAlertAction actionWithTitle:item style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                [self.myWindow setHidden:YES];
                [self performSelector:@selector(threadcall:) onThread:self.jsthread withObject:^{
                    [self.jscallback callWithArguments:@[item]];
                } waitUntilDone:NO];
            }]];
        }

        [self.myWindow setHidden:NO];
       [[self.myWindow rootViewController] presentViewController:alert animated:YES completion:nil];
        
    });
}

-(void)alert0
{
    //通过主线程执行下面的代码
    dispatch_async(dispatch_get_main_queue(), ^{

       UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"提示" message:@"来自OC的问候" preferredStyle:UIAlertControllerStyleAlert];

       [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                [self.myWindow setHidden:YES];
        }]];

        [self.myWindow setHidden:NO];
       [[self.myWindow rootViewController] presentViewController:alert animated:YES completion:nil];
        
    });
}

-(void)alert1:(NSString*)msg
{
    //通过主线程执行下面的代码
    dispatch_async(dispatch_get_main_queue(), ^{

       UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"提示" message:msg preferredStyle:UIAlertControllerStyleAlert];

       [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                [self.myWindow setHidden:YES];
        }]];

        [self.myWindow setHidden:NO];
       [[self.myWindow rootViewController] presentViewController:alert animated:YES completion:nil];
        
    });
}

-(void)alert2:(NSString*)title msg:(NSString*)msg
{
    //通过主线程执行下面的代码
    dispatch_async(dispatch_get_main_queue(), ^{

       UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];

       [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                [self.myWindow setHidden:YES];
        }]];

        [self.myWindow setHidden:NO];
       [[self.myWindow rootViewController] presentViewController:alert animated:YES completion:nil];
        
    });
}

@end

    