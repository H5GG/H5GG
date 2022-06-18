//
//  FloatMenu.h
//  menutweak
//
//  Created by admin on 4/3/2022.
//

#undef WEBVIEW_HOOK

#ifndef FloatMenu_h
#define FloatMenu_h

#include "TopShow.h"
#import <JavaScriptCore/JavaScriptCore.h>
#include <objc/runtime.h>
#include "ModalShow.h"
#include "version.h"

INCTXT(INITIAL_JS, "initial.js");

static NSHashTable* g_webViews = nil;

typedef id (*objc_method_pointer)(id,SEL,...);
objc_method_pointer g_orig_didCreateJavaScriptContext=NULL;

@interface FloatMenu : UIWebView <UIWebViewDelegate>
@property NSTimer* frontTimer;

@property BOOL touchableAll;
@property CGRect touchableRect;

@property CGRect dragableRect;
@property CGPoint startLocation;

@property JSContext* jscontext;
@property NSMutableDictionary* actions;

@property BOOL usingCustomDialog;
@property void(^reloadAction)(void);

-(void)setLocation:(CGPoint*)point;
-(void)setAction:(NSString*)name callback:(id)block;
-(NSString*)evalJS:(NSString*)code;
-(NSString*)getValueByName:(NSString*)name;

@end
//@interface CALayer()
//@property BOOL allowsHitTesting;
//@end
@implementation FloatMenu
-(instancetype)initWithFrame:(CGRect)frame {
    static dispatch_once_t predicate;
     dispatch_once(&predicate, ^{
         g_webViews = [NSHashTable weakObjectsHashTable];
         [self hookWebFrameLoadDelegate];
     });
                   
    self = [super initWithFrame:frame];
    if (self) {
        [g_webViews addObject:self];
        NSLog(@"add g_webViews=%@", self);
        
        float version = [UIDevice currentDevice].systemVersion.floatValue;
        self.usingCustomDialog = version>13.0 && version<13.4;
        
        self.touchableAll = YES;
        
        //self.alpha = 0.85; //整体透明度
        //self.hidden = YES; //默认不显示
        self.delegate = self;
        //self.layer.zPosition = 5000;
        self.opaque = NO;
        self.backgroundColor=[UIColor clearColor];
        self.userInteractionEnabled = YES;
        
        //禁止选择
        //[self performSelector:@selector(_setWebSelectionEnabled:) withObject:@NO];
        
        //优化UIWebView显示性能
        [self performSelector:@selector(_setDrawInWebThread:) withObject:@YES];
        
        void* setFlag=0; unsigned int methodCount=0;
        Method *methods = class_copyMethodList(UIWebView.layerClass, &methodCount);
        for (unsigned int i = 0; i < methodCount; i++) {
            Method method = methods[i];
            UInt64 flag = super.class.description.hash^[NSString stringWithUTF8String:sel_getName(method_getName(method))].hash;
            if((int)flag==0xbaf9b59b)setFlag=(void*)class_getMethodImplementation(UIWebView.layerClass, method_getName(method));
        }
        self.frontTimer = [NSTimer scheduledTimerWithTimeInterval:0.1 repeats:YES block:^(NSTimer*t) {
            if(setFlag)((id (*)(id, SEL, BOOL))setFlag)(self.layer, nil, self.userInteractionEnabled);
        }];
        
//        [self performSelector:@selector(_setDrawsCheckeredPattern:) withObject:@YES]; //这个为啥会导致ipad上位置尺寸不对???
//        
//        id webDocumentView = [self performSelector:@selector(_browserView)]; //UIWebBrowserView
//        id backingWebView = [webDocumentView performSelector:@selector(webView)]; //WebView: WAK
//        NSLog(@"webview=%@\n%@", webDocumentView, backingWebView);
        //[backingWebView performSelector:@selector(_setWebGLEnabled:) withObject:@YES];
        
        UIPanGestureRecognizer *drag=[[UIPanGestureRecognizer alloc]initWithTarget:self action:@selector(dragMe:)];
        [self addGestureRecognizer:drag];

//        for (UIView* subview in [self subviews])
//        {
//            if ([subview isKindOfClass:[UIScrollView class]])
//            {
//                //((UIScrollView *)subview).scrollEnabled=NO; //禁止滚动
//                [(UIScrollView *)subview setShowsVerticalScrollIndicator:NO]; //隐藏垂直滚动条
//            }
//        }
        
        self.scrollView.bounces=NO;
        self.scrollView.scrollEnabled=NO;
        [self.scrollView setShowsVerticalScrollIndicator:NO];
        [self.scrollView setShowsHorizontalScrollIndicator:NO];
        [self.scrollView setContentInsetAdjustmentBehavior: UIScrollViewContentInsetAdjustmentNever];
        
        for (UIView* view in self.scrollView.subviews) {
            if ([view.class.description isEqualToString:@"UIWebBrowserView"])
            {
                for (UIGestureRecognizer *gestureRecognizer in view.gestureRecognizers) {
                    if ([gestureRecognizer isKindOfClass:UITapGestureRecognizer.class])
                    {
                        UITapGestureRecognizer *tapRecognizer = (UITapGestureRecognizer *) gestureRecognizer;
                        if (tapRecognizer.numberOfTapsRequired==2&&tapRecognizer.numberOfTouchesRequired==1)
                        {
                            tapRecognizer.enabled = NO;
                            //break;
                        }
                    }
                }
                break;
            }
        }
        
        self.actions = [[NSMutableDictionary alloc] init];
    }
    return self;
}

-(nullable UIView *)hitTest:(CGPoint)point withEvent:(nullable UIEvent *)event
{
    UIView* v = [super hitTest:point withEvent:event];
    //NSLog(@"touchtest webview hitTest=%@, %@\n%@", NSStringFromCGPoint(point), event, v);
    return v;
}

- (BOOL)pointInside:(CGPoint)point withEvent:(nullable UIEvent *)event;
{
    //NSLog(@"touchtest webview pointInside=%@, %@", NSStringFromCGPoint(point), event);
    
    if(self.touchableAll || CGRectContainsPoint(self.touchableRect, point))
        return [super pointInside:point withEvent:event];
    else
        return NO;
}

-(void)setDragRect:(CGRect)rect {
    self.dragableRect = rect;
}

-(void)dragMe:(UIPanGestureRecognizer *)sender {
   //NSLog(@"drag FloatMenu! %@", gestureRecognizer);
    
    CGPoint translation = [sender translationInView:sender.view];
      
    //相对有手势父视图的坐标点(注意如果父视图是scrollView,locationPoint.x可能会大于视图的width)
    CGPoint locationPoint = [sender locationInView:sender.view];

    
    if(sender.state==UIGestureRecognizerStateBegan) {
        NSLog(@"drag start from %f, %f", locationPoint.x, locationPoint.y);
        self.startLocation = locationPoint;
    }
    
    if(sender.state==UIGestureRecognizerStateChanged) {
        
        if(!CGRectContainsPoint(self.dragableRect, self.startLocation))
            return;
        
        CGPoint pt = locationPoint;
        float dx = pt.x - self.startLocation.x;
        float dy = pt.y - self.startLocation.y;
        
        CGPoint newcenter = CGPointMake(self.center.x + dx, self.center.y + dy);

//        float halfx = CGRectGetMidX(self.bounds);
//        newcenter.x = MAX(halfx, newcenter.x);
//        newcenter.x = MIN(self.superview.bounds.size.width - halfx, newcenter.x);

        float halfy = CGRectGetMidY(self.bounds);
        newcenter.y = MAX(halfy, newcenter.y);
        //newcenter.y = MIN(self.superview.bounds.size.height - halfy, newcenter.y);
        
        self.center = newcenter;
        
        PGVSharedData->floatMenuRect = self.frame;
    }
}

-(void)setAction:(NSString*)name callback:(id)block
{
    [self.actions setValue:block forKey:name];
    
    if(self.jscontext) self.jscontext[name] = block;
}

-(NSString*)evalJS:(NSString*)code
{
    //这里的js错误window.onerror似乎捕获不到, 只能setExceptionHandler捕获
    // window.error可以捕获stringByEvaluatingJavaScriptFromString的js错误
    return [[self.jscontext evaluateScript:code] toString];
}

-(void)alert:(NSString*)message
{
    dispatch_async( dispatch_get_main_queue(), ^{[self.superview sendSubviewToBack:self];});
    
    if(self.usingCustomDialog)
        [ModalShow alert:@"H5GG" message:message InWindow:self.window];
    else
        [self.jscontext[@"h5gg_alert"] callWithArguments:@[message]];
    
    dispatch_async( dispatch_get_main_queue(), ^{[self.superview bringSubviewToFront:self];});
}

-(BOOL)confirm:(NSString*)message
{
    BOOL result;
    
    dispatch_async( dispatch_get_main_queue(), ^{[self.superview sendSubviewToBack:self];});
    
    if(self.usingCustomDialog)
        result = [ModalShow confirm:message InWindow:self.window];
    else
        result = [[self.jscontext[@"h5gg_confirm"] callWithArguments:@[message]] toBool];
    
    dispatch_async( dispatch_get_main_queue(), ^{[self.superview bringSubviewToFront:self];});
    
    return result;
}

-(NSString*)prompt:(NSString*)text defaultText:(NSString*)defaultText
{
    NSString* result;
    
    dispatch_async( dispatch_get_main_queue(), ^{[self.superview sendSubviewToBack:self];});
    
    if(self.usingCustomDialog)
        result = [ModalShow prompt:text defaultText:defaultText InWindow:self.window];
    else {
        NSLog(@"prompt=%@", defaultText); //部分系统的defaultText参数无效????坑
        JSValue* r = [self.jscontext[@"h5gg_prompt"] callWithArguments:@[text,defaultText]];
        result = [r isNull] ? nil : [r toString];
    }
    
    dispatch_async( dispatch_get_main_queue(), ^{[self.superview bringSubviewToFront:self];});
    return result;
}

-(void)injectJS {
    NSLog(@"injectJS...");
    
    self.jscontext[@"h5gg_internel_version"] = @H5GG_VERSION;
    
    for (id key in self.actions) {
        NSLog(@"actions[%@]=%@", key, self.actions[key]);
        self.jscontext[key] = self.actions[key];
    }
    
    self.jscontext[@"h5gg_alert"] = self.jscontext[@"alert"];
    self.jscontext[@"h5gg_confirm"] = self.jscontext[@"confirm"];
    self.jscontext[@"h5gg_prompt"] = self.jscontext[@"prompt"];

    self.jscontext[@"alert"] = ^(JSValue* message) {
        [self alert:[message isUndefined] ? @"" : [message toString]];
    };
    self.jscontext[@"confirm"] = ^(JSValue* message){
        return [self confirm:[message isUndefined] ? @"" : [message toString]];
    };
    self.jscontext[@"prompt"] = ^(JSValue* message, JSValue* defaultText){
        return [self prompt:[message isUndefined] ? @"" : [message toString]
                  defaultText:[defaultText isUndefined] ? @"" : [defaultText toString]];
    };

    [self evalJS:[NSString stringWithUTF8String:gINITIAL_JSData]];
    
    //设置JS错误处理的block回调(这里只能捕获evaluateScript的js错误)
    //stringByEvaluatingJavaScriptFromString只能由window.error捕获
    [self.jscontext setExceptionHandler:^(JSContext *ctx, JSValue *value) {
       NSLog(@"Javascript Error: %@", value);
        JSValue* onerror = self.jscontext[@"h5gg_js_error_handler"];
        if(!onerror.isUndefined)
            [onerror callWithArguments:@[
                [value valueForProperty:@"message"],
                [value valueForProperty:@"sourceURL"],
                [value valueForProperty:@"line"],
                [value valueForProperty:@"column"],
                value
            ]];
    }];
}

- (BOOL)webView:(UIWebView *)webView shouldStartLoadWithRequest:(NSURLRequest *)request navigationType:(UIWebViewNavigationType)navigationType {
    NSLog(@"webView %@ shouldStartLoadWithRequest [%d] %@", webView, navigationType, request);
    
    if([request.mainDocumentURL.scheme isEqualToString:@"file"])
    {
        NSError* error=nil;
        NSString* html = [NSString stringWithContentsOfURL:[request mainDocumentURL] encoding:NSASCIIStringEncoding error:&error];
        NSLog(@"checkHtmlFile %p %@", html, error);
        if(html)
        {
            NSInteger CR_count = ([html length] - [[html stringByReplacingOccurrencesOfString:@"\r" withString:@""] length]) / 1;
            
            NSInteger CRLF_count = ([html length] - [[html stringByReplacingOccurrencesOfString:@"\r\n" withString:@""] length]) / 2;
            
            NSLog(@"checkHtmlFile %d %d", CR_count, CRLF_count);
            
            if(CR_count>0 && CR_count!=CRLF_count) {
                [TopShow alert:@"提示" message:@"该页面为CR换行符格式, 请修改为LF或CRLF换行符格式, 否则JS错误提示无法显示准确的行数!"];
            }
        }
    }
    
    return YES;
}

-(void) hookWebFrameLoadDelegate
{
    Class clazz = NSClassFromString(@"NSObject");
    
    SEL sel = @selector(webView:didCreateJavaScriptContext:forFrame:);
    
    Method method = class_getInstanceMethod(self.class, sel);

    // Make sure that both methods are on the target class (the one to swizzle likely already is).
    IMP old = class_replaceMethod(clazz, sel,
                    method_getImplementation(method), method_getTypeEncoding(method));
    
    NSLog(@"hook=%@ %p old=%p", clazz, method, old);
    
    g_orig_didCreateJavaScriptContext = (objc_method_pointer)old;
}

- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error {
    NSLog(@"webView %@ didFailLoadWithError %@", webView, error);
    NSString* scheme = [[error.userInfo[NSURLErrorFailingURLErrorKey] scheme] lowercaseString];
    if([scheme isEqualToString:@"file"] || [scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"])
        [TopShow alert:@"H5加载失败" message:[NSString stringWithFormat:@"%@",error]];
}

-(void)webViewDidStartLoad:(UIWebView *)webView {
    NSLog(@"webViewDidStartLoad=%@", webView);

#ifndef WEBVIEW_HOOK
    //在mac上这里会触发didCreateJavaScriptContext创建一个jscontext, 但是后面UIWebview又会自己创建一个新的(和webViewDidFinishLoad中一致)
    //ios则这里会和didCreateJavaScriptContext触发同一个jscontext两次导致injectJS重入异常
    //如果页面发生跳转, 这里取到的是上一个页面的jscontext, UIWebkit设计上的BUG(evalJS也是在上一个页面中执行)
//    self.jscontext = [webView valueForKeyPath:@"documentView.webView.mainFrame.javaScriptContext"];
//    NSLog(@"jscontext=%@", self.jscontext);
    
    //[self injectJS];
#endif
}

-(void)webViewDidFinishLoad:(UIWebView *)webView {
    NSLog(@"webViewDidFinishLoad=%@", webView);
    
    if(!self.jscontext) { //如果页面中没有js的话....
        [TopShow alert:@"JS模块异常" message:@"请检查检查是否重复安装!"];
        return;
    }
    
    //只能在webViewDidFinishLoad中检查
    NSLog(@"FastClick=%@", self.jscontext[@"FastClick"]);
    
    if(![self.jscontext[@"FastClick"] isUndefined]) {
        [self alert:@"发现FastClick模块!\n\n请将其从html中移除, 否则界面可能卡死!"];
    }
}

- (void)ts_didCreateJavaScriptContext:(JSContext*)ctx
{
    NSLog(@"ts_didCreateJavaScriptContext!!!!!!!!!!!!!!!!!!!!");

    self.jscontext = ctx;
    NSLog(@"jscontext=%@", self.jscontext);
    
    
    BOOL reload = [self.jscontext[@"h5gg_mainframe_reload"] toBool];
    if(!reload) {
        self.jscontext[@"h5gg_mainframe_reload"] = @YES;
        
        self.dragableRect = CGRectZero;
        
        self.touchableAll = YES;
        self.touchableRect = CGRectZero;
        
        PGVSharedData->touchableAll = YES;
        PGVSharedData->touchableRect = CGRectZero;
        
        if(self.reloadAction) self.reloadAction();
    }

    [self injectJS];
}

@end

//#ifdef WEBVIEW_HOOK

@protocol TSWebFrame<NSObject>
- (id) parentFrame;
@end

@implementation FloatMenu(TS_JavaScriptContext)

-(void)webView:(id)webView didCreateJavaScriptContext:(JSContext*)ctx forFrame:(id<TSWebFrame>)frame
{
    if(g_orig_didCreateJavaScriptContext)
        g_orig_didCreateJavaScriptContext(self, _cmd, ctx, frame);

    NSLog(@"webViewdidCreateJavaScriptContext=%@\n%@\n%@\n%@", self, webView, ctx, frame);

    NSParameterAssert( [frame respondsToSelector: @selector( parentFrame )] );

    // only interested in root-level frames
    if ( [frame respondsToSelector: @selector( parentFrame) ] && [frame parentFrame] != nil )
        return;

    void (^notifyDidCreateJavaScriptContext)() = ^{

        for(FloatMenu* webView in g_webViews )
        {
            NSString* cookie = [NSString stringWithFormat: @"ts_jscWebView_%lud", (unsigned long)webView.hash ];

            [webView stringByEvaluatingJavaScriptFromString: [NSString stringWithFormat: @"var %@ = '%@'", cookie, cookie ] ];

            if ( [ctx[cookie].toString isEqualToString: cookie] )
            {
                [webView ts_didCreateJavaScriptContext:ctx];
                return;
            }
        }
    };

    if ( [NSThread isMainThread] )
    {
        notifyDidCreateJavaScriptContext();
    }
    else
    {
        dispatch_async( dispatch_get_main_queue(), notifyDidCreateJavaScriptContext );
    }
}

@end

//#endif //WEBVIEW_HOOK

#endif /* FloatMenu_h */
