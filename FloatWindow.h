//
//  FloatWindow.h
//  h5gg
//
//  Created by admin on 24/4/2022.
//

#ifndef FloatWindow_h
#define FloatWindow_h

@interface AppWinController : UIViewController
@property UIViewController* bindVC;
@end

@implementation AppWinController

-(instancetype)initWithBind:(UIViewController*)vc {
    self = [super init];
    if(self) {
        self.bindVC = vc;
    }
    return self;
}

- (id)forwardingTargetForSelector:(SEL)aSelector {
    NSLog(@"FloatWindow %@ %@", NSStringFromSelector(_cmd) ,NSStringFromSelector(aSelector));
    return self.bindVC;
}

- (BOOL)shouldAutorotate {
    if(!PGVSharedData->followCurrentOrientation)
        return self.bindVC.shouldAutorotate;
    return YES;
}

- (UIInterfaceOrientationMask)supportedInterfaceOrientations {
    if(!PGVSharedData->followCurrentOrientation)
        return self.bindVC.supportedInterfaceOrientations;
    return (UIInterfaceOrientationMask)(1<<PGVSharedData->curOrientation);
}

-(UIInterfaceOrientation)preferredInterfaceOrientationForPresentation
{
    if(!PGVSharedData->followCurrentOrientation)
        return self.bindVC.preferredInterfaceOrientationForPresentation;
    return (UIInterfaceOrientation)PGVSharedData->curOrientation;
}

@end

@interface FloatController : UIViewController
@property UIWindow* followWindow;
@property void (^onResizeCallback)(CGSize size);
@end

@implementation FloatController

-(instancetype)init {
    self = [super init];
    if(self) {
        self.followWindow = UIApplication.sharedApplication.keyWindow;
    }
    return self;
}

//如果不定义旋转相关委托函数, 并且屏幕锁定开关没有打开, 则UIAlertController会跟随陀螺仪旋转, 并且界面全部卡死
//主要是supportedInterfaceOrientations返回的支持方向集合, 如果原window不支持竖屏, 新window旋转为横屏, 则原window会卡死
//当前keyWindow是不受控制的, 即使没有makeKeyAndVisible, 也可能会成为keyWindow, 可能是windows发生变化时, 系统自动设置了

- (BOOL)shouldAutorotate { //ipad这没调用?
    BOOL should;
    if(PGVSharedData->enable && PGVSharedData->viewHosted && PGVSharedData->followCurrentOrientation)
        should = YES;
    else
        should = self.followWindow.rootViewController.shouldAutorotate;

    NSLog(@"FloatWindow shouldAutorotate=%d : %d,%d", should,
          [[UIDevice currentDevice] orientation],
          [UIApplication sharedApplication].statusBarOrientation);

    return should;
}

- (UIInterfaceOrientationMask)supportedInterfaceOrientations
{
    UIInterfaceOrientationMask mask;
    if(PGVSharedData->enable && PGVSharedData->viewHosted && PGVSharedData->followCurrentOrientation)
        mask = (UIInterfaceOrientationMask)(1<<PGVSharedData->curOrientation);
    else
        mask = self.followWindow.rootViewController.supportedInterfaceOrientations;

    NSLog(@"FloatWindow supportedInterfaceOrientations=%d : %d,%d", mask,
          [[UIDevice currentDevice] orientation],
          [UIApplication sharedApplication].statusBarOrientation);

    return mask;
}

-(UIInterfaceOrientation)preferredInterfaceOrientationForPresentation
{
    UIInterfaceOrientation prefedrred;
    if(PGVSharedData->enable && PGVSharedData->viewHosted && PGVSharedData->followCurrentOrientation)
        prefedrred = (UIInterfaceOrientation)PGVSharedData->curOrientation;
    else
        prefedrred = self.followWindow.rootViewController.preferredInterfaceOrientationForPresentation;

    NSLog(@"FloatWindow preferredInterfaceOrientationForPresentation=%d : %d,%d", prefedrred,
          [[UIDevice currentDevice] orientation],
          [UIApplication sharedApplication].statusBarOrientation);

    return prefedrred;
}

- (void)viewWillTransitionToSize:(CGSize)size withTransitionCoordinator:(id <UIViewControllerTransitionCoordinator>)coordinator
{
    [super viewWillTransitionToSize:size withTransitionCoordinator:coordinator];
    NSLog(@"FloatWindow=resize=%f,%f : %@", size.width, size.height, self.view);
    if(self.onResizeCallback) self.onResizeCallback(size);
}

@end



@interface FloatWindow : UIWindow
@end

@implementation FloatWindow
// recursively calls -pointInside:withEvent:. point is in the receiver's coordinate system
-(nullable UIView *)hitTest:(CGPoint)point withEvent:(nullable UIEvent *)event
{
    UIView* v = [super hitTest:point withEvent:event];
    //NSLog(@"touchtest floatwin hitTest=%@, %@\n%@", NSStringFromCGPoint(point), event, v);
    return v;
}
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
            return YES;
        }
    }
    return NO;
}

-(void)setHidden:(BOOL)hidden
{
    if(hidden==NO)
    {
        UIWindow* keyWindow = UIApplication.sharedApplication.keyWindow;
        NSLog(@"FloatWindow follow=%@", keyWindow);
        ((FloatController*)self.rootViewController).followWindow = keyWindow;
    }
    
    [super setHidden:hidden];
    
    NSLog(@"FloatWindow setHidden=%d", hidden);

    if(hidden==NO)
    {
        //移除vc自动创建的全屏view (ipad模式还会有多层superview(在window出来之后才会存在))
        UIView* superview = self.rootViewController.view;
        while(superview && ![superview isKindOfClass:UIWindow.class])
        {
            [superview setHidden:YES];
            superview = superview.superview;
        }
    }
}

@end


#endif /* FloatWindow_h */

