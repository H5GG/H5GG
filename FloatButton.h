//
//  FloatButton.h
//  menutweak
//
//  Created by admin on 3/3/2022.
//

#ifndef FloatButton_h
#define FloatButton_h


#import <UIKit/UIKit.h>
 
@interface FloatButton : UIImageView
@property BOOL keepFront;
@property BOOL keepWindow;
@property NSTimer* frontTimer;
@property CGPoint startLocation;
@property void(^actionBlock)(void);

-(void)setIcon:(UIImage*)image;
-(void)setAction:(void(^)(void))block;
-(void)setLocation:(CGPoint*)point;
 
@end

@implementation FloatButton
 
-(instancetype)init {
    self = [super initWithFrame:CGRectMake(20, 25, 50, 50)];
    if (self) {
        
        self.clipsToBounds = YES;
        self.layer.cornerRadius = self.frame.size.width / 2;
        
        self.alpha = 0.8;
        self.layer.zPosition = MAXFLOAT;
        self.backgroundColor = [UIColor redColor];
        
        self.userInteractionEnabled = YES;
        
        self.keepFront = YES;
        self.keepWindow = NO;
        
        self.frontTimer = [NSTimer scheduledTimerWithTimeInterval:0.2 repeats:YES block:^(NSTimer*t){
            if(!self.hidden) {
                
                if(self.keepFront) [self.superview bringSubviewToFront:self];
                
                if(!self.keepWindow) {
                    UIWindow *window = [UIApplication sharedApplication].keyWindow;
                    if(self.superview != window) [window addSubview:self];
                }
                
                CGRect newFrame = self.superview.frame;
                static CGRect lastFrame = newFrame;
                if(!CGRectEqualToRect(lastFrame, self.superview.frame)) {
                    
                    float newX = newFrame.size.width * self.frame.origin.x/lastFrame.size.width;
                    float newY = newFrame.size.height * self.frame.origin.y/lastFrame.size.height;

                    if(newX<0) newX=0;
                    if((newX+self.frame.size.width) > newFrame.size.width)
                        newX = newFrame.size.width - self.frame.size.width;
                    
                    if(newY<0) newY=0;
                    if((newY+self.frame.size.height) > newFrame.size.height)
                        newY = newFrame.size.height - self.frame.size.height;

                    self.frame = CGRectMake(newX, newY, self.frame.size.width, self.frame.size.height);
                    
                    lastFrame = newFrame;
                }
            }
        }];
        
        UITapGestureRecognizer *tap=[[UITapGestureRecognizer alloc]initWithTarget:self action:@selector(tapMe)];
        [self addGestureRecognizer:tap];
    }
    return self;
}
 
-(void)touchesBegan:(NSSet*)touches withEvent:(UIEvent*)event {
    CGPoint pt = [[touches anyObject] locationInView:self];
    self.startLocation = pt;
    [[self superview] bringSubviewToFront:self];
}
 
-(void)touchesMoved:(NSSet*)touches withEvent:(UIEvent*)event {
    CGPoint pt = [[touches anyObject] locationInView:self];
    float dx = pt.x - self.startLocation.x;
    float dy = pt.y - self.startLocation.y;
    CGPoint newcenter = CGPointMake(self.center.x + dx, self.center.y + dy);
    //
    float halfx = CGRectGetMidX(self.bounds);
    newcenter.x = MAX(halfx, newcenter.x);
    newcenter.x = MIN(self.superview.bounds.size.width - halfx, newcenter.x);
    //
    float halfy = CGRectGetMidY(self.bounds);
    newcenter.y = MAX(halfy, newcenter.y);
    newcenter.y = MIN(self.superview.bounds.size.height - halfy, newcenter.y);
    //
    self.center = newcenter;
}
 
-(void)touchesEnded:(NSSet *)touches withEvent:(UIEvent *)event {
//    CGPoint point = self.center;
//    if (point.x>[self superview].width/2.0) {
//        [UIView animateWithDuration:0.2 animations:^{
//            self.x = [self superview].width-self.width;
//        }];
//    }else{
//        [UIView animateWithDuration:0.2 animations:^{
//            self.x = 0;
//        }];
//    }
}
 
-(void)touchesCancelled:(NSSet *)touches withEvent:(UIEvent *)event {
}
 
-(void)tapMe {
    NSLog(@"click FloatButton!");
    if(self.actionBlock){ _actionBlock(); }
}
 

-(void)setAction:(void (^)(void))block {
    self.actionBlock = block;
}

-(void)setIcon:(UIImage *)image {
    self.image = image;
    self.backgroundColor = [UIColor clearColor];
}
 
@end

#endif /* FloatButton_h */
