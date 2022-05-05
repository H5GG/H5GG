//
//  headers.h
//  PullOverPro
//
//  Created by Will Smillie on 4/8/19.
//

@interface UIDevice (mh)
-(void)setOrientation:(long long)arg1 animated:(BOOL)arg2 ;
@end

@interface SpringBoard
-(id)_accessibilityFrontMostApplication;
-(void)_relaunchSpringBoardNow;
-(BOOL)isLocked;
-(long long)activeInterfaceOrientation;
-(long long)_currentNonFlatDeviceOrientation;
-(void)_returnToHomescreenWithCompletion:(/*^block*/id)arg1 ;
@end

@interface UIApplication (MHXI)
-(void)_setForcedUserInterfaceLayoutDirection:(long long)arg1 ;
+(id)sharedApplication;
- (id)_mainScene;
+(NSString *)displayIdentifier;
-(void) RA_updateWindowsForSizeChange:(CGSize)size isReverting:(BOOL)revert;
-(void) RA_forceRotationToInterfaceOrientation:(UIInterfaceOrientation)orientation isReverting:(BOOL)reverting;
-(BOOL)_isSupportedOrientation:(long long)arg1 ;
-(void)noteActiveInterfaceOrientationWillChangeToOrientation:(long long)arg1 ;
-(void)_setStatusBarOrientation:(long long)arg1 animated:(BOOL)arg2 ;
-(void)_setStatusBarOrientation:(long long)arg1 animated:(BOOL)arg2 ;
-(id)statusBarWindow;
-(void)terminateWithSuccess;
@end


@interface SBUIController : NSObject
-(BOOL)isAppSwitcherShowing;
@end

@interface SBApplicationIcon : NSObject
-(id)initWithApplication:(id)arg1 ;
-(id)generateIconImage:(int)arg1;
-(void)setBadge:(id)arg1;
-(id)generateIconImage:(int)arg1 ;
@end

//@interface SBIcon (undocumented)
//@property (nonatomic, retain) NSString* applicationBundleID;
//-(NSString*)displayNameForLocation:(NSInteger)location;
//-(UIImage*)generateIconImage:(int)arg1;
//@end
@interface SBApplication
@property NSString *bundleIdentifier;
@property NSString *displayIdentifier;
@property NSString *displayName;
- (id)mainScene;
@end

@interface SBApplicationController
+ (id)sharedInstance;
- (id)applicationWithBundleIdentifier:(NSString *)bid;
- (SBApplication *)applicationWithDisplayIdentifier:(NSString *)identifier;
@end

@interface SBMainSwitcherViewController : NSObject
+(id)sharedInstance;
-(id)appLayouts;
@end



@interface SBAlertItem : NSObject
@end
@interface SBUserNotificationAlert : SBAlertItem
-(int)token;
- (void)setAlertHeader:(NSString *)header;
- (void)setAlertMessage:(NSString *)msg;
- (void)setDefaultButtonTitle:(NSString *)title;
- (void)setAlternateButtonTitle:(NSString *)title;
@end
@interface SBAlertItemsController : NSObject
+ (id)sharedInstance;
- (void)activateAlertItem:(SBAlertItem *)item;
@end

@interface SBFluidSwitcherGestureManager
-(void)grabberTongueBeganPulling:(id)arg1 withDistance:(double)arg2 andVelocity:(double)arg3 ;
-(void)grabberTongueCanceledPulling:(id)arg1 withDistance:(double)arg2 andVelocity:(double)arg3 ;
@end

@interface SBLockStateAggregator : NSObject
+(id)sharedInstance;
-(unsigned long long)lockState;
@end


typedef struct SBIconImageInfo {
    CGSize size;
    double scale;
    double continuousCornerRadius;
} SBIconImageInfo;

@interface SBIcon : NSObject
@property (nonatomic, retain) NSString* applicationBundleID;
-(NSString*)displayNameForLocation:(NSInteger)location;
-(UIImage*)generateIconImage:(int)arg1;
-(id)generateIconImageWithInfo:(SBIconImageInfo)arg1 ;
@end
@interface SBIconView : UIView
@property (nonatomic, retain) SBIcon* icon;
@end
@interface SBIconModel : NSObject
-(id)expectedIconForDisplayIdentifier:(NSString*)ident;
@end
@interface SBRootFolderController : NSObject
@property (nonatomic, retain) UIView* contentView;
@end
@interface SBIconController : NSObject
+(id)sharedInstance;
@property (nonatomic, retain) SBIconModel* model;
@property (nonatomic, assign) BOOL isEditing;
-(UIView*)currentRootIconList;
-(UIView*)dockListView;
-(SBRootFolderController*)_rootFolderController;
-(SBRootFolderController*)_currentFolderController;
-(void)clearHighlightedIcon;
-(NSInteger)currentIconListIndex;
-(void)removeIcon:(id)arg1 compactFolder:(BOOL)arg2;
-(id)insertIcon:(id)arg1 intoListView:(id)arg2 iconIndex:(long long)arg3 moveNow:(BOOL)arg4 pop:(BOOL)arg5;
-(id)rootFolder;
-(UIView*)iconListViewAtIndex:(NSInteger)index inFolder:(id)folder createIfNecessary:(BOOL)create;
-(BOOL)scrollToIconListAtIndex:(long long)arg1 animate:(BOOL)arg2;
-(NSArray*)allApplications;
-(BOOL)_canRevealShortcutMenu;
-(void)_revealMenuForIconView:(SBIconView*)icon presentImmediately:(BOOL)immediately;
-(void)_dismissShortcutMenuAnimated:(BOOL)animated completionHandler:(id)completionHandler;
@end

@interface SBHomeScreenViewController : UIViewController
@end
