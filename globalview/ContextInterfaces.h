#define __is__iOS9__ [[[UIDevice currentDevice] systemVersion] floatValue] >= 9.0

#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>

#import "headers.h"

@interface SBApplication (ContextHostManager)
@property NSString *bundleIdentifier;
@property NSString *displayIdentifier; //14系统没有这个?
@property NSString *displayName;
@end


@interface FBSceneLayerManager : NSObject
@property (nonatomic,readonly) NSOrderedSet * layers;                   //@synthesize layers=_layers - In the implementation block
@end

@interface FBSceneHostManager : NSObject
-(void)setDefaultBackgroundColorWhileHosting:(UIColor *)arg1 ;
-(void)setDefaultBackgroundColorWhileNotHosting:(UIColor *)arg1 ;
-(id)hostViewForRequester:(id)arg1 enableAndOrderFront:(BOOL)arg2 ;
-(void)enableHostingForRequester:(id)arg1 orderFront:(BOOL)arg2 ;
-(void)disableHostingForRequester:(id)arg1 ;
-(id)initWithLayerManager:(id)arg1 scene:(id)arg2 ;
- (void)enableHostingForRequester:(id)arg1 priority:(int)arg2;
@end

@interface _UIExternalSceneLayerHostView : UIView 
-(id)initWithSceneLayer:(id)arg1 parentScene:(id)arg2 ;
@end


@interface _UIContextLayerHostView : UIView
-(id)initWithSceneLayer:(id)arg1 ;
@property (assign,nonatomic) unsigned long long renderingMode;
@end

@interface SBSceneManager
-(id)allScenes;
-(id)sceneIdentityForApplication:(id)arg1;
-(id)scenesMatchingPredicate:(id)arg1 ;
@end


@interface FBSceneLayer
-(NSString *)externalSceneID;
@end

@interface FBSMutableSceneSettings
- (void)setBackgrounded:(bool)arg1; //设置为后台暂停状态
-(id)otherSettings;
@property (assign,getter=isForeground,nonatomic) BOOL foreground;
@end

@interface FBScene : NSObject
-(NSString *)identifier;
- (FBSceneHostManager *)hostManager;
- (id)mutableSettings;
-(void)updateSettings:(id)arg1 withTransitionContext:(id)arg2 completion:(/*^block*/id)arg3 ;
- (void)_applyMutableSettings:(id)arg1 withTransitionContext:(id)arg2 completion:(id)arg3;
-(void)updateSettings:(id)arg1 withTransitionContext:(id)arg2 ;
-(void)setMutableSettings:(FBSMutableSceneSettings *)arg1 ;
@end

@interface FBSceneManager
+(id)sharedInstance;
-(id)sceneWithIdentifier:(id)arg1 ;
-(id)fbsSceneWithIdentifier:(id)arg1 ;
-(void)_startLayerHostingForScene:(id)arg1 ;
-(void)_stopLayerHostingForScene:(id)arg1 ;
-(id)_rootWindowForRootDisplayIdentity:(id)arg1 createIfNecessary:(BOOL)arg2 ;
-(id)_rootWindowForDisplayConfiguration:(id)arg1 createIfNecessary:(BOOL)arg2 ;
@end


@interface FBWindowContextHostManager : NSObject
-(void)_updateHostViewFrameForRequester:(id)arg1 ;
- (void)enableHostingForRequester:(id)arg1 orderFront:(BOOL)arg2;
- (void)enableHostingForRequester:(id)arg1 priority:(int)arg2;
- (void)disableHostingForRequester:(id)arg1;
- (id)hostViewForRequester:(id)arg1 enableAndOrderFront:(BOOL)arg2;
@end

@interface FBWindowContextHostWrapperView
- (void)updateFrame;
@end

@interface FBWindowContextHostView : UIView
- (BOOL)isHosting;
@end



@interface UIApplication (Private)
-(long long)_frontMostAppOrientation;
-(id)_accessibilityFrontMostApplication;
- (void)_relaunchSpringBoardNow;
- (id)_accessibilityFrontMostApplication;
- (void)launchApplicationWithIdentifier: (NSString*)identifier suspended: (BOOL)suspended;
- (id)displayIdentifier;
- (void)setStatusBarHidden:(bool)arg1 animated:(bool)arg2;
void receivedStatusBarChange(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo);
void receivedLandscapeRotate();
void receivedPortraitRotate();
@end

@interface SBBannerContextView : UIView
@end

@interface SBAppSwitcherModel
+ (id)sharedInstance;
- (id)snapshotOfFlattenedArrayOfAppIdentifiersWhichIsOnlyTemporary;
@end

@interface SBAppSwitcherController : NSObject
- (id)_snapshotViewForDisplayItem:(id)arg1;
@end

@interface SBDisplayItem
+ (id)displayItemWithType:(NSString *)arg1 displayIdentifier:(id)arg2;
@end

@interface SBAppSwitcherSnapshotView : NSObject
-(void)_loadSnapshotSync;
@end

@interface _UIBackdropViewSettings : NSObject
+(id)settingsForStyle:(NSInteger)style graphicsQuality:(NSInteger)quality;
+(id)settingsForStyle:(NSInteger)style;
-(void)setDefaultValues;
-(id)initWithDefaultValues;
@end
@interface _UIBackdropViewSettingsCombiner : _UIBackdropViewSettings
@end
@interface _UIBackdropView : UIView
-(id)initWithFrame:(CGRect)frame autosizesToFitSuperview:(BOOL)autoresizes settings:(_UIBackdropViewSettings*)settings;
@end

@interface SBAppToAppWorkspaceTransaction
- (void)begin;
- (id)initWithAlertManager:(id)alertManager exitedApp:(id)app;
- (id)initWithAlertManager:(id)arg1 from:(id)arg2 to:(id)arg3 withResult:(id)arg4;
- (id)initWithTransitionRequest:(id)arg1;
@end

@interface FBWorkspaceEvent : NSObject
+ (instancetype)eventWithName:(NSString *)label handler:(id)handler;
@end

@interface FBWorkspaceEventQueue : NSObject
+ (instancetype)sharedInstance;
- (void)executeOrAppendEvent:(FBWorkspaceEvent *)event;
@end
@interface SBDeactivationSettings
-(id)init;
-(void)setFlag:(int)flag forDeactivationSetting:(unsigned)deactivationSetting;
@end
@interface SBWorkspaceApplicationTransitionContext : NSObject
@property(nonatomic) BOOL animationDisabled; // @synthesize animationDisabled=_animationDisabled;
- (void)setEntity:(id)arg1 forLayoutRole:(int)arg2;
@end
@interface SBWorkspaceDeactivatingEntity
@property(nonatomic) long long layoutRole; // @synthesize layoutRole=_layoutRole;
+ (id)entity;
@end
@interface SBWorkspaceHomeScreenEntity : NSObject
@end
@interface SBMainWorkspaceTransitionRequest : NSObject
- (id)initWithDisplay:(id)arg1;
@end

static int const UITapticEngineFeedbackPeek = 1001;
static int const UITapticEngineFeedbackPop = 1002;
@interface UITapticEngine : NSObject
- (void)actuateFeedback:(int)arg1;
- (void)endUsingFeedback:(int)arg1;
- (void)prepareUsingFeedback:(int)arg1;
@end
@interface UIDevice (Private)
-(UITapticEngine*)_tapticEngine;
@end

OBJC_EXTERN UIImage* _UICreateScreenUIImage(void) NS_RETURNS_RETAINED;
