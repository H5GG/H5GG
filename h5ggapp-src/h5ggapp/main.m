#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <objc/message.h>
#import "AppDelegate.h"

struct CTServerConnection *serverConnection=NULL;


int main(int argc, char * argv[]) {
    
    NSString * bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];
    
    // open handle
    void *CoreTelephonyHandle = dlopen("/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony", RTLD_LAZY);
    
    int (*_CTServerConnectionSetCellularUsagePolicy)(CFTypeRef, NSString *, NSDictionary *) = dlsym(CoreTelephonyHandle, "_CTServerConnectionSetCellularUsagePolicy");
    struct CTServerConnection * (*CTServerConnectionCreate)(CFAllocatorRef, void *, void *) = dlsym(CoreTelephonyHandle, "_CTServerConnectionCreate");
    serverConnection=CTServerConnectionCreate(kCFAllocatorDefault, NULL, NULL);
    _CTServerConnectionSetCellularUsagePolicy(serverConnection, bundleIdentifier, @{
        @"kCTCellularDataUsagePolicy" : @"kCTCellularDataUsagePolicyAlwaysAllow",
        @"kCTWiFiDataUsagePolicy" : @"kCTCellularDataUsagePolicyAlwaysAllow"
    });
    // close
    dlclose(CoreTelephonyHandle);
    
    NSString * appDelegateClassName;
    @autoreleasepool {
        // Setup code that might create autoreleased objects goes here.
        appDelegateClassName = NSStringFromClass([AppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
