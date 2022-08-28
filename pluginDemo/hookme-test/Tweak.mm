//为了保持未来版本兼容性, 请勿使用JSContext
//To maintain compatibility with future versions, do not use JSContext
#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <JavaScriptCore/JavaScriptCore.h>
#import <UIKit/UIKit.h>

#pragma GCC diagnostic ignored "-Wunguarded-availability-new"

//定义JS函数接口
@protocol hookmeJSExport <JSExport>

JSExportAs(addInt, -(int)addInt:(int)n1 n2:(int)n2);
JSExportAs(addFloat, -(float)addFloat:(float)n1 n2:(float)n2);
JSExportAs(addDouble, -(double)addDouble:(double)n1 n2:(double)n2);
@end

//定义插件类
@interface hookme : NSObject <hookmeJSExport>
@end

//实现插件接口函数
@implementation hookme


-(int)addInt:(int)n1 n2:(int)n2
{
    return n1+n2;
}

-(float)addFloat:(float)n1 n2:(float)n2
{
    return n1+n2;
}

-(double)addDouble:(double)n1 n2:(double)n2
{
    return n1+n2;
}

@end