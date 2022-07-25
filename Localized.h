//
//  Localization.h
//  h5gg
//
//  Created by admin on 24/7/2022.
//

#ifndef Localization_h
#define Localization_h

NSDictionary* enLocalizedString = @{
    
@"请尝试修复当前APP联网权限" : @"try to fix the current APP network issues",
@"页面可能无法正确加载" : @"Pages may not load correctly",
@"网络异常" : @"Network Exception",
@"继续启动" : @"Continue Start",
@"悬浮模块加载失败" : @"Floating Show Load Failed",
@"请检查你的越狱基板是否安装并启用, 也可能被其他插件禁用或干扰!" : @"Please check if your jailbreak MobileSubstrate is installed and enabled, it may also be disabled or interfered by other tweaks!",

@"制作失败\n\n无法读取文件:\n%@" : @"Build Failed\n\ncannot read file:\n%@",
@"制作失败\n\n图标文件超过512KB" : @"Build Failed\n\nIcon file size more than 512KB",
@"制作失败\n\nH5文件超过2MB" : @"Build Failed\n\nHtml file size more than 2MB",
@"制作失败\n\n当前已经是定制版本, 请使用原版H5GG制作插件" : @"Build Failed\n\nthis already is custom dylib, please make by using original H5GG",
@"制作失败\n\n无法写入文件到%@\n\n%@" : @"Build Failed\n\ncannot write file to %@\n\n%@",
@"制作成功!\n\n专属H5GG.dylib已生成在当前App的Documents数据目录:\n%@" : @"Build Success!\n\nyour custom H5GG.dylib has been generated in the Documents Directory of the current App:\n%@",

@"该页面为CR换行符格式, 请修改为LF或CRLF换行符格式, 否则JS错误提示无法显示准确的行数!" : @"The page is in CR line break format, please modify it to LF or CRLF line break format, otherwise the JS error prompt cannot display the exact number of lines!",
@"H5加载失败" : @"Page Load Failed",
@"JS模块异常" : @"JS Module Exception",
@"请检查检查是否重复安装!" : @"Please check to see if the installation is repeated!",
@"发现FastClick模块!\n\n请将其从html中移除, 否则界面可能卡死!" : @"FastClick module found!\n\nPlease remove it from html, otherwise the interface may freeze!",

@"提示" : @"Alert",
@"确定" : @"OK",
@"取消" : @"Cancel",

@"当前H5GG版本过低" : @"The current H5GG version is too low",
@"浮点误差格式错误" : @"float number format error",
@"错误:内存不足!" : @"error:out of memory",
@"不支持的数值类型" : @"unsupport value type",
@"数值格式错误或与类型不匹配" : @"value formart error or does not match type",
@"数值搜索:参数有误" : @"SearchNumber:parameter error",
@"搜索范围需以0x开头十六进制数" : @"Memory search range must be a hexadecimal number and start with 0x",
@"内存搜索范围格式错误" : @"Memory search range formart error",
@"改善搜索失败: 当前列表为空, 请清除后再重新开始搜索" : @"SearchAgain Failed: current results list is empty, please do clear then start new search",
@"邻近搜索:参数有误" : @"NearbySearch Error:parameter error",
@"邻近范围需以0x开头十六进制数" : @"NearbyRange must be a hexadecimal number and start with 0x",
@"邻近范围格式错误" : @"NearbyRange formart error",
@"邻近范围只能在2~4096之间" : @"NearbyRange can only be between 2 and 4096",
@"邻近搜索错误: 当前列表为空, 请清除后再重新开始搜索" : @"NearbySearch Error: current results list is empty, please do clear then start new search",
@"读取失败:地址格式有误!" : @"getValue failed: address formart error!",
@"修改失败:地址格式有误!" : @"setValue failed: address formart error!",
@"修改全部: 结果列表为空!" : @"EditAll failed: resuls list is empty!",
@"\n\n你的设备未越狱, 你也可以将:\n悬浮按钮图标文件 H5Icon.png\n悬浮菜单H5文件  H5Menu.html\n打包进ipa中的.app目录中即可自动加载!" : @"\n\nYour device is not jailbroken, you can also put these files:\nFloating button icon file H5Icon.png\nFloating menu H5 file H5Menu.html\n into the .app directory in ipa to load it automatically!",


};

NSString* getLLCode()
{
    NSString *language = [NSLocale preferredLanguages][0];
    NSArray  *array = [language componentsSeparatedByString:@"-"];
    return array[0];
}

NSString* Localized(NSString* string)
{
    static NSString* llcode=getLLCode();
    
    if([llcode isEqualToString:@"zh"])
        return string;
    
    NSString* localized_string = enLocalizedString[string];
    assert(localized_string);
    return localized_string;
}


#endif /* Localization_h */
