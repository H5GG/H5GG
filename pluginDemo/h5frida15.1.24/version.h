
#define H5FRIDA_PLUGIN_VERSION  2.0

#define FRIDA_CORE_VERSION  "15.1.24"

/*
h5frida-v1.2 发布:
1: 支持调用任意OC/C/C++函数(免越狱)
3: 支持HOOK进程任意OC函数(免越狱)
4: 支持HOOK任何模块导出的C/C++函数(免越狱)
5: 支持HOOK任意地址的C/C++函数(需要越狱)

h5frida-v1.3:
 1: 修复h5frida崩溃闪退的BUG
 
h5frida-v1.4:
 1: frida-gadget修改为由h5frida加载
 2: inline-hook支持免越狱拦截app的模块任意地址函数/指令
 
h5grida-v1.5:
 1: 优化免越狱inline-hook流程
 2: 免越狱inline-hook增加砸壳判断
 
h5frida-v1.6:
 1: 修复目标进程断开后可能无法再次附加的BUG
 2: 新增免越狱动态修改基址的功能, 可动态开关
 
h5frida-v1.7:
 1: 修复免越狱inline-hook崩溃问题
 
h5frida-v2.0:
 1: 合并多个dll和内置初始js
 2: 优化frida脚本js错误提示准确行数
 3: 简化免越狱动态代码补丁流程
 4: 加载gadget自动等待初始化完毕
 5: 修复页面刷新后重载frida脚本失败的问题
 
*/

