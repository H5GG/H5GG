h5gg.require(7.7); //设定最低需求的H5GG版本号

//将h5frida-15.1.24.dylib放到.app目录中
var h5frida=h5gg.loadPlugin("h5frida","h5frida-15.1.24.dylib");
if(!h5frida) throw "加载h5frida插件失败";

//免越狱:将frida-gadget的dylib和config两个文件放到.app目录中, 不支持Interceptor功能
if(!h5frida.loadGadget("frida-gadget-15.1.24.dylib"))
    throw "加载frida-gadget守护模块失败, 请先安装frida核心免越狱dylib动态库";

var pid = -1;  //pid=-1, 使用自身进程

alert("h5frida插件版本="+h5frida.pluginVersion() + "\nfrida引擎版本="+h5frida.coreVersion());
/*
 这里如果frida-gadget刚加载还没初始化完毕可能无法获取到进程列表
 等上面的弹框关闭后再获取进程列表时机就差不多了
 也可以将frida-gadget静态注入app主模块启动时自动加载
 */
var procs = h5frida.enumerate_processes();
if(!procs || !procs.length) throw "frida无法获取进程列表";

var found = false;
for(var i=0;i<procs.length;i++) {
    if(procs[i].pid==pid) {
        if(procs[i].name!='Gadget') throw "免越狱测试请卸载frida越狱deb";
        found = true;
    }
}

if(!pid) throw "frida无法找到目标进程";

var session = h5frida.attach(pid);
if(!session) throw "frida附加进程失败";

//监听frida目标进程连接状态, 比如异常退出
session.on("detached", function(reason) {
    alert("frida目标进程会话已终止: "+reason);
});

var frida_script_code = "("+frida_script.toString()+")()"; //将frida脚本转换成字符串
var script = session.create_script(frida_script_code); //注入frida的js脚本代码

if(!script) throw "frida注入脚本失败";

//启动脚本前先设置frida脚本消息接收函数
//不要在frida脚本里发太多高频消息过来让h5gg弹出alert
//消息太多让alert阻塞在后台内存会爆导致闪退崩溃
script.on('message', function(msg) {
    if(msg.type=='error')
    {
        script.unload(); //如果脚本发生错误就停止frida脚本
        alert("frida脚本错误:\n"+JSON.stringify(msg));
    }
    
    if(msg.type=='send')
        alert("frida脚本消息:\n"+JSON.stringify(msg.payload));
    if(msg.type=='log')
        alert("frida脚本日志:\n"+msg.payload);
});

script.load(); //启动脚本

//获取frida脚本中的rpc.exports导出函数列表
alert("frida脚本导出函数列表:\n" + script.list_exports());

alert("HOOK拦截OC函数:\n" + script.call("hook_objc"));

alert("测试HOOK拦截效果, 开始主动调用触发");

var result1 = script.call("testcall_objc", ["https://ipapi.co/ip"]);
setTimeout(function(){
    alert("测试调用OC函数:\n" + result1);
    
    //OC调用测试完之后再测试C/C++调用
    alert("HOOK拦截C/C++函数:\n" + script.call("hook_cxx"));
    
    alert("测试HOOK拦截效果, 开始主动调用触发");

    var result2 = script.call("testcall_cxx", ["testfile.txt"]);
    setTimeout(function(){ alert("测试调用C/C++函数:\n" + result2);}, 200);
    
}, 200);


//script.unload(); //卸载脚本

//session.detach(); //断开目标进程

/***************************************************************/

//frida的js脚本代码, 运行在目标进程, 不能在h5gg中直接调用这个js函数
//frida的js脚本代码中不能使用任何h5gg的函数和变量, 也不能使用window对象
//h5gg和frida只能通过console.log和send/recv/post还有rpc.exports进行通信
function frida_script()
{
    //发送frida脚本的日志消息给h5gg
    console.log("frida脚本开始运行...");

    //HOOK拦截dylib模块中的C/C++导出函数, 非模块导出函数不能hook
    rpc.exports.hook_cxx=function()
    {
        //获取.app路径
        var app_path = ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
        //加载fishhook插件, 需要将fishhook.dylib放到.app目录中
        var fishhookModule = Module.load(app_path+"/fishhook.dylib");
        //获取fishhook导出函数: fishhook(指定模块地址, 函数名称, 新函数地址) 返回原始函数地址, 模块地址=0代表HOOK所有模块
        var fishhookExport = fishhookModule.getExportByName("fishhook");
        //转换成js函数对象
        var fishhookFunction = new NativeFunction(fishhookExport, "pointer", ["pointer", "pointer", "pointer"]);
        
        global.fishhook = function(functionName, returnType, argTypes, callback) {
            
            //NativeCallback不能被释放所以存到callback的属性中(务必)
            callback.NativeCallback = new NativeCallback(callback, returnType, argTypes);
            
            var oldFunctionAddr = fishhookFunction(ptr(0), Memory.allocUtf8String(functionName), callback.NativeCallback);
            
            if(!oldFunctionAddr || oldFunctionAddr.isNull())
                throw "fishhookError:"+functionName;
            
            if(!global["dlsym_init"])
            {
                global["dlsym_init"] = true;
                global["dlsym_hook"] = {};
                
                //拦截动态调用目标函数
                var dlsym = fishhook("dlsym", "pointer", ["pointer", "pointer"], function(handle, symbol) {
                    var addr = dlsym(handle, symbol);
                    //send(["dlsym", handle, symbol.readUtf8String(), addr, global["dlsym_hook"][addr]]);

                    if(global["dlsym_hook"][addr]) {
                        //send(["dlsym attach", handle, symbol.readUtf8String(), addr, global["dlsym_hook"][addr]]);
                        addr = global["dlsym_hook"][addr];
                    }

                    return addr;
                });
            }
            
            global["dlsym_hook"][oldFunctionAddr] = callback.NativeCallback;
            
            //将原始函数转换成js函数对象
            return new NativeFunction(oldFunctionAddr, returnType, argTypes);
        }
        
        /*******************************************************/
        //HOOK所有静态引入和后续动态获取的fopen调用
        var fopen = fishhook("fopen", //要HOOK的C/C++导出函数名称
                 "pointer", //要HOOK的C/C++导出函数返回值类型
                 ["pointer", "pointer"], //要HOOK的C/C++导出函数参数类型列表
                 function(path, mode) //HOOK之后的js处理函数
                 {
                    //通知h5gg
                    if(mode.readUtf8String()=="wb")
                    send(["拦截到fopen调用", path.readUtf8String(), mode.readUtf8String()]);

                    //调用原始函数并返回值
                    return fopen(path, mode);
                }
        );
        
        return "成功hook拦截fopen函数, 如有被调用会有通知!";
    };
   
    //HOOK拦截任意Objective-C类的方法函数
    rpc.exports.hook_objc = function()
    {
        if(ObjC.available)
        {
            var objc_Class = ObjC.classes["NSURL"]; //获取OC类
            var objc_Method = objc_Class["+ URLWithString:"]; //获取OC方法
            
            var oldMethod = objc_Method.implementation; //备份原始方法
            
            //替换方法(HOOK)
            objc_Method.implementation = ObjC.implement(objc_Method, function(self, SEL, url) {
                //第一个参数是self, 第二个是selector, 后面是OC方法参数
                
                var urlString = ObjC.Object(url); //将OC对象参数转换为js对象
                /* 如果是免越狱自身进程测试, 则alert弹出的文本中若果有网址,
                 系统UILabel会自动调用URLWithString创建NSURL对象导致死循环,
                 所以这里把网址格式打乱再发给h5gg弹出显示 */
                console.log("拦截到网址访问:\n" + urlString.toString().split("").join(" "));
                //send("callstack:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
                
                //替换参数, 确保当前APP开启了HTTP明文网络权限
                //url = ObjC.classes.NSString.stringWithString_("http://ip-api.com/json?fields=query");
                
                return oldMethod(self, SEL, url); //调用原始方法;
            });
        }
        
        return "成功hook拦截NSURL的URLWithString方法, 如有被调用会有通知!";
    };
    
    rpc.exports.testcall_objc = function(url) {
        
        //[NSURL URLWithString:url];
        var nsurl = ObjC.classes.NSURL.URLWithString_(url);

        var NSASCIIStringEncoding=1;
        var error = Memory.alloc(8);
        
        //[NSString stringWithContentsOfURL:nsurl encoding:NSASCIIStringEncoding error:&error];
        var content = ObjC.classes.NSString.stringWithContentsOfURL_encoding_error_(nsurl, NSASCIIStringEncoding, error);
        if(!content || content.isNull())  return "获取本机IP失败";
        
        return "本机IP="+content.toString();
    }
    
    rpc.exports.testcall_cxx = function(filename) {
        var NSHomeDirectory = new NativeFunction(ptr(Module.findExportByName("Foundation","NSHomeDirectory")),'pointer',[]);
        var path = ObjC.Object(NSHomeDirectory()).toString() + "/Documents/" + filename;
        
        var fopen = new NativeFunction(Module.findExportByName(null, "fopen"), "pointer", ["pointer","pointer"]);
        var fputs = new NativeFunction(Module.findExportByName(null, "fputs"), "int", ["pointer","pointer"]);
        var fclose = new NativeFunction(Module.findExportByName(null, "fclose"), "int", ["pointer"]);
        
        var fp = fopen(Memory.allocUtf8String(path), Memory.allocUtf8String("wb"));
        if(fp.isNull()) return "打开文件失败";
        
        fputs(Memory.allocUtf8String("frida"), fp);
        
        fclose(fp);
        
        return "成功写入文件: " + path;
    }

    //执行到这里之后script.load()才会返回
}

/***************************************************************/
