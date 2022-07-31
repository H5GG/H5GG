h5gg.require(7.8); //设定最低需求的H5GG版本号//min version support for H5GG

//将h5frida-15.1.24.dylib放到.app目录中
//put h5frida-15.1.24.dylib into .app folder
var h5frida=h5gg.loadPlugin("h5frida", "h5frida-15.1.24.dylib");
if(!h5frida) throw "加载h5frida插件失败\n\nFailed to load h5frida plugin";

//优先调用集成的frida核心, 将frida-gadget的dylib和config两个文件放到.app目录中
if(!h5frida.loadGadget("frida-gadget-15.1.24.dylib"))
    throw "加载frida-gadget守护模块失败\n\nFailed to load frida-gadget daemon module";
    
alert("h5frida插件版本="+h5frida.pluginVersion()
          + "\nfrida引擎版本="+h5frida.coreVersion()+"\n\n"
          +"frida plugin version="+h5frida.pluginVersion()
          + "\nfrida core version="+h5frida.coreVersion());

/*
 这里如果frida-gadget刚加载还没初始化完毕可能无法获取到进程列表
 所以上面加了一个alert弹框延, 给frida-gadget一点初始化时间
 第二种方式是将frida-gadget注入ipa自动随app自动加载
 
 Here, if frida-gadget has just been loaded and has not been initialized, the process list may not be obtained. So an alert pop-up delay is added to the above, giving frida-gadget a little initialization timeIt's almost time to get the process list after the above alert pop-up-box is closed. The second way is to inject frida-gadget into ipa to automatically load with the app.
 */
    
var procs = h5frida.enumerate_processes();
if(!procs || !procs.length) throw "frida无法获取进程列表\n\nfrida can't get process list";

var pid = -1;
//pid=-1, 使用自身进程来调用OC/C/C++函数, 也可以附加到其他APP进程来调用
//Use its own process to call OC/C/C++ functions, or attach to other APP processes to call

var found = false;
for(var i=0;i<procs.length;i++) {
    if(procs[i].pid==pid) {
        if(procs[i].name!='Gadget') throw "免越狱测试请卸载frida-server的deb然后重启当前APP\nFor non-jailbreak tests, please uninstall the frida-server deb and restart the current APP";
        found = true;
    }
}

if(!found) throw "frida无法找到目标进程\n\nfrida cannot find the target process";

var session = h5frida.attach(pid);
if(!session) throw "frida附加进程失败\n\nfrida attach process failed";

//监听frida目标进程连接状态, 比如异常退出
session.on("detached", function(reason) {
    alert("frida目标进程会话已终止(frida target process session terminated):\n"+reason);
});

var frida_script_code = "("+frida_script.toString()+")()"; //将frida脚本转换成字符串
var script = session.create_script(frida_script_code); //注入frida的js脚本代码

if(!script) throw "frida注入脚本失败\n\nfrida inject script failed!";

/*启动脚本前先设置frida脚本消息接收函数
不要在frida脚本里发太多高频消息过来让h5gg弹出alert
消息太多让alert阻塞在后台内存会爆导致闪退崩溃
 
 Set the frida script message receiving function before starting the script,
 Don't send too many high-frequency messages in the frida script to let h5gg show alerts,
 because too many messages to alert will block h5frida in the background, and cause out-of-memory and crashes.
 */
script.on('message', function(msg) {
    if(msg.type=='error')
    {
        script.unload(); //如果脚本发生错误就停止frida脚本
        alert("frida脚本错误(script error):\n"+JSON.stringify(msg));
    }
    
    if(msg.type=='send')
        alert("frida脚本消息(srcipt msg):\n"+JSON.stringify(msg.payload));
    if(msg.type=='log')
        alert("frida脚本日志(script log):\n"+msg.payload);
});

if(!script.load()) throw "frida启动脚本失败\n\nfrida load script failed"; //启动脚本

/**********************************************************************************/

//获取frida脚本中的rpc.exports导出函数列表
alert("frida脚本导出函数列表:\nfrida export method list:\n" + script.list_exports());

alert("HOOK拦截OC函数:\nHOOK Objective-C method:\n" + script.call("hook_objc"));

alert("测试HOOK拦截效果, 开始主动调用触发\nTest the HOOK interception effect and start to trigger");

var result1 = script.call("testcall_objc", ["https://ipapi.co/ip"]);
setTimeout(function(){
    alert("测试调用OC函数:\nTest invoke Objective-C method:\n" + result1);
    
    //OC调用测试完之后再测试C/C++调用
    alert("HOOK拦截C/C++函数:\nHOOK API function:\n" + script.call("hook_API"));
    
    alert("测试HOOK拦截效果, 开始主动调用触发\nTest the HOOK interception effect and start to trigger");

    var result2 = script.call("testcall_API", ["testfile.txt"]);
    setTimeout(function(){
        alert("测试调用C/C++函数:\nTest invoke API function\n" + result2);
    }, 200);
    
}, 200);


//script.unload(); //卸载脚本

//session.detach(); //断开目标进程

/***************************************************************/

/*
 下面是frida的js脚本代码, 运行在目标进程, 不能在h5gg中直接调用这个js函数
 frida的js脚本代码中不能使用任何h5gg的函数和变量, 也不能使用window对象
 h5gg和frida只能通过console.log和send/recv/post还有rpc.exports进行通信

 The following is the js script code of frida, which runs in the target process, and this js function cannot be called directly in h5gg
 You cannot use any h5gg functions and variables in frida's js script code, nor can you use the window object
 h5gg and frida can only communicate through console.log and send/recv/post and rpc.exports
 */
function frida_script()
{
    //发送frida脚本的日志消息给h5gg
    console.log("frida脚本正在运行...\nfrida script is running...");
    
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
    /*******************************************************/
    /*******************************************************/
    
    //HOOK拦截dylib模块中的C/C++导出函数, 非模块导出函数不能hook
    rpc.exports.hook_API=function()
    {
        //HOOK所有静态引入和后续动态获取的fopen调用
        var fopen = fishhook("fopen", //要HOOK的C/C++导出函数名称
                 "pointer", //要HOOK的C/C++导出函数返回值类型
                 ["pointer", "pointer"], //要HOOK的C/C++导出函数参数类型列表
                 function(path, mode) //HOOK之后的js处理函数
                 {
                    //通知h5gg
                    if(mode.readUtf8String()=="wb")
                    send(["拦截到fopen调用(fopen called)", path.readUtf8String(), mode.readUtf8String()]);

                    //调用原始函数并返回值 //invoke the original fopen
                    return fopen(path, mode);
                }
        );
        
        return "成功hook拦截fopen函数, 如有被调用会有通知!\nSuccessful hook intercepts the fopen function, if it is called, there will be a notification";
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
                console.log("拦截到网址访问(Found URL Accessed):\n" + urlString.toString().split("").join(" "));
                //send("callstack:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
                
                //替换参数, 确保当前APP开启了HTTP明文网络权限
                //url = ObjC.classes.NSString.stringWithString_("http://ip-api.com/json?fields=query");
                
                return oldMethod(self, SEL, url); //调用原始方法;
            });
        }
        
        return "成功hook拦截NSURL的URLWithString方法, 如有被调用会有通知!\nSuccessful hook intercepts the URLWithString method of NSURL, if it is called, there will be a notification!";
    };
    
    rpc.exports.testcall_objc = function(url) {
        
        //[NSURL URLWithString:url];
        var nsurl = ObjC.classes.NSURL.URLWithString_(url);

        var NSASCIIStringEncoding=1;
        var error = Memory.alloc(8);
        
        //[NSString stringWithContentsOfURL:nsurl encoding:NSASCIIStringEncoding error:&error];
        var content = ObjC.classes.NSString.stringWithContentsOfURL_encoding_error_(nsurl, NSASCIIStringEncoding, error);
        if(!content || content.isNull())  return "获取本机IP失败\nFailed to get IP of current device";
        
        return "本机IP:\nIP of current device:\n"+content.toString();
    }
    
    rpc.exports.testcall_API = function(filename) {
        var NSHomeDirectory = new NativeFunction(ptr(Module.findExportByName("Foundation","NSHomeDirectory")),'pointer',[]);
        var path = ObjC.Object(NSHomeDirectory()).toString() + "/Documents/" + filename;
        
        var fopen = new NativeFunction(Module.findExportByName(null, "fopen"), "pointer", ["pointer","pointer"]);
        var fputs = new NativeFunction(Module.findExportByName(null, "fputs"), "int", ["pointer","pointer"]);
        var fclose = new NativeFunction(Module.findExportByName(null, "fclose"), "int", ["pointer"]);
        
        var fp = fopen(Memory.allocUtf8String(path), Memory.allocUtf8String("wb"));
        if(fp.isNull()) return "打开文件失败\nFailed to open file";
        
        fputs(Memory.allocUtf8String("frida"), fp);
        
        fclose(fp);
        
        return "成功写入文件:\nSuccess to write file:\n" + path;
    }

    //执行到这里之后script.load()才会返回 //script.load() will return after execution here
}

/***************************************************************/
