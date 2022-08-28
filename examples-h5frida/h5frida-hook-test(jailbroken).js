h5gg.require(7.9); //设定最低需求的H5GG版本号//min version support for H5GG

//获取h5gg当前选择的进程号 //Get the currently selected process ID of h5gg
var pid = $("#procname").attr('pid');
if(!pid) throw "无法获取h5gg选择的进程, 请使用h5gg跨进程版测试\nUnable to get the process selected by h5gg, please use h5gg cross-process app to test";

//install frida-server deb for jailbroken
//越狱:安装frida核心deb, 支持Interceptor进行inline hook功能

//将h5frida-15.1.24.dylib放到h5ggapp.app目录中 //put h5frida dylib into h5ggapp.app folder
var h5frida=h5gg.loadPlugin("h5frida","h5frida-15.1.24.dylib");
if(!h5frida) throw "加载h5frida插件失败\n\nFailed to load h5frida plugin";

alert("h5frida插件版本="+h5frida.pluginVersion()
      + "\nfrida引擎版本="+h5frida.coreVersion()+"\n\n"
      +"frida plugin version="+h5frida.pluginVersion()
      + "\nfrida core version="+h5frida.coreVersion());

var procs = h5frida.enumerate_processes();
if(!procs || !procs.length) throw "frida无法获取进程列表\n\nfrida can't get process list";

var found = false;
for(var i=0;i<procs.length;i++) {
    if(procs[i].pid==pid)
        found = true;
}

if(!found) throw "frida无法找到目标进程\n\nfrida cannot find the target process";

//检查目标APP进程是否在前台运行, 如果在后台暂停了, frida附加调用会卡住
//Check whether the target APP process is running in the foreground, if it is suspended in the background, frida will be blocked
while(true) {
    var frontapp = h5frida.get_frontmost_application();
    if(frontapp && frontapp.pid == pid) break;
    
    alert("请将目标APP切换至前台运行, 再点击确定继续...\n"
          + "Please switch the target APP to the foreground to run, and then click OK to continue...");
}

var session = h5frida.attach(pid);
if(!session) throw "frida附加进程失败\n\nfrida attach process failed";

//监听frida目标进程连接状态, 比如异常退出
session.on("detached", function(reason) {
    alert("frida目标进程会话已终止(frida target process session terminated):\n"+reason);
});

var frida_script_line = frida_script("getline"); //safari console will auto add 2 line
var frida_script_code = "("+frida_script.toString()+")()"; //将frida脚本转换成字符串
var script = session.create_script(frida_script_code); //注入frida的js脚本代码

if(!script) throw "frida注入脚本失败\n\nfrida inject script failed!";

/*启动脚本前先设置frida脚本消息接收函数, 不要在frida脚本里发太多高频消息过来让h5gg弹出alert, 消息太多让alert阻塞在后台内存会爆导致闪退崩溃
 Set the frida script message receiving function before starting the script,
 Don't send too many high-frequency messages in the frida script to let h5gg show alerts,
 because too many messages to alert will block h5frida in the background, and cause out-of-memory and crashes.
 */
script.on('message', function(msg) {
    if(msg.type=='error') {
        script.unload(); //如果脚本发生错误就停止frida脚本
        try {if(msg.fileName=="/frida_script.js") msg.lineNumber += frida_script_line-1;} catch(e) {}
        if(Array.isArray(msg.info)) msg.info.map(function(item){ try { if(item.fileName=="/frida_script.js")
            item.lineNumber += frida_script_line-1;} catch(e) {}; return item;});
        var errmsg = JSON.stringify(msg,null,1).replace(/\/frida_script\.js\:(\d+)/gm,
            function(m,c,o,a){return "/frida_script.js:"+(Number(c)+frida_script_line-1);});
        alert("frida(脚本错误)script error:\n"+errmsg.replaceAll("\\n","\n"));
    }
    
    if(msg.type=='send')
        alert("frida(脚本消息)srcipt msg:\n"+JSON.stringify(msg.payload,null,1));
    if(msg.type=='log')
        alert("frida(脚本日志)script log:\n"+msg.payload);
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
    alert("HOOK拦截C/C++函数:\nHOOK C/C++ function:\n" + script.call("hook_cxx"));

    alert("测试HOOK拦截效果, 开始主动调用触发\nTest the HOOK interception effect and start to trigger");
    
    var result2 = script.call("testcall_cxx", ["testfile.txt"]);
    setTimeout(function(){
        alert("测试调用C/C++函数:\nTest invoke C/C++ function:\n" + result2);
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
function frida_script() { if(arguments.length) return new Error().line; //do not modify this line!!!

    //发送frida脚本的日志消息给h5gg
    console.log("frida脚本正在运行...\nfrida script is running...");

    rpc.exports.hook_cxx=function()
    {
        var fopen = Module.findExportByName(null, "fopen");
        
        
        //inline-hook拦截任意地址的C/C++函数或指令
        //first way: inline-hook any offset function or instrument
        Interceptor.attach(fopen, {
                           
            onEnter(args) //调用原方法前的js回调
            {
                var path = args[0];
                var mode = args[1];
                
                //通知h5gg
                if(mode.readUtf8String()=="wb")
                send(["拦截到fopen调用(fopen called)", path.readUtf8String(), mode.readUtf8String()]);
            },
            
            onLeave(retval) //调用原方法后的js回调
            {
                //替换返回值
                //retval.replace(ptr(0));
            }
            
        });
        
        //方式二: 替换HOOK函数, 可以修改浮点参数或返回值
        //second way: only hook for function, can change float/double args or return value
        const fclosePtr = Module.getExportByName(null, 'fclose');
        const fclose = new NativeFunction(fclosePtr,
                                          'int', //返回值类型 //return value type
                                          ['pointer'] //参数类型列表 //parameter types
                                          );
        var my_fclose = function(FILE_fp) {
            send(["拦截到fclose调用(fclose called)", FILE_fp]);
            return fclose(FILE_fp); //call original
        };
        Interceptor.replace(fclosePtr, new NativeCallback(my_fclose, 'int', ['pointer']) );
        
        return "成功hook拦截fopen和fclose函数, 如有被调用会有通知!\nSuccessful hook intercepts the fopen and fclose function, if it is called, there will be a notification";
    };
   
    //HOOK拦截任意Objective-C类的方法函数
    rpc.exports.hook_objc = function()
    {
        if(ObjC.available)
        {
            var objc_Class = ObjC.classes["NSURL"]; //获取OC类
            var objc_Method = objc_Class["+ URLWithString:"]; //获取OC方法
            
            //inline hook拦截OC方法(可以hook任意地址的函数)
            Interceptor.attach(objc_Method.implementation, {
                               
                onEnter(args) //调用原方法前的js回调
                {
                    //args[0]=self, args[1]=selector, args[2-n]是OC方法参数
                    
                    var urlString = ObjC.Object(args[2]); //将OC对象参数转换为js对象

                    console.log("拦截到网址访问(Found URL Accessed):\n" + urlString.toString());
                    
                    //替换参数, 确保当前APP开启了HTTP明文网络权限
                    //args[2] = ObjC.classes.NSString.stringWithString_("http://ip-api.com/json?fields=query");
                    
                },
                
                onLeave(retval) //调用原方法后的js回调
                {
                    //替换返回值
                    //retval.replace(ptr(0));
                }
                
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
        
        return "本机IP(IP of current device):\n"+content.toString();
    }
    
    rpc.exports.testcall_cxx = function(filename) {
        var NSHomeDirectory = new NativeFunction(ptr(Module.findExportByName("Foundation","NSHomeDirectory")),'pointer',[]);
        var path = ObjC.Object(NSHomeDirectory()).toString() + "/Documents/" + filename;
        
        var fopen = new NativeFunction(Module.findExportByName(null, "fopen"), "pointer", ["pointer","pointer"]);
        var fputs = new NativeFunction(Module.findExportByName(null, "fputs"), "int", ["pointer","pointer"]);
        var fclose = new NativeFunction(Module.findExportByName(null, "fclose"), "int", ["pointer"]);
        
        var fp = fopen(Memory.allocUtf8String(path), Memory.allocUtf8String("wb"));
        if(fp.isNull()) return "打开文件失败\nFailed to open file";
        
        fputs(Memory.allocUtf8String("frida"), fp);
        
        fclose(fp);
        
        return "成功写入文件(Success to write file):\n" + path;
    }

    //执行到这里之后script.load()才会返回 //script.load() will return after execution here
}

/***************************************************************/
