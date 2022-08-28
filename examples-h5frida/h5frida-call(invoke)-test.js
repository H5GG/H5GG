h5gg.require(7.9); //设定最低需求的H5GG版本号//min version support for H5GG

//将h5frida-15.1.24.dylib放到.app目录中 //put h5frida-15.1.24.dylib into .app folder of ipa
var h5frida=h5gg.loadPlugin("h5frida", "h5frida-15.1.24.dylib");
if(!h5frida) throw "加载h5frida插件失败\n\nFailed to load h5frida plugin";

alert("h5frida插件版本="+h5frida.pluginVersion() + "\nfrida引擎版本="+h5frida.coreVersion()+"\n\n"
      +"frida plugin version="+h5frida.pluginVersion() + "\nfrida core version="+h5frida.coreVersion());

//优先调用集成的frida核心, 将frida-gadget的dylib和config两个文件放到.app目录中
if(!h5frida.loadGadget("frida-gadget-15.1.24.dylib"))
    throw "加载frida-gadget守护模块失败\n\nFailed to load frida-gadget daemon module";
    
var procs = h5frida.enumerate_processes();
if(!procs || !procs.length) throw "frida无法获取进程列表\n\nfrida can't get process list";

var pid = -1; //pid=-1, 使用自身进程来调用OC/C/C++函数, 也可以附加到其他APP进程来调用
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

var app_path = script.call("ObjC_getAppPath");
alert("frida调用OC获取APP路径:\nfrida invoke objective-c to get app path:\n" + app_path);

var files = script.call("Cxx_getDirFiles", [app_path]);
alert("frida调用C/C++获取目录文件列表:\nfrida invoke c/c++ to get file list of folder:\n" + files);


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

    //frida调用Objective-C方法, 参考 https://frida.re/docs/javascript-api/#objc
    rpc.exports.ObjC_getAppPath = function()
    {
        var NSBundle = ObjC.classes.NSBundle;
        var bundlePath = NSBundle.mainBundle().bundlePath();
        var path = bundlePath.toString();
        return path;
    };

    //frida调用任意C/C++函数, 参考:https://frida.re/docs/javascript-api/#nativefunction
    rpc.exports.Cxx_getDirFiles = function(path)
    {
        var opendir = new NativeFunction(Module.findExportByName(null, "opendir"), "pointer", ["pointer"]);
        var readdir = new NativeFunction(Module.findExportByName(null, "readdir"), "pointer", ["pointer"]);
        var closedir = new NativeFunction(Module.findExportByName(null, "closedir"), "int", ["pointer"]);
        
        var DIR = opendir(Memory.allocUtf8String(path));
        if(DIR.isNull()) throw "opendir 失败\n\nopendir Failed";
        
        var results = [];
        
        while(true)
        {
            var dirent=readdir(DIR);
            if(dirent.isNull()) break;
            
    //            send(hexdump(dirent, {
    //                offset: 0,
    //                length: 64,
    //                header: false,
    //                ansi: false
    //            }));
            
            var filenameAddr = dirent.add(0x15);
            var filename = filenameAddr.readUtf8String();
            results.push(filename);
        }
        
        closedir(DIR);
        
        return results;
    };

    //执行到这里之后script.load()才会返回 //script.load() will return after execution here
}

/***************************************************************/

