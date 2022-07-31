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

//hook前先将目标模块加载起来 //load hookme.dylib for testing to hook it
var hookme = h5gg.loadPlugin("hookme", "hookme.dylib");

var info = "\n修改前测试:\ntest before active patches:\n"
+ "修改目标: hookme.dylib\npatch target: hookme.dylib";
info += "\naddInt(1,2)="+hookme.addInt(1,2);
info += "\naddFloat(3,4)="+hookme.addFloat(3,4);
info += "\naddDouble(5,6)="+hookme.addDouble(5,6);
alert(info);

if(script.call("active_patches"))
{
    alert("修改成功\nactive patches success");

    var info = "\n修改后测试:\ntest after active patches:\n"
    + "修改目标: hookme.dylib\npatch target: hookme.dylib";
    info += "\naddInt(1,2)="+hookme.addInt(1,2);
    info += "\naddFloat(3,4)="+hookme.addFloat(3,4);
    info += "\naddDouble(5,6)="+hookme.addDouble(5,6);
    alert(info);
    
    if(script.call("deactive_patches"))
    {
        alert("恢复成功\ndeactive patches success");

        var info = "\n恢复后测试:\ntest after deactive patches:\n"
        info += "\naddInt(1,2)="+hookme.addInt(1,2);
        info += "\naddFloat(3,4)="+hookme.addFloat(3,4);
        info += "\naddDouble(5,6)="+hookme.addDouble(5,6);
        alert(info);
    } else {
        alert("恢复失败, 请检查日志信息!\nrestore patches failed, Please check log message");
    }
    
} else {
    alert("修改失败, 请检查日志信息!\npatch failed, Please check log message");
}

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
    //加载StaticInlineHook插件, 需要将StaticInlineHook.dylib放到.app目录中
    var SIHModule = Module.load(app_path+"/StaticInlineHook.dylib");
    
    var StaticInlineHookPatchExport = new NativeFunction(SIHModule.getExportByName("StaticInlineHookPatch"),
                                              "pointer", ["pointer", "uint", "pointer"]);
    var ActiveCodePatchExport = new NativeFunction(SIHModule.getExportByName("ActiveCodePatch"),
                                              "bool", ["pointer", "uint", "pointer"]);
    var DeactiveCodePatchExport = new NativeFunction(SIHModule.getExportByName("DeactiveCodePatch"),
                                              "bool", ["pointer", "uint", "pointer"]);
    
    global.ActiveCodePatch = function(fpath, vaddr, bytes) {
        
        var result = ActiveCodePatchExport(Memory.allocUtf8String(fpath), vaddr, Memory.allocUtf8String(bytes));
        
        if(!result)
        {
            var patchResult = StaticInlineHookPatchExport(Memory.allocUtf8String(fpath), vaddr, Memory.allocUtf8String(bytes));
            console.log(fpath+":0x"+vaddr.toString(16)+"-修改失败!\n" +
                        fpath+":0x"+vaddr.toString(16)+"-PatchFailed!\n" +
                        ObjC.Object(patchResult).toString());
            return false;
        }
        return true;
    }

    global.DeactiveCodePatch = function(fpath, vaddr, bytes) {
        return DeactiveCodePatchExport(Memory.allocUtf8String(fpath), vaddr, Memory.allocUtf8String(bytes));
    }
    
    /*******************************************************/
    /*******************************************************/
    /*******************************************************/
    
    rpc.exports.active_patches=function()
    {
        //第一个参数需要是文件在.app中的相对路径 //The first parameter needs to be the relative path of the file in the .app
        var patch1 = ActiveCodePatch("hookme.dylib", 0x7E48, "200080D2");
        var patch2 = ActiveCodePatch("hookme.dylib", 0x7E70, "00102E1E");
        var patch3 = ActiveCodePatch("hookme.dylib", 0x7E98, "00106E1E");
        
        return patch1 && patch2 && patch3;
    };
    
    rpc.exports.deactive_patches=function()
    {
        var patch1 = DeactiveCodePatch("hookme.dylib", 0x7E48, "200080D2");
        var patch2 = DeactiveCodePatch("hookme.dylib", 0x7E70, "00102E1E");
        var patch3 = DeactiveCodePatch("hookme.dylib", 0x7E98, "00106E1E");
        
        return patch1 && patch2 && patch3;
    }

    //执行到这里之后script.load()才会返回 //script.load() will return after execution here
}

/***************************************************************/
