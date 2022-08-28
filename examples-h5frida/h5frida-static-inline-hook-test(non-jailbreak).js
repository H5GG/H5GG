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

//hook前先将目标模块加载起来 //load hookme.test.dylib for testing to hook it
var hookme = h5gg.loadPlugin("hookme", "hookme.test.dylib");

var info = "\nhook前测试:\ntest before do hook:\n"
+ "hook目标: hookme.test.dylib\nhook target: hookme.test.dylib";
info += "\naddInt(1,2)="+hookme.addInt(1,2);
info += "\naddFloat(3,4)="+hookme.addFloat(3,4);
info += "\naddDouble(5,6)="+hookme.addDouble(5,6);
alert(info);

if(script.call("hook_dylib"))
{
    alert("inline hook拦截成功\ndo inline hook success");

    var info = "\nhook后测试:\ntest after do hook:\n"
    + "hook目标: hookme.test.dylib\nhook target: hookme.test.dylib";
    info += "\naddInt(1,2)="+hookme.addInt(1,2);
    info += "\naddFloat(3,4)="+hookme.addFloat(3,4);
    info += "\naddDouble(5,6)="+hookme.addDouble(5,6);
    alert(info);
} else {
    alert("inline hook拦截失败, 请检查日志信息!\nDo inline hook failed, Please check log message");
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
function frida_script() { if(arguments.length) return new Error().line; //do not modify this line!!!

    //发送frida脚本的日志消息给h5gg
    console.log("frida脚本正在运行...\nfrida script is running...");

    //HOOK拦截.app中的任何模块中的任意地址的函数或指令
    rpc.exports.hook_dylib=function()
    {
        //inline hook拦截hookme.test.dylib中的addInt函数
        var addInt = h5frida.StaticInlineHookFunction("hookme.test.dylib", //要HOOK的模块在.app中的相对路径//The relative path of the module to be hooked in .app
                 0x00007E2C, //要HOOK的C/C++函数偏移地址//The offset of function to be hooked
                 "int", //要HOOK的C/C++函数返回值类型//The return value type of the function to be hooked
                 ["pointer", "pointer", "int", "int"], //要HOOK的C/C++函数参数类型列表//List of function parameter types to hook
                 function(self, sel, number1, number2) //HOOK之后的js处理函数
                 {
                    //通知h5gg
                    send(["拦截到addInt调用(addInt called)", number1, number2]);
            
                    number1 *= 2; //修改参数1数值翻倍
                    number2 *= 2; //修改参数2数值翻倍

                    //调用原始函数 //call the original 
                    return addInt(self, sel, number1, number2);
                }
        );
        
        //inline hook拦截hookme.test.dylib中的addInt函数最后一条指令 //hook single instruction
        var hook2 = h5frida.StaticInlineHookInstrument("hookme.test.dylib", //要HOOK的模块在.app中的相对路径
                 0x00007E50, //要HOOK的指令偏移地址 //instruction offset
                 function(context)
                 {
                    //send(["拦截到addInt最后一条指令执行", context]);
            
                    var r = context.x[0]; //获取返回值x0寄存器
            
                    send(["拦截到addInt最后一条指令执行(Intercept the execution of the last instruction of addInt)", r]);
            
                    r = Number(r) * 2; //将返回值翻倍
            
                    /* 寄存器的值都是NativePointer类型, 需要转换为Number类型, 修改后需要再次转换回NativePointer类型 */
            
                    context.x[0] = new NativePointer(r); //修改结果数值翻倍
                 }
        );
        
        //inline hook拦截hookme.test.dylib中的addFloat函数第一条指令
        var hook3 = h5frida.StaticInlineHookInstrument("hookme.test.dylib", //要HOOK的模块在.app中的相对路径
                 0x00007E54, //要HOOK的指令偏移地址
                 function(context)
                 {
                    //send(["拦截到addFloat第一条指令", context]);
            
                    var number1 = context.get_float(0); //获取第1个单精度浮点参数
                    var number2 = context.get_float(1); //获取第2个单精度浮点参数
            
                    send(["拦截到addFloat第一条指令执行(Intercept the execution of the first instruction of addFloat)", number1, number2]);
            
                    context.set_float(0, number1*2); //修改参数1数值翻倍
                    context.set_float(1, number2*2); //修改参数2数值翻倍
                 }
        );
        
        //inline hook拦截hookme.test.dylib中的addDouble函数最后一条指令
        var hook4 = h5frida.StaticInlineHookInstrument("hookme.test.dylib", //要HOOK的模块在.app中的相对路径
                 0x00007EA0, //要HOOK的指令偏移地址
                 function(context)
                 {
                    var r = context.get_double(0); //获取双精度浮点返回值
            
                    send(["拦截到addDouble最后一条指令执行(Intercept the execution of the last instruction of addDouble)", r]);
            
                    context.set_double(0, r*2); //修改结果数值翻倍
                 }
        );
        
        //返回是否全部HOOK成功 //Check if all hooks are successful
        return addInt && hook2 && hook3 && hook4;
    };

    //执行到这里之后script.load()才会返回 //script.load() will return after execution here
}

/***************************************************************/
