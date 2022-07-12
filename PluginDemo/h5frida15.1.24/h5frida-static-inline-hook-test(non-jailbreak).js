h5gg.require(7.6); //设定最低需求的H5GG版本号

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

//hook前先将目标模块加载起来
var hookme = h5gg.loadPlugin("hookme", "hookme.dylib");

var info = "\nhook前测试:\nhook目标: hookme.dylib";
info += "\naddInt(1,2)="+hookme.addInt(1,2);
info += "\naddFloat(3,4)="+hookme.addFloat(3,4);
info += "\naddDouble(5,6)="+hookme.addDouble(5,6);
alert(info);

if(script.call("hook_dylib"))
{
    alert("inline hook拦截成功");

    var info = "hook后测试:\nhook目标: hookme.dylib";
    info += "\naddInt(1,2)="+hookme.addInt(1,2);
    info += "\naddFloat(3,4)="+hookme.addFloat(3,4);
    info += "\naddDouble(5,6)="+hookme.addDouble(5,6);
    alert(info);
} else {
    alert("inline hook拦截失败, 请检查日志信息!");
}

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

    //HOOK拦截.app中的任何模块中的任意地址的函数或指令
    rpc.exports.hook_dylib=function()
    {
        //获取.app路径
        var app_path = ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
        //加载StaticInlineHook插件, 需要将StaticInlineHook.dylib放到.app目录中
        var SIHModule = Module.load(app_path+"/StaticInlineHook.dylib");
        
        var StaticInlineHookPatchExport = new NativeFunction(SIHModule.getExportByName("StaticInlineHookPatch"),
                                                  "bool", ["pointer", "uint"]);
        var StaticInlineHookPatchCommitExport = new NativeFunction(SIHModule.getExportByName("StaticInlineHookPatchCommit"),
                                                  "bool", []);
        var StaticInlineHookFunctionExport = new NativeFunction(SIHModule.getExportByName("StaticInlineHookFunction"),
                                                  "pointer", ["pointer", "uint", "pointer"]);
        var StaticInlineHookInstrumentExport = new NativeFunction(SIHModule.getExportByName("StaticInlineHookInstrument"),
                                                  "bool", ["pointer", "uint", "pointer"]);
        
        global.StaticInlineHookPatchCount = 0;
        global.StaticInlineHookFailedCount = 0;
        
        global.StaticInlineHookCommit = function()
        {
            if(global.StaticInlineHookPatchCount > 0) {
                global.StaticInlineHookPatchCount = 0;
                if(!StaticInlineHookPatchCommitExport())
                    return false;
            }
            if(global.StaticInlineHookFailedCount) {
                global.StaticInlineHookFailedCount = 0;
                return false;
            }
            return true;
        }
        
        global.StaticInlineHookFunction = function(fpath, vaddr, returnType, argTypes, callback) {
            
            //NativeCallback不能被释放所以存到callback的属性中(务必)
            callback.NativeCallback = new NativeCallback(callback, returnType, argTypes);
            
            var oldFunctionAddr = StaticInlineHookFunctionExport(Memory.allocUtf8String(fpath), vaddr, callback.NativeCallback);
            
            if(!oldFunctionAddr || oldFunctionAddr.isNull())
            {
                global.StaticInlineHookFailedCount++;
                if(StaticInlineHookPatchExport(Memory.allocUtf8String(fpath), vaddr)) {
                    global.StaticInlineHookPatchCount++;
                    console.log(fpath+":0x"+vaddr.toString(16)+"未签名该HOOK地址, 修补文件将生成在APP的Documents/static-inline-hook目录中, 请将该目录中所有文件替换到ipa中的.app目录并重新签名安装!");
                } else {
                    console.log(fpath+":0x"+vaddr.toString(16)+"未签名该HOOK地址, 修补文件失败!");
                }
                return null;
            }
            
            //将原始函数转换成js函数对象
            return new NativeFunction(oldFunctionAddr, returnType, argTypes);
        }
        
        global.StaticInlineHookInstrument = function(fpath, vaddr, callback) {
            
            //NativeCallback不能被释放所以存到callback的属性中(务必)
            callback.NativeCallback = new NativeCallback(function(p) {
                var context = {
                    sp: p.add(8).readPointer(),
                    fp: p.add(0x18+29*8+0).readPointer(),
                    lr: p.add(0x18+29*8+8).readPointer(),
                    x: []
                };
                for(var i=0; i<29; i++) context.x[i] = p.add(0x18+i*8).readPointer();
                
                context.get_float = function(index) {return p.add(0x18+29*8+0x10+index*16).readFloat();};
                context.set_float = function(index, value) {return p.add(0x18+29*8+0x10+index*16).writeFloat(value);};
                
                context.get_double = function(index) {return p.add(0x18+29*8+0x10+index*16).readDouble();};
                context.set_double = function(index, value) {return p.add(0x18+29*8+0x10+index*16).writeDouble(value);};
                
                callback(context);
                
                p.add(8).writePointer(context.sp);
                p.add(0x18+29*8+0).writePointer(context.fp);
                p.add(0x18+29*8+8).writePointer(context.lr);
                for(var i=0; i<29; i++) p.add(0x18+i*8).writePointer(context.x[i]);
                
            }, "void", ["pointer"]);
            
            if(!StaticInlineHookInstrumentExport(Memory.allocUtf8String(fpath), vaddr, callback.NativeCallback))
            {
                global.StaticInlineHookFailedCount++;
                if(StaticInlineHookPatchExport(Memory.allocUtf8String(fpath), vaddr)) {
                    global.StaticInlineHookPatchCount++;
                    console.log(fpath+":0x"+vaddr.toString(16)+"未签名该HOOK地址, 修补文件将生成在APP的Documents/static-inline-hook目录中, 请将该目录中所有文件替换到ipa中的.app目录并重新签名安装!");
                } else {
                    console.log(fpath+":0x"+vaddr.toString(16)+"未签名该HOOK地址, 修补文件失败!");
                }
                return false;
            }

            return true;
        }
        
        /*******************************************************/
        /*******************************************************/
        /*******************************************************/
        
        //inline hook拦截hookme.dylib中的addInt函数
        var addInt = StaticInlineHookFunction("hookme.dylib", //要HOOK的模块在.app中的相对路径
                 0x00007E2C, //要HOOK的C/C++函数偏移地址
                 "int", //要HOOK的C/C++函数返回值类型
                 ["pointer", "pointer", "int", "int"], //要HOOK的C/C++函数参数类型列表
                 function(self, sel, number1, number2) //HOOK之后的js处理函数
                 {
                    //通知h5gg
                    send(["拦截到addInt调用", number1, number2]);
            
                    number1 *= 2; //修改参数1数值翻倍
                    number2 *= 2; //修改参数2数值翻倍

                    //调用原始函数
                    return addInt(self, sel, number1, number2);
                }
        );
        
        //inline hook拦截hookme.dylib中的addInt函数最后一条指令
        StaticInlineHookInstrument("hookme.dylib", //要HOOK的模块在.app中的相对路径
                 0x00007E50, //要HOOK的指令偏移地址
                 function(context)
                 {
                    //send(["拦截到addInt最后一条指令执行", context]);
            
                    var r = context.x[0]; //获取返回值x0寄存器
            
                    send(["拦截到addInt最后一条指令执行", r]);
            
                    r = Number(r) * 2; //将返回值翻倍
            
                    /* 寄存器的值都是NativePointer类型, 需要转换为Number类型, 修改后需要再次转换回NativePointer类型 */
            
                    context.x[0] = new NativePointer(r); //修改结果数值翻倍
                 }
        );
        
        //inline hook拦截hookme.dylib中的addFloat函数第一条指令
        StaticInlineHookInstrument("hookme.dylib", //要HOOK的模块在.app中的相对路径
                 0x00007E54, //要HOOK的指令偏移地址
                 function(context)
                 {
                    //send(["拦截到addFloat第一条指令", context]);
            
                    var number1 = context.get_float(0); //获取第1个单精度浮点参数
                    var number2 = context.get_float(1); //获取第2个单精度浮点参数
            
                    send(["拦截到addFloat第一条指令执行", number1, number2]);
            
                    context.set_float(0, number1*2); //修改参数1数值翻倍
                    context.set_float(1, number2*2); //修改参数2数值翻倍
                 }
        );
        
        //inline hook拦截hookme.dylib中的addDouble函数最后一条指令
        StaticInlineHookInstrument("hookme.dylib", //要HOOK的模块在.app中的相对路径
                 0x00007EA0, //要HOOK的指令偏移地址
                 function(context)
                 {
                    var r = context.get_double(0); //获取双精度浮点返回值
            
                    send(["拦截到addDouble最后一条指令执行", r]);
            
                    context.set_double(0, r*2); //修改结果数值翻倍
                 }
        );
        
        //确认全部HOOK并返回是否成功
        return global.StaticInlineHookCommit();
    };

    //执行到这里之后script.load()才会返回
}

/***************************************************************/
