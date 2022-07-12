h5gg.require(7.5); //设定最低需求的H5GG版本号

//将h5frida-15.1.24.dylib放到.app目录中
var h5frida=h5gg.loadPlugin("h5frida","h5frida-15.1.24.dylib");
if(!h5frida) throw "加载h5frida插件失败";

alert("h5frida插件版本="+h5frida.pluginVersion() + "\nfrida引擎版本="+h5frida.coreVersion());

//将frida-gadget的dylib和config两个文件放到.app目录中, 免越狱不支持Interceptor功能
if(!h5frida.loadGadget("frida-gadget-15.1.24.dylib"))
    throw "加载frida-gadget守护模块失败";


var procs = h5frida.enumerate_processes();
if(!procs || !procs.length) throw "frida无法获取进程列表";

var pid = 0;
for(var i=0;i<procs.length;i++) {
    if(procs[i].pid==-1) //查找pid=-1即为找到自身进程
        pid = procs[i].pid;
}

if(!pid) throw "frida无法找到进程";

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
script.on('message', function(msg) {
    if(msg.type=='error')
        alert("frida脚本错误:\n"+JSON.stringify(msg));
    if(msg.type=='send')
        alert("frida脚本消息:\n"+JSON.stringify(msg.payload));
    if(msg.type=='log')
        alert("frida脚本日志:\n"+msg.payload);
});

if(!script.load()) throw "启动脚本失败"; //启动脚本

//给frida脚本的recv发送消息
script.post({
    "type":"h5ggmsg", //消息名称
    "payload":"msg1 from h5gg to frida" //消息内容
});


//再发个消息
script.post({
    "type":"h5ggmsg", //消息名称
    "payload":"msg2 from h5gg to frida" //消息内容
});

//获取frida脚本中的rpc.exports导出函数列表
alert("frida脚本导出函数列表:\n" + script.list_exports());

//调用frida脚本中的导出函数并获取返回值
var result = script.call("getinfo");
alert("rpc.exports.getinfo() = " + result);

//传入参数调用frida脚本中的导出函数并获取返回值
var result = script.call("add", [1, 2]);
alert("rpc.exports.add(1,2) = " + result);

/***************************************************************/

//frida的js脚本代码, 运行在目标进程, 不能在h5gg中直接调用这个js函数
//frida的js脚本代码中不能使用任何h5gg的函数和变量, 也不能使用window对象
//h5gg和frida只能通过console.log和send/recv/post还有rpc.exports进行通信
function frida_script()
{
    //发送frida脚本的日志消息给h5gg
    console.log("log from frida to h5gg");

    //发送frida脚本的自定义数据给h5gg
    send("msg from frida to h5gg");
    
    //设置接收h5gg发送的数据的回掉方法(每次调用recv只能接收一次h5gg的post数据)
    recv('h5ggmsg', function onMessage(msg) {
        
        send("send back<"+msg["payload"]+">"); //发送回复消息给h5gg
        
        recv('h5ggmsg', onMessage); //接收到消息之后再重新请求获取新的消息
    });
    
    //导出frida脚本函数给h5gg调用
    rpc.exports = {
        getinfo : function() {
            console.log("rpc.exports.getinfo called!");
            return "i'm from frida, yeah!";
        },
        
        add : function(x, y) {
            console.log("rpc.exports.add called!");
            return x+y;
        }
    };

    //执行到这里之后script.load()才会返回
}

/***************************************************************/
