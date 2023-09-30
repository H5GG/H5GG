h5gg.require(7.8); //设定最低需求的H5GG版本号

//将插件dylib放到.app目录中调用//copy plugin dylib to .app folder
var MyAlert = h5gg.loadPlugin("MyAlert", "customAlert.dylib");

if(!MyAlert) throw "插件加载失败! Plugin Load Failed!";

//延迟一秒等H5GG的脚本执行完毕弹出之后再执行调用, 避免后面的弹框被阻塞弹不出来
setTimeout(function(){
    
    MyAlert.choice(["弹框Style1","弹框Style2","弹框Style3"], function(item)
    {
        if(item=='弹框Style1') MyAlert.alert0(); //调用无参数函数

        if(item=='弹框Style2')MyAlert.alert1("提示文本AlertText"); //调用一个参数函数
        
        if(item=='弹框Style3') MyAlert.alert2("标题文本AlertTitle", "内容文本AlertText"); //调用两个参数函数
    });
    
}, 1000);
