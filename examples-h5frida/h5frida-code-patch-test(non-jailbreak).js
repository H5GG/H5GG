h5gg.require(7.9); //设定最低需求的H5GG版本号//min version support for H5GG

//将h5frida-15.1.24.dylib放到.app目录中 //put h5frida-15.1.24.dylib into .app folder of ipa
var h5frida=h5gg.loadPlugin("h5frida", "h5frida-15.1.24.dylib");
if(!h5frida) throw "加载h5frida插件失败\n\nFailed to load h5frida plugin";

alert("h5frida插件版本="+h5frida.pluginVersion() + "\nfrida引擎版本="+h5frida.coreVersion()+"\n\n"
      +"frida plugin version="+h5frida.pluginVersion() + "\nfrida core version="+h5frida.coreVersion());

function ActiveCodePatch(fpath, vaddr, bytes) {
    if(!h5frida.ActiveCodePatch(fpath, vaddr, bytes)) {
        var result = h5frida.ApplyCodePatch(fpath, vaddr, bytes);
        alert(fpath+":0x"+vaddr.toString(16)+"-修改失败!\n" + fpath+":0x"+vaddr.toString(16)+"-PatchFailed!\n" + result);return false;
    } return true;
}
function DeactiveCodePatch(fpath, vaddr, bytes) {
    return h5frida.DeactiveCodePatch(fpath, vaddr, bytes);
}

/**************************************************************************************/

//hook前先将目标模块加载起来 //load hookme.test.dylib for testing to hook it
var hookme = h5gg.loadPlugin("hookme", "hookme.test.dylib");

var info = "\n修改前测试:\ntest before active patches:\n"
+ "修改目标: hookme.test.dylib\npatch target: hookme.test.dylib";
info += "\naddInt(1,2)="+hookme.addInt(1,2);
info += "\naddFloat(3,4)="+hookme.addFloat(3,4);
info += "\naddDouble(5,6)="+hookme.addDouble(5,6);
alert(info);


ActiveCodePatch("hookme.test.dylib", 0x7E48, "200080D2");
ActiveCodePatch("hookme.test.dylib", 0x7E70, "00102E1E");
ActiveCodePatch("hookme.test.dylib", 0x7E98, "00106E1E");

var info = "\n修改后测试:\ntest after active patches:\n"
    + "修改目标: hookme.test.dylib\npatch target: hookme.test.dylib";
info += "\naddInt(1,2)="+hookme.addInt(1,2);
info += "\naddFloat(3,4)="+hookme.addFloat(3,4);
info += "\naddDouble(5,6)="+hookme.addDouble(5,6);
alert(info);

DeactiveCodePatch("hookme.test.dylib", 0x7E48, "200080D2");
DeactiveCodePatch("hookme.test.dylib", 0x7E70, "00102E1E");
DeactiveCodePatch("hookme.test.dylib", 0x7E98, "00106E1E");

var info = "\n恢复后测试:\ntest after deactive patches:\n"
info += "\naddInt(1,2)="+hookme.addInt(1,2);
info += "\naddFloat(3,4)="+hookme.addFloat(3,4);
info += "\naddDouble(5,6)="+hookme.addDouble(5,6);
alert(info);
