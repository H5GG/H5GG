global.h5frida = {};

h5frida.fishhook = function(functionName, returnType, argTypes, callback) {
    
    /*NativeCallback不能被释放所以存到callback的属性中(务必)*/
    callback.NativeCallback = new NativeCallback(callback, returnType, argTypes);
    
    var oldFunctionAddr = ObjC.classes["h5frida"].fish_hook_(Memory.allocUtf8String(functionName), callback.NativeCallback);
    
    if(!oldFunctionAddr || oldFunctionAddr.isNull())
        throw "fishhookError:"+functionName;
    
    if(!global["dlsym_init"])
    {
        global["dlsym_init"] = true;
        global["dlsym_hook"] = {};
        
        /*拦截动态调用目标函数*/
        var dlsym = h5frida.fishhook("dlsym", "pointer", ["pointer", "pointer"], function(handle, symbol) {
            var addr = dlsym(handle, symbol);
            /*send(["dlsym", handle, symbol.readUtf8String(), addr, global["dlsym_hook"][addr]]);//*/

            if(global["dlsym_hook"][addr]) {
                /*send(["dlsym attach", handle, symbol.readUtf8String(), addr, global["dlsym_hook"][addr]]);//*/
                addr = global["dlsym_hook"][addr];
            }

            return addr;
        });
    }
    
    global["dlsym_hook"][oldFunctionAddr] = callback.NativeCallback;
    
    /*将原始函数转换成js函数对象*/
    return new NativeFunction(oldFunctionAddr, returnType, argTypes);
};

h5frida.StaticInlineHookFunction = function(fpath, vaddr, returnType, argTypes, callback) {
    
    /*NativeCallback不能被释放所以存到callback的属性中(务必)*/
    callback.NativeCallback = new NativeCallback(callback, returnType, argTypes);
    
    var oldFunctionAddr = ObjC.classes["h5frida"].staticInline_Hook_Function_(Memory.allocUtf8String(fpath), vaddr, callback.NativeCallback);
    
    if(!oldFunctionAddr || oldFunctionAddr.isNull())
    {
        var patchResult = ObjC.classes["h5frida"].staticInline_Hook_Patch_(Memory.allocUtf8String(fpath), vaddr, ptr(0));
        console.log(fpath+":0x"+vaddr.toString(16)+"-HOOK失败!\n" +
                    fpath+":0x"+vaddr.toString(16)+"-HOOK-Failed!\n" +
                    ObjC.Object(patchResult).toString());
        return null;
    }
    
    /*将原始函数转换成js函数对象*/
    return new NativeFunction(oldFunctionAddr, returnType, argTypes);
};

h5frida.StaticInlineHookInstrument = function(fpath, vaddr, callback) {
    
    /*NativeCallback不能被释放所以存到callback的属性中(务必)*/
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
    
    if(!ObjC.classes["h5frida"].staticInline_Hook_Instrument_(Memory.allocUtf8String(fpath), vaddr, callback.NativeCallback))
    {
        var patchResult = ObjC.classes["h5frida"].staticInline_Hook_Patch_(Memory.allocUtf8String(fpath), vaddr, ptr(0));
        console.log(fpath+":0x"+vaddr.toString(16)+"-HOOK失败!\n" +
                    fpath+":0x"+vaddr.toString(16)+"-HOOK-Failed!\n" + ObjC.Object(patchResult).toString());
        return false;
    }

    return true;
};

