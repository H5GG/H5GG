h5gg.require(7.8); //min version

//ModuleFileName: like "UnityFramework", or 0 for main executable
var modules = h5gg.getRangesList("ModuleFileName");

var base = Number(modules[0].start);

var addr = base + _offset_; //your offset

var pointer = h5gg.getValue(addr, "U64");

alert('0x'+pointer.toString(16));


