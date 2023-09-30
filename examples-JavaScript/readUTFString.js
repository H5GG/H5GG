
function readUTF16String(address, maxlen)
{
    var str = "";
    for (var s = 0; !maxlen||s<maxlen; s++) {
        var charCode = Number(h5gg.getValue(address + s * 2, "U16"));
        if(!charCode) break;
        str += String.fromCharCode(charCode);
    }
    return str;
}

function readUTF32String(address, maxlen)
{
    var str = "";
    for (var s = 0; !maxlen||s<maxlen; s++) {
        var charCode = Number(h5gg.getValue(address + s * 4, "U32"));
        if(!charCode) break;
        str += String.fromCharCode(charCode);
    }
    return str;
}


//This is usually slower, It is recommended to cache it

//var str1 = readUTF16String(addr);
//var str2 = readUTF16String(addr, 20);
//var str3 = readUTF32String(addr);
//var str4 = readUTF32String(addr, 20);
