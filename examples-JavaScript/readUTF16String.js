
//This is usually slower, It is recommended to cache it

function readUTF16String(address)
{
    var str = "";
    for (var s = 0; ; s++) {
        var after = Number(h5gg.getValue(address + s * 2, "U8")).toString(16).padStart(2, '0');
        var before = Number(h5gg.getValue(address + s * 2 + 1, "U8")).toString(16).padStart(2, '0');
        var charCode = before + after;
        if (charCode == "0000") break;

        str += String.fromCharCode(parseInt(charCode, 16));
    }
    return str;
}
