h5gg.require(7.7);

var sleep = (timeountMS) => new Promise((resolve) => {
    setTimeout(resolve, timeountMS);
  });

//***********************************************************
(async () => {

await sleep(200);

var minOffset = 0;
var dataAddress = Number(prompt("请输入要搜索的数据地址(0x开头十六进制)\n\nPlease enter the data address to be searched (hexadecimal starting with 0x)"));
if(!dataAddress) return alert("输入的参数有误\n\nIncorrect parameter entered");
if(h5gg.getValue(dataAddress, "I8")=="") return alert("无效的数据地址, 无法读取该地址\n\nInvalid data address, the address cannot be read");
var maxOffset = Number(prompt("请输入最大搜索偏移(0x开头十六进制)\n\nPlease enter the maximum search offset (hexadecimal starting with 0x)"));
if(!maxOffset) return alert("输入的参数有误\n\nIncorrect parameter entered");
var maxLevel = Number(prompt("请输入最大搜索层数\n\nPlease enter a maximum search level"));
if(!maxLevel) return alert("输入的参数有误\n\nIncorrect parameter entered");
    
/*/////////////////////////////////////////////////////////////

//*********************************************************************/

var AppModules = [];
var FoundChains = [];

var allmodules = h5gg.getRangesList();
for(var i=0; i<allmodules.length; i++)
{
    if(Number(allmodules[i].end)!=0 && allmodules[i].name.indexOf("/var/")!=-1) {
        allmodules[i].name = allmodules[i].name.replace(/(.+)\/([^\/]+)$/, "$2");
        AppModules.push(allmodules[i]);
    }
}

window.closeAutoSearchOffset = function() {
    $("#asopage").hide();
}

window.stopAutoSearchOffset = false;
window.pauseAutoSearchOffset = false;

function showlog(msg)
{
    console.log(msg);

    if($("#asopage").length==0) {
        var popup_progress_html = $('<div id="asopage" class="scrollbar" style="background-color: #FDFDFD; width:100%; height:100%; position:absolute; left:0; top:0; border:1px solid #B8B8B880; border-radius: 5px; padding: 0px; z-index: 99999;-webkit-user-select: all;-webkit-touch-callout: default;"></div>');
        $(document.body).append(popup_progress_html);
    }

    var html = msg;

    if(!window.stopAutoSearchOffset) {
        html += "<br/><button onclick='window.stopAutoSearchOffset=true;'>停止Stop</button>";
        if(window.pauseAutoSearchOffset)
            html += "<button onclick='window.pauseAutoSearchOffset=false;'>继续Continue</button>";
        else
            html += "<button onclick='window.pauseAutoSearchOffset=true;'>暂停Pause</button>";
    }

    html += "<br/><br/>已找到"+FoundChains.length+"条偏移链(Found "+FoundChains.length+" chian(s)).";
 
    if(FoundChains.length>0) {
        for(var n=FoundChains.length; n>0; n--) {
            html += "<br/>[" + n + "] "+FoundChains[n-1];
        }
    }

    if(window.stopAutoSearchOffset) html += "<br/><br/><button onclick='window.closeAutoSearchOffset()'>关闭Close</button>";

    $("#asopage").html(html);
    $("#asopage").show();
}

function checkInModule(address, chain)
{
    for(var i=0; i<AppModules.length; i++)
    {
        address = Number(address);
        if(address>Number(AppModules[i].start) && address<Number(AppModules[i].end))
        {
            var offset = address - Number(AppModules[i].start);
            var info = AppModules[i].name + ":0x" + offset.toString(16);
            if(chain.length>0) info += " -> " + chain.join(" -> ");
            //showlog("找到偏移链 "+info);
            FoundChains.push(info);
            //throw "ok";
        }
    }
}

var gLevelResults = [ { addr:dataAddress, chain:[] } ];

for(var level=0; level<maxLevel; level++)
{
    var LevelResults = gLevelResults;
    gLevelResults = [];

    showlog("开始搜索第"+(level+1)+"层...");

    for(var i=0; i<LevelResults.length; i++)
    {
        var dataAddress = LevelResults[i].addr;
        var chain = LevelResults[i].chain;

        var start = Number(dataAddress) - maxOffset;
        var end = Number(dataAddress) - minOffset;

        h5gg.clearResults();
        h5gg.searchNumber(Number(start)+'~'+Number(end), "U64", "0x0", "0xFFFFFFFF00000000");
        var count = h5gg.getResultsCount();

        await sleep(100);

        var info = "搜索第"+(level+1)+"层第"+(i+1)+"/"+LevelResults.length+"个指针=>"+gLevelResults.length+"+"+count;
        info += "<br/>searching...level="+(level+1)+",index="+(i+1)+"/"+LevelResults.length+"=>"+gLevelResults.length+"+"+count;
        showlog(info);

        while(true)
        {
            if(!window.pauseAutoSearchOffset || window.stopAutoSearchOffset)
                break;
            await sleep(100);
        }
        
        if(window.stopAutoSearchOffset) break;

        var results = h5gg.getResults(count);

        results.map(function(obj) {
            var offset = Number(dataAddress) - Number(obj.value);
            offset = '0x'+offset.toString(16);
            var chain2 = [offset, ...chain];
            checkInModule(obj.address, chain2);
            gLevelResults.push({addr:obj.address, chain:chain2});
            // obj.value='0x'+Number(obj.value).toString(16);
            // return obj;
        });

        //console.log(results);
    }

    if(window.stopAutoSearchOffset) break;

    //console.log(LevelResults);
}

window.stopAutoSearchOffset = true;

showlog("搜索完毕(Search Done)");

FoundChains = [];
AppModules = [];
gLevelResults = [];

})();
