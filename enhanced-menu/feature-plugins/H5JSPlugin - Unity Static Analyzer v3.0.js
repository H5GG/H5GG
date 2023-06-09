/*
    H5GG Plugin Mod Menu logic should enable easier Mod Menu development for non-jailbroken. It preserve existing H5GG UI and features, while adding new cheat menu.
    First implementation of core H5GG menu feature through Plugin approach. It aims to demonstrate the capability of JS Plugin. 
    Implementation of Unity Static Analyzer with 
    - il2cpp dumper like Class, Field, Method dump and allow searching. Properties is not implemented, as it mostly covered by Method.
    - Network Graph show Inter-class relation
    - Detail view on Class with available on Scene Object List to allow easy access 
    Contribute by Happy Secret on iOSGods (2023)
*/

var script = initializeUnitySupport();
var isRunning = false;
var isStopProcess = false;
var throttledUIUpdate = throttle(updateUnityStaticProgress, 500);
var throttledGraphUpdate = throttle(updateUnityGraphProgress, 500);
var UnityStaticGraphNetworkMaxHop = 5;

/* Add button on H5GG UI to open the Cheat UI, if it does not exist */
if ($("#unitypluginmodmenu").length == 0) {
    var btn = $('<button id="unitypluginmodmenu">UA</button>');
    btn.attr("credit", "Happy Secret");
    btn.click(function () {
        $("#unitypluginpage").show();
    });
    //backward compatible with standard H5GG menu
    if ($("#frontview").length == 0) {
        $('#results_count').after(btn);
    } else {
        $("#frontview").append(btn);
    }
}

/* Create the Cheat UI Layer, if it does not exist */
if ($("#unitypluginpage").length == 0) {
    var popup_unitystaticanalyzer_html = $('<div id="unitypluginpage"  style="background-color: #FDFDFD; width:100%; height:100%; position:absolute; left:0; top:0; border:1px solid #B8B8B880; border-radius: 5px; padding: 0px; -webkit-user-select: all;-webkit-touch-callout: default;"></div>');
    $(document.body).append(popup_unitystaticanalyzer_html);
}
if ($("#unitypluginclasspage").length == 0) {
    var popup_unitystaticclassanalyzer_html = $('<div id="unitypluginclasspage"  style="background-color: #FDFDFD; width:100%; height:100%; position:absolute; left:0; top:0; border:1px solid #B8B8B880; border-radius: 5px; padding: 0px; -webkit-user-select: all;-webkit-touch-callout: default;"></div>');
    $(document.body).append(popup_unitystaticclassanalyzer_html);
}
if ($("#unitypluginclassdetailpage").length == 0) {
    var popup_unitystaticclassdetail_html = $('<div id="unitypluginclassdetailpage"  style="background-color: #FDFDFD; width:100%; height:100%; position:absolute; left:0; top:0; border:1px solid #B8B8B880; border-radius: 5px; padding: 0px; -webkit-user-select: all;-webkit-touch-callout: default;"></div>');
    $(document.body).append(popup_unitystaticclassdetail_html);
}


/* Generate Clean Cheat Menu UI - Base Unity Static UI*/
var html = '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Unity Static Analyzer by Happy Secret';
html += '<div style="float:right; font-size:16px; font-family: Arial, sans-serif;" onclick="closeunitypluginpage()">&nbsp;X&nbsp;</div>';
html += '<input id="searchInput" type="text" name="searchKey" placeholder="Interesting Stuff..." onkeydown="handleUnityStaticAnalyzeKeyDown(event)">'
html += '<label><input name="unityStaticradio-group1" type="radio" value="klass" checked onclick="refreshStaticSearch(this)" />Klass</label>'
html += '<label><input name="unityStaticradio-group1" type="radio" value="field" onclick="refreshStaticSearch(this)" />Field</label>'
html += '<label><input name="unityStaticradio-group1" type="radio" value="method" onclick="refreshStaticSearch(this)" />Method</label>'
html += '<div id="unitystaticinfo" class="menuview current scrollbar" style="height:calc(100% - 55px); overflow-x:auto;">'
html += '<table id="unitystaticinfolist" class="tblHover" style="width:100%;" border="1" cellspacing=0 cellpadding=0>'
html += '<tr><th>Name</th><th>Namespace</th><th>Parent</th><th>Klass</th><th>Pklass</th></tr>'
html += '</table>'
html += '</div>'
html += '<label>&nbsp;&nbsp;Touch and hold item to see Class Network. </label>'
html += '<div id="unitystaticprogresscontainer" style="display: none;position: absolute;top: 50vh;left: 50vw;transform: translate(-50%, -50%);z-index: 99999; width:50vw">'
html += '<div id="unitystaticprogressbase" style="width: 100%; background-color: #ddd;" onclick="confirmStopProcess()">'
html += '<div id="unitystaticprogressdivbar" style="width: 1%; height: 30px; background-color: #04AA6D;text-align: center;line-height: 30px;color: white;"></div></div>'

html += '</div>'

$("#unitypluginpage").html(html);

/* Generate Clean Cheat Menu UI - Base Unity Static UI*/
var html = '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Unity Static Class View - ';
html += '<label id="unityStaticClassName"> </label>'
html += '<button id="action">&#9874;</button>'
html += '<button id="spread" onclick=spreadUnityGraph()>&#9875;</button>'
html += '<div style="float:right; font-size:16px; font-family: Arial, sans-serif;" onclick="closeunitypluginclasspage()">&nbsp;X&nbsp;</div>';

html += '<div id="unityclassstaticinfo" class="menuview current scrollbar" style="height:calc(100% - 55px);overflow-x:auto;">'
html += '</div>'
html += '<label>&nbsp;&nbsp;[WARNING]&nbsp;&nbsp;It could take quite a bit of time of the network is complex. Processed:&nbsp;&nbsp;</label>'
html += '<label id="unityStaticGraphStatus"> </label>'

$("#unitypluginclasspage").html(html);

/* Generate Clean Cheat Menu UI - Base Unity Static Detail UI*/
var html = '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Unity Static Class Detail View - ';
html += '<label id="unityStaticClassNameDetail"> </label>'
html += '<div style="float:right; font-size:16px; font-family: Arial, sans-serif;" onclick="closeunitypluginclassdetailpage()">&nbsp;X&nbsp;</div>';
html += '<br>'
html += '<label><input name="unityStaticradio-group2" type="radio" value="klass" checked onclick="refreshStaticDetail(this)" />Klass</label>'
html += '<label><input name="unityStaticradio-group2" type="radio" value="field" onclick="refreshStaticDetail(this)" />Field</label>'
html += '<label><input name="unityStaticradio-group2" type="radio" value="method" onclick="refreshStaticDetail(this)" />Method</label>'
html += '<div id="unityclassstaticdetailinfo" class="menuview current scrollbar" style="height:calc(100% - 65px);overflow-x:auto;">'
html += '<table id="unitystaticdetailinfolist" class="tblHover" style="width:calc(100% - 10px)" border="1" cellspacing=0 cellpadding=0>'
html += '<tr><th>Property</th><th>Detail</th></tr>'
html += '</table>'
html += '</div>'
html += '<label>&nbsp;&nbsp;Touch on the Klass -> On Scene Object(s) row to refresh Object(s). </label>'

$("#unitypluginclassdetailpage").html(html);


// Check if the vis-network script is already loaded
var isVisNetworkLoaded = Array.from(document.getElementsByTagName('script')).some((script) => {
    return script.src === 'https://unpkg.com/vis-network/standalone/umd/vis-network.min.js';
});

// If the script is not already loaded, add it to the page
if (!isVisNetworkLoaded) {
    let scriptElement = document.createElement('script');
    scriptElement.setAttribute('src', 'https://unpkg.com/vis-network/standalone/umd/vis-network.min.js');
    document.head.appendChild(scriptElement);
}

/*************functional****************/

function handleUnityStaticAnalyzeKeyDown(event) {
    if (event.keyCode === 13) {
        refreshStaticSearch()
    }
}

function confirmStopProcess() {
    var confirmed = confirm("Are you sure you want to stop this process?");
    if (confirmed) {
        isStopProcess = true
        isRunning = false
        const progressContainer = document.getElementById('unitystaticprogresscontainer');
        progressContainer.style.display = 'none';
    }
}

function refreshStaticSearch() {
    let searchType = $("input:radio[name=unityStaticradio-group1]:checked").val()
    $("table#unitystaticinfolist tr").remove();

    var searchStr = $("#searchInput").val().trim().toLowerCase()
    if (!searchStr) return
    else searchStr = "*" + searchStr + "*"
    isStopProcess = false;
    switch (searchType) {
        case "klass":
            updateKlassPromise(searchStr)
            break;
        case "field":
            updateFieldPromise(searchStr)
            break;
        case "method":
            updateMethod(searchStr)
            break;
    }

    function updateKlassPromise(searchStr) {
        var row = '<tr><th>Name</th><th>Namespace</th><th>Parent</th><th>Klass</th><th>Pklass</th></tr>'
        $("table#unitystaticinfolist tbody").append(row);
        let ary = searchLevel1Keys(window.gUnityClasses, searchStr)
        if (ary.length == 0) {
            alert("No class meet search criteria: " + searchStr)
            return
        }

        let i = 0;
        const progressContainer = document.getElementById('unitystaticprogresscontainer');
        progressContainer.style.display = 'block';

        function processKlass() {

            row = '<tr ontouchstart="longTouchOpenUnityStaticClass(\'' + ary[i] + '\')" ontouchend="resetTouch()">'

            let objInfo = script.call("findUnityObjectOfType", [ary[i], true])
            if (typeof objInfo !== "undefined" && objInfo.length > 0) {
                row += '<td onclick="onShowUnityObjInfo(true,' + objInfo[0] + ')" bgcolor="yellow">' + ary[i].split("$").pop() + '</td>'
                debugInfo("Search Klass: " + searchStr + " -> " + ary[i] + " [" + objInfo.length + "]", objInfo)
            } else {
                let monsterArj = nestsearchLevel3Keys(window.gUnityClasses, ary[i].split("$").pop())
                let j = -1
                for (j = 0; j < monsterArj.length; j++) {
                    objInfo = script.call("findUnityObjectOfType", [monsterArj[j].level1Key, true])
                    if (typeof objInfo !== "undefined" && objInfo.length > 0) break;
                }
                if (typeof objInfo !== "undefined" && objInfo.length > 0) {
                    row += '<td onclick="onShowUnityObjInfo(true,' + (Number(objInfo[0]) + Number(window.gUnityClasses[monsterArj[j].level1Key][monsterArj[j].level2Key].offset)) + ')" bgcolor="pink">' + ary[i].split("$").pop() + '</td>'
                    debugInfo("Search Klass: " + searchStr + " -> " + ary[i] + " -> " + monsterArj[j].level1Key + "(" + objInfo[0] + ") + " + window.gUnityClasses[monsterArj[j].level1Key][monsterArj[j].level2Key].offset + " [" + objInfo.length + "]", objInfo)
                } else
                    row += '<td>' + ary[i].split("$").pop() + '</td>'
            } //longTouchOpenUnityStaticClass

            row += '<td>' + window.gUnityClasses[ary[i]].namespace + '</td>'
            row += '<td>' + window.gUnityClasses[ary[i]].parentName + '</td>'
            row += '<td>' + window.gUnityClasses[ary[i]].klass + '</td>'
            row += '<td>' + window.gUnityClasses[ary[i]].parentClass + '</td>'
            row += '</tr>'
            $("table#unitystaticinfolist tbody").append(row);

            // Check if we're done
            throttledUIUpdate(Math.round((i + 1) / ary.length * 100));

            i++;
            if (i < ary.length && !isStopProcess) {
                // Wait for the UI update to complete before moving on to the next chunk of heavy work
                return new Promise(resolve => setTimeout(resolve, 0)).then(processKlass);
            }
        }

        processKlass()
    }

    function updateFieldPromise(searchStr) {

        var classObj = {}
        var row = '<tr><th>Offset</th><th>Name</th><th>Type</th><th>Class</th><th>Namespace</th></tr>'
        $("table#unitystaticinfolist tbody").append(row);
        //Search through level2 key (fieldname /mehtodname)
        let ary = searchLevel2Keys(window.gUnityClasses, searchStr)
        if (ary.length == 0) {
            alert("No field meet search criteria: " + searchStr)
            return
        }

        let i = 0;
        const progressContainer = document.getElementById('unitystaticprogresscontainer');
        progressContainer.style.display = 'block';

        function processField() {
            //skip if it is not field related (method related)
            if (ary[i].value.hasOwnProperty("fieldClassName")) {

                row = '<tr ontouchstart="longTouchOpenUnityStaticClass(\'' + ary[i].level1Key + '\')" ontouchend="resetTouch()">'

                let objInfo = script.call("findUnityObjectOfType", [ary[i].level1Key, true])
                if (typeof objInfo !== "undefined" && objInfo.length > 0) {
                    classObj[ary[i].level1Key] = objInfo;
                    row += '<td onclick="onShowUnityObjInfo(true,' + (Number(objInfo[0]) + Number(ary[i].value.offset)) + ')" bgcolor="yellow">' + ary[i].value.offset + '</td>'
                    debugInfo("Search Klass: " + searchStr + " -> " + ary[i].level2Key + " -> " + ary[i].level1Key + " + " + ary[i].value.offset + " [" + objInfo.length + "]", objInfo)
                } else {
                    let monsterArj = nestsearchLevel3Keys(window.gUnityClasses, ary[i].level1Key.split("$").pop())
                    let j = -1
                    let k = -1
                    for (j = 0; j < monsterArj.length; j++) {
                        //TODO: Special Handle data hidden under generic type later (Different type need different access method), skip for now
                        if (window.gUnityClasses[monsterArj[j].level1Key][monsterArj[j].level2Key].fieldGenericType != "") continue;
                        objInfo = classObj[monsterArj[j].level1Key];
                        if (!objInfo)
                            objInfo = script.call("findUnityObjectOfType", [monsterArj[j].level1Key, true])
                        if (typeof objInfo !== "undefined" && objInfo.length > 0) {
                            classObj[monsterArj[j].level1Key] = objInfo;
                            break;
                        }
                    }
                    if (typeof objInfo !== "undefined" && objInfo.length > 0) {
                        for (k = 0; k < objInfo.length; k++) {
                            targetObj = readPtr(Number(objInfo[k]) + Number(window.gUnityClasses[monsterArj[j].level1Key][monsterArj[j].level2Key].offset)) + Number(ary[i].value.offset)

                            if (targetObj > 0x100000000 && targetObj < 0x280000000) break
                            else targetObj = 0x0;
                        }
                        if (targetObj != 0x0) {
                            row += '<td onclick="onShowUnityObjInfo(true,' + targetObj + ')" bgcolor="pink">' + ary[i].value.offset + '</td>'
                            debugInfo("Search Klass: " + searchStr + " -> " + ary[i].level2Key + " -> " + ary[i].level1Key + " + " + ary[i].value.offset + " -> " + monsterArj[j].level1Key + "(" + objInfo[k] + ") + " + window.gUnityClasses[monsterArj[j].level1Key][monsterArj[j].level2Key].offset + " [" + objInfo.length + "]", objInfo)
                        } else row += '<td>' + ary[i].value.offset + '</td>'
                    } else
                        row += '<td>' + ary[i].value.offset + '</td>'
                }

                row += '<td>' + ary[i].level2Key + '</td>'
                row += '<td>' + ary[i].value.fieldClassName + '</td>'
                row += '<td>' + ary[i].level1Key.split("$").pop() + '</td>'
                row += '<td>' + ary[i].level1Key.substring(0, ary[i].level1Key.lastIndexOf("$")) + '</td>'
                row += '</tr>'

                $("table#unitystaticinfolist tbody").append(row);
            } //end if has fieldClassName

            // Check if we're done
            throttledUIUpdate(Math.round((i + 1) / ary.length * 100));

            i++;
            if (i < ary.length && !isStopProcess) {
                // Wait for the UI update to complete before moving on to the next chunk of heavy work
                return new Promise(resolve => setTimeout(resolve, 0)).then(processField);
            }
        }

        processField()
    }


    function updateMethod(searchStr) {
        var row = '<tr><th>Name</th><th>Return Type</th><th>Offset</th><th>Class</th><th>Namespace</th></tr>'
        $("table#unitystaticinfolist tbody").append(row);
        let ary = searchLevel2Keys(window.gUnityClasses, searchStr)
        if (ary.length == 0) alert("No method meet search criteria: " + searchStr)
        for (let i = 0; i < ary.length; i++) {
            if (!ary[i].value.hasOwnProperty("methodOffset")) continue;
            //row = '<tr>'
            row = '<tr ontouchstart="longTouchOpenUnityStaticClass(\'' + ary[i].level1Key + '\')" ontouchend="resetTouch()">'
            row += '<td>' + ary[i].level2Key + '</td>'
            row += '<td>' + ary[i].value.returnClassName + '</td>'
            row += '<td>' + ary[i].value.methodOffset + '</td>'
            row += '<td>' + ary[i].level1Key.split("$").pop() + '</td>'
            row += '<td>' + ary[i].level1Key.substring(0, ary[i].level1Key.lastIndexOf("$")) + '</td>'
            row += '</tr>'
            $("table#unitystaticinfolist tbody").append(row);
        }

    }

    //Define helper function to help search with wild card (*)
    //Could be duplicate consider to remove one
    function searchLevel1Keys(obj, pattern) {
        let escapedPattern;
        if (pattern.indexOf(".") == -1 && pattern.indexOf("*") == -1) escapedPattern = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        else escapedPattern = pattern
        const regex = new RegExp(escapedPattern.replace(/\*/g, '.*'), 'i');
        return Object.keys(obj).filter(key => regex.test(key));
    }

    //not sure if it is faster with nested loop
    //var starttime = performance.now();
    function searchLevel2Keys(Obj, searchPattern) { //Field or Method
        let segments = searchPattern.split("*");
        let regexPattern = new RegExp("^" + segments.map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join(".*"), "i");
        let result = Object.entries(Obj)
            .flatMap(([level1Key, nestedObj]) =>
                Object.entries(nestedObj).filter(([level2Key, value]) =>
                    regexPattern.test(level2Key)
                ).map(([level2Key, value]) => ({
                    level2Key,
                    value,
                    level1Key
                }))
            );
        return result

    }

    function nestsearchLevel3Keys(Obj, searchPattern) { //nested search is faster on level 3 than flatmap
        let segments = searchPattern.split("*");
        let regexPattern = new RegExp("^" + segments.map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join(".*"), "i");
        let result = [];
        for (let level1Key in Obj) {
            if (Obj.hasOwnProperty(level1Key)) {
                let nestedObj = Obj[level1Key]; //Level1Key is Klass
                for (let level2Key in nestedObj) {
                    if (nestedObj.hasOwnProperty(level2Key)) {//Leve2Key is info/field name/method name
                        let nestedNestedObj = nestedObj[level2Key];
                        for (let level3Key in nestedNestedObj) {//Level3Key is "fieldClassName"
                            //For Non-exact match - We can use regexPattern.test(nestedNestedObj[level3Key]) 
                            if (nestedNestedObj.hasOwnProperty("fieldClassName") && (nestedNestedObj[level3Key] == searchPattern)) {
                                result.push({
                                    level3Key,
                                    value: nestedNestedObj[level3Key],
                                    level2Key,
                                    level1Key
                                });
                            }
                        }
                    }
                }
            }
        }

        return result;
    }
}

var visited;
var nodes;
var edges;
var network;

function renderChildGraphPromise(selectedClass, maxHops) {

    nodes = new vis.DataSet();
    edges = new vis.DataSet();


    let container = document.getElementById('unityclassstaticinfo');
    let data = {
        nodes: nodes,
        edges: edges,
    };
    let options = {

    };
    network = new vis.Network(container, data, options);

    // Add the selected class as the root node
    nodes.add({
        id: selectedClass,
        label: selectedClass,
        color: 'lightgray',
        shape: 'box',
        level: 0
    });

    // Traverse the relationships between classes and their fields up to 5 hops away
    if (!maxHops) maxHops = 5;
    visited = new Set([selectedClass]);

    //Start Process Child
    let queue = [{
        class_name: selectedClass,
        level: 0
    }];
    function processChild() {
        let {
            class_name,
            level
        } = queue.shift();
        if (level < maxHops) {

            let fields = window.gUnityClasses[class_name];
            for (let field_name in fields) {
                let field_type = fields[field_name]['fieldClassName'];
                let field_namespace = fields[field_name]['fieldNameSpace'];
                let field_fulltype = field_namespace + "$" + field_type;
                if (!window.gUnityClasses[field_fulltype]) continue;
                if (!visited.has(field_fulltype)) {
                    visited.add(field_fulltype);
                    queue.push({
                        class_name: field_fulltype,
                        level: level + 1
                    });
                    if (!nodes.get(field_fulltype)) {
                        nodes.add({
                            id: field_fulltype,
                            label: field_fulltype,
                            color: 'Gold',
                            shape: 'box',
                            level: level + 1
                        });
                    }
                    edges.add({
                        from: class_name,
                        to: field_fulltype,
                        arrows: 'to'
                    });
                }
            }
        } //end if <maxhop

        throttledGraphUpdate(class_name);

        if (queue.length > 0 && !isStopProcess) {
            // Wait for the UI update to complete before moving on to the next chunk of heavy work
            return new Promise(resolve => setTimeout(resolve, 0)).then(processChild);
        }
    } //End processChild

    processChild()

}

function renderParentGraphPromise(selectedClass, maxHops) {
    // Traverse the relationships between classes and their fields up to 5 hops away
    if (!maxHops) maxHops = 5;
    //Reset the visited, so that a class can be both child and parent, but then network will have two copy of the class at different level
    visited = new Set([selectedClass]);

    //Start Process Parent
    queue = [{
        class_name: selectedClass,
        level: 0
    }];

    function processParent() {
        let {
            class_name,
            level
        } = queue.shift();
        if (Math.abs(level) < maxHops) {


            for (let parent_class_name in window.gUnityClasses) {
                let parent_fields = window.gUnityClasses[parent_class_name];
                for (let parent_field_name in parent_fields) {
                    let parent_field_type = parent_fields[parent_field_name]['fieldNameSpace'] + "$" + parent_fields[parent_field_name]['fieldClassName'];
                    if (parent_field_type === class_name) {
                        if (!visited.has(parent_class_name)) {
                            visited.add(parent_class_name);
                            queue.push({
                                class_name: parent_class_name,
                                level: level - 1
                            });
                        }

                        if (!nodes.get(parent_class_name)) {
                            nodes.add({
                                id: parent_class_name,
                                label: parent_class_name,
                                color: 'PaleGreen',
                                shape: 'box',
                                level: level - 1,
                                parentLevel: [level - 1], //handle case that class is both child and parent.
                                fieldName: parent_field_name,
                                offset: parent_fields[parent_field_name]['offset']
                            });
                        } else {
                            tmpNode = nodes.get(parent_class_name)
                            //check if it is a child, if yes add parent level as well.
                            //if it is a parent already, it wont add additonal node info, keep it as closest level parent, however edge will still be added
                            if (!tmpNode.parentLevel) tmpNode.parentLevel = []
                            if (!tmpNode.parentLevel.includes(level - 1))
                                tmpNode.parentLevel.push(level - 1)
                        }

                        let existingEdges = edges.get().filter(function (edge) {
                            return edge.from === parent_class_name && edge.to === class_name &&
                                edge.arrows === 'to';
                        });

                        // if no matching edge exists, add the new edge
                        if (existingEdges.length === 0) {

                            edges.add({
                                from: parent_class_name,
                                to: class_name,
                                arrows: 'to'
                            });
                        }
                    }
                }
            }
        }
        throttledGraphUpdate(class_name);

        if (queue.length > 0 && !isStopProcess) {
            // Wait for the UI update to complete before moving on to the next chunk of heavy work
            return new Promise(resolve => setTimeout(resolve, 0)).then(processParent);
        }

    } //End processParent

    processParent()
}

function attachNetworkEvent() {
    network.on('hold', function (properties) {
        var ids = properties.nodes;
        var clickedNodes = nodes.get(ids);
        alert("clicked nodes: " + JSON.stringify(clickedNodes))
    });
}

function networkESP() {


}


function spreadUnityGraph() {
    /* Different avoid overlapping options
        "springConstant": 0,
        "avoidOverlap": 0.2
    */
    network.setOptions({
        "physics": {
            "barnesHut": {
                "gravitationalConstant": -3900,
                "centralGravity": 0
            },

            minVelocity: 1
        }
    });
    network.fit()
}

function getEdgeBetweenNodes(nodeID1, nodeID2) {
    return edges.get().filter(function (edge) {
        return (edge.from === nodeID1 && edge.to === nodeID2) || (edge.from === nodeID2 && edge.to === nodeID1);
    });
};

function refreshStaticDetail() {
    let displayType = $("input:radio[name=unityStaticradio-group2]:checked").val()
    let displayKlass = $("label#unityStaticClassNameDetail").text()
    $("table#unitystaticdetailinfolist tr").remove();

    switch (displayType) {
        case "klass":
            displayKlassDetail()
            break;
        case "field":
            displayFieldDetail()
            break;
        case "method":
            displayMethodDetail()
            break;
    }

    function displayKlassDetail() {
        var row = '<tr><th>Property</th><th>Detail</th></tr>'
        $("table#unitystaticdetailinfolist tbody").append(row);
        let klassInfo = window.gUnityClasses[displayKlass];
        if (!klassInfo) alert("Invalid cache for " + displayKlass)

        row = '<tr><td>klass</td><td>' + window.gUnityClasses[displayKlass].klass + '</td></tr>'
        row += '<tr><td>Assembly Image</td><td>' + window.gUnityClasses[displayKlass].klassImageName + '</td></tr>'
        row += '<tr><td>Namespace</td><td>' + window.gUnityClasses[displayKlass].namespace + '</td></tr>'
        row += '<tr><td>Parents</td><td>' + window.gUnityClasses[displayKlass].parents + '</td></tr>'
        row += '<tr onclick="refreshOnSceneObjectList()"><td>On Scene Object(s)</td><td id=onSceneObjectList></td></tr>'
        $("table#unitystaticdetailinfolist tbody").append(row);
        refreshOnSceneObjectList()
    }

    function displayFieldDetail() {
        var row = '<tr><th>Offset</th><th>Name</th><th>Type</th><th>Generic Type</th><th>Full Type Name</th></tr>'
        $("table#unitystaticdetailinfolist tbody").append(row);
        let klassInfo = window.gUnityClasses[displayKlass];
        if (!klassInfo) alert("Invalid cache for " + displayKlass)

        let keys = Object.keys(window.gUnityClasses[displayKlass])
        row = ""
        for (let i = 0; i < keys.length; i++) {
            if (!window.gUnityClasses[displayKlass][keys[i]].hasOwnProperty("fieldClassName")) continue;
            row += '<tr><td>' + window.gUnityClasses[displayKlass][keys[i]].offset + '</td>'
            row += '<td>' + keys[i] + '</td>'
            row += '<td>' + window.gUnityClasses[displayKlass][keys[i]].fieldClassName + '</td>'
            row += '<td>' + window.gUnityClasses[displayKlass][keys[i]].fieldGenericType + '</td>'
            row += '<td>' + window.gUnityClasses[displayKlass][keys[i]].fieldClassFullName + '</td>'
            row += '</tr>'
        }

        $("table#unitystaticdetailinfolist tbody").append(row);
        sortTable("unitystaticdetailinfolist", 0)
    }

    function displayMethodDetail() {
        var row = '<tr><th>Offset</th><th>Name</th><th>Return Type</th><th>Parameter List</th></tr>'
        $("table#unitystaticdetailinfolist tbody").append(row);
        let klassInfo = window.gUnityClasses[displayKlass];
        if (!klassInfo) alert("Invalid cache for " + displayKlass)

        let keys = Object.keys(window.gUnityClasses[displayKlass])
        row = ""
        for (let i = 0; i < keys.length; i++) {
            if (!window.gUnityClasses[displayKlass][keys[i]].hasOwnProperty("methodOffset")) continue;
            row += '<tr><td>' + window.gUnityClasses[displayKlass][keys[i]].methodOffset + '</td>'
            row += '<td>' + keys[i] + '</td>'
            row += '<td>' + window.gUnityClasses[displayKlass][keys[i]].returnClassName + '</td>'

            row += '<td>' + window.gUnityClasses[displayKlass][keys[i]].parameterList.replace(/, /g, ', \n') + '</td>'

            row += '</tr>'
        }

        $("table#unitystaticdetailinfolist tbody").append(row);
        sortTable("unitystaticdetailinfolist", 1)
    }


}

$("#unitypluginpage").hide();
$("#unitypluginclasspage").hide();
$("#unitypluginclassdetailpage").hide();


var timer;

function longTouchOpenUnityStaticClass(selectedKlass) {
    // Start the timer when the user touches the screen
    timer = setTimeout(function () {
        // If the timer completes, the user has performed a long press
        var result = showunitypluginclasspage(selectedKlass);
    }, 750); 	// Set the duration of the long press here (in milliseconds)
}

function resetTouch() {
    clearTimeout(timer);
}

function closeunitypluginpage() {
    $("#unitypluginpage").hide();
}

function showunitypluginclasspage(selectedClass) {
    $("label#unityStaticClassName").text(selectedClass)
    $("#unitypluginclasspage").show();
    isStopProcess = false

    $("#unitypluginclasspage").find("button#action").unbind("click").click(function () {
        showunitypluginclassdetailpage(selectedClass)
    });
    renderChildGraphPromise(selectedClass, UnityStaticGraphNetworkMaxHop)
    renderParentGraphPromise(selectedClass, UnityStaticGraphNetworkMaxHop)
}

function closeunitypluginclasspage() {
    $("#unitypluginclasspage").hide();
    nodes.clear();
    edges.clear();
    isStopProcess = true
}

function showunitypluginclassdetailpage(selectedClass) {
    $("label#unityStaticClassNameDetail").text(selectedClass)
    $("#unitypluginclassdetailpage").show();
    isStopProcess = true
    refreshStaticDetail();
}

function closeunitypluginclassdetailpage() {
    $("#unitypluginclassdetailpage").hide();
}
/*
function debugInfo(message, obj) {
    gDebug.push({
        text: message,
        address: obj
    }); //data format {text:textmessage, address:[0x1234, 0x5678], objData:[00 01 02, 03 04 05]} 
}*/

function updateUnityStaticProgress(completionPercentage) {
    const progressContainer = document.getElementById('unitystaticprogresscontainer');
    const progressDivBar = document.getElementById("unitystaticprogressdivbar");
    //debugInfo("progressbar" + completionPercentage, [progressDivBar])
    if (completionPercentage > 0 && completionPercentage < 100) {
        progressDivBar.style.width = completionPercentage + "%";
        progressDivBar.innerHTML = completionPercentage + "%";
        isRunning = true
    } else if (completionPercentage >= 100) {
        progressContainer.style.display = 'none';
        isRunning = false
    }
}

function updateUnityGraphProgress(className) {
    $("label#unityStaticGraphStatus").text(className)
    isRunning = true

    if (className == "DONE") isRunning = false
}

function getUnityNodesAtLevel(level) {
    var nodesAtLevel = [];
    //var nodesDataSet = network.body.data.nodes;

    // Iterate over all nodes in the DataSet
    nodes.forEach(function (node) {
        // If the node's level matches the desired level, add it to the nodesAtLevel array
        if (node.level === level || (node.parentLevel && node.parentLevel.includes(level))) {
            nodesAtLevel.push(node);
        }
    });


    return nodesAtLevel;
}

function refreshOnSceneObjectList() {
    let resultObj = {}
    let displayKlass = $("label#unityStaticClassNameDetail").text()
    let objectAry = script.call("findUnityObjectOfType", [displayKlass, true])
    if (!objectAry) { //Frida would have crashed or script got GC
        script = initializeUnitySupport(); //try initialize again
        alert("Frida would have lost. Tired auto heal.\n Please try again,. If it still failed, please restart the game")
        return
    }

    resultObj["direct"] = {
        parentName: "direct",
        level: [0],
        objectList: objectAry,
    }
    for (var i = -1; i > -5; i--) {
        let parentNodes = getUnityNodesAtLevel(i);
        for (var j = 0; j < parentNodes.length; j++) {
            let parentObjectAry = script.call("findUnityObjectOfType", [parentNodes[j].id, true])

            if (resultObj.hasOwnProperty(parentNodes[j].id)) {
                resultObj[parentNodes[j].id].level.push(i)
            } else {
                let tmpObj = {
                    parentName: parentNodes[j].id,
                    level: [i],
                    objectList: parentObjectAry,
                }
                resultObj[parentNodes[j].id] = tmpObj
            }
        }
    }

    let row = "";
    let keys = Object.keys(resultObj);
    for (var i = 0; i < keys.length; i++) { //loop though parents
        let tmp;
        let resultAry = resultObj[keys[i]].objectList
        if (resultAry.length == 0) continue; //this parent has no object instance found
        for (var j = 0; j < resultAry.length; j++) {//loop though parent object instance
            if (resultObj[keys[i]].level[0] == 0) {
                if (!tmp)
                    tmp = '<a href=# onclick="onShowUnityObjInfo(true,' + resultAry[j] + ',true)">' + resultAry[j] + '</a>';
                else
                    tmp = tmp + ', ' + '<a href=# onclick="onShowUnityObjInfo(true,' + resultAry[j] + ',true)">' + resultAry[j] + '</a>';
            } else {
                let tmpObjAry = []
                for (let n = 0; n < resultObj[keys[i]].level.length; n++) {
                    if (resultObj[keys[i]].level[n] == 0) continue;
                    let tmpAry = getTargetObj(resultObj[keys[i]], resultAry[j], [], resultObj[keys[i]].level[n])
                    if (tmpAry && tmpAry.length > 0) tmpObjAry = tmpObjAry.concat(tmpAry)
                }

                if (tmpObjAry.length == 0) continue;
                for (let k = 0; k < tmpObjAry.length; k++) {
                    let targetObjs = tmpObjAry[k].targetObjs;
                    for (let l = 0; l < targetObjs.length; l++) { //target objects through a certain field
                        if (l == 0) tmp = '<a href=# onclick="onShowUnityObjInfo(true,' + targetObjs[l] + ',true)">' + targetObjs[l] + '</a>';
                        else tmp = tmp + ', ' + '<a href=# onclick="onShowUnityObjInfo(true,' + targetObjs[l] + ',true)">' + targetObjs[l] + '</a>';
                    }
                    row += '<tr><td>&#8658;' + keys[i] + '(Object: ' + '<a href=# onclick="onShowUnityObjInfo(true,' + resultAry[j] + ',true)">' + resultAry[j] + '</a>'
                        + ', Level: ' + resultObj[keys[i]].level + ')&#8658;<br>'
                    row += '<span style="font-size: 70%;"> - '

                    let path = tmpObjAry[k].path
                    for (let m = 0; m < path.length; m++) {
                        row += path[m].fieldName + ' (' + path[m].offset + ') &#8658; ' + path[m].targetObjKlass
                        if (path[m].targetObjKlass != displayKlass) row += ' (' + path[m].targetObjs + ')'
                        row += ' &#8658; '
                    }
                    row += '</span></td><td>' + tmp + '</td><tr>'

                }
            }
        }
        if (resultObj[keys[i]].level[0] == 0) {
            row += '<tr><td>&#8658;' + keys[i] + '(0)&#8658;<br>'
            row += '</td><td>' + tmp + '</td><tr>'
        }
    }
    $("table#unitystaticdetailinfolist tbody").append(row);

    function getTargetObj(infoObj, curUnityObj, pathAry, level) {
        if (!pathAry) pathAry = []; //initialize if empty
        if (level == 0) return curUnityObj; //this line in fact never executed, we dont call getTargetObj at level == 0
        else if (level == -1) {
            let curLvBranchObjInfos = extractObjFromFields(curUnityObj, infoObj.parentName, displayKlass, pathAry)
            return curLvBranchObjInfos;

        } else if (level < -1) {//covering -2, -3, -4 level (level < -1)
            //it could have multiple field having the same target field type 
            let tmpEdges = edges.get().filter(function (edge) {
                return edge.from === infoObj.parentName;
            });

            let curLvBranchObjInfos = []
            for (let i = 0; i < tmpEdges.length; i++) {
                let nextLevelNode = nodes.get(tmpEdges[i].to);
                let nextLevelInfoObj = resultObj[nextLevelNode.id];

                if (!nextLevelInfoObj) {//meaning it is outside the draw range (maxhop)
                    debugInfo("Cannot found Next Level Info Object: " + nextLevelNode.id + " [" + resultObj.length + "]", [resultObj])
                    continue;
                } else if (!nextLevelInfoObj.level.includes(level + 1)) continue;
                let tmpCurLvBranchObjInfos = extractObjFromFields(curUnityObj, infoObj.parentName, nextLevelNode.id, pathAry)
                //call next level
                for (let j = 0; j < tmpCurLvBranchObjInfos.length; j++) { //different field reference
                    let newPathAry = tmpCurLvBranchObjInfos[j].path;
                    let nextLevelObjs = tmpCurLvBranchObjInfos[j].targetObjs;
                    for (let k = 0; k < nextLevelObjs.length; k++) { //same field could have multiple object (generic type)
                        let tmpResult = getTargetObj(nextLevelInfoObj, nextLevelObjs[k], newPathAry, level + 1)
                        if (tmpResult.length > 0) curLvBranchObjInfos = curLvBranchObjInfos.concat(tmpResult)
                    }
                }

            }//end for loop on edges
            return curLvBranchObjInfos;
        }
    }

    function extractObjFromFields(SourceObj, SourceObjKlass, TargetObjKlass, pathAry) {
        let resultObj = []
        //window.gUnityClasses
        let SourceKlassInfo = window.gUnityClasses[SourceObjKlass]; //Level1Key is Klass
        for (let level2Key in SourceKlassInfo) {
            //if there are multiple field having target field type, it will add all
            if (SourceKlassInfo.hasOwnProperty(level2Key) && SourceKlassInfo[level2Key]["fieldClassName"] == TargetObjKlass.split("$").pop()) {//Leve2Key is info/field name/method name
                //get valid object (s) with offset (genericType would have multiple Objects)
                let targets = [];
                let curPathAry = pathAry.slice(); //reset path to input, decouple different field path (not mixed together), force it to create a separate copy
                let tmpAddr = readPtr(Number(SourceObj) + Number(SourceKlassInfo[level2Key]["offset"]));
                //0x0 is pointing to class type, but sometime it looks used to do loop back instance. hard code to patch it back the instance address
                if (SourceKlassInfo[level2Key]["offset"] == 0) tmpAddr = Number(SourceObj)

                if (tmpAddr == 0x0) continue; //no pointer exists
                if (SourceKlassInfo[level2Key]["fieldGenericType"] == "")
                    targets.push("0x" + tmpAddr.toString(16))
                else {
                    //Process generic type 
                    //handle list type first
                    if (SourceKlassInfo[level2Key]["fieldGenericType"].indexOf("List") != -1) {
                        let objList = new UnityList(tmpAddr);

                        for (let i = 0; i < objList.size(); i++) {
                            tmpAddr = objList.get_Item(i);
                            if (tmpAddr == 0x0) continue; //no real pointer exists, it could be a list storing list of empty items
                            targets.push("0x" + tmpAddr.toString(16))
                        }
                        if (targets.length == 0) continue; //no pointer exists
                    } else continue; //cannot handle other generic type 
                }
                curPathAry.push({
                    fieldName: level2Key,
                    offset: SourceKlassInfo[level2Key]["offset"],
                    fieldKlassName: TargetObjKlass.split("$").pop(),
                    fieldGenericType: SourceKlassInfo[level2Key]["fieldGenericType"],
                    sourceObj: SourceObj,
                    targetObjs: targets,
                    sourceObjKlass: SourceObjKlass,
                    targetObjKlass: TargetObjKlass,
                })
                resultObj.push({
                    path: curPathAry,
                    targetObjs: targets,
                });
            }
        }
        return resultObj;
    }
}
/*
//START: Define Unity List Object for easy List access
function UnityList(address) {
    this._address = address;
    this._size = readInt(Number(address) + 0x18);
    this._items = readPtr(Number(address) + 0x10);
}

UnityList.prototype.size = function () {
    return this._size;
}

UnityList.prototype.get_Item = function (index) {
    //NOT SURE IF IT HAS TO BE POINTER, WHAT HAPPENS TO PRIMITIVE TYPES
    //Normally what we really want is object of certain type of interest, say Player, Skill, etc
    return readPtr(Number(this._items) + 0x20 + (index * 8));
}

//END: Define Unity List Object for easy List access
*/
function throttle(fn, delay) {
    let timerId;
    let lastExecutionTime = 0;
    let lastResult;
    return function () {
        const now = Date.now();
        const timeSinceLastExecution = now - lastExecutionTime;
        if (timeSinceLastExecution >= delay) {
            lastExecutionTime = now;
            lastResult = fn.apply(this, arguments);
        } else {
            clearTimeout(timerId);
            timerId = setTimeout(() => {
                lastExecutionTime = Date.now();
                lastResult = fn.apply(this, arguments);
            }, delay - timeSinceLastExecution);
        }
        return lastResult;
    };
}

function sortTable(tablename, columnIndex) {
    var table = document.getElementById(tablename);
    var rows = table.rows;
    var switching = true;
    var shouldSwitch;
    var i;
    while (switching) {
        switching = false;
        for (i = 1; i < (rows.length - 1); i++) {
            shouldSwitch = false;
            var x = rows[i].getElementsByTagName("td")[columnIndex];
            var y = rows[i + 1].getElementsByTagName("td")[columnIndex];
            if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                shouldSwitch = true;
                break;
            }
        }
        if (shouldSwitch) {
            rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
            switching = true;
        }
    }
}

setLayoutAction(function (w, h) {
    var width = 800;
    var height = 600; //默认尺寸370/400
    if (w < h) {
        height = 600; //竖屏模式加大显示高度
    }
    width = Math.min(width, w); //适配iPad浮窗, 最大宽度不超出
    height = Math.min(height, h); //适配老设备, 最大高度不超出
    var x = (w - width) / 2;
    var y = (h - height) / 2;
    if (w < h) {
        y = Math.max(20, y);
        height = Math.min(height, h - y);
    }
    setWindowRect(x, y, width, height);
});