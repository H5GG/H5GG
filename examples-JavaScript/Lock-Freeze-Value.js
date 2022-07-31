h5gg.require(7.8); //min version

h5gg.clearResults();
h5gg.searchNumber("123", "I32", "0x0", "0xFFFFFFFF00000000");
var count = h5gg.getResultsCount();
var results = h5gg.getResults(count);

var locker = setInterval(function() {
    console.log("running...");
    for(var i=0; i<count; i++) {
        h5gg.setValue(results[i].address, "456", "I32");
    }
},
500  //lock/freeze time interval (millseconds)
);

//then we can cancel the lock/freeze:
//clearInterval(locker);
