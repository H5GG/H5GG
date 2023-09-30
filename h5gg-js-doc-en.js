**************** H5GG JavaScript Engine Document (update on v7.5) ********************

h5gg is the engine object, which can call the following functions (similar to the lua interface of Android gg, but the parameters are somewhat different)


h5gg.require(H5GG version number); //Set the minimum H5GG version number required by the script, which can be written in the first line at the beginning of the script

h5gg.setFloatTolerance('floating-point deviation'); //Set the deviation range of F32/F64 floating-point search, the engine defaults to 0.0

h5gg.searchNumber('value', 'type', 'search lower limit', 'search upper limit'); //Search or secondary search (improve) exact value

h5gg.searchNearby('value', 'type', 'adjacent range'); //Nearby (joint) search, consistent with igg's

h5gg.getValue('address', 'type'); //Read the value of the specified address, return the value string

h5gg.setValue('Address', 'Value', 'Type'); //Set the value of the specified address, return success or failure

h5gg.editAll('value', 'type'); //Modify all the values in the search results (cannot be called after clearing the results), and return the number of successful modifications

h5gg.getResultsCount(); //Get the total number of search results, return the total number

h5gg.getResults('GetCount', 'SkipCount'); //Get the result array, each element has three attributes of address, value and type

h5gg.clearResults(); //Clear search results, start a new search

h5gg.getRangesList('module file name'); //Return the module array, the module has start (base address), end (end address), name (path) attributes
(If the module file name=0, it will return the APP main program module information, if the module file name is not passed in, it will return a list of all modules)

h5gg.loadPlugin('Objective-C Class Name','dylib file path'); //load a dylib plugin, return an OC Instance Object (The returned OC object instance can be called directly in js, dylib supports absolute path or relative path in .app)


For standalone CrosProc APP version only:

h5gg.setTargetProc(process number); //Set the current target process, return success or failure

h5gg.getProcList('process name'); //Get the process array, the elements in the array have pid (process number), name (process name) attributes
(If the process name is not passed in, it will return a list of all running app processes, which can be called periodically to determine whether the target process has ended)


Other APIs:

setButtonImage(icon); //Set the icon of the floating button, you can pass in the http starting URL image or the base64 encoded DataURL image

setButtonAction(js callback function); //Set a custom floating button icon click action, which is called when a js function is passed in to click

setWindowRect(x, y, width, height); //Modify the position and size of the window suspended on the screen

setWindowDrag(x, y, width, height); //Set the area of the draggable floating window in the H5 page

setWindowTouch (whether to respond to touch); //true=the entire floating window is impenetrable by touch, false=the entire floating window can be touched by touch

setWindowVisible (whether to display), //Set the visibility of the floating window, true=display, false=hidden

setLayoutAction(js callback function); //Set the js callback when the screen rotates or the iPad split screen float changes, the callback function parameters are (width, height)



Notice:

1: The address parameter supports automatic identification in decimal or hexadecimal format starting with 0x, other parameters must be in string format

2: float number types: F32, F64, signed number types: I8, I16, I32, I64, unsigned number types: U8, U16, U32, U64

3: If there are many search results, do not get all the data at one time with getResults, it maybe crash for using too mach memory, and should be obtained in sections

4: The address and value of the search result are all string types. If you want to do digital operations, please use Number(x) to convert them into numeric types before you can perform operations.
(Unlike lua, which automatically converts the string types on both sides of the + sign to numeric types, in js, if the + sign is a string, the two strings will be concatenated)

5: The numeric type can be converted into a hexadecimal string format with x.toString(16), but x must be a numeric type to convert successfully

6: The numerical value of the search supports the range format, such as "50～100", such as "2.3～7.8", both searchNumber and searchNearby search are supported

5: The default size of the floating window is 370 points wide and 370 points high. You can set the position, size and draggable area through the js api on the H5 page.

