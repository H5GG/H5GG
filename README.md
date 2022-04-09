# H5GG

an iOS cheat engine for JavaScript APIs & Html5 UI.

provide memory apis likely (Android)GameGuardian's Lua APIs.

support load scripts(*.js or *.html file)

and you can customize UI by using HTML+CSS.

and you can make your own tweak(dylib) by click one button, then just select your icon and .html file, so easy!

supported 3 modes to run:

1: inject to ipa in non-jailbreak devices

2: tweak(deb) in jailbroken devices

3: standalone APP(deb) in jailbroken devices

it's completely free & open source!
 
![text](https://static.gameguardian.net/monthly_2022_04/image.thumb.png.433774be109efdf5813f767a9bd9edb4.png)

![text](https://static.gameguardian.net/monthly_2022_04/image.thumb.png.c814bd0ae4ea89f3aa260e50d03172e8.png)

![text](https://static.gameguardian.net/monthly_2022_04/image.thumb.png.20dce31a6fb8d9458c569a05b3bd3349.png)

currently supported JS APIs:

<!--script>
**************** H5GGv5.2 ** JS script engine ********************
<h5gg> is the engine object, which can call the following functions (similar to the lua interface of Android gg, but the parameters are somewhat different)

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

For standalone APP version only:
h5gg.setTargetProc(process number); //Set the current target process, return success or failure
h5gg.getProcList('process name'); //Get the process array, the elements in the array have pid (process number), name (process name) attributes
    (If the process name is not passed in, it will return a list of all running app processes, which can be called periodically to determine whether the target process has ended)

Other APIs:
closeMenu(); //Hide the floating window
setFloatButton(http or https URL); //Load from URL link and replace floating button icon
setFloatWindow(x, y, height, width); //Modify the position and size of the window suspended on the screen
setWindowDrag(x, y, height, width); //Set the area of the draggable floating window in the H5 page
 
Notice:
1: The address parameter supports automatic identification in decimal or hexadecimal format starting with 0x, other parameters must be in string format
2: Floating point types are divided into: F32, F64, signed numbers: I8, I16, I32, I64, unsigned numbers: U8, U16, U32, U64
3: If there are many search results, do not get all the data at one time with getResults, it is easy to cause memory explosion, flashback and crash, and should be obtained in sections
4: The address and value of the search result are all string types. If you want to do digital operations, please use Number(x) to convert them into numeric types before you can perform operations.
    (Unlike lua, which automatically converts the string types on both sides of the + sign to numeric types, in js, if the + sign is a string, the two strings will be concatenated)
5: The numeric type can be converted into a hexadecimal string format with x.toString(16), but x must be a numeric type to convert successfully
6: The numerical value of the search supports the range format, such as "50~100", such as "2.3~7.8", both numerical search and adjacent (joint) search are supported
5: The default size of the floating window is 380 points wide and 400 points high. You can set the position, size and draggable area through the js interface on the H5 page.
</script>

