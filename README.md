# H5GG

**Discuss in [Discord](https://discord.gg/FAs4MH7HMc) or [iOSGods](https://iosgods.com/forum/595-h5gg-igamegod/)**

an iOS Cheat Engine for JavaScript APIs & Html5 UI.

provide memory [APIs](/examples-JavaScript/) likely Android-GG's Lua APIs.

support load scripts(*.js or *.html file) from loacl or network.

support load dylib plugin for javascript api ([demo](/pluginDemo/customAlert)).  

support [auto search static pointer and offsets of the value](/examples-JavaScript/AutoSearchPointerChains.js).

and you can customize UI by using [HTML+CSS](/examples-HTML5/) without computer.

and you can make your own tweak(dylib) by click one button, so easy!

**For fuzzy search it is recommended to use: https://igg-server.herokuapp.com/**

## H5GG supported 4 modes to run:

1. [inject H5GG.dylib to ipa for non-jailbreak devices](/packages/)

2. [tweak(deb) auto load into all app for jailbroken devices](/packages/)

3. [standalone APP for jailbroken devices(compatible with iPad's SlideOver+SplitView)](/appstand/packages/)

4. [Float On Screen for jailbroken devices(not compatible with iPad's SlideOver+SplitView), tested on ios11~ios14](/globalview/packages/)

  and there is [a special version for TrollStore](/appstand/packages/)


## h5gg-official-plugin [h5frida](/examples-h5frida):

1: support invoke any C/C++/Objective-C function (without jailbroken)

2: support hook any module's Objective-C method (without jailbroken)

3: support hook any module's C/C++ exprot function (without jailbroken)

4: support hook any module's C/C++ internal function/instruction (jailbroken only)

5: **support inline-hook app-module's C/C++ function/instruction (without jailbroken)**

6: **support code-patch (patch-offset) with bytes dynamically (without jailbroken)**



## screenshots:
 
![text](/pictures/h5gg1.png)

![text](/pictures/h5gg2.png)

![text](/pictures/h5gg3.png)

![text](/pictures/h5gg4.PNG)



## Design Html Menu UI in EasyHtml on iPhone/iPad 
(**install EasyHtml from AppStore!**)

![text](/pictures/easyhtml.png)



## [Debug the js/html of H5GG running on ios through macOS safari](https://www.lifewire.com/activate-the-debug-console-in-safari-445798):
the host app need get-task-allow entitlement (jailbroken or sign by Developer Certificate, not sign by Distribution Certificate)

![text](/pictures/macos.png)


## Dependences:

the GlobalView module of Floating APP requires these tweaks and may need to update for new ios version.

+ BackgrounderAction : libH5GG.B12.dylib (jp.akusio.backgrounderaction12) for ios11~ios12 

+ BackgrounderAction2 : libH5GG.B.dylib (jp.akusio.backgrounderaction13) for ios13+

+ [libAPAppView](https://github.com/Baw-Appie/libAPAppView) : libH5GG.A.dylib (com.rpgfarm.libapappview) for ios13+





## [H5GG JavaScript Engine Document](/h5gg-js-doc-en.js)


it's all completely free & open source! 

