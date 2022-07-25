
window.onerror=h5gg_js_error_handler=function(message, url, line, column, error) {
    console.log('log---onerror::::', message, url, line, column, error);
    var fname=navigator.language.indexOf("zh-")==0 ? '(匿名脚本)' : "(anonymous code)";
    try {
        fname = new URL(url);
        fname = decodeURI(fname.pathname);
        fname = fname.substring(fname.lastIndexOf('/')+1);
    } catch(e) {}
    
    if(navigator.language.indexOf("zh-")==0)
        alert('JS错误 在'+fname+'第'+line+'行第'+column+"列:\n\n"+message);
    else
        alert('JSError in:'+fname+' line:'+line+' column:'+column+":\n\n"+message);
};

