
window.onerror=h5gg_js_error_handler=function(message, url, line, column, error) {
    console.log('log---onerror::::', message, url, line, column, error);
    var fname='匿名脚本';
    try {
        fname = new URL(url);
        fname = decodeURI(fname.pathname);
        fname = fname.substring(fname.lastIndexOf('/')+1);
    } catch(e) {}
    alert('JS错误: 在'+fname+'第'+line+'行第'+column+"列:\n\n"+message);
};
