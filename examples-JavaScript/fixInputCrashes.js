$(document).on('focus', "input", function(){$(this).blur(); var val=prompt();if(val!=undefined)$(this).val(val)});
