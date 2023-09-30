//some app will crash if you tap an input control, this is a temporary solution to fix it
$(document).on('focus', "input", function(){$(this).blur(); var val=prompt();if(val!=undefined)$(this).val(val)});
