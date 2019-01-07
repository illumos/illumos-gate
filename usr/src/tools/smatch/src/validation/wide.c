static char c = L'\x41';
static int n = 1/(0x41 - L'\x41');
/*
 * check-name: wide character constants
 *
 * check-error-start
wide.c:2:17: warning: division by zero
 * check-error-end
 */
