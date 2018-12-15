static unsigned int ok1  = !1 &&  2;
static unsigned int bad1 = !1 &   2;
static unsigned int ok2  = !1 ||  2;
static unsigned int bad2 = !1 |   2;
static unsigned int ok3  =  1 && !2;
static unsigned int bad3 =  1 &  !2;
static unsigned int ok4  =  1 || !2;
static unsigned int bad4 =  1 |  !2;
static unsigned int ok5  = !1 && !2;
static unsigned int bad5 = !1 &  !2;
static unsigned int ok6  = !1 || !2;
static unsigned int bad6 = !1 |  !2;
/*
 * check-name: Dubious bitwise operation on !x
 *
 * check-error-start
dubious-bitwise-with-not.c:2:31: warning: dubious: !x & y
dubious-bitwise-with-not.c:4:31: warning: dubious: !x | y
dubious-bitwise-with-not.c:6:31: warning: dubious: x & !y
dubious-bitwise-with-not.c:8:31: warning: dubious: x | !y
dubious-bitwise-with-not.c:10:31: warning: dubious: !x & !y
dubious-bitwise-with-not.c:12:31: warning: dubious: !x | !y
 * check-error-end
 */
