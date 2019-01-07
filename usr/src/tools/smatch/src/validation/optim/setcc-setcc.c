static _Bool blt(int a, int b)	{ return  (a <  b); }
static _Bool bnge(int a, int b)	{ return !(a >= b); }
static _Bool bgt(int a, int b)	{ return  (a >  b); }
static _Bool bnle(int a, int b)	{ return !(a <= b); }
static _Bool ble(int a, int b)	{ return  (a <= b); }
static _Bool bngt(int a, int b)	{ return !(a >  b); }
static _Bool bge(int a, int b)	{ return  (a >= b); }
static _Bool bnlt(int a, int b)	{ return !(a <  b); }

/*
 * check-name: optim/setcc-setcc
 * check-command: test-linearize $file
 * check-output-ignore
 *
 * check-output-excludes: set..\\.32
 * check-output-excludes: setne\\.1
 * check-output-excludes: seteq\\.1
 * check-output-contains: set[gt][te]\\.1
 */
