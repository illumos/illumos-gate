static _Bool bnoteq0(int a)	{ return !(a == 0); }
static _Bool bne0(int a)	{ return  (a != 0); }
static _Bool bnotnot(int a)	{ return !!a; }

/*
 * check-name: optim/setcc-setne
 * check-command: test-linearize $file
 * check-output-ignore
 *
 * check-output-excludes: set..\\.32
 * check-output-excludes: seteq\\.1
 * check-output-contains: setne\\.1
 */
