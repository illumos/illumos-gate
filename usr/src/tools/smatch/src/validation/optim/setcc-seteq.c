static _Bool beq0(int a)	{ return  (a == 0); }
static _Bool bnotneq0(int a)	{ return !(a != 0); }
static _Bool bnot(int a)	{ return !a; }

/*
 * check-name: optim/setcc-seteq
 * check-command: test-linearize $file
 * check-output-ignore
 *
 * check-output-excludes: set..\\.32
 * check-output-excludes: setne\\.1
 * check-output-contains: seteq\\.1
 */
