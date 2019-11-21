extern int a[3];

int (*fa(int i))[] { return &a; }
int *f0(int i) { return &a[0]; }
int *fd(int i) { return  a; }

/*
 * check-name: degen-array
 * check-command: test-linearize -m64 -Wno-decl $file
 * check-assert: sizeof(void *) == 8
 *
 * check-output-start
fa:
.L0:
	<entry-point>
	ret.64      a


f0:
.L2:
	<entry-point>
	ret.64      a


fd:
.L4:
	<entry-point>
	ret.64      a


 * check-output-end
 */
