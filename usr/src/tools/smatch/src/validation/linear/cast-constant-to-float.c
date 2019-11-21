typedef unsigned int uint;
typedef unsigned long ulong;

double f1(void) { return -1; }
double f2(void) { return (double)-1; }
double f3(void) { return -1.0; }

/*
 * check-name: cast-constant-to-float
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
f1:
.L0:
	<entry-point>
	setfval.64  %r1 <- -1.000000e+00
	ret.64      %r1


f2:
.L2:
	<entry-point>
	setfval.64  %r3 <- -1.000000e+00
	ret.64      %r3


f3:
.L4:
	<entry-point>
	setfval.64  %r5 <- -1.000000e+00
	ret.64      %r5


 * check-output-end
 */
