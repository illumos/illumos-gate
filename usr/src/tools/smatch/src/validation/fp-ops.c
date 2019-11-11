double fadd(double x, double y) { return x + y; }
double fsub(double x, double y) { return x - y; }
double fmul(double x, double y) { return x * y; }
double fdiv(double x, double y) { return x / y; }
double fneg(double x)           { return -x; }
_Bool  ftst(double x)           { return !x; }

/*
 * check-name: floating-point ops
 * check-command: test-linearize -Wno-decl $file

 * check-output-start
fadd:
.L0:
	<entry-point>
	fadd.64     %r3 <- %arg1, %arg2
	ret.64      %r3


fsub:
.L2:
	<entry-point>
	fsub.64     %r7 <- %arg1, %arg2
	ret.64      %r7


fmul:
.L4:
	<entry-point>
	fmul.64     %r11 <- %arg1, %arg2
	ret.64      %r11


fdiv:
.L6:
	<entry-point>
	fdiv.64     %r15 <- %arg1, %arg2
	ret.64      %r15


fneg:
.L8:
	<entry-point>
	fneg.64     %r18 <- %arg1
	ret.64      %r18


ftst:
.L10:
	<entry-point>
	setfval.64  %r21 <- 0.000000e+00
	fcmpoeq.1   %r23 <- %arg1, %r21
	ret.1       %r23


 * check-output-end
 */
