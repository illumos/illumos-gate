#define	bool	_Bool

bool bfimp(float a) { return a; }
bool bfexp(float a) { return (bool)a; }

bool bfnot(float a) { return !a; }
int  ifnot(float a) { return !a; }
bool bfior(float a, float b) { return a || b; }
int  ifior(float a, float b) { return a || b; }
bool bfand(float a, float b) { return a && b; }
int  ifand(float a, float b) { return a && b; }

/*
 * check-name: bool context fp
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
bfimp:
.L0:
	<entry-point>
	setfval.32  %r2 <- 0.000000e+00
	fcmpune.1   %r3 <- %arg1, %r2
	ret.1       %r3


bfexp:
.L2:
	<entry-point>
	setfval.32  %r6 <- 0.000000e+00
	fcmpune.1   %r7 <- %arg1, %r6
	ret.1       %r7


bfnot:
.L4:
	<entry-point>
	setfval.32  %r10 <- 0.000000e+00
	fcmpoeq.1   %r12 <- %arg1, %r10
	ret.1       %r12


ifnot:
.L6:
	<entry-point>
	setfval.32  %r15 <- 0.000000e+00
	fcmpoeq.32  %r16 <- %arg1, %r15
	ret.32      %r16


bfior:
.L8:
	<entry-point>
	setfval.32  %r19 <- 0.000000e+00
	fcmpune.1   %r20 <- %arg1, %r19
	fcmpune.1   %r23 <- %arg2, %r19
	or.1        %r24 <- %r20, %r23
	ret.1       %r24


ifior:
.L10:
	<entry-point>
	setfval.32  %r29 <- 0.000000e+00
	fcmpune.1   %r30 <- %arg1, %r29
	fcmpune.1   %r33 <- %arg2, %r29
	or.1        %r34 <- %r30, %r33
	zext.32     %r35 <- (1) %r34
	ret.32      %r35


bfand:
.L12:
	<entry-point>
	setfval.32  %r38 <- 0.000000e+00
	fcmpune.1   %r39 <- %arg1, %r38
	fcmpune.1   %r42 <- %arg2, %r38
	and.1       %r43 <- %r39, %r42
	ret.1       %r43


ifand:
.L14:
	<entry-point>
	setfval.32  %r48 <- 0.000000e+00
	fcmpune.1   %r49 <- %arg1, %r48
	fcmpune.1   %r52 <- %arg2, %r48
	and.1       %r53 <- %r49, %r52
	zext.32     %r54 <- (1) %r53
	ret.32      %r54


 * check-output-end
 */
