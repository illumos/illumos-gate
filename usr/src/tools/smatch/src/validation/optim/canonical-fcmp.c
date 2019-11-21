extern double g;

int  fcmp_eq(double a) { return  (g == a); }
int  fcmp_ne(double a) { return  (g != a); }

int  fcmp_gt(double a) { return  (g >  a); }
int  fcmp_ge(double a) { return  (g >= a); }
int  fcmp_le(double a) { return  (g <= a); }
int  fcmp_lt(double a) { return  (g <  a); }

int nfcmp_ne(double a) { return !(g == a); }
int nfcmp_eq(double a) { return !(g != a); }

int nfcmp_le(double a) { return !(g >  a); }
int nfcmp_lt(double a) { return !(g >= a); }
int nfcmp_gt(double a) { return !(g <= a); }
int nfcmp_ge(double a) { return !(g <  a); }

/*
 * check-name: canonical-cmp
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-excludes: \\$123,
 *
 * check-output-start
fcmp_eq:
.L0:
	<entry-point>
	load.64     %r1 <- 0[g]
	fcmpoeq.32  %r3 <- %r1, %arg1
	ret.32      %r3


fcmp_ne:
.L2:
	<entry-point>
	load.64     %r5 <- 0[g]
	fcmpune.32  %r7 <- %r5, %arg1
	ret.32      %r7


fcmp_gt:
.L4:
	<entry-point>
	load.64     %r9 <- 0[g]
	fcmpogt.32  %r11 <- %r9, %arg1
	ret.32      %r11


fcmp_ge:
.L6:
	<entry-point>
	load.64     %r13 <- 0[g]
	fcmpoge.32  %r15 <- %r13, %arg1
	ret.32      %r15


fcmp_le:
.L8:
	<entry-point>
	load.64     %r17 <- 0[g]
	fcmpole.32  %r19 <- %r17, %arg1
	ret.32      %r19


fcmp_lt:
.L10:
	<entry-point>
	load.64     %r21 <- 0[g]
	fcmpolt.32  %r23 <- %r21, %arg1
	ret.32      %r23


nfcmp_ne:
.L12:
	<entry-point>
	load.64     %r25 <- 0[g]
	fcmpune.32  %r28 <- %r25, %arg1
	ret.32      %r28


nfcmp_eq:
.L14:
	<entry-point>
	load.64     %r30 <- 0[g]
	fcmpoeq.32  %r33 <- %r30, %arg1
	ret.32      %r33


nfcmp_le:
.L16:
	<entry-point>
	load.64     %r35 <- 0[g]
	fcmpule.32  %r38 <- %r35, %arg1
	ret.32      %r38


nfcmp_lt:
.L18:
	<entry-point>
	load.64     %r40 <- 0[g]
	fcmpult.32  %r43 <- %r40, %arg1
	ret.32      %r43


nfcmp_gt:
.L20:
	<entry-point>
	load.64     %r45 <- 0[g]
	fcmpugt.32  %r48 <- %r45, %arg1
	ret.32      %r48


nfcmp_ge:
.L22:
	<entry-point>
	load.64     %r50 <- 0[g]
	fcmpuge.32  %r53 <- %r50, %arg1
	ret.32      %r53


 * check-output-end
 */
