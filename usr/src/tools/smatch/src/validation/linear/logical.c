struct S {
	         int  :1;
	  signed int s:2;
	unsigned int u:3;
	        long l;
	      double d;
};

int os(int i, struct S *b) { return i || b->s; }
int ou(int i, struct S *b) { return i || b->u; }
int ol(int i, struct S *b) { return i || b->l; }
int od(int i, struct S *b) { return i || b->d; }

int as(int i, struct S *b) { return i && b->s; }
int au(int i, struct S *b) { return i && b->u; }
int al(int i, struct S *b) { return i && b->l; }
int ad(int i, struct S *b) { return i && b->d; }

/*
 * check-name: logical
 * check-command: test-linearize -m64 -fdump-ir -Wno-decl $file
 * check-assert: sizeof(void *) == 8 && sizeof(long) == 8 && sizeof(double) == 8
 *
 * check-output-start
os:
.L0:
	<entry-point>
	store.32    %arg1 -> 0[i]
	store.64    %arg2 -> 0[b]
	load.32     %r2 <- 0[i]
	setne.1     %r3 <- %r2, $0
	phisrc.32   %phi1 <- $1
	cbr         %r3, .L3, .L2

.L2:
	load.64     %r4 <- 0[b]
	load.32     %r5 <- 0[%r4]
	lsr.32      %r6 <- %r5, $1
	trunc.2     %r7 <- (32) %r6
	setne.1     %r8 <- %r7, $0
	zext.32     %r9 <- (1) %r8
	phisrc.32   %phi2 <- %r9
	br          .L3

.L3:
	phi.32      %r1 <- %phi1, %phi2
	phisrc.32   %phi3(return) <- %r1
	br          .L1

.L1:
	phi.32      %r10 <- %phi3(return)
	ret.32      %r10


ou:
.L4:
	<entry-point>
	store.32    %arg1 -> 0[i]
	store.64    %arg2 -> 0[b]
	load.32     %r12 <- 0[i]
	setne.1     %r13 <- %r12, $0
	phisrc.32   %phi4 <- $1
	cbr         %r13, .L7, .L6

.L6:
	load.64     %r14 <- 0[b]
	load.32     %r15 <- 0[%r14]
	lsr.32      %r16 <- %r15, $3
	trunc.3     %r17 <- (32) %r16
	setne.1     %r18 <- %r17, $0
	zext.32     %r19 <- (1) %r18
	phisrc.32   %phi5 <- %r19
	br          .L7

.L7:
	phi.32      %r11 <- %phi4, %phi5
	phisrc.32   %phi6(return) <- %r11
	br          .L5

.L5:
	phi.32      %r20 <- %phi6(return)
	ret.32      %r20


ol:
.L8:
	<entry-point>
	store.32    %arg1 -> 0[i]
	store.64    %arg2 -> 0[b]
	load.32     %r22 <- 0[i]
	setne.1     %r23 <- %r22, $0
	phisrc.32   %phi7 <- $1
	cbr         %r23, .L11, .L10

.L10:
	load.64     %r24 <- 0[b]
	load.64     %r25 <- 8[%r24]
	setne.1     %r26 <- %r25, $0
	zext.32     %r27 <- (1) %r26
	phisrc.32   %phi8 <- %r27
	br          .L11

.L11:
	phi.32      %r21 <- %phi7, %phi8
	phisrc.32   %phi9(return) <- %r21
	br          .L9

.L9:
	phi.32      %r28 <- %phi9(return)
	ret.32      %r28


od:
.L12:
	<entry-point>
	store.32    %arg1 -> 0[i]
	store.64    %arg2 -> 0[b]
	load.32     %r30 <- 0[i]
	setne.1     %r31 <- %r30, $0
	phisrc.32   %phi10 <- $1
	cbr         %r31, .L15, .L14

.L14:
	load.64     %r32 <- 0[b]
	load.64     %r33 <- 16[%r32]
	setfval.64  %r34 <- 0.000000e+00
	fcmpune.1   %r35 <- %r33, %r34
	zext.32     %r36 <- (1) %r35
	phisrc.32   %phi11 <- %r36
	br          .L15

.L15:
	phi.32      %r29 <- %phi10, %phi11
	phisrc.32   %phi12(return) <- %r29
	br          .L13

.L13:
	phi.32      %r37 <- %phi12(return)
	ret.32      %r37


as:
.L16:
	<entry-point>
	store.32    %arg1 -> 0[i]
	store.64    %arg2 -> 0[b]
	load.32     %r39 <- 0[i]
	setne.1     %r40 <- %r39, $0
	phisrc.32   %phi13 <- $0
	cbr         %r40, .L18, .L19

.L18:
	load.64     %r41 <- 0[b]
	load.32     %r42 <- 0[%r41]
	lsr.32      %r43 <- %r42, $1
	trunc.2     %r44 <- (32) %r43
	setne.1     %r45 <- %r44, $0
	zext.32     %r46 <- (1) %r45
	phisrc.32   %phi14 <- %r46
	br          .L19

.L19:
	phi.32      %r38 <- %phi13, %phi14
	phisrc.32   %phi15(return) <- %r38
	br          .L17

.L17:
	phi.32      %r47 <- %phi15(return)
	ret.32      %r47


au:
.L20:
	<entry-point>
	store.32    %arg1 -> 0[i]
	store.64    %arg2 -> 0[b]
	load.32     %r49 <- 0[i]
	setne.1     %r50 <- %r49, $0
	phisrc.32   %phi16 <- $0
	cbr         %r50, .L22, .L23

.L22:
	load.64     %r51 <- 0[b]
	load.32     %r52 <- 0[%r51]
	lsr.32      %r53 <- %r52, $3
	trunc.3     %r54 <- (32) %r53
	setne.1     %r55 <- %r54, $0
	zext.32     %r56 <- (1) %r55
	phisrc.32   %phi17 <- %r56
	br          .L23

.L23:
	phi.32      %r48 <- %phi16, %phi17
	phisrc.32   %phi18(return) <- %r48
	br          .L21

.L21:
	phi.32      %r57 <- %phi18(return)
	ret.32      %r57


al:
.L24:
	<entry-point>
	store.32    %arg1 -> 0[i]
	store.64    %arg2 -> 0[b]
	load.32     %r59 <- 0[i]
	setne.1     %r60 <- %r59, $0
	phisrc.32   %phi19 <- $0
	cbr         %r60, .L26, .L27

.L26:
	load.64     %r61 <- 0[b]
	load.64     %r62 <- 8[%r61]
	setne.1     %r63 <- %r62, $0
	zext.32     %r64 <- (1) %r63
	phisrc.32   %phi20 <- %r64
	br          .L27

.L27:
	phi.32      %r58 <- %phi19, %phi20
	phisrc.32   %phi21(return) <- %r58
	br          .L25

.L25:
	phi.32      %r65 <- %phi21(return)
	ret.32      %r65


ad:
.L28:
	<entry-point>
	store.32    %arg1 -> 0[i]
	store.64    %arg2 -> 0[b]
	load.32     %r67 <- 0[i]
	setne.1     %r68 <- %r67, $0
	phisrc.32   %phi22 <- $0
	cbr         %r68, .L30, .L31

.L30:
	load.64     %r69 <- 0[b]
	load.64     %r70 <- 16[%r69]
	setfval.64  %r71 <- 0.000000e+00
	fcmpune.1   %r72 <- %r70, %r71
	zext.32     %r73 <- (1) %r72
	phisrc.32   %phi23 <- %r73
	br          .L31

.L31:
	phi.32      %r66 <- %phi22, %phi23
	phisrc.32   %phi24(return) <- %r66
	br          .L29

.L29:
	phi.32      %r74 <- %phi24(return)
	ret.32      %r74


 * check-output-end
 */
