typedef unsigned int uint;
typedef _Bool bool;

static uint   ini(uint a) { return !a; }
static bool   bni(uint a) { return !a; }
static uint  ioii(uint a, uint b) { return a || b; }
static uint  iaii(uint a, uint b) { return a && b; }
static bool  boii(uint a, uint b) { return a || b; }
static bool  baii(uint a, uint b) { return a && b; }
static uint ioiii(uint a, uint b, uint c) { return a || b || c; }
static uint iaiii(uint a, uint b, uint c) { return a && b && c; }
static bool boiii(uint a, uint b, uint c) { return a || b || c; }
static bool baiii(uint a, uint b, uint c) { return a && b && c; }

static uint   inb(bool a) { return !a; }
static bool   bnb(bool a) { return !a; }
static uint  iobb(bool a, bool b) { return a || b; }
static uint  iabb(bool a, bool b) { return a && b; }
static bool  bobb(bool a, bool b) { return a || b; }
static bool  babb(bool a, bool b) { return a && b; }
static uint iobbb(bool a, bool b, bool c) { return a || b || c; }
static uint iabbb(bool a, bool b, bool c) { return a && b && c; }
static bool bobbb(bool a, bool b, bool c) { return a || b || c; }
static bool babbb(bool a, bool b, bool c) { return a && b && c; }

/*
 * check-name: bool-simplify2
 * check-command: test-linearize $file
 *
 * check-output-pattern(20): setne\\.
 * check-output-pattern(4):  seteq\\.
 * check-output-pattern(8): zext\\.
 * check-output-pattern(12): and
 * check-output-pattern(12): or
 * check-output-end
 *
 * check-output-start
ini:
.L0:
	<entry-point>
	seteq.32    %r2 <- %arg1, $0
	ret.32      %r2


bni:
.L2:
	<entry-point>
	seteq.1     %r6 <- %arg1, $0
	ret.1       %r6


ioii:
.L4:
	<entry-point>
	setne.1     %r9 <- %arg1, $0
	setne.1     %r11 <- %arg2, $0
	or.1        %r12 <- %r9, %r11
	zext.32     %r13 <- (1) %r12
	ret.32      %r13


iaii:
.L6:
	<entry-point>
	setne.1     %r16 <- %arg1, $0
	setne.1     %r18 <- %arg2, $0
	and.1       %r19 <- %r16, %r18
	zext.32     %r20 <- (1) %r19
	ret.32      %r20


boii:
.L8:
	<entry-point>
	setne.1     %r23 <- %arg1, $0
	setne.1     %r25 <- %arg2, $0
	or.1        %r26 <- %r23, %r25
	ret.1       %r26


baii:
.L10:
	<entry-point>
	setne.1     %r31 <- %arg1, $0
	setne.1     %r33 <- %arg2, $0
	and.1       %r34 <- %r31, %r33
	ret.1       %r34


ioiii:
.L12:
	<entry-point>
	setne.1     %r39 <- %arg1, $0
	setne.1     %r41 <- %arg2, $0
	or.1        %r42 <- %r39, %r41
	setne.1     %r46 <- %arg3, $0
	or.1        %r47 <- %r42, %r46
	zext.32     %r48 <- (1) %r47
	ret.32      %r48


iaiii:
.L14:
	<entry-point>
	setne.1     %r51 <- %arg1, $0
	setne.1     %r53 <- %arg2, $0
	and.1       %r54 <- %r51, %r53
	setne.1     %r58 <- %arg3, $0
	and.1       %r59 <- %r54, %r58
	zext.32     %r60 <- (1) %r59
	ret.32      %r60


boiii:
.L16:
	<entry-point>
	setne.1     %r63 <- %arg1, $0
	setne.1     %r65 <- %arg2, $0
	or.1        %r66 <- %r63, %r65
	setne.1     %r70 <- %arg3, $0
	or.1        %r71 <- %r66, %r70
	ret.1       %r71


baiii:
.L18:
	<entry-point>
	setne.1     %r76 <- %arg1, $0
	setne.1     %r78 <- %arg2, $0
	and.1       %r79 <- %r76, %r78
	setne.1     %r83 <- %arg3, $0
	and.1       %r84 <- %r79, %r83
	ret.1       %r84


inb:
.L20:
	<entry-point>
	seteq.32    %r89 <- %arg1, $0
	ret.32      %r89


bnb:
.L22:
	<entry-point>
	seteq.1     %r93 <- %arg1, $0
	ret.1       %r93


iobb:
.L24:
	<entry-point>
	or.1        %r97 <- %arg1, %arg2
	zext.32     %r98 <- (1) %r97
	ret.32      %r98


iabb:
.L26:
	<entry-point>
	and.1       %r102 <- %arg1, %arg2
	zext.32     %r103 <- (1) %r102
	ret.32      %r103


bobb:
.L28:
	<entry-point>
	or.1        %r107 <- %arg1, %arg2
	ret.1       %r107


babb:
.L30:
	<entry-point>
	and.1       %r113 <- %arg1, %arg2
	ret.1       %r113


iobbb:
.L32:
	<entry-point>
	or.1        %r119 <- %arg1, %arg2
	or.1        %r123 <- %r119, %arg3
	zext.32     %r124 <- (1) %r123
	ret.32      %r124


iabbb:
.L34:
	<entry-point>
	and.1       %r128 <- %arg1, %arg2
	and.1       %r132 <- %r128, %arg3
	zext.32     %r133 <- (1) %r132
	ret.32      %r133


bobbb:
.L36:
	<entry-point>
	or.1        %r137 <- %arg1, %arg2
	or.1        %r141 <- %r137, %arg3
	ret.1       %r141


babbb:
.L38:
	<entry-point>
	and.1       %r147 <- %arg1, %arg2
	and.1       %r151 <- %r147, %arg3
	ret.1       %r151


 * check-output-end
 */
