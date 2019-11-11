typedef	  signed int	sint;
typedef	unsigned int	uint;

sint seq(sint p, sint a) { return (123 == p) ? a : 0; }
sint sne(sint p, sint a) { return (123 != p) ? a : 0; }

sint slt(sint p, sint a) { return (123 >  p) ? a : 0; }
sint sle(sint p, sint a) { return (123 >= p) ? a : 0; }
sint sge(sint p, sint a) { return (123 <= p) ? a : 0; }
sint sgt(sint p, sint a) { return (123 <  p) ? a : 0; }

uint ueq(uint p, uint a) { return (123 == p) ? a : 0; }
uint une(uint p, uint a) { return (123 != p) ? a : 0; }

uint ubt(uint p, uint a) { return (123 >  p) ? a : 0; }
uint ube(uint p, uint a) { return (123 >= p) ? a : 0; }
uint uae(uint p, uint a) { return (123 <= p) ? a : 0; }
uint uat(uint p, uint a) { return (123 <  p) ? a : 0; }

/*
 * check-name: canonical-cmp
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-excludes: \\$123,
 *
 * check-output-start
seq:
.L0:
	<entry-point>
	seteq.32    %r3 <- %arg1, $123
	select.32   %r4 <- %r3, %arg2, $0
	ret.32      %r4


sne:
.L2:
	<entry-point>
	setne.32    %r8 <- %arg1, $123
	select.32   %r9 <- %r8, %arg2, $0
	ret.32      %r9


slt:
.L4:
	<entry-point>
	setlt.32    %r13 <- %arg1, $123
	select.32   %r14 <- %r13, %arg2, $0
	ret.32      %r14


sle:
.L6:
	<entry-point>
	setle.32    %r18 <- %arg1, $123
	select.32   %r19 <- %r18, %arg2, $0
	ret.32      %r19


sge:
.L8:
	<entry-point>
	setge.32    %r23 <- %arg1, $123
	select.32   %r24 <- %r23, %arg2, $0
	ret.32      %r24


sgt:
.L10:
	<entry-point>
	setgt.32    %r28 <- %arg1, $123
	select.32   %r29 <- %r28, %arg2, $0
	ret.32      %r29


ueq:
.L12:
	<entry-point>
	seteq.32    %r33 <- %arg1, $123
	select.32   %r34 <- %r33, %arg2, $0
	ret.32      %r34


une:
.L14:
	<entry-point>
	setne.32    %r38 <- %arg1, $123
	select.32   %r39 <- %r38, %arg2, $0
	ret.32      %r39


ubt:
.L16:
	<entry-point>
	setb.32     %r43 <- %arg1, $123
	select.32   %r44 <- %r43, %arg2, $0
	ret.32      %r44


ube:
.L18:
	<entry-point>
	setbe.32    %r48 <- %arg1, $123
	select.32   %r49 <- %r48, %arg2, $0
	ret.32      %r49


uae:
.L20:
	<entry-point>
	setae.32    %r53 <- %arg1, $123
	select.32   %r54 <- %r53, %arg2, $0
	ret.32      %r54


uat:
.L22:
	<entry-point>
	seta.32     %r58 <- %arg1, $123
	select.32   %r59 <- %r58, %arg2, $0
	ret.32      %r59


 * check-output-end
 */
