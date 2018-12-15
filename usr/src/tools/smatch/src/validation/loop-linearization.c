extern int p(int);

static int ffor(void)
{
	int i;
	for (int i = 0; i < 10; i++) {
		if (!p(i))
			return 0;
	}
	return 1;
}

static int fwhile(void)
{
	int i = 0;
	while (i < 10) {
		if (!p(i))
			return 0;
		i++;
	}
	return 1;
}

static int fdo(void)
{
	int i = 0;
	do {
		if (!p(i))
			return 0;
	} while (i++ < 10);
	return 1;
}

/*
 * check-name: loop-linearization
 * check-command: test-linearize $file
 *
 * check-output-start
ffor:
.L0:
	<entry-point>
	phisrc.32   %phi5(i) <- $0
	br          .L4

.L4:
	phi.32      %r1(i) <- %phi5(i), %phi6(i)
	setlt.32    %r2 <- %r1(i), $10
	cbr         %r2, .L1, .L3

.L1:
	call.32     %r4 <- p, %r1(i)
	cbr         %r4, .L2, .L5

.L5:
	phisrc.32   %phi1(return) <- $0
	br          .L7

.L2:
	add.32      %r7 <- %r1(i), $1
	phisrc.32   %phi6(i) <- %r7
	br          .L4

.L3:
	phisrc.32   %phi2(return) <- $1
	br          .L7

.L7:
	phi.32      %r5 <- %phi1(return), %phi2(return)
	ret.32      %r5


fwhile:
.L8:
	<entry-point>
	phisrc.32   %phi11(i) <- $0
	br          .L12

.L12:
	phi.32      %r8(i) <- %phi11(i), %phi12(i)
	setlt.32    %r9 <- %r8(i), $10
	cbr         %r9, .L9, .L11

.L9:
	call.32     %r11 <- p, %r8(i)
	cbr         %r11, .L14, .L13

.L13:
	phisrc.32   %phi7(return) <- $0
	br          .L15

.L14:
	add.32      %r14 <- %r8(i), $1
	phisrc.32   %phi12(i) <- %r14
	br          .L12

.L11:
	phisrc.32   %phi8(return) <- $1
	br          .L15

.L15:
	phi.32      %r12 <- %phi7(return), %phi8(return)
	ret.32      %r12


fdo:
.L16:
	<entry-point>
	phisrc.32   %phi16(i) <- $0
	br          .L17

.L17:
	phi.32      %r15(i) <- %phi16(i), %phi17(i)
	call.32     %r16 <- p, %r15(i)
	cbr         %r16, .L18, .L20

.L20:
	phisrc.32   %phi13(return) <- $0
	br          .L22

.L18:
	add.32      %r19 <- %r15(i), $1
	setlt.32    %r20 <- %r15(i), $10
	phisrc.32   %phi17(i) <- %r19
	cbr         %r20, .L17, .L19

.L19:
	phisrc.32   %phi14(return) <- $1
	br          .L22

.L22:
	phi.32      %r17 <- %phi13(return), %phi14(return)
	ret.32      %r17


 * check-output-end
 */
