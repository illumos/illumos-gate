unsigned int shl0(unsigned int x)
{
	return x << 15 << 15;
}

unsigned int shl1(unsigned int x)
{
	return x << 16 << 15;
}

unsigned int shl2(unsigned int x)
{
	return x << 16 << 16;
}

unsigned int shl3(unsigned int x)
{
	return x << 12 << 10 << 10;
}


unsigned int lsr0(unsigned int x)
{
	return x >> 15 >> 15;
}

unsigned int lsr1(unsigned int x)
{
	return x >> 16 >> 15;
}

unsigned int lsr2(unsigned int x)
{
	return x >> 16 >> 16;
}

unsigned int lsr3(unsigned int x)
{
	return x >> 12 >> 10 >> 10;
}


int asr0(int x)
{
	return x >> 15 >> 15;
}

int asr1(int x)
{
	return x >> 16 >> 15;
}

int asr2(int x)
{
	return x >> 16 >> 16;
}

int asr3(int x)
{
	return x >> 12 >> 10 >> 10;
}

/*
 * check-name: shift-shift
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
shl0:
.L0:
	<entry-point>
	shl.32      %r3 <- %arg1, $30
	ret.32      %r3


shl1:
.L2:
	<entry-point>
	shl.32      %r7 <- %arg1, $31
	ret.32      %r7


shl2:
.L4:
	<entry-point>
	ret.32      $0


shl3:
.L6:
	<entry-point>
	ret.32      $0


lsr0:
.L8:
	<entry-point>
	lsr.32      %r20 <- %arg1, $30
	ret.32      %r20


lsr1:
.L10:
	<entry-point>
	lsr.32      %r24 <- %arg1, $31
	ret.32      %r24


lsr2:
.L12:
	<entry-point>
	ret.32      $0


lsr3:
.L14:
	<entry-point>
	ret.32      $0


asr0:
.L16:
	<entry-point>
	asr.32      %r37 <- %arg1, $30
	ret.32      %r37


asr1:
.L18:
	<entry-point>
	asr.32      %r41 <- %arg1, $31
	ret.32      %r41


asr2:
.L20:
	<entry-point>
	asr.32      %r45 <- %arg1, $31
	ret.32      %r45


asr3:
.L22:
	<entry-point>
	asr.32      %r50 <- %arg1, $31
	ret.32      %r50


 * check-output-end
 */
