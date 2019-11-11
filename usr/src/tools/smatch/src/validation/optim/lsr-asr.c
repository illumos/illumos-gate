int lsrasr0(unsigned int x)
{
	return ((int) (x >> 15)) >> 15;
}

int lsrasr1(unsigned int x)
{
	return ((int) (x >> 16)) >> 15;
}

int lsrasr2(unsigned int x)
{
	return ((int) (x >> 16)) >> 16;
}

/*
 * check-name: lsr-asr
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
lsrasr0:
.L0:
	<entry-point>
	lsr.32      %r3 <- %arg1, $30
	ret.32      %r3


lsrasr1:
.L2:
	<entry-point>
	lsr.32      %r7 <- %arg1, $31
	ret.32      %r7


lsrasr2:
.L4:
	<entry-point>
	ret.32      $0


 * check-output-end
 */
