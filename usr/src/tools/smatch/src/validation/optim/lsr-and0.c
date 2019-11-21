unsigned lsr_and0(unsigned x)
{
	unsigned t = (x & 0x00000fff);
	return (t >> 12) & t;
}

/*
 * check-name: lsr-and0
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: ret\\..*\\$0$
 */
