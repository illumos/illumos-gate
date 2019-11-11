unsigned shl_and0(unsigned x)
{
	unsigned t = (x & 0xfff00000);
	return (t << 12) & t;
}

/*
 * check-name: shl-and0
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: ret\\..*\\$0$
 */
