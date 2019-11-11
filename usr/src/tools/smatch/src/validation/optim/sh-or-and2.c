unsigned lsr_or_and2(unsigned x, unsigned b)
{
	return (((x & 0xf0ffffff) | b) >> 12);
}

unsigned shl_or_and2(unsigned x, unsigned b)
{
	return (((x & 0xffffff0f) | b) << 12);
}

/*
 * check-name: sh-or-and2
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(1): lsr\\.
 * check-output-pattern(1): shl\\.
 * check-output-pattern(2): or\\.
 * check-output-pattern(1): and\\..*\\$0xf0fff000
 * check-output-pattern(1): and\\..*\\$0xfff0f
 */
