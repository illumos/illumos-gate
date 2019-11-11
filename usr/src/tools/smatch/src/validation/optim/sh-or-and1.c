unsigned lsr_or_and1(unsigned x, unsigned b)
{
	return (((x & 0xfffff000) | b) >> 12);
}

unsigned shl_or_and1(unsigned x, unsigned b)
{
	return (((x & 0x000fffff) | b) << 12);
}

/*
 * check-name: sh-or-and1
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(1): lsr\\.
 * check-output-pattern(1): shl\\.
 * check-output-pattern(2): or\\.
 * check-output-excludes: and\\.
 */
