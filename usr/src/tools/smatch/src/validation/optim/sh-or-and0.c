unsigned lsr_or_and0(unsigned x, unsigned b)
{
	return (((x & 0x00000fff) | b) >> 12);
}

unsigned shl_or_and0(unsigned x, unsigned b)
{
	return (((x & 0xfff00000) | b) << 12);
}

/*
 * check-name: sh-or-and0
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(1): lsr\\.
 * check-output-pattern(1): shl\\.
 * check-output-excludes: or\\.
 * check-output-excludes: and\\.
 */
