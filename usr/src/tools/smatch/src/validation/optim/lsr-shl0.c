unsigned mask(unsigned x)
{
	return (x << 15) >> 15;
}

/*
 * check-name: lsr-shl0
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: and\\..*0x1ffff
 * check-output-excludes: lsr\\.
 * check-output-excludes: shl\\.
 */
