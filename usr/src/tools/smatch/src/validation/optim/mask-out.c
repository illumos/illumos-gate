unsigned mask(unsigned a, unsigned b)
{
	return ((a & 0xffff0000) | b) & 0x0000ffff;
}

/*
 * check-name: mask-out
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: %arg1
 */
