// If (t >> S) is simplified into (x >> S)
// then the whole expression will be 0.
// The test is only interesting if the sub-expression
// (x & M) is referenced more than once
// (because otherwise other simplifications apply).
unsigned lsr_and1(unsigned x)
{
	unsigned t = (x & 0xfffff000);
	return ((t >> 12) ^ (x >> 12)) & t;
}

/*
 * check-name: lsr-and1
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: ret\\..*\\$0$
 */
