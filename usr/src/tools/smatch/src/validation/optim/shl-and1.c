// If (t << S) is simplified into (x << S)
// then the whole expression will be 0.
// The test is only interesting if the sub-expression
// (x & M) is referenced more than once
// (because otherwise other simplifications apply).
unsigned shl_and1(unsigned x)
{
	unsigned t = (x & 0x000fffff);
	return ((t << 12) ^ (x << 12)) & t;
}

/*
 * check-name: shl-and1
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: ret\\..*\\$0$
 */
