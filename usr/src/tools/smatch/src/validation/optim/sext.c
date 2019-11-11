int sext(int x)
{
	return (x << 5) >> 5;
}

/*
 * check-name: sext
 * check-command: test-linearize -Wno-decl $file
 * check-known-to-fail
 *
 * check-output-ignore
 * check-output-contains: sext\\.$27
 * check-output-excludes: asr\\.
 * check-output-excludes: shl\\.
 */
