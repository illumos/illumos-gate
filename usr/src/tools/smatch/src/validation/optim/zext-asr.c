unsigned short foo(unsigned short a)
{
	return a >> 16;
}

/*
 * check-name: zext-asr
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: ret\\..*\\$0
 * check-output-excludes: asr\\.
 */
