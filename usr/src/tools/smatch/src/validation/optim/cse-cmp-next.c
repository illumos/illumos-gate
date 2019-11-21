void foo(int p, int i, int f, int *ref, int *dst, int *src)
{
	if (p)
		f = ref[i];
	if (f)
		dst[i] = src[i];
}

/*
 * check-name: cse-cmp-next
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(1,2): mul\\.
 */
