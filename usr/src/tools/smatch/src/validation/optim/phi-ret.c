int foo(int p, int q, int v)
{
	if (q) {
		if (p) {
			v = p;
			p = 0;
		}
	} else
		p = 0;
	if (p)
		return v + 1;
	return q;
}

/*
 * check-name: phi-ret
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: phi\\.
 */
