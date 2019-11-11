int f1(void)
{
	if (1)
		return 1;
}

int f0(void)
{
	if (0)
		return 0;
}

int fx(int p)
{
	if (p)
		return 0;
}

int bar(int p)
{
	if (p)
		return 0;
	p++;
}

/*
 * check-name: missing-return
 * check-command: test-linearize -m32 -fdump-ir=mem2reg -Wno-decl $file
 * check-known-to-fail
 *
 * check-output-ignore
 * check-output-pattern(1): ret.32 *\\$1
 * check-output-pattern(3): ret.32 *UNDEF
 */
