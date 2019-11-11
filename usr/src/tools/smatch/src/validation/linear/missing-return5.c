int foo(int p)
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
 * check-name: missing/undef return
 * check-command: test-linearize -Wno-decl -fdump-ir=linearize $file
 *
 * check-output-ignore
 * check-output-pattern(2): phi\\..*,.*
 * check-output-pattern(2): phisrc\\..*\\$0
 * check-output-pattern(2): phisrc\\..*UNDEF
 * check-output-excludes: ret\\..*\\$0
 */
