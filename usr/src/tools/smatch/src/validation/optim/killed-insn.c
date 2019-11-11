static void foo(int v)
{
	int a[2] = { };
	a;
	a[1] = v;
}

/*
 * check-name: killed-insn
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-excludes: store\\.
 */
