// See if the replaced operation is effectively killed or not

static int kill_add(int a, int b)
{
	return (a + b) && 0;
}

static int kill_scast(short a)
{
	return ((int) a) && 0;
}

static int kill_ucast(unsigned char a)
{
	return ((int) a) && 0;
}

static int kill_pcast(int *a)
{
	return ((void*) a) && 0;
}

static int kill_fcast(double a)
{
	return ((int) a) && 0;
}

static int kill_select(int a)
{
	return (a ? 1 : 0) && 0;
}

static int kill_setval(int a)
{
l:
	return &&l && 0;
}

static int kill_load(int *a)
{
	return *a && 0;
}

static int kill_store(int *a)
{
	return (*a = 1) && 0;
}

/*
 * check-name: kill-replaced-insn
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-excludes: add\\.
 * check-output-excludes: scast\\.
 * check-output-excludes: \\<cast\\.
 * check-output-excludes: ptrcast\\.
 * check-output-excludes: fpcast\\.
 * check-output-excludes: sel\\.
 * check-output-excludes: set\\.
 */
