void foo(int x);
void foo(int x)
{
	unsigned int ui;

	ui = x + 1;
	ui = ui ? 0 : 1;
}

/*
 * check-name: kill-select
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-excludes: add\\.
 */
