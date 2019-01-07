void foo(int a);
void foo(int a)
{
	void *l = &&end + 3;

end:
	if (a * 0)
		goto *l;
}

/*
 * check-name: kill-computedgoto
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-excludes: add\\.
 */
