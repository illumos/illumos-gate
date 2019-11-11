extern int i;

static void foo(void)
{
	switch (i) {
	case 0:
		;
	}
}

/*
 * check-name: kill-switch
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-excludes: load\\.
 */
