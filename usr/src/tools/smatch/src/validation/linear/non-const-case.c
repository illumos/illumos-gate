static int foo(int a)
{
	switch (a) {
	case 0:
		return a;
	case a:
		return 0;
	case (a - a):
		return 1;
	default:
		return a;
	}
}

static int bar(int a)
{
	switch (a) {
	case 0:
		break;
	case a:
		a++;
label:
		return a;
	}

	goto label;
}


/*
 * check-name: non-const-case
 * check-command: test-linearize -Wno-decl $file
 *
 * check-error-ignore
 * check-output-ignore
 * check-output-excludes:switch \\.
 */
