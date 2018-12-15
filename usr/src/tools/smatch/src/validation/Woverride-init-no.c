static int array[] = {
	[1] = 3,
	[1] = 1,		/* check-should-warn */
};

/*
 * check-name: Woverride-init-no
 * check-command: sparse -Wno-override-init $file
 *
 * check-error-start
 * check-error-end
 */
