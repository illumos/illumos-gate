static int array[] = {
	[1] = 3,
	[1] = 1,		/* check-should-warn */
};

/*
 * check-name: Woverride-init-yes
 * check-command: sparse -Woverride-init $file
 *
 * check-error-start
Woverride-init-yes.c:2:10: warning: Initializer entry defined twice
Woverride-init-yes.c:3:10:   also defined here
 * check-error-end
 */
