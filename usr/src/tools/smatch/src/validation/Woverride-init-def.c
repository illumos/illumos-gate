static int array[] = {
	[1] = 3,
	[1] = 1,		/* check-should-warn */
};

/*
 * check-name: Woverride-init-def
 * check-command: sparse $file
 *
 * check-error-start
Woverride-init-def.c:2:10: warning: Initializer entry defined twice
Woverride-init-def.c:3:10:   also defined here
 * check-error-end
 */
