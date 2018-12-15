static int ref[] = {
	[1] = 3,
	[2] = 3,
	[3] = 3,
	[2] = 2,		/* check-should-warn */
	[1] = 1,		/* check-should-warn */
};

static int foo[] = {
	[1 ... 3] = 3,
};

static int foz[4] = {
	[0 ... 3] = 3,
	[0] = 0,
	[1] = 0,
	[2 ... 3] = 1,
	[2] = 3,		/* check-should-warn */
	[3] = 3,		/* check-should-warn */
};

static int bar[] = {
	[1 ... 3] = 3,
	[1]       = 1,		/* check-should-warn */
	[2]       = 2,		/* check-should-warn */
	[2 ... 4] = 2,		/* check-should-warn */
	[2 ... 3] = 2,		/* check-should-warn */
	[4] = 4,		/* check-should-warn */
	[0] = 0,
	[5] = 5,
};

static int baz[3][3] = {
	[0 ... 2][0 ... 2] = 0,
	[0] = { 0, 0, 0, },	/* check-should-warn */
	[0][0] = 1,		/* check-should-warn */
	[1] = { 0, 0, 0, },	/* check-should-warn */
	[1][0] = 1,		/* check-should-warn */
	[1][1] = 1,		/* check-should-warn */
	[1 ... 2][1 ... 2] = 2,
};


struct s {
	int i;
	int a[2];
};

static struct s s = {
	.a[0] = 0,
	.a[1] = 1,
};

static struct s a[2] = {
	[0].i = 0,
	[1].i = 1,
	[0].a[0] = 2,
	[0].a[1] = 3,
};

static struct s b[2] = {
	[0 ... 1] = { 0, { 1, 2 }, },
	[0].i = 0,
	[1].i = 1,
	[0].a[0] = 2,
	[0].a[1] = 3,
};

/*
 * check-name: field-override
 * check-command: sparse -Woverride-init -Woverride-init-all $file
 *
 * check-error-start
field-override.c:2:10: warning: Initializer entry defined twice
field-override.c:6:10:   also defined here
field-override.c:3:10: warning: Initializer entry defined twice
field-override.c:5:10:   also defined here
field-override.c:17:10: warning: Initializer entry defined twice
field-override.c:18:10:   also defined here
field-override.c:17:10: warning: Initializer entry defined twice
field-override.c:19:10:   also defined here
field-override.c:23:10: warning: Initializer entry defined twice
field-override.c:24:10:   also defined here
field-override.c:23:10: warning: Initializer entry defined twice
field-override.c:25:10:   also defined here
field-override.c:23:10: warning: Initializer entry defined twice
field-override.c:26:10:   also defined here
field-override.c:26:10: warning: Initializer entry defined twice
field-override.c:27:10:   also defined here
field-override.c:26:10: warning: Initializer entry defined twice
field-override.c:28:10:   also defined here
field-override.c:35:10: warning: Initializer entry defined twice
field-override.c:36:10:   also defined here
field-override.c:37:10: warning: Initializer entry defined twice
field-override.c:38:10:   also defined here
field-override.c:37:10: warning: Initializer entry defined twice
field-override.c:39:10:   also defined here
field-override.c:37:10: warning: Initializer entry defined twice
field-override.c:40:10:   also defined here
 * check-error-end
 */
