/* Tests for the "Initializer entry defined twice" warning. */

/* Initializing a struct field twice should trigger the warning. */
struct normal {
	int field1;
	int field2;
};

static struct normal struct_error = {
	.field1 = 0,
	.field1 = 0
};

/* Initializing two different fields of a union should trigger the warning. */
struct has_union {
	int x;
	union {
		int a;
		int b;
	} y;
	int z;
};

static struct has_union union_error = {
	.y = {
		.a = 0,
		.b = 0
	}
};

/* Empty structures can make two fields have the same offset in a struct.
 * Initializing both should not trigger the warning. */
struct empty { };

struct same_offset {
	struct empty field1;
	int field2;
};

static struct same_offset not_an_error = {
	.field1 = { },
	.field2 = 0
};

/*
 * _Bools generally take a whole byte, so ensure that we can initialize
 * them without spewing a warning.
 */
static _Bool boolarray[3] = {
	[0] = 1,
	[1] = 1,
};

/*
 * check-name: Initializer entry defined twice
 *
 * check-error-start
initializer-entry-defined-twice.c:10:10: warning: Initializer entry defined twice
initializer-entry-defined-twice.c:11:10:   also defined here
initializer-entry-defined-twice.c:26:18: warning: Initializer entry defined twice
initializer-entry-defined-twice.c:27:18:   also defined here
 * check-error-end
 */
