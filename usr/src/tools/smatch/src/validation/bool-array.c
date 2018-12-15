static _Bool boolarray_d1[1];
static _Bool boolarray_d8[8];
static _Bool boolarray_i2[2] = {
	0,
	1,
};
static int nd1 = sizeof(boolarray_d1);
static int nd8 = sizeof(boolarray_d8);
static int ni2 = sizeof(boolarray_i2);


static long longarray_u2[] = {
	0,
	1,
};
static int nl2 = sizeof(longarray_u2);

/*
 * Used to get "warning: excessive elements in array initializer"
 * for all elements but the first one.
 * Note: only occurs if nbr of elements is a multiple of 8
 *       (if not, theer was another problem)
 */
static _Bool boolarray_u8[] = {
	0,
	1,
	0,
	1,
	0,
	1,
	0,
	1,
};

/*
 * Used to get "error: cannot size expression" for the sizeof.
 */
static _Bool boolarray_u2[] = {
	0,
	1,
};
static int nu2 = sizeof(boolarray_u2);

/*
 * check-name: sizeof(bool array)
 * check-command: sparse -Wno-sizeof-bool $file
 */
