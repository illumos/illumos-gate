static int array[] = { 0, 1, 2, 3, };
_Static_assert(sizeof(array) == 4 * sizeof(int), "size of array");


typedef int table_t[];
static table_t tbl2 = {
	0,
	1,
};
_Static_assert(sizeof(tbl2) == 2 * sizeof(int), "size of tbl2");

static table_t tbl1 = {
	0,
};
_Static_assert(sizeof(tbl1) == 1 * sizeof(int), "size of tbl1");

static table_t tbl3 = {
	0,
	1,
	2,
};
_Static_assert(sizeof(tbl3) == 3 * sizeof(int), "size of tbl3");

/*
 * check-name: array-implicit-size
 */
