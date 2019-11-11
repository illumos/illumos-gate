enum bound_int_max {
	IMAX = __INT_MAX__,
};
_Static_assert([typeof(IMAX)] == [int], "");

enum bound_int_maxp1 {
	IMP1 = __INT_MAX__ + 1L,
};
_Static_assert([typeof(IMP1)] == [unsigned int], "");

enum bound_int_maxm1 {
	IMM1 = -__INT_MAX__ - 1L,
};
_Static_assert([typeof(IMM1)] == [int], "");

enum bound_int_maxm2 {
	IMM2 = -__INT_MAX__ - 2L,
};
_Static_assert([typeof(IMM2)] == [long], "");

/*
 * check-name: enum-bounds
 * check-command: sparse -m64 $file
 * check-assert: sizeof(long) == 8
 */
