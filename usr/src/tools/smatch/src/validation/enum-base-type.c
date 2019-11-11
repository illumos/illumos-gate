enum n {
	NA,
	NB = 1L,
	NC = 1UL,
	ND = 1LL,
	NE = 1ULL,
	NF = -1,
	NG = -1L,
	NH = -1LL,
};
_Static_assert(sizeof(enum n) == sizeof(int), "+-1");

enum m {
	MA = 0L,
	MB = 1L,
	MG = -1L,
};
_Static_assert(sizeof(enum m) == sizeof(int), "+-1L");

enum p {
	PA = 0UL,
	PB = 1UL,
};
_Static_assert(sizeof(enum p) == sizeof(int), "UL");

/*
 * check-name: enum-base-type
 * check-command: sparse -m64 $file
 */
