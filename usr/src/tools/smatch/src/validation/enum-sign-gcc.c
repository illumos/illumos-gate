// For enum's underlying/compatible type:
//  std C:	unspecified
//  GCC:	'unsigned int' if no negative values,
//		otherwise 'int' (see GCC manul 4.9).
//		But also accept ulong, long
// For the type of the enumerators:
// std C:	'int'
// GCC:		'int' if the value fit in a 'int'
//		otherwise same as the enum underlying type?
//
// The following tests match GCC's choices

#define is_unsigned(X) ((typeof(X))-1 > 0)

enum u {
	U = 1U,			// fit in 'int'
	// no negatives
};
_Static_assert(sizeof(enum u) == sizeof(int), "size");
_Static_assert(is_unsigned(enum u), "enum u");
_Static_assert(is_unsigned(U) == 0, "value U");		// fail

enum v {
	V = __INT_MAX__ + 1U,	// doesn't fit in 'int'
	// no negatives
};
_Static_assert(sizeof(enum v) == sizeof(int), "size");
_Static_assert(is_unsigned(enum v), "enum v");
_Static_assert(is_unsigned(V) == 1, "value V");

enum w {
	W = __LONG_MAX__ + 1UL,	// doesn't fit in 'long'
};
_Static_assert(sizeof(enum w) == sizeof(long), "size");
_Static_assert(is_unsigned(enum w), "enum w");
_Static_assert(is_unsigned(W) == 1, "value W");

enum x {
	A = 1,			// fit in 'int'
	B = 0x100000000UL,	// doesn't fit in int
};
_Static_assert(sizeof(enum x) == sizeof(long), "size");
_Static_assert(is_unsigned(enum x), "enum x");
_Static_assert(sizeof(A) == sizeof(int), "size A");	// fail
_Static_assert(is_unsigned(A) == 0, "enum A");		// fail
_Static_assert(sizeof(B) == sizeof(long), "size B");
_Static_assert(is_unsigned(B) == 1, "enum B");

enum y {
	C = 1,			// fit in 'int'
	D = 0x100000000L,	// doesn't fit in int
};
_Static_assert(sizeof(enum y) == sizeof(long), "size");
_Static_assert(is_unsigned(enum y), "enum y");
_Static_assert(sizeof(C) == sizeof(int), "size C");	// fail
_Static_assert(is_unsigned(C) == 0, "enum C");		// fail
_Static_assert(sizeof(D) == sizeof(long), "size D");
_Static_assert(is_unsigned(D) == 1, "enum D");

/*
 * check-name: enum-sign-gcc
 * check-command: sparse -m64 $file
 * check-assert: sizeof(long) == 8
 */
