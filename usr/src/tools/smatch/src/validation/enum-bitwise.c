#define __bitwise __attribute__((bitwise))
#define __force   __attribute__((force))

typedef long long __bitwise bits;

enum r {
	RZ = (__force bits) 0,
	RO = (__force bits) 1,
	RM = (__force bits) -1,
};

_Static_assert([typeof(RZ)] == [bits], "RZ");
_Static_assert([typeof(RO)] == [bits], "RO");
_Static_assert([typeof(RM)] == [bits], "RM");
_Static_assert(sizeof(enum r) == sizeof(bits), "bits");

/*
 * check-name: enum-bitwise
 */
