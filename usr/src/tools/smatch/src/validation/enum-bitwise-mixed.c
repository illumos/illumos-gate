#define __bitwise __attribute__((bitwise))
#define __force   __attribute__((force))

typedef long long __bitwise bits;

enum a {
	AR = (__force bits) 0,
	AP = 0,
	AS = (__force bits) 1,
	AQ = 1,
};
_Static_assert(sizeof(AP) == sizeof(int), "is bad?");

enum b {
	BP = 0,
	BR = (__force bits) 0,
	BQ = 1,
	BS = (__force bits) 1,
};
_Static_assert(sizeof(BP) == sizeof(int), "is bad?");

/*
 * check-name: enum-bitwise-mixed
 *
 * check-error-start
enum-bitwise-mixed.c:8:14: warning: mixed bitwiseness
enum-bitwise-mixed.c:16:15: warning: mixed bitwiseness
 * check-error-end
 */
