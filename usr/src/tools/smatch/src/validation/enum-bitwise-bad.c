#define __bitwise __attribute__((bitwise))
#define __force   __attribute__((force))

typedef int __bitwise apple_t;
typedef int __bitwise orange_t;

enum fruit {
	A = (__force  apple_t) 0,
	B = (__force orange_t) 1,
};

/*
 * check-name: enum-bitwise-bad
 *
 * check-error-start
enum-bitwise-bad.c:9:14: error: incompatible restricted type
enum-bitwise-bad.c:9:14:    expected: restricted apple_t
enum-bitwise-bad.c:9:14:         got: restricted orange_t
 * check-error-end
 */
