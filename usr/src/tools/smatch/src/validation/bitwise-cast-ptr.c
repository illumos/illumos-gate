#define __bitwise	__attribute__((bitwise))
#define __force		__attribute__((force))

typedef unsigned int u32;
typedef unsigned int __bitwise __be32;

static __be32* tobi(u32 *x)
{
	return x;			// should warn, implicit cast
}

static __be32* tobe(u32 *x)
{
	return (__be32 *) x;		// should warn, explicit cast
}

static __be32* tobf(u32 *x)
{
	return (__force __be32 *) x;	// should not warn, forced cast
	return (__be32 __force *) x;	// should not warn, forced cast
}

/*
 * check-name: cast of bitwise pointers
 * check-command: sparse -Wbitwise -Wbitwise-pointer $file
 *
 * check-error-start
bitwise-cast-ptr.c:9:16: warning: incorrect type in return expression (different base types)
bitwise-cast-ptr.c:9:16:    expected restricted __be32 [usertype] *
bitwise-cast-ptr.c:9:16:    got unsigned int [usertype] *x
bitwise-cast-ptr.c:14:17: warning: cast to restricted __be32 [usertype] *
 * check-error-end
 */
