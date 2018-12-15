typedef unsigned short __be16;
typedef unsigned short __u16;
typedef unsigned short u16;
#define __force

#define __swab16(x) (__u16)__builtin_bswap16((__u16)(x))
/* the test behaves as though it's always on a little-endian machine */
#define __cpu_to_be16(x) ((__force __be16)__swab16((x)))
#define ___htons(x) __cpu_to_be16(x)
#define htons(x) ___htons(x)

#define ETH_P_IPV6 0x86DD

static u16 protocol;

static void test(void)
{
	switch (protocol) {
	case htons(ETH_P_IPV6):
		break;
	}
}

/*
 * check-name: constant folding in bswap builtins
 * check-error-start
 * check-error-end
 */
