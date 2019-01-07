#ifndef _COMPAT_BSWAP_H_
#define _COMPAT_BSWAP_H_

#if defined(__GNUC__)
#if (__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 8))
#define	__HAS_BUILTIN_BSWAP16
#endif
#if (__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4))
#define	__HAS_BUILTIN_BSWAP32
#define	__HAS_BUILTIN_BSWAP64
#endif
#endif

#if defined(__clang__)
#if (__clang_major__ > 3) || ((__clang_major__ == 3) && (__clang_minor__ >= 2))
#define	__HAS_BUILTIN_BSWAP16
#endif
#if (__clang_major__ > 3) || ((__clang_major__ == 3) && (__clang_minor__ >= 0))
#define	__HAS_BUILTIN_BSWAP32
#define	__HAS_BUILTIN_BSWAP64
#endif
#endif

#ifdef __HAS_BUILTIN_BSWAP16
#define bswap16(x)	__builtin_bswap16(x)
#else
#include <stdint.h>
static inline uint16_t bswap16(uint16_t x)
{
	return x << 8 | x >> 8;
}
#endif

#ifdef __HAS_BUILTIN_BSWAP32
#define bswap32(x)	__builtin_bswap32(x)
#else
#include <stdint.h>
static inline uint32_t bswap32(uint32_t x)
{
	return x >> 24 | (x >> 8 & 0xff00) | (x << 8 & 0xff0000) | x << 24;
}
#endif

#ifdef __HAS_BUILTIN_BSWAP64
#define bswap64(x)	__builtin_bswap64(x)
#else
#include <stdint.h>
static inline uint64_t bswap64(uint64_t x)
{
	return ((uint64_t)bswap32(x)) << 32 | bswap32(x >> 32);
}
#endif

#endif
