#if defined(__BIG_ENDIAN__)
#error "__BIG_ENDIAN__ defined!"
#endif
#if (__LITTLE_ENDIAN__ != 1)
#error "__LITTLE_ENDIAN__ not correctly defined!"
#endif
#if (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
#error "__BYTE_ORDER__ not correctly defined!"
#endif

/*
 * check-name: endian-little.c
 * check-command: sparse -mlittle-endian $file
 */
