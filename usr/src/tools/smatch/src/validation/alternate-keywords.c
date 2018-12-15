
extern float strtof(const char *__restrict__ ptr, char **__restrict__ endptr);
extern double strtod(const char *__restrict ptr, char **__restrict endptr);
/* restrict: -std=c99 or -std=gnu99 or -std=c11 */
extern long double strtold(const char *restrict ptr, char **restrict endptr);

extern int (*funcs[])(void);

/* typeof: no -std or -std=gnu90 or -std=gnu99 or -std=gnu11 */
extern typeof (funcs[0]) f0;
extern __typeof (funcs[1]) f1;
extern __typeof__(funcs[2]) f2;

typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

static __inline__ uint16_t swap16(uint16_t val)
{
	return ((((uint16_t)(val) & (uint16_t)0x00ffU) << 8) |
		(((uint16_t)(val) & (uint16_t)0xff00U) >> 8));
}

static __inline uint32_t swap32(uint32_t val)
{
	return ((((uint32_t)(val) & (uint32_t)0x000000ffUL) << 24) |
		(((uint32_t)(val) & (uint32_t)0x0000ff00UL) <<  8) |
		(((uint32_t)(val) & (uint32_t)0x00ff0000UL) >>  8) |
		(((uint32_t)(val) & (uint32_t)0xff000000UL) >> 24));
}

/* inline: no -std or -std=gnu90 or -std=c99 or -std=c11 */
static inline uint64_t swap64(uint64_t val)
{
	return ((((uint64_t)(val) & (uint64_t)0x00000000000000ffULL) << 56) |
		(((uint64_t)(val) & (uint64_t)0x000000000000ff00ULL) << 40) |
		(((uint64_t)(val) & (uint64_t)0x0000000000ff0000ULL) << 24) |
		(((uint64_t)(val) & (uint64_t)0x00000000ff000000ULL) <<  8) |
		(((uint64_t)(val) & (uint64_t)0x000000ff00000000ULL) >>  8) |
		(((uint64_t)(val) & (uint64_t)0x0000ff0000000000ULL) >> 24) |
		(((uint64_t)(val) & (uint64_t)0x00ff000000000000ULL) >> 40) |
		(((uint64_t)(val) & (uint64_t)0xff00000000000000ULL) >> 56));
}
/*
 * check-name: alternate keywords
 */
