typedef unsigned short	   u16;
typedef unsigned int	   u32;
typedef unsigned long long u64;

static u16 swap16v(u16 a)
{
	return __builtin_bswap16(a);
}

static u32 swap32v(u64 a)
{
	return __builtin_bswap32(a);
}

static u64 swap64v(u32 a)
{
	return __builtin_bswap64(a);
}

/*
 * check-name: builtin-bswap
 * check-command: test-linearize $file
 * check-description: Check that the right builtin function is called, and
 *                    that the args are correctly promoted or truncated.
 *
 * check-output-ignore
 * check-output-contains:call.16 .* __builtin_bswap16
 * check-output-contains:cast.32 .* (64) %arg1
 * check-output-contains:call.32 .* __builtin_bswap32
 * check-output-contains:cast.64 .* (32) %arg1
 * check-output-contains:call.64 .* __builtin_bswap64
 */
