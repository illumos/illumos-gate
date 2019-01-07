static unsigned int bad_nbr_args_cte(int a)
{
	int r = 0;
	r |= __builtin_bswap16();
	r |= __builtin_bswap16(1, 2);
	r |= __builtin_bswap32();
	r |= __builtin_bswap32(1, 2);
	r |= __builtin_bswap64();
	r |= __builtin_bswap64(1, 2);
	return r;
}

static unsigned int bad_nbr_args_var(int a, int b)
{
	int r = 0;
	r |= __builtin_bswap16();
	r |= __builtin_bswap16(a, b);
	r |= __builtin_bswap32();
	r |= __builtin_bswap32(a, b);
	r |= __builtin_bswap64();
	r |= __builtin_bswap64(a, b);
	return r;
}

/*
 * check-name: builtin-args-checking
 * check-command: sparse $file
 * check-description: Check that the arguments checking is done
 *                    for expanded builtins with a prototype.
 *
 * check-error-start
builtin-args-checking.c:4:31: error: not enough arguments for function __builtin_bswap16
builtin-args-checking.c:5:31: error: too many arguments for function __builtin_bswap16
builtin-args-checking.c:6:31: error: not enough arguments for function __builtin_bswap32
builtin-args-checking.c:7:31: error: too many arguments for function __builtin_bswap32
builtin-args-checking.c:8:31: error: not enough arguments for function __builtin_bswap64
builtin-args-checking.c:9:31: error: too many arguments for function __builtin_bswap64
builtin-args-checking.c:16:31: error: not enough arguments for function __builtin_bswap16
builtin-args-checking.c:17:31: error: too many arguments for function __builtin_bswap16
builtin-args-checking.c:18:31: error: not enough arguments for function __builtin_bswap32
builtin-args-checking.c:19:31: error: too many arguments for function __builtin_bswap32
builtin-args-checking.c:20:31: error: not enough arguments for function __builtin_bswap64
builtin-args-checking.c:21:31: error: too many arguments for function __builtin_bswap64
 * check-error-end
 */
