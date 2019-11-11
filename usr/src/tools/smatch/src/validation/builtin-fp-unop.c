static void test_not_enough_args(void)
{
	__builtin_isfinite();
	__builtin_isinf();
	__builtin_isinf_sign();
	__builtin_isnan();
	__builtin_isnormal();
	__builtin_signbit();
}

static void test_too_many_args(double v)
{
	__builtin_isfinite(v, v);
	__builtin_isinf(v, v);
	__builtin_isinf_sign(v, v);
	__builtin_isnan(v, v);
	__builtin_isnormal(v, v);
	__builtin_signbit(v, v);
}

static void test_non_float(int v)
{
	__builtin_isfinite(v);
	__builtin_isinf(v);
	__builtin_isinf_sign(v);
	__builtin_isnan(v);
	__builtin_isnormal(v);
	__builtin_signbit(v);
}

static void test_float(float v)
{
	__builtin_isfinite(v);
	__builtin_isinf(v);
	__builtin_isinf_sign(v);
	__builtin_isnan(v);
	__builtin_isnormal(v);
	__builtin_signbit(v);
}

static void test_double(double v)
{
	__builtin_isfinite(v);
	__builtin_isinf(v);
	__builtin_isinf_sign(v);
	__builtin_isnan(v);
	__builtin_isnormal(v);
	__builtin_signbit(v);
}

static void test_ldouble(long double v)
{
	__builtin_isfinite(v);
	__builtin_isinf(v);
	__builtin_isinf_sign(v);
	__builtin_isnan(v);
	__builtin_isnormal(v);
	__builtin_signbit(v);
}

static void test_constant(void)
{
	__builtin_isfinite(0.0);
	__builtin_isinf(0.0);
	__builtin_isinf_sign(0.0);
	__builtin_isnan(0.0);
	__builtin_isnormal(0.0);
	__builtin_signbit(0.0);
}

/*
 * check-name: builtin float-point unop
 * check-command: sparse -Wno-decl $file
 *
 * check-error-start
builtin-fp-unop.c:3:27: error: not enough arguments for __builtin_isfinite
builtin-fp-unop.c:4:24: error: not enough arguments for __builtin_isinf
builtin-fp-unop.c:5:29: error: not enough arguments for __builtin_isinf_sign
builtin-fp-unop.c:6:24: error: not enough arguments for __builtin_isnan
builtin-fp-unop.c:7:27: error: not enough arguments for __builtin_isnormal
builtin-fp-unop.c:8:26: error: not enough arguments for __builtin_signbit
builtin-fp-unop.c:13:27: error: too many arguments for __builtin_isfinite
builtin-fp-unop.c:14:24: error: too many arguments for __builtin_isinf
builtin-fp-unop.c:15:29: error: too many arguments for __builtin_isinf_sign
builtin-fp-unop.c:16:24: error: too many arguments for __builtin_isnan
builtin-fp-unop.c:17:27: error: too many arguments for __builtin_isnormal
builtin-fp-unop.c:18:26: error: too many arguments for __builtin_signbit
builtin-fp-unop.c:23:27: error: non-floating-point argument in call to __builtin_isfinite()
builtin-fp-unop.c:24:24: error: non-floating-point argument in call to __builtin_isinf()
builtin-fp-unop.c:25:29: error: non-floating-point argument in call to __builtin_isinf_sign()
builtin-fp-unop.c:26:24: error: non-floating-point argument in call to __builtin_isnan()
builtin-fp-unop.c:27:27: error: non-floating-point argument in call to __builtin_isnormal()
builtin-fp-unop.c:28:26: error: non-floating-point argument in call to __builtin_signbit()
 * check-error-end
 */
