static double d = __builtin_huge_val();
static float f = __builtin_huge_valf();
static long double l = __builtin_huge_vall();
static double di = __builtin_inf();
static float fi = __builtin_inff();
static long double li = __builtin_infl();
static double dn = __builtin_nan("");
static float fn = __builtin_nanf("");
static long double ln = __builtin_nanl("");
static int inf = __builtin_isinf_sign(0.0);
static int fin = __builtin_isfinite(0.0);
static int nan = __builtin_isnan(0.0);

/*
 * check-name: __builtin INFINITY / nan()
 */
