/*
 * Copyright (c) 2014 Alex Crichton
 *
 * Permission is hereby granted, free of charge, to any
 * person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the
 * Software without restriction, including without
 * limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software
 * is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice
 * shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
 * ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
 * SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
 * IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
/*
 * Copyright 2019, Joyent, Inc.
 */

/*
 * Test cases taken from rustc-demangle 0.1.9
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <demangle-sys.h>

typedef struct rust_test_case {
	const char *mangled;
	const char *demangled;
} rust_test_case_t;
#define	T(_m, _d) { .mangled = _m, .demangled = _d }
#define	T_ERR(_m) { .mangled = _m }

typedef struct rust_test_grp {
	const char		*name;
	rust_test_case_t	tests[];
} rust_test_grp_t;
#define	GROUP(_n, ...)			\
	static rust_test_grp_t _n = {	\
		.name = #_n,		\
		.tests = {		\
			__VA_ARGS__,	\
			{ NULL, NULL }	\
		}			\
	}

GROUP(demangle,
    T_ERR("test"),
    T("_ZN4testE", "test"),
    T_ERR("_ZN4test"),
    T("_ZN4test1a2bcE", "test::a::bc"));

GROUP(demangle_dollars,
    T("_ZN4$RP$E", ")"),
    T("_ZN8$RF$testE", "&test"),
    T("_ZN8$BP$test4foobE", "*test::foob"),
    T("_ZN9$u20$test4foobE", " test::foob"),
    T("_ZN35Bar$LT$$u5b$u32$u3b$$u20$4$u5d$$GT$E", "Bar<[u32; 4]>"));

GROUP(demangle_many_dollars,
    T("_ZN13test$u20$test4foobE", "test test::foob"),
    T("_ZN12test$BP$test4foobE", "test*test::foob"));

/* BEGIN CSTYLED */
GROUP(demangle_osx,
    T("__ZN5alloc9allocator6Layout9for_value17h02a996811f781011E",
    "alloc::allocator::Layout::for_value::h02a996811f781011"),
    T("__ZN38_$LT$core..option..Option$LT$T$GT$$GT$6unwrap18_MSG_FILE_LINE_COL17haf7cb8d5824ee659E",
    "<core::option::Option<T>>::unwrap::_MSG_FILE_LINE_COL::haf7cb8d5824ee659"),
    T("__ZN4core5slice89_$LT$impl$u20$core..iter..traits..IntoIterator$u20$for$u20$$RF$$u27$a$u20$$u5b$T$u5d$$GT$9into_iter17h450e234d27262170E",
    "core::slice::<impl core::iter::traits::IntoIterator for &'a [T]>::into_iter::h450e234d27262170"));
/* END CSTYLED */

GROUP(demangle_elements_beginning_with_underscore,
    T("_ZN13_$LT$test$GT$E", "<test>"),
    T("_ZN28_$u7b$$u7b$closure$u7d$$u7d$E", "{{closure}}"),
    T("_ZN15__STATIC_FMTSTRE", "__STATIC_FMTSTR"));

/* BEGIN CSTYLED */
GROUP(demangle_trait_impls,
    T("_ZN71_$LT$Test$u20$$u2b$$u20$$u27$static$u20$as$u20$foo..Bar$LT$Test$GT$$GT$3barE",
    "<Test + 'static as foo::Bar<Test>>::bar"));
/* END CSTYLED */

GROUP(invalid_no_chop, T_ERR("_ZNfooE"));

/* BEGIN CSTYLED */
GROUP(handle_assoc_types,
    T("_ZN151_$LT$alloc..boxed..Box$LT$alloc..boxed..FnBox$LT$A$C$$u20$Output$u3d$R$GT$$u20$$u2b$$u20$$u27$a$GT$$u20$as$u20$core..ops..function..FnOnce$LT$A$GT$$GT$9call_once17h69e8f44b3723e1caE",
    "<alloc::boxed::Box<alloc::boxed::FnBox<A, Output=R> + 'a> as core::ops::function::FnOnce<A>>::call_once::h69e8f44b3723e1ca"));
/* END CSTYLED */

static rust_test_grp_t *rust_tests[] = {
	&demangle,
	&demangle_dollars,
	&demangle_many_dollars,
	&demangle_osx,
	&demangle_elements_beginning_with_underscore,
	&demangle_trait_impls,
	&invalid_no_chop,
	&handle_assoc_types
};

static const size_t n_rust_tests = ARRAY_SIZE(rust_tests);

static boolean_t
check_failure(size_t i, rust_test_case_t *tc, const char *dem, boolean_t res)
{
	int savederr = errno;

	if (dem == NULL && savederr == EINVAL)
		return (B_TRUE);

	if (res)
		(void) printf("FAILURE\n");

	if (dem != NULL) {
		(void) printf("  [%zu] Successfully demanged an invalid "
		    "name\n", i);
		(void) printf("         Name: '%s'\n", tc->mangled);
		(void) printf("    Demangled: '%s'\n", dem);
		return (B_FALSE);
	}

	(void) printf("  [%zu] demangle() returned an unexpected error\n", i);
	(void) printf("    Errno: %d\n", savederr);
	return (B_FALSE);
}

static boolean_t
check_success(size_t i, rust_test_case_t *tc, const char *dem, boolean_t res)
{
	if (dem != NULL && strcmp(tc->demangled, dem) == 0)
		return (B_TRUE);

	if (res)
		(void) printf("FAILURE\n");

	if (dem == NULL) {
		(void) printf("  [%zu] Failed to demangle '%s'\n", i,
		    tc->mangled);
		return (B_FALSE);
	}

	(void) printf("  [%zu] Demangled results do not match.\n", i);
	(void) printf("       Mangled: %s\n", tc->mangled);
	(void) printf("      Expected: %s\n", tc->demangled);
	(void) printf("        Actual: %s\n", dem);
	return (B_FALSE);
}

static boolean_t
run_test(rust_test_grp_t *test)
{
	boolean_t res = B_TRUE;

	(void) printf("Test %s: ", test->name);

	for (size_t i = 0; test->tests[i].mangled != NULL; i++) {
		char *dem;

		dem = sysdemangle(test->tests[i].mangled, SYSDEM_LANG_RUST,
		    NULL);
		if (test->tests[i].demangled == NULL)
			res &= check_failure(i, &test->tests[i], dem, res);
		else
			res &= check_success(i, &test->tests[i], dem, res);

		free(dem);
	}

	if (res)
		(void) printf("SUCCESS\n");

	return (res);
}

int
main(int argc, char **argv)
{
	boolean_t ok = B_TRUE;

	for (size_t i = 0; i < n_rust_tests; i++)
		ok &= run_test(rust_tests[i]);

	return (ok ? 0 : 1);
}

const char *
_umem_debug_init(void)
{
	return ("default,verbose");
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents");
}
