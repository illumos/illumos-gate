/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2025 Oxide Computer Company
 * Copyright 2024 Ryan Zezeski
 */

/*
 * The Kernel Test Facility
 * ------------------------
 *
 * The kernel test facility, otherwise known as "ktest", provides a
 * means for in situ kernel testing. It allows one to write kernel
 * modules whose purpose is to test other kernel modules (or the
 * kernel at large). While much can be tested from userland, there are
 * some cases where there is no substitute for running the test code
 * in kernel context, right next to the code it's testing. In many
 * cases it's the only way to efficiently test specific execution
 * paths, by avoiding the brittleness of action from afar which relies
 * on subtle interactions between userland and kernel. For these
 * cases, and many more, ktest gives you the best chance at directly
 * testing kernel code (short of injecting DEBUG invariant checks
 * inline with the code itself).
 *
 * The kernel test facility provides the following.
 *
 * - The ktest kernel module (this file), which acts as a central
 *   location for all administration and execution of test modules.
 *
 * - The ktest(9) API, which provides the tools to write tests and
 *   register them with the ktest module.
 *
 * - The ktest pseudo device, which presents a control surface to
 *   userspace in the form of your typical ioctl interface.
 *
 * - A ktest(8) user command, which provides a user interface to the
 *   ktest facility.
 *
 * Ktest Architecture
 * ------------------
 *
 * ## The Test Triple
 *
 * Ktest provides a three-level namespace for organizing tests,
 * referred to as the "test triple". It consists of the module name,
 * suite name, and test name, written as '<module>:<suite>:<test>'.
 *
 * - Module: The top of the namespace, typically named after the
 *   module-under-test (MUT). The convention is to append the '_test'
 *   suffix to the module-under-test. For example, the 'mac' module
 *   might have a 'mac_ktest' test module. However, there is no hard
 *   rule that a test module must be named after its
 *   module-under-test, it’s merely a suggestion. Such a convention is
 *   a bit unwieldy for large modules like genunix. In those cases it
 *   makes sense to break from the norm.
 *
 * - Suite: Each module consists of one or more suites. A suite groups
 *   tests of related functionality. For example, you may have several
 *   tests that verify checksum routines for which you might name the
 *   suite 'checksum'.
 *
 * - Test: Each suite consists of one of more tests. The name of the
 *   test can be any string which you find descriptive of the test. A
 *   unit test for a single, small function will often use the name of
 *   the function-under-test with a _test suffix added. But for
 *   testing a series of function calls, or a larger function, it may
 *   make sense to abandon this convention.
 *
 * A test triple can be fully or partially-qualified, depending on the
 * context. A fully-qualified triple is one that names one test by
 * specifying each level of the namespace and using no glob characters
 * -- it’s unambiguous. A partially-qualified triple, on the other
 * hand, can be ambiguous; it only names some of the namespace or
 * makes use of glob characters.
 *
 * Fully qualified:
 *
 *   'mac:checksum:mac_sw_cksum_ipv4_tcp_test'
 *
 * Partially qualified
 *
 *   '*'
 *   '*:*:*'
 *   'mac:'
 *   'mac:checksum'
 *   'mac:*:mac_sw*'
 *
 * ## The Context Handle
 *
 * All communication between ktest and the individual test happens via
 * the "context object". This object cannot be accessed directly.
 * Instead, ktest provides a context handle to be accessed via its
 * ktest(9) API. A test must conform to the ktest_fn_t prototype.
 *
 * ## Setting Test Results
 *
 * A test conveys its result using one of the result ktest(9) APIs. A
 * result is typically pass or fail, but a test may also be skipped or
 * may encounter an unforeseen error. See ktest_result_type_t for a
 * description of the types of results. All test results should
 * include the associated source line by way of the __LINE__ macro.
 * The fail, error, and skip results should also include a message
 * giving further context on the result.
 *
 * ktest_result_pass(ktest_ctx_hdl_t *, int)
 *
 *   The test ran as expected and all conditions were met. The result
 *   value is set to KTEST_RESULT_PASS.
 *
 * ktest_result_fail(ktest_ctx_hdl_t *, int, const char *, ...)
 *
 *   One of the test conditions was violated. The test should use the
 *   format string and arguments to create a message describing which
 *   condition failed and why. The result value is set to KTEST_RESULT_FAIL.
 *
 * ktest_result_error(ktest_ctx_hdl_t *, int, const char *, ...)
 *
 *   The test encountered an unexpected error, one that is not
 *   directly related to the logic under test. For example, failure to
 *   acquire memory is often outside of the test parameters for most
 *   tests. These types of errors are often encountered when
 *   interacting with the kernel at large and when acquiring resources
 *   for test setup. Perhaps most importantly, it indicates the lack
 *   of a pass/fail determination for this test. The result value is
 *   set to KTEST_RESULT_ERROR.
 *
 * ktest_result_skip(ktest_ctx_hdl_t *, int, const char *, ...)
 *
 *   The test lacks the required context to execute, typically for
 *   lack of resources or specific hardware under test. Like the error
 *   result, this lacks a pass/fail determination. The result value is
 *   set to KTEST_RESULT_SKIP.
 *
 * ## Result Macros
 *
 * Using the API above is cumbersome, requiring the repetitive use of
 * the __LINE__ macro. The following macros are provided for ease of
 * use.
 *
 *     - KT_PASS(ktest_ctx_hdl_t *ctx)
 *     - KT_FAIL(ktest_ctx_hdl_t *ctx, char *msg, ...)
 *     - KT_ERROR(ktest_ctx_hdl_t *ctx, char *msg, ...)
 *     - KT_SKIP(ktest_ctx_hdl_t *ctx, char *msg, ...)
 *
 * ## KTest ASSERT Macros
 *
 * Even with the help of the result macros, writing test assertions
 * requires quite a bit of verbosity and boilerplate; requiring an if
 * statement, a KT_* call, and the failure message arguments. The
 * KTest ASSERT macros provide an ASSERT3-like family of macros to
 * reduce the boilerplate and make test writing feel more natural.
 * However, they are different from the ASSERT3 family in two major
 * ways.
 *
 * 1. They don't panic. The point is to report test failure, not
 *    preserve system state leading up to an invalid condition.
 *    However, for particularly difficult-to-debug test failures you
 *    could use DTrace to invoke a panic upon entry to
 *    ktest_result_error.
 *
 * 2. Following from (1), there may be test state to cleanup such as
 *    freeing memory or other resources. This cleanup needs to happen
 *    as a consequence of the assertion triggering, before returning
 *    from the test function.
 *
 * There are three types of KT_ASSERT macros: KTest ASSERT, KTest
 * ASSERT Goto, and KTest ASSERT Block. The first type of assert is
 * the closest match to the standard ASSERT macros: they provide no
 * state cleanup, but require the context handle is passed as final
 * argument. The goto versions allow for cleanup via a jump to a
 * label. The block versions allow for cleanup via an attached block,
 * much like an if statement, but requires an additional
 * KT_ASSERTB_END to indicate the end of the block. What follows is a
 * list of the various KT_ASSERT macros and their arguments. For each
 * macro listed below, there is a corresponding KTEST_EASSERT macro.
 * These later macros set a KTEST_ERROR result when tripped.
 *
 * KTest ASSERT (no cleanup)
 *
 *   KTEST_ASSERT3S(left, op, right, ctx)
 *   KTEST_ASSERT3U(left, op, right, ctx)
 *   KTEST_ASSERT3P(left, op, right, ctx)
 *   KTEST_ASSERT(exp, ctx)
 *   KTEST_ASSERT0(exp, ctx)
 *
 * KTest ASSERT Goto (cleanup via label)
 *
 *   KT_ASSERT3SG(left, op, right, ctx, label)
 *   KT_ASSERT3UG(left, op, right, ctx, label)
 *   KT_ASSERT3PG(left, op, right, ctx, label)
 *   KT_ASSERTG(exp, ctx, label)
 *   KT_ASSERT0G(exp, ctx, label)
 *
 * KTest ASSERT Block (cleanup via block)
 *
 *   KT_ASSERT*B(left, op, right, ctx) {
 *      <... cleanup goes here ...>
 *   }
 *   KT_ASSERTB_END
 *
 * ## Additional Failure/Error Context
 *
 * Sometimes the failure message generated by the KT_ASSERT macro is
 * not enough. You might want to prepend some information to the
 * message to provide additional context about the failure. This would
 * require using the ktest result API manually, which defeats the
 * purpose of the KT_ASSERT macros. Instead, ktest offers the
 * ktest_msg_{prepend,clear}(9F) API; allowing you to prepend
 * additional context to the failure message (if the assertion should
 * trip) while still using the KT_ASSERT macros.
 *
 * For example, if you were asserting an invariant on an array of
 * objects, and you wanted the failure message to include the index of
 * the object which tripped the assert, you could write something like
 * the following.
 *
 * ----
 * for (int i = 0; i < num_objs; i++) {
 *         obj_t *obj = &objs[i];
 *
 *         ktest_msg_prepend(ctx, "objs[%d]: ", i);
 *         KT_ASSERT3P(obj->o_state, !=, NULL, ctx);
 * }
 *
 * ktest_msg_clear(ctx);
 * ----
 *
 * The ktest_msg_prepend() call is not additive; it always overwrites
 * the contents of the prepend buffer.
 *
 * ## Test Input
 *
 * A test has the option to require input. The input is always in the
 * form of a byte stream. The interpretation of those bytes is left to
 * the test; the ktest facility at large treats the input stream as
 * opaque. It is legal to have an input stream of zero bytes. The test
 * retrieves its byte stream with the ktest_get_input(9F) API.
 *
 * ## Testing Private Functions
 *
 * A test module often needs to test static (private) functions.
 * However, as the test module and module-under-test are two different
 * modules, and a static function's linkage is local, there is no way
 * to easily access them. Ktest works around this by offering a set of
 * APIs to dynamically load the the function object into the test module.
 *
 *   ktest_hold_mod(9F)
 *   ktest_get_fn(9F)
 *   ktest_release_mod(9F)
 *
 * The test modules must perform four steps when accessing a static
 * function.
 *
 *   1. Recreate the function prototype, typically in the form of a
 *      typedef. This is then used to declare the function pointer to
 *      the static function.
 *
 *   2. Get a handle to the module-under-test via ktest_hold_mod(9F).
 *
 *   3. Fill in the function pointer with ktest_get_fn(9F), after
 *      which it can be called just as it would in the
 *      module-under-test.
 *
 *   4. At completion of the test release the module handle via
 *      ktest_release_mod(9F).
 *
 * ## Registering Tests
 *
 * For a test to be run it first needs to be registered with the ktest
 * facility. This is done via the ktest(9) APIs described below. The
 * test module should be a 'modlmisc' module and perform all test
 * registration/unregistration in its '_init' and '_fini' callbacks.
 * Internally, ktest tracks all registered tests via the ktest_modules
 * list.
 *
 * ktest_create_module(9F)
 * ktest_add_test(9F)
 * ktest_add_suite(9F)
 * ktest_register_module(9F)
 * ktest_unregister_module(9F)
 *
 * The creation and registration of tests is typically done in the
 * following order.
 *
 *   1. Create a new module with ktest_create_module(9F).
 *
 *   2. Add a new suite with ktest_add_suite(9F).
 *
 *   3. Add one or more tests to the suite with ktest_add_test(9F).
 *
 *   4. Go back to step (2) if more suites are needed.
 *
 *   5. Register the module with ktest_register_module(9F).
 *
 * For unregistering your test module it's a simple matter of calling
 * ktest_unregister_module(9F).
 *
 * The ktest_add_test(9F) API does provide a flags argument for
 * providing additional information about the test, see
 * ktest_test_flags_t for more information.
 */
#include <sys/stddef.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/ktest_impl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#define	KTEST_CTL_MINOR	0

dev_info_t	*ktest_dip;
kmutex_t	ktest_lock;

/*
 * The global list of registered ktest modules. A module must call
 * ktest_register_module() to register itself with the ktest framework.
 *
 * Protected by ktest_lock.
 *
 * List modules in MDB
 * -------------------
 *
 * > ktest_modules::walk list |::print ktest_module_t
 */
list_t ktest_modules;

/*
 * Determine if the name is valid. This is probably overly
 * restrictive, but it's easier to add additional characters later
 * than to remove them. We want to avoid:
 *
 * - KTEST_SEPARATOR and KTEST_GMATCH_CHARS, as it causes ambiguity.
 *
 * - Characters that make it harder to use the ktest command in an
 *   interactive shell, such as whitespace and special characters like '&'.
 */
static int
ktest_valid_name(const char *name)
{
	size_t len = strnlen(name, KTEST_MAX_NAME_LEN);

	if (len >= KTEST_MAX_NAME_LEN) {
		return (EOVERFLOW);
	}

	for (uint_t i = 0; i < len; i++) {
		char c = name[i];
		boolean_t good_char = c == '.' || c == '_' ||
		    (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9');

		if (!good_char) {
			return (EINVAL);
		}
	}

	return (0);
}

static ktest_module_t *
ktest_find_module(const char *module)
{
	ktest_module_t *km = NULL;

	VERIFY(MUTEX_HELD(&ktest_lock));

	for (km = list_head(&ktest_modules); km != NULL;
	    km = list_next(&ktest_modules, km)) {
		if (strncmp(km->km_name, module, KTEST_MAX_NAME_LEN) == 0) {
			return (km);
		}
	}

	return (NULL);
}

static ktest_suite_t *
ktest_find_suite(ktest_module_t *km, const char *suite)
{
	ktest_suite_t *ks = NULL;

	for (ks = list_head(&km->km_suites); ks != NULL;
	    ks = list_next(&km->km_suites, ks)) {
		if (strncmp(ks->ks_name, suite, KTEST_MAX_NAME_LEN) == 0) {
			return (ks);
		}
	}

	return (NULL);
}

static ktest_test_t *
ktest_find_test(ktest_suite_t *ks, const char *test)
{
	ktest_test_t *kt = NULL;

	for (kt = list_head(&ks->ks_tests); kt != NULL;
	    kt = list_next(&ks->ks_tests, kt)) {
		if (strncmp(kt->kt_name, test, KTEST_MAX_NAME_LEN) == 0) {
			return (kt);
		}
	}

	return (NULL);
}

/*
 * Return a pointer to the test that matches the fully-qualified
 * triple. Return NULL if no match is found.
 */
static ktest_test_t *
ktest_get_test(const char *module, const char *suite, const char *test)
{
	ktest_module_t *km = NULL;
	ktest_suite_t *ks = NULL;

	VERIFY(module != NULL);
	VERIFY(suite != NULL);
	VERIFY(test != NULL);
	VERIFY(MUTEX_HELD(&ktest_lock));

	if ((km = ktest_find_module(module)) == NULL) {
		return (NULL);
	}

	if ((ks = ktest_find_suite(km, suite)) == NULL) {
		return (NULL);
	}

	return (ktest_find_test(ks, test));
}

/*
 * Create a new test module object named 'name'. The test module name
 * may be the same as the module-under-test, but this isn't required.
 *
 * Zero indicates success and a handle to the module object is
 * returned via 'km_hdl'.
 *
 * See ktest_create_module(9F).
 */
int
ktest_create_module(const char *name, ktest_module_hdl_t **km_hdl)
{
	int ret = 0;
	ktest_module_t *km = NULL;

	if ((ret = ktest_valid_name(name)) != 0) {
		return (ret);
	}

	if ((km = kmem_zalloc(sizeof (*km), KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}

	list_create(&km->km_suites, sizeof (ktest_suite_t),
	    offsetof(ktest_suite_t, ks_node));
	/* The length was already checked by ktest_valid_name(). */
	(void) strlcpy(km->km_name, name, sizeof (km->km_name));
	*km_hdl = (ktest_module_hdl_t *)km;
	return (0);
}

/*
 * Create a new suite object named 'name' and add it to the module.
 *
 * Zero indicates success and a handle to the suite object is returned
 * via 'ks_hdl'.
 *
 * See ktest_add_suite(9F).
 */
int
ktest_add_suite(ktest_module_hdl_t *km_hdl, const char *name,
    ktest_suite_hdl_t **ks_hdl)
{
	int ret = 0;
	ktest_module_t *km = (ktest_module_t *)km_hdl;
	ktest_suite_t *ks = NULL;

	if ((ret = ktest_valid_name(name)) != 0) {
		return (ret);
	}

	if (ktest_find_suite(km, name) != NULL) {
		return (EEXIST);
	}

	if ((ks = kmem_zalloc(sizeof (*ks), KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}

	list_create(&ks->ks_tests, sizeof (ktest_test_t),
	    offsetof(ktest_test_t, kt_node));
	/* The length was already checked by ktest_valid_name(). */
	(void) strlcpy(ks->ks_name, name, sizeof (ks->ks_name));
	ks->ks_module = km;
	list_insert_tail(&km->km_suites, ks);
	km->km_num_suites++;
	km->km_num_tests += ks->ks_num_tests;
	*ks_hdl = (ktest_suite_hdl_t *)ks;
	return (0);
}

static int
ktest_create_test(ktest_test_t **test_out, ktest_suite_t *ks, const char *name,
    ktest_fn_t fn, ktest_test_flags_t flags)
{
	int ret = 0;
	ktest_test_t *kt = NULL;
	boolean_t requires_input = B_FALSE;

	if ((ret = ktest_valid_name(name)) != 0) {
		return (ret);
	}

	if ((kt = kmem_zalloc(sizeof (*kt), KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}

	if ((flags & KTEST_FLAG_INPUT) != 0) {
		requires_input = B_TRUE;
	}

	/* The length was already checked by ktest_valid_name(). */
	(void) strlcpy(kt->kt_name, name, sizeof (kt->kt_name));
	kt->kt_fn = fn;
	kt->kt_suite = ks;
	kt->kt_requires_input = requires_input;
	*test_out = kt;
	return (0);
}

/*
 * Add a test function to the suite specified by 'ks_hdl'. The test is
 * registered under the 'name' pseudonym and refers to the 'fn'
 * function. While the name is often the same as the function symbol,
 * this is merely a convention and not enforced. The 'flags' argument
 * may specify additional information about the function -- see the
 * ktest_test_flags_t definition.
 *
 * This function creates a new test object on the caller's behalf and
 * registers it with the specified suite. Zero indicates success.
 *
 * See ktest_add_test(9F).
 */
int
ktest_add_test(ktest_suite_hdl_t *ks_hdl, const char *name, ktest_fn_t fn,
    ktest_test_flags_t flags)
{
	ktest_suite_t *ks = (ktest_suite_t *)ks_hdl;
	ktest_test_t *test;
	int ret;

	if (ktest_find_test(ks, name) != NULL) {
		return (EEXIST);
	}

	if ((ret = ktest_create_test(&test, ks, name, fn, flags)) != 0) {
		return (ret);
	}

	list_insert_tail(&ks->ks_tests, test);
	ks->ks_num_tests++;
	return (0);
}

/*
 * Register the test module specified by 'km_hdl' with the ktest
 * facility.
 *
 * See ktest_register_module(9F).
 */
int
ktest_register_module(ktest_module_hdl_t *km_hdl)
{
	ktest_module_t *km = (ktest_module_t *)km_hdl;

	mutex_enter(&ktest_lock);

	ktest_module_t *conflict = ktest_find_module(km->km_name);
	if (conflict != NULL) {
		/*
		 * The ktest self-test module will, as part of its duties,
		 * attempt to double-register its module to confirm that it
		 * receives an EEXIST rejection.
		 *
		 * For that one specific case, the error output to the console
		 * is suppressed, since the behavior is anticipated and the
		 * operator should not be alarmed.
		 */
		const boolean_t selftest_suppress_msg =
		    conflict == km &&
		    strncmp(km->km_name, "ktest", KTEST_MAX_NAME_LEN) == 0;
		mutex_exit(&ktest_lock);

		if (!selftest_suppress_msg) {
			cmn_err(CE_NOTE, "test module already exists: %s",
			    km->km_name);
		}
		return (EEXIST);
	}

	list_insert_tail(&ktest_modules, km);
	mutex_exit(&ktest_lock);
	return (0);
}

static void
ktest_free_test(ktest_test_t *test)
{
	kmem_free(test, sizeof (*test));
}

static void
ktest_free_suite(ktest_suite_t *ks)
{
	ktest_test_t *kt = NULL;

	while ((kt = list_remove_head(&ks->ks_tests)) != NULL) {
		ktest_free_test(kt);
	}

	list_destroy(&ks->ks_tests);
	kmem_free(ks, sizeof (*ks));
}

void
ktest_free_module(ktest_module_hdl_t *km_hdl)
{
	ktest_module_t *km = (ktest_module_t *)km_hdl;
	ktest_suite_t *ks = NULL;

	while ((ks = list_remove_head(&km->km_suites)) != NULL) {
		ktest_free_suite(ks);
	}

	list_destroy(&km->km_suites);
	kmem_free(km, sizeof (*km));
}

/*
 * Unregister the test module named by 'name'. This walks all suites
 * and tests registered under this module, removing them and freeing
 * their resources.
 *
 * See ktest_unregister_module(9F).
 */
void
ktest_unregister_module(const char *name)
{
	mutex_enter(&ktest_lock);

	for (ktest_module_t *km = list_head(&ktest_modules);
	    km != NULL;
	    km = list_next(&ktest_modules, km)) {
		if (strncmp(name, km->km_name, KTEST_MAX_NAME_LEN) == 0) {
			list_remove(&ktest_modules, km);
			ktest_free_module((ktest_module_hdl_t *)km);
			break;
		}
	}

	mutex_exit(&ktest_lock);
}

static void
ktest_unregister_all()
{
	ktest_module_t *km;
	mutex_enter(&ktest_lock);

	while ((km = list_remove_head(&ktest_modules)) != NULL) {
		ktest_free_module((ktest_module_hdl_t *)km);
	}

	mutex_exit(&ktest_lock);
}

/*
 * Get a function pointer to the function with symbol 'fn_name'. This
 * function must be a symbol in the module referenced by 'hdl',
 * otherwise an error is returned. It's up to the caller to make sure
 * that the 'fn' pointer is declared correctly.
 *
 * Zero indicates success.
 *
 * See ktest_get_fn(9F).
 */
int
ktest_get_fn(ddi_modhandle_t hdl, const char *fn_name, void **fn)
{
	int err;

	if ((*fn = ddi_modsym(hdl, fn_name, &err)) == NULL) {
		return (err);
	}

	return (0);
}

/*
 * Get the input stream from the context handle. The contract for this
 * API guarantees that if it is called, then there MUST be an input
 * stream. It does this by VERIFYing that a) the test's
 * 'kt_requires_input' flag is set, and b) that the 'ktc_input' is
 * non-NULL. This means that failure to set an input stream on a test
 * which requires it will result in a kernel panic. That may seem
 * extreme, however, consider that this is meant to be discovered
 * during development, and that the ktest cmd also takes steps to
 * ensure that any test which requires input has an input stream
 * specified. The impetus for this contract is to avoid checking for
 * valid input in every test -- it allows the test to assume the input
 * is there and categorically catch any case where it is not.
 *
 * This contract does not preclude the possibility of a 0-byte stream,
 * which may be a valid test case for some tests. It only precludes a
 * non-existent stream.
 *
 * See ktest_get_input(9F).
 */
void
ktest_get_input(const ktest_ctx_hdl_t *hdl, uchar_t **input, size_t *len)
{
	ktest_ctx_t *ctx = (ktest_ctx_t *)hdl;
	VERIFY(ctx->ktc_test->kt_requires_input == B_TRUE);
	VERIFY3P(ctx->ktc_input, !=, NULL);
	*len = ctx->ktc_input_len;
	*input = ctx->ktc_input;
}

/*
 * Grab a hold on 'module' and return it in 'hdl'. Meant to be used
 * with ktest_get_fn(). Zero indicates success.
 *
 * Remember, 'ddi_modhandle_t' is a pointer, so 'hdl' is pointer to
 * pointer.
 *
 * See ktest_hold_mod(9F).
 */
int
ktest_hold_mod(const char *module, ddi_modhandle_t *hdl)
{
	int err;

	if ((*hdl = ddi_modopen(module, KRTLD_MODE_FIRST, &err)) == NULL) {
		return (err);
	}

	return (0);
}

/*
 * The opposite of ktest_hold_mod().
 *
 * See ktest_release_mod(9F).
 */
void
ktest_release_mod(ddi_modhandle_t hdl)
{
	(void) ddi_modclose(hdl);
}

/*
 * Check if the result is already set. Setting the result more than
 * once is a bug in the test. This check catches the bug and produces
 * an error result with a message indicating the line number of the
 * original result which was overwritten. It replaces 'ktc_res_line'
 * with the line number of the overwriting result.
 *
 * Return true when an existing result was found.
 */
static boolean_t
ktest_result_check(ktest_ctx_t *ctx, int line)
{
	if (ctx->ktc_res->kr_type != KTEST_RESULT_NONE) {
		char *msg = ctx->ktc_res->kr_msg;
		int first_line = ctx->ktc_res->kr_line;

		ctx->ktc_res->kr_type = KTEST_RESULT_ERROR;
		ctx->ktc_res->kr_line = line;

		/* We know the string is within max length. */
		(void) snprintf(msg, KTEST_MAX_LOG_LEN, "multiple results: "
		    "prev result at line %d", first_line);

		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Set result if and only if one has not already been set. Return true
 * if the result was set. Return false if it was already set.
 */
static boolean_t
ktest_set_result(ktest_ctx_hdl_t *hdl, ktest_result_type_t rt, int line)
{
	ktest_ctx_t *ctx = (ktest_ctx_t *)hdl;

	/* Overwriting a previous result is not allowed. */
	if (ktest_result_check(ctx, line)) {
		return (B_FALSE);
	}

	ctx->ktc_res->kr_type = rt;
	ctx->ktc_res->kr_line = line;
	return (B_TRUE);
}

static void
ktest_set_msg(ktest_ctx_hdl_t *hdl, const char *format, va_list args)
{
	ktest_ctx_t *ctx = (ktest_ctx_t *)hdl;
	char *msg = ctx->ktc_res->kr_msg;
	size_t written = 0;

	written = vsnprintf(msg, KTEST_MAX_LOG_LEN, format, args);

	/* Subtract one to account for the implicit NULL byte. */
	if (written > (KTEST_MAX_LOG_LEN - 1)) {
		const ktest_test_t *test = ctx->ktc_test;
		ktest_suite_t *suite = test->kt_suite;
		ktest_module_t *mod = suite->ks_module;

		cmn_err(CE_NOTE, "result message truncated: %s:%s:%s [%d]",
		    mod->km_name, suite->ks_name, test->kt_name,
		    ctx->ktc_res->kr_line);
	}
}

void
ktest_result_skip(ktest_ctx_hdl_t *hdl, int line, const char *format, ...)
{
	if (ktest_set_result(hdl, KTEST_RESULT_SKIP, line)) {
		va_list adx;

		va_start(adx, format);
		ktest_set_msg(hdl, format, adx);
		va_end(adx);
	}
}

void
ktest_result_fail(ktest_ctx_hdl_t *hdl, int line, const char *format, ...)
{
	if (ktest_set_result(hdl, KTEST_RESULT_FAIL, line)) {
		va_list adx;

		va_start(adx, format);
		ktest_set_msg(hdl, format, adx);
		va_end(adx);
	}
}

void
ktest_result_error(ktest_ctx_hdl_t *hdl, int line, const char *format, ...)
{
	if (ktest_set_result(hdl, KTEST_RESULT_ERROR, line)) {
		va_list adx;

		va_start(adx, format);
		ktest_set_msg(hdl, format, adx);
		va_end(adx);
	}
}

void
ktest_result_pass(ktest_ctx_hdl_t *hdl, int line)
{
	(void) ktest_set_result(hdl, KTEST_RESULT_PASS, line);
}

/*
 * Clear the prepend message, undoing any message set by ktest_msg_prepend().
 *
 * See ktest_msg_clear(9F).
 */
void
ktest_msg_clear(ktest_ctx_hdl_t *hdl)
{
	ktest_ctx_t *ctx = (ktest_ctx_t *)hdl;
	ctx->ktc_res->kr_msg_prepend[0] = '\0';
}

/*
 * Prepend formatted text to the result message. This is useful in
 * cases where the KT_ASSERT macro's generated message doesn't convey
 * enough context to determine the precise cause of the failure. By
 * prepending the formatted text you can add additional context while
 * still using the KT_ASSERT macros (and not having to reimplement
 * them yourself). This overwrites any existing prepend text.
 *
 * See ktest_msg_prepend(9F).
 */
void
ktest_msg_prepend(ktest_ctx_hdl_t *hdl, const char *format, ...)
{
	ktest_ctx_t *ctx = (ktest_ctx_t *)hdl;
	char *msg = ctx->ktc_res->kr_msg_prepend;
	size_t written;
	va_list adx;

	va_start(adx, format);
	written = vsnprintf(msg, KTEST_MAX_LOG_LEN, format, adx);
	/* Subtract one to account for the implicit NULL byte. */
	if (written > (KTEST_MAX_LOG_LEN - 1)) {
		const ktest_test_t *test = ctx->ktc_test;
		ktest_suite_t *suite = test->kt_suite;
		ktest_module_t *mod = suite->ks_module;

		cmn_err(CE_NOTE, "prepend message truncated: %s:%s:%s",
		    mod->km_name, suite->ks_name, test->kt_name);
	}
	va_end(adx);
}

/*
 * Each `{:}` represents an nvpair, each `[,]` represents an nvlist.
 *
 * Test nvlist
 * -----------
 *
 * [{"name":"<test_name>"},
 *  {"input_required":boolean_t}]
 *
 * Tests nvlist
 * ------------
 *
 * [{"test1":<test1_nvlist>},
 *  {"test2":<test2_nvlist>"},
 *  ...]
 *
 * Suite nvlist
 * ------------
 *
 * [{"name":"<ks->ks_name>"},
 *  {"tests":<tests_nvlist>}]
 *
 * Suites nvlist
 * -------------
 *
 * [{"suite1":<suite1_nvlist>},
 *  {"suite2":<suite2_nvlist>},
 *  ...]
 *
 * Module nvlist
 * -------------
 *
 * [{"name":"<km->km_name>"},
 *  {"suites":<suites_nvlist>}]
 *
 * Modules nvlist
 * --------------
 *
 * [{"ser_fmt_version":1},
 *  {"module1":<module1_nvlist>},
 *  {"module2":<module2_nvlist>},
 *  ...]
 *
 */
int
ktest_list_tests(ktest_list_op_t *klo, int mode)
{
	nvlist_t *modules = fnvlist_alloc();
	char *buf = NULL;
	size_t len = 0;
	int ret = 0;

	/*
	 * The first thing we add is a uint64_t ser_fmt_version field.
	 * This field allows any consumer of this nvlist (namely the
	 * ktest cmd) to know which serialization format it is in.
	 * Specifically, the format version tells the consumer which
	 * fields to expect and how they are laid out. Given that the
	 * ktest kernel facility and its user command are delivered in
	 * gate, this should never be needed. However, including a
	 * versioned format now keeps the future flexible, and costs
	 * us little.
	 */
	fnvlist_add_uint64(modules, "ser_fmt_version", KTEST_SER_FMT_VSN);
	mutex_enter(&ktest_lock);

	for (ktest_module_t *km = list_head(&ktest_modules);
	    km != NULL;
	    km = list_next(&ktest_modules, km)) {
		nvlist_t *module = fnvlist_alloc();
		nvlist_t *suites = fnvlist_alloc();

		for (ktest_suite_t *ks = list_head(&km->km_suites);
		    ks != NULL;
		    ks = list_next(&km->km_suites, ks)) {
			nvlist_t *suite = fnvlist_alloc();
			nvlist_t *tests = fnvlist_alloc();

			for (ktest_test_t *kt = list_head(&ks->ks_tests);
			    kt != NULL;
			    kt = list_next(&ks->ks_tests, kt)) {
				nvlist_t *test = fnvlist_alloc();

				fnvlist_add_string(test, KTEST_NAME_KEY,
				    kt->kt_name);
				fnvlist_add_boolean_value(test,
				    KTEST_TEST_INPUT_KEY,
				    kt->kt_requires_input);
				fnvlist_add_nvlist(tests, kt->kt_name, test);
				nvlist_free(test);
			}

			if (nvlist_empty(tests)) {
				nvlist_free(tests);
				nvlist_free(suite);
				continue;
			}

			fnvlist_add_string(suite, KTEST_NAME_KEY, ks->ks_name);
			fnvlist_add_nvlist(suite, KTEST_SUITE_TESTS_KEY, tests);
			fnvlist_add_nvlist(suites, ks->ks_name, suite);
			nvlist_free(tests);
			nvlist_free(suite);
		}

		if (nvlist_empty(suites)) {
			nvlist_free(suites);
			nvlist_free(module);
			continue;
		}

		fnvlist_add_string(module, KTEST_NAME_KEY, km->km_name);
		fnvlist_add_nvlist(module, KTEST_MODULE_SUITES_KEY, suites);
		fnvlist_add_nvlist(modules, km->km_name, module);
		nvlist_free(suites);
		nvlist_free(module);
	}

	mutex_exit(&ktest_lock);
	buf = fnvlist_pack(modules, &len);

	/*
	 * The userspace response buffer is not large enough. Fill in
	 * the amount needed and return ENOBUFS so that the command
	 * may retry.
	 */
	if (klo->klo_resp_len < len) {
		klo->klo_resp_len = len;
		nvlist_free(modules);
		ret = ENOBUFS;
		goto out;
	}

	klo->klo_resp_len = len;

	if (ddi_copyout(buf, klo->klo_resp, len, mode) != 0) {
		ret = EFAULT;
		goto out;
	}

out:
	nvlist_free(modules);
	kmem_free(buf, len);
	return (ret);
}

static void
ktest_run_test(const ktest_test_t *kt, uchar_t *input, uint64_t input_len,
    ktest_result_t *res)
{
	ktest_ctx_t ctx;

	bzero(&ctx, sizeof (ctx));
	res->kr_type = KTEST_RESULT_NONE;
	ctx.ktc_test = kt;
	ctx.ktc_res = res;
	ctx.ktc_input = input;
	ctx.ktc_input_len = input_len;
	kt->kt_fn((ktest_ctx_hdl_t *)&ctx);
}

static int
ktest_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = ktest_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)0;
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
ktest_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(dip, "ktest", S_IFCHR, KTEST_CTL_MINOR,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	ktest_dip = dip;
	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

static int
ktest_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	ddi_remove_minor_node(dip, NULL);
	ktest_dip = NULL;
	return (DDI_SUCCESS);
}

static int
ktest_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	/* Make sure attach(9E) has completed. */
	if (ktest_dip == NULL) {
		return (ENXIO);
	}

	if (getminor(*devp) != KTEST_CTL_MINOR) {
		return (ENXIO);
	}

	if (flag & FWRITE) {
		return (EACCES);
	}

	if (flag & FEXCL) {
		return (ENOTSUP);
	}

	/*
	 * Access to the ktest facility requires the utmost respect:
	 * test modules have full access to the kernel address space
	 * and the user executing ktest can pipe in any arbitrary
	 * stream of bytes to any test which takes an input stream.
	 * Given this liability, and the fact the test facility should
	 * mostly be used for development quality assurance or
	 * production pre-flight checklists or healthchecks, it makes
	 * sense to restrict the loading, listing, and execution of
	 * tests to those with the highest of privilege: the root
	 * role/user in the Global Zone.
	 */
	if (drv_priv(credp) != 0 || crgetzoneid(credp) != GLOBAL_ZONEID) {
		return (EPERM);
	}

	return (0);
}

static int
ktest_close(dev_t dev, int flags, int otype, cred_t *credp)
{
	return (0);
}

static int
ktest_ioctl_run_test(intptr_t arg, int mode)
{
	int ret = 0;
	ktest_run_op_t kro;
	uchar_t *input_bytes = NULL;
	ktest_test_t *kt = NULL;

	bzero(&kro, sizeof (kro));
	if (ddi_copyin((void *)arg, &kro, sizeof (kro), mode) != 0) {
		return (EFAULT);
	}

	if (kro.kro_input_len > KTEST_IOCTL_MAX_LEN) {
		return (EINVAL);
	}

	/*
	 * If there is input, copy it into KAS.
	 */
	if (kro.kro_input_len > 0) {
		input_bytes = kmem_zalloc(kro.kro_input_len, KM_SLEEP);
		ret = ddi_copyin((void *)kro.kro_input_bytes, input_bytes,
		    kro.kro_input_len, mode);

		if (ret != 0) {
			ret = EFAULT;
			goto done;
		}
	}

	mutex_enter(&ktest_lock);
	kt = ktest_get_test(kro.kro_module, kro.kro_suite, kro.kro_test);

	/*
	 * We failed to find a matching test. The ktest command should
	 * always send down a valid fully-qualified triple; but it's
	 * good hygiene to check for this case.
	 */
	if (kt == NULL) {
		ret = ENOENT;
		goto done;
	}

	/*
	 * The test requires input but none was provided. The ktest
	 * command should not send down such a request; but it's good
	 * hygiene to check for it.
	 */
	if (kt->kt_requires_input && kro.kro_input_len == 0) {
		ret = EINVAL;
		goto done;
	}

	ktest_run_test(kt, input_bytes, kro.kro_input_len, &kro.kro_result);

done:
	mutex_exit(&ktest_lock);
	kmem_free(input_bytes, kro.kro_input_len);

	if (ret == 0 &&
	    ddi_copyout(&kro, (void *)arg, sizeof (kro), mode) != 0) {
		ret = EFAULT;
	}

	return (ret);
}

static int
ktest_ioctl_list_tests(intptr_t arg, int mode)
{
	int ret = 0;
	ktest_list_op_t klo;

	bzero(&klo, sizeof (klo));
	if (ddi_copyin((void *)arg, &klo, sizeof (klo), mode) != 0) {
		return (EFAULT);
	}

	if ((ret = ktest_list_tests(&klo, mode)) == 0) {
		if (ddi_copyout(&klo, (void *)arg, sizeof (klo), mode) != 0) {
			return (EFAULT);
		}
	}

	return (ret);
}

static int
ktest_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int ret = 0;

	/*
	 * We make two assumptions:
	 *
	 *  1. That only the ktest command interacts with the ktest driver.
	 *
	 *  2. The the ktest command is 64-bit.
	 */
	if (ddi_model_convert_from(mode) != DDI_MODEL_NONE) {
		return (ENOSYS);
	}

	switch (cmd) {
	case KTEST_IOCTL_RUN_TEST:
		ret = ktest_ioctl_run_test(arg, mode);
		break;

	case KTEST_IOCTL_LIST_TESTS:
		ret = ktest_ioctl_list_tests(arg, mode);
		break;

	default:
		ret = EINVAL;
		break;
	}

	return (ret);
}

static struct cb_ops ktest_cb_ops = {
	.cb_open = ktest_open,
	.cb_close = ktest_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = ktest_ioctl,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_flag = D_MP | D_64BIT,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev,
	.cb_str = NULL
};

static struct dev_ops ktest_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = ktest_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = ktest_attach,
	.devo_detach = ktest_detach,
	.devo_reset = nodev,
	.devo_power = NULL,
	.devo_quiesce = ddi_quiesce_not_supported,
	.devo_cb_ops = &ktest_cb_ops,
	.devo_bus_ops = NULL
};

static struct modldrv ktest_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Kernel Test Driver v1",
	.drv_dev_ops = &ktest_dev_ops
};

static struct modlinkage ktest_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &ktest_modldrv, NULL }
};

static void
ktest_fini()
{
	ktest_unregister_all();
	list_destroy(&ktest_modules);
	mutex_destroy(&ktest_lock);
}

/*
 * This is a pseudo device driver with a single instance, therefore
 * all state is allocated/freed during init/fini. We delay the
 * creation of the taskq until attach, since tests cannot be executed
 * until the driver is attached.
 */
int
_init(void)
{
	int ret;

	mutex_init(&ktest_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&ktest_modules, sizeof (ktest_module_t),
	    offsetof(ktest_module_t, km_node));
	ret = mod_install(&ktest_modlinkage);

	if (ret != DDI_SUCCESS) {
		ktest_fini();
	}

	return (ret);
}

int
_fini(void)
{
	int ret = mod_remove(&ktest_modlinkage);

	if (ret == DDI_SUCCESS) {
		ktest_fini();
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ktest_modlinkage, modinfop));
}
