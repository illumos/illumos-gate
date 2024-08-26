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
 * Copyright 2023 Oxide Computer Company
 * Copyright 2024 Ryan Zezeski
 */
#include <sys/debug.h>
#include <sys/ktest.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/list.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <stdarg.h>
#include <strings.h>
#include <libgen.h>
#include <libnvpair.h>
#include <regex.h>
#include <libcmdutils.h>
#include <ofmt.h>
#include <zone.h>

#define	EXIT_USAGE		2
#define	KTEST_CMD_SZ		24
#define	KTEST_DEV_PATH		"/dev/ktest"

static const char *ktest_prog;

/* Print a horizontal rule. */
static void
ktest_print_hr(uint8_t cols)
{
	for (uint8_t i = 0; i < cols; i++) {
		(void) putchar('-');
	}

	(void) putchar('\n');
}

/* An adapter to use errx with libofmt. */
void
ktest_ofmt_errx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verrx(EXIT_FAILURE, fmt, ap);
}

typedef enum ktest_fmt_fields {
	KTEST_FMT_RESULT,
	KTEST_FMT_MODULE,
	KTEST_FMT_SUITE,
	KTEST_FMT_TEST,
	KTEST_FMT_INPUT_FLAG,
	KTEST_FMT_INPUT_PATH,
	KTEST_FMT_LINE,
	KTEST_FMT_REASON,
} ktest_fmt_fields_t;

typedef struct ktest_list_ofmt {
	char *klof_module;
	char *klof_suite;
	char *klof_test;
	boolean_t klof_input;
} ktest_list_ofmt_t;

static boolean_t
ktest_list_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t len)
{
	ktest_list_ofmt_t *klof = ofarg->ofmt_cbarg;

	switch (ofarg->ofmt_id) {
	case KTEST_FMT_MODULE:
		if (snprintf(buf, len, "%s", klof->klof_module) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_SUITE:
		if (snprintf(buf, len, "%s", klof->klof_suite) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_TEST:
		if (snprintf(buf, len, "%s", klof->klof_test) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_INPUT_FLAG: {
		const char *flag = klof->klof_input ? "Y" : "N";

		if (snprintf(buf, len, "%s", flag) >= len) {
			return (B_FALSE);
		}
	}
	}

	return (B_TRUE);
}

#define	KTEST_LIST_CMD_DEF_FIELDS	"module,suite,test,input"

static const ofmt_field_t ktest_list_ofmt[] = {
	{ "MODULE", 12, KTEST_FMT_MODULE, ktest_list_ofmt_cb },
	{ "SUITE", 16, KTEST_FMT_SUITE, ktest_list_ofmt_cb },
	{ "TEST", 45, KTEST_FMT_TEST, ktest_list_ofmt_cb },
	{ "INPUT", 7, KTEST_FMT_INPUT_FLAG, ktest_list_ofmt_cb },
	{ NULL, 0, 0, NULL },
};

static const char *
ktest_result_str(ktest_result_t *result)
{
	switch (result->kr_type) {
	case KTEST_RESULT_NONE:
		return ("NONE");
	case KTEST_RESULT_PASS:
		return ("PASS");
	case KTEST_RESULT_FAIL:
		return ("FAIL");
	case KTEST_RESULT_SKIP:
		return ("SKIP");
	case KTEST_RESULT_ERROR:
		return ("ERROR");
	}

	/* Make the compiler happy. */
	return ("NONE");
}

static boolean_t
ktest_run_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t len)
{
	ktest_run_op_t *op = ofarg->ofmt_cbarg;
	ktest_result_t *res = &op->kro_result;

	switch (ofarg->ofmt_id) {
	case KTEST_FMT_RESULT:
		if (snprintf(buf, len, "%s", ktest_result_str(res)) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_MODULE:
		if (snprintf(buf, len, "%s", op->kro_module) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_SUITE:
		if (snprintf(buf, len, "%s", op->kro_suite) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_TEST:
		if (snprintf(buf, len, "%s", op->kro_test) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_INPUT_PATH: {
		if (snprintf(buf, len, "%s", op->kro_input_path) >= len) {
			return (B_FALSE);
		}
		break;
	}

	case KTEST_FMT_LINE:
		if (snprintf(buf, len, "%d", op->kro_result.kr_line) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_REASON: {
		if (snprintf(buf, len, "%s%s", res->kr_msg_prepend,
		    res->kr_msg) >= len) {
			return (B_FALSE);
		}
		break;
	}
	}

	return (B_TRUE);
}

/*
 * The 'run' and 'run-file' commands share the same fields.
 */
#define	KTEST_RUN_CMD_DEF_FIELDS	"result,line,module,suite,test"

/*
 * The input column for the run command is for displaying the path to
 * the input file, as opposed to the list command which indicates if
 * the test requires input or not.
 */
static const ofmt_field_t ktest_run_ofmt[] = {
	{ "RESULT", 7, KTEST_FMT_RESULT, ktest_run_ofmt_cb },
	{ "MODULE", 12, KTEST_FMT_MODULE, ktest_run_ofmt_cb },
	{ "SUITE", 16, KTEST_FMT_SUITE, ktest_run_ofmt_cb },
	{ "TEST", 45, KTEST_FMT_TEST, ktest_run_ofmt_cb },
	{ "INPUT", 48, KTEST_FMT_INPUT_PATH, ktest_run_ofmt_cb },
	{ "LINE", 6, KTEST_FMT_LINE, ktest_run_ofmt_cb },
	{ "REASON", 256, KTEST_FMT_REASON, ktest_run_ofmt_cb },
	{ NULL, 0, 0, NULL },
};

typedef enum ktest_stat_type {
	KTEST_STAT_MOD,
	KTEST_STAT_SUITE,
} ktest_stat_type_t;

typedef struct ktest_stats {
	list_node_t		ks_node;
	ktest_stat_type_t	ks_type;
	char			*ks_name;
	uint32_t		ks_total;
	uint32_t		ks_pass;
	uint32_t		ks_fail;
	uint32_t		ks_err;
	uint32_t		ks_skip;
	uint32_t		ks_none;
} ktest_stats_t;

static ktest_stats_t *
ktest_stats_new(ktest_stat_type_t type, const char *name)
{
	ktest_stats_t *stats;

	if ((stats = malloc(sizeof (ktest_stats_t))) == NULL) {
		err(EXIT_FAILURE, "failed to allocate stats structure");
	}

	stats->ks_type = type;
	stats->ks_name = strndup(name, KTEST_MAX_NAME_LEN);

	if (stats->ks_name == NULL) {
		err(EXIT_FAILURE, "failed to allocate stats name");
	}

	stats->ks_total = 0;
	stats->ks_pass = 0;
	stats->ks_fail = 0;
	stats->ks_err = 0;
	stats->ks_skip = 0;
	stats->ks_none = 0;
	return (stats);
}

static void
ktest_record_stat(ktest_stats_t *mod, ktest_stats_t *suite,
    const ktest_result_t *res)
{
	mod->ks_total++;
	suite->ks_total++;

	switch (res->kr_type) {
	case KTEST_RESULT_NONE:
		mod->ks_none++;
		suite->ks_none++;
		break;

	case KTEST_RESULT_PASS:
		mod->ks_pass++;
		suite->ks_pass++;
		break;

	case KTEST_RESULT_FAIL:
		mod->ks_fail++;
		suite->ks_fail++;
		break;

	case KTEST_RESULT_SKIP:
		mod->ks_skip++;
		suite->ks_skip++;
		break;

	case KTEST_RESULT_ERROR:
		mod->ks_err++;
		suite->ks_err++;
		break;
	}
}

typedef enum ktest_fmt_stats {
	KTEST_FMT_STATS_MS,
	KTEST_FMT_STATS_TOTAL,
	KTEST_FMT_STATS_PASS,
	KTEST_FMT_STATS_FAIL,
	KTEST_FMT_STATS_ERR,
	KTEST_FMT_STATS_SKIP,
	KTEST_FMT_STATS_NONE,
} ktest_fmt_stats_t;

static boolean_t
ktest_stats_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t len)
{
	ktest_stats_t *stats = ofarg->ofmt_cbarg;

	switch (ofarg->ofmt_id) {
	case KTEST_FMT_STATS_MS: {
		char *pre = (stats->ks_type == KTEST_STAT_MOD) ? "" : "  ";

		if (snprintf(buf, len, "%s%s", pre, stats->ks_name) >= len) {
			return (B_FALSE);
		}
		break;
	}

	case KTEST_FMT_STATS_TOTAL:
		if (snprintf(buf, len, "%" PRIu32, stats->ks_total) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_STATS_PASS:
		if (snprintf(buf, len, "%" PRIu32, stats->ks_pass) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_STATS_FAIL:
		if (snprintf(buf, len, "%" PRIu32, stats->ks_fail) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_STATS_ERR:
		if (snprintf(buf, len, "%" PRIu32, stats->ks_err) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_STATS_SKIP:
		if (snprintf(buf, len, "%" PRIu32, stats->ks_skip) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_STATS_NONE:
		if (snprintf(buf, len, "%" PRIu32, stats->ks_none) >= len) {
			return (B_FALSE);
		}
		break;
	}

	return (B_TRUE);
}

#define	KTEST_STATS_FIELDS	"module/suite,total,pass,fail,err,skip,none"

static const ofmt_field_t ktest_stats_ofmt[] = {
	{ "MODULE/SUITE", 40, KTEST_FMT_STATS_MS, ktest_stats_ofmt_cb },
	{ "TOTAL", 6, KTEST_FMT_STATS_TOTAL, ktest_stats_ofmt_cb },
	{ "PASS", 6, KTEST_FMT_STATS_PASS, ktest_stats_ofmt_cb },
	{ "FAIL", 6, KTEST_FMT_STATS_FAIL, ktest_stats_ofmt_cb },
	{ "ERR", 6, KTEST_FMT_STATS_ERR, ktest_stats_ofmt_cb },
	{ "SKIP", 6, KTEST_FMT_STATS_SKIP, ktest_stats_ofmt_cb },
	{ "NONE", 6, KTEST_FMT_STATS_NONE, ktest_stats_ofmt_cb },
};

static void
ktest_usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr,
	    "usage: %s <subcommand> [<opts>] [<args>]\n\n"
	    "\tlist [-H] [[-p] -o field,...] [<triple> ...]: "
	    "list registered tests\n"
	    "\trun [-H] [[-p] -o field,...] [-i <file>] <triple> ...: "
	    "run specified tests\n"
	    "\trun-file [-H] [[-p] -o field,...] [<runfile>]: "
	    "run tests specified in runfile\n",
	    ktest_prog);
}

/*
 * A user-specified test triple. The input path is set to the empty
 * string if no input is provided. The line number provides useful
 * error reporting when an error is encountered in the run file.
 */
typedef struct ktest_triple {
	list_node_t	ktr_node;
	char		ktr_module[KTEST_MAX_NAME_LEN];
	char		ktr_suite[KTEST_MAX_NAME_LEN];
	char		ktr_test[KTEST_MAX_NAME_LEN];
	char		ktr_input_path[MAXPATHLEN];
	uint32_t	ktr_lineno;
} ktest_triple_t;

/* The default triple matches all tests. */
static ktest_triple_t *ktest_def_triple;

/*
 * A test description obtained from iterating the list tests nvlist.
 */
typedef struct ktest_test_desc {
	char		*ktd_module;
	char		*ktd_suite;
	char		*ktd_test;
	boolean_t	ktd_requires_input;
} ktest_test_desc_t;

static void
ktest_test_desc_init(ktest_test_desc_t *desc)
{
	desc->ktd_module = NULL;
	desc->ktd_suite = NULL;
	desc->ktd_test = NULL;
	desc->ktd_requires_input = B_FALSE;
}

static void
ktest_free_triples(list_t *triples)
{
	ktest_triple_t *t = NULL;

	while ((t = list_remove_head(triples)) != NULL) {
		free(t);
	}
}

/*
 * Does the test descriptor match this triple? The descriptor will
 * always have module name present, but the suite and test names may
 * or may not be present.
 */
static boolean_t
ktest_match_triple(const ktest_test_desc_t *desc, const ktest_triple_t *triple)
{
	/* Must at least specify the module. */
	VERIFY(desc->ktd_module != NULL);

	if (desc->ktd_suite != NULL && desc->ktd_test != NULL) {
		return (gmatch(desc->ktd_module, triple->ktr_module) != 0 &&
		    gmatch(desc->ktd_suite, triple->ktr_suite) != 0 &&
		    gmatch(desc->ktd_test, triple->ktr_test) != 0);
	} else if (desc->ktd_suite != NULL) {
		return (gmatch(desc->ktd_module, triple->ktr_module) != 0 &&
		    gmatch(desc->ktd_suite, triple->ktr_suite) != 0);
	}

	return (gmatch(desc->ktd_module, triple->ktr_module) != 0);
}

/*
 * Does the test descriptor match any of the triples?
 */
static boolean_t
ktest_match_any(const ktest_test_desc_t *desc, list_t *triples)
{
	for (ktest_triple_t *triple = list_head(triples); triple != NULL;
	    triple = list_next(triples, triple)) {
		if (ktest_match_triple(desc, triple)) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

typedef struct ktest_iter {
	/*
	 * The list of all modules and current module the iterator is on.
	 */
	nvlist_t	*ki_modules;
	nvpair_t	*ki_module;

	/*
	 * The list of all suites in the current module and the
	 * current suite the iterator is on.
	 */
	nvlist_t	*ki_suites;
	nvpair_t	*ki_suite;

	/*
	 * The list of all tests in the current suite and the current
	 * test the iterator is on.
	 */
	nvlist_t	*ki_tests;
	nvpair_t	*ki_test;

	ktest_test_desc_t	ki_desc;

	/*
	 * A list of ktest_triple_t used to filter the tests returned
	 * by the iterator.
	 */
	list_t		*ki_triples;
} ktest_iter_t;

static char *
ktest_module_name(nvpair_t *module)
{
	nvlist_t *desc = fnvpair_value_nvlist(module);
	return (fnvlist_lookup_string(desc, KTEST_NAME_KEY));
}

static nvlist_t *
ktest_module_suites(nvpair_t *module)
{
	nvlist_t *desc = fnvpair_value_nvlist(module);
	return (fnvlist_lookup_nvlist(desc, KTEST_MODULE_SUITES_KEY));
}

static char *
ktest_suite_name(nvpair_t *suite)
{
	nvlist_t *desc = fnvpair_value_nvlist(suite);
	return (fnvlist_lookup_string(desc, KTEST_NAME_KEY));
}

static nvlist_t *
ktest_suite_tests(nvpair_t *suite)
{
	nvlist_t *desc = fnvpair_value_nvlist(suite);
	return (fnvlist_lookup_nvlist(desc, KTEST_SUITE_TESTS_KEY));
}

static char *
ktest_test_name(nvpair_t *test)
{
	nvlist_t *desc = fnvpair_value_nvlist(test);
	return (fnvlist_lookup_string(desc, KTEST_NAME_KEY));
}

static boolean_t
ktest_test_requires_input(nvpair_t *test)
{
	nvlist_t *desc = fnvpair_value_nvlist(test);
	return (fnvlist_lookup_boolean_value(desc, KTEST_TEST_INPUT_KEY));
}

static ktest_iter_t *
ktest_iter(nvlist_t *tests, list_t *triples)
{
	ktest_iter_t *iter = malloc(sizeof (ktest_iter_t));

	if (iter == NULL) {
		err(EXIT_FAILURE, "failed to allocate test iterator");
	}

	iter->ki_modules = tests;
	iter->ki_module = nvlist_next_nvpair(tests, NULL);

	iter->ki_suites = NULL;
	iter->ki_suite = NULL;

	iter->ki_tests = NULL;
	iter->ki_test = NULL;

	ktest_test_desc_init(&iter->ki_desc);

	iter->ki_triples = triples;
	return (iter);
}

#define	KT_NEXT_TEST(iter)						\
	(nvlist_next_nvpair((iter)->ki_tests, (iter)->ki_test))

static boolean_t
ktest_iter_tests(ktest_iter_t *iter, ktest_test_desc_t *desc)
{
	if (iter->ki_test == NULL) {
		iter->ki_test = KT_NEXT_TEST(iter);
	}

	for (; iter->ki_test != NULL; iter->ki_test = KT_NEXT_TEST(iter)) {
		iter->ki_desc.ktd_test = ktest_test_name(iter->ki_test);
		iter->ki_desc.ktd_requires_input =
		    ktest_test_requires_input(iter->ki_test);

		/*
		 * We found a match and are returning control to the
		 * ktest_iter_next() caller; but we first need to copy
		 * the matching descriptor and move the iterator to
		 * the next test in preparation for the next call to
		 * ktest_iter_next().
		 */
		if (ktest_match_any(&iter->ki_desc, iter->ki_triples)) {
			*desc = iter->ki_desc;
			iter->ki_test = KT_NEXT_TEST(iter);
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

#define	KT_NEXT_SUITE(iter)						\
	(nvlist_next_nvpair((iter)->ki_suites, (iter)->ki_suite))

static boolean_t
ktest_iter_suites(ktest_iter_t *iter, ktest_test_desc_t *desc)
{
	if (iter->ki_suite == NULL) {
		iter->ki_suite = KT_NEXT_SUITE(iter);
	}

	for (; iter->ki_suite != NULL; iter->ki_suite = KT_NEXT_SUITE(iter)) {
		iter->ki_desc.ktd_suite = ktest_suite_name(iter->ki_suite);

		if (!ktest_match_any(&iter->ki_desc, iter->ki_triples)) {
			continue;
		}

		iter->ki_tests = ktest_suite_tests(iter->ki_suite);

		if (ktest_iter_tests(iter, desc)) {
			/*
			 * We've iterated all tests in the suite, move
			 * to the next one.
			 */
			if (iter->ki_test == NULL) {
				iter->ki_suite = KT_NEXT_SUITE(iter);
			}

			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

#define	KT_NEXT_MOD(iter)						\
	(nvlist_next_nvpair((iter)->ki_modules, (iter)->ki_module))

static boolean_t
ktest_iter_next(ktest_iter_t *iter, ktest_test_desc_t *desc)
{
	for (; iter->ki_module != NULL; iter->ki_module = KT_NEXT_MOD(iter)) {
		ktest_test_desc_init(&iter->ki_desc);
		iter->ki_desc.ktd_module = ktest_module_name(iter->ki_module);

		if (!ktest_match_any(&iter->ki_desc, iter->ki_triples)) {
			continue;
		}

		iter->ki_suites = ktest_module_suites(iter->ki_module);

		if (ktest_iter_suites(iter, desc)) {
			/*
			 * We've iterated all suites in the module,
			 * move to the next one.
			 */
			if (iter->ki_suite == NULL) {
				iter->ki_module = KT_NEXT_MOD(iter);
			}

			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * Get a list of tests from the in-kernel ktest registry.
 */
static nvlist_t *
ktest_list_tests(int dev)
{
	int ret = 0;
	nvlist_t *tests = NULL;
	boolean_t retry = B_FALSE;
	ktest_list_op_t klo;
	size_t resp_len = 1 * 1024 * 1024;
	char *resp = NULL;
	uint64_t vsn = 0;

	if ((resp = malloc(resp_len)) == NULL) {
		err(EXIT_FAILURE, "failed to allocate response buffer");
	}

	bzero(resp, resp_len);
	klo.klo_resp = resp;
	klo.klo_resp_len = resp_len;

retry:
	ret = ioctl(dev, KTEST_IOCTL_LIST_TESTS, &klo);

	if (ret == -1 && errno == ENOBUFS && !retry) {
		free(resp);
		resp_len = klo.klo_resp_len;

		if ((resp = malloc(resp_len)) == NULL) {
			err(EXIT_FAILURE, "failed to allocate response buffer");
		}

		bzero(resp, resp_len);
		retry = B_TRUE;
		goto retry;
	} else if (ret == -1) {
		err(EXIT_FAILURE, "list ioctl failed");
	}

	resp_len = klo.klo_resp_len;

	if ((ret = nvlist_unpack(resp, resp_len, &tests, 0)) != 0) {
		errx(EXIT_FAILURE, "failed to unpack list response: %s",
		    strerror(ret));
	}

	free(resp);

	/*
	 * Verify that the response is marked with the expected
	 * serialization format. Remove the nvpair so that only the
	 * modules remain.
	 */
	if (nvlist_lookup_uint64(tests, KTEST_SER_FMT_KEY, &vsn) != 0) {
		errx(EXIT_FAILURE, "invalid list response, missing %s key\n",
		    KTEST_SER_FMT_KEY);
	}

	if (vsn != KTEST_SER_FMT_VSN) {
		errx(EXIT_FAILURE,
		    "invalid serialization format version: %" PRIu64 "\n", vsn);
	}

	fnvlist_remove(tests, KTEST_SER_FMT_KEY);
	return (tests);
}

static void
ktest_print_tests(nvlist_t *tests, list_t *triples, ofmt_handle_t ofmt)
{
	ktest_iter_t *iter = ktest_iter(tests, triples);
	ktest_test_desc_t desc;

	while (ktest_iter_next(iter, &desc)) {
		ktest_list_ofmt_t klof;

		klof.klof_module = desc.ktd_module;
		klof.klof_suite = desc.ktd_suite;
		klof.klof_test = desc.ktd_test;
		klof.klof_input = desc.ktd_requires_input;
		ofmt_print(ofmt, &klof);
	}

	free(iter);
}

static void
ktest_print_stats(list_t *stats)
{
	ktest_stats_t *stat;
	ofmt_handle_t stats_ofmt;
	ofmt_status_t oferr;
	boolean_t first = B_FALSE;

	oferr = ofmt_open(KTEST_STATS_FIELDS, ktest_stats_ofmt, 0, 0,
	    &stats_ofmt);
	ofmt_check(oferr, B_FALSE, stats_ofmt, ktest_ofmt_errx, warnx);

	for (stat = list_head(stats); stat != NULL;
	    stat = list_next(stats, stat)) {
		if (!first && stat->ks_type == KTEST_STAT_MOD) {
			printf("\n");
		}

		ofmt_print(stats_ofmt, stat);

		if (stat->ks_type == KTEST_STAT_MOD) {
			first = B_FALSE;
			ktest_print_hr(74);
		}
	}

	ofmt_close(stats_ofmt);
}

/*
 * Read file at path into the byte array. The byte array is allocated
 * as part of this function and ownership is given to the caller via
 * the bytes argument along with its length returned by 'len'. If an
 * error occurs while reading, the 'err' string is filled in with the
 * appropriate error message.
 *
 * It might be nice to replace this with kobj_{open,read}_file() in
 * the ktest kernel module to avoid shuffling bytes between user and
 * kernel (see devcache which uses these private APIs for the purpose
 * of reading serialized nvlists).
 */
static boolean_t
ktest_read_file(const char *path, uchar_t **bytes, uint64_t *len, char *err)
{
	FILE *f;
	struct stat stats;
	uchar_t *tmp_bytes;
	uint64_t tmp_len;

	*bytes = NULL;
	*len = 0;

	if ((f = fopen(path, "r")) == NULL) {
		(void) strcpy(err, "failed to open input file");
		return (B_FALSE);
	}

	if (fstat(fileno(f), &stats) == -1) {
		(void) fclose(f);
		(void) strcpy(err, "failed to stat input file");
		return (B_FALSE);
	}

	tmp_len = (uint64_t)stats.st_size;

	if ((tmp_bytes = malloc(tmp_len)) == NULL) {
		(void) fclose(f);
		(void) strcpy(err, "failed to allocate byte array of size");
		return (B_FALSE);
	}

	if (fread(tmp_bytes, sizeof (*tmp_bytes), tmp_len, f) != tmp_len) {
		(void) fclose(f);
		(void) snprintf(err, KTEST_MAX_LOG_LEN,
		    "failed to read %u bytes from input file", tmp_len);
		return (B_FALSE);
	}

	*bytes = tmp_bytes;
	*len = tmp_len;
	return (B_TRUE);
}

static boolean_t
ktest_run_test(int dev, const ktest_test_desc_t *desc, const char *input_path,
    ktest_stats_t *mod_stats, ktest_stats_t *suite_stats, ofmt_handle_t ofmt)
{
	ktest_run_op_t kro;
	char err_msg[KTEST_MAX_LOG_LEN];

	/*
	 * It is up to the caller to ensure that an input path is
	 * specified when a test requires it.
	 */
	if (desc->ktd_requires_input) {
		VERIFY(input_path != NULL);
	}

	bzero(&err_msg, KTEST_MAX_LOG_LEN);
	bzero(&kro, sizeof (kro));

	/*
	 * The module/suite/test come from the kernel's list tests
	 * nvlist which we know contain properly sized strings.
	 */
	(void) strlcpy(kro.kro_module, desc->ktd_module, KTEST_MAX_NAME_LEN);
	(void) strlcpy(kro.kro_suite, desc->ktd_suite, KTEST_MAX_NAME_LEN);
	(void) strlcpy(kro.kro_test, desc->ktd_test, KTEST_MAX_NAME_LEN);

	if (input_path != NULL) {
		uchar_t *bytes = NULL;
		uint64_t len = 0;

		/*
		 * The input_path came from the ktest_triple_t which
		 * we know contains a properly sized string.
		 */
		(void) strlcpy(kro.kro_input_path, input_path,
		    sizeof (kro.kro_input_path));

		/*
		 * We treat a failure to read the input file as a test
		 * error.
		 */
		if (!ktest_read_file(input_path, &bytes, &len, err_msg)) {
			kro.kro_result.kr_type = KTEST_RESULT_ERROR;
			(void) strlcpy(kro.kro_result.kr_msg, err_msg,
			    KTEST_MAX_LOG_LEN);
			ktest_record_stat(mod_stats, suite_stats,
			    &kro.kro_result);
			ofmt_print(ofmt, &kro);
			return (B_FALSE);
		}

		/*
		 * The input stream must contain at least 1 byte.
		 */
		if (len == 0) {
			kro.kro_result.kr_type = KTEST_RESULT_ERROR;
			(void) strcpy(kro.kro_result.kr_msg,
			    "zero-length input stream");
			ktest_record_stat(mod_stats, suite_stats,
			    &kro.kro_result);
			ofmt_print(ofmt, &kro);
			return (B_FALSE);
		}

		kro.kro_input_len = len;
		kro.kro_input_bytes = bytes;
	}

	if (ioctl(dev, KTEST_IOCTL_RUN_TEST, &kro) == -1) {
		if (input_path != NULL) {
			err(EXIT_FAILURE, "failed to run test %s:%s:%s with "
			    "input %s", desc->ktd_module, desc->ktd_suite,
			    desc->ktd_test, input_path);
		} else {
			err(EXIT_FAILURE, "failed to run test %s:%s:%s",
			    desc->ktd_module, desc->ktd_suite, desc->ktd_test);
		}
	}

	ktest_record_stat(mod_stats, suite_stats, &kro.kro_result);
	ofmt_print(ofmt, &kro);
	return (kro.kro_result.kr_type == KTEST_RESULT_PASS ||
	    kro.kro_result.kr_type == KTEST_RESULT_SKIP);
}

/*
 * Run all tests specified in the run list and print the result of
 * each test. If print_stats is true, the result statistics are
 * printed as well. A return of true indicates all tests passed. A
 * return of false indicates one or more tests produced an ERROR or
 * FAIL result.
 */
static boolean_t
ktest_run_tests(int dev, nvlist_t *tests, list_t *run_list, ofmt_handle_t ofmt,
    boolean_t print_stats)
{
	ktest_iter_t *iter = ktest_iter(tests, run_list);
	ktest_test_desc_t desc;
	ktest_stats_t *mod_stats = NULL;
	ktest_stats_t *suite_stats = NULL;
	list_t stats;
	ktest_stats_t *stat = NULL;
	boolean_t all_pass = B_TRUE;

	ktest_test_desc_init(&desc);
	list_create(&stats, sizeof (ktest_stats_t),
	    offsetof(ktest_stats_t, ks_node));

	while (ktest_iter_next(iter, &desc)) {
		/*
		 * Either this is our first matching test or we are
		 * transitioning to a new module and/or suite. In
		 * either case, create new stats structures and add
		 * them to the list.
		 */
		if (mod_stats == NULL ||
		    strcmp(mod_stats->ks_name, desc.ktd_module) != 0) {
			mod_stats = ktest_stats_new(KTEST_STAT_MOD,
			    desc.ktd_module);
			list_insert_tail(&stats, mod_stats);
		}

		if (suite_stats == NULL ||
		    strcmp(suite_stats->ks_name, desc.ktd_suite) != 0) {
			suite_stats = ktest_stats_new(KTEST_STAT_SUITE,
			    desc.ktd_suite);
			list_insert_tail(&stats, suite_stats);
		}

		/*
		 * A test that does not require input only has to run
		 * once.
		 */
		if (!desc.ktd_requires_input) {
			if (!ktest_run_test(dev, &desc, NULL, mod_stats,
			    suite_stats, ofmt)) {
				all_pass = B_FALSE;
			}
			continue;
		}

		/*
		 * A test that requires input may have more than one
		 * matching triple. This feature allows a user to
		 * specify multiple input streams for the same test
		 * where each input stream is a separate run of the
		 * test. We iterate the run list; running the test
		 * for each triple that matches and has an input path
		 * specified.
		 */
		for (ktest_triple_t *triple = list_head(run_list);
		    triple != NULL;
		    triple = list_next(run_list, triple)) {
			if (ktest_match_triple(&desc, triple) &&
			    triple->ktr_input_path[0] != '\0') {
				if (!ktest_run_test(dev, &desc,
				    triple->ktr_input_path, mod_stats,
				    suite_stats, ofmt)) {
					all_pass = B_FALSE;
				}
			}
		}
	}

	if (print_stats) {
		printf("\n");
		ktest_print_stats(&stats);
	}

	while ((stat = list_remove_head(&stats)) != NULL) {
		free(stat);
	}

	list_destroy(&stats);
	free(iter);
	return (all_pass);
}

/*
 * Attempt to parse the test triple string and return the resulting
 * triple struct. This leaves the original triple string untouched.
 *
 * This function produces a warning when failing to parse a triple,
 * this is on purpose. This allows the run file parser to produce an
 * error that points out the line number with the bad triple.
 */
static ktest_triple_t *
ktest_parse_triple(const char *tstr, uint32_t lineno)
{
	char *cp = NULL, *orig = NULL;
	char *module = NULL;
	char *suite = NULL;
	char *test = NULL;
	ktest_triple_t *triple = NULL;

	if ((triple = calloc(1, sizeof (*triple))) == NULL) {
		warn("failed to allocate triple");
		return (NULL);
	}

	triple->ktr_lineno = lineno;

	if (strnlen(tstr, KTEST_MAX_TRIPLE_LEN) >= KTEST_MAX_TRIPLE_LEN) {
		warnx("triple is too long");
		goto fail;
	}

	if ((cp = strndup(tstr, KTEST_MAX_TRIPLE_LEN)) == NULL) {
		warn("failed to dup triple string");
		goto fail;
	}

	orig = cp;
	module = strsep(&cp, KTEST_SEPARATOR);

	if (strnlen(module, KTEST_MAX_NAME_LEN) >= KTEST_MAX_NAME_LEN) {
		warnx("module pattern too long: %s", module);
		goto fail;
	}

	if (*module == '\0') {
		module = "*";
	}

	if (cp == NULL) {
		suite = "*";
		test = "*";
		goto copy;
	}

	suite = strsep(&cp, KTEST_SEPARATOR);

	if (strnlen(suite, KTEST_MAX_NAME_LEN) >= KTEST_MAX_NAME_LEN) {
		warnx("suite pattern too long: %s", suite);
		goto fail;
	}

	if (*suite == '\0') {
		suite = "*";
	}

	if (cp == NULL) {
		test = "*";
		goto copy;
	}

	test = cp;

	if (strstr(cp, KTEST_SEPARATOR) != NULL) {
		warnx("malformed triple, unexpected ':' in test pattern: %s",
		    test);
		goto fail;
	}

	if (strnlen(test, KTEST_MAX_NAME_LEN) >= KTEST_MAX_NAME_LEN) {
		warnx("test pattern too long: %s", test);
		goto fail;
	}

	if (*test == '\0') {
		test = "*";
	}

copy:
	/* We've checked the string lengths, but just in case. */
	(void) strlcpy(triple->ktr_module, module, sizeof (triple->ktr_module));
	(void) strlcpy(triple->ktr_suite, suite, sizeof (triple->ktr_suite));
	(void) strlcpy(triple->ktr_test, test, sizeof (triple->ktr_test));
	free(orig);
	return (triple);

fail:
	free(orig);
	free(triple);
	return (NULL);
}

/*
 * Attempt to load the run file specified and decode it into a run
 * list. Use stdin as the content of the runfile when use_stdin is
 * true.
 *
 * Currently all input files must either be relative to the working
 * directory or an absolute path. In the future it would be nice to
 * support something like glob(3C) to perform tilde expansion for the
 * input file path. Another idea would be to add a search path for
 * input files, allowing us to more easily constrain where on the
 * filesystem these files are searched for.
 */
static void
ktest_load_run_file(const char *path, boolean_t use_stdin, nvlist_t *tests,
    list_t *run_list)
{
	FILE *f;
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;
	uint32_t lineno = 0;
	boolean_t one_line = B_FALSE; /* At least one valid line? */

	if (use_stdin) {
		f = stdin;
	} else {
		if ((f = fopen(path, "r")) == NULL) {
			err(EXIT_FAILURE, "failed to open run file %s", path);
		}
	}

	while ((len = getline(&line, &cap, f)) != -1) {
		char *input, *lasts, *tstr;
		ktest_triple_t *triple;

		lineno++;
		/* A line is always at least one character: newline. */
		VERIFY3S(len, >=, 1);
		/* Skip the newline. */
		line[len - 1] = '\0';

		/* Skip empty lines. */
		if (line[0] == '\0') {
			continue;
		}

		/*
		 * A valid line consists of either a test triple on
		 * its own or a test triple and an input file
		 * separated by whitespace.
		 */
		tstr = strtok_r(line, " \t", &lasts);
		triple = ktest_parse_triple(tstr, lineno);

		if (triple == NULL) {
			errx(EXIT_FAILURE, "failed to parse triple %s at line "
			    "%u", tstr, lineno);
		}

		input = strtok_r(NULL, " \t", &lasts);

		if (input != NULL) {
			size_t len = strlcpy(triple->ktr_input_path, input,
			    sizeof (triple->ktr_input_path));
			if (len >= sizeof (triple->ktr_input_path)) {
				err(EXIT_FAILURE, "input path at line %u too "
				    "long: %s\n", lineno, input);
			}
		}

		list_insert_tail(run_list, triple);
		one_line = B_TRUE;
	}

	/*
	 * If we broke from the loop for a reason other than EOF, then
	 * assume we do not have a full run list and exit.
	 */
	if (ferror(f)) {
		err(EXIT_FAILURE, "failed to read entire runfile");
	}

	if (!use_stdin) {
		(void) fclose(f);
	}

	free(line);

	if (!one_line) {
		errx(EXIT_FAILURE, "no tests specified in: %s", path);
	}
}

/*
 * Is this test triple fully-qualified?
 *
 * A fully-qualified triple is one where the module, suite, and test
 * use no glob characters with the intent that it refers to a single,
 * unique test.
 */
static boolean_t
ktest_is_fqt(const ktest_triple_t *triple)
{
	return (strpbrk(triple->ktr_module, KTEST_GMATCH_CHARS) == NULL &&
	    strpbrk(triple->ktr_suite, KTEST_GMATCH_CHARS) == NULL &&
	    strpbrk(triple->ktr_test, KTEST_GMATCH_CHARS) == NULL);
}

/*
 * Does this fully-qualified triple refer to a test which requires
 * input?
 */
static boolean_t
ktest_fqt_requires_input(ktest_triple_t *triple, nvlist_t *tests)
{
	list_t filter;
	ktest_iter_t *iter = NULL;
	ktest_test_desc_t desc;
	/*
	 * Need a local copy of the triple in order to build a filter
	 * list for ktest_iter() because the argument is already a
	 * part of the run list and reusing it would clobber its node
	 * link.
	 */
	ktest_triple_t cp = *triple;

	VERIFY(ktest_is_fqt(triple));

	list_create(&filter, sizeof (ktest_triple_t),
	    offsetof(ktest_triple_t, ktr_node));
	list_insert_head(&filter, &cp);
	iter = ktest_iter(tests, &filter);

	if (!ktest_iter_next(iter, &desc)) {
		return (B_FALSE);
	}

	return (desc.ktd_requires_input);
}

/*
 * Check if the fully-qualified triple has an input path when it
 * should. Return true if the entry is okay and false if there is a
 * mismatch between the test descriptor the the triple entry.
 */
static boolean_t
ktest_check_fqt_entry(nvlist_t *tests, ktest_triple_t *triple)
{
	boolean_t requires_input = ktest_fqt_requires_input(triple, tests);

	if (requires_input && strlen(triple->ktr_input_path) == 0) {
		warnx("fully-qualified triple %s:%s:%s at line %u missing "
		    "input for test that requires input", triple->ktr_module,
		    triple->ktr_suite, triple->ktr_test, triple->ktr_lineno);
		return (B_FALSE);
	} else if (!requires_input && strlen(triple->ktr_input_path) != 0) {
		warnx("fully-qualified triple %s:%s:%s at line %u specifies "
		    "input for test that does not require it",
		    triple->ktr_module, triple->ktr_suite, triple->ktr_test,
		    triple->ktr_lineno);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * When a test is fully-qualified it could be for the purpose of
 * specifying an input stream. We provide this check to catch missing
 * input (or input on a test that does not require it) as a benefit to
 * the user.
 *
 * We do not exit immediately upon finding a bad entry; but instead
 * print a warning for each bad triple and then exit with failure.
 */
static void
ktest_check_fqt_entries(nvlist_t *tests, list_t *run_list)
{
	boolean_t bad_triple = B_FALSE;

	for (ktest_triple_t *triple = list_head(run_list); triple != NULL;
	    triple = list_next(run_list, triple)) {
		if (ktest_is_fqt(triple)) {
			if (!ktest_check_fqt_entry(tests, triple)) {
				bad_triple = B_TRUE;
			}
		}
	}

	if (bad_triple) {
		errx(EXIT_FAILURE, "one or more incorrect triples");
	}
}

/*
 * Verify that the run list is acceptable.
 */
static void
ktest_verify_run_list(nvlist_t *tests, list_t *run_list)
{
	ktest_check_fqt_entries(tests, run_list);
}

static boolean_t
ktest_run_cmd(int argc, char *argv[], int ktdev)
{
	int c;
	nvlist_t *tests = NULL;
	list_t run_list;
	char *input_path = NULL;
	boolean_t parsable = B_FALSE;
	boolean_t fields_set = B_FALSE;
	boolean_t print_stats = B_TRUE;
	char *fields = KTEST_RUN_CMD_DEF_FIELDS;
	uint_t oflags = 0;
	ofmt_handle_t ofmt = NULL;
	ofmt_status_t oferr;
	boolean_t all_pass = B_FALSE;

	while ((c = getopt(argc, argv, ":Ho:pi:")) != -1) {
		switch (c) {
		case 'H':
			oflags |= OFMT_NOHEADER;
			break;
		case 'o':
			fields = optarg;
			fields_set = B_TRUE;
			break;
		case 'p':
			parsable = B_TRUE;
			print_stats = B_FALSE;
			oflags |= OFMT_PARSABLE;
			break;
		case 'i':
			if (input_path != NULL) {
				ktest_usage("cannot specify -i more than once");
				exit(EXIT_USAGE);
			}

			input_path = optarg;

			if (strnlen(input_path, MAXPATHLEN) >= MAXPATHLEN) {
				err(EXIT_FAILURE, "input path too long");
			}

			break;
		case ':':
			ktest_usage("missing argument to -%c", optopt);
			exit(EXIT_USAGE);

		case '?':
			ktest_usage("unknown run option: -%c", optopt);
			exit(EXIT_USAGE);
		}
	}

	if (parsable && !fields_set) {
		ktest_usage("must specify -o with -p");
		exit(EXIT_USAGE);
	}

	oferr = ofmt_open(fields, ktest_run_ofmt, oflags, 0, &ofmt);
	ofmt_check(oferr, parsable, ofmt, ktest_ofmt_errx, warnx);

	argc -= optind;
	argv += optind;

	/*
	 * We don't run all tests by default. We assume that as the
	 * library of test modules grows we want to be sure the user
	 * actually wants to run all tests by forcing them to at least
	 * specify the `*` glob.
	 */
	if (argc < 1) {
		ktest_usage("must specify at least one triple");
		exit(EXIT_USAGE);
	}

	list_create(&run_list, sizeof (ktest_triple_t),
	    offsetof(ktest_triple_t, ktr_node));

	for (uint_t i = 0; i < argc; i++) {
		ktest_triple_t *triple = ktest_parse_triple(argv[i], 0);

		if (triple == NULL) {
			errx(EXIT_FAILURE, "failed to parse triple: %s",
			    argv[i]);
		}

		if (input_path != NULL) {
			/*
			 * The path length was checked during option
			 * parsing.
			 */
			(void) strcpy(triple->ktr_input_path, input_path);
		}

		list_insert_tail(&run_list, triple);
	}

	tests = ktest_list_tests(ktdev);
	ktest_verify_run_list(tests, &run_list);
	all_pass = ktest_run_tests(ktdev, tests, &run_list, ofmt, print_stats);
	ofmt_close(ofmt);
	ktest_free_triples(&run_list);
	list_destroy(&run_list);
	nvlist_free(tests);
	return (all_pass);
}

static boolean_t
ktest_run_file_cmd(int argc, char *argv[], int ktdev)
{
	int c;
	nvlist_t *tests = NULL;
	list_t run_list;
	char *run_file = NULL;
	boolean_t use_stdin = B_FALSE;
	boolean_t parsable = B_FALSE;
	boolean_t fields_set = B_FALSE;
	boolean_t print_stats = B_TRUE;
	char *fields = KTEST_RUN_CMD_DEF_FIELDS;
	uint_t oflags = 0;
	ofmt_handle_t ofmt = NULL;
	ofmt_status_t oferr;
	boolean_t all_pass = B_FALSE;

	while ((c = getopt(argc, argv, ":Ho:p")) != -1) {
		switch (c) {
		case 'H':
			oflags |= OFMT_NOHEADER;
			break;
		case 'o':
			fields = optarg;
			fields_set = B_TRUE;
			break;
		case 'p':
			parsable = B_TRUE;
			print_stats = B_FALSE;
			oflags |= OFMT_PARSABLE;
			break;
		case ':':
			ktest_usage("missing argument to -%c", optopt);
			exit(EXIT_USAGE);
		case '?':
			ktest_usage("unknown option: -%c", optopt);
			exit(EXIT_USAGE);
		}
	}

	if (parsable && !fields_set) {
		ktest_usage("must specify -o with -p");
		exit(EXIT_USAGE);
	}

	oferr = ofmt_open(fields, ktest_run_ofmt, oflags, 0, &ofmt);
	ofmt_check(oferr, parsable, ofmt, ktest_ofmt_errx, warnx);

	argc -= optind;
	argv += optind;

	if (argc > 1) {
		ktest_usage("must specify only one run file");
		exit(EXIT_USAGE);
	}

	/*
	 * Use stdin as the run file when no run file argument is
	 * specified.
	 */
	if (argc == 0) {
		use_stdin = B_TRUE;
	}

	run_file = argv[0];
	tests = ktest_list_tests(ktdev);
	list_create(&run_list, sizeof (ktest_triple_t),
	    offsetof(ktest_triple_t, ktr_node));
	ktest_load_run_file(run_file, use_stdin, tests, &run_list);
	ktest_verify_run_list(tests, &run_list);
	all_pass = ktest_run_tests(ktdev, tests, &run_list, ofmt, print_stats);
	ofmt_close(ofmt);
	ktest_free_triples(&run_list);
	list_destroy(&run_list);
	nvlist_free(tests);
	return (all_pass);
}

static void
ktest_list_cmd(int argc, char *argv[], int dev)
{
	int c;
	list_t triples;
	nvlist_t *tests = NULL;
	boolean_t parsable = B_FALSE;
	boolean_t fields_set = B_FALSE;
	char *fields = KTEST_LIST_CMD_DEF_FIELDS;
	uint_t oflags = 0;
	ofmt_handle_t ofmt = NULL;
	ofmt_status_t oferr;

	list_create(&triples, sizeof (ktest_triple_t),
	    offsetof(ktest_triple_t, ktr_node));

	while ((c = getopt(argc, argv, ":Ho:p")) != -1) {
		switch (c) {
		case 'H':
			oflags |= OFMT_NOHEADER;
			break;
		case 'o':
			fields = optarg;
			fields_set = B_TRUE;
			break;
		case 'p':
			parsable = B_TRUE;
			oflags |= OFMT_PARSABLE;
			break;
		case ':':
			ktest_usage("missing argument to -%c", optopt);
			exit(EXIT_USAGE);
		case '?':
			ktest_usage("unknown option: -%c", optopt);
			exit(EXIT_USAGE);
		}
	}

	if (parsable && !fields_set) {
		ktest_usage("must specify -o with -p");
		exit(EXIT_USAGE);
	}

	oferr = ofmt_open(fields, ktest_list_ofmt, oflags, 0, &ofmt);
	ofmt_check(oferr, parsable, ofmt, ktest_ofmt_errx, warnx);

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		list_insert_tail(&triples, ktest_def_triple);
	} else {
		for (uint_t i = 0; i < argc; i++) {
			ktest_triple_t *triple = ktest_parse_triple(argv[i], 0);

			if (triple == NULL) {
				errx(EXIT_FAILURE, "failed to parse triple: %s",
				    argv[i]);
			}

			list_insert_tail(&triples, triple);
		}
	}

	tests = ktest_list_tests(dev);
	ktest_print_tests(tests, &triples, ofmt);
	ofmt_close(ofmt);
	nvlist_free(tests);
	ktest_free_triples(&triples);
	list_destroy(&triples);
}

static void
ktest_alloc_def_triple()
{
	ktest_def_triple = ktest_parse_triple(KTEST_DEF_TRIPLE, 0);

	if (ktest_def_triple == NULL) {
		err(EXIT_FAILURE, "failed to initialize default triple");
	}
}

int
main(int argc, char *argv[])
{
	int fd;
	const char *cmd;

	ktest_prog = basename(argv[0]);

	if (getzoneid() != GLOBAL_ZONEID || getuid() != 0) {
		errx(EXIT_FAILURE, "can only be used by root from"
		    " the global zone");
	}

	if (argc < 2) {
		ktest_usage("no command specified");
		exit(EXIT_USAGE);
	}

	/*
	 * Peel off program name and command.
	 */
	cmd = argv[1];
	argc -= 2;
	argv += 2;
	optind = 0;

	if ((fd = open(KTEST_DEV_PATH, O_RDONLY, 0)) == -1) {
		err(EXIT_FAILURE, "failed to open %s", KTEST_DEV_PATH);
	}

	ktest_alloc_def_triple();

	if (strncasecmp("list", cmd, KTEST_CMD_SZ) == 0) {
		ktest_list_cmd(argc, argv, fd);
	} else if (strncasecmp("run", cmd, KTEST_CMD_SZ) == 0) {
		if (!ktest_run_cmd(argc, argv, fd)) {
			errx(EXIT_FAILURE, "one or more tests did not pass");
		}
	} else if (strncasecmp("run-file", cmd, KTEST_CMD_SZ) == 0) {
		if (!ktest_run_file_cmd(argc, argv, fd)) {
			errx(EXIT_FAILURE, "one or more tests did not pass");
		}
	} else if (strncasecmp("help", cmd, KTEST_CMD_SZ) == 0) {
		ktest_usage(NULL);
	} else {
		ktest_usage("unknown command: %s", cmd);
		exit(EXIT_USAGE);
	}

	(void) close(fd);
	return (0);
}
