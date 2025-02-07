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
#include <libktest.h>

#define	EXIT_USAGE		2
#define	KTEST_CMD_SZ		24

static const char *ktest_prog;


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
	ktest_entry_t *ent = ofarg->ofmt_cbarg;

	switch (ofarg->ofmt_id) {
	case KTEST_FMT_MODULE:
		if (snprintf(buf, len, "%s", ent->ke_module) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_SUITE:
		if (snprintf(buf, len, "%s", ent->ke_suite) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_TEST:
		if (snprintf(buf, len, "%s", ent->ke_test) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_INPUT_FLAG: {
		const char *flag = ent->ke_requires_input ? "Y" : "N";

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

typedef struct ktest_run_output {
	ktest_run_req_t		*kro_req;
	ktest_run_result_t	*kro_result;
	char			*kro_input_path;
} ktest_run_output_t;

static boolean_t
ktest_run_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t len)
{
	const ktest_run_output_t *kro = ofarg->ofmt_cbarg;
	const ktest_run_req_t *req = kro->kro_req;
	const ktest_run_result_t *result = kro->kro_result;
	const char *input_path =
	    kro->kro_input_path != NULL ? kro->kro_input_path : "";

	switch (ofarg->ofmt_id) {
	case KTEST_FMT_RESULT:
		if (snprintf(buf, len, "%s",
		    ktest_code_name(result->krr_code)) >= len) {
			return (B_FALSE);
		}
		break;
	case KTEST_FMT_MODULE:
		if (snprintf(buf, len, "%s", req->krq_module) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_SUITE:
		if (snprintf(buf, len, "%s", req->krq_suite) >= len) {
			return (B_FALSE);
		}
		break;

	case KTEST_FMT_TEST:
		if (snprintf(buf, len, "%s", req->krq_test) >= len) {
			return (B_FALSE);
		}
		break;
	case KTEST_FMT_INPUT_PATH:
		if (snprintf(buf, len, "%s", input_path) >= len) {
			return (B_FALSE);
		}
		break;
	case KTEST_FMT_LINE:
		if (snprintf(buf, len, "%u", result->krr_line) >= len) {
			return (B_FALSE);
		}
		break;
	case KTEST_FMT_REASON:
		if (snprintf(buf, len, "%s", result->krr_msg) >= len) {
			return (B_FALSE);
		}
		break;
	}

	return (B_TRUE);
}

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
    const ktest_run_result_t *res)
{
	mod->ks_total++;
	suite->ks_total++;

	switch (res->krr_code) {
	case KTEST_CODE_NONE:
		mod->ks_none++;
		suite->ks_none++;
		break;

	case KTEST_CODE_PASS:
		mod->ks_pass++;
		suite->ks_pass++;
		break;

	case KTEST_CODE_FAIL:
		mod->ks_fail++;
		suite->ks_fail++;
		break;

	case KTEST_CODE_SKIP:
		mod->ks_skip++;
		suite->ks_skip++;
		break;

	case KTEST_CODE_ERROR:
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
	    "\trun [-Hn] [[-p] -o field,...] [-i <file>] <triple> ...: "
	    "run specified tests\n"
	    "\tload <name> | -a\n"
	    "\tunload <name> | -a\n",
	    ktest_prog);
}

/*
 * A user-specified test triple. The input path is set to the empty
 * string if no input is provided. The line number provides useful
 * error reporting when an error is encountered in the run file.
 */
typedef struct ktest_triple {
	list_node_t	ktr_node;
	char		*ktr_module;
	char		*ktr_suite;
	char		*ktr_test;
	/* Did this triple match one or more tests during a ktest-run? */
	boolean_t	ktr_was_matched;
} ktest_triple_t;

/* Match-all triple used as default when user provides no triples */
static ktest_triple_t ktest_def_triple = {
	.ktr_module = "*",
	.ktr_suite = "*",
	.ktr_test = "*",
};

static void
ktest_free_triples(list_t *triples)
{
	ktest_triple_t *t = NULL;

	while ((t = list_remove_head(triples)) != NULL) {
		if (t == &ktest_def_triple) {
			/*
			 * Default triple is not heap allocated, and is used
			 * only when no other matches are specified
			 */
			VERIFY(list_is_empty(triples));
			continue;
		}
		free(t->ktr_module);
		free(t->ktr_suite);
		free(t->ktr_test);
		free(t);
	}

	list_destroy(triples);
}

/*
 * Does the test entry match this triple?
 */
static boolean_t
ktest_match_triple(const ktest_entry_t *ent, const ktest_triple_t *triple)
{
	return (gmatch(ent->ke_module, triple->ktr_module) != 0 &&
	    gmatch(ent->ke_suite, triple->ktr_suite) != 0 &&
	    gmatch(ent->ke_test, triple->ktr_test) != 0);
}

/*
 * Does the test entry match any triples in the provided list?
 *
 * Returns a pointer to the matching triple, if one found.
 */
static ktest_triple_t *
ktest_match_triples(const ktest_entry_t *ent, list_t *triples)
{
	for (ktest_triple_t *triple = list_head(triples);
	    triple != NULL;
	    triple = list_next(triples, triple)) {
		if (ktest_match_triple(ent, triple)) {
			return (triple);
		}
	}
	return (NULL);
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
ktest_parse_triple(const char *tstr)
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
	triple->ktr_module = strdup(module);
	triple->ktr_suite = strdup(suite);
	triple->ktr_test = strdup(test);
	free(orig);
	return (triple);

fail:
	free(orig);
	free(triple);
	return (NULL);
}

static void
ktest_parse_triples(list_t *triples, uint_t count, const char *tinput[])
{
	list_create(triples, sizeof (ktest_triple_t),
	    offsetof(ktest_triple_t, ktr_node));

	if (count == 0) {
		list_insert_tail(triples, &ktest_def_triple);
		return;
	}

	for (uint_t i = 0; i < count; i++) {
		ktest_triple_t *triple = ktest_parse_triple(tinput[i]);

		if (triple == NULL) {
			errx(EXIT_FAILURE, "failed to parse triple: %s",
			    tinput[i]);
		}

		list_insert_tail(triples, triple);
	}
}


/*
 * Does the test entry match any of the triples?
 */
static boolean_t
ktest_match_any(const ktest_entry_t *ent, list_t *triples)
{
	for (ktest_triple_t *triple = list_head(triples); triple != NULL;
	    triple = list_next(triples, triple)) {
		if (ktest_match_triple(ent, triple)) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
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
			/* Print a 72-char horizontal rule. */
			printf("-----------------------------------"
			    "-----------------------------------\n");
		}
	}

	ofmt_close(stats_ofmt);
}

/*
 * Read file at path into the byte array.  If an error occurs, `err` will be
 * populated with an allocated string describing the problem.  If the file was
 * read successfully, the allocated buffer will be placed in `bytes` with its
 * size recorded in `len`.
 */
static boolean_t
ktest_read_file(const char *path, uchar_t **bytes, size_t *len, char **err)
{
	FILE *fp = fopen(path, "r");
	if (fp == NULL) {
		*err = strdup("failed to open input file");
		return (B_FALSE);
	}

	struct stat stats;
	if (fstat(fileno(fp), &stats) == -1) {
		(void) fclose(fp);
		*err = strdup("failed to stat input file");
		return (B_FALSE);
	}

	const size_t target_sz = (size_t)stats.st_size;
	const size_t max_sz = ktest_max_input_size();
	if (target_sz > max_sz) {
		(void) fclose(fp);
		(void) asprintf(err,
		    "input size greater than max of %u bytes", max_sz);
		return (B_FALSE);
	} else if (target_sz == 0) {
		(void) fclose(fp);
		*err = strdup("input file cannot be zero-length");
		return (B_FALSE);
	}

	uchar_t *buf = malloc(target_sz);
	if (buf == NULL) {
		(void) fclose(fp);
		*err = strdup("failed to allocate byte array of size");
		return (B_FALSE);
	}

	if (fread(buf, 1, target_sz, fp) != target_sz) {
		(void) fclose(fp);
		(void) asprintf(err,
		    "failed to read %u bytes from input file", target_sz);
		return (B_FALSE);
	}

	*bytes = buf;
	*len = target_sz;
	return (B_TRUE);
}

static boolean_t
ktest_run_test(ktest_hdl_t *kthdl, const ktest_entry_t *ent,
    char *input_path, ktest_stats_t *mod_stats, ktest_stats_t *suite_stats,
    ofmt_handle_t ofmt)
{
	ktest_run_req_t req = {
		.krq_module = ent->ke_module,
		.krq_suite = ent->ke_suite,
		.krq_test = ent->ke_test,
	};
	ktest_run_result_t res = { 0 };
	ktest_run_output_t kro = {
		.kro_req = &req,
		.kro_result = &res,
		.kro_input_path = input_path,
	};

	/* Fail with error when lacking input for test which requires it */
	if (ent->ke_requires_input && input_path == NULL) {
		res.krr_msg = strdup("test requires input and none provided");
		res.krr_code = KTEST_CODE_ERROR;
		ktest_record_stat(mod_stats, suite_stats, &res);
		ofmt_print(ofmt, &kro);
		free(res.krr_msg);
		return (B_FALSE);
	}

	if (input_path != NULL) {
		/* We treat a failure to read the input file as a test error. */
		if (!ktest_read_file(input_path, &req.krq_input,
		    &req.krq_input_len, &res.krr_msg)) {
			res.krr_code = KTEST_CODE_ERROR;
			ktest_record_stat(mod_stats, suite_stats, &res);
			ofmt_print(ofmt, &kro);
			free(res.krr_msg);
			return (B_FALSE);
		}
	}

	if (!ktest_run(kthdl, &req, &res)) {
		if (input_path != NULL) {
			err(EXIT_FAILURE, "failed to run test %s:%s:%s with "
			    "input %s", ent->ke_module, ent->ke_suite,
			    ent->ke_test, input_path);
		} else {
			err(EXIT_FAILURE, "failed to run test %s:%s:%s",
			    ent->ke_module, ent->ke_suite, ent->ke_test);
		}
	}

	ktest_record_stat(mod_stats, suite_stats, &res);
	ofmt_print(ofmt, &kro);
	free(res.krr_msg);
	return (res.krr_code == KTEST_CODE_PASS ||
	    res.krr_code == KTEST_CODE_SKIP);
}

typedef enum ktest_run_test_flags {
	KRTF_PRINT_STATS = (1 << 0),
	KRTF_SKIP_INPUT_REQ = (1 << 1),
} ktest_run_test_flags_t;

/*
 * Run all tests specified in the run list and print the result of each test.
 *
 * Returns the number of tests which failed.
 */
static uint_t
ktest_run_tests(ktest_hdl_t *kthdl, list_t *run_list, char *input_path,
    ofmt_handle_t ofmt, ktest_run_test_flags_t flags)
{
	ktest_stats_t *mod_stats = NULL;
	ktest_stats_t *suite_stats = NULL;
	list_t stats;
	ktest_stats_t *stat = NULL;

	list_create(&stats, sizeof (ktest_stats_t),
	    offsetof(ktest_stats_t, ks_node));

	ktest_list_iter_t *iter = ktest_list(kthdl);
	if (iter == NULL) {
		err(EXIT_FAILURE, "Could not list ktests");
	}

	uint_t tests_matched = 0, tests_failed = 0;
	ktest_entry_t ent;
	while (ktest_list_next(iter, &ent)) {
		ktest_triple_t *triple;
		if ((triple = ktest_match_triples(&ent, run_list)) == NULL) {
			continue;
		}

		if (ent.ke_requires_input && input_path == NULL &&
		    (flags & KRTF_SKIP_INPUT_REQ)) {
			/*
			 * User has provided no input and requested that
			 * input-required tests be explicitly skipped.
			 */
			continue;
		}

		/*
		 * Since this matching test will not be skipped for input
		 * reasons, record that its corresponding triple was used.
		 *
		 * This could be inadequate if the user specifies triples which
		 * overlap in their matches.  We can make it more robust to such
		 * cases later.
		 */
		triple->ktr_was_matched |= B_TRUE;
		tests_matched++;

		/*
		 * Either this is our first matching test or we are
		 * transitioning to a new module and/or suite. In either case,
		 * create new stats structures and add them to the list.
		 */
		if (mod_stats == NULL ||
		    strcmp(mod_stats->ks_name, ent.ke_module) != 0) {
			mod_stats = ktest_stats_new(KTEST_STAT_MOD,
			    ent.ke_module);
			list_insert_tail(&stats, mod_stats);
		}
		if (suite_stats == NULL ||
		    strcmp(suite_stats->ks_name, ent.ke_suite) != 0) {
			suite_stats = ktest_stats_new(KTEST_STAT_SUITE,
			    ent.ke_suite);
			list_insert_tail(&stats, suite_stats);
		}

		/* Run the test */
		if (!ktest_run_test(kthdl, &ent, input_path,
		    mod_stats, suite_stats, ofmt)) {
			tests_failed++;
		}
	}

	/* Make sure we ran _something_ */
	if (tests_matched == 0) {
		errx(EXIT_FAILURE, "No tests matched selection triple(s)");
	}

	/* Confirm that all triples matched something */
	boolean_t fail_match = B_FALSE;
	for (ktest_triple_t *triple = list_head(run_list);
	    triple != NULL;
	    triple = list_next(run_list, triple)) {
		if (!triple->ktr_was_matched) {
			fail_match = B_TRUE;
			break;
		}
	}
	if (fail_match) {
		(void) fprintf(stderr, "These triples failed to match "
		    "any tests, or were superseded by other matches:\n");
		for (ktest_triple_t *triple = list_head(run_list);
		    triple != NULL;
		    triple = list_next(run_list, triple)) {
			if (!triple->ktr_was_matched) {
				(void) fprintf(stderr, "\t%s:%s:%s\n",
				    triple->ktr_module, triple->ktr_suite,
				    triple->ktr_test);
			}
		}
		exit(EXIT_FAILURE);
	}

	if (flags & KRTF_PRINT_STATS) {
		printf("\n");
		ktest_print_stats(&stats);
	}

	while ((stat = list_remove_head(&stats)) != NULL) {
		free(stat);
	}
	list_destroy(&stats);
	free(iter);
	return (tests_failed);
}

static void
ktest_run_cmd(int argc, char *argv[])
{
	int c;
	char *input_path = NULL;
	boolean_t parsable = B_FALSE;
	boolean_t fields_set = B_FALSE;
	ktest_run_test_flags_t flags = KRTF_PRINT_STATS;
	char *fields = KTEST_RUN_CMD_DEF_FIELDS;
	uint_t oflags = 0;
	ofmt_handle_t ofmt = NULL;
	ofmt_status_t oferr;

	while ((c = getopt(argc, argv, ":Hno:pi:")) != -1) {
		switch (c) {
		case 'H':
			oflags |= OFMT_NOHEADER;
			break;
		case 'n':
			flags |= KRTF_SKIP_INPUT_REQ;
			break;
		case 'o':
			fields = optarg;
			fields_set = B_TRUE;
			break;
		case 'p':
			parsable = B_TRUE;
			flags &= ~KRTF_PRINT_STATS;
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
	 * We don't run all tests by default. We assume that as the library of
	 * test modules grows we want to be sure the user actually wants to run
	 * all tests by forcing them to at least specify the `*` glob.
	 */
	if (argc < 1) {
		ktest_usage("must specify at least one triple");
		exit(EXIT_USAGE);
	}
	list_t triples;
	ktest_parse_triples(&triples, argc, (const char **)argv);

	ktest_hdl_t *kthdl = ktest_init();
	if (kthdl == NULL) {
		err(EXIT_FAILURE, "Could not open ktest");
	}
	uint_t failed_count =
	    ktest_run_tests(kthdl, &triples, input_path, ofmt, flags);

	ofmt_close(ofmt);
	ktest_free_triples(&triples);
	ktest_fini(kthdl);

	if (failed_count != 0) {
		errx(EXIT_FAILURE, "%u %s did not pass",
		    failed_count, failed_count > 1 ? "tests" : "test");
	}
}

static void
ktest_list_cmd(int argc, char *argv[])
{
	int c;
	boolean_t parsable = B_FALSE;
	boolean_t fields_set = B_FALSE;
	char *fields = KTEST_LIST_CMD_DEF_FIELDS;
	uint_t oflags = 0;
	ofmt_handle_t list_ofmt = NULL;
	ofmt_status_t oferr;

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

	oferr = ofmt_open(fields, ktest_list_ofmt, oflags, 0, &list_ofmt);
	ofmt_check(oferr, parsable, list_ofmt, ktest_ofmt_errx, warnx);

	argc -= optind;
	argv += optind;

	list_t triples;
	ktest_parse_triples(&triples, argc, (const char **)argv);

	ktest_hdl_t *kthdl = ktest_init();
	if (kthdl == NULL) {
		err(EXIT_FAILURE, "Could not open ktest");
	}
	ktest_list_iter_t *iter = ktest_list(kthdl);
	if (iter == NULL) {
		err(EXIT_FAILURE, "Could not list ktests");
	}

	ktest_entry_t ent;
	while (ktest_list_next(iter, &ent)) {
		if (!ktest_match_any(&ent, &triples)) {
			continue;
		}
		ofmt_print(list_ofmt, &ent);
	}

	ktest_list_free(iter);
	ktest_fini(kthdl);

	ofmt_close(list_ofmt);
	ktest_free_triples(&triples);
}

static void
ktest_load_cmd(int argc, char *argv[])
{
	int c;
	boolean_t load_all = B_FALSE;

	while ((c = getopt(argc, argv, "a")) != -1) {
		switch (c) {
		case 'a':
			load_all = B_TRUE;
			break;
		case '?':
			ktest_usage("unknown option: -%c", optopt);
			exit(EXIT_USAGE);
		}
	}

	argc -= optind;
	argv += optind;

	if (load_all) {
		/*
		 * We just ignore specified module names if the user requested
		 * that everything should be loaded.
		 */
		if (!ktest_mod_load_all()) {
			err(EXIT_FAILURE, "Could not load all ktests");
		}
		return;
	}
	if (argc <= 0) {
		ktest_usage("must specify module name(s) or -a");
		exit(EXIT_USAGE);
	}
	boolean_t any_failed = B_FALSE;
	for (int i = 0; i < argc; i++) {
		if (!ktest_mod_load(argv[i])) {
			any_failed = B_TRUE;
			warn("Could not load module %s", argv[i]);
		}
	}
	if (any_failed) {
		errx(EXIT_FAILURE, "Some modules failed to load");
	}
}

static void
ktest_unload_cmd(int argc, char *argv[])
{
	int c;
	boolean_t unload_all = B_FALSE;

	while ((c = getopt(argc, argv, "a")) != -1) {
		switch (c) {
		case 'a':
			unload_all = B_TRUE;
			break;
		case '?':
			ktest_usage("unknown option: -%c", optopt);
			exit(EXIT_USAGE);
		}
	}

	argc -= optind;
	argv += optind;

	if (unload_all) {
		/*
		 * We just ignore specified module names if the user requested
		 * that everything should be unloaded.
		 */
		if (!ktest_mod_unload_all()) {
			err(EXIT_FAILURE, "Could not unload all ktests");
		}
		return;
	}
	if (argc <= 0) {
		ktest_usage("must specify module name(s) or -a");
		exit(EXIT_USAGE);
	}
	for (int i = 0; i < argc; i++) {
		ktest_mod_unload(argv[i]);
	}
}

int
main(int argc, char *argv[])
{
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

	if (strncasecmp("list", cmd, KTEST_CMD_SZ) == 0) {
		ktest_list_cmd(argc, argv);
	} else if (strncasecmp("run", cmd, KTEST_CMD_SZ) == 0) {
		ktest_run_cmd(argc, argv);
	} else if (strncasecmp("load", cmd, KTEST_CMD_SZ) == 0) {
		ktest_load_cmd(argc, argv);
	} else if (strncasecmp("unload", cmd, KTEST_CMD_SZ) == 0) {
		ktest_unload_cmd(argc, argv);
	} else if (strncasecmp("help", cmd, KTEST_CMD_SZ) == 0) {
		ktest_usage(NULL);
	} else {
		ktest_usage("unknown command: %s", cmd);
		exit(EXIT_USAGE);
	}

	return (EXIT_SUCCESS);
}
