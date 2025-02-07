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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <atomic.h>
#include <sys/ktest.h>
#include <sys/systeminfo.h>
#include <sys/modctl.h>
#include <upanic.h>

#include "libktest_impl.h"

/*
 * Open ktest device handle.
 *
 * Returns handle pointer on success, otherwise NULL (setting errno).
 */
ktest_hdl_t *
ktest_init(void)
{
	int fd = open(KTEST_DEV_PATH, O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0) {
		return (NULL);
	}

	ktest_hdl_t *hdl = malloc(sizeof (ktest_hdl_t));
	if (hdl == NULL) {
		const int err = errno;
		(void) close(fd);
		errno = err;
		return (NULL);
	}

	hdl->kt_fd = fd;
	return (hdl);
}

/*
 * Close ktest device handle.
 */
void
ktest_fini(ktest_hdl_t *hdl)
{
	if (hdl == NULL) {
		return;
	}
	if (hdl->kt_fd >= 0) {
		(void) close(hdl->kt_fd);
		hdl->kt_fd = -1;
	}
	free(hdl);
}

#define	DEFAULT_LIST_BUF_SZ	(64 * 1024)

static nvlist_t *
ktest_query_tests(ktest_hdl_t *hdl)
{
	char *resp = malloc(DEFAULT_LIST_BUF_SZ);
	ktest_list_op_t op = {
		.klo_resp = resp,
		.klo_resp_len = DEFAULT_LIST_BUF_SZ,
	};

	if (resp == NULL) {
		return (NULL);
	}

	int ret;
	ret = ioctl(hdl->kt_fd, KTEST_IOCTL_LIST_TESTS, &op);

	/* Resize buffer and retry, if ioctl indicates it was too small */
	if (ret == -1 && errno == ENOBUFS) {
		free(resp);

		if ((resp = malloc(op.klo_resp_len)) == NULL) {
			return (NULL);
		}
		op.klo_resp = resp;
		ret = ioctl(hdl->kt_fd, KTEST_IOCTL_LIST_TESTS, &op);
	}
	if (ret == -1) {
		free(resp);
		return (NULL);
	}

	nvlist_t *tests = NULL;
	if ((ret = nvlist_unpack(resp, op.klo_resp_len, &tests, 0)) != 0) {
		free(resp);
		errno = ret;
		return (NULL);
	}
	free(resp);

	/*
	 * Verify that the response is marked with the expected serialization
	 * format. Remove the nvpair so that only the modules remain.
	 */
	uint64_t vsn = 0;
	if (nvlist_lookup_uint64(tests, KTEST_SER_FMT_KEY, &vsn) != 0 ||
	    vsn != KTEST_SER_FMT_VSN) {
		nvlist_free(tests);
		errno = EINVAL;
		return (NULL);
	}
	fnvlist_remove(tests, KTEST_SER_FMT_KEY);

	return (tests);
}

static void
ktest_iter_next_test(ktest_list_iter_t *iter, bool do_reset)
{
	if (iter->kli_test == NULL && !do_reset) {
		return;
	}
	if (iter->kli_tests == NULL) {
		return;
	}

	iter->kli_test = nvlist_next_nvpair(iter->kli_tests, iter->kli_test);
	while (iter->kli_test != NULL) {
		boolean_t requires_input;
		if (nvpair_type(iter->kli_test) == DATA_TYPE_NVLIST &&
		    nvlist_lookup_boolean_value(
		    fnvpair_value_nvlist(iter->kli_test), KTEST_TEST_INPUT_KEY,
		    &requires_input) == 0) {
			iter->kli_req_input = requires_input;
			break;
		}
		iter->kli_test =
		    nvlist_next_nvpair(iter->kli_tests, iter->kli_test);
	}
}

static void
ktest_iter_next_suite(ktest_list_iter_t *iter, bool do_reset)
{
	if (iter->kli_suite == NULL && !do_reset) {
		return;
	}
	if (iter->kli_suites == NULL) {
		return;
	}

	iter->kli_suite = nvlist_next_nvpair(iter->kli_suites, iter->kli_suite);
	iter->kli_tests = NULL;
	iter->kli_test = NULL;
	while (iter->kli_suite != NULL) {
		if (nvpair_type(iter->kli_suite) == DATA_TYPE_NVLIST &&
		    nvlist_lookup_nvlist(fnvpair_value_nvlist(iter->kli_suite),
		    KTEST_SUITE_TESTS_KEY, &iter->kli_tests) == 0) {
			break;
		}

		iter->kli_suite = nvlist_next_nvpair(iter->kli_suites,
		    iter->kli_suite);
	}

	ktest_iter_next_test(iter, true);
}

static void
ktest_iter_next_module(ktest_list_iter_t *iter, bool do_reset)
{
	if (iter->kli_module == NULL && !do_reset) {
		return;
	}
	VERIFY(iter->kli_modules != NULL);

	iter->kli_module = nvlist_next_nvpair(iter->kli_modules,
	    iter->kli_module);
	iter->kli_suites = NULL;
	iter->kli_suite = NULL;

	while (iter->kli_module != NULL) {
		if (nvpair_type(iter->kli_module) == DATA_TYPE_NVLIST &&
		    nvlist_lookup_nvlist(fnvpair_value_nvlist(iter->kli_module),
		    KTEST_MODULE_SUITES_KEY, &iter->kli_suites) == 0) {
			break;
		}

		iter->kli_module =
		    nvlist_next_nvpair(iter->kli_modules, iter->kli_module);
	}

	ktest_iter_next_suite(iter, true);
}

/*
 * List currently available ktests.
 *
 * Returns test list iterator on success, otherwise NULL (setting errno).
 */
ktest_list_iter_t *
ktest_list(ktest_hdl_t *hdl)
{
	nvlist_t *tests = ktest_query_tests(hdl);

	if (tests == NULL) {
		return (NULL);
	}

	ktest_list_iter_t *iter = malloc(sizeof (ktest_list_iter_t));
	if (iter == NULL) {
		const int err = errno;
		nvlist_free(tests);
		errno = err;
		return (NULL);
	}

	iter->kli_hdl = hdl;
	iter->kli_modules = tests;
	iter->kli_module = NULL;
	ktest_iter_next_module(iter, true);

	return (iter);
}

/*
 * Get the next ktest entry from a test list iterator.
 *
 * Returns true an item was available from the iterator (populating entry),
 * otherwise false.
 */
bool
ktest_list_next(ktest_list_iter_t *iter, ktest_entry_t *entry)
{
	while (iter->kli_module != NULL) {
		if (iter->kli_test != NULL) {
			/*
			 * Output the current test, and move iterator to the
			 * next in preparation for a subsequent call.
			 */
			entry->ke_module = nvpair_name(iter->kli_module);
			entry->ke_suite = nvpair_name(iter->kli_suite);
			entry->ke_test = nvpair_name(iter->kli_test);
			entry->ke_requires_input = iter->kli_req_input;
			ktest_iter_next_test(iter, false);
			return (true);
		}

		ktest_iter_next_suite(iter, false);
		if (iter->kli_suite != NULL) {
			continue;
		}
		ktest_iter_next_module(iter, false);
	}
	return (false);
}

/*
 * Reset ktest list iterator to its beginning.
 */
void
ktest_list_reset(ktest_list_iter_t *iter)
{
	iter->kli_module = NULL;
	ktest_iter_next_module(iter, true);
}

/*
 * Free a ktest list iterator.
 */
void
ktest_list_free(ktest_list_iter_t *iter)
{
	if (iter == NULL) {
		return;
	}
	iter->kli_test = iter->kli_suite = iter->kli_module = NULL;
	if (iter->kli_modules != NULL) {
		nvlist_free(iter->kli_modules);
		iter->kli_modules = NULL;
	}
	free(iter);
}

/*
 * Run a ktest.
 *
 * Requests that the ktest module run a ktest specified by module/suite/test
 * triple in the ktest_run_req_t.  If the test requires input, that too is
 * expected to be set in the run request.
 *
 * If the test was able to be run (regardless of its actual result), and the
 * emitted results data processed, ktest_run() will return true.  Any message
 * output from the test will be placed in krr_msg, which the caller is
 * responsible for free()-ing.
 *
 * If an error was encountered while attempting to run the test, or process its
 * results, ktest_run() will return false, and the ktest_run_result_t will not
 * be populated.
 */
bool
ktest_run(ktest_hdl_t *hdl, const ktest_run_req_t *req, ktest_run_result_t *res)
{
	ktest_run_op_t kro = {
		.kro_input_bytes = req->krq_input,
		.kro_input_len = req->krq_input_len,
	};

	(void) strncpy(kro.kro_module, req->krq_module,
	    sizeof (kro.kro_module));
	(void) strncpy(kro.kro_suite, req->krq_suite, sizeof (kro.kro_suite));
	(void) strncpy(kro.kro_test, req->krq_test, sizeof (kro.kro_test));

	if (ioctl(hdl->kt_fd, KTEST_IOCTL_RUN_TEST, &kro) == -1) {
		return (false);
	}

	const ktest_result_t *kres = &kro.kro_result;
	res->krr_code = (ktest_code_t)kres->kr_type;
	res->krr_line = (uint_t)kres->kr_line;

	const size_t msg_len =
	    strnlen(kres->kr_msg_prepend, sizeof (kres->kr_msg_prepend)) +
	    strnlen(kres->kr_msg, sizeof (kres->kr_msg));

	if (msg_len != 0) {
		if (asprintf(&res->krr_msg, "%s%s", kres->kr_msg_prepend,
		    kres->kr_msg) == -1) {
			return (false);
		}
	} else {
		res->krr_msg = NULL;
	}

	return (true);
}


/*
 * Get the string name for a ktest_code_t.
 */
const char *
ktest_code_name(ktest_code_t code)
{
	switch (code) {
	case KTEST_CODE_NONE:
		return ("NONE");
	case KTEST_CODE_PASS:
		return ("PASS");
	case KTEST_CODE_FAIL:
		return ("FAIL");
	case KTEST_CODE_SKIP:
		return ("SKIP");
	case KTEST_CODE_ERROR:
		return ("ERROR");
	default:
		break;
	}
	const char errmsg[] = "unexpected ktest_code value";
	upanic(errmsg, sizeof (errmsg));
}

#define	KTEST_MODULE_SUFFIX	"_ktest"
#define	KTEST_BASE_MODULE_DIR	"/usr/kernel/misc/ktest"

static char *ktest_cached_module_dir;

static const char *
ktest_mod_directory(void)
{
	if (ktest_cached_module_dir != NULL) {
		return (ktest_cached_module_dir);
	}

	char archbuf[20];
	if (sysinfo(SI_ARCHITECTURE_64, archbuf, sizeof (archbuf)) < 0) {
		return (NULL);
	}

	char *path = NULL;
	if (asprintf(&path, "%s/%s", KTEST_BASE_MODULE_DIR, archbuf) < 0) {
		return (NULL);
	}

	char *old = atomic_cas_ptr(&ktest_cached_module_dir, NULL, path);
	if (old == NULL) {
		return (path);
	} else {
		free(path);
		return (ktest_cached_module_dir);
	}
}

static bool
ktest_mod_path(const char *name, char *buf)
{
	const char *base = ktest_mod_directory();
	if (base == NULL) {
		return (false);
	}

	(void) snprintf(buf, MAXPATHLEN, "%s/%s" KTEST_MODULE_SUFFIX, base,
	    name);
	return (true);
}

static int
ktest_mod_id_for_name(const char *name)
{
	struct modinfo modinfo = {
		.mi_info = MI_INFO_ONE | MI_INFO_BY_NAME,
	};
	(void) snprintf(modinfo.mi_name, sizeof (modinfo.mi_name),
	    "%s" KTEST_MODULE_SUFFIX, name);

	if (modctl(MODINFO, 0, &modinfo) < 0) {
		return (-1);
	}
	return (modinfo.mi_id);
}

/*
 * Attempt to load a test module.
 *
 * Returns true if a ktests for the module could be loaded (or were already so),
 * otherwise false (setting errno).
 */
bool
ktest_mod_load(const char *name)
{
	if (ktest_mod_id_for_name(name) > 0) {
		/* Module is already loaded */
		return (true);
	}

	char path[MAXPATHLEN];
	if (!ktest_mod_path(name, path)) {
		return (false);
	}

	int id = 0;
	if (modctl(MODLOAD, 0, path, &id) != 0) {
		return (false);
	}
	return (true);
}

/*
 * Attempt to unload a test module.
 */
void
ktest_mod_unload(const char *name)
{
	const int id = ktest_mod_id_for_name(name);
	if (id > 0) {
		(void) modctl(MODUNLOAD, id);
	}
}

static bool
ktest_mod_for_each(void (*cb)(const char *))
{
	const char *dpath;

	if ((dpath = ktest_mod_directory()) == NULL) {
		return (false);
	}

	DIR *dp = opendir(dpath);
	if (dp == NULL) {
		return (false);
	}
	struct dirent *de;
	while ((de = readdir(dp)) != NULL) {
		char *suffix = strrchr(de->d_name, '_');

		if (suffix == NULL ||
		    strcmp(suffix, KTEST_MODULE_SUFFIX) != 0) {
			continue;
		}
		/*
		 * Drop the suffix from the name, and confirm that it is
		 * appropriately sized for a module.
		 */
		*suffix = '\0';
		const size_t name_sz = strnlen(de->d_name, MODMAXNAMELEN);
		if (name_sz == 0 || name_sz >= MODMAXNAMELEN) {
			continue;
		}

		/* Execute on valid candidate */
		cb(de->d_name);
	}
	return (true);
}

static void
ktest_mod_load_cb(const char *name)
{
	(void) ktest_mod_load(name);
}

/*
 * Attempt to load all known test modules.
 *
 * Returns true if the modules could be found in their expected directory, and
 * all were loaded successfully, otherwise false (setting errno).  In the case
 * of error, some modules may have been loaded.
 */
bool
ktest_mod_load_all(void)
{
	return (ktest_mod_for_each(ktest_mod_load_cb));
}

static void
ktest_mod_unload_cb(const char *name)
{
	ktest_mod_unload(name);
}

/*
 * Attempt to unload all known test modules.
 *
 * Returns true if the test modules could be iterated over, and unload
 * operations attempted.  A false result (with its accompanying errno) indicates
 * a problem reading the directory in which the tests reside.
 */
bool
ktest_mod_unload_all(void)
{
	return (ktest_mod_for_each(ktest_mod_unload_cb));
}

/*
 * Query the max input data size (in bytes) which can be provided to a test.
 */
size_t
ktest_max_input_size(void)
{
	return (KTEST_IOCTL_MAX_LEN);
}
