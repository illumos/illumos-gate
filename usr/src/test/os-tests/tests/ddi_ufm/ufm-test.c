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
 * Copyright 2019 Joyent, Inc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libnvpair.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>
#include <sys/debug.h>
#include <sys/ddi_ufm.h>
#include <sys/types.h>
#include <sys/varargs.h>

#include "ufmtest.h"

#define	ERRNO_ANY	-1
#define	UFMTEST_DEV	"/pseudo/ufmtest@0"

static const char *pname;

struct ufm_test_state {
	uint_t		ufts_n_run;
	uint_t		ufts_n_passes;
	uint_t		ufts_n_fails;
	int		ufts_ufm_fd;
	int		ufts_ufmtest_fd;
};

#define	MAX_IMAGES	5
#define	MAX_SLOTS	5
#define	MAX_STR		128
struct ufm_test_slot_data {
	const char			us_vers[MAX_STR];
	int				us_attrs;
	int				us_nmisc;
};

struct ufm_test_img_data {
	const char			ui_desc[MAX_STR];
	int				ui_nslots;
	int				ui_nmisc;
	struct ufm_test_slot_data	ui_slots[MAX_SLOTS];
};

struct ufm_test_data {
	uint_t				ud_nimages;
	struct ufm_test_img_data	ud_images[MAX_IMAGES];
};

#define	NO_SLOT	{"", -1, -1}
#define	NO_IMG	{"", -1, -1, {NO_SLOT, NO_SLOT, NO_SLOT, NO_SLOT, NO_SLOT}}

/*
 * 3 images w\
 * - 1 slot
 * - 2 slots (1st active)
 * - 3 slots (1st active, 3rd empty)
 */
const struct ufm_test_data fw_data1 = {
	3,
	{
	{"fw image 1", 1, 0, {
	{"1.0", 4, 0 }, NO_SLOT, NO_SLOT, NO_SLOT, NO_SLOT }},
	{"fw image 2", 2, 0, {
	{"1.0", 4, 0 }, {"1.1", 0, 0}, NO_SLOT, NO_SLOT, NO_SLOT }},
	{"fw image 3", 3, 0, {
	{"1.0", 4, 0 }, {"1.1", 0, 0}, {"", 8, 0}, NO_SLOT, NO_SLOT }},
	NO_IMG,
	NO_IMG
	}
};

/*
 * Generate an ISO 8601 timestamp
 */
static void
get_timestamp(char *buf, size_t bufsize)
{
	time_t utc_time;
	struct tm *p_tm;

	(void) time(&utc_time);
	p_tm = localtime(&utc_time);

	(void) strftime(buf, bufsize, "%FT%TZ", p_tm);
}

/* PRINTFLIKE1 */
static void
logmsg(const char *format, ...)
{
	char timestamp[128];
	va_list ap;

	get_timestamp(timestamp, sizeof (timestamp));
	(void) fprintf(stdout, "%s ", timestamp);
	va_start(ap, format);
	(void) vfprintf(stdout, format, ap);
	va_end(ap);
	(void) fprintf(stdout, "\n");
	(void) fflush(stdout);
}

static int
do_test_setup(struct ufm_test_state *tst_state)
{
	if ((tst_state->ufts_ufm_fd = open(DDI_UFM_DEV, O_RDONLY)) < 0) {
		logmsg("failed to open %s (%s)", DDI_UFM_DEV,
		    strerror(errno));
		return (-1);
	}
	if ((tst_state->ufts_ufmtest_fd = open("/dev/ufmtest", O_RDONLY)) < 0) {
		logmsg("failed to open /dev/ufmtest (%s)",
		    strerror(errno));
		return (0);
	}
	return (0);
}

static void
free_nvlist_arr(nvlist_t **nvlarr, uint_t nelems)
{
	for (uint_t i = 0; i < nelems; i++) {
		if (nvlarr[i] != NULL)
			nvlist_free(nvlarr[i]);
	}
	free(nvlarr);
}

static int
do_setfw(struct ufm_test_state *tst_state, const struct ufm_test_data *fwdata)
{
	ufmtest_ioc_setfw_t ioc = { 0 };
	nvlist_t *nvl = NULL, **images = NULL, **slots = NULL;
	int ret = -1;

	if ((images = calloc(sizeof (nvlist_t *), fwdata->ud_nimages)) == NULL)
		return (-1);

	for (uint_t i = 0; i < fwdata->ud_nimages; i++) {
		if (nvlist_alloc(&images[i], NV_UNIQUE_NAME, 0) != 0 ||
		    nvlist_add_string(images[i], DDI_UFM_NV_IMAGE_DESC,
		    fwdata->ud_images[i].ui_desc) != 0) {
			goto out;
		}
		if ((slots = calloc(sizeof (nvlist_t *),
		    fwdata->ud_images[i].ui_nslots)) == NULL) {
			goto out;
		}

		for (int s = 0; s < fwdata->ud_images[i].ui_nslots; s++) {
			if (nvlist_alloc(&slots[s], NV_UNIQUE_NAME, 0) != 0 ||
			    nvlist_add_string(slots[s], DDI_UFM_NV_SLOT_VERSION,
			    fwdata->ud_images[i].ui_slots[s].us_vers) != 0 ||
			    nvlist_add_uint32(slots[s], DDI_UFM_NV_SLOT_ATTR,
			    fwdata->ud_images[i].ui_slots[s].us_attrs) != 0) {

				free_nvlist_arr(slots,
				    fwdata->ud_images[i].ui_nslots);
				goto out;
			}
		}

		if (nvlist_add_nvlist_array(images[i], DDI_UFM_NV_IMAGE_SLOTS,
		    slots, fwdata->ud_images[i].ui_nslots) != 0) {
			free_nvlist_arr(slots, fwdata->ud_images[i].ui_nslots);
			goto out;
		}
		free_nvlist_arr(slots, fwdata->ud_images[i].ui_nslots);
	}
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_add_nvlist_array(nvl, DDI_UFM_NV_IMAGES, images,
	    fwdata->ud_nimages) != 0) {
		goto out;
	}

	if (nvlist_size(nvl, &ioc.utsw_bufsz, NV_ENCODE_NATIVE) != 0 ||
	    (ioc.utsw_buf = malloc(ioc.utsw_bufsz)) == NULL ||
	    nvlist_pack(nvl, &ioc.utsw_buf, &ioc.utsw_bufsz, NV_ENCODE_NATIVE,
	    0) != 0) {
		goto out;
	}

	if (ioctl(tst_state->ufts_ufmtest_fd, UFMTEST_IOC_SET_FW, &ioc) < 0) {
		logmsg("UFMTEST_IOC_SET_FW ioctl failed (%s)",
		    strerror(errno));
		return (-1);
	}
	ret = 0;
out:
	free_nvlist_arr(images, fwdata->ud_nimages);
	nvlist_free(nvl);
	free(ioc.utsw_buf);

	return (ret);
}

static int
do_toggle_fails(struct ufm_test_state *tst_state, uint32_t fail_flags)
{
	ufmtest_ioc_fails_t ioc = { 0 };

	ioc.utfa_flags = fail_flags;

	if (ioctl(tst_state->ufts_ufmtest_fd, UFMTEST_IOC_TOGGLE_FAILS,
	    &ioc) < 0) {
		logmsg("UFMTEST_IOC_TOGGLE_FAILS ioctl failed (%s)",
		    strerror(errno));
		return (1);
	}
	return (0);
}

static int
do_update(struct ufm_test_state *tst_state)
{
	if (ioctl(tst_state->ufts_ufmtest_fd, UFMTEST_IOC_DO_UPDATE,
	    NULL) < 0) {
		logmsg("UFMTEST_IOC_DO_UPDATE ioctl failed (%s)",
		    strerror(errno));
		return (1);
	}
	return (0);
}

static int
try_open(int oflag, int exp_errno)
{
	int fd;

	fd = open(DDI_UFM_DEV, oflag);
	if (fd != -1) {
		logmsg("FAIL: expected open(2) to return -1");
		(void) close(fd);
		return (-1);
	}
	if (errno != exp_errno) {
		logmsg("FAIL: expected errno to be set to %u (%s)\n"
		    "actual errno was %u (%s)", exp_errno, strerror(exp_errno),
		    errno, strerror(errno));
		return (-1);
	}
	return (0);
}

static void
do_negative_open_tests(struct ufm_test_state *tst_state)
{
	/*
	 * Assertion: Opening /dev/ufm in write-only mode will fail with errno
	 * set to EINVAL;
	 */
	logmsg("TEST ufm_open_negative_001: Open %s in write-only mode",
	    DDI_UFM_DEV);
	if (try_open(O_WRONLY, EINVAL) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	/*
	 * Assertion: Opening /dev/ufm in read-write mode will fail with errno
	 * set to EINVAL;
	 */
	logmsg("TEST ufm_open_negative_002: Open %s in read-write mode",
	    DDI_UFM_DEV);
	if (try_open(O_RDWR, EINVAL) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	/*
	 * Assertion: Opening /dev/ufm in exclusive mode will fail with errno
	 * set to EINVAL;
	 */
	logmsg("TEST ufm_open_negative_003: Open %s in exclusive mode",
	    DDI_UFM_DEV);
	if (try_open(O_RDONLY | O_EXCL, EINVAL) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	/*
	 * Assertion: Opening /dev/ufm in non-blocking mode will fail with errno
	 * set to EINVAL;
	 */
	logmsg("TEST ufm_open_negative_004: Open %s in non-block mode",
	    DDI_UFM_DEV);
	if (try_open(O_RDONLY | O_NONBLOCK, EINVAL) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	/*
	 * Assertion: Opening /dev/ufm in no-delay mode will fail with errno
	 * set to EINVAL;
	 */
	logmsg("TEST ufm_open_negative_005: Open %s in ndelay mode",
	    DDI_UFM_DEV);
	if (try_open(O_RDONLY | O_NDELAY, EINVAL) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;
}


static int
try_ioctl(int fd, int cmd, void *arg, int exp_errno)
{
	int ret;

	ret = ioctl(fd, cmd, arg);
	if (ret != -1) {
		logmsg("FAIL: expected ioctl(2) to return -1");
		(void) close(fd);
		return (-1);
	}
	if (exp_errno != ERRNO_ANY && errno != exp_errno) {
		logmsg("FAIL: expected errno to be set to %u (%s)\n"
		    "actual errno was %u (%s)", exp_errno, strerror(exp_errno),
		    errno, strerror(errno));
		return (-1);
	}
	return (0);
}

/*
 * These are a set of negative test cases to verify the correctness and
 * robustness of the DDI UFM ioctl interface.
 */
static void
do_negative_ioctl_tests(struct ufm_test_state *tst_state)
{
	ufm_ioc_getcaps_t ugc = { 0 };
	ufm_ioc_bufsz_t ubz = { 0 };
	ufm_ioc_report_t urep = { 0 };
	size_t reportsz;
	char *buf;
	uint_t i, j;

	uint8_t not_ascii[MAXPATHLEN];
	char no_nul[MAXPATHLEN];

	for (uint_t i = 0; i < MAXPATHLEN; i++)
		no_nul[i] = '%';

	CTASSERT(MAXPATHLEN > 129);
	for (i = 0, j = 128; j <= 256; i++, j++)
		not_ascii[i] = j;

	not_ascii[i] = '\0';

	/*
	 * Seed the test driver with a set of valid firmware data
	 */
	if (do_setfw(tst_state, &fw_data1) != 0) {
		logmsg("Failed to seed ufmtest driver with fw data");
		return;
	}

	/*
	 * Cache the report size, and create a buffer of that size,
	 * as we'll need them for some of the tests that follow.
	 */
	ubz.ufbz_version = DDI_UFM_CURRENT_VERSION;
	(void) strlcpy(ubz.ufbz_devpath, UFMTEST_DEV, MAXPATHLEN);
	if (ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORTSZ, &ubz) < 0) {
		logmsg("Failed to get fw data report size");
		return;
	}
	reportsz = ubz.ufbz_size;
	if ((buf = malloc(reportsz)) == NULL) {
		logmsg("Failed to allocate %u bytes to hold report");
		return;
	}

	/*
	 * Assertion: Specifying a DDI UFM version that is out of range in the
	 * argument to UFM_IOC_GETCAPS will fail and set errno to ENOTSUP.
	 */
	logmsg("TEST ufm_getcaps_negative_001: Bad DDI UFM version (too low)");
	ugc.ufmg_version = 0;
	(void) strlcpy(ugc.ufmg_devpath, UFMTEST_DEV, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_GETCAPS, &ugc,
	    ENOTSUP) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	logmsg("TEST ufm_getcaps_negative_002: Bad DDI UFM version (too high)");
	ugc.ufmg_version = 999;
	(void) strlcpy(ugc.ufmg_devpath, UFMTEST_DEV, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_GETCAPS, &ugc,
	    ENOTSUP) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	/*
	 * Assertion: Specifying a bad device pathname in the argument to
	 * UFM_IOC_GETCAPS will cause the ioctl to fail, but the driver will
	 * not hang or panic.
	 */
	logmsg("TEST ufm_getcaps_negative_003: Bad devpath (empty)");
	ugc.ufmg_version = DDI_UFM_CURRENT_VERSION;
	ugc.ufmg_devpath[0] = '\0';
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_GETCAPS, &ugc,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	logmsg("TEST ufm_getcaps_negative_004: Bad devpath (not a device)");
	(void) strlcpy(ugc.ufmg_devpath, "/usr/bin/ls", MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_GETCAPS, &ugc,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	logmsg("TEST ufm_getcaps_negative_005: Bad devpath (not UFM device)");
	(void) strlcpy(ugc.ufmg_devpath, "/dev/stdout", MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_GETCAPS, &ugc,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	logmsg("TEST ufm_getcaps_negative_006: Bad devpath (no NUL term)");
	(void) strncpy(ugc.ufmg_devpath, no_nul, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_GETCAPS, &ugc,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	logmsg("TEST ufm_getcaps_negative_007: Bad devpath (not ascii str)");
	(void) strlcpy(ugc.ufmg_devpath, (char *)not_ascii, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_GETCAPS, &ugc,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	/*
	 * Assertion: Specifying a DDI UFM version that is out of range in the
	 * argument to UFM_IOC_REPORTSZ will fail and set errno to ENOTSUP.
	 */
	logmsg("TEST ufm_reportsz_negative_001: Bad DDI UFM version (too low)");
	ubz.ufbz_version = 0;
	(void) strlcpy(ubz.ufbz_devpath, UFMTEST_DEV, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORTSZ, &ubz,
	    ENOTSUP) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	logmsg("TEST ufm_reportsz_negative_002: Bad DDI UFM version (too "
	    "high)");
	ubz.ufbz_version = 999;
	(void) strlcpy(ubz.ufbz_devpath, UFMTEST_DEV, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORTSZ, &ubz,
	    ENOTSUP) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	/*
	 * Assertion: Specifying a bad device pathname in the argument to
	 * UFM_IOC_REPORTSZ will cause the ioctl to fail, but the driver will
	 * not hang or panic.
	 */
	logmsg("TEST ufm_reportsz_negative_003: Bad devpath (empty)");
	ubz.ufbz_version = DDI_UFM_CURRENT_VERSION;
	ubz.ufbz_devpath[0] = '\0';
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORTSZ, &ubz,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	logmsg("TEST ufm_reportsz_negative_004: Bad devpath (not a device)");
	ubz.ufbz_version = DDI_UFM_CURRENT_VERSION;
	(void) strlcpy(ubz.ufbz_devpath, "/usr/bin/ls", MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORTSZ, &ubz,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	logmsg("TEST ufm_reportsz_negative_005: Bad devpath (not UFM device)");
	ubz.ufbz_version = DDI_UFM_CURRENT_VERSION;
	(void) strlcpy(ubz.ufbz_devpath, "/dev/stdout", MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORTSZ, &ubz,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	logmsg("TEST ufm_reportsz_negative_006: Bad devpath (no NUL term)");
	ubz.ufbz_version = DDI_UFM_CURRENT_VERSION;
	(void) strncpy(ubz.ufbz_devpath, no_nul, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORTSZ, &ubz,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	logmsg("TEST ufm_reportsz_negative_007: Bad devpath (not ascii str)");
	ubz.ufbz_version = DDI_UFM_CURRENT_VERSION;
	(void) strlcpy(ubz.ufbz_devpath, (char *)not_ascii, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORTSZ, &ubz,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	/*
	 * Assertion: Specifying a DDI UFM version that is out of range in the
	 * argument to UFM_IOC_REPORT will fail and set errno to ENOTSUP.
	 */
	logmsg("TEST ufm_report_negative_001: Bad DDI UFM version (too low)");
	urep.ufmr_version = 0;
	urep.ufmr_bufsz = reportsz;
	urep.ufmr_buf = buf;
	(void) strlcpy(urep.ufmr_devpath, UFMTEST_DEV, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORT, &urep,
	    ENOTSUP) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	logmsg("TEST ufm_report_negative_002: Bad DDI UFM version (too high)");
	urep.ufmr_version = 999;
	urep.ufmr_bufsz = reportsz;
	urep.ufmr_buf = buf;
	(void) strlcpy(urep.ufmr_devpath, UFMTEST_DEV, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORT, &urep,
	    ENOTSUP) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	/*
	 * Assertion: Specifying a bad device pathname in the argument to
	 * UFM_IOC_REPORT will cause the ioctl to fail, but the driver will
	 * not hang or panic.
	 */
	logmsg("TEST ufm_report_negative_003: Bad devpath (empty)");
	urep.ufmr_version = DDI_UFM_CURRENT_VERSION;
	urep.ufmr_bufsz = reportsz;
	urep.ufmr_buf = buf;
	urep.ufmr_devpath[0] = '\0';
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORT, &urep,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	logmsg("TEST ufm_report_negative_004: Bad devpath (not a device)");
	urep.ufmr_version = DDI_UFM_CURRENT_VERSION;
	urep.ufmr_bufsz = reportsz;
	urep.ufmr_buf = buf;
	(void) strlcpy(urep.ufmr_devpath, "/usr/bin/ls", MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORT, &urep,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	logmsg("TEST ufm_report_negative_005: Bad devpath (not UFM device)");
	urep.ufmr_version = DDI_UFM_CURRENT_VERSION;
	urep.ufmr_bufsz = reportsz;
	urep.ufmr_buf = buf;
	(void) strlcpy(urep.ufmr_devpath, "/dev/stdout", MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORT, &urep,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	logmsg("TEST ufm_report_negative_006: Bad devpath (no NUL term)");
	urep.ufmr_version = DDI_UFM_CURRENT_VERSION;
	urep.ufmr_bufsz = reportsz;
	urep.ufmr_buf = buf;
	(void) strncpy(urep.ufmr_devpath, no_nul, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORT, &urep,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	logmsg("TEST ufm_report_negative_007: Bad devpath (not ascii str)");
	urep.ufmr_version = DDI_UFM_CURRENT_VERSION;
	urep.ufmr_bufsz = reportsz;
	urep.ufmr_buf = buf;
	(void) strlcpy(urep.ufmr_devpath, (char *)not_ascii, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORT, &urep,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	/*
	 * Assertion: Passing a bufsz that is too small to the UFM_IOC_REPORT
	 * ioctl will cause the ioctl to fail, but the driver will not hang or
	 * panic.
	 */
	logmsg("TEST ufm_report_negative_008: bad bufsz (too small)");
	urep.ufmr_version = DDI_UFM_CURRENT_VERSION;
	urep.ufmr_bufsz = 10;
	urep.ufmr_buf = buf;
	(void) strlcpy(urep.ufmr_devpath, UFMTEST_DEV, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORT, &urep,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	/*
	 * Assertion: Passing a bufsz that is too small to the UFM_IOC_REPORT
	 * ioctl will cause the ioctl to fail, but the driver will not hang or
	 * panic.
	 */
	logmsg("TEST ufm_report_negative_009: bad buf (NULL pointer)");
	urep.ufmr_version = DDI_UFM_CURRENT_VERSION;
	urep.ufmr_bufsz = 10;
	urep.ufmr_buf = NULL;
	(void) strlcpy(urep.ufmr_devpath, UFMTEST_DEV, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORT, &urep,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;
}

/*
 * These are a set of negative test cases to verify the correctness and
 * robustness of the DDI UFM subsystems when a driver UFM callback returns
 * an error.
 *
 * For each callback, we do the following:
 *
 * 1. Toggle the callback failure via a UFMTEST_IOC_TOGGLE_FAILS ioctl
 * 2. Force a ddi_ufm_update() via a UFMTEST_IOC_DO_UPDATE ioctl.  This is
 *    done in order to invalidate any cached firmware data for this device.
 * 3. Call UFM_IOC_REPORTSZ ioctl to force the ufm_cache_fill() codepath to
 *    be executed.
 */
static void
do_negative_callback_tests(struct ufm_test_state *tst_state)
{
	ufm_ioc_getcaps_t ugc = { 0 };
	ufm_ioc_bufsz_t ubz = { 0 };
	uint32_t failflags;
	boolean_t failed;

	/*
	 * Seed the test driver with a set of valid firmware data
	 */
	if (do_setfw(tst_state, &fw_data1) != 0) {
		logmsg("Failed to seed ufmtest driver with fw data");
		return;
	}

	/*
	 * Assertion: If a driver's ddi_ufm_op_getcaps callback returns a
	 * failure, the kernel should not hang or panic when servicing a
	 * UFM_IOC_REPORTSZ ioctl.  Furthermore, the UFM_IOC_REPORTSZ ioctl
	 * should fail.
	 */
	logmsg("TEST ufm_callback_negative_001: ddi_ufm_op_getcaps fails");
	failed = B_FALSE;
	failflags = UFMTEST_FAIL_GETCAPS;
	if (do_toggle_fails(tst_state, failflags) != 0 ||
	    do_update(tst_state) != 0) {
		failed = B_TRUE;
	}

	ubz.ufbz_version = DDI_UFM_CURRENT_VERSION;
	(void) strlcpy(ubz.ufbz_devpath, UFMTEST_DEV, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORTSZ, &ubz,
	    ERRNO_ANY) != 0)
		failed = B_TRUE;

	if (failed)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	/*
	 * Assertion: If a driver's ddi_ufm_op_getcaps callback returns a
	 * failure, the kernel should not hang or panic when servicing a
	 * UFM_IOC_GETCAPS ioctl for that device.  Furthermore, the
	 * UFM_IOC_GETCAPS ioctl should fail.
	 */
	logmsg("TEST ufm_callback_negative_002: ddi_ufm_op_getcaps fails");
	failed = B_FALSE;
	ugc.ufmg_version = DDI_UFM_CURRENT_VERSION;
	(void) strlcpy(ugc.ufmg_devpath, UFMTEST_DEV, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_GETCAPS, &ugc,
	    ERRNO_ANY) != 0)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	/*
	 * Assertion: If a driver's ddi_ufm_op_nimages callback returns a
	 * failure, the kernel should not hang or panic when servicing a
	 * UFM_IOC_REPORTSZ ioctl.  Furthermore, the UFM_IOC_REPORTSZ ioctl
	 * should fail.
	 */
	logmsg("TEST ufm_callback_negative_003: ddi_ufm_op_nimages fails");
	failed = B_FALSE;
	failflags = UFMTEST_FAIL_NIMAGES;
	if (do_toggle_fails(tst_state, failflags) != 0 ||
	    do_update(tst_state) != 0) {
		failed = B_TRUE;
	}

	ubz.ufbz_version = DDI_UFM_CURRENT_VERSION;
	(void) strlcpy(ubz.ufbz_devpath, UFMTEST_DEV, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORTSZ, &ubz,
	    ERRNO_ANY) != 0)
		failed = B_TRUE;

	if (failed)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	/*
	 * Assertion: If a driver's ddi_ufm_op_fill_image callback returns a
	 * failure, the kernel should not hang or panic when servicing a
	 * UFM_IOC_REPORTSZ ioctl.  Furthermore, the UFM_IOC_REPORTSZ ioctl
	 * should fail.
	 */
	logmsg("TEST ufm_callback_negative_004: ddi_ufm_op_fill_image fails");
	failed = B_FALSE;
	failflags = UFMTEST_FAIL_FILLIMAGE;
	if (do_toggle_fails(tst_state, failflags) != 0 ||
	    do_update(tst_state) != 0) {
		failed = B_TRUE;
	}

	ubz.ufbz_version = DDI_UFM_CURRENT_VERSION;
	(void) strlcpy(ubz.ufbz_devpath, UFMTEST_DEV, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORTSZ, &ubz,
	    ERRNO_ANY) != 0)
		failed = B_TRUE;

	if (failed)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	/*
	 * Assertion: If a driver's ddi_ufm_op_fill_slot callback returns a
	 * failure, the kernel should not hang or panic when servicing a
	 * UFM_IOC_REPORTSZ ioctl.  Furthermore, the UFM_IOC_REPORTSZ ioctl
	 * should fail.
	 */
	logmsg("TEST ufm_callback_negative_005: ddi_ufm_op_fill_slot fails");
	failed = B_FALSE;
	failflags = UFMTEST_FAIL_FILLSLOT;
	if (do_toggle_fails(tst_state, failflags) != 0 ||
	    do_update(tst_state) != 0) {
		failed = B_TRUE;
	}

	ubz.ufbz_version = DDI_UFM_CURRENT_VERSION;
	(void) strlcpy(ubz.ufbz_devpath, UFMTEST_DEV, MAXPATHLEN);
	if (try_ioctl(tst_state->ufts_ufm_fd, UFM_IOC_REPORTSZ, &ubz,
	    ERRNO_ANY) != 0)
		failed = B_TRUE;

	if (failed)
		tst_state->ufts_n_fails++;
	else
		tst_state->ufts_n_passes++;

	tst_state->ufts_n_run++;

	/* Unset the fail flags */
	failflags = 0;
	if (do_toggle_fails(tst_state, failflags) != 0)
		logmsg("Failed to clear fail flags");
}

int
main(int argc, char **argv)
{
	int status = EXIT_FAILURE;
	struct ufm_test_state tst_state = { 0 };

	pname = argv[0];

	if (do_test_setup(&tst_state) != 0) {
		logmsg("Test setup failed - exiting");
		return (status);
	}

	do_negative_open_tests(&tst_state);

	if (tst_state.ufts_ufmtest_fd > 0) {
		do_negative_ioctl_tests(&tst_state);
		do_negative_callback_tests(&tst_state);
	}

	logmsg("Number of Tests Run: %u", tst_state.ufts_n_run);
	logmsg("Number of Passes:    %u", tst_state.ufts_n_passes);
	logmsg("Number of Fails :    %u", tst_state.ufts_n_fails);
	if (tst_state.ufts_n_fails == 0)
		status = EXIT_SUCCESS;

	(void) close(tst_state.ufts_ufm_fd);
	if (tst_state.ufts_ufmtest_fd >= 0)
		(void) close(tst_state.ufts_ufmtest_fd);
	return (status);
}
