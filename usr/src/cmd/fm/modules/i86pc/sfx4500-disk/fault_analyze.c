/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/byteorder.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <utility.h>

#include "util.h"
#include "sfx4500-disk.h"

/*
 * The functions defined below are used to query SCSI (or SCSI-like)
 * disk devices for their Information Exceptions (IE) page via LOG SENSE.
 * SATA disks in Solaris implement command translation that transforms
 * the SATA SMART information into the appropriate IE page data.
 *
 * The general algorithm for determining if a disk has detected an imminent
 * failure via the IE mechanism is as follows:
 *
 * STEP 1 - INITIALIZATION
 * 1) Check to see if the IE mechanism is enabled via MODE SENSE for the
 *    IE Control page (page 0x1C), checking the DEXCPT field (1 = IE is
 *    disabled).  If it is enabled, goto step 3; else if there was an error
 *    getting the mode page, abort IE processing, otherwise, continue to
 *    step 2.
 * 2) Enable the IE mechanism by sending a MODE SELECT for page 0x1C
 *    with the DEXCPT = 0, PERF = 1, MRIE = 6, EWASC = 1, TEST = 0,
 *    REPORT COUNT = 0001h, LOGERR = 1 (enable IE, minimize delay associated
 *    with SMART processing, only report IE condition on request,
 *    enable warnings, testing disabled, limit to 1 the number
 *    of times to report each IE, and enable logging of errors).
 * 3) Check to see if the IE log page is supported by issuing a LOG
 *    SENSE with page == 0x2F.  If the page list returned includes the
 *    IE page, examine the log page and ensure that the parameter 0 length
 *    is at least 4 (some drives that are pre-SCSI3 return smaller lengths
 *    with non-sensical values for parameter 0).
 *    Check for the IBM extensions to the IE log page (the first byte of the
 *    vendor-specific area is non-zero if the temperature is present).
 *    and make a note of it.
 *    If there is no support for the IE Log page, we can still check SMART
 *    status by issuing a REQUEST SENSE by itself (since that's how we
 *    configured the MRIE field in the IE Control mode page).  The presence
 *    of the IE log page makes life easier by aggregating almost all the
 *    information we need (the ASC/ASCQ of the predictive failure mode and
 *    the temperature information).
 * 4) Check for self-test logs by issuing a LOG SENSE for page 0x10 and
 *    examining the returned page.  If the page makes sense, make a note
 *    of it.
 * 5) Check for a temperature log page.  If it exists, make a note of it.
 *    (Prefer the temperature log page for monitoring because the SCSI-3 spec
 *    specifies an optional threshold temperature parameter (and most
 *    drives that support the temperature log page include the threshold).
 *    [Relying on the IE Log page for temperature constraint information
 *    is not reliable because the threshold information in the IE log
 *    page is an IBM extension and is not present on all drives.  Plus,
 *    not many drives actually implement the IE log page.)]
 * 6) Clear the GLTSD bit in Control mode page 0xA.  This will allow the
 *    drive to save each of the log pages described above to nonvolatile
 *    storage.  This is essential if the drive is to remember its failures
 *    across power-offs (it would be very bad for a previously-bad drive to
 *    go through another set of failures, just to recognize its badness after
 *    a power cycle).  If the MODE SELECT for this operation fails, issue a
 *    warning, but continue anyway.
 *
 * STEP 2 - MONITORING
 * 1) To determine if a predictable failure is imminent, either send the
 *    device an unsolicited REQUEST SENSE command or a LOG SENSE for the
 *    Informational Exceptions page, and use the sense information from
 *    either of the sources to determine if a failure is imminent.
 *    (SK=NO SENSE/ASC=0x5D/ASCQ=[0..0x6C] (real impending failures) or
 *    SK=NO SENSE/ASC=0x5D/ASCQ=0xFF (FALSE impending failure)).
 * 2) If self-test logs are present, check them.  If a self-test occurred
 *    since the last time the monitoring function was called, check to see its
 *    results.  If there was a self-test failure, a self-test failure is
 *    returned.
 * 3) Based on the available temperature information from the drive (either
 *    from the temperature log page or from the temperature information
 *    available on the IE page), determine if the drive has exceeded its
 *    maximum operating temperature.  If so, a drive over-temp failure is
 *    returned.  (If the drive is within 5% of its maximum operating
 *    temperature, return a warning).  If there is no threshold, use the
 *    threshold value passed in.
 *
 */

#define	RQBUF_LEN 255	/* Length of the request-sense buffer (max) */

static int logpage_ie_param_verify(diskmon_t *diskinfop,
    struct log_parameter_header *lphp);
static int logpage_temp_param_verify(diskmon_t *diskinfop,
    struct log_parameter_header *lphp);
static int logpage_selftest_param_verify(diskmon_t *diskinfop,
    struct log_parameter_header *lphp);

static int logpage_ie_param_analyze(diskmon_t *diskinfop,
    struct log_parameter_header *lphp);
static int logpage_temp_param_analyze(diskmon_t *diskinfop,
    struct log_parameter_header *lphp);
static int logpage_selftest_param_analyze(diskmon_t *diskinfop,
    struct log_parameter_header *lphp);


static struct logpage_validation_entry logpage_validation_list[] = {
	{ LOGPAGE_IE,		LOGPAGE_SUPP_IE,	PC_CUMULATIVE,
	    "Informational Exceptions",	B_TRUE,
	    logpage_ie_param_verify, logpage_ie_param_analyze		},

	{ LOGPAGE_TEMP,		LOGPAGE_SUPP_TEMP,	PC_CUMULATIVE,
	    "Temperature",		B_TRUE,
	    logpage_temp_param_verify, logpage_temp_param_analyze	},

	{ LOGPAGE_SELFTEST,	LOGPAGE_SUPP_SELFTEST,	PC_CUMULATIVE,
	    "Self-test",		B_TRUE,
	    logpage_selftest_param_verify, logpage_selftest_param_analyze },

	{ 0xFF,			0,			0,
	    NULL,			B_FALSE,
	    NULL,		NULL					}
};

static char *
dm_get_disk_logphys(diskmon_t *diskp, int *buflen)
{
	char *path, *sep;

	path = (char *)dm_prop_lookup(diskp->props, DISK_PROP_LOGNAME);
	if (path != NULL) {
		*buflen = strlen(path) + 1;
		return (dstrdup(path));
	}

	path = (char *)dm_prop_lookup(diskp->props, DISK_PROP_DEVPATH);

	assert(path != NULL);

	*buflen = strlen(path) + 1;
	path = dstrdup(path);

	if ((sep = strchr(path, DEVPATH_MINOR_SEPARATOR)) != NULL)
		*sep = 0;

	return (path);
}

static void
disk_err(diskmon_t *diskinfop, const char *fmt, ...)
{
	va_list ap;
	char *path;
	int pathlen;

	path = dm_get_disk_logphys(diskinfop, &pathlen);

	log_msg(MM_ERR|MM_SCSI, "ERROR: Disk %s (location: %s): ",
	    path,
	    diskinfop->location);

	va_start(ap, fmt);
	vcont(MM_ERR|MM_SCSI, fmt, ap);
	va_end(ap);

	dfree(path, pathlen);
}

static void
disk_warn(diskmon_t *diskinfop, const char *fmt, ...)
{
	va_list ap;
	char *path;
	int pathlen;

	path = dm_get_disk_logphys(diskinfop, &pathlen);

	log_msg(MM_WARN|MM_SCSI, "WARNING: Disk %s (location: %s): ",
	    path,
	    diskinfop->location);

	va_start(ap, fmt);
	vcont(MM_WARN|MM_SCSI, fmt, ap);
	va_end(ap);

	dfree(path, pathlen);
}

static void
disk_note(diskmon_t *diskinfop, const char *fmt, ...)
{
	va_list ap;
	char *path;
	int pathlen;

	path = dm_get_disk_logphys(diskinfop, &pathlen);

	log_msg(MM_SCSI, "NOTICE: Disk %s (location: %s): ",
	    path,
	    diskinfop->location);

	va_start(ap, fmt);
	vcont(MM_SCSI, fmt, ap);
	va_end(ap);

	dfree(path, pathlen);
}

static int
disk_mode_select(int cdb_len, int fd, uchar_t page_code, int options,
    void *buf, uint_t buflen, struct scsi_ms_hdrs *headers, uint_t *skp,
    uint_t *ascp, uint_t *ascqp)
{
	int result;
	struct scsi_extended_sense sense;
	int senselen = sizeof (struct scsi_extended_sense);
	struct mode_page *mp = (struct mode_page *)buf;

	assert(cdb_len == MODE_CMD_LEN_6 || cdb_len == MODE_CMD_LEN_10);
	assert(headers->length == cdb_len);

	bzero(&sense, sizeof (struct scsi_extended_sense));

	if (mp->ps) {
		options |= MODE_SELECT_SP;
		mp->ps = 0;
	} else
		options &= ~MODE_SELECT_SP;


	if (cdb_len == MODE_CMD_LEN_6) {

		/* The following fields are reserved during mode select: */
		headers->h.g0.mode_header.length = 0;
		headers->h.g0.mode_header.device_specific = 0;

		result = uscsi_mode_select(fd, page_code, options, buf,
		    buflen, &headers->h.g0, &sense, &senselen);

	} else if (cdb_len == MODE_CMD_LEN_10) {

		/* The following fields are reserved during mode select: */
		headers->h.g1.mode_header.length = 0;
		headers->h.g1.mode_header.device_specific = 0;

		result = uscsi_mode_select_10(fd, page_code, options, buf,
		    buflen, &headers->h.g1, &sense, &senselen);
	}

	if (result != 0)
		scsi_translate_error(&sense, skp, ascp, ascqp);

	return (result);
}

static int
disk_mode_sense(int cdb_len, int fd, uchar_t page_code, uchar_t pc,
    void *buf, uint_t buflen, struct scsi_ms_hdrs *headers, uint_t *skp,
    uint_t *ascp, uint_t *ascqp)
{
	int result;
	struct scsi_extended_sense sense;
	int senselen = sizeof (struct scsi_extended_sense);

	assert(cdb_len == MODE_CMD_LEN_6 || cdb_len == MODE_CMD_LEN_10);

	bzero(&sense, sizeof (struct scsi_extended_sense));

	(void) memset(headers, 0, sizeof (struct scsi_ms_hdrs));
	headers->length = cdb_len;

	if (cdb_len == MODE_CMD_LEN_6) {
		result = uscsi_mode_sense(fd, page_code, pc, buf, buflen,
		    &headers->h.g0, &sense, &senselen);
	} else if (cdb_len == MODE_CMD_LEN_10) {
		result = uscsi_mode_sense_10(fd, page_code, pc, buf, buflen,
		    &headers->h.g1, &sense, &senselen);
	}

	if (result != 0)
		scsi_translate_error(&sense, skp, ascp, ascqp);

	return (result);
}

static int
disk_request_sense(int fd, uint_t *skp, uint_t *ascp, uint_t *ascqp)
{
	struct scsi_extended_sense sense, sensebuf;
	int senselen = sizeof (struct scsi_extended_sense);
	int sensebuflen = sizeof (struct scsi_extended_sense);
	int result;

	bzero(&sense, sizeof (struct scsi_extended_sense));
	bzero(&sensebuf, sizeof (struct scsi_extended_sense));

	result = uscsi_request_sense(fd, (caddr_t)&sensebuf, sensebuflen,
	    &sense, &senselen);

	if (result == 0)
		scsi_translate_error(&sensebuf, skp, ascp, ascqp);
	else
		scsi_translate_error(&sense, skp, ascp, ascqp);

	return (result);
}

static int
scsi_enable_ie(int fd, diskmon_t *diskinfop, uint_t *skp, uint_t *ascp,
    uint_t *ascqp, int test_mode, int perf_mode, boolean_t *changed)
{
	struct info_except_page	new_iec_page;
	struct scsi_ms_hdrs hdrs;
	fault_monitor_info_t *fip = diskinfop->fmip;
	int result;

	bzero(&new_iec_page, sizeof (struct info_except_page));
	bzero(&hdrs, sizeof (struct scsi_ms_hdrs));

	(void) memcpy(&new_iec_page, &fip->iec_current,
	    sizeof (struct info_except_page));

	/*
	 * Enable IE reporting:
	 *
	 * (1) DEXCPT = 0
	 * (2) PERF = <as passed in> (minimize delay due to IE processing)
	 * (3) MRIE = 6 (IE_REPORT_ON_REQUEST)
	 * (4) EWASC = 1
	 * (5) TEST = <as passed in>
	 * (6) REPORT COUNT = 0x0001
	 * (7) LOGERR = 1
	 *
	 */

	new_iec_page.dexcpt = 0;
	new_iec_page.mrie = IE_REPORT_ON_REQUEST;

	if (IEC_PERF_CHANGEABLE(fip->iec_changeable))
		new_iec_page.perf = perf_mode ? 1 : 0;

	if (IEC_EWASC_CHANGEABLE(fip->iec_changeable))
		new_iec_page.ewasc = 1;

	if (IEC_TEST_CHANGEABLE(fip->iec_changeable))
		new_iec_page.test = test_mode ? 1 : 0;

	if (IEC_RPTCNT_CHANGEABLE(fip->iec_changeable))
		new_iec_page.report_count = BE_32(1);

	if (IEC_LOGERR_CHANGEABLE(fip->iec_changeable))
		new_iec_page.logerr = 1;

	/*
	 * Now compare the new mode page with the existing one.
	 * if there's no difference, there's no need for a mode select
	 */
	if (memcmp(&new_iec_page, &fip->iec_current,
	    MODEPAGE_INFO_EXCPT_LEN) == 0) {
		*changed = B_FALSE;
		result = 0;
	} else {

		(void) memcpy(&hdrs, &fip->hdrs, sizeof (struct scsi_ms_hdrs));

		if ((result = disk_mode_select(fip->mode_length, fd,
		    MODEPAGE_INFO_EXCPT, MODE_SELECT_PF, &new_iec_page,
		    MODEPAGE_INFO_EXCPT_LEN, &hdrs, skp, ascp, ascqp)) == 0) {

			*changed = B_TRUE;
		}
	}

	return (result);
}

static boolean_t
modepagelist_find(uchar_t *pgdata, uint_t pgdatalen, uchar_t pagecode)
{
	uint_t i = 0;
	struct mode_page *pg;
	boolean_t found = B_FALSE;

	/*
	 * The mode page list contains all mode pages supported by
	 * the device, one after the other.  Since the pages have headers
	 * that describe the page code and their length, we can use pointer
	 * arithmetic to hop to the next page.
	 */
	while (i < pgdatalen) {
		pg = (struct mode_page *)&pgdata[i];

		if (pg->code == pagecode) {
			found = B_TRUE;
			break;
		}

		i += MODESENSE_PAGE_LEN(pg);
	}

	return (found);
}

/*
 * Figure out which MODE SENSE/SELECT to use (the 6-byte or 10-byte
 * version) by executing a MODE SENSE command for a page that should be
 * implemented by the lun.  If the lun doesn't support the Return All Pages
 * mode page (0x3F), then that information is returned as an invalid field in
 * cdb error.  This function updates the diskinfo structure with the command
 * length that's supported.
 */
static int
modepages_init(int fd, diskmon_t *diskinfop, uint_t *skeyp,
    uint_t *ascp, uint_t *ascqp)
{
	/*
	 * allpages_buflen is USHRT_MAX - size of the header because some luns
	 * return nothing if the buffer length is too big -- it must be sized
	 * properly (the maximum buffer size is therefore the maximum that
	 * will fit in a 16-bit integer minus the size of the header.)
	 */
	int allpages_buflen = USHRT_MAX - sizeof (struct scsi_ms_header_g1);
	uchar_t *allpages = (uchar_t *)dzmalloc(allpages_buflen);
	fault_monitor_info_t *fip = diskinfop->fmip;
	struct scsi_ms_header smh;
	struct scsi_ms_header_g1 smh_g1;
	struct scsi_extended_sense sense;
	int resid;
	int result;
	uint_t sk, a, aq;
	uint_t datalength = 0;

	bzero(&smh, sizeof (struct scsi_ms_header));
	bzero(&smh_g1, sizeof (struct scsi_ms_header_g1));
	bzero(&sense, sizeof (struct scsi_extended_sense));

	/*
	 * Attempt a mode sense(6).  If that fails, try a mode sense(10)
	 *
	 * allpages is allocated to be of the maximum size for either a
	 * mode sense(6) or mode sense(10) MODEPAGE_ALLPAGES response.
	 *
	 * Note that the length passed into uscsi_mode_sense should be
	 * set to the maximum size of the parameter response, which in
	 * this case is UCHAR_MAX - the size of the headers/block descriptors.
	 *
	 */

	resid = sizeof (struct scsi_extended_sense);
	if ((result = uscsi_mode_sense(fd, MODEPAGE_ALLPAGES, PC_CURRENT,
	    (caddr_t)allpages, UCHAR_MAX - sizeof (struct scsi_ms_header),
	    &smh, &sense, &resid)) == 0) {

		fip->mode_length = MODE_CMD_LEN_6;

		/*
		 * Compute the data length of the page that contains all
		 * mode sense pages.  This is a bit tricky because the
		 * format of the response from the lun is:
		 *
		 * header: <length> <medium type byte> <dev specific byte>
		 *	   <block descriptor length>
		 *	   [<optional block descriptor>]
		 * data:   [<mode page data> <mode page data> ...]
		 *
		 * Since the length field in the header describes the
		 * length of the entire response (including the header,
		 * but NOT including itself (1 or 2 bytes depending on
		 * which mode sense type (6- or 10- byte) being executed).
		 *
		 * So, the data length equals the length value in the header
		 * plus 1 (because the length byte was not included in the
		 * length count), minus [[the sum of the length of the
		 * header and the length of the block descriptor]].
		 */

		datalength = (smh.mode_header.length +
		    sizeof (smh.mode_header.length)) -
			(sizeof (struct mode_header) +
				smh.mode_header.bdesc_length);

	} else {
		scsi_translate_error(&sense, &sk, &a, &aq);
		if (SCSI_INVALID_OPCODE(sk, a, aq)) {

			resid = sizeof (struct scsi_extended_sense);
			result = uscsi_mode_sense_10(fd, MODEPAGE_ALLPAGES,
			    PC_CURRENT, (caddr_t)allpages, allpages_buflen,
			    &smh_g1, &sense, &resid);

			if (result == 0) {
				fip->mode_length = MODE_CMD_LEN_10;

				datalength =
				    (BE_16(smh_g1.mode_header.length) +
					sizeof (smh_g1.mode_header.length)) -
				    (sizeof (struct mode_header_g1) +
					BE_16(smh_g1.mode_header.bdesc_length));

			} else
				fip->mode_length = MODE_CMD_LEN_UNKNOWN;
		}
	}

	if (result == 0) {

		/*
		 * One of the sets of the commands (above) succeeded, so now
		 * look for the mode pages we need and record them appropriately
		 */

		if (modepagelist_find(allpages, datalength,
		    MODEPAGE_INFO_EXCPT))
			fip->mode_pages_supported |= MODEPAGE_SUPP_IEC;

	} else /* result != 0 */
		scsi_translate_error(&sense, skeyp, ascp, ascqp);

	dfree(allpages, allpages_buflen);
	return (result);
}

static int
load_iec_modepages(int fd, diskmon_t *diskinfop, uint_t *skeyp,
    uint_t *ascp, uint_t *ascqp)
{
	fault_monitor_info_t *fip = diskinfop->fmip;
	struct scsi_ms_hdrs junk_hdrs;
	int result;

	(void) memset(&fip->iec_current, 0,
	    sizeof (struct info_except_page));
	(void) memset(&fip->iec_changeable, 0,
	    sizeof (struct info_except_page));

	if ((result = disk_mode_sense(fip->mode_length, fd,
	    MODEPAGE_INFO_EXCPT, PC_CURRENT, &fip->iec_current,
	    MODEPAGE_INFO_EXCPT_LEN, &fip->hdrs, skeyp, ascp, ascqp))
	    == 0) {

		result = disk_mode_sense(fip->mode_length, fd,
		    MODEPAGE_INFO_EXCPT, PC_CHANGEABLE,
		    &fip->iec_changeable,
		    MODEPAGE_INFO_EXCPT_LEN, &junk_hdrs, skeyp, ascp, ascqp);
	}

	return (result);
}

static int
clear_gltsd(int fd, diskmon_t *diskinfop, uint_t *skp, uint_t *ascp,
    uint_t *ascqp)
{
	fault_monitor_info_t *fip = diskinfop->fmip;
	struct scsi_ms_hdrs hdrs, junk_hdrs;
	struct mode_control_scsi3 control_pg_cur, control_pg_chg;
	int result;

	bzero(&hdrs, sizeof (struct scsi_ms_hdrs));
	bzero(&control_pg_cur, sizeof (struct mode_control_scsi3));
	bzero(&control_pg_chg, sizeof (struct mode_control_scsi3));

	result = disk_mode_sense(fip->mode_length, fd,
	    MODEPAGE_CTRL_MODE, PC_CURRENT, &control_pg_cur,
	    MODEPAGE_CTRL_MODE_LEN, &hdrs, skp, ascp, ascqp);

	if (result != 0) {

		disk_note(diskinfop, "Mode sense failed for the "
		    "current Control mode page -- skipping GLTSD "
		    "initialization.\n");

	} else if (control_pg_cur.mode_page.length !=
	    PAGELENGTH_MODE_CONTROL_SCSI3) {

		disk_note(diskinfop, "Disk does not support SCSI-3 "
		    "Control mode page -- skipping GLTSD "
		    "initialization.\n");

	} else if ((result = disk_mode_sense(fip->mode_length, fd,
	    MODEPAGE_CTRL_MODE, PC_CHANGEABLE, &control_pg_chg,
	    MODEPAGE_CTRL_MODE_LEN, &junk_hdrs, skp, ascp, ascqp))
	    != 0) {

		disk_note(diskinfop, "Mode sense failed for the "
		    "changeable Control mode page -- skipping GLTSD "
		    "initialization.\n");

	} else if (control_pg_cur.gltsd && !GLTSD_CHANGEABLE(control_pg_chg)) {

		disk_note(diskinfop, "GLTSD is set and is not "
		    "changeable. This disk will not save log "
		    "parameters implicitly.\n");

	} else if (control_pg_cur.gltsd) {
		control_pg_cur.gltsd = 0;
		result = disk_mode_select(fip->mode_length, fd,
		    MODEPAGE_CTRL_MODE, MODE_SELECT_PF, &control_pg_cur,
		    MODEPAGE_CTRL_MODE_LEN, &hdrs, skp, ascp, ascqp);
	}

	return (result);
}

static int
ie_enable_and_save(int fd, diskmon_t *diskinfop, uint_t *skp,
    uint_t *ascp, uint_t *ascqp, int test_mode, int perf_mode)
{
	fault_monitor_info_t *fip = diskinfop->fmip;
	int return_code = IE_SUCCESS;
	boolean_t changed;

	/*
	 * Now that we know we can execute a valid mode sense command
	 * (and that the IE control mode page is supported), load the IEC page
	 * so we can check is IE is disabled.  If it is disabled and it's
	 * NOT changeable, then we can't do anything else here.
	 */
	if (load_iec_modepages(fd, diskinfop, skp, ascp, ascqp) != 0) {

		/*
		 * Something went wrong when grabbing the IEC mode page,
		 * so bail out.
		 */

		return_code = IE_OTHER_ERROR;

	} else if ((!IEC_IE_ENABLED(fip->iec_current) &&
	    !IEC_IE_CHANGEABLE(fip->iec_changeable)) ||
	    (fip->iec_current.mrie != IE_REPORT_ON_REQUEST &&
	    !IEC_MRIE_CHANGEABLE(fip->iec_changeable))) {

		/*
		 * We need to be able to change the IE disable bit if
		 * IEs are currently disabled.  We also need to be able to
		 * change the MRIE bits if they're not set to the right values,
		 * so if we can't enable IEs properly, we're done here.
		 */
		return_code = IE_CANNOT_BE_ENABLED;

	} else if (scsi_enable_ie(fd, diskinfop, skp, ascp, ascqp,
	    test_mode, perf_mode, &changed) != 0) {

		return_code = IE_ENABLE_FAILED;

	} else if (changed && load_iec_modepages(fd, diskinfop, skp, ascp,
	    ascqp) != 0) {

		/*
		 * Something went wrong when grabbing the IEC mode page (again),
		 * so bail out.
		 */

		return_code = IE_OTHER_ERROR;

	} else if (!IEC_IE_ENABLED(fip->iec_current)) {

		return_code = IE_ENABLE_DIDNT_STICK;

	} else if (clear_gltsd(fd, diskinfop, skp, ascp, ascqp) != 0) {

		/*
		 * NOTE: Failed to clear the GLTSD bit in the control page;
		 * it's OK if the asc/ascq indicates invalid field in cdb,
		 * meaning this disk doesn't support the GLTSD flag.
		 */
		if (*ascp != ASC_INVALID_CDB_FIELD)
			disk_note(diskinfop, "Could not clear the GLTSD bit "
			    "[KEY=0x%x   ASC=0x%x   ASCQ=0x%x].  Disk "
			    "failures may not be recognized after a power "
			    "cycle.\n", *skp, *ascp, *ascqp);
	}

	if (return_code == IE_SUCCESS) {
		/* Save the update interval */
		fip->update_interval =
		    BE_32(fip->iec_current.interval_timer);
	}

	return (return_code);
}

static int
log_page_to_supp_bit(uchar_t logpage)
{
	int i;

	for (i = 0; logpage_validation_list[i].analyze_fn != NULL; i++) {
		if (logpage_validation_list[i].logpage_code == logpage)
			return (logpage_validation_list[i].supp_bit);
	}

	return (0);
}


static logpage_validation_fn_t
lookup_logpage_validation_fn(uchar_t logpage_code)
{
	int i;

	for (i = 0; logpage_validation_list[i].analyze_fn != NULL; i++) {
		if (logpage_validation_list[i].logpage_code == logpage_code)
			return (logpage_validation_list[i].validate_fn);
	}

	return (NULL);
}

static logpage_analyze_fn_t
lookup_logpage_analyze_fn(uchar_t logpage_code)
{
	int i;

	for (i = 0; logpage_validation_list[i].analyze_fn != NULL; i++) {
		if (logpage_validation_list[i].logpage_code == logpage_code)
			return (logpage_validation_list[i].analyze_fn);
	}

	return (NULL);
}

static uchar_t
logpage_pc_for_verify(uchar_t logpage_code)
{
	int i;

	for (i = 0; logpage_validation_list[i].analyze_fn != NULL; i++) {
		if (logpage_validation_list[i].logpage_code == logpage_code)
			return (logpage_validation_list[i].pc);
	}

	/* If no PC is specifically defined for this page code, use current */
	return (PC_CURRENT);
}

static int
supported_log_pages(int fd, diskmon_t *diskinfop, uint_t *skp,
    uint_t *ascp, uint_t *ascqp)
{
	/*
	 * buflen is USHRT_MAX - size of the header because some luns
	 * return nothing if the buffer length is too big -- it must be sized
	 * properly (the maximum buffer size is therefore the maximum that
	 * will fit in a 16-bit integer minus the size of the header.)
	 */
	int buflen = USHRT_MAX - sizeof (struct log_header);
	struct supported_log_pages *sp = dzmalloc(buflen);
	struct scsi_extended_sense sense;
	int resid = sizeof (struct scsi_extended_sense);
	fault_monitor_info_t *fip = diskinfop->fmip;
	int result;
	int bitset;

	bzero(&sense, sizeof (struct scsi_extended_sense));

	if ((result = uscsi_log_sense(fd, LOGPAGE_SUPP_LIST, PC_CUMULATIVE,
	    (caddr_t)sp, buflen, &sense, &resid)) == 0) {

		int pagecount = BE_16(sp->hdr.length);
		int i = 0;

		while (i < pagecount) {

			bitset = log_page_to_supp_bit(sp->pages[i]);

			fip->log_pages_supported |= bitset;

			i++;
		}
	}

	dfree(sp, buflen);
	if (result != 0)
		scsi_translate_error(&sense, skp, ascp, ascqp);
	return (result);
}

static int
logpage_ie_param_verify(diskmon_t *diskinfop, struct log_parameter_header *lphp)
{
	fault_monitor_info_t *fip = diskinfop->fmip;
	struct info_excpt_log_param *iep;
	int result = 0;

	iep = (struct info_excpt_log_param *)lphp;

	/*
	 * Ensure that parameter code 0 has a length of
	 * at LEAST 4 as per the SCSI SPC3 spec.  If it
	 * does not, don't use this log page (its format
	 * is unknown).
	 */
	if (BE_16(lphp->param_code) == LOGPARAM_IE) {
		if (lphp->length < LOGPARAM_IE_MIN_LEN) {

			disk_note(diskinfop, "IE log page format is unknown -- "
			    "not using it.\n");

			result = -1;

		} else if (lphp->length > LOGPARAM_IE_WITH_TEMP_MIN_LEN) {

			/*
			 * Determine if the vendor-specific area lists a
			 * temperature threshold
			 */
			if (iep->ex_temp_threshold != 0)
				fip->extensions |= EXTN_IE_TEMP_THRESHOLD;
		}
	}

	return (result);
}

static int
logpage_temp_param_verify(diskmon_t *diskinfop,
    struct log_parameter_header *lphp)
{
	int result = 0;
	fault_monitor_info_t *fip = diskinfop->fmip;
	ushort_t param_code = BE_16(lphp->param_code);
	struct temperature_log_param_reftemp *rtp;

	/* The temperature log page has two parameter codes defined: 0 & 1 */
	/* 0 is current temperature, and 1 is the threshold (but is optional) */

	/*
	 * Don't compare the current temperature to 0xff; we don't flag that
	 * as an error now because the condition that caused the drive not to
	 * be able to report a temperature reading could be transitory.
	 */

	switch (param_code) {
	case LOGPARAM_TEMP_CURTEMP:
		if (lphp->length != LOGPARAM_TEMP_CURTEMP_LEN) {
			result = -1;
		}
		break;

	case LOGPARAM_TEMP_REFTEMP:
		rtp = (struct temperature_log_param_reftemp *)lphp;

		if (lphp->length != LOGPARAM_TEMP_REFTEMP_LEN) {
			result = -1;
		} else if (rtp->reference_temp != REFTEMP_INVALID) {
			fip->extensions |= EXTN_TEMPLOG_TEMP_THRESHOLD;
			fip->reference_temp = rtp->reference_temp;
		}
		break;
	}

	if (result < 0)
		disk_note(diskinfop, "Temperature log page format is unknown "
		    "-- not using it.\n");

	return (result);
}

static int
logpage_selftest_param_verify(diskmon_t *diskinfop,
    struct log_parameter_header *lphp)
{
	int result = 0;
	ushort_t param_code = BE_16(lphp->param_code);

	/* Parameter codes range from 0x01-0x14 */
	if (param_code < LOGPAGE_SELFTEST_MIN_PARAM_CODE ||
	    param_code > LOGPAGE_SELFTEST_MAX_PARAM_CODE) {

		result = -1;

	} else if (lphp->length != LOGPAGE_SELFTEST_PARAM_LEN) {

		disk_note(diskinfop, "Bad parameter length for self-test "
		    "parameter %d\n", lphp->param_code);

		result = -1;
	}

	return (result);
}

static fault_monitor_info_t *
new_disk_fault_info(void)
{
	int opts;
	fault_monitor_info_t *fmi =
	    (fault_monitor_info_t *)dzmalloc(sizeof (fault_monitor_info_t));

	/*
	 * This will always succeed.  See sfx4500-disk.c for the default values.
	 */
	(void) dm_prop_lookup_int(dm_global_proplist(),
	    GLOBAL_PROP_FAULT_OPTIONS, &opts);

	fmi->options = opts;

	assert(pthread_mutex_init(&fmi->fault_data_mutex, NULL) == 0);
	fmi->fault_list = NULL;

	return (fmi);
}

void
free_disk_fault_list(fault_monitor_info_t *fmip)
{
	struct disk_fault *cur, *next;

	cur = fmip->fault_list;

	while (cur != NULL) {
		next = cur->next;
		if (cur->msg != NULL)
			dstrfree(cur->msg);
		dfree(cur, sizeof (struct disk_fault));
		cur = next;
	}
	fmip->fault_list = NULL;
	fmip->disk_fault_srcs = DISK_FAULT_SOURCE_NONE;
}

static void
free_disk_fault_info(fault_monitor_info_t **fmipp)
{
	free_disk_fault_list(*fmipp);
	assert(pthread_mutex_destroy(&(*fmipp)->fault_data_mutex) == 0);
	dfree(*fmipp, sizeof (fault_monitor_info_t));
	*fmipp = NULL;
}

static void
add_disk_fault(diskmon_t *diskinfop, disk_flt_src_e fltsrc,
    const char *msg, uchar_t sensekey, uchar_t asc, uchar_t ascq,
    uint16_t selftestresultcode, int curtemp, int threshtemp)
{
	fault_monitor_info_t *fip = diskinfop->fmip;
	struct disk_fault *flt;
	struct disk_fault *newflt;

	/* Do not add duplicate faults */
	if (diskinfop->disk_faults & fltsrc ||
	    fip->disk_fault_srcs & fltsrc)
		return;

	newflt = (struct disk_fault *)
	    dzmalloc(sizeof (struct disk_fault));

	newflt->fault_src = fltsrc;
	/* If the message is NULL, look it up by asc/ascq */

	newflt->selftest_code = selftestresultcode;
	newflt->cur_temp = curtemp;
	newflt->thresh_temp = threshtemp;

	if (asc != 0 || ascq != 0) {
		newflt->sense_valid = B_TRUE;
		newflt->sense_key = sensekey;
		newflt->asc = asc;
		newflt->ascq = ascq;
		if (msg == NULL) {
			const char *scsi_msg = scsi_asc_ascq_string(asc, ascq);
			newflt->msg = (scsi_msg == NULL) ? NULL :
			    dstrdup(scsi_msg);
		} else
			newflt->msg = dstrdup(msg);
	} else {
		newflt->sense_valid = B_FALSE;
		newflt->msg = (msg == NULL) ? NULL : dstrdup(msg);
	}

	assert(pthread_mutex_lock(&fip->fault_data_mutex) == 0);
	fip->disk_fault_srcs |= fltsrc;

	if (fip->fault_list == NULL)
		fip->fault_list = newflt;
	else {
		flt = fip->fault_list;

		while (flt->next != NULL)
			flt = flt->next;

		flt->next = newflt;
	}
	assert(pthread_mutex_unlock(&fip->fault_data_mutex) == 0);
}

void
create_fake_faults(diskmon_t *diskp)
{
	add_disk_fault(diskp, DISK_FAULT_SOURCE_INFO_EXCPT,
	    "Fake SMART impending failure fault", 0,
	    0x5D /* IE Failure threshold exceeded */,
	    0xFF /* false positive */, 0, 0, 0);

	add_disk_fault(diskp, DISK_FAULT_SOURCE_SELFTEST,
	    "Fake self-test failure fault",
	    0, 0, 0, SELFTEST_FAILURE_SEG_FIRST, 0, 0);

	add_disk_fault(diskp, DISK_FAULT_SOURCE_OVERTEMP,
	    "Fake disk overtemp fault",
	    0,
	    0xb /* Warning */,
	    1 /* specified temperature exceeded */, 0,
	    0xff /* curtemp */, 0xfe /* threshold */);
}

static int
logpage_ie_param_analyze(diskmon_t *diskinfop,
    struct log_parameter_header *lphp)
{
	fault_monitor_info_t *fip = diskinfop->fmip;
	struct info_excpt_log_param *iep;
	int result = 0;
	char buf[MSG_BUFLEN];
	ushort_t length = BE_16(lphp->length);

	iep = (struct info_excpt_log_param *)lphp;

	if (lphp->param_code == LOGPARAM_IE) {
		/*
		 * There are two faults that the IE parameter helps
		 * detect -- the general IE predictive failure, and
		 * an overtemp failure (but only if the temperature
		 * threshold information is included.
		 */
		if (iep->ie_asc != 0) {
			add_disk_fault(diskinfop, DISK_FAULT_SOURCE_INFO_EXCPT,
			    NULL, INVALID_SENSE_KEY, iep->ie_asc, iep->ie_ascq,
			    0, 0, 0);

			result = -1;
		}

		/*
		 * If the length of this parameter includes the temperature
		 * threshold, use it to compare the temperature, but only if
		 * there is no temperature log page supported (or, if there
		 * is a temperature log page but no reference temperature in
		 * the temperature log page).
		 */

		if ((!LOG_PAGE_SUPPORTED(fip, LOGPAGE_SUPP_TEMP) ||
		    !EXTN_SUPPORTED(fip, EXTN_TEMPLOG_TEMP_THRESHOLD)) &&
		    (length > LOGPARAM_IE_WITH_TEMP_MIN_LEN) &&
		    (iep->ex_temp_threshold != 0) &&
		    (iep->ex_temp_threshold != INVALID_TEMPERATURE) &&
		    (iep->last_temp >= iep->ex_temp_threshold)) {

			(void) snprintf(buf, MSG_BUFLEN, "Disk temperature (%d "
			    "celsius) is above the threshold (%d celsius)",
			    iep->last_temp, iep->ex_temp_threshold);

			add_disk_fault(diskinfop, DISK_FAULT_SOURCE_OVERTEMP,
			    buf, INVALID_SENSE_KEY, 0, 0, 0, iep->last_temp,
			    iep->ex_temp_threshold);

			result = -1;
		}
	}

	return (result);
}

static int
logpage_temp_param_analyze(diskmon_t *diskinfop,
    struct log_parameter_header *lphp)
{
	char buf[MSG_BUFLEN];
	int result = 0;
	fault_monitor_info_t *fip = diskinfop->fmip;
	ushort_t param_code = BE_16(lphp->param_code);
	struct temperature_log_param_curtemp *ctp =
	    (struct temperature_log_param_curtemp *)lphp;

	/*
	 * If this log page has a reference temperature, it must have
	 * been recorded in the diskinfo structure, so use it
	 * to compare the current temperature reading (if the
	 * reading is valid).
	 */

	/* The temperature log page has two parameter codes defined: 0 & 1 */
	/* 0 is current temperature, and 1 is the threshold (but is optional) */

	/*
	 * Don't compare the current temperature to 0xff; we don't flag that
	 * as an error now because the condition that caused the drive not to
	 * be able to report a temperature reading could be transitory.
	 */

	if (param_code == LOGPARAM_TEMP_CURTEMP &&
	    ctp->current_temp != INVALID_TEMPERATURE &&
	    EXTN_SUPPORTED(fip, EXTN_TEMPLOG_TEMP_THRESHOLD) &&
	    ctp->current_temp >= fip->reference_temp) {

		(void) snprintf(buf, MSG_BUFLEN, "Disk temperature (%d "
		    "celsius) is above the threshold (%d celsius)",
		    ctp->current_temp, fip->reference_temp);

		add_disk_fault(diskinfop, DISK_FAULT_SOURCE_OVERTEMP,
		    buf, INVALID_SENSE_KEY, 0, 0, 0, ctp->current_temp,
		    fip->reference_temp);

		result = -1;
	}

	return (result);
}

static char *
disk_selftest_result_string(struct selftest_log_parameter *stlp, char *buf,
    int buflen)
{
	const char *s;

	switch (stlp->results) {
	case SELFTEST_FAILURE_INCOMPLETE:
		s = "An unknown error occurred while the "
		    "device server was processing the self-test "
		    "and the device server was unable to complete "
		    "the self-test.";
		(void) snprintf(buf, buflen, s);
		break;

	case SELFTEST_FAILURE_SEG_UNKNOWN:
		s = "The self-test completed with a failure in a test "
		    "segment, and the test segment that failed is not known.";
		(void) snprintf(buf, buflen, s);
		break;

	case SELFTEST_FAILURE_SEG_FIRST:
		s = "The first segment of the self-test failed.";
		(void) snprintf(buf, buflen, s);
		break;

	case SELFTEST_FAILURE_SEG_SECOND:
		s = "The second segment of the self-test failed.";
		(void) snprintf(buf, buflen, s);
		break;

	case SELFTEST_FAILURE_SEG_OTHER:
		/* If the test number was 0, the failure segment is unknown */
		if (stlp->test_number == 0)
			s = "The self-test failed in an unknown test segment.";
		else
			s = "The self-test failed in test segment %d.";
		(void) snprintf(buf, buflen, s, stlp->test_number);
		break;

	default:
		s = "Unknown self-test result code (0x%x (%d))";
		(void) snprintf(buf, buflen, s, stlp->results, stlp->results);
		break;
	}

	return (buf);
}

static int
logpage_selftest_param_analyze(diskmon_t *diskinfop,
    struct log_parameter_header *lphp)
{
	struct selftest_log_parameter *stlp =
	    (struct selftest_log_parameter *)lphp;
	int result = 0;
	const char *fmt;
	char buf[MSG_BUFLEN];
	char tsstring[MSG_BUFLEN];
	char lbastring[MSG_BUFLEN];
	char stcause[MSG_BUFLEN];
	ushort_t param_code = BE_16(lphp->param_code);

	/*
	 * If the self-test failed, log a fault.
	 */
	if (param_code >= LOGPAGE_SELFTEST_MIN_PARAM_CODE &&
	    param_code <= LOGPAGE_SELFTEST_MAX_PARAM_CODE &&
	    stlp->results >= SELFTEST_FAILURE_INCOMPLETE &&
	    stlp->results <= SELFTEST_FAILURE_SEG_OTHER) {

		uint16_t timestamp = BE_16(stlp->timestamp);
		uint64_t lbaaddr = BE_64(stlp->lba_of_first_failure);

		fmt = (timestamp == UINT16_MAX) ? ">= %u disk-hours" :
		    "%u disk-hours";
		(void) snprintf(tsstring, MSG_BUFLEN, fmt, timestamp);

		/* The lba failure field is only valid if it's not all 1's */
		fmt = (lbaaddr != UINT64_MAX) ? " LBA address of first "
		    "failure: 0x%llx (%llu)" : "";
		(void) snprintf(lbastring, MSG_BUFLEN, fmt, lbaaddr, lbaaddr);

		(void) snprintf(buf, MSG_BUFLEN, "Disk self-test failed "
		    "[self-test parameter #%d, time of failure: %s%s]: %s",
		    param_code, tsstring, lbastring,
		    disk_selftest_result_string(stlp, stcause, MSG_BUFLEN));

		add_disk_fault(diskinfop, DISK_FAULT_SOURCE_SELFTEST,
		    buf, stlp->sense_key, stlp->asc, stlp->ascq,
		    stlp->results, 0, 0);

		result = -1;
	}

	return (result);
}


static int
verify_logpage(uchar_t logpage_code, int fd, diskmon_t *diskinfop,
    uint_t *skp, uint_t *ascp, uint_t *ascqp)
{
	fault_monitor_info_t *fip = diskinfop->fmip;
	struct log_header 		*lhp;
	struct log_parameter_header 	*lphp;
	struct scsi_extended_sense	sense;
	logpage_validation_fn_t		validate_fn;
	int				buflen;
	int				resid;
	int				log_length;
	int				result		= 0;
	int				i		= 0;
	int				this_param_len	= 0;

	/*
	 * buflen is USHRT_MAX - size of the header because some luns
	 * return nothing if the buffer length is too big -- it must be sized
	 * properly (the maximum buffer size is therefore the maximum that
	 * will fit in a 16-bit integer minus the size of the header.)
	 */
	buflen = USHRT_MAX - sizeof (struct log_header);
	resid = sizeof (struct scsi_extended_sense);
	lhp = dzmalloc(buflen);
	validate_fn = lookup_logpage_validation_fn(logpage_code);
	bzero(&sense, sizeof (struct scsi_extended_sense));

	if ((validate_fn != NULL) &&
	    ((result = uscsi_log_sense(fd, logpage_code,
	    logpage_pc_for_verify(logpage_code),
	    (caddr_t)lhp, buflen, &sense, &resid)) == 0) &&
	    ((log_length = BE_16(lhp->length)) > 0)) {

		lphp = (struct log_parameter_header *)(((uchar_t *)lhp) +
		    sizeof (struct log_header));

		while (i < log_length) {

			lphp = (struct log_parameter_header *)
			    (((uchar_t *)lphp) + this_param_len);

			/*
			 * If the validation fn returns a negative value,
			 * that's the signal to clear the supported bit
			 * for this log page and break out of the loop.
			 */
			if ((*validate_fn)(diskinfop, lphp) < 0) {
				fip->log_pages_supported &=
				    ~log_page_to_supp_bit(logpage_code);
				break;
			}

			this_param_len = lphp->length +
			    sizeof (struct log_parameter_header);

			i += this_param_len;
		}
	}

	dfree(lhp, buflen);
	if (result != 0)
		scsi_translate_error(&sense, skp, ascp, ascqp);
	return (result);
}

static int
verify_logpages(int fd, diskmon_t *diskinfop, uint_t *skp,
    uint_t *ascp, uint_t *ascqp)
{
	fault_monitor_info_t *fip = diskinfop->fmip;
	int result = 0;
	int i;

	for (i = 0; logpage_validation_list[i].analyze_fn != NULL; i++) {

		if ((fip->log_pages_supported &
		    logpage_validation_list[i].supp_bit) == 0) {

			continue;
		}

		/*
		 * verify_logpage will clear the bit from
		 * log_pages_supported if verification fails
		 * (which means that the page is not usable)
		 */
		if (verify_logpage(logpage_validation_list[i].logpage_code,
		    fd, diskinfop, skp, ascp, ascqp) != 0) {
			/*
			 * If something goes wrong here, this is not a fatal
			 * error -- just log the error and continue.
			 */
			log_warn("Error during %s log page verification: "
			    "KEY=0x%x   ASC=0x%x   ASCQ=0x%x",
			    logpage_validation_list[i].descr, *skp, *ascp,
			    *ascqp);

			result -= 1;
		}
	}

	return (result);
}

/*
 * This function calls the analysis function that corresponds to the log page
 * passed-in.  If the analysis function detects a fault in the log page
 * parameter it was called with, it fills-in the disk_fault structure passed-in
 * with the fault specifics, and log parameter processing stops.
 */
static int
fault_analyze_logpage(uchar_t logpage_code, int fd, diskmon_t *diskinfop,
    uint_t *skp, uint_t *ascp, uint_t *ascqp)
{
	struct log_header 		*lhp;
	struct log_parameter_header 	*lphp;
	struct scsi_extended_sense	sense;
	logpage_analyze_fn_t		analyze_fn;
	int				buflen;
	int				resid;
	int				log_length;
	int				result		= 0;
	int				i		= 0;
	int				this_param_len	= 0;

	/*
	 * buflen is USHRT_MAX - size of the header because some luns
	 * return nothing if the buffer length is too big -- it must be sized
	 * properly (the maximum buffer size is therefore the maximum that
	 * will fit in a 16-bit integer minus the size of the header.)
	 */
	buflen = USHRT_MAX - sizeof (struct log_header);
	resid = sizeof (struct scsi_extended_sense);
	lhp = dzmalloc(buflen);
	analyze_fn = lookup_logpage_analyze_fn(logpage_code);
	bzero(&sense, sizeof (struct scsi_extended_sense));

	if ((analyze_fn != NULL) &&
	    ((result = uscsi_log_sense(fd, logpage_code,
	    logpage_pc_for_verify(logpage_code),
	    (caddr_t)lhp, buflen, &sense, &resid)) == 0) &&
	    ((log_length = BE_16(lhp->length)) > 0)) {

		lphp = (struct log_parameter_header *)(((uchar_t *)lhp) +
		    sizeof (struct log_header));

		while (i < log_length) {

			lphp = (struct log_parameter_header *)
			    (((uchar_t *)lphp) + this_param_len);

			/*
			 * If the analysis fn returns a negative value,
			 * then a disk fault identified with this page
			 * has been identified.
			 */
			if ((*analyze_fn)(diskinfop, lphp) < 0)
				disk_warn(diskinfop, "fault found: log page "
				    "0x%x, parameter 0x%x.\n", logpage_code,
				    BE_16(lphp->param_code));

			this_param_len = lphp->length +
			    sizeof (struct log_parameter_header);

			i += this_param_len;
		}
	}

	dfree(lhp, buflen);
	if (result != 0)
		scsi_translate_error(&sense, skp, ascp, ascqp);
	return (result);
}

static int
fault_analyze_logpages(int fd, diskmon_t *diskinfop, int *failidx,
    uint_t *skp, uint_t *ascp, uint_t *ascqp)
{
	fault_monitor_info_t *fip = diskinfop->fmip;
	int result = 0;
	int i;

	for (i = 0; logpage_validation_list[i].analyze_fn != NULL; i++) {

		if ((fip->log_pages_supported &
		    logpage_validation_list[i].supp_bit) == 0) {

			continue;
		}

		/*
		 * analyze_logpage will return a negative value if something
		 * went wrong during a LOG SENSE of the current log page.
		 */
		if (fault_analyze_logpage(
		    logpage_validation_list[i].logpage_code, fd, diskinfop,
		    skp, ascp, ascqp) != 0) {

			/*
			 * If something goes wrong here, this is not a fatal
			 * error -- just remember it and continue.
			 */
			*failidx = i;
			result -= 1;
		}
	}

	return (result);
}

static int
scsi_request_sense(int fd, diskmon_t *diskinfop, uint_t *skp,
    uint_t *ascp, uint_t *ascqp)
{
	fault_monitor_info_t *fip = diskinfop->fmip;
	int result;

	result = disk_request_sense(fd, skp, ascp, ascqp);

	/*
	 * Save the result of a successful REQUEST SENSE
	 * because error information is cleared after it's
	 * sent to the host.
	 */
	if (result == 0) {
		fip->last_rs_key = *skp;
		fip->last_rs_asc = *ascp;
		fip->last_rs_ascq = *ascqp;
	}

	return (result);
}

void
disk_fault_uninit(diskmon_t *diskinfop)
{
	/*
	 * The only thing that consumes memory is the fault list, so free
	 * that now:
	 */
	if (diskinfop->fmip != NULL) {
		free_disk_fault_list(diskinfop->fmip);
		free_disk_fault_info(&diskinfop->fmip);
	}
	assert(pthread_mutex_lock(&diskinfop->disk_faults_mutex) == 0);
	diskinfop->disk_faults = DISK_FAULT_SOURCE_NONE;
	assert(pthread_mutex_unlock(&diskinfop->disk_faults_mutex) == 0);
}

int
disk_fault_init(diskmon_t *diskinfop)
{
	fault_monitor_info_t *fip;
	int fd;
	char path[MAXPATHLEN];
	uint_t sense_key = 0, asc = 0, ascq = 0;
	int return_code = IE_SUCCESS;

	(void) snprintf(path, MAXPATHLEN, "/devices%s",
	    dm_prop_lookup(diskinfop->props, DISK_PROP_DEVPATH));

	if ((fd = open(path, O_RDWR)) < 0) {
		disk_warn(diskinfop, "disk_fault_init: Error opening disk "
		    "node");
		return (-1);
	}

	/* Reset fault-tracking statistics */
	diskinfop->due = (time_t)0;
	diskinfop->analysis_generation = 0;

	diskinfop->fmip = new_disk_fault_info();

	fip = diskinfop->fmip;

	/* Initialize key fields: */
	/* Assume we support no extensions */
	fip->extensions = 0;
	/* Assume we support no log pages */
	fip->log_pages_supported = 0;
	/* Assume we support no mode pages */
	fip->mode_pages_supported = 0;

	if (modepages_init(fd, diskinfop, &sense_key, &asc, &ascq)
	    != 0) {

		/*
		 * If the error was an invalid opcode, then mode sense
		 * isn't supported, and, by extension, IE isn't supported.
		 * If the error is "mode page unsupported", then this lun
		 * is equally as useless.
		 */
		if (SCSI_INVALID_OPCODE(sense_key, asc, ascq) ||
		    MODE_PAGE_UNSUPPORTED(sense_key, asc, ascq))
			return_code = IE_NOT_SUPPORTED;
		else {
			log_err("modepages_init failed: "
			    "KEY=0x%x ASC=0x%x ASCQ=0x%x", sense_key, asc,
				ascq);
			return_code = IE_OTHER_ERROR;
		}

	} else if (!MODE_PAGE_SUPPORTED(fip, MODEPAGE_SUPP_IEC)) {

		disk_note(diskinfop,
		    "No IEC mode page present -- IE (SMART) not supported.\n");
		return_code = IE_NOT_SUPPORTED;

	} else if ((return_code = ie_enable_and_save(fd, diskinfop, &sense_key,
	    &asc, &ascq, OPT_ENABLED(fip, OPTION_TEST_MODE),
	    OPT_ENABLED(fip, OPTION_PERF_MODE))) != 0) {

		log_err("Error during IEC mode page read/update: "
		    "KEY=0x%x   ASC=0x%x   ASCQ=0x%x", sense_key, asc, ascq);

	} else if (supported_log_pages(fd, diskinfop, &sense_key, &asc, &ascq)
	    != 0) {

		/*
		 * If there's an error retrieving the list of supported log
		 * pages, then continue with a warning.
		 */

		disk_warn(diskinfop,
		    "Error during LOG SENSE of supported pages: "
		    "KEY=0x%x   ASC=0x%x   ASCQ=0x%x -- not using any "
		    "log pages for fault monitoring.\n", sense_key, asc, ascq);

	} else {
		(void) verify_logpages(fd, diskinfop, &sense_key, &asc, &ascq);
	}

	(void) close(fd);

	return (return_code);
}

static int
disk_check_ie_sense(int fd, diskmon_t *diskinfop, uint_t *skp,
    uint_t *ascp, uint_t *ascqp)
{
	int result;
	uint_t sense_key, asc, ascq;

	if (scsi_request_sense(fd, diskinfop, &sense_key, &asc, &ascq) != 0) {

		*skp = sense_key;
		*ascp = asc;
		*ascqp = ascq;

		result = -1;
	} else {

		/*
		 * If the sense key is NO SENSE, and the ASC is
		 * any nonzero value, then we have an impending failure
		 */
		if (sense_key == KEY_NO_SENSE && asc != 0) {

			add_disk_fault(diskinfop, DISK_FAULT_SOURCE_INFO_EXCPT,
			    NULL, sense_key, asc, ascq, 0, 0, 0);
		}

		result = 0;
	}

	return (result);
}

/*
 * Returns n>0 if there are disk faults (n faults)
 *           0 if there are no disk faults
 *          <0 if there was a problem accessing the disk
 */
int
disk_fault_analyze(diskmon_t *diskinfop)
{
	int i, fd;
	int faults = 0;
	uint_t sk, asc, ascq;
	struct disk_fault *flt;
	boolean_t print_msg;
	fault_monitor_info_t *fip = diskinfop->fmip;
	char path[MAXPATHLEN];
	disk_flt_src_e before_disk_fault_srcs = fip->disk_fault_srcs;

	(void) snprintf(path, MAXPATHLEN, "/devices%s",
	    dm_prop_lookup(diskinfop->props, DISK_PROP_DEVPATH));

	if ((fd = open(path, O_RDWR)) < 0) {
		disk_err(diskinfop, "disk_fault_analyze: Error opening disk "
		    "node");
		return (-1);
	}

	/*
	 * Grab the fault list mutex here because any of the functions below
	 * can add to it.
	 */
	assert(pthread_mutex_lock(&fip->fault_data_mutex) == 0);

	if (fault_analyze_logpages(fd, diskinfop, &i, &sk, &asc, &ascq) != 0) {
		disk_warn(diskinfop, "Error during %s log page analysis: "
		    "KEY=0x%x   ASC=0x%x   ASCQ=0x%x\n",
		    logpage_validation_list[i].descr, sk, asc, ascq);
	}

	/*
	 * We only need the unsolicited request-sense if we don't have the
	 * IE log page.
	 */
	if (!LOG_PAGE_SUPPORTED(fip, LOGPAGE_SUPP_IE) &&
	    disk_check_ie_sense(fd, diskinfop, &sk, &asc, &ascq) != 0) {

		disk_err(diskinfop, "Request Sense failure: "
		    "KEY=0x%x ASC=0x%x ASCQ=0x%x\n", sk, asc, ascq);
	}

	(void) close(fd);

	/*
	 * If any disk faults were added to the diskinfo structure, then
	 * we may have a disk fault condition.
	 */

	if (before_disk_fault_srcs == fip->disk_fault_srcs) {
		assert(pthread_mutex_unlock(&fip->fault_data_mutex) == 0);
		return (0);
	}


	flt = fip->fault_list;
	while (flt != NULL) {
		if (OPT_ENABLED(fip, OPTION_SELFTEST_ERRS_ARE_FATAL) &&
		    flt->fault_src == DISK_FAULT_SOURCE_SELFTEST) {

			faults++;
			print_msg = B_TRUE;

		} else if (OPT_ENABLED(fip,
		    OPTION_OVERTEMP_ERRS_ARE_FATAL) &&
		    flt->fault_src == DISK_FAULT_SOURCE_OVERTEMP) {

			faults++;
			print_msg = B_TRUE;

		} else if (flt->fault_src == DISK_FAULT_SOURCE_INFO_EXCPT) {

			faults++;
			print_msg = B_TRUE;
		} else
			print_msg = B_FALSE;

		if (print_msg)
			disk_err(diskinfop, "%s\n", flt->msg);

		flt = flt->next;
	}
	assert(pthread_mutex_unlock(&fip->fault_data_mutex) == 0);

	return (faults);
}
