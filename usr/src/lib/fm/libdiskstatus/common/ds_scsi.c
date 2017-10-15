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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <libdiskstatus.h>
#include <limits.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/fm/io/scsi.h>

#include "ds_scsi.h"
#include "ds_scsi_sim.h"
#include "ds_scsi_uscsi.h"

typedef struct ds_scsi_info {
	disk_status_t		*si_dsp;
	void			*si_sim;
	int			si_cdblen;
	int			si_supp_mode;
	int			si_supp_log;
	int			si_extensions;
	int			si_reftemp;
	scsi_ms_hdrs_t		si_hdrs;
	scsi_ie_page_t		si_iec_current;
	scsi_ie_page_t		si_iec_changeable;
	nvlist_t		*si_state_modepage;
	nvlist_t		*si_state_logpage;
	nvlist_t		*si_state_iec;
} ds_scsi_info_t;

#define	scsi_set_errno(sip, errno)	(ds_set_errno((sip)->si_dsp, (errno)))

/*
 * Table to validate log pages
 */
typedef int (*logpage_validation_fn_t)(ds_scsi_info_t *,
    scsi_log_parameter_header_t *, int, nvlist_t *);
typedef int (*logpage_analyze_fn_t)(ds_scsi_info_t *,
    scsi_log_parameter_header_t *, int);

typedef struct logpage_validation_entry {
	uchar_t			ve_code;
	int			ve_supported;
	const char		*ve_desc;
	logpage_validation_fn_t	ve_validate;
	logpage_analyze_fn_t	ve_analyze;
} logpage_validation_entry_t;

static int logpage_ie_verify(ds_scsi_info_t *,
    scsi_log_parameter_header_t *, int, nvlist_t *);
static int logpage_temp_verify(ds_scsi_info_t *,
    scsi_log_parameter_header_t *, int, nvlist_t *);
static int logpage_selftest_verify(ds_scsi_info_t *,
    scsi_log_parameter_header_t *, int, nvlist_t *);
static int logpage_ssm_verify(ds_scsi_info_t *,
    scsi_log_parameter_header_t *, int, nvlist_t *);

static int logpage_ie_analyze(ds_scsi_info_t *,
    scsi_log_parameter_header_t *, int);
static int logpage_temp_analyze(ds_scsi_info_t *,
    scsi_log_parameter_header_t *, int);
static int logpage_selftest_analyze(ds_scsi_info_t *,
    scsi_log_parameter_header_t *, int);
static int logpage_ssm_analyze(ds_scsi_info_t *,
    scsi_log_parameter_header_t *, int);

static struct logpage_validation_entry log_validation[] = {
	{ LOGPAGE_IE,		LOGPAGE_SUPP_IE,
	    "informational-exceptions",
	    logpage_ie_verify,	logpage_ie_analyze },
	{ LOGPAGE_TEMP,		LOGPAGE_SUPP_TEMP,
	    "temperature",
	    logpage_temp_verify, logpage_temp_analyze },
	{ LOGPAGE_SELFTEST,	LOGPAGE_SUPP_SELFTEST,
	    "self-test",
	    logpage_selftest_verify, logpage_selftest_analyze },
	{ LOGPAGE_SSM,		LOGPAGE_SUPP_SSM,
	    FM_EREPORT_SCSI_SSMWEAROUT,
	    logpage_ssm_verify, logpage_ssm_analyze }
};

#define	NLOG_VALIDATION	(sizeof (log_validation) / sizeof (log_validation[0]))

/*
 * Given an extended sense page, retrieves the sense key, as well as the
 * additional sense code information.
 */
static void
scsi_translate_error(struct scsi_extended_sense *rq, uint_t *skeyp,
    uint_t *ascp, uint_t *ascqp)
{
	struct scsi_descr_sense_hdr *sdsp =
	    (struct scsi_descr_sense_hdr *)rq;

	*skeyp = rq->es_key;

	/*
	 * Get asc, ascq and info field from sense data.  There are two
	 * possible formats (fixed sense data and descriptor sense data)
	 * depending on the value of es_code.
	 */
	switch (rq->es_code) {
	case CODE_FMT_DESCR_CURRENT:
	case CODE_FMT_DESCR_DEFERRED:

		*ascp = sdsp->ds_add_code;
		*ascqp = sdsp->ds_qual_code;
		break;

	case CODE_FMT_FIXED_CURRENT:
	case CODE_FMT_FIXED_DEFERRED:
	default:

		if (rq->es_add_len >= 6) {
			*ascp = rq->es_add_code;
			*ascqp = rq->es_qual_code;
		} else {
			*ascp = 0xff;
			*ascqp = 0xff;
		}
		break;
	}
}

/*
 * Routines built atop the bare uscsi commands, which take into account the
 * command length, automatically translate any scsi errors, and transparently
 * call into the simulator if active.
 */
static int
scsi_mode_select(ds_scsi_info_t *sip, uchar_t page_code, int options,
    void *buf, uint_t buflen, scsi_ms_hdrs_t *headers, uint_t *skp,
    uint_t *ascp, uint_t *ascqp)
{
	int result;
	struct scsi_extended_sense sense;
	int senselen = sizeof (struct scsi_extended_sense);
	struct mode_page *mp = (struct mode_page *)buf;

	assert(sip->si_cdblen == MODE_CMD_LEN_6 ||
	    sip->si_cdblen == MODE_CMD_LEN_10);
	assert(headers->ms_length == sip->si_cdblen);

	bzero(&sense, sizeof (struct scsi_extended_sense));

	if (mp->ps) {
		options |= MODE_SELECT_SP;
		mp->ps = 0;
	} else {
		options &= ~MODE_SELECT_SP;
	}

	if (sip->si_cdblen == MODE_CMD_LEN_6) {
		/* The following fields are reserved during mode select: */
		headers->ms_hdr.g0.ms_header.length = 0;
		headers->ms_hdr.g0.ms_header.device_specific = 0;

		if (sip->si_sim)
			result = simscsi_mode_select(sip->si_sim,
			    page_code, options, buf, buflen,
			    &headers->ms_hdr.g0, &sense, &senselen);
		else
			result = uscsi_mode_select(sip->si_dsp->ds_fd,
			    page_code, options, buf, buflen,
			    &headers->ms_hdr.g0, &sense, &senselen);
	} else {
		/* The following fields are reserved during mode select: */
		headers->ms_hdr.g1.ms_header.length = 0;
		headers->ms_hdr.g1.ms_header.device_specific = 0;

		if (sip->si_sim)
			result = simscsi_mode_select_10(sip->si_sim,
			    page_code, options, buf, buflen,
			    &headers->ms_hdr.g1, &sense, &senselen);
		else
			result = uscsi_mode_select_10(sip->si_dsp->ds_fd,
			    page_code, options, buf, buflen,
			    &headers->ms_hdr.g1, &sense, &senselen);
	}

	if (result != 0)
		scsi_translate_error(&sense, skp, ascp, ascqp);

	return (result);
}

static int
scsi_mode_sense(ds_scsi_info_t *sip, uchar_t page_code, uchar_t pc,
    void *buf, uint_t buflen, scsi_ms_hdrs_t *headers, uint_t *skp,
    uint_t *ascp, uint_t *ascqp)
{
	int result;
	struct scsi_extended_sense sense;
	int senselen = sizeof (struct scsi_extended_sense);

	assert(sip->si_cdblen == MODE_CMD_LEN_6 ||
	    sip->si_cdblen == MODE_CMD_LEN_10);

	bzero(&sense, sizeof (struct scsi_extended_sense));

	bzero(headers, sizeof (scsi_ms_hdrs_t));
	headers->ms_length = sip->si_cdblen;

	if (sip->si_cdblen == MODE_CMD_LEN_6) {
		if (sip->si_sim)
			result = simscsi_mode_sense(sip->si_sim,
			    page_code, pc, buf, buflen, &headers->ms_hdr.g0,
			    &sense, &senselen);
		else
			result = uscsi_mode_sense(sip->si_dsp->ds_fd, page_code,
			    pc, buf, buflen, &headers->ms_hdr.g0, &sense,
			    &senselen);
	} else {
		if (sip->si_sim)
			result = simscsi_mode_sense_10(sip->si_sim,
			    page_code, pc, buf, buflen, &headers->ms_hdr.g1,
			    &sense, &senselen);
		else
			result = uscsi_mode_sense_10(sip->si_dsp->ds_fd,
			    page_code, pc, buf, buflen, &headers->ms_hdr.g1,
			    &sense, &senselen);
	}

	if (result != 0)
		scsi_translate_error(&sense, skp, ascp, ascqp);

	return (result);
}

static int
scsi_request_sense(ds_scsi_info_t *sip, uint_t *skp, uint_t *ascp,
    uint_t *ascqp)
{
	struct scsi_extended_sense sense, sensebuf;
	int senselen = sizeof (struct scsi_extended_sense);
	int sensebuflen = sizeof (struct scsi_extended_sense);
	int result;

	bzero(&sense, sizeof (struct scsi_extended_sense));
	bzero(&sensebuf, sizeof (struct scsi_extended_sense));

	if (sip->si_sim)
		result = simscsi_request_sense(sip->si_sim,
		    (caddr_t)&sensebuf, sensebuflen, &sense, &senselen);
	else
		result = uscsi_request_sense(sip->si_dsp->ds_fd,
		    (caddr_t)&sensebuf, sensebuflen, &sense, &senselen);

	if (result == 0)
		scsi_translate_error(&sensebuf, skp, ascp, ascqp);
	else
		scsi_translate_error(&sense, skp, ascp, ascqp);

	return (result);
}

static int
scsi_log_sense(ds_scsi_info_t *sip, int page_code, int page_control,
    caddr_t page_data, int page_size, uint_t *skp, uint_t *ascp, uint_t *ascqp)
{
	int result;
	struct scsi_extended_sense sense;
	int senselen = sizeof (struct scsi_extended_sense);

	if (sip->si_sim)
		result = simscsi_log_sense(sip->si_sim,
		    page_code, page_control, page_data, page_size, &sense,
		    &senselen);
	else
		result = uscsi_log_sense(sip->si_dsp->ds_fd,
		    page_code, page_control, page_data, page_size, &sense,
		    &senselen);

	if (result != 0)
		scsi_translate_error(&sense, skp, ascp, ascqp);

	return (result);
}

/*
 * Given a list of supported mode pages, determine if the given page is present.
 */
static boolean_t
mode_page_present(uchar_t *pgdata, uint_t pgdatalen, uchar_t pagecode)
{
	uint_t i = 0;
	struct mode_page *pg;
	boolean_t found = B_FALSE;

	/*
	 * The mode page list contains all mode pages supported by the device,
	 * one after the other.
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
 * Load mode pages and check that the appropriate pages are supported.
 *
 * As part of this process, we determine which form of the MODE SENSE / MODE
 * SELECT command to use (the 6-byte or 10-byte version) by executing a MODE
 * SENSE command for a page that should be implemented by the device.
 */
static int
load_modepages(ds_scsi_info_t *sip)
{
	int allpages_buflen;
	uchar_t *allpages;
	scsi_ms_hdrs_t headers;
	int result;
	uint_t skey, asc, ascq;
	int datalength = 0;
	scsi_ms_header_t *smh = &headers.ms_hdr.g0;
	scsi_ms_header_g1_t *smh_g1 = &headers.ms_hdr.g1;
	nvlist_t *nvl;

	allpages_buflen = MAX_BUFLEN(scsi_ms_header_g1_t);
	if ((allpages = calloc(allpages_buflen, 1)) == NULL)
		return (scsi_set_errno(sip, EDS_NOMEM));

	bzero(&headers, sizeof (headers));

	/*
	 * Attempt a mode sense(6).  If that fails, try a mode sense(10)
	 *
	 * allpages is allocated to be of the maximum size for either a mode
	 * sense(6) or mode sense(10) MODEPAGE_ALLPAGES response.
	 *
	 * Note that the length passed into uscsi_mode_sense should be set to
	 * the maximum size of the parameter response, which in this case is
	 * UCHAR_MAX - the size of the headers/block descriptors.
	 */
	sip->si_cdblen = MODE_CMD_LEN_6;
	if ((result = scsi_mode_sense(sip, MODEPAGE_ALLPAGES, PC_CURRENT,
	    (caddr_t)allpages, UCHAR_MAX - sizeof (scsi_ms_header_t),
	    &headers, &skey, &asc, &ascq)) == 0) {
		/*
		 * Compute the data length of the page that contains all mode
		 * sense pages.  This is a bit tricky because the format of the
		 * response from the lun is:
		 *
		 * header: <length> <medium type byte> <dev specific byte>
		 *	   <block descriptor length>
		 *	   [<optional block descriptor>]
		 * data:   [<mode page data> <mode page data> ...]
		 *
		 * Since the length field in the header describes the length of
		 * the entire response.  This includes the header, but NOT
		 * the length field itself, which is 1 or 2 bytes depending on
		 * which mode sense type (6- or 10- byte) is being executed.
		 *
		 * So, the data length equals the length value in the header
		 * plus 1 (because the length byte was not included in the
		 * length count), minus [[the sum of the length of the header
		 * and the length of the block descriptor]].
		 */
		datalength = (smh->ms_header.length +
		    sizeof (smh->ms_header.length)) -
		    (sizeof (struct mode_header) +
		    smh->ms_header.bdesc_length);
	} else if (SCSI_INVALID_OPCODE(skey, asc, ascq)) {
		/*
		 * Fallback and try the 10-byte version of the command.
		 */
		sip->si_cdblen = MODE_CMD_LEN_10;
		result = scsi_mode_sense(sip, MODEPAGE_ALLPAGES,
		    PC_CURRENT, (caddr_t)allpages, allpages_buflen,
		    &headers, &skey, &asc, &ascq);

		if (result == 0) {
			datalength = (BE_16(smh_g1->ms_header.length) +
			    sizeof (smh_g1->ms_header.length)) -
			    (sizeof (struct mode_header_g1) +
			    BE_16(smh_g1->ms_header.bdesc_length));

		}
	}

	if (result == 0 && datalength >= 0) {
		if (nvlist_add_int8(sip->si_dsp->ds_state, "command-length",
		    sip->si_cdblen == MODE_CMD_LEN_6 ? 6 : 10) != 0) {
			free(allpages);
			return (scsi_set_errno(sip, EDS_NOMEM));
		}

		nvl = NULL;
		if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0 ||
		    nvlist_add_nvlist(sip->si_dsp->ds_state, "modepages",
		    nvl) != 0) {
			free(allpages);
			nvlist_free(nvl);
			return (scsi_set_errno(sip, EDS_NOMEM));
		}

		nvlist_free(nvl);
		result = nvlist_lookup_nvlist(sip->si_dsp->ds_state,
		    "modepages", &sip->si_state_modepage);
		assert(result == 0);

		/*
		 * One of the sets of the commands (above) succeeded, so now
		 * look for the mode pages we need and record them appropriately
		 */
		if (mode_page_present(allpages, datalength,
		    MODEPAGE_INFO_EXCPT)) {

			nvl = NULL;
			if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0 ||
			    nvlist_add_nvlist(sip->si_state_modepage,
			    "informational-exceptions", nvl) != 0) {
				free(allpages);
				nvlist_free(nvl);
				return (scsi_set_errno(sip, EDS_NOMEM));
			}
			nvlist_free(nvl);
			sip->si_supp_mode |= MODEPAGE_SUPP_IEC;
			result = nvlist_lookup_nvlist(sip->si_state_modepage,
			    "informational-exceptions", &sip->si_state_iec);
			assert(result == 0);
		}

	} else {
		/*
		 * If the device failed to respond to one of the basic commands,
		 * then assume it's not a SCSI device or otherwise doesn't
		 * support the necessary transport.
		 */
		if (datalength < 0)
			dprintf("command returned invalid data length (%d)\n",
			    datalength);
		else
			dprintf("failed to load modepages (KEY=0x%x "
			    "ASC=0x%x ASCQ=0x%x)\n", skey, asc, ascq);

		result = scsi_set_errno(sip, EDS_NO_TRANSPORT);
	}

	free(allpages);
	return (result);
}

/*
 * Verify a single logpage.  This will do some generic validation and then call
 * the logpage-specific function for further verification.
 */
static int
verify_logpage(ds_scsi_info_t *sip, logpage_validation_entry_t *lp)
{
	scsi_log_header_t *lhp;
	struct scsi_extended_sense sense;
	int buflen;
	int log_length;
	int result = 0;
	uint_t kp, asc, ascq;
	nvlist_t *nvl;

	buflen = MAX_BUFLEN(scsi_log_header_t);
	if ((lhp = calloc(buflen, 1)) == NULL)
		return (scsi_set_errno(sip, EDS_NOMEM));
	bzero(&sense, sizeof (struct scsi_extended_sense));

	nvl = NULL;
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_add_nvlist(sip->si_state_logpage, lp->ve_desc, nvl) != 0) {
		nvlist_free(nvl);
		free(lhp);
		return (scsi_set_errno(sip, EDS_NOMEM));
	}
	nvlist_free(nvl);
	result = nvlist_lookup_nvlist(sip->si_state_logpage, lp->ve_desc, &nvl);
	assert(result == 0);

	result = scsi_log_sense(sip, lp->ve_code,
	    PC_CUMULATIVE, (caddr_t)lhp, buflen, &kp, &asc, &ascq);

	if (result == 0) {
		log_length = BE_16(lhp->lh_length);
		if (nvlist_add_uint16(nvl, "length", log_length) != 0) {
			free(lhp);
			return (scsi_set_errno(sip, EDS_NOMEM));
		}

		if (lp->ve_validate(sip, (scsi_log_parameter_header_t *)
		    (((char *)lhp) + sizeof (scsi_log_header_t)),
		    log_length, nvl) != 0) {
			free(lhp);
			return (-1);
		}
	} else {
		dprintf("failed to load %s log page (KEY=0x%x "
		    "ASC=0x%x ASCQ=0x%x)\n", lp->ve_desc, kp, asc, ascq);
	}

	free(lhp);
	return (0);
}

/*
 * Load log pages and determine which pages are supported.
 */
static int
load_logpages(ds_scsi_info_t *sip)
{
	int buflen;
	scsi_supported_log_pages_t *sp;
	struct scsi_extended_sense sense;
	int result;
	uint_t sk, asc, ascq;
	int i, j;
	nvlist_t *nvl;

	buflen = MAX_BUFLEN(scsi_log_header_t);
	if ((sp = calloc(buflen, 1)) == NULL)
		return (scsi_set_errno(sip, EDS_NOMEM));

	bzero(&sense, sizeof (struct scsi_extended_sense));

	if ((result = scsi_log_sense(sip, LOGPAGE_SUPP_LIST,
	    PC_CUMULATIVE, (caddr_t)sp, buflen, &sk, &asc, &ascq)) == 0) {
		int pagecount = BE_16(sp->slp_hdr.lh_length);

		for (i = 0; i < pagecount; i++) {
			for (j = 0; j < NLOG_VALIDATION; j++) {
				if (log_validation[j].ve_code ==
				    sp->slp_pages[i])
					sip->si_supp_log |=
					    log_validation[j].ve_supported;
			}
		}
	}

	free(sp);
	if (result == 0) {
		nvl = NULL;
		if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0 ||
		    nvlist_add_nvlist(sip->si_dsp->ds_state, "logpages",
		    nvl) != 0) {
			nvlist_free(nvl);
			return (scsi_set_errno(sip, EDS_NOMEM));
		}

		nvlist_free(nvl);
		result = nvlist_lookup_nvlist(sip->si_dsp->ds_state,
		    "logpages", &sip->si_state_logpage);
		assert(result == 0);

		/*
		 * Validate the logpage contents.
		 */
		for (i = 0; i < NLOG_VALIDATION; i++) {
			if ((sip->si_supp_log &
			    log_validation[i].ve_supported) == 0)
				continue;

			/*
			 * verify_logpage will clear the supported bit if
			 * verification fails.
			 */
			if (verify_logpage(sip, &log_validation[i]) != 0)
				return (-1);
		}

	} else {
		dprintf("failed to get log pages "
		    "(KEY=0x%x ASC=0x%x ASCq=0x%x)\n", sk, asc, ascq);
	}

	/*
	 * We always return 0 here, even if the required log pages aren't
	 * supported.
	 */
	return (0);
}

/*
 * Verify that the IE log page is sane.  This log page is potentially chock-full
 * of vendor specific information that we do not know how to access.  All we can
 * do is check for the generic predictive failure bit.  If this log page is not
 * well-formed, then bail out.
 */
static int
logpage_ie_verify(ds_scsi_info_t *sip, scsi_log_parameter_header_t *lphp,
    int log_length, nvlist_t *nvl)
{
	int i, plen = 0;
	boolean_t seen = B_FALSE;
	scsi_ie_log_param_t *iep =
	    (scsi_ie_log_param_t *)lphp;

	for (i = 0; i < log_length; i += plen) {
		iep = (scsi_ie_log_param_t *)((char *)iep + plen);

		if (BE_16(iep->ie_hdr.lph_param) == LOGPARAM_IE) {
			if (nvlist_add_boolean_value(nvl, "general",
			    B_TRUE) != 0)
				return (scsi_set_errno(sip, EDS_NOMEM));

			if (lphp->lph_length < LOGPARAM_IE_MIN_LEN) {
				if (nvlist_add_uint8(nvl,
				    "invalid-length", lphp->lph_length) != 0)
					return (scsi_set_errno(sip, EDS_NOMEM));
			} else {
				seen = B_TRUE;
			}
			break;
		}

		plen = iep->ie_hdr.lph_length +
		    sizeof (scsi_log_parameter_header_t);
	}

	if (!seen) {
		sip->si_supp_log &= ~LOGPAGE_SUPP_IE;
		dprintf("IE logpage validation failed\n");
	}

	return (0);
}

/*
 * Verify the contents of the temperature log page.  The temperature log page
 * contains two log parameters: the current temperature, and (optionally) the
 * reference temperature.  For the verification phase, we check that the two
 * parameters we care about are well-formed.  If there is no reference
 * temperature, then we cannot use the page for monitoring purposes.
 */
static int
logpage_temp_verify(ds_scsi_info_t *sip,
    scsi_log_parameter_header_t *lphp, int log_length, nvlist_t *nvl)
{
	int i, plen = 0;
	boolean_t has_reftemp = B_FALSE;
	boolean_t bad_length = B_FALSE;
	ushort_t param_code;

	for (i = 0; i < log_length; i += plen) {
		lphp = (scsi_log_parameter_header_t *)((char *)lphp + plen);
		param_code = BE_16(lphp->lph_param);

		switch (param_code) {
		case LOGPARAM_TEMP_CURTEMP:
			if (nvlist_add_boolean_value(nvl, "current-temperature",
			    B_TRUE) != 0)
				return (scsi_set_errno(sip, EDS_NOMEM));
			if (lphp->lph_length != LOGPARAM_TEMP_LEN) {
				if (nvlist_add_uint8(nvl,
				    "invalid-length", lphp->lph_length) != 0)
					return (scsi_set_errno(sip, EDS_NOMEM));
				bad_length = B_TRUE;
			}
			break;

		case LOGPARAM_TEMP_REFTEMP:
			if (nvlist_add_boolean_value(nvl,
			    "reference-temperature", B_TRUE) != 0)
				return (scsi_set_errno(sip, EDS_NOMEM));
			if (lphp->lph_length != LOGPARAM_TEMP_LEN) {
				if (nvlist_add_uint8(nvl,
				    "invalid-length", lphp->lph_length) != 0)
					return (scsi_set_errno(sip, EDS_NOMEM));
				bad_length = B_TRUE;
			}
			has_reftemp = B_TRUE;
			break;
		}

		plen = lphp->lph_length +
		    sizeof (scsi_log_parameter_header_t);
	}

	if (bad_length || !has_reftemp) {
		sip->si_supp_log &= ~LOGPAGE_SUPP_TEMP;
		dprintf("temperature logpage validation failed\n");
	}

	return (0);
}

/*
 * Verify the contents of the self test log page.  The log supports a maximum of
 * 20 entries, where each entry's parameter code is its index in the log.  We
 * check that the parameter codes fall within this range, and that the size of
 * each page is what we expect.  It's perfectly acceptable for there to be no
 * entries in this log, so we must also be sure to validate the contents as part
 * of the analysis phase.
 */
static int
logpage_selftest_verify(ds_scsi_info_t *sip,
    scsi_log_parameter_header_t *lphp, int log_length, nvlist_t *nvl)
{
	int i, plen = 0;
	boolean_t bad = B_FALSE;
	int entries = 0;
	ushort_t param_code;

	for (i = 0; i < log_length; i += plen, entries++) {
		lphp = (scsi_log_parameter_header_t *)((char *)lphp + plen);
		param_code = BE_16(lphp->lph_param);

		if (param_code < LOGPAGE_SELFTEST_MIN_PARAM_CODE ||
		    param_code > LOGPAGE_SELFTEST_MAX_PARAM_CODE) {
			if (nvlist_add_uint16(nvl, "invalid-param-code",
			    param_code) != 0)
				return (scsi_set_errno(sip, EDS_NOMEM));
			bad = B_TRUE;
			break;
		}

		if (lphp->lph_length != LOGPAGE_SELFTEST_PARAM_LEN) {
			if (nvlist_add_uint8(nvl, "invalid-length",
			    lphp->lph_length) != 0)
				return (scsi_set_errno(sip, EDS_NOMEM));
			bad = B_TRUE;
			break;

		}

		plen = lphp->lph_length +
		    sizeof (scsi_log_parameter_header_t);
	}

	if (bad) {
		sip->si_supp_log &= ~LOGPAGE_SUPP_SELFTEST;
		dprintf("selftest logpage validation failed\n");
	}

	return (0);
}

/*
 * Verify the contents of the Solid State Media (SSM) log page.
 * As of SBC3r36 SSM log page contains one log parameter:
 * "Percentage Used Endurance Indicator" which is mandatory.
 * For the verification phase, we sanity check this parameter
 * by making sure it's present and it's length is set to 0x04.
 */
static int
logpage_ssm_verify(ds_scsi_info_t *sip,
    scsi_log_parameter_header_t *lphp, int log_length, nvlist_t *nvl)
{
	ushort_t param_code;
	int i, plen = 0;

	for (i = 0; i < log_length; i += plen) {
		lphp = (scsi_log_parameter_header_t *)((char *)lphp + plen);
		param_code = BE_16(lphp->lph_param);

		switch (param_code) {
		case LOGPARAM_PRCNT_USED:
			if (nvlist_add_boolean_value(nvl,
			    FM_EREPORT_SCSI_SSMWEAROUT, B_TRUE) != 0)
				return (scsi_set_errno(sip, EDS_NOMEM));
			if (lphp->lph_length != LOGPARAM_PRCNT_USED_PARAM_LEN) {
				if (nvlist_add_uint8(nvl,
				    "invalid-length", lphp->lph_length) != 0)
					return (scsi_set_errno(sip, EDS_NOMEM));

				dprintf("solid state media logpage bad len\n");
				break;
			}

			/* verification succeded */
			return (0);
		}

		plen = lphp->lph_length +
		    sizeof (scsi_log_parameter_header_t);
	}

	/* verification failed */
	sip->si_supp_log &= ~LOGPAGE_SUPP_SSM;
	return (0);
}

/*
 * Load the current IE mode pages
 */
static int
load_ie_modepage(ds_scsi_info_t *sip)
{
	struct scsi_ms_hdrs junk_hdrs;
	int result;
	uint_t skey, asc, ascq;

	if (!(sip->si_supp_mode & MODEPAGE_SUPP_IEC))
		return (0);

	bzero(&sip->si_iec_current, sizeof (sip->si_iec_current));
	bzero(&sip->si_iec_changeable, sizeof (sip->si_iec_changeable));

	if ((result = scsi_mode_sense(sip,
	    MODEPAGE_INFO_EXCPT, PC_CURRENT, &sip->si_iec_current,
	    MODEPAGE_INFO_EXCPT_LEN, &sip->si_hdrs, &skey, &asc,
	    &ascq)) == 0) {
		result = scsi_mode_sense(sip,
		    MODEPAGE_INFO_EXCPT, PC_CHANGEABLE,
		    &sip->si_iec_changeable,
		    MODEPAGE_INFO_EXCPT_LEN, &junk_hdrs, &skey, &asc, &ascq);
	}

	if (result != 0) {
		dprintf("failed to get IEC modepage (KEY=0x%x "
		    "ASC=0x%x ASCQ=0x%x)", skey, asc, ascq);
		sip->si_supp_mode &= ~MODEPAGE_SUPP_IEC;
	} else  {
		if (nvlist_add_boolean_value(sip->si_state_iec,
		    "dexcpt", sip->si_iec_current.ie_dexcpt) != 0 ||
		    nvlist_add_boolean_value(sip->si_state_iec,
		    "logerr", sip->si_iec_current.ie_logerr) != 0 ||
		    nvlist_add_uint8(sip->si_state_iec,
		    "mrie", sip->si_iec_current.ie_mrie) != 0 ||
		    nvlist_add_boolean_value(sip->si_state_iec,
		    "test", sip->si_iec_current.ie_test) != 0 ||
		    nvlist_add_boolean_value(sip->si_state_iec,
		    "ewasc", sip->si_iec_current.ie_ewasc) != 0 ||
		    nvlist_add_boolean_value(sip->si_state_iec,
		    "perf", sip->si_iec_current.ie_perf) != 0 ||
		    nvlist_add_boolean_value(sip->si_state_iec,
		    "ebf", sip->si_iec_current.ie_ebf) != 0 ||
		    nvlist_add_uint32(sip->si_state_iec,
		    "interval-timer",
		    BE_32(sip->si_iec_current.ie_interval_timer)) != 0 ||
		    nvlist_add_uint32(sip->si_state_iec,
		    "report-count",
		    BE_32(sip->si_iec_current.ie_report_count)) != 0)
			return (scsi_set_errno(sip, EDS_NOMEM));
	}

	return (0);
}

/*
 * Enable IE reporting.  We prefer the following settings:
 *
 * (1) DEXCPT = 0
 * (3) MRIE = 6 (IE_REPORT_ON_REQUEST)
 * (4) EWASC = 1
 * (6) REPORT COUNT = 0x00000001
 * (7) LOGERR = 1
 *
 * However, not all drives support changing these values, and the current state
 * may be useful enough as-is.  For example, some drives support IE logging, but
 * don't support changing the MRIE.  In this case, we can still use the
 * information provided by the log page.
 */
static int
scsi_enable_ie(ds_scsi_info_t *sip, boolean_t *changed)
{
	scsi_ie_page_t new_iec_page;
	scsi_ms_hdrs_t hdrs;
	uint_t skey, asc, ascq;

	if (!(sip->si_supp_mode & MODEPAGE_SUPP_IEC))
		return (0);

	bzero(&new_iec_page, sizeof (new_iec_page));
	bzero(&hdrs, sizeof (hdrs));

	(void) memcpy(&new_iec_page, &sip->si_iec_current,
	    sizeof (new_iec_page));

	if (IEC_IE_CHANGEABLE(sip->si_iec_changeable))
		new_iec_page.ie_dexcpt = 0;

	if (IEC_MRIE_CHANGEABLE(sip->si_iec_changeable))
		new_iec_page.ie_mrie = IE_REPORT_ON_REQUEST;

	/*
	 * We only want to enable warning reporting if we are able to change the
	 * mrie to report on request.  Otherwise, we risk unnecessarily
	 * interrupting normal SCSI commands with a CHECK CONDITION code.
	 */
	if (IEC_EWASC_CHANGEABLE(sip->si_iec_changeable)) {
		if (new_iec_page.ie_mrie == IE_REPORT_ON_REQUEST)
			new_iec_page.ie_ewasc = 1;
		else
			new_iec_page.ie_ewasc = 0;
	}

	if (IEC_RPTCNT_CHANGEABLE(sip->si_iec_changeable))
		new_iec_page.ie_report_count = BE_32(1);

	if (IEC_LOGERR_CHANGEABLE(sip->si_iec_changeable))
		new_iec_page.ie_logerr = 1;

	/*
	 * Now compare the new mode page with the existing one.
	 * if there's no difference, there's no need for a mode select
	 */
	if (memcmp(&new_iec_page, &sip->si_iec_current,
	    MODEPAGE_INFO_EXCPT_LEN) == 0) {
		*changed = B_FALSE;
	} else {
		(void) memcpy(&hdrs, &sip->si_hdrs, sizeof (sip->si_hdrs));

		if (scsi_mode_select(sip,
		    MODEPAGE_INFO_EXCPT, MODE_SELECT_PF, &new_iec_page,
		    MODEPAGE_INFO_EXCPT_LEN, &hdrs, &skey, &asc, &ascq) == 0) {
			*changed = B_TRUE;
		} else {
			dprintf("failed to enable IE (KEY=0x%x "
			    "ASC=0x%x ASCQ=0x%x)\n", skey, asc, ascq);
			*changed = B_FALSE;
		}
	}

	if (nvlist_add_boolean_value(sip->si_state_iec, "changed",
	    *changed) != 0)
		return (scsi_set_errno(sip, EDS_NOMEM));

	return (0);
}

/*
 * Clear the GLTSD bit, indicating log pages should be saved to non-volatile
 * storage.
 */
static int
clear_gltsd(ds_scsi_info_t *sip)
{
	scsi_ms_hdrs_t hdrs, junk_hdrs;
	struct mode_control_scsi3 control_pg_cur, control_pg_chg;
	int result;
	uint_t skey, asc, ascq;

	bzero(&hdrs, sizeof (hdrs));
	bzero(&control_pg_cur, sizeof (control_pg_cur));
	bzero(&control_pg_chg, sizeof (control_pg_chg));

	result = scsi_mode_sense(sip,
	    MODEPAGE_CTRL_MODE, PC_CURRENT, &control_pg_cur,
	    MODEPAGE_CTRL_MODE_LEN, &hdrs, &skey, &asc, &ascq);

	if (result != 0) {
		dprintf("failed to read Control mode page (KEY=0x%x "
		    "ASC=0x%x ASCQ=0x%x)\n", skey, asc, ascq);
	} else if (control_pg_cur.mode_page.length !=
	    PAGELENGTH_MODE_CONTROL_SCSI3) {
		dprintf("SCSI-3 control mode page not supported\n");
	} else if ((result = scsi_mode_sense(sip,
	    MODEPAGE_CTRL_MODE, PC_CHANGEABLE, &control_pg_chg,
	    MODEPAGE_CTRL_MODE_LEN, &junk_hdrs, &skey, &asc, &ascq))
	    != 0) {
		dprintf("failed to read changeable Control mode page (KEY=0x%x "
		    "ASC=0x%x ASCQ=0x%x)\n", skey, asc, ascq);
	} else if (control_pg_cur.gltsd && !GLTSD_CHANGEABLE(control_pg_chg)) {
		dprintf("gltsd is set and not changeable\n");
		if (nvlist_add_boolean_value(sip->si_dsp->ds_state,
		    "gltsd", control_pg_cur.gltsd) != 0)
			return (scsi_set_errno(sip, EDS_NOMEM));
	} else if (control_pg_cur.gltsd) {
		control_pg_cur.gltsd = 0;
		result = scsi_mode_select(sip,
		    MODEPAGE_CTRL_MODE, MODE_SELECT_PF, &control_pg_cur,
		    MODEPAGE_CTRL_MODE_LEN, &hdrs, &skey, &asc, &ascq);
		if (result != 0)
			dprintf("failed to enable GLTSD (KEY=0x%x "
			    "ASC=0x%x ASCQ=0x%x\n", skey, asc, ascq);
		if (nvlist_add_boolean_value(sip->si_dsp->ds_state,
		    "gltsd", control_pg_cur.gltsd) != 0)
			return (scsi_set_errno(sip, EDS_NOMEM));
	}

	return (0);
}

/*
 * Fetch the contents of the logpage, and then call the logpage-specific
 * analysis function.  The analysis function is responsible for detecting any
 * faults and filling in the details.
 */
static int
analyze_one_logpage(ds_scsi_info_t *sip, logpage_validation_entry_t *entry)
{
	scsi_log_header_t *lhp;
	scsi_log_parameter_header_t *lphp;
	int buflen;
	int log_length;
	uint_t skey, asc, ascq;
	int result;

	buflen = MAX_BUFLEN(scsi_log_header_t);
	if ((lhp = calloc(buflen, 1)) == NULL)
		return (scsi_set_errno(sip, EDS_NOMEM));

	result = scsi_log_sense(sip, entry->ve_code,
	    PC_CUMULATIVE, (caddr_t)lhp, buflen, &skey, &asc, &ascq);

	if (result == 0) {
		log_length = BE_16(lhp->lh_length);
		lphp = (scsi_log_parameter_header_t *)(((uchar_t *)lhp) +
		    sizeof (scsi_log_header_t));

		result = entry->ve_analyze(sip, lphp, log_length);
	} else {
		result = scsi_set_errno(sip, EDS_IO);
	}

	free(lhp);
	return (result);
}

/*
 * Analyze the IE logpage.  If we find an IE log record with a non-zero 'asc',
 * then we have a fault.
 */
static int
logpage_ie_analyze(ds_scsi_info_t *sip, scsi_log_parameter_header_t *lphp,
    int log_length)
{
	int i, plen = 0;
	scsi_ie_log_param_t *iep = (scsi_ie_log_param_t *)lphp;
	nvlist_t *nvl;

	assert(sip->si_dsp->ds_predfail == NULL);
	if (nvlist_alloc(&sip->si_dsp->ds_predfail, NV_UNIQUE_NAME, 0) != 0)
		return (scsi_set_errno(sip, EDS_NOMEM));
	nvl = sip->si_dsp->ds_predfail;

	for (i = 0; i < log_length; i += plen) {
		iep = (scsi_ie_log_param_t *)((char *)iep + plen);

		/*
		 * Even though we validated the length during the initial phase,
		 * never trust the device.
		 */
		if (BE_16(iep->ie_hdr.lph_param) == LOGPARAM_IE &&
		    iep->ie_hdr.lph_length >= LOGPARAM_IE_MIN_LEN) {
			if (nvlist_add_uint8(nvl, FM_EREPORT_PAYLOAD_SCSI_ASC,
			    iep->ie_asc) != 0 ||
			    nvlist_add_uint8(nvl, FM_EREPORT_PAYLOAD_SCSI_ASCQ,
			    iep->ie_ascq) != 0)
				return (scsi_set_errno(sip, EDS_NOMEM));

			if (iep->ie_asc != 0)
				sip->si_dsp->ds_faults |=
				    DS_FAULT_PREDFAIL;
			break;
		}
		plen = iep->ie_hdr.lph_length +
		    sizeof (scsi_log_parameter_header_t);
	}

	return (0);
}

static int
logpage_temp_analyze(ds_scsi_info_t *sip, scsi_log_parameter_header_t *lphp,
    int log_length)
{
	int i, plen = 0;
	uint8_t reftemp, curtemp;
	ushort_t param_code;
	scsi_temp_log_param_t *temp;
	nvlist_t *nvl;

	assert(sip->si_dsp->ds_overtemp == NULL);
	if (nvlist_alloc(&sip->si_dsp->ds_overtemp, NV_UNIQUE_NAME, 0) != 0)
		return (scsi_set_errno(sip, EDS_NOMEM));
	nvl = sip->si_dsp->ds_overtemp;

	reftemp = curtemp = INVALID_TEMPERATURE;
	for (i = 0; i < log_length; i += plen) {
		lphp = (scsi_log_parameter_header_t *)((char *)lphp + plen);
		param_code = BE_16(lphp->lph_param);
		temp = (scsi_temp_log_param_t *)lphp;

		switch (param_code) {
		case LOGPARAM_TEMP_CURTEMP:
			if (lphp->lph_length != LOGPARAM_TEMP_LEN)
				break;

			if (nvlist_add_uint8(nvl,
			    FM_EREPORT_PAYLOAD_SCSI_CURTEMP,
			    temp->t_temp) != 0)
				return (scsi_set_errno(sip, EDS_NOMEM));
			curtemp = temp->t_temp;
			break;

		case LOGPARAM_TEMP_REFTEMP:
			if (lphp->lph_length != LOGPARAM_TEMP_LEN)
				break;

			if (nvlist_add_uint8(nvl,
			    FM_EREPORT_PAYLOAD_SCSI_THRESHTEMP,
			    temp->t_temp) != 0)
				return (scsi_set_errno(sip, EDS_NOMEM));
			reftemp = temp->t_temp;
			break;
		}

		plen = lphp->lph_length +
		    sizeof (scsi_log_parameter_header_t);
	}

	if (reftemp != INVALID_TEMPERATURE && curtemp != INVALID_TEMPERATURE &&
	    curtemp > reftemp)
		sip->si_dsp->ds_faults |= DS_FAULT_OVERTEMP;

	return (0);
}

static int
logpage_selftest_analyze(ds_scsi_info_t *sip, scsi_log_parameter_header_t *lphp,
    int log_length)
{
	int i, plen = 0;
	int entries = 0;
	ushort_t param_code;
	scsi_selftest_log_param_t *stp;
	nvlist_t *nvl;

	assert(sip->si_dsp->ds_testfail == NULL);
	if (nvlist_alloc(&sip->si_dsp->ds_testfail, NV_UNIQUE_NAME, 0) != 0)
		return (scsi_set_errno(sip, EDS_NOMEM));
	nvl = sip->si_dsp->ds_testfail;

	for (i = 0; i < log_length; i += plen, entries++) {
		lphp = (scsi_log_parameter_header_t *)((char *)lphp + plen);
		param_code = BE_16(lphp->lph_param);
		stp = (scsi_selftest_log_param_t *)lphp;

		if (param_code >= LOGPAGE_SELFTEST_MIN_PARAM_CODE &&
		    param_code <= LOGPAGE_SELFTEST_MAX_PARAM_CODE &&
		    lphp->lph_length >= LOGPAGE_SELFTEST_PARAM_LEN) {
			/*
			 * We always log the last result, or the result of the
			 * last completed test.
			 */
			if ((param_code == 1 ||
			    SELFTEST_COMPLETE(stp->st_results))) {
				if (nvlist_add_uint8(nvl,
				    FM_EREPORT_PAYLOAD_SCSI_RESULTCODE,
				    stp->st_results) != 0 ||
				    nvlist_add_uint16(nvl,
				    FM_EREPORT_PAYLOAD_SCSI_TIMESTAMP,
				    BE_16(stp->st_timestamp)) != 0 ||
				    nvlist_add_uint8(nvl,
				    FM_EREPORT_PAYLOAD_SCSI_SEGMENT,
				    stp->st_number) != 0 ||
				    nvlist_add_uint64(nvl,
				    FM_EREPORT_PAYLOAD_SCSI_ADDRESS,
				    BE_64(stp->st_lba)) != 0)
					return (scsi_set_errno(sip,
					    EDS_NOMEM));

				if (SELFTEST_COMPLETE(stp->st_results)) {
					if (stp->st_results != SELFTEST_OK)
						sip->si_dsp->ds_faults |=
						    DS_FAULT_TESTFAIL;
					return (0);
				}
			}
		}

		plen = lphp->lph_length +
		    sizeof (scsi_log_parameter_header_t);
	}

	return (0);
}

/*
 * Analyze the contents of the Solid State Media (SSM) log page's
 * "Percentage Used Endurance Indicator" log parameter.
 * We generate a fault if the percentage used is equal to or over
 * PRCNT_USED_FAULT_THRSH
 */
static int
logpage_ssm_analyze(ds_scsi_info_t *sip, scsi_log_parameter_header_t *lphp,
    int log_length)
{
	uint16_t param_code;
	scsi_ssm_log_param_t *ssm;
	nvlist_t *nvl;
	int i, plen = 0;

	assert(sip->si_dsp->ds_overtemp == NULL);
	if (nvlist_alloc(&sip->si_dsp->ds_overtemp, NV_UNIQUE_NAME, 0) != 0)
		return (scsi_set_errno(sip, EDS_NOMEM));
	nvl = sip->si_dsp->ds_overtemp;

	for (i = 0; i < log_length; i += plen) {
		lphp = (scsi_log_parameter_header_t *)((uint8_t *)lphp + plen);
		param_code = BE_16(lphp->lph_param);
		ssm = (scsi_ssm_log_param_t *)lphp;

		switch (param_code) {
		case LOGPARAM_PRCNT_USED:
			if (lphp->lph_length != LOGPARAM_PRCNT_USED_PARAM_LEN)
				break;

			if ((nvlist_add_uint8(nvl,
			    FM_EREPORT_PAYLOAD_SCSI_CURSSMWEAROUT,
			    ssm->ssm_prcnt_used) != 0) ||
			    (nvlist_add_uint8(nvl,
			    FM_EREPORT_PAYLOAD_SCSI_THRSHSSMWEAROUT,
			    PRCNT_USED_FAULT_THRSH) != 0))
				return (scsi_set_errno(sip, EDS_NOMEM));

			if (ssm->ssm_prcnt_used >= PRCNT_USED_FAULT_THRSH)
				sip->si_dsp->ds_faults |= DS_FAULT_SSMWEAROUT;

			return (0);
		}

		plen = lphp->lph_length +
		    sizeof (scsi_log_parameter_header_t);
	}

	/*
	 * If we got this far we didn't see LOGPARAM_PRCNT_USED
	 * which is strange since we verified that it's there
	 */
	dprintf("solid state media logpage analyze failed\n");
#if DEBUG
	abort();
#endif
	return (scsi_set_errno(sip, EDS_NOT_SUPPORTED));
}

/*
 * Analyze the IE mode sense page explicitly.  This is only needed if the IE log
 * page is not supported.
 */
static int
analyze_ie_sense(ds_scsi_info_t *sip)
{
	uint_t skey, asc, ascq;
	nvlist_t *nvl;

	/*
	 * Don't bother checking if we weren't able to set our MRIE correctly.
	 */
	if (sip->si_iec_current.ie_mrie != IE_REPORT_ON_REQUEST)
		return (0);

	if (scsi_request_sense(sip, &skey, &asc, &ascq) != 0) {
		dprintf("failed to request IE page (KEY=0x%x ASC=0x%x "
		    "ASCQ=0x%x)\n", skey, asc, ascq);
		return (scsi_set_errno(sip, EDS_IO));
	} else if (skey == KEY_NO_SENSE) {
		assert(sip->si_dsp->ds_predfail == NULL);
		if (nvlist_alloc(&sip->si_dsp->ds_predfail,
		    NV_UNIQUE_NAME, 0) != 0)
			return (scsi_set_errno(sip, EDS_NOMEM));
		nvl = sip->si_dsp->ds_predfail;

		if (nvlist_add_uint8(nvl,
		    FM_EREPORT_PAYLOAD_SCSI_ASC, asc) != 0 ||
		    nvlist_add_uint8(nvl,
		    FM_EREPORT_PAYLOAD_SCSI_ASCQ, ascq) != 0) {
			nvlist_free(nvl);
			return (scsi_set_errno(sip, EDS_NOMEM));
		}

		if (asc != 0)
			sip->si_dsp->ds_faults |= DS_FAULT_PREDFAIL;
	}

	return (0);
}

/*
 * Clean up the scsi-specific information structure.
 */
static void
ds_scsi_close(void *arg)
{
	ds_scsi_info_t *sip = arg;
	if (sip->si_sim)
		(void) dlclose(sip->si_sim);

	free(sip);
}

/*
 * Initialize a single disk.  Initialization consists of:
 *
 * 1. Check to see if the IE mechanism is enabled via MODE SENSE for the IE
 *    Control page (page 0x1C).
 *
 * 2. If the IE page is available, try to set the following parameters:
 *
 *    	DEXCPT		0	Enable exceptions
 *    	MRIE		6	Only report IE information on request
 *    	EWASC		1	Enable warning reporting
 *    	REPORT COUNT	1	Only report an IE exception once
 *    	LOGERR		1	Enable logging of errors
 *
 *    The remaining fields are left as-is, preserving the current values.  If we
 *    cannot set some of these fields, then we do our best.  Some drives may
 *    have a static configuration which still allows for some monitoring.
 *
 * 3. Check to see if the IE log page (page 0x2F) is supported by issuing a
 *    LOG SENSE command.
 *
 * 4. Check to see if the self-test log page (page 0x10) is supported.
 *
 * 5. Check to see if the temperature log page (page 0x0D) is supported, and
 *    contains a reference temperature.
 *
 * 6. Clear the GLTSD bit in control mode page 0xA.  This will allow the drive
 *    to save each of the log pages described above to nonvolatile storage.
 *    This is essential if the drive is to remember its failures across
 *    loss of power.
 */
static void *
ds_scsi_open_common(disk_status_t *dsp, ds_scsi_info_t *sip)
{
	boolean_t changed;

	sip->si_dsp = dsp;

	/* Load and validate mode pages */
	if (load_modepages(sip) != 0) {
		ds_scsi_close(sip);
		return (NULL);
	}

	/* Load and validate log pages */
	if (load_logpages(sip) != 0) {
		ds_scsi_close(sip);
		return (NULL);
	}

	/* Load IE state */
	if (load_ie_modepage(sip) != 0 ||
	    scsi_enable_ie(sip, &changed) != 0 ||
	    (changed && load_ie_modepage(sip) != 0)) {
		ds_scsi_close(sip);
		return (NULL);
	}

	/* Clear the GLTSD bit in the control page */
	if (sip->si_supp_log != 0 && clear_gltsd(sip) != 0) {
		ds_scsi_close(sip);
		return (NULL);
	}

	return (sip);
}

static void *
ds_scsi_open_uscsi(disk_status_t *dsp)
{
	ds_scsi_info_t *sip;

	if ((sip = calloc(sizeof (ds_scsi_info_t), 1)) == NULL) {
		(void) ds_set_errno(dsp, EDS_NOMEM);
		return (NULL);
	}

	return (ds_scsi_open_common(dsp, sip));
}

static void *
ds_scsi_open_sim(disk_status_t *dsp)
{
	ds_scsi_info_t *sip;

	if ((sip = calloc(sizeof (ds_scsi_info_t), 1)) == NULL) {
		(void) ds_set_errno(dsp, EDS_NOMEM);
		return (NULL);
	}

	if ((sip->si_sim = dlopen(dsp->ds_path, RTLD_LAZY)) == NULL) {
		(void) ds_set_errno(dsp, EDS_NO_TRANSPORT);
		free(sip);
		return (NULL);
	}

	return (ds_scsi_open_common(dsp, sip));
}


/*
 * Scan for any faults.  The following steps are performed:
 *
 * 1. If the temperature log page is supported, check the current temperature
 *    and threshold.  If the current temperature exceeds the threshold, report
 *    and overtemp fault.
 *
 * 2. If the selftest log page is supported, check to the last completed self
 *    test.  If the last completed test resulted in failure, report a selftest
 *    fault.
 *
 * 3. If the IE log page is supported, check to see if failure is predicted.  If
 *    so, indicate a predictive failure fault.
 *
 * 4. If the IE log page is not supported, but the mode page supports report on
 *    request mode, then issue a REQUEST SENSE for the mode page.  Indicate a
 *    predictive failure fault if necessary.
 */
static int
ds_scsi_scan(void *arg)
{
	ds_scsi_info_t *sip = arg;
	int i;

	for (i = 0; i < NLOG_VALIDATION; i++) {
		if ((sip->si_supp_log & log_validation[i].ve_supported) == 0)
			continue;

		if (analyze_one_logpage(sip, &log_validation[i]) != 0)
			return (-1);
	}

	if (!(sip->si_supp_log & LOGPAGE_SUPP_IE) &&
	    (sip->si_supp_mode & MODEPAGE_SUPP_IEC) &&
	    analyze_ie_sense(sip) != 0)
		return (-1);

	return (0);
}

ds_transport_t ds_scsi_uscsi_transport = {
	ds_scsi_open_uscsi,
	ds_scsi_close,
	ds_scsi_scan
};

ds_transport_t ds_scsi_sim_transport = {
	ds_scsi_open_sim,
	ds_scsi_close,
	ds_scsi_scan
};
