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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SCSI simulator.
 *
 * For testing purposes, we need a way to simulate arbitrary SCSI responses.  A
 * completely flexible SCSI simulation language would be a large undertaking,
 * given the number of possible outcomes.  Instead, we opt for the simpler route
 * of using a shared object which implements versions of these functions.
 *
 * If a shared object doesn't implement a given function, or if the function
 * returns non-zero, then the simulator will provide a suitable response
 * indicating the functionality isn't supported.
 */

#include <libdiskstatus.h>

#include "ds_scsi.h"
#include "ds_scsi_sim.h"

static int
check_invalid_code(int ret, void *rqbuf)
{
	if (ret != 0) {
		struct scsi_extended_sense *sensep = rqbuf;

		sensep->es_key = KEY_ILLEGAL_REQUEST;
		sensep->es_add_len = 6;
		sensep->es_code = CODE_FMT_FIXED_CURRENT;
		sensep->es_add_code = ASC_INVALID_OPCODE;
		sensep->es_qual_code = ASCQ_INVALID_OPCODE;
		ret = -1;
	}

	return (ret);
}

typedef int (*scsi_mode_sense_f)(int, int, caddr_t, int, scsi_ms_header_t *,
    void *, int *);

int
simscsi_mode_sense(void *hdl, int page_code, int page_control,
    caddr_t page_data, int page_size, scsi_ms_header_t *header,
    void *rqbuf, int *rqblen)
{
	scsi_mode_sense_f dscsi_mode_sense;
	int ret = -1;

	dscsi_mode_sense = (scsi_mode_sense_f)dlsym(hdl, "scsi_mode_sense");

	if (dscsi_mode_sense != NULL)
		ret = (*dscsi_mode_sense)(page_code, page_control, page_data,
		    page_size, header, rqbuf, rqblen);

	return (check_invalid_code(ret, rqbuf));
}

typedef int (*scsi_mode_sense_10_f)(int, int, caddr_t, int,
    scsi_ms_header_g1_t *, void *, int *);

int
simscsi_mode_sense_10(void *hdl, int page_code, int page_control,
    caddr_t page_data, int page_size, scsi_ms_header_g1_t *header,
    void *rqbuf, int *rqblen)
{
	scsi_mode_sense_10_f dscsi_mode_sense_10;
	int ret = -1;

	dscsi_mode_sense_10 = (scsi_mode_sense_10_f)dlsym(hdl,
	    "scsi_mode_sense_10");

	if (dscsi_mode_sense_10 != NULL)
		ret = (*dscsi_mode_sense_10)(page_code, page_control, page_data,
		    page_size, header, rqbuf, rqblen);

	return (check_invalid_code(ret, rqbuf));
}

typedef int (*scsi_mode_select_f)(int, int, caddr_t, int, scsi_ms_header_t *,
    void *, int *);

int
simscsi_mode_select(void *hdl, int page_code, int options, caddr_t page_data,
    int page_size, scsi_ms_header_t *header, void *rqbuf, int *rqblen)
{
	scsi_mode_select_f dscsi_mode_select;
	int ret = -1;

	dscsi_mode_select = (scsi_mode_select_f)(dlsym(hdl,
	    "scsi_mode_select"));

	if (dscsi_mode_select != NULL)
		ret = (*dscsi_mode_select)(page_code, options, page_data,
		    page_size, header, rqbuf, rqblen);

	return (check_invalid_code(ret, rqbuf));
}

typedef int (*scsi_mode_select_10_f)(int, int, caddr_t, int,
    scsi_ms_header_g1_t *, void *, int *);

int
simscsi_mode_select_10(void *hdl, int page_code, int options,
    caddr_t page_data, int page_size, scsi_ms_header_g1_t *header,
    void *rqbuf, int *rqblen)
{
	scsi_mode_select_10_f dscsi_mode_select_10;
	int ret = -1;

	dscsi_mode_select_10 = (scsi_mode_select_10_f)dlsym(hdl,
	    "scsi_mode_select_10");

	if (dscsi_mode_select_10 != NULL)
		ret = (*dscsi_mode_select_10)(page_code, options, page_data,
		    page_size, header, rqbuf, rqblen);

	return (check_invalid_code(ret, rqbuf));
}

typedef int (*scsi_log_sense_f)(int, int, caddr_t, int, void *, int *);

int
simscsi_log_sense(void *hdl, int page_code, int page_control,
    caddr_t page_data, int page_size, void *rqbuf, int *rqblen)
{
	scsi_log_sense_f dscsi_log_sense;
	int ret = -1;

	dscsi_log_sense = (scsi_log_sense_f)dlsym(hdl, "scsi_log_sense");

	if (dscsi_log_sense != NULL)
		ret = (*dscsi_log_sense)(page_code, page_control, page_data,
		    page_size, rqbuf, rqblen);

	return (check_invalid_code(ret, rqbuf));
}

typedef int (*scsi_request_sense_f)(caddr_t, int, void *, int *);

int
simscsi_request_sense(void *hdl, caddr_t buf, int buflen,
    void *rqbuf, int *rqblen)
{
	scsi_request_sense_f dscsi_request_sense;
	int ret = -1;

	dscsi_request_sense = (scsi_request_sense_f)dlsym(hdl,
	    "scsi_request_sense");

	if (dscsi_request_sense != NULL)
		ret = (*dscsi_request_sense)(buf, buflen, rqbuf, rqblen);

	return (check_invalid_code(ret, rqbuf));
}
