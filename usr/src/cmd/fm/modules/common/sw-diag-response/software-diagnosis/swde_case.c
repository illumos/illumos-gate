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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stddef.h>
#include <strings.h>

#include "../common/sw_impl.h"

/*
 * We maintain a single list of all active cases across all
 * subsidary diagnosis "modules".  We also offer some serialization
 * services to them.
 *
 * To open a new case a subsidiary engine should use swde_case_open
 * indicating the subsidiary id (from which we lookup the enum sw_casetype)
 * and, optionally, a pointer to a structure for serialization and its size.
 *
 * For each case opened with swde_case_open we maintain an swde_case_t
 * structure in-core.  Embedded in this is the swde_case_data_t with
 * information we need to keep track of and manage this case - it's
 * case type, buffer name used for the sub-de-private data (if any)
 * and the size of the sub-de-private structure.  It is this
 * embedded structure which is serialized as the "casedata" buffer,
 * while the subsidiary-private structure is serialized into another buffer
 * "casedata_<casetype-in-hex>".
 *
 * The subsidiary-private data structure, if any, is required to start
 * with a uint32_t recording the data structure version.  This
 * version is also specified as an argument to swde_case_open, and
 * we note it in the "casedata" buffer we write out and require
 * a match on restore.
 *
 * When we unserialize we restore our management structure as well as
 * the sub-de-private structure.
 *
 * Here's how serialization works:
 *
 * In swde_case_open we create a case data buffer for the case named
 * SW_CASE_DATA_BUFNAME.  We write the buffer out after filling in the
 * structure version and recording the type of case this is, and if there
 * is data for the subsidiary then we call swde_subdata to note the
 * size and version of that data in the case data buf and then to create
 * and write the subdata in a buffer named SW_CASE_DATA_BUFNAME_<casetype>.
 *
 * If the subsidiary updates its case data it is required to call
 * swde_case_data_write.  This just calls fmd_buf_write for the subsidiary
 * buffer name.
 *
 * A subsidiary can retrieve its private data buffer for a case using
 * swde_case_data.  This also fills a uint32_t with the version of the
 * buffer that we have for this subsidiary;  if that is an old version
 * the subsidiary can cast appropriately and/or upgrade the buffer as
 * below.
 *
 * When the host module is reloaded it calls swde_case_init to iterate
 * through all cases we own.  For each we call swde_case_unserialize
 * which restores our case tracking data and any subsidiary-private
 * data that our case data notes.  We then call swde_case_verify which
 * calls any registered verify function in the subsidiary owner, and if this
 * returns 0 the case is closed.
 *
 * After initial write, we don't usually have to update the
 * SW_CASE_DATA_BUFNAME buffer unless the subsidiary changes the size or
 * version of its private buffer.  To do that the subsidiary must call
 * swde_case_data_upgrade.  In that function we destroy the old subsidiary
 * buffer and, if there is still a subsidiary data structure, create a
 * new buffer appropriately sized and call swde_subdata to write it out
 * after updating our case structure with new size etc.  Finally we write
 * out our updated case data structure.
 */

#define	SW_CASE_DATA_BUFNAME		"casedata"

#define	SW_CASE_DATA_VERSION_INITIAL		1
#define	SW_CASE_DATA_BUFNAMELEN	18	/* 8 + 1 + 8 + 1 */
typedef struct swde_case_data {
	uint32_t sc_version;		/* buffer structure version */
	int32_t sc_type;		/* enum sw_casetype */
	uint32_t sc_sub_bufvers;	/* version expected in subsidiary */
	char sc_sub_bufname[SW_CASE_DATA_BUFNAMELEN];	/* subsidiary bufname */
	int32_t sc_sub_bufsz;		/* subsidiary structure size */
} swde_case_data_t;

#define	SW_CASE_DATA_VERSION		SW_CASE_DATA_VERSION_INITIAL

/*
 * In-core case structure.
 */
typedef struct swde_case {
	fmd_case_t *swc_fmdcase;	/* fmd case handle */
	swde_case_data_t swc_data;	/* case data for serialization */
	void *swc_subdata;		/* subsidiary data for serialization */
} swde_case_t;

static void
swde_case_associate(fmd_hdl_t *hdl, fmd_case_t *cp, swde_case_t *scp,
    void *subdata)
{
	scp->swc_fmdcase = cp;
	scp->swc_subdata = subdata;
	fmd_case_setspecific(hdl, cp, scp);
}

static void
swde_case_unserialize(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	swde_case_t *scp;
	swde_case_data_t *datap;
	void *subdata;
	size_t sz;

	scp = fmd_hdl_zalloc(hdl, sizeof (*scp), FMD_SLEEP);
	datap = &scp->swc_data;

	fmd_buf_read(hdl, cp, SW_CASE_DATA_BUFNAME, datap, sizeof (*datap));

	if (datap->sc_version > SW_CASE_DATA_VERSION_INITIAL) {
		fmd_hdl_free(hdl, scp, sizeof (*scp));
		return;
	}

	if ((sz = datap->sc_sub_bufsz) != 0) {
		subdata = fmd_hdl_alloc(hdl, sz, FMD_SLEEP);
		fmd_buf_read(hdl, cp, datap->sc_sub_bufname, subdata, sz);

		if (*((uint32_t *)subdata) != datap->sc_sub_bufvers) {
			fmd_hdl_abort(hdl, "unserialize: expected subdata "
			    "version %u but received %u\n",
			    datap->sc_sub_bufvers, *((uint32_t *)subdata));
		}
	}

	swde_case_associate(hdl, cp, scp, subdata);
}

static void
swde_subdata(fmd_hdl_t *hdl, fmd_case_t *cp, enum sw_casetype type,
    swde_case_t *scp, uint32_t subdata_vers, void *subdata, size_t subdata_sz)
{
	swde_case_data_t *datap = &scp->swc_data;

	if (*((uint32_t *)subdata) != subdata_vers)
		fmd_hdl_abort(hdl, "swde_subdata: subdata version "
		    "does not match argument\n");

	(void) snprintf(datap->sc_sub_bufname, sizeof (datap->sc_sub_bufname),
	    "%s_%08x", SW_CASE_DATA_BUFNAME, type);

	datap->sc_sub_bufsz = subdata_sz;
	datap->sc_sub_bufvers = subdata_vers;
	fmd_buf_create(hdl, cp, datap->sc_sub_bufname, subdata_sz);
	fmd_buf_write(hdl, cp, datap->sc_sub_bufname, subdata, subdata_sz);
}

fmd_case_t *
swde_case_open(fmd_hdl_t *hdl, id_t who, char *req_uuid,
    uint32_t subdata_vers, void *subdata, size_t subdata_sz)
{
	enum sw_casetype ct = sw_id_to_casetype(hdl, who);
	swde_case_data_t *datap;
	swde_case_t *scp;
	fmd_case_t *cp;

	if (ct == SW_CASE_NONE)
		fmd_hdl_abort(hdl, "swde_case_open for type SW_CASE_NONE\n");

	if (subdata != NULL && subdata_sz <= sizeof (uint32_t) ||
	    subdata_sz != 0 && subdata == NULL)
		fmd_hdl_abort(hdl, "swde_case_open: bad subdata\n", ct);

	scp = fmd_hdl_zalloc(hdl, sizeof (*scp), FMD_SLEEP);
	datap = &scp->swc_data;

	if (req_uuid == NULL) {
		cp = fmd_case_open(hdl, (void *)scp);
	} else {
		cp = fmd_case_open_uuid(hdl, req_uuid, (void *)scp);
		if (cp == NULL) {
			fmd_hdl_free(hdl, scp, sizeof (*scp));
			return (NULL);
		}
	}

	fmd_buf_create(hdl, cp, SW_CASE_DATA_BUFNAME, sizeof (*datap));
	datap->sc_version = SW_CASE_DATA_VERSION_INITIAL;
	datap->sc_type = ct;

	if (subdata)
		swde_subdata(hdl, cp, ct, scp, subdata_vers, subdata,
		    subdata_sz);

	fmd_buf_write(hdl, cp, SW_CASE_DATA_BUFNAME, datap, sizeof (*datap));
	swde_case_associate(hdl, cp, scp, subdata);

	return (cp);
}

/*
 * fmdo_close entry point for software-diagnosis
 */
void
swde_close(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	swde_case_t *scp = fmd_case_getspecific(hdl, cp);
	swde_case_data_t *datap = &scp->swc_data;
	swsub_case_close_func_t *closefunc;

	if ((closefunc = sw_sub_case_close_func(hdl, datap->sc_type)) != NULL)
		closefunc(hdl, cp);

	/*
	 * Now that the sub-de has had a chance to clean up, do some ourselves.
	 * Note that we free the sub-de-private subdata structure.
	 */

	if (scp->swc_subdata) {
		fmd_hdl_free(hdl, scp->swc_subdata, datap->sc_sub_bufsz);
		fmd_buf_destroy(hdl, cp, datap->sc_sub_bufname);
	}

	fmd_buf_destroy(hdl, cp, SW_CASE_DATA_BUFNAME);

	fmd_hdl_free(hdl, scp, sizeof (*scp));
}

fmd_case_t *
swde_case_first(fmd_hdl_t *hdl, id_t who)
{
	enum sw_casetype ct = sw_id_to_casetype(hdl, who);
	swde_case_t *scp;
	fmd_case_t *cp;

	if (ct == SW_CASE_NONE)
		fmd_hdl_abort(hdl, "swde_case_first for type SW_CASE_NONE\n");

	for (cp = fmd_case_next(hdl, NULL); cp; cp = fmd_case_next(hdl, cp)) {
		scp = fmd_case_getspecific(hdl, cp);
		if (scp->swc_data.sc_type == ct)
			break;
	}

	return (cp);
}

fmd_case_t *
swde_case_next(fmd_hdl_t *hdl, fmd_case_t *lastcp)
{
	swde_case_t *scp;
	fmd_case_t *cp;
	int ct;

	if (lastcp == NULL)
		fmd_hdl_abort(hdl, "swde_case_next called for NULL lastcp\n");

	scp = fmd_case_getspecific(hdl, lastcp);
	ct = scp->swc_data.sc_type;

	cp = lastcp;
	while ((cp = fmd_case_next(hdl, cp)) != NULL) {
		scp = fmd_case_getspecific(hdl, cp);
		if (scp->swc_data.sc_type == ct)
			break;
	}

	return (cp);
}

void *
swde_case_data(fmd_hdl_t *hdl, fmd_case_t *cp, uint32_t *svp)
{
	swde_case_t *scp = fmd_case_getspecific(hdl, cp);
	swde_case_data_t *datap = &scp->swc_data;

	if (svp != NULL && scp->swc_subdata)
		*svp = datap->sc_sub_bufvers;

	return (scp->swc_subdata);
}

void
swde_case_data_write(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	swde_case_t *scp = fmd_case_getspecific(hdl, cp);
	swde_case_data_t *datap = &scp->swc_data;

	if (scp->swc_subdata == NULL)
		return;

	fmd_buf_write(hdl, cp, scp->swc_data.sc_sub_bufname,
	    scp->swc_subdata, datap->sc_sub_bufsz);
}

void
swde_case_data_upgrade(fmd_hdl_t *hdl, fmd_case_t *cp, uint32_t subdata_vers,
    void *subdata, size_t subdata_sz)
{
	swde_case_t *scp = fmd_case_getspecific(hdl, cp);
	swde_case_data_t *datap = &scp->swc_data;

	if (scp->swc_subdata) {
		fmd_buf_destroy(hdl, cp, datap->sc_sub_bufname);
		fmd_hdl_free(hdl, scp->swc_subdata, datap->sc_sub_bufsz);
		scp->swc_subdata = NULL;
		datap->sc_sub_bufsz = 0;
		datap->sc_sub_bufname[0] = '\0';
	}

	if (subdata != NULL) {
		scp->swc_subdata = subdata;
		swde_subdata(hdl, cp, datap->sc_type, scp, subdata_vers,
		    subdata, subdata_sz);
	}

	fmd_buf_write(hdl, scp->swc_fmdcase, SW_CASE_DATA_BUFNAME,
	    datap, sizeof (*datap));
}

static void
swde_case_verify(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	swde_case_t *scp = fmd_case_getspecific(hdl, cp);
	swde_case_data_t *datap = &scp->swc_data;
	sw_case_vrfy_func_t *vrfy_func;

	if ((vrfy_func = sw_sub_case_vrfy_func(hdl, datap->sc_type)) != NULL) {
		if (vrfy_func(hdl, cp) == 0)
			fmd_case_close(hdl, cp);
	}
}

void
swde_case_init(fmd_hdl_t *hdl)
{
	fmd_case_t *cp;

	for (cp = fmd_case_next(hdl, NULL); cp; cp = fmd_case_next(hdl, cp)) {
		swde_case_unserialize(hdl, cp);
		swde_case_verify(hdl, cp);
	}
}

/*ARGSUSED*/
void
swde_case_fini(fmd_hdl_t *hdl)
{
}
