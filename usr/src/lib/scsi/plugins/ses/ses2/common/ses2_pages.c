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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2019 RackTop Systems
 */

#include <stddef.h>
#include <strings.h>

#include <scsi/libses.h>
#include <scsi/libses_plugin.h>
#include <scsi/plugins/ses/framework/ses2.h>

#include "ses2_impl.h"

static int
ses2_ctl_common_setdef(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_cmn_elem_ctl_impl_t *eip = data;
	nvlist_t *props = ses_node_props(np);

	if (page != SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS)
		return (0);

	SES_NV_CTLBOOL_INVERT(props, SES_PROP_SWAP, eip->seci_rst_swap);
	SES_NV_CTLBOOL(props, SES_PROP_DISABLED, eip->seci_disable);
	SES_NV_CTLBOOL(props, SES_PROP_PRDFAIL, eip->seci_prdfail);

	eip->seci_select = 1;

	return (0);
}

/*ARGSUSED*/
static void *
ses2_aes_index(ses_plugin_t *sp, ses_node_t *np, void *data, size_t pagelen,
    size_t *len)
{
	ses2_aes_page_impl_t *apip = data;
	uint64_t index, eindex, oindex, type;
	nvlist_t *props = ses_node_props(np);
	ses2_aes_descr_eip_impl_t *dep;
	size_t desclen;
	int i, pos;

	VERIFY(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_ONLY_INDEX,
	    &eindex) == 0);
	VERIFY(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_INDEX,
	    &oindex) == 0);
	VERIFY(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_TYPE,
	    &type) == 0);

	if (pagelen < offsetof(ses2_aes_page_impl_t, sapi_data))
		return (0);

	for (dep = (ses2_aes_descr_eip_impl_t *)apip->sapi_data, pos = 0, i = 0;
	    pos < SCSI_READ16(&apip->sapi_page_length);
	    dep = (ses2_aes_descr_eip_impl_t *)(apip->sapi_data + pos), i++) {
		if (!SES_WITHIN_PAGE_STRUCT(dep, data, pagelen))
			break;

		desclen = dep->sadei_length +
		    offsetof(ses2_aes_descr_eip_impl_t, sadei_length) +
		    sizeof (dep->sadei_length);

		if (!SES_WITHIN_PAGE(dep, desclen, data, pagelen))
			break;

		if (dep->sadei_eip) {
			/*
			 * The following switch table deals with the cases
			 * for the EIIOE (element index includes overall
			 * elements).  The treatment for this includes handling
			 * connector and other element indices, but we don't
			 * actually care about or use them, so for now we
			 * really only care about the ELEMENT INDEX field.
			 */
			switch (dep->sadei_eiioe) {
			case 1:
				/*
				 * Use the overall index.  We expect most
				 * modern implementations to use this case.
				 */
				index = oindex;
				break;
			case 0:
			case 2:
			case 3:
				/*
				 * Use the element only index - excluding
				 * the overall elements.
				 */
				index = eindex;
				break;
			}
		}
		pos += desclen;
		if (!dep->sadei_eip &&
		    type != SES_ET_DEVICE &&
		    type != SES_ET_ARRAY_DEVICE) {
			/*
			 * We can't really do anything with this, because
			 * while the standard requires that these descriptors
			 * be in the same order as those in the status page,
			 * some element types may optionally include AES
			 * data.  This means we cannot know which element
			 * this descriptor refers to unless EIP is 1.  Sadly,
			 * the standard only says that this "should" be true.
			 * It's impossible to guess what use this is supposed
			 * to have otherwise.  See 6.1.13.1.
			 */
			continue;
		} else if (dep->sadei_eip) {
			if (dep->sadei_element_index == index) {
				*len = desclen;
				return (dep);
			}
			/*
			 * The element index field from AES descriptor is
			 * element only index which doesn't include the OVERALL
			 * STATUS fields so we should compare with
			 * SES_PROP_ELEMENT_ONLY_INDEX not
			 * SES_PROP_ELEMENT_INDEX.
			 */
			continue;
		} else if (i == eindex) {
			*len = desclen;
			return (dep);
		}
	}

	return (NULL);
}

/*ARGSUSED*/
static void *
ses2_threshold_index(ses_plugin_t *sp, ses_node_t *np, void *data,
    size_t pagelen, size_t *len)
{
	uint64_t index;
	nvlist_t *props = ses_node_props(np);
	ses2_threshold_in_page_impl_t *tpip = data;
	ses2_threshold_impl_t *tp;

	VERIFY(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_INDEX,
	    &index) == 0);

	*len = sizeof (ses2_threshold_impl_t);
	tp = &tpip->stipi_thresholds[index];

	if (!SES_WITHIN_PAGE_STRUCT(tp, data, pagelen))
		return (NULL);

	return (&tpip->stipi_thresholds[index]);
}

/*ARGSUSED*/
static void *
ses2_element_index(ses_plugin_t *sp, ses_node_t *np, void *data,
    size_t pagelen, size_t *len)
{
	uint64_t index;
	nvlist_t *props = ses_node_props(np);
	ses2_elem_desc_page_impl_t *edip = data;
	ses2_elem_descriptor_impl_t *dp;
	int i;
	uint16_t dlen;

	if (nvlist_lookup_uint64(props, SES_PROP_ELEMENT_INDEX, &index) != 0)
		return (NULL);

	if (!SES_WITHIN_PAGE(data, sizeof (*dp), data, pagelen))
		return (NULL);

	/*
	 * This variable-length list of variable-length strings format sucks
	 * for performance; we ALWAYS have to walk the whole bloody thing to
	 * find a particular node's entry.
	 */
	for (i = 0, dp = (ses2_elem_descriptor_impl_t *)edip->sedpi_data;
	    i < index; i++) {

		if (!SES_WITHIN_PAGE_STRUCT(dp, data, pagelen))
			return (NULL);

		dlen = SCSI_READ16(&dp->sedi_descriptor_length);

		dp = (ses2_elem_descriptor_impl_t *)
		    ((uint8_t *)dp->sedi_descriptor + dlen);
	}

	if (!SES_WITHIN_PAGE_STRUCT(dp, data, pagelen))
		return (NULL);

	*len = SCSI_READ16(&dp->sedi_descriptor_length);

	if (!SES_WITHIN_PAGE(dp,
	    *len + offsetof(ses2_elem_descriptor_impl_t, sedi_descriptor),
	    data, pagelen))
		return (NULL);

	return (dp->sedi_descriptor);
}

/*ARGSUSED*/
static void *
ses2_status_index(ses_plugin_t *sp, ses_node_t *np, void *data,
    size_t pagelen, size_t *len)
{
	uint64_t index;
	nvlist_t *props = ses_node_props(np);
	ses2_status_page_impl_t *spip = data;

	if (nvlist_lookup_uint64(props, SES_PROP_ELEMENT_INDEX,
	    &index) != 0)
		return (NULL);

	if ((index + 1) * sizeof (ses2_elem_status_impl_t) +
	    offsetof(ses2_status_page_impl_t, sspi_data) > pagelen)
		return (NULL);

	*len = sizeof (ses2_elem_status_impl_t);
	return ((ses2_elem_status_impl_t *)spip->sspi_data + index);
}

/*ARGSUSED*/
static size_t
ses2_ctl_len(uint_t nelem, int page, size_t datalen)
{
	ASSERT(page == SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS);

	return (nelem * sizeof (ses2_elem_ctl_impl_t) +
	    offsetof(ses2_control_page_impl_t, scpi_data[0]));
}

/*ARGSUSED*/
static void *
ses2_ctl_fill(ses_plugin_t *sp, void *pagedata, size_t pagelen,
    ses_node_t *np)
{
	uint64_t index;
	nvlist_t *props = ses_node_props(np);
	ses2_control_page_impl_t *pip = pagedata;
	ses2_elem_ctl_impl_t *eip;
	void *data;
	ses2_diag_page_t page = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS;

	if (nvlist_lookup_uint64(props, SES_PROP_ELEMENT_INDEX,
	    &index) != 0) {
		(void) ses_error(ESES_BAD_RESPONSE, "missing element index "
		    "for enclosure node");
		return (NULL);
	}

	data = eip = &pip->scpi_data[index];
	/*
	 * if control element was already modified "select" field is non-zero,
	 * so skip setting default values to avoid fields overriding
	 */
	if (eip->seci_common.seci_select)
		return (data);

	if (ses2_ctl_common_setdef(np, page, data) != 0 ||
	    ses2_element_setdef(np, page, data) != 0 ||
	    ses2_enclosure_setdef(np, page, data) != 0)
		return (NULL);

	return (data);
}

/*ARGSUSED*/
static size_t
ses2_stringout_len(uint_t nelem, int page, size_t datalen)
{
	ASSERT(page == SES2_DIAGPAGE_STRING_IO);

	return (datalen + offsetof(ses2_string_out_page_impl_t, ssopi_data[0]));
}

/*ARGSUSED*/
static size_t
ses2_threshout_len(uint_t nelem, int page, size_t datalen)
{
	ASSERT(page == SES2_DIAGPAGE_THRESHOLD_IO);

	return (nelem * sizeof (ses2_threshold_impl_t) +
	    offsetof(ses2_threshold_out_page_impl_t, stopi_thresholds[0]));
}

/*ARGSUSED*/
static void *
ses2_threshout_ctl_fill(ses_plugin_t *sp, void *pagedata, size_t pagelen,
    ses_node_t *np)
{
	uint64_t index;
	nvlist_t *props = ses_node_props(np);
	ses2_threshold_out_page_impl_t *pip = pagedata;
	ses2_threshold_impl_t *tip;
	ses2_diag_page_t page = SES2_DIAGPAGE_THRESHOLD_IO;
	void *data;

	VERIFY(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_INDEX,
	    &index) == 0);

	data = tip = &pip->stopi_thresholds[index];

	/* check if threshold is dirty, so no need to set default values */
	if ((tip->sti_high_crit | tip->sti_low_crit | tip->sti_high_warn |
	    tip->sti_low_warn) != 0)
		return (data);

	if (ses2_element_setdef(np, page, data) != 0)
		return (NULL);

	return (data);
}

/*ARGSUSED*/
static size_t
ses2_substrout_len(uint_t nelem, int page, size_t datalen)
{
	ASSERT(page == SES2_DIAGPAGE_SUBENCLOSURE_STRING_IO);

	return (datalen +
	    offsetof(ses2_substring_out_page_impl_t, ssopi_data[0]));
}

/*ARGSUSED*/
static size_t
ses2_ucodeout_len(uint_t nelem, int page, size_t datalen)
{
	size_t len;

	ASSERT(page == SES2_DIAGPAGE_DL_MICROCODE_CTL_STATUS);

	len = datalen +
	    offsetof(ses2_ucode_ctl_page_impl_t, sucpi_ucode_data[0]);

	return (P2ROUNDUP(len, 4));
}

/*ARGSUSED*/
static void *
ses2_ucodeout_ctl_fill(ses_plugin_t *sp, void *data, size_t pagelen,
    ses_node_t *np)
{
	ses_snap_t *snap = ses_node_snapshot(np);
	nvlist_t *props = ses_node_props(np);
	ses2_ucode_ctl_page_impl_t *uip = data;
	uint64_t eid;

	if (ses_node_type(np) != SES_NODE_ENCLOSURE) {
		(void) ses_error(ESES_BAD_TYPE,
		    "microcode download page only valid for enclosure "
		    "nodes");
		return (NULL);
	}

	VERIFY(nvlist_lookup_uint64(props, SES_EN_PROP_EID, &eid) == 0);

	SCSI_WRITE32(&uip->sucpi_generation_code,
	    ses_snap_generation(snap));
	uip->sucpi_subenclosure_identifier = eid;

	return (data);
}

/*ARGSUSED*/
static size_t
ses2_subnickout_len(uint_t nelem, int page, size_t datalen)
{
	ASSERT(page == SES2_DIAGPAGE_SUBENCLOSURE_NICKNAME_CTL_STATUS);

	return (sizeof (ses2_subnick_ctl_page_impl_t));
}

ses_pagedesc_t ses2_pages[] = {
{
	.spd_pagenum = SES2_DIAGPAGE_SUPPORTED_PAGES,
	.spd_req = SES_REQ_MANDATORY_ALL,
	.spd_gcoff = -1
},
{
	.spd_pagenum = SES2_DIAGPAGE_CONFIG,
	.spd_req = SES_REQ_MANDATORY_STANDARD,
	.spd_gcoff = offsetof(ses2_config_page_impl_t, scpi_generation_code)
},
{
	.spd_pagenum = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.spd_req = SES_REQ_MANDATORY_STANDARD,
	.spd_index = ses2_status_index,
	.spd_gcoff = offsetof(ses2_status_page_impl_t, sspi_generation_code)
},
{
	.spd_pagenum = SES2_DIAGPAGE_HELP_TEXT,
	.spd_req = SES_REQ_OPTIONAL_STANDARD,
	.spd_gcoff = -1
},
{
	.spd_pagenum = SES2_DIAGPAGE_STRING_IO,
	.spd_req = SES_REQ_OPTIONAL_STANDARD,
	.spd_gcoff = -1
},
{
	.spd_pagenum = SES2_DIAGPAGE_THRESHOLD_IO,
	.spd_index = ses2_threshold_index,
	.spd_req = SES_REQ_OPTIONAL_STANDARD,
	.spd_gcoff =
	    offsetof(ses2_threshold_in_page_impl_t, stipi_generation_code)
},
{
	.spd_pagenum = SES2_DIAGPAGE_ELEMENT_DESC,
	.spd_index = ses2_element_index,
	.spd_req = SES_REQ_OPTIONAL_STANDARD,
	.spd_gcoff = offsetof(ses2_elem_desc_page_impl_t, sedpi_generation_code)
},
{
	.spd_pagenum = SES2_DIAGPAGE_ADDL_ELEM_STATUS,
	.spd_index = ses2_aes_index,
	.spd_req = SES_REQ_OPTIONAL_STANDARD,
	.spd_gcoff = offsetof(ses2_aes_page_impl_t, sapi_generation_code)
},
{
	.spd_pagenum = SES2_DIAGPAGE_SUBENCLOSURE_HELP_TEXT,
	.spd_req = SES_REQ_OPTIONAL_STANDARD,
	.spd_gcoff = offsetof(ses2_subhelp_page_impl_t, sspi_generation_code)
},
{
	.spd_pagenum = SES2_DIAGPAGE_SUBENCLOSURE_STRING_IO,
	.spd_req = SES_REQ_OPTIONAL_STANDARD,
	.spd_gcoff =
	    offsetof(ses2_substring_in_page_impl_t, ssipi_generation_code)
},
{
	.spd_pagenum = SES2_DIAGPAGE_SUPPORTED_SES_PAGES,
	.spd_req = SES_REQ_OPTIONAL_STANDARD,
	.spd_gcoff = -1
},
{
	.spd_pagenum = SES2_DIAGPAGE_DL_MICROCODE_CTL_STATUS,
	.spd_req = SES_REQ_OPTIONAL_STANDARD,
	.spd_gcoff =
	    offsetof(ses2_ucode_status_page_impl_t, suspi_generation_code)
},
{
	.spd_pagenum = SES2_DIAGPAGE_SUBENCLOSURE_NICKNAME_CTL_STATUS,
	.spd_req = SES_REQ_OPTIONAL_STANDARD,
	.spd_gcoff =
	    offsetof(ses2_subnick_status_page_impl_t, sspci_generation_code)
},
/* Control pages */
{
	.spd_pagenum = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.spd_ctl_len = ses2_ctl_len,
	.spd_ctl_fill = ses2_ctl_fill,
	.spd_req = SES_REQ_MANDATORY_STANDARD,
	.spd_gcoff = offsetof(ses2_control_page_impl_t, scpi_generation_code)
},
{
	.spd_pagenum = SES2_DIAGPAGE_STRING_IO,
	.spd_ctl_len = ses2_stringout_len,
	.spd_req = SES_REQ_OPTIONAL_STANDARD,
	.spd_gcoff = -1
},
{
	.spd_pagenum = SES2_DIAGPAGE_THRESHOLD_IO,
	.spd_ctl_len = ses2_threshout_len,
	.spd_ctl_fill = ses2_threshout_ctl_fill,
	.spd_req = SES_REQ_OPTIONAL_STANDARD,
	.spd_gcoff =
	    offsetof(ses2_threshold_out_page_impl_t, stopi_generation_code)
},
{
	.spd_pagenum = SES2_DIAGPAGE_SUBENCLOSURE_STRING_IO,
	.spd_ctl_len = ses2_substrout_len,
	.spd_req = SES_REQ_OPTIONAL_STANDARD,
	.spd_gcoff =
	    offsetof(ses2_substring_out_page_impl_t, ssopi_generation_code)
},
{
	.spd_pagenum = SES2_DIAGPAGE_DL_MICROCODE_CTL_STATUS,
	.spd_ctl_len = ses2_ucodeout_len,
	.spd_ctl_fill = ses2_ucodeout_ctl_fill,
	.spd_req = SES_REQ_OPTIONAL_STANDARD,
	.spd_gcoff =
	    offsetof(ses2_ucode_ctl_page_impl_t, sucpi_generation_code)
},
{
	.spd_pagenum = SES2_DIAGPAGE_SUBENCLOSURE_NICKNAME_CTL_STATUS,
	.spd_ctl_len = ses2_subnickout_len,
	.spd_req = SES_REQ_OPTIONAL_STANDARD,
	.spd_gcoff =
	    offsetof(ses2_subnick_ctl_page_impl_t, sspci_generation_code)
},
{
	.spd_pagenum = -1,
	.spd_gcoff = -1
}
};
