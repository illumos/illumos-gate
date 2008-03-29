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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <libnvpair.h>

#include <scsi/libses.h>
#include "ses2_impl.h"

#define	SES_UCODE_CHUNK_SIZE	(32 * 1024)

/*ARGSUSED*/
static int
enc_do_ucode(ses_plugin_t *sp, ses_node_t *np, nvlist_t *nvl)
{
	nvlist_t *props = ses_node_props(np);
	uint64_t maxlen, bufid = 0;
	uint8_t *data;
	ses2_ucode_ctl_page_impl_t *uip;
	size_t offset, len, pagelen;
	uint_t datalen;
	uint64_t mode;

	/*
	 * Get the data and check the length.
	 */
	if (nvlist_lookup_byte_array(nvl, SES_CTL_PROP_UCODE_DATA,
	    &data, &datalen) != 0)
		return (ses_error(ESES_INVALID_PROP,
		    "missing or invalid %s property", SES_CTL_PROP_UCODE_DATA));

	if (nvlist_lookup_uint64(nvl, SES_CTL_PROP_UCODE_MODE,
	    &mode) != 0)
		return (ses_error(ESES_INVALID_PROP,
		    "missing or invalid %s property", SES_CTL_PROP_UCODE_MODE));

	if (nvlist_lookup_uint64(props, SES_EN_PROP_UCODE_SZ,
	    &maxlen) != 0 || datalen > maxlen)
		return (ses_error(ESES_RANGE,
		    "microcode image length (%u) exceeds maximum length (%llu)",
		    datalen, maxlen));

	/*
	 * Get the expected buffer ID, but allow the user to override it.
	 */
	(void) nvlist_lookup_uint64(props, SES_EN_PROP_UCODE_BUF,
	    &bufid);

	if (bufid == 0xFF)
		bufid = 0;

	(void) nvlist_lookup_uint64(nvl, SES_CTL_PROP_UCODE_BUFID, &bufid);

	for (offset = 0; offset < datalen; offset += SES_UCODE_CHUNK_SIZE)  {

		len = MIN(datalen - offset, SES_UCODE_CHUNK_SIZE);
		if (len & 0x3)
			pagelen = (len + 4) & 0x3;
		else
			pagelen = len;

		if ((uip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
		    SES2_DIAGPAGE_DL_MICROCODE_CTL_STATUS, pagelen,
		    np, B_TRUE)) == NULL)
			return (-1);

		uip->sucpi_buffer_id = (uint8_t)bufid;
		uip->sucpi_dl_ucode_mode = mode;
		SCSI_WRITE32(&uip->sucpi_buffer_offset, offset);
		SCSI_WRITE32(&uip->sucpi_ucode_image_length, datalen);
		SCSI_WRITE32(&uip->sucpi_ucode_data_length, len);

		bcopy(data + offset, &uip->sucpi_ucode_data[0],
		    len);

		if (len != pagelen)
			bzero(&uip->sucpi_ucode_data[0] + len,
			    pagelen - len);
	}

	(void) nvlist_remove_all(nvl, SES_CTL_PROP_UCODE_DATA);
	(void) nvlist_remove_all(nvl, SES_CTL_PROP_UCODE_MODE);
	(void) nvlist_remove_all(nvl, SES_CTL_PROP_UCODE_BUFID);

	return (0);
}

static int
enc_ctl_common(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_enclosure_ctl_impl_t *tp;
	const char *name;
	boolean_t boolval;
	uint64_t intval;

	ASSERT(page == SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS);

	if ((tp = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &boolval);
	(void) nvpair_value_uint64(nvp, &intval);

	if (strcmp(name, SES_PROP_IDENT) == 0)
		tp->seci_rqst_ident = boolval;
	else if (strcmp(name, SES_PROP_WARN_REQ) == 0)
		tp->seci_request_warning = boolval;
	else if (strcmp(name, SES_PROP_FAIL_REQ) == 0)
		tp->seci_request_failure = boolval;
	else if (strcmp(name, SES_EN_PROP_POWER_DELAY) == 0)
		tp->seci_power_cycle_delay = intval;
	else if (strcmp(name, SES_EN_PROP_POWER_REQUEST) == 0)
		tp->seci_power_cycle_request = intval;
	else if (strcmp(name, SES_EN_PROP_POWER_DURATION) == 0)
		tp->seci_power_off_duration = intval;
	else
		ses_panic("bad property %s", name);

	return (0);
}

/*ARGSUSED*/
static int
enc_ctl_string(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_substring_out_page_impl_t *spip;
	ses2_string_out_page_impl_t *pip;
	const uint8_t *data;
	size_t datalen;
	uint_t nvlen;
	nvlist_t *props = ses_node_props(np);
	uint64_t eid;

	ASSERT(strcmp(nvpair_name(nvp), SES_EN_PROP_STRING) == 0);

	VERIFY(nvlist_lookup_uint64(props, SES_EN_PROP_EID, &eid) == 0);

	(void) nvpair_value_byte_array(nvp, (uint8_t **)&data, &nvlen);
	datalen = (size_t)nvlen;

	if ((spip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    SES2_DIAGPAGE_SUBENCLOSURE_STRING_IO, datalen, np,
	    B_FALSE)) != NULL) {
		spip->ssopi_subenclosure_identifier = eid;
		bcopy(data, spip->ssopi_data, datalen);
	} else {
		if (eid != 0)
			return (ses_error(ESES_NOTSUP, "target does not "
			    "support string data for secondary subenclosures"));

		if ((pip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
		    SES2_DIAGPAGE_STRING_IO, datalen, np, B_FALSE)) == NULL)
			return (-1);

		bcopy(data, pip->ssopi_data, datalen);
	}

	return (0);
}

static int
enc_ctl_nick(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	/* LINTED - dummy variable for sizeof */
	ses2_subnick_ctl_page_impl_t *pip, dummy;
	const char *nick;
	size_t len, max;
	nvlist_t *props = ses_node_props(np);
	uint64_t eid;

	ASSERT(strcmp(nvpair_name(nvp), SES_EN_PROP_NICK) == 0);
	ASSERT(page == SES2_DIAGPAGE_SUBENCLOSURE_NICKNAME_CTL_STATUS);

	(void) nvpair_value_string(nvp, (char **)&nick);
	len = strlen(nick);

	VERIFY(nvlist_lookup_uint64(props, SES_EN_PROP_EID, &eid) == 0);

	max = sizeof (dummy.sspci_subenclosure_nickname);
	if (len > max)
		return (ses_error(ESES_RANGE, "nickname '%s' exceeds "
		    "maximum length %lu", nick, max));

	if ((pip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, len, np, B_FALSE)) == NULL)
		return (-1);

	pip->sspci_subenclosure_identifier = eid;
	bcopy(nick, pip->sspci_subenclosure_nickname, len);

	return (0);
}

static const ses2_ctl_prop_t enc_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = enc_ctl_common
},
{
	.scp_name = SES_PROP_WARN_REQ,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = enc_ctl_common
},
{
	.scp_name = SES_PROP_FAIL_REQ,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = enc_ctl_common
},
{
	.scp_name = SES_EN_PROP_POWER_DELAY,
	.scp_type = DATA_TYPE_UINT64,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = enc_ctl_common
},
{
	.scp_name = SES_EN_PROP_POWER_DURATION,
	.scp_type = DATA_TYPE_UINT64,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = enc_ctl_common
},
{
	.scp_name = SES_EN_PROP_POWER_REQUEST,
	.scp_type = DATA_TYPE_UINT64,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = enc_ctl_common
},
{
	.scp_name = SES_EN_PROP_STRING,
	.scp_type = DATA_TYPE_BYTE_ARRAY,
	.scp_num = -1,
	.scp_setprop = enc_ctl_string
},
{
	.scp_name = SES_EN_PROP_NICK,
	.scp_type = DATA_TYPE_STRING,
	.scp_num = SES2_DIAGPAGE_SUBENCLOSURE_NICKNAME_CTL_STATUS,
	.scp_setprop = enc_ctl_nick
},
{
	NULL
}
};

static int
enc_setdef_one(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_enclosure_ctl_impl_t *tp = data;
	nvlist_t *props = ses_node_props(np);

	if (page != SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS)
		return (0);

	SES_NV_CTLBOOL(props, SES_PROP_IDENT, tp->seci_rqst_ident);
	SES_NV_CTLBOOL(props, SES_PROP_WARN_REQ,
	    tp->seci_request_warning);
	SES_NV_CTLBOOL(props, SES_PROP_FAIL_REQ,
	    tp->seci_request_failure);

	return (0);
}

int
ses2_enclosure_ctl(ses_plugin_t *sp, ses_node_t *np, const char *op,
    nvlist_t *nvl)
{
	if (strcmp(op, SES_CTL_OP_SETPROP) == 0)
		return (ses2_setprop(sp, np, enc_props, nvl));
	else if (strcmp(op, SES_CTL_OP_DL_UCODE) == 0)
		return (enc_do_ucode(sp, np, nvl));

	return (0);
}

int
ses2_enclosure_setdef(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	nvlist_t *props = ses_node_props(np);
	uint64_t type;

	VERIFY(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_TYPE, &type) == 0);

	if (type == SES_ET_ENCLOSURE &&
	    enc_setdef_one(np, page, data) != 0)
		return (-1);

	return (0);
}
