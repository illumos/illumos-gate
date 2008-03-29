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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <libnvpair.h>

#include <scsi/libses.h>
#include <scsi/plugins/ses/framework/ses2_impl.h>

static int
enc_parse_sd(ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_enclosure_status_impl_t *sdp;
	int nverr;

	sdp = (ses2_enclosure_status_impl_t *)esip;

	SES_NV_ADD(uint64, nverr, nvl, SES_PROP_STATUS_CODE,
	    sdp->sesi_common.sesi_status_code);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_SWAP,
	    sdp->sesi_common.sesi_swap);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_DISABLED,
	    sdp->sesi_common.sesi_disabled);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_PRDFAIL,
	    sdp->sesi_common.sesi_prdfail);

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT, sdp->sesi_ident);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_WARN,
	    sdp->sesi_warning_indication);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL,
	    sdp->sesi_failure_indication);
	SES_NV_ADD(uint64, nverr, nvl, SES_EN_PROP_POWER_DELAY,
	    sdp->sesi_power_delay);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_WARN_REQ,
	    sdp->sesi_warning_requested);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL_REQ,
	    sdp->sesi_warning_requested);
	SES_NV_ADD(uint64, nverr, nvl, SES_EN_PROP_POWER_DURATION,
	    sdp->sesi_power_duration);

	return (0);
}

static int
enc_parse_help(ses_plugin_t *sp, ses_node_t *np)
{
	ses_snap_t *snap = ses_node_snapshot(np);
	ses2_help_page_impl_t *hpip;
	ses2_subhelp_page_impl_t *shpip;
	ses2_subhelp_text_impl_t *tip;
	nvlist_t *nvl = ses_node_props(np);
	uint64_t eid;
	size_t len;
	off_t pos;
	int nverr;

	if (nvlist_lookup_uint64(nvl, SES_EN_PROP_EID, &eid) != 0)
		return (0);

	if ((shpip = ses_plugin_page_lookup(sp, snap,
	    SES2_DIAGPAGE_SUBENCLOSURE_HELP_TEXT, np, &len)) != NULL) {
		pos = 0;
		for (tip = (ses2_subhelp_text_impl_t *)shpip->sspi_data;
		    pos < SCSI_READ16(&shpip->sspi_page_length);
		    pos += SES2_SUBHELP_LEN(tip),
		    tip = (ses2_subhelp_text_impl_t *)((uint8_t *)tip + pos)) {
			if (!SES_WITHIN_PAGE_STRUCT(tip, shpip, len))
				break;

			if (tip->ssti_subenclosure_identifier != eid)
				continue;

			if (!SES_WITHIN_PAGE(tip->ssti_subenclosure_help_text,
			    tip->ssti_subenclosure_help_text_length, shpip,
			    len))
				break;

			SES_NV_ADD(fixed_string, nverr, nvl, SES_EN_PROP_HELP,
			    tip->ssti_subenclosure_help_text,
			    tip->ssti_subenclosure_help_text_length);
			return (0);
		}
	}

	if (eid == 0 && (hpip = ses_plugin_page_lookup(sp, snap,
	    SES2_DIAGPAGE_HELP_TEXT, np, &len)) != NULL) {
		if (!SES_WITHIN_PAGE_STRUCT(hpip, hpip, len))
			return (0);

		if (!SES_WITHIN_PAGE(hpip->shpi_help_text,
		    SCSI_READ16(&hpip->shpi_page_length), hpip, len))
			return (0);

		SES_NV_ADD(fixed_string, nverr, nvl, SES_EN_PROP_HELP,
		    hpip->shpi_help_text, SCSI_READ16(&hpip->shpi_page_length));
	}

	return (0);
}

static int
enc_parse_string_in(ses_plugin_t *sp, ses_node_t *np)
{
	ses_snap_t *snap = ses_node_snapshot(np);
	ses2_string_in_page_impl_t *sip;
	ses2_substring_in_page_impl_t *ssip;
	ses2_substring_in_data_impl_t *dip;
	nvlist_t *nvl = ses_node_props(np);
	uint64_t eid;
	off_t pos;
	size_t len, textlen;
	int nverr;

	if (nvlist_lookup_uint64(nvl, SES_EN_PROP_EID, &eid) != 0)
		return (0);

	if ((ssip = ses_plugin_page_lookup(sp, snap,
	    SES2_DIAGPAGE_SUBENCLOSURE_STRING_IO, np, &len)) != NULL) {
		pos = 0;
		for (dip = (ses2_substring_in_data_impl_t *)ssip->ssipi_data;
		    pos < SCSI_READ16(&ssip->ssipi_page_length);
		    pos += SES2_SUBSTR_LEN(dip),
		    dip = (ses2_substring_in_data_impl_t *)
		    ((uint8_t *)dip + pos)) {
			if (!SES_WITHIN_PAGE_STRUCT(dip, ssip, len))
				break;

			if (dip->ssidi_subenclosure_identifier != eid)
				continue;

			if (!SES_WITHIN_PAGE(dip->ssidi_data,
			    dip->ssidi_substring_data_length, ssip, len))
				break;

			SES_NV_ADD(fixed_string, nverr, nvl, SES_EN_PROP_STRING,
			    (char *)dip->ssidi_data,
			    dip->ssidi_substring_data_length);
			return (0);
		}
	}

	if (eid == 0 && (sip = ses_plugin_page_lookup(sp, snap,
	    SES2_DIAGPAGE_STRING_IO, np, &len)) != NULL) {
		if (!SES_WITHIN_PAGE_STRUCT(sip, sip, len))
			return (0);

		textlen = SCSI_READ16(&sip->ssipi_page_length);

		if (!SES_WITHIN_PAGE(sip->ssipi_data, textlen, sip, len))
			return (0);

		SES_NV_ADD(byte_array, nverr, nvl, SES_EN_PROP_STRING,
		    sip->ssipi_data, textlen);
	}

	return (0);
}

static int
enc_parse_descr(ses_plugin_t *sp, ses_node_t *np)
{
	char *desc;
	nvlist_t *props = ses_node_props(np);
	int nverr;
	size_t len;

	if ((desc = ses_plugin_page_lookup(sp, ses_node_snapshot(np),
	    SES2_DIAGPAGE_ELEMENT_DESC, np, &len)) == NULL)
		return (0);

	SES_NV_ADD(fixed_string, nverr, props, SES_PROP_DESCRIPTION,
	    desc, len);

	return (0);
}

static int
enc_parse_dlucode(ses_plugin_t *sp, ses_node_t *np)
{
	ses_snap_t *snap = ses_node_snapshot(np);
	ses2_ucode_status_page_impl_t *upip;
	ses2_ucode_status_descr_impl_t *dip;
	nvlist_t *nvl = ses_node_props(np);
	int nverr, i;
	size_t len;
	uint64_t eid;

	if ((upip = ses_plugin_page_lookup(sp, snap,
	    SES2_DIAGPAGE_DL_MICROCODE_CTL_STATUS, np, &len)) == NULL)
		return (0);

	if (nvlist_lookup_uint64(nvl, SES_EN_PROP_EID, &eid) != 0)
		return (0);

	if (!SES_WITHIN_PAGE_STRUCT(upip, upip, len))
		return (0);

	/*
	 * The number of subenclosures excludes the primary subenclosure, which
	 * is always part of the response.
	 */
	for (dip = &upip->suspi_descriptors[0], i = 0;
	    i <= upip->suspi_n_subenclosures;
	    i++, dip++) {
		if (!SES_WITHIN_PAGE_STRUCT(dip, upip, len))
			break;

		if (dip->susdi_subenclosure_identifier != eid)
			continue;
		SES_NV_ADD(uint64, nverr, nvl, SES_EN_PROP_UCODE,
		    dip->susdi_subenclosure_dl_status);
		SES_NV_ADD(uint64, nverr, nvl, SES_EN_PROP_UCODE_A,
		    dip->susdi_subenclosure_dl_addl_status);
		SES_NV_ADD(uint64, nverr, nvl, SES_EN_PROP_UCODE_SZ,
		    SCSI_READ32(&dip->susdi_subenclosure_dl_max_size));
		SES_NV_ADD(uint64, nverr, nvl, SES_EN_PROP_UCODE_BUF,
		    dip->susdi_subenclosure_dl_buffer_id);
		SES_NV_ADD(uint64, nverr, nvl, SES_EN_PROP_UCODE_OFF,
		    dip->susdi_subenclosure_dl_buffer_offset);
		break;
	}

	return (0);
}

static int
enc_parse_subnick(ses_plugin_t *sp, ses_node_t *np)
{
	ses_snap_t *snap = ses_node_snapshot(np);
	ses2_subnick_status_page_impl_t *spip;
	ses2_subnick_descr_impl_t *dip;
	nvlist_t *nvl = ses_node_props(np);
	int nverr, i;
	size_t len;
	uint64_t eid;

	if (nvlist_lookup_uint64(nvl, SES_EN_PROP_EID, &eid) != 0)
		return (0);

	if ((spip = ses_plugin_page_lookup(sp, snap,
	    SES2_DIAGPAGE_SUBENCLOSURE_NICKNAME_CTL_STATUS,
	    np, &len)) == NULL)
		return (0);

	if (!SES_WITHIN_PAGE_STRUCT(spip, spip, len))
		return (0);

	for (dip = &spip->sspci_subnicks[0], i = 0;
	    i < spip->sspci_n_subenclosures;
	    i++, dip++) {
		if (!SES_WITHIN_PAGE_STRUCT(dip, spip, len))
			break;

		if (dip->ssdi_subenclosure_identifier != eid)
			continue;
		SES_NV_ADD(uint64, nverr, nvl, SES_EN_PROP_NICK_STATUS,
		    dip->ssdi_subenclosure_nick_status);
		SES_NV_ADD(uint64, nverr, nvl, SES_EN_PROP_NICK_ADDL_STATUS,
		    dip->ssdi_subenclosure_nick_addl_status);
		SES_NV_ADD_FS(nverr, nvl, SES_EN_PROP_NICK,
		    dip->ssdi_subenclosure_nickname);
		SES_NV_ADD(uint64, nverr, nvl, SES_EN_PROP_NICK_LANG,
		    dip->ssdi_subenclosure_nick_lang_code);
		break;
	}

	return (0);
}

int
ses2_fill_enclosure_node(ses_plugin_t *sp, ses_node_t *np)
{
	ses_snap_t *snap = ses_node_snapshot(np);
	nvlist_t *props = ses_node_props(np);
	ses2_elem_status_impl_t *esip;
	int err;
	size_t len;

	if ((esip = ses_plugin_page_lookup(sp, snap,
	    SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS, np, &len)) != NULL) {
		if ((err = enc_parse_sd(esip, props)) != 0)
			return (err);
	}

	if ((err = enc_parse_help(sp, np)) != 0)
		return (err);

	if ((err = enc_parse_string_in(sp, np)) != 0)
		return (err);

	if ((err = enc_parse_descr(sp, np)) != 0)
		return (err);

	if ((err = enc_parse_dlucode(sp, np)) != 0)
		return (err);

	if ((err = enc_parse_subnick(sp, np)) != 0)
		return (err);

	return (0);
}
