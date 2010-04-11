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

#include <sys/scsi/impl/spc3_types.h>

#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <libnvpair.h>

#include <scsi/libses.h>
#include <scsi/libses_plugin.h>
#include <scsi/plugins/ses/framework/ses2.h>
#include <scsi/plugins/ses/framework/ses2_impl.h>
#include <scsi/plugins/ses/framework/libses.h>
#include <scsi/plugins/ses/vendor/sun.h>
#include <scsi/plugins/ses/vendor/sun_impl.h>

/*ARGSUSED*/
static int
enc_parse_feature_block(ses_plugin_t *sp, ses_node_t *np)
{
	sun_feature_block_impl_t *sfbip;
	nvlist_t *encprops;
	uint8_t *vsp;
	uint_t vsp_len;
	uint_t cid_off, cid_len;
	uint16_t revision;
	uint64_t chunk;
	int nverr;

	encprops = ses_node_props(np);
	if (nvlist_lookup_byte_array(encprops, SES_EN_PROP_VS,
	    &vsp, &vsp_len) != 0 ||
	    vsp_len < offsetof(sun_feature_block_impl_t, _reserved2))
		return (0);

	sfbip = (sun_feature_block_impl_t *)vsp;

	if (strncmp((char *)sfbip->sfbi_spms_header, "SPMS", 4) != 0 ||
	    sfbip->sfbi_spms_major_ver != 1)
		return (0);

	revision = SCSI_READ16(&sfbip->sfbi_spms_revision);

	/*
	 * The offset read from the Sun Feature Block needs to be adjusted
	 * so that the difference in the sizes of the Enclosure
	 * Descriptor and the INQUIRY data format is accounted for.
	 */
	cid_len = sfbip->sfbi_chassis_id_len;

	if (sfbip->sfbi_chassis_id_off >= 96 && cid_len >= 4) {
		cid_off = sfbip->sfbi_chassis_id_off -
		    (sizeof (ses2_ed_impl_t) - 1);
		cid_off += offsetof(ses2_ed_impl_t, st_priv[0]) -
		    offsetof(spc3_inquiry_data_t, id_vs_36[0]);

		if (cid_off + cid_len <= vsp_len) {
			SES_NV_ADD(fixed_string, nverr, encprops,
			    LIBSES_EN_PROP_CSN, (char *)(vsp + cid_off),
			    cid_len);
		}
	}

	if (revision >= 104) {
		SES_NV_ADD(boolean_value, nverr, encprops,
		    LIBSES_EN_PROP_INTERNAL, sfbip->sfbi_int);
	}

	if (revision >= 105) {
		if (sfbip->sfbi_fw_upload_max_chunk_sz == 0)
			chunk = 512;
		else if (sfbip->sfbi_fw_upload_max_chunk_sz == 0x7f)
			chunk = 65536;
		else
			chunk = 512 * sfbip->sfbi_fw_upload_max_chunk_sz;

		SES_NV_ADD(uint64, nverr, encprops,
		    LIBSES_EN_PROP_FIRMWARE_CHUNK_SIZE, chunk);
	}

	/*
	 * If this is a subchassis, it will have a subchassis index field
	 * with a value other than 0.  See SPMS-1r111 4.1.3.1.  If not, we
	 * will see 0 and will not create the subchassis member at all; note
	 * that this is backward-compatible with pre-111 implementations that
	 * treated this as a reserved field.  No such implementation contains
	 * a subchassis.
	 */
	if (sfbip->sfbi_spms_revision >= 111 &&
	    sfbip->sfbi_subchassis_index != 0) {
		SES_NV_ADD(uint64, nverr, encprops,
		    LIBSES_EN_PROP_SUBCHASSIS_ID,
		    sfbip->sfbi_subchassis_index - 1);
	}

	return (0);
}

int
sun_fill_enclosure_node(ses_plugin_t *sp, ses_node_t *np)
{
	ses_snap_t *snap = ses_node_snapshot(np);
	nvlist_t *props = ses_node_props(np);
	sun_fru_descr_impl_t *sfdi;
	int err;
	size_t len;

	if ((err = enc_parse_feature_block(sp, np)) != 0)
		return (err);

	if ((sfdi = ses_plugin_page_lookup(sp, snap,
	    SUN_DIAGPAGE_FRUID, np, &len)) != NULL) {
		if ((err = sun_fruid_parse_common(sfdi, props)) != 0)
			return (err);
	}

	return (0);
}
