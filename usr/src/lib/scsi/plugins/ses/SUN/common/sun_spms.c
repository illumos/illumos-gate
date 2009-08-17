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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <alloca.h>

#include <scsi/libses.h>
#include <scsi/libses_plugin.h>
#include <sys/scsi/impl/spc3_types.h>
#include <scsi/plugins/ses/framework/ses2_impl.h>

/*
 * Sun SPMS-1 r106, section 4.2.4 - Configuration
 * Sun SPMS r106, section 4.1.3.1, Table 8 - Sun Feature Definition
 * SES-2 r20, section 6.1.2.2, Table 7 - Enclosure Descriptor
 * SPC-4 r14, section 6.4.2, Table 121 - Std. INQUIRY data format
 *
 * Vendor Specific Enclosure Information:
 * (The below offsets are relative to the SES2 Enclosure Descriptor.)
 *    Sun Feature Block, starts at offset 0x28, size 20 bytes
 *    Platform specific content, starts at offset 0x64, variable size
 *
 */
#pragma pack(1)

typedef struct ses_sun_spms_vs {
	char		ssvs_spms_header[4];
	uint8_t		ssvs_spms_major_ver;
	uint8_t		__reserved1;
	uint16_t	ssvs_spms_revision;
	uint8_t		ssvs_chassis_id_off;
	uint8_t		ssvs_chassis_id_len;
	DECL_BITFIELD2(
	    ssvs_fw_upload_max_chunk_sz	:7,
	    ssvs_int			:1);
	uint8_t		__reserved2[49];
	uint8_t		ssvs_ps[1];	/* Flexible platform specific content */
} ses_sun_spms_vs_t;

#pragma pack()

/*ARGSUSED*/
static int
sun_parse_node(ses_plugin_t *sp, ses_node_t *np)
{
	ses_sun_spms_vs_t *sfbp;
	nvlist_t *encprops;
	uint8_t *vsp;
	uint_t vsp_len;
	uint_t cid_off, cid_len;
	char *csn;
	int nverr;

	if (ses_node_type(np) != SES_NODE_ENCLOSURE)
		return (0);

	encprops = ses_node_props(np);
	if (nvlist_lookup_byte_array(encprops, SES_EN_PROP_VS,
	    &vsp, &vsp_len) != 0 ||
	    vsp_len < offsetof(ses_sun_spms_vs_t, __reserved2))
		return (0);

	sfbp = (ses_sun_spms_vs_t *)vsp;

	if (strncmp(sfbp->ssvs_spms_header, "SPMS", 4) != 0)
		return (0);

	if (sfbp->ssvs_chassis_id_off < 96)
		return (0);

	cid_len = sfbp->ssvs_chassis_id_len;
	if (cid_len < 4)
		return (0);

	/*
	 * The offset read from the Sun Feature Block needs to be adjusted
	 * so that the difference in the sizes of the Enclosure
	 * Descriptor and the INQUIRY data format is accounted for.
	 */
	cid_off = sfbp->ssvs_chassis_id_off - (sizeof (ses2_ed_impl_t) - 1);
	cid_off += offsetof(ses2_ed_impl_t, st_priv[0]) -
	    offsetof(spc3_inquiry_data_t, id_vs_36[0]);

	if (cid_off + cid_len > vsp_len)
		return (0);

	csn = alloca((size_t)cid_len + 1);
	csn[cid_len] = '\0';

	bcopy((void *)(vsp + cid_off), csn, cid_len);
	SES_NV_ADD(fixed_string, nverr, encprops, LIBSES_EN_PROP_CSN,
	    csn, cid_len + 1);

	return (0);
}

int
_ses_init(ses_plugin_t *sp)
{
	ses_plugin_config_t config = {
		.spc_node_parse = sun_parse_node
	};

	return (ses_plugin_register(sp, LIBSES_PLUGIN_VERSION,
	    &config) != 0);
}
