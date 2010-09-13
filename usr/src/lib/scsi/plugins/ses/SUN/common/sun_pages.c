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

#include <scsi/libses.h>
#include <scsi/libses_plugin.h>
#include <scsi/plugins/ses/vendor/sun.h>
#include <scsi/plugins/ses/vendor/sun_impl.h>

/*ARGSUSED*/
static void *
sun_fruid_index(ses_plugin_t *sp, ses_node_t *np, void *data,
    size_t pagelen, size_t *len)
{
	uint64_t index;
	nvlist_t *props = ses_node_props(np);
	sun_fruid_page_impl_t *sfpip = data;
	sun_fru_descr_impl_t *sfdip;
	uint16_t *addr;

	if (ses_node_type(np) != SES_NODE_ELEMENT &&
	    ses_node_type(np) != SES_NODE_ENCLOSURE)
		return (NULL);

	if (nvlist_lookup_uint64(props, SES_PROP_ELEMENT_ONLY_INDEX,
	    &index) != 0)
		return (NULL);

	addr = &sfpip->sfpi_descr_addrs[index];
	if (!SES_WITHIN_PAGE_STRUCT(addr, data, pagelen))
		return (NULL);

	sfdip = (sun_fru_descr_impl_t *)((uint8_t *)sfpip + SCSI_READ16(addr));
	if (!SES_WITHIN_PAGE_STRUCT(sfdip, data, pagelen))
		return (NULL);

	*len = MIN(((uint8_t *)sfpip - (uint8_t *)sfdip) + pagelen,
	    SCSI_READ16(&sfdip->sfdi_fru_data_length) +
	    offsetof(sun_fru_descr_impl_t, sfdi_fru_data));

	return (sfdip);
}

ses_pagedesc_t sun_pages[] = {
{
	.spd_pagenum = SUN_DIAGPAGE_FRUID,
	.spd_index = sun_fruid_index,
	.spd_req = SES_REQ_OPTIONAL_STANDARD,
	.spd_gcoff = offsetof(sun_fruid_page_impl_t, sfpi_generation_code)
},
{
	.spd_pagenum = -1,
	.spd_gcoff = -1
}
};
