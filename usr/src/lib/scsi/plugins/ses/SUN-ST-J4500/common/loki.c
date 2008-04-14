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

#include <string.h>
#include <strings.h>

#include <scsi/libses.h>
#include <scsi/libses_plugin.h>

#include <scsi/plugins/ses/framework/ses2_impl.h>

static int
sun_loki_fix_bay(ses_plugin_t *sp, ses_node_t *np)
{
	ses2_aes_descr_eip_impl_t *dep;
	ses2_aes_descr_sas0_eip_impl_t *s0ep;
	size_t len;
	int nverr;
	nvlist_t *props = ses_node_props(np);

	/*
	 * The spec conveniently defines the bay number as part of the
	 * additional element status descriptor.  However, the AES descriptor
	 * is technically only valid if the device is inserted.  This is a
	 * problem for loki because the bay numbers don't match the element
	 * class index, so when a device is removed we have no way of knowing
	 * *which* bay is empty.  Thankfully, loki defines this value even if
	 * the invalid bit is set, so we override this value, even for empty
	 * bays.
	 */
	if ((dep = ses_plugin_page_lookup(sp, ses_node_snapshot(np),
	    SES2_DIAGPAGE_ADDL_ELEM_STATUS, np, &len)) == NULL)
		return (0);

	if (dep->sadei_protocol_identifier != SPC4_PROTO_SAS ||
	    !dep->sadei_eip || !dep->sadei_invalid)
		return (0);

	s0ep = (ses2_aes_descr_sas0_eip_impl_t *)dep->sadei_protocol_specific;

	SES_NV_ADD(uint64, nverr, props, SES_PROP_BAY_NUMBER,
	    s0ep->sadsi_bay_number);

	return (0);
}

static int
sun_loki_parse_node(ses_plugin_t *sp, ses_node_t *np)
{
	ses_node_t *encp;
	nvlist_t *props = ses_node_props(np);
	nvlist_t *encprops;
	uint8_t *stringin;
	uint_t len;
	nvlist_t *lid;
	int nverr;
	char serial[17];
	uint8_t fieldlen;
	char *field;
	uint64_t wwn;
	uint64_t type, index;
	int i;

	if (ses_node_type(np) != SES_NODE_ENCLOSURE &&
	    ses_node_type(np) != SES_NODE_ELEMENT)
		return (0);

	if (ses_node_type(np) == SES_NODE_ELEMENT) {
		VERIFY(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_TYPE,
		    &type) == 0);

		if (type == SES_ET_ARRAY_DEVICE)
			return (sun_loki_fix_bay(sp, np));

		if (type != SES_ET_COOLING &&
		    type != SES_ET_POWER_SUPPLY)
			return (0);

		VERIFY(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_CLASS_INDEX,
		    &index) == 0);
	}

	/*
	 * Find the containing enclosure node and extract the STRING IN
	 * information.
	 */
	for (encp = np; ses_node_type(encp) != SES_NODE_ENCLOSURE;
	    encp = ses_node_parent(encp))
		;

	encprops = ses_node_props(encp);
	if (nvlist_lookup_byte_array(encprops, SES_EN_PROP_STRING,
	    &stringin, &len) != 0 || len == 0)
		return (0);

	/*
	 * If this is an enclosure, then calculate the chassis WWN by masking
	 * off the bottom 8 bits of the WWN.
	 */
	if (ses_node_type(np) == SES_NODE_ENCLOSURE) {
		VERIFY(nvlist_lookup_nvlist(props, SES_EN_PROP_LID, &lid) == 0);
		VERIFY(nvlist_lookup_uint64(lid, SPC3_NAA_INT, &wwn) == 0);
		(void) snprintf(serial, sizeof (serial), "%llx",
		    wwn & ~0xFFULL);
		SES_NV_ADD(string, nverr, props, LIBSES_EN_PROP_CSN, serial);
	}

	/*
	 * The STRING IN data is organized into a series of variable-length
	 * fields, where each field can be either a key ("Fan PartNUM") or a
	 * value.  If the field length is less than our shortest expected
	 * identifier, then something has gone awry and we assume that the data
	 * is corrupt.
	 */
	fieldlen = *stringin;
	if (fieldlen < 11)
		return (0);

	for (field = (char *)stringin + 1;
	    field + fieldlen <= (char *)stringin + len; field += fieldlen) {
		if (strncmp(field, "ST J4500", 8) == 0) {
			/*
			 * This is the part number for the enclosure itself.
			 */
			if (ses_node_type(np) != SES_NODE_ENCLOSURE)
				continue;

			field += fieldlen;
			if (field + fieldlen > (char *)stringin + len)
				break;

			if (ses_node_type(np) == SES_NODE_ENCLOSURE) {
				SES_NV_ADD(fixed_string_trunc, nverr, props,
				    LIBSES_PROP_PART, field, fieldlen);
				return (0);
			}

		} else if (strncmp(field, "Fan PartNUM", 11) == 0) {
			/*
			 * Part numbers for the fans, of which there are 5.
			 */
			if (ses_node_type(np) != SES_NODE_ELEMENT ||
			    type != SES_ET_COOLING)
				continue;

			field += fieldlen;

			for (i = 0; i < 5 &&
			    field + fieldlen <= (char *)stringin + len;
			    i++, fieldlen += fieldlen) {
				if (index == i &&
				    strncmp(field, "Unknown", 7) != 0 &&
				    strncmp(field, "Not Installed", 13) != 0) {
					SES_NV_ADD(fixed_string_trunc, nverr,
					    props, LIBSES_PROP_PART,
					    field, fieldlen);
					return (0);
				}
			}

		} else if (strncmp(field, "PS PartNUM", 10) == 0) {
			/*
			 * Part numbers for the power supplies, of which there
			 * are 2.
			 */
			if (ses_node_type(np) != SES_NODE_ELEMENT ||
			    type != SES_ET_POWER_SUPPLY)
				continue;

			field += fieldlen;

			for (i = 0; i < 2 &&
			    field + fieldlen <= (char *)stringin + len;
			    i++, fieldlen += fieldlen) {
				if (index == i &&
				    strncmp(field, "Unknown", 7) != 0 &&
				    strncmp(field, "Not Installed", 13) != 0) {
					SES_NV_ADD(fixed_string_trunc, nverr,
					    props, LIBSES_PROP_PART,
					    field, fieldlen);
					return (0);
				}
			}
		}
	}

	return (0);
}

int
_ses_init(ses_plugin_t *sp)
{
	ses_plugin_config_t config = {
		.spc_node_parse = sun_loki_parse_node
	};

	return (ses_plugin_register(sp, LIBSES_PLUGIN_VERSION,
	    &config) != 0);
}
