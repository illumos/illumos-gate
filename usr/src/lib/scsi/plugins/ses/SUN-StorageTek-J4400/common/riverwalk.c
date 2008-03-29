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

#pragma pack(1)

typedef struct ses_riverwalk_stringin {
	uint8_t		rws_download_status;
	uint8_t		rws_descriptor_start;
	uint16_t	rws_descriptor_length;
	char		rws_sim0_id[4];
	char		rws_sim0_pn[15];
	char		rws_sim0_sn[20];
	char		rws_sim1_id[4];
	char		rws_sim1_pn[15];
	char		rws_sim1_sn[20];
	char		rws_mid_id[4];
	char		rws_mid_pn[15];
	char		rws_mid_sn[20];
	char		rws_ps0_id[4];
	char		rws_ps0_pn[15];
	char		rws_ps0_sn[20];
	char		rws_ps1_id[4];
	char		rws_ps1_pn[15];
	char		rws_ps1_sn[20];
	char		__reserved1[29];
	uint8_t		rws_diag_start;
	uint8_t		rws_eid;
	uint16_t	rws_diag_length;
	uint8_t		rws_sim_id;
	uint8_t		rws_numport;
	uint16_t	__reserved2;
	uint8_t		rws_sasaddr[8];
	uint8_t		rws_sys_sn[8];
	char		rws_port0[16];
	char		rws_port1[16];
	char		rws_port2[16];
} ses_riverwalk_stringin_t;

#pragma pack()

/*ARGSUSED*/
static int
sun_riverwalk_parse_node(ses_plugin_t *sp, ses_node_t *np)
{
	nvlist_t *props = ses_node_props(np);
	int nverr;
	ses_riverwalk_stringin_t *strp;
	char buf[32];
	uint64_t type, index;
	char *pn, *sn;
	ses_node_t *encp;
	nvlist_t *encprops;
	uint8_t *stringin;
	uint_t len;

	if (ses_node_type(np) != SES_NODE_ENCLOSURE &&
	    ses_node_type(np) != SES_NODE_ELEMENT)
		return (0);

	/*
	 * Find the containing enclosure node and extract the STRING IN
	 * information.
	 */
	for (encp = np; ses_node_type(encp) != SES_NODE_ENCLOSURE;
	    encp = ses_node_parent(encp))
		;

	encprops = ses_node_props(encp);
	if (nvlist_lookup_byte_array(encprops, SES_EN_PROP_STRING,
	    &stringin, &len) != 0)
		return (0);

	if (len < sizeof (ses_riverwalk_stringin_t))
		return (0);

	strp = (ses_riverwalk_stringin_t *)stringin;

	switch (ses_node_type(np)) {
	case SES_NODE_ELEMENT:
		/*
		 * We can get part and serial information for power supplies and
		 * the SIM cards (ESC_ELECTRONICS elements).
		 */
		VERIFY(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_TYPE,
		    &type) == 0);
		VERIFY(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_CLASS_INDEX,
		    &index) == 0);

		sn = pn = NULL;
		switch (type) {
		case SES_ET_POWER_SUPPLY:
			switch (index) {
			case 0:
				if (strncmp(strp->rws_ps0_id, "SPS0", 4) != 0)
					break;

				pn = strp->rws_ps0_pn;
				sn = strp->rws_ps0_sn;
				break;

			case 1:
				if (strncmp(strp->rws_ps1_id, "SPS1", 4) != 0)
					break;

				pn = strp->rws_ps1_pn;
				sn = strp->rws_ps1_sn;
				break;
			}
			break;

		case SES_ET_ESC_ELECTRONICS:
			switch (index) {
			case 0:
				if (strncmp(strp->rws_sim0_id, "SIM0", 4) != 0)
					break;

				pn = strp->rws_sim0_pn;
				sn = strp->rws_sim0_sn;
				break;

			case 1:
				if (strncmp(strp->rws_sim1_id, "SIM1", 4) != 0)
					break;

				pn = strp->rws_sim1_pn;
				sn = strp->rws_sim1_sn;
				break;
			}
			break;
		}

		if (pn == NULL)
			return (0);

		if (pn[0] != '\0') {
			(void) bcopy(pn, buf, sizeof (strp->rws_ps0_pn));
			buf[sizeof (strp->rws_ps0_pn)] = '\0';
			SES_NV_ADD(string, nverr, props, LIBSES_PROP_PART,
			    buf);
		}

		if (sn[0] != '\0') {
			(void) bcopy(sn, buf, sizeof (strp->rws_ps0_sn));
			buf[sizeof (strp->rws_ps0_sn)] = '\0';
			SES_NV_ADD(string, nverr, props, LIBSES_PROP_SERIAL,
			    sn);
		}

		break;

	case SES_NODE_ENCLOSURE:
		/*
		 * The chassis serial number is derived from the MID FRU
		 * descriptor.
		 */
		if (strncmp(strp->rws_mid_id, "MID ", 4) == 0 &&
		    strp->rws_mid_sn[0] != '\0') {
			(void) bcopy(strp->rws_mid_sn, buf,
			    sizeof (strp->rws_mid_sn));
			buf[sizeof (strp->rws_mid_sn)] = '\0';
			SES_NV_ADD(string, nverr, props, LIBSES_EN_PROP_CSN,
			    buf);
		}

		break;
	}

	return (0);
}

int
_ses_init(ses_plugin_t *sp)
{
	ses_plugin_config_t config = {
		.spc_node_parse = sun_riverwalk_parse_node
	};

	return (ses_plugin_register(sp, LIBSES_PLUGIN_VERSION,
	    &config) != 0);
}
