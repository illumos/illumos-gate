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

/*
 * These functions are used to encode SAS SMP address data into
 * Solaris devid / guid values.
 */

#ifndef _KERNEL
#include <stdio.h>
#endif /* _KERNEL */

#include <sys/inttypes.h>
#include <sys/types.h>
#include <sys/stropts.h>
#include <sys/debug.h>
#include <sys/isa_defs.h>
#include <sys/dditypes.h>
#include <sys/ddi_impldefs.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/generic/smp_frames.h>
#ifndef _KERNEL
#include <sys/libdevid.h>
#endif /* !_KERNEL */
#include "devid_impl.h"

/*
 * Typically the wwnstr makes a good devid, however in some cases the wwnstr
 * comes form the location of a FRU in the chassis instead of from the identity
 * of the FRU.  The table below provides vid/pid information for such cases.
 * These vidpid strings are matched against smp_report_manufacturer_info_resp
 * data. When a match occurs the srmir_vs_52 field, if non-zero, is used
 * to form the devid.
 */
char *vidpid_devid_from_srmir_vs_52[] = {
/*	"                  111111" */
/*	"012345670123456789012345" */
/*	"|-VID--||-----PID------|" */
	"SUN     GENESIS",
	NULL
};

/*
 *    Function: ddi_/devid_smp_encode
 *
 * Description: This routine finds and encodes a unique devid given the
 *		SAS address of an SMP node.
 *
 *   Arguments: version - id encode algorithm version
 *		driver_name - binding driver name (if ! known use NULL)
 *		wwnstr - smp SAS address in wwnstr (unit-address) form.
 *		srmir_buf - REPORT MANUFACTURER INFORMATION response.
 *		srmir_len - amount of srmir_buf data.
 *		devid - id returned
 *
 * Return Code: DEVID_SUCCESS - success
 *		DEVID_FAILURE - failure
 */
int
#ifdef _KERNEL
ddi_devid_smp_encode(
#else /* ! _KERNEL */
devid_smp_encode(
#endif /* _KERNEL */
    int version,	/* IN */
    char *driver_name,	/* IN */
    char *wwnstr,	/* IN */
    uchar_t *srmir_buf,	/* IN */
    size_t srmir_len,	/* IN */
    ddi_devid_t *devid)	/* OUT */
{
	uint64_t				wwn;
	ushort_t				raw_id_type;
	ushort_t				raw_id_len;
	impl_devid_t    			*i_devid;
	int					i_devid_len;
	int					i;
	smp_response_frame_t			*srs;
	smp_report_manufacturer_info_resp_t	*srmir;
	char					**vidpid;
	uint8_t					*vsp;
	uint64_t				s;
	char					sbuf[16 + 1];
	int					vlen, plen, slen;
	int					driver_name_len = 0;

	DEVID_ASSERT(devid != NULL);
	*devid = NULL;

	/* verify valid version */
	if (version > DEVID_SMP_ENCODE_VERSION_LATEST)
		return (DEVID_FAILURE);

	if (wwnstr == NULL)
		return (DEVID_FAILURE);

	/* convert wwnstr to binary */
	if (scsi_wwnstr_to_wwn(wwnstr, &wwn) != DDI_SUCCESS)
		return (DEVID_FAILURE);

	if (srmir_buf &&
	    (srmir_len >= ((sizeof (*srs) - sizeof (srs->srf_data)) +
	    sizeof (*srmir)))) {
		srs = (smp_response_frame_t *)srmir_buf;
		srmir = (smp_report_manufacturer_info_resp_t *)srs->srf_data;

		for (vidpid = vidpid_devid_from_srmir_vs_52; *vidpid; vidpid++)
			if (strncmp(srmir->srmir_vendor_identification,
			    *vidpid, strlen(*vidpid)) == 0)
				break;

		/* no vid/pid match, use wwn for devid */
		if (*vidpid == NULL)
			goto usewwn;

		/* extract the special vendor-specific 'devid serial number' */
		vsp = &srmir->srmir_vs_52[0];
		s = ((uint64_t)vsp[0] << 56) |
		    ((uint64_t)vsp[1] << 48) |
		    ((uint64_t)vsp[2] << 40) |
		    ((uint64_t)vsp[3] << 32) |
		    ((uint64_t)vsp[4] << 24) |
		    ((uint64_t)vsp[5] << 16) |
		    ((uint64_t)vsp[6] <<  8) |
		    ((uint64_t)vsp[7]);

		/* discount zero value */
		if (s == 0)
			goto usewwn;

		/* compute length (with trailing spaces removed) */
		vlen = scsi_ascii_inquiry_len(
		    srmir->srmir_vendor_identification,
		    sizeof (srmir->srmir_vendor_identification));
		plen = scsi_ascii_inquiry_len(
		    srmir->srmir_product_identification,
		    sizeof (srmir->srmir_product_identification));
		slen = snprintf(sbuf, sizeof (sbuf), "%016" PRIx64, s);
		if ((vlen <= 0) || (plen <= 0) || ((slen + 1) != sizeof (sbuf)))
			goto usewwn;

		/* this is most like a devid formed from inquiry data */
		raw_id_type = DEVID_SCSI_SERIAL;
		raw_id_len = vlen + 1 + plen + 1 + slen;

		i_devid_len = sizeof (*i_devid) +
		    raw_id_len - sizeof (i_devid->did_id);
		if ((i_devid = DEVID_MALLOC(i_devid_len)) == NULL)
			return (DEVID_FAILURE);
		bzero(i_devid, i_devid_len);

		/* copy the vid to the beginning */
		bcopy(&srmir->srmir_vendor_identification,
		    &i_devid->did_id[0], vlen);
		i_devid->did_id[vlen] = '.';

		/* copy the pid after the "vid." */
		bcopy(&srmir->srmir_product_identification,
		    &i_devid->did_id[vlen + 1], plen);
		i_devid->did_id[vlen + 1 + plen] = '.';

		/* place the 'devid serial number' buffer the "vid.pid." */
		bcopy(sbuf, &i_devid->did_id[vlen + 1 + plen + 1], slen);
	} else {
usewwn:		raw_id_type = DEVID_SCSI3_WWN;
		raw_id_len = sizeof (wwn);

		i_devid_len = sizeof (*i_devid) +
		    raw_id_len - sizeof (i_devid->did_id);
		if ((i_devid = DEVID_MALLOC(i_devid_len)) == NULL)
			return (DEVID_FAILURE);
		bzero(i_devid, i_devid_len);

		/* binary devid stores wwn bytes in big-endian order */
		for (i = 0; i < sizeof (wwn); i++)
			i_devid->did_id[i] =
			    (wwn >> ((sizeof (wwn) * 8) -
			    ((i + 1) * 8))) & 0xFF;

	}

	i_devid->did_magic_hi = DEVID_MAGIC_MSB;
	i_devid->did_magic_lo = DEVID_MAGIC_LSB;
	i_devid->did_rev_hi = DEVID_REV_MSB;
	i_devid->did_rev_lo = DEVID_REV_LSB;
	DEVID_FORMTYPE(i_devid, raw_id_type);
	DEVID_FORMLEN(i_devid, raw_id_len);

	/* fill in driver name hint */
	bzero(i_devid->did_driver, DEVID_HINT_SIZE);
	if (driver_name != NULL) {
		driver_name_len = strlen(driver_name);
		if (driver_name_len > DEVID_HINT_SIZE) {
			/* pick up last four characters of driver name */
			driver_name += driver_name_len - DEVID_HINT_SIZE;
			driver_name_len = DEVID_HINT_SIZE;
		}
		bcopy(driver_name, i_devid->did_driver, driver_name_len);
	}

	/* return device id */
	*devid = (ddi_devid_t)i_devid;
	return (DEVID_SUCCESS);
}
