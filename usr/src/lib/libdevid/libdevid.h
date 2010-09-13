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

#ifndef	_LIBDEVID_H
#define	_LIBDEVID_H

#include <errno.h>
#include <sys/param.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/dkio.h>
#include <devid.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * libdevid SUN private interfaces or structures.
 */
extern int	devid_str_compare(char *devid1_str, char *devid2_str);

extern int	devid_scsi_encode(int version, char *driver_name, uchar_t *inq,
		    size_t inq_len, uchar_t *inq80, size_t inq80_len,
		    uchar_t *inq83, size_t inq83_len, ddi_devid_t *devid);

extern int	devid_smp_encode(int version, char *driver_name,
		    char *wwnstr, uchar_t *srmir_buf, size_t srmir_len,
		    ddi_devid_t *devid);

extern char	*devid_to_guid(ddi_devid_t devid);
extern void	devid_free_guid(char *guid);

extern int	scsi_wwnstr_to_wwn(const char *wwnstr, uint64_t *wwnp);
extern char	*scsi_wwn_to_wwnstr(uint64_t wwn,
		    int unit_address_form, char *wwnstr);
extern void	scsi_wwnstr_hexcase(char *wwnstr, int lower_case);
extern const char	*scsi_wwnstr_skip_ua_prefix(const char *wwnstr);
extern void	scsi_free_wwnstr(char *wwnstr);

#ifdef	SCSI_ADDR_PROP_LUN64
extern scsi_lun64_t	scsi_lun_to_lun64(scsi_lun_t lun);
extern scsi_lun_t	scsi_lun64_to_lun(scsi_lun64_t lun64);
#endif	/* SCSI_ADDR_PROP_LUN64 */

extern int	scsi_ascii_inquiry_len(char *field, size_t length);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDEVID_H */
