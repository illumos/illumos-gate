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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DS_SCSI_USCSI_H
#define	_DS_SCSI_USCSI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * "impossible" status value
 */
#define	IMPOSSIBLE_SCSI_STATUS	0xff

/*
 * Minimum length of Request Sense data that we can accept
 */
#define	MIN_REQUEST_SENSE_LEN	18

/*
 * Rounded parameter, as returned in Extended Sense information
 */
#define	ROUNDED_PARAMETER	0x37

int uscsi_mode_sense(int, int, int, caddr_t, int, scsi_ms_header_t *,
    void *, int *);
int uscsi_mode_sense_10(int, int, int, caddr_t, int, scsi_ms_header_g1_t *,
    void *, int *);
int uscsi_mode_select(int, int, int, caddr_t, int, scsi_ms_header_t *,
    void *, int *);
int uscsi_mode_select_10(int, int, int, caddr_t, int, scsi_ms_header_g1_t *,
    void *, int *);
int uscsi_log_sense(int, int, int, caddr_t, int, void *, int *);
int uscsi_request_sense(int, caddr_t, int, void *, int *);

#ifdef	__cplusplus
}
#endif

#endif	/* _DS_SCSI_USCSI_H */
