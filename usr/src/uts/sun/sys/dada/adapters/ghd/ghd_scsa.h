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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _GHD_SCSA_H
#define	_GHD_SCSA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/scsi/scsi.h>

/*
 * This really belongs in some sort of scsa include file since
 * it's used by the getcap/setcap interface.
 */
#define	HBA_SETGEOM(hd, sec) (((hd) << 16) | (sec))

void		ghd_tran_sync_pkt(struct scsi_address *ap,
			struct scsi_pkt *pktp);

void		ghd_pktfree(ccc_t *cccp, struct scsi_address *ap,
			struct scsi_pkt *pktp);

#ifdef	__cplusplus
}
#endif

#endif /* _GHD_SCSA_H */
