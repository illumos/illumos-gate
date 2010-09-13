/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#ifndef	_SYS_JBUSPPM_H
#define	_SYS_JBUSPPM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Driver state structure
 */
typedef struct {
	dev_info_t		*dip;
	ddi_acc_handle_t	devid_hndl;
	ddi_acc_handle_t	estar_hndl;
	uint64_t		*devid_csr;
	uint64_t		*estar_csr;
	uint64_t		*j_chng_csr;
	int			is_master;
	int			lyropen;		/* ref count */
} jbppm_unit;

/* offset to JBus Change Initiation Control Register */
#define	J_CHNG_INITIATION_OFFSET	0x08

/* J_ID[1] set indicates master IO bridge */
#define	MASTER_IOBRIDGE_BIT		0x040000	/* j_id[1] */

/*
 * JBus Estar Control Register
 */
#define	JBUS_ESTAR_CNTL_32	0x20ULL
#define	JBUS_ESTAR_CNTL_2	0x2ULL
#define	JBUS_ESTAR_CNTL_1	0x1ULL
#define	JBUS_ESTAR_CNTL_MASK (JBUS_ESTAR_CNTL_32 |	\
    JBUS_ESTAR_CNTL_2 | JBUS_ESTAR_CNTL_1)

/*
 * JBus Change Initiation Control Register
 */
#define	J_CHNG_INITIATION_MASK	0x18ULL		/* Chng_Init[1:0] */
#define	J_CHNG_START		0x10ULL
#define	J_CHNG_OCCURED		0x18ULL
#define	J_CHNG_DELAY_MASK	0x07ULL		/* Chng_Delay[2:0] */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_JBUSPPM_H */
