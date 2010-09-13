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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DDI_SUBRDEFS_H
#define	_SYS_DDI_SUBRDEFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Sun DDI platform implementation subroutines definitions
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

uint32_t i_ddi_get_inum(dev_info_t *dip, uint_t inumber);
uint32_t i_ddi_get_intr_pri(dev_info_t *dip, uint_t inumber);

int	i_ddi_add_ivintr(ddi_intr_handle_impl_t *hdlp);
void	i_ddi_rem_ivintr(ddi_intr_handle_impl_t *hdlp);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DDI_SUBRDEFS_H */
