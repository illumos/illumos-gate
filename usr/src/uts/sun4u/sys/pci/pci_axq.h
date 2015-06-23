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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_PCI_AXQ_H
#define	_SYS_PCI_AXQ_H

#include <sys/types.h>
#include <sys/atomic.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	PIO_LIMIT_ENTER(p)	{ \
				int n;\
				for (;;) {\
					do {\
						n = p->pbm_pio_counter;\
					} while (n <= 0);\
					if (atomic_dec_32_nv(\
					    (uint_t *)&p->pbm_pio_counter)\
					    == (n - 1))\
						break;\
					atomic_inc_32(\
					    (uint_t *)&p->pbm_pio_counter);\
				}\
				}



#define	PIO_LIMIT_EXIT(p)	atomic_inc_32((uint_t *)&p->pbm_pio_counter);

extern void pci_axq_setup(ddi_map_req_t *mp, pbm_t *pbm_p);
extern void pci_axq_pio_limit(pbm_t *pbm_p);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_AXQ_H */
