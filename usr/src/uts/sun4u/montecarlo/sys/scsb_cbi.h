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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MONTECARLO_SYS_SCSB_CBI_H
#define	_MONTECARLO_SYS_SCSB_CBI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	_KERNEL

/*
 * scsb_cbi.h
 * scsb callback interface for some the MonteCarlo/Tonga I2C FRU drivers
 */

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum scsb_fru_event {
	FRU_INTR_EVENT,
	FRU_CMD_EVENT
} scsb_fru_event_t;

scsb_fru_status_t scsb_fru_register(void (*cb_func)(void *,
						scsb_fru_event_t,
						scsb_fru_status_t),
					void *softstate_ptr,
					fru_id_t fru_id);
void scsb_fru_unregister(void *soft_ptr, fru_id_t fru_id);
scsb_fru_status_t scsb_fru_status(fru_id_t fru_id);

#ifdef	__cplusplus
}
#endif
#endif	/* _KERNEL */

#endif	/* _MONTECARLO_SYS_SCSB_CBI_H */
