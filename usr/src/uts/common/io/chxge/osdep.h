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

/*
 * This file is part of the Chelsio T1 Ethernet driver.
 *
 * Copyright (C) 2003-2005 Chelsio Communications.  All rights reserved.
 */

#ifndef _CHELSIO_OSDEP_H
#define	_CHELSIO_OSDEP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Solaris includes
 */
#define	BIG_ENDIAN 4321
#define	LITTLE_ENDIAN 1234
#if defined(__sparc)
#define	BYTE_ORDER BIG_ENDIAN
#else
#define	BYTE_ORDER LITTLE_ENDIAN
#endif

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/stropts.h>
#include <sys/cmn_err.h>
#include <sys/varargs.h>
#include <sys/stream.h>
#include <sys/ddi.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/gld.h>
#include "ostypes.h"

#include "oschtoe.h"
#include "ch_compat.h"

#include "ch.h"

#define	FILE_IDENT(a) static char *id = a

#define	ETH_ALEN 6

typedef struct ch peobj;
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef	kstat_t	*p_kstat_t;

#define	os_printf printf

#define	memcpy(dst, src, cnt) bcopy((src), (dst), (cnt))

#define	adapter_name(chp) (chp->ch_name)

typedef struct ch adapter_t;

#define	DELAY_US(x) DELAY(x)
#define	DELAY_MS(x) DELAY(1000*(x))

#define	TPI_LOCK(obj)	mutex_enter(&obj->ch_lock);
#define	TPI_UNLOCK(obj)	mutex_exit(&obj->ch_lock);
#define	MAC_LOCK(lock)	mutex_enter(&(lock))
#define	MAC_UNLOCK(lock)	mutex_exit(&(lock))
#define	__tpi_read  tpi_read
#define	__tpi_write tpi_write

struct t1_rx_mode {
	struct ch *chp;
	struct ch_mc *mc;
};

#define	t1_rx_mode_promisc(rmp)  (rmp->chp->ch_flags & PEPROMISC)
#define	t1_rx_mode_allmulti(rmp) (rmp->chp->ch_flags & PEALLMULTI)
#define	t1_rx_mode_mc_cnt(rmp)   (rmp->chp->ch_mc_cnt)
uint8_t *t1_get_next_mcaddr(struct t1_rx_mode *);

#define	__devinit

void t1_os_elmer0_ext_intr(adapter_t *adapter);

void t1_os_link_changed(ch_t *adapter, int port_id, int link_status,
    int speed, int duplex, int fc);

#define	CH_DBG(fmt, ...)

#define	CH_MSG(fmt, ...)

#define	t1_os_set_hw_addr(a, b, c) memcpy(a->port[b].enaddr, c, ETH_ALEN)

/* kludge for now */
#define	port_name(adapter, i) "chxge"

#define	SPINLOCK kmutex_t
#define	SPIN_LOCK_INIT(x) mutex_init(&(x), NULL, MUTEX_DRIVER, NULL);
#undef SPIN_LOCK
#define	SPIN_LOCK(x) mutex_enter(&(x))
#define	SPIN_UNLOCK(x) mutex_exit(&(x))
#define	SPIN_TRYLOCK(x) mutex_tryenter(&(x))
#define	SPIN_LOCK_DESTROY(x) mutex_destroy(&(x))

typedef struct ch_cyclic_s {
	timeout_id_t timer;
	void (*func)(void *);
	void *arg;
	clock_t period;
} ch_cyclic_t, *p_ch_cyclic_t;

void ch_init_cyclic(void *, p_ch_cyclic_t, void (*)(void *), void *);
void ch_start_cyclic(p_ch_cyclic_t, unsigned long);
void ch_stop_cyclic(p_ch_cyclic_t);
void ch_cyclic(p_ch_cyclic_t);

#ifdef __cplusplus
}
#endif

#endif /* _CHELSIO_OSDEP_H */
