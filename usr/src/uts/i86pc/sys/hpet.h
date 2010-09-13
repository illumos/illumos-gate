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

#ifndef	_HPET_H
#define	_HPET_H

#include <sys/hpet_acpi.h>

/*
 * Interface for HPET access.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * HPET_INFINITY is used for timers that will never expire.
 */
#define	HPET_INFINITY		(INT64_MAX)

/*
 * State of initialization.
 */
#define	HPET_NO_SUPPORT		(0)
#define	HPET_TIMER_SUPPORT	(1)	/* supports main counter reads */
#define	HPET_INTERRUPT_SUPPORT	(2)	/* supports interrupt/timer */
#define	HPET_FULL_SUPPORT	(3)	/* supports counter and timer intr */

typedef struct hpet {
	uint_t		supported;
	boolean_t	(*install_proxy)(void);
	boolean_t	(*callback)(int);
	/*
	 * Next two function pointers allow CPUs to use the HPET's timer
	 * as a proxy for their LAPIC timers which stop during Deep C-State.
	 */
	boolean_t	(*use_hpet_timer)(hrtime_t *);
	void		(*use_lapic_timer)(hrtime_t);
} hpet_t;

#define	CST_EVENT_MULTIPLE_CSTATES	(128)	/* callbacks for _CST changes */
#define	CST_EVENT_ONE_CSTATE		(129)

/*
 * unix access to the HPET is done through the hpet structure.
 */
extern hpet_t hpet;

int hpet_acpi_init(int *hpet_vect, iflag_t *hpet_flags);
void hpet_acpi_fini(void);
uint32_t hpet_proxy_ipl(void);

#ifdef __cplusplus
}
#endif

#endif	/* _HPET_H */
