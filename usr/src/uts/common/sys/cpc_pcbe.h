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
 * CPC Performance Counter Backend
 *
 * To utilize the performance counters on a given CPU, a pcbe (Performance
 * Counter Backend) must be implemented for that CPU.
 *
 * This file defines the API which the kernel CPC implementation will call into.
 *
 */

#ifndef _SYS_CPC_PCBE_H
#define	_SYS_CPC_PCBE_H

#include <sys/inttypes.h>
#include <sys/cpc_impl.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * All PCBEs must use PCBE_VER_1.
 */
#define	PCBE_VER_1	1

#define	PCBE_IMPL_NAME_P4HT	"Pentium 4 with HyperThreading"

typedef struct __pcbe_ops {
	uint_t		pcbe_ver;
	uint_t		pcbe_caps;
	uint_t		(*pcbe_ncounters)(void);
	const char	*(*pcbe_impl_name)(void);
	const char	*(*pcbe_cpuref)(void);
	char		*(*pcbe_list_events)(uint_t picnum);
	char		*(*pcbe_list_attrs)(void);
	uint64_t	(*pcbe_event_coverage)(char *event);
	uint64_t	(*pcbe_overflow_bitmap)(void);
	int		(*pcbe_configure)(uint_t, char *, uint64_t, uint_t,
				uint_t, kcpc_attr_t *, void **, void *);
	void		(*pcbe_program)(void *);
	void		(*pcbe_allstop)(void);
	void		(*pcbe_sample)(void *);
	void		(*pcbe_free)(void *);
} pcbe_ops_t;

extern pcbe_ops_t *pcbe_ops;

/*
 * uint_t pcbe_ver;
 *
 *	Must always be set to PCBE_VER_1.
 *
 * uint_t pcbe_caps;
 *
 *	Bitmask of capability flags which define the processor's capabilities:
 *		CPC_CAP_OVERFLOW_INTERRUPT:
 *			This processor can generate an interrupt when a counter
 *			overflows.
 *
 *		CPC_CAP_OVERFLOW_PRECISE:
 *			When an overflow interrupt occurs, the backend can
 *			determine programmatically exactly which counter
 *			overflowed.
 *
 * uint_t (*pcbe_ncounters)(void);
 *
 *	Returns the number of counters on the processor.
 *
 * const char *(*pcbe_impl_name)(void);
 *
 *	Returns a pointer to a string which uniquely identifies the CPC
 *	capabilities of the processor.
 *
 * const char *(*pcbe_cpuref)(void);
 *
 *	Returns a pointer to a string which points to a reference manual of
 *	some sort which should be consulted to understand the performance
 *	counters.
 *
 * char	*(*pcbe_list_events)(uint_t picnum);
 *
 *	Returns a pointer to a comma-separated list of events which the given
 *	counter number is capable of counting. picnum starts at 0 and goes as
 *	high as (ncounters - 1).
 *
 * char *(*pcbe_list_attrs)(void);
 *
 *	Returns a pointer to a comma-separated list of attribute names which
 *	the PCBE supports.
 *
 * uint64_t (*pcbe_event_coverage)(char *event);
 *
 *	Returns a bitmask indicating which counters are capable of counting the
 *	named event. Counter n is deemed capable if bit (1 << n) is turned on,
 *	where counters range from 0 to (ncounters - 1).
 *
 * uint64_t (*pcbe_overflow_bitmap)(void);
 *
 *	Called by the kernel when a performance counter interrupt is received.
 *	This routine must return a bitmap of counters indicating which ones have
 *	overflowed. If the platform cannot determine this, it must act as if
 *	_all_ of its counters have overflowed.
 *
 * int (*pcbe_configure)(uint_t picnum, char *event, uint64_t preset,
 *				uint_t flags, uint_t nattrs, kcpc_attr_t *attrp,
 *				void **configp, void *token);
 *
 *	Returns a pointer to a PCBE-private data structure which can later be
 *	used to program the indicated picnum according to the arguments.
 *	token may be passed to kcpc_next_config() in order to walk the list of
 *	configurations which will be programmed together.
 *
 * void	(*pcbe_program)(void *token);
 *
 *	Collects all configurations which will be programmed together, via
 *	kcpc_next_config(), programs them onto the hardware, and starts the
 *	performance counters.
 *
 * void	(*pcbe_allstop)(void);
 *
 *	Stops all hardware performance counters.
 *
 * void	(*pcbe_sample)(void *token);
 *
 *	Samples the values in the performance couters and updates the locations
 *	returned by kcpc_next_config() with the delta since the last sample.
 *
 * void	(*pcbe_free)(void *config);
 *
 *	Frees the given configuration.
 */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_CPC_PCBE_H */
