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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_DOMAIND_H
#define	_SYS_DOMAIND_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sysmacros.h>
#include <sys/cpu_sgnblk_defs.h>

typedef struct domain_data {
	uint32_t	magic;		/* magic number */
	uint8_t		version;	/* version number */
	uint8_t		keyswitch;	/* virtual SC keyswitch */
	uint32_t	master_sc_ip;	/* IP address of master SC */
	uint32_t	leds;		/* software LEDs */
	sig_state_t	domain_state;	/* domain state */
	uint32_t	heartbeat;	/* domain heartbeat */
	cpuset_t	cpus_present;	/* CPU's present in this domain */
	sig_state_t	cpu_sigs[NCPU];	/* state for present CPUs */
	uint32_t	resetinfo_off[NCPU];	/* resetinfo offsets */
	uint8_t		_reserved[16];	/* word aligned */
} domain_data_t;

/*
 * Unique ID for domain data IOSRAM chunk
 */
#define	DOMD_MAGIC	0x444F4D44	/* 'D' 'O' 'M' 'D' */

/*
 * offsets
 */
#define	DOMD_MAGIC_OFFSET	offsetof(domain_data_t, magic)
#define	DOMD_VERSION_OFFSET	offsetof(domain_data_t, version)
#define	DOMD_KEYSWITCH_OFFSET	offsetof(domain_data_t, keyswitch)
#define	DOMD_SCIP_OFFSET	offsetof(domain_data_t, master_sc_ip)
#define	DOMD_LEDS_OFFSET	offsetof(domain_data_t, leds)
#define	DOMD_DSTATE_OFFSET	offsetof(domain_data_t, domain_state)
#define	DOMD_HEARTBEAT_OFFSET	offsetof(domain_data_t, heartbeat)
#define	DOMD_CPUSPRESENT_OFFSET	offsetof(domain_data_t, cpus_present)
#define	DOMD_CPUSIGS_OFFSET	offsetof(domain_data_t, cpu_sigs)
#define	DOMD_RESETINFO_OFFSET	offsetof(domain_data_t, resetinfo_off)

/*
 * tod
 */
#define	TODSC_SET_THRESHOLD	30		/* in seconds */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DOMAIND_H */
