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

#ifndef _SYS_SOFT_STATE_H
#define	_SYS_SOFT_STATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * sun4v Hypervisor Guest State API
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * String definitions for Solaris
 */

#define	SOLARIS_SOFT_STATE_BOOT_MSG_STR		"Solaris booting"
#define	SOLARIS_SOFT_STATE_RUN_MSG_STR		"Solaris running"
#define	SOLARIS_SOFT_STATE_HALT_MSG_STR		"Solaris halting"
#define	SOLARIS_SOFT_STATE_POWER_MSG_STR	"Solaris powering down"
#define	SOLARIS_SOFT_STATE_PANIC_MSG_STR	"Solaris panicking"
#define	SOLARIS_SOFT_STATE_REBOOT_MSG_STR	"Solaris rebooting"
#define	SOLARIS_SOFT_STATE_DEBUG_MSG_STR	"Solaris debugging"
#define	SSM_SIZE				32

#ifndef _ASM

extern char	soft_state_message_strings[][SSM_SIZE];

#define	SOLARIS_SOFT_STATE_BOOT_MSG		soft_state_message_ra[0]
#define	SOLARIS_SOFT_STATE_RUN_MSG		soft_state_message_ra[1]
#define	SOLARIS_SOFT_STATE_HALT_MSG		soft_state_message_ra[2]
#define	SOLARIS_SOFT_STATE_POWER_MSG		soft_state_message_ra[3]
#define	SOLARIS_SOFT_STATE_PANIC_MSG		soft_state_message_ra[4]
#define	SOLARIS_SOFT_STATE_REBOOT_MSG		soft_state_message_ra[5]
#define	SOLARIS_SOFT_STATE_DEBUG_MSG		soft_state_message_ra[6]
#define	SOLARIS_SOFT_STATE_SAVED_MSG		soft_state_message_ra[7]
#define	SOLARIS_SOFT_STATE_MSG_CNT		8

extern uint64_t	soft_state_message_ra[SOLARIS_SOFT_STATE_MSG_CNT];

extern void mach_get_soft_state(uint64_t *state,
		uint64_t *string_ra);

extern void mach_set_soft_state(uint64_t state,
		uint64_t *description_ra);

extern void prom_sun4v_soft_state_supported(void);

#endif	/* _ASM */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SOFT_STATE_H */
