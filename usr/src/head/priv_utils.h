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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This is a private header file.  The interfaces in this header are
 * subject to change or removal without notice.
 * The Sun classification is "Project Private".
 */

#ifndef	_PRIV_UTILS_H
#define	_PRIV_UTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <priv.h>


#ifdef	__cplusplus
extern "C" {
#endif

#define	PU_RESETGROUPS		0x0001	/* Remove supplemental groups */
#define	PU_LIMITPRIVS		0x0002	/* L=P */
#define	PU_INHERITPRIVS		0x0004	/* I=P */
#define	PU_CLEARLIMITSET	0x0008	/* L=0 */

/*
 * Should be run at the start of a set-uid root program;
 * if the effective uid == 0 and the real uid != 0,
 * the specified privileges X are assigned as follows:
 *
 * P = I + X + B (B added insofar allowable from L)
 * E = I
 * (i.e., the requested privileges are dormant, not active)
 * Then resets all uids to the invoking uid; no-op if euid == uid == 0.
 *
 * flags: PU_LIMITPRIVS, PU_CLEARLIMITSET, PU_CLEARINHERITABLE
 *
 * Caches the required privileges for use by __priv_bracket().
 *
 */
extern int __init_suid_priv(int, ...);

/*
 * After calling __init_suid_priv we can __priv_bracket(PRIV_ON) and
 * __priv_bracket(PRIV_OFF) and __priv_relinquish to get rid of the
 * privileges forever.
 */
extern int __priv_bracket(priv_op_t);
extern void __priv_relinquish(void);

/*
 * Runs at the start of a daemon, assuming euid=uid=0.
 *
 * P = E = B + X
 *
 * Then resets uids.
 *
 * Flags: all
 *
 */
extern int __init_daemon_priv(int, uid_t, gid_t, ...);

/*
 * Runs after the daemon is initialized, and gives up the privileges
 * passed in as argument because they are no longer needed.
 * Reenables core dumps.
 */
extern void __fini_daemon_priv(const char *, ...);

#ifdef	__cplusplus
}
#endif

#endif	/* _PRIV_UTILS_H */
