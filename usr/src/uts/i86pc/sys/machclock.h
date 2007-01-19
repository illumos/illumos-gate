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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MACHCLOCK_H
#define	_SYS_MACHCLOCK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * tod module name and operations
 */

struct tod_ops;
typedef struct tod_ops tod_ops_t;

struct tod_ops {
	int		tod_version;
	timestruc_t	(*tod_get)(tod_ops_t *);
	void		(*tod_set)(tod_ops_t *, timestruc_t);
	/*
	 * On SPARC, additional operations include setting
	 * and clearing a watchdog timer, as well as power alarms.
	 */
	struct tod_ops	*tod_next;
};

#define	TOD_OPS_VERSION	1

extern tod_ops_t	*tod_ops;
extern char		*tod_module_name;

#define	TODOP_GET(top)		((top)->tod_get(top))
#define	TODOP_SET(top, ts)	((top)->tod_set(top, ts))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MACHCLOCK_H */
