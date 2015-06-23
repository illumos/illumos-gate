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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 1996-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SCHEDCTL_H
#define	_SCHEDCTL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/schedctl.h>

typedef sc_public_t schedctl_t;

extern void yield(void);

#define	schedctl_start(p)					\
		(void) (((p) == NULL)? 0 :			\
		((((schedctl_t *)(p))->sc_nopreempt = 1), 0))

#define	schedctl_stop(p)					\
		(void) (((p) == NULL)? 0 :			\
		((((schedctl_t *)(p))->sc_nopreempt = 0),	\
		(((schedctl_t *)(p))->sc_yield? (yield(), 0) : 0)))

/*
 * libsched API
 */
schedctl_t	*schedctl_init(void);
schedctl_t	*schedctl_lookup(void);
void		schedctl_exit(void);

#ifdef __cplusplus
}
#endif

#endif	/* _SCHEDCTL_H */
