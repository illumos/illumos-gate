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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYSV_FUNCTIONS_H
#define	_SYSV_FUNCTIONS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern void vsysv_queue_entry(job_t *job, va_list ap);
extern int sysv_queue_state(print_queue_t *qp, char *printer, int verbose,
		int description);
extern int sysv_accept(ns_bsd_addr_t *binding);
extern int sysv_system(ns_bsd_addr_t *binding);
extern void sysv_running();
extern void sysv_default();
extern int sysv_local_status(char *, char *, int, int, char *);
extern print_queue_t *sysv_get_queue(ns_bsd_addr_t *binding, int local);

#ifdef	__cplusplus
}
#endif

#endif /* _SYSV_FUNCTIONS_H */
