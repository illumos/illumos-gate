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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_KLPD_H
#define	_KLPD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/klpd.h>
#include <priv.h>
#include <ucred.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern void *klpd_create(boolean_t (*)(void *, const priv_set_t *, void *),
    void *);
extern int klpd_register_id(const priv_set_t *, void *, idtype_t, id_t);
extern int klpd_register(const priv_set_t *, void *);
extern int klpd_unregister_id(void *, idtype_t, id_t);
extern int klpd_unregister(void *);
extern const char *klpd_getpath(void *);
extern int klpd_getport(void *, int *);
extern int klpd_getucred(ucred_t **, void *);

#ifdef	__cplusplus
}
#endif

#endif	/* _KLPD_H */
