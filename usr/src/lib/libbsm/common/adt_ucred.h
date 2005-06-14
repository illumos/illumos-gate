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
 * adt_ucred.h
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This is a private interface and is subject to change
 */

#ifndef _ADT_UCRED_H
#define	_ADT_UCRED_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <bsm/audit.h>
#include <ucred.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern	au_id_t ucred_getauid(const ucred_t *uc);
extern	au_asid_t ucred_getasid(const ucred_t *uc);
extern	const au_mask_t *ucred_getamask(const ucred_t *uc);
extern	const au_tid64_addr_t *ucred_getatid(const ucred_t *uc);

#ifdef	__cplusplus
}
#endif

#endif	/* _ADT_UCRED_H */
