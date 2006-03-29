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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SBDP_ERROR_H
#define	_SYS_SBDP_ERROR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sbd_ioctl.h>
#include <sys/sbd.h>

/*
 * sbdp error injection
 */

extern int sbdp_inject_error(const char *, uint_t);

#ifdef DEBUG
#define	SBDP_INJECT_ERROR	sbdp_inject_error
#else /* DEBUG */
#define	SBDP_INJECT_ERROR(f, e)	0
#endif /* DEBUG */

extern int sbdp_passthru_inject_error(sbdp_handle_t *, void *);
extern int sbdp_passthru_reset_error(sbdp_handle_t *, void *);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SBDP_ERROR_H */
