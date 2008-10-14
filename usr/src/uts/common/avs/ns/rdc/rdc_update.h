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

#ifndef	_RDC_UPDATE_H
#define	_RDC_UPDATE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rdc_update_s {
	spcs_s_info_t status;
	int	protocol;		/* semantics of update svc */
	char	*volume;		/* volume name */
	uchar_t	*bitmap;		/* set of changes to be made */
	int	size;			/* size of bitmap in bytes */
	int	denied;			/* don't do it? */
} rdc_update_t;

	/* semantics of update svc call */
#define	RDC_SVC_ONRETURN	0	/* caller will update on return */
#define	RDC_SVC_VOL_ENABLED	1	/* tell me if a given vol is enabled */

#ifdef __cplusplus
}
#endif

#endif	/* _RDC_UPDATE_H */
