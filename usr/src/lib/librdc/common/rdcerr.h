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

#ifndef	_RDCERR_H
#define	_RDCERR_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_s_impl.h>
#include <sys/unistat/spcs_errors.h>

/* serious error? */
#define	RDC_FATAL	0x02
#define	RDC_NONFATAL	0x03

/* types of errors */
#define	RDC_INTERNAL	0x01
#define	RDC_OS		0X02
#define	RDC_SPCS	0x04
#define	RDC_DSCFG	0x08

/* errors */
#define	RDC_EINVAL	"Invalid argument"

#define	RDC_NAME_DU_JOUR "Remote Mirror"

#ifndef	RDC_ERR_SIZE
#define	RDC_ERR_SIZE	256
#endif


void
rdc_set_error(spcs_s_info_t *ustatus, int context, int severity,
char *errorstr, ...);

char *
rdc_err(int *severity);

#ifdef	__cplusplus
}
#endif

#endif	/* _RDCERR_H */
