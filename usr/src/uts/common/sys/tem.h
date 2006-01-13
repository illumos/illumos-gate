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

#ifndef	_SYS_TEM_H
#define	_SYS_TEM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#include <sys/visual_io.h>
#include <sys/cred.h>
#include <sys/beep.h>

typedef struct __tem_modechg_cb_arg *tem_modechg_cb_arg_t;
typedef void (*tem_modechg_cb_t) (tem_modechg_cb_arg_t arg);

struct tem;
int	tem_init(struct tem **,
			char *, cred_t *);
void	tem_write(struct tem *,
			uchar_t *, ssize_t, cred_t *);
void	tem_polled_write(struct tem *,
			unsigned char *, int);
void	tem_get_size(struct tem *, ushort_t *, ushort_t *,
			ushort_t *, ushort_t *);
int	tem_fini(struct tem *);

void	tem_register_modechg_cb(struct tem *, tem_modechg_cb_t,
					tem_modechg_cb_arg_t);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_TEM_H */
