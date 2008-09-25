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

#ifndef	_SYS_TEM_H
#define	_SYS_TEM_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#include <sys/visual_io.h>
#include <sys/cred.h>
#include <sys/beep.h>

typedef struct __tem_modechg_cb_arg *tem_modechg_cb_arg_t;
typedef void (*tem_modechg_cb_t) (tem_modechg_cb_arg_t arg);

typedef	struct __tem_vt_state *tem_vt_state_t;

int	tem_initialized(tem_vt_state_t);

tem_vt_state_t tem_init(cred_t *);

void	tem_destroy(tem_vt_state_t, cred_t *);

int	tem_info_init(char *, cred_t *);

void	tem_write(tem_vt_state_t, uchar_t *, ssize_t, cred_t *);

void	tem_safe_polled_write(tem_vt_state_t, unsigned char *, int);

void	tem_get_size(ushort_t *, ushort_t *, ushort_t *, ushort_t *);

void	tem_register_modechg_cb(tem_modechg_cb_t, tem_modechg_cb_arg_t);

void	tem_activate(tem_vt_state_t, boolean_t, cred_t *);

void	tem_switch(tem_vt_state_t, tem_vt_state_t, cred_t *);

uchar_t	tem_get_fbmode(tem_vt_state_t);

void	tem_set_fbmode(tem_vt_state_t, uchar_t, cred_t *);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_TEM_H */
