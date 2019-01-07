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
/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*		All Rights Reserved	*/

#ifndef	_SYS_TEM_H
#define	_SYS_TEM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/visual_io.h>

typedef uint8_t text_color_t;

typedef struct __tem_modechg_cb_arg *tem_modechg_cb_arg_t;
typedef void (*tem_modechg_cb_t) (tem_modechg_cb_arg_t arg);
typedef	struct __tem_vt_state *tem_vt_state_t;

/*
 * tems_* fuctions mean that they just operate on the common soft state
 * (tem_state_t), and tem_* functions mean that they operate on the
 * per-tem structure (tem_vt_state).
 */
int	tems_cls(struct vis_consclear *);
void	tems_display(struct vis_consdisplay *);
void	tems_copy(struct vis_conscopy *);
void	tems_cursor(struct vis_conscursor *);

int	tem_initialized(tem_vt_state_t);

tem_vt_state_t tem_init(void);

int	tem_info_init(struct console *);
void	tem_write(tem_vt_state_t, uint8_t *, ssize_t);
void	tem_get_size(uint16_t *, uint16_t *, uint16_t *, uint16_t *);
void	tem_save_state(void);
void	tem_register_modechg_cb(tem_modechg_cb_t, tem_modechg_cb_arg_t);
void	tem_activate(tem_vt_state_t, boolean_t);
void	tem_switch(tem_vt_state_t, tem_vt_state_t);
void	tem_get_colors(tem_vt_state_t, text_color_t *, text_color_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_TEM_H */
