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

#ifndef	_SYS_CONSPLAT_H
#define	_SYS_CONSPLAT_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern int plat_use_polled_debug(void);
extern int plat_support_serial_kbd_and_ms(void);
extern char *plat_kbdpath(void);
extern char *plat_fbpath(void);
extern char *plat_mousepath(void);
extern char *plat_stdinpath(void);
extern char *plat_stdoutpath(void);
extern int plat_stdin_is_keyboard(void);
extern int plat_stdout_is_framebuffer(void);
extern void plat_tem_get_inverses(int *, int *);
extern void plat_tem_get_prom_font_size(int *, int *);
extern void plat_tem_get_prom_size(size_t *, size_t *);
extern void plat_tem_hide_prom_cursor(void);
extern void plat_tem_get_prom_pos(uint32_t *, uint32_t *);
extern int plat_virtual_console_path(char **);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CONSPLAT_H */
