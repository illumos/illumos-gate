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
 * Copyright (c) 2012 Gary Mills
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is shared between dboot and the kernel.
 */

#ifndef _BOOT_CONSOLE_H
#define	_BOOT_CONSOLE_H

#ifdef __cplusplus
extern "C" {
#endif

#define	CONS_INVALID		-1
#define	CONS_SCREEN_TEXT	0
#define	CONS_TTY		1
#define	CONS_XXX		2	/* Unused */
#define	CONS_USBSER		3
#define	CONS_HYPERVISOR		4
#define	CONS_SCREEN_GRAPHICS	5

#define	CONS_MIN	CONS_SCREEN_TEXT
#define	CONS_MAX	CONS_SCREEN_GRAPHICS

#define	CONS_COLOR	7

extern void kb_init(void);
extern int kb_getchar(void);
extern int kb_ischar(void);

extern int boot_console_type(int *);

extern void bcons_init(char *);
extern void bcons_putchar(int);
extern int bcons_getchar(void);
extern int bcons_ischar(void);
extern int bcons_gets(char *, int);

#if !defined(_BOOT)
extern void bcons_init2(char *, char *, char *);
extern boolean_t bcons_hypervisor_redirect(void);
extern void bcons_device_change(int);
#endif /* !_BOOT */

#ifdef __cplusplus
}
#endif

#endif /* _BOOT_CONSOLE_H */
