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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _BOOT_VGA_H
#define	_BOOT_VGA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Interface to the bootstrap's internal VGA driver.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	VGA_IO_WMR	0x3C8 /* vga io DAC write mode register */
#define	VGA_IO_DR	0x3C9 /* vga io DAC data register */
#define	VGA_IO_IS	0x3DA /* vga io input status register */

#define	VGA_TEXT_COLS		80
#define	VGA_TEXT_ROWS		25

extern void vga_setpos(int, int);
extern void vga_getpos(int *, int *);
extern void vga_clear(int);
extern void vga_scroll(int);
extern void vga_drawc(int, int);
extern void vga_cursor_display(void);

#ifdef __cplusplus
}
#endif

#endif /* _BOOT_VGA_H */
