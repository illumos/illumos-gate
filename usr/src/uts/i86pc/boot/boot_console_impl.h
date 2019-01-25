/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Toomas Soome <tsome@me.com>
 */

#include <sys/types.h>
#include <sys/bootinfo.h>

#ifndef _BOOT_CONSOLE_IMPL_H
#define	_BOOT_CONSOLE_IMPL_H

/*
 * Boot console implementation details.
 */

#ifdef __cplusplus
extern "C" {
#endif

extern boolean_t xbi_fb_init(struct xboot_info *);
extern void boot_fb_init(int);
extern void boot_fb_putchar(uint8_t);
extern void boot_vga_init(int);

extern void vga_setpos(int, int);
extern void vga_getpos(int *, int *);
extern void vga_scroll(int);
extern void vga_drawc(int, int);

#ifdef __cplusplus
}
#endif

#endif /* _BOOT_CONSOLE_IMPL_H */
