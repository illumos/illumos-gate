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

#ifndef _BOOT_CONSOLE_IMPL_H
#define	_BOOT_CONSOLE_IMPL_H

#include <sys/types.h>
#include <sys/bootinfo.h>

/*
 * Boot console implementation details.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Console device callbacks. */
typedef struct bcons_dev {
	void (*bd_putchar)(int);
	void (*bd_eraseline)(void);
	void (*bd_cursor)(boolean_t);
	void (*bd_setpos)(int, int);
	void (*bd_shift)(int);
} bcons_dev_t;

extern boolean_t xbi_fb_init(struct xboot_info *, bcons_dev_t *);
extern void boot_fb_init(int);
extern void boot_vga_init(bcons_dev_t *);
extern void boot_get_color(uint32_t *, uint32_t *);

#ifdef __cplusplus
}
#endif

#endif /* _BOOT_CONSOLE_IMPL_H */
