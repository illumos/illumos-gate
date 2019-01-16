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
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

#ifndef _SYS_RGB_H
#define	_SYS_RGB_H

/*
 * Color data from bootloader.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

typedef struct rgb_color {
	uint8_t pos;
	uint8_t size;
} rgb_color_t;

typedef struct rgb {
	rgb_color_t red;
	rgb_color_t green;
	rgb_color_t blue;
} rgb_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_RGB_H */
