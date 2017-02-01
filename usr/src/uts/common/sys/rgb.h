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
 * Copyright 2018 Toomas Soome <tsoome@me.com>
 */

#ifndef _SYS_RGB_H
#define	_SYS_RGB_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Color data from bootloader.
 */
typedef struct rgb_color {
	uint8_t pos;
	uint8_t size;
} rgb_color_t;

typedef struct rgb {
	rgb_color_t red;
	rgb_color_t green;
	rgb_color_t blue;
} rgb_t;

typedef struct {
	uint8_t red[16];
	uint8_t green[16];
	uint8_t blue[16];
} text_cmap_t;

extern const text_cmap_t cmap4_to_24;
/*
 * ANSI color to sun color translation.
 */

/* The pc color here is actually referring to standard 16 color VGA map. */
typedef enum pc_colors {
	pc_black	= 0,
	pc_blue		= 1,
	pc_green	= 2,
	pc_cyan		= 3,
	pc_red		= 4,
	pc_magenta	= 5,
	pc_brown	= 6,
	pc_white	= 7,
	pc_grey		= 8,
	pc_brt_blue	= 9,
	pc_brt_green	= 10,
	pc_brt_cyan	= 11,
	pc_brt_red	= 12,
	pc_brt_magenta	= 13,
	pc_yellow	= 14,
	pc_brt_white	= 15
} pc_colors_t;

extern const uint8_t dim_xlate[];
extern const uint8_t brt_xlate[];
extern const uint8_t solaris_color_to_pc_color[16];

#ifdef __cplusplus
}
#endif

#endif /* _SYS_RGB_H */
