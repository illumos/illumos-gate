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
 * Number of "base" colors is 16, 8 dark and 8 bright/light.
 * Color map size for indexed colors is 256, to support VGA 256-color modes.
 */
#define	NCOLORS		16
#define	NCMAP		256

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

extern rgb_t rgb_info;

typedef struct {
	uint8_t red[NCOLORS];
	uint8_t green[NCOLORS];
	uint8_t blue[NCOLORS];
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

typedef enum sun_colors {
	sun_brt_white	= 0,
	sun_black	= 1,
	sun_blue	= 2,
	sun_green	= 3,
	sun_cyan	= 4,
	sun_red		= 5,
	sun_magenta	= 6,
	sun_brown	= 7,
	sun_white	= 8,
	sun_grey	= 9,
	sun_brt_blue	= 10,
	sun_brt_green	= 11,
	sun_brt_cyan	= 12,
	sun_brt_red	= 13,
	sun_brt_magenta	= 14,
	sun_yellow	= 15,
} sun_colors_t;

#define	XLATE_NCOLORS	8
extern const uint8_t dim_xlate[XLATE_NCOLORS];
extern const uint8_t brt_xlate[XLATE_NCOLORS];
extern const uint8_t solaris_color_to_pc_color[NCOLORS];
extern const uint8_t pc_color_to_solaris_color[NCOLORS];

extern uint32_t rgb_to_color(const rgb_t *, uint32_t, uint32_t, uint32_t,
    uint32_t);
extern uint32_t rgb_color_map(const rgb_t *, uint8_t, uint8_t);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_RGB_H */
