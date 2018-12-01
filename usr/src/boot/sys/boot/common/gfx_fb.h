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
 * Copyright 2017 Toomas Soome <tsoome@me.com>
 */

#ifndef _GFX_FB_H
#define	_GFX_FB_H

#include <stdbool.h>
#include <sys/visual_io.h>
#include <sys/multiboot2.h>
#include <pnglite.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	EDID_MAGIC	{ 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00 }

struct edid_header {
	uint8_t header[8];	/* fixed header pattern */
	uint16_t manufacturer_id;
	uint16_t product_code;
	uint32_t serial_number;
	uint8_t week_of_manufacture;
	uint8_t year_of_manufacture;
	uint8_t version;
	uint8_t revision;
};

struct edid_basic_display_parameters {
	uint8_t video_input_parameters;
	uint8_t max_horizontal_image_size;
	uint8_t max_vertical_image_size;
	uint8_t display_gamma;
	uint8_t supported_features;
};

struct edid_chromaticity_coordinates {
	uint8_t red_green_lo;
	uint8_t blue_white_lo;
	uint8_t red_x_hi;
	uint8_t red_y_hi;
	uint8_t green_x_hi;
	uint8_t green_y_hi;
	uint8_t blue_x_hi;
	uint8_t blue_y_hi;
	uint8_t white_x_hi;
	uint8_t white_y_hi;
};

struct edid_detailed_timings {
	uint16_t pixel_clock;
	uint8_t horizontal_active_lo;
	uint8_t horizontal_blanking_lo;
	uint8_t horizontal_hi;
	uint8_t vertical_active_lo;
	uint8_t vertical_blanking_lo;
	uint8_t vertical_hi;
	uint8_t horizontal_sync_offset_lo;
	uint8_t horizontal_sync_pulse_width_lo;
	uint8_t vertical_sync_lo;
	uint8_t sync_hi;
	uint8_t horizontal_image_size_lo;
	uint8_t vertical_image_size_lo;
	uint8_t image_size_hi;
	uint8_t horizontal_border;
	uint8_t vertical_border;
	uint8_t features;
};

struct vesa_edid_info {
	struct edid_header header;
	struct edid_basic_display_parameters display;
#define	EDID_FEATURE_PREFERRED_TIMING_MODE	(1 << 1)
	struct edid_chromaticity_coordinates chromaticity;
	uint8_t established_timings_1;
	uint8_t established_timings_2;
	uint8_t manufacturer_reserved_timings;
	uint16_t standard_timings[8];
	struct edid_detailed_timings detailed_timings[4];
	uint8_t number_of_extensions;
	uint8_t checksum;
} __packed;

extern multiboot_tag_framebuffer_t gfx_fb;

void gfx_framework_init(struct visual_ops *);
uint32_t gfx_fb_color_map(uint8_t);
void gfx_fb_display_cursor(struct vis_conscursor *);
void gfx_fb_setpixel(uint32_t, uint32_t);
void gfx_fb_drawrect(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
void gfx_term_drawrect(uint32_t, uint32_t, uint32_t, uint32_t);
void gfx_fb_line(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
void gfx_fb_bezier(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
	uint32_t);
void plat_cons_update_mode(int);
int gfx_fb_putimage(png_t *);

bool gfx_parse_mode_str(char *, int *, int *, int *);
#ifdef  __cplusplus
}
#endif

#endif  /* _GFX_FB_H */
