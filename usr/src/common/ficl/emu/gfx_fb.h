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
 * Copyright 2016 Toomas Some <tsoome@me.com>
 */

#ifndef _GFX_FB_H
#define	_GFX_FB_H

/*
 * Graphics support for loader emulation.
 */
#include <sys/visual_io.h>
#include <pnglite.h>

#ifdef __cplusplus
extern "C" {
#endif

struct framebuffer {
	struct vis_identifier ident;
	int fd;			/* frame buffer device descriptor */
	uint8_t *fb_addr;	/* mapped framebuffer */

	int fb_height;		/* in pixels */
	int fb_width;		/* in pixels */
	int fb_depth;		/* bits per pixel */
	int fb_bpp;		/* bytes per pixel */
	int fb_size;		/* total size in bytes */
	int fb_pitch;		/* bytes per scanline */
	uint16_t terminal_origin_x;
	uint16_t terminal_origin_y;
	uint16_t font_width;
	uint16_t font_height;
	uint8_t red_mask_size;
	uint8_t red_field_position;
	uint8_t green_mask_size;
	uint8_t green_field_position;
	uint8_t blue_mask_size;
	uint8_t blue_field_position;
};

extern struct framebuffer fb;

void gfx_framework_init(void);
void gfx_framework_fini(void);
void gfx_fb_setpixel(uint32_t, uint32_t);
void gfx_fb_drawrect(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
void gfx_term_drawrect(uint32_t, uint32_t, uint32_t, uint32_t);
void gfx_fb_line(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
void gfx_fb_bezier(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
	uint32_t);
int gfx_fb_putimage(png_t *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* _GFX_FB_H */
