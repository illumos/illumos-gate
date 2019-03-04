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

/*
 * Graphics support for loader emulation.
 * The interface in loader and here needs some more development.
 * We can get colormap from gfx_private, but loader is currently
 * relying on tem fg/bg colors for drawing, once the menu code
 * will get some facelift, we would need to provide colors as menu component
 * attributes and stop depending on tem.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/fbio.h>
#include <string.h>
#include "gfx_fb.h"

struct framebuffer fb;

#define	max(x, y)	((x) >= (y) ? (x) : (y))

static void gfx_fb_cons_display(uint32_t, uint32_t,
    uint32_t, uint32_t, uint8_t *);

/* This colormap should be replaced by colormap query from kernel */
typedef struct {
	uint8_t red[16];
	uint8_t green[16];
	uint8_t blue[16];
} text_cmap_t;

text_cmap_t cmap4_to_24 = {
/* BEGIN CSTYLED */
/*             0    1    2    3    4    5    6    7    8    9   10   11   12   13   14   15
              Wh+  Bk   Bl   Gr   Cy   Rd   Mg   Br   Wh   Bk+  Bl+  Gr+  Cy+  Rd+  Mg+  Yw */
  .red   = {0xff,0x00,0x00,0x00,0x00,0x80,0x80,0x80,0x80,0x40,0x00,0x00,0x00,0xff,0xff,0xff},
  .green = {0xff,0x00,0x00,0x80,0x80,0x00,0x00,0x80,0x80,0x40,0x00,0xff,0xff,0x00,0x00,0xff},
  .blue  = {0xff,0x00,0x80,0x00,0x80,0x00,0x80,0x00,0x80,0x40,0xff,0x00,0xff,0x00,0xff,0x00}
/* END CSTYLED */
};

const uint8_t solaris_color_to_pc_color[16] = {
    15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
};

void
gfx_framework_init(void)
{
	struct fbgattr attr;
	struct gfxfb_info *gfxfb_info;
	char buf[10];

	fb.fd = open("/dev/fb", O_RDWR);
	if (fb.fd < 0)
		return;

	/* make sure we have GFX framebuffer */
	if (ioctl(fb.fd, VIS_GETIDENTIFIER, &fb.ident) < 0 ||
	    strcmp(fb.ident.name, "illumos_fb") != 0) {
		(void) close(fb.fd);
		fb.fd = -1;
		return;
	}

	if (ioctl(fb.fd, FBIOGATTR, &attr) < 0) {
		(void) close(fb.fd);
		fb.fd = -1;
		return;
	}
	gfxfb_info = (struct gfxfb_info *)attr.sattr.dev_specific;

	fb.fb_height = attr.fbtype.fb_height;
	fb.fb_width = attr.fbtype.fb_width;
	fb.fb_depth = attr.fbtype.fb_depth;
	fb.fb_size = attr.fbtype.fb_size;
	fb.fb_bpp = attr.fbtype.fb_depth >> 3;
	if (attr.fbtype.fb_depth == 15)
		fb.fb_bpp = 2;
	fb.fb_pitch = gfxfb_info->pitch;
	fb.terminal_origin_x = gfxfb_info->terminal_origin_x;
	fb.terminal_origin_y = gfxfb_info->terminal_origin_y;
	fb.font_width = gfxfb_info->font_width;
	fb.font_height = gfxfb_info->font_height;

	fb.red_mask_size = gfxfb_info->red_mask_size;
	fb.red_field_position = gfxfb_info->red_field_position;
	fb.green_mask_size = gfxfb_info->green_mask_size;
	fb.green_field_position = gfxfb_info->green_field_position;
	fb.blue_mask_size = gfxfb_info->blue_mask_size;
	fb.blue_field_position = gfxfb_info->blue_field_position;

	fb.fb_addr = (uint8_t *)mmap(0, fb.fb_size, (PROT_READ | PROT_WRITE),
	    MAP_SHARED, fb.fd, 0);

	if (fb.fb_addr == NULL) {
		(void) close(fb.fd);
		fb.fd = -1;
		return;
	}
	(void) snprintf(buf, sizeof (buf), "%d", fb.fb_height);
	(void) setenv("screen-height", buf, 1);
	(void) snprintf(buf, sizeof (buf), "%d", fb.fb_width);
	(void) setenv("screen-width", buf, 1);
}

void
gfx_framework_fini(void)
{
	if (fb.fd < 0)
		return;

	(void) munmap((caddr_t)fb.fb_addr, fb.fb_size);
	(void) close(fb.fd);
	fb.fd = -1;
}

static int
isqrt(int num)
{
	int res = 0;
	int bit = 1 << 30;

	/* "bit" starts at the highest power of four <= the argument. */
	while (bit > num)
		bit >>= 2;

	while (bit != 0) {
		if (num >= res + bit) {
			num -= res + bit;
			res = (res >> 1) + bit;
		} else {
			res >>= 1;
		}
		bit >>= 2;
	}
	return (res);
}

void
gfx_fb_setpixel(uint32_t x, uint32_t y)
{
	uint32_t c, offset;

	if (fb.fd < 0)
		return;
	c = 0;		/* black */

	if (x >= fb.fb_width || y >= fb.fb_height)
		return;

	offset = y * fb.fb_pitch + x * fb.fb_bpp;
	switch (fb.fb_depth) {
	case 8:
		fb.fb_addr[offset] = c & 0xff;
		break;
	case 15:
	case 16:
		*(uint16_t *)(fb.fb_addr + offset) = c & 0xffff;
		break;
	case 24:
		fb.fb_addr[offset] = (c >> 16) & 0xff;
		fb.fb_addr[offset + 1] = (c >> 8) & 0xff;
		fb.fb_addr[offset + 2] = c & 0xff;
		break;
	case 32:
		*(uint32_t *)(fb.fb_addr + offset) = c;
		break;
	}
}

void
gfx_fb_drawrect(uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2,
    uint32_t fill)
{
	int x, y;

	if (fb.fd < 0)
		return;

	for (y = y1; y <= y2; y++) {
		if (fill || (y == y1) || (y == y2)) {
			for (x = x1; x <= x2; x++)
				gfx_fb_setpixel(x, y);
		} else {
			gfx_fb_setpixel(x1, y);
			gfx_fb_setpixel(x2, y);
		}
	}
}

void
gfx_term_drawrect(uint32_t row1, uint32_t col1, uint32_t row2, uint32_t col2)
{
	int x1, y1, x2, y2;
	int xshift, yshift;
	int width, i;

	if (fb.fd < 0)
		return;

	width = fb.font_width / 4;	/* line width */
	xshift = (fb.font_width - width) / 2;
	yshift = (fb.font_height - width) / 2;
	/* Terminal coordinates start from (1,1) */
	row1--;
	col1--;
	row2--;
	col2--;

	/*
	 * Draw horizontal lines width points thick, shifted from outer edge.
	 */
	x1 = (row1 + 1) * fb.font_width + fb.terminal_origin_x;
	y1 = col1 * fb.font_height + fb.terminal_origin_y + yshift;
	x2 = row2 * fb.font_width + fb.terminal_origin_x;
	gfx_fb_drawrect(x1, y1, x2, y1 + width, 1);
	y2 = col2 * fb.font_height + fb.terminal_origin_y;
	y2 += fb.font_height - yshift - width;
	gfx_fb_drawrect(x1, y2, x2, y2 + width, 1);

	/*
	 * Draw vertical lines width points thick, shifted from outer edge.
	 */
	x1 = row1 * fb.font_width + fb.terminal_origin_x + xshift;
	y1 = col1 * fb.font_height + fb.terminal_origin_y;
	y1 += fb.font_height;
	y2 = col2 * fb.font_height + fb.terminal_origin_y;
	gfx_fb_drawrect(x1, y1, x1 + width, y2, 1);
	x1 = row2 * fb.font_width + fb.terminal_origin_x;
	x1 += fb.font_width - xshift - width;
	gfx_fb_drawrect(x1, y1, x1 + width, y2, 1);

	/* Draw upper left corner. */
	x1 = row1 * fb.font_width + fb.terminal_origin_x + xshift;
	y1 = col1 * fb.font_height + fb.terminal_origin_y;
	y1 += fb.font_height;

	x2 = row1 * fb.font_width + fb.terminal_origin_x;
	x2 += fb.font_width;
	y2 = col1 * fb.font_height + fb.terminal_origin_y + yshift;
	for (i = 0; i <= width; i++)
		gfx_fb_bezier(x1 + i, y1, x1 + i, y2 + i, x2, y2 + i, width-i);

	/* Draw lower left corner. */
	x1 = row1 * fb.font_width + fb.terminal_origin_x;
	x1 += fb.font_width;
	y1 = col2 * fb.font_height + fb.terminal_origin_y;
	y1 += fb.font_height - yshift;
	x2 = row1 * fb.font_width + fb.terminal_origin_x + xshift;
	y2 = col2 * fb.font_height + fb.terminal_origin_y;
	for (i = 0; i <= width; i++)
		gfx_fb_bezier(x1, y1 - i, x2 + i, y1 - i, x2 + i, y2, width-i);

	/* Draw upper right corner. */
	x1 = row2 * fb.font_width + fb.terminal_origin_x;
	y1 = col1 * fb.font_height + fb.terminal_origin_y + yshift;
	x2 = row2 * fb.font_width + fb.terminal_origin_x;
	x2 += fb.font_width - xshift - width;
	y2 = col1 * fb.font_height + fb.terminal_origin_y;
	y2 += fb.font_height;
	for (i = 0; i <= width; i++)
		gfx_fb_bezier(x1, y1 + i, x2 + i, y1 + i, x2 + i, y2, width-i);

	/* Draw lower right corner. */
	x1 = row2 * fb.font_width + fb.terminal_origin_x;
	y1 = col2 * fb.font_height + fb.terminal_origin_y;
	y1 += fb.font_height - yshift;
	x2 = row2 * fb.font_width + fb.terminal_origin_x;
	x2 += fb.font_width - xshift - width;
	y2 = col2 * fb.font_height + fb.terminal_origin_y;
	for (i = 0; i <= width; i++)
		gfx_fb_bezier(x1, y1 - i, x2 + i, y1 - i, x2 + i, y2, width-i);
}

void
gfx_fb_line(uint32_t x0, uint32_t y0, uint32_t x1, uint32_t y1, uint32_t width)
{
	int dx, sx, dy, sy;
	int err, e2, x2, y2, ed;

	if (fb.fd < 0)
		return;

	sx = x0 < x1? 1 : -1;
	sy = y0 < y1? 1 : -1;
	dx = abs(x1 - x0);
	dy = abs(y1 - y0);
	err = dx - dy;
	ed = dx + dy == 0 ? 1 : isqrt(dx * dx + dy * dy);

	if (dx != 0 && dy != 0)
		width = (width + 1) >> 1;

	for (;;) {
		gfx_fb_setpixel(x0, y0);
		e2 = err;
		x2 = x0;
		if ((e2 << 1) >= -dx) {		/* x step */
			e2 += dy;
			y2 = y0;
			while (e2 < ed * width && (y1 != y2 || dx > dy)) {
				y2 += sy;
				gfx_fb_setpixel(x0, y2);
				e2 += dx;
			}
			if (x0 == x1)
				break;
			e2 = err;
			err -= dy;
			x0 += sx;
		}
		if ((e2 << 1) <= dy) {		/* y step */
			e2 = dx-e2;
			while (e2 < ed * width && (x1 != x2 || dx < dy)) {
				x2 += sx;
				gfx_fb_setpixel(x2, y0);
				e2 += dy;
			}
			if (y0 == y1)
				break;
			err += dx;
			y0 += sy;
		}
	}
}

void
gfx_fb_bezier(uint32_t x0, uint32_t y0, uint32_t x1, uint32_t y1, uint32_t x2,
    uint32_t y2, uint32_t wd)
{
	int sx, sy, xx, yy, xy, width;
	int dx, dy, err, curvature;
	int i;

	if (fb.fd < 0)
		return;

	width = wd;
	sx = x2 - x1;
	sy = y2 - y1;
	xx = x0 - x1;
	yy = y0 - y1;
	curvature = xx*sy - yy*sx;

	if (sx * sx + sy * sy > xx * xx + yy * yy) {
		x2 = x0;
		x0 = sx + x1;
		y2 = y0;
		y0 = sy + y1;
		curvature = -curvature;
	}
	if (curvature != 0) {
		xx += sx;
		sx = x0 < x2? 1 : -1;
		xx *= sx;
		yy += sy;
		sy = y0 < y2? 1 : -1;
		yy *= sy;
		xy = 2 * xx * yy;
		xx *= xx;
		yy *= yy;
		if (curvature * sx * sy < 0) {
			xx = -xx;
			yy = -yy;
			xy = -xy;
			curvature = -curvature;
		}
		dx = 4 * sy * curvature * (x1 - x0) + xx - xy;
		dy = 4 * sx * curvature * (y0 - y1) + yy - xy;
		xx += xx;
		yy += yy;
		err = dx + dy + xy;
		do {
			for (i = 0; i <= width; i++)
				gfx_fb_setpixel(x0 + i, y0);
			if (x0 == x2 && y0 == y2)
				return;  /* last pixel -> curve finished */
			y1 = 2 * err < dx;
			if (2 * err > dy) {
				x0 += sx;
				dx -= xy;
				dy += yy;
				err += dy;
			}
			if (y1 != 0) {
				y0 += sy;
				dy -= xy;
				dx += xx;
				err += dx;
			}
		} while (dy < dx); /* gradient negates -> algorithm fails */
	}
	gfx_fb_line(x0, y0, x2, y2, width);
}

#define	FL_PUTIMAGE_BORDER	0x1
#define	FL_PUTIMAGE_NOSCROLL	0x2
#define	FL_PUTIMAGE_DEBUG	0x80

int
gfx_fb_putimage(png_t *png, uint32_t ux1, uint32_t uy1, uint32_t ux2,
    uint32_t uy2, uint32_t flags)
{
	uint32_t i, j, x, y, fheight, fwidth, color;
	uint8_t r, g, b, a, *p, *data;
	bool scale = false;
	bool trace = false;

	trace = (flags & FL_PUTIMAGE_DEBUG) != 0;

	if (fb.fd < 0) {
		if (trace)
			printf("Framebuffer not active.\n");
		return (1);
	}

	if (png->color_type != PNG_TRUECOLOR_ALPHA) {
		if (trace)
			printf("Not truecolor image.\n");
		return (1);
	}

	if (ux1 > fb.fb_width || uy1 > fb.fb_height) {
		if (trace)
			printf("Top left coordinate off screen.\n");
		return (1);
	}

	if (png->width > UINT16_MAX || png->height > UINT16_MAX) {
		if (trace)
			printf("Image too large.\n");
		return (1);
	}

	if (png->width < 1 || png->height < 1) {
		if (trace)
			printf("Image too small.\n");
		return (1);
	}

	/*
	 * If 0 was passed for either ux2 or uy2, then calculate the missing
	 * part of the bottom right coordinate.
	 */
	scale = true;
	if (ux2 == 0 && uy2 == 0) {
		/* Both 0, use the native resolution of the image */
		ux2 = ux1 + png->width;
		uy2 = uy1 + png->height;
		scale = false;
	} else if (ux2 == 0) {
		/* Set ux2 from uy2/uy1 to maintain aspect ratio */
		ux2 = ux1 + (png->width * (uy2 - uy1)) / png->height;
	} else if (uy2 == 0) {
		/* Set uy2 from ux2/ux1 to maintain aspect ratio */
		uy2 = uy1 + (png->height * (ux2 - ux1)) / png->width;
	}

	if (ux2 > fb.fb_width || uy2 > fb.fb_height) {
		if (trace)
			printf("Bottom right coordinate off screen.\n");
		return (1);
	}

	fwidth = ux2 - ux1;
	fheight = uy2 - uy1;

	/*
	 * If the original image dimensions have been passed explicitly,
	 * disable scaling.
	 */
	if (fwidth == png->width && fheight == png->height)
		scale = false;

	if (ux1 == 0) {
		/*
		 * No top left X co-ordinate (real coordinates start at 1),
		 * place as far right as it will fit.
		 */
		ux2 = fb.fb_width - fb.terminal_origin_x;
		ux1 = ux2 - fwidth;
	}

	if (uy1 == 0) {
		/*
		 * No top left Y co-ordinate (real coordinates start at 1),
		 * place as far down as it will fit.
		 */
		uy2 = fb.fb_height - fb.terminal_origin_y;
		uy1 = uy2 - fheight;
	}

	if (ux1 >= ux2 || uy1 >= uy2) {
		if (trace)
			printf("Image dimensions reversed.\n");
		return (1);
	}

	if (fwidth < 2 || fheight < 2) {
		if (trace)
			printf("Target area too small\n");
		return (1);
	}

	if (trace)
		printf("Image %ux%u -> %ux%u @%ux%u\n",
		    png->width, png->height, fwidth, fheight, ux1, uy1);

	if ((flags & FL_PUTIMAGE_BORDER))
		gfx_fb_drawrect(ux1, uy1, ux2, uy2, 0);

	data = malloc(fwidth * fheight * fb.fb_bpp);
	if (data == NULL) {
		if (trace)
			printf("Out of memory.\n");
		return (1);
	}

	/*
	 * Build image for our framebuffer.
	 */

	/* Helper to calculate the pixel index from the source png */
#define	GETPIXEL(xx, yy) (((yy) * png->width + (xx)) * png->bpp)

	/*
	 * For each of the x and y directions, calculate the number of pixels
	 * in the source image that correspond to a single pixel in the target.
	 * Use fixed-point arithmetic with 16-bits for each of the integer and
	 * fractional parts.
	 */
	const uint32_t wcstep = ((png->width - 1) << 16) / (fwidth - 1);
	const uint32_t hcstep = ((png->height - 1) << 16) / (fheight - 1);

	uint32_t hc = 0;
	for (y = 0; y < fheight; y++) {
		uint32_t hc2 = (hc >> 9) & 0x7f;
		uint32_t hc1 = 0x80 - hc2;

		uint32_t offset_y = hc >> 16;
		uint32_t offset_y1 = offset_y + 1;

		uint32_t wc = 0;
		for (x = 0; x < fwidth; x++) {
			uint32_t wc2 = (wc >> 9) & 0x7f;
			uint32_t wc1 = 0x80 - wc2;

			uint32_t offset_x = wc >> 16;
			uint32_t offset_x1 = offset_x + 1;

			/* Target pixel index */
			j = (y * fwidth + x) * fb.fb_bpp;

			if (!scale) {
				i = GETPIXEL(x, y);
				r = png->image[i];
				g = png->image[i + 1];
				b = png->image[i + 2];
				a = png->image[i + 3];
			} else {
				uint8_t pixel[4];

				uint32_t p00 = GETPIXEL(offset_x, offset_y);
				uint32_t p01 = GETPIXEL(offset_x, offset_y1);
				uint32_t p10 = GETPIXEL(offset_x1, offset_y);
				uint32_t p11 = GETPIXEL(offset_x1, offset_y1);

				/*
				 * Given a 2x2 array of pixels in the source
				 * image, combine them to produce a single
				 * value for the pixel in the target image.
				 * Each column of pixels is combined using
				 * a weighted average where the top and bottom
				 * pixels contribute hc1 and hc2 respectively.
				 * The calculation for bottom pixel pB and
				 * top pixel pT is:
				 *   (pT * hc1 + pB * hc2) / (hc1 + hc2)
				 * Once the values are determined for the two
				 * columns of pixels, then the columns are
				 * averaged together in the same way but using
				 * wc1 and wc2 for the weightings.
				 *
				 * Since hc1 and hc2 are chosen so that
				 * hc1 + hc2 == 128 (and same for wc1 + wc2),
				 * the >> 14 below is a quick way to divide by
				 * (hc1 + hc2) * (wc1 + wc2)
				 */
				for (i = 0; i < 4; i++)
					pixel[i] = (
					    (png->image[p00 + i] * hc1 +
					    png->image[p01 + i] * hc2) * wc1 +
					    (png->image[p10 + i] * hc1 +
					    png->image[p11 + i] * hc2) * wc2)
					    >> 14;

				r = pixel[0];
				g = pixel[1];
				b = pixel[2];
				a = pixel[3];
			}

			color =
			    r >> (8 - fb.red_mask_size)
			    << fb.red_field_position |
			    g >> (8 - fb.green_mask_size)
			    << fb.green_field_position |
			    b >> (8 - fb.blue_mask_size)
			    << fb.blue_field_position;

			switch (fb.fb_depth) {
			case 8: {
				uint32_t best, dist, k;
				int diff;

				color = 0;
				best = 256 * 256 * 256;
				for (k = 0; k < 16; k++) {
					diff = r - cmap4_to_24.red[k];
					dist = diff * diff;
					diff = g - cmap4_to_24.green[k];
					dist += diff * diff;
					diff = b - cmap4_to_24.blue[k];
					dist += diff * diff;

					if (dist < best) {
						color = k;
						best = dist;
						if (dist == 0)
							break;
					}
				}
				data[j] = solaris_color_to_pc_color[color];
				break;
			}
			case 15:
			case 16:
				*(uint16_t *)(data+j) = color;
				break;
			case 24:
				p = (uint8_t *)&color;
				data[j] = p[0];
				data[j+1] = p[1];
				data[j+2] = p[2];
				break;
			case 32:
				color |= a << 24;
				*(uint32_t *)(data+j) = color;
				break;
			}
			wc += wcstep;
		}
		hc += hcstep;
	}

	gfx_fb_cons_display(uy1, ux1, fwidth, fheight, data);
	free(data);
	return (0);
}

/*
 * Implements alpha blending for RGBA data, could use pixels for arguments,
 * but byte stream seems more generic.
 * The generic alpha blending is:
 * blend = alpha * fg + (1.0 - alpha) * bg.
 * Since our alpha is not from range [0..1], we scale appropriately.
 */
static uint8_t
alpha_blend(uint8_t fg, uint8_t bg, uint8_t alpha)
{
	uint16_t blend, h, l;

	/* trivial corner cases */
	if (alpha == 0)
		return (bg);
	if (alpha == 0xFF)
		return (fg);
	blend = (alpha * fg + (0xFF - alpha) * bg);
	/* Division by 0xFF */
	h = blend >> 8;
	l = blend & 0xFF;
	if (h + l >= 0xFF)
		h++;
	return (h);
}

/* Copy memory to framebuffer or to memory. */
static void
bitmap_cpy(uint8_t *dst, uint8_t *src, uint32_t len, int bpp)
{
	uint32_t i;
	uint8_t a;

	switch (bpp) {
	case 4:
		for (i = 0; i < len; i += bpp) {
			a = src[i+3];
			dst[i] = alpha_blend(src[i], dst[i], a);
			dst[i+1] = alpha_blend(src[i+1], dst[i+1], a);
			dst[i+2] = alpha_blend(src[i+2], dst[i+2], a);
			dst[i+3] = a;
		}
		break;
	default:
		(void) memcpy(dst, src, len);
		break;
	}
}

/*
 * gfx_fb_cons_display implements direct draw on frame buffer memory.
 * It is needed till we have way to send bitmaps to tem, tem already has
 * function to send data down to framebuffer.
 */
static void
gfx_fb_cons_display(uint32_t row, uint32_t col,
    uint32_t width, uint32_t height, uint8_t *data)
{
	uint32_t size;		/* write size per scanline */
	uint8_t *fbp;		/* fb + calculated offset */
	int i;

	/* make sure we will not write past FB */
	if (col >= fb.fb_width || row >= fb.fb_height ||
	    col + width > fb.fb_width || row + height > fb.fb_height)
		return;

	size = width * fb.fb_bpp;
	fbp = fb.fb_addr + col * fb.fb_bpp + row * fb.fb_pitch;

	/* write all scanlines in rectangle */
	for (i = 0; i < height; i++) {
		uint8_t *dest = fbp + i * fb.fb_pitch;
		uint8_t *src = data + i * size;
		bitmap_cpy(dest, src, size, fb.fb_bpp);
	}
}
