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
 * Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2020 RackTop Systems, Inc.
 */

/*
 * The workhorse here is gfxfb_blt(). It is implemented to mimic UEFI
 * GOP Blt, and allows us to fill the rectangle on screen, copy
 * rectangle from video to buffer and buffer to video and video to video.
 * Such implementation does allow us to have almost identical implementation
 * for both BIOS VBE and UEFI.
 *
 * ALL pixel data is assumed to be 32-bit BGRA (byte order Blue, Green, Red,
 * Alpha) format, this allows us to only handle RGB data and not to worry
 * about mixing RGB with indexed colors.
 * Data exchange between memory buffer and video will translate BGRA
 * and native format as following:
 *
 * 32-bit to/from 32-bit is trivial case.
 * 32-bit to/from 24-bit is also simple - we just drop the alpha channel.
 * 32-bit to/from 16-bit is more complicated, because we nee to handle
 * data loss from 32-bit to 16-bit. While reading/writing from/to video, we
 * need to apply masks of 16-bit color components. This will preserve
 * colors for terminal text. For 32-bit truecolor PMG images, we need to
 * translate 32-bit colors to 15/16 bit colors and this means data loss.
 * There are different algorithms how to perform such color space reduction,
 * we are currently using bitwise right shift to reduce color space and so far
 * this technique seems to be sufficient (see also gfx_fb_putimage(), the
 * end of for loop).
 * 32-bit to/from 8-bit is the most troublesome because 8-bit colors are
 * indexed. From video, we do get color indexes, and we do translate
 * color index values to RGB. To write to video, we again need to translate
 * RGB to color index. Additionally, we need to translate between VGA and
 * Sun colors.
 *
 * Our internal color data is represented using BGRA format. But the hardware
 * used indexed colors for 8-bit colors (0-255) and for this mode we do
 * need to perform translation to/from BGRA and index values.
 *
 *                   - paletteentry RGB <-> index -
 * BGRA BUFFER <----/                              \ - VIDEO
 *                  \                              /
 *                   -  RGB (16/24/32)            -
 *
 * To perform index to RGB translation, we use palette table generated
 * from when we set up 8-bit mode video. We cannot read palette data from
 * the hardware, because not all hardware supports reading it.
 *
 * BGRA to index is implemented in rgb_to_color_index() by searching
 * palette array for closest match of RBG values.
 *
 * Note: In 8-bit mode, We do store first 16 colors to palette registers
 * in VGA color order, this serves two purposes; firstly,
 * if palette update is not supported, we still have correct 16 colors.
 * Secondly, the kernel does get correct 16 colors when some other boot
 * loader is used. However, the palette map for 8-bit colors is using
 * Sun color ordering - this does allow us to skip translation
 * from VGA colors to Sun colors, while we are reading RGB data.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <stand.h>
#if defined(EFI)
#include <efi.h>
#include <efilib.h>
#include <Protocol/GraphicsOutput.h>
#else
#include <btxv86.h>
#include <vbe.h>
#endif
#include <sys/tem_impl.h>
#include <sys/consplat.h>
#include <sys/visual_io.h>
#include <sys/multiboot2.h>
#include <sys/font.h>
#include <sys/rgb.h>
#include <sys/endian.h>
#include <gfx_fb.h>
#include <pnglite.h>
#include <bootstrap.h>
#include <lz4.h>

/* VGA text mode does use bold font. */
#if !defined(VGA_8X16_FONT)
#define	VGA_8X16_FONT		"/boot/fonts/8x16b.fnt"
#endif
#if !defined(DEFAULT_8X16_FONT)
#define	DEFAULT_8X16_FONT	"/boot/fonts/8x16.fnt"
#endif

/*
 * Global framebuffer struct, to be updated with mode changes.
 */
multiboot_tag_framebuffer_t gfx_fb;

/* To support setenv, keep track of inverses and colors. */
static int gfx_inverse = 0;
static int gfx_inverse_screen = 0;
static uint8_t gfx_fg = DEFAULT_ANSI_FOREGROUND;
static uint8_t gfx_bg = DEFAULT_ANSI_BACKGROUND;
#if defined(EFI)
EFI_GRAPHICS_OUTPUT_BLT_PIXEL *shadow_fb;
static EFI_GRAPHICS_OUTPUT_BLT_PIXEL *GlyphBuffer;
#else
struct paletteentry *shadow_fb;
static struct paletteentry *GlyphBuffer;
#endif
static size_t GlyphBufferSize;

int gfx_fb_cons_clear(struct vis_consclear *);
void gfx_fb_cons_copy(struct vis_conscopy *);
void gfx_fb_cons_display(struct vis_consdisplay *);

static bool insert_font(char *, FONT_FLAGS);

/*
 * Set default operations to use bitmap based implementation.
 * In case of UEFI, if GOP is available, we will switch to GOP based
 * implementation.
 *
 * Also note, for UEFI we do attempt to boost the execution by setting
 * Task Priority Level (TPL) to TPL_NOTIFY, which is highest priority
 * usable in application.
 */

/*
 * Translate platform specific FB address.
 */
static uint8_t *
gfx_get_fb_address(void)
{
	return ((uint8_t *)ptov(gfx_fb.framebuffer_common.framebuffer_addr));
}

/*
 * Generic platform callbacks for tem.
 */
void
plat_tem_get_prom_font_size(int *charheight, int *windowtop)
{
	*charheight = 0;
	*windowtop = 0;
}

void
plat_tem_get_colors(uint8_t *fg, uint8_t *bg)
{
	*fg = gfx_fg;
	*bg = gfx_bg;
}

void
plat_tem_get_inverses(int *inverse, int *inverse_screen)
{
	*inverse = gfx_inverse;
	*inverse_screen = gfx_inverse_screen;
}

/*
 * Utility function to parse gfx mode line strings.
 */
bool
gfx_parse_mode_str(char *str, int *x, int *y, int *depth)
{
	char *p, *end;

	errno = 0;
	p = str;
	*x = strtoul(p, &end, 0);
	if (*x == 0 || errno != 0)
		return (false);
	if (*end != 'x')
		return (false);
	p = end + 1;
	*y = strtoul(p, &end, 0);
	if (*y == 0 || errno != 0)
		return (false);
	if (*end != 'x') {
		*depth = -1;    /* auto select */
	} else {
		p = end + 1;
		*depth = strtoul(p, &end, 0);
		if (*depth == 0 || errno != 0 || *end != '\0')
			return (false);
	}

	return (true);
}

uint32_t
gfx_fb_color_map(uint8_t index)
{
	return (rgb_color_map(&rgb_info, index, 0xff));
}

static bool
color_name_to_ansi(const char *name, int *val)
{
	if (strcasecmp(name, "black") == 0) {
		*val = ANSI_COLOR_BLACK;
		return (true);
	}
	if (strcasecmp(name, "red") == 0) {
		*val = ANSI_COLOR_RED;
		return (true);
	}
	if (strcasecmp(name, "green") == 0) {
		*val = ANSI_COLOR_GREEN;
		return (true);
	}
	if (strcasecmp(name, "yellow") == 0) {
		*val = ANSI_COLOR_YELLOW;
		return (true);
	}
	if (strcasecmp(name, "blue") == 0) {
		*val = ANSI_COLOR_BLUE;
		return (true);
	}
	if (strcasecmp(name, "magenta") == 0) {
		*val = ANSI_COLOR_MAGENTA;
		return (true);
	}
	if (strcasecmp(name, "cyan") == 0) {
		*val = ANSI_COLOR_CYAN;
		return (true);
	}
	if (strcasecmp(name, "white") == 0) {
		*val = ANSI_COLOR_WHITE;
		return (true);
	}
	return (false);
}

/* Callback to check and set colors */
static int
gfx_set_colors(struct env_var *ev, int flags, const void *value)
{
	int val = 0, limit;
	char buf[2];
	const void *evalue;

	if (value == NULL)
		return (CMD_OK);

	limit = 255;

	if (color_name_to_ansi(value, &val)) {
		snprintf(buf, sizeof (buf), "%d", val);
		evalue = buf;
	} else {
		char *end;

		errno = 0;
		val = (int)strtol(value, &end, 0);
		if (errno != 0 || *end != '\0') {
			printf("Allowed values are either ansi color name or "
			    "number from range [0-255].\n");
			return (CMD_OK);
		}
		evalue = value;
	}

	/* invalid value? */
	if ((val < 0 || val > limit)) {
		printf("Allowed values are either ansi color name or "
		    "number from range [0-255].\n");
		return (CMD_OK);
	}

	if (strcmp(ev->ev_name, "tem.fg_color") == 0) {
		/* is it already set? */
		if (gfx_fg == val)
			return (CMD_OK);
		gfx_fg = val;
	}
	if (strcmp(ev->ev_name, "tem.bg_color") == 0) {
		/* is it already set? */
		if (gfx_bg == val)
			return (CMD_OK);
		gfx_bg = val;
	}
	env_setenv(ev->ev_name, flags | EV_NOHOOK, evalue, NULL, NULL);
	plat_cons_update_mode(-1);
	return (CMD_OK);
}

/* Callback to check and set inverses */
static int
gfx_set_inverses(struct env_var *ev, int flags, const void *value)
{
	int t, f;

	if (value == NULL)
		return (CMD_OK);

	t = strcmp(value, "true");
	f = strcmp(value, "false");

	/* invalid value? */
	if (t != 0 && f != 0)
		return (CMD_OK);

	if (strcmp(ev->ev_name, "tem.inverse") == 0) {
		/* is it already set? */
		if (gfx_inverse == (t == 0))
			return (CMD_OK);
		gfx_inverse = (t == 0);
	}
	if (strcmp(ev->ev_name, "tem.inverse-screen") == 0) {
		/* is it already set? */
		if (gfx_inverse_screen == (t == 0))
			return (CMD_OK);
		gfx_inverse_screen = (t == 0);
	}
	env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);
	plat_cons_update_mode(-1);
	return (CMD_OK);
}

/*
 * Initialize gfx framework.
 */
void
gfx_framework_init(void)
{
	int rc, limit;
	char *env, buf[2];

	if (gfx_fb.framebuffer_common.framebuffer_bpp < 24)
		limit = 7;
	else
		limit = 255;

	/* set up tem inverse controls */
	env = getenv("tem.inverse");
	if (env != NULL) {
		if (strcmp(env, "true") == 0)
			gfx_inverse = 1;
		unsetenv("tem.inverse");
	}

	env = getenv("tem.inverse-screen");
	if (env != NULL) {
		if (strcmp(env, "true") == 0)
			gfx_inverse_screen = 1;
		unsetenv("tem.inverse-screen");
	}

	if (gfx_inverse)
		env = "true";
	else
		env = "false";

	env_setenv("tem.inverse", EV_VOLATILE, env, gfx_set_inverses,
	    env_nounset);

	if (gfx_inverse_screen)
		env = "true";
	else
		env = "false";

	env_setenv("tem.inverse-screen", EV_VOLATILE, env, gfx_set_inverses,
	    env_nounset);

	/* set up tem color controls */
	env = getenv("tem.fg_color");
	if (env != NULL) {
		rc = (int)strtol(env, NULL, 0);
		if ((rc >= 0 && rc <= limit) && (rc <= 7 || rc >= 16))
			gfx_fg = rc;
		unsetenv("tem.fg_color");
	}

	env = getenv("tem.bg_color");
	if (env != NULL) {
		rc = (int)strtol(env, NULL, 0);
		if ((rc >= 0 && rc <= limit) && (rc <= 7 || rc >= 16))
			gfx_bg = rc;
		unsetenv("tem.bg_color");
	}

	snprintf(buf, sizeof (buf), "%d", gfx_fg);
	env_setenv("tem.fg_color", EV_VOLATILE, buf, gfx_set_colors,
	    env_nounset);
	snprintf(buf, sizeof (buf), "%d", gfx_bg);
	env_setenv("tem.bg_color", EV_VOLATILE, buf, gfx_set_colors,
	    env_nounset);

	/*
	 * Setup font list to have builtin font.
	 */
	(void) insert_font(NULL, FONT_BUILTIN);
}

/*
 * Get indexed color from RGB. This function is used to write data to video
 * memory when the adapter is set to use indexed colors.
 * Since UEFI does only support 32-bit colors, we do not implement it for
 * UEFI because there is no need for it and we do not have palette array
 * for UEFI.
 */
static uint8_t
rgb_to_color_index(uint8_t r, uint8_t g, uint8_t b)
{
#if !defined(EFI)
	uint32_t color, best, dist, k;
	int diff;

	color = 0;
	best = 255 * 255 * 255;
	for (k = 0; k < NCMAP; k++) {
		diff = r - pe8[k].Red;
		dist = diff * diff;
		diff = g - pe8[k].Green;
		dist += diff * diff;
		diff = b - pe8[k].Blue;
		dist += diff * diff;

		/* Exact match, exit the loop */
		if (dist == 0)
			break;

		if (dist < best) {
			color = k;
			best = dist;
		}
	}
	if (k == NCMAP)
		k = color;
	return (k);
#else
	(void) r;
	(void) g;
	(void) b;
	return (0);
#endif
}

static void
gfx_mem_wr1(uint8_t *base, size_t size, uint32_t o, uint8_t v)
{

	if (o >= size)
		return;
	*(uint8_t *)(base + o) = v;
}

static void
gfx_mem_wr2(uint8_t *base, size_t size, uint32_t o, uint16_t v)
{

	if (o >= size)
		return;
	*(uint16_t *)(base + o) = v;
}

static void
gfx_mem_wr4(uint8_t *base, size_t size, uint32_t o, uint32_t v)
{

	if (o >= size)
		return;
	*(uint32_t *)(base + o) = v;
}

static int
gfxfb_blt_fill(void *BltBuffer,
    uint32_t DestinationX, uint32_t DestinationY,
    uint32_t Width, uint32_t Height)
{
#if defined(EFI)
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *p;
#else
	struct paletteentry *p;
#endif
	uint32_t data, bpp, pitch, y, x;
	size_t size;
	off_t off;
	uint8_t *destination;

	if (BltBuffer == NULL)
		return (EINVAL);

	if (DestinationY + Height >
	    gfx_fb.framebuffer_common.framebuffer_height)
		return (EINVAL);

	if (DestinationX + Width > gfx_fb.framebuffer_common.framebuffer_width)
		return (EINVAL);

	if (Width == 0 || Height == 0)
		return (EINVAL);

	p = BltBuffer;
	if (gfx_fb.framebuffer_common.framebuffer_bpp == 8) {
		data = rgb_to_color_index(p->Red, p->Green, p->Blue);
	} else {
		data = (p->Red &
		    ((1 << gfx_fb.u.fb2.framebuffer_red_mask_size) - 1)) <<
		    gfx_fb.u.fb2.framebuffer_red_field_position;
		data |= (p->Green &
		    ((1 << gfx_fb.u.fb2.framebuffer_green_mask_size) - 1)) <<
		    gfx_fb.u.fb2.framebuffer_green_field_position;
		data |= (p->Blue &
		    ((1 << gfx_fb.u.fb2.framebuffer_blue_mask_size) - 1)) <<
		    gfx_fb.u.fb2.framebuffer_blue_field_position;
	}

	bpp = roundup2(gfx_fb.framebuffer_common.framebuffer_bpp, 8) >> 3;
	pitch = gfx_fb.framebuffer_common.framebuffer_pitch;
	destination = gfx_get_fb_address();
	size = gfx_fb.framebuffer_common.framebuffer_height * pitch;

	for (y = DestinationY; y < Height + DestinationY; y++) {
		off = y * pitch + DestinationX * bpp;
		for (x = 0; x < Width; x++) {
			switch (bpp) {
			case 1:
				gfx_mem_wr1(destination, size, off,
				    (data < NCOLORS) ?
				    solaris_color_to_pc_color[data] : data);
				break;
			case 2:
				gfx_mem_wr2(destination, size, off, data);
				break;
			case 3:
				gfx_mem_wr1(destination, size, off,
				    (data >> 16) & 0xff);
				gfx_mem_wr1(destination, size, off + 1,
				    (data >> 8) & 0xff);
				gfx_mem_wr1(destination, size, off + 2,
				    data & 0xff);
				break;
			case 4:
				gfx_mem_wr4(destination, size, off, data);
				break;
			default:
				return (EINVAL);
			}
			off += bpp;
		}
	}

	return (0);
}

static int
gfxfb_blt_video_to_buffer(void *BltBuffer, uint32_t SourceX, uint32_t SourceY,
    uint32_t DestinationX, uint32_t DestinationY,
    uint32_t Width, uint32_t Height, uint32_t Delta)
{
#if defined(EFI)
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *p;
#else
	struct paletteentry *p;
#endif
	uint32_t x, sy, dy;
	uint32_t bpp, pitch, copybytes;
	off_t off;
	uint8_t *source, *destination, *sb;
	uint8_t rm, rp, gm, gp, bm, bp;
	bool bgra;

	if (BltBuffer == NULL)
		return (EINVAL);

	if (SourceY + Height >
	    gfx_fb.framebuffer_common.framebuffer_height)
		return (EINVAL);

	if (SourceX + Width > gfx_fb.framebuffer_common.framebuffer_width)
		return (EINVAL);

	if (Width == 0 || Height == 0)
		return (EINVAL);

	if (Delta == 0)
		Delta = Width * sizeof (*p);

	bpp = roundup2(gfx_fb.framebuffer_common.framebuffer_bpp, 8) >> 3;
	pitch = gfx_fb.framebuffer_common.framebuffer_pitch;

	copybytes = Width * bpp;

	rm = (1 << gfx_fb.u.fb2.framebuffer_red_mask_size) - 1;
	rp = gfx_fb.u.fb2.framebuffer_red_field_position;
	gm = (1 << gfx_fb.u.fb2.framebuffer_green_mask_size) - 1;
	gp = gfx_fb.u.fb2.framebuffer_green_field_position;
	bm = (1 << gfx_fb.u.fb2.framebuffer_blue_mask_size) - 1;
	bp = gfx_fb.u.fb2.framebuffer_blue_field_position;
	/* If FB pixel format is BGRA, we can use direct copy. */
	bgra = bpp == 4 &&
	    gfx_fb.u.fb2.framebuffer_red_mask_size == 8 &&
	    gfx_fb.u.fb2.framebuffer_red_field_position == 16 &&
	    gfx_fb.u.fb2.framebuffer_green_mask_size == 8 &&
	    gfx_fb.u.fb2.framebuffer_green_field_position == 8 &&
	    gfx_fb.u.fb2.framebuffer_blue_mask_size == 8 &&
	    gfx_fb.u.fb2.framebuffer_blue_field_position == 0;

	for (sy = SourceY, dy = DestinationY; dy < Height + DestinationY;
	    sy++, dy++) {
		off = sy * pitch + SourceX * bpp;
		source = gfx_get_fb_address() + off;
		destination = (uint8_t *)BltBuffer + dy * Delta +
		    DestinationX * sizeof (*p);

		if (bgra) {
			bcopy(source, destination, copybytes);
		} else {
			for (x = 0; x < Width; x++) {
				uint32_t c = 0;

				p = (void *)(destination + x * sizeof (*p));
				sb = source + x * bpp;
				switch (bpp) {
				case 1:
					c = *sb;
					break;
				case 2:
					c = *(uint16_t *)sb;
					break;
				case 3:
					c = sb[0] << 16 | sb[1] << 8 | sb[2];
					break;
				case 4:
					c = *(uint32_t *)sb;
					break;
				default:
					return (EINVAL);
				}

				if (bpp == 1) {
					*(uint32_t *)p = gfx_fb_color_map(
					    (c < NCOLORS) ?
					    pc_color_to_solaris_color[c] : c);
				} else {
					p->Red = (c >> rp) & rm;
					p->Green = (c >> gp) & gm;
					p->Blue = (c >> bp) & bm;
					p->Reserved = 0;
				}
			}
		}
	}

	return (0);
}

static int
gfxfb_blt_buffer_to_video(void *BltBuffer, uint32_t SourceX, uint32_t SourceY,
    uint32_t DestinationX, uint32_t DestinationY,
    uint32_t Width, uint32_t Height, uint32_t Delta)
{
#if defined(EFI)
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *p;
#else
	struct paletteentry *p;
#endif
	uint32_t x, sy, dy;
	uint32_t bpp, pitch, copybytes;
	off_t off;
	uint8_t *source, *destination;
	uint8_t rm, rp, gm, gp, bm, bp;
	bool bgra;

	if (BltBuffer == NULL)
		return (EINVAL);

	if (DestinationY + Height >
	    gfx_fb.framebuffer_common.framebuffer_height)
		return (EINVAL);

	if (DestinationX + Width > gfx_fb.framebuffer_common.framebuffer_width)
		return (EINVAL);

	if (Width == 0 || Height == 0)
		return (EINVAL);

	if (Delta == 0)
		Delta = Width * sizeof (*p);

	bpp = roundup2(gfx_fb.framebuffer_common.framebuffer_bpp, 8) >> 3;
	pitch = gfx_fb.framebuffer_common.framebuffer_pitch;

	copybytes = Width * bpp;

	rm = (1 << gfx_fb.u.fb2.framebuffer_red_mask_size) - 1;
	rp = gfx_fb.u.fb2.framebuffer_red_field_position;
	gm = (1 << gfx_fb.u.fb2.framebuffer_green_mask_size) - 1;
	gp = gfx_fb.u.fb2.framebuffer_green_field_position;
	bm = (1 << gfx_fb.u.fb2.framebuffer_blue_mask_size) - 1;
	bp = gfx_fb.u.fb2.framebuffer_blue_field_position;
	/* If FB pixel format is BGRA, we can use direct copy. */
	bgra = bpp == 4 &&
	    gfx_fb.u.fb2.framebuffer_red_mask_size == 8 &&
	    gfx_fb.u.fb2.framebuffer_red_field_position == 16 &&
	    gfx_fb.u.fb2.framebuffer_green_mask_size == 8 &&
	    gfx_fb.u.fb2.framebuffer_green_field_position == 8 &&
	    gfx_fb.u.fb2.framebuffer_blue_mask_size == 8 &&
	    gfx_fb.u.fb2.framebuffer_blue_field_position == 0;

	for (sy = SourceY, dy = DestinationY; sy < Height + SourceY;
	    sy++, dy++) {
		off = dy * pitch + DestinationX * bpp;
		destination = gfx_get_fb_address() + off;

		if (bgra) {
			source = (uint8_t *)BltBuffer + sy * Delta +
			    SourceX * sizeof (*p);
			bcopy(source, destination, copybytes);
		} else {
			for (x = 0; x < Width; x++) {
				uint32_t c;

				p = (void *)((uint8_t *)BltBuffer +
				    sy * Delta +
				    (SourceX + x) * sizeof (*p));
				if (bpp == 1) {
					c = rgb_to_color_index(p->Red,
					    p->Green, p->Blue);
				} else {
					c = (p->Red & rm) << rp |
					    (p->Green & gm) << gp |
					    (p->Blue & bm) << bp;
				}
				off = x * bpp;
				switch (bpp) {
				case 1:
					gfx_mem_wr1(destination, copybytes,
					    off, (c < NCOLORS) ?
					    solaris_color_to_pc_color[c] : c);
					break;
				case 2:
					gfx_mem_wr2(destination, copybytes,
					    off, c);
					break;
				case 3:
					gfx_mem_wr1(destination, copybytes,
					    off, (c >> 16) & 0xff);
					gfx_mem_wr1(destination, copybytes,
					    off + 1, (c >> 8) & 0xff);
					gfx_mem_wr1(destination, copybytes,
					    off + 2, c & 0xff);
					break;
				case 4:
					gfx_mem_wr4(destination, copybytes,
					    off, c);
					break;
				default:
					return (EINVAL);
				}
			}
		}
	}

	return (0);
}

static int
gfxfb_blt_video_to_video(uint32_t SourceX, uint32_t SourceY,
    uint32_t DestinationX, uint32_t DestinationY,
    uint32_t Width, uint32_t Height)
{
	uint32_t bpp, copybytes;
	int pitch;
	uint8_t *source, *destination;
	off_t off;

	if (SourceY + Height >
	    gfx_fb.framebuffer_common.framebuffer_height)
		return (EINVAL);

	if (SourceX + Width > gfx_fb.framebuffer_common.framebuffer_width)
		return (EINVAL);

	if (DestinationY + Height >
	    gfx_fb.framebuffer_common.framebuffer_height)
		return (EINVAL);

	if (DestinationX + Width > gfx_fb.framebuffer_common.framebuffer_width)
		return (EINVAL);

	if (Width == 0 || Height == 0)
		return (EINVAL);

	bpp = roundup2(gfx_fb.framebuffer_common.framebuffer_bpp, 8) >> 3;
	pitch = gfx_fb.framebuffer_common.framebuffer_pitch;

	copybytes = Width * bpp;

	off = SourceY * pitch + SourceX * bpp;
	source = gfx_get_fb_address() + off;
	off = DestinationY * pitch + DestinationX * bpp;
	destination = gfx_get_fb_address() + off;

	/*
	 * To handle overlapping areas, set up reverse copy here.
	 */
	if ((uintptr_t)destination > (uintptr_t)source) {
		source += Height * pitch;
		destination += Height * pitch;
		pitch = -pitch;
	}

	while (Height-- > 0) {
		bcopy(source, destination, copybytes);
		source += pitch;
		destination += pitch;
	}

	return (0);
}

static void
gfxfb_shadow_fill(uint32_t *BltBuffer,
    uint32_t DestinationX, uint32_t DestinationY,
    uint32_t Width, uint32_t Height)
{
	uint32_t fbX, fbY;

	if (shadow_fb == NULL)
		return;

	fbX = gfx_fb.framebuffer_common.framebuffer_width;
	fbY = gfx_fb.framebuffer_common.framebuffer_height;

	if (BltBuffer == NULL)
		return;

	if (DestinationX + Width > fbX)
		Width = fbX - DestinationX;

	if (DestinationY + Height > fbY)
		Height = fbY - DestinationY;

	uint32_t y2 = Height + DestinationY;
	for (uint32_t y1 = DestinationY; y1 < y2; y1++) {
		uint32_t off = y1 * fbX + DestinationX;

		for (uint32_t x = 0; x < Width; x++) {
			*(uint32_t *)&shadow_fb[off + x] = *BltBuffer;
		}
	}
}

int
gfxfb_blt(void *BltBuffer, GFXFB_BLT_OPERATION BltOperation,
    uint32_t SourceX, uint32_t SourceY,
    uint32_t DestinationX, uint32_t DestinationY,
    uint32_t Width, uint32_t Height, uint32_t Delta)
{
	int rv;
#if defined(EFI)
	EFI_STATUS status;
	EFI_TPL tpl;
	extern EFI_GRAPHICS_OUTPUT_PROTOCOL *gop;

	/*
	 * We assume Blt() does work, if not, we will need to build
	 * exception list case by case.
	 * Once boot services are off, we can not use GOP Blt().
	 */
	if (gop != NULL && has_boot_services) {
		tpl = BS->RaiseTPL(TPL_NOTIFY);
		switch (BltOperation) {
		case GfxFbBltVideoFill:
			gfxfb_shadow_fill(BltBuffer, DestinationX,
			    DestinationY, Width, Height);
			status = gop->Blt(gop, BltBuffer, EfiBltVideoFill,
			    SourceX, SourceY, DestinationX, DestinationY,
			    Width, Height, Delta);
			break;

		case GfxFbBltVideoToBltBuffer:
			status = gop->Blt(gop, BltBuffer,
			    EfiBltVideoToBltBuffer,
			    SourceX, SourceY, DestinationX, DestinationY,
			    Width, Height, Delta);
			break;

		case GfxFbBltBufferToVideo:
			status = gop->Blt(gop, BltBuffer, EfiBltBufferToVideo,
			    SourceX, SourceY, DestinationX, DestinationY,
			    Width, Height, Delta);
			break;

		case GfxFbBltVideoToVideo:
			status = gop->Blt(gop, BltBuffer, EfiBltVideoToVideo,
			    SourceX, SourceY, DestinationX, DestinationY,
			    Width, Height, Delta);
			break;

		default:
			status = EFI_INVALID_PARAMETER;
			break;
		}

		switch (status) {
		case EFI_SUCCESS:
			rv = 0;
			break;

		case EFI_INVALID_PARAMETER:
			rv = EINVAL;
			break;

		case EFI_DEVICE_ERROR:
		default:
			rv = EIO;
			break;
		}

		BS->RestoreTPL(tpl);
		return (rv);
	}
#endif

	switch (BltOperation) {
	case GfxFbBltVideoFill:
		gfxfb_shadow_fill(BltBuffer, DestinationX, DestinationY,
		    Width, Height);
		rv = gfxfb_blt_fill(BltBuffer, DestinationX, DestinationY,
		    Width, Height);
		break;

	case GfxFbBltVideoToBltBuffer:
		rv = gfxfb_blt_video_to_buffer(BltBuffer, SourceX, SourceY,
		    DestinationX, DestinationY, Width, Height, Delta);
		break;

	case GfxFbBltBufferToVideo:
		rv = gfxfb_blt_buffer_to_video(BltBuffer, SourceX, SourceY,
		    DestinationX, DestinationY, Width, Height, Delta);
		break;

	case GfxFbBltVideoToVideo:
		rv = gfxfb_blt_video_to_video(SourceX, SourceY,
		    DestinationX, DestinationY, Width, Height);
		break;

	default:
		rv = EINVAL;
		break;
	}
	return (rv);
}

/*
 * visual io callbacks.
 */
int
gfx_fb_cons_clear(struct vis_consclear *ca)
{
	int rv;
	uint32_t width, height;

	width = gfx_fb.framebuffer_common.framebuffer_width;
	height = gfx_fb.framebuffer_common.framebuffer_height;

	rv = gfxfb_blt(&ca->bg_color, GfxFbBltVideoFill, 0, 0,
	    0, 0, width, height, 0);

	return (rv);
}

void
gfx_fb_cons_copy(struct vis_conscopy *ma)
{
#if defined(EFI)
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *source, *destination;
#else
	struct paletteentry *source, *destination;
#endif
	uint32_t width, height, bytes;
	uint32_t sx, sy, dx, dy;
	uint32_t pitch;
	int step;

	width = ma->e_col - ma->s_col + 1;
	height = ma->e_row - ma->s_row + 1;

	sx = ma->s_col;
	sy = ma->s_row;
	dx = ma->t_col;
	dy = ma->t_row;

	if (sx + width > gfx_fb.framebuffer_common.framebuffer_width)
		width = gfx_fb.framebuffer_common.framebuffer_width - sx;

	if (sy + height > gfx_fb.framebuffer_common.framebuffer_height)
		height = gfx_fb.framebuffer_common.framebuffer_height - sy;

	if (dx + width > gfx_fb.framebuffer_common.framebuffer_width)
		width = gfx_fb.framebuffer_common.framebuffer_width - dx;

	if (dy + height > gfx_fb.framebuffer_common.framebuffer_height)
		height = gfx_fb.framebuffer_common.framebuffer_height - dy;

	if (width == 0 || height == 0)
		return;

	/*
	 * With no shadow fb, use video to video copy.
	 */
	if (shadow_fb == NULL) {
		(void) gfxfb_blt(NULL, GfxFbBltVideoToVideo,
		    sx, sy, dx, dy, width, height, 0);
		return;
	}

	/*
	 * With shadow fb, we need to copy data on both shadow and video,
	 * to preserve the consistency. We only read data from shadow fb.
	 */

	step = 1;
	pitch = gfx_fb.framebuffer_common.framebuffer_width;
	bytes = width * sizeof (*shadow_fb);

	/*
	 * To handle overlapping areas, set up reverse copy here.
	 */
	if (dy * pitch + dx > sy * pitch + sx) {
		sy += height;
		dy += height;
		step = -step;
	}

	while (height-- > 0) {
		source = &shadow_fb[sy * pitch + sx];
		destination = &shadow_fb[dy * pitch + dx];

		bcopy(source, destination, bytes);
		(void) gfxfb_blt(destination, GfxFbBltBufferToVideo,
		    0, 0, dx, dy, width, 1, 0);

		sy += step;
		dy += step;
	}
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
	uint8_t max_alpha;

	/* 15/16 bit depths have alpha channel size less than 8 */
	max_alpha = (1 << (rgb_info.red.size + rgb_info.green.size +
	    rgb_info.blue.size) / 3) - 1;

	/* trivial corner cases */
	if (alpha == 0)
		return (bg);
	if (alpha >= max_alpha)
		return (fg);
	blend = (alpha * fg + (max_alpha - alpha) * bg);
	/* Division by max_alpha */
	h = blend >> 8;
	l = blend & max_alpha;
	if (h + l >= max_alpha)
		h++;
	return (h);
}

/* Copy memory to framebuffer or to memory. */
static void
bitmap_cpy(void *dst, void *src, size_t size)
{
#if defined(EFI)
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *ps, *pd;
#else
	struct paletteentry *ps, *pd;
#endif
	uint32_t i;
	uint8_t a;

	ps = src;
	pd = dst;

	for (i = 0; i < size; i++) {
		a = ps[i].Reserved;
		pd[i].Red = alpha_blend(ps[i].Red, pd[i].Red, a);
		pd[i].Green = alpha_blend(ps[i].Green, pd[i].Green, a);
		pd[i].Blue = alpha_blend(ps[i].Blue, pd[i].Blue, a);
		pd[i].Reserved = a;
	}
}

static void *
allocate_glyphbuffer(uint32_t width, uint32_t height)
{
	size_t size;

	size = sizeof (*GlyphBuffer) * width * height;
	if (size != GlyphBufferSize) {
		free(GlyphBuffer);
		GlyphBuffer = malloc(size);
		if (GlyphBuffer == NULL)
			return (NULL);
		GlyphBufferSize = size;
	}
	return (GlyphBuffer);
}

void
gfx_fb_cons_display(struct vis_consdisplay *da)
{
#if defined(EFI)
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *BltBuffer, *data;
#else
	struct paletteentry *BltBuffer, *data;
#endif
	uint32_t size;

	/* make sure we will not write past FB */
	if ((uint32_t)da->col >= gfx_fb.framebuffer_common.framebuffer_width ||
	    (uint32_t)da->row >= gfx_fb.framebuffer_common.framebuffer_height ||
	    (uint32_t)da->col + da->width >
	    gfx_fb.framebuffer_common.framebuffer_width ||
	    (uint32_t)da->row + da->height >
	    gfx_fb.framebuffer_common.framebuffer_height)
		return;

	/*
	 * If we do have shadow fb, we will use shadow to render data,
	 * and copy shadow to video.
	 */
	if (shadow_fb != NULL) {
		uint32_t pitch = gfx_fb.framebuffer_common.framebuffer_width;
		uint32_t dx, dy, width, height;

		dx = da->col;
		dy = da->row;
		height = da->height;
		width = da->width;

		data = (void *)da->data;
		/* Copy rectangle line by line. */
		for (uint32_t y = 0; y < height; y++) {
			BltBuffer = shadow_fb + dy * pitch + dx;
			bitmap_cpy(BltBuffer, &data[y * width], width);
			(void) gfxfb_blt(BltBuffer, GfxFbBltBufferToVideo,
			    0, 0, dx, dy, width, 1, 0);
			dy++;
		}
		return;
	}

	/*
	 * Common data to display is glyph, use preallocated
	 * glyph buffer.
	 */
	if (tems.ts_pix_data_size != GlyphBufferSize)
		(void) allocate_glyphbuffer(da->width, da->height);

	size = sizeof (*BltBuffer) * da->width * da->height;
	if (size == GlyphBufferSize) {
		BltBuffer = GlyphBuffer;
	} else {
		BltBuffer = malloc(size);
	}
	if (BltBuffer == NULL)
		return;

	if (gfxfb_blt(BltBuffer, GfxFbBltVideoToBltBuffer,
	    da->col, da->row, 0, 0, da->width, da->height, 0) == 0) {
		bitmap_cpy(BltBuffer, da->data, da->width * da->height);
		(void) gfxfb_blt(BltBuffer, GfxFbBltBufferToVideo,
		    0, 0, da->col, da->row, da->width, da->height, 0);
	}

	if (BltBuffer != GlyphBuffer)
		free(BltBuffer);
}

static void
gfx_fb_cursor_impl(void *buf, uint32_t stride, uint32_t fg, uint32_t bg,
    struct vis_conscursor *ca)
{
#if defined(EFI)
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *p;
#else
	struct paletteentry *p;
#endif
	union pixel {
#if defined(EFI)
		EFI_GRAPHICS_OUTPUT_BLT_PIXEL p;
#else
		struct paletteentry p;
#endif
		uint32_t p32;
	} *row;

	p = buf;

	/*
	 * Build inverse image of the glyph.
	 * Since xor has self-inverse property, drawing cursor
	 * second time on the same spot, will restore the original content.
	 */
	for (screen_size_t i = 0; i < ca->height; i++) {
		row = (union pixel *)(p + i * stride);
		for (screen_size_t j = 0; j < ca->width; j++) {
			row[j].p32 = (row[j].p32 ^ fg) ^ bg;
		}
	}
}

void
gfx_fb_display_cursor(struct vis_conscursor *ca)
{
	union pixel {
#if defined(EFI)
		EFI_GRAPHICS_OUTPUT_BLT_PIXEL p;
#else
		struct paletteentry p;
#endif
		uint32_t p32;
	} fg, bg;

	bcopy(&ca->fg_color, &fg.p32, sizeof (fg.p32));
	bcopy(&ca->bg_color, &bg.p32, sizeof (bg.p32));

	if (shadow_fb == NULL &&
	    allocate_glyphbuffer(ca->width, ca->height) != NULL) {
		if (gfxfb_blt(GlyphBuffer, GfxFbBltVideoToBltBuffer,
		    ca->col, ca->row, 0, 0, ca->width, ca->height, 0) == 0)
			gfx_fb_cursor_impl(GlyphBuffer, ca->width,
			    fg.p32, bg.p32, ca);

		(void) gfxfb_blt(GlyphBuffer, GfxFbBltBufferToVideo, 0, 0,
		    ca->col, ca->row, ca->width, ca->height, 0);
		return;
	}

	uint32_t pitch = gfx_fb.framebuffer_common.framebuffer_width;
	uint32_t dx, dy, width, height;

	dx = ca->col;
	dy = ca->row;
	width = ca->width;
	height = ca->height;

	gfx_fb_cursor_impl(shadow_fb + dy * pitch + dx, pitch,
	    fg.p32, bg.p32, ca);
	/* Copy rectangle line by line. */
	for (uint32_t y = 0; y < height; y++) {
		(void) gfxfb_blt(shadow_fb + dy * pitch + dx,
		    GfxFbBltBufferToVideo, 0, 0, dx, dy, width, 1, 0);
		dy++;
	}
}

/*
 * Public graphics primitives.
 */

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
		} else
			res >>= 1;
		bit >>= 2;
	}
	return (res);
}

/* set pixel in framebuffer using gfx coordinates */
void
gfx_fb_setpixel(uint32_t x, uint32_t y)
{
	text_color_t fg, bg;

	if (plat_stdout_is_framebuffer() == 0)
		return;

	tem_get_colors((tem_vt_state_t)tems.ts_active, &fg, &bg);

	if (x >= gfx_fb.framebuffer_common.framebuffer_width ||
	    y >= gfx_fb.framebuffer_common.framebuffer_height)
		return;

	gfxfb_blt(&fg.n, GfxFbBltVideoFill, 0, 0, x, y, 1, 1, 0);
}

/*
 * draw rectangle in framebuffer using gfx coordinates.
 */
void
gfx_fb_drawrect(uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2,
    uint32_t fill)
{
	text_color_t fg, bg;

	if (plat_stdout_is_framebuffer() == 0)
		return;

	tem_get_colors((tem_vt_state_t)tems.ts_active, &fg, &bg);

	if (fill != 0) {
		gfxfb_blt(&fg.n, GfxFbBltVideoFill,
		    0, 0, x1, y1, x2 - x1, y2 - y1, 0);
	} else {
		gfxfb_blt(&fg.n, GfxFbBltVideoFill,
		    0, 0, x1, y1, x2 - x1, 1, 0);
		gfxfb_blt(&fg.n, GfxFbBltVideoFill,
		    0, 0, x1, y2, x2 - x1, 1, 0);
		gfxfb_blt(&fg.n, GfxFbBltVideoFill,
		    0, 0, x1, y1, 1, y2 - y1, 0);
		gfxfb_blt(&fg.n, GfxFbBltVideoFill,
		    0, 0, x2, y1, 1, y2 - y1, 0);
	}
}

void
gfx_fb_line(uint32_t x0, uint32_t y0, uint32_t x1, uint32_t y1, uint32_t wd)
{
	int dx, sx, dy, sy;
	int err, e2, x2, y2, ed, width;

	if (plat_stdout_is_framebuffer() == 0)
		return;

	width = wd;
	sx = x0 < x1? 1 : -1;
	sy = y0 < y1? 1 : -1;
	dx = x1 > x0? x1 - x0 : x0 - x1;
	dy = y1 > y0? y1 - y0 : y0 - y1;
	err = dx + dy;
	ed = dx + dy == 0 ? 1: isqrt(dx * dx + dy * dy);

	for (;;) {
		gfx_fb_setpixel(x0, y0);
		e2 = err;
		x2 = x0;
		if ((e2 << 1) >= -dx) {		/* x step */
			e2 += dy;
			y2 = y0;
			while (e2 < ed * width &&
			    (y1 != (uint32_t)y2 || dx > dy)) {
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
			while (e2 < ed * width &&
			    (x1 != (uint32_t)x2 || dx < dy)) {
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

/*
 * quadratic Bézier curve limited to gradients without sign change.
 */
void
gfx_fb_bezier(uint32_t x0, uint32_t y0, uint32_t x1, uint32_t y1, uint32_t x2,
    uint32_t y2, uint32_t wd)
{
	int sx, sy, xx, yy, xy, width;
	int dx, dy, err, curvature;
	int i;

	if (plat_stdout_is_framebuffer() == 0)
		return;

	width = wd;
	sx = x2 - x1;
	sy = y2 - y1;
	xx = x0 - x1;
	yy = y0 - y1;
	curvature = xx*sy - yy*sx;

	if (sx*sx + sy*sy > xx*xx+yy*yy) {
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
		xy = (xx*yy) << 1;
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

/*
 * draw rectangle using terminal coordinates and current foreground color.
 */
void
gfx_term_drawrect(uint32_t ux1, uint32_t uy1, uint32_t ux2, uint32_t uy2)
{
	int x1, y1, x2, y2;
	int xshift, yshift;
	int width, i;
	uint32_t vf_width, vf_height;

	if (plat_stdout_is_framebuffer() == 0)
		return;

	vf_width = tems.ts_font.vf_width;
	vf_height = tems.ts_font.vf_height;
	width = vf_width / 4;			/* line width */
	xshift = (vf_width - width) / 2;
	yshift = (vf_height - width) / 2;

	/* Shift coordinates */
	if (ux1 != 0)
		ux1--;
	if (uy1 != 0)
		uy1--;
	ux2--;
	uy2--;

	/* mark area used in tem */
	tem_image_display(tems.ts_active, uy1, ux1, uy2 + 1, ux2 + 1);

	/*
	 * Draw horizontal lines width points thick, shifted from outer edge.
	 */
	x1 = (ux1 + 1) * vf_width + tems.ts_p_offset.x;
	y1 = uy1 * vf_height + tems.ts_p_offset.y + yshift;
	x2 = ux2 * vf_width + tems.ts_p_offset.x;
	gfx_fb_drawrect(x1, y1, x2, y1 + width, 1);
	y2 = uy2 * vf_height + tems.ts_p_offset.y;
	y2 += vf_height - yshift - width;
	gfx_fb_drawrect(x1, y2, x2, y2 + width, 1);

	/*
	 * Draw vertical lines width points thick, shifted from outer edge.
	 */
	x1 = ux1 * vf_width + tems.ts_p_offset.x + xshift;
	y1 = uy1 * vf_height + tems.ts_p_offset.y;
	y1 += vf_height;
	y2 = uy2 * vf_height + tems.ts_p_offset.y;
	gfx_fb_drawrect(x1, y1, x1 + width, y2, 1);
	x1 = ux2 * vf_width + tems.ts_p_offset.x;
	x1 += vf_width - xshift - width;
	gfx_fb_drawrect(x1, y1, x1 + width, y2, 1);

	/* Draw upper left corner. */
	x1 = ux1 * vf_width + tems.ts_p_offset.x + xshift;
	y1 = uy1 * vf_height + tems.ts_p_offset.y;
	y1 += vf_height;

	x2 = ux1 * vf_width + tems.ts_p_offset.x;
	x2 += vf_width;
	y2 = uy1 * vf_height + tems.ts_p_offset.y + yshift;
	for (i = 0; i <= width; i++)
		gfx_fb_bezier(x1 + i, y1, x1 + i, y2 + i, x2, y2 + i, width-i);

	/* Draw lower left corner. */
	x1 = ux1 * vf_width + tems.ts_p_offset.x;
	x1 += vf_width;
	y1 = uy2 * vf_height + tems.ts_p_offset.y;
	y1 += vf_height - yshift;
	x2 = ux1 * vf_width + tems.ts_p_offset.x + xshift;
	y2 = uy2 * vf_height + tems.ts_p_offset.y;
	for (i = 0; i <= width; i++)
		gfx_fb_bezier(x1, y1 - i, x2 + i, y1 - i, x2 + i, y2, width-i);

	/* Draw upper right corner. */
	x1 = ux2 * vf_width + tems.ts_p_offset.x;
	y1 = uy1 * vf_height + tems.ts_p_offset.y + yshift;
	x2 = ux2 * vf_width + tems.ts_p_offset.x;
	x2 += vf_width - xshift - width;
	y2 = uy1 * vf_height + tems.ts_p_offset.y;
	y2 += vf_height;
	for (i = 0; i <= width; i++)
		gfx_fb_bezier(x1, y1 + i, x2 + i, y1 + i, x2 + i, y2, width-i);

	/* Draw lower right corner. */
	x1 = ux2 * vf_width + tems.ts_p_offset.x;
	y1 = uy2 * vf_height + tems.ts_p_offset.y;
	y1 += vf_height - yshift;
	x2 = ux2 * vf_width + tems.ts_p_offset.x;
	x2 += vf_width - xshift - width;
	y2 = uy2 * vf_height + tems.ts_p_offset.y;
	for (i = 0; i <= width; i++)
		gfx_fb_bezier(x1, y1 - i, x2 + i, y1 - i, x2 + i, y2, width-i);
}

int
gfx_fb_putimage(png_t *png, uint32_t ux1, uint32_t uy1, uint32_t ux2,
    uint32_t uy2, uint32_t flags)
{
#if defined(EFI)
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *p;
#else
	struct paletteentry *p;
#endif
	struct vis_consdisplay da;
	uint32_t i, j, x, y, fheight, fwidth;
	uint8_t r, g, b, a;
	bool scale = false;
	bool trace = false;

	trace = (flags & FL_PUTIMAGE_DEBUG) != 0;

	if (plat_stdout_is_framebuffer() == 0) {
		if (trace)
			printf("Framebuffer not active.\n");
		return (1);
	}

	if (png->color_type != PNG_TRUECOLOR_ALPHA) {
		if (trace)
			printf("Not truecolor image.\n");
		return (1);
	}

	if (ux1 > gfx_fb.framebuffer_common.framebuffer_width ||
	    uy1 > gfx_fb.framebuffer_common.framebuffer_height) {
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

	if (ux2 > gfx_fb.framebuffer_common.framebuffer_width ||
	    uy2 > gfx_fb.framebuffer_common.framebuffer_height) {
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
		ux2 = gfx_fb.framebuffer_common.framebuffer_width -
		    tems.ts_p_offset.x;
		ux1 = ux2 - fwidth;
	}

	if (uy1 == 0) {
		/*
		 * No top left Y co-ordinate (real coordinates start at 1),
		 * place as far down as it will fit.
		 */
		uy2 = gfx_fb.framebuffer_common.framebuffer_height -
		    tems.ts_p_offset.y;
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

	da.col = ux1;
	da.row = uy1;
	da.width = fwidth;
	da.height = fheight;

	/*
	 * mark area used in tem
	 */
	if (!(flags & FL_PUTIMAGE_NOSCROLL)) {
		tem_image_display(tems.ts_active,
		    da.row / tems.ts_font.vf_height,
		    da.col / tems.ts_font.vf_width,
		    (da.row + da.height) / tems.ts_font.vf_height,
		    (da.col + da.width) / tems.ts_font.vf_width);
	}

	if ((flags & FL_PUTIMAGE_BORDER))
		gfx_fb_drawrect(ux1, uy1, ux2, uy2, 0);

	da.data = malloc(fwidth * fheight * sizeof (*p));
	p = (void *)da.data;
	if (da.data == NULL) {
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
			j = y * fwidth + x;

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

			if (trace)
				printf("r/g/b: %x/%x/%x\n", r, g, b);
			/*
			 * Rough colorspace reduction for 15/16 bit colors.
			 */
			p[j].Red = r >>
			    (8 - gfx_fb.u.fb2.framebuffer_red_mask_size);
			p[j].Green = g >>
			    (8 - gfx_fb.u.fb2.framebuffer_green_mask_size);
			p[j].Blue = b >>
			    (8 - gfx_fb.u.fb2.framebuffer_blue_mask_size);
			p[j].Reserved = a;

			wc += wcstep;
		}
		hc += hcstep;
	}

	gfx_fb_cons_display(&da);
	free(da.data);
	return (0);
}

/* Return  w^2 + h^2 or 0, if the dimensions are unknown */
static unsigned
edid_diagonal_squared(void)
{
	unsigned w, h;

	if (edid_info == NULL)
		return (0);

	w = edid_info->display.max_horizontal_image_size;
	h = edid_info->display.max_vertical_image_size;

	/* If either one is 0, we have aspect ratio, not size */
	if (w == 0 || h == 0)
		return (0);

	/*
	 * some monitors encode the aspect ratio instead of the physical size.
	 */
	if ((w == 16 && h == 9) || (w == 16 && h == 10) ||
	    (w == 4 && h == 3) || (w == 5 && h == 4))
		return (0);

	/*
	 * translate cm to inch, note we scale by 100 here.
	 */
	w = w * 100 / 254;
	h = h * 100 / 254;

	/* Return w^2 + h^2 */
	return (w * w + h * h);
}

/*
 * calculate pixels per inch.
 */
static unsigned
gfx_get_ppi(void)
{
	unsigned dp, di;

	di = edid_diagonal_squared();
	if (di == 0)
		return (0);

	dp = gfx_fb.framebuffer_common.framebuffer_width *
	    gfx_fb.framebuffer_common.framebuffer_width +
	    gfx_fb.framebuffer_common.framebuffer_height *
	    gfx_fb.framebuffer_common.framebuffer_height;

	return (isqrt(dp / di));
}

/*
 * Calculate font size from density independent pixels (dp):
 * ((16dp * ppi) / 160) * display_factor.
 * Here we are using fixed constants: 1dp == 160 ppi and
 * display_factor 2.
 *
 * We are rounding font size up and are searching for font which is
 * not smaller than calculated size value.
 */
bitmap_data_t *
gfx_get_font(short rows, short cols, short height, short width)
{
	unsigned ppi, size;
	bitmap_data_t *font = NULL;
	struct fontlist *fl, *next;

	/* Text mode is not supported here. */
	if (gfx_fb.framebuffer_common.framebuffer_type ==
	    MULTIBOOT_FRAMEBUFFER_TYPE_EGA_TEXT)
		return (NULL);

	ppi = gfx_get_ppi();
	if (ppi == 0)
		return (NULL);

	/*
	 * We will search for 16dp font.
	 * We are using scale up by 10 for roundup.
	 */
	size = (16 * ppi * 10) / 160;
	/* Apply display factor 2.  */
	size = roundup(size * 2, 10) / 10;

	STAILQ_FOREACH(fl, &fonts, font_next) {
		/*
		 * Skip too large fonts.
		 */
		font = fl->font_data;
		if (height / font->height < rows ||
		    width / font->width < cols)
			continue;

		next = STAILQ_NEXT(fl, font_next);
		/*
		 * If this is last font or, if next font is smaller,
		 * we have our font. Make sure, it actually is loaded.
		 */
		if (next == NULL || next->font_data->height < size) {
			if (font->font == NULL ||
			    fl->font_flags == FONT_RELOAD) {
				if (fl->font_load != NULL &&
				    fl->font_name != NULL)
					font = fl->font_load(fl->font_name);
			}
			break;
		}
		font = NULL;
	}

	return (font);
}

static int
load_mapping(int fd, struct font *fp, int n)
{
	size_t i, size;
	ssize_t rv;
	struct font_map *mp;

	if (fp->vf_map_count[n] == 0)
		return (0);

	size = fp->vf_map_count[n] * sizeof (*mp);
	mp = malloc(size);
	if (mp == NULL)
		return (ENOMEM);
	fp->vf_map[n] = mp;

	rv = read(fd, mp, size);
	if (rv < 0 || (size_t)rv != size) {
		free(fp->vf_map[n]);
		fp->vf_map[n] = NULL;
		return (EIO);
	}

	for (i = 0; i < fp->vf_map_count[n]; i++) {
		mp[i].font_src = be32toh(mp[i].font_src);
		mp[i].font_dst = be16toh(mp[i].font_dst);
		mp[i].font_len = be16toh(mp[i].font_len);
	}
	return (0);
}

static int
builtin_mapping(struct font *fp, int n)
{
	size_t size;
	struct font_map *mp;

	if (n >= VFNT_MAPS)
		return (EINVAL);

	if (fp->vf_map_count[n] == 0)
		return (0);

	size = fp->vf_map_count[n] * sizeof (*mp);
	mp = malloc(size);
	if (mp == NULL)
		return (ENOMEM);
	fp->vf_map[n] = mp;

	memcpy(mp, DEFAULT_FONT_DATA.font->vf_map[n], size);
	return (0);
}

/*
 * Load font from builtin or from file.
 * We do need special case for builtin because the builtin font glyphs
 * are compressed and we do need to uncompress them.
 * Having single load_font() for both cases will help us to simplify
 * font switch handling.
 */
static bitmap_data_t *
load_font(char *path)
{
	int fd, i;
	uint32_t glyphs;
	struct font_header fh;
	struct fontlist *fl;
	bitmap_data_t *bp;
	struct font *fp;
	size_t size;
	ssize_t rv;

	/* Get our entry from the font list. */
	STAILQ_FOREACH(fl, &fonts, font_next) {
		if (strcmp(fl->font_name, path) == 0)
			break;
	}
	if (fl == NULL)
		return (NULL);	/* Should not happen. */

	bp = fl->font_data;
	if (bp->font != NULL && fl->font_flags != FONT_RELOAD)
		return (bp);

	fd = -1;
	/*
	 * Special case for builtin font.
	 * Builtin font is the very first font we load, we do not have
	 * previous loads to be released.
	 */
	if (fl->font_flags == FONT_BUILTIN) {
		if ((fp = calloc(1, sizeof (struct font))) == NULL)
			return (NULL);

		fp->vf_width = DEFAULT_FONT_DATA.width;
		fp->vf_height = DEFAULT_FONT_DATA.height;

		fp->vf_bytes = malloc(DEFAULT_FONT_DATA.uncompressed_size);
		if (fp->vf_bytes == NULL) {
			free(fp);
			return (NULL);
		}

		bp->uncompressed_size = DEFAULT_FONT_DATA.uncompressed_size;
		bp->compressed_size = DEFAULT_FONT_DATA.compressed_size;

		if (lz4_decompress(DEFAULT_FONT_DATA.compressed_data,
		    fp->vf_bytes,
		    DEFAULT_FONT_DATA.compressed_size,
		    DEFAULT_FONT_DATA.uncompressed_size, 0) != 0) {
			free(fp->vf_bytes);
			free(fp);
			return (NULL);
		}

		for (i = 0; i < VFNT_MAPS; i++) {
			fp->vf_map_count[i] =
			    DEFAULT_FONT_DATA.font->vf_map_count[i];
			if (builtin_mapping(fp, i) != 0)
				goto free_done;
		}

		bp->font = fp;
		return (bp);
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		return (NULL);
	}

	size = sizeof (fh);
	rv = read(fd, &fh, size);
	if (rv < 0 || (size_t)rv != size) {
		bp = NULL;
		goto done;
	}
	if (memcmp(fh.fh_magic, FONT_HEADER_MAGIC, sizeof (fh.fh_magic)) != 0) {
		bp = NULL;
		goto done;
	}
	if ((fp = calloc(1, sizeof (struct font))) == NULL) {
		bp = NULL;
		goto done;
	}
	for (i = 0; i < VFNT_MAPS; i++)
		fp->vf_map_count[i] = be32toh(fh.fh_map_count[i]);

	glyphs = be32toh(fh.fh_glyph_count);
	fp->vf_width = fh.fh_width;
	fp->vf_height = fh.fh_height;

	size = howmany(fp->vf_width, 8) * fp->vf_height * glyphs;
	bp->uncompressed_size = size;
	if ((fp->vf_bytes = malloc(size)) == NULL)
		goto free_done;

	rv = read(fd, fp->vf_bytes, size);
	if (rv < 0 || (size_t)rv != size)
		goto free_done;
	for (i = 0; i < VFNT_MAPS; i++) {
		if (load_mapping(fd, fp, i) != 0)
			goto free_done;
	}

	/*
	 * Reset builtin flag now as we have full font loaded.
	 */
	if (fl->font_flags == FONT_BUILTIN)
		fl->font_flags = FONT_AUTO;

	/*
	 * Release previously loaded entries. We can do this now, as
	 * the new font is loaded. Note, there can be no console
	 * output till the new font is in place and tem is notified.
	 * We do need to keep fl->font_data for glyph dimensions.
	 */
	STAILQ_FOREACH(fl, &fonts, font_next) {
		if (fl->font_data->font == NULL)
			continue;

		for (i = 0; i < VFNT_MAPS; i++)
			free(fl->font_data->font->vf_map[i]);
		free(fl->font_data->font->vf_bytes);
		free(fl->font_data->font);
		fl->font_data->font = NULL;
	}

	bp->font = fp;
	bp->compressed_size = 0;

done:
	if (fd != -1)
		close(fd);
	return (bp);

free_done:
	for (i = 0; i < VFNT_MAPS; i++)
		free(fp->vf_map[i]);
	free(fp->vf_bytes);
	free(fp);
	bp = NULL;
	goto done;
}


struct name_entry {
	char			*n_name;
	SLIST_ENTRY(name_entry)	n_entry;
};

SLIST_HEAD(name_list, name_entry);

/* Read font names from index file. */
static struct name_list *
read_list(char *fonts)
{
	struct name_list *nl;
	struct name_entry *np;
	char buf[PATH_MAX];
	int fd, len;

	fd = open(fonts, O_RDONLY);
	if (fd < 0)
		return (NULL);

	nl = malloc(sizeof (*nl));
	if (nl == NULL) {
		close(fd);
		return (nl);
	}

	SLIST_INIT(nl);
	while ((len = fgetstr(buf, sizeof (buf), fd)) > 0) {
		np = malloc(sizeof (*np));
		if (np == NULL) {
			close(fd);
			return (nl);    /* return what we have */
		}
		np->n_name = strdup(buf);
		if (np->n_name == NULL) {
			free(np);
			close(fd);
			return (nl);    /* return what we have */
		}
		SLIST_INSERT_HEAD(nl, np, n_entry);
	}
	close(fd);
	return (nl);
}

/*
 * Read the font properties and insert new entry into the list.
 * The font list is built in descending order.
 */
static bool
insert_font(char *name, FONT_FLAGS flags)
{
	struct font_header fh;
	struct fontlist *fp, *previous, *entry, *next;
	size_t size;
	ssize_t rv;
	int fd;
	char *font_name;

	font_name = NULL;
	if (flags == FONT_BUILTIN) {
		/*
		 * We only install builtin font once, while setting up
		 * initial console. Since this will happen very early,
		 * we assume asprintf will not fail. Once we have access to
		 * files, the builtin font will be replaced by font loaded
		 * from file.
		 */
		if (!STAILQ_EMPTY(&fonts))
			return (false);

		fh.fh_width = DEFAULT_FONT_DATA.width;
		fh.fh_height = DEFAULT_FONT_DATA.height;

		(void) asprintf(&font_name, "%dx%d",
		    DEFAULT_FONT_DATA.width, DEFAULT_FONT_DATA.height);
	} else {
		fd = open(name, O_RDONLY);
		if (fd < 0)
			return (false);
		rv = read(fd, &fh, sizeof (fh));
		close(fd);
		if (rv < 0 || (size_t)rv != sizeof (fh))
			return (false);

		if (memcmp(fh.fh_magic, FONT_HEADER_MAGIC,
		    sizeof (fh.fh_magic)) != 0)
			return (false);
		font_name = strdup(name);
	}

	if (font_name == NULL)
		return (false);

	/*
	 * If we have an entry with the same glyph dimensions, replace
	 * the file name and mark us. We only support unique dimensions.
	 */
	STAILQ_FOREACH(entry, &fonts, font_next) {
		if (fh.fh_width == entry->font_data->width &&
		    fh.fh_height == entry->font_data->height) {
			free(entry->font_name);
			entry->font_name = font_name;
			entry->font_flags = FONT_RELOAD;
			return (true);
		}
	}

	fp = calloc(sizeof (*fp), 1);
	if (fp == NULL) {
		free(font_name);
		return (false);
	}
	fp->font_data = calloc(sizeof (*fp->font_data), 1);
	if (fp->font_data == NULL) {
		free(font_name);
		free(fp);
		return (false);
	}
	fp->font_name = font_name;
	fp->font_flags = flags;
	fp->font_load = load_font;
	fp->font_data->width = fh.fh_width;
	fp->font_data->height = fh.fh_height;

	if (STAILQ_EMPTY(&fonts)) {
		STAILQ_INSERT_HEAD(&fonts, fp, font_next);
		return (true);
	}

	previous = NULL;
	size = fp->font_data->width * fp->font_data->height;

	STAILQ_FOREACH(entry, &fonts, font_next) {
		/* Should fp be inserted before the entry? */
		if (size > entry->font_data->width * entry->font_data->height) {
			if (previous == NULL) {
				STAILQ_INSERT_HEAD(&fonts, fp, font_next);
			} else {
				STAILQ_INSERT_AFTER(&fonts, previous, fp,
				    font_next);
			}
			return (true);
		}
		next = STAILQ_NEXT(entry, font_next);
		if (next == NULL ||
		    size > next->font_data->width * next->font_data->height) {
			STAILQ_INSERT_AFTER(&fonts, entry, fp, font_next);
			return (true);
		}
		previous = entry;
	}
	return (true);
}

static int
font_set(struct env_var *ev __unused, int flags __unused, const void *value)
{
	struct fontlist *fl;
	char *eptr;
	unsigned long x = 0, y = 0;

	/*
	 * Attempt to extract values from "XxY" string. In case of error,
	 * we have unmaching glyph dimensions and will just output the
	 * available values.
	 */
	if (value != NULL) {
		x = strtoul(value, &eptr, 10);
		if (*eptr == 'x')
			y = strtoul(eptr + 1, &eptr, 10);
	}
	STAILQ_FOREACH(fl, &fonts, font_next) {
		if (fl->font_data->width == x && fl->font_data->height == y)
			break;
	}
	if (fl != NULL) {
		/* Reset any FONT_MANUAL flag. */
		reset_font_flags();

		/* Mark this font manually loaded */
		fl->font_flags = FONT_MANUAL;
		/* Trigger tem update. */
		tems.update_font = true;
		plat_cons_update_mode(-1);
		return (CMD_OK);
	}

	printf("Available fonts:\n");
	STAILQ_FOREACH(fl, &fonts, font_next) {
		printf("    %dx%d\n", fl->font_data->width,
		    fl->font_data->height);
	}
	return (CMD_OK);
}

void
bios_text_font(bool use_vga_font)
{
	if (use_vga_font)
		(void) insert_font(VGA_8X16_FONT, FONT_MANUAL);
	else
		(void) insert_font(DEFAULT_8X16_FONT, FONT_MANUAL);
	tems.update_font = true;
}

void
autoload_font(bool bios)
{
	struct name_list *nl;
	struct name_entry *np;

	nl = read_list("/boot/fonts/fonts.dir");
	if (nl == NULL)
		return;

	while (!SLIST_EMPTY(nl)) {
		np = SLIST_FIRST(nl);
		SLIST_REMOVE_HEAD(nl, n_entry);
		if (insert_font(np->n_name, FONT_AUTO) == false)
			printf("failed to add font: %s\n", np->n_name);
		free(np->n_name);
		free(np);
	}

	unsetenv("screen-font");
	env_setenv("screen-font", EV_VOLATILE, NULL, font_set, env_nounset);

	/*
	 * If vga text mode was requested, load vga.font (8x16 bold) font.
	 */
	if (bios) {
		bios_text_font(true);
	}

	/* Trigger tem update. */
	tems.update_font = true;
	plat_cons_update_mode(-1);
}

COMMAND_SET(load_font, "loadfont", "load console font from file", command_font);

static int
command_font(int argc, char *argv[])
{
	int i, c, rc = CMD_OK;
	struct fontlist *fl;
	bool list;

	list = false;
	optind = 1;
	optreset = 1;
	rc = CMD_OK;

	while ((c = getopt(argc, argv, "l")) != -1) {
		switch (c) {
		case 'l':
			list = true;
			break;
		case '?':
		default:
			return (CMD_ERROR);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 1 || (list && argc != 0)) {
		printf("Usage: loadfont [-l] | [file.fnt]\n");
		return (CMD_ERROR);
	}

	if (list) {
		STAILQ_FOREACH(fl, &fonts, font_next) {
			printf("font %s: %dx%d%s\n", fl->font_name,
			    fl->font_data->width,
			    fl->font_data->height,
			    fl->font_data->font == NULL? "" : " loaded");
		}
		return (CMD_OK);
	}

	if (argc == 1) {
		char *name = argv[0];

		if (insert_font(name, FONT_MANUAL) == false) {
			printf("loadfont error: failed to load: %s\n", name);
			return (CMD_ERROR);
		}

		tems.update_font = true;
		plat_cons_update_mode(-1);
		return (CMD_OK);
	}

	if (argc == 0) {
		/*
		 * Walk entire font list, release any loaded font, and set
		 * autoload flag. The font list does have at least the builtin
		 * default font.
		 */
		STAILQ_FOREACH(fl, &fonts, font_next) {
			if (fl->font_data->font != NULL) {
				/* Note the tem is releasing font bytes */
				for (i = 0; i < VFNT_MAPS; i++)
					free(fl->font_data->font->vf_map[i]);
				free(fl->font_data->font);
				fl->font_data->font = NULL;
				fl->font_data->uncompressed_size = 0;
				fl->font_flags = FONT_AUTO;
			}
		}
		tems.update_font = true;
		plat_cons_update_mode(-1);
	}
	return (rc);
}

bool
gfx_get_edid_resolution(struct vesa_edid_info *edid, edid_res_list_t *res)
{
	struct resolution *rp, *p;

	/*
	 * Walk detailed timings tables (4).
	 */
	if ((edid->display.supported_features
	    & EDID_FEATURE_PREFERRED_TIMING_MODE) != 0) {
		/* Walk detailed timing descriptors (4) */
		for (int i = 0; i < DET_TIMINGS; i++) {
			/*
			 * Reserved value 0 is not used for display decriptor.
			 */
			if (edid->detailed_timings[i].pixel_clock == 0)
				continue;
			if ((rp = malloc(sizeof (*rp))) == NULL)
				continue;
			rp->width = GET_EDID_INFO_WIDTH(edid, i);
			rp->height = GET_EDID_INFO_HEIGHT(edid, i);
			if (rp->width > 0 && rp->width <= EDID_MAX_PIXELS &&
			    rp->height > 0 && rp->height <= EDID_MAX_LINES)
				TAILQ_INSERT_TAIL(res, rp, next);
			else
				free(rp);
		}
	}

	/*
	 * Walk standard timings list (8).
	 */
	for (int i = 0; i < STD_TIMINGS; i++) {
		/* Is this field unused? */
		if (edid->standard_timings[i] == 0x0101)
			continue;

		if ((rp = malloc(sizeof (*rp))) == NULL)
			continue;

		rp->width = HSIZE(edid->standard_timings[i]);
		switch (RATIO(edid->standard_timings[i])) {
		case RATIO1_1:
			rp->height = HSIZE(edid->standard_timings[i]);
			if (edid->header.version > 1 ||
			    edid->header.revision > 2) {
				rp->height = rp->height * 10 / 16;
			}
			break;
		case RATIO4_3:
			rp->height = HSIZE(edid->standard_timings[i]) * 3 / 4;
			break;
		case RATIO5_4:
			rp->height = HSIZE(edid->standard_timings[i]) * 4 / 5;
			break;
		case RATIO16_9:
			rp->height = HSIZE(edid->standard_timings[i]) * 9 / 16;
			break;
		}

		/*
		 * Create resolution list in decreasing order, except keep
		 * first entry (preferred timing mode).
		 */
		TAILQ_FOREACH(p, res, next) {
			if (p->width * p->height < rp->width * rp->height) {
				/* Keep preferred mode first */
				if (TAILQ_FIRST(res) == p)
					TAILQ_INSERT_AFTER(res, p, rp, next);
				else
					TAILQ_INSERT_BEFORE(p, rp, next);
				break;
			}
			if (TAILQ_NEXT(p, next) == NULL) {
				TAILQ_INSERT_TAIL(res, rp, next);
				break;
			}
		}
	}
	return (!TAILQ_EMPTY(res));
}
