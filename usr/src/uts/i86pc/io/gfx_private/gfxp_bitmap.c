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
 * Framebuffer based console support.
 *
 * Missing (no particular order):
 * memory barriers
 * shadow buffering
 * copyin for userspace calls and then polled io split.
 * callbacks for hw blt() and others?
 */
#include <sys/types.h>
#include <sys/visual_io.h>
#include <sys/fbio.h>
#include <sys/ddi.h>
#include <sys/kd.h>
#include <sys/sunddi.h>
#include <sys/gfx_private.h>
#include "gfxp_fb.h"

#define	MYNAME	"gfxp_bitmap"

static ddi_device_acc_attr_t dev_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_MERGING_OK_ACC
};

/* default structure for FBIOGATTR ioctl */
static struct fbgattr bitmap_attr =  {
/*	real_type	owner */
	FBTYPE_MEMCOLOR, 0,
/* fbtype: type		h  w  depth cms  size */
	{ FBTYPE_MEMCOLOR, 0, 0, 0, 0, 0 },
/* fbsattr: flags emu_type	dev_specific */
	{ 0, FBTYPE_MEMCOLOR, { 0 } },
/*	emu_types */
	{ -1 }
};

static struct vis_identifier gfxp_bitmap_ident = { "illumos_fb" };

static void bitmap_copy_fb(struct gfxp_fb_softc *, uint8_t *, uint8_t *);
static int bitmap_kdsetmode(struct gfxp_fb_softc *, int);
static int bitmap_devinit(struct gfxp_fb_softc *, struct vis_devinit *);
static void	bitmap_cons_copy(struct gfxp_fb_softc *, struct vis_conscopy *);
static void	bitmap_cons_display(struct gfxp_fb_softc *,
    struct vis_consdisplay *);
static int	bitmap_cons_clear(struct gfxp_fb_softc *,
    struct vis_consclear *);
static void	bitmap_cons_cursor(struct gfxp_fb_softc *,
    struct vis_conscursor *);
static uint32_t bitmap_color_map(uint8_t);
static void	bitmap_polled_copy(struct vis_polledio_arg *,
    struct vis_conscopy *);
static void	bitmap_polled_display(struct vis_polledio_arg *,
    struct vis_consdisplay *);
static void	bitmap_polled_cursor(struct vis_polledio_arg *,
    struct vis_conscursor *);
static int	bitmap_suspend(struct gfxp_fb_softc *softc);
static void	bitmap_resume(struct gfxp_fb_softc *softc);
static int	bitmap_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off,
    size_t len, size_t *maplen, uint_t model, void *ptr);

static struct gfxp_ops gfxp_bitmap_ops = {
	.ident = &gfxp_bitmap_ident,
	.kdsetmode = bitmap_kdsetmode,
	.devinit = bitmap_devinit,
	.cons_copy = bitmap_cons_copy,
	.cons_display = bitmap_cons_display,
	.cons_cursor = bitmap_cons_cursor,
	.cons_clear = bitmap_cons_clear,
	.suspend = bitmap_suspend,
	.resume = bitmap_resume,
	.devmap = bitmap_devmap
};

void
gfxp_bm_register_fbops(gfxp_fb_softc_ptr_t ptr, struct gfxp_blt_ops *ops)
{
	struct gfxp_fb_softc *softc = (struct gfxp_fb_softc *)ptr;

	if (softc != NULL) {
		softc->blt_ops.blt = ops->blt;
		softc->blt_ops.copy = ops->copy;
		softc->blt_ops.clear = ops->clear;
		softc->blt_ops.setmode = ops->setmode;
	}
}

void
gfxp_bm_getfb_info(gfxp_fb_softc_ptr_t ptr, struct gfxp_bm_fb_info *fbip)
{
	struct gfxp_fb_softc *softc = (struct gfxp_fb_softc *)ptr;

	switch (softc->fb_type) {
	case GFXP_BITMAP:
		fbip->xres = softc->console->fb.screen.x;
		fbip->yres = softc->console->fb.screen.y;
		fbip->bpp = softc->console->fb.bpp;
		fbip->depth = softc->console->fb.depth;
		break;
	case GFXP_VGATEXT:
		/*
		 * By current knowledge, DRM can not cope with text mode
		 * and the VGA is disabled. The proper approach here
		 * is to set all values to 0. See the drm_getfb_size() and
		 * the i915_gem_init() how the size is used.
		 */
		fbip->xres = 0;
		fbip->yres = 0;
		fbip->bpp = 0;
		fbip->depth = 0;
		break;
	}
}

int
gfxp_bm_attach(dev_info_t *devi __unused, struct gfxp_fb_softc *softc)
{
	softc->polledio.display = bitmap_polled_display;
	softc->polledio.copy = bitmap_polled_copy;
	softc->polledio.cursor = bitmap_polled_cursor;
	softc->gfxp_ops = &gfxp_bitmap_ops;
	softc->fbgattr = &bitmap_attr;
	softc->silent = 0;

	return (DDI_SUCCESS);
}

int
gfxp_bm_detach(dev_info_t *devi __unused, struct gfxp_fb_softc *softc)
{
	if (softc == NULL || softc->console == NULL)
		return (DDI_SUCCESS);

	if (softc->console->fb.fb_size != 0) {
		gfxp_unmap_kernel_space((gfxp_kva_t)softc->console->fb.fb,
		    softc->console->fb.fb_size);
		fb_info.fb = NULL;
		kmem_free(softc->console->fb.shadow_fb,
		    softc->console->fb.fb_size);
		softc->console->fb.shadow_fb = NULL;
	}
	return (DDI_SUCCESS);
}

static void
bitmap_kdsettext(struct gfxp_fb_softc *softc)
{
	bitmap_copy_fb(softc, softc->console->fb.shadow_fb,
	    softc->console->fb.fb);
}

static void
bitmap_kdsetgraphics(struct gfxp_fb_softc *softc __unused)
{
	/* we have the copy of fb content in shadow_fb */
}

static int
bitmap_suspend(struct gfxp_fb_softc *softc __unused)
{
	/* we have the copy of fb content in shadow_fb */
	return (DDI_SUCCESS);
}

static void
bitmap_resume(struct gfxp_fb_softc *softc)
{
	bitmap_kdsettext(softc);
}

static int
bitmap_kdsetmode(struct gfxp_fb_softc *softc, int mode)
{
	switch (mode) {
	case KD_TEXT:
		if (softc->blt_ops.setmode != NULL)
			softc->blt_ops.setmode(KD_TEXT);
		bitmap_kdsettext(softc);
		break;
	case KD_GRAPHICS:
		bitmap_kdsetgraphics(softc);
		if (softc->blt_ops.setmode != NULL)
			softc->blt_ops.setmode(KD_GRAPHICS);
		break;
	case KD_RESETTEXT:
		/*
		 * In order to avoid racing with a starting X server,
		 * this needs to be a test and set that is performed in
		 * a single (softc->lock protected) ioctl into this driver.
		 */
		if (softc->mode == KD_TEXT && softc->silent == 1) {
			bitmap_kdsettext(softc);
		}
		mode = KD_TEXT;
		break;
	default:
		return (EINVAL);
	}

	softc->mode = mode;
	return (0);
}

/*
 * Copy fb_info from early boot and set up the FB
 */
static int
bitmap_setup_fb(struct gfxp_fb_softc *softc)
{
	size_t size;
	struct gfxfb_info *gfxfb_info;

	softc->console = (union gfx_console *)&fb_info;
	size = ptob(btopr(fb_info.fb_size));
	softc->console->fb.fb_size = size;
	softc->console->fb.fb = (uint8_t *)gfxp_map_kernel_space(fb_info.paddr,
	    size, GFXP_MEMORY_WRITECOMBINED);
	if (softc->console->fb.fb == NULL)
		return (DDI_FAILURE);

	softc->console->fb.shadow_fb = kmem_zalloc(size, KM_SLEEP);

	bitmap_attr.fbtype.fb_height = fb_info.screen.y;
	bitmap_attr.fbtype.fb_width = fb_info.screen.x;
	bitmap_attr.fbtype.fb_depth = fb_info.depth;
	bitmap_attr.fbtype.fb_size = size;
	if (fb_info.depth == 32)
		bitmap_attr.fbtype.fb_cmsize = 1 << 24;
	else
		bitmap_attr.fbtype.fb_cmsize = 1 << fb_info.depth;

	gfxfb_info = (struct gfxfb_info *)bitmap_attr.sattr.dev_specific;
	gfxfb_info->terminal_origin_x = fb_info.terminal_origin.x;
	gfxfb_info->terminal_origin_y = fb_info.terminal_origin.y;
	gfxfb_info->pitch = fb_info.pitch;
	gfxfb_info->font_width = fb_info.font_width;
	gfxfb_info->font_height = fb_info.font_height;
	gfxfb_info->red_mask_size = fb_info.rgb.red.size;
	gfxfb_info->red_field_position = fb_info.rgb.red.pos;
	gfxfb_info->green_mask_size = fb_info.rgb.green.size;
	gfxfb_info->green_field_position = fb_info.rgb.green.pos;
	gfxfb_info->blue_mask_size = fb_info.rgb.blue.size;
	gfxfb_info->blue_field_position = fb_info.rgb.blue.pos;

	return (DDI_SUCCESS);
}

static uint32_t
bitmap_color_map(uint8_t index)
{
	uint8_t c, mask;
	uint32_t color = 0;

	c = cmap_rgb16.red[index];
	mask = (1 << fb_info.rgb.red.size) - 1;
	c >>= 8 - fb_info.rgb.red.size;
	c &= mask;
	color |= c << fb_info.rgb.red.pos;

	c = cmap_rgb16.green[index];
	mask = (1 << fb_info.rgb.green.size) - 1;
	c >>= 8 - fb_info.rgb.green.size;
	c &= mask;
	color |= c << fb_info.rgb.green.pos;

	c = cmap_rgb16.blue[index];
	mask = (1 << fb_info.rgb.blue.size) - 1;
	c >>= 8 - fb_info.rgb.blue.size;
	c &= mask;
	color |= c << fb_info.rgb.blue.pos;

	return (color);
}

static int
bitmap_devinit(struct gfxp_fb_softc *softc, struct vis_devinit *data)
{
	union gfx_console *console;

	if (bitmap_setup_fb(softc) == DDI_FAILURE)
		return (1);

	console = softc->console;

	/* make sure we have current state of the screen */
	bitmap_copy_fb(softc, console->fb.fb, console->fb.shadow_fb);

	/* initialize console instance */
	data->version = VIS_CONS_REV;
	data->width = console->fb.screen.x;
	data->height = console->fb.screen.y;
	data->linebytes = console->fb.pitch;
	data->color_map = bitmap_color_map;
	data->depth = console->fb.depth;
	data->mode = VIS_PIXEL;
	data->polledio = &softc->polledio;
#if 0
	data->modechg_cb;
	data->modechg_arg;
#endif
	return (0);
}

/* Buffer to Buffer copy */
static void
bitmap_copy_fb(struct gfxp_fb_softc *softc, uint8_t *src, uint8_t *dst)
{
	uint32_t i, pitch, height;

	pitch = softc->console->fb.pitch;
	height = softc->console->fb.screen.y;

	for (i = 0; i < height; i++) {
		(void) memmove(dst + i * pitch, src + i * pitch, pitch);
	}
}

static void
bitmap_cons_copy(struct gfxp_fb_softc *softc, struct vis_conscopy *ma)
{
	union gfx_console *console;
	uint32_t soffset, toffset;
	uint32_t width, height, pitch;
	uint8_t *src, *dst, *sdst;
	int i;

	console = softc->console;
	soffset = ma->s_col * console->fb.bpp + ma->s_row * console->fb.pitch;
	toffset = ma->t_col * console->fb.bpp + ma->t_row * console->fb.pitch;
	src = console->fb.shadow_fb + soffset;
	dst = console->fb.fb + toffset;
	sdst = console->fb.shadow_fb + toffset;
	width = (ma->e_col - ma->s_col + 1) * console->fb.bpp;
	height = ma->e_row - ma->s_row + 1;
	pitch = console->fb.pitch;

	if (toffset <= soffset) {
		for (i = 0; i < height; i++) {
			uint32_t increment = i * pitch;
			if (softc->mode == KD_TEXT) {
				(void) memmove(dst + increment,
				    src + increment, width);
			}
			(void) memmove(sdst + increment, src + increment,
			    width);
		}
	} else {
		for (i = height - 1; i >= 0; i--) {
			uint32_t increment = i * pitch;
			if (softc->mode == KD_TEXT) {
				(void) memmove(dst + increment,
				    src + increment, width);
			}
			(void) memmove(sdst + increment, src + increment,
			    width);
		}
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

static void
bitmap_cons_display(struct gfxp_fb_softc *softc, struct vis_consdisplay *da)
{
	union gfx_console *console;
	uint32_t size;		/* write size per scanline */
	uint8_t *fbp, *sfbp;	/* fb + calculated offset */
	int i;

	console = softc->console;
	/* make sure we will not write past FB */
	if (da->col >= console->fb.screen.x ||
	    da->row >= console->fb.screen.y ||
	    da->col + da->width > console->fb.screen.x ||
	    da->row + da->height > console->fb.screen.y)
		return;

	size = da->width * console->fb.bpp;
	fbp = console->fb.fb + da->col * console->fb.bpp +
	    da->row * console->fb.pitch;
	sfbp = console->fb.shadow_fb + da->col * console->fb.bpp +
	    da->row * console->fb.pitch;

	/* write all scanlines in rectangle */
	for (i = 0; i < da->height; i++) {
		uint8_t *dest = fbp + i * console->fb.pitch;
		uint8_t *src = da->data + i * size;
		if (softc->mode == KD_TEXT)
			bitmap_cpy(dest, src, size, console->fb.bpp);
		dest = sfbp + i * console->fb.pitch;
		bitmap_cpy(dest, src, size, console->fb.bpp);
	}
}

static int
bitmap_cons_clear(struct gfxp_fb_softc *softc, struct vis_consclear *ca)
{
	union gfx_console *console;
	uint8_t *fb, *sfb;
	uint16_t *fb16, *sfb16;
	uint32_t data, *fb32, *sfb32;
	int i, j, pitch;

	console = softc->console;
	pitch = console->fb.pitch;
	data = bitmap_color_map(ca->bg_color);
	switch (console->fb.depth) {
	case 8:
		for (i = 0; i < console->fb.screen.y; i++) {
			if (softc->mode == KD_TEXT) {
				fb = console->fb.fb + i * pitch;
				(void) memset(fb, ca->bg_color, pitch);
			}
			fb = console->fb.shadow_fb + i * pitch;
			(void) memset(fb, ca->bg_color, pitch);
		}
		break;
	case 15:
	case 16:
		for (i = 0; i < console->fb.screen.y; i++) {
			fb16 = (uint16_t *)(console->fb.fb + i * pitch);
			sfb16 = (uint16_t *)(console->fb.shadow_fb + i * pitch);
			for (j = 0; j < console->fb.screen.x; j++) {
				if (softc->mode == KD_TEXT)
					fb16[j] = (uint16_t)data & 0xffff;
				sfb16[j] = (uint16_t)data & 0xffff;
			}
		}
		break;
	case 24:
		for (i = 0; i < console->fb.screen.y; i++) {
			fb = console->fb.fb + i * pitch;
			sfb = console->fb.shadow_fb + i * pitch;
			for (j = 0; j < pitch; j += 3) {
				if (softc->mode == KD_TEXT) {
					fb[j] = (data >> 16) & 0xff;
					fb[j+1] = (data >> 8) & 0xff;
					fb[j+2] = data & 0xff;
				}

				sfb[j] = (data >> 16) & 0xff;
				sfb[j+1] = (data >> 8) & 0xff;
				sfb[j+2] = data & 0xff;
			}
		}
		break;
	case 32:
		for (i = 0; i < console->fb.screen.y; i++) {
			fb32 = (uint32_t *)(console->fb.fb + i * pitch);
			sfb32 = (uint32_t *)(console->fb.shadow_fb + i * pitch);
			for (j = 0; j < console->fb.screen.x; j++) {
				if (softc->mode == KD_TEXT)
					fb32[j] = data;
				sfb32[j] = data;
			}
		}
		break;
	}

	return (0);
}

static void
bitmap_display_cursor(struct gfxp_fb_softc *softc, struct vis_conscursor *ca)
{
	union gfx_console *console;
	uint32_t fg, bg, offset, size;
	uint32_t *fb32, *sfb32;
	uint16_t *fb16, *sfb16;
	uint8_t *fb8, *sfb8;
	int i, j, bpp, pitch;

	console = softc->console;
	pitch = console->fb.pitch;
	bpp = console->fb.bpp;
	size = ca->width * bpp;

	/*
	 * Build cursor image. We are building mirror image of data on
	 * frame buffer by (D xor FG) xor BG.
	 */
	offset = ca->col * bpp + ca->row * pitch;
	switch (console->fb.depth) {
	case 8:
		fg = ca->fg_color.mono;
		bg = ca->bg_color.mono;
		for (i = 0; i < ca->height; i++) {
			fb8 = console->fb.fb + offset + i * pitch;
			sfb8 = console->fb.shadow_fb + offset + i * pitch;
			for (j = 0; j < size; j += 1) {
				if (softc->mode == KD_TEXT) {
					fb8[j] = (fb8[j] ^ (fg & 0xff)) ^
					    (bg & 0xff);
				}
				sfb8[j] = (sfb8[j] ^ (fg & 0xff)) ^ (bg & 0xff);
			}
		}
		break;
	case 15:
	case 16:
		fg = ca->fg_color.sixteen[0] << 8;
		fg |= ca->fg_color.sixteen[1];
		bg = ca->bg_color.sixteen[0] << 8;
		bg |= ca->bg_color.sixteen[1];
		for (i = 0; i < ca->height; i++) {
			fb16 = (uint16_t *)
			    (console->fb.fb + offset + i * pitch);
			sfb16 = (uint16_t *)
			    (console->fb.shadow_fb + offset + i * pitch);
			for (j = 0; j < ca->width; j++) {
				if (softc->mode == KD_TEXT) {
					fb16[j] = (fb16[j] ^ (fg & 0xffff)) ^
					    (bg & 0xffff);
				}
				sfb16[j] = (sfb16[j] ^ (fg & 0xffff)) ^
				    (bg & 0xffff);
			}
		}
		break;
	case 24:
		fg = ca->fg_color.twentyfour[0] << console->fb.rgb.red.pos;
		fg |= ca->fg_color.twentyfour[1] << console->fb.rgb.green.pos;
		fg |= ca->fg_color.twentyfour[2] << console->fb.rgb.blue.pos;
		bg = ca->bg_color.twentyfour[0] << console->fb.rgb.red.pos;
		bg |= ca->bg_color.twentyfour[1] << console->fb.rgb.green.pos;
		bg |= ca->bg_color.twentyfour[2] << console->fb.rgb.blue.pos;
		for (i = 0; i < ca->height; i++) {
			fb8 = console->fb.fb + offset + i * pitch;
			sfb8 = console->fb.shadow_fb + offset + i * pitch;
			for (j = 0; j < size; j += 3) {
				if (softc->mode == KD_TEXT) {
					fb8[j] = (fb8[j] ^ ((fg >> 16) & 0xff))
					    ^ ((bg >> 16) & 0xff);
					fb8[j+1] =
					    (fb8[j+1] ^ ((fg >> 8) & 0xff)) ^
					    ((bg >> 8) & 0xff);
					fb8[j+2] = (fb8[j+2] ^ (fg & 0xff)) ^
					    (bg & 0xff);
				}

				sfb8[j] = (sfb8[j] ^ ((fg >> 16) & 0xff)) ^
				    ((bg >> 16) & 0xff);
				sfb8[j+1] = (sfb8[j+1] ^ ((fg >> 8) & 0xff)) ^
				    ((bg >> 8) & 0xff);
				sfb8[j+2] = (sfb8[j+2] ^ (fg & 0xff)) ^
				    (bg & 0xff);
			}
		}
		break;
	case 32:
		fg = ca->fg_color.twentyfour[0] << console->fb.rgb.red.pos;
		fg |= ca->fg_color.twentyfour[1] << console->fb.rgb.green.pos;
		fg |= ca->fg_color.twentyfour[2] << console->fb.rgb.blue.pos;
		bg = ca->bg_color.twentyfour[0] << console->fb.rgb.red.pos;
		bg |= ca->bg_color.twentyfour[1] << console->fb.rgb.green.pos;
		bg |= ca->bg_color.twentyfour[2] << console->fb.rgb.blue.pos;
		for (i = 0; i < ca->height; i++) {
			fb32 = (uint32_t *)
			    (console->fb.fb + offset + i * pitch);
			sfb32 = (uint32_t *)
			    (console->fb.shadow_fb + offset + i * pitch);
			for (j = 0; j < ca->width; j++) {
				if (softc->mode == KD_TEXT)
					fb32[j] = (fb32[j] ^ fg) ^ bg;
				sfb32[j] = (sfb32[j] ^ fg) ^ bg;
			}
		}
		break;
	}
}

static void
bitmap_cons_cursor(struct gfxp_fb_softc *softc, struct vis_conscursor *ca)
{
	union gfx_console *console = softc->console;

	switch (ca->action) {
	case VIS_HIDE_CURSOR:
		bitmap_display_cursor(softc, ca);
		console->fb.cursor.visible = B_FALSE;
		break;
	case VIS_DISPLAY_CURSOR:
		/* keep track of cursor position for polled mode */
		console->fb.cursor.pos.x =
		    (ca->col - console->fb.terminal_origin.x) /
		    console->fb.font_width;
		console->fb.cursor.pos.y =
		    (ca->row - console->fb.terminal_origin.y) /
		    console->fb.font_height;
		console->fb.cursor.origin.x = ca->col;
		console->fb.cursor.origin.y = ca->row;

		bitmap_display_cursor(softc, ca);
		console->fb.cursor.visible = B_TRUE;
		break;
	case VIS_GET_CURSOR:
		ca->row = console->fb.cursor.origin.y;
		ca->col = console->fb.cursor.origin.x;
		break;
	}
}

static void
bitmap_polled_copy(struct vis_polledio_arg *arg, struct vis_conscopy *ca)
{
	struct gfxp_fb_softc *softc = (struct gfxp_fb_softc *)arg;
	bitmap_cons_copy(softc, ca);
}

static void
bitmap_polled_display(struct vis_polledio_arg *arg, struct vis_consdisplay *da)
{
	struct gfxp_fb_softc *softc = (struct gfxp_fb_softc *)arg;
	bitmap_cons_display(softc, da);
}

static void
bitmap_polled_cursor(struct vis_polledio_arg *arg, struct vis_conscursor *ca)
{
	struct gfxp_fb_softc *softc = (struct gfxp_fb_softc *)arg;
	bitmap_cons_cursor(softc, ca);
}

/*
 * Device mapping support. Should be possible to mmmap frame buffer
 * to user space. Currently not working, mmap will receive -1 as pointer.
 */
/*ARGSUSED*/
static int
bitmap_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off,
    size_t len, size_t *maplen, uint_t model, void *ptr)
{
	struct gfxp_fb_softc *softc = (struct gfxp_fb_softc *)ptr;
	union gfx_console *console = softc->console;
	size_t length;

	if (softc == NULL) {
		cmn_err(CE_WARN, "bitmap: Can't find softstate");
		return (ENXIO);
	}

	if (off >= console->fb.fb_size) {
		cmn_err(CE_WARN, "bitmap: Can't map offset 0x%llx", off);
		return (ENXIO);
	}

	if (off + len > console->fb.fb_size)
		length = console->fb.fb_size - off;
	else
		length = len;

	gfxp_map_devmem(dhp, console->fb.paddr, length, &dev_attr);

	*maplen = length;

	return (0);
}
