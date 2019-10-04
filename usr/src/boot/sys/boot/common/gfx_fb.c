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
 */

/*
 * Common functions to implement graphical framebuffer support for console.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <stand.h>
#if	defined(EFI)
#include <efi.h>
#include <efilib.h>
#else
#include <btxv86.h>
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

/*
 * Global framebuffer struct, to be updated with mode changes.
 */
multiboot_tag_framebuffer_t gfx_fb;

/* To support setenv, keep track of inverses and colors. */
static int gfx_inverse = 0;
static int gfx_inverse_screen = 0;
static uint8_t gfx_fg = DEFAULT_ANSI_FOREGROUND;
static uint8_t gfx_bg = DEFAULT_ANSI_BACKGROUND;

static int gfx_fb_cons_clear(struct vis_consclear *);
static void gfx_fb_cons_copy(struct vis_conscopy *);
static void gfx_fb_cons_display(struct vis_consdisplay *);

#if	defined(EFI)
static int gfx_gop_cons_clear(uint32_t data, uint32_t width, uint32_t height);
static void gfx_gop_cons_copy(struct vis_conscopy *);
static void gfx_gop_cons_display(struct vis_consdisplay *);
#endif
static int gfx_bm_cons_clear(uint32_t data, uint32_t width, uint32_t height);
static void gfx_bm_cons_copy(struct vis_conscopy *);
static void gfx_bm_cons_display(struct vis_consdisplay *);

/*
 * Set default operations to use bitmap based implementation.
 * In case of UEFI, if GOP is available, we will switch to GOP based
 * implementation.
 *
 * Also note, for UEFI we do attempt to boost the execution by setting
 * Task Priority Level (TPL) to TPL_NOTIFY, which is highest priority
 * usable in application.
 */
struct gfx_fb_ops {
	int (*gfx_cons_clear)(uint32_t, uint32_t, uint32_t);
	void (*gfx_cons_copy)(struct vis_conscopy *);
	void (*gfx_cons_display)(struct vis_consdisplay *);
} gfx_fb_ops = {
	.gfx_cons_clear = gfx_bm_cons_clear,
	.gfx_cons_copy = gfx_bm_cons_copy,
	.gfx_cons_display = gfx_bm_cons_display
};

/*
 * Translate platform specific FB address.
 */
static uint8_t *
gfx_get_fb_address(void)
{
#if	defined(EFI)
	return ((uint8_t *)(uintptr_t)
	    gfx_fb.framebuffer_common.framebuffer_addr);
#else
	return ((uint8_t *)PTOV((uint32_t)
	    gfx_fb.framebuffer_common.framebuffer_addr & 0xffffffff));
#endif
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

/*
 * Support for color mapping.
 */
uint32_t
gfx_fb_color_map(uint8_t index)
{
	rgb_t rgb;

	if (gfx_fb.framebuffer_common.framebuffer_type !=
	    MULTIBOOT_FRAMEBUFFER_TYPE_RGB) {
		if (index < nitems(solaris_color_to_pc_color))
			return (solaris_color_to_pc_color[index]);
		else
			return (index);
	}

	rgb.red.pos = gfx_fb.u.fb2.framebuffer_red_field_position;
	rgb.red.size = gfx_fb.u.fb2.framebuffer_red_mask_size;

	rgb.green.pos = gfx_fb.u.fb2.framebuffer_green_field_position;
	rgb.green.size = gfx_fb.u.fb2.framebuffer_green_mask_size;

	rgb.blue.pos = gfx_fb.u.fb2.framebuffer_blue_field_position;
	rgb.blue.size = gfx_fb.u.fb2.framebuffer_blue_mask_size;

	return (rgb_color_map(&rgb, index));
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

	if (gfx_fb.framebuffer_common.framebuffer_bpp < 24)
		limit = 7;
	else
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
			    "number from range [0-7]%s.\n",
			    limit == 7 ? "" : " or [16-255]");
			return (CMD_OK);
		}
		evalue = value;
	}

	/* invalid value? */
	if ((val < 0 || val > limit) || (val > 7 && val < 16)) {
		printf("Allowed values are either ansi color name or "
		    "number from range [0-7]%s.\n",
		    limit == 7 ? "" : " or [16-255]");
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
gfx_framework_init(struct visual_ops *fb_ops)
{
	int rc, limit;
	char *env, buf[2];
#if	defined(EFI)
	extern EFI_GRAPHICS_OUTPUT *gop;

	if (gop != NULL) {
		gfx_fb_ops.gfx_cons_clear = gfx_gop_cons_clear;
		gfx_fb_ops.gfx_cons_copy = gfx_gop_cons_copy;
		gfx_fb_ops.gfx_cons_display = gfx_gop_cons_display;
	}
#endif

	if (gfx_fb.framebuffer_common.framebuffer_bpp < 24)
		limit = 7;
	else
		limit = 255;

	/* Add visual io callbacks */
	fb_ops->cons_clear = gfx_fb_cons_clear;
	fb_ops->cons_copy = gfx_fb_cons_copy;
	fb_ops->cons_display = gfx_fb_cons_display;

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
}

/*
 * visual io callbacks.
 */

#if	defined(EFI)
static int
gfx_gop_cons_clear(uint32_t data, uint32_t width, uint32_t height)
{
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *BltBuffer;
	EFI_STATUS status;
	extern EFI_GRAPHICS_OUTPUT *gop;

	BltBuffer = (EFI_GRAPHICS_OUTPUT_BLT_PIXEL *)&data;

	status = gop->Blt(gop, BltBuffer, EfiBltVideoFill, 0, 0,
	    0, 0, width, height, 0);

	if (EFI_ERROR(status))
		return (1);
	else
		return (0);
}
#endif

static int
gfx_bm_cons_clear(uint32_t data, uint32_t width, uint32_t height)
{
	uint8_t *fb, *fb8;
	uint32_t *fb32, pitch;
	uint16_t *fb16;
	uint32_t i, j;

	fb = gfx_get_fb_address();
	pitch = gfx_fb.framebuffer_common.framebuffer_pitch;

	switch (gfx_fb.framebuffer_common.framebuffer_bpp) {
	case 8:		/* 8 bit */
		for (i = 0; i < height; i++) {
			(void) memset(fb + i * pitch, data, pitch);
		}
		break;
	case 15:
	case 16:		/* 16 bit */
		for (i = 0; i < height; i++) {
			fb16 = (uint16_t *)(fb + i * pitch);
			for (j = 0; j < width; j++)
				fb16[j] = (uint16_t)(data & 0xffff);
		}
		break;
	case 24:		/* 24 bit */
		for (i = 0; i < height; i++) {
			fb8 = fb + i * pitch;
			for (j = 0; j < pitch; j += 3) {
				fb8[j] = (data >> 16) & 0xff;
				fb8[j+1] = (data >> 8) & 0xff;
				fb8[j+2] = data & 0xff;
			}
		}
		break;
	case 32:		/* 32 bit */
		for (i = 0; i < height; i++) {
			fb32 = (uint32_t *)(fb + i * pitch);
			for (j = 0; j < width; j++)
				fb32[j] = data;
		}
		break;
	default:
		return (1);
	}

	return (0);
}

static int
gfx_fb_cons_clear(struct vis_consclear *ca)
{
	uint32_t data, width, height;
	int ret;
#if	defined(EFI)
	EFI_TPL tpl;
#endif

	data = gfx_fb_color_map(ca->bg_color);
	width = gfx_fb.framebuffer_common.framebuffer_width;
	height = gfx_fb.framebuffer_common.framebuffer_height;

#if	defined(EFI)
	tpl = BS->RaiseTPL(TPL_NOTIFY);
#endif
	ret = gfx_fb_ops.gfx_cons_clear(data, width, height);
#if	defined(EFI)
	BS->RestoreTPL(tpl);
#endif
	return (ret);
}

#if	defined(EFI)
static void
gfx_gop_cons_copy(struct vis_conscopy *ma)
{
	UINTN width, height;
	extern EFI_GRAPHICS_OUTPUT *gop;

	width = ma->e_col - ma->s_col + 1;
	height = ma->e_row - ma->s_row + 1;

	(void) gop->Blt(gop, NULL, EfiBltVideoToVideo, ma->s_col, ma->s_row,
	    ma->t_col, ma->t_row, width, height, 0);
}
#endif

static void
gfx_bm_cons_copy(struct vis_conscopy *ma)
{
	uint32_t soffset, toffset;
	uint32_t width, height;
	uint8_t *src, *dst, *fb;
	uint32_t bpp, pitch;

	fb = gfx_get_fb_address();
	bpp = roundup2(gfx_fb.framebuffer_common.framebuffer_bpp, 8) >> 3;
	pitch = gfx_fb.framebuffer_common.framebuffer_pitch;

	soffset = ma->s_col * bpp + ma->s_row * pitch;
	toffset = ma->t_col * bpp + ma->t_row * pitch;
	src = fb + soffset;
	dst = fb + toffset;
	width = (ma->e_col - ma->s_col + 1) * bpp;
	height = ma->e_row - ma->s_row + 1;

	if (toffset <= soffset) {
		for (uint32_t i = 0; i < height; i++) {
			uint32_t increment = i * pitch;
			(void) memmove(dst + increment, src + increment, width);
		}
	} else {
		for (int i = height - 1; i >= 0; i--) {
			uint32_t increment = i * pitch;
			(void) memmove(dst + increment, src + increment, width);
		}
	}
}

static void
gfx_fb_cons_copy(struct vis_conscopy *ma)
{
#if	defined(EFI)
	EFI_TPL tpl;

	tpl = BS->RaiseTPL(TPL_NOTIFY);
#endif

	gfx_fb_ops.gfx_cons_copy(ma);
#if	defined(EFI)
	BS->RestoreTPL(tpl);
#endif
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
		/*
		 * we only implement alpha blending for depth 32,
		 * use memcpy for other cases.
		 */
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

#if	defined(EFI)
static void
gfx_gop_cons_display(struct vis_consdisplay *da)
{
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *BltBuffer;
	uint32_t size;
	int bpp;
	extern EFI_GRAPHICS_OUTPUT *gop;

	bpp = roundup2(gfx_fb.framebuffer_common.framebuffer_bpp, 8) >> 3;
	size = sizeof (*BltBuffer) * da->width * da->height;
	BltBuffer = malloc(size);
	if (BltBuffer == NULL && gfx_get_fb_address() != NULL) {
		/* Fall back to bitmap implementation */
		gfx_bm_cons_display(da);
		return;
	}

	(void) gop->Blt(gop, BltBuffer, EfiBltVideoToBltBuffer,
	    da->col, da->row, 0, 0, da->width, da->height, 0);
	bitmap_cpy((void *)BltBuffer, da->data, size, bpp);
	(void) gop->Blt(gop, BltBuffer, EfiBltBufferToVideo,
	    0, 0, da->col, da->row, da->width, da->height, 0);
	free(BltBuffer);
}
#endif

static void
gfx_bm_cons_display(struct vis_consdisplay *da)
{
	uint32_t size;		/* write size per scanline */
	uint8_t *fbp;		/* fb + calculated offset */
	int i, bpp, pitch;

	bpp = roundup2(gfx_fb.framebuffer_common.framebuffer_bpp, 8) >> 3;
	pitch = gfx_fb.framebuffer_common.framebuffer_pitch;

	size = da->width * bpp;
	fbp = gfx_get_fb_address();
	fbp += da->col * bpp + da->row * pitch;

	/* write all scanlines in rectangle */
	for (i = 0; i < da->height; i++) {
		uint8_t *dest = fbp + i * pitch;
		uint8_t *src = da->data + i * size;
		bitmap_cpy(dest, src, size, bpp);
	}
}

static void
gfx_fb_cons_display(struct vis_consdisplay *da)
{
#if	defined(EFI)
	EFI_TPL tpl;
#endif

	/* make sure we will not write past FB */
	if ((uint32_t)da->col >= gfx_fb.framebuffer_common.framebuffer_width ||
	    (uint32_t)da->row >= gfx_fb.framebuffer_common.framebuffer_height ||
	    (uint32_t)da->col + da->width >
	    gfx_fb.framebuffer_common.framebuffer_width ||
	    (uint32_t)da->row + da->height >
	    gfx_fb.framebuffer_common.framebuffer_height)
		return;

#if	defined(EFI)
	tpl = BS->RaiseTPL(TPL_NOTIFY);
#endif
	gfx_fb_ops.gfx_cons_display(da);
#if	defined(EFI)
	BS->RestoreTPL(tpl);
#endif
}

void
gfx_fb_display_cursor(struct vis_conscursor *ca)
{
	uint32_t fg, bg;
	uint32_t offset, size, *fb32;
	uint16_t *fb16;
	uint8_t *fb8, *fb;
	uint32_t bpp, pitch;
#if	defined(EFI)
	EFI_TPL tpl;
#endif

	fb = gfx_get_fb_address();
	bpp = roundup2(gfx_fb.framebuffer_common.framebuffer_bpp, 8) >> 3;
	pitch = gfx_fb.framebuffer_common.framebuffer_pitch;

	size = ca->width * bpp;

	/*
	 * Build cursor image. We are building mirror image of data on
	 * frame buffer by (D xor FG) xor BG.
	 */
	offset = ca->col * bpp + ca->row * pitch;
#if	defined(EFI)
	tpl = BS->RaiseTPL(TPL_NOTIFY);
#endif
	switch (gfx_fb.framebuffer_common.framebuffer_bpp) {
	case 8:		/* 8 bit */
		fg = ca->fg_color.mono;
		bg = ca->bg_color.mono;
		for (int i = 0; i < ca->height; i++) {
			fb8 = fb + offset + i * pitch;
			for (uint32_t j = 0; j < size; j += 1) {
				fb8[j] = (fb8[j] ^ (fg & 0xff)) ^ (bg & 0xff);
			}
		}
		break;
	case 15:
	case 16:	/* 16 bit */
		fg = ca->fg_color.sixteen[0] << 8;
		fg |= ca->fg_color.sixteen[1];
		bg = ca->bg_color.sixteen[0] << 8;
		bg |= ca->bg_color.sixteen[1];
		for (int i = 0; i < ca->height; i++) {
			fb16 = (uint16_t *)(fb + offset + i * pitch);
			for (int j = 0; j < ca->width; j++) {
				fb16[j] = (fb16[j] ^ (fg & 0xffff)) ^
				    (bg & 0xffff);
			}
		}
		break;
	case 24:	/* 24 bit */
		fg = ca->fg_color.twentyfour[0] << 16;
		fg |= ca->fg_color.twentyfour[1] << 8;
		fg |= ca->fg_color.twentyfour[2];
		bg = ca->bg_color.twentyfour[0] << 16;
		bg |= ca->bg_color.twentyfour[1] << 8;
		bg |= ca->bg_color.twentyfour[2];

		for (int i = 0; i < ca->height; i++) {
			fb8 = fb + offset + i * pitch;
			for (uint32_t j = 0; j < size; j += 3) {
				fb8[j] = (fb8[j] ^ ((fg >> 16) & 0xff)) ^
				    ((bg >> 16) & 0xff);
				fb8[j+1] = (fb8[j+1] ^ ((fg >> 8) & 0xff)) ^
				    ((bg >> 8) & 0xff);
				fb8[j+2] = (fb8[j+2] ^ (fg & 0xff)) ^
				    (bg & 0xff);
			}
		}
		break;
	case 32:	/* 32 bit */
		fg = ca->fg_color.twentyfour[0] << 16;
		fg |= ca->fg_color.twentyfour[1] << 8;
		fg |= ca->fg_color.twentyfour[2];
		bg = ca->bg_color.twentyfour[0] << 16;
		bg |= ca->bg_color.twentyfour[1] << 8;
		bg |= ca->bg_color.twentyfour[2];
		for (int i = 0; i < ca->height; i++) {
			fb32 = (uint32_t *)(fb + offset + i * pitch);
			for (int j = 0; j < ca->width; j++)
				fb32[j] = (fb32[j] ^ fg) ^ bg;
		}
		break;
	}
#if	defined(EFI)
	BS->RestoreTPL(tpl);
#endif
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
	uint32_t c, offset, pitch, bpp;
	uint8_t *fb;
	text_color_t fg, bg;

	if (plat_stdout_is_framebuffer() == 0)
		return;

	tem_get_colors((tem_vt_state_t)tems.ts_active, &fg, &bg);
	c = gfx_fb_color_map(fg);

	if (x >= gfx_fb.framebuffer_common.framebuffer_width ||
	    y >= gfx_fb.framebuffer_common.framebuffer_height)
		return;

	fb = gfx_get_fb_address();
	pitch = gfx_fb.framebuffer_common.framebuffer_pitch;
	bpp = roundup2(gfx_fb.framebuffer_common.framebuffer_bpp, 8) >> 3;

	offset = y * pitch + x * bpp;
	switch (gfx_fb.framebuffer_common.framebuffer_bpp) {
	case 8:
		fb[offset] = c & 0xff;
		break;
	case 15:
	case 16:
		*(uint16_t *)(fb + offset) = c & 0xffff;
		break;
	case 24:
		fb[offset] = (c >> 16) & 0xff;
		fb[offset + 1] = (c >> 8) & 0xff;
		fb[offset + 2] = c & 0xff;
		break;
	case 32:
		*(uint32_t *)(fb + offset) = c;
		break;
	}
}

/*
 * draw rectangle in framebuffer using gfx coordinates.
 * The function is borrowed from fbsd vt_fb.c
 */
void
gfx_fb_drawrect(uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2,
    uint32_t fill)
{
	uint32_t x, y;

	if (plat_stdout_is_framebuffer() == 0)
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
	/* Terminal coordinates start from (1,1) */
	ux1--;
	uy1--;
	ux2--;
	uy2--;

	/* mark area used in tem */
	tem_image_display(tems.ts_active, uy1 - 1, ux1 - 1, uy2, ux2);

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

#define	FL_PUTIMAGE_BORDER	0x1
#define	FL_PUTIMAGE_NOSCROLL	0x2
#define	FL_PUTIMAGE_DEBUG	0x80

int
gfx_fb_putimage(png_t *png, uint32_t ux1, uint32_t uy1, uint32_t ux2,
    uint32_t uy2, uint32_t flags)
{
	struct vis_consdisplay da;
	uint32_t i, j, x, y, fheight, fwidth, color;
	int fbpp;
	uint8_t r, g, b, a, *p;
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
		    da.row / tems.ts_font.vf_height - 1,
		    da.col / tems.ts_font.vf_width - 1,
		    (da.row + da.height) / tems.ts_font.vf_height - 1,
		    (da.col + da.width) / tems.ts_font.vf_width - 1);
	}

	if ((flags & FL_PUTIMAGE_BORDER))
		gfx_fb_drawrect(ux1, uy1, ux2, uy2, 0);

	fbpp = roundup2(gfx_fb.framebuffer_common.framebuffer_bpp, 8) >> 3;

	da.data = malloc(fwidth * fheight * fbpp);
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
			j = (y * fwidth + x) * fbpp;

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
			    r >> (8 - gfx_fb.u.fb2.framebuffer_red_mask_size)
			    << gfx_fb.u.fb2.framebuffer_red_field_position |
			    g >> (8 - gfx_fb.u.fb2.framebuffer_green_mask_size)
			    << gfx_fb.u.fb2.framebuffer_green_field_position |
			    b >> (8 - gfx_fb.u.fb2.framebuffer_blue_mask_size)
			    << gfx_fb.u.fb2.framebuffer_blue_field_position;

			switch (gfx_fb.framebuffer_common.framebuffer_bpp) {
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
				da.data[j] = solaris_color_to_pc_color[color];
				break;
			}
			case 15:
			case 16:
				*(uint16_t *)(da.data+j) = color;
				break;
			case 24:
				p = (uint8_t *)&color;
				da.data[j] = p[0];
				da.data[j+1] = p[1];
				da.data[j+2] = p[2];
				break;
			case 32:
				color |= a << 24;
				*(uint32_t *)(da.data+j) = color;
				break;
			}
			wc += wcstep;
		}
		hc += hcstep;
	}

	gfx_fb_cons_display(&da);
	free(da.data);
	return (0);
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

/* Load font from file. */
static bitmap_data_t *
load_font(char *path)
{
	int fd, i;
	uint32_t glyphs;
	struct font_header fh;
	struct fontlist *fl;
	bitmap_data_t *bp = NULL;
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
	if (bp->font != NULL)
		return (bp);

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

	bp->uncompressed_size = howmany(bp->width, 8) * bp->height * glyphs;
	size = bp->uncompressed_size;
	if ((fp->vf_bytes = malloc(size)) == NULL)
		goto free_done;

	rv = read(fd, fp->vf_bytes, size);
	if (rv < 0 || (size_t)rv != size)
		goto free_done;
	for (i = 0; i < VFNT_MAPS; i++) {
		if (load_mapping(fd, fp, i) != 0)
			goto free_done;
	}
	bp->font = fp;

	/*
	 * Release previously loaded entry. We can do this now, as
	 * the new font is loaded. Note, there can be no console
	 * output till the new font is in place and tem is notified.
	 * We do need to keep fl->font_data for glyph dimensions.
	 */
	STAILQ_FOREACH(fl, &fonts, font_next) {
		if (fl->font_data->width == bp->width &&
		    fl->font_data->height == bp->height)
			continue;

		if (fl->font_data->font != NULL) {
			for (i = 0; i < VFNT_MAPS; i++)
				free(fl->font_data->font->vf_map[i]);

			/* Unset vf_bytes pointer in tem. */
			if (tems.ts_font.vf_bytes ==
			    fl->font_data->font->vf_bytes) {
				tems.ts_font.vf_bytes = NULL;
			}
			free(fl->font_data->font->vf_bytes);
			free(fl->font_data->font);
			fl->font_data->font = NULL;
			fl->font_data->uncompressed_size = 0;
			fl->font_flags = FONT_AUTO;
		}
	}

	/* free the uncompressed builtin font data in tem. */
	free(tems.ts_font.vf_bytes);
	tems.ts_font.vf_bytes = NULL;

done:
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
insert_font(char *name)
{
	struct font_header fh;
	struct fontlist *fp, *previous, *entry, *next;
	size_t size;
	ssize_t rv;
	int fd;
	char *font_name;

	fd = open(name, O_RDONLY);
	if (fd < 0)
		return (false);
	rv = read(fd, &fh, sizeof (fh));
	close(fd);
	if (rv < 0 || (size_t)rv != sizeof (fh))
		return (false);

	if (memcmp(fh.fh_magic, FONT_HEADER_MAGIC, sizeof (fh.fh_magic)) != 0)
		return (false);

	font_name = strdup(name);
	if (font_name == NULL)
		return (false);

	/*
	 * If we have an entry with the same glyph dimensions, just replace
	 * the file name. We only support unique dimensions.
	 */
	STAILQ_FOREACH(entry, &fonts, font_next) {
		if (fh.fh_width == entry->font_data->width &&
		    fh.fh_height == entry->font_data->height) {
			free(entry->font_name);
			entry->font_name = font_name;
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
	fp->font_flags = FONT_AUTO;
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
		if (size >
		    entry->font_data->width * entry->font_data->height) {
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
autoload_font(void)
{
	struct name_list *nl;
	struct name_entry *np;

	nl = read_list("/boot/fonts/fonts.dir");
	if (nl == NULL)
		return;

	while (!SLIST_EMPTY(nl)) {
		np = SLIST_FIRST(nl);
		SLIST_REMOVE_HEAD(nl, n_entry);
		if (insert_font(np->n_name) == false)
			printf("failed to add font: %s\n", np->n_name);
		free(np->n_name);
		free(np);
	}

	unsetenv("screen-font");
	env_setenv("screen-font", EV_VOLATILE, NULL, font_set, env_nounset);
	/* Trigger tem update. */
	tems.update_font = true;
	plat_cons_update_mode(-1);
}

COMMAND_SET(load_font, "loadfont", "load console font from file", command_font);

static int
command_font(int argc, char *argv[])
{
	int i, rc = CMD_OK;
	struct fontlist *fl;
	bitmap_data_t *bd;

	if (argc > 2) {
		printf("Usage: loadfont [file.fnt]\n");
		return (CMD_ERROR);
	}

	if (argc == 2) {
		char *name = argv[1];

		if (insert_font(name) == false) {
			printf("loadfont error: failed to load: %s\n", name);
			return (CMD_ERROR);
		}

		bd = load_font(name);
		if (bd == NULL) {
			printf("loadfont error: failed to load: %s\n", name);
			return (CMD_ERROR);
		}

		/* Get the font list entry and mark it manually loaded. */
		STAILQ_FOREACH(fl, &fonts, font_next) {
			if (strcmp(fl->font_name, name) == 0)
				fl->font_flags = FONT_MANUAL;
		}
		tems.update_font = true;
		plat_cons_update_mode(-1);
		return (CMD_OK);
	}

	if (argc == 1) {
		/*
		 * Walk entire font list, release any loaded font, and set
		 * autoload flag. If the font list is empty, the tem will
		 * get the builtin default.
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
