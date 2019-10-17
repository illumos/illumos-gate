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
 * Copyright 2019 Toomas Soome <tsoome@me.com>
 */

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/tem_impl.h>
#include <pnglite.h>
#include "bootstrap.h"

font_list_t fonts;
tem_state_t tems;

void
gfx_term_drawrect(uint32_t ux1, uint32_t uy1, uint32_t ux2, uint32_t uy2)
{
}

void
gfx_fb_setpixel(uint32_t x, uint32_t y)
{
}

int
gfx_fb_putimage(png_t *png, uint32_t ux1, uint32_t uy1, uint32_t ux2,
    uint32_t uy2, uint32_t flags)
{
	return (1);
}

void
gfx_fb_drawrect(uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2,
    uint32_t fill)
{
}

void
gfx_fb_line(uint32_t x0, uint32_t y0, uint32_t x1, uint32_t y1, uint32_t wd)
{
}

void
gfx_fb_bezier(uint32_t x0, uint32_t y0, uint32_t x1, uint32_t y1, uint32_t x2,
    uint32_t y2, uint32_t wd)
{
}

int
png_open(png_t *png, const char *filename)
{
	return (PNG_NOT_SUPPORTED);
}

int
png_close(png_t *png)
{
	return (PNG_NOT_SUPPORTED);
}

char *
png_error_string(int error)
{
	return ("Unknown error.");
}

void
tem_save_state(void)
{
}

COMMAND_SET(framebuffer, "framebuffer", "framebuffer mode management",
    command_fb);

static int
command_fb(int argc, char *argv[])
{
	return (CMD_OK);
}
