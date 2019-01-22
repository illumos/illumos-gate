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
 * Generic framebuffer interface. Implementing common interfaces
 * for bitmapped frame buffer and vgatext.
 */
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/visual_io.h>
#include <sys/vgareg.h>
#include <sys/vgasubr.h>

#include <sys/gfx_private.h>
#include "gfxp_fb.h"

/* need to keep vgatext symbols for compatibility */
#pragma weak gfxp_vgatext_softc_alloc = gfxp_fb_softc_alloc
#pragma weak gfxp_vgatext_softc_free = gfxp_fb_softc_free
#pragma weak gfxp_vgatext_attach = gfxp_fb_attach
#pragma weak gfxp_vgatext_detach = gfxp_fb_detach
#pragma weak gfxp_vgatext_open = gfxp_fb_open
#pragma weak gfxp_vgatext_close = gfxp_fb_close
#pragma weak gfxp_vgatext_ioctl = gfxp_fb_ioctl
#pragma weak gfxp_vgatext_devmap = gfxp_fb_devmap

gfxp_fb_softc_ptr_t
gfxp_fb_softc_alloc(void)
{
	return (kmem_zalloc(sizeof (struct gfxp_fb_softc), KM_SLEEP));
}

void
gfxp_fb_softc_free(gfxp_fb_softc_ptr_t ptr)
{
	kmem_free(ptr, sizeof (struct gfxp_fb_softc));
}

int
gfxp_fb_attach(dev_info_t *devi, ddi_attach_cmd_t cmd, gfxp_fb_softc_ptr_t ptr)
{
	return (gfxp_vga_attach(devi, cmd, ptr));
}

int
gfxp_fb_detach(dev_info_t *devi, ddi_detach_cmd_t cmd, gfxp_fb_softc_ptr_t ptr)
{
	return (gfxp_vga_detach(devi, cmd, ptr));
}

/*ARGSUSED*/
int
gfxp_fb_open(dev_t *devp, int flag, int otyp, cred_t *cred,
    gfxp_fb_softc_ptr_t ptr)
{
	struct gfxp_fb_softc *softc = (struct gfxp_fb_softc *)ptr;

	if (softc == NULL || otyp == OTYP_BLK)
		return (ENXIO);

	return (0);
}

/*ARGSUSED*/
int
gfxp_fb_close(dev_t devp, int flag, int otyp, cred_t *cred,
    gfxp_fb_softc_ptr_t ptr)
{
	return (0);
}

int
gfxp_fb_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *cred, int *rval, gfxp_fb_softc_ptr_t ptr)
{
	return (gfxp_vga_ioctl(dev, cmd, data, mode, cred, rval, ptr));
}

int
gfxp_fb_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off,
    size_t len, size_t *maplen, uint_t model, void *ptr)
{
	return (gfxp_vga_devmap(dev, dhp, off, len, maplen, model, ptr));
}
