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

#ifndef _GFXP_FB_H
#define	_GFXP_FB_H

/*
 * gfxp_fb interfaces.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	TEXT_ROWS		25
#define	TEXT_COLS		80

struct gfxp_fb_softc {
	struct vgaregmap	regs;
	struct vgaregmap	fb;
	off_t			fb_size;
	int			fb_regno;
	dev_info_t		*devi;
	int			mode;	/* KD_TEXT or KD_GRAPHICS */
	caddr_t			text_base;	/* hardware text base */
	char			shadow[TEXT_ROWS*TEXT_COLS*2];
	caddr_t			current_base;	/* hardware or shadow */
	struct {
		boolean_t visible;
		int row;
		int col;
	}			cursor;
	struct vis_polledio	polledio;
	struct {
		unsigned char red;
		unsigned char green;
		unsigned char blue;
	}			colormap[VGA8_CMAP_ENTRIES];
	unsigned char attrib_palette[VGA_ATR_NUM_PLT];
	unsigned int flags;
	kmutex_t lock;
};

/* function definitions */
int gfxp_vga_attach(dev_info_t *, ddi_attach_cmd_t, gfxp_fb_softc_ptr_t);
int gfxp_vga_detach(dev_info_t *, ddi_detach_cmd_t, gfxp_fb_softc_ptr_t);
int gfxp_vga_ioctl(dev_t, int, intptr_t, int, cred_t *, int *,
    gfxp_fb_softc_ptr_t);
int gfxp_vga_devmap(dev_t, devmap_cookie_t, offset_t, size_t, size_t *,
    uint_t, void *);

#ifdef __cplusplus
}
#endif

#endif /* _GFXP_FB_H */
