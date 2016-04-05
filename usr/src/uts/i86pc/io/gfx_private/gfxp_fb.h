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

#include <sys/framebuffer.h>
#include <sys/vgareg.h>
#include <sys/vgasubr.h>
#include <sys/gfx_private.h>

#define	GFXP_FLAG_CONSOLE	0x00000001
#define	GFXP_IS_CONSOLE(softc)	((softc)->flags & GFXP_FLAG_CONSOLE)

typedef struct {
	uint8_t red[16];
	uint8_t green[16];
	uint8_t blue[16];
} text_cmap_t;

extern text_cmap_t cmap_rgb16;

struct gfxp_fb_softc;

struct gfxp_ops {
	const struct vis_identifier *ident;
	int (*kdsetmode)(struct gfxp_fb_softc *softc, int mode);
	int (*devinit)(struct gfxp_fb_softc *, struct vis_devinit *data);
	void (*cons_copy)(struct gfxp_fb_softc *, struct vis_conscopy *);
	void (*cons_display)(struct gfxp_fb_softc *, struct vis_consdisplay *);
	void (*cons_cursor)(struct gfxp_fb_softc *, struct vis_conscursor *);
	int (*cons_clear)(struct gfxp_fb_softc *, struct vis_consclear *);
	int (*suspend)(struct gfxp_fb_softc *softc);
	void (*resume)(struct gfxp_fb_softc *softc);
	int (*devmap)(dev_t, devmap_cookie_t, offset_t, size_t, size_t *,
	    uint_t, void *);
};

struct vgareg {
	unsigned char vga_misc;			/* Misc out reg */
	unsigned char vga_crtc[NUM_CRTC_REG];	/* Crtc controller */
	unsigned char vga_seq[NUM_SEQ_REG];	/* Video Sequencer */
	unsigned char vga_grc[NUM_GRC_REG];	/* Video Graphics */
	unsigned char vga_atr[NUM_ATR_REG];	/* Video Atribute */
};

struct gfx_vga {
	struct vgaregmap regs;
	struct vgaregmap fb;
	off_t fb_size;
	int fb_regno;
	caddr_t	 text_base;	/* hardware text base */
	char shadow[VGA_TEXT_ROWS * VGA_TEXT_COLS * 2];
	caddr_t current_base;	/* hardware or shadow */
	char vga_fontslot;
	struct vgareg vga_reg;
	struct {
		boolean_t visible;
		int row;
		int col;
	} cursor;
	struct {
		unsigned char red;
		unsigned char green;
		unsigned char blue;
	} colormap[VGA8_CMAP_ENTRIES];
	unsigned char attrib_palette[VGA_ATR_NUM_PLT];
};

union gfx_console {
	struct fb_info fb;
	struct gfx_vga vga;
};

struct gfxp_fb_softc {
	dev_info_t		*devi;
	int mode;		/* KD_TEXT or KD_GRAPHICS */
	enum gfxp_type		fb_type;
	unsigned int		flags;
	kmutex_t		lock;
	char			silent;
	char			happyface_boot;
	struct vis_polledio	polledio;
	struct gfxp_ops		*gfxp_ops;
	struct gfxp_blt_ops	blt_ops;
	struct fbgattr		*fbgattr;
	union gfx_console	*console;
};

/* function definitions */
int gfxp_bm_attach(dev_info_t *, struct gfxp_fb_softc *);
int gfxp_bm_detach(dev_info_t *, struct gfxp_fb_softc *);

int gfxp_vga_attach(dev_info_t *, struct gfxp_fb_softc *);
int gfxp_vga_detach(dev_info_t *, struct gfxp_fb_softc *);

#ifdef __cplusplus
}
#endif

#endif /* _GFXP_FB_H */
