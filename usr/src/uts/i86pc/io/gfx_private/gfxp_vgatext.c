/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*		All Rights Reserved	*/

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/visual_io.h>
#include <sys/font.h>
#include <sys/fbio.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/open.h>
#include <sys/modctl.h>
#include <sys/pci.h>
#include <sys/kd.h>
#include <sys/ddi_impldefs.h>
#include <sys/gfx_private.h>
#include <sys/vgareg.h>
#include "gfxp_fb.h"

#define	MYNAME	"gfxp_vgatext"

static ddi_device_acc_attr_t dev_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
};

/* default structure for FBIOGATTR ioctl */
static struct fbgattr vgatext_attr =  {
/*	real_type	owner */
	FBTYPE_SUNFAST_COLOR, 0,
/* fbtype: type		h  w  depth cms  size */
	{ FBTYPE_SUNFAST_COLOR, VGA_TEXT_ROWS, VGA_TEXT_COLS, 1,    256,  0 },
/* fbsattr: flags emu_type	dev_specific */
	{ 0, FBTYPE_SUN4COLOR, { 0 } },
/*	emu_types */
	{ -1 }
};

static struct vis_identifier gfxp_vgatext_ident = { "illumos_text" };

static int vgatext_devinit(struct gfxp_fb_softc *, struct vis_devinit *data);
static void	vgatext_cons_copy(struct gfxp_fb_softc *,
			struct vis_conscopy *);
static void	vgatext_cons_display(struct gfxp_fb_softc *,
			struct vis_consdisplay *);
static int	vgatext_cons_clear(struct gfxp_fb_softc *,
			struct vis_consclear *);
static void	vgatext_cons_cursor(struct gfxp_fb_softc *,
			struct vis_conscursor *);
static void	vgatext_polled_copy(struct vis_polledio_arg *,
			struct vis_conscopy *);
static void	vgatext_polled_display(struct vis_polledio_arg *,
			struct vis_consdisplay *);
static void	vgatext_polled_cursor(struct vis_polledio_arg *,
			struct vis_conscursor *);
static void	vgatext_init(struct gfxp_fb_softc *);
static void	vgatext_set_text(struct gfxp_fb_softc *);

static void	vgatext_get_text(struct gfxp_fb_softc *softc);
static void	vgatext_save_text(struct gfxp_fb_softc *softc);
static void	vgatext_kdsettext(struct gfxp_fb_softc *softc);
static int	vgatext_suspend(struct gfxp_fb_softc *softc);
static void	vgatext_resume(struct gfxp_fb_softc *softc);
static int	vgatext_devmap(dev_t, devmap_cookie_t, offset_t, size_t,
    size_t *, uint_t, void *);

#if	defined(USE_BORDERS)
static void	vgatext_init_graphics(struct gfxp_fb_softc *);
#endif

static int vgatext_kdsetmode(struct gfxp_fb_softc *softc, int mode);
static void vgatext_setfont(struct gfxp_fb_softc *softc);
static void vgatext_get_cursor(struct gfxp_fb_softc *softc,
    screen_pos_t *row, screen_pos_t *col);
static void vgatext_set_cursor(struct gfxp_fb_softc *softc, int row, int col);
static void vgatext_hide_cursor(struct gfxp_fb_softc *softc);
static void vgatext_save_colormap(struct gfxp_fb_softc *softc);
static void vgatext_restore_colormap(struct gfxp_fb_softc *softc);
static int vgatext_get_pci_reg_index(dev_info_t *const devi,
    unsigned long himask, unsigned long hival, unsigned long addr,
		off_t *offset);
static int vgatext_get_isa_reg_index(dev_info_t *const devi,
		unsigned long hival, unsigned long addr, off_t *offset);

static struct gfxp_ops gfxp_vgatext_ops = {
	.ident = &gfxp_vgatext_ident,
	.kdsetmode = vgatext_kdsetmode,
	.devinit = vgatext_devinit,
	.cons_copy = vgatext_cons_copy,
	.cons_display = vgatext_cons_display,
	.cons_cursor = vgatext_cons_cursor,
	.cons_clear = vgatext_cons_clear,
	.suspend = vgatext_suspend,
	.resume = vgatext_resume,
	.devmap = vgatext_devmap
};

#define	STREQ(a, b)	(strcmp((a), (b)) == 0)

int
gfxp_vga_attach(dev_info_t *devi, struct gfxp_fb_softc *softc)
{
	int	unit = ddi_get_instance(devi);
	int	error;
	char	*parent_type = NULL;
	int	reg_rnumber;
	off_t	reg_offset;
	off_t	mem_offset;
	char	*cons;
	struct gfx_vga *vga;


	softc->polledio.display = vgatext_polled_display;
	softc->polledio.copy = vgatext_polled_copy;
	softc->polledio.cursor = vgatext_polled_cursor;
	softc->gfxp_ops = &gfxp_vgatext_ops;
	softc->fbgattr = &vgatext_attr;
	vga = kmem_zalloc(sizeof (*vga), KM_SLEEP);
	softc->console = (union gfx_console *)vga;

	error = ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_get_parent(devi),
	    DDI_PROP_DONTPASS, "device_type", &parent_type);
	if (error != DDI_SUCCESS) {
		cmn_err(CE_WARN, MYNAME ": can't determine parent type.");
		goto fail;
	}

	/* Not enable AGP and DRM by default */
	if (STREQ(parent_type, "isa") || STREQ(parent_type, "eisa")) {
		reg_rnumber = vgatext_get_isa_reg_index(devi, 1, VGA_REG_ADDR,
		    &reg_offset);
		if (reg_rnumber < 0) {
			cmn_err(CE_WARN,
			    MYNAME
			    ": can't find reg entry for registers");
			error = DDI_FAILURE;
			goto fail;
		}
		vga->fb_regno = vgatext_get_isa_reg_index(devi, 0,
		    VGA_MEM_ADDR, &mem_offset);
		if (vga->fb_regno < 0) {
			cmn_err(CE_WARN,
			    MYNAME ": can't find reg entry for memory");
			error = DDI_FAILURE;
			goto fail;
		}
	} else if (STREQ(parent_type, "pci") || STREQ(parent_type, "pciex")) {
		reg_rnumber = vgatext_get_pci_reg_index(devi,
		    PCI_REG_ADDR_M|PCI_REG_REL_M,
		    PCI_ADDR_IO|PCI_RELOCAT_B, VGA_REG_ADDR,
		    &reg_offset);
		if (reg_rnumber < 0) {
			cmn_err(CE_WARN,
			    MYNAME ": can't find reg entry for registers");
			error = DDI_FAILURE;
			goto fail;
		}
		vga->fb_regno = vgatext_get_pci_reg_index(devi,
		    PCI_REG_ADDR_M|PCI_REG_REL_M,
		    PCI_ADDR_MEM32|PCI_RELOCAT_B, VGA_MEM_ADDR,
		    &mem_offset);
		if (vga->fb_regno < 0) {
			cmn_err(CE_WARN,
			    MYNAME ": can't find reg entry for memory");
			error = DDI_FAILURE;
			goto fail;
		}
	} else {
		cmn_err(CE_WARN, MYNAME ": unknown parent type \"%s\".",
		    parent_type);
		error = DDI_FAILURE;
		goto fail;
	}
	ddi_prop_free(parent_type);
	parent_type = NULL;

	error = ddi_regs_map_setup(devi, reg_rnumber,
	    (caddr_t *)&vga->regs.addr, reg_offset, VGA_REG_SIZE,
	    &dev_attr, &vga->regs.handle);
	if (error != DDI_SUCCESS)
		goto fail;
	vga->regs.mapped = B_TRUE;

	vga->fb_size = VGA_MEM_SIZE;

	error = ddi_regs_map_setup(devi, vga->fb_regno,
	    (caddr_t *)&vga->fb.addr, mem_offset, vga->fb_size, &dev_attr,
	    &vga->fb.handle);
	if (error != DDI_SUCCESS)
		goto fail;
	vga->fb.mapped = B_TRUE;

	if (ddi_get8(vga->regs.handle,
	    vga->regs.addr + VGA_MISC_R) & VGA_MISC_IOA_SEL)
		vga->text_base = (caddr_t)vga->fb.addr + VGA_COLOR_BASE;
	else
		vga->text_base = (caddr_t)vga->fb.addr + VGA_MONO_BASE;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "console", &cons) == DDI_SUCCESS) {
		if (strcmp(cons, "graphics") == 0) {
			softc->happyface_boot = 1;
			softc->silent = 1;
			vga->current_base = vga->shadow;
		} else {
			vga->current_base = vga->text_base;
		}
		ddi_prop_free(cons);
	} else {
		vga->current_base = vga->text_base;
	}

	/* Set cursor info. */
	vga->cursor.visible = fb_info.cursor.visible;
	vga->cursor.row = fb_info.cursor.pos.y;
	vga->cursor.col = fb_info.cursor.pos.x;

	error = ddi_prop_create(makedevice(DDI_MAJOR_T_UNKNOWN, unit),
	    devi, DDI_PROP_CANSLEEP, DDI_KERNEL_IOCTL, NULL, 0);
	if (error != DDI_SUCCESS)
		goto fail;

	/* only do this if not in graphics mode */
	if ((softc->silent == 0) && (GFXP_IS_CONSOLE(softc))) {
		vgatext_init(softc);
		vgatext_save_colormap(softc);
	}

	return (DDI_SUCCESS);

fail:
	kmem_free(vga, sizeof (*vga));
	if (parent_type != NULL)
		ddi_prop_free(parent_type);
	return (error);
}

int
gfxp_vga_detach(dev_info_t *devi __unused, struct gfxp_fb_softc *softc)
{
	if (softc->console->vga.fb.mapped)
		ddi_regs_map_free(&softc->console->vga.fb.handle);
	if (softc->console->vga.regs.mapped)
		ddi_regs_map_free(&softc->console->vga.regs.handle);
	kmem_free(softc->console, sizeof (struct gfx_vga));
	return (DDI_SUCCESS);
}

/*
 * vgatext_save_text
 * vgatext_suspend
 * vgatext_resume
 *
 *	Routines to save and restore contents of the VGA text area
 * Mostly, this is to support Suspend/Resume operation for graphics
 * device drivers.  Here in the VGAtext common code, we simply squirrel
 * away the contents of the hardware's text area during Suspend and then
 * put it back during Resume
 */
static void
vgatext_save_text(struct gfxp_fb_softc *softc)
{
	union gfx_console *console = softc->console;
	unsigned i;

	for (i = 0; i < sizeof (console->vga.shadow); i++)
		console->vga.shadow[i] = console->vga.current_base[i];
}

static int
vgatext_suspend(struct gfxp_fb_softc *softc)
{
	switch (softc->mode) {
	case KD_TEXT:
		vgatext_save_text(softc);
		break;

	case KD_GRAPHICS:
		break;

	default:
		cmn_err(CE_WARN, MYNAME ": unknown mode in vgatext_suspend.");
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static void
vgatext_resume(struct gfxp_fb_softc *softc)
{

	switch (softc->mode) {
	case KD_TEXT:
		vgatext_kdsettext(softc);
		break;

	case KD_GRAPHICS:

		/*
		 * Upon RESUME, the graphics device will always actually
		 * be in TEXT mode even though the Xorg server did not
		 * make that mode change itself (the suspend code did).
		 * We want first, therefore, to restore textmode
		 * operation fully, and then the Xorg server will
		 * do the rest to restore the device to its
		 * (hi resolution) graphics mode
		 */
		vgatext_kdsettext(softc);
#if	defined(USE_BORDERS)
		vgatext_init_graphics(softc);
#endif
		break;
	default:
		cmn_err(CE_WARN, MYNAME ": unknown mode in vgatext_resume.");
		break;
	}
}

static void
vgatext_progressbar_stop(struct gfxp_fb_softc *softc)
{
	extern void progressbar_stop(void);

	if (softc->silent == 1) {
		softc->silent = 0;
		progressbar_stop();
	}
}

static void
vgatext_kdsettext(struct gfxp_fb_softc *softc)
{
	union gfx_console *console = softc->console;
	int i;

	vgatext_init(softc);
	for (i = 0; i < sizeof (console->vga.shadow); i++) {
		console->vga.text_base[i] = console->vga.shadow[i];
	}
	console->vga.current_base = console->vga.text_base;
	if (console->vga.cursor.visible) {
		vgatext_set_cursor(softc,
		    console->vga.cursor.row,
		    console->vga.cursor.col);
	}
	vgatext_restore_colormap(softc);
}

static void
vgatext_kdsetgraphics(struct gfxp_fb_softc *softc)
{
	vgatext_progressbar_stop(softc);
	vgatext_save_text(softc);
	softc->console->vga.current_base = softc->console->vga.shadow;
	vgatext_get_text(softc);
#if	defined(USE_BORDERS)
	vgatext_init_graphics(softc);
#endif
}

static int
vgatext_kdsetmode(struct gfxp_fb_softc *softc, int mode)
{
	switch (mode) {
	case KD_TEXT:
		if (softc->blt_ops.setmode != NULL)
			if (softc->blt_ops.setmode(KD_TEXT) != 0)
				return (EIO);

		vgatext_kdsettext(softc);
		break;

	case KD_GRAPHICS:
		vgatext_kdsetgraphics(softc);
		if (softc->blt_ops.setmode != NULL)
			if (softc->blt_ops.setmode(KD_GRAPHICS) != 0) {
				vgatext_kdsettext(softc);
				return (EIO);
			}
		break;

	case KD_RESETTEXT:
		/*
		 * In order to avoid racing with a starting X server,
		 * this needs to be a test and set that is performed in
		 * a single (softc->lock protected) ioctl into this driver.
		 */
		if (softc->mode == KD_TEXT && softc->silent == 1) {
			vgatext_progressbar_stop(softc);
			vgatext_kdsettext(softc);
		}
		mode = KD_TEXT;
		break;

	default:
		return (EINVAL);
	}

	softc->mode = mode;
	return (0);
}

/*ARGSUSED*/
static int
vgatext_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off, size_t len,
    size_t *maplen, uint_t model, void *ptr)
{
	struct gfxp_fb_softc *softc = (struct gfxp_fb_softc *)ptr;
	union gfx_console *console;
	int err;
	size_t length;


	if (softc == NULL) {
		cmn_err(CE_WARN, "vgatext: Can't find softstate");
		return (-1);
	}
	console = softc->console;

	if (!(off >= VGA_MEM_ADDR &&
	    off < VGA_MEM_ADDR + console->vga.fb_size)) {
		cmn_err(CE_WARN, "vgatext: Can't map offset 0x%llx", off);
		return (-1);
	}

	if (off + len > VGA_MEM_ADDR + console->vga.fb_size)
		length = VGA_MEM_ADDR + console->vga.fb_size - off;
	else
		length = len;

	if ((err = devmap_devmem_setup(dhp, softc->devi,
	    NULL, console->vga.fb_regno, off - VGA_MEM_ADDR,
	    length, PROT_ALL, 0, &dev_attr)) < 0) {
		return (err);
	}


	*maplen = length;
	return (0);
}


static int
vgatext_devinit(struct gfxp_fb_softc *softc, struct vis_devinit *data)
{
	/* initialize console instance */
	data->version = VIS_CONS_REV;
	data->width = VGA_TEXT_COLS;
	data->height = VGA_TEXT_ROWS;
	data->linebytes = VGA_TEXT_COLS;
	data->color_map = NULL;
	data->depth = 4;
	data->mode = VIS_TEXT;
	data->polledio = &softc->polledio;

	vgatext_save_text(softc);	/* save current console */
	vgatext_hide_cursor(softc);
	return (0);
}

/*
 * Binary searchable table for Unicode to CP437 conversion.
 */
struct unicp437 {
	uint16_t	unicode_base;
	uint8_t		cp437_base;
	uint8_t		length;
};

static const struct unicp437 cp437table[] = {
	{ 0x0020, 0x20, 0x5e }, { 0x00a0, 0x20, 0x00 }, { 0x00a1, 0xad, 0x00 },
	{ 0x00a2, 0x9b, 0x00 }, { 0x00a3, 0x9c, 0x00 }, { 0x00a5, 0x9d, 0x00 },
	{ 0x00a7, 0x15, 0x00 }, { 0x00aa, 0xa6, 0x00 }, { 0x00ab, 0xae, 0x00 },
	{ 0x00ac, 0xaa, 0x00 }, { 0x00b0, 0xf8, 0x00 }, { 0x00b1, 0xf1, 0x00 },
	{ 0x00b2, 0xfd, 0x00 }, { 0x00b5, 0xe6, 0x00 }, { 0x00b6, 0x14, 0x00 },
	{ 0x00b7, 0xfa, 0x00 }, { 0x00ba, 0xa7, 0x00 }, { 0x00bb, 0xaf, 0x00 },
	{ 0x00bc, 0xac, 0x00 }, { 0x00bd, 0xab, 0x00 }, { 0x00bf, 0xa8, 0x00 },
	{ 0x00c4, 0x8e, 0x01 }, { 0x00c6, 0x92, 0x00 }, { 0x00c7, 0x80, 0x00 },
	{ 0x00c9, 0x90, 0x00 }, { 0x00d1, 0xa5, 0x00 }, { 0x00d6, 0x99, 0x00 },
	{ 0x00dc, 0x9a, 0x00 }, { 0x00df, 0xe1, 0x00 }, { 0x00e0, 0x85, 0x00 },
	{ 0x00e1, 0xa0, 0x00 }, { 0x00e2, 0x83, 0x00 }, { 0x00e4, 0x84, 0x00 },
	{ 0x00e5, 0x86, 0x00 }, { 0x00e6, 0x91, 0x00 }, { 0x00e7, 0x87, 0x00 },
	{ 0x00e8, 0x8a, 0x00 }, { 0x00e9, 0x82, 0x00 }, { 0x00ea, 0x88, 0x01 },
	{ 0x00ec, 0x8d, 0x00 }, { 0x00ed, 0xa1, 0x00 }, { 0x00ee, 0x8c, 0x00 },
	{ 0x00ef, 0x8b, 0x00 }, { 0x00f0, 0xeb, 0x00 }, { 0x00f1, 0xa4, 0x00 },
	{ 0x00f2, 0x95, 0x00 }, { 0x00f3, 0xa2, 0x00 }, { 0x00f4, 0x93, 0x00 },
	{ 0x00f6, 0x94, 0x00 }, { 0x00f7, 0xf6, 0x00 }, { 0x00f8, 0xed, 0x00 },
	{ 0x00f9, 0x97, 0x00 }, { 0x00fa, 0xa3, 0x00 }, { 0x00fb, 0x96, 0x00 },
	{ 0x00fc, 0x81, 0x00 }, { 0x00ff, 0x98, 0x00 }, { 0x0192, 0x9f, 0x00 },
	{ 0x0393, 0xe2, 0x00 }, { 0x0398, 0xe9, 0x00 }, { 0x03a3, 0xe4, 0x00 },
	{ 0x03a6, 0xe8, 0x00 }, { 0x03a9, 0xea, 0x00 }, { 0x03b1, 0xe0, 0x01 },
	{ 0x03b4, 0xeb, 0x00 }, { 0x03b5, 0xee, 0x00 }, { 0x03bc, 0xe6, 0x00 },
	{ 0x03c0, 0xe3, 0x00 }, { 0x03c3, 0xe5, 0x00 }, { 0x03c4, 0xe7, 0x00 },
	{ 0x03c6, 0xed, 0x00 }, { 0x03d5, 0xed, 0x00 }, { 0x2010, 0x2d, 0x00 },
	{ 0x2014, 0x2d, 0x00 }, { 0x2018, 0x60, 0x00 }, { 0x2019, 0x27, 0x00 },
	{ 0x201c, 0x22, 0x00 }, { 0x201d, 0x22, 0x00 }, { 0x2022, 0x07, 0x00 },
	{ 0x203c, 0x13, 0x00 }, { 0x207f, 0xfc, 0x00 }, { 0x20a7, 0x9e, 0x00 },
	{ 0x20ac, 0xee, 0x00 }, { 0x2126, 0xea, 0x00 }, { 0x2190, 0x1b, 0x00 },
	{ 0x2191, 0x18, 0x00 }, { 0x2192, 0x1a, 0x00 }, { 0x2193, 0x19, 0x00 },
	{ 0x2194, 0x1d, 0x00 }, { 0x2195, 0x12, 0x00 }, { 0x21a8, 0x17, 0x00 },
	{ 0x2202, 0xeb, 0x00 }, { 0x2208, 0xee, 0x00 }, { 0x2211, 0xe4, 0x00 },
	{ 0x2212, 0x2d, 0x00 }, { 0x2219, 0xf9, 0x00 }, { 0x221a, 0xfb, 0x00 },
	{ 0x221e, 0xec, 0x00 }, { 0x221f, 0x1c, 0x00 }, { 0x2229, 0xef, 0x00 },
	{ 0x2248, 0xf7, 0x00 }, { 0x2261, 0xf0, 0x00 }, { 0x2264, 0xf3, 0x00 },
	{ 0x2265, 0xf2, 0x00 }, { 0x2302, 0x7f, 0x00 }, { 0x2310, 0xa9, 0x00 },
	{ 0x2320, 0xf4, 0x00 }, { 0x2321, 0xf5, 0x00 }, { 0x2500, 0xc4, 0x00 },
	{ 0x2502, 0xb3, 0x00 }, { 0x250c, 0xda, 0x00 }, { 0x2510, 0xbf, 0x00 },
	{ 0x2514, 0xc0, 0x00 }, { 0x2518, 0xd9, 0x00 }, { 0x251c, 0xc3, 0x00 },
	{ 0x2524, 0xb4, 0x00 }, { 0x252c, 0xc2, 0x00 }, { 0x2534, 0xc1, 0x00 },
	{ 0x253c, 0xc5, 0x00 }, { 0x2550, 0xcd, 0x00 }, { 0x2551, 0xba, 0x00 },
	{ 0x2552, 0xd5, 0x00 }, { 0x2553, 0xd6, 0x00 }, { 0x2554, 0xc9, 0x00 },
	{ 0x2555, 0xb8, 0x00 }, { 0x2556, 0xb7, 0x00 }, { 0x2557, 0xbb, 0x00 },
	{ 0x2558, 0xd4, 0x00 }, { 0x2559, 0xd3, 0x00 }, { 0x255a, 0xc8, 0x00 },
	{ 0x255b, 0xbe, 0x00 }, { 0x255c, 0xbd, 0x00 }, { 0x255d, 0xbc, 0x00 },
	{ 0x255e, 0xc6, 0x01 }, { 0x2560, 0xcc, 0x00 }, { 0x2561, 0xb5, 0x00 },
	{ 0x2562, 0xb6, 0x00 }, { 0x2563, 0xb9, 0x00 }, { 0x2564, 0xd1, 0x01 },
	{ 0x2566, 0xcb, 0x00 }, { 0x2567, 0xcf, 0x00 }, { 0x2568, 0xd0, 0x00 },
	{ 0x2569, 0xca, 0x00 }, { 0x256a, 0xd8, 0x00 }, { 0x256b, 0xd7, 0x00 },
	{ 0x256c, 0xce, 0x00 }, { 0x2580, 0xdf, 0x00 }, { 0x2584, 0xdc, 0x00 },
	{ 0x2588, 0xdb, 0x00 }, { 0x258c, 0xdd, 0x00 }, { 0x2590, 0xde, 0x00 },
	{ 0x2591, 0xb0, 0x02 }, { 0x25a0, 0xfe, 0x00 }, { 0x25ac, 0x16, 0x00 },
	{ 0x25b2, 0x1e, 0x00 }, { 0x25ba, 0x10, 0x00 }, { 0x25bc, 0x1f, 0x00 },
	{ 0x25c4, 0x11, 0x00 }, { 0x25cb, 0x09, 0x00 }, { 0x25d8, 0x08, 0x00 },
	{ 0x25d9, 0x0a, 0x00 }, { 0x263a, 0x01, 0x01 }, { 0x263c, 0x0f, 0x00 },
	{ 0x2640, 0x0c, 0x00 }, { 0x2642, 0x0b, 0x00 }, { 0x2660, 0x06, 0x00 },
	{ 0x2663, 0x05, 0x00 }, { 0x2665, 0x03, 0x01 }, { 0x266a, 0x0d, 0x00 },
	{ 0x266c, 0x0e, 0x00 }
};

static uint8_t
vga_get_cp437(uint32_t c)
{
	int min, mid, max;

	min = 0;
	max = (sizeof (cp437table) / sizeof (struct unicp437)) - 1;

	if (c < cp437table[0].unicode_base ||
	    c > cp437table[max].unicode_base + cp437table[max].length)
		return ('?');

	while (max >= min) {
		mid = (min + max) / 2;
		if (c < cp437table[mid].unicode_base)
			max = mid - 1;
		else if (c > cp437table[mid].unicode_base +
		    cp437table[mid].length)
			min = mid + 1;
		else
			return (c - cp437table[mid].unicode_base +
			    cp437table[mid].cp437_base);
	}

	return ('?');
}

/*
 * display a string on the screen at (row, col)
 *	 assume it has been cropped to fit.
 */
static void
vgatext_cons_display(struct gfxp_fb_softc *softc, struct vis_consdisplay *da)
{
	uint32_t *string;
	int	i;
	unsigned char	attr;
	struct cgatext {
		unsigned char ch;
		unsigned char attr;
	};
	struct cgatext *addr;

	/*
	 * Sanity checks.  This is a last-ditch effort to avoid damage
	 * from brokenness or maliciousness above.
	 */
	if (da->row < 0 || da->row >= VGA_TEXT_ROWS ||
	    da->col < 0 || da->col >= VGA_TEXT_COLS ||
	    da->col + da->width > VGA_TEXT_COLS)
		return;

	/*
	 * To be fully general, we should copyin the data.  This is not
	 * really relevant for this text-only driver, but a graphical driver
	 * should support these ioctls from userland to enable simple
	 * system startup graphics.
	 */
	attr = (solaris_color_to_pc_color[da->bg_color & 0xf] << 4)
	    | solaris_color_to_pc_color[da->fg_color & 0xf];
	string = (uint32_t *)da->data;
	addr = (struct cgatext *)softc->console->vga.current_base
	    +  (da->row * VGA_TEXT_COLS + da->col);
	for (i = 0; i < da->width; i++) {
		addr[i].ch = vga_get_cp437(string[i]);
		addr[i].attr = attr;
	}
}

static void
vgatext_polled_display(
	struct vis_polledio_arg *arg,
	struct vis_consdisplay *da)
{
	vgatext_cons_display((struct gfxp_fb_softc *)arg, da);
}

/*
 * screen-to-screen copy
 */

static void
vgatext_cons_copy(struct gfxp_fb_softc *softc, struct vis_conscopy *ma)
{
	unsigned short	*from;
	unsigned short	*to;
	int		cnt;
	screen_size_t chars_per_row;
	unsigned short	*to_row_start;
	unsigned short	*from_row_start;
	screen_size_t	rows_to_move;
	unsigned short	*base;

	/*
	 * Sanity checks.  Note that this is a last-ditch effort to avoid
	 * damage caused by broken-ness or maliciousness above.
	 */
	if (ma->s_col < 0 || ma->s_col >= VGA_TEXT_COLS ||
	    ma->s_row < 0 || ma->s_row >= VGA_TEXT_ROWS ||
	    ma->e_col < 0 || ma->e_col >= VGA_TEXT_COLS ||
	    ma->e_row < 0 || ma->e_row >= VGA_TEXT_ROWS ||
	    ma->t_col < 0 || ma->t_col >= VGA_TEXT_COLS ||
	    ma->t_row < 0 || ma->t_row >= VGA_TEXT_ROWS ||
	    ma->s_col > ma->e_col ||
	    ma->s_row > ma->e_row)
		return;

	/*
	 * Remember we're going to copy shorts because each
	 * character/attribute pair is 16 bits.
	 */
	chars_per_row = ma->e_col - ma->s_col + 1;
	rows_to_move = ma->e_row - ma->s_row + 1;

	/* More sanity checks. */
	if (ma->t_row + rows_to_move > VGA_TEXT_ROWS ||
	    ma->t_col + chars_per_row > VGA_TEXT_COLS)
		return;

	base = (unsigned short *)softc->console->vga.current_base;

	to_row_start = base + ((ma->t_row * VGA_TEXT_COLS) + ma->t_col);
	from_row_start = base + ((ma->s_row * VGA_TEXT_COLS) + ma->s_col);

	if (to_row_start < from_row_start) {
		while (rows_to_move-- > 0) {
			to = to_row_start;
			from = from_row_start;
			to_row_start += VGA_TEXT_COLS;
			from_row_start += VGA_TEXT_COLS;
			for (cnt = chars_per_row; cnt-- > 0; )
				*to++ = *from++;
		}
	} else {
		/*
		 * Offset to the end of the region and copy backwards.
		 */
		cnt = rows_to_move * VGA_TEXT_COLS + chars_per_row;
		to_row_start += cnt;
		from_row_start += cnt;

		while (rows_to_move-- > 0) {
			to_row_start -= VGA_TEXT_COLS;
			from_row_start -= VGA_TEXT_COLS;
			to = to_row_start;
			from = from_row_start;
			for (cnt = chars_per_row; cnt-- > 0; )
				*--to = *--from;
		}
	}
}

static void
vgatext_polled_copy(
	struct vis_polledio_arg *arg,
	struct vis_conscopy *ca)
{
	vgatext_cons_copy((struct gfxp_fb_softc *)arg, ca);
}

/*ARGSUSED*/
static int
vgatext_cons_clear(struct gfxp_fb_softc *softc, struct vis_consclear *ca)
{
	uint16_t val, fg, *base;
	int i;

	if (ca->bg_color == 0)		/* bright white */
		fg = 1;			/* black */
	else
		fg = 8;

	val = (solaris_color_to_pc_color[ca->bg_color & 0xf] << 4) |
	    solaris_color_to_pc_color[fg];
	val = (val << 8) | ' ';

	base = (uint16_t *)softc->console->vga.current_base;
	for (i = 0; i < VGA_TEXT_ROWS * VGA_TEXT_COLS; i++)
		base[i] = val;

	return (0);
}

static void
vgatext_cons_cursor(struct gfxp_fb_softc *softc, struct vis_conscursor *ca)
{
	if (softc->silent)
		return;

	switch (ca->action) {
	case VIS_HIDE_CURSOR:
		softc->console->vga.cursor.visible = B_FALSE;
		if (softc->console->vga.current_base ==
		    softc->console->vga.text_base)
			vgatext_hide_cursor(softc);
		break;
	case VIS_DISPLAY_CURSOR:
		/*
		 * Sanity check.  This is a last-ditch effort to avoid
		 * damage from brokenness or maliciousness above.
		 */
		if (ca->col < 0 || ca->col >= VGA_TEXT_COLS ||
		    ca->row < 0 || ca->row >= VGA_TEXT_ROWS)
			return;

		softc->console->vga.cursor.visible = B_TRUE;
		softc->console->vga.cursor.col = ca->col;
		softc->console->vga.cursor.row = ca->row;
		if (softc->console->vga.current_base ==
		    softc->console->vga.text_base)
			vgatext_set_cursor(softc, ca->row, ca->col);
		break;
	case VIS_GET_CURSOR:
		if (softc->console->vga.current_base ==
		    softc->console->vga.text_base) {
			vgatext_get_cursor(softc, &ca->row, &ca->col);
		}
		break;
	}
}

static void
vgatext_polled_cursor(
	struct vis_polledio_arg *arg,
	struct vis_conscursor *ca)
{
	vgatext_cons_cursor((struct gfxp_fb_softc *)arg, ca);
}

static void
vgatext_hide_cursor(struct gfxp_fb_softc *softc)
{
	union gfx_console *console = softc->console;
	uint8_t msl, s;

	if (softc->silent)
		return;

	msl = vga_get_crtc(&console->vga.regs, VGA_CRTC_MAX_S_LN) & 0x1f;
	s = vga_get_crtc(&console->vga.regs, VGA_CRTC_CSSL) & 0xc0;
	s |= (1 << 5);

	/* disable cursor */
	vga_set_crtc(&console->vga.regs, VGA_CRTC_CSSL, s);
	vga_set_crtc(&console->vga.regs, VGA_CRTC_CESL, msl);
}

static void
vgatext_set_cursor(struct gfxp_fb_softc *softc, int row, int col)
{
	union gfx_console *console = softc->console;
	short	addr;
	uint8_t msl, s;

	if (softc->silent)
		return;

	msl = vga_get_crtc(&console->vga.regs, VGA_CRTC_MAX_S_LN) & 0x1f;
	s = vga_get_crtc(&console->vga.regs, VGA_CRTC_CSSL) & 0xc0;

	addr = row * VGA_TEXT_COLS + col;

	vga_set_crtc(&console->vga.regs, VGA_CRTC_CLAH, addr >> 8);
	vga_set_crtc(&console->vga.regs, VGA_CRTC_CLAL, addr & 0xff);

	/* enable cursor */
	vga_set_crtc(&console->vga.regs, VGA_CRTC_CSSL, s);
	vga_set_crtc(&console->vga.regs, VGA_CRTC_CESL, msl);
}

static void
vgatext_get_cursor(struct gfxp_fb_softc *softc,
    screen_pos_t *row, screen_pos_t *col)
{
	union gfx_console *console = softc->console;
	short   addr;

	addr = (vga_get_crtc(&console->vga.regs, VGA_CRTC_CLAH) << 8) +
	    vga_get_crtc(&console->vga.regs, VGA_CRTC_CLAL);

	*row = addr / VGA_TEXT_COLS;
	*col = addr % VGA_TEXT_COLS;
}

static void
vgatext_get_text(struct gfxp_fb_softc *softc)
{
	union gfx_console *console = softc->console;
	struct vgareg *vga_reg;
	struct vgaregmap *regs;
	int i;

	regs = &console->vga.regs;
	vga_reg = &console->vga.vga_reg;

	vga_reg->vga_misc = vga_get_reg(regs, VGA_MISC_R);

	/* get crt controller registers */
	for (i = 0; i < NUM_CRTC_REG; i++) {
		vga_reg->vga_crtc[i] = vga_get_crtc(regs, i);
	}

	/* get attribute registers */
	for (i = 0; i < NUM_ATR_REG; i++) {
		vga_reg->vga_atr[i] = vga_get_atr(regs, i);
	}

	/* get graphics controller registers */
	for (i = 0; i < NUM_GRC_REG; i++) {
		vga_reg->vga_grc[i] = vga_get_grc(regs, i);
	}

	/* get sequencer registers */
	for (i = 1; i < NUM_SEQ_REG; i++) {
		vga_reg->vga_seq[i] = vga_get_seq(regs, i);
	}
}

/*
 * This code is experimental. It's only enabled if console is
 * set to graphics, a preliminary implementation of happyface boot.
 */
static void
vgatext_set_text(struct gfxp_fb_softc *softc)
{
	union gfx_console *console = softc->console;
	struct vgareg *vga_reg;
	struct vgaregmap *regs;
	int i;

	regs = &console->vga.regs;
	vga_reg = &console->vga.vga_reg;

	vgatext_get_text(softc);

	/*
	 * Set output register bits for text mode.
	 * Make sure the VGA adapter is not in monochrome emulation mode.
	 */
	vga_set_reg(regs, VGA_MISC_W, VGA_MISC_HSP | VGA_MISC_PGSL |
	    VGA_MISC_VCLK1 | VGA_MISC_ENB_RAM | VGA_MISC_IOA_SEL);

	/* set sequencer registers */
	vga_set_seq(regs, VGA_SEQ_RST_SYN,
	    (vga_get_seq(regs, VGA_SEQ_RST_SYN) &
	    ~VGA_SEQ_RST_SYN_NO_SYNC_RESET));
	for (i = 1; i < NUM_SEQ_REG; i++) {
		vga_set_seq(regs, i, VGA_SEQ_TEXT[i]);
	}
	vga_set_seq(regs, VGA_SEQ_RST_SYN,
	    (vga_get_seq(regs, VGA_SEQ_RST_SYN) |
	    VGA_SEQ_RST_SYN_NO_ASYNC_RESET |
	    VGA_SEQ_RST_SYN_NO_SYNC_RESET));

	/* set crt controller registers */
	vga_set_crtc(regs, VGA_CRTC_VRE,
	    (vga_reg->vga_crtc[VGA_CRTC_VRE] & ~VGA_CRTC_VRE_LOCK));
	for (i = 0; i < NUM_CRTC_REG; i++) {
		vga_set_crtc(regs, i, VGA_CRTC_TEXT[i]);
	}

	/* set graphics controller registers */
	for (i = 0; i < NUM_GRC_REG; i++) {
		vga_set_grc(regs, i, VGA_GRC_TEXT[i]);
	}

	/* set attribute registers */
	for (i = 0; i < NUM_ATR_REG; i++) {
		vga_set_atr(regs, i, VGA_ATR_TEXT[i]);
	}

	/* set palette */
	for (i = 0; i < VGA_TEXT_CMAP_ENTRIES; i++) {
		vga_put_cmap(regs, i,
		    VGA_TEXT_PALETTES[i][0] << 2,
		    VGA_TEXT_PALETTES[i][1] << 2,
		    VGA_TEXT_PALETTES[i][2] << 2);
	}
	for (i = VGA_TEXT_CMAP_ENTRIES; i < VGA8_CMAP_ENTRIES; i++) {
		vga_put_cmap(regs, i, 0, 0, 0);
	}
}

static void
vgatext_init(struct gfxp_fb_softc *softc)
{
	union gfx_console *console = softc->console;
	unsigned char atr_mode;

	atr_mode = vga_get_atr(&console->vga.regs, VGA_ATR_MODE);
	if (atr_mode & VGA_ATR_MODE_GRAPH)
		vgatext_set_text(softc);
	atr_mode = vga_get_atr(&console->vga.regs, VGA_ATR_MODE);
	atr_mode &= ~VGA_ATR_MODE_BLINK;
	atr_mode &= ~VGA_ATR_MODE_9WIDE;
	vga_set_atr(&console->vga.regs, VGA_ATR_MODE, atr_mode);
#if	defined(USE_BORDERS)
	vga_set_atr(&console->vga.regs, VGA_ATR_BDR_CLR,
	    vga_get_atr(&console->vga.regs, pc_brt_white));
#else
	vga_set_atr(&console->vga.regs, VGA_ATR_BDR_CLR,
	    vga_get_atr(&console->vga.regs, pc_black));
#endif
	vgatext_setfont(softc);	/* need selectable font? */
}

#if	defined(USE_BORDERS)
static void
vgatext_init_graphics(struct gfxp_fb_softc *softc)
{
	vga_set_atr(&softc->console->vga.regs, VGA_ATR_BDR_CLR,
	    vga_get_atr(&softc->console->vga.regs, pc_black));
}
#endif

/*
 * Binary searchable table for CP437 to Unicode conversion.
 */
struct cp437uni {
	uint8_t		cp437_base;
	uint16_t	unicode_base;
	uint8_t		length;
};

static const struct cp437uni cp437unitable[] = {
	{   0, 0x0000, 0 }, {   1, 0x263A, 1 }, {   3, 0x2665, 1 },
	{   5, 0x2663, 0 }, {   6, 0x2660, 0 }, {   7, 0x2022, 0 },
	{   8, 0x25D8, 0 }, {   9, 0x25CB, 0 }, {  10, 0x25D9, 0 },
	{  11, 0x2642, 0 }, {  12, 0x2640, 0 }, {  13, 0x266A, 1 },
	{  15, 0x263C, 0 }, {  16, 0x25BA, 0 }, {  17, 0x25C4, 0 },
	{  18, 0x2195, 0 }, {  19, 0x203C, 0 }, {  20, 0x00B6, 0 },
	{  21, 0x00A7, 0 }, {  22, 0x25AC, 0 }, {  23, 0x21A8, 0 },
	{  24, 0x2191, 0 }, {  25, 0x2193, 0 }, {  26, 0x2192, 0 },
	{  27, 0x2190, 0 }, {  28, 0x221F, 0 }, {  29, 0x2194, 0 },
	{  30, 0x25B2, 0 }, {  31, 0x25BC, 0 }, {  32, 0x0020, 0x5e },
	{ 127, 0x2302, 0 }, { 128, 0x00C7, 0 }, { 129, 0x00FC, 0 },
	{ 130, 0x00E9, 0 }, { 131, 0x00E2, 0 }, { 132, 0x00E4, 0 },
	{ 133, 0x00E0, 0 }, { 134, 0x00E5, 0 }, { 135, 0x00E7, 0 },
	{ 136, 0x00EA, 1 }, { 138, 0x00E8, 0 }, { 139, 0x00EF, 0 },
	{ 140, 0x00EE, 0 }, { 141, 0x00EC, 0 }, { 142, 0x00C4, 1 },
	{ 144, 0x00C9, 0 }, { 145, 0x00E6, 0 }, { 146, 0x00C6, 0 },
	{ 147, 0x00F4, 0 }, { 148, 0x00F6, 0 }, { 149, 0x00F2, 0 },
	{ 150, 0x00FB, 0 }, { 151, 0x00F9, 0 }, { 152, 0x00FF, 0 },
	{ 153, 0x00D6, 0 }, { 154, 0x00DC, 0 }, { 155, 0x00A2, 1 },
	{ 157, 0x00A5, 0 }, { 158, 0x20A7, 0 }, { 159, 0x0192, 0 },
	{ 160, 0x00E1, 0 }, { 161, 0x00ED, 0 }, { 162, 0x00F3, 0 },
	{ 163, 0x00FA, 0 }, { 164, 0x00F1, 0 }, { 165, 0x00D1, 0 },
	{ 166, 0x00AA, 0 }, { 167, 0x00BA, 0 }, { 168, 0x00BF, 0 },
	{ 169, 0x2310, 0 }, { 170, 0x00AC, 0 }, { 171, 0x00BD, 0 },
	{ 172, 0x00BC, 0 }, { 173, 0x00A1, 0 }, { 174, 0x00AB, 0 },
	{ 175, 0x00BB, 0 }, { 176, 0x2591, 2 }, { 179, 0x2502, 0 },
	{ 180, 0x2524, 0 }, { 181, 0x2561, 1 }, { 183, 0x2556, 0 },
	{ 184, 0x2555, 0 }, { 185, 0x2563, 0 }, { 186, 0x2551, 0 },
	{ 187, 0x2557, 0 }, { 188, 0x255D, 0 }, { 189, 0x255C, 0 },
	{ 190, 0x255B, 0 }, { 191, 0x2510, 0 }, { 192, 0x2514, 0 },
	{ 193, 0x2534, 0 }, { 194, 0x252C, 0 }, { 195, 0x251C, 0 },
	{ 196, 0x2500, 0 }, { 197, 0x253C, 0 }, { 198, 0x255E, 1 },
	{ 200, 0x255A, 0 }, { 201, 0x2554, 0 }, { 202, 0x2569, 0 },
	{ 203, 0x2566, 0 }, { 204, 0x2560, 0 }, { 205, 0x2550, 0 },
	{ 206, 0x256C, 0 }, { 207, 0x2567, 1 }, { 209, 0x2564, 1 },
	{ 211, 0x2559, 0 }, { 212, 0x2558, 0 }, { 213, 0x2552, 1 },
	{ 215, 0x256B, 0 }, { 216, 0x256A, 0 }, { 217, 0x2518, 0 },
	{ 218, 0x250C, 0 }, { 219, 0x2588, 0 }, { 220, 0x2584, 0 },
	{ 221, 0x258C, 0 }, { 222, 0x2590, 0 }, { 223, 0x2580, 0 },
	{ 224, 0x03B1, 0 }, { 225, 0x00DF, 0 }, { 226, 0x0393, 0 },
	{ 227, 0x03C0, 0 }, { 228, 0x03A3, 0 }, { 229, 0x03C3, 0 },
	{ 230, 0x00B5, 0 }, { 231, 0x03C4, 0 }, { 232, 0x03A6, 0 },
	{ 233, 0x0398, 0 }, { 234, 0x03A9, 0 }, { 235, 0x03B4, 0 },
	{ 236, 0x221E, 0 }, { 237, 0x03C6, 0 }, { 238, 0x03B5, 0 },
	{ 239, 0x2229, 0 }, { 240, 0x2261, 0 }, { 241, 0x00B1, 0 },
	{ 242, 0x2265, 0 }, { 243, 0x2264, 0 }, { 244, 0x2320, 1 },
	{ 246, 0x00F7, 0 }, { 247, 0x2248, 0 }, { 248, 0x00B0, 0 },
	{ 249, 0x2219, 0 }, { 250, 0x00B7, 0 }, { 251, 0x221A, 0 },
	{ 252, 0x207F, 0 }, { 253, 0x00B2, 0 }, { 254, 0x25A0, 0 },
	{ 255, 0x00A0, 0 }
};

static uint16_t
vga_cp437_to_uni(uint8_t c)
{
	int min, mid, max;

	min = 0;
	max = (sizeof (cp437unitable) / sizeof (struct cp437uni)) - 1;

	while (max >= min) {
		mid = (min + max) / 2;
		if (c < cp437unitable[mid].cp437_base)
			max = mid - 1;
		else if (c > cp437unitable[mid].cp437_base +
		    cp437unitable[mid].length)
			min = mid + 1;
		else
			return (c - cp437unitable[mid].cp437_base +
			    cp437unitable[mid].unicode_base);
	}

	return ('?');
}

static void
vgatext_setfont(struct gfxp_fb_softc *softc)
{
	union gfx_console *console = softc->console;
	static uchar_t fsreg[8] = {0x0, 0x30, 0x5, 0x35, 0xa, 0x3a, 0xf, 0x3f};

	const uchar_t *from;
	uchar_t volatile *to;
	uint16_t c;
	int	i, j, s;
	int	bpc, f_offset;

	/* Sync-reset the sequencer registers */
	vga_set_seq(&console->vga.regs, 0x00, 0x01);
	/*
	 *  enable write to plane2, since fonts
	 * could only be loaded into plane2
	 */
	vga_set_seq(&console->vga.regs, 0x02, 0x04);
	/*
	 *  sequentially access data in the bit map being
	 * selected by MapMask register (index 0x02)
	 */
	vga_set_seq(&console->vga.regs, 0x04, 0x07);
	/* Sync-reset ended, and allow the sequencer to operate */
	vga_set_seq(&console->vga.regs, 0x00, 0x03);

	/*
	 *  select plane 2 on Read Mode 0
	 */
	vga_set_grc(&console->vga.regs, 0x04, 0x02);
	/*
	 *  system addresses sequentially access data, follow
	 * Memory Mode register bit 2 in the sequencer
	 */
	vga_set_grc(&console->vga.regs, 0x05, 0x00);
	/*
	 * set range of host memory addresses decoded by VGA
	 * hardware -- A0000h-BFFFFh (128K region)
	 */
	vga_set_grc(&console->vga.regs, 0x06, 0x00);

	/*
	 * This assumes 8x16 characters, which yield the traditional 80x25
	 * screen.  It really should support other character heights.
	 */
	bpc = 16;
	s = console->vga.vga_fontslot;
	f_offset = s * 8 * 1024;
	for (i = 0; i < 256; i++) {
		c = vga_cp437_to_uni(i);
		from = font_lookup(font_data_8x16.font, c);
		to = (unsigned char *)console->vga.fb.addr + f_offset +
		    i * 0x20;
		for (j = 0; j < bpc; j++)
			*to++ = *from++;
	}

	/* Sync-reset the sequencer registers */
	vga_set_seq(&console->vga.regs, 0x00, 0x01);
	/* enable write to plane 0 and 1 */
	vga_set_seq(&console->vga.regs, 0x02, 0x03);
	/*
	 * enable character map selection
	 * and odd/even addressing
	 */
	vga_set_seq(&console->vga.regs, 0x04, 0x03);
	/*
	 * select font map
	 */
	vga_set_seq(&console->vga.regs, 0x03, fsreg[s]);
	/* Sync-reset ended, and allow the sequencer to operate */
	vga_set_seq(&console->vga.regs, 0x00, 0x03);

	/* restore graphic registers */

	/* select plane 0 */
	vga_set_grc(&console->vga.regs, 0x04, 0x00);
	/* enable odd/even addressing mode */
	vga_set_grc(&console->vga.regs, 0x05, 0x10);
	/*
	 * range of host memory addresses decoded by VGA
	 * hardware -- B8000h-BFFFFh (32K region)
	 */
	vga_set_grc(&console->vga.regs, 0x06, 0x0e);
	/* enable all color plane */
	vga_set_atr(&console->vga.regs, 0x12, 0x0f);

}

static void
vgatext_save_colormap(struct gfxp_fb_softc *softc)
{
	union gfx_console *console = softc->console;
	int i;

	for (i = 0; i < VGA_ATR_NUM_PLT; i++) {
		console->vga.attrib_palette[i] =
		    vga_get_atr(&console->vga.regs, i);
	}
	for (i = 0; i < VGA8_CMAP_ENTRIES; i++) {
		vga_get_cmap(&console->vga.regs, i,
		    &console->vga.colormap[i].red,
		    &console->vga.colormap[i].green,
		    &console->vga.colormap[i].blue);
	}
}

static void
vgatext_restore_colormap(struct gfxp_fb_softc *softc)
{
	union gfx_console *console = softc->console;
	int i;

	for (i = 0; i < VGA_ATR_NUM_PLT; i++) {
		vga_set_atr(&console->vga.regs, i,
		    console->vga.attrib_palette[i]);
	}
	for (i = 0; i < VGA8_CMAP_ENTRIES; i++) {
		vga_put_cmap(&console->vga.regs, i,
		    console->vga.colormap[i].red,
		    console->vga.colormap[i].green,
		    console->vga.colormap[i].blue);
	}
}

/*
 * search the entries of the "reg" property for one which has the desired
 * combination of phys_hi bits and contains the desired address.
 *
 * This version searches a PCI-style "reg" property.  It was prompted by
 * issues surrounding the presence or absence of an entry for the ROM:
 * (a) a transition problem with PowerPC Virtual Open Firmware
 * (b) uncertainty as to whether an entry will be included on a device
 *     with ROM support (and so an "active" ROM base address register),
 *     but no ROM actually installed.
 *
 * See the note below on vgatext_get_isa_reg_index for the reasons for
 * returning the offset.
 *
 * Note that this routine may not be fully general; it is intended for the
 * specific purpose of finding a couple of particular VGA reg entries and
 * may not be suitable for all reg-searching purposes.
 */
static int
vgatext_get_pci_reg_index(
	dev_info_t *const devi,
	unsigned long himask,
	unsigned long hival,
	unsigned long addr,
	off_t *offset)
{

	int			length, index;
	pci_regspec_t	*reg;

	if (ddi_getlongprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&reg, &length) != DDI_PROP_SUCCESS) {
		return (-1);
	}

	for (index = 0; index < length / sizeof (pci_regspec_t); index++) {
		if ((reg[index].pci_phys_hi & himask) != hival)
			continue;
		if (reg[index].pci_size_hi != 0)
			continue;
		if (reg[index].pci_phys_mid != 0)
			continue;
		if (reg[index].pci_phys_low > addr)
			continue;
		if (reg[index].pci_phys_low + reg[index].pci_size_low <= addr)
			continue;

		*offset = addr - reg[index].pci_phys_low;
		kmem_free(reg, (size_t)length);
		return (index);
	}
	kmem_free(reg, (size_t)length);

	return (-1);
}

/*
 * search the entries of the "reg" property for one which has the desired
 * combination of phys_hi bits and contains the desired address.
 *
 * This version searches a ISA-style "reg" property.  It was prompted by
 * issues surrounding 8514/A support.  By IEEE 1275 compatibility conventions,
 * 8514/A registers should have been added after all standard VGA registers.
 * Unfortunately, the Solaris/Intel device configuration framework
 * (a) lists the 8514/A registers before the video memory, and then
 * (b) also sorts the entries so that I/O entries come before memory
 *     entries.
 *
 * It returns the "reg" index and offset into that register set.
 * The offset is needed because there exist (broken?) BIOSes that
 * report larger ranges enclosing the standard ranges.  One reports
 * 0x3bf for 0x21 instead of 0x3c0 for 0x20, for instance.  Using the
 * offset adjusts for this difference in the base of the register set.
 *
 * Note that this routine may not be fully general; it is intended for the
 * specific purpose of finding a couple of particular VGA reg entries and
 * may not be suitable for all reg-searching purposes.
 */
static int
vgatext_get_isa_reg_index(
	dev_info_t *const devi,
	unsigned long hival,
	unsigned long addr,
	off_t *offset)
{

	int		length, index;
	struct regspec	*reg;

	if (ddi_getlongprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&reg, &length) != DDI_PROP_SUCCESS) {
		return (-1);
	}

	for (index = 0; index < length / sizeof (struct regspec); index++) {
		if (reg[index].regspec_bustype != hival)
			continue;
		if (reg[index].regspec_addr > addr)
			continue;
		if (reg[index].regspec_addr + reg[index].regspec_size <= addr)
			continue;

		*offset = addr - reg[index].regspec_addr;
		kmem_free(reg, (size_t)length);
		return (index);
	}
	kmem_free(reg, (size_t)length);

	return (-1);
}

/*
 * This vgatext function is used to return the fb, and reg pointers
 * and handles for peer graphics drivers.
 */

void
vgatext_return_pointers(struct gfxp_fb_softc *softc, struct vgaregmap *fbs,
    struct vgaregmap *regss)
{

	fbs->addr	= softc->console->vga.fb.addr;
	fbs->handle	= softc->console->vga.fb.handle;
	fbs->mapped	= softc->console->vga.fb.mapped;
	regss->addr	= softc->console->vga.regs.addr;
	regss->handle	= softc->console->vga.regs.handle;
	regss->mapped	= softc->console->vga.regs.mapped;
}
