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
#include "gfxp_fb.h"

#define	MYNAME	"gfxp_vgatext"

typedef enum pc_colors {
	pc_black	= 0,
	pc_blue		= 1,
	pc_green	= 2,
	pc_cyan		= 3,
	pc_red		= 4,
	pc_magenta	= 5,
	pc_brown	= 6,
	pc_white	= 7,
	pc_grey		= 8,
	pc_brt_blue	= 9,
	pc_brt_green	= 10,
	pc_brt_cyan	= 11,
	pc_brt_red	= 12,
	pc_brt_magenta	= 13,
	pc_yellow	= 14,
	pc_brt_white	= 15
} pc_colors_t;

static const unsigned char solaris_color_to_pc_color[16] = {
	pc_brt_white,		/*  0 - brt_white	*/
	pc_black,		/*  1 - black		*/
	pc_blue,		/*  2 - blue		*/
	pc_green,		/*  3 - green		*/
	pc_cyan,		/*  4 - cyan		*/
	pc_red,			/*  5 - red		*/
	pc_magenta,		/*  6 - magenta		*/
	pc_brown,		/*  7 - brown		*/
	pc_white,		/*  8 - white		*/
	pc_grey,		/*  9 - gery		*/
	pc_brt_blue,		/* 10 - brt_blue	*/
	pc_brt_green,		/* 11 - brt_green	*/
	pc_brt_cyan,		/* 12 - brt_cyan	*/
	pc_brt_red,		/* 13 - brt_red		*/
	pc_brt_magenta,		/* 14 - brt_magenta	*/
	pc_yellow		/* 15 - yellow		*/
};

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
			softc->blt_ops.setmode(KD_TEXT);
		vgatext_kdsettext(softc);
		break;

	case KD_GRAPHICS:
		vgatext_kdsetgraphics(softc);
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
 * display a string on the screen at (row, col)
 *	 assume it has been cropped to fit.
 */

static void
vgatext_cons_display(struct gfxp_fb_softc *softc, struct vis_consdisplay *da)
{
	unsigned char	*string;
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
	string = da->data;
	addr = (struct cgatext *)softc->console->vga.current_base
	    +  (da->row * VGA_TEXT_COLS + da->col);
	for (i = 0; i < da->width; i++) {
		addr->ch = string[i];
		addr->attr = attr;
		addr++;
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
	    vga_get_atr(&softc->console->vga.regs, VGA_BLACK));
}
#endif

static void
vgatext_setfont(struct gfxp_fb_softc *softc)
{
	union gfx_console *console = softc->console;
	static uchar_t fsreg[8] = {0x0, 0x30, 0x5, 0x35, 0xa, 0x3a, 0xf, 0x3f};

	uchar_t *from;
	uchar_t volatile *to;
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
		from = font_data_8x16.encoding[i];
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
