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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * ANSI terminal emulator module; parse ANSI X3.64 escape sequences and
 * the like.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/ascii.h>
#include <sys/consdev.h>
#include <sys/font.h>
#include <sys/fbio.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/strsubr.h>
#include <sys/stat.h>
#include <sys/visual_io.h>
#include <sys/mutex.h>
#include <sys/param.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/console.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/tem_impl.h>
#include <sys/tem.h>
#ifdef _HAVE_TEM_FIRMWARE
#include <sys/promif.h>
#endif /* _HAVE_TEM_FIRMWARE */
#include <sys/consplat.h>

/* Terminal emulator functions */
static int	tem_setup_terminal(struct vis_devinit *, tem_t *,
			size_t, size_t);
static void	tem_modechange_callback(tem_t *, struct vis_devinit *);
static void	tem_free(tem_t *);
static void	tem_get_inverses(boolean_t *, boolean_t *);
static void	tem_get_initial_color(tem_t *);
static int	tem_adjust_row(tem_t *, int, cred_t *);

/*
 * Globals
 */
ldi_ident_t	term_li = NULL;


extern struct mod_ops mod_miscops;

static struct modlmisc	modlmisc = {
	&mod_miscops,	/* modops */
	"ANSI Terminal Emulator", /* name */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	int ret;
	ret = mod_install(&modlinkage);
	if (ret != 0)
		return (ret);
	ret = ldi_ident_from_mod(&modlinkage, &term_li);
	if (ret != 0) {
		(void) mod_remove(&modlinkage);
		return (ret);
	}
	return (0);
}

int
_fini()
{
	int ret;

	ret = mod_remove(&modlinkage);
	if (ret == 0) {
		ldi_ident_release(term_li);
		term_li = NULL;
	}
	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
tem_fini(tem_t *tem)
{
	int lyr_rval;

	mutex_enter(&tem->lock);

	ASSERT(tem->hdl != NULL);

	/*
	 * Allow layered on driver to clean up console private
	 * data.
	 */
	(void) ldi_ioctl(tem->hdl, VIS_DEVFINI,
	    0, FKIOCTL, kcred, &lyr_rval);

	/*
	 * Close layered on driver
	 */
	(void) ldi_close(tem->hdl, NULL, kcred);
	tem->hdl = NULL;

	mutex_exit(&tem->lock);

	tem_free(tem);

	return (0);
}

static int
tem_init_failed(tem_t *tem, cred_t *credp, boolean_t finish_ioctl)
{
	int	lyr_rval;

	if (finish_ioctl)
		(void) ldi_ioctl(tem->hdl, VIS_DEVFINI, 0, FWRITE|FKIOCTL,
		    credp, &lyr_rval);

	(void) ldi_close(tem->hdl, NULL, credp);
	tem_free(tem);
	return (ENXIO);
}

static void
tem_free_state(struct tem_state *tems)
{
	ASSERT(tems != NULL);

	if (tems->a_outbuf != NULL)
		kmem_free(tems->a_outbuf,
		    tems->a_c_dimension.width);
	if (tems->a_blank_line != NULL)
		kmem_free(tems->a_blank_line,
		    tems->a_c_dimension.width);
	if (tems->a_pix_data != NULL)
		kmem_free(tems->a_pix_data,
		    tems->a_pix_data_size);
	kmem_free(tems, sizeof (struct tem_state));
}

static void
tem_free(tem_t *tem)
{
	ASSERT(tem != NULL);

	if (tem->state != NULL)
		tem_free_state(tem->state);

	kmem_free(tem, sizeof (struct tem));
}

/*
 * This is the main entry point to the module.  It handles output requests
 * during normal system operation, when (e.g.) mutexes are available.
 */
void
tem_write(tem_t *tem, uchar_t *buf, ssize_t len, cred_t *credp)
{
	mutex_enter(&tem->lock);

	ASSERT(tem->hdl != NULL);

	tem_check_first_time(tem, credp, CALLED_FROM_NORMAL);
	tem_terminal_emulate(tem, buf, len, credp, CALLED_FROM_NORMAL);

	mutex_exit(&tem->lock);
}

int
tem_init(tem_t **ptem, char *pathname, cred_t *credp)
{
	struct vis_devinit devinit;
	tem_t *tem;
	size_t height = 0;
	size_t width = 0;
	uint32_t row = 0;
	uint32_t col = 0;
	char	*pathbuf;
	int	err = 0;
	int	lyr_rval;

	tem = kmem_zalloc(sizeof (struct tem), KM_SLEEP);

	mutex_init(&tem->lock, (char *)NULL, MUTEX_DRIVER, NULL);

#ifdef	_HAVE_TEM_FIRMWARE
	tem->cons_wrtvec = tem_write;
#endif /* _HAVE_TEM_FIRMWARE */

	/*
	 * Open the layered device using the devfs physical device name
	 * after adding the /devices prefix.
	 */
	pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) strcpy(pathbuf, "/devices");
	if (i_ddi_prompath_to_devfspath(pathname,
	    pathbuf + strlen("/devices")) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "terminal emulator: Path conversion error");
		kmem_free(pathbuf, MAXPATHLEN);
		tem_free(tem);
		return (ENXIO);
	}
	if (ldi_open_by_name(pathbuf, FWRITE, credp, &tem->hdl, term_li) != 0) {
		cmn_err(CE_WARN, "terminal emulator: Device path open error");
		kmem_free(pathbuf, MAXPATHLEN);
		tem_free(tem);
		return (ENXIO);
	}
	kmem_free(pathbuf, MAXPATHLEN);

	devinit.modechg_cb  = (vis_modechg_cb_t)tem_modechange_callback;
	devinit.modechg_arg = (struct vis_modechg_arg *)tem;

	/*
	 * Initialize the console and get the device parameters
	 */
	if ((err = ldi_ioctl(tem->hdl, VIS_DEVINIT,
	    (intptr_t)&devinit, FWRITE|FKIOCTL, credp, &lyr_rval)) != 0) {
		cmn_err(CE_WARN, "terminal emulator: Compatible fb not found");
		return (tem_init_failed(tem, credp, B_FALSE));
	}

	/* Make sure the fb driver and terminal emulator versions match */
	if (devinit.version != VIS_CONS_REV) {
		cmn_err(CE_WARN,
		    "terminal emulator: VIS_CONS_REV %d (see sys/visual_io.h) "
		    "of console fb driver not supported", devinit.version);
		return (tem_init_failed(tem, credp, B_TRUE));
	}

	if ((tem->fb_polledio = devinit.polledio) == NULL) {
		cmn_err(CE_WARN, "terminal emulator: fb doesn't support polled "
		    "I/O");
		return (tem_init_failed(tem, credp, B_TRUE));
	}

	/* other sanity checks */
	if (!((devinit.depth == 4) || (devinit.depth == 8) ||
		(devinit.depth == 24) || (devinit.depth == 32))) {
		cmn_err(CE_WARN, "terminal emulator: unsupported depth");
		return (tem_init_failed(tem, credp, B_TRUE));
	}

	if ((devinit.mode != VIS_TEXT) && (devinit.mode != VIS_PIXEL)) {
		cmn_err(CE_WARN, "terminal emulator: unsupported mode");
		return (tem_init_failed(tem, credp, B_TRUE));
	}

	if ((devinit.mode == VIS_PIXEL) && plat_stdout_is_framebuffer()) {
		plat_tem_get_prom_size(&height, &width);
	}

	/*
	 * Initialize the terminal emulator
	 */
	mutex_enter(&tem->lock);
	if ((err = tem_setup_terminal(&devinit, tem, height, width)) != 0) {
		cmn_err(CE_WARN, "terminal emulator: Init failed");
		(void) ldi_ioctl(tem->hdl, VIS_DEVFINI, 0, FWRITE|FKIOCTL,
		    credp, &lyr_rval);
		(void) ldi_close(tem->hdl, NULL, credp);
		mutex_exit(&tem->lock);
		tem_free(tem);
		return (err);
	}

	/*
	 * make our kernel console keep compatibility with OBP.
	 */
	tem_get_initial_color(tem);

	/*
	 * On SPARC don't clear the screen if the console is the framebuffer.
	 * Otherwise it needs to be cleared to get rid of junk that may be
	 * in frameuffer memory, since the screen isn't cleared when
	 * boot messages are directed elsewhere.
	 */
	if (devinit.mode == VIS_TEXT) {
		/*
		 * The old getting current cursor position code, which
		 * is not needed here, has been in tem_write/tem_polled_write.
		 */
		tem_reset_display(tem, credp, CALLED_FROM_NORMAL, 0, NULL);
	} else if (plat_stdout_is_framebuffer()) {
		ASSERT(devinit.mode == VIS_PIXEL);
		plat_tem_hide_prom_cursor();
		tem_reset_display(tem, credp, CALLED_FROM_NORMAL, 0, NULL);

		/*
		 * We are getting the current cursor position in pixel
		 * mode so that we don't over-write the console output
		 * during boot.
		 */
		plat_tem_get_prom_pos(&row, &col);

		/*
		 * Adjust the row if necessary when the font of our
		 * kernel console tem is different with that of prom
		 * tem.
		 */
		row = tem_adjust_row(tem, row, credp);

		/* first line of our kernel console output */
		tem->state->first_line = row + 1;

		/* re-set and align cusror position */
		tem->state->a_c_cursor.row = row;
		tem->state->a_c_cursor.col = 0;
		tem_align_cursor(tem);
	} else {
		tem_reset_display(tem, credp, CALLED_FROM_NORMAL, 1, NULL);
	}

#ifdef _HAVE_TEM_FIRMWARE
	if (plat_stdout_is_framebuffer()) {
		/*
		 * Drivers in the console stream may emit additional
		 * messages before we are ready. This causes text
		 * overwrite on the screen. So we set the redirection
		 * here. It is safe because the ioctl in consconfig_dacf
		 * will succeed and consmode will be set to CONS_KFB.
		 */
		prom_set_stdout_redirect(console_prom_write_cb,
		    (promif_redir_arg_t)tem);

	}
#endif /* _HAVE_TEM_FIRMWARE */

	mutex_exit(&tem->lock);
	*ptem = tem; /* Return tem to caller only upon success */
	return (0);
}

/*
 * This is a callback function that we register with the frame
 * buffer driver layered underneath.  It gets invoked from
 * the underlying frame buffer driver to reconfigure the terminal
 * emulator to a new screen size and depth in conjunction with
 * framebuffer videomode changes.
 * Here we keep the foreground/background color and attributes,
 * which may be different with the initial settings, so that
 * the color won't change while the framebuffer videomode changes.
 * And we also reset the kernel terminal emulator and clear the
 * whole screen.
 */
void
tem_modechange_callback(tem_t *tem, struct vis_devinit *devinit)
{
	tem_color_t tc;

	mutex_enter(&tem->lock);

	ASSERT(tem->hdl != NULL);

	tc.fg_color = tem->state->fg_color;
	tc.bg_color = tem->state->bg_color;
	tc.a_flags = tem->state->a_flags;

	(void) tem_setup_terminal(devinit, tem,
	    tem->state->a_c_dimension.height,
	    tem->state->a_c_dimension.width);

	tem_reset_display(tem, kcred, CALLED_FROM_NORMAL, 1, &tc);

	mutex_exit(&tem->lock);

	if (tem->modechg_cb != NULL)
		tem->modechg_cb(tem->modechg_arg);
}

static int
tem_setup_terminal(
	struct vis_devinit *devinit,
	tem_t *tem,
	size_t height, size_t width)
{
	int i;
	struct tem_state *new_state, *prev_state;

	ASSERT(MUTEX_HELD(&tem->lock));

	prev_state = tem->state;

	new_state = kmem_zalloc(sizeof (struct tem_state), KM_SLEEP);

	new_state->a_pdepth = devinit->depth;
	new_state->display_mode = devinit->mode;
	new_state->linebytes = devinit->linebytes;

	switch (devinit->mode) {
	case VIS_TEXT:
		new_state->a_p_dimension.width  = 0;
		new_state->a_p_dimension.height = 0;
		new_state->a_c_dimension.width	= devinit->width;
		new_state->a_c_dimension.height = devinit->height;

		new_state->in_fp.f_display = tem_text_display;
		new_state->in_fp.f_copy = tem_text_copy;
		new_state->in_fp.f_cursor = tem_text_cursor;
		new_state->in_fp.f_cls = tem_text_cls;
		new_state->in_fp.f_bit2pix = NULL;

		new_state->a_blank_line =
			kmem_alloc(new_state->a_c_dimension.width, KM_SLEEP);

		for (i = 0; i < new_state->a_c_dimension.width; i++)
			new_state->a_blank_line[i] = ' ';

		break;
	case VIS_PIXEL:

		/*
		 * First check to see if the user has specified a screen size.
		 * If so, use those values.  Else use 34x80 as the default.
		 */
		if (width == 0) {
			width = TEM_DEFAULT_COLS;
			height = TEM_DEFAULT_ROWS;
		}
		new_state->a_c_dimension.height = height;
		new_state->a_c_dimension.width = width;

		new_state->a_p_dimension.height = devinit->height;
		new_state->a_p_dimension.width = devinit->width;

		new_state->in_fp.f_display = tem_pix_display;
		new_state->in_fp.f_copy = tem_pix_copy;
		new_state->in_fp.f_cursor = tem_pix_cursor;
		new_state->in_fp.f_cls = tem_pix_cls;

		new_state->a_blank_line = NULL;

		/*
		 * set_font() will select a appropriate sized font for
		 * the number of rows and columns selected.  If we don't
		 * have a font that will fit, then it will use the
		 * default builtin font and adjust the rows and columns
		 * to fit on the screen.
		 */
		set_font(&new_state->a_font,
		    &new_state->a_c_dimension.height,
		    &new_state->a_c_dimension.width,
		    new_state->a_p_dimension.height,
		    new_state->a_p_dimension.width);

		new_state->a_p_offset.y =
			(new_state->a_p_dimension.height -
			(new_state->a_c_dimension.height *
			new_state->a_font.height)) / 2;

		new_state->a_p_offset.x =
			(new_state->a_p_dimension.width -
			(new_state->a_c_dimension.width *
			new_state->a_font.width)) / 2;

		switch (devinit->depth) {
		case 4:
			new_state->in_fp.f_bit2pix = bit_to_pix4;
			new_state->a_pix_data_size =
				(((new_state->a_font.width * 4) +
				NBBY - 1) / NBBY) * new_state->a_font.height;
			break;
		case 8:
			new_state->in_fp.f_bit2pix = bit_to_pix8;
			new_state->a_pix_data_size =
				new_state->a_font.width *
				new_state->a_font.height;
			break;
		case 24:
		case 32:
			new_state->in_fp.f_bit2pix = bit_to_pix24;
			new_state->a_pix_data_size =
				new_state->a_font.width *
				new_state->a_font.height;
			new_state->a_pix_data_size *= 4;
			break;
		}

		new_state->a_pix_data =
			kmem_alloc(new_state->a_pix_data_size, KM_SLEEP);

		break;

	default:
		/*
		 * The layered fb driver conveyed an unrecognized rendering
		 * mode.  We cannot proceed with tem initialization.
		 */
		kmem_free(new_state, sizeof (struct tem_state));
		return (ENXIO);
	}

	new_state->a_outbuf =
		kmem_alloc(new_state->a_c_dimension.width, KM_SLEEP);

	/*
	 * Change state atomically so that polled I/O requests
	 * can be safely and reliably serviced anytime after the terminal
	 * emulator is originally initialized and the console mode has been
	 * switched over from the PROM, even while a videomode change
	 * callback is being processed.
	 */
	tem->state = new_state;

	if (prev_state != NULL)
		tem_free_state(prev_state);

	return (0);
}

/*
 * This function is used to display a rectangular blit of data
 * of a given size and location via the underlying framebuffer driver.
 * The blit can be as small as a pixel or as large as the screen.
 */
void
tem_display_layered(
	tem_t *tem,
	struct vis_consdisplay *pda,
	cred_t *credp)
{
	int rval;

	(void) ldi_ioctl(tem->hdl, VIS_CONSDISPLAY,
	    (intptr_t)pda, FKIOCTL, credp, &rval);
}

/*
 * This function is used to invoke a block copy operation in the
 * underlying framebuffer driver.  Rectangle copies are how scrolling
 * is implemented, as well as horizontal text shifting escape seqs.
 * such as from vi when deleting characters and words.
 */
void
tem_copy_layered(
	tem_t *tem,
	struct vis_conscopy *pma,
	cred_t *credp)
{
	int rval;

	(void) ldi_ioctl(tem->hdl, VIS_CONSCOPY,
	    (intptr_t)pma, FKIOCTL, credp, &rval);
}

/*
 * This function is used to show or hide a rectangluar monochrom
 * pixel inverting, text block cursor via the underlying framebuffer.
 */
void
tem_cursor_layered(
	tem_t *tem,
	struct vis_conscursor *pca,
	cred_t *credp)
{
	int rval;

	(void) ldi_ioctl(tem->hdl, VIS_CONSCURSOR,
	    (intptr_t)pca, FKIOCTL, credp, &rval);
}

void
tem_reset_colormap(
	tem_t *tem,
	cred_t *credp,
	enum called_from called_from)
{
	struct vis_cmap cm;
	int rval;

	if (called_from == CALLED_FROM_STANDALONE)
		return;

	switch (tem->state->a_pdepth) {
	case 8:
		cm.index = 0;
		cm.count = 16;
		cm.red   = cmap4_to_24.red;   /* 8-bits (1/3 of TrueColor 24) */
		cm.blue  = cmap4_to_24.blue;  /* 8-bits (1/3 of TrueColor 24) */
		cm.green = cmap4_to_24.green; /* 8-bits (1/3 of TrueColor 24) */
		(void) ldi_ioctl(tem->hdl, VIS_PUTCMAP, (intptr_t)&cm,
		    FKIOCTL, credp, &rval);
		break;
	}
}

void
tem_get_size(tem_t *tem, ushort_t *r, ushort_t *c,
	ushort_t *x, ushort_t *y)
{
	*r = (ushort_t)tem->state->a_c_dimension.height;
	*c = (ushort_t)tem->state->a_c_dimension.width;
	*x = (ushort_t)tem->state->a_p_dimension.width;
	*y = (ushort_t)tem->state->a_p_dimension.height;
}

void
tem_register_modechg_cb(tem_t *tem, tem_modechg_cb_t func,
	tem_modechg_cb_arg_t arg)
{
	tem->modechg_cb = func;
	tem->modechg_arg = arg;
}

/*
 * This function is to scroll up the OBP output, which has
 * different screen height and width with our kernel console.
 */
static void
tem_prom_scroll_up(struct tem *tem, int nrows, cred_t *credp)
{
	struct tem_state	*tems = tem->state;
	struct vis_conscopy	ma;
	int	ncols, width;

	/* copy */
	ma.s_row = nrows * tems->a_font.height;
	ma.e_row = tems->a_p_dimension.height - 1;
	ma.t_row = 0;

	ma.s_col = 0;
	ma.e_col = tems->a_p_dimension.width - 1;
	ma.t_col = 0;

	tem_copy(tem, &ma, credp, CALLED_FROM_NORMAL);

	/* clear */
	width = tems->a_font.width;
	ncols = (tems->a_p_dimension.width +
	    (width - 1))/ width;

	tem_pix_cls_range(tem,
	    0, nrows, tems->a_p_offset.y,
	    0, ncols, 0,
	    B_TRUE, credp, CALLED_FROM_NORMAL);
}

#define	PROM_DEFAULT_FONT_HEIGHT	22
#define	PROM_DEFAULT_WINDOW_TOP	0x8a

/*
 * This function is to compute the starting row of the console, according to
 * PROM cursor's position. Here we have to take different fonts into account.
 */
static int
tem_adjust_row(tem_t *tem, int prom_row, cred_t *credp)
{
	int	tem_row;
	int	tem_y;
	int	prom_charheight = 0;
	int	prom_window_top = 0;
	int	scroll_up_lines;

	plat_tem_get_prom_font_size(&prom_charheight, &prom_window_top);
	if (prom_charheight == 0)
		prom_charheight = PROM_DEFAULT_FONT_HEIGHT;
	if (prom_window_top == 0)
		prom_window_top = PROM_DEFAULT_WINDOW_TOP;

	tem_y = (prom_row + 1) * prom_charheight + prom_window_top -
	    tem->state->a_p_offset.y;
	tem_row = (tem_y + tem->state->a_font.height - 1) /
	    tem->state->a_font.height - 1;

	if (tem_row < 0) {
		tem_row = 0;
	} else if (tem_row >= (tem->state->a_c_dimension.height - 1)) {
		/*
		 * Scroll up the prom outputs if the PROM cursor's position is
		 * below our tem's lower boundary.
		 */
		scroll_up_lines = tem_row -
		    (tem->state->a_c_dimension.height - 1);
		tem_prom_scroll_up(tem, scroll_up_lines, credp);
		tem_row = tem->state->a_c_dimension.height - 1;
	}

	return (tem_row);
}

static void
tem_get_inverses(boolean_t *p_inverse, boolean_t *p_inverse_screen)
{
	int i_inverse = 0;
	int i_inverse_screen = 0;

	plat_tem_get_inverses(&i_inverse, &i_inverse_screen);

	*p_inverse = (i_inverse == 0) ? B_FALSE : B_TRUE;
	*p_inverse_screen = (i_inverse_screen == 0) ? B_FALSE : B_TRUE;
}

/*
 * Get the foreground/background color and attributes from the initial
 * PROM, so that our kernel console can keep the same visual behaviour.
 */
static void
tem_get_initial_color(tem_t *tem)
{
	boolean_t inverse, inverse_screen;
	unsigned short  flags = 0;

	tem->init_color.fg_color = DEFAULT_ANSI_FOREGROUND;
	tem->init_color.bg_color = DEFAULT_ANSI_BACKGROUND;

	if (plat_stdout_is_framebuffer()) {
		tem_get_inverses(&inverse, &inverse_screen);
		if (inverse)
			flags |= TEM_ATTR_REVERSE;
		if (inverse_screen)
			flags |= TEM_ATTR_SCREEN_REVERSE;
		if (flags != 0)
			flags |= TEM_ATTR_BOLD;
	}

	tem->init_color.a_flags = flags;
}
