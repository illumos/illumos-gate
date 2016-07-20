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
 *
 * How Virtual Terminal Emulator Works:
 *
 * Every virtual terminal is associated with a tem_vt_state structure
 * and maintains a virtual screen buffer in tvs_screen_buf, which contains
 * all the characters which should be shown on the physical screen when
 * the terminal is activated.  There are also two other buffers, tvs_fg_buf
 * and tvs_bg_buf, which track the foreground and background colors of the
 * on screen characters
 *
 * Data written to a virtual terminal is composed of characters which
 * should be displayed on the screen when this virtual terminal is
 * activated, fg/bg colors of these characters, and other control
 * information (escape sequence, etc).
 *
 * When data is passed to a virtual terminal it first is parsed for
 * control information by tem_safe_parse().  Subsequently the character
 * and color data are written to tvs_screen_buf, tvs_fg_buf, and
 * tvs_bg_buf.  They are saved in these buffers in order to refresh
 * the screen when this terminal is activated.  If the terminal is
 * currently active, the data (characters and colors) are also written
 * to the physical screen by invoking a callback function,
 * tem_safe_text_callbacks() or tem_safe_pix_callbacks().
 *
 * When rendering data to the framebuffer, if the framebuffer is in
 * VIS_PIXEL mode, the character data will first be converted to pixel
 * data using tem_safe_pix_bit2pix(), and then the pixels get displayed
 * on the physical screen.  We only store the character and color data in
 * tem_vt_state since the bit2pix conversion only happens when actually
 * rendering to the physical framebuffer.
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
#ifdef _HAVE_TEM_FIRMWARE
#include <sys/promif.h>
#endif /* _HAVE_TEM_FIRMWARE */
#include <sys/consplat.h>
#include <sys/kd.h>
#include <sys/sysmacros.h>
#include <sys/note.h>
#include <sys/t_lock.h>

/* Terminal emulator internal helper functions */
static void	tems_setup_terminal(struct vis_devinit *, size_t, size_t);
static void	tems_modechange_callback(struct vis_modechg_arg *,
		struct vis_devinit *);

static void	tems_reset_colormap(cred_t *, enum called_from);

static void	tem_free_buf(struct tem_vt_state *);
static void	tem_internal_init(struct tem_vt_state *, cred_t *, boolean_t,
		    boolean_t);
static void	tems_get_initial_color(tem_color_t *pcolor);

/*
 * Globals
 */
static ldi_ident_t	term_li = NULL;
tem_state_t	tems;	/* common term info */
_NOTE(MUTEX_PROTECTS_DATA(tems.ts_lock, tems))

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

	mutex_init(&tems.ts_lock, (char *)NULL, MUTEX_DRIVER, NULL);
	list_create(&tems.ts_list, sizeof (struct tem_vt_state),
	    offsetof(struct tem_vt_state, tvs_list_node));
	tems.ts_active = NULL;

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

static void
tem_add(struct tem_vt_state *tem)
{
	ASSERT(MUTEX_HELD(&tems.ts_lock) && MUTEX_HELD(&tem->tvs_lock));

	list_insert_head(&tems.ts_list, tem);
}

static void
tem_rm(struct tem_vt_state *tem)
{
	ASSERT(MUTEX_HELD(&tems.ts_lock) && MUTEX_HELD(&tem->tvs_lock));

	list_remove(&tems.ts_list, tem);
}

/*
 * This is the main entry point to the module.  It handles output requests
 * during normal system operation, when (e.g.) mutexes are available.
 */
void
tem_write(tem_vt_state_t tem_arg, uchar_t *buf, ssize_t len, cred_t *credp)
{
	struct tem_vt_state *tem = (struct tem_vt_state *)tem_arg;

	mutex_enter(&tems.ts_lock);
	mutex_enter(&tem->tvs_lock);

	if (!tem->tvs_initialized) {
		mutex_exit(&tem->tvs_lock);
		mutex_exit(&tems.ts_lock);
		return;
	}

	tem_safe_check_first_time(tem, credp, CALLED_FROM_NORMAL);
	tem_safe_terminal_emulate(tem, buf, len, credp, CALLED_FROM_NORMAL);

	mutex_exit(&tem->tvs_lock);
	mutex_exit(&tems.ts_lock);
}

static void
tem_internal_init(struct tem_vt_state *ptem, cred_t *credp,
    boolean_t init_color, boolean_t clear_screen)
{
	int i, j;
	int width, height;
	int total;
	text_color_t fg;
	text_color_t bg;
	size_t	tc_size = sizeof (text_color_t);

	ASSERT(MUTEX_HELD(&tems.ts_lock) && MUTEX_HELD(&ptem->tvs_lock));

	if (tems.ts_display_mode == VIS_PIXEL) {
		ptem->tvs_pix_data_size = tems.ts_pix_data_size;
		ptem->tvs_pix_data =
		    kmem_alloc(ptem->tvs_pix_data_size, KM_SLEEP);
	}

	ptem->tvs_outbuf_size = tems.ts_c_dimension.width;
	ptem->tvs_outbuf =
	    (unsigned char *)kmem_alloc(ptem->tvs_outbuf_size, KM_SLEEP);

	width = tems.ts_c_dimension.width;
	height = tems.ts_c_dimension.height;
	ptem->tvs_screen_buf_size = width * height;
	ptem->tvs_screen_buf =
	    (unsigned char *)kmem_alloc(width * height, KM_SLEEP);

	total = width * height * tc_size;
	ptem->tvs_fg_buf = (text_color_t *)kmem_alloc(total, KM_SLEEP);
	ptem->tvs_bg_buf = (text_color_t *)kmem_alloc(total, KM_SLEEP);
	ptem->tvs_color_buf_size = total;

	tem_safe_reset_display(ptem, credp, CALLED_FROM_NORMAL,
	    clear_screen, init_color);

	tem_safe_get_color(ptem, &fg, &bg, TEM_ATTR_SCREEN_REVERSE);
	for (i = 0; i < height; i++)
		for (j = 0; j < width; j++) {
			ptem->tvs_screen_buf[i * width + j] = ' ';
			ptem->tvs_fg_buf[(i * width +j) * tc_size] = fg;
			ptem->tvs_bg_buf[(i * width +j) * tc_size] = bg;

		}

	ptem->tvs_initialized  = 1;
}

int
tem_initialized(tem_vt_state_t tem_arg)
{
	struct tem_vt_state *ptem = (struct tem_vt_state *)tem_arg;
	int ret;

	mutex_enter(&ptem->tvs_lock);
	ret = ptem->tvs_initialized;
	mutex_exit(&ptem->tvs_lock);

	return (ret);
}

tem_vt_state_t
tem_init(cred_t *credp)
{
	struct tem_vt_state *ptem;

	ptem = kmem_zalloc(sizeof (struct tem_vt_state), KM_SLEEP);
	mutex_init(&ptem->tvs_lock, (char *)NULL, MUTEX_DRIVER, NULL);

	mutex_enter(&tems.ts_lock);
	mutex_enter(&ptem->tvs_lock);

	ptem->tvs_isactive = B_FALSE;
	ptem->tvs_fbmode = KD_TEXT;

	/*
	 * A tem is regarded as initialized only after tem_internal_init(),
	 * will be set at the end of tem_internal_init().
	 */
	ptem->tvs_initialized = 0;


	if (!tems.ts_initialized) {
		/*
		 * Only happens during early console configuration.
		 */
		tem_add(ptem);
		mutex_exit(&ptem->tvs_lock);
		mutex_exit(&tems.ts_lock);
		return ((tem_vt_state_t)ptem);
	}

	tem_internal_init(ptem, credp, B_TRUE, B_FALSE);
	tem_add(ptem);
	mutex_exit(&ptem->tvs_lock);
	mutex_exit(&tems.ts_lock);

	return ((tem_vt_state_t)ptem);
}

/*
 * re-init the tem after video mode has changed and tems_info has
 * been re-inited. The lock is already held.
 */
static void
tem_reinit(struct tem_vt_state *tem, boolean_t reset_display)
{
	ASSERT(MUTEX_HELD(&tems.ts_lock) && MUTEX_HELD(&tem->tvs_lock));

	tem_free_buf(tem); /* only free virtual buffers */

	/* reserve color */
	tem_internal_init(tem, kcred, B_FALSE, reset_display);
}

static void
tem_free_buf(struct tem_vt_state *tem)
{
	ASSERT(tem != NULL && MUTEX_HELD(&tem->tvs_lock));

	if (tem->tvs_outbuf != NULL)
		kmem_free(tem->tvs_outbuf, tem->tvs_outbuf_size);
	if (tem->tvs_pix_data != NULL)
		kmem_free(tem->tvs_pix_data, tem->tvs_pix_data_size);
	if (tem->tvs_screen_buf != NULL)
		kmem_free(tem->tvs_screen_buf, tem->tvs_screen_buf_size);
	if (tem->tvs_fg_buf != NULL)
		kmem_free(tem->tvs_fg_buf, tem->tvs_color_buf_size);
	if (tem->tvs_bg_buf != NULL)
		kmem_free(tem->tvs_bg_buf, tem->tvs_color_buf_size);
}

void
tem_destroy(tem_vt_state_t tem_arg, cred_t *credp)
{
	struct tem_vt_state *tem = (struct tem_vt_state *)tem_arg;

	mutex_enter(&tems.ts_lock);
	mutex_enter(&tem->tvs_lock);

	if (tem->tvs_isactive && tem->tvs_fbmode == KD_TEXT)
		tem_safe_blank_screen(tem, credp, CALLED_FROM_NORMAL);

	tem_free_buf(tem);
	tem_rm(tem);

	if (tems.ts_active == tem)
		tems.ts_active = NULL;

	mutex_exit(&tem->tvs_lock);
	mutex_exit(&tems.ts_lock);

	kmem_free(tem, sizeof (struct tem_vt_state));
}

static int
tems_failed(cred_t *credp, boolean_t finish_ioctl)
{
	int	lyr_rval;

	ASSERT(MUTEX_HELD(&tems.ts_lock));

	if (finish_ioctl)
		(void) ldi_ioctl(tems.ts_hdl, VIS_DEVFINI, 0,
		    FWRITE|FKIOCTL, credp, &lyr_rval);

	(void) ldi_close(tems.ts_hdl, NULL, credp);
	tems.ts_hdl = NULL;
	return (ENXIO);
}

/*
 * only called once during boot
 */
int
tem_info_init(char *pathname, cred_t *credp)
{
	int			lyr_rval, ret;
	struct vis_devinit	temargs;
	char			*pathbuf;
	size_t height = 0;
	size_t width = 0;
	struct tem_vt_state *p;

	mutex_enter(&tems.ts_lock);

	if (tems.ts_initialized) {
		mutex_exit(&tems.ts_lock);
		return (0);
	}

	/*
	 * Open the layered device using the devfs physical device name
	 * after adding the /devices prefix.
	 */
	pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) strcpy(pathbuf, "/devices");
	if (i_ddi_prompath_to_devfspath(pathname,
	    pathbuf + strlen("/devices")) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "terminal-emulator:  path conversion error");
		kmem_free(pathbuf, MAXPATHLEN);

		mutex_exit(&tems.ts_lock);
		return (ENXIO);
	}
	if (ldi_open_by_name(pathbuf, FWRITE, credp,
	    &tems.ts_hdl, term_li) != 0) {
		cmn_err(CE_WARN, "terminal-emulator:  device path open error");
		kmem_free(pathbuf, MAXPATHLEN);

		mutex_exit(&tems.ts_lock);
		return (ENXIO);
	}
	kmem_free(pathbuf, MAXPATHLEN);

	temargs.modechg_cb  = (vis_modechg_cb_t)tems_modechange_callback;
	temargs.modechg_arg = NULL;

	/*
	 * Initialize the console and get the device parameters
	 */
	if (ldi_ioctl(tems.ts_hdl, VIS_DEVINIT,
	    (intptr_t)&temargs, FWRITE|FKIOCTL, credp, &lyr_rval) != 0) {
		cmn_err(CE_WARN, "terminal emulator: Compatible fb not found");
		ret = tems_failed(credp, B_FALSE);
		mutex_exit(&tems.ts_lock);
		return (ret);
	}

	/* Make sure the fb driver and terminal emulator versions match */
	if (temargs.version != VIS_CONS_REV) {
		cmn_err(CE_WARN,
		    "terminal emulator: VIS_CONS_REV %d (see sys/visual_io.h) "
		    "of console fb driver not supported", temargs.version);
		ret = tems_failed(credp, B_TRUE);
		mutex_exit(&tems.ts_lock);
		return (ret);
	}

	if ((tems.ts_fb_polledio = temargs.polledio) == NULL) {
		cmn_err(CE_WARN, "terminal emulator: fb doesn't support polled "
		    "I/O");
		ret = tems_failed(credp, B_TRUE);
		mutex_exit(&tems.ts_lock);
		return (ret);
	}

	/* other sanity checks */
	if (!((temargs.depth == 4) || (temargs.depth == 8) ||
	    (temargs.depth == 24) || (temargs.depth == 32))) {
		cmn_err(CE_WARN, "terminal emulator: unsupported depth");
		ret = tems_failed(credp, B_TRUE);
		mutex_exit(&tems.ts_lock);
		return (ret);
	}

	if ((temargs.mode != VIS_TEXT) && (temargs.mode != VIS_PIXEL)) {
		cmn_err(CE_WARN, "terminal emulator: unsupported mode");
		ret = tems_failed(credp, B_TRUE);
		mutex_exit(&tems.ts_lock);
		return (ret);
	}

	if ((temargs.mode == VIS_PIXEL) && plat_stdout_is_framebuffer())
		plat_tem_get_prom_size(&height, &width);

	/*
	 * Initialize the common terminal emulator info
	 */
	tems_setup_terminal(&temargs, height, width);

	tems_reset_colormap(credp, CALLED_FROM_NORMAL);
	tems_get_initial_color(&tems.ts_init_color);

	tems.ts_initialized = 1; /* initialization flag */

	for (p = list_head(&tems.ts_list); p != NULL;
	    p = list_next(&tems.ts_list, p)) {
		mutex_enter(&p->tvs_lock);
		tem_internal_init(p, credp, B_TRUE, B_FALSE);
		if (temargs.mode == VIS_PIXEL)
			tem_pix_align(p, credp, CALLED_FROM_NORMAL);
		mutex_exit(&p->tvs_lock);
	}

	mutex_exit(&tems.ts_lock);
	return (0);
}

#define	TEMS_DEPTH_DIFF		0x01
#define	TEMS_DIMENSION_DIFF	0x02

static uchar_t
tems_check_videomode(struct vis_devinit *tp)
{
	uchar_t result = 0;

	if (tems.ts_pdepth != tp->depth)
		result |= TEMS_DEPTH_DIFF;

	if (tp->mode == VIS_TEXT) {
		if (tems.ts_c_dimension.width != tp->width ||
		    tems.ts_c_dimension.height != tp->height)
			result |= TEMS_DIMENSION_DIFF;
	} else {
		if (tems.ts_p_dimension.width != tp->width ||
		    tems.ts_p_dimension.height != tp->height)
			result |= TEMS_DIMENSION_DIFF;
	}

	return (result);
}

static void
tems_setup_terminal(struct vis_devinit *tp, size_t height, size_t width)
{
	int i;
	int old_blank_buf_size = tems.ts_c_dimension.width;

	ASSERT(MUTEX_HELD(&tems.ts_lock));

	tems.ts_pdepth = tp->depth;
	tems.ts_linebytes = tp->linebytes;
	tems.ts_display_mode = tp->mode;

	switch (tp->mode) {
	case VIS_TEXT:
		tems.ts_p_dimension.width = 0;
		tems.ts_p_dimension.height = 0;
		tems.ts_c_dimension.width = tp->width;
		tems.ts_c_dimension.height = tp->height;
		tems.ts_callbacks = &tem_safe_text_callbacks;

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
		tems.ts_c_dimension.height = (screen_size_t)height;
		tems.ts_c_dimension.width = (screen_size_t)width;

		tems.ts_p_dimension.height = tp->height;
		tems.ts_p_dimension.width = tp->width;

		tems.ts_callbacks = &tem_safe_pix_callbacks;

		/*
		 * set_font() will select a appropriate sized font for
		 * the number of rows and columns selected.  If we don't
		 * have a font that will fit, then it will use the
		 * default builtin font and adjust the rows and columns
		 * to fit on the screen.
		 */
		set_font(&tems.ts_font,
		    &tems.ts_c_dimension.height,
		    &tems.ts_c_dimension.width,
		    tems.ts_p_dimension.height,
		    tems.ts_p_dimension.width);

		tems.ts_p_offset.y = (tems.ts_p_dimension.height -
		    (tems.ts_c_dimension.height * tems.ts_font.height)) / 2;
		tems.ts_p_offset.x = (tems.ts_p_dimension.width -
		    (tems.ts_c_dimension.width * tems.ts_font.width)) / 2;

		tems.ts_pix_data_size =
		    tems.ts_font.width * tems.ts_font.height;

		tems.ts_pix_data_size *= 4;

		tems.ts_pdepth = tp->depth;

		break;
	}

	/* Now virtual cls also uses the blank_line buffer */
	if (tems.ts_blank_line)
		kmem_free(tems.ts_blank_line, old_blank_buf_size);

	tems.ts_blank_line = (unsigned char *)
	    kmem_alloc(tems.ts_c_dimension.width, KM_SLEEP);
	for (i = 0; i < tems.ts_c_dimension.width; i++)
		tems.ts_blank_line[i] = ' ';
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
/* ARGSUSED */
void
tems_modechange_callback(struct vis_modechg_arg *arg,
    struct vis_devinit *devinit)
{
	uchar_t diff;
	struct tem_vt_state *p;
	tem_modechg_cb_t cb;
	tem_modechg_cb_arg_t cb_arg;

	ASSERT(!(list_is_empty(&tems.ts_list)));

	mutex_enter(&tems.ts_lock);

	/*
	 * currently only for pixel mode
	 */
	diff = tems_check_videomode(devinit);
	if (diff == 0) {
		mutex_exit(&tems.ts_lock);
		return;
	}

	diff = diff & TEMS_DIMENSION_DIFF;

	if (diff == 0) {
		/*
		 * Only need to reinit the active tem.
		 */
		struct tem_vt_state *active = tems.ts_active;
		tems.ts_pdepth = devinit->depth;

		mutex_enter(&active->tvs_lock);
		ASSERT(active->tvs_isactive);
		tem_reinit(active, B_TRUE);
		mutex_exit(&active->tvs_lock);

		mutex_exit(&tems.ts_lock);
		return;
	}

	tems_setup_terminal(devinit, tems.ts_c_dimension.height,
	    tems.ts_c_dimension.width);

	for (p = list_head(&tems.ts_list); p != NULL;
	    p = list_next(&tems.ts_list, p)) {
		mutex_enter(&p->tvs_lock);
		tem_reinit(p, p->tvs_isactive);
		mutex_exit(&p->tvs_lock);
	}


	if (tems.ts_modechg_cb == NULL) {
		mutex_exit(&tems.ts_lock);
		return;
	}

	cb = tems.ts_modechg_cb;
	cb_arg = tems.ts_modechg_arg;

	/*
	 * Release the lock while doing callback.
	 */
	mutex_exit(&tems.ts_lock);
	cb(cb_arg);
}

/*
 * This function is used to display a rectangular blit of data
 * of a given size and location via the underlying framebuffer driver.
 * The blit can be as small as a pixel or as large as the screen.
 */
void
tems_display_layered(
	struct vis_consdisplay *pda,
	cred_t *credp)
{
	int rval;

	(void) ldi_ioctl(tems.ts_hdl, VIS_CONSDISPLAY,
	    (intptr_t)pda, FKIOCTL, credp, &rval);
}

/*
 * This function is used to invoke a block copy operation in the
 * underlying framebuffer driver.  Rectangle copies are how scrolling
 * is implemented, as well as horizontal text shifting escape seqs.
 * such as from vi when deleting characters and words.
 */
void
tems_copy_layered(
	struct vis_conscopy *pma,
	cred_t *credp)
{
	int rval;

	(void) ldi_ioctl(tems.ts_hdl, VIS_CONSCOPY,
	    (intptr_t)pma, FKIOCTL, credp, &rval);
}

/*
 * This function is used to show or hide a rectangluar monochrom
 * pixel inverting, text block cursor via the underlying framebuffer.
 */
void
tems_cursor_layered(
	struct vis_conscursor *pca,
	cred_t *credp)
{
	int rval;

	(void) ldi_ioctl(tems.ts_hdl, VIS_CONSCURSOR,
	    (intptr_t)pca, FKIOCTL, credp, &rval);
}

static void
tem_kdsetmode(int mode, cred_t *credp)
{
	int rval;

	(void) ldi_ioctl(tems.ts_hdl, KDSETMODE,
	    (intptr_t)mode, FKIOCTL, credp, &rval);

}

static void
tems_reset_colormap(cred_t *credp, enum called_from called_from)
{
	struct vis_cmap cm;
	int rval;

	if (called_from == CALLED_FROM_STANDALONE)
		return;

	switch (tems.ts_pdepth) {
	case 8:
		cm.index = 0;
		cm.count = 16;
		cm.red   = cmap4_to_24.red;   /* 8-bits (1/3 of TrueColor 24) */
		cm.blue  = cmap4_to_24.blue;  /* 8-bits (1/3 of TrueColor 24) */
		cm.green = cmap4_to_24.green; /* 8-bits (1/3 of TrueColor 24) */
		(void) ldi_ioctl(tems.ts_hdl, VIS_PUTCMAP, (intptr_t)&cm,
		    FKIOCTL, credp, &rval);
		break;
	}
}

void
tem_get_size(ushort_t *r, ushort_t *c, ushort_t *x, ushort_t *y)
{
	mutex_enter(&tems.ts_lock);
	*r = (ushort_t)tems.ts_c_dimension.height;
	*c = (ushort_t)tems.ts_c_dimension.width;
	*x = (ushort_t)tems.ts_p_dimension.width;
	*y = (ushort_t)tems.ts_p_dimension.height;
	mutex_exit(&tems.ts_lock);
}

void
tem_register_modechg_cb(tem_modechg_cb_t func, tem_modechg_cb_arg_t arg)
{
	mutex_enter(&tems.ts_lock);

	tems.ts_modechg_cb = func;
	tems.ts_modechg_arg = arg;

	mutex_exit(&tems.ts_lock);
}

/*
 * This function is to scroll up the OBP output, which has
 * different screen height and width with our kernel console.
 */
static void
tem_prom_scroll_up(struct tem_vt_state *tem, int nrows, cred_t *credp,
    enum called_from called_from)
{
	struct vis_conscopy	ma;
	int	ncols, width;

	/* copy */
	ma.s_row = nrows * tems.ts_font.height;
	ma.e_row = tems.ts_p_dimension.height - 1;
	ma.t_row = 0;

	ma.s_col = 0;
	ma.e_col = tems.ts_p_dimension.width - 1;
	ma.t_col = 0;

	tems_safe_copy(&ma, credp, called_from);

	/* clear */
	width = tems.ts_font.width;
	ncols = (tems.ts_p_dimension.width + (width - 1))/ width;

	tem_safe_pix_cls_range(tem, 0, nrows, tems.ts_p_offset.y,
	    0, ncols, 0, B_TRUE, credp, called_from);
}

#define	PROM_DEFAULT_FONT_HEIGHT	22
#define	PROM_DEFAULT_WINDOW_TOP		0x8a

/*
 * This function is to compute the starting row of the console, according to
 * PROM cursor's position. Here we have to take different fonts into account.
 */
static int
tem_adjust_row(struct tem_vt_state *tem, int prom_row, cred_t *credp,
    enum called_from called_from)
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
	    tems.ts_p_offset.y;
	tem_row = (tem_y + tems.ts_font.height - 1) /
	    tems.ts_font.height - 1;

	if (tem_row < 0) {
		tem_row = 0;
	} else if (tem_row >= (tems.ts_c_dimension.height - 1)) {
		/*
		 * Scroll up the prom outputs if the PROM cursor's position is
		 * below our tem's lower boundary.
		 */
		scroll_up_lines = tem_row -
		    (tems.ts_c_dimension.height - 1);
		tem_prom_scroll_up(tem, scroll_up_lines, credp, called_from);
		tem_row = tems.ts_c_dimension.height - 1;
	}

	return (tem_row);
}

void
tem_pix_align(struct tem_vt_state *tem, cred_t *credp,
    enum called_from called_from)
{
	uint32_t row = 0;
	uint32_t col = 0;

	if (plat_stdout_is_framebuffer()) {
		plat_tem_hide_prom_cursor();

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
		row = tem_adjust_row(tem, row, credp, called_from);

		/* first line of our kernel console output */
		tem->tvs_first_line = row + 1;

		/* re-set and align cusror position */
		tem->tvs_s_cursor.row = tem->tvs_c_cursor.row =
		    (screen_pos_t)row;
		tem->tvs_s_cursor.col = tem->tvs_c_cursor.col = 0;
	} else {
		tem_safe_reset_display(tem, credp, called_from, B_TRUE, B_TRUE);
	}
}

static void
tems_get_inverses(boolean_t *p_inverse, boolean_t *p_inverse_screen)
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
tems_get_initial_color(tem_color_t *pcolor)
{
	boolean_t inverse, inverse_screen;
	unsigned short  flags = 0;

	pcolor->fg_color = DEFAULT_ANSI_FOREGROUND;
	pcolor->bg_color = DEFAULT_ANSI_BACKGROUND;

	if (plat_stdout_is_framebuffer()) {
		tems_get_inverses(&inverse, &inverse_screen);
		if (inverse)
			flags |= TEM_ATTR_REVERSE;
		if (inverse_screen)
			flags |= TEM_ATTR_SCREEN_REVERSE;

		if (flags != 0) {
			/*
			 * If either reverse flag is set, the screen is in
			 * white-on-black mode.  We set the bold flag to
			 * improve readability.
			 */
			flags |= TEM_ATTR_BOLD;
		} else {
			/*
			 * Otherwise, the screen is in black-on-white mode.
			 * The SPARC PROM console, which starts in this mode,
			 * uses the bright white background colour so we
			 * match it here.
			 */
			if (pcolor->bg_color == ANSI_COLOR_WHITE)
				flags |= TEM_ATTR_BRIGHT_BG;
		}
	}

	pcolor->a_flags = flags;
}

uchar_t
tem_get_fbmode(tem_vt_state_t tem_arg)
{
	struct tem_vt_state *tem = (struct tem_vt_state *)tem_arg;

	uchar_t fbmode;

	mutex_enter(&tem->tvs_lock);
	fbmode = tem->tvs_fbmode;
	mutex_exit(&tem->tvs_lock);

	return (fbmode);
}

void
tem_set_fbmode(tem_vt_state_t tem_arg, uchar_t fbmode, cred_t *credp)
{
	struct tem_vt_state *tem = (struct tem_vt_state *)tem_arg;

	mutex_enter(&tems.ts_lock);
	mutex_enter(&tem->tvs_lock);

	if (fbmode == tem->tvs_fbmode) {
		mutex_exit(&tem->tvs_lock);
		mutex_exit(&tems.ts_lock);
		return;
	}

	tem->tvs_fbmode = fbmode;

	if (tem->tvs_isactive) {
		tem_kdsetmode(tem->tvs_fbmode, credp);
		if (fbmode == KD_TEXT)
			tem_safe_unblank_screen(tem, credp, CALLED_FROM_NORMAL);
	}

	mutex_exit(&tem->tvs_lock);
	mutex_exit(&tems.ts_lock);
}

void
tem_activate(tem_vt_state_t tem_arg, boolean_t unblank, cred_t *credp)
{
	struct tem_vt_state *tem = (struct tem_vt_state *)tem_arg;

	mutex_enter(&tems.ts_lock);
	tems.ts_active = tem;

	mutex_enter(&tem->tvs_lock);
	tem->tvs_isactive = B_TRUE;

	tem_kdsetmode(tem->tvs_fbmode, credp);

	if (unblank)
		tem_safe_unblank_screen(tem, credp, CALLED_FROM_NORMAL);

	mutex_exit(&tem->tvs_lock);
	mutex_exit(&tems.ts_lock);
}

void
tem_switch(tem_vt_state_t tem_arg1, tem_vt_state_t tem_arg2, cred_t *credp)
{
	struct tem_vt_state *cur = (struct tem_vt_state *)tem_arg1;
	struct tem_vt_state *tobe = (struct tem_vt_state *)tem_arg2;

	mutex_enter(&tems.ts_lock);
	mutex_enter(&tobe->tvs_lock);
	mutex_enter(&cur->tvs_lock);

	tems.ts_active = tobe;
	cur->tvs_isactive = B_FALSE;
	tobe->tvs_isactive = B_TRUE;

	mutex_exit(&cur->tvs_lock);

	if (cur->tvs_fbmode != tobe->tvs_fbmode)
		tem_kdsetmode(tobe->tvs_fbmode, credp);

	if (tobe->tvs_fbmode == KD_TEXT)
		tem_safe_unblank_screen(tobe, credp, CALLED_FROM_NORMAL);

	mutex_exit(&tobe->tvs_lock);
	mutex_exit(&tems.ts_lock);
}
