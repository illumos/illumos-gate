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
 * Copyright 2016 Joyent, Inc.
 * Copyright 2021 Toomas Soome <tsoome@me.com>
 * Copyright 2021 RackTop Systems, Inc.
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
 * the terminal is activated.
 *
 * Data written to a virtual terminal is composed of characters which
 * should be displayed on the screen when this virtual terminal is
 * activated, fg/bg colors of these characters, and other control
 * information (escape sequence, etc).
 *
 * When data is passed to a virtual terminal it first is parsed for
 * control information by tem_parse().  Subsequently the character
 * and color data are written to tvs_screen_buf.
 * They are saved in buffer in order to refresh the screen when this
 * terminal is activated.  If the terminal is currently active, the data
 * (characters and colors) are also written to the physical screen by
 * invoking a callback function, tem_text_callbacks() or tem_pix_callbacks().
 *
 * When rendering data to the framebuffer, if the framebuffer is in
 * VIS_PIXEL mode, the character data will first be converted to pixel
 * data using tem_pix_bit2pix(), and then the pixels get displayed
 * on the physical screen.  We only store the character and color data in
 * tem_vt_state since the bit2pix conversion only happens when actually
 * rendering to the physical framebuffer.
 *
 * Color support:
 * Text mode can only support standard system colors, 4-bit [0-15] indexed.
 * On framebuffer devices, we can aditionally use [16-255] or truecolor.
 * Additional colors can be used via CSI 38 and CSI 48 sequences.
 * CSI 38/48;5 is using indexed colors [0-255], CSI 38/48;2 does
 * specify color by RGB triple.
 *
 * While sending glyphs to display, we need to process glyph attributes:
 * TEM_ATTR_BOLD will cause BOLD font to be used (or BRIGHT color if we
 * we use indexed color [0-7]).
 * We ignore TEM_ATTR_BRIGHT_FG/TEM_ATTR_BRIGHT_BG with RGB colors.
 * TEM_ATTR_REVERSE and TEM_ATTR_SCREEN_REVERSE will cause fg and bg to be
 * swapped.
 */

#include <stand.h>
#include <sys/ascii.h>
#include <sys/errno.h>
#include <sys/tem_impl.h>
#ifdef _HAVE_TEM_FIRMWARE
#include <sys/promif.h>
#endif /* _HAVE_TEM_FIRMWARE */
#include <sys/consplat.h>
#include <sys/kd.h>
#include <stdbool.h>

/* Terminal emulator internal helper functions */
static void	tems_setup_terminal(struct vis_devinit *, size_t, size_t);
static void	tems_modechange_callback(struct vis_modechg_arg *,
		    struct vis_devinit *);

static void	tems_reset_colormap(void);

static void	tem_free_buf(struct tem_vt_state *);
static void	tem_internal_init(struct tem_vt_state *, bool, bool);
static void	tems_get_initial_color(tem_color_t *pcolor);

static void	tem_control(struct tem_vt_state *, uint8_t);
static void	tem_setparam(struct tem_vt_state *, int, int);
static void	tem_selgraph(struct tem_vt_state *);
static void	tem_chkparam(struct tem_vt_state *, uint8_t);
static void	tem_getparams(struct tem_vt_state *, uint8_t);
static void	tem_outch(struct tem_vt_state *, tem_char_t);
static void	tem_parse(struct tem_vt_state *, tem_char_t);

static void	tem_new_line(struct tem_vt_state *);
static void	tem_cr(struct tem_vt_state *);
static void	tem_lf(struct tem_vt_state *);
static void	tem_send_data(struct tem_vt_state *);
static void	tem_cls(struct tem_vt_state *);
static void	tem_tab(struct tem_vt_state *);
static void	tem_back_tab(struct tem_vt_state *);
static void	tem_clear_tabs(struct tem_vt_state *, int);
static void	tem_set_tab(struct tem_vt_state *);
static void	tem_mv_cursor(struct tem_vt_state *, int, int);
static void	tem_shift(struct tem_vt_state *, int, int);
static void	tem_scroll(struct tem_vt_state *, int, int, int, int);
static void	tem_clear_chars(struct tem_vt_state *tem,
			int count, screen_pos_t row, screen_pos_t col);
static void	tem_copy_area(struct tem_vt_state *tem,
			screen_pos_t s_col, screen_pos_t s_row,
			screen_pos_t e_col, screen_pos_t e_row,
			screen_pos_t t_col, screen_pos_t t_row);
static void	tem_bell(struct tem_vt_state *tem);
static void	tem_pix_clear_prom_output(struct tem_vt_state *tem);

static void	tem_virtual_cls(struct tem_vt_state *, size_t, screen_pos_t,
		    screen_pos_t);
static void	tem_virtual_display(struct tem_vt_state *, term_char_t *,
		    size_t, screen_pos_t, screen_pos_t);
static void	tem_align_cursor(struct tem_vt_state *tem);

static void	tem_check_first_time(struct tem_vt_state *tem);
static void	tem_reset_display(struct tem_vt_state *, bool, bool);
static void	tem_terminal_emulate(struct tem_vt_state *, uint8_t *, int);
static void	tem_text_cursor(struct tem_vt_state *, short);
static void	tem_text_cls(struct tem_vt_state *,
		    int count, screen_pos_t row, screen_pos_t col);
static void	tem_pix_display(struct tem_vt_state *, term_char_t *,
		    int, screen_pos_t, screen_pos_t);
static void	tem_pix_copy(struct tem_vt_state *,
		    screen_pos_t, screen_pos_t,
		    screen_pos_t, screen_pos_t,
		    screen_pos_t, screen_pos_t);
static void	tem_pix_cursor(struct tem_vt_state *, short);
static void	tem_get_attr(struct tem_vt_state *, text_color_t *,
		    text_color_t *, text_attr_t *, uint8_t);
static void	tem_get_color(struct tem_vt_state *,
		    text_color_t *, text_color_t *, term_char_t *);
static void	tem_set_color(text_color_t *, color_t *);
static void	tem_pix_align(struct tem_vt_state *);
static void	tem_text_display(struct tem_vt_state *, term_char_t *, int,
		    screen_pos_t, screen_pos_t);
static void	tem_text_copy(struct tem_vt_state *,
		    screen_pos_t, screen_pos_t, screen_pos_t, screen_pos_t,
		    screen_pos_t, screen_pos_t);
static void	tem_pix_bit2pix(struct tem_vt_state *, term_char_t *);
static void	tem_pix_cls_range(struct tem_vt_state *, screen_pos_t, int,
		    int, screen_pos_t, int, int, bool);
static void	tem_pix_cls(struct tem_vt_state *, int,
		    screen_pos_t, screen_pos_t);

static void	bit_to_pix32(struct tem_vt_state *tem, tem_char_t c,
		    text_color_t fg_color, text_color_t bg_color);

/*
 * Globals
 */
tem_state_t	tems;	/* common term info */

tem_callbacks_t tem_text_callbacks = {
	.tsc_display = &tem_text_display,
	.tsc_copy = &tem_text_copy,
	.tsc_cursor = &tem_text_cursor,
	.tsc_bit2pix = NULL,
	.tsc_cls = &tem_text_cls
};
tem_callbacks_t tem_pix_callbacks = {
	.tsc_display = &tem_pix_display,
	.tsc_copy = &tem_pix_copy,
	.tsc_cursor = &tem_pix_cursor,
	.tsc_bit2pix = &tem_pix_bit2pix,
	.tsc_cls = &tem_pix_cls
};

#define	tem_callback_display	(*tems.ts_callbacks->tsc_display)
#define	tem_callback_copy	(*tems.ts_callbacks->tsc_copy)
#define	tem_callback_cursor	(*tems.ts_callbacks->tsc_cursor)
#define	tem_callback_cls	(*tems.ts_callbacks->tsc_cls)
#define	tem_callback_bit2pix	(*tems.ts_callbacks->tsc_bit2pix)

static void
tem_add(struct tem_vt_state *tem)
{
	list_insert_head(&tems.ts_list, tem);
}

/*
 * This is the main entry point to the module.  It handles output requests
 * during normal system operation, when (e.g.) mutexes are available.
 */
void
tem_write(tem_vt_state_t tem_arg, uint8_t *buf, ssize_t len)
{
	struct tem_vt_state *tem = (struct tem_vt_state *)tem_arg;

	if (tems.ts_initialized == 0 || tem->tvs_initialized == 0) {
		return;
	}

	tem_check_first_time(tem);
	tem_terminal_emulate(tem, buf, len);
}

static void
tem_internal_init(struct tem_vt_state *ptem,
    bool init_color, bool clear_screen)
{
	size_t size, width, height;

	if (tems.ts_display_mode == VIS_PIXEL) {
		ptem->tvs_pix_data_size = tems.ts_pix_data_size;
		ptem->tvs_pix_data = malloc(ptem->tvs_pix_data_size);
	}

	ptem->tvs_stateflags = TVS_AUTOWRAP;

	width = tems.ts_c_dimension.width;
	height = tems.ts_c_dimension.height;

	size = width * sizeof (tem_char_t);
	ptem->tvs_outbuf = malloc(size);
	if (ptem->tvs_outbuf == NULL)
		panic("out of memory in tem_internal_init()\n");

	ptem->tvs_maxtab = width / 8;
	ptem->tvs_tabs = calloc(ptem->tvs_maxtab, sizeof (*ptem->tvs_tabs));
	if (ptem->tvs_tabs == NULL)
		panic("out of memory in tem_internal_init()\n");

	tem_reset_display(ptem, clear_screen, init_color);

	ptem->tvs_utf8_left = 0;
	ptem->tvs_utf8_partial = 0;

	ptem->tvs_initialized  = true;

	/*
	 * Out of memory is not fatal there, without the screen history,
	 * we can not optimize the screen copy.
	 */
	size = width * height * sizeof (term_char_t);
	ptem->tvs_screen_buf = malloc(size);
	tem_virtual_cls(ptem, width * height, 0, 0);
}

int
tem_initialized(tem_vt_state_t tem_arg)
{
	struct tem_vt_state *ptem = (struct tem_vt_state *)tem_arg;

	return (ptem->tvs_initialized);
}

tem_vt_state_t
tem_init(void)
{
	struct tem_vt_state *ptem;

	ptem = calloc(1, sizeof (struct tem_vt_state));
	if (ptem == NULL)
		return ((tem_vt_state_t)ptem);

	ptem->tvs_isactive = false;
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
		return ((tem_vt_state_t)ptem);
	}

	tem_internal_init(ptem, true, false);
	tem_add(ptem);

	return ((tem_vt_state_t)ptem);
}

/*
 * re-init the tem after video mode has changed and tems_info has
 * been re-inited.
 */
static void
tem_reinit(struct tem_vt_state *tem, bool reset_display)
{
	tem_free_buf(tem); /* only free virtual buffers */

	/* reserve color */
	tem_internal_init(tem, false, reset_display);
}

static void
tem_free_buf(struct tem_vt_state *tem)
{
	free(tem->tvs_outbuf);
	tem->tvs_outbuf = NULL;

	free(tem->tvs_pix_data);
	tem->tvs_pix_data = NULL;

	free(tem->tvs_screen_buf);
	tem->tvs_screen_buf = NULL;

	free(tem->tvs_tabs);
	tem->tvs_tabs = NULL;
}

static int
tems_failed(bool finish_ioctl)
{
	if (finish_ioctl && tems.ts_hdl != NULL)
		(void) tems.ts_hdl->c_ioctl(tems.ts_hdl, VIS_DEVFINI, NULL);

	tems.ts_hdl = NULL;
	return (ENXIO);
}

/*
 * Only called once during boot
 */
int
tem_info_init(struct console *cp)
{
	int			ret;
	struct vis_devinit	temargs;
	size_t height = 0;
	size_t width = 0;
	struct tem_vt_state *p;

	if (tems.ts_initialized) {
		return (0);
	}

	list_create(&tems.ts_list, sizeof (struct tem_vt_state),
	    __offsetof(struct tem_vt_state, tvs_list_node));
	tems.ts_active = NULL;

	tems.ts_hdl = cp;
	bzero(&temargs, sizeof (temargs));
	temargs.modechg_cb  = (vis_modechg_cb_t)tems_modechange_callback;
	temargs.modechg_arg = NULL;

	/*
	 * Initialize the console and get the device parameters
	 */
	if (cp->c_ioctl(cp, VIS_DEVINIT, &temargs) != 0) {
		printf("terminal emulator: Compatible fb not found\n");
		ret = tems_failed(false);
		return (ret);
	}

	/* Make sure the fb driver and terminal emulator versions match */
	if (temargs.version != VIS_CONS_REV) {
		printf(
		    "terminal emulator: VIS_CONS_REV %d (see sys/visual_io.h) "
		    "of console fb driver not supported\n", temargs.version);
		ret = tems_failed(true);
		return (ret);
	}

	/* other sanity checks */
	if (!((temargs.depth == 4) || (temargs.depth == 8) ||
	    (temargs.depth == 15) || (temargs.depth == 16) ||
	    (temargs.depth == 24) || (temargs.depth == 32))) {
		printf("terminal emulator: unsupported depth\n");
		ret = tems_failed(true);
		return (ret);
	}

	if ((temargs.mode != VIS_TEXT) && (temargs.mode != VIS_PIXEL)) {
		printf("terminal emulator: unsupported mode\n");
		ret = tems_failed(true);
		return (ret);
	}

	plat_tem_get_prom_size(&height, &width);

	/*
	 * Initialize the common terminal emulator info
	 */
	tems_setup_terminal(&temargs, height, width);

	tems_reset_colormap();
	tems_get_initial_color(&tems.ts_init_color);

	tems.ts_initialized = 1; /* initialization flag */

	for (p = list_head(&tems.ts_list); p != NULL;
	    p = list_next(&tems.ts_list, p)) {
		tem_internal_init(p, true, false);
		if (temargs.mode == VIS_PIXEL)
			tem_pix_align(p);
	}

	return (0);
}

#define	TEMS_DEPTH_DIFF		0x01
#define	TEMS_DIMENSION_DIFF	0x02

static uint8_t
tems_check_videomode(struct vis_devinit *tp)
{
	uint8_t result = 0;

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
	if (tems.update_font == true)
		result |= TEMS_DIMENSION_DIFF;

	return (result);
}

static int
env_screen_nounset(struct env_var *ev __unused)
{
	if (tems.ts_p_dimension.width == 0 &&
	    tems.ts_p_dimension.height == 0)
		return (0);
	return (EPERM);
}

static void
tems_setup_font(screen_size_t height, screen_size_t width)
{
	bitmap_data_t *font_data;

	/*
	 * set_font() will select an appropriate sized font for
	 * the number of rows and columns selected.  If we don't
	 * have a font that will fit, then it will use the
	 * default builtin font and adjust the rows and columns
	 * to fit on the screen.
	 */
	font_data = set_font(&tems.ts_c_dimension.height,
	    &tems.ts_c_dimension.width, height, width);

	if (font_data == NULL)
		panic("out of memory");

	/*
	 * To use loaded font, we assign the loaded font data to tems.ts_font.
	 * In case of next load, the previously loaded data is freed
	 * when loading the new font.
	 */
	for (int i = 0; i < VFNT_MAPS; i++) {
		tems.ts_font.vf_map[i] =
		    font_data->font->vf_map[i];
		tems.ts_font.vf_map_count[i] =
		    font_data->font->vf_map_count[i];
	}

	tems.ts_font.vf_bytes = font_data->font->vf_bytes;
	tems.ts_font.vf_width = font_data->font->vf_width;
	tems.ts_font.vf_height = font_data->font->vf_height;
}

static void
tems_setup_terminal(struct vis_devinit *tp, size_t height, size_t width)
{
	char env[8];

	tems.ts_pdepth = tp->depth;
	tems.ts_linebytes = tp->linebytes;
	tems.ts_display_mode = tp->mode;
	tems.ts_color_map = tp->color_map;

	switch (tp->mode) {
	case VIS_TEXT:
		/* Set fake pixel dimensions to assist set_font() */
		tems.ts_p_dimension.width = 0;
		tems.ts_p_dimension.height = 0;
		tems.ts_c_dimension.width = tp->width;
		tems.ts_c_dimension.height = tp->height;
		tems.ts_callbacks = &tem_text_callbacks;

		tems_setup_font(16 * tp->height + BORDER_PIXELS,
		    8 * tp->width + BORDER_PIXELS);

		/* ensure the following are not set for text mode */
		unsetenv("screen-height");
		unsetenv("screen-width");
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
		tems.ts_callbacks = &tem_pix_callbacks;

		tems_setup_font(tp->height, tp->width);

		snprintf(env, sizeof (env), "%d", tems.ts_p_dimension.height);
		env_setenv("screen-height", EV_VOLATILE | EV_NOHOOK, env,
		    env_noset, env_screen_nounset);
		snprintf(env, sizeof (env), "%d", tems.ts_p_dimension.width);
		env_setenv("screen-width", EV_VOLATILE | EV_NOHOOK, env,
		    env_noset, env_screen_nounset);

		tems.ts_p_offset.y = (tems.ts_p_dimension.height -
		    (tems.ts_c_dimension.height * tems.ts_font.vf_height)) / 2;
		tems.ts_p_offset.x = (tems.ts_p_dimension.width -
		    (tems.ts_c_dimension.width * tems.ts_font.vf_width)) / 2;
		tems.ts_pix_data_size =
		    tems.ts_font.vf_width * tems.ts_font.vf_height;
		tems.ts_pix_data_size *= 4;
		tems.ts_pdepth = tp->depth;

		break;
	}

	tems.update_font = false;

	snprintf(env, sizeof (env), "%d", tems.ts_c_dimension.height);
	env_setenv("screen-#rows", EV_VOLATILE | EV_NOHOOK, env,
	    env_noset, env_nounset);
	snprintf(env, sizeof (env), "%d", tems.ts_c_dimension.width);
	env_setenv("screen-#cols", EV_VOLATILE | EV_NOHOOK, env,
	    env_noset, env_nounset);

	snprintf(env, sizeof (env), "%dx%d", tems.ts_font.vf_width,
	    tems.ts_font.vf_height);
	env_setenv("screen-font", EV_VOLATILE | EV_NOHOOK, env, NULL,
	    NULL);
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
tems_modechange_callback(struct vis_modechg_arg *arg __unused,
    struct vis_devinit *devinit)
{
	uint8_t diff;
	struct tem_vt_state *p;
	tem_modechg_cb_t cb;
	tem_modechg_cb_arg_t cb_arg;
	size_t height = 0;
	size_t width = 0;
	int state;

	diff = tems_check_videomode(devinit);
	if (diff == 0) {
		/*
		 * This is color related change, reset color and redraw the
		 * screen. Only need to reinit the active tem.
		 */
		struct tem_vt_state *active = tems.ts_active;
		tems_get_initial_color(&tems.ts_init_color);
		active->tvs_fg_color = tems.ts_init_color.fg_color;
		active->tvs_bg_color = tems.ts_init_color.bg_color;
		active->tvs_flags = tems.ts_init_color.a_flags;
		tem_reinit(active, true);
		return;
	}

	diff = diff & TEMS_DIMENSION_DIFF;

	if (diff == 0) {
		/*
		 * Only need to reinit the active tem.
		 */
		struct tem_vt_state *active = tems.ts_active;
		tems.ts_pdepth = devinit->depth;
		/* color depth did change, reset colors */
		tems_reset_colormap();
		tems_get_initial_color(&tems.ts_init_color);
		tem_reinit(active, true);

		return;
	}

	plat_tem_get_prom_size(&height, &width);

	state = tems.ts_initialized;
	tems.ts_initialized = 0;	/* stop all output */
	tems_setup_terminal(devinit, height, width);

	tems_reset_colormap();
	tems_get_initial_color(&tems.ts_init_color);
	tems.ts_initialized = state;	/* restore state */

	for (p = list_head(&tems.ts_list); p != NULL;
	    p = list_next(&tems.ts_list, p)) {
		tem_reinit(p, p->tvs_isactive);
	}


	if (tems.ts_modechg_cb == NULL) {
		return;
	}

	cb = tems.ts_modechg_cb;
	cb_arg = tems.ts_modechg_arg;

	cb(cb_arg);
}

/*
 * This function is used to clear entire screen via the underlying framebuffer
 * driver.
 */
int
tems_cls(struct vis_consclear *pda)
{
	if (tems.ts_hdl == NULL)
		return (1);
	return (tems.ts_hdl->c_ioctl(tems.ts_hdl, VIS_CONSCLEAR, pda));
}

/*
 * This function is used to display a rectangular blit of data
 * of a given size and location via the underlying framebuffer driver.
 * The blit can be as small as a pixel or as large as the screen.
 */
void
tems_display(struct vis_consdisplay *pda)
{
	if (tems.ts_hdl != NULL)
		(void) tems.ts_hdl->c_ioctl(tems.ts_hdl, VIS_CONSDISPLAY, pda);
}

/*
 * This function is used to invoke a block copy operation in the
 * underlying framebuffer driver.  Rectangle copies are how scrolling
 * is implemented, as well as horizontal text shifting escape seqs.
 * such as from vi when deleting characters and words.
 */
void
tems_copy(struct vis_conscopy *pma)
{
	if (tems.ts_hdl != NULL)
		(void) tems.ts_hdl->c_ioctl(tems.ts_hdl, VIS_CONSCOPY, pma);
}

/*
 * This function is used to show or hide a rectangluar monochrom
 * pixel inverting, text block cursor via the underlying framebuffer.
 */
void
tems_cursor(struct vis_conscursor *pca)
{
	if (tems.ts_hdl != NULL)
		(void) tems.ts_hdl->c_ioctl(tems.ts_hdl, VIS_CONSCURSOR, pca);
}

static void
tem_kdsetmode(int mode)
{
	if (tems.ts_hdl != NULL) {
		(void) tems.ts_hdl->c_ioctl(tems.ts_hdl, KDSETMODE,
		    (void *)(intptr_t)mode);
	}
}

static void
tems_reset_colormap(void)
{
	struct vis_cmap cm;

	switch (tems.ts_pdepth) {
	case 8:
		cm.index = 0;
		cm.count = 16;
		/* 8-bits (1/3 of TrueColor 24) */
		cm.red   = (uint8_t *)cmap4_to_24.red;
		/* 8-bits (1/3 of TrueColor 24) */
		cm.blue  = (uint8_t *)cmap4_to_24.blue;
		/* 8-bits (1/3 of TrueColor 24) */
		cm.green = (uint8_t *)cmap4_to_24.green;
		if (tems.ts_hdl != NULL)
			(void) tems.ts_hdl->c_ioctl(tems.ts_hdl,
			    VIS_PUTCMAP, &cm);
		break;
	}
}

void
tem_get_size(uint16_t *r, uint16_t *c, uint16_t *x, uint16_t *y)
{
	*r = (uint16_t)tems.ts_c_dimension.height;
	*c = (uint16_t)tems.ts_c_dimension.width;
	*x = (uint16_t)tems.ts_p_dimension.width;
	*y = (uint16_t)tems.ts_p_dimension.height;
}

/*
 * Loader extension. Store important data in environment. Intended to be used
 * just before booting the OS to make the data available in kernel
 * environment module.
 */
void
tem_save_state(void)
{
	struct tem_vt_state *active = tems.ts_active;
	char buf[80];

	/*
	 * We already have in environment:
	 * tem.inverse, tem.inverse_screen
	 * tem.fg_color, tem.bg_color.
	 * So we only need to add the position of the cursor.
	 */

	if (active != NULL) {
		snprintf(buf, sizeof (buf), "%d", active->tvs_c_cursor.col);
		setenv("tem.cursor.col", buf, 1);
		snprintf(buf, sizeof (buf), "%d", active->tvs_c_cursor.row);
		setenv("tem.cursor.row", buf, 1);
	}
}

void
tem_register_modechg_cb(tem_modechg_cb_t func, tem_modechg_cb_arg_t arg)
{
	tems.ts_modechg_cb = func;
	tems.ts_modechg_arg = arg;
}

/*
 * This function is to scroll up the OBP output, which has
 * different screen height and width with our kernel console.
 */
static void
tem_prom_scroll_up(struct tem_vt_state *tem, int nrows)
{
	struct vis_conscopy	ma;
	int	ncols, width;

	/* copy */
	ma.s_row = nrows * tems.ts_font.vf_height;
	ma.e_row = tems.ts_p_dimension.height - 1;
	ma.t_row = 0;

	ma.s_col = 0;
	ma.e_col = tems.ts_p_dimension.width - 1;
	ma.t_col = 0;

	tems_copy(&ma);

	/* clear */
	width = tems.ts_font.vf_width;
	ncols = (tems.ts_p_dimension.width + (width - 1)) / width;

	tem_pix_cls_range(tem, 0, nrows, tems.ts_p_offset.y,
	    0, ncols, 0, true);
}

/*
 * This function is to compute the starting row of the console, according to
 * PROM cursor's position. Here we have to take different fonts into account.
 */
static int
tem_adjust_row(struct tem_vt_state *tem, int prom_row)
{
	int	tem_row;
	int	tem_y;
	int	prom_charheight = 0;
	int	prom_window_top = 0;
	int	scroll_up_lines;

	plat_tem_get_prom_font_size(&prom_charheight, &prom_window_top);
	if (prom_charheight == 0)
		prom_charheight = tems.ts_font.vf_height;

	tem_y = (prom_row + 1) * prom_charheight + prom_window_top -
	    tems.ts_p_offset.y;
	tem_row = (tem_y + tems.ts_font.vf_height - 1) /
	    tems.ts_font.vf_height - 1;

	if (tem_row < 0) {
		tem_row = 0;
	} else if (tem_row >= (tems.ts_c_dimension.height - 1)) {
		/*
		 * Scroll up the prom outputs if the PROM cursor's position is
		 * below our tem's lower boundary.
		 */
		scroll_up_lines = tem_row -
		    (tems.ts_c_dimension.height - 1);
		tem_prom_scroll_up(tem, scroll_up_lines);
		tem_row = tems.ts_c_dimension.height - 1;
	}

	return (tem_row);
}

static void
tem_pix_align(struct tem_vt_state *tem)
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
		row = tem_adjust_row(tem, row);

		/* first line of our kernel console output */
		tem->tvs_first_line = row + 1;

		/* re-set and align cursor position */
		tem->tvs_s_cursor.row = tem->tvs_c_cursor.row =
		    (screen_pos_t)row;
		tem->tvs_s_cursor.col = tem->tvs_c_cursor.col = 0;
	} else {
		tem_reset_display(tem, true, true);
	}
}

static void
tems_get_inverses(bool *p_inverse, bool *p_inverse_screen)
{
	int i_inverse = 0;
	int i_inverse_screen = 0;

	plat_tem_get_inverses(&i_inverse, &i_inverse_screen);

	*p_inverse = i_inverse != 0;
	*p_inverse_screen = i_inverse_screen != 0;
}

/*
 * Get the foreground/background color and attributes from environment.
 */
static void
tems_get_initial_color(tem_color_t *pcolor)
{
	bool inverse, inverse_screen;
	unsigned short  flags = 0;
	uint8_t fg, bg;

	fg = DEFAULT_ANSI_FOREGROUND;
	bg = DEFAULT_ANSI_BACKGROUND;
	plat_tem_get_colors(&fg, &bg);
	pcolor->fg_color.n = fg;
	pcolor->bg_color.n = bg;

	tems_get_inverses(&inverse, &inverse_screen);
	if (inverse)
		flags |= TEM_ATTR_REVERSE;
	if (inverse_screen)
		flags |= TEM_ATTR_SCREEN_REVERSE;

	if (flags != 0) {
		/*
		 * The reverse attribute is set.
		 * In case of black on white we want bright white for BG.
		 */
		if (pcolor->fg_color.n == ANSI_COLOR_WHITE)
			flags |= TEM_ATTR_BRIGHT_BG;

		/*
		 * For white on black, unset the bright attribute we
		 * had set to have bright white background.
		 */
		if (pcolor->fg_color.n == ANSI_COLOR_BLACK)
			flags &= ~TEM_ATTR_BRIGHT_BG;
	} else {
		/*
		 * In case of black on white we want bright white for BG.
		 */
		if (pcolor->bg_color.n == ANSI_COLOR_WHITE)
			flags |= TEM_ATTR_BRIGHT_BG;
	}

	pcolor->a_flags = flags;
}

void
tem_activate(tem_vt_state_t tem_arg, bool unblank)
{
	struct tem_vt_state *tem = (struct tem_vt_state *)tem_arg;

	tems.ts_active = tem;
	tem->tvs_isactive = true;

	tem_kdsetmode(tem->tvs_fbmode);

	if (unblank)
		tem_cls(tem);
}

static void
tem_check_first_time(struct tem_vt_state *tem)
{
	static int first_time = 1;

	/*
	 * Realign the console cursor. We did this in tem_init().
	 * However, drivers in the console stream may emit additional
	 * messages before we are ready. This causes text overwrite
	 * on the screen. This is a workaround.
	 */
	if (!first_time)
		return;

	first_time = 0;
	if (tems.ts_display_mode == VIS_TEXT)
		tem_text_cursor(tem, VIS_GET_CURSOR);
	else
		tem_pix_cursor(tem, VIS_GET_CURSOR);
	tem_align_cursor(tem);
}

/* Process partial UTF-8 sequence. */
static void
tem_input_partial(struct tem_vt_state *tem)
{
	unsigned i;
	tem_char_t c;

	if (tem->tvs_utf8_left == 0)
		return;

	for (i = 0; i < sizeof (tem->tvs_utf8_partial); i++) {
		c = (tem->tvs_utf8_partial >> (24 - (i << 3))) & 0xff;
		if (c != 0) {
			tem_parse(tem, c);
		}
	}
	tem->tvs_utf8_left = 0;
	tem->tvs_utf8_partial = 0;
}

/*
 * Handle UTF-8 sequences.
 */
static void
tem_input_byte(struct tem_vt_state *tem, uint8_t c)
{
	/*
	 * Check for UTF-8 code points. In case of error fall back to
	 * 8-bit code. As we only have 8859-1 fonts for console, this will set
	 * the limits on what chars we actually can display, therefore we
	 * have to return to this code once we have solved the font issue.
	 */
	if ((c & 0x80) == 0x00) {
		/* One-byte sequence. */
		tem_input_partial(tem);
		tem_parse(tem, c);
		return;
	}
	if ((c & 0xe0) == 0xc0) {
		/* Two-byte sequence. */
		tem_input_partial(tem);
		tem->tvs_utf8_left = 1;
		tem->tvs_utf8_partial = c;
		return;
	}
	if ((c & 0xf0) == 0xe0) {
		/* Three-byte sequence. */
		tem_input_partial(tem);
		tem->tvs_utf8_left = 2;
		tem->tvs_utf8_partial = c;
		return;
	}
	if ((c & 0xf8) == 0xf0) {
		/* Four-byte sequence. */
		tem_input_partial(tem);
		tem->tvs_utf8_left = 3;
		tem->tvs_utf8_partial = c;
		return;
	}
	if ((c & 0xc0) == 0x80) {
		/* Invalid state? */
		if (tem->tvs_utf8_left == 0) {
			tem_parse(tem, c);
			return;
		}
		tem->tvs_utf8_left--;
		tem->tvs_utf8_partial = (tem->tvs_utf8_partial << 8) | c;
		if (tem->tvs_utf8_left == 0) {
			tem_char_t v, u;
			uint8_t b;

			/*
			 * Transform the sequence of 2 to 4 bytes to
			 * unicode number.
			 */
			v = 0;
			u = tem->tvs_utf8_partial;
			b = (u >> 24) & 0xff;
			if (b != 0) {		/* Four-byte sequence */
				v = b & 0x07;
				b = (u >> 16) & 0xff;
				v = (v << 6) | (b & 0x3f);
				b = (u >> 8) & 0xff;
				v = (v << 6) | (b & 0x3f);
				b = u & 0xff;
				v = (v << 6) | (b & 0x3f);
			} else if ((b = (u >> 16) & 0xff) != 0) {
				v = b & 0x0f;	/* Three-byte sequence */
				b = (u >> 8) & 0xff;
				v = (v << 6) | (b & 0x3f);
				b = u & 0xff;
				v = (v << 6) | (b & 0x3f);
			} else if ((b = (u >> 8) & 0xff) != 0) {
				v = b & 0x1f;	/* Two-byte sequence */
				b = u & 0xff;
				v = (v << 6) | (b & 0x3f);
			}

			tem_parse(tem, v);
			tem->tvs_utf8_partial = 0;
		}
		return;
	}
	/* Anything left is illegal in UTF-8 sequence. */
	tem_input_partial(tem);
	tem_parse(tem, c);
}

/*
 * This is the main entry point into the terminal emulator.
 *
 * For each data message coming downstream, ANSI assumes that it is composed
 * of ASCII characters, which are treated as a byte-stream input to the
 * parsing state machine. All data is parsed immediately -- there is
 * no enqueing.
 */
static void
tem_terminal_emulate(struct tem_vt_state *tem, uint8_t *buf, int len)
{
	if (tem->tvs_isactive && !tem->tvs_cursor_hidden)
		tem_callback_cursor(tem, VIS_HIDE_CURSOR);

	for (; len > 0; len--, buf++)
		tem_input_byte(tem, *buf);

	/*
	 * Send the data we just got to the framebuffer.
	 */
	tem_send_data(tem);

	if (tem->tvs_isactive && !tem->tvs_cursor_hidden)
		tem_callback_cursor(tem, VIS_DISPLAY_CURSOR);
}

/*
 * send the appropriate control message or set state based on the
 * value of the control character ch
 */

static void
tem_control(struct tem_vt_state *tem, uint8_t ch)
{
	tem->tvs_state = A_STATE_START;
	switch (ch) {
	case A_BEL:
		tem_bell(tem);
		break;

	case A_BS:
		tem->tvs_stateflags &= ~TVS_WRAPPED;
		tem_mv_cursor(tem,
		    tem->tvs_c_cursor.row,
		    tem->tvs_c_cursor.col - 1);
		break;

	case A_HT:
		tem_tab(tem);
		break;

	case A_NL:
		/*
		 * tem_send_data(tem, credp, called_from);
		 * tem_new_line(tem, credp, called_from);
		 * break;
		 */

	case A_VT:
		tem_send_data(tem);
		tem_lf(tem);
		break;

	case A_FF:
		tem_send_data(tem);
		tem_cls(tem);
		break;

	case A_CR:
		tem_send_data(tem);
		tem_cr(tem);
		break;

	case A_ESC:
		tem->tvs_state = A_STATE_ESC;
		break;

	case A_CSI:
		tem->tvs_curparam = 0;
		tem->tvs_paramval = 0;
		tem->tvs_gotparam = false;
		/* clear the parameters */
		for (int i = 0; i < TEM_MAXPARAMS; i++)
			tem->tvs_params[i] = -1;
		tem->tvs_state = A_STATE_CSI;
		break;

	case A_GS:
		tem_back_tab(tem);
		break;

	default:
		break;
	}
}


/*
 * if parameters [0..count - 1] are not set, set them to the value
 * of newparam.
 */

static void
tem_setparam(struct tem_vt_state *tem, int count, int newparam)
{
	int i;

	for (i = 0; i < count; i++) {
		if (tem->tvs_params[i] == -1)
			tem->tvs_params[i] = newparam;
	}
}

/*
 * For colors 0-15 the tem is using color code translation
 * from sun colors to vga (dim_xlate and brt_xlate tables, see tem_get_color).
 * Colors 16-255 are used without translation.
 */
static void
tem_select_color(struct tem_vt_state *tem, int color, bool fg)
{
	if (color < 0 || color > 255)
		return;

	/* VGA text mode only does support 16 colors. */
	if (tems.ts_display_mode == VIS_TEXT && color > 15)
		return;

	/* Switch to use indexed colors. */
	if (fg == true) {
		tem->tvs_flags &= ~TEM_ATTR_RGB_FG;
		tem->tvs_fg_color.n = color;
	} else {
		tem->tvs_flags &= ~TEM_ATTR_RGB_BG;
		tem->tvs_bg_color.n = color;
	}

	/*
	 * For colors 0-7, make sure the BRIGHT attribute is not set.
	 */
	if (color < 8) {
		if (fg == true)
			tem->tvs_flags &= ~TEM_ATTR_BRIGHT_FG;
		else
			tem->tvs_flags &= ~TEM_ATTR_BRIGHT_BG;
		return;
	}

	/*
	 * For colors 8-15, we use color codes 0-7 and set BRIGHT attribute.
	 */
	if (color < 16) {
		if (fg == true) {
			tem->tvs_fg_color.n -= 8;
			tem->tvs_flags |= TEM_ATTR_BRIGHT_FG;
		} else {
			tem->tvs_bg_color.n -= 8;
			tem->tvs_flags |= TEM_ATTR_BRIGHT_BG;
		}
	}
}

/*
 * select graphics mode based on the param vals stored in a_params
 */
static void
tem_selgraph(struct tem_vt_state *tem)
{
	int curparam;
	int count = 0;
	int param;
	int r, g, b;

	tem->tvs_state = A_STATE_START;

	curparam = tem->tvs_curparam;
	do {
		param = tem->tvs_params[count];

		switch (param) {
		case -1:
		case 0:
			/* reset to initial normal settings */
			tem->tvs_fg_color = tems.ts_init_color.fg_color;
			tem->tvs_bg_color = tems.ts_init_color.bg_color;
			tem->tvs_flags = tems.ts_init_color.a_flags;
			break;

		case 1: /* Bold Intense */
			tem->tvs_flags |= TEM_ATTR_BOLD;
			break;

		case 2: /* Faint Intense */
			tem->tvs_flags &= ~TEM_ATTR_BOLD;
			break;

		case 4: /* Underline */
			tem->tvs_flags |= TEM_ATTR_UNDERLINE;
			break;

		case 5: /* Blink */
			tem->tvs_flags |= TEM_ATTR_BLINK;
			break;

		case 7: /* Reverse video */
			if (tem->tvs_flags & TEM_ATTR_SCREEN_REVERSE) {
				tem->tvs_flags &= ~TEM_ATTR_REVERSE;
			} else {
				tem->tvs_flags |= TEM_ATTR_REVERSE;
			}
			break;

		case 22: /* Remove Bold */
			tem->tvs_flags &= ~TEM_ATTR_BOLD;
			break;

		case 24: /* Remove Underline */
			tem->tvs_flags &= ~TEM_ATTR_UNDERLINE;
			break;

		case 25: /* Remove Blink */
			tem->tvs_flags &= ~TEM_ATTR_BLINK;
			break;

		case 27: /* Remove Reverse */
			if (tem->tvs_flags & TEM_ATTR_SCREEN_REVERSE) {
				tem->tvs_flags |= TEM_ATTR_REVERSE;
			} else {
				tem->tvs_flags &= ~TEM_ATTR_REVERSE;
			}
			break;

		case 30: /* black	(grey)		foreground */
		case 31: /* red		(light red)	foreground */
		case 32: /* green	(light green)	foreground */
		case 33: /* brown	(yellow)	foreground */
		case 34: /* blue	(light blue)	foreground */
		case 35: /* magenta	(light magenta)	foreground */
		case 36: /* cyan	(light cyan)	foreground */
		case 37: /* white	(bright white)	foreground */
			tem->tvs_fg_color.n = param - 30;
			tem->tvs_flags &= ~TEM_ATTR_BRIGHT_FG;
			tem->tvs_flags &= ~TEM_ATTR_RGB_FG;
			break;

		case 38:
			/*
			 * We should have 3 parameters for 256 colors and
			 * 5 parameters for 24-bit colors.
			 */
			if (curparam < 3) {
				curparam = 0;
				break;
			}

			/*
			 * 256 and truecolor needs depth > 8, but
			 * we still need to process the sequence.
			 */
			count++;
			curparam--;
			param = tem->tvs_params[count];
			switch (param) {
			case 2:	/* RGB colors */
				if (curparam < 4) {
					curparam = 0;
					break;
				}
				r = tem->tvs_params[++count];
				g = tem->tvs_params[++count];
				b = tem->tvs_params[++count];
				curparam -= 3;
				if (r < 0 || r > 255 || g < 0 || g > 255 ||
				    b < 0 || b > 255)
					break;

				if (tems.ts_display_mode == VIS_PIXEL &&
				    tems.ts_pdepth > 8) {
					tem->tvs_flags |= TEM_ATTR_RGB_FG;
					tem->tvs_flags &= ~TEM_ATTR_BRIGHT_FG;
					tem->tvs_fg_color.rgb.a =
					    tem->tvs_alpha;
					tem->tvs_fg_color.rgb.r = r;
					tem->tvs_fg_color.rgb.g = g;
					tem->tvs_fg_color.rgb.b = b;
				}
				break;
			case 5:	/* 256 colors */
				count++;
				curparam--;
				tem_select_color(tem, tem->tvs_params[count],
				    true);
				break;
			default:
				curparam = 0;
				break;
			}
			break;

		case 39:
			/*
			 * Reset the foreground colour and brightness.
			 */
			tem->tvs_fg_color = tems.ts_init_color.fg_color;
			tem->tvs_flags &= ~TEM_ATTR_RGB_FG;
			if (tems.ts_init_color.a_flags & TEM_ATTR_BRIGHT_FG)
				tem->tvs_flags |= TEM_ATTR_BRIGHT_FG;
			else
				tem->tvs_flags &= ~TEM_ATTR_BRIGHT_FG;
			break;

		case 40: /* black	(grey)		background */
		case 41: /* red		(light red)	background */
		case 42: /* green	(light green)	background */
		case 43: /* brown	(yellow)	background */
		case 44: /* blue	(light blue)	background */
		case 45: /* magenta	(light magenta)	background */
		case 46: /* cyan	(light cyan)	background */
		case 47: /* white	(bright white)	background */
			tem->tvs_bg_color.n = param - 40;
			tem->tvs_flags &= ~TEM_ATTR_RGB_BG;
			tem->tvs_flags &= ~TEM_ATTR_BRIGHT_BG;
			break;

		case 48:
			/*
			 * We should have 3 parameters for 256 colors and
			 * 5 parameters for 24-bit colors.
			 */
			/* We should have at least 3 parameters */
			if (curparam < 3) {
				curparam = 0;
				break;
			}

			/*
			 * 256 and truecolor needs depth > 8, but
			 * we still need to process the sequence.
			 */
			count++;
			curparam--;
			param = tem->tvs_params[count];
			switch (param) {
			case 2:	/* RGB colors */
				if (curparam < 4) {
					curparam = 0;
					break;
				}
				r = tem->tvs_params[++count];
				g = tem->tvs_params[++count];
				b = tem->tvs_params[++count];
				curparam -= 3;
				if (r < 0 || r > 255 || g < 0 || g > 255 ||
				    b < 0 || b > 255)
					break;

				if (tems.ts_display_mode == VIS_PIXEL &&
				    tems.ts_pdepth > 8) {
					tem->tvs_flags |= TEM_ATTR_RGB_BG;
					tem->tvs_flags &= ~TEM_ATTR_BRIGHT_BG;
					tem->tvs_bg_color.rgb.a =
					    tem->tvs_alpha;
					tem->tvs_bg_color.rgb.r = r;
					tem->tvs_bg_color.rgb.g = g;
					tem->tvs_bg_color.rgb.b = b;
				}
				break;
			case 5:	/* 256 colors */
				count++;
				curparam--;
				tem_select_color(tem, tem->tvs_params[count],
				    false);
				break;
			default:
				curparam = 0;
				break;
			}
			break;

		case 49:
			/*
			 * Reset the background colour and brightness.
			 */
			tem->tvs_bg_color = tems.ts_init_color.bg_color;
			tem->tvs_flags &= ~TEM_ATTR_RGB_BG;
			if (tems.ts_init_color.a_flags & TEM_ATTR_BRIGHT_BG)
				tem->tvs_flags |= TEM_ATTR_BRIGHT_BG;
			else
				tem->tvs_flags &= ~TEM_ATTR_BRIGHT_BG;
			break;

		case 90: /* black	(grey)		foreground */
		case 91: /* red		(light red)	foreground */
		case 92: /* green	(light green)	foreground */
		case 93: /* brown	(yellow)	foreground */
		case 94: /* blue	(light blue)	foreground */
		case 95: /* magenta	(light magenta)	foreground */
		case 96: /* cyan	(light cyan)	foreground */
		case 97: /* white	(bright white)	foreground */
			tem->tvs_fg_color.n = param - 90;
			tem->tvs_flags |= TEM_ATTR_BRIGHT_FG;
			tem->tvs_flags &= ~TEM_ATTR_RGB_FG;
			break;

		case 100: /* black	(grey)		background */
		case 101: /* red	(light red)	background */
		case 102: /* green	(light green)	background */
		case 103: /* brown	(yellow)	background */
		case 104: /* blue	(light blue)	background */
		case 105: /* magenta	(light magenta)	background */
		case 106: /* cyan	(light cyan)	background */
		case 107: /* white	(bright white)	background */
			tem->tvs_bg_color.n = param - 100;
			tem->tvs_flags |= TEM_ATTR_BRIGHT_BG;
			tem->tvs_flags &= ~TEM_ATTR_RGB_BG;
			break;

		default:
			break;
		}
		count++;
		curparam--;

	} while (curparam > 0);
}

/*
 * perform the appropriate action for the escape sequence
 *
 * General rule:  This code does not validate the arguments passed.
 *                It assumes that the next lower level will do so.
 */
static void
tem_chkparam(struct tem_vt_state *tem, uint8_t ch)
{
	int	i;
	int	row;
	int	col;

	row = tem->tvs_c_cursor.row;
	col = tem->tvs_c_cursor.col;

	switch (ch) {

	case 'm': /* select terminal graphics mode */
		tem_send_data(tem);
		tem_selgraph(tem);
		break;

	case '@':		/* insert char */
		tem_setparam(tem, 1, 1);
		tem_shift(tem, tem->tvs_params[0], TEM_SHIFT_RIGHT);
		break;

	case 'A':		/* cursor up */
		tem->tvs_stateflags &= ~TVS_WRAPPED;
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row - tem->tvs_params[0], col);
		break;

	case 'd':		/* VPA - vertical position absolute */
		tem->tvs_stateflags &= ~TVS_WRAPPED;
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, tem->tvs_params[0] - 1, col);
		break;

	case 'e':		/* VPR - vertical position relative */
	case 'B':		/* cursor down */
		tem->tvs_stateflags &= ~TVS_WRAPPED;
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row + tem->tvs_params[0], col);
		break;

	case 'a':		/* HPR - horizontal position relative */
	case 'C':		/* cursor right */
		tem->tvs_stateflags &= ~TVS_WRAPPED;
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row, col + tem->tvs_params[0]);
		break;

	case '`':		/* HPA - horizontal position absolute */
		tem->tvs_stateflags &= ~TVS_WRAPPED;
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row, tem->tvs_params[0] - 1);
		break;

	case 'D':		/* cursor left */
		tem->tvs_stateflags &= ~TVS_WRAPPED;
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row, col - tem->tvs_params[0]);
		break;

	case 'E':		/* CNL cursor next line */
		tem->tvs_stateflags &= ~TVS_WRAPPED;
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row + tem->tvs_params[0], 0);
		break;

	case 'F':		/* CPL cursor previous line */
		tem->tvs_stateflags &= ~TVS_WRAPPED;
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row - tem->tvs_params[0], 0);
		break;

	case 'G':		/* cursor horizontal position */
		tem->tvs_stateflags &= ~TVS_WRAPPED;
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row, tem->tvs_params[0] - 1);
		break;

	case 'g':		/* clear tabs */
		tem_setparam(tem, 1, 0);
		tem_clear_tabs(tem, tem->tvs_params[0]);
		break;

	case 'f':		/* HVP Horizontal and Vertical Position */
	case 'H':		/* CUP position cursor */
		tem->tvs_stateflags &= ~TVS_WRAPPED;
		tem_setparam(tem, 2, 1);
		tem_mv_cursor(tem,
		    tem->tvs_params[0] - 1, tem->tvs_params[1] - 1);
		break;

	case 'I':		/* CHT - Cursor Horizontal Tab */
		/* Not implemented */
		break;

	case 'J':		/* ED - Erase in Display */
		tem_send_data(tem);
		tem_setparam(tem, 1, 0);
		switch (tem->tvs_params[0]) {
		case 0:
			/* erase cursor to end of screen */
			/* FIRST erase cursor to end of line */
			tem_clear_chars(tem,
			    tems.ts_c_dimension.width -
			    tem->tvs_c_cursor.col,
			    tem->tvs_c_cursor.row,
			    tem->tvs_c_cursor.col);

			/* THEN erase lines below the cursor */
			for (row = tem->tvs_c_cursor.row + 1;
			    row < tems.ts_c_dimension.height;
			    row++) {
				tem_clear_chars(tem,
				    tems.ts_c_dimension.width, row, 0);
			}
			break;

		case 1:
			/* erase beginning of screen to cursor */
			/* FIRST erase lines above the cursor */
			for (row = 0;
			    row < tem->tvs_c_cursor.row;
			    row++) {
				tem_clear_chars(tem,
				    tems.ts_c_dimension.width, row, 0);
			}
			/* THEN erase beginning of line to cursor */
			tem_clear_chars(tem,
			    tem->tvs_c_cursor.col + 1,
			    tem->tvs_c_cursor.row, 0);
			break;

		case 2:
			/* erase whole screen */
			for (row = 0;
			    row < tems.ts_c_dimension.height;
			    row++) {
				tem_clear_chars(tem,
				    tems.ts_c_dimension.width, row, 0);
			}
			break;
		}
		break;

	case 'K':		/* EL - Erase in Line */
		tem_send_data(tem);
		tem_setparam(tem, 1, 0);
		switch (tem->tvs_params[0]) {
		case 0:
			/* erase cursor to end of line */
			tem_clear_chars(tem,
			    (tems.ts_c_dimension.width -
			    tem->tvs_c_cursor.col),
			    tem->tvs_c_cursor.row,
			    tem->tvs_c_cursor.col);
			break;

		case 1:
			/* erase beginning of line to cursor */
			tem_clear_chars(tem,
			    tem->tvs_c_cursor.col + 1,
			    tem->tvs_c_cursor.row, 0);
			break;

		case 2:
			/* erase whole line */
			tem_clear_chars(tem,
			    tems.ts_c_dimension.width,
			    tem->tvs_c_cursor.row, 0);
			break;
		}
		break;

	case 'L':		/* insert line */
		tem_send_data(tem);
		tem_setparam(tem, 1, 1);
		tem_scroll(tem,
		    tem->tvs_c_cursor.row,
		    tems.ts_c_dimension.height - 1,
		    tem->tvs_params[0], TEM_SCROLL_DOWN);
		break;

	case 'M':		/* delete line */
		tem_send_data(tem);
		tem_setparam(tem, 1, 1);
		tem_scroll(tem,
		    tem->tvs_c_cursor.row,
		    tems.ts_c_dimension.height - 1,
		    tem->tvs_params[0], TEM_SCROLL_UP);
		break;

	case 'P':		/* DCH - delete char */
		tem_setparam(tem, 1, 1);
		tem_shift(tem, tem->tvs_params[0], TEM_SHIFT_LEFT);
		break;

	case 'S':		/* scroll up */
		tem_send_data(tem);
		tem_setparam(tem, 1, 1);
		tem_scroll(tem, 0,
		    tems.ts_c_dimension.height - 1,
		    tem->tvs_params[0], TEM_SCROLL_UP);
		break;

	case 'T':		/* scroll down */
		tem_send_data(tem);
		tem_setparam(tem, 1, 1);
		tem_scroll(tem, 0,
		    tems.ts_c_dimension.height - 1,
		    tem->tvs_params[0], TEM_SCROLL_DOWN);
		break;

	case 'X':		/* erase char */
		tem_setparam(tem, 1, 1);
		tem_clear_chars(tem,
		    tem->tvs_params[0],
		    tem->tvs_c_cursor.row,
		    tem->tvs_c_cursor.col);
		break;

	case 'Z':		/* cursor backward tabulation */
		tem_setparam(tem, 1, 1);

		/*
		 * Rule exception - We do sanity checking here.
		 *
		 * Restrict the count to a sane value to keep from
		 * looping for a long time.  There can't be more than one
		 * tab stop per column, so use that as a limit.
		 */
		if (tem->tvs_params[0] > tems.ts_c_dimension.width)
			tem->tvs_params[0] = tems.ts_c_dimension.width;

		for (i = 0; i < tem->tvs_params[0]; i++)
			tem_back_tab(tem);
		break;
	}
	tem->tvs_state = A_STATE_START;
}

static void
tem_chkparam_qmark(struct tem_vt_state *tem, tem_char_t ch)
{
	switch (ch) {
	case 'h': /* DEC private mode set */
		tem_setparam(tem, 1, 1);
		switch (tem->tvs_params[0]) {
		case 7: /* Autowrap mode. */
			tem->tvs_stateflags |= TVS_AUTOWRAP;
			break;

		case 25: /* show cursor */
			/*
			 * Note that cursor is not displayed either way
			 * at this entry point.  Clearing the flag ensures
			 * that on exit from tem_safe_terminal_emulate
			 * we will display the cursor.
			 */
			tem_send_data(tem);
			tem->tvs_cursor_hidden = false;
			break;
		}
		break;
	case 'l':
		/* DEC private mode reset */
		tem_setparam(tem, 1, 1);
		switch (tem->tvs_params[0]) {
		case 7: /* Autowrap mode. */
			tem->tvs_stateflags &= ~TVS_AUTOWRAP;
			break;

		case 25: /* hide cursor */
			/*
			 * Note that the cursor is not displayed already.
			 * This is true regardless of the flag state.
			 * Setting this flag ensures we won't display it
			 * on exit from tem_safe_terminal_emulate.
			 */
			tem_send_data(tem);
			tem->tvs_cursor_hidden = true;
			break;
		}
		break;
	}
	tem->tvs_state = A_STATE_START;
}

/*
 * Gather the parameters of an ANSI escape sequence
 */
static void
tem_getparams(struct tem_vt_state *tem, uint8_t ch)
{
	if (isdigit(ch)) {
		tem->tvs_paramval = ((tem->tvs_paramval * 10) + (ch - '0'));
		tem->tvs_gotparam = true;  /* Remember got parameter */
		return; /* Return immediately */
	} else if (tem->tvs_state == A_STATE_CSI_EQUAL) {
		tem->tvs_state = A_STATE_START;
	} else if (tem->tvs_state == A_STATE_CSI_QMARK) {
		if (tem->tvs_curparam < TEM_MAXPARAMS) {
			if (tem->tvs_gotparam) {
				/* get the parameter value */
				tem->tvs_params[tem->tvs_curparam] =
				    tem->tvs_paramval;
			}
			tem->tvs_curparam++;
		}
		if (ch == ';') {
			/* Restart parameter search */
			tem->tvs_gotparam = false;
			tem->tvs_paramval = 0; /* No parameter value yet */
		} else {
			/* Handle escape sequence */
			tem_chkparam_qmark(tem, ch);
		}
	} else {
		if (tem->tvs_curparam < TEM_MAXPARAMS) {
			if (tem->tvs_gotparam) {
				/* get the parameter value */
				tem->tvs_params[tem->tvs_curparam] =
				    tem->tvs_paramval;
			}
			tem->tvs_curparam++;
		}

		if (ch == ';') {
			/* Restart parameter search */
			tem->tvs_gotparam = false;
			tem->tvs_paramval = 0; /* No parameter value yet */
		} else {
			/* Handle escape sequence */
			tem_chkparam(tem, ch);
		}
	}
}

/*
 * Add character to internal buffer.
 * When its full, send it to the next layer.
 */
static void
tem_outch(struct tem_vt_state *tem, tem_char_t ch)
{
	text_color_t fg;
	text_color_t bg;
	text_attr_t attr;

	/* We have autowrap enabled and we did wrap - get cursor to new line */
	if ((tem->tvs_stateflags & (TVS_AUTOWRAP | TVS_WRAPPED)) ==
	    (TVS_AUTOWRAP | TVS_WRAPPED)) {
		tem_new_line(tem);
	}

	/* buffer up the character until later */
	tem_get_attr(tem, &fg, &bg, &attr, TEM_ATTR_REVERSE);
	tem->tvs_outbuf[tem->tvs_outindex].tc_char = ch | TEM_ATTR(attr);
	tem->tvs_outbuf[tem->tvs_outindex].tc_fg_color = fg;
	tem->tvs_outbuf[tem->tvs_outindex].tc_bg_color = bg;
	tem->tvs_outindex++;
	tem->tvs_c_cursor.col++;
	if (tem->tvs_c_cursor.col >= tems.ts_c_dimension.width) {
		tem->tvs_stateflags |= TVS_WRAPPED;
		tem->tvs_c_cursor.col--;
		tem_send_data(tem);
	} else {
		tem->tvs_stateflags &= ~TVS_WRAPPED;
	}
}

static void
tem_new_line(struct tem_vt_state *tem)
{
	tem_cr(tem);
	tem_lf(tem);
}

static void
tem_cr(struct tem_vt_state *tem)
{
	tem->tvs_c_cursor.col = 0;
	tem->tvs_stateflags &= ~TVS_WRAPPED;
	tem_align_cursor(tem);
}

static void
tem_lf(struct tem_vt_state *tem)
{
	int row;

	tem->tvs_stateflags &= ~TVS_WRAPPED;
	/*
	 * Sanity checking notes:
	 * . a_nscroll was validated when it was set.
	 * . Regardless of that, tem_scroll and tem_mv_cursor
	 *   will prevent anything bad from happening.
	 */
	row = tem->tvs_c_cursor.row + 1;

	if (row >= tems.ts_c_dimension.height) {
		if (tem->tvs_nscroll != 0) {
			tem_scroll(tem, 0,
			    tems.ts_c_dimension.height - 1,
			    tem->tvs_nscroll, TEM_SCROLL_UP);
			row = tems.ts_c_dimension.height -
			    tem->tvs_nscroll;
		} else {	/* no scroll */
			/*
			 * implement Esc[#r when # is zero.  This means no
			 * scroll but just return cursor to top of screen,
			 * do not clear screen.
			 */
			row = 0;
		}
	}

	tem_mv_cursor(tem, row, tem->tvs_c_cursor.col);

	if (tem->tvs_nscroll == 0) {
		/* erase rest of cursor line */
		tem_clear_chars(tem,
		    tems.ts_c_dimension.width -
		    tem->tvs_c_cursor.col,
		    tem->tvs_c_cursor.row,
		    tem->tvs_c_cursor.col);

	}

	tem_align_cursor(tem);
}

static void
tem_send_data(struct tem_vt_state *tem)
{
	if (tem->tvs_outindex == 0) {
		tem_align_cursor(tem);
		return;
	}

	tem_virtual_display(tem, tem->tvs_outbuf, tem->tvs_outindex,
	    tem->tvs_s_cursor.row, tem->tvs_s_cursor.col);

	if (tem->tvs_isactive) {
		/*
		 * Call the primitive to render this data.
		 */
		tem_callback_display(tem,
		    tem->tvs_outbuf, tem->tvs_outindex,
		    tem->tvs_s_cursor.row, tem->tvs_s_cursor.col);
	}

	tem->tvs_outindex = 0;

	tem_align_cursor(tem);
}


/*
 * We have just done something to the current output point.  Reset the start
 * point for the buffered data in a_outbuf.  There shouldn't be any data
 * buffered yet.
 */
static void
tem_align_cursor(struct tem_vt_state *tem)
{
	tem->tvs_s_cursor.row = tem->tvs_c_cursor.row;
	tem->tvs_s_cursor.col = tem->tvs_c_cursor.col;
}

/*
 * State machine parser based on the current state and character input
 * major terminations are to control character or normal character
 */

static void
tem_parse(struct tem_vt_state *tem, tem_char_t ch)
{
	int	i;

	if (tem->tvs_state == A_STATE_START) {	/* Normal state? */
		if (ch == A_CSI || ch == A_ESC || ch < ' ') {
			/* Control */
			tem_control(tem, ch);
		} else {
			/* Display */
			tem_outch(tem, ch);
		}
		return;
	}

	/* In <ESC> sequence */
	if (tem->tvs_state != A_STATE_ESC) {	/* Need to get parameters? */
		if (tem->tvs_state != A_STATE_CSI) {
			tem_getparams(tem, ch);
			return;
		}

		switch (ch) {
		case '?':
			tem->tvs_state = A_STATE_CSI_QMARK;
			return;
		case '=':
			tem->tvs_state = A_STATE_CSI_EQUAL;
			return;
		case 's':
			/*
			 * As defined below, this sequence
			 * saves the cursor.  However, Sun
			 * defines ESC[s as reset.  We resolved
			 * the conflict by selecting reset as it
			 * is exported in the termcap file for
			 * sun-mon, while the "save cursor"
			 * definition does not exist anywhere in
			 * /etc/termcap.
			 * However, having no coherent
			 * definition of reset, we have not
			 * implemented it.
			 */

			/*
			 * Original code
			 * tem->tvs_r_cursor.row = tem->tvs_c_cursor.row;
			 * tem->tvs_r_cursor.col = tem->tvs_c_cursor.col;
			 * tem->tvs_state = A_STATE_START;
			 */

			tem->tvs_state = A_STATE_START;
			return;
		case 'u':
			tem_mv_cursor(tem, tem->tvs_r_cursor.row,
			    tem->tvs_r_cursor.col);
			tem->tvs_state = A_STATE_START;
			return;
		case 'p':	/* sunbow */
			tem_send_data(tem);
			/*
			 * Don't set anything if we are
			 * already as we want to be.
			 */
			if (tem->tvs_flags & TEM_ATTR_SCREEN_REVERSE) {
				tem->tvs_flags &= ~TEM_ATTR_SCREEN_REVERSE;
				/*
				 * If we have switched the characters to be the
				 * inverse from the screen, then switch them as
				 * well to keep them the inverse of the screen.
				 */
				if (tem->tvs_flags & TEM_ATTR_REVERSE)
					tem->tvs_flags &= ~TEM_ATTR_REVERSE;
				else
					tem->tvs_flags |= TEM_ATTR_REVERSE;
			}
			tem_cls(tem);
			tem->tvs_state = A_STATE_START;
			return;
		case 'q':	/* sunwob */
			tem_send_data(tem);
			/*
			 * Don't set anything if we are
			 * already where as we want to be.
			 */
			if (!(tem->tvs_flags & TEM_ATTR_SCREEN_REVERSE)) {
				tem->tvs_flags |= TEM_ATTR_SCREEN_REVERSE;
				/*
				 * If we have switched the characters to be the
				 * inverse from the screen, then switch them as
				 * well to keep them the inverse of the screen.
				 */
				if (!(tem->tvs_flags & TEM_ATTR_REVERSE))
					tem->tvs_flags |= TEM_ATTR_REVERSE;
				else
					tem->tvs_flags &= ~TEM_ATTR_REVERSE;
			}

			tem_cls(tem);
			tem->tvs_state = A_STATE_START;
			return;
		case 'r':	/* sunscrl */
			/*
			 * Rule exception:  check for validity here.
			 */
			tem->tvs_nscroll = tem->tvs_paramval;
			if (tem->tvs_nscroll > tems.ts_c_dimension.height)
				tem->tvs_nscroll = tems.ts_c_dimension.height;
			if (tem->tvs_nscroll < 0)
				tem->tvs_nscroll = 1;
			tem->tvs_state = A_STATE_START;
			return;
		default:
			tem_getparams(tem, ch);
			return;
		}
	}

	/* Previous char was <ESC> */
	if (ch == '[') {
		tem->tvs_curparam = 0;
		tem->tvs_paramval = 0;
		tem->tvs_gotparam = false;
		/* clear the parameters */
		for (i = 0; i < TEM_MAXPARAMS; i++)
			tem->tvs_params[i] = -1;
		tem->tvs_state = A_STATE_CSI;
	} else if (ch == 'Q') {	/* <ESC>Q ? */
		tem->tvs_state = A_STATE_START;
	} else if (ch == 'C') {	/* <ESC>C ? */
		tem->tvs_state = A_STATE_START;
	} else {
		tem->tvs_state = A_STATE_START;
		if (ch == 'c') {
			/* ESC c resets display */
			tem_reset_display(tem, true, true);
		} else if (ch == 'H') {
			/* ESC H sets a tab */
			tem_set_tab(tem);
		} else if (ch == '7') {
			/* ESC 7 Save Cursor position */
			tem->tvs_r_cursor.row = tem->tvs_c_cursor.row;
			tem->tvs_r_cursor.col = tem->tvs_c_cursor.col;
		} else if (ch == '8') {
			/* ESC 8 Restore Cursor position */
			tem_mv_cursor(tem, tem->tvs_r_cursor.row,
			    tem->tvs_r_cursor.col);
		/* check for control chars */
		} else if (ch < ' ') {
			tem_control(tem, ch);
		} else {
			tem_outch(tem, ch);
		}
	}
}

/* ARGSUSED */
static void
tem_bell(struct tem_vt_state *tem __unused)
{
		/* (void) beep(BEEP_CONSOLE); */
}


static void
tem_scroll(struct tem_vt_state *tem, int start, int end, int count,
    int direction)
{
	int	row;
	int	lines_affected;

	lines_affected = end - start + 1;
	if (count > lines_affected)
		count = lines_affected;
	if (count <= 0)
		return;

	switch (direction) {
	case TEM_SCROLL_UP:
		if (count < lines_affected) {
			tem_copy_area(tem, 0, start + count,
			    tems.ts_c_dimension.width - 1, end, 0, start);
		}
		for (row = (end - count) + 1; row <= end; row++) {
			tem_clear_chars(tem, tems.ts_c_dimension.width, row, 0);
		}
		break;

	case TEM_SCROLL_DOWN:
		if (count < lines_affected) {
			tem_copy_area(tem, 0, start,
			    tems.ts_c_dimension.width - 1,
			    end - count, 0, start + count);
		}
		for (row = start; row < start + count; row++) {
			tem_clear_chars(tem, tems.ts_c_dimension.width, row, 0);
		}
		break;
	}
}

static int
tem_copy_width(term_char_t *src, term_char_t *dst, int cols)
{
	int width = cols - 1;

	while (width >= 0) {
		/* We do not have image bits to compare, stop there. */
		if (TEM_CHAR_ATTR(src[width].tc_char) == TEM_ATTR_IMAGE ||
		    TEM_CHAR_ATTR(dst[width].tc_char) == TEM_ATTR_IMAGE)
			break;

		/*
		 * Find difference on line, compare char with its attributes
		 * and colors.
		 */
		if (src[width].tc_char != dst[width].tc_char ||
		    src[width].tc_fg_color.n != dst[width].tc_fg_color.n ||
		    src[width].tc_bg_color.n != dst[width].tc_bg_color.n) {
			break;
		}
		width--;
	}
	return (width + 1);
}

static void
tem_copy_area(struct tem_vt_state *tem,
    screen_pos_t s_col, screen_pos_t s_row,
    screen_pos_t e_col, screen_pos_t e_row,
    screen_pos_t t_col, screen_pos_t t_row)
{
	size_t soffset, toffset;
	term_char_t *src, *dst;
	int rows;
	int cols;

	if (s_col < 0 || s_row < 0 ||
	    e_col < 0 || e_row < 0 ||
	    t_col < 0 || t_row < 0 ||
	    s_col >= tems.ts_c_dimension.width ||
	    e_col >= tems.ts_c_dimension.width ||
	    t_col >= tems.ts_c_dimension.width ||
	    s_row >= tems.ts_c_dimension.height ||
	    e_row >= tems.ts_c_dimension.height ||
	    t_row >= tems.ts_c_dimension.height)
		return;

	if (s_row > e_row || s_col > e_col)
		return;

	rows = e_row - s_row + 1;
	cols = e_col - s_col + 1;
	if (t_row + rows > tems.ts_c_dimension.height ||
	    t_col + cols > tems.ts_c_dimension.width)
		return;

	if (tem->tvs_screen_buf == NULL) {
		if (tem->tvs_isactive) {
			tem_callback_copy(tem, s_col, s_row,
			    e_col, e_row, t_col, t_row);
		}
		return;
	}

	soffset = s_col + s_row * tems.ts_c_dimension.width;
	toffset = t_col + t_row * tems.ts_c_dimension.width;
	src = tem->tvs_screen_buf + soffset;
	dst = tem->tvs_screen_buf + toffset;

	/*
	 * Copy line by line. We determine the length by comparing the
	 * screen content from cached text in tvs_screen_buf.
	 */
	if (toffset <= soffset) {
		for (int i = 0; i < rows; i++) {
			int increment = i * tems.ts_c_dimension.width;
			int width;

			width = tem_copy_width(src + increment,
			    dst + increment, cols);
			memmove(dst + increment, src + increment,
			    width * sizeof (term_char_t));
			if (tem->tvs_isactive) {
				tem_callback_copy(tem, s_col, s_row + i,
				    e_col - cols + width, s_row + i,
				    t_col, t_row + i);
			}
		}
	} else {
		for (int i = rows - 1; i >= 0; i--) {
			int increment = i * tems.ts_c_dimension.width;
			int width;

			width = tem_copy_width(src + increment,
			    dst + increment, cols);
			memmove(dst + increment, src + increment,
			    width * sizeof (term_char_t));
			if (tem->tvs_isactive) {
				tem_callback_copy(tem, s_col, s_row + i,
				    e_col - cols + width, s_row + i,
				    t_col, t_row + i);
			}
		}
	}
}

static void
tem_clear_chars(struct tem_vt_state *tem, int count, screen_pos_t row,
    screen_pos_t col)
{
	if (row < 0 || row >= tems.ts_c_dimension.height ||
	    col < 0 || col >= tems.ts_c_dimension.width ||
	    count < 0)
		return;

	/*
	 * Note that very large values of "count" could cause col+count
	 * to overflow, so we check "count" independently.
	 */
	if (count > tems.ts_c_dimension.width ||
	    col + count > tems.ts_c_dimension.width)
		count = tems.ts_c_dimension.width - col;

	tem_virtual_cls(tem, count, row, col);

	if (!tem->tvs_isactive)
		return;

	tem_callback_cls(tem, count, row, col);
}

static void
tem_text_display(struct tem_vt_state *tem __unused, term_char_t *string,
    int count, screen_pos_t row, screen_pos_t col)
{
	struct vis_consdisplay da;
	int i;
	tem_char_t c;
	text_color_t bg, fg;

	if (count == 0)
		return;

	da.data = (unsigned char *)&c;
	da.width = 1;
	da.row = row;
	da.col = col;

	for (i = 0; i < count; i++) {
		tem_get_color(tem, &fg, &bg, &string[i]);
		tem_set_color(&fg, &da.fg_color);
		tem_set_color(&bg, &da.bg_color);
		c = TEM_CHAR(string[i].tc_char);
		tems_display(&da);
		da.col++;
	}
}

/*
 * This function is used to mark a rectangular image area so the scrolling
 * will know we need to copy the data from there.
 */
void
tem_image_display(struct tem_vt_state *tem, screen_pos_t s_row,
    screen_pos_t s_col, screen_pos_t e_row, screen_pos_t e_col)
{
	screen_pos_t i, j;
	term_char_t c;

	c.tc_char = TEM_ATTR(TEM_ATTR_IMAGE);

	for (i = s_row; i <= e_row; i++) {
		for (j = s_col; j <= e_col; j++) {
			tem_virtual_display(tem, &c, 1, i, j);
		}
	}
}

/*ARGSUSED*/
static void
tem_text_copy(struct tem_vt_state *tem __unused,
    screen_pos_t s_col, screen_pos_t s_row,
    screen_pos_t e_col, screen_pos_t e_row,
    screen_pos_t t_col, screen_pos_t t_row)
{
	struct vis_conscopy da;

	da.s_row = s_row;
	da.s_col = s_col;
	da.e_row = e_row;
	da.e_col = e_col;
	da.t_row = t_row;
	da.t_col = t_col;
	tems_copy(&da);
}

static void
tem_text_cls(struct tem_vt_state *tem,
    int count, screen_pos_t row, screen_pos_t col)
{
	text_attr_t attr;
	term_char_t c;
	int i;

	tem_get_attr(tem, &c.tc_fg_color, &c.tc_bg_color, &attr,
	    TEM_ATTR_SCREEN_REVERSE);
	c.tc_char = TEM_ATTR(attr & ~TEM_ATTR_UNDERLINE) | ' ';

	if (count > tems.ts_c_dimension.width ||
	    col + count > tems.ts_c_dimension.width)
		count = tems.ts_c_dimension.width - col;

	for (i = 0; i < count; i++)
		tem_text_display(tem, &c, 1, row, col++);

}

static void
tem_pix_display(struct tem_vt_state *tem,
    term_char_t *string, int count,
    screen_pos_t row, screen_pos_t col)
{
	struct vis_consdisplay da;
	int	i;

	da.data = (uint8_t *)tem->tvs_pix_data;
	da.width = tems.ts_font.vf_width;
	da.height = tems.ts_font.vf_height;
	da.row = (row * da.height) + tems.ts_p_offset.y;
	da.col = (col * da.width) + tems.ts_p_offset.x;

	for (i = 0; i < count; i++) {
		tem_callback_bit2pix(tem, &string[i]);
		tems_display(&da);
		da.col += da.width;
	}
}

static void
tem_pix_copy(struct tem_vt_state *tem,
    screen_pos_t s_col, screen_pos_t s_row,
    screen_pos_t e_col, screen_pos_t e_row,
    screen_pos_t t_col, screen_pos_t t_row)
{
	struct vis_conscopy ma;
	static bool need_clear = true;

	if (need_clear && tem->tvs_first_line > 0) {
		/*
		 * Clear OBP output above our kernel console term
		 * when our kernel console term begins to scroll up,
		 * we hope it is user friendly.
		 * (Also see comments on tem_pix_clear_prom_output)
		 *
		 * This is only one time call.
		 */
		tem_pix_clear_prom_output(tem);
	}
	need_clear = false;

	ma.s_row = s_row * tems.ts_font.vf_height + tems.ts_p_offset.y;
	ma.e_row = (e_row + 1) * tems.ts_font.vf_height +
	    tems.ts_p_offset.y - 1;
	ma.t_row = t_row * tems.ts_font.vf_height + tems.ts_p_offset.y;

	/*
	 * Check if we're in process of clearing OBP's columns area,
	 * which only happens when term scrolls up a whole line.
	 */
	if (tem->tvs_first_line > 0 && t_row < s_row && t_col == 0 &&
	    e_col == tems.ts_c_dimension.width - 1) {
		/*
		 * We need to clear OBP's columns area outside our kernel
		 * console term. So that we set ma.e_col to entire row here.
		 */
		ma.s_col = s_col * tems.ts_font.vf_width;
		ma.e_col = tems.ts_p_dimension.width - 1;

		ma.t_col = t_col * tems.ts_font.vf_width;
	} else {
		ma.s_col = s_col * tems.ts_font.vf_width + tems.ts_p_offset.x;
		ma.e_col = (e_col + 1) * tems.ts_font.vf_width +
		    tems.ts_p_offset.x - 1;
		ma.t_col = t_col * tems.ts_font.vf_width + tems.ts_p_offset.x;
	}

	tems_copy(&ma);

	if (tem->tvs_first_line > 0 && t_row < s_row) {
		/* We have scrolled up (s_row - t_row) rows. */
		tem->tvs_first_line -= (s_row - t_row);
		if (tem->tvs_first_line <= 0) {
			/* All OBP rows have been cleared. */
			tem->tvs_first_line = 0;
		}
	}
}

static void
tem_pix_bit2pix(struct tem_vt_state *tem, term_char_t *c)
{
	text_color_t fg, bg;

	tem_get_color(tem, &fg, &bg, c);
	bit_to_pix32(tem, c->tc_char, fg, bg);
}


/*
 * This function only clears count of columns in one row
 */
static void
tem_pix_cls(struct tem_vt_state *tem, int count,
    screen_pos_t row, screen_pos_t col)
{
	tem_pix_cls_range(tem, row, 1, tems.ts_p_offset.y,
	    col, count, tems.ts_p_offset.x, false);
}

/*
 * This function clears OBP output above our kernel console term area
 * because OBP's term may have a bigger terminal window than that of
 * our kernel console term. So we need to clear OBP output garbage outside
 * of our kernel console term at a proper time, which is when the first
 * row output of our kernel console term scrolls at the first screen line.
 *
 *	_________________________________
 *	|   _____________________	|  ---> OBP's bigger term window
 *	|   |			|	|
 *	|___|			|	|
 *	| | |			|	|
 *	| | |			|	|
 *	|_|_|___________________|_______|
 *	  | |			|	   ---> first line
 *	  | |___________________|---> our kernel console term window
 *	  |
 *	  |---> columns area to be cleared
 *
 * This function only takes care of the output above our kernel console term,
 * and tem_prom_scroll_up takes care of columns area outside of our kernel
 * console term.
 */
static void
tem_pix_clear_prom_output(struct tem_vt_state *tem)
{
	int	nrows, ncols, width, height, offset;

	width = tems.ts_font.vf_width;
	height = tems.ts_font.vf_height;
	offset = tems.ts_p_offset.y % height;

	nrows = tems.ts_p_offset.y / height;
	ncols = (tems.ts_p_dimension.width + (width - 1)) / width;

	if (nrows > 0)
		tem_pix_cls_range(tem, 0, nrows, offset, 0, ncols, 0, false);
}

/*
 * Clear the whole screen and reset the cursor to start point.
 */
static void
tem_cls(struct tem_vt_state *tem)
{
	struct vis_consclear cl;
	text_color_t fg_color;
	text_color_t bg_color;
	text_attr_t attr;
	term_char_t c;
	int row;

	for (row = 0; row < tems.ts_c_dimension.height; row++) {
		tem_virtual_cls(tem, tems.ts_c_dimension.width, row, 0);
	}

	if (!tem->tvs_isactive)
		return;

	tem_get_attr(tem, &c.tc_fg_color, &c.tc_bg_color, &attr,
	    TEM_ATTR_SCREEN_REVERSE);
	c.tc_char = TEM_ATTR(attr);

	tem_get_color(tem, &fg_color, &bg_color, &c);
	tem_set_color(&bg_color, &cl.bg_color);
	(void) tems_cls(&cl);

	tem->tvs_c_cursor.row = 0;
	tem->tvs_c_cursor.col = 0;
	tem_align_cursor(tem);
}

static void
tem_back_tab(struct tem_vt_state *tem)
{
	int	i;
	screen_pos_t	tabstop;

	tabstop = 0;

	for (i = tem->tvs_ntabs - 1; i >= 0; i--) {
		if (tem->tvs_tabs[i] < tem->tvs_c_cursor.col) {
			tabstop = tem->tvs_tabs[i];
			break;
		}
	}

	tem_mv_cursor(tem, tem->tvs_c_cursor.row, tabstop);
}

static void
tem_tab(struct tem_vt_state *tem)
{
	size_t	i;
	screen_pos_t	tabstop;

	tabstop = tems.ts_c_dimension.width - 1;

	for (i = 0; i < tem->tvs_ntabs; i++) {
		if (tem->tvs_tabs[i] > tem->tvs_c_cursor.col) {
			tabstop = tem->tvs_tabs[i];
			break;
		}
	}

	tem_mv_cursor(tem, tem->tvs_c_cursor.row, tabstop);
}

static void
tem_set_tab(struct tem_vt_state *tem)
{
	size_t	i, j;

	if (tem->tvs_ntabs == tem->tvs_maxtab)
		return;
	if (tem->tvs_ntabs == 0 ||
	    tem->tvs_tabs[tem->tvs_ntabs] < tem->tvs_c_cursor.col) {
			tem->tvs_tabs[tem->tvs_ntabs++] = tem->tvs_c_cursor.col;
			return;
	}
	for (i = 0; i < tem->tvs_ntabs; i++) {
		if (tem->tvs_tabs[i] == tem->tvs_c_cursor.col)
			return;
		if (tem->tvs_tabs[i] > tem->tvs_c_cursor.col) {
			for (j = tem->tvs_ntabs - 1; j >= i; j--)
				tem->tvs_tabs[j+ 1] = tem->tvs_tabs[j];
			tem->tvs_tabs[i] = tem->tvs_c_cursor.col;
			tem->tvs_ntabs++;
			return;
		}
	}
}

static void
tem_clear_tabs(struct tem_vt_state *tem, int action)
{
	size_t	i, j;

	switch (action) {
	case 3: /* clear all tabs */
		tem->tvs_ntabs = 0;
		break;
	case 0: /* clr tab at cursor */

		for (i = 0; i < tem->tvs_ntabs; i++) {
			if (tem->tvs_tabs[i] == tem->tvs_c_cursor.col) {
				tem->tvs_ntabs--;
				for (j = i; j < tem->tvs_ntabs; j++)
					tem->tvs_tabs[j] = tem->tvs_tabs[j + 1];
				return;
			}
		}
		break;
	}
}

static void
tem_mv_cursor(struct tem_vt_state *tem, int row, int col)
{
	/*
	 * Sanity check and bounds enforcement.  Out of bounds requests are
	 * clipped to the screen boundaries.  This seems to be what SPARC
	 * does.
	 */
	if (row < 0)
		row = 0;
	if (row >= tems.ts_c_dimension.height)
		row = tems.ts_c_dimension.height - 1;
	if (col < 0)
		col = 0;
	if (col >= tems.ts_c_dimension.width)
		col = tems.ts_c_dimension.width - 1;

	tem_send_data(tem);
	tem->tvs_c_cursor.row = (screen_pos_t)row;
	tem->tvs_c_cursor.col = (screen_pos_t)col;
	tem_align_cursor(tem);
}

/* ARGSUSED */
static void
tem_reset_emulator(struct tem_vt_state *tem, bool init_color)
{
	int j;

	tem->tvs_c_cursor.row = 0;
	tem->tvs_c_cursor.col = 0;
	tem->tvs_r_cursor.row = 0;
	tem->tvs_r_cursor.col = 0;
	tem->tvs_s_cursor.row = 0;
	tem->tvs_s_cursor.col = 0;
	tem->tvs_outindex = 0;
	tem->tvs_state = A_STATE_START;
	tem->tvs_gotparam = false;
	tem->tvs_curparam = 0;
	tem->tvs_paramval = 0;
	tem->tvs_nscroll = 1;

	if (init_color) {
		/* use initial settings */
		tem->tvs_alpha = 0xff;
		tem->tvs_fg_color = tems.ts_init_color.fg_color;
		tem->tvs_bg_color = tems.ts_init_color.bg_color;
		tem->tvs_flags = tems.ts_init_color.a_flags;
	}

	/*
	 * set up the initial tab stops
	 */
	tem->tvs_ntabs = 0;
	for (j = 8; j < tems.ts_c_dimension.width; j += 8)
		tem->tvs_tabs[tem->tvs_ntabs++] = (screen_pos_t)j;

	for (j = 0; j < TEM_MAXPARAMS; j++)
		tem->tvs_params[j] = 0;
}

static void
tem_reset_display(struct tem_vt_state *tem, bool clear_txt, bool init_color)
{
	tem_reset_emulator(tem, init_color);

	if (clear_txt) {
		if (tem->tvs_isactive)
			tem_callback_cursor(tem, VIS_HIDE_CURSOR);

		tem_cls(tem);

		if (tem->tvs_isactive)
			tem_callback_cursor(tem, VIS_DISPLAY_CURSOR);
	}
}

static void
tem_shift(struct tem_vt_state *tem, int count, int direction)
{
	int rest_of_line;

	rest_of_line = tems.ts_c_dimension.width - tem->tvs_c_cursor.col;
	if (count > rest_of_line)
		count = rest_of_line;

	if (count <= 0)
		return;

	switch (direction) {
	case TEM_SHIFT_LEFT:
		if (count < rest_of_line) {
			tem_copy_area(tem,
			    tem->tvs_c_cursor.col + count,
			    tem->tvs_c_cursor.row,
			    tems.ts_c_dimension.width - 1,
			    tem->tvs_c_cursor.row,
			    tem->tvs_c_cursor.col,
			    tem->tvs_c_cursor.row);
		}

		tem_clear_chars(tem, count, tem->tvs_c_cursor.row,
		    (tems.ts_c_dimension.width - count));
		break;
	case TEM_SHIFT_RIGHT:
		if (count < rest_of_line) {
			tem_copy_area(tem,
			    tem->tvs_c_cursor.col,
			    tem->tvs_c_cursor.row,
			    tems.ts_c_dimension.width - count - 1,
			    tem->tvs_c_cursor.row,
			    tem->tvs_c_cursor.col + count,
			    tem->tvs_c_cursor.row);
		}

		tem_clear_chars(tem, count, tem->tvs_c_cursor.row,
		    tem->tvs_c_cursor.col);
		break;
	}
}

static void
tem_text_cursor(struct tem_vt_state *tem, short action)
{
	struct vis_conscursor	ca;

	ca.row = tem->tvs_c_cursor.row;
	ca.col = tem->tvs_c_cursor.col;
	ca.action = action;

	tems_cursor(&ca);

	if (action == VIS_GET_CURSOR) {
		tem->tvs_c_cursor.row = ca.row;
		tem->tvs_c_cursor.col = ca.col;
	}
}

static void
tem_pix_cursor(struct tem_vt_state *tem, short action)
{
	struct vis_conscursor	ca;
	text_color_t fg, bg;
	term_char_t c;
	text_attr_t attr;

	ca.row = tem->tvs_c_cursor.row * tems.ts_font.vf_height +
	    tems.ts_p_offset.y;
	ca.col = tem->tvs_c_cursor.col * tems.ts_font.vf_width +
	    tems.ts_p_offset.x;
	ca.width = tems.ts_font.vf_width;
	ca.height = tems.ts_font.vf_height;

	tem_get_attr(tem, &c.tc_fg_color, &c.tc_bg_color, &attr,
	    TEM_ATTR_REVERSE);
	c.tc_char = TEM_ATTR(attr);

	tem_get_color(tem, &fg, &bg, &c);
	tem_set_color(&fg, &ca.fg_color);
	tem_set_color(&bg, &ca.bg_color);

	ca.action = action;

	tems_cursor(&ca);

	if (action == VIS_GET_CURSOR) {
		tem->tvs_c_cursor.row = 0;
		tem->tvs_c_cursor.col = 0;

		if (ca.row != 0) {
			tem->tvs_c_cursor.row = (ca.row - tems.ts_p_offset.y) /
			    tems.ts_font.vf_height;
		}
		if (ca.col != 0) {
			tem->tvs_c_cursor.col = (ca.col - tems.ts_p_offset.x) /
			    tems.ts_font.vf_width;
		}
	}
}

static void
bit_to_pix32(struct tem_vt_state *tem,
    tem_char_t c, text_color_t fg, text_color_t bg)
{
	uint32_t *dest;

	dest = (uint32_t *)tem->tvs_pix_data;
	font_bit_to_pix32(&tems.ts_font, dest, c, fg.n, bg.n);
}

/*
 * flag: TEM_ATTR_SCREEN_REVERSE or TEM_ATTR_REVERSE
 */
static void
tem_get_attr(struct tem_vt_state *tem, text_color_t *fg,
    text_color_t *bg, text_attr_t *attr, uint8_t flag)
{
	if (tem->tvs_flags & flag) {
		*fg = tem->tvs_bg_color;
		*bg = tem->tvs_fg_color;
	} else {
		*fg = tem->tvs_fg_color;
		*bg = tem->tvs_bg_color;
	}

	if (attr != NULL)
		*attr = tem->tvs_flags;
}

static void
tem_get_color(struct tem_vt_state *tem, text_color_t *fg, text_color_t *bg,
    term_char_t *c)
{
	bool bold_font;

	*fg = c->tc_fg_color;
	*bg = c->tc_bg_color;

	bold_font = tems.ts_font.vf_map_count[VFNT_MAP_BOLD] != 0;

	/*
	 * If we have both normal and bold font components,
	 * we use bold font for TEM_ATTR_BOLD.
	 * The bright color is traditionally used with TEM_ATTR_BOLD,
	 * in case there is no bold font.
	 */
	if (!TEM_ATTR_ISSET(c->tc_char, TEM_ATTR_RGB_FG) &&
	    c->tc_fg_color.n < XLATE_NCOLORS) {
		if (TEM_ATTR_ISSET(c->tc_char, TEM_ATTR_BRIGHT_FG) ||
		    (TEM_ATTR_ISSET(c->tc_char, TEM_ATTR_BOLD) && !bold_font))
			fg->n = brt_xlate[c->tc_fg_color.n];
		else
			fg->n = dim_xlate[c->tc_fg_color.n];
	}

	if (!TEM_ATTR_ISSET(c->tc_char, TEM_ATTR_RGB_BG) &&
	    c->tc_bg_color.n < XLATE_NCOLORS) {
		if (TEM_ATTR_ISSET(c->tc_char, TEM_ATTR_BRIGHT_BG))
			bg->n = brt_xlate[c->tc_bg_color.n];
		else
			bg->n = dim_xlate[c->tc_bg_color.n];
	}

	if (tems.ts_display_mode == VIS_TEXT)
		return;

	/*
	 * Translate fg and bg to RGB colors.
	 */
	if (TEM_ATTR_ISSET(c->tc_char, TEM_ATTR_RGB_FG)) {
		fg->n = rgb_to_color(&rgb_info,
		    fg->rgb.a, fg->rgb.r, fg->rgb.g, fg->rgb.b);
	} else {
		fg->n = rgb_color_map(&rgb_info, fg->n, tem->tvs_alpha);
	}

	if (TEM_ATTR_ISSET(c->tc_char, TEM_ATTR_RGB_BG)) {
		bg->n = rgb_to_color(&rgb_info,
		    bg->rgb.a, bg->rgb.r, bg->rgb.g, bg->rgb.b);
	} else {
		bg->n = rgb_color_map(&rgb_info, bg->n, tem->tvs_alpha);
	}
}

static void
tem_set_color(text_color_t *t, color_t *c)
{
	switch (tems.ts_pdepth) {
	case 4:
		c->four = t->n & 0xFF;
		break;
	default:
		/* gfx module is expecting all pixel data in 32-bit colors */
		*(uint32_t *)c = t->n;
		break;
	}
}

void
tem_get_colors(tem_vt_state_t tem_arg, text_color_t *fg, text_color_t *bg)
{
	struct tem_vt_state *tem = (struct tem_vt_state *)tem_arg;
	text_attr_t attr;
	term_char_t c;

	tem_get_attr(tem, &c.tc_fg_color, &c.tc_bg_color, &attr,
	    TEM_ATTR_REVERSE);
	c.tc_char = TEM_ATTR(attr);
	tem_get_color(tem, fg, bg, &c);
}

/*
 * Clear a rectangle of screen for pixel mode.
 *
 * arguments:
 *    row:	start row#
 *    nrows:	the number of rows to clear
 *    offset_y:	the offset of height in pixels to begin clear
 *    col:	start col#
 *    ncols:	the number of cols to clear
 *    offset_x:	the offset of width in pixels to begin clear
 *    scroll_up: whether this function is called during sroll up,
 *		 which is called only once.
 */
static void
tem_pix_cls_range(struct tem_vt_state *tem,
    screen_pos_t row, int nrows, int offset_y,
    screen_pos_t col, int ncols, int offset_x,
    bool sroll_up)
{
	struct vis_consdisplay da;
	int	i, j;
	int	row_add = 0;
	term_char_t c;
	text_attr_t attr;

	if (sroll_up)
		row_add = tems.ts_c_dimension.height - 1;

	da.width = tems.ts_font.vf_width;
	da.height = tems.ts_font.vf_height;

	tem_get_attr(tem, &c.tc_fg_color, &c.tc_bg_color, &attr,
	    TEM_ATTR_SCREEN_REVERSE);
	/* Make sure we will not draw underlines */
	c.tc_char = TEM_ATTR(attr & ~TEM_ATTR_UNDERLINE) | ' ';

	tem_callback_bit2pix(tem, &c);
	da.data = (uint8_t *)tem->tvs_pix_data;

	for (i = 0; i < nrows; i++, row++) {
		da.row = (row + row_add) * da.height + offset_y;
		da.col = col * da.width + offset_x;
		for (j = 0; j < ncols; j++) {
			tems_display(&da);
			da.col += da.width;
		}
	}
}

/*
 * virtual screen operations
 */
static void
tem_virtual_display(struct tem_vt_state *tem, term_char_t *string,
    size_t count, screen_pos_t row, screen_pos_t col)
{
	size_t i, width;
	term_char_t *addr;

	if (tem->tvs_screen_buf == NULL)
		return;

	if (row < 0 || row >= tems.ts_c_dimension.height ||
	    col < 0 || col >= tems.ts_c_dimension.width ||
	    col + count > (size_t)tems.ts_c_dimension.width)
		return;

	width = tems.ts_c_dimension.width;
	addr = tem->tvs_screen_buf + (row * width + col);
	for (i = 0; i < count; i++) {
		*addr++ = string[i];
	}
}

static void
tem_virtual_cls(struct tem_vt_state *tem, size_t count,
    screen_pos_t row, screen_pos_t col)
{
	term_char_t c;
	text_attr_t attr;

	tem_get_attr(tem, &c.tc_fg_color, &c.tc_bg_color, &attr,
	    TEM_ATTR_SCREEN_REVERSE);
	/* Make sure we will not draw underlines */
	c.tc_char = TEM_ATTR(attr & ~TEM_ATTR_UNDERLINE) | ' ';

	while (count > 0) {
		tem_virtual_display(tem, &c, 1, row, col);
		col++;
		count--;
	}
}
