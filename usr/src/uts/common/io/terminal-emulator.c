/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <sys/tem_impl.h>
#include <sys/terminal-emulator.h>
#include <sys/param.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/console.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/beep.h>
#include <sys/promif.h>

/* Terminal emulator functions */
static int	tem_setup_terminal(struct vis_devinit *,
			struct terminal_emulator *);
static void	tem_control(struct terminal_emulator *, unsigned char,
			cred_t *, enum called_from);
static void	tem_setparam(struct terminal_emulator *, int, int);
static void	tem_selgraph(struct terminal_emulator *);
static void	tem_chkparam(struct terminal_emulator *, unsigned char,
			cred_t *, enum called_from);
static void	tem_getparams(struct terminal_emulator *, unsigned char,
			cred_t *, enum called_from);
static void	tem_outch(struct terminal_emulator *, unsigned char,
			cred_t *, enum called_from);
static void	tem_parse(struct terminal_emulator *, unsigned char,
			cred_t *, enum called_from);
static void	tem_new_line(struct terminal_emulator *,
			cred_t *, enum called_from);
static void	tem_cr(struct terminal_emulator *);
static void	tem_lf(struct terminal_emulator *,
			cred_t *, enum called_from);
static void	tem_send_data(struct terminal_emulator *, cred_t *,
			enum called_from);
static void	tem_align_cursor(struct terminal_emulator *);
static void	tem_cls(struct terminal_emulator *,
			cred_t *, enum called_from);
static void	tem_clear_entire(struct terminal_emulator *,
			cred_t *, enum called_from);
static void	tem_reset_emulator(struct terminal_emulator *);
static void	tem_reset_colormap(struct terminal_emulator *,
			cred_t *, enum called_from);
static void	tem_reset_display(struct terminal_emulator *,
			cred_t *, enum called_from, int);
static void	tem_tab(struct terminal_emulator *,
			cred_t *, enum called_from);
static void	tem_back_tab(struct terminal_emulator *,
			cred_t *, enum called_from);
static void	tem_clear_tabs(struct terminal_emulator *, int);
static void	tem_set_tab(struct terminal_emulator *);
static void	tem_mv_cursor(struct terminal_emulator *, int, int,
			cred_t *, enum called_from);
static void	tem_shift(struct terminal_emulator *, int, int,
			cred_t *, enum called_from);
static void	tem_scroll(struct terminal_emulator *, int, int,
			int, int, cred_t *, enum called_from);
static void	tem_clear_chars(struct terminal_emulator *tem,
			int count, screen_pos_t row, screen_pos_t col,
			cred_t *credp, enum called_from called_from);
static void	tem_copy_area(struct terminal_emulator *tem,
			screen_pos_t s_col, screen_pos_t s_row,
			screen_pos_t e_col, screen_pos_t e_row,
			screen_pos_t t_col, screen_pos_t t_row,
			cred_t *credp, enum called_from called_from);
static void	tem_free(struct terminal_emulator *);
static void	tem_terminal_emulate(struct terminal_emulator *,
			unsigned char *, int, cred_t *, enum called_from);
static void	tem_text_display(struct terminal_emulator *, unsigned char *,
			int, screen_pos_t, screen_pos_t,
			text_color_t, text_color_t,
			cred_t *, enum called_from);
static void	tem_text_copy(struct terminal_emulator *,
			screen_pos_t, screen_pos_t,
			screen_pos_t, screen_pos_t,
			screen_pos_t, screen_pos_t,
			cred_t *, enum called_from);
static void	tem_text_cursor(struct terminal_emulator *, short,
			cred_t *, enum called_from);
static void	tem_text_cls(struct terminal_emulator *tem,
			int count, screen_pos_t row, screen_pos_t col,
			cred_t *credp, enum called_from called_from);
static void	tem_pix_display(struct terminal_emulator *, unsigned char *,
			int, screen_pos_t, screen_pos_t,
			text_color_t, text_color_t,
			cred_t *, enum called_from);
static void	tem_pix_copy(struct terminal_emulator *,
			screen_pos_t, screen_pos_t,
			screen_pos_t, screen_pos_t,
			screen_pos_t, screen_pos_t,
			cred_t *, enum called_from);
static void	tem_pix_cursor(struct terminal_emulator *, short, cred_t *,
			enum called_from);
static void	tem_pix_cls(struct terminal_emulator *tem,
			int count, screen_pos_t row, screen_pos_t col,
			cred_t *credp, enum called_from called_from);
static void	tem_bell(struct terminal_emulator *tem,
			enum called_from called_from);
static void	tem_reset_colormap(struct terminal_emulator *,
			cred_t *, enum called_from);
static text_color_t ansi_bg_to_solaris(struct terminal_emulator *tem,
			int ansi);
static text_color_t ansi_fg_to_solaris(struct terminal_emulator *tem,
			int ansi);
static void	tem_display(struct terminal_emulator *tem,
			struct vis_consdisplay *pda, cred_t *credp,
			enum called_from called_from);
static void	tem_copy(struct terminal_emulator *tem,
			struct vis_conscopy *pma, cred_t *credp,
			enum called_from called_from);
static void	tem_cursor(struct terminal_emulator *tem,
			struct vis_conscursor *pca, cred_t *credp,
			enum called_from called_from);

static void set_font(struct font *, short *, short *, short, short);

#ifdef HAVE_1BIT
static void bit_to_pix1(struct terminal_emulator *, unsigned char,
	text_color_t, text_color_t);
#endif
static void bit_to_pix4(struct terminal_emulator *, unsigned char,
	text_color_t, text_color_t);
static void bit_to_pix8(struct terminal_emulator *, unsigned char,
	text_color_t, text_color_t);
static void bit_to_pix24(struct terminal_emulator *, unsigned char,
	text_color_t, text_color_t);

#define	INVERSE(ch) (ch ^ 0xff)

extern bitmap_data_t builtin_font_data;
extern struct fontlist fonts[];


#define	BIT_TO_PIX(tem, c, fg, bg)	{ \
	ASSERT((tem)->in_fp.f_bit2pix != NULL); \
	(void) (*(tem)->in_fp.f_bit2pix)((tem), (c), (fg), (bg)); \
}

#define	NELEM(a)	(sizeof (a) / sizeof (*(a)))


/*
 * Globals
 */
ldi_ident_t	term_li = NULL;
int		default_ansi_fg = 7;	/* WHITE */
int		default_ansi_bg = 0;	/* BLACK */


extern struct mod_ops mod_miscops;

static struct modlmisc	modlmisc = {
	&mod_miscops,		/* modops */
	"ANSI Terminal Emulator",	/* name */
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

struct fontlist fonts[] = {
	{"fonts/large.pcf", NULL, NULL},
	{"fonts/med.pcf", NULL, NULL},
	{"fonts/small.pcf", NULL, NULL},
	{NULL, NULL, NULL}
};

int
tem_fini(struct terminal_emulator *tem)
{
	int lyr_rval;

	mutex_enter(&tem->lock);

	if (tem->hdl != NULL) {
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
	}

	mutex_exit(&tem->lock);

	tem_free(tem);

	return (0);
}

/*
 * This is the main entry point to the module.  It handles output requests
 * during normal system operation, when (e.g.) mutexes are available.
 */
int
tem_write(
    struct terminal_emulator *tem,
    unsigned char *buf,
    int len,
    cred_t *credp)
{
	static int first_time = 1;

	mutex_enter(&tem->lock);

	if (tem->hdl == NULL) {
		mutex_exit(&tem->lock);
		return (ENXIO);
	}

	/*
	 * Realign the console cursor. We did this in tem_init().
	 * However, drivers in the console stream may emit additional
	 * messages before we are ready. This causes text overwrite
	 * on the screen. This is a workaround.
	 */
	if (first_time && tem->display_mode == VIS_TEXT) {
		tem_text_cursor(tem, VIS_GET_CURSOR, credp, CALLED_FROM_NORMAL);
		tem_align_cursor(tem);
	}
	first_time = 0;

	tem_terminal_emulate(tem, buf, len, credp, CALLED_FROM_NORMAL);

	mutex_exit(&tem->lock);
	return (0);
}

/*
 * This entry point handles output requests from restricted contexts like
 * kmdb, where services like mutexes are not available.
 */
int
tem_polled_write(
    struct terminal_emulator *tem,
    unsigned char *buf,
    int len)
{
	if (tem->hdl == NULL)
		return (ENXIO);

	if (tem->standalone_writes_ok) {
		tem_terminal_emulate(tem, buf, len, NULL,
			CALLED_FROM_STANDALONE);
	}

	return (0);
}

int
tem_init(
    struct terminal_emulator **ptem,
    char *pathname,
    cred_t *credp,
    int default_rows,
    int default_cols)
{
	int				err = 0, lyr_rval;
	struct vis_devinit		temargs;
	struct terminal_emulator	*tem;
	char				*pathbuf;

	tem = (struct terminal_emulator *)
		kmem_alloc(sizeof (struct terminal_emulator), KM_SLEEP);

	*ptem = tem;

	mutex_init(&tem->lock, (char *)NULL, MUTEX_DRIVER, NULL);
	mutex_enter(&tem->lock);

	tem->default_dims.height = default_rows;
	tem->default_dims.width = default_cols;

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
		tem->hdl = NULL;
		err = ENXIO;
		goto fail_1;
	}
	if (ldi_open_by_name(pathbuf, FWRITE, credp, &tem->hdl, term_li) != 0) {
		cmn_err(CE_WARN, "terminal-emulator:  device path open error");
		kmem_free(pathbuf, MAXPATHLEN);
		tem->hdl = NULL;
		err = ENXIO;
		goto fail_1;
	}
	kmem_free(pathbuf, MAXPATHLEN);

	/*
	 * Initialize the console and get the device parameters
	 */
	if (ldi_ioctl(tem->hdl, VIS_DEVINIT,
	    (intptr_t)&temargs, FWRITE|FKIOCTL, credp, &lyr_rval) != 0) {
		cmn_err(CE_WARN, "terminal-emulator:  VIS_DEVINIT failed");
		err = ENXIO;
		goto fail_2;
	}

	tem->linebytes = temargs.linebytes;
	tem->display_mode = temargs.mode;
	tem->fb_polledio = temargs.polledio;

	/*
	 * Initialize the terminal emulator
	 */
	err = tem_setup_terminal(&temargs, tem);
	if (err != 0) {
		cmn_err(CE_WARN,
	    "terminal-emulator:  terminal emulator initialization failed.");
		goto fail_3;
	}

	tem_reset_display(tem, credp, CALLED_FROM_NORMAL, 0);

	/*
	 * Allow standalone writes.
	 */
	tem->standalone_writes_ok = B_TRUE;
	mutex_exit(&tem->lock);
	return (0);

fail_3:
	/*
	 * Allow layered driver to clean up console private
	 * data.
	 */
	(void) ldi_ioctl(tem->hdl, VIS_DEVFINI, 0, FWRITE|FKIOCTL,
		    credp, &lyr_rval);
fail_2:
	(void) ldi_close(tem->hdl, NULL, credp);
	tem->hdl = NULL;
fail_1:
	mutex_exit(&tem->lock);
	return (err);
}

static int
tem_setup_terminal(struct vis_devinit *tp, struct terminal_emulator *tem)
{
	int i;

	/* Make sure the fb driver and terminal emulator versions match */
	if (tp->version != VIS_CONS_REV) {
		return (EINVAL);
	}

	tem->a_pdepth = tp->depth;

	switch (tp->mode) {
	case VIS_TEXT:
		tem->a_p_dimension.width = 0;
		tem->a_p_dimension.height = 0;
		tem->a_c_dimension.width = tp->width;
		tem->a_c_dimension.height = tp->height;
		tem->in_fp.f_display = tem_text_display;
		tem->in_fp.f_copy = tem_text_copy;
		tem->in_fp.f_cursor = tem_text_cursor;
		tem->in_fp.f_bit2pix = NULL;
		tem->in_fp.f_cls = tem_text_cls;
		tem->a_blank_line = (unsigned char *)
			kmem_alloc(tem->a_c_dimension.width, KM_SLEEP);
		for (i = 0; i < tem->a_c_dimension.width; i++)
			tem->a_blank_line[i] = ' ';

		break;
	case VIS_PIXEL:
		/*
		 * First check to see if the user has specified a screen size.
		 * If so, use those values.  Else use 34x80 as the default.
		 */
		if (tem->default_dims.width != 0)
			tem->a_c_dimension.width = tem->default_dims.width;
		else
			tem->a_c_dimension.width = TEM_DEFAULT_COLS;

		if (tem->default_dims.height != 0)
			tem->a_c_dimension.height = tem->default_dims.height;
		else
			tem->a_c_dimension.height = TEM_DEFAULT_ROWS;

		tem->in_fp.f_display = tem_pix_display;
		tem->in_fp.f_copy = tem_pix_copy;
		tem->in_fp.f_cursor = tem_pix_cursor;
		tem->in_fp.f_cls = tem_pix_cls;
		tem->a_blank_line = NULL;
		tem->a_p_dimension.height = tp->height;
		tem->a_p_dimension.width = tp->width;
		/*
		 * set_font() will select a appropriate sized font for
		 * the number of rows and columns selected.  If we don't
		 * have a font that will fit, then it will use the
		 * default builtin font and adjust the rows and columns
		 * to fit on the screen.
		 */
		set_font(&tem->a_font,
		    &tem->a_c_dimension.height, &tem->a_c_dimension.width,
		    tem->a_p_dimension.height, tem->a_p_dimension.width);
		tem->a_p_offset.y = (tem->a_p_dimension.height -
		    (tem->a_c_dimension.height * tem->a_font.height)) / 2;
		tem->a_p_offset.x = (tem->a_p_dimension.width -
		    (tem->a_c_dimension.width * tem->a_font.width)) / 2;

		switch (tp->depth) {
#if defined(HAVE_1BIT)
		case 1:
			tem->in_fp.f_bit2pix = bit_to_pix1;
			tem->a_pix_data_size = ((tem->a_font.width + NBBY
				- 1) / NBBY) * tem->a_font.height;
			break;
#endif /* HAVE_1BIT */
		case 4:
			tem->in_fp.f_bit2pix = bit_to_pix4;
			tem->a_pix_data_size = (((tem->a_font.width * 4) +
				NBBY - 1) / NBBY) * tem->a_font.height;
			break;
		case 8:
			tem->in_fp.f_bit2pix = bit_to_pix8;
			tem->a_pix_data_size = tem->a_font.width *
				tem->a_font.height;
			break;
		case 24:
			tem->in_fp.f_bit2pix = bit_to_pix24;
			tem->a_pix_data_size = tem->a_font.width *
				tem->a_font.height;
			tem->a_pix_data_size *= 4;
			break;
		}

		tem->a_pix_data = kmem_alloc(tem->a_pix_data_size, KM_SLEEP);
		break;

	default:
		tem_free(tem);
		return (ENXIO);
	}

	tem->a_outbuf =
	    (unsigned char *)kmem_alloc(tem->a_c_dimension.width, KM_SLEEP);

	return (0);
}


static void
tem_free(struct terminal_emulator *tem)
{
	if (tem == NULL)
		return;

	if (tem->a_outbuf != NULL)
		kmem_free(tem->a_outbuf, tem->a_c_dimension.width);
	if (tem->a_blank_line != NULL)
		kmem_free(tem->a_blank_line, tem->a_c_dimension.width);
	if (tem->a_pix_data != NULL)
		kmem_free(tem->a_pix_data, tem->a_pix_data_size);
	if (tem->a_font.image_data != NULL && tem->a_font.image_data_size > 0)
		kmem_free(tem->a_font.image_data, tem->a_font.image_data_size);
	kmem_free(tem, sizeof (struct terminal_emulator));
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
tem_terminal_emulate(
    struct terminal_emulator *tem,
    unsigned char *buf,
    int len,
    cred_t *credp,
    enum called_from called_from)
{
	(*tem->in_fp.f_cursor)(tem, VIS_HIDE_CURSOR, credp, called_from);

	for (; len > 0; len--, buf++)
		tem_parse(tem, *buf, credp, called_from);

	/*
	 * Send the data we just got to the framebuffer.
	 */
	tem_send_data(tem, credp, called_from);

	(*tem->in_fp.f_cursor)(tem, VIS_DISPLAY_CURSOR, credp, called_from);
}

static void
tem_reset_colormap(struct terminal_emulator *tem,
    cred_t *credp, enum called_from called_from)
{
	struct viscmap	cm;
	unsigned char r[1], b[1], g[1];
	int rval;

	if (called_from == CALLED_FROM_STANDALONE)
		return;

	cm.red = r;
	cm.blue = b;
	cm.green = g;

	cm.index = TEM_TEXT_WHITE;
	cm.count = 1;
	r[0] = 0xff;
	b[0] = 0xff;
	g[0] = 0xff;
	(void) ldi_ioctl(tem->hdl, VIS_PUTCMAP, (intptr_t)&cm,
	    FKIOCTL, credp, &rval);

	cm.index = TEM_TEXT_BLACK;
	cm.count = 1;
	r[0] = 0;
	b[0] = 0;
	g[0] = 0;
	(void) ldi_ioctl(tem->hdl, VIS_PUTCMAP, (intptr_t)&cm,
	    FKIOCTL, credp, &rval);
}

/*
 * send the appropriate control message or set state based on the
 * value of the control character ch
 */
static void
tem_control(
	struct terminal_emulator *tem,
	unsigned char ch,
	cred_t *credp,
	enum called_from called_from)
{
	tem->a_state = A_STATE_START;
	switch (ch) {
	case A_BEL:
		tem_bell(tem, called_from);
		break;

	case A_BS:
		tem_mv_cursor(tem,
		    tem->a_c_cursor.row, tem->a_c_cursor.col - 1,
		    credp, called_from);
		break;

	case A_HT:
		tem_tab(tem, credp, called_from);
		break;

	case A_NL:
		/*
		 * tem_send_data(tem, credp, called_from);
		 * tem_new_line(tem, credp, called_from);
		 * break;
		 */

	case A_VT:
		tem_send_data(tem, credp, called_from);
		tem_lf(tem, credp, called_from);
		break;

	case A_FF:
		tem_send_data(tem, credp, called_from);
		tem_cls(tem, credp, called_from);
		break;

	case A_CR:
		tem_send_data(tem, credp, called_from);
		tem_cr(tem);
		break;

	case A_ESC:
		tem->a_state = A_STATE_ESC;
		break;

	case A_CSI:
		{
			int i;
			tem->a_curparam = 0;
			tem->a_paramval = 0;
			tem->a_gotparam = B_FALSE;
			/* clear the parameters */
			for (i = 0; i < TEM_MAXPARAMS; i++)
				tem->a_params[i] = -1;
			tem->a_state = A_STATE_CSI;
		}
		break;

	case A_GS:
		tem_back_tab(tem, credp, called_from);
		break;

	default:
		break;
	}
}


/*
 * if parameters [0..count - 1] are not set, set them to the value of newparam.
 */

static void
tem_setparam(struct terminal_emulator *tem, int count, int newparam)
{
	int i;

	for (i = 0; i < count; i++) {
		if (tem->a_params[i] == -1)
			tem->a_params[i] = newparam;
	}
}


/*
 * select graphics mode based on the param vals stored in a_params
 */
static void
tem_selgraph(struct terminal_emulator *tem)
{
	int curparam;
	int count = 0;
	int param;

	curparam = tem->a_curparam;
	do {
		param = tem->a_params[count];

		switch (param) {
		case -1:
		case 0:
			if (tem->a_flags & TEM_ATTR_SCREEN_REVERSE) {
				tem->a_flags |= TEM_ATTR_REVERSE;
			} else {
				tem->a_flags &= ~TEM_ATTR_REVERSE;
			}
			tem->a_flags &= ~TEM_ATTR_BOLD;
			tem->a_flags &= ~TEM_ATTR_BLINK;
			tem->fg_color = default_ansi_fg;
			tem->bg_color = default_ansi_bg;
			break;

		case 1: /* Bold Intense */
			tem->a_flags |= TEM_ATTR_BOLD;
			break;

		case 5: /* Blink */
			tem->a_flags |= TEM_ATTR_BLINK;
			break;

		case 7: /* Reverse video */
			if (tem->a_flags & TEM_ATTR_SCREEN_REVERSE) {
				tem->a_flags &= ~TEM_ATTR_REVERSE;
			} else {
				tem->a_flags |= TEM_ATTR_REVERSE;
			}
			break;

		case 30: /* black	(grey) 		foreground */
		case 31: /* red		(light red) 	foreground */
		case 32: /* green	(light green) 	foreground */
		case 33: /* brown	(yellow) 	foreground */
		case 34: /* blue	(light blue) 	foreground */
		case 35: /* magenta	(light magenta) foreground */
		case 36: /* cyan	(light cyan) 	foreground */
		case 37: /* white	(bright white) 	foreground */
			tem->fg_color = param - 30;
			break;

		case 40: /* black	(grey) 		background */
		case 41: /* red		(light red) 	background */
		case 42: /* green	(light green) 	background */
		case 43: /* brown	(yellow) 	background */
		case 44: /* blue	(light blue) 	background */
		case 45: /* magenta	(light magenta) background */
		case 46: /* cyan	(light cyan) 	background */
		case 47: /* white	(bright white) 	background */
			tem->bg_color = param - 40;
			break;

		default:
			break;
		}
		count++;
		curparam--;

	} while (curparam > 0);


	tem->a_state = A_STATE_START;
}

/*
 * perform the appropriate action for the escape sequence
 *
 * General rule:  This code does not validate the arguments passed.
 *                It assumes that the next lower level will do so.
 */
static void
tem_chkparam(
	struct terminal_emulator *tem,
	unsigned char ch,
	cred_t *credp,
	enum called_from called_from)
{
	int i;
	int	row;
	int	col;

	row = tem->a_c_cursor.row;
	col = tem->a_c_cursor.col;

	switch (ch) {

	case 'm': /* select terminal graphics mode */
		tem_send_data(tem, credp, called_from);
		tem_selgraph(tem);
		break;

	case '@':		/* insert char */
		tem_setparam(tem, 1, 1);
		tem_shift(tem, tem->a_params[0], TEM_SHIFT_RIGHT,
		    credp, called_from);
		break;

	case 'A':		/* cursor up */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row - tem->a_params[0], col,
			credp, called_from);
		break;

	case 'd':		/* VPA - vertical position absolute */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, tem->a_params[0] - 1, col,
			credp, called_from);
		break;

	case 'e':		/* VPR - vertical position relative */
	case 'B':		/* cursor down */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row + tem->a_params[0], col,
			credp, called_from);
		break;

	case 'a':		/* HPR - horizontal position relative */
	case 'C':		/* cursor right */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row, col + tem->a_params[0],
			credp, called_from);
		break;

	case '`':		/* HPA - horizontal position absolute */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row, tem->a_params[0] - 1,
			credp, called_from);
		break;

	case 'D':		/* cursor left */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row, col - tem->a_params[0],
			credp, called_from);
		break;

	case 'E':		/* CNL cursor next line */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row + tem->a_params[0], 0,
			credp, called_from);
		break;

	case 'F':		/* CPL cursor previous line */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row - tem->a_params[0], 0,
			credp, called_from);
		break;

	case 'G':		/* cursor horizontal position */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row, tem->a_params[0] - 1,
			credp, called_from);
		break;

	case 'g':		/* clear tabs */
		tem_setparam(tem, 1, 0);
		tem_clear_tabs(tem, tem->a_params[0]);
		break;

	case 'f':		/* HVP Horizontal and Vertical Position */
	case 'H':		/* CUP position cursor */
		tem_setparam(tem, 2, 1);
		tem_mv_cursor(tem,
			tem->a_params[0] - 1, tem->a_params[1] - 1,
			credp, called_from);
		break;

	case 'I':		/* CHT - Cursor Horizontal Tab */
		/* Not implemented */
		break;

	case 'J':		/* ED - Erase in Display */
		tem_send_data(tem, credp, called_from);
		tem_setparam(tem, 1, 0);
		switch (tem->a_params[0]) {
		case 0:
			/* erase cursor to end of screen */
			/* FIRST erase cursor to end of line */
			tem_clear_chars(tem,
				tem->a_c_dimension.width -
						tem->a_c_cursor.col,
				tem->a_c_cursor.row,
				tem->a_c_cursor.col, credp, called_from);

			/* THEN erase lines below the cursor */
			for (row = tem->a_c_cursor.row + 1;
				row < tem->a_c_dimension.height;
				row++) {
				tem_clear_chars(tem,
					tem->a_c_dimension.width,
					row, 0, credp, called_from);
			}
			break;

		case 1:
			/* erase beginning of screen to cursor */
			/* FIRST erase lines above the cursor */
			for (row = 0;
				row < tem->a_c_cursor.row;
				row++) {
				tem_clear_chars(tem,
					tem->a_c_dimension.width,
					row, 0, credp, called_from);
			}
			/* THEN erase beginning of line to cursor */
			tem_clear_chars(tem,
				tem->a_c_cursor.col + 1,
				tem->a_c_cursor.row, 0, credp, called_from);
			break;

		case 2:
			/* erase whole screen */
			for (row = 0;
				row < tem->a_c_dimension.height;
				row++) {
				tem_clear_chars(tem,
					tem->a_c_dimension.width,
					row, 0, credp, called_from);
			}
			break;
		}
		break;

	case 'K':		/* EL - Erase in Line */
		tem_send_data(tem, credp, called_from);
		tem_setparam(tem, 1, 0);
		switch (tem->a_params[0]) {
		case 0:
			/* erase cursor to end of line */
			tem_clear_chars(tem,
				(tem->a_c_dimension.width -
				    tem->a_c_cursor.col),
				tem->a_c_cursor.row,
				tem->a_c_cursor.col, credp, called_from);
			break;

		case 1:
			/* erase beginning of line to cursor */
			tem_clear_chars(tem,
				tem->a_c_cursor.col + 1,
				tem->a_c_cursor.row, 0, credp, called_from);
			break;

		case 2:
			/* erase whole line */
			tem_clear_chars(tem,
				tem->a_c_dimension.width,
				tem->a_c_cursor.row, 0, credp, called_from);
			break;
		}
		break;

	case 'L':		/* insert line */
		tem_send_data(tem, credp, called_from);
		tem_setparam(tem, 1, 1);
		tem_scroll(tem,
			tem->a_c_cursor.row,
			tem->a_c_dimension.height - 1,
			tem->a_params[0], TEM_SCROLL_DOWN, credp, called_from);
		break;

	case 'M':		/* delete line */
		tem_send_data(tem, credp, called_from);
		tem_setparam(tem, 1, 1);
		tem_scroll(tem,
			tem->a_c_cursor.row,
			tem->a_c_dimension.height - 1,
			tem->a_params[0], TEM_SCROLL_UP, credp, called_from);
		break;

	case 'P':		/* DCH - delete char */
		tem_setparam(tem, 1, 1);
		tem_shift(tem, tem->a_params[0], TEM_SHIFT_LEFT,
		    credp, called_from);
		break;

	case 'S':		/* scroll up */
		tem_send_data(tem, credp, called_from);
		tem_setparam(tem, 1, 1);
		tem_scroll(tem, 0,
			tem->a_c_dimension.height - 1,
			tem->a_params[0], TEM_SCROLL_UP, credp, called_from);
		break;

	case 'T':		/* scroll down */
		tem_send_data(tem, credp, called_from);
		tem_setparam(tem, 1, 1);
		tem_scroll(tem, 0,
			tem->a_c_dimension.height - 1,
			tem->a_params[0], TEM_SCROLL_DOWN, credp, called_from);
		break;

	case 'X':		/* erase char */
		tem_setparam(tem, 1, 1);
		tem_clear_chars(tem,
			tem->a_params[0],
			tem->a_c_cursor.row,
			tem->a_c_cursor.col, credp, called_from);
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
		if (tem->a_params[0] > tem->a_c_dimension.width)
			tem->a_params[0] = tem->a_c_dimension.width;

		for (i = 0; i < tem->a_params[0]; i++)
			tem_back_tab(tem, credp, called_from);
		break;
	}
	tem->a_state = A_STATE_START;
}


/*
 * Gather the parameters of an ANSI escape sequence
 */
static void
tem_getparams(struct terminal_emulator *tem, unsigned char ch,
    cred_t *credp, enum called_from called_from)
{
	if ((ch >= '0' && ch <= '9') && (tem->a_state != A_STATE_ESC_Q_DELM)) {
		tem->a_paramval = ((tem->a_paramval * 10) + (ch - '0'));
		tem->a_gotparam = B_TRUE;	/* Remember got parameter */
		return;			/* Return immediately */
	}
	switch (tem->a_state) {		/* Handle letter based on state */

	case A_STATE_ESC_Q:			  /* <ESC>Q<num> ? */
		tem->a_params[1] = ch;		  /* Save string delimiter */
		tem->a_params[2] = 0;		  /* String length 0 to start */
		tem->a_state = A_STATE_ESC_Q_DELM; /* Read string next */
		break;

	case A_STATE_ESC_Q_DELM:		  /* <ESC>Q<num><delm> ? */
		if (ch == tem->a_params[1]) {	/* End of string? */
			tem->a_state = A_STATE_START;
			/* End of <ESC> sequence */
		} else if (ch == '^')
			/* Control char escaped with '^'? */
			tem->a_state = A_STATE_ESC_Q_DELM_CTRL;
			/* Read control character next */

		else if (ch != '\0') {
			/* Not a null? Add to string */
			tem->a_fkey[tem->a_params[2]++] = ch;
			if (tem->a_params[2] >= TEM_MAXFKEY)	/* Full? */
				tem->a_state = A_STATE_START;
				/* End of <ESC> sequence */
		}
		break;

	case A_STATE_ESC_Q_DELM_CTRL:	/* Contrl character escaped with '^' */
		tem->a_state = A_STATE_ESC_Q_DELM; /* Read more string later */
		ch -= ' ';		/* Convert to control character */
		if (ch != '\0') {	/* Not a null? Add to string */
			tem->a_fkey[tem->a_params[2]++] = ch;
			if (tem->a_params[2] >= TEM_MAXFKEY)	/* Full? */
				tem->a_state = A_STATE_START;
				/* End of <ESC> sequence */
		}
		break;

	default:			/* All other states */
		if (tem->a_gotparam) {
			if (tem->a_curparam >= TEM_MAXPARAMS) {
				/*
				 * Too many parameters.  Abort the
				 * sequence.
				 */
				tem->a_state = A_STATE_START;
				break;
			}
			/*
			 * Previous number parameter? Save and
			 * point to next free parameter.
			 */
			tem->a_params[tem->a_curparam] = tem->a_paramval;
			tem->a_curparam++;
		}

		if (ch == ';') {
			/* Multiple param separator? */
			/* Restart parameter search */
			tem->a_gotparam = B_FALSE;
			tem->a_paramval = 0;	/* No parameter value yet */
		} else if (tem->a_state == A_STATE_CSI_EQUAL ||
			tem->a_state == A_STATE_CSI_QMARK) {
			tem->a_state = A_STATE_START;
		} else	/* Regular letter */
			/* Handle escape sequence */
			tem_chkparam(tem, ch, credp, called_from);
		break;
	}
}

/*
 * Add character to internal buffer.
 * When its full, send it to the next layer.
 */

static void
tem_outch(struct terminal_emulator *tem, unsigned char ch,
    cred_t *credp, enum called_from called_from)
{
	/* buffer up the character until later */

	tem->a_outbuf[tem->a_outindex++] = ch;
	tem->a_c_cursor.col++;
	if (tem->a_c_cursor.col >= tem->a_c_dimension.width) {
		tem_send_data(tem, credp, called_from);
		tem_new_line(tem, credp, called_from);
	}
}

static void
tem_new_line(struct terminal_emulator *tem,
    cred_t *credp, enum called_from called_from)
{
	tem_cr(tem);
	tem_lf(tem, credp, called_from);
}

static void
tem_cr(struct terminal_emulator *tem)
{
	tem->a_c_cursor.col = 0;
	tem_align_cursor(tem);
}

static void
tem_lf(struct terminal_emulator *tem,
    cred_t *credp, enum called_from called_from)
{
	int row;

	/*
	 * Sanity checking notes:
	 * . a_nscroll was validated when it was set.
	 * . Regardless of that, tem_scroll and tem_mv_cursor will prevent
	 *   anything bad from happening.
	 */
	row = tem->a_c_cursor.row + 1;

	if (row >= tem->a_c_dimension.height) {
		if (tem->a_nscroll != 0) {
			tem_scroll(tem, 0,
			    tem->a_c_dimension.height - 1,
			    tem->a_nscroll, TEM_SCROLL_UP, credp, called_from);
			row = tem->a_c_dimension.height - tem->a_nscroll;
		} else {	/* no scroll */
			/*
			 * implement Esc[#r when # is zero.  This means no
			 * scroll but just return cursor to top of screen,
			 * do not clear screen.
			 */
			row = 0;
		}
	}

	tem_mv_cursor(tem, row, tem->a_c_cursor.col,
		credp, called_from);

	if (tem->a_nscroll == 0) {
		/* erase rest of cursor line */
		tem_clear_chars(tem,
			tem->a_c_dimension.width - tem->a_c_cursor.col,
			tem->a_c_cursor.row,
			tem->a_c_cursor.col, credp, called_from);

	}

	tem_align_cursor(tem);
}

static void
tem_send_data(struct terminal_emulator *tem, cred_t *credp,
    enum called_from called_from)
{
	text_color_t fg_color;
	text_color_t bg_color;

	if (tem->a_outindex != 0) {

		if (tem->a_flags & TEM_ATTR_REVERSE) {
			fg_color = ansi_fg_to_solaris(tem, tem->bg_color);
			bg_color = ansi_bg_to_solaris(tem, tem->fg_color);
		} else {
			fg_color = ansi_fg_to_solaris(tem, tem->fg_color);
			bg_color = ansi_bg_to_solaris(tem, tem->bg_color);
		}

		/*
		 * Call the primitive to render this data.
		 */
		(*tem->in_fp.f_display)(tem,
			tem->a_outbuf,
			tem->a_outindex,
			tem->a_s_cursor.row, tem->a_s_cursor.col,
			fg_color, bg_color,
			credp, called_from);
		tem->a_outindex = 0;
	}
	tem_align_cursor(tem);
}


/*
 * We have just done something to the current output point.  Reset the start
 * point for the buffered data in a_outbuf.  There shouldn't be any data
 * buffered yet.
 */
static void
tem_align_cursor(struct terminal_emulator *tem)
{
	tem->a_s_cursor.row = tem->a_c_cursor.row;
	tem->a_s_cursor.col = tem->a_c_cursor.col;
}



/*
 * State machine parser based on the current state and character input
 * major terminations are to control character or normal character
 */

static void
tem_parse(struct terminal_emulator *tem, unsigned char ch,
    cred_t *credp, enum called_from called_from)
{
	int	i;

	if (tem->a_state == A_STATE_START) {	/* Normal state? */
		if (ch == A_CSI || ch == A_ESC || ch < ' ') /* Control? */
			tem_control(tem, ch, credp, called_from);
		else
			/* Display */
			tem_outch(tem, ch, credp, called_from);
	} else {	/* In <ESC> sequence */
		/* Need to get parameters? */
		if (tem->a_state != A_STATE_ESC) {
			if (tem->a_state == A_STATE_CSI) {
				switch (ch) {
				case '?':
					tem->a_state = A_STATE_CSI_QMARK;
					return;
				case '=':
					tem->a_state = A_STATE_CSI_EQUAL;
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
					 * tem->a_r_cursor.row =
					 *	tem->a_c_cursor.row;
					 * tem->a_r_cursor.col =
					 *	tem->a_c_cursor.col;
					 * tem->a_state = A_STATE_START;
					 */

					tem->a_state = A_STATE_START;
					return;
				case 'u':
					tem_mv_cursor(tem,
					    tem->a_r_cursor.row,
					    tem->a_r_cursor.col,
					    credp, called_from);
					tem->a_state = A_STATE_START;
					return;
				case 'p': 	/* sunbow */
					tem_send_data(tem, credp, called_from);
					/*
					 * Don't set anything if we are
					 * already as we want to be.
					 */
					if (tem->a_flags &
					    TEM_ATTR_SCREEN_REVERSE) {
						tem->a_flags &=
						    ~TEM_ATTR_SCREEN_REVERSE;
						/*
						 * If we have switched the
						 * characters to be the
						 * inverse from the screen,
						 * then switch them as well
						 * to keep them the inverse
						 * of the screen.
						 */
						if (tem->a_flags &
						    TEM_ATTR_REVERSE) {
							tem->a_flags &=
							    ~TEM_ATTR_REVERSE;
						} else {
							tem->a_flags |=
							    TEM_ATTR_REVERSE;
						}
					}
					if (tem->display_mode ==
					    VIS_PIXEL) {
						tem_clear_entire(tem,
						    credp, called_from);
					} else {
						tem_cls(tem,
						    credp, called_from);
					}
					tem->a_state = A_STATE_START;
					return;
				case 'q':  	/* sunwob */
					tem_send_data(tem, credp, called_from);
					/*
					 * Don't set anything if we are
					 * already where as we want to be.
					 */
					if (!(tem->a_flags &
					    TEM_ATTR_SCREEN_REVERSE)) {
						tem->a_flags |=
						    TEM_ATTR_SCREEN_REVERSE;
						/*
						 * If we have switched the
						 * characters to be the
						 * inverse from the screen,
						 * then switch them as well
						 * to keep them the inverse
						 * of the screen.
						 */
						if (!(tem->a_flags &
						    TEM_ATTR_REVERSE)) {
							tem->a_flags |=
							    TEM_ATTR_REVERSE;
						} else {
							tem->a_flags &=
							    ~TEM_ATTR_REVERSE;
						}
					}

					if (tem->display_mode ==
					    VIS_PIXEL) {
						tem_clear_entire(tem,
						    credp, called_from);
					} else {
						tem_cls(tem,
						    credp, called_from);
					}
					tem->a_state = A_STATE_START;
					return;
				case 'r':	/* sunscrl */
					/*
					 * Rule exception:  check for
					 * validity here.
					 */
					tem->a_nscroll = tem->a_paramval;
					if (tem->a_nscroll >
					    tem->a_c_dimension.height) {
						tem->a_nscroll =
						    tem->a_c_dimension.height;
					}
					if (tem->a_nscroll < 0)
						tem->a_nscroll = 1;
					tem->a_state = A_STATE_START;
					return;
				}
			}
			tem_getparams(tem, ch, credp, called_from);
		} else {	/* Previous char was <ESC> */
			if (ch == '[') {
				tem->a_curparam = 0;
				tem->a_paramval = 0;
				tem->a_gotparam = B_FALSE;
				/* clear the parameters */
				for (i = 0; i < TEM_MAXPARAMS; i++)
					tem->a_params[i] = -1;
				tem->a_state = A_STATE_CSI;
			} else if (ch == 'Q') {	/* <ESC>Q ? */
				tem->a_curparam = 0;
				tem->a_paramval = 0;
				tem->a_gotparam = B_FALSE;
				for (i = 0; i < TEM_MAXPARAMS; i++)
					tem->a_params[i] = -1;	/* Clear */
				/* Next get params */
				tem->a_state = A_STATE_ESC_Q;
			} else if (ch == 'C') {	/* <ESC>C ? */
				tem->a_curparam = 0;
				tem->a_paramval = 0;
				tem->a_gotparam = B_FALSE;
				for (i = 0; i < TEM_MAXPARAMS; i++)
					tem->a_params[i] = -1;	/* Clear */
				/* Next get params */
				tem->a_state = A_STATE_ESC_C;
			} else {
				tem->a_state = A_STATE_START;
				if (ch == 'c')
					/* ESC c resets display */
					tem_reset_display(tem, credp,
					    called_from, 1);
				else if (ch == 'H')
					/* ESC H sets a tab */
					tem_set_tab(tem);
				else if (ch == '7') {
					/* ESC 7 Save Cursor position */
					tem->a_r_cursor.row =
						tem->a_c_cursor.row;
					tem->a_r_cursor.col =
						tem->a_c_cursor.col;
				} else if (ch == '8')
					/* ESC 8 Restore Cursor position */
					tem_mv_cursor(tem,
					    tem->a_r_cursor.row,
					    tem->a_r_cursor.col, credp,
						called_from);
				/* check for control chars */
				else if (ch < ' ')
					tem_control(tem, ch, credp,
					    called_from);
				else
					tem_outch(tem, ch, credp,
					    called_from);
			}
		}
	}
}

/* ARGSUSED */
static void
tem_bell(struct terminal_emulator *tem, enum called_from called_from)
{
	if (called_from == CALLED_FROM_STANDALONE)
		beep_polled(BEEP_CONSOLE);
	else
		beep(BEEP_CONSOLE);
}


static void
tem_scroll(struct terminal_emulator *tem,
    int start, int end, int count, int direction,
	cred_t *credp, enum called_from called_from)
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
			tem_copy_area(tem,
					0, start + count,
					tem->a_c_dimension.width - 1, end,
					0, start,
					credp, called_from);
		}
		for (row = (end - count) + 1; row <= end; row++) {
			tem_clear_chars(tem,
				tem->a_c_dimension.width,
				row, 0, credp, called_from);
		}
		break;

	case TEM_SCROLL_DOWN:
		if (count < lines_affected) {
			tem_copy_area(tem,
				    0, start,
				    tem->a_c_dimension.width - 1, end - count,
				    0, start + count,
				    credp, called_from);
		}
		for (row = start; row < start + count; row++) {
			tem_clear_chars(tem,
				tem->a_c_dimension.width,
				row, 0, credp, called_from);
		}
		break;
	}
}

static void
tem_copy_area(struct terminal_emulator *tem,
	screen_pos_t s_col, screen_pos_t s_row,
	screen_pos_t e_col, screen_pos_t e_row,
	screen_pos_t t_col, screen_pos_t t_row,
	cred_t *credp, enum called_from called_from)
{
	int rows;
	int cols;

	if (s_col < 0 || s_row < 0 ||
	    e_col < 0 || e_row < 0 ||
	    t_col < 0 || t_row < 0 ||
	    s_col >= tem->a_c_dimension.width ||
	    e_col >= tem->a_c_dimension.width ||
	    t_col >= tem->a_c_dimension.width ||
	    s_row >= tem->a_c_dimension.height ||
	    e_row >= tem->a_c_dimension.height ||
	    t_row >= tem->a_c_dimension.height)
		return;

	if (s_row > e_row || s_col > e_col)
		return;

	rows = e_row - s_row + 1;
	cols = e_col - s_col + 1;
	if (t_row + rows > tem->a_c_dimension.height ||
	    t_col + cols > tem->a_c_dimension.width)
		return;

	(*tem->in_fp.f_copy)(tem,
		s_col, s_row,
		e_col, e_row,
		t_col, t_row,
		credp, called_from);
}

static void
tem_clear_chars(struct terminal_emulator *tem,
	int count, screen_pos_t row, screen_pos_t col, cred_t *credp,
	enum called_from called_from)
{
	if (row < 0 || row >= tem->a_c_dimension.height ||
	    col < 0 || col >= tem->a_c_dimension.width ||
	    count < 0)
		return;

	/*
	 * Note that very large values of "count" could cause col+count
	 * to overflow, so we check "count" independently.
	 */
	if (count > tem->a_c_dimension.width ||
	    col + count > tem->a_c_dimension.width)
		count = tem->a_c_dimension.width - col;

	(*tem->in_fp.f_cls)(tem, count, row, col, credp, called_from);
}

static void
tem_text_display(struct terminal_emulator *tem, unsigned char *string,
	int count, screen_pos_t row, screen_pos_t col,
	text_color_t fg_color, text_color_t bg_color,
	cred_t *credp, enum called_from called_from)
{
	struct vis_consdisplay da;

	da.version = VIS_DISPLAY_VERSION;
	da.data = string;
	da.width = count;
	da.row = row;
	da.col = col;

	da.fg_color = fg_color;
	da.bg_color = bg_color;

	tem_display(tem, &da, credp, called_from);
}

static void
tem_text_copy(struct terminal_emulator *tem,
	screen_pos_t s_col, screen_pos_t s_row,
	screen_pos_t e_col, screen_pos_t e_row,
	screen_pos_t t_col, screen_pos_t t_row,
	cred_t *credp, enum called_from called_from)
{
	struct vis_conscopy	ma;

	ma.version = VIS_COPY_VERSION;
	ma.s_row = s_row;
	ma.s_col = s_col;
	ma.e_row = e_row;
	ma.e_col = e_col;
	ma.t_row = t_row;
	ma.t_col = t_col;

	tem_copy(tem, &ma, credp, called_from);
}

static void
tem_text_cls(struct terminal_emulator *tem,
	int count, screen_pos_t row, screen_pos_t col, cred_t *credp,
	enum called_from called_from)
{
	struct vis_consdisplay da;

	da.version = VIS_DISPLAY_VERSION;
	da.data = tem->a_blank_line;
	da.width = count;
	da.row = row;
	da.col = col;

	if (tem->a_flags & TEM_ATTR_SCREEN_REVERSE) {
		da.fg_color = ansi_fg_to_solaris(tem, default_ansi_bg);
		da.bg_color = ansi_bg_to_solaris(tem, default_ansi_fg);
	} else {
		da.fg_color = ansi_fg_to_solaris(tem, default_ansi_fg);
		da.bg_color = ansi_bg_to_solaris(tem, default_ansi_bg);
	}

	tem_display(tem, &da, credp, called_from);
}

void
tem_pix_display(struct terminal_emulator *tem,
	unsigned char *string, int count,
	screen_pos_t row, screen_pos_t col,
	text_color_t fg_color, text_color_t bg_color,
	cred_t *credp, enum called_from called_from)
{
	struct vis_consdisplay		da;
	int	i;

	da.version = VIS_DISPLAY_VERSION;
	da.data = (unsigned char *)tem->a_pix_data;
	da.width = tem->a_font.width;
	da.height = tem->a_font.height;
	da.row = (row * da.height) + tem->a_p_offset.y;
	da.col = (col * da.width) + tem->a_p_offset.x;

	for (i = 0; i < count; i++) {
		BIT_TO_PIX(tem, string[i], fg_color, bg_color);
		tem_display(tem, &da, credp, called_from);
		da.col += da.width;
	}
}

static void
tem_pix_copy(struct terminal_emulator *tem,
	screen_pos_t s_col, screen_pos_t s_row,
	screen_pos_t e_col, screen_pos_t e_row,
	screen_pos_t t_col, screen_pos_t t_row,
	cred_t *credp,
	enum called_from called_from)
{
	struct vis_conscopy ma;

	ma.version = VIS_COPY_VERSION;
	ma.s_row = s_row * tem->a_font.height + tem->a_p_offset.y;
	ma.s_col = s_col * tem->a_font.width + tem->a_p_offset.x;
	ma.e_row = (e_row + 1) * tem->a_font.height +
			tem->a_p_offset.y - 1;
	ma.e_col = (e_col + 1) * tem->a_font.width +
			tem->a_p_offset.x - 1;
	ma.t_row = t_row * tem->a_font.height + tem->a_p_offset.y;
	ma.t_col = t_col * tem->a_font.width + tem->a_p_offset.x;

	tem_copy(tem, &ma, credp, called_from);
}

void
tem_pix_cls(struct terminal_emulator *tem, int count,
	screen_pos_t row, screen_pos_t col, cred_t *credp,
	enum called_from called_from)
{
	struct vis_consdisplay		da;
	int	i;
	text_color_t fg_color;
	text_color_t bg_color;

	da.version = VIS_DISPLAY_VERSION;
	da.width = tem->a_font.width;
	da.height = tem->a_font.height;
	da.row = (row * da.height) + tem->a_p_offset.y;
	da.col = (col * da.width) + tem->a_p_offset.x;

	if (tem->a_flags & TEM_ATTR_SCREEN_REVERSE) {
		fg_color = ansi_fg_to_solaris(tem, default_ansi_bg);
		bg_color = ansi_bg_to_solaris(tem, default_ansi_fg);
	} else {
		fg_color = ansi_fg_to_solaris(tem, default_ansi_fg);
		bg_color = ansi_bg_to_solaris(tem, default_ansi_bg);
	}

	BIT_TO_PIX(tem, ' ', fg_color, bg_color);
	da.data = (unsigned char *)tem->a_pix_data;

	for (i = 0; i < count; i++) {
		tem_display(tem, &da, credp, called_from);
		da.col += da.width;
	}
}

static void
tem_back_tab(struct terminal_emulator *tem,
    cred_t *credp, enum called_from called_from)
{
	int	i;
	screen_pos_t	tabstop;

	tabstop = 0;

	for (i = tem->a_ntabs - 1; i >= 0; i--) {
		if (tem->a_tabs[i] < tem->a_c_cursor.col) {
			tabstop = tem->a_tabs[i];
			break;
		}
	}

	tem_mv_cursor(tem, tem->a_c_cursor.row, tabstop, credp, called_from);
}


static void
tem_tab(struct terminal_emulator *tem,
    cred_t *credp, enum called_from called_from)
{
	int	i;
	screen_pos_t	tabstop;

	tabstop = tem->a_c_dimension.width - 1;

	for (i = 0; i < tem->a_ntabs; i++) {
		if (tem->a_tabs[i] > tem->a_c_cursor.col) {
			tabstop = tem->a_tabs[i];
			break;
		}
	}

	tem_mv_cursor(tem, tem->a_c_cursor.row, tabstop, credp, called_from);
}

static void
tem_set_tab(struct terminal_emulator *tem)
{
	int	i;
	int	j;

	if (tem->a_ntabs == TEM_MAXTAB)
		return;
	if (tem->a_ntabs == 0 ||
		tem->a_tabs[tem->a_ntabs] < tem->a_c_cursor.col) {
		tem->a_tabs[tem->a_ntabs++] = tem->a_c_cursor.col;
		return;
	}
	for (i = 0; i < tem->a_ntabs; i++) {
		if (tem->a_tabs[i] == tem->a_c_cursor.col)
			return;
		if (tem->a_tabs[i] > tem->a_c_cursor.col) {
			for (j = tem->a_ntabs - 1; j >= i; j--)
				tem->a_tabs[j+ 1] = tem->a_tabs[j];
			tem->a_tabs[i] = tem->a_c_cursor.col;
			tem->a_ntabs++;
			return;
		}
	}
}


static void
tem_clear_tabs(struct terminal_emulator *tem, int action)
{
	int	i;
	int	j;

	switch (action) {
	case 3: /* clear all tabs */
		tem->a_ntabs = 0;
		break;
	case 0: /* clr tab at cursor */

		for (i = 0; i < tem->a_ntabs; i++) {
			if (tem->a_tabs[i] == tem->a_c_cursor.col) {
				tem->a_ntabs--;
				for (j = i; j < tem->a_ntabs; j++)
					tem->a_tabs[j] = tem->a_tabs[j + 1];
				return;
			}
		}
		break;
	}
}

static void
tem_clear_entire(struct terminal_emulator *tem, cred_t *credp,
    enum called_from called_from)
{
	int	row;
	int	nrows;
	int	col;
	int	ncols;
	struct vis_consdisplay	da;
	text_color_t fg_color;
	text_color_t bg_color;

	da.version = VIS_DISPLAY_VERSION;
	da.width = tem->a_font.width;
	da.height = tem->a_font.height;
	nrows = (tem->a_p_dimension.height + (da.height - 1))/ da.height;
	ncols = (tem->a_p_dimension.width + (da.width - 1))/ da.width;

	if (tem->a_flags & TEM_ATTR_SCREEN_REVERSE) {
		fg_color = ansi_fg_to_solaris(tem, default_ansi_bg);
		bg_color = ansi_bg_to_solaris(tem, default_ansi_fg);
	} else {
		fg_color = ansi_fg_to_solaris(tem, default_ansi_fg);
		bg_color = ansi_bg_to_solaris(tem, default_ansi_bg);
	}

	BIT_TO_PIX(tem, ' ', fg_color, bg_color);
	da.data = (unsigned char *)tem->a_pix_data;

	for (row = 0; row < nrows; row++) {
		da.row = row * da.height;
		da.col = 0;
		for (col = 0; col < ncols; col++) {
			tem_display(tem, &da, credp, called_from);
			da.col += da.width;
		}
	}

	tem->a_c_cursor.row = 0;
	tem->a_c_cursor.col = 0;
	tem_align_cursor(tem);
}

static void
tem_cls(struct terminal_emulator *tem,
    cred_t *credp, enum called_from called_from)
{
	int	row;

	for (row = 0; row < tem->a_c_dimension.height; row++) {
		tem_clear_chars(tem,
			tem->a_c_dimension.width,
			row, 0, credp, called_from);
	}
	tem->a_c_cursor.row = 0;
	tem->a_c_cursor.col = 0;
	tem_align_cursor(tem);
}

static void
tem_mv_cursor(struct terminal_emulator *tem, int row, int col,
    cred_t *credp, enum called_from called_from)
{
	/*
	 * Sanity check and bounds enforcement.  Out of bounds requests are
	 * clipped to the screen boundaries.  This seems to be what SPARC
	 * does.
	 */
	if (row < 0)
		row = 0;
	if (row >= tem->a_c_dimension.height)
		row = tem->a_c_dimension.height - 1;
	if (col < 0)
		col = 0;
	if (col >= tem->a_c_dimension.width)
		col = tem->a_c_dimension.width - 1;

	tem_send_data(tem, credp, called_from);
	tem->a_c_cursor.row = row;
	tem->a_c_cursor.col = col;
	tem_align_cursor(tem);
}


static void
tem_reset_emulator(struct terminal_emulator *tem)
{
	int j;

	tem->a_c_cursor.row = 0;
	tem->a_c_cursor.col = 0;
	tem->a_r_cursor.row = 0;
	tem->a_r_cursor.col = 0;
	tem->a_s_cursor.row = 0;
	tem->a_s_cursor.col = 0;
	tem->a_outindex = 0;
	tem->a_state = A_STATE_START;
	tem->a_gotparam = B_FALSE;
	tem->a_curparam = 0;
	tem->a_paramval = 0;
	tem->a_flags = 0;
	tem->a_nscroll = 1;
	tem->fg_color = default_ansi_fg;
	tem->bg_color = default_ansi_bg;

	/*
	 * set up the initial tab stops
	 */
	tem->a_ntabs = 0;
	for (j = 8; j < tem->a_c_dimension.width; j += 8)
		tem->a_tabs[tem->a_ntabs++] = (screen_pos_t)j;

	for (j = 0; j < TEM_MAXPARAMS; j++)
		tem->a_params[j] = 0;
}

static void
tem_reset_display(struct terminal_emulator *tem,
    cred_t *credp, enum called_from called_from, int clear_txt)
{
	tem_reset_emulator(tem);
	tem_reset_colormap(tem, credp, called_from);

	(*tem->in_fp.f_cursor)(tem, VIS_HIDE_CURSOR, credp, called_from);

	if (tem->display_mode == VIS_PIXEL) {
		tem_clear_entire(tem, credp, called_from);
	} else if (clear_txt) {
		tem_cls(tem, credp, called_from);
	} else {
		/* ask driver where cursor is */
		tem_text_cursor(tem, VIS_GET_CURSOR, credp, CALLED_FROM_NORMAL);
		tem_align_cursor(tem);
	}

	tem->a_initialized = 1;
	(*tem->in_fp.f_cursor)(tem, VIS_DISPLAY_CURSOR, credp, called_from);
}


static void
tem_shift(
	struct terminal_emulator *tem,
	int count,
	int direction,
	cred_t *credp,
	enum called_from called_from)
{
	int rest_of_line;

	rest_of_line = tem->a_c_dimension.width - tem->a_c_cursor.col;
	if (count > rest_of_line)
		count = rest_of_line;

	if (count <= 0)
		return;

	switch (direction) {
	case TEM_SHIFT_LEFT:
		if (count < rest_of_line) {
			tem_copy_area(tem,
				tem->a_c_cursor.col + count,
				tem->a_c_cursor.row,
				tem->a_c_dimension.width - 1,
				tem->a_c_cursor.row,
				tem->a_c_cursor.col,
				tem->a_c_cursor.row,
				credp, called_from);
		}

		tem_clear_chars(tem,
			count,
			tem->a_c_cursor.row,
			(tem->a_c_dimension.width - count), credp,
			    called_from);
		break;
	case TEM_SHIFT_RIGHT:
		if (count < rest_of_line) {
			tem_copy_area(tem,
				tem->a_c_cursor.col,
				tem->a_c_cursor.row,
				tem->a_c_dimension.width - count - 1,
				tem->a_c_cursor.row,
				tem->a_c_cursor.col + count,
				tem->a_c_cursor.row,
				credp, called_from);
		}

		tem_clear_chars(tem,
			count,
			tem->a_c_cursor.row,
			tem->a_c_cursor.col, credp, called_from);
		break;
	}
}

static void
tem_text_cursor(struct terminal_emulator *tem, short action,
    cred_t *credp, enum called_from called_from)
{
	struct vis_conscursor	ca;

	ca.version = VIS_CURSOR_VERSION;
	ca.row = tem->a_c_cursor.row;
	ca.col = tem->a_c_cursor.col;
	ca.action = action;

	tem_cursor(tem, &ca, credp, called_from);

	if (action == VIS_GET_CURSOR) {
		tem->a_c_cursor.row = ca.row;
		tem->a_c_cursor.col = ca.col;
	}
}


static void
tem_pix_cursor(struct terminal_emulator *tem, short action,
    cred_t *credp, enum called_from called_from)
{
	struct vis_conscursor	ca;

	ca.version = VIS_CURSOR_VERSION;
	ca.row = tem->a_c_cursor.row * tem->a_font.height +
				tem->a_p_offset.y;
	ca.col = tem->a_c_cursor.col * tem->a_font.width +
				tem->a_p_offset.x;
	ca.width = tem->a_font.width;
	ca.height = tem->a_font.height;
	if (tem->a_pdepth == 8 || tem->a_pdepth == 4 || tem->a_pdepth == 1) {
		if (tem->a_flags & TEM_ATTR_REVERSE) {
			ca.fg_color.mono = TEM_TEXT_WHITE;
			ca.bg_color.mono = TEM_TEXT_BLACK;
		} else {
			ca.fg_color.mono = TEM_TEXT_BLACK;
			ca.bg_color.mono = TEM_TEXT_WHITE;
		}
	} else if (tem->a_pdepth == 24) {
		if (tem->a_flags & TEM_ATTR_REVERSE) {
			ca.fg_color.twentyfour[0] = TEM_TEXT_WHITE24_RED;
			ca.fg_color.twentyfour[1] = TEM_TEXT_WHITE24_GREEN;
			ca.fg_color.twentyfour[2] = TEM_TEXT_WHITE24_BLUE;

			ca.bg_color.twentyfour[0] = TEM_TEXT_BLACK24_RED;
			ca.bg_color.twentyfour[1] = TEM_TEXT_BLACK24_GREEN;
			ca.bg_color.twentyfour[2] = TEM_TEXT_BLACK24_BLUE;
		} else {
			ca.fg_color.twentyfour[0] = TEM_TEXT_BLACK24_RED;
			ca.fg_color.twentyfour[1] = TEM_TEXT_BLACK24_GREEN;
			ca.fg_color.twentyfour[2] = TEM_TEXT_BLACK24_BLUE;

			ca.bg_color.twentyfour[0] = TEM_TEXT_WHITE24_RED;
			ca.bg_color.twentyfour[1] = TEM_TEXT_WHITE24_GREEN;
			ca.bg_color.twentyfour[2] = TEM_TEXT_WHITE24_BLUE;
		}
	}

	ca.action = action;

	tem_cursor(tem, &ca, credp, called_from);
}

static void
set_font(struct font *f, short *rows, short *cols, short height, short width)
{
	bitmap_data_t	*fontToUse = NULL;
	struct fontlist	*fl;

	/*
	 * Find best font for these dimensions, or use default
	 *
	 * The plus 2 is to make sure we have at least a 1 pixel
	 * boarder around the entire screen.
	 */
	for (fl = fonts; fl->name; fl++) {
		if (fl->data &&
		    (((*rows * fl->data->height) + 2) <= height) &&
		    (((*cols * fl->data->width) + 2) <= width)) {
			fontToUse = fl->data;
			break;
		}
	}

	/*
	 * The minus 2 is to make sure we have at least a 1 pixel
	 * boarder around the entire screen.
	 */
	if (fontToUse == NULL) {
		if (((*rows * builtin_font_data.height) > height) ||
		    ((*cols * builtin_font_data.width) > width)) {
			*rows = (height - 2) / builtin_font_data.height;
			*cols = (width - 2) / builtin_font_data.width;
		}
		fontToUse = &builtin_font_data;
	}

	f->width = fontToUse->width;
	f->height = fontToUse->height;
	bcopy((caddr_t)fontToUse->encoding, (caddr_t)f->char_ptr,
			sizeof (f->char_ptr));
	f->image_data = fontToUse->image;
	f->image_data_size = fontToUse->image_size;

	/* Free extra data structures and bitmaps	*/

	for (fl = fonts; fl->name; fl++) {
		if (fl->data) {
			if (fontToUse != fl->data && fl->data->image_size)
			    kmem_free(fl->data->image, fl->data->image_size);
			kmem_free(fl->data->encoding, fl->data->encoding_size);
			kmem_free(fl->data, sizeof (*fl->data));
		}
	}
}

#if defined(HAVE_1BIT)
/*
 * bit_to_pix1 is for 1-bit frame buffers.  It will essentially pass-through
 * the bitmap, possibly inverting it for reverse video.
 *
 * An input data byte of 0x53 will output the bit pattern 01010011.
 *
 * NEEDSWORK:  Does this properly handle fonts that are not a multiple
 *             of 8 pixels wide?
 */

static void
bit_to_pix1(
    struct terminal_emulator *tem,
    unsigned char c,
    text_color_t fg_color,
    text_color_t bg_color)
{
	int	row;
	int	i;
	uint8_t	*cp;
	int	bytesWide;
	uint8_t	data;
	uint8_t *dest;
	unsigned short	flags;

	dest = (uint8_t *)tem->a_pix_data;
	cp = tem->a_font.char_ptr[c];
	bytesWide = (tem->a_font.width + 7) / 8;
	flags = tem->a_flags;

	for (row = 0; row < tem->a_font.height; row++) {
		for (i = 0; i < bytesWide; i++) {
			data = *cp++;
			if (flags & TEM_ATTR_REVERSE) {
				*dest++ = INVERSE(data);
			} else {
				*dest++ = data;
			}
		}
	}
}
#endif	/* HAVE_1BIT */

/*
 * bit_to_pix4 is for 4-bit frame buffers.  It will write one output byte
 * for each 2 bits of input bitmap.  It inverts the input bits before
 * doing the output translation, for reverse video.
 *
 * Assuming foreground is 0001 and background is 0000...
 * An input data byte of 0x53 will output the bit pattern
 * 00000001 00000001 00000000 00010001.
 */

static void
bit_to_pix4(
    struct terminal_emulator *tem,
    unsigned char c,
    text_color_t fg_color,
    text_color_t bg_color)
{
	int	row;
	int	byte;
	int	i;
	uint8_t	*cp;
	uint8_t	data;
	uint8_t	nibblett;
	int	bytesWide;
	uint8_t *dest;

	dest = (uint8_t *)tem->a_pix_data;

	cp = tem->a_font.char_ptr[c];
	bytesWide = (tem->a_font.width + 7) / 8;

	for (row = 0; row < tem->a_font.height; row++) {
		for (byte = 0; byte < bytesWide; byte++) {
			data = *cp++;
			for (i = 0; i < 4; i++) {
				nibblett = (data >> ((3-i) * 2)) & 0x3;
				switch (nibblett) {
				case 0x0:
					*dest++ = bg_color << 4 | bg_color;
					break;
				case 0x1:
					*dest++ = bg_color << 4 | fg_color;
					break;
				case 0x2:
					*dest++ = fg_color << 4 | bg_color;
					break;
				case 0x3:
					*dest++ = fg_color << 4 | fg_color;
					break;
				}
			}
		}
	}
}

/*
 * bit_to_pix8 is for 8-bit frame buffers.  It will write one output byte
 * for each bit of input bitmap.  It inverts the input bits before
 * doing the output translation, for reverse video.
 *
 * Assuming foreground is 00000001 and background is 00000000...
 * An input data byte of 0x53 will output the bit pattern
 * 0000000 000000001 00000000 00000001 00000000 00000000 00000001 00000001.
 */


static void
bit_to_pix8(
    struct terminal_emulator *tem,
    unsigned char c,
    text_color_t fg_color,
    text_color_t bg_color)
{
	int	row;
	int	byte;
	int	i;
	uint8_t	*cp;
	uint8_t	data;
	int	bytesWide;
	uint8_t	mask;
	int	bitsleft, nbits;
	uint8_t *dest;

	dest = (uint8_t *)tem->a_pix_data;

	cp = tem->a_font.char_ptr[c];
	bytesWide = (tem->a_font.width + 7) / 8;

	for (row = 0; row < tem->a_font.height; row++) {
		bitsleft = tem->a_font.width;
		for (byte = 0; byte < bytesWide; byte++) {
			data = *cp++;
			mask = 0x80;
			nbits = min(8, bitsleft);
			bitsleft -= nbits;
			for (i = 0; i < nbits; i++) {
				*dest++ = (data & mask ? fg_color: bg_color);
				mask = mask >> 1;
			}
		}
	}
}

/*
 * bit_to_pix24 is for 24-bit frame buffers.  It will write four output bytes
 * for each bit of input bitmap.  It inverts the input bits before
 * doing the output translation, for reverse video.
 *
 * Assuming foreground is 00000000 11111111 11111111 11111111
 * and background is 00000000 00000000 00000000 00000000
 * An input data byte of 0x53 will output the bit pattern
 *
 * 00000000 00000000 00000000 00000000
 * 00000000 11111111 11111111 11111111
 * 00000000 00000000 00000000 00000000
 * 00000000 11111111 11111111 11111111
 * 00000000 00000000 00000000 00000000
 * 00000000 00000000 00000000 00000000
 * 00000000 11111111 11111111 11111111
 * 00000000 11111111 11111111 11111111
 *
 * FYI this is a pad byte followed by 1 byte each for R,G, and B.
 */

/*
 * A 24-bit pixel trapped in a 32-bit body.
 */
typedef uint32_t pixel32;

/*
 * Union for working with 24-bit pixels in 0RGB form, where the
 * bytes in memory are 0 (a pad byte), red, green, and blue in that order.
 */
union pixel32_0RGB {
	struct {
		char pad;
		char red;
		char green;
		char blue;
	} bytes;
	pixel32	pix;
};

struct {
	unsigned char red[16];
	unsigned char green[16];
	unsigned char blue[16];
} solaris_to_24 = {
	/* BEGIN CSTYLED */
	/* Wh+  Bk  Bl  Gr  Cy  Rd  Mg  Br Wh  Bk+ Bl+ Gr+ Cy+ Rd+ Mg+ Yw */
	   255,000,000,000,000,128,128,128,128, 64,000,000,000,255,255,255,
	   255,000,000,128,128,000,000,128,128, 64,000,255,255,000,000,255,
	   255,000,128,000,128,000,128,000,128, 64,255,000,255,000,255,000,
	/* END CSTYLED */
};

static void
bit_to_pix24(
    struct terminal_emulator *tem,
    unsigned char c,
    text_color_t fg_color_4,
    text_color_t bg_color_4)
{
	int	row;
	int	byte;
	int	i;
	uint8_t	*cp;
	uint8_t	data;
	int	bytesWide;
	union pixel32_0RGB	fg_color;
	union pixel32_0RGB	bg_color;
	int	bitsleft, nbits;
	pixel32	*destp;

	fg_color.bytes.pad = 0;
	bg_color.bytes.pad = 0;

	fg_color.bytes.red = solaris_to_24.red[fg_color_4];
	fg_color.bytes.green = solaris_to_24.green[fg_color_4];
	fg_color.bytes.blue = solaris_to_24.blue[fg_color_4];
	bg_color.bytes.red = solaris_to_24.red[bg_color_4];
	bg_color.bytes.green = solaris_to_24.green[bg_color_4];
	bg_color.bytes.blue = solaris_to_24.blue[bg_color_4];

	destp = (pixel32 *)tem->a_pix_data;
	cp = tem->a_font.char_ptr[c];
	bytesWide = (tem->a_font.width + 7) / 8;

	for (row = 0; row < tem->a_font.height; row++) {
		bitsleft = tem->a_font.width;
		for (byte = 0; byte < bytesWide; byte++) {
			data = *cp++;
			nbits = min(8, bitsleft);
			bitsleft -= nbits;
			for (i = 0; i < nbits; i++) {
				*destp++ = (data & 0x80 ?
						fg_color.pix : bg_color.pix);
				data <<= 1;
			}
		}
	}
}

typedef enum solaris_colors {
	solaris_brt_white	= 0,
	solaris_black		= 1,
	solaris_blue		= 2,
	solaris_green		= 3,
	solaris_cyan		= 4,
	solaris_red		= 5,
	solaris_magenta		= 6,
	solaris_brown		= 7,
	solaris_white		= 8,
	solaris_grey		= 9,
	solaris_brt_blue	= 10,
	solaris_brt_green	= 11,
	solaris_brt_cyan	= 12,
	solaris_brt_red		= 13,
	solaris_brt_magenta	= 14,
	solaris_yellow		= 15
} solaris_colors_t;

static const text_color_t ansi_bg_to_solaris_colors[8] = {
	solaris_black,		/* 0 - black	*/
	solaris_red,		/* 1 - red	*/
	solaris_green,		/* 2 - green	*/
	solaris_brown,		/* 3 - brown	*/
	solaris_blue,		/* 4 - blue	*/
	solaris_magenta,	/* 5 - magenta	*/
	solaris_cyan,		/* 6 - cyan	*/
	solaris_white		/* 7 - white	*/
};

static const text_color_t ansi_fg_to_solaris_colors[8] = {
	solaris_black,		/* 0 - black	*/
	solaris_red,		/* 1 - red	*/
	solaris_green,		/* 2 - green	*/
	solaris_brown,		/* 3 - brown	*/
	solaris_blue,		/* 4 - blue	*/
	solaris_magenta,	/* 5 - magenta	*/
	solaris_cyan,		/* 6 - cyan	*/
	solaris_white		/* 7 - white	*/
};

static const text_color_t ansi_fg_bold_to_solaris_colors[8] = {
	solaris_grey,		/* 0 - black	*/
	solaris_brt_red,	/* 1 - red	*/
	solaris_brt_green,	/* 2 - green	*/
	solaris_yellow,		/* 3 - brown	*/
	solaris_brt_blue,	/* 4 - blue	*/
	solaris_brt_magenta,	/* 5 - magenta	*/
	solaris_brt_cyan,	/* 6 - cyan	*/
	solaris_brt_white	/* 7 - white	*/
};

/* ARGSUSED */
static text_color_t
ansi_bg_to_solaris(struct terminal_emulator *tem, int ansi)
{
	ASSERT(ansi < NELEM(ansi_bg_to_solaris_colors));
	return (ansi_bg_to_solaris_colors[ansi]);
}

static text_color_t
ansi_fg_to_solaris(struct terminal_emulator *tem, int ansi)
{
	if (tem->a_flags & TEM_ATTR_BOLD) {
		ASSERT(ansi < NELEM(ansi_fg_bold_to_solaris_colors));
		return (ansi_fg_bold_to_solaris_colors[ansi]);
	} else {
		ASSERT(ansi < NELEM(ansi_fg_to_solaris_colors));
		return (ansi_fg_to_solaris_colors[ansi]);
	}
}

static void
tem_display(
    struct terminal_emulator *tem,
    struct vis_consdisplay *pda,
    cred_t *credp,
    enum called_from called_from)
{
	int rval;

	if (called_from == CALLED_FROM_STANDALONE)
		tem->fb_polledio->display(tem->fb_polledio->arg, pda);
	else
		(void) ldi_ioctl(tem->hdl, VIS_CONSDISPLAY,
		    (intptr_t)pda, FKIOCTL, credp, &rval);
}

static void
tem_copy(
    struct terminal_emulator *tem,
    struct vis_conscopy *pma,
    cred_t *credp,
    enum called_from called_from)
{
	int rval;

	if (called_from == CALLED_FROM_STANDALONE)
		tem->fb_polledio->copy(tem->fb_polledio->arg, pma);
	else
		(void) ldi_ioctl(tem->hdl, VIS_CONSCOPY,
		    (intptr_t)pma, FKIOCTL, credp, &rval);
}

static void
tem_cursor(
    struct terminal_emulator *tem,
    struct vis_conscursor *pca,
    cred_t *credp,
    enum called_from called_from)
{
	int rval;

	if (called_from == CALLED_FROM_STANDALONE)
		tem->fb_polledio->cursor(tem->fb_polledio->arg, pca);
	else
		(void) ldi_ioctl(tem->hdl, VIS_CONSCURSOR,
		    (intptr_t)pca, FKIOCTL, credp, &rval);
}

void
tem_get_size(struct terminal_emulator *tem, int *r, int *c, int *x, int *y)
{
	*r = tem->a_c_dimension.height;
	*c = tem->a_c_dimension.width;
	*x = tem->a_p_dimension.width;
	*y = tem->a_p_dimension.height;
}
