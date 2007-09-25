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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Polled I/O safe ANSI terminal emulator module;
 * Supporting TERM types 'sun' and 'sun-color, parsing
 * ANSI x3.64 escape sequences, and the like.  (See wscons(7d)
 * for more information).
 *
 * IMPORTANT:
 *
 *   The functions in this file *must* be able to function in
 *   standalone mode, ie. on a quiesced system.   In that state,
 *   access is single threaded, only one CPU is running.
 *   System services are NOT available.
 *
 * The following restrictions pertain to every function
 * in this file:
 *
 *     - CANNOT use the DDI or LDI interfaces
 *     - CANNOT call system services
 *     - CANNOT use mutexes
 *     - CANNOT wait for interrupts
 *     - CANNOT allocate memory
 *
 */

#include <sys/types.h>
#include <sys/ascii.h>
#include <sys/visual_io.h>
#include <sys/font.h>
#include <sys/tem.h>
#include <sys/tem_impl.h>
#include <sys/ksynch.h>
#include <sys/sysmacros.h>
#include <sys/mutex.h>

static void	tem_display(struct tem *,
			struct vis_consdisplay *,
			cred_t *, enum called_from);
static void	tem_cursor(struct tem *,
			struct vis_conscursor *,
			cred_t *, enum called_from);
static void	tem_control(struct tem *, uchar_t,
			cred_t *, enum called_from);
static void	tem_setparam(struct tem *, int, int);
static void	tem_selgraph(struct tem *);
static void	tem_chkparam(struct tem *, uchar_t,
			cred_t *, enum called_from);
static void	tem_getparams(struct tem *, uchar_t,
			cred_t *, enum called_from);
static void	tem_outch(struct tem *, uchar_t,
			cred_t *, enum called_from);
static void	tem_parse(struct tem *, uchar_t,
			cred_t *, enum called_from);

static void	tem_new_line(struct tem *,
			cred_t *, enum called_from);
static void	tem_cr(struct tem *);
static void	tem_lf(struct tem *,
			cred_t *, enum called_from);
static void	tem_send_data(struct tem *, cred_t *,
			enum called_from);
static void	tem_cls(struct tem *,
			cred_t *, enum called_from);
static void	tem_tab(struct tem *,
			cred_t *, enum called_from);
static void	tem_back_tab(struct tem *,
			cred_t *, enum called_from);
static void	tem_clear_tabs(struct tem *, int);
static void	tem_set_tab(struct tem *);
static void	tem_mv_cursor(struct tem *, int, int,
			cred_t *, enum called_from);
static void	tem_shift(struct tem *, int, int,
			cred_t *, enum called_from);
static void	tem_scroll(struct tem *, int, int,
			int, int, cred_t *, enum called_from);
static void	tem_clear_chars(struct tem *tem,
			int count, screen_pos_t row, screen_pos_t col,
			cred_t *credp, enum called_from called_from);
static void	tem_copy_area(struct tem *tem,
			screen_pos_t s_col, screen_pos_t s_row,
			screen_pos_t e_col, screen_pos_t e_row,
			screen_pos_t t_col, screen_pos_t t_row,
			cred_t *credp, enum called_from called_from);
static void	tem_image_display(struct tem *, uchar_t *,
			int, int, screen_pos_t, screen_pos_t,
			cred_t *, enum called_from);
static void	tem_bell(struct tem *tem,
			enum called_from called_from);
static void	tem_get_color(struct tem *tem,
			text_color_t *fg, text_color_t *bg);
static void	tem_pix_clear_prom_output(struct tem *tem,
			cred_t *credp, enum called_from called_from);

/* BEGIN CSTYLED */
/*                                      Bk  Rd  Gr  Br  Bl  Mg  Cy  Wh */
static text_color_t fg_dim_xlate[] = {  1,  5,  3,  7,  2,  6,  4,  8 };
static text_color_t fg_brt_xlate[] = {  9, 13, 11, 15, 10, 14, 12,  0 };
static text_color_t bg_xlate[] = {      1,  5,  3,  7,  2,  6,  4,  0 };
/* END CSTYLED */


text_cmap_t cmap4_to_24 = {
/* BEGIN CSTYLED */
/* 0    1    2    3    4    5    6    7    8    9   10   11   12   13   14   15
  Wh+  Bk   Bl   Gr   Cy   Rd   Mg   Br   Wh   Bk+  Bl+  Gr+  Cy+  Rd+  Mg+  Yw */
  0xff,0x00,0x00,0x00,0x00,0x80,0x80,0x80,0x80,0x40,0x00,0x00,0x00,0xff,0xff,0xff,
  0xff,0x00,0x00,0x80,0x80,0x00,0x00,0x80,0x80,0x40,0x00,0xff,0xff,0x00,0x00,0xff,
  0xff,0x00,0x80,0x00,0x80,0x00,0x80,0x00,0x80,0x40,0xff,0x00,0xff,0x00,0xff,0x00
/* END CSTYLED */
};

#define	PIX4TO32(pix4) (pixel32_t)(  \
    cmap4_to_24.red[pix4] << 16 |  \
    cmap4_to_24.green[pix4] << 8 | \
    cmap4_to_24.blue[pix4])

/*
 * Fonts are statically linked with this module. At some point an
 * RFE might be desireable to allow dynamic font loading.  The
 * original intention to facilitate dynamic fonts can be seen
 * by examining the data structures and set_font().  As much of
 * the original code is retained but modified to be suited to
 * traversing a list of static fonts.
 */
extern struct fontlist fonts[];

#define	DEFAULT_FONT_DATA font_data_12x22

extern bitmap_data_t font_data_12x22;
extern bitmap_data_t font_data_7x14;
extern bitmap_data_t font_data_6x10;
/*
 * Must be sorted by font size in descending order
 */
struct fontlist fonts[] = {
	{  &font_data_12x22,	NULL  },
	{  &font_data_7x14,	NULL  },
	{  &font_data_6x10,	NULL  },
	{  NULL, NULL  }
};

#define	INVERSE(ch) (ch ^ 0xff)

#define	BIT_TO_PIX(tem, c, fg, bg)	{				\
	ASSERT((tem)->state->in_fp.f_bit2pix != NULL); 			\
	(void) (*(tem)->state->in_fp.f_bit2pix)((tem), (c), (fg), (bg));\
}

void
tem_check_first_time(
    struct tem *tem,
    cred_t *credp,
    enum called_from called_from)
{
	static int first_time = 1;

	/*
	 * Realign the console cursor. We did this in tem_init().
	 * However, drivers in the console stream may emit additional
	 * messages before we are ready. This causes text overwrite
	 * on the screen. This is a workaround.
	 */
	if (first_time && tem->state->display_mode == VIS_TEXT) {
		tem_text_cursor(tem, VIS_GET_CURSOR, credp, called_from);
		tem_align_cursor(tem);
	}
	first_time = 0;

}

/*
 * This entry point handles output requests from restricted contexts like
 * kmdb, where services like mutexes are not available. This function
 * is entered when OBP or when a kernel debugger (such as kmdb)
 * are generating console output.  In those cases, power management
 * concerns are handled by the abort sequence initiation (ie. when
 * the user hits L1+A or the equivalent to enter OBP or the debugger.).
 * It is also entered when the kernel is panicing.
 */
void
tem_polled_write(
    struct tem *tem,
    uchar_t *buf,
    int len)
{

	ASSERT(tem->hdl != NULL);

	tem_check_first_time(tem, kcred, CALLED_FROM_STANDALONE);
	tem_terminal_emulate(tem, buf, len, NULL, CALLED_FROM_STANDALONE);
}


/*
 * This is the main entry point into the terminal emulator.
 *
 * For each data message coming downstream, ANSI assumes that it is composed
 * of ASCII characters, which are treated as a byte-stream input to the
 * parsing state machine. All data is parsed immediately -- there is
 * no enqueing.
 */
void
tem_terminal_emulate(
    struct tem *tem,
    uchar_t *buf,
    int len,
    cred_t *credp,
    enum called_from called_from)
{
	struct tem_state	*tems = tem->state;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	(*tems->in_fp.f_cursor)
	    (tem, VIS_HIDE_CURSOR, credp, called_from);

	for (; len > 0; len--, buf++) {
		tem_parse(tem, *buf, credp, called_from);
	}

	/*
	 * Send the data we just got to the framebuffer.
	 */
	tem_send_data(tem, credp, called_from);

	(*tems->in_fp.f_cursor)
	    (tem, VIS_DISPLAY_CURSOR, credp, called_from);
}

/*
 * Display an rectangular image on the frame buffer using the
 * mechanism appropriate for the system state being called
 * from quiesced or normal (ie. use polled I/O vs. layered ioctls)
 */
static void
tem_display(
	struct tem *tem,
	struct vis_consdisplay *pda,
	cred_t *credp,
	enum called_from called_from)
{
	if (called_from == CALLED_FROM_STANDALONE)
		tem->fb_polledio->display(tem->fb_polledio->arg, pda);
	else
		tem_display_layered(tem, pda, credp);
}

/*
 * Copy a rectangle from one location to another on the frame buffer
 * using the mechanism appropriate for the system state being called
 * from, quiesced or normal (ie. use polled I/O vs. layered ioctls)
 */
void
tem_copy(
	struct tem *tem,
	struct vis_conscopy *pca,
	cred_t *credp,
	enum called_from called_from)
{
	if (called_from == CALLED_FROM_STANDALONE)
		tem->fb_polledio->copy(tem->fb_polledio->arg, pca);
	else
		tem_copy_layered(tem, pca, credp);
}

/*
 * Display or hide a rectangular block text cursor of a specificsize
 * at a specific location on frame buffer* using the mechanism
 * appropriate for the system state being called from, quisced or
 * normal (ie. use polled I/O vs. layered ioctls).
 */
static void
tem_cursor(
	struct tem *tem,
	struct vis_conscursor *pca,
	cred_t *credp,
	enum called_from called_from)
{
	if (called_from == CALLED_FROM_STANDALONE)
		tem->fb_polledio->cursor(tem->fb_polledio->arg, pca);
	else
		tem_cursor_layered(tem, pca, credp);
}

/*
 * send the appropriate control message or set state based on the
 * value of the control character ch
 */

static void
tem_control(
	struct tem *tem,
	uchar_t ch,
	cred_t *credp,
	enum called_from called_from)
{
	struct tem_state	*tems = tem->state;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	tems->a_state = A_STATE_START;
	switch (ch) {
	case A_BEL:
		tem_bell(tem, called_from);
		break;

	case A_BS:
		tem_mv_cursor(tem,
		    tems->a_c_cursor.row,
		    tems->a_c_cursor.col - 1,
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
		tems->a_state = A_STATE_ESC;
		break;

	case A_CSI:
		{
			int i;
			tems->a_curparam = 0;
			tems->a_paramval = 0;
			tems->a_gotparam = B_FALSE;
			/* clear the parameters */
			for (i = 0; i < TEM_MAXPARAMS; i++)
				tems->a_params[i] = -1;
			tems->a_state = A_STATE_CSI;
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
 * if parameters [0..count - 1] are not set, set them to the value
 * of newparam.
 */

static void
tem_setparam(struct tem *tem, int count, int newparam)
{
	int i;

	for (i = 0; i < count; i++) {
		if (tem->state->a_params[i] == -1)
			tem->state->a_params[i] = newparam;
	}
}


/*
 * select graphics mode based on the param vals stored in a_params
 */
static void
tem_selgraph(struct tem *tem)
{
	struct tem_state *tems = tem->state;
	int curparam;
	int count = 0;
	int param;

	curparam = tems->a_curparam;
	do {
		param = tems->a_params[count];

		switch (param) {
		case -1:
		case 0:
			if (tems->a_flags & TEM_ATTR_SCREEN_REVERSE) {
				tems->a_flags |= TEM_ATTR_REVERSE;
			} else {
				tems->a_flags &= ~TEM_ATTR_REVERSE;
			}
			tems->a_flags = tem->init_color.a_flags;
			tems->fg_color = tem->init_color.fg_color;
			tems->bg_color = tem->init_color.bg_color;
			break;

		case 1: /* Bold Intense */
			tems->a_flags |= TEM_ATTR_BOLD;
			break;

		case 2: /* Faint Intense */
			tems->a_flags &= ~TEM_ATTR_BOLD;
			break;

		case 5: /* Blink */
			tems->a_flags |= TEM_ATTR_BLINK;
			break;

		case 7: /* Reverse video */
			if (tems->a_flags & TEM_ATTR_SCREEN_REVERSE) {
				tems->a_flags &= ~TEM_ATTR_REVERSE;
			} else {
				tems->a_flags |= TEM_ATTR_REVERSE;
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
			tems->fg_color = param - 30;
			break;

		case 40: /* black	(grey) 		background */
		case 41: /* red		(light red) 	background */
		case 42: /* green	(light green) 	background */
		case 43: /* brown	(yellow) 	background */
		case 44: /* blue	(light blue) 	background */
		case 45: /* magenta	(light magenta) background */
		case 46: /* cyan	(light cyan) 	background */
		case 47: /* white	(bright white) 	background */
			tems->bg_color = param - 40;
			break;

		default:
			break;
		}
		count++;
		curparam--;

	} while (curparam > 0);


	tems->a_state = A_STATE_START;
}

/*
 * perform the appropriate action for the escape sequence
 *
 * General rule:  This code does not validate the arguments passed.
 *                It assumes that the next lower level will do so.
 */
static void
tem_chkparam(
	struct tem *tem,
	uchar_t ch,
	cred_t *credp,
	enum called_from called_from)
{
	struct tem_state *tems = tem->state;
	int	i;
	int	row;
	int	col;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	row = tems->a_c_cursor.row;
	col = tems->a_c_cursor.col;

	switch (ch) {

	case 'm': /* select terminal graphics mode */
		tem_send_data(tem, credp, called_from);
		tem_selgraph(tem);
		break;

	case '@':		/* insert char */
		tem_setparam(tem, 1, 1);
		tem_shift(tem, tems->a_params[0], TEM_SHIFT_RIGHT,
		    credp, called_from);
		break;

	case 'A':		/* cursor up */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row - tems->a_params[0], col,
		    credp, called_from);
		break;

	case 'd':		/* VPA - vertical position absolute */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, tems->a_params[0] - 1, col,
		    credp, called_from);
		break;

	case 'e':		/* VPR - vertical position relative */
	case 'B':		/* cursor down */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row + tems->a_params[0], col,
		    credp, called_from);
		break;

	case 'a':		/* HPR - horizontal position relative */
	case 'C':		/* cursor right */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row, col + tems->a_params[0],
		    credp, called_from);
		break;

	case '`':		/* HPA - horizontal position absolute */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row, tems->a_params[0] - 1,
		    credp, called_from);
		break;

	case 'D':		/* cursor left */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row, col - tems->a_params[0],
		    credp, called_from);
		break;

	case 'E':		/* CNL cursor next line */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row + tems->a_params[0], 0,
		    credp, called_from);
		break;

	case 'F':		/* CPL cursor previous line */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row - tems->a_params[0], 0,
		    credp, called_from);
		break;

	case 'G':		/* cursor horizontal position */
		tem_setparam(tem, 1, 1);
		tem_mv_cursor(tem, row, tems->a_params[0] - 1,
		    credp, called_from);
		break;

	case 'g':		/* clear tabs */
		tem_setparam(tem, 1, 0);
		tem_clear_tabs(tem, tems->a_params[0]);
		break;

	case 'f':		/* HVP Horizontal and Vertical Position */
	case 'H':		/* CUP position cursor */
		tem_setparam(tem, 2, 1);
		tem_mv_cursor(tem,
		    tems->a_params[0] - 1,
		    tems->a_params[1] - 1,
		    credp, called_from);
		break;

	case 'I':		/* CHT - Cursor Horizontal Tab */
		/* Not implemented */
		break;

	case 'J':		/* ED - Erase in Display */
		tem_send_data(tem, credp, called_from);
		tem_setparam(tem, 1, 0);
		switch (tems->a_params[0]) {
		case 0:
			/* erase cursor to end of screen */
			/* FIRST erase cursor to end of line */
			tem_clear_chars(tem,
			    tems->a_c_dimension.width -
			    tems->a_c_cursor.col,
			    tems->a_c_cursor.row,
			    tems->a_c_cursor.col, credp, called_from);

			/* THEN erase lines below the cursor */
			for (row = tems->a_c_cursor.row + 1;
			    row < tems->a_c_dimension.height;
			    row++) {
				tem_clear_chars(tem,
				    tems->a_c_dimension.width,
				    row, 0, credp, called_from);
			}
			break;

		case 1:
			/* erase beginning of screen to cursor */
			/* FIRST erase lines above the cursor */
			for (row = 0;
			    row < tems->a_c_cursor.row;
			    row++) {
				tem_clear_chars(tem,
				    tems->a_c_dimension.width,
				    row, 0, credp, called_from);
			}
			/* THEN erase beginning of line to cursor */
			tem_clear_chars(tem,
			    tems->a_c_cursor.col + 1,
			    tems->a_c_cursor.row,
			    0, credp, called_from);
			break;

		case 2:
			/* erase whole screen */
			for (row = 0;
			    row < tems->a_c_dimension.height;
			    row++) {
				tem_clear_chars(tem,
				    tems->a_c_dimension.width,
				    row, 0, credp, called_from);
			}
			break;
		}
		break;

	case 'K':		/* EL - Erase in Line */
		tem_send_data(tem, credp, called_from);
		tem_setparam(tem, 1, 0);
		switch (tems->a_params[0]) {
		case 0:
			/* erase cursor to end of line */
			tem_clear_chars(tem,
			    (tems->a_c_dimension.width -
			    tems->a_c_cursor.col),
			    tems->a_c_cursor.row,
			    tems->a_c_cursor.col,
			    credp, called_from);
			break;

		case 1:
			/* erase beginning of line to cursor */
			tem_clear_chars(tem,
			    tems->a_c_cursor.col + 1,
			    tems->a_c_cursor.row,
			    0, credp, called_from);
			break;

		case 2:
			/* erase whole line */
			tem_clear_chars(tem,
			    tems->a_c_dimension.width,
			    tems->a_c_cursor.row,
			    0, credp, called_from);
			break;
		}
		break;

	case 'L':		/* insert line */
		tem_send_data(tem, credp, called_from);
		tem_setparam(tem, 1, 1);
		tem_scroll(tem,
		    tems->a_c_cursor.row,
		    tems->a_c_dimension.height - 1,
		    tems->a_params[0], TEM_SCROLL_DOWN,
		    credp, called_from);
		break;

	case 'M':		/* delete line */
		tem_send_data(tem, credp, called_from);
		tem_setparam(tem, 1, 1);
		tem_scroll(tem,
		    tems->a_c_cursor.row,
		    tems->a_c_dimension.height - 1,
		    tems->a_params[0], TEM_SCROLL_UP,
		    credp, called_from);
		break;

	case 'P':		/* DCH - delete char */
		tem_setparam(tem, 1, 1);
		tem_shift(tem, tems->a_params[0], TEM_SHIFT_LEFT,
		    credp, called_from);
		break;

	case 'S':		/* scroll up */
		tem_send_data(tem, credp, called_from);
		tem_setparam(tem, 1, 1);
		tem_scroll(tem, 0,
		    tems->a_c_dimension.height - 1,
		    tems->a_params[0], TEM_SCROLL_UP,
		    credp, called_from);
		break;

	case 'T':		/* scroll down */
		tem_send_data(tem, credp, called_from);
		tem_setparam(tem, 1, 1);
		tem_scroll(tem, 0,
		    tems->a_c_dimension.height - 1,
		    tems->a_params[0], TEM_SCROLL_DOWN,
		    credp, called_from);
		break;

	case 'X':		/* erase char */
		tem_setparam(tem, 1, 1);
		tem_clear_chars(tem,
		    tems->a_params[0],
		    tems->a_c_cursor.row,
		    tems->a_c_cursor.col,
		    credp, called_from);
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
		if (tems->a_params[0] > tems->a_c_dimension.width)
			tems->a_params[0] = tems->a_c_dimension.width;

		for (i = 0; i < tems->a_params[0]; i++)
			tem_back_tab(tem, credp, called_from);
		break;
	}
	tems->a_state = A_STATE_START;
}


/*
 * Gather the parameters of an ANSI escape sequence
 */
static void
tem_getparams(struct tem *tem, uchar_t ch,
    cred_t *credp, enum called_from called_from)
{
	struct tem_state *tems = tem->state;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	if (ch >= '0' && ch <= '9') {
		tems->a_paramval = ((tems->a_paramval * 10) + (ch - '0'));
		tems->a_gotparam = B_TRUE;  /* Remember got parameter */
		return; /* Return immediately */
	} else if (tems->a_state == A_STATE_CSI_EQUAL ||
	    tems->a_state == A_STATE_CSI_QMARK) {
		tems->a_state = A_STATE_START;
	} else {
		if (tems->a_curparam < TEM_MAXPARAMS) {
			if (tems->a_gotparam) {
				/* get the parameter value */
				tems->a_params[tems->a_curparam] =
				    tems->a_paramval;
			}
			tems->a_curparam++;
		}

		if (ch == ';') {
			/* Restart parameter search */
			tems->a_gotparam = B_FALSE;
			tems->a_paramval = 0; /* No parame value yet */
		} else {
			/* Handle escape sequence */
			tem_chkparam(tem, ch, credp, called_from);
		}
	}
}

/*
 * Add character to internal buffer.
 * When its full, send it to the next layer.
 */

static void
tem_outch(struct tem *tem, uchar_t ch,
    cred_t *credp, enum called_from called_from)
{

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	/* buffer up the character until later */

	tem->state->a_outbuf[tem->state->a_outindex++] = ch;
	tem->state->a_c_cursor.col++;
	if (tem->state->a_c_cursor.col >= tem->state->a_c_dimension.width) {
		tem_send_data(tem, credp, called_from);
		tem_new_line(tem, credp, called_from);
	}
}

static void
tem_new_line(struct tem *tem,
    cred_t *credp, enum called_from called_from)
{
	tem_cr(tem);
	tem_lf(tem, credp, called_from);
}

static void
tem_cr(struct tem *tem)
{
	tem->state->a_c_cursor.col = 0;
	tem_align_cursor(tem);
}

static void
tem_lf(struct tem *tem,
    cred_t *credp, enum called_from called_from)
{
	struct tem_state *tems = tem->state;
	int row;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	/*
	 * Sanity checking notes:
	 * . a_nscroll was validated when it was set.
	 * . Regardless of that, tem_scroll and tem_mv_cursor will prevent
	 *   anything bad from happening.
	 */
	row = tems->a_c_cursor.row + 1;

	if (row >= tems->a_c_dimension.height) {
		if (tems->a_nscroll != 0) {
			tem_scroll(tem, 0,
			    tems->a_c_dimension.height - 1,
			    tems->a_nscroll, TEM_SCROLL_UP,
			    credp, called_from);
			row = tems->a_c_dimension.height -
			    tems->a_nscroll;
		} else {	/* no scroll */
			/*
			 * implement Esc[#r when # is zero.  This means no
			 * scroll but just return cursor to top of screen,
			 * do not clear screen.
			 */
			row = 0;
		}
	}

	tem_mv_cursor(tem, row, tems->a_c_cursor.col,
	    credp, called_from);

	if (tems->a_nscroll == 0) {
		/* erase rest of cursor line */
		tem_clear_chars(tem,
		    tems->a_c_dimension.width -
		    tems->a_c_cursor.col,
		    tems->a_c_cursor.row,
		    tems->a_c_cursor.col,
		    credp, called_from);

	}

	tem_align_cursor(tem);
}

static void
tem_send_data(struct tem *tem, cred_t *credp,
    enum called_from called_from)
{
	struct tem_state *tems = tem->state;
	text_color_t fg_color;
	text_color_t bg_color;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	if (tems->a_outindex != 0) {

		if (tems->a_flags & TEM_ATTR_REVERSE) {
			fg_color = ansi_fg_to_solaris(tem,
			    tems->bg_color);
			bg_color = ansi_bg_to_solaris(tem,
			    tems->fg_color);
		} else {
			fg_color = ansi_fg_to_solaris(tem,
			    tems->fg_color);
			bg_color = ansi_bg_to_solaris(tem,
			    tems->bg_color);
		}

		/*
		 * Call the primitive to render this data.
		 */
		(*tems->in_fp.f_display)(tem,
		    tems->a_outbuf,
		    tems->a_outindex,
		    tems->a_s_cursor.row,
		    tems->a_s_cursor.col,
		    fg_color, bg_color,
		    credp, called_from);
		tems->a_outindex = 0;
	}
	tem_align_cursor(tem);
}


/*
 * We have just done something to the current output point.  Reset the start
 * point for the buffered data in a_outbuf.  There shouldn't be any data
 * buffered yet.
 */
void
tem_align_cursor(struct tem *tem)
{
	tem->state->a_s_cursor.row = tem->state->a_c_cursor.row;
	tem->state->a_s_cursor.col = tem->state->a_c_cursor.col;
}



/*
 * State machine parser based on the current state and character input
 * major terminations are to control character or normal character
 */

static void
tem_parse(struct tem *tem, uchar_t ch,
    cred_t *credp, enum called_from called_from)
{
	struct tem_state *tems = tem->state;
	int	i;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	if (tems->a_state == A_STATE_START) {	/* Normal state? */
		if (ch == A_CSI || ch == A_ESC || ch < ' ') /* Control? */
			tem_control(tem, ch, credp, called_from);
		else
			/* Display */
			tem_outch(tem, ch, credp, called_from);
		return;
	}

	/* In <ESC> sequence */
	if (tems->a_state != A_STATE_ESC) {	/* Need to get parameters? */
		if (tems->a_state != A_STATE_CSI) {
			tem_getparams(tem, ch, credp, called_from);
			return;
		}

		switch (ch) {
		case '?':
			tems->a_state = A_STATE_CSI_QMARK;
			return;
		case '=':
			tems->a_state = A_STATE_CSI_EQUAL;
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
			 * tems->a_r_cursor.row = tems->a_c_cursor.row;
			 * tems->a_r_cursor.col = tems->a_c_cursor.col;
			 * tems->a_state = A_STATE_START;
			 */

			tems->a_state = A_STATE_START;
			return;
		case 'u':
			tem_mv_cursor(tem, tems->a_r_cursor.row,
			    tems->a_r_cursor.col, credp, called_from);
			tems->a_state = A_STATE_START;
			return;
		case 'p': 	/* sunbow */
			tem_send_data(tem, credp, called_from);
			/*
			 * Don't set anything if we are
			 * already as we want to be.
			 */
			if (tems->a_flags & TEM_ATTR_SCREEN_REVERSE) {
				tems->a_flags &= ~TEM_ATTR_SCREEN_REVERSE;
				/*
				 * If we have switched the characters to be the
				 * inverse from the screen, then switch them as
				 * well to keep them the inverse of the screen.
				 */
				if (tems->a_flags & TEM_ATTR_REVERSE) {
					tems->a_flags &= ~TEM_ATTR_REVERSE;
				} else {
					tems->a_flags |= TEM_ATTR_REVERSE;
				}
			}
			tem_cls(tem, credp, called_from);
			tems->a_state = A_STATE_START;
			return;
		case 'q':  	/* sunwob */
			tem_send_data(tem, credp, called_from);
			/*
			 * Don't set anything if we are
			 * already where as we want to be.
			 */
			if (!(tems->a_flags & TEM_ATTR_SCREEN_REVERSE)) {
				tems->a_flags |= TEM_ATTR_SCREEN_REVERSE;
				/*
				 * If we have switched the characters to be the
				 * inverse from the screen, then switch them as
				 * well to keep them the inverse of the screen.
				 */
				if (!(tems->a_flags & TEM_ATTR_REVERSE)) {
					tems->a_flags |= TEM_ATTR_REVERSE;
				} else {
					tems->a_flags &= ~TEM_ATTR_REVERSE;
				}
			}

			tem_cls(tem, credp, called_from);
			tems->a_state = A_STATE_START;
			return;
		case 'r':	/* sunscrl */
			/*
			 * Rule exception:  check for validity here.
			 */
			tems->a_nscroll = tems->a_paramval;
			if (tems->a_nscroll > tems->a_c_dimension.height)
				tems->a_nscroll = tems->a_c_dimension.height;
			if (tems->a_nscroll < 0)
				tems->a_nscroll = 1;
			tems->a_state = A_STATE_START;
			return;
		default:
			tem_getparams(tem, ch, credp, called_from);
			return;
		}
	}

	/* Previous char was <ESC> */
	if (ch == '[') {
		tems->a_curparam = 0;
		tems->a_paramval = 0;
		tems->a_gotparam = B_FALSE;
		/* clear the parameters */
		for (i = 0; i < TEM_MAXPARAMS; i++)
			tems->a_params[i] = -1;
		tems->a_state = A_STATE_CSI;
	} else if (ch == 'Q') {	/* <ESC>Q ? */
		tems->a_state = A_STATE_START;
	} else if (ch == 'C') {	/* <ESC>C ? */
		tems->a_state = A_STATE_START;
	} else {
		tems->a_state = A_STATE_START;
		if (ch == 'c')
			/* ESC c resets display */
			tem_reset_display(tem, credp, called_from, 1, NULL);
		else if (ch == 'H')
			/* ESC H sets a tab */
			tem_set_tab(tem);
		else if (ch == '7') {
			/* ESC 7 Save Cursor position */
			tems->a_r_cursor.row = tems->a_c_cursor.row;
			tems->a_r_cursor.col = tems->a_c_cursor.col;
		} else if (ch == '8')
			/* ESC 8 Restore Cursor position */
			tem_mv_cursor(tem, tems->a_r_cursor.row,
			    tems->a_r_cursor.col, credp, called_from);
		/* check for control chars */
		else if (ch < ' ')
			tem_control(tem, ch, credp, called_from);
		else
			tem_outch(tem, ch, credp, called_from);
	}
}

/* ARGSUSED */
static void
tem_bell(struct tem *tem, enum called_from called_from)
{
	if (called_from == CALLED_FROM_STANDALONE)
		(void) beep_polled(BEEP_CONSOLE);
	else
		(void) beep(BEEP_CONSOLE);
}


static void
tem_scroll(tem_t *tem, int start, int end, int count, int direction,
	cred_t *credp, enum called_from called_from)
{
	struct tem_state *tems = tem->state;
	int	row;
	int	lines_affected;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	lines_affected = end - start + 1;
	if (count > lines_affected)
		count = lines_affected;
	if (count <= 0)
		return;

	switch (direction) {
	case TEM_SCROLL_UP:
		if (count < lines_affected) {
			tem_copy_area(tem, 0, start + count,
			    tems->a_c_dimension.width - 1, end,
			    0, start, credp, called_from);
		}
		for (row = (end - count) + 1; row <= end; row++) {
			tem_clear_chars(tem, tems->a_c_dimension.width,
			    row, 0, credp, called_from);
		}
		break;

	case TEM_SCROLL_DOWN:
		if (count < lines_affected) {
			tem_copy_area(tem, 0, start,
			    tems->a_c_dimension.width - 1,
			    end - count, 0, start + count,
			    credp, called_from);
		}
		for (row = start; row < start + count; row++) {
			tem_clear_chars(tem, tems->a_c_dimension.width,
			    row, 0, credp, called_from);
		}
		break;
	}
}

static void
tem_copy_area(struct tem *tem,
	screen_pos_t s_col, screen_pos_t s_row,
	screen_pos_t e_col, screen_pos_t e_row,
	screen_pos_t t_col, screen_pos_t t_row,
	cred_t *credp, enum called_from called_from)
{
	struct tem_state *tems = tem->state;
	int rows;
	int cols;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	if (s_col < 0 || s_row < 0 ||
	    e_col < 0 || e_row < 0 ||
	    t_col < 0 || t_row < 0 ||
	    s_col >= tems->a_c_dimension.width ||
	    e_col >= tems->a_c_dimension.width ||
	    t_col >= tems->a_c_dimension.width ||
	    s_row >= tems->a_c_dimension.height ||
	    e_row >= tems->a_c_dimension.height ||
	    t_row >= tems->a_c_dimension.height)
		return;

	if (s_row > e_row || s_col > e_col)
		return;

	rows = e_row - s_row + 1;
	cols = e_col - s_col + 1;
	if (t_row + rows > tems->a_c_dimension.height ||
	    t_col + cols > tems->a_c_dimension.width)
		return;

	(*tems->in_fp.f_copy)(tem, s_col, s_row,
	    e_col, e_row, t_col, t_row, credp, called_from);
}

static void
tem_clear_chars(struct tem *tem, int count, screen_pos_t row,
	screen_pos_t col, cred_t *credp, enum called_from called_from)
{
	struct tem_state *tems = tem->state;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	if (row < 0 || row >= tems->a_c_dimension.height ||
	    col < 0 || col >= tems->a_c_dimension.width ||
	    count < 0)
		return;

	/*
	 * Note that very large values of "count" could cause col+count
	 * to overflow, so we check "count" independently.
	 */
	if (count > tems->a_c_dimension.width ||
	    col + count > tems->a_c_dimension.width)
		count = tems->a_c_dimension.width - col;

	(*tems->in_fp.f_cls)(tem, count, row, col, credp, called_from);
}

void
tem_text_display(struct tem *tem, uchar_t *string,
	int count, screen_pos_t row, screen_pos_t col,
	text_color_t fg_color, text_color_t bg_color,
	cred_t *credp, enum called_from called_from)
{
	struct vis_consdisplay da;

	da.data = string;
	da.width = count;
	da.row = row;
	da.col = col;

	da.fg_color = fg_color;
	da.bg_color = bg_color;

	tem_display(tem, &da, credp, called_from);
}

/*
 * This function is used to blit a rectangular color image,
 * unperturbed on the underlying framebuffer, to render
 * icons and pictures.  The data is a pixel pattern that
 * fills a rectangle bounded to the width and height parameters.
 * The color pixel data must to be pre-adjusted by the caller
 * for the current video depth.
 *
 * This function is unused now.
 */
void
tem_image_display(struct tem *tem, uchar_t *image,
	int height, int width, screen_pos_t row, screen_pos_t col,
	cred_t *credp, enum called_from called_from)
{
	struct vis_consdisplay da;

	da.data = image;
	da.width = width;
	da.height = height;
	da.row = row;
	da.col = col;

	tem_display(tem, &da, credp, called_from);
}


void
tem_text_copy(struct tem *tem,
	screen_pos_t s_col, screen_pos_t s_row,
	screen_pos_t e_col, screen_pos_t e_row,
	screen_pos_t t_col, screen_pos_t t_row,
	cred_t *credp, enum called_from called_from)
{
	struct vis_conscopy da;

	da.s_row = s_row;
	da.s_col = s_col;
	da.e_row = e_row;
	da.e_col = e_col;
	da.t_row = t_row;
	da.t_col = t_col;

	tem_copy(tem, &da, credp, called_from);
}

void
tem_text_cls(struct tem *tem,
	int count, screen_pos_t row, screen_pos_t col, cred_t *credp,
	enum called_from called_from)
{
	struct vis_consdisplay da;

	da.data = tem->state->a_blank_line;
	da.width = count;
	da.row = row;
	da.col = col;

	tem_get_color(tem, &da.fg_color, &da.bg_color);
	tem_display(tem, &da, credp, called_from);
}



void
tem_pix_display(struct tem *tem,
	uchar_t *string, int count,
	screen_pos_t row, screen_pos_t col,
	text_color_t fg_color, text_color_t bg_color,
	cred_t *credp, enum called_from called_from)
{
	struct tem_state *tems = tem->state;
	struct vis_consdisplay da;
	int	i;
	da.data = (uchar_t *)tems->a_pix_data;
	da.width = tems->a_font.width;
	da.height = tems->a_font.height;
	da.row = (row * da.height) + tems->a_p_offset.y;
	da.col = (col * da.width) + tems->a_p_offset.x;

	for (i = 0; i < count; i++) {
		BIT_TO_PIX(tem, string[i], fg_color, bg_color);
		tem_display(tem, &da, credp, called_from);
		da.col += da.width;
	}
}

void
tem_pix_copy(struct tem *tem,
	screen_pos_t s_col, screen_pos_t s_row,
	screen_pos_t e_col, screen_pos_t e_row,
	screen_pos_t t_col, screen_pos_t t_row,
	cred_t *credp,
	enum called_from called_from)
{
	struct tem_state *tems = tem->state;
	struct vis_conscopy ma;
	static boolean_t need_clear = B_TRUE;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	if (need_clear && tems->first_line > 0) {
		/*
		 * Clear OBP output above our kernel console term
		 * when our kernel console term begins to scroll up,
		 * we hope it is user friendly.
		 * (Also see comments on tem_pix_clear_prom_output)
		 *
		 * This is only one time call.
		 */
		tem_pix_clear_prom_output(tem, credp, called_from);
	}
	need_clear = B_FALSE;

	ma.s_row = s_row * tems->a_font.height + tems->a_p_offset.y;
	ma.e_row = (e_row + 1) * tems->a_font.height + tems->a_p_offset.y - 1;
	ma.t_row = t_row * tems->a_font.height + tems->a_p_offset.y;

	/*
	 * Check if we're in process of clearing OBP's columns area,
	 * which only happens when term scrolls up a whole line.
	 */
	if (tems->first_line > 0 && t_row < s_row && t_col == 0 &&
	    e_col == tems->a_c_dimension.width - 1) {
		/*
		 * We need to clear OBP's columns area outside our kernel
		 * console term. So that we set ma.e_col to entire row here.
		 */
		ma.s_col = s_col * tems->a_font.width;
		ma.e_col = tems->a_p_dimension.width - 1;

		ma.t_col = t_col * tems->a_font.width;
	} else {
		ma.s_col = s_col * tems->a_font.width + tems->a_p_offset.x;
		ma.e_col = (e_col + 1) * tems->a_font.width +
		    tems->a_p_offset.x - 1;
		ma.t_col = t_col * tems->a_font.width + tems->a_p_offset.x;
	}

	tem_copy(tem, &ma, credp, called_from);

	if (tems->first_line > 0 && t_row < s_row) {
		/* We have scrolled up (s_row - t_row) rows. */
		tems->first_line -= (s_row - t_row);
		if (tems->first_line <= 0) {
			/* All OBP rows have been cleared. */
			tems->first_line = 0;
		}
	}

}

/*
 * This function only clears count of columns in one row
 */
void
tem_pix_cls(struct tem *tem, int count,
	screen_pos_t row, screen_pos_t col, cred_t *credp,
	enum called_from called_from)
{
	struct tem_state *tems = tem->state;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	tem_pix_cls_range(tem, row, 1, tems->a_p_offset.y,
	    col, count, tems->a_p_offset.x, B_FALSE, credp, called_from);
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
tem_pix_clear_prom_output(struct tem *tem, cred_t *credp,
    enum called_from called_from)
{
	struct tem_state *tems = tem->state;
	int	nrows, ncols, width, height;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	width = tems->a_font.width;
	height = tems->a_font.height;

	nrows = (tems->a_p_offset.y + (height - 1))/ height;
	ncols = (tems->a_p_dimension.width + (width - 1))/ width;

	tem_pix_cls_range(tem, 0, nrows, 0, 0, ncols, 0,
	    B_FALSE, credp, called_from);
}

/*
 * clear the whole screen for pixel mode
 */
static void
tem_pix_clear_entire_screen(struct tem *tem, cred_t *credp,
    enum called_from called_from)
{
	struct tem_state *tems = tem->state;
	int	nrows, ncols, width, height;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	width = tems->a_font.width;
	height = tems->a_font.height;

	nrows = (tems->a_p_dimension.height + (height - 1))/ height;
	ncols = (tems->a_p_dimension.width + (width - 1))/ width;

	tem_pix_cls_range(tem, 0, nrows, 0, 0, ncols, 0,
	    B_FALSE, credp, called_from);

	tems->a_c_cursor.row = 0;
	tems->a_c_cursor.col = 0;
	tem_align_cursor(tem);

	/*
	 * Since the whole screen is cleared, we don't need
	 * to clear OBP output later.
	 */
	if (tems->first_line > 0) {
		tems->first_line = 0;
	}
}

/*
 * clear the whole screen
 */
static void
tem_cls(struct tem *tem,
    cred_t *credp, enum called_from called_from)
{
	struct tem_state *tems = tem->state;
	int	row;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	if (tems->display_mode == VIS_TEXT) {
		for (row = 0; row < tems->a_c_dimension.height; row++) {
			tem_clear_chars(tem, tems->a_c_dimension.width,
			    row, 0, credp, called_from);
		}
		tems->a_c_cursor.row = 0;
		tems->a_c_cursor.col = 0;
		tem_align_cursor(tem);
		return;
	}

	ASSERT(tems->display_mode == VIS_PIXEL);

	tem_pix_clear_entire_screen(tem, credp, called_from);
}

static void
tem_back_tab(struct tem *tem,
    cred_t *credp, enum called_from called_from)
{
	struct tem_state *tems = tem->state;
	int	i;
	screen_pos_t	tabstop;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	tabstop = 0;

	for (i = tems->a_ntabs - 1; i >= 0; i--) {
		if (tems->a_tabs[i] < tems->a_c_cursor.col) {
			tabstop = tems->a_tabs[i];
			break;
		}
	}

	tem_mv_cursor(tem, tems->a_c_cursor.row,
	    tabstop, credp, called_from);
}

static void
tem_tab(struct tem *tem,
    cred_t *credp, enum called_from called_from)
{
	struct tem_state *tems = tem->state;
	int	i;
	screen_pos_t	tabstop;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	tabstop = tems->a_c_dimension.width - 1;

	for (i = 0; i < tems->a_ntabs; i++) {
		if (tems->a_tabs[i] > tems->a_c_cursor.col) {
			tabstop = tems->a_tabs[i];
			break;
		}
	}

	tem_mv_cursor(tem, tems->a_c_cursor.row,
	    tabstop, credp, called_from);
}

static void
tem_set_tab(struct tem *tem)
{
	struct tem_state *tems = tem->state;
	int	i;
	int	j;

	if (tems->a_ntabs == TEM_MAXTAB)
		return;
	if (tems->a_ntabs == 0 ||
	    tems->a_tabs[tems->a_ntabs] < tems->a_c_cursor.col) {
		tems->a_tabs[tems->a_ntabs++] = tems->a_c_cursor.col;
		return;
	}
	for (i = 0; i < tems->a_ntabs; i++) {
		if (tems->a_tabs[i] == tems->a_c_cursor.col)
			return;
		if (tems->a_tabs[i] > tems->a_c_cursor.col) {
			for (j = tems->a_ntabs - 1; j >= i; j--)
				tems->a_tabs[j+ 1] = tems->a_tabs[j];
			tems->a_tabs[i] = tems->a_c_cursor.col;
			tems->a_ntabs++;
			return;
		}
	}
}

static void
tem_clear_tabs(struct tem *tem, int action)
{
	struct tem_state *tems = tem->state;
	int	i;
	int	j;

	switch (action) {
	case 3: /* clear all tabs */
		tems->a_ntabs = 0;
		break;
	case 0: /* clr tab at cursor */

		for (i = 0; i < tems->a_ntabs; i++) {
			if (tems->a_tabs[i] == tems->a_c_cursor.col) {
				tems->a_ntabs--;
				for (j = i; j < tems->a_ntabs; j++)
					tems->a_tabs[j] = tems->a_tabs[j + 1];
				return;
			}
		}
		break;
	}
}

static void
tem_mv_cursor(struct tem *tem, int row, int col,
    cred_t *credp, enum called_from called_from)
{
	struct tem_state *tems = tem->state;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	/*
	 * Sanity check and bounds enforcement.  Out of bounds requests are
	 * clipped to the screen boundaries.  This seems to be what SPARC
	 * does.
	 */
	if (row < 0)
		row = 0;
	if (row >= tems->a_c_dimension.height)
		row = tems->a_c_dimension.height - 1;
	if (col < 0)
		col = 0;
	if (col >= tems->a_c_dimension.width)
		col = tems->a_c_dimension.width - 1;

	tem_send_data(tem, credp, called_from);
	tems->a_c_cursor.row = row;
	tems->a_c_cursor.col = col;
	tem_align_cursor(tem);
}

/* ARGSUSED */
void
tem_reset_emulator(struct tem *tem,
    cred_t *credp, enum called_from called_from,
    tem_color_t *pcolor)
{
	struct tem_state *tems = tem->state;
	int j;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	tems->a_c_cursor.row = 0;
	tems->a_c_cursor.col = 0;
	tems->a_r_cursor.row = 0;
	tems->a_r_cursor.col = 0;
	tems->a_s_cursor.row = 0;
	tems->a_s_cursor.col = 0;
	tems->a_outindex = 0;
	tems->a_state = A_STATE_START;
	tems->a_gotparam = B_FALSE;
	tems->a_curparam = 0;
	tems->a_paramval = 0;
	tems->a_nscroll = 1;

	if (pcolor != NULL) {
		/* use customized settings */
		tems->fg_color = pcolor->fg_color;
		tems->bg_color = pcolor->bg_color;
		tems->a_flags = pcolor->a_flags;
	} else {
		/* use initial settings */
		tems->fg_color = tem->init_color.fg_color;
		tems->bg_color = tem->init_color.bg_color;
		tems->a_flags = tem->init_color.a_flags;
	}

	/*
	 * set up the initial tab stops
	 */
	tems->a_ntabs = 0;
	for (j = 8; j < tems->a_c_dimension.width; j += 8)
		tems->a_tabs[tems->a_ntabs++] = (screen_pos_t)j;

	for (j = 0; j < TEM_MAXPARAMS; j++)
		tems->a_params[j] = 0;
}

void
tem_reset_display(struct tem *tem,
    cred_t *credp, enum called_from called_from, int clear_txt,
    tem_color_t *pcolor)
{
	struct tem_state *tems = tem->state;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	tem_reset_emulator(tem, credp, called_from, pcolor);
	tem_reset_colormap(tem, credp, called_from);

	if (clear_txt) {
		(*tems->in_fp.f_cursor)(tem,
		    VIS_HIDE_CURSOR, credp, called_from);

		tem_cls(tem, credp, called_from);

		(*tems->in_fp.f_cursor)(tem,
		    VIS_DISPLAY_CURSOR, credp, called_from);
	}

	tems->a_initialized = 1;
}


static void
tem_shift(
	struct tem *tem,
	int count,
	int direction,
	cred_t *credp,
	enum called_from called_from)
{
	struct tem_state *tems = tem->state;
	int rest_of_line;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	rest_of_line = tems->a_c_dimension.width - tems->a_c_cursor.col;
	if (count > rest_of_line)
		count = rest_of_line;

	if (count <= 0)
		return;

	switch (direction) {
	case TEM_SHIFT_LEFT:
		if (count < rest_of_line) {
			tem_copy_area(tem,
			    tems->a_c_cursor.col + count,
			    tems->a_c_cursor.row,
			    tems->a_c_dimension.width - 1,
			    tems->a_c_cursor.row,
			    tems->a_c_cursor.col,
			    tems->a_c_cursor.row,
			    credp, called_from);
		}

		tem_clear_chars(tem, count, tems->a_c_cursor.row,
		    (tems->a_c_dimension.width - count), credp,
		    called_from);
		break;
	case TEM_SHIFT_RIGHT:
		if (count < rest_of_line) {
			tem_copy_area(tem,
			    tems->a_c_cursor.col,
			    tems->a_c_cursor.row,
			    tems->a_c_dimension.width - count - 1,
			    tems->a_c_cursor.row,
			    tems->a_c_cursor.col + count,
			    tems->a_c_cursor.row,
			    credp, called_from);
		}

		tem_clear_chars(tem, count, tems->a_c_cursor.row,
		    tems->a_c_cursor.col, credp, called_from);
		break;
	}
}

void
tem_text_cursor(struct tem *tem, short action,
    cred_t *credp, enum called_from called_from)
{
	struct tem_state *tems = tem->state;
	struct vis_conscursor	ca;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	ca.row = tems->a_c_cursor.row;
	ca.col = tems->a_c_cursor.col;
	ca.action = action;

	tem_cursor(tem, &ca, credp, called_from);

	if (action == VIS_GET_CURSOR) {
		tems->a_c_cursor.row = ca.row;
		tems->a_c_cursor.col = ca.col;
	}
}


void
tem_pix_cursor(struct tem *tem, short action,
    cred_t *credp, enum called_from called_from)
{
	struct tem_state *tems = tem->state;
	struct vis_conscursor	ca;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	ca.row = tems->a_c_cursor.row * tems->a_font.height +
	    tems->a_p_offset.y;
	ca.col = tems->a_c_cursor.col * tems->a_font.width +
	    tems->a_p_offset.x;
	ca.width = tems->a_font.width;
	ca.height = tems->a_font.height;
	if (tems->a_pdepth == 8 || tems->a_pdepth == 4) {
		if (tems->a_flags & TEM_ATTR_REVERSE) {
			ca.fg_color.mono = TEM_TEXT_WHITE;
			ca.bg_color.mono = TEM_TEXT_BLACK;
		} else {
			ca.fg_color.mono = TEM_TEXT_BLACK;
			ca.bg_color.mono = TEM_TEXT_WHITE;
		}
	} else if (tems->a_pdepth == 24 || tems->a_pdepth == 32) {
		if (tems->a_flags & TEM_ATTR_REVERSE) {
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

#define	BORDER_PIXELS 10
void
set_font(struct font *f, short *rows, short *cols, short height, short width)
{
	bitmap_data_t	*font_selected = NULL;
	struct fontlist	*fl;

	/*
	 * Find best font for these dimensions, or use default
	 *
	 * A 1 pixel border is the absolute minimum we could have
	 * as a border around the text window (BORDER_PIXELS = 2),
	 * however a slightly larger border not only looks better
	 * but for the fonts currently statically built into the
	 * emulator causes much better font selection for the
	 * normal range of screen resolutions.
	 */
	for (fl = fonts; fl->data; fl++) {
		if ((((*rows * fl->data->height) + BORDER_PIXELS) <= height) &&
		    (((*cols * fl->data->width) + BORDER_PIXELS) <= width)) {
			font_selected = fl->data;
			break;
		}
	}
	/*
	 * The minus 2 is to make sure we have at least a 1 pixel
	 * boarder around the entire screen.
	 */
	if (font_selected == NULL) {
		if (((*rows * DEFAULT_FONT_DATA.height) > height) ||
		    ((*cols * DEFAULT_FONT_DATA.width) > width)) {
			*rows = (height - 2) / DEFAULT_FONT_DATA.height;
			*cols = (width - 2) / DEFAULT_FONT_DATA.width;
		}
		font_selected = &DEFAULT_FONT_DATA;
	}

	f->width = font_selected->width;
	f->height = font_selected->height;
	bcopy((caddr_t)font_selected->encoding, (caddr_t)f->char_ptr,
	    sizeof (f->char_ptr));
	f->image_data = font_selected->image;

}

/*
 * bit_to_pix4 is for 4-bit frame buffers.  It will write one output byte
 * for each 2 bits of input bitmap.  It inverts the input bits before
 * doing the output translation, for reverse video.
 *
 * Assuming foreground is 0001 and background is 0000...
 * An input data byte of 0x53 will output the bit pattern
 * 00000001 00000001 00000000 00010001.
 */

void
bit_to_pix4(
    struct tem *tem,
    uchar_t c,
    text_color_t fg_color,
    text_color_t bg_color)
{
	struct tem_state *tems = tem->state;
	int	row;
	int	byte;
	int	i;
	uint8_t	*cp;
	uint8_t	data;
	uint8_t	nibblett;
	int	bytes_wide;
	uint8_t *dest;

	dest = (uint8_t *)tems->a_pix_data;

	cp = tems->a_font.char_ptr[c];
	bytes_wide = (tems->a_font.width + 7) / 8;

	for (row = 0; row < tems->a_font.height; row++) {
		for (byte = 0; byte < bytes_wide; byte++) {
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

void
bit_to_pix8(
    struct tem *tem,
    uchar_t c,
    text_color_t fg_color,
    text_color_t bg_color)
{
	struct tem_state *tems = tem->state;
	int	row;
	int	byte;
	int	i;
	uint8_t	*cp;
	uint8_t	data;
	int	bytes_wide;
	uint8_t	mask;
	int	bitsleft, nbits;
	uint8_t *dest;

	dest = (uint8_t *)tems->a_pix_data;

	cp = tems->a_font.char_ptr[c];
	bytes_wide = (tems->a_font.width + 7) / 8;

	for (row = 0; row < tems->a_font.height; row++) {
		bitsleft = tems->a_font.width;
		for (byte = 0; byte < bytes_wide; byte++) {
			data = *cp++;
			mask = 0x80;
			nbits = MIN(8, bitsleft);
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
 * doing the output translation, for reverse video.  Note that each
 * 24-bit RGB value is finally stored in a 32-bit unsigned int, with the
 * high-order byte set to zero.
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
 */
typedef uint32_t pixel32_t;

void
bit_to_pix24(
	struct tem *tem,
	uchar_t c,
	text_color_t fg_color4,
	text_color_t bg_color4)
{
	struct tem_state *tems = tem->state;
	int	row;
	int	byte;
	int	i;
	uint8_t	*cp;
	uint8_t	data;
	int	bytes_wide;
	int	bitsleft, nbits;

	pixel32_t fg_color32, bg_color32, *destp;

	ASSERT(fg_color4 < 16 && bg_color4 < 16);

	fg_color32 = PIX4TO32(fg_color4);
	bg_color32 = PIX4TO32(bg_color4);

	destp = (pixel32_t *)tems->a_pix_data;
	cp = tems->a_font.char_ptr[c];
	bytes_wide = (tems->a_font.width + 7) / 8;

	for (row = 0; row < tems->a_font.height; row++) {
		bitsleft = tems->a_font.width;
		for (byte = 0; byte < bytes_wide; byte++) {
			data = *cp++;
			nbits = MIN(8, bitsleft);
			bitsleft -= nbits;
			for (i = 0; i < nbits; i++) {
				*destp++ = ((data << i) & 0x80 ?
				    fg_color32 : bg_color32);
			}
		}
	}
}

/* ARGSUSED */
text_color_t
ansi_bg_to_solaris(struct tem *tem, int ansi)
{
	return (bg_xlate[ansi]);
}

text_color_t
ansi_fg_to_solaris(struct tem *tem, int ansi)
{
	if (tem->state->a_flags & TEM_ATTR_BOLD)
		return (fg_brt_xlate[ansi]);
	else
		return (fg_dim_xlate[ansi]);
}

static void
tem_get_color(struct tem *tem, text_color_t *fg, text_color_t *bg)
{
	if (tem->state->a_flags & TEM_ATTR_SCREEN_REVERSE) {
		*fg = ansi_fg_to_solaris(tem,
		    DEFAULT_ANSI_BACKGROUND);
		*bg = ansi_bg_to_solaris(tem,
		    DEFAULT_ANSI_FOREGROUND);
	} else {
		*fg = ansi_fg_to_solaris(tem,
		    DEFAULT_ANSI_FOREGROUND);
		*bg = ansi_bg_to_solaris(tem,
		    DEFAULT_ANSI_BACKGROUND);
	}
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
void
tem_pix_cls_range(tem_t *tem,
	screen_pos_t row, int nrows, int offset_y,
	screen_pos_t col, int ncols, int offset_x,
	boolean_t sroll_up, cred_t *credp,
	enum called_from called_from)
{
	struct tem_state *tems = tem->state;
	struct vis_consdisplay da;
	int	i, j;
	int	row_add = 0;
	text_color_t fg_color;
	text_color_t bg_color;

	ASSERT((called_from == CALLED_FROM_STANDALONE) ||
	    MUTEX_HELD(&tem->lock));

	if (sroll_up)
		row_add = tems->a_c_dimension.height - 1;

	da.width = tems->a_font.width;
	da.height = tems->a_font.height;

	tem_get_color(tem, &fg_color, &bg_color);

	BIT_TO_PIX(tem, ' ', fg_color, bg_color);
	da.data = (uchar_t *)tems->a_pix_data;

	for (i = 0; i < nrows; i++, row++) {
		da.row = (row + row_add) * da.height + offset_y;
		da.col = col * da.width + offset_x;
		for (j = 0; j < ncols; j++) {
			tem_display(tem, &da, credp, called_from);
			da.col += da.width;
		}
	}
}
