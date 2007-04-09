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

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef	_SYS_TEM_IMPL_H
#define	_SYS_TEM_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/visual_io.h>
#include <sys/font.h>
#include <sys/tem.h>

/*
 * definitions for ANSI x3.64 terminal control language parser
 */

#define	TEM_MAXPARAMS	5	/* maximum number of ANSI paramters */
#define	TEM_MAXTAB	40	/* maximum number of tab stops */
#define	TEM_MAXFKEY	30	/* max length of function key with <ESC>Q */
#define	MAX_TEM		2	/* max number of loadable terminal emulators */

#define	TEM_SCROLL_UP		0
#define	TEM_SCROLL_DOWN		1
#define	TEM_SHIFT_LEFT		0
#define	TEM_SHIFT_RIGHT		1

#define	TEM_ATTR_NORMAL		0x0000
#define	TEM_ATTR_REVERSE	0x0001
#define	TEM_ATTR_BOLD		0x0002
#define	TEM_ATTR_BLINK		0x0004
#define	TEM_ATTR_TRANSPARENT	0x0008
#define	TEM_ATTR_SCREEN_REVERSE	0x0010

#define	ANSI_COLOR_BLACK	0
#define	ANSI_COLOR_WHITE	7

#define	TEM_TEXT_WHITE		0
#define	TEM_TEXT_BLACK		1
#define	TEM_TEXT_BLACK24_RED	0x00
#define	TEM_TEXT_BLACK24_GREEN	0x00
#define	TEM_TEXT_BLACK24_BLUE	0x00
#define	TEM_TEXT_WHITE24_RED	0xff
#define	TEM_TEXT_WHITE24_GREEN	0xff
#define	TEM_TEXT_WHITE24_BLUE	0xff

#define	A_STATE_START			0
#define	A_STATE_ESC			1
#define	A_STATE_CSI			2
#define	A_STATE_CSI_QMARK		3
#define	A_STATE_CSI_EQUAL		4

/*
 * Default number of rows and columns
 */
#define	TEM_DEFAULT_ROWS	34
#define	TEM_DEFAULT_COLS	80

/*
 * Default foreground/background color
 */
#ifdef _HAVE_TEM_FIRMWARE
#define	DEFAULT_ANSI_FOREGROUND	ANSI_COLOR_BLACK
#define	DEFAULT_ANSI_BACKGROUND	ANSI_COLOR_WHITE
#else /* _HAVE_TEM_FIRMWARE */
#define	DEFAULT_ANSI_FOREGROUND	ANSI_COLOR_WHITE
#define	DEFAULT_ANSI_BACKGROUND	ANSI_COLOR_BLACK
#endif

#define	BUF_LEN		160 /* Two lines of data can be processed at a time */

typedef uint8_t text_color_t;

typedef struct tem_color {
	text_color_t	fg_color;
	text_color_t	bg_color;
	unsigned short	a_flags;
} tem_color_t;

struct tem_pix_pos {
	screen_pos_t	x;
	screen_pos_t	y;
};

struct tem_char_pos {
	screen_pos_t	col;
	screen_pos_t	row;
};

struct tem_size {
	screen_size_t	width;
	screen_size_t	height;
};

typedef struct {
	uint8_t red[16];
	uint8_t green[16];
	uint8_t blue[16];
} text_cmap_t;

extern text_cmap_t cmap4_to_24;

struct tem;	/* Forward declare */

enum called_from { CALLED_FROM_NORMAL, CALLED_FROM_STANDALONE };

struct in_func_ptrs {
	void (*f_display)(struct tem *, unsigned char *, int,
	    screen_pos_t, screen_pos_t, unsigned char, unsigned char,
	    cred_t *, enum called_from);
	void (*f_copy)(struct tem *,
	    screen_pos_t, screen_pos_t, screen_pos_t, screen_pos_t,
	    screen_pos_t, screen_pos_t, cred_t *, enum called_from);
	void (*f_cursor)(struct tem *, short, cred_t *,
	    enum called_from);
	void (*f_bit2pix)(struct tem *, unsigned char,
	    unsigned char, unsigned char);
	void (*f_cls)(struct tem *, int,
	    screen_pos_t, screen_pos_t, cred_t *, enum called_from);
};

/*
 * State structure for terminal emulator
 */
typedef struct tem_state {		/* state for tem x3.64 emulator */
	int	display_mode;		/* What mode we are in */
	screen_size_t	linebytes;	/* Layered on bytes per scan line */
	unsigned short	a_flags;	/* flags for this x3.64 terminal */
	int	a_state;	/* state in output esc seq processing */
	boolean_t	a_gotparam;	/* does output esc seq have a param */
	int	a_curparam;	/* current param # of output esc seq */
	int	a_paramval;	/* value of current param */
	int	a_params[TEM_MAXPARAMS];  /* parameters of output esc seq */
	screen_pos_t	a_tabs[TEM_MAXTAB];	/* tab stops */
	int	a_ntabs;		/* number of tabs used */
	int	a_nscroll;		/* number of lines to scroll */
	struct tem_char_pos a_s_cursor;	/* start cursor position */
	struct tem_char_pos a_c_cursor;	/* current cursor position */
	struct tem_char_pos a_r_cursor;	/* remembered cursor position */
	struct tem_size a_c_dimension;	/* window dimensions in characters */
	struct tem_size a_p_dimension;	/* screen dimensions in pixels */
	struct tem_pix_pos a_p_offset;	/* pix offset to center the display */
	unsigned char	*a_outbuf;	/* place to keep incomplete lines */
	unsigned char	*a_blank_line;	/* a blank line for scrolling */
	int	a_outindex;	/* index into a_outbuf */
	struct in_func_ptrs	in_fp;	/* internal output functions */
	struct font	a_font;	/* font table */
	int	a_pdepth;	/* pixel depth */
	int	a_initialized;	/* initialization flag */
	void   *a_pix_data;	/* pointer to tmp bitmap area */
	int	a_pix_data_size; /* size of bitmap data areas */
	text_color_t fg_color;
	text_color_t bg_color;
	int	first_line;	/* kernel console output begins */
} tem_state_t;

/*
 * State structure for terminal emulator
 */
typedef struct tem {
#ifdef	_HAVE_TEM_FIRMWARE
	void (*cons_wrtvec)	/* PROM output gets redirected thru this vec. */
	    (struct tem *, uchar_t *, ssize_t, cred_t *);
#endif /* _HAVE_TEM_FIRMWARE */
	ldi_handle_t		hdl; /* Framework handle for layered on dev */
	dev_info_t		*dip; /* Our dip */
	kmutex_t		lock;
	struct vis_polledio	*fb_polledio;
	tem_state_t		*state;
	tem_modechg_cb_t	modechg_cb;
	tem_modechg_cb_arg_t	modechg_arg;
	tem_color_t		init_color; /* initial color and attributes */
} tem_t;

void	tem_check_first_time(tem_t *tem, cred_t *, enum called_from);
void	tem_reset_colormap(tem_t *, cred_t *, enum called_from);
void	tem_align_cursor(tem_t *);
void	tem_reset_emulator(tem_t *, cred_t *, enum called_from, tem_color_t *);
void	tem_reset_display(tem_t *, cred_t *, enum called_from, int,
			tem_color_t *);
void	tem_display_layered(tem_t *, struct vis_consdisplay *, cred_t *);
void	tem_copy_layered(tem_t *, struct vis_conscopy *, cred_t *);
void	tem_cursor_layered(tem_t *, struct vis_conscursor *, cred_t *);
void	tem_terminal_emulate(tem_t *, uchar_t *, int, cred_t *,
			enum called_from);
void	tem_text_display(tem_t *, uchar_t *,
			int, screen_pos_t, screen_pos_t,
			text_color_t, text_color_t,
			cred_t *, enum called_from);
void	tem_text_copy(tem_t *,
			screen_pos_t, screen_pos_t,
			screen_pos_t, screen_pos_t,
			screen_pos_t, screen_pos_t,
			cred_t *, enum called_from);
void	tem_text_cursor(tem_t *, short, cred_t *, enum called_from);
void	tem_text_cls(tem_t *,
			int count, screen_pos_t row, screen_pos_t col,
			cred_t *credp, enum called_from called_from);
void	tem_pix_display(tem_t *, uchar_t *,
			int, screen_pos_t, screen_pos_t,
			text_color_t, text_color_t,
			cred_t *, enum called_from);
void	tem_pix_copy(tem_t *,
			screen_pos_t, screen_pos_t,
			screen_pos_t, screen_pos_t,
			screen_pos_t, screen_pos_t,
			cred_t *, enum called_from);
void	tem_copy(tem_t *,
			struct vis_conscopy *,
			cred_t *, enum called_from);
void	tem_pix_cursor(tem_t *, short, cred_t *, enum called_from);
void	tem_pix_cls(tem_t *, int, screen_pos_t, screen_pos_t,
			cred_t *, enum called_from);
void	tem_pix_cls_range(tem_t *,
			screen_pos_t, int, int,
			screen_pos_t, int, int,
			boolean_t, cred_t *, enum called_from);

void	bit_to_pix24(tem_t *, uchar_t, text_color_t, text_color_t);
void	bit_to_pix8(tem_t *, uchar_t, text_color_t, text_color_t);
void	bit_to_pix4(tem_t *, uchar_t, text_color_t, text_color_t);

text_color_t ansi_bg_to_solaris(tem_t *, int);
text_color_t ansi_fg_to_solaris(tem_t *, int);

void	set_font(struct font *, short *, short *, short, short);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_TEM_IMPL_H */
