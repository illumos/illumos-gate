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

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef	_SYS_TEM_IMPL_H
#define	_SYS_TEM_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/sunldi.h>
#include <sys/visual_io.h>

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
#define	A_STATE_ESC_Q			2
#define	A_STATE_ESC_Q_DELM		3
#define	A_STATE_ESC_Q_DELM_CTRL		4
#define	A_STATE_ESC_C			5
#define	A_STATE_CSI			6
#define	A_STATE_CSI_QMARK		7
#define	A_STATE_CSI_EQUAL		8

/*
 * Default number of rows and columns
 */
#define	TEM_DEFAULT_ROWS	34
#define	TEM_DEFAULT_COLS	80

#define	BUF_LEN		160 /* Two lines of data can be processed at a time */

typedef uint8_t text_color_t;

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

struct terminal_emulator;	/* Forward declare */

enum called_from { CALLED_FROM_NORMAL, CALLED_FROM_STANDALONE };

struct in_func_ptrs {
	void (*f_display)(struct terminal_emulator *, unsigned char *, int,
	    screen_pos_t, screen_pos_t, unsigned char, unsigned char,
	    cred_t *, enum called_from);
	void (*f_copy)(struct terminal_emulator *,
	    screen_pos_t, screen_pos_t, screen_pos_t, screen_pos_t,
	    screen_pos_t, screen_pos_t, cred_t *, enum called_from);
	void (*f_cursor)(struct terminal_emulator *, short, cred_t *,
	    enum called_from);
	void (*f_bit2pix)(struct terminal_emulator *, unsigned char,
	    unsigned char, unsigned char);
	void (*f_cls)(struct terminal_emulator *, int,
	    screen_pos_t, screen_pos_t, cred_t *, enum called_from);
};

/*
 * State structure for terminal emulator
 */
struct terminal_emulator {		/* state for tem x3.64 emulator */
	ldi_handle_t		hdl; /* Framework handle for layered on dev */
	screen_size_t		linebytes; /* Layered on bytes per scan line */
	int			display_mode; /* What mode we are in */
	dev_info_t		*dip; /* Our dip */
	kmutex_t		lock;
	boolean_t		standalone_writes_ok;
	struct vis_polledio	*fb_polledio;
	unsigned short	a_flags;	/* flags for this x3.64 terminal */
	int	a_state;	/* state in output esc seq processing */
	boolean_t	a_gotparam;	/* does output esc seq have a param */
	int	a_curparam;	/* current param # of output esc seq */
	int	a_paramval;	/* value of current param */
	int	a_params[TEM_MAXPARAMS];  /* parameters of output esc seq */
	char	a_fkey[TEM_MAXFKEY];	/* work space for function key */
	screen_pos_t	a_tabs[TEM_MAXTAB];	/* tab stops */
	int	a_ntabs;		/* number of tabs used */
	int	a_nscroll;		/* number of lines to scroll */
	struct tem_char_pos a_s_cursor;	/* start cursor position */
	struct tem_char_pos a_c_cursor;	/* current cursor position */
	struct tem_char_pos a_r_cursor;	/* remembered cursor position */
	struct tem_size a_c_dimension;	/* window dimensions in characters */
	struct tem_size a_p_dimension;	/* screen dimensions in pixels */
	struct tem_size default_dims;	/* target dims in characters */
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
};

#ifdef __cplusplus
}
#endif

#endif /* _SYS_TEM_IMPL_H */
