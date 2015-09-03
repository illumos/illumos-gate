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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright 2015 Joyent, Inc.
 */

/*
 * Terminal I/O Backend
 *
 * Terminal editing backend for standard input.  The terminal i/o backend is
 * actually built on top of two other i/o backends: one for raw input and
 * another for raw output (presumably stdin and stdout).  When IOP_READ is
 * invoked, the terminal backend enters a read-loop in which it can perform
 * command-line editing and access a history buffer.  Once a newline is read,
 * the entire buffered command-line is returned to the caller.  The termio
 * code makes use of a command buffer (see mdb_cmdbuf.c) to maintain and
 * manipulate the state of a command line, and store it for re-use in a
 * history list.  The termio code manipulates the terminal to keep it in
 * sync with the contents of the command buffer, and moves the cursor in
 * response to editing commands.
 *
 * The terminal backend is also responsible for maintaining and manipulating
 * the settings (see stty(1) and termio(7I)) associated with the terminal.
 * The debugger makes use of four distinct sets of terminal attributes:
 *
 * (1) the settings used by the debugger's parent process (tio_ptios),
 * (2) the settings used by a controlled child process (tio_ctios),
 * (3) the settings used for reading and command-line editing (tio_rtios), and
 * (4) the settings used when mdb dcmds are executing (tio_dtios).
 *
 * The parent settings (1) are read from the terminal during initialization.
 * These settings are restored before the debugger exits or when it is stopped
 * by SIGTSTP.  The child settings (2) are initially a copy of (1), but are
 * then restored prior to continuing execution of a victim process.  The new
 * settings (3) and (4) are both derived from (1).  The raw settings (3) used
 * for reading from the terminal allow the terminal code to respond instantly
 * to keypresses and perform all the necessary handling.  The dcmd settings (4)
 * are essentially the same as (1), except that we make sure ISIG is enabled
 * so that we will receive asynchronous SIGINT notification from the terminal
 * driver if the user types the interrupt character (typically ^C).
 */

#include <setjmp.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>

#include <mdb/mdb_types.h>
#include <mdb/mdb_cmdbuf.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_signal.h>
#include <mdb/mdb_callb.h>
#include <mdb/mdb_stdlib.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb_tab.h>
#include <mdb/mdb.h>

#ifdef ERR
#undef ERR
#endif

#include <curses.h>

#define	KEY_ESC	(0x01b)			/* Escape key code */
#define	KEY_DEL (0x07f)			/* ASCII DEL key code */

/*
 * These macros support the use of various ranges within the "tio_keymap"
 * member of "termio_data_t" objects.  This array maps from an input byte, or
 * special control code, to the appropriate terminal handling callback.  The
 * array has KEY_MAX (0x1ff) entries, partitioned as follows:
 *
 *     0 -  7f		7-bit ASCII byte
 *    80 -  ff	META()	ASCII byte with Meta key modifier
 *   100 - 119	KPAD()	Alphabetic character received as part of a single-byte
 *			cursor control sequence, e.g. ESC [ A
 *   11a - 123	FKEY()	Numeric character received as part of a function key
 *			control sequence, e.g. ESC [ 4 ~
 *   124 - 1ff		Unused
 */
#define	META(c)		(((c) & 0x7f) | 0x80)
#define	KPAD(c)		(((c) < 'A' || (c) > 'Z') ? 0 : ((c) - 'A' + 0x100))
#define	FKEY(c)		(((c) < '0' || (c) > '9') ? 0 : ((c) - '0' + 0x11a))

/*
 * These macros allow for composition of control sequences for xterm and other
 * terminals that support certain features of the VT102 and later VT terminals.
 * Refer to the classic monograph "Xterm Control Sequences" for more info.
 */
#define	TI_DECSET(Pm) "\033[?" Pm "h"	/* Compose DEC private mode set */
#define	TI_DECRST(Pm) "\033[?" Pm "l"	/* Compose DEC private mode reset */
#define	TI_DECSAV(Pm) "\033[?" Pm "s"	/* Compose DEC private mode save */
#define	TI_DECRES(Pm) "\033[?" Pm "r"	/* Compose DEC private mode restore */

#define	TI_DECCOLM		"3"	/* Ps = DEC 80/132 column mode */
#define	TI_COLENAB		"40"	/* Ps = 80/132 column switch enable */

#define	TIO_DEFAULT_ROWS	24	/* Default number of rows */
#define	TIO_DEFAULT_COLS	80	/* Default number of columns */

typedef union termio_attr_val {
	const char *at_str;		/* String value */
	int at_val;			/* Integer or boolean value */
} termio_attr_val_t;

typedef struct termio_info {
	termio_attr_val_t ti_cub1;	/* Move back one space */
	termio_attr_val_t ti_cuf1;	/* Move forward one space */
	termio_attr_val_t ti_cuu1;	/* Move up one line */
	termio_attr_val_t ti_cud1;	/* Move down one line */
	termio_attr_val_t ti_pad;	/* Pad character */
	termio_attr_val_t ti_el;	/* Clear to end-of-line */
	termio_attr_val_t ti_am;	/* Automatic right margin? */
	termio_attr_val_t ti_bw;	/* Backward motion at left edge? */
	termio_attr_val_t ti_npc;	/* No padding character? */
	termio_attr_val_t ti_xenl;	/* Newline ignored after 80 cols? */
	termio_attr_val_t ti_xon;	/* Use xon/xoff handshaking? */
	termio_attr_val_t ti_cols;	/* # of columns */
	termio_attr_val_t ti_lines;	/* # of rows */
	termio_attr_val_t ti_pb;	/* Lowest baud rate that requires pad */
	termio_attr_val_t ti_smso;	/* Set standout mode */
	termio_attr_val_t ti_rmso;	/* Remove standout mode */
	termio_attr_val_t ti_smul;	/* Set underline mode */
	termio_attr_val_t ti_rmul;	/* Remove underline mode */
	termio_attr_val_t ti_enacs;	/* Enable alternate character set */
	termio_attr_val_t ti_smacs;	/* Set alternate character set */
	termio_attr_val_t ti_rmacs;	/* Remove alternate character set */
	termio_attr_val_t ti_smcup;	/* Set mode where cup is active */
	termio_attr_val_t ti_rmcup;	/* Remove mode where cup is active */
	termio_attr_val_t ti_rev;	/* Set reverse video mode */
	termio_attr_val_t ti_bold;	/* Set bold text mode */
	termio_attr_val_t ti_dim;	/* Set dim text mode */
	termio_attr_val_t ti_sgr0;	/* Remove all video attributes */
	termio_attr_val_t ti_smir;	/* Set insert mode */
	termio_attr_val_t ti_rmir;	/* Remove insert mode */
	termio_attr_val_t ti_ich1;	/* Insert character */
	termio_attr_val_t ti_ip;	/* Insert pad delay in msecs */
	termio_attr_val_t ti_clear;	/* Clear screen and home cursor */
	termio_attr_val_t ti_cnorm;	/* Make cursor appear normal */
	termio_attr_val_t ti_nel;	/* Newline */
	termio_attr_val_t ti_cr;	/* Carriage return */
} termio_info_t;

typedef enum {
	TIO_ATTR_REQSTR,		/* String attribute that is required */
	TIO_ATTR_STR,			/* String attribute */
	TIO_ATTR_BOOL,			/* Boolean attribute */
	TIO_ATTR_INT			/* Integer attribute */
} termio_attr_type_t;

typedef struct termio_attr {
	const char *ta_name;		/* Capability name */
	termio_attr_type_t ta_type;	/* Capability type */
	termio_attr_val_t *ta_valp;	/* String pointer location */
} termio_attr_t;

struct termio_data;
typedef const char *(*keycb_t)(struct termio_data *, int);
typedef void (*putp_t)(struct termio_data *, const char *, uint_t);

#define	TIO_FINDHIST	0x01		/* Find-history-mode */
#define	TIO_AUTOWRAP	0x02		/* Terminal has autowrap */
#define	TIO_BACKLEFT	0x04		/* Terminal can go back at left edge */
#define	TIO_INSERT	0x08		/* Terminal has insert mode */
#define	TIO_USECUP	0x10		/* Use smcup/rmcup sequences */
#define	TIO_TTYWARN	0x20		/* Warnings about tty issued */
#define	TIO_CAPWARN	0x40		/* Warnings about terminfo issued */
#define	TIO_XTERM	0x80		/* Terminal is xterm compatible */
#define	TIO_TAB		0x100		/* Tab completion mode */

static const mdb_bitmask_t tio_flag_masks[] = {
	{ "FINDHIST", TIO_FINDHIST, TIO_FINDHIST },
	{ "AUTOWRAP", TIO_AUTOWRAP, TIO_AUTOWRAP },
	{ "BACKLEFT", TIO_BACKLEFT, TIO_BACKLEFT },
	{ "INSERT", TIO_INSERT, TIO_INSERT },
	{ "USECUP", TIO_USECUP, TIO_USECUP },
	{ "TTYWARN", TIO_TTYWARN, TIO_TTYWARN },
	{ "CAPWARN", TIO_CAPWARN, TIO_CAPWARN },
	{ "XTERM", TIO_XTERM, TIO_XTERM },
	{ "TAB", TIO_TAB, TIO_TAB},
	{ NULL, 0, 0 }
};

typedef struct termio_data {
	mdb_io_t *tio_io;		/* Pointer back to containing i/o */
	mdb_io_t *tio_out_io;		/* Terminal output backend */
	mdb_io_t *tio_in_io;		/* Terminal input backend */
	mdb_iob_t *tio_out;		/* I/o buffer for terminal output */
	mdb_iob_t *tio_in;		/* I/o buffer for terminal input */
	mdb_iob_t *tio_link;		/* I/o buffer to resize on WINCH */
	keycb_t tio_keymap[KEY_MAX];	/* Keymap (see comments atop file) */
	mdb_cmdbuf_t tio_cmdbuf;	/* Editable command-line buffer */
	struct termios tio_ptios;	/* Parent terminal settings */
	struct termios tio_ctios;	/* Child terminal settings */
	struct termios tio_rtios;	/* Settings for read loop */
	struct termios tio_dtios;	/* Settings for dcmd execution */
	sigjmp_buf tio_env;		/* Read loop setjmp(3c) environment */
	termio_info_t tio_info;		/* Terminal attribute strings */
	char *tio_attrs;		/* Attribute string buffer */
	size_t tio_attrslen;		/* Length in bytes of tio_attrs */
	const char *tio_prompt;		/* Prompt string for this read */
	size_t tio_promptlen;		/* Length of prompt string */
	size_t tio_rows;		/* Terminal height */
	size_t tio_cols;		/* Terminal width */
	size_t tio_x;			/* Cursor x coordinate */
	size_t tio_y;			/* Cursor y coordinate */
	size_t tio_max_x;		/* Previous maximum x coordinate */
	size_t tio_max_y;		/* Previous maximum y coordinate */
	int tio_intr;			/* Interrupt char */
	int tio_quit;			/* Quit char */
	int tio_erase;			/* Erase char */
	int tio_werase;			/* Word-erase char */
	int tio_kill;			/* Kill char */
	int tio_eof;			/* End-of-file char */
	int tio_susp;			/* Suspend char */
	uint_t tio_flags;		/* Miscellaneous flags */
	volatile mdb_bool_t tio_active;	/* Flag denoting read loop active */
	volatile mdb_bool_t tio_rti_on;	/* Flag denoting rtios in use */
	putp_t tio_putp;		/* termio_tput() subroutine */
	uint_t tio_baud;		/* Baud rate (chars per second) */
	uint_t tio_usecpc;		/* Usecs per char at given baud rate */
	pid_t tio_opgid;		/* Old process group id for terminal */
	uint_t tio_suspended;		/* termio_suspend_tty() nesting count */
} termio_data_t;

static ssize_t termio_read(mdb_io_t *, void *, size_t);
static ssize_t termio_write(mdb_io_t *, const void *, size_t);
static off64_t termio_seek(mdb_io_t *, off64_t, int);
static int termio_ctl(mdb_io_t *, int, void *);
static void termio_close(mdb_io_t *);
static const char *termio_name(mdb_io_t *);
static void termio_link(mdb_io_t *, mdb_iob_t *);
static void termio_unlink(mdb_io_t *, mdb_iob_t *);
static int termio_setattr(mdb_io_t *, int, uint_t);
static void termio_suspend(mdb_io_t *);
static void termio_resume(mdb_io_t *);

static void termio_suspend_tty(termio_data_t *, struct termios *);
static void termio_resume_tty(termio_data_t *, struct termios *);

static void termio_putp(termio_data_t *, const char *, uint_t);
static void termio_puts(termio_data_t *, const char *, uint_t);
static void termio_tput(termio_data_t *, const char *, uint_t);
static void termio_addch(termio_data_t *, char, size_t);
static void termio_insch(termio_data_t *, char, size_t);
static void termio_mvcur(termio_data_t *);
static void termio_bspch(termio_data_t *);
static void termio_delch(termio_data_t *);
static void termio_clear(termio_data_t *);
static void termio_redraw(termio_data_t *);
static void termio_prompt(termio_data_t *);

static const char *termio_tab(termio_data_t *, int);
static const char *termio_insert(termio_data_t *, int);
static const char *termio_accept(termio_data_t *, int);
static const char *termio_backspace(termio_data_t *, int);
static const char *termio_delchar(termio_data_t *, int);
static const char *termio_fwdchar(termio_data_t *, int);
static const char *termio_backchar(termio_data_t *, int);
static const char *termio_transpose(termio_data_t *, int);
static const char *termio_home(termio_data_t *, int);
static const char *termio_end(termio_data_t *, int);
static const char *termio_fwdword(termio_data_t *, int);
static const char *termio_backword(termio_data_t *, int);
static const char *termio_kill(termio_data_t *, int);
static const char *termio_killfwdword(termio_data_t *, int);
static const char *termio_killbackword(termio_data_t *, int);
static const char *termio_reset(termio_data_t *, int);
static const char *termio_widescreen(termio_data_t *, int);
static const char *termio_prevhist(termio_data_t *, int);
static const char *termio_nexthist(termio_data_t *, int);
static const char *termio_accel(termio_data_t *, int);
static const char *termio_findhist(termio_data_t *, int);
static const char *termio_refresh(termio_data_t *, int);

static const char *termio_intr(termio_data_t *, int);
static const char *termio_quit(termio_data_t *, int);
static const char *termio_susp(termio_data_t *, int);

static void termio_winch(int, siginfo_t *, ucontext_t *, void *);
static void termio_tstp(int, siginfo_t *, ucontext_t *, void *);

extern const char *tigetstr(const char *);
extern int tigetflag(const char *);
extern int tigetnum(const char *);

static const mdb_io_ops_t termio_ops = {
	termio_read,
	termio_write,
	termio_seek,
	termio_ctl,
	termio_close,
	termio_name,
	termio_link,
	termio_unlink,
	termio_setattr,
	termio_suspend,
	termio_resume
};

static termio_info_t termio_info;

static const termio_attr_t termio_attrs[] = {
	{ "cub1", TIO_ATTR_REQSTR, &termio_info.ti_cub1 },
	{ "cuf1", TIO_ATTR_REQSTR, &termio_info.ti_cuf1 },
	{ "cuu1", TIO_ATTR_REQSTR, &termio_info.ti_cuu1 },
	{ "cud1", TIO_ATTR_REQSTR, &termio_info.ti_cud1 },
	{ "pad", TIO_ATTR_STR, &termio_info.ti_pad },
	{ "el", TIO_ATTR_REQSTR, &termio_info.ti_el },
	{ "am", TIO_ATTR_BOOL, &termio_info.ti_am },
	{ "bw", TIO_ATTR_BOOL, &termio_info.ti_bw },
	{ "npc", TIO_ATTR_BOOL, &termio_info.ti_npc },
	{ "xenl", TIO_ATTR_BOOL, &termio_info.ti_xenl },
	{ "xon", TIO_ATTR_BOOL, &termio_info.ti_xon },
	{ "cols", TIO_ATTR_INT, &termio_info.ti_cols },
	{ "lines", TIO_ATTR_INT, &termio_info.ti_lines },
	{ "pb", TIO_ATTR_INT, &termio_info.ti_pb },
	{ "smso", TIO_ATTR_STR, &termio_info.ti_smso },
	{ "rmso", TIO_ATTR_STR, &termio_info.ti_rmso },
	{ "smul", TIO_ATTR_STR, &termio_info.ti_smul },
	{ "rmul", TIO_ATTR_STR, &termio_info.ti_rmul },
	{ "enacs", TIO_ATTR_STR, &termio_info.ti_enacs },
	{ "smacs", TIO_ATTR_STR, &termio_info.ti_smacs },
	{ "rmacs", TIO_ATTR_STR, &termio_info.ti_rmacs },
	{ "smcup", TIO_ATTR_STR, &termio_info.ti_smcup },
	{ "rmcup", TIO_ATTR_STR, &termio_info.ti_rmcup },
	{ "rev", TIO_ATTR_STR, &termio_info.ti_rev },
	{ "bold", TIO_ATTR_STR, &termio_info.ti_bold },
	{ "dim", TIO_ATTR_STR, &termio_info.ti_dim },
	{ "sgr0", TIO_ATTR_STR, &termio_info.ti_sgr0 },
	{ "smir", TIO_ATTR_STR, &termio_info.ti_smir },
	{ "rmir", TIO_ATTR_STR, &termio_info.ti_rmir },
	{ "ich1", TIO_ATTR_STR, &termio_info.ti_ich1 },
	{ "ip", TIO_ATTR_STR, &termio_info.ti_ip },
	{ "clear", TIO_ATTR_STR, &termio_info.ti_clear },
	{ "cnorm", TIO_ATTR_STR, &termio_info.ti_cnorm },
	{ "nel", TIO_ATTR_STR, &termio_info.ti_nel },
	{ "cr", TIO_ATTR_STR, &termio_info.ti_cr },
	{ NULL, NULL, NULL }
};

/*
 * One-key accelerators.  Some commands are used so frequently as to need
 * single-key equivalents.  termio_accelkeys contains a list of the accelerator
 * keys, with termio_accel listing the accelerated commands.  The array is
 * indexed by the offset of the accelerator in the macro string, and as such
 * *must* stay in the same order.
 */
static const char *const termio_accelkeys = "[]";

static const char *const termio_accelstrings[] = {
	"::step over",	/* [ */
	"::step"	/* ] */
};

static const char *
termio_accel_lookup(int c)
{
	const char *acc;

	if ((acc = strchr(termio_accelkeys, c)) == NULL)
		return (NULL);

	return (termio_accelstrings[(int)(acc - termio_accelkeys)]);
}

static ssize_t
termio_read(mdb_io_t *io, void *buf, size_t nbytes)
{
	termio_data_t *td = io->io_data;

	mdb_bool_t esc = FALSE, pad = FALSE;
	ssize_t rlen = 0;
	int c, fkey = 0;

	const char *s;
	size_t len;

	if (io->io_next != NULL)
		return (IOP_READ(io->io_next, buf, nbytes));

	td->tio_rti_on = TRUE;
	if (termio_ctl(td->tio_io, TCSETSW, &td->tio_rtios) == -1)
		warn("failed to set terminal attributes");

	if (nbytes == 1) {
		if ((c = mdb_iob_getc(td->tio_in)) == EOF)
			goto out;

		*((uchar_t *)buf) = (uchar_t)c;

		rlen = 1;
		goto out;
	}

	if (td->tio_flags & TIO_TAB)
		termio_redraw(td);
	else
		termio_prompt(td);

	/*
	 * We need to redraw the entire command-line and restart our read loop
	 * in the event of a SIGWINCH or resume following SIGTSTP (SIGCONT).
	 */
	if (sigsetjmp(td->tio_env, 1) != 0) {
		td->tio_active = FALSE;
		td->tio_x = td->tio_y = 0;

		len = td->tio_cmdbuf.cmd_buflen + td->tio_promptlen;
		td->tio_max_x = len % td->tio_cols;
		td->tio_max_y = len / td->tio_cols;

		esc = pad = FALSE;

		termio_tput(td, td->tio_info.ti_cr.at_str, 1);
		mdb_iob_flush(td->tio_out);
		termio_redraw(td);
	}

	/*
	 * Since we're about to start the read loop, we know our linked iob
	 * is quiescent. We can now safely resize it to the latest term size.
	 */
	if (td->tio_link != NULL)
		mdb_iob_resize(td->tio_link, td->tio_rows, td->tio_cols);

	td->tio_active = TRUE;

	/*
	 * We may have had some error while in tab completion mode which sent us
	 * longjmping all over the place. If that's the case, come back here and
	 * make sure the flag is off.
	 */
	td->tio_flags &= ~TIO_TAB;

	do {
char_loop:
		if ((c = mdb_iob_getc(td->tio_in)) == EOF) {
			td->tio_active = FALSE;
			goto out;
		}

		if (c == KEY_ESC && esc == FALSE) {
			esc = TRUE;
			goto char_loop;
		}

		if (esc) {
			esc = FALSE;

			if (c == '[') {
				pad++;
				goto char_loop;
			}

			c = META(c);
		}

		if (pad) {
			pad = FALSE;

			if ((fkey = FKEY(c)) != 0) {
				/*
				 * Some terminals send a multibyte control
				 * sequence for particular function keys.
				 * These sequences are of the form:
				 *
				 *	ESC [ n ~
				 *
				 * where "n" is a numeric character from
				 * '0' to '9'.
				 */
				goto char_loop;
			}

			if ((c = KPAD(c)) == 0) {
				/*
				 * This was not a valid keypad control
				 * sequence.
				 */
				goto char_loop;
			}
		}

		if (fkey != 0) {
			if (c == '~') {
				/*
				 * This is a valid special function key
				 * sequence.  Use the value we stashed
				 * earlier.
				 */
				c = fkey;
			}

			fkey = 0;
		}

		len = td->tio_cmdbuf.cmd_buflen + td->tio_promptlen;

		td->tio_max_x = len % td->tio_cols;
		td->tio_max_y = len / td->tio_cols;

	} while ((s = (*td->tio_keymap[c])(td, c)) == NULL);

	td->tio_active = FALSE;
	mdb_iob_nl(td->tio_out);

	if ((rlen = strlen(s)) >= nbytes - 1)
		rlen = nbytes - 1;

	(void) strncpy(buf, s, rlen);
	((char *)buf)[rlen++] = '\n';

out:
	td->tio_rti_on = FALSE;
	if (termio_ctl(td->tio_io, TCSETSW, &td->tio_dtios) == -1)
		warn("failed to restore terminal attributes");

	return (rlen);
}

static ssize_t
termio_write(mdb_io_t *io, const void *buf, size_t nbytes)
{
	termio_data_t *td = io->io_data;

	if (io->io_next != NULL)
		return (IOP_WRITE(io->io_next, buf, nbytes));

	return (IOP_WRITE(td->tio_out_io, buf, nbytes));
}

/*ARGSUSED*/
static off64_t
termio_seek(mdb_io_t *io, off64_t offset, int whence)
{
	return (set_errno(ENOTSUP));
}

static int
termio_ctl(mdb_io_t *io, int req, void *arg)
{
	termio_data_t *td = io->io_data;

	if (io->io_next != NULL)
		return (IOP_CTL(io->io_next, req, arg));

	if (req == MDB_IOC_CTTY) {
		bcopy(&td->tio_ptios, &td->tio_ctios, sizeof (struct termios));
		return (0);
	}

	return (IOP_CTL(td->tio_in_io, req, arg));
}

static void
termio_close(mdb_io_t *io)
{
	termio_data_t *td = io->io_data;

	(void) mdb_signal_sethandler(SIGWINCH, SIG_DFL, NULL);
	(void) mdb_signal_sethandler(SIGTSTP, SIG_DFL, NULL);

	termio_suspend_tty(td, &td->tio_ptios);

	if (td->tio_attrs)
		mdb_free(td->tio_attrs, td->tio_attrslen);

	mdb_cmdbuf_destroy(&td->tio_cmdbuf);

	mdb_iob_destroy(td->tio_out);
	mdb_iob_destroy(td->tio_in);

	mdb_free(td, sizeof (termio_data_t));
}

static const char *
termio_name(mdb_io_t *io)
{
	termio_data_t *td = io->io_data;

	if (io->io_next != NULL)
		return (IOP_NAME(io->io_next));

	return (IOP_NAME(td->tio_in_io));
}

static void
termio_link(mdb_io_t *io, mdb_iob_t *iob)
{
	termio_data_t *td = io->io_data;

	if (io->io_next == NULL) {
		mdb_iob_resize(iob, td->tio_rows, td->tio_cols);
		td->tio_link = iob;
	} else
		IOP_LINK(io->io_next, iob);
}

static void
termio_unlink(mdb_io_t *io, mdb_iob_t *iob)
{
	termio_data_t *td = io->io_data;

	if (io->io_next == NULL) {
		if (td->tio_link == iob)
			td->tio_link = NULL;
	} else
		IOP_UNLINK(io->io_next, iob);
}

static int
termio_setattr(mdb_io_t *io, int req, uint_t attrs)
{
	termio_data_t *td = io->io_data;

	if (io->io_next != NULL)
		return (IOP_SETATTR(io->io_next, req, attrs));

	if ((req != ATT_ON && req != ATT_OFF) || (attrs & ~ATT_ALL) != 0)
		return (set_errno(EINVAL));

	if (req == ATT_ON) {
		if (attrs & ATT_STANDOUT)
			termio_tput(td, td->tio_info.ti_smso.at_str, 1);
		if (attrs & ATT_UNDERLINE)
			termio_tput(td, td->tio_info.ti_smul.at_str, 1);
		if (attrs & ATT_REVERSE)
			termio_tput(td, td->tio_info.ti_rev.at_str, 1);
		if (attrs & ATT_BOLD)
			termio_tput(td, td->tio_info.ti_bold.at_str, 1);
		if (attrs & ATT_DIM)
			termio_tput(td, td->tio_info.ti_dim.at_str, 1);
		if (attrs & ATT_ALTCHARSET)
			termio_tput(td, td->tio_info.ti_smacs.at_str, 1);
	} else {
		if (attrs & ATT_STANDOUT)
			termio_tput(td, td->tio_info.ti_rmso.at_str, 1);
		if (attrs & ATT_UNDERLINE)
			termio_tput(td, td->tio_info.ti_rmul.at_str, 1);
		if (attrs & ATT_ALTCHARSET)
			termio_tput(td, td->tio_info.ti_rmacs.at_str, 1);
		if (attrs & (ATT_REVERSE | ATT_BOLD | ATT_DIM))
			termio_tput(td, td->tio_info.ti_sgr0.at_str, 1);
	}

	mdb_iob_flush(td->tio_out);
	return (0);
}

/*
 * Issue a warning message if the given warning flag is clear.  Then set the
 * flag bit so that we do not issue multiple instances of the same warning.
 */
static void
termio_warn(termio_data_t *td, uint_t flag, const char *format, ...)
{
	if (!(td->tio_flags & flag)) {
		va_list alist;

		va_start(alist, format);
		vwarn(format, alist);
		va_end(alist);

		td->tio_flags |= flag;
	}
}

/*
 * Restore the terminal to its previous state before relinquishing control of
 * it to the shell (on a SIGTSTP) or the victim process (on a continue).  If
 * we need to change the foreground process group, we must temporarily ignore
 * SIGTTOU because TIOCSPGRP could trigger it.
 */
static void
termio_suspend_tty(termio_data_t *td, struct termios *iosp)
{
	if (td->tio_suspended++ != 0)
		return; /* already suspended; do not restore state */

	if (td->tio_flags & TIO_XTERM)
		termio_tput(td, TI_DECRES(TI_COLENAB), 1);

	if (td->tio_flags & TIO_USECUP)
		termio_tput(td, td->tio_info.ti_rmcup.at_str, 1);

	termio_tput(td, td->tio_info.ti_sgr0.at_str, 1);
	mdb_iob_flush(td->tio_out);

	if (termio_ctl(td->tio_io, TCSETSW, iosp) == -1)
		warn("failed to restore terminal attributes");

	if (td->tio_opgid > 0 && td->tio_opgid != mdb.m_pgid) {
		mdb_dprintf(MDB_DBG_CMDBUF, "fg pgid=%d\n", (int)td->tio_opgid);
		(void) mdb_signal_sethandler(SIGTTOU, SIG_IGN, NULL);
		(void) termio_ctl(td->tio_io, TIOCSPGRP, &td->tio_opgid);
		(void) mdb_signal_sethandler(SIGTTOU, SIG_DFL, NULL);
	}
}

/*
 * Resume the debugger's terminal state.  We first save the existing terminal
 * state so we can restore it later, and then install our own state.  We
 * derive our state dynamically from the existing terminal state so that we
 * always reflect the latest modifications made by the user with stty(1).
 */
static void
termio_resume_tty(termio_data_t *td, struct termios *iosp)
{
	/*
	 * We use this table of bauds to convert the baud constant returned by
	 * the terminal code to a baud rate in characters per second.  The
	 * values are in the order of the B* speed defines in <sys/termios.h>.
	 * We then compute tio_usecpc (microseconds-per-char) in order to
	 * determine how many pad characters need to be issued at the current
	 * terminal speed to delay for a given number of microseconds.  For
	 * example, at 300 baud (B300 = 7), we look up baud[7] = 300, and then
	 * compute usecpc as MICROSEC / 300 = 3333 microseconds per character.
	 */
	static const uint_t baud[] = {
		0, 50, 75, 110, 134, 150, 200, 300, 600, 1200,
		1800, 2400, 4800, 9600, 19200, 38400, 57600,
		76800, 115200, 153600, 230400, 307200, 460800, 921600
	};

	struct termios *ntios;
	struct winsize winsz;
	uint_t speed;

	if (td->tio_suspended == 0)
		fail("termio_resume called without matching termio_suspend\n");

	if (--td->tio_suspended != 0)
		return; /* nested suspends; do not resume yet */

	td->tio_opgid = -1; /* set to invalid pgid in case TIOCPGRP fails */
	(void) termio_ctl(td->tio_io, TIOCGPGRP, &td->tio_opgid);

	/*
	 * If the foreground process group does not include the debugger, reset
	 * the foreground process group so we are in control of the terminal.
	 * We temporarily ignore TTOU because TIOCSPGRP could trigger it.
	 */
	if (td->tio_opgid != mdb.m_pgid) {
		(void) mdb_signal_sethandler(SIGTTOU, SIG_IGN, NULL);
		(void) termio_ctl(td->tio_io, TIOCSPGRP, &mdb.m_pgid);
		(void) mdb_signal_sethandler(SIGTTOU, SIG_DFL, NULL);
		mdb_dprintf(MDB_DBG_CMDBUF, "fg pgid=%d\n", (int)mdb.m_pgid);
	}

	/*
	 * Read the current set of terminal attributes, and save them in iosp
	 * so we can restore them later.  Then derive rtios, dtios, and winsz.
	 */
	if (termio_ctl(td->tio_io, TCGETS, iosp) < 0)
		warn("failed to get terminal attributes");

	if (termio_ctl(td->tio_io, TIOCGWINSZ, &winsz) == 0) {
		if (winsz.ws_row != 0)
			td->tio_rows = (size_t)winsz.ws_row;
		if (winsz.ws_col != 0)
			td->tio_cols = (size_t)winsz.ws_col;
	}

	mdb_iob_resize(td->tio_out, td->tio_rows, td->tio_cols);

	td->tio_intr = td->tio_ptios.c_cc[VINTR];
	td->tio_quit = td->tio_ptios.c_cc[VQUIT];
	td->tio_erase = td->tio_ptios.c_cc[VERASE];
	td->tio_werase = td->tio_ptios.c_cc[VWERASE];
	td->tio_kill = td->tio_ptios.c_cc[VKILL];
	td->tio_eof = td->tio_ptios.c_cc[VEOF];
	td->tio_susp = td->tio_ptios.c_cc[VSUSP];

	bcopy(&td->tio_ptios, &td->tio_rtios, sizeof (struct termios));
	td->tio_rtios.c_iflag &= ~(ISTRIP | INPCK | ICRNL | INLCR | IUCLC);
	td->tio_rtios.c_oflag &= ~(OCRNL | ONLRET);
	td->tio_rtios.c_oflag |= ONLCR;
	td->tio_rtios.c_lflag &= ~(ISIG | ICANON | ECHO);
	td->tio_rtios.c_cflag |= CS8;
	td->tio_rtios.c_cc[VTIME] = 0;
	td->tio_rtios.c_cc[VMIN] = 1;

	bcopy(&td->tio_ptios, &td->tio_dtios, sizeof (struct termios));
	td->tio_dtios.c_oflag &= ~(OCRNL | ONLRET);
	td->tio_dtios.c_oflag |= ONLCR;
	td->tio_dtios.c_lflag |= ISIG | ICANON | ECHO;

	/*
	 * Select the appropriate modified settings to restore based on our
	 * current state, and then install them.
	 */
	if (td->tio_rti_on)
		ntios = &td->tio_rtios;
	else
		ntios = &td->tio_dtios;

	if (termio_ctl(td->tio_io, TCSETSW, ntios) < 0)
		warn("failed to reset terminal attributes");

	/*
	 * Compute the terminal speed as described in termio(7I), and then
	 * look up the corresponding microseconds-per-char in our table.
	 */
	if (ntios->c_cflag & CBAUDEXT)
		speed = (ntios->c_cflag & CBAUD) + CBAUD + 1;
	else
		speed = (ntios->c_cflag & CBAUD);

	if (speed >= sizeof (baud) / sizeof (baud[0])) {
		termio_warn(td, TIO_TTYWARN, "invalid speed %u -- assuming "
		    "9600 baud\n", speed);
		speed = B9600;
	}

	td->tio_baud = baud[speed];
	td->tio_usecpc = MICROSEC / td->tio_baud;

	mdb_dprintf(MDB_DBG_CMDBUF, "speed = %u baud (%u usec / char), "
	    "putp = %s\n", td->tio_baud, td->tio_usecpc,
	    td->tio_putp == &termio_puts ? "fast" : "slow");

	/*
	 * Send the necessary terminal initialization sequences to enable
	 * enable cursor positioning.  Clear the screen afterward if possible.
	 */
	if (td->tio_flags & TIO_USECUP) {
		termio_tput(td, td->tio_info.ti_smcup.at_str, 1);
		if (td->tio_info.ti_clear.at_str) {
			termio_tput(td, td->tio_info.ti_clear.at_str, 1);
			td->tio_x = td->tio_y = 0;
		}
	}

	/*
	 * If the terminal is xterm-compatible, enable column mode switching.
	 * Save the previous value in the terminal so we can restore it.
	 */
	if (td->tio_flags & TIO_XTERM) {
		termio_tput(td, TI_DECSAV(TI_COLENAB), 1);
		termio_tput(td, TI_DECSET(TI_COLENAB), 1);
	}

	termio_tput(td, td->tio_info.ti_cnorm.at_str, 1); /* cursor visible */
	termio_tput(td, td->tio_info.ti_enacs.at_str, 1); /* alt char set */

	mdb_iob_flush(td->tio_out);
}

static void
termio_suspend(mdb_io_t *io)
{
	termio_data_t *td = io->io_data;
	termio_suspend_tty(td, &td->tio_ctios);
}

static void
termio_resume(mdb_io_t *io)
{
	termio_data_t *td = io->io_data;
	termio_resume_tty(td, &td->tio_ctios);
}

/*
 * Delay for the specified number of microseconds by sending the pad character
 * to the terminal.  We round up by half a frame and then divide by the usecs
 * per character to determine the number of pad characters to send.
 */
static void
termio_delay(termio_data_t *td, uint_t usec)
{
	char pad = td->tio_info.ti_pad.at_str[0];
	uint_t usecpc = td->tio_usecpc;

	for (usec = (usec + usecpc / 2) / usecpc; usec != 0; usec--) {
		mdb_iob_putc(td->tio_out, pad);
		mdb_iob_flush(td->tio_out);
	}
}

/*
 * Parse the terminfo(4) padding sequence "$<...>" and delay for the specified
 * amount of time by sending pad characters to the terminal.
 */
static const char *
termio_pad(termio_data_t *td, const char *s, uint_t lines)
{
	int xon = td->tio_info.ti_xon.at_val;
	int pb = td->tio_info.ti_pb.at_val;

	const char *p = s;
	uint_t usec = 0;

	/*
	 * The initial string is a number of milliseconds, followed by an
	 * optional decimal point and number of tenths of milliseconds.
	 * We convert this to microseconds for greater accuracy.  Only a single
	 * digit is permitted after the decimal point; we ignore any others.
	 */
	while (*p >= '0' && *p <= '9')
		usec = usec * 10 + *p++ - '0';

	usec *= 1000; /* convert msecs to usecs */

	if (*p == '.') {
		if (p[1] >= '0' && p[1] <= '9')
			usec += (p[1] - '0') * 100;
		for (p++; *p >= '0' && *p <= '9'; p++)
			continue;
	}

	/*
	 * Following the time delay specifier,
	 *
	 * 1. An optional "/" indicates that the delay should be done
	 *    regardless of the value of the terminal's xon property,
	 * 2. An optional "*" indicates that the delay is proportional to the
	 *    count of affected lines, and
	 * 3. A mandatory ">" terminates the sequence.
	 *
	 * If we encounter any other characters, we assume that we found "$<"
	 * accidentally embedded in another sequence, so we just output "$".
	 */
	for (;;) {
		switch (*p++) {
		case '/':
			xon = FALSE;
			continue;
		case '*':
			usec *= lines;
			continue;
		case '>':
			if (xon == FALSE && usec != 0 && td->tio_baud >= pb)
				termio_delay(td, usec);
			return (p);
		default:
			mdb_iob_putc(td->tio_out, *s);
			return (s + 1);
		}
	}
}

/*
 * termio_tput() subroutine for terminals that require padding.  We look ahead
 * for "$<>" sequences, and call termio_pad() to process them; all other chars
 * are output directly to the underlying device and then flushed at the end.
 */
static void
termio_putp(termio_data_t *td, const char *s, uint_t lines)
{
	while (s[0] != '\0') {
		if (s[0] == '$' && s[1] == '<')
			s = termio_pad(td, s + 2, lines);
		else
			mdb_iob_putc(td->tio_out, *s++);
	}

	mdb_iob_flush(td->tio_out);
}

/*
 * termio_tput() subroutine for terminals that do not require padding.  We
 * simply output the string to the underlying i/o buffer; we let the caller
 * take care of flushing so that multiple sequences can be concatenated.
 */
/*ARGSUSED*/
static void
termio_puts(termio_data_t *td, const char *s, uint_t lines)
{
	mdb_iob_puts(td->tio_out, s);
}

/*
 * Print a padded escape sequence string to the terminal.  The caller specifies
 * the string 's' and a count of the affected lines.  If the string contains an
 * embedded delay sequence delimited by "$<>" (see terminfo(4)), appropriate
 * padding will be included in the output.  We determine whether or not padding
 * is required during initialization, and set tio_putp to the proper subroutine.
 */
static void
termio_tput(termio_data_t *td, const char *s, uint_t lines)
{
	if (s != NULL)
		td->tio_putp(td, s, lines);
}

static void
termio_addch(termio_data_t *td, char c, size_t width)
{
	if (width == 1) {
		mdb_iob_putc(td->tio_out, c);
		td->tio_x++;

		if (td->tio_x >= td->tio_cols) {
			if (!(td->tio_flags & TIO_AUTOWRAP))
				termio_tput(td, td->tio_info.ti_nel.at_str, 1);
			td->tio_x = 0;
			td->tio_y++;
		}

		mdb_iob_flush(td->tio_out);
	} else
		termio_redraw(td);
}

static void
termio_insch(termio_data_t *td, char c, size_t width)
{
	if (width == 1 && (td->tio_flags & TIO_INSERT) &&
	    td->tio_y == td->tio_max_y) {

		termio_tput(td, td->tio_info.ti_smir.at_str, 1);
		termio_tput(td, td->tio_info.ti_ich1.at_str, 1);

		mdb_iob_putc(td->tio_out, c);
		td->tio_x++;

		termio_tput(td, td->tio_info.ti_ip.at_str, 1);
		termio_tput(td, td->tio_info.ti_rmir.at_str, 1);

		if (td->tio_x >= td->tio_cols) {
			if (!(td->tio_flags & TIO_AUTOWRAP))
				termio_tput(td, td->tio_info.ti_nel.at_str, 1);
			td->tio_x = 0;
			td->tio_y++;
		}

		mdb_iob_flush(td->tio_out);
	} else
		termio_redraw(td);
}

static void
termio_mvcur(termio_data_t *td)
{
	size_t tipos = td->tio_cmdbuf.cmd_bufidx + td->tio_promptlen;
	size_t dst_x = tipos % td->tio_cols;
	size_t dst_y = tipos / td->tio_cols;

	const char *str;
	size_t cnt, i;

	if (td->tio_y != dst_y) {
		if (td->tio_y < dst_y) {
			str = td->tio_info.ti_cud1.at_str;
			cnt = dst_y - td->tio_y;
			td->tio_x = 0; /* Note: cud1 moves cursor to column 0 */
		} else {
			str = td->tio_info.ti_cuu1.at_str;
			cnt = td->tio_y - dst_y;
		}

		for (i = 0; i < cnt; i++)
			termio_tput(td, str, 1);

		mdb_iob_flush(td->tio_out);
		td->tio_y = dst_y;
	}

	if (td->tio_x != dst_x) {
		if (td->tio_x < dst_x) {
			str = td->tio_info.ti_cuf1.at_str;
			cnt = dst_x - td->tio_x;
		} else {
			str = td->tio_info.ti_cub1.at_str;
			cnt = td->tio_x - dst_x;
		}

		for (i = 0; i < cnt; i++)
			termio_tput(td, str, 1);

		mdb_iob_flush(td->tio_out);
		td->tio_x = dst_x;
	}
}

static void
termio_backleft(termio_data_t *td)
{
	size_t i;

	if (td->tio_flags & TIO_BACKLEFT)
		termio_tput(td, td->tio_info.ti_cub1.at_str, 1);
	else {
		termio_tput(td, td->tio_info.ti_cuu1.at_str, 1);
		for (i = 0; i < td->tio_cols - 1; i++)
			termio_tput(td, td->tio_info.ti_cuf1.at_str, 1);
	}
}

static void
termio_bspch(termio_data_t *td)
{
	if (td->tio_x == 0) {
		termio_backleft(td);
		td->tio_x = td->tio_cols - 1;
		td->tio_y--;
	} else {
		termio_tput(td, td->tio_info.ti_cub1.at_str, 1);
		td->tio_x--;
	}

	termio_delch(td);
}

static void
termio_delch(termio_data_t *td)
{
	mdb_iob_putc(td->tio_out, ' ');

	if (td->tio_x == td->tio_cols - 1 && (td->tio_flags & TIO_AUTOWRAP))
		termio_backleft(td);
	else
		termio_tput(td, td->tio_info.ti_cub1.at_str, 1);

	mdb_iob_flush(td->tio_out);
}

static void
termio_clear(termio_data_t *td)
{
	while (td->tio_x-- != 0)
		termio_tput(td, td->tio_info.ti_cub1.at_str, 1);

	while (td->tio_y < td->tio_max_y) {
		termio_tput(td, td->tio_info.ti_cud1.at_str, 1);
		td->tio_y++;
	}

	while (td->tio_y-- != 0) {
		termio_tput(td, td->tio_info.ti_el.at_str, 1);
		termio_tput(td, td->tio_info.ti_cuu1.at_str, 1);
	}

	termio_tput(td, td->tio_info.ti_el.at_str, 1);
	mdb_iob_flush(td->tio_out);

	termio_prompt(td);
}

static void
termio_redraw(termio_data_t *td)
{
	const char *buf = td->tio_cmdbuf.cmd_buf;
	size_t len = td->tio_cmdbuf.cmd_buflen;
	size_t pos, n;

	termio_clear(td);

	if (len == 0)
		return; /* if the buffer is empty, we're done */

	if (td->tio_flags & TIO_AUTOWRAP)
		mdb_iob_nputs(td->tio_out, buf, len);
	else {
		for (pos = td->tio_promptlen; len != 0; pos = 0) {
			n = MIN(td->tio_cols - pos, len);
			mdb_iob_nputs(td->tio_out, buf, n);
			buf += n;
			len -= n;

			if (pos + n == td->tio_cols)
				termio_tput(td, td->tio_info.ti_nel.at_str, 1);
		}
	}

	pos = td->tio_promptlen + td->tio_cmdbuf.cmd_buflen;
	td->tio_x = pos % td->tio_cols;
	td->tio_y = pos / td->tio_cols;

	mdb_iob_flush(td->tio_out);
	termio_mvcur(td);
}

static void
termio_prompt(termio_data_t *td)
{
	mdb_callb_fire(MDB_CALLB_PROMPT);

	/*
	 * Findhist (^R) overrides the displayed prompt.  We should only update
	 * the main prompt (which may have been changed by the callback) if
	 * findhist isn't active.
	 */
	if (!(td->tio_flags & TIO_FINDHIST)) {
		td->tio_prompt = mdb.m_prompt;
		td->tio_promptlen = mdb.m_promptlen;
	}

	mdb_iob_puts(td->tio_out, td->tio_prompt);
	mdb_iob_flush(td->tio_out);

	td->tio_x = td->tio_promptlen;
	td->tio_y = 0;
}

/*
 * For debugging purposes, iterate over the table of attributes and output them
 * in human readable form for verification.
 */
static void
termio_dump(termio_data_t *td, const termio_attr_t *ta)
{
	char *str;

	for (; ta->ta_name != NULL; ta++) {
		switch (ta->ta_type) {
		case TIO_ATTR_REQSTR:
		case TIO_ATTR_STR:
			if (ta->ta_valp->at_str != NULL) {
				str = strchr2esc(ta->ta_valp->at_str,
				    strlen(ta->ta_valp->at_str));
				mdb_dprintf(MDB_DBG_CMDBUF, "%s = \"%s\"\n",
				    ta->ta_name, str);
				strfree(str);
			} else {
				mdb_dprintf(MDB_DBG_CMDBUF, "%s = <NULL>\n",
				    ta->ta_name);
			}
			break;
		case TIO_ATTR_INT:
			mdb_dprintf(MDB_DBG_CMDBUF, "%s = %d\n",
			    ta->ta_name, ta->ta_valp->at_val);
			break;
		case TIO_ATTR_BOOL:
			mdb_dprintf(MDB_DBG_CMDBUF, "%s = %s\n", ta->ta_name,
			    ta->ta_valp->at_val ? "TRUE" : "FALSE");
			break;
		}
	}

	mdb_dprintf(MDB_DBG_CMDBUF, "tio_flags = <%#b>\n",
	    td->tio_flags, tio_flag_masks);
}

static int
termio_setup_attrs(termio_data_t *td, const char *name)
{
	const termio_attr_t *ta;
	const char *str;
	size_t nbytes;
	char *bufp;

	int need_padding = 0;
	int i;

	/*
	 * Load terminal attributes:
	 */
	for (nbytes = 0, ta = &termio_attrs[0]; ta->ta_name != NULL; ta++) {
		switch (ta->ta_type) {
		case TIO_ATTR_REQSTR:
		case TIO_ATTR_STR:
			str = tigetstr(ta->ta_name);

			if (str == (const char *)-1) {
				termio_warn(td, TIO_CAPWARN,
				    "terminal capability '%s' is not of type "
				    "string as expected\n", ta->ta_name);
				return (0);
			}

			if (str != NULL)
				nbytes += strlen(str) + 1;
			else if (ta->ta_type == TIO_ATTR_REQSTR) {
				termio_warn(td, TIO_CAPWARN,
				    "terminal capability '%s' is not "
				    "available\n", ta->ta_name);
				return (0);
			}
			break;

		case TIO_ATTR_BOOL:
			if (tigetflag(ta->ta_name) == -1) {
				termio_warn(td, TIO_CAPWARN,
				    "terminal capability '%s' is not of type "
				    "boolean as expected\n", ta->ta_name);
				return (0);
			}
			break;

		case TIO_ATTR_INT:
			if (tigetnum(ta->ta_name) == -2) {
				termio_warn(td, TIO_CAPWARN,
				    "terminal capability '%s' is not of type "
				    "integer as expected\n", ta->ta_name);
				return (0);
			}
			break;
		}
	}

	if (nbytes != 0)
		td->tio_attrs = mdb_alloc(nbytes, UM_SLEEP);
	else
		td->tio_attrs = NULL;

	td->tio_attrslen = nbytes;
	bufp = td->tio_attrs;

	/*
	 * Now make another pass through the terminal attributes and load the
	 * actual pointers into our static data structure:
	 */
	for (ta = &termio_attrs[0]; ta->ta_name != NULL; ta++) {
		switch (ta->ta_type) {
		case TIO_ATTR_REQSTR:
		case TIO_ATTR_STR:
			if ((str = tigetstr(ta->ta_name)) != NULL) {
				/*
				 * Copy the result string into our contiguous
				 * buffer, and store a pointer to it in at_str.
				 */
				(void) strcpy(bufp, str);
				ta->ta_valp->at_str = bufp;
				bufp += strlen(str) + 1;
				/*
				 * Check the string for a "$<>" pad sequence;
				 * if none are found, we can optimize later.
				 */
				if ((str = strstr(ta->ta_valp->at_str,
				    "$<")) != NULL && strchr(str, '>') != NULL)
					need_padding++;
			} else {
				ta->ta_valp->at_str = NULL;
			}
			break;

		case TIO_ATTR_BOOL:
			ta->ta_valp->at_val = tigetflag(ta->ta_name);
			break;

		case TIO_ATTR_INT:
			ta->ta_valp->at_val = tigetnum(ta->ta_name);
			break;
		}
	}

	/*
	 * Copy attribute pointers from temporary struct into td->tio_info:
	 */
	bcopy(&termio_info, &td->tio_info, sizeof (termio_info_t));

	/*
	 * Initialize the terminal size based on the terminfo database.  If it
	 * does not have the relevant properties, fall back to the environment
	 * settings or to a hardcoded default.  These settings will only be
	 * used if we subsequently fail to derive the size with TIOCGWINSZ.
	 */
	td->tio_rows = MAX(td->tio_info.ti_lines.at_val, 0);
	td->tio_cols = MAX(td->tio_info.ti_cols.at_val, 0);

	if (td->tio_rows == 0) {
		if ((str = getenv("LINES")) != NULL && strisnum(str) != 0 &&
		    (i = strtoi(str)) > 0)
			td->tio_rows = i;
		else
			td->tio_rows = TIO_DEFAULT_ROWS;
	}

	if (td->tio_cols == 0) {
		if ((str = getenv("COLUMNS")) != NULL && strisnum(str) != 0 &&
		    (i = strtoi(str)) > 0)
			td->tio_cols = i;
		else
			td->tio_cols = TIO_DEFAULT_COLS;
	}

	td->tio_flags = 0;

	if (td->tio_info.ti_am.at_val && !td->tio_info.ti_xenl.at_val)
		td->tio_flags |= TIO_AUTOWRAP;

	if (td->tio_info.ti_bw.at_val)
		td->tio_flags |= TIO_BACKLEFT;

	if (td->tio_info.ti_smir.at_str != NULL ||
	    td->tio_info.ti_ich1.at_str != NULL)
		td->tio_flags |= TIO_INSERT;

	if (mdb.m_flags & MDB_FL_USECUP)
		td->tio_flags |= TIO_USECUP;

	if (name != NULL && (strncmp(name, "xterm", 5) == 0 ||
	    strcmp(name, "dtterm") == 0))
		td->tio_flags |= TIO_XTERM;

	/*
	 * Optimizations for padding: (1) if no pad attribute is present, set
	 * its value to "\0" to avoid testing later; (2) if no pad sequences
	 * were found, force "npc" to TRUE so we pick the optimized tio_putp;
	 * (3) if the padding baud property is not present, reset it to zero
	 * since we need to compare it to an unsigned baud value.
	 */
	if (td->tio_info.ti_pad.at_str == NULL)
		td->tio_info.ti_pad.at_str = ""; /* \0 is the pad char */

	if (need_padding == 0)
		td->tio_info.ti_npc.at_val = TRUE;

	if (td->tio_info.ti_npc.at_val)
		td->tio_putp = &termio_puts;
	else
		td->tio_putp = &termio_putp;

	if (td->tio_info.ti_pb.at_val < 0)
		td->tio_info.ti_pb.at_val = 0;

	/*
	 * If no newline capability is available, assume \r\n will work.  If no
	 * carriage return capability is available, assume \r will work.
	 */
	if (td->tio_info.ti_nel.at_str == NULL)
		td->tio_info.ti_nel.at_str = "\r\n";
	if (td->tio_info.ti_cr.at_str == NULL)
		td->tio_info.ti_cr.at_str = "\r";

	return (1);
}

mdb_io_t *
mdb_termio_create(const char *name, mdb_io_t *rio, mdb_io_t *wio)
{
	struct termios otios;
	termio_data_t *td;
	int rv, err, i;

	td = mdb_zalloc(sizeof (termio_data_t), UM_SLEEP);
	td->tio_io = mdb_alloc(sizeof (mdb_io_t), UM_SLEEP);

	/*
	 * Save the original user settings before calling setupterm(), which
	 * cleverly changes them without telling us what it did or why.
	 */
	if (IOP_CTL(rio, TCGETS, &otios) == -1) {
		warn("failed to read terminal attributes for stdin");
		goto err;
	}

	rv = setupterm((char *)name, IOP_CTL(rio, MDB_IOC_GETFD, NULL), &err);
	IOP_CTL(rio, TCSETSW, &otios); /* undo setupterm() stupidity */

	if (rv == ERR) {
		if (err == 0)
			warn("no terminal data available for TERM=%s\n", name);
		else if (err == -1)
			warn("failed to locate terminfo database\n");
		else
			warn("failed to initialize terminal (err=%d)\n", err);
		goto err;
	}

	if (!termio_setup_attrs(td, name))
		goto err;

	/*
	 * Do not re-issue terminal capability warnings when mdb re-execs.
	 */
	if (mdb.m_flags & MDB_FL_EXEC)
		td->tio_flags |= TIO_TTYWARN | TIO_CAPWARN;

	/*
	 * Initialize i/o structures and command-line buffer:
	 */
	td->tio_io->io_ops = &termio_ops;
	td->tio_io->io_data = td;
	td->tio_io->io_next = NULL;
	td->tio_io->io_refcnt = 0;

	td->tio_in_io = rio;
	td->tio_in = mdb_iob_create(td->tio_in_io, MDB_IOB_RDONLY);

	td->tio_out_io = wio;
	td->tio_out = mdb_iob_create(td->tio_out_io, MDB_IOB_WRONLY);
	mdb_iob_clrflags(td->tio_out, MDB_IOB_AUTOWRAP);

	td->tio_link = NULL;
	mdb_cmdbuf_create(&td->tio_cmdbuf);

	/*
	 * Fill in all the keymap entries with the insert function:
	 */
	for (i = 0; i < KEY_MAX; i++)
		td->tio_keymap[i] = termio_insert;

	/*
	 * Now override selected entries with editing functions:
	 */
	td->tio_keymap['\n'] = termio_accept;
	td->tio_keymap['\r'] = termio_accept;

	td->tio_keymap[CTRL('f')] = termio_fwdchar;
	td->tio_keymap[CTRL('b')] = termio_backchar;
	td->tio_keymap[CTRL('t')] = termio_transpose;
	td->tio_keymap[CTRL('a')] = termio_home;
	td->tio_keymap[CTRL('e')] = termio_end;
	td->tio_keymap[META('f')] = termio_fwdword;
	td->tio_keymap[META('b')] = termio_backword;
	td->tio_keymap[META('d')] = termio_killfwdword;
	td->tio_keymap[META('\b')] = termio_killbackword;
	td->tio_keymap[CTRL('k')] = termio_kill;
	td->tio_keymap[CTRL('p')] = termio_prevhist;
	td->tio_keymap[CTRL('n')] = termio_nexthist;
	td->tio_keymap[CTRL('r')] = termio_findhist;
	td->tio_keymap[CTRL('l')] = termio_refresh;
	td->tio_keymap[CTRL('d')] = termio_delchar;
	td->tio_keymap[CTRL('?')] = termio_widescreen;

	td->tio_keymap[KPAD('A')] = termio_prevhist;
	td->tio_keymap[KPAD('B')] = termio_nexthist;
	td->tio_keymap[KPAD('C')] = termio_fwdchar;
	td->tio_keymap[KPAD('D')] = termio_backchar;

	/*
	 * Many modern terminal emulators treat the "Home" and "End" keys on a
	 * PC keyboard as cursor keys.  Some others use a multibyte function
	 * key control sequence.  We handle both styles here:
	 */
	td->tio_keymap[KPAD('H')] = termio_home;
	td->tio_keymap[FKEY('1')] = termio_home;
	td->tio_keymap[KPAD('F')] = termio_end;
	td->tio_keymap[FKEY('4')] = termio_end;

	/*
	 * We default both ASCII BS and DEL to termio_backspace for safety.  We
	 * want backspace to work whenever possible, regardless of whether or
	 * not we're able to ask the terminal for the specific character that
	 * it will use.  kmdb, for example, is not able to make this request,
	 * and must be prepared to accept both.
	 */
	td->tio_keymap[CTRL('h')] = termio_backspace;
	td->tio_keymap[KEY_DEL] = termio_backspace;

	/*
	 * Overrides for single-key accelerators
	 */
	td->tio_keymap['['] = termio_accel;
	td->tio_keymap[']'] = termio_accel;

	/*
	 * Grab tabs
	 */
	td->tio_keymap['\t'] = termio_tab;

	td->tio_x = 0;
	td->tio_y = 0;
	td->tio_max_x = 0;
	td->tio_max_y = 0;

	td->tio_active = FALSE;
	td->tio_rti_on = FALSE;
	td->tio_suspended = 1;

	/*
	 * Perform a resume operation to complete our terminal initialization,
	 * and then adjust the keymap according to the terminal settings.
	 */
	termio_resume_tty(td, &td->tio_ptios);
	bcopy(&td->tio_ptios, &td->tio_ctios, sizeof (struct termios));

	td->tio_keymap[td->tio_intr] = termio_intr;
	td->tio_keymap[td->tio_quit] = termio_quit;
	td->tio_keymap[td->tio_erase] = termio_backspace;
	td->tio_keymap[td->tio_werase] = termio_killbackword;
	td->tio_keymap[td->tio_kill] = termio_reset;
	td->tio_keymap[td->tio_susp] = termio_susp;

	(void) mdb_signal_sethandler(SIGWINCH, termio_winch, td);
	(void) mdb_signal_sethandler(SIGTSTP, termio_tstp, td);

	if (mdb.m_debug & MDB_DBG_CMDBUF)
		termio_dump(td, &termio_attrs[0]);

	return (td->tio_io);

err:
	mdb_free(td->tio_io, sizeof (mdb_io_t));
	mdb_free(td, sizeof (termio_data_t));

	return (NULL);
}

int
mdb_iob_isatty(mdb_iob_t *iob)
{
	mdb_io_t *io;

	if (iob->iob_flags & MDB_IOB_TTYLIKE)
		return (1);

	for (io = iob->iob_iop; io != NULL; io = io->io_next) {
		if (io->io_ops == &termio_ops)
			return (1);
	}

	return (0);
}

static const char *
termio_insert(termio_data_t *td, int c)
{
	size_t olen = td->tio_cmdbuf.cmd_buflen;

	if (mdb_cmdbuf_insert(&td->tio_cmdbuf, c) == 0) {
		if (mdb_cmdbuf_atend(&td->tio_cmdbuf))
			termio_addch(td, c, td->tio_cmdbuf.cmd_buflen - olen);
		else
			termio_insch(td, c, td->tio_cmdbuf.cmd_buflen - olen);
	}

	return (NULL);
}

static const char *
termio_accept(termio_data_t *td, int c)
{
	if (td->tio_flags & TIO_FINDHIST) {
		(void) mdb_cmdbuf_findhist(&td->tio_cmdbuf, c);

		td->tio_prompt = mdb.m_prompt;
		td->tio_promptlen = mdb.m_promptlen;
		td->tio_flags &= ~TIO_FINDHIST;

		termio_redraw(td);
		return (NULL);
	}

	/* Ensure that the cursor is at the end of the line */
	(void) termio_end(td, c);

	return (mdb_cmdbuf_accept(&td->tio_cmdbuf));
}

static const char *
termio_backspace(termio_data_t *td, int c)
{
	if (mdb_cmdbuf_backspace(&td->tio_cmdbuf, c) == 0) {
		if (mdb_cmdbuf_atend(&td->tio_cmdbuf))
			termio_bspch(td);
		else
			termio_redraw(td);
	}

	return (NULL);
}

/*
 * This function may end up calling termio_read recursively as part of invoking
 * the mdb pager. To work around this fact, we need to go through and make sure
 * that we change the underlying terminal settings before and after this
 * function call. If we don't do this, we invoke the pager, and don't abort
 * (which will longjmp us elsewhere) we're going to return to the read loop with
 * the wrong termio settings.
 *
 * Furthermore, because of the fact that we're being invoked in a user context
 * that allows us to be interrupted, we need to actually allocate the memory
 * that we're using with GC so that it gets cleaned up in case of the pager
 * resetting us and never reaching the end.
 */
/*ARGSUSED*/
static const char *
termio_tab(termio_data_t *td, int c)
{
	char *buf;
	const char *result;
	int nres;
	mdb_tab_cookie_t *mtp;

	if (termio_ctl(td->tio_io, TCSETSW, &td->tio_dtios) == -1)
		warn("failed to restore terminal attributes");

	buf = mdb_alloc(td->tio_cmdbuf.cmd_bufidx + 1, UM_SLEEP | UM_GC);
	(void) strncpy(buf, td->tio_cmdbuf.cmd_buf, td->tio_cmdbuf.cmd_bufidx);
	buf[td->tio_cmdbuf.cmd_bufidx] = '\0';
	td->tio_flags |= TIO_TAB;
	mtp = mdb_tab_init();
	nres = mdb_tab_command(mtp, buf);

	if (nres == 0) {
		result = NULL;
	} else {
		result = mdb_tab_match(mtp);
		if (nres != 1) {
			mdb_printf("\n");
			mdb_tab_print(mtp);
		}
	}

	if (result != NULL) {
		int index = 0;

		while (result[index] != '\0') {
			(void) termio_insert(td, result[index]);
			index++;
		}
	}

	termio_redraw(td);
	mdb_tab_fini(mtp);
	td->tio_flags &= ~TIO_TAB;
	if (termio_ctl(td->tio_io, TCSETSW, &td->tio_rtios) == -1)
		warn("failed to set terminal attributes");


	return (NULL);
}

static const char *
termio_delchar(termio_data_t *td, int c)
{
	if (!(mdb.m_flags & MDB_FL_IGNEOF) &&
	    mdb_cmdbuf_atend(&td->tio_cmdbuf) &&
	    mdb_cmdbuf_atstart(&td->tio_cmdbuf))
		return (termio_quit(td, c));

	if (mdb_cmdbuf_delchar(&td->tio_cmdbuf, c) == 0) {
		if (mdb_cmdbuf_atend(&td->tio_cmdbuf))
			termio_delch(td);
		else
			termio_redraw(td);
	}

	return (NULL);
}

static const char *
termio_fwdchar(termio_data_t *td, int c)
{
	if (mdb_cmdbuf_fwdchar(&td->tio_cmdbuf, c) == 0)
		termio_mvcur(td);

	return (NULL);
}

static const char *
termio_backchar(termio_data_t *td, int c)
{
	if (mdb_cmdbuf_backchar(&td->tio_cmdbuf, c) == 0)
		termio_mvcur(td);

	return (NULL);
}

static const char *
termio_transpose(termio_data_t *td, int c)
{
	if (mdb_cmdbuf_transpose(&td->tio_cmdbuf, c) == 0)
		termio_redraw(td);

	return (NULL);
}

static const char *
termio_home(termio_data_t *td, int c)
{
	if (mdb_cmdbuf_home(&td->tio_cmdbuf, c) == 0)
		termio_mvcur(td);

	return (NULL);
}

static const char *
termio_end(termio_data_t *td, int c)
{
	if (mdb_cmdbuf_end(&td->tio_cmdbuf, c) == 0)
		termio_mvcur(td);

	return (NULL);
}

static const char *
termio_fwdword(termio_data_t *td, int c)
{
	if (mdb_cmdbuf_fwdword(&td->tio_cmdbuf, c) == 0)
		termio_mvcur(td);

	return (NULL);
}

static const char *
termio_backword(termio_data_t *td, int c)
{
	if (mdb_cmdbuf_backword(&td->tio_cmdbuf, c) == 0)
		termio_mvcur(td);

	return (NULL);
}

static const char *
termio_kill(termio_data_t *td, int c)
{
	if (mdb_cmdbuf_kill(&td->tio_cmdbuf, c) == 0)
		termio_redraw(td);

	return (NULL);
}

static const char *
termio_killfwdword(termio_data_t *td, int c)
{
	if (mdb_cmdbuf_killfwdword(&td->tio_cmdbuf, c) == 0)
		termio_redraw(td);

	return (NULL);
}

static const char *
termio_killbackword(termio_data_t *td, int c)
{
	if (mdb_cmdbuf_killbackword(&td->tio_cmdbuf, c) == 0)
		termio_redraw(td);

	return (NULL);
}

static const char *
termio_reset(termio_data_t *td, int c)
{
	if (mdb_cmdbuf_reset(&td->tio_cmdbuf, c) == 0)
		termio_clear(td);

	return (NULL);
}

/*ARGSUSED*/
static const char *
termio_widescreen(termio_data_t *td, int c)
{
	if (td->tio_flags & TIO_XTERM) {
		if (td->tio_cols == 80)
			termio_tput(td, TI_DECSET(TI_DECCOLM), 1);
		else
			termio_tput(td, TI_DECRST(TI_DECCOLM), 1);
		mdb_iob_flush(td->tio_out);
		termio_winch(SIGWINCH, NULL, NULL, td);
	}

	return (NULL);
}

static const char *
termio_prevhist(termio_data_t *td, int c)
{
	if (mdb_cmdbuf_prevhist(&td->tio_cmdbuf, c) == 0)
		termio_redraw(td);

	return (NULL);
}

static const char *
termio_nexthist(termio_data_t *td, int c)
{
	if (mdb_cmdbuf_nexthist(&td->tio_cmdbuf, c) == 0)
		termio_redraw(td);

	return (NULL);
}

/*
 * Single-key accelerator support.  Several commands are so commonly used as to
 * require a single-key equivalent.  If we see one of these accelerator
 * characters at the beginning of an otherwise-empty line, we'll replace it with
 * the expansion.
 */
static const char *
termio_accel(termio_data_t *td, int c)
{
	const char *p;

	if (td->tio_cmdbuf.cmd_buflen != 0 ||
	    (p = termio_accel_lookup(c)) == NULL)
		return (termio_insert(td, c));

	while (*p != '\0')
		(void) termio_insert(td, *p++);
	return (termio_accept(td, '\n'));
}

static const char *
termio_findhist(termio_data_t *td, int c)
{
	if (mdb_cmdbuf_reset(&td->tio_cmdbuf, c) == 0) {
		td->tio_prompt = "Search: ";
		td->tio_promptlen = strlen(td->tio_prompt);
		td->tio_flags |= TIO_FINDHIST;
		termio_redraw(td);
	}

	return (NULL);
}

/*ARGSUSED*/
static const char *
termio_refresh(termio_data_t *td, int c)
{
	if (td->tio_info.ti_clear.at_str) {
		termio_tput(td, td->tio_info.ti_clear.at_str, 1);
		td->tio_x = td->tio_y = 0;
	}
	termio_redraw(td);
	return (NULL);
}

/*
 * Leave the terminal read code by longjmp'ing up the stack of mdb_frame_t's
 * back to the main parsing loop (see mdb_run() in mdb.c).
 */
static const char *
termio_abort(termio_data_t *td, int c, int err)
{
	(void) mdb_cmdbuf_reset(&td->tio_cmdbuf, c);
	td->tio_active = FALSE;
	td->tio_rti_on = FALSE;

	if (termio_ctl(td->tio_io, TCSETSW, &td->tio_dtios) == -1)
		warn("failed to restore terminal attributes");

	longjmp(mdb.m_frame->f_pcb, err);
	/*NOTREACHED*/
	return (NULL);
}

static const char *
termio_intr(termio_data_t *td, int c)
{
	return (termio_abort(td, c, MDB_ERR_SIGINT));
}

static const char *
termio_quit(termio_data_t *td, int c)
{
	return (termio_abort(td, c, MDB_ERR_QUIT));
}

/*ARGSUSED*/
static const char *
termio_susp(termio_data_t *td, int c)
{
	(void) mdb_signal_sethandler(SIGWINCH, SIG_IGN, NULL);
	(void) mdb_signal_sethandler(SIGTSTP, SIG_IGN, NULL);

	termio_suspend_tty(td, &td->tio_ptios);
	mdb_iob_nl(td->tio_out);

	(void) mdb_signal_sethandler(SIGTSTP, SIG_DFL, NULL);
	(void) mdb_signal_pgrp(SIGTSTP);

	/*
	 * When we call mdb_signal_pgrp(SIGTSTP), we are expecting the entire
	 * debugger process group to be stopped by the kernel.  Once we return
	 * from that call, we assume we are resuming from a subsequent SIGCONT.
	 */
	(void) mdb_signal_sethandler(SIGTSTP, SIG_IGN, NULL);
	termio_resume_tty(td, &td->tio_ptios);

	(void) mdb_signal_sethandler(SIGWINCH, termio_winch, td);
	(void) mdb_signal_sethandler(SIGTSTP, termio_tstp, td);

	if (td->tio_active)
		siglongjmp(td->tio_env, SIGCONT);

	return (NULL);
}

/*ARGSUSED*/
static void
termio_winch(int sig, siginfo_t *sip, ucontext_t *ucp, void *data)
{
	termio_data_t *td = data;
	mdb_bool_t change = FALSE;
	struct winsize winsz;

	if (termio_ctl(td->tio_io, TIOCGWINSZ, &winsz) == -1)
		return; /* just ignore this WINCH if the ioctl fails */

	if (td->tio_rows != (size_t)winsz.ws_row ||
	    td->tio_cols != (size_t)winsz.ws_col) {

		if (td->tio_active)
			termio_clear(td);

		if (winsz.ws_row != 0)
			td->tio_rows = (size_t)winsz.ws_row;

		if (winsz.ws_col != 0)
			td->tio_cols = (size_t)winsz.ws_col;

		if (td->tio_active)
			termio_clear(td);

		mdb_iob_resize(td->tio_out, td->tio_rows, td->tio_cols);
		change = TRUE;
	}

	if (change && td->tio_active)
		siglongjmp(td->tio_env, sig);

	if (change && td->tio_link != NULL)
		mdb_iob_resize(td->tio_link, td->tio_rows, td->tio_cols);
}

/*ARGSUSED*/
static void
termio_tstp(int sig, siginfo_t *sip, ucontext_t *ucp, void *data)
{
	(void) termio_susp(data, CTRL('Z'));
}
