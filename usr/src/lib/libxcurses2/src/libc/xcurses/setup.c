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
 * Copyright (c) 1995-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * setupterm.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char const rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/setup.c 1.16 1998/06/05 14:35:33 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <sys/types.h>
#ifdef TIOCGWINSZ
#include <sys/ioctl.h>
#endif
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

TERMINAL	*cur_term;

/*
 * Any version number should be placed in this file, since setupterm()
 * must be called in order to initialize Curses or Terminfo.
 */
char	__m_curses_version[] = M_CURSES_VERSION;

/*
 * True if __m_setupterm() should use either the window settings from
 * ioctl(), or the environment variables LINES and COLUMNS to override
 * the terminfo database entries for 'lines' and 'columns'.
 *
 * Call use_env(flag) before either setupterm(), newterm(), or initscr().
 */
static bool	use_environment = TRUE;

static const char	e_terminal[] =
	"No memory for TERMINAL structure.\n";
static const char	e_unknown[] =
	"\"%s\": Unknown terminal type.\n";
static const char	e_pathmax[] =
	"\"%s\": terminfo database path too long.\n";


/*
 * These globals are used so that macro arguments are evaluated
 * exactly once
 */
/* The downside is that it is not really thread-safe. Oh well... */
WINDOW	*__w1;
chtype	__cht1;
chtype	__cht2;
cchar_t	*__pcht1;
cchar_t	*__pcht2;

/*
 * Take the real command character out of the CC environment variable
 * and substitute it in for the prototype given in 'command_character'.
 */
static void
do_prototype(void)
{
	int	i, j;
	char	proto;
	char	*CC;

	CC = getenv("CC");
	proto = *command_character;

	for (i = 0; i < __COUNT_STR; i++)
		for (j = 0; cur_term->_str[i][j]; ++j)
			if (cur_term->_str[i][j] == proto)
				cur_term->_str[i][j] = *CC;
}

#define	min(a, b)		((a) < (b) ? (a) : (b))

/*
 * Return a number from a terminfo file.  Numbers in a terminfo
 * file are stored as two bytes with low-high ordering.
 */
static short
getnum(int fd)
{
	unsigned char	bytes[2];

	if (read(fd, bytes, 2) != 2)
		return (SHRT_MIN);

	return ((short) (bytes[0] + bytes[1] * 256));
}

/*
 * MKS Header format for terminfo database files.
 *
 * The header consists of six short integers, stored using VAX/PDP style
 * byte swapping (least-significant byte first).  The integers are
 *
 *  1) magic number (octal 0432);
 *  2) the size, in bytes, of the names sections;
 *  3) the number of bytes in the boolean section;
 *  4) the number of short integers in the numbers section;
 *  5) the number of offsets (short integers) in the strings section;
 *  6) the size, in bytes, of the string table.
 *
 * Between the boolean and number sections, a null byte is inserted, if
 * necessary, to ensure that the number section begins on an even byte
 * offset.  All short integers are aligned on a short word boundary.
 */

#define	__TERMINFO_MAGIC		0432

typedef struct {
	short	magic;
	short	name_size;
	short	bool_count;
	short	num_count;
	short	str_count;
	short	str_size;
} terminfo_header_t;

/*
 * Read the compiled terminfo entry in the given file into the
 * structure pointed to by ptr, allocating space for the string
 * table and placing its address in ptr->str_table.
 */
int
__m_read_terminfo(const char *filename, TERMINAL *tp)
{
	int	fd;
	short	offset;
	size_t	i, len;
	terminfo_header_t	header;
	unsigned char	ch;

	/* Get compiled terminfo file header. */
	if ((fd = open(filename, 0)) < 0) {
		goto error_1;
	}

	if ((header.magic = getnum(fd)) != __TERMINFO_MAGIC ||
		(header.name_size = getnum(fd)) < 0 ||
		(header.bool_count = getnum(fd)) < 0 ||
		(header.num_count = getnum(fd)) < 0 ||
		(header.str_count = getnum(fd)) < 0 ||
		(header.str_size = getnum(fd)) < 0) {
		goto error_2;
	}


	/* Allocate and fetch terminal names. */
	len = min(127, header.name_size);
	if ((tp->_names = (char *) malloc(len + 1)) == NULL)
		goto error_2;
	if (read(fd, tp->_names, len) != len)
		goto error_3;
	tp->_names[len] = '\0';

	if (127 < header.name_size)
		(void) lseek(fd, (off_t) (header.name_size - 127), SEEK_CUR);

	/* Fetch booleans. */
	len = min(__COUNT_BOOL, header.bool_count);
	if (read(fd, tp->_bool, len) != len)
		goto error_3;

	if (__COUNT_BOOL < header.bool_count) {
		(void) lseek(fd, (off_t) (header.bool_count - __COUNT_BOOL),
			SEEK_CUR);
	} else {
		for (len = header.bool_count; len < __COUNT_BOOL; ++len)
			tp->_bool[len] = 0;
	}

	/* Eat padding byte. */
	if ((header.name_size + header.bool_count) % 2 != 0)
		(void) read(fd, &ch, sizeof (ch));

	/* Fetch numbers. */
	len = min(__COUNT_NUM, header.num_count);
	for (i = 0; i < len; ++i)
		tp->_num[i] = getnum(fd);

	if (__COUNT_NUM < header.num_count) {
		(void) lseek(fd, (off_t) (2 *
			(header.num_count - __COUNT_NUM)), SEEK_CUR);
	} else {
		for (len = header.num_count; len < __COUNT_NUM; ++len)
			tp->_num[len] = -1;
	}

	/* Allocate and fetch strings. */
	if ((tp->_str_table = (char *) malloc(header.str_size)) == NULL)
		goto error_3;

	/* Read in string offset section setting pointers to strings. */
	len = min(__COUNT_STR, header.str_count);
	for (i = 0; i < len; ++i) {
		if ((offset = getnum(fd)) == SHRT_MIN)
			goto error_4;

		if (offset < 0)
			tp->_str[i] = NULL;
		else
			tp->_str[i] = tp->_str_table + offset;
	}

	if (__COUNT_STR < header.str_count) {
		(void) lseek(fd, (off_t) (2 *
			(header.str_count - __COUNT_STR)), SEEK_CUR);
	} else {
		for (; i < __COUNT_STR; ++i)
			tp->_str[i] = NULL;
	}

	if (read(fd, tp->_str_table, header.str_size) != header.str_size)
		goto error_4;
	(void) close(fd);

	return (0);
error_4:
	free(tp->_str_table);
error_3:
	free(tp->_names);
error_2:
	(void) close(fd);
error_1:
	return (-1);
}

void
use_env(bool bf)
{
	use_environment = bf;
}

/*
 * Set up terminal.
 *
 * Reads in the terminfo database pointed to by $TERMINFO env. var.
 * for the given terminal, but does not set up the output virtualization
 * structues used by CURSES.  If the terminal name pointer is NULL,
 * the $TERM env. var. is used for the terminal.  All output is to
 * the given file descriptor which is initialized for output.
 *
 * On error, if errret != NULL then setupterm() returns OK
 * or ERR and stores a status value in the integer pointed to by
 * errret.  A status of 1 is normal, 0 means the terminal could
 * not be found, and -1 means the terminfo database could not be
 * found.  If errret == NULL then setupterm() prints an error
 * message upon and exit().
 *
 * On success, cur_term set to a terminfo structure and OK returned.
 */
int
__m_setupterm(char *termname, int ifd, int ofd, int *err_return)
{
	int	err_code = 1;
	TERMINAL	*old_term;
	const char 	*err_msg;

	/*
	 * It is possible to call setupterm() for multiple terminals,
	 * in which case we have to be able to restore cur_term in
	 * case of error.
	 */
	old_term = cur_term;

	cur_term = (TERMINAL *) calloc(1, sizeof (*cur_term));
	if (cur_term == NULL) {
		err_code = -1;
		goto error;
	}

	if (isatty(cur_term->_ifd = ifd))
		cur_term->_flags |= __TERM_ISATTY_IN;
	if (isatty(cur_term->_ofd = ofd))
		cur_term->_flags |= __TERM_ISATTY_OUT;

	cur_term->_shell	= (void *) calloc(1, sizeof (struct termios));
	cur_term->_prog		= (void *) calloc(1, sizeof (struct termios));
	cur_term->_save		= (void *) calloc(1, sizeof (struct termios));
	cur_term->_actual	= (void *) calloc(1, sizeof (struct termios));
	cur_term->_term		= NULL;
	cur_term->_names	= NULL;
	cur_term->_str_table	= NULL;
	(void) def_shell_mode();
	(void) def_prog_mode();
	(void) __m_tty_get(PTERMIOS(_actual));	/* Synch cached value */

#ifdef ONLCR
	if ((PTERMIOS(_prog)->c_oflag & (OPOST | ONLCR)) == (OPOST | ONLCR))
#else
	if (PTERMIOS(_prog)->c_oflag & OPOST)
#endif
		cur_term->_flags |= __TERM_NL_IS_CRLF;

	(void) restartterm(termname, ofd, &err_code);
error:
	switch (err_code) {
	case -1:
		err_msg = e_terminal;
		break;
	case 0:
		err_msg = e_unknown;
		break;
	case 1:
		break;
	case 2:
		err_msg = e_pathmax;
		err_code = -1;
		break;
	}

	if (err_return != NULL) {
		*err_return = err_code;

		if (err_code == 1) {
			err_code = OK;
		} else {
			err_code = ERR;
			free(cur_term);
			cur_term = old_term;
		}
	} else if (err_code != 1) {
		(void) fprintf(stderr, err_msg, termname);
		exit(1);
	}

	return (err_code);
}

int
setupterm(char *term, int out, int *err)
{
	int	code;

	code = __m_setupterm(term, STDIN_FILENO, out, err);

	return (code);
}

int
del_curterm(TERMINAL *tp)
{
	if (tp != NULL) {
		if (cur_term == tp)
			cur_term = NULL;
		if (tp->_str_table != NULL)
			free(tp->_str_table);
		if (tp->_names != NULL)
			free(tp->_names);
		if (tp->_term != NULL)
			free(tp->_term);
		if (tp->_pair != (short (*)[2]) 0)
			free(tp->_pair);
		if (tp->_color != (short (*)[3]) 0)
			free(tp->_color);
		if (tp->_shell)
			free(tp->_shell);
		if (tp->_prog)
			free(tp->_prog);
		if (tp->_save)
			free(tp->_save);
		if (tp->_actual)
			free(tp->_actual);
		free(tp);
	}

	return (OK);
}

TERMINAL *
set_curterm(TERMINAL *tp)
{
	TERMINAL	*old;

	old = cur_term;
	cur_term = tp;

	return (old);
}

int
restartterm(char *tm, int fd, int *err_return)
{
	size_t	len;
	int	err_code;
	const char	*err_msg, *terminfo;
	char	*old_names, *old_strings, *old_term, *filename;
	static const char	def_termname[] = M_TERM_NAME;
	static const char	def_terminfo[] = M_TERMINFO_DIR;

	err_code = 1;
	filename = NULL;
	old_term = cur_term->_term;
	old_names = cur_term->_names;
	old_strings = cur_term->_str_table;

	terminfo = getenv("TERMINFO");
	if (terminfo == NULL || terminfo[0] == '\0') {
		terminfo = def_terminfo;
	} else {
		terminfo = (const char *) strdup((char *) terminfo);
		if (terminfo == NULL) {
			/* Not really true... */
			err_msg = e_terminal;
			err_code = 2;
			goto error;
		}
	}

	if ((tm == NULL) &&
		(((tm = getenv("TERM")) == NULL) || (*tm == '\0'))) {
		tm = (char *)def_termname;
	}

	/* Remember the terminal name being loaded. */
	cur_term->_term = strdup(tm);
	if (cur_term->_term == NULL) {
		err_msg = e_terminal;
		err_code = 2;
		goto error;
	}

	/* Length of path we're going to construct. */
	len = strlen(terminfo) + 3 + strlen(tm);

	if ((len > PATH_MAX) ||
		((filename = (char *)malloc(PATH_MAX + 1)) == NULL)) {
		err_msg = e_pathmax;
		err_code = 2;
		goto error;
	}

	/* Construct terminfo filename. */
	(void) sprintf(filename, "%s/%c/%s", terminfo, tm[0], tm);

	/* Go looking for compiled terminal definition. */
	if (__m_read_terminfo(filename, cur_term) < 0) {
		/* Length of default terminfo path. */
		len = strlen(def_terminfo) + 3 + strlen(tm);

		if (len > PATH_MAX) {
			err_msg = e_pathmax;
			err_code = 2;
			goto error;
		}

		(void) sprintf(filename, "%s/%c/%s", def_terminfo, tm[0], tm);

		if (__m_read_terminfo(filename, cur_term) < 0) {
			err_msg = e_unknown;
			err_code = 0;
			goto error;
		}
	}

	if (use_environment) {
		char	*env;
#ifdef TIOCGWINSZ
		/*
		 * Use ioctl(TIOCGWINSZ) to get row and column values.  These
		 * values may override the default terminfo settings.
		 */
		{
			struct winsize	wininfo;
			if (ioctl(fd, TIOCGWINSZ, &wininfo) != -1) {
				if (0 < wininfo.ws_col)
					columns = wininfo.ws_col;
				if (0 < wininfo.ws_row)
					lines = wininfo.ws_row;
			}
		}
#endif /* TIOCGWINSZ */

		/* Check to see is the user wants a particular size terminal. */
		if ((env = getenv("LINES")) != NULL) {
			int	nlines = (int) strtol(env, (char **) 0, 10);
			if (0 < nlines)
				lines = nlines;
		}
		if ((env = getenv("COLUMNS")) != NULL) {
			int ncolumns = (int) strtol(env, (char **) 0, 10);
			if (0 < ncolumns)
				columns = ncolumns;
		}
	}

	if (command_character != NULL && getenv("CC") != NULL)
		do_prototype();

	/*
	 * If no_color_video is disabled, then assign it a value that
	 * permits all attributes in combination with colour.
	 */
	if (no_color_video == -1)
		no_color_video = 0;

	__m_mvcur_cost();
error:
	if (filename != NULL)
		free(filename);

	if (terminfo != def_terminfo)
		free((void *) terminfo);

	if (err_return != NULL) {
		*err_return = err_code;

		if (err_code == 1) {
			err_code = OK;
		} else {
			err_code = ERR;
			cur_term->_term = old_term;
			cur_term->_names = old_names;
			cur_term->_str_table = old_strings;
		}
	} else if (err_code != 1) {
		(void) fprintf(stderr, err_msg, tm);
		exit(1);
	}

	if (err_code == OK) {
		if (old_names != NULL)
			free(old_names);
		if (old_strings != NULL)
			free(old_strings);
		if (old_term != NULL)
			free(old_term);
	}

	return (err_code);
}

/*
 * Get the termios setting for the terminal.  Check the input
 * file descriptor first, else the output file descriptor.  If
 * both input and output are both terminals, it is assumed that
 * they refer to the same terminal.
 */
int
__m_tty_get(struct termios *tp)
{
	if (tcgetattr(cur_term->_ifd, tp) != 0) {
		/*
		 * Input was not a terminal, possibly redirected.
		 * Check output instead.
		 */
		if (tcgetattr(cur_term->_ofd, tp) != 0)
			return (ERR);
	}

	return (OK);
}

int
__m_tty_set_prog_mode(void)
{
	return (__m_tty_set(PTERMIOS(_prog)));
}

/*
 * Restore the termios settings.
 */
int
__m_tty_set(struct termios *tp)
{
	int	fd;
	int	rval;

	if (cur_term->_flags & __TERM_ISATTY_OUT) {
		fd = cur_term->_ofd;
	} else if (cur_term->_flags & __TERM_ISATTY_IN) {
		fd = cur_term->_ifd;
	} else {
		return (OK);
	}
	if (memcmp(tp, &cur_term->_actual, sizeof (struct termios)) == 0)
		return (OK);

	*PTERMIOS(_actual) = *tp;

	rval = tcsetattr(fd, TCSADRAIN, tp) == 0 ? OK : ERR;

	return (rval);
}

int
def_shell_mode(void)
{
	return (__m_tty_get(PTERMIOS(_shell)));
}

int
def_prog_mode(void)
{
	return (__m_tty_get(PTERMIOS(_prog)));
}

int
reset_shell_mode(void)
{
	return (__m_tty_set(PTERMIOS(_shell)));
}

int
reset_prog_mode(void)
{
	return (__m_tty_set_prog_mode());
}
