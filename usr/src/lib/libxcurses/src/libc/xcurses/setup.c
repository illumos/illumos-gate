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
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
static char const rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/setup.c 1.9 1995/10/02 20:22:57 ant Exp $";
#endif
#endif

#include <private.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef M_USE_IOCTL_H
#include <sys/ioctl.h>
#endif
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

TERMINAL *cur_term;

/*
 * Any version number should be placed in this file, since setupterm()
 * must be called in order to initialize Curses or Terminfo.
 */
char __m_curses_version[] = M_CURSES_VERSION;

/* True if __m_setupterm() should use either the window settings from 
 * ioctl(), or the environment variables LINES and COLUMNS to override
 * the terminfo database entries for 'lines' and 'columns'.  
 *
 * Call use_env(flag) before either setupterm(), newterm(), or initscr().
 */
static bool use_environment = TRUE;	

static char const e_terminal[] = "No memory for TERMINAL structure.\n";
static char const e_unknown[] = "\"%s\": Unknown terminal type.\n";
static char const e_pathmax[] = "\"%s\": terminfo database path too long.\n";

static char def_cr[] = "\r";
static char def_nl[] = "\n";

/*
 * Take the real command character out of the CC environment variable
 * and substitute it in for the prototype given in 'command_character'.
 */
static void
do_prototype()
{
    	int i, j;
	char CC, proto;

	CC = *__m_getenv("CC");
	proto = *command_character;

	for (i=0; i < __COUNT_STR; i++)
		for(j = 0; cur_term->_str[i][j]; ++j)
			if (cur_term->_str[i][j] == proto)
				cur_term->_str[i][j] = CC;
}

#define min(a, b)		((a) < (b) ? (a) : (b))

/*
 * Return a number from a terminfo file.  Numbers in a terminfo
 * file are stored as two bytes with low-high ordering.
 */
static short
getnum(fd)
int fd;
{
        unsigned char bytes[2];
 
        if (read(fd, bytes, 2) != 2)
                return SHRT_MIN;
 
        return (short) (bytes[0] + bytes[1] * 256);
}

/*f
 * Read the compiled terminfo entry in the given file into the
 * structure pointed to by ptr, allocating space for the string
 * table and placing its address in ptr->str_table.
 */
int
__m_read_terminfo(filename, tp)
const char *filename;
TERMINAL *tp;
{
	int fd;
	short offset;
	size_t i, len;
	struct stat statbuf;
	terminfo_header_t header;
	unsigned char ch, bytebuf[2];

	/* Get compiled terminfo file header. */
	if ((fd = open(filename, 0)) < 0)
		goto error_1;

	if ((header.magic = getnum(fd)) != __TERMINFO_MAGIC
	|| (header.name_size = getnum(fd)) < 0
	|| (header.bool_count = getnum(fd)) < 0
	|| (header.num_count = getnum(fd)) < 0
	|| (header.str_count = getnum(fd)) < 0
	|| (header.str_size = getnum(fd)) < 0)
		goto error_2;

	/* Allocate and fetch terminal names. */
	len = min(127, header.name_size);
	if ((tp->_names = (char *) malloc(len + 1)) == (char *) 0)
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
		(void) lseek(
			fd, (off_t) (header.bool_count - __COUNT_BOOL), 
			SEEK_CUR
		);
	} else {
		for (len = header.bool_count; len < __COUNT_BOOL; ++len)
			tp->_bool[len] = 0;
	}

	/* Eat padding byte. */
	if ((header.name_size + header.bool_count) % 2 != 0)
		(void) read(fd, &ch, sizeof ch);

	/* Fetch numbers. */
	len = min(__COUNT_NUM, header.num_count);
	for (i = 0; i < len; ++i)
		tp->_num[i] = getnum(fd);

	if (__COUNT_NUM < header.num_count) {
		(void) lseek(
			fd, (off_t) (2 * (header.num_count - __COUNT_NUM)), 
			SEEK_CUR
		);
	} else {
		for (len = header.num_count; len < __COUNT_NUM; ++len)
			tp->_num[len] = -1;
	}

	/* Allocate and fetch strings. */
	if ((tp->_str_table = (char *) malloc(header.str_size)) == (char *) 0)
		goto error_3;

        /* Read in string offset section setting pointers to strings. */
	len = min(__COUNT_STR, header.str_count);
        for (i = 0; i < len; ++i) {
                if ((offset = getnum(fd)) == SHRT_MIN)
                        goto error_4;
 
                if (offset < 0)
                        tp->_str[i] = (char *) 0;
                else
                        tp->_str[i] = tp->_str_table + offset;
        }

	if (__COUNT_STR < header.str_count) {
		(void) lseek(
			fd, (off_t) (2 * (header.str_count - __COUNT_STR)), 
			SEEK_CUR
		);
	} else {
		for (; i < __COUNT_STR; ++i)
			tp->_str[i] = (char *) 0;
	}

	if (read(fd, tp->_str_table, header.str_size) != header.str_size)
		goto error_4;
	(void) close(fd);

	return 0;
error_4:
	free(tp->_str_table);
error_3:
	free(tp->_names);
error_2:
	(void) close(fd);
error_1:
	return -1;
}

void
use_env(bool bf)
{
#ifdef M_CURSES_TRACE
	__m_trace("use_env(%d)", bf);
#endif
	use_environment = bf;
	__m_return_void("use_env");
}

/*f
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
__m_setupterm(termname, ifd, ofd, err_return)
const char *termname;
int ifd, ofd;
int *err_return;
{
	int err_code = 1;
	TERMINAL *old_term;
	char const *err_msg;

	/* It is possible to call setupterm() for multiple terminals, 
	 * in which case we have to be able to restore cur_term in 
	 * case of error.
	 */
	old_term = cur_term;

	cur_term = (TERMINAL *) calloc(1, sizeof *cur_term);
	if (cur_term == (TERMINAL *) 0) {
		err_code = -1;
		goto error;
	}

	if (isatty(cur_term->_ifd = ifd))
		cur_term->_flags |= __TERM_ISATTY_IN;
	if (isatty(cur_term->_ifd = ofd))
		cur_term->_flags |= __TERM_ISATTY_OUT;

	(void) def_shell_mode();
	(void) def_prog_mode();

#ifdef ONLCR
	if ((cur_term->_prog.c_oflag & (OPOST | ONLCR)) == (OPOST | ONLCR))
#else
	if (cur_term->_prog.c_oflag & OPOST)
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

	if (err_return != (int *) 0) {
#ifdef M_CURSES_TRACE
		__m_trace(
			"__m_setupterm error code passed back in %p = %d.", 
			err_return, err_code
		);
#endif
		*err_return = err_code;

		if (err_code == 1) {
			err_code = OK;
		} else {
			err_code = ERR;
			free(cur_term);
			cur_term = old_term;
		}	
	} else if (err_code != 1) {
#ifdef M_CURSES_TRACE
		__m_trace("__m_setupterm() failed with:");
		__m_trace(err_msg, termname);
#endif
		fprintf(stderr, err_msg, termname);
		exit(1);
	}

	return __m_return_code("__m_setupterm", err_code);
}

int
setupterm(term, out, err)
const char *term;
int out, *err;
{
	int code;
#ifdef M_CURSES_TRACE
	__m_trace("setupterm(%p, %d, %p)", term, out, err);
#endif

	code = __m_setupterm(term, STDIN_FILENO, out, err);

	return __m_return_code("setupterm", code);
}

int
del_curterm(tp)
TERMINAL *tp;
{
#ifdef M_CURSES_TRACE
	__m_trace("del_curterm(%p)", tp);
#endif

	if (tp != (TERMINAL *) 0) {
		if (cur_term == tp)
			cur_term = (TERMINAL *) 0;
		if (tp->_str_table != (char *) 0)
			free(tp->_str_table);
		if (tp->_names != (char *) 0)
			free(tp->_names);
		if (tp->_term != (char *) 0)
			free(tp->_term);
		if (tp->_pair != (short (*)[2]) 0)
			free(tp->_pair);
		if (tp->_color != (short (*)[3]) 0)
			free(tp->_color);
		free(tp);
	}

	return __m_return_code("del_curterm", OK);
}

TERMINAL *
set_curterm(tp)
TERMINAL *tp;
{
	TERMINAL *old;

#ifdef M_CURSES_TRACE
	__m_trace("set_curterm(%p)", tp);
#endif

	old = cur_term;
	cur_term = tp;

	return __m_return_pointer("set_curterm", old);
}

int
restartterm(tm, fd, err_return)
const char *tm;
int fd, *err_return;
{
	size_t len;
	int path_max, err_code;
	char const *err_msg, *terminfo;
	char *old_names, *old_strings, *old_term, *filename;
	static char const def_termname[] = M_TERM_NAME;
	static char const def_terminfo[] = M_TERMINFO_DIR;

#ifdef M_CURSES_TRACE
	__m_trace("restartterm(%s, %d, %p)", tm ? tm : "NULL", fd, err_return);
#endif

	err_code = 1;
	filename = (char *) 0;
	old_term = cur_term->_term;
	old_names = cur_term->_names;
	old_strings = cur_term->_str_table;

	terminfo = __m_getenv("TERMINFO");
	if (terminfo == (char *) 0 || terminfo[0] == '\0') {
		terminfo = def_terminfo; 
	} else {
		terminfo = (const char *) strdup((char *) terminfo);
		if (terminfo == (char *) 0) {
			/* Not really true... */
			err_msg = e_terminal; 
			err_code = 2;
			goto error;
		}
	}
			
	if (tm == (char *) 0 && (tm = getenv("TERM")) == (char *) 0)
		tm = def_termname;

	/* Remember the terminal name being loaded. */
	cur_term->_term = m_strdup(tm);

	/* Length of path we're going to construct. */
	len = strlen(terminfo) + 3 + strlen(tm);

	if ((path_max = m_pathmax(terminfo)) == -1 || path_max < len
	|| (filename = (char *) malloc(path_max+1)) == (char *) 0) {
		err_msg = e_pathmax;
		err_code = 2;
		goto error;
	}

	/* Construct terminfo filename. */
	(void) sprintf(filename, "%s/%c/%s", terminfo, tolower(tm[0]), tm);

	/* Go looking for compiled terminal definition. */
	if (__m_read_terminfo(filename, cur_term) < 0) {
		/* Length of default terminfo path. */
		len = strlen(def_terminfo) + 3 + strlen(tm);

		if (path_max < len) {
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
		char *env;
#ifdef TIOCGWINSZ
		/*l
		 * Use ioctl(TIOCGWINSZ) to get row and column values.  These
		 * values may override the default terminfo settings.
		 */
		{
			struct winsize wininfo;
			if (ioctl(fd, TIOCGWINSZ, &wininfo) != -1) {
				if (0 < wininfo.ws_col)
					columns = wininfo.ws_col;
				if (0 < wininfo.ws_row)
					lines = wininfo.ws_row;
			} 
		}
#endif /* TIOCGWINSZ */

		/* Check to see is the user wants a particular size terminal. */
		if ((env = __m_getenv("LINES")) != (char *) 0) {
			int nlines = strtol(env, (char **) 0, 10);
			if (0 < nlines)
				lines = nlines;
		}
		if ((env = __m_getenv("COLUMNS")) != (char *) 0) {
			int ncolumns = strtol(env, (char **) 0, 10);
			if (0 < ncolumns)
				columns = ncolumns;
		}
	}

	if (command_character != (char *) 0 && __m_getenv("CC") != (char *) 0)
		do_prototype();

	/* If no_color_video is disabled, then assign it a value that
	 * permits all attributes in combination with colour.
	 */
	if (no_color_video == -1)
		no_color_video = 0;

	__m_mvcur_cost();
error:
	if (filename != (char *) 0)
		free(filename);

	if (terminfo != def_terminfo)
		free((void *) terminfo);

	if (err_return != NULL) {
#ifdef M_CURSES_TRACE
		__m_trace(
			"restartterm() error code passed back in %p = %d.", 
			err_return, err_code
		);
#endif
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
#ifdef M_CURSES_TRACE
		__m_trace("restartterm() failed with:");
		__m_trace(err_msg, tm);
#endif
		fprintf(stderr, err_msg, tm);
		exit(1);
	} 

	if (err_code == OK) {
		if (old_names != (char *) 0)
			free(old_names);
		if (old_strings != (char *) 0)
			free(old_strings);
		if (old_term != (char *) 0)
			free(old_term);
	}

	return __m_return_code("restartterm", err_code);
}

/*
 * Get the termios setting for the terminal.  Check the input
 * file descriptor first, else the output file descriptor.  If
 * both input and output are both terminals, it is assumed that 
 * they refer to the same terminal.
 */
int
__m_tty_get(tp)
struct termios *tp;
{
	if (tcgetattr(cur_term->_ifd, tp) != 0) {
		/* Input was not a terminal, possibly redirected. 
		 * Check output instead.
		 */
		if (tcgetattr(cur_term->_ofd, tp) != 0)
			return ERR;
	}

	return OK;
}

/*
 * Restore the termios settings.
 */
int
__m_tty_set(tp)
struct termios *tp;
{
	int fd;

	if (cur_term->_flags & __TERM_ISATTY_IN)
		fd = cur_term->_ifd;
	else if (cur_term->_flags & __TERM_ISATTY_OUT)
		fd = cur_term->_ofd;
	else
		return OK;

#ifdef NOT_NOW
	return tcsetattr(fd, TCSADRAIN, tp) == 0 ? OK : ERR;
#else
/* VSU testing bug does not read the master side properly so in order
 * to drain the buffer.  Must use TCSANOW.
 */
	return tcsetattr(fd, TCSANOW, tp) == 0 ? OK : ERR;
#endif
}

int
def_shell_mode()
{
#ifdef M_CURSES_TRACE
	__m_trace("def_shell_mode(void)");
#endif

	return __m_return_code(
		"def_shell_mode", __m_tty_get(&cur_term->_shell)
	);
}

int
def_prog_mode()
{
#ifdef M_CURSES_TRACE
	__m_trace("def_prog_mode(void)");
#endif

	return __m_return_code("def_prog_mode", __m_tty_get(&cur_term->_prog));
}

int
reset_shell_mode()
{
#ifdef M_CURSES_TRACE
	__m_trace("reset_shell_mode(void)");
#endif

	return __m_return_code(
		"reset_shell_mode", __m_tty_set(&cur_term->_shell)
	);
}

int
reset_prog_mode()
{
#ifdef M_CURSES_TRACE
	__m_trace("reset_prog_mode(void)");
#endif

	return __m_return_code(
		"reset_prog_mode", __m_tty_set(&cur_term->_prog)
	);
}

