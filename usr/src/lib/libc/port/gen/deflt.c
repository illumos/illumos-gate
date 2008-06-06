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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "libc.h"
#include <stdio.h>
#include <stdlib.h>
#include <deflt.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include "tsd.h"

#define	TSTBITS(flags, mask)	(((flags) & (mask)) == (mask))

static void strip_quotes(char *);

struct thr_data {
	int  Dcflags;	/* [re-]initialized on each call to defopen() */
	FILE *fp;
	char *buf;
};

#define	BUFFERSIZE	1024

/*
 * destructor for per-thread data, registered with tsdalloc()
 */
static void
free_thr_data(void *arg)
{
	struct thr_data *thr_data = (struct thr_data *)arg;

	if (thr_data->fp) {
		(void) fclose(thr_data->fp);
		thr_data->fp = NULL;
	}
	if (thr_data->buf) {
		lfree(thr_data->buf, BUFFERSIZE);
		thr_data->buf = NULL;
	}
}

/*
 * get the per-thread-data-item for the calling thread
 */
static struct thr_data *
get_thr_data(void)
{
	struct thr_data *thr_data =
	    tsdalloc(_T_DEFREAD, sizeof (*thr_data), free_thr_data);

	return (thr_data);
}

/*
 *	defopen() - declare defopen filename
 *
 *	defopen(fn)
 *		char *fn
 *
 *	If 'fn' is non-null; it is a full pathname of a file
 *	which becomes the one read by subsequent defread() calls.
 *	If 'fn' is null the defopen file is closed.
 *
 *	see defread() for more details.
 *
 *	EXIT    returns 0 if ok
 *		returns -1 if error
 */
int
defopen(char *fn)
{
	struct thr_data *thr_data = get_thr_data();

	if (thr_data == NULL)
		return (-1);

	if (thr_data->fp != NULL) {
		(void) fclose(thr_data->fp);
		thr_data->fp = NULL;
	}

	if (fn == NULL)
		return (0);

	if ((thr_data->fp = fopen(fn, "rF")) == NULL)
		return (-1);

	/*
	 * We allocate the big buffer only if the fopen() succeeds.
	 * Notice that we deallocate the buffer only when the thread exits.
	 * There are misguided applications that assume that data returned
	 * by defread() continues to exist after defopen(NULL) is called.
	 */
	if (thr_data->buf == NULL &&
	    (thr_data->buf = lmalloc(BUFFERSIZE)) == NULL) {
		(void) fclose(thr_data->fp);
		thr_data->fp = NULL;
		return (-1);
	}

	thr_data->Dcflags = DC_STD;

	return (0);
}

/*
 *	defread() - read an entry from the defopen file
 *
 *	defread(cp)
 *		char *cp
 *
 *	The defopen data file must have been previously opened by
 *	defopen().  defread scans the data file looking for a line
 *	which begins with the string '*cp'.  If such a line is found,
 *	defread returns a pointer to the first character following
 *	the matched string (*cp).  If no line is found or no file
 *	is open, defread() returns NULL.
 *
 *	Note that there is no way to simulatniously peruse multiple
 *	defopen files; since there is no way of indicating 'which one'
 *	to defread().  If you want to peruse a secondary file you must
 *	recall defopen().  If you need to go back to the first file,
 *	you must call defopen() again.
 */
char *
defread(char *cp)
{
	struct thr_data *thr_data = get_thr_data();
	int (*compare)(const char *, const char *, size_t);
	char *buf_tmp, *ret_ptr = NULL;
	size_t off, patlen;

	if (thr_data == NULL || thr_data->fp == NULL)
		return (NULL);

	compare = TSTBITS(thr_data->Dcflags, DC_CASE) ? strncmp : strncasecmp;
	patlen = strlen(cp);

	if (!TSTBITS(thr_data->Dcflags, DC_NOREWIND))
		rewind(thr_data->fp);

	while (fgets(thr_data->buf, BUFFERSIZE, thr_data->fp)) {
		for (buf_tmp = thr_data->buf; *buf_tmp == ' '; buf_tmp++)
			;
		off = strlen(buf_tmp) - 1;
		if (buf_tmp[off] == '\n')
			buf_tmp[off] = 0;
		else
			break;	/* line too long */
		if ((*compare)(cp, buf_tmp, patlen) == 0) {
			/* found it */
			/* strip quotes if requested */
			if (TSTBITS(thr_data->Dcflags, DC_STRIP_QUOTES)) {
				strip_quotes(buf_tmp);
			}
			ret_ptr = &buf_tmp[patlen];
			break;
		}
	}

	return (ret_ptr);
}

/*
 *	defcntl -- default control
 *
 *	SYNOPSIS
 *	  oldflags = defcntl(cmd, arg);
 *
 *	ENTRY
 *	  cmd		Command.  One of DC_GET, DC_SET.
 *	  arg		Depends on command.  If DC_GET, ignored.  If
 *		DC_GET, new flags value, created by ORing the DC_* bits.
 *	RETURN
 *	  oldflags	Old value of flags.  -1 on error.
 *	NOTES
 *	  Currently only one bit of flags implemented, namely respect/
 *	  ignore case.  The routine is as general as it is so that we
 *	  leave our options open.  E.g. we might want to specify rewind/
 *	  norewind before each defread.
 */

int
defcntl(int cmd, int newflags)
{
	struct thr_data *thr_data = get_thr_data();
	int  oldflags;

	if (thr_data == NULL)
		return (-1);

	switch (cmd) {
	case DC_GETFLAGS:		/* query */
		oldflags = thr_data->Dcflags;
		break;
	case DC_SETFLAGS:		/* set */
		oldflags = thr_data->Dcflags;
		thr_data->Dcflags = newflags;
		break;
	default:			/* error */
		oldflags = -1;
		break;
	}

	return (oldflags);
}

/*
 *	strip_quotes -- strip double (") or single (') quotes from a buffer
 *
 *	ENTRY
 *	  ptr		initial string
 *
 *	EXIT
 *	  ptr		string with quotes (if any) removed
 */
static void
strip_quotes(char *ptr)
{
	char *strip_ptr = NULL;

	while (*ptr != '\0') {
		if ((*ptr == '"') || (*ptr == '\'')) {
			if (strip_ptr == NULL)
				strip_ptr = ptr;	/* skip over quote */
		} else {
			if (strip_ptr != NULL) {
				*strip_ptr = *ptr;
				strip_ptr++;
			}
		}
		ptr++;
	}
	if (strip_ptr != NULL) {
		*strip_ptr = '\0';
	}
}
