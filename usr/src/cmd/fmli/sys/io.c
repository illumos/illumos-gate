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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<ctype.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	"wish.h"
#include	"eval.h"
#include	"terror.h"
#include	"moremacros.h"

#define INCREMENT	1024


/* only called once in evstr.c */
int
io_size(iop, size)
IOSTRUCT	*iop;
int size;
{
	/* ehr3 (not necessary given only call is in evstr.c)
	if (iop->mu.str.val)
		free(iop->mu.str.val);
	*/
	if ((iop->mu.str.val = malloc(size)) == NULL)
	    fatal(NOMEM, "");	/* abs k17 */
	return (0);
}

IOSTRUCT *
io_open(flags, ptr, next)
int	flags;
char	*ptr;
{
	register IOSTRUCT	*iop;

	iop = (IOSTRUCT *)new(IOSTRUCT);
	iop->flags = flags;
	iop->next = NULL;
	iop->mu.str.val = NULL; /* ehr3 */

	if (flags & EV_USE_FP)
		iop->mu.fp = (FILE *) ptr;
	else {
		iop->mu.str.pos = 0;

		if (ptr && *ptr) {
			iop->mu.str.count = strlen(ptr);

			if (flags & EV_READONLY)
				iop->mu.str.val = ptr;
			else
				iop->mu.str.val = strnsave(ptr, iop->mu.str.count + INCREMENT - 1 & ~(INCREMENT - 1));
		}
		else {
			iop->mu.str.val = NULL;
			iop->mu.str.count = 0;
		}
	}
	return iop;
}

int
io_clear(iop)
IOSTRUCT	*iop;
{
	if (!(iop->flags & EV_USE_STRING))
		return FAIL;
	iop->mu.str.pos = iop->mu.str.count = 0;
	return SUCCESS;
}

int
io_seek(iop, pos)
IOSTRUCT	*iop;
unsigned	pos;
{
	if (iop->flags & EV_USE_STRING)
		if (pos <= iop->mu.str.count)
			iop->mu.str.pos = pos;
		else
			return FAIL;
	else
		return fseek(iop->mu.fp, (long) pos, 0);
	return SUCCESS;
}

/*
 * CAVEAT:  This routine is DESTRUCTIVE for fp's, but NOT for strings!
 */
char *
io_string(iop)
IOSTRUCT	*iop;
{
	if (iop->flags & EV_USE_STRING) {
		if (iop->mu.str.val)
			return(strnsave(iop->mu.str.val, iop->mu.str.pos)); 
		else 
			return(strsave(nil));
	}
	else {
		register char	*buf;
		register int	fd;
		register int	size;
		struct stat	sbuf;
		long	lseek();

		fd = fileno(iop->mu.fp);

		if (fstat(fd, &sbuf) == 0) {
			size = (int) (sbuf.st_size - lseek(fd, 0L, 1));

			if (buf = malloc(size + 1)) {
				buf[read(fileno(iop->mu.fp), buf, size)] = '\0';
				return buf;
			}
		}

		return NULL;
	}
}

/*
 * be careful not to modify this string!
 * (unless, of course, you are going to io_seek to 0 right afterward)
 */
char *
io_ret_string(iop)
IOSTRUCT	*iop;
{
	if (iop->flags & EV_USE_STRING) {
		putac('\0', iop);
		iop->mu.str.count--;
		iop->mu.str.pos--;
		return iop->mu.str.val;
	}
	else
		/* not supported until we need it */
		return nil;
}

int
io_close(iop)
IOSTRUCT	*iop;
{
	if (iop->flags & EV_USE_FP)
		fclose(iop->mu.fp);
	else {
		if (!(iop->flags & EV_READONLY) && iop->mu.str.val) {
			free(iop->mu.str.val);
			iop->mu.str.val = NULL;	/* ehr3 */
		}
	}
	free(iop);
	return SUCCESS;
}

int
getac(iop)
IOSTRUCT	*iop;
{
	IOSTRUCT	*io_pop();

	if (iop->flags & EV_USE_STRING) {
		if (iop->mu.str.pos < iop->mu.str.count)
			return iop->mu.str.val[iop->mu.str.pos++];
	}
	else {
		register int	c;

		if ((c = getc(iop->mu.fp)) != EOF)
			return c;
	}
	if (io_pop(iop))
		return getac(iop);
	return '\0';
}

int
ungetac(c, iop)
int	c;
IOSTRUCT	*iop;
{
	if (iop->flags & EV_USE_STRING) {
		if (--iop->mu.str.pos < 0)
			++iop->mu.str.pos;
	}
	else
		ungetc(c, iop->mu.fp);
	return c;
}

int
putac(c, iop)
int	c;
IOSTRUCT *iop;
{
    if (iop->flags & EV_USE_STRING)
    {
	if ( !iop->mu.str.val )
	{
	    if ((iop->mu.str.val = malloc(INCREMENT)) == NULL)
		fatal(NOMEM, ""); /* abs k17 */
	}
	else		/* changed else clause to match putastr. abs k17 */
	{
	    int oldinc, newinc;

	    oldinc = iop->mu.str.pos / INCREMENT;
	    newinc = (iop->mu.str.pos + 1) / INCREMENT;
	    if (newinc > oldinc)
	    {
		/*
		 * reallocate (needed blocks * BLOCKSIZE)
		 */
		if ((iop->mu.str.val = realloc(iop->mu.str.val,
					       (++newinc) * INCREMENT)) == NULL)
		    fatal(NOMEM, "");
	    }
	}
/*	    if (!(iop->mu.str.pos & INCREMENT - 1) && iop->mu.str.pos)
**	    iop->mu.str.val =
**               realloc(iop->mu.str.val, iop->mu.str.pos + INCREMENT);
** abs k17 
*/
	iop->mu.str.val[iop->mu.str.pos++] = c;
	iop->mu.str.count = iop->mu.str.pos;
    }
    else
	putc(c, iop->mu.fp);
    return c;
}

int
unputac(iop)
IOSTRUCT	*iop;
{
	register int	c;

	if (!(iop->flags & EV_USE_STRING) || iop->mu.str.pos == 0)
		return 0;
	if (iop->mu.str.pos == iop->mu.str.count)
		--iop->mu.str.count;
	return iop->mu.str.val[--iop->mu.str.pos];
}

IOSTRUCT *
io_push(stack, iop)
IOSTRUCT	*stack;
IOSTRUCT	*iop;
{
	IOSTRUCT	tmp;

	tmp = *iop;
	*iop = *stack;
	*stack = tmp;
	stack->next = iop;
	return stack;
}

IOSTRUCT *
io_pop(stack)
IOSTRUCT	*stack;
{
	IOSTRUCT	*ptr;
	IOSTRUCT	tmp;

	if ((ptr = stack->next) == NULL)
		return NULL;

	tmp = *ptr;
	*ptr = *stack;
	*stack = tmp;
	io_close(ptr);
	return stack;
}

int
io_flags(iop, flags)
IOSTRUCT	*iop;
int	flags;
{
	int	tmp;

	tmp = iop->flags;
	iop->flags = flags;
	return tmp;
}

char *
getastr(s, n, iop)
char	*s;
int	n;
IOSTRUCT	*iop;
{
	register char	*p;
	register int	c;

	for (p = s; n > 1; p++) {
		if (c = getac(iop)) {
			*s++ = c;
			if (c == '\n')
				break;
		}
		else
			break;
	}
	if (n > 0)
		*s = '\0';
	return (p == s) ? NULL : s;
}

int
putastr(s, iop)
char	*s;
IOSTRUCT	*iop;
{
    if (iop->flags & EV_USE_STRING)
    {
	register int len, c;
	register int newinc, oldinc;
	int	strlen();
	char	*strcpy();

	len = strlen(s);
	if (!iop->mu.str.val)
	{
	    c = (len / INCREMENT) + 1;
	    if ((iop->mu.str.val = malloc(INCREMENT * c)) == NULL)
		fatal(NOMEM, ""); /* abs k17 */
	    iop->mu.str.pos = 0;
	}
	else
	{
	    oldinc = iop->mu.str.pos / INCREMENT;
	    newinc = (iop->mu.str.pos + len) / INCREMENT;
	    if (newinc > oldinc)
	    {
		/*
		 * reallocate (needed blocks * BLOCKSIZE)
		 */
		if ((iop->mu.str.val = realloc(iop->mu.str.val,
		    (++newinc) * INCREMENT)) == NULL)
			fatal(NOMEM, "");
	    }
	}
	strcpy(iop->mu.str.val + iop->mu.str.pos, s);
	iop->mu.str.count = iop->mu.str.pos += len;
    }
    else
	fputs(s, iop->mu.fp);

	/*
	 * original body of putastr
	 * while (*s)
	 * putac(*s++, iop);
	 */
	return (0);
}
