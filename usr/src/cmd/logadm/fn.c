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
 *
 * logadm/fn.c -- "filename" string module
 *
 * this file contains routines for the manipulation of filenames.
 * they aren't particularly fast (at least they weren't designed
 * for performance), but they are simple and put all the malloc/free
 * stuff for these strings in a central place.  most routines in
 * logadm that return filenames return a struct fn, and most routines
 * that return lists of strings return a struct fn_list.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <libintl.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "err.h"
#include "fn.h"

#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))

/*
 * constants controlling how we malloc space.  bigger means fewer
 * calls to malloc.  smaller means less wasted space.
 */
#define	FN_MIN 1024	/* initial size of string buffers */
#define	FN_MAX 10240	/* maximum size allowed before fatal "overflow" error */
#define	FN_INC 1024	/* increments in buffer size as strings grow */

/* info created by fn_new(), private to this module */
struct fn {
	char *fn_buf;		/* first location in buf */
	char *fn_buflast;	/* last location in buf */
	char *fn_rptr;		/* read pointer (next unread character) */
	char *fn_wptr;		/* write pointer (points at null terminator) */
	struct fn *fn_next;	/* next in list */
	struct stat fn_stbuf;
	int fn_n;
};

/* info created by fn_list_new(), private to this module */
struct fn_list {
	struct fn *fnl_first;	/* first element of list */
	struct fn *fnl_last;	/* last element of list */
	struct fn *fnl_rptr;	/* read pointer for iterating through list */
};

/*
 * fn_new -- create a new filename buffer, possibly with initial contents
 *
 * use like this:
 *	struct fn *fnp = fn_new("this is a string");
 */
struct fn *
fn_new(const char *s)
{
	struct fn *fnp = MALLOC(sizeof (struct fn));

	fnp->fn_n = -1;
	bzero(&fnp->fn_stbuf, sizeof (fnp->fn_stbuf));
	fnp->fn_next = NULL;

	/* if passed-in string contains at least 1 non-null character... */
	if (s != NULL && *s) {
		int len = strlen(s);
		int buflen = roundup(len + 1, FN_INC);

		/* start with buffer filled with passed-in string */
		fnp->fn_buf = MALLOC(buflen);
		fnp->fn_buflast = &fnp->fn_buf[buflen - 1];
		(void) strlcpy(fnp->fn_buf, s, buflen);
		fnp->fn_rptr = fnp->fn_buf;
		fnp->fn_wptr = &fnp->fn_buf[len];
	} else {
		/* start with empty buffer */
		fnp->fn_buf = MALLOC(FN_MIN);
		fnp->fn_buflast = &fnp->fn_buf[FN_MIN - 1];
		*fnp->fn_buf = '\0';
		fnp->fn_rptr = fnp->fn_buf;
		fnp->fn_wptr = fnp->fn_buf;
	}

	return (fnp);
}

/*
 * fn_dup -- duplicate a filename buffer
 */
struct fn *
fn_dup(struct fn *fnp)
{
	struct fn *ret = fn_new(fn_s(fnp));

	ret->fn_n = fnp->fn_n;
	ret->fn_stbuf = fnp->fn_stbuf;

	return (ret);
}

/*
 * fn_dirname -- return the dirname part of a filename
 */
struct fn *
fn_dirname(struct fn *fnp)
{
	char *ptr = NULL;
	struct fn *ret;
	char *buf;

	buf = fn_s(fnp);

	if (buf != NULL)
		ptr = strrchr(buf, '/');
	if (ptr == NULL || buf == NULL)
		return (fn_new("."));
	else {
		*ptr = '\0';
		ret = fn_new(buf);
		*ptr = '/';
		return (ret);
	}
}

/*
 * fn_setn -- set the "n" value for a filename
 *
 * the "n" value is initially -1, and is used by logadm to store
 * the suffix for rotated log files.  the function fn_list_popoldest()
 * looks at these "n" values when sorting filenames to determine which
 * old log file is the oldest and should be expired first.
 */
void
fn_setn(struct fn *fnp, int n)
{
	fnp->fn_n = n;
}

/*
 * fn_setstat -- store a struct stat with a filename
 *
 * the glob functions typically fill in these struct stats since they
 * have to stat while globbing anyway.  just turned out to be a common
 * piece of information that was conveniently stored with the associated
 * filename.
 */
void
fn_setstat(struct fn *fnp, struct stat *stp)
{
	fnp->fn_stbuf = *stp;
}

/*
 * fn_getstat -- return a pointer to the stat info stored by fn_setstat()
 */
struct stat *
fn_getstat(struct fn *fnp)
{
	return (&fnp->fn_stbuf);
}

/*
 * fn_free -- free a filename buffer
 */
void
fn_free(struct fn *fnp)
{
	if (fnp) {
		if (fnp->fn_buf)
			FREE(fnp->fn_buf);
		FREE(fnp);
	}
}

/*
 * fn_renew -- reset a filename buffer
 *
 * calling fn_renew(fnp, s) is the same as calling:
 *	fn_free(fnp);
 *	fn_new(s);
 */
void
fn_renew(struct fn *fnp, const char *s)
{
	fnp->fn_rptr = fnp->fn_wptr = fnp->fn_buf;
	fn_puts(fnp, s);
}

/*
 * fn_putc -- append a character to a filename
 *
 * this is the function that handles growing the filename buffer
 * automatically and calling err() if it overflows.
 */
void
fn_putc(struct fn *fnp, int c)
{
	if (fnp->fn_wptr >= fnp->fn_buflast) {
		int buflen = fnp->fn_buflast + 1 - fnp->fn_buf;
		char *newbuf;
		char *src;
		char *dst;

		/* overflow, allocate more space or die if at FN_MAX */
		if (buflen >= FN_MAX)
			err(0, "fn buffer overflow");
		buflen += FN_INC;
		newbuf = MALLOC(buflen);

		/* copy string into new buffer */
		src = fnp->fn_buf;
		dst = newbuf;

		/* just copy up to wptr, rest is history anyway */
		while (src < fnp->fn_wptr)
			*dst++ = *src++;
		fnp->fn_rptr = &newbuf[fnp->fn_rptr - fnp->fn_buf];
		FREE(fnp->fn_buf);
		fnp->fn_buf = newbuf;
		fnp->fn_buflast = &fnp->fn_buf[buflen - 1];
		fnp->fn_wptr = dst;
	}
	*fnp->fn_wptr++ = c;
	*fnp->fn_wptr = '\0';
}

/*
 * fn_puts -- append a string to a filename
 */
void
fn_puts(struct fn *fnp, const char *s)
{
	/* non-optimal, but simple! */
	while (s != NULL && *s)
		fn_putc(fnp, *s++);
}

/*
 * fn_putfn -- append a filename buffer to a filename
 */
void
fn_putfn(struct fn *fnp, struct fn *srcfnp)
{
	int c;

	fn_rewind(srcfnp);
	while (c = fn_getc(srcfnp))
		fn_putc(fnp, c);
}

/*
 * fn_rewind -- reset the "read pointer" to the beginning of a filename
 */
void
fn_rewind(struct fn *fnp)
{
	fnp->fn_rptr = fnp->fn_buf;
}

/*
 * fn_getc -- "read" the next character of a filename
 */
int
fn_getc(struct fn *fnp)
{
	if (fnp->fn_rptr > fnp->fn_buflast || *fnp->fn_rptr == '\0')
		return (0);

	return (*fnp->fn_rptr++);
}

/*
 * fn_peekc -- "peek" at the next character of a filename
 */
int
fn_peekc(struct fn *fnp)
{
	if (fnp->fn_rptr > fnp->fn_buflast || *fnp->fn_rptr == '\0')
		return (0);

	return (*fnp->fn_rptr);
}

/*
 * fn_s -- return a pointer to a null-terminated string containing the filename
 */
char *
fn_s(struct fn *fnp)
{
	return (fnp->fn_buf);
}

/*
 * fn_isgz -- return true if filename is *.gz
 */
boolean_t
fn_isgz(struct fn *fnp)
{
	size_t	len;
	char	*name;

	name = fnp->fn_buf;
	len = strlen(name);
	if (len > 3 && strcmp(name + len - 3, ".gz") == 0)
		return (B_TRUE);
	else
		return (B_FALSE);
}

/*
 * fn_list_new -- create a new list of filenames
 *
 * by convention, an empty list is represented by an allocated
 * struct fn_list which contains a NULL linked list, rather than
 * by a NULL fn_list pointer.  in other words:
 *
 *	struct fn_list *fnlp = some_func_returning_a_list();
 *	if (fn_list_empty(fnlp))
 *		...
 *
 * is preferable to checking if the fnlp returned is NULL.
 */
struct fn_list *
fn_list_new(const char * const *slist)
{
	struct fn_list *fnlp = MALLOC(sizeof (struct fn_list));

	fnlp->fnl_first = fnlp->fnl_last = fnlp->fnl_rptr = NULL;

	while (slist && *slist)
		fn_list_adds(fnlp, *slist++);

	return (fnlp);
}

/*
 * fn_list_dup -- duplicate a list of filenames
 */
struct fn_list *
fn_list_dup(struct fn_list *fnlp)
{
	struct fn_list *ret = fn_list_new(NULL);
	struct fn *fnp;

	fn_list_rewind(fnlp);
	while ((fnp = fn_list_next(fnlp)) != NULL)
		fn_list_addfn(ret, fn_dup(fnp));

	return (ret);
}

/*
 * fn_list_free -- free a list of filenames
 */
void
fn_list_free(struct fn_list *fnlp)
{
	struct fn *fnp;

	fn_list_rewind(fnlp);
	while ((fnp = fn_list_next(fnlp)) != NULL)
		fn_free(fnp);
	FREE(fnlp);
}

/*
 * fn_list_adds -- add a string to a list of filenames
 */
void
fn_list_adds(struct fn_list *fnlp, const char *s)
{
	fn_list_addfn(fnlp, fn_new(s));
}

/*
 * fn_list_addfn -- add a filename (i.e. struct fn *) to a list of filenames
 */
void
fn_list_addfn(struct fn_list *fnlp, struct fn *fnp)
{
	fnp->fn_next = NULL;
	if (fnlp->fnl_first == NULL)
		fnlp->fnl_first = fnlp->fnl_last = fnlp->fnl_rptr = fnp;
	else {
		fnlp->fnl_last->fn_next = fnp;
		fnlp->fnl_last = fnp;
	}
}

/*
 * fn_list_rewind -- reset the "read pointer" to the beginning of the list
 */
void
fn_list_rewind(struct fn_list *fnlp)
{
	fnlp->fnl_rptr = fnlp->fnl_first;
}

/*
 * fn_list_next -- return the filename at the read pointer and advance it
 */
struct fn *
fn_list_next(struct fn_list *fnlp)
{
	struct fn *ret = fnlp->fnl_rptr;

	if (fnlp->fnl_rptr == fnlp->fnl_last)
		fnlp->fnl_rptr = NULL;
	else if (fnlp->fnl_rptr != NULL)
		fnlp->fnl_rptr = fnlp->fnl_rptr->fn_next;

	return (ret);
}

/*
 * fn_list_addfn_list -- move filenames from fnlp2 to end of fnlp
 *
 * frees fnlp2 after moving all the filenames off of it.
 */
void
fn_list_addfn_list(struct fn_list *fnlp, struct fn_list *fnlp2)
{
	struct fn *fnp2 = fnlp2->fnl_first;
	struct fn *nextfnp2;

	/* for each fn in the second list... */
	while (fnp2) {
		if (fnp2 == fnlp2->fnl_last)
			nextfnp2 = NULL;
		else
			nextfnp2 = fnp2->fn_next;

		/* append it to the first list */
		fn_list_addfn(fnlp, fnp2);

		fnp2 = nextfnp2;
	}
	/* all the fn's were moved off the second list */
	fnlp2->fnl_first = fnlp2->fnl_last = fnlp2->fnl_rptr = NULL;

	/* done with the second list */
	fn_list_free(fnlp2);
}

/*
 * fn_list_appendrange -- append a range of characters to each filename in list
 *
 * range of characters appended is the character at *s up to but not including
 * the character at *limit.  NULL termination is not required.
 */
void
fn_list_appendrange(struct fn_list *fnlp, const char *s, const char *limit)
{
	struct fn *fnp = fnlp->fnl_first;
	struct fn *nextfnp;
	const char *ptr;

	/* for each fn in the list... */
	while (fnp != NULL) {
		if (fnp == fnlp->fnl_last)
			nextfnp = NULL;
		else
			nextfnp = fnp->fn_next;

		/* append the range */
		for (ptr = s; ptr < limit; ptr++)
			fn_putc(fnp, *ptr);

		fnp = nextfnp;
	}
}

/*
 * fn_list_totalsize -- sum up all the st_size fields in the stat structs
 */
off_t
fn_list_totalsize(struct fn_list *fnlp)
{
	struct fn *fnp;
	off_t ret = 0;

	fn_list_rewind(fnlp);
	while ((fnp = fn_list_next(fnlp)) != NULL)
		ret += fnp->fn_stbuf.st_size;

	return (ret);
}

/*
 * fn_list_popoldest -- remove oldest file from list and return it
 *
 * this function uses the "n" values (set by fn_setn()) to determine
 * which file is oldest, or when there's a tie it turns to the modification
 * times in the stat structs, or when there's still a tie lexical sorting.
 */
struct fn *
fn_list_popoldest(struct fn_list *fnlp)
{
	struct fn *fnp;
	struct fn *ret = NULL;

	fn_list_rewind(fnlp);
	while ((fnp = fn_list_next(fnlp)) != NULL)
		if (ret == NULL)
			ret = fnp;
		else if (fnp->fn_n > ret->fn_n ||
		    (fnp->fn_n == ret->fn_n &&
		    (fnp->fn_stbuf.st_mtime < ret->fn_stbuf.st_mtime ||
		    ((fnp->fn_stbuf.st_mtime == ret->fn_stbuf.st_mtime &&
		    strcmp(fnp->fn_buf, ret->fn_buf) > 0)))))
			ret = fnp;

	if (ret == NULL)
		return (NULL);

	/* oldest file is ret, remove it from list */
	if (fnlp->fnl_first == ret) {
		fnlp->fnl_first = ret->fn_next;
	} else {
		fn_list_rewind(fnlp);
		while ((fnp = fn_list_next(fnlp)) != NULL) {
			if (fnp->fn_next == ret) {
				fnp->fn_next = ret->fn_next;
				if (fnlp->fnl_last == ret)
					fnlp->fnl_last = fnp;
				break;
			}
		}
	}

	ret->fn_next = NULL;
	return (ret);
}

/*
 * fn_list_empty -- true if the list is empty
 */
boolean_t
fn_list_empty(struct fn_list *fnlp)
{
	return (fnlp->fnl_first == NULL);
}

/*
 * fn_list_count -- return number of filenames in list
 */
int
fn_list_count(struct fn_list *fnlp)
{
	int ret = 0;

	/*
	 * if this operation were more common, we'd cache the count
	 * in the struct fn_list, but it isn't very common so we just
	 * count 'em up here
	 */
	fn_list_rewind(fnlp);
	while (fn_list_next(fnlp) != NULL)
		ret++;

	return (ret);
}
