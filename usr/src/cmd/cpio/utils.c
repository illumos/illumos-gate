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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved					*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>

#include "cpio.h"

/*
 * Allocation wrappers.  Used to centralize error handling for
 * failed allocations.
 */
static void *
e_alloc_fail(int flag)
{
	if (flag == E_EXIT)
		msg(EXTN, "Out of memory");

	return (NULL);
}

/*
 *  Note: unlike the other e_*lloc functions, e_realloc does not zero out the
 *  additional memory it returns.  Ensure that you do not trust its contents
 *  when you call it.
 */
void *
e_realloc(int flag, void *old, size_t newsize)
{
	void *ret = realloc(old, newsize);

	if (ret == NULL) {
		return (e_alloc_fail(flag));
	}

	return (ret);
}

char *
e_strdup(int flag, const char *arg)
{
	char *ret = strdup(arg);

	if (ret == NULL) {
		return (e_alloc_fail(flag));
	}

	return (ret);
}

void *
e_valloc(int flag, size_t size)
{
	void *ret = valloc(size);

	if (ret == NULL) {
		return (e_alloc_fail(flag));
	}

	return (ret);
}

void *
e_zalloc(int flag, size_t size)
{
	void *ret = malloc(size);

	if (ret == NULL) {
		return (e_alloc_fail(flag));
	}

	(void) memset(ret, 0, size);
	return (ret);
}

/*
 * Simple printf() which only support "%s" conversion.
 * We need secure version of printf since format string can be supplied
 * from gettext().
 */
void
str_fprintf(FILE *fp, const char *fmt, ...)
{
	const char *s = fmt;
	va_list	ap;

	va_start(ap, fmt);
	while (*s != '\0') {
		if (*s != '%') {
			(void) fputc(*s++, fp);
			continue;
		}
		s++;
		if (*s != 's') {
			(void) fputc(*(s - 1), fp);
			(void) fputc(*s++, fp);
			continue;
		}
		(void) fputs(va_arg(ap, char *), fp);
		s++;
	}
	va_end(ap);
}

/*
 * Step through a file discovering and recording pairs of data and hole
 * offsets. Returns a linked list of data/hole offset pairs of a file.
 * If there is no holes found, NULL is returned.
 *
 * Note: According to lseek(2), only filesystems which support
 * fpathconf(_PC_MIN_HOLE_SIZE) support SEEK_HOLE.  For filesystems
 * that do not supply information about holes, the file will be
 * represented as one entire data region.
 */
static holes_list_t *
get_holes_list(int fd, off_t filesz, size_t *countp)
{
	off_t	data, hole;
	holes_list_t *hlh, *hl, **hlp;
	size_t	cnt;

	if (filesz == 0 || fpathconf(fd, _PC_MIN_HOLE_SIZE) < 0)
		return (NULL);

	cnt = 0;
	hole = 0;
	hlh = NULL;
	hlp = &hlh;

	while (hole < filesz) {
		if ((data = lseek(fd, hole, SEEK_DATA)) == -1) {
			/* no more data till the end of file */
			if (errno == ENXIO) {
				data = filesz;
			} else {
				/* assume data starts from the * beginning */
				data = 0;
			}
		}
		if ((hole = lseek(fd, data, SEEK_HOLE)) == -1) {
			/* assume that data ends at the end of file */
			hole = filesz;
		}
		if (data == 0 && hole == filesz) {
			/* no holes */
			break;
		}
		hl = e_zalloc(E_EXIT, sizeof (holes_list_t));
		hl->hl_next = NULL;

		/* set data and hole */
		hl->hl_data = data;
		hl->hl_hole = hole;

		*hlp = hl;
		hlp = &hl->hl_next;
		cnt++;
	}
	if (countp != NULL)
		*countp = cnt;

	/*
	 * reset to the beginning, otherwise subsequent read calls would
	 * get EOF
	 */
	(void) lseek(fd, 0, SEEK_SET);

	return (hlh);
}

/*
 * Calculate the real data size in the sparse file.
 */
static off_t
get_compressed_filesz(holes_list_t *hlh)
{
	holes_list_t *hl;
	off_t	size;

	size = 0;
	for (hl = hlh; hl != NULL; hl = hl->hl_next) {
		size += (hl->hl_hole - hl->hl_data);
	}
	return (size);
}

/*
 * Convert val to digit string and put it in str. The next address
 * of the last digit is returned.
 */
static char *
put_value(off_t val, char *str)
{
	size_t	len;
	char	*digp, dbuf[ULL_MAX_SIZE + 1];

	dbuf[ULL_MAX_SIZE] = '\0';
	digp = ulltostr((u_longlong_t)val, &dbuf[ULL_MAX_SIZE]);
	len = &dbuf[ULL_MAX_SIZE] - digp;
	(void) memcpy(str, digp, len);

	return (str + len);
}

/*
 * Put data/hole offset pair into string in the following
 * sequence.
 * <data> <sp> <hole> <sp>
 */
static void
store_sparse_string(holes_list_t *hlh, char *str, size_t *szp)
{
	holes_list_t *hl;
	char	*p;

	p = str;
	for (hl = hlh; hl != NULL; hl = hl->hl_next) {
		p = put_value(hl->hl_data, p);
		*p++ = ' ';
		p = put_value(hl->hl_hole, p);
		*p++ = ' ';
	}
	*--p = '\0';
	if (szp != NULL)
		*szp = p - str;
}

/*
 * Convert decimal str into unsigned long long value. The end pointer
 * is returned.
 */
static const char *
get_ull_tok(const char *str, uint64_t *ulp)
{
	uint64_t ul;
	char	*np;

	while (isspace(*str))
		str++;
	if (!isdigit(*str))
		return (NULL);

	errno = 0;
	ul = strtoull(str, &np, 10);
	if (ul == ULLONG_MAX && errno == ERANGE)
		return (NULL);		/* invalid value */
	if (*np != ' ' && *np != '\0')
		return (NULL);		/* invalid input */

	*ulp = ul;
	return (np);
}

static void
free_holesdata(holes_info_t *hi)
{
	holes_list_t	*hl, *nhl;

	for (hl = hi->holes_list; hl != NULL; hl = nhl) {
		nhl = hl->hl_next;
		free(hl);
	}
	hi->holes_list = NULL;

	if (hi->holesdata != NULL)
		free(hi->holesdata);
	hi->holesdata = NULL;
}

/*
 * When a hole is detected, non NULL holes_info pointer is returned.
 * If we are in copy-out mode, holes_list is converted to string (holesdata)
 * which will be prepended to file contents. The holesdata is a character
 * string and in the format of:
 *
 * <data size(%10u)><SP><file size(%llu)><SP>
 *   <SP><data off><SP><hole off><SP><data off><SP><hole off> ...
 *
 * This string is parsed by parse_holesholes() in copy-in mode to restore
 * the sparse info.
 */
holes_info_t *
get_holes_info(int fd, off_t filesz, boolean_t pass_mode)
{
	holes_info_t *hi;
	holes_list_t *hl;
	char	*str, hstr[MIN_HOLES_HDRSIZE + 1];
	size_t	ninfo, len;

	if ((hl = get_holes_list(fd, filesz, &ninfo)) == NULL)
		return (NULL);

	hi = e_zalloc(E_EXIT, sizeof (holes_info_t));
	hi->holes_list = hl;

	if (!pass_mode) {
		str = e_zalloc(E_EXIT,
		    MIN_HOLES_HDRSIZE + ninfo * (ULL_MAX_SIZE * 2));
		/*
		 * Convert into string data, and place it to after
		 * the first 2 fixed entries.
		 */
		store_sparse_string(hl, str + MIN_HOLES_HDRSIZE, &len);

		/*
		 * Add the first two fixed entries. The size of holesdata
		 * includes '\0' at the end of data
		 */
		(void) sprintf(hstr, "%10lu %20llu ",
		    (ulong_t)MIN_HOLES_HDRSIZE + len + 1, filesz);
		(void) memcpy(str, hstr, MIN_HOLES_HDRSIZE);

		/* calc real file size without holes */
		hi->data_size = get_compressed_filesz(hl);
		hi->holesdata = str;
		hi->holesdata_sz = MIN_HOLES_HDRSIZE + len + 1;
	}
	return (hi);
}

/*
 * The holesdata information is in the following format:
 * <data size(%10u)><SP><file size(%llu)><SP>
 *   <SP><data off><SP><hole off><SP><data off><SP><hole off> ...
 * read_holes_header() allocates holes_info_t, and read the first 2
 * entries (data size and file size). The rest of holesdata is
 * read by parse_holesdata().
 */
holes_info_t *
read_holes_header(const char *str, off_t filesz)
{
	holes_info_t	*hi;
	uint64_t	ull;

	hi = e_zalloc(E_EXIT, sizeof (holes_info_t));

	/* read prepended holes data size */
	if ((str = get_ull_tok(str, &ull)) == NULL || *str != ' ') {
bad:
		free(hi);
		return (NULL);
	}
	hi->holesdata_sz = (size_t)ull;

	/* read original(expanded) file size */
	if (get_ull_tok(str, &ull) == NULL)
		goto bad;
	hi->orig_size = (off_t)ull;

	/* sanity check */
	if (hi->holesdata_sz > filesz ||
	    hi->holesdata_sz <= MIN_HOLES_HDRSIZE) {
		goto bad;
	}
	return (hi);
}

int
parse_holesdata(holes_info_t *hi, const char *str)
{
	holes_list_t	*hl, **hlp;
	uint64_t	ull;
	off_t		loff;

	/* create hole list */
	hlp = &hi->holes_list;
	while (*str != '\0') {
		hl = e_zalloc(E_EXIT, sizeof (holes_list_t));
		/* link list */
		hl->hl_next = NULL;
		*hlp = hl;
		hlp = &hl->hl_next;

		/* read the string token for data */
		if ((str = get_ull_tok(str, &ull)) == NULL)
			goto bad;
		hl->hl_data = (off_t)ull;

		/* there must be single blank space in between */
		if (*str != ' ')
			goto bad;

		/* read the string token for hole */
		if ((str = get_ull_tok(str, &ull)) == NULL)
			goto bad;
		hl->hl_hole = (off_t)ull;
	}

	/* check to see if offset is in ascending order */
	loff = -1;
	for (hl = hi->holes_list; hl != NULL; hl = hl->hl_next) {
		if (loff >= hl->hl_data)
			goto bad;
		loff = hl->hl_data;
		/* data and hole can be equal */
		if (loff > hl->hl_hole)
			goto bad;
		loff = hl->hl_hole;
	}
	/* The last hole offset should match original file size */
	if (hi->orig_size != loff) {
bad:
		free_holesdata(hi);
		return (1);
	}

	hi->data_size = get_compressed_filesz(hi->holes_list);

	return (0);
}

void
free_holes_info(holes_info_t *hi)
{
	free_holesdata(hi);
	free(hi);
}
