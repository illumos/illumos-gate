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
 * Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SORT_UTILITY_H
#define	_SORT_UTILITY_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/mman.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>

#include "types.h"

#define	CMDNAME	"sort"

#ifndef TRUE
#define	TRUE	1
#endif /* TRUE */

#ifndef FALSE
#define	FALSE	0
#endif /* FALSE */

#define	SGN(x)		(((x) == 0 ? 0 : ((x) > 0 ? 1 : -1)))
#define	MIN(x, y)	(((x) < (y)) ? (x) : (y))
#define	MAX(x, y)	(((x) > (y)) ? (x) : (y))

#define	SE_BAD_FIELD			1
#define	SE_BAD_SPECIFIER		2
#define	SE_BAD_STREAM			3
#define	SE_CANT_MMAP_FILE		4
#define	SE_CANT_OPEN_FILE		5
#define	SE_CANT_SET_SIGNAL		6
#define	SE_CAUGHT_SIGNAL		7
#define	SE_CHECK_ERROR			8
#define	SE_CHECK_FAILED			9
#define	SE_CHECK_SUCCEED		10
#define	SE_ILLEGAL_CHARACTER		11
#define	SE_INSUFFICIENT_DESCRIPTORS	12
#define	SE_INSUFFICIENT_MEMORY		13
#define	SE_MMAP_FAILED			14
#define	SE_MUNMAP_FAILED		15
#define	SE_READ_FAILED			16
#define	SE_REALLOCATE_BUFFER		17
#define	SE_STAT_FAILED			18
#define	SE_TOO_MANY_TEMPFILES		19
#define	SE_UNLINK_FAILED		20
#define	SE_USAGE			21
#define	SE_WRITE_FAILED			22
#define	SE_CLOSE_FAILED			23

#define	KILOBYTE			1024
#define	MEGABYTE			(1024 * KILOBYTE)

#define	AV_MEM_MULTIPLIER		3
#define	AV_MEM_DIVISOR			4

#define	OUTPUT_MODE	(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | \
    S_IWOTH)

#define	E_SUCCESS	0	/* Exit status for successful run */
#define	E_FAILED_CHECK	1	/* Exit status for failed check */
#define	E_ERROR		2	/* Exit status for other error */
#define	E_USAGE		E_ERROR	/* Exit status for usage error */

#define	EMSG_CHECK	\
    gettext("check option (-c) only for use with a single file\n")
#define	EMSG_MMAP	gettext("can't mmap %s")
#define	EMSG_MUNMAP	gettext("can't munmap %s")
#define	EMSG_REALLOC	gettext("unable to reallocate buffer")
#define	EMSG_ALLOC	gettext("unable to allocate memory")
#define	EMSG_OPEN	gettext("can't open %s")
#define	EMSG_READ	gettext("can't read %s")
#define	EMSG_WRITE	gettext("can't write %s")
#define	EMSG_STAT	gettext("can't stat %s")
#define	EMSG_CLOSE	gettext("can't close %s")
#define	EMSG_UNLINK	gettext("can't unlink %s")
#define	EMSG_ILLEGAL_CHAR gettext("can't translate illegal wide character\n")
#define	EMSG_TEMPORARY	gettext("temporary file template exhausted\n")
#define	EMSG_MEMORY	\
    gettext("insufficient memory; use -S option to increase allocation\n")
#define	EMSG_DESCRIPTORS gettext("insufficient available file descriptors\n")
#define	EMSG_SIGNAL	gettext("can't set signal handler for %s")
#define	EMSG_BADPRIME	gettext("internal file state corrupted\n")

#define	EMSG_UNKN_STREAM gettext("INTERNAL: stream of type %d seen\n")
#define	EMSG_UNKN_FIELD	gettext("INTERNAL: field of type %d seen\n")
#define	EMSG_UNKN_OPTION gettext("INTERNAL: option parser error\n")

#define	WMSG_NEWLINE_ADDED \
    gettext("missing NEWLINE added at end of input file %s\n")

extern void warn(const char *, ...);
extern void die(const char *, ...);
extern void usage(void);

extern void swap(void **, void **);

extern int bump_file_template();
extern char *get_file_template();
extern void set_file_template(char **);

extern void set_cleanup_chain(stream_t **);

extern void set_output_file(char *);
extern void set_output_guard(stream_t *);
extern void clear_output_guard(void);
extern void establish_output_guard(sort_t *);
extern void remove_output_guard();

extern void atexit_handler(void);

extern size_t available_memory(size_t);
extern void set_memory_ratio(sort_t *, int *, int *);

extern size_t strtomem(char *);
extern void *safe_realloc(void *, size_t);
extern void safe_free(void *);

extern void *xzmap(void *, size_t, int, int, off_t);
extern void hold_file_descriptor(void);
extern void release_file_descriptor(void);

extern void copy_line_rec(const line_rec_t *, line_rec_t *);
extern void trip_eof(FILE *f);

extern int cxwrite(int, char *, size_t);
extern int wxwrite(int, wchar_t *);

extern int xstreql(const char *, const char *);
extern int xstrneql(const char *, const char *, const size_t);
extern char *xstrnchr(const char *, const int, const size_t);
extern void xstrninv(char *, ssize_t, ssize_t);

extern int xwcsneql(const wchar_t *, const wchar_t *, const size_t);
extern wchar_t *xwsnchr(const wchar_t *, const wint_t, const size_t);
extern void xwcsninv(wchar_t *, ssize_t, ssize_t);

#ifdef _LITTLE_ENDIAN
extern void xwcsntomsb(wchar_t *, ssize_t);
#endif /* _LITTLE_ENDIAN */

extern wchar_t *xmemwchar(wchar_t *, wchar_t, ssize_t);

extern void xcp(char *, char *, off_t);
extern void xdump(FILE *, uchar_t *, size_t, int);

#ifdef DEBUG
#define	ASSERT(x) assert(x)
#else
#define	ASSERT(x)
#endif

#ifdef STATS
#define	__S(x) x
#else
#define	__S(x)
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SORT_UTILITY_H */
