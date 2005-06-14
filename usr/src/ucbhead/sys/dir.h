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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef _SYS_DIR_H
#define	_SYS_DIR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/isa_defs.h>
#include <sys/int_types.h>

/*
 * This header file provides BSD compatibility for DIR and direct structures.
 * The fields in the BSD DIR structure are identical to to the SVR4 DIR
 * structure, except for the fact that the dd_buf field in SVR4 is not
 * statically allocated.
 * The BSD direct structure is similar (not identical) to the dirent
 * structure. All fields of the direct structure can be obtained using
 * the information provided by dirent.
 * All routines manipulating DIR structures are compatible, only readdir
 * is not. The BSD version of this routine returns a direct structure.
 */

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(KERNEL) && !defined(DEV_BSIZE)
#define	DEV_BSIZE	512
#endif
#define	DIRBUF		8192
#define	DIRBLKSIZ	DIRBUF
#define	MAXNAMLEN	255

#if _FILE_OFFSET_BITS == 32
struct	direct {
	ulong_t	d_ino;			/* inode number of entry */
	ushort_t d_reclen;		/* length of this record */
	ushort_t d_namlen;		/* length of string in d_name */
	char	d_name[MAXNAMLEN+1];	/* name of entry */
};
#elif _FILE_OFFSET_BITS == 64
struct	direct {
	ino_t	d_ino;			/* inode number of entry */
	ushort_t d_reclen;		/* length of this record */
	ushort_t d_namlen;		/* length of string in d_name */
	char	d_name[MAXNAMLEN+1];	/* name of entry */
};
#endif
#if	defined(_LARGEFILE64_SOURCE)
struct	direct64 {
	ino64_t	d_ino;			/* inode number of entry */
	ushort_t d_reclen;		/* length of this record */
	ushort_t d_namlen;		/* length of string in d_name */
	char	d_name[MAXNAMLEN+1];	/* name of entry */
};
#endif

/*
 * The macro DIRSIZ(dp) gives an amount of space required to represent
 * a directory entry.
 */
#undef DIRSIZ
#undef DIRSIZ64

#if _FILE_OFFSET_BITS == 32
#define	DIRSIZ(dp)  \
	((sizeof (struct direct) - sizeof ((dp)->d_name) + \
	(strlen((dp)->d_name)+1) + 3) & ~3)
#elif _FILE_OFFSET_BITS == 64
#define	DIRSIZ(dp)  \
	((sizeof (struct direct64) - sizeof ((dp)->d_name) + \
	(strlen((dp)->d_name)+1) + 3) & ~3)
#endif
#if	defined(_LARGEFILE64_SOURCE)
#define	DIRSIZ64(dp)  \
	((sizeof (struct direct64) - sizeof ((dp)->d_name) + \
	(strlen((dp)->d_name)+1) + 3) & ~3)
#endif

#ifndef KERNEL
/*
 * Definitions for library routines operating on directories.
 */
typedef struct _dirdesc {
	int	dd_fd;
	int	dd_loc;
	int	dd_size;
	char	*dd_buf;
} DIR;

#ifndef NULL
#define	NULL 0
#endif

#if defined(_LP64) && defined(_LARGEFILE64_SOURCE)
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	readdir64		readdir
#pragma redefine_extname	scandir64		scandir
#pragma redefine_extname	alphasort64	alphasort
#else
#define	readdir64			readdir
#define	scandir64			scandir
#define	alphasort64		alphasort
#define	direct64		direct
#endif
#endif

#if !defined(_LP64) && (_FILE_OFFSET_BITS == 64)
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	readdir		readdir64
#pragma redefine_extname	scandir		scandir64
#pragma redefine_extname	alphasort	alphasort64
#else
#define	readdir			readdir64
#define	scandir			scandir64
#define	alphasort		alphasort64
#define	direct			direct64
#endif
#endif

#if defined(__STDC__)
extern DIR		*opendir(const char *);
extern struct direct    *readdir(DIR *);
extern long		telldir(DIR *);
extern void		seekdir(DIR *, long);
extern int		scandir(char *, struct direct *(*[]),
			    int (*)(struct direct *),
			    int (*)(struct direct **, struct direct **));
extern int		alphasort(struct direct **, struct direct **);
extern void		rewinddir(DIR *);
extern int		closedir(DIR *);
#else
extern	DIR *opendir();
extern	struct direct *readdir();
extern	long telldir();
extern	void seekdir();
extern	int scandir();
extern	int alphasort();
extern  void rewinddir();
extern	void closedir();
#endif

#if	defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
	    !defined(__PRAGMA_REDEFINE_EXTNAME))
#if defined(__STDC__)
extern struct direct64	*readdir64(DIR *);
extern int		scandir64(char *, struct direct64 *(*[]),
			    int (*)(struct direct64 *),
			    int (*)(struct direct64 **, struct direct64 **));
extern int		alphasort64(struct direct64 **, struct direct64 **);
#else
extern struct direct64	*readdir64();
extern int		scandir64();
extern int		alphasort64();
#endif
#endif	/* _LARGEFILE64_SOURCE... */

#define	rewinddir(dirp)	seekdir((dirp), 0)

#endif

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_DIR_H */
