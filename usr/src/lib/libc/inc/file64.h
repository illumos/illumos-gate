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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2020 Robert Mustacchi
 */

/*
 * This is the header where the internal to libc definition of the FILE
 * structure is defined. The exrernal defintion defines the FILE structure
 * as an array of longs. This prevents customers from writing code that
 * depends upon the implemnetation of stdio. The __fbufsize(3C) man page
 * documents a set of routines that customers can use so that they do not
 * need access to the FILE structure.
 *
 * When compiling libc this file MUST be included BEFORE <stdio.h>, and
 * any other headers that themselves directly or indirectly include
 * <stdio.h>. Failure to do so, will cause the compile of libc to fail,
 * since the structure members will not be visible to the stdio routines.
 */

#ifndef	_FILE64_H
#define	_FILE64_H

#include <synch.h>
#include <stdio_tag.h>
#include <wchar_impl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_MBSTATE_T
#define	_MBSTATE_T
typedef __mbstate_t	mbstate_t;
#endif

#define	rmutex_t	mutex_t

typedef ssize_t (*fread_t)(__FILE *, char *, size_t);
typedef ssize_t (*fwrite_t)(__FILE *, const char *, size_t);
typedef off_t (*fseek_t)(__FILE *, off_t, int);
typedef int (*fclose_t)(__FILE *);

typedef struct {
	fread_t	std_read;
	fwrite_t std_write;
	fseek_t std_seek;
	fclose_t std_close;
	void *std_data;
} stdio_ops_t;

#ifdef	_LP64

/*
 * This structure cannot grow beyond its current size of 128 bytes. See the file
 * lib/libc/port/stdio/README.design for more information.
 */
struct __FILE_TAG {
	unsigned char	*_ptr;	/* next character from/to here in buffer */
	unsigned char	*_base;	/* the buffer */
	unsigned char	*_end;	/* the end of the buffer */
	ssize_t		_cnt;	/* number of available characters in buffer */
	int		_file;	/* UNIX System file descriptor */
	unsigned int	_flag;	/* the state of the stream */
	rmutex_t	_lock;	/* lock for this structure */
	mbstate_t	_state;	/* mbstate_t */
	stdio_ops_t	*_ops;	/* Alternate impl ops */
	char		__fill[24];	/* filler to bring size to 128 bytes */
};

#else

/*
 * Stuff missing from our 32-bit FILE struct.
 */
struct xFILEdata {
	uintptr_t	_magic;	/* Check: magic number, must be first */
	unsigned char	*_end;	/* the end of the buffer */
	rmutex_t	_lock;	/* lock for this structure */
	mbstate_t	_state;	/* mbstate_t */
	int		_altfd;	/* alternate fd if > 255 */
	stdio_ops_t	*_ops;	/* Alternate impl ops */
};

#define	XFILEINITIALIZER	{ 0, NULL, RECURSIVEMUTEX, DEFAULTMBSTATE }

#endif	/*	_LP64	*/

#ifdef	__cplusplus
}
#endif

#endif	/* _FILE64_H */
