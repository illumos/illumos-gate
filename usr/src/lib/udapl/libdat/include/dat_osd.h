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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dat_osd.h
 *
 * PURPOSE: Operating System Dependent layer
 * Description:
 *	Provide OS dependent data structures & functions with
 *	a canonical DAT interface. Designed to be portable
 *	and hide OS specific quirks of common functions.
 *
 * $Id: dat_osd.h,v 1.14 2003/07/31 14:04:19 jlentini Exp $
 */

#ifndef _DAT_OSD_H_
#define	_DAT_OSD_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <dat/udat.h>

#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/time.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *
 * Debugging
 *
 */

#define	dat_os_assert(expr)	assert(expr)

typedef int 			DAT_OS_DBG_TYPE_VAL;

typedef enum
{
    DAT_OS_DBG_TYPE_ERROR 		= 0x1,
    DAT_OS_DBG_TYPE_GENERIC 		= 0x2,
    DAT_OS_DBG_TYPE_SR  		= 0x4,
    DAT_OS_DBG_TYPE_DR  		= 0x8,
    DAT_OS_DBG_TYPE_PROVIDER_API 	= 0x10,
    DAT_OS_DBG_TYPE_CONSUMER_API 	= 0x20,
    DAT_OS_DBG_TYPE_ALL 		= 0xff
} DAT_OS_DBG_TYPE;

extern void
dat_os_dbg_init(void);

extern void
dat_os_dbg_print(
	DAT_OS_DBG_TYPE_VAL		type,
	const char			*fmt,
	...);


/*
 *
 * Utility Functions
 *
 */

#define	DAT_ERROR(Type, SubType) ((DAT_RETURN)(DAT_CLASS_ERROR | Type | \
					SubType))

typedef size_t 			DAT_OS_SIZE;
typedef void * 			DAT_OS_LIBRARY_HANDLE;

extern DAT_RETURN
dat_os_library_load(
    const char 			*library_path,
    DAT_OS_LIBRARY_HANDLE 	*library_handle_ptr);

extern DAT_RETURN
dat_os_library_unload(
    const DAT_OS_LIBRARY_HANDLE library_handle);

/*
 * void *dat_os_library_sym(DAT_OS_LIBRARY_HANDLE library_handle, char *sym)
 */
#define	dat_os_library_sym(libhndl, sym)	dlsym((libhndl), (sym))

/* char *dat_os_getenv(const char *name) */
#define	dat_os_getenv(name)	getenv((name))

/* long int dat_os_strtol(const char *nptr, char **endptr, int base) */
#define	dat_os_strtol(nptr, endptr, base)	strtol((nptr), (endptr), (base))

/* DAT_OS_SIZE dat_os_strlen(const char *s) */
#define	dat_os_strlen(s)	strlen((s))

/* int dat_os_strncmp(const char *s1, const char *s2, DAT_OS_SIZE n) */
#define	dat_os_strncmp(s1, s2, n)	strncmp((s1), (s2), (n))

/* void * dat_os_strncpy(char *dest, const char *src, DAT_OS_SIZE len) */
#define	dat_os_strncpy(dest, src, len)	strncpy((dest), (src), (len))

/* DAT_BOOLEAN dat_os_isblank(int c) */
#define	dat_os_isblank(c)	((DAT_BOOLEAN)((' ' == (c)) || ('\t' == (c))) \
					? DAT_TRUE : DAT_FALSE)


/* DAT_BOOLEAN dat_os_isdigit(int c) */
#define	dat_os_isdigit(c)	((DAT_BOOLEAN)(isdigit((c)) ? DAT_TRUE : \
					DAT_FALSE))

/* void dat_os_usleep(unsigned long usec) */
#define	dat_os_usleep(usec)	usleep((usec))

/*
 *
 * Memory Functions
 *
 */

/* void *dat_os_alloc(int size) */
#define	dat_os_alloc(size)	malloc((size))

/* void dat_os_free(void *ptr, int size) */
#define	dat_os_free(ptr, size)	free((ptr))

/* void *dat_os_memset(void *loc, int c, DAT_OS_SIZE size) */
#define	dat_os_memset(loc, c, size)	memset((loc), (c), (size))

/*
 *
 * File I/O
 *
 */

typedef FILE 			DAT_OS_FILE;
typedef fpos_t			DAT_OS_FILE_POS;

/*
 * DAT_OS_FILE *dat_os_fopen(const char	*path)
 * always open files in read only mode
 */
#define	dat_os_fopen(path)	((DAT_OS_FILE *)fopen((path), "rF"))


/* DAT_RETURN dat_os_fgetpos(DAT_OS_FILE *file, DAT_OS_FILE_POS *pos) */
#define	dat_os_fgetpos(file, pos)	((DAT_RETURN)(			\
			(0 == fgetpos((file), (pos))) ? DAT_SUCCESS :	\
			DAT_INTERNAL_ERROR))

/* DAT_RETURN dat_os_fsetpos(DAT_OS_FILE *file, DAT_OS_FILE_POS *pos) */
#define	dat_os_fsetpos(file, pos)	((DAT_RETURN)(			\
			(0 == fsetpos((file), (pos))) ? DAT_SUCCESS :	\
			DAT_INTERNAL_ERROR))

/*
 * dat_os_fgetc() returns EOF on error or end of file.
 * int dat_os_fgetc(DAT_OS_FILE *file)
 */
#define	dat_os_fgetc(file)	fgetc((file))


/* int dat_os_fputc(DAT_OS_FILE *file, int c) */
#define	dat_os_fputc(file, c)	fputc((c), (file))

/* int dat_os_fungetc(DAT_OS_FILE *file) */
#define	dat_os_fungetc(file)	fseek((file), -1, SEEK_CUR)

/*
 * dat_os_fread returns the number of bytes read from the file.
 * DAT_OS_SIZE dat_os_fread(DAT_OS_FILE *file, char *buf, DAT_OS_SIZE len)
 */
#define	dat_os_fread(file, buf, len)	fread((buf), sizeof (char),	\
						(len), (file))

/* DAT_RETURN dat_os_fclose(DAT_OS_FILE *file) */
#define	dat_os_fclose(file)	((0 == fclose(file)) ? DAT_SUCCESS :	\
					DAT_INTERNAL_ERROR)

/*
 *
 * Locks
 *
 */

typedef pthread_mutex_t 	DAT_OS_LOCK;


/* lock functions */
/*
 * DAT_RETURN dat_os_lock_init(IN DAT_OS_LOCK *m)
 */
#define	dat_os_lock_init(m)	((0 == pthread_mutex_init((m), NULL)) ?	\
					DAT_SUCCESS : DAT_INTERNAL_ERROR)

/* DAT_RETURN dat_os_lock(IN DAT_OS_LOCK *m) */
#define	dat_os_lock(m)		((DAT_RETURN)(				\
				(0 == pthread_mutex_lock((m))) ?	\
					DAT_SUCCESS : DAT_INTERNAL_ERROR))

/* DAT_RETURN dat_os_unlock(IN DAT_OS_LOCK *m) */
#define	dat_os_unlock(m)	((DAT_RETURN)(				\
				(0 == pthread_mutex_unlock((m))) ?	\
					DAT_SUCCESS : DAT_INTERNAL_ERROR))

/* DAT_RETURN dat_os_lock_destroy(IN DAT_OS_LOCK *m) */
#define	dat_os_lock_destroy(m)	((DAT_RETURN)(				\
				(0 == pthread_mutex_destroy((m))) ?	\
					DAT_SUCCESS : DAT_INTERNAL_ERROR))

/*
 * Simple macro to verify a handle is bad. Conditions:
 * - pointer is NULL
 * - pointer is not word aligned
 */
#define	DAT_BAD_HANDLE(h) (((h) == NULL) || ((unsigned long)(h) & 3))

#ifdef	__cplusplus
}
#endif

#endif	/* _DAT_OSD_H_ */
