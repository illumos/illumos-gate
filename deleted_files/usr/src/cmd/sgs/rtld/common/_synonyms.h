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

#ifndef	__SYNONYMS_H
#define	__SYNONYMS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Some synonyms definitions - the intent here is to insure we get the base
 * libc functionality without any thread interposition switch code.
 */
#if	!defined(__lint)
#define	close		_close
#define	fstat		_fstat
#define	ftruncate	_ftruncate
#define	getcwd		_getcwd
#define	getdents	_getdents
#define	getegid		_getegid
#define	geteuid		_geteuid
#define	getgid		_getgid
#define	getpid		_getpid
#define	getugid		_getugid
#define	getuid		_getuid
#define	ioctl		_ioctl
#ifdef	SGS_PRE_UNIFIED_PROCESS
#define	kill		_libc_kill
#else
#define	kill		_kill
#endif
#define	madvise		_madvise
#define	memcpy		_memcpy
#define	memmove		_memmove
#define	memset		_memset
#define	mmap		_mmap
#define	mprotect	_mprotect
#define	munmap		_munmap
#define	open		_open
#define	profil		_profil
#define	resolvepath	_resolvepath
#define	stat		_stat
#define	strdup		_strdup
#define	strerror	_strerror
#define	strtok_r	_strtok_r
#define	sysinfo		_sysinfo
#define	umask		_umask
#define	write		_write

#endif /* !defined(__lint) */

#ifdef	__cplusplus
}
#endif

#endif /* __SYNONYMS_H */
