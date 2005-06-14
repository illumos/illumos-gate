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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MONV_H
#define	_MONV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Versioned monitor file
 *
 * Since this is not really a *shared* file between the compilers and OS
 * (each hold a separate copy), care must be taken to see that it is in
 * in sync with the compiler version.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	General object structure
 */
#ifndef	PROF_TYPES_PREDEFINED
typedef unsigned long long Index;
typedef unsigned long long Address;
typedef unsigned long long Size;
#endif

typedef struct _prof_object {
	unsigned int		type;
	unsigned int		version;
	Size			size;
} ProfObject;


#define	PROF_MAGIC		0x50524F46	/* "PROF" */
#define	PROF_MAJOR_VERSION	1
#define	PROF_MINOR_VERSION	0

typedef struct _prof_header {
	unsigned int		h_magic;
	unsigned short		h_major_ver;
	unsigned short		h_minor_ver;
	Size			size;
} ProfHeader;

/*
 *	Object types
 */
#define	PROF_DUMMY_T		-1		/* to be ignored by gprof */
#define	PROF_BUFFER_T		1
#define	PROF_CALLGRAPH_T	2
#define	PROF_MODULES_T		3

/*
 *	Object version numbers
 */
#define	PROF_BUFFER_VER		1
#define	PROF_CALLGRAPH_VER	1
#define	PROF_MODULES_VER	1

/*
 * Actual number of pcsample elements that can be held in 1Mb with
 * the size of (Address) equal to 8
 */
#define	PROF_BUFFER_SIZE	131072		/* 1 Mb */

typedef struct _prof_buffer {
	unsigned int		type;		/* PROF_BUFFER_T */
	unsigned int		version;	/* 1 */
	Size			size;
	Index			buffer;
	Size			bufsize;
} ProfBuffer;

typedef struct _prof_call_graph {
	unsigned int		type;		/* PROF_CALLGRAPH_T */
	unsigned int		version;	/* 1 */
	Size			size;
	Index			functions;
} ProfCallGraph;

typedef struct _prof_module_list {
	unsigned int		type;		/* PROF_MODULES_T */
	unsigned int		version;	/* 1 */
	Size			size;
	Index			modules;
} ProfModuleList;

typedef struct _prof_module {
	Index			next;
	Index			path;
	Address			startaddr;
	Address			endaddr;
} ProfModule;

typedef struct _prof_function {
	Index			next_to;
	Index			next_from;
	Address			frompc;
	Address			topc;
	unsigned long long	count;
	Index			next_hash;
} ProfFunction;

#ifdef	__cplusplus
}
#endif

#endif	/* _MONV_H */
