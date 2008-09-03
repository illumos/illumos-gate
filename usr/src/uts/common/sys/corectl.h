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

#ifndef _SYS_CORECTL_H
#define	_SYS_CORECTL_H

#include <sys/types.h>
#include <sys/zone.h>
#include <sys/refstr.h>
#include <sys/mutex.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definitions for corectl() system call.
 */

/* subcodes */
#define	CC_SET_OPTIONS		1
#define	CC_GET_OPTIONS		2
#define	CC_SET_GLOBAL_PATH	3
#define	CC_GET_GLOBAL_PATH	4
#define	CC_SET_PROCESS_PATH	5
#define	CC_GET_PROCESS_PATH	6
#define	CC_SET_GLOBAL_CONTENT	7
#define	CC_GET_GLOBAL_CONTENT	8
#define	CC_SET_PROCESS_CONTENT	9
#define	CC_GET_PROCESS_CONTENT	10
#define	CC_SET_DEFAULT_PATH	11
#define	CC_GET_DEFAULT_PATH	12
#define	CC_SET_DEFAULT_CONTENT	13
#define	CC_GET_DEFAULT_CONTENT	14

/* options */
#define	CC_GLOBAL_PATH		0x01	/* enable global core files */
#define	CC_PROCESS_PATH		0x02	/* enable per-process core files */
#define	CC_GLOBAL_SETID		0x04	/* allow global setid core files */
#define	CC_PROCESS_SETID	0x08	/* allow per-process setid core files */
#define	CC_GLOBAL_LOG		0x10	/* log global core dumps to syslog */

/* all of the above */
#define	CC_OPTIONS	\
	(CC_GLOBAL_PATH | CC_PROCESS_PATH | \
	CC_GLOBAL_SETID | CC_PROCESS_SETID | CC_GLOBAL_LOG)

/* contents */
#define	CC_CONTENT_STACK	0x0001ULL /* process stack */
#define	CC_CONTENT_HEAP		0x0002ULL /* process heap */

/* MAP_SHARED file mappings */
#define	CC_CONTENT_SHFILE	0x0004ULL /* file-backed shared mapping */
#define	CC_CONTENT_SHANON	0x0008ULL /* anonymous shared mapping */

/* MAP_PRIVATE file mappings */
#define	CC_CONTENT_TEXT		0x0010ULL /* read/exec file mappings */
#define	CC_CONTENT_DATA		0x0020ULL /* writable file mappings */
#define	CC_CONTENT_RODATA	0x0040ULL /* read-only file mappings */
#define	CC_CONTENT_ANON		0x0080ULL /* anonymous mappings (MAP_ANON) */

#define	CC_CONTENT_SHM		0x0100ULL /* System V shared memory */
#define	CC_CONTENT_ISM		0x0200ULL /* intimate shared memory */
#define	CC_CONTENT_DISM		0x0400ULL /* dynamic intimate shared memory */

#define	CC_CONTENT_CTF		0x0800ULL /* CTF data */
#define	CC_CONTENT_SYMTAB	0x1000ULL /* symbol table */

#define	CC_CONTENT_ALL		0x1fffULL
#define	CC_CONTENT_NONE		0ULL
#define	CC_CONTENT_DEFAULT	(CC_CONTENT_STACK | CC_CONTENT_HEAP | \
	CC_CONTENT_ISM | CC_CONTENT_DISM | CC_CONTENT_SHM | \
	CC_CONTENT_SHANON | CC_CONTENT_TEXT | CC_CONTENT_DATA | \
	CC_CONTENT_RODATA | CC_CONTENT_ANON | CC_CONTENT_CTF | \
	CC_CONTENT_SYMTAB)
#define	CC_CONTENT_INVALID	(-1ULL)

typedef u_longlong_t	core_content_t;

typedef struct corectl_content {
	core_content_t	ccc_content;
	kmutex_t	ccc_mtx;
	uint32_t	ccc_refcnt;
} corectl_content_t;

typedef struct corectl_path {
	refstr_t	*ccp_path;
	kmutex_t	ccp_mtx;
	uint32_t	ccp_refcnt;
} corectl_path_t;

#ifdef _KERNEL

struct core_globals {
	kmutex_t		core_lock;
	refstr_t		*core_file;
	uint32_t		core_options;
	core_content_t		core_content;
	rlim64_t		core_rlimit;
	corectl_path_t		*core_default_path;
	corectl_content_t	*core_default_content;
};

extern	zone_key_t	core_zone_key;

extern void init_core(void);
extern void set_core_defaults(void);

extern core_content_t corectl_content_value(corectl_content_t *);
extern void corectl_content_hold(corectl_content_t *);
extern void corectl_content_rele(corectl_content_t *);

extern refstr_t *corectl_path_value(corectl_path_t *);
extern void corectl_path_hold(corectl_path_t *);
extern void corectl_path_rele(corectl_path_t *);

#else	/* _KERNEL */

extern	int	core_set_options(int);
extern	int	core_get_options(void);
extern	int	core_set_global_path(const char *, size_t);
extern	int	core_get_global_path(char *, size_t);
extern	int	core_set_default_path(const char *, size_t);
extern	int	core_get_default_path(char *, size_t);
extern	int	core_set_process_path(const char *, size_t, pid_t);
extern	int	core_get_process_path(char *, size_t, pid_t);
extern	int	core_set_global_content(const core_content_t *);
extern	int	core_get_global_content(core_content_t *);
extern	int	core_set_default_content(const core_content_t *);
extern	int	core_get_default_content(core_content_t *);
extern	int	core_set_process_content(const core_content_t *, pid_t);
extern	int	core_get_process_content(core_content_t *, pid_t);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CORECTL_H */
