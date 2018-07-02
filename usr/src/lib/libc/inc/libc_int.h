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

#ifndef _LIBC_INT_H
#define	_LIBC_INT_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Libc/rtld Runtime Interface
 */
#define	CI_NULL		0		/* (void) last entry */
#define	CI_VERSION	1		/* current version of ri_interface */
#define	CI_ATEXIT	2		/* _preexec_exit_handlers() address */
#define	CI_LCMESSAGES	3		/* message locale */
#define	CI_BIND_GUARD	4		/* bind_guard() address */
#define	CI_BIND_CLEAR	5		/* bind_clear() address */
#define	CI_THR_SELF	6		/* thr_self() address */
#define	CI_TLS_MODADD	7		/* __tls_mod_add() address */
#define	CI_TLS_MODREM	8		/* __tls_mod_remove() address */
#define	CI_TLS_STATMOD	9		/* __tls_static_mods() address */
#define	CI_THRINIT	10		/* libc thread initialization */
#define	CI_CRITICAL	11		/* critical level query interface */

#define	CI_MAX		12

#define	CI_V_NONE	0		/* ci_version versions */
#define	CI_V_ONE	1		/* original version */
#define	CI_V_TWO	2
#define	CI_V_THREE	3
#define	CI_V_FOUR	4
#define	CI_V_FIVE	5
#define	CI_V_SIX	6
#define	CI_V_CURRENT	CI_V_SIX	/* current version of libc interface */
#define	CI_V_NUM	7		/* number of CI_V_* numbers */

/*
 * Flags for the bindguard routines.
 * THR_FLG_RTLD used to live in usr/src/cmd/sgs/rtld/common/_rtld.h
 * THR_FLG_NOLOCK and THR_FLG_REENTER are new in version CI_V_FIVE.
 */
#define	THR_FLG_RTLD	0x00000001	/* bind_guard() flag */
#define	THR_FLG_NOLOCK	0x00000002	/* don't use ld.so.1's lock */
#define	THR_FLG_REENTER	0x00000004	/* temporary leave / reenter */

/*
 * Libc to ld.so.1 interface communication structure.
 */
typedef struct {
	int	ci_tag;
	union {
		void	*ci_func;
		long	ci_val;
		char	*ci_ptr;
	} ci_un;
} Lc_interface;

/*
 * Address range returned via CI_ATEXIT.  Note, the address range array passed
 * back from ld.so.1 is maintained by ld.so.1 and should not be freed by libc.
 */
typedef struct {
	void *	lb;			/* lower bound */
	void *	ub;			/* upper bound */
} Lc_addr_range_t;

/*
 * Thread-Local storage data type and interfaces shared between
 * libc & ld.so.1.
 */

typedef struct {
	unsigned long	ti_moduleid;	/* module ID for TLS var */
	unsigned long	ti_tlsoffset;	/* offset into tls block for TLS var */
} TLS_index;


typedef struct {
	const char	*tm_modname;		/* name of object */
						/*	containing TLS */
	unsigned long	tm_modid;		/* TLS module id */
	void *		tm_tlsblock;		/* pointer to r/o init image */
	unsigned long	tm_filesz;		/* initialized file size */
	unsigned long	tm_memsz;		/* memory size */
	long		tm_stattlsoffset;	/* signed offset into static */
						/*	TLS block */
	unsigned long	tm_flags;
	void *		tm_tlsinitarray;	/* TLS .init function array */
	unsigned long	tm_tlsinitarraycnt;	/* # of entries in initarray */
	void *		tm_tlsfiniarray;	/* TLS .fini function array */
	unsigned long	tm_tlsfiniarraycnt;	/* # of entries in finiarray */
	unsigned long	tm_pad[5];		/* future expansion */
} TLS_modinfo;

#ifdef _SYSCALL32
typedef struct {
	caddr32_t	tm_modname;		/* name of object */
						/*	containing TLS */
	uint32_t	tm_modid;		/* TLS module id */
	caddr32_t	tm_tlsblock;		/* pointer to r/o init image */
	uint32_t	tm_filesz;		/* initialized file size */
	uint32_t	tm_memsz;		/* memory size */
	int32_t		tm_stattlsoffset;	/* signed offset into static */
						/*	TLS block */
	uint32_t	tm_flags;
	caddr32_t	tm_tlsinitarray;	/* TLS .init function array */
	uint32_t	tm_tlsinitarraycnt;	/* # of entries in initarray */
	caddr32_t	tm_tlsfiniarray;	/* TLS .fini function array */
	uint32_t	tm_tlsfiniarraycnt;	/* # of entries in finiarray */
	uint32_t	tm_pad[5];		/* future expansion */
} TLS_modinfo32;
#endif


/*
 * Flag values for TLS_modifo.tm_flags
 */
#define	TM_FLG_STATICTLS	0x0001		/* Static TLS module */


#ifdef	__cplusplus
}
#endif

#endif /* _LIBC_INT_H */
