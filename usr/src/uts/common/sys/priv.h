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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_PRIV_H
#define	_SYS_PRIV_H

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/priv_names.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef uint32_t priv_chunk_t;
typedef struct priv_set priv_set_t;

#ifdef _KERNEL

/*
 * Kernel type definitions.
 */
typedef int priv_ptype_t;
typedef int priv_t;

#else /* _KERNEL */

/*
 * Userland type definitions.
 */

typedef const char *priv_ptype_t;
typedef const char *priv_t;

#endif /* _KERNEL */

/*
 * priv_op_t indicates a privilege operation type
 */
typedef enum priv_op {
	PRIV_ON,
	PRIV_OFF,
	PRIV_SET
} priv_op_t;

/*
 * Privilege system call subcodes.
 */

#define	PRIVSYS_SETPPRIV	0
#define	PRIVSYS_GETPPRIV	1
#define	PRIVSYS_GETIMPLINFO	2
#define	PRIVSYS_SETPFLAGS	3
#define	PRIVSYS_GETPFLAGS	4
#define	PRIVSYS_ISSETUGID	5
#define	PRIVSYS_KLPD_REG	6
#define	PRIVSYS_KLPD_UNREG	7
#define	PRIVSYS_PFEXEC_REG	8
#define	PRIVSYS_PFEXEC_UNREG	9


/*
 * Maximum length of a user defined privilege name.
 */
#define	PRIVNAME_MAX		32

/*
 * Privilege interface functions for those parts of the kernel that
 * know nothing of the privilege internals.
 *
 * A privilege implementation can have a varying number of sets; sets
 * consist of a number of priv_chunk_t's and the size is expressed as such.
 * The privileges can be represented as
 *
 *		priv_chunk_t privs[info.priv_nsets][info.priv_setsize]
 *		... priv_infosize of extra information ...
 *
 * Extra data contained in the privilege information consists of chunks
 * of data with specified size and type all headed by a priv_info_t header
 * which defines both the type of information as well as the size of the
 * information.  ((char*)&info)+info->priv_info_size should be rounded up
 * to point to the next piece of information.
 */

typedef struct priv_impl_info {
	uint32_t	priv_headersize;	/* sizeof (priv_impl_info) */
	uint32_t	priv_flags;		/* additional flags */
	uint32_t	priv_nsets;		/* number of priv sets */
	uint32_t	priv_setsize;		/* size in priv_chunk_t */
	uint32_t	priv_max;		/* highest actual valid priv */
	uint32_t	priv_infosize;		/* Per proc. additional info */
	uint32_t	priv_globalinfosize;	/* Per system info */
} priv_impl_info_t;

#define	PRIV_IMPL_INFO_SIZE(p) \
			((p)->priv_headersize + (p)->priv_globalinfosize)

#define	PRIV_PRPRIV_INFO_OFFSET(p) \
		(sizeof (*(p)) + \
		((p)->pr_nsets * (p)->pr_setsize - 1) * sizeof (priv_chunk_t))

#define	PRIV_PRPRIV_SIZE(p) \
		(PRIV_PRPRIV_INFO_OFFSET(p) + (p)->pr_infosize)

/*
 * Per credential flags.
 */
#define	PRIV_DEBUG			0x0001		/* User debugging */
#define	PRIV_AWARE			0x0002		/* Is privilege aware */
#define	PRIV_AWARE_INHERIT		0x0004		/* Inherit awareness */
#define	__PROC_PROTECT			0x0008		/* Private */
#define	NET_MAC_AWARE			0x0010		/* Is MAC aware */
#define	NET_MAC_AWARE_INHERIT		0x0020		/* Inherit MAC aware */
#define	PRIV_AWARE_RESET		0x0040		/* Reset on setuid() */
#define	PRIV_XPOLICY			0x0080		/* Extended policy */
#define	PRIV_PFEXEC			0x0100		/* As if pfexec'ed */

/* user-settable flags: */
#define	PRIV_USER	(PRIV_DEBUG | NET_MAC_AWARE | NET_MAC_AWARE_INHERIT |\
			    PRIV_XPOLICY | PRIV_AWARE_RESET | PRIV_PFEXEC)

/*
 * Header of the privilege info data structure; multiple structures can
 * follow the privilege sets and priv_impl_info structures.
 */
typedef struct priv_info {
	uint32_t	priv_info_type;
	uint32_t	priv_info_size;
} priv_info_t;

typedef struct priv_info_uint {
	priv_info_t	info;
	uint_t		val;
} priv_info_uint_t;

/*
 * Global privilege set information item; the actual size of the array is
 * {priv_setsize}.
 */
typedef struct priv_info_set {
	priv_info_t	info;
	priv_chunk_t	set[1];
} priv_info_set_t;

/*
 * names[1] is a place holder which can contain multiple NUL terminated,
 * non-empty strings.
 */

typedef struct priv_info_names {
	priv_info_t	info;
	int		cnt;		/* number of strings */
	char		names[1];	/* "string1\0string2\0 ..stringN\0" */
} priv_info_names_t;

/*
 * Privilege information types.
 */
#define	PRIV_INFO_SETNAMES		0x0001
#define	PRIV_INFO_PRIVNAMES		0x0002
#define	PRIV_INFO_BASICPRIVS		0x0003
#define	PRIV_INFO_FLAGS			0x0004

/*
 * Special "privileges" used to indicate special conditions in privilege
 * debugging/tracing code.
 */
#define	PRIV_ALL			(-1)	/* All privileges required */
#define	PRIV_MULTIPLE			(-2)	/* More than one */
#define	PRIV_NONE			(-3)	/* No value */
#define	PRIV_ALLZONE			(-4)	/* All privileges in zone */
#define	PRIV_GLOBAL			(-5)	/* Must be in global zone */

#ifdef _KERNEL

#define	PRIV_ALLOC			0x1

extern int priv_debug;
extern int priv_basic_test;

struct proc;
struct prpriv;
struct cred;

extern int priv_prgetprivsize(struct prpriv *);
extern void cred2prpriv(const struct cred *, struct prpriv *);
extern int priv_pr_spriv(struct proc *, struct prpriv *, const struct cred *);

extern priv_impl_info_t *priv_hold_implinfo(void);
extern void priv_release_implinfo(void);
extern size_t priv_get_implinfo_size(void);
extern const priv_set_t *priv_getset(const struct cred *, int);
extern void priv_getinfo(const struct cred *, void *);
extern int priv_getbyname(const char *, uint_t);
extern int priv_getsetbyname(const char *, int);
extern const char *priv_getbynum(int);
extern const char *priv_getsetbynum(int);

extern void priv_emptyset(priv_set_t *);
extern void priv_fillset(priv_set_t *);
extern void priv_addset(priv_set_t *, int);
extern void priv_delset(priv_set_t *, int);
extern boolean_t priv_ismember(const priv_set_t *, int);
extern boolean_t priv_isemptyset(const priv_set_t *);
extern boolean_t priv_isfullset(const priv_set_t *);
extern boolean_t priv_isequalset(const priv_set_t *, const priv_set_t *);
extern boolean_t priv_issubset(const priv_set_t *, const priv_set_t *);
extern int priv_proc_cred_perm(const struct cred *, struct proc *,
	struct cred **, int);
extern void priv_intersect(const priv_set_t *, priv_set_t *);
extern void priv_union(const priv_set_t *, priv_set_t *);
extern void priv_inverse(priv_set_t *);

extern void priv_set_PA(cred_t *);
extern void priv_adjust_PA(cred_t *);
extern void priv_reset_PA(cred_t *, boolean_t);
extern boolean_t priv_can_clear_PA(const cred_t *);

extern int setpflags(uint_t, uint_t, cred_t *);
extern uint_t getpflags(uint_t, const cred_t *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PRIV_H */
