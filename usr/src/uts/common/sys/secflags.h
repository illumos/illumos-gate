/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/* Copyright 2014, Richard Lowe */

#ifndef _SYS_SECFLAGS_H
#define	_SYS_SECFLAGS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/procset.h>

struct proc;
typedef uint64_t secflagset_t;

typedef struct psecflags {
	secflagset_t psf_effective;
	secflagset_t psf_inherit;
	secflagset_t psf_lower;
	secflagset_t psf_upper;
} psecflags_t;

typedef struct secflagdelta {
	secflagset_t psd_add;		/* Flags to add */
	secflagset_t psd_rem;		/* Flags to remove */
	secflagset_t psd_assign;	/* Flags to assign */
	boolean_t psd_ass_active;	/* Need to assign */
} secflagdelta_t;

typedef enum {
	PSF_EFFECTIVE = 0,
	PSF_INHERIT,
	PSF_LOWER,
	PSF_UPPER
} psecflagwhich_t;


/*
 * p_secflags codes
 *
 * These flags indicate the extra security-related features enabled for a
 * given process.
 */
typedef enum {
	PROC_SEC_ASLR = 0,
	PROC_SEC_FORBIDNULLMAP,
	PROC_SEC_NOEXECSTACK
} secflag_t;

extern secflagset_t secflag_to_bit(secflag_t);
extern boolean_t secflag_isset(secflagset_t, secflag_t);
extern void secflag_clear(secflagset_t *, secflag_t);
extern void secflag_set(secflagset_t *, secflag_t);
extern boolean_t secflags_isempty(secflagset_t);
extern void secflags_zero(secflagset_t *);
extern void secflags_fullset(secflagset_t *);
extern void secflags_copy(secflagset_t *, const secflagset_t *);
extern boolean_t secflags_issubset(secflagset_t, secflagset_t);
extern boolean_t secflags_issuperset(secflagset_t, secflagset_t);
extern boolean_t secflags_intersection(secflagset_t, secflagset_t);
extern void secflags_union(secflagset_t *, const secflagset_t *);
extern void secflags_difference(secflagset_t *, const secflagset_t *);
extern boolean_t psecflags_validate_delta(const psecflags_t *,
    const secflagdelta_t *);
extern boolean_t psecflags_validate(const psecflags_t *);
extern void psecflags_default(psecflags_t *sf);
extern const char *secflag_to_str(secflag_t);
extern boolean_t secflag_by_name(const char *, secflag_t *);
extern void secflags_to_str(secflagset_t, char *, size_t);

/* All valid bits */
#define	PROC_SEC_MASK	(secflag_to_bit(PROC_SEC_ASLR) |	\
    secflag_to_bit(PROC_SEC_FORBIDNULLMAP) |			\
    secflag_to_bit(PROC_SEC_NOEXECSTACK))

#if !defined(_KERNEL)
extern int secflags_parse(const secflagset_t *, const char *, secflagdelta_t *);
extern int psecflags(idtype_t, id_t, psecflagwhich_t, secflagdelta_t *);
#endif

#if defined(_KERNEL)
extern boolean_t secflag_enabled(struct proc *, secflag_t);
extern void secflags_promote(struct proc *);
extern void secflags_apply_delta(secflagset_t *, const secflagdelta_t *);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SECFLAGS_H */
