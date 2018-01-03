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

/*
 * Copyright 2018 Joyent, Inc.
 */

#ifndef	_VM_SEG_VMM_H
#define	_VM_SEG_VMM_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct segvmm_crargs {
	caddr_t	kaddr;
	uchar_t	prot;			/* protection */
	void	*cookie;		/* opaque resource backing memory */
	void	(*hold)(void *);	/* add reference to cookie */
	void	(*rele)(void *);	/* release reference to cookie */
} segvmm_crargs_t;

typedef void (*segvmm_holdfn_t)(void *);
typedef void (*segvmm_relefn_t)(void *);

typedef struct segvmm_data {
	krwlock_t	svmd_lock;
	uintptr_t	svmd_kaddr;
	uchar_t		svmd_prot;
	void		*svmd_cookie;
	segvmm_holdfn_t	svmd_hold;
	segvmm_relefn_t	svmd_rele;
	size_t		svmd_softlockcnt;
} segvmm_data_t;

extern int segvmm_create(struct seg **, void *);

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_SEG_VMM_H */
