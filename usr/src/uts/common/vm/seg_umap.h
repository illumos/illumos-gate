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
 * Copyright 2016 Joyent, Inc.
 */

#ifndef	_VM_SEG_UMAP_H
#define	_VM_SEG_UMAP_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct segumap_crargs {
	caddr_t	kaddr;
	uchar_t	prot;		/* protection */
	uchar_t	maxprot;	/* maximum protection */
} segumap_crargs_t;

typedef struct segumap_data {
	krwlock_t	sud_lock;
	caddr_t		sud_kaddr;
	uchar_t		sud_prot;
	size_t		sud_softlockcnt;
} segumap_data_t;

extern int segumap_create(struct seg *, void *);

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_SEG_UMAP_H */
