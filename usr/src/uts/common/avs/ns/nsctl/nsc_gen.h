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

#ifndef _NSC_GEN_H
#define	_NSC_GEN_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __NSC_GEN__
Error: Illegal #include - private file.
#endif


/*
 * Global resource map.
 */

#define	_NSC_MAXNAME	20

typedef struct nsc_rmmap_s {
	char	name[_NSC_MAXNAME];	/* Description */
	int32_t	offset;			/* Offset into arena */
	uint32_t	size;		/* Length of area */
	int32_t	inuse;			/* Bitmap of nodes using area */
	int32_t	pad[2];			/* For future expansion */
} nsc_rmmap_t;


#ifdef _KERNEL
#include <sys/nsctl/nsc_mem.h>

extern kmutex_t _nsc_global_lock;
extern int _nsc_global_lock_init;

extern int _nsc_rmmap_init(nsc_rmmap_t *, char *, int, size_t, ulong_t);
extern ulong_t _nsc_rmmap_alloc(nsc_rmmap_t *, char *, size_t, void (*)());
extern void _nsc_rmmap_free(nsc_rmmap_t *, char *, nsc_mem_t *);
extern size_t _nsc_rmmap_size(nsc_rmmap_t *, char *);
extern size_t _nsc_rmmap_avail(nsc_rmmap_t *);

extern nsc_rmmap_t *_nsc_global_nvmemmap_lookup(nsc_rmmap_t *);
extern void nsc_cm_errhdlr(void *, void *, size_t, int);
extern caddr_t _nsc_rm_nvmem_base;

/*
 * Inter-module function (callback) services.
 */

typedef struct nsc_svc_s {
	struct nsc_svc_s *svc_next;	/* linked list */
	struct nsc_service_s *svc_svc;	/* back link */
	void (*svc_fn)(intptr_t);	/* service function, or NULL (client) */
} nsc_svc_t;

typedef struct nsc_service_s {
	struct nsc_service_s *s_next;	/* linked list */
	char *s_name;			/* name of service */
	nsc_svc_t *s_servers;		/* providers of the service */
	nsc_svc_t *s_clients;		/* clients of the service */
	krwlock_t s_rwlock;		/* lock */
} nsc_service_t;

extern void _nsc_init_svc(void);
extern void _nsc_deinit_svc(void);

#endif /* _KERNEL */


/*
 * ncall usage (NCALL_NSC .. NCALL_NSC+9)
 */

/* inter-node setval */
#define	NSC_SETVAL		(NCALL_NSC + 1)
#define	NSC_SETVAL_ALL		(NCALL_NSC + 2)

#define	NSC_UNUSED3		(NCALL_NSC + 3)
#define	NSC_UNUSED4		(NCALL_NSC + 4)

/* ncall-io io provider */
#define	NSC_NCIO_PARTSIZE	(NCALL_NSC + 5)
#define	NSC_NCIO_READ		(NCALL_NSC + 6)
#define	NSC_NCIO_WRITE		(NCALL_NSC + 7)

#define	NSC_UNUSED8		(NCALL_NSC + 8)
#define	NSC_UNUSED9		(NCALL_NSC + 9)

#ifdef __cplusplus
}
#endif

#endif /* _NSC_GEN_H */
