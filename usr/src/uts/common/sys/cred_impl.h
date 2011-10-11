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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_CRED_IMPL_H
#define	_SYS_CRED_IMPL_H

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/priv_impl.h>
#include <sys/sid.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The user credential implementation.
 *
 * This is is not a public interface.  This file must not be included
 * except by those routines in Solaris proper that implement credential
 * manipulation and kernel policy.
 *
 * Credentials are shared, and therefor read-only, data structure.
 * After finalization, on the cr_ref field is changed through crhold/crfree.
 *
 * Kernel modules that need access to fields of cred_t should use the
 * accessor functions defined in <sys/cred.h>
 *
 * The size of the cr_groups[] array is configurable but is the same
 * (ngroups_max) for all cred_impl structures; cr_ngroups records the number
 * of elements currently in use, not the array size.
 *
 * Changes in the implementation will move cr_groups[] around.
 *
 * Properly sized cred_t structures are only returned by crget()/crdup()
 * crcopy().  It is not possible to declare one.
 */

#if defined(_KERNEL) || defined(_KMEMUSER)

struct zone;		/* forward reference */
struct ts_label_s;	/* forward reference */
struct credklpd;	/* forward reference */

/* Supplemental groups list. */
typedef struct credgrp {
	uint_t		crg_ref;
	uint_t		crg_ngroups;
	gid_t		crg_groups[1];
} credgrp_t;

struct cred {
	uint_t		cr_ref;		/* reference count */
	uid_t		cr_uid;		/* effective user id */
	gid_t		cr_gid;		/* effective group id */
	uid_t		cr_ruid;	/* real user id */
	gid_t		cr_rgid;	/* real group id */
	uid_t		cr_suid;	/* "saved" user id (from exec) */
	gid_t		cr_sgid;	/* "saved" group id (from exec) */
	cred_priv_t	cr_priv;	/* privileges */
	projid_t	cr_projid;	/* project */
	struct zone	*cr_zone;	/* pointer to per-zone structure */
	struct ts_label_s *cr_label;	/* pointer to the effective label */
	struct credklpd *cr_klpd;	/* pointer to the cred's klpd */
	credsid_t	*cr_ksid;	/* pointer to SIDs */
	credgrp_t	*cr_grps;	/* supplemental groups */
					/* audit info is defined dynamically */
					/* and valid only when audit enabled */
	/* auditinfo_addr_t	cr_auinfo;	audit info */
};

extern int ngroups_max;

#define	CR_PRIVS(c)	(&(c)->cr_priv)
#define	CR_PRIVSETS(c)	(((c)->cr_priv.crprivs))

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CRED_IMPL_H */
