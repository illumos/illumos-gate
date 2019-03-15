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
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMB_PASS_H
#define	_SMB_PASS_H

/*
 * Password keychains interface
 */

#include <sys/avl.h>
#include <netsmb/smb_dev.h>

/*
 * Here just so our mdb module can use it.
 * Otherwise could be private to smb_pass.c
 */
typedef struct smb_passid {
	avl_node_t	cpnode;	 /* Next Node information */
	uid_t		uid;		/* User id */
	zoneid_t	zoneid;		/* Future Use */
	char		*srvdom;	/* Windows Domain (or server) */
	char		*username;	/* Windows User name */
	uchar_t		lmhash[SMBIOC_HASH_SZ];
	uchar_t		nthash[SMBIOC_HASH_SZ];
} smb_passid_t;

/* Called from smb_dev.c */
void smb_pkey_init(void);
void smb_pkey_fini(void);
int smb_pkey_idle(void);

#endif /* _SMB_PASS_H */
