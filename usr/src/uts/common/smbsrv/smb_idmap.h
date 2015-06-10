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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMB_IDMAP_H
#define	_SMB_IDMAP_H

#if defined(_KERNEL) /* intentionally not || defined(_FAKE_KERNEL) */
#include <sys/kidmap.h>
#else
#include <idmap.h>
#endif

#include <smbsrv/smb_sid.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SMB ID mapping
 *
 * Solaris ID mapping service (aka Winchester) works with domain SIDs
 * and RIDs where domain SIDs are in string format. CIFS service works
 * with binary SIDs understanable by CIFS clients. A layer of SMB ID
 * mapping functions are implemeted to hide the SID conversion details
 * and also hide the handling of array of batch mapping requests.
 */

#define	SMB_IDMAP_UNKNOWN	-1
#define	SMB_IDMAP_GROUP		0
#define	SMB_IDMAP_USER		1
#define	SMB_IDMAP_OWNERAT	2
#define	SMB_IDMAP_GROUPAT	3
#define	SMB_IDMAP_EVERYONE	4

#define	SMB_IDMAP_SID2ID	0x0001
#define	SMB_IDMAP_ID2SID	0x0002

/*
 * smb_idmap_t
 *
 * sim_idtype: ID type (output in sid->uid mapping)
 * sim_id:     UID/GID (output in sid->uid mapping)
 */
typedef struct smb_idmap {
	int		sim_idtype;
	uid_t		*sim_id;
	char		*sim_domsid;
	uint32_t	sim_rid;
	smb_sid_t	*sim_sid;
	idmap_stat	sim_stat;
} smb_idmap_t;

typedef struct smb_idmap_batch {
	uint16_t		sib_nmap;
	uint32_t		sib_flags;
	uint32_t		sib_size;
	smb_idmap_t 		*sib_maps;
	idmap_get_handle_t 	*sib_idmaph;
} smb_idmap_batch_t;

idmap_stat smb_idmap_getsid(uid_t, int, smb_sid_t **);
idmap_stat smb_idmap_getid(smb_sid_t *, uid_t *, int *);

void smb_idmap_batch_destroy(smb_idmap_batch_t *);
idmap_stat smb_idmap_batch_create(smb_idmap_batch_t *, uint16_t, int);
idmap_stat smb_idmap_batch_getmappings(smb_idmap_batch_t *);
idmap_stat smb_idmap_batch_getid(idmap_get_handle_t *, smb_idmap_t *,
    smb_sid_t *, int);
idmap_stat smb_idmap_batch_getsid(idmap_get_handle_t *, smb_idmap_t *,
    uid_t, int);

#ifdef __cplusplus
}
#endif


#endif /* _SMB_IDMAP_H */
