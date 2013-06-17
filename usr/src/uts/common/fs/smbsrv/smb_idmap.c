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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * SMB server interface to idmap
 * (smb_idmap_get..., smb_idmap_batch_...)
 *
 * There are three implementations of this interface:
 *	uts/common/fs/smbsrv/smb_idmap.c (smbsrv kmod)
 *	lib/smbsrv/libfksmbsrv/common/fksmb_idmap.c (libfksmbsrv)
 *	lib/smbsrv/libsmb/common/smb_idmap.c (libsmb)
 *
 * There are enough differences (relative to the code size)
 * that it's more trouble than it's worth to merge them.
 *
 * This one differs from the others in that it:
 *	calls kernel (kidmap_...) interfaces
 *	domain SIDs are shared, not strdup'ed
 */

/*
 * SMB ID mapping
 *
 * Solaris ID mapping service (aka Winchester) works with domain SIDs
 * and RIDs where domain SIDs are in string format. CIFS service works
 * with binary SIDs understandable by CIFS clients. A layer of SMB ID
 * mapping functions are implemeted to hide the SID conversion details
 * and also hide the handling of array of batch mapping requests.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/tzfile.h>
#include <sys/atomic.h>
#include <sys/kidmap.h>
#include <sys/time.h>
#include <sys/spl.h>
#include <sys/random.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smb_idmap.h>

#include <sys/sid.h>
#include <sys/priv_names.h>

static int smb_idmap_batch_binsid(smb_idmap_batch_t *sib);

/*
 * smb_idmap_getsid
 *
 * Maps the given Solaris ID to a Windows SID using the
 * simple mapping API.
 */
idmap_stat
smb_idmap_getsid(uid_t id, int idtype, smb_sid_t **sid)
{
	smb_idmap_t sim;

	switch (idtype) {
	case SMB_IDMAP_USER:
		sim.sim_stat = kidmap_getsidbyuid(global_zone, id,
		    (const char **)&sim.sim_domsid, &sim.sim_rid);
		break;

	case SMB_IDMAP_GROUP:
		sim.sim_stat = kidmap_getsidbygid(global_zone, id,
		    (const char **)&sim.sim_domsid, &sim.sim_rid);
		break;

	case SMB_IDMAP_EVERYONE:
		/* Everyone S-1-1-0 */
		sim.sim_domsid = "S-1-1";
		sim.sim_rid = 0;
		sim.sim_stat = IDMAP_SUCCESS;
		break;

	default:
		ASSERT(0);
		return (IDMAP_ERR_ARG);
	}

	if (sim.sim_stat != IDMAP_SUCCESS)
		return (sim.sim_stat);

	if (sim.sim_domsid == NULL)
		return (IDMAP_ERR_NOMAPPING);

	sim.sim_sid = smb_sid_fromstr(sim.sim_domsid);
	if (sim.sim_sid == NULL)
		return (IDMAP_ERR_INTERNAL);

	*sid = smb_sid_splice(sim.sim_sid, sim.sim_rid);
	smb_sid_free(sim.sim_sid);
	if (*sid == NULL)
		sim.sim_stat = IDMAP_ERR_INTERNAL;

	return (sim.sim_stat);
}

/*
 * smb_idmap_getid
 *
 * Maps the given Windows SID to a Unix ID using the
 * simple mapping API.
 */
idmap_stat
smb_idmap_getid(smb_sid_t *sid, uid_t *id, int *idtype)
{
	smb_idmap_t sim;
	char sidstr[SMB_SID_STRSZ];

	smb_sid_tostr(sid, sidstr);
	if (smb_sid_splitstr(sidstr, &sim.sim_rid) != 0)
		return (IDMAP_ERR_SID);
	sim.sim_domsid = sidstr;
	sim.sim_id = id;

	switch (*idtype) {
	case SMB_IDMAP_USER:
		sim.sim_stat = kidmap_getuidbysid(global_zone, sim.sim_domsid,
		    sim.sim_rid, sim.sim_id);
		break;

	case SMB_IDMAP_GROUP:
		sim.sim_stat = kidmap_getgidbysid(global_zone, sim.sim_domsid,
		    sim.sim_rid, sim.sim_id);
		break;

	case SMB_IDMAP_UNKNOWN:
		sim.sim_stat = kidmap_getpidbysid(global_zone, sim.sim_domsid,
		    sim.sim_rid, sim.sim_id, &sim.sim_idtype);
		break;

	default:
		ASSERT(0);
		return (IDMAP_ERR_ARG);
	}

	*idtype = sim.sim_idtype;

	return (sim.sim_stat);
}

/*
 * smb_idmap_batch_create
 *
 * Creates and initializes the context for batch ID mapping.
 */
idmap_stat
smb_idmap_batch_create(smb_idmap_batch_t *sib, uint16_t nmap, int flags)
{
	ASSERT(sib);

	bzero(sib, sizeof (smb_idmap_batch_t));

	sib->sib_idmaph = kidmap_get_create(global_zone);

	sib->sib_flags = flags;
	sib->sib_nmap = nmap;
	sib->sib_size = nmap * sizeof (smb_idmap_t);
	sib->sib_maps = kmem_zalloc(sib->sib_size, KM_SLEEP);

	return (IDMAP_SUCCESS);
}

/*
 * smb_idmap_batch_destroy
 *
 * Frees the batch ID mapping context.
 * If ID mapping is Solaris -> Windows it frees memories
 * allocated for binary SIDs.
 */
void
smb_idmap_batch_destroy(smb_idmap_batch_t *sib)
{
	char *domsid;
	int i;

	ASSERT(sib);
	ASSERT(sib->sib_maps);

	if (sib->sib_idmaph)
		kidmap_get_destroy(sib->sib_idmaph);

	if (sib->sib_flags & SMB_IDMAP_ID2SID) {
		/*
		 * SIDs are allocated only when mapping
		 * UID/GID to SIDs
		 */
		for (i = 0; i < sib->sib_nmap; i++)
			smb_sid_free(sib->sib_maps[i].sim_sid);
	} else if (sib->sib_flags & SMB_IDMAP_SID2ID) {
		/*
		 * SID prefixes are allocated only when mapping
		 * SIDs to UID/GID
		 */
		for (i = 0; i < sib->sib_nmap; i++) {
			domsid = sib->sib_maps[i].sim_domsid;
			if (domsid)
				smb_mem_free(domsid);
		}
	}

	if (sib->sib_size && sib->sib_maps)
		kmem_free(sib->sib_maps, sib->sib_size);
}

/*
 * smb_idmap_batch_getid
 *
 * Queue a request to map the given SID to a UID or GID.
 *
 * sim->sim_id should point to variable that's supposed to
 * hold the returned UID/GID. This needs to be setup by caller
 * of this function.
 *
 * If requested ID type is known, it's passed as 'idtype',
 * if it's unknown it'll be returned in sim->sim_idtype.
 */
idmap_stat
smb_idmap_batch_getid(idmap_get_handle_t *idmaph, smb_idmap_t *sim,
    smb_sid_t *sid, int idtype)
{
	char strsid[SMB_SID_STRSZ];
	idmap_stat idm_stat;

	ASSERT(idmaph);
	ASSERT(sim);
	ASSERT(sid);

	smb_sid_tostr(sid, strsid);
	if (smb_sid_splitstr(strsid, &sim->sim_rid) != 0)
		return (IDMAP_ERR_SID);
	sim->sim_domsid = smb_mem_strdup(strsid);

	switch (idtype) {
	case SMB_IDMAP_USER:
		idm_stat = kidmap_batch_getuidbysid(idmaph, sim->sim_domsid,
		    sim->sim_rid, sim->sim_id, &sim->sim_stat);
		break;

	case SMB_IDMAP_GROUP:
		idm_stat = kidmap_batch_getgidbysid(idmaph, sim->sim_domsid,
		    sim->sim_rid, sim->sim_id, &sim->sim_stat);
		break;

	case SMB_IDMAP_UNKNOWN:
		idm_stat = kidmap_batch_getpidbysid(idmaph, sim->sim_domsid,
		    sim->sim_rid, sim->sim_id, &sim->sim_idtype,
		    &sim->sim_stat);
		break;

	default:
		ASSERT(0);
		return (IDMAP_ERR_ARG);
	}

	return (idm_stat);
}

/*
 * smb_idmap_batch_getsid
 *
 * Queue a request to map the given UID/GID to a SID.
 *
 * sim->sim_domsid and sim->sim_rid will contain the mapping
 * result upon successful process of the batched request.
 */
idmap_stat
smb_idmap_batch_getsid(idmap_get_handle_t *idmaph, smb_idmap_t *sim,
    uid_t id, int idtype)
{
	idmap_stat idm_stat;

	switch (idtype) {
	case SMB_IDMAP_USER:
		idm_stat = kidmap_batch_getsidbyuid(idmaph, id,
		    (const char **)&sim->sim_domsid, &sim->sim_rid,
		    &sim->sim_stat);
		break;

	case SMB_IDMAP_GROUP:
		idm_stat = kidmap_batch_getsidbygid(idmaph, id,
		    (const char **)&sim->sim_domsid, &sim->sim_rid,
		    &sim->sim_stat);
		break;

	case SMB_IDMAP_OWNERAT:
		/* Current Owner S-1-5-32-766 */
		sim->sim_domsid = NT_BUILTIN_DOMAIN_SIDSTR;
		sim->sim_rid = SECURITY_CURRENT_OWNER_RID;
		sim->sim_stat = IDMAP_SUCCESS;
		idm_stat = IDMAP_SUCCESS;
		break;

	case SMB_IDMAP_GROUPAT:
		/* Current Group S-1-5-32-767 */
		sim->sim_domsid = NT_BUILTIN_DOMAIN_SIDSTR;
		sim->sim_rid = SECURITY_CURRENT_GROUP_RID;
		sim->sim_stat = IDMAP_SUCCESS;
		idm_stat = IDMAP_SUCCESS;
		break;

	case SMB_IDMAP_EVERYONE:
		/* Everyone S-1-1-0 */
		sim->sim_domsid = NT_WORLD_AUTH_SIDSTR;
		sim->sim_rid = 0;
		sim->sim_stat = IDMAP_SUCCESS;
		idm_stat = IDMAP_SUCCESS;
		break;

	default:
		ASSERT(0);
		return (IDMAP_ERR_ARG);
	}

	return (idm_stat);
}

/*
 * smb_idmap_batch_getmappings
 *
 * trigger ID mapping service to get the mappings for queued
 * requests.
 *
 * Checks the result of all the queued requests.
 * If this is a Solaris -> Windows mapping it generates
 * binary SIDs from returned (domsid, rid) pairs.
 */
idmap_stat
smb_idmap_batch_getmappings(smb_idmap_batch_t *sib)
{
	idmap_stat idm_stat = IDMAP_SUCCESS;
	int i;

	idm_stat = kidmap_get_mappings(sib->sib_idmaph);
	if (idm_stat != IDMAP_SUCCESS)
		return (idm_stat);

	/*
	 * Check the status for all the queued requests
	 */
	for (i = 0; i < sib->sib_nmap; i++) {
		if (sib->sib_maps[i].sim_stat != IDMAP_SUCCESS)
			return (sib->sib_maps[i].sim_stat);
	}

	if (smb_idmap_batch_binsid(sib) != 0)
		idm_stat = IDMAP_ERR_OTHER;

	return (idm_stat);
}

/*
 * smb_idmap_batch_binsid
 *
 * Convert sidrids to binary sids
 *
 * Returns 0 if successful and non-zero upon failure.
 */
static int
smb_idmap_batch_binsid(smb_idmap_batch_t *sib)
{
	smb_sid_t *sid;
	smb_idmap_t *sim;
	int i;

	if (sib->sib_flags & SMB_IDMAP_SID2ID)
		/* This operation is not required */
		return (0);

	sim = sib->sib_maps;
	for (i = 0; i < sib->sib_nmap; sim++, i++) {
		ASSERT(sim->sim_domsid);
		if (sim->sim_domsid == NULL)
			return (1);

		if ((sid = smb_sid_fromstr(sim->sim_domsid)) == NULL)
			return (1);

		sim->sim_sid = smb_sid_splice(sid, sim->sim_rid);
		smb_sid_free(sid);
	}

	return (0);
}
