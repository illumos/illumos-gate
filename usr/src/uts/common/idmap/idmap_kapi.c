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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Windows to Solaris Identity Mapping kernel API
 * This module provides an API to map Windows SIDs to
 * Solaris UID and GIDs.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/door.h>
#include <rpc/rpc_msg.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/rpc_sztypes.h>
#ifdef	DEBUG
#include <sys/cmn_err.h>
#endif	/* DEBUG */
#include <sys/proc.h>
#include <sys/sunddi.h>
#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/sysmacros.h>
#include <sys/disp.h>
#include <sys/kidmap.h>
#include "idmap_prot.h"
#include "kidmap_priv.h"


static	kmutex_t	idmap_lock;
static	idmap_cache_t	idmap_cache;

/*
 * Used to hold RPC header, in particular the XID (not that XID matters
 * in doors RPC)
 */
static struct rpc_msg	call_msg;

typedef struct idmap_get_res {
	idmap_id_type	idtype;
	uid_t		*uid;
	gid_t		*gid;
	uid_t		*pid;
	int		*is_user;
	const char	**sid_prefix;
	uint32_t	*rid;
	idmap_stat	*stat;
} idmap_get_res;

/* Batch mapping handle structure */
struct idmap_get_handle {
	idmap_cache_t	*cache;
	int 		mapping_num;
	int 		mapping_size;
	idmap_mapping	*mapping;
	idmap_get_res	*result;
};

static kmutex_t	idmap_mutex;
static int	idmap_stopped = 0;

struct idmap_reg {
	door_handle_t 	idmap_door;
	int		idmap_invalid;
	int		idmap_invalidated;
	int		idmap_ref;
};

static idmap_reg_t *idmap_ptr;


static int
kidmap_rpc_call(uint32_t op, xdrproc_t xdr_args, caddr_t args,
		xdrproc_t xdr_res, caddr_t res);

static int	kidmap_call_door(door_arg_t *arg);

static void
idmap_freeone(idmap_reg_t *p)
{
	ASSERT(p->idmap_ref == 0);
	ASSERT(MUTEX_HELD(&idmap_mutex));

	door_ki_rele(p->idmap_door);
	if (idmap_ptr == p)
		idmap_ptr = NULL;

	kmem_free(p, sizeof (*p));
}

void
idmap_get_door(idmap_reg_t **state, door_handle_t *dh)
{
	idmap_reg_t *idmp;

	*state = NULL;
	if (dh != NULL)
		*dh = NULL;

	mutex_enter(&idmap_mutex);
	if ((idmp = idmap_ptr) == NULL || idmp->idmap_invalid) {
		mutex_exit(&idmap_mutex);
		return;
	}

	idmap_ptr->idmap_ref++;

	mutex_exit(&idmap_mutex);

	*state = idmp;
	if (dh != NULL)
		*dh = idmp->idmap_door;
}

void
idmap_release_door(idmap_reg_t *idmp)
{
	mutex_enter(&idmap_mutex);

	/*
	 * Note we may decrement idmap_ref twice; if we do it's because
	 * we had EBADF, and rather than decrement the ref count where
	 * that happens we do it here to make sure that we do both
	 * decrements while holding idmap_mutex.
	 */
	if (idmp->idmap_invalid && !idmp->idmap_invalidated) {
		idmp->idmap_invalidated = 1;
		if (--idmp->idmap_ref == 0) {
			idmap_freeone(idmap_ptr);
			mutex_exit(&idmap_mutex);
			return;
		}
	}

	if (--idmp->idmap_ref == 0)
		idmap_freeone(idmap_ptr);

	mutex_exit(&idmap_mutex);
}

int
idmap_reg_dh(door_handle_t dh)
{
	idmap_reg_t *idmp;

	idmp = kmem_alloc(sizeof (*idmp), KM_SLEEP);

	idmp->idmap_door = dh;
	mutex_enter(&idmap_mutex);


	if (idmap_stopped) {
		mutex_exit(&idmap_mutex);
		/*
		 * We're unloading the module.  Calling idmap_reg(2)
		 * again once we're done unloading should cause the
		 * module to be loaded again, so we return EAGAIN.
		 */
		return (EAGAIN);
	}

	if (idmap_ptr != NULL) {
		if (--idmap_ptr->idmap_ref == 0)
			idmap_freeone(idmap_ptr);
	}
	idmp->idmap_invalid = 0;
	idmp->idmap_invalidated = 0;
	idmp->idmap_ref = 1;
	idmap_ptr = idmp;

	call_msg.rm_xid = 1;
	call_msg.rm_call.cb_prog = IDMAP_PROG;
	call_msg.rm_call.cb_vers = IDMAP_V1;

	mutex_exit(&idmap_mutex);

	return (0);
}

int
idmap_unreg_dh(door_handle_t dh)
{
	kidmap_cache_purge(&idmap_cache);

	mutex_enter(&idmap_mutex);
	if (idmap_ptr == NULL || idmap_ptr->idmap_door != dh) {
		mutex_exit(&idmap_mutex);
		return (EINVAL);
	}

	if (idmap_ptr->idmap_invalid) {
		mutex_exit(&idmap_mutex);
		return (EINVAL);
	}
	idmap_ptr->idmap_invalid = 1;
	idmap_ptr->idmap_invalidated = 1;
	if (--idmap_ptr->idmap_ref == 0)
		idmap_freeone(idmap_ptr);
	mutex_exit(&idmap_mutex);
	return (0);
}


static int
kidmap_call_door(door_arg_t *arg)
{
	int status = 0;
	door_handle_t	dh;
	idmap_reg_t	*reg;

	idmap_get_door(&reg, &dh);
	if (reg == NULL || dh == NULL) {
		return (-1);
	}

	status = door_ki_upcall(dh, arg);

#ifdef	DEBUG
	if (status != 0)
		cmn_err(CE_WARN, "idmap: Door call failed %d\n", status);
#endif	/* DEBUG */

	if (status == EBADF) {
		reg->idmap_invalid = 1;
	}

	idmap_release_door(reg);

	return (status);
}


int
kidmap_start(void)
{
	mutex_init(&idmap_lock, NULL, MUTEX_DEFAULT, NULL);
	kidmap_sid_prefix_store_init();
	kidmap_cache_create(&idmap_cache);

	idmap_stopped = 0;

	return (0);
}


int
kidmap_stop(void)
{
	mutex_enter(&idmap_mutex);

	if (idmap_ptr != NULL) {
		mutex_exit(&idmap_mutex);
		return (EBUSY);
	}

	idmap_stopped = 1;

	mutex_exit(&idmap_mutex);

	kidmap_cache_delete(&idmap_cache);
	mutex_destroy(&idmap_lock);

	return (0);
}


/*
 * Given Domain SID and RID, get UID
 *
 * Input:
 * sid_prefix	- Domain SID in canonical form
 * rid	- RID
 *
 * Output:
 * uid  - POSIX UID if return == IDMAP_SUCCESS
 *
 * Return:
 * Success return IDMAP_SUCCESS else IDMAP error
 */
idmap_stat
kidmap_getuidbysid(const char *sid_prefix, uint32_t rid, uid_t *uid)
{
	idmap_mapping_batch	args;
	idmap_mapping		mapping;
	idmap_ids_res		results;
	uint32_t		op = IDMAP_GET_MAPPED_IDS;
	const char		*new_sid_prefix;
	idmap_stat		status;

	if (sid_prefix == NULL || uid == NULL)
		return (IDMAP_ERR_ARG);

	if (kidmap_cache_lookup_uidbysid(&idmap_cache, sid_prefix, rid, uid)
	    == IDMAP_SUCCESS)
		return (IDMAP_SUCCESS);

	bzero(&mapping, sizeof (idmap_mapping));
	mapping.id1.idtype = IDMAP_SID;
	mapping.id1.idmap_id_u.sid.prefix = (char *)sid_prefix;
	mapping.id1.idmap_id_u.sid.rid = rid;
	mapping.id2.idtype = IDMAP_UID;

	bzero(&results, sizeof (idmap_ids_res));

	args.idmap_mapping_batch_len = 1;
	args.idmap_mapping_batch_val = &mapping;

	if (kidmap_rpc_call(op, xdr_idmap_mapping_batch,
	    (caddr_t)&args, xdr_idmap_ids_res,
	    (caddr_t)&results) == 0) {
		/* Door call succeded */
		if (results.ids.ids_len >= 1 &&
		    results.ids.ids_val[0].id.idtype == IDMAP_UID) {
			status = results.ids.ids_val[0].retcode;
			*uid = results.ids.ids_val[0].id.idmap_id_u.uid;
			if (status == IDMAP_SUCCESS) {
				new_sid_prefix = kidmap_find_sid_prefix(
				    sid_prefix);
				kidmap_cache_add_uidbysid(&idmap_cache,
				    new_sid_prefix, rid, *uid);
			}
		} else {
			status = IDMAP_ERR_NOMAPPING;
			*uid = UID_NOBODY;
		}
		xdr_free(xdr_idmap_ids_res, (char *)&results);
	} else {
		/* Door call failed */
		status = IDMAP_ERR_NOMAPPING;
		*uid = UID_NOBODY;
	}
	return (status);
}


/*
 * Given Domain SID and RID, get GID
 *
 * Input:
 * sid_prefix	- Domain SID in canonical form
 * rid	- RID
 *
 * Output:
 * gid  - POSIX UID if return == IDMAP_SUCCESS
 *
 * Return:
 * Success return IDMAP_SUCCESS else IDMAP error
 */
idmap_stat
kidmap_getgidbysid(const char *sid_prefix, uint32_t rid, gid_t *gid)
{
	idmap_mapping_batch	args;
	idmap_mapping		mapping;
	idmap_ids_res		results;
	uint32_t		op = IDMAP_GET_MAPPED_IDS;
	const char		*new_sid_prefix;
	idmap_stat		status;

	if (sid_prefix == NULL || gid == NULL)
		return (IDMAP_ERR_ARG);

	if (kidmap_cache_lookup_gidbysid(&idmap_cache, sid_prefix, rid, gid)
	    == IDMAP_SUCCESS) {
		return (IDMAP_SUCCESS);
	}

	bzero(&mapping, sizeof (idmap_mapping));
	mapping.id1.idtype = IDMAP_SID;
	mapping.id1.idmap_id_u.sid.prefix = (char *)sid_prefix;
	mapping.id1.idmap_id_u.sid.rid = rid;
	mapping.id2.idtype = IDMAP_GID;

	bzero(&results, sizeof (idmap_ids_res));

	args.idmap_mapping_batch_len = 1;
	args.idmap_mapping_batch_val = &mapping;

	if (kidmap_rpc_call(op, xdr_idmap_mapping_batch,
	    (caddr_t)&args, xdr_idmap_ids_res,
	    (caddr_t)&results) == 0) {
		/* Door call succeded */
		if (results.ids.ids_len >= 1 &&
		    results.ids.ids_val[0].id.idtype == IDMAP_GID) {
			status = results.ids.ids_val[0].retcode;
			*gid = results.ids.ids_val[0].id.idmap_id_u.gid;
			if (status == IDMAP_SUCCESS) {
				new_sid_prefix = kidmap_find_sid_prefix(
				    sid_prefix);
				kidmap_cache_add_gidbysid(&idmap_cache,
				    new_sid_prefix, rid, *gid);
			}
		} else {
			status = IDMAP_ERR_NOMAPPING;
			*gid = GID_NOBODY;
		}
		xdr_free(xdr_idmap_ids_res, (char *)&results);
	} else {
		/* Door call failed */
		status = IDMAP_ERR_NOMAPPING;
		*gid = GID_NOBODY;
	}
	return (status);
}

/*
 * Given Domain SID and RID, get Posix ID
 *
 * Input:
 * sid_prefix	- Domain SID in canonical form
 * rid	- RID
 *
 * Output:
 * pid  - POSIX ID if return == IDMAP_SUCCESS
 * is_user - 1 == UID, 0 == GID  if return == IDMAP_SUCCESS
 *
 * Return:
 * Success return IDMAP_SUCCESS else IDMAP error
 */
idmap_stat
kidmap_getpidbysid(const char *sid_prefix, uint32_t rid, uid_t *pid,
		int *is_user)
{
	idmap_mapping_batch	args;
	idmap_mapping		mapping;
	idmap_ids_res		results;
	uint32_t		op = IDMAP_GET_MAPPED_IDS;
	const char		*new_sid_prefix;
	idmap_stat		status;

	if (sid_prefix == NULL || pid == NULL || is_user == NULL)
		return (IDMAP_ERR_ARG);

	if (kidmap_cache_lookup_pidbysid(&idmap_cache, sid_prefix, rid, pid,
	    is_user) == IDMAP_SUCCESS) {
		return (IDMAP_SUCCESS);
	}

	bzero(&mapping, sizeof (idmap_mapping));
	mapping.id1.idtype = IDMAP_SID;
	mapping.id1.idmap_id_u.sid.prefix = (char *)sid_prefix;
	mapping.id1.idmap_id_u.sid.rid = rid;
	mapping.id2.idtype = IDMAP_POSIXID;

	bzero(&results, sizeof (idmap_ids_res));

	args.idmap_mapping_batch_len = 1;
	args.idmap_mapping_batch_val = &mapping;

	if (kidmap_rpc_call(op, xdr_idmap_mapping_batch,
	    (caddr_t)&args, xdr_idmap_ids_res,
	    (caddr_t)&results) == 0) {
		/* Door call succeded */
		if (results.ids.ids_len >= 1 && (
		    results.ids.ids_val[0].id.idtype == IDMAP_UID ||
		    results.ids.ids_val[0].id.idtype == IDMAP_GID)) {
			status = results.ids.ids_val[0].retcode;
			if (results.ids.ids_val[0].id.idtype == IDMAP_UID) {
				*is_user = 1;
				*pid = results.ids.ids_val[0].id.idmap_id_u.uid;
			} else {
				*is_user = 0;
				*pid = results.ids.ids_val[0].id.idmap_id_u.gid;
			}
			if (status == IDMAP_SUCCESS) {
				new_sid_prefix = kidmap_find_sid_prefix(
				    sid_prefix);
				kidmap_cache_add_pidbysid(&idmap_cache,
				    new_sid_prefix, rid, *pid,
				    *is_user);
			}
		} else {
			status = IDMAP_ERR_NOMAPPING;
			*is_user = 1;
			*pid = UID_NOBODY;
		}
		xdr_free(xdr_idmap_ids_res, (char *)&results);
	} else {
		/* Door call failed */
		status = IDMAP_ERR_NOMAPPING;
		*is_user = 1;
		*pid = UID_NOBODY;
	}
	return (status);
}


/*
 * Given UID, get Domain SID and RID
 *
 * Input:
 * uid - Posix UID
 *
 * Output:
 * sid_prefix	- Domain SID if return == IDMAP_SUCCESS
 * rid	- RID if return == IDMAP_SUCCESS
 *
 * Return:
 * Success return IDMAP_SUCCESS else IDMAP error
 */
idmap_stat
kidmap_getsidbyuid(uid_t uid, const char **sid_prefix, uint32_t *rid)
{
	idmap_mapping_batch	args;
	idmap_mapping		mapping;
	idmap_ids_res		results;
	uint32_t		op = IDMAP_GET_MAPPED_IDS;
	idmap_stat		status;
	time_t			entry_ttl;
	idmap_id		*id;

	if (sid_prefix == NULL || rid == NULL)
		return (IDMAP_ERR_ARG);

	if (kidmap_cache_lookup_sidbyuid(&idmap_cache, sid_prefix, rid, uid)
	    == IDMAP_SUCCESS) {
		return (IDMAP_SUCCESS);
	}

	bzero(&mapping, sizeof (idmap_mapping));
	mapping.id1.idtype = IDMAP_UID;
	mapping.id1.idmap_id_u.uid = uid;
	mapping.id2.idtype = IDMAP_SID;

	bzero(&results, sizeof (idmap_ids_res));

	args.idmap_mapping_batch_len = 1;
	args.idmap_mapping_batch_val = &mapping;

	if (kidmap_rpc_call(op, xdr_idmap_mapping_batch,
	    (caddr_t)&args, xdr_idmap_ids_res,
	    (caddr_t)&results) == 0) {
		/* Door call succeded */
		if (results.ids.ids_len >= 1 &&
		    results.ids.ids_val[0].id.idtype == IDMAP_SID) {
			status = results.ids.ids_val[0].retcode;
			id = &results.ids.ids_val[0].id;
			*sid_prefix = kidmap_find_sid_prefix(
			    id->idmap_id_u.sid.prefix);
			*rid = id->idmap_id_u.sid.rid;
			if (status == IDMAP_SUCCESS) {
				kidmap_cache_add_sidbyuid(&idmap_cache,
				    *sid_prefix, *rid, uid);
			}
		} else {
			status = IDMAP_ERR_NOMAPPING;
			*rid = 0;
			*sid_prefix = NULL;
		}
		xdr_free(xdr_idmap_ids_res, (char *)&results);
	} else {
		/* Door call failed */
		status = IDMAP_ERR_NOMAPPING;
		*rid = 0;
		*sid_prefix = NULL;
	}
	return (status);
}


/*
 * Given GID, get Domain SID and RID
 *
 * Input:
 * gid - Posix GID
 *
 * Output:
 * sid_prefix	- Domain SID if return == IDMAP_SUCCESS
 * rid	- RID if return == IDMAP_SUCCESS
 *
 * Return:
 * Success return IDMAP_SUCCESS else IDMAP error
 */
idmap_stat
kidmap_getsidbygid(gid_t gid, const char **sid_prefix, uint32_t *rid)
{
	idmap_mapping_batch	args;
	idmap_mapping		mapping;
	idmap_ids_res		results;
	uint32_t		op = IDMAP_GET_MAPPED_IDS;
	idmap_stat		status;
	idmap_id		*id;

	if (sid_prefix == NULL || rid == NULL)
		return (IDMAP_ERR_ARG);

	if (kidmap_cache_lookup_sidbygid(&idmap_cache, sid_prefix, rid, gid)
	    == IDMAP_SUCCESS) {
		return (IDMAP_SUCCESS);
	}

	bzero(&mapping, sizeof (idmap_mapping));
	mapping.id1.idtype = IDMAP_GID;
	mapping.id1.idmap_id_u.uid = gid;
	mapping.id2.idtype = IDMAP_SID;

	bzero(&results, sizeof (idmap_ids_res));

	args.idmap_mapping_batch_len = 1;
	args.idmap_mapping_batch_val = &mapping;

	if (kidmap_rpc_call(op, xdr_idmap_mapping_batch,
	    (caddr_t)&args, xdr_idmap_ids_res,
	    (caddr_t)&results) == 0) {
		/* Door call succeded */
		if (results.ids.ids_len >= 1 &&
		    results.ids.ids_val[0].id.idtype == IDMAP_SID) {
			status = results.ids.ids_val[0].retcode;
			id = &results.ids.ids_val[0].id;
			*sid_prefix = kidmap_find_sid_prefix(
			    id->idmap_id_u.sid.prefix);
			*rid = id->idmap_id_u.sid.rid;
			if (status == IDMAP_SUCCESS) {
				kidmap_cache_add_sidbygid(&idmap_cache,
				    *sid_prefix, *rid, gid);
			}
		} else {
			status = IDMAP_ERR_NOMAPPING;
			*rid = 0;
			*sid_prefix = NULL;
		}
		xdr_free(xdr_idmap_ids_res, (char *)&results);
	} else {
		/* Door call failed */
		status = IDMAP_ERR_NOMAPPING;
		*rid = 0;
		*sid_prefix = NULL;
	}
	return (status);
}

/*
 * Create handle to get SID to UID/GID mapping entries
 *
 * Input:
 * 	none
 * Return:
 *	get_handle
 *
 */
idmap_get_handle_t *
kidmap_get_create(void)
{
	idmap_get_handle_t *handle;
#define	INIT_MAPPING_SIZE	6

	handle = kmem_zalloc(sizeof (idmap_get_handle_t), KM_SLEEP);

	handle->mapping = kmem_zalloc((sizeof (idmap_mapping)) *
	    INIT_MAPPING_SIZE, KM_SLEEP);

	handle->result = kmem_zalloc((sizeof (idmap_get_res)) *
	    INIT_MAPPING_SIZE, KM_SLEEP);
	handle->mapping_size = INIT_MAPPING_SIZE;
	handle->cache = &idmap_cache;

	return (handle);
}

/*
 * Internal routine to extend a "get_handle"
 */
static void
kidmap_get_extend(idmap_get_handle_t *get_handle)
{
	idmap_mapping *mapping;
	idmap_get_res *result;
	int new_size = get_handle->mapping_size + INIT_MAPPING_SIZE;

	mapping = kmem_zalloc((sizeof (idmap_mapping)) *
	    new_size, KM_SLEEP);
	(void) memcpy(mapping, get_handle->mapping,
	    (sizeof (idmap_mapping)) * get_handle->mapping_size);

	result = kmem_zalloc((sizeof (idmap_get_res)) *
	    new_size, KM_SLEEP);
	(void) memcpy(result, get_handle->result,
	    (sizeof (idmap_get_res)) * get_handle->mapping_size);

	kmem_free(get_handle->mapping,
	    (sizeof (idmap_mapping)) * get_handle->mapping_size);
	get_handle->mapping = mapping;

	kmem_free(get_handle->result,
	    (sizeof (idmap_get_res)) * get_handle->mapping_size);
	get_handle->result = result;

	get_handle->mapping_size = new_size;
}


/*
 * Given Domain SID and RID, get UID
 *
 * Input:
 * sid_prefix	- Domain SID in canonical form
 * rid	- RID
 *
 * Output:
 * stat - status of the get request
 * uid  - POSIX UID if stat == IDMAP_SUCCESS
 *
 * Note: The output parameters will be set by idmap_get_mappings()
 */
idmap_stat
kidmap_batch_getuidbysid(idmap_get_handle_t *get_handle, const char *sid_prefix,
			uint32_t rid, uid_t *uid, idmap_stat *stat)
{
	idmap_mapping	*mapping;
	idmap_get_res 	*result;

	if (get_handle == NULL || sid_prefix == NULL ||
	    uid == NULL || stat == NULL)
		return (IDMAP_ERR_ARG);

	if (kidmap_cache_lookup_uidbysid(get_handle->cache, sid_prefix,
	    rid, uid) == IDMAP_SUCCESS) {
		*stat = IDMAP_SUCCESS;
		return (IDMAP_SUCCESS);
	}

	if (get_handle->mapping_num >= get_handle->mapping_size)
		kidmap_get_extend(get_handle);

	mapping = &get_handle->mapping[get_handle->mapping_num];
	mapping->flag = 0;
	mapping->id1.idtype = IDMAP_SID;
	mapping->id1.idmap_id_u.sid.prefix = (char *)sid_prefix;
	mapping->id1.idmap_id_u.sid.rid = rid;
	mapping->id2.idtype = IDMAP_UID;

	result = &get_handle->result[get_handle->mapping_num];
	result->idtype = IDMAP_UID;
	result->uid = uid;
	result->gid = NULL;
	result->pid = NULL;
	result->sid_prefix = NULL;
	result->rid = NULL;
	result->is_user = NULL;
	result->stat = stat;

	get_handle->mapping_num++;

	return (IDMAP_SUCCESS);
}


/*
 * Given Domain SID and RID, get GID
 *
 * Input:
 * sid_prefix	- Domain SID in canonical form
 * rid	- RID
 *
 * Output:
 * stat - status of the get request
 * gid  - POSIX GID if stat == IDMAP_SUCCESS
 *
 * Note: The output parameters will be set by idmap_get_mappings()
 */
idmap_stat
kidmap_batch_getgidbysid(idmap_get_handle_t *get_handle, const char *sid_prefix,
			uint32_t rid, uid_t *gid, idmap_stat *stat)
{
	idmap_mapping	*mapping;
	idmap_get_res 	*result;

	if (get_handle == NULL || sid_prefix == NULL ||
	    gid == NULL || stat == NULL)
		return (IDMAP_ERR_ARG);

	if (kidmap_cache_lookup_gidbysid(get_handle->cache, sid_prefix,
	    rid, gid) == IDMAP_SUCCESS) {
		*stat = IDMAP_SUCCESS;
		return (IDMAP_SUCCESS);
	}

	if (get_handle->mapping_num >= get_handle->mapping_size)
		kidmap_get_extend(get_handle);

	mapping = &get_handle->mapping[get_handle->mapping_num];
	mapping->flag = 0;
	mapping->id1.idtype = IDMAP_SID;
	mapping->id1.idmap_id_u.sid.prefix = (char *)sid_prefix;
	mapping->id1.idmap_id_u.sid.rid = rid;
	mapping->id2.idtype = IDMAP_GID;

	result = &get_handle->result[get_handle->mapping_num];
	result->idtype = IDMAP_GID;
	result->uid = NULL;
	result->gid = gid;
	result->pid = NULL;
	result->sid_prefix = NULL;
	result->rid = NULL;
	result->is_user = NULL;
	result->stat = stat;

	get_handle->mapping_num++;

	return (IDMAP_SUCCESS);
}


/*
 * Given Domain SID and RID, get Posix ID
 *
 * Input:
 * sid_prefix	- Domain SID in canonical form
 * rid	- RID
 *
 * Output:
 * stat    - status of the get request
 * is_user - user or group
 * pid     - POSIX UID if stat == IDMAP_SUCCESS and is_user == 1
 *           POSIX GID if stat == IDMAP_SUCCESS and is_user == 0
 *
 * Note: The output parameters will be set by idmap_get_mappings()
 */
idmap_stat
kidmap_batch_getpidbysid(idmap_get_handle_t *get_handle, const char *sid_prefix,
		uint32_t rid, uid_t *pid, int *is_user, idmap_stat *stat)
{
	idmap_mapping	*mapping;
	idmap_get_res 	*result;

	if (get_handle == NULL || sid_prefix == NULL || pid == NULL ||
	    is_user == NULL || stat == NULL)
		return (IDMAP_ERR_ARG);

	if (kidmap_cache_lookup_pidbysid(get_handle->cache, sid_prefix,
	    rid, pid, is_user) == IDMAP_SUCCESS) {
		*stat = IDMAP_SUCCESS;
		return (IDMAP_SUCCESS);
	}


	if (get_handle->mapping_num >= get_handle->mapping_size)
		kidmap_get_extend(get_handle);

	mapping = &get_handle->mapping[get_handle->mapping_num];
	mapping->flag = 0;
	mapping->id1.idtype = IDMAP_SID;
	mapping->id1.idmap_id_u.sid.prefix = (char *)sid_prefix;
	mapping->id1.idmap_id_u.sid.rid = rid;
	mapping->id2.idtype = IDMAP_POSIXID;

	result = &get_handle->result[get_handle->mapping_num];
	result->idtype = IDMAP_POSIXID;
	result->uid = NULL;
	result->gid = NULL;
	result->pid = pid;
	result->sid_prefix = NULL;
	result->rid = NULL;
	result->is_user = is_user;
	result->stat = stat;

	get_handle->mapping_num++;

	return (IDMAP_SUCCESS);
}


/*
 * Given UID, get SID and RID
 *
 * Input:
 * uid  - POSIX UID
 *
 * Output:
 * stat - status of the get request
 * sid  - SID in canonical form (if stat == IDMAP_SUCCESS)
 * rid	- RID (if stat == IDMAP_SUCCESS)
 *
 * Note: The output parameters will be set by idmap_get_mappings()
 */
idmap_stat
kidmap_batch_getsidbyuid(idmap_get_handle_t *get_handle, uid_t uid,
		const char **sid_prefix, uint32_t *rid, idmap_stat *stat)
{
	idmap_mapping	*mapping;
	idmap_get_res 	*result;

	if (get_handle == NULL || sid_prefix == NULL ||
	    rid == NULL || stat == NULL)
		return (IDMAP_ERR_ARG);

	if (kidmap_cache_lookup_sidbyuid(get_handle->cache, sid_prefix,
	    rid, uid) == IDMAP_SUCCESS) {
		*stat = IDMAP_SUCCESS;
		return (IDMAP_SUCCESS);
	}

	if (get_handle->mapping_num >= get_handle->mapping_size)
		kidmap_get_extend(get_handle);

	mapping = &get_handle->mapping[get_handle->mapping_num];
	mapping->flag = 0;
	mapping->id1.idtype = IDMAP_UID;
	mapping->id1.idmap_id_u.uid = uid;
	mapping->id2.idtype = IDMAP_SID;

	result = &get_handle->result[get_handle->mapping_num];
	result->idtype = IDMAP_SID;
	result->uid = NULL;
	result->gid = NULL;
	result->pid = NULL;
	result->sid_prefix = sid_prefix;
	result->rid = rid;
	result->is_user = NULL;
	result->stat = stat;

	get_handle->mapping_num++;

	return (IDMAP_SUCCESS);
}


/*
 * Given GID, get SID and RID
 *
 * Input:
 * gid  - POSIX GID
 *
 * Output:
 * stat - status of the get request
 * sid  - SID in canonical form (if stat == IDMAP_SUCCESS)
 * rid	- RID (if stat == IDMAP_SUCCESS)
 *
 * Note: The output parameters will be set by idmap_get_mappings()
 */
idmap_stat
kidmap_batch_getsidbygid(idmap_get_handle_t *get_handle, gid_t gid,
		const char **sid_prefix, uint32_t *rid, idmap_stat *stat)
{
	idmap_mapping	*mapping;
	idmap_get_res 	*result;

	if (get_handle == NULL || sid_prefix == NULL ||
	    rid == NULL || stat == NULL)
		return (IDMAP_ERR_ARG);

	if (kidmap_cache_lookup_sidbygid(get_handle->cache, sid_prefix,
	    rid, gid) == IDMAP_SUCCESS) {
		*stat = IDMAP_SUCCESS;
		return (IDMAP_SUCCESS);
	}

	if (get_handle->mapping_num >= get_handle->mapping_size)
		kidmap_get_extend(get_handle);

	mapping = &get_handle->mapping[get_handle->mapping_num];
	mapping->flag = 0;
	mapping->id1.idtype = IDMAP_GID;
	mapping->id1.idmap_id_u.gid = gid;
	mapping->id2.idtype = IDMAP_SID;

	result = &get_handle->result[get_handle->mapping_num];
	result->idtype = IDMAP_SID;
	result->uid = NULL;
	result->gid = NULL;
	result->pid = NULL;
	result->sid_prefix = sid_prefix;
	result->rid = rid;
	result->is_user = NULL;
	result->stat = stat;

	get_handle->mapping_num++;

	return (IDMAP_SUCCESS);
}


/*
 * Process the batched "get mapping" requests. The results (i.e.
 * status and identity) will be available in the data areas
 * provided by individual requests.
 *
 * If the door call fails the status IDMAP_ERR_NOMAPPING is
 * return and the UID or UID result is set to "nobody"
 */

idmap_stat
kidmap_get_mappings(idmap_get_handle_t *get_handle)
{
	idmap_mapping_batch	args;
	idmap_ids_res		results;
	uint32_t		op = IDMAP_GET_MAPPED_IDS;
	idmap_mapping		*mapping;
	idmap_get_res		*result;
	idmap_id		*id;
	int			status;
	int			i;
	const char		*sid_prefix;
	int			is_user;

	if (get_handle == NULL)
		return (IDMAP_ERR_ARG);

	if (get_handle->mapping_num == 0)
		return (IDMAP_SUCCESS);

	bzero(&results, sizeof (idmap_ids_res));

	args.idmap_mapping_batch_len = get_handle->mapping_num;
	args.idmap_mapping_batch_val = get_handle->mapping;

	if (kidmap_rpc_call(op, xdr_idmap_mapping_batch,
	    (caddr_t)&args, xdr_idmap_ids_res,
	    (caddr_t)&results) == 0) {
		/* Door call succeded */
		status = IDMAP_SUCCESS;
		for (i = 0; i < get_handle->mapping_num; i++) {
			mapping = &get_handle->mapping[i];
			result =  &get_handle->result[i];

			if (i > results.ids.ids_len) {
				*result->stat =	IDMAP_ERR_NOMAPPING;
				if (result->uid)
					*result->uid = UID_NOBODY;
				if (result->gid)
					*result->gid = GID_NOBODY;
				if (result->pid)
					*result->pid = UID_NOBODY;
				if (result->is_user)
					*result->is_user = 1;
				if (result->sid_prefix)
					*result->sid_prefix = NULL;
				if (result->rid)
					*result->rid = 0;
				continue;
			}
			*result->stat = results.ids.ids_val[i].retcode;

			id = &results.ids.ids_val[i].id;
			switch (id->idtype) {
			case IDMAP_UID:
				if (result->uid)
					*result->uid = id->idmap_id_u.uid;
				if (result->pid)
					*result->pid = id->idmap_id_u.uid;
				if (result->is_user)
					*result->is_user = 1;
				sid_prefix = kidmap_find_sid_prefix(
				    mapping->id1.idmap_id_u.sid.prefix);
				if (*result->stat == IDMAP_SUCCESS &&
				    result->uid)
					kidmap_cache_add_uidbysid(
					    get_handle->cache,
					    sid_prefix,
					    mapping->id1.idmap_id_u.sid.rid,
					    id->idmap_id_u.uid);
				else if (*result->stat == IDMAP_SUCCESS &&
				    result->pid)
					kidmap_cache_add_pidbysid(
					    get_handle->cache,
					    sid_prefix,
					    mapping->id1.idmap_id_u.sid.rid,
					    id->idmap_id_u.uid, 1);
				break;

			case IDMAP_GID:
				if (result->gid)
					*result->gid = id->idmap_id_u.gid;
				if (result->pid)
					*result->pid = id->idmap_id_u.gid;
				if (result->is_user)
					*result->is_user = 0;
				sid_prefix = kidmap_find_sid_prefix(
				    mapping->id1.idmap_id_u.sid.prefix);
				if (*result->stat == IDMAP_SUCCESS &&
				    result->gid)
					kidmap_cache_add_gidbysid(
					    get_handle->cache,
					    sid_prefix,
					    mapping->id1.idmap_id_u.sid.rid,
					    id->idmap_id_u.gid);
				else if (*result->stat == IDMAP_SUCCESS &&
				    result->pid)
					kidmap_cache_add_pidbysid(
					    get_handle->cache,
					    sid_prefix,
					    mapping->id1.idmap_id_u.sid.rid,
					    id->idmap_id_u.gid, 0);
				break;

			case IDMAP_SID:
				sid_prefix = kidmap_find_sid_prefix(
				    id->idmap_id_u.sid.prefix);
				if (result->sid_prefix && result->rid) {
					*result->sid_prefix = sid_prefix;
					*result->rid = id->idmap_id_u.sid.rid;
				}
				if (*result->stat == IDMAP_SUCCESS &&
				    mapping->id1.idtype == IDMAP_UID)
					kidmap_cache_add_sidbyuid(
					    get_handle->cache,
					    sid_prefix,
					    id->idmap_id_u.sid.rid,
					    mapping->id1.idmap_id_u.uid);
				else if (*result->stat == IDMAP_SUCCESS &&
				    mapping->id1.idtype == IDMAP_GID)
					kidmap_cache_add_sidbygid(
					    get_handle->cache,
					    sid_prefix,
					    id->idmap_id_u.sid.rid,
					    mapping->id1.idmap_id_u.gid);
				break;

			default:
				*result->stat = IDMAP_ERR_NORESULT;
				if (result->uid)
					*result->uid = UID_NOBODY;
				if (result->gid)
					*result->gid = GID_NOBODY;
				if (result->pid)
					*result->pid = UID_NOBODY;
				if (result->is_user)
					*result->is_user = 1;
				if (result->sid_prefix)
					*result->sid_prefix = NULL;
				if (result->rid)
					*result->rid = 0;
				break;
			}
		}
		xdr_free(xdr_idmap_ids_res, (char *)&results);
	} else {
		/* Door call failed */
		status = IDMAP_ERR_NOMAPPING;
		for (i = 0; i < get_handle->mapping_num; i++) {
			result =  &get_handle->result[i];

			*result->stat = IDMAP_ERR_NOMAPPING;
			if (result->uid)
				*result->uid = UID_NOBODY;
			if (result->gid)
				*result->gid = GID_NOBODY;
			if (result->pid)
				*result->pid = UID_NOBODY;
			if (result->is_user)
				*result->is_user = 1;
			if (result->sid_prefix)
				*result->sid_prefix = NULL;
			if (result->rid)
				*result->rid = 0;
		}
	}

	/* Reset get_handle for new resquests */
	get_handle->mapping_num = 0;
	return (status);
}


/*
 * Destroy the "get mapping" handle
 */
void
kidmap_get_destroy(idmap_get_handle_t *get_handle)
{
	if (get_handle == NULL)
		return;

	kmem_free(get_handle->mapping,
	    (sizeof (idmap_mapping)) * get_handle->mapping_size);
	get_handle->mapping = NULL;

	kmem_free(get_handle->result,
	    (sizeof (idmap_get_res)) * get_handle->mapping_size);
	get_handle->result = NULL;

	kmem_free(get_handle, sizeof (idmap_get_handle_t));
}


static int
kidmap_rpc_call(uint32_t op, xdrproc_t xdr_args, caddr_t args,
		xdrproc_t xdr_res, caddr_t res)
{
	XDR		xdr_ctx;
	struct	rpc_msg reply_msg;
	char		*inbuf_ptr = NULL;
	size_t		inbuf_size = 4096;
	char		*outbuf_ptr = NULL;
	size_t 		outbuf_size = 4096;
	size_t		size;
	int		status = 0;
	door_arg_t	params;
	int 		retry = 0;

	params.rbuf = NULL;
	params.rsize = 0;

retry:
	inbuf_ptr = kmem_alloc(inbuf_size, KM_SLEEP);
	outbuf_ptr = kmem_alloc(outbuf_size, KM_SLEEP);

	xdrmem_create(&xdr_ctx, inbuf_ptr, inbuf_size, XDR_ENCODE);
	atomic_inc_32(&call_msg.rm_xid);
	if (!xdr_callhdr(&xdr_ctx, &call_msg)) {
#ifdef	DEBUG
		cmn_err(CE_WARN, "idmap: xdr encoding header error");
#endif	/* DEBUG */
		status = -1;
		goto exit;
	}

	if (!xdr_uint32(&xdr_ctx, &op) ||
	    /* Auth none */
	    !xdr_opaque_auth(&xdr_ctx, &_null_auth) ||
	    !xdr_opaque_auth(&xdr_ctx, &_null_auth) ||
	    /* RPC args */
	    !xdr_args(&xdr_ctx, args)) {
#ifdef	DEBUG
		cmn_err(CE_WARN, "idmap: xdr encoding error");
#endif	/* DEBUG */
		if (retry > 2) {
			status = -1;
			goto exit;
		}
		retry++;
		if (inbuf_ptr) {
			kmem_free(inbuf_ptr, inbuf_size);
			inbuf_ptr = NULL;
		}
		if (outbuf_ptr) {
			kmem_free(outbuf_ptr, outbuf_size);
			outbuf_ptr = NULL;
		}
		if ((size = xdr_sizeof(xdr_args, args)) == 0) {
#ifdef	DEBUG
			cmn_err(CE_WARN, "idmap: xdr_sizeof error");
#endif	/* DEBUG */
			status = -1;
			goto exit;
		}
		inbuf_size = size + 1024;
		outbuf_size = size + 1024;
		goto retry;
	}

	params.data_ptr = inbuf_ptr;
	params.data_size = XDR_GETPOS(&xdr_ctx);
	params.desc_ptr = NULL;
	params.desc_num = 0;
	params.rbuf = outbuf_ptr;
	params.rsize = outbuf_size;

	if (kidmap_call_door(&params) != 0) {
		status = -1;
		goto exit;
	}

	reply_msg.acpted_rply.ar_verf = _null_auth;
	reply_msg.acpted_rply.ar_results.where = res;
	reply_msg.acpted_rply.ar_results.proc = xdr_res;
	xdrmem_create(&xdr_ctx, params.data_ptr, params.data_size, XDR_DECODE);
	if (xdr_replymsg(&xdr_ctx, &reply_msg)) {
		if (reply_msg.rm_reply.rp_stat != MSG_ACCEPTED ||
		    reply_msg.rm_reply.rp_acpt.ar_stat != SUCCESS) {
			status = -1;
			goto exit;
		}
	} else {
#ifdef	DEBUG
		cmn_err(CE_WARN, "idmap: xdr decoding reply message error");
#endif	/* DEBUG */
		status = -1;
	}

exit:
	if (outbuf_ptr != params.rbuf && params.rbuf != NULL)
		kmem_free(params.rbuf, params.rsize);
	if (inbuf_ptr)
		kmem_free(inbuf_ptr, inbuf_size);
	if (outbuf_ptr)
		kmem_free(outbuf_ptr, outbuf_size);
	return (status);
}
