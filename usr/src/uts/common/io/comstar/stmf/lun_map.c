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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/disp.h>
#include <sys/byteorder.h>
#include <sys/atomic.h>

#include <sys/stmf.h>
#include <sys/lpif.h>
#include <sys/portif.h>
#include <sys/stmf_ioctl.h>

#include "stmf_impl.h"
#include "lun_map.h"
#include "stmf_state.h"

void stmf_update_sessions_per_ve(stmf_view_entry_t *ve,
		stmf_lu_t *lu, int action);
void stmf_add_lus_to_session_per_vemap(stmf_i_local_port_t *ilport,
		stmf_i_scsi_session_t *iss, stmf_lun_map_t *vemap);
stmf_id_data_t *stmf_lookup_group_for_host(uint8_t *ident, uint16_t ident_size);
stmf_status_t stmf_add_ent_to_map(stmf_lun_map_t *sm, void *ent, uint8_t *lun);
stmf_status_t stmf_remove_ent_from_map(stmf_lun_map_t *sm, uint8_t *lun);
uint16_t stmf_get_next_free_lun(stmf_lun_map_t *sm, uint8_t *lun);
stmf_status_t stmf_add_tg(uint8_t *tg_name, uint16_t tg_name_size,
		int allow_special, uint32_t *err_detail);
stmf_status_t stmf_add_hg(uint8_t *hg_name, uint16_t hg_name_size,
		int allow_special, uint32_t *err_detail);
stmf_i_local_port_t *stmf_targetident_to_ilport(uint8_t *target_ident,
		uint16_t ident_size);
stmf_i_scsi_session_t *stmf_lookup_session_for_hostident(
		stmf_i_local_port_t *ilport, uint8_t *host_ident,
		uint16_t ident_size);
stmf_i_lu_t *stmf_luident_to_ilu(uint8_t *lu_ident);
stmf_lun_map_t *stmf_get_ve_map_per_ids(stmf_id_data_t *tgid,
		stmf_id_data_t *hgid);
stmf_lun_map_t *stmf_duplicate_ve_map(stmf_lun_map_t *src);
int stmf_merge_ve_map(stmf_lun_map_t *src, stmf_lun_map_t *dst,
		stmf_lun_map_t **pp_ret_map, stmf_merge_flags_t mf);
void stmf_destroy_ve_map(stmf_lun_map_t *dst);
void stmf_free_id(stmf_id_data_t *id);


/*
 * Init the view
 */
void
stmf_view_init()
{
	uint8_t grpname_forall = '*';
	(void) stmf_add_hg(&grpname_forall, 1, 1, NULL);
	(void) stmf_add_tg(&grpname_forall, 1, 1, NULL);
}

/*
 * Clear config database here
 */
void
stmf_view_clear_config()
{
	stmf_id_data_t *idgrp, *idgrp_next, *idmemb, *idmemb_next;
	stmf_ver_tg_t *vtg, *vtg_next;
	stmf_ver_hg_t *vhg, *vhg_next;
	stmf_view_entry_t *ve, *ve_next;
	stmf_i_lu_t	*ilu;
	stmf_id_list_t	*idlist;
	stmf_i_local_port_t *ilport;

	for (vtg = stmf_state.stmf_ver_tg_head; vtg; vtg = vtg_next) {
		for (vhg = vtg->vert_verh_list; vhg; vhg = vhg_next) {
			if (vhg->verh_ve_map.lm_nentries) {
				kmem_free(vhg->verh_ve_map.lm_plus,
				    vhg->verh_ve_map.lm_nentries *
				    sizeof (void *));
			}
			vhg_next = vhg->verh_next;
			kmem_free(vhg, sizeof (stmf_ver_hg_t));
		}
		vtg_next = vtg->vert_next;
		kmem_free(vtg, sizeof (stmf_ver_tg_t));
	}
	stmf_state.stmf_ver_tg_head = NULL;

	if (stmf_state.stmf_luid_list.id_count) {
		/* clear the views for lus */
		for (idmemb = stmf_state.stmf_luid_list.idl_head;
		    idmemb; idmemb = idmemb_next) {
			for (ve = (stmf_view_entry_t *)idmemb->id_impl_specific;
			    ve; ve = ve_next) {
				ve_next = ve->ve_next;
				ve->ve_hg->id_refcnt--;
				ve->ve_tg->id_refcnt--;
				kmem_free(ve, sizeof (stmf_view_entry_t));
			}
			if (idmemb->id_pt_to_object) {
				ilu = (stmf_i_lu_t *)(idmemb->id_pt_to_object);
				ilu->ilu_luid = NULL;
			}
			idmemb_next = idmemb->id_next;
			stmf_free_id(idmemb);
		}
		stmf_state.stmf_luid_list.id_count = 0;
		stmf_state.stmf_luid_list.idl_head =
		    stmf_state.stmf_luid_list.idl_tail = NULL;
	}

	if (stmf_state.stmf_hg_list.id_count) {
		/* free all the host group */
		for (idgrp = stmf_state.stmf_hg_list.idl_head;
		    idgrp; idgrp = idgrp_next) {
			idlist = (stmf_id_list_t *)(idgrp->id_impl_specific);
			if (idlist->id_count) {
				for (idmemb = idlist->idl_head; idmemb;
				    idmemb = idmemb_next) {
					idmemb_next = idmemb->id_next;
					stmf_free_id(idmemb);
				}
			}
			idgrp_next = idgrp->id_next;
			stmf_free_id(idgrp);
		}
		stmf_state.stmf_hg_list.id_count = 0;
		stmf_state.stmf_hg_list.idl_head =
		    stmf_state.stmf_hg_list.idl_tail = NULL;
	}
	if (stmf_state.stmf_tg_list.id_count) {
		/* free all the target group */
		for (idgrp = stmf_state.stmf_tg_list.idl_head;
		    idgrp; idgrp = idgrp_next) {
			idlist = (stmf_id_list_t *)(idgrp->id_impl_specific);
			if (idlist->id_count) {
				for (idmemb = idlist->idl_head; idmemb;
				    idmemb = idmemb_next) {
					idmemb_next = idmemb->id_next;
					stmf_free_id(idmemb);
				}
			}
			idgrp_next = idgrp->id_next;
			stmf_free_id(idgrp);
		}
		stmf_state.stmf_tg_list.id_count = 0;
		stmf_state.stmf_tg_list.idl_head =
		    stmf_state.stmf_tg_list.idl_tail = NULL;
	}

	for (ilport = stmf_state.stmf_ilportlist; ilport;
	    ilport = ilport->ilport_next) {
		ilport->ilport_tg = NULL;
	}
}

/*
 * Create luns map for session based on the view
 */
stmf_status_t
stmf_session_create_lun_map(stmf_i_local_port_t *ilport,
		stmf_i_scsi_session_t *iss)
{
	stmf_id_data_t *tg;
	stmf_id_data_t *hg;
	stmf_ver_tg_t	*vertg;
	char *phg_data, *ptg_data;
	stmf_ver_hg_t	*verhg;
	stmf_lun_map_t	*ve_map;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	tg = ilport->ilport_tg;
	hg = stmf_lookup_group_for_host(iss->iss_ss->ss_rport_id->ident,
	    iss->iss_ss->ss_rport_id->ident_length);
	iss->iss_hg = hg;

	/*
	 * get the view entry map,
	 * take all host/target group into consideration
	 */
	ve_map = stmf_duplicate_ve_map(0);
	for (vertg = stmf_state.stmf_ver_tg_head; vertg != NULL;
	    vertg = vertg->vert_next) {
		ptg_data = (char *)vertg->vert_tg_ref->id_data;
		if ((ptg_data[0] != '*') && (!tg ||
		    ((tg->id_data[0] != '*') &&
		    (vertg->vert_tg_ref != tg)))) {
			continue;
		}
		for (verhg = vertg->vert_verh_list; verhg != NULL;
		    verhg = verhg->verh_next) {
			phg_data = (char *)verhg->verh_hg_ref->id_data;
			if ((phg_data[0] != '*') && (!hg ||
			    ((hg->id_data[0] != '*') &&
			    (verhg->verh_hg_ref != hg)))) {
				continue;
			}
			(void) stmf_merge_ve_map(&verhg->verh_ve_map, ve_map,
			    &ve_map, 0);
		}
	}


	if (ve_map->lm_nluns) {
		stmf_add_lus_to_session_per_vemap(ilport, iss, ve_map);
	}
	/* not configured, cannot access any luns for now */

	stmf_destroy_ve_map(ve_map);

	return (STMF_SUCCESS);
}

/*
 * destroy lun map for session
 */
/* ARGSUSED */
stmf_status_t
stmf_session_destroy_lun_map(stmf_i_local_port_t *ilport,
		stmf_i_scsi_session_t *iss)
{
	stmf_lun_map_t *sm;
	stmf_i_lu_t *ilu;
	uint16_t n;
	stmf_lun_map_ent_t *ent;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));
	/*
	 * to avoid conflict with updating session's map,
	 * which only grab stmf_lock
	 */
	sm = iss->iss_sm;
	iss->iss_sm = NULL;
	iss->iss_hg = NULL;
	if (sm->lm_nentries) {
		for (n = 0; n < sm->lm_nentries; n++) {
			if ((ent = (stmf_lun_map_ent_t *)sm->lm_plus[n])
			    != NULL) {
				if (ent->ent_itl_datap) {
					stmf_do_itl_dereg(ent->ent_lu,
					    ent->ent_itl_datap,
					    STMF_ITL_REASON_IT_NEXUS_LOSS);
				}
				ilu = (stmf_i_lu_t *)
				    ent->ent_lu->lu_stmf_private;
				atomic_dec_32(&ilu->ilu_ref_cnt);
				kmem_free(sm->lm_plus[n],
				    sizeof (stmf_lun_map_ent_t));
			}
		}
		kmem_free(sm->lm_plus,
		    sizeof (stmf_lun_map_ent_t *) * sm->lm_nentries);
	}

	kmem_free(sm, sizeof (*sm));
	return (STMF_SUCCESS);
}

/*
 * Expects the session lock to be held.
 */
stmf_xfer_data_t *
stmf_session_prepare_report_lun_data(stmf_lun_map_t *sm)
{
	stmf_xfer_data_t *xd;
	uint16_t nluns, ent;
	uint32_t alloc_size, data_size;
	int i;

	nluns = sm->lm_nluns;

	data_size = 8 + (((uint32_t)nluns) << 3);
	if (nluns == 0) {
		data_size += 8;
	}
	alloc_size = data_size + sizeof (stmf_xfer_data_t) - 4;

	xd = (stmf_xfer_data_t *)kmem_zalloc(alloc_size, KM_NOSLEEP);

	if (xd == NULL)
		return (NULL);

	xd->alloc_size = alloc_size;
	xd->size_left = data_size;

	*((uint32_t *)xd->buf) = BE_32(data_size - 8);
	if (nluns == 0) {
		return (xd);
	}

	ent = 0;

	for (i = 0; ((i < sm->lm_nentries) && (ent < nluns)); i++) {
		if (sm->lm_plus[i] == NULL)
			continue;
		/* Fill in the entry */
		xd->buf[8 + (ent << 3) + 1] = (uchar_t)i;
		xd->buf[8 + (ent << 3) + 0] = ((uchar_t)(i >> 8));
		ent++;
	}

	ASSERT(ent == nluns);

	return (xd);
}

/*
 * Add a lu to active sessions based on LUN inventory.
 * Only invoked when the lu is onlined
 */
void
stmf_add_lu_to_active_sessions(stmf_lu_t *lu)
{
	stmf_id_data_t *luid;
	stmf_view_entry_t	*ve;
	stmf_i_lu_t *ilu;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));
	ilu = (stmf_i_lu_t *)lu->lu_stmf_private;
	ASSERT(ilu->ilu_state == STMF_STATE_ONLINE);

	luid = ((stmf_i_lu_t *)lu->lu_stmf_private)->ilu_luid;

	if (!luid) {
		/* we did not configure view for this lun, so just return */
		return;
	}

	for (ve = (stmf_view_entry_t *)luid->id_impl_specific;
	    ve; ve = ve->ve_next) {
		stmf_update_sessions_per_ve(ve, lu, 1);
	}
}
/*
 * Unmap a lun from all sessions
 */
void
stmf_session_lu_unmapall(stmf_lu_t *lu)
{
	stmf_i_lu_t *ilu;
	stmf_id_data_t *luid;
	stmf_view_entry_t *ve;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	ilu = (stmf_i_lu_t *)lu->lu_stmf_private;

	if (ilu->ilu_ref_cnt == 0)
		return;

	luid = ((stmf_i_lu_t *)lu->lu_stmf_private)->ilu_luid;
	if (!luid) {
		/*
		 * we did not configure view for this lun, this should be
		 * an error
		 */
		return;
	}

	for (ve = (stmf_view_entry_t *)luid->id_impl_specific;
	    ve; ve = ve->ve_next) {
		stmf_update_sessions_per_ve(ve, lu, 0);
		if (ilu->ilu_ref_cnt == 0)
			break;
	}
}
/*
 * add lu to a session, stmf_lock is already held
 */
stmf_status_t
stmf_add_lu_to_session(stmf_i_local_port_t *ilport,
		stmf_i_scsi_session_t	*iss,
		stmf_lu_t *lu,
		uint8_t *lu_nbr)
{
	stmf_lun_map_t *sm = iss->iss_sm;
	stmf_status_t ret;
	stmf_i_lu_t *ilu = (stmf_i_lu_t *)lu->lu_stmf_private;
	stmf_lun_map_ent_t *lun_map_ent;
	uint32_t new_flags = 0;
	uint16_t luNbr =
	    ((uint16_t)lu_nbr[1] | (((uint16_t)(lu_nbr[0] & 0x3F)) << 8));

	ASSERT(mutex_owned(&stmf_state.stmf_lock));
	ASSERT(!stmf_get_ent_from_map(sm, luNbr));

	if ((sm->lm_nluns == 0) &&
	    ((iss->iss_flags & ISS_BEING_CREATED) == 0)) {
		new_flags = ISS_GOT_INITIAL_LUNS;
		atomic_or_32(&ilport->ilport_flags, ILPORT_SS_GOT_INITIAL_LUNS);
		stmf_state.stmf_process_initial_luns = 1;
	}

	lun_map_ent = (stmf_lun_map_ent_t *)
	    kmem_zalloc(sizeof (stmf_lun_map_ent_t), KM_SLEEP);
	lun_map_ent->ent_lu = lu;
	ret = stmf_add_ent_to_map(sm, (void *)lun_map_ent, lu_nbr);
	ASSERT(ret == STMF_SUCCESS);
	atomic_inc_32(&ilu->ilu_ref_cnt);
	/*
	 * do not set lun inventory flag for standby port
	 * as this would be handled from peer
	 */
	if (ilport->ilport_standby == 0) {
		new_flags |= ISS_LUN_INVENTORY_CHANGED;
	}
	atomic_or_32(&iss->iss_flags, new_flags);
	return (STMF_SUCCESS);
}

/*
 * remvoe lu from a session, stmf_lock is already held
 */
/* ARGSUSED */
stmf_status_t
stmf_remove_lu_from_session(stmf_i_local_port_t *ilport,
		stmf_i_scsi_session_t *iss,
		stmf_lu_t *lu,
		uint8_t *lu_nbr)
{
	stmf_status_t ret;
	stmf_i_lu_t *ilu;
	stmf_lun_map_t *sm = iss->iss_sm;
	stmf_lun_map_ent_t *lun_map_ent;
	uint16_t luNbr =
	    ((uint16_t)lu_nbr[1] | (((uint16_t)(lu_nbr[0] & 0x3F)) << 8));

	ASSERT(mutex_owned(&stmf_state.stmf_lock));
	lun_map_ent = stmf_get_ent_from_map(sm, luNbr);
	ASSERT(lun_map_ent && lun_map_ent->ent_lu == lu);

	ilu = (stmf_i_lu_t *)lu->lu_stmf_private;

	ret = stmf_remove_ent_from_map(sm, lu_nbr);
	ASSERT(ret == STMF_SUCCESS);
	atomic_dec_32(&ilu->ilu_ref_cnt);
	iss->iss_flags |= ISS_LUN_INVENTORY_CHANGED;
	if (lun_map_ent->ent_itl_datap) {
		stmf_do_itl_dereg(lu, lun_map_ent->ent_itl_datap,
		    STMF_ITL_REASON_USER_REQUEST);
	}
	kmem_free((void *)lun_map_ent, sizeof (stmf_lun_map_ent_t));
	return (STMF_SUCCESS);
}

/*
 * add or remove lu from all related sessions based on view entry,
 * action is 0 for delete, 1 for add
 */
void
stmf_update_sessions_per_ve(stmf_view_entry_t *ve,
		stmf_lu_t *lu, int action)
{
	stmf_i_lu_t *ilu_tmp;
	stmf_lu_t *lu_to_add;
	stmf_i_local_port_t *ilport;
	stmf_i_scsi_session_t *iss;
	stmf_id_list_t	*hostlist;
	stmf_id_list_t	*targetlist;
	int all_hg = 0, all_tg = 0;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	if (!lu) {
		ilu_tmp = (stmf_i_lu_t *)ve->ve_luid->id_pt_to_object;
		if (!ilu_tmp)
			return;
		lu_to_add = ilu_tmp->ilu_lu;
	} else {
		lu_to_add = lu;
		ilu_tmp = (stmf_i_lu_t *)lu->lu_stmf_private;
	}

	if (ve->ve_hg->id_data[0] == '*')
		all_hg = 1;
	if (ve->ve_tg->id_data[0] == '*')
		all_tg = 1;
	hostlist = (stmf_id_list_t *)ve->ve_hg->id_impl_specific;
	targetlist = (stmf_id_list_t *)ve->ve_tg->id_impl_specific;

	if ((!all_hg && !hostlist->idl_head) ||
	    (!all_tg && !targetlist->idl_head))
		/* No sessions to be updated */
		return;

	for (ilport = stmf_state.stmf_ilportlist; ilport != NULL;
	    ilport = ilport->ilport_next) {
		if (!all_tg && ilport->ilport_tg != ve->ve_tg)
			continue;
		/* This ilport belongs to the target group */
		rw_enter(&ilport->ilport_lock, RW_WRITER);
		for (iss = ilport->ilport_ss_list; iss != NULL;
		    iss = iss->iss_next) {
			if (!all_hg && iss->iss_hg != ve->ve_hg)
				continue;
			/* This host belongs to the host group */
			if (action == 0) { /* to remove */
				(void) stmf_remove_lu_from_session(ilport, iss,
				    lu_to_add, ve->ve_lun);
				if (ilu_tmp->ilu_ref_cnt == 0) {
					rw_exit(&ilport->ilport_lock);
					return;
				}
			} else {
				(void) stmf_add_lu_to_session(ilport, iss,
				    lu_to_add, ve->ve_lun);
			}
		}
		rw_exit(&ilport->ilport_lock);
	}
}

/*
 * add luns in view entry map to a session,
 * and stmf_lock is already held
 */
void
stmf_add_lus_to_session_per_vemap(stmf_i_local_port_t *ilport,
		stmf_i_scsi_session_t *iss,
		stmf_lun_map_t *vemap)
{
	stmf_lu_t *lu;
	stmf_i_lu_t *ilu;
	stmf_view_entry_t *ve;
	uint32_t	i;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	for (i = 0; i < vemap->lm_nentries; i++) {
		ve = (stmf_view_entry_t *)vemap->lm_plus[i];
		if (!ve)
			continue;
		ilu = (stmf_i_lu_t *)ve->ve_luid->id_pt_to_object;
		if (ilu && ilu->ilu_state == STMF_STATE_ONLINE) {
			lu = ilu->ilu_lu;
			(void) stmf_add_lu_to_session(ilport, iss, lu,
			    ve->ve_lun);
		}
	}
}
/* remove luns in view entry map from a session */
void
stmf_remove_lus_from_session_per_vemap(stmf_i_local_port_t *ilport,
		stmf_i_scsi_session_t *iss,
		stmf_lun_map_t *vemap)
{
	stmf_lu_t *lu;
	stmf_i_lu_t *ilu;
	stmf_view_entry_t *ve;
	uint32_t i;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	for (i = 0; i < vemap->lm_nentries; i++) {
		ve = (stmf_view_entry_t *)vemap->lm_plus[i];
		if (!ve)
			continue;
		ilu = (stmf_i_lu_t *)ve->ve_luid->id_pt_to_object;
		if (ilu && ilu->ilu_state == STMF_STATE_ONLINE) {
			lu = ilu->ilu_lu;
			(void) stmf_remove_lu_from_session(ilport, iss, lu,
			    ve->ve_lun);
		}
	}
}

stmf_id_data_t *
stmf_alloc_id(uint16_t id_size, uint16_t type, uint8_t *id_data,
			uint32_t additional_size)
{
	stmf_id_data_t *id;
	int struct_size, total_size, real_id_size;

	real_id_size = ((uint32_t)id_size + 7) & (~7);
	struct_size = (sizeof (*id) + 7) & (~7);
	total_size = ((additional_size + 7) & (~7)) + struct_size +
	    real_id_size;
	id = (stmf_id_data_t *)kmem_zalloc(total_size, KM_SLEEP);
	id->id_type = type;
	id->id_data_size = id_size;
	id->id_data = ((uint8_t *)id) + struct_size;
	id->id_total_alloc_size = total_size;
	if (additional_size) {
		id->id_impl_specific = ((uint8_t *)id) + struct_size +
		    real_id_size;
	}
	bcopy(id_data, id->id_data, id_size);

	return (id);
}

void
stmf_free_id(stmf_id_data_t *id)
{
	kmem_free(id, id->id_total_alloc_size);
}


stmf_id_data_t *
stmf_lookup_id(stmf_id_list_t *idlist, uint16_t id_size, uint8_t *data)
{
	stmf_id_data_t *id;

	for (id = idlist->idl_head; id != NULL; id = id->id_next) {
		if ((id->id_data_size == id_size) &&
		    (bcmp(id->id_data, data, id_size) == 0)) {
			return (id);
		}
	}

	return (NULL);
}
/* Return the target group which a target belong to */
stmf_id_data_t *
stmf_lookup_group_for_target(uint8_t *ident, uint16_t ident_size)
{
	stmf_id_data_t *tgid;
	stmf_id_data_t *target;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	for (tgid = stmf_state.stmf_tg_list.idl_head; tgid;
	    tgid = tgid->id_next) {
		target = stmf_lookup_id(
		    (stmf_id_list_t *)tgid->id_impl_specific,
		    ident_size, ident);
		if (target)
			return (tgid);
	}
	return (NULL);
}
/* Return the host group which a host belong to */
stmf_id_data_t *
stmf_lookup_group_for_host(uint8_t *ident, uint16_t ident_size)
{
	stmf_id_data_t *hgid;
	stmf_id_data_t *host;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	for (hgid = stmf_state.stmf_hg_list.idl_head; hgid;
	    hgid = hgid->id_next) {
		host = stmf_lookup_id(
		    (stmf_id_list_t *)hgid->id_impl_specific,
		    ident_size, ident);
		if (host)
			return (hgid);
	}
	return (NULL);
}

void
stmf_append_id(stmf_id_list_t *idlist, stmf_id_data_t *id)
{
	id->id_next = NULL;

	if ((id->id_prev = idlist->idl_tail) == NULL) {
		idlist->idl_head = idlist->idl_tail = id;
	} else {
		idlist->idl_tail->id_next = id;
		idlist->idl_tail = id;
	}
	atomic_inc_32(&idlist->id_count);
}

void
stmf_remove_id(stmf_id_list_t *idlist, stmf_id_data_t *id)
{
	if (id->id_next) {
		id->id_next->id_prev = id->id_prev;
	} else {
		idlist->idl_tail = id->id_prev;
	}

	if (id->id_prev) {
		id->id_prev->id_next = id->id_next;
	} else {
		idlist->idl_head = id->id_next;
	}
	atomic_dec_32(&idlist->id_count);
}


/*
 * The refcnts of objects in a view entry are updated when then entry
 * is successfully added. ve_map is just another representation of the
 * view enrtries in a LU. Duplicating or merging a ve map does not
 * affect any refcnts.
 */
stmf_lun_map_t *
stmf_duplicate_ve_map(stmf_lun_map_t *src)
{
	stmf_lun_map_t *dst;
	int i;

	dst = (stmf_lun_map_t *)kmem_zalloc(sizeof (*dst), KM_SLEEP);

	if (src == NULL)
		return (dst);

	if (src->lm_nentries) {
		dst->lm_plus = kmem_zalloc(dst->lm_nentries *
		    sizeof (void *), KM_SLEEP);
		for (i = 0; i < dst->lm_nentries; i++) {
			dst->lm_plus[i] = src->lm_plus[i];
		}
	}

	return (dst);
}

void
stmf_destroy_ve_map(stmf_lun_map_t *dst)
{
	if (dst->lm_nentries) {
		kmem_free(dst->lm_plus, dst->lm_nentries * sizeof (void *));
	}
	kmem_free(dst, sizeof (*dst));
}

int
stmf_merge_ve_map(stmf_lun_map_t *src, stmf_lun_map_t *dst,
		stmf_lun_map_t **pp_ret_map, stmf_merge_flags_t mf)
{
	int i;
	int nentries;
	int to_create_space = 0;

	if (dst == NULL) {
		*pp_ret_map = stmf_duplicate_ve_map(src);
		return (1);
	}

	if (src == NULL || src->lm_nluns == 0) {
		if (mf & MERGE_FLAG_RETURN_NEW_MAP)
			*pp_ret_map = stmf_duplicate_ve_map(dst);
		else
			*pp_ret_map = dst;
		return (1);
	}

	if (mf & MERGE_FLAG_RETURN_NEW_MAP) {
		*pp_ret_map = stmf_duplicate_ve_map(NULL);
		nentries = max(dst->lm_nentries, src->lm_nentries);
		to_create_space = 1;
	} else {
		*pp_ret_map = dst;
		/* If there is not enough space in dst map */
		if (dst->lm_nentries < src->lm_nentries) {
			nentries = src->lm_nentries;
			to_create_space = 1;
		}
	}
	if (to_create_space) {
		void **p;
		p = (void **)kmem_zalloc(nentries * sizeof (void *), KM_SLEEP);
		if (dst->lm_nentries) {
			bcopy(dst->lm_plus, p,
			    dst->lm_nentries * sizeof (void *));
		}
		if (mf & (MERGE_FLAG_RETURN_NEW_MAP == 0))
			kmem_free(dst->lm_plus,
			    dst->lm_nentries * sizeof (void *));
		(*pp_ret_map)->lm_plus = p;
		(*pp_ret_map)->lm_nentries = nentries;
	}

	for (i = 0; i < src->lm_nentries; i++) {
		if (src->lm_plus[i] == NULL)
			continue;
		if (dst->lm_plus[i] != NULL) {
			if (mf & MERGE_FLAG_NO_DUPLICATE) {
				if (mf & MERGE_FLAG_RETURN_NEW_MAP) {
					stmf_destroy_ve_map(*pp_ret_map);
					*pp_ret_map = NULL;
				}
				return (0);
			}
		} else {
			dst->lm_plus[i] = src->lm_plus[i];
			dst->lm_nluns++;
		}
	}

	return (1);
}

/*
 * add host group, id_impl_specific point to a list of hosts,
 * on return, if error happened, err_detail may be assigned if
 * the pointer is not NULL
 */
stmf_status_t
stmf_add_hg(uint8_t *hg_name, uint16_t hg_name_size,
		int allow_special, uint32_t *err_detail)
{
	stmf_id_data_t *id;

	if (!allow_special) {
		if (hg_name[0] == '*')
			return (STMF_INVALID_ARG);
	}

	if (stmf_lookup_id(&stmf_state.stmf_hg_list,
	    hg_name_size, (uint8_t *)hg_name)) {
		if (err_detail)
			*err_detail = STMF_IOCERR_HG_EXISTS;
		return (STMF_ALREADY);
	}
	id = stmf_alloc_id(hg_name_size, STMF_ID_TYPE_HOST_GROUP,
	    (uint8_t *)hg_name, sizeof (stmf_id_list_t));
	stmf_append_id(&stmf_state.stmf_hg_list, id);

	return (STMF_SUCCESS);
}

/* add target group */
stmf_status_t
stmf_add_tg(uint8_t *tg_name, uint16_t tg_name_size,
		int allow_special, uint32_t *err_detail)
{
	stmf_id_data_t *id;

	if (!allow_special) {
		if (tg_name[0] == '*')
			return (STMF_INVALID_ARG);
	}


	if (stmf_lookup_id(&stmf_state.stmf_tg_list, tg_name_size,
	    (uint8_t *)tg_name)) {
		if (err_detail)
			*err_detail = STMF_IOCERR_TG_EXISTS;
		return (STMF_ALREADY);
	}
	id = stmf_alloc_id(tg_name_size, STMF_ID_TYPE_TARGET_GROUP,
	    (uint8_t *)tg_name, sizeof (stmf_id_list_t));
	stmf_append_id(&stmf_state.stmf_tg_list, id);

	return (STMF_SUCCESS);
}

/*
 * insert view entry into list for a luid, if ve->ve_id is 0xffffffff,
 * pick up a smallest available veid for it, and return the veid in ve->ve_id.
 * The view entries list is sorted based on veid.
 */
stmf_status_t
stmf_add_ve_to_luid(stmf_id_data_t *luid, stmf_view_entry_t *ve)
{
	stmf_view_entry_t *ve_tmp = NULL;
	stmf_view_entry_t *ve_prev = NULL;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	ve_tmp = (stmf_view_entry_t *)luid->id_impl_specific;

	if (ve->ve_id != 0xffffffff) {
		for (; ve_tmp; ve_tmp = ve_tmp->ve_next) {
			if (ve_tmp->ve_id > ve->ve_id) {
				break;
			} else if (ve_tmp->ve_id == ve->ve_id) {
				return (STMF_ALREADY);
			}
			ve_prev = ve_tmp;
		}
	} else {
		uint32_t veid = 0;
		/* search the smallest available veid */
		for (; ve_tmp; ve_tmp = ve_tmp->ve_next) {
			ASSERT(ve_tmp->ve_id >= veid);
			if (ve_tmp->ve_id != veid)
				break;
			veid++;
			if (veid == 0xffffffff)
				return (STMF_NOT_SUPPORTED);
			ve_prev = ve_tmp;
		}
		ve->ve_id = veid;
	}

	/* insert before ve_tmp if it exist */
	ve->ve_next = ve_tmp;
	ve->ve_prev = ve_prev;
	if (ve_tmp) {
		ve_tmp->ve_prev = ve;
	}
	if (ve_prev) {
		ve_prev->ve_next = ve;
	} else {
		luid->id_impl_specific = (void *)ve;
	}
	return (STMF_SUCCESS);
}

/* stmf_lock is already held, err_detail may be assigned if error happens */
stmf_status_t
stmf_add_view_entry(stmf_id_data_t *hg, stmf_id_data_t *tg,
		uint8_t *lu_guid, uint32_t *ve_id, uint8_t *lun,
		stmf_view_entry_t **conflicting, uint32_t *err_detail)
{
	stmf_id_data_t *luid;
	stmf_view_entry_t *ve;
	char *phg, *ptg;
	stmf_lun_map_t *ve_map = NULL;
	stmf_ver_hg_t *verhg = NULL, *verhg_ex = NULL;
	stmf_ver_tg_t *vertg = NULL, *vertg_ex = NULL;
	char luid_new;
	uint16_t lun_num;
	stmf_i_lu_t *ilu;
	stmf_status_t ret;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	lun_num = ((uint16_t)lun[1] | (((uint16_t)(lun[0] & 0x3F)) << 8));

	luid = stmf_lookup_id(&stmf_state.stmf_luid_list, 16, lu_guid);
	if (luid == NULL) {
		luid = stmf_alloc_id(16, STMF_ID_TYPE_LU_GUID, lu_guid, 0);
		ilu = stmf_luident_to_ilu(lu_guid);
		if (ilu) {
			ilu->ilu_luid = luid;
			luid->id_pt_to_object = (void *)ilu;
		}
		luid_new = 1;
	} else {
		luid_new = 0;
		ilu = (stmf_i_lu_t *)luid->id_pt_to_object;
	}

	/* The view entry won't be added if there is any confilict */
	phg = (char *)hg->id_data; ptg = (char *)tg->id_data;
	for (ve = (stmf_view_entry_t *)luid->id_impl_specific; ve != NULL;
	    ve = ve->ve_next) {
		if (((phg[0] == '*') || (ve->ve_hg->id_data[0] == '*') ||
		    (hg == ve->ve_hg)) && ((ptg[0] == '*') ||
		    (ve->ve_tg->id_data[0] == '*') || (tg == ve->ve_tg))) {
			*conflicting = ve;
			*err_detail = STMF_IOCERR_VIEW_ENTRY_CONFLICT;
			ret = STMF_ALREADY;
			goto add_ve_err_ret;
		}
	}

	ve_map = stmf_duplicate_ve_map(0);
	for (vertg = stmf_state.stmf_ver_tg_head; vertg != NULL;
	    vertg = vertg->vert_next) {
		ptg = (char *)vertg->vert_tg_ref->id_data;
		if ((ptg[0] != '*') && (tg->id_data[0] != '*') &&
		    (vertg->vert_tg_ref != tg)) {
			continue;
		}
		if (vertg->vert_tg_ref == tg)
			vertg_ex = vertg;
		for (verhg = vertg->vert_verh_list; verhg != NULL;
		    verhg = verhg->verh_next) {
			phg = (char *)verhg->verh_hg_ref->id_data;
			if ((phg[0] != '*') && (hg->id_data[0] != '*') &&
			    (verhg->verh_hg_ref != hg)) {
				continue;
			}
			if ((vertg_ex == vertg) && (verhg->verh_hg_ref == hg))
				verhg_ex = verhg;
			(void) stmf_merge_ve_map(&verhg->verh_ve_map, ve_map,
			    &ve_map, 0);
		}
	}

	if (lun[2] == 0xFF) {
		/* Pick a LUN number */
		lun_num = stmf_get_next_free_lun(ve_map, lun);
		if (lun_num > 0x3FFF) {
			stmf_destroy_ve_map(ve_map);
			ret = STMF_NOT_SUPPORTED;
			goto add_ve_err_ret;
		}
	} else {
		if ((*conflicting = stmf_get_ent_from_map(ve_map, lun_num))
		    != NULL) {
			stmf_destroy_ve_map(ve_map);
			*err_detail = STMF_IOCERR_LU_NUMBER_IN_USE;
			ret = STMF_LUN_TAKEN;
			goto add_ve_err_ret;
		}
	}
	stmf_destroy_ve_map(ve_map);

	/* All is well, do the actual addition now */
	ve = (stmf_view_entry_t *)kmem_zalloc(sizeof (*ve), KM_SLEEP);
	ve->ve_id = *ve_id;
	ve->ve_lun[0] = lun[0];
	ve->ve_lun[1] = lun[1];

	if ((ret = stmf_add_ve_to_luid(luid, ve)) != STMF_SUCCESS) {
		kmem_free(ve, sizeof (stmf_view_entry_t));
		goto add_ve_err_ret;
	}
	ve->ve_hg = hg; hg->id_refcnt++;
	ve->ve_tg = tg; tg->id_refcnt++;
	ve->ve_luid = luid; luid->id_refcnt++;

	*ve_id = ve->ve_id;

	if (luid_new) {
		stmf_append_id(&stmf_state.stmf_luid_list, luid);
	}

	if (vertg_ex == NULL) {
		vertg_ex = (stmf_ver_tg_t *)kmem_zalloc(sizeof (stmf_ver_tg_t),
		    KM_SLEEP);
		vertg_ex->vert_next = stmf_state.stmf_ver_tg_head;
		stmf_state.stmf_ver_tg_head = vertg_ex;
		vertg_ex->vert_tg_ref = tg;
		verhg_ex = vertg_ex->vert_verh_list =
		    (stmf_ver_hg_t *)kmem_zalloc(sizeof (stmf_ver_hg_t),
		    KM_SLEEP);
		verhg_ex->verh_hg_ref = hg;
	}
	if (verhg_ex == NULL) {
		verhg_ex = (stmf_ver_hg_t *)kmem_zalloc(sizeof (stmf_ver_hg_t),
		    KM_SLEEP);
		verhg_ex->verh_next = vertg_ex->vert_verh_list;
		vertg_ex->vert_verh_list = verhg_ex;
		verhg_ex->verh_hg_ref = hg;
	}
	ret = stmf_add_ent_to_map(&verhg_ex->verh_ve_map, ve, ve->ve_lun);
	ASSERT(ret == STMF_SUCCESS);

	/* we need to update the affected session */
	if (stmf_state.stmf_service_running) {
		if (ilu && ilu->ilu_state == STMF_STATE_ONLINE)
			stmf_update_sessions_per_ve(ve, ilu->ilu_lu, 1);
	}

	return (STMF_SUCCESS);
add_ve_err_ret:
	if (luid_new) {
		if (ilu)
			ilu->ilu_luid = NULL;
		stmf_free_id(luid);
	}
	return (ret);
}

stmf_status_t
stmf_add_ent_to_map(stmf_lun_map_t *lm, void *ent, uint8_t *lun)
{
	uint16_t n;
	if (((lun[0] & 0xc0) >> 6) != 0)
		return (STMF_FAILURE);

	n = (uint16_t)lun[1] | (((uint16_t)(lun[0] & 0x3F)) << 8);
try_again_to_add:
	if (lm->lm_nentries && (n < lm->lm_nentries)) {
		if (lm->lm_plus[n] == NULL) {
			lm->lm_plus[n] = ent;
			lm->lm_nluns++;
			return (STMF_SUCCESS);
		} else {
			return (STMF_LUN_TAKEN);
		}
	} else {
		void **pplu;
		uint16_t m = n + 1;
		m = ((m + 7) & ~7) & 0x7FFF;
		pplu = (void **)kmem_zalloc(m * sizeof (void *), KM_SLEEP);
		bcopy(lm->lm_plus, pplu,
		    lm->lm_nentries * sizeof (void *));
		kmem_free(lm->lm_plus, lm->lm_nentries * sizeof (void *));
		lm->lm_plus = pplu;
		lm->lm_nentries = m;
		goto try_again_to_add;
	}
}


stmf_status_t
stmf_remove_ent_from_map(stmf_lun_map_t *lm, uint8_t *lun)
{
	uint16_t n, i;
	uint8_t lutype = (lun[0] & 0xc0) >> 6;
	if (lutype != 0)
		return (STMF_FAILURE);

	n = (uint16_t)lun[1] | (((uint16_t)(lun[0] & 0x3F)) << 8);

	if (n >= lm->lm_nentries)
		return (STMF_NOT_FOUND);
	if (lm->lm_plus[n] == NULL)
		return (STMF_NOT_FOUND);

	lm->lm_plus[n] = NULL;
	lm->lm_nluns--;

	for (i = 0; i < lm->lm_nentries; i++) {
		if (lm->lm_plus[lm->lm_nentries - 1 - i] != NULL)
			break;
	}
	i &= ~15;
	if (i >= 16) {
		void **pplu;
		uint16_t m;
		m = lm->lm_nentries - i;
		pplu = (void **)kmem_zalloc(m * sizeof (void *), KM_SLEEP);
		bcopy(lm->lm_plus, pplu, m * sizeof (void *));
		kmem_free(lm->lm_plus, lm->lm_nentries * sizeof (void *));
		lm->lm_plus = pplu;
		lm->lm_nentries = m;
	}

	return (STMF_SUCCESS);
}

uint16_t
stmf_get_next_free_lun(stmf_lun_map_t *sm, uint8_t *lun)
{
	uint16_t luNbr;


	if (sm->lm_nluns < 0x4000) {
		for (luNbr = 0; luNbr < sm->lm_nentries; luNbr++) {
			if (sm->lm_plus[luNbr] == NULL)
				break;
		}
	} else {
		return (0xFFFF);
	}
	if (lun) {
		bzero(lun, 8);
		lun[1] = luNbr & 0xff;
		lun[0] = (luNbr >> 8) & 0xff;
	}

	return (luNbr);
}

void *
stmf_get_ent_from_map(stmf_lun_map_t *sm, uint16_t lun_num)
{
	if ((lun_num & 0xC000) == 0) {
		if (sm->lm_nentries > lun_num)
			return (sm->lm_plus[lun_num & 0x3FFF]);
		else
			return (NULL);
	}

	return (NULL);
}

int
stmf_add_ve(uint8_t *hgname, uint16_t hgname_size,
		uint8_t *tgname, uint16_t tgname_size,
		uint8_t *lu_guid, uint32_t *ve_id,
		uint8_t *luNbr, uint32_t *err_detail)
{
	stmf_id_data_t *hg;
	stmf_id_data_t *tg;
	stmf_view_entry_t *conflictve;
	stmf_status_t ret;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	hg = stmf_lookup_id(&stmf_state.stmf_hg_list, hgname_size,
	    (uint8_t *)hgname);
	if (!hg) {
		*err_detail = STMF_IOCERR_INVALID_HG;
		return (ENOENT); /* could not find group */
	}
	tg = stmf_lookup_id(&stmf_state.stmf_tg_list, tgname_size,
	    (uint8_t *)tgname);
	if (!tg) {
		*err_detail = STMF_IOCERR_INVALID_TG;
		return (ENOENT); /* could not find group */
	}
	ret = stmf_add_view_entry(hg, tg, lu_guid, ve_id, luNbr,
	    &conflictve, err_detail);

	if (ret == STMF_ALREADY) {
		return (EALREADY);
	} else if (ret == STMF_LUN_TAKEN) {
		return (EEXIST);
	} else if (ret == STMF_NOT_SUPPORTED) {
		return (E2BIG);
	} else if (ret != STMF_SUCCESS) {
		return (EINVAL);
	}
	return (0);
}

int
stmf_remove_ve_by_id(uint8_t *guid, uint32_t veid, uint32_t *err_detail)
{
	stmf_id_data_t *luid;
	stmf_view_entry_t	*ve;
	stmf_ver_tg_t *vtg;
	stmf_ver_hg_t *vhg;
	stmf_ver_tg_t *prev_vtg = NULL;
	stmf_ver_hg_t *prev_vhg = NULL;
	int found = 0;
	stmf_i_lu_t *ilu;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));
	luid = stmf_lookup_id(&stmf_state.stmf_luid_list, 16, guid);
	if (luid == NULL) {
		*err_detail = STMF_IOCERR_INVALID_LU_ID;
		return (ENODEV);
	}
	ilu = (stmf_i_lu_t *)luid->id_pt_to_object;

	for (ve = (stmf_view_entry_t *)luid->id_impl_specific;
	    ve; ve = ve->ve_next) {
		if (ve->ve_id == veid) {
			break;
		}
	}
	if (!ve) {
		*err_detail = STMF_IOCERR_INVALID_VE_ID;
		return (ENODEV);
	}
	/* remove the ve */
	if (ve->ve_next)
		ve->ve_next->ve_prev = ve->ve_prev;
	if (ve->ve_prev)
		ve->ve_prev->ve_next = ve->ve_next;
	else {
		luid->id_impl_specific = (void *)ve->ve_next;
		if (!luid->id_impl_specific) {
			/* don't have any view entries related to this lu */
			stmf_remove_id(&stmf_state.stmf_luid_list, luid);
			if (ilu)
				ilu->ilu_luid = NULL;
			stmf_free_id(luid);
		}
	}

	/* we need to update ver_hg->verh_ve_map */
	for (vtg = stmf_state.stmf_ver_tg_head; vtg; vtg = vtg->vert_next) {
		if (vtg->vert_tg_ref == ve->ve_tg) {
			found = 1;
			break;
		}
		prev_vtg = vtg;
	}
	ASSERT(found);
	found = 0;
	for (vhg = vtg->vert_verh_list; vhg; vhg = vhg->verh_next) {
		if (vhg->verh_hg_ref == ve->ve_hg) {
			found = 1;
			break;
		}
		prev_vhg = vhg;
	}
	ASSERT(found);

	(void) stmf_remove_ent_from_map(&vhg->verh_ve_map, ve->ve_lun);

	/* free verhg if it don't have any ve entries related */
	if (!vhg->verh_ve_map.lm_nluns) {
		/* we don't have any view entry related */
		if (prev_vhg)
			prev_vhg->verh_next = vhg->verh_next;
		else
			vtg->vert_verh_list = vhg->verh_next;

		/* Free entries in case the map still has memory */
		if (vhg->verh_ve_map.lm_nentries) {
			kmem_free(vhg->verh_ve_map.lm_plus,
			    vhg->verh_ve_map.lm_nentries *
			    sizeof (void *));
		}
		kmem_free(vhg, sizeof (stmf_ver_hg_t));
		if (!vtg->vert_verh_list) {
			/* we don't have any ve related */
			if (prev_vtg)
				prev_vtg->vert_next = vtg->vert_next;
			else
				stmf_state.stmf_ver_tg_head = vtg->vert_next;
			kmem_free(vtg, sizeof (stmf_ver_tg_t));
		}
	}

	if (stmf_state.stmf_service_running && ilu &&
	    ilu->ilu_state == STMF_STATE_ONLINE) {
		stmf_update_sessions_per_ve(ve, ilu->ilu_lu, 0);
	}

	ve->ve_hg->id_refcnt--;
	ve->ve_tg->id_refcnt--;

	kmem_free(ve, sizeof (stmf_view_entry_t));
	return (0);
}

int
stmf_add_group(uint8_t *grpname, uint16_t grpname_size,
		stmf_id_type_t group_type, uint32_t *err_detail)
{
	stmf_status_t status;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	if (group_type == STMF_ID_TYPE_HOST_GROUP)
		status = stmf_add_hg(grpname, grpname_size, 0, err_detail);
	else if (group_type == STMF_ID_TYPE_TARGET_GROUP)
		status = stmf_add_tg(grpname, grpname_size, 0, err_detail);
	else {
		return (EINVAL);
	}
	switch (status) {
	case STMF_SUCCESS:
		return (0);
	case STMF_INVALID_ARG:
		return (EINVAL);
	case STMF_ALREADY:
		return (EEXIST);
	default:
		return (EIO);
	}
}

/*
 * Group can only be removed only when it does not have
 * any view entry related
 */
int
stmf_remove_group(uint8_t *grpname, uint16_t grpname_size,
		stmf_id_type_t group_type, uint32_t *err_detail)
{
	stmf_id_data_t *id;
	stmf_id_data_t *idmemb;
	stmf_id_list_t *grp_memblist;
	stmf_i_scsi_session_t *iss;
	stmf_i_local_port_t *ilport;

	if (grpname[0] == '*')
		return (EINVAL);

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	if (group_type == STMF_ID_TYPE_HOST_GROUP)
		id = stmf_lookup_id(&stmf_state.stmf_hg_list,
		    grpname_size, grpname);
	else if (group_type == STMF_ID_TYPE_TARGET_GROUP)
		id = stmf_lookup_id(&stmf_state.stmf_tg_list,
		    grpname_size, grpname);
	if (!id) {
		*err_detail = (group_type == STMF_ID_TYPE_HOST_GROUP)?
		    STMF_IOCERR_INVALID_HG:STMF_IOCERR_INVALID_TG;
		return (ENODEV); /* no such grp */
	}
	if (id->id_refcnt) {
		/* fail, still have viewentry related to it */
		*err_detail = (group_type == STMF_ID_TYPE_HOST_GROUP)?
		    STMF_IOCERR_HG_IN_USE:STMF_IOCERR_TG_IN_USE;
		return (EBUSY);
	}
	grp_memblist = (stmf_id_list_t *)id->id_impl_specific;
	while ((idmemb = grp_memblist->idl_head) != NULL) {
		stmf_remove_id(grp_memblist, idmemb);
		stmf_free_id(idmemb);
	}

	ASSERT(!grp_memblist->id_count);
	if (id->id_type == STMF_ID_TYPE_TARGET_GROUP) {
		for (ilport = stmf_state.stmf_ilportlist; ilport;
		    ilport = ilport->ilport_next) {
			if (ilport->ilport_tg == (void *)id) {
				ilport->ilport_tg = NULL;
			}
		}
		stmf_remove_id(&stmf_state.stmf_tg_list, id);
	} else {
		for (ilport = stmf_state.stmf_ilportlist; ilport;
		    ilport = ilport->ilport_next) {
			for (iss = ilport->ilport_ss_list; iss;
			    iss = iss->iss_next) {
				if (iss->iss_hg == (void *)id)
					iss->iss_hg = NULL;
			}
		}
		stmf_remove_id(&stmf_state.stmf_hg_list, id);
	}
	stmf_free_id(id);
	return (0);

}

int
stmf_add_group_member(uint8_t *grpname, uint16_t grpname_size,
		uint8_t	*entry_ident, uint16_t entry_size,
		stmf_id_type_t entry_type, uint32_t *err_detail)
{
	stmf_id_data_t	*id_grp, *id_alltgt;
	stmf_id_data_t	*id_member;
	stmf_id_data_t	*id_grp_tmp;
	stmf_i_scsi_session_t *iss;
	stmf_i_local_port_t *ilport;
	stmf_lun_map_t *vemap, *vemap_alltgt;
	uint8_t grpname_forall = '*';

	ASSERT(mutex_owned(&stmf_state.stmf_lock));
	ASSERT(grpname[0] != '*');

	if (entry_type == STMF_ID_TYPE_HOST) {
		id_grp = stmf_lookup_id(&stmf_state.stmf_hg_list,
		    grpname_size, grpname);
		id_grp_tmp = stmf_lookup_group_for_host(entry_ident,
		    entry_size);
	} else {
		id_grp = stmf_lookup_id(&stmf_state.stmf_tg_list,
		    grpname_size, grpname);
		id_grp_tmp = stmf_lookup_group_for_target(entry_ident,
		    entry_size);
	}
	if (id_grp == NULL) {
		*err_detail = (entry_type == STMF_ID_TYPE_HOST)?
		    STMF_IOCERR_INVALID_HG:STMF_IOCERR_INVALID_TG;
		return (ENODEV); /* not found */
	}

	/* Check whether this member already bound to a group */
	if (id_grp_tmp) {
		if (id_grp_tmp != id_grp) {
			*err_detail = (entry_type == STMF_ID_TYPE_HOST)?
			    STMF_IOCERR_HG_ENTRY_EXISTS:
			    STMF_IOCERR_TG_ENTRY_EXISTS;
			return (EEXIST); /* already added into another grp */
		}
		else
			return (0);
	}

	/* verify target is offline */
	if (entry_type == STMF_ID_TYPE_TARGET) {
		ilport = stmf_targetident_to_ilport(entry_ident, entry_size);
		if (ilport && ilport->ilport_state != STMF_STATE_OFFLINE) {
			*err_detail = STMF_IOCERR_TG_NEED_TG_OFFLINE;
			return (EBUSY);
		}
	}

	id_member = stmf_alloc_id(entry_size, entry_type,
	    entry_ident, 0);
	stmf_append_id((stmf_id_list_t *)id_grp->id_impl_specific, id_member);

	if (entry_type == STMF_ID_TYPE_TARGET) {
		ilport = stmf_targetident_to_ilport(entry_ident, entry_size);
		if (ilport)
			ilport->ilport_tg = (void *)id_grp;
		return (0);
	}
	/* For host group member, update the session if needed */
	if (!stmf_state.stmf_service_running)
		return (0);
	/* Need to consider all target group + this host group */
	id_alltgt = stmf_lookup_id(&stmf_state.stmf_tg_list,
	    1, &grpname_forall);
	vemap_alltgt = stmf_get_ve_map_per_ids(id_alltgt, id_grp);

	/* check whether there are sessions may be affected */
	for (ilport = stmf_state.stmf_ilportlist; ilport;
	    ilport = ilport->ilport_next) {
		if (ilport->ilport_state != STMF_STATE_ONLINE)
			continue;
		iss = stmf_lookup_session_for_hostident(ilport,
		    entry_ident, entry_size);
		if (iss) {
			stmf_id_data_t *tgid;
			iss->iss_hg = (void *)id_grp;
			tgid = ilport->ilport_tg;
			if (tgid) {
				vemap = stmf_get_ve_map_per_ids(tgid, id_grp);
				if (vemap)
					stmf_add_lus_to_session_per_vemap(
					    ilport, iss, vemap);
			}
			if (vemap_alltgt)
				stmf_add_lus_to_session_per_vemap(ilport,
				    iss, vemap_alltgt);
		}
	}

	return (0);
}

int
stmf_remove_group_member(uint8_t *grpname, uint16_t grpname_size,
		uint8_t *entry_ident, uint16_t entry_size,
		stmf_id_type_t entry_type, uint32_t *err_detail)
{
	stmf_id_data_t	*id_grp, *id_alltgt;
	stmf_id_data_t	*id_member;
	stmf_lun_map_t *vemap,  *vemap_alltgt;
	uint8_t grpname_forall = '*';
	stmf_i_local_port_t *ilport;
	stmf_i_scsi_session_t *iss;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));
	ASSERT(grpname[0] != '*');

	if (entry_type == STMF_ID_TYPE_HOST) {
		id_grp = stmf_lookup_id(&stmf_state.stmf_hg_list,
		    grpname_size, grpname);
	} else {
		id_grp = stmf_lookup_id(&stmf_state.stmf_tg_list,
		    grpname_size, grpname);
	}
	if (id_grp == NULL) {
		*err_detail = (entry_type == STMF_ID_TYPE_HOST)?
		    STMF_IOCERR_INVALID_HG:STMF_IOCERR_INVALID_TG;
		return (ENODEV); /* no such group */
	}
	id_member = stmf_lookup_id((stmf_id_list_t *)id_grp->id_impl_specific,
	    entry_size, entry_ident);
	if (!id_member) {
		*err_detail = (entry_type == STMF_ID_TYPE_HOST)?
		    STMF_IOCERR_INVALID_HG_ENTRY:STMF_IOCERR_INVALID_TG_ENTRY;
		return (ENODEV); /* no such member */
	}
	/* verify target is offline */
	if (entry_type == STMF_ID_TYPE_TARGET) {
		ilport = stmf_targetident_to_ilport(entry_ident, entry_size);
		if (ilport && ilport->ilport_state != STMF_STATE_OFFLINE) {
			*err_detail = STMF_IOCERR_TG_NEED_TG_OFFLINE;
			return (EBUSY);
		}
	}

	stmf_remove_id((stmf_id_list_t *)id_grp->id_impl_specific, id_member);
	stmf_free_id(id_member);

	if (entry_type == STMF_ID_TYPE_TARGET) {
		ilport = stmf_targetident_to_ilport(entry_ident, entry_size);
		if (ilport)
			ilport->ilport_tg = NULL;
		return (0);
	}
	/* For host group member, update the session */
	if (!stmf_state.stmf_service_running)
		return (0);

	/* Need to consider all target group + this host group */
	id_alltgt = stmf_lookup_id(&stmf_state.stmf_tg_list,
	    1, &grpname_forall);
	vemap_alltgt = stmf_get_ve_map_per_ids(id_alltgt, id_grp);

	/* check if there are session related, if so, update it */
	for (ilport = stmf_state.stmf_ilportlist; ilport;
	    ilport = ilport->ilport_next) {
		if (ilport->ilport_state != STMF_STATE_ONLINE)
			continue;
		iss = stmf_lookup_session_for_hostident(ilport,
		    entry_ident, entry_size);
		if (iss) {
			stmf_id_data_t *tgid;
			iss->iss_hg = NULL;
			tgid = ilport->ilport_tg;
			if (tgid) {
				vemap = stmf_get_ve_map_per_ids(tgid, id_grp);
				if (vemap)
					stmf_remove_lus_from_session_per_vemap(
					    ilport, iss, vemap);
			}
			if (vemap_alltgt)
				stmf_remove_lus_from_session_per_vemap(ilport,
				    iss, vemap_alltgt);
		}
	}

	return (0);
}

/* Assert stmf_lock is already held */
stmf_i_local_port_t *
stmf_targetident_to_ilport(uint8_t *target_ident, uint16_t ident_size)
{
	stmf_i_local_port_t *ilport;
	uint8_t *id;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	for (ilport = stmf_state.stmf_ilportlist; ilport;
	    ilport = ilport->ilport_next) {
		id = (uint8_t *)ilport->ilport_lport->lport_id;
		if ((id[3] == ident_size) &&
		    bcmp(id + 4, target_ident, ident_size) == 0) {
			return (ilport);
		}
	}
	return (NULL);
}

stmf_i_scsi_session_t *
stmf_lookup_session_for_hostident(stmf_i_local_port_t *ilport,
		uint8_t *host_ident, uint16_t ident_size)
{
	stmf_i_scsi_session_t *iss;
	uint8_t *id;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	for (iss = ilport->ilport_ss_list; iss; iss = iss->iss_next) {
		id = (uint8_t *)iss->iss_ss->ss_rport_id;
		if ((id[3] == ident_size) &&
		    bcmp(id + 4, host_ident, ident_size) == 0) {
			return (iss);
		}
	}
	return (NULL);
}

stmf_i_lu_t *
stmf_luident_to_ilu(uint8_t *lu_ident)
{
	stmf_i_lu_t *ilu;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	for (ilu = stmf_state.stmf_ilulist; ilu; ilu = ilu->ilu_next) {
		if (bcmp(&ilu->ilu_lu->lu_id->ident[0], lu_ident, 16) == 0)
			return (ilu);
	}

	return (NULL);
}

/*
 * Assert stmf_lock is already held,
 * Just get the view map for the specific target group and host group
 * tgid and hgid can not be NULL
 */
stmf_lun_map_t *
stmf_get_ve_map_per_ids(stmf_id_data_t *tgid, stmf_id_data_t *hgid)
{
	int found = 0;
	stmf_ver_tg_t *vertg;
	stmf_ver_hg_t *verhg;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	for (vertg = stmf_state.stmf_ver_tg_head;
	    vertg; vertg = vertg->vert_next) {
		if (vertg->vert_tg_ref == tgid) {
			found = 1;
			break;
		}
	}
	if (!found)
		return (NULL);

	for (verhg = vertg->vert_verh_list; verhg; verhg = verhg->verh_next) {
		if (verhg->verh_hg_ref == hgid) {
			return (&verhg->verh_ve_map);
		}
	}
	return (NULL);
}

stmf_status_t
stmf_validate_lun_view_entry(stmf_id_data_t *hg, stmf_id_data_t *tg,
    uint8_t *lun, uint32_t *err_detail)
{
	char			*phg, *ptg;
	stmf_lun_map_t		*ve_map = NULL;
	stmf_ver_hg_t		*verhg = NULL;
	stmf_ver_tg_t		*vertg = NULL;
	uint16_t		lun_num;
	stmf_status_t		ret = STMF_SUCCESS;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	ve_map = stmf_duplicate_ve_map(0);
	for (vertg = stmf_state.stmf_ver_tg_head; vertg != NULL;
	    vertg = vertg->vert_next) {
		ptg = (char *)vertg->vert_tg_ref->id_data;
		if ((ptg[0] != '*') && (tg->id_data[0] != '*') &&
		    (vertg->vert_tg_ref != tg)) {
			continue;
		}
		for (verhg = vertg->vert_verh_list; verhg != NULL;
		    verhg = verhg->verh_next) {
			phg = (char *)verhg->verh_hg_ref->id_data;
			if ((phg[0] != '*') && (hg->id_data[0] != '*') &&
			    (verhg->verh_hg_ref != hg)) {
				continue;
			}
			(void) stmf_merge_ve_map(&verhg->verh_ve_map, ve_map,
			    &ve_map, 0);
		}
	}

	ret = STMF_SUCCESS;
	/* Return an available lun number */
	if (lun[2] == 0xFF) {
		/* Pick a LUN number */
		lun_num = stmf_get_next_free_lun(ve_map, lun);
		if (lun_num > 0x3FFF)
			ret = STMF_NOT_SUPPORTED;
	} else {
		lun_num = (uint16_t)lun[1] | (((uint16_t)(lun[0] & 0x3F)) << 8);
		if (stmf_get_ent_from_map(ve_map, lun_num) != NULL) {
			*err_detail = STMF_IOCERR_LU_NUMBER_IN_USE;
			ret = STMF_LUN_TAKEN;
		}
	}
	stmf_destroy_ve_map(ve_map);

	return (ret);
}

int
stmf_validate_lun_ve(uint8_t *hgname, uint16_t hgname_size,
		uint8_t *tgname, uint16_t tgname_size,
		uint8_t *luNbr, uint32_t *err_detail)
{
	stmf_id_data_t		*hg;
	stmf_id_data_t		*tg;
	stmf_status_t		ret;

	ASSERT(mutex_owned(&stmf_state.stmf_lock));

	hg = stmf_lookup_id(&stmf_state.stmf_hg_list, hgname_size,
	    (uint8_t *)hgname);
	if (!hg) {
		*err_detail = STMF_IOCERR_INVALID_HG;
		return (ENOENT); /* could not find group */
	}
	tg = stmf_lookup_id(&stmf_state.stmf_tg_list, tgname_size,
	    (uint8_t *)tgname);
	if (!tg) {
		*err_detail = STMF_IOCERR_INVALID_TG;
		return (ENOENT); /* could not find group */
	}
	ret = stmf_validate_lun_view_entry(hg, tg, luNbr, err_detail);

	if (ret == STMF_LUN_TAKEN) {
		return (EEXIST);
	} else if (ret == STMF_NOT_SUPPORTED) {
		return (E2BIG);
	} else if (ret != STMF_SUCCESS) {
		return (EINVAL);
	}
	return (0);
}
