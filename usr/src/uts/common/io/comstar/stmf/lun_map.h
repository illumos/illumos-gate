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
 */
#ifndef	_LUN_MAP_H
#define	_LUN_MAP_H

#include <sys/stmf_defines.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct stmf_lun_map {
	uint32_t	lm_nluns;
	uint32_t	lm_nentries;
	void		**lm_plus; /* this can be lun or view entry */
} stmf_lun_map_t;

struct stmf_itl_data;

typedef struct stmf_lun_map_ent {
	struct stmf_lu		*ent_lu;
	struct stmf_itl_data	*ent_itl_datap;
} stmf_lun_map_ent_t;

void stmf_view_init();
void stmf_view_clear_config();
stmf_status_t stmf_session_create_lun_map(stmf_i_local_port_t *ilport,
		stmf_i_scsi_session_t *iss);
stmf_status_t stmf_session_destroy_lun_map(stmf_i_local_port_t *ilport,
		stmf_i_scsi_session_t *iss);
stmf_xfer_data_t *stmf_session_prepare_report_lun_data(stmf_lun_map_t *sm);
void stmf_add_lu_to_active_sessions(stmf_lu_t *lu);
void stmf_session_lu_unmapall(stmf_lu_t *lu);
void *stmf_get_ent_from_map(stmf_lun_map_t *sm, uint16_t lun_num);


/*
 * Common struct used to maintain an Identifer's data. That Identifier
 * can be a Host group, Target group or LU GUID data. Note that a LU is
 * different from LU GUID data because either can be there without
 * its counterpart being present in the system.
 * id_impl_specific pointer to:
 * case LUID, a list of stmf_view_entry
 * case initiator group, a list of initiators
 * case target group, a list of targets
 * id_pt_to_object pointer to stmf_i_lu_t instance for LU.
 */
typedef struct stmf_id_data {
	struct stmf_id_data		*id_next;
	struct stmf_id_data		*id_prev;
	uint32_t			id_refcnt;
	uint16_t			id_type;
	uint16_t			id_data_size;
	uint8_t				*id_data;
	uint32_t			id_total_alloc_size;
	uint32_t			id_rsvd;
	void				*id_pt_to_object;
	void				*id_impl_specific;
} stmf_id_data_t;

typedef enum {
	STMF_ID_TYPE_HOST,
	STMF_ID_TYPE_TARGET,
	STMF_ID_TYPE_LU_GUID,
	STMF_ID_TYPE_HOST_GROUP,
	STMF_ID_TYPE_TARGET_GROUP
} stmf_id_type_t;

typedef struct stmf_id_list {
	stmf_id_data_t		*idl_head;
	stmf_id_data_t		*idl_tail;
	uint32_t		id_count;
} stmf_id_list_t;

typedef struct stmf_view_entry {
	struct stmf_view_entry	*ve_next;
	struct stmf_view_entry	*ve_prev;
	uint32_t		ve_id;
	stmf_id_data_t		*ve_hg;
	stmf_id_data_t		*ve_tg;
	stmf_id_data_t		*ve_luid;
	uint8_t			ve_lun[8];
} stmf_view_entry_t;

/*
 * Following structs are used as an alternate representation of view entries
 * in a LU ID.
 * ver_tg_root--->ver_tg_t    +-> ver_tg_t ....
 *                   |        |
 *                  vert_next-+
 *                   |
 *                   vert_verh_list --> ver_hg_t  +-> ver_hg_t ....
 *                                        |       |
 *                                      verh_next-+
 *                                        |
 *                                      verh_ve_map (view entry map for this
 *                                             target group + host group )
 */

typedef struct ver_hg {
	struct ver_hg		*verh_next;
	stmf_id_data_t		*verh_hg_ref;	/* ref. to the host group */
	stmf_lun_map_t		verh_ve_map;
} stmf_ver_hg_t;

typedef struct ver_tg {
	struct ver_tg		*vert_next;
	stmf_id_data_t		*vert_tg_ref;	/* ref to target group */
	stmf_ver_hg_t		*vert_verh_list;
} stmf_ver_tg_t;

/*
 * flag which define how the merging of maps is to be done.
 */
typedef enum {
	MERGE_FLAG_NO_DUPLICATE		= 0x01, /* fail upon duplicate */
	MERGE_FLAG_RETURN_NEW_MAP	= 0x02, /* Does not modify dst */
	MERGE_FLAG_NONE			= 0
} stmf_merge_flags_t;

int stmf_add_group_member(uint8_t *grpname, uint16_t grpname_size,
		uint8_t	*entry_ident, uint16_t entry_size,
		stmf_id_type_t entry_type, uint32_t *err_detail);
int stmf_remove_group_member(uint8_t *grpname, uint16_t grpname_size,
		uint8_t *entry_ident, uint16_t entry_size,
		stmf_id_type_t entry_type, uint32_t *err_detail);
int stmf_remove_group(uint8_t *grpname, uint16_t grpname_size,
		stmf_id_type_t group_type, uint32_t *err_detail);
int stmf_add_group(uint8_t *grpname, uint16_t grpname_size,
		stmf_id_type_t group_type, uint32_t *err_detail);
int stmf_add_ve(uint8_t *hgname, uint16_t hgname_size, uint8_t *tgname,
		uint16_t tgname_size, uint8_t *lu_guid, uint32_t *ve_id,
		uint8_t *luNbr, uint32_t *err_detail);
int stmf_validate_lun_ve(uint8_t *hgname, uint16_t hgname_size, uint8_t *tgname,
		uint16_t tgname_size, uint8_t *luNbr, uint32_t *err_detail);
int stmf_remove_ve_by_id(uint8_t *guid, uint32_t veid, uint32_t *err_detail);
stmf_id_data_t *stmf_lookup_id(stmf_id_list_t *idlist, uint16_t id_size,
		uint8_t *data);
stmf_id_data_t *stmf_lookup_group_for_target(uint8_t *ident,
		uint16_t ident_size);

#ifdef	__cplusplus
}
#endif

#endif /* _LUN_MAP_H */
