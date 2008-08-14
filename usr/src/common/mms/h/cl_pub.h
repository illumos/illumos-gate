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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _CL_PUB_
#define	_CL_PUB_
#ifndef _LH_DEFS_
#include "lh_defs.h"
#endif

#ifndef _LM_STRUCTS_
#include "lm_structs.h"
#endif

#ifndef _DB_STRUCTS_
#include "db_structs.h"
#endif

#ifndef FILE
#include <stdio.h>
#endif


BOOLEAN cl_abbreviation(char *cp_full, char *cp_abbrev,
			char *cp_map_full, char *cp_map_abbrev);
STATUS		cl_acs_valid(ACS acs_id);
STATUS		cl_available(DRIVEID *drive_ids, int num_of_drives,
			VOLID *vol_ids, int num_of_vols);
STATUS		cl_cap_release(CAPID cap_id);
STATUS		cl_caps_in_lsm(int panel_count,
			PANEL_TYPE panel_types[MAX_PANEL + 1],
			BOOLEAN caps_in_lsm[MAX_CAP + 1]);
STATUS		cl_cap_valid(CAPID cap_id, COMMAND command);
STATUS		cl_cel_next(LH_ADDR *first, LH_ADDR *last, LH_ADDR *cell_id);
STATUS		cl_cel_valid(CELLID cell_id);
int		cl_chk_input(long tmo);
char		*cl_command(COMMAND command);
BOOLEAN	cl_debug_trace(void);

STATUS		cl_drv_list(VOLID vol_id, int *drive_count,
		    QU_DRV_STATUS **drive_list);
STATUS		cl_drv_valid(DRIVEID drive_id);
void		cl_el_log_event(const char *cp_msg);
void		cl_el_log_register(void);
void		cl_el_log_trace(const char *cp_msg);
void		cl_el_trace(const char *cp_msg);
STATUS		cl_expand_string(char *cp_dest, char *cp_source,
			unsigned int iu_length);
STATUS		cl_file_line(FILE *fp, char *buff, char **ret_cptr);
char		*cl_get_sockname(char *sock_name);
char		*cl_identifier(TYPE type, IDENTIFIER *id);
char		*cl_resource_event(RESOURCE_EVENT resource_event);
void		cl_inform(STATUS message_status, TYPE type,
			IDENTIFIER *identifier, int error);
char		*cl_lh_error(LH_ERR_TYPE lh_err);
char		*cl_lh_identifier(LH_ADDR_TYPE type, void *lh_addr_id);
int		cl_lh_timeout(LH_REQ_TYPE request);
STATUS		cl_lh_tostatus(LH_REQ_TYPE request, LH_ERR_TYPE error);
char		*cl_lh_type(LH_ADDR_TYPE lh_type);
STATUS		cl_loc_val(LOCKID *lock_id, RESPONSE_STATUS *rstatus);
void 	cl_log_lh_error(char *caller, LH_ERR_TYPE lh_err);
void		cl_log_trace(const char *cp_msg, ...);
void		cl_log_trace_register(void (*funcptr)(const char *));
STATUS		cl_lsm_list(LSMID lsm_id, LSM **lsm_list);
STATUS		cl_lsm_read(QUERY_TYPE query_type, LSM_RECORD *lsm_record);
STATUS		cl_lsm_valid(LSMID lsm_id);
STATUS		cl_mm_info(QU_MMI_RESPONSE *mmi_ptr);
char		*cl_mk_path(char *sub_dir_path, char *filename,
			char *new_path);
STATUS		cl_mt_vt(VOLUME_RECORD *volume_record);
STATUS		cl_proc_init(TYPE mod_type, int argc, char **argv);
STATUS		cl_pnl_valid(PANELID panel_id);
STATUS		cl_prt_valid(PORTID port_id);
STATUS		cl_range_read(VOLRANGE vol_range, int *count,
			VOLID **vol_list, REQUEST_HEADER *p_reqhdr);
STATUS		cl_range_valid(VOLRANGE vol_range);
STATUS		cl_removed(LOCKID lock_id, DRIVEID *drive_ids,
			int num_of_drives, VOLID *vol_ids, int num_of_vols);
STATUS		cl_req_valid(MESSAGE_ID message_id);
STATUS		cl_rp_init(TYPE mod_type, int argc, char **argv,
			void *buf, int *byte_cnt);
STATUS		cl_scratch_read(POOLID pool_id, int all, int *count,
			QU_SCR_STATUS **vol_list);
int		cl_select_input(int nfds, int *fds, long tmo);
void		cl_set_hostid(HOSTID *sp_hostid, const char *cp_source);
TYPE		cl_set_type(STATUS status);
const char *cl_sig_desc(const int sig);
void		cl_sig_hdlr(int sig);
void	cl_sig_trap(SIGFUNCP sig_hdlr, int sig_count, ...);
STATUS		cl_sql_commit(char *caller);
STATUS		cl_sql_rollback(char *caller);
char		*cl_state(STATE state);
char		*cl_status(STATUS status);
char		*cl_str_to_buf(const char *cp_in, char *cp_out);
STATUS		cl_sub_valid(SUBPANELID subpanel_id);
void		cl_trace(char *rtn_name, int parm_cnt, ...);
void		cl_trace_register(void (*funcptr)(const char *));
char		*cl_type(TYPE type);
char		*cl_vol_type(VOLUME_TYPE type);
STATUS		cl_vol_valid(VOLID volume_id, VOLUME_TYPE volume_type);




STATUS		cl_acs_destroy(ACS acs);
STATUS		cl_acs_read(QUERY_TYPE query_type, ACS_RECORD *acs_record);
STATUS		cl_acs_update(ACS acs_id, FIELD field_id,
			STATE curr_value, STATE new_value);
STATUS		cl_acs_write(ACS_RECORD *acs_record, WRITE_MODE write_mode);
STATUS		cl_cap_destroy(CAPID cap_id);
STATUS		cl_cap_exists(CAPID cap_id, BOOLEAN explicit);
STATUS		cl_cap_read(QUERY_TYPE query_type, CAP_RECORD *cap_record);
STATUS		cl_cap_reserve(STATUS activity, CAP_RECORD *cap_record);
STATUS		cl_cap_update(CAPID cap_id, FIELD field_id,
			int cur_value, int new_value);
STATUS		cl_cap_write(CAP_RECORD *cap_record, WRITE_MODE write_mode);
STATUS		cl_cel_destroy(CELLID cell_id);
STATUS		cl_cel_read(QUERY_TYPE query_type, CELL_RECORD *cell_record);
STATUS		cl_cel_select(LSMID lsm_id, SELECT_OPTION select_option,
			CELLID *out_cell_id);
STATUS		cl_cel_update(CELLID cell_id, FIELD field_id,
			int curr_value, int new_value);
STATUS		cl_cel_write(CELL_RECORD *cell_record, WRITE_MODE write_mode);
STATUS		cl_chk_offline(TYPE type, IDENTIFIER *identifier,
			BOOLEAN initial);
STATUS		cl_cln_read(QUERY_TYPE query_type,
			VOLUME_RECORD *volume_record);
STATUS		cl_csi_read(QUERY_TYPE query_type, CSI_RECORD *csi_record);
STATUS		cl_csi_write(CSI_RECORD *csi_record);
STATUS		cl_db_acs(ACS *p_last_acs);
STATUS		cl_db_cap(LSMID lsm_id, CAP *p_last_cap);
STATUS		cl_db_connect(void);
STATUS		cl_db_disconnect(void);
STATUS		cl_db_drv(PANELID panel_id, DRIVE *p_last_drv);
STATUS		cl_db_lsm(ACS acs_id, LSM *p_last_lsm);
STATUS		cl_db_pnl(LSMID lsm_id, PANEL *p_last_pnl);
STATUS		cl_drv_destroy(DRIVEID drive_id);
STATUS		cl_drv_read(QUERY_TYPE query_type, DRIVE_RECORD *drive_record);
STATUS		cl_drv_update(DRIVEID drive_id, FIELD field_id,
			int cur_value, int new_value, LOCKID lock_id);
STATUS		cl_drv_write(DRIVE_RECORD *drive_record,
			WRITE_MODE write_mode);
STATUS		cl_loc_read(QUERY_TYPE query_type,
			LOCKID_RECORD *lockid_record);
STATUS		cl_lsm_destroy(LSMID lsm_id);
STATUS		cl_lsm_update(LSMID lsm_id, FIELD field_id,
			int cur_value, int new_value);
STATUS		cl_lsm_write(LSM_RECORD *lsm_record, WRITE_MODE write_mode);
STATUS		cl_msc_list(POOLID pool_id, int *drive_count,
			QU_DRV_STATUS **drive_list);
STATUS		cl_pool_count(POOLID pool_id, int *count);
STATUS		cl_pool_destroy(POOLID pool_id);
STATUS		cl_pool_read(QUERY_TYPE query_type, POOL_RECORD *pool_record);
STATUS		cl_pool_write(POOL_RECORD *pool_record, WRITE_MODE write_mode);
STATUS		cl_prt_destroy(PORTID port_id);
STATUS		cl_prt_read(QUERY_TYPE query_type, PORT_RECORD *port_record);
STATUS		cl_prt_update(PORTID port_id, FIELD field_id,
			int curr_value, int new_value);
STATUS		cl_prt_write(PORT_RECORD *port_record, WRITE_MODE write_mode);
STATUS		cl_vac_destroy(VAC_RECORD *p_vac_record);
STATUS		cl_vac_read(QUERY_TYPE query_type, VAC_RECORD *p_vac_record);
STATUS		cl_vac_write(VAC_RECORD *p_vac_record, WRITE_MODE write_mode);
STATUS		cl_vol_destroy(VOLID vol_id);
STATUS		cl_vol_read(QUERY_TYPE query_type,
			VOLUME_RECORD *volume_record);
STATUS		cl_vol_update(VOLID vol_id, FIELD field_id,
			int cur_value, int new_value, LOCKID lock_id,
			REQUEST_HEADER *p_req_hdr);
STATUS		cl_vol_write(VOLUME_RECORD *volume_record,
			WRITE_MODE write_mode);



#endif /* _CL_PUB_ */
