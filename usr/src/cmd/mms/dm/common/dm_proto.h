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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__DM_PROTO_H
#define	__DM_PROTO_H


#ifdef	__cplusplus
extern "C" {
#endif

char **dm_bld_dir_tab(void);
char *dm_bld_config_cmd(char *task);
char *dm_bld_task(char *cmd);
char *dm_char_to_hex(uchar_t *ibuf, int ilen, char *obuf, int olen);
char *dm_get_attr_value(mms_par_node_t *root, char *obj, char *attr);
char *dm_get_capabilities(char *tokens);
char *dm_get_task(mms_par_node_t *root);
char *dm_get_user(pid_t pid);
char *dm_malloc(size_t size, char *filename, int line);
char *dm_msg_add(int class, int code, char *fmt, ...);
char *dm_msg_add_aux(int tail, int class, int code, char *fmt, va_list args);
char *dm_msg_add_head(int class, int code, char *fmt, ...);
char *dm_msg_prepend(char *fmt, ...);
char *dm_msg_text(void);
char *dm_show_virt_cart_path(void);
char *dm_strdup(char *str, char *filename, int line);
char *dm_timestamp(void);
dm_command_t *dm_get_cmd_by_task(char *task);
dm_command_t *dm_send_cmd(char *cmdbuf, int (*cmd_func) (dm_command_t *),
    char *task);
dm_msg_hdr_t *dm_msg_get_hdr(void);
drv_skaa_t *dm_skaa_lookup(uchar_t senkey, uchar_t asc, uchar_t ascq);
int dm_accept_cmd_aux(dm_command_t *cmd);
int dm_activate_cmd(dm_command_t *cmd);
int dm_activate_disable(dm_command_t *cmd);
int dm_activate_enable(dm_command_t *cmd);
int dm_activate_release(dm_command_t *cmd);
int dm_activate_reserve(dm_command_t *cmd);
int dm_ask_freserve(void);
int dm_ask_preempt(void);
int dm_ask_reply(char *reply);
int dm_ask_write_lbl(char *from, char *to, char *pcl);
int dm_attach_cmd(dm_command_t *cmd);
int dm_bind_raw_dev(int oflag);
int dm_bind_target(void);
int dm_bind_target_base(void);
int dm_cap_clause(char **pconf);
int dm_cap_clause_aux(char *fmt, char **pconf, drv_shape_density_t *sd);
int dm_chk_dev_auth(char *user);
int dm_chk_eof(void);
int dm_chk_uscsi_error(int ret, struct uscsi_cmd *us, int err);
int dm_close();
int dm_cmd_response(dm_command_t *cmd);
int dm_create_eof1(void);
int dm_create_eof2(void);
int dm_create_hdr1(void);
int dm_create_hdr2(void);
int dm_create_trailor_lbls(void);
int dm_create_vol1(void);
int dm_detach_cmd(dm_command_t *cmd);
int dm_dmpm_private_cmd(dm_command_t *cmd);
int dm_drv_assigned(void);
int dm_duplicate_bit(drv_shape_density_t *sd);
int dm_duplicate_shape(drv_shape_density_t *sd, char *type);
int dm_force_release(void);
int dm_get_app_options(mms_par_node_t *);
int dm_get_bof_pos(void);
int dm_get_capacity(mms_par_node_t *);
int dm_get_default_lib_path(void);
int dm_get_dev_lib_name(void);
int dm_get_eof_pos(void);
int dm_get_hostpath(void);
int dm_get_log_sense_parm(uchar_t *page, int code, uint64_t *val);
int dm_get_mount_options(dm_command_t *cmd);
int dm_get_part_rwmode(mms_par_node_t *);
int dm_get_system_options(void);
int dm_get_target_base(void);
int dm_get_target_by_serial_num(void);
int dm_get_target_pathname(void);
int dm_goto_eof(void);
int dm_have_mms_rsv(void);
int dm_identify_cmd(dm_command_t *cmd);
int dm_init(int argc, char **argv);
int dm_init_session(int retries);
int dm_ioctl(int cmd, void *arg);
int dm_ioctl_bsb(int count);
int dm_ioctl_bsf(int count);
int dm_ioctl_clrerr(drm_reply_t *rep);
int dm_ioctl_fsb(int count);
int dm_ioctl_fsf(int count);
int dm_ioctl_get_capacity(drm_reply_t *rep);
int dm_ioctl_get_density(drm_reply_t *rep);
int dm_ioctl_getpos(drm_reply_t *rep);
int dm_ioctl_locate(drm_request_t *req);
int dm_ioctl_mtget(drm_request_t *req, drm_reply_t *rep);
int dm_ioctl_mtgetpos(drm_reply_t *rep);
int dm_ioctl_mtiocltop(drm_request_t *req, drm_reply_t *rep);
int dm_ioctl_mtrestpos(drm_request_t *req);
int dm_ioctl_rewind(void);
int dm_ioctl_seek(int count);
int dm_ioctl_set_blksize(uint64_t blksize);
int dm_ioctl_set_density(void);
int dm_ioctl_upt_capacity(void);
int dm_ioctl_wtm(int count);
int dm_load_cmd(dm_command_t *cmd);
int dm_load_default_lib(void);
int dm_load_devlib(void);
int dm_msg_class(void);
int dm_msg_code(void);
int dm_mtiocltop(drv_req_t *op);
int dm_open(drm_request_t *req, drm_reply_t *rep);
int dm_open_dm_device(void);
int dm_open_labeled(int *newfile);
int dm_open_nonlabeled(int *newfile);
int dm_open_pos(void);
int dm_pos_fseq(void);
int dm_preempt_rsv(void);
int dm_probe_dir(char *dirname);
int dm_read(drm_reply_t *rep);
int dm_read_cfg(char *cfgname);
int dm_read_err(drm_request_t *req, drm_reply_t *rep);
int dm_read_tm(drm_request_t *req);
int dm_reader(char **cmdbuf);
int dm_rebind_target(void);
int dm_release_target(void);
int dm_reserve_target(void);
int dm_reserve_target_prsv(void);
int dm_reserve_target_rsv(void);
int dm_responded_with(dm_command_t *cmd, char *keyword);
int dm_rewind_file(void);
int dm_rw_shape(char *shape);
int dm_send_capacity(mms_capacity_t *cap);
int dm_send_cartridge_media_error(void);
int dm_send_clean_request(void);
int dm_send_config(void);
int dm_send_drive_broken(void);
int dm_send_eof_pos(void);
int dm_send_error(void);
int dm_send_loaded(void);
int dm_send_ready(int msgid, ...);
int dm_send_ready_aux(char *spec, int msgid, va_list args);
int dm_send_ready_broken(int msgid, ...);
int dm_send_ready_disconnected(int msgid, ...);
int dm_send_ready_not(int msgid, ...);
int dm_send_statistics(void);
int dm_send_write_protect(int wp);
int dm_set_file_blksize(int blksize);
int dm_set_label_blksize(void);
int dm_setup_incoming_cmd(dm_command_t *cmd);
int dm_show_dca_info(mms_par_node_t **);
int dm_show_drive_dmname(char **dmname);
int dm_show_eof_pos(void);
int dm_show_mount_point(mms_par_node_t **typeroot);
int dm_show_system_options(mms_par_node_t **root);
int dm_silent(void);
int dm_stat_targ_base(void);
int dm_terminate_file(void);
int dm_trace(mms_trace_sev_t severity, char *file, int line, char *fmt, ...);
int dm_unload_cmd(dm_command_t *cmd);
int dm_update_bitformat(void);
int dm_update_capacity(void);
int dm_update_drivetype(void);
int dm_update_write_protect(void);
int dm_uscsi(struct uscsi_cmd *us);
int dm_validate_fname(void);
int dm_validate_xdate(void);
int dm_verify_serial_num(void);
int dm_verify_target_dev(char *devname);
int dm_verify_trailor_label(char *buf);
int dm_write(drm_reply_t *rep);
int dm_write_0(drm_request_t *req, drm_reply_t *rep);
int dm_write_err(drm_request_t *req, drm_reply_t *rep);
int dm_writer(char *cmdbuf);
int dm_writer_accept(char *cmdbuf);
int dm_writer_aux(char *cmdbuf, int accept);
int drv_bind_raw_dev(int oflags);
int drv_blk_limit(mms_blk_limit_t *lmt);
int drv_bsb(uint64_t count, int cross);
int drv_bsf(uint64_t count);
int drv_clrerr(void);
int drv_eom(void);
int drv_fsb(uint64_t count, int cross);
int drv_fsf(uint64_t count);
int drv_get_blksize(uint64_t *size);
int drv_get_capacity(mms_capacity_t *cap);
int drv_get_density(int *den, int *comp);
int drv_get_drivetype(void);
int drv_get_mount_points(void);
int drv_get_pos(tapepos_t *pos);
int drv_get_serial_num(char *ser);
int drv_get_statistics(void);
int drv_get_write_protect(int *wp);
int drv_inquiry(void);
int drv_load(void);
int drv_locate(tapepos_t *pos);
int drv_log_sense(uchar_t *buf, int len, int page_control, int page_code);
int drv_mode_select(int pf, int len);
int drv_mode_sense(int page, int pc, int len);
int drv_prsv_clear(void);
int drv_prsv_preempt(char *curkey);
int drv_prsv_read_keys(char *buf, int bufsize);
int drv_prsv_read_rsv(char *buf, int bufsize);
int drv_prsv_register(void);
int drv_prsv_release(void);
int drv_prsv_reserve(void);
int drv_read(char *buf, int len);
int drv_read_tm(void);
int drv_read_attribute(uchar_t *buf, int32_t len, int servact, int32_t attr);
int drv_rebind_target(void);
int drv_release(void);
int drv_req_sense(int len);
int drv_reserve(void);
int drv_rewind(void);
int drv_seek(uint64_t count);
int drv_set_blksize(uint64_t size);
int drv_set_compression(int comp);
int drv_set_density(int den);
int drv_tell(uint64_t *count);
int drv_tur(void);
int drv_unload(void);
int drv_write(char *buf, int len);
int drv_wtm(uint64_t count);
int main(int argc, char **argv);
int64_t drv_get_avail_capacity(void);
minor_t dm_get_targ(minor_t minor);
minor_t dm_hdl_minor(void);
mms_sym_t *dm_sym_in(mms_sym_t *arr, char *token);
void *dm_worker(void *arg);
void char_to_int32(signed char *start, int len, int32_t *val);
void char_to_int64(signed char *start, int len, int64_t *val);
void char_to_uint32(uchar_t *start, int len, uint32_t *val);
void char_to_uint64(uchar_t *start, int len, uint64_t *val);
void dm_accept_cmds(void);
void dm_clear_dev(void);
void dm_destroy_cmd(dm_command_t *cmd);
void dm_destroy_dca(void);
void dm_destroy_mnt(void);
void dm_disallowed(void);
void dm_dispatch_cmds(void);
void dm_err_trace(void);
void dm_exit(int code, char *file, int line);
void dm_exit_cmd(dm_command_t *cmd);
void dm_free(void *ptr, char *filename, int line);
void dm_get_mt_error(int err);
void dm_get_mtstat(int save);
void dm_get_request(void);
void dm_init_dev_lib(void *hdl, int init);
void dm_init_log(void);
void dm_init_sense_buf(void);
void dm_init_wka(void);
void dm_mk_prsv_key(void);
void dm_mms_to_db_time(char *db);
void dm_msg_create_hdr(void);
void dm_msg_destroy(void);
void dm_msg_remove(dm_msg_t *msg);
void dm_parse_err(mms_par_node_t *root, mms_list_t *err_list);
void dm_proc_request(void);
void dm_read_input(void);
void dm_rem_old_handle(void);
void dm_reset_cmd(dm_command_t *cmd);
void dm_resp_error(char *task, int msgid, ...);
void dm_resp_success(char *task, char *text);
void dm_resp_unacceptable(int msgid, ...);
void dm_restart_session(void);
void dm_scsi_error(int err, int status, int cdblen, uchar_t *cdb, int senlen,
    uchar_t *sense);
void dm_send_message(char *who, char *severity, int msgid, ...);
void dm_send_request(char **reply, int msgid, ...);
void dm_setup_sig_handler(void);
void dm_sighup(void);
void dm_sigint(void);
void dm_signal(int sig, void (*handler) ());
void dm_sigterm(void);
void dm_sigusr1(void);
void dm_sigusr2(void);
void dm_to_upper(char *vp);
void dm_trim_tail(char *str);
void drv_disallowed(void);
void drv_mk_prsv_key(void);
void drv_proc_error(void);
void int32_to_char(int32_t val, uchar_t *start, int len);
void int64_to_char(int64_t val, uchar_t *start, int len);

#ifdef	__cplusplus
}
#endif

#endif	/* __DM_PROTO_H */
