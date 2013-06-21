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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Function prototypes for the SMB module.
 */

#ifndef _SMB_KPROTO_H_
#define	_SMB_KPROTO_H_

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/socket.h>
#include <sys/ksocket.h>
#include <sys/cred.h>
#include <sys/nbmlock.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <smbsrv/smb.h>
#include <smbsrv/string.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/smb_token.h>
#include <smbsrv/smb_ktypes.h>
#include <smbsrv/smb_ioctl.h>

/*
 * DTrace SDT probes have different signatures in userland than they do in
 * kernel.  If they're being used in kernel code, re-define them out of
 * existence for their counterparts in libfksmbsrv
 */
#ifndef	_KERNEL
#undef	DTRACE_SMB_1
#define	DTRACE_SMB_1(a, b, c)			((void)c)
#undef	DTRACE_SMB_2
#define	DTRACE_SMB_2(a, b, c, d, e)		((void)c, (void)e)
#undef	DTRACE_PROBE1
#define	DTRACE_PROBE1(a, b, c)			((void)c)
#undef	DTRACE_PROBE2
#define	DTRACE_PROBE2(a, b, c, d, e)		((void)c, (void)e)
#undef	DTRACE_PROBE3
#define	DTRACE_PROBE3(a, b, c, d, e, f, g)	((void)c, (void)e, (void)g)
#endif	/* _KERNEL */

extern	int smb_maxbufsize;
extern	int smb_flush_required;
extern	int smb_dirsymlink_enable;
extern	int smb_oplock_levelII;
extern	int smb_oplock_timeout;
extern	int smb_oplock_min_timeout;
extern	int smb_shortnames;
extern	int smb_sign_debug;
extern	int smb_raw_mode;
extern	uint_t smb_audit_flags;
extern	int smb_ssetup_threshold;
extern	int smb_tcon_threshold;
extern	int smb_opipe_threshold;
extern	int smb_ssetup_timeout;
extern	int smb_tcon_timeout;
extern	int smb_opipe_timeout;
extern const uint32_t smb_vop_dosattr_settable;

/* Thread priorities - see smb_init.c */
extern	int smbsrv_base_pri;
extern	int smbsrv_listen_pri;
extern	int smbsrv_receive_pri;
extern	int smbsrv_worker_pri;
extern	int smbsrv_notify_pri;
extern	int smbsrv_timer_pri;

extern	kmem_cache_t		*smb_cache_request;
extern	kmem_cache_t		*smb_cache_session;
extern	kmem_cache_t		*smb_cache_user;
extern	kmem_cache_t		*smb_cache_tree;
extern	kmem_cache_t		*smb_cache_ofile;
extern	kmem_cache_t		*smb_cache_odir;
extern	kmem_cache_t		*smb_cache_opipe;
extern	kmem_cache_t		*smb_cache_event;

extern	kmem_cache_t		*smb_kshare_cache_vfs;

int		fd_dealloc(int);

off_t		lseek(int fildes, off_t offset, int whence);

int		arpioctl(int cmd, void *data);
int		microtime(timestruc_t *tvp);
int		clock_get_uptime(void);

int smb_server_lookup(smb_server_t **);
void smb_server_release(smb_server_t *);

/*
 * SMB request handers called from the dispatcher.  Each SMB request
 * is handled in three phases: pre, com (command) and post.
 *
 * The pre-handler is primarily to set things up for the DTrace start
 * probe.  Typically, the SMB request is unmarshalled so that request
 * specific context can be traced.  This is also a useful place to
 * allocate memory that will be used throughout the processing of the
 * command.
 *
 * The com-handler performs the requested operation: request validation,
 * bulk (write) incoming data decode, implementation of the appropriate
 * algorithm and transmission of a response (as appropriate).
 *
 * The post-handler is always called, regardless of success or failure
 * of the pre or com functions, to trigger the DTrace done probe and
 * deallocate memory allocated in the pre-handler.
 */
#define	SMB_SDT_OPS(NAME)	\
	smb_pre_##NAME,		\
	smb_com_##NAME,		\
	smb_post_##NAME

#define	SMB_COM_DECL(NAME)				\
	smb_sdrc_t smb_pre_##NAME(smb_request_t *);	\
	smb_sdrc_t smb_com_##NAME(smb_request_t *);	\
	void smb_post_##NAME(smb_request_t *)

SMB_COM_DECL(check_directory);
SMB_COM_DECL(close);
SMB_COM_DECL(close_and_tree_disconnect);
SMB_COM_DECL(close_print_file);
SMB_COM_DECL(create);
SMB_COM_DECL(create_directory);
SMB_COM_DECL(create_new);
SMB_COM_DECL(create_temporary);
SMB_COM_DECL(delete);
SMB_COM_DECL(delete_directory);
SMB_COM_DECL(echo);
SMB_COM_DECL(find);
SMB_COM_DECL(find_close);
SMB_COM_DECL(find_close2);
SMB_COM_DECL(find_unique);
SMB_COM_DECL(flush);
SMB_COM_DECL(get_print_queue);
SMB_COM_DECL(invalid);
SMB_COM_DECL(ioctl);
SMB_COM_DECL(lock_and_read);
SMB_COM_DECL(lock_byte_range);
SMB_COM_DECL(locking_andx);
SMB_COM_DECL(logoff_andx);
SMB_COM_DECL(negotiate);
SMB_COM_DECL(nt_cancel);
SMB_COM_DECL(nt_create_andx);
SMB_COM_DECL(nt_rename);
SMB_COM_DECL(nt_transact);
SMB_COM_DECL(nt_transact_secondary);
SMB_COM_DECL(open);
SMB_COM_DECL(open_andx);
SMB_COM_DECL(open_print_file);
SMB_COM_DECL(process_exit);
SMB_COM_DECL(query_information);
SMB_COM_DECL(query_information2);
SMB_COM_DECL(query_information_disk);
SMB_COM_DECL(read);
SMB_COM_DECL(read_andx);
SMB_COM_DECL(read_raw);
SMB_COM_DECL(rename);
SMB_COM_DECL(search);
SMB_COM_DECL(seek);
SMB_COM_DECL(session_setup_andx);
SMB_COM_DECL(set_information);
SMB_COM_DECL(set_information2);
SMB_COM_DECL(transaction);
SMB_COM_DECL(transaction2);
SMB_COM_DECL(transaction2_secondary);
SMB_COM_DECL(transaction_secondary);
SMB_COM_DECL(tree_connect);
SMB_COM_DECL(tree_connect_andx);
SMB_COM_DECL(tree_disconnect);
SMB_COM_DECL(unlock_byte_range);
SMB_COM_DECL(write);
SMB_COM_DECL(write_and_close);
SMB_COM_DECL(write_and_unlock);
SMB_COM_DECL(write_andx);
SMB_COM_DECL(write_print_file);
SMB_COM_DECL(write_raw);

#define	SMB_NT_TRANSACT_DECL(NAME)				\
	smb_sdrc_t smb_pre_##NAME(smb_request_t *, smb_xa_t *);	\
	smb_sdrc_t smb_##NAME(smb_request_t *, smb_xa_t *);	\
	void smb_post_##NAME(smb_request_t *, smb_xa_t *)

SMB_NT_TRANSACT_DECL(nt_transact_create);

smb_sdrc_t smb_nt_transact_notify_change(smb_request_t *, smb_xa_t *);
smb_sdrc_t smb_nt_transact_query_security_info(smb_request_t *, smb_xa_t *);
smb_sdrc_t smb_nt_transact_set_security_info(smb_request_t *, smb_xa_t *);
smb_sdrc_t smb_nt_transact_ioctl(smb_request_t *, smb_xa_t *);
smb_sdrc_t smb_nt_transact_rename(smb_request_t *, smb_xa_t *);
smb_sdrc_t smb_nt_transact_query_quota(smb_request_t *, smb_xa_t *);
smb_sdrc_t smb_nt_transact_set_quota(smb_request_t *, smb_xa_t *);

smb_sdrc_t smb_com_trans2_open2(smb_request_t *, smb_xa_t *);
smb_sdrc_t smb_com_trans2_create_directory(smb_request_t *, smb_xa_t *);
smb_sdrc_t smb_com_trans2_find_first2(smb_request_t *, smb_xa_t *);
smb_sdrc_t smb_com_trans2_find_next2(smb_request_t *, smb_xa_t *);
smb_sdrc_t smb_com_trans2_query_fs_information(smb_request_t *, smb_xa_t *);
smb_sdrc_t smb_com_trans2_set_fs_information(smb_request_t *, smb_xa_t *);
smb_sdrc_t smb_com_trans2_query_path_information(smb_request_t *, smb_xa_t *);
smb_sdrc_t smb_com_trans2_query_file_information(smb_request_t *, smb_xa_t *);
smb_sdrc_t smb_com_trans2_set_path_information(smb_request_t *, smb_xa_t *);
smb_sdrc_t smb_com_trans2_set_file_information(smb_request_t *, smb_xa_t *);
smb_sdrc_t smb_com_trans2_get_dfs_referral(smb_request_t *, smb_xa_t *);
int smb_trans2_rename(smb_request_t *, smb_node_t *, char *, int);

uint32_t smb_quota_query_user_quota(smb_request_t *, uid_t, smb_quota_t *);

/*
 * Logging functions
 */
void smb_log_flush(void);
void smb_correct_keep_alive_values(uint32_t new_keep_alive);
void smb_close_all_connections(void);

int smb_net_id(uint32_t);

/*
 * oplock functions - node operations
 */
int smb_oplock_init(void);
void smb_oplock_fini(void);
void smb_oplock_acquire(smb_request_t *sr, smb_node_t *, smb_ofile_t *);
void smb_oplock_release(smb_node_t *, smb_ofile_t *);
int smb_oplock_break(smb_request_t *, smb_node_t *, uint32_t);
void smb_oplock_break_levelII(smb_node_t *);
void smb_oplock_ack(smb_node_t *, smb_ofile_t *, uint8_t);
void smb_oplock_broadcast(smb_node_t *);

/*
 * range lock functions - node operations
 */
uint32_t smb_lock_get_lock_count(smb_node_t *, smb_ofile_t *);
uint32_t smb_unlock_range(smb_request_t *, smb_node_t *,
    uint64_t, uint64_t);
uint32_t smb_lock_range(smb_request_t *, uint64_t, uint64_t, uint32_t,
    uint32_t locktype);
void smb_lock_range_error(smb_request_t *, uint32_t);
DWORD smb_nbl_conflict(smb_node_t *, uint64_t, uint64_t, nbl_op_t);

void smb_mangle(const char *, ino64_t, char *, size_t);
int smb_unmangle(smb_node_t *, char *, char *, int, uint32_t);
boolean_t smb_needs_mangled(const char *);
boolean_t smb_maybe_mangled(char *);
boolean_t smb_is_reserved_dos_name(const char *);
boolean_t smb_is_invalid_filename(const char *);

void smbsr_cleanup(smb_request_t *sr);

int smbsr_connect_tree(smb_request_t *);

int smb_common_create_directory(smb_request_t *);

void	smb_convert_wildcards(char *);
boolean_t smb_contains_wildcards(const char *);
int	smb_ascii_or_unicode_strlen(smb_request_t *, char *);
int	smb_ascii_or_unicode_strlen_null(smb_request_t *, char *);
int	smb_ascii_or_unicode_null_len(smb_request_t *);

int	smb_search(smb_request_t *);

uint32_t smb_common_create(smb_request_t *);
uint32_t smb_common_open(smb_request_t *);
int smb_common_write(smb_request_t *, smb_rw_param_t *);

void smb_pathname_init(smb_request_t *, smb_pathname_t *, char *);
boolean_t smb_pathname_validate(smb_request_t *, smb_pathname_t *);
boolean_t smb_validate_dirname(smb_request_t *, smb_pathname_t *);
boolean_t smb_validate_object_name(smb_request_t *, smb_pathname_t *);
boolean_t smb_validate_stream_name(smb_request_t *, smb_pathname_t *);
boolean_t smb_is_stream_name(char *);
void smb_stream_parse_name(char *, char *, char *);


uint32_t smb_omode_to_amask(uint32_t desired_access);

void	sshow_distribution_info(char *);

void	smb_dispatch_stats_init(smb_server_t *);
void	smb_dispatch_stats_fini(smb_server_t *);
void	smb_dispatch_stats_update(smb_server_t *,
		smb_kstat_req_t *, int, int);

boolean_t smb_dispatch_request(smb_request_t *);
int	smbsr_encode_empty_result(smb_request_t *);
void	smbsr_lookup_file(smb_request_t *);
void	smbsr_release_file(smb_request_t *);

int	smbsr_decode_vwv(smb_request_t *sr, char *fmt, ...);
int	smbsr_decode_data(smb_request_t *sr, char *fmt, ...);
boolean_t smbsr_decode_data_avail(smb_request_t *);
int	smbsr_encode_result(smb_request_t *, int, int, char *, ...);
smb_xa_t *smbsr_lookup_xa(smb_request_t *sr);
void	smbsr_send_reply(smb_request_t *);

void	smbsr_map_errno(int, smb_error_t *);
void	smbsr_set_error(smb_request_t *, smb_error_t *);
void	smbsr_errno(smb_request_t *, int);
void	smbsr_status(smb_request_t *, DWORD, uint16_t, uint16_t);
#define	smbsr_error(SR, ST, CL, CO) \
	smbsr_status(SR, ST, CL, CO)
#define	smbsr_warn(SR, ST, CL, CO) \
	smbsr_status(SR, ST, CL, CO)

int	clock_get_milli_uptime(void);

int	smb_mbc_vencodef(mbuf_chain_t *, char *, va_list);
int	smb_mbc_vdecodef(mbuf_chain_t *, char *, va_list);
int	smb_mbc_decodef(mbuf_chain_t *, char *, ...);
int	smb_mbc_encodef(mbuf_chain_t *, char *, ...);
int	smb_mbc_peek(mbuf_chain_t *, int, char *, ...);
int	smb_mbc_poke(mbuf_chain_t *, int, char *, ...);
int	smb_mbc_put_mem(mbuf_chain_t *, void *, int);
int	smb_mbc_copy(mbuf_chain_t *, const mbuf_chain_t *, int, int);

void	smbsr_encode_header(smb_request_t *sr, int wct,
		    int bcc, char *fmt, ...);

int smb_lock_range_access(smb_request_t *, smb_node_t *,
    uint64_t, uint64_t, boolean_t);

void smb_encode_sid(smb_xa_t *, smb_sid_t *);
smb_sid_t *smb_decode_sid(smb_xa_t *, uint32_t);
uint32_t smb_decode_sd(smb_xa_t *, smb_sd_t *);

uint32_t smb_pad_align(uint32_t, uint32_t);

/*
 * Socket functions
 */
ksocket_t smb_socreate(int domain, int type, int protocol);
void smb_soshutdown(ksocket_t so);
void smb_sodestroy(ksocket_t so);
int smb_sorecv(ksocket_t so, void *msg, size_t len);
void smb_net_init(void);
void smb_net_fini(void);
void smb_net_txl_constructor(smb_txlst_t *);
void smb_net_txl_destructor(smb_txlst_t *);
smb_txreq_t *smb_net_txr_alloc(void);
void smb_net_txr_free(smb_txreq_t *);
int smb_net_txr_send(ksocket_t, smb_txlst_t *, smb_txreq_t *);

/*
 * SMB RPC interface
 */
void smb_opipe_dealloc(smb_opipe_t *);
int smb_opipe_open(smb_request_t *, uint32_t);
void smb_opipe_close(smb_ofile_t *);
int smb_opipe_read(smb_request_t *, struct uio *);
int smb_opipe_write(smb_request_t *, struct uio *);
int smb_opipe_get_nread(smb_request_t *, int *);

void smb_opipe_door_init(smb_server_t *);
void smb_opipe_door_fini(smb_server_t *);
int smb_opipe_door_open(smb_server_t *, int);
void smb_opipe_door_close(smb_server_t *);
int smb_opipe_door_call(smb_opipe_t *);
void fksmb_opipe_door_open(smb_server_t *, void *);

void smb_kdoor_init(smb_server_t *);
void smb_kdoor_fini(smb_server_t *);
int smb_kdoor_open(smb_server_t *, int);
void smb_kdoor_close(smb_server_t *);
int smb_kdoor_upcall(smb_server_t *, uint32_t,
	void *, xdrproc_t, void *, xdrproc_t);
void fksmb_kdoor_open(smb_server_t *, void *);

/*
 * SMB server functions (file smb_server.c)
 */
int smb_server_g_init(void);
int smb_server_g_fini(void);
int smb_server_create(void);
int smb_server_delete(void);
int smb_server_configure(smb_ioc_cfg_t *);
int smb_server_start(smb_ioc_start_t *);
int smb_server_stop(void);
boolean_t smb_server_is_stopping(smb_server_t *);
void smb_server_cancel_event(smb_server_t *, uint32_t);
int smb_server_notify_event(smb_ioc_event_t *);
uint32_t smb_server_get_session_count(smb_server_t *);
int smb_server_set_gmtoff(smb_ioc_gmt_t *);
int smb_server_numopen(smb_ioc_opennum_t *);
int smb_server_enum(smb_ioc_svcenum_t *);
int smb_server_session_close(smb_ioc_session_t *);
int smb_server_file_close(smb_ioc_fileid_t *);
int smb_server_sharevp(smb_server_t *, const char *, vnode_t **);
int smb_server_unshare(const char *);

void smb_server_get_cfg(smb_server_t *, smb_kmod_cfg_t *);

int smb_server_spooldoc(smb_ioc_spooldoc_t *);
int smb_spool_add_doc(smb_tree_t *, smb_kspooldoc_t *);
void smb_spool_add_fid(smb_server_t *, uint16_t);

void smb_server_inc_nbt_sess(smb_server_t *);
void smb_server_dec_nbt_sess(smb_server_t *);
void smb_server_inc_tcp_sess(smb_server_t *);
void smb_server_dec_tcp_sess(smb_server_t *);
void smb_server_inc_users(smb_server_t *);
void smb_server_dec_users(smb_server_t *);
void smb_server_inc_trees(smb_server_t *);
void smb_server_dec_trees(smb_server_t *);
void smb_server_inc_files(smb_server_t *);
void smb_server_dec_files(smb_server_t *);
void smb_server_inc_pipes(smb_server_t *);
void smb_server_dec_pipes(smb_server_t *);
void smb_server_add_rxb(smb_server_t *, int64_t);
void smb_server_add_txb(smb_server_t *, int64_t);
void smb_server_inc_req(smb_server_t *);

smb_event_t *smb_event_create(smb_server_t *, int);
void smb_event_destroy(smb_event_t *);
uint32_t smb_event_txid(smb_event_t *);
int smb_event_wait(smb_event_t *);
void smb_event_notify(smb_server_t *, uint32_t);

/*
 * SMB node functions (file smb_node.c)
 */
void smb_node_init(void);
void smb_node_fini(void);
smb_node_t *smb_node_lookup(smb_request_t *, smb_arg_open_t *,
    cred_t *, vnode_t *, char *, smb_node_t *, smb_node_t *);
smb_node_t *smb_stream_node_lookup(smb_request_t *, cred_t *,
    smb_node_t *, vnode_t *, vnode_t *, char *);

void smb_node_ref(smb_node_t *);
void smb_node_release(smb_node_t *);
void smb_node_rename(smb_node_t *, smb_node_t *, smb_node_t *, char *);
int smb_node_root_init(smb_server_t *, smb_node_t **);
void smb_node_add_lock(smb_node_t *, smb_lock_t *);
void smb_node_destroy_lock(smb_node_t *, smb_lock_t *);
void smb_node_destroy_lock_by_ofile(smb_node_t *, smb_ofile_t *);
void smb_node_start_crit(smb_node_t *, krw_t);
void smb_node_end_crit(smb_node_t *);
int smb_node_in_crit(smb_node_t *);
void smb_node_rdlock(smb_node_t *);
void smb_node_wrlock(smb_node_t *);
void smb_node_unlock(smb_node_t *);
void smb_node_add_ofile(smb_node_t *, smb_ofile_t *);
void smb_node_rem_ofile(smb_node_t *, smb_ofile_t *);
void smb_node_inc_open_ofiles(smb_node_t *);
uint32_t smb_node_dec_open_ofiles(smb_node_t *);
void smb_node_inc_opening_count(smb_node_t *);
void smb_node_dec_opening_count(smb_node_t *);
boolean_t smb_node_is_file(smb_node_t *);
boolean_t smb_node_is_dir(smb_node_t *);
boolean_t smb_node_is_symlink(smb_node_t *);
boolean_t smb_node_is_dfslink(smb_node_t *);
boolean_t smb_node_is_reparse(smb_node_t *);
boolean_t smb_node_is_vfsroot(smb_node_t *);
boolean_t smb_node_is_system(smb_node_t *);

uint32_t smb_node_open_check(smb_node_t *, uint32_t, uint32_t);
DWORD smb_node_rename_check(smb_node_t *);
DWORD smb_node_delete_check(smb_node_t *);
boolean_t smb_node_share_check(smb_node_t *);

void smb_node_fcn_subscribe(smb_node_t *, smb_request_t *);
void smb_node_fcn_unsubscribe(smb_node_t *, smb_request_t *);
void smb_node_notify_change(smb_node_t *, uint_t, const char *);
void smb_node_notify_parents(smb_node_t *);
int smb_node_getattr(smb_request_t *, smb_node_t *, cred_t *,
    smb_ofile_t *, smb_attr_t *);
int smb_node_setattr(smb_request_t *, smb_node_t *, cred_t *,
    smb_ofile_t *, smb_attr_t *);
uint32_t smb_node_set_delete_on_close(smb_node_t *, cred_t *, uint32_t);
void smb_node_reset_delete_on_close(smb_node_t *);
boolean_t smb_node_file_is_readonly(smb_node_t *);
int smb_node_getpath(smb_node_t *, vnode_t *, char *, uint32_t);
int smb_node_getmntpath(smb_node_t *, char *, uint32_t);
int smb_node_getshrpath(smb_node_t *, smb_tree_t *, char *, uint32_t);

/*
 * Pathname functions
 */

int smb_pathname_reduce(smb_request_t *, cred_t *,
    const char *, smb_node_t *, smb_node_t *, smb_node_t **, char *);

int smb_pathname(smb_request_t *, char *, int, smb_node_t *,
    smb_node_t *, smb_node_t **, smb_node_t **, cred_t *);

/*
 * smb_vfs functions
 */

int smb_vfs_hold(smb_export_t *, vfs_t *);
void smb_vfs_rele(smb_export_t *, vfs_t *);
void smb_vfs_rele_all(smb_export_t *);

/* NOTIFY CHANGE */

void smb_notify_event(smb_node_t *, uint_t, const char *);
void smb_notify_file_closed(smb_ofile_t *of);

int smb_fem_fcn_install(smb_node_t *);
void smb_fem_fcn_uninstall(smb_node_t *);
int smb_fem_oplock_install(smb_node_t *);
void smb_fem_oplock_uninstall(smb_node_t *);

/* FEM */

int smb_fem_init(void);
void smb_fem_fini(void);

int smb_try_grow(smb_request_t *sr, int64_t new_size);

unsigned short smb_worker_getnum();

/* SMB signing routines smb_signing.c */
int smb_sign_begin(smb_request_t *, smb_token_t *);
int smb_sign_check_request(smb_request_t *);
int smb_sign_check_secondary(smb_request_t *, unsigned int);
void smb_sign_reply(smb_request_t *, mbuf_chain_t *);

boolean_t smb_sattr_check(uint16_t, uint16_t);

void smb_request_cancel(smb_request_t *);
void smb_request_wait(smb_request_t *);

/*
 * authentication support (smb_authenticate.c)
 */
int smb_authenticate_ext(smb_request_t *);
int smb_authenticate_old(smb_request_t *);
void smb_authsock_close(smb_user_t *);

/*
 * session functions (file smb_session.c)
 */
smb_session_t *smb_session_create(ksocket_t, uint16_t, smb_server_t *, int);
void smb_session_receiver(smb_session_t *);
void smb_session_disconnect(smb_session_t *);
void smb_session_timers(smb_llist_t *);
void smb_session_delete(smb_session_t *session);
void smb_session_cancel_requests(smb_session_t *, smb_tree_t *,
    smb_request_t *);
void smb_session_config(smb_session_t *session);
void smb_session_disconnect_from_share(smb_llist_t *, char *);
smb_user_t *smb_session_dup_user(smb_session_t *, char *, char *);
smb_user_t *smb_session_lookup_uid(smb_session_t *, uint16_t);
smb_user_t *smb_session_lookup_uid_st(smb_session_t *session,
    uint16_t uid, smb_user_state_t st);
void smb_session_post_user(smb_session_t *, smb_user_t *);
void smb_session_post_tree(smb_session_t *, smb_tree_t *);
smb_tree_t *smb_session_lookup_tree(smb_session_t *, uint16_t);
smb_tree_t *smb_session_lookup_share(smb_session_t *, const char *,
    smb_tree_t *);
smb_tree_t *smb_session_lookup_volume(smb_session_t *, const char *,
    smb_tree_t *);
void smb_session_close_pid(smb_session_t *, uint16_t);
void smb_session_disconnect_owned_trees(smb_session_t *, smb_user_t *);
void smb_session_disconnect_trees(smb_session_t *);
void smb_session_disconnect_share(smb_session_t *, const char *);
void smb_session_getclient(smb_session_t *, char *, size_t);
boolean_t smb_session_isclient(smb_session_t *, const char *);
void smb_session_correct_keep_alive_values(smb_llist_t *, uint32_t);
void smb_session_oplock_break(smb_session_t *, uint16_t, uint16_t, uint8_t);
int smb_session_send(smb_session_t *, uint8_t type, mbuf_chain_t *);
int smb_session_xprt_gethdr(smb_session_t *, smb_xprt_t *);
boolean_t smb_session_oplocks_enable(smb_session_t *);
boolean_t smb_session_levelII_oplocks(smb_session_t *);

#define	SMB_SESSION_GET_ID(s)	((s)->s_kid)

smb_request_t *smb_request_alloc(smb_session_t *, int);
void smb_request_free(smb_request_t *);

/*
 * ofile functions (file smb_ofile.c)
 */
smb_ofile_t *smb_ofile_lookup_by_fid(smb_request_t *, uint16_t);
smb_ofile_t *smb_ofile_lookup_by_uniqid(smb_tree_t *, uint32_t);
boolean_t smb_ofile_disallow_fclose(smb_ofile_t *);
smb_ofile_t *smb_ofile_open(smb_request_t *, smb_node_t *,
    smb_arg_open_t *, uint16_t, uint32_t, smb_error_t *);
void smb_ofile_close(smb_ofile_t *, int32_t);
void smb_ofile_delete(void *);
uint32_t smb_ofile_access(smb_ofile_t *, cred_t *, uint32_t);
int smb_ofile_seek(smb_ofile_t *, ushort_t, int32_t, uint32_t *);
boolean_t smb_ofile_hold(smb_ofile_t *);
void smb_ofile_release(smb_ofile_t *);
void smb_ofile_request_complete(smb_ofile_t *);
void smb_ofile_close_all(smb_tree_t *);
void smb_ofile_close_all_by_pid(smb_tree_t *, uint16_t);
void smb_ofile_set_flags(smb_ofile_t *, uint32_t);
boolean_t smb_ofile_is_open(smb_ofile_t *);
int smb_ofile_enum(smb_ofile_t *, smb_svcenum_t *);
uint32_t smb_ofile_open_check(smb_ofile_t *, uint32_t, uint32_t);
uint32_t smb_ofile_rename_check(smb_ofile_t *);
uint32_t smb_ofile_delete_check(smb_ofile_t *);
boolean_t smb_ofile_share_check(smb_ofile_t *);
cred_t *smb_ofile_getcred(smb_ofile_t *);
void smb_ofile_set_delete_on_close(smb_ofile_t *);
void smb_delayed_write_timer(smb_llist_t *);
void smb_ofile_set_quota_resume(smb_ofile_t *, char *);
void smb_ofile_get_quota_resume(smb_ofile_t *, char *, int);

#define	SMB_OFILE_GET_SESSION(of)	((of)->f_session)
#define	SMB_OFILE_GET_TREE(of)		((of)->f_tree)
#define	SMB_OFILE_GET_FID(of)		((of)->f_fid)
#define	SMB_OFILE_GET_NODE(of)		((of)->f_node)

#define	smb_ofile_granted_access(_of_)	((_of_)->f_granted_access)

/*
 * odir functions (file smb_odir.c)
 */
uint16_t smb_odir_open(smb_request_t *, char *, uint16_t, uint32_t);
uint16_t smb_odir_openat(smb_request_t *, smb_node_t *);
void smb_odir_close(smb_odir_t *);
boolean_t smb_odir_hold(smb_odir_t *);
void smb_odir_release(smb_odir_t *);
void smb_odir_delete(void *);

int smb_odir_read(smb_request_t *, smb_odir_t *,
    smb_odirent_t *, boolean_t *);
int smb_odir_read_fileinfo(smb_request_t *, smb_odir_t *,
    smb_fileinfo_t *, uint16_t *);
int smb_odir_read_streaminfo(smb_request_t *, smb_odir_t *,
    smb_streaminfo_t *, boolean_t *);

void smb_odir_save_cookie(smb_odir_t *, int, uint32_t cookie);
void smb_odir_save_fname(smb_odir_t *, uint32_t, const char *);

void smb_odir_resume_at(smb_odir_t *, smb_odir_resume_t *);

/*
 * SMB user functions (file smb_user.c)
 */
smb_user_t *smb_user_new(smb_session_t *);
int smb_user_logon(smb_user_t *, cred_t *,
    char *, char *, uint32_t, uint32_t, uint32_t);
smb_user_t *smb_user_dup(smb_user_t *);
void smb_user_logoff(smb_user_t *);
void smb_user_delete(void *);
boolean_t smb_user_is_admin(smb_user_t *);
boolean_t smb_user_namecmp(smb_user_t *, const char *);
int smb_user_enum(smb_user_t *, smb_svcenum_t *);
boolean_t smb_user_hold(smb_user_t *);
void smb_user_hold_internal(smb_user_t *);
void smb_user_release(smb_user_t *);
cred_t *smb_user_getcred(smb_user_t *);
cred_t *smb_user_getprivcred(smb_user_t *);
void smb_user_netinfo_init(smb_user_t *, smb_netuserinfo_t *);
void smb_user_netinfo_fini(smb_netuserinfo_t *);
int smb_user_netinfo_encode(smb_user_t *, uint8_t *, size_t, uint32_t *);
smb_token_t *smb_get_token(smb_session_t *, smb_logon_t *);
cred_t *smb_cred_create(smb_token_t *);
void smb_user_setcred(smb_user_t *, cred_t *, uint32_t);

/*
 * SMB tree functions (file smb_tree.c)
 */
smb_tree_t *smb_tree_connect(smb_request_t *);
void smb_tree_disconnect(smb_tree_t *, boolean_t);
void smb_tree_dealloc(void *);
void smb_tree_post_ofile(smb_tree_t *, smb_ofile_t *);
void smb_tree_post_odir(smb_tree_t *, smb_odir_t *);
void smb_tree_close_pid(smb_tree_t *, uint16_t);
boolean_t smb_tree_has_feature(smb_tree_t *, uint_t);
int smb_tree_enum(smb_tree_t *, smb_svcenum_t *);
int smb_tree_fclose(smb_tree_t *, uint32_t);
boolean_t smb_tree_hold(smb_tree_t *);
void smb_tree_release(smb_tree_t *);
smb_odir_t *smb_tree_lookup_odir(smb_request_t *, uint16_t);
boolean_t smb_tree_is_connected(smb_tree_t *);
#define	SMB_TREE_GET_TID(tree)		((tree)->t_tid)

smb_xa_t *smb_xa_create(smb_session_t *session, smb_request_t *sr,
    uint32_t total_parameter_count, uint32_t total_data_count,
    uint32_t max_parameter_count, uint32_t max_data_count,
    uint32_t max_setup_count, uint32_t setup_word_count);
void smb_xa_delete(smb_xa_t *xa);
smb_xa_t *smb_xa_hold(smb_xa_t *xa);
void smb_xa_rele(smb_session_t *session, smb_xa_t *xa);
int smb_xa_open(smb_xa_t *xa);
void smb_xa_close(smb_xa_t *xa);
int smb_xa_complete(smb_xa_t *xa);
smb_xa_t *smb_xa_find(smb_session_t *session, uint16_t pid, uint16_t mid);

struct mbuf *smb_mbuf_get(uchar_t *buf, int nbytes);
struct mbuf *smb_mbuf_allocate(struct uio *uio);
void smb_mbuf_trim(struct mbuf *mhead, int nbytes);

void smb_check_status(void);
int smb_handle_write_raw(smb_session_t *session, smb_request_t *sr);

int32_t smb_time_gmt_to_local(smb_request_t *, int32_t);
int32_t smb_time_local_to_gmt(smb_request_t *, int32_t);
int32_t	smb_time_dos_to_unix(int16_t, int16_t);
void smb_time_unix_to_dos(int32_t, int16_t *, int16_t *);
void smb_time_nt_to_unix(uint64_t nt_time, timestruc_t *unix_time);
uint64_t smb_time_unix_to_nt(timestruc_t *);

int netbios_name_isvalid(char *in, char *out);

int uioxfer(struct uio *src_uio, struct uio *dst_uio, int n);

/*
 * Pool ID function prototypes
 */
int	smb_idpool_constructor(smb_idpool_t *pool);
void	smb_idpool_destructor(smb_idpool_t  *pool);
int	smb_idpool_alloc(smb_idpool_t *pool, uint16_t *id);
void	smb_idpool_free(smb_idpool_t *pool, uint16_t id);

/*
 * SMB thread function prototypes
 */
void	smb_session_worker(void *arg);

/*
 * SMB locked list function prototypes
 */
void	smb_llist_init(void);
void	smb_llist_fini(void);
void	smb_llist_constructor(smb_llist_t *, size_t, size_t);
void	smb_llist_destructor(smb_llist_t *);
void	smb_llist_exit(smb_llist_t *);
void	smb_llist_post(smb_llist_t *, void *, smb_dtorproc_t);
void	smb_llist_flush(smb_llist_t *);
void	smb_llist_insert_head(smb_llist_t *ll, void *obj);
void	smb_llist_insert_tail(smb_llist_t *ll, void *obj);
void	smb_llist_remove(smb_llist_t *ll, void *obj);
int	smb_llist_upgrade(smb_llist_t *ll);
uint32_t smb_llist_get_count(smb_llist_t *ll);
#define	smb_llist_enter(ll, mode)	rw_enter(&(ll)->ll_lock, mode)
#define	smb_llist_head(ll)		list_head(&(ll)->ll_list)
#define	smb_llist_next(ll, obj)		list_next(&(ll)->ll_list, obj)
int	smb_account_connected(smb_user_t *user);

/*
 * SMB Synchronized list function prototypes
 */
void	smb_slist_constructor(smb_slist_t *, size_t, size_t);
void	smb_slist_destructor(smb_slist_t *);
void	smb_slist_insert_head(smb_slist_t *sl, void *obj);
void	smb_slist_insert_tail(smb_slist_t *sl, void *obj);
void	smb_slist_remove(smb_slist_t *sl, void *obj);
void	smb_slist_wait_for_empty(smb_slist_t *sl);
void	smb_slist_exit(smb_slist_t *sl);
uint32_t smb_slist_move_tail(list_t *lst, smb_slist_t *sl);
void    smb_slist_obj_move(smb_slist_t *dst, smb_slist_t *src, void *obj);
#define	smb_slist_enter(sl)		mutex_enter(&(sl)->sl_mutex)
#define	smb_slist_head(sl)		list_head(&(sl)->sl_list)
#define	smb_slist_next(sl, obj)		list_next(&(sl)->sl_list, obj)

void    smb_rwx_init(smb_rwx_t *rwx);
void    smb_rwx_destroy(smb_rwx_t *rwx);
#define	smb_rwx_rwenter(rwx, mode)	rw_enter(&(rwx)->rwx_lock, mode)
void    smb_rwx_rwexit(smb_rwx_t *rwx);
int	smb_rwx_rwwait(smb_rwx_t *rwx, clock_t timeout);
#define	smb_rwx_xenter(rwx)		mutex_enter(&(rwx)->rwx_mutex)
#define	smb_rwx_xexit(rwx)		mutex_exit(&(rwx)->rwx_mutex)
krw_t   smb_rwx_rwupgrade(smb_rwx_t *rwx);
void    smb_rwx_rwdowngrade(smb_rwx_t *rwx, krw_t mode);

void	smb_thread_init(smb_thread_t *, char *, smb_thread_ep_t,
		void *, pri_t);
void	smb_thread_destroy(smb_thread_t *);
int	smb_thread_start(smb_thread_t *);
void	smb_thread_stop(smb_thread_t *);
void    smb_thread_signal(smb_thread_t *);
boolean_t smb_thread_continue(smb_thread_t *);
boolean_t smb_thread_continue_nowait(smb_thread_t *);
boolean_t smb_thread_continue_timedwait(smb_thread_t *, int /* seconds */);

uint32_t smb_denymode_to_sharemode(uint32_t desired_access, char *fname);
uint32_t smb_ofun_to_crdisposition(uint16_t ofun);

/* 100's of ns between 1/1/1970 and 1/1/1601 */
#define	NT_TIME_BIAS	(134774LL * 24LL * 60LL * 60LL * 10000000LL)

uint32_t smb_sd_read(smb_request_t *, smb_sd_t *, uint32_t);
uint32_t smb_sd_write(smb_request_t *, smb_sd_t *, uint32_t);

acl_t *smb_fsacl_inherit(acl_t *, int, int, cred_t *);
acl_t *smb_fsacl_merge(acl_t *, acl_t *);
void smb_fsacl_split(acl_t *, acl_t **, acl_t **, int);
acl_t *smb_fsacl_from_vsa(vsecattr_t *, acl_type_t);
int smb_fsacl_to_vsa(acl_t *, vsecattr_t *, int *);

boolean_t smb_ace_is_generic(int);
boolean_t smb_ace_is_access(int);
boolean_t smb_ace_is_audit(int);

uint32_t smb_vss_ioctl_enumerate_snaps(smb_request_t *, smb_xa_t *);
int smb_vss_lookup_nodes(smb_request_t *, smb_node_t *, smb_node_t *,
    char *, smb_node_t **, smb_node_t **);
vnode_t *smb_lookuppathvptovp(smb_request_t *, char *, vnode_t *, vnode_t *);

void smb_panic(char *, const char *, int);
#pragma	does_not_return(smb_panic)
#define	SMB_PANIC()	smb_panic(__FILE__, __func__, __LINE__)

void smb_latency_init(smb_latency_t *);
void smb_latency_destroy(smb_latency_t *);
void smb_latency_add_sample(smb_latency_t *, hrtime_t);
void smb_srqueue_init(smb_srqueue_t *);
void smb_srqueue_destroy(smb_srqueue_t *);
void smb_srqueue_waitq_enter(smb_srqueue_t *);
void smb_srqueue_runq_exit(smb_srqueue_t *);
void smb_srqueue_waitq_to_runq(smb_srqueue_t *);
void smb_srqueue_update(smb_srqueue_t *, smb_kstat_utilization_t *);

void *smb_mem_alloc(size_t);
void *smb_mem_zalloc(size_t);
void *smb_mem_realloc(void *, size_t);
void *smb_mem_rezalloc(void *, size_t);
void smb_mem_free(void *);
void smb_mem_zfree(void *);
char *smb_mem_strdup(const char *);
void smb_srm_init(smb_request_t *);
void smb_srm_fini(smb_request_t *);
void *smb_srm_alloc(smb_request_t *, size_t);
void *smb_srm_zalloc(smb_request_t *, size_t);
void *smb_srm_realloc(smb_request_t *, void *, size_t);
void *smb_srm_rezalloc(smb_request_t *, void *, size_t);
char *smb_srm_strdup(smb_request_t *, const char *);

void smb_export_start(smb_server_t *);
void smb_export_stop(smb_server_t *);

#ifdef	_KERNEL
struct __door_handle;
struct __door_handle *smb_kshare_door_init(int);
void smb_kshare_door_fini(struct __door_handle *);
int smb_kshare_upcall(struct __door_handle *, void *, boolean_t);
#endif	/* _KERNEL */

void smb_kshare_g_init(void);
void smb_kshare_g_fini(void);
void smb_kshare_init(smb_server_t *);
void smb_kshare_fini(smb_server_t *);
int smb_kshare_start(smb_server_t *);
void smb_kshare_stop(smb_server_t *);

int smb_kshare_export_list(smb_ioc_share_t *);
int smb_kshare_unexport_list(smb_ioc_share_t *);
int smb_kshare_info(smb_ioc_shareinfo_t *);
void smb_kshare_enum(smb_server_t *, smb_enumshare_info_t *);
smb_kshare_t *smb_kshare_lookup(smb_server_t *, const char *);
void smb_kshare_release(smb_server_t *, smb_kshare_t *);
int smb_kshare_exec(smb_server_t *, smb_shr_execinfo_t *);
uint32_t smb_kshare_hostaccess(smb_kshare_t *, smb_session_t *);


void smb_avl_create(smb_avl_t *, size_t, size_t, const smb_avl_nops_t *);
void smb_avl_destroy(smb_avl_t *);
int smb_avl_add(smb_avl_t *, void *);
void smb_avl_remove(smb_avl_t *, void *);
void *smb_avl_lookup(smb_avl_t *, void *);
void smb_avl_release(smb_avl_t *, void *);
void smb_avl_iterinit(smb_avl_t *, smb_avl_cursor_t *);
void *smb_avl_iterate(smb_avl_t *, smb_avl_cursor_t *);

void smb_threshold_init(smb_cmd_threshold_t *,
    char *, uint_t, uint_t);
void smb_threshold_fini(smb_cmd_threshold_t *);
int smb_threshold_enter(smb_cmd_threshold_t *);
void smb_threshold_exit(smb_cmd_threshold_t *);
void smb_threshold_wake_all(smb_cmd_threshold_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _SMB_KPROTO_H_ */
