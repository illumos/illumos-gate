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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Function prototypes for the SMB module.
 */

#ifndef _SMB_KPROTO_H_
#define	_SMB_KPROTO_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/strsubr.h>
#include <sys/socketvar.h>
#include <sys/cred.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/smb_token.h>
#include <smbsrv/smbvar.h>

/*
 * Definitions that should be elsewhere...
 */
struct mbuf	*m_free(struct mbuf *);
void		m_freem(struct mbuf *);

int		fd_dealloc(int);

off_t		lseek(int fildes, off_t offset, int whence);

int		arpioctl(int cmd, void *data);
/* Why? uint32_t	inet_addr(char *str); */
int		microtime(timestruc_t *tvp);
int		clock_get_uptime(void);

/*
 * SMB Service init/shutdown functions
 */
int smb_service_init(void);
void smb_service_fini(void);
int smb_service_open(struct smb_info *si);
void smb_service_close(struct smb_info *si);
int smb_service_connect(struct smb_info *si);
void smb_service_disconnect(struct smb_info *si);
int smb_service_start_threads(struct smb_info *si);
void smb_service_stop_threads(struct smb_info *si);

/*
 * SMB request handers called from the dispatcher.
 */
smb_sdrc_t smb_com_cancel_forward(struct smb_request *);
smb_sdrc_t smb_com_check_directory(struct smb_request *);
smb_sdrc_t smb_com_close(struct smb_request *);
smb_sdrc_t smb_com_close_and_tree_disconnect(struct smb_request *);
smb_sdrc_t smb_com_close_print_file(struct smb_request *);
smb_sdrc_t smb_com_copy(struct smb_request *);
smb_sdrc_t smb_com_create(struct smb_request *);
smb_sdrc_t smb_com_create_directory(struct smb_request *);
smb_sdrc_t smb_com_create_new(struct smb_request *);
smb_sdrc_t smb_com_create_temporary(struct smb_request *);
smb_sdrc_t smb_com_delete(struct smb_request *);
smb_sdrc_t smb_com_delete_directory(struct smb_request *);
smb_sdrc_t smb_com_echo(struct smb_request *);
smb_sdrc_t smb_com_find(struct smb_request *);
smb_sdrc_t smb_com_find_close(struct smb_request *);
smb_sdrc_t smb_com_find_close2(struct smb_request *);
smb_sdrc_t smb_com_find_notify_close(struct smb_request *);
smb_sdrc_t smb_com_find_unique(struct smb_request *);
smb_sdrc_t smb_com_flush(struct smb_request *);
smb_sdrc_t smb_com_forward_user_name(struct smb_request *);
smb_sdrc_t smb_com_get_machine_name(struct smb_request *);
smb_sdrc_t smb_com_get_print_queue(struct smb_request *);
smb_sdrc_t smb_com_invalid_command(struct smb_request *);
smb_sdrc_t smb_com_ioctl(struct smb_request *);
smb_sdrc_t smb_com_ioctl_secondary(struct smb_request *);
smb_sdrc_t smb_com_lock_and_read(struct smb_request *);
smb_sdrc_t smb_com_lock_byte_range(struct smb_request *);
smb_sdrc_t smb_com_locking_andx(struct smb_request *);
smb_sdrc_t smb_com_logoff_andx(struct smb_request *);
smb_sdrc_t smb_com_move(struct smb_request *);
smb_sdrc_t smb_com_negotiate(struct smb_request *);
smb_sdrc_t smb_com_nt_cancel(struct smb_request *);
smb_sdrc_t smb_com_nt_create_andx(struct smb_request *);
smb_sdrc_t smb_com_nt_transact(struct smb_request *);
smb_sdrc_t smb_com_nt_transact_secondary(struct smb_request *);
smb_sdrc_t smb_com_open(struct smb_request *);
smb_sdrc_t smb_com_open_andx(struct smb_request *);
smb_sdrc_t smb_com_open_print_file(struct smb_request *);
smb_sdrc_t smb_com_process_exit(struct smb_request *);
smb_sdrc_t smb_com_query_information(struct smb_request *);
smb_sdrc_t smb_com_query_information2(struct smb_request *);
smb_sdrc_t smb_com_query_information_disk(struct smb_request *);
smb_sdrc_t smb_com_read(struct smb_request *);
smb_sdrc_t smb_com_read_andx(struct smb_request *);
smb_sdrc_t smb_com_read_mpx(struct smb_request *);
smb_sdrc_t smb_com_read_mpx_secondary(struct smb_request *);
smb_sdrc_t smb_com_read_raw(struct smb_request *);
smb_sdrc_t smb_com_rename(struct smb_request *);
smb_sdrc_t smb_com_search(struct smb_request *);
smb_sdrc_t smb_com_seek(struct smb_request *);
smb_sdrc_t smb_com_send_broadcast_message(struct smb_request *);
smb_sdrc_t smb_com_send_end_mb_message(struct smb_request *);
smb_sdrc_t smb_com_send_single_message(struct smb_request *);
smb_sdrc_t smb_com_send_start_mb_message(struct smb_request *);
smb_sdrc_t smb_com_send_text_mb_message(struct smb_request *);
smb_sdrc_t smb_com_session_setup_andx(struct smb_request *);
smb_sdrc_t smb_com_set_information(struct smb_request *);
smb_sdrc_t smb_com_set_information2(struct smb_request *);
smb_sdrc_t smb_com_transaction(struct smb_request *);
smb_sdrc_t smb_com_transaction2(struct smb_request *);
smb_sdrc_t smb_com_transaction2_secondary(struct smb_request *);
smb_sdrc_t smb_com_transaction_secondary(struct smb_request *);
smb_sdrc_t smb_com_tree_connect(struct smb_request *);
smb_sdrc_t smb_com_tree_connect_andx(struct smb_request *);
smb_sdrc_t smb_com_tree_disconnect(struct smb_request *);
smb_sdrc_t smb_com_unlock_byte_range(struct smb_request *);
smb_sdrc_t smb_com_write(struct smb_request *);
smb_sdrc_t smb_com_write_and_close(struct smb_request *);
smb_sdrc_t smb_com_write_and_unlock(struct smb_request *);
smb_sdrc_t smb_com_write_andx(struct smb_request *);
smb_sdrc_t smb_com_write_complete(struct smb_request *);
smb_sdrc_t smb_com_write_mpx(struct smb_request *);
smb_sdrc_t smb_com_write_mpx_secondary(struct smb_request *);
smb_sdrc_t smb_com_write_print_file(struct smb_request *);
smb_sdrc_t smb_com_write_raw(struct smb_request *);

smb_sdrc_t smb_nt_transact_create(struct smb_request *, struct smb_xa *);
smb_sdrc_t smb_nt_transact_notify_change(struct smb_request *, struct smb_xa *);
smb_sdrc_t smb_nt_transact_query_security_info(struct smb_request *,
    struct smb_xa *);
smb_sdrc_t smb_nt_transact_set_security_info(struct smb_request *,
    struct smb_xa *);
smb_sdrc_t smb_nt_transact_ioctl(struct smb_request *, struct smb_xa *);

smb_sdrc_t smb_com_trans2_create_directory(struct smb_request *,
    struct smb_xa *);
smb_sdrc_t smb_com_trans2_find_first2(struct smb_request *, struct smb_xa *);
smb_sdrc_t smb_com_trans2_find_next2(struct smb_request *, struct smb_xa *);
smb_sdrc_t smb_com_trans2_query_fs_information(struct smb_request *,
    struct smb_xa *);
smb_sdrc_t smb_com_trans2_query_path_information(struct smb_request *,
    struct smb_xa *);
smb_sdrc_t smb_com_trans2_query_file_information(struct smb_request *,
    struct smb_xa *);
smb_sdrc_t smb_com_trans2_set_path_information(struct smb_request *,
    struct smb_xa *);
smb_sdrc_t smb_com_trans2_set_file_information(struct smb_request *,
    struct smb_xa *);

/*
 * Logging functions
 */
void smb_log_flush(void);
void smb_correct_keep_alive_values(uint32_t new_keep_alive);
void smb_close_all_connections(void);
int smb_set_file_size(struct smb_request *sr);
int smb_session_send(smb_session_t *, uint8_t type, struct mbuf_chain *);
int smb_session_xprt_gethdr(smb_session_t *, smb_xprt_t *);

int smb_net_id(uint32_t);
uint32_t smb_gmt_to_local_time(uint32_t);
uint32_t smb_local_time_to_gmt(uint32_t);

void smb_process_file_notify_change_queue(struct smb_ofile *of);

void smb_oplock_init(void);

DWORD smb_acquire_oplock(struct smb_request *sr,
    struct smb_ofile *file,
    unsigned int level_requested,
    unsigned int *level_granted);

DWORD smb_break_oplock(struct smb_request *sr, struct smb_node *node);
void smb_release_oplock(struct smb_ofile *file, int reason);

uint32_t smb_unlock_range(struct smb_request *, struct smb_node *,
    uint64_t, uint64_t);
uint32_t smb_lock_range(struct smb_request *, struct smb_ofile *,
    uint64_t, uint64_t, uint32_t, uint32_t);
void smb_lock_range_error(smb_request_t *, uint32_t);

DWORD smb_range_check(smb_request_t *, cred_t *, smb_node_t *,
    uint64_t, uint64_t, boolean_t);

int smb_mangle_name(ino64_t fileid, char *name, char *shortname,
    char *name83, int force);
int smb_unmangle_name(struct smb_request *sr, cred_t *cred,
    smb_node_t *dir_node, char *name, char *real_name, int realname_size,
    char *shortname, char *name83, int od);
int smb_maybe_mangled_name(char *name);
int smb_maybe_mangled_path(const char *path, size_t pathlen);
int smb_needs_mangle(char *name, char **dot_pos);

void smb_set_stability(int mode);
void smb_commit_required(int state);


void smbsr_cleanup(struct smb_request *sr);

int smbsr_connect_tree(struct smb_request *);

int smb_common_create_directory(struct smb_request *);

int		smb_convert_unicode_wildcards(char *);
int	smb_ascii_or_unicode_strlen(struct smb_request *, char *);
int	smb_ascii_or_unicode_strlen_null(struct smb_request *, char *);
int	smb_ascii_or_unicode_null_len(struct smb_request *);

int	smb_search(struct smb_request *);
void smb_rdir_close(struct smb_request *);
int	smb_rdir_open(struct smb_request *, char *, unsigned short);
int smb_rdir_next(smb_request_t *sr, smb_node_t **rnode,
    smb_odir_context_t *pc);

uint32_t smb_common_open(smb_request_t *);
DWORD smb_validate_object_name(char *path, unsigned int ftype);

uint32_t smb_omode_to_amask(uint32_t desired_access);

void	sshow_distribution_info(char *);

void	smb_dispatch_request(struct smb_request *);
void	smbsr_disconnect_file(smb_request_t *);
void	smbsr_disconnect_dir(smb_request_t *);
int	smbsr_encode_empty_result(struct smb_request *);

int	smbsr_decode_vwv(struct smb_request *sr, char *fmt, ...);
int	smbsr_decode_data(struct smb_request *sr, char *fmt, ...);
int	smbsr_encode_result(struct smb_request *, int, int, char *, ...);
smb_xa_t *smbsr_lookup_xa(smb_request_t *sr);
void	smbsr_send_reply(struct smb_request *);

void	smbsr_map_errno(int, smb_error_t *);
void	smbsr_set_error(smb_request_t *, smb_error_t *);
void	smbsr_errno(struct smb_request *, int);
void	smbsr_warn(struct smb_request *, DWORD, uint16_t, uint16_t);
void	smbsr_error(struct smb_request *, DWORD, uint16_t, uint16_t);

int	smb_mbc_encode(struct mbuf_chain *mbc, char *fmt, va_list ap);
int	smb_mbc_decode(struct mbuf_chain *mbc, char *fmt, va_list ap);

int	clock_get_milli_uptime(void);
int	dosfs_dos_to_ux_time(int, int);
int	dosfs_ux_to_dos_time(int, short int *, short int *);

int	smb_decode_mbc(struct  mbuf_chain *mbc, char *fmt, ...);
int	smb_decode_buf(unsigned char *buf, int n_buf, char *fmt, ...);
int	smb_encode_mbc(struct mbuf_chain *mbc, char *fmt, ...);
int	smb_encode_buf(unsigned char *buf, int n_buf, char *fmt, ...);
int	smb_peek_mbc(struct mbuf_chain *buf, int offset, char *fmt, ...);
int	smb_poke_mbc(struct mbuf_chain *buf, int offset, char *fmt, ...);

void	smbsr_encode_header(struct smb_request *sr, int wct,
		    int bcc, char *fmt, ...);

int	smb_xlate_dialect_str_to_cd(char *);
char	*smb_xlate_com_cd_to_str(int);
char	*smb_xlate_dialect_cd_to_str(int);

void	smb_od_destruct(struct smb_session *, struct smb_odir *);
int	smbd_fs_query(struct smb_request *, struct smb_fqi *, int);
int smb_component_match(struct smb_request *sr, ino64_t fileid,
    struct smb_odir *od, smb_odir_context_t *pc);

int smb_lock_range_access(struct smb_request *, struct smb_node *,
    uint64_t, uint64_t, boolean_t);

uint32_t smb_decode_sd(struct smb_xa *, smb_sd_t *);

/*
 * Socket functions
 */
struct sonode *smb_socreate(int domain, int type, int protocol);
void smb_soshutdown(struct sonode *so);
void smb_sodestroy(struct sonode *so);
int smb_sorecv(struct sonode *so, void *msg, size_t len);
int smb_iov_sorecv(struct sonode *so, iovec_t *iop, int iovlen,
    size_t total_len);
void smb_net_txl_constructor(smb_txlst_t *);
void smb_net_txl_destructor(smb_txlst_t *);
smb_txbuf_t *smb_net_txb_alloc(void);
void smb_net_txb_free(smb_txbuf_t *);
int smb_net_txb_send(struct sonode *, smb_txlst_t *, smb_txbuf_t *);

/*
 * SMB RPC interface
 */
int smb_rpc_open(struct smb_request *);
void smb_rpc_close(struct smb_ofile *);
smb_sdrc_t smb_rpc_transact(struct smb_request *, struct uio *);
int smb_rpc_read(struct smb_request *, struct uio *);
int smb_rpc_write(struct smb_request *, struct uio *);

/*
 * SMB node functions (file smb_node.c)
 */
struct smb_node *smb_node_lookup(struct smb_request *sr, struct open_param *op,
    cred_t *cr, vnode_t *vp, char *od_name, smb_node_t *dir_snode,
    smb_node_t *unnamed_node, smb_attr_t *attr);
struct smb_node *smb_stream_node_lookup(struct smb_request *sr, cred_t *cr,
    smb_node_t *fnode, vnode_t *xattrdirvp, vnode_t *vp, char *stream_name,
    smb_attr_t *ret_attr);
void smb_node_ref(smb_node_t *node);
void smb_node_release(smb_node_t *node);
int smb_node_assert(smb_node_t *node, const char *file, int line);
int smb_node_rename(smb_node_t *from_dir_snode, smb_node_t *ret_snode,
    smb_node_t *to_dir_snode, char *to_name);
int smb_node_root_init();
void smb_node_root_fini();
void smb_node_add_lock(smb_node_t *node, smb_lock_t *lock);
void smb_node_destroy_lock(smb_node_t *node, smb_lock_t *lock);
void smb_node_destroy_lock_by_ofile(smb_node_t *node, smb_ofile_t *file);
void smb_node_start_crit(smb_node_t *node, krw_t mode);
void smb_node_end_crit(smb_node_t *node);
int smb_node_in_crit(smb_node_t *node);

uint32_t smb_node_open_check(smb_node_t *, cred_t *,
    uint32_t, uint32_t);
uint32_t smb_node_share_check(smb_node_t *, cred_t *,
    uint32_t, uint32_t, smb_ofile_t *);
DWORD smb_node_rename_check(smb_node_t *);
DWORD smb_node_delete_check(smb_node_t *);

uint64_t smb_node_get_size(smb_node_t *node, smb_attr_t *attr);
void smb_node_set_time(struct smb_node *node, timestruc_t *crtime,
    timestruc_t *mtime, timestruc_t *atime,
    timestruc_t *ctime, unsigned int what);
timestruc_t *smb_node_get_crtime(struct smb_node *node);
timestruc_t *smb_node_get_atime(struct smb_node *node);
timestruc_t *smb_node_get_ctime(struct smb_node *node);
timestruc_t *smb_node_get_mtime(struct smb_node *node);
void smb_node_set_dosattr(struct smb_node *, uint32_t);
uint32_t smb_node_get_dosattr(struct smb_node *node);
int smb_node_set_delete_on_close(smb_node_t *, cred_t *);
void smb_node_reset_delete_on_close(smb_node_t *);



/*
 * Pathname functions
 */

int smb_pathname_reduce(struct smb_request *, cred_t *,
    const char *, smb_node_t *, smb_node_t *, smb_node_t **, char *);

int smb_pathname(struct smb_request *, char *, int, smb_node_t *,
    smb_node_t *, smb_node_t **, smb_node_t **, cred_t *);

/*
 * Share functions
 */

int smb_share_export(char *);
int smb_share_unexport(char *, char *);

/*
 * smb_vfs functions
 */

boolean_t smb_vfs_hold(vfs_t *);
void smb_vfs_rele(vfs_t *);
void smb_vfs_rele_all(void);

/*
 * String manipulation function
 */
char *smb_kstrdup(const char *s, size_t n);

int smb_sync_fsattr(struct smb_request *sr, cred_t *cr,
    struct smb_node *node);

DWORD	smb_validate_dirname(char *path);


void smb_encode_stream_info(struct smb_request *sr, struct smb_xa *xa,
    smb_node_t *snode, smb_attr_t *attr);

/* NOTIFY CHANGE */
void smb_process_session_notify_change_queue(struct smb_session *session);
void smb_process_node_notify_change_queue(struct smb_node *node);
void smb_reply_specific_cancel_request(struct smb_request *sr);

void smb_fem_fcn_install(smb_node_t *node);
void smb_fem_fcn_uninstall(smb_node_t *node);

/* FEM */

int smb_fem_init();
void smb_fem_shutdown();

int smb_try_grow(struct smb_request *sr, int64_t new_size);

/* functions from smb_memory_manager.c */

void	*smbsr_malloc(smb_malloc_list *, size_t);
void	*smbsr_realloc(void *, size_t);
void	smbsr_free_malloc_list(smb_malloc_list *);

void smbsr_rq_notify(smb_request_t *sr,
    smb_session_t *session, smb_tree_t *tree);

unsigned short smb_worker_getnum();
int smb_common_close(struct smb_request *sr, uint32_t last_wtime);
void smb_preset_delete_on_close(struct smb_ofile *file);
void smb_commit_delete_on_close(struct smb_ofile *file);

int smb_stream_parse_name(char *name, char *u_stream_name,
    char *stream_name);

uint32_t smb_get_gmtoff(void);
void smb_set_gmtoff(uint32_t);

DWORD smb_trans2_set_information(struct smb_request *sr,
    smb_trans2_setinfo_t *info,
    smb_error_t *smberr);

/* SMB signing routines smb_signing.c */
void smb_sign_init(struct smb_request *req,
	smb_session_key_t *session_key, char *resp, int resp_len);

int smb_sign_check_request(struct smb_request *req);

int smb_sign_check_secondary(struct smb_request *req, unsigned int seqnum);

void smb_sign_reply(struct smb_request *req, struct mbuf_chain *reply);

uint32_t smb_mode_to_dos_attributes(smb_attr_t *ap);
int smb_sattr_check(smb_attr_t *ap, char *name, unsigned short sattr);

smb_request_t *smb_request_alloc(struct smb_session *session,
    int request_length);
void smb_request_cancel(smb_request_t *sr);
void smb_request_free(smb_request_t *sr);

smb_session_t *smb_session_create(struct sonode *new_so, uint16_t port);
void smb_session_delete(smb_session_t *session);
void smb_session_cancel(smb_session_t *session);
void smb_session_cancel_requests(smb_session_t *session);
void smb_session_config(smb_session_t *session);
void smb_session_reject(smb_session_t *session, char *reason);
void smb_session_disconnect_share(char *);
void smb_session_disconnect_volume(fs_desc_t *);


/*
 * ofile functions (file smb_ofile.c)
 */
smb_ofile_t *smb_ofile_lookup_by_fid(smb_tree_t *tree, uint16_t fid);
smb_ofile_t *smb_ofile_open(smb_tree_t *tree, smb_node_t *node, uint16_t pid,
    uint32_t access_granted, uint32_t create_options, uint32_t share_access,
    uint16_t ftype, char *pipe_name, uint32_t rpc_fid, uint32_t uniqid,
    smb_error_t *err);
int smb_ofile_close(smb_ofile_t *ofile, uint32_t last_wtime);
uint32_t smb_ofile_access(smb_ofile_t *ofile, cred_t *cr, uint32_t access);
int smb_ofile_seek(smb_ofile_t *of, ushort_t mode, int32_t off,
    uint32_t *retoff);
void smb_ofile_release(smb_ofile_t *ofile);
void smb_ofile_close_all(smb_tree_t *tree);
void smb_ofile_close_all_by_pid(smb_tree_t *tree, uint16_t pid);
void smb_ofile_set_flags(smb_ofile_t *of, uint32_t flags);
void smb_ofile_close_timestamp_update(smb_ofile_t *of, uint32_t last_wtime);
boolean_t smb_ofile_is_open(smb_ofile_t *of);
#define	smb_ofile_granted_access(_of_)	((_of_)->f_granted_access)

/*
 * odir functions (file smb_odir.c)
 */
smb_odir_t *smb_odir_open(smb_tree_t *tree, smb_node_t *node, char *pattern,
    uint16_t pid, unsigned short sattr);
void smb_odir_close(smb_odir_t *od);
void smb_odir_close_all(smb_tree_t *tree);
void smb_odir_close_all_by_pid(smb_tree_t *tree, uint16_t pid);
void smb_odir_release(smb_odir_t *od);
smb_odir_t *smb_odir_lookup_by_sid(smb_tree_t *tree, uint16_t sid);

/*
 * SMB user functions (file smb_user.c)
 */
smb_user_t *smb_user_login(smb_session_t *, cred_t *,
    char *, char *, uint32_t, uint32_t, uint32_t);
smb_user_t *smb_user_dup(smb_user_t *);
void smb_user_logoff(smb_user_t *user);
void smb_user_logoff_all(smb_session_t *session);
smb_user_t *smb_user_lookup_by_uid(smb_session_t *, cred_t **, uint16_t);
smb_user_t *smb_user_lookup_by_name(smb_session_t *, char *, char *);
smb_user_t *smb_user_lookup_by_state(smb_session_t *, smb_user_t *user);
void smb_user_disconnect_share(smb_user_t *user, char *sharename);
void smb_user_disconnect_volume(smb_user_t *user, fs_desc_t *fsd);
void smb_user_release(smb_user_t *user);

/*
 * SMB tree functions (file smb_tree.c)
 */
smb_tree_t *smb_tree_connect(smb_user_t *user, uint16_t access_flags,
    char *sharename, char *resource, int32_t rt_share,
    smb_node_t *snode, fsvol_attr_t *vol_attr);
void smb_tree_disconnect(smb_tree_t *tree);
void smb_tree_disconnect_all(smb_user_t *user);
void smb_tree_close_all_by_pid(smb_user_t *user, uint16_t pid);
smb_tree_t *smb_tree_lookup_by_tid(smb_user_t *user, uint16_t tid);
smb_tree_t *smb_tree_lookup_by_name(smb_user_t *, char *, smb_tree_t *);
smb_tree_t *smb_tree_lookup_by_fsd(smb_user_t *, fs_desc_t *, smb_tree_t *);
void smb_tree_release(smb_tree_t *tree);

uint32_t smb_user_get_num(void);
void smb_dr_user_free(smb_dr_user_ctx_t *uinfo);
void smb_dr_ulist_free(smb_dr_ulist_t *ulist);
int smb_dr_ulist_get(int offset, smb_dr_ulist_t *dr_ulist);

/*
 * SMB user's credential functions
 */
cred_t *smb_cred_create(smb_token_t *, uint32_t *);
void smb_cred_rele(cred_t *cr);
int smb_cred_is_member(cred_t *cr, nt_sid_t *sid);

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

void smb_winpipe_init(void);
void smb_winpipe_fini(void);
int smb_winpipe_open(int door_id);
void smb_winpipe_close(void);
int smb_winpipe_call(smb_request_t *, mlsvc_pipe_t *, mlsvc_stream_t *,
    uint16_t, uint32_t *, boolean_t *);

void smb_reconnection_check(struct smb_session *session);

uint32_t nt_to_unix_time(uint64_t nt_time, timestruc_t *unix_time);
uint64_t unix_to_nt_time(timestruc_t *);

int netbios_name_isvalid(char *in, char *out);

size_t
unicodestooems(char *oemstring, const mts_wchar_t *unicodestring,
    size_t nbytes, unsigned int cpid);

size_t oemstounicodes(mts_wchar_t *unicodestring, const char *oemstring,
    size_t nwchars, unsigned int cpid);

int uioxfer(struct uio *src_uio, struct uio *dst_uio, int n);

int smb_match_name(ino64_t fileid, char *name, char *shortname,
    char *name83, char *pattern, int ignore_case);
int is_dot_or_dotdot(char *name);
int token2buf(smb_token_t *token, char *buf);

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
void	smb_llist_constructor(smb_llist_t *, size_t, size_t);
void	smb_llist_destructor(smb_llist_t *);
void	smb_llist_insert_head(smb_llist_t *ll, void *obj);
void	smb_llist_insert_tail(smb_llist_t *ll, void *obj);
void	smb_llist_remove(smb_llist_t *ll, void *obj);
int	smb_llist_upgrade(smb_llist_t *ll);
uint32_t smb_llist_get_count(smb_llist_t *ll);
#define	smb_llist_enter(ll, mode)	rw_enter(&(ll)->ll_lock, mode)
#define	smb_llist_exit(ll)		rw_exit(&(ll)->ll_lock)
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

void	smb_thread_init(smb_thread_t *, char *, smb_thread_ep_t, void *,
    smb_thread_aw_t, void *);
void	smb_thread_destroy(smb_thread_t *);
int	smb_thread_start(smb_thread_t *);
void	smb_thread_stop(smb_thread_t *);
void    smb_thread_signal(smb_thread_t *);
boolean_t smb_thread_continue(smb_thread_t *);
boolean_t smb_thread_continue_nowait(smb_thread_t *);
boolean_t smb_thread_continue_timedwait(smb_thread_t *, int /* seconds */);
void smb_thread_set_awaken(smb_thread_t *, smb_thread_aw_t, void *);

uint32_t smb_denymode_to_sharemode(uint32_t desired_access, char *fname);
uint32_t smb_ofun_to_crdisposition(uint16_t ofun);

void    smb_audit_buf_node_create(smb_node_t *node);
void    smb_audit_buf_node_destroy(smb_node_t *node);
#define	smb_audit_node(_n_)					\
	if ((_n_)->n_audit_buf) {				\
		smb_audit_record_node_t	*anr;			\
								\
		anr = (_n_)->n_audit_buf->anb_records;		\
		anr += (_n_)->n_audit_buf->anb_index;		\
		(_n_)->n_audit_buf->anb_index++;		\
		(_n_)->n_audit_buf->anb_index &=		\
		    (_n_)->n_audit_buf->anb_max_index;		\
		anr->anr_refcnt = node->n_refcnt;		\
		anr->anr_depth = getpcstack(anr->anr_stack,	\
		    SMB_AUDIT_STACK_DEPTH);			\
	}

/* 100's of ns between 1/1/1970 and 1/1/1601 */
#define	NT_TIME_BIAS	(134774LL * 24LL * 60LL * 60LL * 10000000LL)

void smb_sd_init(smb_sd_t *, uint8_t);
void smb_sd_term(smb_sd_t *);
uint32_t smb_sd_get_secinfo(smb_sd_t *);
uint32_t smb_sd_len(smb_sd_t *, uint32_t);
uint32_t smb_sd_tofs(smb_sd_t *, smb_fssd_t *);
uint32_t smb_sd_read(smb_request_t *, smb_sd_t *, uint32_t);
uint32_t smb_sd_write(smb_request_t *, smb_sd_t *, uint32_t);

void smb_fssd_init(smb_fssd_t *, uint32_t, uint32_t);
void smb_fssd_term(smb_fssd_t *);

void smb_acl_sort(smb_acl_t *);
void smb_acl_free(smb_acl_t *);
smb_acl_t *smb_acl_alloc(uint8_t, uint16_t, uint16_t);
smb_acl_t *smb_acl_from_zfs(acl_t *, uid_t, gid_t);
uint32_t smb_acl_to_zfs(smb_acl_t *, uint32_t, int, acl_t **);
uint16_t smb_acl_len(smb_acl_t *);
boolean_t smb_acl_isvalid(smb_acl_t *, int);

void smb_fsacl_free(acl_t *);
acl_t *smb_fsacl_alloc(int, int);
acl_t *smb_fsacl_inherit(acl_t *, int, int, uid_t);
acl_t *smb_fsacl_merge(acl_t *, acl_t *);
void smb_fsacl_split(acl_t *, acl_t **, acl_t **, int);
acl_t *smb_fsacl_from_vsa(vsecattr_t *, acl_type_t);
int smb_fsacl_to_vsa(acl_t *, vsecattr_t *, int *);

boolean_t smb_ace_is_generic(int);
boolean_t smb_ace_is_access(int);
boolean_t smb_ace_is_audit(int);

#ifdef	__cplusplus
}
#endif

#endif /* _SMB_KPROTO_H_ */
