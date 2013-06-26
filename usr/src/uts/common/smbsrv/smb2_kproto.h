/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMB2_KPROTO_H_
#define	_SMB2_KPROTO_H_

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb2.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern uint32_t smb2_tcp_rcvbuf;
extern uint32_t smb2_max_rwsize;
extern uint32_t smb2_max_trans;

void	smb2_dispatch_stats_init(smb_server_t *);
void	smb2_dispatch_stats_fini(smb_server_t *);
void	smb2_dispatch_stats_update(smb_server_t *,
		smb_kstat_req_t *, int, int);

int	smb2sr_newrq(smb_request_t *);
int	smb2sr_newrq_async(smb_request_t *);
int	smb2sr_newrq_cancel(smb_request_t *);
void	smb2sr_work(smb_request_t *);

int smb2_decode_header(smb_request_t *);
int smb2_encode_header(smb_request_t *, boolean_t);
void smb2_send_reply(smb_request_t *);
void smb2sr_put_error(smb_request_t *, uint32_t);
void smb2sr_put_error_data(smb_request_t *, uint32_t, mbuf_chain_t *);
void smb2sr_put_errno(struct smb_request *, int);
uint32_t smb2sr_lookup_fid(smb_request_t *, smb2fid_t *);

/* SMB2 signing routines - smb2_signing.c */
int smb2_sign_check_request(smb_request_t *);
void smb2_sign_reply(smb_request_t *);

uint32_t smb2_fsctl_vneginfo(smb_request_t *, smb_fsctl_t *);

smb_sdrc_t smb2_negotiate(smb_request_t *);
smb_sdrc_t smb2_session_setup(smb_request_t *);
smb_sdrc_t smb2_logoff(smb_request_t *);
smb_sdrc_t smb2_tree_connect(smb_request_t *);
smb_sdrc_t smb2_tree_disconn(smb_request_t *);
smb_sdrc_t smb2_create(smb_request_t *);
smb_sdrc_t smb2_close(smb_request_t *);
smb_sdrc_t smb2_flush(smb_request_t *);
smb_sdrc_t smb2_read(smb_request_t *);
smb_sdrc_t smb2_write(smb_request_t *);
smb_sdrc_t smb2_lock(smb_request_t *);
smb_sdrc_t smb2_ioctl(smb_request_t *);
/* No smb2_cancel() - see smb2_dispatch.c */
smb_sdrc_t smb2_echo(smb_request_t *);
smb_sdrc_t smb2_query_dir(smb_request_t *);
smb_sdrc_t smb2_change_notify(smb_request_t *);
smb_sdrc_t smb2_query_info(smb_request_t *);
smb_sdrc_t smb2_set_info(smb_request_t *);
smb_sdrc_t smb2_oplock_break_ack(smb_request_t *);

int smb2_newrq_negotiate(smb_request_t *);

uint32_t smb2_ofile_getattr(smb_request_t *, smb_ofile_t *, smb_attr_t *);
uint32_t smb2_ofile_getstd(smb_ofile_t *, smb_queryinfo_t *);
uint32_t smb2_ofile_getname(smb_ofile_t *, smb_queryinfo_t *);

uint32_t smb2_qinfo_file(smb_request_t *, smb_queryinfo_t *);
uint32_t smb2_qinfo_fs(smb_request_t *, smb_queryinfo_t *);
uint32_t smb2_qinfo_sec(smb_request_t *, smb_queryinfo_t *);
uint32_t smb2_qinfo_quota(smb_request_t *, smb_queryinfo_t *);
uint32_t smb2_qinfo_stream(smb_request_t *, smb_queryinfo_t *);

uint32_t smb2_setinfo_file(smb_request_t *, smb_setinfo_t *, int);
uint32_t smb2_setinfo_fs(smb_request_t *, smb_setinfo_t *, int);
uint32_t smb2_setinfo_sec(smb_request_t *, smb_setinfo_t *, uint32_t);
uint32_t smb2_setinfo_quota(smb_request_t *, smb_setinfo_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _SMB2_KPROTO_H_ */
