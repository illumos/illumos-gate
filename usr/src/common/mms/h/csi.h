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


#ifndef _CSI_
#define	_CSI_
#ifndef _CL_QM_DEFS_
#include "cl_qm_defs.h"
#endif

#ifndef _ACSLM_
#include "acslm.h"
#endif

#ifndef _CSI_MSG_
#include "csi_msg.h"
#endif

#ifndef _CSI_STRUCTS_
#include "csi_structs.h"
#endif

#ifndef _CSI_V1_STRUCTS_
#include "csi_v1_structs.h"
#endif

#ifndef _CSI_V2_STRUCTS_
#include "csi_v2_structs.h"
#endif

#ifdef ADI
#define	 CSI_LOG_NAME    "OSLAN"
#else
#define	 CSI_LOG_NAME    "ONC RPC"
#endif

#ifndef INETSOCKETS
#define	CSI_INPUT_SOCKET "./to_CSI"
#define	CSI_ACSLM_SOCKET "./to_ACSLM"
#else
#define	CSI_INPUT_SOCKET ANY_PORT
#define	CSI_ACSLM_SOCKET ACSLM
#endif

typedef void (*CSI_VOIDFUNC)(CSI_HEADER *cs_hdrp, char *stringp, int maxsize);

#define	CSI_XDR_TRACE_LEVEL		5
#define	CSI_DEF_CONNECTQ_AGETIME 172800
#define	CSI_MIN_CONNECTQ_AGETIME 600
#define	CSI_MAX_CONNECTQ_AGETIME 31536000
#define	CSI_SELECT_TIMEOUT		2
#define	CSI_DEF_RETRY_TIMEOUT		3
#define	CSI_DEF_RETRY_TRIES		5
#define	CSI_HOSTNAMESIZE		128
#define	CSI_NO_CALLEE   (NULL *)char

#define	CSI_NO_LOGFUNCTION (CSI_VOIDFUNC) NULL
#define	CSI_NO_SSI_IDENTIFIER		0
#define	CSI_ISFINALRESPONSE(opt) (0 == (INTERMEDIATE & opt) && \
	0 == (ACKNOWLEDGE & opt) ? TRUE : FALSE)
#define	CSI_MAX_MESSAGE_SIZE		MAX_MESSAGE_SIZE


#define	CSI_TO_ACSLM		0
#define	CSI_FROM_ACSLM		1

#define	CSI_TO_ACSPD		2
#define	CSI_FROM_ACSPD		3
#define	CSI_NAME_SIZE		16

#define	CSI_DGRAM_SIZE		1495
#define	ADI_HANDSHAKE_TIMEOUT		30


#define	CSI_PROGRAM1		0x200000fe
#define	CSI_PROGRAM		0x000493ff
#define	CSI_UDP_VERSION		1
#define	CSI_TCP_VERSION		2
#define	CSI_ACSLM_PROC		1000
#define	CSI_ACSPD_PROC		1001
#define	CSI_DEF_TCPSENDBUF		0
#define	CSI_DEF_TCPRECVBUF		0

typedef enum {
	CSI_NORMAL_SEND,
	CSI_FLUSH_OUTPUT_QUEUE
} CSI_NET_SEND_OPTIONS;


#define	CSI_HOSTNAME	"CSI_HOSTNAME"


#define	CSI_SSI_ACSLM_CALLBACK_PROCEDURE "SSI_ACSLM_CALLBACK_PROCEDURE"
#define	CSI_SSI_ACSPD_CALLBACK_PROCEDURE "SSI_ACSPD_CALLBACK_PROCEDURE"
#define	CSI_SSI_CALLBACK_VERSION_NUMBER  "SSI_CALLBACK_VERSION_NUMBER"
#define	CSI_HAVENT_GOTTEN_ENVIRONMENT_YET (long)-2
#define	CSI_NOT_IN_ENVIRONMENT		(long)-1


#define	CSI_MAXMEMB_LM_QUEUE		0
#define	CSI_MAXMEMB_NI_OUT_QUEUE		0
#define	CSI_MAXQUEUES		2
#define	CSI_CONNECTQ_NAME "connection queue"
#define	CSI_NI_OUTQ_NAME  "network output queue"
#define	CSI_QCB_REMARKS   "master control block"

#define	CSI_PAK_NETOFFSET	(sizeof (CSI_HEADER) > sizeof (IPC_HEADER))\
	? 0 : sizeof (IPC_HEADER) - sizeof (CSI_HEADER)
#define	CSI_PAK_IPCOFFSET	(sizeof (CSI_HEADER) > sizeof (IPC_HEADER))\
	? sizeof (CSI_HEADER) - sizeof (IPC_HEADER) : 0
#define	CSI_PAK_LMOFFSET		CSI_PAK_IPCOFFSET
#define	CSI_PAK_NETDATAP(bufp)  ((char *)(bufp)->data) + \
	((char *)CSI_PAK_NETOFFSET)
#define	CSI_PAK_IPCDATAP(bufp)  ((char *)(bufp)->data) + \
	((char *)CSI_PAK_IPCOFFSET)
#define	CSI_PAK_LMDATAP(bufp)   CSI_PAK_IPCDATAP(bufp)

typedef enum {
	CSI_PAKSTAT_INITIAL = 0,
	CSI_PAKSTAT_XLATE_COMPLETED,
	CSI_PAKSTAT_XLATE_ERROR,
	CSI_PAKSTAT_DUPLICATE_PACKET
} CSI_PAKSTAT;

typedef struct csi_q_mgmt {
	unsigned short		xmit_tries;
} CSI_Q_MGMT;

typedef struct {
	int		offset;
	int		size;
	int		maxsize;
	int		translated_size;
	CSI_PAKSTAT		packet_status;
	CSI_Q_MGMT		q_mgmt;
	TYPE		service_type;
	ALIGNED_BYTES data[1];
} CSI_MSGBUF;

#define	CSI_MSGBUF_MAXSIZE	(sizeof (CSI_MSGBUF) + CSI_MAX_MESSAGE_SIZE)

#define	CSI_INTERNET_ADDR_TO_STRING(strbuf, netaddr) \
	sprintf(strbuf, "%u.%u.%u.%u",           \
	(long)((netaddr & 0xff000000)	>> 24), \
	(long)((netaddr & 0xff0000)	>> 16), \
	(long)((netaddr & 0xff00)	>> 8),  \
	(long)(netaddr & 0xff))

#ifdef DEBUG
#define	CSI_DEBUG_LOG_NETQ_PACK(csi_request_headerp, action_str, status)    \
{                                                                             \
	CSI_REQUEST_HEADER *rp = csi_request_headerp;                         \
	char		*typ;                                                 \
	char		*actionp = action_str;                                \
	STATUS		ecode = status;                                       \
	if (rp->message_header.message_options & ACKNOWLEDGE)                 \
	typ = "ACKNOWLEDGE";                                                  \
	else if (rp->message_header.message_options & INTERMEDIATE)           \
	typ = "INTERMEDIATE";                                                 \
	else                                                                  \
	typ = "FINAL, or REQUEST";                                            \
	MLOGCSI((ecode, st_module, CSI_NO_CALLEE, MMSG(1191, 		      \
	"%s\ncommand:%s\ntype:%s\nsequence#:%d\nssi identifier:%d"),	      \
	actionp, cl_command(rp->message_header.command),                      \
	typ, rp->csi_header.xid.seq_num, rp->csi_header.ssi_identifier));     \
}
#else
#define	CSI_DEBUG_LOG_NETQ_PACK(csi_request_headerp, action_str, status)
#endif
typedef union {
	CSI_V0_REQUEST_HEADER		csi_req_header;
	CSI_V0_AUDIT_REQUEST		csi_audit_req;
	CSI_V0_ENTER_REQUEST		csi_enter_req;
	CSI_V0_EJECT_REQUEST		csi_eject_req;
	CSI_V0_VARY_REQUEST		csi_vary_req;
	CSI_V0_MOUNT_REQUEST		csi_mount_req;
	CSI_V0_DISMOUNT_REQUEST		csi_dismount_req;
	CSI_V0_QUERY_REQUEST		csi_query_req;
	CSI_V0_CANCEL_REQUEST		csi_cancel_req;
	CSI_V0_START_REQUEST		csi_start_req;
	CSI_V0_IDLE_REQUEST		csi_idle_req;
} CSI_V0_REQUEST;

typedef union {
	CSI_V0_REQUEST_HEADER		csi_req_header;
	CSI_V0_ACKNOWLEDGE_RESPONSE		csi_ack_res;
	CSI_V0_AUDIT_RESPONSE		csi_audit_res;
	CSI_V0_ENTER_RESPONSE		csi_enter_res;
	CSI_V0_EJECT_RESPONSE		csi_eject_res;
	CSI_V0_VARY_RESPONSE		csi_vary_res;
	CSI_V0_MOUNT_RESPONSE		csi_mount_res;
	CSI_V0_DISMOUNT_RESPONSE		csi_dismount_res;
	CSI_V0_QUERY_RESPONSE		csi_query_res;
	CSI_V0_CANCEL_RESPONSE		csi_cancel_res;
	CSI_V0_START_RESPONSE		csi_start_res;
	CSI_V0_IDLE_RESPONSE		csi_idle_res;
	CSI_V0_EJECT_ENTER		csi_eject_enter_res;
} CSI_V0_RESPONSE;


typedef union {
	CSI_V1_REQUEST_HEADER		csi_req_header;
	CSI_V1_AUDIT_REQUEST		csi_audit_req;
	CSI_V1_ENTER_REQUEST		csi_enter_req;
	CSI_V1_EJECT_REQUEST		csi_eject_req;
	CSI_V1_EXT_EJECT_REQUEST		csi_xeject_req;
	CSI_V1_VARY_REQUEST		csi_vary_req;
	CSI_V1_MOUNT_REQUEST		csi_mount_req;
	CSI_V1_DISMOUNT_REQUEST		csi_dismount_req;
	CSI_V1_QUERY_REQUEST		csi_query_req;
	CSI_V1_CANCEL_REQUEST		csi_cancel_req;
	CSI_V1_START_REQUEST		csi_start_req;
	CSI_V1_IDLE_REQUEST		csi_idle_req;
	CSI_V1_SET_CLEAN_REQUEST		csi_set_clean_req;
	CSI_V1_SET_CAP_REQUEST		csi_set_cap_req;
	CSI_V1_SET_SCRATCH_REQUEST		csi_set_scratch_req;
	CSI_V1_DEFINE_POOL_REQUEST		csi_define_pool_req;
	CSI_V1_DELETE_POOL_REQUEST		csi_delete_pool_req;
	CSI_V1_MOUNT_SCRATCH_REQUEST		csi_mount_scratch_req;
	CSI_V1_LOCK_REQUEST		csi_lock_req;
	CSI_V1_CLEAR_LOCK_REQUEST		csi_clear_lock_req;
	CSI_V1_QUERY_LOCK_REQUEST		csi_query_lock_req;
	CSI_V1_UNLOCK_REQUEST		csi_unlock_req;
	CSI_V1_VENTER_REQUEST		csi_venter_req;
} CSI_V1_REQUEST;

typedef union {
	CSI_V1_REQUEST_HEADER		csi_req_header;
	CSI_V1_ACKNOWLEDGE_RESPONSE		csi_ack_res;
	CSI_V1_AUDIT_RESPONSE		csi_audit_res;
	CSI_V1_ENTER_RESPONSE		csi_enter_res;
	CSI_V1_EJECT_RESPONSE		csi_eject_res;
	CSI_V1_VARY_RESPONSE		csi_vary_res;
	CSI_V1_MOUNT_RESPONSE		csi_mount_res;
	CSI_V1_DISMOUNT_RESPONSE		csi_dismount_res;
	CSI_V1_QUERY_RESPONSE		csi_query_res;
	CSI_V1_CANCEL_RESPONSE		csi_cancel_res;
	CSI_V1_START_RESPONSE		csi_start_res;
	CSI_V1_IDLE_RESPONSE		csi_idle_res;
	CSI_V1_EJECT_ENTER		csi_eject_enter_res;
	CSI_V1_SET_CLEAN_RESPONSE		csi_set_clean_res;
	CSI_V1_SET_CAP_RESPONSE		csi_set_cap_res;
	CSI_V1_SET_SCRATCH_RESPONSE		csi_set_scratch_res;
	CSI_V1_DEFINE_POOL_RESPONSE		csi_define_pool_res;
	CSI_V1_DELETE_POOL_RESPONSE		csi_delete_pool_res;
	CSI_V1_MOUNT_SCRATCH_RESPONSE		csi_mount_scratch_res;
	CSI_V1_LOCK_RESPONSE		csi_lock_res;
	CSI_V1_CLEAR_LOCK_RESPONSE		csi_clear_lock_res;
	CSI_V1_QUERY_LOCK_RESPONSE		csi_query_lock_res;
	CSI_V1_UNLOCK_RESPONSE		csi_unlock_res;
} CSI_V1_RESPONSE;


typedef union {
	CSI_V2_REQUEST_HEADER		csi_req_header;
	CSI_V2_AUDIT_REQUEST		csi_audit_req;
	CSI_V2_ENTER_REQUEST		csi_enter_req;
	CSI_V2_EJECT_REQUEST		csi_eject_req;
	CSI_V2_EXT_EJECT_REQUEST		csi_xeject_req;
	CSI_V2_VARY_REQUEST		csi_vary_req;
	CSI_V2_MOUNT_REQUEST		csi_mount_req;
	CSI_V2_DISMOUNT_REQUEST		csi_dismount_req;
	CSI_V2_QUERY_REQUEST		csi_query_req;
	CSI_V2_CANCEL_REQUEST		csi_cancel_req;
	CSI_V2_START_REQUEST		csi_start_req;
	CSI_V2_IDLE_REQUEST		csi_idle_req;
	CSI_V2_SET_CLEAN_REQUEST		csi_set_clean_req;
	CSI_V2_SET_CAP_REQUEST		csi_set_cap_req;
	CSI_V2_SET_SCRATCH_REQUEST		csi_set_scratch_req;
	CSI_V2_DEFINE_POOL_REQUEST		csi_define_pool_req;
	CSI_V2_DELETE_POOL_REQUEST		csi_delete_pool_req;
	CSI_V2_MOUNT_SCRATCH_REQUEST		csi_mount_scratch_req;
	CSI_V2_LOCK_REQUEST		csi_lock_req;
	CSI_V2_CLEAR_LOCK_REQUEST		csi_clear_lock_req;
	CSI_V2_QUERY_LOCK_REQUEST		csi_query_lock_req;
	CSI_V2_UNLOCK_REQUEST		csi_unlock_req;
	CSI_V2_VENTER_REQUEST		csi_venter_req;
} CSI_V2_REQUEST;

typedef union {
	CSI_V2_REQUEST_HEADER		csi_req_header;
	CSI_V2_ACKNOWLEDGE_RESPONSE		csi_ack_res;
	CSI_V2_AUDIT_RESPONSE		csi_audit_res;
	CSI_V2_ENTER_RESPONSE		csi_enter_res;
	CSI_V2_EJECT_RESPONSE		csi_eject_res;
	CSI_V2_VARY_RESPONSE		csi_vary_res;
	CSI_V2_MOUNT_RESPONSE		csi_mount_res;
	CSI_V2_DISMOUNT_RESPONSE		csi_dismount_res;
	CSI_V2_QUERY_RESPONSE		csi_query_res;
	CSI_V2_CANCEL_RESPONSE		csi_cancel_res;
	CSI_V2_START_RESPONSE		csi_start_res;
	CSI_V2_IDLE_RESPONSE		csi_idle_res;
	CSI_V2_EJECT_ENTER		csi_eject_enter_res;
	CSI_V2_SET_CLEAN_RESPONSE		csi_set_clean_res;
	CSI_V2_SET_CAP_RESPONSE		csi_set_cap_res;
	CSI_V2_SET_SCRATCH_RESPONSE		csi_set_scratch_res;
	CSI_V2_DEFINE_POOL_RESPONSE		csi_define_pool_res;
	CSI_V2_DELETE_POOL_RESPONSE		csi_delete_pool_res;
	CSI_V2_MOUNT_SCRATCH_RESPONSE csi_mount_scratch_res;
	CSI_V2_LOCK_RESPONSE		csi_lock_res;
	CSI_V2_CLEAR_LOCK_RESPONSE		csi_clear_lock_res;
	CSI_V2_QUERY_LOCK_RESPONSE		csi_query_lock_res;
	CSI_V2_UNLOCK_RESPONSE		csi_unlock_res;
} CSI_V2_RESPONSE;

typedef union {
	CSI_REQUEST_HEADER		csi_req_header;
	CSI_AUDIT_REQUEST		csi_audit_req;
	CSI_ENTER_REQUEST		csi_enter_req;
	CSI_EJECT_REQUEST		csi_eject_req;
	CSI_EXT_EJECT_REQUEST		csi_xeject_req;
	CSI_VARY_REQUEST		csi_vary_req;
	CSI_MOUNT_REQUEST		csi_mount_req;
	CSI_DISMOUNT_REQUEST		csi_dismount_req;
	CSI_QUERY_REQUEST		csi_query_req;
	CSI_CANCEL_REQUEST		csi_cancel_req;
	CSI_START_REQUEST		csi_start_req;
	CSI_IDLE_REQUEST		csi_idle_req;
	CSI_SET_CLEAN_REQUEST		csi_set_clean_req;
	CSI_SET_CAP_REQUEST		csi_set_cap_req;
	CSI_SET_SCRATCH_REQUEST		csi_set_scratch_req;
	CSI_DEFINE_POOL_REQUEST		csi_define_pool_req;
	CSI_DELETE_POOL_REQUEST		csi_delete_pool_req;
	CSI_MOUNT_SCRATCH_REQUEST		csi_mount_scratch_req;
	CSI_LOCK_REQUEST		csi_lock_req;
	CSI_CLEAR_LOCK_REQUEST		csi_clear_lock_req;
	CSI_QUERY_LOCK_REQUEST		csi_query_lock_req;
	CSI_UNLOCK_REQUEST		csi_unlock_req;
	CSI_VENTER_REQUEST		csi_venter_req;
	CSI_REGISTER_REQUEST		csi_register_req;
	CSI_UNREGISTER_REQUEST		csi_unregister_req;
	CSI_CHECK_REGISTRATION_REQUEST		csi_check_registration_req;
	CSI_DISPLAY_REQUEST		csi_display_req;
	CSI_MOUNT_PINFO_REQUEST		csi_mount_pinfo_req;
} CSI_REQUEST;

typedef union {
	CSI_REQUEST_HEADER		csi_req_header;
	CSI_ACKNOWLEDGE_RESPONSE		csi_ack_res;
	CSI_AUDIT_RESPONSE		csi_audit_res;
	CSI_ENTER_RESPONSE		csi_enter_res;
	CSI_EJECT_RESPONSE		csi_eject_res;
	CSI_VARY_RESPONSE		csi_vary_res;
	CSI_MOUNT_RESPONSE		csi_mount_res;
	CSI_DISMOUNT_RESPONSE		csi_dismount_res;
	CSI_QUERY_RESPONSE		csi_query_res;
	CSI_CANCEL_RESPONSE		csi_cancel_res;
	CSI_START_RESPONSE		csi_start_res;
	CSI_IDLE_RESPONSE		csi_idle_res;
	CSI_EJECT_ENTER		csi_eject_enter_res;
	CSI_SET_CLEAN_RESPONSE		csi_set_clean_res;
	CSI_SET_CAP_RESPONSE		csi_set_cap_res;
	CSI_SET_SCRATCH_RESPONSE		csi_set_scratch_res;
	CSI_DEFINE_POOL_RESPONSE		csi_define_pool_res;
	CSI_DELETE_POOL_RESPONSE		csi_delete_pool_res;
	CSI_MOUNT_SCRATCH_RESPONSE csi_mount_scratch_res;
	CSI_LOCK_RESPONSE		csi_lock_res;
	CSI_CLEAR_LOCK_RESPONSE		csi_clear_lock_res;
	CSI_QUERY_LOCK_RESPONSE		csi_query_lock_res;
	CSI_UNLOCK_RESPONSE		csi_unlock_res;
	CSI_REGISTER_RESPONSE		csi_register_res;
	CSI_UNREGISTER_RESPONSE		csi_unregister_res;
	CSI_CHECK_REGISTRATION_RESPONSE		csi_check_registration_res;
	CSI_DISPLAY_RESPONSE		csi_display_res;
	CSI_MOUNT_PINFO_RESPONSE		csi_mount_pinfo_res;
} CSI_RESPONSE;




extern QM_QID		csi_ni_out_qid;
extern long		csi_lmq_lastcleaned;
extern int		csi_rpc_tcpsock;
extern int		csi_rpc_udpsock;
extern BOOLEAN		csi_udp_rpcsvc;
extern BOOLEAN		csi_tcp_rpcsvc;
extern CSI_MSGBUF *csi_netbufp;
extern SVCXPRT		*csi_udpxprt;
extern SVCXPRT		*csi_tcpxprt;
extern QM_QID		csi_lm_qid;
extern IPC_HEADER		csi_ipc_header;
extern int		csi_retry_tries;
extern char		csi_hostname[];
extern int		csi_pid;
extern int		csi_xexp_size;
extern int		csi_xcur_size;
extern unsigned char csi_netaddr[];
extern int		csi_trace_flag;
extern int		csi_broke_pipe;

extern VERSION		csi_active_xdr_version_branch;

#ifdef ADI
extern int		csi_co_process_pid;
extern unsigned char csi_client_name[];
#endif


extern CSI_HEADER		csi_ssi_rpc_addr;
extern CSI_HEADER		csi_ssi_adi_addr;

extern int		csi_adi_ref;
extern long		csi_ssi_alt_procno_lm;


int 	cl_chk_input(long tmo);
void 	csi_fmtlmq_log(CSI_HEADER *cs_hdrp, char *stringp, int maxsize);
void 	csi_fmtniq_log(CSI_MSGBUF *netbufp, char *stringp, int maxsize);
STATUS	csi_freeqmem(QM_QID queue_id, QM_MID member_id,
	CSI_VOIDFUNC log_fmt_func);
STATUS	csi_getiaddr(caddr_t addrp);
char 	*csi_getmsg(CSI_MSGNO msgno);
STATUS	csi_hostaddr(char *hostname, unsigned char *addrp, int maxlen);
STATUS	csi_init(void);
STATUS	csi_ipcdisp(CSI_MSGBUF *netbufp);
void 	csi_logevent(STATUS status, char *msg, char *caller,
	char *failed_func, char *source_file, int source_line);
STATUS	csi_net_send(CSI_MSGBUF *newpakp, CSI_NET_SEND_OPTIONS options);
STATUS	csi_netbufinit(CSI_MSGBUF **buffer);
void	csi_process(void);
void 	csi_ptrace(register CSI_MSGBUF *msgbufp, unsigned long ssi_id,
	char *netaddr_strp, char *port_strp, char *dir);
STATUS	csi_qclean(QM_QID q_id, unsigned long agetime, CSI_VOIDFUNC log_func);
int 	csi_qcmp(register QM_QID q_id, void *datap, unsigned int size);
STATUS	csi_qget(QM_QID q_id, QM_MID m_id, void **q_datap);
STATUS	csi_qinit(QM_QID *q_id, unsigned short max_members, char *name);
STATUS	csi_qput(QM_QID q_id, void *q_datap, int size, QM_MID *m_id);
STATUS	csi_rpccall(CSI_MSGBUF *netbufp);
void		csi_rpcdisp(struct svc_req *reqp, SVCXPRT *xprtp);
int 	csi_rpcinput(SVCXPRT *xprtp, xdrproc_t inproc, CSI_MSGBUF *inbufp,
	xdrproc_t outproc, CSI_MSGBUF *outbufp,
	xdrproc_t free_rtn);
STATUS	csi_rpctinit(void);
unsigned long csi_rpctransient(unsigned long proto, unsigned long vers,
	int *sockp, struct sockaddr_in *addrp);
STATUS	csi_rpcuinit(void);
void 	csi_shutdown(void);
void 	csi_sighdlr(int sig);
int		csi_ssicmp(CSI_XID *xid1, CSI_XID *xid2);
STATUS	csi_svcinit(void);

void sighdlr(int signum);

bool_t csi_xaccess_id(XDR *xdrsp, ACCESSID *accessidp);
bool_t csi_xacs(XDR *xdrsp, ACS *acsp);
bool_t csi_xcap(XDR *xdrsp, CAP *capp);
bool_t csi_xcap_id(XDR *xdrsp, CAPID *capidp);
bool_t csi_xcap_mode(XDR *xdrsp, CAP_MODE *cap_mode);
bool_t csi_xcell_id(XDR *xdrsp, CELLID *cellidp);
bool_t csi_xcol(XDR *xdrsp, COL *colp);
bool_t csi_xcommand(XDR *xdrsp, COMMAND *comp);
bool_t csi_xcsi_hdr(XDR *xdrsp, CSI_HEADER *csi_hdr);
bool_t csi_xdrive(XDR *xdrsp, DRIVE *drivep);
bool_t csi_xdrive_id(XDR *xdrsp, DRIVEID *driveidp);
bool_t csi_xdrive_type(XDR *xdrsp, DRIVE_TYPE *drive_type);
bool_t csi_xfreecells(XDR *xdrsp, FREECELLS *freecells);
int csi_xidcmp(CSI_XID *xid1, CSI_XID *xid2);
bool_t csi_xidentifier(XDR *xdrsp, IDENTIFIER *identifp, TYPE type);
bool_t csi_xipc_hdr(XDR *xdrsp, IPC_HEADER *ipchp);
bool_t csi_xlm_request(XDR *xdrsp, CSI_MSGBUF *bufferp);
bool_t csi_xlm_response(XDR *xdrsp, CSI_MSGBUF *bufferp);
bool_t csi_xlocation(XDR *xdrsp, LOCATION *locp);
bool_t csi_xlockid(XDR *xdrsp, LOCKID *lockid);
bool_t csi_xlsm(XDR *xdrsp, LSM *lsmp);
bool_t csi_xlsm_id(XDR *xdrsp, LSMID *lsmidp);
bool_t csi_xmedia_type(XDR *xdrsp, MEDIA_TYPE *media_type);
bool_t csi_xmsg_hdr(XDR *xdrsp, MESSAGE_HEADER *msghp);
bool_t csi_xmsg_id(XDR *xdrsp, MESSAGE_ID *msgid);
bool_t csi_xpnl(XDR *xdrsp, PANEL *pnlp);
bool_t csi_xpnl_id(XDR *xdrsp, PANELID *pnlidp);
bool_t csi_xpool(XDR *xdrsp, POOL *pool);
bool_t csi_xpool_id(XDR *xdrsp, POOLID *poolidp);
bool_t csi_xport(XDR *xdrsp, PORT *portp);
bool_t csi_xport_id(XDR *xdrsp, PORTID *portidp);
bool_t csi_xptp_id(XDR *xdrsp, PTPID *ptpidp);
bool_t csi_xqu_response(XDR *xdrsp, CSI_QUERY_RESPONSE *resp);
bool_t csi_xquv0_response(XDR *xdrsp, CSI_V0_QUERY_RESPONSE *resp);
bool_t csi_xreq_hdr(XDR *xdrsp, CSI_REQUEST_HEADER *req_hdr);
bool_t csi_xreqsummary(XDR *xdrsp, REQ_SUMMARY *sump);
bool_t csi_xres_status(XDR *xdrsp, RESPONSE_STATUS *rstatp);
bool_t csi_xrow(XDR *xdrsp, ROW *rowp);
bool_t csi_xsockname(XDR *xdrsp, char *socknamep);
bool_t csi_xspnl_id(XDR *xdrsp, SUBPANELID *spidp);
bool_t csi_xstate(XDR *xdrsp, STATE *state);
bool_t csi_xstatus(XDR *xdrsp, STATUS *status);
bool_t csi_xtype(XDR *xdrsp, TYPE *type);
bool_t csi_xv0_cap_id(XDR *xdrsp, V0_CAPID *capidp);
bool_t csi_xv0_req(XDR *xdrsp, CSI_V0_REQUEST *reqp);
bool_t csi_xv0_res(XDR *xdrsp, CSI_V0_RESPONSE *resp);
bool_t csi_xv0quresponse(XDR *xdrsp, CSI_V0_QUERY_RESPONSE *resp);
bool_t csi_xv1_cap_id(XDR *xdrsp, V1_CAPID *capidp);
bool_t csi_xv1_req(XDR *xdrsp, CSI_V1_REQUEST *reqp);
bool_t csi_xv1_res(XDR *xdrsp, CSI_V1_RESPONSE *resp);
bool_t csi_xv1quresponse(XDR *xdrsp, CSI_V1_QUERY_RESPONSE *resp);
bool_t csi_xv2_req(XDR *xdrsp, CSI_V2_REQUEST *reqp);
bool_t csi_xv2_res(XDR *xdrsp, CSI_V2_RESPONSE *resp);
bool_t csi_xv2quresponse(XDR *xdrsp, CSI_V2_QUERY_RESPONSE *resp);
bool_t csi_xv4_req(XDR *xdrsp, CSI_REQUEST *reqp);
bool_t csi_xv4_res(XDR *xdrsp, CSI_RESPONSE *resp);
bool_t csi_xversion(XDR *xdrsp, VERSION *version);
bool_t csi_xvol_id(XDR *xdrsp, VOLID *volidp);
bool_t csi_xvol_status(XDR *xdrsp, VOLUME_STATUS *vstatp);
bool_t csi_xvolrange(XDR *xdrsp, VOLRANGE *vp);

bool_t csi_xevent_reg_status(XDR *xdrsp,
	EVENT_REGISTER_STATUS *ev_reg_stat_ptr, int *total);
bool_t csi_xevent_rsrc_status(XDR *xdrsp, EVENT_RESOURCE_STATUS *ev_rsrc_stat);
bool_t csi_xevent_vol_status(XDR *xdrsp, EVENT_VOLUME_STATUS *ev_vol_stat_ptr);
bool_t csi_xhand_id(XDR *xdrsp, HANDID *hand_id_ptr);
bool_t csi_xregister_status(XDR *xdrsp, REGISTER_STATUS *reg_stat);
bool_t csi_xresource_data(XDR *xdrsp,
	RESOURCE_DATA *res_dta, RESOURCE_DATA_TYPE dta_type);
bool_t csi_xregistration_id(XDR *xdrsp, REGISTRATION_ID *reg_id_ptr);
bool_t csi_xsense_fsc(XDR *xdrsp, SENSE_FSC *sense_fsc_ptr);
bool_t csi_xsense_hli(XDR *xdrsp, SENSE_HLI *sense_hli);
bool_t csi_xsense_scsi(XDR *xdrsp, SENSE_SCSI *sense_scsi);
bool_t csi_xserial_num(XDR *xdrsp, SERIAL_NUM *serial_num_ptr);
bool_t csi_xxml_data(XDR *xdrsp, DISPLAY_XML_DATA *xml_data_ptr);
bool_t csi_xxgrp_type(XDR *xdrsp, GROUP_TYPE *grptype);
bool_t csi_xevent_drive_status(XDR *xdrsp, EVENT_DRIVE_STATUS *ev_drive_stat);
bool_t csi_xdrive_data(XDR *xdrsp, DRIVE_ACTIVITY_DATA *drive_data);

#endif /* _CSI_ */
