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

#ifndef	_FP_H
#define	_FP_H


#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Debugging, Error reporting, and tracing
 */
#define	FP_LOG_SIZE		1024 * 1024

#define	FP_LEVEL_1		0x00001		/* attach/detach PM CPR */
#define	FP_LEVEL_2		0x00002		/* startup */
#define	FP_LEVEL_3		0x00004		/* state change, discovery */
#define	FP_LEVEL_4		0x00008		/* statec/devc to ULPs */
#define	FP_LEVEL_5		0x00010		/* FCA UB callbacks */
#define	FP_LEVEL_6		0x00020		/* Name Server */
#define	FP_LEVEL_7		0x00040		/* RSCN */
#define	FP_LEVEL_8		0x00080		/* I/O tracing */
#define	FP_LEVEL_9		0x00100		/* Failure messages */


/*
 * Log contents to system messages file
 */
#define	FP_MSG_LEVEL_1		(FP_LEVEL_1 | FC_TRACE_LOG_MSG)
#define	FP_MSG_LEVEL_2		(FP_LEVEL_2 | FC_TRACE_LOG_MSG)
#define	FP_MSG_LEVEL_3		(FP_LEVEL_3 | FC_TRACE_LOG_MSG)
#define	FP_MSG_LEVEL_4		(FP_LEVEL_4 | FC_TRACE_LOG_MSG)
#define	FP_MSG_LEVEL_5		(FP_LEVEL_5 | FC_TRACE_LOG_MSG)
#define	FP_MSG_LEVEL_6		(FP_LEVEL_6 | FC_TRACE_LOG_MSG)
#define	FP_MSG_LEVEL_7		(FP_LEVEL_7 | FC_TRACE_LOG_MSG)
#define	FP_MSG_LEVEL_8		(FP_LEVEL_8 | FC_TRACE_LOG_MSG)
#define	FP_MSG_LEVEL_9		(FP_LEVEL_9 | FC_TRACE_LOG_MSG)


/*
 * Log contents to trace buffer
 */
#define	FP_BUF_LEVEL_1		(FP_LEVEL_1 | FC_TRACE_LOG_BUF)
#define	FP_BUF_LEVEL_2		(FP_LEVEL_2 | FC_TRACE_LOG_BUF)
#define	FP_BUF_LEVEL_3		(FP_LEVEL_3 | FC_TRACE_LOG_BUF)
#define	FP_BUF_LEVEL_4		(FP_LEVEL_4 | FC_TRACE_LOG_BUF)
#define	FP_BUF_LEVEL_5		(FP_LEVEL_5 | FC_TRACE_LOG_BUF)
#define	FP_BUF_LEVEL_6		(FP_LEVEL_6 | FC_TRACE_LOG_BUF)
#define	FP_BUF_LEVEL_7		(FP_LEVEL_7 | FC_TRACE_LOG_BUF)
#define	FP_BUF_LEVEL_8		(FP_LEVEL_8 | FC_TRACE_LOG_BUF)
#define	FP_BUF_LEVEL_9		(FP_LEVEL_9 | FC_TRACE_LOG_BUF)


/*
 * Log contents to both system messages file and trace buffer
 */
#define	FP_MSG_BUF_LEVEL_1	(FP_LEVEL_1 | FC_TRACE_LOG_BUF |\
				FC_TRACE_LOG_MSG)
#define	FP_MSG_BUF_LEVEL_2	(FP_LEVEL_2 | FC_TRACE_LOG_BUF |\
				FC_TRACE_LOG_MSG)
#define	FP_MSG_BUF_LEVEL_3	(FP_LEVEL_3 | FC_TRACE_LOG_BUF |\
				FC_TRACE_LOG_MSG)
#define	FP_MSG_BUF_LEVEL_4	(FP_LEVEL_4 | FC_TRACE_LOG_BUF |\
				FC_TRACE_LOG_MSG)
#define	FP_MSG_BUF_LEVEL_5	(FP_LEVEL_5 | FC_TRACE_LOG_BUF |\
				FC_TRACE_LOG_MSG)
#define	FP_MSG_BUF_LEVEL_6	(FP_LEVEL_6 | FC_TRACE_LOG_BUF |\
				FC_TRACE_LOG_MSG)
#define	FP_MSG_BUF_LEVEL_7	(FP_LEVEL_7 | FC_TRACE_LOG_BUF |\
				FC_TRACE_LOG_MSG)
#define	FP_MSG_BUF_LEVEL_8	(FP_LEVEL_8 | FC_TRACE_LOG_BUF |\
				FC_TRACE_LOG_MSG)
#define	FP_MSG_BUF_LEVEL_9	(FP_LEVEL_9 | FC_TRACE_LOG_BUF |\
				FC_TRACE_LOG_MSG)

/*
 * Log contents to system messages file, console and trace buffer
 */
#define	FP_MSG_BUF_CONSOLE_LEVEL_1	(FP_LEVEL_1 | FC_TRACE_LOG_BUF |\
					FC_TRACE_LOG_MSG | FC_TRACE_LOG_CONSOLE)
#define	FP_MSG_BUF_CONSOLE_LEVEL_2	(FP_LEVEL_2 | FC_TRACE_LOG_BUF |\
					FC_TRACE_LOG_MSG | FC_TRACE_LOG_CONSOLE)
#define	FP_MSG_BUF_CONSOLE_LEVEL_3	(FP_LEVEL_3 | FC_TRACE_LOG_BUF |\
					FC_TRACE_LOG_MSG | FC_TRACE_LOG_CONSOLE)
#define	FP_MSG_BUF_CONSOLE_LEVEL_4	(FP_LEVEL_4 | FC_TRACE_LOG_BUF |\
					FC_TRACE_LOG_MSG | FC_TRACE_LOG_CONSOLE)
#define	FP_MSG_BUF_CONSOLE_LEVEL_5	(FP_LEVEL_5 | FC_TRACE_LOG_BUF |\
					FC_TRACE_LOG_MSG | FC_TRACE_LOG_CONSOLE)
#define	FP_MSG_BUF_CONSOLE_LEVEL_6	(FP_LEVEL_6 | FC_TRACE_LOG_BUF |\
					FC_TRACE_LOG_MSG | FC_TRACE_LOG_CONSOLE)
#define	FP_MSG_BUF_CONSOLE_LEVEL_7	(FP_LEVEL_7 | FC_TRACE_LOG_BUF |\
					FC_TRACE_LOG_MSG | FC_TRACE_LOG_CONSOLE)
#define	FP_MSG_BUF_CONSOLE_LEVEL_8	(FP_LEVEL_8 | FC_TRACE_LOG_BUF |\
					FC_TRACE_LOG_MSG | FC_TRACE_LOG_CONSOLE)
#define	FP_MSG_BUF_CONSOLE_LEVEL_9	(FP_LEVEL_9 | FC_TRACE_LOG_BUF |\
					FC_TRACE_LOG_MSG | FC_TRACE_LOG_CONSOLE)
#ifdef DEBUG

#define	FP_DTRACE		fc_trace_debug

#else

#define	FP_DTRACE

#endif

#define	FP_TRACE		fc_trace_debug


#ifdef	DEBUG

#define	FP_TRACE_DEFAULT 	(FC_TRACE_LOG_MASK | FP_LEVEL_1 |\
				FP_LEVEL_2 | FP_LEVEL_3 |\
				FP_LEVEL_4 | FP_LEVEL_5 |\
				FP_LEVEL_6 | FP_LEVEL_7 | FP_LEVEL_9)

#else

#define	FP_TRACE_DEFAULT 	(FC_TRACE_LOG_MASK | FP_LEVEL_1 |\
				FP_LEVEL_2 | FP_LEVEL_3 |\
				FP_LEVEL_4 | FP_LEVEL_5 |\
				FP_LEVEL_6 | FP_LEVEL_7 | FP_LEVEL_9)
#endif

#define	FP_THEAD(x, y, z)	fp_logq, x->fp_ibuf, fp_trace, y, z

#define	FP_NHEAD1(x, y)		FP_THEAD(port, FP_BUF_LEVEL_##x, y)

#define	FP_NHEAD2(x, y)		FP_THEAD(port, FP_MSG_BUF_LEVEL_##x, y)

#define	FP_NHEAD3(x, y)		FP_THEAD(port, FP_MSG_BUF_CONSOLE_LEVEL_##x, y)


/* This is used in about a dozen or so places in fp.c */
#define	FP_IS_PKT_ERROR(pkt)	(((pkt)->pkt_state != FC_PKT_SUCCESS) ||\
				((pkt)->pkt_state == FC_PKT_SUCCESS &&\
				(pkt)->pkt_resp_resid != 0))


/*
 * This is only used in fp_ns_init() and fp_fabric_online().
 */
#define	FP_MAX_DEVICES			255


/*
 * Software restoration bit fields while doing (PM)SUSPEND/(PM)RESUME
 * Used with the fp_restore field in the fc_local_port_t struct.
 */
#define	FP_RESTORE_WAIT_TIMEOUT		0x01
#define	FP_RESTORE_OFFLINE_TIMEOUT	0x02
#define	FP_ELS_TIMEOUT		(20)
#define	FP_NS_TIMEOUT		(120)
#define	FP_IS_F_PORT(p)		((p) & 0x1000)
#define	FP_RETRY_COUNT		(5)
#define	FP_RETRY_DELAY		(3)			/* E_D_TOV + 1 second */
#define	FP_OFFLINE_TICKER	(90)			/* seconds */
#define	FP_DEFAULT_SID		(0x000AE)		/* Used once */
#define	FP_DEFAULT_DID		(0x000EA)		/* Used once */
#define	FP_PORT_IDENTIFIER_LEN	(4)
#define	FP_UNSOL_BUF_COUNT	(20)
#define	FP_UNSOL_BUF_SIZE	(sizeof (la_els_logi_t))
#define	FP_CMDWAIT_DELAY	(240)	/* Enough time for all cmds to complt */


/*
 * Values and macros  used with fp_task and fp_last_task fields in
 * the fc_local_port_t struct. Also see fp_job_handler() for more info.
 */
#define	FP_TASK_IDLE			0
#define	FP_TASK_PORT_STARTUP		1
#define	FP_TASK_OFFLINE			2
#define	FP_TASK_ONLINE			3
#define	FP_TASK_GETMAP			4


/*
 * cmd_flags
 */
#define	FP_CMD_CFLAG_UNDEFINED		(-1)
#define	FP_CMD_PLOGI_DONT_CARE		0x00
#define	FP_CMD_PLOGI_RETAIN		0x01	/* Retain LOGIN */
#define	FP_CMD_DELDEV_ON_ERROR		0x02	/* Remove device on error */

/*
 * cmd_dflags
 */
#define	FP_CMD_VALID_DMA_MEM		0x01
#define	FP_CMD_VALID_DMA_BIND		0x02
#define	FP_RESP_VALID_DMA_MEM		0x04
#define	FP_RESP_VALID_DMA_BIND		0x08


/* Values for fp_flag field in the fc_local_port_t struct */
#define	FP_IDLE		0x00
#define	FP_OPEN		0x01
#define	FP_EXCL		0x02
#define	FP_EXCL_BUSY	0x04	/* Exclusive operation in progress */


/* message block/unblock'ing */
#define	FP_WARNING_MESSAGES		0x01
#define	FP_FATAL_MESSAGES		0x02


#define	FP_IS_CLASS_1_OR_2(x)	\
	((x) == FC_TRAN_CLASS1 || (x) == FC_TRAN_CLASS2)


/*
 * Driver message control
 */
typedef enum fp_mesg_dest {
	FP_CONSOLE_ONLY,
	FP_LOG_ONLY,
	FP_LOG_AND_CONSOLE
} fp_mesg_dest_t;

typedef struct soft_attach {
	fc_attach_cmd_t    	att_cmd;
	struct fc_local_port   	*att_port;
	boolean_t		att_need_pm_idle;
} fp_soft_attach_t;

typedef struct fp_cmd {
	uint16_t	cmd_dflags;		/* DMA flags */
	ksema_t		cmd_sema;
	int		cmd_flags;		/* cmd flags */
	int		cmd_retry_count;
	int		cmd_retry_interval;	/* milli secs */
	fc_packet_t	cmd_pkt;
	fc_local_port_t	*cmd_port;
	opaque_t	cmd_private;
	struct fp_cmd	*cmd_next;
	fc_packet_t	*cmd_ulp_pkt;
	job_request_t	*cmd_job;
	int (*cmd_transport) (opaque_t fca_handle, fc_packet_t *);
} fp_cmd_t;

typedef struct fp_unsol_spec {
	fc_local_port_t	*port;
	fc_unsol_buf_t	*buf;
} fp_unsol_spec_t;


#if	!defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("unique per request", fp_cmd))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", soft_attach))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", fp_unsol_spec))
#endif	/* __lint */

/*
 * Procedure templates.
 */
static int fp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int fp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int fp_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,
    void *arg, void **result);
static int fp_power(dev_info_t *dip, int comp, int level);
static int fp_open(dev_t *devp, int flag, int otype, cred_t *credp);
static int fp_close(dev_t dev, int flag, int otype, cred_t *credp);
static int fp_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *credp, int *rval);
static int fp_attach_handler(dev_info_t *dip);
static int fp_resume_handler(dev_info_t *dip);
static int fp_power_up(fc_local_port_t *port);
static int fp_resume_all(fc_local_port_t *port, fc_attach_cmd_t cmd);
static int fp_detach_handler(fc_local_port_t *port);
static int fp_suspend_handler(fc_local_port_t *port);
static int fp_power_down(fc_local_port_t *port);
static void fp_suspend_all(fc_local_port_t *port);
static int fp_cache_constructor(void *buf, void *cdarg, int kmflags);
static void fp_cache_destructor(void *buf, void *cdarg);
static fp_cmd_t *fp_alloc_pkt(fc_local_port_t *port, int cmd_len,
    int resp_len, int kmflags, fc_remote_port_t *pd);
static void fp_free_pkt(fp_cmd_t *cmd);
static void fp_free_dma(fp_cmd_t *cmd);
static void fp_job_handler(fc_local_port_t *port);
static int fp_port_startup(fc_local_port_t *port, job_request_t *job);
static void fp_startup_done(opaque_t arg, uchar_t result);
static void fp_ulp_port_attach(void *arg);
static int fp_sendcmd(fc_local_port_t *port, fp_cmd_t *cmd,
    opaque_t fca_handle);
static void fp_resendcmd(void *port_handle);
static int fp_retry_cmd(fc_packet_t *pkt);
static void fp_enque_cmd(fc_local_port_t *port, fp_cmd_t *cmd);
static int fp_handle_reject(fc_packet_t *pkt);
static uchar_t fp_get_nextclass(fc_local_port_t *port, uchar_t cur_class);
static int fp_is_class_supported(uint32_t cos, uchar_t tran_class);
static fp_cmd_t *fp_deque_cmd(fc_local_port_t *port);
static void fp_jobwait(job_request_t *job);
int fp_state_to_rval(uchar_t state);
static void fp_iodone(fp_cmd_t *cmd);
static void fp_jobdone(job_request_t *job);
static void fp_port_shutdown(fc_local_port_t *port, job_request_t *job);
static void fp_get_loopmap(fc_local_port_t *port, job_request_t *job);
static void fp_loop_online(fc_local_port_t *port, job_request_t *job,
    int orphan);
static int fp_get_lilpmap(fc_local_port_t *port, fc_lilpmap_t *lilp_map);
static int fp_fabric_login(fc_local_port_t *port, uint32_t s_id,
    job_request_t *job, int flag, int sleep);
static int fp_port_login(fc_local_port_t *port, uint32_t d_id,
    job_request_t *job, int cmd_flag, int sleep, fc_remote_port_t *pd,
    fc_packet_t *ulp_pkt);
static void fp_register_login(ddi_acc_handle_t *handle, fc_remote_port_t *pd,
    la_els_logi_t *acc, uchar_t class);
static void fp_remote_port_offline(fc_remote_port_t *pd);
static void fp_unregister_login(fc_remote_port_t *pd);
static void fp_port_offline(fc_local_port_t *port, int notify);
static void fp_offline_timeout(void *port_handle);
static void fp_els_init(fp_cmd_t *cmd, uint32_t s_id, uint32_t d_id,
    void (*comp) (), job_request_t *job);
static void fp_xlogi_init(fc_local_port_t *port, fp_cmd_t *cmd, uint32_t s_id,
    uint32_t d_id, void (*intr) (), job_request_t *job, uchar_t ls_code);
static void fp_logo_init(fc_remote_port_t *pd, fp_cmd_t *cmd,
    job_request_t *job);
static void fp_adisc_init(fp_cmd_t *cmd, job_request_t *job);
static int fp_ulp_statec_cb(fc_local_port_t *port, uint32_t state,
    fc_portmap_t *changelist, uint32_t listlen, uint32_t alloc_len, int sleep);
static int fp_ulp_devc_cb(fc_local_port_t *port, fc_portmap_t *changelist,
    uint32_t listlen, uint32_t alloc_len, int sleep, int sync);
static void fp_plogi_group(fc_local_port_t *port, job_request_t *job);
static void fp_ns_init(fc_local_port_t *port, job_request_t *job, int sleep);
static void fp_ns_fini(fc_local_port_t *port, job_request_t *job);
static int fp_ns_reg(fc_local_port_t *port, fc_remote_port_t *pd,
    uint16_t cmd_code, job_request_t *job, int polled, int sleep);
static int fp_common_intr(fc_packet_t *pkt, int iodone);
static void fp_flogi_intr(fc_packet_t *pkt);
static void fp_plogi_intr(fc_packet_t *pkt);
static void fp_adisc_intr(fc_packet_t *pkt);
static void fp_logo_intr(fc_packet_t *pkt);
static void fp_rls_intr(fc_packet_t *pkt);
static void fp_rnid_intr(fc_packet_t *pkt);
static int  fp_send_rnid(fc_local_port_t *port, intptr_t data, int mode,
    fcio_t *fcio, la_wwn_t *pwwn);
static int  fp_get_rnid(fc_local_port_t *port, intptr_t data, int mode,
    fcio_t *fcio);
static int  fp_set_rnid(fc_local_port_t *port, intptr_t data, int mode,
    fcio_t *fcio);
static void fp_intr(fc_packet_t *pkt);
static void fp_statec_cb(opaque_t port_handle, uint32_t state);
static int fp_ns_scr(fc_local_port_t *port, job_request_t *job,
    uchar_t scr_func, int sleep);
static int fp_ns_get_devcount(fc_local_port_t *port, job_request_t *job,
    int create, int sleep);
static int fp_fciocmd(fc_local_port_t *port, intptr_t data, int mode,
    fcio_t *fcio);
static int fp_copyout(void *from, void *to, size_t len, int mode);
static int fp_fcio_copyout(fcio_t *fcio, intptr_t data, int mode);
static void fp_p2p_online(fc_local_port_t *port, job_request_t *job);
static int fp_fillout_p2pmap(fc_local_port_t *port, fcio_t *fcio, int mode);
static void fp_fabric_online(fc_local_port_t *port, job_request_t *job);
static int fp_fillout_loopmap(fc_local_port_t *port, fcio_t *fcio, int mode);
static void fp_unsol_intr(fc_packet_t *pkt);
static void fp_linit_intr(fc_packet_t *pkt);
static void fp_unsol_cb(opaque_t port_handle, fc_unsol_buf_t *buf,
    uint32_t type);
static void fp_handle_unsol_buf(fc_local_port_t *port, fc_unsol_buf_t *buf,
    job_request_t *job);
static void fp_ba_rjt_init(fc_local_port_t *port, fp_cmd_t *cmd,
    fc_unsol_buf_t *buf, job_request_t *job);
static void fp_els_rjt_init(fc_local_port_t *port, fp_cmd_t *cmd,
    fc_unsol_buf_t *buf, uchar_t action, uchar_t reason, job_request_t *job);
static void fp_els_acc_init(fc_local_port_t *port, fp_cmd_t *cmd,
    fc_unsol_buf_t *buf, job_request_t *job);
static void fp_handle_unsol_logo(fc_local_port_t *port, fc_unsol_buf_t *buf,
    fc_remote_port_t *pd, job_request_t *job);
static void fp_handle_unsol_prlo(fc_local_port_t *port, fc_unsol_buf_t *buf,
    fc_remote_port_t *pd, job_request_t *job);
static void fp_unsol_resp_init(fc_packet_t *pkt, fc_unsol_buf_t *buf,
    uchar_t r_ctl, uchar_t type);
static void fp_i_handle_unsol_els(fc_local_port_t *port, fc_unsol_buf_t *buf);
static void fp_handle_unsol_plogi(fc_local_port_t *port, fc_unsol_buf_t *buf,
    job_request_t *job, int sleep);
static void fp_handle_unsol_flogi(fc_local_port_t *port, fc_unsol_buf_t *buf,
    job_request_t *job, int sleep);
static void fp_login_acc_init(fc_local_port_t *port, fp_cmd_t *cmd,
    fc_unsol_buf_t *buf, job_request_t *job, int sleep);
static void fp_handle_unsol_rscn(fc_local_port_t *port, fc_unsol_buf_t *buf,
    job_request_t *job, int sleep);
static void fp_fillout_old_map_held(fc_portmap_t *map, fc_remote_port_t *pd,
    uchar_t flag);
static void fp_fillout_old_map(fc_portmap_t *map, fc_remote_port_t *pd,
    uchar_t flag);
static void fp_fillout_changed_map(fc_portmap_t *map, fc_remote_port_t *pd,
    uint32_t *new_did, la_wwn_t *new_pwwn);
static void fp_fillout_new_nsmap(fc_local_port_t *port,
    ddi_acc_handle_t *handle, fc_portmap_t *port_map, ns_resp_gan_t *gan_resp,
    uint32_t d_id);
static int fp_remote_lip(fc_local_port_t *port, la_wwn_t *pwwn, int sleep,
    job_request_t *job);
static void fp_stuff_device_with_gan(ddi_acc_handle_t *handle,
    fc_remote_port_t *pd, ns_resp_gan_t *gan_resp);
static int fp_ns_query(fc_local_port_t *port, fctl_ns_req_t *ns_cmd,
    job_request_t *job, int polled, int sleep);
static void fp_ct_init(fc_local_port_t *port, fp_cmd_t *cmd,
    fctl_ns_req_t *ns_cmd, uint16_t cmd_code, caddr_t cmd_buf,
    uint16_t cmd_len, uint16_t resp_len, job_request_t *job);
static void fp_ns_intr(fc_packet_t *pkt);
static void fp_gan_handler(fc_packet_t *pkt, fctl_ns_req_t *ns_cmd);
static void fp_ns_query_handler(fc_packet_t *pkt, fctl_ns_req_t *ns_cmd);
static void fp_handle_unsol_adisc(fc_local_port_t *port, fc_unsol_buf_t *buf,
    fc_remote_port_t *pd, job_request_t *job);
static void fp_adisc_acc_init(fc_local_port_t *port, fp_cmd_t *cmd,
    fc_unsol_buf_t *buf, job_request_t *job);
static void fp_load_ulp_modules(dev_info_t *dip, fc_local_port_t *port);
static int fp_logout(fc_local_port_t *port, fc_remote_port_t *pd,
    job_request_t *job);
static void fp_attach_ulps(fc_local_port_t *port, fc_attach_cmd_t cmd);
static int fp_ulp_notify(fc_local_port_t *port, uint32_t statec, int sleep);
static int fp_ns_getmap(fc_local_port_t *port, job_request_t *job,
    fc_portmap_t **map, uint32_t *len, uint32_t sid);
static fc_remote_port_t *fp_create_remote_port_by_ns(fc_local_port_t *port,
    uint32_t d_id, int sleep);
static int fp_check_perms(uchar_t open_flag, uint16_t ioctl_cmd);
static int fp_bind_callbacks(fc_local_port_t *port);
static void fp_retrieve_caps(fc_local_port_t *port);
static void fp_validate_area_domain(fc_local_port_t *port, uint32_t id,
    uint32_t mask, job_request_t *job, int sleep);
static void fp_validate_rscn_page(fc_local_port_t *port, fc_affected_id_t *page,
    job_request_t *job, fctl_ns_req_t *ns_cmd, fc_portmap_t *listptr,
    int *listindex, int sleep);
static int fp_ns_validate_device(fc_local_port_t *port, fc_remote_port_t *pd,
    job_request_t *job, int polled, int sleep);
static int fp_validate_lilp_map(fc_lilpmap_t *lilp_map);
static int fp_is_valid_alpa(uchar_t al_pa);
static void fp_ulp_unsol_cb(void *arg);
static void fp_printf(fc_local_port_t *port, int level, fp_mesg_dest_t dest,
    int fc_errno, fc_packet_t *pkt, const char *fmt, ...);
static int fp_fcio_logout(fc_local_port_t *port, fcio_t *fcio,
    job_request_t *job);
static int fp_fcio_login(fc_local_port_t *port, fcio_t *fcio,
    job_request_t *job);

#ifdef	__cplusplus
}
#endif

#endif	/* _FP_H */
