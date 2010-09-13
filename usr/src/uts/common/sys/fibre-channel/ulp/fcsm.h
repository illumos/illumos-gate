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

#ifndef	_FCSM_H
#define	_FCSM_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * Message printing flags
 */
#define	SM_LOG			1
#define	SM_CONSOLE		2
#define	SM_LOG_AND_CONSOLE	3

/*
 * Debug levels
 */
#define	SMDL_TRACE	0x0001
#define	SMDL_IO		0x0002
#define	SMDL_ERR	0x0004
#define	SMDL_INFO	0x0008

#ifdef	DEBUG
#define	FCSM_DEBUG(level, args)	\
	if (fcsm_debug & (level))	fcsm_display args

extern uint32_t fcsm_debug;
#else /* DEBUG */
#define	FCSM_DEBUG(level, args)
#endif /* DEBUG */

#define	FCSM_INIT_INSTANCES	8	/* # of instances for soft_state_init */
/*
 * Open flags
 */
#define	FCSM_IDLE		0x00
#define	FCSM_OPEN		0x01
#define	FCSM_EXCL		0x02

#define	FCSM_ELS_TIMEOUT	(20)	/* secs */
#define	FCSM_MS_TIMEOUT		(20)	/* secs */

#define	FCSM_OFFLINE_TICKER	(120)	/* secs */

/* Definitions for command retries */
#define	FCSM_MAX_CMD_RETRIES	5	/* Max retries in case of failure */
#define	FCSM_RETRY_INTERVAL	3	/* Retry interval in seconds */
#define	FCSM_RETRY_TICKER	1	/* Retry thread execution interval */

#define	FCSM_MAX_JOB_RETRIES	3	/* Max retries in case of job failure */

/*
 * fcsm_job - Job structure to issue commands using command thread
 */
typedef struct fcsm_job {
	uint32_t	job_code;		/* Command code */
	uint32_t	job_flags;		/* Command Flags */
	int		job_port_instance;	/* port driver instance */
	int		job_result;		/* job completion result */
	opaque_t	job_arg;		/* Command Arguments */
	opaque_t	job_caller_priv;	/* Caller private */
	void		(*job_comp)(opaque_t, struct fcsm_job *, int);
						/* completion func */
	opaque_t	job_comp_arg;		/* Arg for completion func */
	kmutex_t	job_mutex;		/* per command mutex */
	ksema_t		job_sema;		/* To wait for completion */
	struct fcsm_job	*job_next;		/* for linked list */
	int		job_retry_count;	/* Retry count */
	void		*job_priv;		/* for fcsm private use	 */
	uint32_t	job_priv_flags;		/* fcsm private flags */
} fcsm_job_t;

/*
 * fcsm_t - FCSM Structure for per port information
 */
typedef struct fcsm {
	kmutex_t		sm_mutex;	/* mutex for protection */
	struct fcsm		*sm_next;	/* for global linked list */
	int			sm_sid;		/* FCA Port ID */
	int			sm_instance;	/* fc port instance number */
	uint32_t		sm_port_state;	/* FCA port state */
	uint32_t		sm_port_top;	/* Port topology */
	uint32_t		sm_state;	/* San Mgmt State information */
	uint32_t		sm_flags;	/* San Mgmt Flags (see below) */
	int			sm_ncmds;	/* # of pending commands */
	int			sm_cb_count;	/* # callbacks in progress */
	fc_ulp_port_info_t	sm_port_info;	/* FCA Port Information */
	fcsm_job_t		*sm_job_head;	/* port's job queue head */
	fcsm_job_t		*sm_job_tail;	/* port's job queue tail */
	struct fcsm_cmd		*sm_retry_head;	/* cmd retry queue head */
	struct fcsm_cmd		*sm_retry_tail;	/* cmd retry queue tail */
	timeout_id_t		sm_retry_tid;	/* retry timer */
	timeout_id_t		sm_offline_tid;	/* offline timer */
	kcondvar_t		sm_job_cv;	/* cv for job processing */
	uint32_t		sm_dev_count;	/* # of devices discovered */
	fc_portmap_t		*sm_portmap;	/* device map */
	kthread_t		*sm_thread;	/* per port job thread */
	kmem_cache_t		*sm_cmd_cache;	/* per port fc packet cache */
	la_els_logi_t		sm_ms_service_params;
						/* Mgmt Server Login Params */
	callb_cpr_t		sm_cpr_info;	/* CPR info */
} fcsm_t;


typedef struct fcsm_cmd {
	fc_packet_t	*cmd_fp_pkt;
	fcsm_job_t	*cmd_job;
	fcsm_t		*cmd_fcsm;
	int		cmd_retry_count;
	int		cmd_retry_interval;
	int		cmd_max_retries;
	struct fcsm_cmd	*cmd_next;
	void		(*cmd_comp)(struct fcsm_cmd *);
	int		(*cmd_transport)(opaque_t, fc_packet_t *);
	uint32_t	cmd_dma_flags;
	fc_packet_t	cmd_fc_packet;
} fcsm_cmd_t;

/*
 * sm_flags in the per port FCSM Structure
 */
#define	FCSM_ATTACHING			0x0001
#define	FCSM_ATTACHED			0x0002
#define	FCSM_DETACHING			0x0004
#define	FCSM_DETACHED			0x0008
#define	FCSM_SUSPENDED			0x0010
#define	FCSM_POWER_DOWN			0x0020
#define	FCSM_RESTORE_RETRY_TIMEOUT	0x0040
#define	FCSM_RESTORE_OFFLINE_TIMEOUT	0x0080
#define	FCSM_RETRY_TIMER_ACTIVE		0x0100
#define	FCSM_SERIALIZE_JOBTHREAD	0x0200
#define	FCSM_CMD_RETRY_Q_SUSPENDED	0x0400
#define	FCSM_PORT_OFFLINE		0x0800
#define	FCSM_LINK_DOWN			0x1000
#define	FCSM_MGMT_SERVER_LOGGED_IN	0x2000
#define	FCSM_MGMT_SERVER_LOGIN_IN_PROG	0x4000
#define	FCSM_USING_NODMA_FCA		0x8000

/* Command flags for Job structure */
#define	FCSM_JOBFLAG_SYNC		0x01
#define	FCSM_JOBFLAG_ASYNC		0x02
#define	FCSM_JOBFLAG_SERIALIZE		0x04
#define	FCSM_JOBFLAG_CTHEADER_BE	0X08

/* Command codes */
#define	FCSM_JOB_NONE			0x00
#define	FCSM_JOB_THREAD_SHUTDOWN	0x01
#define	FCSM_JOB_LOGIN_NAME_SERVER	0x02
#define	FCSM_JOB_LOGIN_MGMT_SERVER	0x03
#define	FCSM_JOB_CT_PASSTHRU		0x04

/* Private flags for command */
#define	FCSM_JOB_PRIV_WAIT_FOR_LOGIN	0x01
#define	FCSM_JOB_PRIV_LOGIN_IN_PROG	0x02

/* Command DMA Flags */
#define	FCSM_CF_CMD_VALID_DMA_MEM	0x01
#define	FCSM_CF_CMD_VALID_DMA_BIND	0x02
#define	FCSM_CF_RESP_VALID_DMA_MEM	0x04
#define	FCSM_CF_RESP_VALID_DMA_BIND	0x08

#define	FCSM_INIT_CMD(cmd, job, tran_flags, tran_type, max_retries, func) { \
	(cmd)->cmd_job = (job); \
	(cmd)->cmd_fc_packet.pkt_tran_flags = (tran_flags); \
	(cmd)->cmd_fc_packet.pkt_tran_type = (tran_type); \
	(cmd)->cmd_max_retries = max_retries; \
	(cmd)->cmd_comp = func; \
}

/*
 * Macros to address endian issues
 * local variable "fcsm" must exist before using these
 */
#define	FCSM_REP_RD(handle, hostaddr, devaddr, cnt)			\
	{								\
		if (!((fcsm)->sm_flags & FCSM_USING_NODMA_FCA)) {	\
			ddi_rep_get8((handle), (uint8_t *)(hostaddr),	\
				    (uint8_t *)(devaddr), (cnt),	\
				    DDI_DEV_AUTOINCR);			\
		} else {						\
			bcopy((devaddr), (hostaddr), (cnt));		\
		}							\
	}

#define	FCSM_REP_WR(handle, hostaddr, devaddr, cnt)			\
	{								\
		if (!((fcsm)->sm_flags & FCSM_USING_NODMA_FCA)) {	\
			ddi_rep_put8((handle), (uint8_t *)(hostaddr),	\
				    (uint8_t *)(devaddr), (cnt),	\
				    DDI_DEV_AUTOINCR);			\
		} else {						\
			bcopy((hostaddr), (devaddr), (cnt));		\
		}							\
	}

#endif /* _KERNEL */

/*
 * IOCTL Definitions
 */
typedef struct fc_ct_aiu {
	fc_ct_header_t	aiu_header;
	char		aiu_payload[1];
	/* aiu_payload can be up to 'm' bytes (arbitrary length) */
} fc_ct_aiu_t;

#define	FCSMIO			('S' << 8)
#define	FCSMIO_CMD		(FCSMIO | 2000)

#define	FCSMIO_SUB_CMD		('Y' << 8)
#define	FCSMIO_CT_CMD		(FCSMIO_SUB_CMD + 0x01)
#define	FCSMIO_ADAPTER_LIST	(FCSMIO_SUB_CMD + 0x02)
#define	FCSMIO_FIND_ADAPTER	(FCSMIO_SUB_CMD + 0x03)

#define	FCSM_MAX_CT_SIZE	(65536)		/* 64K */

/* Management Server - Fabric Configuration Server Commands */
#define	MS_CS_GTIN	0x0100	/* Get Topology Information */
#define	MS_CS_GIEL	0x0101	/* Get Interconnect Element List */
#define	MS_CS_GIET	0x0111	/* Get Interconnect Element Type */
#define	MS_CS_GDID	0x0112	/* Get Domain Identifier */
#define	MS_CS_GMID	0x0113	/* Get Management Identifier */
#define	MS_CS_GFN	0x0114	/* Get Fabric Name */
#define	MS_CS_GIELN	0x0115	/* Get Interconnect Element Logical Name */
#define	MS_CS_GMAL	0x0116	/* Get Management Address List */
#define	MS_CS_GIEIL	0x0117	/* Get Interconnect Element Information List */
#define	MS_CS_GPL	0x0118	/* Get Port List */
#define	MS_CS_GPT	0x0121	/* Get Port Type */
#define	MS_CS_GPPN	0x0122	/* Get Physical Port Number */
#define	MS_CS_GAPNL	0x0124	/* Get Attached Port Name List */
#define	MS_CS_GPS	0x0126	/* Get Port State */
#define	MS_CS_GATIN	0x0128	/* Get Attached Topology Information */
#define	MS_CS_GPLNL	0x0191	/* Get Platform Node Name List */
#define	MS_CS_GPLT	0x0192	/* Get Platform Type */
#define	MS_CS_GPLML	0x0193	/* Get Platform Management Address List */
#define	MS_CS_GNPL	0x01a1	/* Get Platform Name - Node Name */
#define	MS_CS_GPNL	0x01a2	/* Get Platform Name List */
#define	MS_CS_GNID	0x01b1	/* Get Node Identification Data - Node Name */
#define	MS_CS_RIELN	0x0215	/* Register Interconnect Element Logical Name */
#define	MS_CS_RPL	0x0280	/* Register Platform */
#define	MS_CS_RPLN	0x0291	/* Register Platform Name */
#define	MS_CS_RPLT	0x0292	/* Register Platform Type */
#define	MS_CS_RPLM	0x0293	/* Register Platform Management Address */
#define	MS_CS_DPL	0x0380	/* Deregister Platform */
#define	MS_CS_DPLN	0x0391	/* Deregister Platform Node Name */
#define	MS_CS_DPLML	0x0393	/* Deregister Platform Management Addr List */

#ifdef _KERNEL

/*
 * Driver entry point functions
 */
static int	fcsm_attach(dev_info_t *, ddi_attach_cmd_t);
static int	fcsm_detach(dev_info_t *, ddi_detach_cmd_t);
static int	fcsm_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	fcsm_open(dev_t *, int, int, cred_t *);
static int	fcsm_close(dev_t, int, int, cred_t *);
static int	fcsm_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/*
 * FC Transport functions
 */
static int	fcsm_port_attach(opaque_t, fc_ulp_port_info_t *,
		    fc_attach_cmd_t, uint32_t);
static int	fcsm_port_detach(opaque_t, fc_ulp_port_info_t *,
		    fc_detach_cmd_t);
static int	fcsm_port_ioctl(opaque_t, opaque_t, dev_t, int, intptr_t,
		    int, cred_t *, int *, uint32_t);
static void	fcsm_statec_cb(opaque_t, opaque_t, uint32_t, uint32_t,
		    fc_portmap_t *, uint32_t, uint32_t);
static int	fcsm_els_cb(opaque_t, opaque_t, fc_unsol_buf_t *, uint32_t);
static int	fcsm_data_cb(opaque_t, opaque_t, fc_unsol_buf_t *, uint32_t);

/*
 * Internal functions
 */
static int	fcsm_handle_port_attach(fc_ulp_port_info_t *, uint32_t, int);
static int	fcsm_handle_port_resume(opaque_t, fc_ulp_port_info_t *,
		    fc_attach_cmd_t, uint32_t, fcsm_t *);
static int	fcsm_handle_port_detach(fc_ulp_port_info_t *, fcsm_t *,
		    fc_detach_cmd_t);
static void	fcsm_suspend_port(fcsm_t *);
static void	fcsm_resume_port(fcsm_t *);
static void	fcsm_cleanup_port(fcsm_t *);
static void	fcsm_offline_timeout(void *);
static int	fcsm_fciocmd(intptr_t, int, cred_t *, fcio_t *);
static int	fcsm_fcio_copyout(fcio_t *, intptr_t, int);
static int	fcsm_job_cache_constructor(void *, void *, int);
static void	fcsm_job_cache_destructor(void *, void *);
static fcsm_job_t *fcsm_alloc_job(int);
static void	fcsm_dealloc_job(fcsm_job_t *);
static void	fcsm_init_job(fcsm_job_t *, int, uint32_t, uint32_t, opaque_t,
		    opaque_t, void (*comp)(opaque_t, fcsm_job_t *, int),
		    opaque_t);
static int	fcsm_process_job(fcsm_job_t *, int);
static void	fcsm_enque_job(fcsm_t *, fcsm_job_t *, int);
static fcsm_job_t *fcsm_deque_job(fcsm_t *);
static int	fcsm_cmd_cache_constructor(void *, void *, int);
static void	fcsm_cmd_cache_destructor(void *, void *);
static fcsm_cmd_t	*fcsm_alloc_cmd(fcsm_t *, uint32_t, uint32_t, int);
static void	fcsm_free_cmd_dma(fcsm_cmd_t *);
static void	fcsm_job_thread(fcsm_t *);
static int	fcsm_retry_job(fcsm_t *fcsm, fcsm_job_t *job);
static void	fcsm_jobdone(fcsm_job_t *);
static void	fcsm_ct_init(fcsm_t *, fcsm_cmd_t *, fc_ct_aiu_t *, size_t,
		    void (*comp_func)());
static void	fcsm_ct_intr(fcsm_cmd_t *);
static void	fcsm_job_ct_passthru(fcsm_job_t *);
static int	fcsm_login_and_process_job(fcsm_t *, fcsm_job_t *);
static void	fcsm_login_ms_comp(opaque_t, fcsm_job_t *, int);
static void	fcsm_els_init(fcsm_cmd_t *, uint32_t);
static int	fcsm_xlogi_init(fcsm_t *, fcsm_cmd_t *, uint32_t,
		    void (*comp_func)(), uchar_t);
static void	fcsm_xlogi_intr(fcsm_cmd_t *);
static void	fcsm_job_login_mgmt_server(fcsm_job_t *);
int		fcsm_ct_passthru(int, fcio_t *, int, int,
		    void (*func)(fcio_t *));
static void	fcsm_ct_passthru_comp(opaque_t, fcsm_job_t *, int);
static void	fcsm_pkt_common_intr(fc_packet_t *);
static int	fcsm_issue_cmd(fcsm_cmd_t *);
static int	fcsm_retry_cmd(fcsm_cmd_t *);
static void	fcsm_enque_cmd(fcsm_t *, fcsm_cmd_t *);
static fcsm_cmd_t *fcsm_deque_cmd(fcsm_t *);
static void	fcsm_retry_timeout(void *);
static void	fcsm_force_port_detach_all(void);


/*
 * Utility functions
 */
static void	fcsm_disp_devlist(fcsm_t *, fc_portmap_t *, uint32_t);

static void	fcsm_display(int, int, fcsm_t *,
		    fc_packet_t *, const char *, ...);
int		fcsm_pkt_state_to_rval(uchar_t, uint32_t);
caddr_t		fcsm_port_state_to_str(uint32_t);
caddr_t		fcsm_topology_to_str(uint32_t);
static caddr_t	fcsm_dev_type_to_str(uint32_t);


#endif /* _KERNEL */


#ifdef	__cplusplus
}
#endif

#endif /* _FCSM_H */
