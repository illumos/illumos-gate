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

#ifndef	_FC_PORTIF_H
#define	_FC_PORTIF_H

#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * To remove the port WWN from the orphan list; An orphan list
 * scan typically happens during ONLINE processing (after a LIP
 * in Public loop or link reset) or during RSCN validation.
 */
#define	FC_ORPHAN_SCAN_LIMIT		15

/*
 * Show a limited tolerance on the number of LOGOs that an
 * N/NL_Port can send; Beyond that it'll be removed entirely
 * from the port driver's data base. The tolerance counter
 * is reset after each link reset.
 */
#define	FC_LOGO_TOLERANCE_LIMIT		16
#define	FC_LOGO_TOLERANCE_TIME_LIMIT	5000000	/* 5 seconds */

/*
 * ns_flags field definitions in struct
 * fctl_ns_req_t
 */
#define	FCTL_NS_FILL_NS_MAP		0x01
#define	FCTL_NS_GET_DEV_COUNT		0x02
#define	FCTL_NS_NO_DATA_BUF		0x04
#define	FCTL_NS_BUF_IS_USERLAND		0x08
#define	FCTL_NS_BUF_IS_FC_PORTMAP	0x10
#define	FCTL_NS_CREATE_DEVICE		0x20
#define	FCTL_NS_VALIDATE_PD		0x40
#define	FCTL_NS_ASYNC_REQUEST		0x80
#define	FCTL_GAN_START_ID		0xFFFFFF



/*
 * Values for the fp_soft_state field in the fc_local_port_t struct.
 *
 * Notice below that in two cases, suspend and pm-suspend,there
 * is no usage of _IN_, which means the bits will stay even after
 * suspend/pm-suspend is complete they are cleared at the time of
 * resume/pm-resume.
 */

/*
 * FP_SOFT_IN_DETACH is set in fp_detach_handler(), which is called from
 * fp_detach() for the DDI_DETACH flag. FP_SOFT_IN_DETACH is checked in
 * numerous places. It is never explicitly cleared -- apparently the code
 * relies on ddi_softstate_free(9F) to clear it.
 */
#define	FP_SOFT_IN_DETACH		0x0002

/*
 * FP_SOFT_SUSPEND is set in fp_suspend_handler() and cleared in
 * fp_resume_handler.  It is tested in a number of placed in fp and fctl,
 * including fp_job_handler().
 */
#define	FP_SOFT_SUSPEND			0x0004

/*
 * FP_SOFT_POWER_DOWN is set in fp_power_down() and cleared in fp_power_up().
 * It is tested in a number of different places in fp/fctl.
 */
#define	FP_SOFT_POWER_DOWN		0x0008
#define	FP_SOFT_IN_STATEC_CB		0x0010
#define	FP_SOFT_IN_UNSOL_CB		0x0020
#define	FP_SOFT_IN_LINK_RESET		0x0040
#define	FP_SOFT_BAD_LINK		0x0080
#define	FP_SOFT_IN_FCA_RESET		0x0100
#define	FP_DETACH_INPROGRESS		0x0200
#define	FP_DETACH_FAILED		0x0400
#define	FP_SOFT_NO_PMCOMP		0x0800
#define	FP_SOFT_FCA_IS_NODMA		0x1000

/*
 * Instruct the port driver to just accept logins from these addresses
 */
#define	FC_MUST_ACCEPT_D_ID(x)		(FC_WELL_KNOWN_ADDR(x) || (x) == 0)

#define	FC_IS_REAL_DEVICE(x)		(!FC_MUST_ACCEPT_D_ID(x))

/*
 * Bit definitions for fp_options field in fc_local_port_t
 * structure for Feature and Hack additions to make
 * the driver code a real hairball.
 */
#define	FP_NS_SMART_COUNT			0x01
#define	FP_SEND_RJT				0x02
#define	FP_CORE_ON_OFFLINE_TIMEOUT		0x04
#define	FP_RESET_CORE_ON_OFFLINE_TIMEOUT	0x08
#define	FP_TARGET_MODE				0x10


/*
 * Values for fp_pm_level in the fc_local_port_t struct. Tracks current PM
 * level for the local port.
 */
#define	FP_PM_PORT_DOWN			0
#define	FP_PM_PORT_UP			1


/*
 * FC port compoment for PM. Used with pm_raise_power() and friends.
 */
#define	FP_PM_COMPONENT			0


#define	FCTL_WWN_SIZE(wwn)		\
	(sizeof ((wwn)->raw_wwn) / sizeof ((wwn)->raw_wwn[0]))


/*
 * Structure for issuing a work request to the per-instance "job handler"
 * thread. Primarily allocated/initialized by fctl_alloc_job() and freed by
 * fctl_dealloc_job().	fctl keeps a kmem_cache of these structs anchored by the
 * fctl_job_cache global variable.  The cache is created at fctl's _init(9E) and
 * destroyed at fctl's _fini(9E).  See also fctl_cache_constructor()
 * and fctl_cache_destructor().
 */
typedef struct job_request {
	/*
	 * ID code for the job or task to be performed.	 Set by fctl_alloc_job()
	 * and read by fp_job_handler().
	 */
	int		job_code;

	/*
	 * Completion status of the request.  Typically FC_SUCCESS or
	 * FC_FAILURE, but may make use of other error code values (such as
	 * FC_OFFLINE, FC_BADCMD, FC_NO_MAP, and friends). The complete set
	 * of values is not clearly specified.
	 */
	int		job_result;

	/* Execution control flags (defined below) */
	int		job_flags;

	/*
	 * This allows multiple concurrent operations using the same
	 * job_request_t struct, such as a PLOGI to a group of remote ports
	 * (see fp_plogi_group()).
	 *
	 * This is why this scheme needs the job_mutex to protect
	 * the job_counter variable, plus the additional job_port_sema for
	 * synchronizing thread(s).
	 */
	int		job_counter;


	opaque_t	job_cb_arg;		/* callback func arg */

	kmutex_t	job_mutex;
	ksema_t		job_fctl_sema;
	ksema_t		job_port_sema;


	void		(*job_comp) (opaque_t, uchar_t result);
	fc_packet_t	**job_ulp_pkts;
	uint32_t	job_ulp_listlen;	/* packet list length */
	void		*job_private;		/* caller's private */
	void		*job_arg;		/* caller's argument */

	/*
	 * Pointer for singly-liked list of outstanding job_request structs,
	 * maintained on a per-instance basis by the fp_port_head and
	 * fp_port_tail pointers in the fc_local_port_t struct.
	 */
	struct job_request	*job_next;
} job_request_t;


#if	!defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("unique per request",
	job_request::job_code job_request::job_result job_request::job_flags
	job_request::job_cb_arg job_request::job_comp
	job_request::job_ulp_pkts job_request::job_ulp_listlen
	job_request::job_private job_request::job_arg))
_NOTE(MUTEX_PROTECTS_DATA(fc_local_port::fp_mutex, job_request::job_next))
_NOTE(MUTEX_PROTECTS_DATA(job_request::job_mutex, job_request::job_counter))
#endif	/* __lint */


/*
 * Values for the job_code field in the job_request_t struct.
 */
#define	JOB_ATTACH_ULP			1	/* ULP call to fc_ulp_add() */
#define	JOB_PORT_STARTUP		2
#define	JOB_PORT_GETMAP			3
#define	JOB_PORT_GETMAP_PLOGI_ALL	4
#define	JOB_PLOGI_ONE			5
#define	JOB_PLOGI_GROUP			6
#define	JOB_LOGO_ONE			7
#define	JOB_PORT_OFFLINE		8
#define	JOB_PORT_ONLINE			9

/* Prepare the local port and the driver softstate for a DDI_DETACH. */
#define	JOB_PORT_SHUTDOWN		10

/* Handle an unsolicited request in the job thread */
#define	JOB_UNSOL_REQUEST		11

#define	JOB_NS_CMD			12
#define	JOB_LINK_RESET			13
#define	JOB_ULP_NOTIFY			14

#define	JOB_FCIO_LOGIN			15
#define	JOB_FCIO_LOGOUT			16

/*
 * This is used for requests that will not actually be dispatched to the job
 * thread.
 */
#define	JOB_DUMMY			127


/*
 * Bitmask values for the job_flags field in the job_request_t struct.
 *
 * JOB_TYPE_FCTL_ASYNC is set in various places in fp and fctl. If set then
 * fctl_jobdone() will call the completion function in the job_comp field and
 * deallocate the job_request_t struct.	 If not set then fctl_jobdone() will
 * sema_v() the job_fctl_sema to wake up any waiting thread.  This bit is also
 * checked in fc_ulp_login(): if *clear* then fc_ulp_login() will call
 * fctl_jobwait() in order to block the calling thread in the job_fctl_sema, and
 * then call fctl_dealloc_job() after fctl_jobwait() returns.
 *
 * JOB_TYPE_FP_ASYNC is set in various places in fp. If set then fp_jobdone()
 * will call fctl_jobdone(); if clear then fp_jobdone() will sema_v() the
 * job_port_sema in the job_request_t.	fp_port_shutdown() also looks for
 * JOB_TYPE_FP_ASYNC.  Just to keep thing interesting, JOB_TYPE_FP_ASYNC is
 * also set in fp_validate_area_domain() and cleared in fp_fcio_login() and
 * fp_ns_get_devcount()
 *
 * The apparent purpose of all this is to allow nested job requests to
 * occur in parallel.
 *
 * JOB_CANCEL_ULP_NOTIFICATION appears to be intended to  the number of
 * state change callbacks that are reported to ULPs when mutiple state
 * changes are being processed in parallel.
 */
#define	JOB_TYPE_FCTL_ASYNC		0x01
#define	JOB_TYPE_FP_ASYNC		0x02
#define	JOB_CANCEL_ULP_NOTIFICATION	0x10



typedef struct fc_port_clist {
	opaque_t	clist_port;		/* port handle */
	uint32_t	clist_state;		/* port state */
	uint32_t	clist_len;		/* map len */
	uint32_t	clist_size;		/* alloc len */
	fc_portmap_t	*clist_map;		/* changelist */
	uint32_t	clist_flags;		/* port topology */
	uint32_t	clist_wait;		/* for synchronous requests */
	kmutex_t	clist_mutex;		/* clist lock */
	kcondvar_t	clist_cv;		/* clist cv */
} fc_port_clist_t;

#if	!defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("unique per state change", fc_port_clist))
#endif	/* __lint */

/*
 * The cmd_size and resp_size shouldn't include the CT HEADER.
 *
 * For commands like GAN, the ns_resp_size should indicate the
 * total number of bytes allocated in the ns_resp_buf to get all
 * the NS objects.
 */
typedef struct fctl_ns_req {
	int			ns_result;
	uint32_t		ns_gan_index;
	uint32_t		ns_gan_sid;
	uint32_t		ns_flags;
	uint16_t		ns_cmd_code;	/* NS command code */
	caddr_t			ns_cmd_buf;	/* NS command buffer */
	uint16_t		ns_cmd_size;	/* NS command length */
	uint16_t		ns_resp_size;	/* NS response length */
	caddr_t			ns_data_buf;	/* User buffer */
	uint32_t		ns_data_len;	/* User buffer length */
	uint32_t		ns_gan_max;
	fc_ct_header_t		ns_resp_hdr;
	fc_remote_port_t	*ns_pd;
} fctl_ns_req_t;

#if	!defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("unique per state change", fctl_ns_req))
#endif	/* __lint */

/*
 * Orphan list of Port WWNs
 */
typedef struct fc_orphan {
	int			orp_nscan;	/* Number of scans */
	clock_t			orp_tstamp;	/* When it disappeared */
	la_wwn_t		orp_pwwn;	/* Port WWN */
	struct fc_orphan	*orp_next;	/* Next orphan */
} fc_orphan_t;

#define	FC_GET_RSP(x_port, x_handle, x_dest, x_src, x_size, x_flag)	\
	{								\
		if (!((x_port)->fp_soft_state & FP_SOFT_FCA_IS_NODMA)) {\
			ddi_rep_get8((x_handle), (uint8_t *)(x_dest),	\
				    (uint8_t *)(x_src), (x_size),	\
				    (x_flag));				\
		} else {						\
			bcopy((x_src), (x_dest), (x_size));		\
		}							\
	}

#define	FC_SET_CMD(x_port, x_handle, x_src, x_dest, x_size, x_flag)	\
	{								\
		if (!((x_port)->fp_soft_state & FP_SOFT_FCA_IS_NODMA)) {\
			ddi_rep_put8((x_handle), (uint8_t *)(x_src),	\
				    (uint8_t *)(x_dest), (x_size),	\
				    (x_flag));				\
		} else {						\
			bcopy((x_src), (x_dest), (x_size));		\
		}							\
	}

#if	!defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("scans don't interleave",
    fc_orphan::orp_nscan fc_orphan::orp_pwwn fc_orphan::orp_tstamp))
_NOTE(MUTEX_PROTECTS_DATA(fc_local_port::fp_mutex, fc_orphan::orp_next))
#endif /* __lint */

fc_remote_node_t *fctl_create_remote_node(la_wwn_t *nwwn, int sleep);
void fctl_destroy_remote_node(fc_remote_node_t *rnp);
fc_remote_port_t *fctl_create_remote_port(fc_local_port_t *port,
    la_wwn_t *node_wwn, la_wwn_t *port_wwn, uint32_t d_id,
    uchar_t recepient, int sleep);
int fctl_destroy_remote_port(fc_local_port_t *port, fc_remote_port_t *pd);
fc_remote_port_t *fctl_alloc_remote_port(fc_local_port_t *port,
    la_wwn_t *port_wwn, uint32_t d_id, uchar_t recepient, int sleep);
void fctl_dealloc_remote_port(fc_remote_port_t *pd);
void fctl_release_remote_port(fc_remote_port_t *pd);
void fctl_destroy_all_remote_ports(fc_local_port_t *port);
void fctl_link_remote_port_to_remote_node(fc_remote_node_t *rnp,
    fc_remote_port_t *pd);
int fctl_unlink_remote_port_from_remote_node(fc_remote_node_t *rnp,
    fc_remote_port_t *pd);

job_request_t *fctl_alloc_job(int job_code, int job_flags,
    void (*comp) (opaque_t, uchar_t), opaque_t arg, int sleep);
void fctl_dealloc_job(job_request_t *job);
void fctl_enque_job(fc_local_port_t *port, job_request_t *job);
void fctl_priority_enque_job(fc_local_port_t *port, job_request_t *job);
job_request_t *fctl_deque_job(fc_local_port_t *port);
void fctl_jobwait(job_request_t *job);
void fctl_jobdone(job_request_t *job);

void fctl_attach_ulps(fc_local_port_t *port, fc_attach_cmd_t cmd,
    struct modlinkage *linkage);
int fctl_detach_ulps(fc_local_port_t *port, fc_detach_cmd_t cmd,
    struct modlinkage *linkage);

void fctl_add_port(fc_local_port_t *port);
void fctl_remove_port(fc_local_port_t *port);
int fctl_busy_port(fc_local_port_t *port);
void fctl_idle_port(fc_local_port_t *port);

fc_remote_port_t *fctl_get_remote_port_by_did(fc_local_port_t *port,
    uint32_t d_id);
fc_remote_port_t *fctl_hold_remote_port_by_did(fc_local_port_t *port,
    uint32_t d_id);
fc_remote_port_t *fctl_get_remote_port_by_pwwn(fc_local_port_t *port,
    la_wwn_t *pwwn);
fc_remote_port_t *fctl_hold_remote_port_by_pwwn(fc_local_port_t *port,
    la_wwn_t *pwwn);
fc_remote_port_t *
    fctl_get_remote_port_by_pwwn_mutex_held(fc_local_port_t *port,
    la_wwn_t *pwwn);
fc_remote_node_t *fctl_get_remote_node_by_nwwn(la_wwn_t *node_wwn);
fc_remote_node_t *fctl_lock_remote_node_by_nwwn(la_wwn_t *node_wwn);
fc_remote_port_t *fctl_lookup_pd_by_did(fc_local_port_t *port, uint32_t d_id);
fc_remote_port_t *fctl_lookup_pd_by_index(fc_local_port_t *port,
    uint32_t index);
fc_remote_port_t *fctl_lookup_pd_by_wwn(fc_local_port_t *port, la_wwn_t wwn);

void fctl_enlist_did_table(fc_local_port_t *port, fc_remote_port_t *pd);
void fctl_delist_did_table(fc_local_port_t *port, fc_remote_port_t *pd);
void fctl_enlist_pwwn_table(fc_local_port_t *port, fc_remote_port_t *pd);
void fctl_delist_pwwn_table(fc_local_port_t *port, fc_remote_port_t *pd);
int fctl_enlist_nwwn_table(fc_remote_node_t *rnp, int sleep);
void fctl_delist_nwwn_table(fc_remote_node_t *rnp);

void fctl_ulp_statec_cb(void *arg);
void fctl_ulp_unsol_cb(fc_local_port_t *port, fc_unsol_buf_t *buf,
    uchar_t type);
int fctl_ulp_port_ioctl(fc_local_port_t *port, dev_t dev, int cmd,
    intptr_t data, int mode, cred_t *credp, int *rval);

void fctl_fillout_map(fc_local_port_t *port, fc_portmap_t **map,
    uint32_t *len, int whole_map, int justcopy, int orphan);
void fctl_copy_portmap_held(fc_portmap_t *map, fc_remote_port_t *pd);
void fctl_copy_portmap(fc_portmap_t *map, fc_remote_port_t *pd);

fctl_ns_req_t *fctl_alloc_ns_cmd(uint32_t cmd_len, uint32_t resp_len,
    uint32_t data_len, uint32_t ns_flags, int sleep);
void fctl_free_ns_cmd(fctl_ns_req_t *ns_cmd);

int fctl_remove_if_orphan(fc_local_port_t *port, la_wwn_t *pwwn);
int fctl_add_orphan_held(fc_local_port_t *port, fc_remote_port_t *pd);
int fctl_add_orphan(fc_local_port_t *port, fc_remote_port_t *pd, int sleep);
void fctl_remove_oldies(fc_local_port_t *port);

int fctl_is_wwn_zero(la_wwn_t *wwn);
int fctl_wwn_cmp(la_wwn_t *src, la_wwn_t *dst);
int fctl_atoi(caddr_t string, int base);
int fctl_count_fru_ports(fc_local_port_t *port, int npivflag);
fc_local_port_t *fctl_get_adapter_port_by_index(fc_local_port_t *port,
	uint32_t port_index);

void fctl_tc_constructor(timed_counter_t *tc, uint32_t max_value,
    clock_t timer);
void fctl_tc_destructor(timed_counter_t *tc);
boolean_t fctl_tc_increment(timed_counter_t *tc);
void fctl_tc_reset(timed_counter_t *tc);

#ifdef	__cplusplus
}
#endif

#endif	/* _FC_PORTIF_H */
