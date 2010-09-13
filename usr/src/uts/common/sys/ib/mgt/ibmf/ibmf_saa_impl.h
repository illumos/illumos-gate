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

#ifndef _SYS_IB_MGT_IBMF_IBMF_SAA_IMPL_H
#define	_SYS_IB_MGT_IBMF_IBMF_SAA_IMPL_H

/*
 * saa_impl.h
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ib/mgt/ibmf/ibmf_saa.h>
#include <sys/ib/mgt/ibmf/ibmf_impl.h>

#define	SAA_MAX_CLIENTS_PER_PORT	100
#define	SAA_MAD_BASE_VERSION		1
#define	SAA_MAD_CLASS_VERSION		2
#define	IBMF_SAA_RETRANS_RETRIES 	0
#define	IBMF_SAA_MAX_SUBNET_TIMEOUT 	20
#define	IBMF_SAA_MAX_RESP_TIME		20
#define	IBMF_SAA_MAX_BUSY_RETRY_COUNT	10
#define	IBMF_SAA_MAX_WAIT_TIME_IN_SECS	60
#define	IBMF_SAA_TRANS_WAIT_TIME_IN_SECS 240
#define	IBMF_SAA_BUSY_RETRY_SLEEP_SECS	1	/* seconds between retry */

/*
 * saa_port_s:
 * Linked list of ports that saa is using. Each port is registered to ibmf.
 * Multiple saa clients can associate with an saa port
 */
typedef enum saa_port_state_s {
	IBMF_SAA_PORT_STATE_REGISTERING,
	IBMF_SAA_PORT_STATE_READY,
	IBMF_SAA_PORT_STATE_INVALID, 	/* client MUST close */
	IBMF_SAA_PORT_STATE_PURGING	/* being purged */
} saa_port_state_t;

typedef struct saa_port_s {

	struct saa_port_s	*next;

	kmutex_t		saa_pt_mutex;

	/* registration synchronization: only one client registers to ibmf */
	kcondvar_t		saa_pt_ibmf_reg_cv;

	/* state and client reference counts */
	saa_port_state_t	saa_pt_state;
	int			saa_pt_reference_count;

	/* port identification and ibmf registration info */
	ib_guid_t		saa_pt_port_guid;
	ibmf_register_info_t	saa_pt_ibmf_reginfo;

	ibmf_handle_t		saa_pt_ibmf_handle;
	ibmf_impl_caps_t 	saa_pt_ibmf_impl_features;
	ibmf_qp_handle_t	saa_pt_qp_handle;
	ib_qpn_t		saa_pt_qpn;

	/* transaction parameters */
	int			saa_pt_timeout; 	/* from portinfo */
	uint16_t		saa_pt_sa_cap_mask;  	/* from classportinfo */

	ibmf_addr_info_t	saa_pt_ibmf_addr_info;
	ibmf_global_addr_info_t	saa_pt_ibmf_global_addr;
	uint32_t		saa_pt_ibmf_msg_flags;
	boolean_t		saa_pt_redirect_active;	/* SA has redirected */

	ibmf_retrans_t		saa_pt_ibmf_retrans;
	uint64_t 		saa_pt_current_tid;
	int			saa_pt_num_outstanding_trans;

	/* kstats */
	kmutex_t		saa_pt_kstat_mutex;
	struct kstat		*saa_pt_kstatp;

	/* sync. for receiving informinfo req packets */
	kmutex_t		saa_pt_event_sub_mutex;
	uint8_t			saa_pt_event_sub_arrive_mask;
	uint8_t			saa_pt_event_sub_success_mask;
	uint8_t			saa_pt_event_sub_last_success_mask;
	struct saa_client_data_s	*saa_pt_event_sub_client_list;

	/* node guid and port num, saved for easy ibt_queries */
	ib_guid_t		saa_pt_node_guid;
	uint8_t			saa_pt_port_num;

	/* latest hrtime that packet from SA was received */
	hrtime_t		saa_pt_sa_uptime;
} saa_port_t;
_NOTE(MUTEX_PROTECTS_DATA(saa_port_t::saa_pt_mutex,
    saa_port_t::saa_pt_reference_count
    saa_port_t::saa_pt_ibmf_reg_cv
    saa_port_t::saa_pt_ibmf_retrans
    saa_port_t::saa_pt_current_tid
    saa_port_t::saa_pt_num_outstanding_trans
    saa_port_t::saa_pt_timeout
    saa_port_t::saa_pt_ibmf_addr_info
    saa_port_t::saa_pt_ibmf_global_addr
    saa_port_t::saa_pt_ibmf_msg_flags
    saa_port_t::saa_pt_redirect_active))
_NOTE(MUTEX_PROTECTS_DATA(saa_port_t::saa_pt_kstat_mutex,
    saa_port_t::saa_pt_kstatp))


#define	IBMF_SAA_PORT_EVENT_SUB_ALL_ARRIVE		\
	(IBMF_SAA_EVENT_STATUS_MASK_PRODUCER_CA |	\
	IBMF_SAA_EVENT_STATUS_MASK_PRODUCER_SWITCH |	\
	IBMF_SAA_EVENT_STATUS_MASK_PRODUCER_ROUTER |	\
	IBMF_SAA_EVENT_STATUS_MASK_PRODUCER_SM)

typedef struct ibmf_saa_kstat_s {
	kstat_named_t	clients_registered;	/* # saa registrants */
	kstat_named_t	clients_reg_failed;	/* # failed registrants */
	kstat_named_t	outstanding_requests;	/* # outstanding requests */
	kstat_named_t	total_requests;		/* # requests ever made */
	kstat_named_t	failed_requests;	/* # failed requests */
	kstat_named_t	requests_timedout;	/* # requests that timedout */
} ibmf_saa_kstat_t;

#define	IBMF_SAA_ADD32_KSTATS(subnetp, xx, val)				\
	if ((subnetp != NULL) && (subnetp->saa_pt_kstatp != NULL)) {	\
		ibmf_saa_kstat_t	*kp;				\
		kp = (ibmf_saa_kstat_t *)subnetp->saa_pt_kstatp->ks_data;\
		kp->xx.value.ui32 += val;				\
	}

#define	IBMF_SAA_SUB32_KSTATS(subnetp, xx, val)				\
	if ((subnetp != NULL) && (subnetp->saa_pt_kstatp != NULL)) {	\
		ibmf_saa_kstat_t	*kp;				\
		kp = (ibmf_saa_kstat_t *)subnetp->saa_pt_kstatp->ks_data;\
		kp->xx.value.ui32 -= val;				\
	}

typedef enum _saa_client_state_e {
	SAA_CLIENT_STATE_ACTIVE,
	SAA_CLIENT_STATE_WAITING,
	SAA_CLIENT_STATE_CLOSED
} saa_client_state_t;

typedef struct saa_client_data_s {
	void				*next;

	/* set for valid handles */
	void				*saa_client_sig;
	saa_port_t			*saa_client_port;
	kmutex_t			saa_client_mutex;
	int				saa_client_num_pending_trans;
	kcondvar_t			saa_client_state_cv;
	saa_client_state_t		saa_client_state;
	ib_smkey_t			saa_client_sm_key;

	int				saa_client_event_cb_num_active;
	kcondvar_t			saa_client_event_cb_cv;

	ibmf_saa_subnet_event_cb_t	saa_client_event_cb;
	void				*saa_client_event_cb_arg;
} saa_client_data_t;
_NOTE(READ_ONLY_DATA(saa_client_data_t::saa_client_port))
_NOTE(READ_ONLY_DATA(saa_client_data_t::saa_client_sig))


typedef struct saa_state_s {

	saa_port_t	*saa_port_list;
	kmutex_t	saa_port_list_mutex;
	taskq_t		*saa_event_taskq;
} saa_state_t;
_NOTE(MUTEX_PROTECTS_DATA(saa_state_t::saa_port_list_mutex,
    saa_port_t::next
    saa_state_t::saa_port_list))
_NOTE(READ_ONLY_DATA(saa_state_t::saa_event_taskq))

/*
 * special callback used specifically for handling informinfo responses;
 * extra parameter is producer_type
 */
typedef void (*ibmf_saa_sub_cb_t) (void *, size_t, char *, int, uint32_t);

/*
 * saa_impl_trans_info_t:
 * Convenience structure wich allows ibmf_access_sa to group all the fields
 * into one structure as a parameter to the send request function.
 * This structure is allocated by ibmf_access_sa() and freed by ibmf_access_sa()
 * in the sync case and by the ibmf_msg_transport callback in the async case
 */
typedef struct saa_impl_trans_info_t {

	saa_client_data_t	*si_trans_client_data;
	saa_port_t		*si_trans_port;

	/* used to tell send_request about request mad */
	size_t			si_trans_template_length; /* for unknown attr */
	uint16_t		si_trans_attr_id;
	uint64_t		si_trans_component_mask;
	void			*si_trans_template;
	uint8_t			si_trans_method;

	/* used for async call to tell send_request which callback to use */
	ibmf_saa_cb_t		si_trans_callback;
	void			*si_trans_callback_arg;

	/*
	 * used to tell ibmf_access_sa about response if the request was sync.
	 * If the request was async, the ibmf_msg_transport callback function
	 * will fill these values directly into the si_trans_callback
	 */
	int			si_trans_status;
	void			*si_trans_result;
	size_t			si_trans_length;

	/* fields needed for specific case of handling InformInfo requests */

	/*
	 * producer_type indicates the notice producer type that the
	 * subscription was for.  There is no way to tell which type the
	 * response packet is for.
	 */
	uint32_t		si_trans_sub_producer_type;

	/*
	 * separate callback typedef to provide the producer type to the
	 * subscription response handler (ibmf_saa_impl_get_informinfo_cb)
	 */
	ibmf_saa_sub_cb_t	si_trans_sub_callback;

	/*
	 * some unsubscribe requests are sequenced, others are unsequenced
	 * (depending on context that generated unsubscribe request)
	 */
	boolean_t		si_trans_unseq_unsubscribe;

	/* trans flags saved in case sm lid changes and msg must be resent */
	uint8_t			si_trans_transport_flags;

	/* counter for retrying requests which return MAD_BUSY status */
	uint8_t			si_trans_retry_busy_count;

	/* hrtime that we initiated this transaction */
	hrtime_t		si_trans_send_time;
} saa_impl_trans_info_t;
_NOTE(SCHEME_PROTECTS_DATA("private callback arg", saa_impl_trans_info_t))

typedef struct ibmf_saa_event_taskq_args_s {
	saa_client_data_t		*et_client;
	ibmf_saa_subnet_event_t		et_subnet_event;
	ibmf_saa_event_details_t	*et_event_details;
	ib_mad_notice_t			*et_notice;
	ibmf_saa_subnet_event_cb_t	et_callback;
	void				*et_callback_arg;
} ibmf_saa_event_taskq_args_t;
_NOTE(READ_ONLY_DATA(ibmf_saa_event_taskq_args_t::et_subnet_event
    ibmf_saa_event_taskq_args_t::et_event_details
    ibmf_saa_event_taskq_args_t::et_client
    ibmf_saa_event_taskq_args_t::et_notice
    ibmf_saa_event_taskq_args_t::et_callback
    ibmf_saa_event_taskq_args_t::et_callback_arg))

/*
 * Public Functions
 */
int ibmf_saa_impl_init();
int ibmf_saa_impl_fini();
boolean_t ibmf_saa_is_valid(saa_port_t *saa_portp, int add_ref);
void ibmf_saa_impl_purge();
int ibmf_saa_impl_add_client(saa_port_t *saa_portp);
int ibmf_saa_impl_create_port(ib_guid_t	pt_guid, saa_port_t **saa_portpp);
int ibmf_saa_impl_init_kstats(saa_port_t *saa_portp);
void ibmf_saa_impl_register_failed(saa_port_t *saa_portp);
int ibmf_saa_impl_register_port(saa_port_t *saa_portp);
void ibmf_saa_impl_get_classportinfo(saa_port_t *saa_portp);
int ibmf_saa_impl_send_request(saa_impl_trans_info_t *trans_info);

void ibmf_saa_async_cb(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args);

void
ibmf_saa_add_event_subscriber(saa_client_data_t *client,
    ibmf_saa_subnet_event_args_t *event_args);

void ibmf_saa_subscribe_events(saa_port_t *saa_portp, boolean_t subscribe,
    boolean_t seq_unsubscribe);

void ibmf_saa_subscribe_sm_events(saa_port_t *saa_portp);

void
ibmf_saa_notify_event_clients(saa_port_t *saa_portp,
    ibmf_saa_event_details_t *event_details,
    ibmf_saa_subnet_event_t subnet_event,
    saa_client_data_t *registering_client);

void
ibmf_saa_report_cb(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp,
    void *args);
#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_MGT_IBMF_IBMF_SAA_IMPL_H */
