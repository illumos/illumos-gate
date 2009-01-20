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

/*
 * This file implements the client interfaces of the IBMF.
 */

#include <sys/ib/mgt/ibmf/ibmf_impl.h>
#include <sys/ib/mgt/ib_mad.h>

extern ibmf_state_t *ibmf_statep;

/* global settable */
int	ibmf_send_wqes_per_port = IBMF_MAX_SQ_WRE;
int	ibmf_recv_wqes_per_port = IBMF_MAX_RQ_WRE;
int	ibmf_send_wqes_posted_per_qp = IBMF_MAX_POSTED_SQ_PER_QP;
int	ibmf_recv_wqes_posted_per_qp = IBMF_MAX_POSTED_RQ_PER_QP;

int	ibmf_taskq_max_tasks = 1024;

int	ibmf_trace_level = DPRINT_L0;

#define	IBMF_MAD_CL_HDR_OFF_1	0
#define	IBMF_MAD_CL_HDR_OFF_2	12
#define	IBMF_MAD_CL_HDR_SZ_1	40
#define	IBMF_MAD_CL_HDR_SZ_2	20
#define	IBMF_MAD_CL_HDR_SZ_3	0
#define	IBMF_MAD_CL_HDR_SZ_4	4

#define	IBMF_VALID_CLIENT_TYPE(client_type)		\
	((client_type) == SUBN_AGENT ||			\
	(client_type) == SUBN_MANAGER ||		\
	(client_type) == SUBN_ADM_AGENT ||		\
	(client_type) == SUBN_ADM_MANAGER ||		\
	(client_type) == PERF_AGENT ||			\
	(client_type) == PERF_MANAGER ||		\
	(client_type) == BM_AGENT ||			\
	(client_type) == BM_MANAGER ||			\
	(client_type) == DEV_MGT_AGENT ||		\
	(client_type) == DEV_MGT_MANAGER ||		\
	(client_type) == COMM_MGT_MANAGER_AGENT ||	\
	(client_type) == SNMP_MANAGER_AGENT ||		\
	(client_type) == VENDOR_09_MANAGER_AGENT ||	\
	(client_type) == VENDOR_0A_MANAGER_AGENT ||	\
	(client_type) == VENDOR_0B_MANAGER_AGENT ||	\
	(client_type) == VENDOR_0C_MANAGER_AGENT ||	\
	(client_type) == VENDOR_0D_MANAGER_AGENT ||	\
	(client_type) == VENDOR_0E_MANAGER_AGENT ||	\
	(client_type) == VENDOR_0F_MANAGER_AGENT ||	\
	(client_type) == VENDOR_30_MANAGER_AGENT ||	\
	(client_type) == VENDOR_31_MANAGER_AGENT ||	\
	(client_type) == VENDOR_32_MANAGER_AGENT ||	\
	(client_type) == VENDOR_33_MANAGER_AGENT ||	\
	(client_type) == VENDOR_34_MANAGER_AGENT ||	\
	(client_type) == VENDOR_35_MANAGER_AGENT ||	\
	(client_type) == VENDOR_36_MANAGER_AGENT ||	\
	(client_type) == VENDOR_37_MANAGER_AGENT ||	\
	(client_type) == VENDOR_38_MANAGER_AGENT ||	\
	(client_type) == VENDOR_39_MANAGER_AGENT ||	\
	(client_type) == VENDOR_3A_MANAGER_AGENT ||	\
	(client_type) == VENDOR_3B_MANAGER_AGENT ||	\
	(client_type) == VENDOR_3C_MANAGER_AGENT ||	\
	(client_type) == VENDOR_3D_MANAGER_AGENT ||	\
	(client_type) == VENDOR_3E_MANAGER_AGENT ||	\
	(client_type) == VENDOR_3F_MANAGER_AGENT ||	\
	(client_type) == VENDOR_40_MANAGER_AGENT ||	\
	(client_type) == VENDOR_41_MANAGER_AGENT ||	\
	(client_type) == VENDOR_42_MANAGER_AGENT ||	\
	(client_type) == VENDOR_43_MANAGER_AGENT ||	\
	(client_type) == VENDOR_44_MANAGER_AGENT ||	\
	(client_type) == VENDOR_45_MANAGER_AGENT ||	\
	(client_type) == VENDOR_46_MANAGER_AGENT ||	\
	(client_type) == VENDOR_47_MANAGER_AGENT ||	\
	(client_type) == VENDOR_48_MANAGER_AGENT ||	\
	(client_type) == VENDOR_49_MANAGER_AGENT ||	\
	(client_type) == VENDOR_4A_MANAGER_AGENT ||	\
	(client_type) == VENDOR_4B_MANAGER_AGENT ||	\
	(client_type) == VENDOR_4C_MANAGER_AGENT ||	\
	(client_type) == VENDOR_4D_MANAGER_AGENT ||	\
	(client_type) == VENDOR_4E_MANAGER_AGENT ||	\
	(client_type) == VENDOR_4F_MANAGER_AGENT ||	\
	(client_type) == APPLICATION_10_MANAGER_AGENT || \
	(client_type) == APPLICATION_11_MANAGER_AGENT || \
	(client_type) == APPLICATION_12_MANAGER_AGENT || \
	(client_type) == APPLICATION_13_MANAGER_AGENT || \
	(client_type) == APPLICATION_14_MANAGER_AGENT || \
	(client_type) == APPLICATION_15_MANAGER_AGENT || \
	(client_type) == APPLICATION_16_MANAGER_AGENT || \
	(client_type) == APPLICATION_17_MANAGER_AGENT || \
	(client_type) == APPLICATION_18_MANAGER_AGENT || \
	(client_type) == APPLICATION_19_MANAGER_AGENT || \
	(client_type) == APPLICATION_1A_MANAGER_AGENT || \
	(client_type) == APPLICATION_1B_MANAGER_AGENT || \
	(client_type) == APPLICATION_1C_MANAGER_AGENT || \
	(client_type) == APPLICATION_1D_MANAGER_AGENT || \
	(client_type) == APPLICATION_1E_MANAGER_AGENT || \
	(client_type) == APPLICATION_1F_MANAGER_AGENT || \
	(client_type) == APPLICATION_20_MANAGER_AGENT || \
	(client_type) == APPLICATION_21_MANAGER_AGENT || \
	(client_type) == APPLICATION_22_MANAGER_AGENT || \
	(client_type) == APPLICATION_23_MANAGER_AGENT || \
	(client_type) == APPLICATION_24_MANAGER_AGENT || \
	(client_type) == APPLICATION_25_MANAGER_AGENT || \
	(client_type) == APPLICATION_26_MANAGER_AGENT || \
	(client_type) == APPLICATION_27_MANAGER_AGENT || \
	(client_type) == APPLICATION_28_MANAGER_AGENT || \
	(client_type) == APPLICATION_29_MANAGER_AGENT || \
	(client_type) == APPLICATION_2A_MANAGER_AGENT || \
	(client_type) == APPLICATION_2B_MANAGER_AGENT || \
	(client_type) == APPLICATION_2C_MANAGER_AGENT || \
	(client_type) == APPLICATION_2D_MANAGER_AGENT || \
	(client_type) == APPLICATION_2E_MANAGER_AGENT || \
	(client_type) == APPLICATION_2F_MANAGER_AGENT || \
	(client_type) == UNIVERSAL_CLASS)

static ibmf_ci_t *ibmf_i_lookup_ci(ib_guid_t ci_guid);
static int ibmf_i_init_ci(ibmf_register_info_t *client_infop,
    ibmf_ci_t *cip);
static void ibmf_i_uninit_ci(ibmf_ci_t *cip);
static void ibmf_i_init_ci_done(ibmf_ci_t *cip);
static void ibmf_i_uninit_ci_done(ibmf_ci_t *cip);
static int ibmf_i_init_qp(ibmf_ci_t *ibmf_cip, ibmf_qp_t *qpp);
static void ibmf_i_uninit_qp(ibmf_ci_t *ibmf_cip, ibmf_qp_t *qpp);
static int ibmf_i_init_cqs(ibmf_ci_t *cip);
static void ibmf_i_fini_cqs(ibmf_ci_t *cip);
static void ibmf_i_init_qplist(ibmf_ci_t *ibmf_cip);
static void ibmf_i_fini_qplist(ibmf_ci_t *ibmf_cip);
static int ibmf_i_lookup_client_by_info(ibmf_ci_t *ibmf_cip,
    ibmf_register_info_t *ir_client, ibmf_client_t **clientpp);

/*
 * ibmf_init():
 *	Initializes module state and registers with the IBT framework.
 * 	Returns 0 if initialization was successful, else returns non-zero.
 */
int
ibmf_init(void)
{
	ibt_status_t 	status;
	ibt_clnt_hdl_t 	ibmf_ibt_handle;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_init_start,
	    IBMF_TNF_TRACE, "", "ibmf_init() enter\n");

	/* setup the IBT module information */
	ibmf_statep->ibmf_ibt_modinfo.mi_ibt_version = IBTI_V_CURR;
	ibmf_statep->ibmf_ibt_modinfo.mi_clnt_class = IBT_IBMA;
	ibmf_statep->ibmf_ibt_modinfo.mi_async_handler
	    = ibmf_ibt_async_handler;
	ibmf_statep->ibmf_ibt_modinfo.mi_reserved = NULL;
	ibmf_statep->ibmf_ibt_modinfo.mi_clnt_name = "ibmf";

	/* setup a connection to IB transport layer (IBTF) */
	status = ibt_attach(&ibmf_statep->ibmf_ibt_modinfo, (void *)NULL,
	    (void *)NULL, (void *)&ibmf_ibt_handle);
	if (status != IBT_SUCCESS) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1, ibmf_init_err,
		    IBMF_TNF_ERROR, "", "%s, status = %d\n", tnf_string, msg,
		    "ibt attach failed", tnf_uint, status, status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_init_end,
		    IBMF_TNF_TRACE, "", "ibmf_init() exit\n");
		return (1);
	}

	/* initialize the IBMF state context */
	ibmf_statep->ibmf_ibt_handle = ibmf_ibt_handle;
	ibmf_statep->ibmf_ci_list = (ibmf_ci_t *)NULL;
	ibmf_statep->ibmf_ci_list_tail = (ibmf_ci_t *)NULL;
	mutex_init(&ibmf_statep->ibmf_mutex, NULL, MUTEX_DRIVER, NULL);
	ibmf_statep->ibmf_cq_handler = ibmf_i_mad_completions;

	ibmf_statep->ibmf_taskq = taskq_create("ibmf_taskq", IBMF_TASKQ_1THREAD,
	    MINCLSYSPRI, 1, ibmf_taskq_max_tasks, TASKQ_PREPOPULATE);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_init_end,
	    IBMF_TNF_TRACE, "", "ibmf_init() exit\n");

	return (0);
}

/*
 * ibmf_fini():
 *	Cleans up module state resources and unregisters from IBT framework.
 */
int
ibmf_fini(void)
{
	ibmf_ci_t	*cip;
	ibmf_ci_t	*tcip;
	ibt_status_t	status;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_fini_start,
	    IBMF_TNF_TRACE, "", "ibmf_fini() enter\n");

	ASSERT(MUTEX_NOT_HELD(&ibmf_statep->ibmf_mutex));

	mutex_enter(&ibmf_statep->ibmf_mutex);

	/* free all the Channel Interface (CI) context structures */
	cip = ibmf_statep->ibmf_ci_list;
	tcip = NULL;
	while (cip != (ibmf_ci_t *)NULL) {

		mutex_enter(&cip->ci_mutex);
		ASSERT((cip->ci_state == IBMF_CI_STATE_PRESENT && cip->ci_ref ==
		    0) || (cip->ci_state == IBMF_CI_STATE_GONE));
		ASSERT(cip->ci_init_state == IBMF_CI_INIT_HCA_LINKED);
		ASSERT(cip->ci_qp_list == NULL && cip->ci_qp_list_tail == NULL);
		if (tcip != (ibmf_ci_t *)NULL)
			tcip->ci_next = cip->ci_next;
		if (ibmf_statep->ibmf_ci_list_tail == cip)
			ibmf_statep->ibmf_ci_list_tail = NULL;
		if (ibmf_statep->ibmf_ci_list == cip)
			ibmf_statep->ibmf_ci_list = cip->ci_next;
		tcip = cip->ci_next;
		mutex_exit(&cip->ci_mutex);
		/* free up the ci structure */
		if (cip->ci_port_kstatp != NULL) {
			kstat_delete(cip->ci_port_kstatp);
		}
		mutex_destroy(&cip->ci_mutex);
		mutex_destroy(&cip->ci_clients_mutex);
		mutex_destroy(&cip->ci_wqe_mutex);
		cv_destroy(&cip->ci_state_cv);
		cv_destroy(&cip->ci_wqes_cv);
		kmem_free((void *) cip, sizeof (ibmf_ci_t));
		cip = tcip;
	}

	ASSERT(ibmf_statep->ibmf_ci_list == NULL);
	ASSERT(ibmf_statep->ibmf_ci_list_tail == NULL);

	taskq_destroy(ibmf_statep->ibmf_taskq);

	mutex_exit(&ibmf_statep->ibmf_mutex);

	/* detach from IBTF */
	status = ibt_detach(ibmf_statep->ibmf_ibt_handle);
	if (status != IBT_SUCCESS) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1, ibmf_fini_err,
		    IBMF_TNF_ERROR, "", "%s, status = %d\n", tnf_string, msg,
		    "ibt detach error", tnf_uint, status, status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_fini_end,
		    IBMF_TNF_TRACE, "", "ibmf_fini() exit\n");
		return (1);
	}

	mutex_destroy(&ibmf_statep->ibmf_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_fini_end,
	    IBMF_TNF_TRACE, "", "ibmf_fini() exit\n");

	return (0);
}

/*
 * ibmf_i_validate_class_mask():
 *	Checks client type value in client information structure.
 */
int
ibmf_i_validate_class_mask(ibmf_register_info_t	*client_infop)
{
	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_validate_class_mask_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_validate_class_mask() enter, client_infop = %p\n",
	    tnf_opaque, client_infop, client_infop);

	if (IBMF_VALID_CLIENT_TYPE(client_infop->ir_client_class) == B_FALSE) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_validate_class_mask_err, IBMF_TNF_ERROR, "",
		    "%s, class = %x\n", tnf_string, msg,
		    "invalid class", tnf_uint, class,
		    client_infop->ir_client_class);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_validate_class_mask_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_validate_class_mask() exit\n");
		return (IBMF_BAD_CLASS);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_validate_class_mask_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_validate_class_mask() exit\n");
	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_validate_ci_guid_and_port():
 *	Checks validity of port number and HCA GUID at client
 *	registration time.
 */
int
ibmf_i_validate_ci_guid_and_port(ib_guid_t hca_guid, uint8_t port_num)
{
	ibt_status_t	status;
	ibt_hca_attr_t	hca_attrs;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_validate_ci_guid_and_port_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_validate_ci_guid_and_port() enter, hca_guid = %x, "
	    "port_num = %d\n", tnf_opaque, hca_guid, hca_guid,
	    tnf_uint, port_num, port_num);

	/* check for incorrect port number specification */
	if (port_num == 0) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, 1,
		    ibmf_i_validate_ci_guid_and_port_err, IBMF_TNF_ERROR, "",
		    "%s\n", tnf_string, msg, "port num is 0");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_validate_ci_guid_and_port_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_validate_ci_guid_and_port() exit\n");
		return (IBMF_BAD_PORT);
	}

	/* call IB transport layer for HCA attributes */
	status = ibt_query_hca_byguid(hca_guid, &hca_attrs);
	if (status != IBT_SUCCESS) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_validate_ci_guid_and_port_err,
		    IBMF_TNF_ERROR, "", "%s, status = %d\n", tnf_string, msg,
		    "query_hca_guid failed", tnf_uint, status, status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_validate_ci_guid_and_port_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_validate_ci_guid_and_port() exit\n");
		return (IBMF_BAD_NODE);
	}

	/* check if the specified port number is within the HCAs range */
	if (port_num > hca_attrs.hca_nports) {
		IBMF_TRACE_3(IBMF_TNF_NODEBUG, 1,
		    ibmf_i_validate_ci_guid_and_port_err, IBMF_TNF_ERROR, "",
		    "%s, num = %d, hca_ports = %d\n",
		    tnf_string, msg, "port num > valid ports",
		    tnf_uint, num, port_num, tnf_uint, hca_nports,
		    hca_attrs.hca_nports);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_validate_ci_guid_and_port_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_validate_ci_guid_and_port() exit\n");
		return (IBMF_BAD_PORT);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_validate_ci_guid_and_port_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_validate_ci_guid_and_port() exit\n");
	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_lookup_ci():
 * 	Lookup the ci and return if found. If the CI is not found, returns
 * 	NULL.
 */
static ibmf_ci_t *
ibmf_i_lookup_ci(ib_guid_t ci_guid)
{
	ibmf_ci_t	*cip = NULL;

	ASSERT(MUTEX_NOT_HELD(&ibmf_statep->ibmf_mutex));

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_lookup_ci_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_lookup_ci(): enter, guid = 0x%x\n",
	    tnf_uint64, guid, ci_guid);

	/* walk the CI list looking for one that matches the provided GUID */
	mutex_enter(&ibmf_statep->ibmf_mutex);
	cip = ibmf_statep->ibmf_ci_list;
	while (cip != (ibmf_ci_t *)NULL) {
		if (ci_guid == cip->ci_node_guid) {
			/* found it in our list */
			break;
		}
		cip = cip->ci_next;
	}
	mutex_exit(&ibmf_statep->ibmf_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_lookup_ci_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_lookup_ci() exit\n");

	return (cip);
}

/*
 * ibmf_i_get_ci():
 *	Get the CI structure based on the HCA GUID from a list if it exists.
 *	If the CI structure does not exist, and the HCA GUID is valid,
 *	create a new CI structure and add it to the list.
 */
int
ibmf_i_get_ci(ibmf_register_info_t *client_infop, ibmf_ci_t **cipp)
{
	ibmf_ci_t 		*cip;
	ibt_status_t		status;
	boolean_t		invalid = B_FALSE;
	ibt_hca_attr_t		hca_attrs;
	ibmf_port_kstat_t	*ksp;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_get_ci_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_get_ci() enter, clinfop = %p\n",
	    tnf_opaque, client_infop, client_infop);

	/* look for a CI context with a matching GUID */
	cip = ibmf_i_lookup_ci(client_infop->ir_ci_guid);

	if (cip == NULL) {

		/*
		 * attempt to create the ci. First, verify the ci exists.
		 * If it exists, allocate ci memory and insert in the ci list.
		 * It is possible that some other thread raced with us
		 * and inserted created ci while we are blocked in
		 * allocating memory. Check for that case and if that is indeed
		 * the case, free up what we allocated and try to get a
		 * reference count on the ci that the other thread added.
		 */
		status = ibt_query_hca_byguid(client_infop->ir_ci_guid,
		    &hca_attrs);
		if (status == IBT_SUCCESS) {

			ibmf_ci_t *tcip;
			char buf[128];

			/* allocate memory for the CI structure */
			cip = (ibmf_ci_t *)kmem_zalloc(sizeof (ibmf_ci_t),
			    KM_SLEEP);

			_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*cip))

			mutex_init(&cip->ci_mutex, NULL, MUTEX_DRIVER, NULL);
			mutex_init(&cip->ci_clients_mutex, NULL, MUTEX_DRIVER,
			    NULL);
			mutex_init(&cip->ci_wqe_mutex, NULL, MUTEX_DRIVER,
			    NULL);
			cv_init(&cip->ci_state_cv, NULL, CV_DRIVER, NULL);
			cv_init(&cip->ci_wqes_cv, NULL, CV_DRIVER, NULL);

			(void) sprintf(buf, "r%08X",
			    (uint32_t)client_infop->ir_ci_guid);
			mutex_enter(&cip->ci_mutex);

			cip->ci_state = IBMF_CI_STATE_PRESENT;
			cip->ci_node_guid = client_infop->ir_ci_guid;

			/* set up per CI kstats */
			(void) sprintf(buf, "ibmf_%016" PRIx64 "_%d_stat",
			    client_infop->ir_ci_guid,
			    client_infop->ir_port_num);
			if ((cip->ci_port_kstatp = kstat_create("ibmf", 0, buf,
			    "misc", KSTAT_TYPE_NAMED,
			    sizeof (ibmf_port_kstat_t) / sizeof (kstat_named_t),
			    KSTAT_FLAG_WRITABLE)) == NULL) {
				mutex_exit(&cip->ci_mutex);
				mutex_destroy(&cip->ci_mutex);
				mutex_destroy(&cip->ci_clients_mutex);
				mutex_destroy(&cip->ci_wqe_mutex);
				cv_destroy(&cip->ci_state_cv);
				cv_destroy(&cip->ci_wqes_cv);
				kmem_free((void *)cip, sizeof (ibmf_ci_t));
				IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
				    ibmf_i_get_ci_err, IBMF_TNF_ERROR, "",
				    "%s\n", tnf_string, msg,
				    "kstat create failed");
				IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
				    ibmf_i_get_ci_end, IBMF_TNF_TRACE, "",
				    "ibmf_i_get_ci() exit\n");
				return (IBMF_NO_RESOURCES);
			}
			ksp = (ibmf_port_kstat_t *)cip->ci_port_kstatp->ks_data;
			kstat_named_init(&ksp->clients_registered,
			    "clients_registered", KSTAT_DATA_UINT32);
			kstat_named_init(&ksp->client_regs_failed,
			    "client_registrations_failed", KSTAT_DATA_UINT32);
			kstat_named_init(&ksp->send_wqes_alloced,
			    "send_wqes_allocated", KSTAT_DATA_UINT32);
			kstat_named_init(&ksp->recv_wqes_alloced,
			    "receive_wqes_allocated", KSTAT_DATA_UINT32);
			kstat_named_init(&ksp->swqe_allocs_failed,
			    "send_wqe_allocs_failed", KSTAT_DATA_UINT32);
			kstat_named_init(&ksp->rwqe_allocs_failed,
			    "recv_wqe_allocs_failed", KSTAT_DATA_UINT32);
			kstat_install(cip->ci_port_kstatp);

			mutex_exit(&cip->ci_mutex);

			mutex_enter(&ibmf_statep->ibmf_mutex);

			tcip = ibmf_statep->ibmf_ci_list;
			while (tcip != (ibmf_ci_t *)NULL) {
				if (client_infop->ir_ci_guid ==
				    tcip->ci_node_guid) {
					/* found it in our list */
					break;
				}
				tcip = tcip->ci_next;
			}

			/* if the ci isn't on the list, add it */
			if (tcip == NULL) {
				cip->ci_next = NULL;

				_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*cip))

				if (ibmf_statep->ibmf_ci_list_tail != NULL)
					ibmf_statep->ibmf_ci_list_tail->
					    ci_next = cip;
				if (ibmf_statep->ibmf_ci_list == NULL)
					ibmf_statep->ibmf_ci_list = cip;
				ibmf_statep->ibmf_ci_list_tail = cip;

				mutex_enter(&cip->ci_mutex);
				cip->ci_init_state |= IBMF_CI_INIT_HCA_LINKED;
				mutex_exit(&cip->ci_mutex);

			} else {
				/* free cip and set it to the one on the list */
				kstat_delete(cip->ci_port_kstatp);
				mutex_destroy(&cip->ci_mutex);
				mutex_destroy(&cip->ci_clients_mutex);
				mutex_destroy(&cip->ci_wqe_mutex);
				cv_destroy(&cip->ci_state_cv);
				cv_destroy(&cip->ci_wqes_cv);
				kmem_free((void *)cip, sizeof (ibmf_ci_t));

				_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*cip))

				cip = tcip;
			}
			mutex_exit(&ibmf_statep->ibmf_mutex);
		} else {
			/* we didn't find it and the CI doesn't exist */
			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L1,
			    ibmf_i_get_ci_err, IBMF_TNF_ERROR, "", "%s\n",
			    tnf_string, msg, "GUID doesn't exist");
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_get_ci_end, IBMF_TNF_TRACE, "",
			    "ibmf_i_get_ci() exit\n");
			return (IBMF_TRANSPORT_FAILURE);
		}
	}

	ASSERT(cip != NULL);

	/*
	 * We now have a CI context structure, either found it on the list,
	 * or created it.
	 * We now proceed to intialize the CI context.
	 */
	for (;;) {
		mutex_enter(&cip->ci_mutex);

		/* CI is INITED & no state change in progress; we are all set */
		if (cip->ci_state == IBMF_CI_STATE_INITED && (cip->
		    ci_state_flags & (IBMF_CI_STATE_INVALIDATING |
		    IBMF_CI_STATE_UNINITING)) == 0) {

			cip->ci_ref++;
			mutex_exit(&cip->ci_mutex);

			break;
		}

		/* CI is PRESENT; transition it to INITED */
		if (cip->ci_state == IBMF_CI_STATE_PRESENT && (cip->
		    ci_state_flags & (IBMF_CI_STATE_INVALIDATING |
		    IBMF_CI_STATE_INITING)) == 0) {

			/* mark state as initing and init the ci */
			cip->ci_state_flags |= IBMF_CI_STATE_INITING;
			mutex_exit(&cip->ci_mutex);

			_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*cip))

			if (ibmf_i_init_ci(client_infop, cip) != IBMF_SUCCESS) {
				invalid = B_TRUE;
				break;
			}

			_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*cip))

			continue;
		}

		/*
		 * If CI is GONE and no validation is in progress, we should
		 * return failure. Also, if CI is INITED but in the process of
		 * being made GONE (ie., a hot remove in progress), return
		 * failure.
		 */
		if ((cip->ci_state == IBMF_CI_STATE_GONE && (cip->
		    ci_state_flags & IBMF_CI_STATE_VALIDATING) == 0) ||
		    (cip->ci_state == IBMF_CI_STATE_INITED && (cip->
		    ci_state_flags & IBMF_CI_STATE_INVALIDATING) != 0)) {

			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_get_ci_err, IBMF_TNF_ERROR, "",
			    "ci_state = %x, ci_state_flags = %x\n",
			    tnf_opaque, cip->ci_state, cip->ci_state,
			    tnf_opaque, cip->ci_state_flags,
			    cip->ci_state_flags);

			invalid = B_TRUE;
			mutex_exit(&cip->ci_mutex);

			break;
		}

		/* a state change in progress; block waiting for state change */
		if (cip->ci_state_flags & IBMF_CI_STATE_VALIDATING)
			cip->ci_state_flags |= IBMF_CI_STATE_VALIDATE_WAIT;
		else if (cip->ci_state_flags & IBMF_CI_STATE_INITING)
			cip->ci_state_flags |= IBMF_CI_STATE_INIT_WAIT;
		else if (cip->ci_state_flags & IBMF_CI_STATE_UNINITING)
			cip->ci_state_flags |= IBMF_CI_STATE_UNINIT_WAIT;

		cv_wait(&cip->ci_state_cv, &cip->ci_mutex);

		mutex_exit(&cip->ci_mutex);
	}

	if (invalid == B_TRUE) {
		IBMF_TRACE_0(IBMF_TNF_NODEBUG, DPRINT_L2, ibmf_i_get_ci_err,
		    IBMF_TNF_ERROR, "", "ibmf_i_get_ci() error\n");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_get_ci_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_get_ci() exit\n");
		return (IBMF_FAILURE);
	}

	if (cip != NULL) {
		*cipp = cip;
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_get_ci_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_get_ci() exit\n");
		return (IBMF_SUCCESS);
	} else {
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_get_ci_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_get_ci() exit\n");
		return (IBMF_FAILURE);
	}
}

/*
 * ibmf_i_release_ci():
 *	Drop the reference count for the CI.
 */
void
ibmf_i_release_ci(ibmf_ci_t *cip)
{
	uint_t ref;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_release_ci_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_release_ci() enter, cip = %p\n",
	    tnf_opaque, cip, cip);

	ASSERT(MUTEX_NOT_HELD(&cip->ci_mutex));

	mutex_enter(&cip->ci_mutex);
	ref = cip->ci_ref--;
	if (ref == 1) {
		ASSERT(cip->ci_state == IBMF_CI_STATE_INITED);
		cip->ci_state_flags |= IBMF_CI_STATE_UNINITING;
	}
	mutex_exit(&cip->ci_mutex);

	if (ref == 1) {
		ibmf_i_uninit_ci(cip);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_release_ci_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_release_ci() exit\n");
}

/*
 * ibmf_i_init_ci():
 *	Initialize the CI structure by setting up the HCA, allocating
 *	protection domains, completion queues, a pool of WQEs.
 */
/* ARGSUSED */
static int
ibmf_i_init_ci(ibmf_register_info_t *client_infop, ibmf_ci_t *cip)
{
	ibt_pd_hdl_t		pd;
	ibt_status_t		status;
	ib_guid_t		ci_guid;
	ibt_hca_attr_t		hca_attrs;
	ibt_hca_hdl_t		hca_handle;
	ibt_pd_flags_t		pd_flags = IBT_PD_NO_FLAGS;
	boolean_t		error = B_FALSE;
	int			ibmfstatus = IBMF_SUCCESS;
	char			errmsg[128];

	_NOTE(ASSUMING_PROTECTED(*cip))

	ASSERT(MUTEX_NOT_HELD(&ibmf_statep->ibmf_mutex));
	ASSERT(MUTEX_NOT_HELD(&cip->ci_mutex));

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_ci_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_ci() enter, cip = %p\n",
	    tnf_opaque, ibmf_ci, cip);

	mutex_enter(&cip->ci_mutex);
	ci_guid = cip->ci_node_guid;
	ASSERT(cip->ci_state == IBMF_CI_STATE_PRESENT);
	ASSERT((cip->ci_state_flags & IBMF_CI_STATE_INITING) != 0);
	mutex_exit(&cip->ci_mutex);

	/* set up a connection to the HCA specified by the GUID */
	status = ibt_open_hca(ibmf_statep->ibmf_ibt_handle, ci_guid,
	    &hca_handle);
	ASSERT(status != IBT_HCA_IN_USE);
	if (status != IBT_SUCCESS) {
		ibmf_i_init_ci_done(cip);
		(void) sprintf(errmsg, "ibt open hca failed, status = 0x%x",
		    status);
		error = B_TRUE;
		ibmfstatus = IBMF_TRANSPORT_FAILURE;
		goto bail;
	}

	/* get the HCA attributes */
	status = ibt_query_hca(hca_handle, &hca_attrs);
	if (status != IBT_SUCCESS) {
		(void) ibt_close_hca(hca_handle);
		ibmf_i_init_ci_done(cip);
		(void) sprintf(errmsg, "ibt query hca failed, status = 0x%x",
		    status);
		error = B_TRUE;
		ibmfstatus = IBMF_TRANSPORT_FAILURE;
		goto bail;
	}

	/* allocate a Protection Domain */
	status = ibt_alloc_pd(hca_handle, pd_flags, &pd);
	if (status != IBT_SUCCESS) {
		(void) ibt_close_hca(hca_handle);
		ibmf_i_init_ci_done(cip);
		(void) sprintf(errmsg, "alloc PD failed, status = 0x%x",
		    status);
		error = B_TRUE;
		ibmfstatus = IBMF_TRANSPORT_FAILURE;
		goto bail;
	}

	/* init the ci */
	mutex_enter(&cip->ci_mutex);
	cip->ci_nports = hca_attrs.hca_nports;
	cip->ci_vendor_id = hca_attrs.hca_vendor_id;
	cip->ci_device_id = hca_attrs.hca_device_id;
	cip->ci_ci_handle = hca_handle;
	cip->ci_pd = pd;
	cip->ci_init_state |= IBMF_CI_INIT_HCA_INITED;
	mutex_exit(&cip->ci_mutex);

	/* initialize cqs */
	if (ibmf_i_init_cqs(cip) != IBMF_SUCCESS) {
		(void) ibt_free_pd(cip->ci_ci_handle, cip->ci_pd);
		mutex_enter(&cip->ci_mutex);
		cip->ci_init_state &= ~IBMF_CI_INIT_HCA_INITED;
		mutex_exit(&cip->ci_mutex);
		(void) ibt_close_hca(cip->ci_ci_handle);
		ibmf_i_init_ci_done(cip);
		(void) sprintf(errmsg, "init CQs failed");
		error = B_TRUE;
		ibmfstatus = IBMF_FAILURE;
		goto bail;
	}

	/* initialize wqes */
	if (ibmf_i_init_wqes(cip) != IBMF_SUCCESS) {
		ibmf_i_fini_cqs(cip);
		(void) ibt_free_pd(cip->ci_ci_handle, cip->ci_pd);
		mutex_enter(&cip->ci_mutex);
		cip->ci_init_state &= ~IBMF_CI_INIT_HCA_INITED;
		mutex_exit(&cip->ci_mutex);
		(void) ibt_close_hca(cip->ci_ci_handle);
		ibmf_i_init_ci_done(cip);
		(void) sprintf(errmsg, "init WQEs failed");
		error = B_TRUE;
		ibmfstatus = IBMF_FAILURE;
		goto bail;
	}

	/* initialize the UD destination structure pool */
	ibmf_i_init_ud_dest(cip);

	/* initialize the QP list */
	ibmf_i_init_qplist(cip);

	/* initialize condition variable, state, and enable CQ notification */
	cip->ci_init_state |= IBMF_CI_INIT_MUTEX_CV_INITED;
	(void) ibt_enable_cq_notify(cip->ci_cq_handle, IBT_NEXT_COMPLETION);
	(void) ibt_enable_cq_notify(cip->ci_alt_cq_handle, IBT_NEXT_COMPLETION);

	/* set state to INITED */
	mutex_enter(&cip->ci_mutex);
	cip->ci_state = IBMF_CI_STATE_INITED;
	mutex_exit(&cip->ci_mutex);

	/* wake up waiters blocked on an initialization done event */
	ibmf_i_init_ci_done(cip);

bail:
	if (error) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1, ibmf_i_init_ci_err,
		    IBMF_TNF_ERROR, "", "%s, status = %d\n", tnf_string, msg,
		    errmsg, tnf_uint, ibmfstatus, ibmfstatus);
	}

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_ci_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_ci() exit, cip = %p\n",
	    tnf_opaque, ibmf_ci, cip);

	return (ibmfstatus);
}

/*
 * ibmf_i_uninit_ci():
 *	Free up the resources allocated when initalizing the CI structure.
 */
static void
ibmf_i_uninit_ci(ibmf_ci_t *cip)
{
	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_uninit_ci_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_uninit_ci() enter, cip = %p\n",
	    tnf_opaque, cip, cip);

	ASSERT(MUTEX_HELD(&cip->ci_mutex) == 0);

	/* clean up the QP list */
	ibmf_i_fini_qplist(cip);

	/* empty completions directly */
	ibmf_i_mad_completions(cip->ci_cq_handle, (void*)cip);
	ibmf_i_mad_completions(cip->ci_alt_cq_handle, (void*)cip);

	mutex_enter(&cip->ci_mutex);
	if (cip->ci_init_state & IBMF_CI_INIT_MUTEX_CV_INITED) {
		cip->ci_init_state &= ~IBMF_CI_INIT_MUTEX_CV_INITED;
	}
	mutex_exit(&cip->ci_mutex);

	/* clean up the UD destination structure pool */
	ibmf_i_fini_ud_dest(cip);

	/* clean up any WQE caches */
	ibmf_i_fini_wqes(cip);

	/* free up the completion queues */
	ibmf_i_fini_cqs(cip);

	/* free up the protection domain */
	(void) ibt_free_pd(cip->ci_ci_handle, cip->ci_pd);

	/* close the HCA connection */
	(void) ibt_close_hca(cip->ci_ci_handle);

	/* set state down to PRESENT */
	mutex_enter(&cip->ci_mutex);
	cip->ci_init_state &= ~IBMF_CI_INIT_HCA_INITED;
	cip->ci_state = IBMF_CI_STATE_PRESENT;
	mutex_exit(&cip->ci_mutex);

	/* wake up waiters blocked on an un-initialization done event */
	ibmf_i_uninit_ci_done(cip);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_uninit_ci_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_uninit_ci() exit\n");
}

/*
 * ibmf_i_init_ci_done():
 *	Mark CI initialization as "done", and wake up any waiters.
 */
static void
ibmf_i_init_ci_done(ibmf_ci_t *cip)
{
	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_ci_done_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_ci_done() enter, cip = %p\n",
	    tnf_opaque, cip, cip);

	mutex_enter(&cip->ci_mutex);
	cip->ci_state_flags &= ~IBMF_CI_STATE_INITING;
	if (cip->ci_state_flags & IBMF_CI_STATE_INIT_WAIT) {
		cip->ci_state_flags &= ~IBMF_CI_STATE_INIT_WAIT;
		cv_broadcast(&cip->ci_state_cv);
	}
	mutex_exit(&cip->ci_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_ci_done_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_ci_done() exit\n");
}

/*
 * ibmf_i_uninit_ci_done():
 *	Mark CI uninitialization as "done", and wake up any waiters.
 */
static void
ibmf_i_uninit_ci_done(ibmf_ci_t *cip)
{
	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_uninit_ci_done_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_uninit_ci_done() enter, cip = %p\n",
	    tnf_opaque, cip, cip);

	mutex_enter(&cip->ci_mutex);
	cip->ci_state_flags &= ~IBMF_CI_STATE_UNINITING;
	if (cip->ci_state_flags & IBMF_CI_STATE_UNINIT_WAIT) {
		cip->ci_state_flags &= ~IBMF_CI_STATE_UNINIT_WAIT;
		cv_broadcast(&cip->ci_state_cv);
	}
	mutex_exit(&cip->ci_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_uninit_ci_done_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_uninit_ci_done() exit\n");
}

/*
 * ibmf_i_init_cqs():
 *	Allocate a completion queue and set the CQ handler.
 */
static int
ibmf_i_init_cqs(ibmf_ci_t *cip)
{
	ibt_status_t		status;
	ibt_cq_attr_t		cq_attrs;
	ibt_cq_hdl_t		cq_handle;
	uint32_t		num_entries;

	ASSERT(MUTEX_NOT_HELD(&cip->ci_mutex));

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_cqs_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_cqs() enter, cip = %p\n",
	    tnf_opaque, cip, cip);

	/*
	 * Allocate completion queue handle.
	 * The CQ size should be a 2^n - 1 value to avoid excess CQ allocation
	 * as done by some HCAs when the CQ size is specified as a 2^n
	 * quantity.
	 */
	cq_attrs.cq_size = (cip->ci_nports * (ibmf_send_wqes_posted_per_qp +
	    ibmf_recv_wqes_posted_per_qp)) - 1;

	cq_attrs.cq_sched = NULL;
	cq_attrs.cq_flags = 0;

	/* Get the CQ handle for the special QPs */
	status = ibt_alloc_cq(cip->ci_ci_handle, &cq_attrs,
	    &cq_handle, &num_entries);
	if (status != IBT_SUCCESS) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1, ibmf_i_init_cqs_err,
		    IBMF_TNF_ERROR, "", "%s, status = %d\n", tnf_string, msg,
		    "ibt_alloc_cq failed", tnf_uint, ibt_status, status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_cqs_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_init_cqs() exit\n");
		return (IBMF_TRANSPORT_FAILURE);
	}
	ibt_set_cq_handler(cq_handle, ibmf_statep->ibmf_cq_handler, cip);
	cip->ci_cq_handle = cq_handle;

	/* Get the CQ handle for the alternate QPs */
	status = ibt_alloc_cq(cip->ci_ci_handle, &cq_attrs,
	    &cq_handle, &num_entries);
	if (status != IBT_SUCCESS) {
		(void) ibt_free_cq(cip->ci_cq_handle);
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1, ibmf_i_init_cqs_err,
		    IBMF_TNF_ERROR, "", "%s, status = %d\n", tnf_string, msg,
		    "ibt_alloc_cq failed", tnf_uint, ibt_status, status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_cqs_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_init_cqs() exit\n");
		return (IBMF_TRANSPORT_FAILURE);
	}
	ibt_set_cq_handler(cq_handle, ibmf_statep->ibmf_cq_handler, cip);
	cip->ci_alt_cq_handle = cq_handle;

	/* set state to CQ INITED */
	mutex_enter(&cip->ci_mutex);
	cip->ci_init_state |= IBMF_CI_INIT_CQ_INITED;
	mutex_exit(&cip->ci_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_cqs_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_cqs() exit\n");

	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_fini_cqs():
 *	Free up the completion queue
 */
static void
ibmf_i_fini_cqs(ibmf_ci_t *cip)
{
	ibt_status_t	status;
	uint_t		ci_init_state;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_fini_cqs_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_fini_cqs() enter, cip = %p\n",
	    tnf_opaque, cip, cip);

	mutex_enter(&cip->ci_mutex);
	ci_init_state = cip->ci_init_state;
	cip->ci_init_state &= ~IBMF_CI_INIT_CQ_INITED;
	mutex_exit(&cip->ci_mutex);

	if (ci_init_state & IBMF_CI_INIT_CQ_INITED) {
		status = ibt_free_cq(cip->ci_alt_cq_handle);
		if (status != IBT_SUCCESS) {
			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L3,
			    ibmf_i_fini_cqs_err, IBMF_TNF_ERROR, "",
			    "%s, status = %d\n", tnf_string, msg,
			    "ibt free cqs failed", tnf_uint, status, status);
		}

		status = ibt_free_cq(cip->ci_cq_handle);
		if (status != IBT_SUCCESS) {
			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L3,
			    ibmf_i_fini_cqs_err, IBMF_TNF_ERROR, "",
			    "%s, status = %d\n", tnf_string, msg,
			    "ibt free cqs failed", tnf_uint, status, status);
		}
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_fini_cqs_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_fini_cqs() exit");
}

/*
 * ibmf_i_init_qplist():
 *	Set the QP list inited state flag
 */
static void
ibmf_i_init_qplist(ibmf_ci_t *ibmf_cip)
{
	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_qplist_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_qplist() enter, cip = %p\n",
	    tnf_opaque, cip, ibmf_cip);

	mutex_enter(&ibmf_cip->ci_mutex);
	ASSERT((ibmf_cip->ci_init_state & IBMF_CI_INIT_QP_LIST_INITED) == 0);
	ASSERT(ibmf_cip->ci_qp_list == NULL && ibmf_cip->ci_qp_list_tail ==
	    NULL);
	cv_init(&ibmf_cip->ci_qp_cv, NULL, CV_DRIVER, NULL);
	ibmf_cip->ci_init_state |= IBMF_CI_INIT_QP_LIST_INITED;
	mutex_exit(&ibmf_cip->ci_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_qplist_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_qplist() exit\n");
}

/*
 * ibmf_i_fini_qplist():
 *	Clean up the QP list
 */
static void
ibmf_i_fini_qplist(ibmf_ci_t *ibmf_cip)
{
	ibmf_qp_t *qpp;
	ibmf_alt_qp_t *altqpp;
	ibt_status_t status;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_fini_qplist_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_fini_qplist() enter, cip = %p\n",
	    tnf_opaque, cip, ibmf_cip);

	mutex_enter(&ibmf_cip->ci_mutex);

	if ((ibmf_cip->ci_init_state & IBMF_CI_INIT_QP_LIST_INITED) != 0) {

		/* walk through the qp list and free the memory */
		qpp = ibmf_cip->ci_qp_list;
		while (qpp != NULL) {
			/* Remove qpp from the list */
			ibmf_cip->ci_qp_list = qpp->iq_next;

			ASSERT(qpp->iq_qp_ref == 0);
			ASSERT(qpp->iq_flags == IBMF_QP_FLAGS_INVALID);
			mutex_exit(&ibmf_cip->ci_mutex);
			if (qpp->iq_qp_handle != NULL) {
				/* Flush the special QP */
				status = ibt_flush_qp(qpp->iq_qp_handle);
				if (status != IBT_SUCCESS) {
					IBMF_TRACE_2(IBMF_TNF_NODEBUG,
					    DPRINT_L1, ibmf_i_fini_qplist_err,
					    IBMF_TNF_ERROR, "",
					    "%s, status = %d\n", tnf_string,
					    msg, "ibt_flush_qp returned error",
					    tnf_int, status, status);
				}

				/* Grab the ci_mutex mutex before waiting */
				mutex_enter(&ibmf_cip->ci_mutex);

				/* Wait if WQEs for special QPs are alloced */
				while (ibmf_cip->ci_wqes_alloced != 0) {
					cv_wait(&ibmf_cip->ci_wqes_cv,
					    &ibmf_cip->ci_mutex);
				}

				mutex_exit(&ibmf_cip->ci_mutex);

				/* Free the special QP */
				status = ibt_free_qp(qpp->iq_qp_handle);
				if (status != IBT_SUCCESS) {
					IBMF_TRACE_2(IBMF_TNF_NODEBUG,
					    DPRINT_L1, ibmf_i_fini_qplist_err,
					    IBMF_TNF_ERROR, "",
					    "%s, status = %d\n", tnf_string,
					    msg, "ibt_free_qp returned error",
					    tnf_int, status, status);
				}
			}
			mutex_destroy(&qpp->iq_mutex);
			kmem_free((void *)qpp, sizeof (ibmf_qp_t));

			/* Grab the mutex again before accessing the QP list */
			mutex_enter(&ibmf_cip->ci_mutex);
			qpp = ibmf_cip->ci_qp_list;
		}

		cv_destroy(&ibmf_cip->ci_qp_cv);

		ibmf_cip->ci_qp_list = ibmf_cip->ci_qp_list_tail = NULL;
		ibmf_cip->ci_init_state &=  ~IBMF_CI_INIT_QP_LIST_INITED;

		altqpp = ibmf_cip->ci_alt_qp_list;
		while (altqpp != NULL) {
			/* Remove altqpp from the list */
			ibmf_cip->ci_alt_qp_list = altqpp->isq_next;
			mutex_exit(&ibmf_cip->ci_mutex);

			if (altqpp->isq_qp_handle != NULL) {
				/* Flush the special QP */
				status = ibt_flush_qp(altqpp->isq_qp_handle);
				if (status != IBT_SUCCESS) {
					IBMF_TRACE_2(IBMF_TNF_NODEBUG,
					    DPRINT_L1, ibmf_i_fini_qplist_err,
					    IBMF_TNF_ERROR, "",
					    "%s, status = %d\n", tnf_string,
					    msg, "ibt_flush_qp returned error",
					    tnf_int, status, status);
				}

				/* Free the special QP */
				status = ibt_free_qp(altqpp->isq_qp_handle);
				if (status != IBT_SUCCESS) {
					IBMF_TRACE_2(IBMF_TNF_NODEBUG,
					    DPRINT_L1, ibmf_i_fini_qplist_err,
					    IBMF_TNF_ERROR, "",
					    "%s, status = %d\n", tnf_string,
					    msg, "ibt_free_qp returned error",
					    tnf_int, status, status);
				}
			}
			mutex_destroy(&altqpp->isq_mutex);
			kmem_free((void *)altqpp, sizeof (ibmf_alt_qp_t));

			/* Grab the mutex again before accessing the QP list */
			mutex_enter(&ibmf_cip->ci_mutex);
			altqpp = ibmf_cip->ci_alt_qp_list;
		}
	}

	mutex_exit(&ibmf_cip->ci_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_fini_qplist_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_fini_qplist() exit\n");
}

/*
 * ibmf_i_alloc_client():
 *	Allocate and initialize the client structure.
 */
int
ibmf_i_alloc_client(ibmf_register_info_t *client_infop, uint_t flags,
    ibmf_client_t **clientpp)
{
	ibmf_client_t		*ibmf_clientp;
	char			buf[128];
	ibmf_kstat_t		*ksp;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_alloc_client_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_alloc_client() enter, "
	    "client_infop = %p\n", tnf_opaque, client_infop, client_infop);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ibmf_clientp))

	/* allocate memory for ibmf_client and initialize it */
	ibmf_clientp = kmem_zalloc(sizeof (ibmf_client_t), KM_SLEEP);
	mutex_init(&ibmf_clientp->ic_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ibmf_clientp->ic_msg_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ibmf_clientp->ic_kstat_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ibmf_clientp->ic_recv_cb_teardown_cv, NULL, CV_DRIVER, NULL);

	(void) sprintf(buf, "s%08X_0x%08X",
	    (uint32_t)client_infop->ir_ci_guid, client_infop->ir_client_class);

	/* create a taskq to handle send completions based on reg flags */
	if ((flags & IBMF_REG_FLAG_NO_OFFLOAD) == 0) {
		if (flags & IBMF_REG_FLAG_SINGLE_OFFLOAD)
			ibmf_clientp->ic_send_taskq = taskq_create(buf,
			    IBMF_TASKQ_1THREAD, MINCLSYSPRI, 1,
			    ibmf_taskq_max_tasks, TASKQ_PREPOPULATE);
		else
			ibmf_clientp->ic_send_taskq = taskq_create(buf,
			    IBMF_TASKQ_NTHREADS, MINCLSYSPRI, 1,
			    ibmf_taskq_max_tasks,
			    TASKQ_DYNAMIC | TASKQ_PREPOPULATE);
		if (ibmf_clientp->ic_send_taskq == NULL) {
			cv_destroy(&ibmf_clientp->ic_recv_cb_teardown_cv);
			mutex_destroy(&ibmf_clientp->ic_mutex);
			mutex_destroy(&ibmf_clientp->ic_msg_mutex);
			mutex_destroy(&ibmf_clientp->ic_kstat_mutex);
			kmem_free((void *)ibmf_clientp, sizeof (ibmf_client_t));
			IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_alloc_client_err, IBMF_TNF_ERROR, "", "%s\n",
			    tnf_string, msg, buf);
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_alloc_client_end, IBMF_TNF_TRACE, "",
			    "ibmf_i_alloc_client() exit\n");
			return (IBMF_NO_RESOURCES);
		}
	}
	ibmf_clientp->ic_init_state_class |= IBMF_CI_INIT_SEND_TASKQ_DONE;

	(void) sprintf(buf, "r%08X_0x%08X",
	    (uint32_t)client_infop->ir_ci_guid, client_infop->ir_client_class);

	/* create a taskq to handle receive completions on reg flags */
	if ((flags & IBMF_REG_FLAG_NO_OFFLOAD) == 0) {
		if (flags & IBMF_REG_FLAG_SINGLE_OFFLOAD)
			ibmf_clientp->ic_recv_taskq = taskq_create(buf,
			    IBMF_TASKQ_1THREAD, MINCLSYSPRI, 1,
			    ibmf_taskq_max_tasks, TASKQ_PREPOPULATE);
		else
			ibmf_clientp->ic_recv_taskq = taskq_create(buf,
			    IBMF_TASKQ_NTHREADS, MINCLSYSPRI, 1,
			    ibmf_taskq_max_tasks,
			    TASKQ_DYNAMIC | TASKQ_PREPOPULATE);
		if (ibmf_clientp->ic_recv_taskq == NULL) {
			cv_destroy(&ibmf_clientp->ic_recv_cb_teardown_cv);
			mutex_destroy(&ibmf_clientp->ic_mutex);
			mutex_destroy(&ibmf_clientp->ic_msg_mutex);
			mutex_destroy(&ibmf_clientp->ic_kstat_mutex);
			taskq_destroy(ibmf_clientp->ic_send_taskq);
			kmem_free((void *)ibmf_clientp, sizeof (ibmf_client_t));
			IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_alloc_client_err, IBMF_TNF_ERROR, "", "%s\n",
			    tnf_string, msg, buf);
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_alloc_client_end, IBMF_TNF_TRACE, "",
			    "ibmf_i_alloc_client() exit\n");
			return (IBMF_NO_RESOURCES);
		}
	}
	ibmf_clientp->ic_init_state_class |= IBMF_CI_INIT_RECV_TASKQ_DONE;
	ibmf_clientp->ic_client_info.ci_guid = client_infop->ir_ci_guid;
	ibmf_clientp->ic_client_info.port_num = client_infop->ir_port_num;

	/* Get the base LID */
	(void) ibt_get_port_state_byguid(ibmf_clientp->ic_client_info.ci_guid,
	    ibmf_clientp->ic_client_info.port_num, NULL,
	    &ibmf_clientp->ic_base_lid);

	ibmf_clientp->ic_client_info.client_class =
	    client_infop->ir_client_class;

	/* set up the per client ibmf kstats */
	(void) sprintf(buf, "ibmf_%016" PRIx64 "_%d_%X_stat",
	    client_infop->ir_ci_guid, client_infop->ir_port_num,
	    client_infop->ir_client_class);
	if ((ibmf_clientp->ic_kstatp = kstat_create("ibmf", 0, buf, "misc",
	    KSTAT_TYPE_NAMED, sizeof (ibmf_kstat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_WRITABLE)) == NULL) {
		cv_destroy(&ibmf_clientp->ic_recv_cb_teardown_cv);
		mutex_destroy(&ibmf_clientp->ic_mutex);
		mutex_destroy(&ibmf_clientp->ic_msg_mutex);
		mutex_destroy(&ibmf_clientp->ic_kstat_mutex);
		if ((flags & IBMF_REG_FLAG_NO_OFFLOAD) == 0) {
			taskq_destroy(ibmf_clientp->ic_send_taskq);
			taskq_destroy(ibmf_clientp->ic_recv_taskq);
		}
		kmem_free((void *)ibmf_clientp, sizeof (ibmf_client_t));
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_alloc_client_err, IBMF_TNF_ERROR, "", "%s\n",
		    tnf_string, msg, "kstat creation failed");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_alloc_client_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_alloc_client() exit\n");
		return (IBMF_NO_RESOURCES);
	}
	ksp = (ibmf_kstat_t *)ibmf_clientp->ic_kstatp->ks_data;
	kstat_named_init(&ksp->msgs_alloced, "messages_allocated",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&ksp->msgs_active, "messages_active",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&ksp->msgs_sent, "messages_sent", KSTAT_DATA_UINT32);
	kstat_named_init(&ksp->msgs_received, "messages_received",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&ksp->sends_active, "sends_active", KSTAT_DATA_UINT32);
	kstat_named_init(&ksp->recvs_active, "receives_active",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&ksp->ud_dests_alloced, "ud_dests_allocated",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&ksp->alt_qps_alloced, "alt_qps_allocated",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&ksp->send_cb_active, "send_callbacks_active",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&ksp->recv_cb_active, "receive_callbacks_active",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&ksp->recv_bufs_alloced, "receive_bufs_allocated",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&ksp->msg_allocs_failed, "msg_allocs_failed",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&ksp->uddest_allocs_failed, "uddest_allocs_failed",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&ksp->alt_qp_allocs_failed, "alt_qp_allocs_failed",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&ksp->send_pkt_failed, "send_pkt_failed",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&ksp->rmpp_errors, "rmpp_errors",
	    KSTAT_DATA_UINT32);

	kstat_install(ibmf_clientp->ic_kstatp);

	*clientpp = ibmf_clientp;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*ibmf_clientp))

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_alloc_client_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_alloc_client() exit\n");

	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_free_client():
 *	Free up the client structure and release resources
 */
void
ibmf_i_free_client(ibmf_client_t *clientp)
{
	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_free_client_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_free_client() enter, clientp = %p\n",
	    tnf_opaque, clientp, clientp);

	/* delete the general ibmf kstats */
	if (clientp->ic_kstatp != NULL) {
		kstat_delete(clientp->ic_kstatp);
		clientp->ic_kstatp = NULL;
	}

	/* release references and destroy the resources */
	if (clientp->ic_init_state_class & IBMF_CI_INIT_SEND_TASKQ_DONE) {
		if ((clientp->ic_reg_flags & IBMF_REG_FLAG_NO_OFFLOAD) == 0) {
			taskq_destroy(clientp->ic_send_taskq);
		}
		clientp->ic_init_state_class &= ~IBMF_CI_INIT_SEND_TASKQ_DONE;
	}

	if (clientp->ic_init_state_class & IBMF_CI_INIT_RECV_TASKQ_DONE) {
		if ((clientp->ic_reg_flags & IBMF_REG_FLAG_NO_OFFLOAD) == 0) {
			taskq_destroy(clientp->ic_recv_taskq);
		}
		clientp->ic_init_state_class &= ~IBMF_CI_INIT_RECV_TASKQ_DONE;
	}

	mutex_destroy(&clientp->ic_mutex);
	mutex_destroy(&clientp->ic_msg_mutex);
	mutex_destroy(&clientp->ic_kstat_mutex);
	cv_destroy(&clientp->ic_recv_cb_teardown_cv);
	kmem_free((void *)clientp, sizeof (ibmf_client_t));

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_free_client_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_free_client() exit\n");
}

/*
 * ibmf_i_validate_classes_and_port():
 *	Validate the class type and get the client structure
 */
int
ibmf_i_validate_classes_and_port(ibmf_ci_t *ibmf_cip,
    ibmf_register_info_t *client_infop)
{
	ibmf_client_t		*ibmf_clientp;
	int			status;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_validate_classes_and_port_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_validate_classes_and_port() enter, cip = %p, "
	    "clientp = %p\n", tnf_opaque, cip, ibmf_cip,
	    tnf_opaque, client_infop, client_infop);

	/*
	 * the Solaris implementation of IBMF does not support
	 * the UNIVERSAL_CLASS
	 */
	if (client_infop->ir_client_class == UNIVERSAL_CLASS) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_validate_classes_and_port_err, IBMF_TNF_ERROR, "",
		    "%s\n", tnf_string, msg,
		    "UNIVERSAL class is not supported");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_validate_classes_and_port_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_validate_classes_and_port() exit\n");
		return (IBMF_NOT_SUPPORTED);
	}

	/*
	 * Check if the client context already exists on the list
	 * maintained in the CI context. If it is, then the client class
	 * has already been registered for.
	 */
	status = ibmf_i_lookup_client_by_info(ibmf_cip, client_infop,
	    &ibmf_clientp);
	if (status != IBMF_SUCCESS) {
		/* client class has not been previously registered for */
		status = IBMF_SUCCESS;
	} else {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_validate_classes_and_port_err, IBMF_TNF_ERROR, "",
		    "client already registered, class = 0x%X\n",
		    tnf_uint, class, client_infop->ir_client_class);
		status = IBMF_PORT_IN_USE;
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_validate_classes_and_port_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_validate_classes_and_port() exit\n");
	return (status);
}

/*
 * ibmf_i_lookup_client_by_info():
 *	Get the client structure from the list
 */
static int
ibmf_i_lookup_client_by_info(ibmf_ci_t *ibmf_cip,
    ibmf_register_info_t *ir_client, ibmf_client_t **clientpp)
{
	ibmf_client_t *clientp;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_lookup_client_by_info_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_lookup_client_by_info() enter, cip = %p, clientinfo = %p\n",
	    tnf_opaque, cip, ibmf_cip, tnf_opaque, clientinfo, ir_client);

	ASSERT(MUTEX_NOT_HELD(&ibmf_cip->ci_clients_mutex));

	/*
	 * walk the CI's client list searching for one with the specified class
	 */
	mutex_enter(&ibmf_cip->ci_clients_mutex);
	clientp = ibmf_cip->ci_clients;
	while (clientp != NULL) {
		ibmf_client_info_t *tmp = &clientp->ic_client_info;
		if (tmp->client_class == ir_client->ir_client_class &&
		    ir_client->ir_client_class != UNIVERSAL_CLASS &&
		    tmp->ci_guid == ir_client->ir_ci_guid &&
		    tmp->port_num == ir_client->ir_port_num) {
			/* found our match */
			break;
		}
		clientp = clientp->ic_next;
	}
	mutex_exit(&ibmf_cip->ci_clients_mutex);

	if (clientp != NULL) {
		*clientpp = clientp;
		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_lookup_client_by_info_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_lookup_client_by_info(): clientp = %p\n",
		    tnf_opaque, clientp, clientp);
		return (IBMF_SUCCESS);
	} else {
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_lookup_client_by_info_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_lookup_client_by_info() exit\n");
		return (IBMF_FAILURE);
	}
}

/*
 * ibmf_i_add_client():
 *	Add a new client to the client list
 */
void
ibmf_i_add_client(ibmf_ci_t *ibmf_cip, ibmf_client_t *ibmf_clientp)
{
	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_add_start,
	    IBMF_TNF_TRACE, "",
	    "ibmf_i_add_client() enter, cip = %p, clientp = %p\n",
	    tnf_opaque, ibmf_ci, ibmf_cip, tnf_opaque, client, ibmf_clientp);

	ASSERT(MUTEX_NOT_HELD(&ibmf_cip->ci_clients_mutex));

	mutex_enter(&ibmf_cip->ci_clients_mutex);
	ibmf_clientp->ic_next = NULL;
	ibmf_clientp->ic_prev = ibmf_cip->ci_clients_last;
	if (ibmf_cip->ci_clients == NULL) {
		ibmf_cip->ci_clients = ibmf_clientp;
	}
	if (ibmf_cip->ci_clients_last) {
		ibmf_cip->ci_clients_last->ic_next = ibmf_clientp;
	}
	ibmf_cip->ci_clients_last = ibmf_clientp;
	mutex_exit(&ibmf_cip->ci_clients_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_add_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_add_client() exit\n");
}

/*
 * ibmf_i_delete_client():
 *	Delete a client from the client list
 */
void
ibmf_i_delete_client(ibmf_ci_t *ibmf_cip, ibmf_client_t *ibmf_clientp)
{
	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_delete_client_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_delete_client() enter, "
	    "ibmf_i_delete_client() enter, cip = %p, clientp = %p\n",
	    tnf_opaque, ibmf_ci, ibmf_cip, tnf_opaque, client, ibmf_clientp);

	ASSERT(MUTEX_NOT_HELD(&ibmf_cip->ci_clients_mutex));

	mutex_enter(&ibmf_cip->ci_clients_mutex);
	if (ibmf_clientp->ic_next)
		ibmf_clientp->ic_next->ic_prev = ibmf_clientp->ic_prev;

	if (ibmf_clientp->ic_prev)
		ibmf_clientp->ic_prev->ic_next = ibmf_clientp->ic_next;

	if (ibmf_cip->ci_clients == ibmf_clientp) {
		ibmf_cip->ci_clients = ibmf_clientp->ic_next;
	}
	if (ibmf_cip->ci_clients_last == ibmf_clientp) {
		ibmf_cip->ci_clients_last = ibmf_clientp->ic_prev;
	}
	mutex_exit(&ibmf_cip->ci_clients_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_delete_client_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_delete_client() exit\n");
}

/*
 * ibmf_i_get_qp():
 *	Get the QP structure based on the client class
 */
int
ibmf_i_get_qp(ibmf_ci_t *ibmf_cip, uint_t port_num, ibmf_client_type_t class,
    ibmf_qp_t **qppp)
{
	ibmf_qp_t		*qpp;
	int			qp_num, status = IBMF_SUCCESS;

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_get_qp_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_get_qp() enter, cip = %p, "
	    "port = %d, class = %x\n", tnf_opaque, ibmf_ci, ibmf_cip,
	    tnf_int, port, port_num, tnf_opaque, class, class);

	ASSERT(MUTEX_NOT_HELD(&ibmf_cip->ci_mutex));

	mutex_enter(&ibmf_cip->ci_mutex);

	/*
	 * walk through the list of qps on this ci, looking for one that
	 * corresponds to the type and class the caller is interested in.
	 * If it is not there, we need allocate it from the transport. Since
	 * qp0 & qp1 can only be allocated once, we maintain a reference count
	 * and call the transport for allocation iff the ref count is 0.
	 */
	qp_num = (class == SUBN_AGENT || class == SUBN_MANAGER) ? 0 : 1;

	qpp = ibmf_cip->ci_qp_list;
	while (qpp != NULL) {
		if (port_num == qpp->iq_port_num && qp_num == qpp->iq_qp_num)
			break;
		qpp = qpp->iq_next;
	}

	if (qpp == NULL) {
		/*
		 * allocate qp and add it the qp list; recheck to
		 * catch races
		 */
		ibmf_qp_t *tqpp;

		mutex_exit(&ibmf_cip->ci_mutex);

		tqpp = (ibmf_qp_t *)kmem_zalloc(sizeof (ibmf_qp_t), KM_SLEEP);

		/* check the list under lock */
		mutex_enter(&ibmf_cip->ci_mutex);

		qpp = ibmf_cip->ci_qp_list;
		while (qpp != NULL) {
			if (port_num == qpp->iq_port_num && qp_num ==
			    qpp->iq_qp_num)
				break;
			qpp = qpp->iq_next;
		}

		if (qpp != NULL) {
			/* some one raced past us and added to the list */
			kmem_free((void *)tqpp, sizeof (ibmf_qp_t));
		} else {
			/* add this to the qp list */
			qpp = tqpp;
			_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*qpp))
			qpp->iq_next = NULL;
			if (ibmf_cip->ci_qp_list == NULL)
				ibmf_cip->ci_qp_list = qpp;
			if (ibmf_cip->ci_qp_list_tail != NULL)
				ibmf_cip->ci_qp_list_tail->iq_next = qpp;
			ibmf_cip->ci_qp_list_tail = qpp;
			qpp->iq_port_num = port_num;
			qpp->iq_qp_num = qp_num;
			qpp->iq_flags = IBMF_QP_FLAGS_INVALID;
			mutex_init(&qpp->iq_mutex, NULL, MUTEX_DRIVER, NULL);
		}
	}

	/* we now have a QP context */
	for (;;) {
		if (qpp->iq_flags == IBMF_QP_FLAGS_INITING) {

			/* block till qp is in VALID state */
			cv_wait(&ibmf_cip->ci_qp_cv, &ibmf_cip->ci_mutex);
			continue;

		}

		if (qpp->iq_flags == IBMF_QP_FLAGS_UNINITING) {

			/* block till qp is in INVALID state */
			cv_wait(&ibmf_cip->ci_qp_cv, &ibmf_cip->ci_mutex);
			continue;
		}

		if (qpp->iq_flags == IBMF_QP_FLAGS_INVALID) {
			if ((status = ibmf_i_init_qp(ibmf_cip, qpp)) !=
			    IBMF_SUCCESS) {
				ibmf_qp_t *tqpp;

				/*
				 * Remove the QP context from the CI's list.
				 * Only initialized QPs should be on the list.
				 * We know that this QP is on the list, so
				 * the list is not empty.
				 */
				tqpp = ibmf_cip->ci_qp_list;
				if (tqpp == qpp) {
					/* Only QP context on the list */
					ibmf_cip->ci_qp_list = NULL;
					ibmf_cip->ci_qp_list_tail = NULL;
				}

				/* Find the QP context before the last one */
				if (tqpp != qpp) {
					while (tqpp->iq_next != qpp) {
						tqpp = tqpp->iq_next;
					}

					/*
					 * We are at the second last element of
					 * the list. Readjust the tail pointer.
					 * Remove the last element from the
					 * list.
					 */
					tqpp->iq_next = NULL;
					ibmf_cip->ci_qp_list_tail = tqpp;
				}

				/* Free up the QP context */
				kmem_free((void *)qpp, sizeof (ibmf_qp_t));

				break;
			}
			continue;
		}

		if (qpp->iq_flags == IBMF_QP_FLAGS_INITED) {
			qpp->iq_qp_ref++;
			break;
		}
	}

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*qpp))

	mutex_exit(&ibmf_cip->ci_mutex);

	if (status == IBMF_SUCCESS) {
		*qppp = qpp;
		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_get_qp_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_get_qp() exit "
		    "qp_handle = %p\n", tnf_opaque, qp_handle, qpp);
		return (IBMF_SUCCESS);
	} else {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1, ibmf_i_get_qp_err,
		    IBMF_TNF_ERROR, "", "%s\n", tnf_string, msg,
		    "ibmf_i_get_qp(): qp_not found");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_get_qp_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_get_qp() exit\n");
		return (status);
	}
}

/*
 * ibmf_i_release_qp():
 *	Drop the reference count on the QP structure
 */
void
ibmf_i_release_qp(ibmf_ci_t *ibmf_cip, ibmf_qp_t **qppp)
{
	ibmf_qp_t	*qpp;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_release_qp_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_release_qp() enter, cip = %p, "
	    "qpp = %p\n", tnf_opaque, cip, ibmf_cip, tnf_opaque, qpp, *qppp);

	ASSERT(MUTEX_NOT_HELD(&ibmf_cip->ci_mutex));

	mutex_enter(&ibmf_cip->ci_mutex);
	qpp = *qppp;
	qpp->iq_qp_ref--;
	if (qpp->iq_qp_ref == 0)
		ibmf_i_uninit_qp(ibmf_cip, qpp);
	mutex_exit(&ibmf_cip->ci_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_release_qp_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_release_qp() exit\n");
}

/*
 * ibmf_i_init_qp():
 *	Set up the QP context, request a QP from the IBT framework
 *	and initialize it
 */
static int
ibmf_i_init_qp(ibmf_ci_t *ibmf_cip, ibmf_qp_t *qpp)
{
	ibt_sqp_type_t		qp_type;
	ibt_qp_alloc_attr_t	qp_attrs;
	ibt_qp_hdl_t		qp_handle;
	ibt_qp_info_t		qp_modify_attr;
	ibt_status_t		ibt_status;
	int			i, status;

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_qp_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_qp() enter, cip = %p, "
	    "port = %d, qp = %d\n", tnf_opaque, ibmf_ci, ibmf_cip, tnf_int,
	    port, qpp->iq_port_num, tnf_int, num, qpp->iq_qp_num);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(qpp->iq_qp_handle))

	ASSERT(MUTEX_HELD(&ibmf_cip->ci_mutex));

	qpp->iq_flags = IBMF_QP_FLAGS_INITING;
	mutex_exit(&ibmf_cip->ci_mutex);
	if (qpp->iq_qp_handle) {	/* closed but not yet freed */
		ibt_status = ibt_free_qp(qpp->iq_qp_handle);
		if (ibt_status != IBT_SUCCESS) {
			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_init_qp_err, IBMF_TNF_ERROR, "",
			    "%s, status = %d\n", tnf_string, msg,
			    "ibt_free_qp returned error",
			    tnf_uint, ibt_status, ibt_status);
		}
		qpp->iq_qp_handle = NULL;
	}
	ASSERT(qpp->iq_qp_num == 0 || qpp->iq_qp_num == 1);
	if (qpp->iq_qp_num == 0)
		qp_type = IBT_SMI_SQP;
	else
		qp_type = IBT_GSI_SQP;
	qp_attrs.qp_scq_hdl = ibmf_cip->ci_cq_handle;
	qp_attrs.qp_rcq_hdl = ibmf_cip->ci_cq_handle;
	qp_attrs.qp_pd_hdl = ibmf_cip->ci_pd;
	qp_attrs.qp_sizes.cs_sq_sgl = 1;
	qp_attrs.qp_sizes.cs_rq_sgl = IBMF_MAX_RQ_WR_SGL_ELEMENTS;
	qp_attrs.qp_sizes.cs_sq = ibmf_send_wqes_posted_per_qp;
	qp_attrs.qp_sizes.cs_rq = ibmf_recv_wqes_posted_per_qp;
	qp_attrs.qp_flags = IBT_ALL_SIGNALED;
	qp_attrs.qp_alloc_flags = IBT_QP_NO_FLAGS;

	/* call the IB transport to allocate a special QP */
	ibt_status = ibt_alloc_special_qp(ibmf_cip->ci_ci_handle,
	    qpp->iq_port_num, qp_type, &qp_attrs, NULL, &qp_handle);
	if (ibt_status != IBT_SUCCESS) {
		mutex_enter(&ibmf_cip->ci_mutex);
		qpp->iq_flags = IBMF_QP_FLAGS_INVALID;
		cv_broadcast(&ibmf_cip->ci_qp_cv);
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1, ibmf_i_init_qp_err,
		    IBMF_TNF_ERROR, "", "ibmf_i_init_qp() error status = %d\n",
		    tnf_uint, ibt_status, ibt_status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_qp_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_init_qp() exit\n");
		return (IBMF_TRANSPORT_FAILURE);
	}

	/* initialize qpp */
	qpp->iq_qp_handle = qp_handle;
	qp_modify_attr.qp_trans = IBT_UD_SRV;
	qp_modify_attr.qp_flags = IBT_CEP_NO_FLAGS;

	/* get the pkey index for the specified pkey */
	if (ibmf_i_get_pkeyix(ibmf_cip->ci_ci_handle, IBMF_P_KEY_DEF_LIMITED,
	    qpp->iq_port_num, &qp_modify_attr.qp_transport.ud.ud_pkey_ix) !=
	    IBMF_SUCCESS) {
		ibt_status = ibt_free_qp(qpp->iq_qp_handle);
		if (ibt_status != IBT_SUCCESS) {
			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_init_qp_err, IBMF_TNF_ERROR, "",
			    "%s, status = %d\n", tnf_string, msg,
			    "ibt_free_qp returned error",
			    tnf_uint, ibt_status, ibt_status);
		}
		mutex_enter(&ibmf_cip->ci_mutex);
		qpp->iq_flags = IBMF_QP_FLAGS_INVALID;
		cv_broadcast(&ibmf_cip->ci_qp_cv);
		IBMF_TRACE_0(IBMF_TNF_NODEBUG, DPRINT_L1, ibmf_i_init_qp_err,
		    IBMF_TNF_ERROR, "", "ibmf_init_qp(): failed to get "
		    "pkey index\n");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_qp_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_init_qp() exit\n");
		return (IBMF_FAILURE);
	}
	qp_modify_attr.qp_transport.ud.ud_sq_psn = 0;
	qp_modify_attr.qp_transport.ud.ud_port = qpp->iq_port_num;
	qp_modify_attr.qp_transport.ud.ud_qkey = IBMF_MGMT_Q_KEY;

	/* call the IB transport to initialize the QP */
	ibt_status = ibt_initialize_qp(qp_handle, &qp_modify_attr);
	if (ibt_status != IBT_SUCCESS) {
		ibt_status = ibt_free_qp(qpp->iq_qp_handle);
		if (ibt_status != IBT_SUCCESS) {
			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_init_qp_err, IBMF_TNF_ERROR, "",
			    "%s, status = %d\n", tnf_string, msg,
			    "ibt_free_qp returned error",
			    tnf_uint, ibt_status, ibt_status);
		}
		mutex_enter(&ibmf_cip->ci_mutex);
		qpp->iq_flags = IBMF_QP_FLAGS_INVALID;
		cv_broadcast(&ibmf_cip->ci_qp_cv);
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1, ibmf_i_init_qp_err,
		    IBMF_TNF_ERROR, "", "ibmf_init_qp(): error status = %d\n",
		    tnf_uint, ibt_status, ibt_status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_qp_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_init_qp() exit\n");
		return (IBMF_TRANSPORT_FAILURE);
	}

	/* post receive wqes to the RQ to handle unsolicited inbound packets  */
	for (i = 0; i < ibmf_recv_wqes_per_port; i++) {
		status =  ibmf_i_post_recv_buffer(ibmf_cip, qpp,
		    B_TRUE, IBMF_QP_HANDLE_DEFAULT);
		if (status != IBMF_SUCCESS) {
			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L1,
			    ibmf_i_init_qp, IBMF_TNF_TRACE, "",
			    "%s\n", tnf_string, msg, "ibmf_i_init_qp(): "
			    "ibmf_i_post_recv_buffer() failed");
		}
	}
	mutex_enter(&ibmf_cip->ci_mutex);

	/* set the state and signal blockers */
	qpp->iq_flags = IBMF_QP_FLAGS_INITED;
	cv_broadcast(&ibmf_cip->ci_qp_cv);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_qp_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_qp() exit\n");
	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_uninit_qp():
 *	Invalidate the QP context
 */
static void
ibmf_i_uninit_qp(ibmf_ci_t *ibmf_cip, ibmf_qp_t *qpp)
{
	ibt_status_t		status;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_uninit_qp_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_uninit_qp() enter, cip = %p "
	    "qpp = %p\n", tnf_opaque, cip, ibmf_cip, tnf_opaque, qpp, qpp);

	ASSERT(MUTEX_HELD(&ibmf_cip->ci_mutex));

	/* mark the state as uniniting */
	ASSERT(qpp->iq_qp_ref == 0);
	qpp->iq_flags = IBMF_QP_FLAGS_UNINITING;
	mutex_exit(&ibmf_cip->ci_mutex);

	/* note: we ignore error values from ibt_flush_qp */
	status = ibt_flush_qp(qpp->iq_qp_handle);
	if (status != IBT_SUCCESS) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L2,
		    ibmf_i_uninit_qp_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_uninit_qp(): %s, status = %d\n", tnf_string, msg,
		    "ibt_flush_qp returned error", tnf_int, status, status);
	}

	/* mark state as INVALID and signal any blockers */
	mutex_enter(&ibmf_cip->ci_mutex);
	qpp->iq_flags = IBMF_QP_FLAGS_INVALID;
	cv_broadcast(&ibmf_cip->ci_qp_cv);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_uninit_qp_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_uninit_qp() exit\n");
}

/*
 * ibmf_i_alloc_msg():
 *	Allocate and set up a message context
 */
int
ibmf_i_alloc_msg(ibmf_client_t *clientp, ibmf_msg_impl_t **msgp, int km_flags)
{
	ibmf_msg_impl_t *msgimplp;

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_alloc_msg_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_alloc_msg() enter, clientp = %p, msg = %p, "
	    " kmflags = %d\n", tnf_opaque, clientp, clientp, tnf_opaque, msg,
	    *msgp, tnf_int, km_flags, km_flags);

	/* allocate the message context */
	msgimplp = (ibmf_msg_impl_t *)kmem_zalloc(sizeof (ibmf_msg_impl_t),
	    km_flags);
	if (msgimplp != NULL) {
		if (km_flags == KM_SLEEP) {
			ibmf_i_pop_ud_dest_thread(clientp->ic_myci);
		}
	} else {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_alloc_msg_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_alloc_msg(): %s\n",
		    tnf_string, msg, "kmem_xalloc failed");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_alloc_msg_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_alloc_msg() exit\n");
		return (IBMF_NO_RESOURCES);
	}

	*msgp = msgimplp;
	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_alloc_msg_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_alloc_msg() exit\n");
	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_free_msg():
 *	frees up all buffers allocated by IBMF for
 * 	this message context, and then frees up the context
 */
void
ibmf_i_free_msg(ibmf_msg_impl_t *msgimplp)
{
	ibmf_msg_bufs_t *msgbufp = &msgimplp->im_msgbufs_recv;
	ibmf_client_t *clientp = (ibmf_client_t *)msgimplp->im_client;
	uint32_t	cl_hdr_sz, cl_hdr_off;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_free_msg_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_free_msg() enter, msg = %p\n", tnf_opaque, msg, msgimplp);

	/* free up the UD destination resource */
	if (msgimplp->im_ibmf_ud_dest != NULL) {
		ibmf_i_free_ud_dest(clientp, msgimplp);
		ibmf_i_clean_ud_dest_list(clientp->ic_myci, B_FALSE);
	}

	/* free up the receive buffer if allocated previously */
	if (msgbufp->im_bufs_mad_hdr != NULL) {
		ibmf_i_mgt_class_to_hdr_sz_off(
		    msgbufp->im_bufs_mad_hdr->MgmtClass,
		    &cl_hdr_sz, &cl_hdr_off);
		kmem_free(msgbufp->im_bufs_mad_hdr, sizeof (ib_mad_hdr_t) +
		    cl_hdr_off + msgbufp->im_bufs_cl_hdr_len +
		    msgbufp->im_bufs_cl_data_len);
		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_SUB32_KSTATS(clientp, recv_bufs_alloced, 1);
		mutex_exit(&clientp->ic_kstat_mutex);
	}

	/* destroy the message mutex */
	mutex_destroy(&msgimplp->im_mutex);

	/* free the message context */
	kmem_free(msgimplp, sizeof (ibmf_msg_impl_t));

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_free_msg_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_free_msg() exit\n");
}

/*
 * ibmf_i_msg_transport():
 *	Send a message posted by the IBMF client using the RMPP protocol
 *	if specified
 */
int
ibmf_i_msg_transport(ibmf_client_t *clientp, ibmf_qp_handle_t ibmf_qp_handle,
    ibmf_msg_impl_t *msgimplp, int blocking)
{
	ib_mad_hdr_t	*madhdrp;
	ibmf_msg_bufs_t *msgbufp, *smsgbufp;
	uint32_t	cl_hdr_sz, cl_hdr_off;
	boolean_t	isDS = 0; /* double sided (sequenced) transaction */
	boolean_t	error = B_FALSE;
	int		status = IBMF_SUCCESS;
	uint_t		refcnt;
	char		errmsg[128];
	timeout_id_t	msg_rp_unset_id, msg_tr_unset_id;

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_msg_transport_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_msg_transport(): clientp = 0x%p, "
	    "qphdl = 0x%p, msgp = 0x%p, block = %d\n",
	    tnf_opaque, clientp, clientp, tnf_opaque, qphdl, ibmf_qp_handle,
	    tnf_opaque, msg, msgimplp, tnf_uint, block, blocking);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*msgimplp, *msgbufp))

	mutex_enter(&msgimplp->im_mutex);

	madhdrp = msgimplp->im_msgbufs_send.im_bufs_mad_hdr;
	msgbufp = &msgimplp->im_msgbufs_recv;
	smsgbufp = &msgimplp->im_msgbufs_send;

	/*
	 * check if transp_op_flags specify that the transaction is
	 * a single packet, then the size of the message header + data
	 * does not exceed 256 bytes
	 */
	if ((msgimplp->im_transp_op_flags & IBMF_MSG_TRANS_FLAG_RMPP) == 0) {
		ibmf_i_mgt_class_to_hdr_sz_off(
		    smsgbufp->im_bufs_mad_hdr->MgmtClass,
		    &cl_hdr_sz, &cl_hdr_off);

		if ((sizeof (ib_mad_hdr_t) + cl_hdr_off +
		    smsgbufp->im_bufs_cl_hdr_len +
		    smsgbufp->im_bufs_cl_data_len) > IBMF_MAD_SIZE) {
			mutex_exit(&msgimplp->im_mutex);
			(void) sprintf(errmsg,
			    "Non-RMPP message size is too large");
			error = B_TRUE;
			status = IBMF_BAD_SIZE;
			goto bail;
		}
	}

	/* more message context initialization */
	msgimplp->im_qp_hdl 	= ibmf_qp_handle;
	msgimplp->im_tid	= b2h64(madhdrp->TransactionID);
	msgimplp->im_mgt_class 	= madhdrp->MgmtClass;
	msgimplp->im_unsolicited = B_FALSE;
	msgimplp->im_trans_state_flags = IBMF_TRANS_STATE_FLAG_UNINIT;
	bzero(&msgimplp->im_rmpp_ctx, sizeof (ibmf_rmpp_ctx_t));
	msgimplp->im_rmpp_ctx.rmpp_state = IBMF_RMPP_STATE_UNDEFINED;
	msgimplp->im_rmpp_ctx.rmpp_respt = IBMF_RMPP_DEFAULT_RRESPT;
	msgimplp->im_rmpp_ctx.rmpp_retry_cnt = 0;
	msgimplp->im_ref_count = 0;
	msgimplp->im_pending_send_compls = 0;
	IBMF_MSG_INCR_REFCNT(msgimplp);
	if (msgimplp->im_retrans.retrans_retries == 0)
		msgimplp->im_retrans.retrans_retries = IBMF_RETRANS_DEF_RETRIES;
	if (msgimplp->im_retrans.retrans_rtv == 0)
		msgimplp->im_retrans.retrans_rtv = IBMF_RETRANS_DEF_RTV;
	if (msgimplp->im_retrans.retrans_rttv == 0)
		msgimplp->im_retrans.retrans_rttv = IBMF_RETRANS_DEF_RTTV;

	IBMF_TRACE_5(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_i_msg_transport,
	    IBMF_TNF_TRACE, "", "ibmf_i_msg_transport(): %s, msgp = 0x%p, "
	    "class = 0x%x, method = 0x%x, attributeID = 0x%x\n",
	    tnf_string, msg, "Added message", tnf_opaque, msgimplp,
	    msgimplp, tnf_opaque, class, msgimplp->im_mgt_class, tnf_opaque,
	    method, madhdrp->R_Method, tnf_opaque, attrib_id,
	    b2h16(madhdrp->AttributeID));

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_i_msg_transport,
	    IBMF_TNF_TRACE, "", "ibmf_i_msg_transport(): msgp = 0x%p, "
	    "TID = 0x%p, transp_op_flags = 0x%x\n",
	    tnf_opaque, msgimplp, msgimplp, tnf_opaque, tid, msgimplp->im_tid,
	    tnf_uint, transp_op_flags, msgimplp->im_transp_op_flags);

	/*
	 * Do not allow reuse of a message where the receive buffers are
	 * being used as send buffers if this is a sequenced transaction
	 */
	if ((madhdrp == msgbufp->im_bufs_mad_hdr) &&
	    (msgimplp->im_transp_op_flags & IBMF_MSG_TRANS_FLAG_SEQ)) {
		IBMF_MSG_DECR_REFCNT(msgimplp);
		mutex_exit(&msgimplp->im_mutex);
		(void) sprintf(errmsg,
		    "Send and Recv buffers are the same for sequenced"
		    " transaction");
		error = B_TRUE;
		status = IBMF_REQ_INVALID;
		goto bail;
	}

	/* set transaction flags */
	if (msgimplp->im_transp_op_flags & IBMF_MSG_TRANS_FLAG_SEQ)
		msgimplp->im_flags |= IBMF_MSG_FLAGS_SEQUENCED;

	if (msgimplp->im_transp_op_flags & IBMF_MSG_TRANS_FLAG_RMPP)
		msgimplp->im_flags |= IBMF_MSG_FLAGS_SEND_RMPP;
	else
		msgimplp->im_flags |= IBMF_MSG_FLAGS_NOT_RMPP;

	/* free recv buffers if this is a reused message */
	if ((msgbufp->im_bufs_mad_hdr != NULL) &&
	    (msgimplp->im_transp_op_flags & IBMF_MSG_TRANS_FLAG_SEQ)) {

		IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_i_msg_transport,
		    IBMF_TNF_TRACE, "", "ibmf_i_msg_transport(): %s, "
		    "msgp = 0x%p, mad_hdrp = 0x%p\n", tnf_string, msg,
		    "Freeing recv buffer for reused message",
		    tnf_opaque, msgimplp, msgimplp,
		    tnf_opaque, mad_hdr, msgbufp->im_bufs_mad_hdr);

		ibmf_i_mgt_class_to_hdr_sz_off(
		    msgbufp->im_bufs_mad_hdr->MgmtClass,
		    &cl_hdr_sz, &cl_hdr_off);

		kmem_free(msgbufp->im_bufs_mad_hdr, sizeof (ib_mad_hdr_t) +
		    cl_hdr_off + msgbufp->im_bufs_cl_hdr_len +
		    msgbufp->im_bufs_cl_data_len);

		msgbufp->im_bufs_mad_hdr = NULL;
		msgbufp->im_bufs_cl_hdr = NULL;
		msgbufp->im_bufs_cl_hdr_len = 0;
		msgbufp->im_bufs_cl_data = NULL;
		msgbufp->im_bufs_cl_data_len = 0;
	}

	mutex_exit(&msgimplp->im_mutex);

	/* initialize (and possibly allocate) the address handle */
	status = ibmf_i_alloc_ud_dest(clientp, msgimplp,
	    &msgimplp->im_ud_dest, blocking);
	if (status != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "ibmf_i_alloc_ud_dest() failed");
		error = B_TRUE;
		goto bail;
	}

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*msgimplp, *msgbufp))

	/* add the message to the client context's message list */
	ibmf_i_client_add_msg(clientp, msgimplp);

	mutex_enter(&msgimplp->im_mutex);

	/* no one should have touched our state */
	ASSERT(msgimplp->im_trans_state_flags == IBMF_TRANS_STATE_FLAG_UNINIT);

	/* transition out of uninit state */
	msgimplp->im_trans_state_flags = IBMF_TRANS_STATE_FLAG_INIT;

	IBMF_TRACE_5(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_i_msg_transport,
	    IBMF_TNF_TRACE, "", "ibmf_i_msg_transport(): msgp = 0x%p, "
	    "local_lid = 0x%x, remote_lid = 0x%x, remote_qpn = 0x%x, "
	    "block = %d\n", tnf_opaque, msgp, msgimplp,
	    tnf_uint, local_lid, msgimplp->im_local_addr.ia_local_lid,
	    tnf_uint, remote_lid, msgimplp->im_local_addr.ia_remote_lid,
	    tnf_uint, remote_qpn, msgimplp->im_local_addr.ia_remote_qno,
	    tnf_uint, blocking, blocking);

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_i_msg_transport,
	    IBMF_TNF_TRACE, "", "ibmf_i_msg_transport(): "
	    "unsetting timer %p %d\n", tnf_opaque, msgimplp, msgimplp,
	    tnf_opaque, timeout_id, msgimplp->im_rp_timeout_id);

	ASSERT(msgimplp->im_rp_timeout_id == 0);
	ASSERT(msgimplp->im_tr_timeout_id == 0);

	if ((msgimplp->im_transp_op_flags & IBMF_MSG_TRANS_FLAG_RMPP) == 0) {

		/* Non-RMPP transaction */

		status = ibmf_i_send_single_pkt(clientp, ibmf_qp_handle,
		    msgimplp, blocking);
		if (status != IBMF_SUCCESS) {
			IBMF_MSG_DECR_REFCNT(msgimplp);
			mutex_exit(&msgimplp->im_mutex);
			ibmf_i_client_rem_msg(clientp, msgimplp, &refcnt);
			(void) sprintf(errmsg, "Single packet send failed");
			error = B_TRUE;
			goto bail;
		}

	} else if (msgimplp->im_transp_op_flags & IBMF_MSG_TRANS_FLAG_RMPP) {

		/* RMPP transaction */

		/* check if client supports RMPP traffic */
		if ((clientp->ic_reg_flags & IBMF_REG_FLAG_RMPP) == 0) {
			IBMF_MSG_DECR_REFCNT(msgimplp);
			mutex_exit(&msgimplp->im_mutex);
			ibmf_i_client_rem_msg(clientp, msgimplp, &refcnt);
			(void) sprintf(errmsg, "Class does not support RMPP");
			error = B_TRUE;
			status = IBMF_BAD_RMPP_OPT;
			goto bail;
		}

		/* for non-special QPs, check if QP supports RMPP traffic */
		if (ibmf_qp_handle != IBMF_QP_HANDLE_DEFAULT &&
		    (((ibmf_alt_qp_t *)ibmf_qp_handle)->isq_supports_rmpp ==
		    B_FALSE)) {
			IBMF_MSG_DECR_REFCNT(msgimplp);
			mutex_exit(&msgimplp->im_mutex);
			ibmf_i_client_rem_msg(clientp, msgimplp, &refcnt);
			(void) sprintf(errmsg, "QP does not support RMPP");
			error = B_TRUE;
			status = IBMF_BAD_RMPP_OPT;
			goto bail;
		}

		/* check if transaction is "double sided" (send and receive) */
		if (msgimplp->im_transp_op_flags & IBMF_MSG_TRANS_FLAG_SEQ)
			isDS = 1;

		status = ibmf_i_send_rmpp_pkts(clientp, ibmf_qp_handle,
		    msgimplp, isDS, blocking);
		if (status != IBMF_SUCCESS) {
			IBMF_MSG_DECR_REFCNT(msgimplp);
			mutex_exit(&msgimplp->im_mutex);
			ibmf_i_client_rem_msg(clientp, msgimplp, &refcnt);
			(void) sprintf(errmsg, "RMPP packets send failed");
			error = B_TRUE;
			goto bail;
		}
	}

	/*
	 * decrement the reference count so notify_client() can remove the
	 * message when it's ready
	 */
	IBMF_MSG_DECR_REFCNT(msgimplp);

	/* check if the transaction is a blocking transaction */
	if (blocking && ((msgimplp->im_trans_state_flags &
	    IBMF_TRANS_STATE_FLAG_SIGNALED) == 0)) {

		/* indicate that the tranaction is waiting */
		msgimplp->im_trans_state_flags |= IBMF_TRANS_STATE_FLAG_WAIT;

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_i_msg_transport,
		    IBMF_TNF_TRACE, "",
		    "ibmf_i_msg_transport(): %s, msgp = 0x%p\n",
		    tnf_string, msg, "blocking for completion",
		    tnf_opaque, msgimplp, msgimplp);

		/* wait for transaction completion */
		cv_wait(&msgimplp->im_trans_cv, &msgimplp->im_mutex);

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_i_msg_transport,
		    IBMF_TNF_TRACE, "",
		    "ibmf_i_msg_transport(): %s, msgp = 0x%p\n",
		    tnf_string, msg, "unblocking for completion",
		    tnf_opaque, msgimplp, msgimplp);

		/* clean up flags */
		msgimplp->im_trans_state_flags &= ~IBMF_TRANS_STATE_FLAG_WAIT;
		msgimplp->im_flags &= ~IBMF_MSG_FLAGS_BUSY;

		if (msgimplp->im_msg_status != IBMF_SUCCESS) {

			IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_msg_transport_err, IBMF_TNF_ERROR, "",
			    "ibmf_i_msg_transport(): msg_status = %d\n",
			    tnf_uint, msgstatus, msgimplp->im_msg_status);

			status = msgimplp->im_msg_status;
		}
	} else if (blocking && (msgimplp->im_trans_state_flags &
	    IBMF_TRANS_STATE_FLAG_SIGNALED)) {
		msgimplp->im_flags &= ~IBMF_MSG_FLAGS_BUSY;

		if (msgimplp->im_msg_status != IBMF_SUCCESS) {
			IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_msg_transport_err, IBMF_TNF_ERROR, "",
			    "ibmf_i_msg_transport(): msg_status = %d\n",
			    tnf_uint, msgstatus, msgimplp->im_msg_status);
			status = msgimplp->im_msg_status;
		}
	}

	msg_rp_unset_id = msg_tr_unset_id = 0;
	msg_rp_unset_id = msgimplp->im_rp_unset_timeout_id;
	msg_tr_unset_id = msgimplp->im_tr_unset_timeout_id;
	msgimplp->im_rp_unset_timeout_id = 0;
	msgimplp->im_tr_unset_timeout_id = 0;

	mutex_exit(&msgimplp->im_mutex);

	/* Unset the timers */
	if (msg_rp_unset_id != 0) {
		(void) untimeout(msg_rp_unset_id);
	}

	if (msg_tr_unset_id != 0) {
		(void) untimeout(msg_tr_unset_id);
	}

	/* increment kstats of the number of sent messages */
	mutex_enter(&clientp->ic_kstat_mutex);
	IBMF_ADD32_KSTATS(clientp, msgs_sent, 1);
	mutex_exit(&clientp->ic_kstat_mutex);

bail:
	if (error) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_msg_transport_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_msg_transport(): %s, msgp = 0x%p\n",
		    tnf_string, msg, errmsg, tnf_opaque, msgimplp, msgimplp);
	}

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4,	ibmf_i_msg_transport_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_msg_transport() exit, status = %d\n",
	    tnf_uint, status, status);

	return (status);
}

/*
 * ibmf_i_init_msg():
 *	Initialize the message fields
 */
void
ibmf_i_init_msg(ibmf_msg_impl_t *msgimplp, ibmf_msg_cb_t trans_cb,
    void *trans_cb_arg, ibmf_retrans_t *retrans, boolean_t block)
{
	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_msg_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_msg() enter\n");

	_NOTE(ASSUMING_PROTECTED(msgimplp->im_trans_cb,
	    msgimplp->im_trans_cb_arg))

	if (block == B_TRUE)
		msgimplp->im_msg_flags |= IBMF_MSG_FLAGS_BLOCKING;
	msgimplp->im_trans_cb = trans_cb;
	msgimplp->im_trans_cb_arg = trans_cb_arg;

	bzero(&msgimplp->im_retrans, sizeof (ibmf_retrans_t));
	if (retrans != NULL) {
		bcopy((void *)retrans, (void *)&msgimplp->im_retrans,
		    sizeof (ibmf_retrans_t));
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_msg_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_msg() exit\n");
}

/*
 * ibmf_i_alloc_qp():
 *	Allocate a QP context for the alternate QPs
 */
int
ibmf_i_alloc_qp(ibmf_client_t *clientp, ib_pkey_t p_key, ib_qkey_t q_key,
    uint_t flags, ibmf_qp_handle_t *ibmf_qp_handlep)
{
	ibmf_ci_t		*ibmf_cip = clientp->ic_myci;
	ibt_qp_alloc_attr_t	qp_attrs;
	ibt_qp_info_t		qp_modify_attr;
	ibmf_alt_qp_t		*qp_ctx;
	uint16_t		pkey_ix;
	ibt_status_t		ibt_status;
	int			i, blocking;
	boolean_t		error = B_FALSE;
	int			status = IBMF_SUCCESS;
	char			errmsg[128];


	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_alloc_qp_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_alloc_qp() enter, clientp = %p, pkey = %x, qkey = %x \n",
	    tnf_opaque, clientp, clientp, tnf_uint, p_key, p_key,
	    tnf_uint, q_key, q_key);

	/*
	 * get the pkey index associated with this pkey if present in table
	 */
	if (ibmf_i_get_pkeyix(clientp->ic_ci_handle, p_key,
	    clientp->ic_client_info.port_num, &pkey_ix) != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "pkey not in table, pkey = %x", p_key);
		error = B_TRUE;
		status = IBMF_FAILURE;
		goto bail;
	}

	/* allocate QP context memory */
	qp_ctx = (ibmf_alt_qp_t *)kmem_zalloc(sizeof (ibmf_alt_qp_t),
	    (flags & IBMF_ALLOC_SLEEP) ? KM_SLEEP : KM_NOSLEEP);
	if (qp_ctx == NULL) {
		(void) sprintf(errmsg, "failed to kmem_zalloc qp ctx");
		error = B_TRUE;
		status = IBMF_NO_RESOURCES;
		goto bail;
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*qp_ctx));

	/* setup the qp attrs for the alloc call */
	qp_attrs.qp_scq_hdl = ibmf_cip->ci_alt_cq_handle;
	qp_attrs.qp_rcq_hdl = ibmf_cip->ci_alt_cq_handle;
	qp_attrs.qp_pd_hdl = ibmf_cip->ci_pd;
	qp_attrs.qp_sizes.cs_sq_sgl = IBMF_MAX_SQ_WR_SGL_ELEMENTS;
	qp_attrs.qp_sizes.cs_rq_sgl = IBMF_MAX_RQ_WR_SGL_ELEMENTS;
	qp_attrs.qp_sizes.cs_sq = ibmf_send_wqes_posted_per_qp;
	qp_attrs.qp_sizes.cs_rq = ibmf_recv_wqes_posted_per_qp;
	qp_attrs.qp_flags = IBT_ALL_SIGNALED;
	qp_attrs.qp_alloc_flags = IBT_QP_NO_FLAGS;

	/* request IBT for a qp with the desired attributes */
	ibt_status = ibt_alloc_qp(clientp->ic_ci_handle, IBT_UD_RQP,
	    &qp_attrs, &qp_ctx->isq_qp_sizes, &qp_ctx->isq_qpn,
	    &qp_ctx->isq_qp_handle);
	if (ibt_status != IBT_SUCCESS) {
		kmem_free(qp_ctx, sizeof (ibmf_alt_qp_t));
		(void) sprintf(errmsg, "failed to alloc qp, status = %d",
		    ibt_status);
		error = B_TRUE;
		status = IBMF_NO_RESOURCES;
		goto bail;
	}

	qp_modify_attr.qp_trans = IBT_UD_SRV;
	qp_modify_attr.qp_flags = IBT_CEP_NO_FLAGS;
	qp_modify_attr.qp_transport.ud.ud_qkey = q_key;
	qp_modify_attr.qp_transport.ud.ud_sq_psn = 0;
	qp_modify_attr.qp_transport.ud.ud_pkey_ix = pkey_ix;
	qp_modify_attr.qp_transport.ud.ud_port =
	    clientp->ic_client_info.port_num;

	/* Set up the client handle in the QP context */
	qp_ctx->isq_client_hdl = clientp;

	/* call the IB transport to initialize the QP */
	ibt_status = ibt_initialize_qp(qp_ctx->isq_qp_handle, &qp_modify_attr);
	if (ibt_status != IBT_SUCCESS) {
		(void) ibt_free_qp(qp_ctx->isq_qp_handle);
		kmem_free(qp_ctx, sizeof (ibmf_alt_qp_t));
		(void) sprintf(errmsg, "failed to initialize qp, status = %d",
		    ibt_status);
		error = B_TRUE;
		status = IBMF_NO_RESOURCES;
		goto bail;
	}

	/* Set up the WQE caches */
	status = ibmf_i_init_altqp_wqes(qp_ctx);
	if (status != IBMF_SUCCESS) {
		(void) ibt_free_qp(qp_ctx->isq_qp_handle);
		kmem_free(qp_ctx, sizeof (ibmf_alt_qp_t));
		(void) sprintf(errmsg, "failed to init wqe caches, status = %d",
		    status);
		error = B_TRUE;
		goto bail;
	}

	qp_ctx->isq_next = NULL;
	qp_ctx->isq_pkey = p_key;
	qp_ctx->isq_qkey = q_key;
	qp_ctx->isq_port_num = clientp->ic_client_info.port_num;
	mutex_init(&qp_ctx->isq_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&qp_ctx->isq_wqe_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&qp_ctx->isq_recv_cb_teardown_cv, NULL, CV_DRIVER, NULL);
	cv_init(&qp_ctx->isq_sqd_cv, NULL, CV_DRIVER, NULL);
	cv_init(&qp_ctx->isq_wqes_cv, NULL, CV_DRIVER, NULL);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*qp_ctx));

	/* add alt qp to the list in CI context */
	mutex_enter(&ibmf_cip->ci_mutex);
	if (ibmf_cip->ci_alt_qp_list == NULL) {
		ibmf_cip->ci_alt_qp_list = qp_ctx;
	} else {
		ibmf_alt_qp_t *qpp;

		qpp = ibmf_cip->ci_alt_qp_list;
		while (qpp->isq_next != NULL) {
			qpp = qpp->isq_next;
		}
		qpp->isq_next = qp_ctx;
	}
	mutex_exit(&ibmf_cip->ci_mutex);

	*ibmf_qp_handlep = (ibmf_qp_handle_t)qp_ctx;

	if (flags & IBMF_ALLOC_SLEEP)
		blocking = 1;
	else
		blocking = 0;

	/* post the max number of buffers to RQ */
	for (i = 0; i < ibmf_recv_wqes_per_port; i++) {
		status = ibmf_i_post_recv_buffer(ibmf_cip, clientp->ic_qp,
		    blocking, *ibmf_qp_handlep);
		if (status != IBMF_SUCCESS) {
			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_alloc_qp, IBMF_TNF_TRACE, "",
			    "ibmf_i_alloc_qp(): %s, status = %d\n",
			    tnf_string, msg, "ibmf_i_post_recv_buffer() failed",
			    tnf_int, status, status);
		}
	}

	mutex_enter(&clientp->ic_kstat_mutex);
	IBMF_ADD32_KSTATS(clientp, alt_qps_alloced, 1);
	mutex_exit(&clientp->ic_kstat_mutex);

bail:
	if (error) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_alloc_qp_err, IBMF_TNF_TRACE, "",
		    "ibmf_i_alloc_qp(): %s\n", tnf_string, msg, errmsg);
	}

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_alloc_qp_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_alloc_qp() exit, qp = %p\n",
	    tnf_opaque, qp_handlep, *ibmf_qp_handlep);
	return (status);
}

/*
 * ibmf_i_free_qp():
 *	Free an alternate QP context
 */
/* ARGSUSED */
int
ibmf_i_free_qp(ibmf_qp_handle_t ibmf_qp_handle, uint_t flags)
{
	ibmf_alt_qp_t		*qp_ctx = (ibmf_alt_qp_t *)ibmf_qp_handle;
	ibmf_client_t		*clientp = qp_ctx->isq_client_hdl;
	ibmf_ci_t		*ibmf_cip = qp_ctx->isq_client_hdl->ic_myci;
	ibmf_alt_qp_t		*qpp, *pqpp;
	ibt_status_t		ibt_status;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_free_qp_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_free_qp() enter, qp_hdl = %p, flags = %x\n",
	    tnf_opaque, qp_hdl, ibmf_qp_handle, tnf_uint, flags, flags);

	/* remove qp from the list in CI context */

	mutex_enter(&ibmf_cip->ci_mutex);
	qpp = ibmf_cip->ci_alt_qp_list;
	ASSERT(qpp != NULL);
	if (qpp == qp_ctx) {
		ibmf_cip->ci_alt_qp_list = qpp->isq_next;
	} else {
		while (qpp != NULL) {
			if (qpp == qp_ctx)
				break;
			pqpp = qpp;
			qpp = qpp->isq_next;
		}
		ASSERT(qpp != NULL);
		pqpp->isq_next = qpp->isq_next;
	}

	mutex_exit(&ibmf_cip->ci_mutex);

	/* flush the WQEs in the QP queues */
	ibt_status = ibt_flush_qp(qp_ctx->isq_qp_handle);
	if (ibt_status != IBT_SUCCESS) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_free_qp_err, IBMF_TNF_TRACE, "",
		    "ibmf_i_free_qp(): %s, status = %d\n",
		    tnf_string, msg, "failed to close qp",
		    tnf_uint, ibt_status, ibt_status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_free_qp_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_free_qp() exit\n");
		return (IBMF_TRANSPORT_FAILURE);
	}

	/* Call the MAD completion handler */
	ibmf_i_mad_completions(ibmf_cip->ci_alt_cq_handle, (void*)ibmf_cip);

	/* Wait here for all WQE owned by this QP to get freed */
	mutex_enter(&qpp->isq_mutex);
	while (qpp->isq_wqes_alloced != 0) {
		cv_wait(&qpp->isq_wqes_cv, &qpp->isq_mutex);
	}
	mutex_exit(&qpp->isq_mutex);

	cv_destroy(&qp_ctx->isq_recv_cb_teardown_cv);
	cv_destroy(&qp_ctx->isq_sqd_cv);
	cv_destroy(&qp_ctx->isq_wqes_cv);

	/* call the IB transport to free the QP */
	ibt_status = ibt_free_qp(qp_ctx->isq_qp_handle);
	if (ibt_status != IBT_SUCCESS) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_free_qp_err, IBMF_TNF_TRACE, "",
		    "ibmf_i_free_qp(): %s, status = %d\n",
		    tnf_string, msg, "failed to free qp",
		    tnf_uint, ibt_status, ibt_status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_free_qp_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_free_qp() exit\n");
		return (IBMF_TRANSPORT_FAILURE);
	}

	/* Clean up the WQE caches */
	ibmf_i_fini_altqp_wqes(qp_ctx);
	mutex_destroy(&qp_ctx->isq_wqe_mutex);
	mutex_destroy(&qp_ctx->isq_mutex);

	mutex_enter(&clientp->ic_kstat_mutex);
	IBMF_SUB32_KSTATS(clientp, alt_qps_alloced, 1);
	mutex_exit(&clientp->ic_kstat_mutex);

	kmem_free(qp_ctx, sizeof (ibmf_alt_qp_t));

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_free_qp_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_free_qp() exit\n");

	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_query_qp():
 *	Query an alternate QP context
 */
/* ARGSUSED */
int
ibmf_i_query_qp(ibmf_qp_handle_t ibmf_qp_handle, uint_t flags,
    uint_t *qp_nump, ib_pkey_t *p_keyp, ib_qkey_t *q_keyp, uint8_t *portnump)
{
	ibt_qp_query_attr_t	qp_query;
	ibmf_alt_qp_t		*qp_ctx = (ibmf_alt_qp_t *)ibmf_qp_handle;
	uint16_t		pkey_ix;
	ibt_status_t		ibt_status;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_free_qp_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_free_qp() enter, qp_hdl = %p, flags = %x\n",
	    tnf_opaque, qp_hdl, ibmf_qp_handle, tnf_uint, flags, flags);

	ibt_status = ibt_query_qp(qp_ctx->isq_qp_handle, &qp_query);
	if (ibt_status != IBT_SUCCESS) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_query_qp_err, IBMF_TNF_TRACE, "",
		    "ibmf_i_query_qp(): %s, status = %d\n",
		    tnf_string, msg, "failed to query qp",
		    tnf_uint, ibt_status, ibt_status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_query_qp_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_query_qp() exit\n");
		return (IBMF_TRANSPORT_FAILURE);
	}

	/* move the desired attributes into the locations provided */
	*qp_nump = qp_query.qp_qpn;
	*q_keyp = qp_query.qp_info.qp_transport.ud.ud_qkey;
	*portnump = qp_query.qp_info.qp_transport.ud.ud_port;

	pkey_ix = qp_query.qp_info.qp_transport.ud.ud_pkey_ix;

	/* get the pkey based on the pkey_ix */
	ibt_status = ibt_index2pkey(qp_ctx->isq_client_hdl->ic_ci_handle,
	    *portnump, pkey_ix, p_keyp);
	if (ibt_status != IBT_SUCCESS) {
		IBMF_TRACE_3(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_query_qp_err, IBMF_TNF_TRACE, "",
		    "ibmf_i_query_qp(): %s, pkey_ix = %d, status = %d\n",
		    tnf_string, msg, "failed to get pkey from index",
		    tnf_uint, pkey_ix, pkey_ix,
		    tnf_uint, ibt_status, ibt_status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_query_qp_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_query_qp() exit\n");
		return (IBMF_TRANSPORT_FAILURE);
	}

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_query_qp_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_query_qp() exit, qp_num = 0x%x, "
	    "pkey = 0x%x, qkey = 0x%x, portnum = %d\n",
	    tnf_uint, qp_num, *qp_nump, tnf_uint, pkey, *p_keyp,
	    tnf_uint, qkey, *q_keyp, tnf_uint, portnum, *portnump);

	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_modify_qp():
 *	Modify an alternate QP context
 */
/* ARGSUSED */
int
ibmf_i_modify_qp(ibmf_qp_handle_t ibmf_qp_handle, ib_pkey_t p_key,
    ib_qkey_t q_key, uint_t flags)
{
	ibmf_alt_qp_t		*qp_ctx = (ibmf_alt_qp_t *)ibmf_qp_handle;
	ibmf_client_t		*clientp = qp_ctx->isq_client_hdl;
	ibmf_ci_t		*ibmf_cip = clientp->ic_myci;
	ibmf_alt_qp_t		*qpp;
	ibt_qp_info_t		qp_mod;
	ibt_cep_modify_flags_t	qp_mod_flags;
	ibt_queue_sizes_t	actual_sz;
	uint16_t		pkey_ix;
	ibt_status_t		ibt_status;

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_modify_qp_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_modify_qp() enter, qp_hdl = %p, flags = %x, pkey = 0x%x, "
	    "qkey = 0x%x\n", tnf_opaque, qp_hdl, ibmf_qp_handle,
	    tnf_uint, flags, flags, tnf_uint, p_key, p_key,
	    tnf_uint, q_key, q_key);

	/*
	 * get the pkey index associated with this pkey if present in table
	 */
	if (ibmf_i_get_pkeyix(clientp->ic_ci_handle, p_key,
	    clientp->ic_client_info.port_num, &pkey_ix) != IBMF_SUCCESS) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_modify_qp_err, IBMF_TNF_TRACE, "",
		    "ibmf_i_modify_qp(): %s, pkey = %x\n",
		    tnf_string, msg, "pkey not in table",
		    tnf_uint, pkey, p_key);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_modify_qp_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_modify_qp() exit\n");
		return (IBMF_FAILURE);
	}

	/* Find the QP context in the CI QP context list */
	mutex_enter(&ibmf_cip->ci_mutex);
	qpp = ibmf_cip->ci_alt_qp_list;
	while (qpp != NULL) {
		if (qpp == qp_ctx) {
			break;
		}
		qpp = qpp->isq_next;
	}

	if (qpp == NULL) {
		mutex_exit(&ibmf_cip->ci_mutex);

		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_modify_qp_err, IBMF_TNF_TRACE, "",
		    "ibmf_i_modify_qp(): %s\n",
		    tnf_string, msg, "QP not in altqp list");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_modify_qp_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_modify_qp() exit\n");
		return (IBMF_BAD_QP_HANDLE);

	} else {

		mutex_enter(&qp_ctx->isq_mutex);
	}

	mutex_exit(&ibmf_cip->ci_mutex);

	/*
	 * Transition the QP to SQD state
	 */
	bzero(&qp_mod, sizeof (ibt_qp_info_t));
	qp_mod.qp_trans = IBT_UD_SRV;
	qp_mod.qp_state = IBT_STATE_SQD;
	qp_mod_flags = IBT_CEP_SET_STATE | IBT_CEP_SET_SQD_EVENT;
	ibt_status = ibt_modify_qp(qp_ctx->isq_qp_handle, qp_mod_flags,
	    &qp_mod, &actual_sz);
	if (ibt_status != IBT_SUCCESS) {
		mutex_exit(&qp_ctx->isq_mutex);
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_modify_qp_err, IBMF_TNF_TRACE, "",
		    "ibmf_i_modify_qp(): %s, qp_hdl = %p\n",
		    tnf_string, msg, "QP transition RTS to SQD failed",
		    tnf_opaque, qp_handle, qp_ctx->isq_qp_handle);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_modify_qp_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_modify_qp() exit\n");
		return (IBMF_TRANSPORT_FAILURE);
	}

	/*
	 * Wait for an event indicating that the QP is in SQD state
	 */
	cv_wait(&qp_ctx->isq_sqd_cv, &qp_ctx->isq_mutex);

	/* Setup QP modification information for transition to RTS state */
	bzero(&qp_mod, sizeof (ibt_qp_info_t));
	qp_mod.qp_trans = IBT_UD_SRV;
	qp_mod.qp_state = IBT_STATE_RTS;
	qp_mod.qp_current_state = IBT_STATE_SQD;
	qp_mod.qp_transport.ud.ud_pkey_ix = pkey_ix;
	qp_mod.qp_transport.ud.ud_qkey = q_key;
	qp_mod_flags = IBT_CEP_SET_STATE | IBT_CEP_SET_PKEY_IX |
	    IBT_CEP_SET_QKEY;

	/*
	 * transition the QP back to RTS state to allow
	 * modification of the pkey and qkey
	 */

	ibt_status = ibt_modify_qp(qp_ctx->isq_qp_handle, qp_mod_flags,
	    &qp_mod, &actual_sz);
	if (ibt_status != IBT_SUCCESS) {
		mutex_exit(&qp_ctx->isq_mutex);
		IBMF_TRACE_3(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_modify_qp_err, IBMF_TNF_TRACE, "",
		    "ibmf_i_modify_qp(): %s, qp_hdl = %p, status = %d\n",
		    tnf_string, msg, "QP transition SQD to RTS failed",
		    tnf_opaque, qp_handle, qp_ctx->isq_qp_handle,
		    tnf_uint, ibt_status, ibt_status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_modify_qp_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_modify_qp() exit\n");
		return (IBMF_TRANSPORT_FAILURE);
	}

	qp_ctx->isq_pkey = p_key;
	qp_ctx->isq_qkey = q_key;
	mutex_exit(&qp_ctx->isq_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_modify_qp_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_modify_qp() exit\n");
	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_post_recv_buffer():
 *	Post a WQE to the RQ of the specified QP
 */
int
ibmf_i_post_recv_buffer(ibmf_ci_t *cip, ibmf_qp_t *qpp, boolean_t block,
    ibmf_qp_handle_t ibmf_qp_handle)
{
	int			ret;
	ibt_wr_ds_t		*sgl;
	ibt_status_t		status;
	ibmf_recv_wqe_t		*recv_wqep;
	ibt_qp_hdl_t		ibt_qp_handle;
	struct kmem_cache	*kmem_cachep;
	ibmf_alt_qp_t		*altqp;

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_post_recv_buffer_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_post_recv_buffer() enter, cip = %p, qpp = %p, "
	    "qp_hdl = %p, block = %d\n", tnf_opaque, cip, cip,
	    tnf_opaque, qpp, qpp, tnf_opaque, qp_hdl, ibmf_qp_handle,
	    tnf_uint, block, block);

	/*
	 * if we haven't hit the max wqes per qp, attempt to allocate a recv
	 * wqe and post it to the recv queue.
	 * It is possible for more than one thread to get through this
	 * check below and post wqes that could push us above the
	 * ibmf_recv_wqes_posted_per_qp. We catch that case when the recv
	 * completion is signaled.
	 */
	ASSERT(MUTEX_NOT_HELD(&cip->ci_mutex));

	/* Get the WQE kmem cache pointer based on the QP type */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT)
		kmem_cachep = cip->ci_recv_wqes_cache;
	else {
		altqp = (ibmf_alt_qp_t *)ibmf_qp_handle;
		kmem_cachep = altqp->isq_recv_wqes_cache;
	}

	/* allocate a receive WQE from the receive WQE kmem cache */
	recv_wqep = kmem_cache_alloc(kmem_cachep,
	    (block == B_TRUE ? KM_SLEEP : KM_NOSLEEP));
	if (recv_wqep == NULL) {
		/*
		 * Attempt to extend the cache and then retry the
		 * kmem_cache_alloc()
		 */
		if (ibmf_i_extend_wqe_cache(cip, ibmf_qp_handle, block) ==
		    IBMF_NO_RESOURCES) {
			mutex_enter(&cip->ci_mutex);
			IBMF_ADD32_PORT_KSTATS(cip, rwqe_allocs_failed, 1);
			mutex_exit(&cip->ci_mutex);
			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_post_recv_buffer_err, IBMF_TNF_ERROR, "",
			    "ibmf_i_post_recv_buffer(): %s, status = %d\n",
			    tnf_string, msg, "alloc recv_wqe failed",
			    tnf_int, ibmf_status, IBMF_NO_RESOURCES);
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_post_recv_buffer_end, IBMF_TNF_TRACE, "",
			    "ibmf_i_post_recv_buffer() exit\n");
			return (IBMF_NO_RESOURCES);
		} else {
			recv_wqep = kmem_cache_alloc(kmem_cachep,
			    (block == B_TRUE ? KM_SLEEP : KM_NOSLEEP));
			if (recv_wqep == NULL) {
				/* Allocation failed again. Give up here. */
				mutex_enter(&cip->ci_mutex);
				IBMF_ADD32_PORT_KSTATS(cip, rwqe_allocs_failed,
				    1);
				mutex_exit(&cip->ci_mutex);
				IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
				    ibmf_i_post_recv_buffer_err,
				    IBMF_TNF_ERROR, "",
				    "ibmf_i_post_recv_buffer(): %s, "
				    "status = %d\n",
				    tnf_string, msg, "alloc recv_wqe failed",
				    tnf_int, ibmf_status, IBMF_NO_RESOURCES);
				IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
				    ibmf_i_post_recv_buffer_end,
				    IBMF_TNF_TRACE, "",
				    "ibmf_i_post_recv_buffer() exit\n");
				return (IBMF_NO_RESOURCES);
			}
		}
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*recv_wqep))

	/*
	 * if the qp handle provided in ibmf_send_pkt() or
	 * ibmf_setup_recv_cb() is not the default qp handle
	 * for this client, then the wqe must be queued on this qp,
	 * else use the default qp handle set up during ibmf_register()
	 */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		ibt_qp_handle = qpp->iq_qp_handle;
	} else {
		ibt_qp_handle =
		    ((ibmf_alt_qp_t *)ibmf_qp_handle)->isq_qp_handle;
	}

	/* allocate memory for the scatter-gather list */
	sgl = kmem_zalloc(IBMF_MAX_RQ_WR_SGL_ELEMENTS * sizeof (ibt_wr_ds_t),
	    (block == B_TRUE) ? KM_SLEEP : KM_NOSLEEP);
	if (sgl == NULL) {
		kmem_cache_free(kmem_cachep, recv_wqep);
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_post_recv_buffer_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_post_recv_buffer(): %s\n",
		    tnf_string, msg, "failed to kmem_zalloc qp ctx");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_post_recv_buffer_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_post_recv_buffer() exit\n");
		return (IBMF_NO_RESOURCES);
	}

	/* initialize it */
	ibmf_i_init_recv_wqe(qpp, sgl, recv_wqep, ibt_qp_handle,
	    ibmf_qp_handle);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*recv_wqep))

	/* and post it */
	status = ibt_post_recv(recv_wqep->recv_qp_handle, &recv_wqep->recv_wr,
	    1, NULL);

	ret = ibmf_i_ibt_to_ibmf_status(status);
	if (ret != IBMF_SUCCESS) {
		kmem_free(sgl, IBMF_MAX_RQ_WR_SGL_ELEMENTS *
		    sizeof (ibt_wr_ds_t));
		kmem_cache_free(kmem_cachep, recv_wqep);
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_post_recv_buffer_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_post_recv_buffer(): %s, status = %d\n",
		    tnf_string, msg, "ibt_post_recv failed",
		    tnf_uint, ibt_status, status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_post_recv_buffer_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_post_recv_buffer() exit\n");
		return (ret);
	}

	mutex_enter(&cip->ci_mutex);
	IBMF_ADD32_PORT_KSTATS(cip, recv_wqes_alloced, 1);
	mutex_exit(&cip->ci_mutex);
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		mutex_enter(&qpp->iq_mutex);
		qpp->iq_rwqes_posted++;
		mutex_exit(&qpp->iq_mutex);
		mutex_enter(&cip->ci_mutex);
		cip->ci_wqes_alloced++;
		mutex_exit(&cip->ci_mutex);
	} else {
		mutex_enter(&altqp->isq_mutex);
		altqp->isq_wqes_alloced++;
		altqp->isq_rwqes_posted++;
		mutex_exit(&altqp->isq_mutex);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_post_recv_buffer_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_post_recv_buffer() exit\n");

	return (ret);
}

/*
 * ibmf_i_mgt_class_to_hdr_sz_off():
 *	Determine class header offser and size for management classes
 */
void
ibmf_i_mgt_class_to_hdr_sz_off(uint32_t mgt_class, uint32_t *szp,
    uint32_t *offp)
{
	uint32_t	hdr_sz = 0, hdr_off = 0;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_mgt_class_to_hdr_sz_off_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_mgt_class_to_hdr_sz_off(): mgt_class = 0x%x\n",
	    tnf_uint, mgt_class, mgt_class);

	switch (mgt_class) {
	case MAD_MGMT_CLASS_SUBN_LID_ROUTED :
	case MAD_MGMT_CLASS_SUBN_DIRECT_ROUTE :
	case MAD_MGMT_CLASS_PERF :
	case MAD_MGMT_CLASS_BM :
	case MAD_MGMT_CLASS_DEV_MGT :
	case MAD_MGMT_CLASS_SNMP :
		hdr_sz = IBMF_MAD_CL_HDR_SZ_1;
		hdr_off = IBMF_MAD_CL_HDR_OFF_1;
		break;
	case MAD_MGMT_CLASS_SUBN_ADM :
		hdr_sz = IBMF_MAD_CL_HDR_SZ_2;
		hdr_off = IBMF_MAD_CL_HDR_OFF_2;
		break;
	}

	if (((mgt_class >= MAD_MGMT_CLASS_VENDOR_START) &&
	    (mgt_class <= MAD_MGMT_CLASS_VENDOR_END)) ||
	    ((mgt_class >= MAD_MGMT_CLASS_APPLICATION_START) &&
	    (mgt_class <= MAD_MGMT_CLASS_APPLICATION_END))) {
		hdr_sz = IBMF_MAD_CL_HDR_SZ_3;
		hdr_off = IBMF_MAD_CL_HDR_OFF_1;
	}

	if ((mgt_class >= MAD_MGMT_CLASS_VENDOR2_START) &&
	    (mgt_class <= MAD_MGMT_CLASS_VENDOR2_END)) {
		hdr_sz = IBMF_MAD_CL_HDR_SZ_4;
		hdr_off = IBMF_MAD_CL_HDR_OFF_2;
	}

	*szp = hdr_sz;
	*offp = hdr_off;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_mgt_class_to_hdr_sz_off_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_mgt_class_to_hdr_sz_off() exit,hdr_sz = %d, hdr_off = %d\n",
	    tnf_uint, hdr_sz, hdr_sz, tnf_uint, hdr_off, hdr_off);
}

/*
 * ibmf_i_lookup_client_by_mgmt_class():
 *	Lookup the client context based on the management class of
 *	the incoming packet
 */
int
ibmf_i_lookup_client_by_mgmt_class(ibmf_ci_t *ibmf_cip, int port_num,
    ibmf_client_type_t class, ibmf_client_t **clientpp)
{
	ibmf_client_t 		*clientp;
	ibmf_client_info_t	*client_infop;

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_lookup_client_by_mgmt_class_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_lookup_client_by_mgmt_class() enter, cip = %p, "
	    "port_num = %d, class = 0x%x\n", tnf_opaque, cip, ibmf_cip,
	    tnf_int, port, port_num, tnf_opaque, class, class);

	ASSERT(MUTEX_NOT_HELD(&ibmf_cip->ci_clients_mutex));

	mutex_enter(&ibmf_cip->ci_clients_mutex);

	clientp = ibmf_cip->ci_clients;

	/* walk client context list looking for class/portnum match */
	while (clientp != NULL) {
		client_infop = &clientp->ic_client_info;
		if (class == client_infop->client_class &&
		    port_num == client_infop->port_num) {
			/* found our match */
			break;
		}
		clientp = clientp->ic_next;
	}

	mutex_exit(&ibmf_cip->ci_clients_mutex);

	if (clientp != NULL) {
		*clientpp = clientp;
		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_lookup_client_by_mgmt_class_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_lookup_client_by_mgmt_class() exit, clp = %p\n",
		    tnf_opaque, clientp, clientp);
		return (IBMF_SUCCESS);
	} else {
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_lookup_client_by_mgmt_class_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_lookup_client_by_mgmt_class() failure exit\n");
		return (IBMF_FAILURE);
	}
}

/*
 * ibmf_i_get_pkeyix():
 *	Get the pkey index of the pkey in the pkey table of the specified
 *	port. Take into account the partition membership.
 */
int
ibmf_i_get_pkeyix(ibt_hca_hdl_t hca_handle, ib_pkey_t pkey, uint8_t port,
    ib_pkey_t *pkeyixp)
{
	ib_pkey_t		tpkey;
	ibt_status_t		ibt_status;

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_get_pkeyix_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_get_pkeyix() enter, hcahdl = %p, "
	    "pkey = 0x%x, port = %d\n", tnf_opaque, hcahdl, hca_handle,
	    tnf_int, pkey, pkey, tnf_int, port, port);

	/*
	 * If the client specifies the FULL membership pkey and the
	 * pkey is not in the table, this function should fail.
	 */
	if (pkey & IBMF_PKEY_MEMBERSHIP_MASK) {
		ibt_status = ibt_pkey2index(hca_handle, port,
		    pkey, pkeyixp);
		if (ibt_status != IBT_SUCCESS) {
			IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_get_pkeyix_err, IBMF_TNF_ERROR, "",
			    "ibmf_i_get_pkeyix() error status = %d\n",
			    tnf_uint, ibt_status, ibt_status);
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_get_pkeyix_end, IBMF_TNF_TRACE, "",
			    "ibmf_i_get_pkeyix() exit\n");
			return (IBMF_TRANSPORT_FAILURE);
		}
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_get_pkeyix_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_get_pkeyix() exit\n");
		return (IBMF_SUCCESS);
	}

	/*
	 * Limited member pkey processing
	 * Check if this limited member pkey is in the pkey table
	 */
	ibt_status = ibt_pkey2index(hca_handle, port, pkey, pkeyixp);
	if (ibt_status == IBT_SUCCESS) {
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_get_pkeyix_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_get_pkeyix() exit\n");
		return (IBMF_SUCCESS);
	}

	/*
	 * Could not find the limited member version of the pkey.
	 * Now check if the full member version of the pkey is in the
	 * pkey table. If not, fail the call.
	 */
	tpkey = pkey | IBMF_PKEY_MEMBERSHIP_MASK;
	ibt_status = ibt_pkey2index(hca_handle, port, tpkey, pkeyixp);
	if (ibt_status != IBT_SUCCESS) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_get_pkeyix_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_get_pkeyix() error status = %d\n",
		    tnf_uint, ibt_status, ibt_status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_get_pkeyix_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_get_pkeyix() exit\n");
		return (IBMF_TRANSPORT_FAILURE);
	}

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_get_pkeyix_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_get_pkeyix(): pkey_ix = %d\n",
	    tnf_int, pkeyix, *pkeyixp);
	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_pkey_ix_to_key():
 *	Figure out pkey from pkey index
 */
int
ibmf_i_pkey_ix_to_key(ibmf_ci_t *cip, uint_t port_num, uint_t pkey_ix,
    ib_pkey_t *pkeyp)
{
	ibt_status_t		ibt_status;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_pkey_ix_to_key_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_pkey_ix_to_key() enter\n");

	ibt_status = ibt_index2pkey(cip->ci_ci_handle, port_num, pkey_ix,
	    pkeyp);
	if (ibt_status != IBT_SUCCESS) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_pkey_ix_to_key, IBMF_TNF_TRACE, "",
		    "ibmf_i_pkey_ix_to_key(): ibt_index2pkey failed for "
		    " pkey index %d \n", tnf_uint, pkey_ix, pkey_ix);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_pkey_ix_to_key_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_pkey_ix_to_key() exit\n");
		return (IBMF_TRANSPORT_FAILURE);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_pkey_ix_to_key_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_pkey_ix_to_key() exit\n");

	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_ibt_to_ibmf_status():
 *	Map IBT return code to IBMF return code
 */
int
ibmf_i_ibt_to_ibmf_status(ibt_status_t ibt_status)
{
	int ibmf_status;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_ibt_to_ibmf_status_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_ibt_to_ibmf_status() enter, "
	    "status = %d\n", tnf_uint, ibt_status, ibt_status);

	switch (ibt_status) {

	case IBT_SUCCESS:
		ibmf_status = IBMF_SUCCESS;
		break;

	case IBT_INSUFF_KERNEL_RESOURCE:
	case IBT_INSUFF_RESOURCE:
	case IBT_QP_FULL:
		ibmf_status = IBMF_NO_RESOURCES;
		break;

	case IBT_HCA_IN_USE:
	case IBT_QP_IN_USE:
	case IBT_CQ_BUSY:
	case IBT_PD_IN_USE:
	case IBT_MR_IN_USE:
		ibmf_status = IBMF_BUSY;
		break;

	default:
		ibmf_status = IBMF_FAILURE;
		break;
	}

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_ibt_to_ibmf_status_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_ibt_to_ibmf_status() exit, "
	    "ibt_status = %d, ibmf_status = %d\n", tnf_uint, ibt_status,
	    ibt_status, tnf_int, ibmf_status, ibmf_status);

	return (ibmf_status);
}

/*
 * ibmf_i_ibt_wc_to_ibmf_status():
 *	Map work completion code to IBMF return code
 */
int
ibmf_i_ibt_wc_to_ibmf_status(ibt_wc_status_t ibt_wc_status)
{
	int ibmf_status;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_ibt_wc_to_ibmf_status_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_ibt_to_ibmf_status() enter, status = %d\n",
	    tnf_uint, ibt_wc_status, ibt_wc_status);

	switch (ibt_wc_status) {

	case IBT_WC_SUCCESS:
		ibmf_status = IBMF_SUCCESS;
		break;

	default:
		ibmf_status = IBMF_FAILURE;
		break;
	}

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_ibt_wc_to_ibmf_status_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_ibt_to_ibmf_status() exit, wc_status = %d, "
	    "ibmf_status = %d\n", tnf_uint, ibt_wc_status,
	    ibt_wc_status, tnf_int, ibmf_status, ibmf_status);

	return (ibmf_status);
}

/*
 * ibmf_i_is_ibmf_handle_valid():
 *	Validate the ibmf handle
 */
int
ibmf_i_is_ibmf_handle_valid(ibmf_handle_t ibmf_handle)
{
	ibmf_ci_t	*cip;
	ibmf_client_t	*clp, *clientp = (ibmf_client_t *)ibmf_handle;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_is_ibmf_handle_valid_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_is_ibmf_handle_valid() enter\n");

	mutex_enter(&ibmf_statep->ibmf_mutex);

	cip = ibmf_statep->ibmf_ci_list;

	/* iterate through all the channel interace contexts */
	while (cip != NULL) {

		mutex_enter(&cip->ci_clients_mutex);

		clp = cip->ci_clients;

		/* search all registration contexts for this ci */
		while (clp != NULL) {
			if (clp == clientp)
				break;
			clp = clp->ic_next;
		}

		mutex_exit(&cip->ci_clients_mutex);

		if (clp == clientp) {
			/* ci found */
			break;
		} else {
			/* ci not found, move onto next ci */
			cip = cip->ci_next;
		}
	}

	mutex_exit(&ibmf_statep->ibmf_mutex);

	if (cip != NULL) {
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_is_ibmf_handle_valid_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_is_ibmf_handle_valid() exit\n");
		return (IBMF_SUCCESS);
	} else {
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_is_ibmf_handle_valid_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_is_ibmf_handle_valid() failure exit\n");
		return (IBMF_FAILURE);
	}
}

/*
 * ibmf_i_is_qp_handle_valid():
 *	Validate the QP handle
 */
int
ibmf_i_is_qp_handle_valid(ibmf_handle_t ibmf_handle,
    ibmf_qp_handle_t ibmf_qp_handle)
{
	ibmf_client_t	*clientp = (ibmf_client_t *)ibmf_handle;
	ibmf_alt_qp_t	*alt_qp, *qpp = (ibmf_alt_qp_t *)ibmf_qp_handle;
	ibmf_ci_t	*cip = clientp->ic_myci;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_is_qp_handle_valid_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_is_qp_handle_valid() enter\n");

	/* the default qp handle is always valid */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT)
		return (IBMF_SUCCESS);

	mutex_enter(&cip->ci_mutex);

	alt_qp = cip->ci_alt_qp_list;

	while (alt_qp != NULL) {
		if (alt_qp == qpp) {
			/* qp handle found */
			break;
		} else {
			/* qp handle not found, get next qp on list */
			alt_qp = alt_qp->isq_next;
		}
	}

	mutex_exit(&cip->ci_mutex);

	if (alt_qp != NULL) {
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_is_qp_handle_valid_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_is_qp_handle_valid() exit\n");
		return (IBMF_SUCCESS);
	} else {
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_is_qp_handle_valid_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_is_qp_handle_valid() failure exit\n");
		return (IBMF_FAILURE);
	}
}

void
ibmf_dprintf(int l, const char *fmt, ...)
{
	va_list ap;

	if ((l) > ibmf_trace_level) {

		return;
	}

	va_start(ap, fmt);
	(void) vprintf(fmt, ap);
	va_end(ap);
}

/*
 * ibmf_setup_term_ctx():
 * Sets up a message context that is the duplicate of the one
 * passed in the regmsgimplp argument. The duplicate message context
 * is not visible to the client. It is managed internally by ibmf
 * to process the RMPP receiver termination flow logic for the
 * transaction while the client is notified of the completion of the
 * same transaction (i.e. all the solicited data has been received).
 */
int
ibmf_setup_term_ctx(ibmf_client_t *clientp, ibmf_msg_impl_t *regmsgimplp)
{
	ibmf_msg_impl_t	*msgimplp;
	size_t		offset;
	uint32_t	cl_hdr_sz, cl_hdr_off;
	int		status;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_setup_term_ctx_start, IBMF_TNF_TRACE, "",
	    "ibmf_setup_term_ctx() enter\n");

	/*
	 * Allocate the termination message context
	 */
	msgimplp = (ibmf_msg_impl_t *)kmem_zalloc(sizeof (ibmf_msg_impl_t),
	    KM_NOSLEEP);
	if (msgimplp == NULL) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_setup_term_ctx_error, IBMF_TNF_ERROR, "",
		    "ibmf_setup_term_ctx(): %s\n", tnf_string, msg,
		    "message mem allocation failure");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_setup_term_ctx_end, IBMF_TNF_TRACE, "",
		    "ibmf_setup_term_ctx() exit\n");
		return (IBMF_NO_RESOURCES);
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*msgimplp))

	/* Copy the message context to the termination message structure */
	*msgimplp = *regmsgimplp;

	/* Initialize the message mutex */
	mutex_init(&msgimplp->im_mutex, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Allocate enough memory for the MAD header only.
	 */
	msgimplp->im_msgbufs_recv.im_bufs_mad_hdr =
	    (ib_mad_hdr_t *)kmem_zalloc(IBMF_MAD_SIZE, KM_NOSLEEP);
	if (msgimplp->im_msgbufs_recv.im_bufs_mad_hdr == NULL) {
		kmem_free(msgimplp, sizeof (ibmf_msg_impl_t));
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_setup_term_ctx_error, IBMF_TNF_ERROR, "",
		    "ibmf_setup_term_ctx(): %s\n", tnf_string, msg,
		    "recv buf mem allocation failure");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_setup_term_ctx_end, IBMF_TNF_TRACE, "",
		    "ibmf_setup_term_ctx() exit\n");
		return (IBMF_NO_RESOURCES);
	}

	/* Copy over just the MAD header contents */
	bcopy((const void *)regmsgimplp->im_msgbufs_recv.im_bufs_mad_hdr,
	    (void *)msgimplp->im_msgbufs_recv.im_bufs_mad_hdr,
	    sizeof (ib_mad_hdr_t));

	offset = sizeof (ib_mad_hdr_t);
	ibmf_i_mgt_class_to_hdr_sz_off(
	    regmsgimplp->im_msgbufs_recv.im_bufs_mad_hdr->MgmtClass,
	    &cl_hdr_sz, &cl_hdr_off);
	offset += cl_hdr_off;

	/*
	 * Copy the management class header
	 */
	msgimplp->im_msgbufs_recv.im_bufs_cl_hdr =
	    (uchar_t *)msgimplp->im_msgbufs_recv.im_bufs_mad_hdr + offset;
	msgimplp->im_msgbufs_recv.im_bufs_cl_hdr_len =
	    regmsgimplp->im_msgbufs_recv.im_bufs_cl_hdr_len;
	bcopy((void *)regmsgimplp->im_msgbufs_recv.im_bufs_cl_hdr,
	    (void *)msgimplp->im_msgbufs_recv.im_bufs_cl_hdr,
	    regmsgimplp->im_msgbufs_recv.im_bufs_cl_hdr_len);

	/*
	 * Clear the termination message timers copied from the regular message
	 * since ibmf_i_set_timer() expects them to be cleared.
	 */
	msgimplp->im_rp_timeout_id = 0;
	msgimplp->im_tr_timeout_id = 0;

	/* Mark this message as being in a receiver RMPP mode */
	msgimplp->im_flags |= IBMF_MSG_FLAGS_RECV_RMPP;

	/* Mark this message as being a "termination flow" message */
	msgimplp->im_flags |= IBMF_MSG_FLAGS_TERMINATION;

	/*
	 * Clear the IBMF_MSG_FLAGS_SET_TERMINATION copied over from the regular
	 * message.
	 */
	msgimplp->im_flags &= ~IBMF_MSG_FLAGS_SET_TERMINATION;

	/*
	 * Clear the trans_state RECV_DONE and DONE flags so that the
	 * protocol continues with the termination message context.
	 */
	msgimplp->im_trans_state_flags &= ~IBMF_TRANS_STATE_FLAG_RECV_DONE;
	msgimplp->im_trans_state_flags &= ~IBMF_TRANS_STATE_FLAG_DONE;

	/* Clear out references to the old UD dest handles */
	msgimplp->im_ibmf_ud_dest = NULL;
	msgimplp->im_ud_dest = NULL;

	/*
	 * Request new UD dest resources for the termination phase.
	 * The old UD dest resources are freed when the IBMF client
	 * calls ibmf_free_msg(), so they cannot be relied on to exist
	 * when the RMPP termination loop completes.
	 */
	status = ibmf_i_alloc_ud_dest(clientp, msgimplp, &msgimplp->im_ud_dest,
	    B_FALSE);
	if (status != IBMF_SUCCESS) {
		kmem_free(msgimplp, sizeof (ibmf_msg_impl_t));
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_setup_term_ctx_err, IBMF_TNF_ERROR, "",
		    "ibmf_setup_term_ctx(): %s, status = %d\n",
		    tnf_string, msg, "UD destination resource allocation"
		    " failed", tnf_int, ibmf_status, status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_setup_term_ctx_end, IBMF_TNF_TRACE, "",
		    "ibmf_setup_term_ctx() exit\n");
		return (status);
	}

	/*
	 * Add the message to the termination client list by virtue of
	 * having the IBMF_MSG_FLAGS_TERMINATION "im_flags" flag set.
	 */
	ibmf_i_client_add_msg(clientp, msgimplp);

	/*
	 * Increase the "allocted messages" count so that the client
	 * does not unregister before this message has been freed.
	 * This is necessary because we want the client context to
	 * be around when the receive timeout expires for this termination
	 * loop, otherwise the code will access freed memory and crash.
	 */
	mutex_enter(&clientp->ic_mutex);
	clientp->ic_msgs_alloced++;
	mutex_exit(&clientp->ic_mutex);

	mutex_enter(&msgimplp->im_mutex);
	/* Set the response timer for the termination message. */
	ibmf_i_set_timer(ibmf_i_recv_timeout, msgimplp, IBMF_RESP_TIMER);
	mutex_exit(&msgimplp->im_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_setup_term_ctx_end,
	    IBMF_TNF_TRACE, "", "ibmf_setup_term_ctx() exit\n");

	return (IBMF_SUCCESS);
}
