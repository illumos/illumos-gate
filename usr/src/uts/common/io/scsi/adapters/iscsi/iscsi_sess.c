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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * iSCSI session interfaces
 */

#include <sys/bootprops.h>
#include "iscsi.h"
#include "persistent.h"
#include "iscsi_targetparam.h"

#define	ISCSI_SESS_ENUM_TIMEOUT_DEFAULT	60
#define	SCSI_INQUIRY_PQUAL_MASK 0xE0

boolean_t iscsi_sess_logging = B_FALSE;
/*
 * used to store report lun information found
 *
 * lun_valid:	if TRUE means the entry contains a valid entry
 * lun_found:	if TRUE means the lun has been found in the sess_lun_list
 * lun_num:	contains the lun_number
 * lun_addr_type:	indicates lun's type of addressing
 */
typedef	struct replun_data {
	boolean_t	lun_valid;
	boolean_t	lun_found;
	uint16_t	lun_num;
	uint8_t		lun_addr_type;
} replun_data_t;

int	iscsi_sess_enum_timeout = ISCSI_SESS_ENUM_TIMEOUT_DEFAULT;

/*
 * The following private tunable, settable via
 *      set iscsi:iscsi_sess_max_delay = 64
 * in /etc/system, provides customer relief for configurations max interval in
 * seconds of retry for a unreachable target during the login.
 */
int	iscsi_sess_max_delay = ISCSI_DEFAULT_MAX_STORM_DELAY;

/*
 * Warning messages for the session scsi enumeration
 */
static const char *iscsi_sess_enum_warn_msgs[] = {
	"completed",
	"partially successful",
	"IO failures",
	"submitted",
	"unable to submit the enumeration",
	"session is gone",
	"test unit ready failed"
};

/* internal interfaces */
/* LINTED E_STATIC_UNUSED */
static iscsi_sess_t *iscsi_sess_alloc(iscsi_hba_t *ihp, iscsi_sess_type_t type);
static char *iscsi_sess_event_str(iscsi_sess_event_t event);
static iscsi_status_t iscsi_sess_threads_create(iscsi_sess_t *isp);
static void iscsi_sess_flush(iscsi_sess_t *isp);
static void iscsi_sess_offline_luns(iscsi_sess_t *isp);
static iscsi_status_t retrieve_lundata(uint32_t lun_count, unsigned char *buf,
	iscsi_sess_t *isp, uint16_t *lun_data, uint8_t *lun_addr_type);

/* internal state machine interfaces */
static void iscsi_sess_state_free(iscsi_sess_t *isp,
    iscsi_sess_event_t event, uint32_t event_count);
static void iscsi_sess_state_logged_in(iscsi_sess_t *isp,
    iscsi_sess_event_t event, uint32_t event_count);
static void iscsi_sess_state_failed(iscsi_sess_t *isp,
    iscsi_sess_event_t event, uint32_t event_count);
static void iscsi_sess_state_in_flush(iscsi_sess_t *isp,
    iscsi_sess_event_t event, uint32_t event_count);
static void iscsi_sess_state_flushed(iscsi_sess_t *isp,
    iscsi_sess_event_t event, uint32_t event_count);

/* internal enumeration interfaces */
static void iscsi_sess_enumeration(void *arg);
static iscsi_status_t iscsi_sess_testunitready(iscsi_sess_t *isp,
    uint32_t event_count);
static iscsi_status_t iscsi_sess_reportluns(iscsi_sess_t *isp,
    uint32_t event_count);
static void iscsi_sess_inquiry(iscsi_sess_t *isp, uint16_t lun_num,
    uint8_t lun_addr_type, uint32_t event_count, iscsi_lun_t *ilp);
static void iscsi_sess_update_busy_luns(iscsi_sess_t *isp, boolean_t clear);
static void iscsi_sess_enum_warn(iscsi_sess_t *isp, iscsi_enum_result_t r);

/*
 * +--------------------------------------------------------------------+
 * | External Session Interfaces					|
 * +--------------------------------------------------------------------+
 */
iscsi_sess_t *
iscsi_sess_create(iscsi_hba_t *ihp, iSCSIDiscoveryMethod_t method,
    struct sockaddr *addr_dsc, char *target_name, int tpgt, uchar_t isid_lsb,
    iscsi_sess_type_t type, uint32_t *oid)
{
	iscsi_sess_t	*isp		= NULL;
	int		len		= 0;
	char		*tq_name;
	char		*th_name;
	iscsi_status_t	status;

	len = strlen(target_name);

clean_failed_sess:
	if (isp != NULL) {
		(void) iscsi_sess_destroy(isp);
	}

	for (isp = ihp->hba_sess_list; isp; isp = isp->sess_next) {
		/* Match target name and LSB ISID */
		if ((strcmp((char *)isp->sess_name, target_name) == 0) &&
		    (isp->sess_isid[5] == isid_lsb)) {

			/* Match TPGT */
			if (isp->sess_tpgt_conf == tpgt) {
				/* Found mathing session, return oid/ptr */
				*oid = isp->sess_oid;
				if (isp->sess_wd_thread != NULL &&
				    isp->sess_ic_thread != NULL) {
					return (isp);
				}

				if (isp->sess_wd_thread == NULL) {
					/*
					 * Under rare cases wd thread is already
					 * freed, create it if so.
					 */
					th_name = kmem_zalloc(
					    ISCSI_TH_MAX_NAME_LEN, KM_SLEEP);
					if (snprintf(th_name,
					    (ISCSI_TH_MAX_NAME_LEN - 1),
					    ISCSI_SESS_WD_NAME_FORMAT,
					    ihp->hba_oid, isp->sess_oid) <
					    ISCSI_TH_MAX_NAME_LEN) {
						isp->sess_wd_thread =
						    iscsi_thread_create(
						    ihp->hba_dip,
						    th_name,
						    iscsi_wd_thread,
						    isp);
						(void) iscsi_thread_start(
						    isp->sess_wd_thread);
					}
					kmem_free(th_name,
					    ISCSI_TH_MAX_NAME_LEN);
					if (isp->sess_wd_thread == NULL) {
						/* No way to save it */
						goto clean_failed_sess;
					}
				}

				if (isp->sess_ic_thread == NULL) {
					status = iscsi_sess_threads_create(isp);
					if (status != ISCSI_STATUS_SUCCESS) {
						goto clean_failed_sess;
					}
				}
				return (isp);
			}

			/*
			 * Also protect against creating duplicate
			 * sessions with different configured tpgt
			 * values.  default vs. defined.
			 */
			if ((((isp->sess_tpgt_conf == ISCSI_DEFAULT_TPGT) &&
			    (tpgt != ISCSI_DEFAULT_TPGT)) ||
			    ((isp->sess_tpgt_conf != ISCSI_DEFAULT_TPGT) &&
			    (tpgt == ISCSI_DEFAULT_TPGT)))) {
				/* Dangerous configuration.  Fail Request */
				return (NULL);
			}
		}
	}

	isp = (iscsi_sess_t *)kmem_zalloc(sizeof (iscsi_sess_t), KM_SLEEP);
	/*
	 * If this session is not a Send Targets session, set the target
	 * that this session is associated with.
	 */
	if (strncmp(target_name, SENDTARGETS_DISCOVERY,
	    strlen(SENDTARGETS_DISCOVERY))) {
		isp->sess_target_oid = iscsi_targetparam_get_oid(
		    (uchar_t *)target_name);
	}

	if (method & iSCSIDiscoveryMethodBoot) {
		/* This is boot session. */
		isp->sess_boot = B_TRUE;
	} else {
		isp->sess_boot = B_FALSE;
	}

	/* Associate session with this discovery method */
	method = method & ~(iSCSIDiscoveryMethodBoot);

	isp->sess_discovered_by = method;
	if (addr_dsc == NULL) {
		bzero(&isp->sess_discovered_addr,
		    sizeof (isp->sess_discovered_addr));
	} else {
		bcopy(addr_dsc, &isp->sess_discovered_addr,
		    SIZEOF_SOCKADDR(addr_dsc));
	}

	/* assign unique key for the session */
	mutex_enter(&iscsi_oid_mutex);
	isp->sess_oid = iscsi_oid++;
	*oid = isp->sess_oid;
	mutex_exit(&iscsi_oid_mutex);

	/* setup session parameters */
	isp->sess_name_length		= 0;
	isp->sess_sig			= ISCSI_SIG_SESS;
	isp->sess_state			= ISCSI_SESS_STATE_FREE;
	rw_init(&isp->sess_state_rwlock, NULL, RW_DRIVER, NULL);
	mutex_init(&isp->sess_reset_mutex, NULL, MUTEX_DRIVER, NULL);
	isp->sess_hba			= ihp;

	isp->sess_isid[0]		= ISCSI_SUN_ISID_0;
	isp->sess_isid[1]		= ISCSI_SUN_ISID_1;
	isp->sess_isid[2]		= ISCSI_SUN_ISID_2;
	isp->sess_isid[3]		= ISCSI_SUN_ISID_3;
	isp->sess_isid[4]		= 0;
	isp->sess_isid[5]		= isid_lsb;

	isp->sess_cmdsn			= 1;
	isp->sess_expcmdsn		= 1;
	isp->sess_maxcmdsn		= 1;
	isp->sess_last_err		= NoError;
	isp->sess_tsid			= 0;
	isp->sess_type			= type;
	isp->sess_reset_in_progress	= B_FALSE;
	isp->sess_boot_nic_reset	= B_FALSE;
	idm_sm_audit_init(&isp->sess_state_audit);

	/* copy default driver login parameters */
	bcopy(&ihp->hba_params, &isp->sess_params,
	    sizeof (iscsi_login_params_t));

	/* copy target name into session */
	bcopy((char *)target_name, isp->sess_name, len);
	isp->sess_name_length	= len;
	isp->sess_tpgt_conf	= tpgt;
	isp->sess_tpgt_nego	= ISCSI_DEFAULT_TPGT;

	/* initialize pending and completion queues */
	iscsi_init_queue(&isp->sess_queue_pending);
	iscsi_init_queue(&isp->sess_queue_completion);

	/* setup sessions lun list */
	isp->sess_lun_list = NULL;
	rw_init(&isp->sess_lun_list_rwlock, NULL, RW_DRIVER, NULL);

	/* setup sessions connection list */
	isp->sess_conn_act = NULL;
	isp->sess_conn_list = NULL;
	rw_init(&isp->sess_conn_list_rwlock, NULL, RW_DRIVER, NULL);

	mutex_init(&isp->sess_cmdsn_mutex, NULL, MUTEX_DRIVER, NULL);

	/* create the session task queue */
	tq_name = kmem_zalloc(ISCSI_TH_MAX_NAME_LEN, KM_SLEEP);
	if (snprintf(tq_name, (ISCSI_TH_MAX_NAME_LEN - 1),
	    ISCSI_SESS_LOGIN_TASKQ_NAME_FORMAT, ihp->hba_oid, isp->sess_oid) <
	    ISCSI_TH_MAX_NAME_LEN) {
		isp->sess_login_taskq = ddi_taskq_create(ihp->hba_dip,
		    tq_name, 1, TASKQ_DEFAULTPRI, 0);
	}
	if (isp->sess_login_taskq == NULL) {
		kmem_free(tq_name, ISCSI_TH_MAX_NAME_LEN);
		goto iscsi_sess_cleanup2;
	}

	if (snprintf(tq_name, (ISCSI_TH_MAX_NAME_LEN - 1),
	    ISCSI_SESS_ENUM_TASKQ_NAME_FORMAT, ihp->hba_oid, isp->sess_oid) <
	    ISCSI_TH_MAX_NAME_LEN) {
		isp->sess_enum_taskq = ddi_taskq_create(ihp->hba_dip,
		    tq_name, 1, TASKQ_DEFAULTPRI, 0);
	}
	kmem_free(tq_name, ISCSI_TH_MAX_NAME_LEN);
	if (isp->sess_enum_taskq == NULL) {
		goto iscsi_sess_cleanup1;
	}
	/* startup watchdog */
	th_name = kmem_zalloc(ISCSI_TH_MAX_NAME_LEN, KM_SLEEP);
	if (snprintf(th_name, (ISCSI_TH_MAX_NAME_LEN - 1),
	    ISCSI_SESS_WD_NAME_FORMAT, ihp->hba_oid, isp->sess_oid) <
	    ISCSI_TH_MAX_NAME_LEN) {
		isp->sess_wd_thread = iscsi_thread_create(ihp->hba_dip,
		    th_name, iscsi_wd_thread, isp);
		(void) iscsi_thread_start(isp->sess_wd_thread);
	}

	kmem_free(th_name, ISCSI_TH_MAX_NAME_LEN);
	if (isp->sess_wd_thread == NULL) {
		goto iscsi_sess_cleanup0;
	}

	status = iscsi_sess_threads_create(isp);
	if (status != ISCSI_STATUS_SUCCESS) {
		goto iscsi_sess_cleanup1;
	}

	/* Add new target to the hba target list */
	if (ihp->hba_sess_list == NULL) {
		ihp->hba_sess_list = isp;
	} else {
		isp->sess_next = ihp->hba_sess_list;
		ihp->hba_sess_list = isp;
	}
	KSTAT_INC_HBA_CNTR_SESS(ihp);

	(void) iscsi_sess_kstat_init(isp);

	if (type == ISCSI_SESS_TYPE_NORMAL) {
		isp->sess_enum_status = ISCSI_SESS_ENUM_FREE;
		isp->sess_enum_result = ISCSI_SESS_ENUM_COMPLETE;
		isp->sess_enum_result_count = 0;
		mutex_init(&isp->sess_enum_lock, NULL, MUTEX_DRIVER, NULL);
		cv_init(&isp->sess_enum_cv, NULL, CV_DRIVER, NULL);
	}

	mutex_init(&isp->sess_state_wmutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&isp->sess_state_wcv, NULL, CV_DRIVER, NULL);
	isp->sess_state_hasw = B_FALSE;

	isp->sess_state_event_count = 0;

	return (isp);
iscsi_sess_cleanup0:
	ddi_taskq_destroy(isp->sess_enum_taskq);
iscsi_sess_cleanup1:
	ddi_taskq_destroy(isp->sess_login_taskq);
iscsi_sess_cleanup2:
	if (isp->sess_wd_thread != NULL) {
		iscsi_thread_destroy(isp->sess_wd_thread);
		isp->sess_wd_thread  = NULL;
	}
	if (isp->sess_ic_thread != NULL) {
		iscsi_thread_destroy(isp->sess_ic_thread);
		isp->sess_ic_thread = NULL;
	}
	mutex_destroy(&isp->sess_cmdsn_mutex);
	rw_destroy(&isp->sess_conn_list_rwlock);
	rw_destroy(&isp->sess_lun_list_rwlock);
	iscsi_destroy_queue(&isp->sess_queue_completion);
	iscsi_destroy_queue(&isp->sess_queue_pending);
	rw_destroy(&isp->sess_state_rwlock);
	mutex_destroy(&isp->sess_reset_mutex);
	kmem_free(isp, sizeof (iscsi_sess_t));

	return (NULL);
}

/*
 * iscsi_sess_get - return the session structure for based on a
 * passed in oid and hba instance.
 */
int
iscsi_sess_get(uint32_t oid, iscsi_hba_t *ihp, iscsi_sess_t **ispp)
{
	int		rval		= 0;
	iscsi_sess_t	*isp		= NULL;

	ASSERT(ihp != NULL);
	ASSERT(ispp != NULL);

	/* See if we already created this session */
	for (isp = ihp->hba_sess_list; isp; isp = isp->sess_next) {
		/* compare target name as the unique identifier */
		if (isp->sess_oid == oid) {
			/* Found matching session */
			break;
		}
	}

	/* If not null this session is already available */
	if (isp != NULL) {
		/* Existing session, return it */
		*ispp = isp;
	} else {
		rval = EFAULT;
	}
	return (rval);
}

/*
 * iscsi_sess_online - initiate online of sessions connections
 */
void
iscsi_sess_online(void *arg)
{
	iscsi_sess_t	*isp;
	iscsi_hba_t	*ihp;
	iscsi_conn_t	*icp;
	int		idx;
	uint32_t	event_count;

	isp = (iscsi_sess_t *)arg;

	ASSERT(isp != NULL);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);

	/*
	 * Stale /dev links can cause us to get floods
	 * of config requests. To prevent these repeated
	 * requests from causing unneeded login to the
	 * unreachable target, we won't try it during
	 * the delay.
	 */
	if (ddi_get_lbolt() < isp->sess_failure_lbolt +
	    SEC_TO_TICK(isp->sess_storm_delay)) {
		return;
	}

	/*
	 * Perform a crude version of round robin to
	 * determine which connection to use for
	 * this session. Since byte 5 in session ID
	 * is overridden for full feature session,
	 * the connection to be selected depends on
	 * the result of sess_isid[5] devided by the
	 * next connection ID.
	 * If MS/T is enabled and there are multiple
	 * IPs are available on the target, we can
	 * select different IPs to connect in this
	 * way.
	 */
	icp = isp->sess_conn_act;
	if (icp == NULL) {
		icp = isp->sess_conn_list;
		for (idx = 0; idx < (isp->sess_isid[5] %
		    isp->sess_conn_next_cid); idx++) {
			ASSERT(icp->conn_next != NULL);
			icp = icp->conn_next;
		}
		isp->sess_conn_act = icp;
	}

	if (icp == NULL) {
		cmn_err(CE_NOTE, "iscsi session(%d) - "
		    "no connection assigned", isp->sess_oid);
		return;
	}

	/*
	 * If connection is in free state, start
	 * login.  If already logged in, try to
	 * re-enumerate LUs on the session.
	 */
	mutex_enter(&icp->conn_state_mutex);
	if (icp->conn_state == ISCSI_CONN_STATE_FREE) {
		/*
		 * attempt to login into the first connection in our connection
		 * list.  If this fails, we will try the next connection
		 * in our list until end of the list.
		 */
		while (icp != NULL) {
			if (iscsi_conn_online(icp) == ISCSI_STATUS_SUCCESS) {
				mutex_exit(&icp->conn_state_mutex);
				break;
			} else {
				mutex_exit(&icp->conn_state_mutex);
				icp = icp->conn_next;
				if (icp != NULL) {
					mutex_enter(&icp->conn_state_mutex);
				}
			}
		}
		isp->sess_conn_act = icp;
		if (icp == NULL) {
		/* the target for this session is unreachable */
			isp->sess_failure_lbolt = ddi_get_lbolt();
			if (isp->sess_storm_delay == 0) {
				isp->sess_storm_delay++;
			} else {

				if ((isp->sess_storm_delay * 2) <
				    iscsi_sess_max_delay) {
					isp->sess_storm_delay =
					    isp->sess_storm_delay * 2;
				} else {
					isp->sess_storm_delay =
					    iscsi_sess_max_delay;
				}
			}

		} else {
			isp->sess_storm_delay = 0;
			isp->sess_failure_lbolt = 0;
		}
	} else if (icp->conn_state == ISCSI_CONN_STATE_LOGGED_IN) {
		mutex_exit(&icp->conn_state_mutex);
		event_count = atomic_inc_32_nv(&isp->sess_state_event_count);
		iscsi_sess_enter_state_zone(isp);
		iscsi_sess_state_machine(isp,
		    ISCSI_SESS_EVENT_N1, event_count);
		iscsi_sess_exit_state_zone(isp);
	} else {
		mutex_exit(&icp->conn_state_mutex);
	}
}

/*
 * iscsi_sess_destroy - Destroys a iscsi session structure
 * and de-associates it from the hba.
 */
iscsi_status_t
iscsi_sess_destroy(iscsi_sess_t *isp)
{
	iscsi_status_t	rval	= ISCSI_STATUS_SUCCESS;
	iscsi_status_t	tmprval = ISCSI_STATUS_SUCCESS;
	iscsi_hba_t	*ihp;
	iscsi_sess_t	*t_isp;
	iscsi_lun_t	*ilp;
	iscsi_conn_t	*icp;

	ASSERT(isp != NULL);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);

	/*
	 * The first step in tearing down the session
	 * has to be offlining all the LUNs.  This will
	 * ensure there is no outstanding IO by upper
	 * level drivers.  If this fails then we are
	 * unable to destroy the session.
	 *
	 * Try all luns and continue upon failure
	 * to remove what is removable before returning
	 * the last error.
	 */
	rw_enter(&isp->sess_lun_list_rwlock, RW_WRITER);
	ilp = isp->sess_lun_list;
	while (ilp != NULL) {
		iscsi_lun_t	*ilp_next = ilp->lun_next;

		tmprval = iscsi_lun_destroy(ihp, ilp);
		if (!ISCSI_SUCCESS(tmprval)) {
			rval = tmprval;
		}
		ilp = ilp_next;
	}
	rw_exit(&isp->sess_lun_list_rwlock);

	if (!ISCSI_SUCCESS(rval)) {
		return (rval);
	}

	/* The next step is to logout of the connections. */
	rw_enter(&isp->sess_conn_list_rwlock, RW_WRITER);
	icp = isp->sess_conn_list;
	while (icp != NULL) {
		rval = iscsi_conn_offline(icp);
		if (ISCSI_SUCCESS(rval)) {
			/* Succes, Continue processing... */
			icp = icp->conn_next;
		} else {
			/* Failure, Stop processing... */
			rw_exit(&isp->sess_conn_list_rwlock);
			return (rval);
		}
	}
	rw_exit(&isp->sess_conn_list_rwlock);

	/*
	 * At this point all connections should be in
	 * a FREE state which will have pushed the session
	 * to a FREE state.
	 */
	ASSERT(isp->sess_state == ISCSI_SESS_STATE_FREE ||
	    isp->sess_state == ISCSI_SESS_STATE_FAILED);

	/* Stop watchdog before destroying connections */
	if (isp->sess_wd_thread) {
		iscsi_thread_destroy(isp->sess_wd_thread);
		isp->sess_wd_thread = NULL;
	}

	/* Destroy connections */
	rw_enter(&isp->sess_conn_list_rwlock, RW_WRITER);
	icp = isp->sess_conn_list;
	while (icp != NULL) {
		rval = iscsi_conn_destroy(icp);
		if (!ISCSI_SUCCESS(rval)) {
			rw_exit(&isp->sess_conn_list_rwlock);
			return (rval);
		}
		icp = isp->sess_conn_list;
	}
	rw_exit(&isp->sess_conn_list_rwlock);

	/* Destroy Session ic thread */
	if (isp->sess_ic_thread != NULL) {
		iscsi_thread_destroy(isp->sess_ic_thread);
		isp->sess_ic_thread = NULL;
	}

	/* Destroy session task queue */
	ddi_taskq_destroy(isp->sess_enum_taskq);
	ddi_taskq_destroy(isp->sess_login_taskq);

	/* destroy pending and completion queues */
	iscsi_destroy_queue(&isp->sess_queue_pending);
	iscsi_destroy_queue(&isp->sess_queue_completion);

	/* Remove session from ihp */
	if (ihp->hba_sess_list == isp) {
		/* session first item in list */
		ihp->hba_sess_list = isp->sess_next;
	} else {
		/*
		 * search hba list for isp pointing
		 * to session being removed.  Then
		 * update that sessions next pointer.
		 */
		t_isp = ihp->hba_sess_list;
		while (t_isp->sess_next != NULL) {
			if (t_isp->sess_next == isp) {
				break;
			}
			t_isp = t_isp->sess_next;
		}
		if (t_isp->sess_next == isp) {
			t_isp->sess_next = isp->sess_next;
		} else {
			/* couldn't find session */
			ASSERT(FALSE);
		}
	}

	if (isp->sess_type == ISCSI_SESS_TYPE_NORMAL) {
		/* Wait for all enum requests complete */
		mutex_enter(&isp->sess_enum_lock);
		while (isp->sess_enum_result_count > 0) {
			cv_wait(&isp->sess_enum_cv, &isp->sess_enum_lock);
		}
		mutex_exit(&isp->sess_enum_lock);
	}

	/* Destroy this Sessions Data */
	(void) iscsi_sess_kstat_term(isp);
	rw_destroy(&isp->sess_lun_list_rwlock);
	rw_destroy(&isp->sess_conn_list_rwlock);
	mutex_destroy(&isp->sess_cmdsn_mutex);
	rw_destroy(&isp->sess_state_rwlock);
	mutex_destroy(&isp->sess_reset_mutex);
	if (isp->sess_type == ISCSI_SESS_TYPE_NORMAL) {
		mutex_destroy(&isp->sess_enum_lock);
		cv_destroy(&isp->sess_enum_cv);
	}
	mutex_destroy(&isp->sess_state_wmutex);
	cv_destroy(&isp->sess_state_wcv);
	kmem_free(isp, sizeof (iscsi_sess_t));
	return (rval);
}

extern ib_boot_prop_t   *iscsiboot_prop;
/*
 * static iscsi_sess_set_auth -
 *
 */
boolean_t
iscsi_sess_set_auth(iscsi_sess_t *isp)
{
	char			*init_name;
	iscsi_chap_props_t	*chap = NULL;
	iscsi_auth_props_t	*auth = NULL;
	uchar_t			*tmp  = NULL;

	if (isp == (iscsi_sess_t *)NULL) {
		return (B_FALSE);
	}

	/* Obtain initiator's name */
	if (isp->sess_hba == (iscsi_hba_t *)NULL) {
		return (B_FALSE);
	}

	init_name = (char *)isp->sess_hba->hba_name;

	/* Zero out the session authentication structure */
	bzero(&isp->sess_auth, sizeof (iscsi_auth_t));

	if (isp->sess_boot == B_FALSE) {

		auth = (iscsi_auth_props_t *)kmem_zalloc
		    (sizeof (iscsi_auth_props_t), KM_SLEEP);
		/* Obtain target's authentication settings. */
		if (persistent_auth_get((char *)isp->sess_name, auth)
		    != B_TRUE) {
			/*
			 * If no target authentication settings found,
			 * try to obtain system wide configuration
			 * (from the initiator).
			 */
			bzero(auth, sizeof (*auth));
			if (persistent_auth_get(init_name, auth) != B_TRUE) {
				bzero(auth, sizeof (*auth));
				auth->a_auth_method = authMethodNone;
			}

			/*
			 * We do not support system wide bi-directional
			 * auth flag.
			 */
			auth->a_bi_auth = B_FALSE;
		}

		chap = (iscsi_chap_props_t *)kmem_zalloc
		    (sizeof (iscsi_chap_props_t), KM_SLEEP);

		/*
		 * Initialize the target-side chap name to the session name
		 * if no chap settings have been saved for the current session.
		 */
		if (persistent_chap_get((char *)isp->sess_name, chap)
		    == B_FALSE) {
			int name_len = strlen((char *)isp->sess_name);
			bcopy((char *)isp->sess_name, chap->c_user, name_len);
			chap->c_user_len = name_len;
			(void) (persistent_chap_set((char *)isp->sess_name,
			    chap));
			bzero(chap, sizeof (*chap));
		}

		if (auth->a_auth_method & authMethodCHAP) {
			/* Obtain initiator's CHAP settings. */
			if (persistent_chap_get(init_name, chap) == B_FALSE) {
				/* No initiator secret defined. */
				kmem_free(chap, sizeof (iscsi_chap_props_t));
				/* Set authentication method to NONE */
				isp->sess_auth.password_length = 0;
				kmem_free(auth, sizeof (iscsi_auth_props_t));
				return (B_FALSE);
			}

			bcopy(chap->c_user, isp->sess_auth.username,
			    sizeof (chap->c_user));
			bcopy(chap->c_secret, isp->sess_auth.password,
			    sizeof (chap->c_secret));
			isp->sess_auth.password_length = chap->c_secret_len;
		} else {
			/* Set authentication method to NONE */
			isp->sess_auth.password_length = 0;
		}

		/*
		 * Consider enabling bidirectional authentication only if
		 * authentication method is not NONE.
		 */
		if (auth->a_auth_method & authMethodCHAP &&
		    auth->a_bi_auth == B_TRUE) {
			/* Enable bi-directional authentication. */
			isp->sess_auth.bidirectional_auth = 1;

			bzero(chap, sizeof (*chap));
			/* Obtain target's CHAP settings. */
			if (persistent_chap_get((char *)isp->sess_name, chap)
			    == B_TRUE) {
				bcopy(chap->c_secret,
				    isp->sess_auth.password_in,
				    sizeof (chap->c_secret));
				bcopy(chap->c_user, isp->sess_auth.username_in,
				    strlen((char *)chap->c_user));
				isp->sess_auth.password_length_in =
				    chap->c_secret_len;
			} else {
				/*
				 * No target secret defined.
				 * RADIUS server should have been enabled.
				 */
				/* EMPTY */
			}
		} else {
			/* Disable bi-directional authentication */
			isp->sess_auth.bidirectional_auth = 0;
		}

		if (auth != NULL) {
			kmem_free(auth, sizeof (iscsi_auth_props_t));
		}
		if (chap != NULL) {
			kmem_free(chap, sizeof (iscsi_chap_props_t));
		}
	} else {
		/*
		 * This session is boot session. We will use the CHAP and
		 * the user name got from the boot property structure instead
		 * of persistent sotre.
		 */
		if (iscsiboot_prop == NULL) {
			return (B_FALSE);
		}

		if (iscsiboot_prop->boot_init.ini_chap_sec == NULL) {
			return (B_FALSE);
		}

		/* CHAP secret */
		(void) bcopy(iscsiboot_prop->boot_init.ini_chap_sec,
		    isp->sess_auth.password,
		    strlen((char *)iscsiboot_prop->boot_init.ini_chap_sec));

		/*
		 * If chap name is not set,
		 * we will use initiator name instead.
		 */
		if (iscsiboot_prop->boot_init.ini_chap_name == NULL) {
			(void) bcopy(init_name, isp->sess_auth.username,
			    strlen(init_name));
		} else {
			tmp = iscsiboot_prop->boot_init.ini_chap_name;
			(void) bcopy(tmp,
			    isp->sess_auth.username, strlen((char *)tmp));
		}

		isp->sess_auth.password_length =
		    strlen((char *)iscsiboot_prop->boot_init.ini_chap_sec);

		if (iscsiboot_prop->boot_tgt.tgt_chap_sec != NULL) {
			/*
			 * Bidirectional authentication is required.
			 */
			tmp = iscsiboot_prop->boot_tgt.tgt_chap_sec;
			(void) bcopy(tmp,
			    isp->sess_auth.password_in, strlen((char *)tmp));

			/*
			 * If the target's chap name is not set, we will use
			 * session name instead.
			 */
			if (iscsiboot_prop->boot_tgt.tgt_chap_name == NULL) {
				(void) bcopy(isp->sess_name,
				    isp->sess_auth.username_in,
				    isp->sess_name_length);
			} else {
				tmp = iscsiboot_prop->boot_tgt.tgt_chap_name;
				(void) bcopy(tmp,
				    isp->sess_auth.username_in,
				    strlen((char *)tmp));
			}
			tmp = iscsiboot_prop->boot_tgt.tgt_chap_sec;
			isp->sess_auth.password_length_in =
			    strlen((char *)tmp);
			isp->sess_auth.bidirectional_auth = 1;
		}
	}

	/* Set up authentication buffers only if configured */
	if ((isp->sess_auth.password_length != 0) ||
	    (isp->sess_auth.password_length_in != 0)) {
		isp->sess_auth.num_auth_buffers = 5;
		isp->sess_auth.auth_buffers[0].address =
		    &(isp->sess_auth.auth_client_block);
		isp->sess_auth.auth_buffers[0].length =
		    sizeof (isp->sess_auth.auth_client_block);
		isp->sess_auth.auth_buffers[1].address =
		    &(isp->sess_auth.auth_recv_string_block);
		isp->sess_auth.auth_buffers[1].length =
		    sizeof (isp->sess_auth.auth_recv_string_block);
		isp->sess_auth.auth_buffers[2].address =
		    &(isp->sess_auth.auth_send_string_block);
		isp->sess_auth.auth_buffers[2].length =
		    sizeof (isp->sess_auth.auth_send_string_block);
		isp->sess_auth.auth_buffers[3].address =
		    &(isp->sess_auth.auth_recv_binary_block);
		isp->sess_auth.auth_buffers[3].length =
		    sizeof (isp->sess_auth.auth_recv_binary_block);
		isp->sess_auth.auth_buffers[4].address =
		    &(isp->sess_auth.auth_send_binary_block);
		isp->sess_auth.auth_buffers[4].length =
		    sizeof (isp->sess_auth.auth_send_binary_block);
	}

	return (B_TRUE);
}

/*
 * iscsi_sess_reserve_itt - Used to reserve an ITT hash slot
 */
iscsi_status_t
iscsi_sess_reserve_scsi_itt(iscsi_cmd_t *icmdp)
{
	idm_task_t *itp;
	iscsi_conn_t *icp = icmdp->cmd_conn;
	itp = idm_task_alloc(icp->conn_ic);
	if (itp == NULL)
		return (ISCSI_STATUS_INTERNAL_ERROR);
	itp->idt_private = icmdp;
	icmdp->cmd_itp = itp;
	icmdp->cmd_itt = itp->idt_tt;
	return (ISCSI_STATUS_SUCCESS);
}

/*
 * iscsi_sess_release_scsi_itt - Used to release ITT hash slot
 */
void
iscsi_sess_release_scsi_itt(iscsi_cmd_t *icmdp)
{
	idm_task_free(icmdp->cmd_itp);
}

/*
 * iscsi_sess_reserve_itt - Used to reserve an ITT hash slot
 */
iscsi_status_t
iscsi_sess_reserve_itt(iscsi_sess_t *isp, iscsi_cmd_t *icmdp)
{
	/* If no more slots are open fail reservation */
	if (isp->sess_cmd_table_count >= ISCSI_CMD_TABLE_SIZE) {
		return (ISCSI_STATUS_ITT_TABLE_FULL);
	}

	/*
	 * Keep itt values out of the range used by IDM
	 */
	if (isp->sess_itt < IDM_TASKIDS_MAX)
		isp->sess_itt = IDM_TASKIDS_MAX;

	/*
	 * Find the next available slot.  Normally its the
	 * slot pointed to by the session's sess_itt value.
	 * If this is not true the table has become fragmented.
	 * Fragmentation can occur during max loads and IOs
	 * are completed out of order.  Defragmentation will
	 * occur when IO slows down and ITT slots are released.
	 */
	while (isp->sess_cmd_table[isp->sess_itt %
	    ISCSI_CMD_TABLE_SIZE] != NULL) {
		isp->sess_itt++;
	}

	/* reserve slot and update counters */
	icmdp->cmd_itt = isp->sess_itt;
	isp->sess_cmd_table[isp->sess_itt %
	    ISCSI_CMD_TABLE_SIZE] = icmdp;
	isp->sess_cmd_table_count++;
	isp->sess_itt++;

	return (ISCSI_STATUS_SUCCESS);
}

/*
 * iscsi_sess_release_itt - Used to release ITT hash slot
 */
void
iscsi_sess_release_itt(iscsi_sess_t *isp, iscsi_cmd_t *icmdp)
{
	int hash_index = (icmdp->cmd_itt % ISCSI_CMD_TABLE_SIZE);

	ASSERT(isp->sess_cmd_table[hash_index] != NULL);

	/* release slot and update counters */
	isp->sess_cmd_table[hash_index] = NULL;
	isp->sess_cmd_table_count--;
}

/*
 * iscsi_sess_redrive_io - Used to redrive IO on connections in
 * a full feature state.
 */
void
iscsi_sess_redrive_io(iscsi_sess_t *isp)
{
	iscsi_conn_t	*icp;

	ASSERT(isp != NULL);

	icp = isp->sess_conn_list;
	while (icp != NULL) {
		if (ISCSI_CONN_STATE_FULL_FEATURE(
		    icp->conn_state)) {
			(void) iscsi_thread_send_wakeup(
			    icp->conn_tx_thread);
		}
		icp = icp->conn_next;
	}
}

/*
 * iscsi_sess_state_machine -
 *
 * 7.3.1  Session State Diagram for an Initiator
 *
 *      Symbolic Names for States:
 *        Q1: FREE      - State on instantiation of after cleanup
 *        Q3: LOGGED_IN - Waiting for all session events.
 *        Q4: FAILED    - Waiting for session recovery or session cont.
 *        Q5: IN_FLUSH	- A login parameter has changed.  We are in the
 *			  process of flushing active, aborting, and
 *			  completed queues. Once flushed the iscsi_ic_thread()
 *			  will drop of drop connections (T14) and reconnect
 *			  to the target with new values.
 *	  Q6: FLUSHED	- Active, Aborting and Completed Queues flushed.
 *			  Awaiting reconnect or failure. iscsi_tx/ic_threads
 *			  are still running and might be timing-out IOs.
 *      State Q3/4 represent the Full Feature Phase operation of the session.
 *
 *      The state diagram is as follows:
 *
 *                                ------ (N5/6/7 == NOOP)
 *                               / Q1    \
 *    +------------------------->\       /<-------------+
 *    |                           ---+---               |
 *    |                     N5       |N1                |
 *    |  +------+   +-------------+  |                  |
 *    |  |      V   V             |  V                  |
 *    |  |      ----+--           -----+                |
 *    |N6|N5/7 / Q4    \         / Q3   \(N6 == NOOP)   |
 *    +--+-----\       /----+--->\      /-----+---------+
 *    |         -------    /N1    -+----      |       N3|
 *    |  (N7 == NOOP)     /      N7|  ^ N1/3/5|         |
 *    |                  /         |  +-------+         |
 *    |  +-------+      /          |                    |
 *    |  |       V     /           v                    |
 *    |  |      -------           -+----                |
 *    |N6|N6   / Q6    \    N5   / Q5   \               |
 *    +--+-----\       /<--------\      /-----+---------+
 *              -------           ------      |       N3
 *            (N7 == NOOP)            ^ N1/3/5|
 *                                    +-------+
 *
 * The state transition table is as follows:
 *
 *            +------+------+----+--------+----+
 *            |Q1    |Q3    |Q4  |Q5      |Q6  |
 *       -----+------+------+----+--------+----+
 *        Q1  |N5/6/7|N1    | -  |        |    |
 *       -----+------+------+----+--------+----+
 *        Q3  |N3    |N1/3/5|N5  |N7      |    |
 *       -----+------+------+----+--------+----+
 *        Q4  |N6    |N1    |N5/7|        |    |
 *       -----+------+------+----+--------+----+
 *        Q5  |N3    |      |    |N1/3/5/7|N6  |
 *       -----+------+------+----+--------+----+
 *        Q6  |N6    |N1    |N6/7|        |    |
 *       -----+------+------+----+--------+----+
 *
 * Event definitions:
 *
 * -N1: A connection logged in
 * -N3: A connection logged out
 * -N5: A connection failed
 * -N6: Session state timeout occurred, or a session
 *      reinstatement cleared this session instance.  This results in
 *      the freeing of all associated resources and the session state
 *      is discarded.
 * -N7: Login parameters for session have changed.
 *	Re-negeotation required.
 *
 * Any caller to the state machine (and so as a state writer) must
 * enter the state zone before calling this function, and vice versa
 * any caller that doesn't change the state machine shouldn't enter
 * the zone, and should act as a reader for a better performance.
 *
 * The handler of state transition shouldn't try to enter the state
 * zone in the same thread or dead lock will occur.
 */
void
iscsi_sess_state_machine(iscsi_sess_t *isp, iscsi_sess_event_t event,
    uint32_t event_count)
{
	ASSERT(isp != NULL);
	ASSERT(rw_read_locked(&isp->sess_state_rwlock) == 0);

	DTRACE_PROBE3(event, iscsi_sess_t *, isp,
	    char *, iscsi_sess_state_str(isp->sess_state),
	    char *, iscsi_sess_event_str(event));

	/* Audit event */
	idm_sm_audit_event(&isp->sess_state_audit,
	    SAS_ISCSI_SESS, isp->sess_state, event, 0);

	isp->sess_prev_state = isp->sess_state;
	isp->sess_state_lbolt = ddi_get_lbolt();

	ISCSI_SESS_LOG(CE_NOTE,
	    "DEBUG: sess_state: isp: %p state: %d event: %d event count: %d",
	    (void *)isp, isp->sess_state, event, event_count);
	switch (isp->sess_state) {
	case ISCSI_SESS_STATE_FREE:
		iscsi_sess_state_free(isp, event, event_count);
		break;
	case ISCSI_SESS_STATE_LOGGED_IN:
		iscsi_sess_state_logged_in(isp, event, event_count);
		break;
	case ISCSI_SESS_STATE_FAILED:
		iscsi_sess_state_failed(isp, event, event_count);
		break;
	case ISCSI_SESS_STATE_IN_FLUSH:
		iscsi_sess_state_in_flush(isp, event, event_count);
		break;
	case ISCSI_SESS_STATE_FLUSHED:
		iscsi_sess_state_flushed(isp, event, event_count);
		break;
	default:
		ASSERT(FALSE);
	}

	/* Audit state change */
	if (isp->sess_prev_state != isp->sess_state) {
		idm_sm_audit_state_change(&isp->sess_state_audit,
		    SAS_ISCSI_SESS, isp->sess_prev_state, isp->sess_state);
	}
}


/*
 * iscsi_sess_state_str -
 *
 */
char *
iscsi_sess_state_str(iscsi_sess_state_t state)
{
	switch (state) {
	case ISCSI_SESS_STATE_FREE:
		return ("free");
	case ISCSI_SESS_STATE_LOGGED_IN:
		return ("logged_in");
	case ISCSI_SESS_STATE_FAILED:
		return ("failed");
	case ISCSI_SESS_STATE_IN_FLUSH:
		return ("in_flush");
	case ISCSI_SESS_STATE_FLUSHED:
		return ("flushed");
	default:
		return ("unknown");
	}
}


/*
 * +--------------------------------------------------------------------+
 * | Internal Session Interfaces					|
 * +--------------------------------------------------------------------+
 */


/*
 * iscsi_sess_state_free -
 *
 */
static void
iscsi_sess_state_free(iscsi_sess_t *isp, iscsi_sess_event_t event,
    uint32_t event_count)
{
	iscsi_hba_t		*ihp;
	iscsi_enum_result_t	enum_result;

	ASSERT(isp != NULL);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);
	ASSERT(isp->sess_state == ISCSI_SESS_STATE_FREE);

	/* switch on event change */
	switch (event) {
	/*
	 * -N1: A connection logged in
	 */
	case ISCSI_SESS_EVENT_N1:
		isp->sess_state = ISCSI_SESS_STATE_LOGGED_IN;
		rw_downgrade(&isp->sess_state_rwlock);
		if (isp->sess_type == ISCSI_SESS_TYPE_NORMAL) {
			cmn_err(CE_NOTE,
			    "!iscsi session(%u) %s online\n",
			    isp->sess_oid, isp->sess_name);
			enum_result =
			    iscsi_sess_enum_request(isp, B_TRUE,
			    event_count);
			if (enum_result == ISCSI_SESS_ENUM_SUBMITTED) {
				enum_result =
				    iscsi_sess_enum_query(isp);
			}
			if (enum_result != ISCSI_SESS_ENUM_COMPLETE) {
				iscsi_sess_enum_warn(isp, enum_result);
			}
		}
		break;

	/*
	 * -N5: A connection failed
	 */
	case ISCSI_SESS_EVENT_N5:
		/* NOOP - not connected */
		break;

	/*
	 * -N6: Session state timeout occurred, or a session
	 *	reinstatement cleared this session instance.  This results in
	 *	the freeing of all associated resources and the session state
	 *	is discarded.
	 */
	case ISCSI_SESS_EVENT_N6:
		/* FALLTHRU */

	/*
	 * -N7: Login parameters for session have changed.
	 *	Re-negeotation required.
	 */
	case ISCSI_SESS_EVENT_N7:
		/* NOOP - not connected */
		break;

	/* All other events are invalid for this state */
	default:
		ASSERT(FALSE);
	}
}


/*
 * iscsi_sess_logged_in -
 *
 */
static void
iscsi_sess_state_logged_in(iscsi_sess_t *isp, iscsi_sess_event_t event,
    uint32_t event_count)
{
	iscsi_enum_result_t	enum_result;

	ASSERT(isp != NULL);
	ASSERT(isp->sess_state == ISCSI_SESS_STATE_LOGGED_IN);

	/* switch on event change */
	switch (event) {
	/*
	 * -N1: At least one transport connection reached the
	 * LOGGED_IN state
	 */
	case ISCSI_SESS_EVENT_N1:
		/*
		 * A different connection already logged in.  If the
		 * session is NORMAL, just re-enumerate the session.
		 */
		if (isp->sess_type == ISCSI_SESS_TYPE_NORMAL) {
			rw_downgrade(&isp->sess_state_rwlock);
			enum_result =
			    iscsi_sess_enum_request(isp, B_TRUE, event_count);
			if (enum_result == ISCSI_SESS_ENUM_SUBMITTED) {
				enum_result = iscsi_sess_enum_query(isp);
			}
			if (enum_result != ISCSI_SESS_ENUM_COMPLETE) {
				iscsi_sess_enum_warn(isp, enum_result);
			}
		}
		break;

	/*
	 * -N3: A connection logged out.
	 */
	case ISCSI_SESS_EVENT_N3:
		/* FALLTHRU */

	/*
	 * -N5: A connection failed
	 */
	case ISCSI_SESS_EVENT_N5:
		/*
		 * MC/S: If this is the last connection to
		 * fail then move the the failed state.
		 */
		if (event == ISCSI_SESS_EVENT_N3) {
			isp->sess_state = ISCSI_SESS_STATE_FREE;
		} else {
			isp->sess_state = ISCSI_SESS_STATE_FAILED;
		}
		rw_downgrade(&isp->sess_state_rwlock);

		/* no longer connected reset nego tpgt */
		isp->sess_tpgt_nego = ISCSI_DEFAULT_TPGT;

		iscsi_sess_flush(isp);

		if (event == ISCSI_SESS_EVENT_N3) {
			if (isp->sess_type == ISCSI_SESS_TYPE_NORMAL) {
				cmn_err(CE_NOTE,
				    "!iscsi session(%u) %s offline\n",
				    isp->sess_oid, isp->sess_name);
			}
			/*
			 * During the process of offlining the LUNs
			 * our ic thread might be calling back into
			 * the driver via a target driver failure
			 * path to do a reset or something
			 * we need to release the sess_state_mutex
			 * while we are killing these threads so
			 * they don't get deadlocked.
			 */
			iscsi_sess_offline_luns(isp);
		}

		mutex_enter(&isp->sess_reset_mutex);
		isp->sess_reset_in_progress = B_FALSE;
		mutex_exit(&isp->sess_reset_mutex);
		/* update busy luns if needed */
		iscsi_sess_update_busy_luns(isp, B_TRUE);

		break;

	/*
	 * -N6: Session state timeout occurred, or a session
	 *	reinstatement cleared this session instance.  This results in
	 *	the freeing of all associated resources and the session state
	 *	is discarded.
	 */
	case ISCSI_SESS_EVENT_N6:
		/* NOOP - Not last connection */
		break;

	/*
	 * -N7: Login parameters for session have changed.
	 *	Re-negeotation required.
	 */
	case ISCSI_SESS_EVENT_N7:
		isp->sess_state = ISCSI_SESS_STATE_IN_FLUSH;
		break;

	/* All other events are invalid for this state */
	default:
		ASSERT(FALSE);
	}
}


/*
 * iscsi_sess_state_failed -
 *
 */
static void
iscsi_sess_state_failed(iscsi_sess_t *isp, iscsi_sess_event_t event,
    uint32_t event_count)
{
	iscsi_hba_t		*ihp;
	iscsi_enum_result_t	enum_result;

	ASSERT(isp != NULL);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);
	ASSERT(isp->sess_state == ISCSI_SESS_STATE_FAILED);

	/* switch on event change */
	switch (event) {
	/* -N1: A session continuation attempt succeeded */
	case ISCSI_SESS_EVENT_N1:
		isp->sess_state = ISCSI_SESS_STATE_LOGGED_IN;
		rw_downgrade(&isp->sess_state_rwlock);
		if (isp->sess_type == ISCSI_SESS_TYPE_NORMAL) {
			enum_result =
			    iscsi_sess_enum_request(isp, B_TRUE,
			    event_count);
			if (enum_result == ISCSI_SESS_ENUM_SUBMITTED) {
				enum_result =
				    iscsi_sess_enum_query(isp);
			}
			if (enum_result != ISCSI_SESS_ENUM_COMPLETE) {
				iscsi_sess_enum_warn(isp, enum_result);
			}
		}
		break;

	/*
	 * -N5: A connection failed
	 */
	case ISCSI_SESS_EVENT_N5:
		/* NOOP - not connected */
		break;

	/*
	 * -N6: Session state timeout occurred, or a session
	 *	reinstatement cleared this session instance.  This results in
	 *	the freeing of all associated resources and the session state
	 *	is discarded.
	 */
	case ISCSI_SESS_EVENT_N6:
		isp->sess_state = ISCSI_SESS_STATE_FREE;

		if (isp->sess_type == ISCSI_SESS_TYPE_NORMAL) {
			cmn_err(CE_NOTE, "!iscsi session(%u) %s offline\n",
			    isp->sess_oid, isp->sess_name);
		}

		rw_downgrade(&isp->sess_state_rwlock);
		iscsi_sess_offline_luns(isp);
		break;

	/*
	 * -N7: Login parameters for session have changed.
	 *	Re-negeotation required.
	 */
	case ISCSI_SESS_EVENT_N7:
		/* NOOP - not connected */
		break;

	/* All other events are invalid for this state */
	default:
		ASSERT(FALSE);
	}
}

/*
 * iscsi_sess_state_in_flush -
 *
 */
/* ARGSUSED */
static void
iscsi_sess_state_in_flush(iscsi_sess_t *isp, iscsi_sess_event_t event,
    uint32_t event_count)
{
	ASSERT(isp != NULL);
	ASSERT(isp->sess_state == ISCSI_SESS_STATE_IN_FLUSH);

	/* switch on event change */
	switch (event) {
	/* -N1: A session continuation attempt succeeded */
	case ISCSI_SESS_EVENT_N1:
		/* NOOP - connections already online */
		break;

	/*
	 * -N3: A connection logged out.
	 */
	case ISCSI_SESS_EVENT_N3:
		/* FALLTHRU */

	/*
	 * -N5: A connection failed
	 */
	case ISCSI_SESS_EVENT_N5:
		/*
		 * MC/S: If this is the last connection to
		 * fail then move the the failed state.
		 */
		if (event == ISCSI_SESS_EVENT_N3) {
			isp->sess_state = ISCSI_SESS_STATE_FREE;
		} else {
			isp->sess_state = ISCSI_SESS_STATE_FLUSHED;
		}
		rw_downgrade(&isp->sess_state_rwlock);

		/* no longer connected reset nego tpgt */
		isp->sess_tpgt_nego = ISCSI_DEFAULT_TPGT;
		iscsi_sess_flush(isp);

		if (event == ISCSI_SESS_EVENT_N3) {
			if (isp->sess_type == ISCSI_SESS_TYPE_NORMAL) {
				cmn_err(CE_NOTE,
				    "!iscsi session(%u) %s offline\n",
				    isp->sess_oid, isp->sess_name);
			}
			/*
			 * During the process of offlining the LUNs
			 * our ic thread might be calling back into
			 * the driver via a target driver failure
			 * path to do a reset or something
			 * we need to release the sess_state_mutex
			 * while we are killing these threads so
			 * they don't get deadlocked.
			 */
			iscsi_sess_offline_luns(isp);
		}

		mutex_enter(&isp->sess_reset_mutex);
		isp->sess_reset_in_progress = B_FALSE;
		mutex_exit(&isp->sess_reset_mutex);
		/* update busy luns if needed */
		iscsi_sess_update_busy_luns(isp, B_TRUE);

		break;

	/*
	 * -N6: Session state timeout occurred, or a session
	 *	reinstatement cleared this session instance.  This results in
	 *	the freeing of all associated resources and the session state
	 *	is discarded.
	 */
	case ISCSI_SESS_EVENT_N6:
		/* NOOP - Not last connection */
		break;

	/*
	 * -N7: Login parameters for session have changed.
	 *	Re-negeotation required.
	 */
	case ISCSI_SESS_EVENT_N7:
		/* NOOP - Already attempting to update */
		break;

	/* All other events are invalid for this state */
	default:
		ASSERT(FALSE);
	}
}


/*
 * iscsi_sess_state_flushed -
 *
 */
static void
iscsi_sess_state_flushed(iscsi_sess_t *isp, iscsi_sess_event_t event,
    uint32_t event_count)
{
	iscsi_hba_t	*ihp;
	iscsi_enum_result_t	enum_result;

	ASSERT(isp != NULL);
	ASSERT(isp->sess_state == ISCSI_SESS_STATE_FLUSHED);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);

	/* switch on event change */
	switch (event) {
	/* -N1: A session continuation attempt succeeded */
	case ISCSI_SESS_EVENT_N1:
		isp->sess_state = ISCSI_SESS_STATE_LOGGED_IN;
		rw_downgrade(&isp->sess_state_rwlock);
		if (isp->sess_type == ISCSI_SESS_TYPE_NORMAL) {
			enum_result =
			    iscsi_sess_enum_request(isp, B_TRUE,
			    event_count);
			if (enum_result == ISCSI_SESS_ENUM_SUBMITTED) {
				enum_result =
				    iscsi_sess_enum_query(isp);
			}
			if (enum_result != ISCSI_SESS_ENUM_COMPLETE) {
				iscsi_sess_enum_warn(isp, enum_result);
			}
		}
		break;

	/*
	 * -N6: Session state timeout occurred, or a session
	 *	reinstatement cleared this session instance.  This results in
	 *	the freeing of all associated resources and the session state
	 *	is discarded.
	 */
	case ISCSI_SESS_EVENT_N6:
		isp->sess_state = ISCSI_SESS_STATE_FREE;
		rw_downgrade(&isp->sess_state_rwlock);

		if (isp->sess_type == ISCSI_SESS_TYPE_NORMAL) {
			cmn_err(CE_NOTE, "!iscsi session(%u) %s offline\n",
			    isp->sess_oid, isp->sess_name);
		}

		iscsi_sess_offline_luns(isp);
		break;

	/*
	 * -N7: Login parameters for session have changed.
	 *	Re-negeotation required.
	 */
	case ISCSI_SESS_EVENT_N7:
		/* NOOP - not connected */
		break;

	/* All other events are invalid for this state */
	default:
		ASSERT(FALSE);
	}
}

/*
 * iscsi_sess_event_str -
 *
 */
static char *
iscsi_sess_event_str(iscsi_sess_event_t event)
{
	switch (event) {
	case ISCSI_SESS_EVENT_N1:
		return ("N1");
	case ISCSI_SESS_EVENT_N3:
		return ("N3");
	case ISCSI_SESS_EVENT_N5:
		return ("N5");
	case ISCSI_SESS_EVENT_N6:
		return ("N6");
	case ISCSI_SESS_EVENT_N7:
		return ("N7");
	default:
		return ("unknown");
	}
}

/*
 * iscsi_sess_thread_create -
 *
 */
static iscsi_status_t
iscsi_sess_threads_create(iscsi_sess_t *isp)
{
	iscsi_hba_t	*ihp;
	char		th_name[ISCSI_TH_MAX_NAME_LEN];

	ASSERT(isp != NULL);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);

	/* Completion thread creation. */
	if (snprintf(th_name, sizeof (th_name) - 1,
	    ISCSI_SESS_IOTH_NAME_FORMAT, ihp->hba_oid,
	    isp->sess_oid) >= sizeof (th_name)) {
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	isp->sess_ic_thread = iscsi_thread_create(ihp->hba_dip,
	    th_name, iscsi_ic_thread, isp);

	if (isp->sess_ic_thread == NULL) {
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	(void) iscsi_thread_start(isp->sess_ic_thread);

	return (ISCSI_STATUS_SUCCESS);
}

/*
 * iscsi_sess_enumeration - This function is used to drive the enumeration
 * of LUs on a session.  It will first prepare the target by sending test
 * unit ready commands, then it will issue a report luns.  If the report
 * luns is successful then it will process all the luns in the report.
 * If report luns is not successful we will do a stepping enumeration
 * of luns until no more luns are found.
 */
static void
iscsi_sess_enumeration(void *arg)
{
	iscsi_task_t		*itp = (iscsi_task_t *)arg;
	iscsi_sess_t		*isp;
	iscsi_status_t		rval    = ISCSI_STATUS_SUCCESS;
	iscsi_enum_result_t	enum_result = ISCSI_SESS_ENUM_COMPLETE;
	uint32_t		event_count = itp->t_event_count;

	ASSERT(itp != NULL);
	isp = (iscsi_sess_t *)itp->t_arg;
	ASSERT(isp != NULL);

	/*
	 * Send initial TEST_UNIT_READY to target.  If it fails this we
	 * stop our enumeration as the target is not responding properly.
	 */
	rval = iscsi_sess_testunitready(isp, event_count);
	if (ISCSI_SUCCESS(rval)) {
		/*
		 * Now we know the target is ready start our enumeration with
		 * REPORT LUNs, If this fails we will have to fall back to
		 * stepping
		 */
		rval = iscsi_sess_reportluns(isp, event_count);
		if (!ISCSI_SUCCESS(rval)) {
			/*
			 * report luns failed so lets just check for LUN 0.
			 * This will match fcp's enumeration support and
			 * avoid issues with older devices like the A5K that
			 * respond poorly.
			 */
			if (isp->sess_lun_list == NULL) {
				iscsi_sess_inquiry(isp, 0, 0, event_count,
				    NULL);
			}
		}
	} else {
		enum_result = ISCSI_SESS_ENUM_TUR_FAIL;
	}

	kmem_free(itp, sizeof (iscsi_task_t));
	mutex_enter(&isp->sess_enum_lock);
	if (isp->sess_enum_result_count != 0) {
		isp->sess_enum_status = ISCSI_SESS_ENUM_DONE;
	} else {
		isp->sess_enum_status = ISCSI_SESS_ENUM_FREE;
	}
	isp->sess_enum_result = enum_result;
	cv_broadcast(&isp->sess_enum_cv);
	mutex_exit(&isp->sess_enum_lock);
}

/*
 * iscsi_sess_testunitready - This is used during enumeration to
 * ensure an array is ready to be enumerated.
 */
static iscsi_status_t
iscsi_sess_testunitready(iscsi_sess_t *isp, uint32_t event_count)
{
	iscsi_status_t			rval		= ISCSI_STATUS_SUCCESS;
	int				retries		= 0;
	struct uscsi_cmd		ucmd;
	char				cdb[CDB_GROUP0];

	ASSERT(isp != NULL);

	/* loop until successful sending test unit ready or retries out */
	while ((retries++ < 3) &&
	    (isp->sess_state_event_count == event_count)) {
		/* cdb is all zeros */
		bzero(&cdb[0], CDB_GROUP0);

		/* setup uscsi cmd */
		bzero(&ucmd, sizeof (struct uscsi_cmd));
		ucmd.uscsi_timeout	= iscsi_sess_enum_timeout;
		ucmd.uscsi_cdb		= &cdb[0];
		ucmd.uscsi_cdblen	= CDB_GROUP0;

		/* send test unit ready to lun zero on this session */
		rval = iscsi_handle_passthru(isp, 0, &ucmd);

		/*
		 * If passthru was successful then we were able to
		 * communicate with the target, continue enumeration.
		 */
		if (ISCSI_SUCCESS(rval)) {
			break;
		}
	}

	return (rval);
}

#define	SCSI_REPORTLUNS_ADDRESS_SIZE			8
#define	SCSI_REPORTLUNS_ADDRESS_MASK			0xC0
#define	SCSI_REPORTLUNS_ADDRESS_PERIPHERAL		0x00
#define	SCSI_REPORTLUNS_ADDRESS_FLAT_SPACE		0x40
#define	SCSI_REPORTLUNS_ADDRESS_LOGICAL_UNIT		0x80
#define	SCSI_REPORTLUNS_ADDRESS_EXTENDED_UNIT		0xC0
#define	SCSI_REPORTLUNS_ADDRESS_LOGICAL_UNIT_2B		0x00
#define	SCSI_REPORTLUNS_ADDRESS_LOGICAL_UNIT_4B		0x01
#define	SCSI_REPORTLUNS_ADDRESS_LOGICAL_UNIT_6B		0x10
#define	SCSI_REPORTLUNS_ADDRESS_LOGICAL_UNIT_8B		0x20
#define	SCSI_REPORTLUNS_ADDRESS_LOGICAL_UNIT_SIZE	0x30

/*
 * iscsi_sess_reportluns - This is used during enumeration to
 * ensure an array is ready to be enumerated.
 */
static iscsi_status_t
iscsi_sess_reportluns(iscsi_sess_t *isp, uint32_t event_count)
{
	iscsi_status_t		rval		= ISCSI_STATUS_SUCCESS;
	iscsi_hba_t		*ihp;
	struct uscsi_cmd	ucmd;
	unsigned char		cdb[CDB_GROUP5];
	unsigned char		*buf		= NULL;
	int			buf_len		= sizeof (struct scsi_inquiry);
	uint32_t		lun_list_length = 0;
	uint16_t		lun_num		= 0;
	uint8_t			lun_addr_type	= 0;
	uint32_t		lun_count	= 0;
	uint32_t		lun_start	= 0;
	uint32_t		lun_total	= 0;
	int			retries		= 0;
	iscsi_lun_t		*ilp_next;
	iscsi_lun_t		*ilp		= NULL;
	replun_data_t		*saved_replun_ptr = NULL;

	ASSERT(isp != NULL);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);

	/*
	 * Attempt to send report luns until we successfully
	 * get all the data or the retries run out.
	 */
	while ((retries++ < 3) &&
	    (isp->sess_state_event_count == event_count)) {
		/*
		 * Allocate our buffer based on current buf_len.
		 * buf_len may change after we received a response
		 * from the target.
		 */
		if (buf == NULL) {
			buf = kmem_zalloc(buf_len, KM_SLEEP);
		}

		/* setup cdb */
		bzero(&cdb, CDB_GROUP5);
		cdb[0] = SCMD_REPORT_LUNS;
		cdb[6] = (buf_len & 0xff000000) >> 24;
		cdb[7] = (buf_len & 0x00ff0000) >> 16;
		cdb[8] = (buf_len & 0x0000ff00) >> 8;
		cdb[9] = (buf_len & 0x000000ff);

		/* setup uscsi cmd */
		bzero(&ucmd, sizeof (struct uscsi_cmd));
		ucmd.uscsi_flags	= USCSI_READ;
		ucmd.uscsi_timeout	= iscsi_sess_enum_timeout;
		ucmd.uscsi_cdb		= (char *)&cdb[0];
		ucmd.uscsi_cdblen	= CDB_GROUP5;
		ucmd.uscsi_bufaddr	= (char *)buf;
		ucmd.uscsi_buflen	= buf_len;

		/* send uscsi cmd to lun 0 on session */
		rval = iscsi_handle_passthru(isp, 0, &ucmd);

		/* If passthru successful but not scsi status update istatus */
		if (ISCSI_SUCCESS(rval) &&
		    (ucmd.uscsi_status != STATUS_GOOD)) {
			rval = ISCSI_STATUS_USCSI_FAILED;
		}

		/* If successful, check if we have all the data */
		if (ISCSI_SUCCESS(rval)) {
			/* total data - header (SCSI_REPORTLUNS_ADDRESS_SIZE) */
			lun_list_length	= htonl(*(uint32_t *)buf);

			if (buf_len >= lun_list_length +
			    SCSI_REPORTLUNS_ADDRESS_SIZE) {
				/* we have all the data, were done */
				break;
			}

			/*
			 * We don't have all the data.  free up the
			 * memory for the next pass and update the
			 * buf_len
			 */
			kmem_free(buf, buf_len);
			buf = NULL;
			buf_len = lun_list_length +
			    SCSI_REPORTLUNS_ADDRESS_SIZE;
		} else {
			retries++;
		}
	}

	if (isp->sess_state_event_count != event_count) {
		if (buf != NULL) {
			kmem_free(buf, buf_len);
			buf = NULL;
		}
		return (rval);
	}

	/* If not successful go no further */
	if (!ISCSI_SUCCESS(rval)) {
		kmem_free(buf, buf_len);
		return (rval);
	}

	/*
	 * find out the number of luns returned by the SCSI ReportLun call
	 * and allocate buffer space
	 */
	lun_total = lun_list_length / SCSI_REPORTLUNS_ADDRESS_SIZE;
	saved_replun_ptr = kmem_zalloc(lun_total * sizeof (replun_data_t),
	    KM_SLEEP);

	/*
	 * walk the isp->sess_lun_list
	 * for each lun in this list
	 *	look to see if this lun is in the SCSI ReportLun list we
	 *	    just retrieved
	 *	if it is in the SCSI ReportLun list and it is already ONLINE or
	 *	if it is in the SCSI ReportLun list and it is OFFLINE or
	 *	if it isn't in the SCSI ReportLunlist or then
	 *	    issue the iscsi_sess_inquiry() to handle
	 *
	 *	as we walk the SCSI ReportLun list, we save this lun information
	 *	    into the buffer we just allocated.  This will save us from
	 *	    having to figure out this information later
	 */
	lun_start = 0;
	rw_enter(&isp->sess_lun_list_rwlock, RW_WRITER);
	for (ilp = isp->sess_lun_list; ilp; ilp = ilp_next) {
		if (isp->sess_state_event_count != event_count)
			break;

		ilp_next = ilp->lun_next;

		for (lun_count = lun_start; lun_count < lun_total;
		    lun_count++) {
			/*
			 * if the first lun in saved_replun_ptr buffer has
			 * already been found we can move on and do not
			 * have to check this lun in the future
			 */
			if (lun_count == lun_start &&
			    saved_replun_ptr[lun_start].lun_found) {
				lun_start++;
				continue;
			}
			/*
			 * check to see if the lun we are looking for is in the
			 * saved_replun_ptr buffer
			 * if it is, process the lun
			 * if it isn't, then we must go to SCSI
			 * Report Lun buffer
			 * we retrieved to get lun info
			 */
			if ((saved_replun_ptr[lun_count].lun_valid
			    == B_TRUE) &&
			    (saved_replun_ptr[lun_count].lun_num
			    == ilp->lun_num)) {
				/*
				 * the lun we are looking for is found,
				 * give it to iscsi_sess_inquiry()
				 */
				rw_exit(&isp->sess_lun_list_rwlock);
				iscsi_sess_inquiry(isp, ilp->lun_num,
				    saved_replun_ptr[lun_count].lun_addr_type,
				    event_count, ilp);
				rw_enter(&isp->sess_lun_list_rwlock,
				    RW_WRITER);
				saved_replun_ptr[lun_count].lun_found
				    = B_TRUE;
				break;
			} else {
				/*
				 * lun information is not found in the
				 * saved_replun buffer, retrieve lun
				 * information from the SCSI Report Lun buffer
				 * and store this information in the
				 * saved_replun buffer
				 */
				if (retrieve_lundata(lun_count, buf, isp,
				    &lun_num, &lun_addr_type) !=
				    ISCSI_STATUS_SUCCESS) {
					continue;
				}
				saved_replun_ptr[lun_count].lun_valid = B_TRUE;
				saved_replun_ptr[lun_count].lun_num = lun_num;
				saved_replun_ptr[lun_count].lun_addr_type =
				    lun_addr_type;
				if (ilp->lun_num == lun_num) {
					/*
					 * lun is found in the SCSI Report Lun
					 * buffer, give it to inquiry
					 */
					rw_exit(&isp->sess_lun_list_rwlock);
					iscsi_sess_inquiry(isp, lun_num,
					    lun_addr_type, event_count, ilp);
					rw_enter(&isp->sess_lun_list_rwlock,
					    RW_WRITER);
					saved_replun_ptr[lun_count].lun_found
					    = B_TRUE;
					break;
				}
			}
		}

		if (lun_count == lun_total) {
			/*
			 * this lun we found in the sess->lun_list does
			 * not exist anymore, need to offline this lun
			 */

			DTRACE_PROBE2(
			    sess_reportluns_lun_no_longer_exists,
			    int, ilp->lun_num, int, ilp->lun_state);

			(void) iscsi_lun_destroy(ihp, ilp);
		}
	}
	rw_exit(&isp->sess_lun_list_rwlock);
	/*
	 * look for new luns that we found in the SCSI Report Lun buffer that
	 * we did not have in the sess->lun_list and add them into the list
	 */
	for (lun_count = lun_start; lun_count < lun_total; lun_count++) {
		if (saved_replun_ptr[lun_count].lun_valid == B_FALSE) {
			/*
			 * lun information is not in the
			 * saved_replun buffer, retrieve
			 * it from the SCSI Report Lun buffer
			 */
			if (retrieve_lundata(lun_count, buf, isp,
			    &lun_num, &lun_addr_type) != ISCSI_STATUS_SUCCESS) {
				continue;
			}
		} else {
			/*
			 * lun information is in the saved_replun buffer
			 * if this lun has been found already,
			 * then we can move on
			 */
			if (saved_replun_ptr[lun_count].lun_found == B_TRUE) {
				continue;
			}
			lun_num = saved_replun_ptr[lun_count].lun_num;
			lun_addr_type =
			    saved_replun_ptr[lun_count].lun_addr_type;
		}


		/* New luns found should not conflict with existing luns */
		rw_enter(&isp->sess_lun_list_rwlock, RW_READER);
		for (ilp = isp->sess_lun_list; ilp; ilp = ilp->lun_next) {
			if (ilp->lun_num == lun_num) {
				break;
			}
		}
		rw_exit(&isp->sess_lun_list_rwlock);

		if (ilp == NULL) {
			/* new lun found, add this lun */
			iscsi_sess_inquiry(isp, lun_num, lun_addr_type,
			    event_count, NULL);
		} else {
			cmn_err(CE_NOTE,
			    "!Duplicate Lun Number(%d) recieved from "
			    "Target(%s)", lun_num, isp->sess_name);
		}
	}
	if (buf != NULL) {
		kmem_free(buf, buf_len);
	}
	kmem_free(saved_replun_ptr, lun_total * sizeof (replun_data_t));

	return (rval);
}

#define	ISCSI_MAX_INQUIRY_BUF_SIZE	0xFF
#define	ISCSI_MAX_INQUIRY_RETRIES	3

/*
 * iscsi_sess_inquiry - Final processing of a LUN before we create a tgt
 * mapping, if necessary the old lun will be deleted.
 *
 * We need to collect the stardard inquiry page and the
 * vendor identification page for this LUN.  If both of these are
 * successful and the identification page contains a NAA or EUI type
 * we will continue.  Otherwise we fail the creation of a tgt for
 * this LUN.
 *
 * Keep the old lun unchanged if it is online and following things are
 * match, lun_addr_type, lun_type, and lun_guid.
 *
 * Online the old lun if it is offline/invalid and those three things
 * are match.
 *
 * Online a new lun if the old lun is offline and any of those three things
 * is not match, and needs to destroy the old first.
 *
 * Destroy the old lun and online the new lun if the old is online/invalid
 * and any of those three things is not match, and then online the new lun
 */
static void
iscsi_sess_inquiry(iscsi_sess_t *isp, uint16_t lun_num, uint8_t lun_addr_type,
    uint32_t event_count, iscsi_lun_t *ilp)
{
	iscsi_status_t		rval;
	struct uscsi_cmd	ucmd;
	uchar_t			cdb[CDB_GROUP0];
	uchar_t			*inq;
	size_t			inq_len;
	uchar_t			*inq83;
	size_t			inq83_len;
	int			retries;
	ddi_devid_t		devid;
	char			*guid = NULL;
	iscsi_hba_t		*ihp;
	iscsi_status_t		status = ISCSI_STATUS_SUCCESS;
	boolean_t		inq_ready = B_FALSE;
	boolean_t		inq83_ready = B_FALSE;
	boolean_t		nochange = B_FALSE;
	uchar_t			lun_type;

	ASSERT(isp != NULL);
	ihp	= isp->sess_hba;
	ASSERT(ihp != NULL);

	inq	= kmem_zalloc(ISCSI_MAX_INQUIRY_BUF_SIZE, KM_SLEEP);
	inq83	= kmem_zalloc(ISCSI_MAX_INQUIRY_BUF_SIZE, KM_SLEEP);

	if (ilp == NULL) {
		/* easy case, just to create the new lun */
		goto sess_inq;
	}

	if (ilp->lun_addr_type != lun_addr_type) {
		goto offline_old;
	}

	goto sess_inq;

offline_old:
	if (isp->sess_state_event_count != event_count) {
		goto inq_done;
	}

	status = iscsi_lun_destroy(ihp, ilp);
	if (status != ISCSI_STATUS_SUCCESS) {
		/* have to abort the process */
		cmn_err(CE_WARN, "iscsi session(%u) is unable to offline"
		    " obsolete logical unit %d", isp->sess_oid, lun_num);
		goto inq_done;
	}
	ilp = NULL;

sess_inq:
	if (inq_ready == B_TRUE) {
		goto sess_inq83;
	}
	/*
	 * STANDARD INQUIRY - We need the standard inquiry information
	 * to feed into the scsi_hba_nodename_compatible_get function.
	 * This function is used to detemine which driver will bind
	 * on top of us, via the compatible id.
	 */
	bzero(&cdb, CDB_GROUP0);
	cdb[0] = SCMD_INQUIRY;
	cdb[4] = ISCSI_MAX_INQUIRY_BUF_SIZE;

	bzero(&ucmd, sizeof (struct uscsi_cmd));
	ucmd.uscsi_flags	= USCSI_READ;
	ucmd.uscsi_timeout	= iscsi_sess_enum_timeout;
	ucmd.uscsi_cdb		= (char *)&cdb[0];
	ucmd.uscsi_cdblen	= CDB_GROUP0;
	ucmd.uscsi_bufaddr	= (char *)inq;
	ucmd.uscsi_buflen	= ISCSI_MAX_INQUIRY_BUF_SIZE;

	/* Attempt to get inquiry information until successful or retries */
	retries = 0;
	while ((retries++ < ISCSI_MAX_INQUIRY_RETRIES) &&
	    (isp->sess_state_event_count == event_count)) {
		/* issue passthru */
		rval = iscsi_handle_passthru(isp, lun_num, &ucmd);

		/* If we were successful but scsi stat failed update istatus */
		if (ISCSI_SUCCESS(rval) &&
		    (ucmd.uscsi_status != STATUS_GOOD)) {
			rval = ISCSI_STATUS_USCSI_FAILED;
		}

		/* If successful break */
		if (ISCSI_SUCCESS(rval)) {
			inq_len = ISCSI_MAX_INQUIRY_BUF_SIZE - ucmd.uscsi_resid;
			break;
		}

		/* loop until we are successful or retries run out */
	}

	/* If failed don't continue */
	if (!ISCSI_SUCCESS(rval)) {
		cmn_err(CE_NOTE, "iscsi session(%u) unable to enumerate "
		    "logical unit - inquiry failed lun %d",
		    isp->sess_oid, lun_num);

		goto inq_done;
	}
	inq_ready = B_TRUE;

sess_inq83:
	/*
	 * T-10 SPC Section 6.4.2.  Standard INQUIRY Peripheral
	 * qualifier of 000b is the only type we should attempt
	 * to plumb under the IO stack.
	 */
	if ((inq[0] & SCSI_INQUIRY_PQUAL_MASK) != 0x00) {
		/* shouldn't enumerate, destroy the old one if exists */
		if (ilp != NULL) {
			goto offline_old;
		}
		goto inq_done;
	}

	/*
	 * If lun type has changed
	 */
	lun_type = ((struct scsi_inquiry *)inq)->inq_dtype & DTYPE_MASK;
	if ((ilp != NULL) && (ilp->lun_type != lun_type)) {
		goto offline_old;
	}

	if (inq83_ready == B_TRUE) {
		goto guid_ready;
	}

	/*
	 * VENDOR IDENTIFICATION INQUIRY - This will be used to identify
	 * a unique lunId.  This Id is passed to the mdi alloc calls so
	 * we can properly plumb into scsi_vhci/mpxio.
	 */

	bzero(&cdb, CDB_GROUP0);
	cdb[0] = SCMD_INQUIRY;
	cdb[1] = 0x01; /* EVP bit */
	cdb[2] = 0x83;
	cdb[4] = ISCSI_MAX_INQUIRY_BUF_SIZE;

	ucmd.uscsi_flags	= USCSI_READ;
	ucmd.uscsi_timeout	= iscsi_sess_enum_timeout;
	ucmd.uscsi_cdb		= (char *)&cdb[0];
	ucmd.uscsi_cdblen	= CDB_GROUP0;
	ucmd.uscsi_bufaddr	= (char *)inq83;
	ucmd.uscsi_buflen	= ISCSI_MAX_INQUIRY_BUF_SIZE;

	/* Attempt to get inquiry information until successful or retries */
	retries = 0;
	while ((retries++ < ISCSI_MAX_INQUIRY_RETRIES) &&
	    (isp->sess_state_event_count == event_count)) {
		/* issue passthru command */
		rval = iscsi_handle_passthru(isp, lun_num, &ucmd);

		/* If we were successful but scsi stat failed update istatus */
		if (ISCSI_SUCCESS(rval) &&
		    (ucmd.uscsi_status != STATUS_GOOD)) {
			rval = ISCSI_STATUS_USCSI_FAILED;
		}

		/* Break if successful */
		if (ISCSI_SUCCESS(rval)) {
			inq83_len = ISCSI_MAX_INQUIRY_BUF_SIZE -
			    ucmd.uscsi_resid;
			break;
		}
	}

	/*
	 * If we were successful collecting page 83 data attempt
	 * to generate a GUID.  If no GUID can be generated then
	 * the logical unit will skip attempt to plumb under
	 * scsi_vhci/mpxio.
	 */
	if (ISCSI_SUCCESS(rval)) {
		/* create DEVID from inquiry data */
		if (ddi_devid_scsi_encode(
		    DEVID_SCSI_ENCODE_VERSION_LATEST, NULL,
		    inq, inq_len, NULL, 0, inq83, inq83_len, &devid) ==
		    DDI_SUCCESS) {

			/* extract GUID from DEVID */
			guid = ddi_devid_to_guid(devid);

			/* devid no longer needed */
			ddi_devid_free(devid);
		}
	}
	inq83_ready = B_TRUE;

guid_ready:

	if (ilp != NULL) {
		if ((guid == NULL) && (ilp->lun_guid == NULL)) {
			nochange = B_TRUE;
		}

		if ((guid != NULL) && (ilp->lun_guid != NULL) &&
		    ((strlen(guid) + 1) == ilp->lun_guid_size) &&
		    (bcmp(guid, ilp->lun_guid, ilp->lun_guid_size) == 0)) {
			nochange = B_TRUE;
		}

		if (nochange != B_TRUE) {
			goto offline_old;
		}

		if (ilp->lun_state & (ISCSI_LUN_STATE_OFFLINE |
		    ISCSI_LUN_STATE_INVALID)) {
			if (isp->sess_state_event_count == event_count) {
				(void) iscsi_lun_online(ihp, ilp);
			}
		}
	} else {
		if (isp->sess_state_event_count == event_count) {
			(void) iscsi_lun_create(isp, lun_num, lun_addr_type,
			    (struct scsi_inquiry *)inq, guid);
		}
	}

inq_done:
	if (guid != NULL) {
		/* guid is no longer needed */
		ddi_devid_free_guid(guid);
	}

	/* free up memory now that we are done */
	kmem_free(inq, ISCSI_MAX_INQUIRY_BUF_SIZE);
	kmem_free(inq83, ISCSI_MAX_INQUIRY_BUF_SIZE);
}

static iscsi_status_t
retrieve_lundata(uint32_t lun_count, unsigned char *buf, iscsi_sess_t *isp,
    uint16_t *lun_num, uint8_t *lun_addr_type)
{
	uint32_t		lun_idx		= 0;

	ASSERT(lun_num != NULL);
	ASSERT(lun_addr_type != NULL);

	lun_idx = (lun_count + 1) * SCSI_REPORTLUNS_ADDRESS_SIZE;
	/* determine report luns addressing type */
	switch (buf[lun_idx] & SCSI_REPORTLUNS_ADDRESS_MASK) {
		/*
		 * Vendors in the field have been found to be concatenating
		 * bus/target/lun to equal the complete lun value instead
		 * of switching to flat space addressing
		 */
		/* 00b - peripheral device addressing method */
		case SCSI_REPORTLUNS_ADDRESS_PERIPHERAL:
			/* FALLTHRU */
		/* 10b - logical unit addressing method */
		case SCSI_REPORTLUNS_ADDRESS_LOGICAL_UNIT:
			/* FALLTHRU */
		/* 01b - flat space addressing method */
		case SCSI_REPORTLUNS_ADDRESS_FLAT_SPACE:
			/* byte0 bit0-5=msb lun byte1 bit0-7=lsb lun */
			*lun_addr_type = (buf[lun_idx] &
			    SCSI_REPORTLUNS_ADDRESS_MASK) >> 6;
			*lun_num = (buf[lun_idx] & 0x3F) << 8;
			*lun_num |= buf[lun_idx + 1];
			return (ISCSI_STATUS_SUCCESS);
		default: /* protocol error */
			cmn_err(CE_NOTE, "iscsi session(%u) unable "
			    "to enumerate logical units - report "
			    "luns returned an unsupported format",
			    isp->sess_oid);
			break;
	}
	return (ISCSI_STATUS_INTERNAL_ERROR);
}

/*
 * iscsi_sess_flush - flushes remaining pending io on the session
 */
static void
iscsi_sess_flush(iscsi_sess_t *isp)
{
	iscsi_cmd_t	*icmdp;

	ASSERT(isp != NULL);
	ASSERT(isp->sess_state != ISCSI_SESS_STATE_LOGGED_IN);

	/*
	 * Flush out any remaining commands in the pending
	 * queue.
	 */
	mutex_enter(&isp->sess_queue_pending.mutex);
	icmdp = isp->sess_queue_pending.head;
	while (icmdp != NULL) {
		if (isp->sess_state == ISCSI_SESS_STATE_FAILED) {
			mutex_enter(&icmdp->cmd_mutex);
			if (icmdp->cmd_type == ISCSI_CMD_TYPE_SCSI) {
				icmdp->cmd_un.scsi.pkt_stat |= STAT_ABORTED;
			}
			mutex_exit(&icmdp->cmd_mutex);
		}

		iscsi_cmd_state_machine(icmdp,
		    ISCSI_CMD_EVENT_E7, isp);
		icmdp = isp->sess_queue_pending.head;
	}
	mutex_exit(&isp->sess_queue_pending.mutex);
}

/*
 * iscsi_sess_offline_luns - offline all this sessions luns
 */
static void
iscsi_sess_offline_luns(iscsi_sess_t *isp)
{
	iscsi_lun_t	*ilp;
	iscsi_hba_t	*ihp;

	ASSERT(isp != NULL);
	ASSERT(isp->sess_state != ISCSI_SESS_STATE_LOGGED_IN);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);

	rw_enter(&isp->sess_lun_list_rwlock, RW_READER);
	ilp = isp->sess_lun_list;
	while (ilp != NULL) {
		(void) iscsi_lun_offline(ihp, ilp, B_FALSE);
		ilp = ilp->lun_next;
	}
	rw_exit(&isp->sess_lun_list_rwlock);
}

/*
 * iscsi_sess_get_by_target - return the session structure for based on a
 * passed in target oid and hba instance.  NOTE:  There may be
 * multiple sessions associated with any given target.  In this case,
 * we will return the first matching session.  This function
 * is intended to be used in retrieving target info that is constant
 * across sessions (target name, alias, etc.).
 */
int
iscsi_sess_get_by_target(uint32_t target_oid, iscsi_hba_t *ihp,
    iscsi_sess_t **ispp)
{
	int rval = 0;
	iscsi_sess_t *isp = NULL;

	ASSERT(ihp != NULL);
	ASSERT(ispp != NULL);

	/* See if we already created this session */
	for (isp = ihp->hba_sess_list; isp; isp = isp->sess_next) {
		/*
		 * Look for a session associated to the given target.
		 * Return the first one found.
		 */
		if (isp->sess_target_oid == target_oid) {
			/* Found matching session */
			break;
		}
	}

	/* If not null this session is already available */
	if (isp != NULL) {
		/* Existing session, return it */
		*ispp = isp;
	} else {
		rval = EFAULT;
	}
	return (rval);
}

static void
iscsi_sess_update_busy_luns(iscsi_sess_t *isp, boolean_t clear)
{
	iscsi_lun_t	*ilp;
	iscsi_hba_t	*ihp;

	ASSERT(isp != NULL);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);

	rw_enter(&isp->sess_lun_list_rwlock, RW_WRITER);
	ilp = isp->sess_lun_list;
	while (ilp != NULL) {
		if (clear == B_TRUE) {
			ilp->lun_state &= ~ISCSI_LUN_STATE_BUSY;
		} else {
			ilp->lun_state |= ISCSI_LUN_STATE_BUSY;
		}
		ilp = ilp->lun_next;
	}
	rw_exit(&isp->sess_lun_list_rwlock);
}

/*
 * Submits the scsi enumeration request. Returns
 * ISCSI_SESS_ENUM_SUBMITTED upon success, or others if failures are met.
 * If the request is submitted and the wait is set to B_TRUE, the caller
 * must call iscsi_sess_enum_query at a later time to unblock next enum
 */
iscsi_enum_result_t
iscsi_sess_enum_request(iscsi_sess_t *isp, boolean_t wait, uint32_t event_count)
{
	iscsi_task_t		*itp;

	itp = kmem_zalloc(sizeof (iscsi_task_t), KM_SLEEP);
	itp->t_arg = isp;
	itp->t_event_count = event_count;

	mutex_enter(&isp->sess_enum_lock);
	while ((isp->sess_enum_status != ISCSI_SESS_ENUM_FREE) &&
	    (isp->sess_enum_status != ISCSI_SESS_ENUM_INPROG)) {
		cv_wait(&isp->sess_enum_cv, &isp->sess_enum_lock);
	}
	if (isp->sess_enum_status == ISCSI_SESS_ENUM_INPROG) {
		/* easy case */
		if (wait == B_TRUE) {
			isp->sess_enum_result_count ++;
		}
		mutex_exit(&isp->sess_enum_lock);
		kmem_free(itp, sizeof (iscsi_task_t));
		return (ISCSI_SESS_ENUM_SUBMITTED);
	}

	ASSERT(isp->sess_enum_status == ISCSI_SESS_ENUM_FREE);
	ASSERT(isp->sess_enum_result_count == 0);

	isp->sess_enum_status = ISCSI_SESS_ENUM_INPROG;
	if (ddi_taskq_dispatch(isp->sess_enum_taskq,
	    iscsi_sess_enumeration, itp, DDI_SLEEP) != DDI_SUCCESS) {
		isp->sess_enum_status = ISCSI_SESS_ENUM_FREE;
		mutex_exit(&isp->sess_enum_lock);
		kmem_free(itp, sizeof (iscsi_task_t));
		return (ISCSI_SESS_ENUM_SUBFAIL);
	}
	if (wait == B_TRUE) {
		isp->sess_enum_result_count ++;
	}
	mutex_exit(&isp->sess_enum_lock);
	return (ISCSI_SESS_ENUM_SUBMITTED);
}

/*
 * Wait and query the result of the enumeration.
 * The last caller is responsible for kicking off the DONE status
 */
iscsi_enum_result_t
iscsi_sess_enum_query(iscsi_sess_t *isp)
{
	iscsi_enum_result_t	ret = ISCSI_SESS_ENUM_IOFAIL;

	mutex_enter(&isp->sess_enum_lock);
	while (isp->sess_enum_status != ISCSI_SESS_ENUM_DONE) {
		cv_wait(&isp->sess_enum_cv, &isp->sess_enum_lock);
	}
	ret = isp->sess_enum_result;
	isp->sess_enum_result_count --;
	if (isp->sess_enum_result_count == 0) {
		isp->sess_enum_status = ISCSI_SESS_ENUM_FREE;
		cv_broadcast(&isp->sess_enum_cv);
	}
	mutex_exit(&isp->sess_enum_lock);

	return (ret);
}

static void
iscsi_sess_enum_warn(iscsi_sess_t *isp, iscsi_enum_result_t r)
{
	cmn_err(CE_WARN, "iscsi session (%u) enumeration fails - %s",
	    isp->sess_oid, iscsi_sess_enum_warn_msgs[r]);
}

void
iscsi_sess_enter_state_zone(iscsi_sess_t *isp)
{
	mutex_enter(&isp->sess_state_wmutex);
	while (isp->sess_state_hasw == B_TRUE) {
		cv_wait(&isp->sess_state_wcv, &isp->sess_state_wmutex);
	}
	isp->sess_state_hasw = B_TRUE;
	mutex_exit(&isp->sess_state_wmutex);

	rw_enter(&isp->sess_state_rwlock, RW_WRITER);
}

void
iscsi_sess_exit_state_zone(iscsi_sess_t *isp)
{
	rw_exit(&isp->sess_state_rwlock);

	mutex_enter(&isp->sess_state_wmutex);
	isp->sess_state_hasw = B_FALSE;
	cv_signal(&isp->sess_state_wcv);
	mutex_exit(&isp->sess_state_wmutex);
}
