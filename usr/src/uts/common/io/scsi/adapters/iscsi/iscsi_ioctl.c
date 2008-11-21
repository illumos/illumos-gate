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
 *
 * iSCSI Software Initiator
 */

/*
 * Framework interface routines for iSCSI
 */
#include "iscsi.h"		/* main header */
#include <sys/scsi/adapters/iscsi_if.h>		/* ioctl interfaces */
/* protocol structs and defines */
#include <sys/scsi/adapters/iscsi_protocol.h>
#include "persistent.h"
#include <sys/scsi/adapters/iscsi_door.h>
#include "iscsi_targetparam.h"
#include <sys/strsubr.h>
#include <sys/socketvar.h>
#include <sys/bootprops.h>

extern ib_boot_prop_t	*iscsiboot_prop;

static iscsi_status_t iscsi_create_sendtgts_list(iscsi_conn_t *icp,
    char *data, int data_len, iscsi_sendtgts_list_t *stl);

/*
 * iscsi_ioctl_copyin -
 */
void *
iscsi_ioctl_copyin(caddr_t arg, int mode, size_t size)
{
	void	*data = NULL;

	ASSERT(arg != NULL);
	ASSERT(size != 0);

	data = kmem_alloc(size, KM_SLEEP);

	if (ddi_copyin(arg, data, size, mode) != 0) {
		kmem_free(data, size);
		data = NULL;
	}
	return (data);
}

/*
 * iscsi_ioctl_copyout -
 */
int
iscsi_ioctl_copyout(void *data, size_t size, caddr_t arg, int mode)
{
	int	rtn;

	rtn = EFAULT;
	if (ddi_copyout(data, arg, size, mode) == 0) {
		rtn = 0;
	}
	kmem_free(data, size);
	return (rtn);
}

/*
 * iscsi_conn_list_get_copyin -
 */
iscsi_conn_list_t *
iscsi_ioctl_conn_oid_list_get_copyin(caddr_t arg, int mode)
{
	iscsi_conn_list_t	*cl_tmp;
	iscsi_conn_list_t	*cl = NULL;
	size_t			alloc_len;

	ASSERT(arg != NULL);

	cl_tmp = (iscsi_conn_list_t *)kmem_zalloc(sizeof (*cl_tmp), KM_SLEEP);

	if (ddi_copyin(arg, cl_tmp, sizeof (*cl_tmp), mode) == 0) {

		if (cl_tmp->cl_vers == ISCSI_INTERFACE_VERSION) {
			alloc_len = sizeof (*cl);
			if (cl_tmp->cl_in_cnt != 0) {
				alloc_len += ((cl_tmp->cl_in_cnt - 1) *
				    sizeof (iscsi_if_conn_t));
			}

			cl = (iscsi_conn_list_t *)kmem_zalloc(alloc_len,
			    KM_SLEEP);
			bcopy(cl_tmp, cl, sizeof (*cl_tmp));
		}
	}
	kmem_free(cl_tmp, sizeof (*cl_tmp));
	return (cl);
}

/*
 * iscsi_conn_list_get_copyout -
 */
int
iscsi_ioctl_conn_oid_list_get_copyout(iscsi_conn_list_t *cl, caddr_t arg,
    int mode)
{
	size_t			alloc_len;
	int			rtn;

	ASSERT(cl != NULL);
	ASSERT(arg != NULL);

	rtn = EFAULT;
	alloc_len = sizeof (*cl);
	if (cl->cl_in_cnt != 0) {
		alloc_len += ((cl->cl_in_cnt - 1) * sizeof (iscsi_if_conn_t));
	}

	if (ddi_copyout(cl, arg, alloc_len, mode) == 0) {
		rtn = 0;
	}
	kmem_free(cl, alloc_len);
	return (rtn);
}

/*
 * iscsi_conn_oid_list_get -
 */
boolean_t
iscsi_ioctl_conn_oid_list_get(iscsi_hba_t *ihp, iscsi_conn_list_t *cl)
{
	iscsi_sess_t		*isp;
	iscsi_conn_t		*icp;
	iscsi_if_conn_t		*cnx;
	uint32_t		target_oid;

	/* Let's check the version. */
	if (cl->cl_vers != ISCSI_INTERFACE_VERSION) {
		return (B_FALSE);
	}

	/* We preinitialize the output connection counter. */
	cl->cl_out_cnt = 0;

	/* The list of sessions is walked holding the HBA mutex. */
	rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
	isp = ihp->hba_sess_list;

	/*
	 * Check to see if oid references a target-param oid.  If so,
	 * find the associated  session oid before getting lu list.
	 */
	if (iscsi_targetparam_get_name(cl->cl_sess_oid) != NULL) {
		for (isp = ihp->hba_sess_list; isp; isp = isp->sess_next) {
			if (isp->sess_target_oid == cl->cl_sess_oid) {
				target_oid  = isp->sess_oid;
				break;
			}
		}
	} else {
		target_oid = cl->cl_sess_oid;
	}

	while (isp != NULL) {
		ASSERT(isp->sess_sig == ISCSI_SIG_SESS);

		/* return connections for NORMAL sessions only */
		if ((isp->sess_type == ISCSI_SESS_TYPE_NORMAL) &&
		    ((cl->cl_all_sess == B_TRUE) ||
		    (target_oid == isp->sess_oid))) {
			/*
			 * The list of connections is walked holding
			 * the session mutex.
			 */
			rw_enter(&isp->sess_conn_list_rwlock, RW_READER);
			icp = isp->sess_conn_list;

			while (icp != NULL) {
				ASSERT(icp->conn_sig == ISCSI_SIG_CONN);

				if (icp->conn_state ==
				    ISCSI_CONN_STATE_LOGGED_IN) {

					if (cl->cl_out_cnt < cl->cl_in_cnt) {
						/* There's still room. */
						cnx =
						    &cl->cl_list[
						    cl->cl_out_cnt];

						bzero(cnx, sizeof (*cnx));

						cnx->c_cid = icp->conn_cid;
						cnx->c_oid = icp->conn_oid;
						cnx->c_sess_oid = isp->sess_oid;
					}
					++cl->cl_out_cnt;
				}
				icp = icp->conn_next;
			}
			rw_exit(&isp->sess_conn_list_rwlock);

			if (cl->cl_all_sess == B_FALSE) {
				/*
				 * We got here because it was the only session
				 * we were looking for.  We can exit now.
				 */
				break;
			}
		}
		isp = isp->sess_next;
	}
	rw_exit(&ihp->hba_sess_list_rwlock);
	return (B_TRUE);
}

/*
 * iscsi_ioctl_conn_props_get -
 */
boolean_t
iscsi_ioctl_conn_props_get(iscsi_hba_t *ihp, iscsi_conn_props_t *cp)
{
	iscsi_sess_t		*isp;
	iscsi_conn_t		*icp;
	boolean_t		rtn;

	/* Let's check the version. */
	if (cp->cp_vers != ISCSI_INTERFACE_VERSION) {
		return (B_FALSE);
	}

	/* Let's find the session. */
	rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
	if (iscsi_sess_get(cp->cp_sess_oid, ihp, &isp) != 0) {
		rw_exit(&ihp->hba_sess_list_rwlock);
		return (B_FALSE);
	}

	ASSERT(isp->sess_sig == ISCSI_SIG_SESS);

	rtn = B_FALSE;

	rw_enter(&isp->sess_conn_list_rwlock, RW_READER);
	icp = isp->sess_conn_list;
	cp->cp_params_valid = B_FALSE;

	while (icp != NULL) {

		ASSERT(icp->conn_sig == ISCSI_SIG_CONN);

		if (icp->conn_oid == cp->cp_oid) {

			if (icp->conn_socket->so_laddr.soa_len <=
			    sizeof (cp->cp_local)) {
				bcopy(icp->conn_socket->so_laddr.soa_sa,
				    &cp->cp_local,
				    icp->conn_socket->so_laddr.soa_len);
			}
			if (icp->conn_socket->so_faddr.soa_len <=
			    sizeof (cp->cp_peer)) {
				bcopy(icp->conn_socket->so_faddr.soa_sa,
				    &cp->cp_peer,
				    icp->conn_socket->so_faddr.soa_len);
			}

			if (icp->conn_state == ISCSI_CONN_STATE_LOGGED_IN) {
				cp->cp_params_valid = B_TRUE;
				bcopy(&icp->conn_params, &cp->cp_params,
				    sizeof (icp->conn_params));
			}

			rtn = B_TRUE;
			break;
		}
		icp = icp->conn_next;
	}
	rw_exit(&isp->sess_conn_list_rwlock);
	rw_exit(&ihp->hba_sess_list_rwlock);
	return (rtn);
}


/*
 * iscsi_ioctl_sendtgts_get - 0 on success; errno on failure
 *
 */
int
iscsi_ioctl_sendtgts_get(iscsi_hba_t *ihp, iscsi_sendtgts_list_t *stl)
{
#define	ISCSI_SENDTGTS_REQ_STR		"SendTargets=All"

	int			rtn = EFAULT;
	iscsi_status_t		status;
	iscsi_sess_t		*isp;
	iscsi_conn_t		*icp;
	uint32_t		oid;
	char			*data;
	uint32_t		data_len;
	uint32_t		rx_data_len;
	iscsi_sockaddr_t	addr_snd;

	ASSERT(ihp != NULL);
	ASSERT(stl != NULL);

	iscsid_addr_to_sockaddr(stl->stl_entry.e_insize,
	    &stl->stl_entry.e_u, stl->stl_entry.e_port,
	    &addr_snd.sin);

	/* create discovery session */
	rw_enter(&ihp->hba_sess_list_rwlock, RW_WRITER);
	isp = iscsi_sess_create(ihp, iSCSIDiscoveryMethodSendTargets,
	    NULL, SENDTARGETS_DISCOVERY, ISCSI_DEFAULT_TPGT,
	    ISCSI_SUN_ISID_5, ISCSI_SESS_TYPE_DISCOVERY, &oid);
	if (isp == NULL) {
		rw_exit(&ihp->hba_sess_list_rwlock);
		return (1);
	}

	/* create connection */
	rw_enter(&isp->sess_conn_list_rwlock, RW_WRITER);
	status = iscsi_conn_create(&addr_snd.sin, isp, &icp);
	rw_exit(&isp->sess_conn_list_rwlock);

	if (!ISCSI_SUCCESS(status)) {
		(void) iscsi_sess_destroy(isp);
		rw_exit(&ihp->hba_sess_list_rwlock);
		return (1);
	}
	rw_exit(&ihp->hba_sess_list_rwlock);

	/* start login */
	mutex_enter(&icp->conn_state_mutex);
	(void) iscsi_conn_state_machine(icp, ISCSI_CONN_EVENT_T1);
	mutex_exit(&icp->conn_state_mutex);

	if (icp->conn_state == ISCSI_CONN_STATE_LOGGED_IN) {
		data_len = icp->conn_params.max_xmit_data_seg_len;
retry_sendtgts:
		/* alloc/init buffer for SendTargets req/resp */
		data = kmem_zalloc(data_len, KM_SLEEP);
		bcopy(ISCSI_SENDTGTS_REQ_STR, data,
		    sizeof (ISCSI_SENDTGTS_REQ_STR));

		/* execute SendTargets operation */
		status = iscsi_handle_text(icp, data, data_len,
		    sizeof (ISCSI_SENDTGTS_REQ_STR), &rx_data_len);

		/* check if allocated buffer is too small for response */
		if (status == ISCSI_STATUS_DATA_OVERFLOW) {
			kmem_free(data, data_len);
			data_len = rx_data_len;
			goto retry_sendtgts;
		}

		if (ISCSI_SUCCESS(status)) {
			status = iscsi_create_sendtgts_list(icp, data,
			    rx_data_len, stl);
			if (ISCSI_SUCCESS(status)) {
				rtn = 0;
			}
		} else {
			rtn = EFAULT;
		}

		kmem_free(data, data_len);
	} else {
		rtn = EFAULT;
	}

	/*
	 * check if session is still alive.  It may have been destroyed
	 * by a driver unload
	 */
	rw_enter(&ihp->hba_sess_list_rwlock, RW_WRITER);
	if (iscsi_sess_get(oid, ihp, &isp) == 0) {
		(void) iscsi_sess_destroy(isp);
	}
	rw_exit(&ihp->hba_sess_list_rwlock);

	return (rtn);
}


/*
 * iscsi_create_sendtgts_list -  Based upon the given data, build a
 * linked list of SendTarget information.  The data passed into this
 * function  is expected to be the data portion(s) of SendTarget text
 * response.
 */
static iscsi_status_t
iscsi_create_sendtgts_list(iscsi_conn_t *icp, char *data, int data_len,
    iscsi_sendtgts_list_t *stl)
{
	char			*line = NULL;
	boolean_t		targetname_added = B_FALSE;
	iscsi_sendtgts_entry_t	*curr_ste = NULL,
	    *prev_ste = NULL;
	struct hostent		*hptr;
	int			error_num;

	/* initialize number of targets found */
	stl->stl_out_cnt = 0;

	if (data_len == 0)
		return (ISCSI_STATUS_SUCCESS);

	while ((line = iscsi_get_next_text(data, data_len, line)) != NULL) {
		if (strncmp(TARGETNAME, line, strlen(TARGETNAME)) == 0) {
			/* check if this is first targetname */
			if (prev_ste != NULL) {
				stl->stl_out_cnt++;
			}
			if (stl->stl_out_cnt >= stl->stl_in_cnt) {
				/*
				 * continue processing the data so that
				 * the total number of targets are known
				 * and the caller can retry with the correct
				 * number of entries in the list
				 */
				continue;
			}
			curr_ste = &(stl->stl_list[stl->stl_out_cnt]);

			/*
			 * This entry will use the IP address and port
			 * that was passed into this routine. If the next
			 * line that we receive is a TargetAddress we will
			 * know to modify this entry with the new IP address,
			 * port and portal group tag. If this state flag
			 * is not set we'll just create a new entry using
			 * only the previous entries targetname.
			 */
			(void) strncpy((char *)curr_ste->ste_name,
			    line + strlen(TARGETNAME),
			    sizeof (curr_ste->ste_name));

			if (icp->conn_base_addr.sin.sa_family == AF_INET) {

				struct sockaddr_in *addr_in =
				    &icp->conn_base_addr.sin4;
				curr_ste->ste_ipaddr.a_addr.i_insize =
				    sizeof (struct in_addr);
				bcopy(&addr_in->sin_addr.s_addr,
				    &curr_ste->ste_ipaddr.a_addr.i_addr,
				    sizeof (struct in_addr));
				curr_ste->ste_ipaddr.a_port =
				    htons(addr_in->sin_port);

			} else {

				struct sockaddr_in6 *addr_in6 =
				    &icp->conn_base_addr.sin6;
				curr_ste->ste_ipaddr.a_addr.i_insize =
				    sizeof (struct in6_addr);
				bcopy(&addr_in6->sin6_addr.s6_addr,
				    &curr_ste->ste_ipaddr.a_addr.i_addr,
				    sizeof (struct in6_addr));
				curr_ste->ste_ipaddr.a_port =
				    htons(addr_in6->sin6_port);
			}
			curr_ste->ste_tpgt = -1;

			targetname_added = B_TRUE;

		} else if (strncmp(TARGETADDRESS, line,
		    strlen(TARGETADDRESS)) == 0) {

			char *in_str,
			    *tmp_buf,
			    *addr_str,
			    *port_str,
			    *tpgt_str;
			int type,
			    tmp_buf_len;
			long result;

			/*
			 * If TARGETADDRESS is first line a SendTarget response
			 * (i.e. no TARGETNAME lines preceding), treat as
			 * an error.  To check this an assumption is made that
			 * at least one sendtarget_entry_t should exist prior
			 * to entering this code.
			 */
			if (prev_ste == NULL) {
				cmn_err(CE_NOTE, "SendTargets protocol error: "
				    "TARGETADDRESS first");
				return (ISCSI_STATUS_PROTOCOL_ERROR);
			}

			/*
			 * If we can't find an '=' then the sendtargets
			 * response if invalid per spec.  Return empty list.
			 */
			in_str = strchr(line, '=');
			if (in_str == NULL) {
				return (ISCSI_STATUS_PROTOCOL_ERROR);
			}

			/* move past the '=' */
			in_str++;

			/* Copy  addr, port, and tpgt into temporary buffer */
			tmp_buf_len = strlen(in_str) + 1;
			tmp_buf = kmem_zalloc(tmp_buf_len, KM_SLEEP);
			(void) strncpy(tmp_buf, in_str, tmp_buf_len);

			/*
			 * Parse the addr, port, and tpgt from
			 * sendtarget response
			 */
			if (parse_addr_port_tpgt(tmp_buf, &addr_str, &type,
			    &port_str, &tpgt_str) == B_FALSE) {
				/* Unable to extract addr */
				kmem_free(tmp_buf, tmp_buf_len);
				return (ISCSI_STATUS_PROTOCOL_ERROR);
			}

			/* Now convert string addr to binary */
			hptr = kgetipnodebyname(addr_str, type,
			    AI_ALL, &error_num);
			if (!hptr) {
				/* Unable to get valid address */
				kmem_free(tmp_buf, tmp_buf_len);
				return (ISCSI_STATUS_PROTOCOL_ERROR);
			}

			/* Check if space for response */
			if (targetname_added == B_FALSE) {
				stl->stl_out_cnt++;
				if (stl->stl_out_cnt >= stl->stl_in_cnt) {
					/*
					 * continue processing the data so that
					 * the total number of targets are
					 * known and the caller can retry with
					 * the correct number of entries in
					 * the list
					 */
					kfreehostent(hptr);
					kmem_free(tmp_buf, tmp_buf_len);
					continue;
				}
				curr_ste = &(stl->stl_list[stl->stl_out_cnt]);
				(void) strcpy((char *)curr_ste->ste_name,
				    (char *)prev_ste->ste_name);
			}

			curr_ste->ste_ipaddr.a_addr.i_insize = hptr->h_length;
			bcopy(*hptr->h_addr_list,
			    &(curr_ste->ste_ipaddr.a_addr.i_addr),
			    curr_ste->ste_ipaddr.a_addr.i_insize);
			kfreehostent(hptr);

			if (port_str != NULL) {
				(void) ddi_strtol(port_str, NULL, 0, &result);
				curr_ste->ste_ipaddr.a_port = (short)result;
			} else {
				curr_ste->ste_ipaddr.a_port = ISCSI_LISTEN_PORT;
			}

			if (tpgt_str != NULL) {
				(void) ddi_strtol(tpgt_str, NULL, 0, &result);
				curr_ste->ste_tpgt = (short)result;
			} else {
				cmn_err(CE_NOTE, "SendTargets protocol error: "
				    "TPGT not specified");
				kmem_free(tmp_buf, tmp_buf_len);
				return (ISCSI_STATUS_PROTOCOL_ERROR);
			}

			kmem_free(tmp_buf, tmp_buf_len);

			targetname_added = B_FALSE;

		} else if (strlen(line) != 0) {
			/*
			 * Any other string besides an empty string
			 * is a protocol error
			 */
			cmn_err(CE_NOTE, "SendTargets protocol error: "
			    "unexpected response");
			return (ISCSI_STATUS_PROTOCOL_ERROR);
		}

		prev_ste = curr_ste;
	}

	/*
	 * If target found increment out count one more time because
	 * this is the total number of entries in the list not an index
	 * like it was used above
	 */
	if (prev_ste != NULL) {
		stl->stl_out_cnt++;
	}

	return (ISCSI_STATUS_SUCCESS);
}

/*
 * iscsi_set_param - This function is a helper to ISCSI_SET_PARAM
 * IOCTL
 */
int
iscsi_set_param(iscsi_login_params_t *params, iscsi_param_set_t *ipsp)
{
	int rtn = 0;
	iscsi_param_get_t *ipgp;

	/*
	 * Use get param to get the min, max and increment values for the
	 * given parameter so validation can be done on the new value.
	 */
	ipgp = (iscsi_param_get_t *)kmem_alloc(sizeof (*ipgp), KM_SLEEP);
	ipgp->g_param = ipsp->s_param;
	rtn = iscsi_get_param(params, B_TRUE, ipgp);
	if (rtn != 0) {
		kmem_free(ipgp, sizeof (*ipgp));
		return (rtn);
	}

	if (ipsp->s_param == ISCSI_LOGIN_PARAM_HEADER_DIGEST ||
	    ipsp->s_param == ISCSI_LOGIN_PARAM_DATA_DIGEST ||
	    ipsp->s_param == ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_RETAIN ||
	    ipsp->s_param == ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_WAIT ||
	    ipsp->s_param == ISCSI_LOGIN_PARAM_MAX_RECV_DATA_SEGMENT_LENGTH ||
	    ipsp->s_param == ISCSI_LOGIN_PARAM_FIRST_BURST_LENGTH ||
	    ipsp->s_param == ISCSI_LOGIN_PARAM_MAX_BURST_LENGTH) {

		if (ipsp->s_value.v_integer < ipgp->g_value.v_integer.i_min ||
		    ipsp->s_value.v_integer > ipgp->g_value.v_integer.i_max ||
		    (ipsp->s_value.v_integer %
		    ipgp->g_value.v_integer.i_incr) != 0) {
			rtn = EINVAL;
			kmem_free(ipgp, sizeof (*ipgp));
			return (rtn);
		}

	}
	kmem_free(ipgp, sizeof (*ipgp));


	switch (ipsp->s_param) {

	/*
	 * Boolean parameters
	 */
	case ISCSI_LOGIN_PARAM_DATA_SEQUENCE_IN_ORDER:
		params->data_sequence_in_order = ipsp->s_value.v_bool;
		break;
	case ISCSI_LOGIN_PARAM_IMMEDIATE_DATA:
		params->immediate_data = ipsp->s_value.v_bool;
		break;
	case ISCSI_LOGIN_PARAM_INITIAL_R2T:
		params->initial_r2t = ipsp->s_value.v_bool;
		break;
	case ISCSI_LOGIN_PARAM_DATA_PDU_IN_ORDER:
		params->data_pdu_in_order = ipsp->s_value.v_bool;
		break;

	/*
	 * Integer parameters
	 */
	case ISCSI_LOGIN_PARAM_HEADER_DIGEST:
		params->header_digest = ipsp->s_value.v_integer;
		break;
	case ISCSI_LOGIN_PARAM_DATA_DIGEST:
		params->data_digest = ipsp->s_value.v_integer;
		break;
	case ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_RETAIN:
		params->default_time_to_retain = ipsp->s_value.v_integer;
		break;
	case ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_WAIT:
		params->default_time_to_wait = ipsp->s_value.v_integer;
		break;
	case ISCSI_LOGIN_PARAM_MAX_RECV_DATA_SEGMENT_LENGTH:
		params->max_recv_data_seg_len = ipsp->s_value.v_integer;
		break;
	case ISCSI_LOGIN_PARAM_FIRST_BURST_LENGTH:
		if (ipsp->s_value.v_integer <= params->max_burst_length) {
			params->first_burst_length = ipsp->s_value.v_integer;
		} else {
			rtn = EINVAL;
		}
		break;
	case ISCSI_LOGIN_PARAM_MAX_BURST_LENGTH:
		if (ipsp->s_value.v_integer >= params->first_burst_length) {
			params->max_burst_length = ipsp->s_value.v_integer;
		} else {
			rtn = EINVAL;
		}
		break;

	/*
	 * Integer parameters which currently are unsettable
	 */
	case ISCSI_LOGIN_PARAM_MAX_CONNECTIONS:
	case ISCSI_LOGIN_PARAM_OUTSTANDING_R2T:
	case ISCSI_LOGIN_PARAM_ERROR_RECOVERY_LEVEL:
		rtn = ENOTSUP;
		break;

	default:
		rtn = EINVAL;
		break;
	}
	return (rtn);
}

int
iscsi_set_params(iscsi_param_set_t *ils, iscsi_hba_t *ihp, boolean_t persist)
{
	iscsi_login_params_t	*params	= NULL;
	uchar_t			*name	= NULL;
	iscsi_sess_t		*isp	= NULL;
	iscsi_param_get_t	*ilg;
	int			rtn	= 0;

	/* handle special case for Initiator name */
	if (ils->s_param == ISCSI_LOGIN_PARAM_INITIATOR_NAME) {
		(void) strlcpy((char *)ihp->hba_name,
		    (char *)ils->s_value.v_name, ISCSI_MAX_NAME_LEN);
		if (persist) {
			char			*name;
			boolean_t		rval;

			/* save off old Initiator name */
			name = kmem_alloc(ISCSI_MAX_NAME_LEN, KM_SLEEP);
			rval = persistent_initiator_name_get(name,
			    ISCSI_MAX_NAME_LEN);

			(void) persistent_initiator_name_set(
			    (char *)ihp->hba_name);
			if (rval == B_TRUE) {
				/*
				 * check to see if we have login param,
				 * chap param, or authentication params
				 * loaded in persistent that we have to change
				 * the name of
				 */
				persistent_param_t	*pp;
				iscsi_chap_props_t	*chap;
				iscsi_auth_props_t	*auth;

				/* checking login params */
				pp = kmem_zalloc(sizeof (persistent_param_t),
				    KM_SLEEP);
				if (persistent_param_get(name, pp)) {
					rval = persistent_param_clear(name);
					if (rval == B_TRUE) {
						rval = persistent_param_set(
						    (char *)ihp->hba_name, pp);
					}
					if (rval == B_FALSE) {
						rtn = EFAULT;
					}
				}
				kmem_free(pp, sizeof (persistent_param_t));

				/* check chap params */
				chap = kmem_zalloc(sizeof (iscsi_chap_props_t),
				    KM_SLEEP);
				if (persistent_chap_get(name, chap)) {
					rval = persistent_chap_clear(name);
					if (rval == B_TRUE) {
					/*
					 * Update CHAP user name only if the
					 * original username was set to the
					 * initiator node name.  Otherwise
					 * leave it the way it is.
					 */
						int userSize;
						userSize =
						    sizeof (chap->c_user);
						if (strncmp((char *)
						    chap->c_user, name,
						    sizeof (chap->c_user))
						    == 0) {
							bzero(chap->c_user,
							    userSize);
							bcopy((char *)
							    ihp->hba_name,
							    chap->c_user,
							    strlen((char *)
							    ihp->hba_name));
							chap->c_user_len =
							    strlen((char *)
							    ihp->hba_name);

					}
					rval = persistent_chap_set(
					    (char *)ihp->hba_name, chap);
					}
					if (rval == B_FALSE) {
						rtn = EFAULT;
					}
				}
				kmem_free(chap, sizeof (iscsi_chap_props_t));

				/* check authentication params */
				auth = kmem_zalloc(sizeof (iscsi_auth_props_t),
				    KM_SLEEP);
				if (persistent_auth_get(name, auth)) {
					rval = persistent_auth_clear(name);
					if (rval == B_TRUE) {
						rval = persistent_auth_set(
						    (char *)ihp->hba_name,
						    auth);
					}
					if (rval == B_FALSE) {
						rtn = EFAULT;
					}
				}
				kmem_free(auth, sizeof (iscsi_auth_props_t));
			}
			kmem_free(name, ISCSI_MAX_NAME_LEN);
		}
	} else if (ils->s_param == ISCSI_LOGIN_PARAM_INITIATOR_ALIAS) {
		(void) strlcpy((char *)ihp->hba_alias,
		    (char *)ils->s_value.v_name, ISCSI_MAX_NAME_LEN);
		ihp->hba_alias_length =
		    strlen((char *)ils->s_value.v_name);
		if (persist) {
			(void) persistent_alias_name_set(
			    (char *)ihp->hba_alias);
		}
	} else {
		/* switch login based if looking for initiator params */
		if (ils->s_oid == ihp->hba_oid) {
			/* initiator */
			params = &ihp->hba_params;
			name = ihp->hba_name;
			rtn = iscsi_set_param(params, ils);
		} else {
			/* session */
			name = iscsi_targetparam_get_name(ils->s_oid);

			if (persist) {
				boolean_t		rval;
				persistent_param_t	*pp;

				pp = (persistent_param_t *)
				    kmem_zalloc(sizeof (*pp), KM_SLEEP);
				if (!persistent_param_get((char *)name, pp)) {
					iscsi_set_default_login_params(
					    &pp->p_params);
				}

				pp->p_bitmap |= (1 << ils->s_param);
				rtn = iscsi_set_param(&pp->p_params, ils);
				if (rtn == 0) {
					rval = persistent_param_set(
					    (char *)name, pp);
					if (rval == B_FALSE) {
						rtn = EFAULT;
					}
				}
				kmem_free(pp, sizeof (*pp));
			}

			/*
			 * Here may have multiple sessions with different
			 * tpgt values.  So it is needed to loop through
			 * the sessions and update all sessions.
			 */
			if (rtn == 0) {
				rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
				for (isp = ihp->hba_sess_list; isp;
				    isp = isp->sess_next) {
					if (iscsiboot_prop &&
					    isp->sess_boot &&
					    iscsi_chk_bootlun_mpxio(ihp)) {
						/*
						 * MPxIO is enabled so capable
						 * of changing. All changes
						 * will be applied later,
						 * after this function
						 */
						continue;
					}

					if (strncmp((char *)isp->sess_name,
					    (char *)name,
					    ISCSI_MAX_NAME_LEN) == 0) {
mutex_enter(&isp->sess_state_mutex);
iscsi_sess_state_machine(isp, ISCSI_SESS_EVENT_N7);
mutex_exit(&isp->sess_state_mutex);
					}
				}
				rw_exit(&ihp->hba_sess_list_rwlock);
			}

		} /* end of 'else' */

		if (params && persist && (rtn == 0)) {
			boolean_t		rval;
			persistent_param_t	*pp;

			pp = (persistent_param_t *)
			    kmem_zalloc(sizeof (*pp), KM_SLEEP);
			(void) persistent_param_get((char *)name, pp);
			pp->p_bitmap |= (1 << ils->s_param);
			bcopy(params, &pp->p_params, sizeof (*params));
			rval = persistent_param_set((char *)name, pp);
			if (rval == B_FALSE) {
				rtn = EFAULT;
			}
			kmem_free(pp, sizeof (*pp));
		}
		/*
		 * if initiator parameter set, modify all associated
		 * sessions that don't already have the parameter
		 * overriden
		 */
		if (ils->s_oid == ihp->hba_oid) {
			ilg = (iscsi_param_get_t *)
			    kmem_alloc(sizeof (*ilg), KM_SLEEP);

			rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
			for (isp = ihp->hba_sess_list; isp;
			    isp = isp->sess_next) {
				ilg->g_param = ils->s_param;
				params = &isp->sess_params;
				if (iscsi_get_persisted_param(
				    isp->sess_name, ilg, params) != 0) {
					rtn = iscsi_set_param(params, ils);
					if (rtn != 0) {
						break;
					}
					if (iscsiboot_prop &&
					    isp->sess_boot &&
					    iscsi_chk_bootlun_mpxio(ihp)) {
						/*
						 * MPxIO is enabled so capable
						 * of changing. Changes will
						 * be applied later, right
						 * after this function
						 */
						continue;
					}

					/*
					 * Notify the session that
					 * the login parameters have
					 * changed.
					 */
					mutex_enter(&isp->
					    sess_state_mutex);
					iscsi_sess_state_machine(isp,
					    ISCSI_SESS_EVENT_N7);
					mutex_exit(&isp->
					    sess_state_mutex);
				}
			}
			kmem_free(ilg, sizeof (*ilg));
			rw_exit(&ihp->hba_sess_list_rwlock);
		}
	}
	return (rtn);
}

int
iscsi_target_prop_mod(iscsi_hba_t *ihp, iscsi_property_t *ipp, int cmd)
{
	iscsi_sess_t *isp = NULL;
	iscsi_conn_t *icp;
	int rtn;
	char *name;

	/*
	 * If we're just attempting to get the target properties don't
	 * create the session if it doesn't already exist. If we setting
	 * the property then create the session if needed because we'll
	 * most likely see an ISCSI_LOGIN in a few.
	 */
	rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);

	/*
	 * If the oid does represent a session check to see
	 * if it is a target oid.  If so, return the target's
	 * associated session.
	 */
	rtn = iscsi_sess_get(ipp->p_oid, ihp, &isp);
	if (rtn != 0) {
		rtn = iscsi_sess_get_by_target(ipp->p_oid, ihp, &isp);
	}

	/*
	 * If rtn is zero then we have found an existing session.
	 * Use the session name for database lookup.  If rtn is
	 * non-zero then create a targetparam object and use
	 * its name for database lookup.
	 */
	if (rtn == 0) {
		name = (char *)isp->sess_name;
	} else {
		name = (char *)iscsi_targetparam_get_name(ipp->p_oid);
		isp = NULL;
	}

	if (name == NULL) {
		rw_exit(&ihp->hba_sess_list_rwlock);
		rtn = EFAULT;
		return (rtn);
	}

	rtn = 0;
	if (cmd == ISCSI_TARGET_PROPS_GET) {
		/*
		 * If isp is not null get the session's parameters, otherwise
		 * the get is for a target-param object so defaults need to
		 * be returned.
		 */
		if (isp != NULL) {
			int conn_count = 0;

			bcopy(isp->sess_alias, ipp->p_alias,
			    isp->sess_alias_length);
			bcopy(isp->sess_name, ipp->p_name,
			    isp->sess_name_length);
			ipp->p_alias_len = isp->sess_alias_length;
			ipp->p_name_len  = isp->sess_name_length;
			ipp->p_discovery = isp->sess_discovered_by;
			ipp->p_last_err  = isp->sess_last_err;
			ipp->p_tpgt_conf = isp->sess_tpgt_conf;
			ipp->p_tpgt_nego = isp->sess_tpgt_nego;
			bcopy(isp->sess_isid, ipp->p_isid, ISCSI_ISID_LEN);

			rw_enter(&isp->sess_conn_list_rwlock, RW_READER);
			for (icp = isp->sess_conn_list; icp;
			    icp = icp->conn_next) {
				if (icp->conn_state ==
				    ISCSI_CONN_STATE_LOGGED_IN) {
					conn_count++;
				}
			}
			rw_exit(&isp->sess_conn_list_rwlock);
			ipp->p_num_of_connections = conn_count;
			ipp->p_connected = (conn_count > 0) ? B_TRUE : B_FALSE;
		} else {
			bcopy(name, ipp->p_name, strlen(name));
			ipp->p_name_len  = strlen(name);
			bcopy("", ipp->p_alias, strlen(""));
			ipp->p_alias_len = strlen("");
			ipp->p_discovery = iSCSIDiscoveryMethodUnknown;
			ipp->p_last_err  =  NoError;
			ipp->p_tpgt_conf = ISCSI_DEFAULT_TPGT;
			ipp->p_tpgt_nego = ISCSI_DEFAULT_TPGT;
			ipp->p_num_of_connections = 0;
			ipp->p_connected = B_FALSE;
		}
	} else {
		if (isp == NULL) {
			rw_exit(&ihp->hba_sess_list_rwlock);
			rtn = EFAULT;
			return (rtn);
		}

		/* ISCSI_TARGET_PROPS_SET */
		/*
		 * only update if new, otherwise could clear out alias
		 * if just updating the discovery.
		 */
		if (ipp->p_alias_len != 0) {
			bcopy(ipp->p_alias, isp->sess_alias,
			    ipp->p_alias_len);
			isp->sess_alias_length  = ipp->p_alias_len;
		}
		isp->sess_discovered_by = ipp->p_discovery;
	}
	rw_exit(&ihp->hba_sess_list_rwlock);
	return (rtn);
}

/*
 * iscsi_ioctl_get_config_sess - gets configured session information
 *
 * This function is an ioctl helper function to get the
 * configured session information from the persistent store.
 */
int
iscsi_ioctl_get_config_sess(iscsi_hba_t *ihp, iscsi_config_sess_t *ics)
{
	uchar_t *name;

	/* Get the matching iscsi node name for the oid */
	if (ics->ics_oid == ISCSI_INITIATOR_OID) {
		/* initiator name */
		name = ihp->hba_name;
	} else {
		/* target name */
		name = iscsi_targetparam_get_name(ics->ics_oid);
		if (name == NULL) {
			/* invalid node name */
			return (EINVAL);
		}
	}

	/* get configured session information */
	if (persistent_get_config_session((char *)name, ics) == B_FALSE) {
		/*
		 * There might not be anything in the database yet.  If
		 * this is a request for the target check the initiator
		 * value.  If neither is set return the default value.
		 */
		if (ics->ics_oid != ISCSI_INITIATOR_OID) {
			if (persistent_get_config_session(
			    (char *)ihp->hba_name, ics) == B_FALSE) {
				/*
				 * No initiator value is set.
				 * Return the defaults.
				 */
				ics->ics_out = ISCSI_DEFAULT_SESS_NUM;
				ics->ics_bound = ISCSI_DEFAULT_SESS_BOUND;
			}
		} else {
			ics->ics_out = ISCSI_DEFAULT_SESS_NUM;
			ics->ics_bound = ISCSI_DEFAULT_SESS_BOUND;
		}
	}

	return (0);
}

/*
 * iscsi_ioctl_set_config_sess - sets configured session information
 *
 * This function is an ioctl helper function to set the
 * configured session information in the persistent store.
 * In addition it will notify any active sessions of the
 * changed so this can update binding information.  It
 * will also destroy sessions that were removed and add
 * new sessions.
 */
int
iscsi_ioctl_set_config_sess(iscsi_hba_t *ihp, iscsi_config_sess_t *ics)
{
	uchar_t *name;
	iscsi_sess_t *isp;

	/* check range infomration */
	if ((ics->ics_in < ISCSI_MIN_CONFIG_SESSIONS) ||
	    (ics->ics_in > ISCSI_MAX_CONFIG_SESSIONS)) {
		/* invalid range information */
		return (EINVAL);
	}

	if (ics->ics_oid == ISCSI_INITIATOR_OID) {
		name = ihp->hba_name;
	} else {
		/* get target name */
		name = iscsi_targetparam_get_name(ics->ics_oid);
		if (name == NULL) {
			/* invalid node name */
			return (EINVAL);
		}
	}

	/* store the new information */
	if (persistent_set_config_session((char *)name, ics) == B_FALSE) {
		/* failed to store new information */
		return (EINVAL);
	}

	/* notify existing sessions of change */
	rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
	isp = ihp->hba_sess_list;
	while (isp != NULL) {

		if ((ics->ics_oid == ISCSI_INITIATOR_OID) ||
		    (strncmp((char *)isp->sess_name, (char *)name,
		    ISCSI_MAX_NAME_LEN) == 0)) {

			/*
			 * If this sessions least signficant byte
			 * of the isid is less than or equal to
			 * the the number of configured sessions
			 * then we need to tear down this session.
			 */
			if (ics->ics_in <= isp->sess_isid[5]) {
				/* First attempt to destory the session */
				if (ISCSI_SUCCESS(iscsi_sess_destroy(isp))) {
					isp = ihp->hba_sess_list;
				} else {
					/*
					 * If we can't destroy it then
					 * atleast poke it to disconnect
					 * it.
					 */
					mutex_enter(&isp->sess_state_mutex);
					iscsi_sess_state_machine(isp,
					    ISCSI_SESS_EVENT_N7);
					mutex_exit(&isp->sess_state_mutex);
					isp = isp->sess_next;
				}
			} else {
				isp = isp->sess_next;
			}
		} else {
			isp = isp->sess_next;
		}
	}
	rw_exit(&ihp->hba_sess_list_rwlock);

	/*
	 * The number of targets has changed.  Since we don't expect
	 * this to be a common operation lets keep the code simple and
	 * just use a slightly larger hammer and poke discovery.  This
	 * force the reevaulation of this target and all other targets.
	 */
	iscsid_poke_discovery(ihp, iSCSIDiscoveryMethodUnknown);
	/* lock so only one config operation occrs */
	sema_p(&iscsid_config_semaphore);
	iscsid_config_all(ihp, B_FALSE);
	sema_v(&iscsid_config_semaphore);

	return (0);
}
