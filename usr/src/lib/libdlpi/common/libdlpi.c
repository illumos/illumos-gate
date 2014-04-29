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
 * Data-Link Provider Interface (Version 2)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <stropts.h>
#include <sys/dlpi.h>
#include <errno.h>
#include <alloca.h>
#include <sys/sysmacros.h>
#include <ctype.h>
#include <net/if_types.h>
#include <netinet/arp.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libdlpi.h>
#include <libintl.h>
#include <libinetutil.h>
#include <dirent.h>

#include "libdlpi_impl.h"

static int i_dlpi_open(const char *, int *, uint_t, boolean_t);
static int i_dlpi_style1_open(dlpi_impl_t *);
static int i_dlpi_style2_open(dlpi_impl_t *);
static int i_dlpi_checkstyle(dlpi_impl_t *, t_uscalar_t);
static int i_dlpi_attach(dlpi_impl_t *);
static void i_dlpi_passive(dlpi_impl_t *);

static int i_dlpi_strputmsg(dlpi_impl_t *, const dlpi_msg_t *, const void *,
    size_t, int);
static int i_dlpi_strgetmsg(dlpi_impl_t *, int, dlpi_msg_t *, t_uscalar_t,
    t_uscalar_t, size_t, void *, size_t *, size_t *);
static int i_dlpi_msg_common(dlpi_impl_t *, const dlpi_msg_t *, dlpi_msg_t *,
    size_t, int);

static size_t i_dlpi_getprimsize(t_uscalar_t);
static int i_dlpi_multi(dlpi_handle_t, t_uscalar_t, const uint8_t *, size_t);
static int i_dlpi_promisc(dlpi_handle_t, t_uscalar_t, uint_t);
static uint_t i_dlpi_buildsap(uint8_t *, uint_t);
static void i_dlpi_writesap(void *, uint_t, uint_t);
static int i_dlpi_notifyind_process(dlpi_impl_t *, dl_notify_ind_t *);
static boolean_t i_dlpi_notifyidexists(dlpi_impl_t *, dlpi_notifyent_t *);
static void i_dlpi_deletenotifyid(dlpi_impl_t *);

struct i_dlpi_walklink_arg {
	dlpi_walkfunc_t *fn;
	void *arg;
};

static int
i_dlpi_walk_link(const char *name, void *arg)
{
	struct i_dlpi_walklink_arg *warg = arg;

	return ((warg->fn(name, warg->arg)) ? DLADM_WALK_TERMINATE :
	    DLADM_WALK_CONTINUE);
}

/*ARGSUSED*/
void
dlpi_walk(dlpi_walkfunc_t *fn, void *arg, uint_t flags)
{
	struct i_dlpi_walklink_arg warg;
	struct dirent *d;
	DIR *dp;
	dladm_handle_t handle;

	warg.fn = fn;
	warg.arg = arg;

	if (flags & DLPI_DEVIPNET) {
		if ((dp = opendir("/dev/ipnet")) == NULL)
			return;

		while ((d = readdir(dp)) != NULL) {
			if (d->d_name[0] == '.')
				continue;

			if (warg.fn(d->d_name, warg.arg))
				break;
		}

		(void) closedir(dp);
	} else {
		/*
		 * Rather than have libdlpi take the libdladm handle,
		 * open the handle here.
		 */
		if (dladm_open(&handle) != DLADM_STATUS_OK)
			return;

		(void) dladm_walk(i_dlpi_walk_link, handle, &warg,
		    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_ACTIVE);

		dladm_close(handle);
	}
}

int
dlpi_open(const char *linkname, dlpi_handle_t *dhp, uint_t flags)
{
	int		retval, on = 1;
	ifspec_t	ifsp;
	dlpi_impl_t  	*dip;

	/*
	 * Validate linkname, fail if logical unit number (lun) is specified,
	 * otherwise decompose the contents into ifsp.
	 */
	if (linkname == NULL || (strchr(linkname, ':') != NULL) ||
	    !ifparse_ifspec(linkname, &ifsp))
		return (DLPI_ELINKNAMEINVAL);

	/*
	 * Ensure flags values are sane.
	 */
	if ((flags & (DLPI_DEVIPNET|DLPI_DEVONLY)) ==
	    (DLPI_DEVIPNET|DLPI_DEVONLY))
		return (DLPI_EINVAL);

	/* Allocate a new dlpi_impl_t. */
	if ((dip = calloc(1, sizeof (dlpi_impl_t))) == NULL)
		return (DL_SYSERR);

	/* Fill in known/default libdlpi handle values. */
	dip->dli_timeout = DLPI_DEF_TIMEOUT;
	dip->dli_ppa = ifsp.ifsp_ppa;
	dip->dli_oflags = flags;
	dip->dli_notifylistp = NULL;
	dip->dli_note_processing = B_FALSE;
	if (getenv("DLPI_DEVONLY") != NULL)
		dip->dli_oflags |= DLPI_DEVONLY;

	/* Copy linkname provided to the function. */
	if (strlcpy(dip->dli_linkname, linkname, sizeof (dip->dli_linkname)) >=
	    sizeof (dip->dli_linkname)) {
		free(dip);
		return (DLPI_ELINKNAMEINVAL);
	}

	/* Copy provider name. */
	(void) strlcpy(dip->dli_provider, ifsp.ifsp_devnm,
	    sizeof (dip->dli_provider));

	/*
	 * Special case: DLPI_SERIAL flag is set to indicate a synchronous
	 * serial line interface (see syncinit(1M), syncstat(1M),
	 * syncloop(1M)), which is not a DLPI link.
	 */
	if (dip->dli_oflags & DLPI_SERIAL) {
		if ((retval = i_dlpi_style2_open(dip)) != DLPI_SUCCESS) {
			free(dip);
			return (retval);
		}

		*dhp = (dlpi_handle_t)dip;
		return (retval);
	}

	if ((retval = i_dlpi_style1_open(dip)) != DLPI_SUCCESS) {
		if (retval == DLPI_ENOTSTYLE2) {
			/*
			 * The error code indicates not to continue the
			 * style-2 open. Change the error code back to
			 * DL_SYSERR, so that one would know the cause
			 * of failure from errno.
			 */
			retval = DL_SYSERR;
		} else if (!(dip->dli_oflags & DLPI_DEVIPNET)) {
			retval = i_dlpi_style2_open(dip);
		}
		if (retval != DLPI_SUCCESS) {
			free(dip);
			return (retval);
		}
	}

	if (dip->dli_oflags & DLPI_PASSIVE)
		i_dlpi_passive(dip);

	if ((dip->dli_oflags & DLPI_RAW) &&
	    ioctl(dip->dli_fd, DLIOCRAW, 0) < 0) {
		dlpi_close((dlpi_handle_t)dip);
		return (DLPI_ERAWNOTSUP);
	}

	if ((dip->dli_oflags & DLPI_IPNETINFO) &&
	    ioctl(dip->dli_fd, DLIOCIPNETINFO, &on) < 0) {
		dlpi_close((dlpi_handle_t)dip);
		return (DLPI_EIPNETINFONOTSUP);
	}

	/*
	 * We intentionally do not care if this request fails, as this
	 * indicates the underlying DLPI device does not support Native mode
	 * (pre-GLDV3 device drivers).
	 */
	if (dip->dli_oflags & DLPI_NATIVE) {
		if ((retval = ioctl(dip->dli_fd, DLIOCNATIVE, 0)) > 0)
			dip->dli_mactype = retval;
	}

	*dhp = (dlpi_handle_t)dip;
	return (DLPI_SUCCESS);
}

void
dlpi_close(dlpi_handle_t dh)
{
	dlpi_impl_t	*dip = (dlpi_impl_t *)dh;
	dlpi_notifyent_t *next, *dnp;

	if (dip != NULL) {
		for (dnp = dip->dli_notifylistp; dnp != NULL; dnp = next) {
			next = dnp->dln_next;
			free(dnp);
		}

		(void) close(dip->dli_fd);
		free(dip);
	}
}

/*
 * NOTE: The opt argument must be zero and is reserved for future use to extend
 * fields to the dlpi_info_t structure (see dlpi_info(3DLPI)).
 */
int
dlpi_info(dlpi_handle_t dh, dlpi_info_t *infop, uint_t opt)
{
	int 		retval;
	dlpi_msg_t	req, ack;
	dl_info_ack_t	*infoackp;
	uint8_t		*sapp, *addrp;
	caddr_t		ackendp, datap;
	t_uscalar_t	dataoff, datalen;
	dlpi_impl_t	*dip = (dlpi_impl_t *)dh;

	if (dip == NULL)
		return (DLPI_EINHANDLE);

	if (infop == NULL || opt != 0)
		return (DLPI_EINVAL);

	(void) memset(infop, 0, sizeof (dlpi_info_t));

	/* Set QoS range parameters to default unsupported value. */
	infop->di_qos_range.dl_qos_type = (t_uscalar_t)DL_UNKNOWN;
	infop->di_qos_range.dl_trans_delay.dl_target_value = DL_UNKNOWN;
	infop->di_qos_range.dl_trans_delay.dl_accept_value = DL_UNKNOWN;
	infop->di_qos_range.dl_priority.dl_min = DL_UNKNOWN;
	infop->di_qos_range.dl_priority.dl_max = DL_UNKNOWN;
	infop->di_qos_range.dl_protection.dl_min = DL_UNKNOWN;
	infop->di_qos_range.dl_protection.dl_max = DL_UNKNOWN;
	infop->di_qos_range.dl_residual_error = DL_UNKNOWN;

	/* Set QoS parameters to default unsupported value. */
	infop->di_qos_sel.dl_qos_type = (t_uscalar_t)DL_UNKNOWN;
	infop->di_qos_sel.dl_trans_delay = DL_UNKNOWN;
	infop->di_qos_sel.dl_priority = DL_UNKNOWN;
	infop->di_qos_sel.dl_protection = DL_UNKNOWN;
	infop->di_qos_sel.dl_residual_error = DL_UNKNOWN;

	DLPI_MSG_CREATE(req, DL_INFO_REQ);
	DLPI_MSG_CREATE(ack, DL_INFO_ACK);

	retval = i_dlpi_msg_common(dip, &req, &ack, DL_INFO_ACK_SIZE, RS_HIPRI);
	if (retval != DLPI_SUCCESS)
		return (retval);

	infoackp = &(ack.dlm_msg->info_ack);
	if (infoackp->dl_version != DL_VERSION_2)
		return (DLPI_EVERNOTSUP);

	if (infoackp->dl_service_mode != DL_CLDLS)
		return (DLPI_EMODENOTSUP);

	dip->dli_style = infoackp->dl_provider_style;
	dip->dli_mactype = infoackp->dl_mac_type;

	ackendp = (caddr_t)ack.dlm_msg + ack.dlm_msgsz;

	/* Check and save QoS selection information, if any. */
	datalen = infoackp->dl_qos_length;
	dataoff = infoackp->dl_qos_offset;
	if (dataoff != 0 && datalen != 0) {
		datap = (caddr_t)infoackp + dataoff;
		if (datalen > sizeof (dl_qos_cl_sel1_t) ||
		    dataoff < DL_INFO_ACK_SIZE || datap + datalen > ackendp)
			return (DLPI_EBADMSG);

		(void) memcpy(&infop->di_qos_sel, datap, datalen);
		if (infop->di_qos_sel.dl_qos_type != DL_QOS_CL_SEL1)
			return (DLPI_EMODENOTSUP);
	}

	/* Check and save QoS range information, if any. */
	datalen = infoackp->dl_qos_range_length;
	dataoff = infoackp->dl_qos_range_offset;
	if (dataoff != 0 && datalen != 0) {
		datap = (caddr_t)infoackp + dataoff;
		if (datalen > sizeof (dl_qos_cl_range1_t) ||
		    dataoff < DL_INFO_ACK_SIZE || datap + datalen > ackendp)
			return (DLPI_EBADMSG);

		(void) memcpy(&infop->di_qos_range, datap, datalen);
		if (infop->di_qos_range.dl_qos_type != DL_QOS_CL_RANGE1)
			return (DLPI_EMODENOTSUP);
	}

	/* Check and save physical address and SAP information. */
	dip->dli_saplen = abs(infoackp->dl_sap_length);
	dip->dli_sapbefore = (infoackp->dl_sap_length > 0);
	infop->di_physaddrlen = infoackp->dl_addr_length - dip->dli_saplen;

	if (infop->di_physaddrlen > DLPI_PHYSADDR_MAX ||
	    dip->dli_saplen > DLPI_SAPLEN_MAX)
		return (DL_BADADDR);

	dataoff = infoackp->dl_addr_offset;
	datalen = infoackp->dl_addr_length;
	if (dataoff != 0 && datalen != 0) {
		datap = (caddr_t)infoackp + dataoff;
		if (dataoff < DL_INFO_ACK_SIZE || datap + datalen > ackendp)
			return (DLPI_EBADMSG);

		sapp = addrp = (uint8_t *)datap;
		if (dip->dli_sapbefore)
			addrp += dip->dli_saplen;
		else
			sapp += infop->di_physaddrlen;

		(void) memcpy(infop->di_physaddr, addrp, infop->di_physaddrlen);
		infop->di_sap = i_dlpi_buildsap(sapp, dip->dli_saplen);
	}

	/* Check and save broadcast address information, if any. */
	datalen = infoackp->dl_brdcst_addr_length;
	dataoff = infoackp->dl_brdcst_addr_offset;
	if (dataoff != 0 && datalen != 0) {
		datap = (caddr_t)infoackp + dataoff;
		if (dataoff < DL_INFO_ACK_SIZE || datap + datalen > ackendp)
			return (DLPI_EBADMSG);
		if (datalen != infop->di_physaddrlen)
			return (DL_BADADDR);

		infop->di_bcastaddrlen = datalen;
		(void) memcpy(infop->di_bcastaddr, datap, datalen);
	}

	infop->di_max_sdu = infoackp->dl_max_sdu;
	infop->di_min_sdu = infoackp->dl_min_sdu;
	infop->di_state = infoackp->dl_current_state;
	infop->di_mactype = infoackp->dl_mac_type;

	/* Information retrieved from the handle. */
	(void) strlcpy(infop->di_linkname, dip->dli_linkname,
	    sizeof (infop->di_linkname));
	infop->di_timeout = dip->dli_timeout;

	return (DLPI_SUCCESS);
}

/*
 * This function parses 'linkname' and stores the 'provider' name and 'PPA'.
 */
int
dlpi_parselink(const char *linkname, char *provider, uint_t *ppa)
{
	dladm_status_t status;

	status = dladm_parselink(linkname, provider, ppa);

	if (status != DLADM_STATUS_OK)
		return (DLPI_ELINKNAMEINVAL);

	return (DLPI_SUCCESS);
}

/*
 * This function takes a provider name and a PPA and stores a full linkname
 * as 'linkname'. If 'provider' already is a full linkname 'provider' name
 * is stored in 'linkname'.
 */
int
dlpi_makelink(char *linkname, const char *provider, uint_t ppa)
{
	int provlen = strlen(provider);

	if (linkname == NULL || provlen == 0 || provlen >= DLPI_LINKNAME_MAX)
		return (DLPI_ELINKNAMEINVAL);

	if (!isdigit(provider[provlen - 1])) {
		(void) snprintf(linkname, DLPI_LINKNAME_MAX, "%s%d", provider,
		    ppa);
	} else {
		(void) strlcpy(linkname, provider, DLPI_LINKNAME_MAX);
	}

	return (DLPI_SUCCESS);
}

int
dlpi_bind(dlpi_handle_t dh, uint_t sap, uint_t *boundsap)
{
	int		retval;
	dlpi_msg_t	req, ack;
	dl_bind_req_t	*bindreqp;
	dl_bind_ack_t	*bindackp;
	dlpi_impl_t	*dip = (dlpi_impl_t *)dh;

	if (dip == NULL)
		return (DLPI_EINHANDLE);

	DLPI_MSG_CREATE(req, DL_BIND_REQ);
	DLPI_MSG_CREATE(ack, DL_BIND_ACK);
	bindreqp = &(req.dlm_msg->bind_req);

	/*
	 * If 'sap' is DLPI_ANY_SAP, bind to SAP 2 on token ring, else 0 on
	 * other interface types (SAP 0 has special significance on token ring).
	 */
	if (sap == DLPI_ANY_SAP)
		bindreqp->dl_sap = ((dip->dli_mactype == DL_TPR) ? 2 : 0);
	else
		bindreqp->dl_sap = sap;

	bindreqp->dl_service_mode = DL_CLDLS;
	bindreqp->dl_conn_mgmt = 0;
	bindreqp->dl_max_conind = 0;
	bindreqp->dl_xidtest_flg = 0;

	retval = i_dlpi_msg_common(dip, &req, &ack, DL_BIND_ACK_SIZE, 0);
	if (retval != DLPI_SUCCESS)
		return (retval);

	bindackp = &(ack.dlm_msg->bind_ack);
	/*
	 * Received a DLPI_BIND_ACK, now verify that the bound SAP
	 * is equal to the SAP requested. Some DLPI MAC type may bind
	 * to a different SAP than requested, in this case 'boundsap'
	 * returns the actual bound SAP. For the case where 'boundsap'
	 * is NULL and 'sap' is not DLPI_ANY_SAP, dlpi_bind fails.
	 */
	if (boundsap != NULL) {
		*boundsap = bindackp->dl_sap;
	} else if (sap != DLPI_ANY_SAP && bindackp->dl_sap != sap) {
		if (dlpi_unbind(dh) != DLPI_SUCCESS)
			return (DLPI_FAILURE);
		else
			return (DLPI_EUNAVAILSAP);
	}

	dip->dli_sap = bindackp->dl_sap;	/* save sap value in handle */
	return (DLPI_SUCCESS);
}

int
dlpi_unbind(dlpi_handle_t dh)
{
	dlpi_msg_t	req, ack;
	dlpi_impl_t	*dip = (dlpi_impl_t *)dh;

	if (dip == NULL)
		return (DLPI_EINHANDLE);

	DLPI_MSG_CREATE(req, DL_UNBIND_REQ);
	DLPI_MSG_CREATE(ack, DL_OK_ACK);

	return (i_dlpi_msg_common(dip, &req, &ack, DL_OK_ACK_SIZE, 0));
}

/*
 * This function is invoked by dlpi_enabmulti() or dlpi_disabmulti() and
 * based on the "op" value, multicast address is enabled/disabled.
 */
static int
i_dlpi_multi(dlpi_handle_t dh, t_uscalar_t op, const uint8_t *addrp,
    size_t addrlen)
{
	dlpi_msg_t		req, ack;
	dl_enabmulti_req_t	*multireqp;
	dlpi_impl_t		*dip = (dlpi_impl_t *)dh;

	if (dip == NULL)
		return (DLPI_EINHANDLE);

	if (addrlen > DLPI_PHYSADDR_MAX)
		return (DLPI_EINVAL);

	DLPI_MSG_CREATE(req, op);
	DLPI_MSG_CREATE(ack, DL_OK_ACK);

	multireqp = &(req.dlm_msg->enabmulti_req);
	multireqp->dl_addr_length = addrlen;
	multireqp->dl_addr_offset = sizeof (dl_enabmulti_req_t);
	(void) memcpy(&multireqp[1], addrp, addrlen);

	return (i_dlpi_msg_common(dip, &req, &ack, DL_OK_ACK_SIZE, 0));
}

int
dlpi_enabmulti(dlpi_handle_t dh, const void *addrp, size_t addrlen)
{
	return (i_dlpi_multi(dh, DL_ENABMULTI_REQ, addrp, addrlen));
}

int
dlpi_disabmulti(dlpi_handle_t dh, const void *addrp, size_t addrlen)
{
	return (i_dlpi_multi(dh, DL_DISABMULTI_REQ, addrp, addrlen));
}

/*
 * This function is invoked by dlpi_promiscon() or dlpi_promiscoff(). Based
 * on the value of 'op', promiscuous mode is turned on/off at the specified
 * 'level'.
 */
static int
i_dlpi_promisc(dlpi_handle_t dh, t_uscalar_t op, uint_t level)
{
	dlpi_msg_t		req, ack;
	dl_promiscon_req_t	*promiscreqp;
	dlpi_impl_t		*dip = (dlpi_impl_t *)dh;

	if (dip == NULL)
		return (DLPI_EINHANDLE);

	DLPI_MSG_CREATE(req, op);
	DLPI_MSG_CREATE(ack, DL_OK_ACK);

	promiscreqp = &(req.dlm_msg->promiscon_req);
	promiscreqp->dl_level = level;

	return (i_dlpi_msg_common(dip, &req, &ack, DL_OK_ACK_SIZE, 0));
}

int
dlpi_promiscon(dlpi_handle_t dh, uint_t level)
{
	return (i_dlpi_promisc(dh, DL_PROMISCON_REQ, level));
}

int
dlpi_promiscoff(dlpi_handle_t dh, uint_t level)
{
	return (i_dlpi_promisc(dh, DL_PROMISCOFF_REQ, level));
}

int
dlpi_get_physaddr(dlpi_handle_t dh, uint_t type, void *addrp, size_t *addrlenp)
{
	int			retval;
	dlpi_msg_t  		req, ack;
	dl_phys_addr_req_t	*physreqp;
	dl_phys_addr_ack_t	*physackp;
	t_uscalar_t		dataoff, datalen;
	caddr_t			datap, physackendp;
	dlpi_impl_t		*dip = (dlpi_impl_t *)dh;

	if (dip == NULL)
		return (DLPI_EINHANDLE);

	if (addrlenp == NULL || addrp == NULL || *addrlenp < DLPI_PHYSADDR_MAX)
		return (DLPI_EINVAL);

	DLPI_MSG_CREATE(req, DL_PHYS_ADDR_REQ);
	DLPI_MSG_CREATE(ack, DL_PHYS_ADDR_ACK);

	physreqp = &(req.dlm_msg->physaddr_req);
	physreqp->dl_addr_type = type;

	retval = i_dlpi_msg_common(dip, &req, &ack, DL_PHYS_ADDR_ACK_SIZE, 0);
	if (retval != DLPI_SUCCESS)
		return (retval);

	/* Received DL_PHYS_ADDR_ACK, store the physical address and length. */
	physackp = &(ack.dlm_msg->physaddr_ack);
	physackendp = (caddr_t)ack.dlm_msg + ack.dlm_msgsz;
	dataoff = physackp->dl_addr_offset;
	datalen = physackp->dl_addr_length;
	if (dataoff != 0 && datalen != 0) {
		datap = (caddr_t)physackp + dataoff;
		if (datalen > DLPI_PHYSADDR_MAX)
			return (DL_BADADDR);
		if (dataoff < DL_PHYS_ADDR_ACK_SIZE ||
		    datap + datalen > physackendp)
			return (DLPI_EBADMSG);

		*addrlenp = physackp->dl_addr_length;
		(void) memcpy(addrp, datap, datalen);
	} else {
		*addrlenp = datalen;
	}

	return (DLPI_SUCCESS);
}

int
dlpi_set_physaddr(dlpi_handle_t dh, uint_t type, const void *addrp,
    size_t addrlen)
{
	dlpi_msg_t  		req, ack;
	dl_set_phys_addr_req_t	*setphysreqp;
	dlpi_impl_t		*dip = (dlpi_impl_t *)dh;

	if (dip == NULL)
		return (DLPI_EINHANDLE);

	if (addrp == NULL || type != DL_CURR_PHYS_ADDR ||
	    addrlen > DLPI_PHYSADDR_MAX)
		return (DLPI_EINVAL);

	DLPI_MSG_CREATE(req, DL_SET_PHYS_ADDR_REQ);
	DLPI_MSG_CREATE(ack, DL_OK_ACK);

	setphysreqp = &(req.dlm_msg->set_physaddr_req);
	setphysreqp->dl_addr_length = addrlen;
	setphysreqp->dl_addr_offset = sizeof (dl_set_phys_addr_req_t);
	(void) memcpy(&setphysreqp[1], addrp, addrlen);

	return (i_dlpi_msg_common(dip, &req, &ack, DL_OK_ACK_SIZE, 0));
}

int
dlpi_send(dlpi_handle_t dh, const void *daddrp, size_t daddrlen,
    const void *msgbuf, size_t msglen, const dlpi_sendinfo_t *sendp)
{
	dlpi_msg_t		req;
	dl_unitdata_req_t	*udatareqp;
	uint_t			sap;
	dlpi_impl_t		*dip = (dlpi_impl_t *)dh;

	if (dip == NULL)
		return (DLPI_EINHANDLE);

	if (dip->dli_oflags & DLPI_RAW)
		return (i_dlpi_strputmsg(dip, NULL, msgbuf, msglen, 0));

	if ((daddrlen > 0 && daddrp == NULL) || daddrlen > DLPI_PHYSADDR_MAX)
		return (DLPI_EINVAL);

	DLPI_MSG_CREATE(req, DL_UNITDATA_REQ);
	udatareqp = &(req.dlm_msg->unitdata_req);

	/* Set priority to default priority range. */
	udatareqp->dl_priority.dl_min = 0;
	udatareqp->dl_priority.dl_max = 0;

	/* Use SAP value if specified otherwise use bound SAP value. */
	if (sendp != NULL) {
		sap = sendp->dsi_sap;
		if (sendp->dsi_prio.dl_min != DL_QOS_DONT_CARE)
			udatareqp->dl_priority.dl_min = sendp->dsi_prio.dl_min;
		if (sendp->dsi_prio.dl_max != DL_QOS_DONT_CARE)
			udatareqp->dl_priority.dl_max = sendp->dsi_prio.dl_max;
	} else {
		sap = dip->dli_sap;
	}

	udatareqp->dl_dest_addr_length = daddrlen + dip->dli_saplen;
	udatareqp->dl_dest_addr_offset = DL_UNITDATA_REQ_SIZE;

	/*
	 * Since `daddrp' only has the link-layer destination address,
	 * we must prepend or append the SAP (according to dli_sapbefore)
	 * to make a full DLPI address.
	 */
	if (dip->dli_sapbefore) {
		i_dlpi_writesap(&udatareqp[1], sap, dip->dli_saplen);
		(void) memcpy((caddr_t)&udatareqp[1] + dip->dli_saplen,
		    daddrp, daddrlen);
	} else {
		(void) memcpy(&udatareqp[1], daddrp, daddrlen);
		i_dlpi_writesap((caddr_t)&udatareqp[1] + daddrlen, sap,
		    dip->dli_saplen);
	}

	return (i_dlpi_strputmsg(dip, &req, msgbuf, msglen, 0));
}

int
dlpi_recv(dlpi_handle_t dh, void *saddrp, size_t *saddrlenp, void *msgbuf,
    size_t *msglenp, int msec, dlpi_recvinfo_t *recvp)
{
	int			retval;
	dlpi_msg_t		ind;
	size_t			totmsglen;
	dl_unitdata_ind_t	*udatap;
	t_uscalar_t		dataoff, datalen;
	caddr_t			datap, indendp;
	dlpi_impl_t		*dip = (dlpi_impl_t *)dh;

	if (dip == NULL)
		return (DLPI_EINHANDLE);
	/*
	 * If handle is in raw mode ignore everything except total message
	 * length.
	 */
	if (dip->dli_oflags & DLPI_RAW) {
		retval = i_dlpi_strgetmsg(dip, msec, NULL, 0, 0, 0, msgbuf,
		    msglenp, &totmsglen);

		if (retval == DLPI_SUCCESS && recvp != NULL)
			recvp->dri_totmsglen = totmsglen;
		return (retval);
	}

	DLPI_MSG_CREATE(ind, DL_UNITDATA_IND);
	udatap = &(ind.dlm_msg->unitdata_ind);
	indendp = (caddr_t)ind.dlm_msg + ind.dlm_msgsz;

	if ((retval = i_dlpi_strgetmsg(dip, msec, &ind, DL_UNITDATA_IND,
	    DL_UNITDATA_IND, DL_UNITDATA_IND_SIZE, msgbuf,
	    msglenp, &totmsglen)) != DLPI_SUCCESS)
		return (retval);

	/*
	 * If DLPI link provides source address, store source address in
	 * 'saddrp' and source length in 'saddrlenp', else set saddrlenp to 0.
	 */
	if (saddrp != NULL && saddrlenp != NULL)  {
		if (*saddrlenp < DLPI_PHYSADDR_MAX)
			return (DLPI_EINVAL);

		dataoff = udatap->dl_src_addr_offset;
		datalen = udatap->dl_src_addr_length;
		if (dataoff != 0 && datalen != 0) {
			datap = (caddr_t)udatap + dataoff;
			if (dataoff < DL_UNITDATA_IND_SIZE ||
			    datap + datalen > indendp)
				return (DLPI_EBADMSG);

			*saddrlenp = datalen - dip->dli_saplen;
			if (*saddrlenp > DLPI_PHYSADDR_MAX)
				return (DL_BADADDR);

			if (dip->dli_sapbefore)
				datap += dip->dli_saplen;
			(void) memcpy(saddrp, datap, *saddrlenp);
		} else {
			*saddrlenp = 0;
		}
	}

	/*
	 * If destination address requested, check and save destination
	 * address, if any.
	 */
	if (recvp != NULL) {
		dataoff = udatap->dl_dest_addr_offset;
		datalen = udatap->dl_dest_addr_length;
		if (dataoff != 0 && datalen != 0) {
			datap = (caddr_t)udatap + dataoff;
			if (dataoff < DL_UNITDATA_IND_SIZE ||
			    datap + datalen > indendp)
				return (DLPI_EBADMSG);

			recvp->dri_destaddrlen = datalen - dip->dli_saplen;
			if (recvp->dri_destaddrlen > DLPI_PHYSADDR_MAX)
				return (DL_BADADDR);

			if (dip->dli_sapbefore)
				datap += dip->dli_saplen;
			(void) memcpy(recvp->dri_destaddr, datap,
			    recvp->dri_destaddrlen);
		} else {
			recvp->dri_destaddrlen = 0;
		}

		recvp->dri_destaddrtype = udatap->dl_group_address;
		recvp->dri_totmsglen = totmsglen;
	}

	return (DLPI_SUCCESS);
}

int
dlpi_enabnotify(dlpi_handle_t dh, uint_t notes, dlpi_notifyfunc_t *funcp,
    void *arg, dlpi_notifyid_t *id)
{
	int			retval;
	dlpi_msg_t		req, ack;
	dl_notify_req_t		*notifyreqp;
	dlpi_impl_t		*dip = (dlpi_impl_t *)dh;
	dlpi_notifyent_t	*newnotifp;
	dlpi_info_t 		dlinfo;

	if (dip == NULL)
		return (DLPI_EINHANDLE);

	retval = dlpi_info((dlpi_handle_t)dip, &dlinfo, 0);
	if (retval != DLPI_SUCCESS)
		return (retval);

	if (dip->dli_note_processing)
		return (DLPI_FAILURE);

	if (funcp == NULL || id == NULL)
		return (DLPI_EINVAL);

	if ((~DLPI_NOTIFICATION_TYPES & notes) ||
	    !(notes & DLPI_NOTIFICATION_TYPES))
		return (DLPI_ENOTEINVAL);

	DLPI_MSG_CREATE(req, DL_NOTIFY_REQ);
	DLPI_MSG_CREATE(ack, DL_NOTIFY_ACK);

	notifyreqp = &(req.dlm_msg->notify_req);
	notifyreqp->dl_notifications = notes;
	notifyreqp->dl_timelimit = 0;

	retval = i_dlpi_msg_common(dip, &req, &ack, DL_NOTIFY_ACK_SIZE, 0);
	if (retval == DL_NOTSUPPORTED)
		return (DLPI_ENOTENOTSUP);

	if (retval != DLPI_SUCCESS)
		return (retval);

	if ((newnotifp = calloc(1, sizeof (dlpi_notifyent_t))) == NULL)
		return (DL_SYSERR);

	/* Register notification information. */
	newnotifp->dln_fnp = funcp;
	newnotifp->dln_notes = notes;
	newnotifp->arg = arg;
	newnotifp->dln_rm = B_FALSE;

	/* Insert notification node at head */
	newnotifp->dln_next = dip->dli_notifylistp;
	dip->dli_notifylistp = newnotifp;

	*id = (dlpi_notifyid_t)newnotifp;
	return (DLPI_SUCCESS);
}

int
dlpi_disabnotify(dlpi_handle_t dh, dlpi_notifyid_t id, void **argp)
{
	dlpi_impl_t		*dip = (dlpi_impl_t *)dh;
	dlpi_notifyent_t	*remid = (dlpi_notifyent_t *)id;

	if (dip == NULL)
		return (DLPI_EINHANDLE);

	/* Walk the notifyentry list to find matching id. */
	if (!(i_dlpi_notifyidexists(dip, remid)))
		return (DLPI_ENOTEIDINVAL);

	if (argp != NULL)
		*argp = remid->arg;

	remid->dln_rm = B_TRUE;
	/* Delete node if callbacks are not being processed. */
	if (!dip->dli_note_processing)
		i_dlpi_deletenotifyid(dip);

	return (DLPI_SUCCESS);
}

int
dlpi_fd(dlpi_handle_t dh)
{
	dlpi_impl_t	*dip = (dlpi_impl_t *)dh;

	return (dip != NULL ? dip->dli_fd : -1);
}

int
dlpi_set_timeout(dlpi_handle_t dh, int sec)
{
	dlpi_impl_t	*dip = (dlpi_impl_t *)dh;

	if (dip == NULL)
		return (DLPI_EINHANDLE);

	dip->dli_timeout = sec;
	return (DLPI_SUCCESS);
}

const char *
dlpi_linkname(dlpi_handle_t dh)
{
	dlpi_impl_t	*dip = (dlpi_impl_t *)dh;

	return (dip != NULL ? dip->dli_linkname : NULL);
}

/*
 * Returns DLPI style stored in the handle.
 * Note: This function is used for test purposes only. Do not remove without
 * fixing the DLPI testsuite.
 */
uint_t
dlpi_style(dlpi_handle_t dh)
{
	dlpi_impl_t	*dip = (dlpi_impl_t *)dh;

	return (dip->dli_style);
}

uint_t
dlpi_arptype(uint_t dlpitype)
{
	switch (dlpitype) {

	case DL_ETHER:
		return (ARPHRD_ETHER);

	case DL_FRAME:
		return (ARPHRD_FRAME);

	case DL_ATM:
		return (ARPHRD_ATM);

	case DL_IPATM:
		return (ARPHRD_IPATM);

	case DL_HDLC:
		return (ARPHRD_HDLC);

	case DL_FC:
		return (ARPHRD_FC);

	case DL_CSMACD:				/* ieee 802 networks */
	case DL_TPB:
	case DL_TPR:
	case DL_METRO:
	case DL_FDDI:
		return (ARPHRD_IEEE802);

	case DL_IB:
		return (ARPHRD_IB);

	case DL_IPV4:
	case DL_IPV6:
		return (ARPHRD_TUNNEL);
	}

	return (0);
}

uint_t
dlpi_iftype(uint_t dlpitype)
{
	switch (dlpitype) {

	case DL_ETHER:
		return (IFT_ETHER);

	case DL_ATM:
		return (IFT_ATM);

	case DL_CSMACD:
		return (IFT_ISO88023);

	case DL_TPB:
		return (IFT_ISO88024);

	case DL_TPR:
		return (IFT_ISO88025);

	case DL_FDDI:
		return (IFT_FDDI);

	case DL_IB:
		return (IFT_IB);

	case DL_OTHER:
		return (IFT_OTHER);
	}

	return (0);
}

/*
 * This function attempts to open a device under the following namespaces:
 *	/dev/ipnet	- if DLPI_DEVIPNET is specified
 *      /dev/net	- if a data-link with the specified name exists
 *	/dev		- if DLPI_DEVONLY is specified, or if there is no
 *			  data-link with the specified name (could be /dev/ip)
 *
 * In particular, if DLPI_DEVIPNET is not specified, this function is used to
 * open a data-link node, or "/dev/ip" node. It is usually be called firstly
 * with style1 being B_TRUE, and if that fails and the return value is not
 * DLPI_ENOTSTYLE2, the function will again be called with style1 being
 * B_FALSE (style-1 open attempt first, then style-2 open attempt).
 *
 * If DLPI_DEVONLY is specified, both attempt will try to open the /dev node
 * directly.
 *
 * Otherwise, for style-1 attempt, the function will try to open the style-1
 * /dev/net node, and perhaps fallback to open the style-1 /dev node if the
 * give name is not a data-link name (e.g., it is /dev/ip). Note that the
 * fallback and the subsequent style-2 attempt will not happen if:
 * 1. style-1 opening of the /dev/net node succeeds;
 * 2. style-1 opening of the /dev/net node fails with errno other than ENOENT,
 *    which means that the specific /dev/net node exist, but the attempt fails
 *    for some other reason;
 * 3. style-1 openning of the /dev/net fails with ENOENT, but the name is
 *    a known device name or its VLAN PPA hack name. (for example, assuming
 *    device bge0 is renamed to net0, opening /dev/net/bge1000 would return
 *    ENOENT, but we should not fallback to open /dev/bge1000 in this case,
 *    as VLAN 1 over the bge0 device should be named as net1000.
 *
 * DLPI_ENOTSTYLE2 will be returned in case 2 and 3 to indicate not to proceed
 * the second style-2 open attempt.
 */
static int
i_dlpi_open(const char *provider, int *fd, uint_t flags, boolean_t style1)
{
	char		path[MAXPATHLEN];
	int		oflags;

	errno = ENOENT;
	oflags = O_RDWR;
	if (flags & DLPI_EXCL)
		oflags |= O_EXCL;

	if (flags & DLPI_DEVIPNET) {
		(void) snprintf(path, sizeof (path), "/dev/ipnet/%s", provider);
		if ((*fd = open(path, oflags)) != -1)
			return (DLPI_SUCCESS);
		else
			return (errno == ENOENT ? DLPI_ENOLINK : DL_SYSERR);
	} else if (style1 && !(flags & DLPI_DEVONLY)) {
		char		driver[DLPI_LINKNAME_MAX];
		char		device[DLPI_LINKNAME_MAX];
		datalink_id_t	linkid;
		uint_t		ppa;
		dladm_handle_t	handle;

		/*
		 * This is not a valid style-1 name. It could be "ip" module
		 * for example. Fallback to open the /dev node.
		 */
		if (dlpi_parselink(provider, driver, &ppa) != DLPI_SUCCESS)
			goto fallback;

		(void) snprintf(path, sizeof (path), "/dev/net/%s", provider);
		if ((*fd = open(path, oflags)) != -1)
			return (DLPI_SUCCESS);

		/*
		 * We don't fallback to open the /dev node when it returns
		 * error codes other than ENOENT. In that case, DLPI_ENOTSTYLE2
		 * is returned to indicate not to continue the style-2 open.
		 */
		if (errno != ENOENT)
			return (DLPI_ENOTSTYLE2);

		/*
		 * We didn't find the /dev/net node. Then we check whether
		 * the given name is a device name or its VLAN PPA hack name
		 * of a known link. If the answer is yes, and this link
		 * supports vanity naming, then the link (or the VLAN) should
		 * also have its /dev/net node but perhaps with another vanity
		 * name (for example, when bge0 is renamed to net0). In this
		 * case, although attempt to open the /dev/net/<devname> fails,
		 * we should not fallback to open the /dev/<devname> node.
		 */
		(void) snprintf(device, DLPI_LINKNAME_MAX, "%s%d", driver,
		    ppa >= 1000 ? ppa % 1000 : ppa);

		/* open libdladm handle rather than taking it as input */
		if (dladm_open(&handle) != DLADM_STATUS_OK)
			goto fallback;

		if (dladm_dev2linkid(handle, device, &linkid) ==
		    DLADM_STATUS_OK) {
			dladm_phys_attr_t dpa;

			if ((dladm_phys_info(handle, linkid, &dpa,
			    DLADM_OPT_ACTIVE)) == DLADM_STATUS_OK &&
			    !dpa.dp_novanity) {
				dladm_close(handle);
				return (DLPI_ENOTSTYLE2);
			}
		}
		dladm_close(handle);
	}

fallback:
	(void) snprintf(path, sizeof (path), "/dev/%s", provider);
	if ((*fd = open(path, oflags)) != -1)
		return (DLPI_SUCCESS);

	return (errno == ENOENT ? DLPI_ENOLINK : DL_SYSERR);
}

/*
 * Open a style 1 link. PPA is implicitly attached.
 */
static int
i_dlpi_style1_open(dlpi_impl_t *dip)
{
	int		retval, save_errno;
	int		fd;

	retval = i_dlpi_open(dip->dli_linkname, &fd, dip->dli_oflags, B_TRUE);
	if (retval != DLPI_SUCCESS)
		return (retval);
	dip->dli_fd = fd;

	if ((retval = i_dlpi_checkstyle(dip, DL_STYLE1)) != DLPI_SUCCESS) {
		save_errno = errno;
		(void) close(dip->dli_fd);
		errno = save_errno;
	}

	return (retval);
}

/*
 * Open a style 2 link. PPA must be explicitly attached.
 */
static int
i_dlpi_style2_open(dlpi_impl_t *dip)
{
	int 		fd;
	int 		retval, save_errno;

	retval = i_dlpi_open(dip->dli_provider, &fd, dip->dli_oflags, B_FALSE);
	if (retval != DLPI_SUCCESS)
		return (retval);
	dip->dli_fd = fd;

	/*
	 * Special case: DLPI_SERIAL flag (synchronous serial lines) is not a
	 * DLPI link so attach and ignore rest.
	 */
	if (dip->dli_oflags & DLPI_SERIAL)
		goto attach;

	if ((retval = i_dlpi_checkstyle(dip, DL_STYLE2)) != DLPI_SUCCESS)
		goto failure;

	/*
	 * Succeeded opening the link and verified it is style2. Now attach to
	 * PPA only if DLPI_NOATTACH is not set.
	 */
	if (dip->dli_oflags & DLPI_NOATTACH)
		return (DLPI_SUCCESS);

attach:
	if ((retval = i_dlpi_attach(dip)) == DLPI_SUCCESS)
		return (DLPI_SUCCESS);

failure:
	save_errno = errno;
	(void) close(dip->dli_fd);
	errno = save_errno;
	return (retval);
}

/*
 * Verify with DLPI that the link is the expected DLPI 'style' device,
 * dlpi_info sets the DLPI style in the DLPI handle.
 */
static int
i_dlpi_checkstyle(dlpi_impl_t *dip, t_uscalar_t style)
{
	int retval;
	dlpi_info_t dlinfo;

	retval = dlpi_info((dlpi_handle_t)dip, &dlinfo, 0);
	if (retval == DLPI_SUCCESS && dip->dli_style != style)
		retval = DLPI_EBADLINK;

	return (retval);
}

/*
 * For DLPI style 2 providers, an explicit attach of PPA is required.
 */
static int
i_dlpi_attach(dlpi_impl_t *dip)
{
	dlpi_msg_t		req, ack;
	dl_attach_req_t		*attachreqp;

	/*
	 * Special case: DLPI_SERIAL flag (synchronous serial lines)
	 * is not a DLPI link so ignore DLPI style.
	 */
	if (dip->dli_style != DL_STYLE2 && !(dip->dli_oflags & DLPI_SERIAL))
		return (DLPI_ENOTSTYLE2);

	DLPI_MSG_CREATE(req, DL_ATTACH_REQ);
	DLPI_MSG_CREATE(ack, DL_OK_ACK);

	attachreqp = &(req.dlm_msg->attach_req);
	attachreqp->dl_ppa = dip->dli_ppa;

	return (i_dlpi_msg_common(dip, &req, &ack, DL_OK_ACK_SIZE, 0));
}

/*
 * Enable DLPI passive mode on a DLPI handle. We intentionally do not care
 * if this request fails, as this indicates the underlying DLPI device does
 * not support link aggregation (pre-GLDV3 device drivers), and thus will
 * see the expected behavior without failing with DL_SYSERR/EBUSY when issuing
 * DLPI primitives like DL_BIND_REQ. For further info see dlpi(7p).
 */
static void
i_dlpi_passive(dlpi_impl_t *dip)
{
	dlpi_msg_t		req, ack;

	DLPI_MSG_CREATE(req, DL_PASSIVE_REQ);
	DLPI_MSG_CREATE(ack, DL_OK_ACK);

	(void) i_dlpi_msg_common(dip, &req, &ack, DL_OK_ACK_SIZE, 0);
}

/*
 * Send a dlpi control message and/or data message on a stream. The inputs
 * for this function are:
 * 	dlpi_impl_t *dip: internal dlpi handle to open stream
 *	const dlpi_msg_t *dlreqp: request message structure
 *	void *databuf:	data buffer
 *	size_t datalen:	data buffer len
 *	int flags:	flags to set for putmsg()
 * Returns DLPI_SUCCESS if putmsg() succeeds, otherwise DL_SYSERR on failure.
 */
static int
i_dlpi_strputmsg(dlpi_impl_t *dip, const dlpi_msg_t *dlreqp,
    const void *databuf, size_t datalen, int flags)
{
	int		retval;
	int		fd = dip->dli_fd;
	struct strbuf	ctl;
	struct strbuf   data;

	if (dlreqp != NULL) {
		ctl.buf = (void *)dlreqp->dlm_msg;
		ctl.len = dlreqp->dlm_msgsz;
	}

	data.buf = (void *)databuf;
	data.len = datalen;

	retval = putmsg(fd, (dlreqp == NULL ? NULL: &ctl),
	    (databuf == NULL ? NULL : &data), flags);

	return ((retval == 0) ? DLPI_SUCCESS : DL_SYSERR);
}

/*
 * Get a DLPI control message and/or data message from a stream. The inputs
 * for this function are:
 * 	dlpi_impl_t *dip: 	internal dlpi handle
 * 	int msec: 		timeout to wait for message
 *	dlpi_msg_t *dlreplyp:	reply message structure, the message size
 *				member on return stores actual size received
 *	t_uscalar_t dlreqprim: 	requested primitive
 *	t_uscalar_t dlreplyprim:acknowledged primitive in response to request
 *	size_t dlreplyminsz:	minimum size of acknowledged primitive size
 *	void *databuf: 		data buffer
 *	size_t *datalenp:	data buffer len
 *	size_t *totdatalenp: 	total data received. Greater than 'datalenp' if
 *				actual data received is larger than 'databuf'
 * Function returns DLPI_SUCCESS if requested message is retrieved
 * otherwise returns error code or timeouts. If a notification arrives on
 * the stream the callback is notified. However, error returned during the
 * handling of notification is ignored as it would be confusing to actual caller
 * of this function.
 */
static int
i_dlpi_strgetmsg(dlpi_impl_t *dip, int msec, dlpi_msg_t *dlreplyp,
    t_uscalar_t dlreqprim, t_uscalar_t dlreplyprim, size_t dlreplyminsz,
    void *databuf, size_t *datalenp, size_t *totdatalenp)
{
	int			retval;
	int			flags;
	int			fd = dip->dli_fd;
	struct strbuf		ctl, data;
	struct pollfd		pfd;
	hrtime_t		start, current;
	long			bufc[DLPI_CHUNKSIZE / sizeof (long)];
	long			bufd[DLPI_CHUNKSIZE / sizeof (long)];
	union DL_primitives	*dlprim;
	dl_notify_ind_t		*dlnotif;
	boolean_t		infinite = (msec < 0);	/* infinite timeout */

	/*
	 * dlreplyp and databuf can be NULL at the same time, to force a check
	 * for pending events on the DLPI link instance; dlpi_enabnotify(3DLPI).
	 * this will be true more so for DLPI_RAW mode with notifications
	 * enabled.
	 */
	if ((databuf == NULL && datalenp != NULL) ||
	    (databuf != NULL && datalenp == NULL))
		return (DLPI_EINVAL);

	pfd.fd = fd;
	pfd.events = POLLIN | POLLPRI;

	ctl.buf = (dlreplyp == NULL) ? bufc : (void *)dlreplyp->dlm_msg;
	ctl.len = 0;
	ctl.maxlen = (dlreplyp == NULL) ? sizeof (bufc) : dlreplyp->dlm_msgsz;

	data.buf = (databuf == NULL) ? bufd : databuf;
	data.len = 0;
	data.maxlen = (databuf == NULL) ? sizeof (bufd): *datalenp;

	for (;;) {
		if (!infinite)
			start = NSEC2MSEC(gethrtime());

		switch (poll(&pfd, 1, msec)) {
		default:
			if (pfd.revents & POLLHUP)
				return (DL_SYSERR);
			break;
		case 0:
			return (DLPI_ETIMEDOUT);
		case -1:
			return (DL_SYSERR);
		}

		flags = 0;
		if ((retval = getmsg(fd, &ctl, &data, &flags)) < 0)
			return (DL_SYSERR);

		if (totdatalenp != NULL)
			*totdatalenp = data.len;

		/*
		 * The supplied DLPI_CHUNKSIZE sized buffers are large enough
		 * to retrieve all valid DLPI responses in one iteration.
		 * If MORECTL or MOREDATA is set, we are not interested in the
		 * remainder of the message. Temporary buffers are used to
		 * drain the remainder of this message.
		 * The special case we have to account for is if
		 * a higher priority messages is enqueued  whilst handling
		 * this condition. We use a change in the flags parameter
		 * returned by getmsg() to indicate the message has changed.
		 */
		while (retval & (MORECTL | MOREDATA)) {
			struct strbuf   cscratch, dscratch;
			int		oflags = flags;

			cscratch.buf = (char *)bufc;
			dscratch.buf = (char *)bufd;
			cscratch.len = dscratch.len = 0;
			cscratch.maxlen = dscratch.maxlen =
			    sizeof (bufc);

			if ((retval = getmsg(fd, &cscratch, &dscratch,
			    &flags)) < 0)
				return (DL_SYSERR);

			if (totdatalenp != NULL)
				*totdatalenp += dscratch.len;
			/*
			 * In the special case of higher priority
			 * message received, the low priority message
			 * received earlier is discarded, if no data
			 * or control message is left.
			 */
			if ((flags != oflags) &&
			    !(retval & (MORECTL | MOREDATA)) &&
			    (cscratch.len != 0)) {
				ctl.len = MIN(cscratch.len, DLPI_CHUNKSIZE);
				if (dlreplyp != NULL)
					(void) memcpy(dlreplyp->dlm_msg, bufc,
					    ctl.len);
				break;
			}
		}

		/*
		 * Check if DL_NOTIFY_IND message received. If there is one,
		 * notify the callback function(s) and continue processing the
		 * requested message.
		 */
		if (dip->dli_notifylistp != NULL &&
		    ctl.len >= (int)(sizeof (t_uscalar_t)) &&
		    *(t_uscalar_t *)(void *)ctl.buf == DL_NOTIFY_IND) {
			/* process properly-formed DL_NOTIFY_IND messages */
			if (ctl.len >= DL_NOTIFY_IND_SIZE) {
				dlnotif = (dl_notify_ind_t *)(void *)ctl.buf;
				(void) i_dlpi_notifyind_process(dip, dlnotif);
			}
			goto update_timer;
		}

		/*
		 * If we were expecting a data message, and we got one, set
		 * *datalenp.  If we aren't waiting on a control message, then
		 * we're done.
		 */
		if (databuf != NULL && data.len >= 0) {
			*datalenp = data.len;
			if (dlreplyp == NULL)
				break;
		}

		/*
		 * If we were expecting a control message, and the message
		 * we received is at least big enough to be a DLPI message,
		 * then verify it's a reply to something we sent.  If it
		 * is a reply to something we sent, also verify its size.
		 */
		if (dlreplyp != NULL && ctl.len >= sizeof (t_uscalar_t)) {
			dlprim = dlreplyp->dlm_msg;
			if (dlprim->dl_primitive == dlreplyprim) {
				if (ctl.len < dlreplyminsz)
					return (DLPI_EBADMSG);
				dlreplyp->dlm_msgsz = ctl.len;
				break;
			} else if (dlprim->dl_primitive == DL_ERROR_ACK) {
				if (ctl.len < DL_ERROR_ACK_SIZE)
					return (DLPI_EBADMSG);

				/* Is it ours? */
				if (dlprim->error_ack.dl_error_primitive ==
				    dlreqprim)
					break;
			}
		}
update_timer:
		if (!infinite) {
			current = NSEC2MSEC(gethrtime());
			msec -= (current - start);

			if (msec <= 0)
				return (DLPI_ETIMEDOUT);
		}
	}

	return (DLPI_SUCCESS);
}

/*
 * Common routine invoked by all DLPI control routines. The inputs for this
 * function are:
 * 	dlpi_impl_t *dip: internal dlpi handle
 *	const dlpi_msg_t *dlreqp: request message structure
 *	dlpi_msg_t *dlreplyp: reply message structure
 *	size_t dlreplyminsz: minimum size of reply primitive
 *	int flags: flags to be set to send a message
 * This routine succeeds if the message is an expected request/acknowledged
 * message. However, if DLPI notification has been enabled via
 * dlpi_enabnotify(), DL_NOTIFY_IND messages are handled before handling
 * expected messages. Otherwise, any other unexpected asynchronous messages will
 * be discarded.
 */
static int
i_dlpi_msg_common(dlpi_impl_t *dip, const dlpi_msg_t *dlreqp,
    dlpi_msg_t *dlreplyp, size_t dlreplyminsz, int flags)
{
	int		retval;
	t_uscalar_t	dlreqprim = dlreqp->dlm_msg->dl_primitive;
	t_uscalar_t 	dlreplyprim = dlreplyp->dlm_msg->dl_primitive;

	/* Put the requested primitive on the stream. */
	retval = i_dlpi_strputmsg(dip, dlreqp, NULL, 0, flags);
	if (retval != DLPI_SUCCESS)
		return (retval);

	/* Retrieve acknowledged message for requested primitive. */
	retval = i_dlpi_strgetmsg(dip, (dip->dli_timeout * MILLISEC),
	    dlreplyp, dlreqprim, dlreplyprim, dlreplyminsz, NULL, NULL, NULL);
	if (retval != DLPI_SUCCESS)
		return (retval);

	/*
	 * If primitive is DL_ERROR_ACK, set errno.
	 */
	if (dlreplyp->dlm_msg->dl_primitive == DL_ERROR_ACK) {
		errno = dlreplyp->dlm_msg->error_ack.dl_unix_errno;
		retval = dlreplyp->dlm_msg->error_ack.dl_errno;
	}

	return (retval);
}

/*
 * DLPI error codes.
 */
static const char *dlpi_errlist[] = {
	"bad LSAP selector",				/* DL_BADSAP  0x00 */
	"DLSAP address in improper format or invalid",	/* DL_BADADDR 0x01 */
	"improper permissions for request",		/* DL_ACCESS  0x02 */
	"primitive issued in improper state",		/* DL_OUTSTATE 0x03 */
	NULL,						/* DL_SYSERR  0x04 */
	"sequence number not from outstanding DL_CONN_IND",
							/* DL_BADCORR 0x05 */
	"user data exceeded provider limit",		/* DL_BADDATA 0x06 */
	"requested service not supplied by provider",
						/* DL_UNSUPPORTED 0x07 */
	"specified PPA was invalid", 			/* DL_BADPPA 0x08 */
	"primitive received not known by provider",	/* DL_BADPRIM 0x09 */
	"QoS parameters contained invalid values",
						/* DL_BADQOSPARAM 0x0a */
	"QoS structure type is unknown/unsupported",	/* DL_BADQOSTYPE 0x0b */
	"token used not an active stream", 		/* DL_BADTOKEN 0x0c */
	"attempted second bind with dl_max_conind",	/* DL_BOUND 0x0d */
	"physical link initialization failed",		/* DL_INITFAILED 0x0e */
	"provider couldn't allocate alternate address",	/* DL_NOADDR 0x0f */
	"physical link not initialized",		/* DL_NOTINIT 0x10 */
	"previous data unit could not be delivered",
						/* DL_UNDELIVERABLE 0x11 */
	"primitive is known but unsupported",
						/* DL_NOTSUPPORTED 0x12 */
	"limit exceeded",				/* DL_TOOMANY 0x13 */
	"promiscuous mode not enabled",			/* DL_NOTENAB 0x14 */
	"other streams for PPA in post-attached",	/* DL_BUSY 0x15 */
	"automatic handling XID&TEST unsupported",	/* DL_NOAUTO 0x16 */
	"automatic handling of XID unsupported",	/* DL_NOXIDAUTO 0x17 */
	"automatic handling of TEST unsupported",	/* DL_NOTESTAUTO 0x18 */
	"automatic handling of XID response",		/* DL_XIDAUTO 0x19 */
	"automatic handling of TEST response", 		/* DL_TESTAUTO 0x1a */
	"pending outstanding connect indications"	/* DL_PENDING 0x1b */
};

/*
 * libdlpi error codes.
 */
static const char *libdlpi_errlist[] = {
	"DLPI operation succeeded",		/* DLPI_SUCCESS */
	"invalid argument",			/* DLPI_EINVAL */
	"invalid DLPI linkname",		/* DLPI_ELINKNAMEINVAL */
	"DLPI link does not exist",		/* DLPI_ENOLINK */
	"bad DLPI link",			/* DLPI_EBADLINK */
	"invalid DLPI handle",			/* DLPI_EINHANDLE */
	"DLPI operation timed out",		/* DLPI_ETIMEDOUT */
	"unsupported DLPI version",		/* DLPI_EVERNOTSUP */
	"unsupported DLPI connection mode",	/* DLPI_EMODENOTSUP */
	"unavailable DLPI SAP",			/* DLPI_EUNAVAILSAP */
	"DLPI operation failed",		/* DLPI_FAILURE */
	"DLPI style-2 node reports style-1",	/* DLPI_ENOTSTYLE2 */
	"bad DLPI message",			/* DLPI_EBADMSG */
	"DLPI raw mode not supported",		/* DLPI_ERAWNOTSUP */
	"DLPI notification not supported by link",
						/* DLPI_ENOTENOTSUP */
	"invalid DLPI notification type",	/* DLPI_ENOTEINVAL */
	"invalid DLPI notification id",		/* DLPI_ENOTEIDINVAL */
	"DLPI_IPNETINFO not supported"		/* DLPI_EIPNETINFONOTSUP */
};

const char *
dlpi_strerror(int err)
{
	if (err == DL_SYSERR)
		return (strerror(errno));
	else if (err >= 0 && err < NELEMS(dlpi_errlist))
		return (dgettext(TEXT_DOMAIN, dlpi_errlist[err]));
	else if (err >= DLPI_SUCCESS && err < DLPI_ERRMAX)
		return (dgettext(TEXT_DOMAIN, libdlpi_errlist[err -
		    DLPI_SUCCESS]));
	else
		return (dgettext(TEXT_DOMAIN, "Unknown DLPI error"));
}

/*
 * Each table entry comprises a DLPI/Private mactype and the description.
 */
static const dlpi_mactype_t dlpi_mactypes[] = {
	{ DL_CSMACD,		"CSMA/CD"		},
	{ DL_TPB,		"Token Bus"		},
	{ DL_TPR,		"Token Ring"		},
	{ DL_METRO,		"Metro Net"		},
	{ DL_ETHER,		"Ethernet"		},
	{ DL_HDLC,		"HDLC"			},
	{ DL_CHAR,		"Sync Character"	},
	{ DL_CTCA,		"CTCA"			},
	{ DL_FDDI,		"FDDI"			},
	{ DL_FRAME,		"Frame Relay (LAPF)"	},
	{ DL_MPFRAME,		"MP Frame Relay"	},
	{ DL_ASYNC,		"Async Character"	},
	{ DL_IPX25,		"X.25 (Classic IP)"	},
	{ DL_LOOP,		"Software Loopback"	},
	{ DL_FC,		"Fiber Channel"		},
	{ DL_ATM,		"ATM"			},
	{ DL_IPATM,		"ATM (Classic IP)"	},
	{ DL_X25,		"X.25 (LAPB)"		},
	{ DL_ISDN,		"ISDN"			},
	{ DL_HIPPI,		"HIPPI"			},
	{ DL_100VG,		"100BaseVG Ethernet"	},
	{ DL_100VGTPR,		"100BaseVG Token Ring"	},
	{ DL_ETH_CSMA,		"Ethernet/IEEE 802.3"	},
	{ DL_100BT,		"100BaseT"		},
	{ DL_IB,		"Infiniband"		},
	{ DL_IPV4,		"IPv4 Tunnel"		},
	{ DL_IPV6,		"IPv6 Tunnel"		},
	{ DL_WIFI,		"IEEE 802.11"		},
	{ DL_IPNET,		"IPNET"			}
};

const char *
dlpi_mactype(uint_t mactype)
{
	int i;

	for (i = 0; i < NELEMS(dlpi_mactypes); i++) {
		if (dlpi_mactypes[i].dm_mactype == mactype)
			return (dlpi_mactypes[i].dm_desc);
	}

	return ("Unknown MAC Type");
}

/*
 * Each table entry comprises a DLPI primitive and the maximum buffer
 * size needed, in bytes, for the DLPI message (see <sys/dlpi.h> for details).
 */
static const dlpi_primsz_t dlpi_primsizes[] = {
{ DL_INFO_REQ,		DL_INFO_REQ_SIZE				},
{ DL_INFO_ACK,		DL_INFO_ACK_SIZE + (2 * DLPI_PHYSADDR_MAX) +
			DLPI_SAPLEN_MAX + (2 * sizeof (union DL_qos_types))},
{ DL_ATTACH_REQ,	DL_ATTACH_REQ_SIZE				},
{ DL_BIND_REQ,		DL_BIND_REQ_SIZE				},
{ DL_BIND_ACK, 		DL_BIND_ACK_SIZE + DLPI_PHYSADDR_MAX +
			DLPI_SAPLEN_MAX					},
{ DL_UNBIND_REQ, 	DL_UNBIND_REQ_SIZE				},
{ DL_ENABMULTI_REQ, 	DL_ENABMULTI_REQ_SIZE + DLPI_PHYSADDR_MAX	},
{ DL_DISABMULTI_REQ, 	DL_DISABMULTI_REQ_SIZE + DLPI_PHYSADDR_MAX	},
{ DL_PROMISCON_REQ, 	DL_PROMISCON_REQ_SIZE				},
{ DL_PROMISCOFF_REQ,	DL_PROMISCOFF_REQ_SIZE				},
{ DL_PASSIVE_REQ, 	DL_PASSIVE_REQ_SIZE				},
{ DL_UNITDATA_REQ, 	DL_UNITDATA_REQ_SIZE + DLPI_PHYSADDR_MAX +
			DLPI_SAPLEN_MAX					},
{ DL_UNITDATA_IND, 	DL_UNITDATA_IND_SIZE + (2 * (DLPI_PHYSADDR_MAX +
			DLPI_SAPLEN_MAX))				},
{ DL_PHYS_ADDR_REQ, 	DL_PHYS_ADDR_REQ_SIZE				},
{ DL_PHYS_ADDR_ACK, 	DL_PHYS_ADDR_ACK_SIZE + DLPI_PHYSADDR_MAX	},
{ DL_SET_PHYS_ADDR_REQ, DL_SET_PHYS_ADDR_REQ_SIZE + DLPI_PHYSADDR_MAX	},
{ DL_OK_ACK,		MAX(DL_ERROR_ACK_SIZE, DL_OK_ACK_SIZE)		},
{ DL_NOTIFY_REQ,	DL_NOTIFY_REQ_SIZE				},
{ DL_NOTIFY_ACK,	MAX(DL_ERROR_ACK_SIZE, DL_NOTIFY_ACK_SIZE)	},
{ DL_NOTIFY_IND,	DL_NOTIFY_IND_SIZE + DLPI_PHYSADDR_MAX +
			DLPI_SAPLEN_MAX					}
};

/*
 * Refers to the dlpi_primsizes[] table to return corresponding maximum
 * buffer size.
 */
static size_t
i_dlpi_getprimsize(t_uscalar_t prim)
{
	int	i;

	for (i = 0; i < NELEMS(dlpi_primsizes); i++) {
		if (dlpi_primsizes[i].dp_prim == prim)
			return (dlpi_primsizes[i].dp_primsz);
	}

	return (sizeof (t_uscalar_t));
}

/*
 * sap values vary in length and are in host byte order, build sap value
 * by writing saplen bytes, so that the sap value is left aligned.
 */
static uint_t
i_dlpi_buildsap(uint8_t *sapp, uint_t saplen)
{
	int i;
	uint_t sap = 0;

#ifdef _LITTLE_ENDIAN
	for (i = saplen - 1; i >= 0; i--) {
#else
	for (i = 0; i < saplen; i++) {
#endif
		sap <<= 8;
		sap |= sapp[i];
	}

	return (sap);
}

/*
 * Copy sap value to a buffer in host byte order. saplen is the number of
 * bytes to copy.
 */
static void
i_dlpi_writesap(void *dstbuf, uint_t sap, uint_t saplen)
{
	uint8_t *sapp;

#ifdef _LITTLE_ENDIAN
	sapp = (uint8_t *)&sap;
#else
	sapp = (uint8_t *)&sap + (sizeof (sap) - saplen);
#endif

	(void) memcpy(dstbuf, sapp, saplen);
}

/*
 * Fill notification payload and callback each registered functions.
 * Delete nodes if any was called while processing.
 */
static int
i_dlpi_notifyind_process(dlpi_impl_t *dip, dl_notify_ind_t *dlnotifyindp)
{
	dlpi_notifyinfo_t	notifinfo;
	t_uscalar_t		dataoff, datalen;
	caddr_t			datap;
	dlpi_notifyent_t	*dnp;
	uint_t			note = dlnotifyindp->dl_notification;
	uint_t			deletenode = B_FALSE;

	notifinfo.dni_note = note;

	switch (note) {
	case DL_NOTE_SPEED:
		notifinfo.dni_speed = dlnotifyindp->dl_data;
		break;
	case DL_NOTE_SDU_SIZE:
		notifinfo.dni_size = dlnotifyindp->dl_data;
		break;
	case DL_NOTE_PHYS_ADDR:
		/*
		 * libdlpi currently only supports notifications for
		 * DL_CURR_PHYS_ADDR.
		 */
		if (dlnotifyindp->dl_data != DL_CURR_PHYS_ADDR)
			return (DLPI_ENOTENOTSUP);

		dataoff = dlnotifyindp->dl_addr_offset;
		datalen = dlnotifyindp->dl_addr_length;

		if (dataoff == 0 || datalen == 0)
			return (DLPI_EBADMSG);

		datap = (caddr_t)dlnotifyindp + dataoff;
		if (dataoff < DL_NOTIFY_IND_SIZE)
			return (DLPI_EBADMSG);

		notifinfo.dni_physaddrlen = datalen - dip->dli_saplen;

		if (notifinfo.dni_physaddrlen > DLPI_PHYSADDR_MAX)
			return (DL_BADADDR);

		(void) memcpy(notifinfo.dni_physaddr, datap,
		    notifinfo.dni_physaddrlen);
		break;
	}

	dip->dli_note_processing = B_TRUE;

	for (dnp = dip->dli_notifylistp; dnp != NULL; dnp = dnp->dln_next) {
		if (note & dnp->dln_notes)
			dnp->dln_fnp((dlpi_handle_t)dip, &notifinfo, dnp->arg);
		if (dnp->dln_rm)
			deletenode = B_TRUE;
	}

	dip->dli_note_processing = B_FALSE;

	/* Walk the notifyentry list to unregister marked entries. */
	if (deletenode)
		i_dlpi_deletenotifyid(dip);

	return (DLPI_SUCCESS);
}
/*
 * Find registered notification.
 */
static boolean_t
i_dlpi_notifyidexists(dlpi_impl_t *dip, dlpi_notifyent_t *id)
{
	dlpi_notifyent_t	*dnp;

	for (dnp = dip->dli_notifylistp; dnp != NULL; dnp = dnp->dln_next) {
		if (id == dnp)
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Walk the list of notifications and deleted nodes marked to be deleted.
 */
static void
i_dlpi_deletenotifyid(dlpi_impl_t *dip)
{
	dlpi_notifyent_t	 *prev, *dnp;

	prev = NULL;
	dnp = dip->dli_notifylistp;
	while (dnp != NULL) {
		if (!dnp->dln_rm) {
			prev = dnp;
			dnp = dnp->dln_next;
		} else if (prev == NULL) {
			dip->dli_notifylistp = dnp->dln_next;
			free(dnp);
			dnp = dip->dli_notifylistp;
		} else {
			prev->dln_next = dnp->dln_next;
			free(dnp);
			dnp = prev->dln_next;
		}
	}
}
