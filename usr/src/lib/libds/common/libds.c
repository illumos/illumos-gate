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

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/sysevent.h>
#include <libsysevent.h>
#include <sys/vlds.h>
#include "libds.h"

#define	PTRTOUINT64(ptr)	((uint64_t)((uintptr_t)(ptr)))
static char vlds_device[] =
	"/devices/virtual-devices@100/channel-devices@200/"
	"virtual-domain-service@0:vlds";

typedef struct dslibentry {
	ds_hdl_t dsl_hdl;
	uint32_t dsl_flags;
	uint32_t dsl_tflags;
	char *dsl_service;
	ds_ops_t dsl_ops;
} dslibentry_t;

/* dsl_tflags */
#define	DSL_ENTRY_INUSE		0x0001	/* handle is currently active */

#define	MIN_DSLIB_ENTRIES	64
static dslibentry_t *dslibtab;
static int ndslib;

/*
 * Lock to protect the dslibtab table.  We only need to protect this
 * table for those functions which actually look at or modify the table:
 * service registration (ds_svc_reg/ds_clnt_reg), service unregistration
 * (ds_hdl_unreg) or during callbacks (ds_recv)
 */
static mutex_t dslib_lock;

static int ds_fd = -1;

static char *ds_sid_name = "vlds";

static evchan_t *ds_evchan;

/*
 * Static functions internal to dslib.
 */
static dslibentry_t *ds_hdl_to_dslibentry(ds_hdl_t hdl);
static dslibentry_t *ds_new_dslibentry(void);
static uint_t ds_service_count(char *service, boolean_t is_client);
static dslibentry_t *ds_lookup_dslibentry(char *service, boolean_t is_client);
static dslibentry_t *ds_register_dslibentry(ds_hdl_t hdl, char *service,
    boolean_t is_client);
static void ds_free_dslibentry(dslibentry_t *dsp, int force_unreg);
static int ds_recv(sysevent_t *sep, void *arg);
static void ds_string_arg(vlds_string_t *dsp, char *str);
static int ds_register(ds_capability_t *cap, ds_ops_t *ops, uint_t flags);

static dslibentry_t *
ds_hdl_to_dslibentry(ds_hdl_t hdl)
{
	int i;
	dslibentry_t *dsp;

	for (i = 0, dsp = dslibtab; i < ndslib; i++, dsp++) {
		if (hdl == dsp->dsl_hdl)
			return (dsp);
	}
	return (NULL);
}

static dslibentry_t *
ds_new_dslibentry(void)
{
	int newndslib;
	dslibentry_t *dsp;

	if ((dsp = ds_hdl_to_dslibentry(0)) != NULL)
		return (dsp);

	/* double the size */
	newndslib = ndslib << 1;
	if ((dslibtab = realloc(dslibtab, newndslib * sizeof (dslibentry_t)))
	    == NULL)
		return (NULL);
	dsp = &dslibtab[ndslib];
	(void) memset(dsp, 0, (newndslib - ndslib) * sizeof (dslibentry_t));
	ndslib = newndslib;
	return (dsp);
}

static uint_t
ds_service_count(char *service, boolean_t is_client)
{
	int i;
	dslibentry_t *dsp;
	uint_t is_client_flag = is_client ? VLDS_REG_CLIENT : 0;
	uint_t count = 0;

	for (i = 0, dsp = dslibtab; i < ndslib; i++, dsp++) {
		if (dsp->dsl_hdl != 0 &&
		    strcmp(dsp->dsl_service, service) == 0 &&
		    (dsp->dsl_flags & VLDS_REG_CLIENT) == is_client_flag) {
			count++;
		}
	}
	return (count);
}

static dslibentry_t *
ds_lookup_dslibentry(char *service, boolean_t is_client)
{
	int i;
	dslibentry_t *dsp;
	uint_t is_client_flag = is_client ? VLDS_REG_CLIENT : 0;

	for (i = 0, dsp = dslibtab; i < ndslib; i++, dsp++) {
		if (dsp->dsl_hdl != 0 &&
		    strcmp(dsp->dsl_service, service) == 0 &&
		    (dsp->dsl_flags & VLDS_REG_CLIENT) == is_client_flag) {
			return (dsp);
		}
	}
	return (NULL);
}

static dslibentry_t *
ds_register_dslibentry(ds_hdl_t hdl, char *service, boolean_t is_client)
{
	dslibentry_t *dsp, *orig_dsp;

	if ((dsp = ds_hdl_to_dslibentry(hdl)) != NULL) {
		dsp->dsl_tflags |= DSL_ENTRY_INUSE;
		return (dsp);
	}

	if ((orig_dsp = ds_lookup_dslibentry(service, is_client)) == NULL) {
		return (NULL);
	}

	if ((orig_dsp->dsl_tflags & DSL_ENTRY_INUSE) == 0) {
		/* use the original structure entry */
		orig_dsp->dsl_tflags |= DSL_ENTRY_INUSE;
		orig_dsp->dsl_hdl = hdl;
		return (orig_dsp);
	}

	/* allocate a new structure entry */
	if ((dsp = ds_new_dslibentry()) == NULL)
		return (NULL);

	*dsp = *orig_dsp;
	dsp->dsl_service = strdup(orig_dsp->dsl_service);
	dsp->dsl_hdl = hdl;
	return (dsp);
}

/*
 * Want to leave an entry in the dslib table even though all the
 * handles may have been unregistered for it.
 */
static void
ds_free_dslibentry(dslibentry_t *dsp, int force_unreg)
{
	uint_t nhdls;

	/*
	 * Find out if we have 1 or 2 or more handles for the given
	 * service.  Having one implies that we want to leave the entry
	 * intact but marked as not in use unless this is a ds_unreg_hdl
	 * (force_unreg is true).
	 */
	nhdls = ds_service_count(dsp->dsl_service,
	    (dsp->dsl_flags & VLDS_REG_CLIENT) != 0);

	if ((nhdls == 1 && force_unreg) || nhdls >= 2) {
		dsp->dsl_hdl = 0;
		if (dsp->dsl_service) {
			free(dsp->dsl_service);
		}
		(void) memset(dsp, 0, sizeof (dslibentry_t));
	} else if (nhdls == 1) {
		dsp->dsl_tflags &= ~DSL_ENTRY_INUSE;
	}
}

/*ARGSUSED*/
static int
ds_recv(sysevent_t *sep, void *arg)
{
	nvlist_t *nvl;
	uint64_t hdl;
	ds_ver_t ver;
	ds_domain_hdl_t dhdl;
	uchar_t *bufp;
	boolean_t is_client;
	uint_t buflen;
	char *subclass;
	char *servicep;
	dslibentry_t *dsp;
	ds_cb_arg_t cb_arg;

	subclass = sysevent_get_subclass_name(sep);
	if (sysevent_get_attr_list(sep, &nvl) != 0) {
		return (0);
	}

	if (nvlist_lookup_uint64(nvl, VLDS_HDL, &hdl) == 0) {
		if (strcmp(subclass, ESC_VLDS_REGISTER) == 0) {
			void (*reg_cb)(ds_hdl_t, ds_cb_arg_t, ds_ver_t *,
			    ds_domain_hdl_t) = NULL;

			if (nvlist_lookup_string(nvl, VLDS_SERVICE_ID,
			    &servicep) == 0 &&
			    nvlist_lookup_boolean_value(nvl, VLDS_ISCLIENT,
			    &is_client) == 0) {
				(void) mutex_lock(&dslib_lock);
				if ((dsp = ds_register_dslibentry(hdl,
				    servicep, is_client)) != NULL) {
					reg_cb = dsp->dsl_ops.ds_reg_cb;
					cb_arg = dsp->dsl_ops.cb_arg;
				}
				(void) mutex_unlock(&dslib_lock);
				if (reg_cb != NULL &&
				    nvlist_lookup_uint64(nvl, VLDS_DOMAIN_HDL,
				    &dhdl) == 0 &&
				    nvlist_lookup_uint16(nvl, VLDS_VER_MAJOR,
				    &ver.major) == 0 &&
				    nvlist_lookup_uint16(nvl, VLDS_VER_MINOR,
				    &ver.minor) == 0) {
					(reg_cb)((ds_hdl_t)hdl, cb_arg, &ver,
					    dhdl);
				}
			}
		} else if (strcmp(subclass, ESC_VLDS_UNREGISTER) == 0) {
			void (*unreg_cb)(ds_hdl_t, ds_cb_arg_t) = NULL;

			(void) mutex_lock(&dslib_lock);
			if ((dsp = ds_hdl_to_dslibentry(hdl)) != NULL) {
				unreg_cb = dsp->dsl_ops.ds_unreg_cb;
				cb_arg = dsp->dsl_ops.cb_arg;
				ds_free_dslibentry(dsp, 0);
			}
			(void) mutex_unlock(&dslib_lock);
			if (unreg_cb != NULL) {
				(unreg_cb)((ds_hdl_t)hdl, cb_arg);
			}
		} else if (strcmp(subclass, ESC_VLDS_DATA) == 0) {
			void (*data_cb)(ds_hdl_t, ds_cb_arg_t, void *,
			    size_t) = NULL;

			(void) mutex_lock(&dslib_lock);
			if ((dsp = ds_hdl_to_dslibentry(hdl)) != NULL) {
				data_cb = dsp->dsl_ops.ds_data_cb;
				cb_arg = dsp->dsl_ops.cb_arg;
			}
			(void) mutex_unlock(&dslib_lock);
			if (data_cb != NULL &&
			    nvlist_lookup_byte_array(nvl, VLDS_DATA, &bufp,
			    &buflen) == 0) {
				(data_cb)((ds_hdl_t)hdl, cb_arg, bufp, buflen);
			}
		}
	}
	nvlist_free(nvl);
	return (0);
}

static void
ds_string_arg(vlds_string_t *dsp, char *str)
{
	if (str == NULL) {
		dsp->vlds_strp = 0;
		dsp->vlds_strlen = 0;
	} else {
		dsp->vlds_strp = PTRTOUINT64(str);
		dsp->vlds_strlen = strlen(str) + 1;
	}
}

static int
ds_init_sysev(void)
{
	char evchan_name[MAX_CHNAME_LEN];

	(void) sprintf(evchan_name, VLDS_SYSEV_CHAN_FMT, (int)getpid());
	if (sysevent_evc_bind(evchan_name, &ds_evchan, 0) != 0) {
		return (errno);
	}
	if (sysevent_evc_subscribe(ds_evchan, ds_sid_name, EC_VLDS,
	    ds_recv, NULL, 0) != 0) {
		(void) sysevent_evc_unbind(ds_evchan);
		ds_evchan = NULL;
		return (errno);
	}
	return (0);
}

int
ds_init(void)
{
	if (ds_fd >= 0)
		return (0);

	if ((ds_fd = open(vlds_device, 0)) < 0)
		return (errno);

	if (dslibtab == NULL) {
		dslibtab = malloc(sizeof (dslibentry_t) * MIN_DSLIB_ENTRIES);
		if (dslibtab == NULL)
			return (errno = ENOMEM);
		ndslib = MIN_DSLIB_ENTRIES;
		(void) memset(dslibtab, 0, sizeof (dslibentry_t) * ndslib);
	}

	(void) mutex_init(&dslib_lock, USYNC_THREAD, NULL);
	return (0);
}

static int
ds_register(ds_capability_t *cap, ds_ops_t *ops, uint_t flags)
{
	dslibentry_t *dsp;
	vlds_svc_reg_arg_t vlds_arg;
	vlds_cap_t vlds_cap;
	vlds_ver_t vlds_vers[VLDS_MAX_VERS];
	uint64_t hdl_arg;
	ds_hdl_t hdl;
	uint_t nhdls;
	int i;

	if (cap == NULL || ops == NULL || cap->svc_id == NULL ||
	    cap->vers == NULL || (flags & (~VLDS_REG_CLIENT)) != 0) {
		return (errno = EINVAL);
	}

	if (cap->nvers > VLDS_MAX_VERS) {
		return (errno = EINVAL);
	}

	if (ds_fd < 0 && (errno = ds_init()) != 0) {
		return (errno);
	}

	if (ds_hdl_lookup(cap->svc_id, (flags & VLDS_REG_CLIENT), NULL, 1,
	    &nhdls) == 0 && nhdls == 1) {
		return (errno = EALREADY);
	}

	(void) mutex_lock(&dslib_lock);
	if ((dsp = ds_new_dslibentry()) == NULL) {
		(void) mutex_unlock(&dslib_lock);
		return (errno = ENOMEM);
	}

	/* Setup device driver capability structure. */

	/* service string */
	ds_string_arg(&vlds_cap.vlds_service, cap->svc_id);

	/* version array */
	for (i = 0; i < cap->nvers; i++) {
		vlds_vers[i].vlds_major = cap->vers[i].major;
		vlds_vers[i].vlds_minor = cap->vers[i].minor;
	}
	vlds_cap.vlds_versp = PTRTOUINT64(vlds_vers);
	vlds_cap.vlds_nver = cap->nvers;

	/*
	 * Format args for VLDS_SVC_REG ioctl.
	 */

	vlds_arg.vlds_capp = PTRTOUINT64(&vlds_cap);

	/* op flags */
	if (ops->ds_reg_cb != NULL)
		flags |= VLDS_REGCB_VALID;
	if (ops->ds_unreg_cb != NULL)
		flags |= VLDS_UNREGCB_VALID;
	if (ops->ds_data_cb != NULL)
		flags |= VLDS_DATACB_VALID;
	vlds_arg.vlds_reg_flags = flags;

	/* returned handle */
	vlds_arg.vlds_hdlp = PTRTOUINT64(&hdl_arg);

	if (ioctl(ds_fd, VLDS_SVC_REG, &vlds_arg) < 0) {
		(void) mutex_unlock(&dslib_lock);
		return (errno);
	}

	/*
	 * Setup user callback sysevent channel.
	 */
	if ((flags & VLDS_ANYCB_VALID) != 0 && ds_evchan == NULL &&
	    ds_init_sysev() != 0) {
		(void) mutex_unlock(&dslib_lock);
		(void) ioctl(ds_fd, VLDS_UNREG_HDL, &vlds_arg);
		return (errno);
	}

	hdl = hdl_arg;

	/*
	 * Set entry values in dslibtab.
	 */
	dsp->dsl_hdl = hdl;
	dsp->dsl_flags = flags;
	dsp->dsl_tflags = 0;
	dsp->dsl_service = strdup(cap->svc_id);
	dsp->dsl_ops = *ops;
	(void) mutex_unlock(&dslib_lock);
	return (0);
}

/*
 * Registers a service provider.  Kicks off the handshake with other
 * domain(s) to announce servce.  Callback events are as described above.
 */
int
ds_svc_reg(ds_capability_t *cap, ds_ops_t *ops)
{
	return (ds_register(cap, ops, 0));
}

/*
 * Registers interest in a service from a specific domain.  When that
 * service is registered, the register callback is invoked.  When that
 * service is unregistered, the unregister callback is invoked.  When
 * data is received, the receive data callback is invoked.
 */
int
ds_clnt_reg(ds_capability_t *cap, ds_ops_t *ops)
{
	return (ds_register(cap, ops, VLDS_REG_CLIENT));
}

/*
 * Given a service name and type, returns the existing handle(s), if
 * one or more exist.  This could be used to poll for the connection being
 * registered or unregistered, rather than using the register/unregister
 * callbacks.
 */
int
ds_hdl_lookup(char *service, boolean_t is_client, ds_hdl_t *hdlsp,
    uint_t maxhdls, uint_t *nhdlsp)
{
	vlds_hdl_lookup_arg_t vlds_arg;
	uint64_t nhdls_arg;

	errno = 0;
	if (ds_fd < 0) {
		return (errno = EBADF);
	}

	if (service == NULL) {
		return (errno = EINVAL);
	}

	ds_string_arg(&vlds_arg.vlds_service, service);
	vlds_arg.vlds_isclient = is_client ? VLDS_REG_CLIENT : 0;
	vlds_arg.vlds_hdlsp = PTRTOUINT64(hdlsp);
	vlds_arg.vlds_maxhdls = maxhdls;
	vlds_arg.vlds_nhdlsp = PTRTOUINT64(&nhdls_arg);

	if (ioctl(ds_fd, VLDS_HDL_LOOKUP, &vlds_arg) < 0) {
		return (errno);
	}

	*nhdlsp = nhdls_arg;
	return (0);
}

/*
 * Given a handle, return its associated domain.
 */
int
ds_domain_lookup(ds_hdl_t hdl, ds_domain_hdl_t *dhdlp)
{
	vlds_dmn_lookup_arg_t vlds_arg;
	uint64_t dhdl_arg;

	if (ds_fd < 0) {
		return (errno = EBADF);
	}

	vlds_arg.vlds_hdl = hdl;
	vlds_arg.vlds_dhdlp = PTRTOUINT64(&dhdl_arg);

	if (ioctl(ds_fd, VLDS_DMN_LOOKUP, &vlds_arg) < 0) {
		return (errno);
	}

	if (dhdlp) {
		*dhdlp = dhdl_arg;
	}

	return (0);
}

/*
 * Unregisters either a service or an interest in that service
 * indicated by the supplied handle.
 */
int
ds_unreg_hdl(ds_hdl_t hdl)
{
	dslibentry_t *dsp;
	vlds_unreg_hdl_arg_t vlds_arg;

	(void) mutex_lock(&dslib_lock);
	if ((dsp = ds_hdl_to_dslibentry(hdl)) != NULL) {
		ds_free_dslibentry(dsp, 1);
	}
	(void) mutex_unlock(&dslib_lock);

	if (ds_fd >= 0) {
		vlds_arg.vlds_hdl = hdl;
		(void) ioctl(ds_fd, VLDS_UNREG_HDL, &vlds_arg);
	}

	return (0);
}

/*
 * Send data to the appropriate service provider or client
 * indicated by the provided handle.  The sender will block
 * until the message has been sent.  There is no guarantee
 * that multiple calls to ds_send_msg by the same thread
 * will result in the data showing up at the receiver in
 * the same order as sent.  If multiple messages are required,
 * it will be up to the sender and receiver to implement a
 * protocol.
 */
int
ds_send_msg(ds_hdl_t hdl, void *buf, size_t buflen)
{
	vlds_send_msg_arg_t vlds_arg;

	if (ds_fd < 0) {
		return (errno = EBADF);
	}

	vlds_arg.vlds_hdl = hdl;
	vlds_arg.vlds_bufp = PTRTOUINT64(buf);
	vlds_arg.vlds_buflen = buflen;

	if (ioctl(ds_fd, VLDS_SEND_MSG, &vlds_arg) < 0) {
		return (errno);
	}

	return (0);
}

/*
 * Receive data from the appropriate service provider or client
 * indicated by the provided handle.  The sender will block
 * until a message has been received.
 */
int
ds_recv_msg(ds_hdl_t hdl, void *buf, size_t buflen, size_t *msglen)
{
	vlds_recv_msg_arg_t vlds_arg;
	uint64_t msglen_arg;

	if (ds_fd < 0) {
		return (errno = EBADF);
	}

	vlds_arg.vlds_hdl = hdl;
	vlds_arg.vlds_bufp = PTRTOUINT64(buf);
	vlds_arg.vlds_buflen = buflen;
	vlds_arg.vlds_msglenp = PTRTOUINT64(&msglen_arg);

	if (ioctl(ds_fd, VLDS_RECV_MSG, &vlds_arg) < 0) {
		if (errno == EFBIG && msglen) {
			*msglen = msglen_arg;
		}
		return (errno);
	}

	if (msglen) {
		*msglen = msglen_arg;
	}

	return (0);
}

int
ds_isready(ds_hdl_t hdl, boolean_t *is_ready)
{
	vlds_hdl_isready_arg_t vlds_arg;
	uint64_t is_ready_arg;

	if (ds_fd < 0) {
		return (errno = EBADF);
	}

	vlds_arg.vlds_hdl = hdl;
	vlds_arg.vlds_isreadyp = PTRTOUINT64(&is_ready_arg);

	if (ioctl(ds_fd, VLDS_HDL_ISREADY, &vlds_arg) < 0) {
		return (errno);
	}

	*is_ready = (is_ready_arg != 0);
	return (0);
}

/*
 * Given a domain name, return its associated domain handle.
 */
int
ds_dom_name_to_hdl(char *domain_name, ds_domain_hdl_t *dhdlp)
{
	vlds_dom_nam2hdl_arg_t vlds_arg;
	uint64_t dhdl_arg;

	if (ds_fd < 0) {
		return (errno = EBADF);
	}

	ds_string_arg(&vlds_arg.vlds_domain_name, domain_name);
	vlds_arg.vlds_dhdlp = PTRTOUINT64(&dhdl_arg);

	if (ioctl(ds_fd, VLDS_DOM_NAM2HDL, &vlds_arg) < 0) {
		return (errno);
	}

	if (dhdlp) {
		*dhdlp = dhdl_arg;
	}

	return (0);
}

/*
 * Given a domain handle, return its associated domain name.
 */
int
ds_dom_hdl_to_name(ds_domain_hdl_t dhdl, char *domain_name, uint_t maxnamlen)
{
	vlds_dom_hdl2nam_arg_t vlds_arg;

	if (ds_fd < 0) {
		return (errno = EBADF);
	}

	vlds_arg.vlds_dhdl = dhdl;
	vlds_arg.vlds_domain_name.vlds_strp = PTRTOUINT64(domain_name);
	vlds_arg.vlds_domain_name.vlds_strlen = maxnamlen;

	if (ioctl(ds_fd, VLDS_DOM_HDL2NAM, &vlds_arg) < 0) {
		return (errno);
	}

	return (0);
}

void
ds_unreg_svc(char *service, boolean_t is_client)
{
	ds_hdl_t hdl;
	uint_t nhdls;

	while (ds_hdl_lookup(service, is_client, &hdl, 1, &nhdls) == 0 &&
	    nhdls == 1) {
		(void) ds_unreg_hdl(hdl);
	}
}

void
ds_fini(void)
{
	int i;
	dslibentry_t *dsp;

	if (ds_fd >= 0) {
		(void) close(ds_fd);
		ds_fd = -1;
	}
	if (ds_evchan) {
		(void) sysevent_evc_unsubscribe(ds_evchan, ds_sid_name);
		(void) sysevent_evc_unbind(ds_evchan);
		ds_evchan = NULL;
	}
	if (ndslib > 0) {
		(void) mutex_lock(&dslib_lock);
		for (i = 0, dsp = dslibtab; i < ndslib; i++, dsp++) {
			if (dsp->dsl_hdl == 0)
				continue;
			if (dsp->dsl_service) {
				free(dsp->dsl_service);
			}
		}
		free(dslibtab);
		ndslib = 0;
		dslibtab = NULL;
		(void) mutex_unlock(&dslib_lock);
		(void) mutex_destroy(&dslib_lock);
	}
}
