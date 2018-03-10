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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <synch.h>
#include <thread.h>
#include <unistd.h>
#include <utility.h>
#include <sys/mdesc.h>
#include <sys/mdesc_impl.h>
#include <sys/debug.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include "ldma.h"
#include "libds.h"
#include "libv12n.h"

/*
 * sun4 support for libv12n.
 *
 * Non-sun4v support is minimal.  The v12n_capabilities() function will
 * only return 0 (not supported, not enabled, no implementation).
 *
 * For sun4v the support for v12n_capabilities(), v12n_domain_roles(),
 * v12n_domain_name() and v12n_domain_uuid() are supported by scanning the
 * MD from /dev/mdesc for specific properties.  For v12n_ctrl_domain() and
 * v12n_chassis_serialno(), the ldoms agent daemon (ldmad) on the control
 * domain supplies the required information via the "agent-system" domain
 * service.
 */

/* libds statics */
static void *v12n_ds_dlhdl = NULL;
static int (*v12n_ds_send_msg)(ds_hdl_t, void *, size_t) = NULL;
static int (*v12n_ds_clnt_reg)(ds_capability_t *, ds_ops_t *);
static int (*v12n_ds_unreg_svc)(char *, boolean_t);

/*
 * Defines to support the 'agent-system' domain service.
 */

#define	LDMA_SYSTEM_NVERS		\
			(sizeof (v12n_ldma_system_vers) / sizeof (ds_ver_t))
static ds_ver_t v12n_ldma_system_vers[] = { { 1, 0} };

static ds_capability_t v12n_ldma_cap = {
	LDMA_NAME_SYSTEM,	/* svc_id */
	v12n_ldma_system_vers,	/* vers */
	LDMA_SYSTEM_NVERS	/* nvers */
};

static void v12n_ldma_register_handler(ds_hdl_t hdl, ds_cb_arg_t arg,
    ds_ver_t *ver, ds_domain_hdl_t dhdl);
static void v12n_ldma_data_handler(ds_hdl_t hdl, ds_cb_arg_t arg, void *buf,
    size_t buflen);

static ds_ops_t v12n_ldma_ops = {
	v12n_ldma_register_handler,	/* ds_reg_cb */
	NULL,				/* ds_unreg_cb */
	v12n_ldma_data_handler,		/* ds_data_cb */
	NULL				/* ds_cb_arg */
};

/* v12n_ldma_cv_state values */
#define	V12N_LDMA_CVINVALID	-1	/* invalid value for cv_state */
#define	V12N_LDMA_REGWAITING	0	/* waiting for ctrl domain reg */
#define	V12N_LDMA_REGRECEIVED	1	/* received ctrl domain reg */
#define	V12N_LDMA_MSGWAITING	2	/* waiting for message response */
#define	V12N_LDMA_MSGRECEIVED	3	/* received message response */
#define	V12N_LDMA_MSGERROR	4	/* received a bad message */

/* 'agent-system' data used in async registration/data message handlers */
static ds_hdl_t v12n_ldma_ctrl_hdl = DS_INVALID_HDL;
static int v12n_ldma_msgtype;
static char *v12n_ldma_msgstr;
static mutex_t v12n_ldma_lock = DEFAULTMUTEX;
static cond_t v12n_ldma_cv = DEFAULTCV;
static int v12n_ldma_cv_state = V12N_LDMA_CVINVALID;
static mutex_t v12n_ldma_cv_lock = DEFAULTMUTEX;

/* 'agent-system' timeout values in seconds */
static int v12n_ldma_timeout = 15;
static int v12n_ldma_sleeptime = 1;


#define	V12N_LDOMS_SUPPORTED	(V12N_CAP_SUPPORTED | V12N_CAP_ENABLED | \
				    V12N_CAP_IMPL_LDOMS)

#define	MD_DEVICE		"/dev/mdesc"

/*
 * libv12n routines to support /dev/mdesc.
 */

/*
 * Wrapper for MD free: need unused size argument.
 */
/* ARGSUSED */
static void
v12n_md_free(void *buf, size_t n)
{
	free(buf);
}

/*
 * Wrapper for MD init: read MD and invoke md_init_intern.
 */
static md_t *
v12n_md_init()
{
	md_t *mdp;
	char *buf = NULL;
	md_header_t mdh;
	int md_size;
	int fd;

	/*
	 * Open the Machine Description (MD)
	 */
	fd = open(MD_DEVICE, O_RDONLY);
	if (fd == -1) {
		return (NULL);
	}

	if (read(fd, &mdh, sizeof (md_header_t)) != sizeof (md_header_t))
		goto errdone;

	md_size = sizeof (md_header_t) + mdh.node_blk_sz + mdh.name_blk_sz +
	    mdh.data_blk_sz;

	if ((buf = malloc(md_size)) == NULL)
		goto errdone;

	(void) memcpy(buf, &mdh, sizeof (md_header_t));
	if (read(fd, buf + sizeof (md_header_t),
	    md_size - sizeof (md_header_t)) != md_size - sizeof (md_header_t)) {
		goto errdone;
	}

	mdp = md_init_intern((uint64_t *)((void *)buf), malloc, v12n_md_free);

	(void) close(fd);

	return (mdp);

errdone:
	(void) close(fd);
	free(buf);

	return (NULL);
}

/*
 * Wrapper for md_fini.  Allow NULL md ptr and free MD buffer.
 */
static void
v12n_md_fini(void *md)
{
	md_impl_t *mdp = (md_impl_t *)md;

	if (mdp) {
		free(mdp->caddr);
		(void) md_fini(md);
	}
}

/*
 * See if LDoms domaining is enabled, returns 1 if enabled.
 * Get the value of the 'domaining-enabled' property under the
 * 'platform' node.  Value of 1 => domaining is enabled.
 */
static int
v12n_domaining_enabled()
{
	mde_cookie_t *nodes, rootnode;
	int nnodes;
	uint64_t prop_val = 0;
	md_t *mdp;

	if ((mdp = v12n_md_init()) == NULL) {
		return (0);
	}

	nnodes = md_node_count(mdp);
	nodes = malloc(nnodes * sizeof (mde_cookie_t));
	if (nodes == NULL) {
		v12n_md_fini(mdp);
		return (0);
	}

	rootnode = md_root_node(mdp);

	nnodes = md_scan_dag(mdp, rootnode, md_find_name(mdp, "platform"),
	    md_find_name(mdp, "fwd"), nodes);

	if (nnodes >= 1) {
		(void) md_get_prop_val(mdp, nodes[0], "domaining-enabled",
		    &prop_val);
	}

	v12n_md_fini(mdp);
	free(nodes);
	return (prop_val == 1);
}

int
v12n_capabilities()
{
	struct utsname uinfo;
	struct stat st;
	int cap;

	/*
	 * Check if this is an LDoms system. When using LDoms each
	 * domain should have a /dev/mdesc device providing access to
	 * the Machine Description (MD) of the domain. If this device
	 * does not exist then this is not an LDoms system.
	 */
	if (uname(&uinfo) == -1 || strcmp(uinfo.machine, "sun4v")) {
		/*
		 * Not sun4v -> LDoms not supported
		 */
		cap = 0;
	} else if (stat(MD_DEVICE, &st) == 0) {
		/*
		 * sun4v + /dev/mdesc exists -> Check if LDoms enabled
		 * via the 'domaining-enabled' property.
		 */
		cap = (V12N_CAP_SUPPORTED | V12N_CAP_IMPL_LDOMS |
		    (v12n_domaining_enabled() ? V12N_CAP_ENABLED : 0));
	} else if (errno == ENOENT) {
		/*
		 * sun4v + /dev/mdesc does not exist -> LDoms supported
		 * but not enabled.
		 */
		cap = (V12N_CAP_SUPPORTED | V12N_CAP_IMPL_LDOMS);
	}

	return (cap);
}

/*
 * Routines to support v12n_domain_roles.
 */
static int
v12n_scan_md_nodes(md_t *mdp, char *node_name, char *node_str_prop,
    char **props)
{
	mde_cookie_t *nodes, rootnode;
	int nnodes, i, j;
	char *prop_str;

	nnodes = md_node_count(mdp);
	nodes = malloc(nnodes * sizeof (mde_cookie_t));
	if (nodes == NULL) {
		return (0);
	}

	rootnode = md_root_node(mdp);

	nnodes = md_scan_dag(mdp, rootnode, md_find_name(mdp, node_name),
	    md_find_name(mdp, "fwd"), nodes);

	if (node_str_prop == NULL)
		return (nnodes > 0);

	for (i = 0; i < nnodes; i++) {
		if (md_get_prop_str(mdp, nodes[i], node_str_prop, &prop_str))
			continue;
		for (j = 0; props[j] != NULL; j++) {
			if (strcmp(prop_str, props[j]) == 0) {
				free(nodes);
				return (1);
			}
		}
	}
	free(nodes);
	return (0);
}

/*
 * Check if MD has a hypervisor access point, returns 1 if true.
 * Check the MD for a 'virtual-device-port' node whose 'vldc-svc-name' is
 * 'hvctl'.
 */
static int
v12n_check_hv_access(md_t *mdp)
{
	static char *hvctl_str[] = {
		"hvctl",
		NULL
	};

	return (v12n_scan_md_nodes(mdp, "virtual-device-port", "vldc-svc-name",
	    hvctl_str));
}

/*
 * Check if MD has a virtual device service (vcc, vsw, vds), returns 1 if true.
 * Need to check all the MD 'virtual-device' nodes for a 'device-type' property
 * of 'vcc', 'vsw' or 'vds'.
 */
static int
v12n_check_virtual_service(md_t *mdp)
{
	static char *vdevs[] = {
		"vcc",
		"vsw",
		"vds",
		NULL
	};

	return (v12n_scan_md_nodes(mdp, "virtual-device", "device-type",
	    vdevs));
}

/*
 * Check if MD has an physical I/O device node, returns 1 if true.
 */
static int
v12n_check_io_service(md_t *mdp)
{
	return (v12n_scan_md_nodes(mdp, "iodevice", NULL, NULL));
}

/*
 * Check if a MD node is root PCI device, returns 1 if true.
 * Need to check all the MD 'iodevice' nodes for a 'device-type' property
 * of 'pciex'.
 */
static int
v12n_check_root(md_t *mdp)
{
	static char *pciex[] = {
		"pciex",
		NULL
	};

	return (v12n_scan_md_nodes(mdp, "iodevice", "device-type", pciex));
}

/*
 * Get the domain roles for the domain.
 */
int
v12n_domain_roles()
{
	md_t *mdp;
	int roles = 0;

	if (v12n_capabilities() != V12N_LDOMS_SUPPORTED) {
		errno = ENOTSUP;
		return (-1);
	}

	if ((mdp = v12n_md_init()) == NULL) {
		errno = EACCES;
		return (-1);
	}

	if (v12n_check_hv_access(mdp))
		roles |= V12N_ROLE_CONTROL;

	if (v12n_check_virtual_service(mdp))
		roles |= V12N_ROLE_SERVICE;

	if (v12n_check_io_service(mdp))
		roles |= V12N_ROLE_IO;

	if (v12n_check_root(mdp))
		roles |= V12N_ROLE_ROOT;

	v12n_md_fini(mdp);

	return (roles);
}

/*
 * Get domain name from MD's virtual domain service node, returns 1 on success.
 * The domain name is a string property 'vlds-domain-name' under the
 * 'virtual-device' device node whose name is 'virtual-domain-service'.
 */
static int
v12n_get_md_domain_name(md_t *mdp, char **vds_dnamep)
{
	mde_cookie_t *vdev_nodes, rootnode;
	int list_size, nvdevs, num_nodes, i, rv;
	char *vldc_name;

	num_nodes = md_node_count(mdp);
	list_size = num_nodes * sizeof (mde_cookie_t);
	vdev_nodes = malloc(list_size);
	if (vdev_nodes == NULL) {
		return (0);
	}

	rootnode = md_root_node(mdp);

	nvdevs = md_scan_dag(mdp, rootnode, md_find_name(mdp, "virtual-device"),
	    md_find_name(mdp, "fwd"), vdev_nodes);

	rv = 0;
	for (i = 0; i < nvdevs; i++) {
		if (md_get_prop_str(mdp, vdev_nodes[i], "name", &vldc_name))
			continue;
		if (strcmp(vldc_name, "virtual-domain-service") == 0) {
			rv = (md_get_prop_str(mdp, vdev_nodes[i],
			    "vlds-domain-name", vds_dnamep) == 0);
			break;
		}
	}
	free(vdev_nodes);
	return (rv);
}

/*
 * String copyout utility.
 */
static size_t
v12n_string_copyout(char *sout, char *sfrom, size_t count)
{
	size_t ret = strlen(sfrom) + 1;

	if (sout != NULL && count > 0) {
		count = MIN(ret, count);
		(void) memcpy(sout, sfrom, count);
	}
	return (ret);
}

/*
 * Get the domain name of this domain.
 */
size_t
v12n_domain_name(char *buf, size_t count)
{
	md_t *mdp = NULL;
	char *ldmname;
	int rv = -1;

	if (v12n_capabilities() != V12N_LDOMS_SUPPORTED) {
		errno = ENOTSUP;
	} else if ((mdp = v12n_md_init()) == NULL) {
		errno = EACCES;
	} else if (!v12n_get_md_domain_name(mdp, &ldmname)) {
		errno = ESRCH;
	} else {
		rv = v12n_string_copyout(buf, ldmname, count);
	}

	v12n_md_fini(mdp);
	return (rv);
}

/*
 * Get UUID string from MD, returns 1 on success.
 * The UUID is a string property 'uuid' under the 'platform' node of the MD.
 */
static int
v12n_get_md_uuid_str(md_t *mdp, char **uuid_strp)
{
	mde_cookie_t *plat_nodes, rootnode;
	int list_size, npnodes, num_nodes, rv;

	num_nodes = md_node_count(mdp);
	list_size = num_nodes * sizeof (mde_cookie_t);
	plat_nodes = malloc(list_size);
	if (plat_nodes == NULL) {
		return (0);
	}

	rootnode = md_root_node(mdp);

	npnodes = md_scan_dag(mdp, rootnode, md_find_name(mdp, "platform"),
	    md_find_name(mdp, "fwd"), plat_nodes);

	if (npnodes >= 1)
		rv = !md_get_prop_str(mdp, plat_nodes[0], "uuid", uuid_strp);
	else
		rv = 0;

	free(plat_nodes);
	return (rv);
}

/*
 * Get the domain UUID.
 */
int
v12n_domain_uuid(uuid_t uuid)
{
	md_t *mdp = NULL;
	char *uuid_str;
	int rv = -1;

	if (v12n_capabilities() != V12N_LDOMS_SUPPORTED) {
		errno = ENOTSUP;
	} else if ((mdp = v12n_md_init()) == NULL) {
		errno = EACCES;
	} else if (!v12n_get_md_uuid_str(mdp, &uuid_str)) {
		errno = ESRCH;
	} else {
		rv = uuid_parse(uuid_str, uuid);
	}

	v12n_md_fini(mdp);

	return (rv);
}

/*
 * Send 'agent-system' request message.
 */
static int
v12n_ldma_send_request()
{
	ldma_message_header_t ldmamsg;

	if (v12n_ds_send_msg == NULL || v12n_ldma_ctrl_hdl == DS_INVALID_HDL)
		return (ENOENT);

	ldmamsg.msg_num = 0;
	ldmamsg.msg_type = v12n_ldma_msgtype;
	ldmamsg.msg_info = 0;
	return (v12n_ds_send_msg(v12n_ldma_ctrl_hdl, (char *)&ldmamsg,
	    sizeof (ldmamsg)));
}

/*
 * 'agent-system' registration handler.
 * If we get a registration from the control domain (domain 0), then send
 * the requested message.  Otherwise, ignore the registration.
 */
/* ARGSUSED */
static void
v12n_ldma_register_handler(ds_hdl_t hdl, ds_cb_arg_t arg, ds_ver_t *ver,
    ds_domain_hdl_t dhdl)
{

	/* got registration from control domain */
	if (dhdl == 0) {
		(void) mutex_lock(&v12n_ldma_cv_lock);
		if (v12n_ldma_cv_state == V12N_LDMA_REGWAITING) {
			v12n_ldma_ctrl_hdl = hdl;
			v12n_ldma_cv_state = V12N_LDMA_REGRECEIVED;
			(void) cond_signal(&v12n_ldma_cv);
		}
		(void) mutex_unlock(&v12n_ldma_cv_lock);
	}
}

/*
 * 'agent-system' data handler.
 */
/* ARGSUSED */
static void
v12n_ldma_data_handler(ds_hdl_t hdl, ds_cb_arg_t arg, void *buf,
    size_t buflen)
{
	char *data;
	ldma_message_header_t *ldmp;
	int n;
	int cv_state = V12N_LDMA_MSGERROR;

	/*
	 * Ignore any message not from the control domain.
	 */
	if (v12n_ldma_ctrl_hdl != hdl)
		return;

	/*
	 * Ignore any unexpected message.
	 */
	if (buflen < LDMA_MESSAGE_HEADER_SIZE)
		return;

	/*
	 * Ignore message with unexpected msgnum.
	 */
	ldmp = (ldma_message_header_t *)buf;
	if (ldmp->msg_num != 0)
		return;

	switch (ldmp->msg_type) {

	case LDMA_MSG_RESULT:
		if (ldmp->msg_info == 0 ||
		    ldmp->msg_info > LDMA_MESSAGE_DLEN(buflen)) {
			cv_state = V12N_LDMA_MSGERROR;
			break;
		}
		data = LDMA_HDR2DATA(buf);

		/* ensure that data ends with a '\0' */
		data[ldmp->msg_info - 1] = '\0';
		switch (v12n_ldma_msgtype) {

		case LDMA_MSGSYS_GET_SYSINFO:
			/*
			 * Control domain nodename is second string in the
			 * message.  Make sure there is enough data in the msg
			 * to have a second string.
			 */
			n = strlen(data);
			if (LDMA_MESSAGE_DLEN(buflen) <= n + 3) {
				cv_state = V12N_LDMA_MSGERROR;
				break;
			}
			data += n + 1;
			if ((v12n_ldma_msgstr = strdup(data)) == NULL)
				cv_state = V12N_LDMA_MSGERROR;
			else
				cv_state = V12N_LDMA_MSGRECEIVED;
			break;

		case LDMA_MSGSYS_GET_CHASSISNO:
			if ((v12n_ldma_msgstr = strdup(data)) == NULL)
				cv_state = V12N_LDMA_MSGERROR;
			else
				cv_state = V12N_LDMA_MSGRECEIVED;
			break;

		default:
			/* v12n_ldma_msgtype must be valid */
			ASSERT(0);
		}
		break;

	case LDMA_MSG_ERROR:
		cv_state = V12N_LDMA_MSGERROR;
		break;

	default:
		/* unexpected message, ignored */
		return;
	}

	(void) mutex_lock(&v12n_ldma_cv_lock);
	v12n_ldma_cv_state = cv_state;
	(void) cond_signal(&v12n_ldma_cv);
	(void) mutex_unlock(&v12n_ldma_cv_lock);
}


/*
 * libds doesn't exist on non-sun4v, dynamically load it and get the
 * function pointers to the needed lib functions.
 */
static int
v12n_libds_init(void)
{
	if (v12n_ds_dlhdl != NULL) {
		if (v12n_ds_clnt_reg == NULL || v12n_ds_send_msg == NULL ||
		    v12n_ds_unreg_svc == NULL)
			return (ENOENT);
		return (0);
	}

	if ((v12n_ds_dlhdl = dlopen("libds.so.1",
	    RTLD_NOW | RTLD_GLOBAL)) == NULL)
		return (ENOENT);

	if ((v12n_ds_clnt_reg = (int (*)(ds_capability_t *, ds_ops_t *))
	    dlsym(v12n_ds_dlhdl, "ds_clnt_reg")) == NULL)
		return (ENOENT);

	if ((v12n_ds_send_msg = (int (*)(ds_hdl_t, void *, size_t))
	    dlsym(v12n_ds_dlhdl, "ds_send_msg")) == NULL)
		return (ENOENT);

	if ((v12n_ds_unreg_svc = (int (*)(char *, boolean_t))
	    dlsym(v12n_ds_dlhdl, "ds_unreg_svc")) == NULL)
		return (ENOENT);

	return (0);
}

/*
 * Initiate and wait for an ldmad 'agent-system' domain service.
 * Dynamically load libds, register the client 'agent-system' service
 * and wait for a specified amount of time for the 'agent-system'
 * service on the control domain to respond to the request.
 */
static int
v12n_get_ldma_system_msg(int msgtype, char **strp)
{
	int tout;
	int err = 0;
	timestruc_t timeout;

	/*
	 * Ensure that there's only one thread trying to do a
	 * 'agent-system' client registration/message at a time.
	 */
	(void) mutex_lock(&v12n_ldma_lock);
	if ((err = v12n_libds_init()) != 0) {
		(void) mutex_unlock(&v12n_ldma_lock);
		return (err);
	}

	v12n_ldma_msgtype = msgtype;
	v12n_ldma_msgstr = NULL;

	/* initialize v12n_ldma_cv_state variable before registering service */
	(void) mutex_lock(&v12n_ldma_cv_lock);
	v12n_ldma_cv_state = V12N_LDMA_REGWAITING;
	(void) mutex_unlock(&v12n_ldma_cv_lock);

	/*
	 * Other instances may be trying to load the "agent-system" service.
	 * If a collision happens (EBUSY error), wait and try again.
	 */
	for (tout = 0; tout < v12n_ldma_timeout; tout += v12n_ldma_sleeptime) {
		if ((err = v12n_ds_clnt_reg(&v12n_ldma_cap,
		    &v12n_ldma_ops)) == 0)
			break;
		if (err != EALREADY) {
			goto done;
		}
		(void) sleep(v12n_ldma_sleeptime);
	}

	if (tout >= v12n_ldma_timeout) {
		err = EBUSY;
		goto done;
	}

	/*
	 * Wait for control domain registration.
	 */
	timeout.tv_sec = v12n_ldma_timeout;
	timeout.tv_nsec = 0;

	(void) mutex_lock(&v12n_ldma_cv_lock);
	while (v12n_ldma_cv_state == V12N_LDMA_REGWAITING) {
		if ((err = cond_reltimedwait(&v12n_ldma_cv,
		    &v12n_ldma_cv_lock, &timeout)) != EINTR)
			break;
	}

	/*
	 * Check for timeout or an error.
	 */
	if (v12n_ldma_cv_state != V12N_LDMA_REGRECEIVED) {
		if (err == 0)
			err = EPROTO;
		(void) mutex_unlock(&v12n_ldma_cv_lock);
		goto done;
	}

	/*
	 * Received a registration request, send the request message.
	 */
	v12n_ldma_cv_state = V12N_LDMA_MSGWAITING;
	if ((err = v12n_ldma_send_request()) != 0) {
		(void) mutex_unlock(&v12n_ldma_cv_lock);
		goto done;
	}

	while (v12n_ldma_cv_state == V12N_LDMA_MSGWAITING) {
		if ((err = cond_reltimedwait(&v12n_ldma_cv,
		    &v12n_ldma_cv_lock, &timeout)) != EINTR)
			break;
	}

	if (v12n_ldma_cv_state != V12N_LDMA_MSGRECEIVED) {
		if (err == 0)
			err = EPROTO;
		(void) mutex_unlock(&v12n_ldma_cv_lock);
		goto done;
	}

	v12n_ldma_cv_state = V12N_LDMA_CVINVALID;
	(void) mutex_unlock(&v12n_ldma_cv_lock);

	/*
	 * If v12n_ldma_msgstr is set, a valid data response was seen.
	 */
	if (v12n_ldma_msgstr == NULL)
		err = ENODATA;
	else {
		if (*v12n_ldma_msgstr == '\0' ||
		    (*strp = strdup(v12n_ldma_msgstr)) == NULL)
			err = ENODATA;
		free(v12n_ldma_msgstr);
		v12n_ldma_msgstr = NULL;
	}

done:
	v12n_ds_unreg_svc(LDMA_NAME_SYSTEM, B_TRUE);
	v12n_ldma_msgtype = -1;
	v12n_ldma_ctrl_hdl = DS_INVALID_HDL;
	(void) mutex_unlock(&v12n_ldma_lock);

	return (err);
}

/*
 * Get the nodename of the control domain.  Returns the equivalent
 * of 'uname -n' on the control domain.
 *   This is obtained via the 'agent-system' domain service provided
 *   by ldmad.
 */
size_t
v12n_ctrl_domain(char *buf, size_t count)
{
	char *str;
	int err;
	size_t rv = (size_t)(-1);

	if (v12n_capabilities() != V12N_LDOMS_SUPPORTED) {
		errno = ENOTSUP;
	} else if ((err = v12n_get_ldma_system_msg(LDMA_MSGSYS_GET_SYSINFO,
	    &str)) != 0) {
		errno = err;
	} else {
		rv = v12n_string_copyout(buf, str, count);
	}
	return (rv);
}

/*
 * Get the Chassis serial number from the Control Domain.
 *   This is obtained via the 'agent-system' domain service provided
 *   by ldmad.
 */
size_t
v12n_chassis_serialno(char *buf, size_t count)
{
	char *str;
	int err;
	size_t rv = (size_t)(-1);

	if (v12n_capabilities() != V12N_LDOMS_SUPPORTED) {
		errno = ENOTSUP;
	} else if ((err = v12n_get_ldma_system_msg(LDMA_MSGSYS_GET_CHASSISNO,
	    &str)) != 0) {
		errno = err;
	} else {
		rv = v12n_string_copyout(buf, str, count);
	}
	return (rv);
}
