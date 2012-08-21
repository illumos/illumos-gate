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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/varargs.h>
#include <sys/vlan.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>	/* LIFNAMSIZ */
#include <netinet/vrrp.h>
#include <libdladm.h>
#include <libdlvnic.h>
#include <libdlvlan.h>
#include <libdllink.h>
#include <libintl.h>
#include <libscf.h>
#include <libvrrpadm.h>

#define	VRRP_SERVICE	"network/vrrp:default"

typedef vrrp_err_t vrrp_cmd_func_t(int, void *);

static boolean_t
vrrp_svc_isonline(char *svc_name)
{
	char		*s;
	boolean_t	isonline = B_FALSE;

	if ((s = smf_get_state(svc_name)) != NULL) {
		if (strcmp(s, SCF_STATE_STRING_ONLINE) == 0)
			isonline = B_TRUE;
		free(s);
	}

	return (isonline);
}

#define	MAX_WAIT_TIME	15

static vrrp_err_t
vrrp_enable_service()
{
	int	i;

	if (vrrp_svc_isonline(VRRP_SERVICE))
		return (VRRP_SUCCESS);

	if (smf_enable_instance(VRRP_SERVICE, 0) == -1) {
		if (scf_error() == SCF_ERROR_PERMISSION_DENIED)
			return (VRRP_EPERM);
		else
			return (VRRP_ENOSVC);
	}

	/*
	 * Wait up to MAX_WAIT_TIME seconds for the VRRP service being brought
	 * up online
	 */
	for (i = 0; i < MAX_WAIT_TIME; i++) {
		if (vrrp_svc_isonline(VRRP_SERVICE))
			break;
		(void) sleep(1);
	}
	if (i == MAX_WAIT_TIME)
		return (VRRP_ENOSVC);

	return (VRRP_SUCCESS);
}

/*
 * Disable the VRRP service if there is no VRRP router left.
 */
static void
vrrp_disable_service_when_no_router()
{
	uint32_t	cnt = 0;

	/*
	 * Get the number of the existing routers. If there is no routers
	 * left, disable the service.
	 */
	if (vrrp_list(NULL, VRRP_VRID_NONE, NULL, AF_UNSPEC, &cnt,
	    NULL) == VRRP_SUCCESS && cnt == 0) {
		(void) smf_disable_instance(VRRP_SERVICE, 0);
	}
}

static vrrp_err_t
vrrp_cmd_request(void *cmd, size_t csize, vrrp_cmd_func_t func, void *arg)
{
	struct sockaddr_un	to;
	int			sock, flags;
	size_t			len, cur_size = 0;
	vrrp_ret_t		ret;
	vrrp_err_t		err;

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return (VRRP_ESYS);

	/*
	 * Set it to be non-blocking.
	 */
	flags = fcntl(sock, F_GETFL, 0);
	(void) fcntl(sock, F_SETFL, (flags | O_NONBLOCK));

	(void) memset(&to, 0, sizeof (to));
	to.sun_family = AF_UNIX;
	(void) strlcpy(to.sun_path, VRRPD_SOCKET, sizeof (to.sun_path));

	/*
	 * Connect to vrrpd
	 */
	if (connect(sock, (const struct sockaddr *)&to, sizeof (to)) < 0) {
		(void) close(sock);
		return (VRRP_ENOSVC);
	}

	/*
	 * Send the request
	 */
	while (cur_size < csize) {
		len = write(sock, (char *)cmd + cur_size, csize - cur_size);
		if (len == (size_t)-1 && errno == EAGAIN) {
			continue;
		} else if (len > 0) {
			cur_size += len;
			continue;
		}
		(void) close(sock);
		return (VRRP_ENOSVC);
	}

	/*
	 * Expect the ack, first get the error code.
	 */
	cur_size = 0;
	while (cur_size < sizeof (vrrp_err_t)) {
		len = read(sock, (char *)&ret + cur_size,
		    sizeof (vrrp_err_t) - cur_size);

		if (len == (size_t)-1 && errno == EAGAIN) {
			continue;
		} else if (len > 0) {
			cur_size += len;
			continue;
		}
		(void) close(sock);
		return (VRRP_ESYS);
	}

	if ((err = ret.vr_err) != VRRP_SUCCESS)
		goto done;

	/*
	 * The specific callback gets the rest of the information.
	 */
	if (func != NULL)
		err = func(sock, arg);

done:
	(void) close(sock);
	return (err);
}

/*
 * public APIs
 */
const char *
vrrp_err2str(vrrp_err_t err)
{
	switch (err) {
	case VRRP_SUCCESS:
		return (dgettext(TEXT_DOMAIN, "success"));
	case VRRP_ENOMEM:
		return (dgettext(TEXT_DOMAIN, "not enough memory"));
	case VRRP_EINVALVRNAME:
		return (dgettext(TEXT_DOMAIN, "invalid router name"));
	case VRRP_ENOPRIM:
		return (dgettext(TEXT_DOMAIN, "no primary IP"));
	case VRRP_EEXIST:
		return (dgettext(TEXT_DOMAIN, "already exists"));
	case VRRP_ENOVIRT:
		return (dgettext(TEXT_DOMAIN, "no virtual IPs"));
	case VRRP_EIPADM:
		return (dgettext(TEXT_DOMAIN, "ip configuration failure"));
	case VRRP_EDLADM:
		return (dgettext(TEXT_DOMAIN, "data-link configuration "
		    "failure"));
	case VRRP_EDB:
		return (dgettext(TEXT_DOMAIN, "configuration update error"));
	case VRRP_EBADSTATE:
		return (dgettext(TEXT_DOMAIN, "invalid state"));
	case VRRP_EVREXIST:
		return (dgettext(TEXT_DOMAIN, "VRRP router already exists"));
	case VRRP_ETOOSMALL:
		return (dgettext(TEXT_DOMAIN, "not enough space"));
	case VRRP_EINSTEXIST:
		return (dgettext(TEXT_DOMAIN, "router name already exists"));
	case VRRP_ENOTFOUND:
		return (dgettext(TEXT_DOMAIN, "VRRP router not found"));
	case VRRP_EINVALADDR:
		return (dgettext(TEXT_DOMAIN, "invalid IP address"));
	case VRRP_EINVALAF:
		return (dgettext(TEXT_DOMAIN, "invalid IP address family"));
	case VRRP_EINVALLINK:
		return (dgettext(TEXT_DOMAIN, "invalid data-link"));
	case VRRP_EPERM:
		return (dgettext(TEXT_DOMAIN, "permission denied"));
	case VRRP_ESYS:
		return (dgettext(TEXT_DOMAIN, "system error"));
	case VRRP_EAGAIN:
		return (dgettext(TEXT_DOMAIN, "try again"));
	case VRRP_EALREADY:
		return (dgettext(TEXT_DOMAIN, "operation already in progress"));
	case VRRP_ENOVNIC:
		return (dgettext(TEXT_DOMAIN, "VRRP VNIC has not been "
		    "created"));
	case VRRP_ENOLINK:
		return (dgettext(TEXT_DOMAIN, "the data-link does not exist"));
	case VRRP_ENOSVC:
		return (dgettext(TEXT_DOMAIN, "the VRRP service cannot "
		    "be enabled"));
	case VRRP_EINVAL:
	default:
		return (dgettext(TEXT_DOMAIN, "invalid argument"));
	}
}

const char *
vrrp_state2str(vrrp_state_t state)
{
	switch (state) {
	case VRRP_STATE_NONE:
		return (dgettext(TEXT_DOMAIN, "NONE"));
	case VRRP_STATE_INIT:
		return (dgettext(TEXT_DOMAIN, "INIT"));
	case VRRP_STATE_MASTER:
		return (dgettext(TEXT_DOMAIN, "MASTER"));
	case VRRP_STATE_BACKUP:
		return (dgettext(TEXT_DOMAIN, "BACKUP"));
	default:
		return (dgettext(TEXT_DOMAIN, "INVALID"));
	}
}

vrrp_err_t
vrrp_open(vrrp_handle_t *vh)
{
	dladm_handle_t	dh;

	if (dladm_open(&dh) != DLADM_STATUS_OK)
		return (VRRP_EDLADM);

	if ((*vh = malloc(sizeof (struct vrrp_handle))) == NULL) {
		dladm_close(dh);
		return (VRRP_ENOMEM);
	}
	(*vh)->vh_dh = dh;
	return (VRRP_SUCCESS);
}

void
vrrp_close(vrrp_handle_t vh)
{
	if (vh != NULL) {
		dladm_close(vh->vh_dh);
		free(vh);
	}
}

boolean_t
vrrp_valid_name(const char *name)
{
	const char	*c;

	/*
	 * The legal characters in a valid router name are:
	 * alphanumeric (a-z,  A-Z,  0-9), underscore ('_'), and '.'.
	 */
	for (c = name; *c != '\0'; c++) {
		if ((isalnum(*c) == 0) && (*c != '_'))
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*ARGSUSED*/
vrrp_err_t
vrrp_create(vrrp_handle_t vh, vrrp_vr_conf_t *conf)
{
	vrrp_cmd_create_t	cmd;
	vrrp_err_t		err;

again:
	/*
	 * Enable the VRRP service if it is not already enabled.
	 */
	if ((err = vrrp_enable_service()) != VRRP_SUCCESS)
		return (err);

	cmd.vcc_cmd = VRRP_CMD_CREATE;
	(void) memcpy(&cmd.vcc_conf, conf, sizeof (vrrp_vr_conf_t));

	err = vrrp_cmd_request(&cmd, sizeof (cmd), NULL, NULL);
	if (err == VRRP_ENOSVC) {
		/*
		 * This may be due to another process is deleting the last
		 * router and disabled the VRRP service, try again.
		 */
		goto again;
	} else if (err != VRRP_SUCCESS) {
		/*
		 * If router cannot be created, check if the VRRP service
		 * should be disabled, and disable if needed.
		 */
		vrrp_disable_service_when_no_router();
	}

	return (err);
}

/*ARGSUSED*/
vrrp_err_t
vrrp_delete(vrrp_handle_t vh, const char *vn)
{
	vrrp_cmd_delete_t	cmd;
	vrrp_err_t		err;

	/*
	 * If the VRRP service is not enabled, we assume there is no router
	 * configured.
	 */
	if (!vrrp_svc_isonline(VRRP_SERVICE))
		return (VRRP_ENOTFOUND);

	cmd.vcd_cmd = VRRP_CMD_DELETE;
	if (strlcpy(cmd.vcd_name, vn, VRRP_NAME_MAX) >= VRRP_NAME_MAX)
		return (VRRP_EINVAL);

	err = vrrp_cmd_request(&cmd, sizeof (cmd), NULL, NULL);
	if (err == VRRP_SUCCESS)
		vrrp_disable_service_when_no_router();
	return (err);
}

/*ARGSUSED*/
vrrp_err_t
vrrp_enable(vrrp_handle_t vh, const char *vn)
{
	vrrp_cmd_enable_t	cmd;
	vrrp_err_t		err;

	/*
	 * If the VRRP service is not enabled, we assume there is no router
	 * configured.
	 */
	if (!vrrp_svc_isonline(VRRP_SERVICE))
		return (VRRP_ENOTFOUND);

	cmd.vcs_cmd = VRRP_CMD_ENABLE;
	if (strlcpy(cmd.vcs_name, vn, VRRP_NAME_MAX) >= VRRP_NAME_MAX)
		return (VRRP_EINVAL);

	err = vrrp_cmd_request(&cmd, sizeof (cmd), NULL, NULL);
	return (err);
}

/*ARGSUSED*/
vrrp_err_t
vrrp_disable(vrrp_handle_t vh, const char *vn)
{
	vrrp_cmd_disable_t	cmd;
	vrrp_err_t		err;

	/*
	 * If the VRRP service is not enabled, we assume there is no router
	 * configured.
	 */
	if (!vrrp_svc_isonline(VRRP_SERVICE))
		return (VRRP_ENOTFOUND);

	cmd.vcx_cmd = VRRP_CMD_DISABLE;
	if (strlcpy(cmd.vcx_name, vn, VRRP_NAME_MAX) >= VRRP_NAME_MAX)
		return (VRRP_EINVAL);

	err = vrrp_cmd_request(&cmd, sizeof (cmd), NULL, NULL);
	return (err);
}

/*ARGSUSED*/
vrrp_err_t
vrrp_modify(vrrp_handle_t vh, vrrp_vr_conf_t *conf, uint32_t mask)
{
	vrrp_cmd_modify_t	cmd;
	vrrp_err_t		err;

	/*
	 * If the VRRP service is not enabled, we assume there is no router
	 * configured.
	 */
	if (!vrrp_svc_isonline(VRRP_SERVICE))
		return (VRRP_ENOTFOUND);

	cmd.vcm_cmd = VRRP_CMD_MODIFY;
	cmd.vcm_mask = mask;
	(void) memcpy(&cmd.vcm_conf, conf, sizeof (vrrp_vr_conf_t));

	err = vrrp_cmd_request(&cmd, sizeof (cmd), NULL, NULL);
	return (err);
}

typedef struct vrrp_cmd_list_arg {
	uint32_t	*vfl_cnt;
	char		*vfl_names;
} vrrp_cmd_list_arg_t;

static vrrp_err_t
vrrp_list_func(int sock, void *arg)
{
	vrrp_cmd_list_arg_t	*list_arg = arg;
	uint32_t		in_cnt = *(list_arg->vfl_cnt);
	uint32_t		out_cnt;
	vrrp_ret_list_t		ret;
	size_t			len, cur_size = 0;

	/*
	 * Get the rest of vrrp_ret_list_t besides the error code.
	 */
	cur_size = sizeof (vrrp_err_t);
	while (cur_size < sizeof (vrrp_ret_list_t)) {
		len = read(sock, (char *)&ret + cur_size,
		    sizeof (vrrp_ret_list_t) - cur_size);

		if (len == (size_t)-1 && errno == EAGAIN) {
			continue;
		} else if (len > 0) {
			cur_size += len;
			continue;
		}
		return (VRRP_ESYS);
	}

	*(list_arg->vfl_cnt) = out_cnt = ret.vrl_cnt;
	out_cnt = (in_cnt <= out_cnt) ? in_cnt : out_cnt;
	cur_size = 0;

	while (cur_size < VRRP_NAME_MAX * out_cnt) {
		len = read(sock, (char *)list_arg->vfl_names + cur_size,
		    VRRP_NAME_MAX * out_cnt - cur_size);

		if (len == (size_t)-1 && errno == EAGAIN) {
			continue;
		} else if (len > 0) {
			cur_size += len;
			continue;
		}
		return (VRRP_ESYS);
	}
	return (VRRP_SUCCESS);
}

/*
 * Looks up the vrrp instances that matches the given variable.
 *
 * If the given cnt is 0, names should be set to NULL. In this case, only
 * the count of the matched instances is returned.
 *
 * If the given cnt is non-zero, caller must allocate "names" whose size
 * is (cnt * VRRP_NAME_MAX).
 *
 * Return value: the current count of matched instances, and names will be
 * points to the list of the current vrrp instances names. Note that
 * only MIN(in_cnt, out_cnt) number of names will be returned.
 */
/*ARGSUSED*/
vrrp_err_t
vrrp_list(vrrp_handle_t vh, vrid_t vrid, const char *intf, int af,
    uint32_t *cnt, char *names)
{
	vrrp_cmd_list_t		cmd;
	vrrp_err_t		err;
	vrrp_cmd_list_arg_t	list_arg;

	if ((cnt == NULL) || (*cnt != 0 && names == NULL))
		return (VRRP_EINVAL);

	cmd.vcl_ifname[0] = '\0';
	if (intf != NULL && (strlcpy(cmd.vcl_ifname, intf,
	    LIFNAMSIZ) >= LIFNAMSIZ)) {
		return (VRRP_EINVAL);
	}

	/*
	 * If the service is not online, we assume there is no router
	 * configured.
	 */
	if (!vrrp_svc_isonline(VRRP_SERVICE)) {
		*cnt = 0;
		return (VRRP_SUCCESS);
	}

	cmd.vcl_cmd = VRRP_CMD_LIST;
	cmd.vcl_vrid = vrid;
	cmd.vcl_af = af;

	list_arg.vfl_cnt = cnt;
	list_arg.vfl_names = names;

	err = vrrp_cmd_request(&cmd, sizeof (cmd), vrrp_list_func, &list_arg);
	return (err);
}

static vrrp_err_t
vrrp_query_func(int sock, void *arg)
{
	vrrp_queryinfo_t	*qinfo = arg;
	size_t			len, cur_size = 0, total;
	uint32_t		in_cnt = qinfo->show_va.va_vipcnt;
	uint32_t		out_cnt;

	/*
	 * Expect the ack, first get the vrrp_ret_t.
	 */
	total = sizeof (vrrp_queryinfo_t);
	while (cur_size < total) {
		len = read(sock, (char *)qinfo + cur_size, total - cur_size);
		if (len == (size_t)-1 && errno == EAGAIN) {
			continue;
		} else if (len > 0) {
			cur_size += len;
			continue;
		}
		return (VRRP_ESYS);
	}

	out_cnt = qinfo->show_va.va_vipcnt;

	/*
	 * Even if there is no IP virtual IP address, there is always
	 * space in the vrrp_queryinfo_t structure for one virtual
	 * IP address.
	 */
	out_cnt = (out_cnt == 0) ? 1 : out_cnt;
	out_cnt = (in_cnt < out_cnt ? in_cnt : out_cnt) - 1;
	total += out_cnt * sizeof (vrrp_addr_t);

	while (cur_size < total) {
		len = read(sock, (char *)qinfo + cur_size, total - cur_size);
		if (len == (size_t)-1 && errno == EAGAIN) {
			continue;
		} else if (len > 0) {
			cur_size += len;
			continue;
		}
		return (VRRP_ESYS);
	}
	return (VRRP_SUCCESS);
}

/*
 * *vqp is allocated inside this function and must be freed by the caller.
 */
/*ARGSUSED*/
vrrp_err_t
vrrp_query(vrrp_handle_t vh, const char *vn, vrrp_queryinfo_t **vqp)
{
	vrrp_cmd_query_t	cmd;
	vrrp_queryinfo_t	*qinfo;
	vrrp_err_t		err;
	size_t			size;
	uint32_t		vipcnt = 1;

	if (strlcpy(cmd.vcq_name, vn, VRRP_NAME_MAX) >= VRRP_NAME_MAX)
		return (VRRP_EINVAL);

	/*
	 * If the service is not online, we assume there is no router
	 * configured.
	 */
	if (!vrrp_svc_isonline(VRRP_SERVICE))
		return (VRRP_ENOTFOUND);

	cmd.vcq_cmd = VRRP_CMD_QUERY;

	/*
	 * Allocate enough room for virtual IPs.
	 */
again:
	size = sizeof (vrrp_queryinfo_t);
	size += (vipcnt == 0) ? 0 : (vipcnt - 1) * sizeof (vrrp_addr_t);
	if ((qinfo = malloc(size)) == NULL) {
		err = VRRP_ENOMEM;
		goto done;
	}

	qinfo->show_va.va_vipcnt = vipcnt;
	err = vrrp_cmd_request(&cmd, sizeof (cmd), vrrp_query_func, qinfo);
	if (err != VRRP_SUCCESS) {
		free(qinfo);
		goto done;
	}

	/*
	 * If the returned number of virtual IPs is greater than we expected,
	 * allocate more room and try again.
	 */
	if (qinfo->show_va.va_vipcnt > vipcnt) {
		vipcnt = qinfo->show_va.va_vipcnt;
		free(qinfo);
		goto again;
	}

	*vqp = qinfo;

done:
	return (err);
}

struct lookup_vnic_arg {
	vrid_t		lva_vrid;
	datalink_id_t	lva_linkid;
	int		lva_af;
	uint16_t	lva_vid;
	vrrp_handle_t	lva_vh;
	char		lva_vnic[MAXLINKNAMELEN];
};

/*
 * Is this a special VNIC interface created for VRRP? If so, return
 * the linkid the VNIC was created on, the VRRP ID and address family.
 */
boolean_t
vrrp_is_vrrp_vnic(vrrp_handle_t vh, datalink_id_t vnicid,
    datalink_id_t *linkidp, uint16_t *vidp, vrid_t *vridp, int *afp)
{
	dladm_vnic_attr_t	vattr;

	if (dladm_vnic_info(vh->vh_dh, vnicid, &vattr, DLADM_OPT_ACTIVE) !=
	    DLADM_STATUS_OK) {
		return (B_FALSE);
	}

	*vridp = vattr.va_vrid;
	*vidp = vattr.va_vid;
	*afp = vattr.va_af;
	*linkidp = vattr.va_link_id;
	return (vattr.va_vrid != VRRP_VRID_NONE);
}

static int
lookup_vnic(dladm_handle_t dh, datalink_id_t vnicid, void *arg)
{
	vrid_t			vrid;
	uint16_t		vid;
	datalink_id_t		linkid;
	int			af;
	struct lookup_vnic_arg	*lva = arg;

	if (vrrp_is_vrrp_vnic(lva->lva_vh, vnicid, &linkid, &vid, &vrid,
	    &af) && lva->lva_vrid == vrid && lva->lva_linkid == linkid &&
	    (lva->lva_vid == VLAN_ID_NONE || lva->lva_vid == vid) &&
	    lva->lva_af == af) {
		if (dladm_datalink_id2info(dh, vnicid, NULL, NULL, NULL,
		    lva->lva_vnic, sizeof (lva->lva_vnic)) == DLADM_STATUS_OK) {
			return (DLADM_WALK_TERMINATE);
		}
	}
	return (DLADM_WALK_CONTINUE);
}

/*
 * Given the primary link name, find the assoicated VRRP vnic name, if
 * the vnic does not exist yet, return the linkid, vid of the primary link.
 */
vrrp_err_t
vrrp_get_vnicname(vrrp_handle_t vh, vrid_t vrid, int af, char *link,
    datalink_id_t *linkidp, uint16_t *vidp, char *vnic, size_t len)
{
	datalink_id_t		linkid;
	uint32_t		flags;
	uint16_t		vid = VLAN_ID_NONE;
	datalink_class_t	class;
	dladm_vlan_attr_t	vlan_attr;
	dladm_vnic_attr_t	vnic_attr;
	struct lookup_vnic_arg	lva;
	uint32_t		media;

	if ((strlen(link) == 0) || dladm_name2info(vh->vh_dh,
	    link, &linkid, &flags, &class, &media) !=
	    DLADM_STATUS_OK || !(flags & DLADM_OPT_ACTIVE)) {
		return (VRRP_EINVAL);
	}

	if (class == DATALINK_CLASS_VLAN) {
		if (dladm_vlan_info(vh->vh_dh, linkid, &vlan_attr,
		    DLADM_OPT_ACTIVE) != DLADM_STATUS_OK) {
			return (VRRP_EINVAL);
		}
		linkid = vlan_attr.dv_linkid;
		vid = vlan_attr.dv_vid;
		if ((dladm_datalink_id2info(vh->vh_dh, linkid, NULL,
		    &class, &media, NULL, 0)) != DLADM_STATUS_OK) {
			return (VRRP_EINVAL);
		}
	}

	if (class == DATALINK_CLASS_VNIC) {
		if (dladm_vnic_info(vh->vh_dh, linkid, &vnic_attr,
		    DLADM_OPT_ACTIVE) != DLADM_STATUS_OK) {
			return (VRRP_EINVAL);
		}
		linkid = vnic_attr.va_link_id;
		vid = vnic_attr.va_vid;
	}

	/*
	 * Only VRRP over vnics, aggrs and physical ethernet links is supported
	 */
	if ((class != DATALINK_CLASS_PHYS && class != DATALINK_CLASS_AGGR &&
	    class != DATALINK_CLASS_VNIC) || media != DL_ETHER) {
		return (VRRP_EINVAL);
	}

	if (linkidp != NULL)
		*linkidp = linkid;
	if (vidp != NULL)
		*vidp = vid;

	/*
	 * Find the assoicated vnic with the given vrid/vid/af/linkid
	 */
	lva.lva_vrid = vrid;
	lva.lva_vid = vid;
	lva.lva_af = af;
	lva.lva_linkid = linkid;
	lva.lva_vh = vh;
	lva.lva_vnic[0] = '\0';

	(void) dladm_walk_datalink_id(lookup_vnic, vh->vh_dh, &lva,
	    DATALINK_CLASS_VNIC, DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
	if (strlen(lva.lva_vnic) != 0) {
		(void) strlcpy(vnic, lva.lva_vnic, len);
		return (VRRP_SUCCESS);
	}

	return (VRRP_ENOVNIC);
}
