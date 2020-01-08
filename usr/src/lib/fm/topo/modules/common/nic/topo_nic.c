/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2017, Joyent, Inc.
 * Copyright 2020 Robert Mustacchi
 */

/*
 * This module covers enumerating properties of physical NICs. At this time, as
 * various devices are discovered that may relate to various networking gear, we
 * will attempt to enumerate ports and transceivers under them, if requested.
 */

#include <strings.h>
#include <libdevinfo.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libdlstat.h>
#include <libsff.h>
#include <unistd.h>
#include <sys/dld_ioc.h>
#include <sys/dld.h>
#include <sys/mac.h>

#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_list.h>
#include <fm/topo_method.h>

#include <topo_port.h>
#include <topo_transceiver.h>

#include "topo_nic.h"

typedef enum {
	NIC_PORT_UNKNOWN,
	NIC_PORT_SFF
} nic_port_type_t;

static const topo_pgroup_info_t datalink_pgroup = {
	TOPO_PGROUP_DATALINK,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

typedef struct nic_port_mac {
	char npm_mac[ETHERADDRSTRL];
	boolean_t npm_valid;
	topo_mod_t *npm_mod;
} nic_port_mac_t;

/*
 * The first MAC address is always the primary MAC address, so we only worry
 * about the first. Thus this function always returns B_FALSE, to terminate
 * iteration.
 */
static boolean_t
nic_port_datalink_mac_cb(void *arg, dladm_macaddr_attr_t *attr)
{
	nic_port_mac_t *mac = arg;

	if (attr->ma_addrlen != ETHERADDRL) {
		topo_mod_dprintf(mac->npm_mod,
		    "found address with bad length: %u\n", attr->ma_addrlen);
		return (B_FALSE);
	}

	(void) snprintf(mac->npm_mac, sizeof (mac->npm_mac),
	    "%02x:%02x:%02x:%02x:%02x:%02x",
	    attr->ma_addr[0], attr->ma_addr[1], attr->ma_addr[2],
	    attr->ma_addr[3], attr->ma_addr[4], attr->ma_addr[5]);
	mac->npm_valid = B_TRUE;
	return (B_FALSE);
}

static int
nic_port_datalink_props(topo_mod_t *mod, tnode_t *port, dladm_handle_t handle,
    datalink_id_t linkid)
{
	int err;
	dladm_status_t status;
	uint64_t ifspeed;
	link_duplex_t duplex;
	link_state_t state;
	const char *duplex_str, *state_str;
	datalink_class_t dlclass;
	uint32_t media;
	char dlname[MAXLINKNAMELEN * 2];
	char dlerr[DLADM_STRSIZE];
	nic_port_mac_t mac;

	status = dladm_datalink_id2info(handle, linkid, NULL, &dlclass, &media,
	    dlname, sizeof (dlname));
	if (status != DLADM_STATUS_OK) {
		topo_mod_dprintf(mod, "failed to get link info: %s\n",
		    dladm_status2str(status, dlerr));
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	if (dlclass != DATALINK_CLASS_PHYS) {
		return (0);
	}

	status = dladm_get_single_mac_stat(handle, linkid, "ifspeed",
	    KSTAT_DATA_UINT64, &ifspeed);
	if (status != DLADM_STATUS_OK) {
		topo_mod_dprintf(mod, "failed to get ifspeed: %s\n",
		    dladm_status2str(status, dlerr));
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	status = dladm_get_single_mac_stat(handle, linkid, "link_duplex",
	    KSTAT_DATA_UINT32, &duplex);
	if (status != DLADM_STATUS_OK) {
		topo_mod_dprintf(mod, "failed to get link_duplex: %s\n",
		    dladm_status2str(status, dlerr));
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	switch (duplex) {
	case LINK_DUPLEX_HALF:
		duplex_str = TOPO_PGROUP_DATALINK_LINK_DUPLEX_HALF;
		break;
	case LINK_DUPLEX_FULL:
		duplex_str = TOPO_PGROUP_DATALINK_LINK_DUPLEX_FULL;
		break;
	default:
		duplex_str = TOPO_PGROUP_DATALINK_LINK_DUPLEX_UNKNOWN;
		break;
	}

	status = dladm_get_single_mac_stat(handle, linkid, "link_state",
	    KSTAT_DATA_UINT32, &state);
	if (status != DLADM_STATUS_OK) {
		topo_mod_dprintf(mod, "failed to get link_duplex: %s\n",
		    dladm_status2str(status, dlerr));
		return (topo_mod_seterrno(mod, status));
	}

	switch (state) {
	case LINK_STATE_UP:
		state_str = TOPO_PGROUP_DATALINK_LINK_STATUS_UP;
		break;
	case LINK_STATE_DOWN:
		state_str = TOPO_PGROUP_DATALINK_LINK_STATUS_DOWN;
		break;
	default:
		state_str = TOPO_PGROUP_DATALINK_LINK_STATUS_UNKNOWN;
		break;
	}

	/*
	 * Override the duplex if the link is down. Some devices will leave it
	 * set at half as opposed to unknown.
	 */
	if (state == LINK_STATE_DOWN || state == LINK_STATE_UNKNOWN) {
		duplex_str = TOPO_PGROUP_DATALINK_LINK_DUPLEX_UNKNOWN;
	}

	mac.npm_mac[0] = '\0';
	mac.npm_valid = B_FALSE;
	mac.npm_mod = mod;
	if (media == DL_ETHER) {
		(void) dladm_walk_macaddr(handle, linkid, &mac,
		    nic_port_datalink_mac_cb);
	}

	if (topo_pgroup_create(port, &datalink_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "falied to create property group %s: "
		    "%s\n", TOPO_PGROUP_DATALINK, topo_strerror(err));
		return (topo_mod_seterrno(mod, err));
	}

	if (topo_prop_set_uint64(port, TOPO_PGROUP_DATALINK,
	    TOPO_PGROUP_DATALINK_LINK_SPEED, TOPO_PROP_IMMUTABLE, ifspeed,
	    &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s property: %s\n",
		    TOPO_PGROUP_DATALINK_LINK_SPEED, topo_strerror(err));
		return (topo_mod_seterrno(mod, err));
	}

	if (topo_prop_set_string(port, TOPO_PGROUP_DATALINK,
	    TOPO_PGROUP_DATALINK_LINK_DUPLEX, TOPO_PROP_IMMUTABLE, duplex_str,
	    &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s property: %s\n",
		    TOPO_PGROUP_DATALINK_LINK_DUPLEX, topo_strerror(err));
		return (topo_mod_seterrno(mod, err));
	}

	if (topo_prop_set_string(port, TOPO_PGROUP_DATALINK,
	    TOPO_PGROUP_DATALINK_LINK_STATUS, TOPO_PROP_IMMUTABLE, state_str,
	    &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s property: %s\n",
		    TOPO_PGROUP_DATALINK_LINK_STATUS, topo_strerror(err));
		return (topo_mod_seterrno(mod, err));
	}

	if (topo_prop_set_string(port, TOPO_PGROUP_DATALINK,
	    TOPO_PGROUP_DATALINK_LINK_NAME, TOPO_PROP_IMMUTABLE, dlname,
	    &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s propery: %s\n",
		    TOPO_PGROUP_DATALINK_LINK_NAME, topo_strerror(err));
		return (topo_mod_seterrno(mod, err));
	}

	if (mac.npm_valid) {
		if (topo_prop_set_string(port, TOPO_PGROUP_DATALINK,
		    TOPO_PGROUP_DATALINK_PMAC, TOPO_PROP_IMMUTABLE,
		    mac.npm_mac, &err) != 0) {
			topo_mod_dprintf(mod, "failed to set %s propery: %s\n",
			    TOPO_PGROUP_DATALINK_PMAC, topo_strerror(err));
			return (topo_mod_seterrno(mod, err));
		}
	}


	return (0);
}

/*
 * Create an instance of a transceiver with the specified id. We must create
 * both its port and the transceiver node.
 */
static int
nic_create_transceiver(topo_mod_t *mod, tnode_t *pnode, dladm_handle_t handle,
    datalink_id_t linkid, uint_t tranid, nic_port_type_t port_type)
{
	int ret;
	tnode_t *port;
	dld_ioc_gettran_t dgt;
	dld_ioc_tranio_t dti;
	uint8_t buf[256];
	char ouibuf[16];
	char *vendor = NULL, *part = NULL, *rev = NULL, *serial = NULL;
	nvlist_t *nvl = NULL;

	switch (port_type) {
	case NIC_PORT_UNKNOWN:
		ret = port_create_unknown(mod, pnode, tranid, &port);
		break;
	case NIC_PORT_SFF:
		ret = port_create_sff(mod, pnode, tranid, &port);
		break;
	}

	if ((ret = nic_port_datalink_props(mod, port, handle, linkid)) != 0)
		return (ret);

	if (port_type != NIC_PORT_SFF)
		return (0);

	bzero(&dgt, sizeof (dgt));
	dgt.dgt_linkid = linkid;
	dgt.dgt_tran_id = tranid;

	if (ioctl(dladm_dld_fd(handle), DLDIOC_GETTRAN, &dgt) != 0) {
		if (errno == ENOTSUP)
			return (0);
		return (-1);
	}

	if (dgt.dgt_present == 0)
		return (0);

	bzero(&dti, sizeof (dti));
	dti.dti_linkid = linkid;
	dti.dti_tran_id = tranid;
	dti.dti_page = 0xa0;
	dti.dti_nbytes = sizeof (buf);
	dti.dti_buf = (uintptr_t)buf;

	if (ioctl(dladm_dld_fd(handle), DLDIOC_READTRAN, &dti) == 0) {
		uchar_t *oui;
		uint_t nbyte;

		if (libsff_parse(buf, dti.dti_nbytes, dti.dti_page,
		    &nvl) == 0) {
			if ((ret = nvlist_lookup_string(nvl, LIBSFF_KEY_VENDOR,
			    &vendor)) != 0 && nvlist_lookup_byte_array(nvl,
			    LIBSFF_KEY_OUI, &oui, &nbyte) == 0 && nbyte == 3) {
				if (snprintf(ouibuf, sizeof (ouibuf),
				    "%02x:%02x:%02x", oui[0], oui[1], oui[2]) <
				    sizeof (ouibuf)) {
					vendor = ouibuf;
				}
			} else if (ret != 0) {
				vendor = NULL;
			}

			if (nvlist_lookup_string(nvl, LIBSFF_KEY_PART,
			    &part) != 0) {
				part = NULL;
			}

			if (nvlist_lookup_string(nvl, LIBSFF_KEY_REVISION,
			    &rev) != 0) {
				rev = NULL;
			}

			if (nvlist_lookup_string(nvl, LIBSFF_KEY_SERIAL,
			    &serial) != 0) {
				serial = NULL;
			}
		}
	}

	if (transceiver_range_create(mod, port, 0, 0) != 0) {
		nvlist_free(nvl);
		return (-1);
	}

	if (transceiver_create_sff(mod, port, 0, dgt.dgt_usable, vendor, part,
	    rev, serial, NULL) != 0) {
		nvlist_free(nvl);
		return (-1);
	}

	nvlist_free(nvl);
	return (0);
}

/* ARGSUSED */
static int
nic_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *modarg, void *data)
{
	di_node_t din = data;
	datalink_id_t linkid;
	dladm_handle_t handle;
	dld_ioc_gettran_t dgt;
	uint_t ntrans, i;
	char dname[MAXNAMELEN];
	nic_port_type_t pt;

	if (strcmp(name, NIC) != 0) {
		topo_mod_dprintf(mod, "nic_enum: asked to enumerate unknown "
		    "component: %s\n", name);
		return (-1);
	}

	if (din == NULL) {
		topo_mod_dprintf(mod, "nic_enum: missing data argument\n");
		return (-1);
	}

	if ((handle = topo_mod_getspecific(mod)) == NULL) {
		topo_mod_dprintf(mod, "nic_enum: failed to get nic module "
		    "specific data\n");
		return (-1);
	}

	if (snprintf(dname, sizeof (dname), "%s%d", di_driver_name(din),
	    di_instance(din)) >= sizeof (dname)) {
		topo_mod_dprintf(mod, "nic_enum: device name overflowed "
		    "internal buffer\n");
		return (-1);
	}

	if (dladm_dev2linkid(handle, dname, &linkid) != DLADM_STATUS_OK)
		return (-1);

	bzero(&dgt, sizeof (dgt));
	dgt.dgt_linkid = linkid;
	dgt.dgt_tran_id = DLDIOC_GETTRAN_GETNTRAN;

	if (ioctl(dladm_dld_fd(handle), DLDIOC_GETTRAN, &dgt) != 0) {
		if (errno != ENOTSUP) {
			return (-1);
		}
		pt = NIC_PORT_UNKNOWN;
		dgt.dgt_tran_id = 1;
	} else {
		pt = NIC_PORT_SFF;
	}

	ntrans = dgt.dgt_tran_id;
	if (ntrans == 0)
		return (0);

	if (port_range_create(mod, pnode, 0, ntrans - 1) != 0)
		return (-1);

	for (i = 0; i < ntrans; i++) {
		if (nic_create_transceiver(mod, pnode, handle, linkid, i,
		    pt) != 0) {
			return (-1);
		}
	}

	return (0);
}

static const topo_modops_t nic_ops = {
	nic_enum, NULL
};

static topo_modinfo_t nic_mod = {
	NIC, FM_FMRI_SCHEME_HC, NIC_VERSION, &nic_ops
};

int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	dladm_handle_t handle;

	if (getenv("TOPONICDEBUG") != NULL)
		topo_mod_setdebug(mod);

	topo_mod_dprintf(mod, "_mod_init: "
	    "initializing %s enumerator\n", NIC);

	if (version != NIC_VERSION) {
		return (-1);
	}

	if (dladm_open(&handle) != 0)
		return (-1);

	if (topo_mod_register(mod, &nic_mod, TOPO_VERSION) != 0) {
		dladm_close(handle);
		return (-1);
	}

	topo_mod_setspecific(mod, handle);

	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
	dladm_handle_t handle;

	if ((handle = topo_mod_getspecific(mod)) == NULL)
		return;

	dladm_close(handle);
	topo_mod_setspecific(mod, NULL);
}
