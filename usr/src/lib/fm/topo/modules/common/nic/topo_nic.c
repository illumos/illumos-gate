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
#include <libsff.h>
#include <unistd.h>
#include <sys/dld_ioc.h>
#include <sys/dld.h>

#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_list.h>
#include <fm/topo_method.h>

#include <topo_port.h>
#include <topo_transceiver.h>

#include "topo_nic.h"

/*
 * Create an instance of a transceiver with the specified id. We must create
 * both its port and the transceiver node.
 */
static int
nic_create_transceiver(topo_mod_t *mod, tnode_t *pnode, dladm_handle_t handle,
    datalink_id_t linkid, uint_t tranid)
{
	int ret;
	tnode_t *port;
	dld_ioc_gettran_t dgt;
	dld_ioc_tranio_t dti;
	uint8_t buf[256];
	char ouibuf[16];
	char *vendor = NULL, *part = NULL, *rev = NULL, *serial = NULL;
	nvlist_t *nvl = NULL;

	if ((ret = port_create_sff(mod, pnode, tranid, &port)) != 0)
		return (ret);

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
		if (errno == ENOTSUP)
			return (0);
		return (-1);
	}

	ntrans = dgt.dgt_tran_id;
	if (ntrans == 0)
		return (0);

	if (port_range_create(mod, pnode, 0, ntrans - 1) != 0)
		return (-1);

	for (i = 0; i < ntrans; i++) {
		if (nic_create_transceiver(mod, pnode, handle, linkid, i) != 0)
			return (-1);
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
