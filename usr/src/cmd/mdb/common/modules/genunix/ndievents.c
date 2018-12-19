/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include "ndievents.h"
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/dditypes.h>
#include <sys/ddi_impldefs.h>
#include <sys/sunddi.h>
#include <sys/param.h>


int
dip_to_pathname(struct dev_info *device, char *path, int buflen)
{
	char *bp;
	char *addr;
	char addr_str[32];
	char nodename[MAXNAMELEN];
	struct dev_info devi_parent;

	if (!device) {
		mdb_warn("Unable to access devinfo.");
		return (-1);
	}

	if (device->devi_parent == NULL) {
		if (mdb_readstr(nodename, sizeof (nodename),
		    (uintptr_t)device->devi_node_name) == -1) {
			return (-1);
		}

		if (sizeof (nodename) > (buflen - strlen(path))) {
			return (-1);
		}

		strncpy(path, nodename, sizeof (nodename));
		return (0);
	}

	if (mdb_vread(&devi_parent, sizeof (struct dev_info),
	    (uintptr_t)device->devi_parent) == -1) {
		mdb_warn("Unable to access devi_parent at %p",
		    (uintptr_t)device->devi_parent);
		return (-1);
	}

	if (dip_to_pathname(&devi_parent, path, buflen) == -1) {
		return (-1);
	}

	if (mdb_readstr(nodename, sizeof (nodename),
	    (uintptr_t)device->devi_node_name) == -1) {
		return (-1);
	}

	if (device->devi_node_state < DS_INITIALIZED) {
		addr_str[0] = '\0';
	} else {
		addr = device->devi_addr;
		if (mdb_readstr(addr_str, sizeof (addr_str),
		    (uintptr_t)addr) == -1) {
			return (-1);
		}
	}

	bp = path + strlen(path);

	if (addr_str[0] == '\0') {
		(void) mdb_snprintf(bp, buflen - strlen(path), "/%s", nodename);
	} else {
		(void) mdb_snprintf(bp, buflen - strlen(path), "/%s@%s",
		    nodename, addr_str);
	}
	return (0);

}

/*ARGSUSED*/
int
ndi_callback_print(struct ndi_event_cookie *cookie, uint_t flags)
{

	struct ndi_event_callbacks *callback_list;
	struct ndi_event_callbacks cb;
	char device_path[MAXPATHLEN];
	struct dev_info devi;

	if (!cookie) {
		return (DCMD_ERR);
	}

	callback_list = cookie->callback_list;

	while (callback_list != NULL) {
		if (mdb_vread(&cb, sizeof (struct ndi_event_callbacks),
		    (uintptr_t)callback_list) == -1) {
			mdb_warn("Could not read callback structure at"
			    " %p", callback_list);
			return (DCMD_ERR);
		}

		if (mdb_vread(&devi, sizeof (struct dev_info),
		    (uintptr_t)cb.ndi_evtcb_dip) == -1) {
			mdb_warn("Could not read devinfo structure at"
			    " %p", cb.ndi_evtcb_dip);
			return (DCMD_ERR);
		}

		if (dip_to_pathname(&devi, device_path, sizeof (device_path))
		    == -1) {
			return (DCMD_ERR);
		}

		mdb_printf("\t\tCallback Registered By: %s\n", device_path);
		mdb_printf("\t\t  Callback Address:\t%-?p\n"
		    "\t\t  Callback Function:\t%-p\n"
		    "\t\t  Callback Args:\t%-?p\n"
		    "\t\t  Callback Cookie:\t%-?p\n",
		    callback_list, cb.ndi_evtcb_callback, cb.ndi_evtcb_arg,
		    cb.ndi_evtcb_cookie);

		callback_list = cb.ndi_evtcb_next;

	}

	return (DCMD_OK);
}

int
ndi_event_print(struct ndi_event_hdl *hdl, uint_t flags)
{

	struct	ndi_event_definition def;
	struct	ndi_event_cookie cookie;
	struct	ndi_event_cookie *cookie_list;
	char	ndi_event_name[256];

	if (!hdl)
		return (DCMD_ERR);

	cookie_list = hdl->ndi_evthdl_cookie_list;
	if (cookie_list == NULL) {
		mdb_printf("\tNo cookies defined for this handle.\n");
		return (DCMD_OK);
	}

	while (cookie_list != NULL) {
		if (mdb_vread(&cookie, sizeof (struct ndi_event_cookie),
		    (uintptr_t)cookie_list) == -1) {
			mdb_warn("Unable to access cookie list");
			return (DCMD_ERR);
		}

		if (mdb_vread(&def, sizeof (struct ndi_event_definition),
		    (uintptr_t)cookie.definition) == -1) {
			mdb_warn("Unable to access definition at %p",
			    cookie.definition);
			return (DCMD_ERR);
		}

		if (mdb_readstr(ndi_event_name, sizeof (ndi_event_name),
		    (uintptr_t)def.ndi_event_name) == -1) {
			mdb_warn("Unable to read cookie name.");
			return (DCMD_ERR);
		}

		mdb_printf("\tCookie(%s %p) :Plevel(%d)\n\tddip(%p)"
		    " : Attr(%d)\n",
		    ndi_event_name, cookie_list, def.ndi_event_plevel,
		    cookie.ddip, def.ndi_event_attributes);

		ndi_callback_print(&cookie, flags);
		cookie_list = cookie.next_cookie;

	}
	return (0);
}

/*ARGSUSED*/
int
ndi_event_hdl(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{

	struct dev_info devi;
	struct ndi_event_hdl handle;
	char path[MAXPATHLEN];
	int done;

	if (!(flags & DCMD_ADDRSPEC)) {
		return (DCMD_USAGE);
	}

	if (mdb_vread(&handle, sizeof (struct ndi_event_hdl), addr) == -1) {
		mdb_warn("failed to read ndi_event_hdl at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_vread(&devi, sizeof (struct dev_info),
	    (uintptr_t)handle.ndi_evthdl_dip) == -1) {
		mdb_warn("failed to read devinfo node at %p",
		    handle.ndi_evthdl_dip);
		return (DCMD_ERR);
	}

	if (dip_to_pathname(&devi, path, sizeof (path)) == -1) {
		return (DCMD_ERR);
	}

	done = 0;
	while (!done) {

		mdb_printf("%<b>Handle%</b> (%p) :%<b> Path%</b> (%s) : %<b>"
		    "dip %</b>(%p) \n", addr, path, handle.ndi_evthdl_dip);

		mdb_printf("mutexes:	handle(%p)	callback(%p)\n",
		    handle.ndi_evthdl_mutex, handle.ndi_evthdl_cb_mutex);

		ndi_event_print(&handle, flags);

		if (handle.ndi_next_hdl == NULL) {
			done = 1;
		} else {
			addr = (uintptr_t)handle.ndi_next_hdl;
			if (mdb_vread(&handle, sizeof (struct ndi_event_hdl),
			    (uintptr_t)addr) == -1) {
				mdb_warn("failed to read ndi_event_hdl at %p",
				    addr);
				break;
			}

		}
	}

	return (0);
}
