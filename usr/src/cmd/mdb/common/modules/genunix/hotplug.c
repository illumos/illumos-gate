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

#include <sys/mdb_modapi.h>
#include <sys/proc.h>
#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/ddi_hp.h>
#include "devinfo.h"

static char *
ddihp_get_cn_state(ddi_hp_cn_state_t state)
{
	switch (state) {
	case DDI_HP_CN_STATE_EMPTY:
		return ("Empty");
	case DDI_HP_CN_STATE_PRESENT:
		return ("Present");
	case DDI_HP_CN_STATE_POWERED:
		return ("Powered");
	case DDI_HP_CN_STATE_ENABLED:
		return ("Enabled");
	case DDI_HP_CN_STATE_PORT_EMPTY:
		return ("Port_Empty");
	case DDI_HP_CN_STATE_PORT_PRESENT:
		return ("Port_Present");
	case DDI_HP_CN_STATE_OFFLINE:
		return ("Offline");
	case DDI_HP_CN_STATE_ATTACHED:
		return ("Attached");
	case DDI_HP_CN_STATE_MAINTENANCE:
		return ("Maintenance");
	case DDI_HP_CN_STATE_ONLINE:
		return ("Online");
	default:
		return ("Unknown");
	}
}

/*ARGSUSED*/
static int
hotplug_print(uintptr_t addr, struct dev_info *dev, devinfo_cb_data_t *data)
{
	ddi_hp_cn_handle_t	hdl;
	uintptr_t		hdlp = (uintptr_t)dev->devi_hp_hdlp;
	char			cn_type[15];
	char			cn_name[15];

	while (hdlp) {
		if (mdb_vread(&hdl, sizeof (ddi_hp_cn_handle_t), hdlp) == -1) {
			mdb_warn("Failed to read hdlp!\n");
			return (DCMD_ERR);
		}

		if (!(data->di_flags & DEVINFO_HP_PHYSICAL) ||
		    hdl.cn_info.cn_type != DDI_HP_CN_TYPE_VIRTUAL_PORT) {
			if (mdb_readstr(cn_type, sizeof (cn_type),
			    (uintptr_t)hdl.cn_info.cn_type_str) == -1) {
				mdb_warn("Failed to read cn_type!\n");
				return (DCMD_ERR);
			}
			if (mdb_readstr(cn_name, sizeof (cn_name),
			    (uintptr_t)hdl.cn_info.cn_name) == -1) {
				mdb_warn("Failed to read cn_name!\n");
				return (DCMD_ERR);
			}
			mdb_printf("%?p %?p %-12s %-15s %-15s\n", hdl.cn_dip,
			    hdlp, ddihp_get_cn_state(hdl.cn_info.cn_state),
			    cn_type, cn_name);
		}
		hdlp = (uintptr_t)hdl.next;
	};

	return (WALK_NEXT);
}

void
hotplug_help(void)
{
	mdb_printf("Switches:\n"
	    "  -p   only print the physical hotplug connectors\n");
}

int
hotplug(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	devinfo_cb_data_t data;
	uintptr_t devinfo_root;		/* Address of root of devinfo tree */
	ddi_hp_cn_handle_t	hdl;
	char			cn_type[15];
	char			cn_name[15];
	int status;

	data.di_flags = 0;
	data.di_filter = NULL;
	if (mdb_getopts(argc, argv,
	    'p', MDB_OPT_SETBITS, DEVINFO_HP_PHYSICAL, &data.di_flags, NULL)
	    != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s %?s %-12s %-15s %-15s%</u>\n",
		    "PARENT_DEVINFO", "HANDLE", "STATE", "TYPE", "CN_NAME");
	}

	if ((flags & DCMD_ADDRSPEC) == 0) {
		data.di_flags |= DEVINFO_PARENT | DEVINFO_CHILD;

		if (mdb_readvar(&devinfo_root, "top_devinfo") == -1) {
			mdb_warn("failed to read 'top_devinfo'");
			return (0);
		}

		data.di_base = devinfo_root;
		status = mdb_pwalk("devinfo", (mdb_walk_cb_t)hotplug_print,
		    &data, devinfo_root);
		if (status == -1) {
			mdb_warn("couldn't walk devinfo tree");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&hdl, sizeof (ddi_hp_cn_handle_t), (uintptr_t)addr)
	    == -1) {
		mdb_warn("Failed to read hdlp!\n");
		return (DCMD_ERR);
	}
	if (mdb_readstr(cn_type, sizeof (cn_type),
	    (uintptr_t)hdl.cn_info.cn_type_str) == -1) {
		mdb_warn("Failed to read cn_type!\n");
		return (DCMD_ERR);
	}
	if (mdb_readstr(cn_name, sizeof (cn_name),
	    (uintptr_t)hdl.cn_info.cn_name) == -1) {
		mdb_warn("Failed to read cn_name!\n");
		return (DCMD_ERR);
	}
	mdb_printf("%?p %?p %-12s %-15s %-15s\n", hdl.cn_dip, addr,
	    ddihp_get_cn_state(hdl.cn_info.cn_state), cn_type, cn_name);

	return (DCMD_OK);
}
