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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/sysevent.h>
#include <sys/sysevent_impl.h>
#include <libsysevent.h>
#include <libsysevent_impl.h>
#include "../genunix/sysevent.h"

int
sysevent(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if ((flags & DCMD_LOOP) == 0) {
		if (mdb_pwalk_dcmd("sysevent", "sysevent", argc, argv,
		    addr) == -1) {
			mdb_warn("can't walk sysevent queue");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	return (sysevent_buf(addr, flags, 0));
}

/*ARGSUSED*/
int
sysevent_handle(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	ssize_t channel_name_sz;
	char channel_name[CLASS_LIST_FIELD_MAX];
	subscriber_priv_t sub;
	sysevent_impl_hdl_t sysevent_hdl;

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);


	if (argc != 0)
		return (DCMD_USAGE);


	if (mdb_vread(&sysevent_hdl, sizeof (sysevent_hdl),
	    (uintptr_t)addr) == -1) {
		mdb_warn("failed to read sysevent handle at %p", addr);
		return (DCMD_ERR);
	}
	if ((channel_name_sz = mdb_readstr(channel_name, CLASS_LIST_FIELD_MAX,
	    (uintptr_t)sysevent_hdl.sh_channel_name)) == -1) {
		mdb_warn("failed to read channel name at %p",
		    sysevent_hdl.sh_channel_name);
		return (DCMD_ERR);
	}
	if (channel_name_sz >= CLASS_LIST_FIELD_MAX - 1)
		(void) strcpy(&channel_name[CLASS_LIST_FIELD_MAX - 4], "...");

	if (sysevent_hdl.sh_type == SUBSCRIBER) {
		if (mdb_vread(&sub, sizeof (sub),
		    (uintptr_t)sysevent_hdl.sh_priv_data) == -1) {
			mdb_warn("failed to read sysevent handle at %p", addr);
			return (DCMD_ERR);
		}

		if (DCMD_HDRSPEC(flags))
			mdb_printf("%<u>%-?s %-24s %-13s %-5s %-?s"
			    "%</u>\n", "ADDR", "NAME", "TYPE", "ID",
			    "EVENT QUEUE ADDR");

		mdb_printf("%-?p %-24s %-13s %-5lu %-?p\n",
		    addr, channel_name, "SUBSCRIBER", sysevent_hdl.sh_id,
		    (uintptr_t)sub.sp_evq_head);

	} else {
		if (DCMD_HDRSPEC(flags))
			mdb_printf("%<u>%-?s %-24s %-13s %-5s %-?s"
			    "%</u>\n", "ADDR", "NAME",
			    "TYPE", "ID", "CLASS LIST ADDR");

		mdb_printf("%-?p %-24s %-13s %-5lu %-?p\n",
		    addr, channel_name, "PUBLISHER", sysevent_hdl.sh_id,
		    (uintptr_t)sysevent_hdl.sh_priv_data +
		    offsetof(publisher_priv_t, pp_class_hash));
	}

	return (DCMD_OK);
}

static const mdb_dcmd_t dcmds[] = {
	{ "sysevent", "?[-v]", "print the contents of a sysevent queue",
		sysevent},
	{ "sysevent_handle", ":", "print sysevent subscriber/publisher handle",
		sysevent_handle},
	{ "sysevent_class_list", ":", "print sysevent class list",
		sysevent_class_list },
	{ "sysevent_subclass_list", ":", "print sysevent subclass list",
		sysevent_subclass_list },
	{ NULL }
};

int
sysevent_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("sysevent does not support global walks");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
sysevent_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	sysevent_queue_t se_q;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&se_q, sizeof (se_q), wsp->walk_addr) == -1) {
		mdb_warn("failed to read sysevent queue at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback((uintptr_t)se_q.sq_ev, NULL,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)se_q.sq_next;

	return (status);
}

static const mdb_walker_t walkers[] = {
	{ "sysevent", "walk sysevent buffer queue",
		sysevent_walk_init, sysevent_walk_step,
		NULL },
	{ "sysevent_class_list", "walk sysevent subsccription class list",
		sysevent_class_list_walk_init, sysevent_class_list_walk_step,
		sysevent_class_list_walk_fini },
	{ "sysevent_subclass_list", "walk sysevent subsccription subclass list",
		sysevent_subclass_list_walk_init,
		sysevent_subclass_list_walk_step, NULL },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
