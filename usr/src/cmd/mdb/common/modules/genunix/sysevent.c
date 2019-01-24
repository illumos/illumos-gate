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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "sysevent.h"

int
sysevent_buf(uintptr_t addr, uint_t flags, uint_t opt_flags)
{
	sysevent_hdr_t evh;
	sysevent_impl_t *ev;
	int size;

	if (DCMD_HDRSPEC(flags)) {
		if ((opt_flags & SYSEVENT_VERBOSE) == 0) {
			mdb_printf("%<u>%-?s %-16s %-9s %-10s "
			    "%-?s%</u>\n", "ADDRESS", "SEQUENCE ID",
			    "CLASS", "SUBCLASS", "NVPAIR BUF ADDR");
		}
	}

	/*
	 * Read in the sysevent buffer header first.  After extracting
	 * the size of the buffer, re-read the buffer in its entirety.
	 */
	if (mdb_vread(&evh, sizeof (sysevent_hdr_t), addr) == -1) {
		mdb_warn("failed to read event header at %p", addr);
		return (DCMD_ERR);
	}

	size = SE_SIZE((sysevent_impl_t *)&evh);
	ev = mdb_alloc(size, UM_SLEEP | UM_GC);

	if (mdb_vread(ev, size, addr) == -1) {
		mdb_warn("can not read sysevent at %p", addr);
		return (DCMD_ERR);
	}

	if ((opt_flags & SYSEVENT_VERBOSE) == 0) {
		char ev_class[CLASS_FIELD_MAX];
		char ev_subclass[SUBCLASS_FIELD_MAX];

		if (mdb_snprintf(ev_class, CLASS_FIELD_MAX, "%s",
		    SE_CLASS_NAME(ev)) >= CLASS_FIELD_MAX - 1)
			(void) strcpy(&ev_class[CLASS_FIELD_MAX - 4], "...");

		if (mdb_snprintf(ev_subclass, SUBCLASS_FIELD_MAX, "%s",
		    SE_SUBCLASS_NAME(ev)) >= SUBCLASS_FIELD_MAX - 1)
			(void) strcpy(&ev_subclass[SUBCLASS_FIELD_MAX - 4],
			    "...");

		mdb_printf("%-?p %-16llu %-9s %-10s %-?p%\n",
			addr, SE_SEQ(ev), ev_class, ev_subclass,
			addr + SE_ATTR_OFF(ev));
	} else {
		mdb_printf("%<b>Sequence ID\t : %llu%</b>\n", SE_SEQ(ev));
		mdb_printf("%16s : %s\n", "publisher", SE_PUB_NAME(ev));
		mdb_printf("%16s : %p\n", "event address", (caddr_t)addr);
		mdb_printf("%16s : %s\n", "class", SE_CLASS_NAME(ev));
		mdb_printf("%16s : %s\n", "subclass", SE_SUBCLASS_NAME(ev));
		mdb_printf("%16s : %llu\n", "time stamp", SE_TIME(ev));
		mdb_printf("%16s : %p\n", "nvpair buf addr",
		    addr + SE_ATTR_OFF(ev));
	}

	return (DCMD_OK);
}

int
sysevent_subclass_list(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	int subclass_name_sz;
	char subclass_name[CLASS_LIST_FIELD_MAX];
	subclass_lst_t sclist;

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if ((flags & DCMD_LOOP) == 0) {
		if (mdb_pwalk_dcmd("sysevent_subclass_list",
		    "sysevent_subclass_list", argc, argv, addr) == -1) {
			mdb_warn("can't walk sysevent subclass list");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-?s %-24s %-?s%</u>\n",
		    "ADDR", "NAME", "SUBSCRIBER DATA ADDR");
	}
	if (mdb_vread(&sclist, sizeof (sclist), (uintptr_t)addr) == -1) {
		mdb_warn("failed to read subclass list at %p", addr);
		return (DCMD_ERR);
	}
	if ((subclass_name_sz = mdb_readstr(subclass_name, CLASS_LIST_FIELD_MAX,
	    (uintptr_t)sclist.sl_name)) == -1) {
		mdb_warn("failed to read class name at %p",
		    sclist.sl_name);
		return (DCMD_ERR);
	}
	if (subclass_name_sz >= CLASS_LIST_FIELD_MAX - 1)
		(void) strcpy(&subclass_name[CLASS_LIST_FIELD_MAX - 4], "...");

	mdb_printf("%-?p %-24s %-?p\n", addr, subclass_name,
	    addr + offsetof(subclass_lst_t, sl_num));

	return (DCMD_OK);
}


int
sysevent_class_list(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	int class_name_sz;
	char class_name[CLASS_LIST_FIELD_MAX];
	class_lst_t clist;

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if ((flags & DCMD_LOOP) == 0) {
		if (mdb_pwalk_dcmd("sysevent_class_list", "sysevent_class_list",
		    argc, argv, addr) == -1) {
			mdb_warn("can't walk sysevent class list");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%-?s %-24s %-?s%</u>\n",
		    "ADDR", "NAME", "SUBCLASS LIST ADDR");

	if (mdb_vread(&clist, sizeof (clist),
	    (uintptr_t)addr) == -1) {
		mdb_warn("failed to read class clist at %p", addr);
		return (DCMD_ERR);
	}
	if ((class_name_sz = mdb_readstr(class_name, CLASS_LIST_FIELD_MAX,
	    (uintptr_t)clist.cl_name)) == -1) {
		mdb_warn("failed to read class name at %p",
		    clist.cl_name);
		return (DCMD_ERR);
	}
	if (class_name_sz >= CLASS_LIST_FIELD_MAX - 1)
		(void) strcpy(&class_name[CLASS_LIST_FIELD_MAX - 4], "...");

	mdb_printf("%-?p %-24s %-?p\n", addr, class_name,
	    clist.cl_subclass_list);

	return (DCMD_OK);
}

int
sysevent_subclass_list_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("sysevent_subclass_list does not support global "
		    "walks");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (subclass_lst_t), UM_SLEEP);
	return (WALK_NEXT);
}

int
sysevent_subclass_list_walk_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (subclass_lst_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read class list at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((subclass_lst_t *)wsp->walk_data)->sl_next);

	return (status);
}

void
sysevent_subclass_list_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (subclass_lst_t));
}

typedef struct class_walk_data {
	int	hash_index;
	class_lst_t *hash_tbl[CLASS_HASH_SZ + 1];
} class_walk_data_t;

int
sysevent_class_list_walk_init(mdb_walk_state_t *wsp)
{
	class_walk_data_t *cl_walker;

	if (wsp->walk_addr == 0) {
		mdb_warn("sysevent_class_list does not support global walks");
		return (WALK_ERR);
	}

	cl_walker = mdb_zalloc(sizeof (class_walk_data_t), UM_SLEEP);
	if (mdb_vread(cl_walker->hash_tbl,
	    sizeof (cl_walker->hash_tbl), wsp->walk_addr) == -1) {
		mdb_warn("failed to read class hash table at %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)cl_walker->hash_tbl[0];
	wsp->walk_data = cl_walker;

	return (WALK_NEXT);
}

int
sysevent_class_list_walk_step(mdb_walk_state_t *wsp)
{
	int status = WALK_NEXT;
	class_walk_data_t *cl_walker;
	class_lst_t clist;

	cl_walker = (class_walk_data_t *)wsp->walk_data;

	/* Skip over empty class table entries */
	if (wsp->walk_addr != 0) {
		if (mdb_vread(&clist, sizeof (class_lst_t),
		    wsp->walk_addr) == -1) {
			mdb_warn("failed to read class list at %p",
			    wsp->walk_addr);
			return (WALK_ERR);
		}

		status = wsp->walk_callback(wsp->walk_addr, NULL,
		    wsp->walk_cbdata);
		wsp->walk_addr = (uintptr_t)clist.cl_next;
	} else {
		if (cl_walker->hash_index > CLASS_HASH_SZ) {
			return (WALK_DONE);
		} else {
			wsp->walk_addr = (uintptr_t)
			    cl_walker->hash_tbl[cl_walker->hash_index];
			cl_walker->hash_index++;
		}
	}


	return (status);
}

void
sysevent_class_list_walk_fini(mdb_walk_state_t *wsp)
{
	class_walk_data_t *cl_walker = wsp->walk_data;

	mdb_free(cl_walker, sizeof (cl_walker));
}

#ifdef _KERNEL
int
sysevent(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t sys_flags = FALSE;

	if (mdb_getopts(argc, argv,
	    's', MDB_OPT_SETBITS, SYSEVENT_SENTQ, &sys_flags,
	    'v', MDB_OPT_SETBITS, SYSEVENT_VERBOSE, &sys_flags, NULL) != argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		if (sys_flags & SYSEVENT_SENTQ) {
			if (mdb_walk_dcmd("sysevent_sent", "sysevent", argc,
			    argv) == -1) {
				mdb_warn("can not walk sent queue");
				return (DCMD_ERR);
			}
		} else {
			if (mdb_walk_dcmd("sysevent_pend", "sysevent", argc,
			    argv) == -1) {
				mdb_warn("can not walk pending queue");
				return (DCMD_ERR);
			}
		}
		return (DCMD_OK);
	}

	return (sysevent_buf(addr, flags, sys_flags));
}

int
sysevent_channel(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	ssize_t channel_name_sz;
	char channel_name[CHAN_FIELD_MAX];
	sysevent_channel_descriptor_t chan_tbl;

	if (argc != 0)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		if (mdb_walk_dcmd("sysevent_channel", "sysevent_channel",
		    argc, argv) == -1) {
			mdb_warn("can't walk sysevent channel");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}


	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%-?s %-16s %-8s %-?s%</u>\n",
		    "ADDR", "NAME", "REF CNT", "CLASS LST ADDR");

	if (mdb_vread(&chan_tbl, sizeof (chan_tbl),
	    (uintptr_t)addr) == -1) {
		mdb_warn("failed to read channel table at %p", addr);
		return (DCMD_ERR);
	}
	if ((channel_name_sz = mdb_readstr(channel_name, CHAN_FIELD_MAX,
	    (uintptr_t)chan_tbl.scd_channel_name)) == -1) {
		mdb_warn("failed to read channel name at %p",
		    chan_tbl.scd_channel_name);
		return (DCMD_ERR);
	}
	if (channel_name_sz >= CHAN_FIELD_MAX - 1)
		(void) strcpy(&channel_name[CHAN_FIELD_MAX - 4], "...");

	mdb_printf("%-?p %-16s %-8lu %-?p\n",
	    addr, channel_name, chan_tbl.scd_ref_cnt,
	    addr + offsetof(sysevent_channel_descriptor_t,
	    scd_class_list_tbl));

	return (DCMD_OK);
}

typedef struct channel_walk_data {
	int hash_index;
	sysevent_channel_descriptor_t *hash_tbl[CHAN_HASH_SZ];
} channel_walk_data_t;

int
sysevent_channel_walk_init(mdb_walk_state_t *wsp)
{
	channel_walk_data_t *ch_walker;

	if (wsp->walk_addr != 0) {
		mdb_warn("sysevent_channel supports only global walks");
		return (WALK_ERR);
	}

	ch_walker = mdb_zalloc(sizeof (channel_walk_data_t), UM_SLEEP);
	if (mdb_readvar(ch_walker->hash_tbl, "registered_channels")
	    == -1) {
		mdb_warn("failed to read 'registered_channels'");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)ch_walker->hash_tbl[0];
	wsp->walk_data = ch_walker;

	return (WALK_NEXT);
}

int
sysevent_channel_walk_step(mdb_walk_state_t *wsp)
{
	int status = WALK_NEXT;
	channel_walk_data_t *ch_walker;
	sysevent_channel_descriptor_t scd;

	ch_walker = (channel_walk_data_t *)wsp->walk_data;

	/* Skip over empty hash table entries */
	if (wsp->walk_addr != 0) {
		if (mdb_vread(&scd, sizeof (sysevent_channel_descriptor_t),
		    wsp->walk_addr) == -1) {
			mdb_warn("failed to read channel at %p",
			    wsp->walk_addr);
			return (WALK_ERR);
		}

		status = wsp->walk_callback(wsp->walk_addr, NULL,
		    wsp->walk_cbdata);
		wsp->walk_addr = (uintptr_t)scd.scd_next;
	} else {
		if (ch_walker->hash_index == CHAN_HASH_SZ) {
			return (WALK_DONE);
		} else {

			wsp->walk_addr = (uintptr_t)
			    ch_walker->hash_tbl[ch_walker->hash_index];
			ch_walker->hash_index++;
		}
	}

	return (status);
}

void
sysevent_channel_walk_fini(mdb_walk_state_t *wsp)
{
	channel_walk_data_t *ch_walker = wsp->walk_data;

	mdb_free(ch_walker, sizeof (ch_walker));
}

int
sysevent_pend_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		if (mdb_readvar(&wsp->walk_addr, "log_eventq_head") == -1) {
			mdb_warn("failed to read 'log_eventq_head'");
			return (WALK_ERR);
		}
	}

	wsp->walk_data = mdb_alloc(sizeof (log_eventq_t), UM_SLEEP);
	return (WALK_NEXT);
}

int
sysevent_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	uintptr_t ev_arg_addr;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (log_eventq_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read event queue at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	ev_arg_addr = wsp->walk_addr + offsetof(log_eventq_t, arg.buf);

	status = wsp->walk_callback(ev_arg_addr, wsp->walk_data,
	    wsp->walk_cbdata);
	wsp->walk_addr = (uintptr_t)(((log_eventq_t *)wsp->walk_data)->next);
	return (status);
}

int
sysevent_sent_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		if (mdb_readvar(&wsp->walk_addr, "log_eventq_sent") == -1) {
			mdb_warn("failed to read 'log_eventq_sent'");
			return (WALK_ERR);
		}
	}
	wsp->walk_data = mdb_alloc(sizeof (log_eventq_t), UM_SLEEP);
	return (WALK_NEXT);
}

void
sysevent_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (log_eventq_t));
}

#endif
