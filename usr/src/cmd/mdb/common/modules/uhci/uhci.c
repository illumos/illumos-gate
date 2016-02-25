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

#include <gelf.h>

#include <sys/mdb_modapi.h>
#include <mdb/mdb_ks.h>

#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_types.h>

#include <sys/usb/hcd/uhci/uhci.h>
#include <sys/usb/hcd/uhci/uhcid.h>
#include <sys/usb/hcd/uhci/uhciutil.h>


#define	UHCI_TD	0
#define	UHCI_QH	1


/* Prototypes */

int	uhci_td(uintptr_t, uint_t, int, const mdb_arg_t *);
int	uhci_qh(uintptr_t, uint_t, int, const mdb_arg_t *);
int	uhci_td_walk_init(mdb_walk_state_t *);
int	uhci_td_walk_step(mdb_walk_state_t *);
int	uhci_qh_walk_init(mdb_walk_state_t *);
int	uhci_qh_walk_step(mdb_walk_state_t *);


/*
 * Callback for find_uhci_statep (called back from walk "softstate" in
 * find_uhci_statep).
 *
 * - uhci_instancep is the value of the current pointer in the array of soft
 * state instance pointers (see i_ddi_soft_state in ddi_impldefs.h)
 * - local_ss is a pointer to the copy of the i_ddi_soft_state in local space
 * - cb_arg is a pointer to the cb arg (an instance of state_find_data).
 *
 * For the current uchi_state_t*, see if the td address is in its pool.
 *
 * Returns WALK_NEXT on success (match not found yet), WALK_ERR on errors.
 *
 * WALK_DONE is returned, cb_data.found is set to TRUE, and
 * *cb_data.fic_uhci_statep is filled in with the contents of the state
 * struct in core. This forces the walk to terminate.
 */
typedef struct find_instance_struct {
	void		*fic_td_qh;	/* td/qh we want uhci instance for */
	boolean_t	fic_td_or_qh;	/* which one td_qh points to */
	boolean_t	fic_found;
	uhci_state_t	*fic_uhci_statep; /* buffer uhci_state's written into */
} find_instance_cb_t;

/*ARGSUSED*/
static int
find_uhci_instance(uintptr_t uhci_instancep, const void *local_ss, void *cb_arg)
{
	int			td_pool_size, qh_pool_size;
	find_instance_cb_t	*cb_data = (find_instance_cb_t *)cb_arg;
	uhci_state_t		*uhcip = cb_data->fic_uhci_statep;


	if (mdb_vread(cb_data->fic_uhci_statep, sizeof (uhci_state_t),
	    uhci_instancep) == -1) {
		mdb_warn("failed to read uhci_state at %p", uhci_instancep);
		return (-1);
	}

	if (mdb_readsym(&td_pool_size, sizeof (int), "uhci_td_pool_size") ==
	    -1) {
		mdb_warn("failed to read uhci_td_pool_size");
		return (-1);
	}

	if (mdb_readsym(&qh_pool_size, sizeof (int), "uhci_qh_pool_size") ==
	    -1) {
		mdb_warn("failed to read uhci_td_pool_size");
		return (-1);
	}

	/*
	 * See if the addr is within the appropriate pool for this instance.
	 */
	if ((cb_data->fic_td_or_qh == UHCI_TD &&

	    ((uhci_td_t *)cb_data->fic_td_qh >= uhcip->uhci_td_pool_addr &&
	    (uhci_td_t *)cb_data->fic_td_qh <= (uhcip->uhci_td_pool_addr +
	    td_pool_size - sizeof (uhci_td_t)))) ||

	    (cb_data->fic_td_or_qh == UHCI_QH &&

	    ((queue_head_t *)cb_data->fic_td_qh >= uhcip->uhci_qh_pool_addr &&
	    (queue_head_t *)cb_data->fic_td_qh <= (uhcip->uhci_qh_pool_addr +
	    qh_pool_size - sizeof (queue_head_t))))) {

		/* td/qh address is within pool for this instance of uhci. */
		cb_data->fic_found = TRUE;
		return (WALK_DONE);
	}

	return (WALK_NEXT);
}

/*
 * Figure out which instance of uhci owns a td/qh.
 *
 * - td_qh: a pointer to a uhci td or qh
 * - td_or_qh: a flag indicating which it is (td/qh),
 * - uhci_statep, pointer to a uhci_state_t, to be filled in with data from
 * the found instance of uhci_state_t.
 *
 * Only works for Cntl/Interrupt tds/qhs; others are dynamically allocated
 * and so cannot be found with this method.
 *
 * Returns 0 on success (no match found), 1 on success (match found),
 * -1 on errors.
 */
static int
find_uhci_statep(void *td_qh, boolean_t td_or_qh, uhci_state_t *uhci_statep)
{
	find_instance_cb_t	cb_data;
	uintptr_t		uhci_ss;


	if (uhci_statep == NULL) {
		mdb_warn("failed to find uhci statep: "
		    "NULL uhci_statep param\n");
		return (-1);
	}

	cb_data.fic_td_qh = td_qh;
	cb_data.fic_td_or_qh = td_or_qh;
	cb_data.fic_found = FALSE;
	cb_data.fic_uhci_statep = uhci_statep;


	if (mdb_readsym(&uhci_ss, sizeof (uhci_statep),
	    "uhci_statep") == -1) {
		mdb_warn("failed to read uhci_statep");
		return (-1);
	}


	/*
	 * Walk all instances of uhci.
	 * The callback func checks if td_qh belongs to a given instance
	 * of uhci.
	 */
	if (mdb_pwalk("softstate", find_uhci_instance, &cb_data,
	    uhci_ss) != 0) {
		mdb_warn("failed to walk softstate");
		return (-1);
	}

	if (cb_data.fic_found == TRUE) {
		return (1);
	}

	return (0);
}

/*
 * Dump a UHCI TD (transaction descriptor);
 * or (-d) the chain of TDs starting with the one specified.
 */
int
uhci_td(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		depth_flag = FALSE;
	uhci_state_t	uhci_state, *uhcip = &uhci_state;
	uhci_td_t	td;


	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (addr & ~QH_LINK_PTR_MASK) {
		mdb_warn("address must be on a 16-byte boundary.\n");
		return (DCMD_ERR);
	}

	if (mdb_getopts(argc, argv,
	    'd', MDB_OPT_SETBITS, TRUE, &depth_flag,
	    NULL) != argc) {
		return (DCMD_USAGE);
	}


	if (depth_flag) {
		if (mdb_pwalk_dcmd("uhci_td", "uhci_td", 0, NULL, addr) == -1) {
			mdb_warn("failed to walk 'uhci_td'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}


	if (find_uhci_statep((void *)addr, UHCI_TD, uhcip) != 1) {
		mdb_warn("failed to find uhci_statep");
		return (DCMD_ERR);
	}

	if (mdb_vread(&td, sizeof (td), addr) != sizeof (td))  {
		mdb_warn("failed to read td at vaddr %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("\n  UHCI td struct at (vaddr) %08x:\n", addr);

	if (!(td.link_ptr & HC_END_OF_LIST) && td.link_ptr != NULL) {
		mdb_printf("        link_ptr (paddr)    : %-8x        "
		    "(vaddr)      : %p\n",
		    td.link_ptr,
		    /* Note: uhcip needed by TD_VADDR macro */
		    TD_VADDR(td.link_ptr & QH_LINK_PTR_MASK));
	} else {
		mdb_printf("        link_ptr (paddr)    : %-8x\n",
		    td.link_ptr);
	}
	mdb_printf("        td_dword2           : %08x\n", td.dw2);
	mdb_printf("        td_dword3           : %08x\n", td.dw3);
	mdb_printf("        buffer_address      : %08x\n", td.buffer_address);
	mdb_printf("        qh_td_prev          : %?p        "
	    "tw_td_next   : %?p\n",
	    td.qh_td_prev, td.tw_td_next);
	mdb_printf("        outst_td_prev        : %?p        "
	    "outst_td_next : %?p\n",
	    td.outst_td_prev, td.outst_td_next);
	mdb_printf("        tw                  : %?p        "
	    "flag         : %02x\n", td.tw, td.flag);
	mdb_printf("        isoc_next           : %?p        "
	    "isoc_prev    : %0x\n", td.isoc_next, td.isoc_prev);
	mdb_printf("        isoc_pkt_index      : %0x        "
	    "startingframe: %0x\n", td.isoc_pkt_index, td.starting_frame);


	if (td.link_ptr == NULL)  {
		mdb_printf("        --> Link pointer = NULL\n");
		return (DCMD_ERR);
	} else {

		/* Inform user if link is to a TD or QH.  */
		if (td.link_ptr & HC_END_OF_LIST)  {
			mdb_printf("        "
			    "--> Link pointer invalid (terminate bit set).\n");
		} else {
			if ((td.link_ptr & HC_QUEUE_HEAD) == HC_QUEUE_HEAD)  {
				mdb_printf("        "
				    "--> Link pointer points to a QH.\n");
			} else {
				mdb_printf("        "
				    "--> Link pointer points to a TD.\n");
			}
		}
	}

	return (DCMD_OK);
}

/*
 * Dump a UHCI QH (queue head).
 * -b walk/dump the chian of QHs starting with the one specified.
 * -d also dump the chain of TDs starting with the one specified.
 */
int
uhci_qh(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		breadth_flag = FALSE, depth_flag = FALSE;
	uhci_state_t	uhci_state, *uhcip = &uhci_state;
	queue_head_t	qh;


	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (addr & ~QH_LINK_PTR_MASK) {
		mdb_warn("address must be on a 16-byte boundary.\n");
		return (DCMD_ERR);
	}

	if (mdb_getopts(argc, argv,
	    'b', MDB_OPT_SETBITS, TRUE, &breadth_flag,
	    'd', MDB_OPT_SETBITS, TRUE, &depth_flag,
	    NULL) != argc) {
		return (DCMD_USAGE);
	}


	if (breadth_flag) {
		uint_t		new_argc = 0;
		mdb_arg_t	new_argv[1];


		if (depth_flag) {
			new_argc = 1;
			new_argv[0].a_type = MDB_TYPE_STRING;
			new_argv[0].a_un.a_str = "-d";
		}

		if ((mdb_pwalk_dcmd("uhci_qh", "uhci_qh", new_argc, new_argv,
		    addr)) != 0)  {
			mdb_warn("failed to walk 'uhci_qh'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}


	if (find_uhci_statep((void *)addr, UHCI_QH, uhcip) != 1) {
		mdb_warn("failed to find uhci_statep");
		return (DCMD_ERR);
	}


	if (mdb_vread(&qh, sizeof (qh), addr) != sizeof (qh))  {
		mdb_warn("failed to read qh at vaddr %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("\n  UHCI qh struct at (vaddr) %08x:\n", addr);

	if (!(qh.link_ptr & HC_END_OF_LIST) && qh.link_ptr != NULL) {
		mdb_printf("        link_ptr (paddr)    : %08x        "
		    "(vaddr)      : %p\n",
		    qh.link_ptr,
		    /* Note: uhcip needed by QH_VADDR macro */
		    QH_VADDR(qh.link_ptr & QH_LINK_PTR_MASK));
	} else {
		mdb_printf(
		    "        link_ptr (paddr)    : %08x\n",
		    qh.link_ptr);
	}

	if (!(qh.element_ptr & HC_END_OF_LIST) && qh.element_ptr != NULL) {
		mdb_printf("        element_ptr (paddr) : %08x        "
		    "(vaddr)      : %p\n",
		    qh.element_ptr,
		    /* Note: uhcip needed by TD_VADDR macro */
		    TD_VADDR(qh.element_ptr & QH_LINK_PTR_MASK));
	} else {
		mdb_printf(
		    "        element_ptr (paddr) : %08x\n", qh.element_ptr);
	}

	mdb_printf("        node                : %04x            "
	    "flag         : %04x\n",
	    qh.node, qh.qh_flag);
	mdb_printf("        prev_qh             : %?p        "
	    "td_tailp     : %?p\n",
	    qh.prev_qh, qh.td_tailp);
	mdb_printf("        bulk_xfer_isoc_info : %?p\n", qh.bulk_xfer_info);


	if (qh.link_ptr == NULL)  {
		mdb_printf("        --> Link pointer = NULL\n");
		return (DCMD_ERR);
	} else {

		/* Inform user if next link is a TD or QH.  */
		if (qh.link_ptr & HC_END_OF_LIST)  {
			mdb_printf("        "
			    "--> Link pointer invalid (terminate bit set).\n");
		} else {
			if ((qh.link_ptr & HC_QUEUE_HEAD) == HC_QUEUE_HEAD)  {
				mdb_printf("        "
				    "--> Link pointer points to a QH.\n");
			} else {
				/* Should never happen. */
				mdb_warn("        "
				    "--> Link pointer points to a TD.\n");
				return (DCMD_ERR);
			}
		}
	}


	if (qh.element_ptr == NULL)  {
		mdb_printf("        element_ptr = NULL\n");
		return (DCMD_ERR);
	} else {

		/* Inform user if next element is a TD or QH.  */
		if (qh.element_ptr & HC_END_OF_LIST)  {
			mdb_printf("        "
			    "-->Element pointer invalid (terminate bit set)."
			    "\n");
			return (DCMD_OK);
		} else {
			if ((qh.element_ptr & HC_QUEUE_HEAD) == HC_QUEUE_HEAD) {
				mdb_printf("        "
				    "--> Element pointer points to a QH.\n");
				/* Should never happen in UHCI implementation */
				return (DCMD_ERR);
			} else {
				mdb_printf("        "
				    "--> Element pointer points to a TD.\n");
			}
		}
	}

	/*
	 * If the user specified the -d (depth) option,
	 * dump all TDs linked to this TD via the element_ptr.
	 */
	if (depth_flag) {

		/* Traverse and display all the TDs in the chain */
		if (mdb_pwalk_dcmd("uhci_td", "uhci_td", argc, argv,
		    (uintptr_t)(TD_VADDR(qh.element_ptr &
		    QH_LINK_PTR_MASK))) == -1) {
			mdb_warn("failed to walk 'uhci_td'");
			return (DCMD_ERR);
		}
	}

	return (DCMD_OK);
}

/*
 * Walk a list of UHCI Transaction Descriptors (td's).
 * Stop at the end of the list, or if the next element in the list is a
 * queue head (qh).
 * User must specify the address of the first td to look at.
 */
int
uhci_td_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL)  {
		return (DCMD_USAGE);
	}

	wsp->walk_data = mdb_alloc(sizeof (uhci_td_t), UM_SLEEP | UM_GC);
	wsp->walk_arg = mdb_alloc(sizeof (uhci_state_t), UM_SLEEP | UM_GC);


	/*
	 * Read the uhci_state_t for the instance of uhci
	 * using this td address into buf pointed to by walk_arg.
	 */
	if (find_uhci_statep((void *)wsp->walk_addr, UHCI_TD,
	    wsp->walk_arg) != 1) {
		mdb_warn("failed to find uhci_statep");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

/*
 * At each step, read a TD into our private storage, and then invoke
 * the callback function.  We terminate when we reach a QH, or
 * link_ptr is NULL.
 */
int
uhci_td_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	uhci_state_t	*uhcip = (uhci_state_t *)wsp->walk_arg;


	if (mdb_vread(wsp->walk_data, sizeof (uhci_td_t), wsp->walk_addr)
	    == -1) {
		mdb_warn("failed to read td at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	/* Next td. */
	wsp->walk_addr = ((uhci_td_t *)wsp->walk_data)->link_ptr;

	/* Check if we're at the last element */
	if (wsp->walk_addr == NULL || wsp->walk_addr & HC_END_OF_LIST)
		return (WALK_DONE);

	/* Make sure next element is a TD.  If a QH, stop.  */
	if (((((uhci_td_t *)wsp->walk_data)->link_ptr) & HC_QUEUE_HEAD)
	    == HC_QUEUE_HEAD)  {
		return (WALK_DONE);
	}

	/* Strip terminate etc. bits.  */
	wsp->walk_addr &= QH_LINK_PTR_MASK; /* there is no TD_LINK_PTR_MASK */

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	/*
	 * Convert link_ptr paddr to vaddr
	 * Note: uhcip needed by TD_VADDR macro
	 */
	wsp->walk_addr = (uintptr_t)TD_VADDR(wsp->walk_addr);

	return (status);
}

/*
 * Walk a list of UHCI Queue Heads (qh's).
 * Stop at the end of the list, or if the next element in the list is a
 * Transaction Descriptor (td).
 * User must specify the address of the first qh to look at.
 */
int
uhci_qh_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL)
		return (DCMD_USAGE);

	wsp->walk_data = mdb_alloc(sizeof (queue_head_t), UM_SLEEP | UM_GC);
	wsp->walk_arg = mdb_alloc(sizeof (uhci_state_t), UM_SLEEP | UM_GC);


	/*
	 * Read the uhci_state_t for the instance of uhci
	 * using this td address into buf pointed to by walk_arg.
	 */
	if (find_uhci_statep((void *)wsp->walk_addr, UHCI_QH,
	    (uhci_state_t *)wsp->walk_arg) != 1) {
		mdb_warn("failed to find uhci_statep");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

/*
 * At each step, read a QH into our private storage, and then invoke
 * the callback function.  We terminate when we reach a QH, or
 * link_ptr is NULL.
 */
int
uhci_qh_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	uhci_state_t	*uhcip = (uhci_state_t *)wsp->walk_arg;


	if (wsp->walk_addr == NULL)	/* Should never occur */
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (queue_head_t), wsp->walk_addr)
	    == -1) {
		mdb_warn("failure reading qh at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	/* Next QH. */
	wsp->walk_addr = ((queue_head_t *)wsp->walk_data)->link_ptr;


	/* Check if we're at the last element */
	if (wsp->walk_addr == NULL || wsp->walk_addr & HC_END_OF_LIST)  {
		return (WALK_DONE);
	}

	/* Make sure next element is a QH.  If a TD, stop.  */
	if (((((queue_head_t *)wsp->walk_data)->link_ptr) & HC_QUEUE_HEAD)
	    != HC_QUEUE_HEAD)  {
		return (WALK_DONE);
	}

	/* Strip terminate etc. bits.  */
	wsp->walk_addr &= QH_LINK_PTR_MASK;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	/*
	 * Convert link_ptr paddr to vaddr
	 * Note: uhcip needed by QH_VADDR macro
	 */
	wsp->walk_addr = (uintptr_t)QH_VADDR(wsp->walk_addr);

	return (status);
}

/*
 * MDB module linkage information:
 *
 * We declare a list of structures describing our dcmds, and a function
 * named _mdb_init to return a pointer to our module information.
 */

static const mdb_dcmd_t dcmds[] = {
	{ "uhci_td", ": [-d]", "print UHCI TD", uhci_td, NULL },
	{ "uhci_qh", ": [-bd]", "print UHCI QH", uhci_qh, NULL},
	{ NULL }
};


static const mdb_walker_t walkers[] = {
	{ "uhci_td", "walk list of UHCI TD structures",
	    uhci_td_walk_init, uhci_td_walk_step, NULL,
	    NULL },
	{ "uhci_qh", "walk list of UHCI QH structures",
	    uhci_qh_walk_init, uhci_qh_walk_step, NULL,
	    NULL },
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
