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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2016 Joyent, Inc.
 */

#include <stddef.h>
#include <sys/mdb_modapi.h>
#include <mdb/mdb_ks.h>

#include <sys/usb/usba.h>
#include <sys/ddi_impldefs.h>
#include <sys/usb/usba/usba_types.h>
#include <sys/usb/usba/usba_impl.h>
#include <sys/usb/usba/hcdi_impl.h>
#include <sys/usb/hubd/hub.h>
#include <sys/usb/hubd/hubdvar.h>
#include <sys/file.h>
#include <sys/sunndi.h>
#include <unistd.h>


/*
 * Prototypes
 */
/* usba.c */
extern uintptr_t mdb_usba_get_usba_device(uintptr_t);
extern uintptr_t mdb_usba_hcdi_get_hcdi(struct dev_info *);

/*
 * Defines
 */
/* dcmd options */
#define	USB_DUMP_VERBOSE	0x01
#define	USB_DUMP_ACTIVE_PIPES	0x02

/* Hardcoded slop factor designed into debug buf logic */
#define	USB_DEBUG_SIZE_EXTRA_ALLOC 8


/*
 * Callback arg struct for find_dip (callback func used in usba_device2devinfo).
 */
typedef struct usba_device2devinfo_data {
	uintptr_t	u2d_target_usb_dev_p;	/* one we're looking for */
	uintptr_t	*u2d_dip_addr;		/* Where to store result */
	boolean_t	u2d_found;		/* Match found */
} usba_device2devinfo_cbdata_t;


/*
 * Callback for usba_device2dip.
 * Callback called from the devinfo_children walk invoked in usba_device2dip.
 *
 * For the current dip, get the (potential) pointer to its usba_device_t
 * struct.
 * See if this pointer matches the address of the usba_device_t we're looking
 * for (passed in as usb_dev_p).  If so, stuff its value in u2d_dip_addr,
 * and terminate the walk.
 *
 * - dip_addr is the address in core of the dip currently being processed by the
 * walk
 * - local_dip is a pointer to a copy of the struct dev_info in local memory
 * - cb_data is the addr of the callback arg the walker was invoked with
 * (passed through transparently from walk invoker).
 *
 * Returns:
 * - WALK_NEXT on success (match not found yet)
 * - WALK_ERR on errors.
 * - WALK_DONE is returned, cb_data.found is set to TRUE, and
 * *cb_data.u2d_dip_addr is set to the matched dip addr if a dip corresponding
 * to the desired usba_device_t* is found.
 */
/*ARGSUSED*/
static int
find_dip(uintptr_t dip_addr, const void *local_dip, void *cb_arg)
{
	uintptr_t			cur_usb_dev;
	usba_device2devinfo_cbdata_t	*cb_data =
	    (usba_device2devinfo_cbdata_t *)cb_arg;

	if ((cur_usb_dev = mdb_usba_get_usba_device(dip_addr)) == NULL) {
		/*
		 * If there's no corresponding usba_device_t, this dip isn't
		 * a usb node.  Might be an sd node.  Ignore it.
		 */

		return (WALK_NEXT);
	}

	if (cur_usb_dev == cb_data->u2d_target_usb_dev_p) {
		*cb_data->u2d_dip_addr = dip_addr;
		cb_data->u2d_found = TRUE;

		return (WALK_DONE);
	}

	return (WALK_NEXT);
}


/*
 * Given a usba_device pointer, figure out which dip is associated with it.
 * Relies on usba_device.usb_root_hub_dip being accurate.
 *
 * - usb_dev_addr is a pointer to a usba_device_t in core.
 * - dip_addr is the address of a uintptr_t to receive the address in core
 * of the found dip (if any).
 *
 * Returns:
 *  0 on success (no match found)
 *  1 on success (match found)
 * -1 on errors.
 */
static int
usba_device2dip(uintptr_t usb_dev_addr, uintptr_t *dip_addr)
{
	usba_device_t			usb_dev;
	usba_device2devinfo_cbdata_t	cb_data;

	/*
	 * Walk all USB children of the root hub devinfo.
	 * The callback func looks for a match on the usba_device address.
	 */
	cb_data.u2d_target_usb_dev_p = usb_dev_addr;
	cb_data.u2d_dip_addr = dip_addr;
	cb_data.u2d_found = FALSE;

	if (mdb_vread(&usb_dev, sizeof (usba_device_t),
	    usb_dev_addr) == -1) {
		mdb_warn("failed to read usba_device struct");

		return (-1);
	}

	/*
	 * Walk devinfo children starting with the root hub node,
	 * looking for a match on the usba_device pointer (which is what
	 * find_dip does).
	 * Result is placed in cb_data.dip_addr.
	 */
	if (mdb_pwalk("devinfo_children", find_dip, &cb_data,
	    (uintptr_t)usb_dev.usb_root_hub_dip) != 0) {
		mdb_warn("failed to walk devinfo_children");

		return (-1);
	}

	if (cb_data.u2d_found == TRUE) {

		return (1);
	}

	return (0);
}


/*
 * Generic walker usba_list_entry_t walker.
 * Works for any usba_list_entry_t list.
 */
int
usba_list_walk_init(mdb_walk_state_t *wsp)
{
	/* Must have a start addr.  */
	if (wsp->walk_addr == NULL) {
		mdb_warn("not a global walk.  Starting address required\n");

		return (WALK_ERR);
	}

	return (WALK_NEXT);
}


/*
 * Generic list walker step routine.
 * NOTE: multiple walkers share this routine.
 */
int
usba_list_walk_step(mdb_walk_state_t *wsp)
{
	int			status;
	usba_list_entry_t	list_entry;

	if (mdb_vread(&list_entry, sizeof (usba_list_entry_t),
	    (uintptr_t)wsp->walk_addr) == -1) {
		mdb_warn("failed to read usba_list_entry_t at %p",
		    wsp->walk_addr);

		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &list_entry,
	    wsp->walk_cbdata);
	wsp->walk_addr = (uintptr_t)list_entry.next;

	/* Check if we're at the last element */
	if (wsp->walk_addr == NULL) {

		return (WALK_DONE);
	}

	return (status);
}


/*
 * usb_pipe_handle walker
 * Given a pointer to a usba_device_t, walk the array of endpoint
 * pipe_handle lists.
 * For each list, traverse the list, invoking the callback on each element.
 *
 * Note this function takes the address of a usba_device struct (which is
 * easily obtainable), but actually traverses a sub-portion of the struct
 * (which address is not so easily obtainable).
 */
int
usb_pipe_handle_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("not a global walk; usba_device_t required\n");

		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc((sizeof (usba_ph_impl_t)) * USBA_N_ENDPOINTS,
	    UM_SLEEP | UM_GC);

	/*
	 * Read the usb_ph_list array into local memory.
	 * Set start address to first element/endpoint in usb_pipehandle_list
	 */
	if (mdb_vread(wsp->walk_data,
	    (sizeof (usba_ph_impl_t)) * USBA_N_ENDPOINTS,
	    (uintptr_t)((size_t)(wsp->walk_addr) +
	    offsetof(usba_device_t, usb_ph_list))) == -1) {
		mdb_warn("failed to read usb_pipehandle_list at %p",
		    wsp->walk_addr);

		return (WALK_ERR);
	}

	wsp->walk_arg = 0;

	return (WALK_NEXT);
}


int
usb_pipe_handle_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	usba_ph_impl_t *impl_list = (usba_ph_impl_t *)(wsp->walk_data);
	intptr_t index = (intptr_t)wsp->walk_arg;

	/* Find the first valid endpoint, starting from where we left off. */
	while ((index < USBA_N_ENDPOINTS) &&
	    (impl_list[index].usba_ph_data == NULL)) {
		index++;
	}

	/* No more valid endpoints. */
	if (index >= USBA_N_ENDPOINTS) {

		return (WALK_DONE);
	}

	status = wsp->walk_callback((uintptr_t)impl_list[index].usba_ph_data,
	    wsp->walk_data, wsp->walk_cbdata);

	/* Set up to start at next pipe handle next time. */
	wsp->walk_arg = (void *)(index + 1);

	return (status);
}


/*
 * Given the address of a usba_pipe_handle_data_t, dump summary info.
 */
/*ARGSUSED*/
int
usb_pipe_handle(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char			*dir, *type, *state;
	usb_ep_descr_t		ept_descr;
	usba_pipe_handle_data_t	pipe_handle;
	usba_ph_impl_t		ph_impl;

	if (!(flags & DCMD_ADDRSPEC)) {

		return (DCMD_USAGE);
	}

	if (mdb_vread(&pipe_handle,
	    sizeof (usba_pipe_handle_data_t), addr) == -1) {
		mdb_warn("failed to read pipe handle at %p", addr);

		return (DCMD_ERR);
	}

	if (mdb_vread(&ph_impl, sizeof (usba_ph_impl_t),
	    (uintptr_t)pipe_handle.p_ph_impl) == -1) {
		state = "*******";
	} else {
		switch (ph_impl.usba_ph_state) {
		case USB_PIPE_STATE_CLOSED:
			state = "CLOSED ";
			break;

		case USB_PIPE_STATE_IDLE:
			state = "IDLE   ";
			break;

		case USB_PIPE_STATE_ACTIVE:
			state = "ACTIVE ";
			break;

		case USB_PIPE_STATE_ERROR:
			state = "ERROR  ";
			break;

		case USB_PIPE_STATE_CLOSING:
			state = "CLOSING";
			break;

		default:
			state = "ILLEGAL";
			break;
		}
	}

	bcopy(&pipe_handle.p_ep, &ept_descr, sizeof (usb_ep_descr_t));

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("\n    %<u>%-3s %5s %3s %7s %-?s %-?s %-?s%</u>\n",
		    "EP", "TYPE ", "DIR", "STATE  ", "P_HANDLE", "P_POLICY",
		    "EP DESCR");
	}

	dir = ((ept_descr.bEndpointAddress & USB_EP_DIR_MASK) &
	    USB_EP_DIR_IN) ? "In " : "Out";
	switch (ept_descr.bmAttributes & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		type = "Cntrl";
		break;

	case USB_EP_ATTR_ISOCH:
		type = "Isoch";
		break;

	case USB_EP_ATTR_BULK:
		type = "Bulk ";
		break;

	case USB_EP_ATTR_INTR:
		type = "Intr ";
		break;

	default:
		type = "*****";
		break;
	}

	mdb_printf("    %3d %5s %3s %7s %-?p %-?p %-?p\n",
	    ept_descr.bEndpointAddress & USB_EP_NUM_MASK, type, dir, state,
	    addr, addr + offsetof(usba_pipe_handle_data_t, p_policy),
	    addr + offsetof(usba_pipe_handle_data_t, p_ep));

	return (DCMD_OK);
}


/*
 * usba_device walker:
 *
 * walks the chain of usba_device structs headed by usba_device_list in usba.c
 * NOTE: It uses the generic list walk step routine usba_list_walk_step.
 * No walk_fini routine is needed.
 */
int
usba_device_walk_init(mdb_walk_state_t *wsp)
{
	usba_list_entry_t	list_entry;

	if (wsp->walk_addr != NULL) {
		mdb_warn(
		    "global walk only.  Must be invoked without an address\n");

		return (WALK_ERR);
	}

	if (mdb_readvar(&list_entry, "usba_device_list") == -1) {
		mdb_warn("failed to read usba_device_list");

		return (WALK_ERR);
	}

	/* List head is not part of usba_device_t, get first usba_device_t */
	wsp->walk_addr = (uintptr_t)list_entry.next;

	return (WALK_NEXT);
}

int
usba_hubd_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr != 0) {
		mdb_warn("hubd only supports global walks.\n");
		return (WALK_ERR);
	}

	if (mdb_layered_walk("usba_device", wsp) == -1) {
		mdb_warn("couldn't walk 'usba_device'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

/*
 * Getting the hub state is annoying. The root hubs are stored on dev_info_t
 * while the normal hubs are stored as soft state.
 */
int
usba_hubd_walk_step(mdb_walk_state_t *wsp)
{
	usba_device_t ud;
	hubd_t hubd;
	struct dev_info dev_info;
	uintptr_t state_addr;

	if (mdb_vread(&ud, sizeof (ud), wsp->walk_addr) != sizeof (ud)) {
		mdb_warn("failed to read usba_device_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	if (ud.usb_root_hubd != NULL) {
		if (mdb_vread(&hubd, sizeof (hubd),
		    (uintptr_t)ud.usb_root_hubd) != sizeof (hubd)) {
			mdb_warn("failed to read hubd at %p", ud.usb_root_hubd);
			return (WALK_ERR);
		}
		return (wsp->walk_callback((uintptr_t)ud.usb_root_hubd, &hubd,
		    wsp->walk_cbdata));
	}

	if (ud.usb_hubdi == NULL)
		return (WALK_NEXT);

	/*
	 * For non-root hubs, the hubd_t is stored in the soft state. Figure out
	 * the instance from the dev_info_t and then get its soft state.
	 */
	if (mdb_vread(&dev_info, sizeof (struct dev_info),
	    (uintptr_t)ud.usb_dip) != sizeof (struct dev_info)) {
		mdb_warn("failed to read dev_info_t for device %p at %p",
		    wsp->walk_addr, ud.usb_dip);
		return (WALK_ERR);
	}

	if (mdb_get_soft_state_byname("hubd_statep", dev_info.devi_instance,
	    &state_addr, &hubd, sizeof (hubd)) == -1) {
		mdb_warn("failed to read hubd soft state for instance %d from "
		    "usb device %p", dev_info.devi_instance, wsp->walk_addr);
		return (WALK_ERR);
	}

	return (wsp->walk_callback(state_addr, &hubd, wsp->walk_cbdata));
}

/*
 * usba_device dcmd
 *	Given the address of a usba_device struct, dump summary info
 *	-v:	Print more (verbose) info
 *	-p:	Walk/dump all open pipes for this usba_device
 */
/*ARGSUSED*/
int
usba_device(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int		status;
	char		pathname[MAXNAMELEN];
	char		dname[MODMAXNAMELEN + 1] = "<unatt>"; /* Driver name */
	char		drv_statep[MODMAXNAMELEN+ 10];
	uint_t		usb_flag  = NULL;
	boolean_t	no_driver_attached = FALSE;
	uintptr_t	dip_addr;
	struct dev_info	devinfo;

	if (!(flags & DCMD_ADDRSPEC)) {
		/* Global walk */
		if (mdb_walk_dcmd("usba_device", "usba_device", argc,
		    argv) == -1) {
			mdb_warn("failed to walk usba_device");

			return (DCMD_ERR);
		}

		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'p', MDB_OPT_SETBITS, USB_DUMP_ACTIVE_PIPES, &usb_flag,
	    'v', MDB_OPT_SETBITS, USB_DUMP_VERBOSE, &usb_flag, NULL) != argc) {

		return (DCMD_USAGE);
	}

	if (usb_flag && !(DCMD_HDRSPEC(flags))) {
		mdb_printf("\n");
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-15s %4s %-?s %-42s%</u>\n",
		    "NAME", "INST", "DIP", "PATH                             ");
	}

	status = usba_device2dip(addr, &dip_addr);
	/*
	 * -1 = error
	 * 0 = no error, no match
	 * 1 = no error, match
	 */
	if (status != 1) {
		if (status == -1) {
			mdb_warn("error looking for dip for usba_device %p",
			    addr);
		} else {
			mdb_warn("failed to find dip for usba_device %p\n",
			    addr);
		}
		mdb_warn("dip and statep unobtainable\n");

		return (DCMD_ERR);
	}

	/* Figure out what driver (name) is attached to this node. */
	(void) mdb_devinfo2driver(dip_addr, (char *)dname, sizeof (dname));

	if (mdb_vread(&devinfo, sizeof (struct dev_info),
	    dip_addr) == -1) {
		mdb_warn("failed to read devinfo");

		return (DCMD_ERR);
	}

	if (!(DDI_CF2(&devinfo))) {
		no_driver_attached = TRUE;
	}

	(void) mdb_ddi_pathname(dip_addr, pathname, sizeof (pathname));
	mdb_printf("%-15s %2d   %-?p %s\n", dname, devinfo.devi_instance,
	    dip_addr, pathname);

	if (usb_flag & USB_DUMP_VERBOSE) {
		int		i;
		uintptr_t	statep = NULL;
		char		*string_descr;
		char		**config_cloud, **conf_str_descr;
		usb_dev_descr_t	usb_dev_descr;
		usba_device_t	usba_device_struct;

		if (mdb_vread(&usba_device_struct,
		    sizeof (usba_device_t), addr) == -1) {
			mdb_warn("failed to read usba_device struct");

			return (DCMD_ERR);
		}

		mdb_printf("    usba_device: %-16p\n\n", (usba_device_t *)addr);

		if (mdb_vread(&usb_dev_descr, sizeof (usb_dev_descr),
		    (uintptr_t)usba_device_struct.usb_dev_descr) == -1) {
			mdb_warn("failed to read usb_dev_descr_t struct");

			return (DCMD_ERR);
		}

		mdb_printf("\n    idVendor: 0x%04x idProduct: 0x%04x "
		    "usb_addr: 0x%02x\n", usb_dev_descr.idVendor,
		    usb_dev_descr.idProduct, usba_device_struct.usb_addr);

		/* Get the string descriptor string into local space. */
		string_descr = (char *)mdb_alloc(USB_MAXSTRINGLEN, UM_GC);

		if (usba_device_struct.usb_mfg_str == NULL) {
			(void) strcpy(string_descr, "<No Manufacturer String>");
		} else {
			if (mdb_readstr(string_descr, USB_MAXSTRINGLEN,
			    (uintptr_t)usba_device_struct.usb_mfg_str) == -1) {
				mdb_warn("failed to read manufacturer "
				    "string descriptor");
				(void) strcpy(string_descr, "???");
			}
		}
		mdb_printf("\n    Manufacturer String:\t%s\n", string_descr);

		if (usba_device_struct.usb_product_str == NULL) {
			(void) strcpy(string_descr, "<No Product String>");
		} else {
			if (mdb_readstr(string_descr, USB_MAXSTRINGLEN,
			    (uintptr_t)usba_device_struct.usb_product_str) ==
			    -1) {
				mdb_warn("failed to read product string "
				    "descriptor");
				(void) strcpy(string_descr, "???");
			}
		}
		mdb_printf("    Product String:\t\t%s\n", string_descr);

		if (usba_device_struct.usb_serialno_str == NULL) {
			(void) strcpy(string_descr, "<No SerialNumber String>");
		} else {
			if (mdb_readstr(string_descr, USB_MAXSTRINGLEN,
			    (uintptr_t)usba_device_struct.usb_serialno_str) ==
			    -1) {
				mdb_warn("failed to read serial number string "
				    "descriptor");
				(void) strcpy(string_descr, "???");
			}
		}
		mdb_printf("    SerialNumber String:\t%s\n", string_descr);

		if (no_driver_attached) {
			mdb_printf("\n");
		} else {
			mdb_printf("      state_p: ");

			/*
			 * Given the dip, find the associated statep. The
			 * convention to generate this soft state anchor is:
			 *	<driver_name>_statep
			 */
			(void) mdb_snprintf(drv_statep, sizeof (drv_statep),
			    "%s_statep", dname);
			if (mdb_devinfo2statep(dip_addr, drv_statep,
			    &statep) == -1) {
				mdb_warn("failed to find %s state struct for "
				    "dip %p", drv_statep, dip_addr);

				return (DCMD_ERR);
			}
			mdb_printf("%-?p\n", statep);
		}

		config_cloud = (char **)mdb_alloc(sizeof (void *) *
		    usba_device_struct.usb_n_cfgs, UM_GC);

		conf_str_descr = (char **)mdb_alloc(sizeof (void *) *
		    usba_device_struct.usb_n_cfgs, UM_GC);

		if ((usba_device_struct.usb_cfg_array) &&
		    (usba_device_struct.usb_cfg_str_descr)) {
			if ((mdb_vread(config_cloud,  sizeof (void *) *
			    usba_device_struct.usb_n_cfgs,
			    (uintptr_t)usba_device_struct.usb_cfg_array) ==
			    -1) || (mdb_vread(conf_str_descr, sizeof (void *)
			    * usba_device_struct.usb_n_cfgs, (uintptr_t)
			    usba_device_struct.usb_cfg_str_descr)) == -1) {

				mdb_warn("failed to read config cloud "
				    "pointers");

			} else {

				mdb_printf("\n    Device Config Clouds:\n"
				    "    Index\tConfig\t\tConfiguration "
				    "String\n"
				    "    -----\t------\t\t"
				    "--------------------\n");

				for (i = 0; i < usba_device_struct.usb_n_cfgs;
				    i++) {
					if (mdb_readstr(string_descr,
					    USB_MAXSTRINGLEN,
					    (uintptr_t)conf_str_descr[i]) ==
					    -1) {
						(void) strcpy(string_descr,
						    "<No Configuration "
						    "String>");
					}
					mdb_printf("    %4d\t0x%p\t%s\n", i,
					    config_cloud[i], string_descr);
				}
			}
		}

		mdb_printf("\n    Active configuration index: %d\n",
		    usba_device_struct.usb_active_cfg_ndx);
	}

	if (usb_flag & USB_DUMP_ACTIVE_PIPES) {

		if (mdb_pwalk_dcmd("usb_pipe_handle", "usb_pipe_handle",
		    0, NULL, addr) == -1) {
			mdb_warn("failed to walk usb_pipe_handle");
			return (DCMD_ERR);
		}
	}

	return (DCMD_OK);
}


/*
 * Dump the contents of the usba_debug_buf, from the oldest to newest,
 * wrapping around if necessary.
 */
/*ARGSUSED*/
int
usba_debug_buf(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char	*debug_buf_addr;	/* addr in core */
	char	*local_debug_buf;	/* local copy of buf */
	int	debug_buf_size;
	char	*term_p;
	int	being_cleared;

	if (flags & DCMD_ADDRSPEC) {

		return (DCMD_USAGE);
	}

	if (mdb_readvar(&being_cleared, "usba_clear_debug_buf_flag") ==
	    -1) {
		mdb_warn("failed to read usba_clear_debug_buf_flag");

		return (DCMD_ERR);
	}
	if (being_cleared) {

		return (DCMD_OK);
	}

	if (mdb_readvar(&debug_buf_addr, "usba_debug_buf") == -1) {
		mdb_warn("failed to read usba_debug_buf");

		return (DCMD_ERR);
	}

	if (debug_buf_addr == NULL) {
		mdb_warn("usba_debug_buf not allocated\n");

		return (DCMD_OK);
	}


	if (mdb_readvar(&debug_buf_size, "usba_debug_buf_size") == -1) {
		mdb_warn("failed to read usba_debug_buf_size");

		return (DCMD_ERR);
	}

	debug_buf_size += USB_DEBUG_SIZE_EXTRA_ALLOC;
	local_debug_buf = (char *)mdb_alloc(debug_buf_size, UM_SLEEP | UM_GC);

	if ((mdb_vread(local_debug_buf, debug_buf_size,
	    (uintptr_t)debug_buf_addr)) == -1) {
		mdb_warn("failed to read usba_debug_buf at %p",
		    local_debug_buf);

		return (DCMD_ERR);
	}
	local_debug_buf[debug_buf_size - 1] = '\0';

	if (strlen(local_debug_buf) == NULL) {

		return (DCMD_OK);
	}

	if ((term_p = strstr(local_debug_buf, ">>>>")) == NULL) {
		mdb_warn("failed to find terminator \">>>>\"\n");

		return (DCMD_ERR);
	}

	/*
	 * Print the chunk of buffer from the terminator to the end.
	 * This will print a null string if no wrap has occurred yet.
	 */
	mdb_printf("%s", term_p+5);	/* after >>>>\0 to end of buf */
	mdb_printf("%s\n", local_debug_buf);	/* beg of buf to >>>>\0 */

	return (DCMD_OK);
}

/*ARGSUSED*/
int
usba_clear_debug_buf(
	uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int clear = 1;

	/* stop the tracing */
	if (mdb_writevar((void*)&clear, "usba_clear_debug_buf_flag") == -1) {
		mdb_warn("failed to set usba_clear_debug_buf_flag");

		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/* prtusb entries */
extern int prtusb(uintptr_t, uint_t, int, const mdb_arg_t *);

extern void prt_usb_usage(void);

/*
 * MDB module linkage information:
 *
 * We declare a list of structures describing our dcmds, and a function
 * named _mdb_init to return a pointer to our module information.
 */
static const mdb_dcmd_t dcmds[] = {
	{ "usb_pipe_handle", ":",
	    "print a usb_pipe_handle struct", usb_pipe_handle, NULL},
	{ "usba_device", ": [-pv]",
	    "print summary info for a usba_device_t struct", usba_device, NULL},
	{ "usba_debug_buf", NULL,
	    "print usba_debug_buf", usba_debug_buf, NULL},
	{ "usba_clear_debug_buf", NULL,
	    "clear usba_debug_buf", usba_clear_debug_buf, NULL},
	{ "prtusb", "?[-t] [-v] [-i index]",
	    "print trees and descriptors for usba_device_t",
	    prtusb, prt_usb_usage},
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	/* Generic list walker. */
	{ "usba_list_entry", "walk list of usba_list_entry_t structures",
	    usba_list_walk_init, usba_list_walk_step, NULL, NULL },
	{ "usb_pipe_handle", "walk USB pipe handles, given a usba_device_t ptr",
	    usb_pipe_handle_walk_init, usb_pipe_handle_walk_step, NULL, NULL },
	{ "usba_device", "walk global list of usba_device_t structures",
	    usba_device_walk_init, usba_list_walk_step, NULL, NULL },
	{ "hubd", "walk hubd instances", usba_hubd_walk_init,
	    usba_hubd_walk_step, NULL, NULL },
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
