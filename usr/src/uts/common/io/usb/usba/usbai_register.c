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
 *
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

/*
 * USBA: Solaris USB Architecture support
 *
 * This module builds a tree of parsed USB standard descriptors and unparsed
 * Class/Vendor specific (C/V) descriptors.  Routines are grouped into three
 * groups: those which build the tree, those which take it down, and those which
 * dump it.
 *
 * The tree built hangs off of the dev_cfg field of the usb_client_dev_data_t
 * structure returned by usb_get_dev_data().  The tree consists of different
 * kinds of tree nodes (usb_xxx_data_t) each containing a standard USB
 * descriptor (usb_xxx_descr_t) and pointers to arrays of other nodes.
 *
 * Arrays are dynamically sized, as the descriptors coming from the device may
 * lie, but the number of descriptors from the device is a more reliable
 * indicator of configuration.	This makes the code more robust.  After the raw
 * descriptor data has been parsed into a non-sparse tree, the tree is ordered
 * and made sparse with a bin-sort style algorithm.
 *
 * dev_cfg is an array of configuration tree nodes. Each contains space for one
 * parsed standard USB configuration descriptor, a pointer to an array of c/v
 * tree nodes and a pointer to an array of interface tree nodes.
 *
 * Each interface tree node represents a group of interface descriptors, called
 * alternates, with the same interface number.	Thus, each interface tree node
 * has a pointer to an array of alternate-interface tree nodes each containing a
 * standard USB interface descriptor. Alternate-interface tree nodes also
 * contain a pointer to an array of c/v tree nodes and a pointer to an array of
 * endpoint tree nodes.
 *
 * Endpoint tree nodes contain a standard endpoint descriptor, plus a pointer to
 * an array of c/v tree nodes.
 *
 * Each array in the tree contains elements ranging from 0 to the largest key
 * value of it's elements.  Endpoints are a special case.  The direction bit is
 * right shifted over three unused bits before the index is determined, leaving
 * a range of 0..31 instead of a sparsely-populated range of 0..255.
 *
 * The indices of tree elements coincide with their USB key values.  For
 * example, standard USB devices have no configuration 0;  if they have one
 * configuration it is #1.  dev_cfg[0] is zeroed out;  dev_cfg[1] is the root
 * of configuration #1.
 *
 * The idea here is for a driver to be able to parse the tree to easily find a
 * desired descriptor.	For example, the interval of endpoint 2, alternate 3,
 * interface 1, configuration 1 would be:
 *  dv->dev_cfg[1].cfg_if[1].if_alt[3].altif_ep[2].ep_descr.bInterval
 *
 * How the tree is built:
 *
 * usb_build_descr_tree() is responsible for the whole process.
 *
 * Next, usba_build_descr_tree() coordinates parsing this byte stream,
 * descriptor by descriptor.  usba_build_descr_tree() calls the appropriate
 * usba_process_xx_descr() function to interpret and install each descriptor in
 * the tree, based on the descriptor's type.  When done with this phase, a
 * non-sparse tree exists containing tree nodes with descriptors in the order
 * they were found in the raw data.
 *
 * All levels of the tree, except alternates, remain non-sparse.  Alternates are
 * moved, possibly, within their array, so that descriptors are indexed by their
 * alternate ID.
 *
 * The usba_reg_state_t structure maintains state of the tree-building process,
 * helping coordinate all routines involved.
 */
#define	USBA_FRAMEWORK
#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_impl.h>
#include <sys/usb/usba/usba_private.h>
#include <sys/usb/usba/hcdi_impl.h>
#include <sys/usb/hubd/hub.h>

#include <sys/usb/usba/usbai_register_impl.h>

/*
 * Header needed for use by this module only.
 * However, function may be used in V0.8 drivers so needs to be global.
 */
int usb_log_descr_tree(usb_client_dev_data_t *, usb_log_handle_t,
				uint_t, uint_t);

/* Debug stuff */
usb_log_handle_t	usbai_reg_log_handle;
uint_t			usbai_register_errlevel = USB_LOG_L2;
uint_t			usbai_register_dump_errlevel = USB_LOG_L2;
uint_t			usbai_register_errmask = (uint_t)-1;

/* Function prototypes */
static int usba_build_descr_tree(dev_info_t *, usba_device_t *,
				usb_client_dev_data_t *);
static void usba_process_cfg_descr(usba_reg_state_t *);
static int usba_process_if_descr(usba_reg_state_t *, boolean_t *);
static int usba_process_ep_descr(usba_reg_state_t *);
static int usba_process_cv_descr(usba_reg_state_t *);
static int usba_set_parse_values(dev_info_t *dip, usba_device_t *usba_device,
    usba_reg_state_t *state);
static void* usba_kmem_realloc(void *, int, int);
static void usba_augment_array(void **, uint_t, uint_t);
static void usba_make_alts_sparse(usb_alt_if_data_t **, uint_t *);

static void usba_order_tree(usba_reg_state_t *);

static void usba_free_if_array(usb_if_data_t *, uint_t);
static void usba_free_ep_array(usb_ep_data_t *, uint_t);
static void usba_free_cv_array(usb_cvs_data_t *, uint_t);

static int usba_dump_descr_tree(dev_info_t *, usb_client_dev_data_t *,
				usb_log_handle_t, uint_t, uint_t);
static void usba_dump_if(usb_if_data_t *, usb_log_handle_t,
				uint_t, uint_t, char *);
static void usba_dump_ep(uint_t, usb_ep_data_t *, usb_log_handle_t, uint_t,
				uint_t, char *);
static void usba_dump_cv(usb_cvs_data_t *, usb_log_handle_t, uint_t, uint_t,
				char *, int);
static void usba_dump_bin(uint8_t *, int, int, usb_log_handle_t,
				uint_t,  uint_t, char *, int);

/* Framework initialization. */
void
usba_usbai_register_initialization()
{
	usbai_reg_log_handle = usb_alloc_log_hdl(NULL, "usbreg",
	    &usbai_register_errlevel,
	    &usbai_register_errmask, NULL,
	    0);

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usba_usbai_register_initialization");
}


/* Framework destruction. */
void
usba_usbai_register_destroy()
{
	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usba_usbai_register destroy");

	usb_free_log_hdl(usbai_reg_log_handle);
}


/*
 * usb_client_attach:
 *
 * Arguments:
 *	dip		- pointer to devinfo node of the client
 *	version 	- USBA registration version number
 *	flags		- None used
 *
 * Return Values:
 *	USB_SUCCESS		- attach succeeded
 *	USB_INVALID_ARGS	- received null dip
 *	USB_INVALID_VERSION	- version argument is incorrect.
 *	USB_FAILURE		- other internal failure
 */
/*ARGSUSED*/
int
usb_client_attach(dev_info_t *dip, uint_t version, usb_flags_t flags)
{
	int rval;
	usba_device_t *usba_device;

	if (dip == NULL) {

		return (USB_INVALID_ARGS);
	}

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usb_client attach:");

	usba_device = usba_get_usba_device(dip);

	/*
	 * Allow exact match for legacy (DDK 0.8/9) drivers, or same major
	 * VERSion and smaller or same minor version for non-legacy drivers.
	 */
	if ((version !=
	    USBA_MAKE_VER(USBA_LEG_MAJOR_VER, USBA_LEG_MINOR_VER)) &&
	    ((USBA_GET_MAJOR(version) != USBA_MAJOR_VER) ||
	    (USBA_GET_MINOR(version) > USBA_MINOR_VER))) {
		USB_DPRINTF_L1(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
		    "Incorrect USB driver version for %s%d: found: %d.%d, "
		    "expecting %d.%d",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    USBA_GET_MAJOR(version), USBA_GET_MINOR(version),
		    USBA_MAJOR_VER, USBA_MINOR_VER);

		return (USB_INVALID_VERSION);
	}

	if (version == USBA_MAKE_VER(USBA_LEG_MAJOR_VER, USBA_LEG_MINOR_VER)) {
		USB_DPRINTF_L2(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
		    "Accepting legacy USB driver version %d.%d for %s%d",
		    USBA_LEG_MAJOR_VER, USBA_LEG_MINOR_VER,
		    ddi_driver_name(dip), ddi_get_instance(dip));
	}

	rval = ndi_prop_update_int(DDI_DEV_T_NONE, dip, "driver-major",
	    USBA_GET_MAJOR(version));
	if (rval != DDI_PROP_SUCCESS) {

		return (USB_FAILURE);
	}
	rval = ndi_prop_update_int(DDI_DEV_T_NONE, dip, "driver-minor",
	    USBA_GET_MINOR(version));
	if (rval != DDI_PROP_SUCCESS) {

		return (USB_FAILURE);
	}

	mutex_enter(&usba_device->usb_mutex);
	if (strcmp(ddi_driver_name(dip), "usb_mid") != 0) {
		usba_device->usb_client_flags[usba_get_ifno(dip)] |=
		    USBA_CLIENT_FLAG_ATTACH;
		usba_device->usb_client_attach_list->dip = dip;
	}
	mutex_exit(&usba_device->usb_mutex);

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usb_client attach: done");

	return (USB_SUCCESS);
}


/*
 * usb_client_detach:
 *	free dev_data is reg != NULL, not much else to do
 *
 * Arguments:
 *	dip		- pointer to devinfo node of the client
 *	reg		- return registration data at this address
 */
void
usb_client_detach(dev_info_t *dip, usb_client_dev_data_t *reg)
{
	usba_device_t *usba_device = usba_get_usba_device(dip);

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usb_client_detach:");

	if (dip) {
		USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
		    "Unregistering usb client %s%d: reg=0x%p",
		    ddi_driver_name(dip), ddi_get_instance(dip), (void *)reg);

		usb_free_dev_data(dip, reg);

		mutex_enter(&usba_device->usb_mutex);
		if (strcmp(ddi_driver_name(dip), "usb_mid") != 0) {
			usba_device->usb_client_flags[usba_get_ifno(dip)] &=
			    ~USBA_CLIENT_FLAG_ATTACH;
		}
		mutex_exit(&usba_device->usb_mutex);
	}

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usb_client_detach done");
}


/*
 * usb_register_client (deprecated):
 *	The client registers with USBA during attach.
 */
/*ARGSUSED*/
int
usb_register_client(dev_info_t *dip, uint_t version,
    usb_client_dev_data_t **reg, usb_reg_parse_lvl_t parse_level,
    usb_flags_t flags)
{
	int rval = usb_client_attach(dip, version, flags);

	if (rval == USB_SUCCESS) {
		rval = usb_get_dev_data(dip, reg, parse_level, flags);

		if (rval != USB_SUCCESS) {
			usb_client_detach(dip, NULL);
		}
	}

	return (rval);
}


/*
 * usb_unregister_client (deprecated):
 *	Undo the makings of usb_get_dev_data().  Free memory if allocated.
 *
 * Arguments:
 *	dip	- pointer to devinfo node of the client
 *	reg	- pointer to registration data to be freed
 */
void
usb_unregister_client(dev_info_t *dip, usb_client_dev_data_t *reg)
{
	usb_client_detach(dip, reg);
}


/*
 * usb_get_dev_data:
 *	On completion, the registration data has been initialized.
 *	Most data items are straightforward.
 *	Among the items returned in the data is the tree of
 *	parsed descriptors, in dev_cfg;	 the number of configurations parsed,
 *	in dev_n_cfg; a pointer to the current configuration in the tree,
 *	in dev_curr_cfg; the index of the first valid interface in the
 *	tree, in dev_curr_if, and a parse level that accurately reflects what
 *	is in the tree, in dev_parse_level.
 *
 *	This routine sets up directly-initialized fields, and calls
 *	usb_build_descr_tree() to parse the raw descriptors and initialize the
 *	tree.
 *
 *	Parse_level determines the extent to which the tree is built.  It has
 *	the following values:
 *
 *	USB_PARSE_LVL_NONE - Build no tree.  dev_n_cfg will return 0, dev_cfg
 *			     and dev_curr_cfg will return NULL.
 *	USB_PARSE_LVL_IF   - Parse configured interface only, if configuration#
 *			     and interface properties are set (as when different
 *			     interfaces are viewed by the OS as different device
 *			     instances). If an OS device instance is set up to
 *			     represent an entire physical device, this works
 *			     like USB_PARSE_LVL_ALL.
 *	USB_PARSE_LVL_CFG  - Parse entire configuration of configured interface
 *			     only.  This is like USB_PARSE_LVL_IF except entire
 *			     configuration is returned.
 *	USB_PARSE_LVL_ALL  - Parse entire device (all configurations), even
 *			     when driver is bound to a single interface of a
 *			     single configuration.
 *
 *	No tree is built for root hubs, regardless of parse_level.
 *
 * Arguments:
 *	dip		- pointer to devinfo node of the client
 *	version		- USBA registration version number
 *	reg		- return registration data at this address
 *	parse_level	- See above
 *	flags		- None used
 *
 * Return Values:
 *	USB_SUCCESS		- usb_get_dev_data succeeded
 *	USB_INVALID_ARGS	- received null dip or reg argument
 *	USB_INVALID_CONTEXT	- called from callback context
 *	USB_FAILURE		- bad descriptor info or other internal failure
 *
 * Note: The non-standard USB descriptors are returned in RAW format.
 *	returns initialized registration data.	Most data items are clear.
 *	Among the items returned is the tree of parsed descriptors in dev_cfg;
 *	and the number of configurations parsed in dev_n_cfg.
 *
 *	The registration data is not shared. each client receives its own
 *	copy.
 */
/*ARGSUSED*/
int
usb_get_dev_data(dev_info_t *dip,
    usb_client_dev_data_t **reg, usb_reg_parse_lvl_t parse_level,
    usb_flags_t flags)
{
	usb_client_dev_data_t	*usb_reg = NULL;
	char			*tmpbuf = NULL;
	usba_device_t		*usba_device;
	int			rval = USB_SUCCESS;

	if ((dip == NULL) || (reg == NULL)) {

		return (USB_INVALID_ARGS);
	}

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usb_get_dev_data: %s%d",
	    ddi_driver_name(dip), ddi_get_instance(dip));

	*reg = NULL;

	/* did the client attach first? */
	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "driver-major", -1) == -1) {

		return (USB_INVALID_VERSION);
	}
	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "driver-minor", -1) == -1) {

		return (USB_INVALID_VERSION);
	}

	usb_reg = kmem_zalloc(sizeof (usb_client_dev_data_t), KM_SLEEP);
	usba_device = usba_get_usba_device(dip);
	usb_reg->dev_descr = usba_device->usb_dev_descr;
	usb_reg->dev_default_ph = usba_get_dflt_pipe_handle(dip);
	if (usb_reg->dev_default_ph == NULL) {
		kmem_free(usb_reg, sizeof (usb_client_dev_data_t));

		return (USB_FAILURE);
	}

	usb_reg->dev_iblock_cookie = usba_hcdi_get_hcdi(
	    usba_device->usb_root_hub_dip)->hcdi_soft_iblock_cookie;

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "cookie = 0x%p", (void *)usb_reg->dev_iblock_cookie);

	tmpbuf = (char *)kmem_zalloc(USB_MAXSTRINGLEN, KM_SLEEP);

	if (usba_device->usb_mfg_str != NULL) {
		usb_reg->dev_mfg = kmem_zalloc(
		    strlen(usba_device->usb_mfg_str) + 1, KM_SLEEP);
		(void) strcpy(usb_reg->dev_mfg, usba_device->usb_mfg_str);
	}

	if (usba_device->usb_product_str != NULL) {
		usb_reg->dev_product = kmem_zalloc(
		    strlen(usba_device->usb_product_str) + 1,
		    KM_SLEEP);
		(void) strcpy(usb_reg->dev_product,
		    usba_device->usb_product_str);
	}

	if (usba_device->usb_serialno_str != NULL) {
		usb_reg->dev_serial = kmem_zalloc(
		    strlen(usba_device->usb_serialno_str) + 1,
		    KM_SLEEP);
		(void) strcpy(usb_reg->dev_serial,
		    usba_device->usb_serialno_str);
	}

	if ((usb_reg->dev_parse_level = parse_level) == USB_PARSE_LVL_NONE) {
		rval = USB_SUCCESS;

	} else if ((rval = usba_build_descr_tree(dip, usba_device, usb_reg)) !=
	    USB_SUCCESS) {
		usb_unregister_client(dip, usb_reg);
		usb_reg = NULL;
	} else {

		/* Current tree cfg is always zero if only one cfg in tree. */
		if (usb_reg->dev_n_cfg == 1) {
			usb_reg->dev_curr_cfg = &usb_reg->dev_cfg[0];
		} else {
			mutex_enter(&usba_device->usb_mutex);
			usb_reg->dev_curr_cfg =
			    &usb_reg->dev_cfg[usba_device->usb_active_cfg_ndx];
			mutex_exit(&usba_device->usb_mutex);
			ASSERT(usb_reg->dev_curr_cfg != NULL);
			ASSERT(usb_reg->dev_curr_cfg->cfg_descr.bLength ==
			    USB_CFG_DESCR_SIZE);
		}

		/*
		 * Keep dev_curr_if at device's single interface only if that
		 * particular interface has been explicitly defined by the
		 * device.
		 */
		usb_reg->dev_curr_if = usba_get_ifno(dip);
#ifdef DEBUG
		(void) usb_log_descr_tree(usb_reg, usbai_reg_log_handle,
		    usbai_register_dump_errlevel, (uint_t)-1);
#endif
		/*
		 * Fail if interface and configuration of dev_curr_if and
		 * dev_curr_cfg don't exist or are invalid.  (Shouldn't happen.)
		 * These indices must be reliable for tree traversal.
		 */
		if ((usb_reg->dev_curr_cfg->cfg_n_if <= usb_reg->dev_curr_if) ||
		    (usb_reg->dev_curr_cfg->cfg_descr.bLength == 0) ||
		    (usb_reg->dev_curr_cfg->cfg_if[usb_reg->dev_curr_if].
		    if_n_alt == 0)) {
			USB_DPRINTF_L2(DPRINT_MASK_ALL, usbai_reg_log_handle,
			    "usb_get_dev_data: dev_curr_cfg or "
			    "dev_curr_if have no descriptors");
			usb_unregister_client(dip, usb_reg);
			usb_reg = NULL;
			rval = USB_FAILURE;
		}
	}

	*reg = usb_reg;
	kmem_free(tmpbuf, USB_MAXSTRINGLEN);

	if (rval == USB_SUCCESS) {
		usb_client_dev_data_list_t *entry = kmem_zalloc(
		    sizeof (*entry), KM_SLEEP);
		mutex_enter(&usba_device->usb_mutex);

		usba_device->usb_client_flags[usba_get_ifno(dip)] |=
		    USBA_CLIENT_FLAG_DEV_DATA;

		entry->cddl_dip = dip;
		entry->cddl_dev_data = usb_reg;
		entry->cddl_ifno = usba_get_ifno(dip);

		entry->cddl_next =
		    usba_device->usb_client_dev_data_list.cddl_next;
		if (entry->cddl_next) {
			entry->cddl_next->cddl_prev = entry;
		}
		entry->cddl_prev = &usba_device->usb_client_dev_data_list;
		usba_device->usb_client_dev_data_list.cddl_next = entry;

		mutex_exit(&usba_device->usb_mutex);
	}

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usb_get_dev_data rval=%d", rval);

	return (rval);
}


/*
 * usb_free_dev_data
 *	undoes what usb_get_dev_data does
 *
 * Arguments:
 *	dip		- pointer to devinfo node of the client
 *	reg		- return registration data at this address
 */
void
usb_free_dev_data(dev_info_t *dip, usb_client_dev_data_t *reg)
{
	if (dip == NULL) {

		return;
	}

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usb_free_dev_data %s%d: reg=0x%p",
	    ddi_driver_name(dip), ddi_get_instance(dip), (void *)reg);

	if (reg != NULL) {
		usba_device_t *usba_device = usba_get_usba_device(dip);
		usb_client_dev_data_list_t *next, *prev, *entry;
		int	matches = 0;

		if (reg->dev_serial != NULL) {
			kmem_free((char *)reg->dev_serial,
			    strlen((char *)reg->dev_serial) + 1);
		}

		if (reg->dev_product != NULL) {
			kmem_free((char *)reg->dev_product,
			    strlen((char *)reg->dev_product) + 1);
		}

		if (reg->dev_mfg != NULL) {
			kmem_free((char *)reg->dev_mfg,
			    strlen((char *)reg->dev_mfg) + 1);
		}

		/* Free config tree under reg->dev_cfg. */
		if (reg->dev_cfg != NULL) {
			usb_free_descr_tree(dip, reg);
		}

		mutex_enter(&usba_device->usb_mutex);
		prev = &usba_device->usb_client_dev_data_list;
		entry = usba_device->usb_client_dev_data_list.cddl_next;

		/* free the entries in usb_client_data_list */
		while (entry) {
			next = entry->cddl_next;
			if ((dip == entry->cddl_dip) &&
			    (reg == entry->cddl_dev_data)) {
				prev->cddl_next = entry->cddl_next;
				if (entry->cddl_next) {
					entry->cddl_next->cddl_prev = prev;
				}
				kmem_free(entry, sizeof (*entry));
			} else {
				/*
				 * any other entries for this interface?
				 */
				if (usba_get_ifno(dip) == entry->cddl_ifno) {
					matches++;
				}
				prev = entry;
			}
			entry = next;
		}

		USB_DPRINTF_L3(DPRINT_MASK_REGISTER,
		    usbai_reg_log_handle,
		    "usb_free_dev_data: next=0x%p flags[%d]=0x%x",
		    (void *)usba_device->usb_client_dev_data_list.cddl_next,
		    usba_get_ifno(dip),
		    usba_device->usb_client_flags[usba_get_ifno(dip)]);

		if (matches == 0) {
			usba_device->
			    usb_client_flags[usba_get_ifno(dip)] &=
			    ~USBA_CLIENT_FLAG_DEV_DATA;
		}
		mutex_exit(&usba_device->usb_mutex);

		kmem_free(reg, sizeof (usb_client_dev_data_t));
	}

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usb_free_dev_data done");
}

/*
 * usba_build_descr_tree:
 *	This builds the descriptor tree.  See module header comment for tree
 *	description.
 *
 * Arguments:
 *	dip		- devinfo pointer - cannot be NULL.
 *	usba_device	- pointer to usba_device structure.
 *	usb_reg		- pointer to area returned to client describing device.
 *			  number of configuration (dev_n_cfg) and array of
 *			  configurations (dev_cfg) are initialized here -
 *			  dev_parse_level used and may be modified to fit
 *			  current configuration.
 * Return values:
 *	USB_SUCCESS	 - Tree build succeeded
 *	USB_INVALID_ARGS - dev_parse_level in usb_reg is invalid.
 *	USB_FAILURE	 - Bad descriptor info or other internal failure
 */
static int
usba_build_descr_tree(dev_info_t *dip, usba_device_t *usba_device,
    usb_client_dev_data_t *usb_reg)
{
	usba_reg_state_t state;			/* State of tree construction */
	int		cfg_len_so_far = 0;	/* Bytes found, this config. */
	uint8_t 	*last_byte;	/* Ptr to the end of the cfg cloud. */
	uint_t		this_cfg_ndx;		/* Configuration counter. */
	uint_t		high_cfg_bound;		/* High config index + 1. */
	uint_t		low_cfg_bound;		/* Low config index. */
	boolean_t	process_this_if_tree = B_FALSE; /* Save alts, eps, */
							/* of this interface. */

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usba_build_descr_tree starting");

	bzero(&state, sizeof (usba_reg_state_t));
	state.dip = dip;

	/*
	 * Set config(s) and interface(s) to parse based on parse level.
	 * Adjust parse_level according to which configs and interfaces are
	 * made available by the device.
	 */
	state.st_dev_parse_level = usb_reg->dev_parse_level;
	if (usba_set_parse_values(dip, usba_device, &state) != USB_SUCCESS) {

		return (USB_INVALID_ARGS);
	}
	usb_reg->dev_parse_level = state.st_dev_parse_level;

	/* Preallocate configurations based on parse level. */
	if (usb_reg->dev_parse_level == USB_PARSE_LVL_ALL) {
		usb_reg->dev_n_cfg = usba_device->usb_n_cfgs;
		low_cfg_bound = 0;
		high_cfg_bound = usba_device->usb_n_cfgs;
	} else {
		usb_reg->dev_n_cfg = 1;
		mutex_enter(&usba_device->usb_mutex);
		low_cfg_bound = usba_device->usb_active_cfg_ndx;
		high_cfg_bound = usba_device->usb_active_cfg_ndx + 1;
		mutex_exit(&usba_device->usb_mutex);
	}
	usb_reg->dev_cfg = state.st_dev_cfg = kmem_zalloc(
	    (usb_reg->dev_n_cfg * sizeof (usb_cfg_data_t)),
	    KM_SLEEP);
	/*
	 * this_cfg_ndx loops through all configurations presented;
	 * state.st_dev_n_cfg limits the cfgs checked to the number desired.
	 */
	state.st_dev_n_cfg = 0;
	for (this_cfg_ndx = low_cfg_bound; this_cfg_ndx < high_cfg_bound;
	    this_cfg_ndx++) {

		state.st_curr_raw_descr =
		    usba_device->usb_cfg_array[this_cfg_ndx];
		ASSERT(state.st_curr_raw_descr != NULL);

		/* Clear the following for config cloud sanity checking. */
		last_byte = NULL;
		state.st_curr_cfg = NULL;
		state.st_curr_if = NULL;
		state.st_curr_alt = NULL;
		state.st_curr_ep = NULL;

		do {
			/* All descr have length and type at offset 0 and 1 */
			state.st_curr_raw_descr_len =
			    state.st_curr_raw_descr[0];
			state.st_curr_raw_descr_type =
			    state.st_curr_raw_descr[1];

			/* First descr in cloud must be a config descr. */
			if ((last_byte == NULL) &&
			    (state.st_curr_raw_descr_type !=
			    USB_DESCR_TYPE_CFG)) {

				return (USB_FAILURE);
			}

			/*
			 * Bomb if we don't find a new cfg descr when expected.
			 * cfg_len_so_far = total_cfg_length = 0 1st time thru.
			 */
			if (cfg_len_so_far > state.st_total_cfg_length) {
				USB_DPRINTF_L2(DPRINT_MASK_ALL,
				    usbai_reg_log_handle,
				    "usba_build_descr_tree: Configuration (%d) "
				    "larger than wTotalLength (%d).",
				    cfg_len_so_far, state.st_total_cfg_length);

				return (USB_FAILURE);
			}

			USB_DPRINTF_L3(DPRINT_MASK_REGISTER,
			    usbai_reg_log_handle,
			    "usba_build_descr_tree: Process type %d descr "
			    "(addr=0x%p)", state.st_curr_raw_descr_type,
			    (void *)state.st_curr_raw_descr);

			switch (state.st_curr_raw_descr_type) {
			case USB_DESCR_TYPE_CFG:
				cfg_len_so_far = 0;
				process_this_if_tree = B_FALSE;

				state.st_curr_cfg_str = usba_device->
				    usb_cfg_str_descr[this_cfg_ndx];
				usba_process_cfg_descr(&state);
				state.st_last_processed_descr_type =
				    USB_DESCR_TYPE_CFG;
				last_byte = state.st_curr_raw_descr +
				    (state.st_total_cfg_length *
				    sizeof (uchar_t));

				break;

			case USB_DESCR_TYPE_IF:
				/*
				 * process_this_if_tree == TRUE means this
				 * interface, plus all eps and c/vs in it are
				 * to be processed.
				 */
				if (usba_process_if_descr(&state,
				    &process_this_if_tree) != USB_SUCCESS) {

					return (USB_FAILURE);
				}
				state.st_last_processed_descr_type =
				    USB_DESCR_TYPE_IF;

				break;

			case USB_DESCR_TYPE_EP:
				/*
				 * Skip if endpoints of a specific interface are
				 * desired and this endpoint is associated with
				 * a different interface.
				 */
				if (process_this_if_tree) {
					if (usba_process_ep_descr(&state) !=
					    USB_SUCCESS) {

						return (USB_FAILURE);
					}
					state.st_last_processed_descr_type =
					    USB_DESCR_TYPE_EP;
				}

				break;
			case USB_DESCR_TYPE_STRING:
				USB_DPRINTF_L2(DPRINT_MASK_ALL,
				    usbai_reg_log_handle,
				    "usb_get_dev_data: "
				    "Found unexpected str descr at addr 0x%p",
				    (void *)state.st_curr_raw_descr);

				break;	/* Shouldn't be any here.  Skip. */

			default:
				/*
				 * Treat all other descr as class/vendor
				 * specific.  Skip if c/vs of a specific
				 * interface are desired and this c/v is
				 * associated with a different one.
				 * Device level c/vs should always be
				 * processed, e.g., the security descrs
				 * for the Host Wire Adapter.
				 */
				if ((state.st_last_processed_descr_type ==
				    USB_DESCR_TYPE_CFG) ||
				    (process_this_if_tree == B_TRUE)) {
					if (usba_process_cv_descr(&state) !=
					    USB_SUCCESS) {

						return (USB_FAILURE);
					}
				}
			}

			state.st_curr_raw_descr += state.st_curr_raw_descr_len;
			cfg_len_so_far += state.st_curr_raw_descr_len;

		} while (state.st_curr_raw_descr < last_byte);
	}

	/* Make tree sparse, and put elements in order. */
	usba_order_tree(&state);

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usba_build_descr_tree done");

	return (USB_SUCCESS);
}


/*
 * usba_process_cfg_descr:
 *	Set up a configuration tree node based on a raw config descriptor.
 *
 * Arguments:
 *	state		- Pointer to this module's state structure.
 *
 * Returns:
 *	B_TRUE: the descr processed corresponds to a requested configuration.
 *	B_FALSE: the descr processed does not correspond to a requested config.
 */
static void
usba_process_cfg_descr(usba_reg_state_t *state)
{
	usb_cfg_data_t *curr_cfg;

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usba_process_cfg_descr starting");

	curr_cfg = state->st_curr_cfg =
	    &state->st_dev_cfg[state->st_dev_n_cfg++];

	/* Parse and store config descriptor proper in the tree. */
	(void) usb_parse_data("2cs5c",
	    state->st_curr_raw_descr, state->st_curr_raw_descr_len,
	    &curr_cfg->cfg_descr,
	    sizeof (usb_cfg_descr_t));

	state->st_total_cfg_length = curr_cfg->cfg_descr.wTotalLength;

	if (state->st_curr_cfg_str != NULL) {
		curr_cfg->cfg_strsize = strlen(state->st_curr_cfg_str) + 1;
		curr_cfg->cfg_str = kmem_zalloc(curr_cfg->cfg_strsize,
		    KM_SLEEP);
		(void) strcpy(curr_cfg->cfg_str, state->st_curr_cfg_str);
	}

	curr_cfg->cfg_n_if = curr_cfg->cfg_descr.bNumInterfaces;
	curr_cfg->cfg_if = kmem_zalloc((curr_cfg->cfg_n_if *
	    sizeof (usb_if_data_t)), KM_SLEEP);

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usba_process_cfg_descr done");
}


/*
 * usba_process_if_descr:
 *	This processes a raw interface descriptor, and sets up an analogous
 *	interface node and child "alternate" nodes (each containing an
 *	interface descriptor) in the descriptor tree.
 *
 *	It groups all descriptors with the same bInterfaceNumber (alternates)
 *	into an array.	It makes entries in an interface array, each of which
 *	points to an array of alternates.
 *
 * Arguments:
 *	state		- Pointer to this module's state structure.
 *	requested_if	- Address into which the following is returned:
 *	    B_TRUE	- the processed descr is of a requested interface.
 *	    B_FALSE	- the processed descr if of a non-requested interface.
 *
 * Returns:
 *	USB_SUCCESS:	Descriptor is successfully parsed.
 *	USB_FAILURE:	Descriptor is inappropriately placed in config cloud.
 */
static int
usba_process_if_descr(usba_reg_state_t *state, boolean_t *requested_if)
{
	char *string;
	usb_if_descr_t *new_if_descr;
	usba_device_t *usba_device = usba_get_usba_device(state->dip);
	int is_root_hub = (usba_device->usb_addr == ROOT_HUB_ADDR);

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usba_process_if_descr starting");

	/* No config preceeds this interface. */
	if (state->st_curr_cfg == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
		    "usba_process_if_descr found interface after no config.");

		return (USB_FAILURE);
	}

	new_if_descr = kmem_zalloc(sizeof (usb_if_descr_t), KM_SLEEP);

	/* Strictly speaking, unpacking is not necessary.  Could use bcopy. */
	(void) usb_parse_data("9c", state->st_curr_raw_descr,
	    state->st_curr_raw_descr_len,
	    new_if_descr, sizeof (usb_if_descr_t));

	/* Check the interface number in case of a malfunction device */
	if (new_if_descr->bInterfaceNumber >= state->st_curr_cfg->cfg_n_if) {
		USB_DPRINTF_L2(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
		    "usba_process_if_descr: bInterfaceNumber=%d is not "
		    "a valid one", new_if_descr->bInterfaceNumber);
		kmem_free(new_if_descr, sizeof (usb_if_descr_t));

		*requested_if = B_FALSE;

		return (USB_SUCCESS);
	}
	*requested_if = B_TRUE;

	/* Not a requested interface. */
	if ((state->st_if_to_build != new_if_descr->bInterfaceNumber) &&
	    (state->st_if_to_build != USBA_ALL)) {
		*requested_if = B_FALSE;

	} else {
		usb_alt_if_data_t *alt_array;
		uint_t		alt_index;

		/* Point to proper interface node, based on num in descr. */
		state->st_curr_if =
		    &state->st_curr_cfg->cfg_if[new_if_descr->bInterfaceNumber];

		/* Make room for new alternate. */
		alt_index = state->st_curr_if->if_n_alt;
		alt_array = state->st_curr_if->if_alt;
		usba_augment_array((void **)(&alt_array), alt_index,
		    sizeof (usb_alt_if_data_t));

		/* Ptr to the current alt, may be used to attach a c/v to it. */
		state->st_curr_alt = &alt_array[alt_index];

		bcopy(new_if_descr, &(alt_array[alt_index++].altif_descr),
		    sizeof (usb_if_descr_t));
		state->st_curr_if->if_alt = alt_array;
		state->st_curr_if->if_n_alt = alt_index;

		string = kmem_zalloc(USB_MAXSTRINGLEN, KM_SLEEP);
		if (!is_root_hub) {
			(void) usb_get_string_descr(state->dip, USB_LANG_ID,
			    state->st_curr_alt->altif_descr.iInterface,
			    string, USB_MAXSTRINGLEN);
		}
		if (string[0] == '\0') {
			(void) strcpy(string, "<none>");
		}
		state->st_curr_alt->altif_strsize = strlen(string) + 1;
		state->st_curr_alt->altif_str = kmem_zalloc(
		    state->st_curr_alt->altif_strsize, KM_SLEEP);
		(void) strcpy(state->st_curr_alt->altif_str, string);
		kmem_free(string, USB_MAXSTRINGLEN);
	}

	kmem_free(new_if_descr, sizeof (usb_if_descr_t));

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usba_process_if_descr done");

	return (USB_SUCCESS);
}


/*
 * usba_process_ep_descr:
 *	This processes a raw endpoint descriptor, and sets up an analogous
 *	endpoint descriptor node in the descriptor tree.
 *
 * Arguments:
 *	state		- Pointer to this module's state structure.
 *
 * Returns:
 *	USB_SUCCESS:	Descriptor is successfully parsed.
 *	USB_FAILURE:	Descriptor is inappropriately placed in config cloud.
 */
static int
usba_process_ep_descr(usba_reg_state_t *state)
{
	usb_alt_if_data_t *curr_alt = state->st_curr_alt;

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usba_process_ep_descr starting");

	/* No interface preceeds this endpoint. */
	if (state->st_curr_alt == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
		    "usba_process_ep_descr: no requested alt before endpt.");

		return (USB_FAILURE);
	}

	usba_augment_array((void **)(&curr_alt->altif_ep),
	    curr_alt->altif_n_ep, sizeof (usb_ep_data_t));

	/* Ptr to the current endpt, may be used to attach a c/v to it. */
	state->st_curr_ep = &curr_alt->altif_ep[curr_alt->altif_n_ep++];

	(void) usb_parse_data("4csc", state->st_curr_raw_descr,
	    state->st_curr_raw_descr_len,
	    &state->st_curr_ep->ep_descr, sizeof (usb_ep_descr_t));

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usba_process_ep_descr done");

	return (USB_SUCCESS);
}


/*
 * usba_process_cv_descr:
 *	This processes a raw endpoint descriptor, and sets up an analogous
 *	endpoint descriptor in the descriptor tree.  C/Vs are associated with
 *	other descriptors they follow in the raw data.
 *	last_processed_descr_type indicates the type of descr this c/v follows.
 *
 * Arguments:
 *	state		- Pointer to this module's state structure.
 *
 * Returns:
 *	USB_SUCCESS:	Descriptor is successfully parsed.
 *	USB_FAILURE:	Descriptor is inappropriately placed in config cloud.
 */
static int
usba_process_cv_descr(usba_reg_state_t *state)
{
	usb_cvs_data_t	*curr_cv_descr;
	usb_cvs_data_t	**cvs_ptr = NULL;
	uint_t		*n_cvs_ptr;

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usba_process_cv_descr starting.  Processing c/v for descr type %d",
	    state->st_last_processed_descr_type);

	/*
	 * Attach the c/v to a node based on the last descr type processed.
	 * Save handles to appropriate c/v node array and count to update.
	 */
	switch (state->st_last_processed_descr_type) {
	case USB_DESCR_TYPE_CFG:
		n_cvs_ptr = &state->st_curr_cfg->cfg_n_cvs;
		cvs_ptr = &state->st_curr_cfg->cfg_cvs;
		break;

	case USB_DESCR_TYPE_IF:
		n_cvs_ptr = &state->st_curr_alt->altif_n_cvs;
		cvs_ptr = &state->st_curr_alt->altif_cvs;
		break;

	case USB_DESCR_TYPE_EP:
		n_cvs_ptr = &state->st_curr_ep->ep_n_cvs;
		cvs_ptr = &state->st_curr_ep->ep_cvs;
		break;

	default:
		USB_DPRINTF_L2(DPRINT_MASK_ALL, usbai_reg_log_handle,
		    "usba_process_cv_descr: Type of last descriptor unknown. ");

		return (USB_FAILURE);
	}

	usba_augment_array((void **)cvs_ptr, *n_cvs_ptr,
	    sizeof (usb_cvs_data_t));
	curr_cv_descr = &(*cvs_ptr)[(*n_cvs_ptr)++];

	curr_cv_descr->cvs_buf =
	    kmem_zalloc(state->st_curr_raw_descr_len, KM_SLEEP);
	curr_cv_descr->cvs_buf_len = state->st_curr_raw_descr_len;
	bcopy(state->st_curr_raw_descr, curr_cv_descr->cvs_buf,
	    state->st_curr_raw_descr_len);

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usba_process_cv_descr done");

	return (USB_SUCCESS);
}


/*
 * usba_set_parse_values:
 *	Based on parse level, set the configuration(s) and interface(s) to build
 *
 *	Returned configuration value can be USBA_ALL indicating to build all
 *	configurations.  Likewise for the returned interface value.
 *
 * Arguments:
 *	dip		- pointer to devinfo of the device
 *	usba_device	- pointer to usba_device structure of the device
 *	state		- Pointer to this module's state structure.
 *			  if no specific config specified, default to all config
 *			  if no specific interface specified, default to all.
 *			  if_to_build and config_to_build are modified.
 *			  dev_parse_level may be modified.
 *
 * Returns:
 *	USB_SUCCESS	- success
 *	USB_INVALID_ARGS - state->st_dev_parse_level is invalid.
 */
static int
usba_set_parse_values(dev_info_t *dip, usba_device_t *usba_device,
    usba_reg_state_t *state)
{
	/* Default to *all* in case configuration# prop not set. */
	mutex_enter(&usba_device->usb_mutex);
	state->st_cfg_to_build = usba_device->usb_active_cfg_ndx;
	mutex_exit(&usba_device->usb_mutex);
	if (state->st_cfg_to_build == USBA_DEV_CONFIG_INDEX_UNDEFINED) {
		state->st_cfg_to_build = USBA_ALL;
	}
	state->st_if_to_build = usb_get_if_number(dip);

	switch (state->st_dev_parse_level) {
	case USB_PARSE_LVL_ALL:		/* Parse all configurations */
		state->st_cfg_to_build = USBA_ALL;
		state->st_if_to_build = USBA_ALL;
		break;

	case USB_PARSE_LVL_CFG:		/* Parse all interfaces of a */
					/* specific configuration. */
		state->st_if_to_build = USBA_ALL;
		break;

	case USB_PARSE_LVL_IF:		/* Parse configured interface only */
		if (state->st_if_to_build < 0) {
			state->st_if_to_build = USBA_ALL;
		}
		break;

	default:

		return (USB_INVALID_ARGS);
	}

	/*
	 * Set parse level to identify this tree properly, regardless of what
	 * the caller thought the tree would have.
	 */
	if ((state->st_if_to_build == USBA_ALL) &&
	    (state->st_dev_parse_level == USB_PARSE_LVL_IF)) {
		state->st_dev_parse_level = USB_PARSE_LVL_CFG;
	}
	if ((state->st_cfg_to_build == USBA_ALL) &&
	    (state->st_dev_parse_level == USB_PARSE_LVL_CFG)) {
		state->st_dev_parse_level = USB_PARSE_LVL_ALL;
	}

	return (USB_SUCCESS);
}


/*
 * usba_kmem_realloc:
 *	Resize dynamic memory.	Copy contents of old area to
 *	beginning of new area.
 *
 * Arguments:
 *	old_mem		- pointer to old memory area.
 *	old_size	- size of old memory area.  0 is OK.
 *	new_size	- size desired.
 *
 * Returns:
 *	pointer to new memory area.
 */
static void*
usba_kmem_realloc(void* old_mem, int old_size, int new_size)
{
	void *new_mem = NULL;

	if (new_size > 0) {
		new_mem = kmem_zalloc(new_size, KM_SLEEP);
		if (old_size > 0) {
			bcopy(old_mem, new_mem,
			    min(old_size, new_size));
		}
	}

	if (old_size > 0) {
		kmem_free(old_mem, old_size);
	}

	return (new_mem);
}


/*
 * usba_augment_array:
 *	Add a new element on the end of an array.
 *
 * Arguments:
 *	addr		- ptr to the array address.  Array addr will change.
 *	n_elements	- array element count.
 *	element_size	- size of an array element
 */
static void
usba_augment_array(void **addr, uint_t n_elements, uint_t element_size)
{
	*addr = usba_kmem_realloc(*addr, (n_elements * element_size),
	    ((n_elements + 1) * element_size));
}


/*
 * usba_make_alts_sparse:
 *	Disburse alternate array elements such that they are at the proper array
 *	indices for which alt they represent.  It is assumed that all key values
 *	used for ordering the elements are positive.  Original array space may
 *	be freed and new space allocated.
 *
 * Arguments:
 *	array		- pointer to alternates array; may be modified
 *	n_elements	- number of elements in the array; may be modified
 */
static void
usba_make_alts_sparse(usb_alt_if_data_t **array, uint_t *n_elements)
{
	uint_t	n_orig_elements = *n_elements;
	uint8_t smallest_value;
	uint8_t largest_value;
	uint8_t curr_value;
	uint_t	in_order = 0;
	usb_alt_if_data_t *orig_addr = *array; /* Non-sparse array base ptr */
	usb_alt_if_data_t *repl_array;	/* Base ptr to sparse array */
	uint_t	n_repl_elements;	/* Number elements in the new array */
	uint_t	i;

	/* Check for a null array. */
	if ((array == NULL) || (n_orig_elements == 0)) {

		return;
	}

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "make_sparse: array=0x%p, n_orig_elements=%d",
	    (void *)array, n_orig_elements);

	curr_value = orig_addr[0].altif_descr.bAlternateSetting;
	smallest_value = largest_value = curr_value;

	/* Figure the low-high range of the array. */
	for (i = 1; i < n_orig_elements; i++) {
		curr_value = orig_addr[i].altif_descr.bAlternateSetting;
		if (curr_value < smallest_value) {
			smallest_value = curr_value;
		} else if (curr_value > largest_value) {
			in_order++;
			largest_value = curr_value;
		}
	}
	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "make_sparse: largest=%d, smallest=%d, "
	    "order=%d",
	    largest_value, smallest_value, in_order);

	n_repl_elements = largest_value + 1;

	/*
	 * No holes to leave, array starts at zero, and everything is already
	 * in order.  Just return original array.
	 */
	if ((n_repl_elements == n_orig_elements) &&
	    ((in_order + 1) == n_orig_elements)) {
		USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
		    "No holes");

		return;
	}

	/* Allocate zeroed space for the array. */
	repl_array = kmem_zalloc(
	    (n_repl_elements * sizeof (usb_alt_if_data_t)), KM_SLEEP);

	/* Now fill in the array. */
	for (i = 0; i < n_orig_elements; i++) {
		curr_value = orig_addr[i].altif_descr.bAlternateSetting;

		/* Place in sparse array based on key. */
		USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
		    "move %lu bytes (key %d) from 0x%p to 0x%p",
		    (unsigned long)sizeof (usb_alt_if_data_t), curr_value,
		    (void *)&orig_addr[i], (void *)&repl_array[curr_value]);

		bcopy((char *)&orig_addr[i], (char *)&repl_array[curr_value],
		    sizeof (usb_alt_if_data_t));
	}

	kmem_free(*array, sizeof (usb_alt_if_data_t) * n_orig_elements);
	*array = repl_array;
	*n_elements = n_repl_elements;
}


/*
 * usba_order_tree:
 *	Take a tree as built by usba_build_descr_tree and make sure the key
 *	values of all elements match their indeces.  Proper order is implied.
 *
 * Arguments:
 *	state		- Pointer to this module's state structure.
 */
static void
usba_order_tree(usba_reg_state_t *state)
{
	usb_cfg_data_t	*this_cfg;
	usb_if_data_t	*this_if;
	uint_t		n_cfgs = state->st_dev_n_cfg;
	uint_t		cfg;
	uint_t		which_if;

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usba_order_tree:");

	for (cfg = 0; cfg < n_cfgs; cfg++) {
		this_cfg = &state->st_dev_cfg[cfg];

		for (which_if = 0; which_if < this_cfg->cfg_n_if; which_if++) {
			this_if = this_cfg->cfg_if;
			usba_make_alts_sparse(&this_if->if_alt,
			    &this_if->if_n_alt);
		}
	}
}


/*
 * usb_free_descr_tree:
 *	Take down the configuration tree.  Called internally and can be called
 *	from a driver standalone to take the tree down while leaving the rest
 *	of the registration intact.
 *
 * Arguments:
 *	dip		- pointer to devinfo of the device
 *	dev_data	- pointer to registration data containing the tree.
 */
void
usb_free_descr_tree(dev_info_t *dip, usb_client_dev_data_t *dev_data)
{
	usb_cfg_data_t *cfg_array;
	int n_cfgs;
	int cfg;

	if ((dip == NULL) || (dev_data == NULL)) {

		return;
	}
	cfg_array = dev_data->dev_cfg;
	n_cfgs = dev_data->dev_n_cfg;

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usb_free_descr_tree starting for %s%d",
	    ddi_driver_name(dip), ddi_get_instance(dip));

	for (cfg = 0; cfg < n_cfgs; cfg++) {
		if (cfg_array[cfg].cfg_if) {
			usba_free_if_array(cfg_array[cfg].cfg_if,
			    cfg_array[cfg].cfg_n_if);
		}
		if (cfg_array[cfg].cfg_cvs) {
			usba_free_cv_array(cfg_array[cfg].cfg_cvs,
			    cfg_array[cfg].cfg_n_cvs);
		}
		if (cfg_array[cfg].cfg_str) {
			kmem_free(cfg_array[cfg].cfg_str,
			    cfg_array[cfg].cfg_strsize);
		}
	}

	if (cfg_array) {
		kmem_free(cfg_array, (sizeof (usb_cfg_data_t) * n_cfgs));
	}

	dev_data->dev_parse_level = USB_PARSE_LVL_NONE;
	dev_data->dev_n_cfg = 0;
	dev_data->dev_cfg = NULL;
	dev_data->dev_curr_cfg = NULL;

	USB_DPRINTF_L4(DPRINT_MASK_REGISTER, usbai_reg_log_handle,
	    "usb_free_descr_tree done");
}


/*
 * usba_free_if_array:
 *	Free a configuration's array of interface nodes and their subtrees of
 *	interface alternate, endpoint and c/v descriptors.
 *
 * Arguments:
 *	if_array	- pointer to array of interfaces to remove.
 *	n_ifs		- number of elements in the array to remove.
 */
static void
usba_free_if_array(usb_if_data_t *if_array, uint_t n_ifs)
{
	uint_t which_if;
	uint_t which_alt;
	uint_t n_alts;
	usb_alt_if_data_t *altif;

	for (which_if = 0; which_if < n_ifs; which_if++) {
		n_alts = if_array[which_if].if_n_alt;

		/* Every interface has at least one alternate. */
		for (which_alt = 0; which_alt < n_alts; which_alt++) {
			altif = &if_array[which_if].if_alt[which_alt];
			usba_free_ep_array(altif->altif_ep, altif->altif_n_ep);
			usba_free_cv_array(altif->altif_cvs,
			    altif->altif_n_cvs);
			kmem_free(altif->altif_str, altif->altif_strsize);
		}

		kmem_free(if_array[which_if].if_alt,
		    (sizeof (usb_alt_if_data_t) * n_alts));
	}

	/* Free the interface array itself. */
	kmem_free(if_array, (sizeof (usb_if_data_t) * n_ifs));
}


/*
 * usba_free_ep_array:
 *	Free an array of endpoint nodes and their subtrees of c/v descriptors.
 *
 * Arguments:
 *	ep_array	- pointer to array of endpoints to remove.
 *	n_eps		- number of elements in the array to remove.
 */
static void
usba_free_ep_array(usb_ep_data_t *ep_array, uint_t n_eps)
{
	uint_t ep;

	for (ep = 0; ep < n_eps; ep++) {
		usba_free_cv_array(ep_array[ep].ep_cvs, ep_array[ep].ep_n_cvs);
	}

	kmem_free(ep_array, (sizeof (usb_ep_data_t) * n_eps));
}


/*
 * usba_free_cv_array:
 *	Free an array of class/vendor (c/v) descriptor nodes.
 *
 * Arguments:
 *	cv_array	- pointer to array of c/v nodes to remove.
 *	n_cvs		- number of elements in the array to remove.
 */
static void
usba_free_cv_array(usb_cvs_data_t *cv_array, uint_t n_cvs)
{
	uint_t cv_node;

	/* Free data areas hanging off of each c/v descriptor. */
	for (cv_node = 0; cv_node < n_cvs; cv_node++) {
		kmem_free(cv_array[cv_node].cvs_buf,
		    cv_array[cv_node].cvs_buf_len);
	}

	/* Free the array of cv descriptors. */
	kmem_free(cv_array, (sizeof (usb_cvs_data_t) * n_cvs));
}


/*
 * usb_log_descr_tree:
 *	Log to the usba_debug_buf a descriptor tree as returned by
 *	usbai_register_client.
 *
 * Arguments:
 *	dev_data	- pointer to registration area containing the tree
 *	log_handle	- pointer to log handle to use for dumping.
 *	level		- print level, one of USB_LOG_L0 ... USB_LOG_L4
 *			  Please see usb_log(9F) for details.
 *	mask		- print mask.  Please see usb_log(9F) for details.
 *
 * Returns:
 *	USB_SUCCESS		- tree successfully dumped
 *	USB_INVALID_CONTEXT	- called from callback context
 *	USB_INVALID_ARGS	- bad arguments given
 */
int
usb_log_descr_tree(usb_client_dev_data_t *dev_data,
    usb_log_handle_t log_handle, uint_t level, uint_t mask)
{
	return (usba_dump_descr_tree(NULL, dev_data, log_handle, level, mask));
}


/*
 * usb_print_descr_tree:
 *	Print to the screen a descriptor tree as returned by
 *	usbai_register_client.
 *
 * Arguments:
 *	dip		- pointer to devinfo of the client
 *	dev_data	- pointer to registration area containing the tree
 *
 * Returns:
 *	USB_SUCCESS		- tree successfully dumped
 *	USB_INVALID_CONTEXT	- called from callback context
 *	USB_INVALID_ARGS	- bad arguments given
 */
int
usb_print_descr_tree(dev_info_t *dip, usb_client_dev_data_t *dev_data)
{
	return (usba_dump_descr_tree(dip, dev_data, NULL, 0, 0));
}


/*
 * usba_dump_descr_tree:
 *	Dump a descriptor tree.
 *
 * Arguments:
 *	dip		- pointer to devinfo of the client.  Used when no
 *			  log_handle argument given.
 *	usb_reg		- pointer to registration area containing the tree
 *	log_handle	- pointer to log handle to use for dumping.  If NULL,
 *			  use internal log handle, which dumps to screen.
 *	level		- print level, one of USB_LOG_L0 ... USB_LOG_L4
 *			  Used only when log_handle provided.
 *	mask		- print mask, used when log_handle argument provided.
 *
 * Returns:
 *	USB_SUCCESS		- tree successfully dumped
 *	USB_INVALID_CONTEXT	- called from callback context
 *	USB_INVALID_ARGS	- bad arguments given
 */
static int
usba_dump_descr_tree(dev_info_t *dip, usb_client_dev_data_t *usb_reg,
    usb_log_handle_t log_handle, uint_t level, uint_t mask)
{
	usb_log_handle_t dump_handle;
	uint_t		dump_level;
	uint_t		dump_mask;
	int		which_config; /* Counters. */
	int		which_if;
	int		which_cv;
	usb_cfg_data_t	*config; /* ptr to current configuration tree node */
	usb_cfg_descr_t *config_descr; /* and its USB descriptor. */
	char		*string;
	char		*name_string = NULL;
	int		name_string_size;

	if ((usb_reg == NULL) || ((log_handle == NULL) && (dip == NULL))) {

		return (USB_INVALID_ARGS);
	}

	/*
	 * To keep calling this simple, kmem_zalloc with the sleep flag always.
	 * This means no interrupt context is allowed.
	 */
	if (servicing_interrupt()) {

		return (USB_INVALID_CONTEXT);
	}

	string = kmem_zalloc(USB_MAXSTRINGLEN, KM_SLEEP);

	if (log_handle != NULL) {
		dump_level = level;
		dump_mask = mask;
		dump_handle = log_handle;
	} else {
		dump_level = USB_LOG_L1;
		dump_mask = DPRINT_MASK_ALL;

		/* Build device name string. */
		(void) snprintf(string, USB_MAXSTRINGLEN,
		    "Port%d", usb_get_addr(dip));
		name_string_size = strlen(string) + 1;
		name_string = kmem_zalloc(name_string_size, KM_SLEEP);
		(void) strcpy(name_string, string);

		/* Allocate a log handle specifying the name string. */
		dump_handle = usb_alloc_log_hdl(NULL, name_string,
		    &dump_level, &dump_mask, NULL,
		    USB_FLAGS_SLEEP);
	}

	(void) usb_log(dump_handle, dump_level, dump_mask,
	    "USB descriptor tree for %s %s",
	    (usb_reg->dev_mfg != NULL ? usb_reg->dev_mfg : ""),
	    (usb_reg->dev_product != NULL ? usb_reg->dev_product : ""));
	if (usb_reg->dev_n_cfg == 0) {
		(void) usb_log(dump_handle, dump_level, dump_mask,
		    "No descriptor tree present");
	} else {
		(void) usb_log(dump_handle, dump_level, dump_mask,
		    "highest configuration found=%d", usb_reg->dev_n_cfg - 1);
	}

	for (which_config = 0; which_config < usb_reg->dev_n_cfg;
	    which_config++) {
		config = &usb_reg->dev_cfg[which_config];
		config_descr = &config->cfg_descr;
		if (config_descr->bLength == 0) {

			continue;
		}
		if (dump_level == USB_LOG_L0) {
			(void) usb_log(dump_handle, dump_level, dump_mask, " ");
		}
		(void) usb_log(dump_handle, dump_level, dump_mask,
		    "Configuration #%d (Addr= 0x%p)", which_config,
		    (void *)config);
		(void) usb_log(dump_handle, dump_level, dump_mask,
		    "String descr=%s", config->cfg_str);
		(void) usb_log(dump_handle, dump_level, dump_mask,
		    "config descr: len=%d tp=%d totLen=%d numIf=%d "
		    "cfgVal=%d att=0x%x pwr=%d",
		    config_descr->bLength, config_descr->bDescriptorType,
		    config_descr->wTotalLength, config_descr->bNumInterfaces,
		    config_descr->bConfigurationValue,
		    config_descr->bmAttributes, config_descr->bMaxPower);
		if ((config->cfg_n_if > 0) || (config->cfg_n_cvs > 0)) {
			(void) usb_log(dump_handle, dump_level, dump_mask,
			    "usb_cfg_data_t shows max if=%d "
			    "and %d cv descr(s).",
			    config->cfg_n_if - 1, config->cfg_n_cvs);
		}

		for (which_if = 0; which_if < config->cfg_n_if;
		    which_if++) {

			if (dump_level == USB_LOG_L0) {
				(void) usb_log(dump_handle, dump_level,
				    dump_mask, " ");
			}
			(void) usb_log(dump_handle, dump_level, dump_mask,
			    "	 interface #%d (0x%p)",
			    which_if, (void *)&config->cfg_if[which_if]);
			usba_dump_if(&config->cfg_if[which_if],
			    dump_handle, dump_level, dump_mask, string);
		}

		for (which_cv = 0; which_cv < config->cfg_n_cvs; which_cv++) {
			(void) usb_log(dump_handle, dump_level, dump_mask,
			    "  config cv descriptor %d (Address=0x%p)",
			    which_cv, (void *)&config->cfg_cvs[which_cv]);
			usba_dump_cv(&config->cfg_cvs[which_cv],
			    dump_handle, dump_level, dump_mask, string, 4);
		}
	}

	(void) usb_log(dump_handle, dump_level, dump_mask,
	    "Returning dev_curr_cfg:0x%p, dev_curr_if:%d",
	    (void *)usb_reg->dev_curr_cfg, usb_reg->dev_curr_if);

	if (log_handle == NULL) {
		usb_free_log_hdl(dump_handle);
	}
	if (name_string != NULL) {
		kmem_free(name_string, name_string_size);
	}
	kmem_free(string, USB_MAXSTRINGLEN);

	return (USB_SUCCESS);
}


/*
 * usba_dump_if:
 *	Dump an interface node and its branches.
 *
 * Arguments:
 *	which_if	- interface node to dump
 *	dump_handle	- write data through this log handle
 *	dump_level	- level passed to usb_log
 *	dump_mask	- mask passed to usb_log
 *	string		- temporary area used for processing
 *
 */
static void
usba_dump_if(usb_if_data_t *which_if, usb_log_handle_t dump_handle,
    uint_t dump_level, uint_t dump_mask, char *string)
{
	int		which_alt;	/* Number of alt being dumped */
	usb_alt_if_data_t *alt;		/* Pointer to it. */
	usb_if_descr_t *if_descr;	/* Pointer to its USB descr. */
	int		which_ep;	/* Endpoint counter. */
	int		which_cv;	/* C/V descr counter. */

	for (which_alt = 0; which_alt < which_if->if_n_alt; which_alt++) {
		alt = &which_if->if_alt[which_alt];
		if_descr = &alt->altif_descr;

		if (if_descr->bLength == 0) {

			continue;
		}
		if (dump_level == USB_LOG_L0) {
			(void) usb_log(dump_handle, dump_level, dump_mask, " ");
		}
		(void) usb_log(dump_handle, dump_level, dump_mask,
		    "\tAlt #%d (0x%p)", which_alt, (void *)alt);
		(void) usb_log(dump_handle, dump_level, dump_mask,
		    "\tString descr=%s", alt->altif_str);
		(void) usb_log(dump_handle, dump_level, dump_mask,
		    "\tif descr: len=%d type=%d if=%d alt=%d n_ept=%d "
		    "cls=%d sub=%d proto=%d",
		    if_descr->bLength,
		    if_descr->bDescriptorType, if_descr->bInterfaceNumber,
		    if_descr->bAlternateSetting, if_descr->bNumEndpoints,
		    if_descr->bInterfaceClass, if_descr->bInterfaceSubClass,
		    if_descr->bInterfaceProtocol);

		if ((alt->altif_n_ep > 0) || (alt->altif_n_cvs > 0)) {
			(void) usb_log(dump_handle, dump_level, dump_mask,
			    "\tusb_alt_if_data_t shows max ep=%d "
			    "and %d cv descr(s).",
			    alt->altif_n_ep - 1, alt->altif_n_cvs);
		}

		for (which_ep = 0; which_ep < alt->altif_n_ep;
		    which_ep++) {
			if (alt->altif_ep[which_ep].ep_descr.bLength == 0) {

				continue;
			}
			if (dump_level == USB_LOG_L0) {
				(void) usb_log(dump_handle, dump_level,
				    dump_mask, " ");
			}
			usba_dump_ep(which_ep, &alt->altif_ep[which_ep],
			    dump_handle, dump_level, dump_mask, string);
		}

		for (which_cv = 0; which_cv < alt->altif_n_cvs; which_cv++) {
			if (dump_level == USB_LOG_L0) {
				(void) usb_log(dump_handle, dump_level,
				    dump_mask, " ");
			}
			(void) usb_log(dump_handle, dump_level, dump_mask,
			    "\talt cv descriptor #%d (0x%p), size=%d",
			    which_cv, (void *)&alt->altif_cvs[which_cv],
			    alt->altif_cvs[which_cv].cvs_buf_len);
			usba_dump_cv(&alt->altif_cvs[which_cv],
			    dump_handle, dump_level, dump_mask, string, 2);
		}
	}
}


/*
 * usba_dump_ep:
 *	Dump an endpoint node and its branches.
 *
 * Arguments:
 *	which_ep	- index to display
 *	ep		- endpoint node to dump
 *	dump_handle	- write data through this log handle
 *	dump_level	- level passed to usb_log
 *	dump_mask	- mask passed to usb_log
 *	string		- temporary area used for processing
 *
 */
static void
usba_dump_ep(uint_t which_ep, usb_ep_data_t *ep, usb_log_handle_t dump_handle,
		uint_t dump_level, uint_t dump_mask, char *string)
{
	int which_cv;
	usb_ep_descr_t *ep_descr = &ep->ep_descr;

	(void) usb_log(dump_handle, dump_level, dump_mask,
	    "\t    endpoint[%d], epaddr=0x%x (0x%p)", which_ep,
	    ep_descr->bEndpointAddress, (void *)ep);
	(void) usb_log(dump_handle, dump_level, dump_mask,
	    "\t    len=%d type=%d attr=0x%x pktsize=%d interval=%d",
	    ep_descr->bLength, ep_descr->bDescriptorType,
	    ep_descr->bmAttributes, ep_descr->wMaxPacketSize,
	    ep_descr->bInterval);
	if (ep->ep_n_cvs > 0) {
		(void) usb_log(dump_handle, dump_level, dump_mask,
		    "\t    usb_ep_data_t shows %d cv descr(s)", ep->ep_n_cvs);
	}

	for (which_cv = 0; which_cv < ep->ep_n_cvs; which_cv++) {
		if (dump_level == USB_LOG_L0) {
			(void) usb_log(dump_handle, dump_level,
			    dump_mask, " ");
		}
		(void) usb_log(dump_handle, dump_level, dump_mask,
		    "\t    endpoint cv descriptor %d (0x%p), size=%d",
		    which_cv, (void *)&ep->ep_cvs[which_cv],
		    ep->ep_cvs[which_cv].cvs_buf_len);
		usba_dump_cv(&ep->ep_cvs[which_cv],
		    dump_handle, dump_level, dump_mask, string, 3);
	}
}


/*
 * usba_dump_cv:
 *	Dump a raw class or vendor specific descriptor.
 *
 * Arguments:
 *	cv_node		- pointer to the descriptor to dump
 *	dump_handle	- write data through this log handle
 *	dump_level	- level passed to usb_log
 *	dump_mask	- mask passed to usb_log
 *	string		- temporary area used for processing
 *	indent		- number of tabs to indent output
 *
 */
static void
usba_dump_cv(usb_cvs_data_t *cv_node, usb_log_handle_t dump_handle,
    uint_t dump_level, uint_t dump_mask, char *string, int indent)
{
	if (cv_node) {
		usba_dump_bin(cv_node->cvs_buf, cv_node->cvs_buf_len, indent,
		    dump_handle, dump_level, dump_mask, string,
		    USB_MAXSTRINGLEN);
	}
}


/*
 * usba_dump_bin:
 *	Generic byte dump function.
 *
 * Arguments:
 *	data		- pointer to the data to dump
 *	max_bytes	- amount of data to dump
 *	indent		- number of indentation levels
 *	dump_handle	- write data through this log handle
 *	dump_level	- level passed to usb_log
 *	dump_mask	- mask passed to usb_log
 *	buffer		- temporary area used for processing
 *	bufferlen	- size of the temporary string area
 *
 */
static void
usba_dump_bin(uint8_t *data, int max_bytes, int indent,
    usb_log_handle_t dump_handle, uint_t dump_level, uint_t dump_mask,
    char *buffer, int bufferlen)
{
	int i;
	int bufoffset = 0;
	int nexthere;

	if ((indent * SPACES_PER_INDENT) >
	    (bufferlen - (BINDUMP_BYTES_PER_LINE * 3))) {
		(void) usb_log(dump_handle, dump_level, dump_mask,
		    "Offset to usb_dump_bin must be %d or less.  "
		    "Setting to 0.\n",
		    (bufferlen - (BINDUMP_BYTES_PER_LINE * 3)));
		indent = 0;
	}

	/* Assume a tab is 2 four-space units. */
	for (i = 0; i < indent/2; i++) {
		buffer[bufoffset] = '\t';
		bufoffset++;
	}

	if (indent % 2) {
		(void) strcpy(&buffer[bufoffset], INDENT_SPACE_STR);
		bufoffset += SPACES_PER_INDENT;
	}

	i = 0;			/* Num dumped bytes put on this line. */
	nexthere = bufoffset;
	while (i < max_bytes) {
		(void) sprintf(&buffer[nexthere], "%2x ", *data++);
		nexthere += 3;
		i++;
		if (!(i % BINDUMP_BYTES_PER_LINE)) {
			buffer[nexthere] = '\0';
			(void) usb_log(dump_handle, dump_level, dump_mask,
			    buffer);
			nexthere = bufoffset;
		}
	}

	if (nexthere > bufoffset) {
		buffer[nexthere] = '\0';
		(void) usb_log(dump_handle, dump_level, dump_mask, buffer);
	}
}
