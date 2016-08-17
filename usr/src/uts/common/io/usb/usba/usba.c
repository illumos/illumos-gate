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
 * Copyright 2016 James S. Blachly, MD <james.blachly@gmail.com>
 */


/*
 * USBA: Solaris USB Architecture support
 */
#define	USBA_FRAMEWORK
#include <sys/usb/usba/usba_impl.h>
#include <sys/usb/usba/hcdi_impl.h>
#include <sys/usb/hubd/hub.h>
#include <sys/fs/dv_node.h>

/*
 * USBA private variables and tunables
 */
static kmutex_t	usba_mutex;

/* mutex to protect usba_root_hubs */
static kmutex_t usba_hub_mutex;

typedef struct usba_root_hub_ent {
	dev_info_t *dip;
	struct usba_root_hub_ent *next;
}usba_root_hub_ent_t;

static usba_root_hub_ent_t *usba_root_hubs = NULL;

/*
 * ddivs forced binding:
 *
 *    usbc usbc_xhubs usbc_xaddress  node name
 *
 *	0	x	x	class name or "device"
 *
 *	1	0	0	ddivs_usbc
 *	1	0	>1	ddivs_usbc except device
 *				at usbc_xaddress
 *	1	1	0	ddivs_usbc except hubs
 *	1	1	>1	ddivs_usbc except hubs and
 *				device at usbc_xaddress
 */
uint_t usba_ddivs_usbc;
uint_t usba_ddivs_usbc_xhubs;
uint_t usba_ddivs_usbc_xaddress;

uint_t usba_ugen_force_binding;

/*
 * compatible name handling
 */
/*
 * allowing for 15 compat names, plus one force bind name and
 * one possible specified client driver name
 */
#define	USBA_MAX_COMPAT_NAMES		17
#define	USBA_MAX_COMPAT_NAME_LEN	64

/* double linked list for usba_devices */
usba_list_entry_t	usba_device_list;

_NOTE(MUTEX_PROTECTS_DATA(usba_mutex, usba_device_list))

/*
 * modload support
 */

static struct modlmisc modlmisc	= {
	&mod_miscops,	/* Type	of module */
	"USBA: USB Architecture 2.0 1.66"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void	*)&modlmisc, NULL
};


static usb_log_handle_t	usba_log_handle;
uint_t		usba_errlevel = USB_LOG_L4;
uint_t		usba_errmask = (uint_t)-1;

extern usb_log_handle_t	hubdi_log_handle;

int
_init(void)
{
	int rval;

	/*
	 * usbai providing log support needs to be init'ed first
	 * and destroyed last
	 */
	usba_usbai_initialization();
	usba_usba_initialization();
	usba_usbai_register_initialization();
	usba_hcdi_initialization();
	usba_hubdi_initialization();
	usba_devdb_initialization();

	if ((rval = mod_install(&modlinkage)) != 0) {
		usba_devdb_destroy();
		usba_hubdi_destroy();
		usba_hcdi_destroy();
		usba_usbai_register_destroy();
		usba_usba_destroy();
		usba_usbai_destroy();
	}

	return (rval);
}

int
_fini()
{
	int rval;

	if ((rval = mod_remove(&modlinkage)) == 0) {
		usba_devdb_destroy();
		usba_hubdi_destroy();
		usba_hcdi_destroy();
		usba_usbai_register_destroy();
		usba_usba_destroy();
		usba_usbai_destroy();
	}

	return (rval);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

boolean_t
usba_owns_ia(dev_info_t *dip)
{
	int if_count = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "interface-count", 0);

	return ((if_count) ? B_TRUE : B_FALSE);
}

/*
 * common bus ctl for hcd, usb_mid, and hubd
 */
int
usba_bus_ctl(dev_info_t	*dip,
	dev_info_t		*rdip,
	ddi_ctl_enum_t		op,
	void			*arg,
	void			*result)
{
	dev_info_t		*child_dip = (dev_info_t *)arg;
	usba_device_t		*usba_device;
	usba_hcdi_t		*usba_hcdi;
	usba_hcdi_ops_t		*usba_hcdi_ops;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, hubdi_log_handle,
	    "usba_bus_ctl: %s%d %s%d op=%d", ddi_node_name(rdip),
	    ddi_get_instance(rdip), ddi_node_name(dip),
	    ddi_get_instance(dip), op);

	switch (op) {

	case DDI_CTLOPS_REPORTDEV:
	{
		char *name, compat_name[64], *speed;
		usba_device_t	*hub_usba_device;
		dev_info_t	*hubdip;

		usba_device = usba_get_usba_device(rdip);

		/* find the parent hub */
		hubdip = ddi_get_parent(rdip);
		while ((strcmp(ddi_driver_name(hubdip), "hubd") != 0) &&
		    !(usba_is_root_hub(hubdip))) {
			hubdip = ddi_get_parent(hubdip);
		}

		hub_usba_device = usba_get_usba_device(hubdip);

		if (usba_device) {
			if (usb_owns_device(rdip)) {
				(void) snprintf(compat_name,
				    sizeof (compat_name),
				    "usb%x,%x",
				    usba_device->usb_dev_descr->idVendor,
				    usba_device->usb_dev_descr->idProduct);
			} else if (usba_owns_ia(rdip)) {
				(void) snprintf(compat_name,
				    sizeof (compat_name),
				    "usbia%x,%x.config%x.%x",
				    usba_device->usb_dev_descr->idVendor,
				    usba_device->usb_dev_descr->idProduct,
				    usba_device->usb_cfg_value,
				    usb_get_if_number(rdip));
			} else {
				(void) snprintf(compat_name,
				    sizeof (compat_name),
				    "usbif%x,%x.config%x.%x",
				    usba_device->usb_dev_descr->idVendor,
				    usba_device->usb_dev_descr->idProduct,
				    usba_device->usb_cfg_value,
				    usb_get_if_number(rdip));
			}
			switch (usba_device->usb_port_status) {
			case USBA_HIGH_SPEED_DEV:
				speed = "hi speed (USB 2.x)";

				break;
			case USBA_LOW_SPEED_DEV:
				speed = "low speed (USB 1.x)";

				break;
			case USBA_FULL_SPEED_DEV:
			default:
				speed = "full speed (USB 1.x)";

				break;
			}

			cmn_err(CE_CONT,
			    "?USB %x.%x %s (%s) operating at %s on "
			    "USB %x.%x %s hub: "
			    "%s@%s, %s%d at bus address %d\n",
			    (usba_device->usb_dev_descr->bcdUSB & 0xff00) >> 8,
			    usba_device->usb_dev_descr->bcdUSB & 0xff,
			    (usb_owns_device(rdip) ? "device" :
			    ((usba_owns_ia(rdip) ? "interface-association" :
			    "interface"))),
			    compat_name, speed,
			    (hub_usba_device->usb_dev_descr->bcdUSB &
			    0xff00) >> 8,
			    hub_usba_device->usb_dev_descr->bcdUSB & 0xff,
			    usba_is_root_hub(hubdip) ? "root" : "external",
			    ddi_node_name(rdip), ddi_get_name_addr(rdip),
			    ddi_driver_name(rdip),
			    ddi_get_instance(rdip), usba_device->usb_addr);

			name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
			(void) usba_get_mfg_prod_sn_str(rdip, name, MAXNAMELEN);
			if (name[0] != '\0') {
				cmn_err(CE_CONT, "?%s\n", name);
			}
			kmem_free(name, MAXNAMELEN);

		} else { /* harden USBA against this case; if it happens */

			cmn_err(CE_CONT,
			    "?USB-device: %s@%s, %s%d\n",
			    ddi_node_name(rdip), ddi_get_name_addr(rdip),
			    ddi_driver_name(rdip), ddi_get_instance(rdip));
		}

		return (DDI_SUCCESS);
	}

	case DDI_CTLOPS_INITCHILD:
	{
		int			usb_addr;
		uint_t			n;
		char			name[32];
		int			*data;
		int			rval;
		int			len = sizeof (usb_addr);

		usba_hcdi	= usba_hcdi_get_hcdi(dip);
		usba_hcdi_ops	= usba_hcdi->hcdi_ops;
		ASSERT(usba_hcdi_ops != NULL);

		/*
		 * as long as the dip exists, it should have
		 * usba_device structure associated with it
		 */
		usba_device = usba_get_usba_device(child_dip);
		if (usba_device == NULL) {

			USB_DPRINTF_L2(DPRINT_MASK_USBA, hubdi_log_handle,
			    "usba_bus_ctl: DDI_NOT_WELL_FORMED (%s (0x%p))",
			    ddi_node_name(child_dip), (void *)child_dip);

			return (DDI_NOT_WELL_FORMED);
		}

		/* the dip should have an address and reg property */
		if (ddi_prop_op(DDI_DEV_T_NONE, child_dip, PROP_LEN_AND_VAL_BUF,
		    DDI_PROP_DONTPASS |	DDI_PROP_CANSLEEP, "assigned-address",
		    (caddr_t)&usb_addr,	&len) != DDI_SUCCESS) {

			USB_DPRINTF_L2(DPRINT_MASK_USBA, hubdi_log_handle,
			    "usba_bus_ctl:\n\t"
			    "%s%d %s%d op=%d rdip = 0x%p dip = 0x%p",
			    ddi_node_name(rdip), ddi_get_instance(rdip),
			    ddi_node_name(dip), ddi_get_instance(dip), op,
			    (void *)rdip, (void *)dip);

			USB_DPRINTF_L2(DPRINT_MASK_USBA, hubdi_log_handle,
			    "usba_bus_ctl: DDI_NOT_WELL_FORMED (%s (0x%p))",
			    ddi_node_name(child_dip), (void *)child_dip);

			return (DDI_NOT_WELL_FORMED);
		}

		if ((rval = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child_dip,
		    DDI_PROP_DONTPASS, "reg",
		    &data, &n)) != DDI_SUCCESS) {

			USB_DPRINTF_L2(DPRINT_MASK_USBA, hubdi_log_handle,
			    "usba_bus_ctl: %d, DDI_NOT_WELL_FORMED", rval);

			return (DDI_NOT_WELL_FORMED);
		}


		/*
		 * if the configuration is 1, the unit address is
		 * just the interface number
		 */
		if ((n == 1) || ((n > 1) && (data[1] == 1))) {
			(void) sprintf(name, "%x", data[0]);
		} else {
			(void) sprintf(name, "%x,%x", data[0], data[1]);
		}

		USB_DPRINTF_L3(DPRINT_MASK_USBA,
		    hubdi_log_handle, "usba_bus_ctl: name = %s", name);

		ddi_prop_free(data);
		ddi_set_name_addr(child_dip, name);

		/*
		 * increment the reference count for each child using this
		 * usba_device structure
		 */
		mutex_enter(&usba_device->usb_mutex);
		usba_device->usb_ref_count++;

		USB_DPRINTF_L3(DPRINT_MASK_USBA, hubdi_log_handle,
		    "usba_bus_ctl: init usba_device = 0x%p ref_count = %d",
		    (void *)usba_device, usba_device->usb_ref_count);

		mutex_exit(&usba_device->usb_mutex);

		return (DDI_SUCCESS);
	}

	case DDI_CTLOPS_UNINITCHILD:
	{
		usba_device = usba_get_usba_device(child_dip);

		if (usba_device != NULL) {
			/*
			 * decrement the reference count for each child
			 * using this  usba_device structure
			 */
			mutex_enter(&usba_device->usb_mutex);
			usba_device->usb_ref_count--;

			USB_DPRINTF_L3(DPRINT_MASK_USBA, hubdi_log_handle,
			    "usba_hcdi_bus_ctl: uninit usba_device=0x%p "
			    "ref_count=%d",
			    (void *)usba_device, usba_device->usb_ref_count);

			mutex_exit(&usba_device->usb_mutex);
		}
		ddi_set_name_addr(child_dip, NULL);

		return (DDI_SUCCESS);
	}

	case DDI_CTLOPS_IOMIN:
		/* Do nothing */
		return (DDI_SUCCESS);

	/*
	 * These ops correspond	to functions that "shouldn't" be called
	 * by a	USB client driver.  So	we whine when we're called.
	 */
	case DDI_CTLOPS_DMAPMAPC:
	case DDI_CTLOPS_REPORTINT:
	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
	case DDI_CTLOPS_SIDDEV:
	case DDI_CTLOPS_SLAVEONLY:
	case DDI_CTLOPS_AFFINITY:
	case DDI_CTLOPS_POKE:
	case DDI_CTLOPS_PEEK:
		cmn_err(CE_CONT, "%s%d:	invalid	op (%d)	from %s%d",
		    ddi_node_name(dip), ddi_get_instance(dip),
		    op, ddi_node_name(rdip), ddi_get_instance(rdip));
		return (DDI_FAILURE);

	/*
	 * Everything else (e.g. PTOB/BTOP/BTOPR requests) we pass up
	 */
	default:
		return (ddi_ctlops(dip,	rdip, op, arg, result));
	}
}


/*
 * initialize and destroy USBA module
 */
void
usba_usba_initialization()
{
	usba_log_handle = usb_alloc_log_hdl(NULL, "usba", &usba_errlevel,
	    &usba_errmask, NULL, 0);

	USB_DPRINTF_L4(DPRINT_MASK_USBA,
	    usba_log_handle, "usba_usba_initialization");

	mutex_init(&usba_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&usba_hub_mutex, NULL, MUTEX_DRIVER, NULL);
	usba_init_list(&usba_device_list, NULL, NULL);
}


void
usba_usba_destroy()
{
	USB_DPRINTF_L4(DPRINT_MASK_USBA, usba_log_handle, "usba_usba_destroy");

	mutex_destroy(&usba_hub_mutex);
	mutex_destroy(&usba_mutex);
	usba_destroy_list(&usba_device_list);

	usb_free_log_hdl(usba_log_handle);
}


/*
 * usba_set_usb_address:
 *	set usb address in usba_device structure
 */
int
usba_set_usb_address(usba_device_t *usba_device)
{
	usb_addr_t address;
	uchar_t s = 8;
	usba_hcdi_t *hcdi;
	char *usb_address_in_use;

	mutex_enter(&usba_device->usb_mutex);

	hcdi = usba_hcdi_get_hcdi(usba_device->usb_root_hub_dip);

	mutex_enter(&hcdi->hcdi_mutex);
	usb_address_in_use = hcdi->hcdi_usb_address_in_use;

	for (address = ROOT_HUB_ADDR + 1;
	    address <= USBA_MAX_ADDRESS; address++) {
		if (usb_address_in_use[address/s] & (1 << (address % s))) {
			continue;
		}
		usb_address_in_use[address/s] |= (1 << (address % s));
		hcdi->hcdi_device_count++;
		HCDI_HOTPLUG_STATS_DATA(hcdi)->hcdi_device_count.value.ui64++;
		mutex_exit(&hcdi->hcdi_mutex);

		USB_DPRINTF_L3(DPRINT_MASK_USBA, usba_log_handle,
		    "usba_set_usb_address: %d", address);

		usba_device->usb_addr = address;

		mutex_exit(&usba_device->usb_mutex);

		return (USB_SUCCESS);
	}

	usba_device->usb_addr = 0;

	USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
	    "no usb address available");

	mutex_exit(&hcdi->hcdi_mutex);
	mutex_exit(&usba_device->usb_mutex);

	return (USB_FAILURE);
}


/*
 * usba_unset_usb_address:
 *	unset usb_address in usba_device structure
 */
void
usba_unset_usb_address(usba_device_t *usba_device)
{
	usb_addr_t address;
	usba_hcdi_t *hcdi;
	uchar_t s = 8;
	char *usb_address_in_use;

	mutex_enter(&usba_device->usb_mutex);
	address = usba_device->usb_addr;
	hcdi = usba_hcdi_get_hcdi(usba_device->usb_root_hub_dip);

	if (address > ROOT_HUB_ADDR) {
		USB_DPRINTF_L3(DPRINT_MASK_USBA, usba_log_handle,
		    "usba_unset_usb_address: address=%d", address);

		mutex_enter(&hcdi->hcdi_mutex);
		usb_address_in_use = hcdi->hcdi_usb_address_in_use;

		ASSERT(usb_address_in_use[address/s] & (1 << (address % s)));

		usb_address_in_use[address/s] &= ~(1 << (address % s));

		hcdi->hcdi_device_count--;
		HCDI_HOTPLUG_STATS_DATA(hcdi)->hcdi_device_count.value.ui64--;

		mutex_exit(&hcdi->hcdi_mutex);

		usba_device->usb_addr = 0;
	}
	mutex_exit(&usba_device->usb_mutex);
}


struct usba_evdata *
usba_get_evdata(dev_info_t *dip)
{
	usba_evdata_t *evdata;
	usba_device_t *usba_device = usba_get_usba_device(dip);

	/* called when dip attaches */
	ASSERT(usba_device != NULL);

	mutex_enter(&usba_device->usb_mutex);
	evdata = usba_device->usb_evdata;
	while (evdata) {
		if (evdata->ev_dip == dip) {
			mutex_exit(&usba_device->usb_mutex);

			return (evdata);
		}
		evdata = evdata->ev_next;
	}

	evdata = kmem_zalloc(sizeof (usba_evdata_t), KM_SLEEP);
	evdata->ev_dip = dip;
	evdata->ev_next = usba_device->usb_evdata;
	usba_device->usb_evdata = evdata;
	mutex_exit(&usba_device->usb_mutex);

	return (evdata);
}


/*
 * allocate a usb device structure and link it in the list
 */
usba_device_t *
usba_alloc_usba_device(dev_info_t *root_hub_dip)
{
	usba_device_t	*usba_device;
	int		ep_idx;
	ddi_iblock_cookie_t iblock_cookie =
	    usba_hcdi_get_hcdi(root_hub_dip)->hcdi_iblock_cookie;

	/*
	 * create a new usba_device structure
	 */
	usba_device = kmem_zalloc(sizeof (usba_device_t), KM_SLEEP);

	/*
	 * initialize usba_device
	 */
	mutex_init(&usba_device->usb_mutex, NULL, MUTEX_DRIVER,
	    iblock_cookie);

	usba_init_list(&usba_device->usb_device_list, (usb_opaque_t)usba_device,
	    iblock_cookie);
	usba_init_list(&usba_device->usb_allocated, (usb_opaque_t)usba_device,
	    iblock_cookie);
	mutex_enter(&usba_device->usb_mutex);
	usba_device->usb_root_hub_dip = root_hub_dip;

	/*
	 * add to list of usba_devices
	 */
	usba_add_to_list(&usba_device_list, &usba_device->usb_device_list);

	/* init mutex in each usba_ph_impl structure */
	for (ep_idx = 0; ep_idx < USBA_N_ENDPOINTS; ep_idx++) {
		mutex_init(&usba_device->usb_ph_list[ep_idx].usba_ph_mutex,
		    NULL, MUTEX_DRIVER, iblock_cookie);
	}

	USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
	    "allocated usba_device 0x%p", (void *)usba_device);

	mutex_exit(&usba_device->usb_mutex);

	return (usba_device);
}


/* free NDI event data associated with usba_device */
void
usba_free_evdata(usba_evdata_t *evdata)
{
	usba_evdata_t *next;

	while (evdata) {
		next = evdata->ev_next;
		kmem_free(evdata, sizeof (usba_evdata_t));
		evdata = next;
	}
}


/*
 * free usb device structure
 */
void
usba_free_usba_device(usba_device_t *usba_device)
{
	int			i, ep_idx;
	usb_pipe_handle_t	def_ph;

	if (usba_device == NULL) {

		return;
	}

	mutex_enter(&usba_device->usb_mutex);
	if (usba_device->usb_ref_count) {
		mutex_exit(&usba_device->usb_mutex);

		return;
	}

	USB_DPRINTF_L3(DPRINT_MASK_USBA, usba_log_handle,
	    "usba_free_usba_device 0x%p, address=0x%x, ref cnt=%d",
	    (void *)usba_device, usba_device->usb_addr,
	    usba_device->usb_ref_count);

	usba_free_evdata(usba_device->usb_evdata);
	mutex_exit(&usba_device->usb_mutex);

	def_ph = usba_usbdev_to_dflt_pipe_handle(usba_device);
	if (def_ph != NULL) {
		usba_pipe_handle_data_t	*ph_data = usba_get_ph_data(def_ph);

		if (ph_data) {
			usb_pipe_close(ph_data->p_dip, def_ph,
			    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED,
			    NULL, NULL);
		}
	}

	mutex_enter(&usba_mutex);

	/* destroy mutex in each usba_ph_impl structure */
	for (ep_idx = 0; ep_idx < USBA_N_ENDPOINTS; ep_idx++) {
		mutex_destroy(&usba_device->usb_ph_list[ep_idx].usba_ph_mutex);
	}

	(void) usba_rm_from_list(&usba_device_list,
	    &usba_device->usb_device_list);

	mutex_exit(&usba_mutex);

	usba_destroy_list(&usba_device->usb_device_list);
	usba_destroy_list(&usba_device->usb_allocated);

	USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
	    "deallocating usba_device = 0x%p, address = 0x%x",
	    (void *)usba_device, usba_device->usb_addr);

	/*
	 * ohci allocates descriptors for root hub so we can't
	 * deallocate these here
	 */

	if (usba_device->usb_addr != ROOT_HUB_ADDR) {
		if (usba_device->usb_cfg_array) {
			USB_DPRINTF_L3(DPRINT_MASK_USBA, usba_log_handle,
			    "deallocating usb_config_array: 0x%p",
			    (void *)usba_device->usb_cfg_array);
			mutex_enter(&usba_device->usb_mutex);
			for (i = 0;
			    i < usba_device->usb_dev_descr->bNumConfigurations;
			    i++) {
				if (usba_device->usb_cfg_array[i]) {
					kmem_free(
					    usba_device->usb_cfg_array[i],
					    usba_device->usb_cfg_array_len[i]);
				}
			}

			/* free the array pointers */
			kmem_free(usba_device->usb_cfg_array,
			    usba_device->usb_cfg_array_length);
			kmem_free(usba_device->usb_cfg_array_len,
			    usba_device->usb_cfg_array_len_length);

			mutex_exit(&usba_device->usb_mutex);
		}

		if (usba_device->usb_cfg_str_descr) {
			USB_DPRINTF_L3(DPRINT_MASK_USBA, usba_log_handle,
			    "deallocating usb_cfg_str_descr: 0x%p",
			    (void *)usba_device->usb_cfg_str_descr);
			for (i = 0;
			    i < usba_device->usb_dev_descr->bNumConfigurations;
			    i++) {
				if (usba_device->usb_cfg_str_descr[i]) {
					kmem_free(
					    usba_device->usb_cfg_str_descr[i],
					    strlen(usba_device->
					    usb_cfg_str_descr[i]) + 1);
				}
			}
			/* free the array pointers */
			kmem_free(usba_device->usb_cfg_str_descr,
			    sizeof (uchar_t *) * usba_device->usb_n_cfgs);
		}

		if (usba_device->usb_dev_descr) {
			kmem_free(usba_device->usb_dev_descr,
			    sizeof (usb_dev_descr_t));
		}

		if (usba_device->usb_mfg_str) {
			kmem_free(usba_device->usb_mfg_str,
			    strlen(usba_device->usb_mfg_str) + 1);
		}

		if (usba_device->usb_product_str) {
			kmem_free(usba_device->usb_product_str,
			    strlen(usba_device->usb_product_str) + 1);
		}

		if (usba_device->usb_serialno_str) {
			kmem_free(usba_device->usb_serialno_str,
			    strlen(usba_device->usb_serialno_str) + 1);
		}

		usba_unset_usb_address(usba_device);
	}

#ifndef __lock_lint
	ASSERT(usba_device->usb_client_dev_data_list.cddl_next == NULL);
#endif

	if (usba_device->usb_client_flags) {
#ifndef __lock_lint
		int i;

		for (i = 0; i < usba_device->usb_n_ifs; i++) {
			ASSERT(usba_device->usb_client_flags[i] == 0);
		}
#endif
		kmem_free(usba_device->usb_client_flags,
		    usba_device->usb_n_ifs * USBA_CLIENT_FLAG_SIZE);
	}


	if (usba_device->usb_client_attach_list) {
		kmem_free(usba_device->usb_client_attach_list,
		    usba_device->usb_n_ifs *
		    sizeof (*usba_device->usb_client_attach_list));
	}
	if (usba_device->usb_client_ev_cb_list) {
		kmem_free(usba_device->usb_client_ev_cb_list,
		    usba_device->usb_n_ifs *
		    sizeof (*usba_device->usb_client_ev_cb_list));
	}

	/*
	 * finally ready to destroy the structure
	 */
	mutex_destroy(&usba_device->usb_mutex);

	kmem_free((caddr_t)usba_device, sizeof (usba_device_t));
}


/* clear the data toggle for all endpoints on this device */
void
usba_clear_data_toggle(usba_device_t *usba_device)
{
	int	i;

	if (usba_device != NULL) {
		mutex_enter(&usba_device->usb_mutex);
		for (i = 0; i < USBA_N_ENDPOINTS; i++) {
			usba_device->usb_ph_list[i].usba_ph_flags &=
			    ~USBA_PH_DATA_TOGGLE;
		}
		mutex_exit(&usba_device->usb_mutex);
	}
}


/*
 * usba_create_child_devi():
 *	create a child devinfo node, usba_device, attach properties.
 *	the usba_device structure is shared between all interfaces
 */
int
usba_create_child_devi(dev_info_t	*dip,
		char			*node_name,
		usba_hcdi_ops_t		*usba_hcdi_ops,
		dev_info_t		*usb_root_hub_dip,
		usb_port_status_t	port_status,
		usba_device_t		*usba_device,
		dev_info_t		**child_dip)
{
	int rval = USB_FAILURE;
	int usba_device_allocated = 0;
	usb_addr_t	address;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usba_log_handle,
	    "usba_create_child_devi: %s usba_device=0x%p "
	    "port status=0x%x", node_name,
	    (void *)usba_device, port_status);

	ndi_devi_alloc_sleep(dip, node_name, (pnode_t)DEVI_SID_NODEID,
	    child_dip);

	USB_DPRINTF_L3(DPRINT_MASK_USBA, usba_log_handle,
	    "child dip=0x%p", (void *)*child_dip);

	if (usba_device == NULL) {

		usba_device = usba_alloc_usba_device(usb_root_hub_dip);

		/* grab the mutex to keep warlock happy */
		mutex_enter(&usba_device->usb_mutex);
		usba_device->usb_hcdi_ops	= usba_hcdi_ops;
		usba_device->usb_port_status	= port_status;
		mutex_exit(&usba_device->usb_mutex);

		usba_device_allocated++;
	} else {
		mutex_enter(&usba_device->usb_mutex);
		if (usba_hcdi_ops) {
			ASSERT(usba_device->usb_hcdi_ops == usba_hcdi_ops);
		}
		if (usb_root_hub_dip) {
			ASSERT(usba_device->usb_root_hub_dip ==
			    usb_root_hub_dip);
		}

		usba_device->usb_port_status	= port_status;

		mutex_exit(&usba_device->usb_mutex);
	}

	if (usba_device->usb_addr == 0) {
		if (usba_set_usb_address(usba_device) == USB_FAILURE) {
			address = 0;

			USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
			    "cannot set usb address for dip=0x%p",
			    (void *)*child_dip);

			goto fail;
		}
	}
	address = usba_device->usb_addr;

	/* attach properties */
	rval = ndi_prop_update_int(DDI_DEV_T_NONE, *child_dip,
	    "assigned-address", address);
	if (rval != DDI_PROP_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
		    "cannot set usb address property for dip=0x%p",
		    (void *)*child_dip);
		rval = USB_FAILURE;

		goto fail;
	}

	/*
	 * store the usba_device point in the dip
	 */
	usba_set_usba_device(*child_dip, usba_device);

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usba_log_handle,
	    "usba_create_child_devi: devi=0x%p (%s) ud=0x%p",
	    (void *)*child_dip, ddi_driver_name(*child_dip),
	    (void *)usba_device);

	return (USB_SUCCESS);

fail:
	if (*child_dip) {
		int rval = usba_destroy_child_devi(*child_dip, NDI_DEVI_REMOVE);
		ASSERT(rval == USB_SUCCESS);
		*child_dip = NULL;
	}

	if (usba_device_allocated) {
		usba_free_usba_device(usba_device);
	} else if (address && usba_device) {
		usba_unset_usb_address(usba_device);
	}

	USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
	    "usba_create_child_devi failed: rval=%d", rval);

	return (rval);
}


int
usba_destroy_child_devi(dev_info_t *dip, uint_t flag)
{
	usba_device_t	*usba_device;
	int		rval = NDI_SUCCESS;

	USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
	    "usba_destroy_child_devi: %s%d (0x%p)",
	    ddi_driver_name(dip), ddi_get_instance(dip), (void *)dip);

	usba_device = usba_get_usba_device(dip);

	/*
	 * if the child hasn't been bound yet, we can just
	 * free the dip
	 */
	if (i_ddi_node_state(dip) < DS_INITIALIZED) {
		/*
		 * do not call ndi_devi_free() since it might
		 * deadlock
		 */
		rval = ddi_remove_child(dip, 0);

	} else {
		char *devnm = kmem_alloc(MAXNAMELEN + 1, KM_SLEEP);
		dev_info_t *pdip = ddi_get_parent(dip);

		(void) ddi_deviname(dip, devnm);

		USB_DPRINTF_L3(DPRINT_MASK_USBA, usba_log_handle,
		    "usba_destroy_child_devi:\n\t"
		    "offlining dip 0x%p usba_device=0x%p (%s)", (void *)dip,
		    (void *)usba_device, devnm);

		(void) devfs_clean(pdip, NULL, DV_CLEAN_FORCE);
		rval =	ndi_devi_unconfig_one(pdip, devnm + 1, NULL,
		    flag | NDI_UNCONFIG | NDI_DEVI_OFFLINE);
		if (rval != NDI_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
			    " ndi_devi_unconfig_one %s%d failed (%d)",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    rval);
		}
		kmem_free(devnm, MAXNAMELEN + 1);
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usba_log_handle,
	    "usba_destroy_child_devi: rval=%d", rval);

	return (rval == NDI_SUCCESS ? USB_SUCCESS : USB_FAILURE);
}


/*
 * list management
 */
void
usba_init_list(usba_list_entry_t *element, usb_opaque_t private,
	ddi_iblock_cookie_t	iblock_cookie)
{
	mutex_init(&element->list_mutex, NULL, MUTEX_DRIVER,
	    iblock_cookie);
	mutex_enter(&element->list_mutex);
	element->private = private;
	mutex_exit(&element->list_mutex);
}


void
usba_destroy_list(usba_list_entry_t *head)
{
	mutex_enter(&head->list_mutex);
	ASSERT(head->next == NULL);
	ASSERT(head->prev == NULL);
	mutex_exit(&head->list_mutex);

	mutex_destroy(&head->list_mutex);
}


void
usba_add_to_list(usba_list_entry_t *head, usba_list_entry_t *element)
{
	usba_list_entry_t *next;
	int		remaining;

	mutex_enter(&head->list_mutex);
	mutex_enter(&element->list_mutex);

	remaining = head->count;

	/* check if it is not in another list */
	ASSERT(element->next == NULL);
	ASSERT(element->prev == NULL);

#ifdef DEBUG
	/*
	 * only verify the list when not in interrupt context, we
	 * have to trust the HCD
	 */
	if (!servicing_interrupt()) {

		/* check if not already in this list */
		for (next = head->next; (next != NULL);
		    next = next->next) {
			if (next == element) {
				USB_DPRINTF_L0(DPRINT_MASK_USBA,
				    usba_log_handle,
				    "Attempt to corrupt USB list at 0x%p",
				    (void *)head);
				ASSERT(next == element);

				goto done;
			}
			remaining--;

			/*
			 * Detect incorrect circ links or found
			 * unexpected elements.
			 */
			if ((next->next && (remaining == 0)) ||
			    ((next->next == NULL) && remaining)) {
				panic("Corrupted USB list at 0x%p",
				    (void *)head);
				/*NOTREACHED*/
			}
		}
	}
#endif

	if (head->next == NULL) {
		head->prev = head->next = element;
	} else {
		/* add to tail */
		head->prev->next = element;
		element->prev = head->prev;
		head->prev = element;
	}

	head->count++;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usba_log_handle,
	    "usba_add_to_list: head=0x%p element=0x%p count=%d",
	    (void *)head, (void *)element, head->count);

done:
	mutex_exit(&head->list_mutex);
	mutex_exit(&element->list_mutex);
}


int
usba_rm_from_list(usba_list_entry_t *head, usba_list_entry_t *element)
{
	usba_list_entry_t *e;
	int		found = 0;
	int		remaining;

	/* find the element in the list first */
	mutex_enter(&head->list_mutex);

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usba_log_handle,
	    "usba_rm_from_list: head=0x%p element=0x%p count=%d",
	    (void *)head, (void *)element, head->count);

	remaining = head->count;
	e = head->next;

	while (e) {
		if (e == element) {
			found++;
			break;
		}
		e = e->next;

		remaining--;

		/* Detect incorrect circ links or found unexpected elements. */
		if ((e && (remaining == 0)) ||
		    ((e == NULL) && (remaining))) {
			panic("Corrupted USB list at 0x%p", (void *)head);
			/*NOTREACHED*/
		}
	}

	if (!found) {
		mutex_exit(&head->list_mutex);

		return (USB_FAILURE);
	}

	/* now remove the element */
	mutex_enter(&element->list_mutex);

	if (element->next) {
		element->next->prev = element->prev;
	}
	if (element->prev) {
		element->prev->next = element->next;
	}
	if (head->next == element) {
		head->next = element->next;
	}
	if (head->prev == element) {
		head->prev = element->prev;
	}

	element->prev = element->next = NULL;
	if (head->next == NULL) {
		ASSERT(head->prev == NULL);
	} else {
		ASSERT(head->next->prev == NULL);
	}
	if (head->prev == NULL) {
		ASSERT(head->next == NULL);
	} else {
		ASSERT(head->prev->next == NULL);
	}

	head->count--;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usba_log_handle,
	    "usba_rm_from_list success: head=0x%p element=0x%p cnt=%d",
	    (void *)head, (void *)element, head->count);

	mutex_exit(&element->list_mutex);
	mutex_exit(&head->list_mutex);

	return (USB_SUCCESS);
}


usba_list_entry_t *
usba_rm_first_from_list(usba_list_entry_t *head)
{
	usba_list_entry_t *element = NULL;

	if (head) {
		mutex_enter(&head->list_mutex);
		element = head->next;
		if (element) {
			/* now remove the element */
			mutex_enter(&element->list_mutex);
			head->next = element->next;
			if (head->next) {
				head->next->prev = NULL;
			}
			if (head->prev == element) {
				head->prev = element->next;
			}
			element->prev = element->next = NULL;
			mutex_exit(&element->list_mutex);
			head->count--;
		}
		if (head->next == NULL) {
			ASSERT(head->prev == NULL);
		} else {
			ASSERT(head->next->prev == NULL);
		}
		if (head->prev == NULL) {
			ASSERT(head->next == NULL);
		} else {
			ASSERT(head->prev->next == NULL);
		}
		USB_DPRINTF_L4(DPRINT_MASK_USBA, usba_log_handle,
		    "usba_rm_first_from_list: head=0x%p el=0x%p cnt=%d",
		    (void *)head, (void *)element, head->count);

		mutex_exit(&head->list_mutex);
	}

	return (element);
}


usb_opaque_t
usba_rm_first_pvt_from_list(usba_list_entry_t *head)
{
	usba_list_entry_t *element = usba_rm_first_from_list(head);
	usb_opaque_t private = NULL;

	if (element) {
		mutex_enter(&element->list_mutex);
		private = element->private;
		mutex_exit(&element->list_mutex);
	}

	return (private);
}


/*
 * move list to new list and zero original list
 */
void
usba_move_list(usba_list_entry_t *head, usba_list_entry_t *new,
	ddi_iblock_cookie_t iblock_cookie)
{
	usba_init_list(new, NULL, iblock_cookie);
	mutex_enter(&head->list_mutex);
	mutex_enter(&new->list_mutex);

	new->next = head->next;
	new->prev = head->prev;
	new->count = head->count;
	new->private = head->private;

	head->next = NULL;
	head->prev = NULL;
	head->count = 0;
	head->private = NULL;
	mutex_exit(&head->list_mutex);
	mutex_exit(&new->list_mutex);
}


int
usba_check_in_list(usba_list_entry_t *head, usba_list_entry_t *element)
{
	int		rval = USB_FAILURE;
	int		remaining;
	usba_list_entry_t *next;

	mutex_enter(&head->list_mutex);
	remaining = head->count;

	mutex_enter(&element->list_mutex);
	for (next = head->next; next != NULL; next = next->next) {
		if (next == element) {
			rval = USB_SUCCESS;
			break;
		}
		remaining--;

		/* Detect incorrect circ links or found unexpected elements. */
		if ((next->next && (remaining == 0)) ||
		    ((next->next == NULL) && remaining)) {
			panic("Corrupted USB list at 0x%p", (void *)head);
			/*NOTREACHED*/
		}
	}
	mutex_exit(&element->list_mutex);
	mutex_exit(&head->list_mutex);

	return (rval);
}


int
usba_list_entry_leaks(usba_list_entry_t *head, char *what)
{
	int		count = 0;
	int		remaining;
	usba_list_entry_t *next;

	mutex_enter(&head->list_mutex);
	remaining = head->count;
	for (next = head->next; next != NULL; next = next->next) {
		USB_DPRINTF_L2(DPRINT_MASK_HCDI, usba_log_handle,
		    "leaking %s 0x%p", what, (void *)next->private);
		count++;

		remaining--;

		/* Detect incorrect circ links or found unexpected elements. */
		if ((next->next && (remaining == 0)) ||
		    ((next->next == NULL) && remaining)) {
			panic("Corrupted USB list at 0x%p", (void *)head);
			/*NOTREACHED*/
		}
	}
	ASSERT(count == head->count);
	mutex_exit(&head->list_mutex);

	if (count) {
		USB_DPRINTF_L2(DPRINT_MASK_HCDI, usba_log_handle,
		    "usba_list_entry_count: leaking %d", count);
	}

	return (count);
}


int
usba_list_entry_count(usba_list_entry_t *head)
{
	int count;

	mutex_enter(&head->list_mutex);
	count = head->count;
	mutex_exit(&head->list_mutex);

	return (count);
}

/* add a new root hub to the usba_root_hubs list */

void
usba_add_root_hub(dev_info_t *dip)
{
	usba_root_hub_ent_t *hub;

	hub = (usba_root_hub_ent_t *)
	    kmem_zalloc(sizeof (usba_root_hub_ent_t), KM_SLEEP);

	mutex_enter(&usba_hub_mutex);
	hub->dip = dip;
	hub->next = usba_root_hubs;
	usba_root_hubs = hub;
	mutex_exit(&usba_hub_mutex);
}

/* remove a root hub from the usba_root_hubs list */

void
usba_rem_root_hub(dev_info_t *dip)
{
	usba_root_hub_ent_t **hubp, *hub;

	mutex_enter(&usba_hub_mutex);
	hubp = &usba_root_hubs;
	while (*hubp) {
		if ((*hubp)->dip == dip) {
			hub = *hubp;
			*hubp = hub->next;
			kmem_free(hub, sizeof (struct usba_root_hub_ent));
			mutex_exit(&usba_hub_mutex);

			return;
		}
		hubp = &(*hubp)->next;
	}
	mutex_exit(&usba_hub_mutex);
}

/*
 * check whether this dip is the root hub. Any root hub known by
 * usba is recorded in the linked list pointed to by usba_root_hubs
 */
int
usba_is_root_hub(dev_info_t *dip)
{
	usba_root_hub_ent_t *hub;

	mutex_enter(&usba_hub_mutex);
	hub = usba_root_hubs;
	while (hub) {
		if (hub->dip == dip) {
			mutex_exit(&usba_hub_mutex);

			return (1);
		}
		hub = hub->next;
	}
	mutex_exit(&usba_hub_mutex);

	return (0);
}

/*
 * get and store usba_device pointer in the devi
 */
usba_device_t *
usba_get_usba_device(dev_info_t *dip)
{
	/*
	 * we cannot use parent_data in the usb node because its
	 * bus parent (eg. PCI nexus driver) uses this data
	 *
	 * we cannot use driver data in the other usb nodes since
	 * usb drivers may need to use this
	 */
	if (usba_is_root_hub(dip)) {
		usba_hcdi_t *hcdi = usba_hcdi_get_hcdi(dip);

		return (hcdi->hcdi_usba_device);
	} else {

		return (ddi_get_parent_data(dip));
	}
}


/*
 * Retrieve the usba_device pointer from the dev without checking for
 * the root hub first.	This function is only used in polled mode.
 */
usba_device_t *
usba_polled_get_usba_device(dev_info_t *dip)
{
	/*
	 * Don't call usba_is_root_hub() to find out if this is
	 * the root hub  usba_is_root_hub() calls into the DDI
	 * where there are locking issues. The dip sent in during
	 * polled mode will never be the root hub, so just get
	 * the usba_device pointer from the dip.
	 */
	return (ddi_get_parent_data(dip));
}


void
usba_set_usba_device(dev_info_t *dip, usba_device_t *usba_device)
{
	if (usba_is_root_hub(dip)) {
		usba_hcdi_t *hcdi = usba_hcdi_get_hcdi(dip);
		/* no locking is needed here */
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(hcdi->hcdi_usba_device))
		hcdi->hcdi_usba_device = usba_device;
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(hcdi->hcdi_usba_device))
	} else {
		ddi_set_parent_data(dip, usba_device);
	}
}


/*
 * usba_set_node_name() according to class, subclass, and protocol
 * following the 1275 USB binding tables.
 */

/* device node table, refer to section 3.2.2.1 of 1275 binding */
static node_name_entry_t device_node_name_table[] = {
{ USB_CLASS_COMM,	DONTCARE,	DONTCARE,	"communications" },
{ USB_CLASS_HUB,	DONTCARE,	DONTCARE,	"hub" },
{ USB_CLASS_DIAG,	DONTCARE,	DONTCARE,	"diagnostics" },
{ USB_CLASS_MISC,	DONTCARE,	DONTCARE,	"miscellaneous" },
{ DONTCARE,		DONTCARE,	DONTCARE,	"device" }
};

/* interface-association node table */
static node_name_entry_t ia_node_name_table[] = {
{ USB_CLASS_AUDIO,	DONTCARE,	DONTCARE, "audio" },
{ USB_CLASS_VIDEO,	DONTCARE,	DONTCARE, "video" },
{ USB_CLASS_WIRELESS,	USB_SUBCLS_WUSB_2, USB_PROTO_WUSB_DWA,
						"device-wire-adaptor" },
{ USB_CLASS_WIRELESS,	DONTCARE,	DONTCARE, "wireless-controller" },
{ DONTCARE,		DONTCARE,	DONTCARE, "interface-association" }
};

/* interface node table, refer to section 3.3.2.1 */
static node_name_entry_t if_node_name_table[] = {
{ USB_CLASS_AUDIO, USB_SUBCLS_AUD_CONTROL, DONTCARE,	"sound-control" },
{ USB_CLASS_AUDIO, USB_SUBCLS_AUD_STREAMING, DONTCARE, "sound" },
{ USB_CLASS_AUDIO, USB_SUBCLS_AUD_MIDI_STREAMING, DONTCARE, "midi" },
{ USB_CLASS_AUDIO, DONTCARE,		DONTCARE,	"sound" },

{ USB_CLASS_COMM, USB_SUBCLS_CDCC_DIRECT_LINE,	DONTCARE, "line" },
{ USB_CLASS_COMM, USB_SUBCLS_CDCC_ABSTRCT_CTRL,	DONTCARE, "modem" },
{ USB_CLASS_COMM, USB_SUBCLS_CDCC_PHONE_CTRL, DONTCARE, "telephone" },
{ USB_CLASS_COMM, USB_SUBCLS_CDCC_MULTCNL_ISDN, DONTCARE, "isdn" },
{ USB_CLASS_COMM, USB_SUBCLS_CDCC_ISDN,		DONTCARE, "isdn" },
{ USB_CLASS_COMM, USB_SUBCLS_CDCC_ETHERNET,	DONTCARE, "ethernet" },
{ USB_CLASS_COMM, USB_SUBCLS_CDCC_ATM_NETWORK, DONTCARE, "atm-network" },
{ USB_CLASS_COMM, DONTCARE,		DONTCARE,	"communications" },

{ USB_CLASS_HID, USB_SUBCLS_HID_1, USB_PROTO_HID_KEYBOARD,	"keyboard" },
{ USB_CLASS_HID, USB_SUBCLS_HID_1, USB_PROTO_HID_MOUSE,	"mouse" },
{ USB_CLASS_HID,	DONTCARE,	DONTCARE,	"input" },

{ USB_CLASS_HUB,	DONTCARE,	DONTCARE,	"hub" },

{ USB_CLASS_PHYSICAL,	DONTCARE,	DONTCARE,	"physical" },

{ USB_CLASS_IMAGE,	DONTCARE,	DONTCARE,	"image" },

{ USB_CLASS_PRINTER,	DONTCARE,	DONTCARE,	"printer" },

{ USB_CLASS_MASS_STORAGE, DONTCARE,	DONTCARE,	"storage" },

{ USB_CLASS_CDC_DATA,	DONTCARE,	DONTCARE,	"data" },

{ USB_CLASS_SECURITY,	DONTCARE,	DONTCARE,	"security" },

{ USB_CLASS_VIDEO, USB_SUBCLS_VIDEO_CONTROL, DONTCARE,	"video-control" },
{ USB_CLASS_VIDEO, USB_SUBCLS_VIDEO_STREAM,  DONTCARE,	"video-stream" },
{ USB_CLASS_VIDEO,	DONTCARE,	DONTCARE,	"video" },

{ USB_CLASS_APP,	USB_SUBCLS_APP_FIRMWARE, DONTCARE, "firmware" },
{ USB_CLASS_APP,	USB_SUBCLS_APP_IRDA,	DONTCARE, "IrDa" },
{ USB_CLASS_APP,	USB_SUBCLS_APP_TEST,	DONTCARE, "test" },

{ USB_CLASS_MISC,	USB_SUBCLS_CBAF, USB_PROTO_CBAF,  "wusb_ca"},
{ USB_CLASS_WIRELESS, USB_SUBCLS_WUSB_1, USB_PROTO_WUSB_RC, "hwa-radio" },
{ USB_CLASS_WIRELESS, USB_SUBCLS_WUSB_2, USB_PROTO_WUSB_HWA, "hwa-host" },
{ USB_CLASS_WIRELESS, USB_SUBCLS_WUSB_2, USB_PROTO_WUSB_DWA, "dwa-control" },
{ USB_CLASS_WIRELESS, USB_SUBCLS_WUSB_2, USB_PROTO_WUSB_DWA_ISO, "dwa-isoc" },
{ USB_CLASS_WIRELESS, DONTCARE, DONTCARE, "wireless" },

{ DONTCARE,		DONTCARE,	DONTCARE,	"interface" },

};

/* combined node table, refer to section 3.4.2.1 */
static node_name_entry_t combined_node_name_table[] = {
{ USB_CLASS_AUDIO, USB_SUBCLS_AUD_CONTROL, DONTCARE,	"sound-control" },
{ USB_CLASS_AUDIO, USB_SUBCLS_AUD_STREAMING, DONTCARE, "sound" },
{ USB_CLASS_AUDIO, USB_SUBCLS_AUD_MIDI_STREAMING, DONTCARE, "midi" },
{ USB_CLASS_AUDIO, DONTCARE,		DONTCARE,	"sound" },

{ USB_CLASS_COMM, USB_SUBCLS_CDCC_DIRECT_LINE,	DONTCARE, "line" },
{ USB_CLASS_COMM, USB_SUBCLS_CDCC_ABSTRCT_CTRL,	DONTCARE, "modem" },
{ USB_CLASS_COMM, USB_SUBCLS_CDCC_PHONE_CTRL, DONTCARE, "telephone" },
{ USB_CLASS_COMM, USB_SUBCLS_CDCC_MULTCNL_ISDN, DONTCARE, "isdn" },
{ USB_CLASS_COMM, USB_SUBCLS_CDCC_ISDN,		DONTCARE, "isdn" },
{ USB_CLASS_COMM, USB_SUBCLS_CDCC_ETHERNET,	DONTCARE, "ethernet" },
{ USB_CLASS_COMM, USB_SUBCLS_CDCC_ATM_NETWORK, DONTCARE, "atm-network" },
{ USB_CLASS_COMM, DONTCARE,		DONTCARE,	"communications" },

{ USB_CLASS_HID, USB_SUBCLS_HID_1, USB_PROTO_HID_KEYBOARD, "keyboard" },
{ USB_CLASS_HID, USB_SUBCLS_HID_1, USB_PROTO_HID_MOUSE,	"mouse" },
{ USB_CLASS_HID,	DONTCARE,	DONTCARE,	"input" },

{ USB_CLASS_PHYSICAL,	DONTCARE,	DONTCARE,	"physical" },

{ USB_CLASS_IMAGE,	DONTCARE,	DONTCARE,	"image" },

{ USB_CLASS_PRINTER,	DONTCARE,	DONTCARE,	"printer" },

{ USB_CLASS_MASS_STORAGE, USB_SUBCLS_MS_RBC_T10,	DONTCARE, "storage" },
{ USB_CLASS_MASS_STORAGE, USB_SUBCLS_MS_SFF8020I,	DONTCARE, "cdrom" },
{ USB_CLASS_MASS_STORAGE, USB_SUBCLS_MS_QIC_157,	DONTCARE, "tape" },
{ USB_CLASS_MASS_STORAGE, USB_SUBCLS_MS_UFI,		DONTCARE, "floppy" },
{ USB_CLASS_MASS_STORAGE, USB_SUBCLS_MS_SFF8070I,	DONTCARE, "storage" },
{ USB_CLASS_MASS_STORAGE, USB_SUBCLS_MS_SCSI,		DONTCARE, "storage" },
{ USB_CLASS_MASS_STORAGE, DONTCARE,	DONTCARE,	"storage" },

{ USB_CLASS_CDC_DATA,	DONTCARE,	DONTCARE,	"data" },

{ USB_CLASS_SECURITY,	DONTCARE,	DONTCARE,	"security" },

{ USB_CLASS_VIDEO, USB_SUBCLS_VIDEO_CONTROL, DONTCARE,	"video-control" },
{ USB_CLASS_VIDEO, USB_SUBCLS_VIDEO_STREAM,  DONTCARE,	"video-stream" },
{ USB_CLASS_VIDEO,	DONTCARE,	DONTCARE,	"video" },

{ USB_CLASS_APP,	USB_SUBCLS_APP_FIRMWARE, DONTCARE, "firmware" },
{ USB_CLASS_APP,	USB_SUBCLS_APP_IRDA,	DONTCARE, "IrDa" },
{ USB_CLASS_APP,	USB_SUBCLS_APP_TEST,	DONTCARE, "test" },

{ USB_CLASS_COMM,	DONTCARE,	DONTCARE,	"communications" },
{ USB_CLASS_HUB,	DONTCARE,	DONTCARE,	"hub" },
{ USB_CLASS_DIAG,	DONTCARE,	DONTCARE,	"diagnostics" },
{ USB_CLASS_MISC,	DONTCARE,	DONTCARE,	"miscellaneous" },
{ DONTCARE,		DONTCARE,	DONTCARE,	"device" }
};

static size_t device_node_name_table_size =
	sizeof (device_node_name_table)/sizeof (struct node_name_entry);
static size_t ia_node_name_table_size =
	sizeof (ia_node_name_table)/sizeof (struct node_name_entry);
static size_t if_node_name_table_size =
	sizeof (if_node_name_table)/sizeof (struct node_name_entry);
static size_t combined_node_name_table_size =
	sizeof (combined_node_name_table)/sizeof (struct node_name_entry);


static void
usba_set_node_name(dev_info_t *dip, uint8_t class, uint8_t subclass,
    uint8_t protocol, uint_t flag)
{
	int i;
	size_t size;
	node_name_entry_t *node_name_table;

	switch (flag) {
	/* interface share node names with interface-association */
	case FLAG_INTERFACE_ASSOCIATION_NODE:
		node_name_table = ia_node_name_table;
		size = ia_node_name_table_size;
		break;
	case FLAG_INTERFACE_NODE:
		node_name_table = if_node_name_table;
		size = if_node_name_table_size;
		break;
	case FLAG_DEVICE_NODE:
		node_name_table = device_node_name_table;
		size = device_node_name_table_size;
		break;
	case FLAG_COMBINED_NODE:
		node_name_table = combined_node_name_table;
		size = combined_node_name_table_size;
		break;
	default:

		return;
	}

	for (i = 0; i < size; i++) {
		int16_t c = node_name_table[i].class;
		int16_t s = node_name_table[i].subclass;
		int16_t p = node_name_table[i].protocol;

		if (((c == DONTCARE) || (c == class)) &&
		    ((s == DONTCARE) || (s == subclass)) &&
		    ((p == DONTCARE) || (p == protocol))) {
			char *name = node_name_table[i].name;

			(void) ndi_devi_set_nodename(dip, name, 0);
			break;
		}
	}
}


#ifdef DEBUG
/*
 * walk the children of the parent of this devi and compare the
 * name and  reg property of each child. If there is a match
 * return this node
 */
static dev_info_t *
usba_find_existing_node(dev_info_t *odip)
{
	dev_info_t *ndip, *child, *pdip;
	int	*odata, *ndata;
	uint_t	n_odata, n_ndata;
	int	circular;

	pdip = ddi_get_parent(odip);
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY,
	    odip, DDI_PROP_DONTPASS, "reg",
	    &odata, &n_odata) != DDI_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_HCDI, usba_log_handle,
		    "usba_find_existing_node: "
		    "%s: DDI_NOT_WELL_FORMED", ddi_driver_name(odip));

		return (NULL);
	}

	ndi_devi_enter(pdip, &circular);
	ndip = (dev_info_t *)(DEVI(pdip)->devi_child);
	while ((child = ndip) != NULL) {

		ndip = (dev_info_t *)(DEVI(child)->devi_sibling);

		if (child == odip) {
			continue;
		}

		if (strcmp(DEVI(child)->devi_node_name,
		    DEVI(odip)->devi_node_name)) {
			continue;
		}

		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY,
		    child, DDI_PROP_DONTPASS, "reg",
		    &ndata, &n_ndata) != DDI_SUCCESS) {

			USB_DPRINTF_L2(DPRINT_MASK_HCDI, usba_log_handle,
			    "usba_find_existing_node: "
			    "%s DDI_NOT_WELL_FORMED", ddi_driver_name(child));

		} else if (n_ndata && n_odata && (bcmp(odata, ndata,
		    max(n_odata, n_ndata) * sizeof (int)) == 0)) {

			USB_DPRINTF_L3(DPRINT_MASK_HCDI, usba_log_handle,
			    "usba_find_existing_node: found %s%d (%p)",
			    ddi_driver_name(child),
			    ddi_get_instance(child), (void *)child);

			USB_DPRINTF_L3(DPRINT_MASK_HCDI, usba_log_handle,
			    "usba_find_existing_node: "
			    "reg: %x %x %x - %x %x %x",
			    n_odata, odata[0], odata[1],
			    n_ndata, ndata[0], ndata[1]);

			ddi_prop_free(ndata);
			break;

		} else {
			ddi_prop_free(ndata);
		}
	}

	ndi_devi_exit(pdip, circular);

	ddi_prop_free(odata);

	return (child);
}
#endif

/* change all unprintable characters to spaces */
static void
usba_filter_string(char *instr, char *outstr)
{
	while (*instr) {
		if ((*instr >= ' ') && (*instr <= '~')) {
			*outstr = *instr;
		} else {
			*outstr = ' ';
		}
		outstr++;
		instr++;
	}
	*outstr = '\0';
}


/*
 * lookup ugen binding specified in property in
 * hcd.conf files
 */
int
usba_get_ugen_binding(dev_info_t *dip)
{
	usba_device_t	*usba_device = usba_get_usba_device(dip);
	usba_hcdi_t	*hcdi =
	    usba_hcdi_get_hcdi(usba_device->usb_root_hub_dip);

	return (hcdi->hcdi_ugen_default_binding);
}


/*
 * driver binding support at device level
 */
dev_info_t *
usba_ready_device_node(dev_info_t *child_dip)
{
	int		rval, i;
	int		n = 0;
	usba_device_t	*usba_device = usba_get_usba_device(child_dip);
	usb_dev_descr_t	*usb_dev_descr;
	uint_t		n_cfgs;	/* number of configs */
	uint_t		n_ifs;	/* number of interfaces */
	uint_t		port, bus_num;
	size_t		usb_config_length;
	uchar_t 	*usb_config;
	int		reg[1];
	usb_addr_t	address = usb_get_addr(child_dip);
	usb_if_descr_t	if_descr;
	size_t		size;
	int		combined_node = 0;
	int		is_hub;
	char		*devprop_str;
	char		*force_bind = NULL;
	char		*usba_name_buf = NULL;
	char		*usba_name[USBA_MAX_COMPAT_NAMES];

	usb_config = usb_get_raw_cfg_data(child_dip, &usb_config_length);

	mutex_enter(&usba_device->usb_mutex);
	mutex_enter(&usba_mutex);

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usba_log_handle,
	    "usba_ready_device_node: child=0x%p", (void *)child_dip);

	port = usba_device->usb_port;
	usb_dev_descr = usba_device->usb_dev_descr;
	n_cfgs = usba_device->usb_n_cfgs;
	n_ifs = usba_device->usb_n_ifs;
	bus_num = usba_device->usb_addr;

	if (address != ROOT_HUB_ADDR) {
		size = usb_parse_if_descr(
		    usb_config,
		    usb_config_length,
		    0,		/* interface index */
		    0,		/* alt interface index */
		    &if_descr,
		    USB_IF_DESCR_SIZE);

		if (size != USB_IF_DESCR_SIZE) {
			USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
			    "parsing interface: "
			    "size (%lu) != USB_IF_DESCR_SIZE (%d)",
			    size, USB_IF_DESCR_SIZE);

			mutex_exit(&usba_mutex);
			mutex_exit(&usba_device->usb_mutex);

			return (child_dip);
		}
	} else {
		/* fake an interface descriptor for the root hub */
		bzero(&if_descr, sizeof (if_descr));

		if_descr.bInterfaceClass = USB_CLASS_HUB;
	}

	reg[0] = port;

	mutex_exit(&usba_mutex);
	mutex_exit(&usba_device->usb_mutex);

	rval = ndi_prop_update_int_array(
	    DDI_DEV_T_NONE, child_dip, "reg", reg, 1);

	if (rval != DDI_PROP_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
		    "usba_ready_device_node: property update failed");

		return (child_dip);
	}

	combined_node = ((n_cfgs == 1) && (n_ifs == 1) &&
	    ((usb_dev_descr->bDeviceClass == USB_CLASS_HUB) ||
	    (usb_dev_descr->bDeviceClass == 0)));

	is_hub = (if_descr.bInterfaceClass == USB_CLASS_HUB) ||
	    (usb_dev_descr->bDeviceClass == USB_CLASS_HUB);

	/* set node name */
	if (combined_node) {
		usba_set_node_name(child_dip,
		    if_descr.bInterfaceClass,
		    if_descr.bInterfaceSubClass,
		    if_descr.bInterfaceProtocol,
		    FLAG_COMBINED_NODE);
	} else {
		usba_set_node_name(child_dip,
		    usb_dev_descr->bDeviceClass,
		    usb_dev_descr->bDeviceSubClass,
		    usb_dev_descr->bDeviceProtocol,
		    FLAG_DEVICE_NODE);
	}

	/*
	 * check force binding rules
	 */
	if ((address != ROOT_HUB_ADDR) && usba_ddivs_usbc &&
	    (address != usba_ddivs_usbc_xaddress) &&
	    (!(usba_ddivs_usbc_xhubs && is_hub))) {
		force_bind = "ddivs_usbc";
		(void) ndi_devi_set_nodename(child_dip, "ddivs_usbc", 0);

	} else if (usba_device->usb_preferred_driver) {
		force_bind = usba_device->usb_preferred_driver;

	} else if ((address != ROOT_HUB_ADDR) &&
	    ((usba_ugen_force_binding == USBA_UGEN_DEVICE_BINDING) ||
	    ((usba_ugen_force_binding == USBA_UGEN_INTERFACE_BINDING) &&
	    combined_node)) && (!is_hub)) {
		force_bind = "ugen";
	}

#ifdef DEBUG
	/*
	 * check whether there is another dip with this name and address
	 * If the dip contains usba_device, it is held by the previous
	 * round of configuration.
	 */
	ASSERT(usba_find_existing_node(child_dip) == NULL);
#endif

	usba_name_buf = kmem_zalloc(USBA_MAX_COMPAT_NAMES *
	    USBA_MAX_COMPAT_NAME_LEN, KM_SLEEP);

	for (i = 0; i < USBA_MAX_COMPAT_NAMES; i++) {
		usba_name[i] = usba_name_buf + (i * USBA_MAX_COMPAT_NAME_LEN);
	}

	if (force_bind) {
		(void) ndi_devi_set_nodename(child_dip, force_bind, 0);
		(void) strncpy(usba_name[n++], force_bind,
		    USBA_MAX_COMPAT_NAME_LEN);
	}

	/*
	 * If the callback function of specified driver is registered,
	 * it will be called here to check whether to take over the device.
	 */
	if (usb_cap.usba_dev_driver_cb != NULL) {
		char		*dev_drv = NULL;
		usb_dev_str_t	dev_str;
		char		*pathname = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		dev_str.usb_mfg = usba_device->usb_mfg_str;
		dev_str.usb_product = usba_device->usb_product_str;
		dev_str.usb_serialno = usba_device->usb_serialno_str;

		(void) ddi_pathname(child_dip, pathname);

		if ((usb_cap.usba_dev_driver_cb(usb_dev_descr, &dev_str,
		    pathname, bus_num, port, &dev_drv, NULL) == USB_SUCCESS) &&
		    (dev_drv != NULL)) {
			USB_DPRINTF_L3(DPRINT_MASK_USBA, usba_log_handle,
			    "usba_ready_device_node: dev_driver=%s, port =%d,"
			    "bus =%d, path=%s\n\t",
			    dev_drv, port, bus_num, pathname);

			(void) strncpy(usba_name[n++], dev_drv,
			    USBA_MAX_COMPAT_NAME_LEN);
		}
		kmem_free(pathname, MAXPATHLEN);
	}

	/* create compatible names */
	if (combined_node) {

		/* 1. usbVID,PID.REV */
		(void) sprintf(usba_name[n++],
		    "usb%x,%x.%x",
		    usb_dev_descr->idVendor,
		    usb_dev_descr->idProduct,
		    usb_dev_descr->bcdDevice);

		/* 2. usbVID,PID */
		(void) sprintf(usba_name[n++],
		    "usb%x,%x",
		    usb_dev_descr->idVendor,
		    usb_dev_descr->idProduct);

		if (usb_dev_descr->bDeviceClass != 0) {
			/* 3. usbVID,classDC.DSC.DPROTO */
			(void) sprintf(usba_name[n++],
			    "usb%x,class%x.%x.%x",
			    usb_dev_descr->idVendor,
			    usb_dev_descr->bDeviceClass,
			    usb_dev_descr->bDeviceSubClass,
			    usb_dev_descr->bDeviceProtocol);

			/* 4. usbVID,classDC.DSC */
			(void) sprintf(usba_name[n++],
			    "usb%x,class%x.%x",
			    usb_dev_descr->idVendor,
			    usb_dev_descr->bDeviceClass,
			    usb_dev_descr->bDeviceSubClass);

			/* 5. usbVID,classDC */
			(void) sprintf(usba_name[n++],
			    "usb%x,class%x",
			    usb_dev_descr->idVendor,
			    usb_dev_descr->bDeviceClass);

			/* 6. usb,classDC.DSC.DPROTO */
			(void) sprintf(usba_name[n++],
			    "usb,class%x.%x.%x",
			    usb_dev_descr->bDeviceClass,
			    usb_dev_descr->bDeviceSubClass,
			    usb_dev_descr->bDeviceProtocol);

			/* 7. usb,classDC.DSC */
			(void) sprintf(usba_name[n++],
			    "usb,class%x.%x",
			    usb_dev_descr->bDeviceClass,
			    usb_dev_descr->bDeviceSubClass);

			/* 8. usb,classDC */
			(void) sprintf(usba_name[n++],
			    "usb,class%x",
			    usb_dev_descr->bDeviceClass);
		}

		if (if_descr.bInterfaceClass != 0) {
			/* 9. usbifVID,classIC.ISC.IPROTO */
			(void) sprintf(usba_name[n++],
			    "usbif%x,class%x.%x.%x",
			    usb_dev_descr->idVendor,
			    if_descr.bInterfaceClass,
			    if_descr.bInterfaceSubClass,
			    if_descr.bInterfaceProtocol);

			/* 10. usbifVID,classIC.ISC */
			(void) sprintf(usba_name[n++],
			    "usbif%x,class%x.%x",
			    usb_dev_descr->idVendor,
			    if_descr.bInterfaceClass,
			    if_descr.bInterfaceSubClass);

			/* 11. usbifVID,classIC */
			(void) sprintf(usba_name[n++],
			    "usbif%x,class%x",
			    usb_dev_descr->idVendor,
			    if_descr.bInterfaceClass);

			/* 12. usbif,classIC.ISC.IPROTO */
			(void) sprintf(usba_name[n++],
			    "usbif,class%x.%x.%x",
			    if_descr.bInterfaceClass,
			    if_descr.bInterfaceSubClass,
			    if_descr.bInterfaceProtocol);

			/* 13. usbif,classIC.ISC */
			(void) sprintf(usba_name[n++],
			    "usbif,class%x.%x",
			    if_descr.bInterfaceClass,
			    if_descr.bInterfaceSubClass);

			/* 14. usbif,classIC */
			(void) sprintf(usba_name[n++],
			    "usbif,class%x",
			    if_descr.bInterfaceClass);
		}

		/* 15. ugen or usb_mid */
		if (usba_get_ugen_binding(child_dip) ==
		    USBA_UGEN_DEVICE_BINDING) {
			(void) sprintf(usba_name[n++], "ugen");
		} else {
			(void) sprintf(usba_name[n++], "usb,device");
		}

	} else {
		if (n_cfgs > 1) {
			/* 1. usbVID,PID.REV.configCN */
			(void) sprintf(usba_name[n++],
			    "usb%x,%x.%x.config%x",
			    usb_dev_descr->idVendor,
			    usb_dev_descr->idProduct,
			    usb_dev_descr->bcdDevice,
			    usba_device->usb_cfg_value);
		}

		/* 2. usbVID,PID.REV */
		(void) sprintf(usba_name[n++],
		    "usb%x,%x.%x",
		    usb_dev_descr->idVendor,
		    usb_dev_descr->idProduct,
		    usb_dev_descr->bcdDevice);

		/* 3. usbVID,PID.configCN */
		if (n_cfgs > 1) {
			(void) sprintf(usba_name[n++],
			    "usb%x,%x.%x",
			    usb_dev_descr->idVendor,
			    usb_dev_descr->idProduct,
			    usba_device->usb_cfg_value);
		}

		/* 4. usbVID,PID */
		(void) sprintf(usba_name[n++],
		    "usb%x,%x",
		    usb_dev_descr->idVendor,
		    usb_dev_descr->idProduct);

		if (usb_dev_descr->bDeviceClass != 0) {
			/* 5. usbVID,classDC.DSC.DPROTO */
			(void) sprintf(usba_name[n++],
			    "usb%x,class%x.%x.%x",
			    usb_dev_descr->idVendor,
			    usb_dev_descr->bDeviceClass,
			    usb_dev_descr->bDeviceSubClass,
			    usb_dev_descr->bDeviceProtocol);

			/* 6. usbVID,classDC.DSC */
			(void) sprintf(usba_name[n++],
			    "usb%x.class%x.%x",
			    usb_dev_descr->idVendor,
			    usb_dev_descr->bDeviceClass,
			    usb_dev_descr->bDeviceSubClass);

			/* 7. usbVID,classDC */
			(void) sprintf(usba_name[n++],
			    "usb%x.class%x",
			    usb_dev_descr->idVendor,
			    usb_dev_descr->bDeviceClass);

			/* 8. usb,classDC.DSC.DPROTO */
			(void) sprintf(usba_name[n++],
			    "usb,class%x.%x.%x",
			    usb_dev_descr->bDeviceClass,
			    usb_dev_descr->bDeviceSubClass,
			    usb_dev_descr->bDeviceProtocol);

			/* 9. usb,classDC.DSC */
			(void) sprintf(usba_name[n++],
			    "usb,class%x.%x",
			    usb_dev_descr->bDeviceClass,
			    usb_dev_descr->bDeviceSubClass);

			/* 10. usb,classDC */
			(void) sprintf(usba_name[n++],
			    "usb,class%x",
			    usb_dev_descr->bDeviceClass);
		}

		if (usba_get_ugen_binding(child_dip) ==
		    USBA_UGEN_DEVICE_BINDING) {
			/* 11. ugen */
			(void) sprintf(usba_name[n++], "ugen");
		} else {
			/* 11. usb,device */
			(void) sprintf(usba_name[n++], "usb,device");
		}
	}

	for (i = 0; i < n; i += 2) {
		USB_DPRINTF_L3(DPRINT_MASK_USBA, usba_log_handle,
		    "compatible name:\t%s\t%s", usba_name[i],
		    (((i+1) < n)? usba_name[i+1] : ""));
	}

	rval = ndi_prop_update_string_array(DDI_DEV_T_NONE, child_dip,
	    "compatible", (char **)usba_name, n);

	kmem_free(usba_name_buf, USBA_MAX_COMPAT_NAMES *
	    USBA_MAX_COMPAT_NAME_LEN);

	if (rval != DDI_PROP_SUCCESS) {

		USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
		    "usba_ready_device_node: property update failed");

		return (child_dip);
	}

	/* update the address property */
	rval = ndi_prop_update_int(DDI_DEV_T_NONE, child_dip,
	    "assigned-address", usba_device->usb_addr);
	if (rval != DDI_PROP_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
		    "usba_ready_device_node: address update failed");
	}

	/* update the usb device properties (PSARC/2000/454) */
	rval = ndi_prop_update_int(DDI_DEV_T_NONE, child_dip,
	    "usb-vendor-id", usb_dev_descr->idVendor);
	if (rval != DDI_PROP_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
		    "usba_ready_device_node: usb-vendor-id update failed");
	}

	rval = ndi_prop_update_int(DDI_DEV_T_NONE, child_dip,
	    "usb-product-id", usb_dev_descr->idProduct);
	if (rval != DDI_PROP_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
		    "usba_ready_device_node: usb-product-id update failed");
	}

	rval = ndi_prop_update_int(DDI_DEV_T_NONE, child_dip,
	    "usb-revision-id", usb_dev_descr->bcdDevice);
	if (rval != DDI_PROP_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
		    "usba_ready_device_node: usb-revision-id update failed");
	}

	rval = ndi_prop_update_int(DDI_DEV_T_NONE, child_dip,
	    "usb-num-configs", usb_dev_descr->bNumConfigurations);
	if (rval != DDI_PROP_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
		    "usba_ready_device_node: usb-num-configs update failed");
	}

	rval = ndi_prop_update_int(DDI_DEV_T_NONE, child_dip,
	    "usb-release", usb_dev_descr->bcdUSB);
	if (rval != DDI_PROP_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
		    "usba_ready_device_node: usb-release update failed");
	}

	rval = ndi_prop_update_byte_array(DDI_DEV_T_NONE, child_dip,
	    "usb-dev-descriptor", (uchar_t *)usb_dev_descr,
	    sizeof (usb_dev_descr_t));
	if (rval != DDI_PROP_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
		    "usba_ready_device_node: usb-descriptor update failed");
	}

	rval = ndi_prop_update_byte_array(DDI_DEV_T_NONE, child_dip,
	    "usb-raw-cfg-descriptors", usb_config, usb_config_length);
	if (rval != DDI_PROP_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
		    "usba_ready_device_node: usb-raw-cfg-descriptors update "
		    "failed");
	}

	devprop_str = kmem_zalloc(USB_MAXSTRINGLEN, KM_SLEEP);

	if (usba_device->usb_serialno_str) {
		usba_filter_string(usba_device->usb_serialno_str, devprop_str);
		rval = ndi_prop_update_string(DDI_DEV_T_NONE, child_dip,
		    "usb-serialno", devprop_str);
		if (rval != DDI_PROP_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
			    "usba_ready_device_node: "
			    "usb-serialno update failed");
		}
	}

	if (usba_device->usb_mfg_str) {
		usba_filter_string(usba_device->usb_mfg_str, devprop_str);
		rval = ndi_prop_update_string(DDI_DEV_T_NONE, child_dip,
		    "usb-vendor-name", devprop_str);
		if (rval != DDI_PROP_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
			    "usba_ready_device_node: "
			    "usb-vendor-name update failed");
		}
	}

	if (usba_device->usb_product_str) {
		usba_filter_string(usba_device->usb_product_str, devprop_str);
		rval = ndi_prop_update_string(DDI_DEV_T_NONE, child_dip,
		    "usb-product-name", devprop_str);
		if (rval != DDI_PROP_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
			    "usba_ready_device_node: "
			    "usb-product-name update failed");
		}
	}

	kmem_free(devprop_str, USB_MAXSTRINGLEN);

	if (!combined_node) {
		/* update the configuration property */
		rval = ndi_prop_update_int(DDI_DEV_T_NONE, child_dip,
		    "configuration#", usba_device->usb_cfg_value);
		if (rval != DDI_PROP_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
			    "usba_ready_device_node: "
			    "config prop update failed");
		}
	}

	if (usba_device->usb_port_status == USBA_LOW_SPEED_DEV) {
		/* create boolean property */
		rval = ndi_prop_create_boolean(DDI_DEV_T_NONE, child_dip,
		    "low-speed");
		if (rval != DDI_PROP_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
			    "usba_ready_device_node: "
			    "low speed prop update failed");
		}
	}

	if (usba_device->usb_port_status == USBA_HIGH_SPEED_DEV) {
		/* create boolean property */
		rval = ndi_prop_create_boolean(DDI_DEV_T_NONE, child_dip,
		    "high-speed");
		if (rval != DDI_PROP_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
			    "usba_ready_device_node: "
			    "high speed prop update failed");
		}
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usba_log_handle,
	    "%s%d at port %d: %s, dip=0x%p",
	    ddi_node_name(ddi_get_parent(child_dip)),
	    ddi_get_instance(ddi_get_parent(child_dip)),
	    port, ddi_node_name(child_dip), (void *)child_dip);

	usba_set_usba_device(child_dip, usba_device);

	ASSERT(!mutex_owned(&(usba_get_usba_device(child_dip)->usb_mutex)));

	return (child_dip);
}


/*
 * driver binding at interface association level. the first arg is the parent
 * dip. if_count returns amount of interfaces which are associated within
 * this interface-association that starts from first_if.
 */
/*ARGSUSED*/
dev_info_t *
usba_ready_interface_association_node(dev_info_t	*dip,
					uint_t		first_if,
					uint_t		*if_count)
{
	dev_info_t		*child_dip = NULL;
	usba_device_t		*child_ud = usba_get_usba_device(dip);
	usb_dev_descr_t		*usb_dev_descr;
	size_t			usb_cfg_length;
	uchar_t			*usb_cfg;
	usb_ia_descr_t		ia_descr;
	int			i, n, rval;
	int			reg[2];
	size_t			size;
	usb_port_status_t	port_status;
	char			*force_bind = NULL;
	char			*usba_name_buf = NULL;
	char			*usba_name[USBA_MAX_COMPAT_NAMES];

	usb_cfg = usb_get_raw_cfg_data(dip, &usb_cfg_length);

	mutex_enter(&child_ud->usb_mutex);

	usb_dev_descr = child_ud->usb_dev_descr;

	/*
	 * for each interface association, determine all compatible names
	 */
	USB_DPRINTF_L3(DPRINT_MASK_USBA, usba_log_handle,
	    "usba_ready_ia_node: "
	    "port %d, interface = %d, port_status = %x",
	    child_ud->usb_port, first_if, child_ud->usb_port_status);

	/* Parse the interface descriptor */
	size = usb_parse_ia_descr(
	    usb_cfg,
	    usb_cfg_length,
	    first_if,	/* interface index */
	    &ia_descr,
	    USB_IA_DESCR_SIZE);

	*if_count = 1;
	if (size != USB_IA_DESCR_SIZE) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
		    "parsing ia: size (%lu) != USB_IA_DESCR_SIZE (%d)",
		    size, USB_IA_DESCR_SIZE);
		mutex_exit(&child_ud->usb_mutex);

		return (NULL);
	}

	port_status = child_ud->usb_port_status;

	/* create reg property */
	reg[0] = first_if;
	reg[1] = child_ud->usb_cfg_value;

	mutex_exit(&child_ud->usb_mutex);

	/* clone this dip */
	rval =	usba_create_child_devi(dip,
	    "interface-association",
	    NULL,		/* usba_hcdi ops */
	    NULL,		/* root hub dip */
	    port_status,	/* port status */
	    child_ud,	/* share this usba_device */
	    &child_dip);

	if (rval != USB_SUCCESS) {

		goto fail;
	}

	rval = ndi_prop_update_int_array(
	    DDI_DEV_T_NONE, child_dip, "reg", reg, 2);

	if (rval != DDI_PROP_SUCCESS) {

		goto fail;
	}

	usba_set_node_name(child_dip, ia_descr.bFunctionClass,
	    ia_descr.bFunctionSubClass, ia_descr.bFunctionProtocol,
	    FLAG_INTERFACE_ASSOCIATION_NODE);

	/* check force binding */
	if (usba_ugen_force_binding ==
	    USBA_UGEN_INTERFACE_ASSOCIATION_BINDING) {
		force_bind = "ugen";
	}

	/*
	 * check whether there is another dip with this name and address
	 */
	ASSERT(usba_find_existing_node(child_dip) == NULL);

	usba_name_buf = kmem_zalloc(USBA_MAX_COMPAT_NAMES *
	    USBA_MAX_COMPAT_NAME_LEN, KM_SLEEP);

	for (i = 0; i < USBA_MAX_COMPAT_NAMES; i++) {
		usba_name[i] = usba_name_buf + (i * USBA_MAX_COMPAT_NAME_LEN);
	}

	n = 0;

	if (force_bind) {
		(void) ndi_devi_set_nodename(child_dip, force_bind, 0);
		(void) strncpy(usba_name[n++], force_bind,
		    USBA_MAX_COMPAT_NAME_LEN);
	}

	/* 1) usbiaVID,PID.REV.configCN.FN */
	(void) sprintf(usba_name[n++],
	    "usbia%x,%x.%x.config%x.%x",
	    usb_dev_descr->idVendor,
	    usb_dev_descr->idProduct,
	    usb_dev_descr->bcdDevice,
	    child_ud->usb_cfg_value,
	    first_if);

	/* 2) usbiaVID,PID.configCN.FN */
	(void) sprintf(usba_name[n++],
	    "usbia%x,%x.config%x.%x",
	    usb_dev_descr->idVendor,
	    usb_dev_descr->idProduct,
	    child_ud->usb_cfg_value,
	    first_if);


	if (ia_descr.bFunctionClass) {
		/* 3) usbiaVID,classFC.FSC.FPROTO */
		(void) sprintf(usba_name[n++],
		    "usbia%x,class%x.%x.%x",
		    usb_dev_descr->idVendor,
		    ia_descr.bFunctionClass,
		    ia_descr.bFunctionSubClass,
		    ia_descr.bFunctionProtocol);

		/* 4) usbiaVID,classFC.FSC */
		(void) sprintf(usba_name[n++],
		    "usbia%x,class%x.%x",
		    usb_dev_descr->idVendor,
		    ia_descr.bFunctionClass,
		    ia_descr.bFunctionSubClass);

		/* 5) usbiaVID,classFC */
		(void) sprintf(usba_name[n++],
		    "usbia%x,class%x",
		    usb_dev_descr->idVendor,
		    ia_descr.bFunctionClass);

		/* 6) usbia,classFC.FSC.FPROTO */
		(void) sprintf(usba_name[n++],
		    "usbia,class%x.%x.%x",
		    ia_descr.bFunctionClass,
		    ia_descr.bFunctionSubClass,
		    ia_descr.bFunctionProtocol);

		/* 7) usbia,classFC.FSC */
		(void) sprintf(usba_name[n++],
		    "usbia,class%x.%x",
		    ia_descr.bFunctionClass,
		    ia_descr.bFunctionSubClass);

		/* 8) usbia,classFC */
		(void) sprintf(usba_name[n++],
		    "usbia,class%x",
		    ia_descr.bFunctionClass);
	}

	if (usba_get_ugen_binding(child_dip) ==
	    USBA_UGEN_INTERFACE_ASSOCIATION_BINDING) {
		/* 9) ugen */
		(void) sprintf(usba_name[n++], "ugen");
	} else {

		(void) sprintf(usba_name[n++], "usb,ia");
	}

	for (i = 0; i < n; i += 2) {
		USB_DPRINTF_L3(DPRINT_MASK_USBA, usba_log_handle,
		    "compatible name:\t%s\t%s", usba_name[i],
		    (((i+1) < n)? usba_name[i+1] : ""));
	}

	/* create compatible property */
	rval = ndi_prop_update_string_array(DDI_DEV_T_NONE, child_dip,
	    "compatible", (char **)usba_name, n);

	kmem_free(usba_name_buf, USBA_MAX_COMPAT_NAMES *
	    USBA_MAX_COMPAT_NAME_LEN);

	if (rval != DDI_PROP_SUCCESS) {

		goto fail;
	}

	/* update the address property */
	rval = ndi_prop_update_int(DDI_DEV_T_NONE, child_dip,
	    "assigned-address", child_ud->usb_addr);
	if (rval != DDI_PROP_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
		    "usba_ready_interface_node: address update failed");
	}

	/* create property with first interface number */
	rval = ndi_prop_update_int(DDI_DEV_T_NONE, child_dip,
	    "interface", ia_descr.bFirstInterface);

	if (rval != DDI_PROP_SUCCESS) {

		goto fail;
	}

	/* create property with the count of interfaces in this ia */
	rval = ndi_prop_update_int(DDI_DEV_T_NONE, child_dip,
	    "interface-count", ia_descr.bInterfaceCount);

	if (rval != DDI_PROP_SUCCESS) {

		goto fail;
	}

	USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
	    "%s%d port %d: %s, dip = 0x%p",
	    ddi_node_name(ddi_get_parent(dip)),
	    ddi_get_instance(ddi_get_parent(dip)),
	    child_ud->usb_port, ddi_node_name(child_dip), (void *)child_dip);

	*if_count = ia_descr.bInterfaceCount;
	usba_set_usba_device(child_dip, child_ud);
	ASSERT(!mutex_owned(&(usba_get_usba_device(child_dip)->usb_mutex)));

	return (child_dip);

fail:
	(void) usba_destroy_child_devi(child_dip, NDI_DEVI_REMOVE);

	return (NULL);
}


/*
 * driver binding at interface level, the first arg will be the
 * the parent dip
 */
/*ARGSUSED*/
dev_info_t *
usba_ready_interface_node(dev_info_t *dip, uint_t intf)
{
	dev_info_t		*child_dip = NULL;
	usba_device_t		*child_ud = usba_get_usba_device(dip);
	usb_dev_descr_t	*usb_dev_descr;
	size_t			usb_cfg_length;
	uchar_t 		*usb_cfg;
	usb_if_descr_t	if_descr;
	int			i, n, rval;
	int			reg[2];
	size_t			size;
	usb_port_status_t	port_status;
	char			*force_bind = NULL;
	char			*usba_name_buf = NULL;
	char			*usba_name[USBA_MAX_COMPAT_NAMES];

	usb_cfg = usb_get_raw_cfg_data(dip, &usb_cfg_length);

	mutex_enter(&child_ud->usb_mutex);

	usb_dev_descr = child_ud->usb_dev_descr;

	/*
	 * for each interface, determine all compatible names
	 */
	USB_DPRINTF_L3(DPRINT_MASK_USBA, usba_log_handle,
	    "usba_ready_interface_node: "
	    "port %d, interface = %d port status = %x",
	    child_ud->usb_port, intf, child_ud->usb_port_status);

	/* Parse the interface descriptor */
	size = usb_parse_if_descr(
	    usb_cfg,
	    usb_cfg_length,
	    intf,		/* interface index */
	    0,		/* alt interface index */
	    &if_descr,
	    USB_IF_DESCR_SIZE);

	if (size != USB_IF_DESCR_SIZE) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
		    "parsing interface: size (%lu) != USB_IF_DESCR_SIZE (%d)",
		    size, USB_IF_DESCR_SIZE);
		mutex_exit(&child_ud->usb_mutex);

		return (NULL);
	}

	port_status = child_ud->usb_port_status;

	/* create reg property */
	reg[0] = intf;
	reg[1] = child_ud->usb_cfg_value;

	mutex_exit(&child_ud->usb_mutex);

	/* clone this dip */
	rval =	usba_create_child_devi(dip,
	    "interface",
	    NULL,		/* usba_hcdi ops */
	    NULL,		/* root hub dip */
	    port_status,	/* port status */
	    child_ud,	/* share this usba_device */
	    &child_dip);

	if (rval != USB_SUCCESS) {

		goto fail;
	}

	rval = ndi_prop_update_int_array(
	    DDI_DEV_T_NONE, child_dip, "reg", reg, 2);

	if (rval != DDI_PROP_SUCCESS) {

		goto fail;
	}

	usba_set_node_name(child_dip, if_descr.bInterfaceClass,
	    if_descr.bInterfaceSubClass, if_descr.bInterfaceProtocol,
	    FLAG_INTERFACE_NODE);

	/* check force binding */
	if (usba_ugen_force_binding == USBA_UGEN_INTERFACE_BINDING) {
		force_bind = "ugen";
	}

	/*
	 * check whether there is another dip with this name and address
	 */
	ASSERT(usba_find_existing_node(child_dip) == NULL);

	usba_name_buf = kmem_zalloc(USBA_MAX_COMPAT_NAMES *
	    USBA_MAX_COMPAT_NAME_LEN, KM_SLEEP);

	for (i = 0; i < USBA_MAX_COMPAT_NAMES; i++) {
		usba_name[i] = usba_name_buf + (i * USBA_MAX_COMPAT_NAME_LEN);
	}

	n = 0;

	if (force_bind) {
		(void) ndi_devi_set_nodename(child_dip, force_bind, 0);
		(void) strncpy(usba_name[n++], force_bind,
		    USBA_MAX_COMPAT_NAME_LEN);
	}

	/* 1) usbifVID,PID.REV.configCN.IN */
	(void) sprintf(usba_name[n++],
	    "usbif%x,%x.%x.config%x.%x",
	    usb_dev_descr->idVendor,
	    usb_dev_descr->idProduct,
	    usb_dev_descr->bcdDevice,
	    child_ud->usb_cfg_value,
	    intf);

	/* 2) usbifVID,PID.configCN.IN */
	(void) sprintf(usba_name[n++],
	    "usbif%x,%x.config%x.%x",
	    usb_dev_descr->idVendor,
	    usb_dev_descr->idProduct,
	    child_ud->usb_cfg_value,
	    intf);


	if (if_descr.bInterfaceClass) {
		/* 3) usbifVID,classIC.ISC.IPROTO */
		(void) sprintf(usba_name[n++],
		    "usbif%x,class%x.%x.%x",
		    usb_dev_descr->idVendor,
		    if_descr.bInterfaceClass,
		    if_descr.bInterfaceSubClass,
		    if_descr.bInterfaceProtocol);

		/* 4) usbifVID,classIC.ISC */
		(void) sprintf(usba_name[n++],
		    "usbif%x,class%x.%x",
		    usb_dev_descr->idVendor,
		    if_descr.bInterfaceClass,
		    if_descr.bInterfaceSubClass);

		/* 5) usbifVID,classIC */
		(void) sprintf(usba_name[n++],
		    "usbif%x,class%x",
		    usb_dev_descr->idVendor,
		    if_descr.bInterfaceClass);

		/* 6) usbif,classIC.ISC.IPROTO */
		(void) sprintf(usba_name[n++],
		    "usbif,class%x.%x.%x",
		    if_descr.bInterfaceClass,
		    if_descr.bInterfaceSubClass,
		    if_descr.bInterfaceProtocol);

		/* 7) usbif,classIC.ISC */
		(void) sprintf(usba_name[n++],
		    "usbif,class%x.%x",
		    if_descr.bInterfaceClass,
		    if_descr.bInterfaceSubClass);

		/* 8) usbif,classIC */
		(void) sprintf(usba_name[n++],
		    "usbif,class%x",
		    if_descr.bInterfaceClass);
	}

	if (usba_get_ugen_binding(child_dip) ==
	    USBA_UGEN_INTERFACE_BINDING) {
		/* 9) ugen */
		(void) sprintf(usba_name[n++], "ugen");
	}

	for (i = 0; i < n; i += 2) {
		USB_DPRINTF_L3(DPRINT_MASK_USBA, usba_log_handle,
		    "compatible name:\t%s\t%s", usba_name[i],
		    (((i+1) < n)? usba_name[i+1] : ""));
	}

	/* create compatible property */
	rval = ndi_prop_update_string_array(DDI_DEV_T_NONE, child_dip,
	    "compatible", (char **)usba_name, n);

	kmem_free(usba_name_buf, USBA_MAX_COMPAT_NAMES *
	    USBA_MAX_COMPAT_NAME_LEN);

	if (rval != DDI_PROP_SUCCESS) {

		goto fail;
	}

	/* update the address property */
	rval = ndi_prop_update_int(DDI_DEV_T_NONE, child_dip,
	    "assigned-address", child_ud->usb_addr);
	if (rval != DDI_PROP_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
		    "usba_ready_interface_node: address update failed");
	}

	/* create property with if number */
	rval = ndi_prop_update_int(DDI_DEV_T_NONE, child_dip,
	    "interface", intf);

	if (rval != DDI_PROP_SUCCESS) {

		goto fail;
	}

	USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
	    "%s%d port %d: %s, dip = 0x%p",
	    ddi_node_name(ddi_get_parent(dip)),
	    ddi_get_instance(ddi_get_parent(dip)),
	    child_ud->usb_port, ddi_node_name(child_dip), (void *)child_dip);

	usba_set_usba_device(child_dip, child_ud);
	ASSERT(!mutex_owned(&(usba_get_usba_device(child_dip)->usb_mutex)));

	return (child_dip);

fail:
	(void) usba_destroy_child_devi(child_dip, NDI_DEVI_REMOVE);

	return (NULL);
}


/*
 * retrieve string descriptors for manufacturer, vendor and serial
 * number
 */
void
usba_get_dev_string_descrs(dev_info_t *dip, usba_device_t *ud)
{
	char	*tmpbuf, *str;
	int	l;
	usb_dev_descr_t *usb_dev_descr = ud->usb_dev_descr;


	USB_DPRINTF_L4(DPRINT_MASK_USBA, usba_log_handle,
	    "usba_get_usb_string_descr: m=%d, p=%d, s=%d",
	    usb_dev_descr->iManufacturer,
	    usb_dev_descr->iProduct,
	    usb_dev_descr->iSerialNumber);

	tmpbuf = kmem_zalloc(USB_MAXSTRINGLEN, KM_SLEEP);

	/* fetch manufacturer string */
	if ((ud->usb_mfg_str == NULL) && usb_dev_descr->iManufacturer &&
	    (usb_get_string_descr(dip, USB_LANG_ID,
	    usb_dev_descr->iManufacturer, tmpbuf, USB_MAXSTRINGLEN) ==
	    USB_SUCCESS)) {

		l = strlen(tmpbuf);
		if (l > 0) {
			str = kmem_zalloc(l + 1, KM_SLEEP);
			mutex_enter(&ud->usb_mutex);
			ud->usb_mfg_str = str;
			(void) strcpy(ud->usb_mfg_str, tmpbuf);
			mutex_exit(&ud->usb_mutex);
		}
	}

	/* fetch product string */
	if ((ud->usb_product_str == NULL) && usb_dev_descr->iProduct &&
	    (usb_get_string_descr(dip, USB_LANG_ID, usb_dev_descr->iProduct,
	    tmpbuf, USB_MAXSTRINGLEN) ==
	    USB_SUCCESS)) {

		l = strlen(tmpbuf);
		if (l > 0) {
			str = kmem_zalloc(l + 1, KM_SLEEP);
			mutex_enter(&ud->usb_mutex);
			ud->usb_product_str = str;
			(void) strcpy(ud->usb_product_str, tmpbuf);
			mutex_exit(&ud->usb_mutex);
		}
	}

	/* fetch device serial number string */
	if ((ud->usb_serialno_str == NULL) && usb_dev_descr->iSerialNumber &&
	    (usb_get_string_descr(dip, USB_LANG_ID,
	    usb_dev_descr->iSerialNumber, tmpbuf, USB_MAXSTRINGLEN) ==
	    USB_SUCCESS)) {

		l = strlen(tmpbuf);
		if (l > 0) {
			str = kmem_zalloc(l + 1, KM_SLEEP);
			mutex_enter(&ud->usb_mutex);
			ud->usb_serialno_str = str;
			(void) strcpy(ud->usb_serialno_str, tmpbuf);
			mutex_exit(&ud->usb_mutex);
		}
	}

	kmem_free(tmpbuf, USB_MAXSTRINGLEN);
}


/*
 * usba_get_mfg_prod_sn_str:
 *	Return a string containing mfg, product, serial number strings.
 *	Remove duplicates if some strings are the same.
 *
 * Arguments:
 *	dip	- pointer to dev info
 *	buffer	- Where string is returned
 *	buflen	- Length of buffer
 *
 * Returns:
 *	Same as second arg.
 */
char *
usba_get_mfg_prod_sn_str(
    dev_info_t	*dip,
    char	*buffer,
    int		buflen)
{
	usba_device_t *usba_device = usba_get_usba_device(dip);
	int return_len = 0;
	int len = 0;

	buffer[0] = '\0';
	buffer[buflen-1] = '\0';

	/* Manufacturer string exists. */
	if ((usba_device->usb_mfg_str) &&
	    ((len = strlen(usba_device->usb_mfg_str)) != 0)) {
		(void) strncpy(buffer, usba_device->usb_mfg_str, buflen - 1);
		return_len = min(buflen - 1, len);
	}

	/* Product string exists to append. */
	if ((usba_device->usb_product_str) &&
	    ((len = strlen(usba_device->usb_product_str)) != 0)) {
		if (return_len > 0) {
			buffer[return_len++] = ' ';
		}
		(void) strncpy(&buffer[return_len],
		    usba_device->usb_product_str, buflen - return_len - 1);
		return_len = min(buflen - 1, return_len + len);
	}

	/* Serial number string exists to append. */
	if ((usba_device->usb_serialno_str) &&
	    ((len = strlen(usba_device->usb_serialno_str)) != 0)) {
		if (return_len > 0) {
			buffer[return_len++] = ' ';
		}
		(void) strncpy(&buffer[return_len],
		    usba_device->usb_serialno_str,
		    buflen - return_len - 1);
	}

	return (buffer);
}


/*
 * USB enumeration statistic functions
 */

/*
 * Increments the hotplug statistics based on flags.
 */
void
usba_update_hotplug_stats(dev_info_t *dip, usb_flags_t flags)
{
	usba_device_t	*usba_device = usba_get_usba_device(dip);
	usba_hcdi_t	*hcdi =
	    usba_hcdi_get_hcdi(usba_device->usb_root_hub_dip);

	mutex_enter(&hcdi->hcdi_mutex);
	if (flags & USBA_TOTAL_HOTPLUG_SUCCESS) {
		hcdi->hcdi_total_hotplug_success++;
		HCDI_HOTPLUG_STATS_DATA(hcdi)->
		    hcdi_hotplug_total_success.value.ui64++;
	}
	if (flags & USBA_HOTPLUG_SUCCESS) {
		hcdi->hcdi_hotplug_success++;
		HCDI_HOTPLUG_STATS_DATA(hcdi)->
		    hcdi_hotplug_success.value.ui64++;
	}
	if (flags & USBA_TOTAL_HOTPLUG_FAILURE) {
		hcdi->hcdi_total_hotplug_failure++;
		HCDI_HOTPLUG_STATS_DATA(hcdi)->
		    hcdi_hotplug_total_failure.value.ui64++;
	}
	if (flags & USBA_HOTPLUG_FAILURE) {
		hcdi->hcdi_hotplug_failure++;
		HCDI_HOTPLUG_STATS_DATA(hcdi)->
		    hcdi_hotplug_failure.value.ui64++;
	}
	mutex_exit(&hcdi->hcdi_mutex);
}


/*
 * Retrieve the current enumeration statistics
 */
void
usba_get_hotplug_stats(dev_info_t *dip, ulong_t *total_success,
    ulong_t *success, ulong_t *total_failure, ulong_t *failure,
    uchar_t *device_count)
{
	usba_device_t	*usba_device = usba_get_usba_device(dip);
	usba_hcdi_t	*hcdi =
	    usba_hcdi_get_hcdi(usba_device->usb_root_hub_dip);

	mutex_enter(&hcdi->hcdi_mutex);
	*total_success = hcdi->hcdi_total_hotplug_success;
	*success = hcdi->hcdi_hotplug_success;
	*total_failure = hcdi->hcdi_total_hotplug_failure;
	*failure = hcdi->hcdi_hotplug_failure;
	*device_count = hcdi->hcdi_device_count;
	mutex_exit(&hcdi->hcdi_mutex);
}


/*
 * Reset the resetable hotplug stats
 */
void
usba_reset_hotplug_stats(dev_info_t *dip)
{
	usba_device_t	*usba_device = usba_get_usba_device(dip);
	usba_hcdi_t	*hcdi =
	    usba_hcdi_get_hcdi(usba_device->usb_root_hub_dip);
	hcdi_hotplug_stats_t *hsp;

	mutex_enter(&hcdi->hcdi_mutex);
	hcdi->hcdi_hotplug_success = 0;
	hcdi->hcdi_hotplug_failure = 0;

	hsp = HCDI_HOTPLUG_STATS_DATA(hcdi);
	hsp->hcdi_hotplug_success.value.ui64 = 0;
	hsp->hcdi_hotplug_failure.value.ui64 = 0;
	mutex_exit(&hcdi->hcdi_mutex);
}


/*
 * usba_bind_driver():
 *	This function calls ndi_devi_bind_driver() which tries to
 *	bind a driver to the device.  If the driver binding fails
 *	we get an rval of NDI_UNBOUD and report an error to the
 *	syslog that the driver failed binding.
 *	If rval is something other than NDI_UNBOUND we report an
 *	error to the console.
 *
 *	This function returns USB_SUCCESS if no errors were
 *	encountered while binding.
 */
int
usba_bind_driver(dev_info_t *dip)
{
	int	rval;
	char	*name;
	uint8_t if_num = usba_get_ifno(dip);

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usba_log_handle,
	    "usba_bind_driver: dip = 0x%p, if_num = 0x%x", (void *)dip, if_num);

	name = kmem_zalloc(MAXNAMELEN, KM_SLEEP);

	/* bind device to the driver */
	if ((rval = ndi_devi_bind_driver(dip, 0)) != NDI_SUCCESS) {
		/* if we fail to bind report an error */
		(void) usba_get_mfg_prod_sn_str(dip, name, MAXNAMELEN);
		if (name[0] != '\0') {
			if (!usb_owns_device(dip)) {
				USB_DPRINTF_L1(DPRINT_MASK_USBA,
				    usba_log_handle,
				    "no driver found for "
				    "interface %d (nodename: '%s') of %s",
				    if_num, ddi_node_name(dip), name);
			} else {
				USB_DPRINTF_L1(DPRINT_MASK_USBA,
				    usba_log_handle,
				    "no driver found for device %s", name);
			}
		} else {
			(void) ddi_pathname(dip, name);
			USB_DPRINTF_L1(DPRINT_MASK_USBA,
			    usba_log_handle,
			    "no driver found for device %s", name);
		}

		kmem_free(name, MAXNAMELEN);

		return (USB_FAILURE);
	}
	kmem_free(name, MAXNAMELEN);

	return ((rval == NDI_SUCCESS) ? USB_SUCCESS : USB_FAILURE);
}


/*
 * usba_get_hc_dma_attr:
 *	function returning dma attributes of the HCD
 *
 * Arguments:
 *	dip	- pointer to devinfo of the client
 *
 * Return Values:
 *	hcdi_dma_attr
 */
ddi_dma_attr_t *
usba_get_hc_dma_attr(dev_info_t *dip)
{
	usba_device_t *usba_device = usba_get_usba_device(dip);
	usba_hcdi_t *hcdi = usba_hcdi_get_hcdi(usba_device->usb_root_hub_dip);

	return (hcdi->hcdi_dma_attr);
}


/*
 * usba_check_for_leaks:
 *	check usba_device structure for leaks
 *
 * Arguments:
 *	usba_device	- usba_device structure pointer
 */
void
usba_check_for_leaks(usba_device_t *usba_device)
{
	int i, ph_open_cnt, req_wrp_leaks, iface;
	int leaks = 0;

	USB_DPRINTF_L4(DPRINT_MASK_USBA, usba_log_handle,
	    "usba_check_for_leaks: %s%d usba_device=0x%p",
	    ddi_driver_name(usba_device->usb_dip),
	    ddi_get_instance(usba_device->usb_dip), (void *)usba_device);

	/*
	 * default pipe is still open
	 * all other pipes should be closed
	 */
	for (ph_open_cnt = 0, i = 1; i < USBA_N_ENDPOINTS; i++) {
		usba_ph_impl_t *ph_impl =
		    &usba_device->usb_ph_list[i];
		if (ph_impl->usba_ph_data) {
			USB_DPRINTF_L2(DPRINT_MASK_USBA,
			    usba_log_handle,
			    "%s%d: leaking pipehandle=0x%p (0x%p) ep_addr=0x%x",
			    ddi_driver_name(ph_impl->usba_ph_data->p_dip),
			    ddi_get_instance(ph_impl->usba_ph_data->p_dip),
			    (void *)ph_impl,
			    (void *)ph_impl->usba_ph_data,
			    ph_impl->usba_ph_ep.bEndpointAddress);
			ph_open_cnt++;
			leaks++;
#ifndef DEBUG
			usb_pipe_close(ph_impl->usba_ph_data->p_dip,
			    (usb_pipe_handle_t)ph_impl, USB_FLAGS_SLEEP,
			    NULL, NULL);
#endif
		}
	}
	req_wrp_leaks =  usba_list_entry_leaks(&usba_device->
	    usb_allocated, "request wrappers");

	ASSERT(ph_open_cnt == 0);
	ASSERT(req_wrp_leaks == 0);

	if (req_wrp_leaks) {
		usba_list_entry_t *entry;

		while ((entry = usba_rm_first_from_list(
		    &usba_device->usb_allocated)) != NULL) {
			usba_req_wrapper_t *wrp;

			mutex_enter(&entry->list_mutex);
			wrp = (usba_req_wrapper_t *)entry->private;
			mutex_exit(&entry->list_mutex);
			leaks++;

			USB_DPRINTF_L2(DPRINT_MASK_USBA,
			    usba_log_handle,
			    "%s%d: leaking request 0x%p",
			    ddi_driver_name(wrp->wr_dip),
			    ddi_get_instance(wrp->wr_dip),
			    (void *)wrp->wr_req);

			/*
			 * put it back, usba_req_wrapper_free
			 * expects it on the list
			 */
			usba_add_to_list(&usba_device->usb_allocated,
			    &wrp->wr_allocated_list);

			usba_req_wrapper_free(wrp);
		}
	}

	mutex_enter(&usba_device->usb_mutex);
	for (iface = 0; iface < usba_device->usb_n_ifs; iface++) {
		USB_DPRINTF_L3(DPRINT_MASK_USBA, usba_log_handle,
		    "usba_check_for_leaks: if=%d client_flags=0x%x",
		    iface, usba_device->usb_client_flags[iface]);

		if (usba_device->usb_client_flags[iface] &
		    USBA_CLIENT_FLAG_DEV_DATA) {
			usb_client_dev_data_list_t *entry =
			    usba_device->usb_client_dev_data_list.cddl_next;
			usb_client_dev_data_list_t *next;
			usb_client_dev_data_t *dev_data;

			while (entry) {
				dev_info_t *dip = entry->cddl_dip;
				next = entry->cddl_next;
				dev_data = entry->cddl_dev_data;


				if (!i_ddi_devi_attached(dip)) {
					USB_DPRINTF_L2(DPRINT_MASK_USBA,
					    usba_log_handle,
					    "%s%d: leaking dev_data 0x%p",
					    ddi_driver_name(dip),
					    ddi_get_instance(dip),
					    (void *)dev_data);

					leaks++;

					mutex_exit(&usba_device->usb_mutex);
					usb_free_dev_data(dip, dev_data);
					mutex_enter(&usba_device->usb_mutex);
				}

				entry = next;
			}
		}
		if (usba_device->usb_client_flags[iface] &
		    USBA_CLIENT_FLAG_ATTACH) {
			dev_info_t *dip = usba_device->
			    usb_client_attach_list[iface].dip;

			USB_DPRINTF_L2(DPRINT_MASK_USBA,
			    usba_log_handle,
			    "%s%d: did no usb_client_detach",
			    ddi_driver_name(dip), ddi_get_instance(dip));
			leaks++;

			mutex_exit(&usba_device->usb_mutex);
			usb_client_detach(dip, NULL);
			mutex_enter(&usba_device->usb_mutex);

			usba_device->
			    usb_client_attach_list[iface].dip = NULL;

			usba_device->usb_client_flags[iface] &=
			    ~USBA_CLIENT_FLAG_ATTACH;

		}
		if (usba_device->usb_client_flags[iface] &
		    USBA_CLIENT_FLAG_EV_CBS) {
			dev_info_t *dip =
			    usba_device->usb_client_ev_cb_list[iface].
			    dip;
			usb_event_t *ev_data =
			    usba_device->usb_client_ev_cb_list[iface].
			    ev_data;

			USB_DPRINTF_L2(DPRINT_MASK_USBA,
			    usba_log_handle,
			    "%s%d: did no usb_unregister_event_cbs",
			    ddi_driver_name(dip), ddi_get_instance(dip));
			leaks++;

			mutex_exit(&usba_device->usb_mutex);
			usb_unregister_event_cbs(dip, ev_data);
			mutex_enter(&usba_device->usb_mutex);

			usba_device->usb_client_ev_cb_list[iface].
			    dip = NULL;
			usba_device->usb_client_ev_cb_list[iface].
			    ev_data = NULL;
			usba_device->usb_client_flags[iface] &=
			    ~USBA_CLIENT_FLAG_EV_CBS;
		}
	}
	mutex_exit(&usba_device->usb_mutex);

	if (leaks) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, usba_log_handle,
		    "all %d leaks fixed", leaks);
	}
}
