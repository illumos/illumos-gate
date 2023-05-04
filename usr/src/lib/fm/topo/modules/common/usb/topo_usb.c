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
 * Copyright (c) 2019, Joyent, Inc.
 */

/*
 * The purpose of this module is to build topology information for USB devices.
 * USB devices are more complicated to build topology information for, as there
 * are multiple sources of information needed to correctly understand the
 * topology, and the way they present themselves is not always straightforward.
 *
 * We enumerate two different types of devices:
 *
 *   o USB ports
 *   o USB devices
 *
 * A USB port represents a logical port, while a USB device represents an actual
 * device that's been plugged in. If a device is a hub, then we'll enumerate
 * that device as well.
 *
 * Now, some basics. There are several different USB controllers that exist in
 * the system. Some are part of the chipset, while others may be present via
 * add-on cards. The system interfaces initially with USB devices through a host
 * controller. Prior to USB 3.0/xhci, a single controller only supported a
 * single protocol. With USB 3.0, it is possible for a port to share wiring with
 * both USB 2.0 devices and USB 3.0 devices. However, to the host controller
 * this appears as two different logical ports.
 *
 * To make matters worse, during the transition to USB 3, the ports that were
 * controlled could be routed to and from a USB 2 controller to a USB 3
 * controller. This means that there are a lot of ways for ports to overlap.
 *
 * In the first case, controllers define a way to perform this mapping by
 * leveraging ACPI information. Of course, this only helps us if the platform
 * provides ACPI information, which it may not. When we do know that two ports
 * are actually the same port, either because of ACPI or because of a
 * product-specific mapping file, then we'll use that to say two ports are the
 * same. Otherwise, we'll enumerate them as two separate logical ports.
 *
 * To perform the actual enumeration, the first time we're asked to enumerate a
 * node, we go through and put together an entire picture of all of the USB
 * devices in the system. This is done so we can make sure to enumerate devices
 * under specific devices.  The actual topology is determined in a few different
 * passes.
 *
 * Before we walk any trees, we look to see if we have a topo USB metadata file
 * and if present, load it. However, we do not apply any information from it.
 *
 * The first pass uses the devinfo tree to determine all of the USB controllers
 * and devices that are in the system. We use properties in the devices tree to
 * identify whether items are a root hub. When a root hub is found, we walk all
 * of its children and make a note of all of the logical ports under it.
 *
 * Next, we walk the information provided by ACPI to try and reduplicate
 * information about the ports on the system. If the USB topology metadata tells
 * us that we should not skip ACPI, then we use it. This is done by walking the
 * /devices/fw tree, looking for USB nodes and then linking them to their
 * corresponding entries found from the first devinfo walk.
 *
 * Finally, we go back and apply metadata to ports that match.
 *
 *
 * To logically keep track of all of this, we have several different structures:
 *
 *  topo_usb_controller_t  - Represents a physical controller.
 *  topo_usb_port_t	   - Represents a physical port. This is a synthetic
 *			     construct that we put together based on ACPI
 *			     information.
 *  topo_usb_lport_t	   - Represents a logical port. This is what the OS
 *			     actually detects and sees. Each logical port
 *			     belongs to a corresponding topo_usb_port_t.
 *  topo_usb_t		   - Represents the overall topology enumeration state.
 *
 *
 * This topo module is invoked at three different points by the surrounding code
 * and logic. Specifically:
 *
 *   * Dynamically by the pcibus enumerator when we encounter PCI add on cards
 *     which are present in a physical slot. Traditional chipset devices are not
 *     considered a part of this.
 *
 *   * Statically under the motherboard. All ports that don't belong to a PCI
 *     device are assumed to belong under the motherboard, unless a
 *     platform-specific topology map maps them under the chassis.
 *
 *   * Statically under the chassis. Ports are only placed under the chassis if
 *     a platform-specific topology file indicates that the port is a part of
 *     the chassis.
 */

#include <libdevinfo.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/debug.h>
#include <unistd.h>

#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_list.h>
#include <fm/topo_method.h>

#include <topo_port.h>

#include "topo_usb.h"
#include "topo_usb_int.h"

typedef enum topo_usb_type {
	TOPO_USB_PCI,
	TOPO_USB_MOBO,
	TOPO_USB_CHASSIS
} topo_usb_type_t;

typedef enum topo_usb_cdrv {
	TOPO_USB_D_UNKNOWN,
	TOPO_USB_D_UHCI,
	TOPO_USB_D_OHCI,
	TOPO_USB_D_EHCI,
	TOPO_USB_D_XHCI
} topo_usb_cdrv_t;

typedef enum topo_usb_protocol {
	TOPO_USB_P_UNKNOWN,
	TOPO_USB_P_1x,
	TOPO_USB_P_20,
	TOPO_USB_P_30,
	TOPO_USB_P_31
} topo_usb_protocol_t;

typedef enum topo_usb_port_connected {
	TOPO_USB_C_UNKNOWN,
	TOPO_USB_C_DISCONNECTED,
	TOPO_USB_C_CONNECTED
} topo_usb_port_connected_t;

typedef struct topo_usb_port {
	topo_list_t	tup_link;
	uint_t		tup_nlports;
	topo_list_t	tup_lports;
	boolean_t	tup_pld_valid;
	acpi_pld_info_t	tup_pld;
	uint_t		tup_port_type;
	topo_usb_port_connected_t	tup_port_connected;
	topo_usb_meta_port_t	*tup_meta;
} topo_usb_port_t;

typedef struct topo_usb_lport {
	topo_list_t		tul_link;
	uint_t			tul_portno;
	topo_usb_protocol_t	tul_protocol;
	di_node_t		tul_device;
	di_node_t		tul_acpi_device;
	topo_usb_port_t		*tul_port;
	uint_t			tul_nhubd_ports;
	uint_t			tul_nports;
	topo_list_t		tul_ports;
	char			tul_name[PATH_MAX];
	const char		*tul_acpi_name;
} topo_usb_lport_t;

typedef struct topo_usb_controller {
	topo_list_t	tuc_link;
	di_node_t	tuc_devinfo;
	char		*tuc_path;
	char		*tuc_acpi_path;
	char		tuc_name[PATH_MAX];
	topo_usb_cdrv_t	tuc_driver;
	/*
	 * Number of actual ports we've created (some of the logical ports are
	 * deduped).
	 */
	uint_t		tuc_nports;
	topo_list_t	tuc_ports;
	/*
	 * Total number of logical ports we expect to exist on this controller.
	 * This may be greater than the number of actual ports we've created
	 * under it because some physical ports represent more than one logical
	 * port (xhci with USB2/3).
	 */
	uint_t		tuc_nhubd_ports;
	/*
	 * Keep track of port number and offset information. This is only done
	 * for xhci.
	 */
	uint_t		tuc_nusb20;
	uint_t		tuc_fusb20;
	uint_t		tuc_nusb30;
	uint_t		tuc_fusb30;
	uint_t		tuc_nusb31;
	uint_t		tuc_fusb31;
	boolean_t	tuc_enumed;
} topo_usb_controller_t;

typedef struct topo_usb {
	topo_list_t	tu_controllers;
	boolean_t	tu_enum_done;
	di_node_t	tu_devinfo;
	topo_list_t	tu_metadata;
	topo_usb_meta_flags_t	tu_meta_flags;
	topo_list_t	tu_chassis_ports;
	uint_t		tu_nchassis_ports;
} topo_usb_t;

typedef struct topo_usb_devcfg_arg {
	topo_usb_t	*tda_usb;
	topo_mod_t	*tda_mod;
	boolean_t	tda_fatal;
} topo_usb_devcfg_arg_t;

static const topo_pgroup_info_t topo_usb_port_pgroup = {
	TOPO_PGROUP_USB_PORT,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t topo_io_pgroup = {
	TOPO_PGROUP_IO,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t topo_binding_pgroup = {
	TOPO_PGROUP_BINDING,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t topo_usb_props_pgroup = {
	TOPO_PGROUP_USB_PROPS,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

/* Required forwards */
static int topo_usb_enum_device(topo_mod_t *, tnode_t *, topo_usb_port_t *);

/*
 * Defines the maximum number of USB ports that can exist. Ports are basically
 * defined by a uint8_t, meaning that we can go up to UINT8_MAX inclusively.
 */
#define	USB_TOPO_PORT_MAX	256

/*
 * Default value to indicate that a USB port has no valid type.
 */
#define	USB_TOPO_PORT_TYPE_DEFAULT	0xff

/*
 * These come from the ACPI 6.2 / Table 9-290 UPC Return Package Values.
 */
static const char *
topo_usb_port_type_to_string(int type)
{
	switch (type) {
	case 0x00:
		return ("Type A connector");
	case 0x01:
		return ("Mini-AB connector");
	case 0x02:
		return ("ExpressCard");
	case 0x03:
		return ("USB 3 Standard-A connector");
	case 0x04:
		return ("USB 3 Standard-B connector");
	case 0x05:
		return ("USB 3 Micro-B connector");
	case 0x06:
		return ("USB 3 Micro-AB connector");
	case 0x07:
		return ("USB 3 Power-B connector");
	case 0x08:
		return ("Type C connector - USB2-only");
	case 0x09:
		return ("Type C connector - USB2 and SS with Switch");
	case 0x0A:
		return ("Type C connector - USB2 and SS without Switch");
	/* 0x0B->0xFE are reserved. Treat them like 0xFF */
	case 0xFF:
	default:
		return ("Unknown");
	}
}

/*
 * Searches the list of ports at a given layer (not recursively) for the
 * specific port id.
 */
static topo_usb_lport_t *
topo_usb_lport_find(topo_list_t *plist, uint_t logid)
{
	topo_usb_port_t *p;

	for (p = topo_list_next(plist); p != NULL; p = topo_list_next(p)) {
		topo_usb_lport_t *l;

		for (l = topo_list_next(&p->tup_lports); l != NULL;
		    l = topo_list_next(l)) {
			if (l->tul_portno == logid)
				return (l);
		}
	}
	return (NULL);
}

/*
 * Create an instance of a controller and seed the basic information.
 */
static topo_usb_controller_t *
topo_usb_controller_create(topo_mod_t *mod, topo_usb_t *usb, di_node_t node)
{
	int *pcount, inst;
	char *drvname, *acpi;
	topo_usb_controller_t *c;

	/*
	 * If we can't get the port count or the driver, then this node is
	 * uninteresting.
	 */
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "usb-port-count",
	    &pcount) != 1) {
		return (NULL);
	}

	if ((drvname = di_driver_name(node)) == NULL ||
	    (inst = di_instance(node) == -1))
		return (NULL);

	if ((c = topo_mod_zalloc(mod, sizeof (topo_usb_controller_t))) ==
	    NULL || *pcount <= 0) {
		return (NULL);
	}

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node, "acpi-namespace",
	    &acpi) == 1) {
		c->tuc_acpi_path = acpi;
	}

	c->tuc_nhubd_ports = (uint_t)*pcount;
	c->tuc_devinfo = node;
	c->tuc_path = di_devfs_path(node);
	(void) snprintf(c->tuc_name, sizeof (c->tuc_name), "%s%d", drvname,
	    inst);
	if (strcmp(drvname, "xhci") == 0) {
		int *p;

		c->tuc_driver = TOPO_USB_D_XHCI;

		/*
		 * Grab the properties that we need so we can better do a port
		 * speed mapping.
		 */
		if (di_prop_lookup_ints(DDI_DEV_T_ANY, node,
		    "usb2.0-port-count", &p) == 1 && *p > 0) {
			c->tuc_nusb20 = (uint_t)*p;
		}

		if (di_prop_lookup_ints(DDI_DEV_T_ANY, node,
		    "usb2.0-first-port", &p) == 1 && *p > 0) {
			c->tuc_fusb20 = (uint_t)*p;
		}

		if (di_prop_lookup_ints(DDI_DEV_T_ANY, node,
		    "usb3.0-port-count", &p) == 1 && *p > 0) {
			c->tuc_nusb30 = (uint_t)*p;
		}

		if (di_prop_lookup_ints(DDI_DEV_T_ANY, node,
		    "usb3.0-first-port", &p) == 1 && *p > 0) {
			c->tuc_fusb30 = (uint_t)*p;
		}

		if (di_prop_lookup_ints(DDI_DEV_T_ANY, node,
		    "usb3.1-port-count", &p) == 1 && *p > 0) {
			c->tuc_nusb31 = (uint_t)*p;
		}

		if (di_prop_lookup_ints(DDI_DEV_T_ANY, node,
		    "usb3.1-first-port", &p) == 1 && *p > 0) {
			c->tuc_fusb31 = (uint_t)*p;
		}
	} else if (strcmp(drvname, "ehci") == 0) {
		c->tuc_driver = TOPO_USB_D_EHCI;
	} else if (strcmp(drvname, "uhci") == 0) {
		c->tuc_driver = TOPO_USB_D_UHCI;
	} else if (strcmp(drvname, "ohci") == 0) {
		c->tuc_driver = TOPO_USB_D_OHCI;
	} else {
		c->tuc_driver = TOPO_USB_D_UNKNOWN;
	}
	topo_list_append(&usb->tu_controllers, c);
	topo_mod_dprintf(mod, "created new USB controller at %s", c->tuc_path);

	return (c);
}

/*
 * Process this port and any others that might exist.
 */
static boolean_t
topo_usb_gather_acpi_port(topo_mod_t *mod, topo_usb_t *usb, topo_list_t *plist,
    uint_t *nports, topo_usb_controller_t *tuc, di_node_t portinfo)
{
	int64_t *portno;
	uchar_t *loc;
	int loclen, *type;
	char *acpi;
	acpi_pld_info_t pld;
	boolean_t pld_valid = B_FALSE;
	topo_usb_port_t *port = NULL;
	topo_usb_lport_t *lport;
	di_node_t child;

	/*
	 * Get the port's address, it's a required value. Because this is coming
	 * from firmware, we cannot trust the port's value to be correct.
	 */
	if (di_prop_lookup_int64(DDI_DEV_T_ANY, portinfo, "acpi-address",
	    &portno) != 1 || *portno < 1 || *portno >= USB_TOPO_PORT_MAX) {
		return (B_FALSE);
	}

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, portinfo, "acpi-namespace",
	    &acpi) != 1) {
		return (B_FALSE);
	}

	/*
	 * Check to see if we have any ACPI location information. If we do, we
	 * can decode it.
	 */
	if ((loclen = di_prop_lookup_bytes(DDI_DEV_T_ANY, portinfo,
	    "acpi-physical-location", &loc)) >= ACPI_PLD_REV1_BUFFER_SIZE &&
	    usbtopo_decode_pld(loc, loclen, &pld)) {
		pld_valid = B_TRUE;
	}

	/*
	 * Find the corresponding lport. If this node doesn't happen to match
	 * something we've enumerated from the hub. Warn about that fact and
	 * consider this bad data.
	 */
	lport = topo_usb_lport_find(plist, (uint_t)*portno);
	if (lport == NULL) {
		topo_mod_dprintf(mod, "failed to find physical usb port for "
		    "%s/%u", acpi, (uint_t)*portno);
		return (B_TRUE);
	}

	if (lport->tul_acpi_device != DI_NODE_NIL) {
		topo_mod_dprintf(mod, "logical port already bound to %s, not "
		    "binding to %s", lport->tul_acpi_name, acpi);
		return (B_FALSE);
	}

	lport->tul_acpi_device = portinfo;
	lport->tul_acpi_name = acpi;
	port = lport->tul_port;

	if (pld_valid) {
		port->tup_pld_valid = B_TRUE;
		port->tup_pld = pld;
	}

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, portinfo, "usb-port-type",
	    &type) == 1 && *type >= 0) {
		port->tup_port_type = *type;
	} else {
		port->tup_port_type = USB_TOPO_PORT_TYPE_DEFAULT;
	}

	if (di_prop_find(DDI_DEV_T_ANY, portinfo,
	    "usb-port-connectable") != DI_PROP_NIL) {
		port->tup_port_connected = TOPO_USB_C_CONNECTED;
	} else {
		port->tup_port_connected = TOPO_USB_C_DISCONNECTED;
	}

	for (child = di_child_node(portinfo); child != NULL;
	    child = di_sibling_node(child)) {
		const char *pname;

		pname = di_node_name(child);
		if (pname == NULL || strcmp(pname, "port") != 0) {
			continue;
		}

		if (!topo_usb_gather_acpi_port(mod, usb, &lport->tul_ports,
		    &lport->tul_nports, tuc, child)) {
			return (B_FALSE);
		}
	}

	topo_mod_dprintf(mod, "discovered %u ACPI usb child ports",
	    lport->tul_nports);

	return (B_TRUE);
}

/*
 * First, bootstrap all of our information by reading the ACPI information
 * exposed in the devinfo tree. All of the nodes we care about will be under
 * /fw/sb@XX/usbrootub@YYY/port@ZZZ
 */
static boolean_t
topo_usb_gather_acpi(topo_mod_t *mod, topo_usb_t *usb)
{
	di_node_t fwroot, sbnode;

	/*
	 * If we can't find the /fw node, that's fine. We may not have any ACPI
	 * information on the system.
	 */
	fwroot = di_lookup_node(usb->tu_devinfo, "/fw");
	if (fwroot == DI_NODE_NIL)
		return (B_TRUE);

	for (sbnode = di_child_node(fwroot); sbnode != DI_NODE_NIL;
	    sbnode = di_sibling_node(sbnode)) {
		const char *sbname;
		di_node_t hub;

		sbname = di_node_name(sbnode);
		if (sbname == NULL || strcmp(sbname, "sb") != 0) {
			continue;
		}

		for (hub = di_child_node(sbnode); hub != DI_NODE_NIL;
		    hub = di_sibling_node(hub)) {
			const char *hubname;
			char *acpi;
			topo_usb_controller_t *tuc;
			di_node_t port;

			hubname = di_node_name(hub);
			if (hubname == NULL ||
			    strcmp(hubname, "usbroothub") != 0) {
				continue;
			}

			if (di_prop_lookup_strings(DDI_DEV_T_ANY, hub,
			    "acpi-controller-name", &acpi) != 1) {
				continue;
			}

			for (tuc = topo_list_next(&usb->tu_controllers);
			    tuc != NULL;
			    tuc = topo_list_next(tuc)) {
				if (tuc->tuc_acpi_path != NULL &&
				    strcmp(acpi, tuc->tuc_acpi_path) == 0)
					break;
			}

			if (tuc == NULL) {
				topo_mod_dprintf(mod, "failed to find USB "
				    "controller for ACPI path %s", acpi);
				continue;
			}

			for (port = di_child_node(hub); port != NULL;
			    port = di_sibling_node(port)) {
				const char *pname;

				pname = di_node_name(port);
				if (pname == NULL ||
				    strcmp(pname, "port") != 0) {
					continue;
				}

				if (!topo_usb_gather_acpi_port(mod, usb,
				    &tuc->tuc_ports, &tuc->tuc_nports, tuc,
				    port)) {
					return (B_FALSE);
				}
			}

			topo_mod_dprintf(mod, "found ACPI usb controller %s "
			    "with %d top-level ports", tuc->tuc_path,
			    tuc->tuc_nports);
		}
	}

	return (B_TRUE);
}

static topo_usb_port_t *
topo_usb_port_create(topo_mod_t *mod, uint_t portno, const char *parent,
    char sep)
{
	topo_usb_lport_t *l;
	topo_usb_port_t *p;

	if ((l = topo_mod_zalloc(mod, sizeof (topo_usb_lport_t))) == NULL) {
		return (NULL);
	}
	l->tul_portno = portno;
	if (snprintf(l->tul_name, sizeof (l->tul_name), "%s%c%u", parent, sep,
	    portno) >= sizeof (l->tul_name)) {
		topo_mod_free(mod, l, sizeof (topo_usb_lport_t));
		return (NULL);
	}

	if ((p = topo_mod_zalloc(mod, sizeof (topo_usb_port_t))) == NULL) {
		topo_mod_free(mod, l, sizeof (topo_usb_lport_t));
		return (NULL);
	}
	l->tul_port = p;
	p->tup_port_type = USB_TOPO_PORT_TYPE_DEFAULT;
	topo_list_append(&p->tup_lports, l);
	p->tup_nlports++;

	return (p);
}

/*
 * Set the protocol of a port that belongs to a root hub.
 */
static void
topo_usb_set_rhub_port_protocol(topo_mod_t *mod, topo_usb_controller_t *tuc,
    topo_usb_lport_t *lport)
{
	switch (tuc->tuc_driver) {
	case TOPO_USB_D_XHCI:
		break;
	case TOPO_USB_D_UHCI:
	case TOPO_USB_D_OHCI:
		lport->tul_protocol = TOPO_USB_P_1x;
		return;
	case TOPO_USB_D_EHCI:
		lport->tul_protocol = TOPO_USB_P_20;
		return;
	case TOPO_USB_D_UNKNOWN:
	default:
		lport->tul_protocol = TOPO_USB_P_UNKNOWN;
		return;
	}

	/*
	 * The xHCI controller can support multiple different, protocols. It
	 * communicates this information to us via devinfo properties. It's
	 * possible that a port that is within max ports is not within the range
	 * here. If that's the case, we'll set it to unknown.
	 */
	if (lport->tul_portno >= tuc->tuc_fusb20 &&
	    lport->tul_portno < tuc->tuc_fusb20 + tuc->tuc_nusb20) {
		lport->tul_protocol = TOPO_USB_P_20;
	} else if (lport->tul_portno >= tuc->tuc_fusb30 &&
	    lport->tul_portno < tuc->tuc_fusb30 + tuc->tuc_nusb30) {
		lport->tul_protocol = TOPO_USB_P_30;
	} else if (lport->tul_portno >= tuc->tuc_fusb31 &&
	    lport->tul_portno < tuc->tuc_fusb31 + tuc->tuc_nusb31) {
		lport->tul_protocol = TOPO_USB_P_31;
	} else {
		lport->tul_protocol = TOPO_USB_P_UNKNOWN;
	}
}

/*
 * We've found a node on the list. Attempt to find its corresponding port. If we
 * find a hub, then we will descend further down this part of the tree.
 */
static int
topo_usb_gather_devcfg_port(topo_mod_t *mod, topo_usb_controller_t *c,
    topo_list_t *plist, di_node_t node)
{
	int *vend, *reg, *nports;
	topo_usb_lport_t *l;
	char *drvname;

	/*
	 * Look for the presence of the usb-vendor-id property to determine
	 * whether or not this is a usb device node. usba always adds this
	 * to the devices that it enumerates.
	 */
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "usb-vendor-id",
	    &vend) != 1) {
		topo_mod_dprintf(mod, "failed to find usb-vendor-id property "
		    "for child");
		return (0);
	}

	/*
	 * For usb-devices, the reg property is one entry long and it has the
	 * logical port that the controller sees.
	 */
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "reg", &reg) != 1 ||
	    *reg <= 0) {
		topo_mod_dprintf(mod, "got bad \"reg\" property");
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
	}

	if ((l = topo_usb_lport_find(plist, (uint_t)*reg)) == NULL) {
		topo_mod_dprintf(mod, "failed to find topo_usb_lport_t for "
		    "port %d", *reg);
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	l->tul_device = node;

	/*
	 * Check to see if we have a hub and if so, process it.
	 */
	if ((drvname = di_driver_name(node)) != NULL &&
	    strcmp(drvname, "hubd") == 0 &&
	    di_prop_lookup_ints(DDI_DEV_T_ANY, node, "usb-port-count",
	    &nports) == 1 && *nports >= 1) {
		di_node_t child;

		/*
		 * First go through and try and discover and create all the
		 * logical ports that exist. It is possible that these ports
		 * already exist and that we have ACPI information about them.
		 * This would happen when a root port is connected into a set of
		 * hubs that are built-in.
		 */
		l->tul_nhubd_ports = (uint_t)*nports;
		for (uint_t i = 1; i <= l->tul_nhubd_ports; i++) {
			topo_usb_lport_t *clport;
			topo_usb_port_t *cport;

			if ((cport = topo_usb_port_create(mod, i, l->tul_name,
			    '.')) == NULL) {
				return (topo_mod_seterrno(mod, EMOD_NOMEM));
			}

			clport = topo_list_next(&cport->tup_lports);
			topo_list_append(&l->tul_ports, cport);
			l->tul_nports++;

			clport->tul_protocol = l->tul_protocol;
		}

		/*
		 * Now go through and discover its children.
		 */
		for (child = di_child_node(node); child != NULL;
		    child = di_sibling_node(child)) {
			int ret;

			if ((ret = topo_usb_gather_devcfg_port(mod, c,
			    &l->tul_ports, child)) != 0) {
				return (-1);
			}
		}
	}

	return (0);
}

static int
topo_usb_gather_devcfg_cb(di_node_t node, void *arg)
{
	uint_t i;
	topo_usb_controller_t *tuc;
	di_prop_t prop = DI_PROP_NIL;
	boolean_t rh = B_FALSE, pc = B_FALSE;
	topo_usb_devcfg_arg_t *tda = arg;
	topo_usb_t *usb = tda->tda_usb;
	topo_mod_t *mod = tda->tda_mod;
	di_node_t child;

	while ((prop = di_prop_next(node, prop)) != DI_PROP_NIL) {
		const char *name = di_prop_name(prop);
		int *ports;

		if (strcmp(name, "root-hub") == 0 &&
		    di_prop_type(prop) == DI_PROP_TYPE_BOOLEAN) {
			rh = B_TRUE;
		} else if (strcmp(name, "usb-port-count") == 0 &&
		    di_prop_ints(prop, &ports) == 1 && *ports > 0 &&
		    *ports < USB_TOPO_PORT_MAX) {
			pc = B_TRUE;
		}
	}

	if (!rh || !pc)
		return (DI_WALK_CONTINUE);

	if ((tuc = topo_usb_controller_create(mod, usb, node)) == NULL) {
		tda->tda_fatal = B_TRUE;
		return (DI_WALK_TERMINATE);
	}

	/*
	 * Check to make sure that every logical port exists at this level and
	 * that we have its speed information filled in. If it does not exist,
	 * create it.
	 */
	for (i = 1; i <= tuc->tuc_nhubd_ports; i++) {
		topo_usb_lport_t *l;
		topo_usb_port_t *p;

		topo_mod_dprintf(mod, "attempting to discover lport %u on "
		    "controller %s", i, tuc->tuc_path);

		if ((p = topo_usb_port_create(mod, i, tuc->tuc_name, '@')) ==
		    NULL) {
			topo_mod_dprintf(mod, "failed to create "
			    "port %u", i);
			tda->tda_fatal = B_TRUE;
			return (DI_WALK_TERMINATE);
		}

		topo_list_append(&tuc->tuc_ports, p);
		tuc->tuc_nports++;
		l = topo_list_next(&p->tup_lports);

		topo_usb_set_rhub_port_protocol(mod, tuc, l);
	}

	for (child = di_child_node(tuc->tuc_devinfo); child != NULL;
	    child = di_sibling_node(child)) {
		int ret;

		if ((ret = topo_usb_gather_devcfg_port(mod, tuc,
		    &tuc->tuc_ports, child)) != 0) {
			tda->tda_fatal = B_TRUE;
			return (DI_WALK_TERMINATE);
		}
	}

	return (DI_WALK_PRUNECHILD);
}

/*
 * To find all the controllers in the system, look for device nodes that have
 * the 'root-hub' property and also a valid usb-port-count property.
 */
static boolean_t
topo_usb_gather_devcfg(topo_mod_t *mod, topo_usb_t *usb)
{
	topo_usb_devcfg_arg_t tda;

	tda.tda_usb = usb;
	tda.tda_mod = mod;
	tda.tda_fatal = B_FALSE;

	(void) di_walk_node(usb->tu_devinfo, DI_WALK_CLDFIRST,
	    &tda, topo_usb_gather_devcfg_cb);

	return (!tda.tda_fatal);
}

/*
 * For more information on the matching logic here, see xHCI r1.1 / Appendix D -
 * Port to Connector Mapping.
 */
static boolean_t
topo_usb_acpi_pld_match(const acpi_pld_info_t *l, const acpi_pld_info_t *r)
{
	if (l->Panel == r->Panel &&
	    l->VerticalPosition == r->VerticalPosition &&
	    l->HorizontalPosition == r->HorizontalPosition &&
	    l->Shape == r->Shape &&
	    l->GroupOrientation == r->GroupOrientation &&
	    l->GroupPosition == r->GroupPosition &&
	    l->GroupToken == r->GroupToken) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

typedef boolean_t (*topo_usb_port_match_f)(topo_usb_port_t *, void *);

static topo_usb_port_t *
topo_usb_port_match_lport(topo_usb_lport_t *lport, boolean_t remove,
    topo_usb_port_match_f func, void *arg)
{
	topo_usb_port_t *p;

	for (p = topo_list_next(&lport->tul_ports); p != NULL;
	    p = topo_list_next(p)) {
		topo_usb_lport_t *l;
		topo_usb_port_t *ret;

		if (func(p, arg)) {
			if (remove) {
				topo_list_delete(&lport->tul_ports, p);
				lport->tul_nports--;
			}

			return (p);
		}

		for (l = topo_list_next(&p->tup_lports); l != NULL;
		    l = topo_list_next(l)) {
			if ((ret = topo_usb_port_match_lport(l,
			    remove, func, arg)) != NULL) {
				return (ret);
			}
		}
	}

	return (NULL);
}

static topo_usb_port_t *
topo_usb_port_match_controller(topo_usb_controller_t *c, boolean_t remove,
    topo_usb_port_match_f func, void *arg)
{
	topo_usb_port_t *p;

	for (p = topo_list_next(&c->tuc_ports); p != NULL;
	    p = topo_list_next(p)) {
		topo_usb_lport_t *l;
		topo_usb_port_t *ret;

		if (func(p, arg)) {
			if (remove) {
				topo_list_delete(&c->tuc_ports, p);
				c->tuc_nports--;
			}

			return (p);
		}

		for (l = topo_list_next(&p->tup_lports); l != NULL;
		    l = topo_list_next(l)) {
			if ((ret = topo_usb_port_match_lport(l,
			    remove, func, arg)) != NULL) {
				return (ret);
			}
		}
	}

	return (NULL);
}

static topo_usb_port_t *
topo_usb_port_match(topo_usb_t *usb, boolean_t remove,
    topo_usb_port_match_f func, void *arg)
{
	topo_usb_controller_t *c;

	for (c = topo_list_next(&usb->tu_controllers); c != NULL;
	    c = topo_list_next(c)) {
		topo_usb_port_t *p;

		if ((p = topo_usb_port_match_controller(c, remove, func,
		    arg)) != NULL)
			return (p);
	}
	return (NULL);
}

/*
 * Merge all of the local ports and information in source, to sink.
 */
static void
topo_usb_port_merge(topo_usb_port_t *sink, topo_usb_port_t *source)
{
	topo_usb_lport_t *l;

	while ((l = topo_list_next(&source->tup_lports)) != NULL) {
		topo_list_delete(&source->tup_lports, l);
		source->tup_nlports--;
		topo_list_append(&sink->tup_lports, l);
		sink->tup_nlports++;
	}

	if (sink->tup_port_type == USB_TOPO_PORT_TYPE_DEFAULT) {
		sink->tup_port_type = source->tup_port_type;
	}

	if (sink->tup_port_connected == TOPO_USB_C_UNKNOWN) {
		sink->tup_port_connected = source->tup_port_connected;
	}
}

static boolean_t
topo_usb_acpi_port_match(topo_usb_port_t *port, void *arg)
{
	topo_usb_port_t *target = arg;

	return (port != target && port->tup_pld_valid &&
	    topo_usb_acpi_pld_match(&port->tup_pld, &target->tup_pld));
}

/*
 * Ports on an xhci controller can match up. If we've been told that we should
 * do so, attempt to perform that match. We only try to find matches in the top
 * level ports of an xhci controller as that's what's most common on systems,
 * though we'll search all the descendants.
 */
static void
topo_usb_acpi_match(topo_mod_t *mod, topo_usb_controller_t *tuc)
{
	topo_usb_port_t *p;

	for (p = topo_list_next(&tuc->tuc_ports); p != NULL;
	    p = topo_list_next(p)) {
		topo_usb_port_t *match;

		if ((match = topo_usb_port_match_controller(tuc, B_TRUE,
		    topo_usb_acpi_port_match, p)) != NULL) {
			VERIFY3P(p, !=, match);
			topo_usb_port_merge(p, match);
			topo_mod_free(mod, match, sizeof (topo_usb_port_t));
		}
	}
}

static boolean_t
topo_usb_metadata_match(topo_usb_port_t *port, void *arg)
{
	topo_usb_meta_port_path_t *path = arg;
	topo_usb_lport_t *l;

	if (path->tmpp_type != TOPO_USB_T_ACPI)
		return (B_FALSE);

	for (l = topo_list_next(&port->tup_lports); l != NULL;
	    l = topo_list_next(l)) {
		if (l->tul_acpi_name != NULL && strcmp(path->tmpp_path,
		    l->tul_acpi_name) == 0) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * We've found metadata describing the USB ports. We need to now go through and
 * try to match that data up to actual nodes.
 */
static void
topo_usb_apply_metadata(topo_mod_t *mod, topo_usb_t *usb)
{
	topo_usb_meta_port_t *m;

	for (m = topo_list_next(&usb->tu_metadata); m != NULL;
	    m = topo_list_next(m)) {
		topo_usb_port_t *p, *sink = NULL;
		topo_usb_meta_port_path_t *path;
		boolean_t remove = B_FALSE;

		/*
		 * If this is a chassis node, we'll remove the port and move it
		 * to the chassis.
		 */
		if (m->tmp_flags & TOPO_USB_F_CHASSIS) {
			remove = B_TRUE;
		}

		for (path = topo_list_next(&m->tmp_paths); path != NULL;
		    path = topo_list_next(path)) {
			topo_mod_dprintf(mod, "considering metadata path %s",
			    path->tmpp_path);
			if ((p = topo_usb_port_match(usb, remove,
			    topo_usb_metadata_match, path)) == NULL)
				continue;
			topo_mod_dprintf(mod, "matched path to a logical port");
			p->tup_meta = m;

			/*
			 * Check if we can move this to the Chassis. We should
			 * always do this on the first port in a group. However,
			 * if it's a match candidate, then it will have already
			 * been appended.
			 */
			if ((m->tmp_flags & TOPO_USB_F_CHASSIS) != 0 &&
			    sink == NULL) {
				topo_list_append(&usb->tu_chassis_ports, p);
				usb->tu_nchassis_ports++;
			}

			if ((usb->tu_meta_flags & TOPO_USB_M_METADATA_MATCH) !=
			    0) {
				if (sink == NULL) {
					sink = p;
					remove = B_TRUE;
				} else {
					VERIFY3P(p, !=, sink);
					topo_usb_port_merge(sink, p);
					topo_mod_free(mod, p,
					    sizeof (topo_usb_port_t));
				}
				continue;
			}

			break;
		}

	}
}

static int
topo_usb_gather(topo_mod_t *mod, topo_usb_t *usb, tnode_t *pnode)
{
	int ret;

	if ((ret = topo_usb_load_metadata(mod, pnode, &usb->tu_metadata,
	    &usb->tu_meta_flags)) != 0) {
		topo_mod_dprintf(mod, "failed to read usb metadata");
		return (-1);
	}
	topo_mod_dprintf(mod, "loaded metadata flags: %d", usb->tu_meta_flags);

	if (!topo_usb_gather_devcfg(mod, usb)) {
		topo_mod_dprintf(mod, "encountered fatal error while "
		    "gathering physical data");
		return (-1);
	}

	if ((usb->tu_meta_flags & TOPO_USB_M_NO_ACPI) == 0 &&
	    !topo_usb_gather_acpi(mod, usb)) {
		topo_mod_dprintf(mod, "encountered fatal error while "
		    "gathering ACPI data");
		return (-1);
	}

	if ((usb->tu_meta_flags & TOPO_USB_M_ACPI_MATCH) != 0) {
		topo_usb_controller_t *c;

		for (c = topo_list_next(&usb->tu_controllers); c != NULL;
		    c = topo_list_next(c)) {
			if (c->tuc_driver == TOPO_USB_D_XHCI) {
				topo_usb_acpi_match(mod, c);
			}
		}
	}

	topo_usb_apply_metadata(mod, usb);

	return (0);
}

static int
topo_usb_port_properties(topo_mod_t *mod, tnode_t *tn, topo_usb_port_t *port)
{
	int err;
	char **strs = NULL;
	uint_t i;
	topo_usb_lport_t *l;
	char *label;
	const char *ptype;
	size_t strlen;

	strlen = sizeof (char *) * MAX(port->tup_nlports,
	    TOPO_PROP_USB_PORT_NATTRS);
	if ((strs = topo_mod_zalloc(mod, strlen)) == NULL) {
		return (-1);
	}

	label = NULL;
	if (port->tup_meta != NULL) {
		label = port->tup_meta->tmp_label;
	}

	if (port->tup_meta != NULL && port->tup_meta->tmp_port_type !=
	    USB_TOPO_PORT_TYPE_DEFAULT) {
		ptype =
		    topo_usb_port_type_to_string(port->tup_meta->tmp_port_type);
	} else {
		ptype = topo_usb_port_type_to_string(port->tup_port_type);
	}

	if (topo_pgroup_create(tn, &topo_usb_port_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create property group %s: "
		    "%s\n", TOPO_PGROUP_USB_PORT, topo_strerror(err));
		goto error;

	}

	if (label != NULL && topo_node_label_set(tn, label, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set label on port: %s",
		    topo_strerror(err));
		goto error;
	}

	if (ptype != NULL && topo_prop_set_string(tn, TOPO_PGROUP_USB_PORT,
	    TOPO_PROP_USB_PORT_TYPE, TOPO_PROP_IMMUTABLE, ptype, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s property: %s",
		    TOPO_PROP_USB_PORT_TYPE, topo_strerror(err));
		goto error;
	}

	for (i = 0, l = topo_list_next(&port->tup_lports); l != NULL;
	    l = topo_list_next(l)) {
		char *vers;
		int j;

		switch (l->tul_protocol) {
		case TOPO_USB_P_1x:
			vers = "1.x";
			break;
		case TOPO_USB_P_20:
			vers = "2.0";
			break;
		case TOPO_USB_P_30:
			vers = "3.0";
			break;
		case TOPO_USB_P_31:
			vers = "3.1";
			break;
		default:
			continue;
		}

		/*
		 * Make sure we don't already have this string. This can happen
		 * when we have an ehci port and xhci support that both provide
		 * USB 2.0 service.
		 */
		for (j = 0; j < i; j++) {
			if (strcmp(strs[j], vers) == 0)
				break;
		}

		if (j < i)
			continue;
		strs[i++] = vers;
	}

	if (i > 0 && topo_prop_set_string_array(tn, TOPO_PGROUP_USB_PORT,
	    TOPO_PROP_USB_PORT_VERSIONS, TOPO_PROP_IMMUTABLE,
	    (const char **)strs, i, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s property: %s",
		    TOPO_PROP_USB_PORT_VERSIONS, topo_strerror(err));
		goto error;
	}

	i = 0;
	if (port->tup_pld_valid && port->tup_pld.UserVisible != 0 &&
	    port->tup_port_connected == TOPO_USB_C_CONNECTED) {
		strs[i++] = TOPO_PROP_USB_PORT_A_VISIBLE;
	} else if (port->tup_port_connected == TOPO_USB_C_CONNECTED) {
		strs[i++] = TOPO_PROP_USB_PORT_A_CONNECTED;
	} else if (port->tup_port_connected == TOPO_USB_C_DISCONNECTED) {
		strs[i++] = TOPO_PROP_USB_PORT_A_DISCONNECTED;
	}

	if (port->tup_meta != NULL) {
		if (port->tup_meta->tmp_flags & TOPO_USB_F_INTERNAL) {
			strs[i++] = TOPO_PROP_USB_PORT_A_INTERNAL;
		}

		if (port->tup_meta->tmp_flags & TOPO_USB_F_EXTERNAL) {
			strs[i++] = TOPO_PROP_USB_PORT_A_EXTERNAL;
		}
	}

	if (i > 0 && topo_prop_set_string_array(tn, TOPO_PGROUP_USB_PORT,
	    TOPO_PROP_USB_PORT_ATTRIBUTES, TOPO_PROP_IMMUTABLE,
	    (const char **)strs, i, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s property: %s",
		    TOPO_PROP_USB_PORT_VERSIONS, topo_strerror(err));
		goto error;
	}

	for (i = 0, l = topo_list_next(&port->tup_lports); l != NULL;
	    l = topo_list_next(l)) {
		strs[i++] = l->tul_name;
	}

	if (i > 0 && topo_prop_set_string_array(tn, TOPO_PGROUP_USB_PORT,
	    TOPO_PROP_USB_PORT_LPORTS, TOPO_PROP_IMMUTABLE,
	    (const char **)strs, i, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s propert: %s",
		    TOPO_PROP_USB_PORT_LPORTS, topo_strerror(err));
		goto error;
	}

	err = 0;
error:
	if (strs != NULL) {
		topo_mod_free(mod, strs, strlen);
	}

	if (err != 0) {
		return (topo_mod_seterrno(mod, err));
	}

	return (err);
}

/*
 * Create a disk node under the scsa2usb node. When we have an scsa2usb node,
 * we'll have a child devinfo which is a disk. To successfully enumerate this,
 * we need to find the child node (which should be our only direct descendent)
 * and get its devfs path. From there we can construct a 'binding' property
 * group with the 'occupantpath' property that points to the module. At that
 * point we can invoke the disk enumerator.
 */
static int
topo_usb_enum_scsa2usb(topo_mod_t *mod, tnode_t *tn, topo_usb_lport_t *lport)
{
	int ret;
	di_node_t child;
	char *devfs = NULL;
	topo_instance_t min = 0, max = 0;

	if ((child = di_child_node(lport->tul_device)) == DI_NODE_NIL ||
	    strcmp("disk", di_node_name(child)) != 0) {
		return (0);
	}

	if ((devfs = di_devfs_path(child)) == NULL) {
		topo_mod_dprintf(mod, "failed to get USB disk child device "
		    "devfs path");
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	if (topo_mod_load(mod, DISK, TOPO_VERSION) == NULL) {
		topo_mod_dprintf(mod, "failed to load disk module: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	if (topo_pgroup_create(tn, &topo_binding_pgroup, &ret) != 0) {
		topo_mod_dprintf(mod, "failed to create \"binding\" "
		    "property group: %s", topo_strerror(ret));
		goto error;
	}

	if (topo_prop_set_string(tn, TOPO_PGROUP_BINDING,
	    TOPO_BINDING_OCCUPANT, TOPO_PROP_IMMUTABLE, devfs, &ret) !=
	    0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s",
		    TOPO_IO_MODULE, topo_strerror(ret));
		goto error;
	}

	if (topo_node_range_create(mod, tn, DISK, min, max) != 0) {
		topo_mod_dprintf(mod, "failed to create disk node range %s: %s",
		    devfs, topo_mod_errmsg(mod));
		goto error;
	}

	if (topo_mod_enumerate(mod, tn, DISK, DISK, min, max, NULL) != 0) {
		topo_mod_dprintf(mod, "failed to create disk node %s: %s",
		    devfs, topo_mod_errmsg(mod));
		goto error;
	}
	di_devfs_path_free(devfs);

	return (0);

error:
	di_devfs_path_free(devfs);
	return (-1);
}

static int
topo_usb_enum_port_children(topo_mod_t *mod, tnode_t *pn,
    topo_usb_lport_t *plport)
{
	int ret;
	topo_usb_port_t *port;
	topo_instance_t min = 0, i;

	if ((ret = port_range_create(mod, pn, min, plport->tul_nports)) != 0) {
		topo_mod_dprintf(mod, "failed to create port range [%u, %u) "
		    "for child hub", 0, plport->tul_nports);
		return (ret);
	}

	for (i = 0, port = topo_list_next(&plport->tul_ports); port != NULL;
	    port = topo_list_next(port)) {
		tnode_t *tn;
		if ((ret = port_create_usb(mod, pn, i, &tn)) != 0)
			return (ret);

		if ((ret = topo_usb_port_properties(mod, tn, port)) != 0) {
			return (ret);
		}

		if ((ret = topo_usb_enum_device(mod, tn, port)) != 0)
			return (ret);

		i++;
	}

	return (0);
}

/*
 * Enumerate the requested device. Depending on the driver associated with it
 * (if any), we may have to create child nodes.
 */
static int
topo_usb_enum_lport(topo_mod_t *mod, tnode_t *pn, topo_usb_port_t *port,
    topo_usb_lport_t *lport, topo_instance_t topo_inst)
{
	int ret, inst;
	int *vendid = NULL, *prodid = NULL, *revid = NULL, *release = NULL;
	char *vend = NULL, *prod = NULL, *serial = NULL, *speed = NULL;
	char *min_speed = NULL, *sup_speeds = NULL;
	int nsup_speeds = 0;
	char *driver, *devfs;
	char revbuf[32], relbuf[32];
	tnode_t *tn = NULL;
	di_prop_t prop = DI_PROP_NIL;
	nvlist_t *auth = NULL, *fmri = NULL, *modnvl = NULL;

	/*
	 * Look up the information we'll need to create the usb-properties. We
	 * do this first because this information is often part of the FMRI.
	 */
	for (prop = di_prop_next(lport->tul_device, DI_PROP_NIL);
	    prop != DI_PROP_NIL; prop = di_prop_next(lport->tul_device, prop)) {
		const char *pname = di_prop_name(prop);

		if (strcmp(pname, "usb-vendor-id") == 0) {
			if (di_prop_ints(prop, &vendid) != 1)
				vendid = NULL;
		} else if (strcmp(pname, "usb-product-id") == 0) {
			if (di_prop_ints(prop, &prodid) != 1)
				prodid = NULL;
		} else if (strcmp(pname, "usb-revision-id") == 0) {
			if (di_prop_ints(prop, &revid) != 1) {
				revid = NULL;
			} else {
				(void) snprintf(revbuf, sizeof (revbuf), "%x",
				    *revid);
			}
		} else if (strcmp(pname, "usb-release") == 0) {
			if (di_prop_ints(prop, &release) != 1) {
				release = NULL;
			} else {
				(void) snprintf(relbuf, sizeof (relbuf),
				    "%x.%x", *release >> 8,
				    (*release >> 4) & 0xf);
			}
		} else if (strcmp(pname, "usb-vendor-name") == 0) {
			if (di_prop_strings(prop, &vend) != 1)
				vend = NULL;
		} else if (strcmp(pname, "usb-product-name") == 0) {
			if (di_prop_strings(prop, &prod) != 1)
				prod = NULL;
		} else if (strcmp(pname, "usb-serialno") == 0) {
			if (di_prop_strings(prop, &serial) != 1)
				serial = NULL;
		} else if (strcmp(pname, "full-speed") == 0) {
			speed = "full-speed";
		} else if (strcmp(pname, "low-speed") == 0) {
			speed = "low-speed";
		} else if (strcmp(pname, "high-speed") == 0) {
			speed = "high-speed";
		} else if (strcmp(pname, "super-speed") == 0) {
			speed = "super-speed";
		} else if (strcmp(pname, "usb-minimum-speed") == 0) {
			if (di_prop_strings(prop, &min_speed) != 1)
				min_speed = NULL;
		} else if (strcmp(pname, "usb-supported-speeds") == 0) {
			nsup_speeds = di_prop_strings(prop, &sup_speeds);
			if (nsup_speeds <= 0) {
				sup_speeds = NULL;
			}
		}
	}

	driver = di_driver_name(lport->tul_device);
	inst = di_instance(lport->tul_device);
	devfs = di_devfs_path(lport->tul_device);

	if ((auth = topo_mod_auth(mod, pn)) == NULL) {
		topo_mod_dprintf(mod, "failed to get authority for USB device: "
		    "%s", topo_mod_errmsg(mod));
		goto error;
	}

	if ((fmri = topo_mod_hcfmri(mod, pn, FM_HC_SCHEME_VERSION, USB_DEVICE,
	    topo_inst, NULL, auth, prod, revbuf, serial)) == NULL) {
		topo_mod_dprintf(mod, "failed to generate fmri for USB "
		    "device %s: %s", di_devfs_path(lport->tul_device),
		    topo_mod_errmsg(mod));
		goto error;
	}

	if ((tn = topo_node_bind(mod, pn, USB_DEVICE, topo_inst, fmri)) ==
	    NULL) {
		topo_mod_dprintf(mod, "failed to bind USB device node: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	/*
	 * In general, we expect a USB device to be its own FRU. There are some
	 * exceptions to this, for example, a built-in hub. However, it's hard
	 * for us to generally know. It may be nice to allow the platform to
	 * override this in the future.
	 */
	if (topo_node_fru_set(tn, fmri, 0, &ret) != 0) {
		topo_mod_dprintf(mod, "failed to set FRU: %s",
		    topo_strerror(ret));
		(void) topo_mod_seterrno(mod, ret);
		goto error;
	}

	/*
	 * Inherit the label from the port on the device. This is intended to
	 * only go a single way.
	 */
	if (port->tup_meta != NULL && port->tup_meta->tmp_label != NULL &&
	    topo_node_label_set(tn, port->tup_meta->tmp_label, &ret) != 0) {
		topo_mod_dprintf(mod, "failed to set label on device: %s",
		    topo_strerror(ret));
		goto error;
	}

	/*
	 * USB-properties
	 */
	if (topo_pgroup_create(tn, &topo_usb_props_pgroup, &ret) != 0) {
		topo_mod_dprintf(mod, "failed to create \"usb-properties\" "
		    "property group: %s", topo_strerror(ret));
		goto error;
	}

	if (topo_prop_set_uint32(tn, TOPO_PGROUP_USB_PROPS,
	    TOPO_PGROUP_USB_PROPS_PORT, TOPO_PROP_IMMUTABLE, lport->tul_portno,
	    &ret) != 0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s",
		    TOPO_PGROUP_USB_PROPS_PORT, topo_strerror(ret));
		goto error;
	}

	if (vendid != NULL && topo_prop_set_int32(tn, TOPO_PGROUP_USB_PROPS,
	    TOPO_PGROUP_USB_PROPS_VID, TOPO_PROP_IMMUTABLE, *vendid, &ret) !=
	    0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s",
		    TOPO_PGROUP_USB_PROPS_VID, topo_strerror(ret));
		goto error;
	}

	if (prodid != NULL && topo_prop_set_int32(tn, TOPO_PGROUP_USB_PROPS,
	    TOPO_PGROUP_USB_PROPS_PID, TOPO_PROP_IMMUTABLE, *prodid, &ret) !=
	    0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s",
		    TOPO_PGROUP_USB_PROPS_PID, topo_strerror(ret));
		goto error;
	}

	if (revid != NULL && topo_prop_set_string(tn, TOPO_PGROUP_USB_PROPS,
	    TOPO_PGROUP_USB_PROPS_REV, TOPO_PROP_IMMUTABLE, revbuf, &ret) !=
	    0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s",
		    TOPO_PGROUP_USB_PROPS_REV, topo_strerror(ret));
		goto error;
	}

	if (release != NULL && topo_prop_set_string(tn, TOPO_PGROUP_USB_PROPS,
	    TOPO_PGROUP_USB_PROPS_VERSION, TOPO_PROP_IMMUTABLE, relbuf, &ret) !=
	    0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s",
		    TOPO_PGROUP_USB_PROPS_VERSION, topo_strerror(ret));
		goto error;
	}

	if (vend != NULL && topo_prop_set_string(tn, TOPO_PGROUP_USB_PROPS,
	    TOPO_PGROUP_USB_PROPS_VNAME, TOPO_PROP_IMMUTABLE, vend, &ret) !=
	    0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s",
		    TOPO_PGROUP_USB_PROPS_VNAME, topo_strerror(ret));
		goto error;
	}

	if (prod != NULL && topo_prop_set_string(tn, TOPO_PGROUP_USB_PROPS,
	    TOPO_PGROUP_USB_PROPS_PNAME, TOPO_PROP_IMMUTABLE, prod, &ret) !=
	    0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s",
		    TOPO_PGROUP_USB_PROPS_PNAME, topo_strerror(ret));
		goto error;
	}

	if (serial != NULL && topo_prop_set_string(tn, TOPO_PGROUP_USB_PROPS,
	    TOPO_PGROUP_USB_PROPS_SN, TOPO_PROP_IMMUTABLE, serial, &ret) !=
	    0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s",
		    TOPO_PGROUP_USB_PROPS_SN, topo_strerror(ret));
		goto error;
	}

	if (speed != NULL && topo_prop_set_string(tn, TOPO_PGROUP_USB_PROPS,
	    TOPO_PGROUP_USB_PROPS_SPEED, TOPO_PROP_IMMUTABLE, speed, &ret) !=
	    0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s",
		    TOPO_PGROUP_USB_PROPS_SPEED, topo_strerror(ret));
		goto error;
	}

	if (min_speed != NULL && topo_prop_set_string(tn, TOPO_PGROUP_USB_PROPS,
	    TOPO_PGROUP_USB_PROPS_MIN_SPEED, TOPO_PROP_IMMUTABLE, min_speed,
	    &ret) != 0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s",
		    TOPO_PGROUP_USB_PROPS_MIN_SPEED, topo_strerror(ret));
		goto error;
	}

	if (sup_speeds != NULL) {
		const char **strings, *c;
		int i, rval;

		if ((strings = topo_mod_zalloc(mod, sizeof (char *) *
		    nsup_speeds)) == NULL) {
			topo_mod_dprintf(mod, "failed to allocate character "
			    "array for property %s",
			    TOPO_PGROUP_USB_PROPS_SUPPORTED_SPEEDS);
			goto error;
		}

		/*
		 * devinfo string properties are concatenated NUL-terminated
		 * strings. We need to translate that to a string array.
		 */
		for (c = sup_speeds, i = 0; i < nsup_speeds; i++) {
			size_t len;

			strings[i] = c;
			if (i + 1 < nsup_speeds) {
				len = strlen(c);
				c += len + 1;
			}
		}

		rval = topo_prop_set_string_array(tn, TOPO_PGROUP_USB_PROPS,
		    TOPO_PGROUP_USB_PROPS_SUPPORTED_SPEEDS, TOPO_PROP_IMMUTABLE,
		    strings, nsup_speeds, &ret);
		topo_mod_free(mod, strings, sizeof (char *) * nsup_speeds);
		if (rval != 0) {
			topo_mod_dprintf(mod, "failed to create property %s: "
			    "%s", TOPO_PGROUP_USB_PROPS_SUPPORTED_SPEEDS,
			    topo_strerror(ret));
		}
	}

	/*
	 * I/O pgroup
	 */
	if (topo_pgroup_create(tn, &topo_io_pgroup, &ret) != 0) {
		topo_mod_dprintf(mod, "failed to create \"io\" "
		    "property group: %s", topo_strerror(ret));
		goto error;
	}

	if (driver != NULL && topo_prop_set_string(tn, TOPO_PGROUP_IO,
	    TOPO_IO_DRIVER, TOPO_PROP_IMMUTABLE, driver, &ret) !=
	    0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s",
		    TOPO_IO_DRIVER, topo_strerror(ret));
		goto error;
	}

	if (inst != -1 && topo_prop_set_uint32(tn, TOPO_PGROUP_IO,
	    TOPO_IO_INSTANCE, TOPO_PROP_IMMUTABLE, inst, &ret) !=
	    0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s",
		    TOPO_IO_INSTANCE, topo_strerror(ret));
		goto error;
	}

	if (devfs != NULL && topo_prop_set_string(tn, TOPO_PGROUP_IO,
	    TOPO_IO_DEV_PATH, TOPO_PROP_IMMUTABLE, devfs, &ret) !=
	    0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s",
		    TOPO_IO_DEV_PATH, topo_strerror(ret));
		goto error;
	}

	if (driver != NULL && (modnvl = topo_mod_modfmri(mod,
	    FM_MOD_SCHEME_VERSION, driver)) != NULL &&
	    topo_prop_set_fmri(tn, TOPO_PGROUP_IO, TOPO_IO_MODULE,
	    TOPO_PROP_IMMUTABLE, modnvl, &ret) != 0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s",
		    TOPO_IO_MODULE, topo_strerror(ret));
		goto error;
	}

	/*
	 * Check the drivers to determine special behavior that we should do.
	 * The following are cases that we want to handle:
	 *
	 *   o Creating disk nodes for scsa2usb devices
	 *   o Creating children ports and searching them for hubd
	 */
	if (driver != NULL && strcmp(driver, "scsa2usb") == 0) {
		if ((ret = topo_usb_enum_scsa2usb(mod, tn, lport)) != 0)
			goto error;
	}

	if (lport->tul_nports > 0 && driver != NULL &&
	    strcmp(driver, "hubd") == 0) {
		if ((ret = topo_usb_enum_port_children(mod, tn, lport)) != 0)
			goto error;
	}

	di_devfs_path_free(devfs);
	nvlist_free(fmri);
	nvlist_free(auth);
	nvlist_free(modnvl);
	return (0);

error:
	topo_node_unbind(tn);
	di_devfs_path_free(devfs);
	nvlist_free(fmri);
	nvlist_free(auth);
	nvlist_free(modnvl);
	return (-1);
}

static int
topo_usb_enum_device(topo_mod_t *mod, tnode_t *pn, topo_usb_port_t *port)
{
	int ret;
	topo_instance_t i, max;
	topo_usb_lport_t *l;

	max = 0;
	for (l = topo_list_next(&port->tup_lports); l != NULL;
	    l = topo_list_next(l)) {
		if (l->tul_device != DI_NODE_NIL)
			max++;
	}

	if (max == 0) {
		return (0);
	}

	if ((ret = topo_node_range_create(mod, pn, USB_DEVICE, 0, max - 1)) !=
	    0) {
		return (-1);
	}

	for (i = 0, l = topo_list_next(&port->tup_lports); l != NULL;
	    l = topo_list_next(l)) {
		if (l->tul_device != DI_NODE_NIL) {
			topo_mod_dprintf(mod, "enumerating device on lport "
			    "%u, log inst %" PRIu64 "", l->tul_portno, i);
			if ((ret = topo_usb_enum_lport(mod, pn, port, l,
			    i)) != 0) {
				return (ret);
			}
			i++;
		}
	}

	return (0);
}

static int
topo_usb_enum_controller(topo_mod_t *mod, tnode_t *pnode,
    topo_usb_controller_t *c, topo_instance_t base)
{
	int ret;
	topo_usb_port_t *port;

	if (c->tuc_enumed)
		return (0);

	c->tuc_enumed = B_TRUE;
	if (c->tuc_nports == 0)
		return (0);

	for (port = topo_list_next(&c->tuc_ports); port != NULL;
	    port = topo_list_next(port)) {
		tnode_t *tn;
		if ((ret = port_create_usb(mod, pnode, base, &tn)) != 0)
			return (ret);

		if ((ret = topo_usb_port_properties(mod, tn, port)) != 0) {
			return (ret);
		}

		if ((ret = topo_usb_enum_device(mod, tn, port)) != 0)
			return (ret);

		base++;
	}

	return (0);
}

static int
topo_usb_enum_mobo(topo_mod_t *mod, tnode_t *pnode, topo_usb_t *usb)
{
	int ret;
	topo_usb_controller_t *c;
	topo_instance_t inst = 0;

	/*
	 * First count the number of ports, so we can create the right range.
	 * Then go back and actually create things. Some of the ports here may
	 * be actually on the chassis, that's OK, we don't mind over counting
	 * here.
	 */
	for (c = topo_list_next(&usb->tu_controllers); c != NULL;
	    c = topo_list_next(c)) {
		inst += c->tuc_nports;
	}

	if ((ret = port_range_create(mod, pnode, 0, inst)) != 0) {
		topo_mod_dprintf(mod, "failed to create port range [0, %"
		    PRIu64 ") for mobo", inst);
		return (ret);
	}

	inst = 0;
	for (c = topo_list_next(&usb->tu_controllers); c != NULL;
	    c = topo_list_next(c)) {
		if (c->tuc_enumed)
			continue;
		if ((ret = topo_usb_enum_controller(mod, pnode, c, inst)) !=
		    0) {
			return (ret);
		}
		inst += c->tuc_nports;
	}

	return (0);
}

static int
topo_usb_enum_pci(topo_mod_t *mod, tnode_t *pnode, topo_usb_t *usb,
    di_node_t din)
{
	int ret;
	topo_usb_controller_t *c;

	for (c = topo_list_next(&usb->tu_controllers); c != NULL;
	    c = topo_list_next(c)) {
		if (din == c->tuc_devinfo) {
			break;
		}
	}

	if (c == NULL) {
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
	}

	if ((ret = port_range_create(mod, pnode, 0, c->tuc_nports)) != 0) {
		topo_mod_dprintf(mod, "failed to create port range [0, %u) "
		    "for controller %s", c->tuc_nports, c->tuc_path);
		return (ret);
	}

	return (topo_usb_enum_controller(mod, pnode, c, 0));
}

static int
topo_usb_enum_chassis(topo_mod_t *mod, tnode_t *pnode, topo_usb_t *usb)
{
	int ret;
	topo_usb_port_t *p;
	topo_instance_t base = 0;

	if (usb->tu_nchassis_ports == 0)
		return (0);

	if ((ret = port_range_create(mod, pnode, 0, usb->tu_nchassis_ports)) !=
	    0) {
		topo_mod_dprintf(mod, "failed to create port range [0, %u) "
		    "for chassis", usb->tu_nchassis_ports);
		return (ret);
	}

	for (p = topo_list_next(&usb->tu_chassis_ports); p != NULL;
	    p = topo_list_next(p)) {
		tnode_t *tn;
		if ((ret = port_create_usb(mod, pnode, base, &tn)) != 0)
			return (ret);

		if ((ret = topo_usb_port_properties(mod, tn, p)) != 0) {
			return (ret);
		}

		if ((ret = topo_usb_enum_device(mod, tn, p)) != 0)
			return (ret);

		base++;
	}

	return (0);
}

/* ARGSUSED */
static int
topo_usb_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *modarg, void *data)
{
	topo_usb_t *usb;
	topo_usb_type_t type;

	if (strcmp(name, USB_PCI) == 0) {
		type = TOPO_USB_PCI;
	} else if (strcmp(name, USB_MOBO) == 0) {
		type = TOPO_USB_MOBO;
	} else if (strcmp(name, USB_CHASSIS) == 0) {
		type = TOPO_USB_CHASSIS;
	} else {
		topo_mod_dprintf(mod, "usb_enum: asked to enumerate unknown "
		    "component: %s\n", name);
		return (-1);
	}

	if (type == TOPO_USB_PCI && data == NULL) {
		topo_mod_dprintf(mod, "usb_enum: missing argument to "
		    "PCI controller enum");
		return (-1);
	} else if (type != TOPO_USB_PCI && data != NULL) {
		topo_mod_dprintf(mod, "extraneous argument to non-controller "
		    "enum %s", name);
		return (-1);
	}

	if ((usb = topo_mod_getspecific(mod)) == NULL) {
		return (-1);
	}

	if (!usb->tu_enum_done) {
		if (topo_usb_gather(mod, usb, pnode) != 0)
			return (-1);
		usb->tu_enum_done = B_TRUE;
	}

	/*
	 * Now that we've built up the topo nodes, enumerate the specific nodes
	 * based on the requested type.
	 */
	if (type == TOPO_USB_PCI) {
		return (topo_usb_enum_pci(mod, pnode, usb, data));
	} else if (type == TOPO_USB_MOBO) {
		return (topo_usb_enum_mobo(mod, pnode, usb));
	} else if (type == TOPO_USB_CHASSIS) {
		return (topo_usb_enum_chassis(mod, pnode, usb));
	}

	return (0);
}

static const topo_modops_t usb_ops = {
	topo_usb_enum, NULL
};

static topo_modinfo_t usb_mod = {
	USB, FM_FMRI_SCHEME_HC, USB_VERSION, &usb_ops
};

static void
topo_usb_port_free(topo_mod_t *mod, topo_usb_port_t *p)
{
	topo_usb_lport_t *lport;

	while ((lport = topo_list_next(&p->tup_lports)) != NULL) {
		topo_usb_port_t *child;

		topo_list_delete(&p->tup_lports, lport);
		while ((child = topo_list_next(&lport->tul_ports)) != NULL) {
			topo_list_delete(&lport->tul_ports, child);
			topo_usb_port_free(mod, child);
		}
		topo_mod_free(mod, lport, sizeof (topo_usb_lport_t));
	}

	topo_mod_free(mod, p, sizeof (topo_usb_port_t));
}

static void
topo_usb_free(topo_mod_t *mod, topo_usb_t *usb)
{
	topo_usb_controller_t *c;
	topo_usb_port_t *p;

	if (usb == NULL)
		return;

	while ((p = topo_list_next(&usb->tu_chassis_ports)) != NULL) {
		topo_list_delete(&usb->tu_chassis_ports, p);
		topo_usb_port_free(mod, p);
	}

	while ((c = topo_list_next(&usb->tu_controllers)) != NULL) {

		topo_list_delete(&usb->tu_controllers, c);
		di_devfs_path_free(c->tuc_path);

		while ((p = topo_list_next(&c->tuc_ports)) != NULL) {
			topo_list_delete(&c->tuc_ports, p);
			topo_usb_port_free(mod, p);
		}
		topo_mod_free(mod, c, sizeof (topo_usb_controller_t));
	}

	topo_usb_free_metadata(mod, &usb->tu_metadata);

	/*
	 * The devinfo handle came from fm, don't do anything ourselevs.
	 */
	usb->tu_devinfo = DI_NODE_NIL;

	topo_mod_free(mod, usb, sizeof (topo_usb_t));
}

static topo_usb_t *
topo_usb_alloc(topo_mod_t *mod)
{
	topo_usb_t *usb = NULL;

	if ((usb = topo_mod_zalloc(mod, sizeof (topo_usb_t))) == NULL) {
		goto free;
	}

	if ((usb->tu_devinfo = topo_mod_devinfo(mod)) == DI_NODE_NIL) {
		goto free;
	}

	return (usb);

free:
	topo_usb_free(mod, usb);
	return (NULL);
}

int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	topo_usb_t *usb;

	if (getenv("TOPOUSBDEBUG") != NULL)
		topo_mod_setdebug(mod);

	topo_mod_dprintf(mod, "_mod_init: initializing %s enumerator\n", USB);

	if (version != USB_VERSION) {
		return (-1);
	}

	if ((usb = topo_usb_alloc(mod)) == NULL) {
		return (-1);
	}

	if (topo_mod_register(mod, &usb_mod, TOPO_VERSION) != 0) {
		topo_usb_free(mod, usb);
		return (-1);
	}

	topo_mod_setspecific(mod, usb);

	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_usb_free(mod, topo_mod_getspecific(mod));
	topo_mod_setspecific(mod, NULL);
}
