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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdlib.h>
#include <dhcp_impl.h>
#include <netinet/inetutil.h>
#include <sys/systeminfo.h>
#include <netinet/in.h>
#include <strings.h>
#include <net/if.h>
#include <libdevinfo.h>
#include <sys/isa_defs.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <alloca.h>
#include <stdio.h>
#include <sys/sockio.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <bootinfo.h>
#include <bootinfo_aux.h>

#define	MAXIFS	256	/* default max number of interfaces */

/*
 * Callback structure used when walking the device tree.
 */
typedef struct {
	char		*cb_path;	/* device path we want to match */
	di_node_t	cb_node;	/* found leaf node of device path */
} cb_t;

/*
 * Handles on devinfo stuff.
 */
static di_node_t	root_node = DI_NODE_NIL;
static di_prom_handle_t	phdl = DI_PROM_HANDLE_NIL;

/*
 * Root filesystem type string.
 */
static char *rootfs_type = NULL;

/*
 * Handles on DHCP's packet list and interface-name.
 */
static PKT_LIST	*dhcp_pl = NULL;
static char	dhcp_ifn[IFNAMSIZ + 1];

/*
 * Deallocate dhcp_pl.
 */
static void
dhcp_info_end(void)
{
	if (dhcp_pl != NULL) {
		free(dhcp_pl->pkt);
		free(dhcp_pl);
	}
	dhcp_pl = NULL;
	dhcp_ifn[0] = '\0';
}

/*
 * Determine whether the kernel has a cached DHCP ACK, and if so
 * initialize dhcp_pl and dhcp_ifn.
 */
static boolean_t
dhcp_info_init(void)
{
	boolean_t	ret = B_FALSE;
	char		dummy;
	char		*dhcack = NULL;
	long		dhcacksz;
	char		*ackp;

	/*
	 * See whether the kernel has a cached DHCP ACK, and if so get it.
	 * If there is no DHCP ACK, then the returned length is equal to
	 * the size of an empty string.
	 */
	if ((dhcacksz = sysinfo(SI_DHCP_CACHE, &dummy,
	    sizeof (dummy))) == sizeof ("")) {
		return (B_TRUE);
	}
	if ((dhcack = malloc(dhcacksz)) == NULL) {
		goto cleanup;
	}
	if ((dhcp_pl = calloc(1, sizeof (PKT_LIST))) == NULL) {
		goto cleanup;
	}
	(void) sysinfo(SI_DHCP_CACHE, (caddr_t)dhcack, dhcacksz);

	/*
	 * The first IFNAMSIZ bytes are reserved for the interface name;
	 * the ACK follows.
	 */
	ackp = &dhcack[IFNAMSIZ];

	/*
	 * Convert and scan the options.
	 */
	dhcp_pl->len = strlen(ackp) / 2;
	if ((dhcp_pl->pkt = malloc(dhcp_pl->len)) == NULL) {
		goto cleanup;
	}
	if (hexascii_to_octet(ackp, dhcp_pl->len * 2,
	    dhcp_pl->pkt, &dhcp_pl->len) != 0) {
		goto cleanup;
	}
	if (dhcp_options_scan(dhcp_pl, B_TRUE) != 0) {
		goto cleanup;
	}

	/*
	 * Set the interface-name.
	 */
	(void) strlcpy(dhcp_ifn, dhcack, sizeof (dhcp_ifn));

	ret = B_TRUE;
cleanup:
	if (!ret) {
		dhcp_info_end();
	}
	if (dhcack != NULL) {
		free(dhcack);
	}

	return (ret);
}

/*
 * Deallocate devinfo stuff.
 */
static void
destroy_snapshot(void)
{
	if (phdl != DI_PROM_HANDLE_NIL) {
		di_prom_fini(phdl);
	}
	phdl = DI_PROM_HANDLE_NIL;

	if (root_node != DI_NODE_NIL) {
		di_fini(root_node);
	}
	root_node = DI_NODE_NIL;
}

/*
 * Take a snapshot of the device tree, i.e. get a devinfo handle and
 * a PROM handle.
 */
static boolean_t
snapshot_devtree(void)
{
	/*
	 * Deallocate any existing devinfo stuff first.
	 */
	destroy_snapshot();

	if ((root_node = di_init("/", DINFOCPYALL)) == DI_NODE_NIL ||
	    (phdl = di_prom_init()) == DI_PROM_HANDLE_NIL) {
		destroy_snapshot();
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Get the value of the named property on the named node in root.
 */
static char *
get_prop(const char *nodename, const char *propname, size_t *lenp)
{
	di_node_t		node;
	di_prom_prop_t		pp;
	char			*val = NULL;
	int			len;

	/*
	 * Locate nodename within '/'.
	 */
	for (node = di_child_node(root_node);
	    node != DI_NODE_NIL;
	    node = di_sibling_node(node)) {
		if (strcmp(di_node_name(node), nodename) == 0) {
			break;
		}
	}
	if (node == DI_NODE_NIL) {
		return (NULL);
	}

	/*
	 * Scan all properties of /nodename for the 'propname' property.
	 */
	for (pp = di_prom_prop_next(phdl, node, DI_PROM_PROP_NIL);
	    pp != DI_PROM_PROP_NIL;
	    pp = di_prom_prop_next(phdl, node, pp)) {
		if (strcmp(propname, di_prom_prop_name(pp)) == 0) {
			break;
		}
	}
	if (pp == DI_PROM_PROP_NIL) {
		return (NULL);
	}

	/*
	 * Found the property; copy out its length and return its value.
	 */
	len = di_prom_prop_data(pp, (uchar_t **)&val);
	if (lenp != NULL) {
		*lenp = len;
	}
	return (val);
}

/*
 * Strip any trailing arguments from a device path.
 * Returned memory must be freed by caller.
 */
static char *
strip_args(char *path, size_t len)
{
	char	*stripped_path = NULL;

	if (path != NULL && len != 0 &&
	    (stripped_path = calloc(len + 1, sizeof (char))) != NULL) {
		char	*p;

		(void) memcpy(stripped_path, path, len);
		if ((p = strchr(stripped_path, ':')) != NULL) {
			*p = '\0';
		}
	}
	return (stripped_path);
}

/*
 * Return the "bootpath" property (sans arguments) from /chosen.
 * Returned memory must be freed by caller.
 */
static char *
get_bootpath(void)
{
	char	*path;
	size_t	len;

	path = get_prop("chosen", "bootpath", &len);
	return (strip_args(path, len));
}

/*
 * Return the "net" property (sans arguments) from /aliases.
 * Returned memory must be freed by caller.
 */
static char *
get_netalias(void)
{
	char	*path;
	size_t	len;

	path = get_prop("aliases", "net", &len);
	return (strip_args(path, len));
}

/*
 * Callback used by path2node().
 */
static int
p2n_cb(di_node_t node, void *arg)
{
	int	ret = DI_WALK_CONTINUE;
	cb_t	*cbp = arg;
	char	*phys_path = di_devfs_path(node);

	if (strcmp(cbp->cb_path, phys_path) == 0) {
		cbp->cb_node = node;
		ret = DI_WALK_TERMINATE;
	}
	di_devfs_path_free(phys_path);

	return (ret);
}

/*
 * Map a device path to its matching di_node_t.
 */
static di_node_t
path2node(char *path)
{
	cb_t	cb;

	cb.cb_path = path;
	cb.cb_node = DI_NODE_NIL;

	(void) di_walk_node(root_node, DI_WALK_CLDFIRST, &cb, p2n_cb);

	return (cb.cb_node);
}

/*
 * Check whether node corresponds to a network device.
 */
static boolean_t
is_network_device(di_node_t node)
{
	char		*type;

	return (di_prom_prop_lookup_strings(phdl, node,
	    "device_type", &type) > 0 && strcmp(type, "network") == 0);
}

/*
 * Initialise bootmisc with the rootfs-type.
 */
static boolean_t
rootfs_type_init(void)
{
	static struct statvfs	vfs;

	if (statvfs("/", &vfs) >= 0) {
		if (strncmp(vfs.f_basetype, "nfs", sizeof ("nfs") - 1) == 0) {
			vfs.f_basetype[sizeof ("nfs") - 1] = '\0';
		}
		rootfs_type = vfs.f_basetype;
	}

	return (rootfs_type != NULL && bi_put_bootmisc(BI_ROOTFS_TYPE,
	    rootfs_type, strlen(rootfs_type) + 1));
}

/*
 * Initialise bootmisc with the interface-name of the primary network device,
 * and the net-config-strategy employed in configuring that device.
 */
static boolean_t
netif_init(char *ifn, char *ncs)
{
	return (bi_put_bootmisc(BI_INTERFACE_NAME, ifn, strlen(ifn) + 1) &&
	    bi_put_bootmisc(BI_NET_CONFIG_STRATEGY, ncs, strlen(ncs) + 1));
}

/*
 * Determine whether the interface was configured manually.
 */
static boolean_t
manual_if_init(void)
{
	boolean_t	ret = B_FALSE;
	char		*ncs;
	char		*devpath;
	di_node_t	node;
	int		instance;
	char		*drvname;
	char		ifname[IFNAMSIZ + 1];

	/*
	 * If net-config-strategy isn't "manual", don't go any further.
	 */
	if ((ncs = get_prop("chosen", BI_NET_CONFIG_STRATEGY, NULL)) == NULL ||
	    strcmp(ncs, "manual") != 0) {
		return (B_FALSE);
	}

	/*
	 * First check the 'bootpath' property of /chosen to see whether
	 * it specifies the path of a network device; if so, use this.
	 */
	if ((devpath = get_bootpath()) == NULL ||
	    (node = path2node(devpath)) == DI_NODE_NIL ||
	    !is_network_device(node)) {
		/*
		 * Must have been booted from CD-ROM or disk; attempt to
		 * use the path defined by the 'net' property of /aliases.
		 */
		free(devpath);
		if ((devpath = get_netalias()) == NULL ||
		    (node = path2node(devpath)) == DI_NODE_NIL ||
		    !is_network_device(node)) {
			goto cleanup;
		}
	}

	/*
	 * Get the driver name and instance number of this node.
	 * We may have to load the driver.
	 */
	if ((drvname = di_driver_name(node)) == NULL) {
		goto cleanup;
	}
	if ((instance = di_instance(node)) == -1) {
		di_node_t	tmp;

		/*
		 * Attempt to load the driver, create a new snapshot of the
		 * (possibly changed) device tree and re-compute our node.
		 */
		if ((tmp = di_init_driver(drvname, 0)) != DI_NODE_NIL) {
			di_fini(tmp);

			if (!snapshot_devtree() ||
			    (node = path2node(devpath)) == DI_NODE_NIL) {
				goto cleanup;
			}
		}
		instance = di_instance(node);
	}

	/*
	 * Construct the interface name.
	 */
	if (instance == -1) {
		(void) snprintf(ifname, sizeof (ifname),
		    "%s", di_driver_name(node));
	} else {
		(void) snprintf(ifname, sizeof (ifname),
		    "%s%d", di_driver_name(node), instance);
	}

	ret = netif_init(ifname, "manual");
cleanup:
	free(devpath);
	return (ret);
}

/*
 * Determine whether the interface was configured via DHCP.
 */
static boolean_t
dhcp_if_init(void)
{
	return (strlen(dhcp_ifn) != 0 && netif_init(dhcp_ifn, "dhcp"));
}

static boolean_t
bootmisc_init(void)
{
	return (rootfs_type_init() &&
	    (manual_if_init() || dhcp_if_init()));
}


/*
 * Functions dealing with bootinfo initialization/cleanup.
 */
boolean_t
bi_init_bootinfo(void)
{
	if (snapshot_devtree() && dhcp_info_init() && bootmisc_init()) {
		return (B_TRUE);
	}
	bi_end_bootinfo();
	return (B_FALSE);
}

void
bi_end_bootinfo(void)
{
	destroy_snapshot();
	dhcp_info_end();
}

/*
 * Function dealing with /chosen data.
 */
boolean_t
bi_get_chosen_prop(const char *name, void *valbuf, size_t *vallenp)
{
	char		*val;
	size_t		buflen = *vallenp;

	if ((val = get_prop("chosen", name, vallenp)) == NULL) {
		return (B_FALSE);
	}
	if (*vallenp <= buflen) {
		(void) memcpy(valbuf, val, *vallenp);
	}

	return (B_TRUE);
}

/*
 * Function dealing with DHCP data.
 */
boolean_t
bi_get_dhcp_info(uchar_t optcat, uint16_t optcode, uint16_t optsize,
    void *valbuf, size_t *vallenp)
{
	return (dhcp_getinfo_pl(dhcp_pl,
	    optcat, optcode, optsize, valbuf, vallenp));
}
