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
 * Copyright 2020 Oxide Computer Company
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All rights reserved.	*/


#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/tuneable.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <sys/unistd.h>
#include <sys/debug.h>
#include <sys/bootconf.h>
#include <sys/socket.h>
#include <sys/policy.h>
#include <net/if.h>
#include <sys/sunddi.h>
#include <sys/promif.h>
#include <sys/zone.h>
#include <sys/model.h>
#include <netinet/inetutil.h>

static void get_netif_name(char *, char *);

long
systeminfo(int command, char *buf, long count)
{
	int error = 0;
	long strcnt, getcnt;
	char *kstr;
	char hostidp[HW_HOSTID_LEN];

	if (count < 0 && command != SI_SET_HOSTNAME &&
	    command != SI_SET_SRPC_DOMAIN)
		return (set_errno(EINVAL));

	/*
	 * Deal with the common "get a string" case first.
	 */
	switch (command) {
	case SI_SYSNAME:
		kstr = utsname.sysname;
		break;
	case SI_HOSTNAME:
		kstr = uts_nodename();
		break;
	case SI_RELEASE:
		kstr = utsname.release;
		break;
	case SI_VERSION:
		kstr = utsname.version;
		break;
	case SI_MACHINE:
		kstr = utsname.machine;
		break;
#ifdef _LP64
	case SI_ADDRESS_WIDTH:
		kstr = "64";
		break;
	case SI_ARCHITECTURE_64:
	case SI_ARCHITECTURE_K:
		kstr = architecture;
		break;
	case SI_ARCHITECTURE_32:
	case SI_ARCHITECTURE:
		kstr = architecture_32;
		break;
	case SI_ARCHITECTURE_NATIVE:
		kstr = get_udatamodel() == DATAMODEL_NATIVE ?
		    architecture : architecture_32;
		break;
#else
	case SI_ADDRESS_WIDTH:
		kstr = "32";
		break;
	case SI_ARCHITECTURE_K:
	case SI_ARCHITECTURE_32:
	case SI_ARCHITECTURE:
	case SI_ARCHITECTURE_NATIVE:
		kstr = architecture;
		break;
#endif
	case SI_HW_SERIAL:
		(void) snprintf(hostidp, sizeof (hostidp), "%u",
		    zone_get_hostid(curzone));
		kstr = hostidp;
		break;
	case SI_HW_PROVIDER:
		kstr = hw_provider;
		break;
	case SI_SRPC_DOMAIN:
		kstr = curproc->p_zone->zone_domain;
		break;
	case SI_PLATFORM:
		kstr = platform;
		break;
	case SI_ISALIST:
		kstr = isa_list;
		break;
	default:
		kstr = NULL;
		break;
	}

	if (kstr != NULL) {
		strcnt = strlen(kstr);
		if (count > 0) {
			if (count <= strcnt) {
				getcnt = count - 1;
				if (subyte(buf + getcnt, 0) < 0)
					return (set_errno(EFAULT));
			} else {
				getcnt = strcnt + 1;
			}
			if (copyout(kstr, buf, getcnt))
				return (set_errno(EFAULT));
		}
		return (strcnt + 1);
	}

	switch (command) {
	case SI_DHCP_CACHE:
	{
		char	*tmp;
		unsigned int tlen, octlen;

		if (dhcack == NULL) {
			tmp = "";
			strcnt = 0;
		} else {
			/*
			 * If the interface didn't have a name (bindable
			 * driver) to begin with, it might have one now.
			 * So, re-run strplumb_get_netdev_path() to see
			 * if one can be established at this time.
			 */
			if (netdev_path == NULL || netdev_path[0] == '\0') {
				netdev_path = strplumb_get_netdev_path();
			}
			/*
			 * If the interface name has not yet been resolved
			 * and a validnetdev_path[] was stashed by
			 * loadrootmodules in swapgeneric.c, or established
			 * above, resolve the interface name now.
			 */
			if (dhcifname[0] == '\0' &&
			    netdev_path != NULL && netdev_path[0] != '\0') {
				get_netif_name(netdev_path, dhcifname);
			}

			/*
			 * Form reply:
			 *  IFNAMESIZ array of dhcp i/f
			 *  hexascii representation of dhcp reply
			 */
			octlen = dhcacklen * 2 + 1;
			tlen = octlen + IFNAMSIZ;
			tmp = kmem_alloc(tlen, KM_SLEEP);
			(void) strncpy(tmp, dhcifname, IFNAMSIZ);
			if (octet_to_hexascii(dhcack, dhcacklen,
			    &tmp[IFNAMSIZ], &octlen) != 0) {
				kmem_free(tmp, tlen);
				error = EINVAL;
				break;
			} else {
				strcnt = IFNAMSIZ + octlen;
			}
		}

		if (count > 0) {
			if (count <= strcnt) {
				getcnt = count - 1;
				if (subyte((buf + getcnt), 0) < 0)
					goto fail;
			} else {
				getcnt = strcnt + 1;
			}
			if (copyout(tmp, buf, getcnt))
				goto fail;
		}
		if (strcnt != 0)
			kmem_free(tmp, tlen);
		return (strcnt + 1);
fail:
		if (strcnt != 0)
			kmem_free(tmp, tlen);
		error = EFAULT;
		break;
	}

	case SI_SET_HOSTNAME:
	{
		size_t		len;
		char		name[SYS_NMLN];
		char		*name_to_use;

		if ((error = secpolicy_systeminfo(CRED())) != 0)
			break;

		name_to_use = uts_nodename();
		if ((error = copyinstr(buf, name, SYS_NMLN, &len)) != 0)
			break;

		/*
		 * Must be non-NULL string and string
		 * must be less than SYS_NMLN chars.
		 */
		if (len < 2 || (len == SYS_NMLN && name[SYS_NMLN-1] != '\0')) {
			error = EINVAL;
			break;
		}

		/*
		 * Copy the name into the relevant zone's nodename.
		 */
		(void) strcpy(name_to_use, name);

		/*
		 * Notify other interested parties that the nodename was set
		 */
		if (name_to_use == utsname.nodename) /* global zone nodename */
			nodename_set();

		return (len);
	}

	case SI_SET_SRPC_DOMAIN:
	{
		char name[SYS_NMLN];
		size_t len;

		if ((error = secpolicy_systeminfo(CRED())) != 0)
			break;
		if ((error = copyinstr(buf, name, SYS_NMLN, &len)) != 0)
			break;
		/*
		 * If string passed in is longer than length
		 * allowed for domain name, fail.
		 */
		if (len == SYS_NMLN && name[SYS_NMLN-1] != '\0') {
			error = EINVAL;
			break;
		}

		(void) strcpy(curproc->p_zone->zone_domain, name);
		return (len);
	}

	default:
		error = EINVAL;
		break;
	}

	return (set_errno(error));
}

/*
 * i_path_find_node: Internal routine used by path_to_devinfo
 * to locate a given nodeid in the device tree.
 */
struct i_path_findnode {
	pnode_t nodeid;
	dev_info_t *dip;
};

static int
i_path_find_node(dev_info_t *dev, void *arg)
{
	struct i_path_findnode *f = (struct i_path_findnode *)arg;


	if (ddi_get_nodeid(dev) == (int)f->nodeid) {
		f->dip = dev;
		return (DDI_WALK_TERMINATE);
	}
	return (DDI_WALK_CONTINUE);
}

/*
 * Return the devinfo node to a boot device
 */
static dev_info_t *
path_to_devinfo(char *path)
{
	struct i_path_findnode fn;
	extern dev_info_t *top_devinfo;

	/*
	 * Get the nodeid of the given pathname, if such a mapping exists.
	 */
	fn.dip = NULL;
	fn.nodeid = prom_finddevice(path);
	if (fn.nodeid != OBP_BADNODE) {
		/*
		 * Find the nodeid in our copy of the device tree and return
		 * whatever name we used to bind this node to a driver.
		 */
		ddi_walk_devs(top_devinfo, i_path_find_node, (void *)(&fn));
	}

	return (fn.dip);
}

/*
 * Determine the network interface name from the device path argument.
 */
static void
get_netif_name(char *devname, char *ifname)
{
	dev_info_t	*dip;
	major_t		ndev;
	char		*name;
	int		unit;

	dip = path_to_devinfo(devname);
	if (dip == NULL) {
		cmn_err(CE_WARN, "get_netif_name: "
		    "can't bind driver for '%s'\n", devname);
		return;
	}

	ndev = ddi_driver_major(dip);
	if (ndev == -1) {
		cmn_err(CE_WARN, "get_netif_name: "
		    "no driver bound to '%s'\n", devname);
		return;
	}

	name = ddi_major_to_name(ndev);
	if (name == NULL) {
		cmn_err(CE_WARN, "get_netif_name: "
		    "no name for major number %d\n", ndev);
		return;
	}

	unit = i_ddi_devi_get_ppa(dip);
	if (unit < 0) {
		cmn_err(CE_WARN, "get_netif_name: "
		    "illegal unit number %d\n", unit);
		return;
	}

	(void) snprintf(ifname, IFNAMSIZ, "%s%d", name, unit);
}
