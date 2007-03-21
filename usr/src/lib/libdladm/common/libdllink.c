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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/dld.h>
#include <libdlpi.h>
#include <libdevinfo.h>
#include <libdllink.h>
#include <libdladm_impl.h>

typedef struct dladm_dev {
	char			dd_name[IFNAMSIZ];
	struct dladm_dev	*dd_next;
} dladm_dev_t;

typedef struct dladm_walk {
	dladm_dev_t		*dw_dev_list;
} dladm_walk_t;

/*
 * Return the attributes of the specified datalink from the DLD driver.
 */
static int
i_dladm_info(int fd, const char *name, dladm_attr_t *dap)
{
	dld_ioc_attr_t	dia;

	if (strlen(name) >= IFNAMSIZ) {
		errno = EINVAL;
		return (-1);
	}

	(void) strlcpy(dia.dia_name, name, IFNAMSIZ);

	if (i_dladm_ioctl(fd, DLDIOCATTR, &dia, sizeof (dia)) < 0)
		return (-1);

	(void) strlcpy(dap->da_dev, dia.dia_dev, MAXNAMELEN);
	dap->da_max_sdu = dia.dia_max_sdu;
	dap->da_vid = dia.dia_vid;

	return (0);
}

/*
 * Adds a datalink to the array corresponding to arg.
 */
static void
i_dladm_nt_net_add(void *arg, char *name)
{
	dladm_walk_t	*dwp = arg;
	dladm_dev_t	*ddp = dwp->dw_dev_list;
	dladm_dev_t	**lastp = &dwp->dw_dev_list;

	while (ddp) {
		/*
		 * Skip duplicates.
		 */
		if (strcmp(ddp->dd_name, name) == 0)
			return;

		lastp = &ddp->dd_next;
		ddp = ddp->dd_next;
	}

	if ((ddp = malloc(sizeof (*ddp))) == NULL)
		return;

	(void) strlcpy(ddp->dd_name, name, IFNAMSIZ);
	ddp->dd_next = NULL;
	*lastp = ddp;
}

/*
 * Walker callback invoked for each DDI_NT_NET node.
 */
static int
i_dladm_nt_net_walk(di_node_t node, di_minor_t minor, void *arg)
{
	char		linkname[DLPI_LINKNAME_MAX];
	dlpi_handle_t	dh;

	if (dlpi_makelink(linkname, di_minor_name(minor),
	    di_instance(node)) != DLPI_SUCCESS)
		return (DI_WALK_CONTINUE);

	if (dlpi_open(linkname, &dh, 0) == DLPI_SUCCESS) {
		i_dladm_nt_net_add(arg, linkname);
		dlpi_close(dh);
	}
	return (DI_WALK_CONTINUE);
}

/*
 * Hold a data-link.
 */
static int
i_dladm_hold_link(const char *name, zoneid_t zoneid, boolean_t docheck)
{
	int		fd;
	dld_hold_vlan_t	dhv;

	if (strlen(name) >= IFNAMSIZ) {
		errno = EINVAL;
		return (-1);
	}

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
		return (-1);

	bzero(&dhv, sizeof (dld_hold_vlan_t));
	(void) strlcpy(dhv.dhv_name, name, IFNAMSIZ);
	dhv.dhv_zid = zoneid;
	dhv.dhv_docheck = docheck;

	if (i_dladm_ioctl(fd, DLDIOCHOLDVLAN, &dhv, sizeof (dhv)) < 0) {
		int olderrno = errno;

		(void) close(fd);
		errno = olderrno;
		return (-1);
	}

	(void) close(fd);
	return (0);
}

/*
 * Release a data-link.
 */
static int
i_dladm_rele_link(const char *name, zoneid_t zoneid, boolean_t docheck)
{
	int		fd;
	dld_hold_vlan_t	dhv;

	if (strlen(name) >= IFNAMSIZ) {
		errno = EINVAL;
		return (-1);
	}

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
		return (-1);

	bzero(&dhv, sizeof (dld_hold_vlan_t));
	(void) strlcpy(dhv.dhv_name, name, IFNAMSIZ);
	dhv.dhv_zid = zoneid;
	dhv.dhv_docheck = docheck;

	if (i_dladm_ioctl(fd, DLDIOCRELEVLAN, &dhv, sizeof (dhv)) < 0) {
		int olderrno = errno;

		(void) close(fd);
		errno = olderrno;
		return (-1);
	}

	(void) close(fd);
	return (0);
}

/*
 * Invoke the specified callback function for each active DDI_NT_NET
 * node.
 */
int
dladm_walk(void (*fn)(void *, const char *), void *arg)
{
	di_node_t	root;
	dladm_walk_t	dw;
	dladm_dev_t	*ddp, *last_ddp;

	if ((root = di_init("/", DINFOCACHE)) == DI_NODE_NIL) {
		errno = EFAULT;
		return (-1);
	}
	dw.dw_dev_list = NULL;

	(void) di_walk_minor(root, DDI_NT_NET, DI_CHECK_ALIAS, &dw,
	    i_dladm_nt_net_walk);

	di_fini(root);

	ddp = dw.dw_dev_list;
	while (ddp) {
		fn(arg, ddp->dd_name);
		last_ddp = ddp;
		ddp = ddp->dd_next;
		free(last_ddp);
	}

	return (0);
}

/*
 * MAC Administration Library.
 *
 * This library is used by administration tools such as dladm(1M) to
 * iterate through the list of MAC interfaces
 *
 */

typedef struct dladm_mac_dev {
	char			dm_name[MAXNAMELEN];
	struct dladm_mac_dev	*dm_next;
} dladm_mac_dev_t;

typedef struct macadm_walk {
	dladm_mac_dev_t		*dmd_dev_list;
} dladm_mac_walk_t;

/*
 * Local callback invoked for each DDI_NT_NET node.
 */
/* ARGSUSED */
static int
i_dladm_mac_walk(di_node_t node, di_minor_t minor, void *arg)
{
	dladm_mac_walk_t	*dmwp = arg;
	dladm_mac_dev_t		*dmdp = dmwp->dmd_dev_list;
	dladm_mac_dev_t		**last_dmdp = &dmwp->dmd_dev_list;
	char			mac[MAXNAMELEN];

	(void) snprintf(mac, MAXNAMELEN, "%s%d",
	    di_driver_name(node), di_instance(node));

	/*
	 * Skip aggregations.
	 */
	if (strcmp("aggr", di_driver_name(node)) == 0)
		return (DI_WALK_CONTINUE);

	while (dmdp) {
		/*
		 * Skip duplicates.
		 */
		if (strcmp(dmdp->dm_name, mac) == 0)
			return (DI_WALK_CONTINUE);

		last_dmdp = &dmdp->dm_next;
		dmdp = dmdp->dm_next;
	}

	if ((dmdp = malloc(sizeof (*dmdp))) == NULL)
		return (DI_WALK_CONTINUE);

	(void) strlcpy(dmdp->dm_name, mac, MAXNAMELEN);
	dmdp->dm_next = NULL;
	*last_dmdp = dmdp;

	return (DI_WALK_CONTINUE);
}

/*
 * Invoke the specified callback for each DDI_NT_MAC node.
 */
int
dladm_mac_walk(void (*fn)(void *, const char *), void *arg)
{
	di_node_t		root;
	dladm_mac_walk_t	dmw;
	dladm_mac_dev_t		*dmdp, *next;

	if ((root = di_init("/", DINFOCACHE)) == DI_NODE_NIL)
		return (-1);

	dmw.dmd_dev_list = NULL;

	(void) di_walk_minor(root, DDI_NT_NET, DI_CHECK_ALIAS, &dmw,
	    i_dladm_mac_walk);

	di_fini(root);

	dmdp = dmw.dmd_dev_list;
	for (dmdp = dmw.dmd_dev_list; dmdp != NULL; dmdp = next) {
		next = dmdp->dm_next;
		(*fn)(arg, dmdp->dm_name);
		free(dmdp);
	}

	return (0);
}

/*
 * Returns the current attributes of the specified datalink.
 */
int
dladm_info(const char *name, dladm_attr_t *dap)
{
	int		fd;

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
		return (-1);

	if (i_dladm_info(fd, name, dap) < 0)
		goto failed;

	(void) close(fd);
	return (0);

failed:
	(void) close(fd);
	return (-1);
}

const char *
dladm_linkstate2str(link_state_t state, char *buf)
{
	const char	*s;

	switch (state) {
	case LINK_STATE_UP:
		s = "up";
		break;
	case LINK_STATE_DOWN:
		s = "down";
		break;
	default:
		s = "unknown";
		break;
	}
	(void) snprintf(buf, DLADM_STRSIZE, "%s", s);
	return (buf);
}

const char *
dladm_linkduplex2str(link_duplex_t duplex, char *buf)
{
	const char	*s;

	switch (duplex) {
	case LINK_DUPLEX_FULL:
		s = "full";
		break;
	case LINK_DUPLEX_HALF:
		s = "half";
		break;
	default:
		s = "unknown";
		break;
	}
	(void) snprintf(buf, DLADM_STRSIZE, "%s", s);
	return (buf);
}

/*
 * Do a "hold" operation to a link.
 */
int
dladm_hold_link(const char *name, zoneid_t zoneid, boolean_t docheck)
{
	return (i_dladm_hold_link(name, zoneid, docheck));
}

/*
 * Do a "release" operation to a link.
 */
int
dladm_rele_link(const char *name, zoneid_t zoneid, boolean_t docheck)
{
	return (i_dladm_rele_link(name, zoneid, docheck));
}
