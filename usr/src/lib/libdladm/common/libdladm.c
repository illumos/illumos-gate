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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <stdlib.h>
#include <errno.h>
#include <libdevinfo.h>
#include <libdlpi.h>
#include <libdladm.h>
#include <sys/dld.h>
#include <net/if.h>

typedef struct dladm_dev {
	char			dd_name[IFNAMSIZ];
	struct dladm_dev	*dd_next;
} dladm_dev_t;

typedef struct dladm_walk {
	dladm_dev_t		*dw_dev_list;
} dladm_walk_t;

/*
 * Issue an ioctl to the specified file descriptor attached to the
 * DLD control driver interface.
 */
static int
i_dladm_ioctl(int fd, int ic_cmd, void *ic_dp, int ic_len)
{
	struct strioctl	iocb;

	iocb.ic_cmd = ic_cmd;
	iocb.ic_timout = 0;
	iocb.ic_len = ic_len;
	iocb.ic_dp = (char *)ic_dp;

	return (ioctl(fd, I_STR, &iocb));
}

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
	dap->da_port = dia.dia_port;
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
	dl_info_ack_t	dlia;
	char		name[IFNAMSIZ];
	int		fd;
	char		*provider;
	uint_t		ppa;

	provider = di_minor_name(minor);

	if ((fd = dlpi_open(provider)) < 0)
		return (DI_WALK_CONTINUE);

	if (dlpi_info(fd, -1, &dlia, NULL, NULL, NULL, NULL, NULL, NULL) < 0) {
		(void) dlpi_close(fd);
		return (DI_WALK_CONTINUE);
	}

	if (dlia.dl_provider_style == DL_STYLE1) {
		i_dladm_nt_net_add(arg, provider);
		(void) dlpi_close(fd);
		return (DI_WALK_CONTINUE);
	}

	ppa = di_instance(node);

	if (dlpi_attach(fd, -1, ppa) < 0) {
		(void) dlpi_close(fd);
		return (DI_WALK_CONTINUE);
	}
	(void) snprintf(name, IFNAMSIZ - 1, "%s%d", provider, ppa);
	i_dladm_nt_net_add(arg, name);
	(void) dlpi_close(fd);
	return (DI_WALK_CONTINUE);
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
		(void) dladm_walk_vlan(fn, arg, ddp->dd_name);
		last_ddp = ddp;
		ddp = ddp->dd_next;
		free(last_ddp);
	}

	return (0);
}

/*
 * Invoke the specified callback function for each vlan managed by dld
 */
int
dladm_walk_vlan(void (*fn)(void *, const char *), void *arg, const char *name)
{
	int		fd, bufsize, i;
	int		nvlan = 4094;
	dld_ioc_vlan_t	*iocp = NULL;
	dld_vlan_info_t	*dvip;

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
		return (-1);

	bufsize = sizeof (dld_ioc_vlan_t) + nvlan * sizeof (dld_vlan_info_t);

	if ((iocp = (dld_ioc_vlan_t *)calloc(1, bufsize)) == NULL)
		return (-1);

	if (strncmp(name, "aggr", 4) == 0) {
		(void) strlcpy((char *)iocp->div_name, "aggr0", IFNAMSIZ);
		iocp->div_port = atoi(strpbrk(name, "0123456789"));
	} else {
		(void) strlcpy((char *)iocp->div_name, name, IFNAMSIZ);
		iocp->div_port = 0;
	}
	if (i_dladm_ioctl(fd, DLDIOCVLAN, iocp, bufsize) == 0) {
		dvip = (dld_vlan_info_t *)(iocp + 1);
		for (i = 0; i < iocp->div_count; i++)
			(*fn)(arg, dvip[i].dvi_name);
	}
	/*
	 * Note: Callers of dladm_walk_vlan() ignore the return
	 * value of this routine. So ignoring ioctl failure case
	 * and just returning 0.
	 */
	free(iocp);
	(void) close(fd);
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
