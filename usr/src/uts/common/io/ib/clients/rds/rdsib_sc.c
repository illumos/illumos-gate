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

#include <sys/ib/clients/rds/rdsib_sc.h>
#include <sys/ib/clients/rds/rdsib_debug.h>
#include <sys/types.h>
#include <sys/sunddi.h>

/*
 * RDS Path MAP
 *
 * N - Node record, P - Path record
 *
 * rds_path_map -
 *              |
 *              v
 *      	---------	---------	---------
 *     		|   N   |------>|  N    |------>|   N   |------> NULL
 * NULL <-------|       |<------|       |<------|       |
 *     		---------       ---------       ---------
 *               |               |               |
 *               |               |               |
 *               v               v               v
 *		--------        ---------       ---------
 *		|  P   |        |  P    |       |  P    |
 *		--------        ---------       ---------
 *		|  ^            |   ^           |   ^
 *		|  |            |   |           |   |
 *		v  |            v   |           v   |
 *		--------	--------	---------
 *		|   P  |	|  P   |	|  P    |
 *		--------	--------	---------
 *		  o		   o		   o
 *		  o		   o		   o
 *		  o		   o		   o
 */

typedef struct rds_path_record_s {
	ipaddr_t			libd_ip;
	ipaddr_t			ribd_ip;
	struct rds_path_record_s	*up;
	struct rds_path_record_s	*downp;
	char				lifname[MAXNAMELEN];
	char				rifname[MAXNAMELEN];
} rds_path_record_t;

typedef struct rds_node_record_s {
	struct rds_node_record_s	*nextp;
	ipaddr_t			lnode_ip;	/* local ip */
	ipaddr_t			rnode_ip;	/* remote ip */
	struct rds_path_record_s	*downp;
	struct rds_node_record_s	*prevp;
} rds_node_record_t;

kmutex_t		rds_pathmap_lock;
rds_node_record_t	*rds_pathmap = NULL;

static boolean_t
rds_validate_interface(rds_path_t *path)
{
	char			devname[MAXNAMELEN];
	uint_t			instance;

	/* separate devname and instance number */
	if (ddi_parse(path->local.ifname, devname, &instance) != DDI_SUCCESS) {
		RDS_DPRINTF2("rds_validate_interface",
		    "local: %s is not right", path->local.ifname);
		return (B_FALSE);
	}

	/* don't care if it is not IPoIB interface */
	if (strcmp(devname, "ibd") != 0) {
		RDS_DPRINTF2("rds_validate_interface",
		    "local: %s is not IB interface", devname);
		return (B_FALSE);
	}

	/* separate devname and instance number */
	if (ddi_parse(path->remote.ifname, devname, &instance) != DDI_SUCCESS) {
		RDS_DPRINTF2("rds_validate_interface",
		    "remote: %s is not right", path->remote.ifname);
		return (B_FALSE);
	}

	/* don't care if it is not IPoIB interface */
	if (strcmp(devname, "ibd") != 0) {
		RDS_DPRINTF2("rds_validate_interface",
		    "remote: %s is not IB interface", devname);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Called by SC on discovering a new path
 */
void
rds_path_up(rds_path_t *path)
{
	rds_node_record_t	*p;
	rds_path_record_t	*p1;

	ASSERT(path != NULL);

	/* don't care if it is not IPoIB interface */
	if (rds_validate_interface(path) == B_FALSE) {
		RDS_DPRINTF2("rds_path_up", "NOT IB interface");
		return;
	}

	mutex_enter(&rds_pathmap_lock);

	p = rds_pathmap;
	while ((p) && ((p->lnode_ip != path->local.node_ipaddr) ||
	    (p->rnode_ip != path->remote.node_ipaddr))) {
		p = p->nextp;
	}

	if (p == NULL) {
		p = (rds_node_record_t *)kmem_alloc(sizeof (rds_node_record_t),
		    KM_SLEEP);
		p1 = (rds_path_record_t *)kmem_alloc(
		    sizeof (rds_path_record_t), KM_SLEEP);

		p->nextp = NULL;
		p->lnode_ip = path->local.node_ipaddr;
		p->rnode_ip = path->remote.node_ipaddr;
		p->downp = p1;
		p->prevp = NULL;

		p1->libd_ip = path->local.ipaddr;
		p1->ribd_ip = path->remote.ipaddr;
		p1->up = NULL;
		p1->downp = NULL;
		(void) strcpy(p1->lifname, path->local.ifname);
		(void) strcpy(p1->rifname, path->remote.ifname);

		if (rds_pathmap == NULL) {
			rds_pathmap = p;
		} else {
			/* insert this node at the head */
			rds_pathmap->prevp = p;
			p->nextp = rds_pathmap;
			rds_pathmap = p;
		}
	} else {
		/* we found a match */
		p1 = (rds_path_record_t *)kmem_alloc(
		    sizeof (rds_path_record_t), KM_SLEEP);

		p1->libd_ip = path->local.ipaddr;
		p1->ribd_ip = path->remote.ipaddr;
		p1->downp = p->downp;
		p->downp->up = p1;
		p1->up = NULL;
		p->downp = p1;
		(void) strcpy(p1->lifname, path->local.ifname);
		(void) strcpy(p1->rifname, path->remote.ifname);
	}

	mutex_exit(&rds_pathmap_lock);
}

/*
 * Called by SC to delete a path
 */
void
rds_path_down(rds_path_t *path)
{
	rds_node_record_t	*p;
	rds_path_record_t	*p1, *p1up, *p1downp;

	ASSERT(path != NULL);

	/* don't care if it is not IPoIB interface */
	if (rds_validate_interface(path) == B_FALSE) {
		RDS_DPRINTF2("rds_path_down", "NOT IB interface");
		return;
	}

	mutex_enter(&rds_pathmap_lock);

	p = rds_pathmap;
	while ((p) && ((p->lnode_ip != path->local.node_ipaddr) ||
	    (p->rnode_ip != path->remote.node_ipaddr))) {
		p = p->nextp;
	}

	if (p == NULL) {
		/* no match */
		RDS_DPRINTF2("rds_path_down", "Node record not found "
		    "(0x%x <-> 0x%x)", path->local.node_ipaddr,
		    path->remote.node_ipaddr);
		mutex_exit(&rds_pathmap_lock);
		return;
	}

	p1 = p->downp;
	while ((p1) && ((p1->libd_ip != path->local.ipaddr) ||
	    (p1->ribd_ip != path->remote.ipaddr))) {
		p1 = p1->downp;
	}

	if (p1 == NULL) {
		/* no match */
		RDS_DPRINTF2("rds_path_down", "Path record not found "
		    "(0x%x <-> 0x%x)", path->local.ipaddr, path->remote.ipaddr);
		mutex_exit(&rds_pathmap_lock);
		return;
	}

	/* we found the record, remove it */
	p1up = p1->up;
	p1downp = p1->downp;

	if (p1up) {
		p1up->downp = p1downp;
	} else {
		/* this is the first path record */
		p->downp = p1downp;
	}

	if (p1downp) {
		p1downp->up = p1up;
	}

	kmem_free(p1, sizeof (rds_path_record_t));

	/* remove the node record if there are no path records */
	if (p->downp == NULL) {
		if (p->prevp) {
			p->prevp->nextp = p->nextp;
		} else {
			/* this is the first node record */
			ASSERT(p == rds_pathmap);
			rds_pathmap = p->nextp;
		}

		if (p->nextp) {
			p->nextp->prevp = p->prevp;
		}

		kmem_free(p, sizeof (rds_node_record_t));
	}

	mutex_exit(&rds_pathmap_lock);
}

int
rds_sc_path_lookup(ipaddr_t *localip, ipaddr_t *remip)
{
	rds_node_record_t	*p;
	rds_path_record_t	*p1;

	mutex_enter(&rds_pathmap_lock);

	p = rds_pathmap;
	while ((p) && ((p->lnode_ip != *localip) || (p->rnode_ip != *remip))) {
		p = p->nextp;
	}

	if (p == NULL) {
		/* no match */
		RDS_DPRINTF2("rds_sc_path_lookup", "Node record not found "
		    "(0x%x <-> 0x%x)", *localip, *remip);
		mutex_exit(&rds_pathmap_lock);
		return (0);
	}

	/* found a path */
	p1 = p->downp;
	*localip = p1->libd_ip;
	*remip = p1->ribd_ip;

	mutex_exit(&rds_pathmap_lock);

	return (1);
}

boolean_t
rds_if_lookup_by_name(char *if_name)
{
	rds_node_record_t	*p;
	rds_path_record_t	*p1;
	char			devname[MAXNAMELEN];
	uint_t			instance;

	if (ddi_parse(if_name, devname, &instance) != DDI_SUCCESS) {
		RDS_DPRINTF2("rds_if_lookup_by_name",
		    "if_name: %s is not right", if_name);
		return (B_FALSE);
	}

	mutex_enter(&rds_pathmap_lock);

	if (rds_pathmap == NULL) {
		/* SC is not configured */
		RDS_DPRINTF2("rds_if_lookup_by_name", "Pathmap is NULL");
		mutex_exit(&rds_pathmap_lock);
		return (B_FALSE);
	}

	/*
	 * Sun Cluster always names its interconnect virtual network interface
	 * as clprivnetx, so  return TRUE if there is atleast one node record
	 * and the interface name is clprivnet something.
	 */
	if (strcmp(devname, "clprivnet") == 0) {
		/* clprivnet address */
		mutex_exit(&rds_pathmap_lock);
		return (B_TRUE);
	}

	p = rds_pathmap;

	while (p != NULL) {
		p1 = p->downp;
		while ((p1 != NULL) && strcmp(if_name, p1->lifname)) {
			p1 = p1->downp;
		}

		/* we found a match */
		if (p1 != NULL)
			break;
		/* go to the next node record */
		p = p->nextp;
	}

	mutex_exit(&rds_pathmap_lock);

	if (p == NULL) {
		/* no match */
		RDS_DPRINTF2("rds_if_lookup_by_name",
		    "Interface: %s not found", if_name);
		return (B_FALSE);
	}

	/* Found a matching node record */
	return (B_TRUE);
}

boolean_t
rds_if_lookup_by_addr(ipaddr_t addr)
{
	rds_node_record_t	*p;
	rds_path_record_t	*p1;

	mutex_enter(&rds_pathmap_lock);

	p = rds_pathmap;
	while ((p) && (p->lnode_ip != addr)) {
		p1 = p->downp;
		while ((p1) && (p1->libd_ip != addr)) {
			p1 = p1->downp;
		}

		/* we found a match */
		if (p1 != NULL)
			break;

		/* go to the next node record */
		p = p->nextp;
	}

	mutex_exit(&rds_pathmap_lock);
	if (p == NULL) {
		/* no match */
		RDS_DPRINTF2("rds_if_lookup_by_addr",
		    "Addr: 0x%x not found", addr);
		return (B_FALSE);
	}

	/* Found a matching node record */
	return (B_TRUE);
}
