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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */
#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/dlpi.h>
#include <sys/ib/clients/rdsv3/rdsv3_sc.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

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

static char			sc_device_name[MAXNAMELEN] = "NotInitialized";
static kmutex_t			rdsv3_pathmap_lock;
static rds_node_record_t	*rdsv3_pathmap = NULL;

#define	RDS_VALIDATE_PATH(p)						\
	if ((p->local.iftype != DL_IB) || (p->remote.iftype != DL_IB))	\
		return

#define	isalpha(ch)	(((ch) >= 'a' && (ch) <= 'z') || \
			((ch) >= 'A' && (ch) <= 'Z'))

/*
 * Called by SC to register the Sun Cluster device name
 */
void
rdsv3_clif_name(char *name)
{
	int	i;

	ASSERT(name != NULL);

	mutex_enter(&rdsv3_pathmap_lock);

	/* extract the device name from the interface name */
	i = strlen(name) - 1;
	while ((i >= 0) && (!isalpha(name[i]))) i--;
	if (i >= 0) {
		(void) strncpy(sc_device_name, name, i + 1);
		sc_device_name[i + 1] = '\0';
	}

	mutex_exit(&rdsv3_pathmap_lock);
}

/*
 * Called by SC on discovering a new path
 */
void
rdsv3_path_up(rds_path_t *path)
{
	rds_node_record_t	*p;
	rds_path_record_t	*p1;

	ASSERT(path != NULL);

	/* ignore if the end points are not of type DL_IB */
	RDS_VALIDATE_PATH(path);

	mutex_enter(&rdsv3_pathmap_lock);

	p = rdsv3_pathmap;
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

		if (rdsv3_pathmap == NULL) {
			rdsv3_pathmap = p;
		} else {
			/* insert this node at the head */
			rdsv3_pathmap->prevp = p;
			p->nextp = rdsv3_pathmap;
			rdsv3_pathmap = p;
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

	mutex_exit(&rdsv3_pathmap_lock);
}

/*
 * Called by SC to delete a path
 */
void
rdsv3_path_down(rds_path_t *path)
{
	rds_node_record_t	*p;
	rds_path_record_t	*p1, *p1up, *p1downp;

	ASSERT(path != NULL);

	/* ignore if the end points are not of type DL_IB */
	RDS_VALIDATE_PATH(path);

	mutex_enter(&rdsv3_pathmap_lock);

	p = rdsv3_pathmap;
	while ((p) && ((p->lnode_ip != path->local.node_ipaddr) ||
	    (p->rnode_ip != path->remote.node_ipaddr))) {
		p = p->nextp;
	}

	if (p == NULL) {
		/* no match */
		RDSV3_DPRINTF2("rdsv3_path_down", "Node record not found "
		    "(0x%x <-> 0x%x)", path->local.node_ipaddr,
		    path->remote.node_ipaddr);
		mutex_exit(&rdsv3_pathmap_lock);
		return;
	}

	p1 = p->downp;
	while ((p1) && ((p1->libd_ip != path->local.ipaddr) ||
	    (p1->ribd_ip != path->remote.ipaddr))) {
		p1 = p1->downp;
	}

	if (p1 == NULL) {
		/* no match */
		RDSV3_DPRINTF2("rdsv3_path_down", "Path record not found "
		    "(0x%x <-> 0x%x)", path->local.ipaddr, path->remote.ipaddr);
		mutex_exit(&rdsv3_pathmap_lock);
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
			ASSERT(p == rdsv3_pathmap);
			rdsv3_pathmap = p->nextp;
		}

		if (p->nextp) {
			p->nextp->prevp = p->prevp;
		}

		kmem_free(p, sizeof (rds_node_record_t));
	}

	mutex_exit(&rdsv3_pathmap_lock);
}

int
rdsv3_sc_path_lookup(ipaddr_t *localip, ipaddr_t *remip)
{
	rds_node_record_t	*p;
	rds_path_record_t	*p1, *p1downp;

	mutex_enter(&rdsv3_pathmap_lock);

	p = rdsv3_pathmap;
	while ((p) && ((p->lnode_ip != *localip) || (p->rnode_ip != *remip))) {
		p = p->nextp;
	}

	if (p == NULL) {
		/* no match */
		RDSV3_DPRINTF2("rdsv3_sc_path_lookup", "Node record not found "
		    "(0x%x <-> 0x%x)", *localip, *remip);
		mutex_exit(&rdsv3_pathmap_lock);
		return (0);
	}

	/* found a path */
	p1 = p->downp;
	*localip = p1->libd_ip;
	*remip = p1->ribd_ip;

	/*
	 * But next time, we want to use a different path record so move this
	 * path record to the end.
	 */
	p1downp = p1->downp;
	if (p1downp != NULL) {
		p->downp = p1downp;
		p1downp->up = NULL;

		/* walk down to the last path record */
		while (p1downp->downp != NULL) {
			p1downp = p1downp->downp;
		}

		/* Attach the first path record to the end */
		p1downp->downp = p1;
		p1->up = p1downp;
		p1->downp = NULL;
	}

	mutex_exit(&rdsv3_pathmap_lock);

	return (1);
}

boolean_t
rdsv3_if_lookup_by_name(char *devname)
{
	mutex_enter(&rdsv3_pathmap_lock);

	/*
	 * Sun Cluster always names its interconnect virtual network interface
	 * as clprivnetx, so  return TRUE if there is atleast one node record
	 * and the interface name is clprivnet something.
	 */
	if (strcmp(devname, sc_device_name) == 0) {
		/* clprivnet address */
		mutex_exit(&rdsv3_pathmap_lock);
		return (B_TRUE);
	}

	mutex_exit(&rdsv3_pathmap_lock);
	return (B_FALSE);
}

boolean_t
rdsv3_if_lookup_by_addr(ipaddr_t addr)
{
	rds_node_record_t	*p;
	rds_path_record_t	*p1;

	mutex_enter(&rdsv3_pathmap_lock);

	p = rdsv3_pathmap;
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

	mutex_exit(&rdsv3_pathmap_lock);
	if (p == NULL) {
		/* no match */
		RDSV3_DPRINTF2("rds_if_lookup_by_addr",
		    "Addr: 0x%x not found", addr);
		return (B_FALSE);
	}

	/* Found a matching node record */
	return (B_TRUE);
}

/*
 * If SC is configured then addr would be a clprivnet address. Find the
 * node record and return the first IB address. If the node record is not
 * found, then return addr as-is.
 */
ipaddr_t
rdsv3_scaddr_to_ibaddr(ipaddr_t addr)
{
	rds_node_record_t	*p;
	rds_path_record_t	*p1;
	ipaddr_t		ret = addr;

	mutex_enter(&rdsv3_pathmap_lock);

	p = rdsv3_pathmap;
	while ((p) && (p->lnode_ip != addr)) {
		/* go to the next node record */
		p = p->nextp;
	}

	if (p != NULL) {
		p1 = p->downp;
		ret = p1->libd_ip;
		RDSV3_DPRINTF3("rds_scaddr_to_ibaddr",
		    "Addr: 0x%x found: 0x%x", addr, p1->libd_ip);
	}
	mutex_exit(&rdsv3_pathmap_lock);

	/* Found a matching node record */
	return (ret);
}
