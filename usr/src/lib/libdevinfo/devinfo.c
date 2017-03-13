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
 * Copyright (c) 1997, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Interfaces for getting device configuration data from kernel
 * through the devinfo driver.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stropts.h>
#include <fcntl.h>
#include <poll.h>
#include <synch.h>
#include <unistd.h>
#include <sys/mkdev.h>
#include <sys/obpdefs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/autoconf.h>
#include <stdarg.h>
#include <sys/ddi_hp.h>

#define	NDEBUG 1
#include <assert.h>

#include "libdevinfo.h"

/*
 * Debug message levels
 */
typedef enum {
	DI_QUIET = 0,	/* No debug messages - the default */
	DI_ERR = 1,
	DI_INFO,
	DI_TRACE,
	DI_TRACE1,
	DI_TRACE2
} di_debug_t;

int di_debug = DI_QUIET;

#define	DPRINTF(args)	{ if (di_debug != DI_QUIET) dprint args; }

void dprint(di_debug_t msglevel, const char *fmt, ...);


#pragma init(_libdevinfo_init)

void
_libdevinfo_init()
{
	char	*debug_str = getenv("_LIBDEVINFO_DEBUG");

	if (debug_str) {
		errno = 0;
		di_debug = atoi(debug_str);
		if (errno || di_debug < DI_QUIET)
			di_debug = DI_QUIET;
	}
}

di_node_t
di_init(const char *phys_path, uint_t flag)
{
	return (di_init_impl(phys_path, flag, NULL));
}

/*
 * We use blocking_open() to guarantee access to the devinfo device, if open()
 * is failing with EAGAIN.
 */
static int
blocking_open(const char *path, int oflag)
{
	int fd;

	while ((fd = open(path, oflag)) == -1 && errno == EAGAIN)
		(void) poll(NULL, 0, 1 * MILLISEC);

	return (fd);
}

/* private interface */
di_node_t
di_init_driver(const char *drv_name, uint_t flag)
{
	int fd;
	char driver[MAXPATHLEN];

	/*
	 * Don't allow drv_name to exceed MAXPATHLEN - 1, or 1023,
	 * which should be sufficient for any sensible programmer.
	 */
	if ((drv_name == NULL) || (strlen(drv_name) >= MAXPATHLEN)) {
		errno = EINVAL;
		return (DI_NODE_NIL);
	}
	(void) strcpy(driver, drv_name);

	/*
	 * open the devinfo driver
	 */
	if ((fd = blocking_open("/devices/pseudo/devinfo@0:devinfo",
	    O_RDONLY)) == -1) {
		DPRINTF((DI_ERR, "devinfo open failed: errno = %d\n", errno));
		return (DI_NODE_NIL);
	}

	if (ioctl(fd, DINFOLODRV, driver) != 0) {
		DPRINTF((DI_ERR, "failed to load driver %s\n", driver));
		(void) close(fd);
		errno = ENXIO;
		return (DI_NODE_NIL);
	}
	(void) close(fd);

	/*
	 * Driver load succeeded, return a snapshot
	 */
	return (di_init("/", flag));
}

di_node_t
di_init_impl(const char *phys_path, uint_t flag,
	struct di_priv_data *priv)
{
	caddr_t pa;
	int fd, map_size;
	struct di_all *dap;
	struct dinfo_io dinfo_io;

	uint_t pageoffset = sysconf(_SC_PAGESIZE) - 1;
	uint_t pagemask = ~pageoffset;

	DPRINTF((DI_INFO, "di_init: taking a snapshot\n"));

	/*
	 * Make sure there is no minor name in the path
	 * and the path do not start with /devices....
	 */
	if (strchr(phys_path, ':') ||
	    (strncmp(phys_path, "/devices", 8) == 0) ||
	    (strlen(phys_path) > MAXPATHLEN)) {
		errno = EINVAL;
		return (DI_NODE_NIL);
	}

	if (strlen(phys_path) == 0)
		(void) sprintf(dinfo_io.root_path, "/");
	else if (*phys_path != '/')
		(void) snprintf(dinfo_io.root_path, sizeof (dinfo_io.root_path),
		    "/%s", phys_path);
	else
		(void) snprintf(dinfo_io.root_path, sizeof (dinfo_io.root_path),
		    "%s", phys_path);

	/*
	 * If private data is requested, copy the format specification
	 */
	if (flag & DINFOPRIVDATA & 0xff) {
		if (priv)
			bcopy(priv, &dinfo_io.priv,
			    sizeof (struct di_priv_data));
		else {
			errno = EINVAL;
			return (DI_NODE_NIL);
		}
	}

	/*
	 * Attempt to open the devinfo driver.  Make a second attempt at the
	 * read-only minor node if we don't have privileges to open the full
	 * version _and_ if we're not requesting operations that the read-only
	 * node can't perform.  (Setgid processes would fail an access() test,
	 * of course.)
	 */
	if ((fd = blocking_open("/devices/pseudo/devinfo@0:devinfo",
	    O_RDONLY)) == -1) {
		if ((flag & DINFOFORCE) == DINFOFORCE ||
		    (flag & DINFOPRIVDATA) == DINFOPRIVDATA) {
			/*
			 * We wanted to perform a privileged operation, but the
			 * privileged node isn't available.  Don't modify errno
			 * on our way out (but display it if we're running with
			 * di_debug set).
			 */
			DPRINTF((DI_ERR, "devinfo open failed: errno = %d\n",
			    errno));
			return (DI_NODE_NIL);
		}

		if ((fd = blocking_open("/devices/pseudo/devinfo@0:devinfo,ro",
		    O_RDONLY)) == -1) {
			DPRINTF((DI_ERR, "devinfo open failed: errno = %d\n",
			    errno));
			return (DI_NODE_NIL);
		}
	}

	/*
	 * Verify that there is no major conflict, i.e., we are indeed opening
	 * the devinfo driver.
	 */
	if (ioctl(fd, DINFOIDENT, NULL) != DI_MAGIC) {
		DPRINTF((DI_ERR,
		    "driver ID failed; check for major conflict\n"));
		(void) close(fd);
		return (DI_NODE_NIL);
	}

	/*
	 * create snapshot
	 */
	if ((map_size = ioctl(fd, flag, &dinfo_io)) < 0) {
		DPRINTF((DI_ERR, "devinfo ioctl failed with "
		    "error: %d\n", errno));
		(void) close(fd);
		return (DI_NODE_NIL);
	} else if (map_size == 0) {
		DPRINTF((DI_ERR, "%s not found\n", phys_path));
		errno = ENXIO;
		(void) close(fd);
		return (DI_NODE_NIL);
	}

	/*
	 * copy snapshot to userland
	 */
	map_size = (map_size + pageoffset) & pagemask;
	if ((pa = valloc(map_size)) == NULL) {
		DPRINTF((DI_ERR, "valloc failed for snapshot\n"));
		(void) close(fd);
		return (DI_NODE_NIL);
	}

	if (ioctl(fd, DINFOUSRLD, pa) != map_size) {
		DPRINTF((DI_ERR, "failed to copy snapshot to usrld\n"));
		(void) close(fd);
		free(pa);
		errno = EFAULT;
		return (DI_NODE_NIL);
	}

	(void) close(fd);

	dap = DI_ALL(pa);
	if (dap->version != DI_SNAPSHOT_VERSION) {
		DPRINTF((DI_ERR, "wrong snapshot version "
		    "(expected=%d, actual=%d)\n",
		    DI_SNAPSHOT_VERSION, dap->version));
		free(pa);
		errno = ESTALE;
		return (DI_NODE_NIL);
	}
	if (dap->top_devinfo == 0) {	/* phys_path not found */
		DPRINTF((DI_ERR, "%s not found\n", phys_path));
		free(pa);
		errno = EINVAL;
		return (DI_NODE_NIL);
	}

	return (DI_NODE(pa + dap->top_devinfo));
}

void
di_fini(di_node_t root)
{
	caddr_t pa;		/* starting address of map */

	DPRINTF((DI_INFO, "di_fini: freeing a snapshot\n"));

	/*
	 * paranoid checking
	 */
	if (root == DI_NODE_NIL) {
		DPRINTF((DI_ERR, "di_fini called with NIL arg\n"));
		return;
	}

	/*
	 * The root contains its own offset--self.
	 * Subtracting it from root address, we get the starting addr.
	 * The map_size is stored at the beginning of snapshot.
	 * Once we have starting address and size, we can free().
	 */
	pa = (caddr_t)root - DI_NODE(root)->self;

	free(pa);
}

di_node_t
di_parent_node(di_node_t node)
{
	caddr_t pa;		/* starting address of map */

	if (node == DI_NODE_NIL) {
		errno = EINVAL;
		return (DI_NODE_NIL);
	}

	DPRINTF((DI_TRACE, "Get parent of node %s\n", di_node_name(node)));

	pa = (caddr_t)node - DI_NODE(node)->self;

	if (DI_NODE(node)->parent) {
		return (DI_NODE(pa + DI_NODE(node)->parent));
	}

	/*
	 * Deal with error condition:
	 *   If parent doesn't exist and node is not the root,
	 *   set errno to ENOTSUP. Otherwise, set errno to ENXIO.
	 */
	if (strcmp(DI_ALL(pa)->root_path, "/") != 0)
		errno = ENOTSUP;
	else
		errno = ENXIO;

	return (DI_NODE_NIL);
}

di_node_t
di_sibling_node(di_node_t node)
{
	caddr_t pa;		/* starting address of map */

	if (node == DI_NODE_NIL) {
		errno = EINVAL;
		return (DI_NODE_NIL);
	}

	DPRINTF((DI_TRACE, "Get sibling of node %s\n", di_node_name(node)));

	pa = (caddr_t)node - DI_NODE(node)->self;

	if (DI_NODE(node)->sibling) {
		return (DI_NODE(pa + DI_NODE(node)->sibling));
	}

	/*
	 * Deal with error condition:
	 *   Sibling doesn't exist, figure out if ioctl command
	 *   has DINFOSUBTREE set. If it doesn't, set errno to
	 *   ENOTSUP.
	 */
	if (!(DI_ALL(pa)->command & DINFOSUBTREE))
		errno = ENOTSUP;
	else
		errno = ENXIO;

	return (DI_NODE_NIL);
}

di_node_t
di_child_node(di_node_t node)
{
	caddr_t pa;		/* starting address of map */

	DPRINTF((DI_TRACE, "Get child of node %s\n", di_node_name(node)));

	if (node == DI_NODE_NIL) {
		errno = EINVAL;
		return (DI_NODE_NIL);
	}

	pa = (caddr_t)node - DI_NODE(node)->self;

	if (DI_NODE(node)->child) {
		return (DI_NODE(pa + DI_NODE(node)->child));
	}

	/*
	 * Deal with error condition:
	 *   Child doesn't exist, figure out if DINFOSUBTREE is set.
	 *   If it isn't, set errno to ENOTSUP.
	 */
	if (!(DI_ALL(pa)->command & DINFOSUBTREE))
		errno = ENOTSUP;
	else
		errno = ENXIO;

	return (DI_NODE_NIL);
}

di_node_t
di_drv_first_node(const char *drv_name, di_node_t root)
{
	caddr_t		pa;		/* starting address of map */
	int		major, devcnt;
	struct di_devnm	*devnm;

	DPRINTF((DI_INFO, "Get first node of driver %s\n", drv_name));

	if (root == DI_NODE_NIL) {
		errno = EINVAL;
		return (DI_NODE_NIL);
	}

	/*
	 * get major number of driver
	 */
	pa = (caddr_t)root - DI_NODE(root)->self;
	devcnt = DI_ALL(pa)->devcnt;
	devnm = DI_DEVNM(pa + DI_ALL(pa)->devnames);

	for (major = 0; major < devcnt; major++)
		if (devnm[major].name && (strcmp(drv_name,
		    (char *)(pa + devnm[major].name)) == 0))
			break;

	if (major >= devcnt) {
		errno = EINVAL;
		return (DI_NODE_NIL);
	}

	if (!(devnm[major].head)) {
		errno = ENXIO;
		return (DI_NODE_NIL);
	}

	return (DI_NODE(pa + devnm[major].head));
}

di_node_t
di_drv_next_node(di_node_t node)
{
	caddr_t		pa;		/* starting address of map */

	if (node == DI_NODE_NIL) {
		errno = EINVAL;
		return (DI_NODE_NIL);
	}

	DPRINTF((DI_TRACE, "next node on per driver list:"
	    " current=%s, driver=%s\n",
	    di_node_name(node), di_driver_name(node)));

	if (DI_NODE(node)->next == (di_off_t)-1) {
		errno = ENOTSUP;
		return (DI_NODE_NIL);
	}

	pa = (caddr_t)node - DI_NODE(node)->self;

	if (DI_NODE(node)->next == NULL) {
		errno = ENXIO;
		return (DI_NODE_NIL);
	}

	return (DI_NODE(pa + DI_NODE(node)->next));
}

/*
 * Internal library interfaces:
 *   node_list etc. for node walking
 */
struct node_list {
	struct node_list *next;
	di_node_t node;
};

static void
free_node_list(struct node_list **headp)
{
	struct node_list *tmp;

	while (*headp) {
		tmp = *headp;
		*headp = (*headp)->next;
		free(tmp);
	}
}

static void
append_node_list(struct node_list **headp, struct node_list *list)
{
	struct node_list *tmp;

	if (*headp == NULL) {
		*headp = list;
		return;
	}

	if (list == NULL)	/* a minor optimization */
		return;

	tmp = *headp;
	while (tmp->next)
		tmp = tmp->next;

	tmp->next = list;
}

static void
prepend_node_list(struct node_list **headp, struct node_list *list)
{
	struct node_list *tmp;

	if (list == NULL)
		return;

	tmp = *headp;
	*headp = list;

	if (tmp == NULL)	/* a minor optimization */
		return;

	while (list->next)
		list = list->next;

	list->next = tmp;
}

/*
 * returns 1 if node is a descendant of parent, 0 otherwise
 */
static int
is_descendant(di_node_t node, di_node_t parent)
{
	/*
	 * DI_NODE_NIL is parent of root, so it is
	 * the parent of all nodes.
	 */
	if (parent == DI_NODE_NIL) {
		return (1);
	}

	do {
		node = di_parent_node(node);
	} while ((node != DI_NODE_NIL) && (node != parent));

	return (node != DI_NODE_NIL);
}

/*
 * Insert list before the first node which is NOT a descendent of parent.
 * This is needed to reproduce the exact walking order of link generators.
 */
static void
insert_node_list(struct node_list **headp, struct node_list *list,
    di_node_t parent)
{
	struct node_list *tmp, *tmp1;

	if (list == NULL)
		return;

	tmp = *headp;
	if (tmp == NULL) {	/* a minor optimization */
		*headp = list;
		return;
	}

	if (!is_descendant(tmp->node, parent)) {
		prepend_node_list(headp, list);
		return;
	}

	/*
	 * Find first node which is not a descendant
	 */
	while (tmp->next && is_descendant(tmp->next->node, parent)) {
		tmp = tmp->next;
	}

	tmp1 = tmp->next;
	tmp->next = list;
	append_node_list(headp, tmp1);
}

/*
 *   Get a linked list of handles of all children
 */
static struct node_list *
get_children(di_node_t node)
{
	di_node_t child;
	struct node_list *result, *tmp;

	DPRINTF((DI_TRACE1, "Get children of node %s\n", di_node_name(node)));

	if ((child = di_child_node(node)) == DI_NODE_NIL) {
		return (NULL);
	}

	if ((result = malloc(sizeof (struct node_list))) == NULL) {
		DPRINTF((DI_ERR, "malloc of node_list failed\n"));
		return (NULL);
	}

	result->node = child;
	tmp = result;

	while ((child = di_sibling_node(tmp->node)) != DI_NODE_NIL) {
		if ((tmp->next = malloc(sizeof (struct node_list))) == NULL) {
			DPRINTF((DI_ERR, "malloc of node_list failed\n"));
			free_node_list(&result);
			return (NULL);
		}
		tmp = tmp->next;
		tmp->node = child;
	}

	tmp->next = NULL;

	return (result);
}

/*
 * Internal library interface:
 *   Delete all siblings of the first node from the node_list, along with
 *   the first node itself.
 */
static void
prune_sib(struct node_list **headp)
{
	di_node_t parent, curr_par, curr_gpar;
	struct node_list *curr, *prev;

	/*
	 * get handle to parent of first node
	 */
	if ((parent = di_parent_node((*headp)->node)) == DI_NODE_NIL) {
		/*
		 * This must be the root of the snapshot, so can't
		 * have any siblings.
		 *
		 * XXX Put a check here just in case.
		 */
		if ((*headp)->next)
			DPRINTF((DI_ERR, "Unexpected err in di_walk_node.\n"));

		free(*headp);
		*headp = NULL;
		return;
	}

	/*
	 * To be complete, we should also delete the children
	 * of siblings that have already been visited.
	 * This happens for DI_WALK_SIBFIRST when the first node
	 * is NOT the first in the linked list of siblings.
	 *
	 * Hence, we compare parent with BOTH the parent and grandparent
	 * of nodes, and delete node is a match is found.
	 */
	prev = *headp;
	curr = prev->next;
	while (curr) {
		if (((curr_par = di_parent_node(curr->node)) != DI_NODE_NIL) &&
		    ((curr_par == parent) || ((curr_gpar =
		    di_parent_node(curr_par)) != DI_NODE_NIL) &&
		    (curr_gpar == parent))) {
			/*
			 * match parent/grandparent: delete curr
			 */
			prev->next = curr->next;
			free(curr);
			curr = prev->next;
		} else
			curr = curr->next;
	}

	/*
	 * delete the first node
	 */
	curr = *headp;
	*headp = curr->next;
	free(curr);
}

/*
 * Internal library function:
 *	Update node list based on action (return code from callback)
 *	and flag specifying walking behavior.
 */
static void
update_node_list(int action, uint_t flag, struct node_list **headp)
{
	struct node_list *children, *tmp;
	di_node_t parent = di_parent_node((*headp)->node);

	switch (action) {
	case DI_WALK_TERMINATE:
		/*
		 * free the node list and be done
		 */
		children = NULL;
		free_node_list(headp);
		break;

	case DI_WALK_PRUNESIB:
		/*
		 * Get list of children and prune siblings
		 */
		children = get_children((*headp)->node);
		prune_sib(headp);
		break;

	case DI_WALK_PRUNECHILD:
		/*
		 * Set children to NULL and pop first node
		 */
		children = NULL;
		tmp = *headp;
		*headp = tmp->next;
		free(tmp);
		break;

	case DI_WALK_CONTINUE:
	default:
		/*
		 * Get list of children and pop first node
		 */
		children = get_children((*headp)->node);
		tmp = *headp;
		*headp = tmp->next;
		free(tmp);
		break;
	}

	/*
	 * insert the list of children
	 */
	switch (flag) {
	case DI_WALK_CLDFIRST:
		prepend_node_list(headp, children);
		break;

	case DI_WALK_SIBFIRST:
		append_node_list(headp, children);
		break;

	case DI_WALK_LINKGEN:
	default:
		insert_node_list(headp, children, parent);
		break;
	}
}

/*
 * Internal library function:
 *   Invoke callback on one node and update the list of nodes to be walked
 *   based on the flag and return code.
 */
static void
walk_one_node(struct node_list **headp, uint_t flag, void *arg,
	int (*callback)(di_node_t, void *))
{
	DPRINTF((DI_TRACE, "Walking node %s\n", di_node_name((*headp)->node)));

	update_node_list(callback((*headp)->node, arg),
	    flag & DI_WALK_MASK, headp);
}

int
di_walk_node(di_node_t root, uint_t flag, void *arg,
	int (*node_callback)(di_node_t, void *))
{
	struct node_list  *head;	/* node_list for tree walk */

	if (root == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if ((head = malloc(sizeof (struct node_list))) == NULL) {
		DPRINTF((DI_ERR, "malloc of node_list failed\n"));
		return (-1);
	}

	head->next = NULL;
	head->node = root;

	DPRINTF((DI_INFO, "Start node walking from node %s\n",
	    di_node_name(root)));

	while (head != NULL)
		walk_one_node(&head, flag, arg, node_callback);

	return (0);
}

/*
 * Internal library function:
 *   Invoke callback for each minor on the minor list of first node
 *   on node_list headp, and place children of first node on the list.
 *
 *   This is similar to walk_one_node, except we only walk in child
 *   first mode.
 */
static void
walk_one_minor_list(struct node_list **headp, const char *desired_type,
	uint_t flag, void *arg, int (*callback)(di_node_t, di_minor_t, void *))
{
	int ddm_type;
	int action = DI_WALK_CONTINUE;
	char *node_type;
	di_minor_t minor = DI_MINOR_NIL;
	di_node_t node = (*headp)->node;

	while ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
		ddm_type = di_minor_type(minor);

		if ((ddm_type == DDM_ALIAS) && !(flag & DI_CHECK_ALIAS))
			continue;

		if ((ddm_type == DDM_INTERNAL_PATH) &&
		    !(flag & DI_CHECK_INTERNAL_PATH))
			continue;

		node_type = di_minor_nodetype(minor);
		if ((desired_type != NULL) && ((node_type == NULL) ||
		    strncmp(desired_type, node_type, strlen(desired_type))
		    != 0))
			continue;

		if ((action = callback(node, minor, arg)) ==
		    DI_WALK_TERMINATE) {
			break;
		}
	}

	update_node_list(action, DI_WALK_LINKGEN, headp);
}

int
di_walk_minor(di_node_t root, const char *minor_type, uint_t flag, void *arg,
	int (*minor_callback)(di_node_t, di_minor_t, void *))
{
	struct node_list	*head;	/* node_list for tree walk */

#ifdef DEBUG
	char	*devfspath = di_devfs_path(root);
	DPRINTF((DI_INFO, "walking minor nodes under %s\n", devfspath));
	di_devfs_path_free(devfspath);
#endif

	if (root == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if ((head = malloc(sizeof (struct node_list))) == NULL) {
		DPRINTF((DI_ERR, "malloc of node_list failed\n"));
		return (-1);
	}

	head->next = NULL;
	head->node = root;

	DPRINTF((DI_INFO, "Start minor walking from node %s\n",
	    di_node_name(root)));

	while (head != NULL)
		walk_one_minor_list(&head, minor_type, flag, arg,
		    minor_callback);

	return (0);
}

/*
 * generic node parameters
 *   Calling these routines always succeeds.
 */
char *
di_node_name(di_node_t node)
{
	return ((caddr_t)node + DI_NODE(node)->node_name - DI_NODE(node)->self);
}

/* returns NULL ptr or a valid ptr to non-NULL string */
char *
di_bus_addr(di_node_t node)
{
	caddr_t pa = (caddr_t)node - DI_NODE(node)->self;

	if (DI_NODE(node)->address == 0)
		return (NULL);

	return ((char *)(pa + DI_NODE(node)->address));
}

char *
di_binding_name(di_node_t node)
{
	caddr_t pa = (caddr_t)node - DI_NODE(node)->self;

	if (DI_NODE(node)->bind_name == 0)
		return (NULL);

	return ((char *)(pa + DI_NODE(node)->bind_name));
}

int
di_compatible_names(di_node_t node, char **names)
{
	char *c;
	int len, size, entries = 0;

	if (DI_NODE(node)->compat_names == 0) {
		*names = NULL;
		return (0);
	}

	*names = (caddr_t)node +
	    DI_NODE(node)->compat_names - DI_NODE(node)->self;

	c = *names;
	len = DI_NODE(node)->compat_length;
	while (len > 0) {
		entries++;
		size = strlen(c) + 1;
		len -= size;
		c += size;
	}

	return (entries);
}

int
di_instance(di_node_t node)
{
	return (DI_NODE(node)->instance);
}

/*
 * XXX: emulate the return value of the old implementation
 * using info from devi_node_class and devi_node_attributes.
 */
int
di_nodeid(di_node_t node)
{
	if (DI_NODE(node)->node_class == DDI_NC_PROM)
		return (DI_PROM_NODEID);

	if (DI_NODE(node)->attributes & DDI_PERSISTENT)
		return (DI_SID_NODEID);

	return (DI_PSEUDO_NODEID);
}

uint_t
di_state(di_node_t node)
{
	uint_t result = 0;

	if (di_node_state(node) < DS_ATTACHED)
		result |= DI_DRIVER_DETACHED;
	if (DI_NODE(node)->state & DEVI_DEVICE_OFFLINE)
		result |= DI_DEVICE_OFFLINE;
	if (DI_NODE(node)->state & DEVI_DEVICE_DOWN)
		result |= DI_DEVICE_DOWN;
	if (DI_NODE(node)->state & DEVI_DEVICE_DEGRADED)
		result |= DI_DEVICE_DEGRADED;
	if (DI_NODE(node)->state & DEVI_DEVICE_REMOVED)
		result |= DI_DEVICE_REMOVED;
	if (DI_NODE(node)->state & DEVI_BUS_QUIESCED)
		result |= DI_BUS_QUIESCED;
	if (DI_NODE(node)->state & DEVI_BUS_DOWN)
		result |= DI_BUS_DOWN;

	return (result);
}

ddi_node_state_t
di_node_state(di_node_t node)
{
	return (DI_NODE(node)->node_state);
}

uint_t
di_flags(di_node_t node)
{
	return (DI_NODE(node)->flags);
}

uint_t
di_retired(di_node_t node)
{
	return (di_flags(node) & DEVI_RETIRED);
}

ddi_devid_t
di_devid(di_node_t node)
{
	if (DI_NODE(node)->devid == 0)
		return (NULL);

	return ((ddi_devid_t)((caddr_t)node +
	    DI_NODE(node)->devid - DI_NODE(node)->self));
}

int
di_driver_major(di_node_t node)
{
	int major;

	major = DI_NODE(node)->drv_major;
	if (major < 0)
		return (-1);
	return (major);
}

char *
di_driver_name(di_node_t node)
{
	int major;
	caddr_t pa;
	struct di_devnm *devnm;

	major = DI_NODE(node)->drv_major;
	if (major < 0)
		return (NULL);

	pa = (caddr_t)node - DI_NODE(node)->self;
	devnm = DI_DEVNM(pa + DI_ALL(pa)->devnames);

	if (devnm[major].name)
		return (pa + devnm[major].name);
	else
		return (NULL);
}

uint_t
di_driver_ops(di_node_t node)
{
	int major;
	caddr_t pa;
	struct di_devnm *devnm;

	major = DI_NODE(node)->drv_major;
	if (major < 0)
		return (0);

	pa = (caddr_t)node - DI_NODE(node)->self;
	devnm = DI_DEVNM(pa + DI_ALL(pa)->devnames);

	return (devnm[major].ops);
}

/*
 * Returns pointer to the allocated string, which must be freed by the caller.
 */
char *
di_devfs_path(di_node_t node)
{
	caddr_t pa;
	di_node_t parent;
	int depth = 0, len = 0;
	char *buf, *name[MAX_TREE_DEPTH], *addr[MAX_TREE_DEPTH];

	if (node == DI_NODE_NIL) {
		errno = EINVAL;
		return (NULL);
	}

	/*
	 * trace back to root, note the node_name & address
	 */
	while ((parent = di_parent_node(node)) != DI_NODE_NIL) {
		name[depth] = di_node_name(node);
		len += strlen(name[depth]) + 1;		/* 1 for '/' */

		if ((addr[depth] = di_bus_addr(node)) != NULL)
			len += strlen(addr[depth]) + 1;	/* 1 for '@' */

		node = parent;
		depth++;
	}

	/*
	 * get the path to the root of snapshot
	 */
	pa = (caddr_t)node - DI_NODE(node)->self;
	name[depth] = DI_ALL(pa)->root_path;
	len += strlen(name[depth]) + 1;

	/*
	 * allocate buffer and assemble path
	 */
	if ((buf = malloc(len)) == NULL) {
		return (NULL);
	}

	(void) strcpy(buf, name[depth]);
	len = strlen(buf);
	if (buf[len - 1] == '/')
		len--;	/* delete trailing '/' */

	while (depth) {
		depth--;
		buf[len] = '/';
		(void) strcpy(buf + len + 1, name[depth]);
		len += strlen(name[depth]) + 1;
		if (addr[depth] && addr[depth][0] != '\0') {
			buf[len] = '@';
			(void) strcpy(buf + len + 1, addr[depth]);
			len += strlen(addr[depth]) + 1;
		}
	}

	return (buf);
}

char *
di_devfs_minor_path(di_minor_t minor)
{
	di_node_t	node;
	char		*full_path, *name, *devfspath;
	int		full_path_len;

	if (minor == DI_MINOR_NIL) {
		errno = EINVAL;
		return (NULL);
	}

	name = di_minor_name(minor);
	node = di_minor_devinfo(minor);
	devfspath = di_devfs_path(node);
	if (devfspath == NULL)
		return (NULL);

	/* make the full path to the device minor node */
	full_path_len = strlen(devfspath) + strlen(name) + 2;
	full_path = (char *)calloc(1, full_path_len);
	if (full_path != NULL)
		(void) snprintf(full_path, full_path_len, "%s:%s",
		    devfspath, name);

	di_devfs_path_free(devfspath);
	return (full_path);
}

/*
 * Produce a string representation of path to di_path_t (pathinfo node). This
 * string is identical to di_devfs_path had the device been enumerated under
 * the pHCI: it has a base path to pHCI, then uses node_name of client, and
 * device unit-address of pathinfo node.
 */
char *
di_path_devfs_path(di_path_t path)
{
	di_node_t	phci_node;
	char		*phci_path, *path_name, *path_addr;
	char		*full_path;
	int		full_path_len;

	if (path == DI_PATH_NIL) {
		errno = EINVAL;
		return (NULL);
	}

	/* get name@addr for path */
	path_name = di_path_node_name(path);
	path_addr = di_path_bus_addr(path);
	if ((path_name == NULL) || (path_addr == NULL))
		return (NULL);

	/* base path to pHCI devinfo node */
	phci_node = di_path_phci_node(path);
	if (phci_node == NULL)
		return (NULL);
	phci_path = di_devfs_path(phci_node);
	if (phci_path == NULL)
		return (NULL);

	/* make the full string representation of path */
	full_path_len = strlen(phci_path) + 1 + strlen(path_name) +
	    1 + strlen(path_addr) + 1;
	full_path = (char *)calloc(1, full_path_len);

	if (full_path != NULL)
		(void) snprintf(full_path, full_path_len, "%s/%s@%s",
		    phci_path, path_name, path_addr);
	di_devfs_path_free(phci_path);
	return (full_path);
}

char *
di_path_client_devfs_path(di_path_t path)
{
	return (di_devfs_path(di_path_client_node(path)));
}

void
di_devfs_path_free(char *buf)
{
	if (buf == NULL) {
		DPRINTF((DI_ERR, "di_devfs_path_free NULL arg!\n"));
		return;
	}

	free(buf);
}

/*
 * Return 1 if name is a IEEE-1275 generic name. If new generic
 * names are defined, they should be added to this table
 */
static int
is_generic(const char *name, int len)
{
	const char	**gp;

	/* from IEEE-1275 recommended practices section 3 */
	static const char *generic_names[] = {
	    "atm",
	    "disk",
	    "display",
	    "dma-controller",
	    "ethernet",
	    "fcs",
	    "fdc",
	    "fddi",
	    "fibre-channel",
	    "ide",
	    "interrupt-controller",
	    "isa",
	    "keyboard",
	    "memory",
	    "mouse",
	    "nvram",
	    "pc-card",
	    "pci",
	    "printer",
	    "rtc",
	    "sbus",
	    "scanner",
	    "scsi",
	    "serial",
	    "sound",
	    "ssa",
	    "tape",
	    "timer",
	    "token-ring",
	    "vme",
	    0
	};

	for (gp = generic_names; *gp; gp++) {
		if ((strncmp(*gp, name, len) == 0) &&
		    (strlen(*gp) == len))
			return (1);
	}
	return (0);
}

/*
 * Determine if two paths below /devices refer to the same device, ignoring
 * any generic .vs. non-generic 'name' issues in "[[/]name[@addr[:minor]]]*".
 * Return 1 if the paths match.
 */
int
di_devfs_path_match(const char *dp1, const char *dp2)
{
	const char	*p1, *p2;
	const char	*ec1, *ec2;
	const char	*at1, *at2;
	char		nc;
	int		g1, g2;

	/* progress through both strings */
	for (p1 = dp1, p2 = dp2; (*p1 == *p2) && *p1; p1++, p2++) {
		/* require match until the start of a component */
		if (*p1 != '/')
			continue;

		/* advance p1 and p2 to start of 'name' in component */
		nc = *(p1 + 1);
		if ((nc == '\0') || (nc == '/'))
			continue;		/* skip trash */
		p1++;
		p2++;

		/*
		 * Both p1 and p2 point to beginning of 'name' in component.
		 * Determine where current component ends: next '/' or '\0'.
		 */
		ec1 = strchr(p1, '/');
		if (ec1 == NULL)
			ec1 = p1 + strlen(p1);
		ec2 = strchr(p2, '/');
		if (ec2 == NULL)
			ec2 = p2 + strlen(p2);

		/* Determine where name ends based on whether '@' exists */
		at1 = strchr(p1, '@');
		at2 = strchr(p2, '@');
		if (at1 && (at1 < ec1))
			ec1 = at1;
		if (at2 && (at2 < ec2))
			ec2 = at2;

		/*
		 * At this point p[12] point to beginning of name and
		 * ec[12] point to character past the end of name. Determine
		 * if the names are generic.
		 */
		g1 = is_generic(p1, ec1 - p1);
		g2 = is_generic(p2, ec2 - p2);

		if (g1 != g2) {
			/*
			 * one generic and one non-generic
			 * skip past the names in the match.
			 */
			p1 = ec1;
			p2 = ec2;
		} else {
			if (*p1 != *p2)
				break;
		}
	}

	return ((*p1 == *p2) ? 1 : 0);
}

/* minor data access */
di_minor_t
di_minor_next(di_node_t node, di_minor_t minor)
{
	caddr_t pa;

	/*
	 * paranoid error checking
	 */
	if (node == DI_NODE_NIL) {
		errno = EINVAL;
		return (DI_MINOR_NIL);
	}

	/*
	 * minor is not NIL
	 */
	if (minor != DI_MINOR_NIL) {
		if (DI_MINOR(minor)->next != 0)
			return ((di_minor_t)((void *)((caddr_t)minor -
			    DI_MINOR(minor)->self + DI_MINOR(minor)->next)));
		else {
			errno = ENXIO;
			return (DI_MINOR_NIL);
		}
	}

	/*
	 * minor is NIL-->caller asks for first minor node
	 */
	if (DI_NODE(node)->minor_data != 0) {
		return (DI_MINOR((caddr_t)node - DI_NODE(node)->self +
		    DI_NODE(node)->minor_data));
	}

	/*
	 * no minor data-->check if snapshot includes minor data
	 *	in order to set the correct errno
	 */
	pa = (caddr_t)node - DI_NODE(node)->self;
	if (DINFOMINOR & DI_ALL(pa)->command)
		errno = ENXIO;
	else
		errno = ENOTSUP;

	return (DI_MINOR_NIL);
}

/* private interface for dealing with alias minor link generation */
di_node_t
di_minor_devinfo(di_minor_t minor)
{
	if (minor == DI_MINOR_NIL) {
		errno = EINVAL;
		return (DI_NODE_NIL);
	}

	return (DI_NODE((caddr_t)minor - DI_MINOR(minor)->self +
	    DI_MINOR(minor)->node));
}

ddi_minor_type
di_minor_type(di_minor_t minor)
{
	return (DI_MINOR(minor)->type);
}

char *
di_minor_name(di_minor_t minor)
{
	if (DI_MINOR(minor)->name == 0)
		return (NULL);

	return ((caddr_t)minor - DI_MINOR(minor)->self + DI_MINOR(minor)->name);
}

dev_t
di_minor_devt(di_minor_t minor)
{
	return (makedev(DI_MINOR(minor)->dev_major,
	    DI_MINOR(minor)->dev_minor));
}

int
di_minor_spectype(di_minor_t minor)
{
	return (DI_MINOR(minor)->spec_type);
}

char *
di_minor_nodetype(di_minor_t minor)
{
	if (DI_MINOR(minor)->node_type == 0)
		return (NULL);

	return ((caddr_t)minor -
	    DI_MINOR(minor)->self + DI_MINOR(minor)->node_type);
}

/*
 * Single public interface for accessing software properties
 */
di_prop_t
di_prop_next(di_node_t node, di_prop_t prop)
{
	int list = DI_PROP_DRV_LIST;

	/*
	 * paranoid check
	 */
	if (node == DI_NODE_NIL) {
		errno = EINVAL;
		return (DI_PROP_NIL);
	}

	/*
	 * Find which prop list we are at
	 */
	if (prop != DI_PROP_NIL)
		list = DI_PROP(prop)->prop_list;

	do {
		switch (list++) {
		case DI_PROP_DRV_LIST:
			prop = di_prop_drv_next(node, prop);
			break;
		case DI_PROP_SYS_LIST:
			prop = di_prop_sys_next(node, prop);
			break;
		case DI_PROP_GLB_LIST:
			prop = di_prop_global_next(node, prop);
			break;
		case DI_PROP_HW_LIST:
			prop = di_prop_hw_next(node, prop);
			break;
		default:	/* shouldn't happen */
			errno = EFAULT;
			return (DI_PROP_NIL);
		}
	} while ((prop == DI_PROP_NIL) && (list <= DI_PROP_HW_LIST));

	return (prop);
}

dev_t
di_prop_devt(di_prop_t prop)
{
	return (makedev(DI_PROP(prop)->dev_major, DI_PROP(prop)->dev_minor));
}

char *
di_prop_name(di_prop_t prop)
{
	if (DI_PROP(prop)->prop_name == 0)
		return (NULL);

	return ((caddr_t)prop - DI_PROP(prop)->self + DI_PROP(prop)->prop_name);
}

int
di_prop_type(di_prop_t prop)
{
	uint_t flags = DI_PROP(prop)->prop_flags;

	if (flags & DDI_PROP_UNDEF_IT)
		return (DI_PROP_TYPE_UNDEF_IT);

	if (DI_PROP(prop)->prop_len == 0)
		return (DI_PROP_TYPE_BOOLEAN);

	if ((flags & DDI_PROP_TYPE_MASK) == DDI_PROP_TYPE_ANY)
		return (DI_PROP_TYPE_UNKNOWN);

	if (flags & DDI_PROP_TYPE_INT)
		return (DI_PROP_TYPE_INT);

	if (flags & DDI_PROP_TYPE_INT64)
		return (DI_PROP_TYPE_INT64);

	if (flags & DDI_PROP_TYPE_STRING)
		return (DI_PROP_TYPE_STRING);

	if (flags & DDI_PROP_TYPE_BYTE)
		return (DI_PROP_TYPE_BYTE);

	/*
	 * Shouldn't get here. In case we do, return unknown type.
	 *
	 * XXX--When DDI_PROP_TYPE_COMPOSITE is implemented, we need
	 *	to add DI_PROP_TYPE_COMPOSITE.
	 */
	DPRINTF((DI_ERR, "Unimplemented property type: 0x%x\n", flags));

	return (DI_PROP_TYPE_UNKNOWN);
}

/*
 * Extract type-specific values of an property
 */
extern int di_prop_decode_common(void *prop_data, int len,
	int ddi_type, int prom);

int
di_prop_ints(di_prop_t prop, int **prop_data)
{
	if (DI_PROP(prop)->prop_len == 0)
		return (0);	/* boolean property */

	if ((DI_PROP(prop)->prop_data == 0) ||
	    (DI_PROP(prop)->prop_data == (di_off_t)-1)) {
		errno = EFAULT;
		*prop_data = NULL;
		return (-1);
	}

	*prop_data = (int *)((void *)((caddr_t)prop - DI_PROP(prop)->self
	    + DI_PROP(prop)->prop_data));

	return (di_prop_decode_common((void *)prop_data,
	    DI_PROP(prop)->prop_len, DI_PROP_TYPE_INT, 0));
}

int
di_prop_int64(di_prop_t prop, int64_t **prop_data)
{
	if (DI_PROP(prop)->prop_len == 0)
		return (0);	/* boolean property */

	if ((DI_PROP(prop)->prop_data == 0) ||
	    (DI_PROP(prop)->prop_data == (di_off_t)-1)) {
		errno = EFAULT;
		*prop_data = NULL;
		return (-1);
	}

	*prop_data = (int64_t *)((void *)((caddr_t)prop - DI_PROP(prop)->self
	    + DI_PROP(prop)->prop_data));

	return (di_prop_decode_common((void *)prop_data,
	    DI_PROP(prop)->prop_len, DI_PROP_TYPE_INT64, 0));
}

int
di_prop_strings(di_prop_t prop, char **prop_data)
{
	if (DI_PROP(prop)->prop_len == 0)
		return (0);	/* boolean property */

	if ((DI_PROP(prop)->prop_data == 0) ||
	    (DI_PROP(prop)->prop_data == (di_off_t)-1)) {
		errno = EFAULT;
		*prop_data = NULL;
		return (-1);
	}

	*prop_data = (char *)((caddr_t)prop - DI_PROP(prop)->self
	    + DI_PROP(prop)->prop_data);

	return (di_prop_decode_common((void *)prop_data,
	    DI_PROP(prop)->prop_len, DI_PROP_TYPE_STRING, 0));
}

int
di_prop_bytes(di_prop_t prop, uchar_t **prop_data)
{
	if (DI_PROP(prop)->prop_len == 0)
		return (0);	/* boolean property */

	if ((DI_PROP(prop)->prop_data == 0) ||
	    (DI_PROP(prop)->prop_data == (di_off_t)-1)) {
		errno = EFAULT;
		*prop_data = NULL;
		return (-1);
	}

	*prop_data = (uchar_t *)((caddr_t)prop - DI_PROP(prop)->self
	    + DI_PROP(prop)->prop_data);

	return (di_prop_decode_common((void *)prop_data,
	    DI_PROP(prop)->prop_len, DI_PROP_TYPE_BYTE, 0));
}

/*
 * returns 1 for match, 0 for no match
 */
static int
match_prop(di_prop_t prop, dev_t match_dev, const char *name, int type)
{
	int prop_type;

#ifdef DEBUG
	if (di_prop_name(prop) == NULL) {
		DPRINTF((DI_ERR, "libdevinfo: property has no name!\n"));
		return (0);
	}
#endif /* DEBUG */

	if (strcmp(name, di_prop_name(prop)) != 0)
		return (0);

	if ((match_dev != DDI_DEV_T_ANY) && (di_prop_devt(prop) != match_dev))
		return (0);

	/*
	 * XXX prop_type is different from DDI_*. See PSARC 1997/127.
	 */
	prop_type = di_prop_type(prop);
	if ((prop_type != DI_PROP_TYPE_UNKNOWN) && (prop_type != type) &&
	    (prop_type != DI_PROP_TYPE_BOOLEAN))
		return (0);

	return (1);
}

static di_prop_t
di_prop_search(dev_t match_dev, di_node_t node, const char *name,
    int type)
{
	di_prop_t prop = DI_PROP_NIL;

	/*
	 * The check on match_dev follows ddi_prop_lookup_common().
	 * Other checks are libdevinfo specific implementation.
	 */
	if ((node == DI_NODE_NIL) || (name == NULL) || (strlen(name) == 0) ||
	    (match_dev == DDI_DEV_T_NONE) || !DI_PROP_TYPE_VALID(type)) {
		errno = EINVAL;
		return (DI_PROP_NIL);
	}

	while ((prop = di_prop_next(node, prop)) != DI_PROP_NIL) {
		DPRINTF((DI_TRACE1, "match prop name %s, devt 0x%lx, type %d\n",
		    di_prop_name(prop), di_prop_devt(prop),
		    di_prop_type(prop)));
		if (match_prop(prop, match_dev, name, type))
			return (prop);
	}

	return (DI_PROP_NIL);
}

di_prop_t
di_prop_find(dev_t match_dev, di_node_t node, const char *name)
{
	di_prop_t prop = DI_PROP_NIL;

	if ((node == DI_NODE_NIL) || (name == NULL) || (strlen(name) == 0) ||
	    (match_dev == DDI_DEV_T_NONE)) {
		errno = EINVAL;
		return (DI_PROP_NIL);
	}

	while ((prop = di_prop_next(node, prop)) != DI_PROP_NIL) {
		DPRINTF((DI_TRACE1, "found prop name %s, devt 0x%lx, type %d\n",
		    di_prop_name(prop), di_prop_devt(prop),
		    di_prop_type(prop)));

		if (strcmp(name, di_prop_name(prop)) == 0 &&
		    (match_dev == DDI_DEV_T_ANY ||
		    di_prop_devt(prop) == match_dev))
			return (prop);
	}

	return (DI_PROP_NIL);
}

int
di_prop_lookup_ints(dev_t dev, di_node_t node, const char *prop_name,
	int **prop_data)
{
	di_prop_t prop;

	if ((prop = di_prop_search(dev, node, prop_name,
	    DI_PROP_TYPE_INT)) == DI_PROP_NIL)
		return (-1);

	return (di_prop_ints(prop, (void *)prop_data));
}

int
di_prop_lookup_int64(dev_t dev, di_node_t node, const char *prop_name,
	int64_t **prop_data)
{
	di_prop_t prop;

	if ((prop = di_prop_search(dev, node, prop_name,
	    DI_PROP_TYPE_INT64)) == DI_PROP_NIL)
		return (-1);

	return (di_prop_int64(prop, (void *)prop_data));
}

int
di_prop_lookup_strings(dev_t dev, di_node_t node, const char *prop_name,
    char **prop_data)
{
	di_prop_t prop;

	if ((prop = di_prop_search(dev, node, prop_name,
	    DI_PROP_TYPE_STRING)) == DI_PROP_NIL)
		return (-1);

	return (di_prop_strings(prop, (void *)prop_data));
}

int
di_prop_lookup_bytes(dev_t dev, di_node_t node, const char *prop_name,
	uchar_t **prop_data)
{
	di_prop_t prop;

	if ((prop = di_prop_search(dev, node, prop_name,
	    DI_PROP_TYPE_BYTE)) == DI_PROP_NIL)
		return (-1);

	return (di_prop_bytes(prop, (void *)prop_data));
}

/*
 * Consolidation private property access functions
 */
enum prop_type {
	PROP_TYPE_DRV,
	PROP_TYPE_SYS,
	PROP_TYPE_GLOB,
	PROP_TYPE_HW
};

static di_prop_t
di_prop_next_common(di_node_t node, di_prop_t prop, int prop_type)
{
	caddr_t pa;
	di_off_t prop_off = 0;

	if (prop != DI_PROP_NIL) {
		if (DI_PROP(prop)->next) {
			return (DI_PROP((caddr_t)prop -
			    DI_PROP(prop)->self + DI_PROP(prop)->next));
		} else {
			return (DI_PROP_NIL);
		}
	}


	/*
	 * prop is NIL, caller asks for first property
	 */
	pa = (caddr_t)node - DI_NODE(node)->self;
	switch (prop_type) {
	case PROP_TYPE_DRV:
		prop_off = DI_NODE(node)->drv_prop;
		break;
	case PROP_TYPE_SYS:
		prop_off = DI_NODE(node)->sys_prop;
		break;
	case PROP_TYPE_HW:
		prop_off = DI_NODE(node)->hw_prop;
		break;
	case PROP_TYPE_GLOB:
		prop_off = DI_NODE(node)->glob_prop;
		if (prop_off == -1) {
			/* no global property */
			prop_off = 0;
		} else if ((prop_off == 0) && (DI_NODE(node)->drv_major >= 0)) {
			/* refer to devnames array */
			struct di_devnm *devnm = DI_DEVNM(pa +
			    DI_ALL(pa)->devnames + (DI_NODE(node)->drv_major *
			    sizeof (struct di_devnm)));
			prop_off = devnm->global_prop;
		}
		break;
	}

	if (prop_off) {
		return (DI_PROP(pa + prop_off));
	}

	/*
	 * no prop found. Check the reason for not found
	 */
	if (DINFOPROP & DI_ALL(pa)->command)
		errno = ENXIO;
	else
		errno = ENOTSUP;

	return (DI_PROP_NIL);
}

di_prop_t
di_prop_drv_next(di_node_t node, di_prop_t prop)
{
	return (di_prop_next_common(node, prop, PROP_TYPE_DRV));
}

di_prop_t
di_prop_sys_next(di_node_t node, di_prop_t prop)
{
	return (di_prop_next_common(node, prop, PROP_TYPE_SYS));
}

di_prop_t
di_prop_global_next(di_node_t node, di_prop_t prop)
{
	return (di_prop_next_common(node, prop, PROP_TYPE_GLOB));
}

di_prop_t
di_prop_hw_next(di_node_t node, di_prop_t prop)
{
	return (di_prop_next_common(node, prop, PROP_TYPE_HW));
}

int
di_prop_rawdata(di_prop_t prop, uchar_t **prop_data)
{
#ifdef DEBUG
	if (prop == DI_PROP_NIL) {
		errno = EINVAL;
		return (-1);
	}
#endif /* DEBUG */

	if (DI_PROP(prop)->prop_len == 0) {
		*prop_data = NULL;
		return (0);
	}

	if ((DI_PROP(prop)->prop_data == 0) ||
	    (DI_PROP(prop)->prop_data == (di_off_t)-1)) {
		errno = EFAULT;
		*prop_data = NULL;
		return (-1);
	}

	/*
	 * No memory allocation.
	 */
	*prop_data = (uchar_t *)((caddr_t)prop - DI_PROP(prop)->self +
	    DI_PROP(prop)->prop_data);

	return (DI_PROP(prop)->prop_len);
}

/*
 * Consolidation private interfaces for accessing I/O multipathing data
 */
di_path_t
di_path_phci_next_path(di_node_t node, di_path_t path)
{
	caddr_t pa;

	/*
	 * path is not NIL
	 */
	if (path != DI_PATH_NIL) {
		if (DI_PATH(path)->path_p_link != 0)
			return (DI_PATH((void *)((caddr_t)path -
			    DI_PATH(path)->self + DI_PATH(path)->path_p_link)));
		else {
			errno = ENXIO;
			return (DI_PATH_NIL);
		}
	}

	/*
	 * Path is NIL; the caller is asking for the first path info node
	 */
	if (DI_NODE(node)->multipath_phci != 0) {
		DPRINTF((DI_INFO, "phci_next_path: returning %p\n",
		    ((caddr_t)node -
		    DI_NODE(node)->self + DI_NODE(node)->multipath_phci)));
		return (DI_PATH((caddr_t)node - DI_NODE(node)->self +
		    DI_NODE(node)->multipath_phci));
	}

	/*
	 * No pathing data; check if the snapshot includes path data in order
	 * to set errno properly.
	 */
	pa = (caddr_t)node - DI_NODE(node)->self;
	if (DINFOPATH & (DI_ALL(pa)->command))
		errno = ENXIO;
	else
		errno = ENOTSUP;

	return (DI_PATH_NIL);
}

di_path_t
di_path_client_next_path(di_node_t node, di_path_t path)
{
	caddr_t pa;

	/*
	 * path is not NIL
	 */
	if (path != DI_PATH_NIL) {
		if (DI_PATH(path)->path_c_link != 0)
			return (DI_PATH((caddr_t)path - DI_PATH(path)->self
			    + DI_PATH(path)->path_c_link));
		else {
			errno = ENXIO;
			return (DI_PATH_NIL);
		}
	}

	/*
	 * Path is NIL; the caller is asking for the first path info node
	 */
	if (DI_NODE(node)->multipath_client != 0) {
		DPRINTF((DI_INFO, "client_next_path: returning %p\n",
		    ((caddr_t)node -
		    DI_NODE(node)->self + DI_NODE(node)->multipath_client)));
		return (DI_PATH((caddr_t)node - DI_NODE(node)->self +
		    DI_NODE(node)->multipath_client));
	}

	/*
	 * No pathing data; check if the snapshot includes path data in order
	 * to set errno properly.
	 */
	pa = (caddr_t)node - DI_NODE(node)->self;
	if (DINFOPATH & (DI_ALL(pa)->command))
		errno = ENXIO;
	else
		errno = ENOTSUP;

	return (DI_PATH_NIL);
}

/*
 * XXX Remove the private di_path_(addr,next,next_phci,next_client) interfaces
 * below after NWS consolidation switches to using di_path_bus_addr,
 * di_path_phci_next_path, and di_path_client_next_path per CR6638521.
 */
char *
di_path_addr(di_path_t path, char *buf)
{
	caddr_t pa;		/* starting address of map */

	pa = (caddr_t)path - DI_PATH(path)->self;

	(void) strncpy(buf, (char *)(pa + DI_PATH(path)->path_addr),
	    MAXPATHLEN);
	return (buf);
}
di_path_t
di_path_next(di_node_t node, di_path_t path)
{
	if (node == DI_NODE_NIL) {
		errno = EINVAL;
		return (DI_PATH_NIL);
	}

	if (DI_NODE(node)->multipath_client) {
		return (di_path_client_next_path(node, path));
	} else if (DI_NODE(node)->multipath_phci) {
		return (di_path_phci_next_path(node, path));
	} else {
		/*
		 * The node had multipathing data but didn't appear to be a
		 * phci *or* a client; probably a programmer error.
		 */
		errno = EINVAL;
		return (DI_PATH_NIL);
	}
}
di_path_t
di_path_next_phci(di_node_t node, di_path_t path)
{
	return (di_path_client_next_path(node, path));
}
di_path_t
di_path_next_client(di_node_t node, di_path_t path)
{
	return (di_path_phci_next_path(node, path));
}




di_path_state_t
di_path_state(di_path_t path)
{
	return ((di_path_state_t)DI_PATH(path)->path_state);
}

uint_t
di_path_flags(di_path_t path)
{
	return (DI_PATH(path)->path_flags);
}

char *
di_path_node_name(di_path_t path)
{
	di_node_t	client_node;

	/* pathinfo gets node_name from client */
	if ((client_node = di_path_client_node(path)) == NULL)
		return (NULL);
	return (di_node_name(client_node));
}

char *
di_path_bus_addr(di_path_t path)
{
	caddr_t pa = (caddr_t)path - DI_PATH(path)->self;

	if (DI_PATH(path)->path_addr == 0)
		return (NULL);

	return ((char *)(pa + DI_PATH(path)->path_addr));
}

int
di_path_instance(di_path_t path)
{
	return (DI_PATH(path)->path_instance);
}

di_node_t
di_path_client_node(di_path_t path)
{
	caddr_t pa;		/* starting address of map */

	if (path == DI_PATH_NIL) {
		errno = EINVAL;
		return (DI_PATH_NIL);
	}

	DPRINTF((DI_TRACE, "Get client node for path %p\n", path));

	pa = (caddr_t)path - DI_PATH(path)->self;

	if (DI_PATH(path)->path_client) {
		return (DI_NODE(pa + DI_PATH(path)->path_client));
	}

	/*
	 * Deal with error condition:
	 *   If parent doesn't exist and node is not the root,
	 *   set errno to ENOTSUP. Otherwise, set errno to ENXIO.
	 */
	if ((DI_PATH(path)->path_snap_state & DI_PATH_SNAP_NOCLIENT) == 0)
		errno = ENOTSUP;
	else
		errno = ENXIO;

	return (DI_NODE_NIL);
}

di_node_t
di_path_phci_node(di_path_t path)
{
	caddr_t pa;		/* starting address of map */

	if (path == DI_PATH_NIL) {
		errno = EINVAL;
		return (DI_PATH_NIL);
	}

	DPRINTF((DI_TRACE, "Get phci node for path %p\n", path));

	pa = (caddr_t)path - DI_PATH(path)->self;

	if (DI_PATH(path)->path_phci) {
		return (DI_NODE(pa + DI_PATH(path)->path_phci));
	}

	/*
	 * Deal with error condition:
	 *   If parent doesn't exist and node is not the root,
	 *   set errno to ENOTSUP. Otherwise, set errno to ENXIO.
	 */
	if ((DI_PATH(path)->path_snap_state & DI_PATH_SNAP_NOPHCI) == 0)
		errno = ENOTSUP;
	else
		errno = ENXIO;

	return (DI_NODE_NIL);
}

di_path_prop_t
di_path_prop_next(di_path_t path, di_path_prop_t prop)
{
	caddr_t pa;

	if (path == DI_PATH_NIL) {
		errno = EINVAL;
		return (DI_PROP_NIL);
	}

	/*
	 * prop is not NIL
	 */
	if (prop != DI_PROP_NIL) {
		if (DI_PROP(prop)->next != 0)
			return (DI_PATHPROP((caddr_t)prop -
			    DI_PROP(prop)->self + DI_PROP(prop)->next));
		else {
			errno = ENXIO;
			return (DI_PROP_NIL);
		}
	}

	/*
	 * prop is NIL-->caller asks for first property
	 */
	pa = (caddr_t)path - DI_PATH(path)->self;
	if (DI_PATH(path)->path_prop != 0) {
		return (DI_PATHPROP(pa + DI_PATH(path)->path_prop));
	}

	/*
	 * no property data-->check if snapshot includes props
	 *	in order to set the correct errno
	 */
	if (DINFOPROP & (DI_ALL(pa)->command))
		errno = ENXIO;
	else
		errno = ENOTSUP;

	return (DI_PROP_NIL);
}

char *
di_path_prop_name(di_path_prop_t prop)
{
	caddr_t pa;		/* starting address of map */
	pa = (caddr_t)prop - DI_PATHPROP(prop)->self;
	return ((char *)(pa + DI_PATHPROP(prop)->prop_name));
}

int
di_path_prop_len(di_path_prop_t prop)
{
	return (DI_PATHPROP(prop)->prop_len);
}

int
di_path_prop_type(di_path_prop_t prop)
{
	switch (DI_PATHPROP(prop)->prop_type) {
		case DDI_PROP_TYPE_INT:
			return (DI_PROP_TYPE_INT);
		case DDI_PROP_TYPE_INT64:
			return (DI_PROP_TYPE_INT64);
		case DDI_PROP_TYPE_BYTE:
			return (DI_PROP_TYPE_BYTE);
		case DDI_PROP_TYPE_STRING:
			return (DI_PROP_TYPE_STRING);
	}
	return (DI_PROP_TYPE_UNKNOWN);
}

int
di_path_prop_bytes(di_path_prop_t prop, uchar_t **prop_data)
{
	if ((DI_PATHPROP(prop)->prop_data == 0) ||
	    (DI_PATHPROP(prop)->prop_data == (di_off_t)-1)) {
		errno = EFAULT;
		*prop_data = NULL;
		return (-1);
	}

	*prop_data = (uchar_t *)((caddr_t)prop - DI_PATHPROP(prop)->self
	    + DI_PATHPROP(prop)->prop_data);

	return (di_prop_decode_common((void *)prop_data,
	    DI_PATHPROP(prop)->prop_len, DI_PROP_TYPE_BYTE, 0));
}

int
di_path_prop_ints(di_path_prop_t prop, int **prop_data)
{
	if (DI_PATHPROP(prop)->prop_len == 0)
		return (0);

	if ((DI_PATHPROP(prop)->prop_data == 0) ||
	    (DI_PATHPROP(prop)->prop_data == (di_off_t)-1)) {
		errno = EFAULT;
		*prop_data = NULL;
		return (-1);
	}

	*prop_data = (int *)((void *)((caddr_t)prop - DI_PATHPROP(prop)->self
	    + DI_PATHPROP(prop)->prop_data));

	return (di_prop_decode_common((void *)prop_data,
	    DI_PATHPROP(prop)->prop_len, DI_PROP_TYPE_INT, 0));
}

int
di_path_prop_int64s(di_path_prop_t prop, int64_t **prop_data)
{
	if (DI_PATHPROP(prop)->prop_len == 0)
		return (0);

	if ((DI_PATHPROP(prop)->prop_data == 0) ||
	    (DI_PATHPROP(prop)->prop_data == (di_off_t)-1)) {
		errno = EFAULT;
		*prop_data = NULL;
		return (-1);
	}

	*prop_data = (int64_t *)((void *)((caddr_t)prop -
	    DI_PATHPROP(prop)->self + DI_PATHPROP(prop)->prop_data));

	return (di_prop_decode_common((void *)prop_data,
	    DI_PATHPROP(prop)->prop_len, DI_PROP_TYPE_INT64, 0));
}

int
di_path_prop_strings(di_path_prop_t prop, char **prop_data)
{
	if (DI_PATHPROP(prop)->prop_len == 0)
		return (0);

	if ((DI_PATHPROP(prop)->prop_data == 0) ||
	    (DI_PATHPROP(prop)->prop_data == (di_off_t)-1)) {
		errno = EFAULT;
		*prop_data = NULL;
		return (-1);
	}

	*prop_data = (char *)((caddr_t)prop - DI_PATHPROP(prop)->self
	    + DI_PATHPROP(prop)->prop_data);

	return (di_prop_decode_common((void *)prop_data,
	    DI_PATHPROP(prop)->prop_len, DI_PROP_TYPE_STRING, 0));
}

static di_path_prop_t
di_path_prop_search(di_path_t path, const char *name, int type)
{
	di_path_prop_t prop = DI_PROP_NIL;

	/*
	 * Sanity check arguments
	 */
	if ((path == DI_PATH_NIL) || (name == NULL) || (strlen(name) == 0) ||
	    !DI_PROP_TYPE_VALID(type)) {
		errno = EINVAL;
		return (DI_PROP_NIL);
	}

	while ((prop = di_path_prop_next(path, prop)) != DI_PROP_NIL) {
		int prop_type = di_path_prop_type(prop);

		DPRINTF((DI_TRACE1, "match path prop name %s, type %d\n",
		    di_path_prop_name(prop), prop_type));

		if (strcmp(name, di_path_prop_name(prop)) != 0)
			continue;

		if ((prop_type != DI_PROP_TYPE_UNKNOWN) && (prop_type != type))
			continue;

		return (prop);
	}

	return (DI_PROP_NIL);
}

int
di_path_prop_lookup_bytes(di_path_t path, const char *prop_name,
    uchar_t **prop_data)
{
	di_path_prop_t prop;

	if ((prop = di_path_prop_search(path, prop_name,
	    DI_PROP_TYPE_BYTE)) == DI_PROP_NIL)
		return (-1);

	return (di_path_prop_bytes(prop, prop_data));
}

int
di_path_prop_lookup_ints(di_path_t path, const char *prop_name,
    int **prop_data)
{
	di_path_prop_t prop;

	if ((prop = di_path_prop_search(path, prop_name,
	    DI_PROP_TYPE_INT)) == DI_PROP_NIL)
		return (-1);

	return (di_path_prop_ints(prop, prop_data));
}

int
di_path_prop_lookup_int64s(di_path_t path, const char *prop_name,
    int64_t **prop_data)
{
	di_path_prop_t prop;

	if ((prop = di_path_prop_search(path, prop_name,
	    DI_PROP_TYPE_INT64)) == DI_PROP_NIL)
		return (-1);

	return (di_path_prop_int64s(prop, prop_data));
}

int di_path_prop_lookup_strings(di_path_t path, const char *prop_name,
    char **prop_data)
{
	di_path_prop_t prop;

	if ((prop = di_path_prop_search(path, prop_name,
	    DI_PROP_TYPE_STRING)) == DI_PROP_NIL)
		return (-1);

	return (di_path_prop_strings(prop, prop_data));
}

/*
 * Consolidation private interfaces for traversing vhci nodes.
 */
di_node_t
di_vhci_first_node(di_node_t root)
{
	struct di_all *dap;
	caddr_t		pa;		/* starting address of map */

	DPRINTF((DI_INFO, "Get first vhci node\n"));

	if (root == DI_NODE_NIL) {
		errno = EINVAL;
		return (DI_NODE_NIL);
	}

	pa = (caddr_t)root - DI_NODE(root)->self;
	dap = DI_ALL(pa);

	if (dap->top_vhci_devinfo == NULL) {
		errno = ENXIO;
		return (DI_NODE_NIL);
	}

	return (DI_NODE(pa + dap->top_vhci_devinfo));
}

di_node_t
di_vhci_next_node(di_node_t node)
{
	caddr_t		pa;		/* starting address of map */

	if (node == DI_NODE_NIL) {
		errno = EINVAL;
		return (DI_NODE_NIL);
	}

	DPRINTF((DI_TRACE, "next vhci node on the snap shot:"
	    " current=%s\n", di_node_name(node)));

	if (DI_NODE(node)->next_vhci == NULL) {
		errno = ENXIO;
		return (DI_NODE_NIL);
	}

	pa = (caddr_t)node - DI_NODE(node)->self;

	return (DI_NODE(pa + DI_NODE(node)->next_vhci));
}

/*
 * Consolidation private interfaces for traversing phci nodes.
 */
di_node_t
di_phci_first_node(di_node_t vhci_node)
{
	caddr_t		pa;		/* starting address of map */

	DPRINTF((DI_INFO, "Get first phci node:\n"
	    " current=%s", di_node_name(vhci_node)));

	if (vhci_node == DI_NODE_NIL) {
		errno = EINVAL;
		return (DI_NODE_NIL);
	}

	pa = (caddr_t)vhci_node - DI_NODE(vhci_node)->self;

	if (DI_NODE(vhci_node)->top_phci == NULL) {
		errno = ENXIO;
		return (DI_NODE_NIL);
	}

	return (DI_NODE(pa + DI_NODE(vhci_node)->top_phci));
}

di_node_t
di_phci_next_node(di_node_t node)
{
	caddr_t		pa;		/* starting address of map */

	if (node == DI_NODE_NIL) {
		errno = EINVAL;
		return (DI_NODE_NIL);
	}

	DPRINTF((DI_TRACE, "next phci node on the snap shot:"
	    " current=%s\n", di_node_name(node)));

	if (DI_NODE(node)->next_phci == NULL) {
		errno = ENXIO;
		return (DI_NODE_NIL);
	}

	pa = (caddr_t)node - DI_NODE(node)->self;

	return (DI_NODE(pa + DI_NODE(node)->next_phci));
}

/*
 * Consolidation private interfaces for private data
 */
void *
di_parent_private_data(di_node_t node)
{
	caddr_t pa;

	if (DI_NODE(node)->parent_data == 0) {
		errno = ENXIO;
		return (NULL);
	}

	if (DI_NODE(node)->parent_data == (di_off_t)-1) {
		/*
		 * Private data requested, but not obtained due to a memory
		 * error (e.g. wrong format specified)
		 */
		errno = EFAULT;
		return (NULL);
	}

	pa = (caddr_t)node - DI_NODE(node)->self;
	if (DI_NODE(node)->parent_data)
		return (pa + DI_NODE(node)->parent_data);

	if (DI_ALL(pa)->command & DINFOPRIVDATA)
		errno = ENXIO;
	else
		errno = ENOTSUP;

	return (NULL);
}

void *
di_driver_private_data(di_node_t node)
{
	caddr_t pa;

	if (DI_NODE(node)->driver_data == 0) {
		errno = ENXIO;
		return (NULL);
	}

	if (DI_NODE(node)->driver_data == (di_off_t)-1) {
		/*
		 * Private data requested, but not obtained due to a memory
		 * error (e.g. wrong format specified)
		 */
		errno = EFAULT;
		return (NULL);
	}

	pa = (caddr_t)node - DI_NODE(node)->self;
	if (DI_NODE(node)->driver_data)
		return (pa + DI_NODE(node)->driver_data);

	if (DI_ALL(pa)->command & DINFOPRIVDATA)
		errno = ENXIO;
	else
		errno = ENOTSUP;

	return (NULL);
}

/*
 * Hotplug information access
 */

typedef struct {
	void		*arg;
	const char	*type;
	uint_t		flag;
	int		(*hp_callback)(di_node_t, di_hp_t, void *);
} di_walk_hp_arg_t;

static int
di_walk_hp_callback(di_node_t node, void *argp)
{
	di_walk_hp_arg_t 	*arg = (di_walk_hp_arg_t *)argp;
	di_hp_t			hp;
	char			*type_str;

	for (hp = DI_HP_NIL; (hp = di_hp_next(node, hp)) != DI_HP_NIL; ) {

		/* Exclude non-matching types if a type filter is specified */
		if (arg->type != NULL) {
			type_str = di_hp_description(hp);
			if (type_str && (strcmp(arg->type, type_str) != 0))
				continue;
		}

		/* Exclude ports if DI_HP_PORT flag not specified */
		if (!(arg->flag & DI_HP_PORT) &&
		    (di_hp_type(hp) == DDI_HP_CN_TYPE_VIRTUAL_PORT))
			continue;

		/* Exclude connectors if DI_HP_CONNECTOR flag not specified */
		if (!(arg->flag & DI_HP_CONNECTOR) &&
		    !(di_hp_type(hp) == DDI_HP_CN_TYPE_VIRTUAL_PORT))
			continue;

		/* Perform callback */
		if (arg->hp_callback(node, hp, arg->arg) != DI_WALK_CONTINUE)
			return (DI_WALK_TERMINATE);
	}

	return (DI_WALK_CONTINUE);
}

int
di_walk_hp(di_node_t node, const char *type, uint_t flag, void *arg,
    int (*hp_callback)(di_node_t node, di_hp_t hp, void *arg))
{
	di_walk_hp_arg_t	walk_arg;
	caddr_t			pa;

#ifdef DEBUG
	char	*devfspath = di_devfs_path(node);
	DPRINTF((DI_INFO, "walking hotplug nodes under %s\n", devfspath));
	di_devfs_path_free(devfspath);
#endif
	/*
	 * paranoid error checking
	 */
	if ((node == DI_NODE_NIL) || (hp_callback == NULL)) {
		errno = EINVAL;
		return (-1);
	}

	/* check if hotplug data is included in snapshot */
	pa = (caddr_t)node - DI_NODE(node)->self;
	if (!(DI_ALL(pa)->command & DINFOHP)) {
		errno = ENOTSUP;
		return (-1);
	}

	walk_arg.arg = arg;
	walk_arg.type = type;
	walk_arg.flag = flag;
	walk_arg.hp_callback = hp_callback;
	return (di_walk_node(node, DI_WALK_CLDFIRST, &walk_arg,
	    di_walk_hp_callback));
}

di_hp_t
di_hp_next(di_node_t node, di_hp_t hp)
{
	caddr_t pa;

	/*
	 * paranoid error checking
	 */
	if (node == DI_NODE_NIL) {
		errno = EINVAL;
		return (DI_HP_NIL);
	}

	/*
	 * hotplug node is not NIL
	 */
	if (hp != DI_HP_NIL) {
		if (DI_HP(hp)->next != 0)
			return (DI_HP((caddr_t)hp - hp->self + hp->next));
		else {
			errno = ENXIO;
			return (DI_HP_NIL);
		}
	}

	/*
	 * hotplug node is NIL-->caller asks for first hotplug node
	 */
	if (DI_NODE(node)->hp_data != 0) {
		return (DI_HP((caddr_t)node - DI_NODE(node)->self +
		    DI_NODE(node)->hp_data));
	}

	/*
	 * no hotplug data-->check if snapshot includes hotplug data
	 *	in order to set the correct errno
	 */
	pa = (caddr_t)node - DI_NODE(node)->self;
	if (DINFOHP & DI_ALL(pa)->command)
		errno = ENXIO;
	else
		errno = ENOTSUP;

	return (DI_HP_NIL);
}

char *
di_hp_name(di_hp_t hp)
{
	caddr_t pa;

	/*
	 * paranoid error checking
	 */
	if (hp == DI_HP_NIL) {
		errno = EINVAL;
		return (NULL);
	}

	pa = (caddr_t)hp - DI_HP(hp)->self;

	if (DI_HP(hp)->hp_name == 0) {
		errno = ENXIO;
		return (NULL);
	}

	return ((char *)(pa + DI_HP(hp)->hp_name));
}

int
di_hp_connection(di_hp_t hp)
{
	/*
	 * paranoid error checking
	 */
	if (hp == DI_HP_NIL) {
		errno = EINVAL;
		return (-1);
	}

	if (DI_HP(hp)->hp_connection == -1)
		errno = ENOENT;

	return (DI_HP(hp)->hp_connection);
}

int
di_hp_depends_on(di_hp_t hp)
{
	/*
	 * paranoid error checking
	 */
	if (hp == DI_HP_NIL) {
		errno = EINVAL;
		return (-1);
	}

	if (DI_HP(hp)->hp_depends_on == -1)
		errno = ENOENT;

	return (DI_HP(hp)->hp_depends_on);
}

int
di_hp_state(di_hp_t hp)
{
	/*
	 * paranoid error checking
	 */
	if (hp == DI_HP_NIL) {
		errno = EINVAL;
		return (-1);
	}

	return (DI_HP(hp)->hp_state);
}

int
di_hp_type(di_hp_t hp)
{
	/*
	 * paranoid error checking
	 */
	if (hp == DI_HP_NIL) {
		errno = EINVAL;
		return (-1);
	}

	return (DI_HP(hp)->hp_type);
}

char *
di_hp_description(di_hp_t hp)
{
	caddr_t pa;

	/*
	 * paranoid error checking
	 */
	if (hp == DI_HP_NIL) {
		errno = EINVAL;
		return (NULL);
	}

	pa = (caddr_t)hp - DI_HP(hp)->self;

	if (DI_HP(hp)->hp_type_str == 0)
		return (NULL);

	return ((char *)(pa + DI_HP(hp)->hp_type_str));
}

di_node_t
di_hp_child(di_hp_t hp)
{
	caddr_t pa;		/* starting address of map */

	/*
	 * paranoid error checking
	 */
	if (hp == DI_HP_NIL) {
		errno = EINVAL;
		return (DI_NODE_NIL);
	}

	pa = (caddr_t)hp - DI_HP(hp)->self;

	if (DI_HP(hp)->hp_child > 0) {
		return (DI_NODE(pa + DI_HP(hp)->hp_child));
	}

	/*
	 * Deal with error condition:
	 *   Child doesn't exist, figure out if DINFOSUBTREE is set.
	 *   If it isn't, set errno to ENOTSUP.
	 */
	if (!(DINFOSUBTREE & DI_ALL(pa)->command))
		errno = ENOTSUP;
	else
		errno = ENXIO;

	return (DI_NODE_NIL);
}

time_t
di_hp_last_change(di_hp_t hp)
{
	/*
	 * paranoid error checking
	 */
	if (hp == DI_HP_NIL) {
		errno = EINVAL;
		return ((time_t)0);
	}

	return ((time_t)DI_HP(hp)->hp_last_change);
}

/*
 * PROM property access
 */

/*
 * openprom driver stuff:
 *	The maximum property length depends on the buffer size. We use
 *	OPROMMAXPARAM defined in <sys/openpromio.h>
 *
 *	MAXNAMESZ is max property name. obpdefs.h defines it as 32 based on 1275
 *	MAXVALSZ is maximum value size, which is whatever space left in buf
 */

#define	OBP_MAXBUF	OPROMMAXPARAM - sizeof (int)
#define	OBP_MAXPROPLEN	OBP_MAXBUF - OBP_MAXPROPNAME;

struct di_prom_prop {
	char *name;
	int len;
	uchar_t *data;
	struct di_prom_prop *next;	/* form a linked list */
};

struct di_prom_handle { /* handle to prom */
	mutex_t lock;	/* synchronize access to openprom fd */
	int	fd;	/* /dev/openprom file descriptor */
	struct di_prom_prop *list;	/* linked list of prop */
	union {
		char buf[OPROMMAXPARAM];
		struct openpromio opp;
	} oppbuf;
};

di_prom_handle_t
di_prom_init()
{
	struct di_prom_handle *p;

	if ((p = malloc(sizeof (struct di_prom_handle))) == NULL)
		return (DI_PROM_HANDLE_NIL);

	DPRINTF((DI_INFO, "di_prom_init: get prom handle 0x%p\n", p));

	(void) mutex_init(&p->lock, USYNC_THREAD, NULL);
	if ((p->fd = open("/dev/openprom", O_RDONLY)) < 0) {
		free(p);
		return (DI_PROM_HANDLE_NIL);
	}
	p->list = NULL;

	return ((di_prom_handle_t)p);
}

static void
di_prom_prop_free(struct di_prom_prop *list)
{
	struct di_prom_prop *tmp = list;

	while (tmp != NULL) {
		list = tmp->next;
		if (tmp->name != NULL) {
			free(tmp->name);
		}
		if (tmp->data != NULL) {
			free(tmp->data);
		}
		free(tmp);
		tmp = list;
	}
}

void
di_prom_fini(di_prom_handle_t ph)
{
	struct di_prom_handle *p = (struct di_prom_handle *)ph;

	DPRINTF((DI_INFO, "di_prom_fini: free prom handle 0x%p\n", p));

	(void) close(p->fd);
	(void) mutex_destroy(&p->lock);
	di_prom_prop_free(p->list);

	free(p);
}

/*
 * Internal library interface for locating the property
 * XXX: ph->lock must be held for the duration of call.
 */
static di_prom_prop_t
di_prom_prop_found(di_prom_handle_t ph, int nodeid,
	di_prom_prop_t prom_prop)
{
	struct di_prom_handle *p = (struct di_prom_handle *)ph;
	struct openpromio *opp = &p->oppbuf.opp;
	int *ip = (int *)((void *)opp->oprom_array);
	struct di_prom_prop *prop = (struct di_prom_prop *)prom_prop;

	DPRINTF((DI_TRACE1, "Looking for nodeid 0x%x\n", nodeid));

	/*
	 * Set "current" nodeid in the openprom driver
	 */
	opp->oprom_size = sizeof (int);
	*ip = nodeid;
	if (ioctl(p->fd, OPROMSETNODEID, opp) < 0) {
		DPRINTF((DI_ERR, "*** Nodeid not found 0x%x\n", nodeid));
		return (DI_PROM_PROP_NIL);
	}

	DPRINTF((DI_TRACE, "Found nodeid 0x%x\n", nodeid));

	bzero(opp, OBP_MAXBUF);
	opp->oprom_size = OBP_MAXPROPNAME;
	if (prom_prop != DI_PROM_PROP_NIL)
		(void) strcpy(opp->oprom_array, prop->name);

	if ((ioctl(p->fd, OPROMNXTPROP, opp) < 0) || (opp->oprom_size == 0))
		return (DI_PROM_PROP_NIL);

	/*
	 * Prom property found. Allocate struct for storing prop
	 *   (reuse variable prop)
	 */
	if ((prop = malloc(sizeof (struct di_prom_prop))) == NULL)
		return (DI_PROM_PROP_NIL);

	/*
	 * Get a copy of property name
	 */
	if ((prop->name = strdup(opp->oprom_array)) == NULL) {
		free(prop);
		return (DI_PROM_PROP_NIL);
	}

	/*
	 * get property value and length
	 */
	opp->oprom_size = OBP_MAXPROPLEN;

	if ((ioctl(p->fd, OPROMGETPROP, opp) < 0) ||
	    (opp->oprom_size == (uint_t)-1)) {
		free(prop->name);
		free(prop);
		return (DI_PROM_PROP_NIL);
	}

	/*
	 * make a copy of the property value
	 */
	prop->len = opp->oprom_size;

	if (prop->len == 0)
		prop->data = NULL;
	else if ((prop->data = malloc(prop->len)) == NULL) {
		free(prop->name);
		free(prop);
		return (DI_PROM_PROP_NIL);
	}

	bcopy(opp->oprom_array, prop->data, prop->len);

	/*
	 * Prepend prop to list in prom handle
	 */
	prop->next = p->list;
	p->list = prop;

	return ((di_prom_prop_t)prop);
}

di_prom_prop_t
di_prom_prop_next(di_prom_handle_t ph, di_node_t node, di_prom_prop_t prom_prop)
{
	struct di_prom_handle *p = (struct di_prom_handle *)ph;

	DPRINTF((DI_TRACE1, "Search next prop for node 0x%p with ph 0x%p\n",
	    node, p));

	/*
	 * paranoid check
	 */
	if ((ph == DI_PROM_HANDLE_NIL) || (node == DI_NODE_NIL)) {
		errno = EINVAL;
		return (DI_PROM_PROP_NIL);
	}

	if (di_nodeid(node) != DI_PROM_NODEID) {
		errno = ENXIO;
		return (DI_PROM_PROP_NIL);
	}

	/*
	 * synchronize access to prom file descriptor
	 */
	(void) mutex_lock(&p->lock);

	/*
	 * look for next property
	 */
	prom_prop = di_prom_prop_found(ph, DI_NODE(node)->nodeid, prom_prop);

	(void) mutex_unlock(&p->lock);

	return (prom_prop);
}

char *
di_prom_prop_name(di_prom_prop_t prom_prop)
{
	/*
	 * paranoid check
	 */
	if (prom_prop == DI_PROM_PROP_NIL) {
		errno = EINVAL;
		return (NULL);
	}

	return (((struct di_prom_prop *)prom_prop)->name);
}

int
di_prom_prop_data(di_prom_prop_t prom_prop, uchar_t **prom_prop_data)
{
	/*
	 * paranoid check
	 */
	if (prom_prop == DI_PROM_PROP_NIL) {
		errno = EINVAL;
		return (NULL);
	}

	*prom_prop_data = ((struct di_prom_prop *)prom_prop)->data;

	return (((struct di_prom_prop *)prom_prop)->len);
}

/*
 * Internal library interface for locating the property
 *    Returns length if found, -1 if prop doesn't exist.
 */
static struct di_prom_prop *
di_prom_prop_lookup_common(di_prom_handle_t ph, di_node_t node,
	const char *prom_prop_name)
{
	struct openpromio *opp;
	struct di_prom_prop *prop;
	struct di_prom_handle *p = (struct di_prom_handle *)ph;

	/*
	 * paranoid check
	 */
	if ((ph == DI_PROM_HANDLE_NIL) || (node == DI_NODE_NIL)) {
		errno = EINVAL;
		return (NULL);
	}

	if (di_nodeid(node) != DI_PROM_NODEID) {
		errno = ENXIO;
		return (NULL);
	}

	opp = &p->oppbuf.opp;

	(void) mutex_lock(&p->lock);

	opp->oprom_size = sizeof (int);
	opp->oprom_node = DI_NODE(node)->nodeid;
	if (ioctl(p->fd, OPROMSETNODEID, opp) < 0) {
		errno = ENXIO;
		DPRINTF((DI_ERR, "*** Nodeid not found 0x%x\n",
		    DI_NODE(node)->nodeid));
		(void) mutex_unlock(&p->lock);
		return (NULL);
	}

	/*
	 * get property length
	 */
	bzero(opp, OBP_MAXBUF);
	opp->oprom_size = OBP_MAXPROPLEN;
	(void) strcpy(opp->oprom_array, prom_prop_name);

	if ((ioctl(p->fd, OPROMGETPROPLEN, opp) < 0) ||
	    (opp->oprom_len == -1)) {
		/* no such property */
		(void) mutex_unlock(&p->lock);
		return (NULL);
	}

	/*
	 * Prom property found. Allocate struct for storing prop
	 */
	if ((prop = malloc(sizeof (struct di_prom_prop))) == NULL) {
		(void) mutex_unlock(&p->lock);
		return (NULL);
	}
	prop->name = NULL;	/* we don't need the name */
	prop->len = opp->oprom_len;

	if (prop->len == 0) {	/* boolean property */
		prop->data = NULL;
		prop->next = p->list;
		p->list = prop;
		(void) mutex_unlock(&p->lock);
		return (prop);
	}

	/*
	 * retrieve the property value
	 */
	bzero(opp, OBP_MAXBUF);
	opp->oprom_size = OBP_MAXPROPLEN;
	(void) strcpy(opp->oprom_array, prom_prop_name);

	if ((ioctl(p->fd, OPROMGETPROP, opp) < 0) ||
	    (opp->oprom_size == (uint_t)-1)) {
		/* error retrieving property value */
		(void) mutex_unlock(&p->lock);
		free(prop);
		return (NULL);
	}

	/*
	 * make a copy of the property value, stick in ph->list
	 */
	if ((prop->data = malloc(prop->len)) == NULL) {
		(void) mutex_unlock(&p->lock);
		free(prop);
		return (NULL);
	}

	bcopy(opp->oprom_array, prop->data, prop->len);

	prop->next = p->list;
	p->list = prop;
	(void) mutex_unlock(&p->lock);

	return (prop);
}

int
di_prom_prop_lookup_ints(di_prom_handle_t ph, di_node_t node,
	const char *prom_prop_name, int **prom_prop_data)
{
	int len;
	struct di_prom_prop *prop;

	prop = di_prom_prop_lookup_common(ph, node, prom_prop_name);

	if (prop == NULL) {
		*prom_prop_data = NULL;
		return (-1);
	}

	if (prop->len == 0) {	/* boolean property */
		*prom_prop_data = NULL;
		return (0);
	}

	len = di_prop_decode_common((void *)&prop->data, prop->len,
	    DI_PROP_TYPE_INT, 1);
	*prom_prop_data = (int *)((void *)prop->data);

	return (len);
}

int
di_prom_prop_lookup_strings(di_prom_handle_t ph, di_node_t node,
	const char *prom_prop_name, char **prom_prop_data)
{
	int len;
	struct di_prom_prop *prop;

	prop = di_prom_prop_lookup_common(ph, node, prom_prop_name);

	if (prop == NULL) {
		*prom_prop_data = NULL;
		return (-1);
	}

	if (prop->len == 0) {	/* boolean property */
		*prom_prop_data = NULL;
		return (0);
	}

	/*
	 * Fix an openprom bug (OBP string not NULL terminated).
	 * XXX This should really be fixed in promif.
	 */
	if (((char *)prop->data)[prop->len - 1] != '\0') {
		uchar_t *tmp;
		prop->len++;
		if ((tmp = realloc(prop->data, prop->len)) == NULL)
			return (-1);

		prop->data = tmp;
		((char *)prop->data)[prop->len - 1] = '\0';
		DPRINTF((DI_INFO, "OBP string not NULL terminated: "
		    "node=%s, prop=%s, val=%s\n",
		    di_node_name(node), prom_prop_name, prop->data));
	}

	len = di_prop_decode_common((void *)&prop->data, prop->len,
	    DI_PROP_TYPE_STRING, 1);
	*prom_prop_data = (char *)prop->data;

	return (len);
}

int
di_prom_prop_lookup_bytes(di_prom_handle_t ph, di_node_t node,
	const char *prom_prop_name, uchar_t **prom_prop_data)
{
	int len;
	struct di_prom_prop *prop;

	prop = di_prom_prop_lookup_common(ph, node, prom_prop_name);

	if (prop == NULL) {
		*prom_prop_data = NULL;
		return (-1);
	}

	if (prop->len == 0) {	/* boolean property */
		*prom_prop_data = NULL;
		return (0);
	}

	len = di_prop_decode_common((void *)&prop->data, prop->len,
	    DI_PROP_TYPE_BYTE, 1);
	*prom_prop_data = prop->data;

	return (len);
}

/*
 * returns an allocated array through <prop_data> only when its count > 0
 * and the number of entries (count) as the function return value;
 * use di_slot_names_free() to free the array
 */
int
di_prop_slot_names(di_prop_t prop, di_slot_name_t **prop_data)
{
	int rawlen, count;
	uchar_t *rawdata;
	char *nm = di_prop_name(prop);

	if (nm == NULL || strcmp(DI_PROP_SLOT_NAMES, nm) != 0)
		goto ERROUT;

	rawlen = di_prop_rawdata(prop, &rawdata);
	if (rawlen <= 0 || rawdata == NULL)
		goto ERROUT;

	count = di_slot_names_decode(rawdata, rawlen, prop_data);
	if (count < 0 || *prop_data == NULL)
		goto ERROUT;

	return (count);
	/*NOTREACHED*/
ERROUT:
	errno = EFAULT;
	*prop_data = NULL;
	return (-1);
}

int
di_prop_lookup_slot_names(dev_t dev, di_node_t node,
    di_slot_name_t **prop_data)
{
	di_prop_t prop;

	/*
	 * change this if and when DI_PROP_TYPE_COMPOSITE is implemented
	 * and slot-names is properly flagged as such
	 */
	if ((prop = di_prop_find(dev, node, DI_PROP_SLOT_NAMES)) ==
	    DI_PROP_NIL) {
		*prop_data = NULL;
		return (-1);
	}

	return (di_prop_slot_names(prop, (void *)prop_data));
}

/*
 * returns an allocated array through <prop_data> only when its count > 0
 * and the number of entries (count) as the function return value;
 * use di_slot_names_free() to free the array
 */
int
di_prom_prop_slot_names(di_prom_prop_t prom_prop, di_slot_name_t **prop_data)
{
	int rawlen, count;
	uchar_t *rawdata;

	rawlen = di_prom_prop_data(prom_prop, &rawdata);
	if (rawlen <= 0 || rawdata == NULL)
		goto ERROUT;

	count = di_slot_names_decode(rawdata, rawlen, prop_data);
	if (count < 0 || *prop_data == NULL)
		goto ERROUT;

	return (count);
	/*NOTREACHED*/
ERROUT:
	errno = EFAULT;
	*prop_data = NULL;
	return (-1);
}

int
di_prom_prop_lookup_slot_names(di_prom_handle_t ph, di_node_t node,
    di_slot_name_t **prop_data)
{
	struct di_prom_prop *prom_prop;

	prom_prop = di_prom_prop_lookup_common(ph, node, DI_PROP_SLOT_NAMES);
	if (prom_prop == NULL) {
		*prop_data = NULL;
		return (-1);
	}

	return (di_prom_prop_slot_names(prom_prop, prop_data));
}

di_lnode_t
di_link_to_lnode(di_link_t link, uint_t endpoint)
{
	struct di_all *di_all;

	if ((link == DI_LINK_NIL) ||
	    ((endpoint != DI_LINK_SRC) && (endpoint != DI_LINK_TGT))) {
		errno = EINVAL;
		return (DI_LNODE_NIL);
	}

	di_all = DI_ALL((caddr_t)link - DI_LINK(link)->self);

	if (endpoint == DI_LINK_SRC) {
		return (DI_LNODE((caddr_t)di_all + DI_LINK(link)->src_lnode));
	} else {
		return (DI_LNODE((caddr_t)di_all + DI_LINK(link)->tgt_lnode));
	}
	/* NOTREACHED */
}

char *
di_lnode_name(di_lnode_t lnode)
{
	return (di_driver_name(di_lnode_devinfo(lnode)));
}

di_node_t
di_lnode_devinfo(di_lnode_t lnode)
{
	struct di_all *di_all;

	di_all = DI_ALL((caddr_t)lnode - DI_LNODE(lnode)->self);
	return (DI_NODE((caddr_t)di_all + DI_LNODE(lnode)->node));
}

int
di_lnode_devt(di_lnode_t lnode, dev_t *devt)
{
	if ((lnode == DI_LNODE_NIL) || (devt == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	if ((DI_LNODE(lnode)->dev_major == (major_t)-1) &&
	    (DI_LNODE(lnode)->dev_minor == (minor_t)-1))
		return (-1);

	*devt = makedev(DI_LNODE(lnode)->dev_major, DI_LNODE(lnode)->dev_minor);
	return (0);
}

int
di_link_spectype(di_link_t link)
{
	return (DI_LINK(link)->spec_type);
}

void
di_minor_private_set(di_minor_t minor, void *data)
{
	DI_MINOR(minor)->user_private_data = (uintptr_t)data;
}

void *
di_minor_private_get(di_minor_t minor)
{
	return ((void *)(uintptr_t)DI_MINOR(minor)->user_private_data);
}

void
di_node_private_set(di_node_t node, void *data)
{
	DI_NODE(node)->user_private_data = (uintptr_t)data;
}

void *
di_node_private_get(di_node_t node)
{
	return ((void *)(uintptr_t)DI_NODE(node)->user_private_data);
}

void
di_path_private_set(di_path_t path, void *data)
{
	DI_PATH(path)->user_private_data = (uintptr_t)data;
}

void *
di_path_private_get(di_path_t path)
{
	return ((void *)(uintptr_t)DI_PATH(path)->user_private_data);
}

void
di_lnode_private_set(di_lnode_t lnode, void *data)
{
	DI_LNODE(lnode)->user_private_data = (uintptr_t)data;
}

void *
di_lnode_private_get(di_lnode_t lnode)
{
	return ((void *)(uintptr_t)DI_LNODE(lnode)->user_private_data);
}

void
di_link_private_set(di_link_t link, void *data)
{
	DI_LINK(link)->user_private_data = (uintptr_t)data;
}

void *
di_link_private_get(di_link_t link)
{
	return ((void *)(uintptr_t)DI_LINK(link)->user_private_data);
}

di_lnode_t
di_lnode_next(di_node_t node, di_lnode_t lnode)
{
	struct di_all *di_all;

	/*
	 * paranoid error checking
	 */
	if (node == DI_NODE_NIL) {
		errno = EINVAL;
		return (DI_LNODE_NIL);
	}

	di_all = DI_ALL((caddr_t)node - DI_NODE(node)->self);

	if (lnode == DI_NODE_NIL) {
		if (DI_NODE(node)->lnodes != NULL)
			return (DI_LNODE((caddr_t)di_all +
			    DI_NODE(node)->lnodes));
	} else {
		if (DI_LNODE(lnode)->node_next != NULL)
			return (DI_LNODE((caddr_t)di_all +
			    DI_LNODE(lnode)->node_next));
	}

	if (DINFOLYR & DI_ALL(di_all)->command)
		errno = ENXIO;
	else
		errno = ENOTSUP;

	return (DI_LNODE_NIL);
}

di_link_t
di_link_next_by_node(di_node_t node, di_link_t link, uint_t endpoint)
{
	struct di_all *di_all;

	/*
	 * paranoid error checking
	 */
	if ((node == DI_NODE_NIL) ||
	    ((endpoint != DI_LINK_SRC) && (endpoint != DI_LINK_TGT))) {
		errno = EINVAL;
		return (DI_LINK_NIL);
	}

	di_all = DI_ALL((caddr_t)node - DI_NODE(node)->self);

	if (endpoint == DI_LINK_SRC) {
		if (link == DI_LINK_NIL) {
			if (DI_NODE(node)->src_links != NULL)
				return (DI_LINK((caddr_t)di_all +
				    DI_NODE(node)->src_links));
		} else {
			if (DI_LINK(link)->src_node_next != NULL)
				return (DI_LINK((caddr_t)di_all +
				    DI_LINK(link)->src_node_next));
		}
	} else {
		if (link == DI_LINK_NIL) {
			if (DI_NODE(node)->tgt_links != NULL)
				return (DI_LINK((caddr_t)di_all +
				    DI_NODE(node)->tgt_links));
		} else {
			if (DI_LINK(link)->tgt_node_next != NULL)
				return (DI_LINK((caddr_t)di_all +
				    DI_LINK(link)->tgt_node_next));
		}
	}

	if (DINFOLYR & DI_ALL(di_all)->command)
		errno = ENXIO;
	else
		errno = ENOTSUP;

	return (DI_LINK_NIL);
}

di_link_t
di_link_next_by_lnode(di_lnode_t lnode, di_link_t link, uint_t endpoint)
{
	struct di_all *di_all;

	/*
	 * paranoid error checking
	 */
	if ((lnode == DI_LNODE_NIL) ||
	    ((endpoint != DI_LINK_SRC) && (endpoint != DI_LINK_TGT))) {
		errno = EINVAL;
		return (DI_LINK_NIL);
	}

	di_all = DI_ALL((caddr_t)lnode - DI_LNODE(lnode)->self);

	if (endpoint == DI_LINK_SRC) {
		if (link == DI_LINK_NIL) {
			if (DI_LNODE(lnode)->link_out == NULL)
				return (DI_LINK_NIL);
			return (DI_LINK((caddr_t)di_all +
			    DI_LNODE(lnode)->link_out));
		} else {
			if (DI_LINK(link)->src_link_next == NULL)
				return (DI_LINK_NIL);
			return (DI_LINK((caddr_t)di_all +
			    DI_LINK(link)->src_link_next));
		}
	} else {
		if (link == DI_LINK_NIL) {
			if (DI_LNODE(lnode)->link_in == NULL)
				return (DI_LINK_NIL);
			return (DI_LINK((caddr_t)di_all +
			    DI_LNODE(lnode)->link_in));
		} else {
			if (DI_LINK(link)->tgt_link_next == NULL)
				return (DI_LINK_NIL);
			return (DI_LINK((caddr_t)di_all +
			    DI_LINK(link)->tgt_link_next));
		}
	}
	/* NOTREACHED */
}

/*
 * Internal library function:
 *   Invoke callback for each link data on the link list of first node
 *   on node_list headp, and place children of first node on the list.
 *
 *   This is similar to walk_one_node, except we only walk in child
 *   first mode.
 */
static void
walk_one_link(struct node_list **headp, uint_t ep,
    void *arg, int (*callback)(di_link_t link, void *arg))
{
	int		action = DI_WALK_CONTINUE;
	di_link_t	link = DI_LINK_NIL;
	di_node_t	node = (*headp)->node;

	while ((link = di_link_next_by_node(node, link, ep)) != DI_LINK_NIL) {
		action = callback(link, arg);
		if (action == DI_WALK_TERMINATE) {
			break;
		}
	}

	update_node_list(action, DI_WALK_LINKGEN, headp);
}

int
di_walk_link(di_node_t root, uint_t flag, uint_t endpoint, void *arg,
    int (*link_callback)(di_link_t link, void *arg))
{
	struct node_list  *head;	/* node_list for tree walk */

#ifdef DEBUG
	char *devfspath = di_devfs_path(root);
	DPRINTF((DI_INFO, "walking %s link data under %s\n",
	    (endpoint == DI_LINK_SRC) ? "src" : "tgt", devfspath));
	di_devfs_path_free(devfspath);
#endif

	/*
	 * paranoid error checking
	 */
	if ((root == DI_NODE_NIL) || (link_callback == NULL) || (flag != 0) ||
	    ((endpoint != DI_LINK_SRC) && (endpoint != DI_LINK_TGT))) {
		errno = EINVAL;
		return (-1);
	}

	if ((head = malloc(sizeof (struct node_list))) == NULL) {
		DPRINTF((DI_ERR, "malloc of node_list failed\n"));
		return (-1);
	}

	head->next = NULL;
	head->node = root;

	DPRINTF((DI_INFO, "Start link data walking from node %s\n",
	    di_node_name(root)));

	while (head != NULL)
		walk_one_link(&head, endpoint, arg, link_callback);

	return (0);
}

/*
 * Internal library function:
 *   Invoke callback for each link data on the link list of first node
 *   on node_list headp, and place children of first node on the list.
 *
 *   This is similar to walk_one_node, except we only walk in child
 *   first mode.
 */
static void
walk_one_lnode(struct node_list **headp, void *arg,
    int (*callback)(di_lnode_t lnode, void *arg))
{
	int		action = DI_WALK_CONTINUE;
	di_lnode_t	lnode = DI_LNODE_NIL;
	di_node_t	node = (*headp)->node;

	while ((lnode = di_lnode_next(node, lnode)) != DI_LNODE_NIL) {
		action = callback(lnode, arg);
		if (action == DI_WALK_TERMINATE) {
			break;
		}
	}

	update_node_list(action, DI_WALK_LINKGEN, headp);
}

int
di_walk_lnode(di_node_t root, uint_t flag, void *arg,
    int (*lnode_callback)(di_lnode_t lnode, void *arg))
{
	struct node_list  *head;	/* node_list for tree walk */

#ifdef DEBUG
	char *devfspath = di_devfs_path(root);
	DPRINTF((DI_INFO, "walking lnode data under %s\n", devfspath));
	di_devfs_path_free(devfspath);
#endif

	/*
	 * paranoid error checking
	 */
	if ((root == DI_NODE_NIL) || (lnode_callback == NULL) || (flag != 0)) {
		errno = EINVAL;
		return (-1);
	}

	if ((head = malloc(sizeof (struct node_list))) == NULL) {
		DPRINTF((DI_ERR, "malloc of node_list failed\n"));
		return (-1);
	}

	head->next = NULL;
	head->node = root;

	DPRINTF((DI_INFO, "Start lnode data walking from node %s\n",
	    di_node_name(root)));

	while (head != NULL)
		walk_one_lnode(&head, arg, lnode_callback);

	return (0);
}

static char *
alias_to_curr(di_node_t anynode, char *devfspath, di_node_t *nodep)
{
	caddr_t		pa;
	struct di_all	*all;
	struct di_alias *di_alias;
	di_node_t	node;
	char		*curr;
	char		*cp;
	char		*alias;
	di_off_t off;
	char buf[MAXPATHLEN];

	*nodep = NULL;

	if (anynode == DI_NODE_NIL || devfspath == NULL)
		return (NULL);

	pa = (caddr_t)anynode - DI_NODE(anynode)->self;
	all = DI_ALL(pa);

	di_alias = NULL;
	for (off = all->aliases; off > 0; off = di_alias->next) {
		di_alias = DI_ALIAS(pa + off);
		alias = di_alias->alias;
		if (strncmp(devfspath, alias, strlen(alias)) == 0) {
			cp = devfspath + strlen(alias);
			node = DI_NODE(pa + di_alias->curroff);
			assert(node != DI_NODE_NIL);
			if (*cp == '\0') {
				*nodep = node;
				return (NULL);
			} else if (*cp == '/') {
				curr = di_devfs_path(node);
				(void) snprintf(buf, sizeof (buf), "%s%s",
				    curr, cp);
				di_devfs_path_free(curr);
				curr = strdup(buf);
				return (curr);
			}
		}
	}

	return (NULL);
}

static di_node_t
di_lookup_node_impl(di_node_t root, char *devfspath)
{
	struct di_all *dap;
	di_node_t node;
	char *copy, *slash, *pname, *paddr;

	/*
	 * Path must be absolute and musn't have duplicate slashes
	 */
	if (*devfspath != '/' || strstr(devfspath, "//")) {
		DPRINTF((DI_ERR, "Invalid path: %s\n", devfspath));
		return (DI_NODE_NIL);
	}

	if (root == DI_NODE_NIL) {
		DPRINTF((DI_ERR, "root node is DI_NODE_NIL\n"));
		return (DI_NODE_NIL);
	}

	dap = DI_ALL((caddr_t)root - DI_NODE(root)->self);
	if (strcmp(dap->root_path, "/") != 0) {
		DPRINTF((DI_ERR, "snapshot root not / : %s\n", dap->root_path));
		return (DI_NODE_NIL);
	}

	if ((copy = strdup(devfspath)) == NULL) {
		DPRINTF((DI_ERR, "strdup failed on: %s\n", devfspath));
		return (DI_NODE_NIL);
	}

	for (slash = copy, node = root; slash; ) {

		/*
		 * Handle devfspath = "/" case as well as trailing '/'
		 */
		if (*(slash + 1) == '\0')
			break;

		/*
		 * More path-components exist. Deal with the next one
		 */
		pname = slash + 1;
		node = di_child_node(node);

		if (slash = strchr(pname, '/'))
			*slash = '\0';
		if (paddr = strchr(pname, '@'))
			*paddr++ = '\0';

		for (; node != DI_NODE_NIL; node = di_sibling_node(node)) {
			char *name, *baddr;

			name = di_node_name(node);
			baddr = di_bus_addr(node);

			if (strcmp(pname, name) != 0)
				continue;

			/*
			 * Mappings between a "path-address" and bus-addr
			 *
			 *	paddr		baddr
			 *	---------------------
			 *	NULL		NULL
			 *	NULL		""
			 *	""		N/A	(invalid paddr)
			 */
			if (paddr && baddr && strcmp(paddr, baddr) == 0)
				break;
			if (paddr == NULL && (baddr == NULL || *baddr == '\0'))
				break;
		}

		/*
		 * No nodes in the sibling list or there was no match
		 */
		if (node == DI_NODE_NIL) {
			DPRINTF((DI_ERR, "%s@%s: no node\n", pname, paddr));
			free(copy);
			return (DI_NODE_NIL);
		}
	}

	assert(node != DI_NODE_NIL);
	free(copy);
	return (node);
}

di_node_t
di_lookup_node(di_node_t root, char *devfspath)
{
	di_node_t	node;
	char		*curr;

	node = di_lookup_node_impl(root, devfspath);
	if (node != DI_NODE_NIL) {
		return (node);
	}

	/* node is already set to DI_NODE_NIL */
	curr = alias_to_curr(root, devfspath, &node);
	if (curr == NULL) {
		/* node may or may node be DI_NODE_NIL */
		return (node);
	}

	node = di_lookup_node_impl(root, curr);

	free(curr);

	return (node);
}

char *
di_alias2curr(di_node_t anynode, char *alias)
{
	di_node_t currnode = DI_NODE_NIL;
	char *curr;

	if (anynode == DI_NODE_NIL || alias == NULL)
		return (NULL);

	curr = alias_to_curr(anynode, alias, &currnode);
	if (curr == NULL && currnode != DI_NODE_NIL) {
		return (di_devfs_path(currnode));
	} else if (curr == NULL) {
		return (strdup(alias));
	}

	return (curr);
}

di_path_t
di_lookup_path(di_node_t root, char *devfspath)
{
	di_node_t	phci_node;
	di_path_t	path = DI_PATH_NIL;
	char		*copy, *lastslash;
	char		*pname, *paddr;
	char		*path_name, *path_addr;

	if ((copy = strdup(devfspath)) == NULL) {
		DPRINTF((DI_ERR, "strdup failed on: %s\n", devfspath));
		return (DI_NODE_NIL);
	}

	if ((lastslash = strrchr(copy, '/')) == NULL) {
		DPRINTF((DI_ERR, "failed to find component: %s\n", devfspath));
		goto out;
	}

	/* stop at pHCI and find the node for the phci */
	*lastslash = '\0';
	phci_node = di_lookup_node(root, copy);
	if (phci_node == NULL) {
		DPRINTF((DI_ERR, "failed to find component: %s\n", devfspath));
		goto out;
	}

	/* set up pname and paddr for last component */
	pname = lastslash + 1;
	if ((paddr = strchr(pname, '@')) == NULL) {
		DPRINTF((DI_ERR, "failed to find unit-addr: %s\n", devfspath));
		goto out;
	}
	*paddr++ = '\0';

	/* walk paths below phci looking for match */
	for (path = di_path_phci_next_path(phci_node, DI_PATH_NIL);
	    path != DI_PATH_NIL;
	    path = di_path_phci_next_path(phci_node, path)) {

		/* get name@addr of path */
		path_name = di_path_node_name(path);
		path_addr = di_path_bus_addr(path);
		if ((path_name == NULL) || (path_addr == NULL))
			continue;

		/* break on match */
		if ((strcmp(pname, path_name) == 0) &&
		    (strcmp(paddr, path_addr) == 0))
			break;
	}

out:	free(copy);
	return (path);
}

static char *
msglevel2str(di_debug_t msglevel)
{
	switch (msglevel) {
		case DI_ERR:
			return ("ERROR");
		case DI_INFO:
			return ("Info");
		case DI_TRACE:
			return ("Trace");
		case DI_TRACE1:
			return ("Trace1");
		case DI_TRACE2:
			return ("Trace2");
		default:
			return ("UNKNOWN");
	}
}

void
dprint(di_debug_t msglevel, const char *fmt, ...)
{
	va_list	ap;
	char	*estr;

	if (di_debug <= DI_QUIET)
		return;

	if (di_debug < msglevel)
		return;

	estr = msglevel2str(msglevel);

	assert(estr);

	va_start(ap, fmt);

	(void) fprintf(stderr, "libdevinfo[%lu]: %s: ",
	    (ulong_t)getpid(), estr);
	(void) vfprintf(stderr, fmt, ap);

	va_end(ap);
}

/* end of devinfo.c */
