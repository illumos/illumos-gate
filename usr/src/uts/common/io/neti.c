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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/kmem.h>
#include <sys/rwlock.h>
#include <sys/errno.h>
#include <sys/queue.h>
#include <inet/common.h>
#include <inet/led.h>
#include <inet/ip.h>
#include <sys/modctl.h>
#include <sys/neti.h>


static krwlock_t netlock;
static LIST_HEAD(netd_listhead, net_data) netd_head; /* list of net_data_t */

static void net_init();
static net_data_t net_find(const char *protocol);

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modlmisc = {
	&mod_miscops,		/* drv_modops */
	"netinfo module 1.0",	/* drv_linkinfo */
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* ml_rev */
	&modlmisc,		/* ml_linkage */
	NULL
};

/*
 * Module entry points.
 */
int
_init(void)
{
	net_init();
	return (mod_install(&modlinkage));
}


int
_fini(void)
{

	return (mod_remove(&modlinkage));
}


int
_info(struct modinfo *modinfop)
{

	return (mod_info(&modlinkage, modinfop));
}


static void
net_init()
{

	rw_init(&netlock, NULL, RW_DRIVER, NULL);
	LIST_INIT(&netd_head);
}


static net_data_t
net_find(const char *protocol)
{
	struct net_data *n;

	ASSERT(protocol != NULL);

	LIST_FOREACH(n, &netd_head, netd_list) {
		ASSERT(n->netd_info.neti_protocol != NULL);
		if (strcmp(n->netd_info.neti_protocol, protocol) == 0) {
			break;
		}
	}

	return (n);
}


net_data_t
net_register(const net_info_t *info)
{
	struct net_data *n, *new;

	ASSERT(info != NULL);

	new = kmem_alloc(sizeof (*new), KM_SLEEP);
	new->netd_refcnt = 0;
	new->netd_hooks = NULL;
	new->netd_info = *info;

	rw_enter(&netlock, RW_WRITER);
	n = net_find(info->neti_protocol);
	if (n != NULL) {
		rw_exit(&netlock);
		kmem_free(new, sizeof (*new));
		return (NULL);
	}

	if (LIST_EMPTY(&netd_head))
		LIST_INSERT_HEAD(&netd_head, new, netd_list);
	else
		LIST_INSERT_AFTER(LIST_FIRST(&netd_head), new, netd_list);

	rw_exit(&netlock);
	return (new);
}


int
net_unregister(net_data_t info)
{

	ASSERT(info != NULL);

	rw_enter(&netlock, RW_WRITER);
	if (info->netd_refcnt != 0) {
		rw_exit(&netlock);
		return (EBUSY);
	}

	LIST_REMOVE(info, netd_list);

	rw_exit(&netlock);

	kmem_free(info, sizeof (struct net_data));
	return (0);
}


net_data_t
net_lookup(const char *protocol)
{
	struct net_data *n;

	ASSERT(protocol != NULL);

	rw_enter(&netlock, RW_READER);
	n = net_find(protocol);
	if (n != NULL)
		atomic_add_32((uint_t *)&n->netd_refcnt, 1);
	rw_exit(&netlock);
	return (n);
}

/*
 * Note: the man page specifies "returns -1 if the value passed in is unknown
 * to this framework".  We are not doing a lookup in this function, just a
 * simply add to the netd_refcnt of the net_data_t passed in, so -1 is never a
 * return value.
 */
int
net_release(net_data_t info)
{
	ASSERT(info != NULL);

	rw_enter(&netlock, RW_READER);
	ASSERT(info->netd_refcnt > 0);
	atomic_add_32((uint_t *)&info->netd_refcnt, -1);

	/* net_release has been called too many times */
	if (info->netd_refcnt < 0) {
		rw_exit(&netlock);
		return (1);
	}
	rw_exit(&netlock);
	return (0);
}


net_data_t
net_walk(net_data_t info)
{
	struct net_data *n = NULL;
	boolean_t found = B_FALSE;

	if (info == NULL)
		found = B_TRUE;

	rw_enter(&netlock, RW_READER);
	LIST_FOREACH(n, &netd_head, netd_list) {
		if (found)
			break;
		if (n == info)
			found = B_TRUE;
	}

	if (info != NULL) {
		ASSERT(info->netd_refcnt > 0);
		atomic_add_32((uint_t *)&info->netd_refcnt, -1);
	}
	if (n != NULL)
		atomic_add_32((uint_t *)&n->netd_refcnt, 1);

	rw_exit(&netlock);
	return (n);
}


/*
 * Public accessor functions
 */
int
net_getifname(net_data_t info, phy_if_t phy_ifdata,
    char *buffer, const size_t buflen)
{

	ASSERT(info != NULL);

	return (info->netd_info.neti_getifname(phy_ifdata, buffer, buflen));
}


int
net_getmtu(net_data_t info, phy_if_t phy_ifdata, lif_if_t ifdata)
{

	ASSERT(info != NULL);

	return (info->netd_info.neti_getmtu(phy_ifdata, ifdata));
}


int
net_getpmtuenabled(net_data_t info)
{

	ASSERT(info != NULL);

	return (info->netd_info.neti_getpmtuenabled());
}


int
net_getlifaddr(net_data_t info, phy_if_t phy_ifdata, lif_if_t ifdata,
    int nelem, net_ifaddr_t type[], void *storage)
{

	ASSERT(info != NULL);

	return (info->netd_info.neti_getlifaddr(phy_ifdata, ifdata,
	    nelem, type, storage));
}


phy_if_t
net_phygetnext(net_data_t info, phy_if_t phy_ifdata)
{

	ASSERT(info != NULL);

	return (info->netd_info.neti_phygetnext(phy_ifdata));
}


phy_if_t
net_phylookup(net_data_t info, const char *name)
{

	ASSERT(info != NULL);

	return (info->netd_info.neti_phylookup(name));
}


lif_if_t
net_lifgetnext(net_data_t info, phy_if_t ifidx, lif_if_t ifdata)
{

	ASSERT(info != NULL);

	return (info->netd_info.neti_lifgetnext(ifidx, ifdata));
}


int
net_inject(net_data_t info, inject_t style, net_inject_t *packet)
{

	ASSERT(info != NULL);

	return (info->netd_info.neti_inject(style, packet));
}


phy_if_t
net_routeto(net_data_t info, struct sockaddr *address)
{

	ASSERT(info != NULL);

	return (info->netd_info.neti_routeto(address));
}


int
net_ispartialchecksum(net_data_t info, mblk_t *mp)
{

	ASSERT(info != NULL);
	ASSERT(mp != NULL);

	return (info->netd_info.neti_ispartialchecksum(mp));
}


int
net_isvalidchecksum(net_data_t info, mblk_t *mp)
{

	ASSERT(info != NULL);
	ASSERT(mp != NULL);

	return (info->netd_info.neti_isvalidchecksum(mp));
}


/*
 * Hooks related functions
 */

/*
 * Function:	net_register_family
 * Returns:	int - 0 = Succ, Else = Fail
 * Parameters:	info(I) - protocol
 *		hf(I) - family pointer
 *
 * Call hook_family_add to register family
 */
int
net_register_family(net_data_t info, hook_family_t *hf)
{
	hook_family_int_t *hfi;

	ASSERT(info != NULL);
	ASSERT(hf != NULL);

	if (info->netd_hooks != NULL)
		return (EEXIST);

	hfi = hook_family_add(hf);
	if (hfi == NULL)
		return (EEXIST);

	info->netd_hooks = hfi;
	return (0);
}


/*
 * Function:	net_unregister_family
 * Returns:	int - transparent value, explained by caller
 * Parameters:	info(I) - protocol
 *		hf(I) - family pointer
 *
 * Call hook_family_remove to unregister family
 */
int
net_unregister_family(net_data_t info, hook_family_t *hf)
{
	int ret;

	ASSERT(info != NULL);
	ASSERT(hf != NULL);

	if (info->netd_hooks == NULL)
		return (ENXIO);

	if (strcmp(info->netd_hooks->hfi_family.hf_name,
	    hf->hf_name) != 0)
		return (EINVAL);

	ret = hook_family_remove(info->netd_hooks);
	if (ret == 0)
		info->netd_hooks = NULL;

	return (ret);
}


/*
 * Function:	net_register_event
 * Returns:	internal event pointer - NULL = Fail
 * Parameters:	info(I) - protocol
 *		he(I) - event pointer
 *
 * Call hook_event_add to register event on specific family
 * 	Internal event pointer is returned so caller can get
 * 	handle to run hooks
 */
hook_event_token_t
net_register_event(net_data_t info, hook_event_t *he)
{
	hook_event_int_t *hei;

	ASSERT(info != NULL);
	ASSERT(he != NULL);

	if (info->netd_hooks == NULL)
		return (NULL);

	hei = hook_event_add(info->netd_hooks, he);
	return ((hook_event_token_t)hei);
}


/*
 * Function:	net_unregister_event
 * Returns:	int - transparent value, explained by caller
 * Parameters:	info(I) - protocol
 *		he(I) - event pointer
 *
 * Call hook_event_remove to unregister event on specific family
 */
int
net_unregister_event(net_data_t info, hook_event_t *he)
{

	ASSERT(info != NULL);
	ASSERT(he != NULL);

	if (info->netd_hooks == NULL)
		return (ENXIO);

	return (hook_event_remove(info->netd_hooks, he));
}


/*
 * Function:	net_register_hook
 * Returns:	int - transparent value, explained by caller
 * Parameters:	info(I) - protocol
 *		event(I) - event name
 *		h(I) - hook pointer
 *
 * Call hook_register to add hook on specific family/event
 */
int
net_register_hook(net_data_t info, char *event, hook_t *h)
{

	ASSERT(info != NULL);
	ASSERT(event != NULL);
	ASSERT(h != NULL);

	if (info->netd_hooks == NULL)
		return (ENXIO);

	return (hook_register(info->netd_hooks, event, h));
}


/*
 * Function:	net_unregister_hook
 * Returns:	int - transparent value, explained by caller
 * Parameters:	info(I) - protocol
 *		event(I) - event name
 *		h(I) - hook pointer
 *
 * Call hook_unregister to remove hook on specific family/event
 */
int
net_unregister_hook(net_data_t info, char *event, hook_t *h)
{

	ASSERT(info != NULL);
	ASSERT(event != NULL);
	ASSERT(h != NULL);

	if (info->netd_hooks == NULL)
		return (ENXIO);

	return (hook_unregister(info->netd_hooks, event, h));
}
