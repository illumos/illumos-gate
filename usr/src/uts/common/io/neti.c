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


static void net_init();
static void net_fini();
static net_data_t net_find(const char *protocol, neti_stack_t *ns);
static void *neti_stack_init(netstackid_t stackid, netstack_t *ns);
static void neti_stack_fini(netstackid_t stackid, void *arg);

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
	int error;

	net_init();
	error = mod_install(&modlinkage);
	if (error != 0)
		net_fini();

	return (error);
}


int
_fini(void)
{
	int error;

	error = mod_remove(&modlinkage);
	if (error == 0)
		net_fini();

	return (error);
}


int
_info(struct modinfo *modinfop)
{

	return (mod_info(&modlinkage, modinfop));
}


static void
net_init()
{
	/*
	 * We want to be informed each time a stack is created or
	 * destroyed in the kernel.
	 */
	netstack_register(NS_NETI, neti_stack_init, NULL,
	    neti_stack_fini);
}

static void
net_fini()
{
	netstack_unregister(NS_NETI);
}


/*
 * Initialize the neti stack instance.
 */
/*ARGSUSED*/
static void *
neti_stack_init(netstackid_t stackid, netstack_t *ns)
{
	neti_stack_t	*nts;

#ifdef NS_DEBUG
	printf("neti_stack_init(stack %d)\n", stackid);
#endif

	nts = (neti_stack_t *)kmem_zalloc(sizeof (*nts), KM_SLEEP);
	nts->nts_netstack = ns;

	rw_init(&nts->nts_netlock, NULL, RW_DRIVER, NULL);
	LIST_INIT(&nts->nts_netd_head);

	return (nts);
}


/*
 * Free the neti stack instance.
 */
/*ARGSUSED*/
static void
neti_stack_fini(netstackid_t stackid, void *arg)
{
	neti_stack_t	*nts = (neti_stack_t *)arg;
#ifdef NS_DEBUG
	printf("neti_stack_fini(%p, stack %d)\n", arg, stackid);
#endif
	rw_destroy(&nts->nts_netlock);
	kmem_free(nts, sizeof (*nts));
}


static net_data_t
net_find(const char *protocol, neti_stack_t *nts)
{
	struct net_data *n;

	ASSERT(protocol != NULL);

	LIST_FOREACH(n, &nts->nts_netd_head, netd_list) {
		ASSERT(n->netd_info.neti_protocol != NULL);
		if (strcmp(n->netd_info.neti_protocol, protocol) == 0) {
			break;
		}
	}

	return (n);
}

net_data_t
net_register(const net_info_t *info, netstackid_t nsid)
{
	netstack_t *ns;
	net_data_t nd;

	ns = netstack_find_by_stackid(nsid);
	nd = net_register_impl(info, ns);
	netstack_rele(ns);

	return (nd);
}

net_data_t
net_register_impl(const net_info_t *info, netstack_t *ns)
{
	struct net_data *n, *new;
	struct neti_stack *nts;

	ASSERT(info != NULL);
	ASSERT(ns != NULL);

	nts = ns->netstack_neti;

	new = kmem_alloc(sizeof (*new), KM_SLEEP);
	new->netd_refcnt = 0;
	new->netd_hooks = NULL;
	new->netd_info = *info;
	new->netd_netstack = ns;

	rw_enter(&nts->nts_netlock, RW_WRITER);
	n = net_find(info->neti_protocol, nts);
	if (n != NULL) {
		rw_exit(&nts->nts_netlock);
		kmem_free(new, sizeof (*new));
		return (NULL);
	}

	if (LIST_EMPTY(&nts->nts_netd_head))
		LIST_INSERT_HEAD(&nts->nts_netd_head, new, netd_list);
	else
		LIST_INSERT_AFTER(LIST_FIRST(&nts->nts_netd_head),
		    new, netd_list);

	rw_exit(&nts->nts_netlock);
	return (new);
}


int
net_unregister(net_data_t info)
{
	struct netstack *ns;
	struct neti_stack *nts;
	ns = info->netd_netstack;
	nts = ns->netstack_neti;

	ASSERT(info != NULL);

	rw_enter(&nts->nts_netlock, RW_WRITER);
	if (info->netd_refcnt != 0) {
		rw_exit(&nts->nts_netlock);
		return (EBUSY);
	}

	LIST_REMOVE(info, netd_list);

	rw_exit(&nts->nts_netlock);

	kmem_free(info, sizeof (struct net_data));
	return (0);
}

net_data_t
net_lookup(const char *protocol, netstackid_t nsid)
{
	netstack_t *ns;
	net_data_t nd;

	ns = netstack_find_by_stackid(nsid);
	nd = net_lookup_impl(protocol, ns);
	netstack_rele(ns);

	return (nd);
}

net_data_t
net_lookup_impl(const char *protocol, netstack_t *ns)
{
	struct net_data *n;
	struct neti_stack *nts;

	ASSERT(protocol != NULL);
	ASSERT(ns != NULL);

	nts = ns->netstack_neti;

	rw_enter(&nts->nts_netlock, RW_READER);
	n = net_find(protocol, nts);
	if (n != NULL)
		atomic_add_32((uint_t *)&n->netd_refcnt, 1);
	rw_exit(&nts->nts_netlock);
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
	struct netstack *ns;
	struct neti_stack *nts;

	ns = info->netd_netstack;
	nts = ns->netstack_neti;

	ASSERT(info != NULL);

	rw_enter(&nts->nts_netlock, RW_READER);
	ASSERT(info->netd_refcnt > 0);
	atomic_add_32((uint_t *)&info->netd_refcnt, -1);

	/* net_release has been called too many times */
	if (info->netd_refcnt < 0) {
		rw_exit(&nts->nts_netlock);
		return (1);
	}
	rw_exit(&nts->nts_netlock);

	return (0);
}

net_data_t
net_walk(net_data_t info, netstackid_t nsid)
{
	netstack_t *ns;
	net_data_t nd;

	ns = netstack_find_by_stackid(nsid);
	nd = net_walk_impl(info, ns);
	netstack_rele(ns);

	return (nd);
}

net_data_t
net_walk_impl(net_data_t info, netstack_t *ns)
{
	struct net_data *n = NULL;
	boolean_t found = B_FALSE;
	struct neti_stack *nts;

	ASSERT(ns != NULL);

	nts = ns->netstack_neti;

	if (info == NULL)
		found = B_TRUE;

	rw_enter(&nts->nts_netlock, RW_READER);
	LIST_FOREACH(n, &nts->nts_netd_head, netd_list) {
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

	rw_exit(&nts->nts_netlock);

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

	return (info->netd_info.neti_getifname(phy_ifdata, buffer, buflen,
	    info->netd_netstack));
}


int
net_getmtu(net_data_t info, phy_if_t phy_ifdata, lif_if_t ifdata)
{

	ASSERT(info != NULL);

	return (info->netd_info.neti_getmtu(phy_ifdata, ifdata,
	    info->netd_netstack));
}


int
net_getpmtuenabled(net_data_t info)
{

	ASSERT(info != NULL);

	return (info->netd_info.neti_getpmtuenabled(info->netd_netstack));
}


int
net_getlifaddr(net_data_t info, phy_if_t phy_ifdata, lif_if_t ifdata,
    int nelem, net_ifaddr_t type[], void *storage)
{

	ASSERT(info != NULL);

	return (info->netd_info.neti_getlifaddr(phy_ifdata, ifdata,
	    nelem, type, storage, info->netd_netstack));
}


phy_if_t
net_phygetnext(net_data_t info, phy_if_t phy_ifdata)
{

	ASSERT(info != NULL);

	return (info->netd_info.neti_phygetnext(phy_ifdata,
	    info->netd_netstack));
}


phy_if_t
net_phylookup(net_data_t info, const char *name)
{

	ASSERT(info != NULL);

	return (info->netd_info.neti_phylookup(name, info->netd_netstack));
}


lif_if_t
net_lifgetnext(net_data_t info, phy_if_t ifidx, lif_if_t ifdata)
{

	ASSERT(info != NULL);

	return (info->netd_info.neti_lifgetnext(ifidx, ifdata,
	    info->netd_netstack));
}


int
net_inject(net_data_t info, inject_t style, net_inject_t *packet)
{

	ASSERT(info != NULL);

	return (info->netd_info.neti_inject(style, packet,
	    info->netd_netstack));
}


phy_if_t
net_routeto(net_data_t info, struct sockaddr *address)
{

	ASSERT(info != NULL);

	return (info->netd_info.neti_routeto(address, info->netd_netstack));
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

	hfi = hook_family_add(hf, info->netd_netstack->netstack_hook);
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
