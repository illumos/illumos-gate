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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/kmem.h>
#include <sys/rwlock.h>
#include <sys/errno.h>
#include <sys/queue.h>
#include <inet/common.h>
#include <inet/led.h>
#include <inet/ip.h>
#include <sys/neti.h>
#include <sys/zone.h>

static net_handle_t net_find(const char *protocol, neti_stack_t *ns);

static net_handle_t
net_find(const char *protocol, neti_stack_t *nts)
{
	struct net_data *n;

	ASSERT(protocol != NULL);
	ASSERT(nts != NULL);

	LIST_FOREACH(n, &nts->nts_netd_head, netd_list) {
		ASSERT(n->netd_info.netp_name != NULL);
		/*
		 * If they're trying to find a protocol that is being
		 * shutdown, just ignore it..
		 */
		if (n->netd_condemned != 0)
			continue;
		if (strcmp(n->netd_info.netp_name, protocol) == 0) {
			break;
		}
	}

	return (n);
}

net_handle_t
net_protocol_register(netid_t id, const net_protocol_t *info)
{
	struct net_data *n, *new;
	neti_stack_t *nts;

	ASSERT(info != NULL);

	nts = net_getnetistackbyid(id);
	if (nts == NULL)
		return (NULL);

	new = kmem_alloc(sizeof (*new), KM_SLEEP);
	new->netd_refcnt = 1;
	new->netd_hooks = NULL;
	new->netd_info = *info;
	new->netd_stack = nts;
	new->netd_condemned = 0;

	mutex_enter(&nts->nts_lock);
	n = net_find(info->netp_name, nts);
	if (n != NULL) {
		mutex_exit(&nts->nts_lock);
		kmem_free(new, sizeof (*new));
		return (NULL);
	}

	if (LIST_EMPTY(&nts->nts_netd_head)) {
		LIST_INSERT_HEAD(&nts->nts_netd_head, new, netd_list);
	} else {
		LIST_INSERT_AFTER(LIST_FIRST(&nts->nts_netd_head),
		    new, netd_list);
	}
	mutex_exit(&nts->nts_lock);

	return (new);
}

int
net_protocol_unregister(net_handle_t info)
{
	neti_stack_t *nts;

	ASSERT(info != NULL);

	nts = info->netd_stack;
	ASSERT(nts != NULL);

	mutex_enter(&nts->nts_lock);
	LIST_REMOVE(info, netd_list);
	info->netd_stack = NULL;
	mutex_exit(&nts->nts_lock);

	(void) net_protocol_release(info);

	return (0);
}

net_handle_t
net_protocol_lookup(netid_t netid, const char *protocol)
{
	neti_stack_t *nts;
	net_handle_t nd;

	ASSERT(protocol != NULL);

	nts = net_getnetistackbyid(netid);
	if (nts == NULL)
		return (NULL);

	mutex_enter(&nts->nts_lock);
	nd = net_find(protocol, nts);
	if (nd != NULL)
		atomic_inc_32((uint_t *)&nd->netd_refcnt);
	mutex_exit(&nts->nts_lock);
	return (nd);
}

/*
 * Note: the man page specifies "returns -1 if the value passed in is unknown
 * to this framework".  We are not doing a lookup in this function, just a
 * simply add to the netd_refcnt of the net_handle_t passed in, so -1 is never a
 * return value.
 */
int
net_protocol_release(net_handle_t info)
{

	ASSERT(info->netd_refcnt > 0);
	/*
	 * Is this safe? No hold on nts_lock? Consider that if the caller
	 * of net_protocol_release() is going to free this structure then
	 * it is now the only owner (refcnt==1) and it will have been
	 * removed from the nts_netd_head list on the neti_stack_t from a
	 * call to net_protocol_unregister already, so it is thus an orphan.
	 */
	if (atomic_dec_32_nv((uint_t *)&info->netd_refcnt) == 0) {
		ASSERT(info->netd_hooks == NULL);
		ASSERT(info->netd_stack == NULL);
		kmem_free(info, sizeof (struct net_data));
	}

	return (0);
}

net_handle_t
net_protocol_walk(netid_t netid, net_handle_t info)
{
	struct net_data *n = NULL;
	boolean_t found = B_FALSE;
	neti_stack_t *nts;

	nts = net_getnetistackbyid(netid);
	ASSERT(nts != NULL);

	if (info == NULL)
		found = B_TRUE;

	mutex_enter(&nts->nts_lock);
	LIST_FOREACH(n, &nts->nts_netd_head, netd_list) {
		if (found) {
			/*
			 * We are only interested in finding protocols that
			 * are not in some sort of shutdown state.  There is
			 * no need to check for netd_stack==NULL because
			 * that implies it is no longer on this list.
			 */
			if (n->netd_condemned == 0)
				continue;
			break;
		}

		if (n == info)
			found = B_TRUE;
	}

	if (info != NULL)
		(void) net_protocol_release(info);

	if (n != NULL)
		atomic_inc_32((uint_t *)&n->netd_refcnt);

	mutex_exit(&nts->nts_lock);

	return (n);
}

/*
 * Public accessor functions
 */
int
net_getifname(net_handle_t info, phy_if_t nic, char *buffer,
    const size_t buflen)
{

	ASSERT(info != NULL);

	if (info->netd_condemned != 0 || info->netd_stack == NULL)
		return (-1);

	return (info->netd_info.netp_getifname(info, nic, buffer, buflen));
}

int
net_getmtu(net_handle_t info, phy_if_t nic, lif_if_t ifdata)
{

	ASSERT(info != NULL);

	if (info->netd_condemned != 0 || info->netd_stack == NULL)
		return (-1);

	return (info->netd_info.netp_getmtu(info, nic, ifdata));
}

int
net_getpmtuenabled(net_handle_t info)
{

	ASSERT(info != NULL);

	if (info->netd_condemned != 0 || info->netd_stack == NULL)
		return (-1);

	return (info->netd_info.netp_getpmtuenabled(info));
}

int
net_getlifaddr(net_handle_t info, phy_if_t nic, lif_if_t ifdata,
    int nelem, net_ifaddr_t type[], void *storage)
{

	ASSERT(info != NULL);

	if (info->netd_condemned != 0 || info->netd_stack == NULL)
		return (-1);

	return (info->netd_info.netp_getlifaddr(info, nic, ifdata,
	    nelem, type, storage));
}

int
net_getlifzone(net_handle_t info, phy_if_t phy_ifdata, lif_if_t ifdata,
    zoneid_t *zoneid)
{
	ASSERT(info != NULL);

	if (info->netd_condemned != 0 || info->netd_stack == NULL)
		return (-1);

	return (info->netd_info.neti_getlifzone(info, phy_ifdata, ifdata,
	    zoneid));
}

int
net_getlifflags(net_handle_t info, phy_if_t phy_ifdata, lif_if_t ifdata,
    uint64_t *flags)
{
	ASSERT(info != NULL);

	if (info->netd_condemned != 0 || info->netd_stack == NULL)
		return (-1);

	return (info->netd_info.neti_getlifflags(info, phy_ifdata, ifdata,
	    flags));
}

phy_if_t
net_phygetnext(net_handle_t info, phy_if_t nic)
{

	ASSERT(info != NULL);

	if (info->netd_condemned != 0 || info->netd_stack == NULL)
		return ((phy_if_t)-1);

	return (info->netd_info.netp_phygetnext(info, nic));
}

phy_if_t
net_phylookup(net_handle_t info, const char *name)
{

	ASSERT(info != NULL);

	if (info->netd_condemned != 0 || info->netd_stack == NULL)
		return ((phy_if_t)-1);

	return (info->netd_info.netp_phylookup(info, name));
}

lif_if_t
net_lifgetnext(net_handle_t info, phy_if_t ifidx, lif_if_t ifdata)
{

	ASSERT(info != NULL);

	if (info->netd_condemned != 0 || info->netd_stack == NULL)
		return ((lif_if_t)-1);

	return (info->netd_info.netp_lifgetnext(info, ifidx, ifdata));
}

int
net_inject(net_handle_t info, inject_t style, net_inject_t *packet)
{

	ASSERT(info != NULL);

	if (info->netd_condemned != 0 || info->netd_stack == NULL)
		return (-1);

	return (info->netd_info.netp_inject(info, style, packet));
}

phy_if_t
net_routeto(net_handle_t info, struct sockaddr *address, struct sockaddr *next)
{

	ASSERT(info != NULL);

	if (info->netd_condemned != 0 || info->netd_stack == NULL)
		return ((phy_if_t)-1);

	return (info->netd_info.netp_routeto(info, address, next));
}

int
net_ispartialchecksum(net_handle_t info, mblk_t *mp)
{

	ASSERT(info != NULL);
	ASSERT(mp != NULL);

	if (info->netd_condemned != 0 || info->netd_stack == NULL)
		return (-1);

	return (info->netd_info.netp_ispartialchecksum(info, mp));
}

int
net_isvalidchecksum(net_handle_t info, mblk_t *mp)
{

	ASSERT(info != NULL);
	ASSERT(mp != NULL);

	if (info->netd_condemned != 0 || info->netd_stack == NULL)
		return (-1);

	return (info->netd_info.netp_isvalidchecksum(info, mp));
}

/*
 * Hooks related functions
 */

/*
 * Function:	net_family_register
 * Returns:	int - 0 = Succ, Else = Fail
 * Parameters:	info(I) - protocol
 *		hf(I) - family pointer
 *
 * Call hook_family_add to register family
 *
 * There is no need to bump netd_refcnt in the two functions
 * net_family_register and net_family_unregister because the caller of these
 * two functions is assumed to "own" a reference on 'info' via an earlier
 * call to net_protocol_register().  Thus the owner is expected to do a
 * call to net_protocol_unregister() after having done a
 * net_family_unregister() to make sure things are properly cleaned up.
 * Passing a pointer to info->netd_hooks into hook_family_add is required
 * so that this can be set before the notify functions are called. If this
 * does not happen, the notify function may do something that seems fine,
 * like add a notify function to the family but cause a panic because
 * netd_hooks is NULL when we get to hook_family_notify_register.
 */
int
net_family_register(net_handle_t info, hook_family_t *hf)
{
	netstack_t *ns;

	ASSERT(info != NULL);
	ASSERT(hf != NULL);

	if (info->netd_condemned != 0 || info->netd_stack == NULL)
		return (ESHUTDOWN);

	if (info->netd_hooks != NULL)
		return (EEXIST);

	ns = info->netd_stack->nts_netstack;
	ASSERT(ns != NULL);
	if (hook_family_add(hf, ns->netstack_hook,
	    (void **)&info->netd_hooks) == NULL)
		return (EEXIST);

	return (0);
}

/*
 * Function:	net_family_unregister
 * Returns:	int - transparent value, explained by caller
 * Parameters:	info(I) - protocol
 *		hf(I) - family pointer
 *
 * Call hook_family_remove to unregister family
 */
int
net_family_unregister(net_handle_t info, hook_family_t *hf)
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

int
net_family_shutdown(net_handle_t info, hook_family_t *hf)
{

	ASSERT(info != NULL);
	ASSERT(hf != NULL);

	if (info->netd_hooks == NULL)
		return (ENXIO);

	if (strcmp(info->netd_hooks->hfi_family.hf_name,
	    hf->hf_name) != 0)
		return (EINVAL);

	return (hook_family_shutdown(info->netd_hooks));
}

/*
 * Function:	net_event_register
 * Returns:	internal event pointer - NULL = Fail
 * Parameters:	info(I) - protocol
 *		he(I) - event pointer
 *
 * Call hook_event_add to register event on specific family
 * 	Internal event pointer is returned so caller can get
 * 	handle to run hooks
 */
hook_event_token_t
net_event_register(net_handle_t info, hook_event_t *he)
{
	hook_event_int_t *hei;

	ASSERT(info != NULL);
	ASSERT(he != NULL);

	if (info->netd_hooks == NULL || info->netd_condemned != 0 ||
	    info->netd_stack == NULL)
		return (NULL);

	hei = hook_event_add(info->netd_hooks, he);
	return ((hook_event_token_t)hei);
}

/*
 * Function:	net_event_unregister
 * Returns:	int - transparent value, explained by caller
 * Parameters:	info(I) - protocol
 *		he(I) - event pointer
 *
 * Call hook_event_remove to unregister event on specific family
 */
int
net_event_unregister(net_handle_t info, hook_event_t *he)
{

	ASSERT(info != NULL);
	ASSERT(he != NULL);

	if (info->netd_hooks == NULL)
		return (ENXIO);

	return (hook_event_remove(info->netd_hooks, he));
}

int
net_event_shutdown(net_handle_t info, hook_event_t *he)
{

	ASSERT(info != NULL);
	ASSERT(he != NULL);

	if (info->netd_hooks == NULL)
		return (ENXIO);

	return (hook_event_shutdown(info->netd_hooks, he));
}

/*
 * Function:	net_hook_register
 * Returns:	int - transparent value, explained by caller
 * Parameters:	info(I) - protocol
 *		event(I) - event name
 *		h(I) - hook pointer
 *
 * Call hook_register to add hook on specific family/event
 */
int
net_hook_register(net_handle_t info, char *event, hook_t *h)
{

	ASSERT(info != NULL);
	ASSERT(event != NULL);
	ASSERT(h != NULL);

	if (info->netd_condemned != 0 || info->netd_stack == NULL)
		return (ESHUTDOWN);

	if (info->netd_hooks == NULL)
		return (ENXIO);

	return (hook_register(info->netd_hooks, event, h));
}

/*
 * Function:	net_hook_unregister
 * Returns:	int - transparent value, explained by caller
 * Parameters:	info(I) - protocol
 *		event(I) - event name
 *		h(I) - hook pointer
 *
 * Call hook_unregister to remove hook on specific family/event
 */
int
net_hook_unregister(net_handle_t info, char *event, hook_t *h)
{

	ASSERT(info != NULL);
	ASSERT(event != NULL);
	ASSERT(h != NULL);

	if (info->netd_hooks == NULL)
		return (ENXIO);

	return (hook_unregister(info->netd_hooks, event, h));
}

netid_t
net_getnetid(net_handle_t netd)
{

	if (netd->netd_stack == NULL)
		return (-1);
	return (netd->netd_stack->nts_id);
}

net_inject_t *
net_inject_alloc(const int version)
{
	net_inject_t *ni;

	ni = kmem_zalloc(sizeof (*ni), KM_NOSLEEP);
	if (ni == NULL)
		return (NULL);

	ni->ni_version = version;
	return (ni);
}

void
net_inject_free(net_inject_t *ni)
{
	kmem_free(ni, sizeof (*ni));
}

kstat_t *
net_kstat_create(netid_t netid, char *module, int instance, char *name,
    char *class, uchar_t type, ulong_t ndata, uchar_t ks_flag)
{
	netstackid_t stackid = net_getnetstackidbynetid(netid);

	if (stackid == -1)
		return (NULL);

	return (kstat_create_netstack(module, instance, name, class, type,
	    ndata, ks_flag, stackid));
}

void
net_kstat_delete(netid_t netid, kstat_t *ks)
{
	netstackid_t stackid = net_getnetstackidbynetid(netid);

	if (stackid != -1)
		kstat_delete_netstack(ks, stackid);
}

int
net_event_notify_register(net_handle_t family, char *event,
    hook_notify_fn_t callback, void *arg)
{
	int error;

	if (family->netd_condemned != 0 || family->netd_stack == NULL)
		return (ESHUTDOWN);

	error = hook_event_notify_register(family->netd_hooks, event,
	    callback, arg);

	return (error);
}

int
net_event_notify_unregister(net_handle_t family, char *event,
    hook_notify_fn_t callback)
{
	int error;

	error = hook_event_notify_unregister(family->netd_hooks, event,
	    callback);

	return (error);
}

int
net_protocol_notify_register(net_handle_t family, hook_notify_fn_t callback,
    void *arg)
{
	int error;

	if (family->netd_condemned != 0 || family->netd_stack == NULL)
		return (ESHUTDOWN);

	error = hook_family_notify_register(family->netd_hooks, callback,
	    arg);

	return (error);
}

int
net_protocol_notify_unregister(net_handle_t family, hook_notify_fn_t callback)
{
	int error;

	error = hook_family_notify_unregister(family->netd_hooks, callback);

	return (error);
}
