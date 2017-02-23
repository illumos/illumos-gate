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
 * Copyright 2000, 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * fc_ops.c: Framework generic fcode ops
 */
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/fcode.h>
#include <sys/ddi_implfuncs.h>
#include <sys/ndi_impldefs.h>
#include <sys/ethernet.h>

static int fco_new_device(dev_info_t *, fco_handle_t, fc_ci_t *);
static int fco_finish_device(dev_info_t *, fco_handle_t, fc_ci_t *);
static int fco_create_property(dev_info_t *, fco_handle_t, fc_ci_t *);

static int fco_validate(dev_info_t *, fco_handle_t, fc_ci_t *);
static int fco_invalidate(dev_info_t *, fco_handle_t, fc_ci_t *);
static int fco_exit(dev_info_t *, fco_handle_t, fc_ci_t *);

static int fco_getproplen(dev_info_t *, fco_handle_t, fc_ci_t *);
static int fco_getprop(dev_info_t *, fco_handle_t, fc_ci_t *);

static int fco_ap_phandle(dev_info_t *, fco_handle_t, fc_ci_t *);
static int fco_child(dev_info_t *, fco_handle_t, fc_ci_t *);
static int fco_peer(dev_info_t *, fco_handle_t, fc_ci_t *);
static int fco_parent(dev_info_t *, fco_handle_t, fc_ci_t *);
static int fco_alloc_phandle(dev_info_t *, fco_handle_t, fc_ci_t *);

static int fco_local_ether_addr(dev_info_t *, fco_handle_t, fc_ci_t *);

struct fc_ops_v {
	char *svc_name;
	fc_ops_t *f;
};

static struct fc_ops_v fov[] = {
	{	"open",			fc_fail_op},
	{	"close",		fc_fail_op},
	{	"$find",		fc_fail_op},
	{	"encode-unit",		fc_fail_op},
	{	"decode-unit",		fc_fail_op},
	{	FC_GET_MY_PROPLEN,	fco_getproplen},
	{	FC_GET_MY_PROP,		fco_getprop},
	{	FC_GET_PKG_PROPLEN,	fco_getproplen},
	{	FC_GET_PKG_PROP,	fco_getprop},
	{	FC_GET_IN_PROPLEN,	fco_getproplen},
	{	FC_GET_IN_PROP,		fco_getprop},
	{	FC_NEW_DEVICE,		fco_new_device},
	{	FC_FINISH_DEVICE,	fco_finish_device},
	{	FC_CREATE_PROPERTY,	fco_create_property},
	{	FC_AP_PHANDLE,		fco_ap_phandle},
	{	"child",		fco_child},
	{	"peer",			fco_peer},
	{	FC_PARENT,		fco_parent},
	{	FC_ALLOC_PHANDLE,	fco_alloc_phandle},
	{	FC_SVC_VALIDATE,	fco_validate},
	{	FC_SVC_INVALIDATE,	fco_invalidate},
	{	FC_SVC_EXIT,		fco_exit},
	{	"local-ether-addr",	fco_local_ether_addr},
	{	NULL,			NULL}
};

/*
 * Allocate a handle for the ops function .. our handle is a resource list
 * Return the handle to our caller, so it can call us with it when we need it.
 */
/*ARGSUSED*/
fco_handle_t
fc_ops_alloc_handle(dev_info_t *ap, dev_info_t *child,
    void *fcode, size_t fcode_size, char *unit_address, void *bus_args)
{
	fco_handle_t rp;
	char *up;

	rp = kmem_zalloc(sizeof (struct fc_resource_list), KM_SLEEP);
	rp->next_handle = NULL;		/* nobody is downstream */
	rp->ap = ap;
	rp->child = child;
	rp->fcode = fcode;
	rp->fcode_size = fcode_size;
	if (unit_address) {
		up = kmem_zalloc(strlen(unit_address) + 1, KM_SLEEP);
		(void) strcpy(up, unit_address);
		rp->unit_address = up;
	}
	rp->bus_args = NULL;		/* generic module has no bus args */
	fc_phandle_table_alloc(fc_handle_to_phandle_head(rp));

	(void) fc_dip_to_phandle(fc_handle_to_phandle_head(rp), ap);

	/*
	 * Create our copy of the device tree.
	 */
	fc_create_device_tree(ap, &rp->dtree);
	return (rp);
}

/*
 * Free any resources associated with this handle.
 */
void
fc_ops_free_handle(fco_handle_t rp)
{
	struct fc_resource *ip, *np;

	if (rp->unit_address)
		kmem_free(rp->unit_address, strlen(rp->unit_address) + 1);

	if (rp->dtree)
		fc_remove_device_tree(&rp->dtree);

	fc_phandle_table_free(fc_handle_to_phandle_head(rp));

	for (ip = rp->head; ip != NULL; ip = np) {
		np = ip->next;
		switch (ip->type) {
		case RT_NODEID:
			impl_ddi_free_nodeid(ip->fc_nodeid_r);
			break;
		default:
			cmn_err(CE_CONT, "pci_fc_ops_free: "
			    "unknown resource type %d\n", ip->type);
			break;
		}
		fc_rem_resource(rp, ip);
		kmem_free(ip, sizeof (struct fc_resource));
	}
	kmem_free(rp, sizeof (struct fc_resource_list));
}

int
fc_ops(dev_info_t *ap, fco_handle_t handle, fc_ci_t *cp)
{
	struct fc_ops_v *pv;
	char *name = fc_cell2ptr(cp->svc_name);

	for (pv = fov; pv->svc_name != NULL; ++pv)
		if (strcmp(pv->svc_name, name) == 0)
			return (pv->f(ap, handle, cp));

	return (-1);
}

/*
 * The interpreter can't do get-inherited-property directly,
 * because we don't want to return a kernel address, so it
 * has to break up the request into a get-proplen and get-prop
 * call so it can allocate memory for the property and pass that
 * buffer in to get-prop.  The buffer should be 'suitably aligned'.
 *
 * XXX: We don't know the property type, so we can't return
 * prop-encoded arrays, which fortunately, isn't a problem
 * on big-endian machines.
 *
 * get-proplen has one result: proplen
 * proplen is returned as -1 if the propname doesn't exist and
 * as zero if the property is a boolean property.
 *
 * get-prop has one result: proplen, returned as -1 if propname doesn't exist.
 */

/*
 * fco_getproplen ( propname phandle -- proplen )
 */

/*ARGSUSED*/
static int
fco_getproplen(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	int proplen;
	int flags = 0;
	fc_phandle_t h;
	dev_info_t *dip;
	char *pnp;
	char propname[OBP_MAXPROPNAME];

	if (strstr(fc_cell2ptr(cp->svc_name), "inherited") == NULL)
		flags |= DDI_PROP_DONTPASS;

	if (fc_cell2int(cp->nargs) != 2)
		return (fc_syntax_error(cp, "nargs must be 2"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be > 0"));

	/*
	 * Make sure this is a handle we gave out ...
	 */
	h = fc_cell2phandle(fc_arg(cp, 0));
	if ((dip = fc_phandle_to_dip(fc_handle_to_phandle_head(rp), h)) == NULL)
		return (fc_priv_error(cp, "unknown handle"));

	/*
	 * XXX: We should care if the string is longer than OBP_MAXPROPNAME
	 */
	pnp = fc_cell2ptr(fc_arg(cp, 1));
	bzero(propname, OBP_MAXPROPNAME);
	if (copyinstr(pnp, propname, OBP_MAXPROPNAME - 1, NULL))
		return (fc_priv_error(cp, "EFAULT copying in propname"));

	if (ddi_getproplen(DDI_DEV_T_ANY, dip, flags, propname, &proplen))
		proplen = -1;

	fc_result(cp, 0) = fc_int2cell(proplen);
	cp->nresults = fc_int2cell(1);
	return (fc_success_op(ap, rp, cp));
}

/*
 * fco_getprop ( propname buffer phandle -- proplen )
 */

/*ARGSUSED*/
static int
fco_getprop(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	int proplen = -1;
	int flags = DDI_PROP_CANSLEEP;
	char *pnp, *bp;
	fc_phandle_t h;
	dev_info_t *dip;
	char propname[OBP_MAXPROPNAME];

	if (strstr(fc_cell2ptr(cp->svc_name), "inherited") == NULL)
		flags |= DDI_PROP_DONTPASS;

	if (fc_cell2int(cp->nargs) != 3)
		return (fc_syntax_error(cp, "nargs must be 3"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be > 0"));

	/*
	 * Make sure this is a handle we gave out ...
	 */
	h = fc_cell2phandle(fc_arg(cp, 0));
	if ((dip = fc_phandle_to_dip(fc_handle_to_phandle_head(rp), h)) == NULL)
		return (fc_priv_error(cp, "unknown handle"));

	/*
	 * XXX: We should care if the string is longer than OBP_MAXPROPNAME
	 */
	pnp = fc_cell2ptr(fc_arg(cp, 2));
	bzero(propname, OBP_MAXPROPNAME);
	if (copyinstr(pnp, propname, OBP_MAXPROPNAME - 1, NULL))
		return (fc_priv_error(cp, "EFAULT copying in propname"));

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, flags,
	    propname, (caddr_t)&bp, &proplen))
		proplen = -1;

	if (proplen > 0) {
		char *up = fc_cell2ptr(fc_arg(cp, 1));
		int error;

		error = copyout(bp, up, proplen);
		kmem_free(bp, proplen);
		if (error)
			return (fc_priv_error(cp, "EFAULT copying data out"));
	}

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = fc_int2cell(proplen);
	return (fc_success_op(ap, rp, cp));
}

static int
fco_ap_phandle(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	fc_phandle_t h;

	if (fc_cell2int(cp->nargs) != 0)
		return (fc_syntax_error(cp, "nargs must be 0"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be > 0"));

	FC_DEBUG1(9, CE_CONT, "fco_ap_phandle: Looking up ap dip %p\n", ap);

	h = fc_dip_to_phandle(fc_handle_to_phandle_head(rp), ap);
	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = fc_phandle2cell(h);
	return (fc_success_op(ap, rp, cp));
}

static int
fco_child(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	fc_phandle_t h;
	dev_info_t *dip;

	if (fc_cell2int(cp->nargs) != 1)
		return (fc_syntax_error(cp, "nargs must be 1"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be > 0"));

	/*
	 * Make sure this is a handle we gave out ...
	 */
	h = fc_cell2phandle(fc_arg(cp, 0));
	if ((dip = fc_phandle_to_dip(fc_handle_to_phandle_head(rp), h)) == NULL)
		return (fc_priv_error(cp, "unknown handle"));

	/*
	 * Find the child and if there is one, return it ...
	 */
	dip = ddi_get_child(dip);
	h = 0;
	if (dip != NULL)
		h = fc_dip_to_phandle(fc_handle_to_phandle_head(rp), dip);

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = fc_phandle2cell(h);
	return (fc_success_op(ap, rp, cp));
}

static int
fco_peer(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	fc_phandle_t h;
	dev_info_t *dip;

	if (fc_cell2int(cp->nargs) != 1)
		return (fc_syntax_error(cp, "nargs must be 1"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be > 0"));

	/*
	 * Make sure this is a handle we gave out ...
	 */
	h = fc_cell2phandle(fc_arg(cp, 0));
	if ((dip = fc_phandle_to_dip(fc_handle_to_phandle_head(rp), h)) == NULL)
		return (fc_priv_error(cp, "unknown handle"));

	/*
	 * Find the child and if there is one, return it ...
	 */
	dip = ddi_get_next_sibling(dip);
	h = 0;
	if (dip != NULL)
		h = fc_dip_to_phandle(fc_handle_to_phandle_head(rp), dip);

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = fc_phandle2cell(h);
	return (fc_success_op(ap, rp, cp));
}

static int
fco_parent(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	fc_phandle_t h;
	dev_info_t *dip;

	if (fc_cell2int(cp->nargs) != 1)
		return (fc_syntax_error(cp, "nargs must be 1"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be > 0"));

	/*
	 * Make sure this is a handle we gave out ...
	 */
	h = fc_cell2phandle(fc_arg(cp, 0));
	if ((dip = fc_phandle_to_dip(fc_handle_to_phandle_head(rp), h)) == NULL)
		return (fc_priv_error(cp, "unknown handle"));

	/*
	 * Find the parent and if there is one, return it ...
	 */
	dip = ddi_get_parent(dip);
	h = 0;
	if (dip != NULL)
		h = fc_dip_to_phandle(fc_handle_to_phandle_head(rp), dip);

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = fc_phandle2cell(h);
	return (fc_success_op(ap, rp, cp));
}

/*
 * Allocate a phandle ... we don't currently track the phandle.
 */
static int
fco_alloc_phandle(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	fc_phandle_t h;
	int n;
	struct fc_resource *ip;

	if (fc_cell2int(cp->nargs) != 0)
		return (fc_syntax_error(cp, "nargs must be 0"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be > 0"));

	if (impl_ddi_alloc_nodeid(&n))
		return (fc_priv_error(cp, "Can't allocate a nodeid"));

	/*
	 * Log the nodeid resource so we can release it later if we need to.
	 */
	ip = kmem_zalloc(sizeof (struct fc_resource), KM_SLEEP);
	ip->type = RT_NODEID;
	ip->fc_nodeid_r = n;
	fc_add_resource(rp, ip);

	h = (fc_phandle_t)n;

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = fc_phandle2cell(h);
	return (fc_success_op(ap, rp, cp));
}

static struct fc_resource *
find_nodeid_resource(fco_handle_t rp, int n)
{
	struct fc_resource *ip;

	fc_lock_resource_list(rp);
	for (ip = rp->head; ip != NULL; ip = ip->next) {
		if (ip->type != RT_NODEID)
			continue;
		if (ip->fc_nodeid_r == n)
			break;
	}
	fc_unlock_resource_list(rp);

	return (ip);
}

/*
 * fco_new_device ( name-cstr unit-addr-cstr parent.phandle phandle -- )
 */
static int
fco_new_device(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	fc_phandle_t ph, ch;
	dev_info_t *pdev, *cdev;
	char *s;
	int createmode = 0;
	char *unit_address = NULL;
	char nodename[OBP_MAXPROPNAME];

	if (fc_cell2int(cp->nargs) != 4)
		return (fc_syntax_error(cp, "nargs must be 4"));

	/*
	 * Make sure these are handles we gave out ... and we have
	 * a corresponding parent devinfo node.
	 */
	ph = fc_cell2phandle(fc_arg(cp, 1));
	pdev = fc_phandle_to_dip(fc_handle_to_phandle_head(rp), ph);
	if (pdev == NULL)
		return (fc_priv_error(cp, "unknown parent phandle"));

	ch = fc_cell2phandle(fc_arg(cp, 0));
	cdev = fc_phandle_to_dip(fc_handle_to_phandle_head(rp), ch);

	switch (rp->cdip_state) {

	case FC_CDIP_NOSTATE:
		/*
		 * The first child must be a child of the attachment point.
		 */
		if (pdev != ap)
			return (fc_priv_error(cp, "first child must be a "
			    "child of the attachment point"));

		/*
		 * If this bus has a config child, the first child must
		 * be the configuration child. Otherwise, the child must
		 * be a new (unknown) node.
		 */
		if (cdev != NULL) {
			if (rp->child != NULL) {
				if (cdev != rp->child)
					return (fc_priv_error(cp, "first "
					    "child must be the "
					    "configuration child"));
			} else {
				return (fc_priv_error(cp, "known child -- "
				    "unknown child expected"));
			}
		}
		break;

	case FC_CDIP_DONE:
		/*
		 * If we've already created the first child, this
		 * child must be unknown and the parent must be a known
		 * child of the attachment point.
		 */
		if (cdev)
			return (fc_priv_error(cp, "known child -- "
			    "unknown child expected"));
		if (fc_find_node(pdev, fc_handle_to_dtree(rp)) == NULL)
			return (fc_priv_error(cp, "parent is an unknown "
			    "child of the attachment point"));
		break;

	default:
		/*
		 * If we're in some other state, we shouldn't be here.
		 */
		return (fc_priv_error(cp, "bad node-creation state"));
		/* NOTREACHED */
	}

	/*
	 * Get the nodename and the unit address.
	 */
	s = fc_cell2ptr(fc_arg(cp, 3));
	bzero(nodename, OBP_MAXPROPNAME);
	if (copyinstr(s, nodename, OBP_MAXPROPNAME - 1, NULL))
		return (fc_priv_error(cp, "EFAULT copying in nodename"));

	s = fc_cell2ptr(fc_arg(cp, 2));
	unit_address = kmem_zalloc(OBP_MAXPATHLEN, KM_SLEEP);
	if (copyinstr(s, unit_address, OBP_MAXPATHLEN - 1, NULL)) {
		kmem_free(unit_address, OBP_MAXPATHLEN);
		return (fc_priv_error(cp, "EFAULT copying in unit address"));
	}

	/*
	 * If cdev is NULL, we have to create the child, otherwise, the
	 * child already exists and we're just merging properties into
	 * the existing node.  The node must be unbound.
	 */

	if (cdev == NULL)
		createmode = 1;

	if (createmode) {
		struct fc_resource *ip;
		int nodeid;
		/*
		 * Make sure 'ch' is a nodeid we gave the interpreter.
		 * It must be on our resource list.
		 */
		if ((ip = find_nodeid_resource(rp, (int)ch)) == NULL) {
			kmem_free(unit_address, OBP_MAXPATHLEN);
			return (fc_priv_error(cp, "Unknown phandle"));
		}

		/*
		 * Allocate a self-identifying, persistent node with
		 * the auto-free attribute.
		 */
		if (ndi_devi_alloc(pdev, nodename, DEVI_SID_NODEID, &cdev)) {
			kmem_free(unit_address, OBP_MAXPATHLEN);
			return (fc_priv_error(cp, "Can't create node"));
		}

		/*
		 * Free the nodeid we just allocated here, and use
		 * the one we handed in. Retain the attributes of
		 * the original SID nodetype.
		 */
		nodeid = ddi_get_nodeid(cdev);
		i_ndi_set_nodeid(cdev, (int)ch);
		impl_ddi_free_nodeid(nodeid);

		/*
		 * Remove nodeid 'ch' from our resource list, now that it
		 * will be managed by the ddi framework.
		 */
		fc_rem_resource(rp, ip);
		kmem_free(ip, sizeof (struct fc_resource));

	} else if (strcmp(ddi_node_name(cdev), nodename) != 0) {
		FC_DEBUG2(1, CE_CONT, "Changing <%s> nodename to <%s>\n",
		    ddi_node_name(cdev), nodename);
		if (ndi_devi_set_nodename(cdev, nodename, 0)) {
			kmem_free(unit_address, OBP_MAXPATHLEN);
			return (fc_priv_error(cp, "Can't set ndi nodename"));
		}
	}

	if (fc_ndi_prop_update(DDI_DEV_T_NONE, cdev, "name",
	    (uchar_t *)nodename, strlen(nodename) + 1)) {
		kmem_free(unit_address, OBP_MAXPATHLEN);
		if (createmode)
			(void) ndi_devi_free(cdev);
		return (fc_priv_error(cp, "Can't create name property"));
	}

	/*
	 * Add the dip->phandle translation to our list of known phandles.
	 */
	fc_add_dip_to_phandle(fc_handle_to_phandle_head(rp), cdev, ch);

	/*
	 * Add the new node to our copy of the subtree.
	 */
	fc_add_child(cdev, pdev, fc_handle_to_dtree(rp));

	rp->cdip = cdev;
	rp->cdip_state = FC_CDIP_STARTED;

	kmem_free(unit_address, OBP_MAXPATHLEN);
	cp->nresults = fc_int2cell(0);
	return (fc_success_op(ap, rp, cp));
}

/*
 * fco_finish_device ( phandle -- )
 */
static int
fco_finish_device(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	fc_phandle_t h;
	dev_info_t *cdev;

	if (fc_cell2int(cp->nargs) != 1)
		return (fc_syntax_error(cp, "nargs must be 1"));

	if (rp->cdip_state != FC_CDIP_STARTED)
		return (fc_priv_error(cp, "bad node-creation state"));

	h = fc_cell2phandle(fc_arg(cp, 0));
	cdev = fc_phandle_to_dip(fc_handle_to_phandle_head(rp), h);
	if (cdev != rp->cdip)
		return (fc_priv_error(cp, "bad phandle"));

	/*
	 * We don't want to online children of the attachment point.
	 * We'll 'config' them online later.
	 *
	 * XXX - APA - I've changed this a bit.  The only time we don't
	 * want to bind the device is if the parent is the attachment point
	 * and the device is the same as the device that was passed to
	 * the interpreter.  We assume the configurator will do the binding.
	 */
	if ((ddi_get_parent(cdev) == ap) && (cdev == rp->child)) {
		FC_DEBUG2(5, CE_CONT, "fc_finish_device: "
		    "*not* binding <%s> dip %p\n", ddi_node_name(cdev), cdev);
	} else {
		FC_DEBUG2(5, CE_CONT, "fc_finish_device: binding <%s> dip %p\n",
		    ddi_node_name(cdev), cdev);

		(void) ndi_devi_bind_driver(cdev, 0);
	}

	rp->cdip_state = FC_CDIP_DONE;
	cp->nresults = fc_int2cell(0);
	return (fc_success_op(ap, rp, cp));
}

/*
 * fco_create_property ( propname-cstr buf len phandle -- )
 */
static int
fco_create_property(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	char *buf, *bp, *pnp;
	size_t len;
	fc_phandle_t h;
	dev_info_t *dev;
	int error;
	char propname[OBP_MAXPROPNAME];

	if (fc_cell2int(cp->nargs) != 4)
		return (fc_syntax_error(cp, "nargs must be 4"));

	h = fc_cell2phandle(fc_arg(cp, 0));
	len = fc_cell2size(fc_arg(cp, 1));
	bp = fc_cell2ptr(fc_arg(cp, 2));
	pnp = fc_cell2ptr(fc_arg(cp, 3));

	dev = fc_phandle_to_dip(fc_handle_to_phandle_head(rp), h);
	if (dev == NULL)
		return (fc_priv_error(cp, "bad phandle"));

	bzero(propname, OBP_MAXPROPNAME);
	if (copyinstr(pnp, propname, OBP_MAXPROPNAME - 1, NULL))
		return (fc_priv_error(cp, "EFAULT copying in propname"));

	buf = NULL;
	if (len != 0) {
		buf = kmem_zalloc(len, KM_SLEEP);
		if (copyin(bp, buf, len)) {
			kmem_free(buf, len);
			return (fc_priv_error(cp, "EFAULT copying in propval"));
		}
	}

	/*
	 * check for propname: 'name' ... we don't allow it
	 * by changed here.  It has to be specified when the node
	 * is created.
	 */
	if (strcmp(propname, "name") == 0) {
		char *n = ddi_node_name(dev);

		if (len == 0)
			return (fc_priv_error(cp, "setting <name> to NULL"));
		if ((len < (strlen(n) + 1)) || (strcmp(n, buf) != 0)) {
			kmem_free(buf, len);
			return (fc_priv_error(cp, "changing <name> property"));
		}
		/*
		 * Since we're not changing the value, and we already created
		 * the 'name' property when we created the node ...
		 */
		kmem_free(buf, len);
		cp->nresults = fc_int2cell(0);
		return (fc_success_op(ap, rp, cp));
	}

	error = fc_ndi_prop_update(DDI_DEV_T_NONE, dev, propname,
	    (uchar_t *)buf, len);

	if (len != 0)
		kmem_free(buf, len);

	if (error)
		return (fc_priv_error(cp, "Can't create property"));

	cp->nresults = fc_int2cell(0);
	return (fc_success_op(ap, rp, cp));
}

/*
 * Make sure any in-progress activity is completed,
 * and for now, online the subtree.
 * XXX: Presumably the configurator will online the subtree
 * XXX: by doing an ndi_devi_online with NDI_CONFIG on the child
 * XXX: if there is one.  For now, we're doing it here.
 * XXX: For buses without a configurator (and thus no config child),
 * XXX: we have to do it here.
 *
 */
static int
fco_validate(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	rp->cdip_state = FC_CDIP_CONFIG;

	cp->nresults = fc_int2cell(0);
	return (fc_success_op(ap, rp, cp));
}

static void
remove_subtree(dev_info_t *root, struct fc_device_tree *subtree)
{
	dev_info_t *child;

	/*
	 * Remove the subtree, depth first. Each iterative
	 * call gets another child at each level of the tree
	 * until there are no more children.
	 */
	while ((child = fc_child_node(root, subtree)) != NULL)
		remove_subtree(child, subtree);

	/*
	 * Delete the subtree root and remove its record from our
	 * copy of the subtree.
	 */
	fc_remove_child(root, subtree);
	(void) ndi_devi_offline(root, NDI_UNCONFIG | NDI_DEVI_REMOVE);
}

static int
fco_invalidate(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	dev_info_t *root, *child;
	struct fc_device_tree *subtree = fc_handle_to_dtree(rp);
	int configured = (rp->cdip_state == FC_CDIP_CONFIG);

	/*
	 * If we created any children, delete them. The root node is the
	 * config child, if one exists for this bus, otherwise it's the
	 * attachment point.
	 *
	 * Our copy of the subtree only contains records of nodes we created
	 * under the subtree root and contains the parent->child linkage
	 * that isn't yet established in the real device tree.
	 *
	 * XXX: What we don't do is restore the config child node to it's
	 * pre-interpretive state. (We may have added properties to
	 * that node. It's not clear if its necessary to clean them up.)
	 */
	root = rp->child ? rp->child : ap;

	while ((child = fc_child_node(root, subtree)) != NULL) {
		FC_DEBUG2(1, CE_CONT, "fco_invalidate: remove subtree "
		    "<%s> dip %p\n", ddi_node_name(child), child);
		remove_subtree(child, subtree);
	}

	if (configured)
		(void) ndi_devi_offline(root, NDI_UNCONFIG);

	cp->nresults = fc_int2cell(0);
	return (fc_success_op(ap, rp, cp));
}

static int
fco_exit(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	FC_DEBUG0(1, CE_CONT, "exit op not implemented .. succeeding\n");
	cp->nresults = fc_int2cell(0);
	return (fc_success_op(ap, rp, cp));
}

/*
 * Needed to implement 'mac-address' Fcode, no obvious place to pick this
 * info up from user-land.
 */
static int
fco_local_ether_addr(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	if (fc_cell2int(cp->nargs) != 0)
		return (fc_syntax_error(cp, "nargs must be 0"));

	if (fc_cell2int(cp->nresults) != 2)
		return (fc_syntax_error(cp, "nresults must be 2"));

	cp->nresults = fc_int2cell(2);

	(void) localetheraddr(NULL, (struct ether_addr *)(&fc_result(cp, 0)));

	return (fc_success_op(ap, rp, cp));
}

#ifdef DEBUG
void
fc_debug(char *fmt, uintptr_t a1, uintptr_t a2, uintptr_t a3,
	uintptr_t a4, uintptr_t a5)
{
	cmn_err(CE_CONT, fmt, a1, a2, a3, a4, a5);
}
#endif
