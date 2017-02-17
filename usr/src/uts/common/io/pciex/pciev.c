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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2017, Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/dditypes.h>
#include <sys/ddifm.h>
#include <sys/sunndi.h>
#include <sys/devops.h>
#include <sys/pcie.h>
#include <sys/pci_cap.h>
#include <sys/pcie_impl.h>
#include <sys/pathname.h>

/*
 * The below 2 global variables are for PCIe IOV Error Handling.  They must only
 * be accessed during error handling under the protection of a error mutex.
 */
static pcie_domains_t *pcie_faulty_domains = NULL;
static boolean_t pcie_faulty_all = B_FALSE;

static void pcie_domain_list_destroy(pcie_domains_t *domain_ids);
static void pcie_bdf_list_add(pcie_req_id_t bdf,
    pcie_req_id_list_t **rlist_p);
static void pcie_bdf_list_remove(pcie_req_id_t bdf,
    pcie_req_id_list_t **rlist_p);
static void pcie_cache_domain_info(pcie_bus_t *bus_p);
static void pcie_uncache_domain_info(pcie_bus_t *bus_p);

static void pcie_faulty_list_clear();
static void pcie_faulty_list_update(pcie_domains_t *pd,
    pcie_domains_t **headp);

dev_info_t *
pcie_find_dip_by_bdf(dev_info_t *rootp, pcie_req_id_t bdf)
{
	dev_info_t *dip;
	pcie_bus_t *bus_p;
	int bus_num;

	dip = ddi_get_child(rootp);
	while (dip) {
		bus_p = PCIE_DIP2BUS(dip);
		if (bus_p && (bus_p->bus_bdf == bdf))
			return (dip);
		if (bus_p) {
			bus_num = (bdf >> 8) & 0xff;
			if ((bus_num >= bus_p->bus_bus_range.lo &&
			    bus_num <= bus_p->bus_bus_range.hi) ||
			    bus_p->bus_bus_range.hi == 0)
				return (pcie_find_dip_by_bdf(dip, bdf));
		}
		dip = ddi_get_next_sibling(dip);
	}
	return (NULL);
}

/*
 * Add a device bdf to the bdf list.
 */
static void
pcie_bdf_list_add(pcie_req_id_t bdf, pcie_req_id_list_t **rlist_p)
{
	pcie_req_id_list_t *rl = PCIE_ZALLOC(pcie_req_id_list_t);

	rl->bdf = bdf;
	rl->next = *rlist_p;
	*rlist_p = rl;
}

/*
 * Remove a bdf from the bdf list.
 */
static void
pcie_bdf_list_remove(pcie_req_id_t bdf, pcie_req_id_list_t **rlist_p)
{
	pcie_req_id_list_t *rl_pre, *rl_next;

	rl_pre = *rlist_p;
	if (rl_pre->bdf == bdf) {
		*rlist_p = rl_pre->next;
		kmem_free(rl_pre, sizeof (pcie_req_id_list_t));
		return;
	}

	while (rl_pre->next) {
		rl_next = rl_pre->next;
		if (rl_next->bdf == bdf) {
			rl_pre->next = rl_next->next;
			kmem_free(rl_next, sizeof (pcie_req_id_list_t));
			break;
		} else
			rl_pre = rl_next;
	}
}

/*
 * Cache IOV domain info in all it's parent's pcie_domain_t
 *
 * The leaf devices's domain info must be set before calling this function.
 */
void
pcie_cache_domain_info(pcie_bus_t *bus_p)
{
	boolean_t 	assigned = PCIE_IS_ASSIGNED(bus_p);
	boolean_t 	fma_dom = PCIE_ASSIGNED_TO_FMA_DOM(bus_p);
	uint_t		domain_id = PCIE_DOMAIN_ID_GET(bus_p);
	pcie_req_id_t	bdf = bus_p->bus_bdf;
	dev_info_t	*pdip;
	pcie_bus_t	*pbus_p;
	pcie_domain_t	*pdom_p;

	ASSERT(!PCIE_IS_BDG(bus_p));

	for (pdip = ddi_get_parent(PCIE_BUS2DIP(bus_p)); PCIE_DIP2BUS(pdip);
	    pdip = ddi_get_parent(pdip)) {
		pbus_p = PCIE_DIP2BUS(pdip);
		pdom_p = PCIE_BUS2DOM(pbus_p);

		if (assigned) {
			if (domain_id)
				PCIE_DOMAIN_LIST_ADD(pbus_p, domain_id);

			if (fma_dom)
				pdom_p->fmadom_count++;
			else {
				PCIE_BDF_LIST_ADD(pbus_p, bdf);
				pdom_p->nfmadom_count++;
			}
		} else
			pdom_p->rootdom_count++;
	}
}

/*
 * Clear the leaf device's domain info and uncache IOV domain info in all it's
 * parent's pcie_domain_t
 *
 * The leaf devices's domain info is also cleared by calling this function.
 */
void
pcie_uncache_domain_info(pcie_bus_t *bus_p)
{
	boolean_t 	assigned = PCIE_IS_ASSIGNED(bus_p);
	boolean_t 	fma_dom = PCIE_ASSIGNED_TO_FMA_DOM(bus_p);
	uint_t		domain_id = PCIE_DOMAIN_ID_GET(bus_p);
	pcie_domain_t	*dom_p = PCIE_BUS2DOM(bus_p), *pdom_p;
	pcie_bus_t	*pbus_p;
	dev_info_t	*pdip;

	ASSERT(!PCIE_IS_BDG(bus_p));
	ASSERT((dom_p->fmadom_count + dom_p->nfmadom_count +
	    dom_p->rootdom_count) == 1);

	/* Clear the domain information */
	if (domain_id) {
		PCIE_DOMAIN_ID_SET(bus_p, NULL);
		PCIE_DOMAIN_ID_DECR_REF_COUNT(bus_p);
	}

	dom_p->fmadom_count = 0;
	dom_p->nfmadom_count = 0;
	dom_p->rootdom_count = 0;

	for (pdip = ddi_get_parent(PCIE_BUS2DIP(bus_p)); PCIE_DIP2BUS(pdip);
	    pdip = ddi_get_parent(pdip)) {
		pbus_p = PCIE_DIP2BUS(pdip);
		pdom_p = PCIE_BUS2DOM(pbus_p);

		if (assigned) {
			if (domain_id)
				PCIE_DOMAIN_LIST_REMOVE(pbus_p, domain_id);

			if (fma_dom)
				pdom_p->fmadom_count--;
			else {
				pdom_p->nfmadom_count--;
				PCIE_BDF_LIST_REMOVE(pbus_p, bus_p->bus_bdf);
			}
		} else
			pdom_p->rootdom_count--;
	}
}


/*
 * Initialize private data structure for IOV environments.
 * o Allocate memory for iov data
 * o Cache Domain ids.
 */
void
pcie_init_dom(dev_info_t *dip)
{
	pcie_domain_t	*dom_p = PCIE_ZALLOC(pcie_domain_t);
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	PCIE_BUS2DOM(bus_p) = dom_p;

	/* Only leaf devices are assignable to IO Domains */
	if (PCIE_IS_BDG(bus_p))
		return;

	/*
	 * At the time of init_dom in the root domain a device may or may not
	 * have been assigned to an IO Domain.
	 *
	 * LDOMS: the property "ddi-assigned" will be set for devices that is
	 * assignable to an IO domain and unusable in the root domain.  If the
	 * property exist assume it has been assigned to a non-fma domain until
	 * otherwise notified.  The domain id is unknown on LDOMS.
	 *
	 * Xen: the "ddi-assigned" property won't be set until Xen store calls
	 * pcie_loan_device is called.  In this function this will always look
	 * like the device is assigned to the root domain.  Domain ID caching
	 * will occur in pcie_loan_device function.
	 */
	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "ddi-assigned", -1) != -1) {
		dom_p->nfmadom_count = 1;

		/* Prevent "assigned" device from detaching */
		ndi_hold_devi(dip);
	} else
		dom_p->rootdom_count = 1;
	(void) ddi_prop_remove(DDI_DEV_T_NONE, dip, "ddi-assigned");

	pcie_cache_domain_info(bus_p);
}

void
pcie_fini_dom(dev_info_t *dip)
{
	pcie_domain_t	*dom_p = PCIE_DIP2DOM(dip);
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	if (PCIE_IS_BDG(bus_p))
		pcie_domain_list_destroy(PCIE_DOMAIN_LIST_GET(bus_p));
	else
		pcie_uncache_domain_info(bus_p);

	kmem_free(dom_p, sizeof (pcie_domain_t));
}

/*
 * PCIe Severity:
 *
 * PF_ERR_NO_ERROR	: no IOV Action
 * PF_ERR_CE		: no IOV Action
 * PF_ERR_NO_PANIC	: contains error telemetry, log domain info
 * PF_ERR_MATCHED_DEVICE: contains error telemetry, log domain info
 * PF_ERR_MATCHED_RC	: Error already taken care of, no further IOV Action
 * PF_ERR_MATCHED_PARENT: Error already taken care of, no further IOV Action
 * PF_ERR_PANIC		: contains error telemetry, log domain info
 *
 * For NO_PANIC, MATCHED_DEVICE and PANIC, IOV wants to look at the affected
 * devices and find the domains involved.
 *
 * If root domain does not own an affected device, IOV EH should change
 * PF_ERR_PANIC to PF_ERR_MATCH_DOM.
 */
int
pciev_eh(pf_data_t *pfd_p, pf_impl_t *impl)
{
	int severity = pfd_p->pe_severity_flags;
	int iov_severity = severity;
	pcie_bus_t *a_bus_p;	/* Affected device's pcie_bus_t */
	pf_data_t *root_pfd_p = impl->pf_dq_head_p;
	pcie_bus_t *root_bus_p;

	/*
	 * check if all devices under the root device are unassigned.
	 * this function should quickly return in non-IOV environment.
	 */
	ASSERT(root_pfd_p != NULL);
	root_bus_p = PCIE_PFD2BUS(root_pfd_p);
	if (PCIE_BDG_IS_UNASSIGNED(root_bus_p))
		return (severity);

	if (severity & PF_ERR_PANIC_DEADLOCK) {
		pcie_faulty_all = B_TRUE;

	} else if (severity & (PF_ERR_NO_PANIC | PF_ERR_MATCHED_DEVICE |
	    PF_ERR_PANIC | PF_ERR_BAD_RESPONSE)) {

		uint16_t affected_flag, dev_affected_flags;
		uint_t is_panic = 0, is_aff_dev_found = 0;

		dev_affected_flags = PFD_AFFECTED_DEV(pfd_p)->pe_affected_flags;
		/* adjust affected flags to leverage cached domain ids */
		if (dev_affected_flags & PF_AFFECTED_CHILDREN) {
			dev_affected_flags |= PF_AFFECTED_SELF;
			dev_affected_flags &= ~PF_AFFECTED_CHILDREN;
		}

		for (affected_flag = 1;
		    affected_flag <= PF_MAX_AFFECTED_FLAG;
		    affected_flag <<= 1) {
			a_bus_p = pciev_get_affected_dev(impl, pfd_p,
			    affected_flag, dev_affected_flags);

			if (a_bus_p == NULL)
				continue;

			is_aff_dev_found++;
			PFD_AFFECTED_DEV(pfd_p)->pe_affected_bdf =
			    a_bus_p->bus_bdf;

			/*
			 * If a leaf device is assigned to the root domain or if
			 * a bridge has children assigned to a root domain
			 * panic.
			 *
			 * If a leaf device or a child of a bridge is assigned
			 * to NFMA domain mark it for panic.  If assigned to FMA
			 * domain save the domain id.
			 */
			if (!PCIE_IS_BDG(a_bus_p) &&
			    !PCIE_IS_ASSIGNED(a_bus_p)) {
				if (severity & PF_ERR_FATAL_FLAGS)
					is_panic++;
				continue;
			}

			if (PCIE_BDG_HAS_CHILDREN_ROOT_DOM(a_bus_p)) {
				if (severity & PF_ERR_FATAL_FLAGS)
					is_panic++;
			}

			if ((PCIE_ASSIGNED_TO_NFMA_DOM(a_bus_p) ||
			    PCIE_BDG_HAS_CHILDREN_NFMA_DOM(a_bus_p)) &&
			    (severity & PF_ERR_FATAL_FLAGS)) {
				PCIE_BUS2DOM(a_bus_p)->nfma_panic = B_TRUE;
				iov_severity |= PF_ERR_MATCH_DOM;
			}

			if (PCIE_ASSIGNED_TO_FMA_DOM(a_bus_p)) {
				pcie_save_domain_id(
				    &PCIE_BUS2DOM(a_bus_p)->domain.id);
				iov_severity |= PF_ERR_MATCH_DOM;
			}

			if (PCIE_BDG_HAS_CHILDREN_FMA_DOM(a_bus_p)) {
				pcie_save_domain_id(
				    PCIE_DOMAIN_LIST_GET(a_bus_p));
				iov_severity |= PF_ERR_MATCH_DOM;
			}
		}

		/*
		 * Overwrite the severity only if affected device can be
		 * identified and root domain does not need to panic.
		 */
		if ((!is_panic) && is_aff_dev_found) {
			iov_severity &= ~PF_ERR_FATAL_FLAGS;
		}
	}

	return (iov_severity);
}

/* ARGSUSED */
void
pciev_eh_exit(pf_data_t *root_pfd_p, uint_t intr_type)
{
	pcie_bus_t *root_bus_p;

	/*
	 * check if all devices under the root device are unassigned.
	 * this function should quickly return in non-IOV environment.
	 */
	root_bus_p = PCIE_PFD2BUS(root_pfd_p);
	if (PCIE_BDG_IS_UNASSIGNED(root_bus_p))
		return;

	pcie_faulty_list_clear();
}

pcie_bus_t *
pciev_get_affected_dev(pf_impl_t *impl, pf_data_t *pfd_p,
    uint16_t affected_flag, uint16_t dev_affected_flags)
{
	pcie_bus_t *bus_p = PCIE_PFD2BUS(pfd_p);
	uint16_t flag = affected_flag & dev_affected_flags;
	pcie_bus_t *temp_bus_p;
	pcie_req_id_t a_bdf;
	uint64_t a_addr;
	uint16_t cmd;

	if (!flag)
		return (NULL);

	switch (flag) {
	case PF_AFFECTED_ROOT:
		return (PCIE_DIP2BUS(bus_p->bus_rp_dip));
	case PF_AFFECTED_SELF:
		return (bus_p);
	case PF_AFFECTED_PARENT:
		return (PCIE_DIP2BUS(ddi_get_parent(PCIE_BUS2DIP(bus_p))));
	case PF_AFFECTED_BDF: /* may only be used for RC */
		a_bdf = PFD_AFFECTED_DEV(pfd_p)->pe_affected_bdf;
		if (!PCIE_CHECK_VALID_BDF(a_bdf))
			return (NULL);

		temp_bus_p = pf_find_busp_by_bdf(impl, a_bdf);
		return (temp_bus_p);
	case PF_AFFECTED_AER:
		if (pf_tlp_decode(bus_p, PCIE_ADV_REG(pfd_p)) == DDI_SUCCESS) {
			temp_bus_p = pf_find_busp_by_aer(impl, pfd_p);
			return (temp_bus_p);
		}
		break;
	case PF_AFFECTED_SAER:
		if (pf_pci_decode(pfd_p, &cmd) == DDI_SUCCESS) {
			temp_bus_p = pf_find_busp_by_saer(impl, pfd_p);
			return (temp_bus_p);
		}
		break;
	case PF_AFFECTED_ADDR: /* ROOT only */
		a_addr = PCIE_ROOT_FAULT(pfd_p)->scan_addr;
		temp_bus_p = pf_find_busp_by_addr(impl, a_addr);
		return (temp_bus_p);
	}

	return (NULL);
}

/* type used for pcie_domain_list_find() function */
typedef enum {
	PCIE_DOM_LIST_TYPE_CACHE = 1,
	PCIE_DOM_LIST_TYPE_FAULT = 2
} pcie_dom_list_type_t;

/*
 * Check if a domain id is already in the linked list
 */
static pcie_domains_t *
pcie_domain_list_find(uint_t domain_id, pcie_domains_t *pd_list_p,
    pcie_dom_list_type_t type)
{
	while (pd_list_p) {
		if (pd_list_p->domain_id == domain_id)
			return (pd_list_p);

		if (type == PCIE_DOM_LIST_TYPE_CACHE) {
			pd_list_p = pd_list_p->cached_next;
		} else if (type == PCIE_DOM_LIST_TYPE_FAULT) {
			pd_list_p = pd_list_p->faulty_next;
		} else {
			return (NULL);
		}
	}

	return (NULL);
}

/*
 * Return true if a leaf device is assigned to a domain or a bridge device
 * has children assigned to the domain
 */
boolean_t
pcie_in_domain(pcie_bus_t *bus_p, uint_t domain_id)
{
	if (PCIE_IS_BDG(bus_p)) {
		pcie_domains_t *pd;
		pd = pcie_domain_list_find(domain_id,
		    PCIE_DOMAIN_LIST_GET(bus_p), PCIE_DOM_LIST_TYPE_CACHE);
		if (pd && pd->cached_count)
			return (B_TRUE);
		return (B_FALSE);
	} else {
		return (PCIE_DOMAIN_ID_GET(bus_p) == domain_id);
	}
}

/*
 * Add a domain id to a cached domain id list.
 * If the domain already exists in the list, increment the reference count.
 */
void
pcie_domain_list_add(uint_t domain_id, pcie_domains_t **pd_list_p)
{
	pcie_domains_t *pd;

	pd = pcie_domain_list_find(domain_id, *pd_list_p,
	    PCIE_DOM_LIST_TYPE_CACHE);

	if (pd == NULL) {
		pd = PCIE_ZALLOC(pcie_domains_t);
		pd->domain_id = domain_id;
		pd->cached_count = 1;
		pd->cached_next = *pd_list_p;
		*pd_list_p = pd;
	} else
		pd->cached_count++;
}

/*
 * Remove a domain id from a cached domain id list.
 * Decrement the reference count.
 */
void
pcie_domain_list_remove(uint_t domain_id, pcie_domains_t *pd_list_p)
{
	pcie_domains_t *pd;

	pd = pcie_domain_list_find(domain_id, pd_list_p,
	    PCIE_DOM_LIST_TYPE_CACHE);

	if (pd) {
		ASSERT((pd->cached_count)--);
	}
}

/* destroy cached domain id list */
static void
pcie_domain_list_destroy(pcie_domains_t *domain_ids)
{
	pcie_domains_t *p = domain_ids;
	pcie_domains_t *next;

	while (p) {
		next = p->cached_next;
		kmem_free(p, sizeof (pcie_domains_t));
		p = next;
	}
}

static void
pcie_faulty_list_update(pcie_domains_t *pd,
    pcie_domains_t **headp)
{
	if (pd == NULL)
		return;

	if (*headp == NULL) {
		*headp = pd;
		pd->faulty_prev = NULL;
		pd->faulty_next = NULL;
		pd->faulty_count = 1;
	} else {
		pd->faulty_next = *headp;
		(*headp)->faulty_prev = pd;
		pd->faulty_prev = NULL;
		pd->faulty_count = 1;
		*headp = pd;
	}
}

static void
pcie_faulty_list_clear()
{
	pcie_domains_t *pd = pcie_faulty_domains;
	pcie_domains_t *next;

	/* unlink all domain structures from the faulty list */
	while (pd) {
		next = pd->faulty_next;
		pd->faulty_prev = NULL;
		pd->faulty_next = NULL;
		pd->faulty_count = 0;
		pd = next;
	}
	pcie_faulty_domains = NULL;
	pcie_faulty_all = B_FALSE;
}

void
pcie_save_domain_id(pcie_domains_t *domain_ids)
{
	pcie_domains_t *old_list_p, *new_list_p, *pd;

	if (pcie_faulty_all)
		return;

	if (domain_ids == NULL)
		return;

	old_list_p = pcie_faulty_domains;
	for (new_list_p = domain_ids; new_list_p;
	    new_list_p = new_list_p->cached_next) {
		if (!new_list_p->cached_count)
			continue;

		/* search domain id in the faulty domain list */
		pd = pcie_domain_list_find(new_list_p->domain_id,
		    old_list_p, PCIE_DOM_LIST_TYPE_FAULT);
		if (pd)
			pd->faulty_count++;
		else
			pcie_faulty_list_update(new_list_p,
			    &pcie_faulty_domains);
	}
}
