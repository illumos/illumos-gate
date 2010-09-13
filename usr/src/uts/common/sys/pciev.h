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

#ifndef	_SYS_PCIEV_H
#define	_SYS_PCIEV_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct pcie_eh_data {
	uint16_t minor_ver;	/* Minor data packet version, added data */
	uint16_t major_ver;	/* Major data packet version, struct change */
	uint16_t pci_err_status;	/* pci status register */
	uint16_t pci_bdg_sec_stat;	/* PCI secondary status reg */
	uint32_t pcix_status;		/* pcix status register */
	uint16_t pcix_bdg_sec_stat;	/* pcix bridge secondary status reg */
	uint32_t pcix_bdg_stat;		/* pcix bridge status reg */
	uint16_t pcix_ecc_control_0;	/* pcix ecc control status reg */
	uint16_t pcix_ecc_status_0;	/* pcix ecc control status reg */
	uint32_t pcix_ecc_fst_addr_0;	/* pcix ecc first address reg */
	uint32_t pcix_ecc_sec_addr_0;	/* pcix ecc second address reg */
	uint32_t pcix_ecc_attr_0;	/* pcix ecc attributes reg */
	uint16_t pcix_ecc_control_1;	/* pcix ecc control status reg */
	uint16_t pcix_ecc_status_1;	/* pcix ecc control status reg */
	uint32_t pcix_ecc_fst_addr_1;	/* pcix ecc first address reg */
	uint32_t pcix_ecc_sec_addr_1;	/* pcix ecc second address reg */
	uint32_t pcix_ecc_attr_1;	/* pcix ecc attributes reg */
	uint16_t pcie_err_status;	/* pcie device status register */
	uint32_t pcie_ue_status;	/* pcie ue error status reg */
	uint32_t pcie_ue_hdr[4];	/* pcie ue header log */
	uint32_t pcie_ce_status;	/* pcie ce error status reg */
	uint32_t pcie_sue_status;	/* pcie bridge secondary ue status */
	uint32_t pcie_sue_hdr[4];	/* pcie bridge secondary ue hdr log */
	uint16_t pcie_rp_ctl;		/* root port control register */
	uint32_t pcie_rp_err_status;	/* pcie root port error status reg */
	uint32_t pcie_rp_err_cmd;	/* pcie root port error cmd reg */
	uint16_t pcie_rp_ce_src_id;	/* pcie root port ce sourpe id */
	uint16_t pcie_rp_ue_src_id;	/* pcie root port ue sourpe id */
} pcie_eh_data_t;

typedef struct pcie_domains {
	uint_t domain_id;
	uint_t cached_count;	/* Reference Count of cached dom id list */
	uint_t faulty_count;	/* Reference Count of faulty dom id list */
	struct pcie_domains *cached_next; /* Next on cached dom id list */
	struct pcie_domains *faulty_prev; /* Prev on faulty dom id list */
	struct pcie_domains *faulty_next; /* Next on faulty dom id list */
} pcie_domains_t;

typedef struct pcie_req_id_list {
	pcie_req_id_t		bdf;
	struct pcie_req_id_list	*next;
} pcie_req_id_list_t;

typedef struct pcie_child_domains {
	pcie_domains_t *ids;
	pcie_req_id_list_t *bdfs;
} pcie_child_domains_t;

/*
 * IOV data structure:
 * This data strucutre is now statically allocated during bus_p
 * initializing time. Do we need to have this data structure for
 * non-root domains? If not, is there a way to differentiate root
 * domain and non-root domain so that we do the initialization for
 * root domain only?
 */
typedef struct pcie_domain {
	/*
	 * Bridges:
	 * Cache the domain/channel id and bdfs of all it's children.
	 *
	 * Leaves:
	 * Cache just the domain/channel id of self.
	 * Bridges will contain 0 <= N <= NumChild
	 *
	 * Note:
	 * there is no lock to protect the access to
	 * pcie_domains_t data struture. Currently we don't see
	 * the need for lock. But we need to pay attention if there
	 * might be issues when hotplug is enabled.
	 */
	union {
		pcie_child_domains_t ids;
		pcie_domains_t id;
	} domain;

	/*
	 * Reference count of the domain type for this device and it's children.
	 * For leaf devices, fmadom + nfma + root = 1
	 * For bridges, the sum of the counts = number of LEAF children.
	 *
	 * All devices start with a count of 1 for either nfmadom or rootdom.
	 */
	uint_t		fmadom_count;	/* FMA channel capable domain */
	uint_t		nfmadom_count;	/* Non-FMA channel domain */
	uint_t		rootdom_count;	/* Root domain */

	/* flag if the affected dev will cause guest domains to panic */
	boolean_t	nfma_panic;
} pcie_domain_t;

extern void pcie_domain_list_add(uint_t, pcie_domains_t **);
extern void pcie_domain_list_remove(uint_t, pcie_domains_t *);
extern void pcie_save_domain_id(pcie_domains_t *);
extern void pcie_init_dom(dev_info_t *);
extern void pcie_fini_dom(dev_info_t *);

#define	PCIE_ASSIGNED_TO_FMA_DOM(bus_p)	\
	(!PCIE_IS_BDG(bus_p) && PCIE_BUS2DOM(bus_p)->fmadom_count > 0)
#define	PCIE_ASSIGNED_TO_NFMA_DOM(bus_p)	\
	(!PCIE_IS_BDG(bus_p) && PCIE_BUS2DOM(bus_p)->nfmadom_count > 0)
#define	PCIE_ASSIGNED_TO_ROOT_DOM(bus_p)			\
	(PCIE_IS_BDG(bus_p) || PCIE_BUS2DOM(bus_p)->rootdom_count > 0)
#define	PCIE_BDG_HAS_CHILDREN_FMA_DOM(bus_p)			\
	(PCIE_IS_BDG(bus_p) && PCIE_BUS2DOM(bus_p)->fmadom_count > 0)
#define	PCIE_BDG_HAS_CHILDREN_NFMA_DOM(bus_p)			\
	(PCIE_IS_BDG(bus_p) && PCIE_BUS2DOM(bus_p)->nfmadom_count > 0)
#define	PCIE_BDG_HAS_CHILDREN_ROOT_DOM(bus_p)			\
	(PCIE_IS_BDG(bus_p) && PCIE_BUS2DOM(bus_p)->rootdom_count > 0)
#define	PCIE_IS_ASSIGNED(bus_p)	\
	(!PCIE_ASSIGNED_TO_ROOT_DOM(bus_p))
#define	PCIE_BDG_IS_UNASSIGNED(bus_p)	\
	(PCIE_IS_BDG(bus_p) &&		\
	(!PCIE_BDG_HAS_CHILDREN_NFMA_DOM(bus_p)) &&	\
	(!PCIE_BDG_HAS_CHILDREN_FMA_DOM(bus_p)))


#define	PCIE_IN_DOMAIN(bus_p, id) (pcie_in_domain((bus_p), (id)))

/* Following macros are only valid for leaf devices */
#define	PCIE_DOMAIN_ID_GET(bus_p) \
	((uint_t)(PCIE_IS_ASSIGNED(bus_p)			\
	    ? PCIE_BUS2DOM(bus_p)->domain.id.domain_id : NULL))
#define	PCIE_DOMAIN_ID_SET(bus_p, new_id) \
	if (!PCIE_IS_BDG(bus_p)) \
		PCIE_BUS2DOM(bus_p)->domain.id.domain_id = (uint_t)(new_id)
#define	PCIE_DOMAIN_ID_INCR_REF_COUNT(bus_p)	\
	if (!PCIE_IS_BDG(bus_p))	\
		PCIE_BUS2DOM(bus_p)->domain.id.cached_count = 1;
#define	PCIE_DOMAIN_ID_DECR_REF_COUNT(bus_p)	\
	if (!PCIE_IS_BDG(bus_p))	\
		PCIE_BUS2DOM(bus_p)->domain.id.cached_count = 0;

/* Following macros are only valid for bridges */
#define	PCIE_DOMAIN_LIST_GET(bus_p) \
	((pcie_domains_t *)(PCIE_IS_BDG(bus_p) ?	\
	    PCIE_BUS2DOM(bus_p)->domain.ids.ids : NULL))
#define	PCIE_DOMAIN_LIST_ADD(bus_p, domain_id) \
	if (PCIE_IS_BDG(bus_p)) \
	    pcie_domain_list_add(domain_id, \
		&PCIE_BUS2DOM(bus_p)->domain.ids.ids)
#define	PCIE_DOMAIN_LIST_REMOVE(bus_p, domain_id) \
	if (PCIE_IS_BDG(bus_p)) \
	    pcie_domain_list_remove(domain_id, \
		PCIE_BUS2DOM(bus_p)->domain.ids.ids)

#define	PCIE_BDF_LIST_GET(bus_p) \
	((pcie_req_id_list_t *)(PCIE_IS_BDG(bus_p) ? \
	    PCIE_BUS2DOM(bus_p)->domain.ids.bdfs : NULL))
#define	PCIE_BDF_LIST_ADD(bus_p, bdf) \
	if (PCIE_IS_BDG(bus_p)) \
		pcie_bdf_list_add(bdf, &PCIE_BUS2DOM(bus_p)->domain.ids.bdfs)
#define	PCIE_BDF_LIST_REMOVE(bus_p, bdf) \
	if (PCIE_IS_BDG(bus_p)) \
		pcie_bdf_list_remove(bdf, &PCIE_BUS2DOM(bus_p)->domain.ids.bdfs)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCIEV_H */
