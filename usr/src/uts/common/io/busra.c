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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#if defined(DEBUG)
#define	BUSRA_DEBUG
#endif

/*
 * This module provides a set of resource management interfaces
 * to manage bus resources globally in the system.
 *
 * The bus nexus drivers are typically responsible to setup resource
 * maps for the bus resources available for a bus instance. However
 * this module also provides resource setup functions for PCI bus
 * (used by both SPARC and X86 platforms) and ISA bus instances (used
 * only for X86 platforms).
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/kmem.h>
#include <sys/pctypes.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/spl.h>
#include <sys/pci.h>
#include <sys/autoconf.h>

#if defined(BUSRA_DEBUG)
int busra_debug = 0;
#define	DEBUGPRT \
	if (busra_debug) cmn_err

#else
#define	DEBUGPRT \
	if (0) cmn_err
#endif


/*
 * global mutex that protects the global list of resource maps.
 */
kmutex_t ra_lock;

/*
 * basic resource element
 */
struct ra_resource {
	struct ra_resource *ra_next;
	uint64_t	ra_base;
	uint64_t 	ra_len;
};

/*
 * link list element for the list of dips (and their resource ranges)
 * for a particular resource type.
 * ra_rangeset points to the list of resources available
 * for this type and this dip.
 */
struct ra_dip_type  {
	struct ra_dip_type *ra_next;
	struct ra_resource  *ra_rangeset;
	dev_info_t *ra_dip;
};


/*
 * link list element for list of types resources. Each element
 * has all resources for a particular type.
 */
struct ra_type_map {
	struct ra_type_map *ra_next;
	struct ra_dip_type *ra_dip_list;
	char *type;
};


/*
 * place holder to keep the head of the whole global list.
 * the address of the first typemap would be stored in it.
 */
static struct ra_type_map	*ra_map_list_head = NULL;


/*
 * This is the loadable module wrapper.
 * It is essentially boilerplate so isn't documented
 */
extern struct mod_ops mod_miscops;

#ifdef BUSRA_DEBUG
void ra_dump_all(char *, dev_info_t *);
#endif

/* internal function prototypes */
static struct ra_dip_type *find_dip_map_resources(dev_info_t *dip, char *type,
    struct ra_dip_type ***backdip, struct ra_type_map ***backtype,
    uint32_t flag);
static int isnot_pow2(uint64_t value);
static int claim_pci_busnum(dev_info_t *dip, void *arg);
static int ra_map_exist(dev_info_t *dip, char *type);

static int pci_get_available_prop(dev_info_t *dip, uint64_t base,
    uint64_t len, char *busra_type);
static int pci_put_available_prop(dev_info_t *dip, uint64_t base,
    uint64_t len, char *busra_type);
static uint32_t pci_type_ra2pci(char *type);
static boolean_t is_pcie_fabric(dev_info_t *dip);

#define	PCI_ADDR_TYPE_MASK	(PCI_REG_ADDR_M | PCI_REG_PF_M)
#define	PCI_ADDR_TYPE_INVAL	0xffffffff

#define	RA_INSERT(prev, el) \
	el->ra_next = *prev; \
	*prev = el;

#define	RA_REMOVE(prev, el) \
	*prev = el->ra_next;


static struct modlmisc modlmisc = {
	&mod_miscops,		/* Type of module. This one is a module */
	"Bus Resource Allocator (BUSRA)",	/* Name of the module. */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init()
{
	int	ret;

	mutex_init(&ra_lock, NULL, MUTEX_DRIVER,
	    (void *)(intptr_t)__ipltospl(SPL7 - 1));
	if ((ret = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&ra_lock);
	}
	return (ret);
}

int
_fini()
{
	int	ret;

	mutex_enter(&ra_lock);

	if (ra_map_list_head != NULL) {
		mutex_exit(&ra_lock);
		return (EBUSY);
	}

	ret = mod_remove(&modlinkage);

	mutex_exit(&ra_lock);

	if (ret == 0)
		mutex_destroy(&ra_lock);

	return (ret);
}

int
_info(struct modinfo *modinfop)

{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * set up an empty resource map for a given type and dip
 */
int
ndi_ra_map_setup(dev_info_t *dip, char *type)
{
	struct ra_type_map  *typemapp;
	struct ra_dip_type  *dipmap;
	struct ra_dip_type  **backdip;
	struct ra_type_map  **backtype;


	mutex_enter(&ra_lock);

	dipmap = find_dip_map_resources(dip, type, &backdip, &backtype, 0);

	if (dipmap == NULL) {
		if (backtype == NULL) {
			typemapp = (struct ra_type_map *)
			    kmem_zalloc(sizeof (*typemapp), KM_SLEEP);
			typemapp->type = (char *)kmem_zalloc(strlen(type) + 1,
			    KM_SLEEP);
			(void) strcpy(typemapp->type, type);
			RA_INSERT(&ra_map_list_head, typemapp);
		} else {
			typemapp = *backtype;
		}
		if (backdip == NULL) {
			/* allocate and insert in list of dips for this type */
			dipmap = (struct ra_dip_type *)
			    kmem_zalloc(sizeof (*dipmap), KM_SLEEP);
			dipmap->ra_dip = dip;
			RA_INSERT(&typemapp->ra_dip_list, dipmap);
		}
	}

	mutex_exit(&ra_lock);
	return (NDI_SUCCESS);
}

/*
 * destroys a resource map for a given dip and type
 */
int
ndi_ra_map_destroy(dev_info_t *dip, char *type)
{
	struct ra_dip_type	*dipmap;
	struct ra_dip_type	**backdip;
	struct ra_type_map  	**backtype, *typemap;
	struct ra_resource	*range;

	mutex_enter(&ra_lock);
	dipmap = find_dip_map_resources(dip, type, &backdip, &backtype, 0);

	if (dipmap == NULL) {
		mutex_exit(&ra_lock);
		return (NDI_FAILURE);
	}

	/*
	 * destroy all resources for this dip
	 * remove dip from type list
	 */
	ASSERT((backdip != NULL) && (backtype != NULL));
	while (dipmap->ra_rangeset != NULL) {
		range = dipmap->ra_rangeset;
		RA_REMOVE(&dipmap->ra_rangeset, range);
		kmem_free((caddr_t)range, sizeof (*range));
	}
	/* remove from dip list */
	RA_REMOVE(backdip, dipmap);
	kmem_free((caddr_t)dipmap, sizeof (*dipmap));
	if ((*backtype)->ra_dip_list == NULL) {
		/*
		 * This was the last dip with this resource type.
		 * Remove the type from the global list.
		 */
		typemap = *backtype;
		RA_REMOVE(backtype, (*backtype));
		kmem_free((caddr_t)typemap->type, strlen(typemap->type) + 1);
		kmem_free((caddr_t)typemap, sizeof (*typemap));
	}

	mutex_exit(&ra_lock);
	return (NDI_SUCCESS);
}

static int
ra_map_exist(dev_info_t *dip, char *type)
{
	struct ra_dip_type  **backdip;
	struct ra_type_map  **backtype;

	mutex_enter(&ra_lock);
	if (find_dip_map_resources(dip, type, &backdip, &backtype, 0) == NULL) {
		mutex_exit(&ra_lock);
		return (NDI_FAILURE);
	}

	mutex_exit(&ra_lock);
	return (NDI_SUCCESS);
}
/*
 * Find a dip map for the specified type, if NDI_RA_PASS will go up on dev tree
 * if found, backdip and backtype will be updated to point to the previous
 * dip in the list and previous type for this dip in the list.
 * If no such type at all in the resource list both backdip and backtype
 * will be null. If the type found but no dip, back dip will be null.
 */

static struct ra_dip_type *
find_dip_map_resources(dev_info_t *dip, char *type,
    struct ra_dip_type ***backdip, struct ra_type_map ***backtype,
    uint32_t flag)
{
	struct ra_type_map **prevmap;
	struct ra_dip_type *dipmap, **prevdip;

	ASSERT(mutex_owned(&ra_lock));
	prevdip = NULL;
	dipmap = NULL;
	prevmap = &ra_map_list_head;

	while (*prevmap) {
		if (strcmp((*prevmap)->type, type) == 0)
			break;
		prevmap = &(*prevmap)->ra_next;
	}

	if (*prevmap) {
		for (; dip != NULL; dip = ddi_get_parent(dip)) {
			prevdip = &(*prevmap)->ra_dip_list;
			dipmap = *prevdip;

			while (dipmap) {
				if (dipmap->ra_dip == dip)
					break;
				prevdip =  &dipmap->ra_next;
				dipmap = dipmap->ra_next;
			}

			if (dipmap != NULL) {
				/* found it */
				break;
			}

			if (!(flag & NDI_RA_PASS)) {
				break;
			}
		}
	}

	*backtype = (*prevmap == NULL) ?  NULL: prevmap;
	*backdip = (dipmap == NULL) ?  NULL: prevdip;

	return (dipmap);
}

int
ndi_ra_free(dev_info_t *dip, uint64_t base, uint64_t len, char *type,
    uint32_t flag)
{
	struct ra_dip_type *dipmap;
	struct ra_resource *newmap, *overlapmap, *oldmap = NULL;
	struct ra_resource  *mapp, **backp;
	uint64_t newend, mapend;
	struct ra_dip_type **backdip;
	struct ra_type_map **backtype;

	if (len == 0) {
		return (NDI_SUCCESS);
	}

	mutex_enter(&ra_lock);

	if ((dipmap = find_dip_map_resources(dip, type, &backdip, &backtype,
	    flag)) == NULL) {
		mutex_exit(&ra_lock);
		return (NDI_FAILURE);
	}

	mapp = dipmap->ra_rangeset;
	backp = &dipmap->ra_rangeset;

	/* now find where range lies and fix things up */
	newend = base + len;
	for (; mapp != NULL; backp = &(mapp->ra_next), mapp = mapp->ra_next) {
		mapend = mapp->ra_base + mapp->ra_len;

		/* check for overlap first */
		if ((base <= mapp->ra_base && newend > mapp->ra_base) ||
		    (base > mapp->ra_base && base < mapend)) {
			/* overlap with mapp */
			overlapmap = mapp;
			goto overlap;
		} else if ((base == mapend && mapp->ra_next) &&
		    (newend > mapp->ra_next->ra_base)) {
			/* overlap with mapp->ra_next */
			overlapmap = mapp->ra_next;
			goto overlap;
		}

		if (newend == mapp->ra_base) {
			/* simple - on front */
			mapp->ra_base = base;
			mapp->ra_len += len;
			/*
			 * don't need to check if it merges with
			 * previous since that would match on on end
			 */
			break;
		} else if (base == mapend) {
			/* simple - on end */
			mapp->ra_len += len;
			if (mapp->ra_next &&
			    (newend == mapp->ra_next->ra_base)) {
				/* merge with next node */
				oldmap = mapp->ra_next;
				mapp->ra_len += oldmap->ra_len;
				RA_REMOVE(&mapp->ra_next, oldmap);
				kmem_free((caddr_t)oldmap, sizeof (*oldmap));
			}
			break;
		} else if (base < mapp->ra_base) {
			/* somewhere in between so just an insert */
			newmap = (struct ra_resource *)
			    kmem_zalloc(sizeof (*newmap), KM_SLEEP);
			newmap->ra_base = base;
			newmap->ra_len = len;
			RA_INSERT(backp, newmap);
			break;
		}
	}
	if (mapp == NULL) {
		/* stick on end */
		newmap = (struct ra_resource *)
		    kmem_zalloc(sizeof (*newmap), KM_SLEEP);
		newmap->ra_base = base;
		newmap->ra_len = len;
		RA_INSERT(backp, newmap);
	}

	mutex_exit(&ra_lock);

	/*
	 * Update dip's "available" property, adding this piece of
	 * resource to the pool.
	 */
	(void) pci_put_available_prop(dipmap->ra_dip, base, len, type);
done:
	return (NDI_SUCCESS);

overlap:
	/*
	 * Bad free may happen on some x86 platforms with BIOS exporting
	 * incorrect resource maps. The system is otherwise functioning
	 * normally. We send such messages to syslog only.
	 */
	cmn_err(CE_NOTE, "!ndi_ra_free: bad free, dip %p, resource type %s \n",
	    (void *)dip, type);
	cmn_err(CE_NOTE, "!ndi_ra_free: freeing base 0x%" PRIx64 ", len 0x%"
	    PRIX64 " overlaps with existing resource base 0x%" PRIx64
	    ", len 0x%" PRIx64 "\n", base, len, overlapmap->ra_base,
	    overlapmap->ra_len);

	mutex_exit(&ra_lock);
	return (NDI_FAILURE);
}

/* check to see if value is power of 2 or not. */
static int
isnot_pow2(uint64_t value)
{
	uint32_t low;
	uint32_t hi;

	low = value & 0xffffffff;
	hi = value >> 32;

	/*
	 * ddi_ffs and ddi_fls gets long values, so in 32bit environment
	 * won't work correctly for 64bit values
	 */
	if ((ddi_ffs(low) == ddi_fls(low)) &&
	    (ddi_ffs(hi) == ddi_fls(hi)))
		return (0);
	return (1);
}

static  void
adjust_link(struct ra_resource **backp, struct ra_resource *mapp,
	    uint64_t base, uint64_t len)
{
	struct ra_resource *newmap;
	uint64_t newlen;

	if (base != mapp->ra_base) {
		/* in the middle or end */
		newlen = base - mapp->ra_base;
		if ((mapp->ra_len - newlen) == len) {
			/* on the end */
			mapp->ra_len = newlen;
		} else {
			/* in the middle */
			newmap = (struct ra_resource *)
			    kmem_zalloc(sizeof (*newmap), KM_SLEEP);
			newmap->ra_base = base + len;
			newmap->ra_len = mapp->ra_len - (len + newlen);
			mapp->ra_len = newlen;
			RA_INSERT(&(mapp->ra_next), newmap);
		}
	} else {
		/* at the beginning */
		mapp->ra_base += len;
		mapp->ra_len -= len;
		if (mapp->ra_len == 0) {
			/* remove the whole node */
			RA_REMOVE(backp, mapp);
			kmem_free((caddr_t)mapp, sizeof (*mapp));
		}
	}
}

int
ndi_ra_alloc(dev_info_t *dip, ndi_ra_request_t *req, uint64_t *retbasep,
    uint64_t *retlenp, char *type, uint32_t flag)
{
	struct ra_dip_type *dipmap;
	struct ra_resource *mapp, **backp, **backlargestp;
	uint64_t mask = 0;
	uint64_t len, remlen, largestbase, largestlen;
	uint64_t base, oldbase, lower, upper;
	struct ra_dip_type  **backdip;
	struct ra_type_map  **backtype;
	int  rval = NDI_FAILURE;


	len = req->ra_len;

	if (req->ra_flags & NDI_RA_ALIGN_SIZE) {
		if (isnot_pow2(req->ra_len)) {
			DEBUGPRT(CE_WARN, "ndi_ra_alloc: bad length(pow2) 0x%"
			    PRIx64, req->ra_len);
			*retbasep = 0;
			*retlenp = 0;
			return (NDI_FAILURE);
		}
	}

	mask = (req->ra_flags & NDI_RA_ALIGN_SIZE) ? (len - 1) :
	    req->ra_align_mask;


	mutex_enter(&ra_lock);
	dipmap = find_dip_map_resources(dip, type, &backdip, &backtype, flag);
	if ((dipmap == NULL) || ((mapp = dipmap->ra_rangeset) == NULL)) {
		mutex_exit(&ra_lock);
		DEBUGPRT(CE_CONT, "ndi_ra_alloc no map found for this type\n");
		return (NDI_FAILURE);
	}

	DEBUGPRT(CE_CONT, "ndi_ra_alloc: mapp = %p len=%" PRIx64 ", mask=%"
	    PRIx64 "\n", (void *)mapp, len, mask);

	backp = &(dipmap->ra_rangeset);
	backlargestp = NULL;
	largestbase = 0;
	largestlen = 0;

	lower = 0;
	upper = ~(uint64_t)0;

	if (req->ra_flags & NDI_RA_ALLOC_BOUNDED) {
		/* bounded so skip to first possible */
		lower = req->ra_boundbase;
		upper = req->ra_boundlen + lower;
		if ((upper == 0) || (upper < req->ra_boundlen))
			upper = ~(uint64_t)0;
		DEBUGPRT(CE_CONT, "ndi_ra_alloc: ra_len = %" PRIx64 ", len = %"
		    PRIx64 " ra_base=%" PRIx64 ", mask=%" PRIx64
		    "\n", mapp->ra_len, len, mapp->ra_base, mask);
		for (; mapp != NULL && (mapp->ra_base + mapp->ra_len) < lower;
		    backp = &(mapp->ra_next), mapp = mapp->ra_next) {
			if (((mapp->ra_len + mapp->ra_base) == 0) ||
			    ((mapp->ra_len + mapp->ra_base) < mapp->ra_len))
				/*
				 * This elements end goes beyond max uint64_t.
				 * potential candidate, check end against lower
				 * would not be precise.
				 */
				break;

			DEBUGPRT(CE_CONT, " ra_len = %" PRIx64 ", ra_base=%"
			    PRIx64 "\n", mapp->ra_len, mapp->ra_base);
			}

	}

	if (!(req->ra_flags & NDI_RA_ALLOC_SPECIFIED)) {
		/* first fit - not user specified */
		DEBUGPRT(CE_CONT, "ndi_ra_alloc(unspecified request)"
		    "lower=%" PRIx64 ", upper=%" PRIx64 "\n", lower, upper);
		for (; mapp != NULL && mapp->ra_base <= upper;
		    backp = &(mapp->ra_next), mapp = mapp->ra_next) {

			DEBUGPRT(CE_CONT, "ndi_ra_alloc: ra_len = %" PRIx64
			    ", len = %" PRIx64 "", mapp->ra_len, len);
			base = mapp->ra_base;
			if (base < lower) {
				base = lower;
				DEBUGPRT(CE_CONT, "\tbase=%" PRIx64
				    ", ra_base=%" PRIx64 ", mask=%" PRIx64,
				    base, mapp->ra_base, mask);
			}

			if ((base & mask) != 0) {
				oldbase = base;
				/*
				 * failed a critical constraint
				 * adjust and see if it still fits
				 */
				base = base & ~mask;
				base += (mask + 1);
				DEBUGPRT(CE_CONT, "\tnew base=%" PRIx64 "\n",
				    base);

				/*
				 * Check to see if the new base is past
				 * the end of the resource.
				 */
				if (base >= (oldbase + mapp->ra_len + 1)) {
					continue;
				}
			}

			if (req->ra_flags & NDI_RA_ALLOC_PARTIAL_OK) {
				if ((upper - mapp->ra_base)  <  mapp->ra_len)
					remlen = upper - base;
				else
					remlen = mapp->ra_len -
					    (base - mapp->ra_base);

				if ((backlargestp == NULL) ||
				    (largestlen < remlen)) {

					backlargestp = backp;
					largestbase = base;
					largestlen = remlen;
				}
			}

			if (mapp->ra_len >= len) {
				/* a candidate -- apply constraints */
				if ((len > (mapp->ra_len -
				    (base - mapp->ra_base))) ||
				    ((len - 1 + base) > upper)) {
					continue;
				}

				/* we have a fit */

				DEBUGPRT(CE_CONT, "\thave a fit\n");

				adjust_link(backp, mapp, base, len);
				rval = NDI_SUCCESS;
				break;

			}
		}
	} else {
		/* want an exact value/fit */
		base = req->ra_addr;
		len = req->ra_len;
		for (; mapp != NULL && mapp->ra_base <= upper;
		    backp = &(mapp->ra_next), mapp = mapp->ra_next) {
			if (base >= mapp->ra_base &&
			    ((base - mapp->ra_base) < mapp->ra_len)) {
				/*
				 * This is the node with the requested base in
				 * its range
				 */
				if ((len > mapp->ra_len) ||
				    (base - mapp->ra_base >
				    mapp->ra_len - len)) {
					/* length requirement not satisfied */
					if (req->ra_flags &
					    NDI_RA_ALLOC_PARTIAL_OK) {
						if ((upper - mapp->ra_base)
						    < mapp->ra_len)
							remlen = upper - base;
						else
							remlen =
							    mapp->ra_len -
							    (base -
							    mapp->ra_base);
					}
					backlargestp = backp;
					largestbase = base;
					largestlen = remlen;
					base = 0;
				} else {
					/* We have a match */
					adjust_link(backp, mapp, base, len);
					rval = NDI_SUCCESS;
				}
				break;
			}
		}
	}

	if ((rval != NDI_SUCCESS) &&
	    (req->ra_flags & NDI_RA_ALLOC_PARTIAL_OK) &&
	    (backlargestp != NULL)) {
		adjust_link(backlargestp, *backlargestp, largestbase,
		    largestlen);

		base = largestbase;
		len = largestlen;
		rval = NDI_RA_PARTIAL_REQ;
	}

	mutex_exit(&ra_lock);

	if (rval == NDI_FAILURE) {
		*retbasep = 0;
		*retlenp = 0;
	} else {
		*retbasep = base;
		*retlenp = len;
	}

	/*
	 * Update dip's "available" property, substract this piece of
	 * resource from the pool.
	 */
	if ((rval == NDI_SUCCESS) || (rval == NDI_RA_PARTIAL_REQ))
		(void) pci_get_available_prop(dipmap->ra_dip,
		    *retbasep, *retlenp, type);

	return (rval);
}

/*
 * isa_resource_setup
 *	check for /used-resources and initialize
 *	based on info there.  If no /used-resources,
 *	fail.
 */
int
isa_resource_setup()
{
	dev_info_t *used, *usedpdip;
	/*
	 * note that at this time bootconf creates 32 bit properties for
	 * io-space and device-memory
	 */
	struct iorange {
		uint32_t	base;
		uint32_t	len;
	} *iorange;
	struct memrange {
		uint32_t	base;
		uint32_t	len;
	} *memrange;
	uint32_t *irq;
	int proplen;
	int i, len;
	int maxrange;
	ndi_ra_request_t req;
	uint64_t retbase;
	uint64_t retlen;

	used = ddi_find_devinfo("used-resources", -1, 0);
	if (used == NULL) {
		DEBUGPRT(CE_CONT,
		    "isa_resource_setup: used-resources not found");
		return (NDI_FAILURE);
	}

	/*
	 * initialize to all resources being present
	 * and then remove the ones in use.
	 */

	usedpdip = ddi_root_node();

	DEBUGPRT(CE_CONT, "isa_resource_setup: used = %p usedpdip = %p\n",
	    (void *)used, (void *)usedpdip);

	if (ndi_ra_map_setup(usedpdip, NDI_RA_TYPE_IO) == NDI_FAILURE) {
		return (NDI_FAILURE);
	}

	/* initialize io space, highest end base is 0xffff */
	/* note that length is highest addr + 1 since starts from 0 */

	(void) ndi_ra_free(usedpdip, 0, 0xffff + 1,  NDI_RA_TYPE_IO, 0);

	if (ddi_getlongprop(DDI_DEV_T_ANY, used, DDI_PROP_DONTPASS,
	    "io-space", (caddr_t)&iorange, &proplen) == DDI_SUCCESS) {
		maxrange = proplen / sizeof (struct iorange);
		/* remove the "used" I/O resources */
		for (i = 0; i < maxrange; i++) {
			bzero((caddr_t)&req, sizeof (req));
			req.ra_addr =  (uint64_t)iorange[i].base;
			req.ra_len = (uint64_t)iorange[i].len;
			req.ra_flags = NDI_RA_ALLOC_SPECIFIED;
			(void) ndi_ra_alloc(usedpdip, &req, &retbase, &retlen,
			    NDI_RA_TYPE_IO, 0);
		}

		kmem_free((caddr_t)iorange, proplen);
	}

	if (ndi_ra_map_setup(usedpdip, NDI_RA_TYPE_MEM) == NDI_FAILURE) {
		return (NDI_FAILURE);
	}
	/* initialize memory space where highest end base is 0xffffffff */
	/* note that length is highest addr + 1 since starts from 0 */
	(void) ndi_ra_free(usedpdip, 0, ((uint64_t)((uint32_t)~0)) + 1,
	    NDI_RA_TYPE_MEM, 0);

	if (ddi_getlongprop(DDI_DEV_T_ANY, used, DDI_PROP_DONTPASS,
	    "device-memory", (caddr_t)&memrange, &proplen) == DDI_SUCCESS) {
		maxrange = proplen / sizeof (struct memrange);
		/* remove the "used" memory resources */
		for (i = 0; i < maxrange; i++) {
			bzero((caddr_t)&req, sizeof (req));
			req.ra_addr = (uint64_t)memrange[i].base;
			req.ra_len = (uint64_t)memrange[i].len;
			req.ra_flags = NDI_RA_ALLOC_SPECIFIED;
			(void) ndi_ra_alloc(usedpdip, &req, &retbase, &retlen,
			    NDI_RA_TYPE_MEM, 0);
		}

		kmem_free((caddr_t)memrange, proplen);
	}

	if (ndi_ra_map_setup(usedpdip, NDI_RA_TYPE_INTR) == NDI_FAILURE) {
		return (NDI_FAILURE);
	}

	/* initialize the interrupt space */
	(void) ndi_ra_free(usedpdip, 0, 16, NDI_RA_TYPE_INTR, 0);

#if defined(__i386) || defined(__amd64)
	bzero(&req, sizeof (req));
	req.ra_addr = 2;	/* 2 == 9 so never allow */
	req.ra_len = 1;
	req.ra_flags = NDI_RA_ALLOC_SPECIFIED;
	(void) ndi_ra_alloc(usedpdip, &req, &retbase, &retlen,
	    NDI_RA_TYPE_INTR, 0);
#endif

	if (ddi_getlongprop(DDI_DEV_T_ANY, used, DDI_PROP_DONTPASS,
	    "interrupts", (caddr_t)&irq, &proplen) == DDI_SUCCESS) {
		/* Initialize available interrupts by negating the used */
		len = (proplen / sizeof (uint32_t));
		for (i = 0; i < len; i++) {
			bzero((caddr_t)&req, sizeof (req));
			req.ra_addr = (uint64_t)irq[i];
			req.ra_len = 1;
			req.ra_flags = NDI_RA_ALLOC_SPECIFIED;
			(void) ndi_ra_alloc(usedpdip, &req, &retbase, &retlen,
			    NDI_RA_TYPE_INTR, 0);
		}
		kmem_free((caddr_t)irq, proplen);
	}

#ifdef BUSRA_DEBUG
	if (busra_debug) {
		(void) ra_dump_all(NULL, usedpdip);
	}
#endif
	return (NDI_SUCCESS);

}

#ifdef BUSRA_DEBUG
void
ra_dump_all(char *type, dev_info_t *dip)
{

	struct ra_type_map *typemap;
	struct ra_dip_type *dipmap;
	struct ra_resource *res;

	typemap =  (struct ra_type_map *)ra_map_list_head;

	for (; typemap != NULL; typemap = typemap->ra_next) {
		if (type != NULL) {
			if (strcmp(typemap->type, type) != 0)
				continue;
		}
		cmn_err(CE_CONT, "type is %s\n", typemap->type);
		for (dipmap = typemap->ra_dip_list; dipmap != NULL;
		    dipmap = dipmap->ra_next) {
			if (dip != NULL) {
				if ((dipmap->ra_dip) != dip)
					continue;
			}
			cmn_err(CE_CONT, "  dip is %p\n",
			    (void *)dipmap->ra_dip);
			for (res = dipmap->ra_rangeset; res != NULL;
			    res = res->ra_next) {
				cmn_err(CE_CONT, "\t  range is %" PRIx64
				    " %" PRIx64 "\n", res->ra_base,
				    res->ra_len);
			}
			if (dip != NULL)
				break;
		}
		if (type != NULL)
			break;
	}
}
#endif

struct bus_range {	/* 1275 "bus-range" property definition */
	uint32_t lo;
	uint32_t hi;
} pci_bus_range;

struct busnum_ctrl {
	int	rv;
	dev_info_t *dip;
	struct	bus_range *range;
};


/*
 * Setup resource map for the pci bus node based on the "available"
 * property and "bus-range" property.
 */
int
pci_resource_setup(dev_info_t *dip)
{
	pci_regspec_t *regs;
	int rlen, rcount, i;
	char bus_type[16] = "(unknown)";
	int len;
	struct busnum_ctrl ctrl;
	int circular_count;
	int rval = NDI_SUCCESS;

	/*
	 * If this is a pci bus node then look for "available" property
	 * to find the available resources on this bus.
	 */
	len = sizeof (bus_type);
	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "device_type",
	    (caddr_t)&bus_type, &len) != DDI_SUCCESS)
		return (NDI_FAILURE);

	/* it is not a pci/pci-ex bus type */
	if ((strcmp(bus_type, "pci") != 0) && (strcmp(bus_type, "pciex") != 0))
		return (NDI_FAILURE);

	/*
	 * The pci-hotplug project addresses adding the call
	 * to pci_resource_setup from pci nexus driver.
	 * However that project would initially be only for x86,
	 * so for sparc pcmcia-pci support we still need to call
	 * pci_resource_setup in pcic driver. Once all pci nexus drivers
	 * are updated to call pci_resource_setup this portion of the
	 * code would really become an assert to make sure this
	 * function is not called for the same dip twice.
	 */
	/*
	 * Another user for the check below is hotplug PCI/PCIe bridges.
	 *
	 * For PCI/PCIE devices under a PCIE hierarchy, ndi_ra_alloc/free
	 * will update the devinfo node's "available" property, to reflect
	 * the fact that a piece of resource has been removed/added to
	 * a devinfo node.
	 * During probe of a new PCI bridge in the hotplug case, PCI
	 * configurator firstly allocates maximum MEM/IO from its parent,
	 * then calls ndi_ra_free() to use these resources to setup busra
	 * pool for the new bridge, as well as adding these resources to
	 * the "available" property of the new devinfo node. Then configu-
	 * rator will attach driver for the bridge before probing its
	 * children, and the bridge driver will then initialize its hotplug
	 * contollers (if it supports hotplug) and HPC driver will call
	 * this function to setup the busra pool, but the resource pool
	 * has already been setup at the first of pcicfg_probe_bridge(),
	 * thus we need the check below to return directly in this case.
	 * Otherwise the ndi_ra_free() below will see overlapping resources.
	 */
	{
		if (ra_map_exist(dip, NDI_RA_TYPE_MEM) == NDI_SUCCESS) {
			return (NDI_FAILURE);
		}
	}


	/*
	 * Create empty resource maps first.
	 *
	 * NOTE: If all the allocated resources are already assigned to
	 * device(s) in the hot plug slot then "available" property may not
	 * be present. But, subsequent hot plug operation may unconfigure
	 * the device in the slot and try to free up it's resources. So,
	 * at the minimum we should create empty maps here.
	 */
	if (ndi_ra_map_setup(dip, NDI_RA_TYPE_MEM) == NDI_FAILURE) {
		return (NDI_FAILURE);
	}

	if (ndi_ra_map_setup(dip, NDI_RA_TYPE_IO) == NDI_FAILURE) {
		return (NDI_FAILURE);
	}

	if (ndi_ra_map_setup(dip, NDI_RA_TYPE_PCI_BUSNUM) == NDI_FAILURE) {
		return (NDI_FAILURE);
	}

	if (ndi_ra_map_setup(dip, NDI_RA_TYPE_PCI_PREFETCH_MEM) ==
	    NDI_FAILURE) {
		return (NDI_FAILURE);
	}

	/* read the "available" property if it is available */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "available", (caddr_t)&regs, &rlen) == DDI_SUCCESS) {
		/*
		 * Remove "available" property as the entries will be
		 * re-created in ndi_ra_free() below, note prom based
		 * property will not be removed. But in ndi_ra_free()
		 * we'll be creating non prom based property entries.
		 */
		(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, "available");
		/*
		 * create the available resource list for both memory and
		 * io space
		 */
		rcount = rlen / sizeof (pci_regspec_t);
		for (i = 0; i < rcount; i++) {
			switch (PCI_REG_ADDR_G(regs[i].pci_phys_hi)) {
			case PCI_REG_ADDR_G(PCI_ADDR_MEM32):
				(void) ndi_ra_free(dip,
				    (uint64_t)regs[i].pci_phys_low,
				    (uint64_t)regs[i].pci_size_low,
				    (regs[i].pci_phys_hi & PCI_REG_PF_M) ?
				    NDI_RA_TYPE_PCI_PREFETCH_MEM :
				    NDI_RA_TYPE_MEM,
				    0);
				break;
			case PCI_REG_ADDR_G(PCI_ADDR_MEM64):
				(void) ndi_ra_free(dip,
				    ((uint64_t)(regs[i].pci_phys_mid) << 32) |
				    ((uint64_t)(regs[i].pci_phys_low)),
				    ((uint64_t)(regs[i].pci_size_hi) << 32) |
				    ((uint64_t)(regs[i].pci_size_low)),
				    (regs[i].pci_phys_hi & PCI_REG_PF_M) ?
				    NDI_RA_TYPE_PCI_PREFETCH_MEM :
				    NDI_RA_TYPE_MEM,
				    0);
				break;
			case PCI_REG_ADDR_G(PCI_ADDR_IO):
				(void) ndi_ra_free(dip,
				    (uint64_t)regs[i].pci_phys_low,
				    (uint64_t)regs[i].pci_size_low,
				    NDI_RA_TYPE_IO,
				    0);
				break;
			case PCI_REG_ADDR_G(PCI_ADDR_CONFIG):
				break;
			default:
				cmn_err(CE_WARN,
				    "pci_resource_setup: bad addr type: %x\n",
				    PCI_REG_ADDR_G(regs[i].pci_phys_hi));
				break;
			}
		}
		kmem_free(regs, rlen);
	}

	/*
	 * update resource map for available bus numbers if the node
	 * has available-bus-range or bus-range property.
	 */
	len = sizeof (struct bus_range);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "available-bus-range", (caddr_t)&pci_bus_range, &len) ==
	    DDI_SUCCESS) {
		/*
		 * Add bus numbers in the range to the free list.
		 */
		(void) ndi_ra_free(dip, (uint64_t)pci_bus_range.lo,
		    (uint64_t)pci_bus_range.hi - (uint64_t)pci_bus_range.lo +
		    1, NDI_RA_TYPE_PCI_BUSNUM, 0);
	} else {
		/*
		 * We don't have an available-bus-range property. If, instead,
		 * we have a bus-range property we add all the bus numbers
		 * in that range to the free list but we must then scan
		 * for pci-pci bridges on this bus to find out the if there
		 * are any of those bus numbers already in use. If so, we can
		 * reclaim them.
		 */
		len = sizeof (struct bus_range);
		if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "bus-range", (caddr_t)&pci_bus_range,
		    &len) == DDI_SUCCESS) {
			if (pci_bus_range.lo != pci_bus_range.hi) {
				/*
				 * Add bus numbers other than the secondary
				 * bus number to the free list.
				 */
				(void) ndi_ra_free(dip,
				    (uint64_t)pci_bus_range.lo + 1,
				    (uint64_t)pci_bus_range.hi -
				    (uint64_t)pci_bus_range.lo,
				    NDI_RA_TYPE_PCI_BUSNUM, 0);

				/* scan for pci-pci bridges */
				ctrl.rv = DDI_SUCCESS;
				ctrl.dip = dip;
				ctrl.range = &pci_bus_range;
				ndi_devi_enter(dip, &circular_count);
				ddi_walk_devs(ddi_get_child(dip),
				    claim_pci_busnum, (void *)&ctrl);
				ndi_devi_exit(dip, circular_count);
				if (ctrl.rv != DDI_SUCCESS) {
					/* failed to create the map */
					(void) ndi_ra_map_destroy(dip,
					    NDI_RA_TYPE_PCI_BUSNUM);
					rval = NDI_FAILURE;
				}
			}
		}
	}

#ifdef BUSRA_DEBUG
	if (busra_debug) {
		(void) ra_dump_all(NULL, dip);
	}
#endif

	return (rval);
}

/*
 * If the device is a PCI bus device (i.e bus-range property exists) then
 * claim the bus numbers used by the device from the specified bus
 * resource map.
 */
static int
claim_pci_busnum(dev_info_t *dip, void *arg)
{
	struct bus_range pci_bus_range;
	struct busnum_ctrl *ctrl;
	ndi_ra_request_t req;
	char bus_type[16] = "(unknown)";
	int len;
	uint64_t base;
	uint64_t retlen;

	ctrl = (struct busnum_ctrl *)arg;

	/* check if this is a PCI bus node */
	len = sizeof (bus_type);
	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "device_type",
	    (caddr_t)&bus_type, &len) != DDI_SUCCESS)
		return (DDI_WALK_PRUNECHILD);

	/* it is not a pci/pci-ex bus type */
	if ((strcmp(bus_type, "pci") != 0) && (strcmp(bus_type, "pciex") != 0))
		return (DDI_WALK_PRUNECHILD);

	/* look for the bus-range property */
	len = sizeof (struct bus_range);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "bus-range", (caddr_t)&pci_bus_range, &len) == DDI_SUCCESS) {
		if ((pci_bus_range.lo >= ctrl->range->lo) &&
		    (pci_bus_range.hi <= ctrl->range->hi)) {

			/* claim the bus range from the bus resource map */
			bzero((caddr_t)&req, sizeof (req));
			req.ra_addr = (uint64_t)pci_bus_range.lo;
			req.ra_flags |= NDI_RA_ALLOC_SPECIFIED;
			req.ra_len = (uint64_t)pci_bus_range.hi -
			    (uint64_t)pci_bus_range.lo + 1;
			if (ndi_ra_alloc(ctrl->dip, &req, &base, &retlen,
			    NDI_RA_TYPE_PCI_BUSNUM, 0) == NDI_SUCCESS)
				return (DDI_WALK_PRUNECHILD);
		}
	}

	/*
	 * Error return.
	 */
	ctrl->rv = DDI_FAILURE;
	return (DDI_WALK_TERMINATE);
}

void
pci_resource_destroy(dev_info_t *dip)
{
	(void) ndi_ra_map_destroy(dip, NDI_RA_TYPE_IO);

	(void) ndi_ra_map_destroy(dip, NDI_RA_TYPE_MEM);

	(void) ndi_ra_map_destroy(dip, NDI_RA_TYPE_PCI_BUSNUM);

	(void) ndi_ra_map_destroy(dip, NDI_RA_TYPE_PCI_PREFETCH_MEM);
}


int
pci_resource_setup_avail(dev_info_t *dip, pci_regspec_t *avail_p, int entries)
{
	int i;

	if (ndi_ra_map_setup(dip, NDI_RA_TYPE_MEM) == NDI_FAILURE)
		return (NDI_FAILURE);
	if (ndi_ra_map_setup(dip, NDI_RA_TYPE_IO) == NDI_FAILURE)
		return (NDI_FAILURE);
	if (ndi_ra_map_setup(dip, NDI_RA_TYPE_PCI_PREFETCH_MEM) == NDI_FAILURE)
		return (NDI_FAILURE);

	/* for each entry in the PCI "available" property */
	for (i = 0; i < entries; i++, avail_p++) {
		if (avail_p->pci_phys_hi == -1u)
			goto err;

		switch (PCI_REG_ADDR_G(avail_p->pci_phys_hi)) {
		case PCI_REG_ADDR_G(PCI_ADDR_MEM32): {
			(void) ndi_ra_free(dip, (uint64_t)avail_p->pci_phys_low,
			    (uint64_t)avail_p->pci_size_low,
			    (avail_p->pci_phys_hi & PCI_REG_PF_M) ?
			    NDI_RA_TYPE_PCI_PREFETCH_MEM : NDI_RA_TYPE_MEM,
			    0);
			}
			break;
		case PCI_REG_ADDR_G(PCI_ADDR_IO):
			(void) ndi_ra_free(dip, (uint64_t)avail_p->pci_phys_low,
			    (uint64_t)avail_p->pci_size_low, NDI_RA_TYPE_IO, 0);
			break;
		default:
			goto err;
		}
	}
#ifdef BUSRA_DEBUG
	if (busra_debug) {
		(void) ra_dump_all(NULL, dip);
	}
#endif
	return (NDI_SUCCESS);

err:
	cmn_err(CE_WARN, "pci_resource_setup_avail: bad entry[%d]=%x\n",
	    i, avail_p->pci_phys_hi);
	return (NDI_FAILURE);
}

/*
 * Return true if the devinfo node resides on PCI or PCI Express bus,
 * sitting in a PCI Express hierarchy.
 */
static boolean_t
is_pcie_fabric(dev_info_t *dip)
{
	dev_info_t *root = ddi_root_node();
	dev_info_t *pdip;
	boolean_t found = B_FALSE;
	char *bus;

	/*
	 * Is this pci/pcie ?
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "device_type", &bus) !=
	    DDI_PROP_SUCCESS) {
		DEBUGPRT(CE_WARN, "is_pcie_fabric: cannot find "
		    "\"device_type\" property for dip %p\n", (void *)dip);
		return (B_FALSE);
	}

	if (strcmp(bus, "pciex") == 0) {
		/* pcie bus, done */
		ddi_prop_free(bus);
		return (B_TRUE);
	} else if (strcmp(bus, "pci") == 0) {
		/*
		 * pci bus, fall through to check if it resides in
		 * a pcie hierarchy.
		 */
		ddi_prop_free(bus);
	} else {
		/* other bus, return failure */
		ddi_prop_free(bus);
		return (B_FALSE);
	}

	/*
	 * Does this device reside in a pcie fabric ?
	 */
	for (pdip = ddi_get_parent(dip); pdip && (pdip != root) &&
	    !found; pdip = ddi_get_parent(pdip)) {
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, pdip,
		    DDI_PROP_DONTPASS, "device_type", &bus) !=
		    DDI_PROP_SUCCESS)
			break;

		if (strcmp(bus, "pciex") == 0)
			found = B_TRUE;

		ddi_prop_free(bus);
	}

	return (found);
}

/*
 * Remove a piece of IO/MEM resource from "available" property of 'dip'.
 */
static int
pci_get_available_prop(dev_info_t *dip, uint64_t base, uint64_t len,
    char *busra_type)
{
	pci_regspec_t	*regs, *newregs;
	uint_t		status;
	int		rlen, rcount;
	int		i, j, k;
	uint64_t	dlen;
	boolean_t	found = B_FALSE;
	uint32_t	type;

	/* check if we're manipulating MEM/IO resource */
	if ((type = pci_type_ra2pci(busra_type)) == PCI_ADDR_TYPE_INVAL)
		return (DDI_SUCCESS);

	/* check if dip is a pci/pcie device resides in a pcie fabric */
	if (!is_pcie_fabric(dip))
		return (DDI_SUCCESS);

	status = ddi_getlongprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "available", (caddr_t)&regs, &rlen);

	ASSERT(status == DDI_SUCCESS);
	if (status != DDI_SUCCESS)
		return (status);

	/*
	 * The updated "available" property will at most have one more entry
	 * than existing one (when the requested range is in the middle of
	 * the matched property entry)
	 */
	newregs = kmem_alloc(rlen + sizeof (pci_regspec_t), KM_SLEEP);

	rcount = rlen / sizeof (pci_regspec_t);
	for (i = 0, j = 0; i < rcount; i++) {
		if (type == (regs[i].pci_phys_hi & PCI_ADDR_TYPE_MASK)) {
			uint64_t range_base, range_len;

			range_base = ((uint64_t)(regs[i].pci_phys_mid) << 32) |
			    ((uint64_t)(regs[i].pci_phys_low));
			range_len = ((uint64_t)(regs[i].pci_size_hi) << 32) |
			    ((uint64_t)(regs[i].pci_size_low));

			if ((base < range_base) ||
			    (base + len > range_base + range_len)) {
				/*
				 * not a match, copy the entry
				 */
				goto copy_entry;
			}

			/*
			 * range_base	base	base+len	range_base
			 *					+range_len
			 *   +------------+-----------+----------+
			 *   |		  |///////////|		 |
			 *   +------------+-----------+----------+
			 */
			/*
			 * Found a match, remove the range out of this entry.
			 */
			found = B_TRUE;

			dlen = base - range_base;
			if (dlen != 0) {
				newregs[j].pci_phys_hi = regs[i].pci_phys_hi;
				newregs[j].pci_phys_mid =
				    (uint32_t)(range_base >> 32);
				newregs[j].pci_phys_low =
				    (uint32_t)(range_base);
				newregs[j].pci_size_hi = (uint32_t)(dlen >> 32);
				newregs[j].pci_size_low = (uint32_t)dlen;
				j++;
			}

			dlen = (range_base + range_len) - (base + len);
			if (dlen != 0) {
				newregs[j].pci_phys_hi = regs[i].pci_phys_hi;
				newregs[j].pci_phys_mid =
				    (uint32_t)((base + len)>> 32);
				newregs[j].pci_phys_low =
				    (uint32_t)(base + len);
				newregs[j].pci_size_hi = (uint32_t)(dlen >> 32);
				newregs[j].pci_size_low = (uint32_t)dlen;
				j++;
			}

			/*
			 * We've allocated the resource from the matched
			 * entry, almost finished but still need to copy
			 * the rest entries from the original property
			 * array.
			 */
			for (k = i + 1; k < rcount; k++) {
				newregs[j] = regs[k];
				j++;
			}

			goto done;

		} else {
copy_entry:
			newregs[j] = regs[i];
			j++;
		}
	}

done:
	/*
	 * This should not fail so assert it. For non-debug kernel we don't
	 * want to panic thus only logging a warning message.
	 */
	ASSERT(found == B_TRUE);
	if (!found) {
		cmn_err(CE_WARN, "pci_get_available_prop: failed to remove "
		    "resource from dip %p : base 0x%" PRIx64 ", len 0x%" PRIX64
		    ", type 0x%x\n", (void *)dip, base, len, type);
		kmem_free(newregs, rlen + sizeof (pci_regspec_t));
		kmem_free(regs, rlen);

		return (DDI_FAILURE);
	}

	/*
	 * Found the resources from parent, update the "available"
	 * property.
	 */
	if (j == 0) {
		/* all the resources are consumed, remove the property */
		(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, "available");
	} else {
		/*
		 * There are still resource available in the parent dip,
		 * update with the remaining resources.
		 */
		(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
		    "available", (int *)newregs,
		    (j * sizeof (pci_regspec_t)) / sizeof (int));
	}

	kmem_free(newregs, rlen + sizeof (pci_regspec_t));
	kmem_free(regs, rlen);

	return (DDI_SUCCESS);
}

/*
 * Add a piece of IO/MEM resource to "available" property of 'dip'.
 */
static int
pci_put_available_prop(dev_info_t *dip, uint64_t base, uint64_t len,
    char *busra_type)
{
	pci_regspec_t	*regs, *newregs;
	uint_t		status;
	int		rlen, rcount;
	int		i, j, k;
	int		matched = 0;
	uint64_t	orig_base = base;
	uint64_t	orig_len = len;
	uint32_t	type;

	/* check if we're manipulating MEM/IO resource */
	if ((type = pci_type_ra2pci(busra_type)) == PCI_ADDR_TYPE_INVAL)
		return (DDI_SUCCESS);

	/* check if dip is a pci/pcie device resides in a pcie fabric */
	if (!is_pcie_fabric(dip))
		return (DDI_SUCCESS);

	status = ddi_getlongprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "available", (caddr_t)&regs, &rlen);

	switch (status) {
		case DDI_PROP_NOT_FOUND:
			goto not_found;

		case DDI_PROP_SUCCESS:
			break;

		default:
			return (status);
	}

	/*
	 * The "available" property exist on the node, try to put this
	 * resource back, merge if there are adjacent resources.
	 *
	 * The updated "available" property will at most have one more entry
	 * than existing one (when there is no adjacent entries thus the new
	 * resource is appended at the end)
	 */
	newregs = kmem_alloc(rlen + sizeof (pci_regspec_t), KM_SLEEP);

	rcount = rlen / sizeof (pci_regspec_t);
	for (i = 0, j = 0; i < rcount; i++) {
		if (type == (regs[i].pci_phys_hi & PCI_ADDR_TYPE_MASK)) {
			uint64_t range_base, range_len;

			range_base = ((uint64_t)(regs[i].pci_phys_mid) << 32) |
			    ((uint64_t)(regs[i].pci_phys_low));
			range_len = ((uint64_t)(regs[i].pci_size_hi) << 32) |
			    ((uint64_t)(regs[i].pci_size_low));

			if ((base + len < range_base) ||
			    (base > range_base + range_len)) {
				/*
				 * Not adjacent, copy the entry and contiue
				 */
				goto copy_entry;
			}

			/*
			 * Adjacent or overlap?
			 *
			 * Should not have overlapping resources so assert it.
			 * For non-debug kernel we don't want to panic thus
			 * only logging a warning message.
			 */
#if 0
			ASSERT((base + len == range_base) ||
			    (base == range_base + range_len));
#endif
			if ((base + len != range_base) &&
			    (base != range_base + range_len)) {
				cmn_err(CE_WARN, "pci_put_available_prop: "
				    "failed to add resource to dip %p : "
				    "base 0x%" PRIx64 ", len 0x%" PRIx64 " "
				    "overlaps with existing resource "
				    "base 0x%" PRIx64 ", len 0x%" PRIx64 "\n",
				    (void *)dip, orig_base, orig_len,
				    range_base, range_len);

				goto failure;
			}

			/*
			 * On the left:
			 *
			 * base		range_base
			 *   +-------------+-------------+
			 *   |/////////////|		 |
			 *   +-------------+-------------+
			 *	len		range_len
			 *
			 * On the right:
			 *
			 * range_base	 base
			 *   +-------------+-------------+
			 *   |		   |/////////////|
			 *   +-------------+-------------+
			 *	range_len	len
			 */
			/*
			 * There are at most two piece of resources adjacent
			 * with this resource, assert it.
			 */
			ASSERT(matched < 2);

			if (!(matched < 2)) {
				cmn_err(CE_WARN, "pci_put_available_prop: "
				    "failed to add resource to dip %p : "
				    "base 0x%" PRIx64 ", len 0x%" PRIx64 " "
				    "found overlaps in existing resources\n",
				    (void *)dip, orig_base, orig_len);

				goto failure;
			}

			/* setup base & len to refer to the merged range */
			len += range_len;
			if (base == range_base + range_len)
				base = range_base;

			if (matched == 0) {
				/*
				 * One adjacent entry, add this resource in
				 */
				newregs[j].pci_phys_hi = regs[i].pci_phys_hi;
				newregs[j].pci_phys_mid =
				    (uint32_t)(base >> 32);
				newregs[j].pci_phys_low = (uint32_t)(base);
				newregs[j].pci_size_hi = (uint32_t)(len >> 32);
				newregs[j].pci_size_low = (uint32_t)len;

				matched = 1;
				k = j;
				j++;
			} else { /* matched == 1 */
				/*
				 * Two adjacent entries, merge them together
				 */
				newregs[k].pci_phys_hi = regs[i].pci_phys_hi;
				newregs[k].pci_phys_mid =
				    (uint32_t)(base >> 32);
				newregs[k].pci_phys_low = (uint32_t)(base);
				newregs[k].pci_size_hi = (uint32_t)(len >> 32);
				newregs[k].pci_size_low = (uint32_t)len;

				matched = 2;
			}
		} else {
copy_entry:
			newregs[j] = regs[i];
			j++;
		}
	}

	if (matched == 0) {
		/* No adjacent entries, append at end */
		ASSERT(j == rcount);

		/*
		 * According to page 15 of 1275 spec, bit "n" of "available"
		 * should be set to 1.
		 */
		newregs[j].pci_phys_hi = type;
		newregs[j].pci_phys_hi |= PCI_REG_REL_M;

		newregs[j].pci_phys_mid = (uint32_t)(base >> 32);
		newregs[j].pci_phys_low = (uint32_t)base;
		newregs[j].pci_size_hi = (uint32_t)(len >> 32);
		newregs[j].pci_size_low = (uint32_t)len;

		j++;
	}

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "available", (int *)newregs,
	    (j * sizeof (pci_regspec_t)) / sizeof (int));

	kmem_free(newregs, rlen + sizeof (pci_regspec_t));
	kmem_free(regs, rlen);
	return (DDI_SUCCESS);

not_found:
	/*
	 * There is no "available" property on the parent node, create it.
	 */
	newregs = kmem_alloc(sizeof (pci_regspec_t), KM_SLEEP);

	/*
	 * According to page 15 of 1275 spec, bit "n" of "available" should
	 * be set to 1.
	 */
	newregs[0].pci_phys_hi = type;
	newregs[0].pci_phys_hi |= PCI_REG_REL_M;

	newregs[0].pci_phys_mid = (uint32_t)(base >> 32);
	newregs[0].pci_phys_low = (uint32_t)base;
	newregs[0].pci_size_hi = (uint32_t)(len >> 32);
	newregs[0].pci_size_low = (uint32_t)len;

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "available", (int *)newregs,
	    sizeof (pci_regspec_t) / sizeof (int));
	kmem_free(newregs, sizeof (pci_regspec_t));
	return (DDI_SUCCESS);

failure:
	kmem_free(newregs, rlen + sizeof (pci_regspec_t));
	kmem_free(regs, rlen);
	return (DDI_FAILURE);
}

static uint32_t
pci_type_ra2pci(char *type)
{
	uint32_t	pci_type = PCI_ADDR_TYPE_INVAL;

	/*
	 * No 64 bit mem support for now
	 */
	if (strcmp(type, NDI_RA_TYPE_IO) == 0) {
		pci_type = PCI_ADDR_IO;

	} else if (strcmp(type, NDI_RA_TYPE_MEM) == 0) {
		pci_type = PCI_ADDR_MEM32;

	} else if (strcmp(type, NDI_RA_TYPE_PCI_PREFETCH_MEM)  == 0) {
		pci_type = PCI_ADDR_MEM32;
		pci_type |= PCI_REG_PF_M;
	}

	return (pci_type);
}
