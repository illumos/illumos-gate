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

/*
 * fcpci.c: Framework PCI fcode ops
 */
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/pci.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddidmareq.h>
#include <sys/pci.h>
#include <sys/modctl.h>
#include <sys/ndi_impldefs.h>
#include <sys/fcode.h>
#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/ddi_implfuncs.h>

#define	PCI_NPT_bits		(PCI_RELOCAT_B | PCI_PREFETCH_B | PCI_ALIAS_B)
#define	PCI_BDF_bits		(PCI_REG_BDFR_M & ~PCI_REG_REG_M)

#define	PCICFG_CONF_INDIRECT_MAP	1

static int pfc_map_in(dev_info_t *, fco_handle_t, fc_ci_t *);
static int pfc_map_out(dev_info_t *, fco_handle_t, fc_ci_t *);
static int pfc_dma_map_in(dev_info_t *, fco_handle_t, fc_ci_t *);
static int pfc_dma_map_out(dev_info_t *, fco_handle_t, fc_ci_t *);
static int pfc_dma_sync(dev_info_t *, fco_handle_t, fc_ci_t *);
static int pfc_dma_cleanup(dev_info_t *, fco_handle_t, fc_ci_t *);

static int pfc_register_fetch(dev_info_t *, fco_handle_t, fc_ci_t *);
static int pfc_register_store(dev_info_t *, fco_handle_t, fc_ci_t *);
static int pfc_config_fetch(dev_info_t *, fco_handle_t, fc_ci_t *);
static int pfc_config_store(dev_info_t *, fco_handle_t, fc_ci_t *);

static int pfc_probe_address(dev_info_t *, fco_handle_t, fc_ci_t *);
static int pfc_probe_space(dev_info_t *, fco_handle_t, fc_ci_t *);

static int pfc_config_child(dev_info_t *, fco_handle_t, fc_ci_t *);
static int pfc_get_fcode_size(dev_info_t *, fco_handle_t, fc_ci_t *);
static int pfc_get_fcode(dev_info_t *, fco_handle_t, fc_ci_t *);
int prom_get_fcode_size(char *);
int prom_get_fcode(char *, char *);
int pfc_update_assigned_prop(dev_info_t *, pci_regspec_t *);
int pfc_remove_assigned_prop(dev_info_t *, pci_regspec_t *);
int pci_alloc_resource(dev_info_t *, pci_regspec_t);
int pci_free_resource(dev_info_t *, pci_regspec_t);
int pci_alloc_mem_chunk(dev_info_t *,  uint64_t, uint64_t *,  uint64_t *);
int pci_alloc_io_chunk(dev_info_t *,  uint64_t,  uint64_t *, uint64_t *);
static int fcpci_indirect_map(dev_info_t *);

int fcpci_unloadable;

static ddi_dma_attr_t fcpci_dma_attr = {
	DMA_ATTR_V0,	/* version number */
	0x0,		/* lowest usable address */
	0xFFFFFFFFull,	/* high DMA address range */
	0xFFFFFFFFull,	/* DMA counter register */
	1,		/* DMA address alignment */
	1,		/* DMA burstsizes */
	1,		/* min effective DMA size */
	0xFFFFFFFFull,	/* max DMA xfer size */
	0xFFFFFFFFull,	/* segment boundary */
	1,		 /* s/g list length */
	1,		/* granularity of device */
	0		/* DMA transfer flags */
};

#ifndef	lint
char _depends_on[] = "misc/fcodem misc/busra";
#endif

#define	HIADDR(n) ((uint32_t)(((uint64_t)(n) & 0xFFFFFFFF00000000)>> 32))
#define	LOADDR(n)((uint32_t)((uint64_t)(n) & 0x00000000FFFFFFFF))
#define	LADDR(lo, hi)    (((uint64_t)(hi) << 32) | (uint32_t)(lo))
#define	PCI_4GIG_LIMIT 0xFFFFFFFFUL
#define	PCI_MEMGRAN 0x100000
#define	PCI_IOGRAN 0x1000


/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops, "FCode pci bus functions"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	if (fcpci_unloadable)
		return (mod_remove(&modlinkage));
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


struct pfc_ops_v {
	char *svc_name;
	fc_ops_t *f;
};

static struct pfc_ops_v pov[] = {
	{	"map-in",		pfc_map_in},
	{	"map-out",		pfc_map_out},
	{	"dma-map-in",		pfc_dma_map_in},
	{	"dma-map-out",		pfc_dma_map_out},
	{	"dma-sync",		pfc_dma_sync},
	{	"rx@",			pfc_register_fetch},
	{	"rl@",			pfc_register_fetch},
	{	"rw@",			pfc_register_fetch},
	{	"rb@",			pfc_register_fetch},
	{	"rx!",			pfc_register_store},
	{	"rl!",			pfc_register_store},
	{	"rw!",			pfc_register_store},
	{	"rb!",			pfc_register_store},
	{	"config-l@",		pfc_config_fetch},
	{	"config-w@",		pfc_config_fetch},
	{	"config-b@",		pfc_config_fetch},
	{	"config-l!",		pfc_config_store},
	{	"config-w!",		pfc_config_store},
	{	"config-b!",		pfc_config_store},
	{	FC_PROBE_ADDRESS,	pfc_probe_address},
	{	FC_PROBE_SPACE,		pfc_probe_space},
	{	FC_SVC_EXIT,		pfc_dma_cleanup},
	{	FC_CONFIG_CHILD,	pfc_config_child},
	{	FC_GET_FCODE_SIZE,	pfc_get_fcode_size},
	{	FC_GET_FCODE,		pfc_get_fcode},
	{	NULL,			NULL}
};

static struct pfc_ops_v shared_pov[] = {
	{	FC_SVC_EXIT,		pfc_dma_cleanup},
	{	NULL,			NULL}
};

int pci_map_phys(dev_info_t *, pci_regspec_t *,
    caddr_t *, ddi_device_acc_attr_t *, ddi_acc_handle_t *);

void pci_unmap_phys(ddi_acc_handle_t *, pci_regspec_t *);

fco_handle_t
pci_fc_ops_alloc_handle(dev_info_t *ap, dev_info_t *child,
    void *fcode, size_t fcode_size, char *unit_address,
    struct pci_ops_bus_args *up)
{
	fco_handle_t rp;
	struct pci_ops_bus_args *bp = NULL;
	phandle_t h;

	rp = kmem_zalloc(sizeof (struct fc_resource_list), KM_SLEEP);
	rp->next_handle = fc_ops_alloc_handle(ap, child, fcode, fcode_size,
	    unit_address, NULL);
	rp->ap = ap;
	rp->child = child;
	rp->fcode = fcode;
	rp->fcode_size = fcode_size;
	if (unit_address) {
		char *buf;

		buf = kmem_zalloc(strlen(unit_address) + 1, KM_SLEEP);
		(void) strcpy(buf, unit_address);
		rp->unit_address = buf;
	}

	bp = kmem_zalloc(sizeof (struct pci_ops_bus_args), KM_SLEEP);
	*bp = *up;
	rp->bus_args = bp;

	/*
	 * Add the child's nodeid to our table...
	 */
	h = ddi_get_nodeid(rp->child);
	fc_add_dip_to_phandle(fc_handle_to_phandle_head(rp), rp->child, h);

	return (rp);
}

void
pci_fc_ops_free_handle(fco_handle_t rp)
{
	struct pci_ops_bus_args *bp;
	struct fc_resource *ip, *np;

	ASSERT(rp);

	if (rp->next_handle)
		fc_ops_free_handle(rp->next_handle);
	if (rp->unit_address)
		kmem_free(rp->unit_address, strlen(rp->unit_address) + 1);
	if ((bp = rp->bus_args) != NULL)
		kmem_free(bp, sizeof (struct pci_ops_bus_args));

	/*
	 * Release all the resources from the resource list
	 * XXX: We don't handle 'unknown' types, but we don't create them.
	 */
	for (ip = rp->head; ip != NULL; ip = np) {
		np = ip->next;
		switch (ip->type) {
		case RT_MAP:
			FC_DEBUG1(1, CE_CONT, "pci_fc_ops_free: "
			    "pci_unmap_phys(%p)\n", ip->fc_map_handle);
			pci_unmap_phys(&ip->fc_map_handle, ip->fc_regspec);
			kmem_free(ip->fc_regspec, sizeof (pci_regspec_t));
			break;
		case RT_DMA:
			/* DMA has to be freed up at exit time */
			cmn_err(CE_CONT, "pfc_fc_ops_free: DMA seen!\n");
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
pci_fc_ops(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	struct pfc_ops_v *pv;
	char *name = fc_cell2ptr(cp->svc_name);

	ASSERT(rp);

	/*
	 * First try the generic fc_ops. If the ops is a shared op,
	 * also call our local function.
	 */
	if (fc_ops(ap, rp->next_handle, cp) == 0) {
		for (pv = shared_pov; pv->svc_name != NULL; ++pv)
			if (strcmp(pv->svc_name, name) == 0)
				return (pv->f(ap, rp, cp));
		return (0);
	}

	for (pv = pov; pv->svc_name != NULL; ++pv)
		if (strcmp(pv->svc_name, name) == 0)
			return (pv->f(ap, rp, cp));

	FC_DEBUG1(9, CE_CONT, "pci_fc_ops: <%s> not serviced\n", name);

	return (-1);
}

/*
 * Create a dma mapping for a given user address.
 */
static int
pfc_dma_map_in(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	ddi_dma_handle_t h;
	int error;
	caddr_t virt;
	size_t len;
	uint_t flags = DDI_DMA_RDWR | DDI_DMA_CONSISTENT;
	struct fc_resource *ip;
	ddi_dma_cookie_t c;
	struct buf *bp;
	uint_t ccnt;

	if (fc_cell2int(cp->nargs) != 3)
		return (fc_syntax_error(cp, "nargs must be 3"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	/*
	 * XXX: It's not clear what we should do with a non-cacheable request
	 */
	virt = fc_cell2ptr(fc_arg(cp, 2));
	len = fc_cell2size(fc_arg(cp, 1));
#ifdef	notdef
	cacheable = fc_cell2int(fc_arg(cp, 0));	/* XXX: do what? */
#endif

	FC_DEBUG2(6, CE_CONT, "pcf_dma_map_in: virt %p, len %d\n", virt, len);

	/*
	 * Set up the address space for physio from userland
	 */
	error = fc_physio_setup(&bp, virt, len);

	if (error)  {
		FC_DEBUG3(1, CE_CONT, "pfc_dma_map_in: fc_physio_setup failed "
		    "error: %d  virt: %p  len %d\n", error, virt, len);
		return (fc_priv_error(cp, "fc_physio_setup failed"));
	}

	FC_DEBUG1(9, CE_CONT, "pfc_dma_map_in: dma_map_in; bp = %p\n", bp);
	error = fc_ddi_dma_alloc_handle(ap, &fcpci_dma_attr, DDI_DMA_SLEEP,
	    NULL, &h);
	if (error != DDI_SUCCESS)  {
		FC_DEBUG3(1, CE_CONT, "pfc_dma_map_in: real dma-map-in failed "
		    "error: %d  virt: %p  len %d\n", error, virt, len);
		return (fc_priv_error(cp, "real dma-map-in failed"));
	}

	error = fc_ddi_dma_buf_bind_handle(h, bp, flags, DDI_DMA_SLEEP, NULL,
	    &c, &ccnt);
	if ((error != DDI_DMA_MAPPED) || (ccnt != 1)) {
		fc_ddi_dma_free_handle(&h);
		FC_DEBUG3(1, CE_CONT, "pfc_dma_map_in: real dma-map-in failed "
		    "error: %d  virt: %p  len %d\n", error, virt, len);
		return (fc_priv_error(cp, "real dma-map-in failed"));
	}

	if (c.dmac_size < len)  {
		error = fc_ddi_dma_unbind_handle(h);
		if (error != DDI_SUCCESS) {
			return (fc_priv_error(cp, "ddi_dma_unbind error"));
		}
		fc_ddi_dma_free_handle(&h);
		return (fc_priv_error(cp, "ddi_dma_buf_bind size < len"));
	}

	FC_DEBUG1(9, CE_CONT, "pfc_dma_map_in: returning devaddr %x\n",
		c.dmac_address);

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = fc_uint32_t2cell(c.dmac_address);	/* XXX size */

	/*
	 * Now we have to log this resource saving the handle and buf header
	 */
	ip = kmem_zalloc(sizeof (struct fc_resource), KM_SLEEP);
	ip->type = RT_DMA;
	ip->fc_dma_virt = virt;
	ip->fc_dma_len = len;
	ip->fc_dma_handle = h;
	ip->fc_dma_devaddr = c.dmac_address;
	ip->fc_dma_bp = bp;
	fc_add_resource(rp, ip);

	return (fc_success_op(ap, rp, cp));
}

static int
pfc_dma_sync(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	void *virt;
	size_t len;
	uint32_t devaddr;
	int error;
	struct fc_resource *ip;

	if (fc_cell2int(cp->nargs) != 3)
		return (fc_syntax_error(cp, "nargs must be 3"));

	virt = fc_cell2ptr(fc_arg(cp, 2));
	devaddr = fc_cell2uint32_t(fc_arg(cp, 1));
	len = fc_cell2size(fc_arg(cp, 0));

	/*
	 * Find if this virt is 'within' a request we know about
	 */
	fc_lock_resource_list(rp);
	for (ip = rp->head; ip != NULL; ip = ip->next) {
		if (ip->type != RT_DMA)
			continue;
		if (ip->fc_dma_devaddr != devaddr)
			continue;
		if (((char *)virt >= (char *)ip->fc_dma_virt) &&
		    (((char *)virt + len) <=
		    ((char *)ip->fc_dma_virt + ip->fc_dma_len)))
			break;
	}
	fc_unlock_resource_list(rp);

	if (ip == NULL)
		return (fc_priv_error(cp, "request not within a "
		    "known dma mapping"));

	/*
	 * We know about this request, so we trust it enough to sync it.
	 * Unfortunately, we don't know which direction, so we'll do
	 * both directions.
	 */

	error = fc_ddi_dma_sync(ip->fc_dma_handle,
	    (char *)virt - (char *)ip->fc_dma_virt, len, DDI_DMA_SYNC_FORCPU);
	error |= fc_ddi_dma_sync(ip->fc_dma_handle,
	    (char *)virt - (char *)ip->fc_dma_virt, len, DDI_DMA_SYNC_FORDEV);

	if (error)
		return (fc_priv_error(cp, "Call to ddi_dma_sync failed"));

	cp->nresults = fc_int2cell(0);
	return (fc_success_op(ap, rp, cp));
}

static int
pfc_dma_map_out(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	void *virt;
	size_t len;
	uint32_t devaddr;
	struct fc_resource *ip;
	int e;

	if (fc_cell2int(cp->nargs) != 3)
		return (fc_syntax_error(cp, "nargs must be 3"));

	virt = fc_cell2ptr(fc_arg(cp, 2));
	devaddr = fc_cell2uint32_t(fc_arg(cp, 1));
	len = fc_cell2size(fc_arg(cp, 0));

	/*
	 * Find if this virt matches a request we know about
	 */
	fc_lock_resource_list(rp);
	for (ip = rp->head; ip != NULL; ip = ip->next) {
		if (ip->type != RT_DMA)
			continue;
		if (ip->fc_dma_devaddr != devaddr)
			continue;
		if (ip->fc_dma_virt != virt)
			continue;
		if (len == ip->fc_dma_len)
			break;
	}
	fc_unlock_resource_list(rp);

	if (ip == NULL)
		return (fc_priv_error(cp, "request doesn't match a "
		    "known dma mapping"));

	/*
	 * ddi_dma_unbind_handle does an implied sync ...
	 */
	e = fc_ddi_dma_unbind_handle(ip->fc_dma_handle);
	if (e != DDI_SUCCESS) {
		cmn_err(CE_CONT, "pfc_dma_map_out: ddi_dma_unbind failed!\n");
	}
	fc_ddi_dma_free_handle(&ip->fc_dma_handle);

	/*
	 * Tear down the physio mappings
	 */
	fc_physio_free(&ip->fc_dma_bp, ip->fc_dma_virt, ip->fc_dma_len);

	/*
	 * remove the resource from the list and release it.
	 */
	fc_rem_resource(rp, ip);
	kmem_free(ip, sizeof (struct fc_resource));

	cp->nresults = fc_int2cell(0);
	return (fc_success_op(ap, rp, cp));
}

static struct fc_resource *
next_dma_resource(fco_handle_t rp)
{
	struct fc_resource *ip;

	fc_lock_resource_list(rp);
	for (ip = rp->head; ip != NULL; ip = ip->next)
		if (ip->type == RT_DMA)
			break;
	fc_unlock_resource_list(rp);

	return (ip);
}

static int
pfc_dma_cleanup(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	struct fc_resource *ip;
	int e;

	while ((ip = next_dma_resource(rp)) != NULL) {

		FC_DEBUG2(9, CE_CONT, "pfc_dma_cleanup: virt %x len %x\n",
			ip->fc_dma_virt, ip->fc_dma_len);

		/*
		 * Free the dma handle
		 */
		e = fc_ddi_dma_unbind_handle(ip->fc_dma_handle);
		if (e != DDI_SUCCESS) {
			cmn_err(CE_CONT, "pfc_dma_cleanup: "
			    "ddi_dma_unbind failed!\n");
		}
		fc_ddi_dma_free_handle(&ip->fc_dma_handle);

		/*
		 * Tear down the userland mapping and free the buf header
		 */
		fc_physio_free(&ip->fc_dma_bp, ip->fc_dma_virt, ip->fc_dma_len);

		fc_rem_resource(rp, ip);
		kmem_free(ip, sizeof (struct fc_resource));
	}

	cp->nresults = fc_int2cell(0);
	return (fc_success_op(ap, rp, cp));
}

static int
pfc_map_in(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	size_t len;
	int error;
	caddr_t virt;
	pci_regspec_t p, *ph;
	struct fc_resource *ip;
	ddi_device_acc_attr_t acc;
	ddi_acc_handle_t h;

	if (fc_cell2int(cp->nargs) != 4)
		return (fc_syntax_error(cp, "nargs must be 4"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	p.pci_size_hi = 0;
	p.pci_size_low = len = fc_cell2size(fc_arg(cp, 0));

	p.pci_phys_hi = fc_cell2uint(fc_arg(cp, 1));
	p.pci_phys_mid = fc_cell2uint(fc_arg(cp, 2));
	p.pci_phys_low = fc_cell2uint(fc_arg(cp, 3));

	acc.devacc_attr_version = DDI_DEVICE_ATTR_V0;

	/*
	 * Fcode is expecting the bytes are not swapped.
	 */
	acc.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	acc.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/*
	 * First We need to allocate the PCI Resource.
	 */
	error = pci_alloc_resource(rp->child, p);

	if (error)  {
		return (fc_priv_error(cp, "pci map-in failed"));
	}

	error = pci_map_phys(rp->child, &p, &virt, &acc, &h);

	if (error)  {
		return (fc_priv_error(cp, "pci map-in failed"));
	}

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = fc_ptr2cell(virt);

	/*
	 * Log this resource ...
	 */
	ip = kmem_zalloc(sizeof (struct fc_resource), KM_SLEEP);
	ip->type = RT_MAP;
	ip->fc_map_virt = virt;
	ip->fc_map_len = len;
	ip->fc_map_handle = h;
	ph = kmem_zalloc(sizeof (pci_regspec_t), KM_SLEEP);
	*ph = p;
	ip->fc_regspec = ph;	/* cache a copy of the reg spec */
	fc_add_resource(rp, ip);

	return (fc_success_op(ap, rp, cp));
}

static int
pfc_map_out(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	caddr_t virt;
	size_t len;
	struct fc_resource *ip;

	if (fc_cell2int(cp->nargs) != 2)
		return (fc_syntax_error(cp, "nargs must be 2"));

	virt = fc_cell2ptr(fc_arg(cp, 1));

	len = fc_cell2size(fc_arg(cp, 0));

	/*
	 * Find if this request matches a mapping resource we set up.
	 */
	fc_lock_resource_list(rp);
	for (ip = rp->head; ip != NULL; ip = ip->next) {
		if (ip->type != RT_MAP)
			continue;
		if (ip->fc_map_virt != virt)
			continue;
		if (ip->fc_map_len == len)
			break;
	}
	fc_unlock_resource_list(rp);

	if (ip == NULL)
		return (fc_priv_error(cp, "request doesn't match a "
		    "known mapping"));

	pci_unmap_phys(&ip->fc_map_handle, ip->fc_regspec);

	kmem_free(ip->fc_regspec, sizeof (pci_regspec_t));

	/*
	 * remove the resource from the list and release it.
	 */
	fc_rem_resource(rp, ip);
	kmem_free(ip, sizeof (struct fc_resource));

	cp->nresults = fc_int2cell(0);
	return (fc_success_op(ap, rp, cp));
}

static int
pfc_register_fetch(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	size_t len;
	caddr_t virt;
	int error;
	uint64_t x;
	uint32_t l;
	uint16_t w;
	uint8_t b;
	char *name = fc_cell2ptr(cp->svc_name);
	struct fc_resource *ip;

	if (fc_cell2int(cp->nargs) != 1)
		return (fc_syntax_error(cp, "nargs must be 1"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	virt = fc_cell2ptr(fc_arg(cp, 0));

	/*
	 * Determine the access width .. we can switch on the 2nd
	 * character of the name which is "rx@", "rl@", "rb@" or "rw@"
	 */
	switch (*(name + 1)) {
	case 'x':	len = sizeof (x); break;
	case 'l':	len = sizeof (l); break;
	case 'w':	len = sizeof (w); break;
	case 'b':	len = sizeof (b); break;
	}

	/*
	 * Check the alignment ...
	 */
	if (((intptr_t)virt & (len - 1)) != 0)
		return (fc_priv_error(cp, "unaligned access"));

	/*
	 * Find if this virt is 'within' a request we know about
	 */
	fc_lock_resource_list(rp);
	for (ip = rp->head; ip != NULL; ip = ip->next) {
		if (ip->type != RT_MAP)
			continue;
		if ((virt >= (caddr_t)ip->fc_map_virt) && ((virt + len) <=
		    ((caddr_t)ip->fc_map_virt + ip->fc_map_len)))
			break;
	}
	fc_unlock_resource_list(rp);

	if (ip == NULL)
		return (fc_priv_error(cp, "request not within a "
		    "known mapping"));

	/*
	 * XXX: We need access handle versions of peek/poke to move
	 * beyond the prototype ... we assume that we have hardware
	 * byte swapping enabled for pci register access here which
	 * is a huge dependency on the current implementation.
	 */
	switch (len) {
	case sizeof (x):
		error = ddi_peek64(rp->child, (int64_t *)virt, (int64_t *)&x);
		break;
	case sizeof (l):
		error = ddi_peek32(rp->child, (int32_t *)virt, (int32_t *)&l);
		break;
	case sizeof (w):
		error = ddi_peek16(rp->child, (int16_t *)virt, (int16_t *)&w);
		break;
	case sizeof (b):
		error = ddi_peek8(rp->child, (int8_t *)virt, (int8_t *)&b);
		break;
	}

	if (error) {
		return (fc_priv_error(cp, "access error"));
	}

	cp->nresults = fc_int2cell(1);
	switch (len) {
	case sizeof (x): fc_result(cp, 0) = x; break;
	case sizeof (l): fc_result(cp, 0) = fc_uint32_t2cell(l); break;
	case sizeof (w): fc_result(cp, 0) = fc_uint16_t2cell(w); break;
	case sizeof (b): fc_result(cp, 0) = fc_uint8_t2cell(b); break;
	}
	return (fc_success_op(ap, rp, cp));
}

static int
pfc_register_store(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	size_t len;
	caddr_t virt;
	int error;
	uint64_t x;
	uint32_t l;
	uint16_t w;
	uint8_t b;
	char *name = fc_cell2ptr(cp->svc_name);
	struct fc_resource *ip;

	if (fc_cell2int(cp->nargs) != 2)
		return (fc_syntax_error(cp, "nargs must be 2"));

	virt = fc_cell2ptr(fc_arg(cp, 0));

	/*
	 * Determine the access width .. we can switch on the 2nd
	 * character of the name which is "rl!", "rb!" or "rw!"
	 */
	switch (*(name + 1)) {
	case 'x': len = sizeof (x); x = fc_arg(cp, 1); break;
	case 'l': len = sizeof (l); l = fc_cell2uint32_t(fc_arg(cp, 1)); break;
	case 'w': len = sizeof (w); w = fc_cell2uint16_t(fc_arg(cp, 1)); break;
	case 'b': len = sizeof (b); b = fc_cell2uint8_t(fc_arg(cp, 1)); break;
	}

	/*
	 * Check the alignment ...
	 */
	if (((intptr_t)virt & (len - 1)) != 0)
		return (fc_priv_error(cp, "unaligned access"));

	/*
	 * Find if this virt is 'within' a request we know about
	 */
	fc_lock_resource_list(rp);
	for (ip = rp->head; ip != NULL; ip = ip->next) {
		if (ip->type != RT_MAP)
			continue;
		if ((virt >= (caddr_t)ip->fc_map_virt) && ((virt + len) <=
		    ((caddr_t)ip->fc_map_virt + ip->fc_map_len)))
			break;
	}
	fc_unlock_resource_list(rp);

	if (ip == NULL)
		return (fc_priv_error(cp, "request not within a "
		    "known mapping"));

	/*
	 * XXX: We need access handle versions of peek/poke to move
	 * beyond the prototype ... we assume that we have hardware
	 * byte swapping enabled for pci register access here which
	 * is a huge dependency on the current implementation.
	 */
	switch (len) {
	case sizeof (x):
		error = ddi_poke64(rp->child, (int64_t *)virt, x);
		break;
	case sizeof (l):
		error = ddi_poke32(rp->child, (int32_t *)virt, l);
		break;
	case sizeof (w):
		error = ddi_poke16(rp->child, (int16_t *)virt, w);
		break;
	case sizeof (b):
		error = ddi_poke8(rp->child, (int8_t *)virt, b);
		break;
	}

	if (error) {
		return (fc_priv_error(cp, "access error"));
	}

	cp->nresults = fc_int2cell(0);
	return (fc_success_op(ap, rp, cp));
}

static int
pfc_config_fetch(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	caddr_t virt, v;
	int error, reg, flags = 0;
	size_t len;
	uint32_t l, tmp;
	uint16_t w;
	uint8_t b;
	char *name = fc_cell2ptr(cp->svc_name);
	pci_regspec_t p;
	ddi_device_acc_attr_t acc;
	ddi_acc_handle_t h;

	if (fc_cell2int(cp->nargs) != 1)
		return (fc_syntax_error(cp, "nargs must be 1"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	/*
	 * Construct a config address pci reg property from the args.
	 * arg[0] is the configuration address.
	 */
	p.pci_phys_hi = fc_cell2uint(fc_arg(cp, 0));
	p.pci_phys_mid = p.pci_phys_low = 0;
	p.pci_size_hi = p.pci_size_low = 0;

	/*
	 * Verify that the address is a configuration space address
	 * ss must be zero.
	 */
	if ((p.pci_phys_hi & PCI_ADDR_MASK) != PCI_ADDR_CONFIG) {
		cmn_err(CE_CONT, "pfc_config_fetch: "
		    "invalid config addr: %x\n", p.pci_phys_hi);
		return (fc_priv_error(cp, "non-config addr"));
	}

	/*
	 * Extract the register number from the config address and
	 * remove the register number from the physical address.
	 */

	reg = (p.pci_phys_hi & PCI_REG_REG_M) |
	    (((p.pci_phys_hi & PCI_REG_EXTREG_M) >> PCI_REG_EXTREG_SHIFT) << 8);

	p.pci_phys_hi &= PCI_BDF_bits;

	/*
	 * Determine the access width .. we can switch on the 9th
	 * character of the name which is "config-{l,w,b}@"
	 */
	switch (*(name + 7)) {
	case 'l':	len = sizeof (l); break;
	case 'w':	len = sizeof (w); break;
	case 'b':	len = sizeof (b); break;
	}

	/*
	 * Verify that the access is properly aligned
	 */
	if ((reg & (len - 1)) != 0)
		return (fc_priv_error(cp, "unaligned access"));

	/*
	 * Map in configuration space (temporarily)
	 */
	acc.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	acc.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	acc.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	error = pci_map_phys(rp->child, &p, &virt, &acc, &h);

	if (error)  {
		return (fc_priv_error(cp, "pci config map-in failed"));
	}

	if (fcpci_indirect_map(rp->child) == DDI_SUCCESS)
		flags |= PCICFG_CONF_INDIRECT_MAP;

	if (flags & PCICFG_CONF_INDIRECT_MAP) {
		tmp = (int32_t)ddi_get32(h, (uint32_t *)virt);
		error = DDI_SUCCESS;
	} else
		error = ddi_peek32(rp->child, (int32_t *)virt, (int32_t *)&tmp);

	if (error == DDI_SUCCESS)
		if ((tmp == (int32_t)0xffffffff) || (tmp == -1)) {
			error = DDI_FAILURE;
			cmn_err(CE_CONT, "fcpcii: conf probe failed.l=%x", tmp);
		}

	if (error != DDI_SUCCESS) {
		return (fc_priv_error(cp, "pci config fetch failed"));
	}


	/*
	 * XXX: We need access handle versions of peek/poke to move
	 * beyond the prototype ... we assume that we have hardware
	 * byte swapping enabled for pci register access here which
	 * is a huge dependency on the current implementation.
	 */
	v = virt + reg;
	switch (len) {
	case sizeof (l):
		l = (int32_t)ddi_get32(h, (uint32_t *)v);
		break;
	case sizeof (w):
		w = (int16_t)ddi_get16(h, (uint16_t *)v);
		break;
	case sizeof (b):
		b = (int8_t)ddi_get8(h, (uint8_t *)v);
		break;
	}

	/*
	 * Remove the temporary config space mapping
	 */
	pci_unmap_phys(&h, &p);

	if (error) {
		return (fc_priv_error(cp, "access error"));
	}

	cp->nresults = fc_int2cell(1);
	switch (len) {
	case sizeof (l): fc_result(cp, 0) = fc_uint32_t2cell(l); break;
	case sizeof (w): fc_result(cp, 0) = fc_uint16_t2cell(w); break;
	case sizeof (b): fc_result(cp, 0) = fc_uint8_t2cell(b); break;
	}

	return (fc_success_op(ap, rp, cp));
}

static int
pfc_config_store(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	caddr_t virt, v;
	int error, reg, flags = 0;
	size_t len;
	uint32_t l, tmp;
	uint16_t w;
	uint8_t b;
	char *name = fc_cell2ptr(cp->svc_name);
	pci_regspec_t p;
	ddi_device_acc_attr_t acc;
	ddi_acc_handle_t h;

	if (fc_cell2int(cp->nargs) != 2)
		return (fc_syntax_error(cp, "nargs must be 2"));

	/*
	 * Construct a config address pci reg property from the args.
	 * arg[0] is the configuration address. arg[1] is the data.
	 */
	p.pci_phys_hi = fc_cell2uint(fc_arg(cp, 0));
	p.pci_phys_mid = p.pci_phys_low = 0;
	p.pci_size_hi = p.pci_size_low = 0;

	/*
	 * Verify that the address is a configuration space address
	 * ss must be zero.
	 */
	if ((p.pci_phys_hi & PCI_ADDR_MASK) != PCI_ADDR_CONFIG) {
		cmn_err(CE_CONT, "pfc_config_store: "
		    "invalid config addr: %x\n", p.pci_phys_hi);
		return (fc_priv_error(cp, "non-config addr"));
	}

	/*
	 * Extract the register number from the config address and
	 * remove the register number from the physical address.
	 */
	reg = (p.pci_phys_hi & PCI_REG_REG_M) |
	    (((p.pci_phys_hi & PCI_REG_EXTREG_M) >> PCI_REG_EXTREG_SHIFT) << 8);

	p.pci_phys_hi &= PCI_BDF_bits;

	/*
	 * Determine the access width .. we can switch on the 8th
	 * character of the name which is "config-{l,w,b}@"
	 */
	switch (*(name + 7)) {
	case 'l': len = sizeof (l); l = fc_cell2uint32_t(fc_arg(cp, 1)); break;
	case 'w': len = sizeof (w); w = fc_cell2uint16_t(fc_arg(cp, 1)); break;
	case 'b': len = sizeof (b); b = fc_cell2uint8_t(fc_arg(cp, 1)); break;
	}

	/*
	 * Verify that the access is properly aligned
	 */
	if ((reg & (len - 1)) != 0)
		return (fc_priv_error(cp, "unaligned access"));

	/*
	 * Map in configuration space (temporarily)
	 */
	acc.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	acc.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	acc.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	error = pci_map_phys(rp->child, &p, &virt, &acc, &h);

	if (error)  {
		return (fc_priv_error(cp, "pci config map-in failed"));
	}

	if (fcpci_indirect_map(rp->child) == DDI_SUCCESS)
		flags |= PCICFG_CONF_INDIRECT_MAP;

	if (flags & PCICFG_CONF_INDIRECT_MAP) {
		tmp = (int32_t)ddi_get32(h, (uint32_t *)virt);
		error = DDI_SUCCESS;
	} else
		error = ddi_peek32(rp->child, (int32_t *)virt, (int32_t *)&tmp);

	if (error == DDI_SUCCESS)
		if ((tmp == (int32_t)0xffffffff) || (tmp == -1)) {
			error = DDI_FAILURE;
			cmn_err(CE_CONT, "fcpci: conf probe failed.l=%x", tmp);
		}

	if (error != DDI_SUCCESS) {
		return (fc_priv_error(cp, "pci config store failed"));
	}


	/*
	 * XXX: We need access handle versions of peek/poke to move
	 * beyond the prototype ... we assume that we have hardware
	 * byte swapping enabled for pci register access here which
	 * is a huge dependency on the current implementation.
	 */
	v = virt + reg;
	switch (len) {
	case sizeof (l):
		ddi_put32(h, (uint32_t *)v, (uint32_t)l);
		break;
	case sizeof (w):
		ddi_put16(h, (uint16_t *)v, (uint16_t)w);
		break;
	case sizeof (b):
		ddi_put8(h, (uint8_t *)v, (uint8_t)b);
		break;
	}

	/*
	 * Remove the temporary config space mapping
	 */
	pci_unmap_phys(&h, &p);

	if (error) {
		return (fc_priv_error(cp, "access error"));
	}

	cp->nresults = fc_int2cell(0);
	return (fc_success_op(ap, rp, cp));
}


static int
pfc_get_fcode(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	caddr_t name_virt, fcode_virt;
	char *name, *fcode;
	int fcode_len, status;

	if (fc_cell2int(cp->nargs) != 3)
		return (fc_syntax_error(cp, "nargs must be 3"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	name_virt = fc_cell2ptr(fc_arg(cp, 0));

	fcode_virt = fc_cell2ptr(fc_arg(cp, 1));

	fcode_len = fc_cell2int(fc_arg(cp, 2));

	name = kmem_zalloc(FC_SVC_NAME_LEN, KM_SLEEP);

	if (copyinstr(fc_cell2ptr(name_virt), name,
	    FC_SVC_NAME_LEN - 1, NULL))  {
		status = 0;
	} else {

		fcode = kmem_zalloc(fcode_len, KM_SLEEP);

		if ((status = prom_get_fcode(name, fcode)) != 0) {

			if (copyout((void *)fcode, (void *)fcode_virt,
			    fcode_len)) {
				cmn_err(CE_WARN, " pfc_get_fcode: Unable "
				    "to copy out fcode image\n");
				status = 0;
			}
		}

		kmem_free(fcode, fcode_len);
	}

	kmem_free(name, FC_SVC_NAME_LEN);

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = status;

	return (fc_success_op(ap, rp, cp));
}

static int
pfc_get_fcode_size(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	caddr_t virt;
	char *name;
	int len;

	if (fc_cell2int(cp->nargs) != 1)
		return (fc_syntax_error(cp, "nargs must be 1"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	virt = fc_cell2ptr(fc_arg(cp, 0));

	name = kmem_zalloc(FC_SVC_NAME_LEN, KM_SLEEP);

	if (copyinstr(fc_cell2ptr(virt), name,
	    FC_SVC_NAME_LEN - 1, NULL))  {
		len = 0;
	} else {
		len = prom_get_fcode_size(name);
	}

	kmem_free(name, FC_SVC_NAME_LEN);

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = len;

	return (fc_success_op(ap, rp, cp));
}

/*
 * Return the physical probe address: lo=0, mid=0, hi-config-addr
 */
static int
pfc_probe_address(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	if (fc_cell2int(cp->nargs) != 0)
		return (fc_syntax_error(cp, "nargs must be 0"));

	if (fc_cell2int(cp->nresults) < 2)
		return (fc_syntax_error(cp, "nresults must be >= 3"));

	cp->nresults = fc_int2cell(2);
	fc_result(cp, 1) = fc_int2cell(0);	/* phys.lo */
	fc_result(cp, 0) = fc_int2cell(0);	/* phys.mid */

	return (fc_success_op(ap, rp, cp));
}

/*
 * Return the phys.hi component of the probe address.
 */
static int
pfc_probe_space(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	struct pci_ops_bus_args *ba = rp->bus_args;

	ASSERT(ba);

	if (fc_cell2int(cp->nargs) != 0)
		return (fc_syntax_error(cp, "nargs must be 0"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = fc_uint32_t2cell(ba->config_address); /* phys.hi */

	return (fc_success_op(ap, rp, cp));
}

static int
pfc_config_child(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	fc_phandle_t h;

	if (fc_cell2int(cp->nargs) != 0)
		return (fc_syntax_error(cp, "nargs must be 0"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	h = fc_dip_to_phandle(fc_handle_to_phandle_head(rp), rp->child);

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = fc_phandle2cell(h);

	return (fc_success_op(ap, rp, cp));
}

int
pci_alloc_mem_chunk(dev_info_t *dip, uint64_t mem_align, uint64_t *mem_size,
    uint64_t *mem_answer)
{
	ndi_ra_request_t req;
	int rval;

	bzero((caddr_t)&req, sizeof (ndi_ra_request_t));
	req.ra_flags = NDI_RA_ALLOC_BOUNDED;
	req.ra_boundbase = 0;
	req.ra_boundlen = PCI_4GIG_LIMIT;
	req.ra_len = *mem_size;
	req.ra_align_mask = mem_align - 1;

	rval = ndi_ra_alloc(dip, &req, mem_answer, mem_size,
	    NDI_RA_TYPE_MEM, NDI_RA_PASS);

	return (rval);
}
int
pci_alloc_io_chunk(dev_info_t *dip, uint64_t io_align, uint64_t *io_size,
    uint64_t *io_answer)
{
	ndi_ra_request_t req;
	int rval;

	bzero((caddr_t)&req, sizeof (ndi_ra_request_t));
	req.ra_flags = (NDI_RA_ALLOC_BOUNDED | NDI_RA_ALLOC_PARTIAL_OK);
	req.ra_boundbase = 0;
	req.ra_boundlen = PCI_4GIG_LIMIT;
	req.ra_len = *io_size;
	req.ra_align_mask = io_align - 1;

	rval = ndi_ra_alloc(dip, &req, io_answer, io_size,
	    NDI_RA_TYPE_IO, NDI_RA_PASS);

	return (rval);
}

int
pci_alloc_resource(dev_info_t *dip, pci_regspec_t phys_spec)
{
	uint64_t answer;
	uint64_t alen;
	int offset, tmp;
	pci_regspec_t config;
	caddr_t virt, v;
	ddi_device_acc_attr_t acc;
	ddi_acc_handle_t h;
	ndi_ra_request_t request;
	pci_regspec_t *assigned;
	int assigned_len, entries, i, l, flags = 0, error;

	l = phys_spec.pci_size_low;

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "assigned-addresses", (caddr_t)&assigned,
	    &assigned_len) == DDI_PROP_SUCCESS) {

		entries = assigned_len / (sizeof (pci_regspec_t));

		/*
		 * Walk through the assigned-addresses entries. If there is
		 * a match, there is no need to allocate the resource.
		 */
		for (i = 0; i < entries; i++) {
			if (assigned[i].pci_phys_hi == phys_spec.pci_phys_hi) {
				if (assigned[i].pci_size_low >=
				    phys_spec.pci_size_low) {
					kmem_free(assigned, assigned_len);
					return (0);
				}
				/*
				 * Fcode wants to assign more than what
				 * probe found.
				 */
				(void) pci_free_resource(dip, assigned[i]);
				/*
				 * Go on to allocate resources.
				 */
				break;
			}
			/*
			 * Check if Fcode wants to map using different
			 * NPT bits.
			 */
			if (PCI_REG_BDFR_G(assigned[i].pci_phys_hi) ==
			    PCI_REG_BDFR_G(phys_spec.pci_phys_hi)) {
				/*
				 * It is an error to change SS bits
				 */
				if (PCI_REG_ADDR_G(assigned[i].pci_phys_hi) !=
				    PCI_REG_ADDR_G(phys_spec.pci_phys_hi)) {

					FC_DEBUG2(2, CE_WARN, "Fcode changing "
					    "ss bits in reg %x -- %x",
					    assigned[i].pci_phys_hi,
					    phys_spec.pci_phys_hi);
				}

				/*
				 * Allocate enough
				 */
				l = MAX(assigned[i].pci_size_low,
				    phys_spec.pci_size_low);

				(void) pci_free_resource(dip, assigned[i]);
				/*
				 * Go on to allocate resources.
				 */
				break;
			}
		}
		kmem_free(assigned, assigned_len);
	}

	bzero((caddr_t)&request, sizeof (ndi_ra_request_t));

	config.pci_phys_hi = PCI_CONF_ADDR_MASK & phys_spec.pci_phys_hi;
	config.pci_phys_hi &= ~PCI_REG_REG_M;
	config.pci_phys_mid = config.pci_phys_low = 0;
	config.pci_size_hi = config.pci_size_low = 0;

	/*
	 * Map in configuration space (temporarily)
	 */
	acc.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	acc.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	acc.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (error = pci_map_phys(dip, &config, &virt, &acc, &h)) {
		return (1);
	}

	if (fcpci_indirect_map(dip) == DDI_SUCCESS)
		flags |= PCICFG_CONF_INDIRECT_MAP;

	if (flags & PCICFG_CONF_INDIRECT_MAP) {
		tmp = (int32_t)ddi_get32(h, (uint32_t *)virt);
		error = DDI_SUCCESS;
	} else
		error = ddi_peek32(dip, (int32_t *)virt, (int32_t *)&tmp);

	if (error == DDI_SUCCESS)
		if ((tmp == (int32_t)0xffffffff) || (tmp == -1)) {
			error = DDI_FAILURE;
		}

	if (error != DDI_SUCCESS) {
		return (1);
	}

	request.ra_flags |= NDI_RA_ALIGN_SIZE;
	request.ra_boundbase = 0;
	request.ra_boundlen = PCI_4GIG_LIMIT;

	offset = PCI_REG_REG_G(phys_spec.pci_phys_hi);

	v = virt + offset;

	if (PCI_REG_REG_G(phys_spec.pci_phys_hi) == PCI_CONF_ROM) {
		request.ra_len = l;
		request.ra_flags ^= NDI_RA_ALLOC_BOUNDED;

		/* allocate memory space from the allocator */

		if (ndi_ra_alloc(ddi_get_parent(dip),
			&request, &answer, &alen,
			NDI_RA_TYPE_MEM, NDI_RA_PASS)
					!= NDI_SUCCESS) {
			pci_unmap_phys(&h, &config);
			return (1);
		}
		FC_DEBUG3(1, CE_CONT, "ROM addr = [0x%x.%x] len [0x%x]\n",
			HIADDR(answer),
			LOADDR(answer),
			alen);

		/* program the low word */

		ddi_put32(h, (uint32_t *)v, LOADDR(answer));

		phys_spec.pci_phys_low = LOADDR(answer);
		phys_spec.pci_phys_mid = HIADDR(answer);
	} else {
		request.ra_len = l;

		switch (PCI_REG_ADDR_G(phys_spec.pci_phys_hi)) {
		case PCI_REG_ADDR_G(PCI_ADDR_MEM64):
			request.ra_flags ^= NDI_RA_ALLOC_BOUNDED;

			if (phys_spec.pci_phys_hi & PCI_REG_REL_M) {
				/*
				 * If it is a non relocatable address,
				 * then specify the address we want.
				 */
				request.ra_flags = NDI_RA_ALLOC_SPECIFIED;
				request.ra_addr = (uint64_t)LADDR(
				    phys_spec.pci_phys_low,
				    phys_spec.pci_phys_mid);
			}

			/* allocate memory space from the allocator */

			if (ndi_ra_alloc(ddi_get_parent(dip),
				&request, &answer, &alen,
				NDI_RA_TYPE_MEM, NDI_RA_PASS)
						!= NDI_SUCCESS) {
				pci_unmap_phys(&h, &config);
				if (request.ra_flags ==
				    NDI_RA_ALLOC_SPECIFIED)
					cmn_err(CE_WARN, "Unable to allocate "
					    "non relocatable address 0x%p\n",
					    (void *) request.ra_addr);
				return (1);
			}
			FC_DEBUG3(1, CE_CONT,
			    "64 addr = [0x%x.%x] len [0x%x]\n",
			    HIADDR(answer),
			    LOADDR(answer),
			    alen);

			/* program the low word */

			ddi_put32(h, (uint32_t *)v, LOADDR(answer));

			/* program the high word with value zero */
			v += 4;
			ddi_put32(h, (uint32_t *)v, HIADDR(answer));

			phys_spec.pci_phys_low = LOADDR(answer);
			phys_spec.pci_phys_mid = HIADDR(answer);
			/*
			 * currently support 32b address space
			 * assignments only.
			 */
			phys_spec.pci_phys_hi ^= PCI_ADDR_MEM64 ^
							PCI_ADDR_MEM32;

			break;

		case PCI_REG_ADDR_G(PCI_ADDR_MEM32):
			request.ra_flags |= NDI_RA_ALLOC_BOUNDED;

			if (phys_spec.pci_phys_hi & PCI_REG_REL_M) {
				/*
				 * If it is a non relocatable address,
				 * then specify the address we want.
				 */
				request.ra_flags = NDI_RA_ALLOC_SPECIFIED;
				request.ra_addr = (uint64_t)
				    phys_spec.pci_phys_low;
			}

			/* allocate memory space from the allocator */

			if (ndi_ra_alloc(ddi_get_parent(dip),
				&request, &answer, &alen,
				NDI_RA_TYPE_MEM, NDI_RA_PASS)
						!= NDI_SUCCESS) {
				pci_unmap_phys(&h, &config);
				if (request.ra_flags ==
				    NDI_RA_ALLOC_SPECIFIED)
					cmn_err(CE_WARN, "Unable to allocate "
					    "non relocatable address 0x%p\n",
					    (void *) request.ra_addr);
				return (1);
			}

			FC_DEBUG3(1, CE_CONT,
			    "32 addr = [0x%x.%x] len [0x%x]\n",
			    HIADDR(answer),
			    LOADDR(answer),
			    alen);

			/* program the low word */

			ddi_put32(h, (uint32_t *)v, LOADDR(answer));

			phys_spec.pci_phys_low = LOADDR(answer);

			break;
		case PCI_REG_ADDR_G(PCI_ADDR_IO):
			request.ra_flags |= NDI_RA_ALLOC_BOUNDED;

			if (phys_spec.pci_phys_hi & PCI_REG_REL_M) {
				/*
				 * If it is a non relocatable address,
				 * then specify the address we want.
				 */
				request.ra_flags = NDI_RA_ALLOC_SPECIFIED;
				request.ra_addr = (uint64_t)
				    phys_spec.pci_phys_low;
			}

			/* allocate I/O space from the allocator */

			if (ndi_ra_alloc(ddi_get_parent(dip),
				&request, &answer, &alen,
				NDI_RA_TYPE_IO, NDI_RA_PASS)
						!= NDI_SUCCESS) {
				pci_unmap_phys(&h, &config);
				if (request.ra_flags ==
				    NDI_RA_ALLOC_SPECIFIED)
					cmn_err(CE_WARN, "Unable to allocate "
					    "non relocatable IO Space 0x%p\n",
					    (void *) request.ra_addr);
				return (1);
			}
			FC_DEBUG3(1, CE_CONT,
			    "I/O addr = [0x%x.%x] len [0x%x]\n",
			    HIADDR(answer),
			    LOADDR(answer),
			    alen);

			ddi_put32(h, (uint32_t *)v, LOADDR(answer));

			phys_spec.pci_phys_low = LOADDR(answer);

			break;
		default:
			pci_unmap_phys(&h, &config);
			return (1);
		} /* switch */
	}

	/*
	 * Now that memory locations are assigned,
	 * update the assigned address property.
	 */
	if (pfc_update_assigned_prop(dip, &phys_spec)) {
		pci_unmap_phys(&h, &config);
		return (1);
	}

	pci_unmap_phys(&h, &config);

	return (0);
}

int
pci_free_resource(dev_info_t *dip, pci_regspec_t phys_spec)
{
	int offset, tmp;
	pci_regspec_t config;
	caddr_t virt, v;
	ddi_device_acc_attr_t acc;
	ddi_acc_handle_t h;
	ndi_ra_request_t request;
	int l, error, flags = 0;

	bzero((caddr_t)&request, sizeof (ndi_ra_request_t));

	config.pci_phys_hi = PCI_CONF_ADDR_MASK & phys_spec.pci_phys_hi;
	config.pci_phys_hi &= ~PCI_REG_REG_M;
	config.pci_phys_mid = config.pci_phys_low = 0;
	config.pci_size_hi = config.pci_size_low = 0;

	/*
	 * Map in configuration space (temporarily)
	 */
	acc.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	acc.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	acc.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (error = pci_map_phys(dip, &config, &virt, &acc, &h)) {
		return (1);
	}
	if (fcpci_indirect_map(dip) == DDI_SUCCESS)
		flags |= PCICFG_CONF_INDIRECT_MAP;

	if (flags & PCICFG_CONF_INDIRECT_MAP) {
		tmp = (int32_t)ddi_get32(h, (uint32_t *)virt);
		error = DDI_SUCCESS;
	} else
		error = ddi_peek32(dip, (int32_t *)virt, (int32_t *)&tmp);

	if (error == DDI_SUCCESS)
		if ((tmp == (int32_t)0xffffffff) || (tmp == -1)) {
			error = DDI_FAILURE;
		}
	if (error != DDI_SUCCESS) {
		return (1);
	}


	offset = PCI_REG_REG_G(phys_spec.pci_phys_hi);

	v = virt + offset;

	/*
	 * Pick up the size to be freed. It may be different from
	 * what probe finds.
	 */
	l = phys_spec.pci_size_low;

	if (PCI_REG_REG_G(phys_spec.pci_phys_hi) == PCI_CONF_ROM) {
		/* free memory back to the allocator */
		if (ndi_ra_free(ddi_get_parent(dip), phys_spec.pci_phys_low,
		    l, NDI_RA_TYPE_MEM,
		    NDI_RA_PASS) != NDI_SUCCESS) {
			pci_unmap_phys(&h, &config);
			return (1);
		}

		/* Unmap the BAR by writing a zero */

		ddi_put32(h, (uint32_t *)v, 0);
	} else {
		switch (PCI_REG_ADDR_G(phys_spec.pci_phys_hi)) {
		case PCI_REG_ADDR_G(PCI_ADDR_MEM64):
			/* free memory back to the allocator */
			if (ndi_ra_free(ddi_get_parent(dip),
			    LADDR(phys_spec.pci_phys_low,
			    phys_spec.pci_phys_mid),
			    l, NDI_RA_TYPE_MEM,
			    NDI_RA_PASS) != NDI_SUCCESS) {
				pci_unmap_phys(&h, &config);
				return (1);
			}

			break;

		case PCI_REG_ADDR_G(PCI_ADDR_MEM32):
			/* free memory back to the allocator */
			if (ndi_ra_free(ddi_get_parent(dip),
			    phys_spec.pci_phys_low,
			    l, NDI_RA_TYPE_MEM,
			    NDI_RA_PASS) != NDI_SUCCESS) {
				pci_unmap_phys(&h, &config);
				return (1);
			}

			break;
		case PCI_REG_ADDR_G(PCI_ADDR_IO):
			/* free I/O space back to the allocator */
			if (ndi_ra_free(ddi_get_parent(dip),
			    phys_spec.pci_phys_low,
			    l, NDI_RA_TYPE_IO,
			    NDI_RA_PASS) != NDI_SUCCESS) {
				pci_unmap_phys(&h, &config);
				return (1);
			}
			break;
		default:
			pci_unmap_phys(&h, &config);
			return (1);
		} /* switch */
	}

	/*
	 * Now that memory locations are assigned,
	 * update the assigned address property.
	 */

	FC_DEBUG1(1, CE_CONT, "updating assigned-addresss for %x\n",
	    phys_spec.pci_phys_hi);

	if (pfc_remove_assigned_prop(dip, &phys_spec)) {
		pci_unmap_phys(&h, &config);
		return (1);
	}

	pci_unmap_phys(&h, &config);

	return (0);
}


int
pci_map_phys(dev_info_t *dip, pci_regspec_t *phys_spec,
	caddr_t *addrp, ddi_device_acc_attr_t *accattrp,
	ddi_acc_handle_t *handlep)
{
	ddi_map_req_t mr;
	ddi_acc_hdl_t *hp;
	int result;

	*handlep = impl_acc_hdl_alloc(KM_SLEEP, NULL);
	hp = impl_acc_hdl_get(*handlep);
	hp->ah_vers = VERS_ACCHDL;
	hp->ah_dip = dip;
	hp->ah_rnumber = 0;
	hp->ah_offset = 0;
	hp->ah_len = 0;
	hp->ah_acc = *accattrp;

	mr.map_op = DDI_MO_MAP_LOCKED;
	mr.map_type = DDI_MT_REGSPEC;
	mr.map_obj.rp = (struct regspec *)phys_spec;
	mr.map_prot = PROT_READ | PROT_WRITE;
	mr.map_flags = DDI_MF_KERNEL_MAPPING;
	mr.map_handlep = hp;
	mr.map_vers = DDI_MAP_VERSION;

	result = ddi_map(dip, &mr, 0, 0, addrp);

	if (result != DDI_SUCCESS) {
		impl_acc_hdl_free(*handlep);
		*handlep = (ddi_acc_handle_t)NULL;
	} else {
		hp->ah_addr = *addrp;
	}

	return (result);
}

void
pci_unmap_phys(ddi_acc_handle_t *handlep, pci_regspec_t *ph)
{
	ddi_map_req_t mr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(*handlep);
	ASSERT(hp);

	mr.map_op = DDI_MO_UNMAP;
	mr.map_type = DDI_MT_REGSPEC;
	mr.map_obj.rp = (struct regspec *)ph;
	mr.map_prot = PROT_READ | PROT_WRITE;
	mr.map_flags = DDI_MF_KERNEL_MAPPING;
	mr.map_handlep = hp;
	mr.map_vers = DDI_MAP_VERSION;

	(void) ddi_map(hp->ah_dip, &mr, hp->ah_offset,
		hp->ah_len, &hp->ah_addr);

	impl_acc_hdl_free(*handlep);


	*handlep = (ddi_acc_handle_t)NULL;
}

int
pfc_update_assigned_prop(dev_info_t *dip, pci_regspec_t *newone)
{
	int		alen;
	pci_regspec_t	*assigned;
	caddr_t		newreg;
	uint_t		status;

	status = ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		"assigned-addresses", (caddr_t)&assigned, &alen);
	switch (status) {
		case DDI_PROP_SUCCESS:
		break;
		case DDI_PROP_NO_MEMORY:
			return (1);
		default:
			(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
			"assigned-addresses", (int *)newone,
				sizeof (*newone)/sizeof (int));
			return (0);
	}

	/*
	 * Allocate memory for the existing
	 * assigned-addresses(s) plus one and then
	 * build it.
	 */

	newreg = kmem_zalloc(alen+sizeof (*newone), KM_SLEEP);

	bcopy(assigned, newreg, alen);
	bcopy(newone, newreg + alen, sizeof (*newone));

	/*
	 * Write out the new "assigned-addresses" spec
	 */
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
		"assigned-addresses", (int *)newreg,
		(alen + sizeof (*newone))/sizeof (int));

	kmem_free((caddr_t)newreg, alen+sizeof (*newone));

	return (0);
}
int
pfc_remove_assigned_prop(dev_info_t *dip, pci_regspec_t *oldone)
{
	int		alen, new_len, num_entries, i;
	pci_regspec_t	*assigned;
	uint_t		status;

	status = ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		"assigned-addresses", (caddr_t)&assigned, &alen);
	switch (status) {
		case DDI_PROP_SUCCESS:
		break;
		case DDI_PROP_NO_MEMORY:
			return (1);
		default:
			return (0);
	}

	num_entries = alen / sizeof (pci_regspec_t);
	new_len = alen - sizeof (pci_regspec_t);

	/*
	 * Search for the memory being removed.
	 */
	for (i = 0; i < num_entries; i++) {
		if (assigned[i].pci_phys_hi == oldone->pci_phys_hi) {
			if (new_len == 0) {
				(void) ndi_prop_remove(DDI_DEV_T_NONE, dip,
				    "assigned-addresses");
				break;
			}
			if ((new_len - (i * sizeof (pci_regspec_t)))
			    == 0) {
				FC_DEBUG1(1, CE_CONT, "assigned-address entry "
				    "%x removed from property (last entry)\n",
				    oldone->pci_phys_hi);
			} else {
				bcopy((void *)(assigned + i + 1),
				    (void *)(assigned + i),
				    (new_len - (i * sizeof (pci_regspec_t))));

				FC_DEBUG1(1, CE_CONT, "assigned-address entry "
				    "%x removed from property\n",
				    oldone->pci_phys_hi);
			}
			(void) ndi_prop_update_int_array(DDI_DEV_T_NONE,
			    dip, "assigned-addresses", (int *)assigned,
			    (new_len/sizeof (int)));

			break;
		}
	}

	return (0);
}
/*
 * we recognize the non transparent bridge child nodes with the
 * following property. This is specific to this implementation only.
 * This property is specific to AP nodes only.
 */
#define	PCICFG_DEV_CONF_MAP_PROP		"pci-parent-indirect"

/*
 * If a non transparent bridge drives a hotplug/hotswap bus, then
 * the following property must be defined for the node either by
 * the driver or the OBP.
 */
#define	PCICFG_BUS_CONF_MAP_PROP		"pci-conf-indirect"

/*
 * this function is called only for SPARC platforms, where we may have
 * a mix n' match of direct vs indirectly mapped configuration space.
 */
/*ARGSUSED*/
static int
fcpci_indirect_map(dev_info_t *dip)
{
	int rc = DDI_FAILURE;

	if (ddi_getprop(DDI_DEV_T_ANY, ddi_get_parent(dip), 0,
			PCICFG_DEV_CONF_MAP_PROP, DDI_FAILURE) != DDI_FAILURE)
		rc = DDI_SUCCESS;
	else
		if (ddi_getprop(DDI_DEV_T_ANY, ddi_get_parent(dip),
				0, PCICFG_BUS_CONF_MAP_PROP,
				DDI_FAILURE) != DDI_FAILURE)
			rc = DDI_SUCCESS;

	return (rc);
}
