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
 * fcgp2.c: Framework gp2 (Safari) fcode ops
 */
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/pci.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddidmareq.h>
#include <sys/modctl.h>
#include <sys/ndi_impldefs.h>
#include <sys/fcode.h>
#include <sys/promif.h>
#include <sys/promimpl.h>

static int gfc_map_in(dev_info_t *, fco_handle_t, fc_ci_t *);
static int gfc_map_out(dev_info_t *, fco_handle_t, fc_ci_t *);
static int gfc_register_fetch(dev_info_t *, fco_handle_t, fc_ci_t *);
static int gfc_register_store(dev_info_t *, fco_handle_t, fc_ci_t *);
static int gfc_claim_address(dev_info_t *, fco_handle_t, fc_ci_t *);
static int gfc_claim_memory(dev_info_t *, fco_handle_t, fc_ci_t *);
static int gfc_release_memory(dev_info_t *, fco_handle_t, fc_ci_t *);
static int gfc_vtop(dev_info_t *, fco_handle_t, fc_ci_t *);
static int gfc_master_intr(dev_info_t *, fco_handle_t, fc_ci_t *);

static int gfc_config_child(dev_info_t *, fco_handle_t, fc_ci_t *);

static int gfc_get_fcode_size(dev_info_t *, fco_handle_t, fc_ci_t *);
static int gfc_get_fcode(dev_info_t *, fco_handle_t, fc_ci_t *);

int prom_get_fcode_size(char *);
int prom_get_fcode(char *, char *);

int fcpci_unloadable;
int no_advisory_dma;

#define	HIADDR(n) ((uint32_t)(((uint64_t)(n) & 0xFFFFFFFF00000000)>> 32))
#define	LOADDR(n)((uint32_t)((uint64_t)(n) & 0x00000000FFFFFFFF))
#define	LADDR(lo, hi)    (((uint64_t)(hi) << 32) | (uint32_t)(lo))
#define	PCI_4GIG_LIMIT 0xFFFFFFFFUL


/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops, "FCode gp2 (safari) bus functions"
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


struct gfc_ops_v {
	char *svc_name;
	fc_ops_t *f;
};

struct gfc_ops_v gp2_pov[] = {
	{	"map-in",		gfc_map_in},
	{	"map-out",		gfc_map_out},
	{	"rx@",			gfc_register_fetch},
	{	"rl@",			gfc_register_fetch},
	{	"rw@",			gfc_register_fetch},
	{	"rb@",			gfc_register_fetch},
	{	"rx!",			gfc_register_store},
	{	"rl!",			gfc_register_store},
	{	"rw!",			gfc_register_store},
	{	"rb!",			gfc_register_store},
	{	"claim-address",	gfc_claim_address},
	{	"master-interrupt",	gfc_master_intr},
	{	"claim-memory",		gfc_claim_memory},
	{	"release-memory",	gfc_release_memory},
	{	"vtop",			gfc_vtop},
	{	FC_CONFIG_CHILD,	gfc_config_child},
	{	FC_GET_FCODE_SIZE,	gfc_get_fcode_size},
	{	FC_GET_FCODE,		gfc_get_fcode},
	{	NULL,			NULL}
};

struct gfc_ops_v gp2_shared_pov[] = {
	{	NULL,			NULL}
};

static int gp2_map_phys(dev_info_t *, struct regspec *,  caddr_t *,
    ddi_device_acc_attr_t *, ddi_acc_handle_t *);
static void gp2_unmap_phys(ddi_acc_handle_t *);

fco_handle_t
gp2_fc_ops_alloc_handle(dev_info_t *ap, dev_info_t *child,
    void *fcode, size_t fcode_size, char *unit_address,
    char *my_args)
{
	fco_handle_t rp;
	phandle_t h;

	rp = kmem_zalloc(sizeof (struct fc_resource_list), KM_SLEEP);
	rp->next_handle = fc_ops_alloc_handle(ap, child, fcode, fcode_size,
	    unit_address, NULL);
	rp->ap = ap;
	rp->child = child;
	rp->fcode = fcode;
	rp->fcode_size = fcode_size;
	rp->my_args = my_args;

	if (unit_address) {
		char *buf;

		buf = kmem_zalloc(strlen(unit_address) + 1, KM_SLEEP);
		(void) strcpy(buf, unit_address);
		rp->unit_address = buf;
	}

	/*
	 * Add the child's nodeid to our table...
	 */
	h = ddi_get_nodeid(rp->child);
	fc_add_dip_to_phandle(fc_handle_to_phandle_head(rp), rp->child, h);

	return (rp);
}

void
gp2_fc_ops_free_handle(fco_handle_t rp)
{
	struct fc_resource *ip, *np;

	ASSERT(rp);

	if (rp->next_handle)
		fc_ops_free_handle(rp->next_handle);
	if (rp->unit_address)
		kmem_free(rp->unit_address, strlen(rp->unit_address) + 1);
	if (rp->my_args != NULL)
		kmem_free(rp->my_args, strlen(rp->my_args) + 1);

	/*
	 * Release all the resources from the resource list
	 */
	for (ip = rp->head; ip != NULL; ip = np) {
		np = ip->next;
		switch (ip->type) {
		case RT_MAP:
			FC_DEBUG1(1, CE_CONT, "gp2_fc_ops_free: "
			    " map handle - %p\n", ip->fc_map_handle);
			break;
		case RT_DMA:
			/* DMA has to be freed up at exit time */
			cmn_err(CE_CONT, "gfc_fc_ops_free: DMA seen!\n");
			break;
		case RT_CONTIGIOUS:
			FC_DEBUG2(1, CE_CONT, "gp2_fc_ops_free: "
			    "Free claim-memory resource 0x%lx size 0x%x\n",
			    ip->fc_contig_virt, ip->fc_contig_len);

			(void) ndi_ra_free(ddi_root_node(),
			    (uint64_t)ip->fc_contig_virt,
			    ip->fc_contig_len, "gptwo-contigousmem",
			    NDI_RA_PASS);

			break;
		default:
			cmn_err(CE_CONT, "gp2_fc_ops_free: "
			    "unknown resource type %d\n", ip->type);
			break;
		}
		fc_rem_resource(rp, ip);
		kmem_free(ip, sizeof (struct fc_resource));
	}
	kmem_free(rp, sizeof (struct fc_resource_list));
}

int
gp2_fc_ops(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	struct gfc_ops_v *pv;
	char *name = fc_cell2ptr(cp->svc_name);

	ASSERT(rp);

	/*
	 * First try the generic fc_ops. If the ops is a shared op,
	 * also call our local function.
	 */
	if (fc_ops(ap, rp->next_handle, cp) == 0) {
		for (pv = gp2_shared_pov; pv->svc_name != NULL; ++pv)
			if (strcmp(pv->svc_name, name) == 0)
				return (pv->f(ap, rp, cp));
		return (0);
	}

	for (pv = gp2_pov; pv->svc_name != NULL; ++pv)
		if (strcmp(pv->svc_name, name) == 0)
			return (pv->f(ap, rp, cp));

	FC_DEBUG1(9, CE_CONT, "gp2_fc_ops: <%s> not serviced\n", name);

	return (-1);
}

/*
 * map-in  (phys.lo phys.hi size -- virt )
 */
static int
gfc_map_in(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	size_t len;
	int error;
	caddr_t virt;
	struct fc_resource *ip;
	struct regspec r;
	ddi_device_acc_attr_t acc;
	ddi_acc_handle_t h;

	if (fc_cell2int(cp->nargs) != 3)
		return (fc_syntax_error(cp, "nargs must be 3"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	r.regspec_size = len = fc_cell2size(fc_arg(cp, 0));
	r.regspec_bustype = fc_cell2uint(fc_arg(cp, 1));
	r.regspec_addr = fc_cell2uint(fc_arg(cp, 2));

	acc.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	acc.devacc_attr_endian_flags = DDI_STRUCTURE_BE_ACC;
	acc.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	FC_DEBUG3(1, CE_CONT, "gfc_map_in: attempting map in "
	    "address 0x%08x.%08x length %x\n", r.regspec_bustype,
	    r.regspec_addr, r.regspec_size);

	error = gp2_map_phys(rp->child, &r, &virt, &acc, &h);

	if (error)  {
		FC_DEBUG3(1, CE_CONT, "gfc_map_in: map in failed - "
		    "address 0x%08x.%08x length %x\n", r.regspec_bustype,
		    r.regspec_addr, r.regspec_size);

		return (fc_priv_error(cp, "gp2 map-in failed"));
	}

	FC_DEBUG1(3, CE_CONT, "gp2_map_in: returning virt %p\n", virt);

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
	fc_add_resource(rp, ip);

	return (fc_success_op(ap, rp, cp));
}

/*
 * map-out ( virt size -- )
 */
static int
gfc_map_out(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	caddr_t virt;
	size_t len;
	struct fc_resource *ip;

	if (fc_cell2int(cp->nargs) != 2)
		return (fc_syntax_error(cp, "nargs must be 2"));

	virt = fc_cell2ptr(fc_arg(cp, 1));

	len = fc_cell2size(fc_arg(cp, 0));

	FC_DEBUG2(1, CE_CONT, "gp2_map_out: attempting map out %p %x\n",
	    virt, len);

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

	gp2_unmap_phys(&ip->fc_map_handle);

	/*
	 * remove the resource from the list and release it.
	 */
	fc_rem_resource(rp, ip);
	kmem_free(ip, sizeof (struct fc_resource));

	cp->nresults = fc_int2cell(0);
	return (fc_success_op(ap, rp, cp));
}

static int
gfc_register_fetch(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	size_t len;
	caddr_t virt;
	int error = 0;
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
		if (ip->type == RT_MAP) {
		    if ((virt >= (caddr_t)ip->fc_map_virt) && ((virt + len) <=
			((caddr_t)ip->fc_map_virt + ip->fc_map_len)))
				break;
		} else if (ip->type == RT_CONTIGIOUS) {
		    if ((virt >= (caddr_t)ip->fc_contig_virt) && ((virt + len)
			<= ((caddr_t)ip->fc_contig_virt + ip->fc_contig_len)))
				break;
		}
	}
	fc_unlock_resource_list(rp);

	if (ip == NULL) {
		return (fc_priv_error(cp, "request not within a "
		    "known mapping or contigious adddress"));
	}

	switch (len) {
	case sizeof (x):
		if (ip->type == RT_MAP)
		    error = ddi_peek64(rp->child,
			(int64_t *)virt, (int64_t *)&x);
		else /* RT_CONTIGIOUS */
		    x = *(int64_t *)virt;
		break;
	case sizeof (l):
		if (ip->type == RT_MAP)
		    error = ddi_peek32(rp->child,
			(int32_t *)virt, (int32_t *)&l);
		else /* RT_CONTIGIOUS */
		    l = *(int32_t *)virt;
		break;
	case sizeof (w):
		if (ip->type == RT_MAP)
		    error = ddi_peek16(rp->child,
			(int16_t *)virt, (int16_t *)&w);
		else /* RT_CONTIGIOUS */
		    w = *(int16_t *)virt;
		break;
	case sizeof (b):
		if (ip->type == RT_MAP)
		    error = ddi_peek8(rp->child,
			(int8_t *)virt, (int8_t *)&b);
		else /* RT_CONTIGIOUS */
		    b = *(int8_t *)virt;
		break;
	}

	if (error) {
		FC_DEBUG2(1, CE_CONT, "gfc_register_fetch: access error "
		    "accessing virt %p len %d\n", virt, len);
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
gfc_register_store(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	size_t len;
	caddr_t virt;
	uint64_t x;
	uint32_t l;
	uint16_t w;
	uint8_t b;
	char *name = fc_cell2ptr(cp->svc_name);
	struct fc_resource *ip;
	int error = 0;

	if (fc_cell2int(cp->nargs) != 2)
		return (fc_syntax_error(cp, "nargs must be 2"));

	virt = fc_cell2ptr(fc_arg(cp, 0));

	/*
	 * Determine the access width .. we can switch on the 2nd
	 * character of the name which is "rx!", "rl!", "rb!" or "rw!"
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
		if (ip->type == RT_MAP) {
		    if ((virt >= (caddr_t)ip->fc_map_virt) && ((virt + len) <=
			((caddr_t)ip->fc_map_virt + ip->fc_map_len)))
				break;
		} else if (ip->type == RT_CONTIGIOUS) {
		    if ((virt >= (caddr_t)ip->fc_contig_virt) && ((virt + len)
			<= ((caddr_t)ip->fc_contig_virt + ip->fc_contig_len)))
				break;
		}
	}
	fc_unlock_resource_list(rp);

	if (ip == NULL)
		return (fc_priv_error(cp, "request not within a "
		    "known mapping or contigious address"));

	switch (len) {
	case sizeof (x):
		if (ip->type == RT_MAP)
			error = ddi_poke64(rp->child, (int64_t *)virt, x);
		else if (ip->type == RT_CONTIGIOUS)
			*(uint64_t *)virt = x;
		break;
	case sizeof (l):
		if (ip->type == RT_MAP)
			error = ddi_poke32(rp->child, (int32_t *)virt, l);
		else if (ip->type == RT_CONTIGIOUS)
			*(uint32_t *)virt = l;
		break;
	case sizeof (w):
		if (ip->type == RT_MAP)
			error = ddi_poke16(rp->child, (int16_t *)virt, w);
		else if (ip->type == RT_CONTIGIOUS)
			*(uint16_t *)virt = w;
		break;
	case sizeof (b):
		if (ip->type == RT_MAP)
			error = ddi_poke8(rp->child, (int8_t *)virt, b);
		else if (ip->type == RT_CONTIGIOUS)
			*(uint8_t *)virt = b;
		break;
	}

	if (error == DDI_FAILURE) {
		FC_DEBUG2(1, CE_CONT, "gfc_register_store: access error "
		    "accessing virt %p len %d\n", virt, len);
		return (fc_priv_error(cp, "access error"));
	}

	cp->nresults = fc_int2cell(0);
	return (fc_success_op(ap, rp, cp));
}

static int
gfc_master_intr(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	int xt, portid;

	if (fc_cell2int(cp->nargs) != 2)
		return (fc_syntax_error(cp, "nargs must be 4"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	xt = fc_cell2int(fc_arg(cp, 1));
	portid = fc_cell2int(fc_arg(cp, 0));

	FC_DEBUG2(1, CE_CONT, "gfc_master_intr: reset-int-xt=%x portid=%x",
	    xt, portid);

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = 0;

	return (fc_success_op(ap, rp, cp));
}

/*
 * gfc_claim_address
 *
 * claim-address (size.lo size.hi type align bar portid -- base.lo base.hi )
 */
static int
gfc_claim_address(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	int bar, portid;
	uint64_t exp, slot, port, slice;
	uint64_t paddr;

	if (fc_cell2int(cp->nargs) != 6)
		return (fc_syntax_error(cp, "nargs must be 6"));

	if (fc_cell2int(cp->nresults) < 2)
		return (fc_syntax_error(cp, "nresults must be 2"));

	bar = fc_cell2int(fc_arg(cp, 1));
	portid = fc_cell2int(fc_arg(cp, 0));

	exp = portid >> 5;
	slot = (0x8 & portid) >> 3;
	port = portid & 0x1;

	switch (bar) {
	case 0: /* PCI IO Bus A */
		paddr = (exp << 28) | (port << 26) | (slot << 27) |
		    ((uint64_t)0x402 << 32);

		break;
	case 1: /* PCI Memory Bus A */
		slice = (exp * 2) + slot + 1;

		paddr = ((uint64_t)1 << 42) | ((uint64_t)slice << 34) |
		    ((uint64_t)port << 33);

		break;
	case 2: /* PCI IO Bus B */
		paddr = (exp << 28) | (port << 26) | (slot << 27) |
		    ((uint64_t)0x402 << 32)  | (1 << 25);

		break;
	case 3: /* PCI Memory Bus B */
		slice = (exp * 2) + slot + 1;

		paddr = ((uint64_t)1 << 42) | ((uint64_t)slice << 34) |
		    ((uint64_t)port << 33);

		paddr |= ((uint64_t)1 << 32);

		break;
	default:
		cmn_err(CE_WARN,
		    "gfc_claim_address - invalid BAR=0x%x\n", bar);

		return (fc_syntax_error(cp, "invalid argument"));
	}

	FC_DEBUG1(1, CE_CONT, "gfc_claim_address: returning 0x%lx\n", paddr);

	cp->nresults = fc_int2cell(2);
	fc_result(cp, 0) = LOADDR(paddr);
	fc_result(cp, 1) = HIADDR(paddr);

	return (fc_success_op(ap, rp, cp));
}

/*
 * gfc_claim_memory
 *
 * claim-memory ( align size vhint -- vaddr)
 */
static int
gfc_claim_memory(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	int align, size, vhint;
	ndi_ra_request_t request;
	uint64_t answer, alen;
	struct fc_resource *ip;

	if (fc_cell2int(cp->nargs) != 3)
		return (fc_syntax_error(cp, "nargs must be 3"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	vhint = fc_cell2int(fc_arg(cp, 2));
	size = fc_cell2int(fc_arg(cp, 1));
	align = fc_cell2int(fc_arg(cp, 0));

	FC_DEBUG3(1, CE_CONT, "gfc_claim_memory: align=0x%x size=0x%x "
	    "vhint=0x%x\n", align, size, vhint);

	if (size == 0) {
		cmn_err(CE_WARN, " gfc_claim_memory - unable to allocate "
		    "contigiuos memory of size zero\n");
		return (fc_priv_error(cp, "allocation error"));
	}

	if (vhint) {
		cmn_err(CE_WARN, "gfc_claim_memory - vhint is not zero "
		    "vhint=0x%x - Ignoring Argument\n", vhint);
	}

	bzero((caddr_t)&request, sizeof (ndi_ra_request_t));
	request.ra_flags  = NDI_RA_ALLOC_BOUNDED;
	request.ra_boundbase = 0;
	request.ra_boundlen = 0xffffffff;
	request.ra_len = size;
	request.ra_align_mask = align - 1;

	if (ndi_ra_alloc(ddi_root_node(), &request, &answer, &alen,
	    "gptwo-contigousmem", NDI_RA_PASS) != NDI_SUCCESS) {
		cmn_err(CE_WARN, " gfc_claim_memory - unable to allocate "
		    "contigiuos memory\n");
		return (fc_priv_error(cp, "allocation error"));

	}

	FC_DEBUG2(1, CE_CONT, "gfc_claim_memory: address allocated=0x%lx "
	    "size=0x%x\n", answer, alen);

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = answer;

	/*
	 * Log this resource ...
	 */
	ip = kmem_zalloc(sizeof (struct fc_resource), KM_SLEEP);
	ip->type = RT_CONTIGIOUS;
	ip->fc_contig_virt = (void *)answer;
	ip->fc_contig_len = size;
	fc_add_resource(rp, ip);

	return (fc_success_op(ap, rp, cp));
}

/*
 * gfc_release_memory
 *
 * release-memory ( size vaddr -- )
 */
static int
gfc_release_memory(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	int32_t vaddr, size;
	struct fc_resource *ip;

	if (fc_cell2int(cp->nargs) != 2)
		return (fc_syntax_error(cp, "nargs must be 2"));

	if (fc_cell2int(cp->nresults) != 0)
		return (fc_syntax_error(cp, "nresults must be 0"));

	vaddr = fc_cell2int(fc_arg(cp, 1));
	size = fc_cell2int(fc_arg(cp, 0));

	FC_DEBUG2(1, CE_CONT, "gfc_release_memory: vaddr=0x%x size=0x%x\n",
	    vaddr, size);
	/*
	 * Find if this request matches a mapping resource we set up.
	 */
	fc_lock_resource_list(rp);
	for (ip = rp->head; ip != NULL; ip = ip->next) {
		if (ip->type != RT_CONTIGIOUS)
			continue;
		if (ip->fc_contig_virt != (void *)(uintptr_t)vaddr)
			continue;
		if (ip->fc_contig_len == size)
			break;
	}
	fc_unlock_resource_list(rp);

	if (ip == NULL)
		return (fc_priv_error(cp, "request doesn't match a "
		    "known mapping"));

	(void) ndi_ra_free(ddi_root_node(), vaddr, size,
	    "gptwo-contigousmem", NDI_RA_PASS);

	/*
	 * remove the resource from the list and release it.
	 */
	fc_rem_resource(rp, ip);
	kmem_free(ip, sizeof (struct fc_resource));

	cp->nresults = fc_int2cell(0);

	return (fc_success_op(ap, rp, cp));
}

/*
 * gfc_vtop
 *
 * vtop ( vaddr -- paddr.lo paddr.hi)
 */
static int
gfc_vtop(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	int vaddr;
	uint64_t paddr;
	struct fc_resource *ip;

	if (fc_cell2int(cp->nargs) != 1)
		return (fc_syntax_error(cp, "nargs must be 1"));

	if (fc_cell2int(cp->nresults) >= 3)
		return (fc_syntax_error(cp, "nresults must be less than 2"));

	vaddr = fc_cell2int(fc_arg(cp, 0));

	/*
	 * Find if this request matches a mapping resource we set up.
	 */
	fc_lock_resource_list(rp);
	for (ip = rp->head; ip != NULL; ip = ip->next) {
		if (ip->type != RT_CONTIGIOUS)
			continue;
		if (ip->fc_contig_virt == (void *)(uintptr_t)vaddr)
				break;
	}
	fc_unlock_resource_list(rp);

	if (ip == NULL)
		return (fc_priv_error(cp, "request doesn't match a "
		    "known mapping"));


	paddr = va_to_pa((void *)(uintptr_t)vaddr);

	FC_DEBUG2(1, CE_CONT, "gfc_vtop: vaddr=0x%x paddr=0x%x\n",
	    vaddr, paddr);

	cp->nresults = fc_int2cell(2);

	fc_result(cp, 0) = paddr;
	fc_result(cp, 1) = 0;

	return (fc_success_op(ap, rp, cp));
}

static int
gfc_config_child(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
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

static int
gfc_get_fcode(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
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
		FC_DEBUG1(1, CE_CONT, "gfc_get_fcode: "
		    "fault copying in drop in name %p\n", name_virt);
		status = 0;
	} else {

		fcode = kmem_zalloc(fcode_len, KM_SLEEP);

		if ((status = prom_get_fcode(name, fcode)) != 0) {

			if (copyout((void *)fcode, (void *)fcode_virt,
			    fcode_len)) {
				cmn_err(CE_WARN, " gfc_get_fcode: Unable "
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
gfc_get_fcode_size(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
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
		FC_DEBUG1(1, CE_CONT, "gfc_get_fcode_size: "
		    "fault copying in drop in name %p\n", virt);
		len = 0;
	} else {

		len = prom_get_fcode_size(name);
	}

	kmem_free(name, FC_SVC_NAME_LEN);

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = len;

	return (fc_success_op(ap, rp, cp));
}

static int
gp2_map_phys(dev_info_t *dip, struct regspec *phys_spec,
	caddr_t *addrp, ddi_device_acc_attr_t *accattrp,
	ddi_acc_handle_t *handlep)
{
	ddi_map_req_t mr;
	ddi_acc_hdl_t *hp;
	int result;
	struct regspec *ph;

	*handlep = impl_acc_hdl_alloc(KM_SLEEP, NULL);
	hp = impl_acc_hdl_get(*handlep);
	hp->ah_vers = VERS_ACCHDL;
	hp->ah_dip = dip;
	hp->ah_rnumber = 0;
	hp->ah_offset = 0;
	hp->ah_len = 0;
	hp->ah_acc = *accattrp;
	ph = kmem_zalloc(sizeof (struct regspec), KM_SLEEP);
	*ph = *phys_spec;
	hp->ah_bus_private = ph;	/* cache a copy of the reg spec */

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

static void
gp2_unmap_phys(ddi_acc_handle_t *handlep)
{
	ddi_map_req_t mr;
	ddi_acc_hdl_t *hp;
	struct regspec_t *ph;

	hp = impl_acc_hdl_get(*handlep);
	ASSERT(hp);
	ph = hp->ah_bus_private;

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
	kmem_free(ph, sizeof (struct regspec));	/* Free the cached copy */
	*handlep = (ddi_acc_handle_t)NULL;
}
