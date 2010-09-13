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
 * CPU functions to the Safari Configurator  (gptwo_cpu)
 */

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/mman.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/autoconf.h>
#include <sys/ksynch.h>
#include <sys/promif.h>
#include <sys/ndi_impldefs.h>
#include <sys/ddi_impldefs.h>
#include <sys/machsystm.h>
#include <sys/gp2cfg.h>
#include <sys/gptwo_cpu.h>
#include <sys/cheetahregs.h>

#ifdef DEBUG
int gptwo_cpu_debug = 0;

static void debug(char *, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t);

#define	GPTWO_DEBUG0(level, flag, s) if (gptwo_cpu_debug >= level) \
    cmn_err(flag, s)
#define	GPTWO_DEBUG1(level, flag, fmt, a1) if (gptwo_cpu_debug >= level) \
    debug(fmt, (uintptr_t)(a1), 0, 0, 0, 0);
#define	GPTWO_DEBUG2(level, flag, fmt, a1, a2) if (gptwo_cpu_debug >= level) \
    debug(fmt, (uintptr_t)(a1), (uintptr_t)(a2), 0, 0, 0);
#define	GPTWO_DEBUG3(level, flag, fmt, a1, a2, a3) \
    if (gptwo_cpu_debug >= level) \
    debug(fmt, (uintptr_t)(a1), (uintptr_t)(a2), (uintptr_t)(a3), 0, 0);
#else
#define	GPTWO_DEBUG0(level, flag, s)
#define	GPTWO_DEBUG1(level, flag, fmt, a1)
#define	GPTWO_DEBUG2(level, flag, fmt, a1, a2)
#define	GPTWO_DEBUG3(level, flag, fmt, a1, a2, a3)
#endif

/*
 * Devinfo branch create arg
 */
struct bca {
	spcd_t *pcd;
	uint_t portid;
	uint_t cpuid;
	uint_t coreid;
	uint_t impl;
	dev_info_t *new_child;
};

static dev_info_t *gptwocfg_create_cpu_node(dev_info_t *, spcd_t *,
    uint_t, uint_t, uint_t, uint_t);
static dev_info_t *gptwocfg_create_mc_node(dev_info_t *, spcd_t *, uint_t);
static dev_info_t *gptwocfg_create_cmp_node(dev_info_t *, spcd_t *, uint_t);
static int gptwocfg_create_core_node(dev_info_t *, spcd_t *, uint_t, uint_t);
static int set_mc_props(dev_info_t *new_child, void *arg, uint_t flags);
static int set_cmp_props(dev_info_t *new_child, void *arg, uint_t flags);
static int set_cpu_props(dev_info_t *new_child, void *arg, uint_t flags);
static int set_cpu_common_props(dev_info_t *new_child, struct bca *bcp);
static int set_cpu_us3_props(dev_info_t *new_child, struct bca *bcp);
static int set_cpu_us4_props(dev_info_t *new_child, struct bca *bcp);
static void get_new_child(dev_info_t *rdip, void *arg, uint_t flags);


/*
 * Module linkage information for the kernel.
 */

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops, /* Type of module */
	"gptwo->cpu configurator",
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	int err = 0;

	/* register device with the configurator */
	gptwocfg_register_ops(SAFPTYPE_CPU, gptwocfg_configure_cpu, NULL);

	if ((err = mod_install(&modlinkage)) != 0) {
		GPTWO_DEBUG1(1, CE_WARN, "gptwo_cpu (CPU/MC Functions) "
		"failed to load, error=%d\n", err);
		gptwocfg_unregister_ops(SAFPTYPE_CPU);
	} else {
		GPTWO_DEBUG0(1, CE_WARN, "gptwo_cpu (CPU/MC Functions) "
		"has been loaded.\n");
	}
	return (err);
}

int
_fini(void)
{
	/* cleanup/freeup structs with configurator */
	gptwocfg_unregister_ops(SAFPTYPE_CPU);
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

gptwo_new_nodes_t *
gptwocfg_configure_cpu(dev_info_t *ap, spcd_t *pcd, uint_t portid)
{
	dev_info_t *cpu_node[AGENTS_PER_PORT], *mc_node[AGENTS_PER_PORT];
	dev_info_t *cmp_node = NULL;
	gptwo_new_nodes_t *new_nodes;
	int nodes = 0;
	int i, j = 0;
	uint_t implementation;

	GPTWO_DEBUG2(1, CE_CONT, "gptwocfg_configure_cpu: portid=%x pcd=%lx\n",
	    portid, pcd);

	for (i = 0; i < AGENTS_PER_PORT; i++) {
		cpu_node[i] = NULL;
		mc_node[i] = NULL;
	}

	implementation = (pcd->spcd_ver_reg >> 32) & 0x000000000000ffff;

	switch (implementation) {
	case CHEETAH_IMPL:
	case CHEETAH_PLUS_IMPL:
	case JAGUAR_IMPL:
	case PANTHER_IMPL:
		break;
	default:
		cmn_err(CE_WARN, "Unsupported cpu implementation=0x%x : "
		    "skipping configure of portid=0x%x", implementation,
		    portid);
		ASSERT(0);
		return (NULL);
	}

	if (CPU_IMPL_IS_CMP(implementation)) {
		if (cmp_node = gptwocfg_create_cmp_node(ap, pcd, portid))
			nodes++;
		else
			return (NULL);
	}

	for (i = 0; i < AGENTS_PER_PORT; i++) {
		if (pcd->spcd_agent[i] != SPCD_RSV_PASS)
			continue;

		if (cpu_node[i] = gptwocfg_create_cpu_node(cmp_node ?
		    cmp_node : ap, pcd, portid, pcd->spcd_cpuid[i], i,
		    implementation)) {
			/*
			 * If the CPU is a CMP, the entire branch is
			 * manipulated using just the top node. Thus,
			 * the dips of the individual cores do not need
			 * to be held or stored in the new node list.
			 */
			if (cmp_node) {
				e_ddi_branch_rele(cpu_node[i]);
			} else {
				nodes++;
			}
		}
	}

	/* current implementations have 1 MC node per Safari port */
	if (pcd->spcd_prsv == SPCD_RSV_PASS &&
	    (mc_node[0] = gptwocfg_create_mc_node(ap, pcd, portid)))
		nodes++;

	new_nodes = gptwocfg_allocate_node_list(nodes);

	j = 0;
	for (i = 0; i < AGENTS_PER_PORT; i++) {
		if ((cpu_node[i] != NULL) && (!CPU_IMPL_IS_CMP(implementation)))
			new_nodes->gptwo_nodes[j++] = cpu_node[i];
		if (mc_node[i] != NULL)
			new_nodes->gptwo_nodes[j++] = mc_node[i];
	}

	if (cmp_node)
		new_nodes->gptwo_nodes[j++] = cmp_node;

	return (new_nodes);
}


static dev_info_t *
gptwocfg_create_cmp_node(dev_info_t *ap, spcd_t *pcd, uint_t portid)
{
	struct bca arg;
	devi_branch_t b;

	arg.pcd = pcd;
	arg.portid = portid;
	arg.cpuid = 0;
	arg.coreid = 0;
	arg.new_child = NULL;

	b.arg = &arg;
	b.type = DEVI_BRANCH_SID;
	b.create.sid_branch_create = set_cmp_props;
	b.devi_branch_callback = get_new_child;

	if (e_ddi_branch_create(ap, &b, NULL, 0))
		return (NULL);

	return (arg.new_child);
}

/*ARGSUSED*/
static int
set_cmp_props(dev_info_t *new_child, void *arg, uint_t flags)
{
	struct bca *bap = (struct bca *)arg;
	gptwo_regspec_t	reg;
	spcd_t *pcd;
	uint_t portid;

	pcd = bap->pcd;
	portid = bap->portid;

	GPTWO_DEBUG2(1, CE_CONT, "set_cmp_props: portid=%x pcd=%lx\n",
	    portid, pcd);

	if (ndi_prop_update_string(DDI_DEV_T_NONE, new_child,
	    "name", "cmp") != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cmp_props: failed to "
		    "create name property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "portid", portid) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cmp_props: failed to "
		    "create portid property\n");
		return (DDI_WALK_ERROR);
	}

	reg.gptwo_phys_hi = 0x400 | (portid >> 9);
	reg.gptwo_phys_low = (portid << 23);
	reg.gptwo_size_hi = 0;
	reg.gptwo_size_low = 0x10000;

	if (ndi_prop_update_int_array(DDI_DEV_T_NONE,
	    new_child, "reg", (int *)&reg,
	    sizeof (gptwo_regspec_t) / sizeof (int)) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cmp_props: failed to "
		    "create reg property\n");
		return (DDI_WALK_ERROR);
	}

	return (DDI_WALK_TERMINATE);
}

static dev_info_t *
gptwocfg_create_cpu_node(dev_info_t *ap, spcd_t *pcd, uint_t portid,
    uint_t cpuid, uint_t coreid, uint_t impl)
{
	struct bca arg;
	devi_branch_t b = {0};

	arg.pcd = pcd;
	arg.portid = portid;
	arg.cpuid = cpuid;
	arg.coreid = coreid;
	arg.impl = impl;
	arg.new_child = NULL;

	b.arg = &arg;
	b.type = DEVI_BRANCH_SID;
	b.create.sid_branch_create = set_cpu_props;
	b.devi_branch_callback = get_new_child;

	if (e_ddi_branch_create(ap, &b, NULL, 0))
		return (NULL);

	return (arg.new_child);
}

/*ARGSUSED*/
static int
set_cpu_props(dev_info_t *new_child, void *arg, uint_t flags)
{
	struct bca *bcp = arg;
	uint_t impl = bcp->impl;
	int rc;

	if (set_cpu_common_props(new_child, bcp) != DDI_WALK_CONTINUE)
		return (DDI_WALK_ERROR);

	switch (impl) {
	case CHEETAH_IMPL:
	case CHEETAH_PLUS_IMPL:
		rc = set_cpu_us3_props(new_child, bcp);
		break;
	case JAGUAR_IMPL:
	case PANTHER_IMPL:
		rc = set_cpu_us4_props(new_child, bcp);
		break;
	default:
		ASSERT(0);
		return (DDI_WALK_ERROR);
	}

	return (rc);
}

/*
 * Set properties common to cpu (non-CMP) and core (CMP) nodes.
 *
 *	cpuid
 * 	device_type
 *	manufacturer#
 * 	implementation#
 *	mask#
 *	sparc-version
 * 	clock-frequency
 *	#dtlb-entries
 *	#itlb-entries
 */
static int
set_cpu_common_props(dev_info_t *new_child, struct bca *bcp)
{
	uint_t	cpuid, impl;
	spcd_t	*pcd;
	int	mask, manufacturer;

	cpuid = bcp->cpuid;
	pcd = bcp->pcd;
	impl = bcp->impl;

	mask = (pcd->spcd_ver_reg >> 24) & 0x00000000000000ff;
	manufacturer = (pcd->spcd_ver_reg >> 48) & 0x000000000000ffff;

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "cpuid", cpuid) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_common_props: failed "
		    "to create cpuid property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_string(DDI_DEV_T_NONE, new_child,
	    "device_type", "cpu") != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_common_props: failed "
		    "to create device_type property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child, "manufacturer#",
	    manufacturer) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_common_props: failed "
		    "to create manufacturer# property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child, "implementation#",
	    impl) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_common_props: failed "
		    "to create implementation# property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child, "mask#",
	    mask) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_common_props: failed "
		    "to create mask# property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "sparc-version", 9) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_common_props: failed "
		    "to create sparc-version property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "clock-frequency", (pcd->spcd_afreq * 1000000)) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_common_props: failed "
		    "to create clock-frequency property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "#dtlb-entries", 0x10) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_common_props: failed "
		    "to create #dtlb-entries property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "#itlb-entries", 0x10) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_common_props: failed "
		    "to create #itlb-entries property\n");
		return (DDI_WALK_ERROR);
	}

	return (DDI_WALK_CONTINUE);
}

/*
 * Set cpu node properties for Cheetah and Cheetah+.
 *
 *	name
 * 	portid
 * 	reg
 * 	icache-size
 * 	icache-line-size
 *	icache-associativity
 *	dcache-size
 *	dcache-line-size
 *	dcache-associativity
 *	ecache-size
 *	ecache-line-size
 *	ecache-associativity
 */
static int
set_cpu_us3_props(dev_info_t *new_child, struct bca *bcp)
{
	char *node_name;
	gptwo_regspec_t	reg;
	int ecache_size, ecache_line_size;
	int dimms, ecache_assoc;
	spcd_t *pcd;
	uint_t portid, impl;

	pcd = bcp->pcd;
	portid = bcp->portid;
	impl = bcp->impl;

	ASSERT(IS_CHEETAH(impl) || IS_CHEETAH_PLUS(impl));

	switch (impl) {
	case CHEETAH_IMPL:
		ecache_assoc = CH_ECACHE_NWAY;
		node_name = "SUNW,UltraSPARC-III";
		break;
	case CHEETAH_PLUS_IMPL:
		/*
		 * Hard coding the ecache-associativity to 2 for Cheetah+.
		 * We probably should add this to the PCD.
		 */
		ecache_assoc = CHP_ECACHE_NWAY;
		node_name = "SUNW,UltraSPARC-III+";
		break;
	default:
		GPTWO_DEBUG1(1, CE_CONT, "set_cpu_us3_props: invalid "
		    "implementation=0x%x\n", impl);
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_string(DDI_DEV_T_NONE, new_child,
	    "name", node_name) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us3_props: failed "
		    "to create name property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "portid", portid) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us3_props: failed "
		    "to create portid property\n");
		return (DDI_WALK_ERROR);
	}

	reg.gptwo_phys_hi = 0x400 | (portid >> 9);
	reg.gptwo_phys_low = (portid << 23);
	reg.gptwo_size_hi = 0;
	reg.gptwo_size_low = 0x10000;

	if (ndi_prop_update_int_array(DDI_DEV_T_NONE,
	    new_child, "reg", (int *)&reg,
	    sizeof (gptwo_regspec_t) / sizeof (int)) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us3_props: failed "
		    "to create reg property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "icache-size", CH_ICACHE_SIZE) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us3_props: failed "
		    "to create icache-size property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "icache-line-size", CH_ICACHE_LSIZE) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us3_props: failed "
		    "to create icache-line-size property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "icache-associativity", CH_ICACHE_NWAY) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us3_props: failed "
		    "to create icache-associativity property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "dcache-size", CH_DCACHE_SIZE) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us3_props: failed "
		    "to create dcache-size property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "dcache-line-size", CH_DCACHE_LSIZE) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us3_props: failed "
		    "to create dcache-line-size property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "dcache-associativity", CH_DCACHE_NWAY) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us3_props: failed "
		    "to create dcache-associativity property\n");
		return (DDI_WALK_ERROR);
	}

	/*
	 * Get the External Cache Size from the Common PCD.
	 */
	ecache_size = pcd->spcd_cache * 0x100000;

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "ecache-size", ecache_size) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us3_props: failed "
		    "to create ecache-line-size property\n");
		return (DDI_WALK_ERROR);
	}

	switch (ecache_size) {
	case CH_ECACHE_1M_SIZE:
		ecache_line_size = 64;
		break;
	case CH_ECACHE_4M_SIZE:
		ecache_line_size = 256;
		break;
	case CH_ECACHE_8M_SIZE:
		ecache_line_size = 512;
		break;
	default:
		GPTWO_DEBUG1(1, CE_CONT, "set_cpu_us3_props: invalid "
		    "ecache-size 0x%x\b", ecache_size);
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "ecache-line-size", ecache_line_size) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us3_props: failed "
		    "to create ecache-line-size property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "ecache-associativity", ecache_assoc) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us3_props: failed "
		    "to create ecache-associativity property\n");
		return (DDI_WALK_ERROR);
	}

	/*
	 * Create the ecache-dimm-label property.
	 */
	dimms = 0;

	while ((pcd->sprd_ecache_dimm_label[dimms] != NULL) &&
	    (dimms < MAX_DIMMS_PER_PORT))
		dimms++;

	if (dimms) {
		(void) ndi_prop_update_string_array(DDI_DEV_T_NONE, new_child,
		    "ecache-dimm-label", (char **)pcd->sprd_ecache_dimm_label,
		    dimms);
	}

	return (DDI_WALK_TERMINATE);
}

/*
 * Set cmp core node properties for Jaguar and Panther.
 *
 * 	name
 * 	compatible
 * 	reg
 *	l1-icache-size
 *	l1-icache-line-size
 *	l1-icache-associativity
 *	l1-dcache-size
 *	l1-dcache-line-size
 *	l1-dcache-associativity
 *	l2-cache-size
 *	l2-cache-line-size
 *	l2-cache-associativity
 *	l2-cache-sharing
 *	l3-cache-size
 *	l3-cache-line-size
 *	l3-cache-associativity
 *	l3-cache-sharing
 */
static int
set_cpu_us4_props(dev_info_t *new_child, struct bca *bcp)
{
	uint_t l1_icache_size, l1_icache_line_size;
	uint_t l2_cache_size, l2_cache_line_size, l2_cache_assoc;
	uint_t l2_cache_share;
	uint_t pcd_cache_size;
	uint_t coreid, impl;
	spcd_t *pcd;
	char *compatible;
	int dimms;
	int i;

	pcd = bcp->pcd;
	coreid = bcp->coreid;
	impl = bcp->impl;

	ASSERT(IS_JAGUAR(impl) || IS_PANTHER(impl));

	/*
	 * Get the External Cache Size from the Common PCD.
	 */
	pcd_cache_size = pcd->spcd_cache * 0x100000;

	switch (impl) {
	case JAGUAR_IMPL:
		compatible = "SUNW,UltraSPARC-IV";
		l1_icache_size = CH_ICACHE_SIZE;
		l1_icache_line_size = CH_ICACHE_LSIZE;
		l2_cache_assoc = CHP_ECACHE_NWAY;

		/*
		 * Jaguar has no logical sharing of L2 cache, so the sharing
		 * bit-map will represent this core only.
		 */
		l2_cache_share = coreid ? 0x2 : 0x1;

		/*
		 * Jaguar has a split ecache, so the total ecache must be
		 * divided in half to get the ecache for the individual core.
		 */
		l2_cache_size = pcd_cache_size / 2;

		switch (l2_cache_size) {
		case JG_ECACHE_4M_SIZE:
			l2_cache_line_size = 64;
			break;
		case JG_ECACHE_8M_SIZE:
			l2_cache_line_size = 128;
			break;
		default:
			GPTWO_DEBUG1(1, CE_CONT, "set_cpu_us4_props: "
			    "invalid l2_cache-size 0x%x\n", l2_cache_size);
			return (DDI_WALK_ERROR);
		}
		break;
	case PANTHER_IMPL:
		ASSERT(pcd_cache_size == PN_L3_SIZE);
		compatible = "SUNW,UltraSPARC-IV+";
		l1_icache_size = PN_ICACHE_SIZE;
		l1_icache_line_size = PN_ICACHE_LSIZE;
		l2_cache_size = PN_L2_SIZE;
		l2_cache_line_size = PN_L2_LINESIZE;
		l2_cache_assoc = PN_ECACHE_NWAY;

		/*
		 * For Panther, the L2 and L3 caches are logically shared by
		 * all enabled cores, so the sharing bit-map will represent
		 * all enabled cores.  Panther split-mode is still considered
		 * shared.
		 *
		 * Check the PCD status to determine enabled cores.
		 */
		ASSERT(pcd->spcd_ptype == SAFPTYPE_CPU);
		l2_cache_share = 0;
		for (i = 0; i < AGENTS_PER_PORT; i++) {
			if (pcd->spcd_agent[i] == SPCD_RSV_PASS) {
				l2_cache_share |= (1 << i);
			}
		}

		break;
	default:
		GPTWO_DEBUG1(1, CE_CONT, "set_cpu_us4_props: invalid "
		    "implementation=0x%x\n", impl);
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_string(DDI_DEV_T_NONE, new_child,
	    "name", "cpu") != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us4_props: failed "
		    "to create name property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_string(DDI_DEV_T_NONE, new_child,
	    "compatible", compatible) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us4_props: failed "
		    "to create compatible property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "reg", coreid) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us4_props: failed "
		    "to create reg property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "l1-icache-size", l1_icache_size) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us4_props: failed "
		    "to create l1-icache-size property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "l1-icache-line-size", l1_icache_line_size) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us4_props: failed "
		    "to create icache-line-size property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "l1-icache-associativity", CH_ICACHE_NWAY) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us4_props: failed "
		    "to create l1-icache-associativity property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "l1-dcache-size", CH_DCACHE_SIZE) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us4_props: failed "
		    "to create l1-dcache-size property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "l1-dcache-line-size", CH_DCACHE_LSIZE) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us4_props: failed "
		    "to create dcache-line-size property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "l1-dcache-associativity", CH_DCACHE_NWAY) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us4_props: failed "
		    "to create l1-dcache-associativity property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "l2-cache-size", l2_cache_size) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us4_props: failed "
		    "to create l2-cache-size property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "l2-cache-line-size", l2_cache_line_size) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us4_props: failed "
		    "to create l2_cache-line-size property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "l2-cache-associativity", l2_cache_assoc) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us4_props: failed "
		    "to create l2-cache-associativity property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "l2-cache-sharing", l2_cache_share) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us4_props: failed "
		    "to create l2-cache-sharing property\n");
		return (DDI_WALK_ERROR);
	}

	/*
	 * Create the ecache-dimm-label property.
	 */
	dimms = 0;

	while ((pcd->sprd_ecache_dimm_label[dimms] != NULL) &&
	    (dimms < MAX_DIMMS_PER_PORT))
		dimms++;

	if (dimms) {
		(void) ndi_prop_update_string_array(DDI_DEV_T_NONE, new_child,
		    "ecache-dimm-label", (char **)pcd->sprd_ecache_dimm_label,
		    dimms);
	}

	if (IS_PANTHER(impl)) {
		int l3_cache_share = l2_cache_share;

		if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
		    "l3-cache-size", PN_L3_SIZE) != DDI_SUCCESS) {
			GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us4_props: "
			    "failed to create l3-cache-size property\n");
			return (DDI_WALK_ERROR);
		}

		if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
		    "l3-cache-line-size", PN_L3_LINESIZE) != DDI_SUCCESS) {
			GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us4_props: "
			    "failed to create l3-cache-line-size property\n");
			return (DDI_WALK_ERROR);
		}

		if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
		    "l3-cache-associativity", PN_ECACHE_NWAY) != DDI_SUCCESS) {
			GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us4_props: "
			    "failed to create l3-cache-associativity "
			    "property\n");
			return (DDI_WALK_ERROR);
		}

		if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
		    "l3-cache-sharing", l3_cache_share) != DDI_SUCCESS) {
			GPTWO_DEBUG0(1, CE_CONT, "set_cpu_us4_props: "
			    "failed to create l3-cache-sharing property\n");
			return (DDI_WALK_ERROR);
		}
	}

	return (DDI_WALK_TERMINATE);
}

static dev_info_t *
gptwocfg_create_mc_node(dev_info_t *ap, spcd_t *pcd, uint_t portid)
{
	struct bca arg;
	devi_branch_t b = {0};

	arg.pcd = pcd;
	arg.portid = portid;
	arg.cpuid = portid;
	arg.new_child = NULL;

	b.arg = &arg;
	b.type = DEVI_BRANCH_SID;
	b.create.sid_branch_create = set_mc_props;
	b.devi_branch_callback = get_new_child;

	if (e_ddi_branch_create(ap, &b, NULL, 0))
		return (NULL);

	return (arg.new_child);
}

/*ARGSUSED*/
static int
set_mc_props(dev_info_t *new_child, void *arg, uint_t flags)
{
	struct bca *bcp = arg;
	gptwo_regspec_t	reg;
	int banks, dimms;
	spcd_t *pcd = bcp->pcd;
	uint_t portid = bcp->portid;
	uint_t cpuid = bcp->cpuid;

	GPTWO_DEBUG3(1, CE_CONT, "set_mc_props: ap=0x%lx portid=0x%x "
	    "cpuid=0x%x\n", ddi_get_parent(new_child), portid, cpuid);

	if (ndi_prop_update_string(DDI_DEV_T_NONE, new_child,
	    "name", "memory-controller") != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_mc_props: failed "
		    "to create name property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_string(DDI_DEV_T_NONE, new_child,
	    "compatible", "SUNW,UltraSPARC-III,mc") != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_mc_props: failed "
		    "to create compatible property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_string(DDI_DEV_T_NONE, new_child,
	    "device_type", "memory-controller") != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_mc_props: failed "
		    "to create device_type property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "portid", portid) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_mc_props: failed "
		    "to create portid property\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_child,
	    "cpuid", cpuid) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_mc_props: failed "
		    "to create cpuid property\n");
		return (DDI_WALK_ERROR);
	}

	reg.gptwo_phys_hi = 0x400 | (portid >> 9);
	reg.gptwo_phys_low = (portid << 23) | 0x400000;
	reg.gptwo_size_hi = 0;
	reg.gptwo_size_low = 0x48;

	if (ndi_prop_update_int_array(DDI_DEV_T_NONE,
	    new_child, "reg", (int *)&reg,
	    sizeof (gptwo_regspec_t) / sizeof (int)) != DDI_SUCCESS) {
		GPTWO_DEBUG0(1, CE_CONT, "set_mc_props: failed "
		    "to create reg property\n");
		return (DDI_WALK_ERROR);
	}

	if (pcd->memory_layout) {
		if (ndi_prop_update_byte_array(DDI_DEV_T_NONE,
		    new_child, "memory-layout", (uchar_t *)pcd->memory_layout,
		    pcd->memory_layout_size) != DDI_SUCCESS) {

			GPTWO_DEBUG0(1, CE_CONT, "set_mc_props: failed "
			    "to create memory-layout property\n");

			return (DDI_WALK_ERROR);
		}
	}

	/*
	 * Create the bank-status property.
	 */
	banks = 0;

	while ((pcd->sprd_bank_rsv[banks] != NULL) &&
	    (banks < MAX_BANKS_PER_PORT))
		banks++;

	if (banks) {
		(void) ndi_prop_update_string_array(DDI_DEV_T_NONE, new_child,
		    "bank-status", (char **)pcd->sprd_bank_rsv, banks);
	}

	/*
	 * Create the dimm-status property.
	 */
	dimms = 0;

	while ((pcd->sprd_dimm[dimms] != NULL) &&
	    (dimms < MAX_DIMMS_PER_PORT))
		dimms++;

	if (dimms) {
		(void) ndi_prop_update_string_array(DDI_DEV_T_NONE, new_child,
		    "dimm-status", (char **)pcd->sprd_dimm, dimms);
	}


	return (DDI_WALK_TERMINATE);
}

/*ARGSUSED*/
static void
get_new_child(dev_info_t *rdip, void *arg, uint_t flags)
{
	struct bca *bcp = arg;

	bcp->new_child = rdip;

}

#ifdef DEBUG
static void
debug(char *fmt, uintptr_t a1, uintptr_t a2, uintptr_t a3,
	uintptr_t a4, uintptr_t a5)
{
	cmn_err(CE_CONT, fmt, a1, a2, a3, a4, a5);
}
#endif
