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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/hwconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/machsystm.h>
#include <sys/fcode.h>
#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/opl_cfg.h>
#include <sys/scfd/scfostoescf.h>

static unsigned int		opl_cfg_inited;
static opl_board_cfg_t		opl_boards[HWD_SBS_PER_DOMAIN];

/*
 * Module control operations
 */

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,				/* Type of module */
	"OPL opl_cfg"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

static int	opl_map_in(dev_info_t *, fco_handle_t, fc_ci_t *);
static int	opl_map_out(dev_info_t *, fco_handle_t, fc_ci_t *);
static int	opl_register_fetch(dev_info_t *, fco_handle_t, fc_ci_t *);
static int	opl_register_store(dev_info_t *, fco_handle_t, fc_ci_t *);

static int	opl_claim_memory(dev_info_t *, fco_handle_t, fc_ci_t *);
static int	opl_release_memory(dev_info_t *, fco_handle_t, fc_ci_t *);
static int	opl_vtop(dev_info_t *, fco_handle_t, fc_ci_t *);

static int	opl_config_child(dev_info_t *, fco_handle_t, fc_ci_t *);

static int	opl_get_fcode_size(dev_info_t *, fco_handle_t, fc_ci_t *);
static int	opl_get_fcode(dev_info_t *, fco_handle_t, fc_ci_t *);

static int	opl_map_phys(dev_info_t *, struct regspec *,  caddr_t *,
				ddi_device_acc_attr_t *, ddi_acc_handle_t *);
static void	opl_unmap_phys(ddi_acc_handle_t *);
static int	opl_get_hwd_va(dev_info_t *, fco_handle_t, fc_ci_t *);
static int	opl_master_interrupt(dev_info_t *, fco_handle_t, fc_ci_t *);

extern int	prom_get_fcode_size(char *);
extern int	prom_get_fcode(char *, char *);

static int	master_interrupt_init(uint32_t, uint32_t);

#define	PROBE_STR_SIZE	64
#define	UNIT_ADDR_SIZE	64

opl_fc_ops_t	opl_fc_ops[] = {

	{	FC_MAP_IN,		opl_map_in},
	{	FC_MAP_OUT,		opl_map_out},
	{	"rx@",			opl_register_fetch},
	{	FC_RL_FETCH,		opl_register_fetch},
	{	FC_RW_FETCH,		opl_register_fetch},
	{	FC_RB_FETCH,		opl_register_fetch},
	{	"rx!",			opl_register_store},
	{	FC_RL_STORE,		opl_register_store},
	{	FC_RW_STORE,		opl_register_store},
	{	FC_RB_STORE,		opl_register_store},
	{	"claim-memory",		opl_claim_memory},
	{	"release-memory",	opl_release_memory},
	{	"vtop",			opl_vtop},
	{	FC_CONFIG_CHILD,	opl_config_child},
	{	FC_GET_FCODE_SIZE,	opl_get_fcode_size},
	{	FC_GET_FCODE,		opl_get_fcode},
	{	"get-hwd-va",		opl_get_hwd_va},
	{	"master-interrupt",	opl_master_interrupt},
	{	NULL,			NULL}

};

extern caddr_t	efcode_vaddr;
extern int	efcode_size;

#ifdef DEBUG
#define	HWDDUMP_OFFSETS		1
#define	HWDDUMP_ALL_STATUS	2
#define	HWDDUMP_CHUNKS		3
#define	HWDDUMP_SBP		4

int		hwddump_flags = HWDDUMP_SBP | HWDDUMP_CHUNKS;
#endif

static int	master_interrupt_inited = 0;

int
_init()
{
	int	err = 0;

	/*
	 * Create a resource map for the contiguous memory allocated
	 * at start-of-day in startup.c
	 */
	err = ndi_ra_map_setup(ddi_root_node(), "opl-fcodemem");
	if (err == NDI_FAILURE) {
		cmn_err(CE_WARN, "Cannot setup resource map opl-fcodemem\n");
		return (1);
	}

	/*
	 * Put the allocated memory into the pool.
	 */
	(void) ndi_ra_free(ddi_root_node(), (uint64_t)efcode_vaddr,
	    (uint64_t)efcode_size, "opl-fcodemem", 0);

	if ((err = mod_install(&modlinkage)) != 0) {
		cmn_err(CE_WARN, "opl_cfg failed to load, error=%d", err);
		(void) ndi_ra_map_destroy(ddi_root_node(), "opl-fcodemem");
	}

	return (err);
}

int
_fini(void)
{
	int ret;

	ret = (mod_remove(&modlinkage));
	if (ret != 0)
		return (ret);

	(void) ndi_ra_map_destroy(ddi_root_node(), "opl-fcodemem");

	return (ret);
}

int
_info(modinfop)
struct modinfo *modinfop;
{
	return (mod_info(&modlinkage, modinfop));
}

#ifdef DEBUG
static void
opl_dump_hwd(opl_probe_t *probe)
{
	hwd_header_t		*hdrp;
	hwd_sb_status_t		*statp;
	hwd_domain_info_t	*dinfop;
	hwd_sb_t		*sbp;
	hwd_cpu_chip_t		*chips;
	hwd_pci_ch_t		*channels;
	int			board, i, status;

	board = probe->pr_board;

	hdrp = probe->pr_hdr;
	statp = probe->pr_sb_status;
	dinfop = probe->pr_dinfo;
	sbp = probe->pr_sb;

	printf("HWD: board %d\n", board);
	printf("HWD:magic = 0x%x\n", hdrp->hdr_magic);
	printf("HWD:version = 0x%x.%x\n", hdrp->hdr_version.major,
	    hdrp->hdr_version.minor);

	if (hwddump_flags & HWDDUMP_OFFSETS) {
		printf("HWD:status offset = 0x%x\n",
		    hdrp->hdr_sb_status_offset);
		printf("HWD:domain offset = 0x%x\n",
		    hdrp->hdr_domain_info_offset);
		printf("HWD:board offset = 0x%x\n", hdrp->hdr_sb_info_offset);
	}

	if (hwddump_flags & HWDDUMP_SBP)
		printf("HWD:sb_t ptr = 0x%p\n", (void *)probe->pr_sb);

	if (hwddump_flags & HWDDUMP_ALL_STATUS) {
		int bd;
		printf("HWD:board status =");
		for (bd = 0; bd < HWD_SBS_PER_DOMAIN; bd++)
			printf("%x ", statp->sb_status[bd]);
		printf("\n");
	} else {
		printf("HWD:board status = %d\n", statp->sb_status[board]);
	}

	printf("HWD:banner name = %s\n", dinfop->dinf_banner_name);
	printf("HWD:platform = %s\n", dinfop->dinf_platform_token);

	printf("HWD:chip status:\n");
	chips = &sbp->sb_cmu.cmu_cpu_chips[0];
	for (i = 0; i < HWD_CPU_CHIPS_PER_CMU; i++) {

		status = chips[i].chip_status;
		printf("chip[%d] = ", i);
		if (HWD_STATUS_NONE(status))
			printf("none");
		else if (HWD_STATUS_FAILED(status))
			printf("fail");
		else if (HWD_STATUS_OK(status))
			printf("ok");
		printf("\n");
	}

	if (hwddump_flags & HWDDUMP_CHUNKS) {
		int chunk;
		hwd_memory_t *mem = &sbp->sb_cmu.cmu_memory;
		printf("HWD:chunks:\n");
		for (chunk = 0; chunk < HWD_MAX_MEM_CHUNKS; chunk++)
			printf("\t%d 0x%lx 0x%lx\n", chunk,
			    mem->mem_chunks[chunk].chnk_start_address,
			    mem->mem_chunks[chunk].chnk_size);
	}

	printf("HWD:channel status:\n");
	channels = &sbp->sb_pci_ch[0];
	for (i = 0; i < HWD_PCI_CHANNELS_PER_SB; i++) {

		status = channels[i].pci_status;
		printf("channels[%d] = ", i);
		if (HWD_STATUS_NONE(status))
			printf("none");
		else if (HWD_STATUS_FAILED(status))
			printf("fail");
		else if (HWD_STATUS_OK(status))
			printf("ok");
		printf("\n");
	}
	printf("channels[%d] = ", i);
	status = sbp->sb_cmu.cmu_ch.chan_status;
	if (HWD_STATUS_NONE(status))
		printf("none");
	else if (HWD_STATUS_FAILED(status))
		printf("fail");
	else if (HWD_STATUS_OK(status))
		printf("ok");
	printf("\n");
}
#endif /* DEBUG */

#ifdef UCTEST
	/*
	 * For SesamI debugging, just map the SRAM directly to a kernel
	 * VA and read it out from there
	 */

#include <sys/vmem.h>
#include <vm/seg_kmem.h>

/*
 * 0x4081F1323000LL is the HWD base address for LSB 0. But we need to map
 * at page boundaries. So, we use a base address of 0x4081F1322000LL.
 * Note that this has to match the HWD base pa set in .sesami-common-defs.
 *
 * The size specified for the HWD in the SCF spec is 36K. But since
 * we adjusted the base address by 4K, we need to use 40K for the
 * mapping size to cover the HWD. And 40K is also a multiple of the
 * base page size.
 */
#define	OPL_HWD_BASE(lsb)       \
(0x4081F1322000LL | (((uint64_t)(lsb)) << 40))

	void    *opl_hwd_vaddr;
#endif /* UCTEST */

/*
 * Get the hardware descriptor from SCF.
 */

/*ARGSUSED*/
int
opl_read_hwd(int board, hwd_header_t **hdrp, hwd_sb_status_t **statp,
	hwd_domain_info_t **dinfop, hwd_sb_t **sbp)
{
	static int (*getinfop)(uint32_t, uint8_t, uint32_t, uint32_t *,
	    void *) = NULL;
	void *hwdp;

	uint32_t key = KEY_ESCF;	/* required value */
	uint8_t  type = 0x40;		/* SUB_OS_RECEIVE_HWD */
	uint32_t transid = board;
	uint32_t datasize = HWD_DATA_SIZE;

	hwd_header_t		*hd;
	hwd_sb_status_t		*st;
	hwd_domain_info_t	*di;
	hwd_sb_t		*sb;

	int	ret;

	if (opl_boards[board].cfg_hwd == NULL) {
#ifdef UCTEST
		/*
		 * Just map the HWD in SRAM to a kernel VA
		 */

		size_t			size;
		pfn_t			pfn;

		size = 0xA000;

		opl_hwd_vaddr = vmem_alloc(heap_arena, size, VM_SLEEP);
		if (opl_hwd_vaddr == NULL) {
			cmn_err(CE_NOTE, "No space for HWD");
			return (-1);
		}

		pfn = btop(OPL_HWD_BASE(board));
		hat_devload(kas.a_hat, opl_hwd_vaddr, size, pfn, PROT_READ,
		    HAT_LOAD_NOCONSIST | HAT_LOAD_LOCK);

		hwdp = (void *)((char *)opl_hwd_vaddr + 0x1000);
		opl_boards[board].cfg_hwd = hwdp;
		ret = 0;
#else

		/* find the scf_service_getinfo() function */
		if (getinfop == NULL)
			getinfop = (int (*)(uint32_t, uint8_t, uint32_t,
			    uint32_t *,
			    void *))modgetsymvalue("scf_service_getinfo", 0);

		if (getinfop == NULL)
			return (-1);

		/* allocate memory to receive the data */
		hwdp = kmem_alloc(HWD_DATA_SIZE, KM_SLEEP);

		/* get the HWD */
		ret = (*getinfop)(key, type, transid, &datasize, hwdp);
		if (ret == 0)
			opl_boards[board].cfg_hwd = hwdp;
		else
			kmem_free(hwdp, HWD_DATA_SIZE);
#endif
	} else {
		hwdp = opl_boards[board].cfg_hwd;
		ret = 0;
	}

	/* copy the data to the destination */
	if (ret == 0) {
		hd = (hwd_header_t *)hwdp;
		st = (hwd_sb_status_t *)
		    ((char *)hwdp + hd->hdr_sb_status_offset);
		di = (hwd_domain_info_t *)
		    ((char *)hwdp + hd->hdr_domain_info_offset);
		sb = (hwd_sb_t *)
		    ((char *)hwdp + hd->hdr_sb_info_offset);
		if (hdrp != NULL)
			*hdrp = hd;
		if (statp != NULL)
			*statp = st;
		if (dinfop != NULL)
			*dinfop = di;
		if (sbp != NULL)
			*sbp = sb;
	}

	return (ret);
}

/*
 * The opl_probe_t probe structure is used to pass all sorts of parameters
 * to callback functions during probing. It also contains a snapshot of
 * the hardware descriptor that is taken at the beginning of a probe.
 */
static int
opl_probe_init(opl_probe_t *probe)
{
	hwd_header_t		**hdrp;
	hwd_sb_status_t		**statp;
	hwd_domain_info_t	**dinfop;
	hwd_sb_t		**sbp;
	int			board, ret;

	board = probe->pr_board;

	hdrp = &probe->pr_hdr;
	statp = &probe->pr_sb_status;
	dinfop = &probe->pr_dinfo;
	sbp = &probe->pr_sb;

	/*
	 * Read the hardware descriptor.
	 */
	ret = opl_read_hwd(board, hdrp, statp, dinfop, sbp);
	if (ret != 0) {

		cmn_err(CE_WARN, "IKP: failed to read HWD header");
		return (-1);
	}

#ifdef DEBUG
	opl_dump_hwd(probe);
#endif
	return (0);
}

/*
 * This function is used to obtain pointers to relevant device nodes
 * which are created by Solaris at boot time.
 *
 * This function walks the child nodes of a given node, extracts
 * the "name" property, if it exists, and passes the node to a
 * callback init function. The callback determines if this node is
 * interesting or not. If it is, then a pointer to the node is
 * stored away by the callback for use during unprobe.
 *
 * The DDI get property function allocates storage for the name
 * property. That needs to be freed within this function.
 */
static int
opl_init_nodes(dev_info_t *parent, opl_init_func_t init)
{
	dev_info_t	*node;
	char		*name;
	int 		circ, ret;
	int		len;

	ASSERT(parent != NULL);

	/*
	 * Hold parent node busy to walk its child list
	 */
	ndi_devi_enter(parent, &circ);
	node = ddi_get_child(parent);

	while (node != NULL) {

		ret = OPL_GET_PROP(string, node, "name", &name, &len);
		if (ret != DDI_PROP_SUCCESS) {
			/*
			 * The property does not exist for this node.
			 */
			node = ddi_get_next_sibling(node);
			continue;
		}

		ret = init(node, name, len);
		kmem_free(name, len);
		if (ret != 0) {

			ndi_devi_exit(parent, circ);
			return (-1);
		}

		node = ddi_get_next_sibling(node);
	}

	ndi_devi_exit(parent, circ);

	return (0);
}

/*
 * This init function finds all the interesting nodes under the
 * root node and stores pointers to them. The following nodes
 * are considered interesting by this implementation:
 *
 *	"cmp"
 *		These are nodes that represent processor chips.
 *
 *	"pci"
 *		These are nodes that represent PCI leaves.
 *
 *	"pseudo-mc"
 *		These are nodes that contain memory information.
 */
static int
opl_init_root_nodes(dev_info_t *node, char *name, int len)
{
	int		portid, board, chip, channel, leaf;
	int		ret;

	if (strncmp(name, OPL_CPU_CHIP_NODE, len) == 0) {

		ret = OPL_GET_PROP(int, node, "portid", &portid, -1);
		if (ret != DDI_PROP_SUCCESS)
			return (-1);

		ret = OPL_GET_PROP(int, node, "board#", &board, -1);
		if (ret != DDI_PROP_SUCCESS)
			return (-1);

		chip = OPL_CPU_CHIP(portid);
		opl_boards[board].cfg_cpu_chips[chip] = node;

	} else if (strncmp(name, OPL_PCI_LEAF_NODE, len) == 0) {

		ret = OPL_GET_PROP(int, node, "portid", &portid, -1);
		if (ret != DDI_PROP_SUCCESS)
			return (-1);

		board = OPL_IO_PORTID_TO_LSB(portid);
		channel = OPL_PORTID_TO_CHANNEL(portid);

		if (channel == OPL_CMU_CHANNEL) {

			opl_boards[board].cfg_cmuch_leaf = node;

		} else {

			leaf = OPL_PORTID_TO_LEAF(portid);
			opl_boards[board].cfg_pcich_leaf[channel][leaf] = node;
		}
	} else if (strncmp(name, OPL_PSEUDO_MC_NODE, len) == 0) {

		ret = OPL_GET_PROP(int, node, "board#", &board, -1);
		if (ret != DDI_PROP_SUCCESS)
			return (-1);

		ASSERT((board >= 0) && (board < HWD_SBS_PER_DOMAIN));

		opl_boards[board].cfg_pseudo_mc = node;
	}

	return (0);
}

/*
 * This function initializes the OPL IKP feature. Currently, all it does
 * is find the interesting nodes that Solaris has created at boot time
 * for boards present at boot time and store pointers to them. This
 * is useful if those boards are unprobed by DR.
 */
int
opl_init_cfg()
{
	dev_info_t	*root;

	if (opl_cfg_inited == 0) {

		root = ddi_root_node();
		if ((opl_init_nodes(root, opl_init_root_nodes) != 0)) {
			cmn_err(CE_WARN, "IKP: init failed");
			return (1);
		}

		opl_cfg_inited = 1;
	}

	return (0);
}

/*
 * When DR is initialized, we walk the device tree and acquire a hold on
 * all the nodes that are interesting to IKP. This is so that the corresponding
 * branches cannot be deleted.
 *
 * The following function informs the walk about which nodes are interesting
 * so that it can hold the corresponding branches.
 */
static int
opl_hold_node(char *name)
{
	/*
	 * We only need to hold/release the following nodes which
	 * represent separate branches that must be managed.
	 */
	return ((strcmp(name, OPL_CPU_CHIP_NODE) == 0) ||
	    (strcmp(name, OPL_PSEUDO_MC_NODE) == 0) ||
	    (strcmp(name, OPL_PCI_LEAF_NODE) == 0));
}

static int
opl_hold_rele_devtree(dev_info_t *rdip, void *arg)
{

	int	*holdp = (int *)arg;
	char	*name = ddi_node_name(rdip);

	/*
	 * We only need to hold/release the following nodes which
	 * represent separate branches that must be managed.
	 */
	if (opl_hold_node(name) == 0) {
		/* Not of interest to us */
		return (DDI_WALK_PRUNECHILD);
	}
	if (*holdp) {
		ASSERT(!e_ddi_branch_held(rdip));
		e_ddi_branch_hold(rdip);
	} else {
		ASSERT(e_ddi_branch_held(rdip));
		e_ddi_branch_rele(rdip);
	}

	return (DDI_WALK_PRUNECHILD);
}

void
opl_hold_devtree()
{
	dev_info_t *dip;
	int circ;
	int hold = 1;

	dip = ddi_root_node();
	ndi_devi_enter(dip, &circ);
	ddi_walk_devs(ddi_get_child(dip), opl_hold_rele_devtree, &hold);
	ndi_devi_exit(dip, circ);
}

void
opl_release_devtree()
{
	dev_info_t *dip;
	int circ;
	int hold = 0;

	dip = ddi_root_node();
	ndi_devi_enter(dip, &circ);
	ddi_walk_devs(ddi_get_child(dip), opl_hold_rele_devtree, &hold);
	ndi_devi_exit(dip, circ);
}

/*
 * This is a helper function that allows opl_create_node() to return a
 * pointer to a newly created node to its caller.
 */
/*ARGSUSED*/
static void
opl_set_node(dev_info_t *node, void *arg, uint_t flags)
{
	opl_probe_t	*probe;

	probe = arg;
	probe->pr_node = node;
}

/*
 * Function to create a node in the device tree under a specified parent.
 *
 * e_ddi_branch_create() allows the creation of a whole branch with a
 * single call of the function. However, we only use it to create one node
 * at a time in the case of non-I/O device nodes. In other words, we
 * create branches by repeatedly using this function. This makes the
 * code more readable.
 *
 * The branch descriptor passed to e_ddi_branch_create() takes two
 * callbacks. The create() callback is used to set the properties of a
 * newly created node. The other callback is used to return a pointer
 * to the newly created node. The create() callback is passed by the
 * caller of this function based on the kind of node it wishes to
 * create.
 *
 * e_ddi_branch_create() returns with the newly created node held. We
 * only need to hold the top nodes of the branches we create. We release
 * the hold for the others. E.g., the "cmp" node needs to be held. Since
 * we hold the "cmp" node, there is no need to hold the "core" and "cpu"
 * nodes below it.
 */
static dev_info_t *
opl_create_node(opl_probe_t *probe)
{
	devi_branch_t	branch;

	probe->pr_node = NULL;

	branch.arg = probe;
	branch.type = DEVI_BRANCH_SID;
	branch.create.sid_branch_create = probe->pr_create;
	branch.devi_branch_callback = opl_set_node;

	if (e_ddi_branch_create(probe->pr_parent, &branch, NULL, 0) != 0)
		return (NULL);

	ASSERT(probe->pr_node != NULL);

	if (probe->pr_hold == 0)
		e_ddi_branch_rele(probe->pr_node);

	return (probe->pr_node);
}

/*
 * Function to tear down a whole branch rooted at the specified node.
 *
 * Although we create each node of a branch individually, we destroy
 * a whole branch in one call. This is more efficient.
 */
static int
opl_destroy_node(dev_info_t *node)
{
	if (e_ddi_branch_destroy(node, NULL, 0) != 0) {
		char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		(void) ddi_pathname(node, path);
		cmn_err(CE_WARN, "OPL node removal failed: %s (%p)", path,
		    (void *)node);
		kmem_free(path, MAXPATHLEN);
		return (-1);
	}

	return (0);
}

/*
 * Set the properties for a "cpu" node.
 */
/*ARGSUSED*/
static int
opl_create_cpu(dev_info_t *node, void *arg, uint_t flags)
{
	opl_probe_t	*probe;
	hwd_cpu_chip_t	*chip;
	hwd_core_t	*core;
	hwd_cpu_t	*cpu;
	int		ret;

	probe = arg;
	chip = &probe->pr_sb->sb_cmu.cmu_cpu_chips[probe->pr_cpu_chip];
	core = &chip->chip_cores[probe->pr_core];
	cpu = &core->core_cpus[probe->pr_cpu];
	OPL_UPDATE_PROP(string, node, "name", OPL_CPU_NODE);
	OPL_UPDATE_PROP(string, node, "device_type", OPL_CPU_NODE);

	OPL_UPDATE_PROP(int, node, "cpuid", cpu->cpu_cpuid);
	OPL_UPDATE_PROP(int, node, "reg", probe->pr_cpu);

	OPL_UPDATE_PROP(string, node, "status", "okay");

	return (DDI_WALK_TERMINATE);
}

/*
 * Create "cpu" nodes as child nodes of a given "core" node.
 */
static int
opl_probe_cpus(opl_probe_t *probe)
{
	int		i;
	hwd_cpu_chip_t	*chip;
	hwd_core_t	*core;
	hwd_cpu_t	*cpus;

	chip = &probe->pr_sb->sb_cmu.cmu_cpu_chips[probe->pr_cpu_chip];
	core = &chip->chip_cores[probe->pr_core];
	cpus = &core->core_cpus[0];

	for (i = 0; i < HWD_CPUS_PER_CORE; i++) {

		/*
		 * Olympus-C has 2 cpus per core.
		 * Jupiter has 4 cpus per core.
		 * For the Olympus-C based platform, we expect the cpu_status
		 * of the non-existent cpus to be set to missing.
		 */
		if (!HWD_STATUS_OK(cpus[i].cpu_status))
			continue;

		probe->pr_create = opl_create_cpu;
		probe->pr_cpu = i;
		if (opl_create_node(probe) == NULL) {

			cmn_err(CE_WARN, "IKP: create cpu (%d-%d-%d-%d) failed",
			    probe->pr_board, probe->pr_cpu_chip, probe->pr_core,
			    probe->pr_cpu);
			return (-1);
		}
	}

	return (0);
}

/*
 * Set the properties for a "core" node.
 */
/*ARGSUSED*/
static int
opl_create_core(dev_info_t *node, void *arg, uint_t flags)
{
	opl_probe_t	*probe;
	hwd_cpu_chip_t	*chip;
	hwd_core_t	*core;
	int		sharing[2];
	int		ret;

	probe = arg;
	chip = &probe->pr_sb->sb_cmu.cmu_cpu_chips[probe->pr_cpu_chip];
	core = &chip->chip_cores[probe->pr_core];

	OPL_UPDATE_PROP(string, node, "name", OPL_CORE_NODE);
	OPL_UPDATE_PROP(string, node, "device_type", OPL_CORE_NODE);
	OPL_UPDATE_PROP(string, node, "compatible", chip->chip_compatible);

	OPL_UPDATE_PROP(int, node, "reg", probe->pr_core);
	OPL_UPDATE_PROP(int, node, "manufacturer#", core->core_manufacturer);
	OPL_UPDATE_PROP(int, node, "implementation#",
	    core->core_implementation);
	OPL_UPDATE_PROP(int, node, "mask#", core->core_mask);

	OPL_UPDATE_PROP(int, node, "sparc-version", 9);
	OPL_UPDATE_PROP(int, node, "clock-frequency", core->core_frequency);

	OPL_UPDATE_PROP(int, node, "l1-icache-size", core->core_l1_icache_size);
	OPL_UPDATE_PROP(int, node, "l1-icache-line-size",
	    core->core_l1_icache_line_size);
	OPL_UPDATE_PROP(int, node, "l1-icache-associativity",
	    core->core_l1_icache_associativity);
	OPL_UPDATE_PROP(int, node, "#itlb-entries",
	    core->core_num_itlb_entries);

	OPL_UPDATE_PROP(int, node, "l1-dcache-size", core->core_l1_dcache_size);
	OPL_UPDATE_PROP(int, node, "l1-dcache-line-size",
	    core->core_l1_dcache_line_size);
	OPL_UPDATE_PROP(int, node, "l1-dcache-associativity",
	    core->core_l1_dcache_associativity);
	OPL_UPDATE_PROP(int, node, "#dtlb-entries",
	    core->core_num_dtlb_entries);

	OPL_UPDATE_PROP(int, node, "l2-cache-size", core->core_l2_cache_size);
	OPL_UPDATE_PROP(int, node, "l2-cache-line-size",
	    core->core_l2_cache_line_size);
	OPL_UPDATE_PROP(int, node, "l2-cache-associativity",
	    core->core_l2_cache_associativity);
	sharing[0] = 0;
	sharing[1] = core->core_l2_cache_sharing;
	OPL_UPDATE_PROP_ARRAY(int, node, "l2-cache-sharing", sharing, 2);

	OPL_UPDATE_PROP(string, node, "status", "okay");

	return (DDI_WALK_TERMINATE);
}

/*
 * Create "core" nodes as child nodes of a given "cmp" node.
 *
 * Create the branch below each "core" node".
 */
static int
opl_probe_cores(opl_probe_t *probe)
{
	int		i;
	hwd_cpu_chip_t	*chip;
	hwd_core_t	*cores;
	dev_info_t	*parent, *node;

	chip = &probe->pr_sb->sb_cmu.cmu_cpu_chips[probe->pr_cpu_chip];
	cores = &chip->chip_cores[0];
	parent = probe->pr_parent;

	for (i = 0; i < HWD_CORES_PER_CPU_CHIP; i++) {

		if (!HWD_STATUS_OK(cores[i].core_status))
			continue;

		probe->pr_parent = parent;
		probe->pr_create = opl_create_core;
		probe->pr_core = i;
		node = opl_create_node(probe);
		if (node == NULL) {

			cmn_err(CE_WARN, "IKP: create core (%d-%d-%d) failed",
			    probe->pr_board, probe->pr_cpu_chip,
			    probe->pr_core);
			return (-1);
		}

		/*
		 * Create "cpu" nodes below "core".
		 */
		probe->pr_parent = node;
		if (opl_probe_cpus(probe) != 0)
			return (-1);
		probe->pr_cpu_impl |= (1 << cores[i].core_implementation);
	}

	return (0);
}

/*
 * Set the properties for a "cmp" node.
 */
/*ARGSUSED*/
static int
opl_create_cpu_chip(dev_info_t *node, void *arg, uint_t flags)
{
	opl_probe_t	*probe;
	hwd_cpu_chip_t	*chip;
	opl_range_t	range;
	uint64_t	dummy_addr;
	int		ret;

	probe = arg;
	chip = &probe->pr_sb->sb_cmu.cmu_cpu_chips[probe->pr_cpu_chip];

	OPL_UPDATE_PROP(string, node, "name", OPL_CPU_CHIP_NODE);

	OPL_UPDATE_PROP(int, node, "portid", chip->chip_portid);
	OPL_UPDATE_PROP(int, node, "board#", probe->pr_board);

	dummy_addr = OPL_PROC_AS(probe->pr_board, probe->pr_cpu_chip);
	range.rg_addr_hi = OPL_HI(dummy_addr);
	range.rg_addr_lo = OPL_LO(dummy_addr);
	range.rg_size_hi = 0;
	range.rg_size_lo = 0;
	OPL_UPDATE_PROP_ARRAY(int, node, "reg", (int *)&range, 4);

	OPL_UPDATE_PROP(int, node, "#address-cells", 1);
	OPL_UPDATE_PROP(int, node, "#size-cells", 0);

	OPL_UPDATE_PROP(string, node, "status", "okay");

	return (DDI_WALK_TERMINATE);
}

/*
 * Create "cmp" nodes as child nodes of the root node.
 *
 * Create the branch below each "cmp" node.
 */
static int
opl_probe_cpu_chips(opl_probe_t *probe)
{
	int		i;
	dev_info_t	**cfg_cpu_chips;
	hwd_cpu_chip_t	*chips;
	dev_info_t	*node;

	cfg_cpu_chips = opl_boards[probe->pr_board].cfg_cpu_chips;
	chips = &probe->pr_sb->sb_cmu.cmu_cpu_chips[0];

	for (i = 0; i < HWD_CPU_CHIPS_PER_CMU; i++) {

		ASSERT(cfg_cpu_chips[i] == NULL);

		if (!HWD_STATUS_OK(chips[i].chip_status))
			continue;

		probe->pr_parent = ddi_root_node();
		probe->pr_create = opl_create_cpu_chip;
		probe->pr_cpu_chip = i;
		probe->pr_hold = 1;
		node = opl_create_node(probe);
		if (node == NULL) {

			cmn_err(CE_WARN, "IKP: create chip (%d-%d) failed",
			    probe->pr_board, probe->pr_cpu_chip);
			return (-1);
		}

		cfg_cpu_chips[i] = node;

		/*
		 * Create "core" nodes below "cmp".
		 * We hold the "cmp" node. So, there is no need to hold
		 * the "core" and "cpu" nodes below it.
		 */
		probe->pr_parent = node;
		probe->pr_hold = 0;
		if (opl_probe_cores(probe) != 0)
			return (-1);
	}

	return (0);
}

/*
 * Set the properties for a "pseudo-mc" node.
 */
/*ARGSUSED*/
static int
opl_create_pseudo_mc(dev_info_t *node, void *arg, uint_t flags)
{
	opl_probe_t	*probe;
	int		board, portid;
	hwd_bank_t	*bank;
	hwd_memory_t	*mem;
	opl_range_t	range;
	opl_mc_addr_t	mc[HWD_BANKS_PER_CMU];
	int		status[2][7];
	int		i, j;
	int		ret;

	probe = arg;
	board = probe->pr_board;

	OPL_UPDATE_PROP(string, node, "name", OPL_PSEUDO_MC_NODE);
	OPL_UPDATE_PROP(string, node, "device_type", "memory-controller");
	OPL_UPDATE_PROP(string, node, "compatible", "FJSV,oplmc");

	portid = OPL_LSB_TO_PSEUDOMC_PORTID(board);
	OPL_UPDATE_PROP(int, node, "portid", portid);

	range.rg_addr_hi = OPL_HI(OPL_MC_AS(board));
	range.rg_addr_lo = 0x200;
	range.rg_size_hi = 0;
	range.rg_size_lo = 0;
	OPL_UPDATE_PROP_ARRAY(int, node, "reg", (int *)&range, 4);

	OPL_UPDATE_PROP(int, node, "board#", board);
	OPL_UPDATE_PROP(int, node, "physical-board#",
	    probe->pr_sb->sb_psb_number);

	OPL_UPDATE_PROP(int, node, "#address-cells", 1);
	OPL_UPDATE_PROP(int, node, "#size-cells", 2);

	mem = &probe->pr_sb->sb_cmu.cmu_memory;

	range.rg_addr_hi = OPL_HI(mem->mem_start_address);
	range.rg_addr_lo = OPL_LO(mem->mem_start_address);
	range.rg_size_hi = OPL_HI(mem->mem_size);
	range.rg_size_lo = OPL_LO(mem->mem_size);
	OPL_UPDATE_PROP_ARRAY(int, node, "sb-mem-ranges", (int *)&range, 4);

	bank = probe->pr_sb->sb_cmu.cmu_memory.mem_banks;
	for (i = 0, j = 0; i < HWD_BANKS_PER_CMU; i++) {

		if (!HWD_STATUS_OK(bank[i].bank_status))
			continue;

		mc[j].mc_bank = i;
		mc[j].mc_hi = OPL_HI(bank[i].bank_register_address);
		mc[j].mc_lo = OPL_LO(bank[i].bank_register_address);
		j++;
	}

	if (j > 0) {
		OPL_UPDATE_PROP_ARRAY(int, node, "mc-addr", (int *)mc, j*3);
	} else {
		/*
		 * If there is no memory, we need the mc-addr property, but
		 * it is length 0.  The only way to do this using ndi seems
		 * to be by creating a boolean property.
		 */
		ret = ndi_prop_create_boolean(DDI_DEV_T_NONE, node, "mc-addr");
		OPL_UPDATE_PROP_ERR(ret, "mc-addr");
	}

	OPL_UPDATE_PROP_ARRAY(byte, node, "cs0-mc-pa-trans-table",
	    mem->mem_cs[0].cs_pa_mac_table, 64);
	OPL_UPDATE_PROP_ARRAY(byte, node, "cs1-mc-pa-trans-table",
	    mem->mem_cs[1].cs_pa_mac_table, 64);

#define	CS_PER_MEM 2

	for (i = 0, j = 0; i < CS_PER_MEM; i++) {
		if (HWD_STATUS_OK(mem->mem_cs[i].cs_status) ||
		    HWD_STATUS_FAILED(mem->mem_cs[i].cs_status)) {
			status[j][0] = i;
			if (HWD_STATUS_OK(mem->mem_cs[i].cs_status))
				status[j][1] = 0;
			else
				status[j][1] = 1;
			status[j][2] =
			    OPL_HI(mem->mem_cs[i].cs_available_capacity);
			status[j][3] =
			    OPL_LO(mem->mem_cs[i].cs_available_capacity);
			status[j][4] = OPL_HI(mem->mem_cs[i].cs_dimm_capacity);
			status[j][5] = OPL_LO(mem->mem_cs[i].cs_dimm_capacity);
			status[j][6] = mem->mem_cs[i].cs_number_of_dimms;
			j++;
		}
	}

	if (j > 0) {
		OPL_UPDATE_PROP_ARRAY(int, node, "cs-status", (int *)status,
		    j*7);
	} else {
		/*
		 * If there is no memory, we need the cs-status property, but
		 * it is length 0.  The only way to do this using ndi seems
		 * to be by creating a boolean property.
		 */
		ret = ndi_prop_create_boolean(DDI_DEV_T_NONE, node,
		    "cs-status");
		OPL_UPDATE_PROP_ERR(ret, "cs-status");
	}

	return (DDI_WALK_TERMINATE);
}

/*
 * Create "pseudo-mc" nodes
 */
static int
opl_probe_memory(opl_probe_t *probe)
{
	int		board;
	opl_board_cfg_t	*board_cfg;
	dev_info_t	*node;

	board = probe->pr_board;
	board_cfg = &opl_boards[board];

	ASSERT(board_cfg->cfg_pseudo_mc == NULL);

	probe->pr_parent = ddi_root_node();
	probe->pr_create = opl_create_pseudo_mc;
	probe->pr_hold = 1;
	node = opl_create_node(probe);
	if (node == NULL) {

		cmn_err(CE_WARN, "IKP: create pseudo-mc (%d) failed", board);
		return (-1);
	}

	board_cfg->cfg_pseudo_mc = node;

	return (0);
}

/*
 * Allocate the fcode ops handle.
 */
/*ARGSUSED*/
static
fco_handle_t
opl_fc_ops_alloc_handle(dev_info_t *parent, dev_info_t *child,
			void *fcode, size_t fcode_size, char *unit_address,
			char *my_args)
{
	fco_handle_t	rp;
	phandle_t	h;
	char		*buf;

	rp = kmem_zalloc(sizeof (struct fc_resource_list), KM_SLEEP);
	rp->next_handle = fc_ops_alloc_handle(parent, child, fcode, fcode_size,
	    unit_address, NULL);
	rp->ap = parent;
	rp->child = child;
	rp->fcode = fcode;
	rp->fcode_size = fcode_size;
	rp->my_args = my_args;

	if (unit_address) {
		buf = kmem_zalloc(UNIT_ADDR_SIZE, KM_SLEEP);
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


static void
opl_fc_ops_free_handle(fco_handle_t rp)
{
	struct fc_resource	*resp, *nresp;

	ASSERT(rp);

	if (rp->next_handle)
		fc_ops_free_handle(rp->next_handle);
	if (rp->unit_address)
		kmem_free(rp->unit_address, UNIT_ADDR_SIZE);

	/*
	 * Release all the resources from the resource list
	 */
	for (resp = rp->head; resp != NULL; resp = nresp) {
		nresp = resp->next;
		switch (resp->type) {

		case RT_MAP:
			/*
			 * If this is still mapped, we'd better unmap it now,
			 * or all our structures that are tracking it will
			 * be leaked.
			 */
			if (resp->fc_map_handle != NULL)
				opl_unmap_phys(&resp->fc_map_handle);
			break;

		case RT_DMA:
			/*
			 * DMA has to be freed up at exit time.
			 */
			cmn_err(CE_CONT,
			    "opl_fc_ops_free_handle: Unexpected DMA seen!");
			break;

		case RT_CONTIGIOUS:
			FC_DEBUG2(1, CE_CONT, "opl_fc_ops_free: "
			    "Free claim-memory resource 0x%lx size 0x%x\n",
			    resp->fc_contig_virt, resp->fc_contig_len);

			(void) ndi_ra_free(ddi_root_node(),
			    (uint64_t)resp->fc_contig_virt,
			    resp->fc_contig_len, "opl-fcodemem",
			    NDI_RA_PASS);

			break;

		default:
			cmn_err(CE_CONT, "opl_fc_ops_free: "
			    "unknown resource type %d", resp->type);
			break;
		}
		fc_rem_resource(rp, resp);
		kmem_free(resp, sizeof (struct fc_resource));
	}

	kmem_free(rp, sizeof (struct fc_resource_list));
}

int
opl_fc_do_op(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	opl_fc_ops_t	*op;
	char		*service = fc_cell2ptr(cp->svc_name);

	ASSERT(rp);

	FC_DEBUG1(1, CE_CONT, "opl_fc_do_op: <%s>\n", service);

	/*
	 * First try the generic fc_ops.
	 */
	if (fc_ops(ap, rp->next_handle, cp) == 0)
		return (0);

	/*
	 * Now try the Jupiter-specific ops.
	 */
	for (op = opl_fc_ops; op->fc_service != NULL; ++op)
		if (strcmp(op->fc_service, service) == 0)
			return (op->fc_op(ap, rp, cp));

	FC_DEBUG1(9, CE_CONT, "opl_fc_do_op: <%s> not serviced\n", service);

	return (-1);
}

/*
 * map-in  (phys.lo phys.hi size -- virt)
 */
static int
opl_map_in(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	size_t			len;
	int			error;
	caddr_t			virt;
	struct fc_resource	*resp;
	struct regspec		rspec;
	ddi_device_acc_attr_t	acc;
	ddi_acc_handle_t	h;

	if (fc_cell2int(cp->nargs) != 3)
		return (fc_syntax_error(cp, "nargs must be 3"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	rspec.regspec_size = len = fc_cell2size(fc_arg(cp, 0));
	rspec.regspec_bustype = fc_cell2uint(fc_arg(cp, 1));
	rspec.regspec_addr = fc_cell2uint(fc_arg(cp, 2));

	acc.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	acc.devacc_attr_endian_flags = DDI_STRUCTURE_BE_ACC;
	acc.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	FC_DEBUG3(1, CE_CONT, "opl_map_in: attempting map in "
	    "address 0x%08x.%08x length %x\n", rspec.regspec_bustype,
	    rspec.regspec_addr, rspec.regspec_size);

	error = opl_map_phys(rp->child, &rspec, &virt, &acc, &h);

	if (error)  {
		FC_DEBUG3(1, CE_CONT, "opl_map_in: map in failed - "
		    "address 0x%08x.%08x length %x\n", rspec.regspec_bustype,
		    rspec.regspec_addr, rspec.regspec_size);

		return (fc_priv_error(cp, "opl map-in failed"));
	}

	FC_DEBUG1(3, CE_CONT, "opl_map_in: returning virt %p\n", virt);

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = fc_ptr2cell(virt);

	/*
	 * Log this resource ...
	 */
	resp = kmem_zalloc(sizeof (struct fc_resource), KM_SLEEP);
	resp->type = RT_MAP;
	resp->fc_map_virt = virt;
	resp->fc_map_len = len;
	resp->fc_map_handle = h;
	fc_add_resource(rp, resp);

	return (fc_success_op(ap, rp, cp));
}

/*
 * map-out (virt size -- )
 */
static int
opl_map_out(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	caddr_t			virt;
	size_t			len;
	struct fc_resource	*resp;

	if (fc_cell2int(cp->nargs) != 2)
		return (fc_syntax_error(cp, "nargs must be 2"));

	virt = fc_cell2ptr(fc_arg(cp, 1));

	len = fc_cell2size(fc_arg(cp, 0));

	FC_DEBUG2(1, CE_CONT, "opl_map_out: attempting map out %p %x\n",
	    virt, len);

	/*
	 * Find if this request matches a mapping resource we set up.
	 */
	fc_lock_resource_list(rp);
	for (resp = rp->head; resp != NULL; resp = resp->next) {
		if (resp->type != RT_MAP)
			continue;
		if (resp->fc_map_virt != virt)
			continue;
		if (resp->fc_map_len == len)
			break;
	}
	fc_unlock_resource_list(rp);

	if (resp == NULL)
		return (fc_priv_error(cp, "request doesn't match a "
		    "known mapping"));

	opl_unmap_phys(&resp->fc_map_handle);

	/*
	 * remove the resource from the list and release it.
	 */
	fc_rem_resource(rp, resp);
	kmem_free(resp, sizeof (struct fc_resource));

	cp->nresults = fc_int2cell(0);
	return (fc_success_op(ap, rp, cp));
}

static int
opl_register_fetch(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	size_t			len;
	caddr_t			virt;
	int			error = 0;
	uint64_t		v;
	uint64_t		x;
	uint32_t		l;
	uint16_t		w;
	uint8_t			b;
	char			*service = fc_cell2ptr(cp->svc_name);
	struct fc_resource	*resp;

	if (fc_cell2int(cp->nargs) != 1)
		return (fc_syntax_error(cp, "nargs must be 1"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	virt = fc_cell2ptr(fc_arg(cp, 0));

	/*
	 * Determine the access width .. we can switch on the 2nd
	 * character of the name which is "rx@", "rl@", "rb@" or "rw@"
	 */
	switch (*(service + 1)) {
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
	for (resp = rp->head; resp != NULL; resp = resp->next) {
		if (resp->type == RT_MAP) {
			if ((virt >= (caddr_t)resp->fc_map_virt) &&
			    ((virt + len) <=
			    ((caddr_t)resp->fc_map_virt + resp->fc_map_len)))
				break;
		} else if (resp->type == RT_CONTIGIOUS) {
			if ((virt >= (caddr_t)resp->fc_contig_virt) &&
			    ((virt + len) <= ((caddr_t)resp->fc_contig_virt +
			    resp->fc_contig_len)))
				break;
		}
	}
	fc_unlock_resource_list(rp);

	if (resp == NULL) {
		return (fc_priv_error(cp, "request not within "
		    "known mappings"));
	}

	switch (len) {
	case sizeof (x):
		if (resp->type == RT_MAP)
			error = ddi_peek64(rp->child, (int64_t *)virt,
			    (int64_t *)&x);
		else /* RT_CONTIGIOUS */
			x = *(int64_t *)virt;
		v = x;
		break;
	case sizeof (l):
		if (resp->type == RT_MAP)
			error = ddi_peek32(rp->child, (int32_t *)virt,
			    (int32_t *)&l);
		else /* RT_CONTIGIOUS */
			l = *(int32_t *)virt;
		v = l;
		break;
	case sizeof (w):
		if (resp->type == RT_MAP)
			error = ddi_peek16(rp->child, (int16_t *)virt,
			    (int16_t *)&w);
		else /* RT_CONTIGIOUS */
			w = *(int16_t *)virt;
		v = w;
		break;
	case sizeof (b):
		if (resp->type == RT_MAP)
			error = ddi_peek8(rp->child, (int8_t *)virt,
			    (int8_t *)&b);
		else /* RT_CONTIGIOUS */
			b = *(int8_t *)virt;
		v = b;
		break;
	}

	if (error == DDI_FAILURE) {
		FC_DEBUG2(1, CE_CONT, "opl_register_fetch: access error "
		    "accessing virt %p len %d\n", virt, len);
		return (fc_priv_error(cp, "access error"));
	}

	FC_DEBUG3(1, CE_CONT, "register_fetch (%s) %llx %llx\n",
	    service, virt, v);

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
opl_register_store(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	size_t			len;
	caddr_t			virt;
	uint64_t		v;
	uint64_t		x;
	uint32_t		l;
	uint16_t		w;
	uint8_t			b;
	char			*service = fc_cell2ptr(cp->svc_name);
	struct fc_resource	*resp;
	int			error = 0;

	if (fc_cell2int(cp->nargs) != 2)
		return (fc_syntax_error(cp, "nargs must be 2"));

	virt = fc_cell2ptr(fc_arg(cp, 0));

	/*
	 * Determine the access width .. we can switch on the 2nd
	 * character of the name which is "rx!", "rl!", "rb!" or "rw!"
	 */
	switch (*(service + 1)) {
	case 'x':
		len = sizeof (x);
		x = fc_arg(cp, 1);
		v = x;
		break;
	case 'l':
		len = sizeof (l);
		l = fc_cell2uint32_t(fc_arg(cp, 1));
		v = l;
		break;
	case 'w':
		len = sizeof (w);
		w = fc_cell2uint16_t(fc_arg(cp, 1));
		v = w;
		break;
	case 'b':
		len = sizeof (b);
		b = fc_cell2uint8_t(fc_arg(cp, 1));
		v = b;
		break;
	}

	FC_DEBUG3(1, CE_CONT, "register_store (%s) %llx %llx\n",
	    service, virt, v);

	/*
	 * Check the alignment ...
	 */
	if (((intptr_t)virt & (len - 1)) != 0)
		return (fc_priv_error(cp, "unaligned access"));

	/*
	 * Find if this virt is 'within' a request we know about
	 */
	fc_lock_resource_list(rp);
	for (resp = rp->head; resp != NULL; resp = resp->next) {
		if (resp->type == RT_MAP) {
			if ((virt >= (caddr_t)resp->fc_map_virt) &&
			    ((virt + len) <=
			    ((caddr_t)resp->fc_map_virt + resp->fc_map_len)))
				break;
		} else if (resp->type == RT_CONTIGIOUS) {
			if ((virt >= (caddr_t)resp->fc_contig_virt) &&
			    ((virt + len) <= ((caddr_t)resp->fc_contig_virt +
			    resp->fc_contig_len)))
				break;
		}
	}
	fc_unlock_resource_list(rp);

	if (resp == NULL)
		return (fc_priv_error(cp, "request not within"
		    "known mappings"));

	switch (len) {
	case sizeof (x):
		if (resp->type == RT_MAP)
			error = ddi_poke64(rp->child, (int64_t *)virt, x);
		else if (resp->type == RT_CONTIGIOUS)
			*(uint64_t *)virt = x;
		break;
	case sizeof (l):
		if (resp->type == RT_MAP)
			error = ddi_poke32(rp->child, (int32_t *)virt, l);
		else if (resp->type == RT_CONTIGIOUS)
			*(uint32_t *)virt = l;
		break;
	case sizeof (w):
		if (resp->type == RT_MAP)
			error = ddi_poke16(rp->child, (int16_t *)virt, w);
		else if (resp->type == RT_CONTIGIOUS)
			*(uint16_t *)virt = w;
		break;
	case sizeof (b):
		if (resp->type == RT_MAP)
			error = ddi_poke8(rp->child, (int8_t *)virt, b);
		else if (resp->type == RT_CONTIGIOUS)
			*(uint8_t *)virt = b;
		break;
	}

	if (error == DDI_FAILURE) {
		FC_DEBUG2(1, CE_CONT, "opl_register_store: access error "
		    "accessing virt %p len %d\n", virt, len);
		return (fc_priv_error(cp, "access error"));
	}

	cp->nresults = fc_int2cell(0);
	return (fc_success_op(ap, rp, cp));
}

/*
 * opl_claim_memory
 *
 * claim-memory (align size vhint -- vaddr)
 */
static int
opl_claim_memory(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	int			align, size, vhint;
	uint64_t		answer, alen;
	ndi_ra_request_t	request;
	struct fc_resource	*resp;

	if (fc_cell2int(cp->nargs) != 3)
		return (fc_syntax_error(cp, "nargs must be 3"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	vhint = fc_cell2int(fc_arg(cp, 2));
	size  = fc_cell2int(fc_arg(cp, 1));
	align = fc_cell2int(fc_arg(cp, 0));

	FC_DEBUG3(1, CE_CONT, "opl_claim_memory: align=0x%x size=0x%x "
	    "vhint=0x%x\n", align, size, vhint);

	if (size == 0) {
		cmn_err(CE_WARN, "opl_claim_memory - unable to allocate "
		    "contiguous memory of size zero\n");
		return (fc_priv_error(cp, "allocation error"));
	}

	if (vhint) {
		cmn_err(CE_WARN, "opl_claim_memory - vhint is not zero "
		    "vhint=0x%x - Ignoring Argument\n", vhint);
	}

	bzero((caddr_t)&request, sizeof (ndi_ra_request_t));
	request.ra_flags	= NDI_RA_ALLOC_BOUNDED;
	request.ra_boundbase	= 0;
	request.ra_boundlen	= 0xffffffff;
	request.ra_len		= size;
	request.ra_align_mask	= align - 1;

	if (ndi_ra_alloc(ddi_root_node(), &request, &answer, &alen,
	    "opl-fcodemem", NDI_RA_PASS) != NDI_SUCCESS) {
		cmn_err(CE_WARN, "opl_claim_memory - unable to allocate "
		    "contiguous memory\n");
		return (fc_priv_error(cp, "allocation error"));
	}

	FC_DEBUG2(1, CE_CONT, "opl_claim_memory: address allocated=0x%lx "
	    "size=0x%x\n", answer, alen);

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = answer;

	/*
	 * Log this resource ...
	 */
	resp = kmem_zalloc(sizeof (struct fc_resource), KM_SLEEP);
	resp->type = RT_CONTIGIOUS;
	resp->fc_contig_virt = (void *)answer;
	resp->fc_contig_len = size;
	fc_add_resource(rp, resp);

	return (fc_success_op(ap, rp, cp));
}

/*
 * opl_release_memory
 *
 * release-memory (size vaddr -- )
 */
static int
opl_release_memory(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	int32_t			vaddr, size;
	struct fc_resource	*resp;

	if (fc_cell2int(cp->nargs) != 2)
		return (fc_syntax_error(cp, "nargs must be 2"));

	if (fc_cell2int(cp->nresults) != 0)
		return (fc_syntax_error(cp, "nresults must be 0"));

	vaddr = fc_cell2int(fc_arg(cp, 1));
	size  = fc_cell2int(fc_arg(cp, 0));

	FC_DEBUG2(1, CE_CONT, "opl_release_memory: vaddr=0x%x size=0x%x\n",
	    vaddr, size);

	/*
	 * Find if this request matches a mapping resource we set up.
	 */
	fc_lock_resource_list(rp);
	for (resp = rp->head; resp != NULL; resp = resp->next) {
		if (resp->type != RT_CONTIGIOUS)
			continue;
		if (resp->fc_contig_virt != (void *)(uintptr_t)vaddr)
			continue;
		if (resp->fc_contig_len == size)
			break;
	}
	fc_unlock_resource_list(rp);

	if (resp == NULL)
		return (fc_priv_error(cp, "request doesn't match a "
		    "known mapping"));

	(void) ndi_ra_free(ddi_root_node(), vaddr, size,
	    "opl-fcodemem", NDI_RA_PASS);

	/*
	 * remove the resource from the list and release it.
	 */
	fc_rem_resource(rp, resp);
	kmem_free(resp, sizeof (struct fc_resource));

	cp->nresults = fc_int2cell(0);

	return (fc_success_op(ap, rp, cp));
}

/*
 * opl_vtop
 *
 * vtop (vaddr -- paddr.lo paddr.hi)
 */
static int
opl_vtop(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	int			vaddr;
	uint64_t		paddr;
	struct fc_resource	*resp;

	if (fc_cell2int(cp->nargs) != 1)
		return (fc_syntax_error(cp, "nargs must be 1"));

	if (fc_cell2int(cp->nresults) >= 3)
		return (fc_syntax_error(cp, "nresults must be less than 2"));

	vaddr = fc_cell2int(fc_arg(cp, 0));

	/*
	 * Find if this request matches a mapping resource we set up.
	 */
	fc_lock_resource_list(rp);
	for (resp = rp->head; resp != NULL; resp = resp->next) {
		if (resp->type != RT_CONTIGIOUS)
			continue;
		if (((uint64_t)resp->fc_contig_virt <= vaddr) &&
		    (vaddr < (uint64_t)resp->fc_contig_virt +
		    resp->fc_contig_len))
			break;
	}
	fc_unlock_resource_list(rp);

	if (resp == NULL)
		return (fc_priv_error(cp, "request doesn't match a "
		    "known mapping"));

	paddr = va_to_pa((void *)(uintptr_t)vaddr);

	FC_DEBUG2(1, CE_CONT, "opl_vtop: vaddr=0x%x paddr=0x%x\n",
	    vaddr, paddr);

	cp->nresults = fc_int2cell(2);

	fc_result(cp, 0) = paddr;
	fc_result(cp, 1) = 0;

	return (fc_success_op(ap, rp, cp));
}

static int
opl_config_child(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
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
opl_get_fcode(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	caddr_t		dropin_name_virt, fcode_virt;
	char		*dropin_name, *fcode;
	int		fcode_len, status;

	if (fc_cell2int(cp->nargs) != 3)
		return (fc_syntax_error(cp, "nargs must be 3"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	dropin_name_virt = fc_cell2ptr(fc_arg(cp, 0));

	fcode_virt = fc_cell2ptr(fc_arg(cp, 1));

	fcode_len = fc_cell2int(fc_arg(cp, 2));

	dropin_name = kmem_zalloc(FC_SVC_NAME_LEN, KM_SLEEP);

	FC_DEBUG2(1, CE_CONT, "get_fcode: %x %d\n", fcode_virt, fcode_len);

	if (copyinstr(fc_cell2ptr(dropin_name_virt), dropin_name,
	    FC_SVC_NAME_LEN - 1, NULL))  {
		FC_DEBUG1(1, CE_CONT, "opl_get_fcode: "
		    "fault copying in drop in name %p\n", dropin_name_virt);
		status = 0;
	} else {
		FC_DEBUG1(1, CE_CONT, "get_fcode: %s\n", dropin_name);

		fcode = kmem_zalloc(fcode_len, KM_SLEEP);

		if ((status = prom_get_fcode(dropin_name, fcode)) != 0) {

			if (copyout((void *)fcode, (void *)fcode_virt,
			    fcode_len)) {
				cmn_err(CE_WARN, " opl_get_fcode: Unable "
				    "to copy out fcode image");
				status = 0;
			}
		}

		kmem_free(fcode, fcode_len);
	}

	kmem_free(dropin_name, FC_SVC_NAME_LEN);

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = status;

	return (fc_success_op(ap, rp, cp));
}

static int
opl_get_fcode_size(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	caddr_t		virt;
	char		*dropin_name;
	int		len;

	if (fc_cell2int(cp->nargs) != 1)
		return (fc_syntax_error(cp, "nargs must be 1"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	virt = fc_cell2ptr(fc_arg(cp, 0));

	dropin_name = kmem_zalloc(FC_SVC_NAME_LEN, KM_SLEEP);

	FC_DEBUG0(1, CE_CONT, "opl_get_fcode_size:\n");

	if (copyinstr(fc_cell2ptr(virt), dropin_name,
	    FC_SVC_NAME_LEN - 1, NULL))  {
		FC_DEBUG1(1, CE_CONT, "opl_get_fcode_size: "
		    "fault copying in drop in name %p\n", virt);
		len = 0;
	} else {
		FC_DEBUG1(1, CE_CONT, "opl_get_fcode_size: %s\n", dropin_name);

		len = prom_get_fcode_size(dropin_name);
	}

	kmem_free(dropin_name, FC_SVC_NAME_LEN);

	FC_DEBUG1(1, CE_CONT, "opl_get_fcode_size: fcode_len = %d\n", len);

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = len;

	return (fc_success_op(ap, rp, cp));
}

static int
opl_map_phys(dev_info_t *dip, struct regspec *phys_spec,
    caddr_t *addrp, ddi_device_acc_attr_t *accattrp,
    ddi_acc_handle_t *handlep)
{
	ddi_map_req_t 	mapreq;
	ddi_acc_hdl_t	*acc_handlep;
	int		result;
	struct regspec	*rspecp;

	*handlep = impl_acc_hdl_alloc(KM_SLEEP, NULL);
	acc_handlep = impl_acc_hdl_get(*handlep);
	acc_handlep->ah_vers = VERS_ACCHDL;
	acc_handlep->ah_dip = dip;
	acc_handlep->ah_rnumber = 0;
	acc_handlep->ah_offset = 0;
	acc_handlep->ah_len = 0;
	acc_handlep->ah_acc = *accattrp;
	rspecp = kmem_zalloc(sizeof (struct regspec), KM_SLEEP);
	*rspecp = *phys_spec;
	/*
	 * cache a copy of the reg spec
	 */
	acc_handlep->ah_bus_private = rspecp;

	mapreq.map_op = DDI_MO_MAP_LOCKED;
	mapreq.map_type = DDI_MT_REGSPEC;
	mapreq.map_obj.rp = (struct regspec *)phys_spec;
	mapreq.map_prot = PROT_READ | PROT_WRITE;
	mapreq.map_flags = DDI_MF_KERNEL_MAPPING;
	mapreq.map_handlep = acc_handlep;
	mapreq.map_vers = DDI_MAP_VERSION;

	result = ddi_map(dip, &mapreq, 0, 0, addrp);

	if (result != DDI_SUCCESS) {
		impl_acc_hdl_free(*handlep);
		kmem_free(rspecp, sizeof (struct regspec));
		*handlep = (ddi_acc_handle_t)NULL;
	} else {
		acc_handlep->ah_addr = *addrp;
	}

	return (result);
}

static void
opl_unmap_phys(ddi_acc_handle_t *handlep)
{
	ddi_map_req_t	mapreq;
	ddi_acc_hdl_t	*acc_handlep;
	struct regspec	*rspecp;

	acc_handlep = impl_acc_hdl_get(*handlep);
	ASSERT(acc_handlep);
	rspecp = acc_handlep->ah_bus_private;

	mapreq.map_op = DDI_MO_UNMAP;
	mapreq.map_type = DDI_MT_REGSPEC;
	mapreq.map_obj.rp = (struct regspec *)rspecp;
	mapreq.map_prot = PROT_READ | PROT_WRITE;
	mapreq.map_flags = DDI_MF_KERNEL_MAPPING;
	mapreq.map_handlep = acc_handlep;
	mapreq.map_vers = DDI_MAP_VERSION;

	(void) ddi_map(acc_handlep->ah_dip, &mapreq, acc_handlep->ah_offset,
	    acc_handlep->ah_len, &acc_handlep->ah_addr);

	impl_acc_hdl_free(*handlep);
	/*
	 * Free the cached copy
	 */
	kmem_free(rspecp, sizeof (struct regspec));
	*handlep = (ddi_acc_handle_t)NULL;
}

static int
opl_get_hwd_va(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	uint32_t	portid;
	void		*hwd_virt;
	hwd_header_t	*hwd_h = NULL;
	hwd_sb_t	*hwd_sb = NULL;
	int		lsb, ch, leaf;
	int		status = 1;

	/* Check the argument */
	if (fc_cell2int(cp->nargs) != 2)
		return (fc_syntax_error(cp, "nargs must be 2"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	/* Get the parameters */
	portid = fc_cell2uint32_t(fc_arg(cp, 0));
	hwd_virt = (void *)fc_cell2ptr(fc_arg(cp, 1));

	/* Get the ID numbers */
	lsb  = OPL_IO_PORTID_TO_LSB(portid);
	ch   = OPL_PORTID_TO_CHANNEL(portid);
	leaf = OPL_PORTID_TO_LEAF(portid);
	ASSERT(OPL_IO_PORTID(lsb, ch, leaf) == portid);

	/* Set the pointer of hwd. */
	if ((hwd_h = (hwd_header_t *)opl_boards[lsb].cfg_hwd) == NULL) {
		return (fc_priv_error(cp, "null hwd header"));
	}
	/* Set the pointer of hwd sb. */
	if ((hwd_sb = (hwd_sb_t *)((char *)hwd_h + hwd_h->hdr_sb_info_offset))
	    == NULL) {
		return (fc_priv_error(cp, "null hwd sb"));
	}

	if (ch == OPL_CMU_CHANNEL) {
		/* Copyout CMU-CH HW Descriptor */
		if (copyout((void *)&hwd_sb->sb_cmu.cmu_ch,
		    (void *)hwd_virt, sizeof (hwd_cmu_chan_t))) {
			cmn_err(CE_WARN, "opl_get_hwd_va: "
			"Unable to copy out cmuch descriptor for %x",
			    portid);
			status = 0;
		}
	} else {
		/* Copyout PCI-CH HW Descriptor */
		if (copyout((void *)&hwd_sb->sb_pci_ch[ch].pci_leaf[leaf],
		    (void *)hwd_virt, sizeof (hwd_leaf_t))) {
			cmn_err(CE_WARN, "opl_get_hwd_va: "
			"Unable to copy out pcich descriptor for %x",
			    portid);
			status = 0;
		}
	}

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = status;

	return (fc_success_op(ap, rp, cp));
}

/*
 * After Solaris boots, a user can enter OBP using L1A, etc. While in OBP,
 * interrupts may be received from PCI devices. These interrupts
 * cannot be handled meaningfully since the system is in OBP. These
 * interrupts need to be cleared on the CPU side so that the CPU may
 * continue with whatever it is doing. Devices that have raised the
 * interrupts are expected to reraise the interrupts after sometime
 * as they have not been handled. At that time, Solaris will have a
 * chance to properly service the interrupts.
 *
 * The location of the interrupt registers depends on what is present
 * at a port. OPL currently supports the Oberon and the CMU channel.
 * The following handler handles both kinds of ports and computes
 * interrupt register addresses from the specifications and Jupiter Bus
 * device bindings.
 *
 * Fcode drivers install their interrupt handler via a "master-interrupt"
 * service. For boot time devices, this takes place within OBP. In the case
 * of DR, OPL uses IKP. The Fcode drivers that run within the efcode framework
 * attempt to install their handler via the "master-interrupt" service.
 * However, we cannot meaningfully install the Fcode driver's handler.
 * Instead, we install our own handler in OBP which does the same thing.
 *
 * Note that the only handling done for interrupts here is to clear it
 * on the CPU side. If any device in the future requires more special
 * handling, we would have to put in some kind of framework for adding
 * device-specific handlers. This is *highly* unlikely, but possible.
 *
 * Finally, OBP provides a hook called "unix-interrupt-handler" to install
 * a Solaris-defined master-interrupt handler for a port. The default
 * definition for this method does nothing. Solaris may override this
 * with its own definition. This is the way the following handler gets
 * control from OBP when interrupts happen at a port after L1A, etc.
 */

static char define_master_interrupt_handler[] =

/*
 * This method translates an Oberon port id to the base (physical) address
 * of the interrupt clear registers for that port id.
 */

": pcich-mid>clear-int-pa   ( mid -- pa ) "
"   dup 1 >> 7 and          ( mid ch# ) "
"   over 4 >> h# 1f and     ( mid ch# lsb# ) "
"   1 d# 46 <<              ( mid ch# lsb# pa ) "
"   swap d# 40 << or        ( mid ch# pa ) "
"   swap d# 37 << or        ( mid pa ) "
"   swap 1 and if h# 70.0000 else h# 60.0000 then "
"   or h# 1400 or           ( pa ) "
"; "

/*
 * This method translates a CMU channel port id to the base (physical) address
 * of the interrupt clear registers for that port id. There are two classes of
 * interrupts that need to be handled for a CMU channel:
 *	- obio interrupts
 *	- pci interrupts
 * So, there are two addresses that need to be computed.
 */

": cmuch-mid>clear-int-pa   ( mid -- obio-pa pci-pa ) "
"   dup 1 >> 7 and          ( mid ch# ) "
"   over 4 >> h# 1f and     ( mid ch# lsb# ) "
"   1 d# 46 <<              ( mid ch# lsb# pa ) "
"   swap d# 40 << or        ( mid ch# pa ) "
"   swap d# 37 << or        ( mid pa ) "
"   nip dup h# 1800 +       ( pa obio-pa ) "
"   swap h# 1400 +          ( obio-pa pci-pa ) "
"; "

/*
 * This method checks if a given I/O port ID is valid or not.
 * For a given LSB,
 *	Oberon ports range from 0 - 3
 *	CMU ch ports range from 4 - 4
 *
 * Also, the Oberon supports leaves 0 and 1.
 * The CMU ch supports only one leaf, leaf 0.
 */

": valid-io-mid? ( mid -- flag ) "
"   dup 1 >> 7 and                     ( mid ch# ) "
"   dup 4 > if 2drop false exit then   ( mid ch# ) "
"   4 = swap 1 and 1 = and not "
"; "

/*
 * This method checks if a given port id is a CMU ch.
 */

": cmuch? ( mid -- flag ) 1 >> 7 and 4 = ; "

/*
 * Given the base address of the array of interrupt clear registers for
 * a port id, this method iterates over the given interrupt number bitmap
 * and resets the interrupt on the CPU side for every interrupt number
 * in the bitmap. Note that physical addresses are used to perform the
 * writes, not virtual addresses. This allows the handler to work without
 * any involvement from Solaris.
 */

": clear-ints ( pa bitmap count -- ) "
"   0 do                            ( pa bitmap ) "
"      dup 0= if 2drop unloop exit then "
"      tuck                         ( bitmap pa bitmap ) "
"      1 and if                     ( bitmap pa ) "
"	 dup i 8 * + 0 swap         ( bitmap pa 0 pa' ) "
"	 h# 15 spacex!              ( bitmap pa ) "
"      then                         ( bitmap pa ) "
"      swap 1 >>                    ( pa bitmap ) "
"   loop "
"; "

/*
 * This method replaces the master-interrupt handler in OBP. Once
 * this method is plumbed into OBP, OBP transfers control to this
 * handler while returning to Solaris from OBP after L1A. This method's
 * task is to simply reset received interrupts on the CPU side.
 * When the devices reassert the interrupts later, Solaris will
 * be able to see them and handle them.
 *
 * For each port ID that has interrupts, this method is called
 * once by OBP. The input arguments are:
 *	mid	portid
 *	bitmap	bitmap of interrupts that have happened
 *
 * This method returns true, if it is able to handle the interrupts.
 * OBP does nothing further.
 *
 * This method returns false, if it encountered a problem. Currently,
 * the only problem could be an invalid port id. OBP needs to do
 * its own processing in that case. If this method returns false,
 * it preserves the mid and bitmap arguments for OBP.
 */

": unix-resend-mondos ( mid bitmap -- [ mid bitmap false ] | true ) "

/*
 * Uncomment the following line if you want to display the input arguments.
 * This is meant for debugging.
 * "   .\" Bitmap=\" dup u. .\" MID=\" over u. cr "
 */

/*
 * If the port id is not valid (according to the Oberon and CMU ch
 * specifications, then return false to OBP to continue further
 * processing.
 */

"   over valid-io-mid? not if       ( mid bitmap ) "
"      false exit "
"   then "

/*
 * If the port is a CMU ch, then the 64-bit bitmap represents
 * 2 32-bit bitmaps:
 *	- obio interrupt bitmap (20 bits)
 *	- pci interrupt bitmap (32 bits)
 *
 * - Split the bitmap into two
 * - Compute the base addresses of the interrupt clear registers
 *   for both pci interrupts and obio interrupts
 * - Clear obio interrupts
 * - Clear pci interrupts
 */

"   over cmuch? if                  ( mid bitmap ) "
"      xlsplit                      ( mid pci-bit obio-bit ) "
"      rot cmuch-mid>clear-int-pa   ( pci-bit obio-bit obio-pa pci-pa ) "
"      >r                           ( pci-bit obio-bit obio-pa ) ( r: pci-pa ) "
"      swap d# 20 clear-ints        ( pci-bit ) ( r: pci-pa ) "
"      r> swap d# 32 clear-ints     (  ) ( r: ) "

/*
 * If the port is an Oberon, then the 64-bit bitmap is used fully.
 *
 * - Compute the base address of the interrupt clear registers
 * - Clear interrupts
 */

"   else                            ( mid bitmap ) "
"      swap pcich-mid>clear-int-pa  ( bitmap pa ) "
"      swap d# 64 clear-ints        (  ) "
"   then "

/*
 * Always return true from here.
 */

"   true                            ( true ) "
"; "
;

static char	install_master_interrupt_handler[] =
	"' unix-resend-mondos to unix-interrupt-handler";
static char	handler[] = "unix-interrupt-handler";
static char	handler_defined[] = "p\" %s\" find nip swap l! ";

/*ARGSUSED*/
static int
master_interrupt_init(uint32_t portid, uint32_t xt)
{
	uint_t	defined;
	char	buf[sizeof (handler) + sizeof (handler_defined)];

	if (master_interrupt_inited)
		return (1);

	/*
	 * Check if the defer word "unix-interrupt-handler" is defined.
	 * This must be defined for OPL systems. So, this is only a
	 * sanity check.
	 */
	(void) sprintf(buf, handler_defined, handler);
	prom_interpret(buf, (uintptr_t)&defined, 0, 0, 0, 0);
	if (!defined) {
		cmn_err(CE_WARN, "master_interrupt_init: "
		    "%s is not defined\n", handler);
		return (0);
	}

	/*
	 * Install the generic master-interrupt handler. Note that
	 * this is only done one time on the first DR operation.
	 * This is because, for OPL, one, single generic handler
	 * handles all ports (Oberon and CMU channel) and all
	 * interrupt sources within each port.
	 *
	 * The current support is only for the Oberon and CMU-channel.
	 * If any others need to be supported, the handler has to be
	 * modified accordingly.
	 */

	/*
	 * Define the OPL master interrupt handler
	 */
	prom_interpret(define_master_interrupt_handler, 0, 0, 0, 0, 0);

	/*
	 * Take over the master interrupt handler from OBP.
	 */
	prom_interpret(install_master_interrupt_handler, 0, 0, 0, 0, 0);

	master_interrupt_inited = 1;

	/*
	 * prom_interpret() does not return a status. So, we assume
	 * that the calls succeeded. In reality, the calls may fail
	 * if there is a syntax error, etc in the strings.
	 */

	return (1);
}

/*
 * Install the master-interrupt handler for a device.
 */
static int
opl_master_interrupt(dev_info_t *ap, fco_handle_t rp, fc_ci_t *cp)
{
	uint32_t	portid, xt;
	int		board, channel, leaf;
	int		status;

	/* Check the argument */
	if (fc_cell2int(cp->nargs) != 2)
		return (fc_syntax_error(cp, "nargs must be 2"));

	if (fc_cell2int(cp->nresults) < 1)
		return (fc_syntax_error(cp, "nresults must be >= 1"));

	/* Get the parameters */
	portid = fc_cell2uint32_t(fc_arg(cp, 0));
	xt = fc_cell2uint32_t(fc_arg(cp, 1));

	board = OPL_IO_PORTID_TO_LSB(portid);
	channel = OPL_PORTID_TO_CHANNEL(portid);
	leaf = OPL_PORTID_TO_LEAF(portid);

	if ((board >= HWD_SBS_PER_DOMAIN) || !OPL_VALID_CHANNEL(channel) ||
	    (OPL_OBERON_CHANNEL(channel) && !OPL_VALID_LEAF(leaf)) ||
	    ((channel == OPL_CMU_CHANNEL) && (leaf != 0))) {
		FC_DEBUG1(1, CE_CONT, "opl_master_interrupt: invalid port %x\n",
		    portid);
		status = 0;
	} else {
		status = master_interrupt_init(portid, xt);
	}

	cp->nresults = fc_int2cell(1);
	fc_result(cp, 0) = status;

	return (fc_success_op(ap, rp, cp));
}

/*
 * Set the properties for a leaf node (Oberon leaf or CMU channel leaf).
 */
/*ARGSUSED*/
static int
opl_create_leaf(dev_info_t *node, void *arg, uint_t flags)
{
	int ret;

	OPL_UPDATE_PROP(string, node, "name", OPL_PCI_LEAF_NODE);

	OPL_UPDATE_PROP(string, node, "status", "okay");

	return (DDI_WALK_TERMINATE);
}

static char *
opl_get_probe_string(opl_probe_t *probe, int channel, int leaf)
{
	char 		*probe_string;
	int		portid;

	probe_string = kmem_zalloc(PROBE_STR_SIZE, KM_SLEEP);

	if (channel == OPL_CMU_CHANNEL)
		portid = probe->pr_sb->sb_cmu.cmu_ch.chan_portid;
	else
		portid = probe->
		    pr_sb->sb_pci_ch[channel].pci_leaf[leaf].leaf_port_id;

	(void) sprintf(probe_string, "%x", portid);

	return (probe_string);
}

static int
opl_probe_leaf(opl_probe_t *probe)
{
	int		channel, leaf, portid, error, circ;
	int		board;
	fco_handle_t	fco_handle, *cfg_handle;
	dev_info_t	*parent, *leaf_node;
	char		unit_address[UNIT_ADDR_SIZE];
	char		*probe_string;
	opl_board_cfg_t	*board_cfg;

	board = probe->pr_board;
	channel = probe->pr_channel;
	leaf = probe->pr_leaf;
	parent = ddi_root_node();
	board_cfg = &opl_boards[board];

	ASSERT(OPL_VALID_CHANNEL(channel));
	ASSERT(OPL_VALID_LEAF(leaf));

	if (channel == OPL_CMU_CHANNEL) {
		portid = probe->pr_sb->sb_cmu.cmu_ch.chan_portid;
		cfg_handle = &board_cfg->cfg_cmuch_handle;
	} else {
		portid = probe->
		    pr_sb->sb_pci_ch[channel].pci_leaf[leaf].leaf_port_id;
		cfg_handle = &board_cfg->cfg_pcich_handle[channel][leaf];
	}

	/*
	 * Prevent any changes to leaf_node until we have bound
	 * it to the correct driver.
	 */
	ndi_devi_enter(parent, &circ);

	/*
	 * Ideally, fcode would be run from the "sid_branch_create"
	 * callback (that is the primary purpose of that callback).
	 * However, the fcode interpreter was written with the
	 * assumption that the "new_child" was linked into the
	 * device tree. The callback is invoked with the devinfo node
	 * in the DS_PROTO state. More investigation is needed before
	 * we can invoke the interpreter from the callback. For now,
	 * we create the "new_child" in the BOUND state, invoke the
	 * fcode interpreter and then rebind the dip to use any
	 * compatible properties created by fcode.
	 */

	probe->pr_parent = parent;
	probe->pr_create = opl_create_leaf;
	probe->pr_hold = 1;

	leaf_node = opl_create_node(probe);
	if (leaf_node == NULL) {

		cmn_err(CE_WARN, "IKP: create leaf (%d-%d-%d) failed",
		    probe->pr_board, probe->pr_channel, probe->pr_leaf);
		ndi_devi_exit(parent, circ);
		return (-1);
	}

	/*
	 * The platform DR interfaces created the dip in
	 * bound state. Bring devinfo node down to linked
	 * state and hold it there until compatible
	 * properties are created.
	 */
	e_ddi_branch_rele(leaf_node);
	(void) i_ndi_unconfig_node(leaf_node, DS_LINKED, 0);
	ASSERT(i_ddi_node_state(leaf_node) == DS_LINKED);
	e_ddi_branch_hold(leaf_node);

	mutex_enter(&DEVI(leaf_node)->devi_lock);
	DEVI(leaf_node)->devi_flags |= DEVI_NO_BIND;
	mutex_exit(&DEVI(leaf_node)->devi_lock);

	/*
	 * Drop the busy-hold on parent before calling
	 * fcode_interpreter to prevent potential deadlocks
	 */
	ndi_devi_exit(parent, circ);

	(void) sprintf(unit_address, "%x", portid);

	/*
	 * Get the probe string
	 */
	probe_string = opl_get_probe_string(probe, channel, leaf);

	/*
	 * The fcode pointer specified here is NULL and the fcode
	 * size specified here is 0. This causes the user-level
	 * fcode interpreter to issue a request to the fcode
	 * driver to get the Oberon/cmu-ch fcode.
	 */
	fco_handle = opl_fc_ops_alloc_handle(parent, leaf_node,
	    NULL, 0, unit_address, probe_string);

	error = fcode_interpreter(parent, &opl_fc_do_op, fco_handle);

	if (error != 0) {
		cmn_err(CE_WARN, "IKP: Unable to probe PCI leaf (%d-%d-%d)",
		    probe->pr_board, probe->pr_channel, probe->pr_leaf);

		opl_fc_ops_free_handle(fco_handle);

		if (probe_string != NULL)
			kmem_free(probe_string, PROBE_STR_SIZE);

		(void) opl_destroy_node(leaf_node);
	} else {
		*cfg_handle = fco_handle;

		if (channel == OPL_CMU_CHANNEL)
			board_cfg->cfg_cmuch_probe_str = probe_string;
		else
			board_cfg->cfg_pcich_probe_str[channel][leaf]
			    = probe_string;

		/*
		 * Compatible properties (if any) have been created,
		 * so bind driver.
		 */
		ndi_devi_enter(parent, &circ);
		ASSERT(i_ddi_node_state(leaf_node) <= DS_LINKED);

		mutex_enter(&DEVI(leaf_node)->devi_lock);
		DEVI(leaf_node)->devi_flags &= ~DEVI_NO_BIND;
		mutex_exit(&DEVI(leaf_node)->devi_lock);

		ndi_devi_exit(parent, circ);

		if (ndi_devi_bind_driver(leaf_node, 0) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "IKP: Unable to bind PCI leaf "
			    "(%d-%d-%d)", probe->pr_board, probe->pr_channel,
			    probe->pr_leaf);
		}
	}

	if ((error != 0) && (channel == OPL_CMU_CHANNEL))
		return (-1);

	return (0);
}

static void
opl_init_leaves(int myboard)
{
	dev_info_t	*parent, *node;
	char		*name;
	int 		circ, ret;
	int		len, portid, board, channel, leaf;
	opl_board_cfg_t	*cfg;

	parent = ddi_root_node();

	/*
	 * Hold parent node busy to walk its child list
	 */
	ndi_devi_enter(parent, &circ);

	for (node = ddi_get_child(parent); (node != NULL); node =
	    ddi_get_next_sibling(node)) {

		ret = OPL_GET_PROP(string, node, "name", &name, &len);
		if (ret != DDI_PROP_SUCCESS) {
			/*
			 * The property does not exist for this node.
			 */
			continue;
		}

		if (strncmp(name, OPL_PCI_LEAF_NODE, len) == 0) {

			ret = OPL_GET_PROP(int, node, "portid", &portid, -1);
			if (ret == DDI_PROP_SUCCESS) {

				ret = OPL_GET_PROP(int, node, "board#",
				    &board, -1);
				if ((ret != DDI_PROP_SUCCESS) ||
				    (board != myboard)) {
					kmem_free(name, len);
					continue;
				}

				cfg = &opl_boards[board];
				channel = OPL_PORTID_TO_CHANNEL(portid);
				if (channel == OPL_CMU_CHANNEL) {

					if (cfg->cfg_cmuch_handle != NULL)
						cfg->cfg_cmuch_leaf = node;

				} else {

					leaf = OPL_PORTID_TO_LEAF(portid);
					if (cfg->cfg_pcich_handle[
					    channel][leaf] != NULL)
						cfg->cfg_pcich_leaf[
						    channel][leaf] = node;
				}
			}
		}

		kmem_free(name, len);
		if (ret != DDI_PROP_SUCCESS)
			break;
	}

	ndi_devi_exit(parent, circ);
}

/*
 * Create "pci" node and hierarchy for the Oberon channels and the
 * CMU channel.
 */
/*ARGSUSED*/
static int
opl_probe_io(opl_probe_t *probe)
{

	int		i, j;
	hwd_pci_ch_t	*channels;

	if (HWD_STATUS_OK(probe->pr_sb->sb_cmu.cmu_ch.chan_status)) {

		probe->pr_channel = HWD_CMU_CHANNEL;
		probe->pr_channel_status =
		    probe->pr_sb->sb_cmu.cmu_ch.chan_status;
		probe->pr_leaf = 0;
		probe->pr_leaf_status = probe->pr_channel_status;

		if (opl_probe_leaf(probe) != 0)
			return (-1);
	}

	channels = &probe->pr_sb->sb_pci_ch[0];

	for (i = 0; i < HWD_PCI_CHANNELS_PER_SB; i++) {

		if (!HWD_STATUS_OK(channels[i].pci_status))
			continue;

		probe->pr_channel = i;
		probe->pr_channel_status = channels[i].pci_status;

		for (j = 0; j < HWD_LEAVES_PER_PCI_CHANNEL; j++) {

			probe->pr_leaf = j;
			probe->pr_leaf_status =
			    channels[i].pci_leaf[j].leaf_status;

			if (!HWD_STATUS_OK(probe->pr_leaf_status))
				continue;

			(void) opl_probe_leaf(probe);
		}
	}
	opl_init_leaves(probe->pr_board);
	return (0);
}

/*
 * Perform the probe in the following order:
 *
 *	processors
 *	memory
 *	IO
 *
 * Each probe function returns 0 on sucess and a non-zero value on failure.
 * What is a failure is determined by the implementor of the probe function.
 * For example, while probing CPUs, any error encountered during probe
 * is considered a failure and causes the whole probe operation to fail.
 * However, for I/O, an error encountered while probing one device
 * should not prevent other devices from being probed. It should not cause
 * the whole probe operation to fail.
 */
int
opl_probe_sb(int board, unsigned *cpu_impl)
{
	opl_probe_t	*probe;
	int		ret;

	if ((board < 0) || (board >= HWD_SBS_PER_DOMAIN))
		return (-1);

	ASSERT(opl_cfg_inited != 0);

	/*
	 * If the previous probe failed and left a partially configured
	 * board, we need to unprobe the board and start with a clean slate.
	 */
	if ((opl_boards[board].cfg_hwd != NULL) &&
	    (opl_unprobe_sb(board) != 0))
		return (-1);

	ret = 0;

	probe = kmem_zalloc(sizeof (opl_probe_t), KM_SLEEP);
	probe->pr_board = board;

	if ((opl_probe_init(probe) != 0) ||

	    (opl_probe_cpu_chips(probe) != 0) ||

	    (opl_probe_memory(probe) != 0) ||

	    (opl_probe_io(probe) != 0)) {

		/*
		 * Probe failed. Perform cleanup.
		 */
		(void) opl_unprobe_sb(board);
		ret = -1;
	}

	*cpu_impl = probe->pr_cpu_impl;

	kmem_free(probe, sizeof (opl_probe_t));

	return (ret);
}

/*
 * This unprobing also includes CMU-CH.
 */
/*ARGSUSED*/
static int
opl_unprobe_io(int board)
{
	int		i, j, ret;
	opl_board_cfg_t	*board_cfg;
	dev_info_t	**node;
	fco_handle_t	*hand;
	char		**probe_str;

	board_cfg = &opl_boards[board];

	for (i = 0; i < HWD_PCI_CHANNELS_PER_SB; i++) {

		for (j = 0; j < HWD_LEAVES_PER_PCI_CHANNEL; j++) {

			node = &board_cfg->cfg_pcich_leaf[i][j];
			hand = &board_cfg->cfg_pcich_handle[i][j];
			probe_str = &board_cfg->cfg_pcich_probe_str[i][j];

			if (*node == NULL)
				continue;

			if (*hand != NULL) {
				opl_fc_ops_free_handle(*hand);
				*hand = NULL;
			}

			if (*probe_str != NULL) {
				kmem_free(*probe_str, PROBE_STR_SIZE);
				*probe_str = NULL;
			}

			ret = opl_destroy_node(*node);
			if (ret != 0) {

				cmn_err(CE_WARN, "IKP: destroy pci (%d-%d-%d) "
				    "failed", board, i, j);
				return (-1);
			}

			*node = NULL;

		}
	}

	node = &board_cfg->cfg_cmuch_leaf;
	hand = &board_cfg->cfg_cmuch_handle;
	probe_str = &board_cfg->cfg_cmuch_probe_str;

	if (*node == NULL)
		return (0);

	if (*hand != NULL) {
		opl_fc_ops_free_handle(*hand);
		*hand = NULL;
	}

	if (*probe_str != NULL) {
		kmem_free(*probe_str, PROBE_STR_SIZE);
		*probe_str = NULL;
	}

	if (opl_destroy_node(*node) != 0) {

		cmn_err(CE_WARN, "IKP: destroy pci (%d-%d-%d) failed", board,
		    OPL_CMU_CHANNEL, 0);
		return (-1);
	}

	*node = NULL;

	return (0);
}

/*
 * Destroy the "pseudo-mc" node for a board.
 */
static int
opl_unprobe_memory(int board)
{
	opl_board_cfg_t	*board_cfg;

	board_cfg = &opl_boards[board];

	if (board_cfg->cfg_pseudo_mc == NULL)
		return (0);

	if (opl_destroy_node(board_cfg->cfg_pseudo_mc) != 0) {

		cmn_err(CE_WARN, "IKP: destroy pseudo-mc (%d) failed", board);
		return (-1);
	}

	board_cfg->cfg_pseudo_mc = NULL;

	return (0);
}

/*
 * Destroy the "cmp" nodes for a board. This also destroys the "core"
 * and "cpu" nodes below the "cmp" nodes.
 */
static int
opl_unprobe_processors(int board)
{
	int		i;
	dev_info_t	**cfg_cpu_chips;

	cfg_cpu_chips = opl_boards[board].cfg_cpu_chips;

	for (i = 0; i < HWD_CPU_CHIPS_PER_CMU; i++) {

		if (cfg_cpu_chips[i] == NULL)
			continue;

		if (opl_destroy_node(cfg_cpu_chips[i]) != 0) {

			cmn_err(CE_WARN, "IKP: destroy chip (%d-%d) failed",
			    board, i);
			return (-1);
		}

		cfg_cpu_chips[i] = NULL;
	}

	return (0);
}

/*
 * Perform the unprobe in the following order:
 *
 *	IO
 *	memory
 *	processors
 */
int
opl_unprobe_sb(int board)
{
	if ((board < 0) || (board >= HWD_SBS_PER_DOMAIN))
		return (-1);

	ASSERT(opl_cfg_inited != 0);

	if ((opl_unprobe_io(board) != 0) ||

	    (opl_unprobe_memory(board) != 0) ||

	    (opl_unprobe_processors(board) != 0))

		return (-1);

	if (opl_boards[board].cfg_hwd != NULL) {
#ifdef UCTEST
		size_t			size = 0xA000;
#endif
		/* Release the memory for the HWD */
		void *hwdp = opl_boards[board].cfg_hwd;
		opl_boards[board].cfg_hwd = NULL;
#ifdef UCTEST
		hwdp = (void *)((char *)hwdp - 0x1000);
		hat_unload(kas.a_hat, hwdp, size, HAT_UNLOAD_UNLOCK);
		vmem_free(heap_arena, hwdp, size);
#else
		kmem_free(hwdp, HWD_DATA_SIZE);
#endif
	}
	return (0);
}

/*
 * For MAC patrol support, we need to update the PA-related properties
 * when there is a copy-rename event.  This should be called after the
 * physical copy and rename has been done by DR, and before the MAC
 * patrol is restarted.
 */
int
oplcfg_pa_swap(int from, int to)
{
	dev_info_t *from_node = opl_boards[from].cfg_pseudo_mc;
	dev_info_t *to_node = opl_boards[to].cfg_pseudo_mc;
	opl_range_t *rangef, *ranget;
	int elems;
	int ret;

	if ((OPL_GET_PROP_ARRAY(int, from_node, "sb-mem-ranges", rangef,
	    elems) != DDI_SUCCESS) || (elems != 4)) {
		/* XXX -- bad news */
		return (-1);
	}
	if ((OPL_GET_PROP_ARRAY(int, to_node, "sb-mem-ranges", ranget,
	    elems) != DDI_SUCCESS) || (elems != 4)) {
		/* XXX -- bad news */
		return (-1);
	}
	OPL_UPDATE_PROP_ARRAY(int, from_node, "sb-mem-ranges", (int *)ranget,
	    4);
	OPL_UPDATE_PROP_ARRAY(int, to_node, "sb-mem-ranges", (int *)rangef,
	    4);

	OPL_FREE_PROP(ranget);
	OPL_FREE_PROP(rangef);

	return (0);
}
