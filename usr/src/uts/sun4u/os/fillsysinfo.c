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

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/cpu.h>
#include <sys/cpuvar.h>
#include <sys/clock.h>

#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/systm.h>
#include <sys/machsystm.h>
#include <sys/debug.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/spitregs.h>
#include <sys/cheetahregs.h>
#include <sys/cpu_module.h>
#include <sys/kobj.h>
#include <sys/cmp.h>
#include <sys/async.h>
#include <vm/page.h>

/*
 * The OpenBoot Standalone Interface supplies the kernel with
 * implementation dependent parameters through the devinfo/property mechanism
 */
typedef enum { XDRBOOL, XDRINT, XDRSTRING } xdrs;

/*
 * structure describing properties that we are interested in querying the
 * OBP for.
 */
struct getprop_info {
	char	*name;
	xdrs	type;
	uint_t	*var;
};

/*
 * structure used to convert between a string returned by the OBP & a type
 * used within the kernel. We prefer to paramaterize rather than type.
 */
struct convert_info {
	char	*name;
	uint_t	var;
	char	*realname;
};

/*
 * structure describing nodes that we are interested in querying the OBP for
 * properties.
 */
struct node_info {
	char			*name;
	int			size;
	struct getprop_info	*prop;
	struct getprop_info	*prop_end;
	unsigned int		*value;
};

/*
 * macro definitions for routines that form the OBP interface
 */
#define	NEXT			prom_nextnode
#define	CHILD			prom_childnode
#define	GETPROP			prom_getprop
#define	GETPROPLEN		prom_getproplen


/* 0=quiet; 1=verbose; 2=debug */
int	debug_fillsysinfo = 0;
#define	VPRINTF if (debug_fillsysinfo) prom_printf

int ncpunode;
struct cpu_node cpunodes[NCPU];

static void	check_cpus_ver(void);
static void	check_cpus_set(void);
static void fill_address(pnode_t, char *);
void	fill_cpu(pnode_t);
void	fill_cpu_ddi(dev_info_t *);
void	empty_cpu(int);
void	plat_fill_mc(pnode_t);
#pragma weak plat_fill_mc

uint64_t	system_clock_freq;

/*
 * list of well known devices that must be mapped, and the variables that
 * contain their addresses.
 */
caddr_t		v_auxio_addr = NULL;
caddr_t		v_eeprom_addr = NULL;
caddr_t		v_timecheck_addr = NULL;
caddr_t		v_rtc_addr_reg = NULL;
volatile unsigned char	*v_rtc_data_reg = NULL;
volatile uint8_t	*v_pmc_addr_reg = NULL;
volatile uint8_t	*v_pmc_data_reg = NULL;

int		niobus = 0;
uint_t		niommu_tsbs = 0;

/*
 * Hardware watchdog support.
 */
#define	CHOSEN_EEPROM	"eeprom"
#define	WATCHDOG_ENABLE "watchdog-enable"
static pnode_t		chosen_eeprom;

/*
 * Appropriate tod module will be dynamically selected while booting
 * based on finding a device tree node with a "device_type" property value
 * of "tod". If such a node describing tod is not found, for backward
 * compatibility, a node with a "name" property value of "eeprom" and
 * "model" property value of "mk48t59" will be used. Failing to find a
 * node matching either of the above criteria will result in no tod module
 * being selected; this will cause the boot process to halt.
 */
char	*tod_module_name;

/*
 * If this variable is non-zero, cpr should return "not supported" when
 * it is queried even though it would normally be supported on this platform.
 */
int cpr_supported_override;

/*
 * Some platforms may need to support CPR even in the absence of the
 * energystar-v* property (Enchilada server, for example).  If this
 * variable is non-zero, cpr should proceed even in the absence
 * of the energystar-v* property.
 */
int cpr_platform_enable = 0;

/*
 * Some nodes have functions that need to be called when they're seen.
 */
static void	have_sbus(pnode_t);
static void	have_pci(pnode_t);
static void	have_eeprom(pnode_t);
static void	have_auxio(pnode_t);
static void	have_rtc(pnode_t);
static void	have_tod(pnode_t);
static void	have_pmc(pnode_t);

static struct wkdevice {
	char *wk_namep;
	void (*wk_func)(pnode_t);
	caddr_t *wk_vaddrp;
	ushort_t wk_flags;
#define	V_OPTIONAL	0x0000
#define	V_MUSTHAVE	0x0001
#define	V_MAPPED	0x0002
#define	V_MULTI		0x0003	/* optional, may be more than one */
} wkdevice[] = {
	{ "sbus", have_sbus, NULL, V_MULTI },
	{ "pci", have_pci, NULL, V_MULTI },
	{ "eeprom", have_eeprom, NULL, V_MULTI },
	{ "auxio", have_auxio, NULL, V_OPTIONAL },
	{ "rtc", have_rtc, NULL, V_OPTIONAL },
	{ "pmc", have_pmc, NULL, V_OPTIONAL },
	{ 0, },
};

static void map_wellknown(pnode_t);

void
map_wellknown_devices()
{
	struct wkdevice *wkp;
	phandle_t	ieeprom;
	pnode_t	root;
	uint_t	stick_freq;

	/*
	 * if there is a chosen eeprom, note it (for have_eeprom())
	 */
	if (GETPROPLEN(prom_chosennode(), CHOSEN_EEPROM) ==
	    sizeof (phandle_t) &&
	    GETPROP(prom_chosennode(), CHOSEN_EEPROM, (caddr_t)&ieeprom) != -1)
		chosen_eeprom = (pnode_t)prom_decode_int(ieeprom);

	root = prom_nextnode((pnode_t)0);
	/*
	 * Get System clock frequency from root node if it exists.
	 */
	if (GETPROP(root, "stick-frequency", (caddr_t)&stick_freq) != -1)
		system_clock_freq = stick_freq;

	map_wellknown(NEXT((pnode_t)0));

	/*
	 * See if it worked
	 */
	for (wkp = wkdevice; wkp->wk_namep; ++wkp) {
		if (wkp->wk_flags == V_MUSTHAVE) {
			cmn_err(CE_PANIC, "map_wellknown_devices: required "
			    "device %s not mapped", wkp->wk_namep);
		}
	}

	/*
	 * all sun4u systems must have an IO bus, i.e. sbus or pcibus
	 */
	if (niobus == 0)
		cmn_err(CE_PANIC, "map_wellknown_devices: no i/o bus node");

	check_cpus_ver();
	check_cpus_set();
}

/*
 * map_wellknown - map known devices & registers
 */
static void
map_wellknown(pnode_t curnode)
{
	extern int status_okay(int, char *, int);
	char tmp_name[MAXSYSNAME];
	int sok;

#ifdef VPRINTF
	VPRINTF("map_wellknown(%x)\n", curnode);
#endif /* VPRINTF */

	for (curnode = CHILD(curnode); curnode; curnode = NEXT(curnode)) {
		/*
		 * prune subtree if status property indicating not okay
		 */
		sok = status_okay((int)curnode, (char *)NULL, 0);
		if (!sok) {
			char devtype_buf[OBP_MAXPROPNAME];
			int size;

#ifdef VPRINTF
			VPRINTF("map_wellknown: !okay status property\n");
#endif /* VPRINTF */
			/*
			 * a status property indicating bad memory will be
			 * associated with a node which has a "device_type"
			 * property with a value of "memory-controller"
			 */
			if ((size = GETPROPLEN(curnode,
			    OBP_DEVICETYPE)) == -1)
				continue;
			if (size > OBP_MAXPROPNAME) {
				cmn_err(CE_CONT, "node %x '%s' prop too "
				    "big\n", curnode, OBP_DEVICETYPE);
				continue;
			}
			if (GETPROP(curnode, OBP_DEVICETYPE,
			    devtype_buf) == -1) {
				cmn_err(CE_CONT, "node %x '%s' get failed\n",
				    curnode, OBP_DEVICETYPE);
				continue;
			}
			if (strcmp(devtype_buf, "memory-controller") != 0)
				continue;
			/*
			 * ...else fall thru and process the node...
			 */
		}
		bzero(tmp_name, MAXSYSNAME);
		if (GETPROP(curnode, OBP_NAME, (caddr_t)tmp_name) != -1)
			fill_address(curnode, tmp_name);
		if (GETPROP(curnode, OBP_DEVICETYPE, tmp_name) != -1 &&
		    strcmp(tmp_name, "cpu") == 0) {
			fill_cpu(curnode);
		}
		if (strcmp(tmp_name, "tod") == 0)
			have_tod(curnode);
		if (sok && (strcmp(tmp_name, "memory-controller") == 0) &&
		    (&plat_fill_mc != NULL))
			plat_fill_mc(curnode);
		map_wellknown(curnode);
	}
}

static void
fill_address(pnode_t curnode, char *namep)
{
	struct wkdevice *wkp;
	int size;
	uint32_t vaddr;

	for (wkp = wkdevice; wkp->wk_namep; ++wkp) {
		if (strcmp(wkp->wk_namep, namep) != 0)
			continue;
		if (wkp->wk_flags == V_MAPPED)
			return;
		if (wkp->wk_vaddrp != NULL) {
			if ((size = GETPROPLEN(curnode, OBP_ADDRESS)) == -1) {
				cmn_err(CE_CONT, "device %s size %d\n",
				    namep, size);
				continue;
			}
			if (size != sizeof (vaddr)) {
				cmn_err(CE_CONT, "device %s address prop too "
				    "big\n", namep);
				continue;
			}
			if (GETPROP(curnode, OBP_ADDRESS,
			    (caddr_t)&vaddr) == -1) {
				cmn_err(CE_CONT, "device %s not mapped\n",
				    namep);
				continue;
			}

			/* make into a native pointer */
			*wkp->wk_vaddrp = (caddr_t)(uintptr_t)vaddr;
#ifdef VPRINTF
			VPRINTF("fill_address: %s mapped to %p\n", namep,
			    (void *)*wkp->wk_vaddrp);
#endif /* VPRINTF */
		}
		if (wkp->wk_func != NULL)
			(*wkp->wk_func)(curnode);
		/*
		 * If this one is optional and there may be more than
		 * one, don't set V_MAPPED, which would cause us to skip it
		 * next time around
		 */
		if (wkp->wk_flags != V_MULTI)
			wkp->wk_flags = V_MAPPED;
	}
}

int
get_portid(pnode_t node, pnode_t *cmpp)
{
	int portid;
	int i;
	char dev_type[OBP_MAXPROPNAME];
	pnode_t cpu_parent;

	if (cmpp != NULL)
		*cmpp = OBP_NONODE;

	if (GETPROP(node, "portid", (caddr_t)&portid) != -1)
		return (portid);
	if (GETPROP(node, "upa-portid", (caddr_t)&portid) != -1)
		return (portid);
	if (GETPROP(node, "device_type", (caddr_t)&dev_type) == -1)
		return (-1);

	/*
	 * For a virtual cpu node that is a CMP core, the "portid"
	 * is in the parent node.
	 * For a virtual cpu node that is a CMT strand, the "portid" is
	 * in its grandparent node.
	 * So we iterate up as far as 2 levels to get the "portid".
	 */
	if (strcmp(dev_type, "cpu") == 0) {
		cpu_parent = node = prom_parentnode(node);
		for (i = 0; i < 2; i++) {
			if (node == OBP_NONODE || node == OBP_BADNODE)
				break;
			if (GETPROP(node, "portid", (caddr_t)&portid) != -1) {
				if (cmpp != NULL)
					*cmpp = cpu_parent;
				return (portid);
			}
			node = prom_parentnode(node);
		}
	}

	return (-1);
}

/*
 * Adjust page coloring variables based on the physical ecache setsize of
 * the configured cpus:
 *
 * Set ecache_setsize to max ecache set size to be used by
 * page_coloring_init() to determine the page colors to configure.
 * The adjustment is unlikely to be necessary... For cheetah+ systems,
 * ecache_setsize should already be set in cpu_fiximp() to the maximum
 * possible ecache setsize of any supported cheetah+ cpus. The adjustment
 * is for the off chance that a non-cheetah+ system may have heterogenous
 * cpus.
 *
 * Set cpu_setsize to the actual cpu setsize if the setsize is homogenous
 * across all cpus otherwise set it to -1 if heterogenous.
 *
 * Set cpu_page_colors to -1 to signify heterogeneity of ecache setsizes
 * to the page_get routines.
 */
static void
adj_ecache_setsize(int ecsetsize)
{
	if (ecsetsize > ecache_setsize)
		ecache_setsize = ecsetsize;

	switch (cpu_setsize) {
	case -1:
		break;
	case 0:
		cpu_setsize = ecsetsize;
		break;
	default:
		/* set to -1 if hetergenous cpus */
		if (cpu_setsize != ecsetsize) {
			if (do_pg_coloring)
				cpu_page_colors = -1;
			/*
			 * if page coloring disabled, cpu_page_colors should
			 * remain 0 to prevent page coloring processing.
			 */
			cpu_setsize = -1;
		}
		break;
	}
}

void
fill_cpu(pnode_t node)
{
	extern int cpu_get_cpu_unum(int, char *, int, int *);
	struct cpu_node *cpunode;
	processorid_t cpuid;
	int portid;
	int tlbsize;
	int size;
	uint_t clk_freq;
	pnode_t cmpnode;
	char namebuf[OBP_MAXPROPNAME], unum[UNUM_NAMLEN];
	char *namebufp;
	int proplen;

	if ((portid = get_portid(node, &cmpnode)) == -1) {
		cmn_err(CE_PANIC, "portid not found");
	}

	if (GETPROP(node, "cpuid", (caddr_t)&cpuid) == -1) {
		cpuid = portid;
	}

	if (cpuid < 0 || cpuid >= NCPU) {
		cmn_err(CE_PANIC, "cpu node %x: cpuid %d out of range", node,
		    cpuid);
		return;
	}

	cpunode = &cpunodes[cpuid];
	cpunode->portid = portid;
	cpunode->nodeid = node;

	if (cpu_get_cpu_unum(cpuid, unum, UNUM_NAMLEN, &size) != 0) {
		cpunode->fru_fmri[0] = '\0';
	} else {
		(void) snprintf(cpunode->fru_fmri, sizeof (cpunode->fru_fmri),
		    "%s%s", CPU_FRU_FMRI, unum);
	}

	if (cmpnode) {
		/*
		 * For the CMT case, the parent "core" node contains
		 * properties needed below, use it instead of the
		 * cpu node.
		 */
		if ((GETPROP(cmpnode, "device_type", namebuf) > 0) &&
		    (strcmp(namebuf, "core") == 0)) {
			node = cmpnode;
		}
	}

	(void) GETPROP(node, (cmpnode ? "compatible" : "name"), namebuf);

	/* Make sure CPU name is within boundary and NULL terminated */
	proplen = GETPROPLEN(node, (cmpnode ? "compatible" : "name"));
	ASSERT(proplen > 0 && proplen <= OBP_MAXPROPNAME);

	if (proplen >= OBP_MAXPROPNAME)
		proplen = OBP_MAXPROPNAME - 1;

	namebuf[proplen] = '\0';

	namebufp = namebuf;
	if (strncmp(namebufp, "SUNW,", 5) == 0)
		namebufp += 5;
	else if (strncmp(namebufp, "FJSV,", 5) == 0)
		namebufp += 5;
	(void) strcpy(cpunode->name, namebufp);

	(void) GETPROP(node, "implementation#",
	    (caddr_t)&cpunode->implementation);
	(void) GETPROP(node, "mask#", (caddr_t)&cpunode->version);

	if (IS_CHEETAH(cpunode->implementation)) {
		/* remap mask reg */
		cpunode->version = REMAP_CHEETAH_MASK(cpunode->version);
	}
	if (GETPROP(node, "clock-frequency", (caddr_t)&clk_freq) == -1) {
		/*
		 * If we didn't find it in the CPU node, look in the root node.
		 */
		pnode_t root = prom_nextnode((pnode_t)0);
		if (GETPROP(root, "clock-frequency", (caddr_t)&clk_freq) == -1)
			clk_freq = 0;
	}
	cpunode->clock_freq = clk_freq;

	ASSERT(cpunode->clock_freq != 0);
	/*
	 * Compute scaling factor based on rate of %tick. This is used
	 * to convert from ticks derived from %tick to nanoseconds. See
	 * comment in sun4u/sys/clock.h for details.
	 */
	cpunode->tick_nsec_scale = (uint_t)(((uint64_t)NANOSEC <<
	    (32 - TICK_NSEC_SHIFT)) / cpunode->clock_freq);

	(void) GETPROP(node, "#itlb-entries", (caddr_t)&tlbsize);
	ASSERT(tlbsize < USHRT_MAX); /* since we cast it */
	cpunode->itlb_size = (ushort_t)tlbsize;

	(void) GETPROP(node, "#dtlb-entries", (caddr_t)&tlbsize);
	ASSERT(tlbsize < USHRT_MAX); /* since we cast it */
	cpunode->dtlb_size = (ushort_t)tlbsize;

	if (cmpnode != OBP_NONODE) {
		/*
		 * If the CPU has a level 3 cache, then it will be the
		 * external cache. Otherwise the level 2 cache is the
		 * external cache.
		 */
		size = 0;
		(void) GETPROP(node, "l3-cache-size", (caddr_t)&size);
		if (size <= 0)
			(void) GETPROP(node, "l2-cache-size", (caddr_t)&size);
		ASSERT(size != 0);
		cpunode->ecache_size = size;

		size = 0;
		(void) GETPROP(node, "l3-cache-line-size", (caddr_t)&size);
		if (size <= 0)
			(void) GETPROP(node, "l2-cache-line-size",
			    (caddr_t)&size);
		ASSERT(size != 0);
		cpunode->ecache_linesize = size;

		size = 0;
		(void) GETPROP(node, "l2-cache-associativity", (caddr_t)&size);
		ASSERT(size != 0);
		cpunode->ecache_associativity = size;

		cmp_add_cpu(portid, cpuid);
	} else {
		size = 0;
		(void) GETPROP(node, "ecache-size", (caddr_t)&size);
		ASSERT(size != 0);
		cpunode->ecache_size = size;

		size = 0;
		(void) GETPROP(node, "ecache-line-size", (caddr_t)&size);
		ASSERT(size != 0);
		cpunode->ecache_linesize = size;

		size = 0;
		(void) GETPROP(node, "ecache-associativity", (caddr_t)&size);
		ASSERT(size != 0);
		cpunode->ecache_associativity = size;
	}

	/* by default set msram to non-mirrored one */
	cpunode->msram = ECACHE_CPU_NON_MIRROR;

	if (GETPROPLEN(node, "msram") != -1) {
		cpunode->msram = ECACHE_CPU_MIRROR;
	}

	if (GETPROPLEN(node, "msram-observed") != -1) {
		cpunode->msram = ECACHE_CPU_MIRROR;
	}

	if (ncpunode == 0) {
		cpu_fiximp(node);
	}

	cpunode->ecache_setsize =
	    cpunode->ecache_size / cpunode->ecache_associativity;

	adj_ecache_setsize(cpunode->ecache_setsize);

	ncpunode++;
}

int
get_portid_ddi(dev_info_t *dip, dev_info_t **cmpp)
{
	int portid;
	int i;
	char dev_type[OBP_MAXPROPNAME];
	int len = OBP_MAXPROPNAME;
	dev_info_t *cpu_parent;

	if (cmpp != NULL)
		*cmpp = NULL;

	if ((portid = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "portid", -1)) != -1)
		return (portid);
	if ((portid = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "upa-portid", -1)) != -1)
		return (portid);
	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS, "device_type", (caddr_t)dev_type,
	    &len) != 0)
		return (-1);

	/*
	 * For a virtual cpu node that is a CMP core, the "portid"
	 * is in the parent node.
	 * For a virtual cpu node that is a CMT strand, the "portid" is
	 * in its grandparent node.
	 * So we iterate up as far as 2 levels to get the "portid".
	 */
	if (strcmp(dev_type, "cpu") == 0) {
		cpu_parent = dip = ddi_get_parent(dip);
		for (i = 0; dip != NULL && i < 2; i++) {
			if ((portid = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS, "portid", -1)) != -1) {
				if (cmpp != NULL)
					*cmpp = cpu_parent;
				return (portid);
			}
			dip = ddi_get_parent(dip);
		}
	}

	return (-1);
}

/*
 * A hotplug version of fill_cpu().  (Doesn't assume that there's a node
 * in the PROM device tree for this CPU.)  We still need the PROM version
 * since it is called very early in the boot cycle before (before
 * setup_ddi()).  Sigh...someday this will all be cleaned up.
 */
void
fill_cpu_ddi(dev_info_t *dip)
{
	extern int cpu_get_cpu_unum(int, char *, int, int *);
	struct cpu_node *cpunode;
	processorid_t cpuid;
	int portid;
	int len = OBP_MAXPROPNAME;
	int tlbsize;
	dev_info_t *cmpnode;
	char namebuf[OBP_MAXPROPNAME], unum[UNUM_NAMLEN];
	char *namebufp;
	char dev_type[OBP_MAXPROPNAME];

	if ((portid = get_portid_ddi(dip, &cmpnode)) == -1) {
		cmn_err(CE_PANIC, "portid not found");
	}

	if ((cpuid = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "cpuid", -1)) == -1) {
		cpuid = portid;
	}

	if (cpuid < 0 || cpuid >= NCPU) {
		cmn_err(CE_PANIC, "cpu dip %p: cpuid %d out of range",
		    (void *)dip, cpuid);
		return;
	}

	cpunode = &cpunodes[cpuid];
	cpunode->portid = portid;
	cpunode->nodeid = ddi_get_nodeid(dip);

	if (cmpnode != NULL) {
		/*
		 * For the CMT case, the parent "core" node contains
		 * properties needed below, use it instead of the
		 * cpu node.
		 */
		if ((ddi_prop_op(DDI_DEV_T_ANY, cmpnode, PROP_LEN_AND_VAL_BUF,
		    DDI_PROP_DONTPASS, "device_type",
		    (caddr_t)dev_type, &len) == DDI_PROP_SUCCESS) &&
		    (strcmp(dev_type, "core") == 0))
			dip = cmpnode;
	}

	if (cpu_get_cpu_unum(cpuid, unum, UNUM_NAMLEN, &len) != 0) {
		cpunode->fru_fmri[0] = '\0';
	} else {
		(void) snprintf(cpunode->fru_fmri, sizeof (cpunode->fru_fmri),
		    "%s%s", CPU_FRU_FMRI, unum);
	}

	len = sizeof (namebuf);
	(void) ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS, (cmpnode ? "compatible" : "name"),
	    (caddr_t)namebuf, &len);

	namebufp = namebuf;
	if (strncmp(namebufp, "SUNW,", 5) == 0)
		namebufp += 5;
	else if (strncmp(namebufp, "FJSV,", 5) == 0)
		namebufp += 5;
	(void) strcpy(cpunode->name, namebufp);

	cpunode->implementation = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "implementation#", 0);

	cpunode->version = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "mask#", 0);

	if (IS_CHEETAH(cpunode->implementation)) {
		/* remap mask reg */
		cpunode->version = REMAP_CHEETAH_MASK(cpunode->version);
	}

	cpunode->clock_freq = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "clock-frequency", 0);

	ASSERT(cpunode->clock_freq != 0);
	/*
	 * Compute scaling factor based on rate of %tick. This is used
	 * to convert from ticks derived from %tick to nanoseconds. See
	 * comment in sun4u/sys/clock.h for details.
	 */
	cpunode->tick_nsec_scale = (uint_t)(((uint64_t)NANOSEC <<
	    (32 - TICK_NSEC_SHIFT)) / cpunode->clock_freq);

	tlbsize = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "#itlb-entries", 0);
	ASSERT(tlbsize < USHRT_MAX); /* since we cast it */
	cpunode->itlb_size = (ushort_t)tlbsize;

	tlbsize = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "#dtlb-entries", 0);
	ASSERT(tlbsize < USHRT_MAX); /* since we cast it */
	cpunode->dtlb_size = (ushort_t)tlbsize;

	if (cmpnode != NULL) {
		/*
		 * If the CPU has a level 3 cache, then that is it's
		 * external cache. Otherwise the external cache must
		 * be the level 2 cache.
		 */
		cpunode->ecache_size = ddi_prop_get_int(DDI_DEV_T_ANY,
		    dip, DDI_PROP_DONTPASS, "l3-cache-size", 0);
		if (cpunode->ecache_size == 0)
			cpunode->ecache_size = ddi_prop_get_int(DDI_DEV_T_ANY,
			    dip, DDI_PROP_DONTPASS, "l2-cache-size", 0);
		ASSERT(cpunode->ecache_size != 0);

		cpunode->ecache_linesize = ddi_prop_get_int(DDI_DEV_T_ANY,
		    dip, DDI_PROP_DONTPASS, "l3-cache-line-size", 0);
		if (cpunode->ecache_linesize == 0)
			cpunode->ecache_linesize =
			    ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS, "l2-cache-line-size", 0);
		ASSERT(cpunode->ecache_linesize != 0);

		cpunode->ecache_associativity = ddi_prop_get_int(DDI_DEV_T_ANY,
		    dip, DDI_PROP_DONTPASS, "l2-cache-associativity", 0);
		ASSERT(cpunode->ecache_associativity != 0);

		cmp_add_cpu(portid, cpuid);
	} else {
		cpunode->ecache_size = ddi_prop_get_int(DDI_DEV_T_ANY,
		    dip, DDI_PROP_DONTPASS, "ecache-size", 0);
		ASSERT(cpunode->ecache_size != 0);

		cpunode->ecache_linesize = ddi_prop_get_int(DDI_DEV_T_ANY,
		    dip, DDI_PROP_DONTPASS, "ecache-line-size", 0);
		ASSERT(cpunode->ecache_linesize != 0);

		cpunode->ecache_associativity = ddi_prop_get_int(DDI_DEV_T_ANY,
		    dip, DDI_PROP_DONTPASS, "ecache-associativity", 0);
		ASSERT(cpunode->ecache_associativity != 0);
	}

	/* by default set msram to non-mirrored one */
	cpunode->msram = ECACHE_CPU_NON_MIRROR;

	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "msram")) {
		cpunode->msram = ECACHE_CPU_MIRROR;
	} else if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "msram-observed")) {
		cpunode->msram = ECACHE_CPU_MIRROR;
	}

	ASSERT(ncpunode > 0);	/* fiximp not req'd */

	cpunode->ecache_setsize =
	    cpunode->ecache_size / cpunode->ecache_associativity;

	adj_ecache_setsize(cpunode->ecache_setsize);

	ncpunode++;
}

void
empty_cpu(int cpuid)
{
	bzero(&cpunodes[cpuid], sizeof (struct cpu_node));
	ncpunode--;
}

#ifdef SF_ERRATA_30 /* call causes fp-disabled */
int spitfire_call_bug = 0;
#endif
#ifdef SF_V9_TABLE_28	/* fp over/underflow traps may cause wrong fsr.cexc */
int spitfire_bb_fsr_bug = 0;
#endif

#ifdef JALAPENO_ERRATA_85
/*
 * Set the values here assuming we're running 2.4 or later Jalapenos.  If
 * not, they'll be reset below.  Either way, the default can be overridden
 * when we read /etc/system later in boot.
 */
int jp_errata_85_allow_slow_scrub = 1;
int jp_errata_85_enable = 0;
#endif	/* JALAPENO_ERRATA_85 */

static void
check_cpus_ver(void)
{
	int i;
	int impl, cpuid = getprocessorid();
	int min_supported_rev;

	ASSERT(cpunodes[cpuid].nodeid != 0);

	impl = cpunodes[cpuid].implementation;
	switch (impl) {
	default:
		min_supported_rev = 0;
		break;
	case SPITFIRE_IMPL:
		min_supported_rev = SPITFIRE_MINREV_SUPPORTED;
		break;
	case CHEETAH_IMPL:
		min_supported_rev = CHEETAH_MINREV_SUPPORTED;
		break;
	}

	for (i = 0; i < NCPU; i++) {
		if (cpunodes[i].nodeid == 0)
			continue;

		if (IS_SPITFIRE(impl)) {
			if (cpunodes[i].version < min_supported_rev) {
				cmn_err(CE_PANIC, "UltraSPARC versions older "
				    "than %d.%d are no longer supported "
				    "(cpu #%d)",
				    SPITFIRE_MAJOR_VERSION(min_supported_rev),
				    SPITFIRE_MINOR_VERSION(min_supported_rev),
				    i);
			}

			/*
			 * Min supported rev is 2.1 but we've seen problems
			 * with that so we still want to warn if we see one.
			 */
			if (cpunodes[i].version < 0x22) {
				cmn_err(CE_WARN,
				"UltraSPARC versions older than "
				"2.2 are not supported (cpu #%d)", i);
#ifdef SF_ERRATA_30 /* call causes fp-disabled */
				spitfire_call_bug = 1;
#endif /* SF_ERRATA_30 */
			}
		}


#ifdef SF_V9_TABLE_28	/* fp over/underflow traps may cause wrong fsr.cexc */
		if (IS_SPITFIRE(impl) || IS_BLACKBIRD(impl))
			spitfire_bb_fsr_bug = 1;
#endif /* SF_V9_TABLE_28 */

		if (IS_CHEETAH(impl)) {
			if (cpunodes[i].version < min_supported_rev) {
				cmn_err(CE_PANIC, "UltraSPARC-III versions "
				    "older than %d.%d are no longer supported "
				    "(cpu #%d)",
				    CHEETAH_MAJOR_VERSION(min_supported_rev),
				    CHEETAH_MINOR_VERSION(min_supported_rev),
				    i);
			}

		}

#ifdef JALAPENO_ERRATA_85
		if (IS_JALAPENO(impl) && (cpunodes[i].version < 0x24)) {
			jp_errata_85_allow_slow_scrub = 0;
			jp_errata_85_enable = 1;
		}
#endif /* JALAPENO_ERRATA_85 */
	}
}

/*
 * Check for a legal set of CPUs.
 */
static void
check_cpus_set(void)
{
	int i;
	int impl;
	int npanther = 0;
	int njupiter = 0;

	impl = cpunodes[getprocessorid()].implementation;

	switch (impl) {
	case CHEETAH_PLUS_IMPL:
	case JAGUAR_IMPL:
	case PANTHER_IMPL:
		/*
		 * Check for a legal heterogeneous set of CPUs.
		 */
		for (i = 0; i < NCPU; i++) {
			if (cpunodes[i].nodeid == 0)
				continue;

			if (IS_PANTHER(cpunodes[i].implementation)) {
				npanther += 1;
			}

			if (!(IS_CHEETAH_PLUS(cpunodes[i].implementation) ||
			    IS_JAGUAR(cpunodes[i].implementation) ||
			    IS_PANTHER(cpunodes[i].implementation))) {
				use_mp = 0;
				break;
			}
		}
		break;
	case OLYMPUS_C_IMPL:
	case JUPITER_IMPL:
		/*
		 * Check for a legal heterogeneous set of CPUs on the
		 * OPL platform.
		 */
		for (i = 0; i < NCPU; i++) {
			if (cpunodes[i].nodeid == 0)
				continue;

			if (IS_JUPITER(cpunodes[i].implementation)) {
				njupiter += 1;
			}
			if (!(IS_OLYMPUS_C(cpunodes[i].implementation) ||
			    IS_JUPITER(cpunodes[i].implementation))) {
				use_mp = 0;
				break;
			}
		}
		break;
	default:
		/*
		 * Check for a homogeneous set of CPUs.
		 */
		for (i = 0; i < NCPU; i++) {
			if (cpunodes[i].nodeid == 0)
				continue;

			if (cpunodes[i].implementation != impl) {
				use_mp = 0;
				break;
			}
		}
		break;
	}

	/*
	 * Change from mmu_page_sizes from 4 to 6 for totally-Panther domains,
	 * where npanther == ncpunode. Also, set ecache_alignsize (and a few
	 * other globals) to the correct value for totally-Panther domains.
	 */
	if (&mmu_init_mmu_page_sizes) {
		(void) mmu_init_mmu_page_sizes(npanther);
	}
	if ((npanther == ncpunode) && (&cpu_fix_allpanther)) {
		cpu_fix_allpanther();
	}

	/*
	 * For all-Jupiter domains the cpu module will update the hwcap features
	 * for integer multiply-add instruction support.
	 */
	if ((njupiter == ncpunode) && (&cpu_fix_alljupiter)) {
		cpu_fix_alljupiter();
	}

	/*
	 * Set max cpus we can have based on ncpunode and use_mp
	 */
	if (use_mp) {
		int (*set_max_ncpus)(void);

		set_max_ncpus = (int (*)(void))
		    kobj_getsymvalue("set_platform_max_ncpus", 0);

		if (set_max_ncpus) {
			max_ncpus = set_max_ncpus();
			if (max_ncpus < ncpunode)
				max_ncpus = ncpunode;
			boot_ncpus = boot_max_ncpus = ncpunode;
		} else {
			max_ncpus = ncpunode;
			boot_ncpus = ncpunode;
		}
	} else {
		cmn_err(CE_NOTE, "MP not supported on mismatched modules,"
		    " booting UP only");

		for (i = 0; i < NCPU; i++) {
			if (cpunodes[i].nodeid == 0)
				continue;

			cmn_err(CE_NOTE, "cpu%d: %s version 0x%x", i,
			    cpunodes[i].name, cpunodes[i].version);
		}

		max_ncpus = 1;
		boot_ncpus = 1;
	}
}

/*
 * The first sysio must always programmed up for the system clock and error
 * handling purposes, referenced by v_sysio_addr in machdep.c.
 */
static void
have_sbus(pnode_t node)
{
	int size;
	uint_t portid;

	size = GETPROPLEN(node, "upa-portid");
	if (size == -1 || size > sizeof (portid))
		cmn_err(CE_PANIC, "upa-portid size");
	if (GETPROP(node, "upa-portid", (caddr_t)&portid) == -1)
		cmn_err(CE_PANIC, "upa-portid");

	niobus++;

	/*
	 * need one physical TSB
	 */
	niommu_tsbs++;
}


#define	IOMMU_PER_SCHIZO	2

/*
 * The first psycho must always programmed up for the system clock and error
 * handling purposes.
 */
static void
have_pci(pnode_t node)
{
	int size;
	uint_t portid;
	char compatible[OBP_MAXDRVNAME];

	size = GETPROPLEN(node, "portid");
	if (size == -1) size = GETPROPLEN(node, "upa-portid");
	if (size == -1)
		return;
	if (size > sizeof (portid))
		cmn_err(CE_PANIC, "portid size wrong");

	if (GETPROP(node, "portid", (caddr_t)&portid) == -1)
		if (GETPROP(node, "upa-portid", (caddr_t)&portid) == -1)
			cmn_err(CE_PANIC, "portid not found");

	niobus++;


	/*
	 * Need two physical TSBs for Schizo compatible nodes,
	 * one otherwise.
	 */
	compatible[0] = '\0';
	(void) prom_getprop(node, OBP_COMPATIBLE, compatible);
	if (strcmp(compatible, "pci108e,8001") == 0)
		niommu_tsbs += IOMMU_PER_SCHIZO;
	else
		niommu_tsbs++;
}

/*
 * The first eeprom is used as the TOD clock, referenced
 * by v_eeprom_addr in locore.s.
 */
static void
have_eeprom(pnode_t node)
{
	int size;
	uint32_t eaddr;

	/*
	 * "todmostek" module will be selected based on finding a "model"
	 * property value of "mk48t59" in the "eeprom" node.
	 */
	if (tod_module_name == NULL) {
		char buf[MAXSYSNAME];

		if ((GETPROP(node, "model", buf) != -1) &&
		    (strcmp(buf, "mk48t59") == 0))
			tod_module_name = "todmostek";
	}

	/*
	 * If we have found two distinct eeprom's, then we're done.
	 */
	if (v_eeprom_addr && v_timecheck_addr != v_eeprom_addr)
		return;

	/*
	 * multiple eeproms may exist but at least
	 * one must have an "address" property
	 */
	if ((size = GETPROPLEN(node, OBP_ADDRESS)) == -1)
		return;
	if (size != sizeof (eaddr))
		cmn_err(CE_PANIC, "eeprom addr size");
	if (GETPROP(node, OBP_ADDRESS, (caddr_t)&eaddr) == -1)
		cmn_err(CE_PANIC, "eeprom addr");

	/*
	 * If we have a chosen eeprom and it is not this node, keep looking.
	 */
	if (chosen_eeprom != NULL && chosen_eeprom != node) {
		v_timecheck_addr = (caddr_t)(uintptr_t)eaddr;
		return;
	}

	v_eeprom_addr = (caddr_t)(uintptr_t)eaddr;

	/*
	 * If we don't find an I/O board to use to check the clock,
	 * we'll fall back on whichever TOD is available.
	 */
	if (v_timecheck_addr == NULL)
		v_timecheck_addr = v_eeprom_addr;

	/*
	 * Does this eeprom have watchdog support?
	 */
	if (GETPROPLEN(node, WATCHDOG_ENABLE) != -1)
		watchdog_available = 1;
}

static void
have_rtc(pnode_t node)
{
	int size;
	uint32_t eaddr;

	/*
	 * "ds1287" module will be selected based on finding a "model"
	 * property value of "ds1287" in the "rtc" node.
	 */
	if (tod_module_name == NULL) {
		char buf[MAXSYSNAME];

		if (GETPROP(node, "model", buf) != -1) {
			if ((strcmp(buf, "m5819p") == 0) ||
			    (strcmp(buf, "m5823") == 0))
				tod_module_name = "todm5823";
			else if (strcmp(buf, "ds1287") == 0)
				tod_module_name = "todds1287";
		}
	}

	/*
	 * XXX - drives on if address prop doesn't exist, later falls
	 * over in tod module
	 */
	if ((size = GETPROPLEN(node, OBP_ADDRESS)) == -1)
		return;
	if (size != sizeof (eaddr))
		cmn_err(CE_PANIC, "rtc addr size");
	if (GETPROP(node, OBP_ADDRESS, (caddr_t)&eaddr) == -1)
		cmn_err(CE_PANIC, "rtc addr");

	v_rtc_addr_reg = (caddr_t)(uintptr_t)eaddr;
	v_rtc_data_reg = (volatile unsigned char *)(uintptr_t)eaddr + 1;

	/*
	 * Does this rtc have watchdog support?
	 */
	if (GETPROPLEN(node, WATCHDOG_ENABLE) != -1)
		watchdog_available = 1;
}

static void
have_pmc(pnode_t node)
{
	uint32_t vaddr;
	pnode_t root;

	/*
	 * Watchdog property is in the root node.
	 */
	root = prom_nextnode((pnode_t)0);
	if (GETPROPLEN(root, WATCHDOG_ENABLE) != -1) {
		/*
		 * The hardware watchdog timer resides within logical
		 * unit 8 of SuperI/O. The address property of the node
		 * contains the virtual address that we use to program
		 * the timer.
		 */
		if (GETPROP(node, OBP_ADDRESS, (caddr_t)&vaddr) == -1) {
			watchdog_available = 0;
			return;
		}
		v_pmc_addr_reg = (volatile uint8_t *)(uintptr_t)vaddr;
		v_pmc_data_reg = (volatile uint8_t *)(uintptr_t)vaddr + 1;
		watchdog_available = 1;
	}
}

static void
have_auxio(pnode_t node)
{
	size_t size, n;
	uint32_t addr[5];

	/*
	 * Get the size of the auzio's address property.
	 * On some platforms, the address property contains one
	 * entry and on others it contains five entries.
	 * In all cases, the first entries are compatible.
	 *
	 * This routine gets the address property for the auxio
	 * node and stores the first entry in v_auxio_addr which
	 * is used by the routine set_auxioreg in sun4u/ml/locore.s.
	 */
	if ((size = GETPROPLEN(node, OBP_ADDRESS)) == -1)
		cmn_err(CE_PANIC, "no auxio address property");

	switch (n = (size / sizeof (addr[0]))) {
	case 1:
		break;
	case 5:
		break;
	default:
		cmn_err(CE_PANIC, "auxio addr has %lu entries?", n);
	}

	if (GETPROP(node, OBP_ADDRESS, (caddr_t)addr) == -1)
		cmn_err(CE_PANIC, "auxio addr");

	v_auxio_addr = (caddr_t)(uintptr_t)(addr[0]); /* make into pointer */
}

static void
have_tod(pnode_t node)
{
	static char tod_name[MAXSYSNAME];

	if (GETPROP(node, OBP_NAME, (caddr_t)tod_name) == -1)
		cmn_err(CE_PANIC, "tod name");
	/*
	 * This is a node with "device_type" property value of "tod".
	 * Name of the tod module is the name from the node.
	 */
	tod_module_name = tod_name;
}
