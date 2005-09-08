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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

void	fill_cpu(dnode_t);
void	plat_fill_mc(dnode_t);
#pragma weak plat_fill_mc

uint64_t	system_clock_freq;
int		niobus = 0;
uint_t		niommu_tsbs = 0;

/*
 * Hardware watchdog support.
 */
#define	CHOSEN_EEPROM	"eeprom"
static dnode_t 		chosen_eeprom;

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
static void	have_pci(dnode_t);

static struct wkdevice {
	char *wk_namep;
	void (*wk_func)(dnode_t);
	caddr_t *wk_vaddrp;
	ushort_t wk_flags;
#define	V_OPTIONAL	0x0000
#define	V_MUSTHAVE	0x0001
#define	V_MAPPED	0x0002
#define	V_MULTI		0x0003	/* optional, may be more than one */
} wkdevice[] = {
	{ "pci", have_pci, NULL, V_MULTI },
	{ 0, },
};

static void map_wellknown(dnode_t);

void
map_wellknown_devices()
{
	struct wkdevice *wkp;
	phandle_t	ieeprom;
	dnode_t	root;
	uint_t	stick_freq;

	/*
	 * if there is a chosen eeprom, note it (for have_eeprom())
	 */
	if (GETPROPLEN(prom_chosennode(), CHOSEN_EEPROM) ==
	    sizeof (phandle_t) &&
	    GETPROP(prom_chosennode(), CHOSEN_EEPROM, (caddr_t)&ieeprom) != -1)
		chosen_eeprom = (dnode_t)prom_decode_int(ieeprom);

	root = prom_nextnode((dnode_t)0);
	/*
	 * Get System clock frequency from root node if it exists.
	 */
	if (GETPROP(root, "stick-frequency", (caddr_t)&stick_freq) != -1)
		system_clock_freq = stick_freq;

	map_wellknown(NEXT((dnode_t)0));

	/*
	 * See if it worked
	 */
	for (wkp = wkdevice; wkp->wk_namep; ++wkp) {
		if (wkp->wk_flags == V_MUSTHAVE) {
			cmn_err(CE_PANIC, "map_wellknown_devices: required "
			    "device %s not mapped", wkp->wk_namep);
		}
	}
}

/*
 * map_wellknown - map known devices & registers
 */
static void
map_wellknown(dnode_t curnode)
{
	extern int status_okay(int, char *, int);
	char tmp_name[MAXSYSNAME];
	static void fill_address(dnode_t, char *);
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

		if (sok && (strcmp(tmp_name, "memory-controller") == 0) &&
		    (&plat_fill_mc != NULL))
			plat_fill_mc(curnode);
		map_wellknown(curnode);
	}
}

static void
fill_address(dnode_t curnode, char *namep)
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
			    *wkp->wk_vaddrp);
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

void
fill_cpu(dnode_t node)
{
	struct cpu_node *cpunode;
	processorid_t cpuid;
	uint_t clk_freq;
	char namebuf[OBP_MAXPROPNAME], unum[UNUM_NAMLEN];
	char *namebufp;

	if (GETPROP(node, "cpuid", (caddr_t)&cpuid) == -1) {
		if (GETPROP(node, "reg", (caddr_t)&cpuid) == -1)
			cmn_err(CE_PANIC, "reg prop not found in cpu node");
		cpuid = PROM_CFGHDL_TO_CPUID(cpuid);
	}

	if (cpuid < 0 || cpuid >= NCPU) {
		cmn_err(CE_CONT, "cpu (dnode %x): out of range cpuid %d - "
		    "cpu excluded from configuration\n", node, cpuid);
		return;
	}

	cpunode = &cpunodes[cpuid];
	cpunode->cpuid = cpuid;
	cpunode->device_id = cpuid;

	unum[0] = '\0';
	(void) snprintf(cpunode->fru_fmri, sizeof (cpunode->fru_fmri),
		"%s%s", CPU_FRU_FMRI, unum);
	(void) GETPROP(node, "compatible", namebuf);
	namebufp = namebuf;
	if (strncmp(namebufp, "SUNW,", 5) == 0)
		namebufp += 5;
	(void) strcpy(cpunode->name, namebufp);

	if (GETPROP(node, "clock-frequency", (caddr_t)&clk_freq) == -1) {
		/*
		 * If we didn't find it in the CPU node, look in the root node.
		 */
		dnode_t root = prom_nextnode((dnode_t)0);
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


	cpunode->nodeid = node;

	/*
	 * Call cpu module specific code to fill in the cpu properities
	 */
	cpu_fiximp(cpunode);
}

#define	IOMMU_PER_SCHIZO	2

/*
 * The first psycho must always programmed up for the system clock and error
 * handling purposes.
 */
static void
have_pci(dnode_t node)
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
	 * Need two physical TSBs for Schizo-compatible nodes,
	 * one otherwise.
	 */
	compatible[0] = '\0';
	(void) prom_getprop(node, OBP_COMPATIBLE, compatible);
	if (strcmp(compatible, "pci108e,8001") == 0)
		niommu_tsbs += IOMMU_PER_SCHIZO;
	else
		niommu_tsbs++;
}


int
get_cpu_pagesizes(void)
{
	/*
	 * XXXQ Get supported page sizes information from the PD
	 * and return a bit mask indicating which page sizes are
	 * supported.
	 *
	 * Return 0 when no information is available.
	 */

	return (0);			/* XXXQ for now return 0 as no PD */
}
