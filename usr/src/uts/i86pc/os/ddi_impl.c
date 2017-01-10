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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>
 * Copyright 2014 Pluribus Networks, Inc.
 */

/*
 * PC specific DDI implementation
 */
#include <sys/types.h>
#include <sys/autoconf.h>
#include <sys/avintr.h>
#include <sys/bootconf.h>
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/ethernet.h>
#include <sys/fp.h>
#include <sys/instance.h>
#include <sys/kmem.h>
#include <sys/machsystm.h>
#include <sys/modctl.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/ddi_impldefs.h>
#include <sys/sysmacros.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>
#include <sys/atomic.h>
#include <sys/spl.h>
#include <sys/archsystm.h>
#include <vm/seg_kmem.h>
#include <sys/ontrap.h>
#include <sys/fm/protocol.h>
#include <sys/ramdisk.h>
#include <sys/sunndi.h>
#include <sys/vmem.h>
#include <sys/pci_impl.h>
#if defined(__xpv)
#include <sys/hypervisor.h>
#endif
#include <sys/mach_intr.h>
#include <vm/hat_i86.h>
#include <sys/x86_archext.h>
#include <sys/avl.h>

/*
 * DDI Boot Configuration
 */

/*
 * Platform drivers on this platform
 */
char *platform_module_list[] = {
	"acpippm",
	"ppm",
	(char *)0
};

/* pci bus resource maps */
struct pci_bus_resource *pci_bus_res;

size_t dma_max_copybuf_size = 0x101000;		/* 1M + 4K */

uint64_t ramdisk_start, ramdisk_end;

int pseudo_isa = 0;

/*
 * Forward declarations
 */
static int getlongprop_buf();
static void get_boot_properties(void);
static void impl_bus_initialprobe(void);
static void impl_bus_reprobe(void);

static int poke_mem(peekpoke_ctlops_t *in_args);
static int peek_mem(peekpoke_ctlops_t *in_args);

static int kmem_override_cache_attrs(caddr_t, size_t, uint_t);

#if defined(__amd64) && !defined(__xpv)
extern void immu_init(void);
#endif

/*
 * We use an AVL tree to store contiguous address allocations made with the
 * kalloca() routine, so that we can return the size to free with kfreea().
 * Note that in the future it would be vastly faster if we could eliminate
 * this lookup by insisting that all callers keep track of their own sizes,
 * just as for kmem_alloc().
 */
struct ctgas {
	avl_node_t ctg_link;
	void *ctg_addr;
	size_t ctg_size;
};

static avl_tree_t ctgtree;

static kmutex_t		ctgmutex;
#define	CTGLOCK()	mutex_enter(&ctgmutex)
#define	CTGUNLOCK()	mutex_exit(&ctgmutex)

/*
 * Minimum pfn value of page_t's put on the free list.  This is to simplify
 * support of ddi dma memory requests which specify small, non-zero addr_lo
 * values.
 *
 * The default value of 2, which corresponds to the only known non-zero addr_lo
 * value used, means a single page will be sacrificed (pfn typically starts
 * at 1).  ddiphysmin can be set to 0 to disable. It cannot be set above 0x100
 * otherwise mp startup panics.
 */
pfn_t	ddiphysmin = 2;

static void
check_driver_disable(void)
{
	int proplen = 128;
	char *prop_name;
	char *drv_name, *propval;
	major_t major;

	prop_name = kmem_alloc(proplen, KM_SLEEP);
	for (major = 0; major < devcnt; major++) {
		drv_name = ddi_major_to_name(major);
		if (drv_name == NULL)
			continue;
		(void) snprintf(prop_name, proplen, "disable-%s", drv_name);
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
		    DDI_PROP_DONTPASS, prop_name, &propval) == DDI_SUCCESS) {
			if (strcmp(propval, "true") == 0) {
				devnamesp[major].dn_flags |= DN_DRIVER_REMOVED;
				cmn_err(CE_NOTE, "driver %s disabled",
				    drv_name);
			}
			ddi_prop_free(propval);
		}
	}
	kmem_free(prop_name, proplen);
}


/*
 * Configure the hardware on the system.
 * Called before the rootfs is mounted
 */
void
configure(void)
{
	extern void i_ddi_init_root();

#if defined(__i386)
	extern int fpu_pentium_fdivbug;
#endif	/* __i386 */
	extern int fpu_ignored;

	/*
	 * Determine if an FPU is attached
	 */

	fpu_probe();

#if defined(__i386)
	if (fpu_pentium_fdivbug) {
		printf("\
FP hardware exhibits Pentium floating point divide problem\n");
	}
#endif	/* __i386 */

	if (fpu_ignored) {
		printf("FP hardware will not be used\n");
	} else if (!fpu_exists) {
		printf("No FPU in configuration\n");
	}

	/*
	 * Initialize devices on the machine.
	 * Uses configuration tree built by the PROMs to determine what
	 * is present, and builds a tree of prototype dev_info nodes
	 * corresponding to the hardware which identified itself.
	 */

	/*
	 * Initialize root node.
	 */
	i_ddi_init_root();

	/* reprogram devices not set up by firmware (BIOS) */
	impl_bus_reprobe();

#if defined(__amd64) && !defined(__xpv)
	/*
	 * Setup but don't startup the IOMMU
	 * Startup happens later via a direct call
	 * to IOMMU code by boot code.
	 * At this point, all PCI bus renumbering
	 * is done, so safe to init the IMMU
	 * AKA Intel IOMMU.
	 */
	immu_init();
#endif

	/*
	 * attach the isa nexus to get ACPI resource usage
	 * isa is "kind of" a pseudo node
	 */
#if defined(__xpv)
	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		if (pseudo_isa)
			(void) i_ddi_attach_pseudo_node("isa");
		else
			(void) i_ddi_attach_hw_nodes("isa");
	}
#else
	if (pseudo_isa)
		(void) i_ddi_attach_pseudo_node("isa");
	else
		(void) i_ddi_attach_hw_nodes("isa");
#endif
}

/*
 * The "status" property indicates the operational status of a device.
 * If this property is present, the value is a string indicating the
 * status of the device as follows:
 *
 *	"okay"		operational.
 *	"disabled"	not operational, but might become operational.
 *	"fail"		not operational because a fault has been detected,
 *			and it is unlikely that the device will become
 *			operational without repair. no additional details
 *			are available.
 *	"fail-xxx"	not operational because a fault has been detected,
 *			and it is unlikely that the device will become
 *			operational without repair. "xxx" is additional
 *			human-readable information about the particular
 *			fault condition that was detected.
 *
 * The absence of this property means that the operational status is
 * unknown or okay.
 *
 * This routine checks the status property of the specified device node
 * and returns 0 if the operational status indicates failure, and 1 otherwise.
 *
 * The property may exist on plug-in cards the existed before IEEE 1275-1994.
 * And, in that case, the property may not even be a string. So we carefully
 * check for the value "fail", in the beginning of the string, noting
 * the property length.
 */
int
status_okay(int id, char *buf, int buflen)
{
	char status_buf[OBP_MAXPROPNAME];
	char *bufp = buf;
	int len = buflen;
	int proplen;
	static const char *status = "status";
	static const char *fail = "fail";
	int fail_len = (int)strlen(fail);

	/*
	 * Get the proplen ... if it's smaller than "fail",
	 * or doesn't exist ... then we don't care, since
	 * the value can't begin with the char string "fail".
	 *
	 * NB: proplen, if it's a string, includes the NULL in the
	 * the size of the property, and fail_len does not.
	 */
	proplen = prom_getproplen((pnode_t)id, (caddr_t)status);
	if (proplen <= fail_len)	/* nonexistant or uninteresting len */
		return (1);

	/*
	 * if a buffer was provided, use it
	 */
	if ((buf == (char *)NULL) || (buflen <= 0)) {
		bufp = status_buf;
		len = sizeof (status_buf);
	}
	*bufp = (char)0;

	/*
	 * Get the property into the buffer, to the extent of the buffer,
	 * and in case the buffer is smaller than the property size,
	 * NULL terminate the buffer. (This handles the case where
	 * a buffer was passed in and the caller wants to print the
	 * value, but the buffer was too small).
	 */
	(void) prom_bounded_getprop((pnode_t)id, (caddr_t)status,
	    (caddr_t)bufp, len);
	*(bufp + len - 1) = (char)0;

	/*
	 * If the value begins with the char string "fail",
	 * then it means the node is failed. We don't care
	 * about any other values. We assume the node is ok
	 * although it might be 'disabled'.
	 */
	if (strncmp(bufp, fail, fail_len) == 0)
		return (0);

	return (1);
}

/*
 * Check the status of the device node passed as an argument.
 *
 *	if ((status is OKAY) || (status is DISABLED))
 *		return DDI_SUCCESS
 *	else
 *		print a warning and return DDI_FAILURE
 */
/*ARGSUSED1*/
int
check_status(int id, char *name, dev_info_t *parent)
{
	char status_buf[64];
	char devtype_buf[OBP_MAXPROPNAME];
	int retval = DDI_FAILURE;

	/*
	 * is the status okay?
	 */
	if (status_okay(id, status_buf, sizeof (status_buf)))
		return (DDI_SUCCESS);

	/*
	 * a status property indicating bad memory will be associated
	 * with a node which has a "device_type" property with a value of
	 * "memory-controller". in this situation, return DDI_SUCCESS
	 */
	if (getlongprop_buf(id, OBP_DEVICETYPE, devtype_buf,
	    sizeof (devtype_buf)) > 0) {
		if (strcmp(devtype_buf, "memory-controller") == 0)
			retval = DDI_SUCCESS;
	}

	/*
	 * print the status property information
	 */
	cmn_err(CE_WARN, "status '%s' for '%s'", status_buf, name);
	return (retval);
}

/*ARGSUSED*/
uint_t
softlevel1(caddr_t arg1, caddr_t arg2)
{
	softint();
	return (1);
}

/*
 * Allow for implementation specific correction of PROM property values.
 */

/*ARGSUSED*/
void
impl_fix_props(dev_info_t *dip, dev_info_t *ch_dip, char *name, int len,
    caddr_t buffer)
{
	/*
	 * There are no adjustments needed in this implementation.
	 */
}

static int
getlongprop_buf(int id, char *name, char *buf, int maxlen)
{
	int size;

	size = prom_getproplen((pnode_t)id, name);
	if (size <= 0 || (size > maxlen - 1))
		return (-1);

	if (-1 == prom_getprop((pnode_t)id, name, buf))
		return (-1);

	if (strcmp("name", name) == 0) {
		if (buf[size - 1] != '\0') {
			buf[size] = '\0';
			size += 1;
		}
	}

	return (size);
}

static int
get_prop_int_array(dev_info_t *di, char *pname, int **pval, uint_t *plen)
{
	int ret;

	if ((ret = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, di,
	    DDI_PROP_DONTPASS, pname, pval, plen))
	    == DDI_PROP_SUCCESS) {
		*plen = (*plen) * (sizeof (int));
	}
	return (ret);
}


/*
 * Node Configuration
 */

struct prop_ispec {
	uint_t	pri, vec;
};

/*
 * For the x86, we're prepared to claim that the interrupt string
 * is in the form of a list of <ipl,vec> specifications.
 */

#define	VEC_MIN	1
#define	VEC_MAX	255

static int
impl_xlate_intrs(dev_info_t *child, int *in,
    struct ddi_parent_private_data *pdptr)
{
	size_t size;
	int n;
	struct intrspec *new;
	caddr_t got_prop;
	int *inpri;
	int got_len;
	extern int ignore_hardware_nodes;	/* force flag from ddi_impl.c */

	static char bad_intr_fmt[] =
	    "bad interrupt spec from %s%d - ipl %d, irq %d\n";

	/*
	 * determine if the driver is expecting the new style "interrupts"
	 * property which just contains the IRQ, or the old style which
	 * contains pairs of <IPL,IRQ>.  if it is the new style, we always
	 * assign IPL 5 unless an "interrupt-priorities" property exists.
	 * in that case, the "interrupt-priorities" property contains the
	 * IPL values that match, one for one, the IRQ values in the
	 * "interrupts" property.
	 */
	inpri = NULL;
	if ((ddi_getprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "ignore-hardware-nodes", -1) != -1) || ignore_hardware_nodes) {
		/* the old style "interrupts" property... */

		/*
		 * The list consists of <ipl,vec> elements
		 */
		if ((n = (*in++ >> 1)) < 1)
			return (DDI_FAILURE);

		pdptr->par_nintr = n;
		size = n * sizeof (struct intrspec);
		new = pdptr->par_intr = kmem_zalloc(size, KM_SLEEP);

		while (n--) {
			int level = *in++;
			int vec = *in++;

			if (level < 1 || level > MAXIPL ||
			    vec < VEC_MIN || vec > VEC_MAX) {
				cmn_err(CE_CONT, bad_intr_fmt,
				    DEVI(child)->devi_name,
				    DEVI(child)->devi_instance, level, vec);
				goto broken;
			}
			new->intrspec_pri = level;
			if (vec != 2)
				new->intrspec_vec = vec;
			else
				/*
				 * irq 2 on the PC bus is tied to irq 9
				 * on ISA, EISA and MicroChannel
				 */
				new->intrspec_vec = 9;
			new++;
		}

		return (DDI_SUCCESS);
	} else {
		/* the new style "interrupts" property... */

		/*
		 * The list consists of <vec> elements
		 */
		if ((n = (*in++)) < 1)
			return (DDI_FAILURE);

		pdptr->par_nintr = n;
		size = n * sizeof (struct intrspec);
		new = pdptr->par_intr = kmem_zalloc(size, KM_SLEEP);

		/* XXX check for "interrupt-priorities" property... */
		if (ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
		    "interrupt-priorities", (caddr_t)&got_prop, &got_len)
		    == DDI_PROP_SUCCESS) {
			if (n != (got_len / sizeof (int))) {
				cmn_err(CE_CONT,
				    "bad interrupt-priorities length"
				    " from %s%d: expected %d, got %d\n",
				    DEVI(child)->devi_name,
				    DEVI(child)->devi_instance, n,
				    (int)(got_len / sizeof (int)));
				goto broken;
			}
			inpri = (int *)got_prop;
		}

		while (n--) {
			int level;
			int vec = *in++;

			if (inpri == NULL)
				level = 5;
			else
				level = *inpri++;

			if (level < 1 || level > MAXIPL ||
			    vec < VEC_MIN || vec > VEC_MAX) {
				cmn_err(CE_CONT, bad_intr_fmt,
				    DEVI(child)->devi_name,
				    DEVI(child)->devi_instance, level, vec);
				goto broken;
			}
			new->intrspec_pri = level;
			if (vec != 2)
				new->intrspec_vec = vec;
			else
				/*
				 * irq 2 on the PC bus is tied to irq 9
				 * on ISA, EISA and MicroChannel
				 */
				new->intrspec_vec = 9;
			new++;
		}

		if (inpri != NULL)
			kmem_free(got_prop, got_len);
		return (DDI_SUCCESS);
	}

broken:
	kmem_free(pdptr->par_intr, size);
	pdptr->par_intr = NULL;
	pdptr->par_nintr = 0;
	if (inpri != NULL)
		kmem_free(got_prop, got_len);

	return (DDI_FAILURE);
}

/*
 * Create a ddi_parent_private_data structure from the ddi properties of
 * the dev_info node.
 *
 * The "reg" and either an "intr" or "interrupts" properties are required
 * if the driver wishes to create mappings or field interrupts on behalf
 * of the device.
 *
 * The "reg" property is assumed to be a list of at least one triple
 *
 *	<bustype, address, size>*1
 *
 * The "intr" property is assumed to be a list of at least one duple
 *
 *	<SPARC ipl, vector#>*1
 *
 * The "interrupts" property is assumed to be a list of at least one
 * n-tuples that describes the interrupt capabilities of the bus the device
 * is connected to.  For SBus, this looks like
 *
 *	<SBus-level>*1
 *
 * (This property obsoletes the 'intr' property).
 *
 * The "ranges" property is optional.
 */
void
make_ddi_ppd(dev_info_t *child, struct ddi_parent_private_data **ppd)
{
	struct ddi_parent_private_data *pdptr;
	int n;
	int *reg_prop, *rng_prop, *intr_prop, *irupts_prop;
	uint_t reg_len, rng_len, intr_len, irupts_len;

	*ppd = pdptr = kmem_zalloc(sizeof (*pdptr), KM_SLEEP);

	/*
	 * Handle the 'reg' property.
	 */
	if ((get_prop_int_array(child, "reg", &reg_prop, &reg_len) ==
	    DDI_PROP_SUCCESS) && (reg_len != 0)) {
		pdptr->par_nreg = reg_len / (int)sizeof (struct regspec);
		pdptr->par_reg = (struct regspec *)reg_prop;
	}

	/*
	 * See if I have a range (adding one where needed - this
	 * means to add one for sbus node in sun4c, when romvec > 0,
	 * if no range is already defined in the PROM node.
	 * (Currently no sun4c PROMS define range properties,
	 * but they should and may in the future.)  For the SBus
	 * node, the range is defined by the SBus reg property.
	 */
	if (get_prop_int_array(child, "ranges", &rng_prop, &rng_len)
	    == DDI_PROP_SUCCESS) {
		pdptr->par_nrng = rng_len / (int)(sizeof (struct rangespec));
		pdptr->par_rng = (struct rangespec *)rng_prop;
	}

	/*
	 * Handle the 'intr' and 'interrupts' properties
	 */

	/*
	 * For backwards compatibility
	 * we first look for the 'intr' property for the device.
	 */
	if (get_prop_int_array(child, "intr", &intr_prop, &intr_len)
	    != DDI_PROP_SUCCESS) {
		intr_len = 0;
	}

	/*
	 * If we're to support bus adapters and future platforms cleanly,
	 * we need to support the generalized 'interrupts' property.
	 */
	if (get_prop_int_array(child, "interrupts", &irupts_prop,
	    &irupts_len) != DDI_PROP_SUCCESS) {
		irupts_len = 0;
	} else if (intr_len != 0) {
		/*
		 * If both 'intr' and 'interrupts' are defined,
		 * then 'interrupts' wins and we toss the 'intr' away.
		 */
		ddi_prop_free((void *)intr_prop);
		intr_len = 0;
	}

	if (intr_len != 0) {

		/*
		 * Translate the 'intr' property into an array
		 * an array of struct intrspec's.  There's not really
		 * very much to do here except copy what's out there.
		 */

		struct intrspec *new;
		struct prop_ispec *l;

		n = pdptr->par_nintr = intr_len / sizeof (struct prop_ispec);
		l = (struct prop_ispec *)intr_prop;
		pdptr->par_intr =
		    new = kmem_zalloc(n * sizeof (struct intrspec), KM_SLEEP);
		while (n--) {
			new->intrspec_pri = l->pri;
			new->intrspec_vec = l->vec;
			new++;
			l++;
		}
		ddi_prop_free((void *)intr_prop);

	} else if ((n = irupts_len) != 0) {
		size_t size;
		int *out;

		/*
		 * Translate the 'interrupts' property into an array
		 * of intrspecs for the rest of the DDI framework to
		 * toy with.  Only our ancestors really know how to
		 * do this, so ask 'em.  We massage the 'interrupts'
		 * property so that it is pre-pended by a count of
		 * the number of integers in the argument.
		 */
		size = sizeof (int) + n;
		out = kmem_alloc(size, KM_SLEEP);
		*out = n / sizeof (int);
		bcopy(irupts_prop, out + 1, (size_t)n);
		ddi_prop_free((void *)irupts_prop);
		if (impl_xlate_intrs(child, out, pdptr) != DDI_SUCCESS) {
			cmn_err(CE_CONT,
			    "Unable to translate 'interrupts' for %s%d\n",
			    DEVI(child)->devi_binding_name,
			    DEVI(child)->devi_instance);
		}
		kmem_free(out, size);
	}
}

/*
 * Name a child
 */
static int
impl_sunbus_name_child(dev_info_t *child, char *name, int namelen)
{
	/*
	 * Fill in parent-private data and this function returns to us
	 * an indication if it used "registers" to fill in the data.
	 */
	if (ddi_get_parent_data(child) == NULL) {
		struct ddi_parent_private_data *pdptr;
		make_ddi_ppd(child, &pdptr);
		ddi_set_parent_data(child, pdptr);
	}

	name[0] = '\0';
	if (sparc_pd_getnreg(child) > 0) {
		(void) snprintf(name, namelen, "%x,%x",
		    (uint_t)sparc_pd_getreg(child, 0)->regspec_bustype,
		    (uint_t)sparc_pd_getreg(child, 0)->regspec_addr);
	}

	return (DDI_SUCCESS);
}

/*
 * Called from the bus_ctl op of sunbus (sbus, obio, etc) nexus drivers
 * to implement the DDI_CTLOPS_INITCHILD operation.  That is, it names
 * the children of sun busses based on the reg spec.
 *
 * Handles the following properties (in make_ddi_ppd):
 *	Property		value
 *	  Name			type
 *	reg		register spec
 *	intr		old-form interrupt spec
 *	interrupts	new (bus-oriented) interrupt spec
 *	ranges		range spec
 */
int
impl_ddi_sunbus_initchild(dev_info_t *child)
{
	char name[MAXNAMELEN];
	void impl_ddi_sunbus_removechild(dev_info_t *);

	/*
	 * Name the child, also makes parent private data
	 */
	(void) impl_sunbus_name_child(child, name, MAXNAMELEN);
	ddi_set_name_addr(child, name);

	/*
	 * Attempt to merge a .conf node; if successful, remove the
	 * .conf node.
	 */
	if ((ndi_dev_is_persistent_node(child) == 0) &&
	    (ndi_merge_node(child, impl_sunbus_name_child) == DDI_SUCCESS)) {
		/*
		 * Return failure to remove node
		 */
		impl_ddi_sunbus_removechild(child);
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

void
impl_free_ddi_ppd(dev_info_t *dip)
{
	struct ddi_parent_private_data *pdptr;
	size_t n;

	if ((pdptr = ddi_get_parent_data(dip)) == NULL)
		return;

	if ((n = (size_t)pdptr->par_nintr) != 0)
		/*
		 * Note that kmem_free is used here (instead of
		 * ddi_prop_free) because the contents of the
		 * property were placed into a separate buffer and
		 * mucked with a bit before being stored in par_intr.
		 * The actual return value from the prop lookup
		 * was freed with ddi_prop_free previously.
		 */
		kmem_free(pdptr->par_intr, n * sizeof (struct intrspec));

	if ((n = (size_t)pdptr->par_nrng) != 0)
		ddi_prop_free((void *)pdptr->par_rng);

	if ((n = pdptr->par_nreg) != 0)
		ddi_prop_free((void *)pdptr->par_reg);

	kmem_free(pdptr, sizeof (*pdptr));
	ddi_set_parent_data(dip, NULL);
}

void
impl_ddi_sunbus_removechild(dev_info_t *dip)
{
	impl_free_ddi_ppd(dip);
	ddi_set_name_addr(dip, NULL);
	/*
	 * Strip the node to properly convert it back to prototype form
	 */
	impl_rem_dev_props(dip);
}

/*
 * DDI Interrupt
 */

/*
 * turn this on to force isa, eisa, and mca device to ignore the new
 * hardware nodes in the device tree (normally turned on only for
 * drivers that need it by setting the property "ignore-hardware-nodes"
 * in their driver.conf file).
 *
 * 7/31/96 -- Turned off globally.  Leaving variable in for the moment
 *		as safety valve.
 */
int ignore_hardware_nodes = 0;

/*
 * Local data
 */
static struct impl_bus_promops *impl_busp;


/*
 * New DDI interrupt framework
 */

/*
 * i_ddi_intr_ops:
 *
 * This is the interrupt operator function wrapper for the bus function
 * bus_intr_op.
 */
int
i_ddi_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t op,
    ddi_intr_handle_impl_t *hdlp, void * result)
{
	dev_info_t	*pdip = (dev_info_t *)DEVI(dip)->devi_parent;
	int		ret = DDI_FAILURE;

	/* request parent to process this interrupt op */
	if (NEXUS_HAS_INTR_OP(pdip))
		ret = (*(DEVI(pdip)->devi_ops->devo_bus_ops->bus_intr_op))(
		    pdip, rdip, op, hdlp, result);
	else
		cmn_err(CE_WARN, "Failed to process interrupt "
		    "for %s%d due to down-rev nexus driver %s%d",
		    ddi_get_name(rdip), ddi_get_instance(rdip),
		    ddi_get_name(pdip), ddi_get_instance(pdip));
	return (ret);
}

/*
 * i_ddi_add_softint - allocate and add a soft interrupt to the system
 */
int
i_ddi_add_softint(ddi_softint_hdl_impl_t *hdlp)
{
	int ret;

	/* add soft interrupt handler */
	ret = add_avsoftintr((void *)hdlp, hdlp->ih_pri, hdlp->ih_cb_func,
	    DEVI(hdlp->ih_dip)->devi_name, hdlp->ih_cb_arg1, hdlp->ih_cb_arg2);
	return (ret ? DDI_SUCCESS : DDI_FAILURE);
}


void
i_ddi_remove_softint(ddi_softint_hdl_impl_t *hdlp)
{
	(void) rem_avsoftintr((void *)hdlp, hdlp->ih_pri, hdlp->ih_cb_func);
}


extern void (*setsoftint)(int, struct av_softinfo *);
extern boolean_t av_check_softint_pending(struct av_softinfo *, boolean_t);

int
i_ddi_trigger_softint(ddi_softint_hdl_impl_t *hdlp, void *arg2)
{
	if (av_check_softint_pending(hdlp->ih_pending, B_FALSE))
		return (DDI_EPENDING);

	update_avsoftintr_args((void *)hdlp, hdlp->ih_pri, arg2);

	(*setsoftint)(hdlp->ih_pri, hdlp->ih_pending);
	return (DDI_SUCCESS);
}

/*
 * i_ddi_set_softint_pri:
 *
 * The way this works is that it first tries to add a softint vector
 * at the new priority in hdlp. If that succeeds; then it removes the
 * existing softint vector at the old priority.
 */
int
i_ddi_set_softint_pri(ddi_softint_hdl_impl_t *hdlp, uint_t old_pri)
{
	int ret;

	/*
	 * If a softint is pending at the old priority then fail the request.
	 */
	if (av_check_softint_pending(hdlp->ih_pending, B_TRUE))
		return (DDI_FAILURE);

	ret = av_softint_movepri((void *)hdlp, old_pri);
	return (ret ? DDI_SUCCESS : DDI_FAILURE);
}

void
i_ddi_alloc_intr_phdl(ddi_intr_handle_impl_t *hdlp)
{
	hdlp->ih_private = (void *)kmem_zalloc(sizeof (ihdl_plat_t), KM_SLEEP);
}

void
i_ddi_free_intr_phdl(ddi_intr_handle_impl_t *hdlp)
{
	kmem_free(hdlp->ih_private, sizeof (ihdl_plat_t));
	hdlp->ih_private = NULL;
}

int
i_ddi_get_intx_nintrs(dev_info_t *dip)
{
	struct ddi_parent_private_data *pdp;

	if ((pdp = ddi_get_parent_data(dip)) == NULL)
		return (0);

	return (pdp->par_nintr);
}

/*
 * DDI Memory/DMA
 */

/*
 * Support for allocating DMAable memory to implement
 * ddi_dma_mem_alloc(9F) interface.
 */

#define	KA_ALIGN_SHIFT	7
#define	KA_ALIGN	(1 << KA_ALIGN_SHIFT)
#define	KA_NCACHE	(PAGESHIFT + 1 - KA_ALIGN_SHIFT)

/*
 * Dummy DMA attribute template for kmem_io[].kmem_io_attr.  We only
 * care about addr_lo, addr_hi, and align.  addr_hi will be dynamically set.
 */

static ddi_dma_attr_t kmem_io_attr = {
	DMA_ATTR_V0,
	0x0000000000000000ULL,		/* dma_attr_addr_lo */
	0x0000000000000000ULL,		/* dma_attr_addr_hi */
	0x00ffffff,
	0x1000,				/* dma_attr_align */
	1, 1, 0xffffffffULL, 0xffffffffULL, 0x1, 1, 0
};

/* kmem io memory ranges and indices */
enum {
	IO_4P, IO_64G, IO_4G, IO_2G, IO_1G, IO_512M,
	IO_256M, IO_128M, IO_64M, IO_32M, IO_16M, MAX_MEM_RANGES
};

static struct {
	vmem_t		*kmem_io_arena;
	kmem_cache_t	*kmem_io_cache[KA_NCACHE];
	ddi_dma_attr_t	kmem_io_attr;
} kmem_io[MAX_MEM_RANGES];

static int kmem_io_idx;		/* index of first populated kmem_io[] */

static page_t *
page_create_io_wrapper(void *addr, size_t len, int vmflag, void *arg)
{
	extern page_t *page_create_io(vnode_t *, u_offset_t, uint_t,
	    uint_t, struct as *, caddr_t, ddi_dma_attr_t *);

	return (page_create_io(&kvp, (u_offset_t)(uintptr_t)addr, len,
	    PG_EXCL | ((vmflag & VM_NOSLEEP) ? 0 : PG_WAIT), &kas, addr, arg));
}

#ifdef __xpv
static void
segkmem_free_io(vmem_t *vmp, void * ptr, size_t size)
{
	extern void page_destroy_io(page_t *);
	segkmem_xfree(vmp, ptr, size, page_destroy_io);
}
#endif

static void *
segkmem_alloc_io_4P(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_4P].kmem_io_attr));
}

static void *
segkmem_alloc_io_64G(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_64G].kmem_io_attr));
}

static void *
segkmem_alloc_io_4G(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_4G].kmem_io_attr));
}

static void *
segkmem_alloc_io_2G(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_2G].kmem_io_attr));
}

static void *
segkmem_alloc_io_1G(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_1G].kmem_io_attr));
}

static void *
segkmem_alloc_io_512M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_512M].kmem_io_attr));
}

static void *
segkmem_alloc_io_256M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_256M].kmem_io_attr));
}

static void *
segkmem_alloc_io_128M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_128M].kmem_io_attr));
}

static void *
segkmem_alloc_io_64M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_64M].kmem_io_attr));
}

static void *
segkmem_alloc_io_32M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_32M].kmem_io_attr));
}

static void *
segkmem_alloc_io_16M(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    page_create_io_wrapper, &kmem_io[IO_16M].kmem_io_attr));
}

struct {
	uint64_t	io_limit;
	char		*io_name;
	void		*(*io_alloc)(vmem_t *, size_t, int);
	int		io_initial;	/* kmem_io_init during startup */
} io_arena_params[MAX_MEM_RANGES] = {
	{0x000fffffffffffffULL,	"kmem_io_4P",	segkmem_alloc_io_4P,	1},
	{0x0000000fffffffffULL,	"kmem_io_64G",	segkmem_alloc_io_64G,	0},
	{0x00000000ffffffffULL,	"kmem_io_4G",	segkmem_alloc_io_4G,	1},
	{0x000000007fffffffULL,	"kmem_io_2G",	segkmem_alloc_io_2G,	1},
	{0x000000003fffffffULL,	"kmem_io_1G",	segkmem_alloc_io_1G,	0},
	{0x000000001fffffffULL,	"kmem_io_512M",	segkmem_alloc_io_512M,	0},
	{0x000000000fffffffULL,	"kmem_io_256M",	segkmem_alloc_io_256M,	0},
	{0x0000000007ffffffULL,	"kmem_io_128M",	segkmem_alloc_io_128M,	0},
	{0x0000000003ffffffULL,	"kmem_io_64M",	segkmem_alloc_io_64M,	0},
	{0x0000000001ffffffULL,	"kmem_io_32M",	segkmem_alloc_io_32M,	0},
	{0x0000000000ffffffULL,	"kmem_io_16M",	segkmem_alloc_io_16M,	1}
};

void
kmem_io_init(int a)
{
	int	c;
	char name[40];

	kmem_io[a].kmem_io_arena = vmem_create(io_arena_params[a].io_name,
	    NULL, 0, PAGESIZE, io_arena_params[a].io_alloc,
#ifdef __xpv
	    segkmem_free_io,
#else
	    segkmem_free,
#endif
	    heap_arena, 0, VM_SLEEP);

	for (c = 0; c < KA_NCACHE; c++) {
		size_t size = KA_ALIGN << c;
		(void) sprintf(name, "%s_%lu",
		    io_arena_params[a].io_name, size);
		kmem_io[a].kmem_io_cache[c] = kmem_cache_create(name,
		    size, size, NULL, NULL, NULL, NULL,
		    kmem_io[a].kmem_io_arena, 0);
	}
}

/*
 * Return the index of the highest memory range for addr.
 */
static int
kmem_io_index(uint64_t addr)
{
	int n;

	for (n = kmem_io_idx; n < MAX_MEM_RANGES; n++) {
		if (kmem_io[n].kmem_io_attr.dma_attr_addr_hi <= addr) {
			if (kmem_io[n].kmem_io_arena == NULL)
				kmem_io_init(n);
			return (n);
		}
	}
	panic("kmem_io_index: invalid addr - must be at least 16m");

	/*NOTREACHED*/
}

/*
 * Return the index of the next kmem_io populated memory range
 * after curindex.
 */
static int
kmem_io_index_next(int curindex)
{
	int n;

	for (n = curindex + 1; n < MAX_MEM_RANGES; n++) {
		if (kmem_io[n].kmem_io_arena)
			return (n);
	}
	return (-1);
}

/*
 * allow kmem to be mapped in with different PTE cache attribute settings.
 * Used by i_ddi_mem_alloc()
 */
int
kmem_override_cache_attrs(caddr_t kva, size_t size, uint_t order)
{
	uint_t hat_flags;
	caddr_t kva_end;
	uint_t hat_attr;
	pfn_t pfn;

	if (hat_getattr(kas.a_hat, kva, &hat_attr) == -1) {
		return (-1);
	}

	hat_attr &= ~HAT_ORDER_MASK;
	hat_attr |= order | HAT_NOSYNC;
	hat_flags = HAT_LOAD_LOCK;

	kva_end = (caddr_t)(((uintptr_t)kva + size + PAGEOFFSET) &
	    (uintptr_t)PAGEMASK);
	kva = (caddr_t)((uintptr_t)kva & (uintptr_t)PAGEMASK);

	while (kva < kva_end) {
		pfn = hat_getpfnum(kas.a_hat, kva);
		hat_unload(kas.a_hat, kva, PAGESIZE, HAT_UNLOAD_UNLOCK);
		hat_devload(kas.a_hat, kva, PAGESIZE, pfn, hat_attr, hat_flags);
		kva += MMU_PAGESIZE;
	}

	return (0);
}

static int
ctgcompare(const void *a1, const void *a2)
{
	/* we just want to compare virtual addresses */
	a1 = ((struct ctgas *)a1)->ctg_addr;
	a2 = ((struct ctgas *)a2)->ctg_addr;
	return (a1 == a2 ? 0 : (a1 < a2 ? -1 : 1));
}

void
ka_init(void)
{
	int a;
	paddr_t maxphysaddr;
#if !defined(__xpv)
	extern pfn_t physmax;

	maxphysaddr = mmu_ptob((paddr_t)physmax) + MMU_PAGEOFFSET;
#else
	maxphysaddr = mmu_ptob((paddr_t)HYPERVISOR_memory_op(
	    XENMEM_maximum_ram_page, NULL)) + MMU_PAGEOFFSET;
#endif

	ASSERT(maxphysaddr <= io_arena_params[0].io_limit);

	for (a = 0; a < MAX_MEM_RANGES; a++) {
		if (maxphysaddr >= io_arena_params[a + 1].io_limit) {
			if (maxphysaddr > io_arena_params[a + 1].io_limit)
				io_arena_params[a].io_limit = maxphysaddr;
			else
				a++;
			break;
		}
	}
	kmem_io_idx = a;

	for (; a < MAX_MEM_RANGES; a++) {
		kmem_io[a].kmem_io_attr = kmem_io_attr;
		kmem_io[a].kmem_io_attr.dma_attr_addr_hi =
		    io_arena_params[a].io_limit;
		/*
		 * initialize kmem_io[] arena/cache corresponding to
		 * maxphysaddr and to the "common" io memory ranges that
		 * have io_initial set to a non-zero value.
		 */
		if (io_arena_params[a].io_initial || a == kmem_io_idx)
			kmem_io_init(a);
	}

	/* initialize ctgtree */
	avl_create(&ctgtree, ctgcompare, sizeof (struct ctgas),
	    offsetof(struct ctgas, ctg_link));
}

/*
 * put contig address/size
 */
static void *
putctgas(void *addr, size_t size)
{
	struct ctgas    *ctgp;
	if ((ctgp = kmem_zalloc(sizeof (*ctgp), KM_NOSLEEP)) != NULL) {
		ctgp->ctg_addr = addr;
		ctgp->ctg_size = size;
		CTGLOCK();
		avl_add(&ctgtree, ctgp);
		CTGUNLOCK();
	}
	return (ctgp);
}

/*
 * get contig size by addr
 */
static size_t
getctgsz(void *addr)
{
	struct ctgas    *ctgp;
	struct ctgas    find;
	size_t		sz = 0;

	find.ctg_addr = addr;
	CTGLOCK();
	if ((ctgp = avl_find(&ctgtree, &find, NULL)) != NULL) {
		avl_remove(&ctgtree, ctgp);
	}
	CTGUNLOCK();

	if (ctgp != NULL) {
		sz = ctgp->ctg_size;
		kmem_free(ctgp, sizeof (*ctgp));
	}

	return (sz);
}

/*
 * contig_alloc:
 *
 *	allocates contiguous memory to satisfy the 'size' and dma attributes
 *	specified in 'attr'.
 *
 *	Not all of memory need to be physically contiguous if the
 *	scatter-gather list length is greater than 1.
 */

/*ARGSUSED*/
void *
contig_alloc(size_t size, ddi_dma_attr_t *attr, uintptr_t align, int cansleep)
{
	pgcnt_t		pgcnt = btopr(size);
	size_t		asize = pgcnt * PAGESIZE;
	page_t		*ppl;
	int		pflag;
	void		*addr;

	extern page_t *page_create_io(vnode_t *, u_offset_t, uint_t,
	    uint_t, struct as *, caddr_t, ddi_dma_attr_t *);

	/* segkmem_xalloc */

	if (align <= PAGESIZE)
		addr = vmem_alloc(heap_arena, asize,
		    (cansleep) ? VM_SLEEP : VM_NOSLEEP);
	else
		addr = vmem_xalloc(heap_arena, asize, align, 0, 0, NULL, NULL,
		    (cansleep) ? VM_SLEEP : VM_NOSLEEP);
	if (addr) {
		ASSERT(!((uintptr_t)addr & (align - 1)));

		if (page_resv(pgcnt, (cansleep) ? KM_SLEEP : KM_NOSLEEP) == 0) {
			vmem_free(heap_arena, addr, asize);
			return (NULL);
		}
		pflag = PG_EXCL;

		if (cansleep)
			pflag |= PG_WAIT;

		/* 4k req gets from freelists rather than pfn search */
		if (pgcnt > 1 || align > PAGESIZE)
			pflag |= PG_PHYSCONTIG;

		ppl = page_create_io(&kvp, (u_offset_t)(uintptr_t)addr,
		    asize, pflag, &kas, (caddr_t)addr, attr);

		if (!ppl) {
			vmem_free(heap_arena, addr, asize);
			page_unresv(pgcnt);
			return (NULL);
		}

		while (ppl != NULL) {
			page_t	*pp = ppl;
			page_sub(&ppl, pp);
			ASSERT(page_iolock_assert(pp));
			page_io_unlock(pp);
			page_downgrade(pp);
			hat_memload(kas.a_hat, (caddr_t)(uintptr_t)pp->p_offset,
			    pp, (PROT_ALL & ~PROT_USER) |
			    HAT_NOSYNC, HAT_LOAD_LOCK);
		}
	}
	return (addr);
}

void
contig_free(void *addr, size_t size)
{
	pgcnt_t	pgcnt = btopr(size);
	size_t	asize = pgcnt * PAGESIZE;
	caddr_t	a, ea;
	page_t	*pp;

	hat_unload(kas.a_hat, addr, asize, HAT_UNLOAD_UNLOCK);

	for (a = addr, ea = a + asize; a < ea; a += PAGESIZE) {
		pp = page_find(&kvp, (u_offset_t)(uintptr_t)a);
		if (!pp)
			panic("contig_free: contig pp not found");

		if (!page_tryupgrade(pp)) {
			page_unlock(pp);
			pp = page_lookup(&kvp,
			    (u_offset_t)(uintptr_t)a, SE_EXCL);
			if (pp == NULL)
				panic("contig_free: page freed");
		}
		page_destroy(pp, 0);
	}

	page_unresv(pgcnt);
	vmem_free(heap_arena, addr, asize);
}

/*
 * Allocate from the system, aligned on a specific boundary.
 * The alignment, if non-zero, must be a power of 2.
 */
static void *
kalloca(size_t size, size_t align, int cansleep, int physcontig,
    ddi_dma_attr_t *attr)
{
	size_t *addr, *raddr, rsize;
	size_t hdrsize = 4 * sizeof (size_t);	/* must be power of 2 */
	int a, i, c;
	vmem_t *vmp;
	kmem_cache_t *cp = NULL;

	if (attr->dma_attr_addr_lo > mmu_ptob((uint64_t)ddiphysmin))
		return (NULL);

	align = MAX(align, hdrsize);
	ASSERT((align & (align - 1)) == 0);

	/*
	 * All of our allocators guarantee 16-byte alignment, so we don't
	 * need to reserve additional space for the header.
	 * To simplify picking the correct kmem_io_cache, we round up to
	 * a multiple of KA_ALIGN.
	 */
	rsize = P2ROUNDUP_TYPED(size + align, KA_ALIGN, size_t);

	if (physcontig && rsize > PAGESIZE) {
		if (addr = contig_alloc(size, attr, align, cansleep)) {
			if (!putctgas(addr, size))
				contig_free(addr, size);
			else
				return (addr);
		}
		return (NULL);
	}

	a = kmem_io_index(attr->dma_attr_addr_hi);

	if (rsize > PAGESIZE) {
		vmp = kmem_io[a].kmem_io_arena;
		raddr = vmem_alloc(vmp, rsize,
		    (cansleep) ? VM_SLEEP : VM_NOSLEEP);
	} else {
		c = highbit((rsize >> KA_ALIGN_SHIFT) - 1);
		cp = kmem_io[a].kmem_io_cache[c];
		raddr = kmem_cache_alloc(cp, (cansleep) ? KM_SLEEP :
		    KM_NOSLEEP);
	}

	if (raddr == NULL) {
		int	na;

		ASSERT(cansleep == 0);
		if (rsize > PAGESIZE)
			return (NULL);
		/*
		 * System does not have memory in the requested range.
		 * Try smaller kmem io ranges and larger cache sizes
		 * to see if there might be memory available in
		 * these other caches.
		 */

		for (na = kmem_io_index_next(a); na >= 0;
		    na = kmem_io_index_next(na)) {
			ASSERT(kmem_io[na].kmem_io_arena);
			cp = kmem_io[na].kmem_io_cache[c];
			raddr = kmem_cache_alloc(cp, KM_NOSLEEP);
			if (raddr)
				goto kallocdone;
		}
		/* now try the larger kmem io cache sizes */
		for (na = a; na >= 0; na = kmem_io_index_next(na)) {
			for (i = c + 1; i < KA_NCACHE; i++) {
				cp = kmem_io[na].kmem_io_cache[i];
				raddr = kmem_cache_alloc(cp, KM_NOSLEEP);
				if (raddr)
					goto kallocdone;
			}
		}
		return (NULL);
	}

kallocdone:
	ASSERT(!P2BOUNDARY((uintptr_t)raddr, rsize, PAGESIZE) ||
	    rsize > PAGESIZE);

	addr = (size_t *)P2ROUNDUP((uintptr_t)raddr + hdrsize, align);
	ASSERT((uintptr_t)addr + size - (uintptr_t)raddr <= rsize);

	addr[-4] = (size_t)cp;
	addr[-3] = (size_t)vmp;
	addr[-2] = (size_t)raddr;
	addr[-1] = rsize;

	return (addr);
}

static void
kfreea(void *addr)
{
	size_t		size;

	if (!((uintptr_t)addr & PAGEOFFSET) && (size = getctgsz(addr))) {
		contig_free(addr, size);
	} else {
		size_t	*saddr = addr;
		if (saddr[-4] == 0)
			vmem_free((vmem_t *)saddr[-3], (void *)saddr[-2],
			    saddr[-1]);
		else
			kmem_cache_free((kmem_cache_t *)saddr[-4],
			    (void *)saddr[-2]);
	}
}

/*ARGSUSED*/
void
i_ddi_devacc_to_hatacc(ddi_device_acc_attr_t *devaccp, uint_t *hataccp)
{
}

/*
 * Check if the specified cache attribute is supported on the platform.
 * This function must be called before i_ddi_cacheattr_to_hatacc().
 */
boolean_t
i_ddi_check_cache_attr(uint_t flags)
{
	/*
	 * The cache attributes are mutually exclusive. Any combination of
	 * the attributes leads to a failure.
	 */
	uint_t cache_attr = IOMEM_CACHE_ATTR(flags);
	if ((cache_attr != 0) && !ISP2(cache_attr))
		return (B_FALSE);

	/* All cache attributes are supported on X86/X64 */
	if (cache_attr & (IOMEM_DATA_UNCACHED | IOMEM_DATA_CACHED |
	    IOMEM_DATA_UC_WR_COMBINE))
		return (B_TRUE);

	/* undefined attributes */
	return (B_FALSE);
}

/* set HAT cache attributes from the cache attributes */
void
i_ddi_cacheattr_to_hatacc(uint_t flags, uint_t *hataccp)
{
	uint_t cache_attr = IOMEM_CACHE_ATTR(flags);
	static char *fname = "i_ddi_cacheattr_to_hatacc";

	/*
	 * If write-combining is not supported, then it falls back
	 * to uncacheable.
	 */
	if (cache_attr == IOMEM_DATA_UC_WR_COMBINE &&
	    !is_x86_feature(x86_featureset, X86FSET_PAT))
		cache_attr = IOMEM_DATA_UNCACHED;

	/*
	 * set HAT attrs according to the cache attrs.
	 */
	switch (cache_attr) {
	case IOMEM_DATA_UNCACHED:
		*hataccp &= ~HAT_ORDER_MASK;
		*hataccp |= (HAT_STRICTORDER | HAT_PLAT_NOCACHE);
		break;
	case IOMEM_DATA_UC_WR_COMBINE:
		*hataccp &= ~HAT_ORDER_MASK;
		*hataccp |= (HAT_MERGING_OK | HAT_PLAT_NOCACHE);
		break;
	case IOMEM_DATA_CACHED:
		*hataccp &= ~HAT_ORDER_MASK;
		*hataccp |= HAT_UNORDERED_OK;
		break;
	/*
	 * This case must not occur because the cache attribute is scrutinized
	 * before this function is called.
	 */
	default:
		/*
		 * set cacheable to hat attrs.
		 */
		*hataccp &= ~HAT_ORDER_MASK;
		*hataccp |= HAT_UNORDERED_OK;
		cmn_err(CE_WARN, "%s: cache_attr=0x%x is ignored.",
		    fname, cache_attr);
	}
}

/*
 * This should actually be called i_ddi_dma_mem_alloc. There should
 * also be an i_ddi_pio_mem_alloc. i_ddi_dma_mem_alloc should call
 * through the device tree with the DDI_CTLOPS_DMA_ALIGN ctl ops to
 * get alignment requirements for DMA memory. i_ddi_pio_mem_alloc
 * should use DDI_CTLOPS_PIO_ALIGN. Since we only have i_ddi_mem_alloc
 * so far which is used for both, DMA and PIO, we have to use the DMA
 * ctl ops to make everybody happy.
 */
/*ARGSUSED*/
int
i_ddi_mem_alloc(dev_info_t *dip, ddi_dma_attr_t *attr,
    size_t length, int cansleep, int flags,
    ddi_device_acc_attr_t *accattrp, caddr_t *kaddrp,
    size_t *real_length, ddi_acc_hdl_t *ap)
{
	caddr_t a;
	int iomin;
	ddi_acc_impl_t *iap;
	int physcontig = 0;
	pgcnt_t npages;
	pgcnt_t minctg;
	uint_t order;
	int e;

	/*
	 * Check legality of arguments
	 */
	if (length == 0 || kaddrp == NULL || attr == NULL) {
		return (DDI_FAILURE);
	}

	if (attr->dma_attr_minxfer == 0 || attr->dma_attr_align == 0 ||
	    !ISP2(attr->dma_attr_align) || !ISP2(attr->dma_attr_minxfer)) {
		return (DDI_FAILURE);
	}

	/*
	 * figure out most restrictive alignment requirement
	 */
	iomin = attr->dma_attr_minxfer;
	iomin = maxbit(iomin, attr->dma_attr_align);
	if (iomin == 0)
		return (DDI_FAILURE);

	ASSERT((iomin & (iomin - 1)) == 0);

	/*
	 * if we allocate memory with IOMEM_DATA_UNCACHED or
	 * IOMEM_DATA_UC_WR_COMBINE, make sure we allocate a page aligned
	 * memory that ends on a page boundry.
	 * Don't want to have to different cache mappings to the same
	 * physical page.
	 */
	if (OVERRIDE_CACHE_ATTR(flags)) {
		iomin = (iomin + MMU_PAGEOFFSET) & MMU_PAGEMASK;
		length = (length + MMU_PAGEOFFSET) & (size_t)MMU_PAGEMASK;
	}

	/*
	 * Determine if we need to satisfy the request for physically
	 * contiguous memory or alignments larger than pagesize.
	 */
	npages = btopr(length + attr->dma_attr_align);
	minctg = howmany(npages, attr->dma_attr_sgllen);

	if (minctg > 1) {
		uint64_t pfnseg = attr->dma_attr_seg >> PAGESHIFT;
		/*
		 * verify that the minimum contig requirement for the
		 * actual length does not cross segment boundary.
		 */
		length = P2ROUNDUP_TYPED(length, attr->dma_attr_minxfer,
		    size_t);
		npages = btopr(length);
		minctg = howmany(npages, attr->dma_attr_sgllen);
		if (minctg > pfnseg + 1)
			return (DDI_FAILURE);
		physcontig = 1;
	} else {
		length = P2ROUNDUP_TYPED(length, iomin, size_t);
	}

	/*
	 * Allocate the requested amount from the system.
	 */
	a = kalloca(length, iomin, cansleep, physcontig, attr);

	if ((*kaddrp = a) == NULL)
		return (DDI_FAILURE);

	/*
	 * if we to modify the cache attributes, go back and muck with the
	 * mappings.
	 */
	if (OVERRIDE_CACHE_ATTR(flags)) {
		order = 0;
		i_ddi_cacheattr_to_hatacc(flags, &order);
		e = kmem_override_cache_attrs(a, length, order);
		if (e != 0) {
			kfreea(a);
			return (DDI_FAILURE);
		}
	}

	if (real_length) {
		*real_length = length;
	}
	if (ap) {
		/*
		 * initialize access handle
		 */
		iap = (ddi_acc_impl_t *)ap->ah_platform_private;
		iap->ahi_acc_attr |= DDI_ACCATTR_CPU_VADDR;
		impl_acc_hdl_init(ap);
	}

	return (DDI_SUCCESS);
}

/* ARGSUSED */
void
i_ddi_mem_free(caddr_t kaddr, ddi_acc_hdl_t *ap)
{
	if (ap != NULL) {
		/*
		 * if we modified the cache attributes on alloc, go back and
		 * fix them since this memory could be returned to the
		 * general pool.
		 */
		if (OVERRIDE_CACHE_ATTR(ap->ah_xfermodes)) {
			uint_t order = 0;
			int e;
			i_ddi_cacheattr_to_hatacc(IOMEM_DATA_CACHED, &order);
			e = kmem_override_cache_attrs(kaddr, ap->ah_len, order);
			if (e != 0) {
				cmn_err(CE_WARN, "i_ddi_mem_free() failed to "
				    "override cache attrs, memory leaked\n");
				return;
			}
		}
	}
	kfreea(kaddr);
}

/*
 * Access Barriers
 *
 */
/*ARGSUSED*/
int
i_ddi_ontrap(ddi_acc_handle_t hp)
{
	return (DDI_FAILURE);
}

/*ARGSUSED*/
void
i_ddi_notrap(ddi_acc_handle_t hp)
{
}


/*
 * Misc Functions
 */

/*
 * Implementation instance override functions
 *
 * No override on i86pc
 */
/*ARGSUSED*/
uint_t
impl_assign_instance(dev_info_t *dip)
{
	return ((uint_t)-1);
}

/*ARGSUSED*/
int
impl_keep_instance(dev_info_t *dip)
{

#if defined(__xpv)
	/*
	 * Do not persist instance numbers assigned to devices in dom0
	 */
	dev_info_t *pdip;
	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		if (((pdip = ddi_get_parent(dip)) != NULL) &&
		    (strcmp(ddi_get_name(pdip), "xpvd") == 0))
			return (DDI_SUCCESS);
	}
#endif
	return (DDI_FAILURE);
}

/*ARGSUSED*/
int
impl_free_instance(dev_info_t *dip)
{
	return (DDI_FAILURE);
}

/*ARGSUSED*/
int
impl_check_cpu(dev_info_t *devi)
{
	return (DDI_SUCCESS);
}

/*
 * Referenced in common/cpr_driver.c: Power off machine.
 * Don't know how to power off i86pc.
 */
void
arch_power_down()
{}

/*
 * Copy name to property_name, since name
 * is in the low address range below kernelbase.
 */
static void
copy_boot_str(const char *boot_str, char *kern_str, int len)
{
	int i = 0;

	while (i < len - 1 && boot_str[i] != '\0') {
		kern_str[i] = boot_str[i];
		i++;
	}

	kern_str[i] = 0;	/* null terminate */
	if (boot_str[i] != '\0')
		cmn_err(CE_WARN,
		    "boot property string is truncated to %s", kern_str);
}

static void
get_boot_properties(void)
{
	extern char hw_provider[];
	dev_info_t *devi;
	char *name;
	int length;
	char property_name[50], property_val[50];
	void *bop_staging_area;

	bop_staging_area = kmem_zalloc(MMU_PAGESIZE, KM_NOSLEEP);

	/*
	 * Import "root" properties from the boot.
	 *
	 * We do this by invoking BOP_NEXTPROP until the list
	 * is completely copied in.
	 */

	devi = ddi_root_node();
	for (name = BOP_NEXTPROP(bootops, "");		/* get first */
	    name;					/* NULL => DONE */
	    name = BOP_NEXTPROP(bootops, name)) {	/* get next */

		/* copy string to memory above kernelbase */
		copy_boot_str(name, property_name, 50);

		/*
		 * Skip vga properties. They will be picked up later
		 * by get_vga_properties.
		 */
		if (strcmp(property_name, "display-edif-block") == 0 ||
		    strcmp(property_name, "display-edif-id") == 0) {
			continue;
		}

		length = BOP_GETPROPLEN(bootops, property_name);
		if (length == 0)
			continue;
		if (length > MMU_PAGESIZE) {
			cmn_err(CE_NOTE,
			    "boot property %s longer than 0x%x, ignored\n",
			    property_name, MMU_PAGESIZE);
			continue;
		}
		BOP_GETPROP(bootops, property_name, bop_staging_area);

		/*
		 * special properties:
		 * si-machine, si-hw-provider
		 *	goes to kernel data structures.
		 * bios-boot-device and stdout
		 *	goes to hardware property list so it may show up
		 *	in the prtconf -vp output. This is needed by
		 *	Install/Upgrade. Once we fix install upgrade,
		 *	this can be taken out.
		 */
		if (strcmp(name, "si-machine") == 0) {
			(void) strncpy(utsname.machine, bop_staging_area,
			    SYS_NMLN);
			utsname.machine[SYS_NMLN - 1] = (char)NULL;
		} else if (strcmp(name, "si-hw-provider") == 0) {
			(void) strncpy(hw_provider, bop_staging_area, SYS_NMLN);
			hw_provider[SYS_NMLN - 1] = (char)NULL;
		} else if (strcmp(name, "bios-boot-device") == 0) {
			copy_boot_str(bop_staging_area, property_val, 50);
			(void) ndi_prop_update_string(DDI_DEV_T_NONE, devi,
			    property_name, property_val);
		} else if (strcmp(name, "stdout") == 0) {
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, devi,
			    property_name, *((int *)bop_staging_area));
		} else if (strcmp(name, "boot-args") == 0) {
			copy_boot_str(bop_staging_area, property_val, 50);
			(void) e_ddi_prop_update_string(DDI_DEV_T_NONE, devi,
			    property_name, property_val);
		} else if (strcmp(name, "bootargs") == 0) {
			copy_boot_str(bop_staging_area, property_val, 50);
			(void) e_ddi_prop_update_string(DDI_DEV_T_NONE, devi,
			    property_name, property_val);
		} else if (strcmp(name, "bootp-response") == 0) {
			(void) e_ddi_prop_update_byte_array(DDI_DEV_T_NONE,
			    devi, property_name, bop_staging_area, length);
		} else if (strcmp(name, "ramdisk_start") == 0) {
			(void) e_ddi_prop_update_int64(DDI_DEV_T_NONE, devi,
			    property_name, *((int64_t *)bop_staging_area));
		} else if (strcmp(name, "ramdisk_end") == 0) {
			(void) e_ddi_prop_update_int64(DDI_DEV_T_NONE, devi,
			    property_name, *((int64_t *)bop_staging_area));
		} else if (strncmp(name, "module-addr-", 12) == 0) {
			(void) e_ddi_prop_update_int64(DDI_DEV_T_NONE, devi,
			    property_name, *((int64_t *)bop_staging_area));
		} else if (strncmp(name, "module-size-", 12) == 0) {
			(void) e_ddi_prop_update_int64(DDI_DEV_T_NONE, devi,
			    property_name, *((int64_t *)bop_staging_area));
		} else {
			/* Property type unknown, use old prop interface */
			(void) e_ddi_prop_create(DDI_DEV_T_NONE, devi,
			    DDI_PROP_CANSLEEP, property_name, bop_staging_area,
			    length);
		}
	}

	kmem_free(bop_staging_area, MMU_PAGESIZE);
}

static void
get_vga_properties(void)
{
	dev_info_t *devi;
	major_t major;
	char *name;
	int length;
	char property_val[50];
	void *bop_staging_area;

	/*
	 * XXXX Hack Allert!
	 * There really needs to be a better way for identifying various
	 * console framebuffers and their related issues.  Till then,
	 * check for this one as a replacement to vgatext.
	 */
	major = ddi_name_to_major("ragexl");
	if (major == (major_t)-1) {
		major = ddi_name_to_major("vgatext");
		if (major == (major_t)-1)
			return;
	}
	devi = devnamesp[major].dn_head;
	if (devi == NULL)
		return;

	bop_staging_area = kmem_zalloc(MMU_PAGESIZE, KM_SLEEP);

	/*
	 * Import "vga" properties from the boot.
	 */
	name = "display-edif-block";
	length = BOP_GETPROPLEN(bootops, name);
	if (length > 0 && length < MMU_PAGESIZE) {
		BOP_GETPROP(bootops, name, bop_staging_area);
		(void) ndi_prop_update_byte_array(DDI_DEV_T_NONE,
		    devi, name, bop_staging_area, length);
	}

	/*
	 * kdmconfig is also looking for display-type and
	 * video-adapter-type. We default to color and svga.
	 *
	 * Could it be "monochrome", "vga"?
	 * Nah, you've got to come to the 21st century...
	 * And you can set monitor type manually in kdmconfig
	 * if you are really an old junky.
	 */
	(void) ndi_prop_update_string(DDI_DEV_T_NONE,
	    devi, "display-type", "color");
	(void) ndi_prop_update_string(DDI_DEV_T_NONE,
	    devi, "video-adapter-type", "svga");

	name = "display-edif-id";
	length = BOP_GETPROPLEN(bootops, name);
	if (length > 0 && length < MMU_PAGESIZE) {
		BOP_GETPROP(bootops, name, bop_staging_area);
		copy_boot_str(bop_staging_area, property_val, length);
		(void) ndi_prop_update_string(DDI_DEV_T_NONE,
		    devi, name, property_val);
	}

	kmem_free(bop_staging_area, MMU_PAGESIZE);
}


/*
 * This is temporary, but absolutely necessary.  If we are being
 * booted with a device tree created by the DevConf project's bootconf
 * program, then we have device information nodes that reflect
 * reality.  At this point in time in the Solaris release schedule, the
 * kernel drivers aren't prepared for reality.  They still depend on their
 * own ad-hoc interpretations of the properties created when their .conf
 * files were interpreted. These drivers use an "ignore-hardware-nodes"
 * property to prevent them from using the nodes passed up from the bootconf
 * device tree.
 *
 * Trying to assemble root file system drivers as we are booting from
 * devconf will fail if the kernel driver is basing its name_addr's on the
 * psuedo-node device info while the bootpath passed up from bootconf is using
 * reality-based name_addrs.  We help the boot along in this case by
 * looking at the pre-bootconf bootpath and determining if we would have
 * successfully matched if that had been the bootpath we had chosen.
 *
 * Note that we only even perform this extra check if we've booted
 * using bootconf's 1275 compliant bootpath, this is the boot device, and
 * we're trying to match the name_addr specified in the 1275 bootpath.
 */

#define	MAXCOMPONENTLEN	32

int
x86_old_bootpath_name_addr_match(dev_info_t *cdip, char *caddr, char *naddr)
{
	/*
	 *  There are multiple criteria to be met before we can even
	 *  consider allowing a name_addr match here.
	 *
	 *  1) We must have been booted such that the bootconf program
	 *	created device tree nodes and properties.  This can be
	 *	determined by examining the 'bootpath' property.  This
	 *	property will be a non-null string iff bootconf was
	 *	involved in the boot.
	 *
	 *  2) The module that we want to match must be the boot device.
	 *
	 *  3) The instance of the module we are thinking of letting be
	 *	our match must be ignoring hardware nodes.
	 *
	 *  4) The name_addr we want to match must be the name_addr
	 *	specified in the 1275 bootpath.
	 */
	static char bootdev_module[MAXCOMPONENTLEN];
	static char bootdev_oldmod[MAXCOMPONENTLEN];
	static char bootdev_newaddr[MAXCOMPONENTLEN];
	static char bootdev_oldaddr[MAXCOMPONENTLEN];
	static int  quickexit;

	char *daddr;
	int dlen;

	char	*lkupname;
	int	rv = DDI_FAILURE;

	if ((ddi_getlongprop(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
	    "devconf-addr", (caddr_t)&daddr, &dlen) == DDI_PROP_SUCCESS) &&
	    (ddi_getprop(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
	    "ignore-hardware-nodes", -1) != -1)) {
		if (strcmp(daddr, caddr) == 0) {
			return (DDI_SUCCESS);
		}
	}

	if (quickexit)
		return (rv);

	if (bootdev_module[0] == '\0') {
		char *addrp, *eoaddrp;
		char *busp, *modp, *atp;
		char *bp1275, *bp;
		int  bp1275len, bplen;

		bp1275 = bp = addrp = eoaddrp = busp = modp = atp = NULL;

		if (ddi_getlongprop(DDI_DEV_T_ANY,
		    ddi_root_node(), 0, "bootpath",
		    (caddr_t)&bp1275, &bp1275len) != DDI_PROP_SUCCESS ||
		    bp1275len <= 1) {
			/*
			 * We didn't boot from bootconf so we never need to
			 * do any special matches.
			 */
			quickexit = 1;
			if (bp1275)
				kmem_free(bp1275, bp1275len);
			return (rv);
		}

		if (ddi_getlongprop(DDI_DEV_T_ANY,
		    ddi_root_node(), 0, "boot-path",
		    (caddr_t)&bp, &bplen) != DDI_PROP_SUCCESS || bplen <= 1) {
			/*
			 * No fallback position for matching. This is
			 * certainly unexpected, but we'll handle it
			 * just in case.
			 */
			quickexit = 1;
			kmem_free(bp1275, bp1275len);
			if (bp)
				kmem_free(bp, bplen);
			return (rv);
		}

		/*
		 *  Determine boot device module and 1275 name_addr
		 *
		 *  bootpath assumed to be of the form /bus/module@name_addr
		 */
		if (busp = strchr(bp1275, '/')) {
			if (modp = strchr(busp + 1, '/')) {
				if (atp = strchr(modp + 1, '@')) {
					*atp = '\0';
					addrp = atp + 1;
					if (eoaddrp = strchr(addrp, '/'))
						*eoaddrp = '\0';
				}
			}
		}

		if (modp && addrp) {
			(void) strncpy(bootdev_module, modp + 1,
			    MAXCOMPONENTLEN);
			bootdev_module[MAXCOMPONENTLEN - 1] = '\0';

			(void) strncpy(bootdev_newaddr, addrp, MAXCOMPONENTLEN);
			bootdev_newaddr[MAXCOMPONENTLEN - 1] = '\0';
		} else {
			quickexit = 1;
			kmem_free(bp1275, bp1275len);
			kmem_free(bp, bplen);
			return (rv);
		}

		/*
		 *  Determine fallback name_addr
		 *
		 *  10/3/96 - Also save fallback module name because it
		 *  might actually be different than the current module
		 *  name.  E.G., ISA pnp drivers have new names.
		 *
		 *  bootpath assumed to be of the form /bus/module@name_addr
		 */
		addrp = NULL;
		if (busp = strchr(bp, '/')) {
			if (modp = strchr(busp + 1, '/')) {
				if (atp = strchr(modp + 1, '@')) {
					*atp = '\0';
					addrp = atp + 1;
					if (eoaddrp = strchr(addrp, '/'))
						*eoaddrp = '\0';
				}
			}
		}

		if (modp && addrp) {
			(void) strncpy(bootdev_oldmod, modp + 1,
			    MAXCOMPONENTLEN);
			bootdev_module[MAXCOMPONENTLEN - 1] = '\0';

			(void) strncpy(bootdev_oldaddr, addrp, MAXCOMPONENTLEN);
			bootdev_oldaddr[MAXCOMPONENTLEN - 1] = '\0';
		}

		/* Free up the bootpath storage now that we're done with it. */
		kmem_free(bp1275, bp1275len);
		kmem_free(bp, bplen);

		if (bootdev_oldaddr[0] == '\0') {
			quickexit = 1;
			return (rv);
		}
	}

	if (((lkupname = ddi_get_name(cdip)) != NULL) &&
	    (strcmp(bootdev_module, lkupname) == 0 ||
	    strcmp(bootdev_oldmod, lkupname) == 0) &&
	    ((ddi_getprop(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
	    "ignore-hardware-nodes", -1) != -1) ||
	    ignore_hardware_nodes) &&
	    strcmp(bootdev_newaddr, caddr) == 0 &&
	    strcmp(bootdev_oldaddr, naddr) == 0) {
		rv = DDI_SUCCESS;
	}

	return (rv);
}

/*
 * Perform a copy from a memory mapped device (whose devinfo pointer is devi)
 * separately mapped at devaddr in the kernel to a kernel buffer at kaddr.
 */
/*ARGSUSED*/
int
e_ddi_copyfromdev(dev_info_t *devi,
    off_t off, const void *devaddr, void *kaddr, size_t len)
{
	bcopy(devaddr, kaddr, len);
	return (0);
}

/*
 * Perform a copy to a memory mapped device (whose devinfo pointer is devi)
 * separately mapped at devaddr in the kernel from a kernel buffer at kaddr.
 */
/*ARGSUSED*/
int
e_ddi_copytodev(dev_info_t *devi,
    off_t off, const void *kaddr, void *devaddr, size_t len)
{
	bcopy(kaddr, devaddr, len);
	return (0);
}


static int
poke_mem(peekpoke_ctlops_t *in_args)
{
	int err = DDI_SUCCESS;
	on_trap_data_t otd;

	/* Set up protected environment. */
	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		switch (in_args->size) {
		case sizeof (uint8_t):
			*(uint8_t *)(in_args->dev_addr) =
			    *(uint8_t *)in_args->host_addr;
			break;

		case sizeof (uint16_t):
			*(uint16_t *)(in_args->dev_addr) =
			    *(uint16_t *)in_args->host_addr;
			break;

		case sizeof (uint32_t):
			*(uint32_t *)(in_args->dev_addr) =
			    *(uint32_t *)in_args->host_addr;
			break;

		case sizeof (uint64_t):
			*(uint64_t *)(in_args->dev_addr) =
			    *(uint64_t *)in_args->host_addr;
			break;

		default:
			err = DDI_FAILURE;
			break;
		}
	} else
		err = DDI_FAILURE;

	/* Take down protected environment. */
	no_trap();

	return (err);
}


static int
peek_mem(peekpoke_ctlops_t *in_args)
{
	int err = DDI_SUCCESS;
	on_trap_data_t otd;

	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		switch (in_args->size) {
		case sizeof (uint8_t):
			*(uint8_t *)in_args->host_addr =
			    *(uint8_t *)in_args->dev_addr;
			break;

		case sizeof (uint16_t):
			*(uint16_t *)in_args->host_addr =
			    *(uint16_t *)in_args->dev_addr;
			break;

		case sizeof (uint32_t):
			*(uint32_t *)in_args->host_addr =
			    *(uint32_t *)in_args->dev_addr;
			break;

		case sizeof (uint64_t):
			*(uint64_t *)in_args->host_addr =
			    *(uint64_t *)in_args->dev_addr;
			break;

		default:
			err = DDI_FAILURE;
			break;
		}
	} else
		err = DDI_FAILURE;

	no_trap();
	return (err);
}


/*
 * This is called only to process peek/poke when the DIP is NULL.
 * Assume that this is for memory, as nexi take care of device safe accesses.
 */
int
peekpoke_mem(ddi_ctl_enum_t cmd, peekpoke_ctlops_t *in_args)
{
	return (cmd == DDI_CTLOPS_PEEK ? peek_mem(in_args) : poke_mem(in_args));
}

/*
 * we've just done a cautious put/get. Check if it was successful by
 * calling pci_ereport_post() on all puts and for any gets that return -1
 */
static int
pci_peekpoke_check_fma(dev_info_t *dip, void *arg, ddi_ctl_enum_t ctlop,
    void (*scan)(dev_info_t *, ddi_fm_error_t *))
{
	int	rval = DDI_SUCCESS;
	peekpoke_ctlops_t *in_args = (peekpoke_ctlops_t *)arg;
	ddi_fm_error_t de;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)in_args->handle;
	ddi_acc_hdl_t *hdlp = (ddi_acc_hdl_t *)in_args->handle;
	int check_err = 0;
	int repcount = in_args->repcount;

	if (ctlop == DDI_CTLOPS_POKE &&
	    hdlp->ah_acc.devacc_attr_access != DDI_CAUTIOUS_ACC)
		return (DDI_SUCCESS);

	if (ctlop == DDI_CTLOPS_PEEK &&
	    hdlp->ah_acc.devacc_attr_access != DDI_CAUTIOUS_ACC) {
		for (; repcount; repcount--) {
			switch (in_args->size) {
			case sizeof (uint8_t):
				if (*(uint8_t *)in_args->host_addr == 0xff)
					check_err = 1;
				break;
			case sizeof (uint16_t):
				if (*(uint16_t *)in_args->host_addr == 0xffff)
					check_err = 1;
				break;
			case sizeof (uint32_t):
				if (*(uint32_t *)in_args->host_addr ==
				    0xffffffff)
					check_err = 1;
				break;
			case sizeof (uint64_t):
				if (*(uint64_t *)in_args->host_addr ==
				    0xffffffffffffffff)
					check_err = 1;
				break;
			}
		}
		if (check_err == 0)
			return (DDI_SUCCESS);
	}
	/*
	 * for a cautious put or get or a non-cautious get that returned -1 call
	 * io framework to see if there really was an error
	 */
	bzero(&de, sizeof (ddi_fm_error_t));
	de.fme_version = DDI_FME_VERSION;
	de.fme_ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (hdlp->ah_acc.devacc_attr_access == DDI_CAUTIOUS_ACC) {
		de.fme_flag = DDI_FM_ERR_EXPECTED;
		de.fme_acc_handle = in_args->handle;
	} else if (hdlp->ah_acc.devacc_attr_access == DDI_DEFAULT_ACC) {
		/*
		 * We only get here with DDI_DEFAULT_ACC for config space gets.
		 * Non-hardened drivers may be probing the hardware and
		 * expecting -1 returned. So need to treat errors on
		 * DDI_DEFAULT_ACC as DDI_FM_ERR_EXPECTED.
		 */
		de.fme_flag = DDI_FM_ERR_EXPECTED;
		de.fme_acc_handle = in_args->handle;
	} else {
		/*
		 * Hardened driver doing protected accesses shouldn't
		 * get errors unless there's a hardware problem. Treat
		 * as nonfatal if there's an error, but set UNEXPECTED
		 * so we raise ereports on any errors and potentially
		 * fault the device
		 */
		de.fme_flag = DDI_FM_ERR_UNEXPECTED;
	}
	(void) scan(dip, &de);
	if (hdlp->ah_acc.devacc_attr_access != DDI_DEFAULT_ACC &&
	    de.fme_status != DDI_FM_OK) {
		ndi_err_t *errp = (ndi_err_t *)hp->ahi_err;
		rval = DDI_FAILURE;
		errp->err_ena = de.fme_ena;
		errp->err_expected = de.fme_flag;
		errp->err_status = DDI_FM_NONFATAL;
	}
	return (rval);
}

/*
 * pci_peekpoke_check_nofma() is for when an error occurs on a register access
 * during pci_ereport_post(). We can't call pci_ereport_post() again or we'd
 * recurse, so assume all puts are OK and gets have failed if they return -1
 */
static int
pci_peekpoke_check_nofma(void *arg, ddi_ctl_enum_t ctlop)
{
	int rval = DDI_SUCCESS;
	peekpoke_ctlops_t *in_args = (peekpoke_ctlops_t *)arg;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)in_args->handle;
	ddi_acc_hdl_t *hdlp = (ddi_acc_hdl_t *)in_args->handle;
	int repcount = in_args->repcount;

	if (ctlop == DDI_CTLOPS_POKE)
		return (rval);

	for (; repcount; repcount--) {
		switch (in_args->size) {
		case sizeof (uint8_t):
			if (*(uint8_t *)in_args->host_addr == 0xff)
				rval = DDI_FAILURE;
			break;
		case sizeof (uint16_t):
			if (*(uint16_t *)in_args->host_addr == 0xffff)
				rval = DDI_FAILURE;
			break;
		case sizeof (uint32_t):
			if (*(uint32_t *)in_args->host_addr == 0xffffffff)
				rval = DDI_FAILURE;
			break;
		case sizeof (uint64_t):
			if (*(uint64_t *)in_args->host_addr ==
			    0xffffffffffffffff)
				rval = DDI_FAILURE;
			break;
		}
	}
	if (hdlp->ah_acc.devacc_attr_access != DDI_DEFAULT_ACC &&
	    rval == DDI_FAILURE) {
		ndi_err_t *errp = (ndi_err_t *)hp->ahi_err;
		errp->err_ena = fm_ena_generate(0, FM_ENA_FMT1);
		errp->err_expected = DDI_FM_ERR_UNEXPECTED;
		errp->err_status = DDI_FM_NONFATAL;
	}
	return (rval);
}

int
pci_peekpoke_check(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result,
    int (*handler)(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *,
    void *), kmutex_t *err_mutexp, kmutex_t *peek_poke_mutexp,
    void (*scan)(dev_info_t *, ddi_fm_error_t *))
{
	int rval;
	peekpoke_ctlops_t *in_args = (peekpoke_ctlops_t *)arg;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)in_args->handle;

	/*
	 * this function only supports cautious accesses, not peeks/pokes
	 * which don't have a handle
	 */
	if (hp == NULL)
		return (DDI_FAILURE);

	if (hp->ahi_acc_attr & DDI_ACCATTR_CONFIG_SPACE) {
		if (!mutex_tryenter(err_mutexp)) {
			/*
			 * As this may be a recursive call from within
			 * pci_ereport_post() we can't wait for the mutexes.
			 * Fortunately we know someone is already calling
			 * pci_ereport_post() which will handle the error bits
			 * for us, and as this is a config space access we can
			 * just do the access and check return value for -1
			 * using pci_peekpoke_check_nofma().
			 */
			rval = handler(dip, rdip, ctlop, arg, result);
			if (rval == DDI_SUCCESS)
				rval = pci_peekpoke_check_nofma(arg, ctlop);
			return (rval);
		}
		/*
		 * This can't be a recursive call. Drop the err_mutex and get
		 * both mutexes in the right order. If an error hasn't already
		 * been detected by the ontrap code, use pci_peekpoke_check_fma
		 * which will call pci_ereport_post() to check error status.
		 */
		mutex_exit(err_mutexp);
	}
	mutex_enter(peek_poke_mutexp);
	rval = handler(dip, rdip, ctlop, arg, result);
	if (rval == DDI_SUCCESS) {
		mutex_enter(err_mutexp);
		rval = pci_peekpoke_check_fma(dip, arg, ctlop, scan);
		mutex_exit(err_mutexp);
	}
	mutex_exit(peek_poke_mutexp);
	return (rval);
}

void
impl_setup_ddi(void)
{
#if !defined(__xpv)
	extern void startup_bios_disk(void);
	extern int post_fastreboot;
#endif
	dev_info_t *xdip, *isa_dip;
	rd_existing_t rd_mem_prop;
	int err;

	ndi_devi_alloc_sleep(ddi_root_node(), "ramdisk",
	    (pnode_t)DEVI_SID_NODEID, &xdip);

	(void) BOP_GETPROP(bootops,
	    "ramdisk_start", (void *)&ramdisk_start);
	(void) BOP_GETPROP(bootops,
	    "ramdisk_end", (void *)&ramdisk_end);

#ifdef __xpv
	ramdisk_start -= ONE_GIG;
	ramdisk_end -= ONE_GIG;
#endif
	rd_mem_prop.phys = ramdisk_start;
	rd_mem_prop.size = ramdisk_end - ramdisk_start + 1;

	(void) ndi_prop_update_byte_array(DDI_DEV_T_NONE, xdip,
	    RD_EXISTING_PROP_NAME, (uchar_t *)&rd_mem_prop,
	    sizeof (rd_mem_prop));
	err = ndi_devi_bind_driver(xdip, 0);
	ASSERT(err == 0);

	/* isa node */
	if (pseudo_isa) {
		ndi_devi_alloc_sleep(ddi_root_node(), "isa",
		    (pnode_t)DEVI_SID_NODEID, &isa_dip);
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, isa_dip,
		    "device_type", "isa");
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, isa_dip,
		    "bus-type", "isa");
		(void) ndi_devi_bind_driver(isa_dip, 0);
	}

	/*
	 * Read in the properties from the boot.
	 */
	get_boot_properties();

	/* not framebuffer should be enumerated, if present */
	get_vga_properties();

	/*
	 * Check for administratively disabled drivers.
	 */
	check_driver_disable();

#if !defined(__xpv)
	if (!post_fastreboot)
		startup_bios_disk();
#endif
	/* do bus dependent probes. */
	impl_bus_initialprobe();
}

dev_t
getrootdev(void)
{
	/*
	 * Precedence given to rootdev if set in /etc/system
	 */
	if (root_is_svm == B_TRUE) {
		return (ddi_pathname_to_dev_t(svm_bootpath));
	}

	/*
	 * Usually rootfs.bo_name is initialized by the
	 * the bootpath property from bootenv.rc, but
	 * defaults to "/ramdisk:a" otherwise.
	 */
	return (ddi_pathname_to_dev_t(rootfs.bo_name));
}

static struct bus_probe {
	struct bus_probe *next;
	void (*probe)(int);
} *bus_probes;

void
impl_bus_add_probe(void (*func)(int))
{
	struct bus_probe *probe;
	struct bus_probe *lastprobe = NULL;

	probe = kmem_alloc(sizeof (*probe), KM_SLEEP);
	probe->probe = func;
	probe->next = NULL;

	if (!bus_probes) {
		bus_probes = probe;
		return;
	}

	lastprobe = bus_probes;
	while (lastprobe->next)
		lastprobe = lastprobe->next;
	lastprobe->next = probe;
}

/*ARGSUSED*/
void
impl_bus_delete_probe(void (*func)(int))
{
	struct bus_probe *prev = NULL;
	struct bus_probe *probe = bus_probes;

	while (probe) {
		if (probe->probe == func)
			break;
		prev = probe;
		probe = probe->next;
	}

	if (probe == NULL)
		return;

	if (prev)
		prev->next = probe->next;
	else
		bus_probes = probe->next;

	kmem_free(probe, sizeof (struct bus_probe));
}

/*
 * impl_bus_initialprobe
 *	Modload the prom simulator, then let it probe to verify existence
 *	and type of PCI support.
 */
static void
impl_bus_initialprobe(void)
{
	struct bus_probe *probe;

	/* load modules to install bus probes */
#if defined(__xpv)
	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		if (modload("misc", "pci_autoconfig") < 0) {
			panic("failed to load misc/pci_autoconfig");
		}

		if (modload("drv", "isa") < 0)
			panic("failed to load drv/isa");
	}

	(void) modload("misc", "xpv_autoconfig");
#else
	if (modload("misc", "pci_autoconfig") < 0) {
		panic("failed to load misc/pci_autoconfig");
	}

	(void) modload("misc", "acpidev");

	if (modload("drv", "isa") < 0)
		panic("failed to load drv/isa");
#endif

	probe = bus_probes;
	while (probe) {
		/* run the probe functions */
		(*probe->probe)(0);
		probe = probe->next;
	}
}

/*
 * impl_bus_reprobe
 *	Reprogram devices not set up by firmware.
 */
static void
impl_bus_reprobe(void)
{
	struct bus_probe *probe;

	probe = bus_probes;
	while (probe) {
		/* run the probe function */
		(*probe->probe)(1);
		probe = probe->next;
	}
}


/*
 * The following functions ready a cautious request to go up to the nexus
 * driver.  It is up to the nexus driver to decide how to process the request.
 * It may choose to call i_ddi_do_caut_get/put in this file, or do it
 * differently.
 */

static void
i_ddi_caut_getput_ctlops(ddi_acc_impl_t *hp, uint64_t host_addr,
    uint64_t dev_addr, size_t size, size_t repcount, uint_t flags,
    ddi_ctl_enum_t cmd)
{
	peekpoke_ctlops_t	cautacc_ctlops_arg;

	cautacc_ctlops_arg.size = size;
	cautacc_ctlops_arg.dev_addr = dev_addr;
	cautacc_ctlops_arg.host_addr = host_addr;
	cautacc_ctlops_arg.handle = (ddi_acc_handle_t)hp;
	cautacc_ctlops_arg.repcount = repcount;
	cautacc_ctlops_arg.flags = flags;

	(void) ddi_ctlops(hp->ahi_common.ah_dip, hp->ahi_common.ah_dip, cmd,
	    &cautacc_ctlops_arg, NULL);
}

uint8_t
i_ddi_caut_get8(ddi_acc_impl_t *hp, uint8_t *addr)
{
	uint8_t value;
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint8_t), 1, 0, DDI_CTLOPS_PEEK);

	return (value);
}

uint16_t
i_ddi_caut_get16(ddi_acc_impl_t *hp, uint16_t *addr)
{
	uint16_t value;
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint16_t), 1, 0, DDI_CTLOPS_PEEK);

	return (value);
}

uint32_t
i_ddi_caut_get32(ddi_acc_impl_t *hp, uint32_t *addr)
{
	uint32_t value;
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint32_t), 1, 0, DDI_CTLOPS_PEEK);

	return (value);
}

uint64_t
i_ddi_caut_get64(ddi_acc_impl_t *hp, uint64_t *addr)
{
	uint64_t value;
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint64_t), 1, 0, DDI_CTLOPS_PEEK);

	return (value);
}

void
i_ddi_caut_put8(ddi_acc_impl_t *hp, uint8_t *addr, uint8_t value)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint8_t), 1, 0, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_put16(ddi_acc_impl_t *hp, uint16_t *addr, uint16_t value)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint16_t), 1, 0, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_put32(ddi_acc_impl_t *hp, uint32_t *addr, uint32_t value)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint32_t), 1, 0, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_put64(ddi_acc_impl_t *hp, uint64_t *addr, uint64_t value)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)&value, (uintptr_t)addr,
	    sizeof (uint64_t), 1, 0, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_rep_get8(ddi_acc_impl_t *hp, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint8_t), repcount, flags, DDI_CTLOPS_PEEK);
}

void
i_ddi_caut_rep_get16(ddi_acc_impl_t *hp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint16_t), repcount, flags, DDI_CTLOPS_PEEK);
}

void
i_ddi_caut_rep_get32(ddi_acc_impl_t *hp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint32_t), repcount, flags, DDI_CTLOPS_PEEK);
}

void
i_ddi_caut_rep_get64(ddi_acc_impl_t *hp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint64_t), repcount, flags, DDI_CTLOPS_PEEK);
}

void
i_ddi_caut_rep_put8(ddi_acc_impl_t *hp, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint8_t), repcount, flags, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_rep_put16(ddi_acc_impl_t *hp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint16_t), repcount, flags, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_rep_put32(ddi_acc_impl_t *hp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint32_t), repcount, flags, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_rep_put64(ddi_acc_impl_t *hp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uintptr_t)host_addr, (uintptr_t)dev_addr,
	    sizeof (uint64_t), repcount, flags, DDI_CTLOPS_POKE);
}

boolean_t
i_ddi_copybuf_required(ddi_dma_attr_t *attrp)
{
	uint64_t hi_pa;

	hi_pa = ((uint64_t)physmax + 1ull) << PAGESHIFT;
	if (attrp->dma_attr_addr_hi < hi_pa) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

size_t
i_ddi_copybuf_size()
{
	return (dma_max_copybuf_size);
}

/*
 * i_ddi_dma_max()
 *    returns the maximum DMA size which can be performed in a single DMA
 *    window taking into account the devices DMA contraints (attrp), the
 *    maximum copy buffer size (if applicable), and the worse case buffer
 *    fragmentation.
 */
/*ARGSUSED*/
uint32_t
i_ddi_dma_max(dev_info_t *dip, ddi_dma_attr_t *attrp)
{
	uint64_t maxxfer;


	/*
	 * take the min of maxxfer and the the worse case fragementation
	 * (e.g. every cookie <= 1 page)
	 */
	maxxfer = MIN(attrp->dma_attr_maxxfer,
	    ((uint64_t)(attrp->dma_attr_sgllen - 1) << PAGESHIFT));

	/*
	 * If the DMA engine can't reach all off memory, we also need to take
	 * the max size of the copybuf into consideration.
	 */
	if (i_ddi_copybuf_required(attrp)) {
		maxxfer = MIN(i_ddi_copybuf_size(), maxxfer);
	}

	/*
	 * we only return a 32-bit value. Make sure it's not -1. Round to a
	 * page so it won't be mistaken for an error value during debug.
	 */
	if (maxxfer >= 0xFFFFFFFF) {
		maxxfer = 0xFFFFF000;
	}

	/*
	 * make sure the value we return is a whole multiple of the
	 * granlarity.
	 */
	if (attrp->dma_attr_granular > 1) {
		maxxfer = maxxfer - (maxxfer % attrp->dma_attr_granular);
	}

	return ((uint32_t)maxxfer);
}

/*ARGSUSED*/
void
translate_devid(dev_info_t *dip)
{
}

pfn_t
i_ddi_paddr_to_pfn(paddr_t paddr)
{
	pfn_t pfn;

#ifdef __xpv
	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		pfn = xen_assign_pfn(mmu_btop(paddr));
	} else {
		pfn = mmu_btop(paddr);
	}
#else
	pfn = mmu_btop(paddr);
#endif

	return (pfn);
}
