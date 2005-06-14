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

#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/promif.h>
#include <sys/cpuvar.h>

#include <sys/pci/pci_regs.h>
#include <sys/pci/pci_obj.h>
#include <sys/hotplug/pci/pcihp.h>

#include <sys/pci/pci_tools_impl.h>
#include <sys/pci_tools.h>
#include <sys/pci_tools_var.h>

/*
 * Extract 64 bit parent or size values from 32 bit cells of
 * pci_ranges_t property.
 *
 * Only bits 42-32 are relevant in parent_high.
 */
#define	PCI_GET_RANGE_PROP(ranges, bank) \
	((((uint64_t)(ranges[bank].parent_high & 0x7ff)) << 32) | \
	ranges[bank].parent_low)

#define	PCI_GET_RANGE_PROP_SIZE(ranges, bank) \
	((((uint64_t)(ranges[bank].size_high)) << 32) | \
	ranges[bank].size_low)

/* Big and little endian as boolean values. */
#define	BE B_TRUE
#define	LE B_FALSE

#define	SUCCESS	0

/* Mechanism for getting offsets of smaller datatypes aligned in 64 bit long */
typedef union {
	uint64_t u64;
	uint32_t u32;
	uint16_t u16;
	uint8_t u8;
} peek_poke_value_t;

/*
 * Offsets of BARS in config space.  First entry of 0 means config space.
 * Entries here correlate to pcitool_bars_t enumerated type.
 */
static uint8_t pci_bars[] = {
	0x0,
	PCI_CONF_BASE0,
	PCI_CONF_BASE1,
	PCI_CONF_BASE2,
	PCI_CONF_BASE3,
	PCI_CONF_BASE4,
	PCI_CONF_BASE5,
	PCI_CONF_ROM
};

/*LINTLIBRARY*/

static int pci_safe_phys_peek(pci_t *, boolean_t, size_t, uint64_t, uint64_t *);
static int pci_safe_phys_poke(pci_t *, boolean_t, size_t, uint64_t, uint64_t);
static int pci_validate_cpuid(uint32_t);
static uint8_t ib_get_ino_devs(ib_t *ib_p, uint32_t ino, uint8_t *devs_ret,
    pcitool_intr_dev_t *devs);
static int pci_access(pci_t *, uint64_t, uint64_t, uint64_t *,
    uint8_t, boolean_t, boolean_t, uint32_t *);
static int pcitool_intr_get_max_ino(uint32_t *, int);
static int pcitool_get_intr(dev_info_t *, void *, int, pci_t *);
static int pcitool_set_intr(dev_info_t *, void *, int, pci_t *);

extern int pci_do_phys_peek(size_t, uint64_t, uint64_t *, int);
extern int pci_do_phys_poke(size_t, uint64_t, uint64_t *, int);

/*
 * Safe C wrapper around assy language routine pci_do_phys_peek
 *
 * Type is TRUE for big endian, FALSE for little endian.
 * Size is 1, 2, 4 or 8 bytes.
 * paddr is the physical address in IO space to access read.
 * value_p is where the value is returned.
 */
static int
pci_safe_phys_peek(pci_t *pci_p, boolean_t type, size_t size, uint64_t paddr,
    uint64_t *value_p)
{
	on_trap_data_t otd;
	int err = DDI_SUCCESS;
	peek_poke_value_t peek_value;	/* XXX Take glbl data structure type. */

	pbm_t *pbm_p = pci_p->pci_pbm_p;

	pbm_p->pbm_ontrap_data = &otd;

	/* Set up trap handling to make the access safe. */

	/*
	 * on_trap works like setjmp.
	 * Set it up to not panic on data access error,
	 * but to call peek_fault instead.
	 * Call pci_do_phys_peek after trap handling is setup.
	 * When on_trap returns FALSE, it has been setup.
	 * When it returns TRUE, an it has caught an error.
	 */
	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		otd.ot_trampoline = (uintptr_t)&peek_fault;
		err = pci_do_phys_peek(size, paddr, &peek_value.u64, type);
	} else {
		err = DDI_FAILURE;
	}

	pbm_p->pbm_ontrap_data = NULL;
	no_trap();

	if (err != DDI_FAILURE) {
		switch (size) {
		case 8:
			*value_p = (uint64_t)peek_value.u64;
			break;
		case 4:
			*value_p = (uint64_t)peek_value.u32;
			break;
		case 2:
			*value_p = (uint64_t)peek_value.u16;
			break;
		case 1:
			*value_p = (uint64_t)peek_value.u8;
			break;
		default:
			err = DDI_FAILURE;
		}
	}

	return (err);
}

/*
 * Safe C wrapper around assy language routine pci_do_phys_poke
 *
 * Type is TRUE for big endian, FALSE for little endian.
 * Size is 1,2,4 or 8 bytes.
 * paddr is the physical address in IO space to access read.
 * value contains the value to be written.
 */
static int
pci_safe_phys_poke(pci_t *pci_p, boolean_t type, size_t size, uint64_t paddr,
    uint64_t value)
{
	on_trap_data_t otd;
	int err = DDI_SUCCESS;
	peek_poke_value_t poke_value;

	pbm_t *pbm_p = pci_p->pci_pbm_p;

	switch (size) {
	case 8:
		poke_value.u64 = value;
		break;
	case 4:
		poke_value.u32 = (uint32_t)value;
		break;
	case 2:
		poke_value.u16 = (uint16_t)value;
		break;
	case 1:
		poke_value.u8 = (uint8_t)value;
		break;
	default:
		return (DDI_FAILURE);
	}

	mutex_enter(&pbm_p->pbm_pokefault_mutex);

	pbm_p->pbm_ontrap_data = &otd;

	/*
	 * on_trap works like setjmp.
	 * Set it up to not panic on data access error,
	 * but to call poke_fault instead.
	 * Call pci_do_phys_poke after trap handling is setup.
	 * When on_trap returns FALSE, it has been setup.
	 * When it returns TRUE, an it has caught an error.
	 */
	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		otd.ot_trampoline = (uintptr_t)&poke_fault;
		err = pci_do_phys_poke(size, paddr, &poke_value.u64, type);
	}

	/* Let the dust settle and errors occur if they will. */
	pbm_clear_error(pbm_p);

	/* Check for an error. */
	if (otd.ot_trap == OT_DATA_ACCESS) {
		err = DDI_FAILURE;
	}

	pbm_p->pbm_ontrap_data = NULL;
	mutex_exit(&pbm_p->pbm_pokefault_mutex);

	no_trap();
	return (err);
}


/*
 * Validate the cpu_id passed in.
 * A value of 1 will be returned for success and zero for failure.
 */
static int
pci_validate_cpuid(uint32_t cpu_id)
{
	extern cpu_t	*cpu[NCPU];
	int rval = 1;

	ASSERT(mutex_owned(&cpu_lock));

	if (cpu_id >= NCPU) {
		rval = 0;

	} else if (cpu[cpu_id] == NULL) {
		rval = 0;

	} else if (!(cpu_is_online(cpu[cpu_id]))) {
		rval = 0;
	}

	return (rval);
}


/*
 * Return the dips or number of dips associated with a given interrupt block.
 * Size of dips array arg is passed in as dips_ret arg.
 * Number of dips returned is returned in dips_ret arg.
 * Array of dips gets returned in the dips argument.
 * Function returns number of dips existing for the given interrupt block.
 *
 */
uint8_t
ib_get_ino_devs(
    ib_t *ib_p, uint32_t ino, uint8_t *devs_ret, pcitool_intr_dev_t *devs)
{
	ib_ino_info_t *ino_p;
	ih_t *ih_p;
	uint32_t num_devs = 0;
	int i;

	mutex_enter(&ib_p->ib_ino_lst_mutex);
	ino_p = ib_locate_ino(ib_p, ino);
	if (ino_p != NULL) {
		num_devs = ino_p->ino_ih_size;
		for (i = 0, ih_p = ino_p->ino_ih_head;
		    ((i < ino_p->ino_ih_size) && (i < *devs_ret));
		    i++, ih_p = ih_p->ih_next) {
		    (void) strncpy(devs[i].driver_name,
			    ddi_driver_name(ih_p->ih_dip), MAXMODCONFNAME-1);
			devs[i].driver_name[MAXMODCONFNAME] = '\0';
			(void) ddi_pathname(ih_p->ih_dip, devs[i].path);
			devs[i].dev_inst = ddi_get_instance(ih_p->ih_dip);
		}
		*devs_ret = i;
	}

	mutex_exit(&ib_p->ib_ino_lst_mutex);

	return (num_devs);
}


/* Return the number of interrupts on a pci bus. */
static int
pcitool_intr_get_max_ino(uint32_t *arg, int mode)
{
	uint32_t num_intr = PCI_MAX_INO;

	if (ddi_copyout(&num_intr, arg, sizeof (uint32_t), mode) !=
	    DDI_SUCCESS) {
		return (EFAULT);
	} else {
		return (SUCCESS);
	}
}


/*
 * Get interrupt information for a given ino.
 * Returns info only for inos mapped to devices.
 *
 * Returned info is valid only when iget.num_devs is returned > 0.
 * If ino is not enabled or is not mapped to a device, num_devs will be = 0.
 */
/*ARGSUSED*/
static int
pcitool_get_intr(dev_info_t *dip, void *arg, int mode, pci_t *pci_p)
{
	/* Array part isn't used here, but oh well... */
	pcitool_intr_get_t partial_iget;
	pcitool_intr_get_t *iget = &partial_iget;
	size_t	iget_kmem_alloc_size = 0;
	ib_t *ib_p = pci_p->pci_ib_p;
	volatile uint64_t *imregp;
	uint64_t imregval;
	uint32_t ino;
	uint8_t num_devs_ret;
	int copyout_rval;
	int rval = SUCCESS;

	/* Read in just the header part, no array section. */
	if (ddi_copyin(arg, &partial_iget, PCITOOL_IGET_SIZE(0), mode) !=
	    DDI_SUCCESS) {

		return (EFAULT);
	}

	ino = partial_iget.ino;
	num_devs_ret = partial_iget.num_devs_ret;

	/* Validate argument. */
	if (ino > PCI_MAX_INO) {
		partial_iget.status = PCITOOL_INVALID_INO;
		partial_iget.num_devs_ret = 0;
		rval = EINVAL;
		goto done_get_intr;
	}

	/* Caller wants device information returned. */
	if (num_devs_ret > 0) {

		/*
		 * Allocate room.
		 * Note if num_devs_ret == 0 iget remains pointing to
		 * partial_iget.
		 */
		iget_kmem_alloc_size = PCITOOL_IGET_SIZE(num_devs_ret);
		iget = kmem_alloc(iget_kmem_alloc_size, KM_SLEEP);

		/* Read in whole structure to verify there's room. */
		if (ddi_copyin(arg, iget, iget_kmem_alloc_size, mode) !=
		    SUCCESS) {

			/* Be consistent and just return EFAULT here. */
			kmem_free(iget, iget_kmem_alloc_size);

			return (EFAULT);
		}
	}

	bzero(iget, PCITOOL_IGET_SIZE(num_devs_ret));
	iget->ino = ino;
	iget->num_devs_ret = num_devs_ret;

	imregp = ib_intr_map_reg_addr(ib_p, ino);
	imregval = *imregp;

	/*
	 * Read "valid" bit.  If set, interrupts are enabled.
	 * This bit happens to be the same on Fire and Tomatillo.
	 */
	if (imregval & COMMON_INTR_MAP_REG_VALID) {

		/*
		 * The following looks up the ib_ino_info and returns
		 * info of devices mapped to this ino.
		 */
		iget->num_devs = ib_get_ino_devs(
		    ib_p, ino, &iget->num_devs_ret, iget->dev);

		/*
		 * Consider only inos mapped to devices (as opposed to
		 * inos mapped to the bridge itself.
		 */
		if (iget->num_devs > 0) {

			/*
			 * These 2 items are platform specific,
			 * extracted from the bridge.
			 */
			iget->ctlr = 0;
			iget->cpu_id =
			    (imregval & COMMON_INTR_MAP_REG_TID) >>
			    COMMON_INTR_MAP_REG_TID_SHIFT;
		}
	}
done_get_intr:
	iget->drvr_version = PCITOOL_DRVR_VERSION;
	copyout_rval = ddi_copyout(iget, arg,
	    PCITOOL_IGET_SIZE(num_devs_ret), mode);

	if (iget_kmem_alloc_size > 0) {
		kmem_free(iget, iget_kmem_alloc_size);
	}

	if (copyout_rval != DDI_SUCCESS) {
		rval = EFAULT;
	}

	return (rval);
}


/*
 * Associate a new CPU with a given ino.
 *
 * Operate only on inos which are already mapped to devices.
 */
static int
pcitool_set_intr(dev_info_t *dip, void *arg, int mode, pci_t *pci_p)
{
	uint8_t zero = 0;
	pcitool_intr_set_t iset;
	uint32_t old_cpu_id;
	hrtime_t start_time;
	ib_t *ib_p = pci_p->pci_ib_p;
	uint64_t imregval;
	uint64_t new_imregval;
	volatile uint64_t *imregp;
	volatile uint64_t *idregp;
	int rval = SUCCESS;

	if (ddi_copyin(arg, &iset, sizeof (pcitool_intr_set_t), mode) !=
	    DDI_SUCCESS) {

		return (EFAULT);
	}

	/* Validate input argument. */
	if (iset.ino > PCI_MAX_INO) {
		iset.status = PCITOOL_INVALID_INO;
		rval = EINVAL;
		goto done_set_intr;
	}

	/* Validate that ino given belongs to a device. */
	if (ib_get_ino_devs(ib_p, iset.ino, &zero, NULL) == 0) {
		iset.status = PCITOOL_INVALID_INO;
		rval = EINVAL;
		goto done_set_intr;
	}

	imregp = (uint64_t *)ib_intr_map_reg_addr(ib_p, iset.ino);
	idregp = IB_INO_INTR_STATE_REG(ib_p, iset.ino);

	DEBUG4(DBG_TOOLS, dip, "set_intr: cpu:%d, ino:0x%x, mapreg @ "
	    "0x%llx, intr_stat @ 0x%llx\n",
	    iset.cpu_id, iset.ino, imregp, idregp);

	/* Save original mapreg value. */
	imregval = *imregp;

	DEBUG1(DBG_TOOLS, dip, "orig mapreg value: 0x%llx\n", imregval);

	/* Is this request a noop? */
	old_cpu_id = (imregval & COMMON_INTR_MAP_REG_TID) >>
		COMMON_INTR_MAP_REG_TID_SHIFT;
	if (old_cpu_id == iset.cpu_id) {
		iset.status = PCITOOL_SUCCESS;
		goto done_set_intr;
	}

	/* Operate only on inos which are already enabled. */
	if (!(imregval & COMMON_INTR_MAP_REG_VALID)) {
		iset.status = PCITOOL_INVALID_INO;
		rval = EINVAL;
		goto done_set_intr;
	}

	/* Clear the interrupt valid/enable bit for particular ino. */
	DEBUG0(DBG_TOOLS, dip, "Clearing intr_enabled...\n");
	*imregp = imregval & ~COMMON_INTR_MAP_REG_VALID;

	/* Wait until there are no more pending interrupts. */
	start_time = gethrtime();

	DEBUG0(DBG_TOOLS, dip,
	    "About to check for pending interrupts...\n");

	while (IB_INO_INTR_PENDING(idregp, iset.ino)) {

		DEBUG0(DBG_TOOLS, dip, "Waiting for pending ints to clear\n");

		if ((gethrtime() - start_time) < pci_intrpend_timeout) {
			continue;

		/* Timed out waiting. */
		} else {
			iset.status = PCITOOL_PENDING_INTRTIMEOUT;
			rval = ETIME;
			goto done_set_intr;
		}
	}

	new_imregval = *imregp;

	DEBUG1(DBG_TOOLS, dip,
	    "after disabling intr, mapreg value: 0x%llx\n", new_imregval);

	/* Prepare new mapreg value with interrupts enabled and new cpu_id. */
	new_imregval = (new_imregval | COMMON_INTR_MAP_REG_VALID) &
	    ~COMMON_INTR_MAP_REG_TID;
	new_imregval |= (iset.cpu_id << COMMON_INTR_MAP_REG_TID_SHIFT);

	/*
	 * Get lock, validate cpu and write new mapreg value.
	 * Return original cpu value to caller via iset.cpu_id.
	 */
	mutex_enter(&cpu_lock);
	if (pci_validate_cpuid(iset.cpu_id)) {

		DEBUG1(DBG_TOOLS, dip, "Writing new mapreg value:0x%llx\n",
		    new_imregval);

		*imregp = new_imregval;
		mutex_exit(&cpu_lock);
		iset.cpu_id = old_cpu_id;
		iset.status = PCITOOL_SUCCESS;

	/* Invalid cpu.  Restore original register image. */
	} else {

		DEBUG0(DBG_TOOLS, dip,
		    "Invalid cpuid: writing orig mapreg value\n");

		*imregp = imregval;
		mutex_exit(&cpu_lock);
		iset.status = PCITOOL_INVALID_CPUID;
		rval = EINVAL;
	}
done_set_intr:
	iset.drvr_version = PCITOOL_DRVR_VERSION;
	if (ddi_copyout(&iset, arg, sizeof (pcitool_intr_set_t), mode) !=
	    DDI_SUCCESS) {
		rval = EFAULT;
	}

	return (rval);
}


/* Main function for handling interrupt CPU binding requests and queries. */
int
pcitool_intr_admn(dev_t dev, void *arg, int cmd, int mode)
{
	pci_t		*pci_p = DEV_TO_SOFTSTATE(dev);
	dev_info_t	*dip = pci_p->pci_dip;
	int		rval = SUCCESS;

	switch (cmd) {

	/* Return the number of interrupts supported by a PCI bus. */
	case PCITOOL_DEVICE_NUM_INTR:
		rval = pcitool_intr_get_max_ino(arg, mode);
		break;

	/* Get interrupt information for a given ino. */
	case PCITOOL_DEVICE_GET_INTR:
		rval = pcitool_get_intr(dip, arg, mode, pci_p);
		break;

	/* Associate a new CPU with a given ino. */
	case PCITOOL_DEVICE_SET_INTR:
		rval = pcitool_set_intr(dip, arg, mode, pci_p);
		break;

	default:
		rval = ENOTTY;
	}

	return (rval);
}


/*
 * Wrapper around pci_safe_phys_peek/poke.
 *
 * Validates arguments and calls pci_safe_phys_peek/poke appropriately.
 *
 * Dip is of the nexus,
 * phys_addr is the address to write in physical space,
 * max_addr is the upper bound on the physical space used for bounds checking,
 * pcitool_status returns more detailed status in addition to a more generic
 * errno-style function return value.
 * other args are self-explanatory.
 */
static int
pci_access(pci_t *pci_p, uint64_t phys_addr, uint64_t max_addr,
    uint64_t *data, uint8_t size, boolean_t write, boolean_t endian,
    uint32_t *pcitool_status)
{

	int rval = SUCCESS;
	dev_info_t *dip = pci_p->pci_dip;

	/* Upper bounds checking. */
	if (phys_addr > max_addr) {
		DEBUG2(DBG_TOOLS, dip,
		    "Phys addr 0x%llx out of range (max 0x%llx).\n",
		    phys_addr, max_addr);
		*pcitool_status = PCITOOL_INVALID_ADDRESS;

		rval = EINVAL;

	/* Alignment checking. */
	} else if (!IS_P2ALIGNED(phys_addr, size)) {
		DEBUG0(DBG_TOOLS, dip, "not aligned.\n");
		*pcitool_status = PCITOOL_NOT_ALIGNED;

		rval = EINVAL;

	/* Made it through checks.  Do the access. */
	} else if (write) {

		DEBUG3(DBG_PHYS_ACC, dip,
		    "%d byte %s pci_safe_phys_poke at addr 0x%llx\n",
		    size, (endian ? "BE" : "LE"), phys_addr);

		if (pci_safe_phys_poke(pci_p, endian, size, phys_addr, *data) !=
		    DDI_SUCCESS) {
			DEBUG3(DBG_PHYS_ACC, dip,
			    "%d byte %s pci_safe_phys_poke at addr "
			    "0x%llx failed\n",
			    size, (endian ? "BE" : "LE"), phys_addr);
			*pcitool_status = PCITOOL_INVALID_ADDRESS;

			rval = EFAULT;
		}

	/* Read */
	} else {

		DEBUG3(DBG_PHYS_ACC, dip,
		    "%d byte %s pci_safe_phys_peek at addr 0x%llx\n",
		    size, (endian ? "BE" : "LE"), phys_addr);

		if (pci_safe_phys_peek(pci_p, endian, size, phys_addr, data) !=
		    DDI_SUCCESS) {
			DEBUG3(DBG_PHYS_ACC, dip,
			    "%d byte %s pci_safe_phys_peek at addr "
			    "0x%llx failed\n",
			    size, (endian ? "BE" : "LE"), phys_addr);
			*pcitool_status = PCITOOL_INVALID_ADDRESS;

			rval = EFAULT;
		}
	}
	return (rval);
}

/*
 * Perform register accesses on the nexus device itself.
 */
int
pcitool_bus_reg_ops(dev_t dev, void *arg, int cmd, int mode)
{

	pci_t			*pci_p = DEV_TO_SOFTSTATE(dev);
	dev_info_t		*dip = pci_p->pci_dip;
	pci_nexus_regspec_t	*pci_rp;
	pcitool_reg_t		prg;
	uint64_t		base_addr;
	uint64_t		max_addr;
	uint32_t		reglen;
	uint32_t		numbanks = 0;
	uint8_t			size;
	uint32_t		rval = 0;
	boolean_t		write_flag = B_FALSE;

	switch (cmd) {
	case PCITOOL_NEXUS_SET_REG:
		write_flag = B_TRUE;

	/*FALLTHRU*/
	case PCITOOL_NEXUS_GET_REG:
		DEBUG0(DBG_TOOLS, dip,
		    "pcitool_bus_reg_ops nexus set/get reg\n");

		/* Read data from userland. */
		if (ddi_copyin(arg, &prg, sizeof (pcitool_reg_t), mode) !=
		    DDI_SUCCESS) {
			DEBUG0(DBG_TOOLS, dip, "Error reading arguments\n");
			return (EFAULT);
		}

		/*
		 * Read reg property which contains starting addr
		 * and size of banks.
		 */
		if (ddi_prop_lookup_int_array(
		    DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "reg", (int **)&pci_rp, &reglen) == DDI_SUCCESS) {
			if (((reglen * sizeof (int)) %
			    sizeof (pci_nexus_regspec_t)) != 0) {
				DEBUG0(DBG_TOOLS, dip,
				    "reg prop not well-formed");
				prg.status = PCITOOL_REGPROP_NOTWELLFORMED;
				rval = EIO;
				goto done;
			}
		}

		numbanks =
		    (reglen * sizeof (int)) / sizeof (pci_nexus_regspec_t);

		/* Bounds check the bank number. */
		if (prg.barnum >= numbanks) {
			prg.status = PCITOOL_OUT_OF_RANGE;
			rval = EINVAL;
			goto done;
		}

		size = PCITOOL_ACC_ATTR_SIZE(prg.acc_attr);
		base_addr = pci_rp[prg.barnum].phys_addr;
		max_addr = base_addr + pci_rp[prg.barnum].size;
		prg.phys_addr = base_addr + prg.offset;

		DEBUG4(DBG_TOOLS, dip,
		    "pcitool_bus_reg_ops: nexus: base:0x%llx, offset:0x%llx, "
		    "addr:0x%llx, max_addr:0x%llx\n",
		    base_addr, prg.offset, prg.phys_addr, max_addr);

		/* Access device.  prg.status is modified. */
		rval = pci_access(pci_p,
		    prg.phys_addr, max_addr, &prg.data, size, write_flag,
		    PCITOOL_ACC_IS_BIG_ENDIAN(prg.acc_attr),	/* BE/LE */
		    &prg.status);

		break;

	default:
		return (ENOTTY);
	}

done:
	prg.drvr_version = PCITOOL_DRVR_VERSION;
	if (ddi_copyout(&prg, arg, sizeof (pcitool_reg_t), mode) !=
	    DDI_SUCCESS) {
		DEBUG0(DBG_TOOLS, dip, "Copyout failed.\n");
		return (EFAULT);
	}

	return (rval);
}


/* Perform register accesses on PCI leaf devices. */
int
pcitool_dev_reg_ops(dev_t dev, void *arg, int cmd, int mode)
{
	pci_t		*pci_p = DEV_TO_SOFTSTATE(dev);
	dev_info_t	*dip = pci_p->pci_dip;
	pci_ranges_t	*rp = pci_p->pci_ranges;
	pcitool_reg_t	prg;
	uint64_t	max_addr;
	uint64_t	base_addr;
	uint64_t	range_prop;
	uint64_t	range_prop_size;
	uint64_t	bar = 0;
	int		rval = 0;
	boolean_t	write_flag = B_FALSE;
	uint8_t		size;
	uint8_t		bar_offset;

	switch (cmd) {
	case (PCITOOL_DEVICE_SET_REG):
		write_flag = B_TRUE;

	/*FALLTHRU*/
	case (PCITOOL_DEVICE_GET_REG):
		DEBUG0(DBG_TOOLS, dip, "pcitool_dev_reg_ops set/get reg\n");
		if (ddi_copyin(arg, &prg, sizeof (pcitool_reg_t), mode) !=
		    DDI_SUCCESS) {
			DEBUG0(DBG_TOOLS, dip,
			    "Error reading arguments\n");
			return (EFAULT);
		}

		if (prg.barnum >= (sizeof (pci_bars) / sizeof (pci_bars[0]))) {
			prg.status = PCITOOL_OUT_OF_RANGE;
			rval = EINVAL;
			goto done_reg;
		}

		DEBUG3(DBG_TOOLS, dip, "raw bus:0x%x, dev:0x%x, func:0x%x\n",
		    prg.bus_no, prg.dev_no, prg.func_no);

		/* Validate address arguments of bus / dev / func */
		if (((prg.bus_no &
		    (PCI_REG_BUS_M >> PCI_REG_BUS_SHIFT)) !=
		    prg.bus_no) ||
		    ((prg.dev_no &
		    (PCI_REG_DEV_M >> PCI_REG_DEV_SHIFT)) !=
		    prg.dev_no) ||
		    ((prg.func_no &
		    (PCI_REG_FUNC_M >> PCI_REG_FUNC_SHIFT)) !=
		    prg.func_no)) {
			prg.status = PCITOOL_INVALID_ADDRESS;
			rval = EINVAL;
			goto done_reg;
		}

		size = PCITOOL_ACC_ATTR_SIZE(prg.acc_attr);

		/* Get config space first. */
		range_prop = PCI_GET_RANGE_PROP(rp, PCI_CONFIG_RANGE_BANK);
		range_prop_size =
		    PCI_GET_RANGE_PROP_SIZE(rp, PCI_CONFIG_RANGE_BANK);
		max_addr = range_prop + range_prop_size;

		/*
		 * Build device address based on base addr from range prop, and
		 * bus, dev and func values passed in.  This address is where
		 * config space begins.
		 */
		base_addr = range_prop +
		    (prg.bus_no << PCI_REG_BUS_SHIFT) +
		    (prg.dev_no << PCI_REG_DEV_SHIFT) +
		    (prg.func_no << PCI_REG_FUNC_SHIFT);

		if ((base_addr < range_prop) || (base_addr >= max_addr)) {
			prg.status = PCITOOL_OUT_OF_RANGE;
			rval = EINVAL;
			goto done_reg;
		}

		DEBUG5(DBG_TOOLS, dip,
		    "range_prop:0x%llx, shifted: bus:0x%x, dev:0x%x "
		    "func:0x%x, addr:0x%x",
		    range_prop,
		    prg.bus_no << PCI_REG_BUS_SHIFT,
		    prg.dev_no << PCI_REG_DEV_SHIFT,
		    prg.func_no << PCI_REG_FUNC_SHIFT,
		    base_addr);

		/* Proper config space desired. */
		if (prg.barnum == 0) {

			/* Access config space and we're done. */
			prg.phys_addr = base_addr + prg.offset;

			DEBUG4(DBG_TOOLS, dip,
			    "config access: base:0x%llx, offset:0x%llx, "
			    "phys_addr:0x%llx, end:%s\n",
			    base_addr, prg.offset, prg.phys_addr,
			    (PCITOOL_ACC_IS_BIG_ENDIAN(prg.acc_attr)?
				"big" : "ltl"));

			/* Access device.  pr.status is modified. */
			rval = pci_access(pci_p,
			    prg.phys_addr, max_addr,
			    &prg.data, size, write_flag,
			    PCITOOL_ACC_IS_BIG_ENDIAN(prg.acc_attr), /* BE/LE */
			    &prg.status);

			DEBUG1(DBG_TOOLS, dip, "config access: data:0x%llx\n",
			    prg.data);

		/* IO/ MEM/ MEM64 space. */
		} else {

			/*
			 * Translate BAR number into offset of the BAR in
			 * the device's config space.
			 */
			bar_offset = pci_bars[prg.barnum];

			DEBUG2(DBG_TOOLS, dip, "barnum:%d, bar_offset:0x%x\n",
			    prg.barnum, bar_offset);

			/*
			 * Get Bus Address Register (BAR) from config space.
			 * bar_offset is the offset into config space of the
			 * BAR desired.  prg.status is modified on error.
			 */
			rval = pci_access(pci_p,
			    base_addr + bar_offset,
			    max_addr, &bar,
			    4,		/* 4 bytes. */
			    B_FALSE,	/* Read */
			    B_FALSE, 	/* Little endian. */
			    &prg.status);
			if (rval != SUCCESS) {
				goto done_reg;
			}

			/*
			 * Reference proper PCI space based on the BAR.
			 * If 64 bit MEM space, need to load other half of the
			 * BAR first.
			 */

			DEBUG1(DBG_TOOLS, dip, "bar returned is 0x%llx\n", bar);
			if (!bar) {
				rval = EINVAL;
				prg.status = PCITOOL_INVALID_ADDRESS;
				goto done_reg;
			}

			/*
			 * BAR has bits saying this space is IO space, unless
			 * this is the ROM address register.
			 */
			if (((PCI_BASE_SPACE_M & bar) == PCI_BASE_SPACE_IO) &&
			    (bar_offset != PCI_CONF_ROM)) {
				DEBUG0(DBG_TOOLS, dip, "IO space\n");

				/* Reposition to focus on IO space. */
				range_prop = PCI_GET_RANGE_PROP(rp,
				    PCI_IO_RANGE_BANK);
				range_prop_size = PCI_GET_RANGE_PROP_SIZE(rp,
				    PCI_IO_RANGE_BANK);

				bar &= PCI_BASE_IO_ADDR_M;

			/*
			 * BAR has bits saying this space is 64 bit memory
			 * space, unless this is the ROM address register.
			 *
			 * The 64 bit address stored in two BAR cells is not
			 * necessarily aligned on an 8-byte boundary.
			 * Need to keep the first 4 bytes read,
			 * and do a separate read of the high 4 bytes.
			 */

			} else if ((PCI_BASE_TYPE_ALL & bar) &&
			    (bar_offset != PCI_CONF_ROM)) {

				uint32_t low_bytes =
				    (uint32_t)(bar & ~PCI_BASE_TYPE_ALL);

				/*
				 * Don't try to read the next 4 bytes
				 * past the end of BARs.
				 */
				if (bar_offset >= PCI_CONF_BASE5) {
					prg.status = PCITOOL_OUT_OF_RANGE;
					rval = EIO;
					goto done_reg;
				}

				/*
				 * Access device.
				 * prg.status is modified on error.
				 */
				rval = pci_access(pci_p,
				    base_addr + bar_offset + 4,
				    max_addr, &bar,
				    4,		/* 4 bytes. */
				    B_FALSE,	/* Read */
				    B_FALSE, 	/* Little endian. */
				    &prg.status);
				if (rval != SUCCESS) {
					goto done_reg;
				}

				bar = (bar << 32) + low_bytes;

				DEBUG1(DBG_TOOLS, dip,
				    "64 bit mem space.  64-bit bar is 0x%llx\n",
				    bar);

				/* Reposition to MEM64 range space. */
				range_prop = PCI_GET_RANGE_PROP(rp,
				    PCI_MEM64_RANGE_BANK);
				range_prop_size = PCI_GET_RANGE_PROP_SIZE(rp,
				    PCI_MEM64_RANGE_BANK);

			/* Mem32 space, including ROM */
			} else {

				if (bar_offset == PCI_CONF_ROM) {

					DEBUG0(DBG_TOOLS, dip,
					    "Additional ROM checking\n");

					/* Can't write to ROM */
					if (write_flag) {
						prg.status = PCITOOL_ROM_WRITE;
						rval = EIO;
						goto done_reg;

					/* ROM disabled for reading */
					} else if (!(bar & 0x00000001)) {
						prg.status =
						    PCITOOL_ROM_DISABLED;
						rval = EIO;
						goto done_reg;
					}
				}

				DEBUG0(DBG_TOOLS, dip, "32 bit mem space\n");
				range_prop = PCI_GET_RANGE_PROP(rp,
				    PCI_MEM_RANGE_BANK);
				range_prop_size = PCI_GET_RANGE_PROP_SIZE(rp,
				    PCI_MEM_RANGE_BANK);
			}

			/* Common code for all IO/MEM range spaces. */
			max_addr = range_prop + range_prop_size;
			base_addr = range_prop + bar;

			DEBUG3(DBG_TOOLS, dip,
			    "addr portion of bar is 0x%llx, base=0x%llx, "
			    "offset:0x%lx\n", bar, base_addr, prg.offset);

			/*
			 * Use offset provided by caller to index into
			 * desired space, then access.
			 * Note that prg.status is modified on error.
			 */
			prg.phys_addr = base_addr + prg.offset;
			rval = pci_access(pci_p,
			    prg.phys_addr,
			    max_addr, &prg.data, size, write_flag,
			    PCITOOL_ACC_IS_BIG_ENDIAN(prg.acc_attr), /* BE/LE */
			    &prg.status);
		}
done_reg:
		prg.drvr_version = PCITOOL_DRVR_VERSION;
		if (ddi_copyout(&prg, arg, sizeof (pcitool_reg_t), mode) !=
		    DDI_SUCCESS) {
			DEBUG0(DBG_TOOLS, dip, "Error returning arguments.\n");
			rval = EFAULT;
		}
		break;
	default:
		rval = ENOTTY;
		break;
	}
	return (rval);
}
