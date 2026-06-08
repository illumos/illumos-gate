/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026 Argo Technology East
 */

/*
 * efi(4D) -- character pseudo-driver providing user-space access to
 * UEFI Runtime Services.
 *
 * This file contains the DDI plumbing only: module entry, attach,
 * detach, open/close/ioctl.  attach() locates the EFI System Table
 * (whose physical address is published as the kernel root-node
 * property "efi-systab" by fakebop) and remembers a pointer to the
 * Runtime Services structure.
 *
 * The actual invocation of Runtime Services from a running kernel is
 * non-trivial: when SetVirtualAddressMap() has not been called, the
 * function pointers in the Runtime Services table are physical
 * addresses, and a 1:1 page-table together with a CR3 swap is needed
 * to call them from kernel mode.  That machinery lives in
 * efi_runtime.c; this file validates each request and dispatches it
 * through those helpers against the ABI in <sys/efiio.h>.
 */

#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/efi.h>
#include <sys/efiio.h>
#include <sys/efi_runtime.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/mach_mmu.h>
#include <sys/modctl.h>
#include <sys/policy.h>
#include <sys/smp_impldefs.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/zone.h>

/*
 * Sanity caps.  Names stay within a few dozen CHAR16; data is capped at
 * 1 MiB, which still admits large Secure Boot databases (db/dbx) while
 * bounding kmem usage and rejecting bogus sizes.
 */
#define	EFI_NAME_MAX	(1024 * sizeof (uint16_t))	/* 1024 CHAR16 */
#define	EFI_DATA_MAX	(1024 * 1024)			/* 1 MiB */

/*
 * Soft state.  This driver supports a single instance.
 */
typedef struct efi_state {
	dev_info_t	*es_dip;
	kmutex_t	es_lock;
	uint32_t	es_arch;	/* firmware bitness; always 64 */
	paddr_t		es_systab_pa;	/* phys addr of EFI System Table */
	caddr_t		es_systab_va;	/* mapped View into the table   */
	size_t		es_systab_len;
	paddr_t		es_runtime_pa;	/* phys addr of Runtime Services */
	efi_runtime_services_t *es_runtime_va;	/* mapped Runtime Services */
	size_t		es_runtime_len;	/* mapped bytes */
	efi_pt_t	*es_pt;		/* alt page table for RT calls */
} efi_state_t;

/*
 * Translate a UEFI EFI_STATUS into an errno for userland.  Codes that
 * we expect Variable Services to produce are mapped explicitly; less
 * common ones collapse to EIO.
 */
static int
efi_status_to_errno(EFI_STATUS s)
{
	switch (s) {
	case EFI_SUCCESS:
		return (0);
	case EFI_NOT_FOUND:
		return (ENOENT);
	case EFI_BUFFER_TOO_SMALL:
		return (EOVERFLOW);
	case EFI_INVALID_PARAMETER:
		return (EINVAL);
	case EFI_OUT_OF_RESOURCES:
		return (ENOMEM);
	case EFI_WRITE_PROTECTED:
		return (EROFS);
	case EFI_SECURITY_VIOLATION:
		return (EACCES);
	case EFI_DEVICE_ERROR:
		return (EIO);
	default:
		return (EIO);
	}
}

static efi_state_t *efi_state;

/*
 * Read the firmware-supplied root-node property "efi-systab" written
 * by fakebop (see usr/src/uts/i86pc/os/fakebop.c).  Returns the
 * physical address of the EFI System Table, or zero if no UEFI
 * firmware was detected.
 */
static paddr_t
efi_lookup_systab(uint32_t *archp)
{
	int64_t pa;
	char *systype = NULL;
	uint32_t arch = 0;

	pa = ddi_prop_get_int64(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "efi-systab", 0);

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "efi-systype", &systype) == DDI_PROP_SUCCESS) {
		/*
		 * Only 64-bit firmware is supported: efi_call_dispatch()
		 * invokes the Runtime Services pointers with the 64-bit MS
		 * ABI, which cannot reach 32-bit firmware code from long
		 * mode.  A "32" system simply leaves arch at 0 so attach
		 * fails cleanly rather than crashing on the first call.
		 */
		if (strcmp(systype, "64") == 0)
			arch = 64;
		ddi_prop_free(systype);
	}

	if (archp != NULL)
		*archp = arch;
	return ((paddr_t)pa);
}

/*
 * Map the EFI System Table from its physical address and validate the
 * signature ("IBI SYST" / 0x5453595320494249).  On success store the
 * Runtime Services physical address in *runtime_pap.
 */
static int
efi_attach_systab(efi_state_t *es)
{
	void *va;
	EFI_SYSTEM_TABLE64 *st;
	uint64_t sig;
	uint32_t rev;
	paddr_t rt_pa;
	size_t maplen;

	if (es->es_arch != 64)
		return (ENOTSUP);
	maplen = sizeof (EFI_SYSTEM_TABLE64);

	va = psm_map_phys_new(es->es_systab_pa, maplen,
	    PROT_READ);
	if (va == NULL) {
		cmn_err(CE_WARN, "efi: failed to map EFI System Table at 0x%lx",
		    (ulong_t)es->es_systab_pa);
		return (EIO);
	}

	st = (EFI_SYSTEM_TABLE64 *)va;
	sig = st->Hdr.Signature;
	rev = st->Hdr.Revision;
	rt_pa = (paddr_t)st->RuntimeServices;

	if (sig != EFI_SYSTEM_TABLE_SIGNATURE) {
		cmn_err(CE_WARN, "efi: bad System Table signature 0x%llx",
		    (u_longlong_t)sig);
		psm_unmap_phys(va, maplen);
		return (EIO);
	}

	es->es_systab_va = va;
	es->es_systab_len = maplen;
	es->es_runtime_pa = rt_pa;

	/*
	 * Also keep a kernel-virtual mapping of the Runtime Services
	 * table so the function pointers (which we cache outside the
	 * critical CR3-swap region) are reachable from any kernel CR3,
	 * not only the alternate one.
	 */
	es->es_runtime_len = sizeof (efi_runtime_services_t);
	es->es_runtime_va = (efi_runtime_services_t *)psm_map_phys_new(
	    es->es_runtime_pa, es->es_runtime_len, PROT_READ);
	if (es->es_runtime_va == NULL) {
		cmn_err(CE_WARN,
		    "efi: failed to map Runtime Services at 0x%lx",
		    (ulong_t)es->es_runtime_pa);
		psm_unmap_phys(va, maplen);
		es->es_systab_va = NULL;
		es->es_systab_len = 0;
		return (EIO);
	}

	cmn_err(CE_CONT, "?efi: %u-bit firmware rev %u.%02u, "
	    "SystemTable@0x%lx, RuntimeServices@0x%lx\n",
	    es->es_arch, EFI_REV_MAJOR(rev), EFI_REV_MINOR(rev),
	    (ulong_t)es->es_systab_pa, (ulong_t)es->es_runtime_pa);

	return (0);
}

static void
efi_detach_systab(efi_state_t *es)
{
	if (es->es_runtime_va != NULL) {
		psm_unmap_phys((caddr_t)es->es_runtime_va, es->es_runtime_len);
		es->es_runtime_va = NULL;
		es->es_runtime_len = 0;
	}
	if (es->es_systab_va != NULL) {
		psm_unmap_phys(es->es_systab_va, es->es_systab_len);
		es->es_systab_va = NULL;
		es->es_systab_len = 0;
	}
}

static int
efi_copyin_ioc(intptr_t arg, struct efi_var_ioc *ku, int mode)
{
	if (ddi_copyin((void *)arg, ku, sizeof (*ku), mode) != 0)
		return (EFAULT);
	return (0);
}

static int
efi_copyout_ioc(struct efi_var_ioc *ku, intptr_t arg, int mode)
{
	if (ddi_copyout(ku, (void *)arg, sizeof (*ku), mode) != 0)
		return (EFAULT);
	return (0);
}

/*
 * Kernel-side working copy of a variable request.  The ABI struct
 * efi_var_ioc carries the name and data user addresses as uint64_t so
 * its layout is model-independent; this holds native kernel pointers to
 * the kmem_alloc()ed name and data buffers.
 */
struct efi_var_kbuf {
	uint16_t	*name;
	size_t		namesize;
	struct uuid	vendor;
	uint32_t	attrib;
	void		*data;
	size_t		datasize;
};

/*
 * Translate a userland struct efi_var_ioc into kernel buffers.  The
 * caller is responsible for kmem_free()ing kbufp->name and (if
 * non-NULL) kbufp->data on return, regardless of error.
 *
 * On entry, ku is the userland snapshot.  On exit, kbufp->name and
 * kbufp->data point at kernel-allocated buffers; the userland pointers
 * are preserved in ku for copyout.
 */
static int
efi_copyin_var(struct efi_var_ioc *ku, struct efi_var_kbuf *kbufp, int mode)
{
	int rc;

	bzero(kbufp, sizeof (*kbufp));
	kbufp->namesize = ku->namesize;
	kbufp->vendor = ku->vendor;
	kbufp->attrib = ku->attrib;
	kbufp->datasize = ku->datasize;

	if (ku->namesize < sizeof (uint16_t) ||
	    ku->namesize % sizeof (uint16_t) != 0 ||
	    ku->namesize > EFI_NAME_MAX) {
		return (EINVAL);
	}
	kbufp->name = kmem_zalloc(ku->namesize + sizeof (uint16_t), KM_SLEEP);
	if (ddi_copyin((void *)(uintptr_t)ku->name, kbufp->name,
	    ku->namesize, mode) != 0) {
		rc = EFAULT;
		goto fail;
	}

	if (ku->datasize > EFI_DATA_MAX ||
	    (ku->datasize > 0 && ku->data == 0)) {
		rc = EINVAL;
		goto fail;
	}
	if (ku->datasize > 0) {
		kbufp->data = kmem_alloc(ku->datasize, KM_SLEEP);
		/*
		 * For VAR_GET / VAR_NEXT the data buffer is output-only
		 * and need not be copied in.  We zero it here so the
		 * later copyout can return zero-padded data when the
		 * Runtime Services produce a short write.
		 */
		bzero(kbufp->data, ku->datasize);
	}

	return (0);

fail:
	if (kbufp->name != NULL)
		kmem_free(kbufp->name, ku->namesize + sizeof (uint16_t));
	if (kbufp->data != NULL)
		kmem_free(kbufp->data, ku->datasize);
	return (rc);
}

static void
efi_free_var(struct efi_var_kbuf *kbufp)
{
	if (kbufp->name != NULL)
		kmem_free(kbufp->name, kbufp->namesize + sizeof (uint16_t));
	if (kbufp->data != NULL && kbufp->datasize != 0)
		kmem_free(kbufp->data, kbufp->datasize);
	bzero(kbufp, sizeof (*kbufp));
}

/*ARGSUSED*/
static int
efi_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	if (otyp != OTYP_CHR)
		return (EINVAL);

	if (crgetzoneid(credp) != GLOBAL_ZONEID)
		return (EPERM);
	if (efi_state == NULL || efi_state->es_systab_va == NULL)
		return (ENXIO);
	return (0);
}

/*ARGSUSED*/
static int
efi_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (0);
}

/*ARGSUSED*/
static int
efi_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	struct efi_var_ioc ku;
	struct efi_var_kbuf kv;
	int rc;

	if (efi_state == NULL || efi_state->es_systab_va == NULL)
		return (ENXIO);

	switch (cmd) {
	case EFIIOC_VAR_GET:
	case EFIIOC_VAR_NEXT:
	case EFIIOC_VAR_SET:
		break;
	default:
		return (ENOTTY);
	}

	/*
	 * Mutating ioctls require root.  Reads of UEFI variables can
	 * also expose secrets (e.g. SecureBoot keys) so we gate them
	 * on PRIV_SYS_CONFIG too.
	 */
	if (secpolicy_sys_config(credp, B_FALSE) != 0)
		return (EPERM);

	rc = efi_copyin_ioc(arg, &ku, mode);
	if (rc != 0)
		return (rc);

	rc = efi_copyin_var(&ku, &kv, mode);
	if (rc != 0)
		return (rc);

	mutex_enter(&efi_state->es_lock);

	switch (cmd) {
	case EFIIOC_VAR_GET: {
		EFI_GUID vendor = kv.vendor;
		UINTN datasize = kv.datasize;
		uint32_t attrib = 0;
		EFI_STATUS s;

		s = efi_call_get_variable(efi_state->es_pt,
		    efi_state->es_runtime_va,
		    (CHAR16 *)kv.name, &vendor, &attrib, &datasize, kv.data);

		ku.attrib = attrib;
		ku.datasize = datasize;
		ku.vendor = vendor;

		if (s == EFI_SUCCESS && datasize > kv.datasize) {
			rc = EIO;
			break;
		}
		if (s == EFI_SUCCESS && datasize > 0 && kv.data != NULL) {
			if (ddi_copyout(kv.data, (void *)(uintptr_t)ku.data,
			    datasize, mode) != 0) {
				rc = EFAULT;
				break;
			}
		}
		if (efi_copyout_ioc(&ku, arg, mode) != 0) {
			rc = EFAULT;
			break;
		}
		rc = efi_status_to_errno(s);
		break;
	}

	case EFIIOC_VAR_NEXT: {
		EFI_GUID vendor = kv.vendor;
		UINTN namesize = kv.namesize;
		EFI_STATUS s;

		s = efi_call_get_next_variable_name(efi_state->es_pt,
		    efi_state->es_runtime_va,
		    &namesize, (CHAR16 *)kv.name, &vendor);

		ku.namesize = (uint32_t)namesize;
		ku.vendor = vendor;

		if (s == EFI_SUCCESS && namesize > kv.namesize) {
			rc = EIO;
			break;
		}
		if (s == EFI_SUCCESS) {
			if (ddi_copyout(kv.name, (void *)(uintptr_t)ku.name,
			    namesize, mode) != 0) {
				rc = EFAULT;
				break;
			}
		}
		if (efi_copyout_ioc(&ku, arg, mode) != 0) {
			rc = EFAULT;
			break;
		}
		rc = efi_status_to_errno(s);
		break;
	}

	case EFIIOC_VAR_SET: {
		EFI_GUID vendor = kv.vendor;
		EFI_STATUS s;

		/*
		 * For SET the userland data buffer is an input. GET/NEXT
		 * leave kv.data zero-filled, so copy it in here. A zero
		 * datasize is legal: per UEFI 8.2.3 it deletes the variable.
		 */
		if (kv.datasize > 0 && ku.data != 0) {
			if (ddi_copyin((void *)(uintptr_t)ku.data, kv.data,
			    kv.datasize, mode) != 0) {
				rc = EFAULT;
				break;
			}
		}

		s = efi_call_set_variable(efi_state->es_pt,
		    efi_state->es_runtime_va,
		    (CHAR16 *)kv.name, &vendor, kv.attrib, kv.datasize,
		    kv.datasize > 0 ? kv.data : NULL);

		rc = efi_status_to_errno(s);
		break;
	}
	}

	mutex_exit(&efi_state->es_lock);

	efi_free_var(&kv);
	return (rc);
}

/*ARGSUSED*/
static int
efi_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (efi_state != NULL && efi_state->es_dip != NULL) {
			*result = efi_state->es_dip;
			return (DDI_SUCCESS);
		}
		return (DDI_FAILURE);
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
efi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	efi_state_t *es;
	uint32_t arch = 0;
	paddr_t systab_pa;
	uint_t nranges = 0;
	int rc;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (efi_state != NULL) {
		/*
		 * Single-instance driver; refuse a second attach.
		 */
		return (DDI_FAILURE);
	}

	systab_pa = efi_lookup_systab(&arch);
	if (systab_pa == 0 || arch == 0) {
		/*
		 * Booted via legacy BIOS or efi-systab not exposed.
		 * Fail attach quietly so the driver simply doesn't
		 * appear in /dev.
		 */
		return (DDI_FAILURE);
	}

	es = kmem_zalloc(sizeof (*es), KM_SLEEP);
	es->es_dip = dip;
	es->es_arch = arch;
	es->es_systab_pa = systab_pa;
	mutex_init(&es->es_lock, NULL, MUTEX_DRIVER, NULL);

	rc = efi_attach_systab(es);
	if (rc != 0) {
		mutex_destroy(&es->es_lock);
		kmem_free(es, sizeof (*es));
		return (DDI_FAILURE);
	}

	/*
	 * Build the alternate page table that any future Runtime
	 * Services call will switch CR3 to.  We need at minimum the
	 * EFI memory ranges marked EFI_MEMORY_RUNTIME by the firmware,
	 * plus the System Table page itself (the RuntimeServices
	 * pointer is read from there at call time).  Without this
	 * table the driver has no way to dispatch into firmware at
	 * all, so we treat allocation/property failures as fatal for
	 * this attach.
	 */
	rc = efi_pt_create(&es->es_pt);
	if (rc != 0) {
		efi_detach_systab(es);
		mutex_destroy(&es->es_lock);
		kmem_free(es, sizeof (*es));
		return (DDI_FAILURE);
	}

	rc = efi_pt_apply_mmap(es->es_pt, &nranges);
	if (rc != 0) {
		cmn_err(CE_WARN,
		    "efi: cannot apply EFI memory map (error %d)", rc);
		efi_pt_destroy(es->es_pt);
		efi_detach_systab(es);
		mutex_destroy(&es->es_lock);
		kmem_free(es, sizeof (*es));
		return (DDI_FAILURE);
	}

	rc = efi_pt_map(es->es_pt, es->es_systab_pa,
	    es->es_systab_len, PT_WRITABLE);
	if (rc != 0) {
		efi_pt_destroy(es->es_pt);
		efi_detach_systab(es);
		mutex_destroy(&es->es_lock);
		kmem_free(es, sizeof (*es));
		return (DDI_FAILURE);
	}

	cmn_err(CE_CONT, "?efi: mapped %u runtime range(s), alt CR3 = 0x%lx\n",
	    nranges, (ulong_t)efi_pt_root_pa(es->es_pt));

	if (ddi_create_minor_node(dip, "efi", S_IFCHR, 0, DDI_PSEUDO,
	    0) != DDI_SUCCESS) {
		efi_pt_destroy(es->es_pt);
		efi_detach_systab(es);
		mutex_destroy(&es->es_lock);
		kmem_free(es, sizeof (*es));
		return (DDI_FAILURE);
	}

	efi_state = es;
	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

static int
efi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	efi_state_t *es = efi_state;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);
	if (es == NULL || es->es_dip != dip)
		return (DDI_FAILURE);

	ddi_remove_minor_node(dip, NULL);
	efi_pt_destroy(es->es_pt);
	efi_detach_systab(es);
	mutex_destroy(&es->es_lock);
	kmem_free(es, sizeof (*es));
	efi_state = NULL;
	return (DDI_SUCCESS);
}

static struct cb_ops efi_cb_ops = {
	.cb_open =	efi_open,
	.cb_close =	efi_close,
	.cb_strategy =	nodev,
	.cb_print =	nodev,
	.cb_dump =	nodev,
	.cb_read =	nodev,
	.cb_write =	nodev,
	.cb_ioctl =	efi_ioctl,
	.cb_devmap =	nodev,
	.cb_mmap =	nodev,
	.cb_segmap =	nodev,
	.cb_chpoll =	nochpoll,
	.cb_prop_op =	ddi_prop_op,
	.cb_str =	NULL,
	.cb_flag =	D_NEW | D_MP,
	.cb_rev =	CB_REV,
	.cb_aread =	nodev,
	.cb_awrite =	nodev
};

static struct dev_ops efi_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt =		0,
	.devo_getinfo =		efi_getinfo,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_attach =		efi_attach,
	.devo_detach =		efi_detach,
	.devo_reset =		nodev,
	.devo_cb_ops =		&efi_cb_ops,
	.devo_bus_ops =		NULL,
	.devo_power =		NULL,
	.devo_quiesce =		ddi_quiesce_not_needed
};

static struct modldrv efi_modldrv = {
	&mod_driverops,
	"UEFI Runtime Services driver",
	&efi_dev_ops,
};

static struct modlinkage efi_modlinkage = {
	MODREV_1,
	(void *)&efi_modldrv,
	NULL,
};

int
_init(void)
{
	return (mod_install(&efi_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&efi_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&efi_modlinkage));
}
