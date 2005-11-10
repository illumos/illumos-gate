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
/*
 * ACPI CA OSL for Solaris x86
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/psm.h>
#include <sys/pci_cfgspace.h>
#include <sys/ddi.h>
#include <sys/pci.h>
#include <sys/kobj.h>
#include <sys/taskq.h>
#include <sys/strlog.h>
#include <sys/note.h>

#include <sys/acpi/acpi.h>
#include <sys/acpica.h>

extern int (*psm_translate_irq)(dev_info_t *, int);

#define	MAX_DAT_FILE_SIZE	(64*1024)

#define	D2A_INITLEN	20
static int d2a_len = 0;
static int d2a_valid = 0;
static d2a *d2a_table;

static int acpi_has_broken_bbn = -1;

/* local functions */
static int CompressEisaID(char *np);

static void create_d2a_map(void);
static void create_d2a_subtree(dev_info_t *dip, ACPI_HANDLE acpiobj, int bus);
static void new_d2a_entry(dev_info_t *dip, ACPI_HANDLE acpiobj,
	int bus, int dev, int func);

static int acpica_query_bbn_problem(void);
static int acpica_find_pcibus(int busno, ACPI_HANDLE *rh);
static int acpica_eval_hid(ACPI_HANDLE dev, char *method, int *rint);

int acpica_find_pciobj(dev_info_t *dip, ACPI_HANDLE *rh);
static int acpica_find_pcid2a(ACPI_HANDLE, d2a **);
int acpica_eval_int(ACPI_HANDLE dev, char *method, int *rint);

/*
 * Event queue vars
 */
int acpica_eventq_thread_count = 1;
int acpica_eventq_init = 0;
ddi_taskq_t *eventq_gpe = NULL;
ddi_taskq_t *eventq_high = NULL;
ddi_taskq_t *eventq_medium = NULL;
ddi_taskq_t *eventq_low = NULL;

/*
 * Note, if you change this path, you need to update
 * /boot/grub/filelist.ramdisk and pkg SUNWckr/prototype_i386
 */
static char *acpi_table_path = "/boot/acpi/tables/";

/* non-zero while create_d2a_map() is working */
static int creating_d2a_map = 0;

/*
 *
 */
static void
discard_event_queues()
{

	/*
	 * destroy event queues
	 */
	if (eventq_gpe)
		ddi_taskq_destroy(eventq_gpe);
	if (eventq_high)
		ddi_taskq_destroy(eventq_high);
	if (eventq_low)
		ddi_taskq_destroy(eventq_low);
	if (eventq_medium)
		ddi_taskq_destroy(eventq_medium);
}


/*
 *
 */
static ACPI_STATUS
init_event_queues()
{

	/*
	 * Initialize event queues
	 * FUTUREWORK: taskq priorities currently the same
	 */

	eventq_gpe = ddi_taskq_create(NULL, "ACPIGPE",
	    acpica_eventq_thread_count, TASKQ_DEFAULTPRI, 0);
	eventq_high = ddi_taskq_create(NULL, "ACPIHIGH",
	    acpica_eventq_thread_count, TASKQ_DEFAULTPRI, 0);
	eventq_medium = ddi_taskq_create(NULL, "ACPIMED",
	    acpica_eventq_thread_count, TASKQ_DEFAULTPRI, 0);
	eventq_low = ddi_taskq_create(NULL, "ACPILOW",
	    acpica_eventq_thread_count, TASKQ_DEFAULTPRI, 0);

	if ((eventq_gpe == NULL) || (eventq_high == NULL) ||
	    (eventq_medium == NULL) || (eventq_low == NULL)) {
		discard_event_queues();
#ifdef	DEBUG
		cmn_err(CE_WARN, "!acpica: could not initialize event queues");
#endif
		return (AE_ERROR);
	}

	acpica_eventq_init = 1;
	return (AE_OK);
}

/*
 *
 */
ACPI_STATUS
AcpiOsInitialize(void)
{

	return (AE_OK);
}

/*
 *
 */
ACPI_STATUS
AcpiOsTerminate(void)
{

	discard_event_queues();
	return (AE_OK);
}


ACPI_STATUS
AcpiOsGetRootPointer(UINT32 Flags, ACPI_POINTER *Address)
{
	return (AcpiFindRootPointer(Flags, Address));
}

/*ARGSUSED*/
ACPI_STATUS
AcpiOsPredefinedOverride(const ACPI_PREDEFINED_NAMES *InitVal,
				ACPI_STRING *NewVal)
{

	*NewVal = 0;
	return (AE_OK);
}

static void
acpica_strncpy(char *dest, const char *src, int len)
{

	/*LINTED*/
	while ((*dest++ = *src++) && (--len > 0))
		/* copy the string */;
	*dest = '\0';
}

ACPI_STATUS
AcpiOsTableOverride(ACPI_TABLE_HEADER *ExistingTable,
			ACPI_TABLE_HEADER **NewTable)
{
	char signature[5];
	char oemid[7];
	char oemtableid[9];
	struct _buf *file;
	char *buf1, *buf2;
	int count;
	char acpi_table_loc[128];

	acpica_strncpy(signature, ExistingTable->Signature, 4);
	acpica_strncpy(oemid, ExistingTable->OemId, 6);
	acpica_strncpy(oemtableid, ExistingTable->OemTableId, 8);

#ifdef	DEBUG
	cmn_err(CE_NOTE, "!acpica: table [%s] v%d OEM ID [%s]"
		    " OEM TABLE ID [%s] OEM rev %x",
		    signature, ExistingTable->Revision, oemid, oemtableid,
		    ExistingTable->OemRevision);
#endif

	/* File name format is "signature_oemid_oemtableid.dat" */
	(void) strcpy(acpi_table_loc, acpi_table_path);
	(void) strcat(acpi_table_loc, signature); /* for example, DSDT */
	(void) strcat(acpi_table_loc, "_");
	(void) strcat(acpi_table_loc, oemid); /* for example, IntelR */
	(void) strcat(acpi_table_loc, "_");
	(void) strcat(acpi_table_loc, oemtableid); /* for example, AWRDACPI */
	(void) strcat(acpi_table_loc, ".dat");

	file = kobj_open_file(acpi_table_loc);
	if (file == (struct _buf *)-1) {
		*NewTable = 0;
		return (AE_OK);
	} else {
		buf1 = (char *)kmem_alloc(MAX_DAT_FILE_SIZE, KM_SLEEP);
		count = kobj_read_file(file, buf1, MAX_DAT_FILE_SIZE-1, 0);
		if (count >= MAX_DAT_FILE_SIZE) {
			cmn_err(CE_WARN, "!acpica: table %s file size too big",
			    acpi_table_loc);
			*NewTable = 0;
		} else {
			buf2 = (char *)kmem_alloc(count, KM_SLEEP);
			(void) memcpy(buf2, buf1, count);
			*NewTable = (ACPI_TABLE_HEADER *)buf2;
			cmn_err(CE_NOTE, "!acpica: replacing table: %s",
			    acpi_table_loc);
		}
	}
	kobj_close_file(file);
	kmem_free(buf1, MAX_DAT_FILE_SIZE);

	return (AE_OK);
}


ACPI_STATUS
AcpiOsCreateSemaphore(UINT32 MaxUnits, UINT32 InitialUnits,
ACPI_HANDLE *OutHandle)
{
	ksema_t	*sp;

	if ((OutHandle == NULL) || (InitialUnits > MaxUnits))
		return (AE_BAD_PARAMETER);

	sp = (ksema_t *)kmem_alloc(sizeof (ksema_t), KM_SLEEP);
	sema_init(sp, InitialUnits, NULL, SEMA_DRIVER, NULL);
	*OutHandle = (void *)sp;
	return (AE_OK);
}


ACPI_STATUS
AcpiOsDeleteSemaphore(ACPI_HANDLE Handle)
{

	sema_destroy((ksema_t *)Handle);
	kmem_free((void *)Handle, sizeof (ksema_t));
	return (AE_OK);
}

ACPI_STATUS
AcpiOsWaitSemaphore(ACPI_HANDLE Handle, UINT32 Units, UINT16 Timeout)
{
	uint32_t p_count = 0;
	clock_t	timeout_ticks = (clock_t)drv_usectohz(Timeout * 1000);

	do {
		if (!sema_tryp((ksema_t *)Handle)) {
			/* going to block */
			if (timeout_ticks > 0) {
				delay(1);
				if (Timeout != 0xffff)
					timeout_ticks--;
				continue;
			} else
				break;
		} else {
			p_count++;
			if (--Units == 0)
				return (AE_OK); /* normal exit */
		}
	} while (timeout_ticks > 0);

	while (p_count > 0)
		sema_v((ksema_t *)Handle);
	return (AE_TIME);
}

ACPI_STATUS
AcpiOsSignalSemaphore(ACPI_HANDLE Handle, UINT32 Units)
{

	while (Units > 0) {
		sema_v((ksema_t *)Handle);
		Units -= 1;
	}
	return (AE_OK);
}

ACPI_STATUS
AcpiOsCreateLock(ACPI_HANDLE *OutHandle)
{
	ksema_t	*sp;

	if (OutHandle == NULL)
		return (AE_BAD_PARAMETER);

	sp = (ksema_t *)kmem_alloc(sizeof (ksema_t), KM_SLEEP);
	sema_init(sp, 1, NULL, SEMA_DRIVER, NULL);
	*OutHandle = (void *)sp;

	return (AE_OK);
}

void
AcpiOsDeleteLock(ACPI_HANDLE Handle)
{
	sema_destroy((ksema_t *)Handle);
	kmem_free((void *)Handle, sizeof (ksema_t));
}

UINT32
AcpiOsAcquireLock(ACPI_HANDLE Handle)
{
	sema_p((ksema_t *)Handle);
	return (0);
}

void
AcpiOsReleaseLock(ACPI_HANDLE Handle, UINT32 Flags)
{
	_NOTE(ARGUNUSED(Flags))

	sema_v((ksema_t *)Handle);
}


void *
AcpiOsAllocate(ACPI_SIZE Size)
{
	ACPI_SIZE *tmp_ptr;

	Size += sizeof (Size);
	tmp_ptr = (ACPI_SIZE *)kmem_zalloc(Size, KM_SLEEP);
	*tmp_ptr++ = Size;
	return ((void *)tmp_ptr);
}

void
AcpiOsFree(void *Memory)
{
	ACPI_SIZE	size, *tmp_ptr;

	tmp_ptr = (ACPI_SIZE *)Memory;
	tmp_ptr -= 1;
	size = *tmp_ptr;
	kmem_free((void *)tmp_ptr, size);
}

ACPI_STATUS
AcpiOsMapMemory(ACPI_PHYSICAL_ADDRESS PhysicalAddress,
		    ACPI_SIZE Size, void **LogicalAddress)
{
	/* FUTUREWORK: test PhysicalAddress for > 32 bits */
	*LogicalAddress = psm_map_new((paddr_t)PhysicalAddress,
		(size_t)Size, PSM_PROT_WRITE | PSM_PROT_READ);
	return (AE_OK);
}

void
AcpiOsUnmapMemory(void *LogicalAddress, ACPI_SIZE Size)
{

	psm_unmap((caddr_t)LogicalAddress, (size_t)Size);
}

/*ARGSUSED*/
ACPI_STATUS
AcpiOsGetPhysicalAddress(void *LogicalAddress,
			ACPI_PHYSICAL_ADDRESS *PhysicalAddress)
{

	/* UNIMPLEMENTED: not invoked by ACPI CA code */
	return (AE_OK);
}


ACPI_OSD_HANDLER acpi_isr;
void *acpi_isr_context;

uint_t
acpi_wrapper_isr(char *arg)
{
	_NOTE(ARGUNUSED(arg))

	int	status;

	status = (*acpi_isr)(acpi_isr_context);

	if (status == ACPI_INTERRUPT_HANDLED) {
		return (DDI_INTR_CLAIMED);
	} else {
		return (DDI_INTR_UNCLAIMED);
	}
}

int intr_hooked = 0;

ACPI_STATUS
AcpiOsInstallInterruptHandler(UINT32 InterruptNumber,
		ACPI_OSD_HANDLER ServiceRoutine,
		void *Context)
{
	int retval;
	int sci_vect;
	iflag_t sci_flags;

	acpi_isr = ServiceRoutine;
	acpi_isr_context = Context;

	/*
	 * Get SCI (adjusted for PIC/APIC mode if necessary)
	 */
	if (acpica_get_sci(&sci_vect, &sci_flags) != AE_OK) {
		return (AE_ERROR);
	}

#ifdef	DEBUG
	cmn_err(CE_NOTE, "!acpica: attaching SCI %d", sci_vect);
#endif

	retval = add_avintr(NULL, SCI_IPL, (avfunc)acpi_wrapper_isr,
				"ACPI SCI", sci_vect, NULL, NULL, NULL);
	if (retval) {
		intr_hooked = 1;
		return (AE_OK);
	} else {
		return (AE_BAD_PARAMETER);
	}
}

ACPI_STATUS
AcpiOsRemoveInterruptHandler(UINT32 InterruptNumber,
			ACPI_OSD_HANDLER ServiceRoutine)
{
	_NOTE(ARGUNUSED(ServiceRoutine))

#ifdef	DEBUG
	cmn_err(CE_NOTE, "!acpica: detaching SCI %d", InterruptNumber);
#endif
	if (intr_hooked) {
		rem_avintr(NULL, LOCK_LEVEL - 1, (avfunc)acpi_wrapper_isr,
				InterruptNumber);
		intr_hooked = 0;
	}
	return (AE_OK);
}


UINT32
AcpiOsGetThreadId(void)
{
	kt_did_t thread_id;

	/* FUTUREWORK: give back a real thread id */
	thread_id = ddi_get_kt_did();
	return ((UINT32)thread_id);
}

/*
 *
 */
ACPI_STATUS
AcpiOsQueueForExecution(UINT32 Priority,
		ACPI_OSD_EXEC_CALLBACK  Function,
		void *Context)
{
	ddi_taskq_t *q;

	if (!acpica_eventq_init) {
		/*
		 * Create taskqs for event handling
		 */
		if (init_event_queues() != AE_OK)
		    return (AE_ERROR);
	}

	switch (Priority) {
	case OSD_PRIORITY_GPE:
		q = eventq_gpe;
		break;
	case OSD_PRIORITY_HIGH:
		q = eventq_high;
		break;
	case OSD_PRIORITY_MED:
		q = eventq_medium;
		break;
	case OSD_PRIORITY_LO:
		q = eventq_low;
		break;
	default:
		q = NULL;
		break;
	}

	if (q == NULL) {
#ifdef	DEBUG
		cmn_err(CE_WARN, "!acpica: unknown priority %d", Priority);
#endif
		return (AE_ERROR);
	}
	if (ddi_taskq_dispatch(q, Function, Context, DDI_NOSLEEP) ==
	    DDI_FAILURE) {
#ifdef	DEBUG
		cmn_err(CE_WARN, "!acpica: unable to dispatch event");
#endif
		return (AE_ERROR);
	}
	return (AE_OK);

}

void
AcpiOsSleep(ACPI_INTEGER Milliseconds)
{
	/*
	 * During kernel startup, before the first
	 * tick interrupt has taken place, we can't call
	 * delay.  So we busy wait if lbolt == 0.
	 */
	if (ddi_get_lbolt() == 0)
		drv_usecwait(Milliseconds * 1000);
	else
		delay(drv_usectohz(Milliseconds * 1000));
}

void
AcpiOsStall(UINT32 Microseconds)
{
	drv_usecwait(Microseconds);
}


/*
 * Implementation of "Windows 2001" compatible I/O permission map
 *
 */
#define	OSL_IO_NONE	(0)
#define	OSL_IO_READ	(1<<0)
#define	OSL_IO_WRITE	(1<<1)
#define	OSL_IO_RW	(OSL_IO_READ | OSL_IO_WRITE)
#define	OSL_IO_TERM	(1<<2)
#define	OSL_IO_DEFAULT	OSL_IO_RW

static struct io_perm  {
	ACPI_IO_ADDRESS	low;
	ACPI_IO_ADDRESS	high;
	uint8_t		perm;
} osl_io_perm[] = {
	{ 0x000, 0x00f, OSL_IO_DEFAULT },	/* DMAC */
	{ 0x020, 0x021, OSL_IO_READ },		/* PIC */
	{ 0x040, 0x043, OSL_IO_READ },		/* PIT (8254) */
	{ 0x048, 0x04b, OSL_IO_DEFAULT },
	{ 0x070, 0x071, OSL_IO_READ },		/* NMI / RTC */
	{ 0x074, 0x076, OSL_IO_READ },		/* NMI / RTC */
	{ 0x081, 0x083, OSL_IO_DEFAULT },	/* DMAC */
	{ 0x087, 0x087, OSL_IO_DEFAULT },	/* DMAC */
	{ 0x089, 0x089, OSL_IO_DEFAULT },	/* DMAC */
	{ 0x08a, 0x08b, OSL_IO_DEFAULT },	/* DMAC */
	{ 0x08f, 0x08f, OSL_IO_DEFAULT },	/* DMAC */
	{ 0x090, 0x091, OSL_IO_DEFAULT },	/* DMAC */
	{ 0x093, 0x094, OSL_IO_DEFAULT },	/* DMAC */
	{ 0x096, 0x097, OSL_IO_DEFAULT },	/* DMAC */
	{ 0x0a0, 0x0a1, OSL_IO_READ },		/* PIC */
	{ 0x0c0, 0x0df, OSL_IO_DEFAULT },	/* DMAC */
	{ 0x4d0, 0x4d1, OSL_IO_DEFAULT },	/* ELCR */
	{ 0xcf8, 0xd00, OSL_IO_NONE | OSL_IO_TERM }
};


/*
 *
 */
static struct io_perm *
osl_io_find_perm(ACPI_IO_ADDRESS addr)
{
	struct io_perm *p;

	p = osl_io_perm;
	while (p != NULL) {
		if ((p->low <= addr) && (addr <= p->high))
			break;
		p = (p->perm & OSL_IO_TERM) ? NULL : p+1;
	}

	return (p);
}

/*
 *
 */
ACPI_STATUS
AcpiOsReadPort(ACPI_IO_ADDRESS Address, UINT32 *Value, UINT32 Width)
{
	struct io_perm *p;

	/* verify permission */
	p = osl_io_find_perm(Address);
	if (p && (p->perm & OSL_IO_READ) == 0) {
		cmn_err(CE_WARN, "!AcpiOsReadPort: %lx %u not permitted",
			    (long)Address, Width);
		*Value = 0xffffffff;
		return (AE_ERROR);
	}

	switch (Width) {
	case 8:
		*Value = inb(Address);
		break;
	case 16:
		*Value = inw(Address);
		break;
	case 32:
		*Value = inl(Address);
		break;
	default:
		cmn_err(CE_WARN, "!AcpiOsReadPort: %lx %u failed",
			    (long)Address, Width);
		return (AE_BAD_PARAMETER);
	}
	return (AE_OK);
}

ACPI_STATUS
AcpiOsWritePort(ACPI_IO_ADDRESS Address, UINT32 Value, UINT32 Width)
{
	struct io_perm *p;

	/* verify permission */
	p = osl_io_find_perm(Address);
	if (p && (p->perm & OSL_IO_WRITE) == 0) {
		cmn_err(CE_WARN, "!AcpiOsWritePort: %lx %u not permitted",
		    (long)Address, Width);
		return (AE_ERROR);
	}

	switch (Width) {
	case 8:
		outb(Address, Value);
		break;
	case 16:
		outw(Address, Value);
		break;
	case 32:
		outl(Address, Value);
		break;
	default:
		cmn_err(CE_WARN, "!AcpiOsWritePort: %lx %u failed",
		    (long)Address, Width);
		return (AE_BAD_PARAMETER);
	}
	return (AE_OK);
}


/*
 *
 */

#define	OSL_RW(ptr, val, type, rw) \
	{ if (rw) *((type *)(ptr)) = *((type *) val); \
	    else *((type *) val) = *((type *)(ptr)); }


static void
osl_rw_memory(ACPI_PHYSICAL_ADDRESS Address, UINT32 *Value,
    UINT32 Width, int write)
{
	size_t	maplen = Width / 8;
	caddr_t	ptr;

	ptr = psm_map_new((paddr_t)Address, maplen,
	    PSM_PROT_WRITE | PSM_PROT_READ);

	switch (maplen) {
	case 1:
		OSL_RW(ptr, Value, uint8_t, write);
		break;
	case 2:
		OSL_RW(ptr, Value, uint16_t, write);
		break;
	case 4:
		OSL_RW(ptr, Value, uint32_t, write);
		break;
	default:
		cmn_err(CE_WARN, "!osl_rw_memory: invalid size %d",
		    Width);
		break;
	}

	psm_unmap(ptr, maplen);
}

ACPI_STATUS
AcpiOsReadMemory(ACPI_PHYSICAL_ADDRESS Address,
		UINT32 *Value, UINT32 Width)
{
	osl_rw_memory(Address, Value, Width, 0);
	return (AE_OK);
}

ACPI_STATUS
AcpiOsWriteMemory(ACPI_PHYSICAL_ADDRESS Address,
		UINT32 Value, UINT32 Width)
{
	osl_rw_memory(Address, &Value, Width, 1);
	return (AE_OK);
}


ACPI_STATUS
AcpiOsReadPciConfiguration(ACPI_PCI_ID *PciId, UINT32 Register,
			void *Value, UINT32 Width)
{

	switch (Width) {
	case 8:
		*((UINT64 *)Value) = (UINT64)(*pci_getb_func)
					(PciId->Bus, PciId->Device,
						PciId->Function, Register);
		break;
	case 16:
		*((UINT64 *)Value) = (UINT64)(*pci_getw_func)
					(PciId->Bus, PciId->Device,
						PciId->Function, Register);
		break;
	case 32:
		*((UINT64 *)Value) = (UINT64)(*pci_getl_func)
					(PciId->Bus, PciId->Device,
						PciId->Function, Register);
		break;
	case 64:
	default:
		cmn_err(CE_WARN, "!AcpiOsReadPciConfiguration: %x %u failed",
		    Register, Width);
		return (AE_BAD_PARAMETER);
	}
	return (AE_OK);
}

/*
 *
 */
int acpica_write_pci_config_ok = 1;

ACPI_STATUS
AcpiOsWritePciConfiguration(ACPI_PCI_ID *PciId, UINT32 Register,
		ACPI_INTEGER Value, UINT32 Width)
{

	if (!acpica_write_pci_config_ok) {
		cmn_err(CE_NOTE, "!write to PCI cfg %x/%x/%x %x"
		    " %lx %d not permitted", PciId->Bus, PciId->Device,
		    PciId->Function, Register, (long)Value, Width);
		return (AE_OK);
	}

	switch (Width) {
	case 8:
		(*pci_putb_func)(PciId->Bus, PciId->Device, PciId->Function,
					Register, (uint8_t)Value);
		break;
	case 16:
		(*pci_putw_func)(PciId->Bus, PciId->Device, PciId->Function,
					Register, (uint16_t)Value);
		break;
	case 32:
		(*pci_putl_func)(PciId->Bus, PciId->Device, PciId->Function,
					Register, (uint32_t)Value);
		break;
	case 64:
	default:
		cmn_err(CE_WARN, "!AcpiOsWritePciConfiguration: %x %u failed",
		    Register, Width);
		return (AE_BAD_PARAMETER);
	}
	return (AE_OK);
}

/*
 * This took me a while to figure out, and thus warrants
 * detailed explanation lest I forget it.
 *
 * Called with ACPI_HANDLEs for both a PCI Config Space
 * OpRegion and (what ACPI CA thinks is) the PCI device
 * to which this ConfigSpace OpRegion belongs.  Problems
 * with this are:
 * - ACPI CA currently only thinks "PNP0A03" is a PCI bridge;
 *   and doesn't recognize "PNP0A08" which is a PCI Express bridge
 *   (in which case the root handle may be higher in the ACPI
 *   namespace than it should, including a non-PCI device)
 *
 * - ACPI CA depends on a valid _BBN object being present
 *   and this is known to not always be true
 *
 * Default values for bus, segment, device and function are
 * all 0 when ACPI CA can't figure them out.
 *
 * This is further complicated by BIOSes that implement
 * _BBN() by reading PCI config space - it means that we'll
 * recurse when we attempt to create the devinfo-to-ACPI
 * map.  If Derive is called during create_d2a_map, we simply
 * can't help and return.  It seems this ends up doing the right
 * thing, at least on the LX50 which gets base bus numbers other
 * than 0 from PCI Config space on bus 0.
 *
 */
void
AcpiOsDerivePciId(ACPI_HANDLE rhandle, ACPI_HANDLE chandle,
		ACPI_PCI_ID **PciId)
{
	ACPI_HANDLE handle;
	d2a *d2ap;
	int devfn;


	/* See above - avoid recursing during create_d2a_map */
	/* doesn't matter if multi-threaded here, either */
	if (creating_d2a_map)
		return;

	/*
	 * We start with the parent node of the OpRegion
	 * and ascend, looking for a matching dip2acpi
	 * node; once located, we use the bus from the d2a
	 * node and the device/function return from the _ADR
	 * method on the ACPI node.
	 * If we encounter any kind of failure, we just
	 * return, possibly after updating the bus value
	 * This is probably always better than nothing.
	 */
	if (AcpiGetParent(chandle, &handle) != AE_OK)
		return;

	while (handle != rhandle) {
		if (acpica_find_pcid2a(handle, &d2ap) == AE_OK) {
			(*PciId)->Bus = d2ap->bus;
			if (acpica_eval_int(handle, "_ADR", &devfn) == AE_OK) {
				(*PciId)->Device = (devfn >> 16) & 0xFFFF;
				(*PciId)->Function = devfn & 0xFFFF;
			}
			break;
		}

		if (AcpiGetParent(handle, &handle) != AE_OK)
			break;
	}
}


BOOLEAN
AcpiOsReadable(void *Pointer, ACPI_SIZE Length)
{

	/* Always says yes; all mapped memory assumed readable */
	return (1);
}

BOOLEAN
AcpiOsWritable(void *Pointer, ACPI_SIZE Length)
{

	/* Always says yes; all mapped memory assumed writable */
	return (1);
}

UINT64
AcpiOsGetTimer(void)
{

	/* New ACPI 3.0 Timer() support */
	/* FUTUREWORK: need to integrate with PSM? */

	cmn_err(CE_NOTE, "!AcpiOsGetTimer unimplemented");
	return (0);
}

ACPI_STATUS
AcpiOsSignal(UINT32 Function, void *Info)
{
	_NOTE(ARGUNUSED(Function, Info))

	/* FUTUREWORK: debugger support */

	cmn_err(CE_NOTE, "!OsSignal unimplemented");
	return (AE_OK);
}

void ACPI_INTERNAL_VAR_XFACE
AcpiOsPrintf(const char *Format, ...)
{
	va_list ap;
	int	buflen;
	char	*buf;

	/*
	 * Try to be nice and emit the message via strlog().
	 * Unfortunately, vstrlog() doesn't define the format
	 * string as const char, so we allocate a local buffer
	 * use vsnprintf().
	 *
	 * If we fail to allocate a string buffer, we resort
	 * to printf().
	 */
	va_start(ap, Format);
	buflen = vsnprintf(NULL, 0, Format, ap) + 1;
	va_end(ap);

	buf = kmem_alloc(buflen, KM_NOSLEEP);
	if (buf == NULL) {
		va_start(ap, Format);
		vprintf(Format, ap);
		va_end(ap);
		return;
	}
	va_start(ap, Format);
	(void) vsnprintf(buf, buflen, Format, ap);
	va_end(ap);

	(void) strlog(0, 0, 0, SL_CONSOLE | SL_NOTE | SL_LOGONLY, buf);
	kmem_free(buf, buflen);
}

void
AcpiOsVprintf(const char *Format, va_list Args)
{
	vprintf(Format, Args);
}

void
AcpiOsRedirectOutput(void *Destination)
{
	_NOTE(ARGUNUSED(Destination))

	/* FUTUREWORK: debugger support */

#ifdef	DEBUG
	cmn_err(CE_WARN, "!acpica: AcpiOsRedirectOutput called");
#endif
}


UINT32
AcpiOsGetLine(char *Buffer)
{
	_NOTE(ARGUNUSED(Buffer))

	/* FUTUREWORK: debugger support */

	return (0);
}




/*
 * Device tree binding
 */

static int
acpica_find_pcibus(int busno, ACPI_HANDLE *rh)
{
	ACPI_HANDLE sbobj, busobj;
	int hid, bbn;

	/* initialize static flag by querying ACPI namespace for bug */
	if (acpi_has_broken_bbn == -1)
		acpi_has_broken_bbn = acpica_query_bbn_problem();

	busobj = NULL;
	AcpiGetHandle(NULL, "\\_SB", &sbobj);
	while (AcpiGetNextObject(ACPI_TYPE_DEVICE, sbobj, busobj,
	    &busobj) == AE_OK) {
		if (acpica_eval_hid(busobj, "_HID", &hid) == AE_OK &&
		    (hid == HID_PCI_BUS || hid == HID_PCI_EXPRESS_BUS)) {
			if (acpi_has_broken_bbn) {
				ACPI_BUFFER rb;
				rb.Pointer = NULL;
				rb.Length = ACPI_ALLOCATE_BUFFER;

				/* Decree _BBN == n from PCI<n> */
				if (AcpiGetName(busobj, ACPI_SINGLE_NAME, &rb)
					    != AE_OK) {
					return (AE_ERROR);
				}
				bbn = ((char *)rb.Pointer)[3] - '0';
				AcpiOsFree(rb.Pointer);
				if (bbn == busno || busno == 0) {
					*rh = busobj;
					return (AE_OK);
				}
			} else {
				if (acpica_eval_int(busobj, "_BBN", &bbn) ==
				    AE_OK) {
					if (bbn == busno) {
						*rh = busobj;
						return (AE_OK);
					}
				} else if (busno == 0) {
					*rh = busobj;
					return (AE_OK);
				}
			}
		}
	}
	return (AE_ERROR);
}


/*
 * Look for ACPI problem where _BBN is zero for multiple PCI buses
 * This is a clear ACPI bug, but we have a workaround in acpica_find_pcibus()
 * below if it exists.
 */
static int
acpica_query_bbn_problem(void)
{
	ACPI_HANDLE sbobj, busobj;
	int hid, bbn;
	int zerobbncnt;

	busobj = NULL;
	zerobbncnt = 0;

	AcpiGetHandle(NULL, "\\_SB", &sbobj);

	while (AcpiGetNextObject(ACPI_TYPE_DEVICE, sbobj, busobj,
	    &busobj) == AE_OK) {
		if ((acpica_eval_hid(busobj, "_HID", &hid) == AE_OK) &&
		    (hid == HID_PCI_BUS || hid == HID_PCI_EXPRESS_BUS) &&
		    (acpica_eval_int(busobj, "_BBN", &bbn) == AE_OK)) {
			if (bbn == 0) {
			/*
			 * If we find more than one bus with a 0 _BBN
			 * we have the problem that BigBear's BIOS shows
			 */
				if (++zerobbncnt > 1)
					return (1);
			}
		}
	}
	return (0);
}

static const char hextab[] = "0123456789ABCDEF";

static int
hexdig(int c)
{
	/*
	 *  Get hex digit:
	 *
	 *  Returns the 4-bit hex digit named by the input character.  Returns
	 *  zero if the input character is not valid hex!
	 */

	int x = ((c < 'a') || (c > 'z')) ? c : (c - ' ');
	int j = sizeof (hextab);

	while (--j && (x != hextab[j]));
	return (j);
}

static int
CompressEisaID(char *np)
{
	/*
	 *  Compress an EISA device name:
	 *
	 *  This routine converts a 7-byte ASCII device name into the 4-byte
	 *  compressed form used by EISA (50 bytes of ROM to save 1 byte of
	 *  NV-RAM!)
	 */

	union { char octets[4]; int retval; } myu;

	myu.octets[0] = ((np[0] & 0x1F) << 2) + ((np[1] >> 3) & 0x03);
	myu.octets[1] = ((np[1] & 0x07) << 5) + (np[2] & 0x1F);
	myu.octets[2] = (hexdig(np[3]) << 4) + hexdig(np[4]);
	myu.octets[3] = (hexdig(np[5]) << 4) + hexdig(np[6]);

	return (myu.retval);
}

int
acpica_eval_int(ACPI_HANDLE dev, char *method, int *rint)
{
	ACPI_STATUS status;
	ACPI_BUFFER rb;
	ACPI_OBJECT ro;

	rb.Pointer = &ro;
	rb.Length = sizeof (ro);
	if ((status = AcpiEvaluateObjectTyped(dev, method, NULL, &rb,
						ACPI_TYPE_INTEGER)) == AE_OK)
		*rint = ro.Integer.Value;

	return (status);
}

static int
acpica_eval_hid(ACPI_HANDLE dev, char *method, int *rint)
{
	ACPI_BUFFER rb;
	ACPI_OBJECT *rv;

	rb.Pointer = NULL;
	rb.Length = ACPI_ALLOCATE_BUFFER;
	if (AcpiEvaluateObject(dev, method, NULL, &rb) == AE_OK) {
		rv = rb.Pointer;
		if (rv->Type == ACPI_TYPE_INTEGER) {
			*rint = rv->Integer.Value;
			AcpiOsFree(rv);
			return (AE_OK);
		} else if (rv->Type == ACPI_TYPE_STRING) {
			char *stringData;

			/* Convert the string into an EISA ID */
			if (rv->String.Pointer == NULL) {
				AcpiOsFree(rv);
				return (AE_ERROR);
			}

			stringData = rv->String.Pointer;

			/*
			 * If the string is an EisaID, it must be 7
			 * characters; if it's an ACPI ID, it will be 8
			 * (and we don't care about ACPI ids here).
			 */
			if (strlen(stringData) != 7) {
				AcpiOsFree(rv);
				return (AE_ERROR);
			}

			*rint = CompressEisaID(stringData);
			AcpiOsFree(rv);
			return (AE_OK);
		} else
			AcpiOsFree(rv);
	}
	return (AE_ERROR);
}

/*
 * Return the d2a node matching this ACPI_HANDLE, if one exists
 */
int
acpica_find_pcid2a(ACPI_HANDLE rh, d2a **dp)
{
	d2a *d2ap;
	int i;

	if (d2a_len == 0)
		create_d2a_map();
	for (d2ap = d2a_table, i = 0; i < d2a_valid; d2ap++, i++)
		if (d2ap->acpiobj == rh) {
			*dp = d2ap;
			return (AE_OK);
		}

	return (AE_ERROR);
}


/*
 * Return the ACPI device node matching this dev_info node, if it
 * exists in the ACPI tree.
 */
int
acpica_find_pciobj(dev_info_t *dip, ACPI_HANDLE *rh)
{
	d2a *d2ap;
	int i;

	if (d2a_len == 0)
		create_d2a_map();
	for (d2ap = d2a_table, i = 0; i < d2a_valid; d2ap++, i++)
		if (d2ap->dip == dip) {
			*rh = d2ap->acpiobj;
			return (AE_OK);
		}

	return (AE_ERROR);
}

/*
 * Create a table mapping PCI dips to ACPI objects
 */
static void
new_d2a_entry(dev_info_t *dip, ACPI_HANDLE acpiobj, int bus, int dev, int func)
{
	int newsize;
	d2a *new_arr, *ep;

	if (d2a_valid >= d2a_len) {
		/* initially, or re-, allocate array */

		newsize = (d2a_len ? d2a_len * 2 : D2A_INITLEN);
		new_arr = kmem_zalloc(newsize * sizeof (d2a), KM_SLEEP);
		if (d2a_len != 0) {
			/* realloc: copy data, free old */
			bcopy(d2a_table, new_arr, d2a_len * sizeof (d2a));
			kmem_free(d2a_table, d2a_len * sizeof (d2a));
		}
		d2a_len = newsize;
		d2a_table = new_arr;
	}
	ep = &d2a_table[d2a_valid++];
	ep->bus = (unsigned char)bus;
	ep->dev = (unsigned char)dev;
	ep->func = (unsigned char)func;
	ep->dip = dip;
	ep->acpiobj = acpiobj;
#ifdef D2ADEBUG
	{
		ACPI_BUFFER rb;
		char pathname[60];
		ddi_pathname(dip, pathname);

		rb.Pointer = NULL;
		rb.Length = ACPI_ALLOCATE_BUFFER;
		if (AcpiGetName(acpiobj, ACPI_FULL_PATHNAME, &rb) == AE_OK) {

			cmn_err(CE_NOTE, "d2a entry: %s %s %d/0x%x/%d",
				pathname, (char *)rb.Pointer, bus, dev, func);
			AcpiOsFree(rb.Pointer);
		}
	}
#endif
}

static void
create_d2a_map(void)
{
	dev_info_t *dip, *cdip;
	ACPI_HANDLE acpiobj;
	char *device_type_prop;
	int bus;
	static int map_error = 0;

	if (map_error)
		return;

	creating_d2a_map = 1;

	/*
	 * Find all child-of-root PCI buses, and find their corresponding
	 * ACPI child-of-root PCI nodes.  For each one, add to the
	 * d2a table.
	 */

	for (dip = ddi_get_child(ddi_root_node());
	    dip != NULL;
	    dip = ddi_get_next_sibling(dip)) {

		/* prune non-PCI nodes */
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0,
		    "device_type", &device_type_prop) != DDI_PROP_SUCCESS)
			continue;

		if ((strcmp("pci", device_type_prop) != 0) &&
		    (strcmp("pciex", device_type_prop) != 0)) {
			ddi_prop_free(device_type_prop);
			continue;
		}

		ddi_prop_free(device_type_prop);

		/*
		 * To get bus number of dip, get first child and get its
		 * bus number.  If NULL, just continue, because we don't
		 * care about bus nodes with no children anyway.
		 */
		if ((cdip = ddi_get_child(dip)) == NULL)
			continue;

		if (acpica_get_bdf(cdip, &bus, NULL, NULL) < 0) {
#ifdef D2ADEBUG
			cmn_err(CE_WARN, "Can't get bus number of PCI child?");
#endif
			map_error = 1;
			creating_d2a_map = 0;
			return;
		}

		if (acpica_find_pcibus(bus, &acpiobj) == AE_ERROR) {
#ifdef D2ADEBUG
			cmn_err(CE_WARN, "No ACPI bus obj for bus %d?\n", bus);
#endif
			map_error = 1;
			continue;
		}

		/*
		 * map this node, with illegal device and fn numbers
		 * (since, as a PCI root node, it exists on the system
		 * bus
		 */

		new_d2a_entry(dip, acpiobj, bus, 32, 8);

		/* call recursive function to enumerate subtrees */
		create_d2a_subtree(dip, acpiobj, bus);
	}
	creating_d2a_map = 0;
}

/*
 * For all acpi child devices of acpiobj, find their matching
 * dip under "dip" argument.  (matching means "matches dev/fn").
 * bus is assumed to already be a match from caller, and is
 * used here only to record in the d2a entry.  Recurse if necessary.
 */
static void
create_d2a_subtree(dev_info_t *dip, ACPI_HANDLE acpiobj, int bus)
{
	int acpi_devfn, hid;
	ACPI_HANDLE acld;
	dev_info_t *dcld;
	int dcld_b, dcld_d, dcld_f;
	int dev, func;

	acld = NULL;
	while (AcpiGetNextObject(ACPI_TYPE_ANY, acpiobj, acld, &acld)
	    == AE_OK) {

		/*
		 * Skip ACPI devices that are obviously not PCI, i.e.,
		 * that have a _HID that is *not* the PCI HID
		 */

		if (acpica_eval_hid(acld, "_HID", &hid) == AE_OK &&
		    hid != HID_PCI_BUS && hid != HID_PCI_EXPRESS_BUS)
			continue;

		/* get the dev/func we're looking for in the devinfo tree */
		if (acpica_eval_int(acld, "_ADR", &acpi_devfn) != AE_OK)
			continue;
		dev = (acpi_devfn >> 16) & 0xFFFF;
		func = acpi_devfn & 0xFFFF;

		/* look through all the immediate children of dip */
		for (dcld = ddi_get_child(dip); dcld != NULL;
		    dcld = ddi_get_next_sibling(dcld)) {
			if (acpica_get_bdf(dcld, &dcld_b, &dcld_d, &dcld_f) < 0)
				continue;

			/* dev must match; function must match or wildcard */
			if (dcld_d != dev ||
			    (func != 0xFFFF && func != dcld_f))
				continue;
			bus = dcld_b;

			/* found a match, record it */
			new_d2a_entry(dcld, acld, bus, dev, func);

			/* recurse from here to pick up child trees */
			create_d2a_subtree(dcld, acld, bus);

			/* done finding a match, so break now */
			break;
		}
	}
}

/*
 * Return bus/dev/fn for PCI dip (note: not the parent "pci" node).
 */

int
acpica_get_bdf(dev_info_t *dip, int *bus, int *device, int *func)
{
	pci_regspec_t *pci_rp;
	int len;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (int **)&pci_rp, (uint_t *)&len) != DDI_SUCCESS)
		return (-1);

	if (len < (sizeof (pci_regspec_t) / sizeof (int))) {
		ddi_prop_free(pci_rp);
		return (-1);
	}
	if (bus != NULL)
		*bus = (int)PCI_REG_BUS_G(pci_rp->pci_phys_hi);
	if (device != NULL)
		*device = (int)PCI_REG_DEV_G(pci_rp->pci_phys_hi);
	if (func != NULL)
		*func = (int)PCI_REG_FUNC_G(pci_rp->pci_phys_hi);
	ddi_prop_free(pci_rp);
	return (0);
}
