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
 * ACPI CA OSL for Solaris x86
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/psm.h>
#include <sys/pci_cfgspace.h>
#include <sys/ddi.h>
#include <sys/sunndi.h>
#include <sys/pci.h>
#include <sys/kobj.h>
#include <sys/taskq.h>
#include <sys/strlog.h>
#include <sys/note.h>

#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpi/acinterp.h>

#define	MAX_DAT_FILE_SIZE	(64*1024)

/* local functions */
static int CompressEisaID(char *np);

static void scan_d2a_map(void);
static void scan_d2a_subtree(dev_info_t *dip, ACPI_HANDLE acpiobj, int bus);
static void acpica_tag_devinfo(dev_info_t *dip, ACPI_HANDLE acpiobj);

static int acpica_query_bbn_problem(void);
static int acpica_find_pcibus(int busno, ACPI_HANDLE *rh);
static int acpica_eval_hid(ACPI_HANDLE dev, char *method, int *rint);
static ACPI_STATUS acpica_set_devinfo(ACPI_HANDLE, dev_info_t *);
static void acpica_devinfo_handler(ACPI_HANDLE, UINT32, void *);

/*
 * Event queue vars
 */
int acpica_eventq_thread_count = 1;
int acpica_eventq_init = 0;
ddi_taskq_t *osl_eventq[OSL_EC_BURST_HANDLER+1];

/*
 * Note, if you change this path, you need to update
 * /boot/grub/filelist.ramdisk and pkg SUNWckr/prototype_i386
 */
static char *acpi_table_path = "/boot/acpi/tables/";

/* non-zero while scan_d2a_map() is working */
static int scanning_d2a_map = 0;
static int d2a_done = 0;

/* set by acpi_poweroff() in PSMs */
int acpica_powering_off = 0;

/* CPU mapping data */
struct cpu_map_item {
	UINT32		proc_id;
	ACPI_HANDLE	obj;
};

static struct cpu_map_item **cpu_map = NULL;
static int cpu_map_count = 0;
static int cpu_map_built = 0;

static int acpi_has_broken_bbn = -1;

/* buffer for AcpiOsVprintf() */
#define	ACPI_OSL_PR_BUFLEN	1024
static char *acpi_osl_pr_buffer = NULL;
static int acpi_osl_pr_buflen;

#define	D2A_DEBUG

/*
 *
 */
static void
discard_event_queues()
{
	int	i;

	/*
	 * destroy event queues
	 */
	for (i = OSL_GLOBAL_LOCK_HANDLER; i <= OSL_EC_BURST_HANDLER; i++) {
		if (osl_eventq[i])
			ddi_taskq_destroy(osl_eventq[i]);
	}
}


/*
 *
 */
static ACPI_STATUS
init_event_queues()
{
	char	namebuf[32];
	int	i, error = 0;

	/*
	 * Initialize event queues
	 */

	for (i = OSL_GLOBAL_LOCK_HANDLER; i <= OSL_EC_BURST_HANDLER; i++) {
		snprintf(namebuf, 32, "ACPI%d", i);
		osl_eventq[i] = ddi_taskq_create(NULL, namebuf,
		    acpica_eventq_thread_count, TASKQ_DEFAULTPRI, 0);
		if (osl_eventq[i] == NULL)
			error++;
	}

	if (error != 0) {
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
 * One-time initialization of OSL layer
 */
ACPI_STATUS
AcpiOsInitialize(void)
{
	/*
	 * Allocate buffer for AcpiOsVprintf() here to avoid
	 * kmem_alloc()/kmem_free() at high PIL
	 */
	acpi_osl_pr_buffer = kmem_alloc(ACPI_OSL_PR_BUFLEN, KM_SLEEP);
	if (acpi_osl_pr_buffer != NULL)
		acpi_osl_pr_buflen = ACPI_OSL_PR_BUFLEN;

	return (AE_OK);
}

/*
 * One-time shut-down of OSL layer
 */
ACPI_STATUS
AcpiOsTerminate(void)
{

	if (acpi_osl_pr_buffer != NULL)
		kmem_free(acpi_osl_pr_buffer, acpi_osl_pr_buflen);

	discard_event_queues();
	return (AE_OK);
}


ACPI_STATUS
AcpiOsGetRootPointer(UINT32 Flags, ACPI_POINTER *Address)
{
	uint_t acpi_root_tab;

	/*
	 * For EFI firmware, the root pointer is defined in EFI systab.
	 * The boot code process the table and put the physical address
	 * in the acpi-root-tab property.
	 */
	acpi_root_tab = ddi_prop_get_int(DDI_DEV_T_ANY, ddi_root_node(), 0,
	    "acpi-root-tab", 0);
	if (acpi_root_tab != 0) {
		Address->PointerType = ACPI_PHYSICAL_POINTER;
		Address->Pointer.Physical = acpi_root_tab;
		return (AE_OK);
	}
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


/*
 * ACPI semaphore implementation
 */
typedef struct {
	kmutex_t	mutex;
	kcondvar_t	cv;
	uint32_t	available;
	uint32_t	initial;
	uint32_t	maximum;
} acpi_sema_t;

/*
 *
 */
void
acpi_sema_init(acpi_sema_t *sp, unsigned max, unsigned count)
{
	mutex_init(&sp->mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&sp->cv, NULL, CV_DRIVER, NULL);
	/* no need to enter mutex here at creation */
	sp->available = count;
	sp->initial = count;
	sp->maximum = max;
}

/*
 *
 */
void
acpi_sema_destroy(acpi_sema_t *sp)
{

	cv_destroy(&sp->cv);
	mutex_destroy(&sp->mutex);
}

/*
 *
 */
ACPI_STATUS
acpi_sema_p(acpi_sema_t *sp, unsigned count, uint16_t wait_time)
{
	ACPI_STATUS rv = AE_OK;
	clock_t deadline;

	mutex_enter(&sp->mutex);

	if (sp->available >= count) {
		/*
		 * Enough units available, no blocking
		 */
		sp->available -= count;
		mutex_exit(&sp->mutex);
		return (rv);
	} else if (wait_time == 0) {
		/*
		 * Not enough units available and timeout
		 * specifies no blocking
		 */
		rv = AE_TIME;
		mutex_exit(&sp->mutex);
		return (rv);
	}

	/*
	 * Not enough units available and timeout specifies waiting
	 */
	if (wait_time != ACPI_WAIT_FOREVER)
		deadline = ddi_get_lbolt() +
		    (clock_t)drv_usectohz(wait_time * 1000);

	do {
		if (wait_time == ACPI_WAIT_FOREVER)
			cv_wait(&sp->cv, &sp->mutex);
		else if (cv_timedwait(&sp->cv, &sp->mutex, deadline) < 0) {
			rv = AE_TIME;
			break;
		}
	} while (sp->available < count);

	/* if we dropped out of the wait with AE_OK, we got the units */
	if (rv == AE_OK)
		sp->available -= count;

	mutex_exit(&sp->mutex);
	return (rv);
}

/*
 *
 */
void
acpi_sema_v(acpi_sema_t *sp, unsigned count)
{
	mutex_enter(&sp->mutex);
	sp->available += count;
	cv_broadcast(&sp->cv);
	mutex_exit(&sp->mutex);
}


ACPI_STATUS
AcpiOsCreateSemaphore(UINT32 MaxUnits, UINT32 InitialUnits,
ACPI_HANDLE *OutHandle)
{
	acpi_sema_t *sp;

	if ((OutHandle == NULL) || (InitialUnits > MaxUnits))
		return (AE_BAD_PARAMETER);

	sp = (acpi_sema_t *)kmem_alloc(sizeof (acpi_sema_t), KM_SLEEP);
	acpi_sema_init(sp, MaxUnits, InitialUnits);
	*OutHandle = (ACPI_HANDLE)sp;
	return (AE_OK);
}


ACPI_STATUS
AcpiOsDeleteSemaphore(ACPI_HANDLE Handle)
{

	if (Handle == NULL)
		return (AE_BAD_PARAMETER);

	acpi_sema_destroy((acpi_sema_t *)Handle);
	kmem_free((void *)Handle, sizeof (acpi_sema_t));
	return (AE_OK);
}

ACPI_STATUS
AcpiOsWaitSemaphore(ACPI_HANDLE Handle, UINT32 Units, UINT16 Timeout)
{

	if ((Handle == NULL) || (Units < 1))
		return (AE_BAD_PARAMETER);

	return (acpi_sema_p((acpi_sema_t *)Handle, Units, Timeout));
}

ACPI_STATUS
AcpiOsSignalSemaphore(ACPI_HANDLE Handle, UINT32 Units)
{

	if ((Handle == NULL) || (Units < 1))
		return (AE_BAD_PARAMETER);

	acpi_sema_v((acpi_sema_t *)Handle, Units);
	return (AE_OK);
}

ACPI_STATUS
AcpiOsCreateLock(ACPI_HANDLE *OutHandle)
{
	kmutex_t *mp;

	if (OutHandle == NULL)
		return (AE_BAD_PARAMETER);

	mp = (kmutex_t *)kmem_alloc(sizeof (kmutex_t), KM_SLEEP);
	mutex_init(mp, NULL, MUTEX_DRIVER, NULL);
	*OutHandle = (ACPI_HANDLE)mp;
	return (AE_OK);
}

void
AcpiOsDeleteLock(ACPI_HANDLE Handle)
{

	if (Handle == NULL)
		return;

	mutex_destroy((kmutex_t *)Handle);
	kmem_free((void *)Handle, sizeof (kmutex_t));
}

ACPI_NATIVE_UINT
AcpiOsAcquireLock(ACPI_HANDLE Handle)
{

	if (Handle == NULL)
		return (AE_BAD_PARAMETER);

	mutex_enter((kmutex_t *)Handle);
	return (AE_OK);
}

void
AcpiOsReleaseLock(ACPI_HANDLE Handle, ACPI_NATIVE_UINT Flags)
{
	_NOTE(ARGUNUSED(Flags))

	if (Handle == NULL)
		return;

	mutex_exit((kmutex_t *)Handle);
}


void *
AcpiOsAllocate(ACPI_SIZE Size)
{
	ACPI_SIZE *tmp_ptr;

	Size += sizeof (Size);
	tmp_ptr = (ACPI_SIZE *)kmem_zalloc(Size, KM_SLEEP);
	*tmp_ptr++ = Size;
	return (tmp_ptr);
}

void
AcpiOsFree(void *Memory)
{
	ACPI_SIZE	size, *tmp_ptr;

	tmp_ptr = (ACPI_SIZE *)Memory;
	tmp_ptr -= 1;
	size = *tmp_ptr;
	kmem_free(tmp_ptr, size);
}

ACPI_STATUS
AcpiOsMapMemory(ACPI_PHYSICAL_ADDRESS PhysicalAddress,
		    ACPI_SIZE Size, void **LogicalAddress)
{
	/* FUTUREWORK: test PhysicalAddress for > 32 bits */
	*LogicalAddress = psm_map_new((paddr_t)PhysicalAddress,
	    (size_t)Size, PSM_PROT_WRITE | PSM_PROT_READ);

	return (*LogicalAddress == NULL ? AE_NO_MEMORY : AE_OK);
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
	return (AE_NOT_IMPLEMENTED);
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

static int acpi_intr_hooked = 0;

ACPI_STATUS
AcpiOsInstallInterruptHandler(UINT32 InterruptNumber,
		ACPI_OSD_HANDLER ServiceRoutine,
		void *Context)
{
	_NOTE(ARGUNUSED(InterruptNumber))

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
	    "ACPI SCI", sci_vect, NULL, NULL, NULL, NULL);
	if (retval) {
		acpi_intr_hooked = 1;
		return (AE_OK);
	} else
		return (AE_BAD_PARAMETER);
}

ACPI_STATUS
AcpiOsRemoveInterruptHandler(UINT32 InterruptNumber,
			ACPI_OSD_HANDLER ServiceRoutine)
{
	_NOTE(ARGUNUSED(ServiceRoutine))

#ifdef	DEBUG
	cmn_err(CE_NOTE, "!acpica: detaching SCI %d", InterruptNumber);
#endif
	if (acpi_intr_hooked) {
		rem_avintr(NULL, LOCK_LEVEL - 1, (avfunc)acpi_wrapper_isr,
		    InterruptNumber);
		acpi_intr_hooked = 0;
	}
	return (AE_OK);
}


ACPI_THREAD_ID
AcpiOsGetThreadId(void)
{
	/*
	 * ACPI CA regards thread ID as an error, but it's valid
	 * on Solaris during kernel initialization.  Thus, 1 is added
	 * to the kernel thread ID to avoid returning 0
	 */
	return (ddi_get_kt_did() + 1);
}

/*
 *
 */
ACPI_STATUS
AcpiOsExecute(ACPI_EXECUTE_TYPE Type, ACPI_OSD_EXEC_CALLBACK  Function,
    void *Context)
{

	if (!acpica_eventq_init) {
		/*
		 * Create taskqs for event handling
		 */
		if (init_event_queues() != AE_OK)
			return (AE_ERROR);
	}

	if (ddi_taskq_dispatch(osl_eventq[Type], Function, Context,
	    DDI_NOSLEEP) == DDI_FAILURE) {
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
	 * delay; very late in kernel shutdown, clock interrupts
	 * are blocked, so delay doesn't work then either.
	 * So we busy wait if lbolt == 0 (kernel startup)
	 * or if psm_shutdown() has set acpi_powering_off to
	 * a non-zero value.
	 */
	if ((ddi_get_lbolt() == 0) || acpica_powering_off)
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
		    (PciId->Bus, PciId->Device, PciId->Function, Register);
		break;
	case 16:
		*((UINT64 *)Value) = (UINT64)(*pci_getw_func)
		    (PciId->Bus, PciId->Device, PciId->Function, Register);
		break;
	case 32:
		*((UINT64 *)Value) = (UINT64)(*pci_getl_func)
		    (PciId->Bus, PciId->Device, PciId->Function, Register);
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
 * Called with ACPI_HANDLEs for both a PCI Config Space
 * OpRegion and (what ACPI CA thinks is) the PCI device
 * to which this ConfigSpace OpRegion belongs.  Since
 * ACPI CA depends on a valid _BBN object being present
 * and this is not always true (one old x86 had broken _BBN),
 * we go ahead and get the correct PCI bus number using the
 * devinfo mapping (which compensates for broken _BBN).
 *
 * Default values for bus, segment, device and function are
 * all 0 when ACPI CA can't figure them out.
 *
 * Some BIOSes implement _BBN() by reading PCI config space
 * on bus #0 - which means that we'll recurse when we attempt
 * to create the devinfo-to-ACPI map.  If Derive is called during
 * scan_d2a_map, we don't translate the bus # and return.
 *
 * We get the parent of the OpRegion, which must be a PCI
 * node, fetch the associated devinfo node and snag the
 * b/d/f from it.
 */
void
AcpiOsDerivePciId(ACPI_HANDLE rhandle, ACPI_HANDLE chandle,
		ACPI_PCI_ID **PciId)
{
	ACPI_HANDLE handle;
	dev_info_t *dip;
	int bus, device, func, devfn;


	/*
	 * See above - avoid recursing during scanning_d2a_map.
	 */
	if (scanning_d2a_map)
		return;

	/*
	 * Get the OpRegion's parent
	 */
	if (AcpiGetParent(chandle, &handle) != AE_OK)
		return;

	/*
	 * If we've mapped the ACPI node to the devinfo
	 * tree, use the devinfo reg property
	 */
	if (acpica_get_devinfo(handle, &dip) == AE_OK) {
		(void) acpica_get_bdf(dip, &bus, &device, &func);
		(*PciId)->Bus = bus;
		(*PciId)->Device = device;
		(*PciId)->Function = func;
	} else if (acpica_eval_int(handle, "_ADR", &devfn) == AE_OK) {
		/* no devinfo node - just confirm the d/f */
		(*PciId)->Device = (devfn >> 16) & 0xFFFF;
		(*PciId)->Function = devfn & 0xFFFF;
	}
}


/*ARGSUSED*/
BOOLEAN
AcpiOsReadable(void *Pointer, ACPI_SIZE Length)
{

	/* Always says yes; all mapped memory assumed readable */
	return (1);
}

/*ARGSUSED*/
BOOLEAN
AcpiOsWritable(void *Pointer, ACPI_SIZE Length)
{

	/* Always says yes; all mapped memory assumed writable */
	return (1);
}

UINT64
AcpiOsGetTimer(void)
{
	/* gethrtime() returns 1nS resolution; convert to 100nS granules */
	return ((gethrtime() + 50) / 100);
}

/*ARGSUSED*/
ACPI_STATUS
AcpiOsValidateInterface(char *interface)
{
	return (AE_SUPPORT);
}

/*ARGSUSED*/
ACPI_STATUS
AcpiOsValidateAddress(UINT8 spaceid, ACPI_PHYSICAL_ADDRESS addr,
    ACPI_SIZE length)
{
	return (AE_OK);
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

	va_start(ap, Format);
	AcpiOsVprintf(Format, ap);
	va_end(ap);
}

/*
 * When != 0, sends output to console
 * Patchable with kmdb or /etc/system.
 */
int acpica_console_out = 0;

#define	ACPICA_OUTBUF_LEN	160
char	acpica_outbuf[ACPICA_OUTBUF_LEN];
int	acpica_outbuf_offset;

/*
 *
 */
static void
acpica_pr_buf(char *buf)
{
	char c, *bufp, *outp;
	int	out_remaining;

	/*
	 * copy the supplied buffer into the output buffer
	 * when we hit a '\n' or overflow the output buffer,
	 * output and reset the output buffer
	 */
	bufp = buf;
	outp = acpica_outbuf + acpica_outbuf_offset;
	out_remaining = ACPICA_OUTBUF_LEN - acpica_outbuf_offset - 1;
	while (c = *bufp++) {
		*outp++ = c;
		if (c == '\n' || --out_remaining == 0) {
			*outp = '\0';
			if (acpica_console_out)
				printf(acpica_outbuf);
			else
				(void) strlog(0, 0, 0,
				    SL_CONSOLE | SL_NOTE | SL_LOGONLY,
				    acpica_outbuf);
			acpica_outbuf_offset = 0;
			outp = acpica_outbuf;
			out_remaining = ACPICA_OUTBUF_LEN - 1;
		}
	}

	acpica_outbuf_offset = outp - acpica_outbuf;
}

void
AcpiOsVprintf(const char *Format, va_list Args)
{

	/*
	 * If AcpiOsInitialize() failed to allocate a string buffer,
	 * resort to vprintf().
	 */
	if (acpi_osl_pr_buffer == NULL) {
		vprintf(Format, Args);
		return;
	}

	/*
	 * It is possible that a very long debug output statement will
	 * be truncated; this is silently ignored.
	 */
	(void) vsnprintf(acpi_osl_pr_buffer, acpi_osl_pr_buflen, Format, Args);
	acpica_pr_buf(acpi_osl_pr_buffer);
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

	while (--j && (x != hextab[j])) {
	}
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

ACPI_STATUS
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
 * Create linkage between devinfo nodes and ACPI nodes
 */
static void
acpica_tag_devinfo(dev_info_t *dip, ACPI_HANDLE acpiobj)
{
	ACPI_STATUS status;
	ACPI_BUFFER rb;

	/*
	 * Tag the ACPI node with the dip
	 */
	status = acpica_set_devinfo(acpiobj, dip);
	ASSERT(status == AE_OK);

	/*
	 * Tag the devinfo node with the ACPI name
	 */
	rb.Pointer = NULL;
	rb.Length = ACPI_ALLOCATE_BUFFER;
	if (AcpiGetName(acpiobj, ACPI_FULL_PATHNAME, &rb) == AE_OK) {
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "acpi-namespace", (char *)rb.Pointer);
		AcpiOsFree(rb.Pointer);
	} else {
		cmn_err(CE_WARN, "acpica: could not get ACPI path!");
	}
}

static void
acpica_add_processor_to_map(UINT32 acpi_id, ACPI_HANDLE obj)
{
	int	cpu_id;

	/*
	 * Special case: if we're a uppc system, there won't be
	 * a CPU map yet.  So we create one and use the passed-in
	 * processor as CPU 0
	 */
	if (cpu_map == NULL) {
		cpu_map = kmem_zalloc(sizeof (cpu_map[0]) * NCPU, KM_SLEEP);
		cpu_map[0] = kmem_zalloc(sizeof (*cpu_map[0]), KM_SLEEP);
		cpu_map[0]->obj = obj;
		cpu_map_count = 1;
		return;
	}

	for (cpu_id = 0; cpu_id < NCPU; cpu_id++) {
		if (cpu_map[cpu_id] == NULL)
			continue;

		if (cpu_map[cpu_id]->proc_id == acpi_id) {
			if (cpu_map[cpu_id]->obj == NULL)
				cpu_map[cpu_id]->obj = obj;
			break;
		}
	}

}

/*
 * Return the ACPI device node matching the CPU dev_info node.
 */
ACPI_STATUS
acpica_get_handle_cpu(dev_info_t *dip, ACPI_HANDLE *rh)
{
	char	*device_type_prop;
	int	cpu_id;

	/*
	 * if "device_type" != "cpu", error
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0,
	    "device_type", &device_type_prop) != DDI_PROP_SUCCESS)
		return (AE_ERROR);

	if (strcmp("cpu", device_type_prop) != 0) {
		ddi_prop_free(device_type_prop);
		return (AE_ERROR);
	}
	ddi_prop_free(device_type_prop);

	/*
	 * if cpu_map itself is NULL, we're a uppc system and
	 * acpica_build_processor_map() hasn't been called yet.
	 * So call it here
	 */
	if (cpu_map == NULL) {
		(void) acpica_build_processor_map();
		if (cpu_map == NULL)
			return (AE_ERROR);
	}

	/*
	 * get 'reg' and get obj from cpu_map
	 */
	cpu_id = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", -1);
	if ((cpu_id < 0) || (cpu_map[cpu_id] == NULL) ||
	    (cpu_map[cpu_id]->obj == NULL))
		return (AE_ERROR);

	/*
	 * tag devinfo and obj
	 */
	(void) acpica_tag_devinfo(dip, cpu_map[cpu_id]->obj);
	*rh = cpu_map[cpu_id]->obj;
	return (AE_OK);
}

/*
 * Determine if this object is a processor
 */
static ACPI_STATUS
acpica_probe_processor(ACPI_HANDLE obj, UINT32 level, void *ctx, void **rv)
{
	ACPI_STATUS status;
	ACPI_OBJECT_TYPE objtype;
	UINT32 acpi_id;
	ACPI_BUFFER rb;

	if (AcpiGetType(obj, &objtype) != AE_OK)
		return (AE_OK);

	if (objtype == ACPI_TYPE_PROCESSOR) {
		/* process a Processor */
		rb.Pointer = NULL;
		rb.Length = ACPI_ALLOCATE_BUFFER;
		status = AcpiEvaluateObject(obj, NULL, NULL, &rb);
		if (status != AE_OK) {
			cmn_err(CE_WARN, "acpica: error probing Processor");
			return (status);
		}
		ASSERT(((ACPI_OBJECT *)rb.Pointer)->Type ==
		    ACPI_TYPE_PROCESSOR);
		acpi_id = ((ACPI_OBJECT *)rb.Pointer)->Processor.ProcId;
		AcpiOsFree(rb.Pointer);
	} else if (objtype == ACPI_TYPE_DEVICE) {
		/* process a processor Device */
		rb.Pointer = NULL;
		rb.Length = ACPI_ALLOCATE_BUFFER;
		status = AcpiGetObjectInfo(obj, &rb);
		if (status != AE_OK) {
			cmn_err(CE_WARN,
			    "acpica: error probing Processor Device\n");
			return (status);
		}
		ASSERT(((ACPI_OBJECT *)rb.Pointer)->Type ==
		    ACPI_TYPE_DEVICE);
		acpi_id = AcpiExStringToUnsignedInteger(
		    ((ACPI_DEVICE_INFO *)rb.Pointer)->UniqueId.Value);
		AcpiOsFree(rb.Pointer);
	}

	acpica_add_processor_to_map(acpi_id, obj);
	return (AE_OK);
}


static void
scan_d2a_map(void)
{
	dev_info_t *dip, *cdip;
	ACPI_HANDLE acpiobj;
	char *device_type_prop;
	int bus;
	static int map_error = 0;

	if (map_error)
		return;

	scanning_d2a_map = 1;

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
			scanning_d2a_map = 0;
			d2a_done = 1;
			return;
		}

		if (acpica_find_pcibus(bus, &acpiobj) == AE_ERROR) {
#ifdef D2ADEBUG
			cmn_err(CE_WARN, "No ACPI bus obj for bus %d?\n", bus);
#endif
			map_error = 1;
			continue;
		}

		acpica_tag_devinfo(dip, acpiobj);

		/* call recursively to enumerate subtrees */
		scan_d2a_subtree(dip, acpiobj, bus);
	}

	scanning_d2a_map = 0;
	d2a_done = 1;
}

/*
 * For all acpi child devices of acpiobj, find their matching
 * dip under "dip" argument.  (matching means "matches dev/fn").
 * bus is assumed to already be a match from caller, and is
 * used here only to record in the d2a entry.  Recurse if necessary.
 */
static void
scan_d2a_subtree(dev_info_t *dip, ACPI_HANDLE acpiobj, int bus)
{
	int acpi_devfn, hid;
	ACPI_HANDLE acld;
	dev_info_t *dcld;
	int dcld_b, dcld_d, dcld_f;
	int dev, func;
	char *device_type_prop;

	acld = NULL;
	while (AcpiGetNextObject(ACPI_TYPE_DEVICE, acpiobj, acld, &acld)
	    == AE_OK) {
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
			acpica_tag_devinfo(dcld, acld);

			/* if we find a bridge, recurse from here */
			if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dcld, 0,
			    "device_type", &device_type_prop) ==
			    DDI_PROP_SUCCESS) {
				if ((strcmp("pci", device_type_prop) == 0) ||
				    (strcmp("pciex", device_type_prop) == 0))
					scan_d2a_subtree(dcld, acld, bus);
				ddi_prop_free(device_type_prop);
			}

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

/*
 * Return the ACPI device node matching this dev_info node, if it
 * exists in the ACPI tree.
 */
ACPI_STATUS
acpica_get_handle(dev_info_t *dip, ACPI_HANDLE *rh)
{
	ACPI_STATUS status;
	char *acpiname;

	if (!d2a_done)
		scan_d2a_map();

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "acpi-namespace", &acpiname) != DDI_PROP_SUCCESS) {
		return (acpica_get_handle_cpu(dip, rh));
	}

	status = AcpiGetHandle(NULL, acpiname, rh);
	ddi_prop_free((void *)acpiname);
	return (status);
}



/*
 * Manage OS data attachment to ACPI nodes
 */

/*
 * Return the (dev_info_t *) associated with the ACPI node.
 */
ACPI_STATUS
acpica_get_devinfo(ACPI_HANDLE obj, dev_info_t **dipp)
{
	ACPI_STATUS status;
	void *ptr;

	status = AcpiGetData(obj, acpica_devinfo_handler, &ptr);
	if (status == AE_OK)
		*dipp = (dev_info_t *)ptr;

	return (status);
}

/*
 * Set the dev_info_t associated with the ACPI node.
 */
static ACPI_STATUS
acpica_set_devinfo(ACPI_HANDLE obj, dev_info_t *dip)
{
	ACPI_STATUS status;

	status = AcpiAttachData(obj, acpica_devinfo_handler, (void *)dip);
	return (status);
}


/*
 *
 */
void
acpica_devinfo_handler(ACPI_HANDLE obj, UINT32 func, void *data)
{
	/* noop */
}


/*
 *
 */
void
acpica_map_cpu(processorid_t cpuid, UINT32 proc_id)
{
	struct cpu_map_item *item;

	if (cpu_map == NULL)
		cpu_map = kmem_zalloc(sizeof (item) * NCPU, KM_SLEEP);

	item = kmem_zalloc(sizeof (*item), KM_SLEEP);
	item->proc_id = proc_id;
	item->obj = NULL;
	cpu_map[cpuid] = item;
	cpu_map_count++;
}

void
acpica_build_processor_map()
{
	ACPI_STATUS status;
	void *rv;

	/*
	 * shouldn't be called more than once anyway
	 */
	if (cpu_map_built)
		return;

	/*
	 * Look for Processor objects
	 */
	status = AcpiWalkNamespace(ACPI_TYPE_PROCESSOR,
	    ACPI_ROOT_OBJECT,
	    4,
	    acpica_probe_processor,
	    NULL,
	    &rv);
	ASSERT(status == AE_OK);

	/*
	 * Look for processor Device objects
	 */
	status = AcpiGetDevices("ACPI0007",
	    acpica_probe_processor,
	    NULL,
	    &rv);
	ASSERT(status == AE_OK);
	cpu_map_built = 1;
}
