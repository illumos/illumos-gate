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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc.
 */
/*
 * Copyright (c) 2009-2010, Intel Corporation.
 * All rights reserved.
 */
/*
 * ACPI CA OSL for Solaris x86
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/psm.h>
#include <sys/pci_cfgspace.h>
#include <sys/apic.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/pci.h>
#include <sys/kobj.h>
#include <sys/taskq.h>
#include <sys/strlog.h>
#include <sys/x86_archext.h>
#include <sys/note.h>
#include <sys/promif.h>

#include <sys/acpi/accommon.h>
#include <sys/acpica.h>

#define	MAX_DAT_FILE_SIZE	(64*1024)

/* local functions */
static int CompressEisaID(char *np);

static void scan_d2a_subtree(dev_info_t *dip, ACPI_HANDLE acpiobj, int bus);
static int acpica_query_bbn_problem(void);
static int acpica_find_pcibus(int busno, ACPI_HANDLE *rh);
static int acpica_eval_hid(ACPI_HANDLE dev, char *method, int *rint);
static ACPI_STATUS acpica_set_devinfo(ACPI_HANDLE, dev_info_t *);
static ACPI_STATUS acpica_unset_devinfo(ACPI_HANDLE);
static void acpica_devinfo_handler(ACPI_HANDLE, void *);

/*
 * Event queue vars
 */
int acpica_eventq_init = 0;
ddi_taskq_t *osl_eventq[OSL_EC_BURST_HANDLER+1];

/*
 * Priorities relative to minclsyspri that each taskq
 * run at; OSL_NOTIFY_HANDLER needs to run at a higher
 * priority than OSL_GPE_HANDLER.  There's an implicit
 * assumption that no priority here results in exceeding
 * maxclsyspri.
 * Note: these initializations need to match the order of
 * ACPI_EXECUTE_TYPE.
 */
int osl_eventq_pri_delta[OSL_EC_BURST_HANDLER+1] = {
	0,	/* OSL_GLOBAL_LOCK_HANDLER */
	2,	/* OSL_NOTIFY_HANDLER */
	0,	/* OSL_GPE_HANDLER */
	0,	/* OSL_DEBUGGER_THREAD */
	0,	/* OSL_EC_POLL_HANDLER */
	0	/* OSL_EC_BURST_HANDLER */
};

/*
 * Note, if you change this path, you need to update
 * /boot/grub/filelist.ramdisk and pkg SUNWckr/prototype_i386
 */
static char *acpi_table_path = "/boot/acpi/tables/";

/* non-zero while scan_d2a_map() is working */
static int scanning_d2a_map = 0;
static int d2a_done = 0;

/* features supported by ACPICA and ACPI device configuration. */
uint64_t acpica_core_features = ACPI_FEATURE_OSI_MODULE;
static uint64_t acpica_devcfg_features = 0;

/* set by acpi_poweroff() in PSMs and appm_ioctl() in acpippm for S3 */
int acpica_use_safe_delay = 0;

/* CPU mapping data */
struct cpu_map_item {
	processorid_t	cpu_id;
	UINT32		proc_id;
	UINT32		apic_id;
	ACPI_HANDLE	obj;
};

kmutex_t cpu_map_lock;
static struct cpu_map_item **cpu_map = NULL;
static int cpu_map_count_max = 0;
static int cpu_map_count = 0;
static int cpu_map_built = 0;

/*
 * On systems with the uppc PSM only, acpica_map_cpu() won't be called at all.
 * This flag is used to check for uppc-only systems by detecting whether
 * acpica_map_cpu() has been called or not.
 */
static int cpu_map_called = 0;

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

	/* Always allocate only 1 thread per queue to force FIFO execution */
	for (i = OSL_GLOBAL_LOCK_HANDLER; i <= OSL_EC_BURST_HANDLER; i++) {
		snprintf(namebuf, 32, "ACPI%d", i);
		osl_eventq[i] = ddi_taskq_create(NULL, namebuf, 1,
		    osl_eventq_pri_delta[i] + minclsyspri, 0);
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


ACPI_PHYSICAL_ADDRESS
AcpiOsGetRootPointer()
{
	ACPI_PHYSICAL_ADDRESS Address;

	/*
	 * For EFI firmware, the root pointer is defined in EFI systab.
	 * The boot code process the table and put the physical address
	 * in the acpi-root-tab property.
	 */
	Address = ddi_prop_get_int(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "acpi-root-tab", NULL);

	if ((Address == NULL) && ACPI_FAILURE(AcpiFindRootPointer(&Address)))
		Address = NULL;

	return (Address);
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
AcpiOsPhysicalTableOverride(ACPI_TABLE_HEADER *ExistingTable,
    ACPI_PHYSICAL_ADDRESS *NewAddress, UINT32 *NewTableLength)
{
	return (AE_SUPPORT);
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

ACPI_CPU_FLAGS
AcpiOsAcquireLock(ACPI_HANDLE Handle)
{


	if (Handle == NULL)
		return (AE_BAD_PARAMETER);

	if (curthread == CPU->cpu_idle_thread) {
		while (!mutex_tryenter((kmutex_t *)Handle))
			/* spin */;
	} else
		mutex_enter((kmutex_t *)Handle);
	return (AE_OK);
}

void
AcpiOsReleaseLock(ACPI_HANDLE Handle, ACPI_CPU_FLAGS Flags)
{
	_NOTE(ARGUNUSED(Flags))

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

static int napics_found;	/* number of ioapic addresses in array */
static ACPI_PHYSICAL_ADDRESS ioapic_paddr[MAX_IO_APIC];
static ACPI_TABLE_MADT *acpi_mapic_dtp = NULL;
static void *dummy_ioapicadr;

void
acpica_find_ioapics(void)
{
	int			madt_seen, madt_size;
	ACPI_SUBTABLE_HEADER		*ap;
	ACPI_MADT_IO_APIC		*mia;

	if (acpi_mapic_dtp != NULL)
		return;	/* already parsed table */
	if (AcpiGetTable(ACPI_SIG_MADT, 1,
	    (ACPI_TABLE_HEADER **) &acpi_mapic_dtp) != AE_OK)
		return;

	napics_found = 0;

	/*
	 * Search the MADT for ioapics
	 */
	ap = (ACPI_SUBTABLE_HEADER *) (acpi_mapic_dtp + 1);
	madt_size = acpi_mapic_dtp->Header.Length;
	madt_seen = sizeof (*acpi_mapic_dtp);

	while (madt_seen < madt_size) {

		switch (ap->Type) {
		case ACPI_MADT_TYPE_IO_APIC:
			mia = (ACPI_MADT_IO_APIC *) ap;
			if (napics_found < MAX_IO_APIC) {
				ioapic_paddr[napics_found++] =
				    (ACPI_PHYSICAL_ADDRESS)
				    (mia->Address & PAGEMASK);
			}
			break;

		default:
			break;
		}

		/* advance to next entry */
		madt_seen += ap->Length;
		ap = (ACPI_SUBTABLE_HEADER *)(((char *)ap) + ap->Length);
	}
	if (dummy_ioapicadr == NULL)
		dummy_ioapicadr = kmem_zalloc(PAGESIZE, KM_SLEEP);
}


void *
AcpiOsMapMemory(ACPI_PHYSICAL_ADDRESS PhysicalAddress, ACPI_SIZE Size)
{
	int	i;

	/*
	 * If the iopaic address table is populated, check if trying
	 * to access an ioapic.  Instead, return a pointer to a dummy ioapic.
	 */
	for (i = 0; i < napics_found; i++) {
		if ((PhysicalAddress & PAGEMASK) == ioapic_paddr[i])
			return (dummy_ioapicadr);
	}
	/* FUTUREWORK: test PhysicalAddress for > 32 bits */
	return (psm_map_new((paddr_t)PhysicalAddress,
	    (size_t)Size, PSM_PROT_WRITE | PSM_PROT_READ));
}

void
AcpiOsUnmapMemory(void *LogicalAddress, ACPI_SIZE Size)
{
	/*
	 * Check if trying to unmap dummy ioapic address.
	 */
	if (LogicalAddress == dummy_ioapicadr)
		return;

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
	 * ACPI CA doesn't care what actual value is returned as long
	 * as it is non-zero and unique to each existing thread.
	 * ACPI CA assumes that thread ID is castable to a pointer,
	 * so we use the current thread pointer.
	 */
	return (ACPI_CAST_PTHREAD_T((uintptr_t)curthread));
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
AcpiOsWaitEventsComplete(void)
{
	int	i;

	/*
	 * Wait for event queues to be empty.
	 */
	for (i = OSL_GLOBAL_LOCK_HANDLER; i <= OSL_EC_BURST_HANDLER; i++) {
		if (osl_eventq[i] != NULL) {
			ddi_taskq_wait(osl_eventq[i]);
		}
	}
}

void
AcpiOsSleep(ACPI_INTEGER Milliseconds)
{
	/*
	 * During kernel startup, before the first tick interrupt
	 * has taken place, we can't call delay; very late in
	 * kernel shutdown or suspend/resume, clock interrupts
	 * are blocked, so delay doesn't work then either.
	 * So we busy wait if lbolt == 0 (kernel startup)
	 * or if acpica_use_safe_delay has been set to a
	 * non-zero value.
	 */
	if ((ddi_get_lbolt() == 0) || acpica_use_safe_delay)
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
	{ 0xcf8, 0xd00, OSL_IO_TERM | OSL_IO_RW}
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
osl_rw_memory(ACPI_PHYSICAL_ADDRESS Address, UINT64 *Value,
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
	case 8:
		OSL_RW(ptr, Value, uint64_t, write);
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
		UINT64 *Value, UINT32 Width)
{
	osl_rw_memory(Address, Value, Width, 0);
	return (AE_OK);
}

ACPI_STATUS
AcpiOsWriteMemory(ACPI_PHYSICAL_ADDRESS Address,
		UINT64 Value, UINT32 Width)
{
	osl_rw_memory(Address, &Value, Width, 1);
	return (AE_OK);
}


ACPI_STATUS
AcpiOsReadPciConfiguration(ACPI_PCI_ID *PciId, UINT32 Reg,
		UINT64 *Value, UINT32 Width)
{

	switch (Width) {
	case 8:
		*Value = (UINT64)(*pci_getb_func)
		    (PciId->Bus, PciId->Device, PciId->Function, Reg);
		break;
	case 16:
		*Value = (UINT64)(*pci_getw_func)
		    (PciId->Bus, PciId->Device, PciId->Function, Reg);
		break;
	case 32:
		*Value = (UINT64)(*pci_getl_func)
		    (PciId->Bus, PciId->Device, PciId->Function, Reg);
		break;
	case 64:
	default:
		cmn_err(CE_WARN, "!AcpiOsReadPciConfiguration: %x %u failed",
		    Reg, Width);
		return (AE_BAD_PARAMETER);
	}
	return (AE_OK);
}

/*
 *
 */
int acpica_write_pci_config_ok = 1;

ACPI_STATUS
AcpiOsWritePciConfiguration(ACPI_PCI_ID *PciId, UINT32 Reg,
		UINT64 Value, UINT32 Width)
{

	if (!acpica_write_pci_config_ok) {
		cmn_err(CE_NOTE, "!write to PCI cfg %x/%x/%x %x"
		    " %lx %d not permitted", PciId->Bus, PciId->Device,
		    PciId->Function, Reg, (long)Value, Width);
		return (AE_OK);
	}

	switch (Width) {
	case 8:
		(*pci_putb_func)(PciId->Bus, PciId->Device, PciId->Function,
		    Reg, (uint8_t)Value);
		break;
	case 16:
		(*pci_putw_func)(PciId->Bus, PciId->Device, PciId->Function,
		    Reg, (uint16_t)Value);
		break;
	case 32:
		(*pci_putl_func)(PciId->Bus, PciId->Device, PciId->Function,
		    Reg, (uint32_t)Value);
		break;
	case 64:
	default:
		cmn_err(CE_WARN, "!AcpiOsWritePciConfiguration: %x %u failed",
		    Reg, Width);
		return (AE_BAD_PARAMETER);
	}
	return (AE_OK);
}

/*
 * Called with ACPI_HANDLEs for both a PCI Config Space
 * OpRegion and (what ACPI CA thinks is) the PCI device
 * to which this ConfigSpace OpRegion belongs.
 *
 * ACPI CA uses _BBN and _ADR objects to determine the default
 * values for bus, segment, device and function; anything ACPI CA
 * can't figure out from the ACPI tables will be 0.  One very
 * old 32-bit x86 system is known to have broken _BBN; this is
 * not addressed here.
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
	if (ACPI_SUCCESS(acpica_get_devinfo(handle, &dip)) &&
	    (acpica_get_bdf(dip, &bus, &device, &func) >= 0)) {
		(*PciId)->Bus = bus;
		(*PciId)->Device = device;
		(*PciId)->Function = func;
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

static struct AcpiOSIFeature_s {
	uint64_t	control_flag;
	const char	*feature_name;
} AcpiOSIFeatures[] = {
	{ ACPI_FEATURE_OSI_MODULE,	"Module Device" },
	{ 0,				"Processor Device" }
};

/*ARGSUSED*/
ACPI_STATUS
AcpiOsValidateInterface(char *feature)
{
	int i;

	ASSERT(feature != NULL);
	for (i = 0; i < sizeof (AcpiOSIFeatures) / sizeof (AcpiOSIFeatures[0]);
	    i++) {
		if (strcmp(feature, AcpiOSIFeatures[i].feature_name) != 0) {
			continue;
		}
		/* Check whether required core features are available. */
		if (AcpiOSIFeatures[i].control_flag != 0 &&
		    acpica_get_core_feature(AcpiOSIFeatures[i].control_flag) !=
		    AcpiOSIFeatures[i].control_flag) {
			break;
		}
		/* Feature supported. */
		return (AE_OK);
	}

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
			switch (acpica_console_out) {
			case 1:
				printf(acpica_outbuf);
				break;
			case 2:
				prom_printf(acpica_outbuf);
				break;
			case 0:
			default:
				(void) strlog(0, 0, 0,
				    SL_CONSOLE | SL_NOTE | SL_LOGONLY,
				    acpica_outbuf);
				break;
			}
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
AcpiOsGetLine(char *Buffer, UINT32 len, UINT32 *BytesRead)
{
	_NOTE(ARGUNUSED(Buffer))
	_NOTE(ARGUNUSED(len))
	_NOTE(ARGUNUSED(BytesRead))

	/* FUTUREWORK: debugger support */

	return (0);
}

/*
 * Device tree binding
 */
static ACPI_STATUS
acpica_find_pcibus_walker(ACPI_HANDLE hdl, UINT32 lvl, void *ctxp, void **rvpp)
{
	_NOTE(ARGUNUSED(lvl));

	int sta, hid, bbn;
	int busno = (intptr_t)ctxp;
	ACPI_HANDLE *hdlp = (ACPI_HANDLE *)rvpp;

	/* Check whether device exists. */
	if (ACPI_SUCCESS(acpica_eval_int(hdl, "_STA", &sta)) &&
	    !(sta & (ACPI_STA_DEVICE_PRESENT | ACPI_STA_DEVICE_FUNCTIONING))) {
		/*
		 * Skip object if device doesn't exist.
		 * According to ACPI Spec,
		 * 1) setting either bit 0 or bit 3 means that device exists.
		 * 2) Absence of _STA method means all status bits set.
		 */
		return (AE_CTRL_DEPTH);
	}

	if (ACPI_FAILURE(acpica_eval_hid(hdl, "_HID", &hid)) ||
	    (hid != HID_PCI_BUS && hid != HID_PCI_EXPRESS_BUS)) {
		/* Non PCI/PCIe host bridge. */
		return (AE_OK);
	}

	if (acpi_has_broken_bbn) {
		ACPI_BUFFER rb;
		rb.Pointer = NULL;
		rb.Length = ACPI_ALLOCATE_BUFFER;

		/* Decree _BBN == n from PCI<n> */
		if (AcpiGetName(hdl, ACPI_SINGLE_NAME, &rb) != AE_OK) {
			return (AE_CTRL_TERMINATE);
		}
		bbn = ((char *)rb.Pointer)[3] - '0';
		AcpiOsFree(rb.Pointer);
		if (bbn == busno || busno == 0) {
			*hdlp = hdl;
			return (AE_CTRL_TERMINATE);
		}
	} else if (ACPI_SUCCESS(acpica_eval_int(hdl, "_BBN", &bbn))) {
		if (bbn == busno) {
			*hdlp = hdl;
			return (AE_CTRL_TERMINATE);
		}
	} else if (busno == 0) {
		*hdlp = hdl;
		return (AE_CTRL_TERMINATE);
	}

	return (AE_CTRL_DEPTH);
}

static int
acpica_find_pcibus(int busno, ACPI_HANDLE *rh)
{
	ACPI_HANDLE sbobj, busobj;

	/* initialize static flag by querying ACPI namespace for bug */
	if (acpi_has_broken_bbn == -1)
		acpi_has_broken_bbn = acpica_query_bbn_problem();

	if (ACPI_SUCCESS(AcpiGetHandle(NULL, "\\_SB", &sbobj))) {
		busobj = NULL;
		(void) AcpiWalkNamespace(ACPI_TYPE_DEVICE, sbobj, UINT32_MAX,
		    acpica_find_pcibus_walker, NULL, (void *)(intptr_t)busno,
		    (void **)&busobj);
		if (busobj != NULL) {
			*rh = busobj;
			return (AE_OK);
		}
	}

	return (AE_ERROR);
}

static ACPI_STATUS
acpica_query_bbn_walker(ACPI_HANDLE hdl, UINT32 lvl, void *ctxp, void **rvpp)
{
	_NOTE(ARGUNUSED(lvl));
	_NOTE(ARGUNUSED(rvpp));

	int sta, hid, bbn;
	int *cntp = (int *)ctxp;

	/* Check whether device exists. */
	if (ACPI_SUCCESS(acpica_eval_int(hdl, "_STA", &sta)) &&
	    !(sta & (ACPI_STA_DEVICE_PRESENT | ACPI_STA_DEVICE_FUNCTIONING))) {
		/*
		 * Skip object if device doesn't exist.
		 * According to ACPI Spec,
		 * 1) setting either bit 0 or bit 3 means that device exists.
		 * 2) Absence of _STA method means all status bits set.
		 */
		return (AE_CTRL_DEPTH);
	}

	if (ACPI_FAILURE(acpica_eval_hid(hdl, "_HID", &hid)) ||
	    (hid != HID_PCI_BUS && hid != HID_PCI_EXPRESS_BUS)) {
		/* Non PCI/PCIe host bridge. */
		return (AE_OK);
	} else if (ACPI_SUCCESS(acpica_eval_int(hdl, "_BBN", &bbn)) &&
	    bbn == 0 && ++(*cntp) > 1) {
		/*
		 * If we find more than one bus with a 0 _BBN
		 * we have the problem that BigBear's BIOS shows
		 */
		return (AE_CTRL_TERMINATE);
	} else {
		/*
		 * Skip children of PCI/PCIe host bridge.
		 */
		return (AE_CTRL_DEPTH);
	}
}

/*
 * Look for ACPI problem where _BBN is zero for multiple PCI buses
 * This is a clear ACPI bug, but we have a workaround in acpica_find_pcibus()
 * below if it exists.
 */
static int
acpica_query_bbn_problem(void)
{
	ACPI_HANDLE sbobj;
	int zerobbncnt;
	void *rv;

	zerobbncnt = 0;
	if (ACPI_SUCCESS(AcpiGetHandle(NULL, "\\_SB", &sbobj))) {
		(void) AcpiWalkNamespace(ACPI_TYPE_DEVICE, sbobj, UINT32_MAX,
		    acpica_query_bbn_walker, NULL, &zerobbncnt, &rv);
	}

	return (zerobbncnt > 1 ? 1 : 0);
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
	if (AcpiEvaluateObject(dev, method, NULL, &rb) == AE_OK &&
	    rb.Length != 0) {
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
ACPI_STATUS
acpica_tag_devinfo(dev_info_t *dip, ACPI_HANDLE acpiobj)
{
	ACPI_STATUS status;
	ACPI_BUFFER rb;

	/*
	 * Tag the devinfo node with the ACPI name
	 */
	rb.Pointer = NULL;
	rb.Length = ACPI_ALLOCATE_BUFFER;
	status = AcpiGetName(acpiobj, ACPI_FULL_PATHNAME, &rb);
	if (ACPI_FAILURE(status)) {
		cmn_err(CE_WARN, "acpica: could not get ACPI path!");
	} else {
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "acpi-namespace", (char *)rb.Pointer);
		AcpiOsFree(rb.Pointer);

		/*
		 * Tag the ACPI node with the dip
		 */
		status = acpica_set_devinfo(acpiobj, dip);
		ASSERT(ACPI_SUCCESS(status));
	}

	return (status);
}

/*
 * Destroy linkage between devinfo nodes and ACPI nodes
 */
ACPI_STATUS
acpica_untag_devinfo(dev_info_t *dip, ACPI_HANDLE acpiobj)
{
	(void) acpica_unset_devinfo(acpiobj);
	(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, "acpi-namespace");

	return (AE_OK);
}

/*
 * Return the ACPI device node matching the CPU dev_info node.
 */
ACPI_STATUS
acpica_get_handle_cpu(int cpu_id, ACPI_HANDLE *rh)
{
	int i;

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

	if (cpu_id < 0) {
		return (AE_ERROR);
	}

	/*
	 * search object with cpuid in cpu_map
	 */
	mutex_enter(&cpu_map_lock);
	for (i = 0; i < cpu_map_count; i++) {
		if (cpu_map[i]->cpu_id == cpu_id) {
			break;
		}
	}
	if (i < cpu_map_count && (cpu_map[i]->obj != NULL)) {
		*rh = cpu_map[i]->obj;
		mutex_exit(&cpu_map_lock);
		return (AE_OK);
	}

	/* Handle special case for uppc-only systems. */
	if (cpu_map_called == 0) {
		uint32_t apicid = cpuid_get_apicid(CPU);
		if (apicid != UINT32_MAX) {
			for (i = 0; i < cpu_map_count; i++) {
				if (cpu_map[i]->apic_id == apicid) {
					break;
				}
			}
			if (i < cpu_map_count && (cpu_map[i]->obj != NULL)) {
				*rh = cpu_map[i]->obj;
				mutex_exit(&cpu_map_lock);
				return (AE_OK);
			}
		}
	}
	mutex_exit(&cpu_map_lock);

	return (AE_ERROR);
}

/*
 * Determine if this object is a processor
 */
static ACPI_STATUS
acpica_probe_processor(ACPI_HANDLE obj, UINT32 level, void *ctx, void **rv)
{
	ACPI_STATUS status;
	ACPI_OBJECT_TYPE objtype;
	unsigned long acpi_id;
	ACPI_BUFFER rb;
	ACPI_DEVICE_INFO *di;

	if (AcpiGetType(obj, &objtype) != AE_OK)
		return (AE_OK);

	if (objtype == ACPI_TYPE_PROCESSOR) {
		/* process a Processor */
		rb.Pointer = NULL;
		rb.Length = ACPI_ALLOCATE_BUFFER;
		status = AcpiEvaluateObjectTyped(obj, NULL, NULL, &rb,
		    ACPI_TYPE_PROCESSOR);
		if (status != AE_OK) {
			cmn_err(CE_WARN, "!acpica: error probing Processor");
			return (status);
		}
		acpi_id = ((ACPI_OBJECT *)rb.Pointer)->Processor.ProcId;
		AcpiOsFree(rb.Pointer);
	} else if (objtype == ACPI_TYPE_DEVICE) {
		/* process a processor Device */
		status = AcpiGetObjectInfo(obj, &di);
		if (status != AE_OK) {
			cmn_err(CE_WARN,
			    "!acpica: error probing Processor Device\n");
			return (status);
		}

		if (!(di->Valid & ACPI_VALID_UID) ||
		    ddi_strtoul(di->UniqueId.String, NULL, 10, &acpi_id) != 0) {
			ACPI_FREE(di);
			cmn_err(CE_WARN,
			    "!acpica: error probing Processor Device _UID\n");
			return (AE_ERROR);
		}
		ACPI_FREE(di);
	}
	(void) acpica_add_processor_to_map(acpi_id, obj, UINT32_MAX);

	return (AE_OK);
}

void
scan_d2a_map(void)
{
	dev_info_t *dip, *cdip;
	ACPI_HANDLE acpiobj;
	char *device_type_prop;
	int bus;
	static int map_error = 0;

	if (map_error || (d2a_done != 0))
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
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS,
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
			if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dcld,
			    DDI_PROP_DONTPASS, "device_type",
			    &device_type_prop) == DDI_PROP_SUCCESS) {
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

#ifdef	DEBUG
	if (d2a_done == 0)
		cmn_err(CE_WARN, "!acpica_get_handle:"
		    " no ACPI mapping for %s", ddi_node_name(dip));
#endif

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "acpi-namespace", &acpiname) != DDI_PROP_SUCCESS) {
		return (AE_ERROR);
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
 * Unset the dev_info_t associated with the ACPI node.
 */
static ACPI_STATUS
acpica_unset_devinfo(ACPI_HANDLE obj)
{
	return (AcpiDetachData(obj, acpica_devinfo_handler));
}

/*
 *
 */
void
acpica_devinfo_handler(ACPI_HANDLE obj, void *data)
{
	/* no-op */
}

ACPI_STATUS
acpica_build_processor_map(void)
{
	ACPI_STATUS status;
	void *rv;

	/*
	 * shouldn't be called more than once anyway
	 */
	if (cpu_map_built)
		return (AE_OK);

	/*
	 * ACPI device configuration driver has built mapping information
	 * among processor id and object handle, no need to probe again.
	 */
	if (acpica_get_devcfg_feature(ACPI_DEVCFG_CPU)) {
		cpu_map_built = 1;
		return (AE_OK);
	}

	/*
	 * Look for Processor objects
	 */
	status = AcpiWalkNamespace(ACPI_TYPE_PROCESSOR,
	    ACPI_ROOT_OBJECT,
	    4,
	    acpica_probe_processor,
	    NULL,
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

	return (status);
}

/*
 * Grow cpu map table on demand.
 */
static void
acpica_grow_cpu_map(void)
{
	if (cpu_map_count == cpu_map_count_max) {
		size_t sz;
		struct cpu_map_item **new_map;

		ASSERT(cpu_map_count_max < INT_MAX / 2);
		cpu_map_count_max += max_ncpus;
		new_map = kmem_zalloc(sizeof (cpu_map[0]) * cpu_map_count_max,
		    KM_SLEEP);
		if (cpu_map_count != 0) {
			ASSERT(cpu_map != NULL);
			sz = sizeof (cpu_map[0]) * cpu_map_count;
			kcopy(cpu_map, new_map, sz);
			kmem_free(cpu_map, sz);
		}
		cpu_map = new_map;
	}
}

/*
 * Maintain mapping information among (cpu id, ACPI processor id, APIC id,
 * ACPI handle). The mapping table will be setup in two steps:
 * 1) acpica_add_processor_to_map() builds mapping among APIC id, ACPI
 *    processor id and ACPI object handle.
 * 2) acpica_map_cpu() builds mapping among cpu id and ACPI processor id.
 * On systems with which have ACPI device configuration for CPUs enabled,
 * acpica_map_cpu() will be called after acpica_add_processor_to_map(),
 * otherwise acpica_map_cpu() will be called before
 * acpica_add_processor_to_map().
 */
ACPI_STATUS
acpica_add_processor_to_map(UINT32 acpi_id, ACPI_HANDLE obj, UINT32 apic_id)
{
	int i;
	ACPI_STATUS rc = AE_OK;
	struct cpu_map_item *item = NULL;

	ASSERT(obj != NULL);
	if (obj == NULL) {
		return (AE_ERROR);
	}

	mutex_enter(&cpu_map_lock);

	/*
	 * Special case for uppc
	 * If we're a uppc system and ACPI device configuration for CPU has
	 * been disabled, there won't be a CPU map yet because uppc psm doesn't
	 * call acpica_map_cpu(). So create one and use the passed-in processor
	 * as CPU 0
	 * Assumption: the first CPU returned by
	 * AcpiGetDevices/AcpiWalkNamespace will be the BSP.
	 * Unfortunately there appears to be no good way to ASSERT this.
	 */
	if (cpu_map == NULL &&
	    !acpica_get_devcfg_feature(ACPI_DEVCFG_CPU)) {
		acpica_grow_cpu_map();
		ASSERT(cpu_map != NULL);
		item = kmem_zalloc(sizeof (*item), KM_SLEEP);
		item->cpu_id = 0;
		item->proc_id = acpi_id;
		item->apic_id = apic_id;
		item->obj = obj;
		cpu_map[0] = item;
		cpu_map_count = 1;
		mutex_exit(&cpu_map_lock);
		return (AE_OK);
	}

	for (i = 0; i < cpu_map_count; i++) {
		if (cpu_map[i]->obj == obj) {
			rc = AE_ALREADY_EXISTS;
			break;
		} else if (cpu_map[i]->proc_id == acpi_id) {
			ASSERT(item == NULL);
			item = cpu_map[i];
		}
	}

	if (rc == AE_OK) {
		if (item != NULL) {
			/*
			 * ACPI alias objects may cause more than one objects
			 * with the same ACPI processor id, only remember the
			 * the first object encountered.
			 */
			if (item->obj == NULL) {
				item->obj = obj;
				item->apic_id = apic_id;
			} else {
				rc = AE_ALREADY_EXISTS;
			}
		} else if (cpu_map_count >= INT_MAX / 2) {
			rc = AE_NO_MEMORY;
		} else {
			acpica_grow_cpu_map();
			ASSERT(cpu_map != NULL);
			ASSERT(cpu_map_count < cpu_map_count_max);
			item = kmem_zalloc(sizeof (*item), KM_SLEEP);
			item->cpu_id = -1;
			item->proc_id = acpi_id;
			item->apic_id = apic_id;
			item->obj = obj;
			cpu_map[cpu_map_count] = item;
			cpu_map_count++;
		}
	}

	mutex_exit(&cpu_map_lock);

	return (rc);
}

ACPI_STATUS
acpica_remove_processor_from_map(UINT32 acpi_id)
{
	int i;
	ACPI_STATUS rc = AE_NOT_EXIST;

	mutex_enter(&cpu_map_lock);
	for (i = 0; i < cpu_map_count; i++) {
		if (cpu_map[i]->proc_id != acpi_id) {
			continue;
		}
		cpu_map[i]->obj = NULL;
		/* Free item if no more reference to it. */
		if (cpu_map[i]->cpu_id == -1) {
			kmem_free(cpu_map[i], sizeof (struct cpu_map_item));
			cpu_map[i] = NULL;
			cpu_map_count--;
			if (i != cpu_map_count) {
				cpu_map[i] = cpu_map[cpu_map_count];
				cpu_map[cpu_map_count] = NULL;
			}
		}
		rc = AE_OK;
		break;
	}
	mutex_exit(&cpu_map_lock);

	return (rc);
}

ACPI_STATUS
acpica_map_cpu(processorid_t cpuid, UINT32 acpi_id)
{
	int i;
	ACPI_STATUS rc = AE_OK;
	struct cpu_map_item *item = NULL;

	ASSERT(cpuid != -1);
	if (cpuid == -1) {
		return (AE_ERROR);
	}

	mutex_enter(&cpu_map_lock);
	cpu_map_called = 1;
	for (i = 0; i < cpu_map_count; i++) {
		if (cpu_map[i]->cpu_id == cpuid) {
			rc = AE_ALREADY_EXISTS;
			break;
		} else if (cpu_map[i]->proc_id == acpi_id) {
			ASSERT(item == NULL);
			item = cpu_map[i];
		}
	}
	if (rc == AE_OK) {
		if (item != NULL) {
			if (item->cpu_id == -1) {
				item->cpu_id = cpuid;
			} else {
				rc = AE_ALREADY_EXISTS;
			}
		} else if (cpu_map_count >= INT_MAX / 2) {
			rc = AE_NO_MEMORY;
		} else {
			acpica_grow_cpu_map();
			ASSERT(cpu_map != NULL);
			ASSERT(cpu_map_count < cpu_map_count_max);
			item = kmem_zalloc(sizeof (*item), KM_SLEEP);
			item->cpu_id = cpuid;
			item->proc_id = acpi_id;
			item->apic_id = UINT32_MAX;
			item->obj = NULL;
			cpu_map[cpu_map_count] = item;
			cpu_map_count++;
		}
	}
	mutex_exit(&cpu_map_lock);

	return (rc);
}

ACPI_STATUS
acpica_unmap_cpu(processorid_t cpuid)
{
	int i;
	ACPI_STATUS rc = AE_NOT_EXIST;

	ASSERT(cpuid != -1);
	if (cpuid == -1) {
		return (rc);
	}

	mutex_enter(&cpu_map_lock);
	for (i = 0; i < cpu_map_count; i++) {
		if (cpu_map[i]->cpu_id != cpuid) {
			continue;
		}
		cpu_map[i]->cpu_id = -1;
		/* Free item if no more reference. */
		if (cpu_map[i]->obj == NULL) {
			kmem_free(cpu_map[i], sizeof (struct cpu_map_item));
			cpu_map[i] = NULL;
			cpu_map_count--;
			if (i != cpu_map_count) {
				cpu_map[i] = cpu_map[cpu_map_count];
				cpu_map[cpu_map_count] = NULL;
			}
		}
		rc = AE_OK;
		break;
	}
	mutex_exit(&cpu_map_lock);

	return (rc);
}

ACPI_STATUS
acpica_get_cpu_object_by_cpuid(processorid_t cpuid, ACPI_HANDLE *hdlp)
{
	int i;
	ACPI_STATUS rc = AE_NOT_EXIST;

	ASSERT(cpuid != -1);
	if (cpuid == -1) {
		return (rc);
	}

	mutex_enter(&cpu_map_lock);
	for (i = 0; i < cpu_map_count; i++) {
		if (cpu_map[i]->cpu_id == cpuid && cpu_map[i]->obj != NULL) {
			*hdlp = cpu_map[i]->obj;
			rc = AE_OK;
			break;
		}
	}
	mutex_exit(&cpu_map_lock);

	return (rc);
}

ACPI_STATUS
acpica_get_cpu_object_by_procid(UINT32 procid, ACPI_HANDLE *hdlp)
{
	int i;
	ACPI_STATUS rc = AE_NOT_EXIST;

	mutex_enter(&cpu_map_lock);
	for (i = 0; i < cpu_map_count; i++) {
		if (cpu_map[i]->proc_id == procid && cpu_map[i]->obj != NULL) {
			*hdlp = cpu_map[i]->obj;
			rc = AE_OK;
			break;
		}
	}
	mutex_exit(&cpu_map_lock);

	return (rc);
}

ACPI_STATUS
acpica_get_cpu_object_by_apicid(UINT32 apicid, ACPI_HANDLE *hdlp)
{
	int i;
	ACPI_STATUS rc = AE_NOT_EXIST;

	ASSERT(apicid != UINT32_MAX);
	if (apicid == UINT32_MAX) {
		return (rc);
	}

	mutex_enter(&cpu_map_lock);
	for (i = 0; i < cpu_map_count; i++) {
		if (cpu_map[i]->apic_id == apicid && cpu_map[i]->obj != NULL) {
			*hdlp = cpu_map[i]->obj;
			rc = AE_OK;
			break;
		}
	}
	mutex_exit(&cpu_map_lock);

	return (rc);
}

ACPI_STATUS
acpica_get_cpu_id_by_object(ACPI_HANDLE hdl, processorid_t *cpuidp)
{
	int i;
	ACPI_STATUS rc = AE_NOT_EXIST;

	ASSERT(cpuidp != NULL);
	if (hdl == NULL || cpuidp == NULL) {
		return (rc);
	}

	*cpuidp = -1;
	mutex_enter(&cpu_map_lock);
	for (i = 0; i < cpu_map_count; i++) {
		if (cpu_map[i]->obj == hdl && cpu_map[i]->cpu_id != -1) {
			*cpuidp = cpu_map[i]->cpu_id;
			rc = AE_OK;
			break;
		}
	}
	mutex_exit(&cpu_map_lock);

	return (rc);
}

ACPI_STATUS
acpica_get_apicid_by_object(ACPI_HANDLE hdl, UINT32 *rp)
{
	int i;
	ACPI_STATUS rc = AE_NOT_EXIST;

	ASSERT(rp != NULL);
	if (hdl == NULL || rp == NULL) {
		return (rc);
	}

	*rp = UINT32_MAX;
	mutex_enter(&cpu_map_lock);
	for (i = 0; i < cpu_map_count; i++) {
		if (cpu_map[i]->obj == hdl &&
		    cpu_map[i]->apic_id != UINT32_MAX) {
			*rp = cpu_map[i]->apic_id;
			rc = AE_OK;
			break;
		}
	}
	mutex_exit(&cpu_map_lock);

	return (rc);
}

ACPI_STATUS
acpica_get_procid_by_object(ACPI_HANDLE hdl, UINT32 *rp)
{
	int i;
	ACPI_STATUS rc = AE_NOT_EXIST;

	ASSERT(rp != NULL);
	if (hdl == NULL || rp == NULL) {
		return (rc);
	}

	*rp = UINT32_MAX;
	mutex_enter(&cpu_map_lock);
	for (i = 0; i < cpu_map_count; i++) {
		if (cpu_map[i]->obj == hdl) {
			*rp = cpu_map[i]->proc_id;
			rc = AE_OK;
			break;
		}
	}
	mutex_exit(&cpu_map_lock);

	return (rc);
}

void
acpica_set_core_feature(uint64_t features)
{
	atomic_or_64(&acpica_core_features, features);
}

void
acpica_clear_core_feature(uint64_t features)
{
	atomic_and_64(&acpica_core_features, ~features);
}

uint64_t
acpica_get_core_feature(uint64_t features)
{
	return (acpica_core_features & features);
}

void
acpica_set_devcfg_feature(uint64_t features)
{
	atomic_or_64(&acpica_devcfg_features, features);
}

void
acpica_clear_devcfg_feature(uint64_t features)
{
	atomic_and_64(&acpica_devcfg_features, ~features);
}

uint64_t
acpica_get_devcfg_feature(uint64_t features)
{
	return (acpica_devcfg_features & features);
}

void
acpica_get_global_FADT(ACPI_TABLE_FADT **gbl_FADT)
{
	*gbl_FADT = &AcpiGbl_FADT;
}

void
acpica_write_cpupm_capabilities(boolean_t pstates, boolean_t cstates)
{
	if (pstates && AcpiGbl_FADT.PstateControl != 0)
		(void) AcpiHwRegisterWrite(ACPI_REGISTER_SMI_COMMAND_BLOCK,
		    AcpiGbl_FADT.PstateControl);

	if (cstates && AcpiGbl_FADT.CstControl != 0)
		(void) AcpiHwRegisterWrite(ACPI_REGISTER_SMI_COMMAND_BLOCK,
		    AcpiGbl_FADT.CstControl);
}

uint32_t
acpi_strtoul(const char *str, char **ep, int base)
{
	ulong_t v;

	if (ddi_strtoul(str, ep, base, &v) != 0 || v > ACPI_UINT32_MAX) {
		return (ACPI_UINT32_MAX);
	}

	return ((uint32_t)v);
}
