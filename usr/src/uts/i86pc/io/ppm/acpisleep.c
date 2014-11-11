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
 * Copyright 2012 Joyent, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/smp_impldefs.h>
#include <sys/promif.h>

#include <sys/kmem.h>
#include <sys/archsystm.h>
#include <sys/cpuvar.h>
#include <sys/pte.h>
#include <vm/seg_kmem.h>
#include <sys/epm.h>
#include <sys/cpr.h>
#include <sys/machsystm.h>
#include <sys/clock.h>

#include <sys/cpr_wakecode.h>
#include <sys/acpi/acpi.h>

#ifdef OLDPMCODE
#include "acpi.h"
#endif

#include	<sys/x86_archext.h>
#include	<sys/reboot.h>
#include	<sys/cpu_module.h>
#include	<sys/kdi.h>

/*
 * S3 stuff
 */

int acpi_rtc_wake = 0x0;		/* wake in N seconds */

/*
 * Execute optional ACPI methods for suspend/resume.
 * The value can be ACPI_EXECUTE_GTS and/or ACPI_EXECUTE_BFS.
 * Global so it can be set in /etc/system.
 * From usr/src/uts/intel/io/acpica/changes.txt:
 *    It has been seen on some systems where the execution of these
 *    methods causes errors and also prevents the machine from entering S5.
 *    It is therefore suggested that host operating systems do not execute
 *    these methods by default. In the future, perhaps these methods can be
 *    optionally executed based on the age of the system...
 */
int acpi_sleep_flags = ACPI_NO_OPTIONAL_METHODS;

#if 0	/* debug */
static uint8_t	branchbuf[64 * 1024];	/* for the HDT branch trace stuff */
#endif	/* debug */

extern int boothowto;

#define	BOOTCPU	0	/* cpu 0 is always the boot cpu */

extern void		kernel_wc_code(void);
extern tod_ops_t	*tod_ops;
extern int flushes_require_xcalls;
extern int tsc_gethrtime_enable;

extern cpuset_t cpu_ready_set;


/*
 * This is what we've all been waiting for!
 */
int
acpi_enter_sleepstate(s3a_t *s3ap)
{
	ACPI_PHYSICAL_ADDRESS	wakephys = s3ap->s3a_wakephys;
	caddr_t			wakevirt = rm_platter_va;
	/*LINTED*/
	wakecode_t		*wp = (wakecode_t *)wakevirt;
	uint_t			Sx = s3ap->s3a_state;

	PT(PT_SWV);
	/* Set waking vector */
	if (AcpiSetFirmwareWakingVector(wakephys) != AE_OK) {
		PT(PT_SWV_FAIL);
		PMD(PMD_SX, ("Can't SetFirmwareWakingVector(%lx)\n",
		    (long)wakephys))
		goto insomnia;
	}

	PT(PT_EWE);
	/* Enable wake events */
	if (AcpiEnableEvent(ACPI_EVENT_POWER_BUTTON, 0) != AE_OK) {
		PT(PT_EWE_FAIL);
		PMD(PMD_SX, ("Can't EnableEvent(POWER_BUTTON)\n"))
	}
	if (acpi_rtc_wake > 0) {
		/* clear the RTC bit first */
		(void) AcpiWriteBitRegister(ACPI_BITREG_RT_CLOCK_STATUS, 1);
		PT(PT_RTCW);
		if (AcpiEnableEvent(ACPI_EVENT_RTC, 0) != AE_OK) {
			PT(PT_RTCW_FAIL);
			PMD(PMD_SX, ("Can't EnableEvent(RTC)\n"))
		}

		/*
		 * Set RTC to wake us in a wee while.
		 */
		mutex_enter(&tod_lock);
		PT(PT_TOD);
		TODOP_SETWAKE(tod_ops, acpi_rtc_wake);
		mutex_exit(&tod_lock);
	}

	/*
	 * Prepare for sleep ... could've done this earlier?
	 */
	PT(PT_SXP);
	PMD(PMD_SX, ("Calling AcpiEnterSleepStatePrep(%d) ...\n", Sx))
	if (AcpiEnterSleepStatePrep(Sx) != AE_OK) {
		PMD(PMD_SX, ("... failed\n!"))
		goto insomnia;
	}

	switch (s3ap->s3a_test_point) {
	case DEVICE_SUSPEND_TO_RAM:
	case FORCE_SUSPEND_TO_RAM:
	case LOOP_BACK_PASS:
		return (0);
	case LOOP_BACK_FAIL:
		return (1);
	default:
		ASSERT(s3ap->s3a_test_point == LOOP_BACK_NONE);
	}

	/*
	 * Tell the hardware to sleep.
	 */
	PT(PT_SXE);
	PMD(PMD_SX, ("Calling AcpiEnterSleepState(%d, %d) ...\n", Sx,
	    acpi_sleep_flags))
	if (AcpiEnterSleepState(Sx, acpi_sleep_flags) != AE_OK) {
		PT(PT_SXE_FAIL);
		PMD(PMD_SX, ("... failed!\n"))
	}

insomnia:
	PT(PT_INSOM);
	/* cleanup is done in the caller */
	return (1);
}

int
acpi_exit_sleepstate(s3a_t *s3ap)
{
	int Sx = s3ap->s3a_state;

	PT(PT_WOKE);
	PMD(PMD_SX, ("!We woke up!\n"))

	PT(PT_LSS);
	if (AcpiLeaveSleepStatePrep(Sx, acpi_sleep_flags) != AE_OK) {
		PT(PT_LSS_FAIL);
		PMD(PMD_SX, ("Problem with LeaveSleepState!\n"))
	}

	if (AcpiLeaveSleepState(Sx) != AE_OK) {
		PT(PT_LSS_FAIL);
		PMD(PMD_SX, ("Problem with LeaveSleepState!\n"))
	}

	PT(PT_CPB);
	if (AcpiClearEvent(ACPI_EVENT_POWER_BUTTON) != AE_OK) {
		PT(PT_CPB_FAIL);
		PMD(PMD_SX, ("Problem w/ ClearEvent(POWER_BUTTON)\n"))
	}
	if (acpi_rtc_wake > 0 &&
	    AcpiDisableEvent(ACPI_EVENT_RTC, 0) != AE_OK) {
		PT(PT_DRTC_FAIL);
		PMD(PMD_SX, ("Problem w/ DisableEvent(RTC)\n"))
	}

	PMD(PMD_SX, ("Exiting acpi_sleepstate() => 0\n"))

	return (0);
}
