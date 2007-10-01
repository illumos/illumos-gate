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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Solaris x86 ACPI CA services
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/file.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>

#include <sys/acpi/acpi.h>
#include <sys/acpica.h>

/*
 *
 */
static	struct modlmisc modlmisc = {
	&mod_miscops,
	"ACPI interpreter",
};

static	struct modlinkage modlinkage = {
	MODREV_1,		/* MODREV_1 manual */
	(void *)&modlmisc,	/* module linkage */
	NULL,			/* list terminator */
};

/*
 * Local data
 */

static kmutex_t	acpica_module_lock;

/*
 * State of acpica subsystem
 * After successful initialization, will be ACPICA_INITIALIZED
 */
int acpica_init_state = ACPICA_NOT_INITIALIZED;

/*
 * Following are set by acpica_process_user_options()
 *
 * acpica_enable = FALSE prevents initialization of ACPI CA
 * completely
 *
 * acpi_init_level determines level of ACPI CA functionality
 * enabled in acpica_init()
 */
int	acpica_enable;
UINT32	acpi_init_level;

/*
 * Non-zero enables lax behavior with respect to some
 * common ACPI BIOS issues; see ACPI CA documentation
 * Setting this to zero causes ACPI CA to enforce strict
 * compliance with ACPI specification
 */
int acpica_enable_interpreter_slack = 1;

/*
 * For non-DEBUG builds, set the ACPI CA debug level to 0
 * to quiet chatty BIOS output into /var/adm/messages
 * Field-patchable for diagnostic use.
 */
#ifdef  DEBUG
int acpica_muzzle_debug_output = 0;
#else
int acpica_muzzle_debug_output = 1;
#endif


int
_init(void)
{
	int error = EBUSY;
	int	status;

	mutex_init(&acpica_module_lock, NULL, MUTEX_DRIVER, NULL);

	if ((error = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&acpica_module_lock);
	}

	AcpiGbl_EnableInterpreterSlack = (acpica_enable_interpreter_slack != 0);

	if ((status = AcpiInitializeSubsystem()) != AE_OK) {
		cmn_err(CE_WARN, "!acpica: error pre-init:1:%d", status);
	}

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	/*
	 * acpica module is never unloaded at run-time; there's always
	 * a PSM depending on it, at the very least
	 */
	return (EBUSY);
}

/*
 * Install acpica-provided address-space handlers
 */
static int
acpica_install_handlers()
{
	ACPI_STATUS	rv = AE_OK;

	/*
	 * Install ACPI CA default handlers
	 */
	if (AcpiInstallAddressSpaceHandler(ACPI_ROOT_OBJECT,
	    ACPI_ADR_SPACE_SYSTEM_MEMORY,
	    ACPI_DEFAULT_HANDLER, NULL, NULL) != AE_OK) {
		cmn_err(CE_WARN, "!acpica: no default handler for"
		    " system memory");
		rv = AE_ERROR;
	}

	if (AcpiInstallAddressSpaceHandler(ACPI_ROOT_OBJECT,
	    ACPI_ADR_SPACE_SYSTEM_IO,
	    ACPI_DEFAULT_HANDLER, NULL, NULL) != AE_OK) {
		cmn_err(CE_WARN, "!acpica: no default handler for"
		    " system I/O");
		rv = AE_ERROR;
	}

	if (AcpiInstallAddressSpaceHandler(ACPI_ROOT_OBJECT,
	    ACPI_ADR_SPACE_PCI_CONFIG,
	    ACPI_DEFAULT_HANDLER, NULL, NULL) != AE_OK) {
		cmn_err(CE_WARN, "!acpica: no default handler for"
		    " PCI Config");
		rv = AE_ERROR;
	}


	return (rv);
}

/*
 * Find the BIOS date, and return TRUE if supplied
 * date is same or later than the BIOS date, or FALSE
 * if the BIOS date can't be fetched for any reason
 */
static int
acpica_check_bios_date(int yy, int mm, int dd)
{

	char *datep;
	int bios_year, bios_month, bios_day;

	/* If firmware has no bios, skip the check */
	if (ddi_prop_exists(DDI_DEV_T_ANY, ddi_root_node(), 0, "bios-free"))
		return (TRUE);

	/*
	 * PC BIOSes contain a string in the form of
	 * "mm/dd/yy" at absolute address 0xffff5,
	 * where mm, dd and yy are all ASCII digits.
	 * We map the string, pluck out the values,
	 * and accept all BIOSes from 1 Jan 1999 on
	 * as valid.
	 */

	if ((int)AcpiOsMapMemory(0xffff5, 8, (void **) &datep) != AE_OK)
		return (FALSE);

	/* year */
	bios_year = ((int)(*(datep + 6) - '0') * 10) + (*(datep + 7) - '0');
	/* month */
	bios_month = ((int)(*datep - '0') * 10) + (*(datep + 1) - '0');
	/* day */
	bios_day = ((int)(*(datep + 3) - '0') * 10) + (*(datep + 4) - '0');

	AcpiOsUnmapMemory((void *) datep, 8);

	if (bios_year < 0 || bios_year > 99 || bios_month < 0 ||
	    bios_month > 99 || bios_day < 0 || bios_day > 99) {
		/* non-digit chars in BIOS date */
		return (FALSE);
	}

	/*
	 * Adjust for 2-digit year; note to grand-children:
	 * need a new scheme before 2080 rolls around
	 */
	bios_year += (bios_year >= 80 && bios_year <= 99) ?
	    1900 : 2000;

	if (bios_year < yy)
		return (FALSE);
	else if (bios_year > yy)
		return (TRUE);

	if (bios_month < mm)
		return (FALSE);
	else if (bios_month > mm)
		return (TRUE);

	if (bios_day < dd)
		return (FALSE);

	return (TRUE);
}

/*
 * Check for Metropolis systems with BIOSes older than 10/12/04
 * return TRUE if BIOS requires legacy mode, FALSE otherwise
 */
static int
acpica_metro_old_bios()
{
	ACPI_TABLE_HEADER *fadt;

	/* get the FADT */
	if (AcpiGetFirmwareTable(FADT_SIG, 1, ACPI_LOGICAL_ADDRESSING,
	    (ACPI_TABLE_HEADER **)&fadt) != AE_OK)
		return (FALSE);

	/* compare OEM Table ID to "SUNmetro" - no match, return false */
	if (strncmp("SUNmetro", fadt->OemTableId, 8))
		return (FALSE);

	/* On a Metro - return FALSE if later than 10/12/04 */
	return (!acpica_check_bios_date(2004, 10, 12));
}


/*
 * Process acpi-user-options property  if present
 */
static void
acpica_process_user_options()
{
	static int processed = 0;
	int acpi_user_options;
	char *acpi_prop;

	/*
	 * return if acpi-user-options has already been processed
	 */
	if (processed)
		return;
	else
		processed = 1;

	/* converts acpi-user-options from type string to int, if any */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "acpi-user-options", &acpi_prop) ==
	    DDI_PROP_SUCCESS) {
		long data;
		int ret;
		ret = ddi_strtol(acpi_prop, NULL, 0, &data);
		if (ret == 0) {
			e_ddi_prop_remove(DDI_DEV_T_NONE, ddi_root_node(),
			    "acpi-user-options");
			e_ddi_prop_update_int(DDI_DEV_T_NONE, ddi_root_node(),
			    "acpi-user-options", data);
		}
		ddi_prop_free(acpi_prop);
	}

	/*
	 * fetch the optional options property
	 */
	acpi_user_options = ddi_prop_get_int(DDI_DEV_T_ANY, ddi_root_node(), 0,
	    "acpi-user-options", 0);

	/*
	 * Note that 'off' has precedence over 'on'
	 * Also note - all cases of ACPI_OUSER_MASK
	 * provided here, no default: case is present
	 */
	switch (acpi_user_options & ACPI_OUSER_MASK) {
	case ACPI_OUSER_DFLT:
		acpica_enable = acpica_check_bios_date(1999, 1, 1);
		break;
	case ACPI_OUSER_ON:
		acpica_enable = TRUE;
		break;
	case ACPI_OUSER_OFF:
	case ACPI_OUSER_OFF | ACPI_OUSER_ON:
		acpica_enable = FALSE;
		break;
	}

	acpi_init_level = ACPI_FULL_INITIALIZATION;

	/*
	 * special test here; may be generalized in the
	 * future - test for a machines that are known to
	 * work only in legacy mode, and set OUSER_LEGACY if
	 * we're on one
	 */
	if (acpica_metro_old_bios())
		acpi_user_options |= ACPI_OUSER_LEGACY;

	/*
	 * If legacy mode is specified, set initialization
	 * options to avoid entering ACPI mode and hooking SCI
	 * - basically try to act like legacy acpi_intp
	 */
	if ((acpi_user_options & ACPI_OUSER_LEGACY) != 0)
		acpi_init_level |= (ACPI_NO_ACPI_ENABLE | ACPI_NO_HANDLER_INIT);

	/*
	 * modify default ACPI CA debug output level for non-DEBUG builds
	 * (to avoid BIOS debug chatter in /var/adm/messages)
	 */
	if (acpica_muzzle_debug_output)
		AcpiDbgLevel = 0;
}

/*
 * Initialize the CA subsystem if it hasn't been done already
 */
int
acpica_init()
{
	ACPI_STATUS status;

	/*
	 * Make sure user options are processed,
	 * then fail to initialize if ACPI CA has been
	 * disabled
	 */
	acpica_process_user_options();
	if (!acpica_enable)
		return (AE_ERROR);

	mutex_enter(&acpica_module_lock);

	if (acpica_init_state == ACPICA_NOT_INITIALIZED) {
		if ((status = AcpiLoadTables()) != AE_OK) {
			goto error;
		}
		if ((status = acpica_install_handlers()) != AE_OK) {
			goto error;
		}
		if ((status = AcpiEnableSubsystem(acpi_init_level)) != AE_OK) {
			goto error;
		}
		if ((status = AcpiInitializeObjects(0)) != AE_OK) {
			goto error;
		}
		/*
		 * Initialize EC
		 */
		acpica_ec_init();

		acpica_init_state = ACPICA_INITIALIZED;
error:
		if (acpica_init_state != ACPICA_INITIALIZED) {
			cmn_err(CE_NOTE, "!failed to initialize"
			    " ACPI services");
		}
	} else
		status = AE_OK;

	/*
	 * Set acpi-status to 13 if acpica has been initialized successfully.
	 * This indicates that acpica is up and running.  This variable name
	 * and value were chosen in order to remain compatible with acpi_intp.
	 */
	e_ddi_prop_update_int(DDI_DEV_T_NONE, ddi_root_node(), "acpi-status",
	    (status == AE_OK) ? (ACPI_BOOT_INIT | ACPI_BOOT_ENABLE |
	    ACPI_BOOT_BOOTCONF) : 0);

	mutex_exit(&acpica_module_lock);
	return (status);
}

/*
 * SCI handling
 */

ACPI_STATUS
acpica_get_sci(int *sci_irq, iflag_t *sci_flags)
{
	APIC_HEADER		*ap;
	MULTIPLE_APIC_TABLE	*mat;
	MADT_INTERRUPT_OVERRIDE	*mio;
	FADT_DESCRIPTOR		*fadt;
	int			madt_seen, madt_size;


	/*
	 * Make sure user options are processed,
	 * then return error if ACPI CA has been
	 * disabled or system is not running in ACPI
	 * and won't need/understand SCI
	 */
	acpica_process_user_options();
	if ((!acpica_enable) || (acpi_init_level & ACPI_NO_ACPI_ENABLE))
		return (AE_ERROR);

	/*
	 * according to Intel ACPI developers, SCI
	 * conforms to PCI bus conventions; level/low
	 * unless otherwise directed by overrides.
	 */
	sci_flags->intr_el = INTR_EL_LEVEL;
	sci_flags->intr_po = INTR_PO_ACTIVE_LOW;
	sci_flags->bustype = BUS_PCI;	/*  we *do* conform to PCI */

	/* get the SCI from the FADT */
	if (AcpiGetFirmwareTable(FADT_SIG, 1, ACPI_LOGICAL_ADDRESSING,
	    (ACPI_TABLE_HEADER **)&fadt) != AE_OK)
		return (AE_ERROR);

	*sci_irq = fadt->SciInt;

	/* search for ISOs that modify it */
	/* if we don't find a MADT, that's OK; no ISOs then */
	if (AcpiGetFirmwareTable(APIC_SIG, 1, ACPI_LOGICAL_ADDRESSING,
	    (ACPI_TABLE_HEADER **) &mat) != AE_OK) {
		return (AE_OK);
	}

	ap = (APIC_HEADER *) (mat + 1);
	madt_size = mat->Length;
	madt_seen = sizeof (*mat);

	while (madt_seen < madt_size) {
		switch (ap->Type) {
		case APIC_XRUPT_OVERRIDE:
			mio = (MADT_INTERRUPT_OVERRIDE *) ap;
			if (mio->Source == *sci_irq) {
				*sci_irq = mio->Interrupt;
				sci_flags->intr_el = mio->TriggerMode;
				sci_flags->intr_po = mio->Polarity;
			}
			break;
		}

		/* advance to next entry */
		madt_seen += ap->Length;
		ap = (APIC_HEADER *)(((char *)ap) + ap->Length);
	}

	/*
	 * One more check; if ISO said "conform", revert to default
	 */
	if (sci_flags->intr_el == INTR_EL_CONFORM)
		sci_flags->intr_el = INTR_EL_LEVEL;
	if (sci_flags->intr_po == INTR_PO_CONFORM)
		sci_flags->intr_po = INTR_PO_ACTIVE_LOW;

	return (AE_OK);
}
