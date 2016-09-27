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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2016, Joyent, Inc.
 */
/*
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */
/*
 * Solaris x86 ACPI CA services
 */

#include <sys/file.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/spl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/kstat.h>
#include <sys/x86_archext.h>

#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/archsystm.h>

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
 * Local prototypes
 */

struct parsed_prw {
	ACPI_HANDLE	prw_gpeobj;
	int		prw_gpebit;
	int		prw_level;
};

static void	acpica_init_kstats(void);
static ACPI_STATUS	acpica_init_PRW(
	ACPI_HANDLE	hdl,
	UINT32		lvl,
	void		*ctxp,
	void		**rvpp);

static ACPI_STATUS	acpica_parse_PRW(
	ACPI_BUFFER	*prw_buf,
	struct parsed_prw *prw);

/*
 * Local data
 */

static kmutex_t	acpica_module_lock;
static kstat_t	*acpica_ksp;

/*
 * State of acpica subsystem
 * After successful initialization, will be ACPICA_INITIALIZED
 */
int acpica_init_state = ACPICA_NOT_INITIALIZED;

void *AcpiGbl_DbBuffer;
uint32_t AcpiGbl_DbConsoleDebugLevel;

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

/*
 * ACPI DDI hooks
 */
static int acpica_ddi_setwake(dev_info_t *dip, int level);

int
_init(void)
{
	int error = EBUSY;
	int	status;
	extern int (*acpi_fp_setwake)();
	extern kmutex_t cpu_map_lock;

	mutex_init(&acpica_module_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&cpu_map_lock, NULL, MUTEX_SPIN,
	    (ddi_iblock_cookie_t)ipltospl(DISP_LEVEL));

	if ((error = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&acpica_module_lock);
		goto load_error;
	}

	AcpiGbl_EnableInterpreterSlack = (acpica_enable_interpreter_slack != 0);

	/* global ACPI CA initialization */
	if (ACPI_FAILURE(status = AcpiInitializeSubsystem()))
		cmn_err(CE_WARN, "!AcpiInitializeSubsystem failed: %d", status);

	/* initialize table manager */
	if (ACPI_FAILURE(status = AcpiInitializeTables(NULL, 0, 0)))
		cmn_err(CE_WARN, "!AcpiInitializeTables failed: %d", status);

	acpi_fp_setwake = acpica_ddi_setwake;

load_error:
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
 * Install acpica-provided (default) address-space handlers
 * that may be needed before AcpiEnableSubsystem() runs.
 * See the comment in AcpiInstallAddressSpaceHandler().
 * Default handlers for remaining address spaces are
 * installed later, in AcpiEnableSubsystem.
 */
static int
acpica_install_handlers()
{
	ACPI_STATUS	rv = AE_OK;
	ACPI_STATUS	res;

	/*
	 * Install ACPI CA default handlers
	 */
	if ((res = AcpiInstallAddressSpaceHandler(ACPI_ROOT_OBJECT,
	    ACPI_ADR_SPACE_SYSTEM_MEMORY,
	    ACPI_DEFAULT_HANDLER, NULL, NULL)) != AE_OK &&
	    res != AE_SAME_HANDLER) {
		cmn_err(CE_WARN, "!acpica: no default handler for"
		    " system memory");
		rv = AE_ERROR;
	}

	if ((res = AcpiInstallAddressSpaceHandler(ACPI_ROOT_OBJECT,
	    ACPI_ADR_SPACE_SYSTEM_IO,
	    ACPI_DEFAULT_HANDLER, NULL, NULL)) != AE_OK &&
	    res != AE_SAME_HANDLER) {
		cmn_err(CE_WARN, "!acpica: no default handler for"
		    " system I/O");
		rv = AE_ERROR;
	}

	if ((res = AcpiInstallAddressSpaceHandler(ACPI_ROOT_OBJECT,
	    ACPI_ADR_SPACE_PCI_CONFIG,
	    ACPI_DEFAULT_HANDLER, NULL, NULL)) != AE_OK &&
	    res != AE_SAME_HANDLER) {
		cmn_err(CE_WARN, "!acpica: no default handler for"
		    " PCI Config");
		rv = AE_ERROR;
	}

	if ((res = AcpiInstallAddressSpaceHandler(ACPI_ROOT_OBJECT,
	    ACPI_ADR_SPACE_DATA_TABLE,
	    ACPI_DEFAULT_HANDLER, NULL, NULL)) != AE_OK &&
	    res != AE_SAME_HANDLER) {
		cmn_err(CE_WARN, "!acpica: no default handler for"
		    " Data Table");
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
	if (ddi_prop_exists(DDI_DEV_T_ANY, ddi_root_node(), DDI_PROP_DONTPASS,
	    "bios-free"))
		return (TRUE);

	/*
	 * PC BIOSes contain a string in the form of
	 * "mm/dd/yy" at absolute address 0xffff5,
	 * where mm, dd and yy are all ASCII digits.
	 * We map the string, pluck out the values,
	 * and accept all BIOSes from 1 Jan 1999 on
	 * as valid.
	 */

	if ((datep = (char *)AcpiOsMapMemory(0xffff5, 8)) == NULL)
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
	if (AcpiGetTable(ACPI_SIG_FADT, 1, (ACPI_TABLE_HEADER **)&fadt) !=
	    AE_OK)
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
	acpi_user_options = ddi_prop_get_int(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "acpi-user-options", 0);

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
	extern void acpica_find_ioapics(void);
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
	if (acpica_init_state == ACPICA_INITIALIZED) {
		mutex_exit(&acpica_module_lock);
		return (AE_OK);
	}

	if (ACPI_FAILURE(status = AcpiLoadTables()))
		goto error;

	if (ACPI_FAILURE(status = acpica_install_handlers()))
		goto error;

	/*
	 * Create ACPI-to-devinfo mapping now so _INI and _STA
	 * methods can access PCI config space when needed
	 */
	scan_d2a_map();

	if (ACPI_FAILURE(status = AcpiEnableSubsystem(acpi_init_level)))
		goto error;

	/* do after AcpiEnableSubsystem() so GPEs are initialized */
	acpica_ec_init();	/* initialize EC if present */

	/* This runs all device _STA and _INI methods. */
	if (ACPI_FAILURE(status = AcpiInitializeObjects(0)))
		goto error;

	acpica_init_state = ACPICA_INITIALIZED;

	/*
	 * [ACPI, sec. 4.4.1.1]
	 * As of ACPICA version 20101217 (December 2010), the _PRW methods
	 * (Power Resources for Wake) are no longer automatically executed
	 * as part of the ACPICA initialization.  The OS must do this.
	 */
	(void) AcpiWalkNamespace(ACPI_TYPE_DEVICE, ACPI_ROOT_OBJECT,
	    UINT32_MAX, acpica_init_PRW, NULL, NULL, NULL);
	(void) AcpiUpdateAllGpes();

	/*
	 * If we are running on the Xen hypervisor as dom0 we need to
	 * find the ioapics so we can prevent ACPI from trying to
	 * access them.
	 */
	if (get_hwenv() == HW_XEN_PV && is_controldom())
		acpica_find_ioapics();
	acpica_init_kstats();
error:
	if (acpica_init_state != ACPICA_INITIALIZED) {
		cmn_err(CE_NOTE, "!failed to initialize ACPI services");
	}

	/*
	 * Set acpi-status to 13 if acpica has been initialized successfully.
	 * This indicates that acpica is up and running.  This variable name
	 * and value were chosen in order to remain compatible with acpi_intp.
	 */
	e_ddi_prop_update_int(DDI_DEV_T_NONE, ddi_root_node(), "acpi-status",
	    (ACPI_SUCCESS(status)) ? (ACPI_BOOT_INIT | ACPI_BOOT_ENABLE |
	    ACPI_BOOT_BOOTCONF) : 0);

	/* Mark acpica subsystem as fully initialized. */
	if (ACPI_SUCCESS(status) &&
	    acpi_init_level == ACPI_FULL_INITIALIZATION) {
		acpica_set_core_feature(ACPI_FEATURE_FULL_INIT);
	}

	mutex_exit(&acpica_module_lock);
	return (status);
}

/*
 * SCI handling
 */

ACPI_STATUS
acpica_get_sci(int *sci_irq, iflag_t *sci_flags)
{
	ACPI_SUBTABLE_HEADER		*ap;
	ACPI_TABLE_MADT			*mat;
	ACPI_MADT_INTERRUPT_OVERRIDE	*mio;
	ACPI_TABLE_FADT			*fadt;
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
	if (AcpiGetTable(ACPI_SIG_FADT, 1, (ACPI_TABLE_HEADER **)&fadt) !=
	    AE_OK)
		return (AE_ERROR);

	*sci_irq = fadt->SciInterrupt;

	/* search for ISOs that modify it */
	/* if we don't find a MADT, that's OK; no ISOs then */
	if (AcpiGetTable(ACPI_SIG_MADT, 1, (ACPI_TABLE_HEADER **) &mat) !=
	    AE_OK)
		return (AE_OK);

	ap = (ACPI_SUBTABLE_HEADER *) (mat + 1);
	madt_size = mat->Header.Length;
	madt_seen = sizeof (*mat);

	while (madt_seen < madt_size) {
		switch (ap->Type) {
		case ACPI_MADT_TYPE_INTERRUPT_OVERRIDE:
			mio = (ACPI_MADT_INTERRUPT_OVERRIDE *) ap;
			if (mio->SourceIrq == *sci_irq) {
				*sci_irq = mio->GlobalIrq;
				sci_flags->intr_el = (mio->IntiFlags &
				    ACPI_MADT_TRIGGER_MASK) >> 2;
				sci_flags->intr_po = mio->IntiFlags &
				    ACPI_MADT_POLARITY_MASK;
			}
			break;
		}

		/* advance to next entry */
		madt_seen += ap->Length;
		ap = (ACPI_SUBTABLE_HEADER *)(((char *)ap) + ap->Length);
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

/*
 * Call-back function used for _PRW initialization.  For every
 * device node that has a _PRW method, evaluate, parse, and do
 * AcpiSetupGpeForWake().
 */
static ACPI_STATUS
acpica_init_PRW(
	ACPI_HANDLE	devhdl,
	UINT32		depth,
	void		*ctxp,
	void		**rvpp)
{
	ACPI_STATUS	status;
	ACPI_BUFFER	prw_buf;
	struct parsed_prw prw;

	prw_buf.Pointer = NULL;
	prw_buf.Length = ACPI_ALLOCATE_BUFFER;

	/*
	 * Attempt to evaluate _PRW object.
	 * If no valid object is found, return quietly, since not all
	 * devices have _PRW objects.
	 */
	status = AcpiEvaluateObject(devhdl, "_PRW", NULL, &prw_buf);
	if (ACPI_FAILURE(status))
		goto done;
	status = acpica_parse_PRW(&prw_buf, &prw);
	if (ACPI_FAILURE(status))
		goto done;

	(void) AcpiSetupGpeForWake(devhdl,
	    prw.prw_gpeobj, prw.prw_gpebit);

done:
	if (prw_buf.Pointer != NULL)
		AcpiOsFree(prw_buf.Pointer);

	return (AE_OK);
}

/*
 * Sets ACPI wake state for device referenced by dip.
 * If level is S0 (0), disables wake event; otherwise,
 * enables wake event which will wake system from level.
 */
static int
acpica_ddi_setwake(dev_info_t *dip, int level)
{
	ACPI_STATUS	status;
	ACPI_HANDLE	devobj;
	ACPI_BUFFER	prw_buf;
	ACPI_OBJECT_LIST	arglist;
	ACPI_OBJECT		args[3];
	struct parsed_prw prw;
	int		rv;

	/*
	 * initialize these early so we can use a common
	 * exit point below
	 */
	prw_buf.Pointer = NULL;
	prw_buf.Length = ACPI_ALLOCATE_BUFFER;
	rv = 0;

	/*
	 * Attempt to get a handle to a corresponding ACPI object.
	 * If no object is found, return quietly, since not all
	 * devices have corresponding ACPI objects.
	 */
	status = acpica_get_handle(dip, &devobj);
	if (ACPI_FAILURE(status)) {
		char pathbuf[MAXPATHLEN];
		ddi_pathname(dip, pathbuf);
#ifdef DEBUG
		cmn_err(CE_NOTE, "!acpica_ddi_setwake: could not get"
		    " handle for %s, %s:%d", pathbuf, ddi_driver_name(dip),
		    ddi_get_instance(dip));
#endif
		goto done;
	}

	/*
	 * ACPI3.0 7.2.1: only use the _PSW method if OSPM does not support
	 * _DSW or if the _DSW method is not present.
	 *
	 * _DSW arguments:
	 * args[0] - Enable/Disable
	 * args[1] - Target system state
	 * args[2] - Target device state
	 */

	arglist.Count = 3;
	arglist.Pointer = args;
	args[0].Type = ACPI_TYPE_INTEGER;
	args[0].Integer.Value = level ? 1 : 0;
	args[1].Type = ACPI_TYPE_INTEGER;
	args[1].Integer.Value = level;
	args[2].Type = ACPI_TYPE_INTEGER;
	args[2].Integer.Value = level;
	if (ACPI_FAILURE(status = AcpiEvaluateObject(devobj, "_DSW",
	    &arglist, NULL))) {

		if (status == AE_NOT_FOUND) {
			arglist.Count = 1;
			args[0].Type = ACPI_TYPE_INTEGER;
			args[0].Integer.Value = level ? 1 : 0;

			if (ACPI_FAILURE(status = AcpiEvaluateObject(devobj,
			    "_PSW", &arglist, NULL))) {

				if (status != AE_NOT_FOUND) {
					cmn_err(CE_NOTE,
					    "!_PSW failure %d for device %s",
					    status, ddi_driver_name(dip));
				}
			}

		} else {
			cmn_err(CE_NOTE, "!_DSW failure %d for device %s",
			    status, ddi_driver_name(dip));
		}
	}

	/*
	 * Attempt to evaluate _PRW object.
	 * If no valid object is found, return quietly, since not all
	 * devices have _PRW objects.
	 */
	status = AcpiEvaluateObject(devobj, "_PRW", NULL, &prw_buf);
	if (ACPI_FAILURE(status))
		goto done;
	status = acpica_parse_PRW(&prw_buf, &prw);
	if (ACPI_FAILURE(status))
		goto done;

	rv = -1;
	if (level == 0) {
		status = AcpiDisableGpe(prw.prw_gpeobj, prw.prw_gpebit);
		if (ACPI_FAILURE(status))
			goto done;
	} else if (prw.prw_level >= level) {
		status = AcpiSetGpeWakeMask(prw.prw_gpeobj, prw.prw_gpebit,
		    ACPI_GPE_ENABLE);
		if (ACPI_SUCCESS(status)) {
			status = AcpiEnableGpe(prw.prw_gpeobj, prw.prw_gpebit);
			if (ACPI_FAILURE(status))
				goto done;
		}
	}
	rv = 0;
done:
	if (prw_buf.Pointer != NULL)
		AcpiOsFree(prw_buf.Pointer);
	return (rv);
}

static ACPI_STATUS
acpica_parse_PRW(
	ACPI_BUFFER	*prw_buf,
	struct parsed_prw *p_prw)
{
	ACPI_HANDLE	gpeobj;
	ACPI_OBJECT	*prw, *gpe;
	int		gpebit, prw_level;

	if (prw_buf->Length == 0 || prw_buf->Pointer == NULL)
		return (AE_NULL_OBJECT);

	prw = prw_buf->Pointer;
	if (prw->Type != ACPI_TYPE_PACKAGE || prw->Package.Count < 2 ||
	    prw->Package.Elements[1].Type != ACPI_TYPE_INTEGER)
		return (AE_TYPE);

	/* fetch the lowest wake level from the _PRW */
	prw_level = prw->Package.Elements[1].Integer.Value;

	/*
	 * process the GPE description
	 */
	switch (prw->Package.Elements[0].Type) {
	case ACPI_TYPE_INTEGER:
		gpeobj = NULL;
		gpebit = prw->Package.Elements[0].Integer.Value;
		break;
	case ACPI_TYPE_PACKAGE:
		gpe = &prw->Package.Elements[0];
		if (gpe->Package.Count != 2 ||
		    gpe->Package.Elements[1].Type != ACPI_TYPE_INTEGER)
			return (AE_TYPE);
		gpeobj = gpe->Package.Elements[0].Reference.Handle;
		gpebit = gpe->Package.Elements[1].Integer.Value;
		if (gpeobj == NULL)
			return (AE_NULL_OBJECT);
		break;
	default:
		return (AE_TYPE);
	}

	p_prw->prw_gpeobj = gpeobj;
	p_prw->prw_gpebit = gpebit;
	p_prw->prw_level  = prw_level;

	return (AE_OK);
}

/*
 * kstat access to a limited set of ACPI propertis
 */
static void
acpica_init_kstats()
{
	ACPI_HANDLE	s3handle;
	ACPI_STATUS	status;
	ACPI_TABLE_FADT	*fadt;
	kstat_named_t *knp;

	/*
	 * Create a small set of named kstats; just return in the rare
	 * case of a failure, * in which case, the kstats won't be present.
	 */
	if ((acpica_ksp = kstat_create("acpi", 0, "acpi", "misc",
	    KSTAT_TYPE_NAMED, 2, 0)) == NULL)
		return;

	/*
	 * initialize kstat 'S3' to reflect the presence of \_S3 in
	 * the ACPI namespace (1 = present, 0 = not present)
	 */
	knp = acpica_ksp->ks_data;
	knp->value.l = (AcpiGetHandle(NULL, "\\_S3", &s3handle) == AE_OK);
	kstat_named_init(knp, "S3", KSTAT_DATA_LONG);
	knp++;		/* advance to next named kstat */

	/*
	 * initialize kstat 'preferred_pm_profile' to the value
	 * contained in the (always present) FADT
	 */
	status = AcpiGetTable(ACPI_SIG_FADT, 1, (ACPI_TABLE_HEADER **)&fadt);
	knp->value.l = (status == AE_OK) ? fadt->PreferredProfile : -1;
	kstat_named_init(knp, "preferred_pm_profile", KSTAT_DATA_LONG);

	/*
	 * install the named kstats
	 */
	kstat_install(acpica_ksp);
}

/*
 * Attempt to save the current ACPI settings (_CRS) for the device
 * which corresponds to the supplied devinfo node.  The settings are
 * saved as a property on the dip.  If no ACPI object is found to be
 * associated with the devinfo node, no action is taken and no error
 * is reported.
 */
void
acpica_ddi_save_resources(dev_info_t *dip)
{
	ACPI_HANDLE	devobj;
	ACPI_BUFFER	resbuf;
	int		ret;

	resbuf.Length = ACPI_ALLOCATE_BUFFER;
	if (ACPI_FAILURE(acpica_get_handle(dip, &devobj)) ||
	    ACPI_FAILURE(AcpiGetCurrentResources(devobj, &resbuf)))
		return;

	ret = ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    "acpi-crs", resbuf.Pointer, resbuf.Length);

	ASSERT(ret == DDI_PROP_SUCCESS);

	AcpiOsFree(resbuf.Pointer);
}

/*
 * If the supplied devinfo node has an ACPI settings property attached,
 * restore them to the associated ACPI device using _SRS.  The property
 * is deleted from the devinfo node afterward.
 */
void
acpica_ddi_restore_resources(dev_info_t *dip)
{
	ACPI_HANDLE	devobj;
	ACPI_BUFFER	resbuf;
	uchar_t		*propdata;
	uint_t		proplen;

	if (ACPI_FAILURE(acpica_get_handle(dip, &devobj)))
		return;

	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "acpi-crs", &propdata, &proplen) != DDI_PROP_SUCCESS)
		return;

	resbuf.Pointer = propdata;
	resbuf.Length = proplen;
	(void) AcpiSetCurrentResources(devobj, &resbuf);
	ddi_prop_free(propdata);
	(void) ddi_prop_remove(DDI_DEV_T_NONE, dip, "acpi-crs");
}

void
acpi_reset_system(void)
{
	ACPI_STATUS status;
	int ten;

	status = AcpiReset();
	if (status == AE_OK) {
		/*
		 * Wait up to 500 milliseconds for AcpiReset() to make its
		 * way.
		 */
		ten = 50000;
		while (ten-- > 0)
			tenmicrosec();
	}
}
