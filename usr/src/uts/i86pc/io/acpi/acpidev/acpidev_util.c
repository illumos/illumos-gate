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
 * Copyright (c) 2018, Joyent, Inc.
 */
/*
 * Copyright (c) 2009-2010, Intel Corporation.
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/note.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>
#include <sys/acpidev_impl.h>
#include <util/sscanf.h>

/* Data structures used to extract the numeric unit address from string _UID. */
static acpidev_pseudo_uid_head_t acpidev_uid_heads[ACPIDEV_CLASS_ID_MAX];
static char *acpidev_uid_formats[] = {
	"%u",
};

static char *acpidev_unknown_object_name = "<unknown>";

int
acpidev_query_device_status(ACPI_HANDLE hdl)
{
	int status;

	ASSERT(hdl != NULL);
	if (hdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: hdl is NULL in acpidev_query_device_status().");
		return (0);
	}

	if (ACPI_FAILURE(acpica_get_object_status(hdl, &status))) {
		/*
		 * When the object status is not present, it will generally be
		 * set to the default value as per the ACPI specification (6.3.7
		 * _STA (Status)).  However, there are other possible cases of
		 * ACPI failures. As this code is not aware of them and has
		 * always treated all failures like the not-present set. Do the
		 * same for the time being.
		 */
		status = 0xF;
	}

	return (status);
}

boolean_t
acpidev_check_device_present(int status)
{
	/*
	 * According to ACPI3.0 Spec, if either the ACPI_STA_DEVICE_PRESENT bit
	 * or the ACPI_STA_DEVICE_FUNCTIONING bit is set, the device exists.
	 */
	if (status & (ACPI_STA_DEVICE_PRESENT | ACPI_STA_DEVICE_FUNCTIONING)) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

boolean_t
acpidev_check_device_enabled(int stat)
{
	/*
	 * According to ACPI3.0 Spec, if either the ACPI_STA_DEVICE_PRESENT bit
	 * or the ACPI_STA_DEVICE_FUNCTIONING bit is set, the device exists.
	 * Return true if device exists and has been enabled.
	 */
	if ((stat & (ACPI_STA_DEVICE_PRESENT | ACPI_STA_DEVICE_FUNCTIONING)) &&
	    (stat & ACPI_STA_DEVICE_ENABLED)) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

boolean_t
acpidev_match_device_id(ACPI_DEVICE_INFO *infop, char **ids, int count)
{
	int i, j;

	ASSERT(infop != NULL);
	ASSERT(ids != NULL || count == 0);
	/* Special case to match all devices if count is 0. */
	if (count == 0) {
		return (B_TRUE);
	} else if (infop == NULL || ids == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameters in "
		    "acpidev_match_device_id().");
		return (B_FALSE);
	}

	/* Match _HID first. */
	if (infop->Valid & ACPI_VALID_HID) {
		for (i = 0; i < count; i++) {
			if (strncmp(ids[i], infop->HardwareId.String,
			    infop->HardwareId.Length) == 0) {
				return (B_TRUE);
			}
		}
	}

	/* Match _CID next. */
	if (infop->Valid & ACPI_VALID_CID) {
		for (i = 0; i < count; i++) {
			for (j = 0; j < infop->CompatibleIdList.Count; j++) {
				if (strncmp(ids[i],
				    infop->CompatibleIdList.Ids[j].String,
				    infop->CompatibleIdList.Ids[j].Length)
				    == 0) {
					return (B_TRUE);
				}
			}
		}
	}

	return (B_FALSE);
}

struct acpidev_get_device_arg {
	boolean_t		skip_non_exist;
	int			id_count;
	char 			**device_ids;
	void			*user_arg;
	ACPI_WALK_CALLBACK	user_func;
};

static ACPI_STATUS
acpidev_get_device_callback(ACPI_HANDLE hdl, UINT32 level, void *arg,
    void **retval)
{
	ACPI_STATUS rc;
	ACPI_DEVICE_INFO *infop;
	struct acpidev_get_device_arg *argp;
	int status;

	argp = (struct acpidev_get_device_arg *)arg;
	ASSERT(argp != NULL);
	ASSERT(hdl != NULL);

	/* Query object information. */
	rc = AcpiGetObjectInfo(hdl, &infop);
	if (ACPI_FAILURE(rc)) {
		cmn_err(CE_WARN, "!acpidev: failed to get ACPI object info "
		    "in acpidev_get_device_callback().");
		return (AE_CTRL_DEPTH);
	}

	rc = acpica_get_object_status(hdl, &status);

	/*
	 * Skip scanning of children if the device is neither PRESENT nor
	 * FUNCTIONING.
	 * Please refer to ACPI Spec3.0b Sec 6.3.1 and 6.5.1.
	 */
	if (argp->skip_non_exist && rc == AE_OK &&
	    !acpidev_check_device_present(status)) {
		rc = AE_CTRL_DEPTH;
	/* Call user callback if matched. */
	} else if (acpidev_match_device_id(infop, argp->device_ids,
	    argp->id_count)) {
		rc = argp->user_func(hdl, level, argp->user_arg, retval);
	} else {
		rc = AE_OK;
	}

	/* Free ACPI object info buffer. */
	AcpiOsFree(infop);

	return (rc);
}

ACPI_STATUS
acpidev_get_device_by_id(ACPI_HANDLE hdl, char **ids, int count,
    int maxdepth, boolean_t skip_non_exist,
    ACPI_WALK_CALLBACK userfunc, void *userarg, void **retval)
{
	ACPI_STATUS rc;
	struct acpidev_get_device_arg arg;

	ASSERT(userfunc != NULL);
	if (hdl == NULL || userfunc == NULL || (ids == NULL && count != 0)) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameters "
		    "in acpidev_get_device_by_id().");
		return (AE_BAD_PARAMETER);
	}

	/* Enumerate all descendant objects. */
	arg.skip_non_exist = skip_non_exist;
	arg.device_ids = ids;
	arg.id_count = count;
	arg.user_arg = userarg;
	arg.user_func = userfunc;
	rc = AcpiWalkNamespace(ACPI_TYPE_DEVICE, hdl, maxdepth,
	    &acpidev_get_device_callback, NULL, &arg, retval);

	return (rc);
}

ACPI_STATUS
acpidev_walk_apic(ACPI_BUFFER *bufp, ACPI_HANDLE hdl, char *method,
    acpidev_apic_walker_t func, void *context)
{
	ACPI_STATUS rc;
	ssize_t len;
	ACPI_BUFFER buf;
	ACPI_OBJECT *obj;
	ACPI_SUBTABLE_HEADER *ap;
	ACPI_TABLE_MADT *mp = NULL;

	ASSERT(func != NULL);
	if (func == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: invalid parameters for acpidev_walk_apic().");
		return (AE_BAD_PARAMETER);
	}

	buf.Pointer = NULL;
	buf.Length = ACPI_ALLOCATE_BUFFER;

	/* A walk buffer was passed in if bufp isn't NULL. */
	if (bufp != NULL) {
		ap = (ACPI_SUBTABLE_HEADER *)(bufp->Pointer);
		len = bufp->Length;
	} else if (method != NULL) {
		/*
		 * Otherwise, if we have an evaluate method, we get the walk
		 * buffer from a successful invocation of
		 * AcpiEvaluateObjectTyped().
		 */
		ASSERT(hdl != NULL);
		rc = AcpiEvaluateObjectTyped(hdl, method, NULL, &buf,
		    ACPI_TYPE_BUFFER);
		if (ACPI_SUCCESS(rc)) {
			ASSERT(buf.Length >= sizeof (*obj));
			obj = buf.Pointer;
			ap = (ACPI_SUBTABLE_HEADER *)obj->Buffer.Pointer;
			len = obj->Buffer.Length;
		} else {
			if (rc != AE_NOT_FOUND)
				cmn_err(CE_WARN, "!acpidev: failed to evaluate "
				    "%s in acpidev_walk_apic().", method);
			return (rc);
		}
	} else {
		/* As a last resort, walk the MADT table. */
		rc = AcpiGetTable(ACPI_SIG_MADT, 1, (ACPI_TABLE_HEADER **)&mp);
		if (ACPI_FAILURE(rc)) {
			cmn_err(CE_WARN, "!acpidev: failed to get MADT table "
			    "in acpidev_walk_apic().");
			return (rc);
		}
		ap = (ACPI_SUBTABLE_HEADER *)(mp + 1);
		len = mp->Header.Length - sizeof (*mp);
	}

	ASSERT(len >= 0);
	for (rc = AE_OK; len > 0 && ACPI_SUCCESS(rc); len -= ap->Length,
	    ap = (ACPI_SUBTABLE_HEADER *)(((char *)ap) + ap->Length)) {
		ASSERT(len >= sizeof (ACPI_SUBTABLE_HEADER));
		if (len <= sizeof (ACPI_SUBTABLE_HEADER) ||
		    ap->Length <= sizeof (ACPI_SUBTABLE_HEADER) ||
		    len < ap->Length) {
			cmn_err(CE_WARN,
			    "!acpidev: invalid APIC entry in MADT/_MAT.");
			break;
		}
		rc = (*func)(ap, context);
	}

	if (buf.Pointer != NULL) {
		AcpiOsFree(buf.Pointer);
	}

	return (rc);
}

char *
acpidev_get_object_name(ACPI_HANDLE hdl)
{
	ACPI_BUFFER buf;
	char *objname = acpidev_unknown_object_name;

	buf.Length = ACPI_ALLOCATE_BUFFER;
	buf.Pointer = NULL;
	if (ACPI_SUCCESS(AcpiGetName(hdl, ACPI_FULL_PATHNAME, &buf))) {
		ASSERT(buf.Pointer != NULL);
		objname = (char *)buf.Pointer;
	}

	return (objname);
}

void
acpidev_free_object_name(char *objname)
{
	if (objname != acpidev_unknown_object_name && objname != NULL) {
		AcpiOsFree(objname);
	}
}

acpidev_walk_info_t *
acpidev_alloc_walk_info(acpidev_op_type_t op_type, int lvl, ACPI_HANDLE hdl,
    acpidev_class_list_t **listpp, acpidev_walk_info_t *pinfop)
{
	acpidev_walk_info_t *infop = NULL;
	acpidev_data_handle_t datap = NULL;

	ASSERT(0 <= lvl && lvl < ACPIDEV_MAX_ENUM_LEVELS);
	infop = kmem_zalloc(sizeof (*infop), KM_SLEEP);
	infop->awi_op_type = op_type;
	infop->awi_level = lvl;
	infop->awi_parent = pinfop;
	infop->awi_class_list = listpp;
	infop->awi_hdl = hdl;
	infop->awi_name = acpidev_get_object_name(hdl);

	/* Cache ACPI device information. */
	if (ACPI_FAILURE(AcpiGetObjectInfo(hdl, &infop->awi_info))) {
		cmn_err(CE_WARN, "!acpidev: failed to get object info for %s "
		    "in acpidev_alloc_walk_info().", infop->awi_name);
		acpidev_free_object_name(infop->awi_name);
		kmem_free(infop, sizeof (*infop));
		return (NULL);
	}

	/*
	 * Get or create an ACPI object data handle, which will be used to
	 * maintain object status information.
	 */
	if ((datap = acpidev_data_get_handle(hdl)) != NULL) {
		ASSERT(datap->aod_hdl == hdl);
		ASSERT(datap->aod_level == lvl);
	} else if ((datap = acpidev_data_create_handle(hdl)) != NULL) {
		datap->aod_level = lvl;
		datap->aod_hdl = hdl;
	} else {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to create object "
		    "handle for %s in acpidev_alloc_walk_info().",
		    infop->awi_name);
		AcpiOsFree(infop->awi_info);
		acpidev_free_object_name(infop->awi_name);
		kmem_free(infop, sizeof (*infop));
		return (NULL);
	}
	infop->awi_data = datap;
	/* Sync DEVICE_CREATED flag. */
	if (datap->aod_iflag & ACPIDEV_ODF_DEVINFO_CREATED) {
		ASSERT(datap->aod_dip != NULL);
		ASSERT(datap->aod_class != NULL);
		infop->awi_dip = datap->aod_dip;
		infop->awi_flags |= ACPIDEV_WI_DEVICE_CREATED;
	}

	return (infop);
}

void
acpidev_free_walk_info(acpidev_walk_info_t *infop)
{
	/*
	 * The ACPI object data handle will only be released when the
	 * corresponding object is going to be destroyed.
	 */
	if (infop != NULL) {
		if (infop->awi_info != NULL) {
			AcpiOsFree(infop->awi_info);
		}
		if (infop->awi_name != NULL) {
			acpidev_free_object_name(infop->awi_name);
		}
		kmem_free(infop, sizeof (*infop));
	}
}

dev_info_t *
acpidev_walk_info_get_pdip(acpidev_walk_info_t *infop)
{
	while (infop != NULL) {
		if (infop->awi_dip != NULL) {
			return (infop->awi_dip);
		}
		infop = infop->awi_parent;
	}

	return (NULL);
}

/*
 * Called to release resources when the corresponding object is going
 * to be destroyed.
 */
static void
acpidev_free_object_handler(ACPI_HANDLE hdl, void *data)
{
	_NOTE(ARGUNUSED(hdl));

	acpidev_data_handle_t objhdl = data;

	if (objhdl->aod_class != NULL) {
		atomic_dec_32(&objhdl->aod_class->adc_refcnt);
		objhdl->aod_class = NULL;
	}
	kmem_free(objhdl, sizeof (acpidev_data_handle_t));
}

acpidev_data_handle_t
acpidev_data_get_handle(ACPI_HANDLE hdl)
{
	void *ptr;
	acpidev_data_handle_t objhdl = NULL;

	if (ACPI_SUCCESS(AcpiGetData(hdl, acpidev_free_object_handler, &ptr))) {
		objhdl = (acpidev_data_handle_t)ptr;
	}

	return (objhdl);
}

acpidev_data_handle_t
acpidev_data_create_handle(ACPI_HANDLE hdl)
{
	acpidev_data_handle_t objhdl;

	objhdl = kmem_zalloc(sizeof (*objhdl), KM_SLEEP);
	objhdl->aod_bdtype = ACPIDEV_INVALID_BOARD;
	objhdl->aod_bdnum = UINT32_MAX;
	objhdl->aod_portid = UINT32_MAX;
	objhdl->aod_class_id = ACPIDEV_CLASS_ID_INVALID;

	if (ACPI_FAILURE(AcpiAttachData(hdl, acpidev_free_object_handler,
	    (void *)objhdl))) {
		cmn_err(CE_WARN,
		    "!acpidev: failed to attach handle data to object.");
		kmem_free(objhdl, sizeof (*objhdl));
		return (NULL);
	}

	return (objhdl);
}

void
acpidev_data_destroy_handle(ACPI_HANDLE hdl)
{
	void *ptr;
	acpidev_data_handle_t objhdl = NULL;

	if (ACPI_SUCCESS(AcpiGetData(hdl, acpidev_free_object_handler, &ptr)) &&
	    ACPI_SUCCESS(AcpiDetachData(hdl, acpidev_free_object_handler))) {
		objhdl = ptr;
		if (objhdl->aod_class != NULL) {
			atomic_dec_32(&objhdl->aod_class->adc_refcnt);
			objhdl->aod_class = NULL;
		}
		kmem_free(ptr, sizeof (acpidev_data_handle_t));
	}
}

ACPI_HANDLE
acpidev_data_get_object(acpidev_data_handle_t hdl)
{
	ASSERT(hdl != NULL);
	return ((hdl != NULL) ? hdl->aod_hdl : NULL);
}

dev_info_t *
acpidev_data_get_devinfo(acpidev_data_handle_t hdl)
{
	ASSERT(hdl != NULL);
	if (hdl == NULL ||
	    (hdl->aod_iflag & ACPIDEV_ODF_DEVINFO_CREATED) == 0) {
		return (NULL);
	} else {
		ASSERT(hdl->aod_dip != NULL);
		return (hdl->aod_dip);
	}
}

int
acpidev_data_get_status(acpidev_data_handle_t hdl)
{
	ASSERT(hdl != NULL);
	if (hdl == NULL ||
	    (hdl->aod_iflag & ACPIDEV_ODF_STATUS_VALID) == 0) {
		return (0);
	} else {
		return (hdl->aod_status);
	}
}

void
acpidev_data_set_flag(acpidev_data_handle_t hdl, uint32_t flag)
{
	ASSERT(hdl != NULL);
	atomic_or_32(&hdl->aod_eflag, flag);
}

void
acpidev_data_clear_flag(acpidev_data_handle_t hdl, uint32_t flag)
{
	ASSERT(hdl != NULL);
	atomic_and_32(&hdl->aod_eflag, ~flag);
}

uint32_t
acpidev_data_get_flag(acpidev_data_handle_t hdl, uint32_t flag)
{
	ASSERT(hdl != NULL);
	return (hdl->aod_eflag & flag);
}

boolean_t
acpidev_data_dr_capable(acpidev_data_handle_t hdl)
{
	ASSERT(hdl != NULL);
	return (hdl->aod_iflag & ACPIDEV_ODF_HOTPLUG_CAPABLE);
}

boolean_t
acpidev_data_dr_ready(acpidev_data_handle_t hdl)
{
	ASSERT(hdl != NULL);
	return (hdl->aod_iflag & ACPIDEV_ODF_HOTPLUG_READY);
}

boolean_t
acpidev_data_dr_failed(acpidev_data_handle_t hdl)
{
	ASSERT(hdl != NULL);
	return (hdl->aod_iflag & ACPIDEV_ODF_HOTPLUG_FAILED);
}

static char *
acpidev_generate_pseudo_unitaddr(char *uid, acpidev_class_id_t cid,
    char *buf, size_t len)
{
	acpidev_pseudo_uid_t *up, **pp;

	ASSERT(len >= 64);
	ASSERT(cid >= 0 && cid < ACPIDEV_CLASS_ID_MAX);
	if (cid < 0 || cid >= ACPIDEV_CLASS_ID_MAX) {
		return (NULL);
	}

	mutex_enter(&acpidev_uid_heads[cid].apuh_lock);
	for (pp = &acpidev_uid_heads[cid].apuh_first; *pp != NULL;
	    pp = &(*pp)->apu_next) {
		if (strcmp(uid, (*pp)->apu_uid) == 0 &&
		    (*pp)->apu_cid == cid) {
			break;
		}
	}
	/* uid doesn't exist, create one and insert it into the list. */
	if (*pp == NULL) {
		up = kmem_zalloc(sizeof (*up), KM_SLEEP);
		up->apu_uid = ddi_strdup(uid, KM_SLEEP);
		up->apu_cid = cid;
		up->apu_nid = acpidev_uid_heads[cid].apuh_id++;
		*pp = up;
	}
	ASSERT(*pp != NULL);
	mutex_exit(&acpidev_uid_heads[cid].apuh_lock);

	/*
	 * Generate a special format unit address with three fields to
	 * guarantee uniqueness. Normal unit addresses for ACPI devices have
	 * either one or two fields.
	 */
	if (snprintf(buf, len, "%u,%u,0", (*pp)->apu_nid, cid) > len) {
		return (NULL);
	}

	return (buf);
}

static char *
acpidev_gen_unitaddr(char *uid, char *fmt, char *buf, size_t len)
{
	size_t i, cnt;
	uint_t id1, id2;

	ASSERT(len >= 64);
	if (fmt == NULL || strlen(fmt) == 0) {
		return (NULL);
	}

	/*
	 * Count '%' in format string to protect sscanf().
	 * Only support '%u' and '%x', and maximum 2 conversions.
	 */
	for (cnt = 0, i = 0; fmt[i] != 0 && cnt <= 2; i++) {
		if (fmt[i] != '%') {
			continue;
		} else if (fmt[i + 1] == 'u' || fmt[i + 1] == 'x') {
			/* Skip next character. */
			i++;
			cnt++;
		} else {
			/* Invalid conversion, stop walking. */
			cnt = SIZE_MAX;
		}
	}
	if (cnt != 1 && cnt != 2) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: invalid uid format string '%s'.", fmt);
		return (NULL);
	}

	/* Scan uid and generate unitaddr. */
	if (sscanf(uid, fmt, &id1, &id2) != cnt) {
		return (NULL);
	}
	/*
	 * Reverse the order of the two IDs to match the requirements of the
	 * hotplug driver.
	 */
	if (cnt == 2 && snprintf(buf, len, "%u,%u", id2, id1) >= len) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: generated unitaddr is too long.");
		return (NULL);
	} else if (cnt == 1 && snprintf(buf, len, "%u", id1) >= len) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: generated unitaddr is too long.");
		return (NULL);
	}

	return (buf);
}

char *
acpidev_generate_unitaddr(char *uid, char **fmts, size_t nfmt,
    char *buf, size_t len)
{
	size_t i;
	uint_t count = 0;
	ulong_t val;
	char **formats = NULL;
	char *rbuf = NULL;
	char *endp = NULL;

	ASSERT(len >= 64);

	/* Use _UID as unit address if it's a decimal integer. */
	if (ddi_strtoul(uid, &endp, 10, &val) == 0 &&
	    (endp == NULL || *endp == 0)) {
		if (snprintf(buf, len, "%s", uid) >= len) {
			return (NULL);
		} else {
			return (buf);
		}
	}

	/* First handle uid format strings from device property. */
	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS,
	    ACPIDEV_PROP_NAME_UID_FORMAT, &formats, &count) == DDI_SUCCESS) {
		/* Walk through format strings and try to generate unitaddr. */
		for (i = 0; i < count && rbuf == NULL; i++) {
			rbuf = acpidev_gen_unitaddr(uid, formats[i], buf, len);
		}
		ddi_prop_free(formats);
	}

	/* Then handle embedded uid format strings. */
	if (fmts != NULL) {
		for (i = 0; i < nfmt && rbuf == NULL; i++) {
			rbuf = acpidev_gen_unitaddr(uid, fmts[i], buf, len);
		}
	}

	return (rbuf);
}

/*
 * The Solaris device "unit-address" property is composed of a comma-delimited
 * list of hexadecimal values. According to the ACPI spec, the ACPI _UID method
 * could return an integer or a string. If it returns an integer, it is used
 * as the unit-address as is. If _UID returns a string, we try to extract some
 * meaningful integers to compose the unit-address property. If we fail to
 * extract any integers, a pseudo-sequential number will be generated for the
 * unit-address.
 */
ACPI_STATUS
acpidev_set_unitaddr(acpidev_walk_info_t *infop, char **fmts, size_t nfmt,
    char *unitaddr)
{
	char unit[64];

	ASSERT(infop != NULL);
	ASSERT(infop->awi_dip != NULL);
	ASSERT(infop->awi_info != NULL);
	if (infop == NULL || infop->awi_dip == NULL ||
	    infop->awi_info == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: invalid parameters in acpidev_set_unitaddr().");
		return (AE_BAD_PARAMETER);
	}

	if (infop->awi_info->Valid & ACPI_VALID_UID) {
		if (ndi_prop_update_string(DDI_DEV_T_NONE, infop->awi_dip,
		    ACPIDEV_PROP_NAME_ACPI_UID,
		    infop->awi_info->UniqueId.String) != NDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "!acpidev: failed to set UID property for %s.",
			    infop->awi_name);
			return (AE_ERROR);
		}
	}

	if (unitaddr == NULL && (infop->awi_info->Valid & ACPI_VALID_UID)) {
		/* Try to generate unit address from _UID. */
		if (fmts == NULL) {
			fmts = acpidev_uid_formats;
			nfmt = sizeof (acpidev_uid_formats) / sizeof (char *);
		}
		unitaddr = acpidev_generate_unitaddr(
		    infop->awi_info->UniqueId.String, fmts, nfmt,
		    unit, sizeof (unit));
		/* Generate pseudo sequential unit address. */
		if (unitaddr == NULL) {
			unitaddr = acpidev_generate_pseudo_unitaddr(
			    infop->awi_info->UniqueId.String,
			    infop->awi_class_curr->adc_class_id,
			    unit, sizeof (unit));
		}
		if (unitaddr == NULL) {
			cmn_err(CE_WARN, "!acpidev: failed to generate unit "
			    "address from %s.",
			    infop->awi_info->UniqueId.String);
			return (AE_ERROR);
		}
	}
	if (unitaddr == NULL) {
		/*
		 * Some ACPI objects may have no _UID method available, so we
		 * can't generate the "unit-address" property for them.
		 * On the other hand, it's legal to support such a device
		 * without a unit address, so return success here.
		 */
		return (AE_OK);
	}

	if (ndi_prop_update_string(DDI_DEV_T_NONE, infop->awi_dip,
	    ACPIDEV_PROP_NAME_UNIT_ADDR, unitaddr) != NDI_SUCCESS) {
		cmn_err(CE_WARN, "!acpidev: failed to set unitaddr for %s.",
		    infop->awi_name);
		return (AE_ERROR);
	}

	return (AE_OK);
}

ACPI_STATUS
acpidev_set_compatible(acpidev_walk_info_t *infop, char **compat, int acount)
{
	int count, i, j;
	char **compatible = NULL;
	ACPI_DEVICE_INFO *di;

	/*
	 * Generate compatible list for device based on:
	 *	* Device HID if available
	 *	* Device CIDs if available
	 *	* property array passed in
	 */
	ASSERT(infop != NULL);
	ASSERT(infop->awi_dip != NULL);
	ASSERT(infop->awi_info != NULL);
	ASSERT(compat != NULL || acount == 0);
	if (infop == NULL || infop->awi_dip == NULL ||
	    infop->awi_info == NULL || (compat == NULL && acount != 0)) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameters "
		    "in acpidev_set_compatible().");
		return (AE_BAD_PARAMETER);
	}

	/* Compute string count. */
	count = acount;
	di = infop->awi_info;
	if (di->Valid & ACPI_VALID_HID) {
		count++;
	}
	if (di->Valid & ACPI_VALID_CID) {
		count += di->CompatibleIdList.Count;
	}
	compatible = kmem_zalloc(sizeof (char *) * count, KM_SLEEP);

	/* Generate string array. */
	i = 0;
	if (di->Valid & ACPI_VALID_HID) {
		compatible[i++] = di->HardwareId.String;
	}
	if (di->Valid & ACPI_VALID_CID) {
		for (j = 0; j < di->CompatibleIdList.Count; j++) {
			compatible[i++] = di->CompatibleIdList.Ids[j].String;
		}
	}
	for (j = 0; j < acount; j++) {
		compatible[i++] = compat[j];
	}
	ASSERT(i == count);

	/* Set "compatible" property. */
	if (ndi_prop_update_string_array(DDI_DEV_T_NONE, infop->awi_dip,
	    OBP_COMPATIBLE, compatible, count) != NDI_SUCCESS) {
		cmn_err(CE_WARN, "!acpidev: failed to set compatible "
		    "property for %s in acpidev_set_compatible().",
		    infop->awi_name);
		kmem_free(compatible, count * sizeof (char *));
		return (AE_ERROR);
	}
	kmem_free(compatible, count * sizeof (char *));

	return (AE_OK);
}

/* Evaluate _OST method under object, which is used to support hotplug event. */
ACPI_STATUS
acpidev_eval_ost(ACPI_HANDLE hdl, uint32_t code, uint32_t status,
    char *bufp, size_t len)
{
	ACPI_STATUS rc;
	ACPI_OBJECT args[3];
	ACPI_OBJECT_LIST arglist;

	args[0].Type = ACPI_TYPE_INTEGER;
	args[0].Integer.Value = code;
	args[1].Type = ACPI_TYPE_INTEGER;
	args[1].Integer.Value = status;
	args[2].Type = ACPI_TYPE_BUFFER;
	args[2].Buffer.Pointer = (UINT8 *)bufp;
	args[2].Buffer.Length = (UINT32)len;
	if (bufp == NULL || len == 0) {
		arglist.Count = 2;
	} else {
		arglist.Count = 3;
	}
	arglist.Pointer = args;
	rc = AcpiEvaluateObject(hdl, ACPIDEV_METHOD_NAME_OST, &arglist, NULL);
	if (rc != AE_OK && rc != AE_NOT_FOUND) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to evaluate _OST method, code 0x%x.", rc);
	}

	return (rc);
}

ACPI_STATUS
acpidev_eval_ej0(ACPI_HANDLE hdl)
{
	ACPI_STATUS rc;
	ACPI_OBJECT args[1];
	ACPI_OBJECT_LIST arglist;

	/*
	 * Quotation from ACPI spec 4.0 section 6.3.3.
	 * Arg0 An Integer containing a device ejection control
	 * 	0  Cancel a mark for ejection request (EJ0 will never be called
	 *	   with this value)
	 * 	1  Hot eject or mark for ejection
	 */
	args[0].Type = ACPI_TYPE_INTEGER;
	args[0].Integer.Value = 1;
	arglist.Count = 1;
	arglist.Pointer = args;
	rc = AcpiEvaluateObject(hdl, ACPIDEV_METHOD_NAME_EJ0, &arglist, NULL);
	if (rc != AE_OK) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to evaluate _EJ0 method, code 0x%x.", rc);
	}

	return (rc);
}

ACPI_STATUS
acpidev_eval_pxm(ACPI_HANDLE hdl, uint32_t *idp)
{
	int pxmid;

	ASSERT(idp != NULL);

	/*
	 * Try to evaluate ACPI _PXM method to get proximity doamin id.
	 * Quotation from ACPI4.0:
	 * If the Local APIC ID / Local SAPIC ID / Local x2APIC ID of a
	 * dynamically added processor is not present in the System Resource
	 * Affinity Table (SRAT), a _PXM object must exist for the processor's
	 * device or one of its ancestors in the ACPI Namespace.
	 */
	while (hdl != NULL) {
		if (ACPI_SUCCESS(acpica_eval_int(hdl,
		    ACPIDEV_METHOD_NAME_PXM, &pxmid))) {
			*idp = (uint32_t)pxmid;
			return (AE_OK);
		}
		if (ACPI_FAILURE(AcpiGetParent(hdl, &hdl))) {
			break;
		}
	}

	return (AE_NOT_FOUND);
}
