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

#include <sys/cpu_acpi.h>

/*
 * List of the processor ACPI object types that are being used.
 */
typedef enum cpu_acpi_obj {
	PDC_OBJ = 0,
	PCT_OBJ,
	PSS_OBJ,
	PSD_OBJ,
	PPC_OBJ,
	PTC_OBJ,
	TSS_OBJ,
	TSD_OBJ,
	TPC_OBJ
} cpu_acpi_obj_t;

/*
 * Container to store object name.
 * Other attributes can be added in the future as necessary.
 */
typedef struct cpu_acpi_obj_attr {
	char *name;
} cpu_acpi_obj_attr_t;

/*
 * List of object attributes.
 * NOTE: Please keep the ordering of the list as same as cpu_acpi_obj_t.
 */
static cpu_acpi_obj_attr_t cpu_acpi_obj_attrs[] = {
	{"_PDC"},
	{"_PCT"},
	{"_PSS"},
	{"_PSD"},
	{"_PPC"},
	{"_PTC"},
	{"_TSS"},
	{"_TSD"},
	{"_TPC"}
};

/*
 * Cache the ACPI CPU control data objects.
 */
static int
cpu_acpi_cache_ctrl_regs(cpu_acpi_handle_t handle, cpu_acpi_obj_t objtype,
    cpu_acpi_ctrl_regs_t *regs)
{
	ACPI_BUFFER abuf;
	ACPI_OBJECT *obj;
	AML_RESOURCE_GENERIC_REGISTER *greg;
	int ret = -1;
	int i;

	/*
	 * Fetch the control registers (if present) for the CPU node.
	 * Since they are optional, non-existence is not a failure
	 * (we just consider it a fixed hardware case).
	 */
	abuf.Length = ACPI_ALLOCATE_BUFFER;
	abuf.Pointer = NULL;
	if (ACPI_FAILURE(AcpiEvaluateObjectTyped(handle->cs_handle,
	    cpu_acpi_obj_attrs[objtype].name, NULL, &abuf,
	    ACPI_TYPE_PACKAGE))) {
		regs[0].cr_addrspace_id = ACPI_ADR_SPACE_FIXED_HARDWARE;
		regs[1].cr_addrspace_id = ACPI_ADR_SPACE_FIXED_HARDWARE;
		return (1);
	}

	obj = abuf.Pointer;
	if (obj->Package.Count != 2) {
		cmn_err(CE_NOTE, "!cpu_acpi: %s package bad count %d.",
		    cpu_acpi_obj_attrs[objtype].name, obj->Package.Count);
		goto out;
	}

	/*
	 * Does the package look coherent?
	 */
	for (i = 0; i < obj->Package.Count; i++) {
		if (obj->Package.Elements[i].Type != ACPI_TYPE_BUFFER) {
			cmn_err(CE_NOTE, "!cpu_acpi: "
			    "Unexpected data in %s package.",
			    cpu_acpi_obj_attrs[objtype].name);
			goto out;
		}

		greg = (AML_RESOURCE_GENERIC_REGISTER *)
		    obj->Package.Elements[i].Buffer.Pointer;
		if (greg->DescriptorType !=
		    ACPI_RESOURCE_NAME_GENERIC_REGISTER) {
			cmn_err(CE_NOTE, "!cpu_acpi: "
			    "%s package has format error.",
			    cpu_acpi_obj_attrs[objtype].name);
			goto out;
		}
		if (greg->ResourceLength !=
		    ACPI_AML_SIZE_LARGE(AML_RESOURCE_GENERIC_REGISTER)) {
			cmn_err(CE_NOTE, "!cpu_acpi: "
			    "%s package not right size.",
			    cpu_acpi_obj_attrs[objtype].name);
			goto out;
		}
		if (greg->AddressSpaceId != ACPI_ADR_SPACE_FIXED_HARDWARE &&
		    greg->AddressSpaceId != ACPI_ADR_SPACE_SYSTEM_IO) {
			cmn_err(CE_NOTE, "!cpu_apci: %s contains unsupported "
			    "address space type %x",
			    cpu_acpi_obj_attrs[objtype].name,
			    greg->AddressSpaceId);
			goto out;
		}
	}

	/*
	 * Looks good!
	 */
	for (i = 0; i < obj->Package.Count; i++) {
		greg = (AML_RESOURCE_GENERIC_REGISTER *)
		    obj->Package.Elements[i].Buffer.Pointer;
		regs[i].cr_addrspace_id = greg->AddressSpaceId;
		regs[i].cr_width = greg->BitWidth;
		regs[i].cr_offset = greg->BitOffset;
		regs[i].cr_asize = greg->AccessSize;
		regs[i].cr_address = greg->Address;
	}
	ret = 0;
out:
	AcpiOsFree(abuf.Pointer);
	return (ret);
}

/*
 * Cache the ACPI _PCT data. The _PCT data defines the interface to use
 * when making power level transitions (i.e., system IO ports, fixed
 * hardware port, etc).
 */
static int
cpu_acpi_cache_pct(cpu_acpi_handle_t handle)
{
	cpu_acpi_pct_t *pct;
	int ret;

	CPU_ACPI_OBJ_IS_NOT_CACHED(handle, CPU_ACPI_PCT_CACHED);
	pct = &CPU_ACPI_PCT(handle)[0];
	if ((ret = cpu_acpi_cache_ctrl_regs(handle, PCT_OBJ, pct)) == 0)
		CPU_ACPI_OBJ_IS_CACHED(handle, CPU_ACPI_PCT_CACHED);
	return (ret);
}

/*
 * Cache the ACPI _PTC data. The _PTC data defines the interface to use
 * when making T-state transitions (i.e., system IO ports, fixed
 * hardware port, etc).
 */
static int
cpu_acpi_cache_ptc(cpu_acpi_handle_t handle)
{
	cpu_acpi_ptc_t *ptc;
	int ret;

	CPU_ACPI_OBJ_IS_NOT_CACHED(handle, CPU_ACPI_PTC_CACHED);
	ptc = &CPU_ACPI_PTC(handle)[0];
	if ((ret = cpu_acpi_cache_ctrl_regs(handle, PTC_OBJ, ptc)) == 0)
		CPU_ACPI_OBJ_IS_CACHED(handle, CPU_ACPI_PTC_CACHED);
	return (ret);
}

/*
 * Cache the ACPI CPU state dependency data objects.
 */
static int
cpu_acpi_cache_state_dependencies(cpu_acpi_handle_t handle,
    cpu_acpi_obj_t objtype, cpu_acpi_state_dependency_t *sd)
{
	ACPI_BUFFER abuf;
	ACPI_OBJECT *pkg, *elements;
	int ret = -1;

	/*
	 * Fetch the dependencies (if present) for the CPU node.
	 * Since they are optional, non-existence is not a failure
	 * (it's up to the caller to determine how to handle non-existence).
	 */
	abuf.Length = ACPI_ALLOCATE_BUFFER;
	abuf.Pointer = NULL;
	if (ACPI_FAILURE(AcpiEvaluateObjectTyped(handle->cs_handle,
	    cpu_acpi_obj_attrs[objtype].name, NULL, &abuf,
	    ACPI_TYPE_PACKAGE))) {
		return (1);
	}

	pkg = abuf.Pointer;
	if (pkg->Package.Count != 1) {
		cmn_err(CE_NOTE, "!cpu_acpi: %s unsupported package "
		    "count %d.", cpu_acpi_obj_attrs[objtype].name,
		    pkg->Package.Count);
		goto out;
	}

	if (pkg->Package.Elements[0].Type != ACPI_TYPE_PACKAGE ||
	    pkg->Package.Elements[0].Package.Count != 5) {
		cmn_err(CE_NOTE, "!cpu_acpi: Unexpected data in %s package.",
		    cpu_acpi_obj_attrs[objtype].name);
		goto out;
	}
	elements = pkg->Package.Elements[0].Package.Elements;
	if (elements[0].Integer.Value != 5 || elements[1].Integer.Value != 0) {
		cmn_err(CE_NOTE, "!cpu_acpi: Unexpected %s revision.",
		    cpu_acpi_obj_attrs[objtype].name);
		goto out;
	}

	sd->sd_entries = elements[0].Integer.Value;
	sd->sd_revision = elements[1].Integer.Value;
	sd->sd_domain = elements[2].Integer.Value;
	sd->sd_type = elements[3].Integer.Value;
	sd->sd_num = elements[4].Integer.Value;

	ret = 0;
out:
	AcpiOsFree(abuf.Pointer);
	return (ret);
}

/*
 * Cache the ACPI _PSD data. The _PSD data defines P-state CPU dependencies
 * (think CPU domains).
 */
static int
cpu_acpi_cache_psd(cpu_acpi_handle_t handle)
{
	cpu_acpi_psd_t *psd;
	int ret;

	CPU_ACPI_OBJ_IS_NOT_CACHED(handle, CPU_ACPI_PSD_CACHED);
	psd = &CPU_ACPI_PSD(handle);
	ret = cpu_acpi_cache_state_dependencies(handle, PSD_OBJ, psd);
	if (ret == 0)
		CPU_ACPI_OBJ_IS_CACHED(handle, CPU_ACPI_PSD_CACHED);
	return (ret);

}

/*
 * Cache the ACPI _TSD data. The _TSD data defines T-state CPU dependencies
 * (think CPU domains).
 */
static int
cpu_acpi_cache_tsd(cpu_acpi_handle_t handle)
{
	cpu_acpi_tsd_t *tsd;
	int ret;

	CPU_ACPI_OBJ_IS_NOT_CACHED(handle, CPU_ACPI_TSD_CACHED);
	tsd = &CPU_ACPI_TSD(handle);
	ret = cpu_acpi_cache_state_dependencies(handle, TSD_OBJ, tsd);
	if (ret == 0)
		CPU_ACPI_OBJ_IS_CACHED(handle, CPU_ACPI_TSD_CACHED);
	return (ret);

}

static void
cpu_acpi_cache_pstate(cpu_acpi_handle_t handle, ACPI_OBJECT *obj, int cnt)
{
	cpu_acpi_pstate_t *pstate;
	ACPI_OBJECT *q, *l;
	int i, j;

	CPU_ACPI_PSTATES_COUNT(handle) = cnt;
	CPU_ACPI_PSTATES(handle) = kmem_zalloc(CPU_ACPI_PSTATES_SIZE(cnt),
	    KM_SLEEP);
	pstate = (cpu_acpi_pstate_t *)CPU_ACPI_PSTATES(handle);
	for (i = 0, l = NULL; i < obj->Package.Count && cnt > 0; i++, l = q) {
		uint32_t *up;

		q = obj->Package.Elements[i].Package.Elements;

		/*
		 * Skip duplicate entries.
		 */
		if (l != NULL && l[0].Integer.Value == q[0].Integer.Value)
			continue;

		up = (uint32_t *)pstate;
		for (j = 0; j < CPU_ACPI_PSS_CNT; j++)
			up[j] = q[j].Integer.Value;
		pstate++;
		cnt--;
	}
}

static void
cpu_acpi_cache_tstate(cpu_acpi_handle_t handle, ACPI_OBJECT *obj, int cnt)
{
	cpu_acpi_tstate_t *tstate;
	ACPI_OBJECT *q, *l;
	int i, j;

	CPU_ACPI_TSTATES_COUNT(handle) = cnt;
	CPU_ACPI_TSTATES(handle) = kmem_zalloc(CPU_ACPI_TSTATES_SIZE(cnt),
	    KM_SLEEP);
	tstate = (cpu_acpi_tstate_t *)CPU_ACPI_TSTATES(handle);
	for (i = 0, l = NULL; i < obj->Package.Count && cnt > 0; i++, l = q) {
		uint32_t *up;

		q = obj->Package.Elements[i].Package.Elements;

		/*
		 * Skip duplicate entries.
		 */
		if (l != NULL && l[0].Integer.Value == q[0].Integer.Value)
			continue;

		up = (uint32_t *)tstate;
		for (j = 0; j < CPU_ACPI_TSS_CNT; j++)
			up[j] = q[j].Integer.Value;
		tstate++;
		cnt--;
	}
}

/*
 * Cache the _PSS or _TSS data.
 */
static int
cpu_acpi_cache_supported_states(cpu_acpi_handle_t handle,
    cpu_acpi_obj_t objtype, int fcnt)
{
	ACPI_BUFFER abuf;
	ACPI_OBJECT *obj, *q, *l;
	boolean_t eot = B_FALSE;
	int ret = -1;
	int cnt;
	int i, j;

	/*
	 * Fetch the data (if present) for the CPU node.
	 */
	abuf.Length = ACPI_ALLOCATE_BUFFER;
	abuf.Pointer = NULL;
	if (ACPI_FAILURE(AcpiEvaluateObjectTyped(handle->cs_handle,
	    cpu_acpi_obj_attrs[objtype].name, NULL, &abuf,
	    ACPI_TYPE_PACKAGE))) {
		cmn_err(CE_NOTE, "!cpu_acpi: %s package not found.",
		    cpu_acpi_obj_attrs[objtype].name);
		return (1);
	}
	obj = abuf.Pointer;
	if (obj->Package.Count < 2) {
		cmn_err(CE_NOTE, "!cpu_acpi: %s package bad count %d.",
		    cpu_acpi_obj_attrs[objtype].name, obj->Package.Count);
		goto out;
	}

	/*
	 * Does the package look coherent?
	 */
	cnt = 0;
	for (i = 0, l = NULL; i < obj->Package.Count; i++, l = q) {
		if (obj->Package.Elements[i].Type != ACPI_TYPE_PACKAGE ||
		    obj->Package.Elements[i].Package.Count != fcnt) {
			cmn_err(CE_NOTE, "!cpu_acpi: "
			    "Unexpected data in %s package.",
			    cpu_acpi_obj_attrs[objtype].name);
			goto out;
		}

		q = obj->Package.Elements[i].Package.Elements;
		for (j = 0; j < fcnt; j++) {
			if (q[j].Type != ACPI_TYPE_INTEGER) {
				cmn_err(CE_NOTE, "!cpu_acpi: "
				    "%s element invalid (type)",
				    cpu_acpi_obj_attrs[objtype].name);
				goto out;
			}
		}

		/*
		 * Ignore duplicate entries.
		 */
		if (l != NULL && l[0].Integer.Value == q[0].Integer.Value)
			continue;

		/*
		 * Some supported state tables are larger than required
		 * and unused elements are filled with patterns
		 * of 0xff.  Simply check here for frequency = 0xffff
		 * and stop counting if found.
		 */
		if (q[0].Integer.Value == 0xffff) {
			eot = B_TRUE;
			continue;
		}

		/*
		 * We should never find a valid entry after we've hit
		 * an the end-of-table entry.
		 */
		if (eot) {
			cmn_err(CE_NOTE, "!cpu_acpi: "
			    "Unexpected data in %s package after eot.",
			    cpu_acpi_obj_attrs[objtype].name);
			goto out;
		}

		/*
		 * states must be defined in order from highest to lowest.
		 */
		if (l != NULL && l[0].Integer.Value < q[0].Integer.Value) {
			cmn_err(CE_NOTE, "!cpu_acpi: "
			    "%s package state definitions out of order.",
			    cpu_acpi_obj_attrs[objtype].name);
			goto out;
		}

		/*
		 * This entry passes.
		 */
		cnt++;
	}
	if (cnt == 0)
		goto out;

	/*
	 * Yes, fill in the structure.
	 */
	ASSERT(objtype == PSS_OBJ || objtype == TSS_OBJ);
	(objtype == PSS_OBJ) ? cpu_acpi_cache_pstate(handle, obj, cnt) :
	    cpu_acpi_cache_tstate(handle, obj, cnt);

	ret = 0;
out:
	AcpiOsFree(abuf.Pointer);
	return (ret);
}

/*
 * Cache the _PSS data. The _PSS data defines the different power levels
 * supported by the CPU and the attributes associated with each power level
 * (i.e., frequency, voltage, etc.). The power levels are number from
 * highest to lowest. That is, the highest power level is _PSS entry 0
 * and the lowest power level is the last _PSS entry.
 */
static int
cpu_acpi_cache_pstates(cpu_acpi_handle_t handle)
{
	int ret;

	CPU_ACPI_OBJ_IS_NOT_CACHED(handle, CPU_ACPI_PSS_CACHED);
	ret = cpu_acpi_cache_supported_states(handle, PSS_OBJ,
	    CPU_ACPI_PSS_CNT);
	if (ret == 0)
		CPU_ACPI_OBJ_IS_CACHED(handle, CPU_ACPI_PSS_CACHED);
	return (ret);
}

/*
 * Cache the _TSS data. The _TSS data defines the different freq throttle
 * levels supported by the CPU and the attributes associated with each
 * throttle level (i.e., frequency throttle percentage, voltage, etc.).
 * The throttle levels are number from highest to lowest.
 */
static int
cpu_acpi_cache_tstates(cpu_acpi_handle_t handle)
{
	int ret;

	CPU_ACPI_OBJ_IS_NOT_CACHED(handle, CPU_ACPI_TSS_CACHED);
	ret = cpu_acpi_cache_supported_states(handle, TSS_OBJ,
	    CPU_ACPI_TSS_CNT);
	if (ret == 0)
		CPU_ACPI_OBJ_IS_CACHED(handle, CPU_ACPI_TSS_CACHED);
	return (ret);
}

/*
 * Cache the ACPI CPU present capabilities data objects.
 */
static int
cpu_acpi_cache_present_capabilities(cpu_acpi_handle_t handle,
    cpu_acpi_obj_t objtype, cpu_acpi_present_capabilities_t *pc)

{
	ACPI_BUFFER abuf;
	ACPI_OBJECT *obj;

	/*
	 * Fetch the present capabilites object (if present) for the CPU node.
	 * Since they are optional, non-existence is not a failure.
	 */
	abuf.Length = ACPI_ALLOCATE_BUFFER;
	abuf.Pointer = NULL;
	if (ACPI_FAILURE(AcpiEvaluateObject(handle->cs_handle,
	    cpu_acpi_obj_attrs[objtype].name, NULL, &abuf))) {
		*pc = 0;
		return (1);
	}

	obj = (ACPI_OBJECT *)abuf.Pointer;
	*pc = obj->Integer.Value;
	AcpiOsFree(abuf.Pointer);
	return (0);
}

/*
 * Cache the _PPC data. The _PPC simply contains an integer value which
 * represents the highest power level that a CPU should transition to.
 * That is, it's an index into the array of _PSS entries and will be
 * greater than or equal to zero.
 */
void
cpu_acpi_cache_ppc(cpu_acpi_handle_t handle)
{
	cpu_acpi_ppc_t *ppc;
	int ret;

	CPU_ACPI_OBJ_IS_NOT_CACHED(handle, CPU_ACPI_PPC_CACHED);
	ppc = &CPU_ACPI_PPC(handle);
	ret = cpu_acpi_cache_present_capabilities(handle, PPC_OBJ, ppc);
	if (ret == 0)
		CPU_ACPI_OBJ_IS_CACHED(handle, CPU_ACPI_PPC_CACHED);
}

/*
 * Cache the _TPC data. The _TPC simply contains an integer value which
 * represents the throttle level that a CPU should transition to.
 * That is, it's an index into the array of _TSS entries and will be
 * greater than or equal to zero.
 */
void
cpu_acpi_cache_tpc(cpu_acpi_handle_t handle)
{
	cpu_acpi_tpc_t *tpc;
	int ret;

	CPU_ACPI_OBJ_IS_NOT_CACHED(handle, CPU_ACPI_TPC_CACHED);
	tpc = &CPU_ACPI_TPC(handle);
	ret = cpu_acpi_cache_present_capabilities(handle, TPC_OBJ, tpc);
	if (ret == 0)
		CPU_ACPI_OBJ_IS_CACHED(handle, CPU_ACPI_TPC_CACHED);
}

/*
 * Cache the _PCT, _PSS, _PSD and _PPC data.
 */
int
cpu_acpi_cache_pstate_data(cpu_acpi_handle_t handle)
{
	if (cpu_acpi_cache_pct(handle) < 0) {
		cmn_err(CE_WARN, "!cpu_acpi: error parsing _PCT for "
		    "CPU instance %d", ddi_get_instance(handle->cs_dip));
		return (-1);
	}

	if (cpu_acpi_cache_pstates(handle) != 0) {
		cmn_err(CE_WARN, "!cpu_acpi: error parsing _PSS for "
		    "CPU instance %d", ddi_get_instance(handle->cs_dip));
		return (-1);
	}

	if (cpu_acpi_cache_psd(handle) < 0) {
		cmn_err(CE_WARN, "!cpu_acpi: error parsing _PSD for "
		    "CPU instance %d", ddi_get_instance(handle->cs_dip));
		return (-1);
	}

	cpu_acpi_cache_ppc(handle);

	return (0);
}

void
cpu_acpi_free_pstate_data(cpu_acpi_handle_t handle)
{
	if (handle != NULL) {
		if (CPU_ACPI_PSTATES(handle)) {
			kmem_free(CPU_ACPI_PSTATES(handle),
			    CPU_ACPI_PSTATES_SIZE(
			    CPU_ACPI_PSTATES_COUNT(handle)));
			CPU_ACPI_PSTATES(handle) = NULL;
		}
	}
}

/*
 * Cache the _PTC, _TSS, _TSD and _TPC data.
 */
int
cpu_acpi_cache_tstate_data(cpu_acpi_handle_t handle)
{
	if (cpu_acpi_cache_ptc(handle) < 0) {
		cmn_err(CE_WARN, "!cpu_acpi: error parsing _PTC for "
		    "CPU instance %d", ddi_get_instance(handle->cs_dip));
		return (-1);
	}

	if (cpu_acpi_cache_tstates(handle) != 0) {
		cmn_err(CE_WARN, "!cpu_acpi: error parsing _TSS for "
		    "CPU instance %d", ddi_get_instance(handle->cs_dip));
		return (-1);
	}

	if (cpu_acpi_cache_tsd(handle) < 0) {
		cmn_err(CE_WARN, "!cpu_acpi: error parsing _TSD for "
		    "CPU instance %d", ddi_get_instance(handle->cs_dip));
		return (-1);
	}

	cpu_acpi_cache_tpc(handle);

	return (0);
}

void
cpu_acpi_free_tstate_data(cpu_acpi_handle_t handle)
{
	if (handle != NULL) {
		if (CPU_ACPI_TSTATES(handle)) {
			kmem_free(CPU_ACPI_TSTATES(handle),
			    CPU_ACPI_TSTATES_SIZE(
			    CPU_ACPI_TSTATES_COUNT(handle)));
			CPU_ACPI_TSTATES(handle) = NULL;
		}
	}
}

/*
 * Register a handler for processor change notifications.
 */
void
cpu_acpi_install_notify_handler(cpu_acpi_handle_t handle,
    ACPI_NOTIFY_HANDLER handler, dev_info_t *dip)
{
	char path[MAXNAMELEN];
	if (ACPI_FAILURE(AcpiInstallNotifyHandler(handle->cs_handle,
	    ACPI_DEVICE_NOTIFY, handler, dip)))
		cmn_err(CE_NOTE, "!cpu_acpi: Unable to register "
		    "notify handler for %s", ddi_pathname(dip, path));
}

/*
 * Write _PDC.
 */
int
cpu_acpi_write_pdc(cpu_acpi_handle_t handle, uint32_t revision, uint32_t count,
    uint32_t *capabilities)
{
	ACPI_OBJECT obj;
	ACPI_OBJECT_LIST list = { 1, &obj};
	uint32_t *buffer;
	uint32_t *bufptr;
	uint32_t bufsize;
	int i;

	bufsize = (count + 2) * sizeof (uint32_t);
	buffer = kmem_zalloc(bufsize, KM_SLEEP);
	buffer[0] = revision;
	buffer[1] = count;
	bufptr = &buffer[2];
	for (i = 0; i < count; i++)
		*bufptr++ = *capabilities++;

	obj.Type = ACPI_TYPE_BUFFER;
	obj.Buffer.Length = bufsize;
	obj.Buffer.Pointer = (void *)buffer;

	/*
	 * _PDC is optional, so don't log failure.
	 */
	if (ACPI_FAILURE(AcpiEvaluateObject(handle->cs_handle, "_PDC",
	    &list, NULL))) {
		kmem_free(buffer, bufsize);
		return (-1);
	}

	kmem_free(buffer, bufsize);
	return (0);
}

/*
 * Write to system IO port.
 */
int
cpu_acpi_write_port(ACPI_IO_ADDRESS address, uint32_t value, uint32_t width)
{
	if (ACPI_FAILURE(AcpiOsWritePort(address, value, width))) {
		cmn_err(CE_NOTE, "cpu_acpi: error writing system IO port "
		    "%lx.", (long)address);
		return (-1);
	}
	return (0);
}

/*
 * Read from a system IO port.
 */
int
cpu_acpi_read_port(ACPI_IO_ADDRESS address, uint32_t *value, uint32_t width)
{
	if (ACPI_FAILURE(AcpiOsReadPort(address, value, width))) {
		cmn_err(CE_NOTE, "cpu_acpi: error reading system IO port "
		    "%lx.", (long)address);
		return (-1);
	}
	return (0);
}

/*
 * Return supported frequencies.
 */
uint_t
cpu_acpi_get_speeds(cpu_acpi_handle_t handle, int **speeds)
{
	cpu_acpi_pstate_t *pstate;
	int *hspeeds;
	uint_t nspeeds;
	int i;

	nspeeds = CPU_ACPI_PSTATES_COUNT(handle);
	pstate = (cpu_acpi_pstate_t *)CPU_ACPI_PSTATES(handle);
	hspeeds = kmem_zalloc(nspeeds * sizeof (int), KM_SLEEP);
	for (i = 0; i < nspeeds; i++) {
		hspeeds[i] = CPU_ACPI_FREQ(pstate);
		pstate++;
	}
	*speeds = hspeeds;
	return (nspeeds);
}

/*
 * Free resources allocated by cpu_acpi_get_speeds().
 */
void
cpu_acpi_free_speeds(int *speeds, uint_t nspeeds)
{
	kmem_free(speeds, nspeeds * sizeof (int));
}

/*
 * Map the dip to an ACPI handle for the device.
 */
cpu_acpi_handle_t
cpu_acpi_init(dev_info_t *dip)
{
	cpu_acpi_handle_t handle;

	handle = kmem_zalloc(sizeof (cpu_acpi_state_t), KM_SLEEP);

	if (ACPI_FAILURE(acpica_get_handle(dip, &handle->cs_handle))) {
		kmem_free(handle, sizeof (cpu_acpi_state_t));
		return (NULL);
	}
	handle->cs_dip = dip;
	return (handle);
}

/*
 * Free any resources.
 */
void
cpu_acpi_fini(cpu_acpi_handle_t handle)
{
	if (handle)
		kmem_free(handle, sizeof (cpu_acpi_state_t));
}
