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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/cpu_acpi.h>
#include <sys/cpu_idle.h>
#include <sys/dtrace.h>
#include <sys/sdt.h>

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
	TPC_OBJ,
	CST_OBJ,
	CSD_OBJ,
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
	{"_TPC"},
	{"_CST"},
	{"_CSD"}
};

/*
 * Cache the ACPI CPU control data objects.
 */
static int
cpu_acpi_cache_ctrl_regs(cpu_acpi_handle_t handle, cpu_acpi_obj_t objtype,
    cpu_acpi_ctrl_regs_t *regs)
{
	ACPI_STATUS astatus;
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
	astatus = AcpiEvaluateObjectTyped(handle->cs_handle,
	    cpu_acpi_obj_attrs[objtype].name, NULL, &abuf, ACPI_TYPE_PACKAGE);
	if (ACPI_FAILURE(astatus)) {
		if (astatus == AE_NOT_FOUND) {
			DTRACE_PROBE3(cpu_acpi__eval__err, int, handle->cs_id,
			    int, objtype, int, astatus);
			regs[0].cr_addrspace_id = ACPI_ADR_SPACE_FIXED_HARDWARE;
			regs[1].cr_addrspace_id = ACPI_ADR_SPACE_FIXED_HARDWARE;
			return (1);
		}
		cmn_err(CE_NOTE, "!cpu_acpi: error %d evaluating %s package "
		    "for CPU %d.", astatus, cpu_acpi_obj_attrs[objtype].name,
		    handle->cs_id);
		goto out;
	}

	obj = abuf.Pointer;
	if (obj->Package.Count != 2) {
		cmn_err(CE_NOTE, "!cpu_acpi: %s package bad count %d for "
		    "CPU %d.", cpu_acpi_obj_attrs[objtype].name,
		    obj->Package.Count, handle->cs_id);
		goto out;
	}

	/*
	 * Does the package look coherent?
	 */
	for (i = 0; i < obj->Package.Count; i++) {
		if (obj->Package.Elements[i].Type != ACPI_TYPE_BUFFER) {
			cmn_err(CE_NOTE, "!cpu_acpi: Unexpected data in "
			    "%s package for CPU %d.",
			    cpu_acpi_obj_attrs[objtype].name,
			    handle->cs_id);
			goto out;
		}

		greg = (AML_RESOURCE_GENERIC_REGISTER *)
		    obj->Package.Elements[i].Buffer.Pointer;
		if (greg->DescriptorType !=
		    ACPI_RESOURCE_NAME_GENERIC_REGISTER) {
			cmn_err(CE_NOTE, "!cpu_acpi: %s package has format "
			    "error for CPU %d.",
			    cpu_acpi_obj_attrs[objtype].name,
			    handle->cs_id);
			goto out;
		}
		if (greg->ResourceLength !=
		    ACPI_AML_SIZE_LARGE(AML_RESOURCE_GENERIC_REGISTER)) {
			cmn_err(CE_NOTE, "!cpu_acpi: %s package not right "
			    "size for CPU %d.",
			    cpu_acpi_obj_attrs[objtype].name,
			    handle->cs_id);
			goto out;
		}
		if (greg->AddressSpaceId != ACPI_ADR_SPACE_FIXED_HARDWARE &&
		    greg->AddressSpaceId != ACPI_ADR_SPACE_SYSTEM_IO) {
			cmn_err(CE_NOTE, "!cpu_apci: %s contains unsupported "
			    "address space type %x for CPU %d.",
			    cpu_acpi_obj_attrs[objtype].name,
			    greg->AddressSpaceId,
			    handle->cs_id);
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
	if (abuf.Pointer != NULL)
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
	ACPI_STATUS astatus;
	ACPI_BUFFER abuf;
	ACPI_OBJECT *pkg, *elements;
	int number;
	int ret = -1;

	if (objtype == CSD_OBJ) {
		number = 6;
	} else {
		number = 5;
	}
	/*
	 * Fetch the dependencies (if present) for the CPU node.
	 * Since they are optional, non-existence is not a failure
	 * (it's up to the caller to determine how to handle non-existence).
	 */
	abuf.Length = ACPI_ALLOCATE_BUFFER;
	abuf.Pointer = NULL;
	astatus = AcpiEvaluateObjectTyped(handle->cs_handle,
	    cpu_acpi_obj_attrs[objtype].name, NULL, &abuf, ACPI_TYPE_PACKAGE);
	if (ACPI_FAILURE(astatus)) {
		if (astatus == AE_NOT_FOUND) {
			DTRACE_PROBE3(cpu_acpi__eval__err, int, handle->cs_id,
			    int, objtype, int, astatus);
			return (1);
		}
		cmn_err(CE_NOTE, "!cpu_acpi: error %d evaluating %s package "
		    "for CPU %d.", astatus, cpu_acpi_obj_attrs[objtype].name,
		    handle->cs_id);
		goto out;
	}

	pkg = abuf.Pointer;

	if (((objtype != CSD_OBJ) && (pkg->Package.Count != 1)) ||
	    ((objtype == CSD_OBJ) && (pkg->Package.Count != 1) &&
	    (pkg->Package.Count != 2))) {
		cmn_err(CE_NOTE, "!cpu_acpi: %s unsupported package count %d "
		    "for CPU %d.", cpu_acpi_obj_attrs[objtype].name,
		    pkg->Package.Count, handle->cs_id);
		goto out;
	}

	/*
	 * For C-state domain, we assume C2 and C3 have the same
	 * domain information
	 */
	if (pkg->Package.Elements[0].Type != ACPI_TYPE_PACKAGE ||
	    pkg->Package.Elements[0].Package.Count != number) {
		cmn_err(CE_NOTE, "!cpu_acpi: Unexpected data in %s package "
		    "for CPU %d.", cpu_acpi_obj_attrs[objtype].name,
		    handle->cs_id);
		goto out;
	}
	elements = pkg->Package.Elements[0].Package.Elements;
	if (elements[0].Integer.Value != number ||
	    elements[1].Integer.Value != 0) {
		cmn_err(CE_NOTE, "!cpu_acpi: Unexpected %s revision for "
		    "CPU %d.", cpu_acpi_obj_attrs[objtype].name,
		    handle->cs_id);
		goto out;
	}

	sd->sd_entries = elements[0].Integer.Value;
	sd->sd_revision = elements[1].Integer.Value;
	sd->sd_domain = elements[2].Integer.Value;
	sd->sd_type = elements[3].Integer.Value;
	sd->sd_num = elements[4].Integer.Value;
	if (objtype == CSD_OBJ) {
		sd->sd_index = elements[5].Integer.Value;
	}

	ret = 0;
out:
	if (abuf.Pointer != NULL)
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

/*
 * Cache the ACPI _CSD data. The _CSD data defines C-state CPU dependencies
 * (think CPU domains).
 */
static int
cpu_acpi_cache_csd(cpu_acpi_handle_t handle)
{
	cpu_acpi_csd_t *csd;
	int ret;

	CPU_ACPI_OBJ_IS_NOT_CACHED(handle, CPU_ACPI_CSD_CACHED);
	csd = &CPU_ACPI_CSD(handle);
	ret = cpu_acpi_cache_state_dependencies(handle, CSD_OBJ, csd);
	if (ret == 0)
		CPU_ACPI_OBJ_IS_CACHED(handle, CPU_ACPI_CSD_CACHED);
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
	ACPI_STATUS astatus;
	ACPI_BUFFER abuf;
	ACPI_OBJECT *obj, *q, *l;
	boolean_t eot = B_FALSE;
	int ret = -1;
	int cnt;
	int i, j;

	/*
	 * Fetch the state data (if present) for the CPU node.
	 */
	abuf.Length = ACPI_ALLOCATE_BUFFER;
	abuf.Pointer = NULL;
	astatus = AcpiEvaluateObjectTyped(handle->cs_handle,
	    cpu_acpi_obj_attrs[objtype].name, NULL, &abuf,
	    ACPI_TYPE_PACKAGE);
	if (ACPI_FAILURE(astatus)) {
		if (astatus == AE_NOT_FOUND) {
			DTRACE_PROBE3(cpu_acpi__eval__err, int, handle->cs_id,
			    int, objtype, int, astatus);
			return (1);
		}
		cmn_err(CE_NOTE, "!cpu_acpi: error %d evaluating %s package "
		    "for CPU %d.", astatus, cpu_acpi_obj_attrs[objtype].name,
		    handle->cs_id);
		goto out;
	}
	obj = abuf.Pointer;
	if (obj->Package.Count < 2) {
		cmn_err(CE_NOTE, "!cpu_acpi: %s package bad count %d for "
		    "CPU %d.", cpu_acpi_obj_attrs[objtype].name,
		    obj->Package.Count, handle->cs_id);
		goto out;
	}

	/*
	 * Does the package look coherent?
	 */
	cnt = 0;
	for (i = 0, l = NULL; i < obj->Package.Count; i++, l = q) {
		if (obj->Package.Elements[i].Type != ACPI_TYPE_PACKAGE ||
		    obj->Package.Elements[i].Package.Count != fcnt) {
			cmn_err(CE_NOTE, "!cpu_acpi: Unexpected data in "
			    "%s package for CPU %d.",
			    cpu_acpi_obj_attrs[objtype].name,
			    handle->cs_id);
			goto out;
		}

		q = obj->Package.Elements[i].Package.Elements;
		for (j = 0; j < fcnt; j++) {
			if (q[j].Type != ACPI_TYPE_INTEGER) {
				cmn_err(CE_NOTE, "!cpu_acpi: %s element "
				    "invalid (type) for CPU %d.",
				    cpu_acpi_obj_attrs[objtype].name,
				    handle->cs_id);
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
			cmn_err(CE_NOTE, "!cpu_acpi: Unexpected data in %s "
			    "package after eot for CPU %d.",
			    cpu_acpi_obj_attrs[objtype].name,
			    handle->cs_id);
			goto out;
		}

		/*
		 * states must be defined in order from highest to lowest.
		 */
		if (l != NULL && l[0].Integer.Value < q[0].Integer.Value) {
			cmn_err(CE_NOTE, "!cpu_acpi: %s package state "
			    "definitions out of order for CPU %d.",
			    cpu_acpi_obj_attrs[objtype].name,
			    handle->cs_id);
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
	if (abuf.Pointer != NULL)
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
	ACPI_STATUS astatus;
	ACPI_BUFFER abuf;
	ACPI_OBJECT *obj;
	int ret = -1;

	/*
	 * Fetch the present capabilites object (if present) for the CPU node.
	 */
	abuf.Length = ACPI_ALLOCATE_BUFFER;
	abuf.Pointer = NULL;
	astatus = AcpiEvaluateObject(handle->cs_handle,
	    cpu_acpi_obj_attrs[objtype].name, NULL, &abuf);
	if (ACPI_FAILURE(astatus) && astatus != AE_NOT_FOUND) {
		cmn_err(CE_NOTE, "!cpu_acpi: error %d evaluating %s "
		    "package for CPU %d.", astatus,
		    cpu_acpi_obj_attrs[objtype].name, handle->cs_id);
		goto out;
	}
	if (astatus == AE_NOT_FOUND || abuf.Length == 0) {
		*pc = 0;
		return (1);
	}

	obj = (ACPI_OBJECT *)abuf.Pointer;
	*pc = obj->Integer.Value;

	ret = 0;
out:
	if (abuf.Pointer != NULL)
		AcpiOsFree(abuf.Pointer);
	return (ret);
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

int
cpu_acpi_verify_cstate(cpu_acpi_cstate_t *cstate)
{
	uint32_t addrspaceid = cstate->cs_addrspace_id;

	if ((addrspaceid != ACPI_ADR_SPACE_FIXED_HARDWARE) &&
	    (addrspaceid != ACPI_ADR_SPACE_SYSTEM_IO)) {
		cmn_err(CE_NOTE, "!cpu_acpi: _CST unsupported address space id"
		    ":C%d, type: %d\n", cstate->cs_type, addrspaceid);
		return (1);
	}
	return (0);
}

int
cpu_acpi_cache_cst(cpu_acpi_handle_t handle)
{
	ACPI_STATUS astatus;
	ACPI_BUFFER abuf;
	ACPI_OBJECT *obj;
	ACPI_INTEGER cnt, old_cnt;
	cpu_acpi_cstate_t *cstate, *p;
	size_t alloc_size;
	int i, count;
	int ret = 1;

	CPU_ACPI_OBJ_IS_NOT_CACHED(handle, CPU_ACPI_CST_CACHED);

	abuf.Length = ACPI_ALLOCATE_BUFFER;
	abuf.Pointer = NULL;

	/*
	 * Fetch the C-state data (if present) for the CPU node.
	 */
	astatus = AcpiEvaluateObjectTyped(handle->cs_handle, "_CST",
	    NULL, &abuf, ACPI_TYPE_PACKAGE);
	if (ACPI_FAILURE(astatus)) {
		if (astatus == AE_NOT_FOUND) {
			DTRACE_PROBE3(cpu_acpi__eval__err, int, handle->cs_id,
			    int, CST_OBJ, int, astatus);
			return (1);
		}
		cmn_err(CE_NOTE, "!cpu_acpi: error %d evaluating _CST package "
		    "for CPU %d.", astatus, handle->cs_id);
		goto out;

	}
	obj = (ACPI_OBJECT *)abuf.Pointer;
	if (obj->Package.Count < 2) {
		cmn_err(CE_NOTE, "!cpu_acpi: _CST unsupported package "
		    "count %d for CPU %d.", obj->Package.Count, handle->cs_id);
		goto out;
	}

	/*
	 * Does the package look coherent?
	 */
	cnt = obj->Package.Elements[0].Integer.Value;
	if (cnt < 1 || cnt != obj->Package.Count - 1) {
		cmn_err(CE_NOTE, "!cpu_acpi: _CST invalid element "
		    "count %d != Package count %d for CPU %d",
		    (int)cnt, (int)obj->Package.Count - 1, handle->cs_id);
		goto out;
	}

	/*
	 * Reuse the old buffer if the number of C states is the same.
	 */
	if (CPU_ACPI_CSTATES(handle) &&
	    (old_cnt = CPU_ACPI_CSTATES_COUNT(handle)) != cnt) {
		kmem_free(CPU_ACPI_CSTATES(handle),
		    CPU_ACPI_CSTATES_SIZE(old_cnt));
		CPU_ACPI_CSTATES(handle) = NULL;
	}

	CPU_ACPI_CSTATES_COUNT(handle) = (uint32_t)cnt;
	alloc_size = CPU_ACPI_CSTATES_SIZE(cnt);
	if (CPU_ACPI_CSTATES(handle) == NULL)
		CPU_ACPI_CSTATES(handle) = kmem_zalloc(alloc_size, KM_SLEEP);
	cstate = (cpu_acpi_cstate_t *)CPU_ACPI_CSTATES(handle);
	p = cstate;

	for (i = 1, count = 1; i <= cnt; i++) {
		ACPI_OBJECT *pkg;
		AML_RESOURCE_GENERIC_REGISTER *reg;
		ACPI_OBJECT *element;

		pkg = &(obj->Package.Elements[i]);
		reg = (AML_RESOURCE_GENERIC_REGISTER *)
		    pkg->Package.Elements[0].Buffer.Pointer;
		cstate->cs_addrspace_id = reg->AddressSpaceId;
		cstate->cs_address = reg->Address;
		element = &(pkg->Package.Elements[1]);
		cstate->cs_type = element->Integer.Value;
		element = &(pkg->Package.Elements[2]);
		cstate->cs_latency = element->Integer.Value;
		element = &(pkg->Package.Elements[3]);
		cstate->cs_power = element->Integer.Value;

		if (cpu_acpi_verify_cstate(cstate)) {
			/*
			 * ignore this entry if it's not valid
			 */
			continue;
		}
		if (cstate == p) {
			cstate++;
		} else if (p->cs_type == cstate->cs_type) {
			/*
			 * if there are duplicate entries, we keep the
			 * last one. This fixes:
			 * 1) some buggy BIOS have total duplicate entries.
			 * 2) ACPI Spec allows the same cstate entry with
			 *    different power and latency, we use the one
			 *    with more power saving.
			 */
			(void) memcpy(p, cstate, sizeof (cpu_acpi_cstate_t));
		} else {
			/*
			 * we got a valid entry, cache it to the
			 * cstate structure
			 */
			p = cstate++;
			count++;
		}
	}

	if (count < 2) {
		cmn_err(CE_NOTE, "!cpu_acpi: _CST invalid count %d < 2 for "
		    "CPU %d", count, handle->cs_id);
		kmem_free(CPU_ACPI_CSTATES(handle), alloc_size);
		CPU_ACPI_CSTATES(handle) = NULL;
		CPU_ACPI_CSTATES_COUNT(handle) = (uint32_t)0;
		goto out;
	}
	cstate = (cpu_acpi_cstate_t *)CPU_ACPI_CSTATES(handle);
	if (cstate[0].cs_type != CPU_ACPI_C1) {
		cmn_err(CE_NOTE, "!cpu_acpi: _CST first element type not "
		    "C1: %d for CPU %d", (int)cstate->cs_type, handle->cs_id);
		kmem_free(CPU_ACPI_CSTATES(handle), alloc_size);
		CPU_ACPI_CSTATES(handle) = NULL;
		CPU_ACPI_CSTATES_COUNT(handle) = (uint32_t)0;
		goto out;
	}

	if (count != cnt) {
		void	*orig = CPU_ACPI_CSTATES(handle);

		CPU_ACPI_CSTATES_COUNT(handle) = (uint32_t)count;
		CPU_ACPI_CSTATES(handle) = kmem_zalloc(
		    CPU_ACPI_CSTATES_SIZE(count), KM_SLEEP);
		(void) memcpy(CPU_ACPI_CSTATES(handle), orig,
		    CPU_ACPI_CSTATES_SIZE(count));
		kmem_free(orig, alloc_size);
	}

	CPU_ACPI_OBJ_IS_CACHED(handle, CPU_ACPI_CST_CACHED);

	ret = 0;

out:
	if (abuf.Pointer != NULL)
		AcpiOsFree(abuf.Pointer);
	return (ret);
}

/*
 * Cache the _PCT, _PSS, _PSD and _PPC data.
 */
int
cpu_acpi_cache_pstate_data(cpu_acpi_handle_t handle)
{
	if (cpu_acpi_cache_pct(handle) < 0) {
		DTRACE_PROBE2(cpu_acpi__cache__err, int, handle->cs_id,
		    int, PCT_OBJ);
		return (-1);
	}

	if (cpu_acpi_cache_pstates(handle) != 0) {
		DTRACE_PROBE2(cpu_acpi__cache__err, int, handle->cs_id,
		    int, PSS_OBJ);
		return (-1);
	}

	if (cpu_acpi_cache_psd(handle) < 0) {
		DTRACE_PROBE2(cpu_acpi__cache__err, int, handle->cs_id,
		    int, PSD_OBJ);
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
	int ret;

	if (cpu_acpi_cache_ptc(handle) < 0) {
		DTRACE_PROBE2(cpu_acpi__cache__err, int, handle->cs_id,
		    int, PTC_OBJ);
		return (-1);
	}

	if ((ret = cpu_acpi_cache_tstates(handle)) != 0) {
		DTRACE_PROBE2(cpu_acpi__cache__err, int, handle->cs_id,
		    int, TSS_OBJ);
		return (ret);
	}

	if (cpu_acpi_cache_tsd(handle) < 0) {
		DTRACE_PROBE2(cpu_acpi__cache__err, int, handle->cs_id,
		    int, TSD_OBJ);
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
 * Cache the _CST data.
 */
int
cpu_acpi_cache_cstate_data(cpu_acpi_handle_t handle)
{
	int ret;

	if ((ret = cpu_acpi_cache_cst(handle)) != 0) {
		DTRACE_PROBE2(cpu_acpi__cache__err, int, handle->cs_id,
		    int, CST_OBJ);
		return (ret);
	}

	if (cpu_acpi_cache_csd(handle) < 0) {
		DTRACE_PROBE2(cpu_acpi__cache__err, int, handle->cs_id,
		    int, CSD_OBJ);
		return (-1);
	}

	return (0);
}

void
cpu_acpi_free_cstate_data(cpu_acpi_handle_t handle)
{
	if (handle != NULL) {
		if (CPU_ACPI_CSTATES(handle)) {
			kmem_free(CPU_ACPI_CSTATES(handle),
			    CPU_ACPI_CSTATES_SIZE(
			    CPU_ACPI_CSTATES_COUNT(handle)));
			CPU_ACPI_CSTATES(handle) = NULL;
		}
	}
}

/*
 * Register a handler for processor change notifications.
 */
void
cpu_acpi_install_notify_handler(cpu_acpi_handle_t handle,
    ACPI_NOTIFY_HANDLER handler, void *ctx)
{
	if (ACPI_FAILURE(AcpiInstallNotifyHandler(handle->cs_handle,
	    ACPI_DEVICE_NOTIFY, handler, ctx)))
		cmn_err(CE_NOTE, "!cpu_acpi: Unable to register "
		    "notify handler for CPU %d.", handle->cs_id);
}

/*
 * Remove a handler for processor change notifications.
 */
void
cpu_acpi_remove_notify_handler(cpu_acpi_handle_t handle,
    ACPI_NOTIFY_HANDLER handler)
{
	if (ACPI_FAILURE(AcpiRemoveNotifyHandler(handle->cs_handle,
	    ACPI_DEVICE_NOTIFY, handler)))
		cmn_err(CE_NOTE, "!cpu_acpi: Unable to remove "
		    "notify handler for CPU %d.", handle->cs_id);
}

/*
 * Write _PDC.
 */
int
cpu_acpi_write_pdc(cpu_acpi_handle_t handle, uint32_t revision, uint32_t count,
    uint32_t *capabilities)
{
	ACPI_STATUS astatus;
	ACPI_OBJECT obj;
	ACPI_OBJECT_LIST list = { 1, &obj};
	uint32_t *buffer;
	uint32_t *bufptr;
	uint32_t bufsize;
	int i;
	int ret = 0;

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
	 * Fetch the ??? (if present) for the CPU node.
	 */
	astatus = AcpiEvaluateObject(handle->cs_handle, "_PDC", &list, NULL);
	if (ACPI_FAILURE(astatus)) {
		if (astatus == AE_NOT_FOUND) {
			DTRACE_PROBE3(cpu_acpi__eval__err, int, handle->cs_id,
			    int, PDC_OBJ, int, astatus);
			ret = 1;
		} else {
			cmn_err(CE_NOTE, "!cpu_acpi: error %d evaluating _PDC "
			    "package for CPU %d.", astatus, handle->cs_id);
			ret = -1;
		}
	}

	kmem_free(buffer, bufsize);
	return (ret);
}

/*
 * Write to system IO port.
 */
int
cpu_acpi_write_port(ACPI_IO_ADDRESS address, uint32_t value, uint32_t width)
{
	if (ACPI_FAILURE(AcpiOsWritePort(address, value, width))) {
		cmn_err(CE_NOTE, "!cpu_acpi: error writing system IO port "
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
		cmn_err(CE_NOTE, "!cpu_acpi: error reading system IO port "
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

uint_t
cpu_acpi_get_max_cstates(cpu_acpi_handle_t handle)
{
	if (CPU_ACPI_CSTATES(handle))
		return (CPU_ACPI_CSTATES_COUNT(handle));
	else
		return (1);
}

void
cpu_acpi_set_register(uint32_t bitreg, uint32_t value)
{
	(void) AcpiWriteBitRegister(bitreg, value);
}

void
cpu_acpi_get_register(uint32_t bitreg, uint32_t *value)
{
	(void) AcpiReadBitRegister(bitreg, value);
}

/*
 * Map the dip to an ACPI handle for the device.
 */
cpu_acpi_handle_t
cpu_acpi_init(cpu_t *cp)
{
	cpu_acpi_handle_t handle;

	handle = kmem_zalloc(sizeof (cpu_acpi_state_t), KM_SLEEP);

	if (ACPI_FAILURE(acpica_get_handle_cpu(cp->cpu_id,
	    &handle->cs_handle))) {
		kmem_free(handle, sizeof (cpu_acpi_state_t));
		return (NULL);
	}
	handle->cs_id = cp->cpu_id;
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
