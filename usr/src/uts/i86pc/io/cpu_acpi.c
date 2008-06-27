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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/cpu_acpi.h>

#define	CPU_ACPI_PSTATES_SIZE(cnt) (cnt * sizeof (cpu_acpi_pstate_t))
#define	CPU_ACPI_PSS_SIZE (sizeof (cpu_acpi_pstate_t) / sizeof (uint32_t))

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
	if (handle->cs_pstates != NULL) {
		if (CPU_ACPI_PSTATES(handle) != NULL)
			kmem_free(CPU_ACPI_PSTATES(handle),
			    CPU_ACPI_PSTATES_SIZE(
			    CPU_ACPI_PSTATES_COUNT(handle)));
		kmem_free(handle->cs_pstates, sizeof (cpu_acpi_pstates_t));
	}
	kmem_free(handle, sizeof (cpu_acpi_state_t));
}

/*
 * Cache the ACPI _PCT data. The _PCT data defines the interface to use
 * when making power level transitions (i.e., system IO ports, fixed
 * hardware port, etc).
 */
int
cpu_acpi_cache_pct(cpu_acpi_handle_t handle)
{
	ACPI_BUFFER abuf;
	ACPI_OBJECT *obj;
	AML_RESOURCE_GENERIC_REGISTER *greg;
	cpu_acpi_pct_t *pct;
	int ret = -1;
	int i;

	/*
	 * Fetch the _PCT (if present) for the CPU node. Since the PCT is
	 * optional, non-existence is not a failure (we just consider
	 * it a fixed hardware case).
	 */
	CPU_ACPI_OBJ_IS_NOT_CACHED(handle, CPU_ACPI_PCT_CACHED);
	abuf.Length = ACPI_ALLOCATE_BUFFER;
	abuf.Pointer = NULL;
	if (ACPI_FAILURE(AcpiEvaluateObjectTyped(handle->cs_handle, "_PCT",
	    NULL, &abuf, ACPI_TYPE_PACKAGE))) {
		CPU_ACPI_PCT(handle)[0].pc_addrspace_id =
		    ACPI_ADR_SPACE_FIXED_HARDWARE;
		CPU_ACPI_PCT(handle)[1].pc_addrspace_id =
		    ACPI_ADR_SPACE_FIXED_HARDWARE;
		return (1);
	}

	obj = abuf.Pointer;
	if (obj->Package.Count != 2) {
		cmn_err(CE_NOTE, "!cpu_acpi: _PCT package bad count %d.",
		    obj->Package.Count);
		goto out;
	}

	/*
	 * Does the package look coherent?
	 */
	for (i = 0; i < obj->Package.Count; i++) {
		if (obj->Package.Elements[i].Type != ACPI_TYPE_BUFFER) {
			cmn_err(CE_NOTE, "!cpu_acpi: "
			    "Unexpected data in _PCT package.");
			goto out;
		}

		greg = (AML_RESOURCE_GENERIC_REGISTER *)
		    obj->Package.Elements[i].Buffer.Pointer;
		if (greg->DescriptorType !=
		    ACPI_RESOURCE_NAME_GENERIC_REGISTER) {
			cmn_err(CE_NOTE, "!cpu_acpi: "
			    "_PCT package has format error.");
			goto out;
		}
		if (greg->ResourceLength !=
		    ACPI_AML_SIZE_LARGE(AML_RESOURCE_GENERIC_REGISTER)) {
			cmn_err(CE_NOTE, "!cpu_acpi: "
			    "_PCT package not right size.");
			goto out;
		}
		if (greg->AddressSpaceId != ACPI_ADR_SPACE_FIXED_HARDWARE &&
		    greg->AddressSpaceId != ACPI_ADR_SPACE_SYSTEM_IO) {
			cmn_err(CE_NOTE, "!cpu_apci: _PCT contains unsupported "
			    "address space type %x", greg->AddressSpaceId);
			goto out;
		}
	}

	/*
	 * Looks good!
	 */
	for (i = 0; i < obj->Package.Count; i++) {
		greg = (AML_RESOURCE_GENERIC_REGISTER *)
		    obj->Package.Elements[i].Buffer.Pointer;
		pct = &CPU_ACPI_PCT(handle)[i];
		pct->pc_addrspace_id = greg->AddressSpaceId;
		pct->pc_width = greg->BitWidth;
		pct->pc_offset = greg->BitOffset;
		pct->pc_asize = greg->AccessSize;
		pct->pc_address = greg->Address;
	}
	CPU_ACPI_OBJ_IS_CACHED(handle, CPU_ACPI_PCT_CACHED);
	ret = 0;
out:
	AcpiOsFree(abuf.Pointer);
	return (ret);
}

/*
 * Cache the ACPI _PSD data. The _PSD data defines CPU dependencies
 * (think CPU domains).
 */
int
cpu_acpi_cache_psd(cpu_acpi_handle_t handle)
{
	ACPI_BUFFER abuf;
	ACPI_OBJECT *pkg, *elements;
	cpu_acpi_psd_t *psd;
	int ret = -1;

	/*
	 * Fetch the _PSD (if present) for the CPU node. Since the PSD is
	 * optional, non-existence is not a failure (it's up to the caller
	 * to determine how to handle non-existence).
	 */
	CPU_ACPI_OBJ_IS_NOT_CACHED(handle, CPU_ACPI_PSD_CACHED);
	abuf.Length = ACPI_ALLOCATE_BUFFER;
	abuf.Pointer = NULL;
	if (ACPI_FAILURE(AcpiEvaluateObjectTyped(handle->cs_handle, "_PSD",
	    NULL, &abuf, ACPI_TYPE_PACKAGE))) {
		return (1);
	}

	pkg = abuf.Pointer;
	if (pkg->Package.Count != 1) {
		cmn_err(CE_NOTE, "!cpu_acpi: _PSD unsupported package "
		    "count %d.", pkg->Package.Count);
		goto out;
	}

	if (pkg->Package.Elements[0].Type != ACPI_TYPE_PACKAGE ||
	    pkg->Package.Elements[0].Package.Count != 5) {
		cmn_err(CE_NOTE, "!cpu_acpi: Unexpected data in _PSD package.");
		goto out;
	}
	elements = pkg->Package.Elements[0].Package.Elements;
	if (elements[0].Integer.Value != 5 || elements[1].Integer.Value != 0) {
		cmn_err(CE_NOTE, "!cpu_acpi: Unexpected _PSD revision.");
		goto out;
	}
	psd = &CPU_ACPI_PSD(handle);

	psd->pd_entries = elements[0].Integer.Value;
	psd->pd_revision = elements[1].Integer.Value;
	psd->pd_domain = elements[2].Integer.Value;
	psd->pd_type = elements[3].Integer.Value;
	psd->pd_num = elements[4].Integer.Value;
	CPU_ACPI_OBJ_IS_CACHED(handle, CPU_ACPI_PSD_CACHED);
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
int
cpu_acpi_cache_pstates(cpu_acpi_handle_t handle)
{
	ACPI_BUFFER abuf;
	ACPI_OBJECT *obj, *q, *l;
	cpu_acpi_pstate_t *pstate;
	boolean_t eot = B_FALSE;
	int ret = -1;
	int cnt;
	int i, j;

	/*
	 * Fetch the _PSS (if present) for the CPU node. If there isn't
	 * one, then CPU power management will not be possible.
	 */
	CPU_ACPI_OBJ_IS_NOT_CACHED(handle, CPU_ACPI_PSS_CACHED);
	abuf.Length = ACPI_ALLOCATE_BUFFER;
	abuf.Pointer = NULL;
	if (ACPI_FAILURE(AcpiEvaluateObjectTyped(handle->cs_handle, "_PSS",
	    NULL, &abuf, ACPI_TYPE_PACKAGE))) {
		cmn_err(CE_NOTE, "!cpu_acpi: _PSS package not found.");
		return (1);
	}
	obj = abuf.Pointer;
	if (obj->Package.Count < 2) {
		cmn_err(CE_NOTE, "!cpu_acpi: _PSS package bad count %d.",
		    obj->Package.Count);
		goto out;
	}

	/*
	 * Does the package look coherent?
	 */
	cnt = 0;
	for (i = 0, l = NULL; i < obj->Package.Count; i++, l = q) {
		if (obj->Package.Elements[i].Type != ACPI_TYPE_PACKAGE ||
		    obj->Package.Elements[i].Package.Count !=
		    CPU_ACPI_PSS_SIZE) {
			cmn_err(CE_NOTE, "!cpu_acpi: "
			    "Unexpected data in _PSS package.");
			goto out;
		}

		q = obj->Package.Elements[i].Package.Elements;
		for (j = 0; j < CPU_ACPI_PSS_SIZE; j++) {
			if (q[j].Type != ACPI_TYPE_INTEGER) {
				cmn_err(CE_NOTE, "!cpu_acpi: "
				    "_PSS element invalid (type)");
				goto out;
			}
		}

		/*
		 * Ignore duplicate entries.
		 */
		if (l != NULL && l[0].Integer.Value == q[0].Integer.Value)
			continue;

		/*
		 * Some _PSS tables are larger than required
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
		 * an end-of-table entry.
		 */
		if (eot) {
			cmn_err(CE_NOTE, "!cpu_acpi: "
			    "Unexpected data in _PSS package after eot.");
			goto out;
		}

		/*
		 * pstates must be defined in order from highest to lowest.
		 */
		if (l != NULL && l[0].Integer.Value < q[0].Integer.Value) {
			cmn_err(CE_NOTE, "!cpu_acpi: "
			    "_PSS package pstate definitions out of order.");
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
	 * Yes, fill in pstate structure.
	 */
	handle->cs_pstates = kmem_zalloc(sizeof (cpu_acpi_pstates_t), KM_SLEEP);
	CPU_ACPI_PSTATES_COUNT(handle) = cnt;
	CPU_ACPI_PSTATES(handle) = kmem_zalloc(CPU_ACPI_PSTATES_SIZE(cnt),
	    KM_SLEEP);
	pstate = CPU_ACPI_PSTATES(handle);
	for (i = 0, l = NULL; i < obj->Package.Count && cnt > 0; i++, l = q) {
		uint32_t *up;

		q = obj->Package.Elements[i].Package.Elements;

		/*
		 * Skip duplicate entries.
		 */
		if (l != NULL && l[0].Integer.Value == q[0].Integer.Value)
			continue;

		up = (uint32_t *)pstate;
		for (j = 0; j < CPU_ACPI_PSS_SIZE; j++)
			up[j] = q[j].Integer.Value;
		pstate++;
		cnt--;
	}
	CPU_ACPI_OBJ_IS_CACHED(handle, CPU_ACPI_PSS_CACHED);
	ret = 0;
out:
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
	ACPI_BUFFER abuf;
	ACPI_OBJECT *obj;

	/*
	 * Fetch the _PPC (if present) for the CPU node. Since the PPC is
	 * optional (I think), non-existence is not a failure.
	 */
	CPU_ACPI_OBJ_IS_NOT_CACHED(handle, CPU_ACPI_PPC_CACHED);
	abuf.Length = ACPI_ALLOCATE_BUFFER;
	abuf.Pointer = NULL;
	if (ACPI_FAILURE(AcpiEvaluateObject(handle->cs_handle, "_PPC",
	    NULL, &abuf))) {
		CPU_ACPI_PPC(handle) = 0;
		return;
	}

	obj = (ACPI_OBJECT *)abuf.Pointer;
	CPU_ACPI_PPC(handle) = obj->Integer.Value;
	CPU_ACPI_OBJ_IS_CACHED(handle, CPU_ACPI_PPC_CACHED);
	AcpiOsFree(abuf.Pointer);
}

/*
 * Cache the _PCT, _PSS, _PSD and _PPC data.
 */
int
cpu_acpi_cache_data(cpu_acpi_handle_t handle)
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

/*
 * Register a handler for _PPC change notifications. The _PPC
 * change notification is the means by which _P
 */
void
cpu_acpi_install_ppc_handler(cpu_acpi_handle_t handle,
    ACPI_NOTIFY_HANDLER handler, dev_info_t *dip)
{
	char path[MAXNAMELEN];
	if (ACPI_FAILURE(AcpiInstallNotifyHandler(handle->cs_handle,
	    ACPI_DEVICE_NOTIFY, handler, dip)))
		cmn_err(CE_NOTE, "!cpu_acpi: Unable to register _PPC "
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
	hspeeds = kmem_zalloc(nspeeds * sizeof (int), KM_SLEEP);
	for (i = 0; i < nspeeds; i++) {
		pstate = CPU_ACPI_PSTATE(handle, i);
		hspeeds[i] = CPU_ACPI_FREQ(pstate);
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
