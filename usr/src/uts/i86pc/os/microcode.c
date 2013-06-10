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
 *
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 */

#include <sys/asm_linkage.h>
#include <sys/bootconf.h>
#include <sys/cpuvar.h>
#include <sys/cmn_err.h>
#include <sys/controlregs.h>
#include <sys/debug.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/machsystm.h>
#include <sys/ontrap.h>
#include <sys/param.h>
#include <sys/machparam.h>
#include <sys/promif.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/thread.h>
#include <sys/ucode.h>
#include <sys/x86_archext.h>
#include <sys/x_call.h>
#ifdef	__xpv
#include <sys/hypervisor.h>
#endif

/*
 * AMD-specific equivalence table
 */
static ucode_eqtbl_amd_t *ucode_eqtbl_amd;

/*
 * mcpu_ucode_info for the boot CPU.  Statically allocated.
 */
static struct cpu_ucode_info cpu_ucode_info0;

static ucode_file_t ucodefile;

static void* ucode_zalloc(processorid_t, size_t);
static void ucode_free(processorid_t, void *, size_t);

static int ucode_capable_amd(cpu_t *);
static int ucode_capable_intel(cpu_t *);

static ucode_errno_t ucode_extract_amd(ucode_update_t *, uint8_t *, int);
static ucode_errno_t ucode_extract_intel(ucode_update_t *, uint8_t *,
    int);

static void ucode_file_reset_amd(ucode_file_t *, processorid_t);
static void ucode_file_reset_intel(ucode_file_t *, processorid_t);

static uint32_t ucode_load_amd(ucode_file_t *, cpu_ucode_info_t *, cpu_t *);
static uint32_t ucode_load_intel(ucode_file_t *, cpu_ucode_info_t *, cpu_t *);

#ifdef	__xpv
static void ucode_load_xpv(ucode_update_t *);
static void ucode_chipset_amd(uint8_t *, int);
#endif

static int ucode_equiv_cpu_amd(cpu_t *, uint16_t *);

static ucode_errno_t ucode_locate_amd(cpu_t *, cpu_ucode_info_t *,
    ucode_file_t *);
static ucode_errno_t ucode_locate_intel(cpu_t *, cpu_ucode_info_t *,
    ucode_file_t *);

#ifndef __xpv
static ucode_errno_t ucode_match_amd(uint16_t, cpu_ucode_info_t *,
    ucode_file_amd_t *, int);
#endif
static ucode_errno_t ucode_match_intel(int, cpu_ucode_info_t *,
    ucode_header_intel_t *, ucode_ext_table_intel_t *);

static void ucode_read_rev_amd(cpu_ucode_info_t *);
static void ucode_read_rev_intel(cpu_ucode_info_t *);

static const struct ucode_ops ucode_amd = {
	MSR_AMD_PATCHLOADER,
	ucode_capable_amd,
	ucode_file_reset_amd,
	ucode_read_rev_amd,
	ucode_load_amd,
	ucode_validate_amd,
	ucode_extract_amd,
	ucode_locate_amd
};

static const struct ucode_ops ucode_intel = {
	MSR_INTC_UCODE_WRITE,
	ucode_capable_intel,
	ucode_file_reset_intel,
	ucode_read_rev_intel,
	ucode_load_intel,
	ucode_validate_intel,
	ucode_extract_intel,
	ucode_locate_intel
};

const struct ucode_ops *ucode;

static const char ucode_failure_fmt[] =
	"cpu%d: failed to update microcode from version 0x%x to 0x%x\n";
static const char ucode_success_fmt[] =
	"?cpu%d: microcode has been updated from version 0x%x to 0x%x\n";

/*
 * Force flag.  If set, the first microcode binary that matches
 * signature and platform id will be used for microcode update,
 * regardless of version.  Should only be used for debugging.
 */
int ucode_force_update = 0;

/*
 * Allocate space for mcpu_ucode_info in the machcpu structure
 * for all non-boot CPUs.
 */
void
ucode_alloc_space(cpu_t *cp)
{
	ASSERT(cp->cpu_id != 0);
	ASSERT(cp->cpu_m.mcpu_ucode_info == NULL);
	cp->cpu_m.mcpu_ucode_info =
	    kmem_zalloc(sizeof (*cp->cpu_m.mcpu_ucode_info), KM_SLEEP);
}

void
ucode_free_space(cpu_t *cp)
{
	ASSERT(cp->cpu_m.mcpu_ucode_info != NULL);
	ASSERT(cp->cpu_m.mcpu_ucode_info != &cpu_ucode_info0);
	kmem_free(cp->cpu_m.mcpu_ucode_info,
	    sizeof (*cp->cpu_m.mcpu_ucode_info));
	cp->cpu_m.mcpu_ucode_info = NULL;
}

/*
 * Called when we are done with microcode update on all processors to free up
 * space allocated for the microcode file.
 */
void
ucode_cleanup()
{
	if (ucode == NULL)
		return;

	ucode->file_reset(&ucodefile, -1);
}

/*
 * Allocate/free a buffer used to hold ucode data. Space for the boot CPU is
 * allocated with BOP_ALLOC() and does not require a free.
 */
static void*
ucode_zalloc(processorid_t id, size_t size)
{
	if (id)
		return (kmem_zalloc(size, KM_NOSLEEP));

	/* BOP_ALLOC() failure results in panic */
	return (BOP_ALLOC(bootops, NULL, size, MMU_PAGESIZE));
}

static void
ucode_free(processorid_t id, void* buf, size_t size)
{
	if (id)
		kmem_free(buf, size);
}

/*
 * Check whether or not a processor is capable of microcode operations
 * Returns 1 if it is capable, 0 if not.
 *
 * At this point we only support microcode update for:
 * - Intel processors family 6 and above, and
 * - AMD processors family 0x10 and above.
 *
 * We also assume that we don't support a mix of Intel and
 * AMD processors in the same box.
 *
 * An i86xpv guest domain or VM can't update the microcode.
 */

#define	XPVDOMU_OR_HVM	\
	((hwenv == HW_XEN_PV && !is_controldom()) || (hwenv & HW_VIRTUAL) != 0)

/*ARGSUSED*/
static int
ucode_capable_amd(cpu_t *cp)
{
	int hwenv = get_hwenv();

	if (XPVDOMU_OR_HVM)
		return (0);

	return (cpuid_getfamily(cp) >= 0x10);
}

static int
ucode_capable_intel(cpu_t *cp)
{
	int hwenv = get_hwenv();

	if (XPVDOMU_OR_HVM)
		return (0);

	return (cpuid_getfamily(cp) >= 6);
}

/*
 * Called when it is no longer necessary to keep the microcode around,
 * or when the cached microcode doesn't match the CPU being processed.
 */
static void
ucode_file_reset_amd(ucode_file_t *ufp, processorid_t id)
{
	ucode_file_amd_t *ucodefp = ufp->amd;

	if (ucodefp == NULL)
		return;

	ucode_free(id, ucodefp, sizeof (ucode_file_amd_t));
	ufp->amd = NULL;
}

static void
ucode_file_reset_intel(ucode_file_t *ufp, processorid_t id)
{
	ucode_file_intel_t *ucodefp = &ufp->intel;
	int total_size, body_size;

	if (ucodefp == NULL || ucodefp->uf_header == NULL)
		return;

	total_size = UCODE_TOTAL_SIZE_INTEL(ucodefp->uf_header->uh_total_size);
	body_size = UCODE_BODY_SIZE_INTEL(ucodefp->uf_header->uh_body_size);
	if (ucodefp->uf_body) {
		ucode_free(id, ucodefp->uf_body, body_size);
		ucodefp->uf_body = NULL;
	}

	if (ucodefp->uf_ext_table) {
		int size = total_size - body_size - UCODE_HEADER_SIZE_INTEL;

		ucode_free(id, ucodefp->uf_ext_table, size);
		ucodefp->uf_ext_table = NULL;
	}

	ucode_free(id, ucodefp->uf_header, UCODE_HEADER_SIZE_INTEL);
	ucodefp->uf_header = NULL;
}

/*
 * Find the equivalent CPU id in the equivalence table.
 */
static int
ucode_equiv_cpu_amd(cpu_t *cp, uint16_t *eq_sig)
{
	char name[MAXPATHLEN];
	intptr_t fd;
	int count;
	int offset = 0, cpi_sig = cpuid_getsig(cp);
	ucode_eqtbl_amd_t *eqtbl = ucode_eqtbl_amd;

	(void) snprintf(name, MAXPATHLEN, "/%s/%s/equivalence-table",
	    UCODE_INSTALL_PATH, cpuid_getvendorstr(cp));

	/*
	 * No kmem_zalloc() etc. available on boot cpu.
	 */
	if (cp->cpu_id == 0) {
		if ((fd = kobj_open(name)) == -1)
			return (EM_OPENFILE);
		/* ucode_zalloc() cannot fail on boot cpu */
		eqtbl = ucode_zalloc(cp->cpu_id, sizeof (*eqtbl));
		ASSERT(eqtbl);
		do {
			count = kobj_read(fd, (int8_t *)eqtbl,
			    sizeof (*eqtbl), offset);
			if (count != sizeof (*eqtbl)) {
				(void) kobj_close(fd);
				return (EM_HIGHERREV);
			}
			offset += count;
		} while (eqtbl->ue_inst_cpu && eqtbl->ue_inst_cpu != cpi_sig);
		(void) kobj_close(fd);
	}

	/*
	 * If not already done, load the equivalence table.
	 * Not done on boot CPU.
	 */
	if (eqtbl == NULL) {
		struct _buf *eq;
		uint64_t size;

		if ((eq = kobj_open_file(name)) == (struct _buf *)-1)
			return (EM_OPENFILE);

		if (kobj_get_filesize(eq, &size) < 0) {
			kobj_close_file(eq);
			return (EM_OPENFILE);
		}

		ucode_eqtbl_amd = kmem_zalloc(size, KM_NOSLEEP);
		if (ucode_eqtbl_amd == NULL) {
			kobj_close_file(eq);
			return (EM_NOMEM);
		}

		count = kobj_read_file(eq, (char *)ucode_eqtbl_amd, size, 0);
		kobj_close_file(eq);

		if (count != size)
			return (EM_FILESIZE);
	}

	/* Get the equivalent CPU id. */
	if (cp->cpu_id)
		for (eqtbl = ucode_eqtbl_amd;
		    eqtbl->ue_inst_cpu && eqtbl->ue_inst_cpu != cpi_sig;
		    eqtbl++)
			;

	*eq_sig = eqtbl->ue_equiv_cpu;

	/* No equivalent CPU id found, assume outdated microcode file. */
	if (*eq_sig == 0)
		return (EM_HIGHERREV);

	return (EM_OK);
}

/*
 * xVM cannot check for the presence of PCI devices. Look for chipset-
 * specific microcode patches in the container file and disable them
 * by setting their CPU revision to an invalid value.
 */
#ifdef __xpv
static void
ucode_chipset_amd(uint8_t *buf, int size)
{
	ucode_header_amd_t *uh;
	uint32_t *ptr = (uint32_t *)buf;
	int len = 0;

	/* skip to first microcode patch */
	ptr += 2; len = *ptr++; ptr += len >> 2; size -= len;

	while (size >= sizeof (ucode_header_amd_t) + 8) {
		ptr++; len = *ptr++;
		uh = (ucode_header_amd_t *)ptr;
		ptr += len >> 2; size -= len;

		if (uh->uh_nb_id) {
			cmn_err(CE_WARN, "ignoring northbridge-specific ucode: "
			    "chipset id %x, revision %x",
			    uh->uh_nb_id, uh->uh_nb_rev);
			uh->uh_cpu_rev = 0xffff;
		}

		if (uh->uh_sb_id) {
			cmn_err(CE_WARN, "ignoring southbridge-specific ucode: "
			    "chipset id %x, revision %x",
			    uh->uh_sb_id, uh->uh_sb_rev);
			uh->uh_cpu_rev = 0xffff;
		}
	}
}
#endif

/*
 * Populate the ucode file structure from microcode file corresponding to
 * this CPU, if exists.
 *
 * Return EM_OK on success, corresponding error code on failure.
 */
/*ARGSUSED*/
static ucode_errno_t
ucode_locate_amd(cpu_t *cp, cpu_ucode_info_t *uinfop, ucode_file_t *ufp)
{
	char name[MAXPATHLEN];
	intptr_t fd;
	int count, rc;
	ucode_file_amd_t *ucodefp = ufp->amd;

#ifndef __xpv
	uint16_t eq_sig = 0;
	int i;

	/* get equivalent CPU id */
	if ((rc = ucode_equiv_cpu_amd(cp, &eq_sig)) != EM_OK)
		return (rc);

	/*
	 * Allocate a buffer for the microcode patch. If the buffer has been
	 * allocated before, check for a matching microcode to avoid loading
	 * the file again.
	 */
	if (ucodefp == NULL)
		ucodefp = ucode_zalloc(cp->cpu_id, sizeof (*ucodefp));
	else if (ucode_match_amd(eq_sig, uinfop, ucodefp, sizeof (*ucodefp))
	    == EM_OK)
		return (EM_OK);

	if (ucodefp == NULL)
		return (EM_NOMEM);

	ufp->amd = ucodefp;

	/*
	 * Find the patch for this CPU. The patch files are named XXXX-YY, where
	 * XXXX is the equivalent CPU id and YY is the running patch number.
	 * Patches specific to certain chipsets are guaranteed to have lower
	 * numbers than less specific patches, so we can just load the first
	 * patch that matches.
	 */

	for (i = 0; i < 0xff; i++) {
		(void) snprintf(name, MAXPATHLEN, "/%s/%s/%04X-%02X",
		    UCODE_INSTALL_PATH, cpuid_getvendorstr(cp), eq_sig, i);
		if ((fd = kobj_open(name)) == -1)
			return (EM_NOMATCH);
		count = kobj_read(fd, (char *)ucodefp, sizeof (*ucodefp), 0);
		(void) kobj_close(fd);

		if (ucode_match_amd(eq_sig, uinfop, ucodefp, count) == EM_OK)
			return (EM_OK);
	}
	return (EM_NOMATCH);
#else
	int size = 0;
	char c;

	/*
	 * The xVM case is special. To support mixed-revision systems, the
	 * hypervisor will choose which patch to load for which CPU, so the
	 * whole microcode patch container file will have to be loaded.
	 *
	 * Since this code is only run on the boot cpu, we don't have to care
	 * about failing ucode_zalloc() or freeing allocated memory.
	 */
	if (cp->cpu_id != 0)
		return (EM_INVALIDARG);

	(void) snprintf(name, MAXPATHLEN, "/%s/%s/container",
	    UCODE_INSTALL_PATH, cpuid_getvendorstr(cp));

	if ((fd = kobj_open(name)) == -1)
		return (EM_OPENFILE);

	/* get the file size by counting bytes */
	do {
		count = kobj_read(fd, &c, 1, size);
		size += count;
	} while (count);

	ucodefp = ucode_zalloc(cp->cpu_id, sizeof (*ucodefp));
	ASSERT(ucodefp);
	ufp->amd = ucodefp;

	ucodefp->usize = size;
	ucodefp->ucodep = ucode_zalloc(cp->cpu_id, size);
	ASSERT(ucodefp->ucodep);

	/* load the microcode patch container file */
	count = kobj_read(fd, (char *)ucodefp->ucodep, size, 0);
	(void) kobj_close(fd);

	if (count != size)
		return (EM_FILESIZE);

	/* make sure the container file is valid */
	rc = ucode->validate(ucodefp->ucodep, ucodefp->usize);

	if (rc != EM_OK)
		return (rc);

	/* disable chipset-specific patches */
	ucode_chipset_amd(ucodefp->ucodep, ucodefp->usize);

	return (EM_OK);
#endif
}

static ucode_errno_t
ucode_locate_intel(cpu_t *cp, cpu_ucode_info_t *uinfop, ucode_file_t *ufp)
{
	char		name[MAXPATHLEN];
	intptr_t	fd;
	int		count;
	int		header_size = UCODE_HEADER_SIZE_INTEL;
	int		cpi_sig = cpuid_getsig(cp);
	ucode_errno_t	rc = EM_OK;
	ucode_file_intel_t *ucodefp = &ufp->intel;

	ASSERT(ucode);

	/*
	 * If the microcode matches the CPU we are processing, use it.
	 */
	if (ucode_match_intel(cpi_sig, uinfop, ucodefp->uf_header,
	    ucodefp->uf_ext_table) == EM_OK && ucodefp->uf_body != NULL) {
		return (EM_OK);
	}

	/*
	 * Look for microcode file with the right name.
	 */
	(void) snprintf(name, MAXPATHLEN, "/%s/%s/%08X-%02X",
	    UCODE_INSTALL_PATH, cpuid_getvendorstr(cp), cpi_sig,
	    uinfop->cui_platid);
	if ((fd = kobj_open(name)) == -1) {
		return (EM_OPENFILE);
	}

	/*
	 * We found a microcode file for the CPU we are processing,
	 * reset the microcode data structure and read in the new
	 * file.
	 */
	ucode->file_reset(ufp, cp->cpu_id);

	ucodefp->uf_header = ucode_zalloc(cp->cpu_id, header_size);
	if (ucodefp->uf_header == NULL)
		return (EM_NOMEM);

	count = kobj_read(fd, (char *)ucodefp->uf_header, header_size, 0);

	switch (count) {
	case UCODE_HEADER_SIZE_INTEL: {

		ucode_header_intel_t	*uhp = ucodefp->uf_header;
		uint32_t	offset = header_size;
		int		total_size, body_size, ext_size;
		uint32_t	sum = 0;

		/*
		 * Make sure that the header contains valid fields.
		 */
		if ((rc = ucode_header_validate_intel(uhp)) == EM_OK) {
			total_size = UCODE_TOTAL_SIZE_INTEL(uhp->uh_total_size);
			body_size = UCODE_BODY_SIZE_INTEL(uhp->uh_body_size);
			ucodefp->uf_body = ucode_zalloc(cp->cpu_id, body_size);
			if (ucodefp->uf_body == NULL) {
				rc = EM_NOMEM;
				break;
			}

			if (kobj_read(fd, (char *)ucodefp->uf_body,
			    body_size, offset) != body_size)
				rc = EM_FILESIZE;
		}

		if (rc)
			break;

		sum = ucode_checksum_intel(0, header_size,
		    (uint8_t *)ucodefp->uf_header);
		if (ucode_checksum_intel(sum, body_size, ucodefp->uf_body)) {
			rc = EM_CHECKSUM;
			break;
		}

		/*
		 * Check to see if there is extended signature table.
		 */
		offset = body_size + header_size;
		ext_size = total_size - offset;

		if (ext_size <= 0)
			break;

		ucodefp->uf_ext_table = ucode_zalloc(cp->cpu_id, ext_size);
		if (ucodefp->uf_ext_table == NULL) {
			rc = EM_NOMEM;
			break;
		}

		if (kobj_read(fd, (char *)ucodefp->uf_ext_table,
		    ext_size, offset) != ext_size) {
			rc = EM_FILESIZE;
		} else if (ucode_checksum_intel(0, ext_size,
		    (uint8_t *)(ucodefp->uf_ext_table))) {
			rc = EM_CHECKSUM;
		} else {
			int i;

			ext_size -= UCODE_EXT_TABLE_SIZE_INTEL;
			for (i = 0; i < ucodefp->uf_ext_table->uet_count;
			    i++) {
				if (ucode_checksum_intel(0,
				    UCODE_EXT_SIG_SIZE_INTEL,
				    (uint8_t *)(&(ucodefp->uf_ext_table->
				    uet_ext_sig[i])))) {
					rc = EM_CHECKSUM;
					break;
				}
			}
		}
		break;
	}

	default:
		rc = EM_FILESIZE;
		break;
	}

	kobj_close(fd);

	if (rc != EM_OK)
		return (rc);

	rc = ucode_match_intel(cpi_sig, uinfop, ucodefp->uf_header,
	    ucodefp->uf_ext_table);

	return (rc);
}

#ifndef __xpv
static ucode_errno_t
ucode_match_amd(uint16_t eq_sig, cpu_ucode_info_t *uinfop,
    ucode_file_amd_t *ucodefp, int size)
{
	ucode_header_amd_t *uh;

	if (ucodefp == NULL || size < sizeof (ucode_header_amd_t))
		return (EM_NOMATCH);

	uh = &ucodefp->uf_header;

	/*
	 * Don't even think about loading patches that would require code
	 * execution. Does not apply to patches for family 0x14 and beyond.
	 */
	if (uh->uh_cpu_rev < 0x5000 &&
	    size > offsetof(ucode_file_amd_t, uf_code_present) &&
	    ucodefp->uf_code_present)
		return (EM_NOMATCH);

	if (eq_sig != uh->uh_cpu_rev)
		return (EM_NOMATCH);

	if (uh->uh_nb_id) {
		cmn_err(CE_WARN, "ignoring northbridge-specific ucode: "
		    "chipset id %x, revision %x", uh->uh_nb_id, uh->uh_nb_rev);
		return (EM_NOMATCH);
	}

	if (uh->uh_sb_id) {
		cmn_err(CE_WARN, "ignoring southbridge-specific ucode: "
		    "chipset id %x, revision %x", uh->uh_sb_id, uh->uh_sb_rev);
		return (EM_NOMATCH);
	}

	if (uh->uh_patch_id <= uinfop->cui_rev && !ucode_force_update)
		return (EM_HIGHERREV);

	return (EM_OK);
}
#endif

/*
 * Returns 1 if the microcode is for this processor; 0 otherwise.
 */
static ucode_errno_t
ucode_match_intel(int cpi_sig, cpu_ucode_info_t *uinfop,
    ucode_header_intel_t *uhp, ucode_ext_table_intel_t *uetp)
{
	if (uhp == NULL)
		return (EM_NOMATCH);

	if (UCODE_MATCH_INTEL(cpi_sig, uhp->uh_signature,
	    uinfop->cui_platid, uhp->uh_proc_flags)) {

		if (uinfop->cui_rev >= uhp->uh_rev && !ucode_force_update)
			return (EM_HIGHERREV);

		return (EM_OK);
	}

	if (uetp != NULL) {
		int i;

		for (i = 0; i < uetp->uet_count; i++) {
			ucode_ext_sig_intel_t *uesp;

			uesp = &uetp->uet_ext_sig[i];

			if (UCODE_MATCH_INTEL(cpi_sig, uesp->ues_signature,
			    uinfop->cui_platid, uesp->ues_proc_flags)) {

				if (uinfop->cui_rev >= uhp->uh_rev &&
				    !ucode_force_update)
					return (EM_HIGHERREV);

				return (EM_OK);
			}
		}
	}

	return (EM_NOMATCH);
}

/*ARGSUSED*/
static int
ucode_write(xc_arg_t arg1, xc_arg_t unused2, xc_arg_t unused3)
{
	ucode_update_t *uusp = (ucode_update_t *)arg1;
	cpu_ucode_info_t *uinfop = CPU->cpu_m.mcpu_ucode_info;
#ifndef __xpv
	on_trap_data_t otd;
#endif

	ASSERT(ucode);
	ASSERT(uusp->ucodep);

#ifndef	__xpv
	/*
	 * Check one more time to see if it is really necessary to update
	 * microcode just in case this is a hyperthreaded processor where
	 * the threads share the same microcode.
	 */
	if (!ucode_force_update) {
		ucode->read_rev(uinfop);
		uusp->new_rev = uinfop->cui_rev;
		if (uinfop->cui_rev >= uusp->expected_rev)
			return (0);
	}

	if (!on_trap(&otd, OT_DATA_ACCESS))
		wrmsr(ucode->write_msr, (uintptr_t)uusp->ucodep);

	no_trap();
#endif
	ucode->read_rev(uinfop);
	uusp->new_rev = uinfop->cui_rev;

	return (0);
}

/*ARGSUSED*/
static uint32_t
ucode_load_amd(ucode_file_t *ufp, cpu_ucode_info_t *uinfop, cpu_t *cp)
{
	ucode_file_amd_t *ucodefp = ufp->amd;
#ifdef	__xpv
	ucode_update_t uus;
#else
	on_trap_data_t otd;
#endif

	ASSERT(ucode);
	ASSERT(ucodefp);

#ifndef	__xpv
	kpreempt_disable();
	if (on_trap(&otd, OT_DATA_ACCESS)) {
		no_trap();
		kpreempt_enable();
		return (0);
	}
	wrmsr(ucode->write_msr, (uintptr_t)ucodefp);
	no_trap();
	ucode->read_rev(uinfop);
	kpreempt_enable();

	return (ucodefp->uf_header.uh_patch_id);
#else
	uus.ucodep = ucodefp->ucodep;
	uus.usize = ucodefp->usize;
	ucode_load_xpv(&uus);
	ucode->read_rev(uinfop);
	uus.new_rev = uinfop->cui_rev;

	return (uus.new_rev);
#endif
}

/*ARGSUSED2*/
static uint32_t
ucode_load_intel(ucode_file_t *ufp, cpu_ucode_info_t *uinfop, cpu_t *cp)
{
	ucode_file_intel_t *ucodefp = &ufp->intel;
#ifdef __xpv
	uint32_t ext_offset;
	uint32_t body_size;
	uint32_t ext_size;
	uint8_t *ustart;
	uint32_t usize;
	ucode_update_t uus;
#endif

	ASSERT(ucode);

#ifdef __xpv
	/*
	 * the hypervisor wants the header, data, and extended
	 * signature tables. We can only get here from the boot
	 * CPU (cpu #0), we don't need to free as ucode_zalloc() will
	 * use BOP_ALLOC().
	 */
	usize = UCODE_TOTAL_SIZE_INTEL(ucodefp->uf_header->uh_total_size);
	ustart = ucode_zalloc(cp->cpu_id, usize);
	ASSERT(ustart);

	body_size = UCODE_BODY_SIZE_INTEL(ucodefp->uf_header->uh_body_size);
	ext_offset = body_size + UCODE_HEADER_SIZE_INTEL;
	ext_size = usize - ext_offset;
	ASSERT(ext_size >= 0);

	(void) memcpy(ustart, ucodefp->uf_header, UCODE_HEADER_SIZE_INTEL);
	(void) memcpy(&ustart[UCODE_HEADER_SIZE_INTEL], ucodefp->uf_body,
	    body_size);
	if (ext_size > 0) {
		(void) memcpy(&ustart[ext_offset],
		    ucodefp->uf_ext_table, ext_size);
	}
	uus.ucodep = ustart;
	uus.usize = usize;
	ucode_load_xpv(&uus);
	ucode->read_rev(uinfop);
	uus.new_rev = uinfop->cui_rev;
#else
	kpreempt_disable();
	wrmsr(ucode->write_msr, (uintptr_t)ucodefp->uf_body);
	ucode->read_rev(uinfop);
	kpreempt_enable();
#endif

	return (ucodefp->uf_header->uh_rev);
}


#ifdef	__xpv
static void
ucode_load_xpv(ucode_update_t *uusp)
{
	xen_platform_op_t op;
	int e;

	ASSERT(DOMAIN_IS_INITDOMAIN(xen_info));

	kpreempt_disable();
	op.cmd = XENPF_microcode_update;
	op.interface_version = XENPF_INTERFACE_VERSION;
	/*LINTED: constant in conditional context*/
	set_xen_guest_handle(op.u.microcode.data, uusp->ucodep);
	op.u.microcode.length = uusp->usize;
	e = HYPERVISOR_platform_op(&op);
	if (e != 0) {
		cmn_err(CE_WARN, "hypervisor failed to accept uCode update");
	}
	kpreempt_enable();
}
#endif /* __xpv */

static void
ucode_read_rev_amd(cpu_ucode_info_t *uinfop)
{
	uinfop->cui_rev = rdmsr(MSR_AMD_PATCHLEVEL);
}

static void
ucode_read_rev_intel(cpu_ucode_info_t *uinfop)
{
	struct cpuid_regs crs;

	/*
	 * The Intel 64 and IA-32 Architecture Software Developer's Manual
	 * recommends that MSR_INTC_UCODE_REV be loaded with 0 first, then
	 * execute cpuid to guarantee the correct reading of this register.
	 */
	wrmsr(MSR_INTC_UCODE_REV, 0);
	(void) __cpuid_insn(&crs);
	uinfop->cui_rev = (rdmsr(MSR_INTC_UCODE_REV) >> INTC_UCODE_REV_SHIFT);
}

static ucode_errno_t
ucode_extract_amd(ucode_update_t *uusp, uint8_t *ucodep, int size)
{
#ifndef __xpv
	uint32_t *ptr = (uint32_t *)ucodep;
	ucode_eqtbl_amd_t *eqtbl;
	ucode_file_amd_t *ufp;
	int count;
	int higher = 0;
	ucode_errno_t rc = EM_NOMATCH;
	uint16_t eq_sig;

	/* skip over magic number & equivalence table header */
	ptr += 2; size -= 8;

	count = *ptr++; size -= 4;
	for (eqtbl = (ucode_eqtbl_amd_t *)ptr;
	    eqtbl->ue_inst_cpu && eqtbl->ue_inst_cpu != uusp->sig;
	    eqtbl++)
		;

	eq_sig = eqtbl->ue_equiv_cpu;

	/* No equivalent CPU id found, assume outdated microcode file. */
	if (eq_sig == 0)
		return (EM_HIGHERREV);

	/* Use the first microcode patch that matches. */
	do {
		ptr += count >> 2; size -= count;

		if (!size)
			return (higher ? EM_HIGHERREV : EM_NOMATCH);

		ptr++; size -= 4;
		count = *ptr++; size -= 4;
		ufp = (ucode_file_amd_t *)ptr;

		rc = ucode_match_amd(eq_sig, &uusp->info, ufp, count);
		if (rc == EM_HIGHERREV)
			higher = 1;
	} while (rc != EM_OK);

	uusp->ucodep = (uint8_t *)ufp;
	uusp->usize = count;
	uusp->expected_rev = ufp->uf_header.uh_patch_id;
#else
	/*
	 * The hypervisor will choose the patch to load, so there is no way to
	 * know the "expected revision" in advance. This is especially true on
	 * mixed-revision systems where more than one patch will be loaded.
	 */
	uusp->expected_rev = 0;
	uusp->ucodep = ucodep;
	uusp->usize = size;

	ucode_chipset_amd(ucodep, size);
#endif

	return (EM_OK);
}

static ucode_errno_t
ucode_extract_intel(ucode_update_t *uusp, uint8_t *ucodep, int size)
{
	uint32_t	header_size = UCODE_HEADER_SIZE_INTEL;
	int		remaining;
	int		found = 0;
	ucode_errno_t	search_rc = EM_NOMATCH; /* search result */

	/*
	 * Go through the whole buffer in case there are
	 * multiple versions of matching microcode for this
	 * processor.
	 */
	for (remaining = size; remaining > 0; ) {
		int	total_size, body_size, ext_size;
		uint8_t	*curbuf = &ucodep[size - remaining];
		ucode_header_intel_t *uhp = (ucode_header_intel_t *)curbuf;
		ucode_ext_table_intel_t *uetp = NULL;
		ucode_errno_t tmprc;

		total_size = UCODE_TOTAL_SIZE_INTEL(uhp->uh_total_size);
		body_size = UCODE_BODY_SIZE_INTEL(uhp->uh_body_size);
		ext_size = total_size - (header_size + body_size);

		if (ext_size > 0)
			uetp = (ucode_ext_table_intel_t *)
			    &curbuf[header_size + body_size];

		tmprc = ucode_match_intel(uusp->sig, &uusp->info, uhp, uetp);

		/*
		 * Since we are searching through a big file
		 * containing microcode for pretty much all the
		 * processors, we are bound to get EM_NOMATCH
		 * at one point.  However, if we return
		 * EM_NOMATCH to users, it will really confuse
		 * them.  Therefore, if we ever find a match of
		 * a lower rev, we will set return code to
		 * EM_HIGHERREV.
		 */
		if (tmprc == EM_HIGHERREV)
			search_rc = EM_HIGHERREV;

		if (tmprc == EM_OK &&
		    uusp->expected_rev < uhp->uh_rev) {
#ifndef __xpv
			uusp->ucodep = (uint8_t *)&curbuf[header_size];
#else
			uusp->ucodep = (uint8_t *)curbuf;
#endif
			uusp->usize =
			    UCODE_TOTAL_SIZE_INTEL(uhp->uh_total_size);
			uusp->expected_rev = uhp->uh_rev;
			found = 1;
		}

		remaining -= total_size;
	}

	if (!found)
		return (search_rc);

	return (EM_OK);
}
/*
 * Entry point to microcode update from the ucode_drv driver.
 *
 * Returns EM_OK on success, corresponding error code on failure.
 */
ucode_errno_t
ucode_update(uint8_t *ucodep, int size)
{
	int		found = 0;
	processorid_t	id;
	ucode_update_t	cached = { 0 };
	ucode_update_t	*cachedp = NULL;
	ucode_errno_t	rc = EM_OK;
	ucode_errno_t	search_rc = EM_NOMATCH; /* search result */
	cpuset_t cpuset;

	ASSERT(ucode);
	ASSERT(ucodep);
	CPUSET_ZERO(cpuset);

	if (!ucode->capable(CPU))
		return (EM_NOTSUP);

	mutex_enter(&cpu_lock);

	for (id = 0; id < max_ncpus; id++) {
		cpu_t *cpu;
		ucode_update_t uus = { 0 };
		ucode_update_t *uusp = &uus;

		/*
		 * If there is no such CPU or it is not xcall ready, skip it.
		 */
		if ((cpu = cpu_get(id)) == NULL ||
		    !(cpu->cpu_flags & CPU_READY))
			continue;

		uusp->sig = cpuid_getsig(cpu);
		bcopy(cpu->cpu_m.mcpu_ucode_info, &uusp->info,
		    sizeof (uusp->info));

		/*
		 * If the current CPU has the same signature and platform
		 * id as the previous one we processed, reuse the information.
		 */
		if (cachedp && cachedp->sig == cpuid_getsig(cpu) &&
		    cachedp->info.cui_platid == uusp->info.cui_platid) {
			uusp->ucodep = cachedp->ucodep;
			uusp->expected_rev = cachedp->expected_rev;
			/*
			 * Intuitively we should check here to see whether the
			 * running microcode rev is >= the expected rev, and
			 * quit if it is.  But we choose to proceed with the
			 * xcall regardless of the running version so that
			 * the other threads in an HT processor can update
			 * the cpu_ucode_info structure in machcpu.
			 */
		} else if ((search_rc = ucode->extract(uusp, ucodep, size))
		    == EM_OK) {
			bcopy(uusp, &cached, sizeof (cached));
			cachedp = &cached;
			found = 1;
		}

		/* Nothing to do */
		if (uusp->ucodep == NULL)
			continue;

#ifdef	__xpv
		/*
		 * for i86xpv, the hypervisor will update all the CPUs.
		 * the hypervisor wants the header, data, and extended
		 * signature tables. ucode_write will just read in the
		 * updated version on all the CPUs after the update has
		 * completed.
		 */
		if (id == 0) {
			ucode_load_xpv(uusp);
		}
#endif

		CPUSET_ADD(cpuset, id);
		kpreempt_disable();
		xc_sync((xc_arg_t)uusp, 0, 0, CPUSET2BV(cpuset), ucode_write);
		kpreempt_enable();
		CPUSET_DEL(cpuset, id);

		if (uusp->new_rev != 0 && uusp->info.cui_rev == uusp->new_rev &&
		    !ucode_force_update) {
			rc = EM_HIGHERREV;
		} else if ((uusp->new_rev == 0) || (uusp->expected_rev != 0 &&
		    uusp->expected_rev != uusp->new_rev)) {
			cmn_err(CE_WARN, ucode_failure_fmt,
			    id, uusp->info.cui_rev, uusp->expected_rev);
			rc = EM_UPDATE;
		} else {
			cmn_err(CE_CONT, ucode_success_fmt,
			    id, uusp->info.cui_rev, uusp->new_rev);
		}
	}

	mutex_exit(&cpu_lock);

	if (!found)
		rc = search_rc;

	return (rc);
}

/*
 * Initialize mcpu_ucode_info, and perform microcode update if necessary.
 * This is the entry point from boot path where pointer to CPU structure
 * is available.
 *
 * cpuid_info must be initialized before ucode_check can be called.
 */
void
ucode_check(cpu_t *cp)
{
	cpu_ucode_info_t *uinfop;
	ucode_errno_t rc = EM_OK;
	uint32_t new_rev = 0;

	ASSERT(cp);
	/*
	 * Space statically allocated for BSP, ensure pointer is set
	 */
	if (cp->cpu_id == 0 && cp->cpu_m.mcpu_ucode_info == NULL)
		cp->cpu_m.mcpu_ucode_info = &cpu_ucode_info0;

	uinfop = cp->cpu_m.mcpu_ucode_info;
	ASSERT(uinfop);

	/* set up function pointers if not already done */
	if (!ucode)
		switch (cpuid_getvendor(cp)) {
		case X86_VENDOR_AMD:
			ucode = &ucode_amd;
			break;
		case X86_VENDOR_Intel:
			ucode = &ucode_intel;
			break;
		default:
			ucode = NULL;
			return;
		}

	if (!ucode->capable(cp))
		return;

	/*
	 * The MSR_INTC_PLATFORM_ID is supported in Celeron and Xeon
	 * (Family 6, model 5 and above) and all processors after.
	 */
	if ((cpuid_getvendor(cp) == X86_VENDOR_Intel) &&
	    ((cpuid_getmodel(cp) >= 5) || (cpuid_getfamily(cp) > 6))) {
		uinfop->cui_platid = 1 << ((rdmsr(MSR_INTC_PLATFORM_ID) >>
		    INTC_PLATFORM_ID_SHIFT) & INTC_PLATFORM_ID_MASK);
	}

	ucode->read_rev(uinfop);

#ifdef	__xpv
	/*
	 * for i86xpv, the hypervisor will update all the CPUs. We only need
	 * do do this on one of the CPUs (and there always is a CPU 0).
	 */
	if (cp->cpu_id != 0) {
		return;
	}
#endif

	/*
	 * Check to see if we need ucode update
	 */
	if ((rc = ucode->locate(cp, uinfop, &ucodefile)) == EM_OK) {
		new_rev = ucode->load(&ucodefile, uinfop, cp);

		if (uinfop->cui_rev != new_rev)
			cmn_err(CE_WARN, ucode_failure_fmt, cp->cpu_id,
			    uinfop->cui_rev, new_rev);
	}

	/*
	 * If we fail to find a match for any reason, free the file structure
	 * just in case we have read in a partial file.
	 *
	 * Since the scratch memory for holding the microcode for the boot CPU
	 * came from BOP_ALLOC, we will reset the data structure as if we
	 * never did the allocation so we don't have to keep track of this
	 * special chunk of memory.  We free the memory used for the rest
	 * of the CPUs in start_other_cpus().
	 */
	if (rc != EM_OK || cp->cpu_id == 0)
		ucode->file_reset(&ucodefile, cp->cpu_id);
}

/*
 * Returns microcode revision from the machcpu structure.
 */
ucode_errno_t
ucode_get_rev(uint32_t *revp)
{
	int i;

	ASSERT(ucode);
	ASSERT(revp);

	if (!ucode->capable(CPU))
		return (EM_NOTSUP);

	mutex_enter(&cpu_lock);
	for (i = 0; i < max_ncpus; i++) {
		cpu_t *cpu;

		if ((cpu = cpu_get(i)) == NULL)
			continue;

		revp[i] = cpu->cpu_m.mcpu_ucode_info->cui_rev;
	}
	mutex_exit(&cpu_lock);

	return (EM_OK);
}
