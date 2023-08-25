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
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/stdbool.h>
#include <sys/cmn_err.h>
#include <sys/controlregs.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/ontrap.h>
#include <sys/sysmacros.h>
#include <sys/ucode.h>
#include <sys/ucode_amd.h>
#include <ucode/ucode_errno.h>
#include <ucode/ucode_utils_amd.h>
#include <sys/x86_archext.h>

extern void *ucode_zalloc(processorid_t, size_t);
extern void ucode_free(processorid_t, void *, size_t);
extern const char *ucode_path(void);
extern int ucode_force_update;

static ucode_file_amd_t *amd_ucodef;
static ucode_eqtbl_amd_t *ucode_eqtbl_amd;
static uint_t ucode_eqtbl_amd_entries;

/*
 * Check whether this module can be used for microcode updates on this
 * platform.
 */
static bool
ucode_select_amd(cpu_t *cp)
{
	return (cpuid_getvendor(cp) == X86_VENDOR_AMD);
}

/*
 * Check whether or not a processor is capable of microcode operations
 *
 * At this point we only support microcode update for:
 * - AMD processors family 0x10 and above.
 */
static bool
ucode_capable_amd(cpu_t *cp)
{
	return (cpuid_getfamily(cp) >= 0x10);
}

/*
 * Called when it is no longer necessary to keep the microcode around,
 * or when the cached microcode doesn't match the CPU being processed.
 */
static void
ucode_file_reset_amd(processorid_t id)
{
	if (amd_ucodef == NULL)
		return;

	ucode_free(id, amd_ucodef, sizeof (*amd_ucodef));
	amd_ucodef = NULL;
}

/*
 * Find the equivalent CPU id in the equivalence table.
 */
static ucode_errno_t
ucode_equiv_cpu_amd(cpu_t *cp, uint16_t *eq_sig)
{
	char *name = NULL;
	int cpi_sig = cpuid_getsig(cp);
	ucode_errno_t ret = EM_OK;

	if (cp->cpu_id == 0 || ucode_eqtbl_amd == NULL) {
		name = ucode_zalloc(cp->cpu_id, MAXPATHLEN);
		if (name == NULL)
			return (EM_NOMEM);

		(void) snprintf(name, MAXPATHLEN, "%s/%s/%s",
		    ucode_path(), cpuid_getvendorstr(cp),
		    UCODE_AMD_EQUIVALENCE_TABLE_NAME);
	}

	if (cp->cpu_id == 0) {
		/*
		 * No kmem_zalloc() etc. available on boot cpu.
		 */
		ucode_eqtbl_amd_t eqtbl;
		int count, offset = 0;
		intptr_t fd;

		ASSERT(name != NULL);

		if ((fd = kobj_open(name)) == -1) {
			ret = EM_OPENFILE;
			goto out;
		}
		do {
			count = kobj_read(fd, (int8_t *)&eqtbl,
			    sizeof (eqtbl), offset);
			if (count != sizeof (eqtbl)) {
				(void) kobj_close(fd);
				ret = EM_HIGHERREV;
				goto out;
			}
			offset += count;
		} while (eqtbl.ue_inst_cpu != 0 &&
		    eqtbl.ue_inst_cpu != cpi_sig);
		(void) kobj_close(fd);
		*eq_sig = eqtbl.ue_equiv_cpu;
	} else {
		ucode_eqtbl_amd_t *eqtbl;

		/*
		 * If not already done, load the equivalence table.
		 * Not done on boot CPU.
		 */
		if (ucode_eqtbl_amd == NULL) {
			struct _buf *eq;
			uint64_t size;
			int count;

			ASSERT(name != NULL);

			if ((eq = kobj_open_file(name)) == (struct _buf *)-1) {
				ret = EM_OPENFILE;
				goto out;
			}

			if (kobj_get_filesize(eq, &size) < 0) {
				kobj_close_file(eq);
				ret = EM_OPENFILE;
				goto out;
			}

			if (size == 0 ||
			    size % sizeof (*ucode_eqtbl_amd) != 0) {
				kobj_close_file(eq);
				ret = EM_HIGHERREV;
				goto out;
			}

			ucode_eqtbl_amd = kmem_zalloc(size, KM_NOSLEEP);
			if (ucode_eqtbl_amd == NULL) {
				kobj_close_file(eq);
				ret = EM_NOMEM;
				goto out;
			}
			count = kobj_read_file(eq, (char *)ucode_eqtbl_amd,
			    size, 0);
			kobj_close_file(eq);

			if (count != size) {
				ucode_eqtbl_amd_entries = 0;
				ret = EM_FILESIZE;
				goto out;
			}

			ucode_eqtbl_amd_entries =
			    size / sizeof (*ucode_eqtbl_amd);
		}

		eqtbl = ucode_eqtbl_amd;
		*eq_sig = 0;
		for (uint_t i = 0; i < ucode_eqtbl_amd_entries; i++, eqtbl++) {
			if (eqtbl->ue_inst_cpu == 0) {
				/* End of table */
				ret = EM_HIGHERREV;
				goto out;
			}
			if (eqtbl->ue_inst_cpu == cpi_sig) {
				*eq_sig = eqtbl->ue_equiv_cpu;
				ret = EM_OK;
				goto out;
			}
		}
		/*
		 * No equivalent CPU id found, assume outdated microcode file.
		 */
		ret = EM_HIGHERREV;
	}

out:
	ucode_free(cp->cpu_id, name, MAXPATHLEN);

	return (ret);
}

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
	    ucodefp->uf_code_present) {
		return (EM_NOMATCH);
	}

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

/*
 * Populate the ucode file structure from microcode file corresponding to
 * this CPU, if exists.
 *
 * Return EM_OK on success, corresponding error code on failure.
 */
static ucode_errno_t
ucode_locate_amd(cpu_t *cp, cpu_ucode_info_t *uinfop)
{
	ucode_file_amd_t *ucodefp = amd_ucodef;
	uint16_t eq_sig;
	int rc;

	/* get equivalent CPU id */
	eq_sig = 0;
	if ((rc = ucode_equiv_cpu_amd(cp, &eq_sig)) != EM_OK)
		return (rc);

	/*
	 * Allocate a buffer for the microcode patch. If the buffer has been
	 * allocated before, check for a matching microcode to avoid loading
	 * the file again.
	 */

	if (ucodefp == NULL) {
		ucodefp = ucode_zalloc(cp->cpu_id, sizeof (*ucodefp));
	} else if (ucode_match_amd(eq_sig, uinfop, ucodefp, sizeof (*ucodefp))
	    == EM_OK) {
		return (EM_OK);
	}

	if (ucodefp == NULL)
		return (EM_NOMEM);

	amd_ucodef = ucodefp;

	/*
	 * Find the patch for this CPU. The patch files are named XXXX-YY, where
	 * XXXX is the equivalent CPU id and YY is the running patch number.
	 * Patches specific to certain chipsets are guaranteed to have lower
	 * numbers than less specific patches, so we can just load the first
	 * patch that matches.
	 */

	for (uint_t i = 0; i < 0xff; i++) {
		char name[MAXPATHLEN];
		intptr_t fd;
		int count;

		(void) snprintf(name, MAXPATHLEN, "%s/%s/%04X-%02X",
		    ucode_path(), cpuid_getvendorstr(cp), eq_sig, i);
		if ((fd = kobj_open(name)) == -1)
			return (EM_NOMATCH);
		count = kobj_read(fd, (char *)ucodefp, sizeof (*ucodefp), 0);
		(void) kobj_close(fd);

		if (ucode_match_amd(eq_sig, uinfop, ucodefp, count) == EM_OK)
			return (EM_OK);
	}
	return (EM_NOMATCH);
}

static void
ucode_read_rev_amd(cpu_ucode_info_t *uinfop)
{
	uinfop->cui_rev = rdmsr(MSR_AMD_PATCHLEVEL);
}

static uint32_t
ucode_load_amd(cpu_ucode_info_t *uinfop)
{
	ucode_file_amd_t *ucodefp = amd_ucodef;
	on_trap_data_t otd;

	VERIFY(ucodefp != NULL);

	kpreempt_disable();
	if (on_trap(&otd, OT_DATA_ACCESS)) {
		no_trap();
		goto out;
	}
	wrmsr(MSR_AMD_PATCHLOADER, (uintptr_t)ucodefp);
	no_trap();
	ucode_read_rev_amd(uinfop);

out:
	kpreempt_enable();
	return (ucodefp->uf_header.uh_patch_id);
}

static ucode_errno_t
ucode_extract_amd(ucode_update_t *uusp, uint8_t *ucodep, int size)
{
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

	return (EM_OK);
}

static const ucode_source_t ucode_amd = {
	.us_name	= "AMD microcode updater",
	.us_write_msr	= MSR_AMD_PATCHLOADER,
	.us_invalidate	= false,
	.us_select	= ucode_select_amd,
	.us_capable	= ucode_capable_amd,
	.us_file_reset	= ucode_file_reset_amd,
	.us_read_rev	= ucode_read_rev_amd,
	.us_load	= ucode_load_amd,
	.us_validate	= ucode_validate_amd,
	.us_extract	= ucode_extract_amd,
	.us_locate	= ucode_locate_amd
};
UCODE_SOURCE(ucode_amd);
