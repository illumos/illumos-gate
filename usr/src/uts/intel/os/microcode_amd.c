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
 * Copyright 2025 Oxide Computer Company
 */

#include <sys/stdbool.h>
#include <sys/cmn_err.h>
#include <sys/controlregs.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/machparam.h>
#include <sys/ontrap.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/ucode.h>
#include <sys/ucode_amd.h>
#include <ucode/ucode_errno.h>
#include <ucode/ucode_utils_amd.h>
#include <sys/x86_archext.h>

extern void *ucode_zalloc(size_t);
extern void ucode_free(void *, size_t);
extern const char *ucode_path(void);
extern int ucode_force_update;
extern bool ucode_use_kmem;

static ucode_file_amd_t *amd_ucodef;
static size_t amd_ucodef_len, amd_ucodef_buflen;
static ucode_eqtbl_amd_t *ucode_eqtbl_amd;
static uint_t ucode_eqtbl_amd_entries;
static bool ucode_amd_fallback = false;

/*
 * Check whether this module can be used for microcode updates on this
 * platform.
 */
static bool
ucode_select_amd(cpu_t *cp)
{
	if ((get_hwenv() & HW_VIRTUAL) != 0)
		return (false);

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
ucode_file_reset_amd(void)
{
	if (amd_ucodef == NULL)
		return;

	ucode_free(amd_ucodef, amd_ucodef_buflen);
	amd_ucodef = NULL;
	amd_ucodef_buflen = amd_ucodef_len = 0;
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

	if (ucode_eqtbl_amd == NULL) {
		name = ucode_zalloc(MAXPATHLEN);
		if (name == NULL)
			return (EM_NOMEM);

		(void) snprintf(name, MAXPATHLEN, "%s/%s/%s",
		    ucode_path(), cpuid_getvendorstr(cp),
		    UCODE_AMD_EQUIVALENCE_TABLE_NAME);
	}

	if (!ucode_use_kmem) {
		/*
		 * No kmem_zalloc() etc. available yet.
		 */
		ucode_eqtbl_amd_t eqtbl;
		int count, offset = 0;
		intptr_t fd;

		ASSERT3P(name, !=, NULL);

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
		 */
		if (ucode_eqtbl_amd == NULL) {
			struct _buf *eq;
			uint64_t size;
			int count;

			ASSERT3P(name, !=, NULL);

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
	ucode_free(name, MAXPATHLEN);

	return (ret);
}

static ucode_errno_t
ucode_match_amd(uint16_t eq_sig, cpu_ucode_info_t *uinfop,
    ucode_file_amd_t *ucodefp, size_t size)
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
 * Copy the given ucode into cpu_ucode_info_t in preparation for loading onto
 * the corresponding CPU via ucode_load_amd().
 */
static ucode_errno_t
ucode_copy_amd(cpu_ucode_info_t *uinfop, const ucode_file_amd_t *ucodefp,
    size_t size)
{
	ASSERT3P(uinfop->cui_pending_ucode, ==, NULL);
	ASSERT3U(size, <=, UCODE_AMD_MAXSIZE);

	uinfop->cui_pending_ucode = ucode_zalloc(size);
	if (uinfop->cui_pending_ucode == NULL)
		return (EM_NOMEM);

	(void) memcpy(uinfop->cui_pending_ucode, ucodefp, size);
	uinfop->cui_pending_size = size;
	uinfop->cui_pending_rev = ucodefp->uf_header.uh_patch_id;

	return (EM_OK);
}

/*
 * Populate the ucode file structure from the microcode file corresponding to
 * this CPU, if exists.
 *
 * Return EM_OK on success, corresponding error code on failure.
 */
static ucode_errno_t
i_ucode_locate_amd(cpu_t *cp, cpu_ucode_info_t *uinfop, bool fallback)
{
	uint16_t eq_sig;
	ucode_errno_t rc;

	/* get equivalent CPU id */
	eq_sig = 0;
	if ((rc = ucode_equiv_cpu_amd(cp, &eq_sig)) != EM_OK)
		return (rc);

	/*
	 * Allocate a buffer for the microcode patch. If the buffer has been
	 * allocated before, check for a matching microcode to avoid loading
	 * the file again.
	 */
	if (amd_ucodef == NULL) {
		size_t len = PAGESIZE;

		amd_ucodef = ucode_zalloc(len);
		if (amd_ucodef == NULL)
			return (EM_NOMEM);
		amd_ucodef_buflen = len;
	} else {
		rc = ucode_match_amd(eq_sig, uinfop, amd_ucodef,
		    amd_ucodef_len);
		if (rc == EM_HIGHERREV)
			return (rc);
		if (rc == EM_OK) {
			return (ucode_copy_amd(uinfop, amd_ucodef,
			    amd_ucodef_len));
		}
	}

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
		/* This is a uint_t to match the signature of kobj_read() */
		uint_t size;

		(void) snprintf(name, MAXPATHLEN, "%s/%s/%s%04X-%02X",
		    ucode_path(), cpuid_getvendorstr(cp),
		    fallback ? "fallback/" : "", eq_sig, i);

		if ((fd = kobj_open(name)) == -1)
			return (EM_NOMATCH);

		/*
		 * Since this code will run for the boot CPU before kmem is
		 * initialised we can't use the kobj_*_file() functions.
		 * In the case where the archive contains compressed files,
		 * kobj_fstat() will return the compressed size and so we must
		 * read the entire file through to determine its size.
		 */
		size = 0;
		do {
			count = kobj_read(fd, (char *)amd_ucodef,
			    amd_ucodef_buflen, size);
			if (count < 0) {
				(void) kobj_close(fd);
				return (EM_OPENFILE);
			}
			size += count;
		} while (count == amd_ucodef_buflen &&
		    size <= UCODE_AMD_MAXSIZE);

		if (size > UCODE_AMD_MAXSIZE) {
			(void) kobj_close(fd);
			cmn_err(CE_WARN, "ucode: microcode file %s is "
			    "too large (over 0x%x bytes)", name,
			    UCODE_AMD_MAXSIZE);
			return (EM_FILESIZE);
		}

		if (size > amd_ucodef_buflen) {
			size_t len = P2ROUNDUP(size, PAGESIZE);

			ucode_file_reset_amd();
			amd_ucodef = ucode_zalloc(len);
			if (amd_ucodef == NULL) {
				(void) kobj_close(fd);
				return (EM_NOMEM);
			}
			amd_ucodef_buflen = len;
		}

		count = kobj_read(fd, (char *)amd_ucodef, amd_ucodef_buflen, 0);
		(void) kobj_close(fd);
		if (count < 0 || count != size)
			return (EM_OPENFILE);

		amd_ucodef_len = count;

		rc = ucode_match_amd(eq_sig, uinfop, amd_ucodef,
		    amd_ucodef_len);
		if (rc == EM_HIGHERREV)
			return (rc);
		if (rc == EM_OK) {
			return (ucode_copy_amd(uinfop, amd_ucodef,
			    amd_ucodef_len));
		}
	}
	return (EM_NOMATCH);
}

ucode_errno_t
ucode_locate_amd(cpu_t *cp, cpu_ucode_info_t *uinfop)
{
	return (i_ucode_locate_amd(cp, uinfop, ucode_amd_fallback));
}

ucode_errno_t
ucode_locate_fallback_amd(cpu_t *cp, cpu_ucode_info_t *uinfop)
{
	/* Once we have switched to the fallback microcode, stick with it */
	ucode_amd_fallback = true;
	return (i_ucode_locate_amd(cp, uinfop, ucode_amd_fallback));
}

static void
ucode_read_rev_amd(cpu_ucode_info_t *uinfop)
{
	uinfop->cui_rev = rdmsr(MSR_AMD_PATCHLEVEL);
}

static void
ucode_load_amd(cpu_ucode_info_t *uinfop)
{
	ucode_file_amd_t *ucodefp = uinfop->cui_pending_ucode;
	on_trap_data_t otd;

	VERIFY3P(ucodefp, !=, NULL);
	VERIFY3U(ucodefp->uf_header.uh_patch_id, ==, uinfop->cui_pending_rev);

	kpreempt_disable();
	if (on_trap(&otd, OT_DATA_ACCESS)) {
		no_trap();
		goto out;
	}
	wrmsr(MSR_AMD_PATCHLOADER, (uintptr_t)ucodefp);
	no_trap();

out:
	kpreempt_enable();
}

static ucode_errno_t
ucode_extract_amd(ucode_update_t *uusp, uint8_t *ucodep, size_t size)
{
	uint32_t *ptr = (uint32_t *)ucodep;
	ucode_eqtbl_amd_t *eqtbl;
	ucode_file_amd_t *ufp;
	uint32_t count;
	bool higher = false;
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

		if (size == 0)
			return (higher ? EM_HIGHERREV : EM_NOMATCH);

		ptr++; size -= 4;
		count = *ptr++; size -= 4;
		ufp = (ucode_file_amd_t *)ptr;

		rc = ucode_match_amd(eq_sig, &uusp->info, ufp, count);
		if (rc == EM_HIGHERREV)
			higher = true;
	} while (rc != EM_OK);

	uusp->ucodep = (uint8_t *)ufp;
	uusp->usize = count;
	uusp->expected_rev = ufp->uf_header.uh_patch_id;

	return (EM_OK);
}

static const ucode_source_t ucode_amd = {
	.us_name		= "AMD microcode updater",
	.us_write_msr		= MSR_AMD_PATCHLOADER,
	.us_invalidate		= false,
	.us_select		= ucode_select_amd,
	.us_capable		= ucode_capable_amd,
	.us_file_reset		= ucode_file_reset_amd,
	.us_read_rev		= ucode_read_rev_amd,
	.us_load		= ucode_load_amd,
	.us_validate		= ucode_validate_amd,
	.us_extract		= ucode_extract_amd,
	.us_locate		= ucode_locate_amd,
	.us_locate_fallback	= ucode_locate_fallback_amd
};
UCODE_SOURCE(ucode_amd);
