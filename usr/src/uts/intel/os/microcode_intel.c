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
#include <sys/ontrap.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/ucode.h>
#include <sys/ucode_intel.h>
#include <ucode/ucode_errno.h>
#include <ucode/ucode_utils_intel.h>
#include <sys/x86_archext.h>

extern void *ucode_zalloc(size_t);
extern void ucode_free(void *, size_t);
extern const char *ucode_path(void);
extern int ucode_force_update;

static ucode_file_intel_t intel_ucodef;

/*
 * Check whether this module can be used for microcode updates on this
 * platform.
 */
static bool
ucode_select_intel(cpu_t *cp)
{
	if ((get_hwenv() & HW_VIRTUAL) != 0)
		return (false);

	return (cpuid_getvendor(cp) == X86_VENDOR_Intel);
}

/*
 * Check whether or not a processor is capable of microcode operations
 *
 * At this point we only support microcode update for:
 * - Intel processors family 6 and above.
 */
static bool
ucode_capable_intel(cpu_t *cp)
{
	return (cpuid_getfamily(cp) >= 6);
}

static void
ucode_file_reset_intel(void)
{
	ucode_file_intel_t *ucodefp = &intel_ucodef;
	int total_size, body_size;

	if (ucodefp->uf_header == NULL)
		return;

	total_size = UCODE_TOTAL_SIZE_INTEL(ucodefp->uf_header->uh_total_size);
	body_size = UCODE_BODY_SIZE_INTEL(ucodefp->uf_header->uh_body_size);

	if (ucodefp->uf_body != NULL) {
		ucode_free(ucodefp->uf_body, body_size);
		ucodefp->uf_body = NULL;
	}

	if (ucodefp->uf_ext_table != NULL) {
		int size = total_size - body_size - UCODE_HEADER_SIZE_INTEL;

		ucode_free(ucodefp->uf_ext_table, size);
		ucodefp->uf_ext_table = NULL;
	}

	ucode_free(ucodefp->uf_header, UCODE_HEADER_SIZE_INTEL);
	ucodefp->uf_header = NULL;
}

/*
 * Checks if the microcode is for this processor.
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
		for (uint_t i = 0; i < uetp->uet_count; i++) {
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

/*
 * Copy the given ucode into cpu_ucode_info_t in preparation for loading onto
 * the corresponding CPU via ucode_load_intel().
 */
static ucode_errno_t
ucode_copy_intel(const ucode_file_intel_t *ucodefp, cpu_ucode_info_t *uinfop)
{
	ASSERT3P(ucodefp->uf_header, !=, NULL);
	ASSERT3P(ucodefp->uf_body, !=, NULL);
	ASSERT3P(uinfop->cui_pending_ucode, ==, NULL);

	/*
	 * Allocate memory for the pending microcode update and copy the body.
	 * We don't need the header or extended signature table which are only
	 * used for matching.
	 */
	size_t sz = UCODE_BODY_SIZE_INTEL(ucodefp->uf_header->uh_body_size);
	uinfop->cui_pending_ucode = ucode_zalloc(sz);
	if (uinfop->cui_pending_ucode == NULL)
		return (EM_NOMEM);
	memcpy(uinfop->cui_pending_ucode, ucodefp->uf_body, sz);

	uinfop->cui_pending_size = sz;
	uinfop->cui_pending_rev = ucodefp->uf_header->uh_rev;

	return (EM_OK);
}

static ucode_errno_t
ucode_locate_intel(cpu_t *cp, cpu_ucode_info_t *uinfop)
{
	char		name[MAXPATHLEN];
	intptr_t	fd;
	int		count;
	int		header_size = UCODE_HEADER_SIZE_INTEL;
	int		cpi_sig = cpuid_getsig(cp);
	ucode_errno_t	rc = EM_OK;
	ucode_file_intel_t *ucodefp = &intel_ucodef;

	/*
	 * If the cached microcode matches the CPU we are processing, use it.
	 */
	if (ucode_match_intel(cpi_sig, uinfop, ucodefp->uf_header,
	    ucodefp->uf_ext_table) == EM_OK && ucodefp->uf_body != NULL) {
		return (ucode_copy_intel(ucodefp, uinfop));
	}

	/*
	 * Look for microcode file with the right name.
	 */
	(void) snprintf(name, MAXPATHLEN, "%s/%s/%08X-%02X",
	    ucode_path(), cpuid_getvendorstr(cp), cpi_sig,
	    uinfop->cui_platid);
	if ((fd = kobj_open(name)) == -1) {
		return (EM_OPENFILE);
	}

	/*
	 * We found a microcode file for the CPU we are processing,
	 * reset the microcode data structure and read in the new
	 * file.
	 */
	ucode_file_reset_intel();

	ucodefp->uf_header = ucode_zalloc(header_size);
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
			ucodefp->uf_body = ucode_zalloc(body_size);
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

		ucodefp->uf_ext_table = ucode_zalloc(ext_size);
		if (ucodefp->uf_ext_table == NULL) {
			rc = EM_NOMEM;
			break;
		}

		if (kobj_read(fd, (char *)ucodefp->uf_ext_table,
		    ext_size, offset) != ext_size) {
			rc = EM_FILESIZE;
		} else if (ucode_checksum_intel(0, ext_size,
		    (uint8_t *)(ucodefp->uf_ext_table))) {
			rc = EM_EXTCHECKSUM;
		} else {
			int i;

			for (i = 0; i < ucodefp->uf_ext_table->uet_count; i++) {
				ucode_ext_sig_intel_t *sig;

				sig = &ucodefp->uf_ext_table->uet_ext_sig[i];

				if (ucode_checksum_intel_extsig(uhp,
				    sig) != 0) {
					rc = EM_SIGCHECKSUM;
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
	if (rc == EM_OK) {
		return (ucode_copy_intel(ucodefp, uinfop));
	}

	return (rc);
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

	/*
	 * The MSR_INTC_PLATFORM_ID is supported in Celeron and Xeon
	 * (Family 6, model 5 and above) and all processors after.
	 */
	if ((cpuid_getmodel(CPU) >= 5 || cpuid_getfamily(CPU) > 6)) {
		uinfop->cui_platid = 1 << ((rdmsr(MSR_INTC_PLATFORM_ID) >>
		    INTC_PLATFORM_ID_SHIFT) & INTC_PLATFORM_ID_MASK);
	}
}

static void
ucode_load_intel(cpu_ucode_info_t *uinfop)
{
	VERIFY3P(uinfop->cui_pending_ucode, !=, NULL);

	kpreempt_disable();
	/*
	 * On some platforms a cache invalidation is required for the
	 * ucode update to be successful due to the parts of the
	 * processor that the microcode is updating.
	 */
	invalidate_cache();
	wrmsr(MSR_INTC_UCODE_WRITE, (uintptr_t)uinfop->cui_pending_ucode);
	kpreempt_enable();
}

static ucode_errno_t
ucode_extract_intel(ucode_update_t *uusp, uint8_t *ucodep, size_t size)
{
	uint32_t	header_size = UCODE_HEADER_SIZE_INTEL;
	size_t		remaining;
	bool		found = false;
	ucode_errno_t	search_rc = EM_NOMATCH; /* search result */

	/*
	 * Go through the whole buffer in case there are
	 * multiple versions of matching microcode for this
	 * processor.
	 */
	for (remaining = size; remaining > 0; ) {
		uint32_t total_size, body_size, ext_size;
		uint8_t *curbuf = &ucodep[size - remaining];
		ucode_header_intel_t *uhp = (ucode_header_intel_t *)curbuf;
		ucode_ext_table_intel_t *uetp = NULL;
		ucode_errno_t tmprc;

		total_size = UCODE_TOTAL_SIZE_INTEL(uhp->uh_total_size);
		body_size = UCODE_BODY_SIZE_INTEL(uhp->uh_body_size);
		ext_size = total_size - (header_size + body_size);

		if (ext_size > 0) {
			uetp = (ucode_ext_table_intel_t *)
			    &curbuf[header_size + body_size];
		}

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
			uusp->ucodep = (uint8_t *)&curbuf[header_size];
			uusp->usize =
			    UCODE_TOTAL_SIZE_INTEL(uhp->uh_total_size);
			uusp->expected_rev = uhp->uh_rev;
			found = true;
		}

		remaining -= total_size;
	}

	if (!found)
		return (search_rc);

	return (EM_OK);
}

static const ucode_source_t ucode_intel = {
	.us_name	= "Intel microcode updater",
	.us_write_msr	= MSR_INTC_UCODE_WRITE,
	.us_invalidate	= true,
	.us_select	= ucode_select_intel,
	.us_capable	= ucode_capable_intel,
	.us_file_reset	= ucode_file_reset_intel,
	.us_read_rev	= ucode_read_rev_intel,
	.us_load	= ucode_load_intel,
	.us_validate	= ucode_validate_intel,
	.us_extract	= ucode_extract_intel,
	.us_locate	= ucode_locate_intel
};
UCODE_SOURCE(ucode_intel);
