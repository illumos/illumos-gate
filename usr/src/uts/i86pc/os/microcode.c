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

#include <sys/asm_linkage.h>
#include <sys/bootconf.h>
#include <sys/cpuvar.h>
#include <sys/cmn_err.h>
#include <sys/controlregs.h>
#include <sys/debug.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/machsystm.h>
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
 * Microcode specific information per core
 */
struct cpu_ucode_info {
	uint32_t	cui_platid;	/* platform id */
	uint32_t	cui_rev;	/* microcode revision */
};

/*
 * Data structure used for xcall
 */
struct ucode_update_struct {
	uint32_t		sig;	/* signature */
	struct cpu_ucode_info	info;	/* ucode info */
	uint32_t		expected_rev;
	uint32_t		new_rev;
	uint8_t			*ucodep; /* pointer to ucode body */
};

/*
 * mcpu_ucode_info for the boot CPU.  Statically allocated.
 */
static struct cpu_ucode_info cpu_ucode_info0;

static ucode_file_t ucodefile = { 0 };

static int ucode_capable(cpu_t *);
static void ucode_file_reset(ucode_file_t *, processorid_t);
static ucode_errno_t ucode_match(int, struct cpu_ucode_info *,
    ucode_header_t *, ucode_ext_table_t *);
static ucode_errno_t ucode_locate(cpu_t *, struct cpu_ucode_info *,
    ucode_file_t *);
static void ucode_update_intel(uint8_t *, struct cpu_ucode_info *);
static void ucode_read_rev(struct cpu_ucode_info *);

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
	cp->cpu_m.mcpu_ucode_info =
	    kmem_zalloc(sizeof (*cp->cpu_m.mcpu_ucode_info), KM_SLEEP);
}

void
ucode_free_space(cpu_t *cp)
{
	ASSERT(cp->cpu_id != 0);
	kmem_free(cp->cpu_m.mcpu_ucode_info,
	    sizeof (*cp->cpu_m.mcpu_ucode_info));
}

/*
 * Called when we are done with microcode update on all processors to free up
 * space allocated for the microcode file.
 */
void
ucode_free()
{
	ucode_file_reset(&ucodefile, -1);
}

/*
 * Check whether or not a processor is capable of microcode operations
 * Returns 1 if it is capable, 0 if not.
 */
/*ARGSUSED*/
static int
ucode_capable(cpu_t *cp)
{
	/* i86xpv guest domain can't update microcode */
#ifdef	__xpv
	if (!DOMAIN_IS_INITDOMAIN(xen_info)) {
		return (0);
	}
#endif

#ifndef	__xpv
	/*
	 * At this point we only support microcode update for Intel
	 * processors family 6 and above.
	 *
	 * We also assume that we don't support a mix of Intel and
	 * AMD processors in the same box.
	 */
	if (cpuid_getvendor(cp) != X86_VENDOR_Intel ||
	    cpuid_getfamily(cp) < 6)
		return (0);
	else
		return (1);
#else
	/*
	 * XXPV - remove when microcode loading works in dom0. Don't support
	 * microcode loading in dom0 right now.
	 */
	return (0);
#endif
}

/*
 * Called when it is no longer necessary to keep the microcode around,
 * or when the cached microcode doesn't match the CPU being processed.
 */
static void
ucode_file_reset(ucode_file_t *ucodefp, processorid_t id)
{
	int total_size, body_size;

	if (ucodefp == NULL)
		return;

	total_size = UCODE_TOTAL_SIZE(ucodefp->uf_header.uh_total_size);
	body_size = UCODE_BODY_SIZE(ucodefp->uf_header.uh_body_size);
	if (ucodefp->uf_body) {
		/*
		 * Space for the boot CPU is allocated with BOP_ALLOC()
		 * and does not require a free.
		 */
		if (id != 0)
			kmem_free(ucodefp->uf_body, body_size);
		ucodefp->uf_body = NULL;
	}

	if (ucodefp->uf_ext_table) {
		int size = total_size - body_size - UCODE_HEADER_SIZE;
		/*
		 * Space for the boot CPU is allocated with BOP_ALLOC()
		 * and does not require a free.
		 */
		if (id != 0)
			kmem_free(ucodefp->uf_ext_table, size);
		ucodefp->uf_ext_table = NULL;
	}

	bzero(&ucodefp->uf_header, UCODE_HEADER_SIZE);
}

/*
 * Populate the ucode file structure from microcode file corresponding to
 * this CPU, if exists.
 *
 * Return EM_OK on success, corresponding error code on failure.
 */
static ucode_errno_t
ucode_locate(cpu_t *cp, struct cpu_ucode_info *uinfop, ucode_file_t *ucodefp)
{
	char		name[MAXPATHLEN];
	intptr_t	fd;
	int		count;
	int		header_size = UCODE_HEADER_SIZE;
	int		cpi_sig = cpuid_getsig(cp);
	ucode_errno_t	rc = EM_OK;

	/*
	 * If the microcode matches the CPU we are processing, use it.
	 */
	if (ucode_match(cpi_sig, uinfop, &ucodefp->uf_header,
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
	ucode_file_reset(ucodefp, cp->cpu_id);

	count = kobj_read(fd, (char *)&ucodefp->uf_header, header_size, 0);

	switch (count) {
	case UCODE_HEADER_SIZE: {

		ucode_header_t	*uhp = &ucodefp->uf_header;
		uint32_t	offset = header_size;
		int		total_size, body_size, ext_size;
		uint32_t	sum = 0;

		/*
		 * Make sure that the header contains valid fields.
		 */
		if ((rc = ucode_header_validate(uhp)) == EM_OK) {
			total_size = UCODE_TOTAL_SIZE(uhp->uh_total_size);
			body_size = UCODE_BODY_SIZE(uhp->uh_body_size);
			if (cp->cpu_id != 0) {
				if ((ucodefp->uf_body = kmem_zalloc(body_size,
				    KM_NOSLEEP)) == NULL) {
					rc = EM_NOMEM;
					break;
				}
			} else {
				/*
				 * BOP_ALLOC() failure results in panic so we
				 * don't have to check for NULL return.
				 */
				ucodefp->uf_body =
				    (uint8_t *)BOP_ALLOC(bootops,
				    NULL, body_size, MMU_PAGESIZE);
			}

			if (kobj_read(fd, (char *)ucodefp->uf_body,
			    body_size, offset) != body_size)
				rc = EM_FILESIZE;
		}

		if (rc)
			break;

		sum = ucode_checksum(0, header_size,
		    (uint8_t *)&ucodefp->uf_header);
		if (ucode_checksum(sum, body_size, ucodefp->uf_body)) {
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

		if (cp->cpu_id != 0) {
			if ((ucodefp->uf_ext_table = kmem_zalloc(ext_size,
			    KM_NOSLEEP)) == NULL) {
				rc = EM_NOMEM;
				break;
			}
		} else {
			/*
			 * BOP_ALLOC() failure results in panic so we
			 * don't have to check for NULL return.
			 */
			ucodefp->uf_ext_table =
			    (ucode_ext_table_t *)BOP_ALLOC(bootops, NULL,
			    ext_size, MMU_PAGESIZE);
		}

		if (kobj_read(fd, (char *)ucodefp->uf_ext_table,
		    ext_size, offset) != ext_size) {
			rc = EM_FILESIZE;
		} else if (ucode_checksum(0, ext_size,
		    (uint8_t *)(ucodefp->uf_ext_table))) {
			rc = EM_CHECKSUM;
		} else {
			int i;

			ext_size -= UCODE_EXT_TABLE_SIZE;
			for (i = 0; i < ucodefp->uf_ext_table->uet_count;
			    i++) {
				if (ucode_checksum(0, UCODE_EXT_SIG_SIZE,
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

	rc = ucode_match(cpi_sig, uinfop, &ucodefp->uf_header,
	    ucodefp->uf_ext_table);

	return (rc);
}


/*
 * Returns 1 if the microcode is for this processor; 0 otherwise.
 */
static ucode_errno_t
ucode_match(int cpi_sig, struct cpu_ucode_info *uinfop,
    ucode_header_t *uhp, ucode_ext_table_t *uetp)
{
	ASSERT(uhp);

	if (UCODE_MATCH(cpi_sig, uhp->uh_signature,
	    uinfop->cui_platid, uhp->uh_proc_flags)) {

		if (uinfop->cui_rev >= uhp->uh_rev && !ucode_force_update)
			return (EM_HIGHERREV);

		return (EM_OK);
	}

	if (uetp != NULL) {
		int i;

		for (i = 0; i < uetp->uet_count; i++) {
			ucode_ext_sig_t *uesp;

			uesp = &uetp->uet_ext_sig[i];

			if (UCODE_MATCH(cpi_sig, uesp->ues_signature,
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
	struct ucode_update_struct *uusp = (struct ucode_update_struct *)arg1;
	struct cpu_ucode_info *uinfop = CPU->cpu_m.mcpu_ucode_info;

	ASSERT(uusp->ucodep);

	/*
	 * Check one more time to see if it is really necessary to update
	 * microcode just in case this is a hyperthreaded processor where
	 * the threads share the same microcode.
	 */
	if (!ucode_force_update) {
		ucode_read_rev(uinfop);
		uusp->new_rev = uinfop->cui_rev;
		if (uinfop->cui_rev >= uusp->expected_rev)
			return (0);
	}

	wrmsr(MSR_INTC_UCODE_WRITE,
	    (uint64_t)(intptr_t)(uusp->ucodep));
	ucode_read_rev(uinfop);
	uusp->new_rev = uinfop->cui_rev;

	return (0);
}


static void
ucode_update_intel(uint8_t *ucode_body, struct cpu_ucode_info *uinfop)
{
	kpreempt_disable();
	wrmsr(MSR_INTC_UCODE_WRITE, (uint64_t)(uintptr_t)ucode_body);
	ucode_read_rev(uinfop);
	kpreempt_enable();
}

static void
ucode_read_rev(struct cpu_ucode_info *uinfop)
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

/*
 * Entry point to microcode update from the ucode_drv driver.
 *
 * Returns EM_OK on success, corresponding error code on failure.
 */
ucode_errno_t
ucode_update(uint8_t *ucodep, int size)
{
	uint32_t	header_size = UCODE_HEADER_SIZE;
	int		remaining;
	int		found = 0;
	processorid_t	id;
	struct ucode_update_struct cached = { 0 };
	struct ucode_update_struct *cachedp = NULL;
	ucode_errno_t	rc = EM_OK;
	ucode_errno_t	search_rc = EM_NOMATCH; /* search result */
	cpuset_t cpuset;

	ASSERT(ucodep);

	CPUSET_ZERO(cpuset);

	if (!ucode_capable(CPU))
		return (EM_NOTSUP);

	mutex_enter(&cpu_lock);

	for (id = 0; id < max_ncpus; id++) {
		cpu_t *cpu;
		struct ucode_update_struct uus = { 0 };
		struct ucode_update_struct *uusp = &uus;

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
		} else {
			/*
			 * Go through the whole buffer in case there are
			 * multiple versions of matching microcode for this
			 * processor.
			 */
			for (remaining = size; remaining > 0; ) {
				int	total_size, body_size, ext_size;
				uint8_t	*curbuf = &ucodep[size - remaining];
				ucode_header_t	*uhp = (ucode_header_t *)curbuf;
				ucode_ext_table_t *uetp = NULL;
				ucode_errno_t tmprc;

				total_size =
				    UCODE_TOTAL_SIZE(uhp->uh_total_size);
				body_size = UCODE_BODY_SIZE(uhp->uh_body_size);
				ext_size = total_size -
				    (header_size + body_size);

				if (ext_size > 0)
					uetp = (ucode_ext_table_t *)
					    &curbuf[header_size + body_size];

				tmprc = ucode_match(uusp->sig, &uusp->info,
				    uhp, uetp);

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
					uusp->ucodep = &curbuf[header_size];
					uusp->expected_rev = uhp->uh_rev;
					bcopy(uusp, &cached, sizeof (cached));
					cachedp = &cached;
					found = 1;
				}

				remaining -= total_size;
			}
		}

		/* Nothing to do */
		if (uusp->ucodep == NULL)
			continue;

		CPUSET_ADD(cpuset, id);
		kpreempt_disable();
		xc_sync((xc_arg_t)uusp, 0, 0, X_CALL_HIPRI, cpuset,
		    ucode_write);
		kpreempt_enable();
		CPUSET_DEL(cpuset, id);

		if (uusp->expected_rev == uusp->new_rev) {
			cmn_err(CE_CONT, ucode_success_fmt,
			    id, uusp->info.cui_rev, uusp->expected_rev);
		} else {
			cmn_err(CE_WARN, ucode_failure_fmt,
			    id, uusp->info.cui_rev, uusp->expected_rev);
			rc = EM_UPDATE;
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
	struct cpu_ucode_info *uinfop;
	ucode_errno_t rc = EM_OK;

	ASSERT(cp);
	if (cp->cpu_id == 0)
		cp->cpu_m.mcpu_ucode_info = &cpu_ucode_info0;

	uinfop = cp->cpu_m.mcpu_ucode_info;
	ASSERT(uinfop);

	if (!ucode_capable(cp))
		return;

	/*
	 * The MSR_INTC_PLATFORM_ID is supported in Celeron and Xeon
	 * (Family 6, model 5 and above) and all processors after.
	 */
	if ((cpuid_getmodel(cp) >= 5) || (cpuid_getfamily(cp) > 6)) {
		uinfop->cui_platid = 1 << ((rdmsr(MSR_INTC_PLATFORM_ID) >>
		    INTC_PLATFORM_ID_SHIFT) & INTC_PLATFORM_ID_MASK);
	}

	ucode_read_rev(uinfop);

	/*
	 * Check to see if we need ucode update
	 */
	if ((rc = ucode_locate(cp, uinfop, &ucodefile)) == EM_OK) {
		ucode_update_intel(ucodefile.uf_body, uinfop);

		if (uinfop->cui_rev != ucodefile.uf_header.uh_rev)
			cmn_err(CE_WARN, ucode_failure_fmt, cp->cpu_id,
			    uinfop->cui_rev, ucodefile.uf_header.uh_rev);
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
		ucode_file_reset(&ucodefile, cp->cpu_id);
}

/*
 * Returns microcode revision from the machcpu structure.
 */
ucode_errno_t
ucode_get_rev(uint32_t *revp)
{
	int i;

	ASSERT(revp);

	if (!ucode_capable(CPU))
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
