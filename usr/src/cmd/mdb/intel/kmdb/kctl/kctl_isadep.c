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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <kmdb/kmdb_auxv.h>
#include <kmdb/kctl/kctl.h>

#include <sys/bootconf.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/cpuvar.h>
#include <sys/kdi_impl.h>
#include <sys/x86_archext.h>
#include <sys/controlregs.h>
#include <sys/archsystm.h>

#if defined(__i386)
/* Copied from stand/i386/sys/bootdef.h */
#define	GS_GDT		0x38	/* dummy cpu_t pointer descriptor	*/
#endif

static int
kctl_boot_prop_read(char *pname, char *prop_buf, int buf_len)
{
	int len;
	struct bootops *ops = kctl.kctl_boot_ops;

	len = BOP_GETPROPLEN(ops, pname);
	if (len > 0 && len <= buf_len) {
		(void) BOP_GETPROP(ops, pname, (void *)prop_buf);
		return (1);
	}

	return (0);
}

static int
kctl_ddi_prop_read(char *pname, char *prop_buf, int buf_len)
{
	dev_info_t *dip = ddi_root_node();
	char *val;
	int ret = 0;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, pname, &val) != DDI_SUCCESS)
		return (0);

	if (strlen(val) < buf_len) {
		(void) strcpy(prop_buf, val);
		ret = 1;
	}

	ddi_prop_free(val);
	return (ret);
}

/*
 * We don't have any property-walking routines, so we have to specifically
 * query and thus have guilty knowledge of the properties that the
 * debugger wants to see.
 *
 * Here actually we only support four console properties:
 *     input-device, output-device, ttya-mode, ttyb-mode.
 */
#define	KCTL_PROPNV_NENT		4

static kmdb_auxv_nv_t *
kctl_pcache_create(int *nprops)
{
	int (*preader)(char *, char *, int);
	kmdb_auxv_nv_t *pnv;
	size_t psz = sizeof (kmdb_auxv_nv_t) * KCTL_PROPNV_NENT;

	if (kctl.kctl_boot_loaded) {
		preader = kctl_boot_prop_read;
	} else {
		preader = kctl_ddi_prop_read;
	}

	pnv = kobj_alloc(psz, KM_WAIT);

	(void) strcpy((&pnv[0])->kanv_name, "input-device");
	(void) strcpy((&pnv[1])->kanv_name, "output-device");
	(void) strcpy((&pnv[2])->kanv_name, "ttya-mode");
	(void) strcpy((&pnv[3])->kanv_name, "ttyb-mode");

	/*
	 * console is defined by "console" property, with
	 * fallback on the old "input-device" property.
	 */
	(void) strcpy((&pnv[0])->kanv_val, "text");	/* default to screen */
	if (!preader("console", (&pnv[0])->kanv_val,
	    sizeof ((&pnv[0])->kanv_val)))
		(void) preader("input-device", (&pnv[0])->kanv_val,
		    sizeof ((&pnv[0])->kanv_val));

	if (strcmp((&pnv[0])->kanv_val, "ttya") == 0 ||
	    strcmp((&pnv[0])->kanv_val, "ttyb") == 0) {
		(void) strcpy((&pnv[1])->kanv_val, (&pnv[0])->kanv_val);
	} else {
		(void) strcpy((&pnv[0])->kanv_val, "keyboard");
		(void) strcpy((&pnv[1])->kanv_val, "screen");
	}

	if (!preader((&pnv[2])->kanv_name, (&pnv[2])->kanv_val,
	    sizeof ((&pnv[2])->kanv_val)))
		(void) strcpy((&pnv[2])->kanv_val, "9600,8,n,1,-");

	if (!preader((&pnv[3])->kanv_name, (&pnv[3])->kanv_val,
	    sizeof ((&pnv[3])->kanv_val)))
		(void) strcpy((&pnv[3])->kanv_val, "9600,8,n,1,-");

	*nprops = KCTL_PROPNV_NENT;
	return (pnv);
}

static void
kctl_pcache_destroy(kmdb_auxv_nv_t *pnv)
{
	kobj_free(pnv, sizeof (kmdb_auxv_nv_t) * KCTL_PROPNV_NENT);
}

/*ARGSUSED*/
static void
kctl_cpu_init(void)
{
}

void
kctl_auxv_init_isadep(kmdb_auxv_t *kav, void *romp)
{
	kav->kav_pcache = kctl_pcache_create(&kav->kav_nprops);
	kav->kav_romp = romp;
}

void
kctl_auxv_fini_isadep(kmdb_auxv_t *kav)
{
	if (kav->kav_pcache != NULL)
		kctl_pcache_destroy(kav->kav_pcache);
}

int
kctl_preactivate_isadep(void)
{
	return (0);
}

/*ARGSUSED*/
int
kctl_activate_isadep(kdi_debugvec_t *dvec)
{
	dvec->dv_kctl_cpu_init = kctl_cpu_init;
	dvec->dv_kctl_vmready = hat_kdi_init;

	if (!kctl.kctl_boot_loaded)
		hat_kdi_init();

	return (0);
}

void
kctl_depreactivate_isadep(void)
{
}

void
kctl_deactivate_isadep(void)
{
	hat_kdi_fini();
}

#if defined(__amd64)
void *
kctl_boot_tmpinit(void)
{
	/*
	 * Many common kernel functions assume that GSBASE has been initialized,
	 * and fail horribly if it hasn't.  We'll install a pointer to a dummy
	 * cpu_t for use during our initialization.
	 */
	cpu_t *old = (cpu_t *)rdmsr(MSR_AMD_GSBASE);

	wrmsr(MSR_AMD_GSBASE, (uint64_t)kobj_zalloc(sizeof (cpu_t), KM_TMP));
	return (old);
}

void
kctl_boot_tmpfini(void *old)
{
	wrmsr(MSR_AMD_GSBASE, (uint64_t)old);
}

#else

void *
kctl_boot_tmpinit(void)
{
	/*
	 * Many common kernel functions assume that %gs has been initialized,
	 * and fail horribly if it hasn't.  Boot has reserved a descriptor for
	 * us (GS_GDT) in its GDT, a descriptor which we'll use to describe our
	 * dummy cpu_t.  We then set %gs to refer to this descriptor.
	 */
	cpu_t *cpu = kobj_zalloc(sizeof (cpu_t), KM_TMP);
	uintptr_t old;
	desctbr_t bgdt;
	user_desc_t *gsdesc;

	rd_gdtr(&bgdt);
	gsdesc = (user_desc_t *)(bgdt.dtr_base + GS_GDT);

	USEGD_SETBASE(gsdesc, (uintptr_t)cpu);
	USEGD_SETLIMIT(gsdesc, sizeof (cpu_t));

	old = getgs();
	setgs(GS_GDT);

	return ((void *)old);
}

void
kctl_boot_tmpfini(void *old)
{
	setgs((uintptr_t)old);
}
#endif
