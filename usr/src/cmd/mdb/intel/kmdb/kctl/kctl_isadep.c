/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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
kctl_ddi_prop_read(kmdb_auxv_nv_t *nv, char *pname, void *arg)
{
	dev_info_t *dip = arg;
	char *val;

	if (strlen(pname) >= sizeof (nv->kanv_name)) {
		cmn_err(CE_WARN, "ignoring boot property %s: name too long\n",
		    pname);
		return (0);
	}

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, pname, &val) != DDI_SUCCESS)
		return (NULL);

	if (strlen(val) >= sizeof (nv->kanv_val)) {
		cmn_err(CE_WARN, "ignoring boot property %s: value too long\n",
		    pname);
		return (0);
	}

	strcpy(nv->kanv_name, pname);
	strcpy(nv->kanv_val, val);

	ddi_prop_free(val);

	return (1);
}

/*ARGSUSED*/
static int
cons_type(void)
{
	static int cons_type = -1;
	char cons_str[10];
	int len;
	struct bootops *ops = kctl.kctl_boot_ops;

	if (cons_type != -1)
		return (cons_type);
	cons_type = 0;	/* default to screen */

	len = BOP_GETPROPLEN(ops, "console");
	if (len > 0 || len <= 10) {
		(void) BOP_GETPROP(ops, "console", (void *)cons_str);
		if (strncmp(cons_str, "ttya", 4) == 0)
			cons_type = 1;
		else if (strncmp(cons_str, "ttyb", 4) == 0)
			cons_type = 2;
	}

	return (cons_type);
}

/*
 * fake prom properties, assuming the properties being read are
 * input-device, output-device, ttya-mode, ttyb-mode.
 */
/*ARGSUSED*/
static int
kctl_boot_prop_read(kmdb_auxv_nv_t *nv, char *pname, void *arg)
{
	if (strcmp(pname, "ttya-mode") == 0 ||
	    strcmp(pname, "ttyb-mode") == 0) {
		(void) strcpy(nv->kanv_val, "9600,8,n,1,-");
		return (0);
	}

	if (strcmp(pname, "input-device") != 0 &&
	    strcmp(pname, "output-device") != 0)
		return (0);

	strcpy(nv->kanv_name, pname);
	switch (cons_type()) {
	case 0:
		if (strcmp(pname, "input-device") == 0)
			(void) strcpy(nv->kanv_val, "keyboard");
		else
			(void) strcpy(nv->kanv_val, "screen");
		break;
	case 1:
		(void) strcpy(nv->kanv_val, "ttya");
		break;
	case 2:
		(void) strcpy(nv->kanv_val, "ttyb");
		break;
	}

	return (1);
}

static int
kctl_props_get(char *pname, kmdb_auxv_nv_t *valnv,
    kmdb_auxv_nv_t *modenv, int (*preader)(kmdb_auxv_nv_t *, char *, void *),
    void *arg)
{
#ifdef __amd64
	/*
	 * The current implementation of the amd64 shim layer doesn't support
	 * the use of the BOP_* calls with stack-allocated buffers.
	 */
	static
#endif
	char modepname[25];

	if (!preader(valnv, pname, arg))
		return (0);

	if (*valnv->kanv_val == '/')
		return (1);

	snprintf(modepname, sizeof (modepname), "%s-mode", valnv->kanv_val);

	return (preader(modenv, modepname, arg) ? 2 : 1);
}

/*
 * We don't have any property-walking routines, so we have to specifically
 * query and thus have guilty knowledge of the properties that the
 * debugger wants to see.
 */
#define	KCTL_PROPNV_NENT		4

static kmdb_auxv_nv_t *
kctl_pcache_create(int *nprops)
{
	int (*preader)(kmdb_auxv_nv_t *, char *, void *);
	kmdb_auxv_nv_t *pnv;
	size_t psz = sizeof (kmdb_auxv_nv_t) * KCTL_PROPNV_NENT;
	void *arg;
	int np = 0;

	if (kctl.kctl_boot_loaded) {
		preader = kctl_boot_prop_read;
		arg = NULL;
	} else {
		preader = kctl_ddi_prop_read;
		arg = ddi_find_devinfo("options", -1, 0);
	}

	pnv = kobj_alloc(psz, KM_WAIT);

	np += kctl_props_get("input-device", &pnv[np], &pnv[np + 1], preader,
	    arg);
	np += kctl_props_get("output-device", &pnv[np], &pnv[np + 1], preader,
	    arg);

	*nprops = np;
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
	cpu_t *cpu = kobj_zalloc(sizeof (cpu_t), KM_TMP);
	cpu_t *old;

	(void) rdmsr(MSR_AMD_GSBASE, (uint64_t *)&old);
	wrmsr(MSR_AMD_GSBASE, (uint64_t *)&cpu);

	return (old);
}

void
kctl_boot_tmpfini(void *old)
{
	wrmsr(MSR_AMD_GSBASE, (uint64_t *)&old);
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
