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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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

static int
kctl_boot_prop_read(char *pname, char *prop_buf, int buf_len)
{
	struct bootops *ops = kctl.kctl_boot_ops;
	int len;

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
void
kctl_activate_isadep(kdi_debugvec_t *dvec)
{
	dvec->dv_kctl_vmready = hat_kdi_init;

	if (!kctl.kctl_boot_loaded)
		hat_kdi_init();
}

void
kctl_depreactivate_isadep(void)
{
}

/*
 * Many common kernel functions assume that %gs can be deferenced, and
 * fail horribly if it cannot.  Ask the kernel to set up a temporary
 * mapping to a fake cpu_t so that we can call such functions during
 * initialization.
 */
void *
kctl_boot_tmpinit(void)
{
	return (boot_kdi_tmpinit());
}

void
kctl_boot_tmpfini(void *old)
{
	boot_kdi_tmpfini(old);
}
