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
 * Copyright (c) 2012 Gary Mills
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <kmdb/kmdb_auxv.h>
#include <kmdb/kctl/kctl.h>

#include <sys/bootconf.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/cpuvar.h>
#include <sys/kdi_impl.h>
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
 * Here actually we only support eight console properties:
 *     input-device, output-device, tty[a-d]-mode, screen-#rows, screen-#cols.
 */
#define	KCTL_PROPNV_NIODEV	2
#define	KCTL_PROPNV_NTTYMD	4
#define	KCTL_PROPNV_NSCREEN	2
#define	KCTL_PROPNV_NENT	(KCTL_PROPNV_NIODEV + KCTL_PROPNV_NTTYMD + \
	KCTL_PROPNV_NSCREEN)

static kmdb_auxv_nv_t *
kctl_pcache_create(int *nprops)
{
	int (*preader)(char *, char *, int);
	kmdb_auxv_nv_t *pnv;
	size_t psz = sizeof (kmdb_auxv_nv_t) * KCTL_PROPNV_NENT;
	char *inputdev, *outputdev;
	int i, j;
	char ttymode[] = "ttyX-mode";

	if (kctl.kctl_boot_loaded) {
		preader = kctl_boot_prop_read;
	} else {
		preader = kctl_ddi_prop_read;
	}

	pnv = kobj_alloc(psz, KM_WAIT);
	inputdev = (&pnv[0])->kanv_val;
	outputdev = (&pnv[1])->kanv_val;

	/* Set the property names. */
	(void) strcpy((&pnv[0])->kanv_name, "input-device");
	(void) strcpy((&pnv[1])->kanv_name, "output-device");
	for (i = 0; i < KCTL_PROPNV_NTTYMD; i++) {
		ttymode[3] = 'a' + i;
		(void) strcpy((&pnv[i + KCTL_PROPNV_NIODEV])->kanv_name,
		    ttymode);
	}

	(void) strcpy(inputdev, "text");	/* default to screen */
	if (!preader("diag-device", inputdev, sizeof ((&pnv[0])->kanv_val)) &&
	    !preader("console", inputdev, sizeof ((&pnv[0])->kanv_val))) {
		(void) preader("input-device", inputdev,
		    sizeof ((&pnv[0])->kanv_val));
	}

	if (strncmp(inputdev, "tty", 3) == 0 &&
	    inputdev[4] == '\0' &&
	    inputdev[3] >= 'a' &&
	    inputdev[3] < 'a' + KCTL_PROPNV_NTTYMD) {
		(void) strcpy(outputdev, inputdev);
	} else {
		(void) strcpy(inputdev, "keyboard");
		(void) strcpy(outputdev, "screen");
	}

	/* Set tty modes or defaults. */
	j = KCTL_PROPNV_NIODEV + KCTL_PROPNV_NTTYMD;
	for (i = KCTL_PROPNV_NIODEV; i < j; i++) {
		if (!preader((&pnv[i])->kanv_name, (&pnv[i])->kanv_val,
		    sizeof ((&pnv[0])->kanv_val)))
			(void) strcpy((&pnv[i])->kanv_val, "9600,8,n,1,-");
	}

	(void) strcpy((&pnv[j])->kanv_name, "screen-#rows");
	(void) strcpy((&pnv[j + 1])->kanv_name, "screen-#cols");
	(void) strcpy((&pnv[j])->kanv_val, "0");
	(void) strcpy((&pnv[j + 1])->kanv_val, "0");
	(void) preader((&pnv[j])->kanv_name, (&pnv[j])->kanv_val,
	    sizeof ((&pnv[j])->kanv_val));
	(void) preader((&pnv[j + 1])->kanv_name, (&pnv[j + 1])->kanv_val,
	    sizeof ((&pnv[j + 1])->kanv_val));

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
