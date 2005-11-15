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

/*
 *	Kstat support for X86 PCI driver
 */

#include <sys/conf.h>
#include <sys/mach_intr.h>
#include <sys/psm.h>
#include <sys/clock.h>
#include <io/pcplusmp/apic.h>
#include <io/pci/pci_var.h>

typedef struct pci_kstat_private {
	ddi_intr_handle_impl_t	*hdlp;
	dev_info_t		*rootnex_dip;
} pci_kstat_private_t;

static struct {
	kstat_named_t ihks_name;
	kstat_named_t ihks_type;
	kstat_named_t ihks_cpu;
	kstat_named_t ihks_pil;
	kstat_named_t ihks_time;
	kstat_named_t ihks_ino;
	kstat_named_t ihks_cookie;
	kstat_named_t ihks_devpath;
	kstat_named_t ihks_buspath;
} pci_ks_template = {
	{ "name",	KSTAT_DATA_CHAR },
	{ "type",	KSTAT_DATA_CHAR },
	{ "cpu",	KSTAT_DATA_UINT64 },
	{ "pil",	KSTAT_DATA_UINT64 },
	{ "time",	KSTAT_DATA_UINT64 },
	{ "ino",	KSTAT_DATA_UINT64 },
	{ "cookie",	KSTAT_DATA_UINT64 },
	{ "devpath",	KSTAT_DATA_STRING },
	{ "buspath",	KSTAT_DATA_STRING },
};

static uint32_t pci_ks_inst;
static kmutex_t pci_ks_template_lock;

/*ARGSUSED*/
static int
pci_ih_ks_update(kstat_t *ksp, int rw)
{
	pci_kstat_private_t	*private_data =
				    (pci_kstat_private_t *)ksp->ks_private;
	dev_info_t		*rootnex_dip = private_data->rootnex_dip;
	ddi_intr_handle_impl_t	*ih_p = private_data->hdlp;
	dev_info_t		*dip = ih_p->ih_dip;
	int			maxlen =
				    sizeof (pci_ks_template.ihks_name.value.c);
	char			ih_devpath[MAXPATHLEN];
	char			ih_buspath[MAXPATHLEN];
	apic_get_intr_t	intrinfo;

	(void) snprintf(pci_ks_template.ihks_name.value.c, maxlen, "%s%d",
	    ddi_driver_name(dip), ddi_get_instance(dip));
	(void) strcpy(pci_ks_template.ihks_type.value.c,
	    DDI_INTR_IS_MSI_OR_MSIX(ih_p->ih_type) ? "msi" : "fixed");
	pci_ks_template.ihks_pil.value.ui64 = ih_p->ih_pri;
	pci_ks_template.ihks_time.value.ui64 =
	    ((ihdl_plat_t *)ih_p->ih_private)->ip_ticks;
	tsc_scalehrtime((hrtime_t *)&pci_ks_template.ihks_time.value.ui64);
	pci_ks_template.ihks_cookie.value.ui64 = ih_p->ih_vector;

	/*
	 * Return a vector since that's what PCItool will require intrd to use.
	 *
	 * PCItool will change the CPU routing of the IRQ that vector maps to.
	 *
	 * Note that although possibly multiple vectors can map to an IRQ, the
	 * vector returned below will always be the same for a given IRQ
	 * specified, and so all kstats for a given IRQ will report the same
	 * value for the ino field.
	 */
	intrinfo.avgi_req_flags = PSMGI_REQ_CPUID | PSMGI_REQ_VECTOR;
	if (pci_get_intr_from_vecirq(&intrinfo,  ih_p->ih_vector, IS_IRQ) !=
	    DDI_SUCCESS) {
		/* again, shouldn't happen */
		pci_ks_template.ihks_cpu.value.ui64 = 0;
		/* XXX Setting this value seems to be harmless. */
		pci_ks_template.ihks_cookie.value.ui64 = ih_p->ih_vector;
	} else {
		pci_ks_template.ihks_cpu.value.ui64 =
		    intrinfo.avgi_cpu_id & ~PSMGI_CPU_FLAGS;
		pci_ks_template.ihks_ino.value.ui64 = intrinfo.avgi_vector;
	}

	(void) ddi_pathname(dip, ih_devpath);
	(void) ddi_pathname(rootnex_dip, ih_buspath);
	kstat_named_setstr(&pci_ks_template.ihks_devpath, ih_devpath);
	kstat_named_setstr(&pci_ks_template.ihks_buspath, ih_buspath);

	return (0);
}


void pci_kstat_create(kstat_t **kspp, dev_info_t *rootnex_dip,
    ddi_intr_handle_impl_t *hdlp)
{
	pci_kstat_private_t *private_data;

	*kspp = kstat_create("pci_intrs", atomic_inc_32_nv(&pci_ks_inst),
	    "config", "interrupts", KSTAT_TYPE_NAMED,
	    sizeof (pci_ks_template) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (*kspp != NULL) {

		private_data =
		    kmem_zalloc(sizeof (pci_kstat_private_t), KM_SLEEP);
		private_data->hdlp = hdlp;
		private_data->rootnex_dip = rootnex_dip;

		(*kspp)->ks_private = private_data;
		(*kspp)->ks_data_size += MAXPATHLEN * 2;
		(*kspp)->ks_lock = &pci_ks_template_lock;
		(*kspp)->ks_data = &pci_ks_template;
		(*kspp)->ks_update = pci_ih_ks_update;
		kstat_install(*kspp);
	}
}

void
pci_kstat_delete(kstat_t *ksp)
{
	pci_kstat_private_t *kstat_private;

	if (ksp) {
		kstat_private = ksp->ks_private;

		/*
		 * Delete the kstat before removing the private pointer, to
		 * prevent a kstat update from coming after private is freed.
		 */
		kstat_delete(ksp);

		if (kstat_private)
			kmem_free(kstat_private, sizeof (pci_kstat_private_t));
	}
}
