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
 */

/*
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/dtrace.h>
#include <sys/kobj.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <vm/seg_kmem.h>
#include <sys/stack.h>
#include <sys/sdt_impl.h>

static dev_info_t		*sdt_devi;

int sdt_verbose = 0;

#define	SDT_REG_G0		0
#define	SDT_REG_O0		8
#define	SDT_REG_O1		9
#define	SDT_REG_O2		10
#define	SDT_REG_O3		11
#define	SDT_REG_O4		12
#define	SDT_REG_O5		13
#define	SDT_REG_I0		24
#define	SDT_REG_I1		25
#define	SDT_REG_I2		26
#define	SDT_REG_I3		27
#define	SDT_REG_I4		28
#define	SDT_REG_I5		29

#define	SDT_SIMM13_MASK		0x1fff
#define	SDT_SIMM13_MAX		((int32_t)0xfff)
#define	SDT_CALL(from, to)	(((uint32_t)1 << 30) | \
				(((uintptr_t)(to) - (uintptr_t)(from) >> 2) & \
				0x3fffffff))
#define	SDT_SAVE		(0x9de3a000 | (-SA(MINFRAME) & SDT_SIMM13_MASK))
#define	SDT_RET			0x81c7e008
#define	SDT_RESTORE		0x81e80000

#define	SDT_OP_SETHI		0x1000000
#define	SDT_OP_OR		0x80100000

#define	SDT_FMT2_RD_SHIFT	25
#define	SDT_IMM22_SHIFT		10
#define	SDT_IMM22_MASK		0x3fffff
#define	SDT_IMM10_MASK		0x3ff

#define	SDT_FMT3_RD_SHIFT	25
#define	SDT_FMT3_RS1_SHIFT	14
#define	SDT_FMT3_RS2_SHIFT	0
#define	SDT_FMT3_IMM		(1 << 13)

#define	SDT_MOV(rs, rd) \
	(SDT_OP_OR | (SDT_REG_G0 << SDT_FMT3_RS1_SHIFT) | \
	((rs) << SDT_FMT3_RS2_SHIFT) | ((rd) << SDT_FMT3_RD_SHIFT))

#define	SDT_ORLO(rs, val, rd) \
	(SDT_OP_OR | ((rs) << SDT_FMT3_RS1_SHIFT) | \
	((rd) << SDT_FMT3_RD_SHIFT) | SDT_FMT3_IMM | ((val) & SDT_IMM10_MASK))

#define	SDT_ORSIMM13(rs, val, rd) \
	(SDT_OP_OR | ((rs) << SDT_FMT3_RS1_SHIFT) | \
	((rd) << SDT_FMT3_RD_SHIFT) | SDT_FMT3_IMM | ((val) & SDT_SIMM13_MASK))

#define	SDT_SETHI(val, reg)	\
	(SDT_OP_SETHI | (reg << SDT_FMT2_RD_SHIFT) | \
	((val >> SDT_IMM22_SHIFT) & SDT_IMM22_MASK))

#define	SDT_ENTRY_SIZE	(11 * sizeof (uint32_t))

static void
sdt_initialize(sdt_probe_t *sdp, uint32_t **trampoline)
{
	uint32_t *instr = *trampoline;

	*instr++ = SDT_SAVE;

	if (sdp->sdp_id > (uint32_t)SDT_SIMM13_MAX)  {
		*instr++ = SDT_SETHI(sdp->sdp_id, SDT_REG_O0);
		*instr++ = SDT_ORLO(SDT_REG_O0, sdp->sdp_id, SDT_REG_O0);
	} else {
		*instr++ = SDT_ORSIMM13(SDT_REG_G0, sdp->sdp_id, SDT_REG_O0);
	}

	*instr++ = SDT_MOV(SDT_REG_I0, SDT_REG_O1);
	*instr++ = SDT_MOV(SDT_REG_I1, SDT_REG_O2);
	*instr++ = SDT_MOV(SDT_REG_I2, SDT_REG_O3);
	*instr++ = SDT_MOV(SDT_REG_I3, SDT_REG_O4);
	*instr = SDT_CALL(instr, dtrace_probe);
	instr++;
	*instr++ = SDT_MOV(SDT_REG_I4, SDT_REG_O5);

	*instr++ = SDT_RET;
	*instr++ = SDT_RESTORE;
	*trampoline = instr;
}

/*ARGSUSED*/
static void
sdt_provide_module(void *arg, struct modctl *ctl)
{
	struct module *mp = ctl->mod_mp;
	char *modname = ctl->mod_modname;
	int primary, nprobes = 0;
	sdt_probedesc_t *sdpd;
	sdt_probe_t *sdp, *old;
	uint32_t *tab;
	sdt_provider_t *prov;
	int len;

	/*
	 * One for all, and all for one:  if we haven't yet registered all of
	 * our providers, we'll refuse to provide anything.
	 */
	for (prov = sdt_providers; prov->sdtp_name != NULL; prov++) {
		if (prov->sdtp_id == DTRACE_PROVNONE)
			return;
	}

	if (mp->sdt_nprobes != 0 || (sdpd = mp->sdt_probes) == NULL)
		return;

	kobj_textwin_alloc(mp);

	/*
	 * Hack to identify unix/genunix/krtld.
	 */
	primary = vmem_contains(heap_arena, (void *)ctl,
	    sizeof (struct modctl)) == 0;

	/*
	 * If there hasn't been an sdt table allocated, we'll do so now.
	 */
	if (mp->sdt_tab == NULL) {
		for (; sdpd != NULL; sdpd = sdpd->sdpd_next) {
			nprobes++;
		}

		/*
		 * We could (should?) determine precisely the size of the
		 * table -- but a reasonable maximum will suffice.
		 */
		mp->sdt_size = nprobes * SDT_ENTRY_SIZE;
		mp->sdt_tab = kobj_texthole_alloc(mp->text, mp->sdt_size);

		if (mp->sdt_tab == NULL) {
			cmn_err(CE_WARN, "couldn't allocate SDT table "
			    "for module %s", modname);
			return;
		}
	}

	tab = (uint32_t *)mp->sdt_tab;

	for (sdpd = mp->sdt_probes; sdpd != NULL; sdpd = sdpd->sdpd_next) {
		char *name = sdpd->sdpd_name, *func, *nname;
		int i, j;
		sdt_provider_t *prov;
		ulong_t offs;
		dtrace_id_t id;

		for (prov = sdt_providers; prov->sdtp_prefix != NULL; prov++) {
			char *prefix = prov->sdtp_prefix;

			if (strncmp(name, prefix, strlen(prefix)) == 0) {
				name += strlen(prefix);
				break;
			}
		}

		nname = kmem_alloc(len = strlen(name) + 1, KM_SLEEP);

		for (i = 0, j = 0; name[j] != '\0'; i++) {
			if (name[j] == '_' && name[j + 1] == '_') {
				nname[i] = '-';
				j += 2;
			} else {
				nname[i] = name[j++];
			}
		}

		nname[i] = '\0';

		sdp = kmem_zalloc(sizeof (sdt_probe_t), KM_SLEEP);
		sdp->sdp_loadcnt = ctl->mod_loadcnt;
		sdp->sdp_primary = primary;
		sdp->sdp_ctl = ctl;
		sdp->sdp_name = nname;
		sdp->sdp_namelen = len;
		sdp->sdp_provider = prov;

		func = kobj_searchsym(mp, sdpd->sdpd_offset +
		    (uintptr_t)mp->text, &offs);

		if (func == NULL)
			func = "<unknown>";

		/*
		 * We have our provider.  Now create the probe.
		 */
		if ((id = dtrace_probe_lookup(prov->sdtp_id, modname,
		    func, nname)) != DTRACE_IDNONE) {
			old = dtrace_probe_arg(prov->sdtp_id, id);
			ASSERT(old != NULL);

			sdp->sdp_next = old->sdp_next;
			sdp->sdp_id = id;
			old->sdp_next = sdp;
		} else {
			sdp->sdp_id = dtrace_probe_create(prov->sdtp_id,
			    modname, func, nname, 1, sdp);

			mp->sdt_nprobes++;
		}

		sdp->sdp_patchval = SDT_CALL((uintptr_t)mp->text +
		    sdpd->sdpd_offset, tab);
		sdp->sdp_patchpoint = (uint32_t *)((uintptr_t)mp->textwin +
		    sdpd->sdpd_offset);
		sdp->sdp_savedval = *sdp->sdp_patchpoint;
		sdt_initialize(sdp, &tab);
	}
}

/*ARGSUSED*/
static void
sdt_destroy(void *arg, dtrace_id_t id, void *parg)
{
	sdt_probe_t *sdp = parg, *old;
	struct modctl *ctl = sdp->sdp_ctl;

	if (ctl != NULL && ctl->mod_loadcnt == sdp->sdp_loadcnt) {
		if ((ctl->mod_loadcnt == sdp->sdp_loadcnt &&
		    ctl->mod_loaded) || sdp->sdp_primary) {
			((struct module *)(ctl->mod_mp))->sdt_nprobes--;
		}
	}

	while (sdp != NULL) {
		old = sdp;
		kmem_free(sdp->sdp_name, sdp->sdp_namelen);
		sdp = sdp->sdp_next;
		kmem_free(old, sizeof (sdt_probe_t));
	}
}

/*ARGSUSED*/
static int
sdt_enable(void *arg, dtrace_id_t id, void *parg)
{
	sdt_probe_t *sdp = parg;
	struct modctl *ctl = sdp->sdp_ctl;

	ctl->mod_nenabled++;

	/*
	 * If this module has disappeared since we discovered its probes,
	 * refuse to enable it.
	 */
	if (!sdp->sdp_primary && !ctl->mod_loaded) {
		if (sdt_verbose) {
			cmn_err(CE_NOTE, "sdt is failing for probe %s "
			    "(module %s unloaded)",
			    sdp->sdp_name, ctl->mod_modname);
		}
		goto err;
	}

	/*
	 * Now check that our modctl has the expected load count.  If it
	 * doesn't, this module must have been unloaded and reloaded -- and
	 * we're not going to touch it.
	 */
	if (ctl->mod_loadcnt != sdp->sdp_loadcnt) {
		if (sdt_verbose) {
			cmn_err(CE_NOTE, "sdt is failing for probe %s "
			    "(module %s reloaded)",
			    sdp->sdp_name, ctl->mod_modname);
		}
		goto err;
	}

	while (sdp != NULL) {
		*sdp->sdp_patchpoint = sdp->sdp_patchval;
		sdp = sdp->sdp_next;
	}

err:
	return (0);
}

/*ARGSUSED*/
static void
sdt_disable(void *arg, dtrace_id_t id, void *parg)
{
	sdt_probe_t *sdp = parg;
	struct modctl *ctl = sdp->sdp_ctl;

	ASSERT(ctl->mod_nenabled > 0);
	ctl->mod_nenabled--;

	if ((!sdp->sdp_primary && !ctl->mod_loaded) ||
	    (ctl->mod_loadcnt != sdp->sdp_loadcnt))
		goto err;

	while (sdp != NULL) {
		*sdp->sdp_patchpoint = sdp->sdp_savedval;
		sdp = sdp->sdp_next;
	}

err:
	;
}

static dtrace_pops_t sdt_pops = {
	NULL,
	sdt_provide_module,
	sdt_enable,
	sdt_disable,
	NULL,
	NULL,
	sdt_getargdesc,
	NULL,
	NULL,
	sdt_destroy
};

static int
sdt_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	sdt_provider_t *prov;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(devi, "sdt", S_IFCHR, 0,
	    DDI_PSEUDO, NULL) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);
	sdt_devi = devi;

	for (prov = sdt_providers; prov->sdtp_name != NULL; prov++) {
		uint32_t priv;

		if (prov->sdtp_priv == DTRACE_PRIV_NONE) {
			priv = DTRACE_PRIV_KERNEL;
			sdt_pops.dtps_mode = NULL;
		} else {
			priv = prov->sdtp_priv;
			ASSERT(priv == DTRACE_PRIV_USER);
			sdt_pops.dtps_mode = sdt_mode;
		}

		if (dtrace_register(prov->sdtp_name, prov->sdtp_attr,
		    priv, NULL, &sdt_pops, prov, &prov->sdtp_id) != 0) {
			cmn_err(CE_WARN, "failed to register sdt provider %s",
			    prov->sdtp_name);
		}
	}

	return (DDI_SUCCESS);
}

static int
sdt_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	sdt_provider_t *prov;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	for (prov = sdt_providers; prov->sdtp_name != NULL; prov++) {
		if (prov->sdtp_id != DTRACE_PROVNONE) {
			if (dtrace_unregister(prov->sdtp_id) != 0)
				return (DDI_FAILURE);
			prov->sdtp_id = DTRACE_PROVNONE;
		}
	}

	ddi_remove_minor_node(devi, NULL);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
sdt_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)sdt_devi;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/*ARGSUSED*/
static int
sdt_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	return (0);
}

static struct cb_ops sdt_cb_ops = {
	sdt_open,		/* open */
	nodev,			/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */
};

static struct dev_ops sdt_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	sdt_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	sdt_attach,		/* attach */
	sdt_detach,		/* detach */
	nodev,			/* reset */
	&sdt_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	nodev,			/* dev power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,		/* module type (this is a pseudo driver) */
	"Statically Defined Tracing",	/* name of module */
	&sdt_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
