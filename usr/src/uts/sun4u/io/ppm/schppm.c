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


/*
 *	Schizo Power Management Driver
 *
 *	This driver deals with Safari bus interface and it is used
 *	as part of the protocol to change the clock speed on Safari bus.
 *
 *	The routine on this driver is referenced by Platform Power
 *	Management driver of systems like Excalibur.  Driver is
 *	loaded because of an explicit dependency defined in PPM driver.
 *	PPM driver also attaches the driver.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>


/*
 * Function prototypes
 */
static int spm_attach(dev_info_t *, ddi_attach_cmd_t);
static int spm_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * Private data for schizo_pm driver
 */
struct spm_soft_state {
	dev_info_t		*dip;
};

/*
 * Configuration data structures
 */
static struct dev_ops spm_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt */
	nodev,			/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	spm_attach,		/* attach */
	spm_detach,		/* detach */
	nodev,			/* reset */
	(struct cb_ops *)0,	/* cb_ops */
	(struct bus_ops *)0,	/* bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/*
 * Driver globals
 */
static void *spm_state;
static int spm_inst = -1;

static struct modldrv modldrv = {
	&mod_driverops,			/* Type of module = driver */
	"schizo pm driver",	/* name of module */
	&spm_ops,			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

/*
 * Schizo CSR E* bit masks
 */
#define	SCHIZO_SAFARI_ECLK_32	0x20ULL
#define	SCHIZO_SAFARI_ECLK_2	0x2ULL
#define	SCHIZO_SAFARI_ECLK_1	0x1ULL
#define	SCHIZO_SAFARI_ECLK_MASK	(SCHIZO_SAFARI_ECLK_32 |	\
    SCHIZO_SAFARI_ECLK_2 | SCHIZO_SAFARI_ECLK_1)

/*
 * bit masks to set schizo clock in parallel with setting cpu clock.
 * Used when changing cpu speeds.
 *
 * NOTE: The order of entries must be from slowest to fastest.
 */
static const uint64_t schizo_safari_masks[] = {
	SCHIZO_SAFARI_ECLK_32,
	SCHIZO_SAFARI_ECLK_2,
	SCHIZO_SAFARI_ECLK_1
};

/*
 * Normally, the address of the registers we use would be accessed from
 * our "official" private data.  However, since the dip is not passed
 * in when spm_change_speed (see below) is called, and since there is
 * only one unit of the spm "device", we keep it here as a static.
 */
static volatile uint64_t *spm_schizo_csr;
ddi_acc_handle_t	 spm_schizo_handle;

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&spm_state,
	    sizeof (struct spm_soft_state), 0)) != 0)
		return (error);

	if ((error = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&spm_state);

	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) == 0)
		ddi_soft_state_fini(&spm_state);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
spm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int rv;
	struct spm_soft_state *softsp;
	ddi_device_acc_attr_t attr;

	switch (cmd) {
	case DDI_ATTACH:
		if (spm_inst != -1) {
			cmn_err(CE_WARN, "spm_attach: "
			    "only one instance is allowed.");
			return (DDI_FAILURE);
		}

		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	spm_inst = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(spm_state, spm_inst) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "spm_attach: can't allocate state.");
		return (DDI_FAILURE);
	}

	if ((softsp = ddi_get_soft_state(spm_state, spm_inst)) == NULL) {
		cmn_err(CE_WARN, "spm_attach: can't get state.");
		return (DDI_FAILURE);
	}

	softsp->dip = dip;
	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags  = DDI_NEVERSWAP_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/*
	 * Map the Safari E* Control register.
	 */
	rv = ddi_regs_map_setup(dip, 0,
	    (caddr_t *)&spm_schizo_csr, 0, 8, &attr, &spm_schizo_handle);
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_WARN, "spm_attach: can't map the register.");
		ddi_soft_state_free(spm_state, spm_inst);
		return (rv);
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
spm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	case DDI_DETACH:
		return (DDI_FAILURE);

	default:
		return (DDI_FAILURE);
	}
}

/*
 * This globally visible function is the main reason this driver exists.
 * It will be called by a platform power management driver to write to
 * the schizo ASIC csr which changes schizo's clock rate.  This is a
 * required step when changing the clock of the cpus.
 *
 * NOTE - The caller should enter this routine sequentially.
 */
void
spm_change_schizo_speed(int lvl_index)
{
	uint64_t	contents;

	ASSERT(lvl_index >= 0 && lvl_index <= 2);
	contents = ddi_get64(spm_schizo_handle, (uint64_t *)spm_schizo_csr);
	contents &= ~SCHIZO_SAFARI_ECLK_MASK;
	contents |= schizo_safari_masks[ lvl_index ];
	ddi_put64(spm_schizo_handle, (uint64_t *)spm_schizo_csr, contents);
}
