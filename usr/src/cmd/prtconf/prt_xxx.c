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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

#include <stdio.h>
#include <stddef.h>
#include <fcntl.h>
#include <string.h>
#include <libdevinfo.h>
#include <sys/pctypes.h>
#include <sys/pcmcia.h>
#include <sys/utsname.h>
#include <sys/avintr.h>

#include "prtconf.h"

struct priv_data {
	char *drv_name;		/* parent name */
	void (*pd_print)(uintptr_t, int);	/* print function */
};

extern void indent_to_level();
static void obio_printregs(struct regspec *, int);
static void obio_printranges(struct rangespec *, int);
static void obio_printintr(struct intrspec *, int);
static void obio_print(uintptr_t, int);
static void pcmcia_printregs(struct pcm_regs *, int);
static void pcmcia_printintr(struct intrspec *, int);
static void pcmcia_print(uintptr_t, int);
static void sbus_print(uintptr_t, int);
static struct priv_data *match_priv_data(di_node_t);

/*
 * This is a hardcoded list of drivers we print parent private
 * data as of Solaris 7.
 */
static struct di_priv_format ppd_format[] = {
	{
		/*
		 * obio format: applies the following list
		 * of nexus drivers. Note that obio driver
		 * went away with sun4m.
		 */
#ifdef	__sparc
		"central dma ebus fhc isa pci rootnex",
#else
		"central dma ebus fhc isa pci pci_pci rootnex",
#endif	/* __sparc */
		sizeof (struct ddi_parent_private_data),

		sizeof (struct regspec),		/* first pointer */
		offsetof(struct ddi_parent_private_data, par_reg),
		offsetof(struct ddi_parent_private_data, par_nreg),

		sizeof (struct intrspec),		/* second pointer */
		offsetof(struct ddi_parent_private_data, par_intr),
		offsetof(struct ddi_parent_private_data, par_nintr),

		sizeof (struct rangespec),		/* third pointer */
		offsetof(struct ddi_parent_private_data, par_rng),
		offsetof(struct ddi_parent_private_data, par_nrng),

		0, 0, 0,	/* no more pointers */
		0, 0, 0
	},

	{	/* pcmcia format */
		"pcic",
		sizeof (struct pcmcia_parent_private),

		sizeof (struct pcm_regs),		/* first pointer */
		offsetof(struct pcmcia_parent_private, ppd_reg),
		offsetof(struct pcmcia_parent_private, ppd_nreg),

		sizeof (struct intrspec),		/* second pointer */
		offsetof(struct pcmcia_parent_private, ppd_intrspec),
		offsetof(struct pcmcia_parent_private, ppd_intr),

		0, 0, 0,	/* no more pointers */
		0, 0, 0,
		0, 0, 0
	},

	{	/* sbus format--it's different on sun4u!! */
		"sbus",
		sizeof (struct ddi_parent_private_data),

		sizeof (struct regspec),		/* first pointer */
		offsetof(struct ddi_parent_private_data, par_reg),
		offsetof(struct ddi_parent_private_data, par_nreg),

		sizeof (struct intrspec),		/* second pointer */
		offsetof(struct ddi_parent_private_data, par_intr),
		offsetof(struct ddi_parent_private_data, par_nintr),

		sizeof (struct rangespec),		/* third pointer */
		offsetof(struct ddi_parent_private_data, par_rng),
		offsetof(struct ddi_parent_private_data, par_nrng),

		0, 0, 0,	/* no more pointers */
		0, 0, 0
	}
};

static struct priv_data prt_priv_data[] = {
	{ ppd_format[0].drv_name, obio_print},
	{ ppd_format[1].drv_name, pcmcia_print},
	{ ppd_format[2].drv_name, sbus_print}
};

static int nprt_priv_data = sizeof (prt_priv_data)/sizeof (struct priv_data);

void
init_priv_data(struct di_priv_data *fetch)
{
	/* no driver private data */
	fetch->version = DI_PRIVDATA_VERSION_0;
	fetch->n_driver = 0;
	fetch->driver = NULL;

	fetch->n_parent = nprt_priv_data;
	fetch->parent = ppd_format;
}

static void
obio_printregs(struct regspec *rp, int ilev)
{
	indent_to_level(ilev);
	(void) printf("    Bus Type=0x%x, Address=0x%x, Size=0x%x\n",
	    rp->regspec_bustype, rp->regspec_addr, rp->regspec_size);
}

static void
obio_printranges(struct rangespec *rp, int ilev)
{
	indent_to_level(ilev);
	(void) printf("    Ch: %.2x,%.8x Pa: %.2x,%.8x, Sz: %x\n",
	    rp->rng_cbustype, rp->rng_coffset,
	    rp->rng_bustype, rp->rng_offset,
	    rp->rng_size);
}

static void
obio_printintr(struct intrspec *ip, int ilev)
{
	indent_to_level(ilev);
	(void) printf("    Interrupt Priority=0x%x (ipl %d)",
	    ip->intrspec_pri, INT_IPL(ip->intrspec_pri));
	if (ip->intrspec_vec)
		(void) printf(", vector=0x%x (%d)",
		    ip->intrspec_vec, ip->intrspec_vec);
	(void) printf("\n");
}

static void
obio_print(uintptr_t data, int ilev)
{
	int i, nreg, nrng, nintr;
	struct ddi_parent_private_data *dp;
	struct regspec *reg;
	struct intrspec *intr;
	struct rangespec *rng;

	dp = (struct ddi_parent_private_data *)data;
#ifdef DEBUG
	dprintf("obio parent private data: nreg = 0x%x offset = 0x%x"
	    " nintr = 0x%x offset = 0x%x nrng = 0x%x offset = %x\n",
	    dp->par_nreg, *((di_off_t *)(&dp->par_reg)),
	    dp->par_nintr, *((di_off_t *)(&dp->par_intr)),
	    dp->par_nrng, *((di_off_t *)(&dp->par_rng)));
#endif /* DEBUG */
	nreg = dp->par_nreg;
	nintr = dp->par_nintr;
	nrng = dp->par_nrng;

	/*
	 * All pointers are translated to di_off_t by the devinfo driver.
	 * This is a private agreement between libdevinfo and prtconf.
	 */
	if (nreg != 0) {
		indent_to_level(ilev);
		(void) printf("Register Specifications:\n");

		reg = (struct regspec *)(data + *(di_off_t *)(&dp->par_reg));
		for (i = 0; i < nreg; ++i)
			obio_printregs(reg + i, ilev);
	}

	if (nrng != 0) {
		indent_to_level(ilev);
		(void) printf("Range Specifications:\n");

		rng = (struct rangespec *)(data + *(di_off_t *)(&dp->par_rng));
		for (i = 0; i < nrng; ++i)
			obio_printranges(rng + i, ilev);
	}

	if (nintr != 0) {
		indent_to_level(ilev);
		(void) printf("Interrupt Specifications:\n");

		intr = (struct intrspec *)(data + *(di_off_t *)(&dp->par_intr));
		for (i = 0; i < nintr; ++i)
			obio_printintr(intr + i, ilev);
	}
}

static void
pcmcia_printregs(struct pcm_regs *rp, int ilev)
{
	indent_to_level(ilev);
	(void) printf("    Phys hi=0x%x, Phys lo=0x%x, Phys len=%x\n",
	    rp->phys_hi, rp->phys_lo, rp->phys_len);
}

static void
pcmcia_printintr(struct intrspec *ip, int ilev)
{
	obio_printintr(ip, ilev);
}

static void
pcmcia_print(uintptr_t data, int ilev)
{
	int i, nreg, nintr;
	struct pcmcia_parent_private *dp;
	struct pcm_regs *reg;
	struct intrspec *intr;

	dp = (struct pcmcia_parent_private *)data;
#ifdef DEBUG
	dprintf("pcmcia parent private data: nreg = 0x%x offset = 0x%x"
	    " intr = 0x%x offset = %x\n",
	    dp->ppd_nreg, *(di_off_t *)(&dp->ppd_reg),
	    dp->ppd_intr, *(di_off_t *)(&dp->ppd_intrspec));
#endif /* DEBUG */
	nreg = dp->ppd_nreg;
	nintr = dp->ppd_intr;

	/*
	 * All pointers are translated to di_off_t by the devinfo driver.
	 * This is a private agreement between libdevinfo and prtconf.
	 */
	if (nreg != 0)  {
		indent_to_level(ilev);
		(void) printf("Register Specifications:\n");

		reg = (struct pcm_regs *)(data + *(di_off_t *)(&dp->ppd_reg));
		for (i = 0; i < nreg; ++i)
			pcmcia_printregs(reg + i, ilev);
	}

	if (nintr != 0)  {
		indent_to_level(ilev);
		(void) printf("Interrupt Specifications:\n");

		intr = (struct intrspec *)
		    (data + *(di_off_t *)(&dp->ppd_intrspec));
		for (i = 0; i < nintr; ++i)
			pcmcia_printintr(intr + i, ilev);
	}
}

static void
sbus_print(uintptr_t data, int ilev)
{
	int i, nreg, nrng, nintr;
	struct ddi_parent_private_data *dp;
	struct regspec *reg;
	struct intrspec *intr;
	struct rangespec *rng;

	dp = (struct ddi_parent_private_data *)data;
#ifdef DEBUG
	dprintf("sbus parent private data: nreg = 0x%x offset = 0x%x"
	    " nintr = 0x%x offset = 0x%x nrng = 0x%x offset = %x\n",
	    dp->par_nreg, *((di_off_t *)(&dp->par_reg)),
	    dp->par_nintr, *((di_off_t *)(&dp->par_intr)),
	    dp->par_nrng, *((di_off_t *)(&dp->par_rng)));
#endif /* DEBUG */
	nreg = dp->par_nreg;
	nintr = dp->par_nintr;
	nrng = dp->par_nrng;

	/*
	 * All pointers are translated to di_off_t by the devinfo driver.
	 * This is a private agreement between libdevinfo and prtconf.
	 */
	if (nreg != 0) {
		indent_to_level(ilev);
		(void) printf("Register Specifications:\n");

		reg = (struct regspec *)(data + *(di_off_t *)(&dp->par_reg));
		for (i = 0; i < nreg; ++i)
			obio_printregs(reg + i, ilev);
	}


	if (nrng != 0) {
		indent_to_level(ilev);
		(void) printf("Range Specifications:\n");

		rng = (struct rangespec *)(data + *(di_off_t *)(&dp->par_rng));
		for (i = 0; i < nrng; ++i)
			obio_printranges(rng + i, ilev);
	}

	/*
	 * To print interrupt property for children of sbus on sun4u requires
	 * definitions in sysiosbus.h.
	 *
	 * We can't #include <sys/sysiosbus.h> to have the build work on
	 * non sun4u machines. It's not right either to
	 *	#include "../../uts/sun4u/sys/sysiosbus.h"
	 * As a result, we will not print the information.
	 */
	if ((nintr != 0) && (strcmp(opts.o_uts.machine, "sun4u") != 0)) {
		indent_to_level(ilev);
		(void) printf("Interrupt Specifications:\n");

		for (i = 0; i < nintr; ++i) {
			intr = (struct intrspec *)
			    (data + *(di_off_t *)(&dp->par_intr));
			obio_printintr(intr + i, ilev);
		}
	}
}

static struct priv_data *
match_priv_data(di_node_t node)
{
	int i;
	size_t len;
	char *drv_name, *tmp;
	di_node_t parent;
	struct priv_data *pdp;

	if ((parent = di_parent_node(node)) == DI_NODE_NIL)
		return (NULL);

	if ((drv_name = di_driver_name(parent)) == NULL)
		return (NULL);

	pdp = prt_priv_data;
	len = strlen(drv_name);
	for (i = 0; i < nprt_priv_data; ++i, ++pdp) {
		tmp = pdp->drv_name;
		while (tmp && (*tmp != '\0')) {
			if (strncmp(tmp, drv_name, len) == 0) {
#ifdef	DEBUG
				dprintf("matched parent private data"
				    " at Node <%s> parent driver <%s>\n",
				    di_node_name(node), drv_name);
#endif	/* DEBUG */
				return (pdp);
			}
			/*
			 * skip a white space
			 */
			if (tmp = strchr(tmp, ' '))
				tmp++;
		}
	}

	return (NULL);
}

void
dump_priv_data(int ilev, di_node_t node)
{
	uintptr_t priv;
	struct priv_data *pdp;

	if ((priv = (uintptr_t)di_parent_private_data(node)) == NULL)
		return;

	if ((pdp = match_priv_data(node)) == NULL) {
#ifdef DEBUG
		dprintf("Error: parent private data format unknown\n");
#endif /* DEBUG */
		return;
	}

	pdp->pd_print(priv, ilev);

	/* ignore driver private data for now */
}

#define	LOOKUP_PROP(proptype, ph, nodetype, dev, node, name, data)	\
	((nodetype == DI_PROM_NODEID) ?					\
	di_prom_prop_lookup_##proptype(ph, node, name, data) :		\
	di_prop_lookup_##proptype(dev, node, name, data))
#define	ISPCI(s)						\
	(((s) != NULL) && ((strcmp((s), "pci") == 0) ||		\
	(strcmp((s), "pciex") == 0)))
/*
 * Print vendor ID and device ID for PCI devices
 */
int
print_pciid(di_node_t node, di_prom_handle_t ph, pcidb_hdl_t *pci)
{
	pcidb_vendor_t *vend = NULL;
	pcidb_device_t *dev = NULL;
	di_node_t pnode = di_parent_node(node);
	char *s = NULL;
	int *i, type = di_nodeid(node);

	if (LOOKUP_PROP(strings, ph, type, DDI_DEV_T_ANY, pnode,
	    "device_type", &s) <= 0)
		return (0);

	if (!ISPCI(s))
		return (0);	/* not a pci device */

	(void) printf(" (%s", s);
	if (LOOKUP_PROP(ints, ph, type, DDI_DEV_T_ANY, node,
	    "vendor-id", &i) > 0)
		(void) printf("%x", i[0]);

	if (pci != NULL)
		vend = pcidb_lookup_vendor(pci, i[0]);

	if (LOOKUP_PROP(ints, ph, type, DDI_DEV_T_ANY, node,
	    "device-id", &i) > 0)
		(void) printf(",%x", i[0]);

	if (vend != NULL)
		dev = pcidb_lookup_device_by_vendor(vend, i[0]);

	(void) printf(") [");

	if (vend != NULL)
		(void) printf("%s ", pcidb_vendor_name(vend));
	else
		(void) printf("unknown vendor, ");

	if (dev != NULL)
		(void) printf("%s", pcidb_device_name(dev));
	else
		(void) printf("unknown device");

	(void) printf("]");
	return (1);
}
