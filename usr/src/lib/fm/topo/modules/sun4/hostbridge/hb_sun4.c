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

#include <string.h>
#include <fm/topo_mod.h>
#include <libdevinfo.h>
#include <sys/param.h>
#include <sys/systeminfo.h>

#include "hb_sun4.h"
#include "util.h"
#include "topo_error.h"
#include "hostbridge.h"
#include "pcibus.h"
#include "did.h"

extern did_hash_t *Didhash;

busorrc_t *
busorrc_new(const char *bus_addr, di_node_t di)
{
	busorrc_t *pp;
	char *comma;
	char *bac;
	int e;

	if ((pp = topo_mod_zalloc(HbHdl, sizeof (busorrc_t))) == NULL)
		return (NULL);
	pp->br_din = di;
	bac = topo_mod_strdup(HbHdl, bus_addr);
	if ((comma = strchr(bac, ',')) != NULL)
		*comma = '\0';
	pp->br_ba_bc = strtonum(HbHdl, bac, &e);
	if (e < 0) {
		topo_mod_dprintf(HbHdl,
		    "Trouble interpreting bus_addr before comma.\n");
		if (comma != NULL)
			*comma = ',';
		topo_mod_strfree(HbHdl, bac);
		topo_mod_free(HbHdl, pp, sizeof (busorrc_t));
		return (NULL);
	}
	if (comma == NULL) {
		pp->br_ba_ac = 0;
		topo_mod_strfree(HbHdl, bac);
		return (pp);
	}
	pp->br_ba_ac = strtonum(HbHdl, comma + 1, &e);
	if (e < 0) {
		topo_mod_dprintf(HbHdl,
		    "Trouble interpreting bus_addr after comma.\n");
		*comma = ',';
		topo_mod_strfree(HbHdl, bac);
		topo_mod_free(HbHdl, pp, sizeof (busorrc_t));
		return (NULL);
	}
	*comma = ',';
	topo_mod_strfree(HbHdl, bac);
	return (pp);
}

void
busorrc_insert(busorrc_t **head, busorrc_t *new)
{
	busorrc_t *ppci, *pci;

	topo_mod_dprintf(HbHdl,
	    "inserting (%x,%x)\n", new->br_ba_bc, new->br_ba_ac);

	/* No entries yet? */
	if (*head == NULL) {
		*head = new;
		return;
	}

	ppci = NULL;
	pci = *head;

	while (pci != NULL) {
		if (new->br_ba_ac == pci->br_ba_ac)
			if (new->br_ba_bc < pci->br_ba_bc)
				break;
		if (new->br_ba_ac < pci->br_ba_ac)
			break;
		ppci = pci;
		pci = pci->br_nextbus;
	}
	if (ppci == NULL) {
		new->br_nextbus = pci;
		pci->br_prevbus = new;
		*head = new;
	} else {
		new->br_nextbus = ppci->br_nextbus;
		if (new->br_nextbus != NULL)
			new->br_nextbus->br_prevbus = new;
		ppci->br_nextbus = new;
		new->br_prevbus = ppci;
	}
}

int
busorrc_add(busorrc_t **list, di_node_t n)
{
	busorrc_t *nb;
	char *ba;

	topo_mod_dprintf(HbHdl, "busorrc_add\n");
	ba = di_bus_addr(n);
	if (ba == NULL ||
	    (nb = busorrc_new(ba, n)) == NULL) {
		topo_mod_dprintf(HbHdl, "busorrc_new() failed.\n");
		return (-1);
	}
	busorrc_insert(list, nb);
	return (0);
}

void
busorrc_free(busorrc_t *pb)
{
	if (pb == NULL)
		return;
	busorrc_free(pb->br_nextbus);
	topo_mod_free(HbHdl, pb, sizeof (busorrc_t));
}

tnode_t *
hb_process(tnode_t *ptn, topo_instance_t hbi, topo_instance_t bi, di_node_t bn)
{
	tnode_t *hb;

	if ((hb = pcihostbridge_declare(ptn, bn, hbi)) == NULL)
		return (NULL);
	if (topo_mod_enumerate(HbHdl, hb, PCI_BUS, PCI_BUS, bi, bi) == 0)
		return (hb);
	return (NULL);
}

tnode_t *
rc_process(tnode_t *ptn, topo_instance_t rci, di_node_t bn)
{
	tnode_t *rc;

	if ((rc = pciexrc_declare(ptn, bn, rci)) == NULL)
		return (NULL);
	if (topo_mod_enumerate(HbHdl,
	    rc, PCI_BUS, PCIEX_BUS, 0, MAX_HB_BUSES) == 0)
		return (rc);
	return (NULL);
}

/*
 * declare_exbuses() assumes the elements in the provided busorrc list
 * are sorted thusly:
 *
 *	(Hostbridge #0, Root Complex #0, ExBus #0)
 *	(Hostbridge #0, Root Complex #0, ExBus #1)
 *		...
 *	(Hostbridge #0, Root Complex #0, ExBus #(buses/rc))
 *	(Hostbridge #0, Root Complex #1, ExBus #0)
 *		...
 *	(Hostbridge #0, Root Complex #1, ExBus #(buses/rc))
 *		...
 *		...
 *	(Hostbridge #0, Root Complex #(rcs/hostbridge), ExBus #(buses/rc))
 *	(Hostbridge #1, Root Complex #0, ExBus #0)
 *		...
 *		...
 *		...
 *		...
 *	(Hostbridge #nhb, Root Complex #(rcs/hostbridge), ExBus #(buses/rc))
 */
int
declare_exbuses(busorrc_t *list, tnode_t *ptn, int nhb, int nrc)
{
	tnode_t **rcs;
	tnode_t **hb;
	busorrc_t *p;
	int br, rc;

	/*
	 * Allocate an array to point at the hostbridge tnode_t pointers.
	 */
	if ((hb = topo_mod_zalloc(HbHdl, nhb * sizeof (tnode_t *))) == NULL)
		return (topo_mod_seterrno(HbHdl, ETOPO_NOMEM));

	/*
	 * Allocate an array to point at the root complex tnode_t pointers.
	 */
	if ((rcs = topo_mod_zalloc(HbHdl, nrc * sizeof (tnode_t *))) == NULL)
		return (topo_mod_seterrno(HbHdl, ETOPO_NOMEM));

	br = rc = 0;
	for (p = list; p != NULL; p = p->br_nextbus) {
		topo_mod_dprintf(HbHdl,
		    "declaring (%x,%x)\n", p->br_ba_bc, p->br_ba_ac);

		if (did_create(Didhash, p->br_din, 0, br, rc, rc) == NULL)
			return (-1);

		if (hb[br] == NULL) {
			hb[br] = pciexhostbridge_declare(ptn, p->br_din, br);
			if (hb[br] == NULL)
				return (-1);
		}
		if (rcs[rc] == NULL) {
			rcs[rc] = rc_process(hb[br], rc, p->br_din);
			if (rcs[rc] == NULL)
				return (-1);
		} else {
			if (topo_mod_enumerate(HbHdl,
			    rcs[rc], PCI_BUS, PCIEX_BUS, 0, MAX_HB_BUSES) < 0)
				return (-1);
		}
		rc++;
		if (rc == nrc) {
			rc = 0;
			br++;
			if (br == nhb)
				br = 0;
		}
	}
	topo_mod_free(HbHdl, rcs, nrc * sizeof (tnode_t *));
	topo_mod_free(HbHdl, hb, nhb * sizeof (tnode_t *));
	return (0);
}

/*
 * declare_buses() assumes the elements in the provided busorrc list
 * are sorted thusly:
 *
 *	(Hostbridge #0, Bus #0)
 *	(Hostbridge #1, Bus #0)
 *		...
 *	(Hostbridge #nhb, Bus #0)
 *	(Hostbridge #0, Bus #1)
 *		...
 *		...
 *	(Hostbridge #nhb, Bus #(buses/hostbridge))
 */
int
declare_buses(busorrc_t *list, tnode_t *ptn, int nhb)
{
	busorrc_t *p;
	tnode_t **hb;
	did_t *link;
	int br, bus;

	/*
	 * Allocate an array to point at the hostbridge tnode_t pointers.
	 */
	if ((hb = topo_mod_zalloc(HbHdl, nhb * sizeof (tnode_t *))) == NULL)
		return (topo_mod_seterrno(HbHdl, EMOD_NOMEM));

	br = bus = 0;
	for (p = list; p != NULL; p = p->br_nextbus) {
		topo_mod_dprintf(HbHdl,
		    "declaring (%x,%x)\n", p->br_ba_bc, p->br_ba_ac);

		if ((link =
		    did_create(Didhash, p->br_din, 0, br, NO_RC, bus)) == NULL)
			return (-1);

		if (hb[br] == NULL) {
			hb[br] = hb_process(ptn, br, bus, p->br_din);
			if (hb[br] == NULL)
				return (-1);
		} else {
			did_link_set(hb[br], link);
			if (topo_mod_enumerate(HbHdl,
			    hb[br], PCI_BUS, PCI_BUS, bus, bus) < 0) {
				return (-1);
			}
		}
		br++;
		if (br == nhb) {
			br = 0;
			bus++;
		}
	}
	topo_mod_free(HbHdl, hb, nhb * sizeof (tnode_t *));
	return (0);
}
