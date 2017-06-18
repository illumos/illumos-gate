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

#include <string.h>
#include <fm/topo_mod.h>
#include <libdevinfo.h>
#include <sys/param.h>
#include <sys/systeminfo.h>

#include <hb_sun4.h>
#include <util.h>
#include <hostbridge.h>
#include <pcibus.h>
#include <did.h>

busorrc_t *
busorrc_new(topo_mod_t *mod, const char *bus_addr, di_node_t di)
{
	busorrc_t *pp;
	char *comma;
	char *bac;
	int e;

	if ((pp = topo_mod_zalloc(mod, sizeof (busorrc_t))) == NULL)
		return (NULL);
	pp->br_din = di;
	bac = topo_mod_strdup(mod, bus_addr);
	if ((comma = strchr(bac, ',')) != NULL)
		*comma = '\0';
	pp->br_ba_bc = fm_strtonum(mod, bac, &e);
	if (e < 0) {
		topo_mod_dprintf(mod,
		    "Trouble interpreting bus_addr before comma.\n");
		if (comma != NULL)
			*comma = ',';
		topo_mod_strfree(mod, bac);
		topo_mod_free(mod, pp, sizeof (busorrc_t));
		return (NULL);
	}
	if (comma == NULL) {
		pp->br_ba_ac = 0;
		topo_mod_strfree(mod, bac);
		return (pp);
	}
	pp->br_ba_ac = fm_strtonum(mod, comma + 1, &e);
	if (e < 0) {
		topo_mod_dprintf(mod,
		    "Trouble interpreting bus_addr after comma.\n");
		*comma = ',';
		topo_mod_strfree(mod, bac);
		topo_mod_free(mod, pp, sizeof (busorrc_t));
		return (NULL);
	}
	*comma = ',';
	topo_mod_strfree(mod, bac);
	return (pp);
}

void
busorrc_insert(topo_mod_t *mod, busorrc_t **head, busorrc_t *new)
{
	busorrc_t *ppci, *pci;

	topo_mod_dprintf(mod,
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
busorrc_add(topo_mod_t *mod, busorrc_t **list, di_node_t n)
{
	busorrc_t *nb;
	char *ba;

	topo_mod_dprintf(mod, "busorrc_add\n");
	ba = di_bus_addr(n);
	if (ba == NULL ||
	    (nb = busorrc_new(mod, ba, n)) == NULL) {
		topo_mod_dprintf(mod, "busorrc_new() failed.\n");
		return (-1);
	}
	busorrc_insert(mod, list, nb);
	return (0);
}

void
busorrc_free(topo_mod_t *mod, busorrc_t *pb)
{
	if (pb == NULL)
		return;
	busorrc_free(mod, pb->br_nextbus);
	topo_mod_free(mod, pb, sizeof (busorrc_t));
}

tnode_t *
hb_process(topo_mod_t *mod, tnode_t *ptn, topo_instance_t hbi,
    topo_instance_t bi, di_node_t bn, did_t *hbdid)
{
	tnode_t *hb;

	if ((hb = pcihostbridge_declare(mod, ptn, bn, hbi)) == NULL)
		return (NULL);
	if (topo_mod_enumerate(mod, hb, PCI_BUS, PCI_BUS, bi, bi, hbdid) == 0)
		return (hb);

	topo_node_unbind(hb);

	return (NULL);
}

tnode_t *
rc_process(topo_mod_t *mod, tnode_t *ptn, topo_instance_t rci, di_node_t bn)
{
	tnode_t *rc;

	if ((rc = pciexrc_declare(mod, ptn, bn, rci)) == NULL)
		return (NULL);
	if (topo_mod_enumerate(mod,
	    rc, PCI_BUS, PCIEX_BUS, 0, MAX_HB_BUSES, NULL) == 0)
		return (rc);

	topo_node_unbind(rc);

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
declare_exbuses(topo_mod_t *mod, busorrc_t *list, tnode_t *ptn, int nhb,
    int nrc)
{
	int err = 0;
	tnode_t **rcs;
	tnode_t **hb;
	busorrc_t *p;
	int br, rc;

	/*
	 * Allocate an array to point at the hostbridge tnode_t pointers.
	 */
	if ((hb = topo_mod_zalloc(mod, nhb * sizeof (tnode_t *))) == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	/*
	 * Allocate an array to point at the root complex tnode_t pointers.
	 */
	if ((rcs = topo_mod_zalloc(mod, nrc * sizeof (tnode_t *))) == NULL) {
		topo_mod_free(mod, hb, nhb * sizeof (tnode_t *));
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	br = rc = 0;
	for (p = list; p != NULL; p = p->br_nextbus) {
		topo_mod_dprintf(mod,
		    "declaring (%x,%x)\n", p->br_ba_bc, p->br_ba_ac);

		if (did_create(mod, p->br_din, 0, br, rc, rc) == NULL) {
			err = -1;
			break;
		}

		if (hb[br] == NULL) {
			hb[br] = pciexhostbridge_declare(mod, ptn, p->br_din,
			    br);
			if (hb[br] == NULL) {
				err = -1;
				break;
			}
		}
		if (rcs[rc] == NULL) {
			rcs[rc] = rc_process(mod, hb[br], rc, p->br_din);
			if (rcs[rc] == NULL) {
				err = -1;
				break;
			}
		} else {
			if (topo_mod_enumerate(mod,
			    rcs[rc], PCI_BUS, PCIEX_BUS, 0, MAX_HB_BUSES,
			    NULL) < 0) {
				err = -1;
				break;
			}
		}
		rc++;
		if (rc == nrc) {
			rc = 0;
			br++;
			if (br == nhb)
				br = 0;
		}
	}

	if (err != 0) {
		int i;

		for (i = 0; i < nhb; ++i)
			topo_node_unbind(hb[br]);
		for (i = 0; i < nrc; ++i)
			topo_node_unbind(rcs[rc]);
	}

	topo_mod_free(mod, rcs, nrc * sizeof (tnode_t *));
	topo_mod_free(mod, hb, nhb * sizeof (tnode_t *));

	return (err);
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
declare_buses(topo_mod_t *mod, busorrc_t *list, tnode_t *ptn, int nhb)
{
	int err = 0;
	busorrc_t *p;
	tnode_t **hb;
	did_t *link;
	int br, bus;

	/*
	 * Allocate an array to point at the hostbridge tnode_t pointers.
	 */
	if ((hb = topo_mod_zalloc(mod, nhb * sizeof (tnode_t *))) == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	br = bus = 0;
	for (p = list; p != NULL; p = p->br_nextbus) {
		topo_mod_dprintf(mod,
		    "declaring (%x,%x)\n", p->br_ba_bc, p->br_ba_ac);

		if ((link =
		    did_create(mod, p->br_din, 0, br, NO_RC, bus)) == NULL) {
			err = -1;
			break;
		}

		if (hb[br] == NULL) {
			hb[br] = hb_process(mod, ptn, br, bus, p->br_din, link);
			if (hb[br] == NULL) {
				err = -1;
				break;
			}
		} else {
			did_link_set(mod, hb[br], link);
			if (topo_mod_enumerate(mod,
			    hb[br], PCI_BUS, PCI_BUS, bus, bus, link) < 0) {
				err = -1;
				break;
			}
		}
		br++;
		if (br == nhb) {
			br = 0;
			bus++;
		}
	}

	if (err != 0) {
		int i;

		for (i = 0; i < nhb; ++i)
			topo_node_unbind(hb[br]);
	}

	topo_mod_free(mod, hb, nhb * sizeof (tnode_t *));
	return (err);
}
