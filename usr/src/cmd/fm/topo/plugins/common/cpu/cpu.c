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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/libtopo_enum.h>
#include <sys/types.h>
#include <sys/processor.h>
#include <string.h>
#include <kstat.h>

#define	SERIALNUMPROP	"SERIAL-ID"
#define	STATUSPROP	"CPU-STATUS"

int topo_cpu_init(void);
void topo_cpu_fini(void);
void topo_cpu_enum(tnode_t *);

static struct tenumr cpu_enumr = {
	NULL,
	topo_cpu_init,
	topo_cpu_fini,
	topo_cpu_enum
};

struct tenumr *
_enum_init(void)
{
	return (&cpu_enumr);
}

int
topo_cpu_init(void)
{
	return (TE_INITOK);
}

void
topo_cpu_fini(void)
{
}

static void
cpu_fru_prop(tnode_t *tn)
{
	const char *pv;

	if ((pv = topo_get_prop(tn, PLATFRU)) != NULL)
		return;
	if ((pv = topo_get_prop(topo_parent(tn), PLATFRU)) != NULL)
		(void) topo_set_prop(tn, PLATFRU, pv);
}

static void
cpu_serialid_prop(tnode_t *tn, uint32_t cpuid, int status)
{
	kstat_named_t *kn;
	kstat_ctl_t *kc;
	uint64_t serialid;
	kstat_t *ksp;
	char as_str[21];	/* uint64_t will have as many as 20 digits */
	int i;

	(void) snprintf(as_str, 21, "%d", status);
	(void) topo_set_prop(tn, STATUSPROP, as_str);

	if ((kc = kstat_open()) == NULL)
		return;

	if ((ksp = kstat_lookup(kc, "cpu_info", cpuid, NULL)) == NULL) {
		(void) kstat_close(kc);
		return;
	}

	if (kstat_read(kc, ksp, NULL) == -1) {
		(void) kstat_close(kc);
		return;
	}

	for (kn = ksp->ks_data, i = 0; i < ksp->ks_ndata; i++, kn++) {
		if (strcmp(kn->name, "device_ID") == 0) {
			serialid = kn->value.ui64;
			(void) snprintf(as_str, 21, "%llu", serialid);
			(void) topo_set_prop(tn, SERIALNUMPROP, as_str);
			break;
		}
	}
	(void) kstat_close(kc);
}

void
topo_cpu_enum(tnode_t *node)
{
	tnode_t *self;
	tnode_t *pn;
	int c, s, min, max;

	/*
	 * This is a dirt simple enumerator that relies on the static
	 * numbering scheme the platforms we care about seem to follow.
	 * The node we're being asked to enumerate may have either a
	 * single id or a range of ids.  We just use p_online() to see
	 * if that id of cpu is present.  If so, we'll also try to find
	 * the serial number and set a property containing that.
	 */
	topo_get_instance_range(node, &min, &max);
	if (min < 0 || max < 0) {
		topo_out(TOPO_DEBUG,
		    "Unexpected cpu instance range min = %d - max = %d.\n",
		    min, max);
		return;
	}
	for (c = min; c <= max; c++) {
		/*
		 * If we get an error, we'll assume the processor isn't
		 * present.
		 */
		if ((s = p_online(c, P_STATUS)) < 0)
			continue;
		self = topo_set_instance_num(node, c);
		cpu_fru_prop(self);
		cpu_serialid_prop(self, c, s);
		/*
		 * If this cpu is a descendant of a topo node that's
		 * not enumerated but whose instance number is
		 * unambiguous, we now know that ancestor is
		 * present, and can enumerate it.
		 */
		pn = topo_parent(node);
		while (pn != NULL) {
			if (topo_get_instance_num(pn) < 0) {
				topo_get_instance_range(pn, &min, &max);
				if (min == max && min >= 0)
					(void) topo_set_instance_num(pn, min);
			}
			pn = topo_parent(pn);
		}
	}
}
