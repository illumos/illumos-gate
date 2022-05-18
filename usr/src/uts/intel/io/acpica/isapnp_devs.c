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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/acpica.h>
#include <sys/kmem.h>
#include <sys/types.h>

/*
 * For historical reasons certain ISA or onboard devices have their name in
 * the device tree altered and other changes made.
 *
 * If a device ID matches here, we will create the devi node name, model, and
 * (if set) compatible property.  The compatible property should already be in
 * 1275 form, and _overwrites_ any identifier from enumeration.
 *
 * In most cases, ISA-like devices not present in this table _will not be
 * enumerated_.  Serial ports are a special case handled because of bugs in
 * old ACPI tables, see enumerate_BIOS_serial() in the isa(4D) nexus.
 */
static const isapnp_desc_t isapnp_descs[] = {
	/*
	 * This wildcard entry catches anything in the PNP keyboard class, and
	 * sets it compatible with the IBM Enhanced 101/102-key, to which
	 * kb8042 actually binds
	 */
	{ "PNP03", B_TRUE, "keyboard", "pnpPNP,303", "System keyboard" },

	/* ecpp(4D) binds to "lp" */
	{ "PNP0400", B_FALSE, "lp", NULL, "Standard LPT printer port" },
	{ "PNP0401", B_FALSE, "lp", NULL, "ECP printer port" },
	{ "ISY0060", B_FALSE, "lp", NULL, "Parallel port" },

	/* asy(4D) binds to "asy" */
	{ "PNP0500", B_FALSE, "asy", NULL, "Standard PC COM port" },
	{ "PNP0501", B_FALSE, "asy", NULL, "16550A-compatible COM port" },
	{ "ISY0020", B_FALSE, "asy", NULL, "Serial port" },

	/* fdc(4D) binds to "fdc" */
	{ "PNP0700", B_FALSE, "fdc", NULL,
	    "PC standard floppy disk controller" },
	{ "PNP0701", B_FALSE, "fdc", NULL,
	    "Standard floppy controller supporting MS Device Bay Spec" },
	{ "ISY0050", B_FALSE, "fdc", NULL,
	    "Floppy disk controller" },

	/* tpm(4D) binds to "tpm" */
	{ "PNP0C31", B_FALSE, "tpm", NULL, "Generic Trusted Platform Module" },
	{ "ATM1200", B_FALSE, "tpm", NULL, "Generic Trusted Platform Module" },
	{ "IFX0102", B_FALSE, "tpm", NULL, "Generic Trusted Platform Module" },
	{ "BCM0101", B_FALSE, "tpm", NULL, "Generic Trusted Platform Module" },
	{ "NSC1200", B_FALSE, "tpm", NULL, "Generic Trusted Platform Module" },

	/*
	 * This wildcard entry catches anything in the PNP mouse class, and
	 * sets it compatible with the Microsoft PS/2-style, to which
	 * mouse8042 actually binds.
	 */
	{ "PNP0F", B_TRUE, "mouse", "pnpPNP,f03", "System mouse" },

	{ "ISY0030", B_FALSE, "mouse", "pnpPNP,f03", "System mouse" },
	{ "SYN010B", B_FALSE, "mouse", "pnpPNP,f03", "Synaptics mouse pad" },

	{ NULL, B_FALSE, NULL, NULL, NULL },
};

/*
 * Return the first record found matching the pnpid list
 */
const isapnp_desc_t *
isapnp_desc_lookup(const device_id_t *pnpid)
{
	const device_id_t *d;
	const isapnp_desc_t *m;

	while (pnpid != NULL) {
		for (m = isapnp_descs; m->ipnp_id != NULL; m++) {
			if (m->ipnp_prefix) {
				if (strncmp(pnpid->id, m->ipnp_id,
				    strlen(m->ipnp_id)) == 0) {
					return (m);
				}
			} else if (strcmp(pnpid->id, m->ipnp_id) == 0) {
				return (m);
			}
		}
		pnpid = pnpid->next;
	}

	return (NULL);
}
