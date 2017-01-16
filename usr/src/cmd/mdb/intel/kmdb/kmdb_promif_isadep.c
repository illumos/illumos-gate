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

/*
 * "PROM" interface
 */

#include <sys/types.h>
#include <sys/promif.h>

#include <kmdb/kmdb_promif_impl.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kmdb_dpi.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb.h>

struct boot_syscalls *kmdb_sysp;

ssize_t
kmdb_prom_obp_writer(caddr_t buf, size_t len)
{
	int i;

	for (i = 0; i < len; i++)
		prom_putchar(*buf++);

	return (len);
}

/*ARGSUSED*/
ihandle_t
kmdb_prom_get_handle(char *name)
{
	/* no handles here */
	return (0);
}

char *
kmdb_prom_get_ddi_prop(kmdb_auxv_t *kav, char *propname)
{
	int i;

	if (kav->kav_pcache != NULL) {
		for (i = 0; i < kav->kav_nprops; i++) {
			kmdb_auxv_nv_t *nv = &kav->kav_pcache[i];
			if (strcmp(nv->kanv_name, propname) == 0)
				return (nv->kanv_val);
		}
	}

	return (NULL);
}

/*ARGSUSED*/
void
kmdb_prom_free_ddi_prop(char *val)
{
}

/*
 * This function is actually about checking if we are using
 * local console versus serial console. Serial console can be named
 * "ttyX" where X is [a-d], or "usb-serial".
 */
int
kmdb_prom_stdout_is_framebuffer(kmdb_auxv_t *kav)
{
	char *dev;

	/*
	 * The property "output-device" value is set in property cache, and
	 * is based on either "output-device" or "console" properties from
	 * the actual system. We can't use the official promif version, as we
	 * need to ensure that property lookups come from our property cache.
	 */

	if ((dev = kmdb_prom_get_ddi_prop(kav, "output-device")) == NULL)
		return (0);

	if (strncmp(dev, "tty", 3) == 0)
		return (0);
	if (strcmp(dev, "usb-serial") == 0)
		return (0);

	/* Anything else is classified as local console. */
	return (1);
}
