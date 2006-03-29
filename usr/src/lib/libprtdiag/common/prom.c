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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <kvm.h>
#include <varargs.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/openpromio.h>
#include <kstat.h>
#include <libintl.h>
#include <syslog.h>
#include <sys/dkio.h>
#include "pdevinfo.h"
#include "display.h"
#include "pdevinfo_sun4u.h"
#include "display_sun4u.h"
#include "libprtdiag.h"

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif


void
disp_prom_version(Prom_node *flashprom)
{
	Prop *version;
	char *vers;		/* OBP version */
	char *temp;

	/* Look version */
	version = find_prop(flashprom, "version");

	vers = (char *)get_prop_val(version);

	if (vers != NULL) {
		log_printf("  %s   ", vers, 0);

		/*
		 * POST string follows the NULL terminated OBP
		 * version string. Do not attempt to print POST
		 * string unless node size is larger than the
		 * length of the OBP version string.
		 */
		if ((strlen(vers) + 1) < version->size) {
			temp = vers + strlen(vers) + 1;
			log_printf("%s", temp, 0);
		}
	}

	log_printf("\n", 0);
}


void
platform_disp_prom_version(Sys_tree *tree)
{
	Board_node *bnode;
	Prom_node *pnode;

	bnode = tree->bd_list;

	/* Display Prom revision header */
	log_printf(dgettext(TEXT_DOMAIN, "System PROM "
		"revisions:\n"), 0);
	log_printf("----------------------\n", 0);

	if ((pnode = find_device(bnode, 0x1F, SBUS_NAME)) == NULL) {
		pnode = find_pci_bus(bnode->nodes, 0x1F, 1);
	}

	/*
	 * in case of platforms with multiple flashproms, find and
	 * display all proms with a "version"(OBP) property. bug 4187301
	 */
	for (pnode = dev_find_node(pnode, "flashprom"); pnode != NULL;
		pnode = dev_next_node(pnode, "flashprom")) {
		    if (find_prop(pnode, "version") != NULL) {
				disp_prom_version(pnode);
		}
	}
}

int
get_pci_class_code_reg(Prom_node *card_node)
{
	void	*value;

	/*
	 * Get the class-code of this node and return it
	 * if it exists. Otherwise return (-1).
	 */
	value = get_prop_val(find_prop(card_node, "class-code"));
	if (value != NULL)
		return (*(int *)value);
	else
		return (-1);
}
