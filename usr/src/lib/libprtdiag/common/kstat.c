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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 * Copyright (c) 2020 Peter Tribble.
 */

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

/*
 * This module does the reading and interpreting of sun4u system
 * kstats. It is overlaid by a platform-specific implementation as
 * appropriate.
 */
void
read_platform_kstats(Sys_tree *tree, struct system_kstat_data *sys_kstat,
	struct envctrl_kstat_data *ep)
{
}

/*
 * This function does the reading and interpreting of sun4u system
 * kstats.
 */
void
read_sun4u_kstats(Sys_tree *tree, struct system_kstat_data *sys_kstat)
{
	kstat_ctl_t	*kc;
	int		i;
	struct envctrl_kstat_data *ep;

	if ((kc = kstat_open()) == NULL) {
		return;
	}

	/* Initialize the kstats structure */
	sys_kstat->sys_kstats_ok = 0;
	sys_kstat->envctrl_kstat_ok = 0;
	for (i = 0; i < MAX_DEVS; i++) {
		ep = &sys_kstat->env_data;
		ep->ps_kstats[i].instance = I2C_NODEV;
		ep->fan_kstats[i].instance = I2C_NODEV;
		ep->encl_kstats[i].instance = I2C_NODEV;
	}

	read_platform_kstats(tree, sys_kstat, ep);
}
