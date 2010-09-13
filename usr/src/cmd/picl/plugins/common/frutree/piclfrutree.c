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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This plugin creates the PICL nodes and properties specified in
 * configuration file.
 * It is used to create the FRU tree for a platform.
 * The configuration file for FRU tree is called "piclfrutree.conf".
 */


#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <alloca.h>
#include <limits.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <sys/stat.h>
#include <libintl.h>
#include <picl.h>
#include <picltree.h>
#include "picld_pluginutil.h"

#define	EM_FAIL	gettext("SUNW_piclfrutree PICL plugin module failed")

static	void	piclfrutree_register(void);
static	void	piclfrutree_init(void);
static	void	piclfrutree_fini(void);

#define	FRUTREE_CONFFILE_NAME		"piclfrutree.conf"

#pragma	init(piclfrutree_register)

static picld_plugin_reg_t  my_reg_info = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_NON_CRITICAL,
	"SUNW_piclfrutree",
	piclfrutree_init,
	piclfrutree_fini
};

static void
piclfrutree_register(void)
{
	(void) picld_plugin_register(&my_reg_info);
}

/*
 * Search for the frutree config file from the platform specific
 * directory to the common directory.
 *
 * The size of outfilename must be PATH_MAX
 */
static int
get_config_file(char *outfilename)
{
	char	nmbuf[SYS_NMLN];
	char	pname[PATH_MAX];

	if (sysinfo(SI_PLATFORM, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, PICLD_PLAT_PLUGIN_DIRF, nmbuf);
		(void) strlcat(pname, FRUTREE_CONFFILE_NAME, PATH_MAX);
		if (access(pname, R_OK) == 0) {
			(void) strlcpy(outfilename, pname, PATH_MAX);
			return (0);
		}
	}

	if (sysinfo(SI_MACHINE, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, PICLD_PLAT_PLUGIN_DIRF, nmbuf);
		(void) strlcat(pname, FRUTREE_CONFFILE_NAME, PATH_MAX);
		if (access(pname, R_OK) == 0) {
			(void) strlcpy(outfilename, pname, PATH_MAX);
			return (0);
		}
	}

	(void) snprintf(pname, PATH_MAX, "%s/%s", PICLD_COMMON_PLUGIN_DIR,
	    FRUTREE_CONFFILE_NAME);

	if (access(pname, R_OK) == 0) {
		(void) strlcpy(outfilename, pname, PATH_MAX);
		return (0);
	}

	return (-1);
}

static void
piclfrutree_init(void)
{
	char		fullfilename[PATH_MAX];
	picl_nodehdl_t	rooth;

	if (get_config_file(fullfilename) < 0)
		return;

	if (ptree_get_root(&rooth) != PICL_SUCCESS)
		return;

	if (picld_pluginutil_parse_config_file(rooth, fullfilename) !=
	    PICL_SUCCESS)
		syslog(LOG_ERR, EM_FAIL);
}

static void
piclfrutree_fini(void)
{
}
