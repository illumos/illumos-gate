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

/*
 * PICL Littleneck platform plug-in to create environment tree nodes.
 */
#define	_POSIX_PRIORITY_SCHEDULING 1

#include <picl.h>
#include <picltree.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <libintl.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <semaphore.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include <sys/systeminfo.h>
#include <psvc_objects.h>

static psvc_opaque_t hdlp;

#define	PSVC_PLUGIN_VERSION	PICLD_PLUGIN_VERSION_1

#pragma init(psvc_psr_plugin_register)	/* place in .init section */

typedef struct {
	char	name[32];
	picl_nodehdl_t  node;
} picl_psvc_t;

extern struct handle {
	uint32_t	obj_count;
	picl_psvc_t *objects;
	FILE *fp;
} psvc_hdl;

void psvc_psr_plugin_init(void);
void psvc_psr_plugin_fini(void);

picld_plugin_reg_t psvc_psr_reg = {
	PSVC_PLUGIN_VERSION,
	PICLD_PLUGIN_CRITICAL,
	"PSVC_PSR",
	psvc_psr_plugin_init,
	psvc_psr_plugin_fini
};

#define	PSVC_INIT_ERR		gettext("%s: Error in psvc_init(): %s\n")
#define	PTREE_DELETE_NODE_ERR	gettext("%s: ptree_delete_node() failed: %s\n")
#define	PTREE_GET_NODE_ERR			\
	gettext("%s: ptree_get_node_by_path() failed: %s\n")

extern int ptree_get_node_by_path(const char *, picl_nodehdl_t *);

struct node_file {
	char	path[256];
	char	file[256];
} dev_pr_info[] = {
{"/SYSTEM/CPU0_MOD_CARD",
	"/devices/pci@8,700000/ebus@5/i2c@1,30/temperature@0,30:die_temp"},
{"/SYSTEM/CPU1_MOD_CARD",
	"/devices/pci@8,700000/ebus@5/i2c@1,30/temperature@0,98:die_temp"},
{"/SYSTEM/AT24C64_A0_1",
	"/devices/pci@8,700000/ebus@5/i2c@1,2e/dimm@1,a0:dimm"},
{"/SYSTEM/AT24C64_A2_1",
	"/devices/pci@8,700000/ebus@5/i2c@1,2e/dimm@1,a2:dimm"},
{"/SYSTEM/AT24C64_A4_1",
	"/devices/pci@8,700000/ebus@5/i2c@1,2e/dimm@1,a4:dimm"},
{"/SYSTEM/AT24C64_A6_1",
	"/devices/pci@8,700000/ebus@5/i2c@1,2e/dimm@1,a6:dimm"},
{"/SYSTEM/AT24C64_A8_1",
	"/devices/pci@8,700000/ebus@5/i2c@1,2e/dimm@1,a8:dimm"},
{"/SYSTEM/AT24C64_AA_1",
	"/devices/pci@8,700000/ebus@5/i2c@1,2e/dimm@1,aa:dimm"},
{"/SYSTEM/AT24C64_AC_1",
	"/devices/pci@8,700000/ebus@5/i2c@1,2e/dimm@1,ac:dimm"},
{"/SYSTEM/AT24C64_AE_1",
	"/devices/pci@8,700000/ebus@5/i2c@1,2e/dimm@1,ae:dimm"}
};
#define	DEV_PR_COUNT (sizeof (dev_pr_info) / sizeof (struct node_file))

static void init_err(char *fmt, char *arg1, char *arg2)
{
	char msg[256];

	sprintf(msg, fmt, arg1, arg2);
	syslog(LOG_ERR, msg);
}

void
psvc_psr_plugin_init(void)
{
	char *funcname = "psvc_plugin_init";
	int32_t i;
	int err;
	boolean_t present;
	/*
	 * So the volatile read/write routines can retrieve data from
	 * psvc or picl
	 */
	err = psvc_init(&hdlp);
	if (err != 0) {
		init_err(PSVC_INIT_ERR, funcname, strerror(errno));

	}

	/*
	 * Remove nodes whose devices aren't present from the picl tree.
	 */
	for (i = 0; i < psvc_hdl.obj_count; ++i) {
		picl_psvc_t *objp;
		uint64_t features;
		objp = &psvc_hdl.objects[i];

		err = psvc_get_attr(hdlp, objp->name, PSVC_PRESENCE_ATTR,
			&present);
		if (err != PSVC_SUCCESS)
			continue;
		err = psvc_get_attr(hdlp, objp->name, PSVC_FEATURES_ATTR,
			&features);
		if (err != PSVC_SUCCESS)
			continue;
		if ((features & (PSVC_DEV_HOTPLUG | PSVC_DEV_OPTION)) &&
			(present == PSVC_ABSENT)) {
			err = ptree_delete_node(objp->node);
			if (err != 0) {
				init_err(PTREE_DELETE_NODE_ERR, funcname,
					picl_strerror(err));
				return;
			}
		}
	}

	/*
	 * Remove PICL device nodes if their /devices file isn't present or
	 * if the device file is present but the open returns ENXIO
	 * which indicates that the node file doesn't represent a device
	 * tree node and is probably a relic from some previous boot config
	 */
	for (i = 0; i < DEV_PR_COUNT; ++i) {
		picl_nodehdl_t	dev_pr_node;
		int fd;
		fd = open(dev_pr_info[i].file, O_RDONLY);
		if (fd != -1) {
			close(fd);
			continue;
		}
		if ((errno != ENOENT) && (errno != ENXIO))
			continue;

		err = ptree_get_node_by_path(dev_pr_info[i].path, &dev_pr_node);
		if (err != 0) {
			init_err(PTREE_GET_NODE_ERR, funcname,
				picl_strerror(err));
			return;
		}

		err = ptree_delete_node(dev_pr_node);
		if (err != 0) {
			init_err(PTREE_DELETE_NODE_ERR, funcname,
				picl_strerror(err));
			return;
		}
	}
	free(psvc_hdl.objects);
}

void
psvc_psr_plugin_fini(void)
{
	psvc_fini(hdlp);
}

void
psvc_psr_plugin_register(void)
{
	picld_plugin_register(&psvc_psr_reg);
}
