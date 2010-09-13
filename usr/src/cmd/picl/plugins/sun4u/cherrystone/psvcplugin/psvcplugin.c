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
 * PICL Cherrystone platform plug-in to remove environment tree nodes
 * if corresponding physical device is not present.  For creating
 * the picltree nodes, see:
 * usr/src/cmd/picl/plugins/sun4u/psvc/psvcplugin/psvcplugin.c
 */
#define	_POSIX_PRIORITY_SCHEDULING 1

#include <picl.h>
#include <picltree.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include  <stdio.h>
#include  <libintl.h>
#include <limits.h>
#include  <ctype.h>
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

/* ======================================== */
struct node_file {
	char	path[256];
	char	file[256];
} dev_pr_info[] = {
/* Search for memory */
{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD/24C02_A0_0",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@0,a0:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD/24C02_A2_0",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@0,a2:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD/24C02_A4_0",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@0,a4:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD/24C02_A6_0",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@0,a6:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD/24C02_A8_0",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@0,a8:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD/24C02_AA_0",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@0,aa:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD/24C02_AC_0",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@0,ac:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD/24C02_AE_0",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@0,ae:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD/24C02_A0_1",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@1,a0:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD/24C02_A2_1",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@1,a2:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD/24C02_A4_1",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@1,a4:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD/24C02_A6_1",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@1,a6:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD/24C02_A8_1",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@1,a8:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD/24C02_AA_1",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@1,aa:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD/24C02_AC_1",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@1,ac:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD/24C02_AE_1",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@1,ae:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD/24C02_A0_2",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@2,a0:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD/24C02_A2_2",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@2,a2:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD/24C02_A4_2",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@2,a4:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD/24C02_A6_2",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@2,a6:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD/24C02_A8_2",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@2,a8:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD/24C02_AA_2",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@2,aa:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD/24C02_AC_2",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@2,ac:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD/24C02_AE_2",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@2,ae:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD/24C02_A0_3",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@3,a0:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD/24C02_A2_3",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@3,a2:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD/24C02_A4_3",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@3,a4:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD/24C02_A6_3",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@3,a6:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD/24C02_A8_3",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@3,a8:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD/24C02_AA_3",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@3,aa:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD/24C02_AC_3",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@3,ac:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD/24C02_AE_3",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@3,ae:fru"},
/* Search for 64Kbit SPD */
{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD/24C64_A0_4",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@4,a0:fru"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD/24C64_A2_4",
	"/devices/pci@9,700000/ebus@1/i2c@1,2e/fru@4,a2:fru"},

/*
 * Search for CPU Module cards.  We check one cpu's die temperature
 * sensor If not present, then we remove the entire node since module
 * cards come with two cpus in them, each cpu having a die temperature
 * sensor
 */

{"/SYSTEM/MOTHERBOARD/CPU_0_2_MOD_SLOT/CPU_0_2_MOD_CARD",
	"/devices/pci@9,700000/ebus@1/i2c@1,30/temperature@0,30:die_temp"},
{"/SYSTEM/MOTHERBOARD/CPU_1_3_MOD_SLOT/CPU_1_3_MOD_CARD",
	"/devices/pci@9,700000/ebus@1/i2c@1,30/temperature@0,52:die_temp"},
{"/SYSTEM/SIB_BOARD",
	"/devices/pci@9,700000/ebus@1/i2c@1,30/temperature@0,98:die_temp"},
/*
 * Check to see if RSC Card FRU is present.  If it is not present,
 * then RSC Card is not present, and so we remove those nodes from
 * picl tree as well.
 */
{"/SYSTEM/RSC_SLOT/RSC_CARD/24C64_A6_5",
	"/devices/pci@9,700000/ebus@1/i2c@1,30/fru@0,a6:fru"},
{"/SYSTEM/RSC_SLOT/RSC_CARD",
	"/devices/pci@9,700000/ebus@1/i2c@1,30/fru@0,a6:fru"}
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
	char *funcname = "psvc_plugin_psr_init";
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
			syslog(LOG_ERR, "Bad path: %s", dev_pr_info[i].path);
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
	hdlp = NULL;
}

void
psvc_psr_plugin_register(void)
{
	picld_plugin_register(&psvc_psr_reg);
}
