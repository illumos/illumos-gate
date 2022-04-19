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
 * Copyright 2005 Sun Microsystems, Inc.   All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains functions that implement the fdisk menu commands.
 */
#include "global.h"
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/stat.h>

#include <sys/dklabel.h>

#include "main.h"
#include "analyze.h"
#include "menu.h"
#include "menu_developer.h"
#include "param.h"
#include "misc.h"
#include "label.h"
#include "startup.h"
#include "partition.h"
#include "prompts.h"
#include "checkdev.h"
#include "io.h"
#include "ctlr_scsi.h"
#include "auto_sense.h"
#include "hardware_structs.h"

extern	struct menu_item menu_developer[];


int
c_developer(void)
{

	cur_menu++;
	last_menu = cur_menu;

	/*
	 * Run the menu.
	 */
	run_menu(menu_developer, "DEVELOPER", "developer", 0);
	cur_menu--;
	return (0);
}

int
dv_disk(void)
{
	struct disk_info *diskp;

	diskp = disk_list;
	while (diskp != NULL) {

		(void) printf("\ndisk_name %s  ", diskp->disk_name);
		(void) printf("disk_path %s\n", diskp->disk_path);
		(void) printf("ctlr_cname = %s  ",
		    diskp->disk_ctlr->ctlr_cname);
		(void) printf("cltr_dname = %s  ",
		    diskp->disk_ctlr->ctlr_dname);
		(void) printf("ctype_name = %s\n",
		    diskp->disk_ctlr->ctlr_ctype->ctype_name);
		(void) printf("ctype_ctype = %d\n",
		    diskp->disk_ctlr->ctlr_ctype->ctype_ctype);
		(void) printf("devfsname = %s\n", diskp->devfs_name);
		diskp = diskp->disk_next;
	}
	return (0);
}

int
dv_cont(void)
{
	struct ctlr_info *contp;

	contp = ctlr_list;
	while (contp != NULL) {

		(void) printf("\nctype_name = %s ",
		    contp->ctlr_ctype->ctype_name);
		(void) printf("cname = %s dname =  %s ",
		    contp->ctlr_cname, contp->ctlr_dname);
		(void) printf("ctype_ctype = %d\n",
		    contp->ctlr_ctype->ctype_ctype);
		contp = contp->ctlr_next;
	}
	return (0);
}

int
dv_cont_chain(void)
{
	struct mctlr_list *ctlrp;

	ctlrp = controlp;

	if (ctlrp == NULL)
		(void) printf("ctlrp is NULL!!\n");

	while (ctlrp != NULL) {
		(void) printf("ctlrp->ctlr_type->ctype_name = %s\n",
		    ctlrp->ctlr_type->ctype_name);
		ctlrp = ctlrp->next;
	}
	return (0);
}

int
dv_params(void)
{
	(void) printf("ncyl = %d\n", ncyl);
	(void) printf("acyl = %d\n", acyl);
	(void) printf("pcyl = %d\n", pcyl);
	(void) printf("nhead = %d\n", nhead);
	(void) printf("nsect = %d\n", nsect);

	return (0);
}
