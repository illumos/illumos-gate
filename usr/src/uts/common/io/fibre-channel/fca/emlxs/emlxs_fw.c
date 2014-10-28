/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#define	DRIVER_NAME		"emlxs"
#define	EMLXS_FW_TABLE_DEF

#include <sys/types.h>
#include <sys/modctl.h>
#include <emlxs_version.h>
#include <emlxs_fw.h>

emlxs_firmware_t emlxs_fw_mod_table[] = EMLXS_FW_TABLE;
int emlxs_fw_mod_count = sizeof (emlxs_fw_mod_table) /
    sizeof (emlxs_firmware_t);
char emlxs_fw_mod_name[] = EMLXS_FW_NAME;

static struct modlmisc emlxs_modlmisc = {
	&mod_miscops,
	emlxs_fw_mod_name
};

static struct modlinkage emlxs_modlinkage = {
	MODREV_1,
	(void *)&emlxs_modlmisc,
	NULL
};

int
_init(void)
{
	int rval;

	rval = mod_install(&emlxs_modlinkage);

	return (rval);

} /* _init() */

int
_fini()
{
	int rval;

	rval = mod_remove(&emlxs_modlinkage);

	return (rval);

} /* _fini() */

int
_info(struct modinfo *modinfop)
{
	int rval;

	rval = mod_info(&emlxs_modlinkage, modinfop);

	return (rval);

} /* _fini() */

int
emlxs_fw_get(emlxs_firmware_t *fw)
{
	uint32_t i;
	emlxs_firmware_t *fw_table;

	/* Find matching firmware table entry */
	fw_table = emlxs_fw_mod_table;
	for (i = 0; i < emlxs_fw_mod_count; i++, fw_table++) {
		/* Validate requested fw image */
		if ((fw_table->id == fw->id) &&
		    (fw_table->kern == fw->kern) &&
		    (fw_table->stub == fw->stub) &&
		    (fw_table->sli1 == fw->sli1) &&
		    (fw_table->sli2 == fw->sli2) &&
		    (fw_table->sli3 == fw->sli3) &&
		    (fw_table->sli4 == fw->sli4)) {
			/* Return image data and size */
			fw->image = fw_table->image;
			fw->size = fw_table->size;

			return (0);
		}
	}

	fw->image = NULL;
	fw->size = 0;

	return (1);

} /* emlxs_fw_get() */
