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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * SD card module support.
 */

#include <sys/modctl.h>
#include <sys/sdcard/sda_impl.h>

/*
 * Static Variables.
 */

static struct modlmisc modlmisc = {
	&mod_miscops,
	"SD Card Architecture",
};

static struct modlinkage modlinkage = {
	MODREV_1, { &modlmisc, NULL }
};

/*
 * DDI entry points.
 */

int
_init(void)
{
	int	rv;

	sda_cmd_init();
	sda_nexus_init();

	if ((rv = mod_install(&modlinkage)) != 0) {
		sda_cmd_fini();
		sda_nexus_fini();
	}

	return (rv);
}

int
_fini(void)
{
	int	rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		sda_cmd_fini();
		sda_nexus_fini();
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
