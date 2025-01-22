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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * sun4u specific DDI implementation
 */
#include <sys/bootconf.h>
#include <sys/conf.h>
#include <sys/machsystm.h>
#include <sys/idprom.h>
#include <sys/promif.h>


/*
 * Favored drivers of this implementation
 * architecture.  These drivers MUST be present for
 * the system to boot at all.
 */
char *impl_module_list[] = {
	"rootnex",
	"options",
	"sad",		/* Referenced via init_tbl[] */
	"pseudo",
	"clone",
	"scsi_vhci",
	(char *)0
};

/*
 * Check the status of the device node passed as an argument.
 *
 *	if ((status is OKAY) || (status is DISABLED))
 *		return DDI_SUCCESS
 *	else
 *		print a warning and return DDI_FAILURE
 */
/*ARGSUSED*/
int
check_status(int id, char *buf, dev_info_t *parent)
{
	char status_buf[64];
	extern int status_okay(int, char *, int);

	/*
	 * is the status okay?
	 */
	if (status_okay(id, status_buf, sizeof (status_buf)))
		return (DDI_SUCCESS);

	return (DDI_FAILURE);
}
