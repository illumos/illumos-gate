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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif_impl.h>
#include <sys/hypervisor_api.h>

/*
 * Reboot Command String
 *
 * The prom_reboot() CIF handler takes an optional string containing
 * arguments to the boot command that are to be applied to the reboot.
 * This information is used to create a full boot command string that
 * is stored in a well known ldom variable (REBOOT_CMD_VAR_NAME). The
 * string is constructed to take the following form:
 *
 *	boot <specified boot arguments><NULL>
 *
 * When the domain comes back up, OBP consults this variable. If set,
 * it will use the unmodified boot command string to boot the domain.
 * The maximum length of the boot command is specified by the constant
 * REBOOT_CMD_MAX_LEN. If the specified arguments cause the command
 * string to exceed this length, the arguments are truncated.
 */
#define	REBOOT_CMD_VAR_NAME		"reboot-command"
#define	REBOOT_CMD_BASE			"boot "
#define	REBOOT_CMD_MAX_LEN		256
#define	REBOOT_CMD_ARGS_MAX_LEN		(REBOOT_CMD_MAX_LEN - 		\
					prom_strlen(REBOOT_CMD_BASE) - 1)
int
promif_reboot(void *p)
{
	cell_t	*ci = (cell_t *)p;
	int	rv = 0;
#ifndef _KMDB
	char	*bootargs;
	char	bootcmd[REBOOT_CMD_MAX_LEN];
	char	*cmd_end;
	int	cmd_len;
#endif

	/* one argument expected */
	ASSERT(ci[1] == 1);

#ifndef _KMDB
	bootargs = p1275_cell2ptr(ci[3]);

	if (bootargs == NULL)
		bootargs = "";

	/* verify the length of the command string */
	cmd_len = prom_strlen(REBOOT_CMD_BASE) + prom_strlen(bootargs) + 1;

	if (cmd_len > REBOOT_CMD_MAX_LEN) {
		/*
		 * Unable to set the requested boot arguments.
		 * Truncate them so that the boot command will
		 * fit within the maximum length. This follows
		 * the policy also used by OBP.
		 */
		cmd_end = bootargs + REBOOT_CMD_ARGS_MAX_LEN;
		*cmd_end = '\0';

		prom_printf("WARNING: reboot command length (%d) too long, "
		    "truncating command arguments\n", cmd_len);
	}

	/* construct the boot command string */
	(void) prom_sprintf(bootcmd, "%s%s", REBOOT_CMD_BASE, bootargs);

	cmd_len = prom_strlen(bootcmd) + 1;
	ASSERT(cmd_len <= REBOOT_CMD_MAX_LEN);

	CIF_DBG_REBOOT("bootcmd='%s'\n", bootcmd);

	/* attempt to set the ldom variable */
	if (promif_ldom_setprop(REBOOT_CMD_VAR_NAME, bootcmd, cmd_len) == -1) {
		prom_printf("WARNING: unable to store boot command for "
		    "use on reboot\n");
	}
#endif

	prom_printf("Resetting...\n");

	rv = hv_mach_sir();

	/* should not return */
	ASSERT(0);

	return (rv);
}
