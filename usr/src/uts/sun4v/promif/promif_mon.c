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
#include <sys/uadmin.h>
#include <sys/machsystm.h>
#include <sys/hypervisor_api.h>

#ifdef _KMDB

extern int kmdb_dpi_get_master_cpuid(void);
extern void kmdb_dpi_kernpanic(int cpuid);
extern void prom_reboot(char *bootstr);

#define	PIL_DECL(p)
#define	PIL_SET7(p)
#define	PIL_REST(p)

#else

extern int vx_handler(cell_t *argument_array);

#define	PIL_DECL(p) int p
#define	PIL_SET7(p) (p = spl7())
#define	PIL_REST(p) (splx(p))

#endif

#define	PROMIF_ENTER	0
#define	PROMIF_EXIT	1

#define	PROMIF_ISPRINT(c)	(((c) >= ' ') && ((c) <= '~'))

static void promif_mon(int mode);

/*ARGSUSED*/
int
promif_enter_mon(void *p)
{
	PIL_DECL(pil);

	PIL_SET7(pil);

	prom_printf("\n");

#ifdef _KMDB
	promif_mon(PROMIF_ENTER);
#else
	idle_other_cpus();
	promif_mon(PROMIF_ENTER);
	resume_other_cpus();
#endif

	PIL_REST(pil);

	return (0);
}

/*ARGSUSED*/
int
promif_exit_to_mon(void *p)
{
	PIL_DECL(pil);

	PIL_SET7(pil);

	prom_printf("Program terminated\n");

	promif_mon(PROMIF_EXIT);

	PIL_REST(pil);

	return (0);
}

static void
promif_mon(int mode)
{
	char		cmd;
	char		*prompt;
	boolean_t	invalid_option;
#ifdef _KMDB
	static char	*exit_prompt  = "r)eboot, h)alt? ";
#else
	char		value[ 8 ];	/* holds "true" or "false" */
	char		*boot_msg;
	static char	*null_msg = ".\" \"";
	static char	*ignore_msg =
	    "cr .\" Ignoring auto-boot? setting for this boot.\" cr";
	static char	*exit_prompt  = "r)eboot, o)k prompt, h)alt? ";
#endif
	static char	*enter_prompt = "c)ontinue, s)ync, r)eboot, h)alt? ";

	prompt = (mode == PROMIF_EXIT) ? exit_prompt : enter_prompt;

	for (;;) {
		prom_printf("%s", prompt);

		while (hv_cngetchar((uint8_t *)&cmd) != H_EOK)
			;

		prom_printf("%c\n", cmd);

		invalid_option = B_FALSE;

		switch (cmd) {

		case 'r':
			prom_reboot("");
			break;

		case 'h':
			(void) hv_mach_exit(0);
			ASSERT(0);

			break;

#ifndef _KMDB
		case 'o':
			/*
			 * This option gives the user an "ok" prompt after
			 * the system reset regardless of the value of
			 * auto-boot?  We offer this option because halt(1m)
			 * doesn't leave the user at the ok prompt (as it
			 * does on non-ldoms systems).  If auto-boot? is
			 * true tell user we are overriding the setting
			 * for this boot only.
			 */
			if (mode == PROMIF_EXIT) {
				bzero(value, sizeof (value));
				(void) promif_stree_getprop(prom_optionsnode(),
				    "auto-boot?", value);
				boot_msg = strcmp(value, "true") ? null_msg :
					ignore_msg;
				(void) promif_ldom_setprop("reboot-command",
				    boot_msg, strlen(boot_msg) + 1);
				(void) hv_mach_sir();
			} else {
				invalid_option = B_TRUE;
			}
			break;
#endif

		case '\r':
			break;

		case 's':
			if (mode == PROMIF_ENTER) {
#ifdef _KMDB
				kmdb_dpi_kernpanic(kmdb_dpi_get_master_cpuid());
#else
				cell_t arg = p1275_ptr2cell("sync");
				(void) vx_handler(&arg);
#endif
			} else {
				invalid_option = B_TRUE;
			}
			break;

		case 'c':
			if (mode == PROMIF_ENTER) {
				return;
			} else {
				invalid_option = B_TRUE;
			}
			break;

		default:
			invalid_option = B_TRUE;
			break;
		}

		if (invalid_option && PROMIF_ISPRINT(cmd))
			prom_printf("invalid option (%c)\n", cmd);
	}

	_NOTE(NOTREACHED)
}
