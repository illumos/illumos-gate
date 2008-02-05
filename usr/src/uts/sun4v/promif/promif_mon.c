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

#define	PROMIF_ISPRINT(c)	(((c) >= ' ') && ((c) <= '~'))

static int promif_ask_before_reset =
#ifdef _KMDB
	1;
#else
	0;
#endif

/*ARGSUSED*/
int
promif_exit_to_mon(void *p)
{
	PIL_DECL(pil);

	PIL_SET7(pil);

	prom_printf("Program terminated\n");

	if (promif_ask_before_reset) {
		prom_printf("Press any key to reboot.");
		(void) prom_getchar();
	}

	(void) hv_mach_sir();

	/* should not return */
	ASSERT(0);

	PIL_REST(pil);

	return (0);
}

/*ARGSUSED*/
int
promif_enter_mon(void *p)
{
	char		cmd;
	static char	*prompt = "c)ontinue, s)ync, r)eset? ";
	PIL_DECL(pil);

	PIL_SET7(pil);

#ifndef _KMDB
	idle_other_cpus();
#endif

	for (;;) {
		prom_printf("%s", prompt);
		cmd = promif_getchar();
		prom_printf("%c\n", cmd);

		switch (cmd) {

		case 'r':
			prom_printf("Resetting...\n");

			(void) hv_mach_sir();

			/* should not return */
			ASSERT(0);
			break;

		case '\r':
			break;

		case 's':
			{
#ifdef _KMDB
				kmdb_dpi_kernpanic(kmdb_dpi_get_master_cpuid());
#else
				cell_t arg = p1275_ptr2cell("sync");

				(void) vx_handler(&arg);
#endif
			}

			/* should not return */
			ASSERT(0);
			break;

		case 'c':
#ifndef _KMDB
			resume_other_cpus();
#endif
			PIL_REST(pil);

			return (0);

		default:
			if (PROMIF_ISPRINT(cmd))
				prom_printf("invalid option (%c)\n", cmd);
			break;
		}
	}

	_NOTE(NOTREACHED)
}
