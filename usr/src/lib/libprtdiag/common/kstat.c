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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <kvm.h>
#include <varargs.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/openpromio.h>
#include <kstat.h>
#include <libintl.h>
#include <syslog.h>
#include <sys/dkio.h>
#include "pdevinfo.h"
#include "display.h"
#include "pdevinfo_sun4u.h"
#include "display_sun4u.h"
#include "libprtdiag.h"

/*
 * This module does the reading and interpreting of sun4u system
 * kstats. These kstats are created by the following drivers:
 * fhc, environ, sysctrl. Each board in the tree should have
 * kstats created for it.  There are also system wide kstats that
 * are created.
 */
void
read_platform_kstats(Sys_tree *tree, struct system_kstat_data *sys_kstat,
	struct bd_kstat_data *bdp, struct envctrl_kstat_data *ep)
{
	Board_node	*bnode;
	kstat_ctl_t	*kc;
	kstat_t		*ksp;
	kstat_named_t	*knp;
	int		i;
	struct hp_info	*hp;

#ifdef lint
	ep = ep;
#endif
	if ((kc = kstat_open()) == NULL) {
		return;
	}

	/* For each board in the system, read the kstats for it. */
	for (bnode = tree->bd_list; bnode != NULL; bnode = bnode->next) {
		int board;

		/*
		 * Kstat instances numbers are set by fhc, ac, simmstat,
		 * and environ drivers based on their board# property.
		 */
		board = bnode->board_num;
		bdp = &sys_kstat->bd_ksp_list[board];

		/* Try to find an FHC instance for this board number */
		ksp = kstat_lookup(kc, UNIX, board, FHC_KSTAT_NAME);

		/* Atempt to read the FHC kstat */
		if ((ksp != NULL) && (kstat_read(kc, ksp, NULL) == -1)) {
			ksp = NULL;
		}

		/* Now read out the data if the kstat read OK */
		if (ksp != NULL) {
			/*
			 * We set the kstats_ok flag to good here. If we
			 * fail one of the data reads, we set it to bad.
			 */
			bdp->fhc_kstats_ok = 1;

			/*
			 * For each data value, If the Kstat named struct
			 * is found, then get the data out.
			 */
			knp = kstat_data_lookup(ksp, CSR_KSTAT_NAMED);
			if (knp != NULL) {
				bdp->fhc_csr = knp->value.ul;
			} else {
				bdp->fhc_kstats_ok = 0;
			}
			knp = kstat_data_lookup(ksp, BSR_KSTAT_NAMED);
			if (knp != NULL) {
				bdp->fhc_bsr = knp->value.ul;
			} else {
				bdp->fhc_kstats_ok = 0;
			}
		}

		/* Try to find an AC instance for this board number */
		ksp = kstat_lookup(kc, UNIX, board, AC_KSTAT_NAME);

		/* Attempt to read the AC kstat. */
		if ((ksp != NULL) && (kstat_read(kc, ksp, NULL) == -1)) {
			ksp = NULL;
		}

		/* If the AC kstat exists, try to read the data from it. */
		if (ksp != NULL) {
			/*
			 * We set the kstats_ok flag to good here. If we
			 * fail one of the data reads, we set it to bad.
			 */
			bdp->ac_kstats_ok = 1;
			bdp->ac_memstat_ok = 1;

			/*
			 * For each data value, If the Kstat named struct
			 * is found, then get the data out.
			 */

			knp = kstat_data_lookup(ksp, MEMCTL_KSTAT_NAMED);
			if (knp != NULL) {
				bdp->ac_memctl = knp->value.ull;
			} else {
				bdp->ac_kstats_ok = 0;
			}

			knp = kstat_data_lookup(ksp, MEMDECODE0_KSTAT_NAMED);
			if (knp != NULL) {
				bdp->ac_memdecode[0] = knp->value.ull;
			} else {
				bdp->ac_kstats_ok = 0;
			}

			knp = kstat_data_lookup(ksp, MEMDECODE1_KSTAT_NAMED);
			if (knp != NULL) {
				bdp->ac_memdecode[1] = knp->value.ull;
			} else {
				bdp->ac_kstats_ok = 0;
			}

			knp = kstat_data_lookup(ksp, BANK_0_KSTAT_NAMED);
			if (knp != NULL) {
				bdp->mem_stat[0].status = knp->value.c[0];
				bdp->mem_stat[0].condition = knp->value.c[1];
			} else {
				bdp->ac_memstat_ok = 0;
			}

			knp = kstat_data_lookup(ksp, BANK_1_KSTAT_NAMED);
			if (knp != NULL) {
				bdp->mem_stat[1].status = knp->value.c[0];
				bdp->mem_stat[1].condition = knp->value.c[1];
			} else {
				bdp->ac_memstat_ok = 0;
			}

		}

		/* Try to find an simmstat instance for this board number */
		ksp = kstat_lookup(kc, UNIX, board, SIMMSTAT_KSTAT_NAME);

		if (ksp != NULL) {
			if (kstat_read(kc, ksp, NULL) == -1) {
				bdp->simmstat_kstats_ok = 0;
			} else {
				bdp->simmstat_kstats_ok = 1;
				(void) memcpy(&bdp->simm_status, ksp->ks_data,
					sizeof (bdp->simm_status));
			}
		}

		/* Try to find an overtemp kstat instance for this board */
		ksp = kstat_lookup(kc, UNIX, board, OVERTEMP_KSTAT_NAME);

		if (ksp != NULL) {
			if (kstat_read(kc, ksp, NULL) == -1) {
				bdp->temp_kstat_ok = 0;
			} else {
				bdp->temp_kstat_ok = 1;
				(void) memcpy(&bdp->tempstat, ksp->ks_data,
					sizeof (bdp->tempstat));
				/* XXX - this is for 2.5.1 testing.  remove */
				if (sizeof (bdp->tempstat) > ksp->ks_data_size)
					bdp->tempstat.trend = TREND_UNKNOWN;
			}
		}
	}

	/* Read the kstats for the system control board */
	ksp = kstat_lookup(kc, UNIX, 0, SYSCTRL_KSTAT_NAME);

	if ((ksp != NULL) && (kstat_read(kc, ksp, NULL) == -1)) {
		sys_kstat->sys_kstats_ok = 0;
		ksp = NULL;
	}

	if (ksp != NULL) {
		sys_kstat->sys_kstats_ok = 1;

		knp = kstat_data_lookup(ksp, CSR_KSTAT_NAMED);
		if (knp != NULL) {
			sys_kstat->sysctrl = knp->value.c[0];
		} else {
			sys_kstat->sys_kstats_ok = 0;
		}

		knp = kstat_data_lookup(ksp, STAT1_KSTAT_NAMED);
		if (knp != NULL) {
			sys_kstat->sysstat1 = knp->value.c[0];
		} else {
			sys_kstat->sys_kstats_ok = 0;
		}

		knp = kstat_data_lookup(ksp, STAT2_KSTAT_NAMED);
		if (knp != NULL) {
			sys_kstat->sysstat2 = knp->value.c[0];
		} else {
			sys_kstat->sys_kstats_ok = 0;
		}

		knp = kstat_data_lookup(ksp, CLK_FREQ2_KSTAT_NAMED);
		if (knp != NULL) {
			sys_kstat->clk_freq2 = knp->value.c[0];
		} else {
			sys_kstat->sys_kstats_ok = 0;
		}

		knp = kstat_data_lookup(ksp, FAN_KSTAT_NAMED);
		if (knp != NULL) {
			sys_kstat->fan_status = knp->value.c[0];
		} else {
			sys_kstat->sys_kstats_ok = 0;
		}

		knp = kstat_data_lookup(ksp, KEY_KSTAT_NAMED);
		if (knp != NULL) {
			sys_kstat->keysw_status = knp->value.c[0];
		} else {
			sys_kstat->sys_kstats_ok = 0;
		}

		knp = kstat_data_lookup(ksp, POWER_KSTAT_NAMED);
		if (knp != NULL) {
			sys_kstat->power_state =
				(enum power_state)knp->value.l;
		} else {
			sys_kstat->sys_kstats_ok = 0;
		}

		knp = kstat_data_lookup(ksp, CLK_VER_KSTAT_NAME);
		if (knp != NULL) {
			sys_kstat->clk_ver = knp->value.c[0];
		} else {
			/*
			 * the clock version register only appears
			 * on new clock boards
			 */
			sys_kstat->clk_ver = 0;
		}

	}

	/* Read the kstats for the power supply stats */
	ksp = kstat_lookup(kc, UNIX, 0, PSSHAD_KSTAT_NAME);

	if ((ksp != NULL) && (kstat_read(kc, ksp, NULL) != -1)) {
		sys_kstat->psstat_kstat_ok = 1;
		(void) memcpy(&sys_kstat->ps_shadow[0], ksp->ks_data,
			sizeof (sys_kstat->ps_shadow));
	} else {
		sys_kstat->psstat_kstat_ok = 0;
	}

	/* read the overtemp kstat for the system control board */
	/* Try to find an overtemp kstat instance for this board */
	ksp = kstat_lookup(kc, UNIX, CLOCK_BOARD_INDEX, OVERTEMP_KSTAT_NAME);

	if (ksp != NULL) {
		if (kstat_read(kc, ksp, NULL) == -1) {
			sys_kstat->temp_kstat_ok = 0;
		} else {
			sys_kstat->temp_kstat_ok = 1;
			(void) memcpy(&sys_kstat->tempstat, ksp->ks_data,
				sizeof (sys_kstat->tempstat));
			/* XXX - this is for 2.5.1 testing.  remove */
			if (sizeof (sys_kstat->tempstat) > ksp->ks_data_size)
				sys_kstat->tempstat.trend = TREND_UNKNOWN;
		}
	}

	/* Read the reset-info kstat from one of the boards. */
	ksp = kstat_lookup(kc, UNIX, 0, RESETINFO_KSTAT_NAME);

	if (ksp == NULL) {
		sys_kstat->reset_kstats_ok = 0;
	} else if (kstat_read(kc, ksp, NULL) == -1) {
		sys_kstat->reset_kstats_ok = 0;
	} else {
		sys_kstat->reset_kstats_ok = 1;
		(void) memcpy(&sys_kstat->reset_info, ksp->ks_data,
			sizeof (sys_kstat->reset_info));
	}

	/* read kstats for hotplugged boards */
	for (i = 0, hp = &sys_kstat->hp_info[0]; i < MAX_BOARDS; i++, hp++) {
		ksp = kstat_lookup(kc, UNIX, i, BDLIST_KSTAT_NAME);

		if (ksp == NULL) {
			continue;
		}

		if (kstat_read(kc, ksp, NULL) == -1) {
			hp->kstat_ok = 0;
		} else {
			hp->kstat_ok = 1;
			(void) memcpy(&hp->bd_info, ksp->ks_data,
				sizeof (hp->bd_info));
		}
	}

	/* read in the kstat for the fault list. */
	ksp = kstat_lookup(kc, UNIX, 0, FT_LIST_KSTAT_NAME);

	if (ksp == NULL) {
		sys_kstat->ft_kstat_ok = 0;
	} else {
		if (kstat_read(kc, ksp, NULL) == -1) {
			perror("kstat read");
			sys_kstat->ft_kstat_ok = 0;
			return;
		}

		sys_kstat->nfaults = ksp->ks_data_size /
			sizeof (struct ft_list);

		sys_kstat->ft_array =
			(struct ft_list *)malloc(ksp->ks_data_size);

		if (sys_kstat->ft_array == NULL) {
			perror("Malloc");
			exit(2);
		}
		sys_kstat->ft_kstat_ok = 1;
		(void) memcpy(sys_kstat->ft_array, ksp->ks_data,
			ksp->ks_data_size);
	}
}

/*
 * This function does the reading and interpreting of sun4u system
 * kstats. These kstats are created by the following drivers:
 * fhc, environ, sysctrl. Each board in the tree should have
 * kstats created for it.  There are also system wide kstats that
 * are created.
 */
void
read_sun4u_kstats(Sys_tree *tree, struct system_kstat_data *sys_kstat)
{
#if 0
	Board_node 	*bnode;
	kstat_t		*ksp;
	kstat_named_t	*knp;
	struct hp_info *hp;
	struct envctrltwo_kstat_data *ecp;
#endif
	kstat_ctl_t 	*kc;
	int		i;
	struct bd_kstat_data *bdp;
	struct envctrl_kstat_data *ep;

	if ((kc = kstat_open()) == NULL) {
		return;
	}
#ifdef lint
	kc = kc;
#endif

	/* Initialize the kstats structure */
	sys_kstat->sys_kstats_ok = 0;
	sys_kstat->temp_kstat_ok = 0;
	sys_kstat->reset_kstats_ok = 0;
	sys_kstat->ft_kstat_ok = 0;
	sys_kstat->envctrl_kstat_ok = 0;
	for (i = 0; i < MAX_BOARDS; i++) {
		bdp = &sys_kstat->bd_ksp_list[i];
		bdp->ac_kstats_ok = 0;
		bdp->fhc_kstats_ok = 0;
		bdp->simmstat_kstats_ok = 0;
		bdp->temp_kstat_ok = 0;

		sys_kstat->hp_info[i].kstat_ok = 0;
	}
	for (i = 0; i < MAX_DEVS; i++) {
		ep = &sys_kstat->env_data;
		ep->ps_kstats[i].instance = I2C_NODEV;
		ep->fan_kstats[i].instance = I2C_NODEV;
		ep->encl_kstats[i].instance = I2C_NODEV;
	}

	read_platform_kstats(tree, sys_kstat, bdp, ep);
}
