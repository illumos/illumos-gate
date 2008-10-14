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
 * This program is strictly for demonstration purposes and not for
 * production use. It demonstrates how to access the dynamic memory
 * caching statistics and turning variables via the kstat library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stropts.h>
#include <ctype.h>
#include <unistd.h>
#include <memory.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <locale.h>
#include <kstat.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/sysinfo.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/dnlc.h>
#include <sys/vmmeter.h>

#define	TRUE 1
#define	FALSE 0
#define	SDBC_KSTAT_MODULE	"sdbc"
#define	SDBC_KSTAT_DYNMEM	"dynmem"

typedef struct {
	int instance;
	kstat_t *ksp;
	} KSTAT_INFO_DEF;

typedef struct {
	kstat_named_t	*knp;
	char		*named;
	int		newval;
	} DYNMEM_KNP_DEFN;

typedef enum {
MONITOR = 0,
MAXLIST,
AGECT1,
AGECT2,
AGECT3,
SEC1,
SEC2,
SEC3,
PCNT1,
PCNT2,
HDPCNT,
ALLOC,
DEALLOC,
HISTORY,
NODATA,
CAND,
DEALLOCS,
HOSTS,
PESTS,
METAS,
HOLDS,
OTHERS,
NOTAVAIL,
DIRECTIVE,
SIMPLECT
} arglist_id;

#define	NO_VALUE -1

DYNMEM_KNP_DEFN dynmem_knp[] = {
	NULL,	"sdbc_monitor_dynmem",		NO_VALUE,
	NULL,	"sdbc_max_dyn_list",		NO_VALUE,
	NULL,	"sdbc_cache_aging_ct1",		NO_VALUE,
	NULL,	"sdbc_cache_aging_ct2",		NO_VALUE,
	NULL,	"sdbc_cache_aging_ct3",		NO_VALUE,
	NULL,	"sdbc_cache_aging_sec1",	NO_VALUE,
	NULL,	"sdbc_cache_aging_sec2",	NO_VALUE,
	NULL,	"sdbc_cache_aging_sec3",	NO_VALUE,
	NULL,	"sdbc_cache_aging_pcnt1",	NO_VALUE,
	NULL,	"sdbc_cache_aging_pcnt2",	NO_VALUE,
	NULL,	"sdbc_max_holds_pcnt",		NO_VALUE,
	NULL,	"sdbc_alloc_cnt",		NO_VALUE,
	NULL,	"sdbc_dealloc_cnt",		NO_VALUE,
	NULL,	"sdbc_history",			NO_VALUE,
	NULL,	"sdbc_nodatas",			NO_VALUE,
	NULL,	"sdbc_candidates",		NO_VALUE,
	NULL,	"sdbc_deallocs",		NO_VALUE,
	NULL,	"sdbc_hosts",			NO_VALUE,
	NULL,	"sdbc_pests",			NO_VALUE,
	NULL,	"sdbc_metas",			NO_VALUE,
	NULL,	"sdbc_holds",			NO_VALUE,
	NULL,	"sdbc_others",			NO_VALUE,
	NULL,	"sdbc_notavail",		NO_VALUE,
	NULL,	"sdbc_process_directive",	NO_VALUE,
	NULL,	"sdbc_simplect",		NO_VALUE,
	NULL,	NULL,				NO_VALUE
	};

/*
 * Print Usage
 */
static void
print_usage()
{
	(void) printf("USAGE: wake - wakeup thread, hys - max hysteresis\n");
	(void) printf("       mon 1 - monitor shutdown\n");
	(void) printf("           2 - monitor thread stats1\n");
	(void) printf("           4 - monitor thread stats2\n");
	(void) printf("       age1 n - num cyc to full host aging and "
	    "dealloc\n");
	(void) printf("       age2 n - num cyc to full meta aging and "
	    "dealloc\n");
	(void) printf("       age3 n - num cyc to full one pg aging and "
	    "dealloc\n");
	(void) printf("       sec1 n  - sec1 aging time\n");
	(void) printf("       sec2 n  - sec2 aging time\n");
	(void) printf("       sec3 n  - sec3 aging time\n");
	(void) printf("       pcnt1 n  - percent to sec1/sec2 trans\n");
	(void) printf("       pcnt2 n  - percent to sec2/sec3 trans\n");
	(void) printf("       hdpcnt n  - max percent of cents for holds\n");
	(void) printf("       list n  - host+pest max len\n");
	(void) printf("No Args - print current settings only\n");
}

/*
 * Main
 */
/* ARGSUSED */
#ifdef lint
int
sd_dynmem_lintmain(int argc, char *argv[])
#else
int
main(int argc, char *argv[])
#endif
{
	DYNMEM_KNP_DEFN	*p_dynmem_knp;
	kstat_ctl_t	*kctl;
	KSTAT_INFO_DEF	info_ksp;
	int		val;
	char		**pargs, **cur_pargs;

	/*
	 * grab and parse argument list
	 */
	p_dynmem_knp = dynmem_knp;
	pargs = argv;
	while (*pargs) {
		(void) printf("pargs=%x - %s\n", (uint_t)pargs, *pargs);

		cur_pargs = pargs;
		pargs++;

		if (strcmp(*cur_pargs, "h") == 0) {
			print_usage();
			return (0);
		}

		if (strcmp(*cur_pargs, "wake") == 0) {
			if ((p_dynmem_knp+DIRECTIVE)->newval == NO_VALUE)
				(p_dynmem_knp+DIRECTIVE)->newval = 0;
			(p_dynmem_knp+DIRECTIVE)->newval |= 0x01;
			continue;
		}

		if (strcmp(*cur_pargs, "hys") == 0) {
			if ((p_dynmem_knp+DIRECTIVE)->newval == NO_VALUE)
				(p_dynmem_knp+DIRECTIVE)->newval = 0;
			(p_dynmem_knp+DIRECTIVE)->newval |= 0x02;
			continue;
		}

		if (strcmp (*cur_pargs, "mon") == 0) {
			val = atoi(*pargs);
			(void) printf("errno=%x, %s=%x\n", errno, *cur_pargs,
			    val);
			pargs++;
			(p_dynmem_knp+MONITOR)->newval = val;
		}

		if (strcmp (*cur_pargs, "age1") == 0) {
			val = atoi(*pargs);
			(void) printf("errno=%x, %s=%x\n", errno, *cur_pargs,
			    val);
			pargs++;
			(p_dynmem_knp+AGECT1)->newval = val;
		}

		if (strcmp(*cur_pargs, "age2") == 0) {
			val = atoi(*pargs);
			(void) printf("errno=%x, %s=%x\n", errno, *cur_pargs,
			    val);
			pargs++;
			(p_dynmem_knp+AGECT2)->newval = val;
		}

		if (strcmp(*cur_pargs, "age3") == 0) {
			val = atoi(*pargs);
			(void) printf("errno=%x, %s=%x\n", errno, *cur_pargs,
			    val);
			pargs++;
			(p_dynmem_knp+AGECT3)->newval = val;
		}

		if (strcmp (*cur_pargs, "sec1") == 0) {
			val = atoi(*pargs);
			(void) printf("errno=%x, %s=%x\n", errno, *cur_pargs,
			    val);
			pargs++;
			if (val == 0)
				break;
			else {
				(p_dynmem_knp+SEC1)->newval = val;
				continue;
			}
		}

		if (strcmp(*cur_pargs, "sec2") == 0) {
			val = atoi(*pargs);
			pargs++;
			(void) printf("errno=%x, %s=%x\n", errno, *cur_pargs,
			    val);
			if (val == 0)
				break;
			else {
				(p_dynmem_knp+SEC2)->newval = val;
				continue;
			}
		}

		if (strcmp(*cur_pargs, "sec3") == 0) {
			val = atoi(*pargs);
			pargs++;
			(void) printf("errno=%x, %s=%x\n", errno, *cur_pargs,
			    val);
			if (val == 0)
				break;
			else {
				(p_dynmem_knp+SEC3)->newval = val;
				continue;
			}
		}

		if (strcmp(*cur_pargs, "pcnt1") == 0) {
			val = atoi(*pargs);
			pargs++;
			(void) printf("errno=%x, %s=%x\n", errno, *cur_pargs,
			    val);
			if (val == 0)
				break;
			else {
				(p_dynmem_knp+PCNT1)->newval = val;
				continue;
			}
		}

		if (strcmp(*cur_pargs, "pcnt2") == 0) {
			val = atoi(*pargs);
			pargs++;
			(void) printf("errno=%x, %s=%x\n", errno, *cur_pargs,
			    val);
			if (val == 0)
				break;
			else {
				(p_dynmem_knp+PCNT2)->newval = val;
				continue;
			}
		}

		if (strcmp(*cur_pargs, "hdpcnt") == 0) {
			val = atoi(*pargs);
			pargs++;
			(void) printf("errno=%x, %s=%x\n", errno, *cur_pargs,
			    val);
			if (val < 0)
				break;
			else {
				(p_dynmem_knp+HDPCNT)->newval = val;
				continue;
			}
		}

		if (strcmp(*cur_pargs, "list") == 0) {
			val = atoi(*pargs);
			pargs++;
			(void) printf("errno=%x, %s=%x\n", errno, *cur_pargs,
			    val);
			if (val == 0)
				break;
			else {
				(p_dynmem_knp+MAXLIST)->newval = val;
				continue;
			}
		}
	}   /* while(*pargs && cl) */

	/*
	 * open the kstat library
	 */
	kctl = kstat_open();
	if (kctl == NULL) {
		(void) printf("kstat_open() failed\n");
		return (1);
	}

	/*
	 * is the name module about
	 */
	info_ksp.instance = 0;
	info_ksp.ksp = kstat_lookup(kctl, SDBC_KSTAT_MODULE, 0,
	    SDBC_KSTAT_DYNMEM);
	if (info_ksp.ksp == NULL) {
		(void) printf("No module to report\n");
		return (1);
	}

	/*
	 * using the info get a copy of the data
	 */
	if (kstat_read(kctl, info_ksp.ksp, NULL) == -1) {
		(void) printf("Can't read kstat\n");
		return (1);
	}

	/*
	 * print the current data
	 */
	p_dynmem_knp = dynmem_knp;
	while (p_dynmem_knp->named) {
		p_dynmem_knp->knp =
			kstat_data_lookup(info_ksp.ksp, p_dynmem_knp->named);
		if (p_dynmem_knp->knp == NULL) {
			(void) printf("kstat_data_lookup(%s) failed\n",
			    p_dynmem_knp->named);
			return (1);
		} else {
			(void) printf("%s: %x\n", p_dynmem_knp->named,
			    (uint_t)p_dynmem_knp->knp->value.ul);
			p_dynmem_knp++;
		}
	}

	/*
	 * modify the data and write it back
	 */
	p_dynmem_knp = dynmem_knp;
	while (p_dynmem_knp->named) {
		if (p_dynmem_knp->newval != NO_VALUE)
			p_dynmem_knp->knp->value.ul = p_dynmem_knp->newval;
		p_dynmem_knp++;
	}

	if (kstat_write(kctl, info_ksp.ksp, NULL) == -1) {
		(void) printf("kstat_write() failed\n");
		return (1);
	}

	(void) printf("Finished (h for help)\n");
	return (0);
}
