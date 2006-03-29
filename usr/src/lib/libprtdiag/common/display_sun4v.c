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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <kvm.h>
#include <varargs.h>
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/openpromio.h>
#include <libintl.h>
#include <syslog.h>
#include <sys/dkio.h>
#include "pdevinfo.h"
#include "display.h"
#include "display_sun4v.h"
#include "libprtdiag.h"


#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

extern	int sys_clk;

int
sun4v_display(Sys_tree *tree, Prom_node *root, int syserrlog,
    picl_nodehdl_t plafh)
{
	int exit_code = 0;	/* init to all OK */
	void *value;		/* used for opaque PROM data */
	struct mem_total memory_total;	/* Total memory in system */
	struct grp_info grps;	/* Info on all groups in system */

	sys_clk = -1;  /* System clock freq. (in MHz) */

	/*
	 * Now display the machine's configuration. We do this if we
	 * are not logging.
	 */
	if (!logging) {
		struct utsname uts_buf;

		/*
		 * Display system banner
		 */
		(void) uname(&uts_buf);

		log_printf(
			dgettext(TEXT_DOMAIN, "System Configuration:  "
				"Sun Microsystems  %s %s\n"), uts_buf.machine,
					get_prop_val(find_prop(root,
					"banner-name")), 0);

		/* display system clock frequency */
		value = get_prop_val(find_prop(root, "clock-frequency"));
		if (value != NULL) {
			sys_clk = ((*((int *)value)) + 500000) / 1000000;
			log_printf(dgettext(TEXT_DOMAIN, "System clock "
				"frequency: %d MHz\n"), sys_clk, 0);
		}

		/* Display the Memory Size */
		display_memorysize(tree, NULL, &grps, &memory_total);

		/* Display the CPU devices */
		sun4v_display_cpu_devices(plafh);

		/* Display the Memory configuration */
		sun4v_display_memoryconf(plafh);

		/* Display all the IO cards. */
		(void) sun4v_display_pci(plafh);

		sun4v_display_diaginfo((syserrlog || (logging)), root, plafh);
	}

	return (exit_code);
}

/*
 * display_pci
 * Display all the PCI IO cards on this board.
 */
void
sun4v_display_pci(picl_nodehdl_t plafh)
{
#ifdef	lint
	plafh = plafh;
#endif
	/*
	 * This function is intentionally empty
	 */
}

void
sun4v_display_memoryconf(picl_nodehdl_t plafh)
{
#ifdef	lint
	plafh = plafh;
#endif
	/*
	 * This function is intentionally empty
	 */
}

void
sun4v_display_cpu_devices(picl_nodehdl_t plafh)
{
	char	*fmt = "%-12s %-5s %-8s %-19s %-5s";

	/*
	 * Display the table header for CPUs . Then display the CPU
	 * frequency, cache size, and processor revision of all cpus.
	 */
	log_printf(dgettext(TEXT_DOMAIN,
		"\n"
		"========================="
		" CPUs "
		"==============================================="
		"\n"
		"\n"));
	log_printf(fmt, "", "", "", "CPU", "CPU", 0);
	log_printf("\n");
	log_printf(fmt, "Location", "CPU", "Freq",
	    "Implementation", "Mask", 0);
	log_printf("\n");
	log_printf(fmt, "------------", "-----", "--------",
	    "-------------------", "-----", 0);
	log_printf("\n");

	(void) picl_walk_tree_by_class(plafh, "cpu", "cpu", sun4v_display_cpus);

	log_printf("\n");
}

/*
 * Display the CPUs present on this board.
 */
/*ARGSUSED*/
int
sun4v_display_cpus(picl_nodehdl_t cpuh, void* args)
{
	int status;
	picl_prophdl_t	proph;
	picl_prophdl_t	tblh;
	picl_prophdl_t	rowproph;
	picl_propinfo_t propinfo;
	int		*int_value;
	uint64_t	cpuid, mask_no;
	char		*comp_value;
	char		*no_prop_value = "   ";
	char		freq_str[MAXSTRLEN];
	char		fru_name[MAXSTRLEN];

	/*
	 * Get cpuid property and print it and the NAC name
	 */
	status = picl_get_propinfo_by_name(cpuh, "cpuid", &propinfo, &proph);
	if (status == PICL_SUCCESS) {
		status = picl_get_propval(proph, &cpuid, sizeof (cpuid));
		if (status != PICL_SUCCESS) {
			log_printf("%-12s", no_prop_value);
			log_printf("%6s", no_prop_value);
		} else {
			(void) snprintf(fru_name, sizeof (fru_name), "%s%d",
			    CPU_STRAND_NAC, (int)cpuid);
			log_printf("%-12s", fru_name);
			log_printf("%6d", (int)cpuid);
		}
	} else {
		log_printf("%-12s", no_prop_value);
		log_printf("%6s", no_prop_value);
	}

clock_freq:
	status = picl_get_propinfo_by_name(cpuh, "clock-frequency", &propinfo,
	    &proph);
	if (status == PICL_SUCCESS) {
		int_value = malloc(propinfo.size);
		if (int_value == NULL) {
			log_printf("%9s", no_prop_value);
			goto compatible;
		}
		status = picl_get_propval(proph, int_value, propinfo.size);
		if (status != PICL_SUCCESS) {
			log_printf("%9s", no_prop_value);
		} else {
			/* Running frequency */
			(void) snprintf(freq_str, sizeof (freq_str), "%d MHz",
			    CLK_FREQ_TO_MHZ(*int_value));
			log_printf("%9s", freq_str);
		}
		free(int_value);
	} else
		log_printf("%9s", no_prop_value);

compatible:
	status = picl_get_propinfo_by_name(cpuh, "compatible", &propinfo,
	    &proph);
	if (status == PICL_SUCCESS) {
		if (propinfo.type == PICL_PTYPE_CHARSTRING) {
			/*
			 * Compatible Property only has 1 value
			 */
			comp_value = malloc(propinfo.size);
			if (comp_value == NULL) {
				log_printf("%20s", no_prop_value, 0);
				goto mask;
			}
			status = picl_get_propval(proph, comp_value,
			    propinfo.size);
			if (status == PICL_SUCCESS) {
				log_printf("%20s", no_prop_value, 0);
				free(comp_value);
			}
		} else if (propinfo.type == PICL_PTYPE_TABLE) {
			/*
			 * Compatible Property has multiple values
			 */
			status = picl_get_propval(proph, &tblh, propinfo.size);
			if (status != PICL_SUCCESS) {
				printf("Failed getting tblh\n");
				log_printf("%20s", no_prop_value, 0);
				goto mask;
			}
			status = picl_get_next_by_row(tblh, &rowproph);
			if (status != PICL_SUCCESS) {
				printf("Failed getting next by row\n");
				log_printf("%20s", no_prop_value, 0);
				goto mask;
			}

			status = picl_get_propinfo(rowproph, &propinfo);
			if (status != PICL_SUCCESS) {
				printf("Failed getting prop for rowproph\n");
				log_printf("%20s", no_prop_value, 0);
				goto mask;
			}

			comp_value = malloc(propinfo.size);
			if (comp_value == NULL) {
				printf("Failed to get malloc value?\n");
				log_printf("%20s", no_prop_value, 0);
				goto mask;
			}

			status = picl_get_propval(rowproph, comp_value,
			    propinfo.size);
			if (status != PICL_SUCCESS) {
				printf("Failed geting rowproph\n");
				log_printf("%20s", no_prop_value, 0);
				free(comp_value);
				goto mask;
			} else
				log_printf("%20s", comp_value, 0);
			free(comp_value);
		}
	} else
		log_printf("%20s", no_prop_value, 0);

mask:
	status = picl_get_propinfo_by_name(cpuh, "mask#", &propinfo, &proph);
	if (status == PICL_SUCCESS) {
		status = picl_get_propval(proph, &mask_no, sizeof (mask_no));
		if (status != PICL_SUCCESS) {
			log_printf("%9s", no_prop_value);
		} else {
			log_printf(dgettext(TEXT_DOMAIN, " %2d.%d"),
			    (mask_no>> 4) & 0xf, mask_no & 0xf);
		}
	} else
		log_printf("%9s", no_prop_value);

done:
	log_printf("\n");
	return (PICL_WALK_CONTINUE);
}

void
sun4v_display_diaginfo(int flag, Prom_node *root, picl_nodehdl_t plafh)
{
#ifdef	lint
	flag = flag;
	root = root;
	plafh = plafh;
#endif
	/*
	 * This function is intentionally empty
	 */
}

void
display_boardnum(int num)
{
	log_printf("%2d   ", num, 0);
}
