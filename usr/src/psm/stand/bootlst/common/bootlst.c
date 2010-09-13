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

#include <sys/promif.h>
#include <sys/salib.h>

#define	MAX_CMDLINE	1600  /* from GRUB source */

char **titles;
char **datasets;

int	menu_entry_count;
int	menu_table_size;

int	in_menu_entry;

#define	ENTRY_ALLOC_COUNT	10

extern void	set_default_fs(char *fsw_name);
extern int	mountroot(char *str);

void
init_table(void)
{

	menu_entry_count = 0;
	titles = (char **)calloc(ENTRY_ALLOC_COUNT, sizeof (char *));
	datasets = (char **)calloc(ENTRY_ALLOC_COUNT, sizeof (char *));
	if (titles == NULL || datasets == NULL)
		prom_panic("out of mem");
	menu_table_size = ENTRY_ALLOC_COUNT;
	in_menu_entry = 0;
}

void
add_title_entry(char *title_str)
{

	/* skip leading white space */
	while (isspace(*title_str))
		title_str++;

	if (menu_entry_count == menu_table_size) {
		printf("Reallocating at count %d\n", menu_table_size);
		titles = (char **)realloc(titles,
		    ENTRY_ALLOC_COUNT * sizeof (char *));
		datasets = (char **)realloc(datasets,
		    ENTRY_ALLOC_COUNT * sizeof (char *));
		if (titles == NULL || datasets == NULL)
			prom_panic("out of mem");
		menu_table_size += ENTRY_ALLOC_COUNT;
	}

	if (in_menu_entry)
		free(titles[menu_entry_count]);
	if ((titles[menu_entry_count] = strdup(title_str)) == NULL)
		prom_panic("out of mem");
	in_menu_entry = 1;
}

void
add_dataset_entry(char *dataset_str)
{
	char	*cp;

	/* skip leading white space */
	while (isspace(*dataset_str))
		dataset_str++;

	/* if there is still any white space in the line, it's invalid */
	for (cp = dataset_str; *cp; cp++)
		if (isspace(*cp))
			break;
	if (*cp)
		return;  /* dataset name was invalid */

	if (!in_menu_entry)
		return;	 /* dataset line was not preceded by a title */

	if ((datasets[menu_entry_count] = strdup(dataset_str)) == NULL)
		prom_panic("out of mem");
	menu_entry_count++;
	in_menu_entry = 0;
}


char *
trim_white_space(char *cp)
{
	char	*ep;

	/* skip leading white space */
	while (isspace(*cp))
		cp++;

	/*
	 *  if the string contained nothing but white space, return a
	 *  null string.
	 */
	if (*cp == '\0')
		return (cp);

	/* truncate trailing white space */
	for (ep = cp + strlen(cp) - 1; isspace(*ep); ep--)
		;
	ep++;
	*ep = '\0';
	return (cp);
}

char *cons_gets(char *, int);

void
main(void *cif)
{
	char linebuf[MAX_CMDLINE];
	FILE	*file;
	char	*cp, *ep;
	int	n;
	unsigned long	choice;

	prom_init("bootlst", cif);
	set_default_fs("promfs");
	if (mountroot("bootfs") != 0)
		prom_panic("can't mount root");

	if ((file = fopen("/boot/menu.lst", "r")) == NULL)
		prom_panic("can't open menu.lst");
	init_table();

	while (fgets(linebuf, MAX_CMDLINE, file)) {
		cp = trim_white_space(linebuf);

		/* skip comments and blank lines */
		if (*cp == '#' || *cp == '\0')
			continue;

		/* find end of first keyword on line */
		for (ep = cp; !isspace(*ep) && *ep; ep++)
			;

		/* if at the end of the line, the line had no arguments */
		if (*ep == '\0')
			continue;

		*ep = '\0';

		if (strcmp(cp, "title") == 0) {
			add_title_entry(ep + 1);
			continue;
		}

		if (strcmp(cp, "bootfs") == 0) {
			add_dataset_entry(ep + 1);
			continue;
		}
	}

	if (menu_entry_count == 0)
		prom_panic("no menu entries found");

	for (n = 0; n < menu_entry_count; n++) {
		printf("%d %s\n", n + 1, titles[n]);
	}

	printf("Select environment to boot: [ 1 - %d ]: ", menu_entry_count);

	while (cons_gets(linebuf, MAX_CMDLINE)) {
		/* cut off leading and trailing white space */
		cp = trim_white_space(linebuf);
		choice = strtoul(cp, NULL, 0);

		/*
		 * If the input is totally invalid, the return value of
		 * strtoul() will be 0 or ULONG_MAX.  Either way, it's
		 * of the acceptable range.
		 */
		if (choice == 0 || choice > menu_entry_count) {
			printf("Invalid entry.\n");
			continue;
		}
		/* XXX here is the result */
		printf("\nTo boot the selected entry, invoke:\n");
		printf("boot [<root-device>] -Z %s\n\n", datasets[choice - 1]);
		prom_exit_to_mon();
	}
}
