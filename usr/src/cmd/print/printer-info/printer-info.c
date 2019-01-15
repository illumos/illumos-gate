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

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prnio.h>
#include <fcntl.h>

#define	COMMAND_SET_MAX	16	/* more than 16 command sets is not likely */
#define	NP(x)	(x ? x : "")

typedef struct {
	char *manufacturer;
	char *model;
	char *description;
	char *class;
	char *command_set[COMMAND_SET_MAX];
} printer_description_t;

int
get_printer_description(char *path, printer_description_t *info)
{
	int fd, rc;
	struct prn_1284_device_id id;
	char buf[BUFSIZ];
	char *s, *iter = NULL;

	/* open the device */
	if ((fd = open(path, O_RDWR)) < 0)
		return (fd);

	/* get the 1284 device id */
	memset(&id, 0, sizeof (id));
	memset(&buf, 0, sizeof (buf));
	id.id_len = sizeof (buf);
	id.id_data = buf;

	rc = ioctl(fd, PRNIOC_GET_1284_DEVID, &id);
	/* close(fd); */
	if (rc < 0)
		return (rc);

	memset(info, 0, sizeof (*info));

	/* parse the 1284 device id string */
	for (s = (char *)strtok_r(buf, ";\n", &iter); s != NULL;
			s = (char *)strtok_r(NULL, ";\n", &iter)) {
		char *t, *u, *iter2 = NULL;

		if ((t = (char *)strtok_r(s, ":\n", &iter2)) == NULL)
			continue;

		if ((u = (char *)strtok_r(NULL, ":\n", &iter2)) == NULL)
			continue;

		if ((strcasecmp(t, "MFG") == 0) ||
		    (strcasecmp(t, "MANUFACTURER") == 0))
			info->manufacturer = strdup(u);
		else if ((strcasecmp(t, "MDL") == 0) ||
		    (strcasecmp(t, "MODEL") == 0))
			info->model = strdup(u);
		else if ((strcasecmp(t, "DES") == 0) ||
		    (strcasecmp(t, "DESCRIPTION") == 0))
			info->description = strdup(u);
		else if ((strcasecmp(t, "CLS") == 0) ||
		    (strcasecmp(t, "CLASS") == 0))
			info->class = strdup(u);
		else if ((strcasecmp(t, "CMD") == 0) ||
		    (strcasecmp(t, "COMMAND SET") == 0)) {
			/* this should be more dynamic, I got lazy */
			char *v, *iter3 = NULL;
			int i = 0;

			for (v = (char *)strtok_r(u, ",\n", &iter3);
				((v != NULL) && (i < COMMAND_SET_MAX));
			v = (char *)strtok_r(NULL, ",\n", &iter3))
				info->command_set[i++] = strdup(v);
		}
	}

	return (0);
}

static void
usage(char *name)
{
	char *program;

	if ((program = strrchr(name, '/')) == NULL)
		program = name;
	else
		program++;

	printf("Usage: %s [-aMmdCc] (path) ...\n", program);
}

int
main(int ac, char *av[])
{
	int rc;
	int manufacturer = 0, model = 0, description = 0, command_set = 0,
	    class = 0;

	while ((rc = getopt(ac, av, "aMmdCc")) != EOF)
		switch (rc) {
		case 'a':
			manufacturer++;
			model++;
			description++;
			command_set++;
			class++;
			break;
		case 'M':
			manufacturer++;
			break;
		case 'm':
			model++;
			break;
		case 'd':
			description++;
			break;
		case 'C':
			command_set++;
			break;
		case 'c':
			class++;
			break;
		default:
			usage(av[0]);
			exit(1);
		}

	if (optind >= ac) {
		usage(av[0]);
		exit(1);
	}

	while (optind < ac) {
		char *path = av[optind++];
		printer_description_t info;

		rc = get_printer_description(path, &info);
		if (rc == 0) {
			printf("%s:\n", path);
			if (manufacturer != 0)
				printf("\tManufacturer: %s\n",
						NP(info.manufacturer));
			if (model != 0)
				printf("\tModel:        %s\n",
						NP(info.model));
			if (description != 0)
				printf("\tDescription:  %s\n",
						NP(info.description));
			if (class != 0)
				printf("\tClass:        %s\n",
						NP(info.class));
			if (command_set != 0) {
				int i;

				printf("\tCommand set:\n");
				for (i = 0; info.command_set[i] != NULL; i++)
					printf("\t\tcmd[%d]: %s\n", i,
						info.command_set[i]);
			}
		} else
			perror(path);
	}
	return (rc);
}
