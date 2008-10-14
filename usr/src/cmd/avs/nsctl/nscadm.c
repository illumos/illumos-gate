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

#include <sys/types.h>
#include <sys/stat.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <locale.h>

#include <nsctl.h>
#define	__NSC_GEN__
#include <sys/nsctl/nsc_gen.h>
#include <sys/nsctl/nsc_mem.h>


/*
 * Private functions from libsd.
 */
extern int nsc_nvclean(int);
extern int nsc_gmem_data(char *);
extern int nsc_gmem_sizes(int *);

/*
 * Local functions.
 */
static int _nsc_gmem(void);
static void show_maps(char *, int);


static void
usage(void)
{
	fprintf(stderr, gettext("usage: nscadm [-h] command\n"));
	fprintf(stderr, gettext("valid commands:\n"));
	fprintf(stderr, gettext("	freeze <device>\n"));
	fprintf(stderr, gettext("	unfreeze <device>\n"));
	fprintf(stderr, gettext("	isfrozen <device>\n"));
}

static void
is_chr_dev(char *dev, char *op)
{
	struct stat sbuf;
	if (stat(dev, &sbuf) < 0) {
		fprintf(stderr, gettext("nscadm: "));
		perror(op);
		exit(255);
	}
	if (!S_ISCHR(sbuf.st_mode)) {
		fprintf(stderr, gettext("nscadm: %s: not a valid device "
		    "<%s>\n"), op, dev);
		exit(255);
	}
}

int
main(int argc, char *argv[])
{
	extern int optind, opterr;
	int opt, rc;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("nscadm");

	rc = 0;
	opterr = 0;

	while ((opt = getopt(argc, argv, "h")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			exit(0);
			break;
		default:
			usage();
			exit(255);
			break;
		}
	}

	if (optind == argc) {
		usage();
		exit(255);
	}

	if (strcoll(argv[optind], gettext("freeze")) == 0 ||
			strcmp(argv[optind], "freeze") == 0) {
		if (argc - optind != 2) {
			usage();
			exit(255);
		}

		is_chr_dev(argv[optind+1], "freeze");
		rc = nsc_isfrozen(argv[optind+1]);
		if (rc < 0) {
			perror(gettext("nscadm: freeze"));
			exit(255);
		} else if (rc != 0) {
			rc = nsc_freeze(argv[optind+1]);
			if (rc < 0) {
				perror(gettext("nscadm: freeze"));
				exit(255);
			}
		} else {
			fprintf(stderr, gettext("nscadm: device <%s> is "
			    "already frozen\n"), argv[optind+1]);
			exit(255);
		}

		printf(gettext("nscadm: device <%s> frozen\n"), argv[optind+1]);
	} else if (strcoll(argv[optind], gettext("unfreeze")) == 0 ||
			strcmp(argv[optind], "unfreeze") == 0) {
		if (argc - optind != 2) {
			usage();
			exit(255);
		}

		is_chr_dev(argv[optind+1], "unfreeze");
		rc = nsc_isfrozen(argv[optind+1]);
		if (rc < 0) {
			perror(gettext("nscadm: unfreeze"));
			exit(255);
		} else if (rc == 0) {
			rc = nsc_unfreeze(argv[optind+1]);
			if (rc < 0) {
				perror(gettext("nscadm: unfreeze"));
				exit(255);
			}
		} else {
			fprintf(stderr, gettext("nscadm: device <%s> is not "
			    "frozen\n"), argv[optind+1]);
			exit(255);
		}

		printf(gettext("nscadm: device <%s> unfrozen\n"),
			argv[optind+1]);
	} else if (strcoll(argv[optind], gettext("isfrozen")) == 0 ||
			strcmp(argv[optind], "isfrozen") == 0) {
		if (argc - optind != 2) {
			usage();
			exit(255);
		}

		is_chr_dev(argv[optind+1], "isfrozen");
		rc = nsc_isfrozen(argv[optind+1]);
		if (rc < 0) {
			perror(gettext("nscadm: isfrozen"));
			exit(255);
		}

		printf(gettext("nscadm: device <%s> is %sfrozen\n"),
			argv[optind+1], rc ? gettext("not ") : "");
#ifdef DEBUG
	} else if (strcoll(argv[optind], gettext("nvclean")) == 0 ||
			strcmp(argv[optind], "nvclean") == 0) {
		rc = nsc_nvclean(0);
		if (rc < 0) {
			perror(gettext("nscadm: nvclean"));
			exit(255);
		}
	} else if (strcoll(argv[optind], gettext("nvclean_force")) == 0 ||
			strcmp(argv[optind], "nvclean_force") == 0) {
		rc = nsc_nvclean(1);
		if (rc < 0) {
			perror(gettext("nscadm: nvclean_force"));
			exit(255);
		}
#endif /* DEBUG */
	} else if (strcoll(argv[optind], gettext("gmem")) == 0 ||
			strcmp(argv[optind], "gmem") == 0) {
		rc = _nsc_gmem();
		if (rc < 0) {
			perror(gettext("nscadm: gmem"));
			exit(255);
		}
	} else {
		usage();
		exit(255);
	}

	return (rc);
}


static int
_nsc_gmem(void)
{
	char *addr;
	int size;
	int rc = 0;

	rc = nsc_gmem_sizes(&size);

	if (rc < 0)
		return (rc);

	printf(gettext("size %d\n"), size);

	if ((addr = (char *)malloc(size * 2)) == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	rc = nsc_gmem_data(addr);

	if (rc < 0) {
		free(addr);
		return (rc);
	}

	printf(gettext("Global map entries:\n"));
	show_maps(addr, size);

	printf(gettext("\nGlobal NVMEM map entries:\n"));
	show_maps(addr + size, size);

	free(addr);
	return (0);
}


static void
show_maps(char *addr, int len)
{
	/* LINTED alignment of cast ok */
	nsc_rmhdr_t *rhp = (nsc_rmhdr_t *)addr;
	nsc_rmmap_t *rmap;
	char tname[_NSC_MAXNAME + 1];
	int i;

	printf(gettext("magic 0x%x ver %d size %d dirty (nvmem systems): %d\n"),
	    rhp->magic, rhp->ver, rhp->size, rhp->rh_dirty);

	for (i = 0, rmap = rhp->map;
		/* LINTED alignment of cast ok */
	    rmap < (nsc_rmmap_t *)(addr + len); ++i, ++rmap) {
		if (!rmap->name[0])
			continue;
		strncpy(tname, rmap->name, _NSC_MAXNAME);
		strcpy(&tname[strlen(tname)], "                     ");
		tname[_NSC_MAXNAME] = '\0';
		printf(gettext(
		    "%d:\tname %s\toffset 0x%x size 0x%x inuse 0x%x\n"),
		    i, tname, rmap->offset, rmap->size, rmap->inuse);
	}
}
