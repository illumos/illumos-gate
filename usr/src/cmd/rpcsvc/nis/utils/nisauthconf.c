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

/*
 * nisauthconf.c
 *
 * Configure NIS+ to use RPCSEC_GSS
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <rpcsvc/nis_dhext.h>

static struct mech_t {
	char	*mechname;
	char	*keylen;
	char	*algtype;
	char	*alias;
	char	*additional;
} mechs[] = {
	"diffie_hellman_1024_0", "1024", "0", "dh1024-0", "default integrity",
	"diffie_hellman_640_0", "640", "0", "dh640-0", "default integrity",
	"-", "-", "-", "des", "# AUTH_DES",
	NULL, NULL, NULL, NULL, NULL
};

static void
preamble(FILE *f)
{
	(void) fprintf(f, "# DO NOT EDIT FILE, AUTOMATICALLY GENERATED\n");
	(void) fprintf(f, "# \n");
	(void) fprintf(f,
		"# The format of this file may change or it may be removed\n");
	(void) fprintf(f, "# in future versions of Solaris.\n# \n");
}

static void
printconf()
{
	int		i = 0;
	mechanism_t	**mechlist;

	if (mechlist = __nis_get_mechanisms(FALSE)) {
		while (mechlist[i]) {
			(void) printf("%s", mechlist[i]->alias);

			if (mechlist[++i])
				(void) printf(", ");
			else
				(void) printf("\n");
		}
	} else
		(void) printf("des\n");
	exit(0);
}


#define	DESMECH1	"-"
#define	DESMECH2	"des"
#define	DESMECH3	"192"
#define	DESMECH4	0
#define	HEADING1	"GSS Mechanism Name"
#define	HEADING2	"Alias"
#define	HEADING3	"Bit Size"
#define	HEADING4	"Algorithm Type"
#define	HEADFMT		"%s%*c%s%*c%s%*c%s\n"
#define	LINEFMT		"%s%*c%s%*c%s%*c%d\n"
#define	GENSPC(a, b)	b, (a - strlen(b)) + 2, ' '

static void
listmechs()
{
	int		sc[3], i;
	char		tmpstr[1024];
	mechanism_t	**mechlist;

	sc[0] = strlen(HEADING1);
	sc[1] = strlen(HEADING2);
	sc[2] = strlen(HEADING3);

	if ((mechlist = __nis_get_mechanisms(FALSE)) == NULL) {
		mechlist = (mechanism_t **) malloc(sizeof (mechanism_t *) * 2);

		mechlist[0] = malloc(sizeof (mechanism_t));
		mechlist[1] = NULL;

		mechlist[0]->mechname = NULL;
		mechlist[0]->alias = "des";
		mechlist[0]->keylen = 192;
		mechlist[0]->algtype = 0;
	}

	for (i = 0; mechlist[i]; i++) {
		int m1 = 0, m2 = 0;

		if (mechlist[i]->mechname) m1 = strlen(mechlist[i]->mechname);
		if (mechlist[i]->alias) m2 = strlen(mechlist[i]->alias);

		sc[0] = sc[0] > m1 ? sc[0] : m1;
		sc[1] = sc[1] > m2 ? sc[1] : m2;
		(void) snprintf(tmpstr, 1024, "%d", mechlist[i]->keylen);
		sc[2] = sc[2] > strlen(tmpstr) ? sc[2] : strlen(tmpstr);
	}

	(void) printf(HEADFMT, GENSPC(sc[0], HEADING1),
			GENSPC(sc[1], HEADING2),
			GENSPC(sc[2], HEADING3), HEADING4);
	for (i = 0; mechlist[i]; i++) {
		(void) snprintf(tmpstr, 1024, "%d", mechlist[i]->keylen);
		(void) printf(LINEFMT, GENSPC(sc[0],
						mechlist[i]->mechname ?
						mechlist[i]->mechname : "-"),
				GENSPC(sc[1], mechlist[i]->alias ?
				mechlist[i]->alias : "-"),
			GENSPC(sc[2], tmpstr),
			mechlist[i]->algtype);
	}
	exit(0);
}


static void
usage(char *cmd)
{
	(void) fprintf(stderr, "usage:\n\t%s [-v] [mechanism, ...]\n", cmd);
	exit(1);
}


int
main(int argc, char **argv)
{
	int c, i, dolistmechs = 0;
	char *cmd = basename(argv[0]);
	FILE *f;

	while ((c = getopt(argc, argv, "v")) != -1) {
		switch (c) {
		case 'v':
			dolistmechs++;
			break;
		default:
			usage(cmd);
		}
	}

	if (dolistmechs)
		listmechs();

	if (argc < 2)
		printconf();

	if (argc == 2 && (strcmp(argv[1], NIS_SEC_CF_DES_ALIAS) == 0)) {
		(void) unlink(NIS_SEC_CF_PATHNAME);
		exit(0);
	}

	if (!(f = fopen(NIS_SEC_CF_PATHNAME, "w"))) {
		(void) fprintf(stderr,
				"Could not open %s for writing.\n",
				NIS_SEC_CF_PATHNAME);
		exit(1);
	}

	preamble(f);

	for (i = 1; i < argc; i++) {
		int j = 0;
		int gotit = 0;

		while (mechs[j].alias) {
			if (!(strcmp(argv[i], mechs[j].alias))) {
				gotit++;

				(void) fprintf(f, "mech\t%s\t%s\t%s\t%s\t%s\n",
							mechs[j].mechname,
							mechs[j].keylen,
							mechs[j].algtype,
							mechs[j].alias,
							mechs[j].additional);
				(void) fflush(f);
				break;
			}
			j++;
		}

		if (!gotit) {
			(void) fprintf(stderr,
					"%s: Mechanism, %s, not found!\n", cmd,
					argv[i]);
			(void) fflush(f);
			(void) fclose(f);
			exit(1);
		}
	}
	(void) fclose(f);
	return (0);
}
