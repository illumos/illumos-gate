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
 * Copyright (c) 1986-1992 by Sun Microsystems Inc.
 */

#include <stdio.h>
#include <rpc/rpc.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#include <string.h>
#include <unistd.h>

#define	MAXMAPS 500
/* number of nickname file entries arbitrarily limited */

static char NICKFILE[] = "/var/yp/nicknames";
static char *transtable[MAXMAPS];

/*
 * This will read nicknames from file /var/yp/nicknames
 * and print it out or save it for future use.
 */
void
maketable(dump)
int dump;
{
	FILE *nickp;
	int i = 0;
	char nickbuf[2*YPMAXMAP+3], nickname[YPMAXMAP+1], mapname[YPMAXMAP+1];

	if ((nickp = fopen(NICKFILE, "r")) == NULL) {
		(void) fprintf(stderr, "nickname file %s does not exist\n",
			NICKFILE);
		exit(1);
	}
	while (fgets(nickbuf, YPMAXMAP, nickp) != NULL) {
		if (strchr(nickbuf, '\n') == NULL) {
			(void) fprintf(stderr,
				"garbled nickname file %s\n", NICKFILE);
			exit(1);
		}
		(void) memset(nickname, 0, YPMAXMAP+1);
		(void) memset(mapname, 0, YPMAXMAP+1);
		if (sscanf(nickbuf, "%s %s\n", nickname, mapname) != 2) {
			(void) fprintf(stderr,
				"garbled nickname file %s\n", NICKFILE);
			exit(1);
		}
		if (!dump) {
			transtable[i] = strdup(nickname);
			transtable[i+1] = strdup(mapname);
			i += 2;
			transtable[i] = NULL;
		} else {
			printf("Use \"%s\"\tfor map \"%s\"\n",
				nickname, mapname);
		}
	}
	fclose(nickp);
}

/*
 * This will get the mapname for a given nickname from the file.
 */
int
getmapname(nick, map)
char *nick, *map;
{
	FILE *nickp;
	char nickbuf[2*YPMAXMAP+3], nickname[YPMAXMAP+1];

	if ((nickp = fopen(NICKFILE, "r")) == NULL)
		return (0);
	while (fgets(nickbuf, YPMAXMAP, nickp) != NULL) {
		if (strchr(nickbuf, '\n') == NULL) {
			fclose(nickp);
			return (0);
		}
		(void) memset(nickname, 0, YPMAXMAP+1);
		(void) memset(map, 0, YPMAXMAP+1);
		if (sscanf(nickbuf, "%s %s\n", nickname, map) != 2) {
			fclose(nickp);
			return (0);
		}
		if (strcmp(nick, nickname) == 0) {
			fclose(nickp);
			return (1);
		}
	}
	fclose(nickp);
	return (0);
}
