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
#include <sys/time.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <values.h>
#include <locale.h>
#include <sys/stat.h>
#include <strings.h>
#include <stdarg.h>
#include <sys/param.h>
#include <nsctl.h>

#include <sys/nsctl/cfg.h>
#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_errors.h>
#include <sys/nsctl/dsw.h>
#include <sys/nsctl/dsw_dev.h>

#define	DSW_TEXT_DOMAIN	"II"

void iicpbmp_usage();
void copybmp(char *, char *);
int find_bitmap_cfg(char *);

extern int optind;

char	*cmdnam;

extern char *optarg;
extern int optind, opterr, optopt;
int	update_cfg = 1;
CFGFILE *cfg;
char shadow[DSW_NAMELEN];
char buf[CFG_MAX_BUF];
char key[CFG_MAX_KEY];
int setnumber;

#ifdef lint
int
iicpbmp_lintmain(int argc, char *argv[])
#else
int
main(int argc, char *argv[])
#endif
{
	cmdnam = argv[0];

	if (argc > 1) {
		if (strcmp(argv[1], "-c") == 0) {
			/* don't update cfg information */
			update_cfg = 0;
			argc--;
			argv++;
		}
	}

	if (argc == 1 || (argc%2) == 0)	/* must have pairs of filenames */
		iicpbmp_usage();

	if (update_cfg) {
		if ((cfg = cfg_open(NULL)) == NULL) {
			fprintf(stderr, gettext("Error opening config\n"));
			exit(1);
		}

		if (!cfg_lock(cfg, CFG_WRLOCK)) {
			spcs_log("ii", NULL,
				"iicpbmp CFG_WRLOCK failed, errno %d", errno);
			fprintf(stderr, gettext("Error locking config\n"));
			exit(1);
		}
	}

	for (argv++; *argv != NULL; argv += 2)
		copybmp(argv[0], argv[1]);
	if (update_cfg)
		cfg_close(cfg);
	exit(0);
	return (0);
}

void
iicpbmp_usage()
{
	fprintf(stderr, gettext("Usage:\n"));
	fprintf(stderr, gettext("\tiicpbmp [-c] old_bitmap new_bitmap\n"));
	exit(1);
}

void
copybmp(char *old_bitmap, char *new_bitmap)
{
	int i;
	int dsw_fd;
	FILE *ifp, *ofp;
	ii_header_t header;
	char cp_buffer[256];
	dsw_stat_t args;

	dsw_fd = open(DSWDEV, O_RDONLY);
	if (dsw_fd < 0) {
		perror(DSWDEV);
		exit(1);
	}
	if (*old_bitmap != '/' || *new_bitmap != '/') {
		fprintf(stderr, gettext(
		"Both old and new bitmap file names must begin with a /.\n"));
		exit(1);
	}

	if (strlen(new_bitmap) > DSW_NAMELEN) {
		fprintf(stderr, gettext("New bitmap name is to long.\n"));
		exit(1);
	}

	if (update_cfg && find_bitmap_cfg(old_bitmap) == 0) {
		perror(old_bitmap);
		fprintf(stderr, gettext("Old bitmap not in existing cfg\n"));
		exit(1);
	}

	strncpy(args.shadow_vol, shadow, DSW_NAMELEN);
	args.shadow_vol[DSW_NAMELEN-1] = '\0';

	args.status = spcs_s_ucreate();
	if (ioctl(dsw_fd, DSWIOC_STAT, &args) != -1) {
		fprintf(stderr, gettext("Suspend the Point-in-Time Copy "
		    "set first\n"));
		close(dsw_fd);
		exit(1);
	}

	if ((ifp = fopen(old_bitmap, "r")) == NULL) {
		perror(old_bitmap);
		fprintf(stderr, gettext("Can't open old bitmap file\n"));
		exit(1);
	}

	/* Check old header looks like an Point-in-Time Copy bitmap header */

	if (fread(&header, sizeof (header), 1, ifp) != 1) {
		fprintf(stderr, gettext("Can't read old bitmap file\n"));
		exit(1);
	}

	if (header.ii_magic != DSW_CLEAN && header.ii_magic != DSW_DIRTY) {
		fprintf(stderr, gettext("%s is not a Point-in-Time Copy "
				    "bitmap.\n"), old_bitmap);
		exit(1);
	}

	if (strncmp(header.bitmap_vol, old_bitmap, DSW_NAMELEN) != 0) {
		fprintf(stderr, gettext(
		"%s has Point-in-Time Copy bitmap magic number,\n"
		"but does not contain correct data.\n"), old_bitmap);
		exit(1);
	}

	if ((ofp = fopen(new_bitmap, "w")) == NULL) {
		perror(new_bitmap);
		fprintf(stderr, gettext("Can't open new bitmap file\n"));
		exit(1);
	}

	/* Set up new header */

	memset(header.bitmap_vol, 0, DSW_NAMELEN);
	strncpy(header.bitmap_vol, new_bitmap, DSW_NAMELEN);

	if (fwrite(&header, sizeof (header), 1, ofp) != 1) {
		perror(new_bitmap);
		fprintf(stderr, gettext("Can't write new bitmap header\n"));
		exit(1);
	}

	/* Copy the bitmap itself */

	while ((i = fread(cp_buffer, sizeof (char), sizeof (cp_buffer), ifp))
				> 0) {
		if (fwrite(cp_buffer, sizeof (char), i, ofp) != i) {
			perror(gettext("Write new bitmap failed"));
			break;
		}
	}
	fclose(ofp);
	fclose(ifp);
	close(dsw_fd);
	if (update_cfg) {
		sprintf(key, "ii.set%d.bitmap", setnumber);
		if (cfg_put_cstring(cfg, key, new_bitmap, strlen(new_bitmap))
						< 0) {
				perror("cfg_put_cstring");
		}
		cfg_commit(cfg);
		spcs_log("ii", NULL,
			"iicpbmp copy bit map for %s from %s to %s",
			shadow, old_bitmap, new_bitmap);
	}
}

/*
 * find_bitmap_cfg()
 *
 */

int
find_bitmap_cfg(char *bitmap)
{
	for (setnumber = 1; ; setnumber++) {
		bzero(buf, CFG_MAX_BUF);
		snprintf(key, sizeof (key), "ii.set%d.bitmap", setnumber);
		if (cfg_get_cstring(cfg, key, buf, DSW_NAMELEN) < 0)
			return (0);
		if (strcmp(buf, bitmap) == 0) {
			snprintf(key, sizeof (key), "ii.set%d.shadow",
						setnumber);
			cfg_get_cstring(cfg, key, shadow, DSW_NAMELEN);
			return (setnumber);
		}
	}
}
