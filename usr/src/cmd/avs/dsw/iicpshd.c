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
#include <sys/nsctl/dsw_dev.h>		/* for bitmap format */

#define	DSW_TEXT_DOMAIN	"II"
#define	BITMAP_TOKEN	"ii.set%d.bitmap"
#define	SHADOW_TOKEN	"ii.set%d.shadow"
#define	SV_TOKEN	"sv.set%d.vol"
#define	DSVOL_TOKEN	"dsvol.set%d.path"

void iicpshd_usage();
void copyshd(char *, char *);
int find_cfg_info(char *, char *);
int copy_shadow_vol(char *, char *);
void convert_to_blockdevice();
int update_dscfg(char *);

extern int optind;

extern	char *optarg;
extern	int optind, opterr, optopt;
int	copy_shadow = 1;
CFGFILE	*cfg;
char	real_bitmap[DSW_NAMELEN];
char	buf[CFG_MAX_BUF];
char	key[CFG_MAX_KEY];
int	set_number;
int	sv_number;
int	dsvol_number;

#ifdef lint
int
iicpshd_lintmain(int argc, char *argv[])
#else
int
main(int argc, char *argv[])
#endif
{
	if (argc > 1) {
		if (strcmp(argv[1], "-s") == 0) {
			/* don't copy shadow, only update dscfg and ii header */
			copy_shadow = 0;
			argc--;
			argv++;
		}
	}

	if (argc == 1 || (argc%2) == 0)	/* must have pairs of filenames */
		iicpshd_usage();

	/* open dscfg anyway */
	if ((cfg = cfg_open(NULL)) == NULL) {
		fprintf(stderr, gettext("Error opening config\n"));
		exit(1);
	}

	for (argv++; *argv != NULL; argv += 2)
		copyshd(argv[0], argv[1]);

	/* close dscfg */
	cfg_close(cfg);
	exit(0);
	return (0);
}

void
iicpshd_usage()
{
	fprintf(stderr, gettext("Usage:\n"));
	fprintf(stderr, gettext("\tiicpshd [-s] old_shadow new_shadow\n"));
	exit(1);
}

void
copyshd(char *old_vol, char *new_vol)
{
	int dsw_fd;
	FILE *ifp;
	char header[FBA_SIZE(1) * DSW_CBLK_FBA];
	ii_header_t *hp;
	dsw_stat_t args;

	/*LINTED pointer alignment*/
	hp = (ii_header_t *)&header;

	dsw_fd = open(DSWDEV, O_RDONLY);
	if (dsw_fd < 0) {
		perror(DSWDEV);
		exit(1);
	}
	if (*old_vol != '/' || *new_vol != '/') {
		fprintf(stderr, gettext(
		"Both old and new shadow file names must begin with a /.\n"));
		exit(1);
	}

	if (strlen(new_vol) > DSW_NAMELEN) {
		fprintf(stderr, gettext("New shadow name is to long.\n"));
		exit(1);
	}

	/* check old shadow is in dscfg */
	if (find_cfg_info(old_vol, SHADOW_TOKEN) == 0) {
		fprintf(stderr, gettext("Old shadow not in existing cfg\n"));
		exit(1);
	}

	/* check ii set status, suspend if need */
	strncpy(args.shadow_vol, old_vol, DSW_NAMELEN);
	args.shadow_vol[DSW_NAMELEN-1] = '\0';
	args.status = spcs_s_ucreate();
	if (ioctl(dsw_fd, DSWIOC_STAT, &args) != -1) {
		fprintf(stderr, gettext("Suspend the Point-in-Time Copy "
		    "set first\n"));
		close(dsw_fd);
		exit(1);
	}

	if (copy_shadow) {
		if (copy_shadow_vol(old_vol, new_vol) == 0) {
			perror(gettext("Write new shadow failed"));
			close(dsw_fd);
			exit(1);
		}
	}
	if (find_cfg_info(old_vol, SV_TOKEN) == 0) {
		fprintf(stderr, gettext("Old shadow not in existing cfg\n"));
		exit(1);
	}
	if (find_cfg_info(old_vol, DSVOL_TOKEN) == 0) {
		fprintf(stderr, gettext("Old shadow not in existing cfg\n"));
		exit(1);
	}
	if (strstr(real_bitmap, "/rdsk/") == NULL) {
		fprintf(stderr,
			gettext("%s is not a character device\n"), real_bitmap);
		exit(1);
	}

	/* use block device /dsk/ to update bitmap header */
	convert_to_blockdevice();

	/* open bitmap by using update mode */
	if ((ifp = fopen(real_bitmap, "r+")) == NULL) {
		fprintf(stderr, gettext("Can't open bitmap file\n"));
		exit(1);
	}

	/* Check old header looks like an II bitmap header */
	if (fread(&header, DSW_CBLK_FBA, FBA_SIZE(1), ifp) != FBA_SIZE(1)) {
		fprintf(stderr, gettext("Can't read bitmap file\n"));
		exit(1);
	}

	if (hp->ii_magic != DSW_CLEAN && hp->ii_magic != DSW_DIRTY) {
		fprintf(stderr, gettext("%s is not an Point-in-Time Copy "
		    "shadow.\n"), old_vol);
		exit(1);
	}

	if (strncmp(hp->shadow_vol, old_vol, DSW_NAMELEN) != 0) {
		fprintf(stderr, gettext(
		"%s has Point-in-Time Copy shadow magic number,\n"
		"but does not contain correct data.\n"), old_vol);
		exit(1);
	}

	memset(hp->shadow_vol, 0, DSW_NAMELEN);
	strncpy(hp->shadow_vol, new_vol, DSW_NAMELEN);

	/* reset the pointer position */
	rewind(ifp);
	if (fwrite(&header, DSW_CBLK_FBA, FBA_SIZE(1), ifp) != FBA_SIZE(1)) {
		perror(new_vol);
		fprintf(stderr, gettext("Can't write new bitmap header\n"));
		exit(1);
	}
	fclose(ifp);
	close(dsw_fd);
	if (update_dscfg(new_vol) == 0) {
		fprintf(stderr, gettext("Failed to update dscfg.\n"));
		exit(1);
	} else {
		spcs_log("ii", NULL,
		"iicpshd copy shadow from %s to %s",
		old_vol, new_vol);
	}
}

/*
 * find_cfg_info()
 *
 */

int
find_cfg_info(char *volume, char *token)
{
	int i;
	/* get read lock */
	if (!cfg_lock(cfg, CFG_RDLOCK)) {
		spcs_log("ii", NULL,
			"iicpbmp CFG_RDLOCK failed, errno %d", errno);
		fprintf(stderr, gettext("Error locking config\n"));
		exit(1);
	}
	for (i = 1; ; i++) {
		bzero(buf, CFG_MAX_BUF);
		snprintf(key, sizeof (key), token, i);
		if (cfg_get_cstring(cfg, key, buf, DSW_NAMELEN) < 0) {
			cfg_unlock(cfg);
			return (0);
		}
		if (strcmp(buf, volume) == 0) {
			if (strcmp(token, SHADOW_TOKEN) == 0) {
				snprintf(key, sizeof (key), BITMAP_TOKEN, i);
				cfg_get_cstring
					(cfg, key, real_bitmap, DSW_NAMELEN);
				set_number = i;
			} else if (strcmp(token, SV_TOKEN) == 0) {
				sv_number = i;
			} else if (strcmp(token, DSVOL_TOKEN) == 0) {
				dsvol_number = i;
			}
			/* release read lock */
			cfg_unlock(cfg);
			return (1);
		}
	}
}

int
copy_shadow_vol(char *old_shadow, char *new_shadow) {
	int i;
	char cp_buffer[256];
	FILE *ishdfp, *oshdfp;
	if ((ishdfp = fopen(old_shadow, "r")) == NULL) {
		fprintf(stderr, gettext("Can't open old shadow file\n"));
		return (0);
	}
	if ((oshdfp = fopen(new_shadow, "w")) == NULL) {
		fprintf(stderr, gettext("Can't open new shadow file\n"));
		return (0);
	}

	/* Copy the shadow vol */
	while ((i = fread(cp_buffer, sizeof (char), sizeof (cp_buffer), ishdfp))
		> 0) {
		if (fwrite(cp_buffer, sizeof (char), i, oshdfp) != i) {
			fclose(ishdfp);
			fclose(oshdfp);
			return (0);
		}
	}
	fclose(ishdfp);
	fclose(oshdfp);
	return (1);
}

int
update_dscfg(char *new_shadow) {

	int len = strlen(new_shadow);
	/* get write lock */
	if (!cfg_lock(cfg, CFG_WRLOCK)) {
		spcs_log("ii", NULL,
			"iicpbmp CFG_WRLOCK failed, errno %d", errno);
		fprintf(stderr, gettext("Error locking config\n"));
		return (0);
	}
	sprintf(key, SHADOW_TOKEN, set_number);
	if (cfg_put_cstring(cfg, key, new_shadow, len) < 0) {
		perror("cfg_put_cstring");
		return (0);
	}
	sprintf(key, SV_TOKEN, sv_number);
	if (cfg_put_cstring(cfg, key, new_shadow, len) < 0) {
		perror("cfg_put_cstring");
		return (0);
	}
	sprintf(key, DSVOL_TOKEN, dsvol_number);
	if (cfg_put_cstring(cfg, key, new_shadow, len) < 0) {
		perror("cfg_put_cstring");
		return (0);
	}
	cfg_commit(cfg);
	cfg_unlock(cfg);
	return (1);
}

void
convert_to_blockdevice() {
	int len = strlen(real_bitmap);
	int i = 0, j = 0;
	char *temp_string = malloc(len-1);
	while (i < len + 1) {
		if (real_bitmap[i] != 'r') {
			temp_string[j] = real_bitmap[i];
			j++;
		}
		i++;
	}
	strcpy(real_bitmap, temp_string);
	free(temp_string);
}
