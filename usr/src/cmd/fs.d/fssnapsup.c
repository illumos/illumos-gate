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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routines to support fssnap subcommand of switchout.  See switchout.c for
 * the real fssnap command.
 */

#include <stdio.h>
#include <kstat.h>
#include <libintl.h>
#include <sys/fssnap_if.h>
#include <string.h>
#include <errno.h>

static void fssnap_display_info(ulong_t, int *, int);

#define	MAX_INFO_DESCRIPTORS	(10)

static char *infosubopts[] = {
#define	INFO_SNAPSHOT		(0)
	"snapnumber",
#define	INFO_BLKDEV		(1)
	"blockdevname",
#define	INFO_CHARDEV		(2)
	"rawdevname",
#define	INFO_MNTPT		(3)
	"mountpoint",
#define	INFO_STATE		(4)
	"state",
#define	INFO_BACKPATH		(5)
	"backing-store",
#define	INFO_BACKSIZE		(6)
	"backing-store-len",
#define	INFO_MAXSIZE		(7)
	"maxsize",
#define	INFO_CREATETIME		(8)
	"createtime",
#define	INFO_CHUNKSIZE		(9)
	"chunksize",
	NULL
};

#define	BLOCK_PATH "/dev/" SNAP_BLOCK_NAME "/"
#define	CHAR_PATH  "/dev/" SNAP_CHAR_NAME  "/"

/* labels are truncated to this many characters when displayed */
#define	MAX_LABEL_LEN		(30)

/*
 * fssnap_show_status() - display file system snapshot status
 *
 *    displays snapshot information.  If mountpoint is set, information is
 *    only displayed for the snapshot (if one exists) on that file system.
 *    If mountpoint is NULL, information is displayed for all snapshots.
 *
 *    If opts is defined, it is parsed as a list of suboptions (via
 *    getsubopt()) corresponding to the options list defined above. These
 *    options determine what data should be displayed and in what order.  An
 *    option may appear more than once.
 *
 *    The labels parameter is a boolean that determines whether labels
 *    (internationalized) are displayed before each data element.  If it is
 *    0, labels are not displayed, otherwise they are.  The labels parameter
 *    is ignored if brief is nonzero.
 *
 *    The brief parameter is also a boolean and specifies a mode where only
 *    the snapshot number and mount point are displayed, regardless of the
 *    value of labels.  This could be used for listing all active snapshots.
 *
 *    Based on these parameters, an order list is created that tells
 *    fssnap_display_info() what info to display and in what order.
 *
 *    Note that when labels are not specified, the assumption is that the
 *    output is made for script readable consumption.  For this reason, text
 *    is not I18N'd and numbers are left as bytes instead of converted to KB.
 */
void
fssnap_show_status(char *mountpoint, char *opts, int labels, int brief)
{
	int *order, orderlen = MAX_INFO_DESCRIPTORS+1;
	kstat_ctl_t *kslib;
	kstat_t *mnt;
	kstat_t *kshigh;
	kstat_named_t *highp;
	char *suboptions, *v, *n;
	int i = 0;
	int num, usenum = 0;

	kslib = kstat_open();
	kshigh = kstat_lookup(kslib, SNAP_NAME, 0, FSSNAP_KSTAT_HIGHWATER);

	/*
	 * First check and see if they gave us a mount point or a device
	 * name (ie /dev/fssnap/X or /dev/rfssnap/X).
	 */
	if (mountpoint) {
		if (strncmp(BLOCK_PATH, mountpoint, strlen(BLOCK_PATH)) == 0 ||
		    strncmp(CHAR_PATH, mountpoint, strlen(CHAR_PATH)) == 0) {
			n = strrchr(mountpoint, '/');
			n++;
			if (isdigit(*n)) {
				errno = 0;
				num = (int)strtol(n, NULL, 10);
				if (errno == 0) {
					usenum++;
				}
			}
		}
	}

	if (opts) {
		i = 0;
		order = (int *)malloc(orderlen * sizeof (int));
		if (order == NULL) {
			fprintf(stderr,
			    gettext("cannot allocate order list.\n"));
			return;
		}
		suboptions = opts;
		while (*suboptions != '\0') {
			/*
			 * -1 means invalid option, MAX_INFO_DESCRIPTORS is
			 * the end.
			 */
			order[i++] = getsubopt(&suboptions, infosubopts, &v);
			if (i >= orderlen) {
				order = (int *)realloc(order,
				    sizeof (int) * (orderlen *= 2));
				if (order == NULL) {
					fprintf(stderr,
					    gettext("cannot reallocate order "
					    "list.\n"));
					return;
				}
			}

		}
		order[i] = MAX_INFO_DESCRIPTORS;
	} else {
		order = (int *)malloc(orderlen * sizeof (int));
		if (order == NULL) {
			fprintf(stderr,
			    gettext("cannot allocate order list.\n"));
			return;
		}
		for (i = 0; i <= MAX_INFO_DESCRIPTORS; i++)
			order[i] = i;
	}

	/* check if fssnap module is loaded */
	if (kshigh == NULL) {
		kstat_close(kslib);
		return;
	}

	(void) kstat_read(kslib, kshigh, NULL);
	highp = kstat_data_lookup(kshigh, FSSNAP_KSTAT_HIGHWATER);

	/* Loop up to the maximum number of snapshots */
	for (i = 0; i <= highp->value.ui32; i++) {
		mnt = kstat_lookup(kslib, SNAP_NAME, i, FSSNAP_KSTAT_MNTPT);

		/* if this snapshot is not allocated, skip to the next */
		if (mnt == NULL)
			continue;
		if (kstat_read(kslib, mnt, NULL) == -1)
			continue;
		if (mountpoint != NULL) {
			if ((usenum && i != num) ||
			    (!usenum && strcmp(mountpoint, mnt->ks_data) != 0))
				continue;
		}

		if (brief)
			printf("%4d\t%s\n", i, (char *)mnt->ks_data);
		else
			fssnap_display_info(i, order, labels);
	}
}

static void
fssnap_display_info(ulong_t snapnum, int *order, int labels)
{
	kstat_ctl_t *kslib;
	kstat_t *back, *num;
	kstat_named_t *numvalp;
	kstat_t	*mnt;
	u_longlong_t inuse, size = 0;
	char buf[BUFSIZ], *first;
	int i;

	/* load num kstat */
	kslib = kstat_open();
	num = kstat_lookup(kslib, SNAP_NAME, snapnum, FSSNAP_KSTAT_NUM);
	if (num == NULL)
		return;

	if (kstat_read(kslib, num, NULL) == -1)
		return;

	for (i = 0; order[i] != MAX_INFO_DESCRIPTORS; i++) {
		switch (order[i]) {
		case	INFO_SNAPSHOT:
			if (labels)
				printf("%-*s: %lu\n", MAX_LABEL_LEN,
				    gettext("Snapshot number"), snapnum);
			else
				printf("%lu\n", snapnum);
			break;
		case	INFO_BLKDEV:
			if (labels)
				printf("%-*s: /dev/%s/%lu\n", MAX_LABEL_LEN,
				    gettext("Block Device"), SNAP_BLOCK_NAME,
				    snapnum);
			else
				printf("/dev/%s/%lu\n", SNAP_BLOCK_NAME,
				    snapnum);
			break;
		case	INFO_CHARDEV:
			if (labels)
				printf("%-*s: /dev/%s/%lu\n", MAX_LABEL_LEN,
				    gettext("Raw Device"), SNAP_CHAR_NAME,
				    snapnum);
			else
				printf("/dev/%s/%lu\n", SNAP_CHAR_NAME,
				    snapnum);
			break;

		case	INFO_MNTPT:
			mnt = kstat_lookup(kslib, SNAP_NAME, snapnum,
			    FSSNAP_KSTAT_MNTPT);
			if (mnt == NULL) {
				fprintf(stderr,
				    gettext("cannot read mount point kstat\n"));
				continue;
			}
			if (kstat_read(kslib, mnt, NULL) == -1) {
				continue;
			}
			if (labels)
				printf("%-*s: %s\n", MAX_LABEL_LEN,
				    gettext("Mount point"),
				    (char *)mnt->ks_data);
			else
				printf("%s\n", (char *)mnt->ks_data);
			break;
		case	INFO_STATE:
			/* state */
			numvalp = kstat_data_lookup(num,
			    FSSNAP_KSTAT_NUM_STATE);
			if (numvalp == NULL) {
				fprintf(stderr,
				    gettext("cannot read state kstat\n"));
				continue;
			}

			if (labels) {
				printf("%-*s: ", MAX_LABEL_LEN,
				    gettext("Device state"));
				switch (numvalp->value.i32) {
				case 0: printf(gettext("creating\n"));
					break;
				case 1: printf(gettext("idle\n"));
					break;
				case 2: printf(gettext("active\n"));
					break;
				case 3: printf(gettext("disabled\n"));
					break;
				default: printf(gettext("unknown\n"));
					break;
				}
			} else {
				switch (numvalp->value.i32) {
				case 0:	printf("creating\n");
					break;
				case 1:	printf("idle\n");
					break;
				case 2:	printf("active\n");
					break;
				case 3:	printf("disabled\n");
					break;
				default: printf("unknown\n");
					break;
				}
			}
			break;

		case	INFO_BACKPATH:
			/* backing file kstat */
			back = kstat_lookup(kslib, SNAP_NAME, snapnum,
			    FSSNAP_KSTAT_BFNAME);
			if (back == NULL ||
			    (kstat_read(kslib, back, NULL) == -1) ||
			    (back->ks_data == NULL)) {
				fprintf(stderr,
				    gettext("cannot read backing file name "
				    "kstat from kernel\n"));
				continue;
			}
			if (labels)
				printf("%-*s: %s\n", MAX_LABEL_LEN,
				    gettext("Backing store path"),
				    (char *)back->ks_data);
			else
				printf("%s\n", (char *)back->ks_data);
			break;

		case	INFO_BACKSIZE:
			numvalp = kstat_data_lookup(num,
			    FSSNAP_KSTAT_NUM_BFSIZE);
			if (numvalp == NULL) {
				fprintf(stderr,
				    gettext("cannot read backing file size "
				    "kstat from kernel\n"));
				continue;
			}

			size = numvalp->value.ui64;

			if (labels)
				printf("%-*s: %llu KB\n", MAX_LABEL_LEN,
				    gettext("Backing store size"),
				    size / 1024LL);
			else
				printf("%llu\n", size);
			break;

		case	INFO_MAXSIZE:
			numvalp = kstat_data_lookup(num,
			    FSSNAP_KSTAT_NUM_MAXSIZE);
			if (numvalp == NULL) {
				fprintf(stderr,
				    gettext("cannot read backing file maxsize "
				    "kstat from kernel\n"));
				continue;
			}
			if (labels) {
				printf("%-*s: ", MAX_LABEL_LEN,
				    gettext("Maximum backing store size"));

				if (numvalp->value.ui64 == 0LL)
					printf(gettext("Unlimited\n"));
				else
					printf("%llu KB\n",
					    numvalp->value.ui64 / 1024LL);
			} else {
				printf("%llu\n", numvalp->value.ui64);
			}
			break;

		case	INFO_CREATETIME:
		{
			/* snapshot creation time */
			char buf[256];
			struct tm *tm;
			char *p;

			numvalp = kstat_data_lookup(num,
			    FSSNAP_KSTAT_NUM_CREATETIME);
			if (numvalp == NULL) {
				fprintf(stderr,
				    gettext("cannot read snapshot create time "
				    "kstat from kernel\n"));
				continue;
			}

			if (labels) {
				printf("%-*s: ", MAX_LABEL_LEN,
				    gettext("Snapshot create time"));

				/* get the localized time */
				tm = localtime(&numvalp->value.l);
				if (strftime(buf, sizeof (buf),
				    "%c\n", tm) == 0)
					/* Wouldn't fit in buf, fall back */
					p = ctime(&numvalp->value.l);
				else
					p = buf;
			} else {
				/*
				 * for script-readable options we want
				 * the locale-independent time only.
				 */
				p = ctime(&numvalp->value.l);
			}
			/* p should already have a \n appended */
			printf("%s", p);
			break;
		}

		case	INFO_CHUNKSIZE:
			numvalp = kstat_data_lookup(num,
			    FSSNAP_KSTAT_NUM_CHUNKSIZE);
			if (numvalp == NULL) {
				fprintf(stderr,
				    gettext("cannot read chunksize kstat\n"));
				continue;
			}
			if (labels)
				printf("%-*s: %lu KB\n", MAX_LABEL_LEN,
				    gettext("Copy-on-write granularity"),
				    numvalp->value.ui32 / 1024L);
			else
				printf("%lu\n", numvalp->value.ui32);
			break;

		case	-1:
			/*
			 * Print a place holder for unknown options so that
			 * the user can determine which option was not
			 * understood and the number outputted is the same
			 * number they requested.
			 */
			printf("?\n");
			break;

		default:
			printf(gettext("No such data type %d.\n"), order[i]);
			break;
		}
	}
}
