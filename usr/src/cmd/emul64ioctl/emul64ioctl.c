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
 * This program provides a command line interface to the
 * three new ioctls for the emul64 driver - EMUL64_WRITE_OFF,
 * EMUL64_WRITE_ON and EMUL64_ZERO_RANGE. All three of these
 * ioctls require the range of blocks to be specified. The
 * range is specified by starting block number and block count
 * both of which are 64 bit.
 *
 * Returns 0 on success, >0 on failure.
 *
 */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/emul64.h>

#define	DEBUG	1
#define	ADMIN_DIR	"/dev/cfg/"

char *Pname;

static int	get_disk_addr(char *path, emul64_tgt_range_t *tr, char **admin);

static void
usage(void)
{
	(void) fprintf(stderr, "Usage: emul64ioctl -s start_block "
	    "-b block_count -c write_off | write_on | zero emul64_dev\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	extern char	*optarg;
	extern int	optind;
	char		*admin;
	int		count_seen = 0;
	int 		fd, retval;
	int		cmd = -1;
	int		do_usage = 0;
	char		*slice;
	int		sb_seen = 0;
	emul64_tgt_range_t tr;

	Pname = strrchr(argv[0], '/');
	if (Pname == NULL)
		Pname = argv[0];
	else
		Pname++;

	while ((retval = getopt(argc, argv, "s:b:c:")) != -1) {
		switch (retval) {
		case 's':
			sb_seen = 1;
			tr.emul64_blkrange.emul64_sb = atoll(optarg);
			break;
		case 'b':
			count_seen = 1;
			tr.emul64_blkrange.emul64_blkcnt = atoll(optarg);
			break;
		case 'c':
			if (strncmp(optarg, "write_off",
			    strlen("write_off")) == 0) {
				cmd = EMUL64_WRITE_OFF;
			} else if (strncmp(optarg, "write_on",
			    strlen("write_on")) == 0) {
				cmd = EMUL64_WRITE_ON;
			} else if (strncmp(optarg, "zero",
			    strlen("zero")) == 0) {
				cmd = EMUL64_ZERO_RANGE;
			} else {
			    do_usage = 1;
			}
			break;
		    default:
			break;
		}
	}

	if (do_usage || (optind != argc - 1)) {
		usage();
	}
	if ((sb_seen == 0) || (count_seen == 0) || (cmd == -1))
		usage();

	slice = argv[optind];

	/*
	 * Get admin device, target and lun
	 */
	if (get_disk_addr(slice, &tr, &admin) != 0)
		exit(1);

	/*
	 * open the specified emul64_dev.
	 */
	if ((fd = open(admin, O_RDONLY, 0444)) != -1)	{

		retval = ioctl(fd, cmd, &tr);
		(void) close(fd);

		if (retval != -1) {
			free(admin);
			return (0);
		}
		(void) printf("emul64ioctl: %s: ioctl %s\n",
		    admin, strerror(errno));
	} else {
		(void) printf("emul64ioctl: %s: open %s\n",
		    admin, strerror(errno));
	}
	free(admin);
	return (1);
}

#define	TOK_CHECK(s)	if (token == NULL) {\
						bogus = (s);\
						goto err_out;\
			}

static int
get_disk_addr(char *path, emul64_tgt_range_t *tr, char **admin)
{
	size_t		admin_size;
	int		ctlr_num;
	int		conversions;
	char		*ctds;

	*admin = NULL;
	ctds = strrchr(path, '/');
	if (ctds == NULL)
		ctds = path;
	else
		ctds++;
	conversions = sscanf(ctds, "c%dt%hud%hu", &ctlr_num,
				&tr->emul64_target, &tr->emul64_lun);
	if (conversions != 3) {
		(void) fprintf(stderr, "%s: \"%s\" is invalid disk name.  "
			"%d conversions\n", Pname, ctds, conversions);
		return (-1);
	}

	/* Build controller name */
	admin_size = strlen(ADMIN_DIR) +
		10 +		/* enough digits for an int */
		1 +		/* c */
		1;		/* Null terminator */
	*admin = malloc(admin_size);
	if (*admin == NULL) {
		(void) fprintf(stderr, "%s: out of memory\n", Pname);
		return (-1);
	}
	(void) snprintf(*admin, admin_size, "%sc%d", ADMIN_DIR, ctlr_num);
	return (0);
}
