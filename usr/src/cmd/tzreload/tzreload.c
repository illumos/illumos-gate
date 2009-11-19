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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved	*/

#include <atomic.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <locale.h>
#include <libintl.h>
#include <zone.h>
#include <libzonecfg.h>
#include <sys/brand.h>
#include <dlfcn.h>

#define	TZSYNC_FILE	"/var/run/tzsync"

static void	init_file(void);
static void	doit(const char *zname, const char *zroot, int get);
static void	counter_get(const char *zname, int fd);
static void	counter_set(int fd);
static void	walk_zones(int get);
static void	send_cron_msg(const char *zname, const char *zroot);

/*
 * There are undocumeted command line options:
 * -l	list the value of semaphore.
 * -I	initialize the semaphore file (ie /var/run/tzsync)
 */

int
main(int argc, char **argv)
{
	int	arg;
	int	all = 0, get = 0, init = 0;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((arg = getopt(argc, argv, "alI")) != EOF) {
		switch (arg) {
		case 'a':
			all = 1;
			break;
		case 'l':
			get = 1;
			break;
		case 'I':
			init = 1;
			break;
		default:
			(void) fprintf(stderr,
			    gettext("Usage: tzreload [-a]\n"));
			exit(1);
		}
	}

	if (init) {
		init_file();
		return (0);
	}

	if (all)
		walk_zones(get);
	else
		doit(NULL, "", get);

	return (0);
}

/*
 * Create /var/run/tzsync atomically.
 *
 * While creating the /var/run/tzsync initially, there is a timing window
 * that the file is created but no disk block is allocated (empty file).
 * If apps mmap'ed the file at the very moment, it succeeds but accessing
 * the memory page causes a segfault since disk block isn't yet allocated.
 * To avoid this situation, we create a temp file which has pagesize block
 * assigned, and then rename it to tzsync.
 */
static void
init_file(void)
{
	char	path[sizeof (TZSYNC_FILE) + 16];
	char	*buf;
	int	fd, pgsz;
	struct stat st;

	/* We don't allow to re-create the file */
	if (stat(TZSYNC_FILE, &st) == 0) {
		(void) fprintf(stderr, gettext("%s already exists.\n"),
		    TZSYNC_FILE);
		exit(1);
	}

	pgsz = sysconf(_SC_PAGESIZE);

	(void) strcpy(path, TZSYNC_FILE "XXXXXX");
	if ((fd = mkstemp(path)) == -1) {
		(void) fprintf(stderr,
		    gettext("failed to create a temporary file.\n"));
		exit(1);
	}

	if ((buf = calloc(1, pgsz)) == NULL) {
		(void) fprintf(stderr, gettext("Insufficient memory.\n"));
errout:
		(void) close(fd);
		(void) unlink(path);
		exit(1);
	}

	if (write(fd, buf, pgsz) != pgsz) {
		(void) fprintf(stderr,
		    gettext("failed to create tzsync file, %s\n"),
		    strerror(errno));
		goto errout;
	}
	(void) close(fd);

	/* link it */
	if (link(path, TZSYNC_FILE) != 0) {
		if (errno == EEXIST) {
			(void) fprintf(stderr, gettext("%s already exists.\n"),
			    TZSYNC_FILE);
		} else {
			(void) fprintf(stderr, gettext("failed to create %s\n"),
			    TZSYNC_FILE);
		}
		(void) unlink(path);
		exit(1);
	}
	(void) unlink(path);

	/*
	 * Unplivileged apps may fail to open the file until the chmod
	 * below succeeds. However, it's okay as long as open() fails;
	 * ctime() won't cache zoneinfo until file is opened and mmap'd.
	 */

	/* /var/run/tzsync has been made. Adjust permission */
	if (chmod(TZSYNC_FILE, 0644) != 0) {
		(void) fprintf(stderr,
		    gettext("failed to change permission of %s\n"),
		    TZSYNC_FILE);
		(void) unlink(TZSYNC_FILE);
		exit(1);
	}
}

/*
 * Open the /var/run/tzsync, then set or get the semaphore.
 *
 * zname	name of zone (NULL if no need to consider zones)
 * zroot	zone's root path
 * get		get/set semaphore
 */
static void
doit(const char *zname, const char *zroot, int get)
{
	int	fd;
	char	file[PATH_MAX + 1];

	if (strlcpy(file, zroot, sizeof (file)) >= sizeof (file) ||
	    strlcat(file, TZSYNC_FILE, sizeof (file)) >= sizeof (file)) {
		(void) fprintf(stderr, gettext("zonepath too long\n"));
		exit(1);
	}

	if ((fd = open(file, get ? O_RDONLY : O_RDWR)) < 0) {
		(void) fprintf(stderr,
		    gettext("Can't open file %s, %s\n"),
		    file, strerror(errno));
		exit(1);
	}

	if (get) {
		counter_get(zname, fd);
	} else {
		counter_set(fd);
		/* let cron reschedule events */
		send_cron_msg(zname, zroot);
	}

	(void) close(fd);
}

/*
 * Get semaphore value and print.
 */
static void
counter_get(const char *zname, int fd)
{
	uint32_t counter;
	caddr_t	addr;

	addr = mmap(NULL, sizeof (uint32_t), PROT_READ, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		(void) fprintf(stderr,
		    gettext("Error mapping semaphore: %s\n"),
		    strerror(errno));
		exit(1);
	}
	counter = *(uint32_t *)(uintptr_t)addr;

	(void) munmap(addr, sizeof (uint32_t));

	if (zname == NULL)
		(void) printf("%u\n", counter);
	else
		(void) printf("%-20s %u\n", zname, counter);

}

/*
 * Increment semaphore value.
 */
static void
counter_set(int fd)
{
	caddr_t	addr;

	addr = mmap(NULL, sizeof (uint32_t), PROT_READ|PROT_WRITE,
	    MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		(void) fprintf(stderr,
		    gettext("Error mapping semaphore: %s\n"),
		    strerror(errno));
		exit(1);
	}

	/*LINTED*/
	atomic_add_32((uint32_t *)addr, 1);

	(void) munmap(addr, sizeof (uint32_t));
}

/*
 * Walk through running zones and call doit() for each zones.
 *
 * Note: we call zone_get_rootpath() indirectly using dlopen().
 * This is because tzreload resides under /sbin and needs to run
 * without /usr (ie /usr/lib/libzonecfg.so.1). The reason tzreload
 * being in /sbin is that tzreload -I may be called to create
 * /var/run/tzsync before /usr is mounted. To do that zone_get_rootpath()
 * isn't necessary. Therefore, libzonecfg is dlopen'd when required
 * rather than having static linkage to it which would make tzreload
 * unable to run without /usr.
 */
static void
walk_zones(int get)
{
	zoneid_t *zids;
	uint_t	ui, nzents, onzents;
	char	zroot[PATH_MAX + 1];
	char	zname[ZONENAME_MAX];
	char	zbrand[MAXNAMELEN];
	static int (*get_zroot)(char *, char *, size_t);

	if (getzoneid() != GLOBAL_ZONEID) {
		(void) fprintf(stderr, gettext("not in the global zone.\n"));
		exit(1);
	}

	if (get_zroot == NULL) {
		void	*hdl;

		if ((hdl = dlopen("libzonecfg.so.1", RTLD_NOW)) == NULL) {
			(void) fprintf(stderr,
			    gettext("unable to get zone configuration.\n"));
			exit(1);
		}
		get_zroot = (int (*)(char *, char *, size_t))
		    dlsym(hdl, "zone_get_rootpath");
		if (get_zroot == NULL) {
			(void) fprintf(stderr,
			    gettext("unable to get zone configuration.\n"));
			exit(1);
		}
	}

	nzents = 0;
	if (zone_list(NULL, &nzents) != 0) {
		(void) fprintf(stderr,
		    gettext("failed to get zoneid list\n"));
		exit(1);
	}

again:
	if (nzents == 0)
		return;

	if ((zids = malloc(nzents * sizeof (zoneid_t))) == NULL) {
		(void) fprintf(stderr, gettext("Insufficient memory.\n"));
		exit(1);
	}

	onzents = nzents;
	if (zone_list(zids, &nzents) != 0) {
		(void) fprintf(stderr,
		    gettext("failed to get zoneid list\n"));
		exit(1);
	}

	if (nzents != onzents) {
		/* zone increased while doing zone_list() */
		free(zids);
		goto again;
	}

	for (ui = 0; ui < nzents; ui++) {
		if (zone_getattr(zids[ui], ZONE_ATTR_BRAND, zbrand,
		    sizeof (zbrand)) < 0) {
			(void) fprintf(stderr,
			    gettext("failed to get zone attribute\n"));
			exit(1);
		}
		/* We only take care of native zones */
		if (strcmp(zbrand, NATIVE_BRAND_NAME) != 0)
			continue;
		if (getzonenamebyid(zids[ui], zname, sizeof (zname)) < 0) {
			(void) fprintf(stderr,
			    gettext("failed to get zone name\n"));
			exit(1);
		}

		if (zids[ui] == GLOBAL_ZONEID) {
			zroot[0] = '\0';
		} else {
			if ((*get_zroot)(zname, zroot,
			    sizeof (zroot)) != Z_OK) {
				(void) fprintf(stderr,
				    gettext("failed to get zone's root\n"));
				exit(1);
			}
		}
		doit(zname, zroot, get);
	}
}

#include "cron.h"

/*
 * Send REFRESH event to cron.
 */
static void
send_cron_msg(const char *zname, const char *zroot)
{
	struct message msg;
	int	msgfd;
	char	fifo[PATH_MAX + 1];

	if (strlcpy(fifo, zroot, sizeof (fifo)) >= sizeof (fifo) ||
	    strlcat(fifo, FIFO, sizeof (fifo)) >= sizeof (fifo)) {
		(void) fprintf(stderr, gettext("zonepath too long\n"));
		exit(1);
	}

	(void) memset(&msg, 0, sizeof (msg));
	msg.etype = REFRESH;

	if ((msgfd = open(fifo, O_WRONLY|O_NDELAY)) < 0) {
		if (errno == ENXIO || errno == ENOENT) {
			if (zname != NULL) {
				(void) fprintf(stderr, gettext(
				    "cron isn't running in %s zone.\n"), zname);
			} else {
				(void) fprintf(stderr,
				    gettext("cron isn't running.\n"));
			}
		} else {
			if (zname != NULL) {
				(void) fprintf(stderr, gettext(
				    "failed to send message to cron "
				    "in %s zone.\n"), zname);
			} else {
				(void) fprintf(stderr, gettext(
				    "failed to send message to cron.\n"));
			}
		}
		return;
	}

	if (write(msgfd, &msg, sizeof (msg)) != sizeof (msg)) {
		(void) fprintf(stderr, gettext("failed to send message.\n"));
	}

	(void) close(msgfd);
}
