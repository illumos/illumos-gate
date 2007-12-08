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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/obpdefs.h>
#include <sys/reboot.h>
#include <sys/promif.h>
#include <sys/stat.h>
#include <sys/bootvfs.h>
#include <sys/platnames.h>
#include <sys/salib.h>
#include <sys/elf.h>
#include <sys/link.h>
#include <sys/auxv.h>
#include <sys/boot_policy.h>
#include <sys/boot_redirect.h>
#include <sys/bootconf.h>
#include <sys/boot.h>
#include "boot_plat.h"
#include "ramdisk.h"

#define	SUCCESS		0
#define	FAILURE		-1

#ifdef DEBUG
extern int debug = 0;
#else
static const int debug = 0;
#endif

#define	dprintf		if (debug) printf

char		*def_boot_archive = "boot_archive";
char		*def_miniroot = "miniroot";
extern char	cmd_line_boot_archive[];

extern int	openfile(char *filename);

static int
read_and_boot_ramdisk(int fd)
{
	struct stat	st;
	caddr_t		virt;
	size_t		size;
	extern		ssize_t xread(int, char *, size_t);

	if ((fstat(fd, &st) != 0) ||
	    ((virt = create_ramdisk(RD_ROOTFS, st.st_size, NULL)) == NULL))
		return (-1);

	dprintf("reading boot archive ...\n");
	if ((size = xread(fd, (char *)virt, st.st_size)) != st.st_size) {
		(void) printf("Error reading boot archive, bytes read = %ld, "
		    "filesize = %ld\n", (long)size, (long)st.st_size);
		destroy_ramdisk(RD_ROOTFS);
		return (-1);
	}

	boot_ramdisk(RD_ROOTFS);
	/* NOT REACHED */
	return (0);	/* to make cc happy */
}


static void
post_mountroot_nfs(void)
{
	int	fd;
	char	*fn;
	char	tmpname[MAXPATHLEN];

	for (;;) {
		fn = NULL;
		if (boothowto & RB_ASKNAME) {
			fn = (cmd_line_boot_archive[0] != '\0') ?
			    cmd_line_boot_archive : def_boot_archive;
			printf("Enter filename [%s]: ", fn);
			(void) cons_gets(tmpname, sizeof (tmpname));
			if (tmpname[0] != '\0')
				fn = tmpname;
		}

		if (boothowto & RB_HALT) {
			printf("Boot halted.\n");
			prom_enter_mon();
		}

		if (fn != NULL)
			fd = openfile(fn);
		else if (cmd_line_boot_archive[0] != '\0') {
			fn = cmd_line_boot_archive;
			fd = openfile(fn);
		} else {
			fn = def_boot_archive;
			if ((fd = openfile(fn)) == FAILURE) {
				fn = def_miniroot;
				fd = openfile(fn);
			}
		}

		if (fd == FAILURE) {
			if (fn != def_miniroot)
				printf("cannot open %s\n", fn);
			else
				printf("cannot open neither %s nor %s\n",
				    def_boot_archive, def_miniroot);
		} else {
			/*
			 * this function does not return if successful.
			 */
			(void) read_and_boot_ramdisk(fd);

			printf("boot failed\n");
			(void) close(fd);
		}
		boothowto |= RB_ASKNAME;
	}
}


/*
 * bpath is the boot device path buffer.
 * bargs is the boot arguments buffer.
 */
/*ARGSUSED*/
int
bootprog(char *bpath, char *bargs, boolean_t user_specified_filename)
{
	systype = set_fstype(v2path, bpath);

	if (verbosemode) {
		printf("device path '%s'\n", bpath);
		if (strcmp(bpath, v2path) != 0)
			printf("client path '%s'\n", v2path);
	}

	if (mountroot(bpath) != SUCCESS)
		prom_panic("Could not mount filesystem.");

	/*
	 * kernname (default-name) might have changed if mountroot() called
	 * boot_nfs_mountroot(), and it called set_default_filename().
	 */
	if (!user_specified_filename)
		(void) strcpy(filename, kernname);

	if (verbosemode)
		printf("standalone = `%s', args = `%s'\n", filename, bargs);

	set_client_bootargs(filename, bargs);

	post_mountroot_nfs();

	return (1);
}
