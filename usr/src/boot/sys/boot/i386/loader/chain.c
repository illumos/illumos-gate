/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Toomas Soome <tsoome@me.com>
 */

/*
 * Chain loader to load BIOS boot block either from MBR or PBR.
 *
 * Note the boot block location 0000:7c000 conflicts with loader, so we need to
 * read in to temporary space and relocate on exec, when btx is stopped.
 */

#include <sys/cdefs.h>
#include <stand.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/diskmbr.h>

#include "bootstrap.h"
#include "libi386/libi386.h"
#include "btxv86.h"

/*
 * The MBR/VBR is located in first sector of disk/partition.
 * Read 512B to temporary location and set up relocation. Then
 * exec relocator.
 */
#define	SECTOR_SIZE	(512)

COMMAND_SET(chain, "chain", "chain load boot block from device", command_chain);

static int
command_chain(int argc, char *argv[])
{
	int fd, len, size = SECTOR_SIZE;
	struct stat st;
	vm_offset_t mem = 0x100000;
	struct i386_devdesc *rootdev;

	if (argc == 1) {
		command_errmsg = "no device or file name specified";
		return (CMD_ERROR);
	}
	if (argc != 2) {
		command_errmsg = "invalid trailing arguments";
		return (CMD_ERROR);
	}

	fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		command_errmsg = "open failed";
		return (CMD_ERROR);
	}

	len = strlen(argv[1]);
	if (argv[1][len-1] != ':') {
		if (fstat(fd, &st) == -1) {
			command_errmsg = "stat failed";
			close(fd);
			return (CMD_ERROR);
		}
		size = st.st_size;
	} else if (strncmp(argv[1], "disk", 4) != 0) {
		command_errmsg = "can only use disk device";
		close(fd);
		return (CMD_ERROR);
	}

	i386_getdev((void **)(&rootdev), argv[1], NULL);
	if (rootdev == NULL) {
		command_errmsg = "can't determine root device";
		close(fd);
		return (CMD_ERROR);
	}

	if (archsw.arch_readin(fd, mem, size) != size) {
		command_errmsg = "failed to read disk";
		close(fd);
		return (CMD_ERROR);
	}
	close(fd);

	if (argv[1][len-1] == ':' &&
	    *((uint16_t *)PTOV(mem + DOSMAGICOFFSET)) != DOSMAGIC) {
		command_errmsg = "wrong magic";
		return (CMD_ERROR);
	}

	relocater_data[0].src = mem;
	relocater_data[0].dest = 0x7C00;
	relocater_data[0].size = size;

	relocator_edx = bd_unit2bios(rootdev->d_unit);
	relocator_esi = relocater_size;
	relocator_ds = 0;
	relocator_es = 0;
	relocator_fs = 0;
	relocator_gs = 0;
	relocator_ss = 0;
	relocator_cs = 0;
	relocator_sp = 0x7C00;
	relocator_ip = 0x7C00;
	relocator_a20_enabled = 0;

	i386_copyin(relocater, 0x600, relocater_size);

	dev_cleanup();

	__exec((void *)0x600);

	panic("exec returned");
	return (CMD_ERROR);		/* not reached */
}
