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
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <sys/multiboot.h>

#include "bblk_einfo.h"
#include "boot_utils.h"
#include "mboot_extra.h"

/*
 * Add version to loader bootblock file. The file should have fake
 * multiboot header and version data will be added at the end of the file.
 * MB header is fake in sense that this bootblock is *not* MB compatible,
 * and MB header will only include load_addr and load_end_addr components.
 * load_addr will be set to value 0 to indicate the beginning of the file
 * and load_end_addr will be set to the size of the original file.
 * The flags value in header must be exactly AOUT kludge.
 *
 * version data is aligned by 8 bytes and whole blootblock will be padded to
 * 512B sector size.
 *
 * To use and verify version data, first find MB header, then load_end_addr
 * will point to the end of the original file, aligned up by 8, is version
 * data implemented as bblk einfo.
 */

void
add_version(char *file, char *version)
{
	int fd;
	int ret;
	uint32_t buf_size;
	uint32_t mboot_off;
	uint32_t extra;
	uint32_t avail_space;
	multiboot_header_t *mboot;
	struct stat sb;
	char *buf;
	bblk_hs_t hs;

	fd = open(file, O_RDONLY);
	if (fd == -1) {
		perror("open");
		return;
	}
	if (fstat(fd, &sb) == -1) {
		perror("fstat");
		close(fd);
		return;
	}

	/*
	 * make sure we have enough space to append EINFO.
	 */
	buf_size = P2ROUNDUP(sb.st_size + SECTOR_SIZE, SECTOR_SIZE);
	buf = malloc(buf_size);
	if (buf == NULL) {
		perror("malloc");
		close(fd);
		return;
	}

	/*
	 * read in whole file. we need to access MB header and einfo
	 * will create MD5 hash.
	 */
	ret = read(fd, buf, sb.st_size);
	if (ret != sb.st_size) {
		perror("read");
		free(buf);
		close(fd);
		return;
	}
	close(fd);

	if (find_multiboot(buf, MBOOT_SCAN_SIZE, &mboot_off)
	    != BC_SUCCESS) {
		printf("Unable to find multiboot header\n");
		free(buf);
		return;
	}

	mboot = (multiboot_header_t *)(buf + mboot_off);
	mboot->load_addr = 0;
	mboot->load_end_addr = sb.st_size;


	hs.src_buf = (unsigned char *)buf;
	hs.src_size = sb.st_size;

	/*
	 * this is location for EINFO data
	 */
	extra = P2ROUNDUP(sb.st_size, 8);
	avail_space = buf_size - extra;
	memset(buf+sb.st_size, 0, buf_size - sb.st_size);
	add_einfo(buf + extra, version, &hs, avail_space);

	fd = open(file, O_WRONLY | O_TRUNC);
	if (fd == -1) {
		perror("open");
		free(buf);
		return;
	}
	ret = write(fd, buf, buf_size);
	close(fd);
	free(buf);
}
