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
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Command utility to drive synthetic memory decoding.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <sys/mman.h>
#include <libnvpair.h>

#include <sys/mc.h>
#include "imc.h"

#define	MCDECODE_USAGE	2

/*
 * Write in 32k chunks.
 */
#define	MCDECODE_WRITE	(1024 * 32)

static void
mcdecode_usage(void)
{
	(void) fprintf(stderr,
	    "Usage: mcdecode [-f infile] [-d address | -w outfile] device\n"
	    "\n"
	    "\t-d  decode physical address to the correspond dimm\n"
	    "\t-f  use decoder image from infile\n"
	    "\t-w  write decoder snapshot state to the specified file\n");
	exit(MCDECODE_USAGE);
}

static void
mcdecode_from_file(const char *file, uint64_t pa)
{
	int fd, ret;
	struct stat st;
	void *addr;
	nvlist_t *nvl;
	imc_t imc;
	imc_decode_state_t dec;
	char *driver;

	if ((fd = open(file, O_RDONLY)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", file);
	}

	if (fstat(fd, &st) != 0) {
		err(EXIT_FAILURE, "failed to get file information for %s",
		    file);
	}

	addr = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
	    fd, 0);
	if (addr == MAP_FAILED) {
		err(EXIT_FAILURE, "failed to map %s", file);
	}
	ret = nvlist_unpack(addr, st.st_size, &nvl, 0);
	if (ret != 0) {
		errx(EXIT_FAILURE, "failed to unpack %s: %s",
		    strerror(ret));
	}
	if (munmap(addr, st.st_size) != 0) {
		err(EXIT_FAILURE, "failed to unmap %s", file);
	}
	if (close(fd) != 0) {
		err(EXIT_FAILURE, "failed to close fd for %s", file);
	}

	if (nvlist_lookup_string(nvl, "mc_dump_driver", &driver) != 0) {
		errx(EXIT_FAILURE, "missing driver indication in dump %s",
		    file);
	}

	if (strcmp(driver, "imc") != 0) {
		errx(EXIT_FAILURE, "unknown driver dump source %s\n", driver);
	}

	if (!imc_restore_decoder(nvl, &imc)) {
		errx(EXIT_FAILURE, "failed to restore memory controller "
		    "snapshot in %s", file);
	}

	bzero(&dec, sizeof (dec));

	if (!imc_decode_pa(&imc, pa, &dec)) {
		errx(EXIT_FAILURE, "failed to decode address 0x%" PRIx64, pa);
	}

	(void) printf("Decoded physical address 0x%" PRIx64 "\n"
	    "\tchip:\t\t\t%u\n"
	    "\tmemory controller:\t%u\n"
	    "\tchannel:\t\t%u\n"
	    "\tdimm:\t\t\t%u\n"
	    "\trank:\t\t\t%u\n",
	    pa, dec.ids_nodeid, dec.ids_tadid, dec.ids_channelid,
	    dec.ids_dimmid, dec.ids_rankid);

	nvlist_free(nvl);
}

static void
mcdecode_pa(const char *device, uint64_t pa)
{
	int fd;
	mc_encode_ioc_t ioc;

	bzero(&ioc, sizeof (ioc));
	ioc.mcei_pa = pa;

	if ((fd = open(device, O_RDONLY)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", device);
	}

	if (ioctl(fd, MC_IOC_DECODE_PA, &ioc) != 0) {
		err(EXIT_FAILURE, "failed to issue decode ioctl");
	}

	if (ioc.mcei_err != 0) {
		(void) fprintf(stderr, "decoding of address 0x%" PRIx64
		    " failed with error 0x%x\n", pa, ioc.mcei_err);
		exit(EXIT_FAILURE);
	}

	(void) printf("Decoded physical address 0x%" PRIx64 "\n"
	    "\tchip:\t\t\t%u\n"
	    "\tmemory controller:\t%u\n"
	    "\tchannel:\t\t%u\n"
	    "\tdimm:\t\t\t%u\n"
	    "\trank:\t\t\t%u\n",
	    pa, ioc.mcei_chip, ioc.mcei_mc, ioc.mcei_chan, ioc.mcei_dimm,
	    ioc.mcei_rank);

	(void) close(fd);
}

static void
mcdecode_dump(const char *device, const char *outfile)
{
	int fd;
	mc_snapshot_info_t mcs;
	char *buf;

	if ((fd = open(device, O_RDONLY)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", device);
	}

	bzero(&mcs, sizeof (mcs));
	if (ioctl(fd, MC_IOC_DECODE_SNAPSHOT_INFO, &mcs) != 0) {
		err(EXIT_FAILURE, "failed to get decode snapshot information");
	}

	if ((buf = malloc(mcs.mcs_size)) == NULL) {
		err(EXIT_FAILURE, "failed to allocate %u bytes for the "
		    "dump snapshot", mcs.mcs_size);
	}

	if (ioctl(fd, MC_IOC_DECODE_SNAPSHOT, buf) != 0) {
		err(EXIT_FAILURE, "failed to retrieve decode snapshot");
	}
	(void) close(fd);

	if ((fd = open(outfile, O_RDWR | O_CREAT | O_TRUNC, 0644)) < 0) {
		err(EXIT_FAILURE, "failed to create output file %s", outfile);
	}

	while (mcs.mcs_size > 0) {
		ssize_t ret;
		size_t out = mcs.mcs_size > MCDECODE_WRITE ? MCDECODE_WRITE :
		    mcs.mcs_size;

		ret = write(fd, buf, out);
		if (ret < 0) {
			warn("failed to write to output file %s", outfile);
			(void) unlink(outfile);
			exit(EXIT_FAILURE);
		}

		buf += ret;
		mcs.mcs_size -= ret;
	}

	if (fsync(fd) != 0) {
		warn("failed to sync output file %s", outfile);
		(void) unlink(outfile);
		exit(EXIT_FAILURE);
	}

	(void) close(fd);
}

int
main(int argc, char *argv[])
{
	int c;
	uint64_t pa = UINT64_MAX;
	const char *outfile = NULL;
	const char *infile = NULL;

	while ((c = getopt(argc, argv, "d:f:w:")) != -1) {
		char *eptr;
		unsigned long long tmp;

		switch (c) {
		case 'd':
			errno = 0;
			tmp = strtoull(optarg, &eptr, 0);
			if (errno != 0 || *eptr != '\0') {
				errx(EXIT_FAILURE, "failed to parse address "
				    "'%s'", eptr);
			}
			pa = (uint64_t)tmp;
			break;
		case 'f':
			infile = optarg;
			break;
		case 'w':
			outfile = optarg;
			break;
		case ':':
			warnx("Option -%c requires an operand", optopt);
			mcdecode_usage();
			break;
		case '?':
			warnx("Unknown option: -%c", optopt);
			mcdecode_usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (outfile != NULL && infile != NULL) {
		errx(EXIT_FAILURE, "-f and -w cannot be used together");
	}

	if (pa != UINT64_MAX && outfile != NULL) {
		errx(EXIT_FAILURE, "-w and -d cannot be used together");
	}

	if (pa == UINT64_MAX && outfile == NULL) {
		warnx("missing either -d or -w\n");
		mcdecode_usage();

	}

	if (argc != 1 && infile == NULL) {
		errx(EXIT_FAILURE, "missing device argument");
	}


	if (pa != UINT64_MAX) {
		if (infile != NULL) {
			mcdecode_from_file(infile, pa);
		} else {
			mcdecode_pa(argv[0], pa);
		}
	} else {
		mcdecode_dump(argv[0], outfile);
	}
	return (0);
}
