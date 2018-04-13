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
 * Copyright (c) 2018 by Chelsio Communications, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <strings.h>
#include <sys/varargs.h>
#include <errno.h>
#include <sys/byteorder.h>
#include <inttypes.h>
#include <sys/sysmacros.h>

#include "t4nex.h"
#include "version.h"
#include "osdep.h"
#include "t4fw_interface.h"

/*
 * Firmware Device Log Dumping
 */

static const char * const devlog_level_strings[] = {
	[FW_DEVLOG_LEVEL_EMERG]		= "EMERG",
	[FW_DEVLOG_LEVEL_CRIT]		= "CRIT",
	[FW_DEVLOG_LEVEL_ERR]		= "ERR",
	[FW_DEVLOG_LEVEL_NOTICE]	= "NOTICE",
	[FW_DEVLOG_LEVEL_INFO]		= "INFO",
	[FW_DEVLOG_LEVEL_DEBUG]		= "DEBUG"
};

static const char * const devlog_facility_strings[] = {
	[FW_DEVLOG_FACILITY_CORE]	= "CORE",
	[FW_DEVLOG_FACILITY_CF]		= "CF",
	[FW_DEVLOG_FACILITY_SCHED]	= "SCHED",
	[FW_DEVLOG_FACILITY_TIMER]	= "TIMER",
	[FW_DEVLOG_FACILITY_RES]	= "RES",
	[FW_DEVLOG_FACILITY_HW]		= "HW",
	[FW_DEVLOG_FACILITY_FLR]	= "FLR",
	[FW_DEVLOG_FACILITY_DMAQ]	= "DMAQ",
	[FW_DEVLOG_FACILITY_PHY]	= "PHY",
	[FW_DEVLOG_FACILITY_MAC]	= "MAC",
	[FW_DEVLOG_FACILITY_PORT]	= "PORT",
	[FW_DEVLOG_FACILITY_VI]		= "VI",
	[FW_DEVLOG_FACILITY_FILTER]	= "FILTER",
	[FW_DEVLOG_FACILITY_ACL]	= "ACL",
	[FW_DEVLOG_FACILITY_TM]		= "TM",
	[FW_DEVLOG_FACILITY_QFC]	= "QFC",
	[FW_DEVLOG_FACILITY_DCB]	= "DCB",
	[FW_DEVLOG_FACILITY_ETH]	= "ETH",
	[FW_DEVLOG_FACILITY_OFLD]	= "OFLD",
	[FW_DEVLOG_FACILITY_RI]		= "RI",
	[FW_DEVLOG_FACILITY_ISCSI]	= "ISCSI",
	[FW_DEVLOG_FACILITY_FCOE]	= "FCOE",
	[FW_DEVLOG_FACILITY_FOISCSI]	= "FOISCSI",
	[FW_DEVLOG_FACILITY_FOFCOE]	= "FOFCOE",
	[FW_DEVLOG_FACILITY_CHNET]	= "CHNET",
};

static const char *progname;

static void usage(FILE *fp)
{
	fprintf(fp, "Usage: %s <path to t4nex#> [operation]\n", progname);
	fprintf(fp,
	    "\tdevlog                              show device log\n"
	    "\tloadfw <FW image>                   Flash the FW image\n");
	exit(fp == stderr ? 1 : 0);
}

static void
err(int code, const char *fmt, ...)
{
	va_list ap;
	int e = errno;

	va_start(ap, fmt);
	fprintf(stderr, "error: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(e));
	va_end(ap);
	exit(code);
}

static int
doit(const char *iff_name, unsigned long cmd, void *data)
{
	int fd = 0;
	int rc = 0;

	if ((fd = open(iff_name, O_RDWR)) < 0)
		return (-1);

	rc = (ioctl(fd, cmd, data) < 0) ? errno : rc;
	close(fd);
	return (rc);
}

static void
get_devlog(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct t4_devlog *devlog;
	struct fw_devlog_e *entry, *buf;
	int rc = 0, first = 0, nentries, i, j, len;
	uint64_t ftstamp = UINT64_MAX;

	devlog = malloc(T4_DEVLOG_SIZE + sizeof (struct t4_devlog));
	if (!devlog)
		err(1, "%s: can't allocate devlog buffer", __func__);

	devlog->len = T4_DEVLOG_SIZE;
	/* Get device log */
	rc = doit(iff_name, T4_IOCTL_DEVLOG, devlog);
	if (rc == ENOBUFS) {
		/*
		 * Default buffer size is not sufficient to hold device log.
		 * Driver has updated the devlog.len to indicate the expected
		 * size. Free the currently allocated devlog.data, allocate
		 * again with right size and retry.
		 */
		len = devlog->len;
		free(devlog);

		if ((devlog = malloc(len + sizeof (struct t4_devlog))) == NULL)
			err(1, "%s: can't reallocate devlog buffer", __func__);

		rc = doit(iff_name, T4_IOCTL_DEVLOG, devlog);
	}
	if (rc) {
		free(devlog);
		err(1, "%s: can't get device log", __func__);
	}

	/* There are nentries number of entries in the buffer */
	nentries = (devlog->len / sizeof (struct fw_devlog_e));

	buf = (struct fw_devlog_e *)devlog->data;

	/* Find the first entry */
	for (i = 0; i < nentries; i++) {
		entry = &buf[i];

		if (entry->timestamp == 0)
			break;

		entry->timestamp = BE_64(entry->timestamp);
		entry->seqno = BE_32(entry->seqno);
		for (j = 0; j < 8; j++)
			entry->params[j] = BE_32(entry->params[j]);

		if (entry->timestamp < ftstamp) {
			ftstamp = entry->timestamp;
			first = i;
		}
	}

	printf("%10s  %15s  %8s  %8s  %s\n", "Seq#", "Tstamp", "Level",
	    "Facility", "Message");

	i = first;

	do {
		entry = &buf[i];

		if (entry->timestamp == 0)
			break;

		printf("%10d  %15llu  %8s  %8s  ", entry->seqno,
		    entry->timestamp,
		    (entry->level < ARRAY_SIZE(devlog_level_strings) ?
		    devlog_level_strings[entry->level] : "UNKNOWN"),
		    (entry->facility < ARRAY_SIZE(devlog_facility_strings) ?
		    devlog_facility_strings[entry->facility] : "UNKNOWN"));

		printf((const char *)entry->fmt, entry->params[0],
		    entry->params[1], entry->params[2], entry->params[3],
		    entry->params[4], entry->params[5], entry->params[6],
		    entry->params[7]);

		if (++i == nentries)
			i = 0;

	} while (i != first);

	free(devlog);
}

static void
load_fw(int argc, char *argv[], int start_arg, const char *iff_name)
{
	const char *fname = argv[start_arg];
	struct t4_ldfw *fw;
	struct stat sb;
	size_t len;
	int fd;

	if (argc != 4)
		err(1, "incorrect number of arguments.");

	fd = open(fname, O_RDONLY);
	if (fd < 0)
		err(1, "%s: opening %s failed", __func__, fname);
	if (fstat(fd, &sb) < 0) {
		close(fd);
		err(1, "%s: fstat %s failed", __func__, fname);
	}
	len = (size_t)sb.st_size;

	fw = malloc(sizeof (struct t4_ldfw) + len);
	if (!fw) {
		close(fd);
		err(1, "%s: %s allocate %ld bytes failed",
		    __func__, fname, sizeof (struct t4_ldfw) + len);
	}

	if (read(fd, fw->data, len) < len) {
		close(fd);
		free(fw);
		err(1, "%s: %s read failed", __func__, fname);
	}

	close(fd);

	fw->len = len;

	if (doit(iff_name, T4_IOCTL_LOAD_FW, fw)) {
		free(fw);
		err(1, "%s: IOCTL failed", __func__);
	} else {
		printf("FW flash success, reload driver/reboot to take "
		    "effect\n");
	}

	free(fw);
}

static void
run_cmd(int argc, char *argv[], const char *iff_name)
{
	if (strcmp(argv[2], "devlog") == 0)
		get_devlog(argc, argv, 3, iff_name);
	else if (strcmp(argv[2], "loadfw") == 0)
		load_fw(argc, argv, 3, iff_name);
	else
		usage(stderr);
}

int
main(int argc, char *argv[])
{
	const char *iff_name;

	progname = argv[0];

	if (argc == 2) {
		if (strcmp(argv[1], "-h") == 0 ||
		    strcmp(argv[1], "--help") == 0) {
			usage(stdout);
		}

		if (strcmp(argv[1], "-v") == 0 ||
		    strcmp(argv[1], "--version") == 0) {
			printf("cxgbetool version %s\n", DRV_VERSION);
			exit(0);
		}
	}

	if (argc < 3)
		usage(stderr);

	iff_name = argv[1];

	run_cmd(argc, argv, iff_name);

	return (0);
}
