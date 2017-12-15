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
 * Copyright (c) 2017, Joyent, Inc.
 */

/*
 * Private utility to dump transceiver information for each physical datalink.
 * Something like this should eventually be a part of dladm or similar.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <strings.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <stdarg.h>
#include <libgen.h>

#include <libdladm.h>
#include <libdllink.h>
#include <sys/dld.h>
#include <sys/dld_ioc.h>
#include <sys/dls_mgmt.h>
#include <libsff.h>

#define	DLTRAN_KIND_LEN	64

static dladm_handle_t dltran_hdl;
static char dltran_dlerrmsg[DLADM_STRSIZE];
static const char *dltran_progname;
static boolean_t dltran_verbose;
static boolean_t dltran_hex;
static boolean_t dltran_write;
static int dltran_outfd;
static int dltran_errors;

/*
 * This routine basically assumes that we'll have 16 byte aligned output to
 * print out the human readable output.
 */
static void
dltran_dump_page(uint8_t *buf, size_t nbytes, uint_t page)
{
	size_t i;
	static boolean_t first = B_TRUE;

	if (first) {
		(void) printf("page  %*s    0", 4, "");
		for (i = 1; i < 16; i++) {
			if (i % 4 == 0 && i % 16 != 0) {
				(void) printf(" ");
			}

			(void) printf("%2x", i);
		}
		(void) printf("  v123456789abcdef\n");
		first = B_FALSE;
	}
	for (i = 0; i < nbytes; i++) {

		if (i % 16 == 0) {
			(void) printf("0x%02x  %04x:  ", page, i);
		}

		if (i % 4 == 0 && i % 16 != 0) {
			(void) printf(" ");
		}


		(void) printf("%02x", buf[i]);

		if (i % 16 == 15) {
			int j;
			(void) printf("  ");
			for (j = i - (i % 16); j <= i; j++) {
				if (!isprint(buf[j])) {
					(void) printf(".");
				} else {
					(void) printf("%c", buf[j]);
				}
			}
			(void) printf("\n");
		}
	}
}

static int
dltran_read_page(datalink_id_t link, uint_t tranid, uint_t page, uint8_t *bufp,
    size_t *buflen)
{
	dld_ioc_tranio_t dti;

	bzero(bufp, *buflen);
	bzero(&dti, sizeof (dti));

	dti.dti_linkid = link;
	dti.dti_tran_id = tranid;
	dti.dti_page = page;
	dti.dti_nbytes = *buflen;
	dti.dti_off = 0;
	dti.dti_buf = (uintptr_t)(void *)bufp;

	if (ioctl(dladm_dld_fd(dltran_hdl), DLDIOC_READTRAN, &dti) != 0) {
		(void) fprintf(stderr, "failed to read transceiver page "
		    "0x%2x: %s\n", page, strerror(errno));
		return (1);
	}

	*buflen = dti.dti_nbytes;
	return (0);
}

static boolean_t
dltran_is_8472(uint8_t *buf)
{
	switch (buf[0]) {
	case 0xc:
	case 0xd:
	case 0x11:
		/*
		 * Catch cases that refer explicitly to QSFP and newer.
		 */
		return (B_FALSE);
	default:
		break;
	}

	/*
	 * Check the byte that indicates compliance with SFF 8472. Use this to
	 * know if we can read page 0xa2 or not.
	 */
	if (buf[94] == 0)
		return (B_FALSE);

	return (B_TRUE);
}

static void
dltran_hex_dump(datalink_id_t linkid, uint_t tranid)
{
	uint8_t buf[256];
	size_t buflen = sizeof (buf);

	if (dltran_read_page(linkid, tranid, 0xa0, buf, &buflen) != 0) {
		dltran_errors++;
		return;
	}

	dltran_dump_page(buf, buflen, 0xa0);

	if (!dltran_is_8472(buf)) {
		return;
	}

	buflen = sizeof (buf);
	if (dltran_read_page(linkid, tranid, 0xa2, buf, &buflen) != 0) {
		dltran_errors++;
		return;
	}

	dltran_dump_page(buf, buflen, 0xa2);
}

static void
dltran_write_page(datalink_id_t linkid, uint_t tranid)
{
	uint8_t buf[256];
	size_t buflen = sizeof (buf);
	off_t off;

	if (dltran_read_page(linkid, tranid, 0xa0, buf, &buflen) != 0) {
		dltran_errors++;
		return;
	}

	off = 0;
	while (buflen > 0) {
		ssize_t ret;

		ret = write(dltran_outfd, buf + off, buflen);
		if (ret == -1) {
			(void) fprintf(stderr, "failed to write data "
			    "to output file: %s\n", strerror(errno));
			dltran_errors++;
			return;
		}

		off += ret;
		buflen -= ret;
	}
}

static void
dltran_verbose_dump(datalink_id_t linkid, uint_t tranid)
{
	uint8_t buf[256];
	size_t buflen = sizeof (buf);
	int ret;
	nvlist_t *nvl;

	if (dltran_read_page(linkid, tranid, 0xa0, buf, &buflen) != 0) {
		dltran_errors++;
		return;
	}

	ret = libsff_parse(buf, buflen, 0xa0, &nvl);
	if (ret == 0) {
		dump_nvlist(nvl, 8);
		nvlist_free(nvl);
	} else {
		fprintf(stderr, "failed to parse sfp data: %s\n",
		    strerror(ret));
		dltran_errors++;
	}
}

static int
dltran_dump_transceivers(dladm_handle_t hdl, datalink_id_t linkid, void *arg)
{
	dladm_status_t status;
	char name[MAXLINKNAMELEN];
	dld_ioc_gettran_t gt;
	uint_t count, i, tranid = UINT_MAX;
	boolean_t tran_found = B_FALSE;
	uint_t *tranidp = arg;

	if (tranidp != NULL)
		tranid = *tranidp;

	if ((status = dladm_datalink_id2info(hdl, linkid, NULL, NULL, NULL,
	    name, sizeof (name))) != DLADM_STATUS_OK) {
		(void) fprintf(stderr, "failed to get datalink name for link "
		    "%d: %s", linkid, dladm_status2str(status,
		    dltran_dlerrmsg));
		dltran_errors++;
		return (DLADM_WALK_CONTINUE);
	}

	bzero(&gt, sizeof (gt));
	gt.dgt_linkid = linkid;
	gt.dgt_tran_id = DLDIOC_GETTRAN_GETNTRAN;

	if (ioctl(dladm_dld_fd(hdl), DLDIOC_GETTRAN, &gt) != 0) {
		if (errno != ENOTSUP) {
			(void) fprintf(stderr, "failed to get transceiver "
			    "count for device %s: %s\n",
			    name, strerror(errno));
			dltran_errors++;
		}
		return (DLADM_WALK_CONTINUE);
	}

	count = gt.dgt_tran_id;
	(void) printf("%s: discovered %d transceiver%s\n", name, count,
	    count > 1 ? "s" : "");
	for (i = 0; i < count; i++) {
		if (tranid != UINT_MAX && i != tranid)
			continue;
		if (tranid != UINT_MAX)
			tran_found = B_TRUE;
		bzero(&gt, sizeof (gt));
		gt.dgt_linkid = linkid;
		gt.dgt_tran_id = i;

		if (ioctl(dladm_dld_fd(hdl), DLDIOC_GETTRAN, &gt) != 0) {
			(void) fprintf(stderr, "failed to get tran info for "
			    "%s: %s\n", name, strerror(errno));
			dltran_errors++;
			return (DLADM_WALK_CONTINUE);
		}

		if (dltran_hex && !gt.dgt_present)
			continue;
		if (!dltran_hex && !dltran_write) {
			(void) printf("\ttransceiver %d present: %s\n", i,
			    gt.dgt_present ? "yes" : "no");
			if (!gt.dgt_present)
				continue;
			(void) printf("\ttransceiver %d usable: %s\n", i,
			    gt.dgt_usable ? "yes" : "no");
		}

		if (dltran_verbose) {
			dltran_verbose_dump(linkid, i);
		}

		if (dltran_write) {
			if (!gt.dgt_present) {
				(void) fprintf(stderr, "warning: no "
				    "transceiver present in port %d, not "
				    "writing\n", i);
				dltran_errors++;
				continue;
			}
			dltran_write_page(linkid, i);
		}

		if (dltran_hex) {
			printf("transceiver %d data:\n", i);
			dltran_hex_dump(linkid, i);
		}
	}

	if (tranid != UINT_MAX && !tran_found) {
		dltran_errors++;
		(void) fprintf(stderr, "failed to find transceiver %d on "
		    "link %s\n", tranid, name);
	}

	return (DLADM_WALK_CONTINUE);
}


static void
dltran_usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		(void) fprintf(stderr, "%s: ", dltran_progname);
		va_start(ap, fmt);
		(void) vfprintf(stderr, fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage: %s [-x | -v | -w file] [tran]...\n"
	    "\n"
	    "\t-v	display all transceiver information\n"
	    "\t-w	write transceiver data page 0xa0 to file\n"
	    "\t-x	dump raw hexadecimal for transceiver\n",
	    dltran_progname);
}

int
main(int argc, char *argv[])
{
	int c;
	dladm_status_t status;
	const char *outfile = NULL;
	uint_t count = 0;

	dltran_progname = basename(argv[0]);

	while ((c = getopt(argc, argv, ":xvw:")) != -1) {
		switch (c) {
		case 'v':
			dltran_verbose = B_TRUE;
			break;
		case 'x':
			dltran_hex = B_TRUE;
			break;
		case 'w':
			dltran_write = B_TRUE;
			outfile = optarg;
			break;
		case ':':
			dltran_usage("option -%c requires an "
			    "operand\n", optopt);
			return (2);
		case '?':
		default:
			dltran_usage("unknown option: -%c\n", optopt);
			return (2);
		}
	}

	argc -= optind;
	argv += optind;

	if (dltran_verbose)
		count++;
	if (dltran_hex)
		count++;
	if (dltran_write)
		count++;
	if (count > 1) {
		(void) fprintf(stderr, "only one of -v, -w, and -x may be "
		    "specified\n");
		return (2);
	}

	if (dltran_write) {
		if ((dltran_outfd = open(outfile, O_RDWR | O_TRUNC | O_CREAT,
		    0644)) < 0) {
			(void) fprintf(stderr, "failed to open output file "
			    "%s: %s\n", outfile, strerror(errno));
			return (1);
		}
	}

	if ((status = dladm_open(&dltran_hdl)) != DLADM_STATUS_OK) {
		(void) fprintf(stderr, "failed to open /dev/dld: %s\n",
		    dladm_status2str(status, dltran_dlerrmsg));
		return (1);
	}

	if (argc == 0) {
		(void) dladm_walk_datalink_id(dltran_dump_transceivers,
		    dltran_hdl, NULL, DATALINK_CLASS_PHYS,
		    DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
	} else {
		int i;
		char *c;

		for (i = 0; i < argc; i++) {
			uint_t tran;
			uint_t *tranidp = NULL;
			datalink_id_t linkid;

			if ((c = strrchr(argv[i], '/')) != NULL) {
				unsigned long u;
				char *eptr;

				c++;
				errno = 0;
				u = strtoul(c, &eptr, 10);
				if (errno != 0 || *eptr != '\0' ||
				    u >= UINT_MAX) {
					(void) fprintf(stderr, "failed to "
					    "parse link/transceiver: %s\n",
					    argv[i]);
					return (1);
				}
				c--;
				*c = '\0';
				tran = (uint_t)u;
				tranidp = &tran;
			}

			if ((status = dladm_name2info(dltran_hdl, argv[i],
			    &linkid, NULL, NULL, NULL)) != DLADM_STATUS_OK) {
				(void) fprintf(stderr, "failed to get link "
				    "id for link %s: %s\n", argv[i],
				    dladm_status2str(status, dltran_dlerrmsg));
				return (1);
			}

			(void) dltran_dump_transceivers(dltran_hdl, linkid,
			    tranidp);
		}
	}

	return (dltran_errors != 0 ? 1 : 0);
}
