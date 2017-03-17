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

#define	DLTRAN_KIND_LEN	64

static dladm_handle_t dltran_hdl;
static char dltran_dlerrmsg[DLADM_STRSIZE];
static char **dltran_links;
static int dltran_nlinks;	/* array size */
static int dltran_clinks;	/* current count */
static boolean_t dltran_tranid_set;
static int dltran_tranid;
static const char *dltran_progname;

/* ARGSUSED */
static int
dltran_dump_transceivers(dladm_handle_t hdl, datalink_id_t linkid, void *arg)
{
	dladm_status_t status;
	char name[MAXLINKNAMELEN];
	dld_ioc_gettran_t gt;
	uint_t count, i;

	if ((status = dladm_datalink_id2info(hdl, linkid, NULL, NULL, NULL,
	    name, sizeof (name))) != DLADM_STATUS_OK) {
		(void) fprintf(stderr, "failed to get datalink name for link "
		    "%d: %s", linkid, dladm_status2str(status,
		    dltran_dlerrmsg));
		return (DLADM_WALK_CONTINUE);
	}

	if (dltran_nlinks != NULL) {
		for (i = 0; i < dltran_clinks; i++) {
			if (strcmp(dltran_links[i], name) == 0)
				break;
		}
		if (i == dltran_clinks)
			return (DLADM_WALK_CONTINUE);
	}

	bzero(&gt, sizeof (gt));
	gt.dgt_linkid = linkid;
	gt.dgt_tran_id = DLDIOC_GETTRAN_GETNTRAN;

	if (ioctl(dladm_dld_fd(hdl), DLDIOC_GETTRAN, &gt) != 0) {
		(void) fprintf(stderr, "failed to get transceiver count "
		    "for device %s: %s\n",
		    name, strerror(errno));
		return (DLADM_WALK_CONTINUE);
	}


	count = gt.dgt_tran_id;
	(void) printf("%s: discovered %d transceivers\n", name, count);
	for (i = 0; i < count; i++) {
		if (dltran_tranid_set && i != dltran_tranid)
			continue;
		bzero(&gt, sizeof (gt));
		gt.dgt_linkid = linkid;
		gt.dgt_tran_id = i;

		if (ioctl(dladm_dld_fd(hdl), DLDIOC_GETTRAN, &gt) != 0) {
			(void) fprintf(stderr, "failed to get tran info for "
			    "%s: %s\n", name, strerror(errno));
			return (DLADM_WALK_CONTINUE);
		}

		(void) printf("\ttransceiver %d present: %s\n", i,
		    gt.dgt_present ? "yes" : "no");
		if (!gt.dgt_present)
			continue;
		(void) printf("\ttransceiver %d usable: %s\n", i,
		    gt.dgt_usable ? "yes" : "no");
	}

	return (DLADM_WALK_CONTINUE);
}

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

/*
 * We always read 256 bytes even though only the first 128 bytes are sometimes
 * significant on a given page and others are reserved.
 */
static int
dltran_read_page(datalink_id_t link, uint_t tranid, uint_t page, uint8_t *bufp,
    size_t buflen)
{
	dld_ioc_tranio_t dti;

	bzero(bufp, buflen);
	bzero(&dti, sizeof (dti));

	dti.dti_linkid = link;
	dti.dti_tran_id = tranid;
	dti.dti_page = page;
	dti.dti_nbytes = buflen;
	dti.dti_off = 0;
	dti.dti_buf = (uintptr_t)(void *)bufp;

	if (ioctl(dladm_dld_fd(dltran_hdl), DLDIOC_READTRAN, &dti) != 0) {
		(void) fprintf(stderr, "failed to read transceiver page "
		    "0x%2x: %s\n", page, strerror(errno));
		return (1);
	}

	dltran_dump_page(bufp, dti.dti_nbytes, page);

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

static int
dltran_read_link(const char *link)
{
	dladm_status_t status;
	datalink_id_t linkid;
	dld_ioc_gettran_t gt;
	uint8_t buf[256];
	int ret;

	if ((status = dladm_name2info(dltran_hdl, link, &linkid, NULL, NULL,
	    NULL)) != DLADM_STATUS_OK) {
		(void) fprintf(stderr, "failed to get link id for link "
		    "%s: %s\n", link,
		    dladm_status2str(status, dltran_dlerrmsg));
		return (1);
	}

	gt.dgt_linkid = linkid;
	gt.dgt_tran_id = dltran_tranid;

	if (ioctl(dladm_dld_fd(dltran_hdl), DLDIOC_GETTRAN, &gt) != 0) {
		(void) fprintf(stderr, "failed to get transceiver information "
		    "for %s: %s\n", link, strerror(errno));
		return (1);
	}

	if ((ret = dltran_read_page(linkid, dltran_tranid, 0xa0, buf,
	    sizeof (buf))) != 0) {
		return (ret);
	}

	if (!dltran_is_8472(buf)) {
		return (0);
	}

	return (dltran_read_page(linkid, dltran_tranid, 0xa2, buf,
	    sizeof (buf)));
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

	(void) fprintf(stderr, "Usage: %s [-i id] [-l link]... [-r]\n"
	    "\n"
	    "\t-i id    specify a transceiver id to operate on\n"
	    "\t-l link  specify a data link to operate on\n"
	    "\t-r       read transceiver page\n",
	    dltran_progname);
}

int
main(int argc, char *argv[])
{
	int c;
	char *eptr;
	long l;
	dladm_status_t status;
	boolean_t do_read = B_FALSE;

	dltran_progname = basename(argv[0]);

	while ((c = getopt(argc, argv, ":hi:l:r")) != -1) {
		switch (c) {
		case 'i':
			errno = 0;
			l = strtol(optarg, &eptr, 10);
			if (errno != 0 || *eptr != '\0' || l < 0 ||
			    l > INT_MAX) {
				(void) fprintf(stderr, "invalid value for -i: "
				    "%s\n", optarg);
				return (2);
			}
			dltran_tranid = (int)l;
			dltran_tranid_set = B_TRUE;
			break;
		case 'l':
			if (dltran_nlinks == dltran_clinks) {
				char **p;
				dltran_nlinks += 8;

				p = realloc(dltran_links,
				    sizeof (char **) * dltran_nlinks);
				if (p == NULL) {
					(void) fprintf(stderr, "failed to "
					    "allocate space for %d links: %s\n",
					    dltran_nlinks, strerror(errno));
					return (1);
				}
				dltran_links = p;
			}
			dltran_links[dltran_clinks++] = optarg;
			break;
		case 'r':
			do_read = B_TRUE;
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

	if (do_read && dltran_clinks != 1) {
		(void) fprintf(stderr, "-r requires exactly one link "
		    "specified with -l\n");
		return (2);
	}

	if ((status = dladm_open(&dltran_hdl)) != DLADM_STATUS_OK) {
		(void) fprintf(stderr, "failed to open /dev/dld: %s\n",
		    dladm_status2str(status, dltran_dlerrmsg));
		return (1);
	}

	if (do_read) {
		return (dltran_read_link(dltran_links[0]));
	}

	(void) dladm_walk_datalink_id(dltran_dump_transceivers, dltran_hdl,
	    NULL, DATALINK_CLASS_PHYS, DATALINK_ANY_MEDIATYPE,
	    DLADM_OPT_ACTIVE);

	return (0);
}
