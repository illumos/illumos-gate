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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>

#include <sys/scsi/scsi.h>
#include <libintl.h>

#include <sys/unistat/spcs_s.h>
#include <sys/nsctl/ste_scsi.h>
#include <sys/nsctl/dsw.h>

#define	SCSI_CDB(c, s, p, l)		\
{					\
	*c = (char)s;			\
	*(c + 2) = (p >> 24) & 0xff;	\
	*(c + 3) = (p >> 16) & 0xff;	\
	*(c + 4) = (p >> 8) & 0xff;	\
	*(c + 5) = p & 0xff;		\
	*(c + 7) = (l >> 8) & 0xff;	\
	*(c + 8) = l & 0xff;		\
}

#define	CDBSIZE		10
#define	RQBSIZE		26

#define	SCSITIME	5
#define	POLLTIME	3
#define	MAXIWWNS	3
#define	IIVOLCNT	4

#define	IN_BUFSIZE	2

/* Globals */
static int  aflag = 0;
static int  cflag = 0;
static int  iflag = 0;
static int  uflag = 0;
static int  wflag = 0;
static int  qflag = 1;

static int  scsi_timeout	= SCSITIME;
static int  wait_poll_time	= POLLTIME;
static int  wwn_count		= MAXIWWNS;
static char *volume		= NULL;
static char direction		= '\0';

/* Prototypes */
void help();
void fail(int, char *);
void parse(int, char **);
int  pit_abort();
int  pit_copy_update(int);
int  pit_list();
int  pit_wait();
int  pit_group_operation(int);
void version();

int
main(int argc, char **argv)
{
	int rc = 0;

	parse(argc, argv);

	if (!aflag && !cflag && !iflag && !uflag && !wflag)
		fail(EINVAL, gettext("operation not specified.\n"));

	/* abort */
	if (aflag && (rc = pit_abort()))
		fail(rc, gettext("abort failed.\n"));

	/* copy */
	if (cflag && (rc = pit_copy_update(II_PIT_COPY)))
		fail(rc, gettext("copy failed.\n"));

	/* update */
	if (uflag && (rc = pit_copy_update(II_PIT_UPDATE)))
		fail(rc, gettext("update failed.\n"));

	/* list */
	if (iflag && (rc = pit_list()))
		fail(rc, gettext("list failed.\n"));

	/* wait */
	if (wflag && (rc = pit_wait()))
		fail(rc, gettext("wait failed.\n"));

	return (0);
}

void
help()
{
	printf(gettext("Usage:\n"));
	printf(gettext("\tdsimage [-t <timeout>] [-n] -a <volume>\n"));
	printf(gettext("\tdsimage [-t <timeout>] [-n] -c [m|s] <volume>\n"));
	printf(gettext("\tdsimage [-t <timeout>] [-n] -u [m|s] <volume>\n"));
	printf(gettext("\tdsimage [-t <timeout>] -i <volume>\n"));
	printf(gettext("\tdsimage [-t <timeout>] [-p <polltime>] -w "
	    "<volume>\n"));
	printf(gettext("\tdsimage -h\n"));
	printf(gettext("\tdsimage -v\n"));
	printf(gettext("Description of options:\n"));
	printf(gettext("\t-a\tAbort any outstanding copy/update "
	    "operations.\n"));
	printf(gettext("\t-c\tInitiate a copy operation, overwriting an "
	    "entire volume.\n"));
	printf(gettext("\t-u\tInitiate a update operation, moving changed "
	    "data.\n"));
	printf(gettext("\t-i\tRetrieve information about the point-in-time "
	    "set.\n"));
	printf(gettext("\t-w\tWait for a copy/update operation to "
	    "complete.\n"));
	printf(gettext("\t-t\tSet the SCSI timeout. (default=%d)\n"), SCSITIME);
	printf(gettext("\t-p\tSet the polling time used for wait "
	    "operation. (default=%d)\n"), POLLTIME);
	printf(gettext("\t-n\tSupress confirmation of operation.\n"));
	printf(gettext("\t-h\tOutput help text.\n"));
	printf(gettext("\t-v\tOutput version of dsimage.\n"));
}

void
fail(int rc, char *msg)
{
	fprintf(stderr, "\n%s\n", msg);
	help();
	exit(rc);
}

void
parse(int argc, char **argv)
{
	int c;
	extern char *optarg;
	extern int optind;

	while ((c = getopt(argc, argv, "ac:hinp:t:u:wv")) != EOF)
		switch (c) {
			case 'a' :		/* ABORT */
				aflag++;
				break;
			case 'c' :		/* COPY */
				cflag++;
				direction = optarg[0];
				break;
			case 'h':		/* HELP */
				help();
				exit(0);
				break;
			case 'i':		/* LIST */
				iflag++;
				break;
			case 'n' :		/* NO CONFIRM */
				qflag = 0;
				break;
			case 'p' :		/* POLLING TIME */
				wait_poll_time = atoi(optarg);
				break;
			case 't' :		/* TIMEOUT */
				scsi_timeout = atoi(optarg);
				break;
			case 'u':		/* UPDATE */
				uflag++;
				direction = optarg[0];
				break;
			case 'w':		/* WAIT */
				wflag++;
				break;
			case 'v':		/* VERSION */
				version();
				break;
		}

	if (!(argc - optind))
		fail(EINVAL, gettext("No volume specified\n"));

	volume = (char *)calloc(DSW_NAMELEN, sizeof (char));
	strcpy(volume, argv[optind]);


	if ((cflag || uflag) && !strchr("ms", direction))
		fail(EINVAL, gettext("Invalid direciton specified.\n"));

	if (scsi_timeout < 1)
		fail(EINVAL, gettext("Invalid SCSI timeout specified.\n"));

	if (wait_poll_time < 1)
		fail(EINVAL, gettext("Invalid poll time specified.\n"));
}

int
scsiwrite(int cmd, char *volume, int len, char *buf)
{
	int fd;
	int rc;
	struct uscsi_cmd scsi_cmd;
	char *rqb;
	char *cdb;

	cdb = (char *)calloc(CDBSIZE, sizeof (char));
	rqb = (char *)calloc(RQBSIZE, sizeof (char));

	SCSI_CDB(cdb, CMD_STOREDGE_WRITE, cmd, len);

	scsi_cmd.uscsi_flags = (USCSI_WRITE | USCSI_RQENABLE);
	scsi_cmd.uscsi_timeout = scsi_timeout;
	scsi_cmd.uscsi_cdb	= cdb;
	scsi_cmd.uscsi_cdblen	= CDBSIZE;
	scsi_cmd.uscsi_rqbuf	= rqb;
	scsi_cmd.uscsi_rqlen	= RQBSIZE;
	scsi_cmd.uscsi_bufaddr	= buf;
	scsi_cmd.uscsi_buflen	= len;

	if ((fd = open(volume, O_RDWR)) == -1)
		fail(EINVAL, "Unable to open specified volume.\n");

	if ((rc = ioctl(fd, USCSICMD, &scsi_cmd)))
		fail(EINVAL, "Image operation timed out.");

	close(fd);

	return (rc);
}

int
scsiread(int cmd, char *volume, int len, char *buf)
{
	int fd;
	int rc;
	struct uscsi_cmd scsi_cmd;
	char *rqb;
	char *cdb;

	cdb = (char *)calloc(CDBSIZE, sizeof (char));
	rqb = (char *)calloc(RQBSIZE, sizeof (char));

	SCSI_CDB(cdb, CMD_STOREDGE_READ, cmd, len);

	scsi_cmd.uscsi_flags = (USCSI_READ | USCSI_RQENABLE);
	scsi_cmd.uscsi_status	= 0;
	scsi_cmd.uscsi_timeout	= scsi_timeout;
	scsi_cmd.uscsi_cdb	= cdb;
	scsi_cmd.uscsi_cdblen	= CDBSIZE;
	scsi_cmd.uscsi_rqbuf	= rqb;
	scsi_cmd.uscsi_rqlen	= RQBSIZE;
	scsi_cmd.uscsi_bufaddr	= buf;
	scsi_cmd.uscsi_buflen	= len;
	scsi_cmd.uscsi_resid	= 0;
	scsi_cmd.uscsi_rqstatus = 0;
	scsi_cmd.uscsi_rqresid	= 0;

	if ((fd = open(volume, O_RDWR)) == -1)
		fail(EINVAL, "Unable to open specified volume.\n");

	if ((rc = ioctl(fd, USCSICMD, &scsi_cmd)))
		fail(EINVAL, "Image operation timed out.");

	close(fd);

	return (rc);
}

/*
 * 'iiadm -i' output
 */
void
print_set(char *buf)
{
	pit_props_t props;
	char *wwnp = (char *)buf + sizeof (pit_props_t);

	bcopy(buf, &props, sizeof (pit_props_t));

	/* vdisk IDs */
	if (props.mstid == -1)
		printf(gettext("<not mapped>"));
	else {
		printf("%s,%d", wwnp, props.mstid);
		wwnp += WWN_STRLEN * wwn_count;
	}
	printf(gettext(" (master volume)\n"));

	if (props.shdid == -1)
		printf(gettext("<not mapped>"));
	else {
		printf("%s,%d", wwnp, props.shdid);
		wwnp += WWN_STRLEN * wwn_count;
	}
	printf(gettext(" (shadow volume)\n"));

	if (props.bmpid == -1)
		printf(gettext("<not mapped>"));
	else {
		printf("%s,%d", wwnp, props.bmpid);
		wwnp += WWN_STRLEN * wwn_count;
	}
	printf(gettext(" (bitmap volume)\n"));

	if (props.has_overflow) {
		if (props.ovrid == -1)
			printf(gettext("<not mapped>"));
		else {
			printf("%s,%d", wwnp, props.ovrid);
			wwnp += WWN_STRLEN * wwn_count;
		}
		printf(gettext(" (ovrflow volume)\n"));
	}

	if (strlen(props.group)) {
		printf(gettext("Group: "));
		printf("%s\n", props.group);
	}
	if (strlen(props.cluster)) {
		printf(gettext("Cluster tag: "));
		printf("%s\n", props.cluster);
	}

	if (props.flags & DSW_GOLDEN)
		(void) printf(gettext("Independent copy"));
	else
		(void) printf(gettext("Dependent copy"));

	if (props.flags & DSW_TREEMAP)
		(void) printf(gettext(", compacted shadow space"));

	if (props.flags & DSW_COPYINGP)
		(void) printf(gettext(", copy in progress"));
	else if (props.flags & DSW_COPYING)
		(void) printf(gettext(", copy not active"));

	if (props.flags & DSW_COPYINGM)
		(void) printf(gettext(", copying master to shadow"));

	if (props.flags & DSW_COPYINGS)
		(void) printf(gettext(", copying shadow to master"));

	if (props.flags & DSW_COPYINGX)
		(void) printf(gettext(", abort of copy requested"));

	if (props.flags & DSW_MSTOFFLINE)
		(void) printf(gettext(", master volume offline"));

	if (props.flags & DSW_SHDOFFLINE)
		(void) printf(gettext(", shadow volume offline"));

	if (props.flags & DSW_BMPOFFLINE)
		(void) printf(gettext(", bitmap volume offline"));

	if (props.flags & DSW_OVROFFLINE)
		(void) printf(gettext(", overflow volume offline"));

	if (props.flags & DSW_SHDEXPORT)
		(void) printf(gettext(", shadow volume exported"));

	if (props.flags & DSW_SHDIMPORT)
		(void) printf(gettext(", shadow volume imported"));

	if (props.flags & DSW_OVERFLOW)
		(void) printf(gettext(", out of space"));

	if (props.flags & DSW_VOVERFLOW)
		(void) printf(gettext(", spilled into overflow volume"));

	printf(gettext("\nVolume size: %d\n"), props.size);

	if (props.copybits > 0) {
		int pctcopy = (props.copybits * 100) / props.shdchks;
		printf(gettext("Copy bitmap is %d%% set.\n"), pctcopy);
		printf(gettext("\t(bitmap dirty)\n"));
	} else
		printf(gettext("Copy bitmap is clean.\n"));

	if (props.shdbits > 0) {
		int pctdiff = (props.shdbits * 100) / props.shdchks;
		printf(gettext("Shadow bitmap is %d%% set.\n"), pctdiff);
		printf(gettext("\t(bitmap dirty)\n"));
	}
	else
		printf(gettext("Differences bitmap is clean.\n"));
}

int
confirm(char *msg)
{
	char c[IN_BUFSIZE];

	if (!qflag)
		return (0);

	fprintf(stdout, msg);
	fgets(c, IN_BUFSIZE, stdin);

	if (c[0] == 'y' || c[0] == 'Y')
		return (0);

	fprintf(stderr, gettext("Operation cancelled.\n"));
	return (1);
}

int
pit_abort()
{
	int rc;
	int iirc;

	if (confirm(gettext("Abort copy/update operations? (y/n): ")))
		return (0);

	rc = scsiwrite(II_PIT_ABORT, volume, sizeof (int), (char *)&iirc);

	if (!rc && iirc == DSW_COPYINGP)
		fprintf(stderr, gettext("Not copying.\n"));

	return (rc);
}

int
pit_copy_update(int cmd)
{
	int rc;

	char msg[80];
	char *op;
	char *v1;
	char *v2;

	pit_update_t update;

	/* Opeartion text for configmr message */
	if (cmd == II_PIT_COPY)
		op = gettext("Copy");

	if (cmd == II_PIT_UPDATE)
		op = gettext("Update");

	/* Direction text for confirm messasge */
	if (direction == 'm') {
		v1 = gettext("shadow");
		v2 = gettext("master");
	}

	if (direction == 's') {
		v1 = gettext("master");
		v2 = gettext("shadow");
	}

	/* Assemble message */
	sprintf(msg, gettext("%s from %s to %s? (y/n): "), op, v1, v2);

	/* Confirm */
	if (confirm(msg))
		return (0);

	/* Set up buffers */
	update.direction = direction;

	/* Begin copy */
	rc = scsiwrite(cmd, volume, sizeof (pit_update_t), (char *)&update);

	if (rc)
		return (rc);


	if (update.iirc == DSW_COPYINGP) {
		fprintf(stderr, gettext("Already copying.\n"));
		return (rc);
	}

	return (0);
}

int
pit_list()
{
	int rc;
	int bufl;
	char *bufp;

	/* Allocate memory to hold set data */
	/* WWN_STRLEN	= # of characters in a WWN */
	/* IIVOLCNT	= # of volumes per II set (mst, shd, bit, ovr) */
	bufl = sizeof (pit_props_t) + (WWN_STRLEN * wwn_count * IIVOLCNT);
	bufp = (char *)calloc(1, bufl);

	/* Data for all of the II sets */
	if ((rc = scsiread(II_PIT_PROPS, volume, bufl, bufp)))
		goto end;

	print_set(bufp);
end:
	free(bufp);
	return (rc);
}

int
pit_wait()
{
	int rc;
	int iirc;

	for (;;) {
		rc = scsiread(II_PIT_WAIT, volume, sizeof (int),
		    (char *)&iirc);

		if (rc || (iirc != DSW_COPYINGP))
			break;

		sleep(POLLTIME);
	}

	return (rc);
}

void
version()
{
	printf("dsimage V%d.%d.%d.%d\n",
	    ISS_VERSION_MAJ,
	    ISS_VERSION_MIN,
	    ISS_VERSION_MIC,
	    ISS_VERSION_NUM);

	exit(0);
}
