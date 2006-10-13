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
 * Copyright (c) 1994 by Sun Microsystems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Program to test the operation of the Volume Test Driver
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stropts.h>
#include <poll.h>
#include <errno.h>
#include <values.h>

#include "voltestdrv.h"

#define	VTBASENAME	"/dev/vt/"
#define	VOLBASE		"/vol"
#define	RDSK		"rdsk"

static char	*prog_name;

extern int	errno;

static u_int	bytes_to_xfer = MAXINT;
static int	verbose = 0;

#define	DEF_NMINORS	1

struct vt_data {
	void	*vd_label;
	u_int	vd_tag;
	char	*vd_name;
};

static void	wait_for_status(int fd, int nchildren);

void
main(int argc, char **argv)
{
	extern char 	*optarg;

	static void	usage(void);
	static void	read_test_vt(struct vt_data *);
	static void	write_test_vt(struct vt_data *);

	int		c;
	int		nminors = DEF_NMINORS;
	int		readtest = 0;
	int		writetest = 0;
	int		nchildren = 0;
	int		err;
	int		fd;
	int		unit;
	char		namebuf[80];
	struct vt_data	**vtdata;
	char		*volbase = VOLBASE;



	prog_name = argv[0];

	/* process arguments */
	while ((c = getopt(argc, argv, "n:rwd:b:v")) != EOF) {
		switch (c) {
		case 'b':
			bytes_to_xfer = atoi(optarg) * 1024;
			break;
		case 'n':
			nminors = atoi(optarg);
			break;
		case 'r':
			readtest++;
			break;
		case 'w':
			writetest++;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
			exit(-1);
		}
	}
	(void) sprintf(namebuf, "%s%s", VTBASENAME, VTCTLNAME);
	if ((fd = open(namebuf, O_RDWR)) < 0) {
		perror(namebuf);
		exit(-1);
	}

	vtdata =
	    (struct vt_data **)malloc(sizeof (struct vt_data) * nminors+1);
	if (vtdata == NULL) {
		perror("malloc");
		exit(-1);
	}

	/* build up the mapping in the vt driver */
	for (unit = 1; unit < nminors+1; unit++) {
		struct	vt_name vtn;
		struct	vt_data *vtd;

		vtd = (struct vt_data *)malloc(sizeof (struct vt_data));
		if (vtd == NULL) {
			perror("malloc");
			exit(-1);
		}
		vtdata[unit] = vtd;
		vtn.vtn_unit = unit;
		/*
		 * This is a bit of an ugly hack here... I make sure
		 * that name is always a multiple of sizeof (int) so
		 * that the checking below is easier.
		 */
		(void) sprintf(namebuf, "unit #%6d", unit);
		vtn.vtn_name = strdup(namebuf);
		if (vtn.vtn_name == NULL) {
			perror("malloc");
			exit(-1);
		}
		vtd->vd_label = (void *)vtn.vtn_name;
		/*
		 * another ugly hack.  I happen to know that volume
		 * management is going to call a device with a label
		 * of unit# 1, /vol/rdsk/unit#1.  I cheat and use
		 * that right here.
		 */
		(void) sprintf(namebuf, "%s/%s/unit#%d", volbase, RDSK, unit);
		vtd->vd_name = strdup(namebuf);
		if (vtd->vd_name == NULL) {
			perror("malloc");
			exit(-1);
		}
		err = ioctl(fd, VTIOCNAME, (caddr_t)&vtn);
		if (err) {
			if (errno == EBUSY) {
				fprintf(stderr, "%s already inserted\n",
					vtd->vd_name);
			} else {
				perror(namebuf);
				fprintf(stderr, "exiting\n");
				exit(-1);
			}
		}
	}

	/*
	 * now that we have the mapping, we figure out the "tag".
	 * We'll use the dev_t of the device in /vol just
	 * so we can track down problems easier.
	 */
	for (unit = 1; unit < nminors+1; unit++) {
		struct vt_data	*vtd;
		struct vt_tag	vtt;
		struct stat	sb;

		vtd = vtdata[unit];
		while (stat(vtd->vd_name, &sb) == -1) {
			if (errno == ENOENT || errno == ESTALE) {
				sleep(2);
				fprintf(stderr, "error on %s\n", vtd->vd_name);
				continue;
			}
			perror(namebuf);
			exit(-1);
		}
		vtd->vd_tag = sb.st_rdev;
		vtt.vtt_unit = unit;
		vtt.vtt_tag = vtd->vd_tag;
		err = ioctl(fd, VTIOCTAG, (caddr_t)&vtt);
		if (err == -1) {
			perror(namebuf);
			exit(-1);
		}
	}
	/* run all the tests */
	for (unit = 1; unit < nminors+1; unit++) {
		if (readtest) {
			if ((err = fork()) == 0) {
				read_test_vt(vtdata[unit]);
			}
			if (err == -1) {
				fprintf(stderr, "nminors == %d\n", nminors);
				perror("fork");
				break;
			} else {
				nchildren++;
			}
		}
		if (writetest) {
			if ((err = fork()) == 0) {
				write_test_vt(vtdata[unit]);
			}
			if (err == -1) {
				fprintf(stderr, "nminors == %d\n", nminors);
				perror("fork");
				break;
			} else {
				nchildren++;
			}
		}
	}

	wait_for_status(fd, nchildren);
}

static void
usage()
{
	fprintf(stderr, "usage: %s [-n num_minors] [-w] [-r]\n",
		prog_name);
}


#define	TBUFSIZ		1024

static void
read_test_vt(struct vt_data *vtd)
{
	int	buf[TBUFSIZ];
	int	fd;
	int	i, n;
	int	len;
	u_int	bytecnt = 0;

	setbuf(stdout, NULL);

	while ((fd = open(vtd->vd_name, O_RDONLY)) < 0) {
		if (errno == ENOENT || errno == ESTALE) {
			sleep(2);
			continue;
		}
		perror(vtd->vd_name);
		exit(-1);
	}
	len = strlen(vtd->vd_label);
	for (;;) {
		n = read(fd, buf, TBUFSIZ * sizeof (int));
		if (n < 0) {
			perror(vtd->vd_name);
			exit(-1);
		}

		if (n / sizeof (int) != TBUFSIZ) {
			fprintf(stderr, "%s: short read (%d)\n",
				vtd->vd_name, n);
		}
		if (bytecnt < len) {
			if (strncmp(vtd->vd_label, (char *)buf, len)) {
				fprintf(stderr,
					"label not right, wanted %s, got %s\n",
					vtd->vd_label, buf);
				exit(-1);
			}
			i = len / sizeof (int);
		} else {
			i = 0;
		}

		for (; i < TBUFSIZ; i++) {
			if (buf[i] != vtd->vd_tag) {
				printf(
				    "read error on %s wanted 0x%x got 0x%x\n",
				    vtd->vd_name, i, buf[i]);
			}
		}
		bytecnt += n;
		if (bytecnt >= bytes_to_xfer) {
			if (verbose) {
				fprintf(stderr, "%s: %u bytes read\n",
					vtd->vd_name, bytecnt);
			}
			exit(0);
		}
	}
}

static void
write_test_vt(struct vt_data *vtd)
{
	int	buf[TBUFSIZ];
	int	fd;
	int	i, n;
	u_int	bytecnt = 0;

	setbuf(stdout, NULL);
	while ((fd = open(vtd->vd_name, O_WRONLY)) < 0) {
		if ((errno == ENOENT) || (errno == ESTALE)) {
			sleep(2);
			continue;
		}
		perror(vtd->vd_name);
		exit(-1);
	}

	for (i = 0; i < TBUFSIZ; i++)
		buf[i] = vtd->vd_tag;

	for (;;) {
		n = write(fd, buf, TBUFSIZ * sizeof (int));
		if (n < 0) {
			perror(vtd->vd_name);
			exit(-1);
		}

		if (n / sizeof (int) != TBUFSIZ) {
			fprintf(stderr, "%s: short write (%d)\n",
				vtd->vd_name, n);
		}
		bytecnt += n;
		if (bytecnt >= bytes_to_xfer) {
			if (verbose) {
				fprintf(stderr, "%s: %u bytes written\n",
					vtd->vd_name, bytecnt);
			}
			exit(0);
		}
	}
}


#define	POLLTIMEOUT	100
#define	MAXPOLLFD	5

static void
wait_for_status(int fd, int nchildren)
{
	static void	getstatus(int);
	struct		pollfd poll_fds[MAXPOLLFD];
	int		npollfd = 0;
	int		i, n;
	int		pid;
	int		status;


	poll_fds[npollfd].fd = fd;
	poll_fds[npollfd].events = POLLRDNORM;
	npollfd++;

#ifdef notdef
	printf("nchildren = %d\n", nchildren);
#endif
	while (1) {
		n = poll(poll_fds, npollfd, POLLTIMEOUT);
		for (i = 0; n && i < npollfd; i++) {
			if (poll_fds[i].revents) {
				getstatus(fd);
			}
		}
		pid = waitpid((pid_t)-1, &status, WNOHANG);
		if (pid > 0 && WIFEXITED(status)) {
			--nchildren;
#ifdef notdef
			printf("process %d exited %d left\n", pid, nchildren);
#endif
			if (nchildren == 0) {
				break;
			}
		}
	}
}

static void
getstatus(int fd)
{
	static void		process_status(struct vt_status *);
	extern int		errno;
	struct vt_status	vse;


	while (1) {
		if (ioctl(fd, VTIOCSTATUS, &vse)) {
			if (errno != EWOULDBLOCK) {
				perror("ioctl");
			}
			return;
		}
		process_status(&vse);
	}
}

static void
process_status(struct vt_status *vse)
{
	switch (vse->vte_type) {
	case VSE_WRTERR:
		printf("write error on unit %d, expected 0x%x, got 0x%x\n",
			vse->vse_wrterr.vwe_unit, vse->vse_wrterr.vwe_want,
			vse->vse_wrterr.vwe_got);
		break;
	}
}
