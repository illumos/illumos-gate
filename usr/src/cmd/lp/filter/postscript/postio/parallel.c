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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

extern char *postbegin;

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/ioctl.h>

#include <sys/bpp_io.h>
#include <sys/ecppsys.h>
#include <sys/prnio.h>

#define PRINTER_IO_ERROR	129

/*
 * the parameter structure for the parallel port
 */
struct ppc_params_t {
	int		flags;		/* same as above */
	int		state;		/* status of the printer interface */
	int		strobe_w;	/* strobe width, in uS */
	int		data_setup;	/* data setup time, in uS */
	int		ack_timeout;	/* ACK timeout, in secs */
	int		error_timeout;	/* PAPER OUT, etc... timeout, in secs */
	int		busy_timeout;	/* BUSY timeout, in seconds */
};



extern char *block;
extern int head, tail;
extern int readblock(int);
extern FILE *fp_log;
static void printer_info(char *fmt, ...);

/*	These are the routines avaliable to others for use 	*/
int is_a_parallel_bpp(int);
int bpp_state(int);
int parallel_comm(int, int());
int get_ecpp_status(int);
int is_a_prnio(int);
int prnio_state(int);

#define PRINTER_ERROR_PAPER_OUT		1
#define PRINTER_ERROR_OFFLINE		2
#define PRINTER_ERROR_BUSY		3
#define PRINTER_ERROR_ERROR		4
#define PRINTER_ERROR_CABLE_POWER	5
#define PRINTER_ERROR_UNKNOWN		6
#define PRINTER_ERROR_TIMEOUT		7

/****************************************************************************/

/**
 *	for BPP PARALLEL interfaces
 **/

int is_a_parallel_bpp(int fd)
{
	if (ioctl(fd, BPPIOC_TESTIO) == 0 || errno == EIO)
		return(1);
	return(0);
}


#if defined(DEBUG) && defined(NOTDEF)
char *BppState(int state)
{
	static char buf[BUFSIZ];

	memset(buf, 0, sizeof(buf));
	sprintf(buf, "State (0x%.4x) - (%s%s%s%s)\n", state,
		((state & BPP_SLCT_ERR) ?  "offline " : ""),
		((state & BPP_BUSY_ERR) ?  "busy " : ""),
		((state & BPP_PE_ERR) ?  "paper " : ""),
		((state & BPP_ERR_ERR) ?  "error " : ""));

	return(buf);
}
#endif

int bpp_state(int fd)
{
	if (ioctl(fd, BPPIOC_TESTIO)) {
		struct bpp_error_status  bpp_stat;
		int state;

		if (ioctl(fd, BPPIOC_GETERR, &bpp_stat) < 0)
			exit(PRINTER_IO_ERROR);
		state = bpp_stat.pin_status;

#if defined(DEBUG) && defined(NOTDEF)
		logit("%s", BppState(state));
#endif

		if (state == (BPP_PE_ERR | BPP_ERR_ERR | BPP_SLCT_ERR)) {
			/* paper is out */
			return(PRINTER_ERROR_PAPER_OUT);
		} else if (state & BPP_BUSY_ERR) {
			/* printer is busy */
			return(PRINTER_ERROR_BUSY);
		} else if (state & BPP_SLCT_ERR) {
			/* printer is offline */
			return(PRINTER_ERROR_OFFLINE);
		} else if (state & BPP_ERR_ERR) {
			/* printer is errored */
			return(PRINTER_ERROR_ERROR);
		} else if (state == BPP_PE_ERR) {
			/* printer is off/unplugged */
			return(PRINTER_ERROR_CABLE_POWER);
		} else if (state) {
			return(PRINTER_ERROR_UNKNOWN);
		} else
			return(0);
	}
	return(0);
}

int
get_ecpp_status(int fd)
{
	int state;
	struct ecpp_transfer_parms transfer_parms;


	if (ioctl(fd, ECPPIOC_GETPARMS, &transfer_parms) == -1) {
		return(-1);
	}

	state = transfer_parms.mode;
	/*
	 * We don't know what all printers will return in
	 * nibble mode, therefore if we support nibble mode we will
	 * force the printer to be in CENTRONICS mode.
	 */

	if (state != ECPP_CENTRONICS) {
		transfer_parms.mode = ECPP_CENTRONICS;
		if (ioctl(fd, ECPPIOC_SETPARMS, &transfer_parms) == -1) {
			return(-1);
		} else {
			state = ECPP_CENTRONICS;
		}
	}

	return(state);
}

/**
 * For prnio(4I) - generic printer interface
 **/
int is_a_prnio(int fd)
{
	uint_t	cap;

	/* check if device supports prnio */
	if (ioctl(fd, PRNIOC_GET_IFCAP, &cap) == -1) {
		return (0);
	}
	/* we will use 1284 status if available */
	if ((cap & PRN_1284_STATUS) == 0) {
		/* some devices may only support 1284 status in unidir. mode */
		if (cap & PRN_BIDI) {
			cap &= ~PRN_BIDI;
			(void) ioctl(fd, PRNIOC_SET_IFCAP, &cap);
		}
	}
	return (1);
}

int prnio_state(int fd)
{
	uint_t	status;
	uchar_t	pins;

	if ((ioctl(fd, PRNIOC_GET_STATUS, &status) == 0) &&
	    (status & PRN_READY)) {
		return(0);
	}

	if (ioctl(fd, PRNIOC_GET_1284_STATUS, &pins) != 0) {
		return(PRINTER_ERROR_UNKNOWN);
	}

	if ((pins & ~PRN_1284_BUSY) == PRN_1284_PE) {
		/* paper is out */
		return(PRINTER_ERROR_PAPER_OUT);
	} else if (pins == (PRN_1284_PE | PRN_1284_SELECT |
				PRN_1284_NOFAULT | PRN_1284_BUSY)) {
		/* printer is off/unplugged */
		return(PRINTER_ERROR_CABLE_POWER);
	} else if ((pins & PRN_1284_SELECT) == 0) {
		/* printer is offline */
		return(PRINTER_ERROR_OFFLINE);
	} else if ((pins & PRN_1284_NOFAULT) == 0) {
		/* printer is errored */
		return(PRINTER_ERROR_ERROR);
	} else if (pins & PRN_1284_PE) {
		/* paper is out */
		return(PRINTER_ERROR_PAPER_OUT);
	} else if (pins ^ (PRN_1284_SELECT | PRN_1284_NOFAULT)) {
		return(PRINTER_ERROR_UNKNOWN);
	}
	return(0);
}

/**
 *	Common routines
 **/

/*ARGSUSED0*/
static void
ByeByeParallel(int sig)
{
	/* try to shove out the EOT */
	(void) write(1, "\004", 1);
	exit(0);
}


/*ARGSUSED0*/
static void
printer_info(char *fmt, ...)
{
	char mesg[BUFSIZ];
	va_list ap;

	va_start(ap, fmt);
	vsprintf(mesg, fmt, ap);
	va_end(ap);

	fprintf(stderr,
		"%%%%[ PrinterError: %s; source: parallel ]%%%%\n",
		mesg);
	fflush(stderr);
	fsync(2);

	if (fp_log != stderr) {
		fprintf(fp_log,
		   "%%%%[ PrinterError: %s; source: parallel ]%%%%\n",
		   mesg);
		fflush(fp_log);
	}
}

static void
printer_error(int error)
{
	switch (error) {
		case -1:
			printer_info("ioctl(): %s", strerror(errno));
			break;
		case PRINTER_ERROR_PAPER_OUT:
			printer_info("out of paper");
			break;
		case PRINTER_ERROR_OFFLINE:
			printer_info("offline");
			break;
		case PRINTER_ERROR_BUSY:
			printer_info("busy");
			break;
		case PRINTER_ERROR_ERROR:
			printer_info("printer error");
			break;
		case PRINTER_ERROR_CABLE_POWER:
			printer_info("printer powered off or disconnected");
			break;
		case PRINTER_ERROR_UNKNOWN:
			printer_info("unknown error");
			break;
		case PRINTER_ERROR_TIMEOUT:
			printer_info("communications timeout");
			break;
		default:
			printer_info("get_status() failed");
	}
}


static void
wait_state(int fd, int get_state())
{
	int state;
	int was_faulted = 0;

	while (state = get_state(fd)) {
		was_faulted=1;
		printer_error(state);
		sleep(15);
	}

	if (was_faulted) {
		fprintf(stderr, "%%%%[ status: idle ]%%%%\n");
		fflush(stderr);
		fsync(2);
		if (fp_log != stderr) {
			fprintf(fp_log, "%%%%[ status: idle ]%%%%\n");
			fflush(fp_log);
		}
	}
}


int
parallel_comm(int fd, int get_state())
{
	int  actual;		/* number of bytes successfully written */
	int count = 0;

	(void) signal(SIGTERM, ByeByeParallel);
	(void) signal(SIGQUIT, ByeByeParallel);
	(void) signal(SIGHUP, ByeByeParallel);
	(void) signal(SIGINT, ByeByeParallel);
	(void) signal(SIGALRM, SIG_IGN);

	/* is the device ready? */

	/* bracket job with EOT */
	wait_state(fd, get_state);
	(void) write(fd, "\004", 1);

/* 	write(fd, postbegin, strlen(postbegin)); */

	while (readblock(fileno(stdin)) > 0) {
		wait_state(fd, get_state);
		alarm(120);
		if ((actual = write(fd, block + head, tail - head)) == -1) {
			alarm(0);
		  	if (errno == EINTR) {
				printer_error(PRINTER_ERROR_TIMEOUT);
				sleep(30);
				continue;
			} else {
				printer_info("I/O Error during write(): %s",
					strerror(errno));
				exit(2);
			}
		}
		alarm(0);
		if (actual >= 0)
			head += actual;

#if defined(DEBUG) && defined(NOTDEF)
		logit("Writing (%d) at 0x%x actual: %d, %s\n", count++, head,
			actual, (actual < 1 ? strerror(errno) : ""));
#endif
	}

	/* write the final EOT */
	wait_state(fd, get_state);
	(void) write(fd, "\004", 1);

	return (0);
}
