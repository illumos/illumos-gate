/*
 * Copyright (c) 1996, 1999 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This software was developed by the Computer Systems Engineering group
 * at Lawrence Berkeley Laboratory under DARPA contract BG 91-66.
 *
 * Copyright (c) 1992 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Lawrence Berkeley Laboratory.
 * 4. The name of the University may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#if defined(REFCLOCK) && defined(MX4200) && defined(PPS)

#include <stdio.h>
#include <ctype.h>
#include <sys/time.h>
#include <errno.h>

#include "ntpd.h"
#include "ntp_io.h"
#include "ntp_refclock.h"
#include "ntp_unixtime.h"
#include "ntp_stdlib.h"

#include "mx4200.h"

#if __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif /* __STDC__ */

#if defined(PPS) && !defined(SYS_SOLARIS)
#include <sys/ppsclock.h>
#endif /* PPS && !SYS_SOLARIS */

/*
 * This driver supports the Magnavox Model MX 4200 GPS Receiver
 * adapted to precision timing applications.  It requires the
 * ppsclock line discipline or streams module described in the
 * Line Disciplines and Streams Drivers page. It also requires a
 * gadget box and 1-PPS level converter, such as described in the
 * Pulse-per-second (PPS) Signal Interfacing page.
 *
 * It's likely that other compatible Magnavox receivers such as the
 * MX 4200D, MX 9212, MX 9012R, MX 9112 will be supported by this code.
 */

/*
 * Check this every time you edit the code!
 */
#define YEAR_RIGHT_NOW 1999

/*
 * GPS Definitions
 */
#define	DEVICE		"/dev/gps%d"	/* device name and unit */
#define	SPEED232	B4800		/* baud */

/*
 * The number of raw samples which we acquire to derive a single estimate.
 * NSAMPLES ideally should not exceed the default poll interval 64.
 * NKEEP must be a power of 2 to simplify the averaging process.
 */
#define NSAMPLES	64
#define NKEEP		8
#define REFCLOCKMAXDISPERSE (FP_SECOND/4) /* max sample dispersion */

/*
 * Radio interface parameters
 */
#define	PRECISION	(-18)	/* precision assumed (about 4 us) */
#define	REFID	"GPS\0"		/* reference id */
#define	DESCRIPTION	"Magnavox MX4200 GPS Receiver" /* who we are */
#define	DEFFUDGETIME	0	/* default fudge time (ms) */

#define	SLEEPTIME	32	/* seconds to wait for reconfig to complete */

/*
 * Position Averaging.
 * Reference: Dr. Thomas A. Clark's Totally Accurate Clock (TAC) files at
 * ftp://aleph.gsfc.nasa.gov/GPS/totally.accurate.clock/
 */
#define INTERVAL	1	/* Interval between position measurements (s) */
#define AVGING_TIME	24	/* Number of hours to average */
#define USUAL_EDOP	0.75	/* used for normalizing EDOP */
#define USUAL_NDOP	0.75	/* used for normalizing NDOP */
#define USUAL_VDOP	1.70	/* used for normalizing VDOP */

/*
 * Imported from the ntp_timer module
 */
extern u_long current_time;	/* current time (s) */

/*
 * Imported from ntpd module
 */
extern int debug;		/* global debug flag */

#ifdef PPS
/*
 * Imported from loop_filter module
 */
extern int fdpps;		/* ppsclock file descriptor */
#endif /* PPS */

/*
 * MX4200 unit control structure.
 */
struct mx4200unit {
	u_int  pollcnt;			/* poll message counter */
	u_int  polled;			/* Hand in a time sample? */
#ifdef PPS
	u_int  lastserial;		/* last pps serial number */
	struct ppsclockev ppsev;	/* PPS control structure */
#endif /* PPS */
	double avg_lat;			/* average latitude */
	double avg_lon;			/* average longitude */
	double avg_alt;			/* average height */
	double filt_lat;		/* latitude filter length */
	double filt_lon;		/* longitude filter length */
	double filt_alt;		/* height filter length */
	double edop;			/* EDOP (east DOP) */
	double ndop;			/* NDOP (north DOP) */
	double vdop;			/* VDOP (vertical DOP) */
	int    last_leap;		/* leap second warning */
	u_int  moving;			/* mobile platform? */
	u_long sloppyclockflag;		/* fudge flags */
	u_int  known;			/* position known yet? */
	u_long clamp_time;		/* when to stop postion averaging */
	u_long log_time;		/* when to print receiver status */
	int    coderecv;		/* total received samples */
	int    nkeep;			/* number of samples to preserve */
	int    rshift;			/* number of rshifts for division */
	l_fp   filter[NSAMPLES];	/* offset filter */
	l_fp   lastref;			/* last reference timestamp */
};

static char pmvxg[] = "PMVXG";

/* XXX should be somewhere else */
#ifdef __GNUC__
#if __GNUC__ < 2  || (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
#ifndef __attribute__
#define __attribute__(args)
#endif
#endif
#else
#ifndef __attribute__
#define __attribute__(args)
#endif
#endif
/* XXX end */

/*
 * Function prototypes
 */
static	int	mx4200_start	P((int, struct peer *));
static	void	mx4200_shutdown	P((int, struct peer *));
static	void	mx4200_receive	P((struct recvbuf *));
static	void	mx4200_poll	P((int, struct peer *));

static	char *	mx4200_parse_t	P((struct peer *));
static	char *	mx4200_parse_p	P((struct peer *));
static	char *	mx4200_parse_d	P((struct peer *));
static	char *	mx4200_parse_s	P((struct peer *));
static	char *	mx4200_offset	P((struct peer *));
static	char *	mx4200_process	P((struct peer *));
#ifdef QSORT_USES_VOID_P
	int	mx4200_cmpl_fp	P((const void *, const void *));
#else
	int	mx4200_cmpl_fp	P((const l_fp *, const l_fp *));
#endif /* not QSORT_USES_VOID_P */
static	void	mx4200_config	P((struct peer *));
static	void	mx4200_ref	P((struct peer *));
static	void	mx4200_send	P((struct peer *, char *, ...))
    __attribute__ ((format (printf, 2, 3)));
static	u_char	mx4200_cksum	P((char *, u_int));
static	int	mx4200_jday	P((int, int, int));
static	void	mx4200_debug	P((struct peer *, char *, ...))
    __attribute__ ((format (printf, 2, 3)));
static	int	mx4200_pps	P((struct peer *));

/*
 * Transfer vector
 */
struct	refclock refclock_mx4200 = {
	mx4200_start,		/* start up driver */
	mx4200_shutdown,	/* shut down driver */
	mx4200_poll,		/* transmit poll message */
	noentry,		/* not used (old mx4200_control) */
	noentry,		/* initialize driver (not used) */
	noentry,		/* not used (old mx4200_buginfo) */
	NOFLAGS			/* not used */
};



/*
 * mx4200_start - open the devices and initialize data for processing
 */
static int
mx4200_start(unit, peer)
	int unit;
	struct peer *peer;
{
	register struct mx4200unit *up;
	struct refclockproc *pp;
	int fd;
	char gpsdev[20];

	/*
	 * Open serial port
	 */
	(void)sprintf(gpsdev, DEVICE, unit);
	if (!(fd = refclock_open(gpsdev, SPEED232,
#ifdef PPS
				 LDISC_PPS
#else  /* not PPS */
				 0
#endif /* not PPS */
				 )))
		return (0);

	/*
	 * Allocate unit structure
	 */
	if (!(up = (struct mx4200unit *) emalloc(sizeof(struct mx4200unit)))) {
		(void) close(fd);
		return (0);
	}
	memset((char *)up, 0, sizeof(struct mx4200unit));
	pp = peer->procptr;
	pp->io.clock_recv = mx4200_receive;
	pp->io.srcclock = (caddr_t)peer;
	pp->io.datalen = 0;
	pp->io.fd = fd;
	if (!io_addclock(&pp->io)) {
		(void) close(fd);
		free(up);
		return (0);
	}
	pp->unitptr = (caddr_t)up;

	/*
	 * Initialize miscellaneous variables
	 */
	peer->precision = PRECISION;
	pp->clockdesc = DESCRIPTION;
	memcpy((char *)&pp->refid, REFID, 4);


	/* Ensure the receiver is properly configured */
	mx4200_config(peer);
	return (1);
}


/*
 * mx4200_shutdown - shut down the clock
 */
static void
mx4200_shutdown(unit, peer)
	int unit;
	struct peer *peer;
{
	register struct mx4200unit *up;
	struct refclockproc *pp;

	pp = peer->procptr;
	up = (struct mx4200unit *)pp->unitptr;
	io_closeclock(&pp->io);
	free(up);
}


/*
 * mx4200_config - Configure the receiver
 */
static void
mx4200_config(peer)
	struct peer *peer;
{
	char tr_mode;
	int add_mode;
	int i;
	register struct mx4200unit *up;
	struct refclockproc *pp;

	pp = peer->procptr;
	up = (struct mx4200unit *)pp->unitptr;

	/*
	 * Initialize the unit variables
	 *
	 * STRANGE BEHAVIOUR WARNING: The fudge flags are not available
	 * at the time mx4200_start is called.  These are set later,
	 * and so the code must be prepared to handle changing flags.
	 */
	up->sloppyclockflag = pp->sloppyclockflag;
	if (pp->sloppyclockflag & CLK_FLAG2) {
		up->moving   = 1;	/* Receiver on mobile platform */
		msyslog(LOG_DEBUG, "mx4200_config: mobile platform");
	} else {
		up->moving   = 0;	/* Static Installation */
	}
	up->pollcnt     = 2;
	up->polled      = 0;
	up->known       = 0;
	up->avg_lat     = 0.0;
	up->avg_lon     = 0.0;
	up->avg_alt     = 0.0;
	up->filt_lat    = 0.0;
	up->filt_lon    = 0.0;
	up->filt_alt    = 0.0;
	up->edop        = USUAL_EDOP;
	up->ndop        = USUAL_NDOP;
	up->vdop        = USUAL_VDOP;
	up->last_leap   = 0;	/* LEAP_NOWARNING */
	up->clamp_time  = current_time + (AVGING_TIME * 60 * 60);
	up->log_time    = current_time + SLEEPTIME;
	up->coderecv    = 0;
	up->nkeep       = NKEEP;
	if (up->nkeep > NSAMPLES) up->nkeep = NSAMPLES;
	if (up->nkeep >=   1) up->rshift = 0;
	if (up->nkeep >=   2) up->rshift = 1;
	if (up->nkeep >=   4) up->rshift = 2;
	if (up->nkeep >=   8) up->rshift = 3;
	if (up->nkeep >=  16) up->rshift = 4;
	if (up->nkeep >=  32) up->rshift = 5;
	if (up->nkeep >=  64) up->rshift = 6;
	up->nkeep =1;
	i = up->rshift;
	while (i > 0) {
		up->nkeep *= 2;
		i--;
	}

	/*
	 * "007" Control Port Configuration
	 * Zero the output list (do it twice to flush possible junk)
	 */
	mx4200_send(peer, "%s,%03d,,%d,,,,,,", pmvxg,
	    PMVXG_S_PORTCONF,
			/* control port output block Label */
	    1);		/* clear current output control list (1=yes) */
			/* add/delete sentences from list */
			/* must be null */
			/* sentence output rate (sec) */
			/* precision for position output */
			/* nmea version for cga & gll output */
			/* pass-through control */
	mx4200_send(peer, "%s,%03d,,%d,,,,,,", pmvxg,
	    PMVXG_S_PORTCONF, 1);

	/*
	 * Request software configuration so we can syslog the firmware version
	 */
	mx4200_send(peer, "%s,%03d", "CDGPQ", PMVXG_D_SOFTCONF);

	/*
	 * "001" Initialization/Mode Control, Part A
	 * Where ARE we?
	 */
	mx4200_send(peer, "%s,%03d,,,,,,,,,,", pmvxg,
	    PMVXG_S_INITMODEA);
			/* day of month */
			/* month of year */
			/* year */
			/* gmt */
			/* latitude   DDMM.MMMM */
			/* north/south */
			/* longitude DDDMM.MMMM */
			/* east/west */
			/* height */
			/* Altitude Reference 1=MSL */

	/*
	 * "001" Initialization/Mode Control, Part B
	 * Start off in 2d/3d coast mode, holding altitude to last known
	 * value if only 3 satellites available.
	 */
	mx4200_send(peer, "%s,%03d,%d,,%.1f,%.1f,%d,%d,%d,%c,%d",
	    pmvxg, PMVXG_S_INITMODEB,
	    3,		/* 2d/3d coast */
			/* reserved */
	    0.1,	/* hor accel fact as per Steve (m/s**2) */
	    0.1,	/* ver accel fact as per Steve (m/s**2) */
	    10,		/* vdop */
	    10,		/* hdop limit as per Steve */
	    5,		/* elevation limit as per Steve (deg) */
	    'U',	/* time output mode (UTC) */
	    0);		/* local time offset from gmt (HHHMM) */

	/*
	 * "023" Time Recovery Configuration
	 * Get UTC time from a stationary receiver.
	 * (Set field 1 'D' == dynamic if we are on a moving platform).
	 * (Set field 1 'S' == static  if we are not moving).
	 * (Set field 1 'K' == known position if we can initialize lat/lon/alt).
	 */

	if (pp->sloppyclockflag & CLK_FLAG2)
		up->moving   = 1;	/* Receiver on mobile platform */
	else
		up->moving   = 0;	/* Static Installation */

	up->pollcnt  = 2;
	if (up->moving) {
		/* dynamic: solve for pos, alt, time, while moving */
		tr_mode = 'D';
	} else {
		/* static: solve for pos, alt, time, while stationary */
		tr_mode = 'S';
	}
	mx4200_send(peer, "%s,%03d,%c,%c,%c,%d,%d,%d,", pmvxg,
	    PMVXG_S_TRECOVCONF,
	    tr_mode,	/* time recovery mode (see above ) */
	    'U',	/* synchronize to UTC */
	    'A',	/* always output a time pulse */
	    500,	/* max time error in ns */
	    0,		/* user bias in ns */
	    1);		/* output "830" sentences to control port */
			/* Multi-satellite mode */

	/*
	 * Output position information (to calculate fixed installation
	 * location) only if we are not moving
	 */
	if (up->moving) {
		add_mode = 2;	/* delete from list */
	} else {
		add_mode = 1;	/* add to list */
	}

	/*
	 * "007" Control Port Configuration
	 * Output "022" DOPs
	 */
	mx4200_send(peer, "%s,%03d,%03d,%d,%d,,%d,,,", pmvxg,
	    PMVXG_S_PORTCONF,
	    PMVXG_D_DOPS, /* control port output block Label */
	    0,		/* clear current output control list (0=no) */
	    add_mode,	/* add/delete sentences from list (1=add, 2=del) */
			/* must be null */
	    INTERVAL);	/* sentence output rate (sec) */
	    		/* precision for position output */
			/* nmea version for cga & gll output */
			/* pass-through control */


	/*
	 * "007" Control Port Configuration
	 * Output "021" position, height, velocity reports
	 */
	mx4200_send(peer, "%s,%03d,%03d,%d,%d,,%d,,,", pmvxg,
	    PMVXG_S_PORTCONF,
	    PMVXG_D_PHV, /* control port output block Label */
	    0,		/* clear current output control list (0=no) */
	    add_mode,	/* add/delete sentences from list (1=add, 2=del) */
			/* must be null */
	    INTERVAL);	/* sentence output rate (sec) */
	    		/* precision for position output */
			/* nmea version for cga & gll output */
			/* pass-through control */
}

/*
 * mx4200_ref - Reconfigure unit as a reference station at a known position.
 */
static void
mx4200_ref(peer)
	struct peer *peer;
{
	register struct mx4200unit *up;
	struct refclockproc *pp;
	double minute, lat, lon, alt;
	char lats[16], lons[16];
	char nsc, ewc;

	pp = peer->procptr;
	up = (struct mx4200unit *)pp->unitptr;

	/* Should never happen! */
	if (up->moving) return;

	/*
	 * Set up to output status information in the near future
	 */
	up->log_time    = current_time + SLEEPTIME;

	/*
	 * "001" Initialization/Mode Control, Part B
	 * Put receiver in fully-constrained 2d nav mode
	 */
	mx4200_send(peer, "%s,%03d,%d,,%.1f,%.1f,%d,%d,%d,%c,%d",
	    pmvxg, PMVXG_S_INITMODEB,
	    2,		/* 2d nav */
			/* reserved */
	    0.1,	/* hor accel fact as per Steve (m/s**2) */
	    0.1,	/* ver accel fact as per Steve (m/s**2) */
	    10,		/* vdop */
	    10,		/* hdop limit as per Steve */
	    5,		/* elevation limit as per Steve (deg) */
	    'U',	/* time output mode (UTC) */
	    0);		/* local time offset from gmt (HHHMM) */

	/*
	 * "023" Time Recovery Configuration
	 * Get UTC time from a stationary receiver.  Solve for time only.
	 * This should improve the time resolution dramatically.
	 */
	mx4200_send(peer, "%s,%03d,%c,%c,%c,%d,%d,%d,", pmvxg,
	    PMVXG_S_TRECOVCONF,
	    'K',	/* known position: solve for time only */
	    'U',	/* synchronize to UTC */
	    'A',	/* always output a time pulse */
	    500,	/* max time error in ns */
	    0,		/* user bias in ns */
	    1);		/* output "830" sentences to control port */
			/* Multi-satellite mode */

	/*
	 * "000" Initialization/Mode Control - Part A
	 * Fix to our averaged position.
	 */
	if (up->avg_lat >= 0.0) {
		lat = up->avg_lat;
		nsc = 'N';
	} else {
		lat = up->avg_lat * (-1.0);
		nsc = 'S';
	}
	if (up->avg_lon >= 0.0) {
		lon = up->avg_lon;
		ewc = 'E';
	} else {
		lon = up->avg_lon * (-1.0);
		ewc = 'W';
	}
	alt = up->avg_alt;
	minute = (lat - (double)(int)lat) * 600.0 / 10.0;
	sprintf(lats,"%02d%02.4f", (int)lat, minute);
	minute = (lon - (double)(int)lon) * 600.0 / 10.0;
	sprintf(lons,"%03d%02.4f", (int)lon, minute);

	mx4200_send(peer, "%s,%03d,,,,,%s,%c,%s,%c,%.2f,%d", pmvxg,
	    PMVXG_S_INITMODEA,
			/* day of month */
			/* month of year */
			/* year */
			/* gmt */
	    lats,	/* latitude   DDMM.MMMM */
	    nsc,	/* north/south */
	    lons,	/* longitude DDDMM.MMMM */
	    ewc,	/* east/west */
	    alt,	/* height */
	    1);		/* Altitude Reference 1=MSL */


	/*
	 * "007" Control Port Configuration
	 * Stop outputting "022" DOPs
	 */
	mx4200_send(peer, "%s,%03d,%03d,%d,%d,,%d,,,", pmvxg,
	    PMVXG_S_PORTCONF,
	    PMVXG_D_DOPS, /* control port output block Label */
	    0,		/* clear current output control list (0=no) */
	    2,		/* add/delete sentences from list (2=delete) */
			/* must be null */
	    0);		/* sentence output rate (sec) */
	    		/* precision for position output */
			/* nmea version for cga & gll output */
			/* pass-through control */

	/*
	 * "007" Control Port Configuration
	 * Stop outputting "021" position, height, velocity reports
	 */
	mx4200_send(peer, "%s,%03d,%03d,%d,%d,,%d,,,", pmvxg,
	    PMVXG_S_PORTCONF,
	    PMVXG_D_PHV, /* control port output block Label */
	    0,		/* clear current output control list (0=no) */
	    2,		/* add/delete sentences from list (2=delete) */
			/* must be null */
	    0);		/* sentence output rate (sec) */
	    		/* precision for position output */
			/* nmea version for cga & gll output */
			/* pass-through control */

	msyslog(LOG_DEBUG,
	    "mx4200_ref: reconfig to fixed location: %s %c, %s %c, %.2f m MSL",
	    lats, nsc, lons, ewc, alt );

}

/*
 * mx4200_poll - mx4200 watchdog routine
 */
static void
mx4200_poll(unit, peer)
	int unit;
	struct peer *peer;
{
	register struct mx4200unit *up;
	struct refclockproc *pp;

	pp = peer->procptr;
	up = (struct mx4200unit *)pp->unitptr;

	/*
	 * You don't need to poll this clock.  It puts out timecodes
	 * once per second.  If asked for a timestamp, take note.
	 * The next time a timecode comes in, it will be fed back.
	 */

	/*
	 * If we haven't had a response in a while, reset the receiver.
	 */
	if (up->pollcnt > 0) {
		up->pollcnt--;
	} else {
		refclock_report(peer, CEVNT_TIMEOUT);

		/*
		 * Request a "000" status message which should trigger a
		 * reconfig
		 */
		mx4200_send(peer, "%s,%03d",
		    "CDGPQ",		/* query from CDU to GPS */
		    PMVXG_D_STATUS);	/* label of desired sentence */
	}

	/*
	 * polled every 64 seconds. Ask mx4200_receive to hand in
	 * a timestamp.
	 */
	up->polled = 1;
	pp->polls++;

	/*
	 * Output receiver status information.
	 */
	if ((up->log_time > 0) && (current_time > up->log_time)) {
		up->log_time = 0;
		/*
		 * Output the following messages once, for debugging.
		 *    "004" Mode Data
		 *    "523" Time Recovery Parameters
		 */
		mx4200_send(peer, "%s,%03d", "CDGPQ", PMVXG_D_MODEDATA);
		mx4200_send(peer, "%s,%03d", "CDGPQ", PMVXG_D_TRECOVUSEAGE);
	}
}

static char char2hex[] = "0123456789ABCDEF";

/*
 * mx4200_receive - receive gps data
 */
static void
mx4200_receive(rbufp)
	struct recvbuf *rbufp;
{
	register struct mx4200unit *up;
	struct refclockproc *pp;
	struct peer *peer;
	char *cp;
	int sentence_type;
	u_char ck;

	/*
	 * Initialize pointers and read the timecode and timestamp.
	 */
	peer = (struct peer *)rbufp->recv_srcclock;
	pp = peer->procptr;
	up = (struct mx4200unit *)pp->unitptr;

	/*
	 * If operating mode has been changed, then reinitialize the receiver
	 * before doing anything else.
	 */
	if ((pp->sloppyclockflag & CLK_FLAG2) !=
	    (up->sloppyclockflag & CLK_FLAG2)) {
		up->sloppyclockflag = pp->sloppyclockflag;
		mx4200_debug(peer,
		    "mx4200_receive: mode switch: reset receiver\n");
		mx4200_config(peer);
		return;
	}
	up->sloppyclockflag = pp->sloppyclockflag;

	/*
	 * Read clock output.  Automatically handles STREAMS, CLKLDISC.
	 */
	pp->lencode = refclock_gtlin(rbufp, pp->a_lastcode, BMAX, &pp->lastrec);

	/*
	 * There is a case where <cr><lf> generates 2 timestamps.
	 */
	if (pp->lencode == 0)
		return;

	up->pollcnt = 2;
	pp->a_lastcode[pp->lencode] = '\0';
	record_clock_stats(&peer->srcadr, pp->a_lastcode);
	mx4200_debug(peer, "mx4200_receive: %d %s\n",
		pp->lencode, pp->a_lastcode);

	/*
	 * The structure of the control port sentences is based on the
	 * NMEA-0183 Standard for interfacing Marine Electronics
	 * Navigation Devices (Version 1.5)
	 *
	 *	$PMVXG,XXX, ....................*CK<cr><lf>
	 *
	 *		$	Sentence Start Identifier (reserved char)
	 *			   (Start-of-Sentence Identifier)
	 *		P	Special ID (Proprietary)
	 *		MVX	Originator ID (Magnavox)
	 *		G	Interface ID (GPS)
	 *		,	Field Delimiters (reserved char)
	 *		XXX	Sentence Type
	 *		......	Data
	 *		*	Checksum Field Delimiter (reserved char)
	 *		CK	Checksum
	 *		<cr><lf> Carriage-Return/Line Feed (reserved chars)
	 *			   (End-of-Sentence Identifier)
	 *
	 * Reject if any important landmarks are missing.
	 */
	cp = pp->a_lastcode + pp->lencode - 3;
	if (cp < pp->a_lastcode || *pp->a_lastcode != '$' || cp[0] != '*' ) {
		mx4200_debug(peer, "mx4200_receive: bad format\n");
		refclock_report(peer, CEVNT_BADREPLY);
		return;
	}

	/*
	 * Check and discard the checksum
	 */
	ck = mx4200_cksum(&pp->a_lastcode[1], pp->lencode - 4);
	if (char2hex[ck >> 4] != cp[1] || char2hex[ck & 0xf] != cp[2]) {
		mx4200_debug(peer, "mx4200_receive: bad checksum\n");
		refclock_report(peer, CEVNT_BADREPLY);
		return;
	}
	*cp = '\0';

	/*
	 * Get the sentence type.
	 */
	sentence_type = 0;
	if ((cp = strchr(pp->a_lastcode, ',')) == NULL) {
		mx4200_debug(peer, "mx4200_receive: no sentence\n");
		refclock_report(peer, CEVNT_BADREPLY);
		return;
	}
	cp++;
	sentence_type = strtol(cp, &cp, 10);

	/*
	 * "000" Status message
	 */

	if (sentence_type == PMVXG_D_STATUS) {
		/*
		 * XXX
		 * Since we configure the receiver to not give us status
		 * messages and since the receiver outputs status messages by
		 * default after being reset to factory defaults when sent the
		 * "$PMVXG,018,C\r\n" message, any status message we get
		 * indicates the reciever needs to be initialized; thus, it is
		 * not necessary to decode the status message.
		 */
		if ((cp = mx4200_parse_s(peer)) != NULL) {
			mx4200_debug(peer,
				"mx4200_receive: status: %s\n", cp);
		}
		mx4200_debug(peer, "mx4200_receive: reset receiver\n");
		mx4200_config(peer);
		return;
	}

	/*
	 * "021" Position, Height, Velocity message,
	 *  if we are still averaging our position
	 */
	if (sentence_type == PMVXG_D_PHV && !up->known) {
		/*
		 * Parse the message, calculating our averaged position.
		 */
		if ((cp = mx4200_parse_p(peer)) != NULL) {
			mx4200_debug(peer, "mx4200_receive: pos: %s\n", cp);
			return;
		}
		mx4200_debug(peer,
			"mx4200_receive: position avg %.9f %.9f %.4f\n",
			up->avg_lat, up->avg_lon, up->avg_alt);
		mx4200_debug(peer,
			"mx4200_receive: position len %.4f %.4f %.4f\n",
			up->filt_lat, up->filt_lon, up->filt_alt);
		mx4200_debug(peer,
			"mx4200_receive: position dop %.2f %.2f %.2f\n",
			up->ndop, up->edop, up->vdop);
		/*
		 * Reinitialize as a reference station
		 * if position is well known.
		 */
		if (current_time > up->clamp_time) {
			up->known++;
			mx4200_debug(peer, "mx4200_receive: reconfiguring!\n");
			mx4200_ref(peer);
		}
		return;
	}

	/*
	 * "022" DOPs, if we are still averaging our position
	 */
	if (sentence_type == PMVXG_D_DOPS && !up->known) {
		if ((cp = mx4200_parse_d(peer)) != NULL) {
			mx4200_debug(peer, "mx4200_receive: dop: %s\n", cp);
			return;
		}
		return;
	}

	/*
	 * Print to the syslog:
	 * "004" Mode Data
	 * "030" Software Configuration
	 * "523" Time Recovery Parameters Currently in Use
	 */
	if (sentence_type == PMVXG_D_MODEDATA ||
	    sentence_type == PMVXG_D_SOFTCONF ||
	    sentence_type == PMVXG_D_TRECOVUSEAGE ) {
		if ((cp = mx4200_parse_s(peer)) != NULL) {
			mx4200_debug(peer,
				"mx4200_receive: multi-record: %s\n", cp);
			return;
		}
		return;
	}

	/*
	 * "830" Time Recovery Results message
	 */
	if (sentence_type == PMVXG_D_TRECOVOUT) {

		/*
		 * Capture the last PPS signal.
		 * Precision timestamp is returned in pp->lastrec
		 */
		if (mx4200_pps(peer) != NULL) {
			mx4200_debug(peer, "mx4200_receive: pps failure\n");
			refclock_report(peer, CEVNT_FAULT);
			return;
		}

		/*
		 * Parse the time recovery message, and keep the info
		 * to print the pretty billboards.
		 */
		if ((cp = mx4200_parse_t(peer)) != NULL) {
			mx4200_debug(peer, "mx4200_receive: time: %s\n", cp);
			refclock_report(peer, CEVNT_BADREPLY);
			return;
		}

		/*
		 * Add the new sample to a median filter.
		 */
		if ((cp =mx4200_offset(peer)) != NULL) {
			mx4200_debug(peer,"mx4200_receive: offset: %s\n", cp);
			refclock_report(peer, CEVNT_BADTIME);
			return;
		}

		/*
		 * The clock will blurt a timecode every second but we only
		 * want one when polled.  If we havn't been polled, bail out.
		 */
		if (!up->polled)
			return;

		/*
		 * It's a live one!  Remember this time.
		 */
		pp->lasttime   = current_time;

		/*
		 * Determine the reference clock offset and dispersion.
		 * NKEEP of NSAMPLE offsets are passed through a median filter.
		 * Save the (filtered) offset and dispersion in
		 * pp->offset and pp->dispersion.
		 */
		if ((cp =mx4200_process(peer)) != NULL) {
			mx4200_debug(peer,"mx4200_receive: process: %s\n", cp);
			refclock_report(peer, CEVNT_BADTIME);
			return;
		}

		/*
		 * Return offset and dispersion to control module.  We use
		 * lastrec as both the reference time and receive time in
		 * order to avoid being cute, like setting the reference time
		 * later than the receive time, which may cause a paranoid
		 * protocol module to chuck out the data.
		 */
		mx4200_debug(peer, "mx4200_receive: process time: ");
		mx4200_debug(peer, "%4d-%03d %02d:%02d:%02d at %s, %s\n",
			pp->year, pp->day, pp->hour, pp->minute, pp->second,
			prettydate(&pp->lastrec), lfptoa(&pp->offset, 6));

		refclock_receive(peer, &pp->offset, 0, pp->dispersion,
			&pp->lastrec, &pp->lastrec, pp->leap);

		/*
		 * We have succeeded in answering the poll.
		 * Turn off the flag and return
		 */
		up->polled = 0;
		return;
	}

	/*
	 * Ignore all other sentence types
	 */
	return;
}

/*
 * mx4200_offset - Calculate the offset, and add to the rolling filter.
 */
static char *
mx4200_offset(peer)
	struct peer *peer;
{
	register struct mx4200unit *up;
	struct refclockproc *pp;
	register int i;
	l_fp offset;

	pp = peer->procptr;
	up = (struct mx4200unit *)pp->unitptr;

	/*
	 * Calculate the offset
	 */
	if (!clocktime(pp->day, pp->hour, pp->minute, pp->second, GMT,
		pp->lastrec.l_ui, &pp->yearstart, &offset.l_ui)) {
		return ("mx4200_process: clocktime failed");
	}
	if (pp->usec) {
		TVUTOTSF(pp->usec, offset.l_uf);
	} else {
		MSUTOTSF(pp->msec, offset.l_uf);
	}
	L_ADD(&offset, &pp->fudgetime1);
	up->lastref = offset;   /* save last reference time */
	L_SUB(&offset, &pp->lastrec); /* form true offset */

	/*
	 * A rolling filter.  Initialize first time around.
	 */
	i = ((up->coderecv)) % NSAMPLES;

	up->filter[i] = offset;
	if (up->coderecv == 0)
		for (i = 1; (u_int) i < NSAMPLES; i++)
			up->filter[i] = up->filter[0];
	up->coderecv++;

	return (NULL);
}

/*
 * mx4200_process - process the sample from the clock,
 * passing it through a median filter and optionally averaging
 * the samples.  Returns offset and dispersion in "up" structure.
 */
static char *
mx4200_process(peer)
	struct peer *peer;
{
	register struct mx4200unit *up;
	struct refclockproc *pp;
	register int i, n;
	int j, k;
	l_fp offset, median, lftmp;
	u_fp disp;
	l_fp off[NSAMPLES];

	pp = peer->procptr;
	up = (struct mx4200unit *)pp->unitptr;

	/*
	 * Copy the raw offsets and sort into ascending order
	 */
	for (i = 0; i < NSAMPLES; i++)
		off[i] = up->filter[i];
	qsort((char *)off, NSAMPLES, sizeof(l_fp), mx4200_cmpl_fp);

	/*
	 * Reject the furthest from the median of NSAMPLES samples until
	 * NKEEP samples remain.
	 */
	i = 0;
	n = NSAMPLES;
	while ((n - i) > up->nkeep) {
		lftmp = off[n - 1];
		median = off[(n + i) / 2];
		L_SUB(&lftmp, &median);
		L_SUB(&median, &off[i]);
		if (L_ISHIS(&median, &lftmp)) {
			/* reject low end */
			i++;
		} else {
			/* reject high end */
			n--;
		}
	}

	/*
	 * Copy key values to the billboard to measure performance.
	 */
	pp->lastref = up->lastref;
	pp->coderecv = up->coderecv;
	pp->nstages = up->nkeep + 2;
	pp->filter[0] = off[0];			/* smallest offset */
	pp->filter[1] = off[NSAMPLES-1];	/* largest offset */
	for (j=2, k=i; k < n; j++, k++)
		pp->filter[j] = off[k];		/* offsets actually examined */

	/*
	 * Compute the dispersion based on the difference between the
	 * extremes of the remaining offsets. Add to this the time since
	 * the last clock update, which represents the dispersion
	 * increase with time. We know that NTP_MAXSKEW is 16. If the
	 * sum is greater than the allowed sample dispersion, bail out.
	 * If the loop is unlocked, return the most recent offset;
	 * otherwise, return the median offset.
	 */
	lftmp = off[n - 1];
	L_SUB(&lftmp, &off[i]);
	disp = LFPTOFP(&lftmp);
	if (disp > REFCLOCKMAXDISPERSE) {
		return("Maximum dispersion exceeded");
	}

	/*
	 * Now compute the offset estimate.  If fudge flag 1
	 * is set, average the remainder, otherwise pick the
	 * median.
	 */
	if (pp->sloppyclockflag & CLK_FLAG1) {
		L_CLR(&lftmp);
		while (i < n) {
			L_ADD(&lftmp, &off[i]);
			i++;
		}
		i = up->rshift;
		while (i > 0) {
			L_RSHIFT(&lftmp);
			i--;
		}
		offset = lftmp;
	} else {
		i = (n + i) / 2;
		offset = off[i];
	}

	/*
	 * The payload: filtered offset and dispersion.
	 */

	pp->offset = offset;
	pp->dispersion = disp;

	return(NULL);

}

/* Compare two l_fp's, used with qsort() */
int
#ifdef QSORT_USES_VOID_P
mx4200_cmpl_fp(p1, p2)
	const void *p1, *p2;
{
	register const l_fp *fp1 = (const l_fp *)p1;
	register const l_fp *fp2 = (const l_fp *)p2;
#else
mx4200_cmpl_fp(fp1, fp2)
	register const l_fp *fp1;
	register const l_fp *fp2;
{
#endif /* not QSORT_USES_VOID_P */

	if (!L_ISGEQ(fp1, fp2))
		return (-1);
	if (L_ISEQU(fp1, fp2))
		return (0);
	return (1);
}


/*
 * Parse a mx4200 time recovery message. Returns a string if error.
 *
 * A typical message looks like this.  Checksum has already been stripped.
 *
 *    $PMVXG,830,T,YYYY,MM,DD,HH:MM:SS,U,S,FFFFFF,PPPPP,BBBBBB,LL
 *
 *	Field	Field Contents
 *	-----	--------------
 *		Block Label: $PMVXG
 *		Sentence Type: 830=Time Recovery Results
 *			This sentence is output approximately 1 second
 *			preceding the 1PPS output.  It indicates the
 *			exact time of the next pulse, whether or not the
 *			time mark will be valid (based on operator-specified
 *			error tolerance), the time to which the pulse is
 *			synchronized, the receiver operating mode,
 *			and the time error of the *last* 1PPS output.
 *	1	Time Mark Valid: T=Valid, F=Not Valid
 *	2	Year: 1993-
 *	3	Month of Year: 1-12
 *	4	Day of Month: 1-31
 *	5	Time of Day: HH:MM:SS
 *	6	Time Synchronization: U=UTC, G=GPS
 *	7	Time Recovery Mode: D=Dynamic, S=Static,
 *			K=Known Position, N=No Time Recovery
 *	8	Oscillator Offset: The filter's estimate of the oscillator
 *			frequency error, in parts per billion (ppb).
 *	9	Time Mark Error: The computed error of the *last* pulse
 *			output, in nanoseconds.
 *	10	User Time Bias: Operator specified bias, in nanoseconds
 *	11	Leap Second Flag: Indicates that a leap second will
 *			occur.  This value is usually zero, except during
 *			the week prior to the leap second occurence, when
 *			this value will be set to +1 or -1.  A value of
 *			+1 indicates that GPS time will be 1 second
 *			further ahead of UTC time.
 *
 */
static char *
mx4200_parse_t(peer)
	struct peer *peer;
{
	struct refclockproc *pp;
	struct mx4200unit *up;
	int sentence_type, valid;
	int year, yearday, month, monthday, hour, minute, second, leapsec;
	char *cp;

	pp = peer->procptr;
	up = (struct mx4200unit *)pp->unitptr;

	cp = pp->a_lastcode;

	if ((cp = strchr(cp, ',')) == NULL)
		return ("no rec-type");
	cp++;

	/* Sentence type */
	sentence_type = strtol(cp, &cp, 10);
	if (sentence_type != PMVXG_D_TRECOVOUT)
		return ("wrong rec-type");

	/* Pulse valid indicator */
	if (*cp++ != ',')
		return ("no pulse-valid");
	if (*cp == 'T')
		valid = 1;
	else if (*cp == 'F')
		valid = 0;
	else
		return ("bad pulse-valid");
	cp++;

	/* Year */
	if (*cp++ != ',')
		return ("no year");
	year = strtol(cp, &cp, 10);

	/* Month of year */
	if (*cp++ != ',')
		return ("no month");
	month = strtol(cp, &cp, 10);

	/* Day of month */
	if (*cp++ != ',')
		return ("no month day");
	monthday = strtol(cp, &cp, 10);

	/* Hour */
	if (*cp++ != ',')
		return ("no hour");
	hour = strtol(cp, &cp, 10);

	/* Minute */
	if (*cp++ != ':')
		return ("no minute");
	minute = strtol(cp, &cp, 10);

	/* Second */
	if (*cp++ != ':')
		return ("no second");
	second = strtol(cp, &cp, 10);

	/* Time indicator */
	if (*cp++ != ',')
		return ("no time indicator");
	if (*cp == 'G')
		return ("synchronized to GPS; should be UTC");
	else if (*cp != 'U')
		return ("not synchronized to UTC");
	cp++;

	/* Time recovery mode */
	if (*cp++ != ',' || *cp++ == '\0')
		return ("no time mode");

	/* Oscillator offset */
	if ((cp = strchr(cp, ',')) == NULL)
		return ("no osc off");
	cp++;

	/* Time mark error */
	/* (by request, always less than 0.5 usec (500 nsec), so ignore) */
	if ((cp = strchr(cp, ',')) == NULL)
		return ("no time mark err");
	cp++;

	/* User time bias */
	/* (by request, always zero, so ignore */
	if ((cp = strchr(cp, ',')) == NULL)
		return ("no user bias");
	cp++;

	/* Leap second flag */
	if ((cp = strchr(cp, ',')) == NULL)
		return ("no leap");
	cp++;
	leapsec = strtol(cp, &cp, 10);


	/*
	 * Check for insane time (allow for possible leap seconds)
	 */
	if (second > 60 || minute > 59 || hour > 23 ||
	    second <  0 || minute <  0 || hour <  0) {
		mx4200_debug(peer,
			"mx4200_parse_t: bad time %02d:%02d:%02d",
			hour, minute, second);
		if (leapsec != 0)
			mx4200_debug(peer, " (leap %+d\n)", leapsec);
		mx4200_debug(peer, "\n");
		refclock_report(peer, CEVNT_BADTIME);
		return ("bad time");
	}
	if ( second == 60 ) {
		msyslog(LOG_DEBUG, "mx4200_parse_t: leap second! %02d:%02d:%02d",
			 hour, minute, second);
	}

	/*
	 * Check for insane date
	 * (Certainly can't be any year before this code was last altered!)
	 */
	if (monthday > 31 || month > 12 ||
	    monthday <  1 || month <  1 || year < YEAR_RIGHT_NOW) {
		mx4200_debug(peer,
			"mx4200_parse_t: bad date (%4d-%02d-%02d)\n",
			year, month, monthday);
		refclock_report(peer, CEVNT_BADDATE);
		return ("bad date");
	}

	/*
	 * Silly Hack for MX4200:
	 * ASCII message is for *next* 1PPS signal, but we have the
	 * timestamp for the *last* 1PPS signal.  So we have to subtract
	 * a second.  Discard if we are on a month boundary to avoid
	 * possible leap seconds and leap days.
	 */
	second--;
	if (second < 0) {
		second = 59;
		minute--;
		if (minute < 0) {
			minute = 59;
			hour--;
			if (hour < 0) {
				hour = 23;
				monthday--;
				if (monthday < 1) {
					return ("sorry, month boundary");
				}
			}
		}
	}

	/*
	 * Calculate Julian date
	 */
	if (!(yearday = mx4200_jday(year, month, monthday))) {
		mx4200_debug(peer,
			"mx4200_parse_t: bad julian date %d (%4d-%02d-%02d)\n",
			yearday, year, month, monthday);
		refclock_report(peer, CEVNT_BADDATE);
		return("invalid julian date");
	}

	/*
	 * Setup leap second indicator
	 */
	if (leapsec == 0)
		pp->leap = LEAP_NOWARNING;
	else if (leapsec == 1)
		pp->leap = LEAP_ADDSECOND;
	else if (leapsec == -1)
		pp->leap = LEAP_DELSECOND;
	else
		pp->leap = LEAP_NOTINSYNC;	/* shouldn't happen */

	/*
	 * Any change to the leap second warning status?
	 */
	if (leapsec != up->last_leap ) {
		msyslog(LOG_DEBUG,
			"mx4200_parse_t: leap second warning: %d to %d (%d)",
			up->last_leap, leapsec, pp->leap);
	}
	up->last_leap = leapsec;

	/*
	 * Copy time data for billboard monitoring.
	 */

	pp->year   = year;
	pp->day    = yearday;
	pp->hour   = hour;
	pp->minute = minute;
	pp->second = second;
	pp->msec   = 0;
	pp->usec   = 0;

	/*
	 * Toss if sentence is marked invalid
	 */
	if (!valid || pp->leap == LEAP_NOTINSYNC) {
		mx4200_debug(peer, "mx4200_parse_t: time mark not valid\n");
		refclock_report(peer, CEVNT_BADTIME);
		return ("pulse invalid");
	}

	return (NULL);
}

/*
 * Calculate the checksum
 */
static u_char
mx4200_cksum(cp, n)
	register char *cp;
	register u_int n;
{
	register u_char ck;

	for (ck = 0; n-- > 0; cp++)
		ck ^= *cp;
	return (ck);
}

/*
 * Tables to compute the day of year.  Viva la leap.
 */
static day1tab[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
static day2tab[] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

/*
 * Calculate the the Julian Day
 */
static int
mx4200_jday(year, month, monthday)
	int year;
	int month;
	int monthday;
{
	register int day, i;
	int leap_year;


	/*
	 * Is this a leap year ?
	 */
	if (year % 4) {
		leap_year = 0; /* FALSE */
	} else {
		if (year % 100) {
			leap_year = 1; /* TRUE */
		} else {
			if (year % 400) {
				leap_year = 0; /* FALSE */
			} else {
				leap_year = 1; /* TRUE */
			}
		}
	}

	/*
	 * Calculate the Julian Date
	 */
	day = monthday;

	if (leap_year) {
		/* a leap year */
		if (day > day2tab[month - 1]) {
			return (0);
		}
		for (i = 0; i < month - 1; i++)
			day += day2tab[i];
	} else {
		/* not a leap year */
		if (day > day1tab[month - 1]) {
			return (0);
		}
		for (i = 0; i < month - 1; i++)
			day += day1tab[i];
	}
	return (day);
}

/*
 * Parse a mx4200 position/height/velocity sentence.
 *
 * A typical message looks like this.  Checksum has already been stripped.
 *
 * $PMVXG,021,SSSSSS.SS,DDMM.MMMM,N,DDDMM.MMMM,E,HHHHH.H,GGGG.G,EEEE.E,WWWW.W,MM
 *
 *	Field	Field Contents
 *	-----	--------------
 *		Block Label: $PMVXG
 *		Sentence Type: 021=Position, Height Velocity Data
 *			This sentence gives the receiver position, height,
 *			navigation mode, and velocity north/east.
 *			*This sentence is intended for post-analysis
 *			applications.*
 *	1	UTC measurement time (seconds into week)
 *	2	WGS-84 Lattitude (degrees, minutes)
 *	3	N=North, S=South
 *	4	WGS-84 Longitude (degrees, minutes)
 *	5	E=East, W=West
 *	6	Altitude (meters above mean sea level)
 *	7	Geoidal height (meters)
 *	8	East velocity (m/sec)
 *	9	West Velocity (m/sec)
 *	10	Navigation Mode
 *		    Mode if navigating:
 *			1 = Position from remote device
 *			2 = 2-D position
 *			3 = 3-D position
 *			4 = 2-D differential position
 *			5 = 3-D differential position
 *			6 = Static
 *			8 = Position known -- reference station
 *			9 = Position known -- Navigator
 *		    Mode if not navigating:
 *			51 = Too few satellites
 *			52 = DOPs too large
 *			53 = Position STD too large
 *			54 = Velocity STD too large
 *			55 = Too many iterations for velocity
 *			56 = Too many iterations for position
 *			57 = 3 sat startup failed
 *			58 = Command abort
 */
static char *
mx4200_parse_p(peer)
	struct peer *peer;
{
	struct refclockproc *pp;
	struct mx4200unit *up;
	int sentence_type, mode;
	double dtemp, dtemp2, mtime, lat, lon, alt, geoid, vele, veln, weight;
	char *cp;

	pp = peer->procptr;
	up = (struct mx4200unit *)pp->unitptr;

	/* Should never happen! */
	if (up->moving) return ("mobile platform - no pos!");

	cp = pp->a_lastcode;

	if ((cp = strchr(cp, ',')) == NULL)
		return ("no rec-type");
	cp++;

	/* Sentence type */
	sentence_type = strtol(cp, &cp, 10);
	if (sentence_type != PMVXG_D_PHV)
		return ("wrong rec-type");

	/* Measurement Time */
	if (*cp++ != ',')
		return ("no measurement time");
	mtime = strtod(cp,&cp);

	/* Latitude (always +ve) */
	if (*cp++ != ',')
		return ("no latitude");
	dtemp = atof(cp);
	dtemp2 = strtod(cp,&cp);
	if (dtemp < 0.0)
		return ("negative latitude");
	lat = (double) ( (int)dtemp / 100);
	lat += (dtemp - (lat*100.0)) * 10.0 / 600.0;

	/* North/South */
	if (*cp++ != ',')
		return ("no north/south indicator");
	if (*cp == 'N')
		lat = lat;
	else if (*cp == 'S')
		lat *= -1.0;
	else
		return ("invalid north/south indicator");
	cp++;

	/* Longitude (always +ve) */
	if (*cp++ != ',')
		return ("no longitude");
	dtemp = atof(cp);
	dtemp2 = strtod(cp,&cp);
	if (dtemp < 0.0)
		return ("negative latitude");
	lon = (double) ( (int)dtemp / 100);
	lon += (dtemp - (lon*100.0)) * 10.0 / 600.0;

	/* East/West */
	if (*cp++ != ',')
		return ("no east/west indicator");
	if (*cp == 'E')
		lon = lon;
	else if (*cp == 'W')
		lon *= -1.0;
	else
		return ("invalid east/west indicator");
	cp++;

	/* Altitude */
	if (*cp++ != ',')
		return ("no altitude");
	alt = atof(cp);
	dtemp2 = strtod(cp,&cp);

	/* geoid height */
	if (*cp++ != ',')
		return ("no geoid height");
	geoid = strtod(cp,&cp);

	/* East velocity */
	if (*cp++ != ',')
		return ("no east velocity");
	vele = strtod(cp,&cp);

	/* north velocity */
	if (*cp++ != ',')
		return ("no north velocity");
	veln = strtod(cp,&cp);

	/* nav mode */
	if (*cp++ != ',')
		return ("no nav mode");
	mode = strtol(cp, &cp, 10);


	/*
	 * return if not navigating
	 */
	if (mode > 10)
		return ("not navigating");

	if (mode != 3 && mode != 5)
		return ("not navigating in 3D");

	/*
	 * Calculate running weighted averages
	 */

	weight = (USUAL_EDOP/up->edop);
	weight = weight * weight;
	up->avg_lon = up->filt_lon * up->avg_lon + weight * lon;
	up->filt_lon += weight;
	up->avg_lon = up->avg_lon / up->filt_lon;

	weight = (USUAL_NDOP/up->ndop);
	weight = weight * weight;
	up->avg_lat = up->filt_lat * up->avg_lat + weight * lat;
	up->filt_lat += weight;
	up->avg_lat = up->avg_lat / up->filt_lat;

	weight = (USUAL_VDOP/up->vdop);
	weight = weight * weight;
	up->avg_alt = up->filt_alt * up->avg_alt + weight * alt;
	up->filt_alt += weight;
	up->avg_alt = up->avg_alt / up->filt_alt;

	return (NULL);
}

/*
 * Parse a mx4200 DOP sentence.
 *
 * A typical message looks like this.  Checksum has already been stripped.
 *
 * $PMVXG,022,SSSSSS.SSEE.E,NN.N,VV.V,XX,XX,XX,XX,XX,XX
 *
 *	Field	Field Contents
 *	-----	--------------
 *		Block Label: $PMVXG
 *		Sentence Type: 022=DOPs.  The DOP values in this sentence
 *			correspond to the satellites listed.  The PRNs in
 *			the message are listed in receiver channel number order
 *	1	UTC measurement time (seconds into week)
 *	2	EDOP (east DOP)
 *	3	NDOP (north DOP)
 *	4	VDOP (vertical DOP)
 *	5	PRN on channel 1
 *	6	PRN on channel 2
 *	7	PRN on channel 3
 *	8	PRN on channel 4
 *	9	PRN on channel 5
 *	10	PRN on channel 6
 */
static char *
mx4200_parse_d(peer)
	struct peer *peer;
{
	struct refclockproc *pp;
	struct mx4200unit *up;
	int sentence_type;
	double mtime, dtemp2, edop, ndop, vdop;
	char *cp;

	pp = peer->procptr;
	up = (struct mx4200unit *)pp->unitptr;

	/* Should never happen! */
	if (up->moving) return ("mobile platform - no dop!");

	cp = pp->a_lastcode;

	if ((cp = strchr(cp, ',')) == NULL)
		return ("no rec-type");
	cp++;

	/* Sentence type */
	sentence_type = strtol(cp, &cp, 10);
	if (sentence_type != PMVXG_D_DOPS)
		return ("wrong rec-type");

	/* Measurement Time */
	if (*cp++ != ',')
		return ("no measurement time");
	mtime = strtod(cp,&cp);

	/* EDOP */
	if (*cp++ != ',')
		return ("no edop");
	edop = atof(cp);
	dtemp2 = strtod(cp,&cp);

	/* NDOP */
	if (*cp++ != ',')
		return ("no ndop");
	ndop = atof(cp);
	dtemp2 = strtod(cp,&cp);

	/* VDOP */
	if (*cp++ != ',')
		return ("no vdop");
	vdop = atof(cp);
	dtemp2 = strtod(cp,&cp);

	/* Ignore the PRNs... */


	/* Update values */
	if (edop <= 0.0 || ndop <= 0.0 || vdop <= 0.0)
		return ("nonpositive dop");
	up->edop = edop;
	up->ndop = ndop;
	up->vdop = vdop;

	return (NULL);
}

/*
 * Parse a mx4200 Status sentence
 * Parse a mx4200 Mode Data sentence
 * Parse a mx4200 Software Configuration sentence
 * Parse a mx4200 Time Recovery Parameters Currently in Use sentence
 * (used only for logging raw strings)
 *
 * A typical message looks like this.  Checksum has already been stripped.
 *
 * $PMVXG,000,XXX,XX,X,HHMM,X
 *
 *	Field	Field Contents
 *	-----	--------------
 *		Block Label: $PMVXG
 *		Sentence Type: 000=Status.
 *			Returns status of the receiver to the controller.
 *	1	Current Receiver Status:
 *		ACQ = Satellite re-acquisition
 *		ALT = Constellation selection
 *		COR = Providing corrections (for reference stations only)
 *		IAC = Initial acquisition
 *		IDL = Idle, no satellites
 *		NAV = Navigation
 *		STS = Search the Sky (no almanac available)
 *		TRK = Tracking
 *	2	Number of satellites that should be visible
 *	3	Number of satellites being tracked
 *	4	Time since last navigation status if not currently navigating
 *		(hours, minutes)
 *	5	Initialization status:
 *		0 = Waiting for initialization parameters
 *		1 = Initialization completed
 *
 * A typical message looks like this.  Checksum has already been stripped.
 *
 * $PMVXG,004,C,R,D,H.HH,V.VV,TT,HHHH,VVVV,T
 *
 *	Field	Field Contents
 *	-----	--------------
 *		Block Label: $PMVXG
 *		Sentence Type: 004=Software Configuration.
 *			Defines the navigation mode and criteria for
 *			acceptable navigation for the receiver.
 *	1	Constrain Altitude Mode:
 *		0 = Auto.  Constrain altitude (2-D solution) and use
 *		    manual altitude input when 3 sats avalable.  Do
 *		    not constrain altitude (3-D solution) when 4 sats
 *		    available.
 *		1 = Always constrain altitude (2-D solution).
 *		2 = Never constrain altitude (3-D solution).
 *		3 = Coast.  Constrain altitude (2-D solution) and use
 *		    last GPS altitude calculation when 3 sats avalable.
 *		    Do not constrain altitude (3-D solution) when 4 sats
 *		    available.
 *	2	Altitude Reference: (always 0 for MX4200)
 *		0 = Ellipsoid
 *		1 = Geoid (MSL)
 *	3	Differential Navigation Control:
 *		0 = Disabled
 *		1 = Enabled
 *	4	Horizontal Acceleration Constant (m/sec**2)
 *	5	Vertical Acceleration Constant (m/sec**2) (0 for MX4200)
 *	6	Tracking Elevation Limit (degrees)
 *	7	HDOP Limit
 *	8	VDOP Limit
 *	9	Time Output Mode:
 *		U = UTC
 *		L = Local time
 *	10	Local Time Offset (minutes) (absent on MX4200)
 *
 * A typical message looks like this.  Checksum has already been stripped.
 *
 * $PMVXG,030,NNNN,FFF
 *
 *	Field	Field Contents
 *	-----	--------------
 *		Block Label: $PMVXG
 *		Sentence Type: 030=Software Configuration.
 *			This sentence contains the navigation processor
 *			and baseband firmware version numbers.
 *	1	Nav Processor Version Number
 *	2	Baseband Firmware Version Number
 *
 * A typical message looks like this.  Checksum has already been stripped.
 *
 * $PMVXG,523,M,S,M,EEEE,BBBBBB,C,R
 *
 *	Field	Field Contents
 *	-----	--------------
 *		Block Label: $PMVXG
 *		Sentence Type: 523=Time Recovery Parameters Currently in Use.
 *			This sentence contains the configuration of the
 *			time recovery feature of the receiver.
 *	1	Time Recovery Mode:
 *		D = Dynamic; solve for position and time while moving
 *		S = Static; solve for position and time while stationary
 *		K = Known position input, solve for time only
 *		N = No time recovery
 *	2	Time Synchronization:
 *		U = UTC time
 *		G = GPS time
 *	3	Time Mark Mode:
 *		A = Always output a time pulse
 *		V = Only output time pulse if time is valid (as determined
 *		    by Maximum Time Error)
 *	4	Maximum Time Error - the maximum error (in nanoseconds) for
 *		which a time mark will be considered valid.
 *	5	User Time Bias - external bias in nanoseconds
 *	6	Time Message Control:
 *		0 = Do not output the time recovery message
 *		1 = Output the time recovery message (record 830) to
 *		    Control port
 *		2 = Output the time recovery message (record 830) to
 *		    Equipment port
 *	7	Reserved
 *	8	Position Known PRN (absent on MX 4200)
 *
 */
static char *
mx4200_parse_s(peer)
	struct peer *peer;
{
	struct refclockproc *pp;
	struct mx4200unit *up;
	int sentence_type;
	char *cp;

	pp = peer->procptr;
	up = (struct mx4200unit *)pp->unitptr;

	cp = pp->a_lastcode;

	if ((cp = strchr(cp, ',')) == NULL)
		return ("no rec-type");
	cp++;

	/* Sentence type */
	sentence_type = strtol(cp, &cp, 10);
	if (sentence_type != PMVXG_D_STATUS &&
	    sentence_type != PMVXG_D_MODEDATA &&
	    sentence_type != PMVXG_D_SOFTCONF &&
	    sentence_type != PMVXG_D_TRECOVUSEAGE )
		return ("wrong rec-type");
	cp++;

	/* Log the Status */
	if (sentence_type == PMVXG_D_STATUS) {
		msyslog(LOG_DEBUG,
		"mx4200_parse_s: status: %s", cp);
	}

	/* Log the Mode Data */
	if (sentence_type == PMVXG_D_MODEDATA) {
		msyslog(LOG_DEBUG,
		"mx4200_parse_s: mode data: %s", cp);
	}

	/* Log the Software Version */
	if (sentence_type == PMVXG_D_SOFTCONF) {
		msyslog(LOG_DEBUG,
		"mx4200_parse_s: firmware configuration: %s", cp);
	}

	/* Log the Time Recovery Parameters */
	if (sentence_type == PMVXG_D_TRECOVUSEAGE) {
		msyslog(LOG_DEBUG,
		"mx4200_parse_s: time recovery parms: %s", cp);
	}

	return (NULL);
}

/*
 * Process a PPS signal, returning a timestamp.
 */
static int
mx4200_pps(peer)
	struct peer *peer;
{
#ifdef PPS
	struct refclockproc *pp;
	struct mx4200unit *up;

	int temp_serial;

	pp = peer->procptr;
	up = (struct mx4200unit *)pp->unitptr;


	/*
	 * Grab the timestamp of the PPS signal.
	 */
	temp_serial = up->ppsev.serial;
	if (ioctl(fdpps, CIOGETEV, (caddr_t)&up->ppsev) < 0) {
		/* XXX Actually, if this fails, we're pretty much screwed */
		mx4200_debug(peer, "mx4200_pps: CIOGETEV: ");
		mx4200_debug(peer, "%s", strerror(errno));
		mx4200_debug(peer, "\n");
		refclock_report(peer, CEVNT_FAULT);
		return(1);
	}
	if (temp_serial == up->ppsev.serial) {
		mx4200_debug(peer,
			"mx4200_pps: ppsev serial not incrementing: %d\n",
				up->ppsev.serial);
		refclock_report(peer, CEVNT_FAULT);
		return(1);
	}

	/*
	 * Check pps serial number against last one
	 */
	if (up->lastserial + 1 != up->ppsev.serial && up->lastserial != 0) {
		if (up->ppsev.serial == up->lastserial)
			mx4200_debug(peer, "mx4200_pps: no new pps event\n");
		else
			mx4200_debug(peer, "mx4200_pps: missed %d pps events\n",
				up->ppsev.serial - up->lastserial - 1);
		refclock_report(peer, CEVNT_FAULT);
	}
	up->lastserial = up->ppsev.serial;

	/*
	 * Return the timestamp in pp->lastrec
	 */
	up->ppsev.tv.tv_sec += (u_int32) JAN_1970;
	TVTOTS(&up->ppsev.tv,&pp->lastrec);

#endif /* PPS */

	return(0);
}

/*
 * mx4200_debug - print debug messages
 */
#if __STDC__
static void
mx4200_debug(struct peer *peer, char *fmt, ...)
#else
static void
mx4200_debug(peer, fmt, va_alist)
	struct peer *peer;
	char *fmt;
#endif
{
	va_list ap;
	struct refclockproc *pp;
	struct mx4200unit *up;

	if (debug) {

#if __STDC__
		va_start(ap, fmt);
#else
		va_start(ap);
#endif

		pp = peer->procptr;
		up = (struct mx4200unit *)pp->unitptr;


		/*
		 * Print debug message to stdout
		 * In the future, we may want to get get more creative...
		 */
		vprintf(fmt, ap);

		va_end(ap);
	}
}

/*
 * Send a character string to the receiver.  Checksum is appended here.
 */
static void
#if __STDC__
mx4200_send(struct peer *peer, char *fmt, ...)
#else
mx4200_send(peer, fmt, va_alist)
	struct peer *peer;
	char *fmt;
	va_dcl
#endif /* __STDC__ */
{
	struct refclockproc *pp;
	struct mx4200unit *up;

	register char *cp;
	register int n, m;
	va_list ap;
	char buf[1024];
	u_char ck;

#if __STDC__
	va_start(ap, fmt);
#else
	va_start(ap);
#endif /* __STDC__ */

	pp = peer->procptr;
	up = (struct mx4200unit *)pp->unitptr;

	cp = buf;
	*cp++ = '$';
#ifdef notdef
	/* BSD is rational */
	n = vsnprintf(cp, sizeof(buf) - 1, fmt, ap);
#else
	/* SunOS sucks */
	(void)vsprintf(cp, fmt, ap);
	n = strlen(cp);
#endif /* notdef */
	ck = mx4200_cksum(cp, n);
	cp += n;
	++n;
#ifdef notdef
	/* BSD is rational */
	n += snprintf(cp, sizeof(buf) - n - 5, "*%02X\r\n", ck);
#else
	/* SunOS sucks */
	sprintf(cp, "*%02X\r\n", ck);
	n += strlen(cp);
#endif /* notdef */

	m = write(pp->io.fd, buf, n);
	if (m < 0)
		msyslog(LOG_ERR, "mx4200_send: write: %m (%s)", buf);
	mx4200_debug(peer, "mx4200_send: %d %s\n", m, buf);
	va_end(ap);
}

#else /* not (REFCLOCK && MX4200 && PPS) */
int refclock_mx4200_bs;
#endif /* not (REFCLOCK && MX4200 && PPS) */
