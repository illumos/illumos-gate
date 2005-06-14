/*
 * Copyright 1996, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ntp_util.c - stuff I didn't have any other place for
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
# ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
# endif
# include <sys/time.h>

#include "ntpd.h"
#include "ntp_io.h"
#include "ntp_unixtime.h"
#include "ntp_filegen.h"
#include "ntp_if.h"
#include "ntp_stdlib.h"

#ifdef  DOSYNCTODR
#if !defined(VMS)
#include <sys/resource.h>
#endif /* VMS */
#endif

#if defined(VMS)
#include <descrip.h>
#endif /* VMS */

/*
 * This contains odds and ends.  Right now the only thing you'll find
 * in here is the hourly stats printer and some code to support rereading
 * the keys file, but I may eventually put other things in here such as
 * code to do something with the leap bits.
 */

/*
 * Name of the keys file
 */
static	char *key_file_name;

/*
 * The name of the drift_comp file and the temporary.
 */
static	char *stats_drift_file;
static	char *stats_temp_file;

extern	l_fp	zero_drift;

/*
 * Statistics file stuff
 */
#ifndef NTP_VAR
#ifndef SYS_WINNT
#define NTP_VAR "/var/NTP/"		/* NOTE the trailing '/' */
#else
#define NTP_VAR "c:\\var\\ntp\\"		/* NOTE the trailing '\\' */
#endif /* SYS_WINNT */
#endif

#ifndef MAXPATHLEN
#define MAXPATHLEN 256
#endif

static	char statsdir[MAXPATHLEN] = NTP_VAR;

static FILEGEN peerstats;
static FILEGEN loopstats;
static FILEGEN clockstats;
static FILEGEN rawstats;

/*
 * We query the errno to see what kind of error occured
 * when opening the drift file.
 */
#ifndef SYS_WINNT
extern int errno;
#endif /* SYS_WINNT */

/*
 * This controls whether stats are written to the fileset. Provided
 * so that xntpdc can turn off stats when the file system fills up. 
 */
int stats_control;

#ifdef DEBUG
extern int debug;
#endif

/*
 * init_util - initialize the utilities
 */
void
init_util()
{
	stats_drift_file = 0;
	stats_temp_file = 0;
	key_file_name = 0;

#define PEERNAME "peerstats"
#define LOOPNAME "loopstats"
#define CLOCKNAME "clockstats"
#define RAWNAME "rawstats"
	peerstats.fp       = NULL;
	peerstats.prefix   = &statsdir[0];
	peerstats.basename = emalloc(strlen(PEERNAME)+1);
	strcpy(peerstats.basename, PEERNAME);
	peerstats.id       = 0;
	peerstats.type     = FILEGEN_DAY;
	peerstats.flag     = FGEN_FLAG_LINK; /* not yet enabled !!*/
	filegen_register("peerstats", &peerstats);
	
	loopstats.fp       = NULL;
	loopstats.prefix   = &statsdir[0];
	loopstats.basename = emalloc(strlen(LOOPNAME)+1);
	strcpy(loopstats.basename, LOOPNAME);
	loopstats.id       = 0;
	loopstats.type     = FILEGEN_DAY;
	loopstats.flag     = FGEN_FLAG_LINK; /* not yet enabled !!*/
	filegen_register("loopstats", &loopstats);

	clockstats.fp      = NULL;
	clockstats.prefix  = &statsdir[0];
	clockstats.basename = emalloc(strlen(CLOCKNAME)+1);
	strcpy(clockstats.basename, CLOCKNAME);
	clockstats.id      = 0;
	clockstats.type    = FILEGEN_DAY;
	clockstats.flag    = FGEN_FLAG_LINK; /* not yet enabled !!*/
	filegen_register("clockstats", &clockstats);

	rawstats.fp      = NULL;
	rawstats.prefix  = &statsdir[0];
	rawstats.basename = emalloc(strlen(RAWNAME)+1);
	strcpy(rawstats.basename, RAWNAME);
	rawstats.id      = 0;
	rawstats.type    = FILEGEN_DAY;
	rawstats.flag    = FGEN_FLAG_LINK; /* not yet enabled !!*/
	filegen_register("rawstats", &rawstats);

#undef PEERNAME
#undef LOOPNAME
#undef CLOCKNAME
#undef RAWNAME

}


/*
 * hourly_stats - print some interesting stats
 */
void
hourly_stats()
{
	FILE *fp;
	extern l_fp last_offset;
	extern s_fp drift_comp;
	extern u_char sys_poll;

#ifdef DOSYNCTODR
	struct timeval tv;
#ifdef HAVE_GETCLOCK
        struct timespec ts;
#endif
	int o_prio;

	/*
	 * Sometimes having a Sun can be a drag.
	 *
	 * The kernel variable dosynctodr controls whether the system's
	 * soft clock is kept in sync with the battery clock. If it
	 * is zero, then the soft clock is not synced, and the battery
	 * clock is simply left to rot. That means that when the system
	 * reboots, the battery clock (which has probably gone wacky)
	 * sets the soft clock. That means xntpd starts off with a very
	 * confused idea of what time it is. It then takes a large
	 * amount of time to figure out just how wacky the battery clock
	 * has made things drift, etc, etc. The solution is to make the
	 * battery clock sync up to system time. The way to do THAT is
	 * to simply set the time of day to the current time of day, but
	 * as quickly as possible. This may, or may not be a sensible
	 * thing to do.
	 *
	 * CAVEAT: settimeofday() steps the sun clock by about 800 us,
	 *         so setting DOSYNCTODR seems a bad idea in the
	 *         case of us resolution
	 */

#if !defined(VMS)
	o_prio=getpriority(PRIO_PROCESS,0); /* Save setting */
	if (setpriority(PRIO_PROCESS,0,-20) != 0) /* overdrive */
	{
		msyslog(LOG_ERR, "can't elevate priority: %m");
		goto skip;
	}
#endif /* VMS */
#ifdef HAVE_GETCLOCK
        (void) getclock(TIMEOFDAY, &ts);
        tv.tv_sec = ts.tv_sec;
        tv.tv_usec = ts.tv_nsec / 1000;
#else /*  not HAVE_GETCLOCK */
	GETTIMEOFDAY(&tv,(struct timezone *)NULL);
#endif /* not HAVE_GETCLOCK */
	if (SETTIMEOFDAY(&tv,(struct timezone *)NULL) != 0)
	{
		msyslog(LOG_ERR, "can't sync battery time: %m");
	}
#if !defined(VMS)
	setpriority(PRIO_PROCESS,0,o_prio); /* downshift */
#endif /* VMS */

 skip:
#endif /* DOSYNCTODR */

	NLOG(NLOG_SYSSTATIST)
	  msyslog(LOG_INFO, "offset %s sec freq %s ppm poll %d",
		 lfptoa(&last_offset, 6), fptoa(drift_comp, 3),
		 sys_poll);
	
	if (stats_drift_file != 0) {
		if ((fp = fopen(stats_temp_file, "w")) == NULL) {
			msyslog(LOG_ERR, "can't open %s: %m",
			    stats_temp_file);
			return;
		}
		fprintf(fp, "%s\n", fptoa(drift_comp, 3));
		(void)fclose(fp);
		/* atomic */
#ifdef SYS_WINNT
		(void) unlink(stats_drift_file); /* rename semantics differ under NT */
#endif /* SYS_WINNT */

#ifndef NO_RENAME
		(void) rename(stats_temp_file, stats_drift_file);
#else
        /* we have no rename NFS of ftp in use*/
		if ((fp = fopen(stats_drift_file, "w")) == NULL) {
			msyslog(LOG_ERR, "can't open %s: %m",
			    stats_drift_file);
			return;
		}

#endif

#if defined(VMS)
		/* PURGE */
		{
			$DESCRIPTOR(oldvers,";-1");
			struct dsc$descriptor driftdsc = {
				strlen(stats_drift_file),0,0,stats_drift_file };

			while(lib$delete_file(&oldvers,&driftdsc) & 1) ;
		}
#endif
	}
}


/*
 * stats_config - configure the stats operation
 */
void
stats_config(item, invalue)
	int item;
	char *invalue;	/* only one type so far */
{
	FILE *fp;
	char buf[128], *value;
	l_fp old_drift;
	int len;

	/* Expand environment strings under Windows NT, since the command
	 * interpreter doesn't do this, the program must.
	 */
#ifdef SYS_WINNT
	char newvalue[MAX_PATH], parameter[MAX_PATH];

	if (!ExpandEnvironmentStrings(invalue, newvalue, MAX_PATH))
    {
 		switch(item) {
		case STATS_FREQ_FILE:
			strcpy(parameter,"STATS_FREQ_FILE");
			break;
		case STATS_STATSDIR:
			strcpy(parameter,"STATS_STATSDIR");
			break;
		case STATS_PID_FILE:
			strcpy(parameter,"STATS_PID_FILE");
			break;
		default:
			strcpy(parameter,"UNKNOWN");
			break;
		}
		value = invalue;

	    msyslog(LOG_ERR, "ExpandEnvironmentStrings(%s) failed: %m\n", parameter);
	}
	else 
	{
		value = newvalue;
	}

#else    
	value = invalue;
#endif /* SYS_WINNT */

	
	
	switch(item) {
	case STATS_FREQ_FILE:
		if (stats_drift_file != 0) {
			(void) free(stats_drift_file);
			(void) free(stats_temp_file);
			stats_drift_file = 0;
			stats_temp_file = 0;
		}

		if (value == 0 || (len = strlen(value)) == 0)
			break;

		/*
		 * To avoid using the (possibly disruptive) stored
		 * drift value in the case where pll is disabled.
		 */
		if (strncmp(value, "IGNORE", len) == 0) {
		        loop_config(LOOP_DRIFTCOMP, &zero_drift);

			msyslog(LOG_WARNING, "phase-lock loop disabled: "
			    "will *not* use clock drift file.");
			break;
		}

		stats_drift_file = emalloc((u_int)(len + 1));
#if !defined(VMS)
		stats_temp_file = emalloc((u_int)(len + sizeof(".TEMP")));
#else
		stats_temp_file = emalloc((u_int)(len + sizeof("-TEMP")));
#endif /* VMS */
		memmove(stats_drift_file, value, len+1);
		memmove(stats_temp_file, value, len);
#if !defined(VMS)
		memmove(stats_temp_file + len, ".TEMP", sizeof(".TEMP"));
#else
		memmove(stats_temp_file + len, "-TEMP", sizeof("-TEMP"));
#endif /* VMS */
		L_CLR(&old_drift);

		/*
		 * Open drift file and read frequency and mode.
		 */
		if ((fp = fopen(stats_drift_file, "r")) == NULL) {
			if (errno != ENOENT)
				msyslog(LOG_ERR, "can't open %s: %m",
				       stats_drift_file);
		        loop_config(LOOP_DRIFTCOMP, &old_drift);
			break;
		}

		strcpy(buf, "0");
		if (fgets(buf, sizeof(buf)-2, fp) == 0 && ferror(fp)) {
			msyslog(LOG_ERR, "can't read %s: %m",
			       stats_drift_file);
			(void) fclose(fp);
		        loop_config(LOOP_DRIFTCOMP, &old_drift);
			break;
		}
		(void) fclose(fp);
		if (!atolfp(buf, &old_drift)) {
			msyslog(LOG_ERR, "drift value '%s' from %s invalid", 
				buf, stats_drift_file);
			loop_config(LOOP_DRIFTCOMP, &old_drift);
			break;
		}
		{
		  char *cp = strchr(buf, (int)'\n');

		  if (cp)
		    *cp = '\0';
		}
		msyslog(LOG_INFO, "read drift of %s from %s", buf, stats_drift_file);
#ifdef DEBUG
		if (debug > 0) {
			printf("read drift of %s from %s\n", buf, stats_drift_file);
		}
#endif
		loop_config(LOOP_DRIFTCOMP, &old_drift);
		break;
	
	case STATS_STATSDIR:
		if (strlen(value) >= sizeof(statsdir)) {
			msyslog(LOG_ERR,
			       "value for statsdir too long (>%d, sigh)",
			       sizeof(statsdir)-1);
		} else {
			l_fp now;

			get_systime(&now);
			strcpy(statsdir,value);
			if(peerstats.prefix == &statsdir[0] &&
			   peerstats.fp != NULL) {
				fclose(peerstats.fp);
				peerstats.fp = NULL;
				filegen_setup(&peerstats, now.l_ui);
			}
			if(loopstats.prefix == &statsdir[0] &&
			   loopstats.fp != NULL) {
				fclose(loopstats.fp);
				loopstats.fp = NULL;
				filegen_setup(&loopstats, now.l_ui);
			}
			if(clockstats.prefix == &statsdir[0] &&
			   clockstats.fp != NULL) {
				fclose(clockstats.fp);
				clockstats.fp = NULL;
				filegen_setup(&clockstats, now.l_ui);
			}
			if(rawstats.prefix == &statsdir[0] &&
			   rawstats.fp != NULL) {
				fclose(rawstats.fp);
				rawstats.fp = NULL;
				filegen_setup(&rawstats, now.l_ui);
			}
		}
		break;

	case STATS_PID_FILE:
		if ((fp = fopen(value, "w")) == NULL) {
			msyslog(LOG_ERR, "Can't open %s: %m", value);
			break;
		}
		fprintf(fp, "%d", (int) getpid());
		fclose(fp);;
		break;

	default:
		/* oh well */
		break;
	}
}

/*
 * record_peer_stats - write peer statistics to file
 *
 * file format:
 * day (mjd)
 * time (s past UTC midnight)
 * peer (ip address)
 * peer status word (hex)
 * peer offset (s)
 * peer delay (s)
 * peer dispersion (s)
 */
void
record_peer_stats(addr, status, offset, delay, dispersion)
	struct sockaddr_in *addr;
	int status;
	l_fp *offset;
	s_fp delay;
	u_fp dispersion;
{
	struct timeval tv;
#ifdef HAVE_GETCLOCK
        struct timespec ts;
#endif
	u_long day, sec, msec;

	if (!stats_control)
		return;
#ifdef HAVE_GETCLOCK
        (void) getclock(TIMEOFDAY, &ts);
        tv.tv_sec = ts.tv_sec;
        tv.tv_usec = ts.tv_nsec / 1000;
#else /*  not HAVE_GETCLOCK */
	GETTIMEOFDAY(&tv, (struct timezone *)NULL);
#endif /* not HAVE_GETCLOCK */
	day = tv.tv_sec / 86400 + MJD_1970;
	sec = tv.tv_sec % 86400;
	msec = tv.tv_usec / 1000;

	filegen_setup(&peerstats, (u_long)(tv.tv_sec + JAN_1970));
	if (peerstats.fp != NULL) {
		fprintf(peerstats.fp, "%lu %lu.%03lu %s %x %s %s %s\n",
			day, sec, msec, ntoa(addr), status, lfptoa(offset, 6),
			fptoa(delay, 5), ufptoa(dispersion, 5));
		fflush(peerstats.fp);
	}
}
/*
 * record_loop_stats - write loop filter statistics to file
 *
 * file format:
 * day (mjd)
 * time (s past midnight)
 * offset (s)
 * frequency (approx ppm)
 * time constant (log base 2)
 */
void
record_loop_stats(offset, freq, poll)
     l_fp *offset;
     s_fp freq;
     unsigned poll;
{
	struct timeval tv;
#ifdef HAVE_GETCLOCK
        struct timespec ts;
#endif
	u_long day, sec, msec;

	if (!stats_control)
		return;
#ifdef HAVE_GETCLOCK
        (void) getclock(TIMEOFDAY, &ts);
        tv.tv_sec = ts.tv_sec;
        tv.tv_usec = ts.tv_nsec / 1000;
#else /*  not HAVE_GETCLOCK */
	GETTIMEOFDAY(&tv, (struct timezone *)NULL);
#endif /* not HAVE_GETCLOCK */
	day = tv.tv_sec / 86400 + MJD_1970;
	sec = tv.tv_sec % 86400;
	msec = tv.tv_usec / 1000;

	filegen_setup(&loopstats, (u_long)(tv.tv_sec + JAN_1970));
	if (loopstats.fp != NULL) {
		fprintf(loopstats.fp, "%lu %lu.%03lu %s %s %d\n",
			day, sec, msec, lfptoa(offset, 6),
			fptoa(freq, 4), poll);
		fflush(loopstats.fp);
	}
}

/*
 * record_clock_stats - write clock statistics to file
 *
 * file format:
 * day (mjd)
 * time (s past midnight)
 * peer (ip address)
 * text message
 */
void
record_clock_stats(addr, text)
	struct sockaddr_in *addr;
	char *text;
{
	struct timeval tv;
#ifdef HAVE_GETCLOCK
        struct timespec ts;
#endif
	u_long day, sec, msec;

	if (!stats_control)
		return;
#ifdef HAVE_GETCLOCK
        (void) getclock(TIMEOFDAY, &ts);
        tv.tv_sec = ts.tv_sec;
        tv.tv_usec = ts.tv_nsec / 1000;
#else /*  not HAVE_GETCLOCK */
	GETTIMEOFDAY(&tv, (struct timezone *)NULL);
#endif /* not HAVE_GETCLOCK */
	day = tv.tv_sec / 86400 + MJD_1970;
	sec = tv.tv_sec % 86400;
	msec = tv.tv_usec / 1000;

	filegen_setup(&clockstats, (u_long)(tv.tv_sec + JAN_1970));
	if (clockstats.fp != NULL) {
		fprintf(clockstats.fp, "%lu %lu.%03lu %s %s\n",
		    day, sec, msec, ntoa(addr), text);
		fflush(clockstats.fp);
	}
}

/*
 * record_raw_stats - write raw timestamps to file
 *
 *
 * file format
 * time (s past midnight)
 * peer ip address
 * local ip address
 * t1 t2 t3 t4 timestamps
 */
void
record_raw_stats(srcadr, dstadr, t1, t2, t3, t4)
        struct sockaddr_in *srcadr, *dstadr;
	l_fp *t1, *t2, *t3, *t4;
{
	struct timeval tv;
#ifdef HAVE_GETCLOCK
        struct timespec ts;
#endif
	u_long day, sec, msec;

	if (!stats_control)
		return;
#ifdef HAVE_GETCLOCK
        (void) getclock(TIMEOFDAY, &ts);
        tv.tv_sec = ts.tv_sec;
        tv.tv_usec = ts.tv_nsec / 1000;
#else /*  not HAVE_GETCLOCK */
	GETTIMEOFDAY(&tv, (struct timezone *)NULL);
#endif /* not HAVE_GETCLOCK */
	day = tv.tv_sec / 86400 + MJD_1970;
	sec = tv.tv_sec % 86400;
	msec = tv.tv_usec / 1000;

	filegen_setup(&rawstats, (u_long)(tv.tv_sec + JAN_1970));
	if (rawstats.fp != NULL) {
                fprintf(rawstats.fp, "%lu %lu.%03lu %s %s %s %s %s %s\n",
		    day, sec, msec, ntoa(srcadr), ntoa(dstadr),
		    ulfptoa(t1, 6), ulfptoa(t2, 6), ulfptoa(t3, 6),
		    ulfptoa(t4, 6));
		fflush(rawstats.fp);
	}
}

/*
 * getauthkeys - read the authentication keys from the specified file
 */
void
getauthkeys(keyfile)
	char *keyfile;
{
	int len;

	len = strlen(keyfile);
	if (len == 0)
		return;
	
	if (key_file_name != 0) {
		if (len > (int)strlen(key_file_name)) {
			(void) free(key_file_name);
			key_file_name = 0;
		}
	}

	if (key_file_name == 0) {
		key_file_name = emalloc((u_int)
#ifndef SYS_WINNT
			(len + 1));
	}
 	memmove(key_file_name, keyfile, len+1);
#else
			(MAXPATHLEN));
	}
    if (!ExpandEnvironmentStrings(keyfile, key_file_name, MAXPATHLEN)) 
    {
		msyslog(LOG_ERR, "ExpandEnvironmentStrings(KEY_FILE) failed: %m\n");
	}
#endif /* SYS_WINNT */

	authreadkeys(key_file_name);
}


/*
 * rereadkeys - read the authentication key file over again.
 */
void
rereadkeys()
{
	if (key_file_name != 0)
		authreadkeys(key_file_name);
}
