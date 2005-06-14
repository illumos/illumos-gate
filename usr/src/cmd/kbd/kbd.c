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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 *	Usage: kbd [-r] [-t] [-l] [-i] [-c on|off] [-a enable|disable|alternate]
 *		    [-d keyboard device]
 *	-r			reset the keyboard as if power-up
 *	-t			return the type of the keyboard being used
 *	-l			return the layout of the keyboard being used,
 *				and the Autorepeat settings
 *	-i			read in the default configuration file
 *	-c on|off		turn on|off clicking
 *	-a enable|disable|alternate	sets abort sequence
 *	-D autorepeat delay	sets autorepeat dealy, unit in ms
 *	-R autorepeat rate	sets autorepeat rate, unit in ms
 *	-d keyboard device	chooses the kbd device, default /dev/kbd.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/kbio.h>
#include <sys/kbd.h>
#include <stdio.h>
#include <fcntl.h>
#include <deflt.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stropts.h>

#define	KBD_DEVICE	"/dev/kbd"		/* default keyboard device */
#define	DEF_FILE	"/etc/default/kbd"	/* kbd defaults file	*/
#define	DEF_ABORT	"KEYBOARD_ABORT="
#define	DEF_CLICK	"KEYCLICK="
#define	DEF_RPTDELAY	"REPEAT_DELAY="
#define	DEF_RPTRATE	"REPEAT_RATE="

static void reset(int);
static void get_type(int);
static void get_layout(int);
static void kbd_defaults(int);
static void usage(void);

static int click(char *, int);
static int abort_enable(char *, int);
static int set_repeat_delay(char *, int);
static int set_repeat_rate(char *, int);

int
main(int argc, char **argv)
{
	int c, error;
	int rflag, tflag, lflag, cflag, dflag, aflag, iflag, errflag,
	    Dflag, Rflag, rtlacDRflag;
	char *copt, *aopt, *delay, *rate;
	char *kbdname = KBD_DEVICE;
	int kbd;
	extern char *optarg;
	extern int optind;

	rflag = tflag = cflag = dflag = aflag = iflag = errflag = lflag =
	    Dflag = Rflag = 0;
	copt = aopt = (char *)0;

	while ((c = getopt(argc, argv, "rtlic:a:d:D:R:")) != EOF) {
		switch (c) {
		case 'r':
			rflag++;
			break;
		case 't':
			tflag++;
			break;
		case 'l':
			lflag++;
			break;
		case 'i':
			iflag++;
			break;
		case 'c':
			copt = optarg;
			cflag++;
			break;
		case 'a':
			aopt = optarg;
			aflag++;
			break;
		case 'd':
			kbdname = optarg;
			dflag++;
			break;
		case 'D':
			delay = optarg;
			Dflag++;
			break;
		case 'R':
			rate = optarg;
			Rflag++;
			break;
		case '?':
			errflag++;
			break;
		}
	}

	/*
	 * Check for valid arguments:
	 *
	 * If argument parsing failed or if there are left-over
	 * command line arguments, then we're done now.
	 */
	if (errflag != 0 || argc != optind) {
		usage();
		exit(1);
	}
	/*
	 * kbd requires that the user specify either "-i" or at least one of
	 * -[rtlacDR].  The "-d" option is, well, optional.  We don't
	 * care if it's there or not.
	 */
	rtlacDRflag = rflag + tflag + lflag + aflag + cflag + Dflag + Rflag;
	if ((iflag != 0 && rtlacDRflag != 0) ||
	    (iflag == 0 && rtlacDRflag == 0)) {
		usage();
		exit(1);
	}

	if (Dflag && atoi(delay) <= 0) {
		(void) fprintf(stderr, "Invalid arguments: -D %s\n", delay);
		usage();
		exit(1);
	}

	if (Rflag && atoi(rate) <= 0) {
		(void) fprintf(stderr, "Invalid arguments: -R %s\n", rate);
		usage();
		exit(1);
	}

	/*
	 * Open the keyboard device
	 */
	if ((kbd = open(kbdname, O_RDWR)) < 0) {
		perror("opening the keyboard");
		(void) fprintf(stderr, "kbd: Cannot open %s\n", kbdname);
		exit(1);
	}

	if (iflag) {
		kbd_defaults(kbd);
		exit(0);	/* A mutually exclusive option */
		/*NOTREACHED*/
	}

	if (tflag)
		get_type(kbd);

	if (lflag)
		get_layout(kbd);

	if (cflag && (error = click(copt, kbd)) != 0)
		exit(error);

	if (rflag)
		reset(kbd);

	if (aflag && (error = abort_enable(aopt, kbd)) != 0)
		exit(error);

	if (Dflag && (error = set_repeat_delay(delay, kbd)) != 0)
		exit(error);

	if (Rflag && (error = set_repeat_rate(rate, kbd)) != 0)
		exit(error);

	return (0);
}

/*
 * this routine resets the state of the keyboard as if power-up
 */
static void
reset(int kbd)
{
	int cmd;

	cmd = KBD_CMD_RESET;

	if (ioctl(kbd, KIOCCMD, &cmd)) {
		perror("kbd: ioctl error");
		exit(1);
	}

}

/*
 * this routine gets the type of the keyboard being used
 */
static void
get_type(int kbd)
{
	int kbd_type;

	if (ioctl(kbd, KIOCTYPE, &kbd_type)) {
		perror("ioctl (kbd type)");
		exit(1);
	}

	switch (kbd_type) {

	case KB_SUN3:
		(void) printf("Type 3 Sun keyboard\n");
		break;

	case KB_SUN4:
		(void) printf("Type 4 Sun keyboard\n");
		break;

	case KB_ASCII:
		(void) printf("ASCII\n");
		break;

	case KB_PC:
		(void) printf("PC\n");
		break;

	case KB_USB:
		(void) printf("USB keyboard\n");
		break;

	default:
		(void) printf("Unknown keyboard type\n");
		break;
	}
}

/*
 * this routine gets the layout of the keyboard being used
 * also, included the autorepeat delay and rate being used
 */
static void
get_layout(int kbd)
{
	int kbd_type;
	int kbd_layout;
	/* these two variables are used for getting delay&rate */
	int delay, rate;
	delay = rate = 0;

	if (ioctl(kbd, KIOCTYPE, &kbd_type)) {
		perror("ioctl (kbd type)");
		exit(1);
	}

	if (ioctl(kbd, KIOCLAYOUT, &kbd_layout)) {
		perror("ioctl (kbd layout)");
		exit(1);
	}

	(void) printf("type=%d\nlayout=%d (0x%.2x)\n",
	    kbd_type, kbd_layout, kbd_layout);

	/* below code is used to get the autorepeat delay and rate */
	if (ioctl(kbd, KIOCGRPTDELAY, &delay)) {
		perror("ioctl (kbd get repeat delay)");
		exit(1);
	}

	if (ioctl(kbd, KIOCGRPTRATE, &rate)) {
		perror("ioctl (kbd get repeat rate)");
		exit(1);
	}

	(void) printf("delay(ms)=%d\n", delay);
	(void) printf("rate(ms)=%d\n", rate);
}

/*
 * this routine enables or disables clicking of the keyboard
 */
static int
click(char *copt, int kbd)
{
	int cmd;

	if (strcmp(copt, "on") == 0)
		cmd = KBD_CMD_CLICK;
	else if (strcmp(copt, "off") == 0)
		cmd = KBD_CMD_NOCLICK;
	else {
		(void) fprintf(stderr, "wrong option -- %s\n", copt);
		usage();
		return (1);
	}

	if (ioctl(kbd, KIOCCMD, &cmd)) {
		perror("kbd ioctl (keyclick)");
		return (1);
	}
	return (0);
}

/*
 * this routine enables/disables/sets BRK or abort sequence feature
 */
static int
abort_enable(char *aopt, int kbd)
{
	int enable;

	if (strcmp(aopt, "alternate") == 0)
		enable = KIOCABORTALTERNATE;
	else if (strcmp(aopt, "enable") == 0)
		enable = KIOCABORTENABLE;
	else if (strcmp(aopt, "disable") == 0)
		enable = KIOCABORTDISABLE;
	else {
		(void) fprintf(stderr, "wrong option -- %s\n", aopt);
		usage();
		return (1);
	}

	if (ioctl(kbd, KIOCSKABORTEN, &enable)) {
		perror("kbd ioctl (abort enable)");
		return (1);
	}
	return (0);
}

/*
 * this routine set autorepeat delay
 */
static int
set_repeat_delay(char *delay_str, int kbd)
{
	int delay = atoi(delay_str);

	/*
	 * The error message depends on the different inputs.
	 * a. the input is a invalid integer(unit in ms)
	 * b. the input is a integer less than the minimal delay setting.
	 * The condition (a) has been covered by main function and set_default
	 * function.
	 */
	if (ioctl(kbd, KIOCSRPTDELAY, &delay) == -1) {
		if (delay < KIOCRPTDELAY_MIN)
			(void) fprintf(stderr, "kbd: specified delay %d is "
			    "less than minimum %d\n", delay, KIOCRPTDELAY_MIN);
		else
			perror("kbd: set repeat delay");
		return (1);
	}

	return (0);
}

/*
 * this routine set autorepeat rate
 */
static int
set_repeat_rate(char *rate_str, int kbd)
{
	int rate = atoi(rate_str);

	/*
	 * The error message depends on the different inputs.
	 * a. the input is a invalid integer(unit in ms)
	 * b. the input is a integer less than the minimal rate setting.
	 * The condition (a) has been covered by main function and set_default
	 * function.
	 */
	if (ioctl(kbd, KIOCSRPTRATE, &rate) == -1) {
		if (rate < KIOCRPTRATE_MIN)
			(void) fprintf(stderr, "kbd: specified rate %d is "
			    "less than minimum %d\n", rate, KIOCRPTRATE_MIN);
		else
			perror("kbd: set repeat rate");
		return (1);
	}

	return (0);
}

#define	BAD_DEFAULT	"kbd: bad default value for %s: %s\n"

static void
kbd_defaults(int kbd)
{
	char *p;

	if (defopen(DEF_FILE) != 0) {
		(void) fprintf(stderr, "Can't open default file: %s\n",
		    DEF_FILE);
		exit(1);
	}

	p = defread(DEF_CLICK);
	if (p != NULL) {
		/*
		 * KEYCLICK must equal "on" or "off"
		 */
		if ((strcmp(p, "on") == 0) || (strcmp(p, "off") == 0))
			(void) click(p, kbd);
		else
			(void) fprintf(stderr, BAD_DEFAULT, DEF_CLICK, p);
	}

	p = defread(DEF_ABORT);
	if (p != NULL) {
		/*
		 * ABORT must equal "enable", "disable" or "alternate"
		 */
		if ((strcmp(p, "enable") == 0) ||
		    (strcmp(p, "alternate") == 0) ||
		    (strcmp(p, "disable") == 0))
			(void) abort_enable(p, kbd);
		else
			(void) fprintf(stderr, BAD_DEFAULT, DEF_ABORT, p);
	}

	p = defread(DEF_RPTDELAY);
	if (p != NULL) {
		/*
		 * REPEAT_DELAY unit in ms
		 */
		if (atoi(p) > 0)
			(void) set_repeat_delay(p, kbd);
		else
			(void) fprintf(stderr, BAD_DEFAULT, DEF_RPTDELAY, p);
	}

	p = defread(DEF_RPTRATE);
	if (p != NULL) {
		/*
		 * REPEAT_RATE unit in ms
		 */
		if (atoi(p) > 0)
			(void) set_repeat_rate(p, kbd);
		else
			(void) fprintf(stderr, BAD_DEFAULT, DEF_RPTRATE, p);
	}
}

static char *usage1 = "kbd [-r] [-t] [-l] [-a enable|disable|alternate]";
static char *usage2 = "    [-c on|off][-D delay][-R rate][-d keyboard device]";
static char *usage3 = "kbd -i [-d keyboard device]";

static void
usage(void)
{
	(void) fprintf(stderr, "Usage:\t%s\n\t%s\n\t%s\n", usage1, usage2,
	    usage3);
}
