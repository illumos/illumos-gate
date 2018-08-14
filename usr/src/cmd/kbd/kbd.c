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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 *	Usage: kbd [-r] [-t] [-l] [-c on|off] [-a enable|disable|alternate]
 *		   [-d keyboard device] [-D autorepeat dealy] [-R autorepeat
 *		   rate]
 *	       kbd [-i] [-d keyboard device]
 *	       kbd -s [language]
 *	       kbd -b [keyboard|console] frequency
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
 *	-s keyboard layout	sets keyboard layout
 *	-b [keyboard| console]	frequency
 *				sets keyboard or console beeper frequency
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
#include <libintl.h>
#include <locale.h>
#include <errno.h>
#include <inttypes.h>
#include <libscf.h>

#define	KBD_DEVICE	"/dev/kbd"		/* default keyboard device */

#define	KBD_LAYOUT_FILE  "/usr/share/lib/keytables/type_6/kbd_layouts"
#define	MAX_LAYOUT_NUM		128
#define	MAX_LINE_SIZE		256
#define	DEFAULT_KBD_LAYOUT	33

#define	KBD_FMRI		"svc:/system/keymap:default"
#define	KBD_PG			"keymap"
#define	KBD_PROP_LAYOUT		"layout"
#define	KBD_PROP_KEYCLICK	"keyclick"
#define	KBD_PROP_KEYBOARD_ABORT	"keyboard_abort"
#define	KBD_PROP_RPTDELAY	"repeat_delay"
#define	KBD_PROP_RPTRATE	"repeat_rate"
#define	KBD_PROP_FREQ		"kbd_beeper_freq"
#define	KBD_PROP_CONSFREQ	"console_beeper_freq"
#define	KBD_MAX_NAME_LEN	1024

char *layout_names[MAX_LAYOUT_NUM];
int layout_numbers[MAX_LAYOUT_NUM];
static int layout_count;
static int default_layout_number = 0;

static void reset(int);
static int get_type(int);
static void get_layout(int);
static void kbd_defaults(int);
static void usage(void);

static int click(char *, int);
static int abort_enable(char *, int);
static int set_repeat_delay(char *, int);
static int set_rptdelay(int, int);
static int set_repeat_rate(char *, int);
static int set_rptrate(int, int);

static int get_layout_number(char *);
static int set_layout(int, int);
static int get_layouts(void);
static int set_kbd_layout(int, char *);
static int set_beep_freq(int, char *, int);

int
main(int argc, char **argv)
{
	int c, error;
	int rflag, tflag, lflag, cflag, dflag, aflag, iflag, errflag,
	    Dflag, Rflag, rtlacDRflag, sflag, bflag;
	char *copt, *aopt, *delay, *rate, *layout_name, *b_type, *freq_str;
	char *kbdname = KBD_DEVICE, *endptr = NULL;
	int kbd, freq_val;
	extern char *optarg;
	extern int optind;

	rflag = tflag = cflag = dflag = aflag = iflag = errflag = lflag =
	    Dflag = Rflag = sflag = bflag = 0;
	copt = aopt = (char *)0;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "rtlisc:a:d:D:R:b:")) != EOF) {
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
		case 's':
			sflag++;
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
		case 'b':
			bflag++;
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
	 * command line arguments(except -s and -b option),
	 * then we're done now.
	 */
	if (errflag != 0 || (sflag == 0 && bflag == 0 && argc != optind)) {
		usage();
		exit(1);
	}

	/*
	 * kbd requires that the user specify either "-i" or "-s" or "-b" or
	 * at least one of -[rtlacDR].  The "-d" option is, well, optional.
	 * We don't care if it's there or not.
	 */
	rtlacDRflag = rflag + tflag + lflag + aflag + cflag + Dflag + Rflag;
	if (!((iflag != 0 && sflag == 0 && bflag == 0 && rtlacDRflag == 0) ||
	    (iflag == 0 && sflag != 0 && bflag == 0 && dflag == 0 &&
	    rtlacDRflag == 0) ||
	    (iflag == 0 && sflag == 0 && bflag == 0 && rtlacDRflag != 0) ||
	    (iflag == 0 && sflag == 0 && bflag != 0 && rtlacDRflag == 0))) {
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
		(void) get_type(kbd);

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

	if (sflag) {
		if (argc == optind) {
			layout_name = NULL;
		} else if (argc == (optind + 1)) {
			layout_name = argv[optind];
		} else {
			usage();
			exit(1);
		}

		if ((error = set_kbd_layout(kbd, layout_name)) != 0)
			exit(error);
	}

	if (bflag) {
		if (argc == optind) {
			b_type = "keyboard";
		} else if (argc == (optind + 1)) {
			b_type = argv[argc - 2];
		} else {
			usage();
			exit(1);
		}

		if (strcmp(b_type, "keyboard") && strcmp(b_type, "console")) {
			usage();
			exit(1);
		}

		freq_str = argv[argc - 1];
		errno = 0;
		freq_val = (int)strtol(freq_str, &endptr, 10);
		if (errno != 0 || endptr[0] != '\0') {
			usage();
			exit(1);
		}

		if (freq_val < 0 || freq_val > INT16_MAX) {
			(void) fprintf(stderr, "Invalid arguments: -b %s\n",
			    freq_str);
			(void) fprintf(stderr, "Frequency range: [0 - %d]\n",
			    INT16_MAX);
			exit(1);
		}

		if ((error = set_beep_freq(kbd, b_type, freq_val)) != 0)
			exit(1);
	}

	return (0);
}

/*
 * this routine gets the type of the keyboard being used
 */
static int
set_kbd_layout(int kbd, char *layout_name)
{
	int layout_num;
	int error = 1;

	/* layout setting is possible only for USB type keyboards */
	if (get_type(kbd) != KB_USB) {
		(void) fprintf(stderr, "The -s option does not apply for this"
		    " keyboard type.\n"
		    "Only USB/PS2 type keyboards support this option.\n");
		return (error);
	}

	/* get the language info from the layouts file */
	if (get_layouts() != 0)
		return (error);

	if (layout_name != NULL) {
		if ((layout_num = get_layout_number(layout_name)) == -1) {
			(void) fprintf(stderr, "%s: unknown layout name\n"
			    "Please refer to 'kbd -s' to get the "
			    "supported layouts.\n", layout_name);
			return (error);
		}
	} else {
			int i, j, print_cnt, input_num;
			boolean_t input_right = B_TRUE;
			boolean_t default_input = B_FALSE;
			char input[8]; /* 8 chars is enough for numbers */

			print_cnt = (layout_count % 2) ?
			    layout_count/2+1 : layout_count/2;

			for (i = 1; i <= print_cnt; i++) {
				(void) printf("%2d. %-30s", i,
				    layout_names[i-1]);
				j = i + print_cnt;
				if (j <= layout_count) {
					(void) printf("%-2d. %-30s\n", j,
					    layout_names[j-1]);
				}
			}
			(void) printf(gettext("\nTo select the keyboard layout,"
			    " enter a number [default %d]:"),
			    default_layout_number+1);

			for (;;) {
				if (input_right == B_FALSE)
					(void) printf(gettext("Invalid input. "
					    "Please input a number "
					    "(1,2,...):"));
				(void) memset(input, 0, 8);
				(void) fflush(stdin);
				(void) fgets(input, 8, stdin);
				if (strlen(input) > 4) {
					input_right = B_FALSE;
					continue;
				}
				if (input[0] == '\n') {
					default_input = B_TRUE;
					break;
				}
				input_right = B_TRUE;
				/* check if the inputs are numbers 0~9 */
				for (i = 0; i < (strlen(input) - 1); i++) {
					if ((input[i] < '0') ||
					    (input[i] > '9')) {
						input_right = B_FALSE;
						break;
					}
				}
				if (input_right == B_FALSE)
					continue;
				input_num = atoi(input);
				if ((input_num > 0) &&
				    (input_num <= layout_count))
					break;
				else
					input_right = B_FALSE;
			}
			if (default_input == B_TRUE)
				layout_num = DEFAULT_KBD_LAYOUT;
			else
				layout_num = layout_numbers[--input_num];
	}

	if ((error = set_layout(kbd, layout_num)) != 0)
		return (error);

	return (0);
}

/*
 * This routine sets keyboard or console beeper frequency
 */
static int
set_beep_freq(int fd, char *type, int freq)
{
	struct freq_request fr_struct;

	if (strcmp(type, "keyboard") == 0)
		fr_struct.type = KBD_BEEP;
	else if (strcmp(type, "console") == 0)
		fr_struct.type = CONSOLE_BEEP;
	else
		return (EINVAL);

	fr_struct.freq = (int16_t)freq;

	return (ioctl(fd, KIOCSETFREQ, &fr_struct));
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
static int
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
	return (kbd_type);
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

static int
set_rptdelay(int delay, int kbd)
{
	/*
	 * The error message depends on the different inputs.
	 * a. the input is a invalid integer(unit in ms)
	 * b. the input is a integer less than the minimal delay setting.
	 * The condition (a) has been covered by main function and kbd_defaults
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
 * this routine set autorepeat delay
 */
static int
set_repeat_delay(char *delay_str, int kbd)
{
	int delay = atoi(delay_str);

	return (set_rptdelay(delay, kbd));
}

static int
set_rptrate(int rate, int kbd)
{
	/*
	 * The input validation check has been covered by main function
	 * and kbd_defaults function.Here just give an error message if
	 * the ioctl fails.
	 */
	if (ioctl(kbd, KIOCSRPTRATE, &rate) == -1) {
		perror("kbd: set repeat rate");
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

	return (set_rptrate(rate, kbd));
}

#define	BAD_DEFAULT_STR		"kbd: bad default value for %s: %s\n"
#define	BAD_DEFAULT_INT		"kbd: bad default value for %s: %d\n"
#define	BAD_DEFAULT_LLINT	"kbd: bad default value for %s: %lld\n"

static void
kbd_defaults(int kbd)
{
	scf_handle_t *h = NULL;
	scf_snapshot_t *snap = NULL;
	scf_instance_t *inst = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *val = NULL;

	int layout_num;
	char *val_layout = NULL, *val_abort = NULL;
	uint8_t val_click;
	int64_t val_delay, val_rate;
	int64_t val_kbd_beeper, val_console_beeper;

	if ((h = scf_handle_create(SCF_VERSION)) == NULL ||
	    scf_handle_bind(h) != 0 ||
	    (inst = scf_instance_create(h)) == NULL ||
	    (snap = scf_snapshot_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (val = scf_value_create(h)) == NULL) {
		goto out;
	}

	if (scf_handle_decode_fmri(h, KBD_FMRI, NULL, NULL, inst,
	    NULL, NULL, SCF_DECODE_FMRI_REQUIRE_INSTANCE) != 0) {
		goto out;
	}

	if (scf_instance_get_snapshot(inst, "running", snap) != 0) {
		scf_snapshot_destroy(snap);
		snap = NULL;
	}

	if (scf_instance_get_pg_composed(inst, snap, KBD_PG, pg) != 0) {
		goto out;
	}

	if ((val_abort = malloc(KBD_MAX_NAME_LEN)) == NULL) {
		(void) fprintf(stderr,
		    "Can not alloc memory for keyboard properties\n");
		goto out;
	}

	if ((val_layout = malloc(KBD_MAX_NAME_LEN)) == NULL) {
		(void) fprintf(stderr,
		    "Can not alloc memory for keyboard properties\n");
		goto out;
	}

	if (scf_pg_get_property(pg, KBD_PROP_KEYCLICK, prop) != 0 ||
	    scf_property_get_value(prop, val) != 0 ||
	    scf_value_get_boolean(val, &val_click) == -1) {
		(void) fprintf(stderr, "Can not get KEYCLICK\n");
	}

	if (val_click == 1)
		(void) click("on", kbd);
	else if (val_click == 0)
		(void) click("off", kbd);
	else
		(void) fprintf(stderr,
		    BAD_DEFAULT_INT, KBD_PROP_KEYCLICK, val_click);

	if (scf_pg_get_property(pg, KBD_PROP_KEYBOARD_ABORT, prop) != 0 ||
	    scf_property_get_value(prop, val) != 0 ||
	    scf_value_get_astring(val, val_abort, KBD_MAX_NAME_LEN) == -1) {
		(void) fprintf(stderr, "Can not get KEYBOARD_ABORT\n");
	}

	if (*val_abort != '\0') {
		/*
		 * ABORT must equal "enable", "disable" or "alternate"
		 */
		if ((strcmp(val_abort, "enable") == 0) ||
		    (strcmp(val_abort, "alternate") == 0) ||
		    (strcmp(val_abort, "disable") == 0))
			(void) abort_enable(val_abort, kbd);
		else
			(void) fprintf(stderr, BAD_DEFAULT_STR,
			    KBD_PROP_KEYBOARD_ABORT, val_abort);
	}

	if (scf_pg_get_property(pg, KBD_PROP_RPTDELAY, prop) != 0 ||
	    scf_property_get_value(prop, val) != 0 ||
	    scf_value_get_integer(val, &val_delay) == -1) {
		(void) fprintf(stderr, "Can not get RPTDELAY\n");
	}

	if (val_delay > 0)
		(void) set_rptdelay(val_delay, kbd);
	else
		(void) fprintf(stderr,
		    BAD_DEFAULT_LLINT, KBD_PROP_RPTDELAY, val_delay);

	if (scf_pg_get_property(pg, KBD_PROP_RPTRATE, prop) != 0 ||
	    scf_property_get_value(prop, val) != 0 ||
	    scf_value_get_integer(val, &val_rate) == -1) {
		(void) fprintf(stderr, "Can not get RPTRATE\n");
	}

	if (val_rate > 0)
		(void) set_rptrate(val_rate, kbd);
	else
		(void) fprintf(stderr,
		    BAD_DEFAULT_LLINT, KBD_PROP_RPTRATE, val_rate);

	if (scf_pg_get_property(pg, KBD_PROP_LAYOUT, prop) != 0 ||
	    scf_property_get_value(prop, val) != 0 ||
	    scf_value_get_astring(val, val_layout, KBD_MAX_NAME_LEN) == -1) {
		(void) fprintf(stderr, "Can not get LAYOUT\n");
	}

	if (*val_layout != '\0') {
		/*
		 * LAYOUT must be one of the layouts supported in kbd_layouts
		 */
		if (get_layouts() != 0)
			goto out;

		if ((layout_num = get_layout_number(val_layout)) == -1) {
			(void) fprintf(stderr,
			    BAD_DEFAULT_STR, KBD_PROP_LAYOUT, val_layout);
			goto out;
		}

		(void) set_layout(kbd, layout_num);
	}

	if (scf_pg_get_property(pg, KBD_PROP_FREQ, prop) != 0 ||
	    scf_property_get_value(prop, val) != 0 ||
	    scf_value_get_integer(val, &val_kbd_beeper) == -1) {
		(void) fprintf(stderr, "Can not get FREQ\n");
	}

	if (val_kbd_beeper >= 0 && val_kbd_beeper <= INT16_MAX)
		(void) set_beep_freq(kbd, "keyboard", val_kbd_beeper);
	else
		(void) fprintf(stderr,
		    BAD_DEFAULT_LLINT, KBD_PROP_FREQ, val_kbd_beeper);

	if (scf_pg_get_property(pg, KBD_PROP_CONSFREQ, prop) != 0 ||
	    scf_property_get_value(prop, val) != 0 ||
	    scf_value_get_integer(val, &val_console_beeper) == -1) {
		(void) fprintf(stderr, "Can not get CONSFREQ\n");
	}

	if (val_console_beeper >= 0 && val_console_beeper <= INT16_MAX)
		(void) set_beep_freq(kbd, "console", val_console_beeper);
	else
		(void) fprintf(stderr,
		    BAD_DEFAULT_LLINT, KBD_PROP_CONSFREQ, val_console_beeper);

out:
	if (val_layout != NULL)
		free(val_layout);
	if (val_abort != NULL)
		free(val_abort);
	if (snap != NULL)
		scf_snapshot_destroy(snap);
	scf_value_destroy(val);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	scf_instance_destroy(inst);
	scf_handle_destroy(h);
}

static int
get_layout_number(char *layout)
{
	int i;
	int layout_number = -1;

	for (i = 0; i < layout_count; i ++) {
		if (strcmp(layout, layout_names[i]) == 0) {
			layout_number = layout_numbers[i];
			break;
		}
	}

	return (layout_number);
}

static int
get_layouts()
{
	FILE *stream;
	char buffer[MAX_LINE_SIZE];
	char *result = NULL;
	int  i = 0;
	char *tmpbuf;

	if ((stream = fopen(KBD_LAYOUT_FILE, "r")) == 0) {
		perror(KBD_LAYOUT_FILE);
		return (1);
	}

	while ((fgets(buffer, MAX_LINE_SIZE, stream) != NULL) &&
	    (i < MAX_LAYOUT_NUM)) {
		if (buffer[0] == '#')
			continue;
		if ((result = strtok(buffer, "=")) == NULL)
			continue;
		if ((tmpbuf = strdup(result)) != NULL) {
			layout_names[i] = tmpbuf;
		} else {
			perror("out of memory getting layout names");
			return (1);
		}
		if ((result = strtok(NULL, "\n")) == NULL)
			continue;
		layout_numbers[i] = atoi(result);
		if (strcmp(tmpbuf, "US-English") == 0)
			default_layout_number = i;
		i++;
	}
	layout_count = i;

	return (0);
}

/*
 * this routine sets the layout of the keyboard being used
 */
static int
set_layout(int kbd, int layout_num)
{

	if (ioctl(kbd, KIOCSLAYOUT, layout_num)) {
		perror("ioctl (set kbd layout)");
		return (1);
	}
	(void) system("/usr/bin/loadkeys");

	return (0);
}

static char *usage1 = "kbd [-r] [-t] [-l] [-a enable|disable|alternate]";
static char *usage2 = "    [-c on|off][-D delay][-R rate][-d keyboard device]";
static char *usage3 = "kbd -i [-d keyboard device]";
static char *usage4 = "kbd -s [language]";
static char *usage5 = "kbd -b [keyboard|console] frequency";

static void
usage(void)
{
	(void) fprintf(stderr, "Usage:\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n", usage1,
	    usage2, usage3, usage4, usage5);
}
