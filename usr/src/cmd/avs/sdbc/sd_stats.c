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
#include <unistd.h>
#include <strings.h>
#include <curses.h>
#include <signal.h>
#include <fcntl.h>
#include <locale.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/nsctl/sdbc_ioctl.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/nsctl/sd_bcache.h>
#include <sys/nsctl/sd_conf.h>

extern void total_display(void);
extern void display_cache(void);
extern void wrefresh_file(WINDOW *, int);
extern int is_dirty(void);
extern int dual_stats(void);
void checkbuf(int);
void setup_ranges(char *);
void prheading(int);
extern int zero_nic(void);

#ifdef m88k
#define	USEC_INIT()	usec_ptr = (unsigned int *)timer_init()
#define	USEC_READ()	(*usec_ptr)
#else /* !m88k */
#define	USEC_INIT()	USEC_START()
#include <sys/time.h>
static struct timeval Usec_time;
static int Usec_started = 0;

extern int higher(int);
extern int is_dirty();
extern int dual_stats();
extern void total_display();
extern void display_cache();
extern void wrefresh_file(WINDOW *, int);
void setup_ranges(char *);

void prheading(int);
void checkbuf(int);
void quit(int);
void leave(int);
#pragma does_not_return(quit, leave)

int sdbc_max_devices = 0;

static void
USEC_START()
{
	if (!Usec_started) {
		(void) gettimeofday(&Usec_time, NULL);
		Usec_started = 1;
	}
}

static unsigned int
USEC_READ()
{
	struct timeval tv;
	if (!Usec_started)
		USEC_START();

	(void) gettimeofday(&tv, NULL);
	return (unsigned)((tv.tv_sec - Usec_time.tv_sec) * 1000000
	    + (tv.tv_usec - Usec_time.tv_usec));
}
#endif /* m88k */

int		rev_flag = 0;		/* Reverse video flag */
int		bold_flg = 0;		/* Bold flag */
int		under_flg = 0;		/* Underline flag */
int		errflg = 0;		/* Error flag */
int		node_sw = 0;		/* Per node switch */
int 		toggle_total_sw = 0;
int		mirror_sw = 0;		/* Dual copy switch */

int		kmemfd;
int		delay = 1;			/* Display delay (seconds) */

time_t	*usec_ptr;
time_t	currtime = 0;
int		lasttime = 0;
int		Elapsed_Time = 0;

static char	*range;
static int	had_r_option = 0;
int		logfd = -1;		/* screen output logging */
extern 		int range_num;
extern		int screen;
extern 		int dual_screen;
int		*on_off;
int		*dual_on_off;
int		*updates_prev;
double		*rate_prev;
int		*samples;
_sd_stats_t	*cs_cur;
_sd_stats_t	*cs_prev;
_sd_stats_t	*cs_persec;

typedef struct {
	int lb, ub;
} range_t;

extern range_t ranges[];

#ifdef lint
int
sd_stats_lintmain(int argc, char *argv[])
#else
int
main(int argc, char *argv[])
#endif
{
	spcs_s_info_t ustats;
	struct timeval tout;
	fd_set readfds;
	char *errmessage, *ch;
	int c, period, prev;
	int count = 0, dflag = 0;
	int fd = fileno(stdin);

	errmessage = NULL;

	if (strcmp(argv[0], "sd_stats") != 0)
		errmessage = getenv("SD_STATS_USAGE");

	if (errmessage == NULL)
		errmessage = gettext("Usage: sd_stats [-Mz] "
				"[-d delay_time] [-l logfile] [-r range]");

	if (SDBC_IOCTL(SDBC_MAXFILES, &sdbc_max_devices,
	    0, 0, 0, 0, &ustats) == SPCS_S_ERROR) {
		if (ustats) {  	/* if SPCS_S_ERROR */
			spcs_s_report(ustats, stderr);
			spcs_s_ufree(&ustats);
		}
		(void) fprintf(stderr, gettext("cannot get maxfiles\n"));
		exit(1);
	}
	on_off = calloc(sdbc_max_devices, sizeof (int));
	dual_on_off = calloc(sdbc_max_devices, sizeof (int));
	updates_prev = calloc(sdbc_max_devices, sizeof (int));
	samples = calloc(sdbc_max_devices, sizeof (int));
	rate_prev = calloc(sdbc_max_devices, sizeof (double));
	cs_cur = malloc(sizeof (_sd_stats_t) +
	    (sdbc_max_devices - 1) * sizeof (_sd_shared_t));
	cs_prev = malloc(sizeof (_sd_stats_t) +
	    (sdbc_max_devices - 1) * sizeof (_sd_shared_t));
	cs_persec = malloc(sizeof (_sd_stats_t) +
	    (sdbc_max_devices - 1) * sizeof (_sd_shared_t));
	range = malloc(100);

	if (!on_off || !dual_on_off || !updates_prev || !samples ||
	    !rate_prev || !cs_cur || !cs_prev || !cs_persec || !range) {
		(void) fprintf(stderr, gettext("no free memory\n"));
		exit(1);
	}

	*range = '\0';

	while ((c = getopt(argc, argv, "DMzd:l:r:h")) != EOF) {

		prev = c;
		switch (c) {

		case 'd':
			delay = atoi(optarg);
			ch = optarg;
			while (*ch != '\0') {
				if (!isdigit(*ch))
					errflg++;
				ch++;
			}
			break;

		case 'l':
			logfd = open(optarg, O_CREAT|O_WRONLY|O_TRUNC, 0644);
			break;

		case 'r':
			ch = optarg;
			while (*ch != '\0') {
				if ((!isdigit(*ch)) && (*ch != ',') &&
				    (*ch != ':'))
					errflg++;
				ch++;
			}
			if (errflg)
				break;

			range = realloc((char *)range,
					(strlen(range) + strlen(optarg) + 1)
					* sizeof (char));

			if (had_r_option)
				(void) strcat(range, ",");
			(void) strcat(range, optarg);
			had_r_option = 1;
			break;

		case 'z':
			if (SDBC_IOCTL(SDBC_ZAP_STATS, 0, 0, 0, 0, 0,
					&ustats) == SPCS_S_ERROR) {
				if (ustats) {
					spcs_s_report(ustats, stderr);
					spcs_s_ufree(&ustats);
				}
			}

			break;

		case 'D':
			dflag = 1;
			break;

		case 'M':
			mirror_sw = 1;
			break;

		case 'h':
		case '?':
		default :
			errflg++;
			break;
		}
	}

	if (errflg) {
		(void) fprintf(stderr, "%s\n", errmessage);
		exit(1);
	} else if (!prev) {
		if (argc > 1) {
			(void) fprintf(stderr, "%s\n", errmessage);
			exit(1);
		}
	}

	if (dflag) {
		exit(is_dirty());
	}


	/*
	 * A few curses routines to setup screen and tty interface
	 */
	(void) initscr();
	(void) cbreak();
	(void) noecho();
	(void) nonl();
	(void) erase();
	(void) clear();
	(void) refresh();

	setup_ranges(range);

	/*
	 * Set signal handle
	 */
	sigset(SIGPIPE, leave);
	sigset(SIGINT, leave);
	sigset(SIGQUIT, leave);
	signal(SIGFPE, leave);
	signal(SIGSEGV, leave);

	USEC_INIT();
	currtime = USEC_READ();

	/*
	 * Wait one second before reading the new values
	 */
	(void) sleep(1);

	/*CONSTCOND*/
	while (1) {

		lasttime = currtime;
		currtime = USEC_READ();

		/*
		 * If less that 1 second, force it to one second
		 */
		if ((period = (currtime - lasttime) / 1000000) <= 0)
			period = 1;

		/*
		 * Calculate new per/period values for statistics
		 */
		Elapsed_Time += period;

		/*
		 * Display new statistics
		 */
		prheading(++count);

		if (mirror_sw) {
			if (dual_stats() < 0)
				mirror_sw = 0;
		} else if (toggle_total_sw)
			total_display();
		else
			display_cache();

		(void) move(0, 0);
		(void) refresh();
		if (logfd > -1) wrefresh_file(stdscr, logfd);

		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);
		tout.tv_sec = delay;
		for (;;) {
			tout.tv_usec = 0;
			if (select(fd + 1, &readfds, (fd_set *)0, (fd_set *)0,
				&tout) <= 0)
				break;
			if ((c = getch()) == EOF) {
				(void) sleep(delay);
				break;
			}
			checkbuf(c);
			tout.tv_sec = 0;
		}
		(void) erase();
	}
#pragma error_messages(off, E_STATEMENT_NOT_REACHED)
	return (0);
#pragma error_messages(default, E_STATEMENT_NOT_REACHED)
}

void
checkbuf(int c)
{
	spcs_s_info_t ustats;

	switch (c) {
	case 'b' : /* ctrl b or b --  scroll backward */
	case  2  :
		{
		if (mirror_sw == 1) {
			if (dual_screen > 0)
				dual_screen--;
			break;
		}
		if (screen > 0)
			screen--;
		break;
		}

	case 'f' : /* ctrl f or f -- scroll forward */
	case  6  :
		{
		if (mirror_sw == 1) {
			dual_screen++;
			break;
		}
		screen++;
		break;
		}

	case 't':
	case 'T':
		if (mirror_sw == 1)
			mirror_sw = 0;

		toggle_total_sw ^= 1;
		break;

	case '-':
	case KEY_DOWN:
		if (delay > 1) {
			--delay;
		} else {
			(void) beep();
		}
		break;

	case '+':
	case KEY_UP:
		delay++;
		break;

	case 'C':
	case 0xc:
		(void) clearok(stdscr, TRUE);
		break;

	case 'B':
		if (bold_flg) {
			bold_flg = 0;
			(void) attroff(A_BOLD);
		} else {
			bold_flg = 1;
			(void) attron(A_BOLD);
		}
		break;

	case 'R':
		if (rev_flag) {
			rev_flag = 0;
			(void) attroff(A_REVERSE);
		} else {
			rev_flag = 1;
			(void) attron(A_REVERSE);
		}
		break;

	case 'z':
		if (SDBC_IOCTL(SDBC_ZAP_STATS, 0, 0, 0, 0, 0,
				&ustats) == SPCS_S_ERROR) {
			if (ustats) {
				spcs_s_report(ustats, stderr);
				spcs_s_ufree(&ustats);
			}
		}
		break;

	case 'm':
	case 'M':
		mirror_sw = mirror_sw ? 0 : 1;
		(void) clear();
		break;
	}
}

void
prheading(int count)
{
	time_t	tim;

	/*
	 * Print sample count in upper left corner
	 */
	(void) mvprintw(0,  0, "SAMPLE %-8d", count);

	/*
	 * Get time and print it in upper right corner
	 */
	tim = time((time_t *)0);
	(void) mvprintw(0, 79 - 10, "%-8.8s\n", &(ctime(&tim)[11]));
}

/*ARGSUSED*/
void
leave(int status)
{
	sigignore(SIGPIPE);
	sigignore(SIGALRM);
	/* clear(); */
	(void) move(LINES, 0);
	(void) refresh();
	if (logfd > -1) wrefresh_file(stdscr, logfd);
	quit(0);
}

void
quit(int status)
{
	(void) resetterm();
	(void) endwin();
	exit(status);
}

void
setup_ranges(char *range)
{
	int ndx;
	char chr1;
	char prev_chr = '\0';
	int got_colon = 0;
	int after_got_colon = 0;
	int got_comma = 0;
	int after_got_comma = 0;
	int number = 0;
	int prev_num = 0;

	if (range == NULL || (strlen(range) == 0)) {
		ranges[range_num].lb = 0;
		ranges[range_num].ub = sdbc_max_devices - 1;
		return;
	} else {
		ndx = 0;
		got_comma = 0;
		got_colon = 0;
		while ((chr1 = (range[ndx++])) != '\0') {
			switch (chr1) {
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				number = number*10 + (chr1 - '0');
				break;
			case ':':
				got_colon = 1;
				break;
			case ',':
				got_comma = 1;
				break;
			default: /* ignore any unknown characters */
				break;
			}	/* switch */
			if (got_comma && after_got_colon) {
				after_got_colon = 0;
				got_comma = 0;
				if (number >= sdbc_max_devices)
					number = sdbc_max_devices - 1;
				ranges[range_num].lb = prev_num;
				ranges[range_num].ub = number;
				if (range_num == 99) break;
				range_num++;
				number = 0;
			} else if (got_colon && after_got_comma) {
				got_colon = 0;
				after_got_colon = 1;
				after_got_comma = 0;
				if (number >= sdbc_max_devices)
					number = sdbc_max_devices - 1;
				prev_num = number;
				number = 0;
			} else if (got_colon) {
				got_colon = 0;
				after_got_colon = 1;
				if ((prev_chr != '\0') && (prev_chr != ':')) {
					if (number >= sdbc_max_devices)
						number = sdbc_max_devices - 1;
					prev_num = number;
					number = 0;
				}
			} else if (got_comma) {
				got_comma = 0;
				after_got_comma = 1;
				after_got_colon = 0;
				if (number >= sdbc_max_devices)
					number = sdbc_max_devices -1;
				if ((prev_chr != '\0') && (prev_chr != ',')) {
					ranges[range_num].lb = number;
					ranges[range_num].ub = number;
					if (range_num == 99) break;
						range_num++;
				}
				number = 0;
			}	/* if */
			prev_chr = chr1;
		}		/* while */
		if (number >= sdbc_max_devices)
			number = sdbc_max_devices - 1;
		if (after_got_colon) {
			ranges[range_num].lb = prev_num;
			ranges[range_num].ub = number;
		} else {
			if ((after_got_comma) && (prev_chr == ','))
				range_num--;
			else {
				ranges[range_num].lb = number;
				ranges[range_num].ub = number;
			}
		}
	}
}
