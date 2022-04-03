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
 * This file contains miscellaneous routines.
 */
#include "global.h"

#include <stdlib.h>
#include <signal.h>
#include <malloc.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <ctype.h>
#include <termio.h>
#include "misc.h"
#include "analyze.h"
#include "label.h"
#include "startup.h"

/* Function prototypes for ANSI C Compilers */
static void	cleanup(int sig);

struct	env *current_env = NULL;	/* ptr to current environment */
static int	stop_pending = 0;	/* ctrl-Z is pending */
struct	ttystate ttystate;		/* tty info */
static int	aborting = 0;		/* in process of aborting */

/*
 * For 4.x, limit the choices of valid disk names to this set.
 */
static char		*disk_4x_identifiers[] = { "sd", "id"};
#define	N_DISK_4X_IDS	(sizeof (disk_4x_identifiers)/sizeof (char *))


/*
 * This is the list of legal inputs for all yes/no questions.
 */
char	*confirm_list[] = {
	"yes",
	"no",
	NULL,
};

/*
 * This routine is a wrapper for malloc.  It allocates pre-zeroed space,
 * and checks the return value so the caller doesn't have to.
 */
void *
zalloc(int count)
{
	void	*ptr;

	if ((ptr = calloc(1, (unsigned)count)) == NULL) {
		err_print("Error: unable to calloc more space.\n");
		fullabort();
	}
	return (ptr);
}

/*
 * This routine is a wrapper for realloc.  It reallocates the given
 * space, and checks the return value so the caller doesn't have to.
 * Note that the any space added by this call is NOT necessarily
 * zeroed.
 */
void *
rezalloc(void *ptr, int count)
{
	void	*new_ptr;


	if ((new_ptr = realloc((char *)ptr, (unsigned)count)) == NULL) {
		err_print("Error: unable to realloc more space.\n");
		fullabort();
	}
	return (new_ptr);
}

/*
 * This routine is a wrapper for free.
 */
void
destroy_data(char *data)
{
	free(data);
}

#ifdef	not
/*
 * This routine takes the space number returned by an ioctl call and
 * returns a mnemonic name for that space.
 */
char *
space2str(uint_t space)
{
	char	*name;

	switch (space&SP_BUSMASK) {
	case SP_VIRTUAL:
		name = "virtual";
		break;
	case SP_OBMEM:
		name = "obmem";
		break;
	case SP_OBIO:
		name = "obio";
		break;
	case SP_MBMEM:
		name = "mbmem";
		break;
	case SP_MBIO:
		name = "mbio";
		break;
	default:
		err_print("Error: unknown address space type encountered.\n");
		fullabort();
	}
	return (name);
}
#endif	/* not */

/*
 * This routine asks the user the given yes/no question and returns
 * the response.
 */
int
check(char *question)
{
	int		answer;
	u_ioparam_t	ioparam;

	/*
	 * If we are running out of a command file, assume a yes answer.
	 */
	if (option_f)
		return (0);
	/*
	 * Ask the user.
	 */
	ioparam.io_charlist = confirm_list;
	answer = input(FIO_MSTR, question, '?', &ioparam, NULL, DATA_INPUT);
	return (answer);
}

/*
 * This routine aborts the current command.  It is called by a ctrl-C
 * interrupt and also under certain error conditions.
 */
void
cmdabort(int sig __unused)
{
	/*
	 * If there is no usable saved environment, gracefully exit.  This
	 * allows the user to interrupt the program even when input is from
	 * a file, or if there is no current menu, like at the "Select disk:"
	 * prompt.
	 */
	if (current_env == NULL || !(current_env->flags & ENV_USE))
		fullabort();

	/*
	 * If we are in a critical zone, note the attempt and return.
	 */
	if (current_env->flags & ENV_CRITICAL) {
		current_env->flags |= ENV_ABORT;
		return;
	}
	/*
	 * All interruptions when we are running out of a command file
	 * cause the program to gracefully exit.
	 */
	if (option_f)
		fullabort();
	fmt_print("\n");
	/*
	 * Clean up any state left by the interrupted command.
	 */
	cleanup(sig);
	/*
	 * Jump to the saved environment.
	 */
	longjmp(current_env->env, 0);
}

/*
 * This routine implements the ctrl-Z suspend mechanism.  It is called
 * when a suspend signal is received.
 */
void
onsusp(int sig __unused)
{
	int		fix_term;
#ifdef	NOT_DEF
	sigset_t	sigmask;
#endif	/* NOT_DEF */

	/*
	 * If we are in a critical zone, note the attempt and return.
	 */
	if (current_env != NULL && current_env->flags & ENV_CRITICAL) {
		stop_pending = 1;
		return;
	}
	/*
	 * If the terminal is mucked up, note that we will need to
	 * re-muck it when we start up again.
	 */
	fix_term = ttystate.ttyflags;
	fmt_print("\n");
	/*
	 * Clean up any state left by the interrupted command.
	 */
	cleanup(sig);
#ifdef	NOT_DEF
	/* Investigate whether all this is necessary */
	/*
	 * Stop intercepting the suspend signal, then send ourselves one
	 * to cause us to stop.
	 */
	sigmask.sigbits[0] = (ulong_t)0xffffffff;
	if (sigprocmask(SIG_SETMASK, &sigmask, NULL) == -1)
		err_print("sigprocmask failed %d\n", errno);
#endif	/* NOT_DEF */
	(void) signal(SIGTSTP, SIG_DFL);
	(void) kill(0, SIGTSTP);
	/*
	 * PC stops here
	 */
	/*
	 * We are started again.  Set us up to intercept the suspend
	 * signal once again.
	 */
	(void) signal(SIGTSTP, onsusp);
	/*
	 * Re-muck the terminal if necessary.
	 */
	if (fix_term & TTY_ECHO_OFF)
		echo_off();
	if (fix_term & TTY_CBREAK_ON)
		charmode_on();
}

/*
 * This routine implements the timing function used during long-term
 * disk operations (e.g. formatting).  It is called when an alarm signal
 * is received.
 */
void
onalarm(int sig __unused)
{
}


/*
 * This routine gracefully exits the program.
 */
void
fullabort(void)
{

	fmt_print("\n");
	/*
	 * Clean up any state left by an interrupted command.
	 * Avoid infinite loops caused by a clean-up
	 * routine failing again...
	 */
	if (!aborting) {
		aborting = 1;
		cleanup(SIGKILL);
	}
	exit(1);
	/*NOTREACHED*/
}

/*
 * This routine cleans up the state of the world.  It is a hodge-podge
 * of kludges to allow us to interrupt commands whenever possible.
 *
 * Some cleanup actions may depend on the type of signal.
 */
static void
cleanup(int sig)
{

	/*
	 * Lock out interrupts to avoid recursion.
	 */
	enter_critical();
	/*
	 * Fix up the tty if necessary.
	 */
	if (ttystate.ttyflags & TTY_CBREAK_ON) {
		charmode_off();
	}
	if (ttystate.ttyflags & TTY_ECHO_OFF) {
		echo_on();
	}

	/*
	 * If the defect list is dirty, write it out.
	 */
	if (cur_list.flags & LIST_DIRTY) {
		cur_list.flags = 0;
		if (!EMBEDDED_SCSI)
			write_deflist(&cur_list);
	}
	/*
	 * If the label is dirty, write it out.
	 */
	if (cur_flags & LABEL_DIRTY) {
		cur_flags &= ~LABEL_DIRTY;
		(void) write_label();
	}
	/*
	 * If we are logging and just interrupted a scan, print out
	 * some summary info to the log file.
	 */
	if (log_file && scan_cur_block >= 0) {
		pr_dblock(log_print, scan_cur_block);
		log_print("\n");
	}
	if (scan_blocks_fixed >= 0)
		fmt_print("Total of %lld defective blocks repaired.\n",
		    scan_blocks_fixed);
	if (sig != SIGSTOP) { /* Don't reset on suspend (converted to stop) */
		scan_cur_block = scan_blocks_fixed = -1;
	}
	exit_critical();
}

/*
 * This routine causes the program to enter a critical zone.  Within the
 * critical zone, no interrupts are allowed.  Note that calls to this
 * routine for the same environment do NOT nest, so there is not
 * necessarily pairing between calls to enter_critical() and exit_critical().
 */
void
enter_critical(void)
{

	/*
	 * If there is no saved environment, interrupts will be ignored.
	 */
	if (current_env == NULL)
		return;
	/*
	 * Mark the environment to be in a critical zone.
	 */
	current_env->flags |= ENV_CRITICAL;
}

/*
 * This routine causes the program to exit a critical zone.  Note that
 * calls to enter_critical() for the same environment do NOT nest, so
 * one call to exit_critical() will erase any number of such calls.
 */
void
exit_critical(void)
{

	/*
	 * If there is a saved environment, mark it to be non-critical.
	 */
	if (current_env != NULL)
		current_env->flags &= ~ENV_CRITICAL;
	/*
	 * If there is a stop pending, execute the stop.
	 */
	if (stop_pending) {
		stop_pending = 0;
		onsusp(SIGSTOP);
	}
	/*
	 * If there is an abort pending, execute the abort.
	 */
	if (current_env == NULL)
		return;
	if (current_env->flags & ENV_ABORT) {
		current_env->flags &= ~ENV_ABORT;
		cmdabort(SIGINT);
	}
}

/*
 * This routine turns off echoing on the controlling tty for the program.
 */
void
echo_off(void)
{
	/*
	 * Open the tty and store the file pointer for later.
	 */
	if (ttystate.ttyflags == 0) {
		if ((ttystate.ttyfile = open("/dev/tty",
		    O_RDWR | O_NDELAY)) < 0) {
			err_print("Unable to open /dev/tty.\n");
			fullabort();
		}
	}
	/*
	 * Get the parameters for the tty, turn off echoing and set them.
	 */
	if (tcgetattr(ttystate.ttyfile, &ttystate.ttystate) < 0) {
		err_print("Unable to get tty parameters.\n");
		fullabort();
	}
	ttystate.ttystate.c_lflag &= ~ECHO;
	if (tcsetattr(ttystate.ttyfile, TCSANOW, &ttystate.ttystate) < 0) {
		err_print("Unable to set tty to echo off state.\n");
		fullabort();
	}

	/*
	 * Remember that we've successfully turned
	 * ECHO mode off, so we know to fix it later.
	 */
	ttystate.ttyflags |= TTY_ECHO_OFF;
}

/*
 * This routine turns on echoing on the controlling tty for the program.
 */
void
echo_on(void)
{

	/*
	 * Using the saved parameters, turn echoing on and set them.
	 */
	ttystate.ttystate.c_lflag |= ECHO;
	if (tcsetattr(ttystate.ttyfile, TCSANOW, &ttystate.ttystate) < 0) {
		err_print("Unable to set tty to echo on state.\n");
		fullabort();
	}
	/*
	 * Close the tty and mark it ok again.
	 */
	ttystate.ttyflags &= ~TTY_ECHO_OFF;
	if (ttystate.ttyflags == 0) {
		(void) close(ttystate.ttyfile);
	}
}

/*
 * This routine turns off single character entry mode for tty.
 */
void
charmode_on(void)
{

	/*
	 * If tty unopened, open the tty and store the file pointer for later.
	 */
	if (ttystate.ttyflags == 0) {
		if ((ttystate.ttyfile = open("/dev/tty",
		    O_RDWR | O_NDELAY)) < 0) {
			err_print("Unable to open /dev/tty.\n");
			fullabort();
		}
	}
	/*
	 * Get the parameters for the tty, turn on char mode.
	 */
	if (tcgetattr(ttystate.ttyfile, &ttystate.ttystate) < 0) {
		err_print("Unable to get tty parameters.\n");
		fullabort();
	}
	ttystate.vmin = ttystate.ttystate.c_cc[VMIN];
	ttystate.vtime = ttystate.ttystate.c_cc[VTIME];

	ttystate.ttystate.c_lflag &= ~ICANON;
	ttystate.ttystate.c_cc[VMIN] = 1;
	ttystate.ttystate.c_cc[VTIME] = 0;

	if (tcsetattr(ttystate.ttyfile, TCSANOW, &ttystate.ttystate) < 0) {
		err_print("Unable to set tty to cbreak on state.\n");
		fullabort();
	}

	/*
	 * Remember that we've successfully turned
	 * CBREAK mode on, so we know to fix it later.
	 */
	ttystate.ttyflags |= TTY_CBREAK_ON;
}

/*
 * This routine turns on single character entry mode for tty.
 * Note, this routine must be called before echo_on.
 */
void
charmode_off(void)
{

	/*
	 * Using the saved parameters, turn char mode on.
	 */
	ttystate.ttystate.c_lflag |= ICANON;
	ttystate.ttystate.c_cc[VMIN] = ttystate.vmin;
	ttystate.ttystate.c_cc[VTIME] = ttystate.vtime;
	if (tcsetattr(ttystate.ttyfile, TCSANOW, &ttystate.ttystate) < 0) {
		err_print("Unable to set tty to cbreak off state.\n");
		fullabort();
	}
	/*
	 * Close the tty and mark it ok again.
	 */
	ttystate.ttyflags &= ~TTY_CBREAK_ON;
	if (ttystate.ttyflags == 0) {
		(void) close(ttystate.ttyfile);
	}
}


/*
 * Allocate space for and return a pointer to a string
 * on the stack.  If the string is null, create
 * an empty string.
 * Use destroy_data() to free when no longer used.
 */
char *
alloc_string(char *s)
{
	char	*ns;

	if (s == NULL) {
		ns = zalloc(1);
	} else {
		ns = zalloc(strlen(s) + 1);
		(void) strcpy(ns, s);
	}
	return (ns);
}



/*
 * This function can be used to build up an array of strings
 * dynamically, with a trailing NULL to terminate the list.
 *
 * Parameters:
 *	argvlist:  a pointer to the base of the current list.
 *		   does not have to be initialized.
 *	size:	   pointer to an integer, indicating the number
 *		   of string installed in the list.  Must be
 *		   initialized to zero.
 *	alloc:	   pointer to an integer, indicating the amount
 *		   of space allocated.  Must be initialized to
 *		   zero.  For efficiency, we allocate the list
 *		   in chunks and use it piece-by-piece.
 *	str:	   the string to be inserted in the list.
 *		   A copy of the string is malloc'ed, and
 *		   appended at the end of the list.
 * Returns:
 *	a pointer to the possibly-moved argvlist.
 *
 * No attempt to made to free unused memory when the list is
 * completed, although this would not be hard to do.  For
 * reasonably small lists, this should suffice.
 */
#define	INITIAL_LISTSIZE	32
#define	INCR_LISTSIZE		32

char **
build_argvlist(char **argvlist, int *size, int *alloc, char *str)
{
	if (*size + 2 > *alloc) {
		if (*alloc == 0) {
			*alloc = INITIAL_LISTSIZE;
			argvlist = zalloc(sizeof (char *) * (*alloc));
		} else {
			*alloc += INCR_LISTSIZE;
			argvlist = rezalloc((void *) argvlist,
			    sizeof (char *) * (*alloc));
		}
	}

	argvlist[*size] = alloc_string(str);
	*size += 1;
	argvlist[*size] = NULL;

	return (argvlist);
}


/*
 * Useful parsing macros
 */
#define	must_be(s, c)		if (*s++ != c) return (0)
#define	skip_digits(s)		while (isdigit(*s)) s++
/* Parsing macro below is created to handle fabric devices which contains */
/* upper hex digits like c2t210000203708B8CEd0s0.			  */
/* To get the target id(tid) the digit and hex upper digit need to	  */
/* be processed.							  */
#define	skip_digit_or_hexupper(s)	while (isdigit(*s) || \
					(isxdigit(*s) && isupper(*s))) s++

/*
 * Return true if a device name matches the conventions
 * for the particular system.
 */
int
conventional_name(char *name)
{
	must_be(name, 'c');
	skip_digits(name);
	if (*name == 't') {
		name++;
		skip_digit_or_hexupper(name);
	}
	must_be(name, 'd');
	skip_digits(name);
	must_be(name, 's');
	skip_digits(name);
	return (*name == 0);
}

#ifdef i386
/*
 * Return true if a device name match the emc powerpath name scheme:
 * emcpowerN[a-p,p0,p1,p2,p3,p4]
 */
int
emcpower_name(char *name)
{
	char	*emcp = "emcpower";
	char	*devp = "/dev/dsk";
	char	*rdevp = "/dev/rdsk";

	if (strncmp(devp, name, strlen(devp)) == 0) {
		name += strlen(devp) + 1;
	} else if (strncmp(rdevp, name, strlen(rdevp)) == 0) {
		name += strlen(rdevp) + 1;
	}
	if (strncmp(emcp, name, strlen(emcp)) == 0) {
		name += strlen(emcp);
		if (isdigit(*name)) {
			skip_digits(name);
			if ((*name >= 'a') && (*name <= 'p')) {
				name ++;
				if ((*name >= '0') && (*name <= '4')) {
					name++;
				}
			}
			return (*name == '\0');
		}
	}
	return (0);
}
#endif

/*
 * Return true if a device name matches the intel physical name conventions
 * for the particular system.
 */
int
fdisk_physical_name(char *name)
{
	must_be(name, 'c');
	skip_digits(name);
	if (*name == 't') {
		name++;
		skip_digit_or_hexupper(name);
	}
	must_be(name, 'd');
	skip_digits(name);
	must_be(name, 'p');
	skip_digits(name);
	return (*name == 0);
}

/*
 * Return true if a device name matches the conventions
 * for a "whole disk" name for the particular system.
 * The name in this case must match exactly that which
 * would appear in the device directory itself.
 */
int
whole_disk_name(char *name)
{
	must_be(name, 'c');
	skip_digits(name);
	if (*name == 't') {
		name++;
		skip_digit_or_hexupper(name);
	}
	must_be(name, 'd');
	skip_digits(name);
	must_be(name, 's');
	must_be(name, '2');
	return (*name == 0);
}


/*
 * Return true if a name is in the internal canonical form
 */
int
canonical_name(char *name)
{
	must_be(name, 'c');
	skip_digits(name);
	if (*name == 't') {
		name++;
		skip_digit_or_hexupper(name);
	}
	must_be(name, 'd');
	skip_digits(name);
	return (*name == 0);
}


/*
 * Return true if a name is in the internal canonical form for 4.x
 * Used to support 4.x naming conventions under 5.0.
 */
int
canonical4x_name(char *name)
{
	char    **p;
	int	i;

	p = disk_4x_identifiers;
	for (i = N_DISK_4X_IDS; i > 0; i--, p++) {
		if (match_substr(name, *p)) {
			name += strlen(*p);
			break;
		}
	}
	if (i == 0)
		return (0);
	skip_digits(name);
	return (*name == 0);
}


/*
 * Map a conventional name into the internal canonical form:
 *
 *	/dev/rdsk/c0t0d0s0 -> c0t0d0
 */
void
canonicalize_name(char *dst, char *src)
{
	char	*s;

	/*
	 * Copy from the 'c' to the end to the destination string...
	 */
	s = strchr(src, 'c');
	if (s != NULL) {
		(void) strcpy(dst, s);
		/*
		 * Remove the trailing slice (partition) reference
		 */
		s = dst + strlen(dst) - 2;
		if (*s == 's') {
			*s = 0;
		}
	} else {
		*dst = 0;	/* be tolerant of garbage input */
	}
}


/*
 * Return true if we find an occurance of s2 at the
 * beginning of s1.  We don't have to match all of
 * s1, but we do have to match all of s2
 */
int
match_substr(char *s1, char *s2)
{
	while (*s2 != 0) {
		if (*s1++ != *s2++)
		return (0);
	}

	return (1);
}


/*
 * Dump a structure in hexadecimal, for diagnostic purposes
 */
#define	BYTES_PER_LINE		16

void
dump(char *hdr, caddr_t src, int nbytes, int format)
{
	int	i;
	int	n;
	char	*p;
	char	s[256];

	assert(format == HEX_ONLY || format == HEX_ASCII);

	(void) strcpy(s, hdr);
	for (p = s; *p; p++) {
		*p = ' ';
	}

	p = hdr;
	while (nbytes > 0) {
		err_print("%s", p);
		p = s;
		n = min(nbytes, BYTES_PER_LINE);
		for (i = 0; i < n; i++) {
			err_print("%02x ", src[i] & 0xff);
		}
		if (format == HEX_ASCII) {
			for (i = BYTES_PER_LINE-n; i > 0; i--) {
				err_print("   ");
			}
			err_print("    ");
			for (i = 0; i < n; i++) {
				err_print("%c", isprint(src[i]) ? src[i] : '.');
			}
		}
		err_print("\n");
		nbytes -= n;
		src += n;
	}
}


float
bn2mb(uint64_t nblks)
{
	float	n;

	n = (float)nblks / 1024.0;
	return ((n / 1024.0) * cur_blksz);
}


diskaddr_t
mb2bn(float mb)
{
	diskaddr_t	n;

	n = (diskaddr_t)(mb * 1024.0 * (1024.0 / cur_blksz));
	return (n);
}

float
bn2gb(uint64_t nblks)
{
	float	n;

	n = (float)nblks / (1024.0 * 1024.0);
	return ((n/1024.0) * cur_blksz);

}

float
bn2tb(uint64_t nblks)
{
	float	n;

	n = (float)nblks / (1024.0 * 1024.0 * 1024.0);
	return ((n/1024.0) * cur_blksz);
}

diskaddr_t
gb2bn(float gb)
{
	diskaddr_t	n;

	n = (diskaddr_t)(gb * 1024.0 * 1024.0 * (1024.0 / cur_blksz));
	return (n);
}

/*
 * This routine finds out the number of lines (rows) in a terminal
 * window. The default value of TTY_LINES is returned on error.
 */
int
get_tty_lines(void)
{
	int	tty_lines = TTY_LINES;
	struct	winsize	winsize;

	if ((option_f == NULL) && isatty(0) == 1 && isatty(1) == 1) {
		/*
		 * We have a real terminal for std input and output
		 */
		winsize.ws_row = 0;
		if (ioctl(1, TIOCGWINSZ, &winsize) == 0) {
			if (winsize.ws_row > 2) {
				/*
				 * Should be atleast 2 lines, for division
				 * by (tty_lines - 1, tty_lines - 2) to work.
				 */
				tty_lines = winsize.ws_row;
			}
		}
	}
	return (tty_lines);
}
