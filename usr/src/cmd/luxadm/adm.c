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




/*LINTLIBRARY*/


/*
 * Administration program for SENA
 * subsystems and individual FC_AL devices.
 */

/*
 * I18N message number ranges
 *  This file: 2000 - 2999
 *  Shared common messages: 1 - 1999
 */

/* #define		 _POSIX_SOURCE 1 */

/*
 * These defines are used to map instance number from sf minor node.
 * They are copied from SF_INST_SHIFT4MINOR and SF_MINOR2INST in sfvar.h.
 * sfvar.h is not clean for userland use.
 * When it is cleaned up, these defines will be removed and sfvar.h
 * will be included in luxadm.h header file.
 */
#define		LUX_SF_INST_SHIFT4MINOR	6
#define		LUX_SF_MINOR2INST(x)	(x >> LUX_SF_INST_SHIFT4MINOR)

/*	Includes	*/
#include	<stdlib.h>
#include	<stdio.h>
#include	<sys/file.h>
#include	<sys/errno.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/param.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<errno.h>
#include	<string.h>
#include	<ctype.h>
#include	<strings.h>
#include	<sys/stat.h>
#include	<dirent.h>
#include	<limits.h>
#include	<stdarg.h>
#include	<termio.h>		/* For password */
#include	<sys/scsi/scsi.h>

#include	"common.h"
#include	"luxadm.h"


/*	Global variables	*/
char	*dtype[16]; /* setting a global for later use. */
char			*whoami;
int	Options;
const	int OPTION_A	= 0x00000001;
const	int OPTION_B	= 0x00000002;
const	int OPTION_C	= 0x00000004;
const	int OPTION_D	= 0x00000008;
const	int OPTION_E	= 0x00000010;
const	int OPTION_F	= 0x00000020;
const	int OPTION_L	= 0x00000040;
const	int OPTION_P	= 0x00000080;
const	int OPTION_R	= 0x00000100;
const	int OPTION_T	= 0x00000200;
const	int OPTION_V	= 0x00000400;
const	int OPTION_Z	= 0x00001000;
const	int OPTION_Y	= 0x00002000;
const	int OPTION_CAPF	= 0x00004000;
const	int PVERBOSE	= 0x00008000;
const	int SAVE	= 0x00010000;
const	int EXPERT	= 0x00020000;

/*
 * Given a pointer to a character array, print the character array.
 * the character array will not necesarily be NULL terminated.
 *
 * Inputs:
 *	size - the max number of characters to print
 *	fill_flag - flag when set fills all NULL characters with spaces
 * Returns:
 *	N/A
 */
void
print_chars(uchar_t *buffer, int size, int fill_flag)
{

int i;

	for (i = 0; i < size; i++) {
		if (buffer[i])
			(void) fprintf(stdout, "%c", buffer[i]);
		else if (fill_flag)
			(void) fprintf(stdout, " ");
		else
			return;
	}
}

/*
 * Name    : memstrstr
 * Input   : pointer to buf1, pointer to buf2, size of buf1, size of buf2
 * Returns :
 *	Pointer to start of contents-of-buf2 in buf1 if it is found
 *	NULL if buf1 does not contain contents of buf2
 * Synopsis:
 * This function works similar to strstr(). The difference is that null
 * characters in the buffer are treated like any other character. So, buf1
 * and buf2 can have embedded null characters in them.
 */
static char *
memstrstr(char *s1, char *s2, int size1, int size2)
{
	int count1, count2;
	char *s1_ptr, *s2_ptr;

	count1 = size1; count2 = size2;
	s1_ptr = s1; s2_ptr = s2;

	if (size2 == 0)
		return (s1);

	while (count1--) {
		if (*s1_ptr++ == *s2_ptr++) {
			if (--count2 == 0)
				return (s1_ptr - size2);
			continue;
		}
		count2 = size2;
		s2_ptr = s2;
	}

	return (NULL);
}


/*
 *	Download host bus adapter FCode to all supported cards.
 *
 *	Specify a directory that holds the FCode files, or
 *	it will use the default dir.  Each file is dealt to
 *	the appropriate function.
 *
 *	-p prints current versions only, -d specifies a directory to load
 */
static	int
adm_fcode(int verbose, char *dir)
{
	struct stat statbuf;
	struct dirent *dirp;
	DIR	*dp;
	int	fp;
	char	fbuf[BUFSIZ];
	char	file[MAXPATHLEN];
	int	retval = 0, strfound = 0;
	char	manf[BUFSIZ];

	/* Find all adapters and print the current FCode version */
	if (Options & OPTION_P) {

/* SOCAL (SBus) adapters are not supported on x86 */
#ifndef __x86
		if (verbose) {
			(void) fprintf(stdout,
			    MSGSTR(2215, "\n  Searching for FC100/S cards:\n"));
		}
		retval += fcal_update(Options & PVERBOSE, NULL);
#endif

		if (verbose) {
			(void) fprintf(stdout,
		MSGSTR(2216, "\n  Searching for FC100/P, FC100/2P cards:\n"));
		}
		retval += q_qlgc_update(Options & PVERBOSE, NULL);
		if (verbose) {
			(void) fprintf(stdout,
			    MSGSTR(2503, "\n  Searching for Emulex cards:\n"));
		}
		retval += emulex_update(NULL);

	/* Send files to the correct function for loading to the HBA */
	} else {

		if (!dir) {
			(void) fprintf(stdout, MSGSTR(2251,
			    "  Location of Fcode not specified.\n"));
			return (1);

		} else if (verbose) {
			(void) fprintf(stdout, MSGSTR(2217,
			    "  Using directory %s"), dir);
		}
		if (lstat(dir, &statbuf) < 0) {
			(void) fprintf(stderr, MSGSTR(134,
			    "%s: lstat() failed - %s\n"),
			    dir, strerror(errno));
			return (1);
		}
		if (S_ISDIR(statbuf.st_mode) == 0) {
		(void) fprintf(stderr,
		    MSGSTR(2218, "Error: %s is not a directory.\n"), dir);
			return (1);
		}
		if ((dp = opendir(dir)) == NULL) {
			(void) fprintf(stderr, MSGSTR(2219,
			    "  Error Cannot open directory %s\n"), dir);
			return (1);
		}

		while ((dirp = readdir(dp)) != NULL) {
			if (strcmp(dirp->d_name, ".") == 0 ||
			    strcmp(dirp->d_name, "..") == 0) {
				continue;
			}
			sprintf(file, "%s/%s", dir, dirp->d_name);

			if ((fp = open(file, O_RDONLY)) < 0) {
				(void) fprintf(stderr,
				    MSGSTR(2220,
					"Error: open() failed to open file "
					"%s\n"), file);
				/*
				 * We should just issue an error message and
				 * make an attempt on the next file,
				 * and the open error is still an error
				 * so the retval should be incremented
				 */
				retval++;
				continue;
			}
			while ((read(fp, fbuf, BUFSIZ)) > 0) {
				if (memstrstr(fbuf, "SUNW,socal",
					BUFSIZ, strlen("SUNW,socal"))
								!= NULL) {
					(void) fprintf(stdout, MSGSTR(2221,
					    "\n  Using file: %s\n"), file);
					retval += fcal_update(
						Options & PVERBOSE, file);
					strfound++;
					break;
				} else if ((memstrstr(fbuf, "SUNW,ifp",
						BUFSIZ, strlen("SUNW,ifp"))
								!= NULL) ||
				    (memstrstr(fbuf, "SUNW,qlc",
					    BUFSIZ, strlen("SUNW,qlc"))
								    != NULL)) {
					(void) fprintf(stdout, MSGSTR(2221,
					    "\n  Using file: %s\n"), file);
					retval += q_qlgc_update(
						Options & PVERBOSE, file);
					strfound++;
					break;
				}
			}
			if (!strfound) {
				/* check to see if this is an emulex fcode */
				memset(manf, 0, sizeof (manf));
				if ((emulex_fcode_reader(fp, "manufacturer",
						    manf,
						    sizeof (manf)) == 0) &&
				    (strncmp(manf, "Emulex", sizeof (manf))
									== 0)) {
					retval += emulex_update(file);
					strfound = 0;
				} else {
					(void) fprintf(stderr, MSGSTR(2222,
					    "\nError: %s is not a valid Fcode "
					    "file.\n"), file);
					retval++;
				}
			} else {
				strfound = 0;
			}
			close(fp);
		}
		closedir(dp);
	}
	return (retval);
}

/*
 * Definition of getaction() routine which does keyword parsing
 *
 * Operation: A character string containing the ascii cmd to be
 * parsed is passed in along with an array of structures.
 * The 1st struct element is a recognizable cmd string, the second
 * is the minimum number of characters from the start of this string
 * to succeed on a match. For example, { "offline", 3, ONLINE }
 * will match "off", "offli", "offline", but not "of" nor "offlinebarf"
 * The third element is the {usually but not necessarily unique}
 * integer to return on a successful match. Note: compares are cAsE insensitive.
 *
 * To change, extend or use this utility, just add or remove appropriate
 * lines in the structure initializer below and in the #define	s for the
 * return values.
 *
 *                              N O T E
 * Do not change the minimum number of characters to produce
 * a match as someone may be building scripts that use this
 * feature.
 */
struct keyword {
	char *match;		/* Character String to match against */
	int  num_match;		/* Minimum chars to produce a match */
	int  ret_code;		/* Value to return on a match */
};

static  struct keyword Keywords[] = {
	{"display",		2, DISPLAY},
	{"download",		3, DOWNLOAD},
	{"enclosure_names",	2, ENCLOSURE_NAMES},
	{"failover",		3, FAILOVER},
	{"fcal_s_download",	4, FCAL_UPDATE},
	{"fcode_download",	4, FCODE_UPDATE},
	{"inquiry",		2, INQUIRY},
	{"insert_device",	3, INSERT_DEVICE},
	{"led",			3, LED},
	{"led_on",		5, LED_ON},
	{"led_off",		5, LED_OFF},
	{"led_blink",		5, LED_BLINK},
	{"password",		2, PASSWORD},
	{"power_on",		8, POWER_ON},
	{"power_off",		9, POWER_OFF},
	{"probe",		2, PROBE},
	{"qlgc_s_download",	4, QLGC_UPDATE},
	{"remove_device",	3, REMOVE_DEVICE},
	{"reserve",		5, RESERVE},
	{"release",		3, RELEASE},
	{"set_boot_dev",	5, SET_BOOT_DEV},
	{"start",		3, START},
	{"stop",		3, STOP},
	{"rdls",		2, RDLS},
	{"bypass",		3, BYPASS},
	{"enable",		3, ENABLE},
	{"p_offline",		4, LUX_P_OFFLINE},
	{"p_online",		4, LUX_P_ONLINE},
	{"forcelip",		2, FORCELIP},
	{"dump",		2, DUMP},
	{"check_file",		2, CHECK_FILE},
	{"dump_map",		2, DUMP_MAP},
	{"sysdump",		5, SYSDUMP},
	{"port",		4, PORT},
	{"external_loopback",	12, EXT_LOOPBACK},
	{"internal_loopback",	12, INT_LOOPBACK},
	{"no_loopback",		11, NO_LOOPBACK},
	{"version",		2, VERSION},
	{"create_fabric_device",	2,	CREATE_FAB},
	/* hotplugging device operations */
	{"online",		2, DEV_ONLINE},
	{"offline",		2, DEV_OFFLINE},
	{"dev_getstate",	5, DEV_GETSTATE},
	{"dev_reset",		5, DEV_RESET},
	/* hotplugging bus operations */
	{"bus_quiesce",		5, BUS_QUIESCE},
	{"bus_unquiesce",	5, BUS_UNQUIESCE},
	{"bus_getstate",	5, BUS_GETSTATE},
	{"bus_reset",		9, BUS_RESET},
	{"bus_resetall",	12, BUS_RESETALL},
	/* hotplugging "helper" subcommands */
	{ NULL,			0, 0}
};

#ifndef	EOK
static	const	int EOK	= 0;	/* errno.h type success return code */
#endif


/*
 * function getaction() takes a character string, cmd, and
 * tries to match it against a passed structure of known cmd
 * character strings. If a match is found, corresponding code
 * is returned in retval. Status returns as follows:
 *   EOK	= Match found, look for cmd's code in retval
 *   EFAULT = One of passed parameters was bad
 *   EINVAL = cmd did not match any in list
 */
static int
getaction(char *cmd, struct keyword *matches, int  *retval)
{
	int actlen;

	/* Idiot checking of pointers */
	if (! cmd || ! matches || ! retval ||
	    ! (actlen = strlen(cmd)))	/* Is there an cmd ? */
	    return (EFAULT);

	/* Keep looping until NULL match string (end of list) */
	while (matches->match) {
		/*
		 * Precedence: Make sure target is no longer than
		 * current match string
		 * and target is at least as long as
		 * minimum # match chars,
		 * then do case insensitive match
		 * based on actual target size
		 */
		if ((((int)strlen(matches->match)) >= actlen) &&
		    (actlen >= matches->num_match) &&
		    /* can't get strncasecmp to work on SCR4 */
		    /* (strncasecmp(matches->match, cmd, actlen) == 0) */
		    (strncmp(matches->match, cmd, actlen) == 0)) {
		    *retval = matches->ret_code;	/* Found our match */
		    return (EOK);
		} else {
		    matches++;		/* Next match string/struct */
		}
	}	/* End of matches loop */
	return (EINVAL);

}	/* End of getaction() */

/* main functions. */
int
main(int argc, char **argv)
{
register int 	c;
/* getopt varbs */
extern char *optarg;
char		*optstring = NULL;
int		path_index, err = 0;
int		cmd = 0;		/* Cmd verb from cmd line */
int		exit_code = 0;		/* exit code for program */
int		temp_fd;		/* For -f option */
char		*file_name = NULL;
int		option_t_input;
char		*path_phys = NULL;
int		USE_FCHBA = 0;

	whoami = argv[0];


	/*
	 * Enable locale announcement
	 */
	i18n_catopen();

	while ((c = getopt(argc, argv, "ve"))
	    != EOF) {
	    switch (c) {
		case 'v':
		    Options |= PVERBOSE;
		    break;
		case 'e':
		    Options |= EXPERT;
		    break;
		default:
		    /* Note: getopt prints an error if invalid option */
		    USEAGE()
		    exit(-1);
	    } /* End of switch(c) */
	}
	setbuf(stdout, NULL);	/* set stdout unbuffered. */

	/*
	 * Build any i18n global variables
	 */
	dtype[0] = MSGSTR(2192, "Disk device");
	dtype[1] = MSGSTR(2193, "Tape device");
	dtype[2] = MSGSTR(2194, "Printer device");
	dtype[3] = MSGSTR(2195, "Processor device");
	dtype[4] = MSGSTR(2196, "WORM device");
	dtype[5] = MSGSTR(2197, "CD-ROM device");
	dtype[6] = MSGSTR(2198, "Scanner device");
	dtype[7] = MSGSTR(2199, "Optical memory device");
	dtype[8] = MSGSTR(2200, "Medium changer device");
	dtype[9] = MSGSTR(2201, "Communications device");
	dtype[10] = MSGSTR(107, "Graphic arts device");
	dtype[11] = MSGSTR(107, "Graphic arts device");
	dtype[12] = MSGSTR(2202, "Array controller device");
	dtype[13] = MSGSTR(2203, "SES device");
	dtype[14] = MSGSTR(71, "Reserved");
	dtype[15] = MSGSTR(71, "Reserved");



	/*
	 * Get subcommand.
	 */
	if ((getaction(argv[optind], Keywords, &cmd)) == EOK) {
		optind++;
		if ((cmd != PROBE) && (cmd != FCAL_UPDATE) &&
		(cmd != QLGC_UPDATE) && (cmd != FCODE_UPDATE) &&
		(cmd != INSERT_DEVICE) && (cmd != SYSDUMP) && (cmd != AU) &&
		(cmd != PORT) && (cmd != CREATE_FAB) && (optind >= argc)) {
			(void) fprintf(stderr,
			MSGSTR(2204,
			"Error: enclosure or pathname not specified.\n"));
			USEAGE();
			exit(-1);
		}
	} else {
		(void) fprintf(stderr,
		MSGSTR(2205, "%s: subcommand not specified.\n"),
		whoami);
		USEAGE();
		exit(-1);
	}

	/* Extract & Save subcommand options */
	if ((cmd == ENABLE) || (cmd == BYPASS)) {
		optstring = "Ffrab";
	} else if (cmd == FCODE_UPDATE) {
		optstring = "pd:";
	} else if (cmd == REMOVE_DEVICE) {
		optstring = "F";
	} else if (cmd == CREATE_FAB) {
		optstring = "f:";
	} else {
		optstring = "Fryszabepcdlvt:f:w:";
	}
	while ((c = getopt(argc, argv, optstring)) != EOF) {
	    switch (c) {
		case 'a':
			Options |= OPTION_A;
			break;
	    case 'b':
			Options |= OPTION_B;
			break;
		case 'c':
			Options |= OPTION_C;
			break;
		case 'd':
			Options |= OPTION_D;
			if (cmd == FCODE_UPDATE) {
			    file_name = optarg;
			}
			break;
		case 'e':
			Options |= OPTION_E;
			break;
		case 'f':
			Options |= OPTION_F;
			if (!((cmd == ENABLE) || (cmd == BYPASS))) {
				file_name = optarg;
			}
			break;
		case 'F':
			Options |= OPTION_CAPF;
			break;
		case 'l':
		    Options |= OPTION_L;
		    break;
		case 'p':
		    Options |= OPTION_P;
		    break;
		case 'r':
		    Options |= OPTION_R;
		    break;
		case 's':
		    Options |= SAVE;
		    break;
		case 't':
		    Options |= OPTION_T;
		    option_t_input = atoi(optarg);
		    break;
		case 'v':
		    Options |= OPTION_V;
		    break;
		case 'z':
		    Options |= OPTION_Z;
		    break;
		case 'y':
		    Options |= OPTION_Y;
		    break;
		default:
		    /* Note: getopt prints an error if invalid option */
		    USEAGE()
		    exit(-1);
	    } /* End of switch(c) */
	}
	if ((cmd != PROBE) && (cmd != FCAL_UPDATE) &&
	    (cmd != QLGC_UPDATE) && (cmd != FCODE_UPDATE) &&
	    (cmd != INSERT_DEVICE) && (cmd != SYSDUMP) &&
	    (cmd != AU) && (cmd != PORT) &&
	    (cmd != CREATE_FAB) && (optind >= argc)) {
	    (void) fprintf(stderr,
		MSGSTR(2206,
		"Error: enclosure or pathname not specified.\n"));
	    USEAGE();
	    exit(-1);
	}
	path_index = optind;

	/*
	 * Check if the file supplied with the -f option is valid
	 * Some sub commands (bypass for example) use the -f option
	 * for other reasons. In such cases, "file_name" should be
	 * NULL.
	 */
	if ((file_name != NULL) && (Options & OPTION_F)) {
		if ((temp_fd = open(file_name, O_RDONLY)) == -1) {
			perror(file_name);
			exit(-1);
		} else {
			close(temp_fd);
		}
	}

	/* Determine which mode to operate in (FC-HBA or original) */
	USE_FCHBA = use_fchba();

	switch (cmd)	{
	    case	DISPLAY:
		if (Options &
		    ~(PVERBOSE | OPTION_A | OPTION_Z | OPTION_R |
		    OPTION_P | OPTION_V | OPTION_L | OPTION_E | OPTION_T)) {
		    USEAGE();
		    exit(-1);
		}
		/* Display object(s) */
		if (USE_FCHBA) {
		    exit_code = fchba_display_config(&argv[path_index],
			    option_t_input, argc - path_index);
		} else {
		    exit_code = adm_display_config(&argv[path_index]);
		}
		break;

	    case	DOWNLOAD:
		    if (Options &
			~(PVERBOSE | OPTION_F | SAVE)) {
			USEAGE();
			exit(-1);
		    }
		    adm_download(&argv[path_index], file_name);
		    break;

	    case	ENCLOSURE_NAMES:
		    if (Options & ~PVERBOSE) {
			USEAGE();
			exit(-1);
		    }
		    up_encl_name(&argv[path_index], argc);
		    break;

	    case	FAILOVER:
		    if (Options & ~PVERBOSE) {
			USEAGE();
			exit(-1);
		    }
		    adm_failover(&argv[path_index]);
		    break;

	    case	INQUIRY:
		if (Options & ~(PVERBOSE)) {
			USEAGE();
			exit(-1);
		}
		if (USE_FCHBA) {
		    exit_code = fchba_inquiry(&argv[path_index]);
		} else {
		    exit_code = adm_inquiry(&argv[path_index]);
		}
		break;

	    case	PROBE:
		if (Options & ~(PVERBOSE | OPTION_P)) {
			USEAGE();
			exit(-1);
		}
		/*
		 * A special check just in case someone entered
		 * any characters after the -p or the probe.
		 *
		 * (I know, a nit.)
		 */
		if (((Options & PVERBOSE) && (Options & OPTION_P) &&
			(argc != 4)) ||
			(!(Options & PVERBOSE) && (Options & OPTION_P) &&
			(argc != 3)) ||
			((Options & PVERBOSE) && (!(Options & OPTION_P)) &&
			(argc != 3)) ||
			(!(Options & PVERBOSE) && (!(Options & OPTION_P)) &&
			(argc != 2))) {
			(void) fprintf(stderr,
			MSGSTR(114, "Error: Incorrect number of arguments.\n"));
			(void) fprintf(stderr,  MSGSTR(2208,
			"Usage: %s [-v] subcommand [option]\n"), whoami);
			exit(-1);
		}
		if (USE_FCHBA) {
		    exit_code = fchba_non_encl_probe();
		} else {
		    pho_probe();
		    non_encl_probe();
		}
		break;

	    case	FCODE_UPDATE:	/* Update Fcode in all cards */
			if ((Options & ~(PVERBOSE)) &
			    ~(OPTION_P | OPTION_D) || argv[path_index]) {
				USEAGE();
				exit(-1);
			}
			if (!((Options & (OPTION_P | OPTION_D)) &&
			    !((Options & OPTION_P) && (Options & OPTION_D)))) {
				USEAGE();
				exit(-1);
			}
			if (adm_fcode(Options & PVERBOSE, file_name) != 0) {
				exit(-1);
			}
			break;

	    case	QLGC_UPDATE:	/* Update Fcode in PCI HBA card(s) */
			if ((Options & ~(PVERBOSE)) & ~(OPTION_F) ||
			    argv[path_index]) {
				USEAGE();
				exit(-1);
			}
			if (q_qlgc_update(Options & PVERBOSE, file_name) != 0) {
				exit(-1);
			}
			break;

	    case	FCAL_UPDATE:	/* Update Fcode in Sbus soc+ card */
			if ((Options & ~(PVERBOSE)) & ~(OPTION_F) ||
			    argv[path_index]) {
				USEAGE();
				exit(-1);
			}
			exit_code = fcal_update(Options & PVERBOSE, file_name);
			break;

	    case	SET_BOOT_DEV:   /* Set boot-device variable in nvram */
			exit_code = setboot(Options & OPTION_Y,
				Options & PVERBOSE, argv[path_index]);
		break;

	    case	LED:
		if (Options & ~(PVERBOSE)) {
			USEAGE();
			exit(-1);
		}
		adm_led(&argv[path_index], L_LED_STATUS);
		break;
	    case	LED_ON:
		if (Options & ~(PVERBOSE)) {
			USEAGE();
			exit(-1);
		}
		adm_led(&argv[path_index], L_LED_ON);
		break;
	    case	LED_OFF:
		if (Options & ~(PVERBOSE)) {
			USEAGE();
			exit(-1);
		}
		adm_led(&argv[path_index], L_LED_OFF);
		break;
	    case	LED_BLINK:
		if (Options & ~(PVERBOSE)) {
			USEAGE();
			exit(-1);
		}
		adm_led(&argv[path_index], L_LED_RQST_IDENTIFY);
		break;
	    case	PASSWORD:
		if (Options & ~(PVERBOSE))  {
			USEAGE();
			exit(-1);
		}
		up_password(&argv[path_index]);
		break;

	    case	RESERVE:

		if (Options & (~PVERBOSE)) {
			USEAGE();
			exit(-1);
		}
		VERBPRINT(MSGSTR(2209,
			"  Reserving: \n %s\n"), argv[path_index]);
		if (USE_FCHBA) {
		    struct stat sbuf;
		    /* Just stat the argument and make sure it exists */
		    if (stat(argv[path_index], &sbuf) < 0) {
			(void) fprintf(stderr, "%s: ", whoami);
			(void) fprintf(stderr,
				MSGSTR(112, "Error: Invalid pathname (%s)"),
				argv[path_index]);
			(void) fprintf(stderr, "\n");
			exit(-1);
		    }
		    path_phys = argv[path_index];
		    if (err = scsi_reserve(path_phys)) {
			(void) print_errString(err, argv[path_index]);
			exit(-1);
		    }
		} else {
		    exit_code = adm_reserve(argv[path_index]);
		}
		break;

	    case	RELEASE:
		if (Options & (~PVERBOSE)) {
			USEAGE();
			exit(-1);
		}
		VERBPRINT(MSGSTR(2210, "  Canceling Reservation for:\n %s\n"),
		    argv[path_index]);
		if (USE_FCHBA) {
		    struct stat sbuf;
		    /* Just stat the argument and make sure it exists */
		    if (stat(argv[path_index], &sbuf) < 0) {
			(void) fprintf(stderr, "%s: ", whoami);
			(void) fprintf(stderr,
				MSGSTR(112, "Error: Invalid pathname (%s)"),
				argv[path_index]);
			(void) fprintf(stderr, "\n");
			exit(-1);
		    }
		    path_phys = argv[path_index];
		    if (err = scsi_release(path_phys)) {
			(void) print_errString(err, argv[path_index]);
			exit(-1);
		    }
		} else {
		    exit_code = adm_release(argv[path_index]);
		}
		break;

	    case	START:
		if (Options & ~(PVERBOSE)) {
			USEAGE();
			exit(-1);
		}
		exit_code = adm_start(&argv[path_index]);
		break;

	    case	STOP:
		if (Options & ~(PVERBOSE)) {
			USEAGE();
			exit(-1);
		}
		exit_code = adm_stop(&argv[path_index]);
		break;

	    case	POWER_OFF:
		if (Options & ~(PVERBOSE | OPTION_CAPF)) {
			USEAGE();
			exit(-1);
		}
		exit_code = adm_power_off(&argv[path_index], 1);
		break;

	    case	POWER_ON:
		if (Options & (~PVERBOSE)) {
			USEAGE();
			exit(-1);
		}
		exit_code = adm_power_off(&argv[path_index], 0);
		break;

	/*
	 * EXPERT commands.
	 */

	    case	FORCELIP:
		if (!(Options & EXPERT) || (Options & ~(PVERBOSE | EXPERT))) {
			E_USEAGE();
			exit(-1);
		}
		exit_code = adm_forcelip(&argv[path_index]);
		break;

	    case	BYPASS:
		if (!(Options & EXPERT) || (Options & ~(PVERBOSE | EXPERT |
			OPTION_CAPF | OPTION_A | OPTION_B | OPTION_F |
			OPTION_R)) || !(Options & (OPTION_A | OPTION_B)) ||
			((Options & OPTION_A) && (Options & OPTION_B))) {
			E_USEAGE();
			exit(-1);
		}
		adm_bypass_enable(&argv[path_index], 1);
		break;

	    case	ENABLE:
		if (!(Options & EXPERT) || (Options & ~(PVERBOSE | EXPERT |
			OPTION_CAPF | OPTION_A | OPTION_B | OPTION_F |
			OPTION_R)) || !(Options & (OPTION_A | OPTION_B)) ||
			((Options & OPTION_A) && (Options & OPTION_B))) {
			E_USEAGE();
			exit(-1);
		}
		adm_bypass_enable(&argv[path_index], 0);
		break;
	    case	LUX_P_OFFLINE:	/* Offline a port */
		if (!(Options & EXPERT) || (Options & ~(PVERBOSE | EXPERT))) {
			E_USEAGE();
			exit(-1);
		}
		exit_code = adm_port_offline_online(&argv[path_index],
		    LUX_P_OFFLINE);
		break;

	    case	LUX_P_ONLINE:	/* Online a port */
		if (!(Options & EXPERT) || (Options & ~(PVERBOSE | EXPERT))) {
			E_USEAGE();
			exit(-1);
		}
		exit_code = adm_port_offline_online(&argv[path_index],
		    LUX_P_ONLINE);
		break;

	    case	RDLS:
		if (!(Options & EXPERT) || (Options & ~(PVERBOSE | EXPERT))) {
			E_USEAGE();
			exit(-1);
		}
		if (USE_FCHBA) {
		    exit_code = fchba_display_link_status(&argv[path_index]);
		} else {
		    display_link_status(&argv[path_index]);
		}
		break;

	    case	CREATE_FAB:
		if (!(Options & (EXPERT | OPTION_F)) ||
			(Options & ~(PVERBOSE | EXPERT | OPTION_F))) {
			E_USEAGE();
			exit(-1);
		}
		if (read_repos_file(file_name) != 0) {
			exit(-1);
		}
		break;

	/*
	 * Undocumented commands.
	 */

	    case	CHECK_FILE:	/* Undocumented Cmd */
		if (Options & ~(PVERBOSE)) {
			USEAGE();
			exit(-1);
		}
		exit_code = adm_check_file(&argv[path_index],
		    (Options & PVERBOSE));
		break;

	    case	DUMP:		/* Undocumented Cmd */
		if (!(Options & EXPERT) || (Options & ~(PVERBOSE | EXPERT))) {
			USEAGE();
			exit(-1);
		}
		dump(&argv[path_index]);
		break;

	    case	DUMP_MAP:	/* Undocumented Cmd */
		if (!(Options & EXPERT) || (Options & ~(PVERBOSE | EXPERT))) {
			USEAGE();
			exit(-1);
		}
		if (USE_FCHBA) {
		    exit_code = fchba_dump_map(&argv[path_index]);
		} else {
		    dump_map(&argv[path_index]);
		}
		break;

	    case	SYSDUMP:
			if (Options & ~(PVERBOSE)) {
			USEAGE();
			exit(-1);
		}
		if (err = sysdump(Options & PVERBOSE)) {
		    (void) print_errString(err, NULL);
		    exit(-1);
		}
		break;

	    case	PORT: /* Undocumented command */
		if (!(Options & EXPERT) || (Options & ~(PVERBOSE | EXPERT))) {
			USEAGE();
			exit(-1);
		}
		if (USE_FCHBA) {
		    exit_code = fchba_display_port(Options & PVERBOSE);
		} else {
		    exit_code = adm_display_port(Options & PVERBOSE);
		}
		break;

	    case	EXT_LOOPBACK:
		if (!(Options & EXPERT) || (Options & ~(PVERBOSE | EXPERT))) {
			USEAGE();
			exit(-1);
		}
		if (adm_port_loopback(argv[path_index], EXT_LOOPBACK) < 0) {
			exit(-1);
		}
		break;

	    case	INT_LOOPBACK:
		if (!(Options & EXPERT) || (Options & ~(PVERBOSE | EXPERT))) {
			USEAGE();
			exit(-1);
		}
		if (adm_port_loopback(argv[path_index], INT_LOOPBACK) < 0) {
			exit(-1);
		}
		break;

	    case	NO_LOOPBACK:
		if (!(Options & EXPERT) || (Options & ~(PVERBOSE | EXPERT))) {
			USEAGE();
			exit(-1);
		}
		if (adm_port_loopback(argv[path_index], NO_LOOPBACK) < 0) {
			exit(-1);
		}
		break;

	    case	VERSION:
		break;


	    case	INSERT_DEVICE:
			if (argv[path_index] == NULL) {
				if ((err = h_insertSena_fcdev()) != 0) {
					(void) print_errString(err, NULL);
					exit(-1);
				}
			} else if ((err = hotplug(INSERT_DEVICE,
					&argv[path_index],
					Options & PVERBOSE,
					Options & OPTION_CAPF)) != 0) {
				(void) print_errString(err, argv[path_index]);
				exit(-1);
			}
			break;
	    case	REMOVE_DEVICE:
			if (err = hotplug(REMOVE_DEVICE, &argv[path_index],
			    Options & PVERBOSE, Options & OPTION_CAPF)) {
			    (void) print_errString(err, argv[path_index]);
			    exit(-1);
			}
			break;

	/* for hotplug device operations */
	    case	DEV_ONLINE:
	    case	DEV_OFFLINE:
	    case	DEV_GETSTATE:
	    case	DEV_RESET:
	    case	BUS_QUIESCE:
	    case	BUS_UNQUIESCE:
	    case	BUS_GETSTATE:
	    case	BUS_RESET:
	    case	BUS_RESETALL:
		if (!(Options & EXPERT) || (Options & ~(PVERBOSE | EXPERT))) {
			E_USEAGE();
			exit(-1);
		}
		if (USE_FCHBA) {
		    if (fchba_hotplug_e(cmd, &argv[path_index],
			    Options & PVERBOSE, Options & OPTION_CAPF) != 0) {
			exit(-1);
		    }
		} else {
		    if (hotplug_e(cmd, &argv[path_index],
			    Options & PVERBOSE, Options & OPTION_CAPF) != 0) {
			exit(-1);
		    }
		}
		break;

	    default:
		(void) fprintf(stderr,
		    MSGSTR(2213, "%s: subcommand decode failed.\n"),
		    whoami);
		USEAGE();
		exit(-1);
	}
	return (exit_code);
}
