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

/*
 * rmf_main.c :
 *	The file containing main() for rmformat. The command line
 *	options are parsed in this file.
 */


#include <priv_utils.h>
#include "rmformat.h"

int32_t b_flag = 0;
int32_t c_flag = 0;
int32_t D_flag = 0;
int32_t e_flag = 0;
int32_t F_flag = 0;
int32_t H_flag = 0;
int32_t l_flag = 0;
int32_t p_flag = 0;
int32_t R_flag = 0;
int32_t s_flag = 0;
int32_t U_flag = 0;
int32_t V_flag = 0;
int32_t W_flag = 0;
int32_t w_flag = 0;

static char *myname;
char *slice_file = NULL;
char *label;
diskaddr_t repair_blk_no;
int32_t quick_format = 0;
int32_t long_format = 0;
int32_t force_format = 0;
int32_t rw_protect_enable = 0;
int32_t rw_protect_disable = 0;
int32_t wp_enable_passwd = 0;
int32_t wp_disable_passwd = 0;
int32_t wp_enable = 0;
int32_t wp_disable = 0;
int32_t verify_write = 0;
char *dev_name = NULL;

static void usage(char *);
void check_invalid_combinations();
void check_invalid_combinations_again(int32_t);
extern uint64_t my_atoll(char *ptr);
extern void my_perror(char *err_string);
void process_options();

int
main(int32_t argc, char **argv)
{
	int i;
	char *tmp_ptr;

	/*
	 * This program requires file_dac_read, file_dac_write,
	 * proc_fork, proc_exec, and sys_devices privileges.
	 *
	 * child processes require the sys_mount privilege
	 */
	(void) __init_suid_priv(PU_INHERITPRIVS,
	    PRIV_FILE_DAC_READ, PRIV_FILE_DAC_WRITE, PRIV_PROC_FORK,
	    PRIV_PROC_EXEC, PRIV_SYS_MOUNT, PRIV_SYS_DEVICES, NULL);

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

	(void) textdomain(TEXT_DOMAIN);

	myname = argv[0];
	DPRINTF1("myname %s\n", myname);

	while ((i = getopt(argc, argv, "b:c:DeF:HlpR:s:tUV:W:w:")) != -1) {
		DPRINTF1("arg %c\n", i);
		switch (i) {
		case 'b' :
			b_flag++;
			label = strdup(optarg);
			if (strlen(label) > 8) {
				(void) fprintf(stderr, gettext("Label is \
restricted to 8 characters.\n"));
				__priv_relinquish();
				exit(1);
			}

			break;

		case 'c' :
			c_flag++;
			tmp_ptr = strdup(optarg);
			errno = 0;
			repair_blk_no = my_atoll(tmp_ptr);
			if (repair_blk_no == (diskaddr_t)(-1)) {
				free(tmp_ptr);
				usage("invalid block number");
			}

			DPRINTF1(" block no. %llu\n", repair_blk_no);
			free(tmp_ptr);
			break;

		case 'D' :
			D_flag++;
			break;

		case 'e' :
			e_flag++;
			break;

		case 'F' :
			F_flag++;
			tmp_ptr = strdup(optarg);
			if (strcmp(tmp_ptr, "quick") == 0) {
				DPRINTF("q");
				quick_format = 1;
			} else if (strcmp(tmp_ptr, "long") == 0) {
				DPRINTF("l");
				long_format = 1;
			} else if (strcmp(tmp_ptr, "force") == 0) {
				DPRINTF("f");
				force_format = 1;
			} else {
				free(tmp_ptr);
				usage("invalid argument for option -F");
			}
			free(tmp_ptr);
			break;

		case 'H' :
			H_flag++;
			break;

		case 'l' :
			l_flag++;
			break;

		case 'p' :
			p_flag++;
			break;

		case 'R' :
			R_flag++;
			tmp_ptr = strdup(optarg);
			if (strcmp(tmp_ptr, "enable") == 0) {
				rw_protect_enable++;
			} else if (strcmp(tmp_ptr, "disable") == 0) {
				rw_protect_disable++;
			} else {
				usage("Invalid argument for -R option");
			}
			free(tmp_ptr);
			break;

		case 's' :
			s_flag++;

			slice_file = strdup(optarg);
			break;

		case 'U' :
			U_flag++;
			break;

		case 'V' :
			V_flag++;
			tmp_ptr = strdup(optarg);
			if (strcmp(tmp_ptr, "read") == 0) {
				verify_write = 0;
			} else if (strcmp(tmp_ptr, "write") == 0) {
				verify_write = 1;
			} else {
				usage("Invalid argument for -V option");
			}
			free(tmp_ptr);
			break;

		case 'W' :
			W_flag++;
			tmp_ptr = strdup(optarg);
			if (strcmp(tmp_ptr, "enable") == 0) {
				wp_enable_passwd++;
			} else if (strcmp(tmp_ptr, "disable") == 0) {
				wp_disable_passwd++;
			} else {
				usage("Invalid argument for -W option");
			}
			free(tmp_ptr);
			break;

		case 'w' :
			w_flag++;
			tmp_ptr = strdup(optarg);
			if (strcmp(tmp_ptr, "enable") == 0) {
				wp_enable++;
			} else if (strcmp(tmp_ptr, "disable") == 0) {
				wp_disable++;
			} else {
				usage("Invalid arguments for -w option");
			}
			free(tmp_ptr);
			break;

		default:
			usage("");
			break;
		}
	}
	if (optind < argc -1) {
		usage("more than one device name argument");
		/* NOTREACHED */
	}

	if (optind == argc -1) {
		dev_name = argv[optind];
	} else if (optind == 1) {
		/* list devices by default */
		l_flag++;
	} else if ((optind == argc) && !l_flag) {
		(void) fprintf(stderr,
		    gettext("No device specified.\n"));
		__priv_relinquish();
		exit(1);
#if 0
		(void) printf("Using floppy device\n");
		dev_name = "/dev/rdiskette";
#endif /* 0 */
	}

	process_options();

	/* Remove the privileges we gave. */
	__priv_relinquish();
	return (0);
}

static void
usage(char *str)
{

	if (strlen(str)) {
		(void) fprintf(stderr, "%s : ", myname);
		(void) fprintf(stderr, gettext(str));
		(void) fprintf(stderr, "\n");
	}

	(void) fprintf(stderr, "Usage:\n");
	(void) fprintf(stderr, gettext("\t%s \
[ -DeHpU ] [ -b label ] [ -c blockno ] [ -F quick|long|force ] \
[ -R enable|disable ] [ -s filename ] [ -V read|write ] \
[ -w enable|disable ] [ -W enable|disable ] devname \n"), myname);
	(void) fprintf(stderr, gettext("\t%s -l [ devname ]\n"),
	    myname);
	__priv_relinquish();
	exit(1);
}

void
check_invalid_combinations()
{

	/* Inherited from FLOPPY */

	if (D_flag && H_flag) {
		usage("Options -D and -H incompatible");
	}

	if (D_flag && F_flag) {
		usage("Options -D and -F incompatible");
	}

	if (H_flag && F_flag) {
		usage("Options -H and -F incompatible");
	}

	/* rmformat additions */

	if ((w_flag && W_flag) || (w_flag && R_flag) || (W_flag && R_flag)) {
		usage("Options -w, -W and -R incompatible");
	}

	if (c_flag && F_flag) {
		usage("Options -c, -F incompatible");
	}

	/* l_flag is mutually exclusive of these flags */
	if (l_flag && (D_flag + e_flag + H_flag + p_flag + U_flag +
	    b_flag + c_flag + F_flag + R_flag + s_flag + V_flag +
	    w_flag + W_flag)) {
		usage("Options incompatible");
	}
}


void
check_invalid_combinations_again(int32_t medium_type)
{
	if ((medium_type != SM_FLOPPY) &&
	    (medium_type != SM_PCMCIA_MEM)) {
		if (D_flag || H_flag) {
			usage("-D, -H  options are compatible with floppy and \
PCMCIA memory cards only.");
		}
	}
}
