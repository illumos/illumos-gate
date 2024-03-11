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
 *
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * raidctl.c is the entry file of RAID configuration utility.
 */

#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <langinfo.h>
#include <regex.h>
#include <locale.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>
#include <raidcfg.h>


#define	TRUE		1
#define	FALSE		0

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * Return value of command
 */
#define	SUCCESS		0
#define	INVALID_ARG	1
#define	FAILURE		2

/*
 * Initial value of variables
 */
#define	INIT_HANDLE_VALUE	-3
#define	MAX64BIT		0xffffffffffffffffull
#define	MAX32BIT		0xfffffffful

/*
 * Flag of set or unset HSP
 */
#define	HSP_SET		1
#define	HSP_UNSET	0

/*
 * Operate codes of command
 */
#define	DO_HW_RAID_NOP		-1
#define	DO_HW_RAID_HELP		0
#define	DO_HW_RAID_CREATEO	1
#define	DO_HW_RAID_CREATEN	2
#define	DO_HW_RAID_DELETE	3
#define	DO_HW_RAID_LIST		4
#define	DO_HW_RAID_FLASH	5
#define	DO_HW_RAID_HSP		6
#define	DO_HW_RAID_SET_ATTR	7
#define	DO_HW_RAID_SNAPSHOT	8

#define	LOWER_H	(1 << 0)
#define	LOWER_C	(1 << 1)
#define	LOWER_D	(1 << 2)
#define	LOWER_L	(1 << 3)
#define	LOWER_R	(1 << 4)
#define	LOWER_Z	(1 << 5)
#define	LOWER_G	(1 << 6)
#define	LOWER_A	(1 << 7)
#define	LOWER_S	(1 << 8)
#define	LOWER_P	(1 << 9)
#define	LOWER_F	(1 << 10)
#define	UPPER_S	(1 << 11)
#define	UPPER_C	(1 << 12)
#define	UPPER_F	(1 << 13)

/* Add a ARRAY state (temporary) */
#define	ARRAY_STATE_SYNC	100

/*
 * Function and strings to properly localize our prompt.
 * So for example in German it would ask (ja/nein) or (yes/no) in
 * english.
 */
#ifndef SCHAR_MAX
#define	SCHAR_MAX	10
#endif

#define	RAIDCTL_LOCKF "/var/run/lockf_raidctl"

/* Locale setting */
static int	yes(void);
static int	rpmatch(char *s);
static char	*yesstr = NULL;
static char	*nostr = NULL;
static char	*yesexpr = NULL;

static char	*default_yesexpr = "^[yY]";
static char	*default_yesstr = "yes";
static char	*default_nostr = "no";

static regex_t	re;

#define	SET_DEFAULT_STRS \
	regfree(&re); \
	free(yesexpr); \
	free(yesstr); \
	free(nostr); \
	yesexpr = default_yesexpr; \
	yesstr = default_yesstr; \
	nostr = default_nostr;

#define	FREE_STRS \
	if (yesexpr != default_yesexpr) \
		free(yesexpr); \
	if (yesstr != default_yesstr) \
		free(yesstr); \
	if (nostr != default_nostr) \
		free(nostr);

/* program name */
static char	*prog_namep;


/*
 * Functions declaration
 */
static void helpinfo(char *prog_namep);
static int do_create_cidl(char *raid_levelp, char *capacityp, char *disk_argp,
    char *stripe_sizep, uint32_t f_flag, char **argv, uint32_t optind);
static int do_create_ctd(char *raid_levelp, char **disks_argpp,
    uint32_t disks_num, uint32_t argindex, uint32_t f_flag);
static int do_list(char *disk_argp, char **argv, uint32_t optind,
    uint8_t is_snapshot);
static int do_delete(uint32_t f_flag, char **argv, uint32_t optind);
static int do_flash(uint8_t f_flag, char *filep, char **ctls_argpp,
    uint32_t index, uint32_t ctl_num);
static int do_set_hsp(char *a_argp, char *disk_argp, char **argv,
    uint32_t optind);
static int do_set_array_attr(uint32_t f_flag, char *p_argp, char **argv,
    uint32_t optind);
static int snapshot_raidsystem(uint8_t recursive, uint8_t indent,
    uint8_t is_snapshot);
static int snapshot_ctl(raid_obj_handle_t ctl_handle, uint8_t recursive,
    uint8_t indent, uint8_t is_snapshot);
static int snapshot_array(raid_obj_handle_t array_handle,
    uint8_t indent, uint8_t is_sub, uint8_t is_snapshot);
static int snapshot_disk(uint32_t ctl_tag, raid_obj_handle_t disk_handle,
    uint8_t indent, uint8_t is_snapshot);
static int print_ctl_table(raid_obj_handle_t ctl_handle);
static int print_array_table(raid_obj_handle_t ctl_handle,
    raid_obj_handle_t array_handle);
static int print_disk_table(raid_obj_handle_t ctl_handle,
    raid_obj_handle_t disk_handle);
static int print_ctl_attr(raidcfg_controller_t *attrp);
static int print_array_attr(raidcfg_array_t *attrp);
static int print_arraypart_attr(raidcfg_arraypart_t *attrp);
static int print_disk_attr(raid_obj_handle_t ctl_handle,
    raid_obj_handle_t disk_handle, raidcfg_disk_t *attrp);
static void print_indent(uint8_t indent);
static int get_disk_handle_cidl(uint32_t ctl_tag, char *disks_argp,
    int *comps_nump, raid_obj_handle_t **handlespp);
static int get_disk_handle_ctd(int disks_num, char **disks_argpp,
    uint32_t *ctl_tagp, raid_obj_handle_t *disks_handlep);
static int get_ctl_tag(char *argp, uint32_t *ctl_tagp);
static int get_array_tag(char *argp, uint32_t *ctl_tagp,
    array_tag_t *array_tagp);
static int get_disk_tag_ctd(char *argp, disk_tag_t *disk_tagp,
    uint32_t *controller_id);
static int get_disk_tag_cidl(char *argp, disk_tag_t *disk_tagp);
static int calc_size(char *sizep, uint64_t *valp);
static int is_fully_numeric(char *strp);
static int size_to_string(uint64_t size, char *string, int len);
static int enter_raidctl_lock(int *fd);
static void exit_raidctl_lock(int fd);

/*
 * Entry function of raidctl command
 */
int
main(int argc, char **argv)
{
	/* operation index */
	int8_t findex = DO_HW_RAID_NOP;

	/* argument pointers */
	char *r_argp = NULL;
	char *z_argp = NULL;
	char *g_argp = NULL;
	char *a_argp = NULL;
	char *s_argp = NULL;
	char *p_argp = NULL;
	char *F_argp = NULL;
	char *C_argp = NULL;

	/*
	 * operation flags.
	 */
	uint8_t r_flag = FALSE;
	uint8_t f_flag = FALSE;
	uint8_t action = FALSE;
	uint64_t options = 0;

	/* index and temporary variables */
	int ret;
	int status;
	int c;

	/* fd for the filelock */
	int fd;

	if (enter_raidctl_lock(&fd) != SUCCESS) {
		return (FAILURE);
	}

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* parse command line, and get program name */
	if ((prog_namep = strrchr(argv[0], '/')) == NULL) {
		prog_namep = argv[0];
	} else {
		prog_namep++;
	}

	/* close error option messages from getopt */
	opterr = 0;

	/* get yes expression according to current locale */
	yesexpr = strdup(nl_langinfo(YESEXPR));
	yesstr = strdup(nl_langinfo(YESSTR));
	nostr = strdup(nl_langinfo(NOSTR));
	if (yesexpr == NULL || yesstr == NULL || nostr == NULL) {
		return (FAILURE);
	}

	/*
	 * If the was no expression or if there is a compile error
	 * use default yes expression.
	 */
	status = regcomp(&re, yesexpr, REG_EXTENDED | REG_NOSUB);
	if ((*yesexpr == '\0') ||
	    (*yesstr == '\0') ||
	    (*nostr == '\0') ||
	    (status != 0)) {
		SET_DEFAULT_STRS;
		if (regcomp(&re, default_yesexpr,
		    REG_EXTENDED | REG_NOSUB) != 0) {
			return (FALSE);
		}
	}

	while ((c = getopt(argc, argv,
	    "?hC:cdlF:r:z:g:a:s:p:fS")) != EOF) {
		switch (c) {
		case 'h':
		case '?':
			if (action == FALSE) {
				findex = DO_HW_RAID_HELP;
				action = TRUE;
				options |= LOWER_H;
			} else {
				findex = DO_HW_RAID_NOP;
			}
			break;
		case 'C':
			if (action == FALSE) {
				findex = DO_HW_RAID_CREATEN;
				C_argp = optarg;
				action = TRUE;
				options |= UPPER_C;
			} else {
				findex = DO_HW_RAID_NOP;
			}
			break;
		case 'c':
			if (action == FALSE) {
				findex = DO_HW_RAID_CREATEO;
				action = TRUE;
				options |= LOWER_C;
			} else {
				findex = DO_HW_RAID_NOP;
			}
			break;
		case 'd':
			if (action == FALSE) {
				findex = DO_HW_RAID_DELETE;
				action = TRUE;
				options |= LOWER_D;
			} else {
				findex = DO_HW_RAID_NOP;
			}
			break;
		case 'l':
			if (action == FALSE) {
				findex = DO_HW_RAID_LIST;
				action = TRUE;
				options |= LOWER_L;
			} else {
				findex = DO_HW_RAID_NOP;
			}
			break;
		case 'F':
			if (action == FALSE) {
				findex = DO_HW_RAID_FLASH;
				F_argp = optarg;
				action = TRUE;
				options |= UPPER_F;
			} else {
				findex = DO_HW_RAID_NOP;
			}
			break;
		case 'a':
			if (action == FALSE) {
				findex = DO_HW_RAID_HSP;
				a_argp = optarg;
				action = TRUE;
				options |= LOWER_A;
			} else {
				findex = DO_HW_RAID_NOP;
			}
			break;
		case 'p':
			if (action == FALSE) {
				findex = DO_HW_RAID_SET_ATTR;
				p_argp = optarg;
				action = TRUE;
				options |= LOWER_P;
			} else {
				findex = DO_HW_RAID_NOP;
			}
			break;
		case 'r':
			r_argp = optarg;
			r_flag = TRUE;
			options |= LOWER_R;
			break;
		case 'z':
			z_argp = optarg;
			options |= LOWER_Z;
			break;
		case 'g':
			g_argp = optarg;
			options |= LOWER_G;
			break;
		case 's':
			s_argp = optarg;
			options |= LOWER_S;
			break;
		case 'f':
			f_flag = TRUE;
			options |= LOWER_F;
			break;
		case 'S':
			if (action == FALSE) {
				findex = DO_HW_RAID_SNAPSHOT;
				action = TRUE;
				options |= UPPER_S;
			} else {
				findex = DO_HW_RAID_NOP;
			}
			break;
		default:
			(void) fprintf(stderr,
			    gettext("Invalid argument(s).\n"));
			exit_raidctl_lock(fd);
			FREE_STRS;
			regfree(&re);
			return (INVALID_ARG);
		}
	}

	/* parse options */
	switch (findex) {
	case DO_HW_RAID_HELP:
		if ((options & ~(LOWER_H)) != 0) {
			ret = INVALID_ARG;
		} else {
			helpinfo(prog_namep);
			ret = SUCCESS;
		}
		break;
	case DO_HW_RAID_CREATEO:
		if ((options & ~(LOWER_F | LOWER_C | LOWER_R)) != 0) {
			ret = INVALID_ARG;
		} else {
			if (r_flag != FALSE && f_flag == FALSE) {
				ret = do_create_ctd(r_argp, argv, argc - 4,
				    optind, f_flag);
			} else if (r_flag == FALSE && f_flag == FALSE) {
				ret = do_create_ctd(NULL, argv, argc - 2,
				    optind, f_flag);
			} else if (r_flag != FALSE && f_flag != FALSE) {
				ret = do_create_ctd(r_argp, argv, argc - 5,
				    optind, f_flag);
			} else {
				ret = do_create_ctd(NULL, argv, argc - 3,
				    optind, f_flag);
			}
		}
		break;
	case DO_HW_RAID_CREATEN:
		if ((options & ~(LOWER_F | UPPER_C | LOWER_R | LOWER_Z |
		    LOWER_S)) != 0) {
			ret = INVALID_ARG;
		} else {
			ret = do_create_cidl(r_argp, z_argp, C_argp, s_argp,
			    f_flag, argv, optind);
		}
		break;
	case DO_HW_RAID_DELETE:
		if ((options & ~(LOWER_F | LOWER_D)) != 0) {
			ret = INVALID_ARG;
		} else {
			ret = do_delete(f_flag, argv, optind);
		}
		break;
	case DO_HW_RAID_LIST:
		if ((options & ~(LOWER_L | LOWER_G)) != 0) {
			ret = INVALID_ARG;
		} else {
			ret = do_list(g_argp, argv, optind, FALSE);
		}
		break;
	case DO_HW_RAID_SNAPSHOT:
		if ((options & ~(UPPER_S | LOWER_G)) != 0) {
			ret = INVALID_ARG;
		} else {
			ret = do_list(g_argp, argv, optind, TRUE);
		}
		break;
	case DO_HW_RAID_FLASH:
		if ((options & ~(LOWER_F | UPPER_F)) != 0) {
			ret = INVALID_ARG;
		} else {
			if (f_flag == FALSE) {
				ret = do_flash(f_flag, F_argp, argv, optind,
				    argc - 3);
			} else {
				ret = do_flash(f_flag, F_argp, argv, optind,
				    argc - 4);
			}
		}
		break;
	case DO_HW_RAID_HSP:
		if ((options & ~(LOWER_A | LOWER_G)) != 0) {
			ret = INVALID_ARG;
		} else {
			ret = do_set_hsp(a_argp, g_argp, argv, optind);
		}
		break;
	case DO_HW_RAID_SET_ATTR:
		if ((options & ~(LOWER_F | LOWER_P)) != 0) {
			ret = INVALID_ARG;
		} else {
			ret = do_set_array_attr(f_flag, p_argp, argv, optind);
		}
		break;
	case DO_HW_RAID_NOP:
		if (argc == 1) {
			ret = do_list(g_argp, argv, optind, FALSE);
		} else {
			ret = INVALID_ARG;
		}
		break;
	default:
		ret = INVALID_ARG;
		break;
	}

	if (ret == INVALID_ARG) {
		(void) fprintf(stderr,
		    gettext("Invalid argument(s).\n"));
	}
	exit_raidctl_lock(fd);

	FREE_STRS;
	regfree(&re);
	return (ret);
}

/*
 * helpinfo(prog_namep)
 * This function prints help informations for usrs.
 */
static void
helpinfo(char *prog_namep)
{
	char quote = '"';

	(void) printf(gettext("%s [-f] -C %c<disks>%c [-r <raid_level>] "
	    "[-z <capacity>] [-s <stripe_size>] <controller>\n"), prog_namep,
	    quote, quote);

	(void) printf(gettext("%s [-f] -d <volume>\n"), prog_namep);

	(void) printf(gettext("%s [-f] -F <filename> <controller1> "
	    "[<controller2> ...]\n"), prog_namep);

	(void) printf(gettext("%s [-f] -p %c<param>=<value>%c <volume>\n"),
	    prog_namep, quote, quote);

	(void) printf(gettext("%s [-f] -c [-r <raid_level>] <disk1> <disk2> "
	    "[<disk3> ...]\n"), prog_namep);

	(void) printf(gettext("%s [-l]\n"), prog_namep);

	(void) printf(gettext("%s -l -g <disk> <controller>\n"), prog_namep);

	(void) printf(gettext("%s -l <volume>\n"), prog_namep);

	(void) printf(gettext("%s -l <controller1> [<controller2> ...]\n"),
	    prog_namep);

	(void) printf(gettext("%s -a {set | unset} -g <disk> "
	    "{<volume> | <controller>}\n"), prog_namep);

	(void) printf(gettext("%s -S [<volume> | <controller>]\n"), prog_namep);

	(void) printf(gettext("%s -S -g <disk> <controller>\n"), prog_namep);

	(void) printf(gettext("%s -h\n"), prog_namep);
}

/*
 * do_create_cidl(raid_levelp, capacityp, disks_argp, stripe_sizep,
 * f_flag, argv, optind)
 * This function creates a new RAID volume with specified arguments,
 * and returns result as SUCCESS, INVALID_ARG or FAILURE.
 * The "c.id.l" is used to express single physical disk. 'c' expresses
 * bus number, 'id' expresses target number, and 'l' expresses lun.
 * The physical disks represented by c.id.l may be invisible to OS, which
 * means physical disks attached to controllers are not accessible by
 * OS directly. The disks should be organized as a logical volume, and
 * the logical volume is exported to OS as a single unit. Some hardware
 * RAID controllers also support physical disks accessed by OS directly,
 * for example LSI1068. In this case, it's both OK to express physical
 * disk by c.id.l format or canonical ctd format.
 */
static int
do_create_cidl(char *raid_levelp, char *capacityp, char *disks_argp,
    char *stripe_sizep, uint32_t f_flag, char **argv, uint32_t optind)
{
	uint32_t ctl_tag = MAX32BIT;
	raid_obj_handle_t ctl_handle = INIT_HANDLE_VALUE;
	uint32_t raid_level = RAID_LEVEL_1;
	uint64_t capacity = 0;
	uint64_t stripe_size = (uint64_t)OBJ_ATTR_NONE;
	raid_obj_handle_t *disk_handlesp = NULL;
	raid_obj_handle_t array_handle = INIT_HANDLE_VALUE;
	raidcfg_controller_t ctl_attr;
	int comps_num = 0;
	int ret = 0;

	raidcfg_array_t array_attr;

	if (argv[optind] == NULL || argv[optind + 1] != NULL) {
		return (INVALID_ARG);
	}

	if (disks_argp == NULL) {
		return (INVALID_ARG);
	}

	/* Check controller tag */
	if (get_ctl_tag(argv[optind], &ctl_tag) != SUCCESS) {
		return (INVALID_ARG);
	}

	ctl_handle = raidcfg_get_controller(ctl_tag);
	if (ctl_handle <= 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ctl_handle));
		return (FAILURE);
	}

	if ((ret = raidcfg_get_attr(ctl_handle, &ctl_attr)) < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		return (FAILURE);
	}

	/* Get raid level */
	if (raid_levelp != NULL) {
		if (*raid_levelp == '1' &&
		    (*(raid_levelp + 1) == 'E' || *(raid_levelp + 1) == 'e')) {
			raid_level = RAID_LEVEL_1E;
		} else {
			if (is_fully_numeric(raid_levelp) == FALSE) {
				return (INVALID_ARG);
			}

			switch (atoi(raid_levelp)) {
			case 0:
				raid_level = RAID_LEVEL_0;
				break;
			case 1:
				raid_level = RAID_LEVEL_1;
				break;
			case 5:
				raid_level = RAID_LEVEL_5;
				break;
			case 10:
				raid_level = RAID_LEVEL_10;
				break;
			case 50:
				raid_level = RAID_LEVEL_50;
				break;
			default:
				return (INVALID_ARG);
			}
		}
	}

	/*
	 * The rang check of capacity and stripe size is performed in library,
	 * and it relates to hardware feature.
	 */

	/* Capacity in bytes. Capacity 0 means max available space. */
	if (capacityp != NULL) {
		if (*capacityp == '-' ||
		    calc_size(capacityp, &capacity) != SUCCESS) {
			return (INVALID_ARG);
		}
	}

	/* Stripe size in bytes */
	if (stripe_sizep != NULL) {
		if (calc_size(stripe_sizep, &stripe_size) != SUCCESS ||
		    *stripe_sizep == '-') {
			return (INVALID_ARG);
		}
	}

	/* Open controller before accessing its object */
	if ((ret = raidcfg_open_controller(ctl_handle, NULL)) < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		return (FAILURE);
	}

	/* Get disks' handles */
	if ((ret = get_disk_handle_cidl(ctl_tag, disks_argp, &comps_num,
	    &disk_handlesp)) != SUCCESS) {
		(void) raidcfg_close_controller(ctl_handle, NULL);
		return (ret);
	}

	if (f_flag == FALSE) {
		(void) fprintf(stdout, gettext("Creating RAID volume "
		    "will destroy all data on spare space of member disks, "
		    "proceed (%s/%s)? "), yesstr, nostr);
		if (!yes()) {
			(void) fprintf(stdout, gettext("RAID volume "
			    "not created.\n\n"));
			(void) raidcfg_close_controller(ctl_handle, NULL);
			free(disk_handlesp);
			return (SUCCESS);
		}
	}

	/* Create array */
	array_handle = raidcfg_create_array(comps_num,
	    disk_handlesp, raid_level, capacity, stripe_size, NULL);

	if (array_handle <= 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(array_handle));
		free(disk_handlesp);
		(void) raidcfg_close_controller(ctl_handle, NULL);
		return (FAILURE);
	}

	/* Get attribute of the new created array */
	if ((ret = raidcfg_get_attr(array_handle, &array_attr)) < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		free(disk_handlesp);
		(void) raidcfg_close_controller(ctl_handle, NULL);
		return (FAILURE);
	}

	(void) fprintf(stdout, gettext("Volume c%ut%llud%llu is created "
	    "successfully!\n"), ctl_tag, array_attr.tag.idl.target_id,
	    array_attr.tag.idl.lun);

	/* Print attribute of array */
	(void) print_array_table(ctl_handle, array_handle);

	/* Close controller */
	(void) raidcfg_close_controller(ctl_handle, NULL);

	free(disk_handlesp);
	return (SUCCESS);
}

/*
 * do_create_ctd(raid_levelp, disks_argpp, disks_num, argindex, f_flag)
 * This function creates array with specified arguments, and return result
 * as SUCCESS, FAILURE, or INVALID_ARG. It only supports LSI MPT controller
 * to be compatible with old raidctl. The capacity and stripe size can't
 * be specified for LSI MPT controller, and they use zero and default value.
 * The "ctd" is the canonical expression of physical disks which are
 * accessible by OS.
 */
static int
do_create_ctd(char *raid_levelp, char **disks_argpp, uint32_t disks_num,
    uint32_t argindex, uint32_t f_flag)
{
	uint32_t ctl_tag = MAX32BIT;
	raid_obj_handle_t ctl_handle = INIT_HANDLE_VALUE;
	uint32_t raid_level = RAID_LEVEL_1;
	uint64_t capacity = 0;
	uint32_t stripe_size = (uint32_t)OBJ_ATTR_NONE;
	raid_obj_handle_t *disk_handlesp = NULL;
	raid_obj_handle_t array_handle = INIT_HANDLE_VALUE;
	raidcfg_controller_t ctl_attr;
	int ret;

	raidcfg_array_t array_attr;
	int i, j;

	/* Check disks parameter */
	if (disks_argpp == NULL || disks_num < 2) {
		return (INVALID_ARG);
	}

	for (i = 0, j = argindex; i < disks_num; i++, j++) {
		if (disks_argpp[j] == NULL) {
			return (INVALID_ARG);
		}
	}

	/*
	 * We need check if the raid_level string is fully numeric. If user
	 * input string with unsupported letters, such as "s10", atoi() will
	 * return zero because it is an illegal string, but it doesn't mean
	 * RAID_LEVEL_0.
	 */
	if (raid_levelp != NULL) {
		if (*raid_levelp == '1' &&
		    (*(raid_levelp + 1) == 'E' || *(raid_levelp + 1) == 'e')) {
			raid_level = RAID_LEVEL_1E;
		} else {
			if (is_fully_numeric(raid_levelp) == FALSE) {
				return (INVALID_ARG);
			}

			switch (atoi(raid_levelp)) {
			case 0:
				raid_level = RAID_LEVEL_0;
				break;
			case 1:
				raid_level = RAID_LEVEL_1;
				break;
			case 5:
				raid_level = RAID_LEVEL_5;
				break;
			default:
				return (INVALID_ARG);
			}
		}
	}

	/* Get disks tag and controller tag */
	disk_handlesp = (raid_obj_handle_t *)calloc(disks_num + 2,
	    sizeof (raid_obj_handle_t));
	if (disk_handlesp == NULL) {
		return (FAILURE);
	}

	disk_handlesp[0] = OBJ_SEPARATOR_BEGIN;
	disk_handlesp[disks_num + 1] = OBJ_SEPARATOR_END;

	if ((ret = get_disk_handle_ctd(disks_num, &disks_argpp[argindex],
	    &ctl_tag, &disk_handlesp[1])) != SUCCESS) {
		free(disk_handlesp);
		return (ret);
	}

	/* LIB API should check whether all disks here belong to one ctl. */
	/* get_disk_handle_ctd has opened controller. */
	ctl_handle = raidcfg_get_controller(ctl_tag);

	if (ctl_handle <= 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ctl_handle));
		(void) raidcfg_close_controller(ctl_handle, NULL);
		free(disk_handlesp);
		return (FAILURE);
	}

	/* Check if the controller is host raid type */
	if ((ret = raidcfg_get_attr(ctl_handle, &ctl_attr)) < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		(void) raidcfg_close_controller(ctl_handle, NULL);
		free(disk_handlesp);
		return (FAILURE);
	}

	if ((ctl_attr.capability & RAID_CAP_DISK_TRANS) == 0) {
		/* -c only support host raid controller, return failure here */
		(void) fprintf(stderr,
		    gettext("Option -c only supports host raid controller.\n"));
		(void) raidcfg_close_controller(ctl_handle, NULL);
		free(disk_handlesp);
		return (FAILURE);
	}

	if (f_flag == FALSE) {
		(void) fprintf(stdout, gettext("Creating RAID volume "
		    "will destroy all data on spare space of member disks, "
		    "proceed (%s/%s)? "), yesstr, nostr);
		if (!yes()) {
			(void) fprintf(stdout, gettext("RAID volume "
			    "not created.\n\n"));
			free(disk_handlesp);
			(void) raidcfg_close_controller(ctl_handle, NULL);
			return (SUCCESS);
		}
	}

	/*
	 * For old raidctl, capacity is 0, which means to creates
	 * max possible capacity of array.
	 */

	array_handle = raidcfg_create_array(disks_num + 2,
	    disk_handlesp, raid_level, capacity, stripe_size, NULL);

	if (array_handle <= 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(array_handle));
		free(disk_handlesp);
		(void) raidcfg_close_controller(ctl_handle, NULL);
		return (FAILURE);
	}

	/* Get attribute of array */
	if ((ret = raidcfg_get_attr(array_handle, &array_attr)) < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		free(disk_handlesp);
		(void) raidcfg_close_controller(ctl_handle, NULL);
		return (FAILURE);
	}

	/* Close controller */
	(void) raidcfg_close_controller(ctl_handle, NULL);

	/* Print feedback for user */
	(void) fprintf(stdout,
	    gettext("Volume c%ut%llud%llu is created successfully!\n"),
	    ctl_tag, array_attr.tag.idl.target_id,
	    array_attr.tag.idl.lun);
	free(disk_handlesp);
	return (SUCCESS);
}

/*
 * do_list(disk_arg, argv, optind, is_snapshot)
 * This function lists RAID's system configuration. It supports various RAID
 * controller. The return value can be SUCCESS, FAILURE, or INVALID_ARG.
 */
static int
do_list(char *disk_argp, char **argv, uint32_t optind, uint8_t is_snapshot)
{
	uint32_t ctl_tag = MAX32BIT;
	raid_obj_handle_t ctl_handle = INIT_HANDLE_VALUE;
	raid_obj_handle_t disk_handle = INIT_HANDLE_VALUE;
	raid_obj_handle_t array_handle = INIT_HANDLE_VALUE;
	disk_tag_t disk_tag;
	array_tag_t array_tag;

	int ret;

	/* print RAID system */
	if (disk_argp == NULL) {
		if (argv[optind] == NULL) {
			ret = snapshot_raidsystem(TRUE, 0, is_snapshot);
			return (ret);
		} else {
			if (is_fully_numeric(argv[optind]) == TRUE) {
				while (argv[optind] != NULL) {
					if (get_ctl_tag(argv[optind], &ctl_tag)
					    != SUCCESS) {
						ret = INVALID_ARG;
						optind++;
						continue;
					}
					ctl_handle =
					    raidcfg_get_controller(ctl_tag);
					if (ctl_handle <= 0) {
						(void) fprintf(stderr, "%s\n",
						    raidcfg_errstr(ctl_handle));
						ret = FAILURE;
						optind++;
						continue;
					}
					ret =
					    raidcfg_open_controller(ctl_handle,
					    NULL);
					if (ret < 0) {
						(void) fprintf(stderr, "%s\n",
						    raidcfg_errstr(ret));
						ret = FAILURE;
						optind++;
						continue;
					}
					if (is_snapshot == FALSE) {
						ret =
						    print_ctl_table(ctl_handle);
					} else {
						ret =
						    snapshot_ctl(ctl_handle,
						    FALSE, 0, is_snapshot);
					}
					(void) raidcfg_close_controller(
					    ctl_handle, NULL);
					optind++;
				}
			} else {
				if (get_array_tag(argv[optind],
				    &ctl_tag, &array_tag) != SUCCESS) {
					return (INVALID_ARG);
				}
				ctl_handle = raidcfg_get_controller(ctl_tag);
				if (ctl_handle <= 0) {
					(void) fprintf(stderr, "%s\n",
					    raidcfg_errstr(ctl_handle));
					return (FAILURE);
				}

				ret = raidcfg_open_controller(ctl_handle, NULL);
				if (ret < 0) {
					(void) fprintf(stderr, "%s\n",
					    raidcfg_errstr(ret));
					return (FAILURE);
				}

				array_handle = raidcfg_get_array(ctl_handle,
				    array_tag.idl.target_id, array_tag.idl.lun);
				if (array_handle <= 0) {
					(void) fprintf(stderr, "%s\n",
					    raidcfg_errstr(array_handle));
					(void) raidcfg_close_controller(
					    ctl_handle, NULL);
					return (FAILURE);
				}
				if (is_snapshot == FALSE) {
					ret = print_array_table(ctl_handle,
					    array_handle);
				} else {
					ret = snapshot_array(array_handle, 0,
					    FALSE, is_snapshot);
				}
				(void) raidcfg_close_controller(
				    ctl_handle, NULL);
			}
		}
	} else {
		if (argv[optind + 1] != NULL) {
			return (INVALID_ARG);
		}

		if (get_ctl_tag(argv[optind], &ctl_tag) != SUCCESS) {
			return (INVALID_ARG);
		}

		ctl_handle = raidcfg_get_controller(ctl_tag);
		if (ctl_handle <= 0) {
			(void) fprintf(stderr, "%s\n",
			    raidcfg_errstr(ctl_handle));
			return (FAILURE);
		}

		if (get_disk_tag_cidl(disk_argp, &disk_tag) != SUCCESS) {
			return (INVALID_ARG);
		}

		ret = raidcfg_open_controller(ctl_handle, NULL);
		if (ret < 0) {
			(void) fprintf(stderr, "%s\n",
			    raidcfg_errstr(ret));
			return (FAILURE);
		}

		disk_handle = raidcfg_get_disk(ctl_handle, disk_tag);
		if (disk_handle <= 0) {
			(void) fprintf(stderr, "%s\n",
			    raidcfg_errstr(disk_handle));
			(void) raidcfg_close_controller(ctl_handle, NULL);
			return (FAILURE);
		}

		if (is_snapshot == FALSE) {
			ret = print_disk_table(ctl_handle, disk_handle);
		} else {
			ret = snapshot_disk(ctl_tag, disk_handle, 0,
			    is_snapshot);
		}
		(void) raidcfg_close_controller(ctl_handle, NULL);
	}
	return (ret);
}

/*
 * do_delete(f_flag, argv, optind)
 * This function deletes a specified array, and return result as SUCCESS,
 * FAILURE or INVALID_ARG.
 */
static int
do_delete(uint32_t f_flag, char **argv, uint32_t optind)
{
	uint32_t ctl_tag;
	char *array_argp;
	array_tag_t array_tag;
	raid_obj_handle_t ctl_handle;
	raid_obj_handle_t array_handle;
	int ret;

	array_argp = argv[optind];
	if (array_argp == NULL || argv[optind + 1] != NULL) {
		return (INVALID_ARG);
	}

	if (get_array_tag(array_argp, &ctl_tag, &array_tag) != SUCCESS) {
		return (INVALID_ARG);
	}

	ctl_handle = raidcfg_get_controller(ctl_tag);
	if (ctl_handle <= 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ctl_handle));
		return (INVALID_ARG);
	}

	ret = raidcfg_open_controller(ctl_handle, NULL);
	if (ret < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		return (FAILURE);
	}

	array_handle = raidcfg_get_array(ctl_handle, array_tag.idl.target_id,
	    array_tag.idl.lun);
	if (array_handle <= 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(array_handle));
		(void) raidcfg_close_controller(ctl_handle, NULL);
		return (FAILURE);
	}

	if (f_flag == FALSE) {
		(void) fprintf(stdout, gettext("Deleting RAID volume "
		    "%s will destroy all data it contains, "
		    "proceed (%s/%s)? "), array_argp, yesstr, nostr);
		if (!yes()) {
			(void) fprintf(stdout, gettext("RAID Volume "
			    "%s not deleted.\n\n"), array_argp);
			(void) raidcfg_close_controller(ctl_handle, NULL);
			return (SUCCESS);
		}
	}


	if ((ret = raidcfg_delete_array(array_handle, NULL)) < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		(void) raidcfg_close_controller(ctl_handle, NULL);
		return (FAILURE);
	}

	(void) fprintf(stdout, gettext("Volume %s is deleted successfully!\n"),
	    array_argp);
	(void) raidcfg_close_controller(ctl_handle, NULL);

	return (SUCCESS);
}

/*
 * do_flash(f_flag, filep, ctls_argpp, index, ctl_num)
 * This function downloads and updates firmware for specified controller, and
 * return result as SUCCESS, FAILURE or INVALID_ARG.
 */
static int
do_flash(uint8_t f_flag, char *filep, char **ctls_argpp,
    uint32_t index, uint32_t ctl_num)
{
	uint32_t ctl_tag = MAX32BIT;
	char *ctl_argp = NULL;
	raid_obj_handle_t ctl_handle = INIT_HANDLE_VALUE;
	int ret;
	int i, j;

	if (ctl_num == 0)
		return (INVALID_ARG);

	for (i = 0, j = index; i < ctl_num; i++, j++) {
		ctl_argp = ctls_argpp[j];
		if (get_ctl_tag(ctl_argp, &ctl_tag) != SUCCESS) {
			return (INVALID_ARG);
		}

		/* Ask user to confirm operation. */
		if (f_flag == FALSE) {
			(void) fprintf(stdout, gettext("Update flash image on "
			    "controller %d (%s/%s)? "), ctl_tag, yesstr, nostr);
			if (!yes()) {
				(void) fprintf(stdout,
				    gettext("Controller %d not "
				    "flashed.\n\n"), ctl_tag);
				return (SUCCESS);
			}
		}

		if ((ctl_handle = raidcfg_get_controller(ctl_tag)) < 0) {
			(void) fprintf(stderr, "%s\n",
			    raidcfg_errstr(ctl_handle));
			return (FAILURE);
		}

		ret = raidcfg_open_controller(ctl_handle, NULL);
		if (ret < 0) {
			(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
			return (FAILURE);
		}

		(void) fprintf(stdout, gettext("Start updating controller "
		    "c%u firmware....\n"), ctl_tag);

		if ((ret = raidcfg_update_fw(ctl_handle, filep, NULL)) < 0) {
			(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
			(void) raidcfg_close_controller(ctl_handle, NULL);
			return (FAILURE);
		}

		(void) fprintf(stdout, gettext("Update controller "
		    "c%u firmware successfully.\n"), ctl_tag);

		(void) raidcfg_close_controller(ctl_handle, NULL);
	}

	return (SUCCESS);
}

/*
 * do_set_hsp(a_argp, disk_argp, argv, optind)
 * This function set or unset HSP relationship between disk and controller/
 * array, and return result as SUCCESS, FAILURE or INVALID_ARG.
 */
static int
do_set_hsp(char *a_argp, char *disk_argp, char **argv, uint32_t optind)
{
	uint32_t flag = MAX32BIT;
	uint32_t ctl_tag = MAX32BIT;
	array_tag_t array_tag;
	raid_obj_handle_t ctl_handle = INIT_HANDLE_VALUE;
	raid_obj_handle_t disk_handle = INIT_HANDLE_VALUE;
	raid_obj_handle_t array_handle = INIT_HANDLE_VALUE;
	raidcfg_controller_t ctl_attr;
	disk_tag_t disk_tag;

	int ret;
	int hsp_type;
	raidcfg_hsp_relation_t hsp_relation;

	(void) memset(&hsp_relation, 0, sizeof (raidcfg_hsp_relation_t));

	if (a_argp == NULL) {
		return (INVALID_ARG);
	}

	if (strcmp(a_argp, "set") == 0) {
		flag = HSP_SET;
	} else if (strcmp(a_argp, "unset") == 0) {
		flag = HSP_UNSET;
	} else {
		return (INVALID_ARG);
	}

	if (disk_argp == NULL) {
		return (INVALID_ARG);
	}

	if (argv[optind] == NULL || argv[optind + 1] != NULL) {
		return (INVALID_ARG);
	} else if (is_fully_numeric(argv[optind]) == TRUE) {
		/* Global HSP */
		hsp_type = 0;
		if (get_disk_tag_cidl(disk_argp, &disk_tag) != SUCCESS) {
			return (INVALID_ARG);
		}

		if (get_ctl_tag(argv[optind], &ctl_tag) != SUCCESS) {
			return (INVALID_ARG);
		}

		ctl_handle = raidcfg_get_controller(ctl_tag);
		if (ctl_handle <= 0) {
			(void) fprintf(stderr, "%s\n",
			    raidcfg_errstr(ctl_handle));
			return (FAILURE);
		}

		ret = raidcfg_open_controller(ctl_handle, NULL);
		if (ret < 0) {
			(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
			return (FAILURE);
		}

		disk_handle = raidcfg_get_disk(ctl_handle, disk_tag);
		if (disk_handle <= 0) {
			(void) fprintf(stderr, "%s\n",
			    raidcfg_errstr(disk_handle));
			(void) raidcfg_close_controller(ctl_handle, NULL);
			return (FAILURE);
		}
	} else {
		/* Local HSP */
		hsp_type = 1;
		if (get_array_tag(argv[optind], &ctl_tag, &array_tag) !=
		    SUCCESS) {
			return (INVALID_ARG);
		}

		/* Open controller */
		ctl_handle = raidcfg_get_controller(ctl_tag);
		if (ctl_handle <= 0) {
			(void) fprintf(stderr, "%s\n",
			    raidcfg_errstr(ctl_handle));
			return (FAILURE);
		}

		ret = raidcfg_open_controller(ctl_handle, NULL);
		if (ret < 0) {
			(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
			return (FAILURE);
		}

		/* Get controller's attribute */
		if ((ret = raidcfg_get_attr(ctl_handle, &ctl_attr)) < 0) {
			(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
			(void) raidcfg_close_controller(ctl_handle, NULL);
			return (FAILURE);
		}

		if (get_disk_tag_cidl(disk_argp, &disk_tag) != SUCCESS) {
			(void) raidcfg_close_controller(ctl_handle, NULL);
			return (INVALID_ARG);
		}

		/* Get disk handle */
		disk_handle = raidcfg_get_disk(ctl_handle, disk_tag);
		if (disk_handle <= 0) {
			(void) fprintf(stderr, "%s\n",
			    raidcfg_errstr(disk_handle));
			(void) raidcfg_close_controller(ctl_handle, NULL);
			return (FAILURE);
		}

		/* Get array handle */
		array_handle = raidcfg_get_array(ctl_handle,
		    array_tag.idl.target_id, array_tag.idl.lun);
		if (array_handle <= 0) {
			(void) fprintf(stderr, "%s\n",
			    raidcfg_errstr(array_handle));
			(void) raidcfg_close_controller(ctl_handle, NULL);
			return (FAILURE);
		}
	}

	hsp_relation.disk_handle = disk_handle;
	if (hsp_type) {
		/* Set or unset local HSP */
		hsp_relation.array_handle = array_handle;
	} else {
		/* Set or unset global HSP */
		hsp_relation.array_handle = OBJ_ATTR_NONE;
	}

	/* Perform operation of set or unset */
	if (flag == HSP_SET) {
		if ((ret = raidcfg_set_hsp(&hsp_relation, NULL)) < 0) {
			(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
			(void) raidcfg_close_controller(ctl_handle, NULL);
			return (FAILURE);
		}

		if (hsp_type) {
			(void) printf(gettext("Set local HSP between disk %s "
			    "and RAID volume %s successfully.\n"),
			    disk_argp, argv[optind]);
		} else {
			(void) printf(gettext("Set global HSP between disk %s "
			    "and controller %s successfully.\n"),
			    disk_argp, argv[optind]);
		}
	} else {
		if ((ret = raidcfg_unset_hsp(&hsp_relation, NULL)) < 0) {
			(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
			(void) raidcfg_close_controller(ctl_handle, NULL);
			return (FAILURE);
		}

		if (hsp_type) {
			(void) printf(gettext("Unset local HSP between "
			    "disk %s and RAID volume %s successfully.\n"),
			    disk_argp, argv[optind]);
		} else {
			(void) printf(gettext("Unset global HSP between "
			    "disk %s and controller %s successfully.\n"),
			    disk_argp, argv[optind]);
		}
	}
	(void) raidcfg_close_controller(ctl_handle, NULL);
	return (SUCCESS);
}

/*
 * do_set_array_attr(f_flag, p_argp, argv, optind)
 * This function changes array's attribute when array is running.
 * The changeable attribute is up to controller's feature.
 * The return value can be SUCCESS, FAILURE or INVALID_ARG.
 */
static int
do_set_array_attr(uint32_t f_flag, char *p_argp, char **argv, uint32_t optind)
{
	uint32_t ctl_tag = MAX32BIT;
	array_tag_t array_tag;
	uint32_t type = MAX32BIT;
	uint32_t value = MAX32BIT;
	raid_obj_handle_t ctl_handle = INIT_HANDLE_VALUE;
	raid_obj_handle_t array_handle = INIT_HANDLE_VALUE;

	char *param, *op = "=";

	int ret;

	if (argv[optind] == NULL || argv[optind + 1] != NULL) {
		return (INVALID_ARG);
	}

	if (p_argp != NULL) {
		param = strtok(p_argp, op);
		if (strcmp(param, "wp") == 0) {
			type = SET_CACHE_WR_PLY;
			param = strtok(NULL, op);
			if (strcmp(param, "on") == 0) {
				value = CACHE_WR_ON;
			} else if (strcmp(param, "off") == 0) {
				value = CACHE_WR_OFF;
			} else {
				return (INVALID_ARG);
			}
		} else if (strcmp(param, "state") == 0) {
			type = SET_ACTIVATION_PLY;
			param = strtok(NULL, op);
			if (strcmp(param, "activate") == 0) {
				value = ARRAY_ACT_ACTIVATE;
			} else {
				return (INVALID_ARG);
			}
		} else {
			return (INVALID_ARG);
		}
	} else {
		return (INVALID_ARG);
	}

	if (get_array_tag(argv[optind], &ctl_tag, &array_tag) != SUCCESS) {
		return (INVALID_ARG);
	}

	ctl_handle = raidcfg_get_controller(ctl_tag);
	if (ctl_handle <= 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ctl_handle));
		return (FAILURE);
	}

	ret = raidcfg_open_controller(ctl_handle, NULL);
	if (ret < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		return (FAILURE);
	}

	array_handle = raidcfg_get_array(ctl_handle, array_tag.idl.target_id,
	    array_tag.idl.lun);
	if (array_handle <= 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(array_handle));
		return (FAILURE);
	}

	/* Ask user to confirm operation. */
	if (f_flag == FALSE) {
		(void) fprintf(stdout, gettext("Update attribute of "
		    "array %s (%s/%s)? "), argv[optind], yesstr, nostr);
		if (!yes()) {
			(void) fprintf(stdout,
			    gettext("Array %s not "
			    "changed.\n\n"), argv[optind]);
			(void) raidcfg_close_controller(ctl_handle, NULL);
			return (SUCCESS);
		}
	}

	if ((ret = raidcfg_set_attr(array_handle, type, &value, NULL)) < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		(void) raidcfg_close_controller(ctl_handle, NULL);
		return (FAILURE);
	}

	(void) printf(gettext("Set attribute of RAID volume %s "
	    "successfully.\n"), argv[optind]);
	(void) raidcfg_close_controller(ctl_handle, NULL);

	return (SUCCESS);
}

/*
 * snapshot_raidsystem(recursive, indent, is_snapshot)
 * This function prints the snapshot of whole RAID's system configuration,
 * and return result as SUCCESS or FAILURE.
 */
static int
snapshot_raidsystem(uint8_t recursive, uint8_t indent, uint8_t is_snapshot)
{
	raid_obj_handle_t ctl_handle = INIT_HANDLE_VALUE;
	int ret;

	ctl_handle = raidcfg_list_head(OBJ_SYSTEM, OBJ_TYPE_CONTROLLER);
	while (ctl_handle > 0) {
		ret = raidcfg_open_controller(ctl_handle, NULL);
		if (ret == 0) {
			if (snapshot_ctl(ctl_handle, recursive, indent,
			    is_snapshot) == FAILURE) {
				(void) raidcfg_close_controller(ctl_handle,
				    NULL);
			}
		}
		ctl_handle = raidcfg_list_next(ctl_handle);
	}
	return (SUCCESS);
}

/*
 * snapshot_ctl(ctl_handle, recursive, indent, is_snapshot)
 * This function prints snapshot of specified controller's configuration,
 * and return result as SUCCESS or FAILURE.
 */
static int
snapshot_ctl(raid_obj_handle_t ctl_handle, uint8_t recursive, uint8_t indent,
    uint8_t is_snapshot)
{
	raid_obj_handle_t array_handle = INIT_HANDLE_VALUE;
	raid_obj_handle_t disk_handle = INIT_HANDLE_VALUE;
	raidcfg_controller_t ctl_attr;
	uint32_t ctl_tag;
	char ctlbuf[256];
	int ret;

	if ((ret = raidcfg_get_attr(ctl_handle, &ctl_attr)) < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		return (FAILURE);
	}

	ctl_tag = ctl_attr.controller_id;
	if (is_snapshot == FALSE) {
		print_indent(indent);
		(void) fprintf(stdout, gettext("Controller: %u\n"), ctl_tag);
	} else {
		(void) snprintf(ctlbuf, sizeof (ctlbuf), "%u \"%s\"",
		    ctl_tag, ctl_attr.controller_type);
		(void) fprintf(stdout, "%s", ctlbuf);

		(void) fprintf(stdout, "\n");
	}

	if (recursive == TRUE) {
		array_handle = raidcfg_list_head(ctl_handle, OBJ_TYPE_ARRAY);
		while (array_handle > 0) {
			if (snapshot_array(array_handle,
			    indent + 1, FALSE, is_snapshot) == FAILURE) {
				return (FAILURE);
			}

			array_handle = raidcfg_list_next(array_handle);
		}

		disk_handle = raidcfg_list_head(ctl_handle, OBJ_TYPE_DISK);
		while (disk_handle > 0) {
			if (snapshot_disk(ctl_tag, disk_handle,
			    indent + 1, is_snapshot) == FAILURE) {
				return (FAILURE);
			}

			disk_handle = raidcfg_list_next(disk_handle);
		}
	}
	return (SUCCESS);
}


/*
 * snapshot_array(array_handle, indent, is_sub, is_snapshot)
 * This function prints snapshot of specified array's configuration,
 * and return result as SUCCESS or FAILURE.
 */
static int
snapshot_array(raid_obj_handle_t array_handle, uint8_t indent, uint8_t is_sub,
    uint8_t is_snapshot)
{
	raid_obj_handle_t ctl_handle;
	raid_obj_handle_t subarray_handle;
	raid_obj_handle_t arraypart_handle;
	raid_obj_handle_t task_handle;

	raidcfg_controller_t ctl_attr;
	raidcfg_array_t array_attr;
	raidcfg_arraypart_t arraypart_attr;
	raidcfg_task_t task_attr;

	char arraybuf[256] = "\0";
	char diskbuf[256] = "\0";
	char tempbuf[256] = "\0";
	int disknum = 0;

	uint32_t ctl_tag;
	int ret;

	ctl_handle = raidcfg_get_container(array_handle);
	ret = raidcfg_get_attr(ctl_handle, &ctl_attr);
	if (ret < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		return (FAILURE);
	}
	ctl_tag = ctl_attr.controller_id;

	/* Print array attribute */
	if ((ret = raidcfg_get_attr(array_handle, &array_attr)) < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		return (FAILURE);
	}

	if (is_snapshot == FALSE) {
		print_indent(indent);
		if (is_sub == FALSE) {
			(void) fprintf(stdout, gettext("Volume:"
			    "c%ut%llud%llu\n"),
			    ctl_tag, array_attr.tag.idl.target_id,
			    array_attr.tag.idl.lun);
		} else {
			(void) fprintf(stdout, gettext("Sub-Volume\n"));
		}
	} else {
		(void) snprintf(arraybuf, sizeof (arraybuf), "c%ut%llud%llu ",
		    ctl_tag, array_attr.tag.idl.target_id,
		    array_attr.tag.idl.lun);

		/* Check if array is in sync state */
		task_handle = raidcfg_list_head(array_handle, OBJ_TYPE_TASK);
		if (task_handle > 0) {
			(void) raidcfg_get_attr(task_handle, &task_attr);
			if (task_attr.task_func == TASK_FUNC_BUILD) {
				array_attr.state = ARRAY_STATE_SYNC;
			}
		} else {
			subarray_handle = raidcfg_list_head(array_handle,
			    OBJ_TYPE_ARRAY);
			while (subarray_handle > 0) {
				task_handle = raidcfg_list_head(subarray_handle,
				    OBJ_TYPE_TASK);
				if (task_handle > 0) {
					(void) raidcfg_get_attr(task_handle,
					    &task_attr);
					if (task_attr.task_func ==
					    TASK_FUNC_BUILD) {
						array_attr.state =
						    ARRAY_STATE_SYNC;
					}
					break;
				}
				subarray_handle =
				    raidcfg_list_next(subarray_handle);
			}
		}

		/* Print sub array */
		subarray_handle = raidcfg_list_head(array_handle,
		    OBJ_TYPE_ARRAY);
		while (subarray_handle > 0) {
			/* print subarraypart */
			arraypart_handle = raidcfg_list_head(subarray_handle,
			    OBJ_TYPE_ARRAY_PART);
			while (arraypart_handle > 0) {
				if ((ret = raidcfg_get_attr(arraypart_handle,
				    &arraypart_attr)) < 0) {
					(void) fprintf(stderr, "%s\n",
					    raidcfg_errstr(ret));
					return (FAILURE);
				}

				if (arraypart_attr.tag.cidl.bus == MAX64BIT) {
					(void) snprintf(tempbuf,
					    sizeof (tempbuf),
					    gettext("N/A"));
				} else {
					(void) snprintf(tempbuf,
					    sizeof (tempbuf),
					    "%llu.%llu.%llu",
					    arraypart_attr.tag.cidl.bus,
					    arraypart_attr.tag.cidl.target_id,
					    arraypart_attr.tag.cidl.lun);
				}
				(void) strlcat(diskbuf, tempbuf,
				    sizeof (diskbuf));
				(void) strcat(diskbuf, " ");
				disknum++;
				arraypart_handle =
				    raidcfg_list_next(arraypart_handle);
			}
			subarray_handle = raidcfg_list_next(subarray_handle);
		}

		/* Print arraypart */
		arraypart_handle = raidcfg_list_head(array_handle,
		    OBJ_TYPE_ARRAY_PART);
		while (arraypart_handle > 0) {
			if ((ret = raidcfg_get_attr(arraypart_handle,
			    &arraypart_attr)) < 0) {
				(void) fprintf(stderr, "%s\n",
				    raidcfg_errstr(ret));
				return (FAILURE);
			}

			if (arraypart_attr.tag.cidl.bus == MAX64BIT) {
				(void) snprintf(tempbuf, sizeof (tempbuf),
				    gettext("N/A"));
			} else {
				(void) snprintf(tempbuf, sizeof (tempbuf),
				    "%llu.%llu.%llu",
				    arraypart_attr.tag.cidl.bus,
				    arraypart_attr.tag.cidl.target_id,
				    arraypart_attr.tag.cidl.lun);
			}
			(void) strlcat(diskbuf, tempbuf, sizeof (diskbuf));
			(void) strcat(diskbuf, " ");
			disknum++;
			arraypart_handle = raidcfg_list_next(arraypart_handle);
		}
		(void) snprintf(tempbuf, sizeof (tempbuf), "%u ", disknum);
		(void) strlcat(arraybuf, tempbuf, sizeof (arraybuf));
		(void) strlcat(arraybuf, diskbuf, sizeof (arraybuf));

		switch (array_attr.raid_level) {
		case RAID_LEVEL_0:
			(void) sprintf(tempbuf, "0");
			break;
		case RAID_LEVEL_1:
			(void) sprintf(tempbuf, "1");
			break;
		case RAID_LEVEL_1E:
			(void) sprintf(tempbuf, "1E");
			break;
		case RAID_LEVEL_5:
			(void) sprintf(tempbuf, "5");
			break;
		case RAID_LEVEL_10:
			(void) sprintf(tempbuf, "10");
			break;
		case RAID_LEVEL_50:
			(void) sprintf(tempbuf, "50");
			break;
		default:
			(void) snprintf(tempbuf, sizeof (tempbuf),
			    gettext("N/A"));
			break;
		}
		(void) strlcat(arraybuf, tempbuf, sizeof (arraybuf));
		(void) fprintf(stdout, "%s ", arraybuf);

		switch (array_attr.state) {
		case ARRAY_STATE_OPTIMAL:
			(void) fprintf(stdout, gettext("OPTIMAL"));
			break;
		case ARRAY_STATE_DEGRADED:
			(void) fprintf(stdout, gettext("DEGRADED"));
			break;
		case ARRAY_STATE_FAILED:
			(void) fprintf(stdout, gettext("FAILED"));
			break;
		case ARRAY_STATE_SYNC:
			(void) fprintf(stdout, gettext("SYNC"));
			break;
		case ARRAY_STATE_MISSING:
			(void) fprintf(stdout, gettext("MISSING"));
			break;
		default:
			(void) fprintf(stdout, gettext("N/A"));
			break;
		}
		(void) fprintf(stdout, "\n");
	}

	return (SUCCESS);
}

/*
 * snapshot_disk(ctl_tag, disk_handle, indent, is_snapshot)
 * This function prints snapshot of specified disk's configuration, and return
 * result as SUCCESS or FAILURE.
 */
static int
snapshot_disk(uint32_t ctl_tag, raid_obj_handle_t disk_handle, uint8_t indent,
    uint8_t is_snapshot)
{
	raid_obj_handle_t ctl_handle = INIT_HANDLE_VALUE;
	raid_obj_handle_t hsp_handle;

	raidcfg_controller_t ctl_attr;
	raidcfg_disk_t disk_attr;
	char diskbuf[256] = "";
	char tempbuf[256] = "";

	int ret;

	ctl_handle = raidcfg_get_controller(ctl_tag);
	ret = raidcfg_get_attr(ctl_handle, &ctl_attr);
	if (ret < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		return (FAILURE);
	}

	/* Print attribute of disk */
	if ((ret = raidcfg_get_attr(disk_handle, &disk_attr)) < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		return (FAILURE);
	}

	if (is_snapshot == FALSE) {
		print_indent(indent);

		hsp_handle = raidcfg_list_head(disk_handle, OBJ_TYPE_HSP);

		if (disk_attr.tag.cidl.bus == MAX64BIT) {
			(void) fprintf(stdout, gettext("Disk: N/A"));
		} else {
			(void) fprintf(stdout, gettext("Disk: %llu.%llu.%llu"),
			    disk_attr.tag.cidl.bus,
			    disk_attr.tag.cidl.target_id,
			    disk_attr.tag.cidl.lun);
		}
		if (hsp_handle > 0) {
			(void) fprintf(stdout, "(HSP)");
		}
		(void) fprintf(stdout, "\n");
	} else {
		if (disk_attr.tag.cidl.bus == MAX64BIT) {
			(void) fprintf(stdout, gettext("N/A"));
		} else {
			(void) snprintf(diskbuf, sizeof (diskbuf),
			    "%llu.%llu.%llu ",
			    disk_attr.tag.cidl.bus,
			    disk_attr.tag.cidl.target_id,
			    disk_attr.tag.cidl.lun);
		}
		hsp_handle = raidcfg_list_head(disk_handle, OBJ_TYPE_HSP);
		if (hsp_handle > 0) {
			(void) snprintf(tempbuf, sizeof (tempbuf),
			    gettext("HSP"));
		} else if (disk_attr.state == DISK_STATE_GOOD) {
			(void) snprintf(tempbuf, sizeof (tempbuf),
			    gettext("GOOD"));
		} else if (disk_attr.state == DISK_STATE_FAILED) {
			(void) snprintf(tempbuf, sizeof (tempbuf),
			    gettext("FAILED"));
		} else {
			(void) snprintf(tempbuf, sizeof (tempbuf),
			    gettext("N/A"));
		}

		(void) strlcat(diskbuf, tempbuf, sizeof (diskbuf));
		(void) fprintf(stdout, "%s\n", diskbuf);
	}

	return (SUCCESS);
}

static int
print_ctl_table(raid_obj_handle_t ctl_handle)
{
	raidcfg_controller_t ctl_attr;
	char controller[8];
	int ret;

	if ((ret = raidcfg_get_attr(ctl_handle, &ctl_attr)) < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		return (FAILURE);
	}

	(void) fprintf(stdout, gettext("Controller\tType\t\tVersion"));
	(void) fprintf(stdout, "\n");
	(void) fprintf(stdout, "--------------------------------");
	(void) fprintf(stdout, "--------------------------------");
	(void) fprintf(stdout, "\n");

	(void) snprintf(controller, sizeof (controller), "%u",
	    ctl_attr.controller_id);
	(void) printf("c%s\t\t", controller);

	(void) print_ctl_attr(&ctl_attr);
	(void) fprintf(stdout, "\n");

	return (SUCCESS);
}

static int
print_array_table(raid_obj_handle_t ctl_handle, raid_obj_handle_t array_handle)
{
	raidcfg_controller_t ctl_attr;
	raidcfg_array_t array_attr;
	raidcfg_array_t subarray_attr;
	raidcfg_arraypart_t arraypart_attr;
	raidcfg_task_t task_attr;

	raid_obj_handle_t subarray_handle;
	raid_obj_handle_t arraypart_handle;
	raid_obj_handle_t task_handle;

	char array[16];
	char arraypart[8];
	int ret;
	int i;

	/* Controller attribute */
	if ((ret = raidcfg_get_attr(ctl_handle, &ctl_attr)) < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		return (FAILURE);
	}

	/* Array attribute */
	if ((ret = raidcfg_get_attr(array_handle, &array_attr)) < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		return (FAILURE);
	}

	/* print header */
	(void) fprintf(stdout, gettext("Volume\t\t\tSize\tStripe\tStatus\t"
	    " Cache\tRAID"));
	(void) fprintf(stdout, "\n");
	(void) fprintf(stdout, gettext("\tSub\t\t\tSize\t\t\tLevel"));
	(void) fprintf(stdout, "\n");
	(void) fprintf(stdout, gettext("\t\tDisk\t\t\t\t\t"));
	(void) fprintf(stdout, "\n");
	(void) fprintf(stdout, "--------------------------------");
	(void) fprintf(stdout, "--------------------------------");
	(void) fprintf(stdout, "\n");

	/* print array */
	(void) snprintf(array, sizeof (array), "c%ut%llud%llu",
	    ctl_attr.controller_id, array_attr.tag.idl.target_id,
	    array_attr.tag.idl.lun);
	(void) fprintf(stdout, "%s\t\t", array);
	if (strlen(array) < 8)
		(void) fprintf(stdout, "\t");


	/* check if array is in sync state */
	task_handle = raidcfg_list_head(array_handle, OBJ_TYPE_TASK);
	if (task_handle > 0) {
		(void) raidcfg_get_attr(task_handle, &task_attr);
		if (task_attr.task_func == TASK_FUNC_BUILD) {
			array_attr.state = ARRAY_STATE_SYNC;
		}
	} else {
		subarray_handle = raidcfg_list_head(array_handle,
		    OBJ_TYPE_ARRAY);
		while (subarray_handle > 0) {
			task_handle = raidcfg_list_head(subarray_handle,
			    OBJ_TYPE_TASK);
			if (task_handle > 0) {
				(void) raidcfg_get_attr(task_handle,
				    &task_attr);
				if (task_attr.task_func == TASK_FUNC_BUILD) {
					array_attr.state = ARRAY_STATE_SYNC;
				}
				break;
			}
			subarray_handle = raidcfg_list_next(subarray_handle);
		}
	}

	(void) print_array_attr(&array_attr);
	(void) fprintf(stdout, "\n");

	/* Print sub array */
	i = 0;			/* Count sub array number */
	subarray_handle = raidcfg_list_head(array_handle, OBJ_TYPE_ARRAY);
	while (subarray_handle > 0) {
		if ((ret = raidcfg_get_attr(subarray_handle,
		    &subarray_attr)) < 0) {
			(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
			return (FAILURE);
		}

		/* Use sub0/sub1 here, not cxtxd0 for subarray */
		(void) snprintf(array, sizeof (array), "sub%u", i++);
		(void) fprintf(stdout, "\t%s\t\t", array);

		/* Check if array is in sync */
		task_handle = raidcfg_list_head(subarray_handle, OBJ_TYPE_TASK);
		if (task_handle > 0) {
			(void) raidcfg_get_attr(task_handle, &task_attr);
			if (task_attr.task_func == TASK_FUNC_BUILD) {
				subarray_attr.state = ARRAY_STATE_SYNC;
			}
		}

		(void) print_array_attr(&subarray_attr);
		(void) fprintf(stdout, "\n");

		/* Print subarraypart */
		arraypart_handle = raidcfg_list_head(subarray_handle,
		    OBJ_TYPE_ARRAY_PART);
		while (arraypart_handle > 0) {
			if ((ret = raidcfg_get_attr(arraypart_handle,
			    &arraypart_attr)) < 0) {
				(void) fprintf(stderr, "%s\n",
				    raidcfg_errstr(ret));
				return (FAILURE);
			}

			if (arraypart_attr.tag.cidl.bus == MAX64BIT) {
				(void) snprintf(arraypart, sizeof (arraypart),
				    gettext("N/A"));
			} else {
				(void) snprintf(arraypart, sizeof (arraypart),
				    "%llu.%llu.%llu",
				    arraypart_attr.tag.cidl.bus,
				    arraypart_attr.tag.cidl.target_id,
				    arraypart_attr.tag.cidl.lun);
			}

			(void) fprintf(stdout, "\t\t%s\t", arraypart);
			(void) print_arraypart_attr(&arraypart_attr);
			(void) fprintf(stdout, "\n");
			arraypart_handle = raidcfg_list_next(arraypart_handle);
		}
		subarray_handle = raidcfg_list_next(subarray_handle);
	}

	/* Print arraypart */
	arraypart_handle = raidcfg_list_head(array_handle,
	    OBJ_TYPE_ARRAY_PART);
	while (arraypart_handle > 0) {
		if ((ret = raidcfg_get_attr(arraypart_handle,
		    &arraypart_attr)) < 0) {
			(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
			return (FAILURE);
		}

		if (arraypart_attr.tag.cidl.bus == MAX64BIT) {
			(void) snprintf(arraypart, sizeof (arraypart),
			    gettext("N/A"));
		} else {
			(void) snprintf(arraypart, sizeof (arraypart),
			    "%llu.%llu.%llu",
			    arraypart_attr.tag.cidl.bus,
			    arraypart_attr.tag.cidl.target_id,
			    arraypart_attr.tag.cidl.lun);
		}

		(void) fprintf(stdout, "\t\t%s\t", arraypart);
		(void) print_arraypart_attr(&arraypart_attr);
		(void) fprintf(stdout, "\n");
		arraypart_handle = raidcfg_list_next(arraypart_handle);
	}

	return (SUCCESS);
}

static int
print_disk_table(raid_obj_handle_t ctl_handle, raid_obj_handle_t disk_handle)
{
	raidcfg_controller_t ctl_attr;
	raidcfg_disk_t disk_attr;
	raidcfg_prop_t *prop_attr, *prop_attr2;
	raid_obj_handle_t prop_handle;
	char disk[8];
	int ret;

	if ((ret = raidcfg_get_attr(ctl_handle, &ctl_attr)) < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		return (FAILURE);
	}

	if ((ret = raidcfg_get_attr(disk_handle, &disk_attr)) < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		return (FAILURE);
	}

	/* Print header */
	(void) fprintf(stdout, gettext("Disk\tVendor   Product          "
	    "Firmware\tCapacity\tStatus\tHSP"));
	(void) fprintf(stdout, "\n");
	(void) fprintf(stdout, "--------------------------------------");
	(void) fprintf(stdout, "--------------------------------------");
	(void) fprintf(stdout, "\n");


	(void) snprintf(disk, sizeof (disk), "%llu.%llu.%llu",
	    disk_attr.tag.cidl.bus,
	    disk_attr.tag.cidl.target_id,
	    disk_attr.tag.cidl.lun);

	(void) fprintf(stdout, "%s\t", disk);

	(void) print_disk_attr(ctl_handle, disk_handle, &disk_attr);

	prop_attr = calloc(1, sizeof (raidcfg_prop_t));
	if (prop_attr == NULL) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ERR_NOMEM));
		return (FAILURE);
	}

	prop_handle = raidcfg_list_head(disk_handle, OBJ_TYPE_PROP);
	if (prop_handle == 0) {
		free(prop_attr);
		return (SUCCESS);
	}

	do {
		prop_attr->prop_size = 0;
		if ((ret = raidcfg_get_attr(prop_handle, prop_attr)) < 0) {
			free(prop_attr);
			(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
			return (FAILURE);
		}
		if (prop_attr->prop_type == PROP_GUID)
			break;
	} while (prop_handle != 0);

	prop_attr2 = realloc(prop_attr,
	    sizeof (raidcfg_prop_t) + prop_attr->prop_size);
	free(prop_attr);
	if (prop_attr2 == NULL) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ERR_NOMEM));
		return (FAILURE);
	}

	if ((ret = raidcfg_get_attr(prop_handle, prop_attr2)) < 0) {
		free(prop_attr2);
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		return (FAILURE);
	}

	(void) fprintf(stdout, "GUID:%s\n", prop_attr2->prop);

	free(prop_attr2);
	return (SUCCESS);
}

/*
 * print_ctl_attr(attrp)
 * This function prints attribute of specified controller, and return
 * result as SUCCESS or FAILURE.
 */
static int
print_ctl_attr(raidcfg_controller_t *attrp)
{
	char type[CONTROLLER_TYPE_LEN];
	char version[CONTROLLER_FW_LEN];

	if (attrp == NULL) {
		return (FAILURE);
	}

	(void) snprintf(type, sizeof (type), "%s", attrp->controller_type);
	(void) fprintf(stdout, "%-16s", type);

	(void) snprintf(version, sizeof (version), "%s", attrp->fw_version);
	(void) fprintf(stdout, "%s", version);

	return (SUCCESS);
}

/*
 * print_array_attr(attrp)
 * This function prints attribute of specified array, and return
 * result as SUCCESS or FAILURE.
 */
static int
print_array_attr(raidcfg_array_t *attrp)
{
	char capacity[8];
	char stripe_size[8];
	char raid_level[8];

	if (attrp == NULL) {
		return (FAILURE);
	}

	if (attrp->capacity != MAX64BIT) {
		if (size_to_string(attrp->capacity, capacity, 8) != SUCCESS) {
			return (FAILURE);
		}
		(void) printf("%s\t", capacity);
	} else {
		(void) printf(gettext("N/A\t"));
	}

	if (attrp->stripe_size != MAX32BIT) {
		(void) snprintf(stripe_size, sizeof (stripe_size), "%uK",
		    attrp->stripe_size / 1024);
		(void) printf("%s\t", stripe_size);
	} else {
		(void) printf(gettext("N/A\t"));
	}

	if (attrp->state & ARRAY_STATE_INACTIVATE)
		(void) printf("%-8s", gettext("INACTIVE"));
	else {
		switch (attrp->state) {
		case ARRAY_STATE_OPTIMAL:
			(void) printf("%-8s", gettext("OPTIMAL"));
			break;
		case ARRAY_STATE_DEGRADED:
			(void) printf("%-8s", gettext("DEGRADED"));
			break;
		case ARRAY_STATE_FAILED:
			(void) printf("%-8s", gettext("FAILED"));
			break;
		case ARRAY_STATE_SYNC:
			(void) printf("%-8s", gettext("SYNC"));
			break;
		case ARRAY_STATE_MISSING:
			(void) printf("%-8s", gettext("MISSING"));
			break;
		default:
			(void) printf("%-8s", gettext("N/A"));
			break;
		}
	}
	(void) printf(" ");

	if (attrp->write_policy == CACHE_WR_OFF) {
		(void) printf(gettext("OFF"));
	} else if (attrp->write_policy == CACHE_WR_ON) {
		(void) printf(gettext("ON"));
	} else {
		(void) printf(gettext("N/A"));
	}
	(void) printf("\t");

	switch (attrp->raid_level) {
	case RAID_LEVEL_0:
		(void) sprintf(raid_level, "RAID0");
		break;
	case RAID_LEVEL_1:
		(void) sprintf(raid_level, "RAID1");
		break;
	case RAID_LEVEL_1E:
		(void) sprintf(raid_level, "RAID1E");
		break;
	case RAID_LEVEL_5:
		(void) sprintf(raid_level, "RAID5");
		break;
	case RAID_LEVEL_10:
		(void) sprintf(raid_level, "RAID10");
		break;
	case RAID_LEVEL_50:
		(void) sprintf(raid_level, "RAID50");
		break;
	default:
		(void) snprintf(raid_level, sizeof (raid_level),
		    gettext("N/A"));
		break;
	}
	(void) printf("%s", raid_level);

	return (SUCCESS);
}

/*
 * print_arraypart_attr(attrp)
 * This function print attribute of specified arraypart, and return
 * result as SUCCESS or FAILURE.
 */
static int
print_arraypart_attr(raidcfg_arraypart_t *attrp)
{
	char size[8];

	if (attrp == NULL) {
		return (FAILURE);
	}

	if (attrp->size != MAX64BIT) {
		if (size_to_string(attrp->size, size, 8) != SUCCESS) {
			return (FAILURE);
		}
		(void) printf("%s\t", size);
	} else {
		(void) printf(gettext("N/A\t"));
	}

	(void) printf("\t");

	if (attrp->state == DISK_STATE_GOOD) {
		(void) printf(gettext("GOOD"));
	} else if (attrp->state == DISK_STATE_FAILED) {
		(void) printf(gettext("FAILED"));
	} else {
		(void) printf(gettext("N/A"));
	}
	(void) printf("\t");

	return (SUCCESS);
}

/*
 * print_disk_attr(ctl_handle, disk_handle, attrp)
 * This function prints attribute of specified disk, and return
 * result as SUCCESS or FAILURE.
 */
static int
print_disk_attr(raid_obj_handle_t ctl_handle, raid_obj_handle_t disk_handle,
    raidcfg_disk_t *attrp)
{
	char vendor[DISK_VENDER_LEN + 1];
	char product[DISK_PRODUCT_LEN + 1];
	char revision[DISK_REV_LEN + 1];
	char capacity[16];
	char hsp[16];

	raid_obj_handle_t hsp_handle;
	raidcfg_hsp_t hsp_attr;
	raidcfg_controller_t ctl_attr;
	int ret;
	char is_indent;

	if (attrp == NULL) {
		return (FAILURE);
	}

	(void) memccpy(vendor, attrp->vendorid, '\0', DISK_VENDER_LEN);
	vendor[DISK_VENDER_LEN] = '\0';
	(void) printf("%-9s", vendor);

	(void) memccpy(product, attrp->productid, '\0', DISK_PRODUCT_LEN);
	product[DISK_PRODUCT_LEN] = '\0';
	(void) printf("%-17s", product);

	(void) memccpy(revision, attrp->revision, '\0', DISK_REV_LEN);
	revision[DISK_REV_LEN] = '\0';
	(void) printf("%s\t\t", revision);

	if (attrp->capacity != MAX64BIT) {
		if (size_to_string(attrp->capacity, capacity, 16) != SUCCESS) {
			return (FAILURE);
		}
		(void) printf("%s\t\t", capacity);
	} else {
		(void) printf(gettext("N/A"));
	}

	if (attrp->state == DISK_STATE_GOOD) {
		(void) printf(gettext("GOOD"));
	} else if (attrp->state == DISK_STATE_FAILED) {
		(void) printf(gettext("FAILED"));
	} else {
		(void) printf(gettext("N/A"));
	}
	(void) printf("\t");

	/* Controller attribute */
	if ((ret = raidcfg_get_attr(ctl_handle, &ctl_attr)) < 0) {
		(void) fprintf(stderr, "%s\n", raidcfg_errstr(ret));
		return (FAILURE);
	}

	hsp_handle = raidcfg_list_head(disk_handle, OBJ_TYPE_HSP);
	if (hsp_handle == 0) {
		(void) printf(gettext("N/A\n"));
	} else {
		is_indent = FALSE;
		while (hsp_handle > 0) {
			if ((ret = raidcfg_get_attr(hsp_handle,
			    &hsp_attr)) < 0) {
				(void) fprintf(stderr, "%s\n",
				    raidcfg_errstr(ret));
				return (FAILURE);
			}

			if (is_indent == TRUE) {
				(void) printf("\t\t\t\t\t\t\t");
			} else {
				is_indent = TRUE;
			}

			if (hsp_attr.type == HSP_TYPE_LOCAL) {
				(void) snprintf(hsp, sizeof (hsp),
				    "c%ut%llud%llu",
				    ctl_attr.controller_id,
				    hsp_attr.tag.idl.target_id,
				    hsp_attr.tag.idl.lun);
				(void) printf("%s\n", hsp);
			} else if (hsp_attr.type == HSP_TYPE_GLOBAL) {
				(void) printf(gettext("Global\n"));
			} else {
				return (FAILURE);
			}

			hsp_handle = raidcfg_list_next(hsp_handle);
		}
	}
	return (SUCCESS);
}


/*
 * print_indent(indent)
 * This function prints specified number of tab characters. It's used to
 * format layout.
 */
static void
print_indent(uint8_t indent)
{
	uint32_t i;
	for (i = 0; i < indent; i++) {
		(void) fprintf(stdout, "\t");
	}
}

/*
 * get_disk_handle_cidl(ctl_tag, disks_argp, comps_num, handlespp)
 * This function parses the string of disk argument, and gets the disks tag
 * and separators from the string. Then it translates the tag to handle, and
 * stores handles and separators to new buffer pointed by parameter handlespp.
 * The format of disk_arg must be C:ID:L, for example, it is 0.1.0. The first
 * "0" is channel number, and the second "1" is target number, and the third
 * "0" is LUN number. The disk tags are separated by comma and parenthesis.
 * Function returns SUCCESS or FAILURE.
 */
static int
get_disk_handle_cidl(uint32_t ctl_tag, char *disks_argp, int *comps_nump,
    raid_obj_handle_t **handlespp)
{
	int len = 0;
	int i = 0, j = 0;
	char *p, *t;
	char *delimit = " ";
	char *disks_str;
	disk_tag_t disk_tag;

	if (disks_argp == NULL || comps_nump == NULL) {
		return (FAILURE);
	}

	p = disks_argp;
	len = strlen(disks_argp);

	if ((disks_str = (char *)malloc(3 * len + 4)) == NULL) {
		return (FAILURE);
	}

	/* Insert whitespace between disk tags, '(' , and ')' */
	disks_str[j ++] = '(';
	disks_str[j ++] = ' ';

	while (p[i] != '\0') {
		if (p[i] == ')' || p[i] == '(') {
			disks_str[j ++] = ' ';
			disks_str[j ++] = p[i];
			disks_str[j ++] = ' ';
		} else
			disks_str[j ++] = p[i];
		i ++;
	}
	disks_str[j ++] = ' ';
	disks_str[j ++] = ')';
	disks_str[j] = '\0';

	len = strlen(disks_str) + 1;

	if ((t = (char *)malloc(len)) == NULL) {
		return (FAILURE);
	}
	(void) memcpy(t, disks_str, len);
	p = strtok(t, delimit);
	while (p != NULL) {
		(*comps_nump)++;
		p = strtok(NULL, delimit);
	}
	free(t);

	*handlespp = calloc(*comps_nump, sizeof (raid_obj_handle_t));
	if (*handlespp == NULL) {
		return (FAILURE);
	}

	for (i = 0; i < *comps_nump; i++)
		(*handlespp)[i] = INIT_HANDLE_VALUE;

	i = 0;
	p = strtok(disks_str, delimit);
	while (p != NULL) {
		if (*p == '(') {
			(*handlespp)[i] = OBJ_SEPARATOR_BEGIN;
		} else if (*p == ')') {
			(*handlespp)[i] = OBJ_SEPARATOR_END;
		} else {
			if (get_disk_tag_cidl(p, &disk_tag) != SUCCESS) {
				free(*handlespp);
				free(disks_str);
				return (INVALID_ARG);
			}
			(*handlespp)[i] =
			    raidcfg_get_disk(raidcfg_get_controller(ctl_tag),
			    disk_tag);
			if ((*handlespp)[i] <= 0) {
				(void) fprintf(stderr, "%s\n",
				    raidcfg_errstr((*handlespp)[i]));
				free(*handlespp);
				free(disks_str);
				return (FAILURE);
			}
		}
		p = strtok(NULL, delimit);
		i++;
	}

	free(disks_str);
	return (SUCCESS);
}

/*
 * get_disk_handle_ctd(disks_num, disks_argpp, ctl_tagp, disks_handlep)
 * This function parses string of single disk with "ctd" format, for example,
 * c0t0d0, and translates it to controller tag and disk tag.
 * Then it calls lib api and get disk handle. The controller tag and disk
 * handle are both returned by out parameters.
 * The return value is SUCCESS or FAILURE.
 */
static int
get_disk_handle_ctd(int disks_num, char **disks_argpp, uint32_t *ctl_tagp,
    raid_obj_handle_t *disks_handlep)
{
	raid_obj_handle_t ctl_handle;
	disk_tag_t disk_tag;
	uint32_t ctl_id;
	int i;
	int ret;

	if (disks_handlep == NULL) {
		return (FAILURE);
	}

	for (i = 0; i < disks_num; i++) {
		if (get_disk_tag_ctd(disks_argpp[i], &disk_tag, &ctl_id) !=
		    SUCCESS) {
			return (INVALID_ARG);
		}

		*ctl_tagp = ctl_id;

		if (i == 0) {
			ctl_handle = raidcfg_get_controller(*ctl_tagp);
			if (ctl_handle <= 0) {
				(void) fprintf(stderr, "%s\n",
				    raidcfg_errstr(ctl_handle));
				return (FAILURE);
			}
			ret = raidcfg_open_controller(ctl_handle, NULL);
			if (ret < 0) {
				(void) fprintf(stderr, "%s\n",
				    raidcfg_errstr(ret));
				return (FAILURE);
			}
		}

		if ((disks_handlep[i] =
		    raidcfg_get_disk(ctl_handle, disk_tag)) < 0) {
			(void) fprintf(stderr, "%s\n",
			    raidcfg_errstr(disks_handlep[i]));
			(void) raidcfg_close_controller(ctl_handle, NULL);
			return (FAILURE);
		}
	}

	return (SUCCESS);
}

/*
 * get_ctl_tag(argp)
 * This function translates controller string to tag. The return value is
 * SUCCESS if the string has legal format and is parsed successfully,
 * or FAILURE if it fails.
 */
static int
get_ctl_tag(char *argp, uint32_t *ctl_tagp)
{
	if (argp == NULL || is_fully_numeric(argp) == FALSE ||
	    ctl_tagp == NULL) {
		return (FAILURE);
	}
	*ctl_tagp = (atoi(argp));
	return (SUCCESS);
}

/*
 * get_array_tag(argp, ctl_tagp, array_tagp)
 * This function parses array string to get array tag and controller tag.
 * The return value is SUCCESS if the string has legal format, or
 * FAILURE if it fails.
 */
static int
get_array_tag(char *argp, uint32_t *ctl_tagp, array_tag_t *array_tagp)
{
	char *t = NULL;
	char *cp = NULL;
	char *tp = NULL;
	char *dp = NULL;

	uint32_t value_c = MAX32BIT;
	uint32_t value_t = MAX32BIT;
	uint32_t value_d = MAX32BIT;

	int len = 0;

	if (argp == NULL || (len = strlen(argp)) == 0 ||
	    array_tagp == NULL) {
		return (FAILURE);
	}

	t = (char *)malloc(len + 1);
	if (t == NULL) {
		return (FAILURE);
	}

	(void) memcpy(t, argp, len + 1);

	/* Now remmber to release t memory if exception occurs */
	if (((dp = strchr(t, 'd')) == NULL) ||
	    ((tp = strchr(t, 't')) == NULL) ||
	    ((cp = strchr(t, 'c')) == NULL)) {
		free(t);
		return (FAILURE);
	}
	cp = t;

	*dp = '\0';
	dp++;
	*tp = '\0';
	tp++;
	cp++;

	if (is_fully_numeric(dp) == FALSE ||
	    is_fully_numeric(tp) == FALSE ||
	    is_fully_numeric(cp) == FALSE) {
		free(t);
		return (FAILURE);
	}

	value_c = atoi(cp);
	value_t = atoi(tp);
	value_d = atoi(dp);

	array_tagp->idl.target_id = value_t;
	array_tagp->idl.lun = value_d;

	if (ctl_tagp != NULL) {
		*ctl_tagp = value_c;
	}

	free(t);
	return (SUCCESS);
}

/*
 * get_disk_tag_ctd(argp, disk_tagp)
 * This function parses disk string of ctd format, and translates it to
 * disk tag and controller tag. The tags is returned by out parameters.
 * The return value is SUCCESS if the string has legal format, or FAILURE
 * if it fails.
 */
static int
get_disk_tag_ctd(char *argp, disk_tag_t *disk_tagp, uint32_t *ctl_tag)
{
	char *t = NULL;
	char *cp = NULL;
	char *tp = NULL;
	char *dp = NULL;

	uint32_t value_c = MAX32BIT;
	uint32_t value_t = MAX32BIT;
	uint32_t value_d = MAX32BIT;

	int len = 0;

	if (argp == NULL || (len = strlen(argp)) == 0 ||
	    disk_tagp == NULL) {
		return (FAILURE);
	}

	t = (char *)malloc(len + 1);
	if (t == NULL) {
		return (FAILURE);
	}

	(void) memcpy(t, argp, len + 1);

	/* Now remmber to release t memory if exception occurs */
	if (((dp = strchr(t, 'd')) == NULL) ||
	    ((tp = strchr(t, 't')) == NULL) ||
	    ((cp = strchr(t, 'c')) == NULL)) {
		free(t);
		return (FAILURE);
	}
	cp = t;

	*dp = '\0';
	dp++;
	*tp = '\0';
	tp++;
	cp++;

	if (is_fully_numeric(dp) == FALSE ||
	    is_fully_numeric(tp) == FALSE ||
	    is_fully_numeric(cp) == FALSE) {
		free(t);
		return (FAILURE);
	}

	value_c = atoi(cp);
	value_t = atoi(tp);
	value_d = atoi(dp);

	disk_tagp->cidl.bus = 0;
	disk_tagp->cidl.target_id = value_t;
	disk_tagp->cidl.lun = value_d;
	*ctl_tag = value_c;

	free(t);
	return (SUCCESS);
}

/*
 * get_disk_tag_cidl(argp, disk_tagp)
 * This function parses disk string of cidl format and translates it to tag.
 * The return value is disk tag if the string has legal format, or FAILURE
 * if it fails.
 */
static int
get_disk_tag_cidl(char *argp, disk_tag_t *disk_tagp)
{
	int len = 0;
	char *p = NULL;
	char *t = NULL;
	char *dot1p = NULL;
	char *dot2p = NULL;

	if (argp == NULL || (len = strlen(argp)) == 0) {
		return (FAILURE);
	}

	if (disk_tagp == NULL) {
		return (FAILURE);
	}

	t = (char *)malloc(len + 1);
	if (t == NULL) {
		return (FAILURE);
	}

	(void) memcpy(t, argp, len + 1);
	p = t;

	dot2p = strrchr(p, '.');
	if (dot2p == NULL) {
		free(t);
		return (FAILURE);
	}
	*dot2p = '\0';
	dot2p++;

	dot1p = strrchr(p, '.');
	if (dot1p == NULL) {
		free(t);
		return (FAILURE);
	}
	*dot1p = '\0';
	dot1p++;

	/* Assert only 2 dots in this string */
	if (strrchr(p, '.') != NULL) {
		free(t);
		return (FAILURE);
	}

	while (*p == ' ')
		p++;

	if (is_fully_numeric(p) == FALSE ||
	    is_fully_numeric(dot1p) == FALSE ||
	    is_fully_numeric(dot2p) == FALSE) {
		free(t);
		return (FAILURE);
	}

	disk_tagp->cidl.bus = atoi(p);
	disk_tagp->cidl.target_id = atoi(dot1p);
	disk_tagp->cidl.lun = atoi(dot2p);

	free(t);
	return (SUCCESS);
}

/*
 * calc_size(sizep, valp)
 * This function calculates the value represented by string sizep.
 * The string sizep can be decomposed into three parts: an initial,
 * possibly empty, sequence of white-space characters; a subject digital
 * sequence interpreted as an integer with unit k/K/m/M/g/G/t/T; and a
 * final string of one or more unrecognized characters or white-sapce
 * characters, including the terminating null. If unrecognized character
 * exists or overflow happens, the conversion must fail and return
 * INVALID_ARG. If the conversion is performed successfully, result will
 * be saved into valp and function returns SUCCESS. It returns FAILURE
 * when memory allocation fails.
 */
static int
calc_size(char *sizep, uint64_t *valp)
{
	int len;
	uint64_t size;
	uint64_t unit;
	char *t = NULL;
	char *tailp = NULL;

	if (sizep == NULL || valp == NULL) {
		return (INVALID_ARG);
	}

	if (is_fully_numeric(sizep) == TRUE) {
		*valp = atoi(sizep);
		return (SUCCESS);
	}

	len = strlen(sizep);
	if (len == 0) {
		return (INVALID_ARG);
	}

	t = (char *)malloc(len + 1);
	if (t == NULL) {
		return (FAILURE);
	}

	(void) memcpy(t, sizep, len + 1);

	switch (*(t + len - 1)) {
	case 'k':
	case 'K':
		unit = 1024ull;
		errno = 0;
		size = strtoll(t, &tailp, 0);
		break;
	case 'm':
	case 'M':
		unit = 1024ull * 1024ull;
		errno = 0;
		size = strtoll(t, &tailp, 0);
		break;
	case 'g':
	case 'G':
		unit = 1024ull * 1024ull * 1024ull;
		errno = 0;
		size = strtoll(t, &tailp, 0);
		break;
	case 't':
	case 'T':
		unit = 1024ull * 1024ull * 1024ull * 1024ull;
		errno = 0;
		size = strtoll(t, &tailp, 0);
		break;
	default:
		/* The unit must be kilobyte at least. */
		free(t);
		return (INVALID_ARG);
	}

	*(t + len - 1) = '\0';
	if (is_fully_numeric(t) != TRUE) {
		free(t);
		return (INVALID_ARG);
	}

	errno = 0;
	size = strtoll(t, &tailp, 0);

	/* Check overflow condition */
	if (errno == ERANGE || (size > (MAX64BIT / unit))) {
		free(t);
		return (INVALID_ARG);
	}

	*valp = size * unit;
	free(t);
	return (SUCCESS);
}

/*
 * is_fully_numeric(str)
 * This function checks if the string are legal numeric string. The beginning
 * or ending characters can be white spaces.
 * Return value is TRUE if the string are legal numeric string, or FALSE
 * otherwise.
 */
static int
is_fully_numeric(char *strp)
{
	uint32_t len;
	uint32_t i;

	if (strp == NULL) {
		return (FALSE);
	}

	len = strlen(strp);
	if (len == 0) {
		return (FALSE);
	}

	/* Skip whitespace characters */
	for (i = 0; i < len; i++) {
		if (strp[i] != ' ') {
			break;
		}
	}

	/* if strp points all space characters */
	if (i == len) {
		return (FALSE);
	}

	/* Check the digitals in string */
	for (; i < len; i++) {
		if (!isdigit(strp[i])) {
			break;
		}
	}

	/* Check the ending string */
	for (; i < len; i++) {
		if (strp[i] != ' ') {
			return (FALSE);
		}
	}

	return (TRUE);
}

static int
yes(void)
{
	int	i, b;
	char    ans[SCHAR_MAX + 1];

	for (i = 0; ; i++) {
		b = getchar();
		if (b == '\n' || b == '\0' || b == EOF) {
			ans[i] = 0;
			break;
		}
		if (i < SCHAR_MAX) {
			ans[i] = b;
		}
	}
	if (i >= SCHAR_MAX) {
		i = SCHAR_MAX;
		ans[SCHAR_MAX] = 0;
	}

	return (rpmatch(ans));
}

/*
 * Function: int rpmatch(char *)
 *
 * Description:
 *
 *	Internationalized get yes / no answer.
 *
 * Inputs:
 *	s	-> Pointer to answer to compare against.
 *
 * Returns:
 *	TRUE	-> Answer was affirmative
 *	FALSE	-> Answer was negative
 */

static int
rpmatch(char *s)
{
	int	status;

	/* match yesexpr */
	status = regexec(&re, s, (size_t)0, NULL, 0);
	if (status != 0) {
		return (FALSE);
	}
	return (TRUE);
}

static int
size_to_string(uint64_t size, char *string, int len)
{
	int i = 0;
	uint32_t remainder;
	char unit[][2] = {" ", "K", "M", "G", "T"};

	if (string == NULL) {
		return (FAILURE);
	}
	while (size > 1023) {
		remainder = size % 1024;
		size /= 1024;
		i++;
	}

	if (i > 4) {
		return (FAILURE);
	}

	remainder /= 103;
	if (remainder == 0) {
		(void) snprintf(string, len, "%llu", size);
	} else {
		(void) snprintf(string, len, "%llu.%1u", size,
		    remainder);
	}

	/* make sure there is one byte for unit */
	if ((strlen(string) + 1) >=  len) {
		return (FAILURE);
	}
	(void) strlcat(string, unit[i], len);

	return (SUCCESS);
}

/*
 * Only one raidctl is running at one time.
 */
static int
enter_raidctl_lock(int *fd)
{
	int fd0 = -1;
	struct flock lock;

	fd0 = open(RAIDCTL_LOCKF, O_CREAT|O_WRONLY, 0600);
	if (fd0 < 0) {
		if (errno == EACCES) {
			(void) fprintf(stderr,
			    gettext("raidctl:must be root to run raidctl"
			    ": %s\n"), strerror(errno));
		} else {
			(void) fprintf(stderr,
			    gettext("raidctl:failed to open lockfile"
			    " '"RAIDCTL_LOCKF"': %s\n"), strerror(errno));
		}
		return (FAILURE);
	}

	*fd = fd0;
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if ((fcntl(fd0, F_SETLK, &lock) == -1) &&
	    (errno == EAGAIN || errno == EDEADLK)) {
		if (fcntl(fd0, F_GETLK, &lock) == -1) {
			(void) fprintf(stderr,
			    gettext("raidctl:enter_filelock error\n"));
			return (FAILURE);
		}
		(void) fprintf(stderr, gettext("raidctl:"
		    "enter_filelock:filelock is owned "
		    "by 'process %d'\n"), lock.l_pid);
		return (FAILURE);
	}

	return (SUCCESS);
}

static void
exit_raidctl_lock(int fd)
{
	struct flock lock;

	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;
	if (fcntl(fd, F_SETLK, &lock) == -1) {
		(void) fprintf(stderr, gettext("raidctl: failed to"
		    " exit_filelock: %s\n"),
		    strerror(errno));
	}
	(void) close(fd);
}
