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

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <libnvpair.h>

#include "mms_trace.h"
#include "mms_mgmt.h"
#include "mgmt_acsls.h"
#include "mgmt_library.h"
#include "mgmt_media.h"
#include "mms_cfg.h"

extern char *optarg;
extern int optind, opterr, optopt;

static char *usemsg =
"Usage:  mmsadm [-h] <subcommand>\n\
Subcommands:\n\
\tdiscover\n\
\tcreate\n\
\tdelete\n\
\tset\n\
\tlist\n\
\tpasswd\n\
\tonline\n\
\toffline\n\
\tadd-volume\n\
\tremove-volume\n\
\tlabel\n\
\tshowreq\n\
\taccept\n\
\treject\n\
\tmount\n\
\tunmount\n\
\tdbbackup\n\
\tdbrestore\n\
Use 'mmsadm <subcommand> -h' to list subcommand options and/or refer to\n\
the mmsadm man page.\n";

static int mmsadm_discover(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_create(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_delete(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_set(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_list(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_online(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_offline(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_add_vol(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_rm_vol(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_showreq(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_accept(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_reject(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_dbbackup(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_dbrestore(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_mount(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_unmount(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_discover_vols(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_passwd(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_label(nvlist_t *nvl, nvlist_t *errs);
static int mmsadm_discover_local(nvlist_t *nvl, nvlist_t *errs);

static void usage(int idx);

static int print_list_values(char *objtype, nvlist_t *nvl, char **printopts,
    int pcount, boolean_t doscript);
static int confirm_delete(char *objname, boolean_t force);

static char discover_usemsg[] =
"\nUsage:  mmsadm discover [-a] [-H] [-S ACSLS-server:port] \
[-t library|drive|vol]\n\
\t-a\tShow all, including already-configured resources\n\
\t-H\tScripting mode\n\
\t-S\tACSLS server name and optional port number\n\
\t\tIf not specified, displays locally connected tape drives\n\
\t-t\tResource type\n";

static char create_usemsg[] =
"\nUsage:  mmsadm create -t <type> -o option=x [-o option2=y ...] name\n\
\t-t\tResource type - library, drive, mpool, app, dkvol, dkdrive or voltype\n";

static char delete_usemsg[] =
"\nUsage:  mmsadm delete -t <type> [-f] name\n\
\t-t\tResource type - library, drive, mpool, app, dkvol, dkdrive or voltype\n\
\t-f\tForce\n";

static char set_usemsg[] =
"\nUsage:  mmsadm set -t <type> -o option=x [-o option2=y ...] name\n\
\t-t\tResource type - system,  library, drive, mpool, app, dkvol, dkdrive \
or voltype\n";

static char passwd_usemsg[] =
"\nUsage:  mmsadm passwd [-P passwdfile] name\n\
\t-P\tPath to a temporary file containing the password\n\
\tname\tApplication name.  Use 'admin' to change the MMS Administrative \
password\n";

static char online_usemsg[] =
"\nUsage:  mmsadm online -t library|drive name\n\
\t-t\t Resource type\n";

static char offline_usemsg[] =
"\nUsage:  mmsadm offline -t library|drive name\n\
\t-t\t Resource type\n";

static char label_usemsg[] =
"\nUsage:  mmsadm label -l library -A application [-f] volume[,volume]\n\
\t-l\tLibrary holding the volume\n\
\t-A\tApplication to which this volume will be assigned after labeling\n\
\t-f\tForce label.  Use this option to relabel a tape that has previously \
been labeled.\n";

static char add_usemsg[] =
"\nUsage:  mmsadm add-volume -l library -x vol[,vol2...] mpool\n\
\t-l\tLibrary from which the volume will be selected\n\
\t-x\tComma separated list of volumes to be added\n\
\tmpool\tName of media pool to which the volumes will be added\n";

static char remove_usemsg[] =
"\nUsage:  mmsadm remove-volume -l library [-f] -x vol[,vol2...] mpool\n\
\t-l\tLibrary from which the volume will be selected\n\
\t-x\tComma separated list of volumes to be added\n\
\t-f\tForce.  Use this option to remove a volume which has previously \
been used\n\
\tmpool\tName of media pool to which the volumes will be added\n";

static char show_usemsg[] =
"\nUsage:  mmsadm showreq [-H]\n\
\t-H\tScripting mode.\n";

static char accept_usemsg[] =
"\nUsage:  mmsadm accept [-r \"response text\"] requestid\n\
\t-r\tOptional text message\n\
\trequestid\tRequest ID as displayed by the 'mmsadm showreq' command\n";

static char reject_usemsg[] =
"\nUsage:  mmsadm reject [-r \"response text\"] requestid\n\
\t-r\tOptional text message\n\
\trequestid\tRequest ID as displayed by the 'mmsadm showreq' command\n";

static char back_usemsg[] =
"\nUsage:  mmsadm dbbackup <directory>\n\
\tdirectory\tDirectory where the database backup file will be stored\n";

static char rest_usemsg[] =
"\nUsage:  mmsadm dbrestore <filename>\n\
\tfilename\tComplete path to the file containing the backup to be restored\n";

static char mount_usemsg[] =
"\nUsage:  mmsadm mount [-n] [-N] [-d drive] [-D density] [-A application] \
-l library [-P passwdfile] [-u username] [-b blocksize] [-R] \
[-M mode[,mode...]] volume\n\
\t-n\tnorewind\n\
\t-N\tnowait\n\
\t-d\tdrive on which to mount the volume\n\
\t-D\tdensity\n\
\t-A\tapplication name\n\
\t-l\tlibrary containing the volume to be mounted\n\
\t-P\tPath to a temporary file containing the password\n\
\t-u\tThe username who will have ownership of pseudodevice created by mount\n\
\t-b\tblocksize\n\
\t-R\treadonly\n\
\t-M\tmode.  One or more of creat, trunc, append. old, st_nobsd, st_tm, raw, \n\
\t\tmms, compression, nocompression, variable, block\n";

static char unmount_usemsg[] =
"\nUsage:  mmsadm unmount [-U] [-l library] [-A application] [-P passwdfile] \
volume|pseudodevice\n\
\t-U\tPhysically unload the tape from the drive\n\
\t-l\tLibrary containing the volume to be unmounted\n\
\t-A\tapplication name\n\
\t-P\tPath to a temporary file containing the password\n\
\tvolume\tVolume to be unmounted \n\
\tpseudodevice\tName of pseudodevice as returned from the \
'mmsadm mount' command\n";

static char *setphrases[2] = {
	"Enter password: ",
	"Re-enter password: "
};

static char *getphrases[2] = {
	"Enter application password: ",
	NULL
};

typedef struct {
	char	*subopt;
	int	(*func)(nvlist_t *nvl, nvlist_t *errs);
	char	*usemsg;
	boolean_t hasobj;
} adminfuncs_t;

static adminfuncs_t mmsadmfuncs[] = {
	{"discover",	mmsadm_discover,	discover_usemsg, B_FALSE},
	{"create",	mmsadm_create,		create_usemsg,	B_TRUE},
	{"delete",	mmsadm_delete,		delete_usemsg,	B_TRUE},
	{"set",		mmsadm_set,		set_usemsg,	B_TRUE},
	{"list",	mmsadm_list,		NULL,	B_FALSE},
	{"online",	mmsadm_online,		online_usemsg,	B_TRUE},
	{"offline",	mmsadm_offline,		offline_usemsg,	B_TRUE},
	{"add-volume",	mmsadm_add_vol,		add_usemsg,	B_TRUE},
	{"remove-volume", mmsadm_rm_vol,	remove_usemsg,	B_TRUE},
	{"showreq",	mmsadm_showreq,		show_usemsg,	B_FALSE},
	{"accept",	mmsadm_accept,		accept_usemsg,	B_TRUE},
	{"reject",	mmsadm_reject,		reject_usemsg,	B_TRUE},
	{"dbbackup",	mmsadm_dbbackup,	back_usemsg,	B_TRUE},
	{"dbrestore",	mmsadm_dbrestore,	rest_usemsg,	B_TRUE},
	{"mount",	mmsadm_mount,		mount_usemsg,	B_TRUE},
	{"unmount",	mmsadm_unmount,		unmount_usemsg,	B_TRUE},
	{"passwd",	mmsadm_passwd,		passwd_usemsg,	B_TRUE},
	{"label",	mmsadm_label,		label_usemsg,	B_TRUE},
	{NULL,		NULL,			NULL,	B_FALSE}
};

static char *cmdopts = ":aA:b:d:D:fF:hHl:L:m:M:nNo:P:r:Rs:S:t:u:Uv?x:V:";

int
main(int argc, char **argv)
{
	int		st = 0;
	int		i;
	int		cmdidx = -1;
	char		*subcmd = NULL;
	nvlist_t	*nvl = NULL;
	char		c;
	int		newargc = argc;
	char		**newargv = argv;
	char		buf[2048];
	char		*bufp;
	int		hflag = 0;
	nvlist_t	*errs = NULL;
	char		*tmpstr;
	boolean_t	allow_empty_val = B_FALSE;
	boolean_t	req_name = B_FALSE;
	boolean_t	listing = B_FALSE;

	if (argc < 2) {
		hflag++;
		st = 1;
		goto done;
	}

	(void) mms_trace_open("/var/log/mms/mmsadm.log", MMS_ID_CLI,
	    MMS_SEV_INFO, 5 * MEGA, 0, 0);

	/* see if this host has been initialized.  If not, fail. */
	st =  mms_cfg_getvar(MMS_CFG_CONFIG_TYPE, buf);
	if (st != 0) {
		fprintf(stderr, "\nError:  MMS has not been initialized for"
		    " use on this system.  Please run the mmsinit command.\n");
		st = MMS_MGMT_MMS_NOT_INIT;
		goto done;
	}

	/*
	 * see if we've got a subcommand.  If we don't, fall through
	 * to getopt() anyway.
	 */
	for (i = 0; mmsadmfuncs[i].subopt != NULL; i++) {
		if (strcmp(mmsadmfuncs[i].subopt, argv[1]) == 0) {
			/* reset options for getopt */
			newargc--;
			newargv = &(argv[1]);
			subcmd = argv[1];
			req_name = mmsadmfuncs[i].hasobj;
			cmdidx = i;
			if (strcmp(subcmd, "list") == 0) {
				listing = B_TRUE;
			}
			break;
		}
	}

	if (subcmd == NULL) {
		hflag++;
		st = 1;
		goto done;
	}

	if (mmsadmfuncs[cmdidx].func == NULL) {
		fprintf(stderr, "mmsadm %s not yet implemented\n",
		    mmsadmfuncs[cmdidx].subopt);
		st = 1;
		goto done;
	}

	st = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);
	if (st != 0) {
		goto done;
	}

	st = nvlist_alloc(&errs, NV_UNIQUE_NAME, 0);
	if (st != 0) {
		goto done;
	}

	if (listing) {
		allow_empty_val = B_TRUE;
	}

	while (st == 0) {
		c = getopt(newargc, newargv, cmdopts);

		if (c == -1) {
			break;
		}

		switch (c) {
			case 'a':
				st = nvlist_add_boolean_value(nvl, "all",
				    B_TRUE);
				break;
			case 'A':
				st = nvlist_add_string(nvl, O_APPS, optarg);
				break;
			case 'b':
				st = nvlist_add_string(nvl, "blocksize",
				    optarg);
				break;
			case 'd':
				st = nvlist_add_string(nvl, O_MMSDRV, optarg);
				break;
			case 'D':
				st = nvlist_add_string(nvl, O_DENSITY, optarg);
				break;
			case 'f':
				st = nvlist_add_boolean_value(nvl, O_FORCE,
				    B_TRUE);
				break;
			case 'F':
				if (!listing) {
					st = nvlist_add_string(nvl, "filename",
					    optarg);
				} else {
					/* list filter */
					nvlist_add_boolean_value(nvl, "filter",
					    B_TRUE);
					st = mgmt_opt_to_var(optarg,
					    allow_empty_val, nvl);
				}
				break;
			case 'H':
				st = nvlist_add_boolean_value(nvl, "script",
				    B_TRUE);
				break;
			case 'l':
			case 'L':
				st = nvlist_add_string(nvl, O_MMSLIB, optarg);
				break;
			case 'm':
				st = nvlist_add_string(nvl, O_MPOOL, optarg);
				break;
			case 'M':
				/* possibly multi-value */
				tmpstr = strdup(optarg);
				if (tmpstr == NULL) {
					st = ENOMEM;
					break;
				}
				st = mgmt_set_str_or_arr(tmpstr, "mode", nvl);

				free(tmpstr);
				tmpstr = NULL;

				break;
			case 'n':
				st = nvlist_add_boolean_value(nvl, O_NOREWIND,
				    B_TRUE);
				break;
			case 'N':
				st = nvlist_add_boolean_value(nvl, O_NOWAIT,
				    B_TRUE);
				break;
			case 'o':
				if (!listing) {
					st = mgmt_opt_to_var(optarg,
					    allow_empty_val, nvl);
				} else {
					/* possibly multi-value */
					tmpstr = strdup(optarg);
					if (tmpstr == NULL) {
						st = ENOMEM;
						break;
					}
					st = mgmt_set_str_or_arr(tmpstr,
					    "printopts", nvl);

					free(tmpstr);
					tmpstr = NULL;
				}
				break;
			case 'P':
				/* read password from file */
				st = nvlist_add_string(nvl, "passwordfile",
				    optarg);
				break;
			case 'r':
				st = nvlist_add_string(nvl, O_RESPTXT, optarg);
				break;
			case 'R':
				st = nvlist_add_string(nvl, "readonly", "true");
				break;
			case 's':
				/* possibly multi-value */
				tmpstr = strdup(optarg);
				if (tmpstr == NULL) {
					st = ENOMEM;
					break;
				}
				st = mgmt_set_str_or_arr(tmpstr, O_DEVCONN,
				    nvl);

				free(tmpstr);
				tmpstr = NULL;

				break;
			case 'S':
				strlcpy(buf, optarg, sizeof (buf));
				bufp = strchr(buf, ':');
				if (bufp != NULL) {
					*bufp++ = '\0';
					st = nvlist_add_string(nvl, O_ACSPORT,
					    bufp);
				}
				if (st == 0) {
					st = nvlist_add_string(nvl, O_ACSHOST,
					    buf);
				}

				break;
			case 't':
				st = nvlist_add_string(nvl, O_OBJTYPE, optarg);
				if (strcmp(optarg, "system") == 0) {
					req_name = B_FALSE;
				}
				break;
			case 'u':
				st = nvlist_add_string(nvl, "user", optarg);
				break;
			case 'U':
				st = nvlist_add_boolean_value(nvl, "unload",
				    B_TRUE);
				break;
			case 'v':
				st = nvlist_add_boolean_value(nvl, "verbose",
				    B_TRUE);
				break;
			case 'V':
				st = nvlist_add_string(nvl, O_VOLTYPE, optarg);
				break;
			case 'x':
				/* process list of volumes */
				/* possibly multi-value */
				tmpstr = strdup(optarg);
				if (tmpstr == NULL) {
					st = ENOMEM;
					break;
				}
				st = mgmt_set_str_or_arr(tmpstr, O_VOLUMES,
				    nvl);

				free(tmpstr);
				tmpstr = NULL;

				break;
			case '?':
			case 'h':
				hflag++;
				break;
			case ':':
				fprintf(stderr,
				    "Option %s requires an operand\n",
				    argv[optind-1]);
				st = 1;
				break;
			default:
				break;
		}
	}

	if ((st != 0) || (subcmd == NULL) || hflag) {
		goto done;
	}

	/* get object name[s] we're to act on, if any */
	if (optind < newargc) {
		/* possibly multi-value */
		tmpstr = strdup(newargv[optind++]);
		if (tmpstr == NULL) {
			st = ENOMEM;
			goto done;
		}
		st = mgmt_set_str_or_arr(tmpstr, O_NAME, nvl);

		free(tmpstr);
		tmpstr = NULL;

		if (st != 0) {
			goto done;
		}
	} else {
		/* see if this subcommand requires one or more objects */
		if (subcmd && req_name) {
			fprintf(stderr,
			    "Error, command requires an object name\n");
			st = ENOENT;
			goto done;
		}
	}

	if (optind < newargc) {
		/* hmm, leftover cmd args? */
		fprintf(stderr,
		    "Error: extra arguments after command line processing.\n");
		hflag++;
		st = 1;
		goto done;
	}

	st = mmsadmfuncs[cmdidx].func(nvl, errs);

done:
	mms_trace_close();

	if (hflag) {
		usage(cmdidx);
	}

	if (nvl != NULL) {
		nvlist_free(nvl);
	}

	if (st != 0) {
		nvpair_t	*nv;
		char		*nvo = NULL;
		int		nvi = 0;
		const char	*nve;

		nve = mms_mgmt_get_errstr(st);
		if (nve) {
			fprintf(stderr, "%s\n", nve);
		}
		fprintf(stderr, "mmsadm exiting with error %d\n", st);

		if (errs) {
			nv = nvlist_next_nvpair(errs, NULL);
			while (nv != NULL) {
				nvo = nvpair_name(nv);
				(void) nvpair_value_int32(nv, &nvi);
				nve = mms_mgmt_get_errstr(nvi);

				if (nve != NULL) {
					fprintf(stderr, "\t%-15s%s\n",
					    nvo, nve);
				} else {
					fprintf(stderr, "\t%-15serror = %d\n",
					    nvo, nvi);
				}
				nv = nvlist_next_nvpair(errs, nv);
			}
		}
	}

	if (errs != NULL) {
		nvlist_free(errs);
	}

	return (st);
}

static void
usage(int idx)
{
	if ((idx == -1) || (mmsadmfuncs[idx].usemsg == NULL)) {
		printf("%s\n", usemsg);
	} else {
		printf("%s\n", mmsadmfuncs[idx].usemsg);
	}
}

static int
mmsadm_discover(nvlist_t *nvl, nvlist_t *errs)
{
	int		st = 0;
	char		*host = NULL;
	char		*bufp;
	boolean_t	drv = B_FALSE;
	boolean_t	lib = B_FALSE;
	boolean_t	dolocal = B_FALSE;
	boolean_t	showall = B_FALSE;
	boolean_t	doscript = B_FALSE;
	mms_list_t	lib_list;
	mms_list_t	drv_list;
	mms_acslib_t	*lsm;
	mms_drive_t	*drive;
	char		*fmt = "%-8s%-10s%-20s%-20s%-20s\n";
	char		*sfmt = "%s\t%s\t%s\t%s\t%s\n";
	char		buf[128];
	char		*fmtp;

	if (nvl == NULL) {
		return (EINVAL);
	}

	memset(&lib_list, 0, sizeof (mms_list_t));
	memset(&drv_list, 0, sizeof (mms_list_t));

	st = nvlist_lookup_string(nvl, O_OBJTYPE, &bufp);
	if (st == ENOENT) {
		/* not set, report on both libraries and drives */
		drv = B_TRUE;
		lib = B_TRUE;
	} else if (st == 0) {
		if (*bufp == 'l') {
			lib = B_TRUE;
		} else if (*bufp == 'd') {
			drv = B_TRUE;
		} else if (*bufp == 'v') {
			/* volumes */
			st = mmsadm_discover_vols(nvl, errs);
			return (st);
		} else {
			st = EINVAL;
			if (errs) {
				nvlist_add_int32(errs, O_TYPE, st);
			}
			return (st);
		}
	} else {
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_ACSHOST, &bufp);
	if (st == 0) {
		host = bufp;
	} else if (st == ENOENT) {
		dolocal = B_TRUE;
		st = nvlist_lookup_string(nvl, O_HOST, &bufp);
		if (st == ENOENT) {
			host = "localhost";
			st = 0;
		} else if (st == 0) {
			host = bufp;
			if (strcmp(host, "localhost") != 0) {
				fprintf(stderr,
				    "Remote discovery not yet supported\n");
				st = EOPNOTSUPP;
			}
		}
	}

	if (st != 0) {
		return (st);
	}

	nvlist_lookup_boolean_value(nvl, "all", &showall);
	nvlist_lookup_boolean_value(nvl, "script", &doscript);

	if (!dolocal) {
		/* get ACSLS information */
		st = mms_mgmt_discover_libraries(host, drv, &lib_list);
	} else {
		/* Local drives only */
		st = mmsadm_discover_local(nvl, errs);
		goto done;
	}

	if ((st != 0) || (lib_list.list_size == 0)) {
		goto done;
	}

	/* print header */
	if (!doscript) {
		fmtp = fmt;
		/* LINTED [E_SEC_PRINTF_VAR_FMT] */
		printf(fmtp, "TYPE", "HWTYPE", "SERIALNUM", "ACS,LSM", "MMSID");
		/* LINTED [E_SEC_PRINTF_VAR_FMT] */
		printf(fmtp, "====", "======", "=========", "=======", "=====");
	} else {
		fmtp = sfmt;
	}

	/* print out what we found */
	mms_list_foreach(&lib_list, lsm) {
		if (lib) {
			if (showall || (lsm->name[0] == '\0')) {
				snprintf(buf, sizeof (buf), "[%d,%d]",
				    lsm->acs, lsm->lsm);
				/* LINTED [E_SEC_PRINTF_VAR_FMT] */
				printf(fmtp, "L", lsm->type, lsm->serialnum,
				    buf, lsm->name);
			}
		}

		if (drv && (lsm->drive_list.list_size != 0)) {
			mms_list_foreach(&lsm->drive_list, drive) {
				if (!showall && (drive->name[0] != '\0')) {
					continue;
				}

				snprintf(buf, sizeof (buf), "[%d,%d,%d,%d]",
				    drive->acs,
				    drive->lsm,
				    drive->panel,
				    drive->drive);

				/* LINTED [E_SEC_PRINTF_VAR_FMT] */
				printf(fmtp, "D", drive->type, drive->serialnum,
				    buf, drive->name);
			}
		}
		fflush(stdout);
	}

done:
	free_acslib_list(&lib_list);

	return (st);
}

static int
mmsadm_create(nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		*objtype = NULL;
	char		*pwfile = NULL;

	if (!nvl) {
		return (EFAULT);
	}

	st = nvlist_lookup_string(nvl, O_OBJTYPE, &objtype);
	if (st != 0) {
		return (st);
	}

	if (strcmp(objtype, "library") == 0) {
		st = mms_add_library(NULL, nvl, errs);
	} else if (strcmp(objtype, "drive") == 0) {
		st = mms_add_drive(NULL, nvl, errs);
	} else if (strcmp(objtype, "app") == 0) {
		nvlist_lookup_string(nvl, "passwordfile", &pwfile);
		st = mms_mgmt_get_pwd(pwfile, O_MMPASS, setphrases, nvl, errs);
		if (st == 0) {
			st = mms_mgmt_add_application(NULL, nvl, errs);
		}
	} else if (strcmp(objtype, "mpool") == 0) {
		st = mms_mgmt_add_mpool(NULL, nvl, errs);
	} else if (strcmp(objtype, "voltype") == 0) {
		st = mms_mgmt_create_voltype(NULL, nvl, errs);
	} else if (strcmp(objtype, "dkvol") == 0) {
		st = mms_mgmt_create_dkvol(NULL, nvl, errs);
	} else if (strcmp(objtype, "dkdrive") == 0) {
		st = mms_mgmt_create_dkdrive(NULL, nvl, errs);
	} else {
		return (EINVAL);
	}

	return (st);
}

static int
mmsadm_delete(nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		*objtype = NULL;
	char		*objname = NULL;
	boolean_t	force;

	if (!nvl) {
		return (EFAULT);
	}

	st = nvlist_lookup_string(nvl, O_OBJTYPE, &objtype);
	if (st == 0) {
		st = val_objtype(objtype);
	}
	if (st != 0) {
		nvlist_add_int32(errs, O_OBJTYPE, st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &objname);
	if (st != 0) {
		nvlist_add_int32(errs, O_NAME, st);
		return (st);
	}

	if ((nvlist_lookup_boolean_value(nvl, O_FORCE, &force)) != 0) {
		force = B_FALSE;
	}

	if (strcmp(objtype, "library") == 0) {
		if ((st = confirm_delete(objname, force)) != 0) {
			return (st);
		}
		st = mms_remove_library(NULL, nvl, errs);
	} else if (strcmp(objtype, "drive") == 0) {
		if ((st = confirm_delete(objname, force)) != 0) {
			return (st);
		}
		st = mms_remove_drive(NULL, nvl, errs);
	} else if (strcmp(objtype, "dkdrive") == 0) {
		if ((st = confirm_delete(objname, force)) != 0) {
			return (st);
		}
		st = mms_remove_drive(NULL, nvl, errs);
	} else if (strcmp(objtype, "app") == 0) {
		if ((st = confirm_delete(objname, force)) != 0) {
			return (st);
		}
		st = mms_mgmt_remove_application(NULL, nvl, errs);
	} else if (strcmp(objtype, "mpool") == 0) {
		if ((st = confirm_delete(objname, force)) != 0) {
			return (st);
		}
		st = mms_mgmt_remove_mpool(NULL, objname, force, errs);
	} else if (strcmp(objtype, "voltype") == 0) {
		if ((st = confirm_delete(objname, force)) != 0) {
			return (st);
		}
		st = mms_mgmt_remove_voltype(NULL, objname);
	} else {
		return (EINVAL);
	}

	return (st);
}

static int
mmsadm_set(nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		*objtype = NULL;

	if (!nvl) {
		return (EFAULT);
	}

	st = nvlist_lookup_string(nvl, O_OBJTYPE, &objtype);
	if (st != 0) {
		return (st);
	}

	if (strcmp(objtype, "library") == 0) {
		st = mms_modify_library(NULL, nvl, errs);
	} else if (strcmp(objtype, "drive") == 0) {
		st = mms_modify_drive(NULL, nvl, errs);
	} else if (strcmp(objtype, "dkdrive") == 0) {
		st = mms_modify_drive(NULL, nvl, errs);
	} else if (strcmp(objtype, "system") == 0) {
		st = mms_mgmt_set_opts(nvl, errs);
	} else if (strcmp(objtype, "app") == 0) {
		st = mms_mgmt_modify_application(NULL, nvl, errs);
	} else if (strcmp(objtype, "mpool") == 0) {
		st = mms_mgmt_modify_mpool(NULL, nvl, errs);
	} else if (strcmp(objtype, "voltype") == 0) {
		st = mms_mgmt_modify_voltype(NULL, nvl, errs);
	} else if (strcmp(objtype, "dkvol") == 0) {
		st = mms_mgmt_set_dkvol_mode(NULL, nvl, errs);
	} else {
		return (EINVAL);
	}

	return (st);
}

static int
mmsadm_list(nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		*objtype = NULL;
	char		*objname = NULL;
	nvlist_t	*outlist = NULL;
	boolean_t	do_all = B_FALSE;
	boolean_t	found = B_FALSE;
	char		**printopts;
	int		pcount = 0;
	boolean_t	doscript = B_FALSE;

	st = nvlist_lookup_string(nvl, O_OBJTYPE, &objtype);
	if (st != 0) {
		if (st == ENOENT) {
			do_all = B_TRUE;
			st = 0;
		} else {
			nvlist_add_int32(errs, O_OBJTYPE, st);
			return (st);
		}
	}

	nvlist_lookup_string(nvl, O_NAME, &objname);
	nvlist_lookup_boolean_value(nvl, "script", &doscript);

	printopts = var_to_array(nvl, "printopts", &pcount);

	if (do_all || (strcmp(objtype, "system") == 0)) {
		found = B_TRUE;
		st = mms_mgmt_get_opts("server", &outlist);
		if (st == 0) {
			st = print_list_values("system", outlist, printopts,
			    pcount, doscript);
			nvlist_free(outlist);
			outlist = NULL;
		}
	}
	if (do_all || (strcmp(objtype, "library") == 0)) {
		found = B_TRUE;
		st = mms_mgmt_list_libraries(NULL, nvl, errs, &outlist);
		if (st == 0) {
			st = print_list_values("library", outlist, printopts,
			    pcount, doscript);
			nvlist_free(outlist);
			outlist = NULL;
		}
	}
	if (do_all || (strcmp(objtype, "drive") == 0)) {
		found = B_TRUE;
		st = mms_mgmt_list_drives(NULL, nvl, errs, &outlist);
		if (st == 0) {
			st = print_list_values("drive", outlist, printopts,
			    pcount, doscript);
			nvlist_free(outlist);
			outlist = NULL;
		}
	}
	if (!do_all && (strcmp(objtype, "dkdrive") == 0)) {
		found = B_TRUE;
		st = mms_mgmt_list_drives(NULL, nvl, errs, &outlist);
		if (st == 0) {
			st = print_list_values("drive", outlist, printopts,
			    pcount, doscript);
			nvlist_free(outlist);
			outlist = NULL;
		}
	}
	if (do_all || (strcmp(objtype, "voltype") == 0)) {
		found = B_TRUE;
		st = mms_mgmt_show_cartridge_type(NULL, objname, &outlist);
		if (st == 0) {
			st = print_list_values("voltype", outlist, printopts,
			    pcount, doscript);
			nvlist_free(outlist);
			outlist = NULL;
		}
	}
	if (do_all || ((strcmp(objtype, "vol") == 0)) ||
	    (strcmp(objtype, "dkvol") == 0)) {
		found = B_TRUE;
		st = mms_mgmt_list_vols(NULL, nvl, &outlist);
		if (st == 0) {
			st = print_list_values("vol", outlist, printopts,
			    pcount, doscript);
			nvlist_free(outlist);
			outlist = NULL;
		}
	}

	if (do_all || (strcmp(objtype, "mpool") == 0)) {
		found = B_TRUE;
		st = mms_mgmt_show_mpool(NULL, nvl, &outlist);
		if (st == 0) {
			st = print_list_values("mpool", outlist, printopts,
			    pcount, doscript);
			nvlist_free(outlist);
			outlist = NULL;
		}
	}

	if (do_all || (strcmp(objtype, "app") == 0)) {
		found = B_TRUE;
		st = mms_mgmt_show_apps(NULL, nvl, &outlist);
		if (st == 0) {
			st = print_list_values("app", outlist, printopts,
			    pcount, doscript);
			nvlist_free(outlist);
			outlist = NULL;
		}
	}

	if (!do_all && !found) {
		st = EOPNOTSUPP;
	}

	if (outlist) {
		nvlist_free(outlist);
	}

	return (st);
}

static int
print_list_values(char *objtype, nvlist_t *nvl, char **printopts, int pcount,
    boolean_t doscript)
{
	nvlist_t	*nva = NULL;
	nvpair_t	*nvp;
	nvpair_t	*nvpb;
	char		*key;
	char		*val;
	boolean_t	first = B_TRUE;
	int		i;
	boolean_t	printme;

	if (!objtype || !nvl) {
		return (EFAULT);
	}

	nvp = NULL;
	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		nvpair_value_nvlist(nvp, &nva);
		key = nvpair_name(nvp);

		if (!doscript) {
			printf("%s %s\n", objtype, key);
		}
		nvpb = NULL;
		while ((nvpb = nvlist_next_nvpair(nva, nvpb)) != NULL) {
			key = nvpair_name(nvpb);
			if (printopts) {
				printme = B_FALSE;
				for (i = 0; i < pcount; i++) {
					if (!printopts[i]) {
						continue;
					}
					if (strcmp(printopts[i], key) == 0) {
						printme = B_TRUE;
						break;
					}
				}
				if (!printme) {
					continue;
				}
			}
			nvpair_value_string(nvpb, &val);
			if (!doscript) {
				printf("\t%-30s\t%-30s\n", key, val);
			} else {
				if (first) {
					/* LINTED [E_SEC_PRINTF_VAR_FMT] */
					printf(val);
					first = B_FALSE;
				} else {
					printf("\t%s", val);
				}
			}
		}

		if (doscript && !first) {
			printf("\n");
		}
		first = B_TRUE;
	}

	return (0);
}

static int
mmsadm_online(nvlist_t *nvl, nvlist_t *errs)
{
	int	st;

	if (!nvl) {
		return (EFAULT);
	}

	nvlist_add_string(nvl, O_OBJSTATE, "online");

	st = mms_mgmt_set_state(NULL, nvl, errs);

	return (st);
}

static int
mmsadm_offline(nvlist_t *nvl, nvlist_t *errs)
{
	int	st;

	if (!nvl) {
		return (EFAULT);
	}

	nvlist_add_string(nvl, O_OBJSTATE, "offline");

	st = mms_mgmt_set_state(NULL, nvl, errs);

	return (st);
}

static int
mmsadm_dbbackup(nvlist_t *nvl, nvlist_t *errs)
{
	int	st;
	char	*fname;
	char	outnm[MAXPATHLEN+1];

	if (!nvl) {
		return (EFAULT);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &fname);
	if (st == 0) {
		st = mgmt_db_dump(fname, outnm, sizeof (outnm));
	} else {
		if (errs) {
			nvlist_add_int32(errs, O_NAME, st);
		}
	}

	if (st == 0) {
		printf("MMS database successfully backed up to %s\n", outnm);
	}

	return (st);
}

static int
mmsadm_dbrestore(nvlist_t *nvl, nvlist_t *errs)
{
	int	st;
	char	*fname;

	if (!nvl) {
		return (EFAULT);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &fname);
	if (st == 0) {
		st = mgmt_db_restore(fname);
		if ((st != 0) && (errs)) {
			if (st == MMS_MGMT_DBDUMP_MISSING) {
				nvlist_add_int32(errs, fname, ENOENT);
			}
		}
	} else {
		if (errs) {
			nvlist_add_int32(errs, O_NAME, st);
		}
	}


	return (st);
}

static int
mmsadm_discover_vols(nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	boolean_t	showall = B_FALSE;
	boolean_t	doscript = B_FALSE;
	mms_list_t	vol_list;
	mms_acscart_t	*vol;
	char		*fmt = "%-10s%-10s%-30s%-20s\n";
	char		*sfmt = "%s\t%s\t%s\t%s\n";
	char		*fmtp;

	if (!nvl) {
		return (EFAULT);
	}

	nvlist_lookup_boolean_value(nvl, "all", &showall);
	nvlist_lookup_boolean_value(nvl, "script", &doscript);

	st = mms_mgmt_discover_media(NULL, showall, nvl, &vol_list, errs);
	if (st != 0) {
		return (st);
	}

	/* print header */
	if (!doscript) {
		fmtp = fmt;
		/* LINTED [E_SEC_PRINTF_VAR_FMT] */
		printf(fmtp, "LABEL", "TYPE", "LIBRARY", "MPOOL");
		/* LINTED [E_SEC_PRINTF_VAR_FMT] */
		printf(fmtp, "=====", "====", "=======", "=====");
	} else {
		fmtp = sfmt;
	}

	mms_list_foreach(&vol_list, vol) {
		/* LINTED [E_SEC_PRINTF_VAR_FMT] */
		printf(fmtp, vol->label, vol->mtype, vol->libname,
		    vol->groupname);
	}

	mms_list_free_and_destroy(&vol_list, free);

	return (st);
}

static int
mmsadm_add_vol(nvlist_t *nvl, nvlist_t *errs)
{
	int	st;

	if (!nvl) {
		return (EFAULT);
	}

	st = mms_mgmt_add_cartridges(NULL, nvl, errs);

	return (st);
}

static int
mmsadm_rm_vol(nvlist_t *nvl, nvlist_t *errs)
{
	int	st;

	if (!nvl) {
		return (EFAULT);
	}

	st = mms_mgmt_remove_cartridges(NULL, nvl, errs);

	return (st);
}

static int
mmsadm_discover_local(nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	nvlist_t	*drv_list = NULL;
	nvlist_t	*drv = NULL;
	nvlist_t	*mmdrvs = NULL;
	nvlist_t	*mm_drv = NULL;
	char		*val;
	nvpair_t	*nvp = NULL;
	nvpair_t	*mnvp = NULL;
	char		*fmt = "%-20s%-20s%-20s%-20s\n";
	char		*sfmt = "%s\t%s\t%s\t%s\n";
	char		*fmtp;
	boolean_t	all = B_FALSE;
	boolean_t	doscript = B_FALSE;
	char		*sn;
	char		*ty;
	char		*dv;
	char		*id;

	if (!nvl) {
		return (EFAULT);
	}

	nvlist_lookup_boolean_value(nvl, "all", &all);
	nvlist_lookup_boolean_value(nvl, "script", &doscript);

	/* probe /dev/rmt */
	st = mgmt_find_local_drives(&drv_list);
	if (st != 0) {
		return (st);
	}

	nvp = nvlist_next_nvpair(drv_list, nvp);
	if (nvp == NULL) {
		printf("No drives attached to this system.\n");
		nvlist_free(drv_list);
		return (0);
	}

	/* print header */
	if (!doscript) {
		fmtp = fmt;
		/* LINTED [E_SEC_PRINTF_VAR_FMT] */
		printf(fmtp, "DEVICE", "TYPE", "SERIALNO", "MMSID");
		/* LINTED [E_SEC_PRINTF_VAR_FMT] */
		printf(fmtp, "======", "====", "========", "=====");
	} else {
		fmtp = sfmt;
	}

	/* get list of drives from MM, if any */
	mms_mgmt_list_drives(NULL, nvl, errs, &mmdrvs);

	do {
		sn = "";
		id = "";
		dv = "";
		ty = "";

		st = nvpair_value_nvlist(nvp, &drv);
		if (st != 0) {
			break;
		}

		/*
		 * while serial number is the best way to look up
		 * devices, need an alternate if device is busy when
		 * we ran the probe.  When filtering is enabled for
		 * listing drives, list only those attached to this
		 * system.  Then we can do device name lookups.
		 */
		st = nvlist_lookup_string(drv, O_SERIALNO, &sn);
		if (st == 0) {
			while ((mnvp = nvlist_next_nvpair(mmdrvs, mnvp))
			    != NULL) {
				st = nvpair_value_nvlist(mnvp, &mm_drv);
				if (st != 0) {
					continue;
				}

				st = nvlist_lookup_string(mm_drv,
				    "DriveSerialNum", &val);
				if (st != 0) {
					continue;
				}
				if (strcmp(sn, val) == 0) {
					st = nvlist_lookup_string(mm_drv,
					    "DriveName", &val);
					if (st == 0) {
						id = val;
					}
				}
			}
		}
		/* reset, lookup failures shouldn't be reported to user */
		st = 0;

		if (!all && (id[0] != '\0')) {
			continue;
		}

		nvlist_lookup_string(drv, O_TYPE, &ty);
		nvlist_lookup_string(drv, O_DEVPATH, &dv);

		/* LINTED [E_SEC_PRINTF_VAR_FMT] */
		printf(fmtp, dv, ty, sn, id);

	} while ((nvp = nvlist_next_nvpair(drv_list, nvp)) != NULL);

	return (0);
}

static int
mmsadm_passwd(nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		*namep = NULL;
	char		*pathp = NULL;

	if (!nvl) {
		return (EFAULT);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &namep);
	if (st != 0) {
		if (errs) {
			nvlist_add_int32(errs, "application name", st);
		}
		return (st);
	}

	nvlist_lookup_string(nvl, "passwordfile", &pathp);

	st = mms_mgmt_get_pwd(pathp, O_MMPASS, setphrases, nvl, errs);
	if (st != 0) {
		if (errs) {
			nvlist_add_int32(errs, O_MMPASS, st);
		}
		return (st);
	}

	st = mms_mgmt_set_pass(NULL, nvl, errs);

	return (st);
}

static int
mmsadm_showreq(nvlist_t *nvl, nvlist_t *errs)	/* ARGSUSED */
{
	int		st;
	nvlist_t	*reqs = NULL;

	st = mms_mgmt_show_requests(NULL, nvl, &reqs);
	if (st != 0) {
		return (st);
	}

	st = print_list_values("operator request", reqs, NULL, 0, B_FALSE);

	return (st);
}

static int
mmsadm_accept(nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		*reqID = NULL;
	char		*resp = NULL;

	if (!nvl) {
		return (EFAULT);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &reqID);
	if (!reqID) {
		nvlist_add_int32(errs, O_NAME, st);
		return (st);
	}

	nvlist_lookup_string(nvl, O_RESPTXT, &resp);

	st = mms_mgmt_accept_request(NULL, reqID, resp);

	return (st);
}

static int
mmsadm_reject(nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		*reqID = NULL;
	char		*resp = NULL;

	if (!nvl) {
		return (EFAULT);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &reqID);
	if (!reqID) {
		nvlist_add_int32(errs, O_NAME, st);
		return (st);
	}

	nvlist_lookup_string(nvl, O_RESPTXT, &resp);

	st = mms_mgmt_reject_request(NULL, reqID, resp);

	return (st);
}

static int
confirm_delete(char *objname, boolean_t force)
{
	char    yesno = 'n';

	if (!objname) {
		return (MMS_MGMT_NOARG);
	}

	if ((!isatty(STDIN_FILENO)) && !force) {
		fprintf(stderr,
		    "To delete %s from a script, please use the -f option.\n",
		    objname);
		return (1);
	}

	fprintf(stdout,
	    "Do you really want to delete %s? ([y]|n)",
	    objname);

	yesno = fgetc(stdin);
	if ((yesno == 'y') || (yesno == 'Y') || (yesno == '\n')) {
		return (0);
	}

	fprintf(stdout, "\n%s will not be deleted.\n", objname);

	return (1);
}

static int
mmsadm_label(nvlist_t *nvl, nvlist_t *errs)
{
	int	st;
	char	*app = NULL;
	char	*pathp = NULL;

	if (!nvl) {
		return (EINVAL);
	}

	nvlist_lookup_string(nvl, "passwordfile", &pathp);
	st = nvlist_lookup_string(nvl, O_APPS, &app);
	if (st != 0) {
		if (st == ENOENT) {
			st = MMS_MGMT_ERR_REQUIRED;
		}
		MGMT_ADD_ERR(errs, O_APPS, st);

		return (st);
	}

	if ((pathp) || (strcasecmp(app, "MMS") != 0)) {
		st = mms_mgmt_get_pwd(pathp, O_MMPASS, getphrases,
		    nvl, errs);
		if (st != 0) {
			return (st);
		}
	}

	st = mms_mgmt_label_multi(NULL, nvl, errs);

	return (st);
}

static int
mmsadm_mount(nvlist_t *nvl, nvlist_t *errs)
{
	int	st;
	char	*val = NULL;
	char	*app = NULL;
	char	*pathp = NULL;

	if (!nvl) {
		return (EINVAL);
	}

	nvlist_lookup_string(nvl, "passwordfile", &pathp);
	st = nvlist_lookup_string(nvl, O_APPS, &app);
	if (st != 0) {
		if (st == ENOENT) {
			st = MMS_MGMT_ERR_REQUIRED;
		}
		MGMT_ADD_ERR(errs, O_APPS, st);

		return (st);
	}

	if ((pathp) || (strcasecmp(app, "MMS") != 0)) {
		st = mms_mgmt_get_pwd(pathp, O_MMPASS, getphrases,
		    nvl, errs);
		if (st != 0) {
			return (st);
		}
	}

	st = mms_mgmt_mount_vol(NULL, nvl, errs);

	if (st == 0) {
		st = nvlist_lookup_string(nvl, "mountdev", &val);
	}

	if (st == 0) {
		printf("Mount successful on device %s\n", val);
		fflush(stdout);
	}

	return (st);
}

static int
mmsadm_unmount(nvlist_t *nvl, nvlist_t *errs)
{
	int	st;
	char	*app = NULL;
	char	*pathp = NULL;

	if (!nvl) {
		return (EINVAL);
	}

	nvlist_lookup_string(nvl, "passwordfile", &pathp);
	st = nvlist_lookup_string(nvl, O_APPS, &app);
	if (st != 0) {
		if (st == ENOENT) {
			st = MMS_MGMT_ERR_REQUIRED;
		}
		MGMT_ADD_ERR(errs, O_APPS, st);

		return (st);
	}

	if ((pathp) || (strcasecmp(app, "MMS") != 0)) {
		st = mms_mgmt_get_pwd(pathp, O_MMPASS, getphrases,
		    nvl, errs);
		if (st != 0) {
			return (st);
		}
	}

	st = mms_mgmt_unmount_vol(nvl, errs);

	return (st);
}
