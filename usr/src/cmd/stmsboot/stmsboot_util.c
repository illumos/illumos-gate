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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stropts.h>
#include <strings.h>
#include <sys/param.h>
#include <libdevinfo.h>
#include <locale.h>
#include <libintl.h>
#include <devid.h>
#include <sys/libdevid.h>
#include <sys/modctl.h> /* for MAXMODCONFNAME */
#include <sys/scsi/adapters/scsi_vhci.h>

/*
 * SAVE_DIR is the directory in which system files are saved.
 * SAVE_DIR must be under the root filesystem, as this program is
 * typically run before any other filesystems are mounted.
 */
#define	SAVE_DIR	"/etc/mpxio"
#define	VHCI_CTL_NODE	"/devices/scsi_vhci:devctl"

/* nvlist property names, these are ALL string types */
#define	NVL_DEVID	"nvl-devid"
#define	NVL_PATH	"nvl-path"
#define	NVL_PHYSPATH	"nvl-physpath"
#define	NVL_MPXPATH	"nvl-mpxiopath"
#define	NVL_MPXEN	"nvl-mpxioenabled"

#define	MPX_LIST		0x01
#define	MPX_MAP			0x02
#define	MPX_CAPABLE_CTRL	0x04
#define	MPX_DEV_PATH		0x06
#define	MPX_INIT		0x08
#define	MPX_PHYSICAL		0x10
#define	MPX_BOOTPATH		0x20
#define	MPX_UPDATEVFSTAB	0x40
#define	MPX_GETPATH		0x60
#define	MPX_USAGE		0x80
#define	MSG_INFO		0x01
#define	MSG_ERROR		0x02
#define	MSG_PANIC		0x04

#define	BOOT_PATH		0x02
#define	BOOT			0x01
#define	NONBOOT			0x00

#define	DISPLAY_ONE_PATH	0x00
#define	DISPLAY_ALL_PATH	0x01

static di_node_t devinfo_root = DI_NODE_NIL;
static char *ondiskname = "/etc/mpxio/devid_path.cache";

/*
 * We use devid-keyed nvlists to keep track of the guid, traditional and
 * MPxIO-enabled /dev/rdsk paths. Each of these nvlists is eventually
 * added to our global nvlist and our on-disk nvlist.
 */
static nvlist_t *mapnvl;
static int mpxenabled = 0;
static int limctrl = -1;
static int mpxprop = 0;
static int guid = 0;
static char *drvlimit;
static int globarg = 0;
static int debugflag = 0;
static char *devicep;
static int readonlyroot = 0;
static int cap_N_option = 0;

static void print_mpx_capable(di_node_t curnode);
static int popcheck_devnvl(di_node_t thisnode, nvlist_t *devnvl,
    char *strdevid);
static int mpxio_nvl_boilerplate(di_node_t curnode);
static int validate_devnvl();
static void report_map(char *argdev, int physpath);
static void list_devs(int listguids, int ctrl);
static void logmsg(int level, const char *msg, ...);
static char *find_link(di_node_t cnode);
static void usage();
static void parse_args(int argc, char *argv[]);
static void get_devid(di_node_t node, ddi_devid_t *thisdevid);
static int print_bootpath();
static void vhci_to_phci(char *devpath, char *slice, int d_flag);
static int update_vfstab();
static void report_dev_node_name(char *strdevfspath);
static void print_node_name(char *drv_name, char *strdevfspath);
int
main(int argc, char **argv)
{
	struct stat cachestat;
	int mapfd = 0;
	int rv = 0;
	char *ondiskbuf;
	size_t newsz = 0;

	parse_args(argc, argv);
	errno = 0;
	devinfo_root = di_init("/", DINFOCPYALL|DINFOFORCE);
	logmsg(MSG_INFO, "errno = %d after "
	    "di_init(/,DINFOCPYALL|DINFOFORCE)\n", errno);
	if (devinfo_root == NULL) {
		logmsg(MSG_ERROR,
		    gettext("Unable to take device tree snapshot "
		    "(%s: %d)\n"), strerror(errno), errno);
		return (-1);
	}
	logmsg(MSG_INFO, "opened root di_node\n");

	if (globarg == MPX_CAPABLE_CTRL) {
		/* we just want to find MPxIO-capable controllers and exit */
		if (drvlimit != NULL) {
			print_mpx_capable(di_drv_first_node(drvlimit,
			    devinfo_root));
		} else {
			print_mpx_capable(di_drv_first_node("fp",
			    devinfo_root));
			print_mpx_capable(di_drv_first_node("mpt",
			    devinfo_root));
			print_mpx_capable(di_drv_first_node("mpt_sas",
			    devinfo_root));
			print_mpx_capable(di_drv_first_node("pmcs",
			    devinfo_root));
		}
		di_fini(devinfo_root);
		return (0);
	}

	mapfd = open(ondiskname, O_RDWR|O_CREAT|O_SYNC, S_IRUSR | S_IWUSR);
	if (mapfd < 0) {
		/* we could be in single-user, so try for RO */
		if ((mapfd = open(ondiskname, O_RDONLY)) < 0) {
			logmsg(MSG_ERROR,
			    gettext("Unable to open or create %s:%s\n"),
			    ondiskname, strerror(errno));
			return (errno);
		}
		readonlyroot = 1;
	}

	if (stat(ondiskname, &cachestat) != 0) {
		logmsg(MSG_ERROR,
		    gettext("Unable to stat() %s: %s\n"),
		    ondiskname, strerror(errno));
		return (errno);
	}
	ondiskbuf = calloc(1, cachestat.st_size);
	if (ondiskbuf == NULL) {
		logmsg(MSG_ERROR,
		    gettext("Unable to allocate memory for the devid "
		    "cache file: %s\n"), strerror(errno));
		return (errno);
	}
	rv = read(mapfd, ondiskbuf, cachestat.st_size);
	if (rv != cachestat.st_size) {
		logmsg(MSG_ERROR,
		    gettext("Unable to read all of devid cache file (got %d "
		    "from expected %d bytes): %s\n"),
		    rv, cachestat.st_size, strerror(errno));
		return (errno);
	}
	errno = 0;
	rv = nvlist_unpack(ondiskbuf, cachestat.st_size, &mapnvl, 0);
	if (rv) {
		logmsg(MSG_INFO,
		    "Unable to unpack devid cache file %s: %s (%d)\n",
		    ondiskname, strerror(rv), rv);
		if (nvlist_alloc(&mapnvl, NV_UNIQUE_NAME, 0) != 0) {
			logmsg(MSG_ERROR,
			    gettext("Unable to allocate root property"
			    "list\n"));
			return (errno);
		}
	}
	free(ondiskbuf);

	if (validate_devnvl() < 0) {
		logmsg(MSG_ERROR,
		    gettext("unable to validate kernel with on-disk devid "
		    "cache file\n"));
		return (errno);
	}

	/*
	 * If we're in single-user mode or maintenance mode, we won't
	 * necessarily have a writable root device (ZFSroot; ufs root is
	 * different in that we _do_ have a writable root device.
	 * This causes problems for the devlink calls (see
	 * $SRC/lib/libdevinfo/devinfo_devlink.c) and we do not try to
	 * write out the devnvl if root is readonly.
	 */
	if (!readonlyroot) {
		rv = nvlist_size(mapnvl, &newsz, NV_ENCODE_NATIVE);
		if (rv) {
			logmsg(MSG_ERROR,
			    gettext("Unable to determine size of packed "
			    "on-disk devid cache file %s: %s (%d).\n"),
			    ondiskname, strerror(rv), rv);
			logmsg(MSG_ERROR, gettext("Terminating\n"));
			nvlist_free(mapnvl);
			(void) close(mapfd);
			return (rv);
		}

		if ((ondiskbuf = calloc(1, newsz)) == NULL) {
			logmsg(MSG_ERROR,
			    "Unable to allocate space for writing out new "
			    "on-disk devid cache file: %s\n", strerror(errno));
			(void) close(mapfd);
			nvlist_free(mapnvl);
			return (errno);
		}

		rv = nvlist_pack(mapnvl, &ondiskbuf, &newsz,
		    NV_ENCODE_NATIVE, 0);
		if (rv) {
			logmsg(MSG_ERROR,
			    gettext("Unable to pack on-disk devid cache "
			    "file: %s (%d)\n"), strerror(rv), rv);
			(void) close(mapfd);
			free(ondiskbuf);
			nvlist_free(mapnvl);
			return (rv);
		}

		rv = lseek(mapfd, 0, 0);
		if (rv == -1) {
			logmsg(MSG_ERROR,
			    gettext("Unable to seek to start of devid cache "
			    "file: %s (%d)\n"), strerror(errno), errno);
			(void) close(mapfd);
			free(ondiskbuf);
			nvlist_free(mapnvl);
			return (-1);
		}

		if (write(mapfd, ondiskbuf, newsz) != newsz) {
			logmsg(MSG_ERROR,
			    gettext("Unable to completely write out "
			    "on-disk devid cache file: %s\n"), strerror(errno));
			(void) close(mapfd);
			nvlist_free(mapnvl);
			free(ondiskbuf);
			return (errno);
		}
	} /* !readonlyroot */

	/* Now we can process the command line args */
	if (globarg == MPX_PHYSICAL) {
		report_map(devicep, BOOT);
	} else if (globarg == MPX_BOOTPATH) {
		rv = print_bootpath();
		di_fini(devinfo_root);
		return (rv);
	} else if (globarg == MPX_UPDATEVFSTAB) {
		rv = update_vfstab();
		di_fini(devinfo_root);
		return (rv);
	} else if (globarg == MPX_GETPATH) {
		report_dev_node_name(devicep);
	} else if (globarg == MPX_DEV_PATH) {
		report_map(devicep, BOOT_PATH);
	} else if (globarg != MPX_INIT) {
		if (globarg & MPX_LIST)
			list_devs(guid, limctrl);

		if (globarg == MPX_MAP)
			report_map(devicep, NONBOOT);
	} else {
		logmsg(MSG_INFO, "\nprivate devid cache file initialised\n");
	}

	nvlist_free(mapnvl);
	di_fini(devinfo_root);
	return (0);
}

static void
usage()
{
	(void) fprintf(stderr,
	    gettext("usage: stmsboot_util -b | -m devname | "
	    "-l <ctrl> | -L | [-g] | -n | -N | -i | -p devname\n"));
	(void) fprintf(stderr, "\n\n");
	(void) fprintf(stderr, gettext("\t-h\tprint this usage message\n"));
	(void) fprintf(stderr, gettext("\t-b\tretrieve the system's bootpath "
	    "setting\n"));
	(void) fprintf(stderr, gettext("\t-m devname\n"));
	(void) fprintf(stderr, gettext("\t\tReports the current mapping for "
	    "devname\n"));
	(void) fprintf(stderr, gettext("\t-g\tprint the GUID for MPxIO-capable "
	    "devices. This\n"));
	(void) fprintf(stderr, gettext("\t\toption is only valid with the -L "
	    "or -l options\n"));
	(void) fprintf(stderr, gettext("\t-L | -l <ctrl>\n"));
	(void) fprintf(stderr, gettext("\t\tList the 'native' to 'MPxIO' "
	    "device mappings. If <ctrl>\n"));
	(void) fprintf(stderr, gettext("\t\tis specified, only print mappings "
	    "for those devices\n"));
	(void) fprintf(stderr, gettext("\t\tattached via the specified "
	    "controller.\n"));
	(void) fprintf(stderr, gettext("\t-i\tinitialise the private devid "
	    "cache file and exit\n"));
	(void) fprintf(stderr, gettext("\t\tThis option excludes all "
	    "others.\n"));
	(void) fprintf(stderr, gettext("\t-n\tprint the devfs paths for "
	    "multipath-capable\n"));
	(void) fprintf(stderr, gettext("\t\tcontroller ports.\n"));
	(void) fprintf(stderr, gettext("\t-N\tprint the device aliases of "
	    "multipath-capable\n"));
	(void) fprintf(stderr, gettext("\t\tcontroller ports.\n"));
	(void) fprintf(stderr, gettext("\t-p\tdevname\n"));
	(void) fprintf(stderr, gettext("\t\tThis option provides the physical "
	    "devfs path for\n"));
	(void) fprintf(stderr, gettext("\t\ta specific device (devname). Used "
	    "to set the bootpath\n"));
	(void) fprintf(stderr, gettext("\t\tvariable on x86/x64 systems\n"));
	(void) fprintf(stderr, gettext("\t-u\ttranslates device mappings in "
	    "/etc/vfstab as \n"));
	(void) fprintf(stderr, gettext("\t\trequired. The output is written "
	    "to /etc/mpxio/vfstab.new\n\n"));
	exit(2);
}

static void
parse_args(int argc, char *argv[])
{
	int opt;

	if (argc == 1)
		usage();

	/*
	 * -b	prints the bootpath property
	 * -d	turns on debug mode for this utility (copious output!)
	 * -D drvname
	 *	if supplied, indicates that we're going to operate on
	 *	devices attached to this driver.
	 * -g	if (-l or -L), prints guids for devices rather than paths
	 * -h	prints the usage() help text.
	 * -i	initialises the cache file and exits.
	 * -l controller
	 *	list non-STMS to STMS device name mappings for the specific
	 *	controller, when MPxIO is enabled only.
	 * -L	list non-STMS to STMS device name mappings for all controllers
	 *	when MPxIO is enabled only.
	 * -m devname
	 *	prints the device path (/dev/rdsk) that devname maps to
	 *	in the currently-running system.
	 * -n
	 *	if supplied, returns name of STMS-capable controller nodes.
	 *	If the -D drvname option is specified as well, we only report
	 *	nodes attached with drvname.
	 * -N
	 *	same as the -n option, except that we only print the
	 *	node-name (dev_info :: devi_node_name). Multiple instances
	 *	through the libdevinfo snapshot are uniqified and separated
	 *	by the "|" character for direct use by egrep(1).
	 * -p devname
	 *	prints the physical devfs path for devname. Only used to
	 *	determine the bootpath.
	 * -u
	 *	remaps devices in /etc/vfstab, saving the newly generated
	 *	file to /etc/mpxio/vfstab.new. If we have any remapped
	 *	devices, exit with status 0, otherwise -1 for error.
	 */
	while ((opt = getopt(argc, argv, "bdD:ghil:Lm:nNo:p:q:u")) != EOF) {
		switch (opt) {
		case 'b':
			globarg = MPX_BOOTPATH;
			break;
		case 'd':
			debugflag = 1;
			break;
		case 'D':
			if ((drvlimit = calloc(1, MAXMODCONFNAME)) == NULL) {
				logmsg(MSG_ERROR,
				    gettext("Unable to allocate memory for a "
				    "driver name: %s\n"), strerror(errno));
				exit(errno);
			}
			if (strlcpy(drvlimit, optarg, MAXMODCONFNAME) >=
			    MAXMODCONFNAME) {
				logmsg(MSG_ERROR,
				    gettext("invalid parent driver (%s) "
				    "specified"), optarg);
				usage();
			}
			/* update this if adding support for a new driver */
			if (strcmp(drvlimit, "fp") != 0 &&
			    strcmp(drvlimit, "mpt") != 0 &&
			    strcmp(drvlimit, "mpt_sas") != 0 &&
			    strcmp(drvlimit, "pmcs") != 0) {
				logmsg(MSG_ERROR,
				    gettext("invalid parent driver (%s) "
				    "specified"), drvlimit);
				usage();
			}
			break;
		case 'h':
			/* Just drop out and print the usage() output */
			globarg = MPX_USAGE;
			break;
		case 'i':
			globarg = MPX_INIT;
			break;
		case 'l':
			globarg |= MPX_LIST;
			limctrl = (int)atol(optarg);
			if (limctrl < 0) {
				logmsg(MSG_INFO,
				    gettext("invalid controller number "
				    "(%d), checking all controllers\n"),
				    limctrl);
			}
			break;
		case 'L':
			globarg |= MPX_LIST;
			break;
		case 'g':
			guid = 1;
			break;
		case 'm':
			globarg = MPX_MAP;
			if ((devicep = calloc(1, MAXPATHLEN)) == NULL) {
				logmsg(MSG_ERROR,
				    gettext("Unable to allocate space for a "
				    "device name\n"));
				exit(errno);
			}
			devicep = strdup(optarg);
			break;
		case 'N':
			cap_N_option = 1;
			globarg = MPX_CAPABLE_CTRL;
			break;
		case 'n':
			globarg = MPX_CAPABLE_CTRL;
			break;
		case 'o':
			globarg = MPX_GETPATH;
			if ((devicep = calloc(1, MAXPATHLEN)) == NULL) {
				logmsg(MSG_ERROR,
				    gettext("Unable to allocate space for a "
				    "device name\n"));
				exit(errno);
			}
			devicep = strdup(optarg);
			break;
		case 'p':
			globarg = MPX_PHYSICAL;
			if ((devicep = calloc(1, MAXPATHLEN)) == NULL) {
				logmsg(MSG_ERROR,
				    gettext("Unable to allocate space for a "
				    "device name\n"));
				exit(errno);
			}
			devicep = strdup(optarg);
			break;
		case 'q':
			globarg = MPX_DEV_PATH;
			if ((devicep = calloc(1, MAXPATHLEN)) == NULL) {
				logmsg(MSG_ERROR,
				    gettext("Unable to allocate space for a "
				    "device name\n"));
				exit(errno);
			}
			devicep = strdup(optarg);
			break;
		case 'u':
			globarg = MPX_UPDATEVFSTAB;
			break;
		default:
			logmsg(MSG_ERROR,
			    gettext("Invalid command line option (%c)\n"),
			    opt);
			usage();
		}
	}

	if ((globarg >= MPX_USAGE) || (guid && (globarg != MPX_LIST)))
		usage();

	if ((drvlimit != NULL) &&
	    ((globarg != MPX_LIST) &&
	    (globarg != MPX_CAPABLE_CTRL)))
		usage();
}

static void
logmsg(int level, const char *msg, ...)
{
	va_list ap;

	if ((level >= MSG_ERROR) ||
	    ((debugflag > 0) && (level >= MSG_INFO))) {
		(void) fprintf(stdout, "stmsboot: ");
		va_start(ap, msg);
		(void) vfprintf(stdout, msg, ap);
		va_end(ap);
	}
}

/*
 * It's up to the caller to do any sorting or pretty-printing of the device
 * mappings we report. Since we're storing the device links as just the cXtYdZ
 * part, we'll add /dev/rdsk/ back on when we print the listing so we maintain
 * compatibility with previous versions of this tool. There's a little bit
 * of footwork involved to make sure that we show all the paths to a device
 * rather than just the first one we stashed away.
 */
static void
list_devs(int listguids, int ctrl)
{
	nvlist_t *thisdevnvl;
	nvpair_t *pair;
	char *diskpath, *livepath, *key, *querydev;
	char *matchctrl = NULL;
	char checkctrl[MAXPATHLEN];
	int rv;

	if (!mpxenabled) {
		if (mpxprop) {
			logmsg(MSG_ERROR, gettext("MPXIO disabled\n"));
		} else {
			logmsg(MSG_ERROR, gettext("No STMS devices have "
			    "been found\n"));
		}
		return;
	}

	if (listguids) {
		(void) printf(gettext("non-STMS device name\t\t\tGUID\n"
		    "------------------------------------------"
		    "------------------------\n"));
	} else {
		(void) printf(gettext("non-STMS device name\t\t\t"
		    "STMS device name\n"
		    "------------------------------------------"
		    "------------------------\n"));
	}

	bzero(checkctrl, MAXPATHLEN);
	pair = NULL;
	while ((pair = nvlist_next_nvpair(mapnvl, pair))
	    != NULL) {
		boolean_t livescsivhcip = B_FALSE;

		if ((((rv = nvpair_value_string(pair, &querydev)) < 0) ||
		    ((key = nvpair_name(pair)) == NULL)) ||
		    ((strstr(key, "/pci") != NULL) ||
		    (strstr(key, "/sbus") != NULL) ||
		    (strstr(key, "/scsi_vhci") != NULL) ||
		    (strncmp(key, "id1", 3) == 0))) {
			logmsg(MSG_INFO,
			    "list_devs: rv = %d; (%s) is not a devlink, "
			    "continuing.\n", rv,
			    (key != NULL) ? key : "null");
			querydev = NULL;
			continue;
		}

		(void) nvlist_lookup_nvlist(mapnvl, querydev, &thisdevnvl);
		(void) nvlist_lookup_boolean_value(thisdevnvl, NVL_MPXEN,
		    &livescsivhcip);
		(void) nvlist_lookup_string(thisdevnvl, NVL_MPXPATH,
		    &livepath);

		if ((!livescsivhcip) ||
		    (livescsivhcip &&
		    (strncmp(key, livepath, strlen(key)) == 0)))
			continue;

		(void) nvlist_lookup_string(thisdevnvl, NVL_PATH,
		    &diskpath);

		logmsg(MSG_INFO,
		    "list_devs: %s :: %s ::%s :: MPXEN (%s)\n",
		    key, diskpath, livepath,
		    ((livescsivhcip) ? "TRUE" : "FALSE"));

		if (ctrl > -1) {
			(void) sprintf(checkctrl, "c%dt", ctrl);
			matchctrl = strstr(key, checkctrl);
			if (matchctrl == NULL)
				continue;
		}
		if (listguids != 0) {
			char *tempguid;
			ddi_devid_t curdevid;
			int rv;

			rv = devid_str_decode(querydev, &curdevid, NULL);
			if (rv == -1) {
				logmsg(MSG_INFO, "Unable to decode devid %s\n",
				    key);
				continue;
			}
			tempguid = devid_to_guid(curdevid);
			if (tempguid != NULL)
				(void) printf("/dev/rdsk/%s\t%s\n",
				    diskpath, tempguid);

			devid_free_guid(tempguid);
			devid_free(curdevid);
			continue;
		}

		(void) printf("/dev/rdsk/%s\t/dev/rdsk/%s\n",
		    (strstr(key, diskpath) == NULL) ? key : diskpath,
		    livepath);
	}
}

/*
 * We get passed a device name which we search the mapnvl for. If we find
 * it, we print the mapping as it is found. It is up to the caller of this
 * utility to do any pretty-printing of the results. If a device listed on
 * the command line does not exist in the mapnvl, then we print NOT_MAPPED.
 * Otherwise we print the command-line device name as it maps to what is
 * stashed in the mapnvl - even if that's a "no change" device mapping.
 *
 * Example output (-p maps to physpath=BOOT)
 * # /lib/mpxio/stmsboot_util -p \
 *	/pci@0,0/pci1022,7450@2/pci1000,3060@3/sd@1,0:a
 * /scsi_vhci/disk@g500000e011e17720:a
 *
 * Or the reverse:
 * # /lib/mpxio/stmsboot_util -p /scsi_vhci/disk@g500000e011e17720:a
 * /pci@0,0/pci1022,7450@2/pci1000,3060@3/sd@1,0:a
 *
 * For the -m option, used when we're trying to find the root device mapping:
 *
 * # /lib/mpxio/stmsboot_util -m /dev/dsk/c2t0d0s2
 * /dev/dsk/c3t500000E011637CF0d0s2
 */
static void
report_map(char *argdev, int physpath)
{
	nvlist_t *thisdev;
	int rv = 0;
	char *thisdevid;
	char *mpxpath = NULL;
	char *prefixt = NULL;
	char *prefixp = NULL;
	char *stripdev = NULL;
	char *slice = NULL;
	boolean_t mpxenp;
	uint_t slicelen = 0;

	mpxenp = B_FALSE;

	if ((prefixt = calloc(1, strlen(argdev) + 1)) == NULL) {
		logmsg(MSG_INFO, "Unable to allocate memory\n");
		(void) printf("NOT_MAPPED\n");
		return;
	}

	(void) strlcpy(prefixt, argdev, strlen(argdev) + 1);

	slice = strrchr(argdev, (physpath == NONBOOT) ? 's' : ':');
	if (slice != NULL) {
		slicelen = strlen(slice);
		if (slicelen > 3)
			/* invalid size - max is 3 chars */
			slicelen = 0;
	}

	if ((stripdev = calloc(1, strlen(prefixt) + 1)) == NULL) {
		logmsg(MSG_INFO, "Unable to allocate memory\n");
		(void) printf("NOT_MAPPED\n");
		free(prefixt);
		return;
	}

	if ((strstr(prefixt, "/scsi_vhci") == NULL) &&
	    (strstr(prefixt, "/pci") == NULL) &&
	    (strstr(prefixt, "/sbus") == NULL)) {
		prefixp = strrchr(prefixt, '/');
		(void) strlcpy(stripdev,
		    (prefixp == NULL) ? prefixt : prefixp + 1,
		    (prefixp == NULL) ?
		    strlen(prefixt) + 1: strlen(prefixp) + 1);
		if (prefixp != NULL)
			prefixt[strlen(argdev) - strlen(prefixp) + 1] = '\0';
	} else {
		if ((physpath != BOOT) &&
		    (physpath != BOOT_PATH)) {
			logmsg(MSG_INFO, "Invalid device path provided\n");
			(void) printf("NOT_MAPPED\n");
			free(stripdev);
			free(prefixt);
			return;
		}
		(void) strlcpy(stripdev, argdev, strlen(argdev) + 1);
	}

	logmsg(MSG_INFO,
	    "stripdev (%s), prefixt(%s), prefixp(%s), slice(%s)\n",
	    (stripdev == NULL) ? "null" : stripdev,
	    (prefixt == NULL) ? "null" : prefixt,
	    (prefixp == NULL) ? "null" : prefixp,
	    (slice == NULL) ? "null" : slice);

	if (slicelen > 0)
		stripdev[strlen(stripdev) - slicelen] = '\0';

	/* search for the shortened version */
	rv = nvlist_lookup_string(mapnvl, stripdev, &thisdevid);
	if (rv) {
		if ((physpath != BOOT) &&
		    (physpath != BOOT_PATH)) {
			logmsg(MSG_INFO,
			    "searched mapnvl for '%s', got %s (%d)\n",
			    stripdev, strerror(rv), rv);
			(void) printf("NOT_MAPPED\n");
			free(stripdev);
			free(prefixt);
			return;
		}
	}

	logmsg(MSG_INFO, "device %s has devid %s\n", stripdev, thisdevid);

	if (nvlist_lookup_nvlist(mapnvl, thisdevid, &thisdev) != 0) {
		logmsg(MSG_INFO, "device (%s) in mapnvl but "
		    "not mapped!\n", thisdevid);
		(void) printf("NOT_MAPPED\n");
		free(stripdev);
		free(prefixt);
		return;
	}

	/* quick exit */
	if (!mpxenabled && (strstr(argdev, "/pci") != NULL ||
	    strstr(argdev, "/sbus") != NULL)) {
		(void) printf("%s\n", argdev);
		free(stripdev);
		free(prefixt);
		return;
	}

	(void) nvlist_lookup_boolean_value(thisdev, NVL_MPXEN, &mpxenp);

	if (physpath == BOOT) {
		(void) nvlist_lookup_string(thisdev, NVL_PHYSPATH, &mpxpath);
		if ((strstr(argdev, "/scsi_vhci") != NULL) &&
		    (strncmp(argdev, mpxpath, strlen(mpxpath)) == 0)) {
			/* Need to translate vhci to phci */
			vhci_to_phci(stripdev, slice, DISPLAY_ONE_PATH);
		} else {
			(void) printf("%s%s\n", mpxpath,
			    ((slicelen > 0) && slice != NULL) ? slice : "");
		}
	} else if (physpath == BOOT_PATH) {
		(void) nvlist_lookup_string(thisdev, NVL_PHYSPATH, &mpxpath);
		if ((strstr(argdev, "/scsi_vhci") != NULL) &&
		    (strncmp(argdev, mpxpath, strlen(mpxpath)) == 0)) {
			/* Need to translate vhci to phci */
			vhci_to_phci(stripdev, slice, DISPLAY_ALL_PATH);
		} else {
			(void) printf("%s%s\n", mpxpath,
			    ((slicelen > 0) && slice != NULL) ? slice : "");
		}
	} else {
		(void) nvlist_lookup_string(thisdev,
		    ((readonlyroot) ? NVL_PHYSPATH :
		    ((mpxenp == B_TRUE) ? NVL_MPXPATH : NVL_PATH)),
		    &mpxpath);
		logmsg(MSG_INFO, "mpxpath = %s\n",
		    (mpxpath == NULL) ? "null" : mpxpath);
		if (readonlyroot ||
		    (strstr(mpxpath, "/scsi_vhci") != NULL) ||
		    (strstr(mpxpath, "/pci") != NULL) ||
		    (strstr(mpxpath, "/sbus") != NULL)) {
			/*
			 * If we see a physical path here it means that
			 * devlinks aren't fully initialised yet, so we
			 * are still in maintenance/single-user mode.
			 */
			(void) printf("/devices%s:%c\n", mpxpath,
			    slice[1] + '1');
		} else {
			(void) printf("%s%s%s\n",
			    (prefixt[0] == '/') ? prefixt : "",
			    mpxpath,
			    ((slicelen > 0) && slice != NULL) ? slice : "");
		}
	}
	free(prefixt);
	free(stripdev);
}

/*
 * Validate the in-kernel and on-disk forms of our devid cache,
 * returns  -1 for unfixable error and 0 for success.
 */
static int
validate_devnvl()
{
	di_node_t	curnode;
	int		rv1 = -1;
	int		rv2 = -1;

	/*
	 * Method: we walk through the kernel's concept of the device tree
	 * looking for "ssd" then "sd" nodes.
	 * We check to see whether the device's devid is already in our nvlist
	 * (on disk) nvlist cache file. If it is, we check that it's components
	 * match what we've got already and fill any missing fields.
	 * If the devid isn't in our on-disk nvlist already then we add it
	 * and populate the property nvpairs.
	 *
	 * At the end of this function we should have this program's concept
	 * of the devid-keyed nvlist matching what is in the ondisk form which
	 * is ready to be written out.
	 * If we can't do this, then we return -1.
	 */
	curnode = di_drv_first_node("ssd", devinfo_root);
	if (curnode != DI_NODE_NIL)
		rv1 = mpxio_nvl_boilerplate(curnode);

	curnode = di_drv_first_node("sd", devinfo_root);
	if (curnode != DI_NODE_NIL)
		rv2 = mpxio_nvl_boilerplate(curnode);

	if (rv1 + rv2 == -2)
		return (-1);

	return (0);
}

/*
 * According to devfs path name, it will print device node name.
 */
static void
print_node_name(char *drv_name, char *strdevfspath)
{
	di_node_t	curnode;
	char *devfspath = NULL;
	char *node_name = NULL;

	curnode = di_drv_first_node(drv_name, devinfo_root);
	for (; curnode != DI_NODE_NIL; curnode = di_drv_next_node(curnode)) {
		devfspath = di_devfs_path(curnode);
		logmsg(MSG_INFO, "find: devfspath %s\n", devfspath);

		if (devfspath == NULL)
			continue;

		if ((strlen(strdevfspath) == strlen(devfspath)) &&
		    (strncmp(strdevfspath, devfspath,
		    strlen(devfspath)) == 0)) {
			node_name = find_link(curnode);
			if (node_name == NULL) {
				(void) printf("NOT MAPPED\n");
			} else {
				(void) printf("%s\n", node_name);
			}
			return;
		}
	}
}

/*
 * report device node name, search "ssd" and "sd" nodes,
 * print the device node name which device path is same as
 * parameter.
 */
static void
report_dev_node_name(char *strdevfspath)
{
	logmsg(MSG_INFO, "strdevfspath: %s\n", strdevfspath);
	print_node_name("ssd", strdevfspath);
	print_node_name("sd", strdevfspath);
}

static int
mpxio_nvl_boilerplate(di_node_t curnode)
{
	int		rv;
	char		*strdevid;
	ddi_devid_t	curdevid;
	nvlist_t	*newnvl;

	for (; curnode != DI_NODE_NIL; curnode = di_drv_next_node(curnode)) {
		errno = 0;

		curdevid = NULL;
		get_devid(curnode, &curdevid);
		if (curdevid == NULL)
			/*
			 * There's no devid registered for this device
			 * so it's not cool enough to play with us
			 */
			continue;

		strdevid = devid_str_encode(curdevid, NULL);
		/* does this exist in the on-disk cache? */
		rv = nvlist_lookup_nvlist(mapnvl, strdevid, &newnvl);
		if (rv == ENOENT) {
			logmsg(MSG_INFO, "nvlist for %s not found\n", strdevid);
			/* no, so alloc a new nvl to store it */
			if (nvlist_alloc(&newnvl, NV_UNIQUE_NAME, 0) != 0) {
				logmsg(MSG_ERROR,
				    gettext("Unable to allocate space for "
				    "a devid property list: %s\n"),
				    strerror(errno));
				return (-1);
			}
		} else {
			if ((rv != ENOTSUP) && (rv != EINVAL))
				logmsg(MSG_INFO,
				    "%s exists in ondisknvl, verifying\n",
				    strdevid);
		}

		if (popcheck_devnvl(curnode, newnvl, strdevid) != 0) {
			logmsg(MSG_ERROR,
			    gettext("Unable to populate devid nvpair "
			    "for device with devid %s\n"),
			    strdevid);
			devid_str_free(strdevid);
			nvlist_free(newnvl);
			return (-1);
		}

		/* Now add newnvl into our cache. */
		errno = 0;
		rv = nvlist_add_nvlist(mapnvl, strdevid, newnvl);
		if (rv) {
			logmsg(MSG_ERROR,
			    gettext("Unable to add device (devid %s) "
			    "to in-kernel nvl: %s (%d)\n"),
			    strdevid, strerror(rv), rv);
			devid_str_free(strdevid);
			nvlist_free(newnvl);
			return (-1);
		}
		logmsg(MSG_INFO,
		    gettext("added device (devid %s) to mapnvl\n\n"),
		    strdevid);
		devid_str_free(strdevid);
	}
	return (0);
}

/*
 * Operates on a single di_node_t, collecting all the device properties
 * that we need. devnvl is allocated by the caller, and we add our nvpairs
 * to it if they don't already exist.
 *
 * We are _only_ interested in devices which have a devid. We pull in
 * devices even when they're excluded via stmsboot -D (driver), because
 * we don't want to miss out on any devid data that might be handy later.
 */
static int
popcheck_devnvl(di_node_t thisnode, nvlist_t *devnvl, char *strdevid)
{
	char *path = NULL;
	char *curpath = NULL;
	char *devfspath = NULL;
	char *prop = NULL;
	int scsivhciparent = 0;
	int rv = 0;
	boolean_t mpxenp = B_FALSE;

	errno = 0;
	devfspath = di_devfs_path(thisnode);
	if (devfspath == NULL) {
		logmsg(MSG_ERROR,
		    gettext("Unable to determine devfs path for node: %s\n"),
		    strerror(errno));
		return (-1);
	}

	/* Add a convenient devfspath to devid inverse map */
	if (nvlist_add_string(mapnvl, devfspath, strdevid) != 0) {
		logmsg(MSG_ERROR,
		    gettext("Unable to add device path %s with devid "
		    "%s to mapnvl\n"), devfspath, strdevid);
		return (-1);
	}
	if (di_prop_lookup_strings(DDI_DEV_T_ANY, di_parent_node(thisnode),
	    "mpxio-disable", &prop) >= 0) {
		if (strncmp(prop, "yes", 3) == 0) {
			if (!mpxprop)
				mpxprop++;
		}
	}

	if (strncmp(di_driver_name(di_parent_node(thisnode)),
	    "scsi_vhci", 9) == 0) {
		scsivhciparent = 1;
		if (!mpxenabled)
			mpxenabled++;

		rv = nvlist_lookup_boolean_value(devnvl, NVL_MPXEN, &mpxenp);
		if (rv || (mpxenp == B_FALSE)) {
			rv = nvlist_add_boolean_value(devnvl,
			    NVL_MPXEN, B_TRUE);
			if (rv) {
				logmsg(MSG_ERROR,
				    gettext("Unable to add property %s "
				    "(set to B_TRUE) for device %s: "
				    "%s (%d)\n"),
				    NVL_MPXEN, devfspath,
				    strerror(rv), rv);
				return (-1);
			}
			logmsg(MSG_INFO, "NVL_MPXEN :: (B_FALSE->B_TRUE)\n");
		}
	} else {
		/* turn _off_ the flag if it was enabled */
		rv = nvlist_add_boolean_value(devnvl, NVL_MPXEN, B_FALSE);
		if (rv) {
			logmsg(MSG_ERROR,
			    gettext("Unable to add property %s "
			    "(set to B_FALSE) for device %s: %s (%d)\n"),
			    NVL_MPXEN, devfspath,
			    strerror(rv), rv);
			return (-1);
		}
		logmsg(MSG_INFO, "NVL_MPXEN :: (B_TRUE-> B_FALSE)\n");
	}

	rv = nvlist_add_string(devnvl, NVL_PHYSPATH, devfspath);
	if (rv) {
		logmsg(MSG_ERROR,
		    gettext("Unable to add physical device path (%s) "
		    "property to nvl\n"));
		return (-1);
	}

	if ((curpath = calloc(1, MAXPATHLEN)) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("Unable to allocate space for current path\n"));
		return (-1);
	}
	curpath = find_link(thisnode);
	if (curpath == NULL) {
		if (readonlyroot) {
			return (0);
		}
		logmsg(MSG_ERROR,
		    gettext("Unable to determine device path for node %s\n"),
		    devfspath);
		return (-1);
	}

	rv = nvlist_lookup_string(devnvl, NVL_MPXPATH, &path);

	if (scsivhciparent) {
		(void) nvlist_add_string(devnvl, NVL_MPXPATH, curpath);
	} else {
		(void) nvlist_add_string(devnvl, NVL_PATH, curpath);
		path = curpath;
	}

	/*
	 * This next block provides the path to devid inverse mapping
	 * that other functions require
	 */
	if (path != NULL) {
		if (nvlist_add_string(mapnvl, path, strdevid) != 0) {
			logmsg(MSG_ERROR,
			    gettext("Unable to add device %s with devid "
			    "%s to mapnvl\n"), path, strdevid);
			return (-1);
		}
		logmsg(MSG_INFO, "popcheck_devnvl: added path %s :: %s\n",
		    path, strdevid);
	}

	if (nvlist_add_string(mapnvl, curpath, strdevid) != 0) {
			logmsg(MSG_ERROR,
			    gettext("Unable to add device %s with devid "
			    "%s to mapnvl: %s\n"),
			    curpath, strdevid, strerror(errno));
			return (-1);
	}
	logmsg(MSG_INFO, "popcheck_devnvl: added curpath %s :: %s\n",
	    curpath, strdevid);

	return (0);
}

static void
print_mpx_capable(di_node_t curnode)
{
	char *prop;
	char *path;
	char *aliases = NULL;

	if (cap_N_option) {
		aliases = calloc(1, MAXPATHLEN + 1);
		if (aliases == NULL) {
			logmsg(MSG_ERROR,
			    gettext("Unable to allocate memory for a device "
			    "alias list\n"));
			return;
		}
	}

	for (; curnode != DI_NODE_NIL; curnode = di_drv_next_node(curnode)) {
		if (di_prop_lookup_strings(DDI_DEV_T_ANY, curnode,
		    "initiator-port", &prop) >= 0) {
			if ((path = di_devfs_path(curnode)) == NULL) {
				logmsg(MSG_INFO,
				    "Unable to find devfs path for device "
				    "%s: %s\n", &curnode, strerror(errno));
				continue;
			}
			if (cap_N_option) {
				char *nodename = di_node_name(curnode);
				/* nodename is never going to be null */
				if (strstr(aliases, nodename) == NULL)
					/* haven't seen this nodename before */
					(void) snprintf(aliases,
					    MAXPATHLEN + 1, "%s|%s",
					    ((aliases != NULL) ? aliases : ""),
					    nodename);
			} else
				(void) printf("%s\n", path);
		}
	}
	if (cap_N_option)
		(void) printf("%s\n", aliases);
}

static int
link_cb(di_devlink_t devlink, void *arg)
{
	const char *result;

	result = di_devlink_path(devlink);
	if (result == NULL) {
		arg = (void *)"(null)";
	} else {
		(void) strlcpy(arg, result, strlen(result));
	}
	logmsg(MSG_INFO, "\nlink_cb::linkdata->resultstr = %s\n",
	    ((result != NULL) ? result : "(null)"));
	return (DI_WALK_CONTINUE);
}

static char *
find_link(di_node_t cnode)
{
	di_minor_t devminor = DI_MINOR_NIL;
	di_devlink_handle_t	hdl;
	char *devfspath = NULL;
	char *minorpath = NULL;
	char *linkname = NULL;
	char *cbresult = NULL;

	devfspath = di_devfs_path(cnode);
	if (cnode == DI_NODE_NIL) {
		logmsg(MSG_ERROR,
		    gettext("find_ctrl must be called with non-null "
		    "di_node_t\n"));
		return (NULL);
	}
	logmsg(MSG_INFO, "find_link: devfspath %s\n", devfspath);

	if (((cbresult = calloc(1, MAXPATHLEN)) == NULL) ||
	    ((minorpath = calloc(1, MAXPATHLEN)) == NULL) ||
	    ((linkname = calloc(1, MAXPATHLEN)) == NULL)) {
		logmsg(MSG_ERROR, "unable to allocate space for dev link\n");
		return (NULL);
	}

	devminor = di_minor_next(cnode, devminor);
	hdl = di_devlink_init(di_devfs_minor_path(devminor), DI_MAKE_LINK);
	if (hdl == NULL) {
		logmsg((readonlyroot ? MSG_INFO : MSG_ERROR),
		    gettext("unable to take devlink snapshot: %s\n"),
		    strerror(errno));
		return (NULL);
	}

	linkname = "^dsk/";
	(void) snprintf(minorpath, MAXPATHLEN, "%s:c", devfspath);

	errno = 0;
	if (di_devlink_walk(hdl, linkname, minorpath, DI_PRIMARY_LINK,
	    (void *)cbresult, link_cb) < 0) {
		logmsg(MSG_ERROR,
		    gettext("Unable to walk devlink snapshot for %s: %s\n"),
		    minorpath, strerror(errno));
		return (NULL);
	}

	if (di_devlink_fini(&hdl) < 0) {
		logmsg(MSG_ERROR,
		    gettext("Unable to close devlink snapshot: %s\n"),
		    strerror(errno));
	}
	if (strstr(cbresult, "dsk/") == NULL)
		return (devfspath);

	bzero(minorpath, MAXPATHLEN);
	/* strip off the trailing "s2" */
	bcopy(cbresult, minorpath, strlen(cbresult) - 1);
	/* Now strip off the /dev/dsk/ prefix for output flexibility */
	linkname = strrchr(minorpath, '/');
	return (++linkname);
}

/*
 * handle case where device has been probed but its target driver is not
 * attached so enumeration has not quite finished. Opening the /devices
 * pathname will force the kernel to finish the enumeration process and
 * let us get the data we need.
 */
static void
get_devid(di_node_t node, ddi_devid_t *thisdevid)
{
	int fd;
	char realpath[MAXPATHLEN];
	char *openpath = di_devfs_path(node);

	errno = 0;
	bzero(realpath, MAXPATHLEN);
	if (strstr(openpath, "/devices") == NULL) {
		(void) snprintf(realpath, MAXPATHLEN,
		    "/devices%s:c,raw", openpath);
		fd = open(realpath, O_RDONLY|O_NDELAY);
	} else {
		fd = open(openpath, O_RDONLY|O_NDELAY);
	}

	if (fd < 0) {
		logmsg(MSG_INFO, "Unable to open path %s: %s\n",
		    openpath, strerror(errno));
		return;
	}

	if (devid_get(fd, thisdevid) != 0) {
		logmsg(MSG_INFO,
		    "'%s' node (%s) without a devid registered\n",
		    di_driver_name(node), di_devfs_path(node));
	}
	(void) close(fd);
}

static int
print_bootpath()
{
	char *bootprop = NULL;

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, devinfo_root,
	    "bootpath", &bootprop) >= 0) {
		(void) printf("%s\n", bootprop);
		return (0);
	} else if (di_prop_lookup_strings(DDI_DEV_T_ANY, devinfo_root,
	    "boot-path", &bootprop) >= 0) {
		(void) printf("%s\n", bootprop);
		return (0);
	} else {
		(void) printf("ERROR: no bootpath/boot-path property found\n");
		return (ENOENT);
	}
}

static void
get_phci_driver_name(char *phci_path, char **driver_name)
{
	di_node_t phci_node = DI_NODE_NIL;
	char *tmp = NULL;

	phci_node = di_init(phci_path, DINFOCPYONE);
	if (phci_node == DI_NODE_NIL) {
		logmsg(MSG_ERROR,
		    gettext("Unable to take phci snapshot "
		    "(%s: %d)\n"), strerror(errno), errno);
		return;
	}
	tmp = di_driver_name(phci_node);
	if (tmp != NULL) {
		(void) strncpy(*driver_name, tmp, 10);
	}
	di_fini(phci_node);
}

/*
 * We only call this routine if we have a scsi_vhci node and must
 * determine the actual physical path of its first online client
 * path.
 */
static void
vhci_to_phci(char *devpath, char *slice, int d_flag)
{
	sv_iocdata_t	ioc;
	sv_path_info_t	*pi;
	int		vhci_fd;
	int		rv;
	uint_t		npaths = 0;
	char nodename[MAXPATHLEN];
	char *phci_driver = NULL;

	vhci_fd = open(VHCI_CTL_NODE, O_RDWR);
	if (vhci_fd < 0)
		goto failure;

	bzero(&ioc, sizeof (sv_iocdata_t));
	ioc.client = devpath;
	ioc.ret_elem = &npaths;
	rv = ioctl(vhci_fd, SCSI_VHCI_GET_CLIENT_MULTIPATH_INFO, &ioc);
	if (rv || npaths == 0) {
		logmsg(MSG_INFO,
		    "SCSI_VHCI_GET_CLIENT_MULTIPATH_INFO ioctl() failed, "
		    "%s (%d)\n", strerror(rv), rv);
		goto failure;
	}

	bzero(&ioc, sizeof (sv_iocdata_t));
	ioc.client = devpath;
	ioc.buf_elem = npaths;
	ioc.ret_elem = &npaths;
	if ((ioc.ret_buf = calloc(npaths, sizeof (sv_path_info_t)))
	    == NULL)
		goto failure;
	rv = ioctl(vhci_fd, SCSI_VHCI_GET_CLIENT_MULTIPATH_INFO, &ioc);
	if (rv || npaths == 0) {
		logmsg(MSG_INFO,
		    "SCSI_VHCI_GET_CLIENT_MULTIPATH_INFO ioctl() (#2) "
		    "failed, %s (%d)\n", strerror(rv), rv);
		free(ioc.ret_buf);
		goto failure;
	}

	if (ioc.buf_elem < npaths)
		npaths = ioc.buf_elem;

	phci_driver = malloc(10);
	if (phci_driver == NULL) {
		logmsg(MSG_INFO,
		    "vhci_to_phci: Memory allocation failed\n");
		free(ioc.ret_buf);
		goto failure;
	}

	pi = (sv_path_info_t *)ioc.ret_buf;
	while (npaths--) {
		bzero(nodename, MAXPATHLEN);
		bzero(phci_driver, 10);

		get_phci_driver_name(pi->device.ret_phci,
		    &phci_driver);
		logmsg(MSG_INFO, "phci driver name: %s\n", phci_driver);
		/*
		 * A hack, but nicer than a platform-specific ifdef
		 * fp on SPARC using "ssd" as nodename
		 * mpt use "sd" when mpxio disabled, use "disk" when
		 * mpxio is enabled
		 * for alll other cases, "disk" should be used as the
		 * nodename
		 */
		if (strstr(devpath, "ssd") != NULL) {
			(void) snprintf(nodename, 5, "ssd");
		} else if (strncmp(phci_driver, "mpt", 10) == 0) {
			(void) snprintf(nodename, 5, "sd");
		} else {
			(void) snprintf(nodename, 5, "disk");
		}
		if ((d_flag == DISPLAY_ONE_PATH) &&
		    (pi->ret_state == MDI_PATHINFO_STATE_ONLINE)) {
			(void) printf("%s/%s@%s", pi->device.ret_phci,
			    nodename, pi->ret_addr);
			if ((slice != NULL) && (strlen(slice) <= 3)) {
				(void) printf("%s\n", slice);
			} else {
				(void) printf("\n");
			}
			break;
		} else if (d_flag == DISPLAY_ALL_PATH) {
			(void) printf("%s/%s@%s", pi->device.ret_phci,
			    nodename, pi->ret_addr);
			if ((slice != NULL) && (strlen(slice) <= 3)) {
				(void) printf("%s\n", slice);
			} else {
				(void) printf("\n");
			}
		}
		pi++;
	}
	free(ioc.ret_buf);
	free(phci_driver);
	return;

failure:
	(void) printf("NOT_MAPPED\n");
}

/*
 * Write /etc/vfstab to /etc/vfstab.new, with any remapped device
 * names substituted.
 *
 * Returns:
 *	0	successful operation
 *	-1	failed
 */
static int
update_vfstab()
{
	FILE *fdin, *fdout;
	char *buf, *tmpbuf;
	char fname[MAXPATHLEN];
	int rv = -1, rval = -1;
	char cdev[MAXPATHLEN];
	char bdev[MAXPATHLEN];
	char mntpt[MAXPATHLEN];
	char fstype[512];
	char fsckpass[512];
	char mntboot[512];
	char mntopt[MAXPATHLEN];
	char fmt[80];
	char *prefixt = NULL;
	char *curdev = NULL;
	char *thisdevid = NULL;
	char *slice = NULL;
	nvlist_t *thisdev;
	boolean_t devmpx = B_FALSE;

	buf = calloc(1, MAXPATHLEN);
	tmpbuf = calloc(1, MAXPATHLEN);
	if (buf == NULL || tmpbuf == NULL)
		return (-1);

	(void) snprintf(fname, MAXPATHLEN, "/etc/mpxio/vfstab.new");

	fdin = fopen("/etc/vfstab", "r");
	fdout = fopen(fname, "w+");
	if (fdin == NULL || fdout == NULL) {
		logmsg(MSG_INFO, "Unable to open vfstab or create a backup "
		    "vfstab %s\n");
		return (-1);
	}

	(void) snprintf(fmt, sizeof (fmt),
	    "%%%ds %%%ds %%%ds %%%ds %%%ds %%%ds %%%ds", sizeof (bdev) - 1,
	    sizeof (cdev) - 1, sizeof (mntpt) - 1, sizeof (fstype) - 1,
	    sizeof (fsckpass) - 1, sizeof (mntboot) - 1, sizeof (mntopt) - 1);

	while (fgets(buf, MAXPATHLEN, fdin) != NULL) {
		if (strlen(buf) == (MAXPATHLEN - 1) &&
		    buf[MAXPATHLEN-2] != '\n') {
			logmsg(MSG_ERROR,
			    gettext("/etc/vfstab line length too long, "
			    "exceeded %2$d: \"%3$s\"\n"),
			    MAXPATHLEN - 2, buf);
			goto out;
		}

		prefixt = NULL;
		curdev = NULL;
		slice = NULL;
		thisdevid = NULL;
		thisdev = NULL;

		/* LINTED - variable format specifier */
		rv = sscanf(buf, fmt, bdev, cdev, mntpt, fstype, fsckpass,
		    mntboot, mntopt);

		/*
		 * Walk through the lines in the input file (/etc/vfstab),
		 * skipping anything which is _not_ a COGD (common or garden
		 * disk), ie all the /devices, /system, /dev/md, /dev/vx and
		 * /dev/zvol and so forth.
		 */
		if ((rv == 7) && (bdev[0] == '/') &&
		    (strstr(bdev, "/dev/dsk"))) {
			slice = strrchr(bdev, 's');
			/* take a copy, strip off /dev/dsk/ */
			prefixt = strrchr(bdev, 'c');
			prefixt[strlen(bdev) - 9 - strlen(slice)] = '\0';
			slice++; /* advance past the s */
			rval = nvlist_lookup_string(mapnvl, prefixt,
			    &thisdevid);
			if (rval) {
				/* Whoa, where did this device go?! */
				logmsg(MSG_INFO,
				    "error looking up device %s\n", prefixt);
				/* Comment-out this line in the new version */
				(void) snprintf(tmpbuf, MAXPATHLEN,
				    "# DEVICE NOT FOUND %s", buf);
				(void) fprintf(fdout, "%s", tmpbuf);
				continue;
			} else {
				/* The device exists in our mapnvl */
				(void) nvlist_lookup_nvlist(mapnvl, thisdevid,
				    &thisdev);
				(void) nvlist_lookup_boolean_value(thisdev,
				    NVL_MPXEN, &devmpx);
				(void) nvlist_lookup_string(thisdev,
				    ((devmpx == B_TRUE)
				    ? NVL_MPXPATH : NVL_PATH),
				    &curdev);
			}
		}

		if ((prefixt != NULL) && (curdev != NULL) &&
		    (rv = (strncmp(prefixt, curdev, strlen(prefixt)) != 0))) {
			/* Mapping change for this device */
			if (strcmp(fstype, "swap") == 0) {
				(void) snprintf(tmpbuf, MAXPATHLEN,
				    "/dev/dsk/%ss%s\t-\t-\tswap\t"
				    "%s\t%s\t%s\n",
				    curdev, slice, fsckpass, mntboot, mntopt);
			} else {
				(void) snprintf(tmpbuf, MAXPATHLEN,
				    "/dev/dsk/%ss%s\t/dev/rdsk/%ss%s\t"
				    "%s\t%s\t%s\t%s\t%s\n",
				    curdev, slice, curdev, slice,
				    mntpt, fstype, fsckpass, mntboot, mntopt);
			}
			errno = 0;
			(void) fprintf(fdout, "%s", tmpbuf);
		} else {
			(void) fprintf(fdout, "%s", buf);
		}

		errno = 0;
		if (fflush(fdout) != 0) {
			logmsg(MSG_ERROR,
			    gettext("fprintf failed to write to %s: %s (%d)\n"),
			    fname, strerror(errno), errno);
			goto out;
		}
	}
out:
	(void) fclose(fdin);
	(void) fclose(fdout);
	free(buf);
	free(tmpbuf);
	return (errno);
}
