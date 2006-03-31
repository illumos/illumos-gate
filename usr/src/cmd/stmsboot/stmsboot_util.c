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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <dirent.h>
#include <sys/param.h>
#include <sys/scsi/adapters/scsi_vhci.h>
#include <libdevinfo.h>
#include <libgen.h>
#include <dlfcn.h>
#include <link.h>
#include <locale.h>
#include <libintl.h>
#include <sys/syscall.h>
#include <sys/vfstab.h>
#include <sys/mount.h>
#include <devid.h>
#include <sys/libdevid.h>

#define	VHCI_CTL_NODE	"/devices/scsi_vhci:devctl"
#define	SLASH_DEVICES	"/devices/"
#define	SLASH_SSD_AT	"/ssd@"
#define	SLASH_FP_AT	"/fp@"
#define	SLASH_SCSI_VHCI	"/scsi_vhci"
#define	DEV_DSK		"/dev/dsk/"
#define	DEV_RDSK	"/dev/rdsk/"
#define	SYS_FILENAME_LEN	256

/*
 * Save directory is the directory in which system files are saved.
 * Save directory must be under the root filesystem, as this program is
 * typically run before any other filesystems are mounted.
 */
#define	SAVE_DIR	"/etc/mpxio"

/* fcp driver publishes this property */
#define	NODE_WWN_PROP	"node-wwn"

typedef enum {
	CLIENT_TYPE_UNKNOWN,
	CLIENT_TYPE_PHCI,
	CLIENT_TYPE_VHCI
} client_type_t;

struct devlink_cbarg {
	char *devlink;
	size_t len;
};

static di_node_t devinfo_root = DI_NODE_NIL;
static di_devlink_handle_t devlink_hdl = NULL;
static int vhci_fd = -1;
static int patch_vfstab, cap_m_option, debug;
static int list_option, list_guid_mappings, list_controllernum = -1;
static char *mapdev = "";
static char *stmsboot = "stmsboot";

static int make_temp(char *, char *, char *, size_t);
static void commit_change(char *, char *, char *, int);
static int map_devname(char *, char *, size_t, int);
static int update_vfstab(char *, char *);
static int list_mappings(int, int);
static int canopen(char *);
static void logerr(char *, ...);
static void logdmsg(char *, ...);
static void *s_malloc(const size_t);
static char *s_strdup(const char *);
static void s_strlcpy(char *, const char *, size_t);
/*
 * Using an exit function not marked __NORETURN causes a warning with gcc.
 * To suppress the warning, use __NORETURN attribute.
 */
static void clean_exit(int)__NORETURN;

/*
 * Print usage and exit.
 */
static void
usage(char *argv0)
{
	char *progname;

	progname = strrchr(argv0, '/');
	if (progname != NULL)
		progname++;
	else
		progname = argv0;

	/*
	 * -u	update /etc/vfstab
	 * -m devname
	 *	if devname is phci based name and not open-able, map it to
	 *	vhci based /devices name.
	 *	if devname is vhci based name and not open-able, map it to
	 *	phci based /devices name.
	 * -M devname
	 *	same as -m except that /dev link is printed instead of
	 *	/devices name.
	 * -l controller
	 *	list non-STMS to STMS device name mappings for the specific
	 *	controller
	 * -L	list non-STMS to STMS device name mappings for all controllers
	 */
	(void) fprintf(stderr, gettext("usage: %s -u | -m devname | "
	    "-M devname | -l controller | -L\n"), progname);
	exit(2);
}

/*
 * Parse command line arguments.
 */
static void
parse_args(int argc, char *argv[])
{
	char opt;
	int n = 0;

	if (argc == 1) {
		usage(argv[0]);
		/*NOTREACHED*/
	}

	while ((opt = getopt(argc, argv, "udm:M:Ll:g")) != EOF) {
		switch (opt) {
		case 'u':
			patch_vfstab = 1;
			n++;
			break;

		case 'd':
			debug = 1;
			break;

		case 'm':
			mapdev = s_strdup(optarg);
			n++;
			break;

		case 'M':
			mapdev = s_strdup(optarg);
			cap_m_option = 1;
			n++;
			break;

		case 'L':
			list_option = 1;
			n++;
			break;

		case 'l':
			list_option = 1;
			list_controllernum = (int)atol(optarg);
			if (list_controllernum < 0) {
				logerr(gettext("controller number %d is "
				    "invalid\n"), list_controllernum);
				clean_exit(1);
			}
			n++;
			break;

		case 'g':
			/*
			 * private option to display non-STMS device name
			 * to GUID mappings.
			 */
			list_guid_mappings = 1;
			n++;
			break;

		default:
			usage(argv[0]);
			/*NOTREACHED*/
		}
	}

	if (n != 1)
		usage(argv[0]);
		/*NOTREACHED*/
}

int
main(int argc, char *argv[])
{
	char save_vfstab[SYS_FILENAME_LEN], tmp_vfstab[SYS_FILENAME_LEN];
	int vfstab_updated;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (getuid() != 0) {
		logerr(gettext("must be super-user to run this program\n"));
		clean_exit(1);
	}

	parse_args(argc, argv);
	(void) umask(022);

	/*
	 * NOTE: The mpxio boot-up script executes this program with the
	 * mapping (-m) option before the /usr is even mounted and when the
	 * root filesystem is still mounted read-only.
	 */
	if (*mapdev != '\0') {
		char newname[MAXPATHLEN];

		if (map_devname(mapdev, newname, sizeof (newname),
		    cap_m_option) == 0) {
			(void) printf("%s\n", newname);
			clean_exit(0);
		}
		clean_exit(1);
	}

	if (list_option || list_guid_mappings) {
		if (list_mappings(list_controllernum, list_guid_mappings) == 0)
			clean_exit(0);
		clean_exit(1);
	}

	/* create a directory where a copy of the system files are saved */
	if (patch_vfstab) {
		if (mkdirp(SAVE_DIR, 0755) != 0 && errno != EEXIST) {
			logerr(gettext("mkdirp: failed to create %1$s: %2$s\n"),
			    SAVE_DIR, strerror(errno));
			clean_exit(1);
		}

		if (make_temp(VFSTAB, save_vfstab, tmp_vfstab,
		    SYS_FILENAME_LEN) != 0)
			clean_exit(1);

		/* build new vfstab without modifying the existing one */
		if ((vfstab_updated = update_vfstab(VFSTAB, tmp_vfstab))
		    == -1) {
			logerr(gettext("failed to update %s\n"), VFSTAB);
			clean_exit(1);
		}

		commit_change(VFSTAB, save_vfstab, tmp_vfstab, vfstab_updated);
	}

	clean_exit(0);
}

/*
 * Make saved and temporary filenames in SAVE_DIR.
 *
 * ex: if the filename is /etc/vfstab then the save_filename and tmp_filename
 * would be SAVE_DIR/vfstab and SAVE_DIR/vfstab.tmp respectively.
 *
 * Returns 0 on success, -1 on failure.
 */
static int
make_temp(char *filename, char *save_filename, char *tmp_filename, size_t len)
{
	char *ptr;

	if ((ptr = strrchr(filename, '/')) == NULL) {
		logdmsg("invalid file %s\n", filename);
		return (-1);
	}
	(void) snprintf(save_filename, len, "%s%s", SAVE_DIR, ptr);
	(void) snprintf(tmp_filename, len, "%s%s.tmp", SAVE_DIR, ptr);
	logdmsg("make_temp: %s: save = %s, temp = %s\n", filename,
	    save_filename, tmp_filename);
	return (0);
}

/*
 * Commit the changes made to the system file
 */
static void
commit_change(char *filename, char *save_filename, char *tmp_filename,
    int updated)
{
	int x;

	if (updated) {
		/* save the original */
		if ((x = rename(filename, save_filename)) != 0) {
			logerr(gettext("rename %1$s to %2$s failed: %3$s\n"),
			    filename, save_filename, strerror(errno));
		}

		/* now rename the new file to the actual file */
		if (rename(tmp_filename, filename) != 0) {
			logerr(gettext("rename %1$s to %2$s failed: %3$s\n"),
			    tmp_filename, filename, strerror(errno));

			/* restore the original */
			if (x == 0 && rename(save_filename, filename) != 0) {
				logerr(
				    gettext("rename %1$s to %2$s failed: %3$s\n"
				    "%4$s is a copy of the original %5$s file"
				    "\n"),
				    save_filename, filename, strerror(errno),
				    save_filename, filename);
			}
		} else
			(void) printf(gettext("%1$s: %2$s has been updated.\n"),
			    stmsboot, filename);
	} else {
		/* remove the temp file */
		(void) unlink(tmp_filename);
		(void) printf(gettext("%1$s: %2$s was not modified as no "
		    "changes were needed.\n"), stmsboot, filename);
	}
}

/*
 * Get the GUID of the device.
 *
 * physpath	/devices name without the /devices prefix and minor name
 *		component.
 * guid		caller supplied buffer where the GUID will be placed on return
 * guid_len	length of the caller supplied guid buffer.
 * no_dealy_flag if set open the device with O_NDELAY
 * node		di_node corresponding to physpath if already available,
 *		otherwise pass DI_NODE_NIL.
 *
 * Returns 0 on success, -1 on failure.
 */
static int
get_guid(char *physpath, char *guid, int guid_len, int no_delay_flag,
	di_node_t node)
{
	int		fd;
	ddi_devid_t	devid;
	int		rv	= -1;
	char		*i_guid	= NULL;
	char		physpath_raw[MAXPATHLEN];
	uchar_t		*wwnp;
	int		i, n, snapshot_taken = 0;

	logdmsg("get_guid: physpath = %s\n", physpath);

	(void) snprintf(physpath_raw, MAXPATHLEN,
	    "/devices%s:a,raw", physpath);

	*guid = '\0';

	if (no_delay_flag)
		no_delay_flag = O_NDELAY;

	/*
	 * Open the raw device
	 * Without the O_DELAY flag, the open will fail on standby paths of
	 * T3 if its mp_support mode is "mpxio".
	 */
	if ((fd = open(physpath_raw, O_RDONLY | no_delay_flag)) == -1) {
		logdmsg("get_guid: failed to open %s: %s\n", physpath_raw,
		    strerror(errno));
		return (-1);
	}

	if (devid_get(fd, &devid) == 0) {
		i_guid = devid_to_guid(devid);
		devid_free(devid);

		if (i_guid != NULL) {
			s_strlcpy(guid, i_guid, guid_len);
			devid_free_guid(i_guid);
			rv = 0;
			goto out;
		} else
			logdmsg("get_guid: devid_to_guid() failed\n");
	} else
		logdmsg("get_guid: devid_get() failed: %s\n", strerror(errno));

	/* fallback to node name as the guid as this is what fcp driver does */
	if (node == DI_NODE_NIL) {
		if ((node = di_init(physpath, DINFOCPYALL | DINFOFORCE))
		    == DI_NODE_NIL) {
			logdmsg("get_guid: di_init on %s failed: %s\n",
			    physpath, strerror(errno));
			goto out;
		}
		snapshot_taken = 1;
	}

	if ((n = di_prop_lookup_bytes(DDI_DEV_T_ANY, node, NODE_WWN_PROP,
	    &wwnp)) == -1) {
		logdmsg("get_guid: di_prop_lookup_bytes() failed to lookup "
		    "%s: %s\n", NODE_WWN_PROP, strerror(errno));
		goto out;
	}

	if (guid_len >= ((n * 2) + 1)) {
		for (i = 0; i < n; i++) {
			(void) sprintf(guid + (i * 2), "%02x", (uint_t)(*wwnp));
			wwnp++;
		}
		rv = 0;
	} else
		logerr(gettext("insufficient buffer size: need %1$d "
		    "bytes, passed %2$d bytes\n"), (n * 2) + 1, guid_len);

out:
	if (snapshot_taken)
		di_fini(node);

	(void) close(fd);
	logdmsg("get_guid: GUID = %s\n", guid);
	return (rv);
}

/*
 * Given client_name return whether it is a phci or vhci based name.
 * client_name is /devices name of a client without the /devices prefix.
 *
 * client_name			Return value
 * .../fp@xxx/ssd@yyy		CLIENT_TYPE_PHCI
 * .../scsi_vhci/ssd@yyy	CLIENT_TYPE_VHCI
 * other			CLIENT_TYPE_UNKNOWN
 */
static client_type_t
client_name_type(char *client_name)
{
	client_type_t client_type = CLIENT_TYPE_UNKNOWN;
	char *p1, *p2;

	if (*client_name != '/')
		return (CLIENT_TYPE_UNKNOWN);

	/* we only care for ssd devices */
	if ((p1 = strrchr(client_name, '/')) == NULL ||
	    strncmp(p1, SLASH_SSD_AT, sizeof (SLASH_SSD_AT) - 1) != 0)
		return (CLIENT_TYPE_UNKNOWN);

	*p1 = '\0';

	if ((p2 = strrchr(client_name, '/')) != NULL) {
		if (strncmp(p2, SLASH_FP_AT, sizeof (SLASH_FP_AT) - 1) == 0)
			client_type = CLIENT_TYPE_PHCI;
		else if (strncmp(p2, SLASH_SCSI_VHCI,
		    sizeof (SLASH_SCSI_VHCI) - 1) == 0)
			client_type = CLIENT_TYPE_VHCI;
	}

	*p1 = '/';
	return (client_type);
}

/*
 * Map phci based client name to vhci based client name.
 *
 * phci_name
 *	phci based client /devices name without the /devices prefix and
 *	minor name component.
 *	ex: /pci@8,600000/SUNW,qlc@4/fp@0,0/ssd@w2100002037cd9f72,0
 *
 * vhci_name
 *	Caller supplied buffer where vhci /devices name will be placed on
 *	return (without the /devices prefix and minor name component).
 *	ex: /scsi_vhci/ssd@g2000002037cd9f72
 *
 * vhci_name_len
 *	Length of the caller supplied vhci_name buffer.
 *
 * Returns 0 on success, -1 on failure.
 */
static int
phci_to_vhci(char *phci_name, char *vhci_name, size_t vhci_name_len)
{
	sv_iocdata_t ioc;
	char *slash;
	char vhci_name_buf[MAXPATHLEN];
	char phci_name_buf[MAXPATHLEN];
	char addr_buf[MAXNAMELEN];

	logdmsg("phci_to_vhci: client = %s\n", phci_name);

	s_strlcpy(phci_name_buf, phci_name, MAXPATHLEN);

	if (client_name_type(phci_name_buf) != CLIENT_TYPE_PHCI ||
	    (slash = strrchr(phci_name_buf, '/')) == NULL ||
	    strncmp(slash, SLASH_SSD_AT, sizeof (SLASH_SSD_AT) - 1) != 0) {
		logdmsg("phci_to_vhci: %s is not of CLIENT_TYPE_PHCI\n",
		    phci_name);
		return (-1);
	}

	if (vhci_fd < 0) {
		if ((vhci_fd = open(VHCI_CTL_NODE, O_RDWR)) < 0)
			return (-1);
	}

	*slash = '\0';
	s_strlcpy(addr_buf, slash + sizeof (SLASH_SSD_AT) - 1, MAXNAMELEN);

	bzero(&ioc, sizeof (sv_iocdata_t));
	ioc.client = vhci_name_buf;
	ioc.phci = phci_name_buf;
	ioc.addr = addr_buf;

	if (ioctl(vhci_fd, SCSI_VHCI_GET_CLIENT_NAME, &ioc) != 0) {
		logdmsg("SCSI_VHCI_GET_CLIENT_NAME on %s "
		    "failed: %s\n", phci_name, strerror(errno));
		return (-1);
	}

	s_strlcpy(vhci_name, vhci_name_buf, vhci_name_len);
	logdmsg("phci_to_vhci: %s maps to %s\n", phci_name, vhci_name);
	return (0);
}

/*
 * Map vhci based client name to phci based client name.
 * If the client has multiple paths, only one of the paths with which client
 * can be accessed is returned. This function does not use SCSI_VHCI ioctls
 * as it is called on mpxio disabled paths.
 *
 * vhci_name
 *	vhci based client /devices name without the /devices prefix and
 *	minor name component.
 *	ex: /scsi_vhci/ssd@g2000002037cd9f72
 *
 * phci_name
 *	Caller supplied buffer where phci /devices name will be placed on
 *	return (without the /devices prefix and minor name component).
 *	ex: /pci@8,600000/SUNW,qlc@4/fp@0,0/ssd@w2100002037cd9f72,0
 *
 * phci_name_len
 *	Length of the caller supplied phci_name buffer.
 *
 * Returns 0 on success, -1 on failure.
 */
static int
vhci_to_phci(char *vhci_name, char *phci_name, size_t phci_name_len)
{
	di_node_t node, parent;
	char *vhci_guid, *devfspath;
	char phci_guid[MAXPATHLEN];
	char *parent_name, *node_name;

	logdmsg("vhci_to_phci: client = %s\n", vhci_name);

	if (client_name_type(vhci_name) != CLIENT_TYPE_VHCI) {
		logdmsg("vhci_to_phci: %s is not of CLIENT_TYPE_VHCI\n",
		    vhci_name);
		return (-1);
	}

	if ((vhci_guid = strrchr(vhci_name, '@')) == NULL ||
	    *(++vhci_guid) != 'g') {
		logerr(gettext("couldn't get guid from %s\n"), vhci_name);
		return (-1);
	}

	/* point to guid */
	++vhci_guid;

	/*
	 * Get devinfo snapshot and walk all ssd nodes whose parent is fp.
	 * For each node get the guid and match it with vhci_guid.
	 */
	if (devinfo_root == DI_NODE_NIL) {
		logdmsg("vhci_to_phci: taking devinfo snapshot\n");
		if ((devinfo_root = di_init("/", DINFOCPYALL | DINFOFORCE))
		    == DI_NODE_NIL) {
			logerr(gettext("di_init failed: %s\n"),
			    strerror(errno));
			return (-1);
		}
		logdmsg("vhci_to_phci: done taking devinfo snapshot\n");
	}

	for (node = di_drv_first_node("ssd", devinfo_root);
	    node != DI_NODE_NIL; node = di_drv_next_node(node)) {
		if ((node_name = di_node_name(node)) == NULL ||
		    strcmp(node_name, "ssd") != 0 ||
		    (parent = di_parent_node(node)) == DI_NODE_NIL ||
		    (parent_name = di_node_name(parent)) == NULL ||
		    strcmp(parent_name, "fp") != 0 ||
		    (devfspath = di_devfs_path(node)) == NULL)
			continue;

		/*
		 * Don't set no_delay_flag to have get_guid() fail on
		 * standby paths of T3. So we'll find the preferred paths.
		 */
		if (get_guid(devfspath, phci_guid,
		    sizeof (phci_guid), 0, node) == 0 &&
		    strcmp(phci_guid, vhci_guid) == 0) {
			s_strlcpy(phci_name, devfspath, phci_name_len);
			di_devfs_path_free(devfspath);
			logdmsg("vhci_to_phci: %s maps to %s\n", vhci_name,
			    phci_name);
			return (0);
		}

		di_devfs_path_free(devfspath);
	}

	logdmsg("vhci_to_phci: couldn't get phci name for %s\n", vhci_name);
	return (-1);
}

/*
 * Map physname from phci name space to vhci name space or vice-versa
 *
 * physname
 *	phci or vhci based client /devices name without the /devices prefix and
 *	minor name component.
 *
 * new_physname
 *	Caller supplied buffer where the mapped physical name is stored on
 *	return (without the /devices prefix and minor name component).
 *
 * len
 *	Length of the caller supplied new_physname buffer.
 *
 * Returns 0 on success, -1 on failure.
 */
static int
map_physname(char *physname, char *new_physname, size_t len)
{
	int type;
	int rv;

	if ((type = client_name_type(physname)) == CLIENT_TYPE_VHCI)
		rv = vhci_to_phci(physname, new_physname, len);
	else if (type == CLIENT_TYPE_PHCI)
		rv = phci_to_vhci(physname, new_physname, len);
	else
		rv = -1;

	return (rv);
}

/*
 * Given a phci or vhci devname which is either a /dev link or /devices name
 * get the corresponding physical node path (without the /devices prefix)
 * and minor name.
 *
 * Returns 0 on success, -1 on failure.
 */
static int
get_physname_minor(char *devname, char *physname, int physname_len,
    char *minorname, int minorname_len)
{
	int linksize;
	char buf[MAXPATHLEN];
	char *p, *m;

	if (strncmp(devname, DEV_DSK, sizeof (DEV_DSK) - 1) == 0 ||
	    strncmp(devname, DEV_RDSK, sizeof (DEV_RDSK) - 1) == 0) {
		if ((linksize = readlink(devname, buf, MAXPATHLEN))
		    > 0 && linksize <= (MAXPATHLEN - 1)) {
			buf[linksize] = '\0';
		} else
			return (-1);
	} else
		s_strlcpy(buf, devname, MAXPATHLEN);

	if ((p = strstr(buf, SLASH_DEVICES)) == NULL)
		return (-1);

	/* point to '/' after /devices */
	p += sizeof (SLASH_DEVICES) - 2;

	if ((m = strrchr(p, ':')) == NULL) {
		logdmsg("get_physname_minor: no minor name component in %s\n",
		    buf);
		return (-1);
	}

	*m = '\0';
	m++;

	if (client_name_type(p) == CLIENT_TYPE_UNKNOWN)
		return (-1);

	s_strlcpy(physname, p, physname_len);
	s_strlcpy(minorname, m, minorname_len);
	logdmsg("get_physname_minor: %s: physname = %s, minor = %s\n",
	    devname, physname, minorname);
	return (0);
}

static int
devlink_callback(di_devlink_t devlink, void *argptr)
{
	const char *link;
	struct devlink_cbarg *argp = argptr;

	if ((link = di_devlink_path(devlink)) != NULL) {
		s_strlcpy(argp->devlink, link, argp->len);
		return (DI_WALK_TERMINATE);
	}

	return (DI_WALK_CONTINUE);
}

/*
 * Lookup the /dev link corresponding to physname and minorname.
 *
 * physname	client /devices path without the /devices prefix and minor
 *		name component.
 * minorname	client minor name.
 * devlink	caller supplied buffer where the /dev link is placed on return.
 * len		caller supplied devlink buffer length
 *
 * Returns 0 on success, -1 on failure.
 */
static int
lookup_devlink(char *physname, char *minorname, char *devlink, size_t len)
{
	char buf[MAXPATHLEN];
	struct devlink_cbarg arg;

	if (devlink_hdl == NULL) {
		logdmsg("lookup_devlink: taking devlink snapshot\n");
		if ((devlink_hdl = di_devlink_init(NULL, 0)) == NULL) {
			logerr(gettext("di_devlink_init failed: %s\n"),
			    strerror(errno));
			clean_exit(1);
		}
	}

	*devlink = '\0';
	(void) snprintf(buf, MAXPATHLEN, "%s:%s", physname, minorname);
	arg.devlink = devlink;
	arg.len = len;
	if (di_devlink_walk(devlink_hdl, NULL, buf, DI_PRIMARY_LINK, &arg,
	    devlink_callback) != 0) {
		logdmsg("lookup_devlink: di_devlink_walk on %s failed: %s\n",
		    buf, strerror(errno));
		return (-1);
	}

	if (*devlink == '\0') {
		logdmsg("lookup_devlink: failed to lookup devlink for %s\n",
		    buf);
		return (-1);
	}

	logdmsg("lookup_devlink: /dev link for %s:%s = %s\n", physname,
	    minorname, devlink);
	return (0);
}

/*
 * open infile for reading and return its file pointer in *fp_in.
 * open outfile for writing and return its file pointer in *fp_out.
 *
 * Returns 0 on success, -1 on failure.
 */
static int
open_in_out_files(char *infile, char *outfile, FILE **fp_in, FILE **fp_out)
{
	FILE *fin = NULL;
	FILE *fout = NULL;
	struct stat sbuf;

	if ((fin = fopen(infile, "r")) == NULL) {
		logerr(gettext("failed to fopen %1$s: %2$s\n"),
		    infile, strerror(errno));
		goto out;
	}

	if (fstat(fileno(fin), &sbuf) != 0) {
		logerr(gettext("fstat failed on %1$s: %2$s\n"),
		    infile, strerror(errno));
		goto out;
	}

	if ((fout = fopen(outfile, "w")) == NULL) {
		logerr(gettext("failed to fopen %1$s: %2$s\n"),
		    outfile, strerror(errno));
		goto out;
	}

	if (fchmod(fileno(fout), (sbuf.st_mode & 0777)) != 0) {
		logerr(gettext("failed to fchmod %1$s to 0%2$o: %3$s\n"),
		    outfile, sbuf.st_mode & 0777, strerror(errno));
		goto out;
	}

	if (fchown(fileno(fout), sbuf.st_uid, sbuf.st_gid) != 0) {
		logerr(gettext("failed to fchown %1$s to uid %2$d and "
		    "gid %3$d: %4$s\n"),
		    outfile, sbuf.st_uid, sbuf.st_gid, strerror(errno));
		goto out;
	}

	*fp_in = fin;
	*fp_out = fout;
	return (0);

out:
	if (fin != NULL)
		(void) fclose(fin);
	if (fout != NULL)
		(void) fclose(fout);
	return (-1);
}

/*
 * If the devname is a phci based name and not open-able, map it to vhci
 * based name. If the devname is a vhci based name and not open-able, map it
 * to phci based name.
 *
 * devname	either a /dev link or /devices name to client device
 * new_devname	caller supplied buffer where the mapped device name is
 *		placed on return.
 * len		caller supplied new_devname buffer length
 * devlink_flag	pass 1 if requesting the /dev link to the mapped device.
 *		pass 0 if requesting the /devices name of the mapped device.
 *
 * Returns 0 on success, -1 on failure.
 */
static int
map_devname(char *devname, char *new_devname, size_t len, int devlink_flag)
{
	char physname[MAXPATHLEN];
	char minor[MAXNAMELEN];
	char new_physname[MAXNAMELEN];

	if (get_physname_minor(devname, physname, sizeof (physname),
	    minor, sizeof (minor)) == 0 &&
	    canopen(devname) == 0 &&
	    map_physname(physname, new_physname, sizeof (new_physname)) == 0) {

		if (devlink_flag) {
			if (lookup_devlink(new_physname, minor, new_devname,
			    len) == 0)
				return (0);
		} else {
			(void) snprintf(new_devname, len, "/devices%s:%s",
			    new_physname, minor);
			return (0);
		}
	}

	return (-1);
}

/*
 * Make a new /etc/vfstab:
 * Read vfstab_in, convert the device name entries to appropriate vhci or phci
 * based names, and write to vfstab_out. Only device names whose physical
 * paths are either phci or vhci based names and not open-able are considered
 * for conversion. Open-able device name entries are not converted as it
 * means that the device is already accessible; hence no need to convert.
 *
 * Returns:
 * 	0	successful but vfstab_out contents are the same as vfstab_in
 *	1	successful and vfstab_out changed from vfstab_in
 *	-1	failed
 */
static int
update_vfstab(char *vfstab_in, char *vfstab_out)
{
	FILE *fp_in, *fp_out;
	char *buf, *tmpbuf;
	char *vfs_cache[2];
	int idx = 0, count = 0;
	int rv = -1;
	int vfstab_updated = 0;
	int i;
	char cdev[MAXPATHLEN];
	char bdev[MAXPATHLEN];
	char mntpt[MAXPATHLEN];
	char fstype[512];
	char fsckpass[512];
	char mntboot[512];
	char mntopt[MAX_MNTOPT_STR];
	char phys_bdev[MAXPATHLEN], phys_cdev[MAXPATHLEN];
	char bdev_minor[MAXNAMELEN], cdev_minor[MAXNAMELEN];
	char new_physname[MAXPATHLEN];
	char new_bdevlink[MAXPATHLEN], new_cdevlink[MAXPATHLEN];
	char fmt[80];

	if (open_in_out_files(vfstab_in, vfstab_out, &fp_in, &fp_out) != 0)
		return (-1);

	/*
	 * Read one line at time from vfstab_in. If no conversion is needed
	 * for the line simply write the line to vfstab_out. If conversion is
	 * needed, first write the existing line as a comment to vfstab_out
	 * and then write the converted line.
	 *
	 * To avoid commented entries piling up in vfstab in case if the
	 * user runs stmsboot multiple times to switch on and off from mpxio,
	 * add the commented line only if not already there. To do this
	 * cache the last two vfstab lines processed and add the commented
	 * entry only if it is not found in the cache. We only need to cache
	 * the last two lines because a device can have at most two names -
	 * one mpxio and one non-mpxio name. Therefore for any device name
	 * entry we at most add two comments - one with mpxio name and one
	 * with non-mpxio name - no matter how many times stmsboot is run.
	 */
	buf = (char *)s_malloc(VFS_LINE_MAX);
	tmpbuf = (char *)s_malloc(VFS_LINE_MAX);
	vfs_cache[0] = (char *)s_malloc(VFS_LINE_MAX);
	vfs_cache[1] = (char *)s_malloc(VFS_LINE_MAX);

	(void) snprintf(fmt, sizeof (fmt),
	    "%%%ds %%%ds %%%ds %%%ds %%%ds %%%ds %%%ds", sizeof (bdev) - 1,
	    sizeof (cdev) - 1, sizeof (mntpt) - 1, sizeof (fstype) - 1,
	    sizeof (fsckpass) - 1, sizeof (mntboot) - 1, sizeof (mntopt) - 1);

	while (fgets(buf, VFS_LINE_MAX, fp_in) != NULL) {
		if (strlen(buf) == (VFS_LINE_MAX - 1) &&
		    buf[VFS_LINE_MAX-2] != '\n') {
			logerr(gettext("%1$s line size too long, "
			    "exceeded %2$d: \"%3$s\"\n"),
			    VFSTAB, VFS_LINE_MAX - 2, buf);
			goto out;
		}

		/* LINTED - format specifier */
		if ((sscanf(buf, fmt, bdev, cdev, mntpt,
		    fstype, fsckpass, mntboot, mntopt) != 7) ||
		    (bdev[0] == '#') ||
		    (get_physname_minor(bdev, phys_bdev, sizeof (phys_bdev),
		    bdev_minor, sizeof (bdev_minor)) != 0) ||

		    (strcmp(fstype, "swap") != 0 &&
		    ((get_physname_minor(cdev, phys_cdev, sizeof (phys_cdev),
		    cdev_minor, sizeof (cdev_minor)) != 0) ||
		    (strcmp(phys_bdev, phys_cdev) != 0))) ||

		    canopen(bdev) ||
		    (map_physname(phys_bdev, new_physname,
		    sizeof (new_physname)) != 0) ||
		    (lookup_devlink(new_physname, bdev_minor, new_bdevlink,
		    sizeof (new_bdevlink)) != 0) ||

		    (strcmp(fstype, "swap") != 0 &&
		    (lookup_devlink(new_physname, cdev_minor, new_cdevlink,
		    sizeof (new_cdevlink)) != 0))) {

			/* cache the last two entries */
			(void) strlcpy(vfs_cache[idx], buf, VFS_LINE_MAX);
			idx = (idx == 0) ? 1 : 0;
			if (count < 2)
				count++;

			if (fputs(buf, fp_out) == EOF) {
				logerr(gettext("fputs \"%1$s\" to %2$s "
				    "failed: %3$s\n"),
				    buf, vfstab_out, strerror(errno));
				goto out;
			}

		} else {
			/*
			 * comment the entry in vfstab only if it is not
			 * already in the cache.
			 */
			if (client_name_type(phys_bdev) == CLIENT_TYPE_VHCI)
				(void) snprintf(tmpbuf, VFS_LINE_MAX,
				    "# mpxio: %s", buf);
			else
				(void) snprintf(tmpbuf, VFS_LINE_MAX,
				    "# non-mpxio: %s", buf);

			for (i = 0; i < count; i++) {
				if (strcmp(vfs_cache[i], tmpbuf) == 0)
					break;
			}

			if (i == count) {
				if (fputs(tmpbuf, fp_out) == EOF) {
					logerr(gettext("fputs \"%1$s\" to %2$s "
					    "failed: %3$s\n"), tmpbuf,
					    vfstab_out, strerror(errno));
					goto out;
				}
			}

			count = 0;
			idx = 0;

			if (fprintf(fp_out, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			    new_bdevlink,
			    (strcmp(fstype, "swap") != 0) ? new_cdevlink : cdev,
			    mntpt, fstype, fsckpass, mntboot, mntopt) < 0) {
				logerr(gettext("fprintf failed to write to "
				    "%1$s: %2$s\n"),
				    vfstab_out, strerror(errno));
				goto out;
			}
			vfstab_updated = 1;
		}
	}

	rv = vfstab_updated;
out:
	(void) fclose(fp_in);
	(void) fclose(fp_out);
	free(buf);
	free(tmpbuf);
	free(vfs_cache[0]);
	free(vfs_cache[1]);
	return (rv);
}

/*
 * if guidmap is 0, list non-STMS to STMS device name mappings for the
 * specified controller.
 * if guidmap is 1, list non-STMS to GUID mappings for the specified controller.
 * If controller is -1 list mappings for all controllers.
 *
 * Returns 0 on success, -1 on failure.
 */
static int
list_mappings(int controller, int guidmap)
{
	int cnum, len, mapped;
	int header = 1;
	char *p1, *p2;
	DIR *dirp;
	struct dirent *direntry;
	char devname[MAXPATHLEN];
	char physname[MAXPATHLEN];
	char new_devname[MAXPATHLEN];
	char new_physname[MAXPATHLEN];
	char guid[MAXPATHLEN];
	char minor[MAXNAMELEN];

	if ((dirp = opendir("/dev/rdsk")) == NULL)
		return (-1);

	while ((direntry = readdir(dirp)) != NULL) {
		if (strcmp(direntry->d_name, ".") == 0 ||
		    strcmp(direntry->d_name, "..") == 0 ||
		    (len = strlen(direntry->d_name)) < 2 ||
		    strcmp(direntry->d_name + len - 2, "s0") != 0 ||
		    sscanf(direntry->d_name, "c%dt", &cnum) != 1 ||
		    (controller != -1 && controller != cnum))
			continue;

		(void) snprintf(devname, MAXPATHLEN, "/dev/rdsk/%s",
		    direntry->d_name);

		if (get_physname_minor(devname, physname, sizeof (physname),
		    minor, sizeof (minor)) != 0 ||
		    client_name_type(physname) != CLIENT_TYPE_PHCI)
			continue;

		/*
		 * First try phci_to_vhci() mapping. It will work if the
		 * device is under MPxIO control. If the device is not under
		 * MPxIO, phci_to_vhci() will fail in which case try to lookup
		 * if an old mapping exists using guid lookup.
		 */
		mapped = 1;
		if (phci_to_vhci(physname, new_physname,
		    sizeof (new_physname)) != 0) {
			if (get_guid(physname, guid, sizeof (guid), 1,
			    DI_NODE_NIL) == 0)
				(void) snprintf(new_physname, MAXPATHLEN,
				    "/scsi_vhci/ssd@g%s", guid);
			else
				mapped = 0;
		}

		if (mapped == 0)
			continue;

		/* strip the slice number part */
		devname[strlen(devname) - 2] = '\0';

		if (guidmap == 0) {
			if (lookup_devlink(new_physname, minor,
			    new_devname, sizeof (new_devname)) != 0)
				continue;

			/* strip the slice number part */
			new_devname[strlen(new_devname) - 2] = '\0';

			if (header) {
				(void) printf(
				    gettext("non-STMS device name\t\t\t"
				    "STMS device name\n"
				    "------------------------------------------"
				    "------------------------\n"));
				header = 0;
			}
			(void) printf("%s\t\t%s\n", devname, new_devname);
		} else {
			/* extract guid part */
			if ((p1 = strstr(new_physname, "ssd@g")) == NULL) {
				logdmsg("invalid vhci: %s\n", new_physname);
				continue;
			}
			p1 += sizeof ("ssd@g") - 1;
			if ((p2 = strrchr(p1, ':')) != NULL)
				*p2 = '\0';

			if (header) {
				(void) printf(
				    gettext("non-STMS device name\t\t\tGUID\n"
				    "------------------------------------------"
				    "------------------------\n"));
				header = 0;
			}
			(void) printf("%s\t\t%s\n", devname, p1);
		}
	}

	(void) closedir(dirp);
	return (0);
}

/*
 * Check if the file can be opened.
 *
 * Return 1 if the file can be opened, 0 otherwise.
 */
static int
canopen(char *filename)
{
	int fd;

	if ((fd = open(filename, O_RDONLY)) == -1)
		return (0);

	(void) close(fd);
	return (1);
}

static void
logerr(char *msg, ...)
{
	va_list ap;

	(void) fprintf(stderr, "%s: ", stmsboot);
	va_start(ap, msg);
	/* LINTED - format specifier */
	(void) vfprintf(stderr, msg, ap);
	va_end(ap);
}

/* log debug message */
static void
logdmsg(char *msg, ...)
{
	va_list ap;

	if (debug) {
		va_start(ap, msg);
		/* LINTED - format specifier */
		(void) vprintf(msg, ap);
		va_end(ap);
	}
}

static void *
s_malloc(const size_t size)
{
	void *rp;

	if ((rp = malloc(size)) == NULL) {
		logerr(gettext("malloc failed to allocate %d bytes\n"), size);
		clean_exit(1);
	}
	return (rp);
}

static char *
s_strdup(const char *ptr)
{
	void *rp;

	if ((rp = strdup(ptr)) == NULL) {
		logerr(gettext("strdup failed to dup %s\n"), ptr);
		clean_exit(1);
	}
	return (rp);
}

static void
s_strlcpy(char *dst, const char *src, size_t dstsize)
{
	int n;

	if ((n = strlcpy(dst, src, dstsize)) >= dstsize) {
		logerr(gettext("strlcpy: destination buffer size is %1$d "
		    "bytes, need to at least %2$d bytes\n"), dstsize, n + 1);
		clean_exit(1);
	}
}

static void
clean_exit(int status)
{
	if (devinfo_root != DI_NODE_NIL)
		di_fini(devinfo_root);

	if (devlink_hdl != NULL)
		(void) di_devlink_fini(&devlink_hdl);

	if (vhci_fd != -1)
		(void) close(vhci_fd);

	exit(status);
}
