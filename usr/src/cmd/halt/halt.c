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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 * Portions contributed by Juergen Keil, <jk@tools.de>.
 */


/*
 * Common code for halt(1M), poweroff(1M), and reboot(1M).  We use
 * argv[0] to determine which behavior to exhibit.
 */

#include <stdio.h>
#include <procfs.h>
#include <sys/types.h>
#include <sys/elf.h>
#include <sys/systeminfo.h>
#include <sys/stat.h>
#include <sys/uadmin.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/mount.h>
#include <sys/fs/ufs_mount.h>
#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <limits.h>
#include <locale.h>
#include <libintl.h>
#include <syslog.h>
#include <signal.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <time.h>
#include <wait.h>
#include <ctype.h>
#include <utmpx.h>
#include <pwd.h>
#include <zone.h>
#include <spawn.h>

#include <libzfs.h>
#if defined(__i386)
#include <libgrubmgmt.h>
#endif

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

#if defined(__sparc)
#define	CUR_ELFDATA	ELFDATA2MSB
#elif defined(__i386)
#define	CUR_ELFDATA	ELFDATA2LSB
#endif

static libzfs_handle_t *g_zfs;

extern int audit_halt_setup(int, char **);
extern int audit_halt_success(void);
extern int audit_halt_fail(void);

extern int audit_reboot_setup(void);
extern int audit_reboot_success(void);
extern int audit_reboot_fail(void);

static char *cmdname;	/* basename(argv[0]), the name of the command */

typedef struct ctidlist_struct {
	ctid_t ctid;
	struct ctidlist_struct *next;
} ctidlist_t;

static ctidlist_t *ctidlist = NULL;
static ctid_t startdct = -1;

#define	FMRI_STARTD_CONTRACT \
	"svc:/system/svc/restarter:default/:properties/restarter/contract"

#define	BEADM_PROG	"/usr/sbin/beadm"
#define	BOOTADM_PROG	"/sbin/bootadm"
#define	ZONEADM_PROG	"/usr/sbin/zoneadm"

/*
 * The length of FASTBOOT_MOUNTPOINT must be less than MAXPATHLEN.
 */
#define	FASTBOOT_MOUNTPOINT	"/tmp/.fastboot.root"

/*
 * Fast Reboot related variables
 */
static char	fastboot_mounted[MAXPATHLEN];

#if defined(__i386)
static grub_boot_args_t	fbarg;
static grub_boot_args_t	*fbarg_used;
static int fbarg_entnum = GRUB_ENTRY_DEFAULT;
#endif	/* __i386 */

static int validate_ufs_disk(char *, char *);
static int validate_zfs_pool(char *, char *);

static pid_t
get_initpid()
{
	static int init_pid = -1;

	if (init_pid == -1) {
		if (zone_getattr(getzoneid(), ZONE_ATTR_INITPID, &init_pid,
		    sizeof (init_pid)) != sizeof (init_pid)) {
			assert(errno == ESRCH);
			init_pid = -1;
		}
	}
	return (init_pid);
}

/*
 * Quiesce or resume init using /proc.  When stopping init, we can't send
 * SIGTSTP (since init ignores it) or SIGSTOP (since the kernel won't permit
 * it).
 */
static int
direct_init(long command)
{
	char ctlfile[MAXPATHLEN];
	pid_t pid;
	int ctlfd;

	assert(command == PCDSTOP || command == PCRUN);
	if ((pid = get_initpid()) == -1) {
		return (-1);
	}

	(void) snprintf(ctlfile, sizeof (ctlfile), "/proc/%d/ctl", pid);
	if ((ctlfd = open(ctlfile, O_WRONLY)) == -1)
		return (-1);

	if (command == PCDSTOP) {
		if (write(ctlfd, &command, sizeof (long)) == -1) {
			(void) close(ctlfd);
			return (-1);
		}
	} else {	/* command == PCRUN */
		long cmds[2];
		cmds[0] = command;
		cmds[1] = 0;
		if (write(ctlfd, cmds, sizeof (cmds)) == -1) {
			(void) close(ctlfd);
			return (-1);
		}
	}
	(void) close(ctlfd);
	return (0);
}

static void
stop_startd()
{
	scf_handle_t *h;
	scf_property_t *prop = NULL;
	scf_value_t *val = NULL;
	uint64_t uint64;

	if ((h = scf_handle_create(SCF_VERSION)) == NULL)
		return;

	if ((scf_handle_bind(h) != 0) ||
	    ((prop = scf_property_create(h)) == NULL) ||
	    ((val = scf_value_create(h)) == NULL))
		goto out;

	if (scf_handle_decode_fmri(h, FMRI_STARTD_CONTRACT,
	    NULL, NULL, NULL, NULL, prop, SCF_DECODE_FMRI_EXACT) != 0)
		goto out;

	if (scf_property_is_type(prop, SCF_TYPE_COUNT) != 0 ||
	    scf_property_get_value(prop, val) != 0 ||
	    scf_value_get_count(val, &uint64) != 0)
		goto out;

	startdct = (ctid_t)uint64;
	(void) sigsend(P_CTID, startdct, SIGSTOP);

out:
	scf_property_destroy(prop);
	scf_value_destroy(val);
	scf_handle_destroy(h);
}

static void
continue_startd()
{
	if (startdct != -1)
		(void) sigsend(P_CTID, startdct, SIGCONT);
}

#define	FMRI_RESTARTER_PROP "/:properties/general/restarter"
#define	FMRI_CONTRACT_PROP "/:properties/restarter/contract"

static int
save_ctid(ctid_t ctid)
{
	ctidlist_t *next;

	for (next = ctidlist; next != NULL; next = next->next)
		if (next->ctid == ctid)
			return (-1);

	next = (ctidlist_t *)malloc(sizeof (ctidlist_t));
	if (next == NULL)
		return (-1);

	next->ctid = ctid;
	next->next = ctidlist;
	ctidlist = next;
	return (0);
}

static void
stop_delegates()
{
	ctid_t ctid;
	scf_handle_t *h;
	scf_scope_t *sc = NULL;
	scf_service_t *svc = NULL;
	scf_instance_t *inst = NULL;
	scf_snapshot_t *snap = NULL;
	scf_snapshot_t *isnap = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *val = NULL;
	scf_iter_t *siter = NULL;
	scf_iter_t *iiter = NULL;
	char *fmri;
	ssize_t length;

	uint64_t uint64;
	ssize_t bytes;

	length = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH);
	if (length <= 0)
		return;

	length++;
	fmri = alloca(length * sizeof (char));

	if ((h = scf_handle_create(SCF_VERSION)) == NULL)
		return;

	if (scf_handle_bind(h) != 0) {
		scf_handle_destroy(h);
		return;
	}

	if ((sc = scf_scope_create(h)) == NULL ||
	    (svc = scf_service_create(h)) == NULL ||
	    (inst = scf_instance_create(h)) == NULL ||
	    (snap = scf_snapshot_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (val = scf_value_create(h)) == NULL ||
	    (siter = scf_iter_create(h)) == NULL ||
	    (iiter = scf_iter_create(h)) == NULL)
		goto out;

	if (scf_handle_get_scope(h, SCF_SCOPE_LOCAL, sc) != 0)
		goto out;

	if (scf_iter_scope_services(siter, sc) != 0)
		goto out;

	while (scf_iter_next_service(siter, svc) == 1) {

		if (scf_iter_service_instances(iiter, svc) != 0)
			continue;

		while (scf_iter_next_instance(iiter, inst) == 1) {

			if ((scf_instance_get_snapshot(inst, "running",
			    snap)) != 0)
				isnap = NULL;
			else
				isnap = snap;

			if (scf_instance_get_pg_composed(inst, isnap,
			    SCF_PG_GENERAL, pg) != 0)
				continue;

			if (scf_pg_get_property(pg, SCF_PROPERTY_RESTARTER,
			    prop) != 0 ||
			    scf_property_get_value(prop, val) != 0)
				continue;

			bytes = scf_value_get_astring(val, fmri, length);
			if (bytes <= 0 || bytes >= length)
				continue;

			if (strlcat(fmri, FMRI_CONTRACT_PROP, length) >=
			    length)
				continue;

			if (scf_handle_decode_fmri(h, fmri, NULL, NULL,
			    NULL, NULL, prop, SCF_DECODE_FMRI_EXACT) != 0)
				continue;

			if (scf_property_is_type(prop, SCF_TYPE_COUNT) != 0 ||
			    scf_property_get_value(prop, val) != 0 ||
			    scf_value_get_count(val, &uint64) != 0)
				continue;

			ctid = (ctid_t)uint64;
			if (save_ctid(ctid) == 0) {
				(void) sigsend(P_CTID, ctid, SIGSTOP);
			}
		}
	}
out:
	scf_scope_destroy(sc);
	scf_service_destroy(svc);
	scf_instance_destroy(inst);
	scf_snapshot_destroy(snap);
	scf_pg_destroy(pg);
	scf_property_destroy(prop);
	scf_value_destroy(val);
	scf_iter_destroy(siter);
	scf_iter_destroy(iiter);

	(void) scf_handle_unbind(h);
	scf_handle_destroy(h);
}

static void
continue_delegates()
{
	ctidlist_t *next;
	for (next = ctidlist; next != NULL; next = next->next)
		(void) sigsend(P_CTID, next->ctid, SIGCONT);
}

#define	FMRI_GDM "svc:/application/graphical-login/gdm:default"
#define	GDM_STOP_TIMEOUT	10	/* Give gdm 10 seconds to shut down */

/*
 * If gdm is running, try to stop gdm.
 * Returns  0 on success, -1 on failure.
 */
static int
stop_gdm()
{
	char *gdm_state = NULL;
	int retry = 0;

	/*
	 * If gdm is running, try to stop gdm.
	 */
	while ((gdm_state = smf_get_state(FMRI_GDM)) != NULL &&
	    strcmp(gdm_state, SCF_STATE_STRING_ONLINE) == 0 &&
	    retry++ < GDM_STOP_TIMEOUT) {

		free(gdm_state);

		/*
		 * Only need to disable once.
		 */
		if (retry == 1 &&
		    smf_disable_instance(FMRI_GDM, SMF_TEMPORARY) != 0) {
			(void) fprintf(stderr,
			    gettext("%s: Failed to stop %s: %s.\n"),
			    cmdname, FMRI_GDM, scf_strerror(scf_error()));
			return (-1);
		}
		(void) sleep(1);
	}

	if (retry >= GDM_STOP_TIMEOUT) {
		(void) fprintf(stderr, gettext("%s: Failed to stop %s.\n"),
		    cmdname, FMRI_GDM);
		return (-1);
	}

	return (0);
}


static void
stop_restarters()
{
	stop_startd();
	stop_delegates();
}

static void
continue_restarters()
{
	continue_startd();
	continue_delegates();
}

/*
 * Copy an array of strings into buf, separated by spaces.  Returns 0 on
 * success.
 */
static int
gather_args(char **args, char *buf, size_t buf_sz)
{
	if (strlcpy(buf, *args, buf_sz) >= buf_sz)
		return (-1);

	for (++args; *args != NULL; ++args) {
		if (strlcat(buf, " ", buf_sz) >= buf_sz)
			return (-1);
		if (strlcat(buf, *args, buf_sz) >= buf_sz)
			return (-1);
	}

	return (0);
}

/*
 * Halt every zone on the system.  We are committed to doing a shutdown
 * even if something goes wrong here. If something goes wrong, we just
 * continue with the shutdown.  Return non-zero if we need to wait for zones to
 * halt later on.
 */
static int
halt_zones()
{
	pid_t pid;
	zoneid_t *zones;
	size_t nz = 0, old_nz;
	int i;
	char zname[ZONENAME_MAX];

	/*
	 * Get a list of zones. If the number of zones changes in between the
	 * two zone_list calls, try again.
	 */

	for (;;) {
		(void) zone_list(NULL, &nz);
		if (nz == 1)
			return (0);
		old_nz = nz;
		zones = calloc(sizeof (zoneid_t), nz);
		if (zones == NULL) {
			(void) fprintf(stderr,
			    gettext("%s: Could not halt zones"
			    " (out of memory).\n"), cmdname);
			return (0);
		}

		(void) zone_list(zones, &nz);
		if (old_nz == nz)
			break;
		free(zones);
	}

	if (nz == 2) {
		(void) fprintf(stderr, gettext("%s: Halting 1 zone.\n"),
		    cmdname);
	} else {
		(void) fprintf(stderr, gettext("%s: Halting %i zones.\n"),
		    cmdname, nz - 1);
	}

	for (i = 0; i < nz; i++) {
		if (zones[i] == GLOBAL_ZONEID)
			continue;
		if (getzonenamebyid(zones[i], zname, sizeof (zname)) < 0) {
			/*
			 * getzonenamebyid should only fail if we raced with
			 * another process trying to shut down the zone.
			 * We assume this happened and ignore the error.
			 */
			if (errno != EINVAL) {
				(void) fprintf(stderr,
				    gettext("%s: Unexpected error while "
				    "looking up zone %ul: %s.\n"),
				    cmdname, zones[i], strerror(errno));
			}

			continue;
		}
		pid = fork();
		if (pid < 0) {
			(void) fprintf(stderr,
			    gettext("%s: Zone \"%s\" could not be"
			    " halted (could not fork(): %s).\n"),
			    cmdname, zname, strerror(errno));
			continue;
		}
		if (pid == 0) {
			(void) execl(ZONEADM_PROG, ZONEADM_PROG,
			    "-z", zname, "halt", NULL);
			(void) fprintf(stderr,
			    gettext("%s: Zone \"%s\" could not be halted"
			    " (cannot exec(" ZONEADM_PROG "): %s).\n"),
			    cmdname, zname, strerror(errno));
			exit(0);
		}
	}

	return (1);
}

/*
 * This function tries to wait for all non-global zones to go away.
 * It will timeout if no progress is made for 5 seconds, or a total of
 * 30 seconds elapses.
 */

static void
check_zones_haltedness()
{
	int t = 0, t_prog = 0;
	size_t nz = 0, last_nz;

	do {
		last_nz = nz;
		(void) zone_list(NULL, &nz);
		if (nz == 1)
			return;

		(void) sleep(1);

		if (last_nz > nz)
			t_prog = 0;

		t++;
		t_prog++;

		if (t == 10) {
			if (nz == 2) {
				(void) fprintf(stderr,
				    gettext("%s: Still waiting for 1 zone to "
				    "halt. Will wait up to 20 seconds.\n"),
				    cmdname);
			} else {
				(void) fprintf(stderr,
				    gettext("%s: Still waiting for %i zones "
				    "to halt. Will wait up to 20 seconds.\n"),
				    cmdname, nz - 1);
			}
		}

	} while ((t < 30) && (t_prog < 5));
}


/*
 * Validate that this is a root disk or dataset
 * Returns 0 if it is a root disk or dataset;
 * returns 1 if it is a disk argument or dataset, but not valid or not root;
 * returns -1 if it is not a valid argument or a disk argument.
 */
static int
validate_disk(char *arg, char *mountpoint)
{
	static char root_dev_path[] = "/dev/dsk";
	char kernpath[MAXPATHLEN];
	struct stat64 statbuf;
	int rc = 0;

	if (strlen(arg) > MAXPATHLEN) {
		(void) fprintf(stderr,
		    gettext("%s: Argument is too long\n"), cmdname);
		return (-1);
	}

	bcopy(FASTBOOT_MOUNTPOINT, mountpoint, sizeof (FASTBOOT_MOUNTPOINT));

	if (strstr(arg, mountpoint) == NULL) {
		/*
		 * Do a force umount just in case some other filesystem has
		 * been mounted there.
		 */
		(void) umount2(mountpoint, MS_FORCE);
	}

	/* Create the directory if it doesn't already exist */
	if (lstat64(mountpoint, &statbuf) != 0) {
		if (mkdirp(mountpoint, 0755) != 0) {
			(void) fprintf(stderr,
			    gettext("Failed to create mountpoint %s\n"),
			    mountpoint);
			return (-1);
		}
	}

	if (strncmp(arg, root_dev_path, strlen(root_dev_path)) == 0) {
		/* ufs root disk argument */
		rc = validate_ufs_disk(arg, mountpoint);
	} else {
		/* zfs root pool argument */
		rc = validate_zfs_pool(arg, mountpoint);
	}

	if (rc != 0)
		return (rc);

	(void) snprintf(kernpath, MAXPATHLEN, "%s/platform/i86pc/kernel/unix",
	    mountpoint);

	if (stat64(kernpath, &statbuf) != 0) {
		(void) fprintf(stderr,
		    gettext("%s: %s is not a root disk or dataset\n"),
		    cmdname, arg);
		return (1);
	}

	return (0);
}


static int
validate_ufs_disk(char *arg, char *mountpoint)
{
	struct ufs_args	ufs_args = { 0 };
	char mntopts[MNT_LINE_MAX] = MNTOPT_LARGEFILES;

	/* perform the mount */
	ufs_args.flags = UFSMNT_LARGEFILES;
	if (mount(arg, mountpoint, MS_DATA|MS_OPTIONSTR,
	    MNTTYPE_UFS, &ufs_args, sizeof (ufs_args),
	    mntopts, sizeof (mntopts)) != 0) {
		perror(cmdname);
		(void) fprintf(stderr,
		    gettext("%s: Failed to mount %s\n"), cmdname, arg);
		return (-1);
	}

	return (0);
}

static int
validate_zfs_pool(char *arg, char *mountpoint)
{
	zfs_handle_t *zhp = NULL;
	char mntopts[MNT_LINE_MAX] = { '\0' };
	int rc = 0;

	if ((g_zfs = libzfs_init()) == NULL) {
		(void) fprintf(stderr, gettext("Internal error: failed to "
		    "initialize ZFS library\n"));
		return (-1);
	}

	/* Try to open the dataset */
	if ((zhp = zfs_open(g_zfs, arg,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_DATASET)) == NULL)
		return (-1);

	/* perform the mount */
	if (mount(zfs_get_name(zhp), mountpoint, MS_DATA|MS_OPTIONSTR|MS_RDONLY,
	    MNTTYPE_ZFS, NULL, 0, mntopts, sizeof (mntopts)) != 0) {
		perror(cmdname);
		(void) fprintf(stderr,
		    gettext("%s: Failed to mount %s\n"), cmdname, arg);
		rc = -1;
	}

validate_zfs_err_out:
	if (zhp != NULL)
		zfs_close(zhp);

	libzfs_fini(g_zfs);
	return (rc);
}

/*
 * Return 0 if not zfs, or is zfs and have successfully constructed the
 * boot argument; returns non-zero otherwise.
 * At successful completion fpth contains pointer where mount point ends.
 * NOTE: arg is supposed to be the resolved path
 */
static int
get_zfs_bootfs_arg(const char *arg, const char ** fpth, int *is_zfs,
		char *bootfs_arg)
{
	zfs_handle_t *zhp = NULL;
	zpool_handle_t *zpoolp = NULL;
	FILE *mtabp = NULL;
	struct mnttab mnt;
	char *poolname = NULL;
	char physpath[MAXPATHLEN];
	char mntsp[ZPOOL_MAXNAMELEN];
	char bootfs[ZPOOL_MAXNAMELEN];
	int rc = 0;
	size_t mntlen = 0;
	size_t msz;
	static char fmt[] = "-B zfs-bootfs=%s,bootpath=\"%s\"";

	*fpth = arg;
	*is_zfs = 0;

	bzero(physpath, sizeof (physpath));
	bzero(bootfs, sizeof (bootfs));

	if ((mtabp = fopen(MNTTAB, "r")) == NULL) {
		return (-1);
	}

	while (getmntent(mtabp, &mnt) == 0) {
		if (strstr(arg, mnt.mnt_mountp) == arg &&
		    (msz = strlen(mnt.mnt_mountp)) > mntlen) {
			mntlen = msz;
			*is_zfs = strcmp(MNTTYPE_ZFS, mnt.mnt_fstype) == 0;
			(void) strlcpy(mntsp, mnt.mnt_special, sizeof (mntsp));
		}
	}

	(void) fclose(mtabp);

	if (mntlen > 1)
		*fpth += mntlen;

	if (!*is_zfs)
		return (0);

	if ((g_zfs = libzfs_init()) == NULL)
		return (-1);

	/* Try to open the dataset */
	if ((zhp = zfs_open(g_zfs, mntsp,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_DATASET)) == NULL) {
		(void) fprintf(stderr, gettext("Cannot open %s\n"), mntsp);
		rc = -1;
		goto validate_zfs_err_out;
	}

	(void) strlcpy(bootfs, mntsp, sizeof (bootfs));

	if ((poolname = strtok(mntsp, "/")) == NULL) {
		rc = -1;
		goto validate_zfs_err_out;
	}

	if ((zpoolp = zpool_open(g_zfs, poolname)) == NULL) {
		(void) fprintf(stderr, gettext("Cannot open %s\n"), poolname);
		rc = -1;
		goto validate_zfs_err_out;
	}

	if (zpool_get_physpath(zpoolp, physpath, sizeof (physpath)) != 0) {
		(void) fprintf(stderr, gettext("Cannot find phys_path\n"));
		rc = -1;
		goto validate_zfs_err_out;
	}

	/*
	 * For the mirror physpath would contain the list of all
	 * bootable devices, pick up the first one.
	 */
	(void) strtok(physpath, " ");
	if (snprintf(bootfs_arg, BOOTARGS_MAX, fmt, bootfs, physpath) >=
	    BOOTARGS_MAX) {
		rc = E2BIG;
		(void) fprintf(stderr,
		    gettext("Boot arguments are too long\n"));
	}

validate_zfs_err_out:
	if (zhp != NULL)
		zfs_close(zhp);

	if (zpoolp != NULL)
		zpool_close(zpoolp);

	libzfs_fini(g_zfs);
	return (rc);
}

/*
 * Validate that the file exists, and is an ELF file.
 * Returns 0 on success, -1 on failure.
 */
static int
validate_unix(char *arg, int *mplen, int *is_zfs, char *bootfs_arg)
{
	const char *location;
	int class, format;
	unsigned char ident[EI_NIDENT];
	char physpath[MAXPATHLEN];
	int elffd = -1;
	size_t	sz;

	if ((sz = resolvepath(arg, physpath, sizeof (physpath) - 1)) ==
	    (size_t)-1) {
		(void) fprintf(stderr,
		    gettext("Cannot resolve path for %s: %s\n"),
		    arg, strerror(errno));
		return (-1);
	}
	(void) strlcpy(arg, physpath, sz + 1);

	if (strlen(arg) > MAXPATHLEN) {
		(void) fprintf(stderr,
		    gettext("%s: New kernel name is too long\n"), cmdname);
		return (-1);
	}

	if (strncmp(basename(arg), "unix", 4) != 0) {
		(void) fprintf(stderr,
		    gettext("%s: %s: Kernel name must be unix\n"),
		    cmdname, arg);
		return (-1);
	}

	if (get_zfs_bootfs_arg(arg, &location, is_zfs, bootfs_arg) != 0)
		goto err_out;

	*mplen = location - arg;

	if (strstr(location, "/boot/platform") == location) {
		/*
		 * Rebooting to failsafe.
		 * Clear bootfs_arg and is_zfs flag.
		 */
		bootfs_arg[0] = 0;
		*is_zfs = 0;
	} else if (strstr(location, "/platform") != location) {
		(void) fprintf(stderr,
		    gettext("%s: %s: No /platform in file name\n"),
		    cmdname, arg);
		goto err_out;
	}

	if ((elffd = open64(arg, O_RDONLY)) < 0 ||
	    (pread64(elffd, ident, EI_NIDENT, 0) != EI_NIDENT)) {
		(void) fprintf(stderr, "%s: %s: %s\n",
		    cmdname, arg, strerror(errno));
		goto err_out;
	}

	class = ident[EI_CLASS];

	if ((class != ELFCLASS32 && class != ELFCLASS64) ||
	    memcmp(&ident[EI_MAG0], ELFMAG, 4) != 0) {
		(void) fprintf(stderr,
		    gettext("%s: %s: Not a valid ELF file\n"), cmdname, arg);
		goto err_out;
	}

	format = ident[EI_DATA];

	if (format != CUR_ELFDATA) {
		(void) fprintf(stderr, gettext("%s: %s: Invalid data format\n"),
		    cmdname, arg);
		goto err_out;
	}

	return (0);

err_out:
	if (elffd >= 0) {
		(void) close(elffd);
		elffd = -1;
	}
	return (-1);
}

static int
halt_exec(const char *path, ...)
{
	pid_t		pid;
	int		i;
	int		st;
	const char	*arg;
	va_list	vp;
	const char	*argv[256];

	if ((pid = fork()) == -1) {
		return (errno);
	} else if (pid == 0) {
		(void) fclose(stdout);
		(void) fclose(stderr);

		argv[0] = path;
		i = 1;

		va_start(vp, path);

		do {
			arg = va_arg(vp, const char *);
			argv[i] = arg;
		} while (arg != NULL &&
		    ++i != sizeof (argv) / sizeof (argv[0]));

		va_end(vp);

		(void) execve(path, (char * const *)argv, NULL);
		(void) fprintf(stderr, gettext("Cannot execute %s: %s\n"),
		    path, strerror(errno));
		exit(-1);
	} else {
		if (waitpid(pid, &st, 0) == pid &&
		    !WIFSIGNALED(st) && WIFEXITED(st))
			st = WEXITSTATUS(st);
		else
			st = -1;
	}
	return (st);
}

/*
 * Mount the specified BE.
 *
 * Upon success returns zero and copies bename string to mountpoint[]
 */
static int
fastboot_bename(const char *bename, char *mountpoint, size_t mpsz)
{
	int rc;

	/*
	 * Attempt to unmount the BE first in case it's already mounted
	 * elsewhere.
	 */
	(void) halt_exec(BEADM_PROG, "umount", bename, NULL);

	if ((rc = halt_exec(BEADM_PROG, "mount", bename, FASTBOOT_MOUNTPOINT,
	    NULL)) != 0)
		(void) fprintf(stderr,
		    gettext("%s: Unable to mount BE \"%s\" at %s\n"),
		    cmdname, bename, FASTBOOT_MOUNTPOINT);
	else
		(void) strlcpy(mountpoint, FASTBOOT_MOUNTPOINT, mpsz);

	return (rc);
}

/*
 * Returns 0 on successful parsing of the arguments;
 * returns EINVAL on parsing failures that should abort the reboot attempt;
 * returns other error code to fall back to regular reboot.
 */
static int
parse_fastboot_args(char *bootargs_buf, size_t buf_size,
    int *is_dryrun, const char *bename)
{
	char mountpoint[MAXPATHLEN];
	char bootargs_saved[BOOTARGS_MAX];
	char bootargs_scratch[BOOTARGS_MAX];
	char bootfs_arg[BOOTARGS_MAX];
	char unixfile[BOOTARGS_MAX];
	char *head, *newarg;
	int buflen;		/* length of the bootargs_buf */
	int mplen;		/* length of the mount point */
	int rootlen = 0;	/* length of the root argument */
	int unixlen = 0;	/* length of the unix argument */
	int off = 0;		/* offset into the new boot argument */
	int is_zfs = 0;
	int rc = 0;

	bzero(mountpoint, sizeof (mountpoint));

	/*
	 * If argc is not 0, buflen is length of the argument being passed in;
	 * else it is 0 as bootargs_buf has been initialized to all 0's.
	 */
	buflen = strlen(bootargs_buf);

	/* Save a copy of the original argument */
	bcopy(bootargs_buf, bootargs_saved, buflen);
	bzero(&bootargs_saved[buflen], sizeof (bootargs_saved) - buflen);

	/* Save another copy to be used by strtok */
	bcopy(bootargs_buf, bootargs_scratch, buflen);
	bzero(&bootargs_scratch[buflen], sizeof (bootargs_scratch) - buflen);
	head = &bootargs_scratch[0];

	/* Get the first argument */
	newarg = strtok(bootargs_scratch, " ");

	/*
	 * If this is a dry run request, verify that the drivers can handle
	 * fast reboot.
	 */
	if (newarg && strncasecmp(newarg, "dryrun", strlen("dryrun")) == 0) {
		*is_dryrun = 1;
		(void) system("/usr/sbin/devfsadm");
	}

	/*
	 * Always perform a dry run to identify all the drivers that
	 * need to implement devo_reset().
	 */
	if (uadmin(A_SHUTDOWN, AD_FASTREBOOT_DRYRUN,
	    (uintptr_t)bootargs_saved) != 0) {
		(void) fprintf(stderr, gettext("%s: Not all drivers "
		    "have implemented quiesce(9E)\n"
		    "\tPlease see /var/adm/messages for drivers that haven't\n"
		    "\timplemented quiesce(9E).\n"), cmdname);
	} else if (*is_dryrun) {
		(void) fprintf(stderr, gettext("%s: All drivers have "
		    "implemented quiesce(9E)\n"), cmdname);
	}

	/* Return if it is a true dry run. */
	if (*is_dryrun)
		return (rc);

#if defined(__i386)
	/* Read boot args from GRUB menu */
	if ((bootargs_buf[0] == 0 || isdigit(bootargs_buf[0])) &&
	    bename == NULL) {
		/*
		 * If no boot arguments are given, or a GRUB menu entry
		 * number is provided, process the GRUB menu.
		 */
		int entnum;
		if (bootargs_buf[0] == 0)
			entnum = GRUB_ENTRY_DEFAULT;
		else {
			errno = 0;
			entnum = strtoul(bootargs_buf, NULL, 10);
			rc = errno;
		}

		if (rc == 0 && (rc = grub_get_boot_args(&fbarg, NULL,
		    entnum)) == 0) {
			if (strlcpy(bootargs_buf, fbarg.gba_bootargs,
			    buf_size) >= buf_size) {
				grub_cleanup_boot_args(&fbarg);
				bcopy(bootargs_saved, bootargs_buf, buf_size);
				rc = E2BIG;
			}
		}
		/* Failed to read GRUB menu, fall back to normal reboot */
		if (rc != 0) {
			(void) fprintf(stderr,
			    gettext("%s: Failed to process GRUB menu "
			    "entry for fast reboot.\n\t%s\n"),
			    cmdname, grub_strerror(rc));
			(void) fprintf(stderr,
			    gettext("%s: Falling back to regular reboot.\n"),
			    cmdname);
			return (-1);
		}
		/* No need to process further */
		fbarg_used = &fbarg;
		fbarg_entnum = entnum;
		return (0);
	}
#endif	/* __i386 */

	/* Zero out the boot argument buffer as we will reconstruct it */
	bzero(bootargs_buf, buf_size);
	bzero(bootfs_arg, sizeof (bootfs_arg));
	bzero(unixfile, sizeof (unixfile));

	if (bename && (rc = fastboot_bename(bename, mountpoint,
	    sizeof (mountpoint))) != 0)
		return (EINVAL);


	/*
	 * If BE is not specified, look for disk argument to construct
	 * mountpoint; if BE has been specified, mountpoint has already been
	 * constructed.
	 */
	if (newarg && newarg[0] != '-' && !bename) {
		int tmprc;

		if ((tmprc = validate_disk(newarg, mountpoint)) == 0) {
			/*
			 * The first argument is a valid root argument.
			 * Get the next argument.
			 */
			newarg = strtok(NULL, " ");
			rootlen = (newarg) ? (newarg - head) : buflen;
			(void) strlcpy(fastboot_mounted, mountpoint,
			    sizeof (fastboot_mounted));

		} else if (tmprc == -1) {
			/*
			 * Not a disk argument.  Use / as default root.
			 */
			bcopy("/", mountpoint, 1);
			bzero(&mountpoint[1], sizeof (mountpoint) - 1);
		} else {
			/*
			 * Disk argument, but not valid or not root.
			 * Return failure.
			 */
			return (EINVAL);
		}
	}

	/*
	 * Make mountpoint the first part of unixfile.
	 * If there is not disk argument, and BE has not been specified,
	 * mountpoint could be empty.
	 */
	mplen = strlen(mountpoint);
	bcopy(mountpoint, unixfile, mplen);

	/*
	 * Look for unix argument
	 */
	if (newarg && newarg[0] != '-') {
		bcopy(newarg, &unixfile[mplen], strlen(newarg));
		newarg = strtok(NULL, " ");
		rootlen = (newarg) ? (newarg - head) : buflen;
	} else if (mplen != 0) {
		/*
		 * No unix argument, but mountpoint is not empty, use
		 * /platform/i86pc/$ISADIR/kernel/unix as default.
		 */
		char isa[20];

		if (sysinfo(SI_ARCHITECTURE_64, isa, sizeof (isa)) != -1)
			(void) snprintf(&unixfile[mplen],
			    sizeof (unixfile) - mplen,
			    "/platform/i86pc/kernel/%s/unix", isa);
		else if (sysinfo(SI_ARCHITECTURE_32, isa, sizeof (isa)) != -1) {
			(void) snprintf(&unixfile[mplen],
			    sizeof (unixfile) - mplen,
			    "/platform/i86pc/kernel/unix");
		} else {
			(void) fprintf(stderr,
			    gettext("%s: Unknown architecture"), cmdname);
			return (EINVAL);
		}
	}

	/*
	 * We now have the complete unix argument.  Verify that it exists and
	 * is an ELF file.  Split the argument up into mountpoint and unix
	 * portions again.  This is necessary to handle cases where mountpoint
	 * is specified on the command line as part of the unix argument,
	 * such as this:
	 *	# reboot -f /.alt/platform/i86pc/kernel/amd64/unix
	 */
	unixlen = strlen(unixfile);
	if (unixlen > 0) {
		if (validate_unix(unixfile, &mplen, &is_zfs,
		    bootfs_arg) != 0) {
			/* Not a valid unix file */
			return (EINVAL);
		} else {
			int space = 0;
			/*
			 * Construct boot argument.
			 */
			unixlen = strlen(unixfile);

			/*
			 * mdep cannot start with space because bootadm
			 * creates bogus menu entries if it does.
			 */
			if (mplen > 0) {
				bcopy(unixfile, bootargs_buf, mplen);
				(void) strcat(bootargs_buf, " ");
				space = 1;
			}
			bcopy(&unixfile[mplen], &bootargs_buf[mplen + space],
			    unixlen - mplen);
			(void) strcat(bootargs_buf, " ");
			off += unixlen + space + 1;
		}
	} else {
		/* Check to see if root is zfs */
		const char	*dp;
		(void) get_zfs_bootfs_arg("/", &dp, &is_zfs, bootfs_arg);
	}

	if (is_zfs && (buflen != 0 || bename != NULL))	{
		/* LINTED E_SEC_SPRINTF_UNBOUNDED_COPY */
		off += sprintf(bootargs_buf + off, "%s ", bootfs_arg);
	}

	/*
	 * Copy the rest of the arguments
	 */
	bcopy(&bootargs_saved[rootlen], &bootargs_buf[off], buflen - rootlen);

	return (rc);
}

#define	MAXARGS		5

static void
do_archives_update(int do_fast_reboot)
{
	int	r, i = 0;
	pid_t	pid;
	char	*cmd_argv[MAXARGS];


	cmd_argv[i++] = "/sbin/bootadm";
	cmd_argv[i++] = "-ea";
	cmd_argv[i++] = "update_all";
	if (do_fast_reboot)
		cmd_argv[i++] = "fastboot";
	cmd_argv[i] = NULL;

	r = posix_spawn(&pid, cmd_argv[0], NULL, NULL, cmd_argv, NULL);

	/* if posix_spawn fails we emit a warning and continue */

	if (r != 0)
		(void) fprintf(stderr, gettext("%s: WARNING, unable to start "
		    "boot archive update\n"), cmdname);
	else
		while (waitpid(pid, NULL, 0) == -1 && errno == EINTR)
			;
}

int
main(int argc, char *argv[])
{
	int qflag = 0, needlog = 1, nosync = 0;
	int fast_reboot = 0;
	int prom_reboot = 0;
	uintptr_t mdep = NULL;
	int cmd, fcn, c, aval, r;
	const char *usage;
	const char *optstring;
	zoneid_t zoneid = getzoneid();
	int need_check_zones = 0;
	char bootargs_buf[BOOTARGS_MAX];
	char *bootargs_orig = NULL;
	char *bename = NULL;

	const char * const resetting = "/etc/svc/volatile/resetting";

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	cmdname = basename(argv[0]);

	if (strcmp(cmdname, "halt") == 0) {
		(void) audit_halt_setup(argc, argv);
		optstring = "dlnqy";
		usage = gettext("usage: %s [ -dlnqy ]\n");
		cmd = A_SHUTDOWN;
		fcn = AD_HALT;
	} else if (strcmp(cmdname, "poweroff") == 0) {
		(void) audit_halt_setup(argc, argv);
		optstring = "dlnqy";
		usage = gettext("usage: %s [ -dlnqy ]\n");
		cmd = A_SHUTDOWN;
		fcn = AD_POWEROFF;
	} else if (strcmp(cmdname, "reboot") == 0) {
		(void) audit_reboot_setup();
#if defined(__i386)
		optstring = "dlnqpfe:";
		usage = gettext("usage: %s [ -dlnq(p|fe:) ] [ boot args ]\n");
#else
		optstring = "dlnqfp";
		usage = gettext("usage: %s [ -dlnq(p|f) ] [ boot args ]\n");
#endif
		cmd = A_SHUTDOWN;
		fcn = AD_BOOT;
	} else {
		(void) fprintf(stderr,
		    gettext("%s: not installed properly\n"), cmdname);
		return (1);
	}

	while ((c = getopt(argc, argv, optstring)) != EOF) {
		switch (c) {
		case 'd':
			if (zoneid == GLOBAL_ZONEID)
				cmd = A_DUMP;
			else {
				(void) fprintf(stderr,
				    gettext("%s: -d only valid from global"
				    " zone\n"), cmdname);
				return (1);
			}
			break;
		case 'l':
			needlog = 0;
			break;
		case 'n':
			nosync = 1;
			break;
		case 'q':
			qflag = 1;
			break;
		case 'y':
			/*
			 * Option ignored for backwards compatibility.
			 */
			break;
		case 'f':
			fast_reboot = 1;
			break;
		case 'p':
			prom_reboot = 1;
			break;
#if defined(__i386)
		case 'e':
			bename = optarg;
			break;
#endif
		default:
			/*
			 * TRANSLATION_NOTE
			 * Don't translate the words "halt" or "reboot"
			 */
			(void) fprintf(stderr, usage, cmdname);
			return (1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0) {
		if (fcn != AD_BOOT) {
			(void) fprintf(stderr, usage, cmdname);
			return (1);
		}

		/* Gather the arguments into bootargs_buf. */
		if (gather_args(argv, bootargs_buf, sizeof (bootargs_buf)) !=
		    0) {
			(void) fprintf(stderr,
			    gettext("%s: Boot arguments too long.\n"), cmdname);
			return (1);
		}

		bootargs_orig = strdup(bootargs_buf);
		mdep = (uintptr_t)bootargs_buf;
	} else {
		/*
		 * Initialize it to 0 in case of fastboot, the buffer
		 * will be used.
		 */
		bzero(bootargs_buf, sizeof (bootargs_buf));
	}

	if (geteuid() != 0) {
		(void) fprintf(stderr,
		    gettext("%s: permission denied\n"), cmdname);
		goto fail;
	}

	if (fast_reboot && prom_reboot) {
		(void) fprintf(stderr,
		    gettext("%s: -p and -f are mutually exclusive\n"),
		    cmdname);
		return (EINVAL);
	}
	/*
	 * Check whether fast reboot is the default operating mode
	 */
	if (fcn == AD_BOOT && !fast_reboot && !prom_reboot &&
	    zoneid == GLOBAL_ZONEID) {
		fast_reboot = scf_is_fastboot_default();

	}

	if (bename && !fast_reboot)	{
		(void) fprintf(stderr, gettext("%s: -e only valid with -f\n"),
		    cmdname);
		return (EINVAL);
	}

#if defined(__sparc)
	if (fast_reboot) {
		fast_reboot = 2;	/* need to distinguish each case */
	}
#endif

	/*
	 * If fast reboot, do some sanity check on the argument
	 */
	if (fast_reboot == 1) {
		int rc;
		int is_dryrun = 0;

		if (zoneid != GLOBAL_ZONEID)	{
			(void) fprintf(stderr,
			    gettext("%s: Fast reboot only valid from global"
			    " zone\n"), cmdname);
			return (EINVAL);
		}

		rc = parse_fastboot_args(bootargs_buf, sizeof (bootargs_buf),
		    &is_dryrun, bename);

		/*
		 * If dry run, or if arguments are invalid, return.
		 */
		if (is_dryrun)
			return (rc);
		else if (rc == EINVAL)
			goto fail;
		else if (rc != 0)
			fast_reboot = 0;

		/*
		 * For all the other errors, we continue on in case user
		 * user want to force fast reboot, or fall back to regular
		 * reboot.
		 */
		if (strlen(bootargs_buf) != 0)
			mdep = (uintptr_t)bootargs_buf;
	}

#if 0	/* For debugging */
	if (mdep != NULL)
		(void) fprintf(stderr, "mdep = %s\n", (char *)mdep);
#endif

	if (needlog) {
		char *user = getlogin();
		struct passwd *pw;
		char *tty;

		openlog(cmdname, 0, LOG_AUTH);
		if (user == NULL && (pw = getpwuid(getuid())) != NULL)
			user = pw->pw_name;
		if (user == NULL)
			user = "root";

		tty = ttyname(1);

		if (tty == NULL)
			syslog(LOG_CRIT, "initiated by %s", user);
		else
			syslog(LOG_CRIT, "initiated by %s on %s", user, tty);
	}

	/*
	 * We must assume success and log it before auditd is terminated.
	 */
	if (fcn == AD_BOOT)
		aval = audit_reboot_success();
	else
		aval = audit_halt_success();

	if (aval == -1) {
		(void) fprintf(stderr,
		    gettext("%s: can't turn off auditd\n"), cmdname);
		if (needlog)
			(void) sleep(5); /* Give syslogd time to record this */
	}

	(void) signal(SIGHUP, SIG_IGN);	/* for remote connections */

	/*
	 * We start to fork a bunch of zoneadms to halt any active zones.
	 * This will proceed with halt in parallel until we call
	 * check_zone_haltedness later on.
	 */
	if (zoneid == GLOBAL_ZONEID && cmd != A_DUMP) {
		need_check_zones = halt_zones();
	}

#if defined(__i386)
	/* set new default entry in the GRUB entry */
	if (fbarg_entnum != GRUB_ENTRY_DEFAULT) {
		char buf[32];
		(void) snprintf(buf, sizeof (buf), "default=%u", fbarg_entnum);
		(void) halt_exec(BOOTADM_PROG, "set-menu", buf, NULL);
	}
#endif	/* __i386 */

	/* if we're dumping, do the archive update here and don't defer it */
	if (cmd == A_DUMP && zoneid == GLOBAL_ZONEID && !nosync)
		do_archives_update(fast_reboot);

	/*
	 * If we're not forcing a crash dump, mark the system as quiescing for
	 * smf(5)'s benefit, and idle the init process.
	 */
	if (cmd != A_DUMP) {
		if (direct_init(PCDSTOP) == -1) {
			/*
			 * TRANSLATION_NOTE
			 * Don't translate the word "init"
			 */
			(void) fprintf(stderr,
			    gettext("%s: can't idle init\n"), cmdname);
			goto fail;
		}

		if (creat(resetting, 0755) == -1)
			(void) fprintf(stderr,
			    gettext("%s: could not create %s.\n"),
			    cmdname, resetting);
	}

	/*
	 * Make sure we don't get stopped by a jobcontrol shell
	 * once we start killing everybody.
	 */
	(void) signal(SIGTSTP, SIG_IGN);
	(void) signal(SIGTTIN, SIG_IGN);
	(void) signal(SIGTTOU, SIG_IGN);
	(void) signal(SIGPIPE, SIG_IGN);
	(void) signal(SIGTERM, SIG_IGN);

	/*
	 * Try to stop gdm so X has a chance to return the screen and
	 * keyboard to a sane state.
	 */
	if (fast_reboot == 1 && stop_gdm() != 0) {
		(void) fprintf(stderr,
		    gettext("%s: Falling back to regular reboot.\n"), cmdname);
		fast_reboot = 0;
		mdep = (uintptr_t)bootargs_orig;
	} else if (bootargs_orig) {
		free(bootargs_orig);
	}

	if (cmd != A_DUMP) {
		/*
		 * Stop all restarters so they do not try to restart services
		 * that are terminated.
		 */
		stop_restarters();

		/*
		 * Wait a little while for zones to shutdown.
		 */
		if (need_check_zones) {
			check_zones_haltedness();

			(void) fprintf(stderr,
			    gettext("%s: Completing system halt.\n"),
			    cmdname);
		}
	}

	/*
	 * If we're not forcing a crash dump, give everyone 5 seconds to
	 * handle a SIGTERM and clean up properly.
	 */
	if (cmd != A_DUMP) {
		int	start, end, delta;

		(void) kill(-1, SIGTERM);
		start = time(NULL);

		if (zoneid == GLOBAL_ZONEID && !nosync)
			do_archives_update(fast_reboot);

		end = time(NULL);
		delta = end - start;
		if (delta < 5)
			(void) sleep(5 - delta);
	}

	(void) signal(SIGINT, SIG_IGN);

	if (!qflag && !nosync) {
		struct utmpx wtmpx;

		bzero(&wtmpx, sizeof (struct utmpx));
		(void) strcpy(wtmpx.ut_line, "~");
		(void) time(&wtmpx.ut_tv.tv_sec);

		if (cmd == A_DUMP)
			(void) strcpy(wtmpx.ut_name, "crash dump");
		else
			(void) strcpy(wtmpx.ut_name, "shutdown");

		(void) updwtmpx(WTMPX_FILE, &wtmpx);
		sync();
	}

	if (cmd == A_DUMP && nosync != 0)
		(void) uadmin(A_DUMP, AD_NOSYNC, NULL);

	if (fast_reboot)
		fcn = AD_FASTREBOOT;

	if (uadmin(cmd, fcn, mdep) == -1)
		(void) fprintf(stderr, "%s: uadmin failed: %s\n",
		    cmdname, strerror(errno));
	else
		(void) fprintf(stderr, "%s: uadmin unexpectedly returned 0\n",
		    cmdname);

	do {
		r = remove(resetting);
	} while (r != 0 && errno == EINTR);

	if (r != 0 && errno != ENOENT)
		(void) fprintf(stderr, gettext("%s: could not remove %s.\n"),
		    cmdname, resetting);

	if (direct_init(PCRUN) == -1) {
		/*
		 * TRANSLATION_NOTE
		 * Don't translate the word "init"
		 */
		(void) fprintf(stderr,
		    gettext("%s: can't resume init\n"), cmdname);
	}

	continue_restarters();

	if (get_initpid() != -1)
		/* tell init to restate current level */
		(void) kill(get_initpid(), SIGHUP);

fail:
	if (fcn == AD_BOOT)
		(void) audit_reboot_fail();
	else
		(void) audit_halt_fail();

	if (fast_reboot == 1) {
		if (bename) {
			(void) halt_exec(BEADM_PROG, "umount", bename, NULL);

		} else if (strlen(fastboot_mounted) != 0) {
			(void) umount(fastboot_mounted);
#if defined(__i386)
		} else if (fbarg_used != NULL) {
			grub_cleanup_boot_args(fbarg_used);
#endif	/* __i386 */
		}
	}

	return (1);
}
