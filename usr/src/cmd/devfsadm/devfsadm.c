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
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Devfsadm replaces drvconfig, audlinks, disks, tapes, ports, devlinks
 * as a general purpose device administrative utility.	It creates
 * devices special files in /devices and logical links in /dev, and
 * coordinates updates to /etc/path_to_instance with the kernel.  It
 * operates in both command line mode to handle user or script invoked
 * reconfiguration updates, and operates in daemon mode to handle dynamic
 * reconfiguration for hotplugging support.
 */

#include <string.h>
#include <deflt.h>
#include <tsol/label.h>
#include <bsm/devices.h>
#include <bsm/devalloc.h>
#include <utime.h>
#include <sys/param.h>
#include <bsm/libbsm.h>
#include <zone.h>
#include "devfsadm_impl.h"

/* externs from devalloc.c */
extern void  _reset_devalloc(int);
extern void _update_devalloc_db(devlist_t *, int, int, char *, char *);
extern int _da_check_for_usb(char *, char *);

/* create or remove nodes or links. unset with -n */
static int file_mods = TRUE;

/* cleanup mode.  Set with -C */
static int cleanup = FALSE;

/* devlinks -d compatibility */
static int devlinks_debug = FALSE;

/* flag to check if system is labeled */
int system_labeled = FALSE;

/* flag to enable/disable device allocation with -e/-d */
static int devalloc_flag = 0;

/* flag that indicates if device allocation is on or not */
static int devalloc_is_on = 0;

/* flag to update device allocation database for this device type */
static int update_devdb = 0;

/*
 * devices to be deallocated with -d :
 *	audio, floppy, cd, floppy, tape, rmdisk.
 */
static char *devalloc_list[10] = {DDI_NT_AUDIO, DDI_NT_CD, DDI_NT_CD_CHAN,
				    DDI_NT_FD, DDI_NT_TAPE, DDI_NT_BLOCK_CHAN,
				    DDI_NT_UGEN, DDI_NT_USB_ATTACHMENT_POINT,
				    DDI_NT_SCSI_NEXUS, NULL};

/* list of allocatable devices */
static devlist_t devlist;

/* load a single driver only.  set with -i */
static int single_drv = FALSE;
static char *driver = NULL;

/* attempt to load drivers or defer attach nodes */
static int load_attach_drv = TRUE;

/* reload all driver.conf files */
static int update_all_drivers = FALSE;

/* set if invoked via /usr/lib/devfsadm/devfsadmd */
static int daemon_mode = FALSE;

/* set if event_handler triggered */
int event_driven = FALSE;

/* output directed to syslog during daemon mode if set */
static int logflag = FALSE;

/* build links in /dev.  -x to turn off */
static int build_dev = TRUE;

/* build nodes in /devices.  -y to turn off */
static int build_devices = TRUE;

/* -z to turn off */
static int flush_path_to_inst_enable = TRUE;

/* variables used for path_to_inst flushing */
static int inst_count = 0;
static mutex_t count_lock;
static cond_t cv;

/* variables for minor_fini thread */
static mutex_t minor_fini_mutex;
static int minor_fini_canceled = TRUE;
static int minor_fini_delayed = FALSE;
static cond_t minor_fini_cv;
static int minor_fini_timeout = MINOR_FINI_TIMEOUT_DEFAULT;

/* single-threads /dev modification */
static sema_t dev_sema;

/* the program we were invoked as; ie argv[0] */
static char *prog;

/* pointers to create/remove link lists */
static create_list_t *create_head = NULL;
static remove_list_t *remove_head = NULL;

/*  supports the class -c option */
static char **classes = NULL;
static int num_classes = 0;

/* used with verbose option -v or -V */
static int num_verbose = 0;
static char **verbose = NULL;

static struct mperm *minor_perms = NULL;
static driver_alias_t *driver_aliases = NULL;

/* set if -r alternate root given */
static char *root_dir = "";

/* /devices or <rootdir>/devices */
static char *devices_dir  = DEVICES;

/* /dev or <rootdir>/dev */
static char *dev_dir = DEV;

/* /etc/dev or <rootdir>/etc/dev */
static char *etc_dev_dir = ETCDEV;

/*
 * writable root (for lock files and doors during install).
 * This is also root dir for /dev attr dir during install.
 */
static char *attr_root = NULL;

/* /etc/path_to_inst unless -p used */
static char *inst_file = INSTANCE_FILE;

/* /usr/lib/devfsadm/linkmods unless -l used */
static char *module_dirs = MODULE_DIRS;

/* default uid/gid used if /etc/minor_perm entry not found */
static uid_t root_uid;
static gid_t sys_gid;

/* /etc/devlink.tab unless devlinks -t used */
static char *devlinktab_file = NULL;

/* File and data structure to reserve enumerate IDs */
static char *enumerate_file = ENUMERATE_RESERVED;
static enumerate_file_t *enumerate_reserved = NULL;

/* set if /dev link is new. speeds up rm_stale_links */
static int linknew = TRUE;

/* variables for devlink.tab compat processing */
static devlinktab_list_t *devlinktab_list = NULL;
static unsigned int devlinktab_line = 0;

/* cache head for devfsadm_enumerate*() functions */
static numeral_set_t *head_numeral_set = NULL;

/* list list of devfsadm modules */
static module_t *module_head = NULL;

/* name_to_major list used in utility function */
static n2m_t *n2m_list = NULL;

/* cache of some links used for performance */
static linkhead_t *headlinkhead = NULL;

/* locking variables to prevent multiples writes to /dev */
static int hold_dev_lock = FALSE;
static int hold_daemon_lock = FALSE;
static int dev_lock_fd;
static int daemon_lock_fd;
static char dev_lockfile[PATH_MAX + 1];
static char daemon_lockfile[PATH_MAX + 1];

/* last devinfo node/minor processed. used for performance */
static di_node_t lnode;
static di_minor_t lminor;
static char lphy_path[PATH_MAX + 1] = {""};

/* Globals used by the link database */
static di_devlink_handle_t devlink_cache;
static int update_database = FALSE;

/* Globals used to set logindev perms */
static struct login_dev *login_dev_cache = NULL;
static int login_dev_enable = FALSE;

/* Global to use devinfo snapshot cache */
static int use_snapshot_cache = FALSE;

/* Global for no-further-processing hash */
static item_t **nfp_hash;
static mutex_t  nfp_mutex = DEFAULTMUTEX;

/*
 * Directories not removed even when empty.  They are packaged, or may
 * be referred to from a non-global zone.  The dirs must be listed in
 * canonical form i.e. without leading "/dev/"
 */
static char *sticky_dirs[] =
	{"dsk", "rdsk", "term", "lofi", "rlofi", NULL};

/* Devname globals */
static int lookup_door_fd = -1;
static char *lookup_door_path;

static void load_dev_acl(void);
static void update_drvconf(major_t, int);
static void check_reconfig_state(void);
static int s_stat(const char *, struct stat *);

static int is_blank(char *);

/* sysevent queue related globals */
static mutex_t  syseventq_mutex = DEFAULTMUTEX;
static syseventq_t *syseventq_front;
static syseventq_t *syseventq_back;
static void process_syseventq();

static di_node_t devi_root_node = DI_NODE_NIL;

int
main(int argc, char *argv[])
{
	struct passwd *pw;
	struct group *gp;
	pid_t pid;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if ((prog = strrchr(argv[0], '/')) == NULL) {
		prog = argv[0];
	} else {
		prog++;
	}

	if (getuid() != 0) {
		err_print(MUST_BE_ROOT);
		devfsadm_exit(1);
		/*NOTREACHED*/
	}

	if (getzoneid() != GLOBAL_ZONEID) {
		err_print(MUST_BE_GLOBAL_ZONE);
		devfsadm_exit(1);
	}

	/*
	 * Close all files except stdin/stdout/stderr
	 */
	closefrom(3);

	if ((pw = getpwnam(DEFAULT_DEV_USER)) != NULL) {
		root_uid = pw->pw_uid;
	} else {
		err_print(CANT_FIND_USER, DEFAULT_DEV_USER);
		root_uid = (uid_t)0;	/* assume 0 is root */
	}

	/* the default group is sys */

	if ((gp = getgrnam(DEFAULT_DEV_GROUP)) != NULL) {
		sys_gid = gp->gr_gid;
	} else {
		err_print(CANT_FIND_GROUP, DEFAULT_DEV_GROUP);
		sys_gid = (gid_t)3;	/* assume 3 is sys */
	}

	(void) umask(0);

	system_labeled = is_system_labeled();
	if (system_labeled == FALSE) {
		/*
		 * is_system_labeled() will return false in case we are
		 * starting before the first reboot after Trusted Extensions
		 * is enabled.  Check the setting in /etc/system to see if
		 * TX is enabled (even if not yet booted).
		 */
		if (defopen("/etc/system") == 0) {
			if (defread("set sys_labeling=1") != NULL)
				system_labeled = TRUE;

			/* close defaults file */
			(void) defopen(NULL);
		}
	}
	/*
	 * Check if device allocation is enabled.
	 */
	devalloc_is_on = (da_is_on() == 1) ? 1 : 0;

#ifdef DEBUG
	if (system_labeled == FALSE) {
		struct stat tx_stat;

		/* test hook: see also mkdevalloc.c and allocate.c */
		system_labeled = is_system_labeled_debug(&tx_stat);
	}
#endif

	parse_args(argc, argv);

	(void) sema_init(&dev_sema, 1, USYNC_THREAD, NULL);

	/* Initialize device allocation list */
	devlist.audio = devlist.cd = devlist.floppy = devlist.tape =
	    devlist.rmdisk = NULL;

	if (daemon_mode == TRUE) {
		/*
		 * Build /dev and /devices before daemonizing if
		 * reconfig booting and daemon invoked with alternate
		 * root. This is to support install.
		 */
		if (getenv(RECONFIG_BOOT) != NULL && root_dir[0] != '\0') {
			vprint(INFO_MID, CONFIGURING);
			load_dev_acl();
			update_drvconf((major_t)-1, 0);
			process_devinfo_tree();
			(void) modctl(MODSETMINIROOT);
		}

		/*
		 * fork before detaching from tty in order to print error
		 * message if unable to acquire file lock.  locks not preserved
		 * across forks.  Even under debug we want to fork so that
		 * when executed at boot we don't hang.
		 */
		if (fork() != 0) {
			devfsadm_exit(0);
			/*NOTREACHED*/
		}

		/* set directory to / so it coredumps there */
		if (chdir("/") == -1) {
			err_print(CHROOT_FAILED, strerror(errno));
		}

		/* only one daemon can run at a time */
		if ((pid = enter_daemon_lock()) == getpid()) {
			detachfromtty();
			(void) cond_init(&cv, USYNC_THREAD, 0);
			(void) mutex_init(&count_lock, USYNC_THREAD, 0);
			if (thr_create(NULL, NULL,
			    (void *(*)(void *))instance_flush_thread,
			    NULL, THR_DETACHED, NULL) != 0) {
				err_print(CANT_CREATE_THREAD, "daemon",
				    strerror(errno));
				devfsadm_exit(1);
				/*NOTREACHED*/
			}

			/* start the minor_fini_thread */
			(void) mutex_init(&minor_fini_mutex, USYNC_THREAD, 0);
			(void) cond_init(&minor_fini_cv, USYNC_THREAD, 0);
			if (thr_create(NULL, NULL,
			    (void *(*)(void *))minor_fini_thread,
			    NULL, THR_DETACHED, NULL)) {
				err_print(CANT_CREATE_THREAD, "minor_fini",
				    strerror(errno));
				devfsadm_exit(1);
				/*NOTREACHED*/
			}


			/*
			 * logindevperms need only be set
			 * in daemon mode and when root dir is "/".
			 */
			if (root_dir[0] == '\0')
				login_dev_enable = TRUE;
			daemon_update();
			devfsadm_exit(0);
			/*NOTREACHED*/
		} else {
			err_print(DAEMON_RUNNING, pid);
			devfsadm_exit(1);
			/*NOTREACHED*/
		}
	} else {
		/* not a daemon, so just build /dev and /devices */

		/*
		 * If turning off device allocation, load the
		 * minor_perm file because process_devinfo_tree() will
		 * need this in order to reset the permissions of the
		 * device files.
		 */
		if (devalloc_flag == DA_OFF) {
			read_minor_perm_file();
		}

		process_devinfo_tree();
		if (devalloc_flag != 0)
			/* Enable/disable device allocation */
			_reset_devalloc(devalloc_flag);
	}
	return (0);
}

static void
update_drvconf(major_t major, int flags)
{
	if (modctl(MODLOADDRVCONF, major, flags) != 0)
		err_print(gettext("update_drvconf failed for major %d\n"),
		    major);
}

static void
load_dev_acl()
{
	if (load_devpolicy() != 0)
		err_print(gettext("device policy load failed\n"));
	load_minor_perm_file();
}

/*
 * As devfsadm is run early in boot to provide the kernel with
 * minor_perm info, we might as well check for reconfig at the
 * same time to avoid running devfsadm twice.  This gets invoked
 * earlier than the env variable RECONFIG_BOOT is set up.
 */
static void
check_reconfig_state()
{
	struct stat sb;

	if (s_stat("/reconfigure", &sb) == 0) {
		(void) modctl(MODDEVNAME, MODDEVNAME_RECONFIG, 0);
	}
}

static void
modctl_sysavail()
{
	/*
	 * Inform /dev that system is available, that
	 * implicit reconfig can now be performed.
	 */
	(void) modctl(MODDEVNAME, MODDEVNAME_SYSAVAIL, 0);
}

static void
set_lock_root(void)
{
	struct stat sb;
	char *lock_root;
	size_t len;

	lock_root = attr_root ? attr_root : root_dir;

	len = strlen(lock_root) + strlen(ETCDEV) + 1;
	etc_dev_dir = s_malloc(len);
	(void) snprintf(etc_dev_dir, len, "%s%s", lock_root, ETCDEV);

	if (s_stat(etc_dev_dir, &sb) != 0) {
		s_mkdirp(etc_dev_dir, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
	} else if (!S_ISDIR(sb.st_mode)) {
		err_print(NOT_DIR, etc_dev_dir);
		devfsadm_exit(1);
		/*NOTREACHED*/
	}
}


/*
 * Parse arguments for all 6 programs handled from devfsadm.
 */
static void
parse_args(int argc, char *argv[])
{
	char opt;
	char get_linkcompat_opts = FALSE;
	char *compat_class;
	int num_aliases = 0;
	int len;
	int retval;
	int config = TRUE;
	int bind = FALSE;
	int force_flag = FALSE;
	struct aliases *ap = NULL;
	struct aliases *a_head = NULL;
	struct aliases *a_tail = NULL;
	struct modconfig mc;

	(void) bzero(&mc, sizeof (mc));

	if (strcmp(prog, DISKS) == 0) {
		compat_class = "disk";
		get_linkcompat_opts = TRUE;

	} else if (strcmp(prog, TAPES) == 0) {
		compat_class = "tape";
		get_linkcompat_opts = TRUE;

	} else if (strcmp(prog, PORTS) == 0) {
		compat_class = "port";
		get_linkcompat_opts = TRUE;

	} else if (strcmp(prog, AUDLINKS) == 0) {
		compat_class = "audio";
		get_linkcompat_opts = TRUE;

	} else if (strcmp(prog, DEVLINKS) == 0) {
		devlinktab_file = DEVLINKTAB_FILE;

		build_devices = FALSE;
		load_attach_drv = FALSE;

		while ((opt = getopt(argc, argv, "dnr:st:vV:")) != EOF) {
			switch (opt) {
			case 'd':
				file_mods = FALSE;
				flush_path_to_inst_enable = FALSE;
				devlinks_debug = TRUE;
				break;
			case 'n':
				/* prevent driver loading and deferred attach */
				load_attach_drv = FALSE;
				break;
			case 'r':
				set_root_devices_dev_dir(optarg);
				if (zone_pathcheck(root_dir) !=
				    DEVFSADM_SUCCESS)
					devfsadm_exit(1);
					/*NOTREACHED*/
				break;
			case 's':
				/*
				 * suppress.  don't create/remove links/nodes
				 * useful with -v or -V
				 */
				file_mods = FALSE;
				flush_path_to_inst_enable = FALSE;
				break;
			case 't':
				/* supply a non-default table file */
				devlinktab_file = optarg;
				break;
			case 'v':
				/* documented verbose flag */
				add_verbose_id(VERBOSE_MID);
				break;
			case 'V':
				/* undocumented for extra verbose levels */
				add_verbose_id(optarg);
				break;
			default:
				usage();
				break;
			}
		}

		if (optind < argc) {
			usage();
		}

	} else if (strcmp(prog, DRVCONFIG) == 0) {
		int update_only = 0;
		build_dev = FALSE;

		while ((opt =
		    getopt(argc, argv, "a:bc:dfi:m:np:R:r:suvV:x")) != EOF) {
			switch (opt) {
			case 'a':
				ap = calloc(sizeof (struct aliases), 1);
				ap->a_name = dequote(optarg);
				len = strlen(ap->a_name) + 1;
				if (len > MAXMODCONFNAME) {
					err_print(ALIAS_TOO_LONG,
					    MAXMODCONFNAME, ap->a_name);
					devfsadm_exit(1);
					/*NOTREACHED*/
				}
				ap->a_len = len;
				if (a_tail == NULL) {
					a_head = ap;
				} else {
					a_tail->a_next = ap;
				}
				a_tail = ap;
				num_aliases++;
				bind = TRUE;
				break;
			case 'b':
				bind = TRUE;
				break;
			case 'c':
				(void) strcpy(mc.drvclass, optarg);
				break;
			case 'd':
				/*
				 * need to keep for compatibility, but
				 * do nothing.
				 */
				break;
			case 'f':
				force_flag = TRUE;
				break;
			case 'i':
				single_drv = TRUE;
				(void) strcpy(mc.drvname, optarg);
				driver = s_strdup(optarg);
				break;
			case 'm':
				mc.major = atoi(optarg);
				break;
			case 'n':
				/* prevent driver loading and deferred attach */
				load_attach_drv = FALSE;
				break;
			case 'p':
				/* specify alternate path_to_inst file */
				inst_file = s_strdup(optarg);
				break;
			case 'R':
				/*
				 * Private flag for suninstall to populate
				 * device information on the installed root.
				 */
				root_dir = s_strdup(optarg);
				if (zone_pathcheck(root_dir) !=
				    DEVFSADM_SUCCESS)
				devfsadm_exit(devfsadm_copy());
				/*NOTREACHED*/
				break;
			case 'r':
				devices_dir = s_strdup(optarg);
				if (zone_pathcheck(devices_dir) !=
				    DEVFSADM_SUCCESS)
					devfsadm_exit(1);
					/*NOTREACHED*/
				break;
			case 's':
				/*
				 * suppress.  don't create nodes
				 * useful with -v or -V
				 */
				file_mods = FALSE;
				flush_path_to_inst_enable = FALSE;
				break;
			case 'u':
				/*
				 * Invoked via update_drv(1m) to update
				 * the kernel's driver/alias binding
				 * when removing one or more aliases.
				 */
				config = FALSE;
				break;
			case 'v':
				/* documented verbose flag */
				add_verbose_id(VERBOSE_MID);
				break;
			case 'V':
				/* undocumented for extra verbose levels */
				add_verbose_id(optarg);
				break;
			case 'x':
				update_only = 1;
				break;
			default:
				usage();
			}
		}

		if (optind < argc) {
			usage();
		}

		if (bind == TRUE) {
			if ((mc.major == -1) || (mc.drvname[0] == NULL)) {
				err_print(MAJOR_AND_B_FLAG);
				devfsadm_exit(1);
				/*NOTREACHED*/
			}
			mc.flags = 0;
			if (force_flag)
				mc.flags |= MOD_UNBIND_OVERRIDE;
			if (update_only)
				mc.flags |= MOD_ADDMAJBIND_UPDATE;
			mc.num_aliases = num_aliases;
			mc.ap = a_head;
			retval =  modctl((config == TRUE) ? MODADDMAJBIND :
			    MODREMDRVALIAS, NULL, (caddr_t)&mc);
			if (retval < 0) {
				err_print((config == TRUE) ? MODCTL_ADDMAJBIND :
				    MODCTL_REMMAJBIND);
			}
			devfsadm_exit(retval);
			/*NOTREACHED*/
		}

	} else if ((strcmp(prog, DEVFSADM) == 0) ||
	    (strcmp(prog, DEVFSADMD) == 0)) {
		char *zonename = NULL;
		int init_drvconf = 0;
		int init_perm = 0;
		int public_mode = 0;
		int init_sysavail = 0;

		if (strcmp(prog, DEVFSADMD) == 0) {
			daemon_mode = TRUE;
		}

		devlinktab_file = DEVLINKTAB_FILE;

		while ((opt = getopt(argc, argv,
		    "a:Cc:deIi:l:np:PR:r:sSt:uvV:x:")) != EOF) {
			if (opt == 'I' || opt == 'P' || opt == 'S') {
				if (public_mode)
					usage();
			} else {
				if (init_perm || init_drvconf || init_sysavail)
					usage();
				public_mode = 1;
			}
			switch (opt) {
			case 'a':
				attr_root = s_strdup(optarg);
				break;
			case 'C':
				cleanup = TRUE;
				break;
			case 'c':
				num_classes++;
				classes = s_realloc(classes,
				    num_classes * sizeof (char *));
				classes[num_classes - 1] = optarg;
				break;
			case 'd':
				if (daemon_mode == FALSE) {
					/*
					 * Device allocation to be disabled.
					 */
					devalloc_flag = DA_OFF;
					build_dev = FALSE;
				}
				break;
			case 'e':
				if (daemon_mode == FALSE) {
					/*
					 * Device allocation to be enabled.
					 */
					devalloc_flag = DA_ON;
					build_dev = FALSE;
				}
				break;
			case 'I':	/* update kernel driver.conf cache */
				if (daemon_mode == TRUE)
					usage();
				init_drvconf = 1;
				break;
			case 'i':
				single_drv = TRUE;
				driver = s_strdup(optarg);
				break;
			case 'l':
				/* specify an alternate module load path */
				module_dirs = s_strdup(optarg);
				break;
			case 'n':
				/* prevent driver loading and deferred attach */
				load_attach_drv = FALSE;
				break;
			case 'p':
				/* specify alternate path_to_inst file */
				inst_file = s_strdup(optarg);
				break;
			case 'P':
				if (daemon_mode == TRUE)
					usage();
				/* load minor_perm and device_policy */
				init_perm = 1;
				break;
			case 'R':
				/*
				 * Private flag for suninstall to populate
				 * device information on the installed root.
				 */
				root_dir = s_strdup(optarg);
				devfsadm_exit(devfsadm_copy());
				/*NOTREACHED*/
				break;
			case 'r':
				set_root_devices_dev_dir(optarg);
				break;
			case 's':
				/*
				 * suppress. don't create/remove links/nodes
				 * useful with -v or -V
				 */
				file_mods = FALSE;
				flush_path_to_inst_enable = FALSE;
				break;
			case 'S':
				if (daemon_mode == TRUE)
					usage();
				init_sysavail = 1;
				break;
			case 't':
				devlinktab_file = optarg;
				break;
			case 'u':	/* complete configuration after */
					/* adding a driver update-only */
				if (daemon_mode == TRUE)
					usage();
				update_all_drivers = TRUE;
				break;
			case 'v':
				/* documented verbose flag */
				add_verbose_id(VERBOSE_MID);
				break;
			case 'V':
				/* undocumented: specify verbose lvl */
				add_verbose_id(optarg);
				break;
			case 'x':
				/*
				 * x is the "private switch" option.  The
				 * goal is to not suck up all the other
				 * option letters.
				 */
				if (strcmp(optarg, "update_devlinksdb") == 0) {
					update_database = TRUE;
				} else if (strcmp(optarg, "no_dev") == 0) {
					/* don't build /dev */
					build_dev = FALSE;
				} else if (strcmp(optarg, "no_devices") == 0) {
					/* don't build /devices */
					build_devices = FALSE;
				} else if (strcmp(optarg, "no_p2i") == 0) {
					/* don't flush path_to_inst */
					flush_path_to_inst_enable = FALSE;
				} else if (strcmp(optarg, "use_dicache") == 0) {
					use_snapshot_cache = TRUE;
				} else {
					usage();
				}
				break;
			default:
				usage();
				break;
			}
		}
		if (optind < argc) {
			usage();
		}

		/*
		 * We're not in zone mode; Check to see if the rootpath
		 * collides with any zonepaths.
		 */
		if (zonename == NULL) {
			if (zone_pathcheck(root_dir) != DEVFSADM_SUCCESS)
				devfsadm_exit(1);
				/*NOTREACHED*/
		}

		if (init_drvconf || init_perm || init_sysavail) {
			/*
			 * Load minor perm before force-loading drivers
			 * so the correct permissions are picked up.
			 */
			if (init_perm) {
				check_reconfig_state();
				load_dev_acl();
			}
			if (init_drvconf)
				update_drvconf((major_t)-1, 0);
			if (init_sysavail)
				modctl_sysavail();
			devfsadm_exit(0);
			/*NOTREACHED*/
		}
	}


	if (get_linkcompat_opts == TRUE) {

		build_devices = FALSE;
		load_attach_drv = FALSE;
		num_classes++;
		classes = s_realloc(classes, num_classes *
		    sizeof (char *));
		classes[num_classes - 1] = compat_class;

		while ((opt = getopt(argc, argv, "Cnr:svV:")) != EOF) {
			switch (opt) {
			case 'C':
				cleanup = TRUE;
				break;
			case 'n':
				/* prevent driver loading or deferred attach */
				load_attach_drv = FALSE;
				break;
			case 'r':
				set_root_devices_dev_dir(optarg);
				if (zone_pathcheck(root_dir) !=
				    DEVFSADM_SUCCESS)
					devfsadm_exit(1);
					/*NOTREACHED*/
				break;
			case 's':
				/* suppress.  don't create/remove links/nodes */
				/* useful with -v or -V */
				file_mods = FALSE;
				flush_path_to_inst_enable = FALSE;
				break;
			case 'v':
				/* documented verbose flag */
				add_verbose_id(VERBOSE_MID);
				break;
			case 'V':
				/* undocumented for extra verbose levels */
				add_verbose_id(optarg);
				break;
			default:
				usage();
			}
		}
		if (optind < argc) {
			usage();
		}
	}
	set_lock_root();
}

void
usage(void)
{
	if (strcmp(prog, DEVLINKS) == 0) {
		err_print(DEVLINKS_USAGE);
	} else if (strcmp(prog, DRVCONFIG) == 0) {
		err_print(DRVCONFIG_USAGE);
	} else if ((strcmp(prog, DEVFSADM) == 0) ||
	    (strcmp(prog, DEVFSADMD) == 0)) {
		err_print(DEVFSADM_USAGE);
	} else {
		err_print(COMPAT_LINK_USAGE);
	}

	devfsadm_exit(1);
	/*NOTREACHED*/
}

static void
devi_tree_walk(struct dca_impl *dcip, int flags, char *ev_subclass)
{
	char *msg, *name;
	struct mlist	mlist = {0};
	di_node_t	node;

	vprint(CHATTY_MID, "devi_tree_walk: root=%s, minor=%s, driver=%s,"
	    " error=%d, flags=%u\n", dcip->dci_root,
	    dcip->dci_minor ? dcip->dci_minor : "<NULL>",
	    dcip->dci_driver ? dcip->dci_driver : "<NULL>", dcip->dci_error,
	    dcip->dci_flags);

	assert(dcip->dci_root);

	if (dcip->dci_flags & DCA_LOAD_DRV) {
		node = di_init_driver(dcip->dci_driver, flags);
		msg = DRIVER_FAILURE;
		name = dcip->dci_driver;
	} else {
		node = di_init(dcip->dci_root, flags);
		msg = DI_INIT_FAILED;
		name = dcip->dci_root;
	}

	if (node == DI_NODE_NIL) {
		dcip->dci_error = errno;
		/*
		 * Rapid hotplugging (commonly seen during USB testing),
		 * may remove a device before the create event for it
		 * has been processed. To prevent alarming users with
		 * a superfluous message, we suppress error messages
		 * for ENXIO and hotplug.
		 */
		if (!(errno == ENXIO && (dcip->dci_flags & DCA_HOT_PLUG)))
			err_print(msg, name, strerror(dcip->dci_error));
		return;
	}

	if (dcip->dci_flags & DCA_FLUSH_PATHINST)
		flush_path_to_inst();

	dcip->dci_arg = &mlist;
	devi_root_node = node;	/* protected by lock_dev() */

	vprint(CHATTY_MID, "walking device tree\n");

	(void) di_walk_minor(node, NULL, DI_CHECK_ALIAS, dcip,
	    check_minor_type);

	process_deferred_links(dcip, DCA_CREATE_LINK);

	dcip->dci_arg = NULL;

	/*
	 * Finished creating devfs files and dev links.
	 * Log sysevent.
	 */
	if (ev_subclass)
		build_and_enq_event(EC_DEV_ADD, ev_subclass, dcip->dci_root,
		    node, dcip->dci_minor);

	/* Add new device to device allocation database */
	if (system_labeled && update_devdb) {
		_update_devalloc_db(&devlist, 0, DA_ADD, NULL, root_dir);
		update_devdb = 0;
	}

	devi_root_node = DI_NODE_NIL;	/* protected by lock_dev() */
	di_fini(node);
}

static void
process_deferred_links(struct dca_impl *dcip, int flags)
{
	struct mlist	*dep;
	struct minor	*mp, *smp;

	vprint(CHATTY_MID, "processing deferred links\n");

	dep = dcip->dci_arg;

	/*
	 * The list head is not used during the deferred create phase
	 */
	dcip->dci_arg = NULL;

	assert(dep);
	assert((dep->head == NULL) ^ (dep->tail != NULL));
	assert(flags == DCA_FREE_LIST || flags == DCA_CREATE_LINK);

	for (smp = NULL, mp = dep->head; mp; mp = mp->next) {
		if (flags == DCA_CREATE_LINK)
			(void) check_minor_type(mp->node, mp->minor, dcip);
		free(smp);
		smp = mp;
	}

	free(smp);
}

/*
 * Called in non-daemon mode to take a snap shot of the devinfo tree.
 * Then it calls the appropriate functions to build /devices and /dev.
 * It also flushes path_to_inst.
 * Except in the devfsadm -i (single driver case), the flags used by devfsadm
 * needs to match DI_CACHE_SNAPSHOT_FLAGS. That will make DINFOCACHE snapshot
 * updated.
 */
void
process_devinfo_tree()
{
	uint_t		flags;
	struct dca_impl	dci;
	char		name[MAXNAMELEN];
	char		*fcn = "process_devinfo_tree: ";

	vprint(CHATTY_MID, "%senter\n", fcn);

	dca_impl_init("/", NULL, &dci);

	lock_dev();

	/*
	 * Update kernel driver.conf cache when devfsadm/drvconfig
	 * is invoked to build /devices and /dev.
	 */
	if (update_all_drivers || load_attach_drv) {
		update_drvconf((major_t)-1,
		    update_all_drivers ? MOD_LOADDRVCONF_RECONF : 0);
	}

	if (single_drv == TRUE) {
		/*
		 * load a single driver, but walk the entire devinfo tree
		 */
		if (load_attach_drv == FALSE)
			err_print(DRV_LOAD_REQD);

		vprint(CHATTY_MID, "%sattaching driver (%s)\n", fcn, driver);

		dci.dci_flags |= DCA_LOAD_DRV;
		(void) snprintf(name, sizeof (name), "%s", driver);
		dci.dci_driver = name;
		flags = DINFOCPYALL | DINFOPATH;

	} else if (load_attach_drv == TRUE) {
		/*
		 * Load and attach all drivers, then walk the entire tree.
		 * If the cache flag is set, use DINFOCACHE to get cached
		 * data.
		 */
		if (use_snapshot_cache == TRUE) {
			flags = DINFOCACHE;
			vprint(CHATTY_MID, "%susing snapshot cache\n", fcn);
		} else {
			vprint(CHATTY_MID, "%sattaching all drivers\n", fcn);
			flags = DI_CACHE_SNAPSHOT_FLAGS;
			if (cleanup) {
				/*
				 * remove dangling entries from /etc/devices
				 * files.
				 */
				flags |= DINFOCLEANUP;
			}
		}
	} else {
		/*
		 * For devlinks, disks, ports, tapes and devfsadm -n,
		 * just need to take a snapshot with active devices.
		 */
		vprint(CHATTY_MID, "%staking snapshot of active devices\n",
		    fcn);
		flags = DINFOCPYALL;
	}

	if (((load_attach_drv == TRUE) || (single_drv == TRUE)) &&
	    (build_devices == TRUE)) {
		dci.dci_flags |= DCA_FLUSH_PATHINST;
	}

	/* handle pre-cleanup operations desired by the modules. */
	pre_and_post_cleanup(RM_PRE);

	devi_tree_walk(&dci, flags, NULL);

	if (dci.dci_error) {
		devfsadm_exit(1);
		/*NOTREACHED*/
	}

	/* handle post-cleanup operations desired by the modules. */
	pre_and_post_cleanup(RM_POST);

	unlock_dev(SYNC_STATE);
}

/*ARGSUSED*/
static void
print_cache_signal(int signo)
{
	if (signal(SIGUSR1, print_cache_signal) == SIG_ERR) {
		err_print("signal SIGUSR1 failed: %s\n", strerror(errno));
		devfsadm_exit(1);
		/*NOTREACHED*/
	}
}

static void
revoke_lookup_door(void)
{
	if (lookup_door_fd != -1) {
		if (door_revoke(lookup_door_fd) == -1) {
			err_print("door_revoke of %s failed - %s\n",
			    lookup_door_path, strerror(errno));
		}
	}
}

/*ARGSUSED*/
static void
catch_exit(int signo)
{
	revoke_lookup_door();
}

/*
 * Register with eventd for messages. Create doors for synchronous
 * link creation.
 */
static void
daemon_update(void)
{
	int fd;
	char *fcn = "daemon_update: ";
	char door_file[MAXPATHLEN];
	const char *subclass_list;
	sysevent_handle_t *sysevent_hp;
	vprint(CHATTY_MID, "%senter\n", fcn);

	if (signal(SIGUSR1, print_cache_signal) == SIG_ERR) {
		err_print("signal SIGUSR1 failed: %s\n", strerror(errno));
		devfsadm_exit(1);
		/*NOTREACHED*/
	}
	if (signal(SIGTERM, catch_exit) == SIG_ERR) {
		err_print("signal SIGTERM failed: %s\n", strerror(errno));
		devfsadm_exit(1);
		/*NOTREACHED*/
	}

	if (snprintf(door_file, sizeof (door_file),
	    "%s%s", attr_root ? attr_root : root_dir, DEVFSADM_SERVICE_DOOR)
	    >= sizeof (door_file)) {
		err_print("update_daemon failed to open sysevent service "
		    "door\n");
		devfsadm_exit(1);
		/*NOTREACHED*/
	}
	if ((sysevent_hp = sysevent_open_channel_alt(
	    door_file)) == NULL) {
		err_print(CANT_CREATE_DOOR,
		    door_file, strerror(errno));
		devfsadm_exit(1);
		/*NOTREACHED*/
	}
	if (sysevent_bind_subscriber(sysevent_hp, event_handler) != 0) {
		err_print(CANT_CREATE_DOOR,
		    door_file, strerror(errno));
		(void) sysevent_close_channel(sysevent_hp);
		devfsadm_exit(1);
		/*NOTREACHED*/
	}
	subclass_list = EC_SUB_ALL;
	if (sysevent_register_event(sysevent_hp, EC_ALL, &subclass_list, 1)
	    != 0) {
		err_print(CANT_CREATE_DOOR,
		    door_file, strerror(errno));
		(void) sysevent_unbind_subscriber(sysevent_hp);
		(void) sysevent_close_channel(sysevent_hp);
		devfsadm_exit(1);
		/*NOTREACHED*/
	}
	if (snprintf(door_file, sizeof (door_file), "%s/%s",
	    etc_dev_dir, DEVFSADM_SYNCH_DOOR) >= sizeof (door_file)) {
		err_print(CANT_CREATE_DOOR, DEVFSADM_SYNCH_DOOR,
		    strerror(ENAMETOOLONG));
		devfsadm_exit(1);
		/*NOTREACHED*/
	}

	(void) s_unlink(door_file);
	if ((fd = open(door_file, O_RDWR | O_CREAT, SYNCH_DOOR_PERMS)) == -1) {
		err_print(CANT_CREATE_DOOR, door_file, strerror(errno));
		devfsadm_exit(1);
		/*NOTREACHED*/
	}
	(void) close(fd);

	if ((fd = door_create(sync_handler, NULL,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) == -1) {
		err_print(CANT_CREATE_DOOR, door_file, strerror(errno));
		(void) s_unlink(door_file);
		devfsadm_exit(1);
		/*NOTREACHED*/
	}

	if (fattach(fd, door_file) == -1) {
		err_print(CANT_CREATE_DOOR, door_file, strerror(errno));
		(void) s_unlink(door_file);
		devfsadm_exit(1);
		/*NOTREACHED*/
	}

	/*
	 * devname_lookup_door
	 */
	if (snprintf(door_file, sizeof (door_file), "%s/%s",
	    etc_dev_dir, DEVNAME_LOOKUP_DOOR) >= sizeof (door_file)) {
		err_print(CANT_CREATE_DOOR, DEVNAME_LOOKUP_DOOR,
		    strerror(ENAMETOOLONG));
		devfsadm_exit(1);
		/*NOTREACHED*/
	}

	(void) s_unlink(door_file);
	if ((fd = open(door_file, O_RDWR | O_CREAT, S_IRUSR|S_IWUSR)) == -1) {
		err_print(CANT_CREATE_DOOR, door_file, strerror(errno));
		devfsadm_exit(1);
		/*NOTREACHED*/
	}
	(void) close(fd);

	if ((fd = door_create(devname_lookup_handler, NULL,
	    DOOR_REFUSE_DESC)) == -1) {
		err_print(CANT_CREATE_DOOR, door_file, strerror(errno));
		(void) s_unlink(door_file);
		devfsadm_exit(1);
		/*NOTREACHED*/
	}

	(void) fdetach(door_file);
	lookup_door_path = s_strdup(door_file);
retry:
	if (fattach(fd, door_file) == -1) {
		if (errno == EBUSY)
			goto retry;
		err_print(CANT_CREATE_DOOR, door_file, strerror(errno));
		(void) s_unlink(door_file);
		devfsadm_exit(1);
		/*NOTREACHED*/
	}
	lookup_door_fd = fd;

	/* pass down the door name to kernel for door_ki_open */
	if (devname_kcall(MODDEVNAME_LOOKUPDOOR, (void *)door_file) != 0)
		err_print(DEVNAME_CONTACT_FAILED, strerror(errno));

	vprint(CHATTY_MID, "%spausing\n", fcn);
	for (;;) {
		(void) pause();
	}
}

/*ARGSUSED*/
static void
sync_handler(void *cookie, char *ap, size_t asize,
    door_desc_t *dp, uint_t ndesc)
{
	door_cred_t	dcred;
	struct dca_off	*dcp, rdca;
	struct dca_impl dci;

	/*
	 * Must be root to make this call
	 * If caller is not root, don't touch its data.
	 */
	if (door_cred(&dcred) != 0 || dcred.dc_euid != 0) {
		dcp = &rdca;
		dcp->dca_error = EPERM;
		goto out;
	}

	assert(ap);
	assert(asize == sizeof (*dcp));

	dcp = (void *)ap;

	/*
	 * Root is always present and is the first component of "name" member
	 */
	assert(dcp->dca_root == 0);

	/*
	 * The structure passed in by the door_client uses offsets
	 * instead of pointers to work across address space boundaries.
	 * Now copy the data into a structure (dca_impl) which uses
	 * pointers.
	 */
	dci.dci_root = &dcp->dca_name[dcp->dca_root];
	dci.dci_minor = dcp->dca_minor ? &dcp->dca_name[dcp->dca_minor] : NULL;
	dci.dci_driver =
	    dcp->dca_driver ? &dcp->dca_name[dcp->dca_driver] : NULL;
	dci.dci_error = 0;
	dci.dci_flags = dcp->dca_flags | (dci.dci_driver ? DCA_LOAD_DRV : 0);
	dci.dci_arg = NULL;

	lock_dev();
	devi_tree_walk(&dci, DINFOCPYALL, NULL);
	dcp->dca_error = dci.dci_error;

	if (dcp->dca_flags & DCA_DEVLINK_SYNC)
		unlock_dev(SYNC_STATE);
	else
		unlock_dev(CACHE_STATE);

out:	(void) door_return((char *)dcp, sizeof (*dcp), NULL, 0);
}

static void
lock_dev(void)
{
	vprint(CHATTY_MID, "lock_dev(): entered\n");

	if (build_dev == FALSE)
		return;

	/* lockout other threads from /dev */
	while (sema_wait(&dev_sema) != 0)
		;

	/*
	 * Lock out other devfsadm processes from /dev.
	 * If this wasn't the last process to run,
	 * clear caches
	 */
	if (enter_dev_lock() != getpid()) {
		invalidate_enumerate_cache();
		rm_all_links_from_cache();
		(void) di_devlink_close(&devlink_cache, DI_LINK_ERROR);

		/* send any sysevents that were queued up. */
		process_syseventq();
	}

	/*
	 * (re)load the  reverse links database if not
	 * already cached.
	 */
	if (devlink_cache == NULL)
		devlink_cache = di_devlink_open(root_dir, 0);

	/*
	 * If modules were unloaded, reload them.  Also use module status
	 * as an indication that we should check to see if other binding
	 * files need to be reloaded.
	 */
	if (module_head == NULL) {
		load_modules();
		read_minor_perm_file();
		read_driver_aliases_file();
		read_devlinktab_file();
		read_logindevperm_file();
		read_enumerate_file();
	}

	if (module_head != NULL)
		return;

	if (strcmp(prog, DEVLINKS) == 0) {
		if (devlinktab_list == NULL) {
			err_print(NO_LINKTAB, devlinktab_file);
			err_print(NO_MODULES, module_dirs);
			err_print(ABORTING);
			devfsadm_exit(1);
			/*NOTREACHED*/
		}
	} else {
		err_print(NO_MODULES, module_dirs);
		if (strcmp(prog, DEVFSADM) == 0) {
			err_print(MODIFY_PATH);
		}
	}
}

/*
 * Unlock the device.  If we are processing a CACHE_STATE call, we signal a
 * minor_fini_thread delayed SYNC_STATE at the end of the call.  If we are
 * processing a SYNC_STATE call, we cancel any minor_fini_thread SYNC_STATE
 * at both the start and end of the call since we will be doing the SYNC_STATE.
 */
static void
unlock_dev(int flag)
{
	assert(flag == SYNC_STATE || flag == CACHE_STATE);

	vprint(CHATTY_MID, "unlock_dev(): entered\n");

	/* If we are starting a SYNC_STATE, cancel minor_fini_thread SYNC */
	if (flag == SYNC_STATE) {
		(void) mutex_lock(&minor_fini_mutex);
		minor_fini_canceled = TRUE;
		minor_fini_delayed = FALSE;
		(void) mutex_unlock(&minor_fini_mutex);
	}

	if (build_dev == FALSE)
		return;

	if (devlink_cache == NULL) {
		err_print(NO_DEVLINK_CACHE);
	}
	assert(devlink_cache);

	if (flag == SYNC_STATE) {
		unload_modules();
		if (update_database)
			(void) di_devlink_update(devlink_cache);
		(void) di_devlink_close(&devlink_cache, 0);

		/*
		 * now that the devlinks db cache has been flushed, it is safe
		 * to send any sysevents that were queued up.
		 */
		process_syseventq();
	}

	exit_dev_lock(0);

	(void) mutex_lock(&minor_fini_mutex);
	if (flag == SYNC_STATE) {
		/* We did a SYNC_STATE, cancel minor_fini_thread SYNC */
		minor_fini_canceled = TRUE;
		minor_fini_delayed = FALSE;
	} else {
		/* We did a CACHE_STATE, start delayed minor_fini_thread SYNC */
		minor_fini_canceled = FALSE;
		minor_fini_delayed = TRUE;
		(void) cond_signal(&minor_fini_cv);
	}
	(void) mutex_unlock(&minor_fini_mutex);

	(void) sema_post(&dev_sema);
}

/*
 * Check that if -r is set, it is not any part of a zone--- that is, that
 * the zonepath is not a substring of the root path.
 */
static int
zone_pathcheck(char *checkpath)
{
	void		*dlhdl = NULL;
	char		*name;
	char		root[MAXPATHLEN]; /* resolved devfsadm root path */
	char		zroot[MAXPATHLEN]; /* zone root path */
	char		rzroot[MAXPATHLEN]; /* resolved zone root path */
	char		tmp[MAXPATHLEN];
	FILE		*cookie;
	int		err = DEVFSADM_SUCCESS;

	if (checkpath[0] == '\0')
		return (DEVFSADM_SUCCESS);

	/*
	 * Check if zones is available on this system.
	 */
	if ((dlhdl = dlopen(LIBZONECFG_PATH, RTLD_LAZY)) == NULL) {
		return (DEVFSADM_SUCCESS);
	}

	bzero(root, sizeof (root));
	if (resolvepath(checkpath, root, sizeof (root) - 1) == -1) {
		/*
		 * In this case the user has done "devfsadm -r" on some path
		 * which does not yet exist, or we got some other misc. error.
		 * We punt and don't resolve the path in this case.
		 */
		(void) strlcpy(root, checkpath, sizeof (root));
	}

	if (strlen(root) > 0 && (root[strlen(root) - 1] != '/')) {
		(void) snprintf(tmp, sizeof (tmp), "%s/", root);
		(void) strlcpy(root, tmp, sizeof (root));
	}

	cookie = setzoneent();
	while ((name = getzoneent(cookie)) != NULL) {
		/* Skip the global zone */
		if (strcmp(name, GLOBAL_ZONENAME) == 0) {
			free(name);
			continue;
		}

		if (zone_get_zonepath(name, zroot, sizeof (zroot)) != Z_OK) {
			free(name);
			continue;
		}

		bzero(rzroot, sizeof (rzroot));
		if (resolvepath(zroot, rzroot, sizeof (rzroot) - 1) == -1) {
			/*
			 * Zone path doesn't exist, or other misc error,
			 * so we try using the non-resolved pathname.
			 */
			(void) strlcpy(rzroot, zroot, sizeof (rzroot));
		}
		if (strlen(rzroot) > 0 && (rzroot[strlen(rzroot) - 1] != '/')) {
			(void) snprintf(tmp, sizeof (tmp), "%s/", rzroot);
			(void) strlcpy(rzroot, tmp, sizeof (rzroot));
		}

		/*
		 * Finally, the comparison.  If the zone root path is a
		 * leading substring of the root path, fail.
		 */
		if (strncmp(rzroot, root, strlen(rzroot)) == 0) {
			err_print(ZONE_PATHCHECK, root, name);
			err = DEVFSADM_FAILURE;
			free(name);
			break;
		}
		free(name);
	}
	endzoneent(cookie);
	(void) dlclose(dlhdl);
	return (err);
}

/*
 *  Called by the daemon when it receives an event from the devfsadm SLM
 *  to syseventd.
 *
 *  The devfsadm SLM uses a private event channel for communication to
 *  devfsadmd set-up via private libsysevent interfaces.  This handler is
 *  used to bind to the devfsadmd channel for event delivery.
 *  The devfsadmd SLM insures single calls to this routine as well as
 *  synchronized event delivery.
 *
 */
static void
event_handler(sysevent_t *ev)
{
	char *path;
	char *minor;
	char *subclass;
	char *dev_ev_subclass;
	char *driver_name;
	nvlist_t *attr_list = NULL;
	int err = 0;
	int instance;
	int branch_event = 0;

	/*
	 * If this is event-driven, then we cannot trust the static devlist
	 * to be correct.
	 */

	event_driven = TRUE;
	subclass = sysevent_get_subclass_name(ev);
	vprint(EVENT_MID, "event_handler: %s id:0X%llx\n",
	    subclass, sysevent_get_seq(ev));

	if (strcmp(subclass, ESC_DEVFS_START) == 0) {
		return;
	}

	/* Check if event is an instance modification */
	if (strcmp(subclass, ESC_DEVFS_INSTANCE_MOD) == 0) {
		devfs_instance_mod();
		return;
	}
	if (sysevent_get_attr_list(ev, &attr_list) != 0) {
		vprint(EVENT_MID, "event_handler: can not get attr list\n");
		return;
	}

	if (strcmp(subclass, ESC_DEVFS_DEVI_ADD) == 0 ||
	    strcmp(subclass, ESC_DEVFS_DEVI_REMOVE) == 0 ||
	    strcmp(subclass, ESC_DEVFS_MINOR_CREATE) == 0 ||
	    strcmp(subclass, ESC_DEVFS_MINOR_REMOVE) == 0) {
		if ((err = nvlist_lookup_string(attr_list, DEVFS_PATHNAME,
		    &path)) != 0)
			goto out;

		if (nvlist_lookup_string(attr_list, DEVFS_DEVI_CLASS,
		    &dev_ev_subclass) != 0)
			dev_ev_subclass = NULL;

		if (nvlist_lookup_string(attr_list, DEVFS_DRIVER_NAME,
		    &driver_name) != 0)
			driver_name = NULL;

		if (nvlist_lookup_int32(attr_list, DEVFS_INSTANCE,
		    &instance) != 0)
			instance = -1;

		if (nvlist_lookup_int32(attr_list, DEVFS_BRANCH_EVENT,
		    &branch_event) != 0)
			branch_event = 0;

		if (nvlist_lookup_string(attr_list, DEVFS_MINOR_NAME,
		    &minor) != 0)
			minor = NULL;

		lock_dev();

		if (strcmp(ESC_DEVFS_DEVI_ADD, subclass) == 0) {
			add_minor_pathname(path, NULL, dev_ev_subclass);
			if (branch_event) {
				build_and_enq_event(EC_DEV_BRANCH,
				    ESC_DEV_BRANCH_ADD, path, DI_NODE_NIL,
				    NULL);
			}

		} else if (strcmp(ESC_DEVFS_MINOR_CREATE, subclass) == 0) {
			add_minor_pathname(path, minor, dev_ev_subclass);

		} else if (strcmp(ESC_DEVFS_MINOR_REMOVE, subclass) == 0) {
			hot_cleanup(path, minor, dev_ev_subclass, driver_name,
			    instance);

		} else { /* ESC_DEVFS_DEVI_REMOVE */
			hot_cleanup(path, NULL, dev_ev_subclass,
			    driver_name, instance);
			if (branch_event) {
				build_and_enq_event(EC_DEV_BRANCH,
				    ESC_DEV_BRANCH_REMOVE, path, DI_NODE_NIL,
				    NULL);
			}
		}

		unlock_dev(CACHE_STATE);

	} else if (strcmp(subclass, ESC_DEVFS_BRANCH_ADD) == 0 ||
	    strcmp(subclass, ESC_DEVFS_BRANCH_REMOVE) == 0) {
		if ((err = nvlist_lookup_string(attr_list,
		    DEVFS_PATHNAME, &path)) != 0)
			goto out;

		/* just log ESC_DEV_BRANCH... event */
		if (strcmp(subclass, ESC_DEVFS_BRANCH_ADD) == 0)
			dev_ev_subclass = ESC_DEV_BRANCH_ADD;
		else
			dev_ev_subclass = ESC_DEV_BRANCH_REMOVE;

		lock_dev();
		build_and_enq_event(EC_DEV_BRANCH, dev_ev_subclass, path,
		    DI_NODE_NIL, NULL);
		unlock_dev(CACHE_STATE);
	} else
		err_print(UNKNOWN_EVENT, subclass);

out:
	if (err)
		err_print(EVENT_ATTR_LOOKUP_FAILED, strerror(err));
	nvlist_free(attr_list);
}

static void
dca_impl_init(char *root, char *minor, struct dca_impl *dcip)
{
	assert(root);

	dcip->dci_root = root;
	dcip->dci_minor = minor;
	dcip->dci_driver = NULL;
	dcip->dci_error = 0;
	dcip->dci_flags = 0;
	dcip->dci_arg = NULL;
}

/*
 *  Kernel logs a message when a devinfo node is attached.  Try to create
 *  /dev and /devices for each minor node.  minorname can be NULL.
 */
void
add_minor_pathname(char *node, char *minor, char *ev_subclass)
{
	struct dca_impl	dci;

	vprint(CHATTY_MID, "add_minor_pathname: node_path=%s minor=%s\n",
	    node, minor ? minor : "NULL");

	dca_impl_init(node, minor, &dci);

	/*
	 * Restrict hotplug link creation if daemon
	 * started  with -i option.
	 */
	if (single_drv == TRUE) {
		dci.dci_driver = driver;
	}

	/*
	 * We are being invoked in response to a hotplug event.
	 */
	dci.dci_flags = DCA_HOT_PLUG | DCA_CHECK_TYPE;

	devi_tree_walk(&dci, DINFOPROP|DINFOMINOR, ev_subclass);
}

static di_node_t
find_clone_node()
{
	static di_node_t clone_node = DI_NODE_NIL;

	if (clone_node == DI_NODE_NIL)
		clone_node = di_init("/pseudo/clone@0", DINFOPROP);
	return (clone_node);
}

static int
is_descendent_of(di_node_t node, char *driver)
{
	while (node != DI_NODE_NIL) {
		char *drv = di_driver_name(node);
		if (strcmp(drv, driver) == 0)
			return (1);
		node = di_parent_node(node);
	}
	return (0);
}

/*
 * Checks the minor type.  If it is an alias node, then lookup
 * the real node/minor first, then call minor_process() to
 * do the real work.
 */
static int
check_minor_type(di_node_t node, di_minor_t minor, void *arg)
{
	ddi_minor_type	minor_type;
	di_node_t	clone_node;
	char		*mn;
	char		*nt;
	struct mlist	*dep;
	struct dca_impl	*dcip = arg;

	assert(dcip);

	dep = dcip->dci_arg;

	mn = di_minor_name(minor);

	/*
	 * We match driver here instead of in minor_process
	 * as we want the actual driver name. This check is
	 * unnecessary during deferred processing.
	 */
	if (dep &&
	    ((dcip->dci_driver && !is_descendent_of(node, dcip->dci_driver)) ||
	    (dcip->dci_minor && strcmp(mn, dcip->dci_minor)))) {
		return (DI_WALK_CONTINUE);
	}

	if ((dcip->dci_flags & DCA_CHECK_TYPE) &&
	    (nt = di_minor_nodetype(minor)) &&
	    (strcmp(nt, DDI_NT_NET) == 0)) {
		dcip->dci_flags &= ~DCA_CHECK_TYPE;
	}

	minor_type = di_minor_type(minor);

	if (minor_type == DDM_MINOR) {
		minor_process(node, minor, dep);

	} else if (minor_type == DDM_ALIAS) {
		struct mlist *cdep, clone_del = {0};

		clone_node = find_clone_node();
		if (clone_node == DI_NODE_NIL) {
			err_print(DI_INIT_FAILED, "clone", strerror(errno));
			return (DI_WALK_CONTINUE);
		}

		cdep = dep ? &clone_del : NULL;

		minor_process(clone_node, minor, cdep);

		/*
		 * cache "alias" minor node and free "clone" minor
		 */
		if (cdep != NULL && cdep->head != NULL) {
			assert(cdep->tail != NULL);
			cache_deferred_minor(dep, node, minor);
			dcip->dci_arg = cdep;
			process_deferred_links(dcip, DCA_FREE_LIST);
			dcip->dci_arg = dep;
		}
	}

	return (DI_WALK_CONTINUE);
}


/*
 *  This is the entry point for each minor node, whether walking
 *  the entire tree via di_walk_minor() or processing a hotplug event
 *  for a single devinfo node (via hotplug ndi_devi_online()).
 */
/*ARGSUSED*/
static void
minor_process(di_node_t node, di_minor_t minor, struct mlist *dep)
{
	create_list_t	*create;
	int		defer;

	vprint(CHATTY_MID, "minor_process: node=%s, minor=%s\n",
	    di_node_name(node), di_minor_name(minor));

	if (dep != NULL) {

		/*
		 * Reset /devices node to minor_perm perm/ownership
		 * if we are here to deactivate device allocation
		 */
		if (build_devices == TRUE) {
			reset_node_permissions(node, minor);
		}

		if (build_dev == FALSE) {
			return;
		}

		/*
		 * This function will create any nodes for /etc/devlink.tab.
		 * If devlink.tab handles link creation, we don't call any
		 * devfsadm modules since that could cause duplicate caching
		 * in the enumerate functions if different re strings are
		 * passed that are logically identical.  I'm still not
		 * convinced this would cause any harm, but better to be safe.
		 *
		 * Deferred processing is available only for devlinks
		 * created through devfsadm modules.
		 */
		if (process_devlink_compat(minor, node) == TRUE) {
			return;
		}
	} else {
		vprint(CHATTY_MID, "minor_process: deferred processing\n");
	}

	/*
	 * look for relevant link create rules in the modules, and
	 * invoke the link create callback function to build a link
	 * if there is a match.
	 */
	defer = 0;
	for (create = create_head; create != NULL; create = create->next) {
		if ((minor_matches_rule(node, minor, create) == TRUE) &&
		    class_ok(create->create->device_class) ==
		    DEVFSADM_SUCCESS) {
			if (call_minor_init(create->modptr) ==
			    DEVFSADM_FAILURE) {
				continue;
			}

			/*
			 * If NOT doing the deferred creates (i.e. 1st pass) and
			 * rule requests deferred processing cache the minor
			 * data.
			 *
			 * If deferred processing (2nd pass), create links
			 * ONLY if rule requests deferred processing.
			 */
			if (dep && ((create->create->flags & CREATE_MASK) ==
			    CREATE_DEFER)) {
				defer = 1;
				continue;
			} else if (dep == NULL &&
			    ((create->create->flags & CREATE_MASK) !=
			    CREATE_DEFER)) {
				continue;
			}

			if ((*(create->create->callback_fcn))
			    (minor, node) == DEVFSADM_TERMINATE) {
				break;
			}
		}
	}

	if (defer)
		cache_deferred_minor(dep, node, minor);
}


/*
 * Cache node and minor in defer list.
 */
static void
cache_deferred_minor(
	struct mlist *dep,
	di_node_t node,
	di_minor_t minor)
{
	struct minor	*mp;
	const char	*fcn = "cache_deferred_minor";

	vprint(CHATTY_MID, "%s node=%s, minor=%s\n", fcn,
	    di_node_name(node), di_minor_name(minor));

	if (dep == NULL) {
		vprint(CHATTY_MID, "%s: cannot cache during "
		    "deferred processing. Ignoring minor\n", fcn);
		return;
	}

	mp = (struct minor *)s_zalloc(sizeof (struct minor));
	mp->node = node;
	mp->minor = minor;
	mp->next = NULL;

	assert(dep->head == NULL || dep->tail != NULL);
	if (dep->head == NULL) {
		dep->head = mp;
	} else {
		dep->tail->next = mp;
	}
	dep->tail = mp;
}

/*
 *  Check to see if "create" link creation rule matches this node/minor.
 *  If it does, return TRUE.
 */
static int
minor_matches_rule(di_node_t node, di_minor_t minor, create_list_t *create)
{
	char *m_nodetype, *m_drvname;

	if (create->create->node_type != NULL) {

		m_nodetype = di_minor_nodetype(minor);
		assert(m_nodetype != NULL);

		switch (create->create->flags & TYPE_MASK) {
		case TYPE_EXACT:
			if (strcmp(create->create->node_type, m_nodetype) !=
			    0) {
				return (FALSE);
			}
			break;
		case TYPE_PARTIAL:
			if (strncmp(create->create->node_type, m_nodetype,
			    strlen(create->create->node_type)) != 0) {
				return (FALSE);
			}
			break;
		case TYPE_RE:
			if (regexec(&(create->node_type_comp), m_nodetype,
			    0, NULL, 0) != 0) {
				return (FALSE);
			}
			break;
		}
	}

	if (create->create->drv_name != NULL) {
		m_drvname = di_driver_name(node);
		switch (create->create->flags & DRV_MASK) {
		case DRV_EXACT:
			if (strcmp(create->create->drv_name, m_drvname) != 0) {
				return (FALSE);
			}
			break;
		case DRV_RE:
			if (regexec(&(create->drv_name_comp), m_drvname,
			    0, NULL, 0) != 0) {
				return (FALSE);
			}
			break;
		}
	}

	return (TRUE);
}

/*
 * If no classes were given on the command line, then return DEVFSADM_SUCCESS.
 * Otherwise, return DEVFSADM_SUCCESS if the device "class" from the module
 * matches one of the device classes given on the command line,
 * otherwise, return DEVFSADM_FAILURE.
 */
static int
class_ok(char *class)
{
	int i;

	if (num_classes == 0) {
		return (DEVFSADM_SUCCESS);
	}

	for (i = 0; i < num_classes; i++) {
		if (strcmp(class, classes[i]) == 0) {
			return (DEVFSADM_SUCCESS);
		}
	}
	return (DEVFSADM_FAILURE);
}

/*
 * call minor_fini on active modules, then unload ALL modules
 */
static void
unload_modules(void)
{
	module_t *module_free;
	create_list_t *create_free;
	remove_list_t *remove_free;

	while (create_head != NULL) {
		create_free = create_head;
		create_head = create_head->next;

		if ((create_free->create->flags & TYPE_RE) == TYPE_RE) {
			regfree(&(create_free->node_type_comp));
		}
		if ((create_free->create->flags & DRV_RE) == DRV_RE) {
			regfree(&(create_free->drv_name_comp));
		}
		free(create_free);
	}

	while (remove_head != NULL) {
		remove_free = remove_head;
		remove_head = remove_head->next;
		free(remove_free);
	}

	while (module_head != NULL) {

		if ((module_head->minor_fini != NULL) &&
		    ((module_head->flags & MODULE_ACTIVE) == MODULE_ACTIVE)) {
			(void) (*(module_head->minor_fini))();
		}

		vprint(MODLOAD_MID, "unloading module %s\n", module_head->name);
		free(module_head->name);
		(void) dlclose(module_head->dlhandle);

		module_free = module_head;
		module_head = module_head->next;
		free(module_free);
	}
}

/*
 * Load devfsadm logical link processing modules.
 */
static void
load_modules(void)
{
	DIR *mod_dir;
	struct dirent *entp;
	char cdir[PATH_MAX + 1];
	char *last;
	char *mdir = module_dirs;
	char *fcn = "load_modules: ";

	while (*mdir != '\0') {

		while (*mdir == ':') {
			mdir++;
		}

		if (*mdir == '\0') {
			continue;
		}

		last = strchr(mdir, ':');

		if (last == NULL) {
			last = mdir + strlen(mdir);
		}

		(void) strncpy(cdir, mdir, last - mdir);
		cdir[last - mdir] = '\0';
		mdir += strlen(cdir);

		if ((mod_dir = opendir(cdir)) == NULL) {
			vprint(MODLOAD_MID, "%sopendir(%s): %s\n",
			    fcn, cdir, strerror(errno));
			continue;
		}

		while ((entp = readdir(mod_dir)) != NULL) {

			if ((strcmp(entp->d_name, ".") == 0) ||
			    (strcmp(entp->d_name, "..") == 0)) {
				continue;
			}

			load_module(entp->d_name, cdir);
		}
		s_closedir(mod_dir);
	}
}

static void
load_module(char *mname, char *cdir)
{
	_devfsadm_create_reg_t *create_reg;
	_devfsadm_remove_reg_V1_t *remove_reg;
	create_list_t *create_list_element;
	create_list_t **create_list_next;
	remove_list_t *remove_list_element;
	remove_list_t **remove_list_next;
	char epath[PATH_MAX + 1], *end;
	char *fcn = "load_module: ";
	char *dlerrstr;
	void *dlhandle;
	module_t *module;
	int flags;
	int n;
	int i;

	/* ignore any file which does not end in '.so' */
	if ((end = strstr(mname, MODULE_SUFFIX)) != NULL) {
		if (end[strlen(MODULE_SUFFIX)] != '\0') {
			return;
		}
	} else {
		return;
	}

	(void) snprintf(epath, sizeof (epath), "%s/%s", cdir, mname);

	if ((dlhandle = dlopen(epath, RTLD_LAZY)) == NULL) {
		dlerrstr = dlerror();
		err_print(DLOPEN_FAILED, epath,
		    dlerrstr ? dlerrstr : "unknown error");
		return;
	}

	/* dlsym the _devfsadm_create_reg structure */
	if (NULL == (create_reg = (_devfsadm_create_reg_t *)
	    dlsym(dlhandle, _DEVFSADM_CREATE_REG))) {
		vprint(MODLOAD_MID, "dlsym(%s, %s): symbol not found\n", epath,
		    _DEVFSADM_CREATE_REG);
	} else {
		vprint(MODLOAD_MID, "%sdlsym(%s, %s) succeeded\n",
		    fcn, epath, _DEVFSADM_CREATE_REG);
	}

	/* dlsym the _devfsadm_remove_reg structure */
	if (NULL == (remove_reg = (_devfsadm_remove_reg_V1_t *)
	    dlsym(dlhandle, _DEVFSADM_REMOVE_REG))) {
		vprint(MODLOAD_MID, "dlsym(%s,\n\t%s): symbol not found\n",
		    epath, _DEVFSADM_REMOVE_REG);
	} else {
		vprint(MODLOAD_MID, "dlsym(%s, %s): succeeded\n",
		    epath, _DEVFSADM_REMOVE_REG);
	}

	vprint(MODLOAD_MID, "module %s loaded\n", epath);

	module = (module_t *)s_malloc(sizeof (module_t));
	module->name = s_strdup(epath);
	module->dlhandle = dlhandle;

	/* dlsym other module functions, to be called later */
	module->minor_fini = (int (*)())dlsym(dlhandle, MINOR_FINI);
	module->minor_init = (int (*)())dlsym(dlhandle, MINOR_INIT);
	module->flags = 0;

	/*
	 *  put a ptr to each struct devfsadm_create on "create_head"
	 *  list sorted in interpose_lvl.
	 */
	if (create_reg != NULL) {
		for (i = 0; i < create_reg->count; i++) {
			int flags = create_reg->tblp[i].flags;

			create_list_element = (create_list_t *)
			    s_malloc(sizeof (create_list_t));

			create_list_element->create = &(create_reg->tblp[i]);
			create_list_element->modptr = module;

			if (((flags & CREATE_MASK) != 0) &&
			    ((flags & CREATE_MASK) != CREATE_DEFER)) {
				free(create_list_element);
				err_print("illegal flag combination in "
				    "module create\n");
				err_print(IGNORING_ENTRY, i, epath);
				continue;
			}

			if (((flags & TYPE_MASK) == 0) ^
			    (create_reg->tblp[i].node_type == NULL)) {
				free(create_list_element);
				err_print("flags value incompatible with "
				    "node_type value in module create\n");
				err_print(IGNORING_ENTRY, i, epath);
				continue;
			}

			if (((flags & TYPE_MASK) != 0) &&
			    ((flags & TYPE_MASK) != TYPE_EXACT) &&
			    ((flags & TYPE_MASK) != TYPE_RE) &&
			    ((flags & TYPE_MASK) != TYPE_PARTIAL)) {
				free(create_list_element);
				err_print("illegal TYPE_* flag combination in "
				    "module create\n");
				err_print(IGNORING_ENTRY, i, epath);
				continue;
			}

			/* precompile regular expression for efficiency */
			if ((flags & TYPE_RE) == TYPE_RE) {
				if ((n = regcomp(&(create_list_element->
				    node_type_comp),
				    create_reg->tblp[i].node_type,
				    REG_EXTENDED)) != 0) {
					free(create_list_element);
					err_print(REGCOMP_FAILED,
					    create_reg->tblp[i].node_type, n);
					err_print(IGNORING_ENTRY, i, epath);
					continue;
				}
			}

			if (((flags & DRV_MASK) == 0) ^
			    (create_reg->tblp[i].drv_name == NULL)) {
				if ((flags & TYPE_RE) == TYPE_RE) {
					regfree(&(create_list_element->
					    node_type_comp));
				}
				free(create_list_element);
				err_print("flags value incompatible with "
				    "drv_name value in module create\n");
				err_print(IGNORING_ENTRY, i, epath);
				continue;
			}

			if (((flags & DRV_MASK) != 0) &&
			    ((flags & DRV_MASK) != DRV_EXACT) &&
			    ((flags & DRV_MASK) !=  DRV_RE)) {
				if ((flags & TYPE_RE) == TYPE_RE) {
					regfree(&(create_list_element->
					    node_type_comp));
				}
				free(create_list_element);
				err_print("illegal DRV_* flag combination in "
				    "module create\n");
				err_print(IGNORING_ENTRY, i, epath);
				continue;
			}

			/* precompile regular expression for efficiency */
			if ((create_reg->tblp[i].flags & DRV_RE) == DRV_RE) {
				if ((n = regcomp(&(create_list_element->
				    drv_name_comp),
				    create_reg->tblp[i].drv_name,
				    REG_EXTENDED)) != 0) {
					if ((flags & TYPE_RE) == TYPE_RE) {
						regfree(&(create_list_element->
						    node_type_comp));
					}
					free(create_list_element);
					err_print(REGCOMP_FAILED,
					    create_reg->tblp[i].drv_name, n);
					err_print(IGNORING_ENTRY, i, epath);
					continue;
				}
			}


			/* add to list sorted by interpose level */
			for (create_list_next = &(create_head);
			    (*create_list_next != NULL) &&
			    (*create_list_next)->create->interpose_lvl >=
			    create_list_element->create->interpose_lvl;
			    create_list_next = &((*create_list_next)->next))
				;
			create_list_element->next = *create_list_next;
			*create_list_next = create_list_element;
		}
	}

	/*
	 *  put a ptr to each struct devfsadm_remove on "remove_head"
	 *  list sorted by interpose_lvl.
	 */
	flags = 0;
	if (remove_reg != NULL) {
		if (remove_reg->version < DEVFSADM_V1)
			flags |= RM_NOINTERPOSE;
		for (i = 0; i < remove_reg->count; i++) {

			remove_list_element = (remove_list_t *)
			    s_malloc(sizeof (remove_list_t));

			remove_list_element->remove = &(remove_reg->tblp[i]);
			remove_list_element->remove->flags |= flags;
			remove_list_element->modptr = module;

			for (remove_list_next = &(remove_head);
			    (*remove_list_next != NULL) &&
			    (*remove_list_next)->remove->interpose_lvl >=
			    remove_list_element->remove->interpose_lvl;
			    remove_list_next = &((*remove_list_next)->next))
				;
			remove_list_element->next = *remove_list_next;
			*remove_list_next = remove_list_element;
		}
	}

	module->next = module_head;
	module_head = module;
}

/*
 * After we have completed a CACHE_STATE, if a SYNC_STATE does not occur
 * within 'timeout' secs the minor_fini_thread needs to do a SYNC_STATE
 * so that we still call the minor_fini routines.
 */
/*ARGSUSED*/
static void
minor_fini_thread(void *arg)
{
	timestruc_t	abstime;

	vprint(INITFINI_MID, "minor_fini_thread starting\n");

	(void) mutex_lock(&minor_fini_mutex);
	for (;;) {
		/* wait the gather period, or until signaled */
		abstime.tv_sec = time(NULL) + minor_fini_timeout;
		abstime.tv_nsec = 0;
		(void) cond_timedwait(&minor_fini_cv,
		    &minor_fini_mutex, &abstime);

		/* if minor_fini was canceled, go wait again */
		if (minor_fini_canceled == TRUE)
			continue;

		/* if minor_fini was delayed, go wait again */
		if (minor_fini_delayed == TRUE) {
			minor_fini_delayed = FALSE;
			continue;
		}

		/* done with cancellations and delays, do the SYNC_STATE */
		(void) mutex_unlock(&minor_fini_mutex);

		lock_dev();
		unlock_dev(SYNC_STATE);
		vprint(INITFINI_MID, "minor_fini sync done\n");

		(void) mutex_lock(&minor_fini_mutex);
	}
}


/*
 * Attempt to initialize module, if a minor_init routine exists.  Set
 * the active flag if the routine exists and succeeds.	If it doesn't
 * exist, just set the active flag.
 */
static int
call_minor_init(module_t *module)
{
	char *fcn = "call_minor_init: ";

	if ((module->flags & MODULE_ACTIVE) == MODULE_ACTIVE) {
		return (DEVFSADM_SUCCESS);
	}

	vprint(INITFINI_MID, "%smodule %s.  current state: inactive\n",
	    fcn, module->name);

	if (module->minor_init == NULL) {
		module->flags |= MODULE_ACTIVE;
		vprint(INITFINI_MID, "minor_init not defined\n");
		return (DEVFSADM_SUCCESS);
	}

	if ((*(module->minor_init))() == DEVFSADM_FAILURE) {
		err_print(FAILED_FOR_MODULE, MINOR_INIT, module->name);
		return (DEVFSADM_FAILURE);
	}

	vprint(INITFINI_MID, "minor_init() returns DEVFSADM_SUCCESS. "
	    "new state: active\n");

	module->flags |= MODULE_ACTIVE;
	return (DEVFSADM_SUCCESS);
}

/*
 * Creates a symlink 'link' to the physical path of node:minor.
 * Construct link contents, then call create_link_common().
 */
/*ARGSUSED*/
int
devfsadm_mklink(char *link, di_node_t node, di_minor_t minor, int flags)
{
	char rcontents[PATH_MAX];
	char devlink[PATH_MAX];
	char phy_path[PATH_MAX];
	char *acontents;
	char *dev_path;
	int numslashes;
	int rv;
	int i, link_exists;
	int last_was_slash = FALSE;

	/*
	 * try to use devices path
	 */
	if ((node == lnode) && (minor == lminor)) {
		acontents = lphy_path;
	} else if (di_minor_type(minor) == DDM_ALIAS) {
		/* use /pseudo/clone@0:<driver> as the phys path */
		(void) snprintf(phy_path, sizeof (phy_path),
		    "/pseudo/clone@0:%s",
		    di_driver_name(di_minor_devinfo(minor)));
		acontents = phy_path;
	} else {
		if ((dev_path = di_devfs_path(node)) == NULL) {
			err_print(DI_DEVFS_PATH_FAILED, strerror(errno));
			devfsadm_exit(1);
			/*NOTREACHED*/
		}
		(void) snprintf(phy_path, sizeof (phy_path), "%s:%s",
		    dev_path, di_minor_name(minor));
		di_devfs_path_free(dev_path);
		acontents = phy_path;
	}

	/* prepend link with dev_dir contents */
	(void) strlcpy(devlink, dev_dir, sizeof (devlink));
	(void) strlcat(devlink, "/", sizeof (devlink));
	(void) strlcat(devlink, link, sizeof (devlink));

	/*
	 * Calculate # of ../ to add.  Account for double '//' in path.
	 * Ignore all leading slashes.
	 */
	for (i = 0; link[i] == '/'; i++)
		;
	for (numslashes = 0; link[i] != '\0'; i++) {
		if (link[i] == '/') {
			if (last_was_slash == FALSE) {
				numslashes++;
				last_was_slash = TRUE;
			}
		} else {
			last_was_slash = FALSE;
		}
	}
	/* Don't count any trailing '/' */
	if (link[i-1] == '/') {
		numslashes--;
	}

	rcontents[0] = '\0';
	do {
		(void) strlcat(rcontents, "../", sizeof (rcontents));
	} while (numslashes-- != 0);

	(void) strlcat(rcontents, "devices", sizeof (rcontents));
	(void) strlcat(rcontents, acontents, sizeof (rcontents));

	if (devlinks_debug == TRUE) {
		vprint(INFO_MID, "adding link %s ==> %s\n", devlink, rcontents);
	}

	if ((rv = create_link_common(devlink, rcontents, &link_exists))
	    == DEVFSADM_SUCCESS) {
		linknew = TRUE;
		add_link_to_cache(link, acontents);
	} else {
		linknew = FALSE;
	}

	if (link_exists == TRUE) {
		/* Link exists or was just created */
		(void) di_devlink_add_link(devlink_cache, link, rcontents,
		    DI_PRIMARY_LINK);

		if (system_labeled && (flags & DA_ADD)) {
			/*
			 * Add this to the list of allocatable devices. If this
			 * is a hotplugged, removable disk, add it as rmdisk.
			 */
			int instance = di_instance(node);

			if ((flags & DA_CD) &&
			    (_da_check_for_usb(devlink, root_dir) == 1)) {
				(void) da_add_list(&devlist, devlink, instance,
				    DA_ADD|DA_RMDISK);
				update_devdb = DA_RMDISK;
			} else if (linknew == TRUE) {
				(void) da_add_list(&devlist, devlink, instance,
				    flags);
				update_devdb = flags;
			}
		}
	}

	return (rv);
}

/*
 * Creates a symlink link to primary_link.  Calculates relative
 * directory offsets, then calls link_common().
 */
/*ARGSUSED*/
int
devfsadm_secondary_link(char *link, char *primary_link, int flags)
{
	char contents[PATH_MAX + 1];
	char devlink[PATH_MAX + 1];
	int rv, link_exists;
	char *fpath;
	char *tpath;
	char *op;

	/* prepend link with dev_dir contents */
	(void) strcpy(devlink, dev_dir);
	(void) strcat(devlink, "/");
	(void) strcat(devlink, link);
	/*
	 * building extra link, so use first link as link contents, but first
	 * make it relative.
	 */
	fpath = link;
	tpath = primary_link;
	op = contents;

	while (*fpath == *tpath && *fpath != '\0') {
		fpath++, tpath++;
	}

	/* Count directories to go up, if any, and add "../" */
	while (*fpath != '\0') {
		if (*fpath == '/') {
			(void) strcpy(op, "../");
			op += 3;
		}
		fpath++;
	}

	/*
	 * Back up to the start of the current path component, in
	 * case in the middle
	 */
	while (tpath != primary_link && *(tpath-1) != '/') {
		tpath--;
	}
	(void) strcpy(op, tpath);

	if (devlinks_debug == TRUE) {
		vprint(INFO_MID, "adding extra link %s ==> %s\n",
		    devlink, contents);
	}

	if ((rv = create_link_common(devlink, contents, &link_exists))
	    == DEVFSADM_SUCCESS) {
		/*
		 * we need to save the ultimate /devices contents, and not the
		 * secondary link, since hotcleanup only looks at /devices path.
		 * Since we don't have devices path here, we can try to get it
		 * by readlink'ing the secondary link.  This assumes the primary
		 * link was created first.
		 */
		add_link_to_cache(link, lphy_path);
		linknew = TRUE;
		if (system_labeled &&
		    ((flags & DA_AUDIO) && (flags & DA_ADD))) {
			/*
			 * Add this device to the list of allocatable devices.
			 */
			int	instance = 0;

			op = strrchr(contents, '/');
			op++;
			(void) sscanf(op, "%d", &instance);
			(void) da_add_list(&devlist, devlink, instance, flags);
			update_devdb = flags;
		}
	} else {
		linknew = FALSE;
	}

	/*
	 * If link exists or was just created, add it to the database
	 */
	if (link_exists == TRUE) {
		(void) di_devlink_add_link(devlink_cache, link, contents,
		    DI_SECONDARY_LINK);
	}

	return (rv);
}

/* returns pointer to the devices directory */
char *
devfsadm_get_devices_dir()
{
	return (devices_dir);
}

/*
 * Does the actual link creation.  VERBOSE_MID only used if there is
 * a change.  CHATTY_MID used otherwise.
 */
static int
create_link_common(char *devlink, char *contents, int *exists)
{
	int try;
	int linksize;
	int max_tries = 0;
	static int prev_link_existed = TRUE;
	char checkcontents[PATH_MAX + 1];
	char *hide;

	*exists = FALSE;

	/* Database is not updated when file_mods == FALSE */
	if (file_mods == FALSE) {
		/* we want *actual* link contents so no alias redirection */
		linksize = readlink(devlink, checkcontents, PATH_MAX);
		if (linksize > 0) {
			checkcontents[linksize] = '\0';
			if (strcmp(checkcontents, contents) != 0) {
				vprint(CHATTY_MID, REMOVING_LINK,
				    devlink, checkcontents);
				return (DEVFSADM_SUCCESS);
			} else {
				vprint(CHATTY_MID, "link exists and is correct:"
				    " %s -> %s\n", devlink, contents);
				/* failure only in that the link existed */
				return (DEVFSADM_FAILURE);
			}
		} else {
			vprint(VERBOSE_MID, CREATING_LINK, devlink, contents);
			return (DEVFSADM_SUCCESS);
		}
	}

	/*
	 * systems calls are expensive, so predict whether to readlink
	 * or symlink first, based on previous attempt
	 */
	if (prev_link_existed == FALSE) {
		try = CREATE_LINK;
	} else {
		try = READ_LINK;
	}

	while (++max_tries <= 3) {

		switch (try) {
		case  CREATE_LINK:

			if (symlink(contents, devlink) == 0) {
				vprint(VERBOSE_MID, CREATING_LINK, devlink,
				    contents);
				prev_link_existed = FALSE;
				/* link successfully created */
				*exists = TRUE;
				set_logindev_perms(devlink);
				return (DEVFSADM_SUCCESS);
			} else {
				switch (errno) {

				case ENOENT:
					/* dirpath to node doesn't exist */
					hide = strrchr(devlink, '/');
					*hide = '\0';
					s_mkdirp(devlink, S_IRWXU|S_IRGRP|
					    S_IXGRP|S_IROTH|S_IXOTH);
					*hide = '/';
					break;
				case EEXIST:
					try = READ_LINK;
					break;
				default:
					err_print(SYMLINK_FAILED, devlink,
					    contents, strerror(errno));
					return (DEVFSADM_FAILURE);
				}
			}
			break;

		case READ_LINK:

			/*
			 * If there is redirection, new phys path
			 * and old phys path will not match and the
			 * link will be created with new phys path
			 * which is what we want. So we want real
			 * contents.
			 */
			linksize = readlink(devlink, checkcontents, PATH_MAX);
			if (linksize >= 0) {
				checkcontents[linksize] = '\0';
				if (strcmp(checkcontents, contents) != 0) {
					s_unlink(devlink);
					vprint(VERBOSE_MID, REMOVING_LINK,
					    devlink, checkcontents);
					try = CREATE_LINK;
				} else {
					prev_link_existed = TRUE;
					vprint(CHATTY_MID,
					    "link exists and is correct:"
					    " %s -> %s\n", devlink, contents);
					*exists = TRUE;
					/* failure in that the link existed */
					return (DEVFSADM_FAILURE);
				}
			} else {
				switch (errno) {
				case EINVAL:
					/* not a symlink, remove and create */
					s_unlink(devlink);
					/* FALLTHROUGH */
				default:
					/* maybe it didn't exist at all */
					try = CREATE_LINK;
					break;
				}
			}
			break;
		}
	}
	err_print(MAX_ATTEMPTS, devlink, contents);
	return (DEVFSADM_FAILURE);
}

static void
set_logindev_perms(char *devlink)
{
	struct login_dev *newdev;
	struct passwd pwd, *resp;
	char pwd_buf[PATH_MAX];
	int rv;
	struct stat sb;
	char *devfs_path = NULL;

	/*
	 * We only want logindev perms to be set when a device is
	 * hotplugged or an application requests synchronous creates.
	 * So we enable this only in daemon mode. In addition,
	 * login(1) only fixes the std. /dev dir. So we don't
	 * change perms if alternate root is set.
	 * login_dev_enable is TRUE only in these cases.
	 */
	if (login_dev_enable != TRUE)
		return;

	/*
	 * Normally, /etc/logindevperm has few (8 - 10 entries) which
	 * may be regular expressions (globs were converted to RE).
	 * So just do a linear search through the list.
	 */
	for (newdev = login_dev_cache; newdev; newdev = newdev->ldev_next) {
		vprint(FILES_MID, "matching %s with %s\n", devlink,
		    newdev->ldev_device);

		if (regexec(&newdev->ldev_device_regex, devlink, 0,
		    NULL, 0) == 0)  {
			vprint(FILES_MID, "matched %s with %s\n", devlink,
			    newdev->ldev_device);
			break;
		}
	}

	if (newdev == NULL)
		return;

	/*
	 * we have a match, now find the driver associated with this
	 * minor node using a snapshot on the physical path
	 */
	(void) resolve_link(devlink, NULL, NULL, &devfs_path, 0);
	/*
	 * We dont need redirection here - the actual link contents
	 * whether "alias" or "current" are fine
	 */
	if (devfs_path) {
		di_node_t node;
		char *drv;
		struct driver_list *list;
		char *p;

		/* truncate on : so we can take a snapshot */
		(void) strcpy(pwd_buf, devfs_path);
		p = strrchr(pwd_buf, ':');
		if (p == NULL) {
			free(devfs_path);
			return;
		}
		*p = '\0';

		vprint(FILES_MID, "link=%s->physpath=%s\n",
		    devlink, pwd_buf);

		node = di_init(pwd_buf, DINFOMINOR);

		drv = NULL;
		if (node) {
			drv = di_driver_name(node);

			if (drv) {
				vprint(FILES_MID, "%s: driver is %s\n",
				    devlink, drv);
			}
		}
		/* search thru the driver list specified in logindevperm */
		list = newdev->ldev_driver_list;
		if ((drv != NULL) && (list != NULL)) {
			while (list) {
				if (strcmp(list->driver_name,
				    drv) == 0) {
					vprint(FILES_MID,
					    "driver %s match!\n", drv);
					break;
				}
				list = list->next;
			}
			if (list == NULL) {
				vprint(FILES_MID, "no driver match!\n");
				free(devfs_path);
				return;
			}
		}
		free(devfs_path);
		di_fini(node);
	} else {
		return;
	}

	vprint(FILES_MID, "changing permissions of %s\n", devlink);

	/*
	 * We have a match. We now attempt to determine the
	 * owner and group of the console user.
	 *
	 * stat() the console device newdev->ldev_console
	 * which will always exist - it will have the right owner but
	 * not the right group. Use getpwuid_r() to determine group for this
	 * uid.
	 * Note, it is safe to use name service here since if name services
	 * are not available (during boot or in single-user mode), then
	 * console owner will be root and its gid can be found in
	 * local files.
	 */
	if (stat(newdev->ldev_console, &sb) == -1) {
		vprint(VERBOSE_MID, STAT_FAILED, newdev->ldev_console,
		    strerror(errno));
		return;
	}

	resp = NULL;
	rv = getpwuid_r(sb.st_uid, &pwd, pwd_buf, sizeof (pwd_buf), &resp);
	if (rv || resp == NULL) {
		rv = rv ? rv : EINVAL;
		vprint(VERBOSE_MID, GID_FAILED, sb.st_uid,
		    strerror(rv));
		return;
	}

	assert(&pwd == resp);

	sb.st_gid = resp->pw_gid;

	if (chmod(devlink, newdev->ldev_perms) == -1) {
		vprint(VERBOSE_MID, CHMOD_FAILED, devlink,
		    strerror(errno));
		return;
	}

	if (chown(devlink, sb.st_uid, sb.st_gid)  == -1) {
		vprint(VERBOSE_MID, CHOWN_FAILED, devlink,
		    strerror(errno));
	}
}

/*
 * Reset /devices node with appropriate permissions and
 * ownership as specified in /etc/minor_perm.
 */
static void
reset_node_permissions(di_node_t node, di_minor_t minor)
{
	int spectype;
	char phy_path[PATH_MAX + 1];
	mode_t mode;
	dev_t dev;
	uid_t uid;
	gid_t gid;
	struct stat sb;
	char *dev_path, *aminor = NULL;

	/* lphy_path starts with / */
	if ((dev_path = di_devfs_path(node)) == NULL) {
		err_print(DI_DEVFS_PATH_FAILED, strerror(errno));
		devfsadm_exit(1);
		/*NOTREACHED*/
	}
	(void) strcpy(lphy_path, dev_path);
	di_devfs_path_free(dev_path);

	(void) strcat(lphy_path, ":");
	if (di_minor_type(minor) == DDM_ALIAS) {
		char *driver;
		aminor = di_minor_name(minor);
		driver = di_driver_name(di_minor_devinfo(minor));
		(void) strcat(lphy_path, driver);
	} else
		(void) strcat(lphy_path, di_minor_name(minor));

	(void) strcpy(phy_path, devices_dir);
	(void) strcat(phy_path, lphy_path);

	lnode = node;
	lminor = minor;

	vprint(CHATTY_MID, "reset_node_permissions: phy_path=%s lphy_path=%s\n",
	    phy_path, lphy_path);

	dev = di_minor_devt(minor);
	spectype = di_minor_spectype(minor); /* block or char */

	getattr(phy_path, aminor, spectype, dev, &mode, &uid, &gid);

	/*
	 * compare and set permissions and ownership
	 *
	 * Under devfs, a quick insertion and removal of USB devices
	 * would cause stat of physical path to fail. In this case,
	 * we emit a verbose message, but don't print errors.
	 */
	if ((stat(phy_path, &sb) == -1) || (sb.st_rdev != dev)) {
		vprint(VERBOSE_MID, NO_DEVFS_NODE, phy_path);
		return;
	}

	/*
	 * If we are here for a new device
	 *	If device allocation is on
	 *	then
	 *		set ownership to root:other and permissions to 0000
	 *	else
	 *		set ownership and permissions as specified in minor_perm
	 * If we are here for an existing device
	 *	If device allocation is to be turned on
	 *	then
	 *		reset ownership to root:other and permissions to 0000
	 *	else if device allocation is to be turned off
	 *		reset ownership and permissions to those specified in
	 *		minor_perm
	 *	else
	 *		preserve existing/user-modified ownership and
	 *		permissions
	 *
	 * devfs indicates a new device by faking access time to be zero.
	 */
	if (sb.st_atime != 0) {
		int  i;
		char *nt;

		if ((devalloc_flag == 0) && (devalloc_is_on != 1))
			/*
			 * Leave existing devices as they are if we are not
			 * turning device allocation on/off.
			 */
			return;

		nt = di_minor_nodetype(minor);

		if (nt == NULL)
			return;

		for (i = 0; devalloc_list[i]; i++) {
			if (strcmp(nt, devalloc_list[i]) == 0)
				/*
				 * One of the types recognized by devalloc,
				 * reset attrs.
				 */
				break;
		}
		if (devalloc_list[i] == NULL)
			return;
	}

	if (file_mods == FALSE) {
		/* Nothing more to do if simulating */
		vprint(VERBOSE_MID, PERM_MSG, phy_path, uid, gid, mode);
		return;
	}

	if ((devalloc_flag == DA_ON) ||
	    ((devalloc_is_on == 1) && (devalloc_flag != DA_OFF))) {
		/*
		 * we are here either to turn device allocation on or
		 * to add a new device while device allocation is on
		 * (and we've confirmed that we're not turning it
		 * off).
		 */
		mode = DEALLOC_MODE;
		uid = DA_UID;
		gid = DA_GID;
	}

	if ((devalloc_is_on == 1) || (devalloc_flag == DA_ON) ||
	    (sb.st_mode != mode)) {
		if (chmod(phy_path, mode) == -1)
			vprint(VERBOSE_MID, CHMOD_FAILED,
			    phy_path, strerror(errno));
	}
	if ((devalloc_is_on == 1) || (devalloc_flag == DA_ON) ||
	    (sb.st_uid != uid || sb.st_gid != gid)) {
		if (chown(phy_path, uid, gid) == -1)
			vprint(VERBOSE_MID, CHOWN_FAILED,
			    phy_path, strerror(errno));
	}

	/* Report that we actually did something */
	vprint(VERBOSE_MID, PERM_MSG, phy_path, uid, gid, mode);
}

/*
 * Removes logical link and the minor node it refers to.  If file is a
 * link, we recurse and try to remove the minor node (or link if path is
 * a double link) that file's link contents refer to.
 */
static void
devfsadm_rm_work(char *file, int recurse, int file_type)
{
	char *fcn = "devfsadm_rm_work: ";
	int linksize;
	char contents[PATH_MAX + 1];
	char nextfile[PATH_MAX + 1];
	char newfile[PATH_MAX + 1];
	char *ptr;

	vprint(REMOVE_MID, "%s%s\n", fcn, file);

	/*
	 * Note: we don't remove /devices (non-links) entries because they are
	 *	covered by devfs.
	 */
	if (file_type != TYPE_LINK) {
		return;
	}

	/* split into multiple if's due to excessive indentations */
	(void) strcpy(newfile, dev_dir);
	(void) strcat(newfile, "/");
	(void) strcat(newfile, file);

	/*
	 * we dont care about the content of the symlink, so
	 * redirection is not needed.
	 */
	if ((recurse == TRUE) &&
	    ((linksize = readlink(newfile, contents, PATH_MAX)) > 0)) {
		contents[linksize] = '\0';

		/*
		 * recurse if link points to another link
		 */
		if (is_minor_node(contents, &ptr) != DEVFSADM_TRUE) {
			if (strncmp(contents, DEV "/", strlen(DEV) + 1) == 0) {
				devfsadm_rm_work(&contents[strlen(DEV) + 1],
				    TRUE, TYPE_LINK);
			} else {
				if ((ptr = strrchr(file, '/')) != NULL) {
					*ptr = '\0';
					(void) strcpy(nextfile, file);
					*ptr = '/';
					(void) strcat(nextfile, "/");
				} else {
					(void) strcpy(nextfile, "");
				}
				(void) strcat(nextfile, contents);
				devfsadm_rm_work(nextfile, TRUE, TYPE_LINK);
			}
		}
	}

	vprint(VERBOSE_MID, DEVFSADM_UNLINK, newfile);
	if (file_mods == TRUE) {
		rm_link_from_cache(file);
		s_unlink(newfile);
		rm_parent_dir_if_empty(newfile);
		invalidate_enumerate_cache();
		(void) di_devlink_rm_link(devlink_cache, file);
	}
}

void
devfsadm_rm_link(char *file)
{
	devfsadm_rm_work(file, FALSE, TYPE_LINK);
}

void
devfsadm_rm_all(char *file)
{
	devfsadm_rm_work(file, TRUE, TYPE_LINK);
}

static int
s_rmdir(char *path)
{
	int	i;
	char	*rpath, *dir;
	const char *fcn = "s_rmdir";

	/*
	 * Certain directories are created at install time by packages.
	 * Some of them (listed in sticky_dirs[]) are required by apps
	 * and need to be present even when empty.
	 */
	vprint(REMOVE_MID, "%s: checking if %s is sticky\n", fcn, path);

	rpath = path + strlen(dev_dir) + 1;

	for (i = 0; (dir = sticky_dirs[i]) != NULL; i++) {
		if (*rpath == *dir) {
			if (strcmp(rpath, dir) == 0) {
				vprint(REMOVE_MID, "%s: skipping sticky dir: "
				    "%s\n", fcn, path);
				errno = EEXIST;
				return (-1);
			}
		}
	}

	return (rmdir(path));
}

/*
 * Try to remove any empty directories up the tree.  It is assumed that
 * pathname is a file that was removed, so start with its parent, and
 * work up the tree.
 */
static void
rm_parent_dir_if_empty(char *pathname)
{
	char *ptr, path[PATH_MAX + 1];
	char *fcn = "rm_parent_dir_if_empty: ";

	vprint(REMOVE_MID, "%schecking %s if empty\n", fcn, pathname);

	(void) strcpy(path, pathname);

	/*
	 * ascend up the dir tree, deleting all empty dirs.
	 * Return immediately if a dir is not empty.
	 */
	for (;;) {

		if ((ptr = strrchr(path, '/')) == NULL) {
			return;
		}

		*ptr = '\0';

		if (finddev_emptydir(path)) {
			/* directory is empty */
			if (s_rmdir(path) == 0) {
				vprint(REMOVE_MID,
				    "%sremoving empty dir %s\n", fcn, path);
			} else if (errno == EEXIST) {
				vprint(REMOVE_MID,
				    "%sfailed to remove dir: %s\n", fcn, path);
				return;
			}
		} else {
			/* some other file is here, so return */
			vprint(REMOVE_MID, "%sdir not empty: %s\n", fcn, path);
			return;
		}
	}
}

/*
 * This function and all the functions it calls below were added to
 * handle the unique problem with world wide names (WWN).  The problem is
 * that if a WWN device is moved to another address on the same controller
 * its logical link will change, while the physical node remains the same.
 * The result is that two logical links will point to the same physical path
 * in /devices, the valid link and a stale link. This function will
 * find all the stale nodes, though at a significant performance cost.
 *
 * Caching is used to increase performance.
 * A cache will be built from disk if the cache tag doesn't already exist.
 * The cache tag is a regular expression "dir_re", which selects a
 * subset of disks to search from typically something like
 * "dev/cXt[0-9]+d[0-9]+s[0-9]+".  After the cache is built, consistency must
 * be maintained, so entries are added as new links are created, and removed
 * as old links are deleted.  The whole cache is flushed if we are a daemon,
 * and another devfsadm process ran in between.
 *
 * Once the cache is built, this function finds the cache which matches
 * dir_re, and then it searches all links in that cache looking for
 * any link whose contents match "valid_link_contents" with a corresponding link
 * which does not match "valid_link".  Any such matches are stale and removed.
 *
 * This happens outside the context of a "reparenting" so we dont need
 * redirection.
 */
void
devfsadm_rm_stale_links(char *dir_re, char *valid_link, di_node_t node,
    di_minor_t minor)
{
	link_t *link;
	linkhead_t *head;
	char phy_path[PATH_MAX + 1];
	char *valid_link_contents;
	char *dev_path;
	char rmlink[PATH_MAX + 1];

	/*
	 * try to use devices path
	 */
	if ((node == lnode) && (minor == lminor)) {
		valid_link_contents = lphy_path;
	} else {
		if ((dev_path = di_devfs_path(node)) == NULL) {
			err_print(DI_DEVFS_PATH_FAILED, strerror(errno));
			devfsadm_exit(1);
			/*NOTREACHED*/
		}
		(void) strcpy(phy_path, dev_path);
		di_devfs_path_free(dev_path);

		(void) strcat(phy_path, ":");
		(void) strcat(phy_path, di_minor_name(minor));
		valid_link_contents = phy_path;
	}

	/*
	 * As an optimization, check to make sure the corresponding
	 * devlink was just created before continuing.
	 */

	if (linknew == FALSE) {
		return;
	}

	head = get_cached_links(dir_re);

	assert(head->nextlink == NULL);

	for (link = head->link; link != NULL; link = head->nextlink) {
		/*
		 * See hot_cleanup() for why we do this
		 */
		head->nextlink = link->next;
		if ((strcmp(link->contents, valid_link_contents) == 0) &&
		    (strcmp(link->devlink, valid_link) != 0)) {
			vprint(CHATTY_MID, "removing %s -> %s\n"
			    "valid link is: %s -> %s\n",
			    link->devlink, link->contents,
			    valid_link, valid_link_contents);
			/*
			 * Use a copy of the cached link name as the
			 * cache entry will go away during link removal
			 */
			(void) snprintf(rmlink, sizeof (rmlink), "%s",
			    link->devlink);
			devfsadm_rm_link(rmlink);
		}
	}
}

/*
 * Return previously created cache, or create cache.
 */
static linkhead_t *
get_cached_links(char *dir_re)
{
	recurse_dev_t rd;
	linkhead_t *linkhead;
	int n;

	vprint(BUILDCACHE_MID, "get_cached_links: %s\n", dir_re);

	for (linkhead = headlinkhead; linkhead != NULL;
	    linkhead = linkhead->nexthead) {
		if (strcmp(linkhead->dir_re, dir_re) == 0) {
			return (linkhead);
		}
	}

	/*
	 * This tag is not in cache, so add it, along with all its
	 * matching /dev entries.  This is the only time we go to disk.
	 */
	linkhead = s_malloc(sizeof (linkhead_t));
	linkhead->nexthead = headlinkhead;
	headlinkhead = linkhead;
	linkhead->dir_re = s_strdup(dir_re);

	if ((n = regcomp(&(linkhead->dir_re_compiled), dir_re,
	    REG_EXTENDED)) != 0) {
		err_print(REGCOMP_FAILED,  dir_re, n);
	}

	linkhead->nextlink = NULL;
	linkhead->link = NULL;

	rd.fcn = build_devlink_list;
	rd.data = (void *)linkhead;

	vprint(BUILDCACHE_MID, "get_cached_links: calling recurse_dev_re\n");

	/* call build_devlink_list for each directory in the dir_re RE */
	if (dir_re[0] == '/') {
		recurse_dev_re("/", &dir_re[1], &rd);
	} else {
		recurse_dev_re(dev_dir, dir_re, &rd);
	}

	return (linkhead);
}

static void
build_devlink_list(char *devlink, void *data)
{
	char *fcn = "build_devlink_list: ";
	char *ptr;
	char *r_contents;
	char *r_devlink;
	char contents[PATH_MAX + 1];
	char newlink[PATH_MAX + 1];
	char stage_link[PATH_MAX + 1];
	int linksize;
	linkhead_t *linkhead = (linkhead_t *)data;
	link_t *link;
	int i = 0;

	vprint(BUILDCACHE_MID, "%scheck_link: %s\n", fcn, devlink);

	(void) strcpy(newlink, devlink);

	do {
		/*
		 * None of the consumers of this function need redirection
		 * so this readlink gets the "current" contents
		 */
		linksize = readlink(newlink, contents, PATH_MAX);
		if (linksize <= 0) {
			/*
			 * The first pass through the do loop we may readlink()
			 * non-symlink files(EINVAL) from false regexec matches.
			 * Suppress error messages in those cases or if the link
			 * content is the empty string.
			 */
			if (linksize < 0 && (i || errno != EINVAL))
				err_print(READLINK_FAILED, "build_devlink_list",
				    newlink, strerror(errno));
			return;
		}
		contents[linksize] = '\0';
		i = 1;

		if (is_minor_node(contents, &r_contents) == DEVFSADM_FALSE) {
			/*
			 * assume that link contents is really a pointer to
			 * another link, so recurse and read its link contents.
			 *
			 * some link contents are absolute:
			 *	/dev/audio -> /dev/sound/0
			 */
			if (strncmp(contents, DEV "/",
			    strlen(DEV) + strlen("/")) != 0) {

				if ((ptr = strrchr(newlink, '/')) == NULL) {
					vprint(REMOVE_MID, "%s%s -> %s invalid "
					    "link. missing '/'\n", fcn,
					    newlink, contents);
					return;
				}
				*ptr = '\0';
				(void) strcpy(stage_link, newlink);
				*ptr = '/';
				(void) strcat(stage_link, "/");
				(void) strcat(stage_link, contents);
				(void) strcpy(newlink, stage_link);
			} else {
				(void) strcpy(newlink, dev_dir);
				(void) strcat(newlink, "/");
				(void) strcat(newlink,
				    &contents[strlen(DEV) + strlen("/")]);
			}

		} else {
			newlink[0] = '\0';
		}
	} while (newlink[0] != '\0');

	if (strncmp(devlink, dev_dir, strlen(dev_dir)) != 0) {
		vprint(BUILDCACHE_MID, "%sinvalid link: %s\n", fcn, devlink);
		return;
	}

	r_devlink = devlink + strlen(dev_dir);

	if (r_devlink[0] != '/')
		return;

	link = s_malloc(sizeof (link_t));

	/* don't store the '/' after rootdir/dev */
	r_devlink += 1;

	vprint(BUILDCACHE_MID, "%scaching link: %s\n", fcn, r_devlink);
	link->devlink = s_strdup(r_devlink);

	link->contents = s_strdup(r_contents);

	link->next = linkhead->link;
	linkhead->link = link;
}

/*
 * to be consistent, devlink must not begin with / and must be
 * relative to /dev/, whereas physpath must contain / and be
 * relative to /devices.
 */
static void
add_link_to_cache(char *devlink, char *physpath)
{
	linkhead_t *linkhead;
	link_t *link;
	int added = 0;

	if (file_mods == FALSE) {
		return;
	}

	vprint(CACHE_MID, "add_link_to_cache: %s -> %s ",
	    devlink, physpath);

	for (linkhead = headlinkhead; linkhead != NULL;
	    linkhead = linkhead->nexthead) {
		if (regexec(&(linkhead->dir_re_compiled), devlink, 0, NULL, 0)
		    == 0) {
			added++;
			link = s_malloc(sizeof (link_t));
			link->devlink = s_strdup(devlink);
			link->contents = s_strdup(physpath);
			link->next = linkhead->link;
			linkhead->link = link;
		}
	}

	vprint(CACHE_MID,
	    " %d %s\n", added, added == 0 ? "NOT ADDED" : "ADDED");
}

/*
 * Remove devlink from cache.  Devlink must be relative to /dev/ and not start
 * with /.
 */
static void
rm_link_from_cache(char *devlink)
{
	linkhead_t *linkhead;
	link_t **linkp;
	link_t *save;

	vprint(CACHE_MID, "rm_link_from_cache enter: %s\n", devlink);

	for (linkhead = headlinkhead; linkhead != NULL;
	    linkhead = linkhead->nexthead) {
		if (regexec(&(linkhead->dir_re_compiled), devlink, 0, NULL, 0)
		    == 0) {

			for (linkp = &(linkhead->link); *linkp != NULL; ) {
				if ((strcmp((*linkp)->devlink, devlink) == 0)) {
					save = *linkp;
					*linkp = (*linkp)->next;
					/*
					 * We are removing our caller's
					 * "next" link. Update the nextlink
					 * field in the head so that our
					 * callers accesses the next valid
					 * link
					 */
					if (linkhead->nextlink == save)
						linkhead->nextlink = *linkp;
					free(save->devlink);
					free(save->contents);
					free(save);
					vprint(CACHE_MID, " %s FREED FROM "
					    "CACHE\n", devlink);
				} else {
					linkp = &((*linkp)->next);
				}
			}
		}
	}
}

static void
rm_all_links_from_cache()
{
	linkhead_t *linkhead;
	linkhead_t *nextlinkhead;
	link_t *link;
	link_t *nextlink;

	vprint(CACHE_MID, "rm_all_links_from_cache\n");

	for (linkhead = headlinkhead; linkhead != NULL;
	    linkhead = nextlinkhead) {

		nextlinkhead = linkhead->nexthead;
		assert(linkhead->nextlink == NULL);
		for (link = linkhead->link; link != NULL; link = nextlink) {
			nextlink = link->next;
			free(link->devlink);
			free(link->contents);
			free(link);
		}
		regfree(&(linkhead->dir_re_compiled));
		free(linkhead->dir_re);
		free(linkhead);
	}
	headlinkhead = NULL;
}

/*
 * Called when the kernel has modified the incore path_to_inst data.  This
 * function will schedule a flush of the data to the filesystem.
 */
static void
devfs_instance_mod(void)
{
	char *fcn = "devfs_instance_mod: ";
	vprint(PATH2INST_MID, "%senter\n", fcn);

	/* signal instance thread */
	(void) mutex_lock(&count_lock);
	inst_count++;
	(void) cond_signal(&cv);
	(void) mutex_unlock(&count_lock);
}

static void
instance_flush_thread(void)
{
	int i;
	int idle;

	for (;;) {

		(void) mutex_lock(&count_lock);
		while (inst_count == 0) {
			(void) cond_wait(&cv, &count_lock);
		}
		inst_count = 0;

		vprint(PATH2INST_MID, "signaled to flush path_to_inst."
		    " Enter delay loop\n");
		/*
		 * Wait MAX_IDLE_DELAY seconds after getting the last flush
		 * path_to_inst event before invoking a flush, but never wait
		 * more than MAX_DELAY seconds after getting the first event.
		 */
		for (idle = 0, i = 0; i < MAX_DELAY; i++) {

			(void) mutex_unlock(&count_lock);
			(void) sleep(1);
			(void) mutex_lock(&count_lock);

			/* shorten the delay if we are idle */
			if (inst_count == 0) {
				idle++;
				if (idle > MAX_IDLE_DELAY) {
					break;
				}
			} else {
				inst_count = idle = 0;
			}
		}

		(void) mutex_unlock(&count_lock);

		flush_path_to_inst();
	}
}

/*
 * Helper function for flush_path_to_inst() below; this routine calls the
 * inst_sync syscall to flush the path_to_inst database to the given file.
 */
static int
do_inst_sync(char *filename, char *instfilename)
{
	void (*sigsaved)(int);
	int err = 0, flags = INST_SYNC_IF_REQUIRED;
	struct stat sb;

	if (stat(instfilename, &sb) == -1 && errno == ENOENT)
		flags = INST_SYNC_ALWAYS;

	vprint(INSTSYNC_MID, "do_inst_sync: about to flush %s\n", filename);
	sigsaved = sigset(SIGSYS, SIG_IGN);
	if (inst_sync(filename, flags) == -1)
		err = errno;
	(void) sigset(SIGSYS, sigsaved);

	switch (err) {
	case 0:
		return (DEVFSADM_SUCCESS);
	case EALREADY:	/* no-op, path_to_inst already up to date */
		return (EALREADY);
	case ENOSYS:
		err_print(CANT_LOAD_SYSCALL);
		break;
	case EPERM:
		err_print(SUPER_TO_SYNC);
		break;
	default:
		err_print(INSTSYNC_FAILED, filename, strerror(err));
		break;
	}
	return (DEVFSADM_FAILURE);
}

/*
 * Flush the kernel's path_to_inst database to /etc/path_to_inst.  To do so
 * safely, the database is flushed to a temporary file, then moved into place.
 *
 * The following files are used during this process:
 * 	/etc/path_to_inst:	The path_to_inst file
 * 	/etc/path_to_inst.<pid>: Contains data flushed from the kernel
 * 	/etc/path_to_inst.old:  The backup file
 * 	/etc/path_to_inst.old.<pid>: Temp file for creating backup
 *
 */
static void
flush_path_to_inst(void)
{
	char *new_inst_file = NULL;
	char *old_inst_file = NULL;
	char *old_inst_file_npid = NULL;
	FILE *inst_file_fp = NULL;
	FILE *old_inst_file_fp = NULL;
	struct stat sb;
	int err = 0;
	int c;
	int inst_strlen;

	vprint(PATH2INST_MID, "flush_path_to_inst: %s\n",
	    (flush_path_to_inst_enable == TRUE) ? "ENABLED" : "DISABLED");

	if (flush_path_to_inst_enable == FALSE) {
		return;
	}

	inst_strlen = strlen(inst_file);
	new_inst_file = s_malloc(inst_strlen + PID_STR_LEN + 2);
	old_inst_file = s_malloc(inst_strlen + PID_STR_LEN + 6);
	old_inst_file_npid = s_malloc(inst_strlen +
	    sizeof (INSTANCE_FILE_SUFFIX));

	(void) snprintf(new_inst_file, inst_strlen + PID_STR_LEN + 2,
	    "%s.%ld", inst_file, getpid());

	if (stat(new_inst_file, &sb) == 0) {
		s_unlink(new_inst_file);
	}

	err = do_inst_sync(new_inst_file, inst_file);
	if (err != DEVFSADM_SUCCESS) {
		goto out;
		/*NOTREACHED*/
	}

	/*
	 * Now we deal with the somewhat tricky updating and renaming
	 * of this critical piece of kernel state.
	 */

	/*
	 * Copy the current instance file into a temporary file.
	 * Then rename the temporary file into the backup (.old)
	 * file and rename the newly flushed kernel data into
	 * the instance file.
	 * Of course if 'inst_file' doesn't exist, there's much
	 * less for us to do .. tee hee.
	 */
	if ((inst_file_fp = fopen(inst_file, "r")) == NULL) {
		/*
		 * No such file.  Rename the new onto the old
		 */
		if ((err = rename(new_inst_file, inst_file)) != 0)
			err_print(RENAME_FAILED, inst_file, strerror(errno));
		goto out;
		/*NOTREACHED*/
	}

	(void) snprintf(old_inst_file, inst_strlen + PID_STR_LEN + 6,
	    "%s.old.%ld", inst_file, getpid());

	if (stat(old_inst_file, &sb) == 0) {
		s_unlink(old_inst_file);
	}

	if ((old_inst_file_fp = fopen(old_inst_file, "w")) == NULL) {
		/*
		 * Can't open the 'old_inst_file' file for writing.
		 * This is somewhat strange given that the syscall
		 * just succeeded to write a file out.. hmm.. maybe
		 * the fs just filled up or something nasty.
		 *
		 * Anyway, abort what we've done so far.
		 */
		err_print(CANT_UPDATE, old_inst_file);
		err = DEVFSADM_FAILURE;
		goto out;
		/*NOTREACHED*/
	}

	/*
	 * Copy current instance file into the temporary file
	 */
	err = 0;
	while ((c = getc(inst_file_fp)) != EOF) {
		if ((err = putc(c, old_inst_file_fp)) == EOF) {
			break;
		}
	}

	if (fclose(old_inst_file_fp) == EOF || err == EOF) {
		vprint(INFO_MID, CANT_UPDATE, old_inst_file);
		err = DEVFSADM_FAILURE;
		goto out;
		/* NOTREACHED */
	}

	/*
	 * Set permissions to be the same on the backup as
	 * /etc/path_to_inst.
	 */
	(void) chmod(old_inst_file, 0444);

	/*
	 * So far, everything we've done is more or less reversible.
	 * But now we're going to commit ourselves.
	 */

	(void) snprintf(old_inst_file_npid,
	    inst_strlen + sizeof (INSTANCE_FILE_SUFFIX),
	    "%s%s", inst_file, INSTANCE_FILE_SUFFIX);

	if ((err = rename(old_inst_file, old_inst_file_npid)) != 0) {
		err_print(RENAME_FAILED, old_inst_file_npid,
		    strerror(errno));
	} else if ((err = rename(new_inst_file, inst_file)) != 0) {
		err_print(RENAME_FAILED, inst_file, strerror(errno));
	}

out:
	if (inst_file_fp != NULL) {
		if (fclose(inst_file_fp) == EOF) {
			err_print(FCLOSE_FAILED, inst_file, strerror(errno));
		}
	}

	if (stat(new_inst_file, &sb) == 0) {
		s_unlink(new_inst_file);
	}
	free(new_inst_file);

	if (stat(old_inst_file, &sb) == 0) {
		s_unlink(old_inst_file);
	}
	free(old_inst_file);

	free(old_inst_file_npid);

	if (err != 0 && err != EALREADY) {
		err_print(FAILED_TO_UPDATE, inst_file);
	}
}

/*
 * detach from tty.  For daemon mode.
 */
void
detachfromtty()
{
	(void) setsid();
	if (DEVFSADM_DEBUG_ON == TRUE) {
		return;
	}

	(void) close(0);
	(void) close(1);
	(void) close(2);
	(void) open("/dev/null", O_RDWR, 0);
	(void) dup(0);
	(void) dup(0);
	openlog(DEVFSADMD, LOG_PID, LOG_DAEMON);
	(void) setlogmask(LOG_UPTO(LOG_INFO));
	logflag = TRUE;
}

/*
 * Use an advisory lock to synchronize updates to /dev.  If the lock is
 * held by another process, block in the fcntl() system call until that
 * process drops the lock or exits.  The lock file itself is
 * DEV_LOCK_FILE.  The process id of the current and last process owning
 * the lock is kept in the lock file.  After acquiring the lock, read the
 * process id and return it.  It is the process ID which last owned the
 * lock, and will be used to determine if caches need to be flushed.
 *
 * NOTE: if the devlink database is held open by the caller, it may
 * be closed by this routine. This is to enforce the following lock ordering:
 *	1) /dev lock 2) database open
 */
pid_t
enter_dev_lock()
{
	struct flock lock;
	int n;
	pid_t pid;
	pid_t last_owner_pid;

	if (file_mods == FALSE) {
		return (0);
	}

	(void) snprintf(dev_lockfile, sizeof (dev_lockfile),
	    "%s/%s", etc_dev_dir, DEV_LOCK_FILE);

	vprint(LOCK_MID, "enter_dev_lock: lock file %s\n", dev_lockfile);

	dev_lock_fd = open(dev_lockfile, O_CREAT|O_RDWR, 0644);
	if (dev_lock_fd < 0) {
		err_print(OPEN_FAILED, dev_lockfile, strerror(errno));
		devfsadm_exit(1);
		/*NOTREACHED*/
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	/* try for the lock, but don't wait */
	if (fcntl(dev_lock_fd, F_SETLK, &lock) == -1) {
		if ((errno == EACCES) || (errno == EAGAIN)) {
			pid = 0;
			n = read(dev_lock_fd, &pid, sizeof (pid_t));
			vprint(LOCK_MID, "waiting for PID %d to complete\n",
			    (int)pid);
			if (lseek(dev_lock_fd, 0, SEEK_SET) == (off_t)-1) {
				err_print(LSEEK_FAILED, dev_lockfile,
				    strerror(errno));
				devfsadm_exit(1);
				/*NOTREACHED*/
			}
			/*
			 * wait for the dev lock. If we have the database open,
			 * close it first - the order of lock acquisition should
			 * always be:  1) dev_lock 2) database
			 * This is to prevent deadlocks with any locks the
			 * database code may hold.
			 */
			(void) di_devlink_close(&devlink_cache, 0);

			/* send any sysevents that were queued up. */
			process_syseventq();

			if (fcntl(dev_lock_fd, F_SETLKW, &lock) == -1) {
				err_print(LOCK_FAILED, dev_lockfile,
				    strerror(errno));
				devfsadm_exit(1);
				/*NOTREACHED*/
			}
		}
	}

	hold_dev_lock = TRUE;
	pid = 0;
	n = read(dev_lock_fd, &pid, sizeof (pid_t));
	if (n == sizeof (pid_t) && pid == getpid()) {
		return (pid);
	}

	last_owner_pid = pid;

	if (lseek(dev_lock_fd, 0, SEEK_SET) == (off_t)-1) {
		err_print(LSEEK_FAILED, dev_lockfile, strerror(errno));
		devfsadm_exit(1);
		/*NOTREACHED*/
	}
	pid = getpid();
	n = write(dev_lock_fd, &pid, sizeof (pid_t));
	if (n != sizeof (pid_t)) {
		err_print(WRITE_FAILED, dev_lockfile, strerror(errno));
		devfsadm_exit(1);
		/*NOTREACHED*/
	}

	return (last_owner_pid);
}

/*
 * Drop the advisory /dev lock, close lock file.  Close and re-open the
 * file every time so to ensure a resync if for some reason the lock file
 * gets removed.
 */
void
exit_dev_lock(int exiting)
{
	struct flock unlock;

	if (hold_dev_lock == FALSE) {
		return;
	}

	vprint(LOCK_MID, "exit_dev_lock: lock file %s, exiting = %d\n",
	    dev_lockfile, exiting);

	unlock.l_type = F_UNLCK;
	unlock.l_whence = SEEK_SET;
	unlock.l_start = 0;
	unlock.l_len = 0;

	if (fcntl(dev_lock_fd, F_SETLK, &unlock) == -1) {
		err_print(UNLOCK_FAILED, dev_lockfile, strerror(errno));
	}

	hold_dev_lock = FALSE;

	if (close(dev_lock_fd) == -1) {
		err_print(CLOSE_FAILED, dev_lockfile, strerror(errno));
		if (!exiting)
			devfsadm_exit(1);
			/*NOTREACHED*/
	}
}

/*
 *
 * Use an advisory lock to ensure that only one daemon process is active
 * in the system at any point in time.	If the lock is held by another
 * process, do not block but return the pid owner of the lock to the
 * caller immediately.	The lock is cleared if the holding daemon process
 * exits for any reason even if the lock file remains, so the daemon can
 * be restarted if necessary.  The lock file is DAEMON_LOCK_FILE.
 */
pid_t
enter_daemon_lock(void)
{
	struct flock lock;

	(void) snprintf(daemon_lockfile, sizeof (daemon_lockfile),
	    "%s/%s", etc_dev_dir, DAEMON_LOCK_FILE);

	vprint(LOCK_MID, "enter_daemon_lock: lock file %s\n", daemon_lockfile);

	daemon_lock_fd = open(daemon_lockfile, O_CREAT|O_RDWR, 0644);
	if (daemon_lock_fd < 0) {
		err_print(OPEN_FAILED, daemon_lockfile, strerror(errno));
		devfsadm_exit(1);
		/*NOTREACHED*/
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(daemon_lock_fd, F_SETLK, &lock) == -1) {

		if (errno == EAGAIN || errno == EDEADLK) {
			if (fcntl(daemon_lock_fd, F_GETLK, &lock) == -1) {
				err_print(LOCK_FAILED, daemon_lockfile,
				    strerror(errno));
				devfsadm_exit(1);
				/*NOTREACHED*/
			}
			return (lock.l_pid);
		}
	}
	hold_daemon_lock = TRUE;
	return (getpid());
}

/*
 * Drop the advisory daemon lock, close lock file
 */
void
exit_daemon_lock(int exiting)
{
	struct flock lock;

	if (hold_daemon_lock == FALSE) {
		return;
	}

	vprint(LOCK_MID, "exit_daemon_lock: lock file %s, exiting = %d\n",
	    daemon_lockfile, exiting);

	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(daemon_lock_fd, F_SETLK, &lock) == -1) {
		err_print(UNLOCK_FAILED, daemon_lockfile, strerror(errno));
	}

	if (close(daemon_lock_fd) == -1) {
		err_print(CLOSE_FAILED, daemon_lockfile, strerror(errno));
		if (!exiting)
			devfsadm_exit(1);
			/*NOTREACHED*/
	}
}

/*
 * Called to removed danging nodes in two different modes: RM_PRE, RM_POST.
 * RM_PRE mode is called before processing the entire devinfo tree, and RM_POST
 * is called after processing the entire devinfo tree.
 */
static void
pre_and_post_cleanup(int flags)
{
	remove_list_t *rm;
	recurse_dev_t rd;
	cleanup_data_t cleanup_data;
	char *fcn = "pre_and_post_cleanup: ";

	if (build_dev == FALSE)
		return;

	vprint(CHATTY_MID, "attempting %s-cleanup\n",
	    flags == RM_PRE ? "pre" : "post");
	vprint(REMOVE_MID, "%sflags = %d\n", fcn, flags);

	/*
	 * the generic function recurse_dev_re is shared among different
	 * functions, so set the method and data that it should use for
	 * matches.
	 */
	rd.fcn = matching_dev;
	rd.data = (void *)&cleanup_data;
	cleanup_data.flags = flags;

	(void) mutex_lock(&nfp_mutex);
	nfphash_create();

	for (rm = remove_head; rm != NULL; rm = rm->next) {
		if ((flags & rm->remove->flags) == flags) {
			cleanup_data.rm = rm;
			/*
			 * If reached this point, RM_PRE or RM_POST cleanup is
			 * desired.  clean_ok() decides whether to clean
			 * under the given circumstances.
			 */
			vprint(REMOVE_MID, "%scleanup: PRE or POST\n", fcn);
			if (clean_ok(rm->remove) == DEVFSADM_SUCCESS) {
				vprint(REMOVE_MID, "cleanup: cleanup OK\n");
				recurse_dev_re(dev_dir,
				    rm->remove->dev_dirs_re, &rd);
			}
		}
	}
	nfphash_destroy();
	(void) mutex_unlock(&nfp_mutex);
}

/*
 * clean_ok() determines whether cleanup should be done according
 * to the following matrix:
 *
 * command line arguments RM_PRE    RM_POST	  RM_PRE &&    RM_POST &&
 *						  RM_ALWAYS    RM_ALWAYS
 * ---------------------- ------     -----	  ---------    ----------
 *
 * <neither -c nor -C>	  -	    -		  pre-clean    post-clean
 *
 * -C			  pre-clean  post-clean   pre-clean    post-clean
 *
 * -C -c class		  pre-clean  post-clean   pre-clean    post-clean
 *			  if class  if class	  if class     if class
 *			  matches   matches	  matches      matches
 *
 * -c class		   -	       -	  pre-clean    post-clean
 *						  if class     if class
 *						  matches      matches
 *
 */
static int
clean_ok(devfsadm_remove_V1_t *remove)
{
	int i;

	if (single_drv == TRUE) {
		/* no cleanup at all when using -i option */
		return (DEVFSADM_FAILURE);
	}

	/*
	 * no cleanup if drivers are not loaded. We make an exception
	 * for the "disks" program however, since disks has a public
	 * cleanup flag (-C) and disk drivers are usually never
	 * unloaded.
	 */
	if (load_attach_drv == FALSE && strcmp(prog, DISKS) != 0) {
		return (DEVFSADM_FAILURE);
	}

	/* if the cleanup flag was not specified, return false */
	if ((cleanup == FALSE) && ((remove->flags & RM_ALWAYS) == 0)) {
		return (DEVFSADM_FAILURE);
	}

	if (num_classes == 0) {
		return (DEVFSADM_SUCCESS);
	}

	/*
	 * if reached this point, check to see if the class in the given
	 * remove structure matches a class given on the command line
	 */

	for (i = 0; i < num_classes; i++) {
		if (strcmp(remove->device_class, classes[i]) == 0) {
			return (DEVFSADM_SUCCESS);
		}
	}

	return (DEVFSADM_FAILURE);
}

/*
 * Called to remove dangling nodes after receiving a hotplug event
 * containing the physical node pathname to be removed.
 */
void
hot_cleanup(char *node_path, char *minor_name, char *ev_subclass,
    char *driver_name, int instance)
{
	link_t *link;
	linkhead_t *head;
	remove_list_t *rm;
	char *fcn = "hot_cleanup: ";
	char path[PATH_MAX + 1];
	int path_len;
	char rmlink[PATH_MAX + 1];
	nvlist_t *nvl = NULL;
	int skip;
	int ret;

	/*
	 * dev links can go away as part of hot cleanup.
	 * So first build event attributes in order capture dev links.
	 */
	if (ev_subclass != NULL)
		nvl = build_event_attributes(EC_DEV_REMOVE, ev_subclass,
		    node_path, DI_NODE_NIL, driver_name, instance, minor_name);

	(void) strcpy(path, node_path);
	(void) strcat(path, ":");
	(void) strcat(path, minor_name == NULL ? "" : minor_name);

	path_len = strlen(path);

	vprint(REMOVE_MID, "%spath=%s\n", fcn, path);

	(void) mutex_lock(&nfp_mutex);
	nfphash_create();

	for (rm = remove_head; rm != NULL; rm = rm->next) {
		if ((RM_HOT & rm->remove->flags) == RM_HOT) {
			head = get_cached_links(rm->remove->dev_dirs_re);
			assert(head->nextlink == NULL);
			for (link = head->link;
			    link != NULL; link = head->nextlink) {
				/*
				 * The remove callback below may remove
				 * the current and/or any or all of the
				 * subsequent links in the list.
				 * Save the next link in the head. If
				 * the callback removes the next link
				 * the saved pointer in the head will be
				 * updated by the callback to point at
				 * the next valid link.
				 */
				head->nextlink = link->next;

				/*
				 * if devlink is in no-further-process hash,
				 * skip its remove
				 */
				if (nfphash_lookup(link->devlink) != NULL)
					continue;

				if (minor_name)
					skip = strcmp(link->contents, path);
				else
					skip = strncmp(link->contents, path,
					    path_len);
				if (skip ||
				    (call_minor_init(rm->modptr) ==
				    DEVFSADM_FAILURE))
					continue;

				vprint(REMOVE_MID,
				    "%sremoving %s -> %s\n", fcn,
				    link->devlink, link->contents);
				/*
				 * Use a copy of the cached link name
				 * as the cache entry will go away
				 * during link removal
				 */
				(void) snprintf(rmlink, sizeof (rmlink),
				    "%s", link->devlink);
				if (rm->remove->flags & RM_NOINTERPOSE) {
					((void (*)(char *))
					    (rm->remove->callback_fcn))(rmlink);
				} else {
					ret = ((int (*)(char *))
					    (rm->remove->callback_fcn))(rmlink);
					if (ret == DEVFSADM_TERMINATE)
						nfphash_insert(rmlink);
				}
			}
		}
	}

	nfphash_destroy();
	(void) mutex_unlock(&nfp_mutex);

	/* update device allocation database */
	if (system_labeled) {
		int	devtype = 0;

		if (strstr(path, DA_SOUND_NAME))
			devtype = DA_AUDIO;
		else if (strstr(path, "storage"))
			devtype = DA_RMDISK;
		else if (strstr(path, "disk"))
			devtype = DA_RMDISK;
		else if (strstr(path, "floppy"))
			/* TODO: detect usb cds and floppies at insert time */
			devtype = DA_RMDISK;
		else
			goto out;

		(void) _update_devalloc_db(&devlist, devtype, DA_REMOVE,
		    node_path, root_dir);
	}

out:
	/* now log an event */
	if (nvl) {
		log_event(EC_DEV_REMOVE, ev_subclass, nvl);
		free(nvl);
	}
}

/*
 * Open the dir current_dir.  For every file which matches the first dir
 * component of path_re, recurse.  If there are no more *dir* path
 * components left in path_re (ie no more /), then call function rd->fcn.
 */
static void
recurse_dev_re(char *current_dir, char *path_re, recurse_dev_t *rd)
{
	regex_t re1;
	char *slash;
	char new_path[PATH_MAX + 1];
	char *anchored_path_re;
	size_t len;
	finddevhdl_t fhandle;
	const char *fp;

	vprint(RECURSEDEV_MID, "recurse_dev_re: curr = %s path=%s\n",
	    current_dir, path_re);

	if (finddev_readdir(current_dir, &fhandle) != 0)
		return;

	len = strlen(path_re);
	if ((slash = strchr(path_re, '/')) != NULL) {
		len = (slash - path_re);
	}

	anchored_path_re = s_malloc(len + 3);
	(void) sprintf(anchored_path_re, "^%.*s$", len, path_re);

	if (regcomp(&re1, anchored_path_re, REG_EXTENDED) != 0) {
		free(anchored_path_re);
		goto out;
	}

	free(anchored_path_re);

	while ((fp = finddev_next(fhandle)) != NULL) {

		if (regexec(&re1, fp, 0, NULL, 0) == 0) {
			/* match */
			(void) strcpy(new_path, current_dir);
			(void) strcat(new_path, "/");
			(void) strcat(new_path, fp);

			vprint(RECURSEDEV_MID, "recurse_dev_re: match, new "
			    "path = %s\n", new_path);

			if (slash != NULL) {
				recurse_dev_re(new_path, slash + 1, rd);
			} else {
				/* reached the leaf component of path_re */
				vprint(RECURSEDEV_MID,
				    "recurse_dev_re: calling fcn\n");
				(*(rd->fcn))(new_path, rd->data);
			}
		}
	}

	regfree(&re1);

out:
	finddev_close(fhandle);
}

/*
 *  Found a devpath which matches a RE in the remove structure.
 *  Now check to see if it is dangling.
 */
static void
matching_dev(char *devpath, void *data)
{
	cleanup_data_t *cleanup_data = data;
	int norm_len = strlen(dev_dir) + strlen("/");
	int ret;
	char *fcn = "matching_dev: ";

	vprint(RECURSEDEV_MID, "%sexamining devpath = '%s'\n", fcn,
	    devpath);

	/*
	 * If the link is in the no-further-process hash
	 * don't do any remove operation on it.
	 */
	if (nfphash_lookup(devpath + norm_len) != NULL)
		return;

	/*
	 * Dangling check will work whether "alias" or "current"
	 * so no need to redirect.
	 */
	if (resolve_link(devpath, NULL, NULL, NULL, 1) == TRUE) {
		if (call_minor_init(cleanup_data->rm->modptr) ==
		    DEVFSADM_FAILURE) {
			return;
		}

		devpath += norm_len;

		vprint(RECURSEDEV_MID, "%scalling callback %s\n", fcn, devpath);
		if (cleanup_data->rm->remove->flags & RM_NOINTERPOSE)
			((void (*)(char *))
			    (cleanup_data->rm->remove->callback_fcn))(devpath);
		else {
			ret = ((int (*)(char *))
			    (cleanup_data->rm->remove->callback_fcn))(devpath);
			if (ret == DEVFSADM_TERMINATE) {
				/*
				 * We want no further remove processing for
				 * this link. Add it to the nfp_hash;
				 */
				nfphash_insert(devpath);
			}
		}
	}
}

int
devfsadm_read_link(di_node_t anynode, char *link, char **devfs_path)
{
	char devlink[PATH_MAX];
	char *path;

	*devfs_path = NULL;

	/* prepend link with dev_dir contents */
	(void) strcpy(devlink, dev_dir);
	(void) strcat(devlink, "/");
	(void) strcat(devlink, link);

	/* We *don't* want a stat of the /devices node */
	path = NULL;
	(void) resolve_link(devlink, NULL, NULL, &path, 0);
	if (path != NULL) {
		/* redirect if alias to current */
		*devfs_path = di_alias2curr(anynode, path);
		free(path);
	}
	return (*devfs_path ? DEVFSADM_SUCCESS : DEVFSADM_FAILURE);
}

int
devfsadm_link_valid(di_node_t anynode, char *link)
{
	struct stat sb;
	char devlink[PATH_MAX + 1], *contents, *raw_contents;
	int rv, type;
	int instance = 0;

	/* prepend link with dev_dir contents */
	(void) strcpy(devlink, dev_dir);
	(void) strcat(devlink, "/");
	(void) strcat(devlink, link);

	if (!device_exists(devlink) || lstat(devlink, &sb) != 0) {
		return (DEVFSADM_FALSE);
	}

	raw_contents = NULL;
	type = 0;
	if (resolve_link(devlink, &raw_contents, &type, NULL, 1) == TRUE) {
		rv = DEVFSADM_FALSE;
	} else {
		rv = DEVFSADM_TRUE;
	}

	/*
	 * resolve alias paths for primary links
	 */
	contents = raw_contents;
	if (type == DI_PRIMARY_LINK) {
		contents = di_alias2curr(anynode, raw_contents);
		free(raw_contents);
	}

	/*
	 * The link exists. Add it to the database
	 */
	(void) di_devlink_add_link(devlink_cache, link, contents, type);
	if (system_labeled && (rv == DEVFSADM_TRUE) &&
	    strstr(devlink, DA_AUDIO_NAME) && contents) {
		(void) sscanf(contents, "%*[a-z]%d", &instance);
		(void) da_add_list(&devlist, devlink, instance,
		    DA_ADD|DA_AUDIO);
		_update_devalloc_db(&devlist, 0, DA_ADD, NULL, root_dir);
	}
	free(contents);

	return (rv);
}

/*
 * devpath: Absolute path to /dev link
 * content_p: Returns malloced string (link content)
 * type_p: Returns link type: primary or secondary
 * devfs_path: Returns malloced string: /devices path w/out "/devices"
 * dangle: if set, check if link is dangling
 * Returns:
 *	TRUE if dangling
 *	FALSE if not or if caller doesn't care
 * Caller is assumed to have initialized pointer contents to NULL
 *
 */
static int
resolve_link(char *devpath, char **content_p, int *type_p, char **devfs_path,
    int dangle)
{
	char contents[PATH_MAX + 1];
	char stage_link[PATH_MAX + 1];
	char *fcn = "resolve_link: ";
	char *ptr;
	int linksize;
	int rv = TRUE;
	struct stat sb;

	/*
	 * This routine will return the "raw" contents. It is upto the
	 * the caller to redirect "alias" to "current" (or vice versa)
	 */
	linksize = readlink(devpath, contents, PATH_MAX);

	if (linksize <= 0) {
		return (FALSE);
	} else {
		contents[linksize] = '\0';
	}
	vprint(REMOVE_MID, "%s %s -> %s\n", fcn, devpath, contents);

	if (content_p) {
		*content_p = s_strdup(contents);
	}

	/*
	 * Check to see if this is a link pointing to another link in /dev.  The
	 * cheap way to do this is to look for a lack of ../devices/.
	 */

	if (is_minor_node(contents, &ptr) == DEVFSADM_FALSE) {

		if (type_p) {
			*type_p = DI_SECONDARY_LINK;
		}

		/*
		 * assume that linkcontents is really a pointer to another
		 * link, and if so recurse and read its link contents.
		 */
		if (strncmp(contents, DEV "/", strlen(DEV) + 1) == 0)  {
			(void) strcpy(stage_link, dev_dir);
			(void) strcat(stage_link, "/");
			(void) strcpy(stage_link,
			    &contents[strlen(DEV) + strlen("/")]);
		} else {
			if ((ptr = strrchr(devpath, '/')) == NULL) {
				vprint(REMOVE_MID, "%s%s -> %s invalid link. "
				    "missing '/'\n", fcn, devpath, contents);
				return (TRUE);
			}
			*ptr = '\0';
			(void) strcpy(stage_link, devpath);
			*ptr = '/';
			(void) strcat(stage_link, "/");
			(void) strcat(stage_link, contents);
		}
		return (resolve_link(stage_link, NULL, NULL, devfs_path,
		    dangle));
	}

	/* Current link points at a /devices minor node */
	if (type_p) {
		*type_p = DI_PRIMARY_LINK;
	}

	if (devfs_path)
		*devfs_path = s_strdup(ptr);

	rv = FALSE;
	if (dangle)
		rv = (stat(ptr - strlen(DEVICES), &sb) == -1);

	vprint(REMOVE_MID, "%slink=%s, returning %s\n", fcn,
	    devpath, ((rv == TRUE) ? "TRUE" : "FALSE"));

	return (rv);
}

/*
 * Returns the substring of interest, given a path.
 */
static char *
alloc_cmp_str(const char *path, devfsadm_enumerate_t *dep)
{
	uint_t match;
	char *np, *ap, *mp;
	char *cmp_str = NULL;
	char at[] = "@";
	char *fcn = "alloc_cmp_str";

	np = ap = mp = NULL;

	/*
	 * extract match flags from the flags argument.
	 */
	match = (dep->flags & MATCH_MASK);

	vprint(ENUM_MID, "%s: enumeration match type: 0x%x"
	    " path: %s\n", fcn, match, path);

	/*
	 * MATCH_CALLBACK and MATCH_ALL are the only flags
	 * which may be used if "path" is a /dev path
	 */
	if (match == MATCH_CALLBACK) {
		if (dep->sel_fcn == NULL) {
			vprint(ENUM_MID, "%s: invalid enumerate"
			    " callback: path: %s\n", fcn, path);
			return (NULL);
		}
		cmp_str = dep->sel_fcn(path, dep->cb_arg);
		return (cmp_str);
	}

	cmp_str = s_strdup(path);

	if (match == MATCH_ALL) {
		return (cmp_str);
	}

	/*
	 * The remaining flags make sense only for /devices
	 * paths
	 */
	if ((mp = strrchr(cmp_str, ':')) == NULL) {
		vprint(ENUM_MID, "%s: invalid path: %s\n",
		    fcn, path);
		goto err;
	}

	if (match == MATCH_MINOR) {
		/* A NULL "match_arg" values implies entire minor */
		if (get_component(mp + 1, dep->match_arg) == NULL) {
			vprint(ENUM_MID, "%s: invalid minor component:"
			    " path: %s\n", fcn, path);
			goto err;
		}
		return (cmp_str);
	}

	if ((np = strrchr(cmp_str, '/')) == NULL) {
		vprint(ENUM_MID, "%s: invalid path: %s\n", fcn, path);
		goto err;
	}

	if (match == MATCH_PARENT) {
		if (strcmp(cmp_str, "/") == 0) {
			vprint(ENUM_MID, "%s: invalid path: %s\n",
			    fcn, path);
			goto err;
		}

		if (np == cmp_str) {
			*(np + 1) = '\0';
		} else {
			*np = '\0';
		}
		return (cmp_str);
	}

	/* ap can be NULL - Leaf address may not exist or be empty string */
	ap = strchr(np+1, '@');

	/* minor is no longer of interest */
	*mp = '\0';

	if (match == MATCH_NODE) {
		if (ap)
			*ap = '\0';
		return (cmp_str);
	} else if (match == MATCH_ADDR) {
		/*
		 * The empty string is a valid address. The only MATCH_ADDR
		 * allowed in this case is against the whole address or
		 * the first component of the address (match_arg=NULL/"0"/"1")
		 * Note that in this case, the path won't have an "@"
		 * As a result ap will be NULL. We fake up an ap = @'\0'
		 * so that get_component() will work correctly.
		 */
		if (ap == NULL) {
			ap = at;
		}

		if (get_component(ap + 1, dep->match_arg) == NULL) {
			vprint(ENUM_MID, "%s: invalid leaf addr. component:"
			    " path: %s\n", fcn, path);
			goto err;
		}
		return (cmp_str);
	}

	vprint(ENUM_MID, "%s: invalid enumeration flags: 0x%x"
	    " path: %s\n", fcn, dep->flags, path);

	/*FALLTHRU*/
err:
	free(cmp_str);
	return (NULL);
}


/*
 * "str" is expected to be a string with components separated by ','
 * The terminating null char is considered a separator.
 * get_component() will remove the portion of the string beyond
 * the component indicated.
 * If comp_str is NULL, the entire "str" is returned.
 */
static char *
get_component(char *str, const char *comp_str)
{
	long comp;
	char *cp;

	if (str == NULL) {
		return (NULL);
	}

	if (comp_str == NULL) {
		return (str);
	}

	errno = 0;
	comp = strtol(comp_str, &cp, 10);
	if (errno != 0 || *cp != '\0' || comp < 0) {
		return (NULL);
	}

	if (comp == 0)
		return (str);

	for (cp = str; ; cp++) {
		if (*cp == ',' || *cp == '\0')
			comp--;
		if (*cp == '\0' || comp <= 0) {
			break;
		}
	}

	if (comp == 0) {
		*cp = '\0';
	} else {
		str = NULL;
	}

	return (str);
}


/*
 * Enumerate serves as a generic counter as well as a means to determine
 * logical unit/controller numbers for such items as disk and tape
 * drives.
 *
 * rules[] is an array of  devfsadm_enumerate_t structures which defines
 * the enumeration rules to be used for a specified set of links in /dev.
 * The set of links is specified through regular expressions (of the flavor
 * described in regex(5)). These regular expressions are used to determine
 * the set of links in /dev to examine. The last path component in these
 * regular expressions MUST contain a parenthesized subexpression surrounding
 * the RE which is to be considered the enumerating component. The subexp
 * member in a rule is the subexpression number of the enumerating
 * component. Subexpressions in the last path component are numbered starting
 * from 1.
 *
 * A cache of current id assignments is built up from existing symlinks and
 * new assignments use the lowest unused id. Assignments are based on a
 * match of a specified substring of a symlink's contents. If the specified
 * component for the devfs_path argument matches the corresponding substring
 * for a existing symlink's contents, the cached id is returned. Else, a new
 * id is created and returned in *buf. *buf must be freed by the caller.
 *
 * An id assignment may be governed by a combination of rules, each rule
 * applicable to a different subset of links in /dev. For example, controller
 * numbers may be determined by a combination of disk symlinks in /dev/[r]dsk
 * and controller symlinks in /dev/cfg, with the two sets requiring different
 * rules to derive the "substring of interest". In such cases, the rules
 * array will have more than one element.
 */
int
devfsadm_enumerate_int(char *devfs_path, int index, char **buf,
    devfsadm_enumerate_t rules[], int nrules)
{
	return (find_enum_id(rules, nrules,
	    devfs_path, index, "0", INTEGER, buf, 0));
}

int
ctrl_enumerate_int(char *devfs_path, int index, char **buf,
    devfsadm_enumerate_t rules[], int nrules, int multiple,
    boolean_t scsi_vhci)
{
	return (find_enum_id(rules, nrules,
	    devfs_path, index, scsi_vhci ? "0" : "1", INTEGER, buf, multiple));
}

/*
 * Same as above, but allows a starting value to be specified.
 * Private to devfsadm.... used by devlinks.
 */
static int
devfsadm_enumerate_int_start(char *devfs_path, int index, char **buf,
    devfsadm_enumerate_t rules[], int nrules, char *start)
{
	return (find_enum_id(rules, nrules,
	    devfs_path, index, start, INTEGER, buf, 0));
}

/*
 *  devfsadm_enumerate_char serves as a generic counter returning
 *  a single letter.
 */
int
devfsadm_enumerate_char(char *devfs_path, int index, char **buf,
    devfsadm_enumerate_t rules[], int nrules)
{
	return (find_enum_id(rules, nrules,
	    devfs_path, index, "a", LETTER, buf, 0));
}

/*
 * Same as above, but allows a starting char to be specified.
 * Private to devfsadm - used by ports module (port_link.c)
 */
int
devfsadm_enumerate_char_start(char *devfs_path, int index, char **buf,
    devfsadm_enumerate_t rules[], int nrules, char *start)
{
	return (find_enum_id(rules, nrules,
	    devfs_path, index, start, LETTER, buf, 0));
}


/*
 * For a given numeral_set (see get_cached_set for desc of numeral_set),
 * search all cached entries looking for matches on a specified substring
 * of devfs_path. The substring is derived from devfs_path based on the
 * rule specified by "index". If a match is found on a cached entry,
 * return the enumerated id in buf. Otherwise, create a new id by calling
 * new_id, then cache and return that entry.
 */
static int
find_enum_id(devfsadm_enumerate_t rules[], int nrules,
    char *devfs_path, int index, char *min, int type, char **buf,
    int multiple)
{
	numeral_t *matchnp;
	numeral_t *numeral;
	int matchcount = 0;
	char *cmp_str;
	char *fcn = "find_enum_id";
	numeral_set_t *set;

	if (rules == NULL) {
		vprint(ENUM_MID, "%s: no rules. path: %s\n",
		    fcn, devfs_path ? devfs_path : "<NULL path>");
		return (DEVFSADM_FAILURE);
	}

	if (devfs_path == NULL) {
		vprint(ENUM_MID, "%s: NULL path\n", fcn);
		return (DEVFSADM_FAILURE);
	}

	if (nrules <= 0 || index < 0 || index >= nrules || buf == NULL) {
		vprint(ENUM_MID, "%s: invalid arguments. path: %s\n",
		    fcn, devfs_path);
		return (DEVFSADM_FAILURE);
	}

	*buf = NULL;


	cmp_str = alloc_cmp_str(devfs_path, &rules[index]);
	if (cmp_str == NULL) {
		return (DEVFSADM_FAILURE);
	}

	if ((set = get_enum_cache(rules, nrules)) == NULL) {
		free(cmp_str);
		return (DEVFSADM_FAILURE);
	}

	assert(nrules == set->re_count);

	/*
	 * Check and see if a matching entry is already cached.
	 */
	matchcount = lookup_enum_cache(set, cmp_str, rules, index,
	    &matchnp);

	if (matchcount < 0 || matchcount > 1) {
		free(cmp_str);
		if (multiple && matchcount > 1)
			return (DEVFSADM_MULTIPLE);
		else
			return (DEVFSADM_FAILURE);
	}

	/* if matching entry already cached, return it */
	if (matchcount == 1) {
		/* should never create a link with a reserved ID */
		vprint(ENUM_MID, "%s: 1 match w/ ID: %s\n", fcn, matchnp->id);
		assert(matchnp->flags == 0);
		*buf = s_strdup(matchnp->id);
		free(cmp_str);
		return (DEVFSADM_SUCCESS);
	}

	/*
	 * no cached entry, initialize a numeral struct
	 * by calling new_id() and cache onto the numeral_set
	 */
	numeral = s_malloc(sizeof (numeral_t));
	numeral->id = new_id(set->headnumeral, type, min);
	numeral->full_path = s_strdup(devfs_path);
	numeral->rule_index = index;
	numeral->cmp_str = cmp_str;
	cmp_str = NULL;
	numeral->flags = 0;
	vprint(RSRV_MID, "%s: alloc new_id: %s numeral flags = %d\n",
	    fcn, numeral->id, numeral->flags);


	/* insert to head of list for fast lookups */
	numeral->next = set->headnumeral;
	set->headnumeral = numeral;

	*buf = s_strdup(numeral->id);
	return (DEVFSADM_SUCCESS);
}


/*
 * Looks up the specified cache for a match with a specified string
 * Returns:
 *	-1	: on error.
 *	0/1/2	: Number of matches.
 * Returns the matching element only if there is a single match.
 * If the "uncached" flag is set, derives the "cmp_str" afresh
 * for the match instead of using cached values.
 */
static int
lookup_enum_cache(numeral_set_t *set, char *cmp_str,
    devfsadm_enumerate_t rules[], int index, numeral_t **matchnpp)
{
	int matchcount = 0, rv = -1;
	int uncached;
	numeral_t *np;
	char *fcn = "lookup_enum_cache";
	char *cp;

	*matchnpp = NULL;

	assert(index < set->re_count);

	if (cmp_str == NULL) {
		return (-1);
	}

	uncached = 0;
	if ((rules[index].flags & MATCH_UNCACHED) == MATCH_UNCACHED) {
		uncached = 1;
	}

	/*
	 * Check and see if a matching entry is already cached.
	 */
	for (np = set->headnumeral; np != NULL; np = np->next) {

		/*
		 * Skip reserved IDs
		 */
		if (np->flags & NUMERAL_RESERVED) {
			vprint(RSRV_MID, "lookup_enum_cache: "
			    "Cannot Match with reserved ID (%s), "
			    "skipping\n", np->id);
			assert(np->flags == NUMERAL_RESERVED);
			continue;
		} else {
			vprint(RSRV_MID, "lookup_enum_cache: "
			    "Attempting match with numeral ID: %s"
			    " numeral flags = %d\n", np->id, np->flags);
			assert(np->flags == 0);
		}

		if (np->cmp_str == NULL) {
			vprint(ENUM_MID, "%s: invalid entry in enumerate"
			    " cache. path: %s\n", fcn, np->full_path);
			return (-1);
		}

		if (uncached) {
			vprint(CHATTY_MID, "%s: bypassing enumerate cache."
			    " path: %s\n", fcn, cmp_str);
			cp = alloc_cmp_str(np->full_path,
			    &rules[np->rule_index]);
			if (cp == NULL)
				return (-1);
			rv = strcmp(cmp_str, cp);
			free(cp);
		} else {
			rv = strcmp(cmp_str, np->cmp_str);
		}

		if (rv == 0) {
			if (matchcount++ != 0) {
				break; /* more than 1 match. */
			}
			*matchnpp = np;
		}
	}

	return (matchcount);
}

#ifdef	DEBUG
static void
dump_enum_cache(numeral_set_t *setp)
{
	int i;
	numeral_t *np;
	char *fcn = "dump_enum_cache";

	vprint(ENUM_MID, "%s: re_count = %d\n", fcn, setp->re_count);
	for (i = 0; i < setp->re_count; i++) {
		vprint(ENUM_MID, "%s: re[%d] = %s\n", fcn, i, setp->re[i]);
	}

	for (np = setp->headnumeral; np != NULL; np = np->next) {
		vprint(ENUM_MID, "%s: id: %s\n", fcn, np->id);
		vprint(ENUM_MID, "%s: full_path: %s\n", fcn, np->full_path);
		vprint(ENUM_MID, "%s: rule_index: %d\n", fcn, np->rule_index);
		vprint(ENUM_MID, "%s: cmp_str: %s\n", fcn, np->cmp_str);
		vprint(ENUM_MID, "%s: flags: %d\n", fcn, np->flags);
	}
}
#endif

/*
 * For a given set of regular expressions in rules[], this function returns
 * either a previously cached struct numeral_set or it will create and
 * cache a new struct numeral_set.  There is only one struct numeral_set
 * for the combination of REs present in rules[].  Each numeral_set contains
 * the regular expressions in rules[] used for cache selection AND a linked
 * list of struct numerals, ONE FOR EACH *UNIQUE* numeral or character ID
 * selected by the grouping parenthesized subexpression found in the last
 * path component of each rules[].re.  For example, the RE: "rmt/([0-9]+)"
 * selects all the logical nodes of the correct form in dev/rmt/.
 * Each rmt/X will store a *single* struct numeral... ie 0, 1, 2 each get a
 * single struct numeral. There is no need to store more than a single logical
 * node matching X since the information desired in the devfspath would be
 * identical for the portion of the devfspath of interest. (the part up to,
 * but not including the minor name in this example.)
 *
 * If the given numeral_set is not yet cached, call enumerate_recurse to
 * create it.
 */
static numeral_set_t *
get_enum_cache(devfsadm_enumerate_t rules[], int nrules)
{
	/* linked list of numeral sets */
	numeral_set_t *setp;
	int i;
	int ret;
	char *path_left;
	enumerate_file_t *entry;
	char *fcn = "get_enum_cache";

	/*
	 * See if we've already cached this numeral set.
	 */
	for (setp = head_numeral_set; setp != NULL; setp = setp->next) {
		/*
		 *  check all regexp's passed in function against
		 *  those in cached set.
		 */
		if (nrules != setp->re_count) {
			continue;
		}

		for (i = 0; i < nrules; i++) {
			if (strcmp(setp->re[i], rules[i].re) != 0) {
				break;
			}
		}

		if (i == nrules) {
			return (setp);
		}
	}

	/*
	 * If the MATCH_UNCACHED flag is set, we should not  be here.
	 */
	for (i = 0; i < nrules; i++) {
		if ((rules[i].flags & MATCH_UNCACHED) == MATCH_UNCACHED) {
			vprint(ENUM_MID, "%s: invalid enumeration flags: "
			    "0x%x\n", fcn, rules[i].flags);
			return (NULL);
		}
	}

	/*
	 *  Since we made it here, we have not yet cached the given set of
	 *  logical nodes matching the passed re.  Create a cached entry
	 *  struct numeral_set and populate it with a minimal set of
	 *  logical nodes from /dev.
	 */

	setp = s_malloc(sizeof (numeral_set_t));
	setp->re = s_malloc(sizeof (char *) * nrules);
	for (i = 0; i < nrules; i++) {
		setp->re[i] = s_strdup(rules[i].re);
	}
	setp->re_count = nrules;
	setp->headnumeral = NULL;

	/* put this new cached set on the cached set list */
	setp->next = head_numeral_set;
	head_numeral_set = setp;

	/*
	 * For each RE, search the "reserved" list to create numeral IDs that
	 * are reserved.
	 */
	for (entry = enumerate_reserved; entry; entry = entry->er_next) {

		vprint(RSRV_MID, "parsing rstring: %s\n", entry->er_file);

		for (i = 0; i < nrules; i++) {
			path_left = s_strdup(setp->re[i]);
			vprint(RSRV_MID, "parsing rule RE: %s\n", path_left);
			ret = enumerate_parse(entry->er_file, path_left,
			    setp, rules, i);
			free(path_left);
			if (ret == 1) {
				/*
				 * We found the reserved ID for this entry.
				 * We still keep the entry since it is needed
				 * by the new link bypass code in disks
				 */
				vprint(RSRV_MID, "found rsv ID: rstring: %s "
				    "rule RE: %s\n", entry->er_file, path_left);
				break;
			}
		}
	}

	/*
	 * For each RE, search disk and cache any matches on the
	 * numeral list.
	 */
	for (i = 0; i < nrules; i++) {
		path_left = s_strdup(setp->re[i]);
		enumerate_recurse(dev_dir, path_left, setp, rules, i);
		free(path_left);
	}

#ifdef	DEBUG
	dump_enum_cache(setp);
#endif

	return (setp);
}


/*
 * This function stats the pathname namebuf.  If this is a directory
 * entry, we recurse down dname/fname until we find the first symbolic
 * link, and then stat and return it.  This is valid for the same reason
 * that we only need to read a single pathname for multiple matching
 * logical ID's... ie, all the logical nodes should contain identical
 * physical paths for the parts we are interested.
 */
int
get_stat_info(char *namebuf, struct stat *sb)
{
	char *cp;
	finddevhdl_t fhandle;
	const char *fp;

	if (lstat(namebuf, sb) < 0) {
		(void) err_print(LSTAT_FAILED, namebuf, strerror(errno));
		return (DEVFSADM_FAILURE);
	}

	if ((sb->st_mode & S_IFMT) == S_IFLNK) {
		return (DEVFSADM_SUCCESS);
	}

	/*
	 * If it is a dir, recurse down until we find a link and
	 * then use the link.
	 */
	if ((sb->st_mode & S_IFMT) == S_IFDIR) {

		if (finddev_readdir(namebuf, &fhandle) != 0) {
			return (DEVFSADM_FAILURE);
		}

		/*
		 *  Search each dir entry looking for a symlink.  Return
		 *  the first symlink found in namebuf.  Recurse dirs.
		 */
		while ((fp = finddev_next(fhandle)) != NULL) {
			cp = namebuf + strlen(namebuf);
			if ((strlcat(namebuf, "/", PATH_MAX) >= PATH_MAX) ||
			    (strlcat(namebuf, fp, PATH_MAX) >= PATH_MAX)) {
				*cp = '\0';
				finddev_close(fhandle);
				return (DEVFSADM_FAILURE);
			}
			if (get_stat_info(namebuf, sb) == DEVFSADM_SUCCESS) {
				finddev_close(fhandle);
				return (DEVFSADM_SUCCESS);
			}
			*cp = '\0';
		}
		finddev_close(fhandle);
	}

	/* no symlink found, so return error */
	return (DEVFSADM_FAILURE);
}

/*
 * An existing matching ID was not found, so this function is called to
 * create the next lowest ID.  In the INTEGER case, return the next
 * lowest unused integer.  In the case of LETTER, return the next lowest
 * unused letter.  Return empty string if all 26 are used.
 * Only IDs >= min will be returned.
 */
char *
new_id(numeral_t *numeral, int type, char *min)
{
	int imin;
	temp_t *temp;
	temp_t *ptr;
	temp_t **previous;
	temp_t *head = NULL;
	char *retval;
	static char tempbuff[8];
	numeral_t *np;

	if (type == LETTER) {

		char letter[26], i;

		if (numeral == NULL) {
			return (s_strdup(min));
		}

		for (i = 0; i < 26; i++) {
			letter[i] = 0;
		}

		for (np = numeral; np != NULL; np = np->next) {
			assert(np->flags == 0 ||
			    np->flags == NUMERAL_RESERVED);
			letter[*np->id - 'a']++;
		}

		imin = *min - 'a';

		for (i = imin; i < 26; i++) {
			if (letter[i] == 0) {
				retval = s_malloc(2);
				retval[0] = 'a' + i;
				retval[1] = '\0';
				return (retval);
			}
		}

		return (s_strdup(""));
	}

	if (type == INTEGER) {

		if (numeral == NULL) {
			return (s_strdup(min));
		}

		imin = atoi(min);

		/* sort list */
		for (np = numeral; np != NULL; np = np->next) {
			assert(np->flags == 0 ||
			    np->flags == NUMERAL_RESERVED);
			temp = s_malloc(sizeof (temp_t));
			temp->integer = atoi(np->id);
			temp->next = NULL;

			previous = &head;
			for (ptr = head; ptr != NULL; ptr = ptr->next) {
				if (temp->integer < ptr->integer) {
					temp->next = ptr;
					*previous = temp;
					break;
				}
				previous = &(ptr->next);
			}
			if (ptr == NULL) {
				*previous = temp;
			}
		}

		/* now search sorted list for first hole >= imin */
		for (ptr = head; ptr != NULL; ptr = ptr->next) {
			if (imin == ptr->integer) {
				imin++;
			} else {
				if (imin < ptr->integer) {
					break;
				}
			}

		}

		/* free temp list */
		for (ptr = head; ptr != NULL; ) {
			temp = ptr;
			ptr = ptr->next;
			free(temp);
		}

		(void) sprintf(tempbuff, "%d", imin);
		return (s_strdup(tempbuff));
	}

	return (s_strdup(""));
}

static int
enumerate_parse(char *rsvstr, char *path_left, numeral_set_t *setp,
    devfsadm_enumerate_t rules[], int index)
{
	char	*slash1 = NULL;
	char	*slash2 = NULL;
	char	*numeral_id;
	char	*path_left_save;
	char	*rsvstr_save;
	int	ret = 0;
	static int warned = 0;

	rsvstr_save = rsvstr;
	path_left_save = path_left;

	if (rsvstr == NULL || rsvstr[0] == '\0' || rsvstr[0] == '/') {
		if (!warned) {
			err_print("invalid reserved filepath: %s\n",
			    rsvstr ? rsvstr : "<NULL>");
			warned = 1;
		}
		return (0);
	}

	vprint(RSRV_MID, "processing rule: %s, rstring: %s\n",
	    path_left, rsvstr);


	for (;;) {
		/* get rid of any extra '/' in the reserve string */
		while (*rsvstr == '/') {
			rsvstr++;
		}

		/* get rid of any extra '/' in the RE */
		while (*path_left == '/') {
			path_left++;
		}

		if (slash1 = strchr(path_left, '/')) {
			*slash1 = '\0';
		}
		if (slash2 = strchr(rsvstr, '/')) {
			*slash2 = '\0';
		}

		if ((slash1 != NULL) ^ (slash2 != NULL)) {
			ret = 0;
			vprint(RSRV_MID, "mismatch in # of path components\n");
			goto out;
		}

		/*
		 *  Returns true if path_left matches the list entry.
		 *  If it is the last path component, pass subexp
		 *  so that it will return the corresponding ID in
		 *  numeral_id.
		 */
		numeral_id = NULL;
		if (match_path_component(path_left, rsvstr, &numeral_id,
		    slash1 ? 0 : rules[index].subexp)) {

			/* We have a match. */
			if (slash1 == NULL) {
				/* Is last path component */
				vprint(RSRV_MID, "match and last component\n");
				create_reserved_numeral(setp, numeral_id);
				if (numeral_id != NULL) {
					free(numeral_id);
				}
				ret = 1;
				goto out;
			} else {
				/* Not last path component. Continue parsing */
				*slash1 = '/';
				*slash2 = '/';
				path_left = slash1 + 1;
				rsvstr = slash2 + 1;
				vprint(RSRV_MID,
				    "match and NOT last component\n");
				continue;
			}
		} else {
			/* No match */
			ret = 0;
			vprint(RSRV_MID, "No match: rule RE = %s, "
			    "rstring = %s\n", path_left, rsvstr);
			goto out;
		}
	}

out:
	if (slash1)
		*slash1 = '/';
	if (slash2)
		*slash2 = '/';

	if (ret == 1) {
		vprint(RSRV_MID, "match: rule RE: %s, rstring: %s\n",
		    path_left_save, rsvstr_save);
	} else {
		vprint(RSRV_MID, "NO match: rule RE: %s, rstring: %s\n",
		    path_left_save, rsvstr_save);
	}

	return (ret);
}

/*
 * Search current_dir for all files which match the first path component
 * of path_left, which is an RE.  If a match is found, but there are more
 * components of path_left, then recurse, otherwise, if we have reached
 * the last component of path_left, call create_cached_numerals for each
 * file.   At some point, recurse_dev_re() should be rewritten so that this
 * function can be eliminated.
 */
static void
enumerate_recurse(char *current_dir, char *path_left, numeral_set_t *setp,
    devfsadm_enumerate_t rules[], int index)
{
	char *slash;
	char *new_path;
	char *numeral_id;
	finddevhdl_t fhandle;
	const char *fp;

	if (finddev_readdir(current_dir, &fhandle) != 0) {
		return;
	}

	/* get rid of any extra '/' */
	while (*path_left == '/') {
		path_left++;
	}

	if (slash = strchr(path_left, '/')) {
		*slash = '\0';
	}

	while ((fp = finddev_next(fhandle)) != NULL) {

		/*
		 *  Returns true if path_left matches the list entry.
		 *  If it is the last path component, pass subexp
		 *  so that it will return the corresponding ID in
		 *  numeral_id.
		 */
		numeral_id = NULL;
		if (match_path_component(path_left, (char *)fp, &numeral_id,
		    slash ? 0 : rules[index].subexp)) {

			new_path = s_malloc(strlen(current_dir) +
			    strlen(fp) + 2);

			(void) strcpy(new_path, current_dir);
			(void) strcat(new_path, "/");
			(void) strcat(new_path, fp);

			if (slash != NULL) {
				enumerate_recurse(new_path, slash + 1,
				    setp, rules, index);
			} else {
				create_cached_numeral(new_path, setp,
				    numeral_id, rules, index);
				if (numeral_id != NULL) {
					free(numeral_id);
				}
			}
			free(new_path);
		}
	}

	if (slash != NULL) {
		*slash = '/';
	}
	finddev_close(fhandle);
}


/*
 * Returns true if file matches file_re.  If subexp is non-zero, it means
 * we are searching the last path component and need to return the
 * parenthesized subexpression subexp in id.
 *
 */
static int
match_path_component(char *file_re,  char *file,  char **id, int subexp)
{
	regex_t re1;
	int match = 0;
	int nelements;
	regmatch_t *pmatch;

	if (subexp != 0) {
		nelements = subexp + 1;
		pmatch =
		    (regmatch_t *)s_malloc(sizeof (regmatch_t) * nelements);
	} else {
		pmatch = NULL;
		nelements = 0;
	}

	if (regcomp(&re1, file_re, REG_EXTENDED) != 0) {
		if (pmatch != NULL) {
			free(pmatch);
		}
		return (0);
	}

	if (regexec(&re1, file, nelements, pmatch, 0) == 0) {
		match = 1;
	}

	if ((match != 0) && (subexp != 0)) {
		int size = pmatch[subexp].rm_eo - pmatch[subexp].rm_so;
		*id = s_malloc(size + 1);
		(void) strncpy(*id, &file[pmatch[subexp].rm_so], size);
		(*id)[size] = '\0';
	}

	if (pmatch != NULL) {
		free(pmatch);
	}
	regfree(&re1);
	return (match);
}

static void
create_reserved_numeral(numeral_set_t *setp, char *numeral_id)
{
	numeral_t *np;

	vprint(RSRV_MID, "Attempting to create reserved numeral: %s\n",
	    numeral_id);

	/*
	 * We found a numeral_id from an entry in the enumerate_reserved file
	 * which matched the re passed in from devfsadm_enumerate.  We only
	 * need to make sure ONE copy of numeral_id exists on the numeral list.
	 * We only need to store /dev/dsk/cNtod0s0 and no other entries
	 * hanging off of controller N.
	 */
	for (np = setp->headnumeral; np != NULL; np = np->next) {
		if (strcmp(numeral_id, np->id) == 0) {
			vprint(RSRV_MID, "ID: %s, already reserved\n", np->id);
			assert(np->flags == NUMERAL_RESERVED);
			return;
		} else {
			assert(np->flags == 0 ||
			    np->flags == NUMERAL_RESERVED);
		}
	}

	/* NOT on list, so add it */
	np = s_malloc(sizeof (numeral_t));
	np->id = s_strdup(numeral_id);
	np->full_path = NULL;
	np->rule_index = 0;
	np->cmp_str = NULL;
	np->flags = NUMERAL_RESERVED;
	np->next = setp->headnumeral;
	setp->headnumeral = np;

	vprint(RSRV_MID, "Reserved numeral ID: %s\n", np->id);
}

/*
 * This function is called for every file which matched the leaf
 * component of the RE.  If the "numeral_id" is not already on the
 * numeral set's numeral list, add it and its physical path.
 */
static void
create_cached_numeral(char *path, numeral_set_t *setp, char *numeral_id,
    devfsadm_enumerate_t rules[], int index)
{
	char linkbuf[PATH_MAX + 1];
	char lpath[PATH_MAX + 1];
	char *linkptr, *cmp_str;
	numeral_t *np;
	int linksize;
	struct stat sb;
	char *contents;
	const char *fcn = "create_cached_numeral";

	assert(index >= 0 && index < setp->re_count);
	assert(strcmp(rules[index].re, setp->re[index]) == 0);

	/*
	 *  We found a numeral_id from an entry in /dev which matched
	 *  the re passed in from devfsadm_enumerate.  We only need to make sure
	 *  ONE copy of numeral_id exists on the numeral list.  We only need
	 *  to store /dev/dsk/cNtod0s0 and no other entries hanging off
	 *  of controller N.
	 */
	for (np = setp->headnumeral; np != NULL; np = np->next) {
		assert(np->flags == 0 || np->flags == NUMERAL_RESERVED);
		if (strcmp(numeral_id, np->id) == 0) {
			/*
			 * Note that we can't assert that the flags field
			 * of the numeral is 0, since both reserved and
			 * unreserved links in /dev come here
			 */
			if (np->flags == NUMERAL_RESERVED) {
				vprint(RSRV_MID, "ID derived from /dev link is"
				    " reserved: %s\n", np->id);
			} else {
				vprint(RSRV_MID, "ID derived from /dev link is"
				    " NOT reserved: %s\n", np->id);
			}
			return;
		}
	}

	/* NOT on list, so add it */

	(void) strcpy(lpath, path);
	/*
	 * If path is a dir, it is changed to the first symbolic link it find
	 * if it finds one.
	 */
	if (get_stat_info(lpath, &sb) == DEVFSADM_FAILURE) {
		return;
	}

	/* If we get here, we found a symlink */
	linksize = readlink(lpath, linkbuf, PATH_MAX);

	if (linksize <= 0) {
		err_print(READLINK_FAILED, fcn, lpath, strerror(errno));
		return;
	}

	linkbuf[linksize] = '\0';

	/*
	 * redirect alias path to current path
	 * devi_root_node is protected by lock_dev()
	 */
	contents = di_alias2curr(devi_root_node, linkbuf);

	/*
	 * the following just points linkptr to the root of the /devices
	 * node if it is a minor node, otherwise, to the first char of
	 * linkbuf if it is a link.
	 */
	(void) is_minor_node(contents, &linkptr);

	cmp_str = alloc_cmp_str(linkptr, &rules[index]);
	if (cmp_str == NULL) {
		free(contents);
		return;
	}

	np = s_malloc(sizeof (numeral_t));

	np->id = s_strdup(numeral_id);
	np->full_path = s_strdup(linkptr);
	np->rule_index = index;
	np->cmp_str = cmp_str;
	np->flags = 0;

	np->next = setp->headnumeral;
	setp->headnumeral = np;

	free(contents);
}


/*
 * This should be called either before or after granting access to a
 * command line version of devfsadm running, since it may have changed
 * the state of /dev.  It forces future enumerate calls to re-build
 * cached information from /dev.
 */
void
invalidate_enumerate_cache(void)
{
	numeral_set_t *setp;
	numeral_set_t *savedsetp;
	numeral_t *savednumset;
	numeral_t *numset;
	int i;

	for (setp = head_numeral_set; setp != NULL; ) {
		/*
		 *  check all regexp's passed in function against
		 *  those in cached set.
		 */

		savedsetp = setp;
		setp = setp->next;

		for (i = 0; i < savedsetp->re_count; i++) {
			free(savedsetp->re[i]);
		}
		free(savedsetp->re);

		for (numset = savedsetp->headnumeral; numset != NULL; ) {
			savednumset = numset;
			numset = numset->next;
			assert(savednumset->rule_index < savedsetp->re_count);
			free(savednumset->id);
			free(savednumset->full_path);
			free(savednumset->cmp_str);
			free(savednumset);
		}
		free(savedsetp);
	}
	head_numeral_set = NULL;
}

/*
 * Copies over links from /dev to <root>/dev and device special files in
 * /devices to <root>/devices, preserving the existing file modes.  If
 * the link or special file already exists on <root>, skip the copy.  (it
 * would exist only if a package hard coded it there, so assume package
 * knows best?).  Use /etc/name_to_major and <root>/etc/name_to_major to
 * make translations for major numbers on device special files.	No need to
 * make a translation on minor_perm since if the file was created in the
 * miniroot then it would presumably have the same minor_perm entry in
 *  <root>/etc/minor_perm.  To be used only by install.
 */
int
devfsadm_copy(void)
{
	char filename[PATH_MAX + 1];

	/* load the installed root's name_to_major for translations */
	(void) snprintf(filename, sizeof (filename), "%s%s", root_dir,
	    NAME_TO_MAJOR);
	if (load_n2m_table(filename) == DEVFSADM_FAILURE) {
		return (DEVFSADM_FAILURE);
	}

	/* Copy /dev to target disk. No need to copy /devices with devfs */
	(void) nftw(DEV, devfsadm_copy_file, 20, FTW_PHYS);

	/* Let install handle copying over path_to_inst */

	return (DEVFSADM_SUCCESS);
}

/*
 * This function copies links, dirs, and device special files.
 * Note that it always returns DEVFSADM_SUCCESS, so that nftw doesn't
 * abort.
 */
/*ARGSUSED*/
static int
devfsadm_copy_file(const char *file, const struct stat *stat,
    int flags, struct FTW *ftw)
{
	struct stat sp;
	dev_t newdev;
	char newfile[PATH_MAX + 1];
	char linkcontents[PATH_MAX + 1];
	int bytes;
	const char *fcn = "devfsadm_copy_file";

	(void) strcpy(newfile, root_dir);
	(void) strcat(newfile, "/");
	(void) strcat(newfile, file);

	if (lstat(newfile, &sp) == 0) {
		/* newfile already exists, so no need to continue */
		return (DEVFSADM_SUCCESS);
	}

	if (((stat->st_mode & S_IFMT) == S_IFBLK) ||
	    ((stat->st_mode & S_IFMT) == S_IFCHR)) {
		if (translate_major(stat->st_rdev, &newdev) ==
		    DEVFSADM_FAILURE) {
			return (DEVFSADM_SUCCESS);
		}
		if (mknod(newfile, stat->st_mode, newdev) == -1) {
			err_print(MKNOD_FAILED, newfile, strerror(errno));
			return (DEVFSADM_SUCCESS);
		}
	} else if ((stat->st_mode & S_IFMT) == S_IFDIR) {
		if (mknod(newfile, stat->st_mode, 0) == -1) {
			err_print(MKNOD_FAILED, newfile, strerror(errno));
			return (DEVFSADM_SUCCESS);
		}
	} else if ((stat->st_mode & S_IFMT) == S_IFLNK)  {
		/*
		 * No need to redirect alias paths. We want a
		 * true copy. The system on first boot after install
		 * will redirect paths
		 */
		if ((bytes = readlink(file, linkcontents, PATH_MAX)) == -1)  {
			err_print(READLINK_FAILED, fcn, file, strerror(errno));
			return (DEVFSADM_SUCCESS);
		}
		linkcontents[bytes] = '\0';
		if (symlink(linkcontents, newfile) == -1) {
			err_print(SYMLINK_FAILED, newfile, newfile,
			    strerror(errno));
			return (DEVFSADM_SUCCESS);
		}
	}

	(void) lchown(newfile, stat->st_uid, stat->st_gid);
	return (DEVFSADM_SUCCESS);
}

/*
 *  Given a dev_t from the running kernel, return the new_dev_t
 *  by translating to the major number found on the installed
 *  target's root name_to_major file.
 */
static int
translate_major(dev_t old_dev, dev_t *new_dev)
{
	major_t oldmajor;
	major_t newmajor;
	minor_t oldminor;
	minor_t newminor;
	char cdriver[FILENAME_MAX + 1];
	char driver[FILENAME_MAX + 1];
	char *fcn = "translate_major: ";

	oldmajor = major(old_dev);
	if (modctl(MODGETNAME, driver, sizeof (driver), &oldmajor) != 0) {
		return (DEVFSADM_FAILURE);
	}

	if (strcmp(driver, "clone") != 0) {
		/* non-clone case */

		/* look up major number is target's name2major */
		if (get_major_no(driver, &newmajor) == DEVFSADM_FAILURE) {
			return (DEVFSADM_FAILURE);
		}

		*new_dev = makedev(newmajor, minor(old_dev));
		if (old_dev != *new_dev) {
			vprint(CHATTY_MID, "%sdriver: %s old: %lu,%lu "
			    "new: %lu,%lu\n", fcn, driver, major(old_dev),
			    minor(old_dev), major(*new_dev), minor(*new_dev));
		}
		return (DEVFSADM_SUCCESS);
	} else {
		/*
		 *  The clone is a special case.  Look at its minor
		 *  number since it is the major number of the real driver.
		 */
		if (get_major_no(driver, &newmajor) == DEVFSADM_FAILURE) {
			return (DEVFSADM_FAILURE);
		}

		oldminor = minor(old_dev);
		if (modctl(MODGETNAME, cdriver, sizeof (cdriver),
		    &oldminor) != 0) {
			err_print(MODGETNAME_FAILED, oldminor);
			return (DEVFSADM_FAILURE);
		}

		if (get_major_no(cdriver, &newminor) == DEVFSADM_FAILURE) {
			return (DEVFSADM_FAILURE);
		}

		*new_dev = makedev(newmajor, newminor);
		if (old_dev != *new_dev) {
			vprint(CHATTY_MID, "%sdriver: %s old: "
			    "%lu,%lu  new: %lu,%lu\n", fcn, driver,
			    major(old_dev), minor(old_dev),
			    major(*new_dev), minor(*new_dev));
		}
		return (DEVFSADM_SUCCESS);
	}
}

/*
 *
 * Find the major number for driver, searching the n2m_list that was
 * built in load_n2m_table().
 */
static int
get_major_no(char *driver, major_t *major)
{
	n2m_t *ptr;

	for (ptr = n2m_list; ptr != NULL; ptr = ptr->next) {
		if (strcmp(ptr->driver, driver) == 0) {
			*major = ptr->major;
			return (DEVFSADM_SUCCESS);
		}
	}
	err_print(FIND_MAJOR_FAILED, driver);
	return (DEVFSADM_FAILURE);
}

/*
 * Loads a name_to_major table into memory.  Used only for suninstall's
 * private -R option to devfsadm, to translate major numbers from the
 * running to the installed target disk.
 */
static int
load_n2m_table(char *file)
{
	FILE *fp;
	char line[1024], *cp;
	char driver[PATH_MAX + 1];
	major_t major;
	n2m_t *ptr;
	int ln = 0;

	if ((fp = fopen(file, "r")) == NULL) {
		err_print(FOPEN_FAILED, file, strerror(errno));
		return (DEVFSADM_FAILURE);
	}

	while (fgets(line, sizeof (line), fp) != NULL) {
		ln++;
		/* cut off comments starting with '#' */
		if ((cp = strchr(line, '#')) != NULL)
			*cp = '\0';
		/* ignore comment or blank lines */
		if (is_blank(line))
			continue;
		/* sanity-check */
		if (sscanf(line, "%1024s%lu", driver, &major) != 2) {
			err_print(IGNORING_LINE_IN, ln, file);
			continue;
		}
		ptr = (n2m_t *)s_malloc(sizeof (n2m_t));
		ptr->major = major;
		ptr->driver = s_strdup(driver);
		ptr->next = n2m_list;
		n2m_list = ptr;
	}
	if (fclose(fp) == EOF) {
		err_print(FCLOSE_FAILED, file, strerror(errno));
	}
	return (DEVFSADM_SUCCESS);
}

/*
 * Called at devfsadm startup to read the file /etc/dev/enumerate_reserved
 * Creates a linked list of devlinks from which reserved IDs can be derived
 */
static void
read_enumerate_file(void)
{
	FILE *fp;
	int linenum;
	char line[PATH_MAX+1];
	enumerate_file_t *entry;
	struct stat current_sb;
	static struct stat cached_sb;
	static int cached = FALSE;

	assert(enumerate_file);

	if (stat(enumerate_file, &current_sb) == -1) {
		vprint(RSRV_MID, "No reserved file: %s\n", enumerate_file);
		cached = FALSE;
		if (enumerate_reserved != NULL) {
			vprint(RSRV_MID, "invalidating %s cache\n",
			    enumerate_file);
		}
		while (enumerate_reserved != NULL) {
			entry = enumerate_reserved;
			enumerate_reserved = entry->er_next;
			free(entry->er_file);
			free(entry->er_id);
			free(entry);
		}
		return;
	}

	/* if already cached, check to see if it is still valid */
	if (cached == TRUE) {

		if (current_sb.st_mtime == cached_sb.st_mtime) {
			vprint(RSRV_MID, "%s cache valid\n", enumerate_file);
			vprint(FILES_MID, "%s cache valid\n", enumerate_file);
			return;
		}

		vprint(RSRV_MID, "invalidating %s cache\n", enumerate_file);
		vprint(FILES_MID, "invalidating %s cache\n", enumerate_file);

		while (enumerate_reserved != NULL) {
			entry = enumerate_reserved;
			enumerate_reserved = entry->er_next;
			free(entry->er_file);
			free(entry->er_id);
			free(entry);
		}
		vprint(RSRV_MID, "Recaching file: %s\n", enumerate_file);
	} else {
		vprint(RSRV_MID, "Caching file (first time): %s\n",
		    enumerate_file);
		cached = TRUE;
	}

	(void) stat(enumerate_file, &cached_sb);

	if ((fp = fopen(enumerate_file, "r")) == NULL) {
		err_print(FOPEN_FAILED, enumerate_file, strerror(errno));
		return;
	}

	vprint(RSRV_MID, "Reading reserve file: %s\n", enumerate_file);
	linenum = 0;
	while (fgets(line, sizeof (line), fp) != NULL) {
		char	*cp, *ncp;

		linenum++;

		/* remove newline */
		cp = strchr(line, '\n');
		if (cp)
			*cp = '\0';

		vprint(RSRV_MID, "Reserve file: line %d: %s\n", linenum, line);

		/* skip over space and tab */
		for (cp = line; *cp == ' ' || *cp == '\t'; cp++)
			;

		if (*cp == '\0' || *cp == '#') {
			vprint(RSRV_MID, "Skipping line: '%s'\n", line);
			continue; /* blank line or comment line */
		}

		ncp = cp;

		/* delete trailing blanks */
		for (; *cp != ' ' && *cp != '\t' && *cp != '\0'; cp++)
			;
		*cp = '\0';

		entry = s_zalloc(sizeof (enumerate_file_t));
		entry->er_file = s_strdup(ncp);
		entry->er_id = NULL;
		entry->er_next = enumerate_reserved;
		enumerate_reserved = entry;
	}

	if (fclose(fp) == EOF) {
		err_print(FCLOSE_FAILED, enumerate_file, strerror(errno));
	}
}

/*
 * Called at devfsadm startup to read in the devlink.tab file.	Creates
 * a linked list of devlinktab_list structures which will be
 * searched for every minor node.
 */
static void
read_devlinktab_file(void)
{
	devlinktab_list_t *headp = NULL;
	devlinktab_list_t *entryp;
	devlinktab_list_t **previous;
	devlinktab_list_t *save;
	char line[MAX_DEVLINK_LINE], *cp;
	char *selector;
	char *p_link;
	char *s_link;
	FILE *fp;
	int i;
	static struct stat cached_sb;
	struct stat current_sb;
	static int cached = FALSE;

	if (devlinktab_file == NULL) {
		return;
	}

	(void) stat(devlinktab_file, &current_sb);

	/* if already cached, check to see if it is still valid */
	if (cached == TRUE) {

		if (current_sb.st_mtime == cached_sb.st_mtime) {
			vprint(FILES_MID, "%s cache valid\n", devlinktab_file);
			return;
		}

		vprint(FILES_MID, "invalidating %s cache\n", devlinktab_file);

		while (devlinktab_list != NULL) {
			free_link_list(devlinktab_list->p_link);
			free_link_list(devlinktab_list->s_link);
			free_selector_list(devlinktab_list->selector);
			free(devlinktab_list->selector_pattern);
			free(devlinktab_list->p_link_pattern);
			if (devlinktab_list->s_link_pattern != NULL) {
				free(devlinktab_list->s_link_pattern);
			}
			save = devlinktab_list;
			devlinktab_list = devlinktab_list->next;
			free(save);
		}
	} else {
		cached = TRUE;
	}

	(void) stat(devlinktab_file, &cached_sb);

	if ((fp = fopen(devlinktab_file, "r")) == NULL) {
		err_print(FOPEN_FAILED, devlinktab_file, strerror(errno));
		return;
	}

	previous = &headp;

	while (fgets(line, sizeof (line), fp) != NULL) {
		devlinktab_line++;
		i = strlen(line);
		if (line[i-1] == NEWLINE) {
			line[i-1] = '\0';
		} else if (i == sizeof (line-1)) {
			err_print(LINE_TOO_LONG, devlinktab_line,
			    devlinktab_file, sizeof (line)-1);
			while (((i = getc(fp)) != '\n') && (i != EOF))
				;
			continue;
		}

		/* cut off comments starting with '#' */
		if ((cp = strchr(line, '#')) != NULL)
			*cp = '\0';
		/* ignore comment or blank lines */
		if (is_blank(line))
			continue;

		vprint(DEVLINK_MID, "table: %s line %d: '%s'\n",
		    devlinktab_file, devlinktab_line, line);

		/* break each entry into fields.  s_link may be NULL */
		if (split_devlinktab_entry(line, &selector, &p_link,
		    &s_link) == DEVFSADM_FAILURE) {
			vprint(DEVLINK_MID, "split_entry returns failure\n");
			continue;
		} else {
			vprint(DEVLINK_MID, "split_entry selector='%s' "
			    "p_link='%s' s_link='%s'\n\n", selector,
			    p_link, (s_link == NULL) ? "" : s_link);
		}

		entryp =
		    (devlinktab_list_t *)s_malloc(sizeof (devlinktab_list_t));

		entryp->line_number = devlinktab_line;

		if ((entryp->selector = create_selector_list(selector))
		    == NULL) {
			free(entryp);
			continue;
		}
		entryp->selector_pattern = s_strdup(selector);

		if ((entryp->p_link = create_link_list(p_link)) == NULL) {
			free_selector_list(entryp->selector);
			free(entryp->selector_pattern);
			free(entryp);
			continue;
		}

		entryp->p_link_pattern = s_strdup(p_link);

		if (s_link != NULL) {
			if ((entryp->s_link =
			    create_link_list(s_link)) == NULL) {
				free_selector_list(entryp->selector);
				free_link_list(entryp->p_link);
				free(entryp->selector_pattern);
				free(entryp->p_link_pattern);
				free(entryp);
				continue;
			}
			entryp->s_link_pattern = s_strdup(s_link);
		} else {
			entryp->s_link = NULL;
			entryp->s_link_pattern = NULL;

		}

		/* append to end of list */

		entryp->next = NULL;
		*previous = entryp;
		previous = &(entryp->next);
	}
	if (fclose(fp) == EOF) {
		err_print(FCLOSE_FAILED, devlinktab_file, strerror(errno));
	}
	devlinktab_list = headp;
}

/*
 *
 * For a single line entry in devlink.tab, split the line into fields
 * selector, p_link, and an optionally s_link.	If s_link field is not
 * present, then return NULL in s_link (not NULL string).
 */
static int
split_devlinktab_entry(char *entry, char **selector, char **p_link,
    char **s_link)
{
	char *tab;

	*selector = entry;

	if ((tab = strchr(entry, TAB)) != NULL) {
		*tab = '\0';
		*p_link = ++tab;
	} else {
		err_print(MISSING_TAB, devlinktab_line, devlinktab_file);
		return (DEVFSADM_FAILURE);
	}

	if (**p_link == '\0') {
		err_print(MISSING_DEVNAME, devlinktab_line, devlinktab_file);
		return (DEVFSADM_FAILURE);
	}

	if ((tab = strchr(*p_link, TAB)) != NULL) {
		*tab = '\0';
		*s_link = ++tab;
		if (strchr(*s_link, TAB) != NULL) {
			err_print(TOO_MANY_FIELDS, devlinktab_line,
			    devlinktab_file);
			return (DEVFSADM_FAILURE);
		}
	} else {
		*s_link = NULL;
	}

	return (DEVFSADM_SUCCESS);
}

/*
 * For a given devfs_spec field, for each element in the field, add it to
 * a linked list of devfs_spec structures.  Return the linked list in
 * devfs_spec_list.
 */
static selector_list_t *
create_selector_list(char *selector)
{
	char *key;
	char *val;
	int error = FALSE;
	selector_list_t *head_selector_list = NULL;
	selector_list_t *selector_list;

	/* parse_devfs_spec splits the next field into keyword & value */
	while ((*selector != NULL) && (error == FALSE)) {
		if (parse_selector(&selector, &key, &val) == DEVFSADM_FAILURE) {
			error = TRUE;
			break;
		} else {
			selector_list = (selector_list_t *)
			    s_malloc(sizeof (selector_list_t));
			if (strcmp(NAME_S, key) == 0) {
				selector_list->key = NAME;
			} else if (strcmp(TYPE_S, key) == 0) {
				selector_list->key = TYPE;
			} else if (strncmp(ADDR_S, key, ADDR_S_LEN) == 0) {
				selector_list->key = ADDR;
				if (key[ADDR_S_LEN] == '\0') {
					selector_list->arg = 0;
				} else if (isdigit(key[ADDR_S_LEN]) != FALSE) {
					selector_list->arg =
					    atoi(&key[ADDR_S_LEN]);
				} else {
					error = TRUE;
					free(selector_list);
					err_print(BADKEYWORD, key,
					    devlinktab_line, devlinktab_file);
					break;
				}
			} else if (strncmp(MINOR_S, key, MINOR_S_LEN) == 0) {
				selector_list->key = MINOR;
				if (key[MINOR_S_LEN] == '\0') {
					selector_list->arg = 0;
				} else if (isdigit(key[MINOR_S_LEN]) != FALSE) {
					selector_list->arg =
					    atoi(&key[MINOR_S_LEN]);
				} else {
					error = TRUE;
					free(selector_list);
					err_print(BADKEYWORD, key,
					    devlinktab_line, devlinktab_file);
					break;
				}
				vprint(DEVLINK_MID, "MINOR = %s\n", val);
			} else {
				err_print(UNRECOGNIZED_KEY, key,
				    devlinktab_line, devlinktab_file);
				error = TRUE;
				free(selector_list);
				break;
			}
			selector_list->val = s_strdup(val);
			selector_list->next = head_selector_list;
			head_selector_list = selector_list;
			vprint(DEVLINK_MID, "key='%s' val='%s' arg=%d\n",
			    key, val, selector_list->arg);
		}
	}

	if ((error == FALSE) && (head_selector_list != NULL)) {
		return (head_selector_list);
	} else {
		/* parse failed.  Free any allocated structs */
		free_selector_list(head_selector_list);
		return (NULL);
	}
}

/*
 * Takes a semicolon separated list of selector elements and breaks up
 * into a keyword-value pair.	semicolon and equal characters are
 * replaced with NULL's.  On success, selector is updated to point to the
 * terminating NULL character terminating the keyword-value pair, and the
 * function returns DEVFSADM_SUCCESS.	If there is a syntax error,
 * devfs_spec is not modified and function returns DEVFSADM_FAILURE.
 */
static int
parse_selector(char **selector, char **key, char **val)
{
	char *equal;
	char *semi_colon;

	*key = *selector;

	if ((equal = strchr(*key, '=')) != NULL) {
		*equal = '\0';
	} else {
		err_print(MISSING_EQUAL, devlinktab_line, devlinktab_file);
		return (DEVFSADM_FAILURE);
	}

	*val = ++equal;
	if ((semi_colon = strchr(equal, ';')) != NULL) {
		*semi_colon = '\0';
		*selector = semi_colon + 1;
	} else {
		*selector = equal + strlen(equal);
	}
	return (DEVFSADM_SUCCESS);
}

/*
 * link is either the second or third field of devlink.tab.  Parse link
 * into a linked list of devlink structures and return ptr to list.  Each
 * list element is either a constant string, or one of the following
 * escape sequences: \M, \A, \N, or \D.  The first three escape sequences
 * take a numerical argument.
 */
static link_list_t *
create_link_list(char *link)
{
	int x = 0;
	int error = FALSE;
	int counter_found = FALSE;
	link_list_t *head = NULL;
	link_list_t **ptr;
	link_list_t *link_list;
	char constant[MAX_DEVLINK_LINE];
	char *error_str;

	if (link == NULL) {
		return (NULL);
	}

	while ((*link != '\0') && (error == FALSE)) {
		link_list = (link_list_t *)s_malloc(sizeof (link_list_t));
		link_list->next = NULL;

		while ((*link != '\0') && (*link != '\\')) {
			/* a non-escaped string */
			constant[x++] = *(link++);
		}
		if (x != 0) {
			constant[x] = '\0';
			link_list->type = CONSTANT;
			link_list->constant = s_strdup(constant);
			x = 0;
			vprint(DEVLINK_MID, "CONSTANT FOUND %s\n", constant);
		} else {
			switch (*(++link)) {
			case 'M':
				link_list->type = MINOR;
				break;
			case 'A':
				link_list->type = ADDR;
				break;
			case 'N':
				if (counter_found == TRUE) {
					error = TRUE;
					error_str =
					    "multiple counters not permitted";
					free(link_list);
				} else {
					counter_found = TRUE;
					link_list->type = COUNTER;
				}
				break;
			case 'D':
				link_list->type = NAME;
				break;
			default:
				error = TRUE;
				free(link_list);
				error_str = "unrecognized escape sequence";
				break;
			}
			if (*(link++) != 'D') {
				if (isdigit(*link) == FALSE) {
					error_str = "escape sequence must be "
					    "followed by a digit\n";
					error = TRUE;
					free(link_list);
				} else {
					link_list->arg =
					    (int)strtoul(link, &link, 10);
					vprint(DEVLINK_MID, "link_list->arg = "
					    "%d\n", link_list->arg);
				}
			}
		}
		/* append link_list struct to end of list */
		if (error == FALSE) {
			for (ptr = &head; *ptr != NULL; ptr = &((*ptr)->next))
				;
			*ptr = link_list;
		}
	}

	if (error == FALSE) {
		return (head);
	} else {
		err_print(CONFIG_INCORRECT, devlinktab_line, devlinktab_file,
		    error_str);
		free_link_list(head);
		return (NULL);
	}
}

/*
 * Called for each minor node devfsadm processes; for each minor node,
 * look for matches in the devlinktab_list list which was created on
 * startup read_devlinktab_file().  If there is a match, call build_links()
 * to build a logical devlink and a possible extra devlink.
 */
static int
process_devlink_compat(di_minor_t minor, di_node_t node)
{
	int link_built = FALSE;
	devlinktab_list_t *entry;
	char *nodetype;
	char *dev_path;

	if (devlinks_debug == TRUE) {
		nodetype =  di_minor_nodetype(minor);
		assert(nodetype != NULL);
		if ((dev_path = di_devfs_path(node)) != NULL) {
			vprint(INFO_MID, "'%s' entry: %s:%s\n",
			    nodetype, dev_path,
			    di_minor_name(minor) ? di_minor_name(minor) : "");
			di_devfs_path_free(dev_path);
		}

	}


	/* don't process devlink.tab if devfsadm invoked with -c <class> */
	if (num_classes > 0) {
		return (FALSE);
	}

	for (entry = devlinktab_list; entry != NULL; entry = entry->next) {
		if (devlink_matches(entry, minor, node) == DEVFSADM_SUCCESS) {
			link_built = TRUE;
			(void) build_links(entry, minor, node);
		}
	}
	return (link_built);
}

/*
 * For a given devlink.tab devlinktab_list entry, see if the selector
 * field matches this minor node.  If it does, return DEVFSADM_SUCCESS,
 * otherwise DEVFSADM_FAILURE.
 */
static int
devlink_matches(devlinktab_list_t *entry, di_minor_t minor, di_node_t node)
{
	selector_list_t *selector = entry->selector;
	char *addr;
	char *minor_name;
	char *node_type;

	for (; selector != NULL; selector = selector->next) {
		switch (selector->key) {
		case NAME:
			if (strcmp(di_node_name(node), selector->val) != 0) {
				return (DEVFSADM_FAILURE);
			}
			break;
		case TYPE:
			node_type = di_minor_nodetype(minor);
			assert(node_type != NULL);
			if (strcmp(node_type, selector->val) != 0) {
				return (DEVFSADM_FAILURE);
			}
			break;
		case ADDR:
			if ((addr = di_bus_addr(node)) == NULL) {
				return (DEVFSADM_FAILURE);
			}
			if (selector->arg == 0) {
				if (strcmp(addr, selector->val) != 0) {
					return (DEVFSADM_FAILURE);
				}
			} else {
				if (compare_field(addr, selector->val,
				    selector->arg) == DEVFSADM_FAILURE) {
					return (DEVFSADM_FAILURE);
				}
			}
			break;
		case MINOR:
			if ((minor_name = di_minor_name(minor)) == NULL) {
				return (DEVFSADM_FAILURE);
			}
			if (selector->arg == 0) {
				if (strcmp(minor_name, selector->val) != 0) {
					return (DEVFSADM_FAILURE);
				}
			} else {
				if (compare_field(minor_name, selector->val,
				    selector->arg) == DEVFSADM_FAILURE) {
					return (DEVFSADM_FAILURE);
				}
			}
			break;
		default:
			return (DEVFSADM_FAILURE);
		}
	}

	return (DEVFSADM_SUCCESS);
}

/*
 * For the given minor node and devlinktab_list entry from devlink.tab,
 * build a logical dev link and a possible extra devlink.
 * Return DEVFSADM_SUCCESS if link is created, otherwise DEVFSADM_FAILURE.
 */
static int
build_links(devlinktab_list_t *entry, di_minor_t minor, di_node_t node)
{
	char secondary_link[PATH_MAX + 1];
	char primary_link[PATH_MAX + 1];
	char contents[PATH_MAX + 1];
	char *dev_path;

	if ((dev_path = di_devfs_path(node)) == NULL) {
		err_print(DI_DEVFS_PATH_FAILED, strerror(errno));
		devfsadm_exit(1);
		/*NOTREACHED*/
	}
	(void) strcpy(contents, dev_path);
	di_devfs_path_free(dev_path);

	(void) strcat(contents, ":");
	(void) strcat(contents, di_minor_name(minor));

	if (construct_devlink(primary_link, entry->p_link, contents,
	    minor, node, entry->p_link_pattern) == DEVFSADM_FAILURE) {
		return (DEVFSADM_FAILURE);
	}
	(void) devfsadm_mklink(primary_link, node, minor, 0);

	if (entry->s_link == NULL) {
		return (DEVFSADM_SUCCESS);
	}

	if (construct_devlink(secondary_link, entry->s_link, primary_link,
	    minor, node, entry->s_link_pattern) == DEVFSADM_FAILURE) {
		return (DEVFSADM_FAILURE);
	}

	(void) devfsadm_secondary_link(secondary_link, primary_link, 0);

	return (DEVFSADM_SUCCESS);
}

/*
 * The counter rule for devlink.tab entries is implemented via
 * devfsadm_enumerate_int_start(). One of the arguments to this function
 * is a path, where each path component is treated as a regular expression.
 * For devlink.tab entries, this path regular expression is derived from
 * the devlink spec. get_anchored_re() accepts path regular expressions derived
 * from devlink.tab entries and inserts the anchors '^' and '$' at the beginning
 * and end respectively of each path component. This is done to prevent
 * false matches. For example, without anchors, "a/([0-9]+)" will match "ab/c9"
 * and incorrect links will be generated.
 */
static int
get_anchored_re(char *link, char *anchored_re, char *pattern)
{
	if (*link == '/' || *link == '\0') {
		err_print(INVALID_DEVLINK_SPEC, pattern);
		return (DEVFSADM_FAILURE);
	}

	*anchored_re++ = '^';
	for (; *link != '\0'; ) {
		if (*link == '/') {
			while (*link == '/')
				link++;
			*anchored_re++ = '$';
			*anchored_re++ = '/';
			if (*link != '\0') {
				*anchored_re++ = '^';
			}
		} else {
			*anchored_re++ = *link++;
			if (*link == '\0') {
				*anchored_re++ = '$';
			}
		}
	}
	*anchored_re = '\0';

	return (DEVFSADM_SUCCESS);
}

static int
construct_devlink(char *link, link_list_t *link_build, char *contents,
    di_minor_t minor, di_node_t node, char *pattern)
{
	int counter_offset = -1;
	devfsadm_enumerate_t rules[1] = {NULL};
	char templink[PATH_MAX + 1];
	char *buff;
	char start[10];
	char *node_path;
	char anchored_re[PATH_MAX + 1];

	link[0] = '\0';

	for (; link_build != NULL; link_build = link_build->next) {
		switch (link_build->type) {
		case NAME:
			(void) strcat(link, di_node_name(node));
			break;
		case CONSTANT:
			(void) strcat(link, link_build->constant);
			break;
		case ADDR:
			if (component_cat(link, di_bus_addr(node),
			    link_build->arg) == DEVFSADM_FAILURE) {
				node_path = di_devfs_path(node);
				err_print(CANNOT_BE_USED, pattern, node_path,
				    di_minor_name(minor));
				di_devfs_path_free(node_path);
				return (DEVFSADM_FAILURE);
			}
			break;
		case MINOR:
			if (component_cat(link, di_minor_name(minor),
			    link_build->arg) == DEVFSADM_FAILURE) {
				node_path = di_devfs_path(node);
				err_print(CANNOT_BE_USED, pattern, node_path,
				    di_minor_name(minor));
				di_devfs_path_free(node_path);
				return (DEVFSADM_FAILURE);
			}
			break;
		case COUNTER:
			counter_offset = strlen(link);
			(void) strcat(link, "([0-9]+)");
			(void) sprintf(start, "%d", link_build->arg);
			break;
		default:
			return (DEVFSADM_FAILURE);
		}
	}

	if (counter_offset != -1) {
		/*
		 * copy anything appended after "([0-9]+)" into
		 * templink
		 */

		(void) strcpy(templink,
		    &link[counter_offset + strlen("([0-9]+)")]);
		if (get_anchored_re(link, anchored_re, pattern)
		    != DEVFSADM_SUCCESS) {
			return (DEVFSADM_FAILURE);
		}
		rules[0].re = anchored_re;
		rules[0].subexp = 1;
		rules[0].flags = MATCH_ALL;
		if (devfsadm_enumerate_int_start(contents, 0, &buff,
		    rules, 1, start) == DEVFSADM_FAILURE) {
			return (DEVFSADM_FAILURE);
		}
		(void) strcpy(&link[counter_offset], buff);
		free(buff);
		(void) strcat(link, templink);
		vprint(DEVLINK_MID, "COUNTER is	%s\n", link);
	}
	return (DEVFSADM_SUCCESS);
}

/*
 * Compares "field" number of the comma separated list "full_name" with
 * field_item.	Returns DEVFSADM_SUCCESS for match,
 * DEVFSADM_FAILURE for no match.
 */
static int
compare_field(char *full_name, char *field_item, int field)
{
	--field;
	while ((*full_name != '\0') && (field != 0)) {
		if (*(full_name++) == ',') {
			field--;
		}
	}

	if (field != 0) {
		return (DEVFSADM_FAILURE);
	}

	while ((*full_name != '\0') && (*field_item != '\0') &&
	    (*full_name != ',')) {
		if (*(full_name++) != *(field_item++)) {
			return (DEVFSADM_FAILURE);
		}
	}

	if (*field_item != '\0') {
		return (DEVFSADM_FAILURE);
	}

	if ((*full_name == '\0') || (*full_name == ','))
		return (DEVFSADM_SUCCESS);

	return (DEVFSADM_FAILURE);
}

/*
 * strcat() field # "field" of comma separated list "name" to "link".
 * Field 0 is the entire name.
 * Return DEVFSADM_SUCCESS or DEVFSADM_FAILURE.
 */
static int
component_cat(char *link, char *name, int field)
{

	if (name == NULL) {
		return (DEVFSADM_FAILURE);
	}

	if (field == 0) {
		(void) strcat(link, name);
		return (DEVFSADM_SUCCESS);
	}

	while (*link != '\0') {
		link++;
	}

	--field;
	while ((*name != '\0') && (field != 0)) {
		if (*(name++) == ',') {
			--field;
		}
	}

	if (field != 0) {
		return (DEVFSADM_FAILURE);
	}

	while ((*name != '\0') && (*name != ',')) {
		*(link++) = *(name++);
	}

	*link = '\0';
	return (DEVFSADM_SUCCESS);
}

static void
free_selector_list(selector_list_t *head)
{
	selector_list_t *temp;

	while (head != NULL) {
		temp = head;
		head = head->next;
		free(temp->val);
		free(temp);
	}
}

static void
free_link_list(link_list_t *head)
{
	link_list_t *temp;

	while (head != NULL) {
		temp = head;
		head = head->next;
		if (temp->type == CONSTANT) {
			free(temp->constant);
		}
		free(temp);
	}
}

/*
 * Prints only if level matches one of the debug levels
 * given on command line.  INFO_MID is always printed.
 *
 * See devfsadm.h for a listing of globally defined levels and
 * meanings.  Modules should prefix the level with their
 * module name to prevent collisions.
 */
/*PRINTFLIKE2*/
void
devfsadm_print(char *msgid, char *message, ...)
{
	va_list ap;
	static int newline = TRUE;
	int x;

	if (msgid != NULL) {
		for (x = 0; x < num_verbose; x++) {
			if (strcmp(verbose[x], msgid) == 0) {
				break;
			}
			if (strcmp(verbose[x], ALL_MID) == 0) {
				break;
			}
		}
		if (x == num_verbose) {
			return;
		}
	}

	va_start(ap, message);

	if (msgid == NULL) {
		if (logflag == TRUE) {
			(void) vsyslog(LOG_NOTICE, message, ap);
		} else {
			(void) vfprintf(stdout, message, ap);
		}

	} else {
		if (logflag == TRUE) {
			(void) syslog(LOG_DEBUG, "%s[%ld]: %s: ",
			    prog, getpid(), msgid);
			(void) vsyslog(LOG_DEBUG, message, ap);
		} else {
			if (newline == TRUE) {
				(void) fprintf(stdout, "%s[%ld]: %s: ",
				    prog, getpid(), msgid);
			}
			(void) vfprintf(stdout, message, ap);
		}
	}

	if (message[strlen(message) - 1] == '\n') {
		newline = TRUE;
	} else {
		newline = FALSE;
	}
	va_end(ap);
}

/*
 * print error messages to the terminal or to syslog
 */
/*PRINTFLIKE1*/
void
devfsadm_errprint(char *message, ...)
{
	va_list ap;

	va_start(ap, message);

	if (logflag == TRUE) {
		(void) vsyslog(LOG_ERR, message, ap);
	} else {
		(void) fprintf(stderr, "%s: ", prog);
		(void) vfprintf(stderr, message, ap);
	}
	va_end(ap);
}

/*
 * return noupdate state (-s)
 */
int
devfsadm_noupdate(void)
{
	return (file_mods == TRUE ? DEVFSADM_TRUE : DEVFSADM_FALSE);
}

/*
 * return current root update path (-r)
 */
const char *
devfsadm_root_path(void)
{
	if (root_dir[0] == '\0') {
		return ("/");
	} else {
		return ((const char *)root_dir);
	}
}

void
devfsadm_free_dev_names(char **dev_names, int len)
{
	int i;

	for (i = 0; i < len; i++)
		free(dev_names[i]);
	free(dev_names);
}

/*
 * Return all devlinks corresponding to phys_path as an array of strings.
 * The number of entries in the array is returned through lenp.
 * devfsadm_free_dev_names() is used to free the returned array.
 * NULL is returned on failure or when there are no matching devlinks.
 *
 * re is an extended regular expression in regex(5) format used to further
 * match devlinks pointing to phys_path; it may be NULL to match all
 */
char **
devfsadm_lookup_dev_names(char *phys_path, char *re, int *lenp)
{
	struct devlink_cb_arg cb_arg;
	char **dev_names = NULL;
	int i;

	*lenp = 0;
	cb_arg.count = 0;
	cb_arg.rv = 0;
	(void) di_devlink_cache_walk(devlink_cache, re, phys_path,
	    DI_PRIMARY_LINK, &cb_arg, devlink_cb);

	if (cb_arg.rv == -1 || cb_arg.count <= 0)
		return (NULL);

	dev_names = s_malloc(cb_arg.count * sizeof (char *));
	if (dev_names == NULL)
		goto out;

	for (i = 0; i < cb_arg.count; i++) {
		dev_names[i] = s_strdup(cb_arg.dev_names[i]);
		if (dev_names[i] == NULL) {
			devfsadm_free_dev_names(dev_names, i);
			dev_names = NULL;
			goto out;
		}
	}
	*lenp = cb_arg.count;

out:
	free_dev_names(&cb_arg);
	return (dev_names);
}

/* common exit function which ensures releasing locks */
static void
devfsadm_exit(int status)
{
	if (DEVFSADM_DEBUG_ON) {
		vprint(INFO_MID, "exit status = %d\n", status);
	}

	exit_dev_lock(1);
	exit_daemon_lock(1);

	if (logflag == TRUE) {
		closelog();
	}

	exit(status);
	/*NOTREACHED*/
}

/*
 * set root_dir, devices_dir, dev_dir using optarg.
 */
static void
set_root_devices_dev_dir(char *dir)
{
	size_t len;

	root_dir = s_strdup(dir);
	len = strlen(dir) + strlen(DEVICES) + 1;
	devices_dir = s_malloc(len);
	(void) snprintf(devices_dir, len, "%s%s", root_dir, DEVICES);
	len = strlen(root_dir) + strlen(DEV) + 1;
	dev_dir = s_malloc(len);
	(void) snprintf(dev_dir, len, "%s%s", root_dir, DEV);
}

/*
 * Removes quotes.
 */
static char *
dequote(char *src)
{
	char	*dst;
	int	len;

	len = strlen(src);
	dst = s_malloc(len + 1);
	if (src[0] == '\"' && src[len - 1] == '\"') {
		len -= 2;
		(void) strncpy(dst, &src[1], len);
		dst[len] = '\0';
	} else {
		(void) strcpy(dst, src);
	}
	return (dst);
}

/*
 * For a given physical device pathname and spectype, return the
 * ownership and permissions attributes by looking in data from
 * /etc/minor_perm.  If currently in installation mode, check for
 * possible major number translations from the miniroot to the installed
 * root's name_to_major table. Note that there can be multiple matches,
 * but the last match takes effect.  pts seems to rely on this
 * implementation behavior.
 */
static void
getattr(char *phy_path, char *aminor, int spectype, dev_t dev, mode_t *mode,
    uid_t *uid, gid_t *gid)
{
	char devname[PATH_MAX + 1];
	char *node_name;
	char *minor_name;
	int match = FALSE;
	int is_clone;
	int mp_drvname_matches_node_name;
	int mp_drvname_matches_minor_name;
	int mp_drvname_is_clone;
	int mp_drvname_matches_drvname;
	struct mperm *mp;
	major_t major_no;
	char driver[PATH_MAX + 1];

	/*
	 * Get the driver name based on the major number since the name
	 * in /devices may be generic.  Could be running with more major
	 * numbers than are in /etc/name_to_major, so get it from the kernel
	 */
	major_no = major(dev);

	if (modctl(MODGETNAME, driver, sizeof (driver), &major_no) != 0) {
		/* return default values */
		goto use_defaults;
	}

	(void) strcpy(devname, phy_path);

	node_name = strrchr(devname, '/'); /* node name is the last */
					/* component */
	if (node_name == NULL) {
		err_print(NO_NODE, devname);
		goto use_defaults;
	}

	minor_name = strchr(++node_name, '@'); /* see if it has address part */

	if (minor_name != NULL) {
		*minor_name++ = '\0';
	} else {
		minor_name = node_name;
	}

	minor_name = strchr(minor_name, ':'); /* look for minor name */

	if (minor_name == NULL) {
		err_print(NO_MINOR, devname);
		goto use_defaults;
	}
	*minor_name++ = '\0';

	/*
	 * mp->mp_drvname = device name from minor_perm
	 * mp->mp_minorname = minor part of device name from
	 * minor_perm
	 * drvname = name of driver for this device
	 */

	is_clone = (strcmp(node_name, "clone") == 0 ? TRUE : FALSE);
	for (mp = minor_perms; mp != NULL; mp = mp->mp_next) {
		mp_drvname_matches_node_name =
		    (strcmp(mp->mp_drvname, node_name) == 0 ? TRUE : FALSE);
		mp_drvname_matches_minor_name =
		    (strcmp(mp->mp_drvname, minor_name) == 0  ? TRUE:FALSE);
		mp_drvname_is_clone =
		    (strcmp(mp->mp_drvname, "clone") == 0  ? TRUE : FALSE);
		mp_drvname_matches_drvname =
		    (strcmp(mp->mp_drvname, driver) == 0  ? TRUE : FALSE);

		/*
		 * If one of the following cases is true, then we try to change
		 * the permissions if a "shell global pattern match" of
		 * mp_>mp_minorname matches minor_name.
		 *
		 * 1.  mp->mp_drvname matches driver.
		 *
		 * OR
		 *
		 * 2.  mp->mp_drvname matches node_name and this
		 *	name is an alias of the driver name
		 *
		 * OR
		 *
		 * 3.  /devices entry is the clone device and either
		 *	minor_perm entry is the clone device or matches
		 *	the minor part of the clone device.
		 */

		if ((mp_drvname_matches_drvname == TRUE)||
		    ((mp_drvname_matches_node_name == TRUE) &&
		    (alias(driver, node_name) == TRUE)) ||
		    ((is_clone == TRUE) &&
		    ((mp_drvname_is_clone == TRUE) ||
		    (mp_drvname_matches_minor_name == TRUE)))) {
			/*
			 * Check that the minor part of the
			 * device name from the minor_perm
			 * entry matches and if so, set the
			 * permissions.
			 *
			 * Under real devfs, clone minor name is changed
			 * to match the driver name, but minor_perm may
			 * not match. We reconcile it here.
			 */
			if (aminor != NULL)
				minor_name = aminor;

			if (gmatch(minor_name, mp->mp_minorname) != 0) {
				*uid = mp->mp_uid;
				*gid = mp->mp_gid;
				*mode = spectype | mp->mp_mode;
				match = TRUE;
			}
		}
	}

	if (match == TRUE) {
		return;
	}

	use_defaults:
	/* not found in minor_perm, so just use default values */
	*uid = root_uid;
	*gid = sys_gid;
	*mode = (spectype | 0600);
}

/*
 * Called by devfs_read_minor_perm() to report errors
 * key is:
 *	line number: ignoring line number error
 *	errno: open/close errors
 *	size: alloc errors
 */
static void
minorperm_err_cb(minorperm_err_t mp_err, int key)
{
	switch (mp_err) {
	case MP_FOPEN_ERR:
		err_print(FOPEN_FAILED, MINOR_PERM_FILE, strerror(key));
		break;
	case MP_FCLOSE_ERR:
		err_print(FCLOSE_FAILED, MINOR_PERM_FILE, strerror(key));
		break;
	case MP_IGNORING_LINE_ERR:
		err_print(IGNORING_LINE_IN, key, MINOR_PERM_FILE);
		break;
	case MP_ALLOC_ERR:
		err_print(MALLOC_FAILED, key);
		break;
	case MP_NVLIST_ERR:
		err_print(NVLIST_ERROR, MINOR_PERM_FILE, strerror(key));
		break;
	case MP_CANT_FIND_USER_ERR:
		err_print(CANT_FIND_USER, DEFAULT_DEV_USER);
		break;
	case MP_CANT_FIND_GROUP_ERR:
		err_print(CANT_FIND_GROUP, DEFAULT_DEV_GROUP);
		break;
	}
}

static void
read_minor_perm_file(void)
{
	static int cached = FALSE;
	static struct stat cached_sb;
	struct stat current_sb;

	(void) stat(MINOR_PERM_FILE, &current_sb);

	/* If already cached, check to see if it is still valid */
	if (cached == TRUE) {

		if (current_sb.st_mtime == cached_sb.st_mtime) {
			vprint(FILES_MID, "%s cache valid\n", MINOR_PERM_FILE);
			return;
		}
		devfs_free_minor_perm(minor_perms);
		minor_perms = NULL;
	} else {
		cached = TRUE;
	}

	(void) stat(MINOR_PERM_FILE, &cached_sb);

	vprint(FILES_MID, "loading binding file: %s\n", MINOR_PERM_FILE);

	minor_perms = devfs_read_minor_perm(minorperm_err_cb);
}

static void
load_minor_perm_file(void)
{
	read_minor_perm_file();
	if (devfs_load_minor_perm(minor_perms, minorperm_err_cb) != 0)
		err_print(gettext("minor_perm load failed\n"));
}

static char *
convert_to_re(char *dev)
{
	char *p, *l, *out;
	int i;

	out = s_malloc(PATH_MAX);

	for (l = p = dev, i = 0; (*p != '\0') && (i < (PATH_MAX - 1));
	    ++p, i++) {
		if ((*p == '*') && ((l != p) && (*l == '/'))) {
			out[i++] = '.';
			out[i] = '+';
		} else {
			out[i] = *p;
		}
		l = p;
	}
	out[i] = '\0';
	p = (char *)s_malloc(strlen(out) + 1);
	(void) strlcpy(p, out, strlen(out) + 1);
	free(out);

	vprint(FILES_MID, "converted %s -> %s\n", dev, p);

	return (p);
}

static void
read_logindevperm_file(void)
{
	static int cached = FALSE;
	static struct stat cached_sb;
	struct stat current_sb;
	struct login_dev *ldev;
	FILE *fp;
	char line[MAX_LDEV_LINE];
	int ln, perm, rv;
	char *cp, *console, *dlist, *dev;
	char *lasts, *devlasts, *permstr, *drv;
	struct driver_list *list, *next;

	/* Read logindevperm only when enabled */
	if (login_dev_enable != TRUE)
		return;

	if (cached == TRUE) {
		if (stat(LDEV_FILE, &current_sb) == 0 &&
		    current_sb.st_mtime == cached_sb.st_mtime) {
			vprint(FILES_MID, "%s cache valid\n", LDEV_FILE);
			return;
		}
		vprint(FILES_MID, "invalidating %s cache\n", LDEV_FILE);
		while (login_dev_cache != NULL) {

			ldev = login_dev_cache;
			login_dev_cache = ldev->ldev_next;
			free(ldev->ldev_console);
			free(ldev->ldev_device);
			regfree(&ldev->ldev_device_regex);
			list = ldev->ldev_driver_list;
			while (list) {
				next = list->next;
				free(list);
				list = next;
			}
			free(ldev);
		}
	} else {
		cached = TRUE;
	}

	assert(login_dev_cache == NULL);

	if (stat(LDEV_FILE, &cached_sb) != 0) {
		cached = FALSE;
		return;
	}

	vprint(FILES_MID, "loading file: %s\n", LDEV_FILE);

	if ((fp = fopen(LDEV_FILE, "r")) == NULL) {
		/* Not fatal to devfsadm */
		cached = FALSE;
		err_print(FOPEN_FAILED, LDEV_FILE, strerror(errno));
		return;
	}

	ln = 0;
	while (fgets(line, MAX_LDEV_LINE, fp) != NULL) {
		ln++;

		/* Remove comments */
		if ((cp = strchr(line, '#')) != NULL)
			*cp = '\0';

		if ((console = strtok_r(line, LDEV_DELIMS, &lasts)) == NULL)
			continue;	/* Blank line */

		if ((permstr =  strtok_r(NULL, LDEV_DELIMS, &lasts)) == NULL) {
			err_print(IGNORING_LINE_IN, ln, LDEV_FILE);
			continue;	/* Malformed line */
		}

		/*
		 * permstr is string in octal format. Convert to int
		 */
		cp = NULL;
		errno = 0;
		perm = strtol(permstr, &cp, 8);
		if (errno || perm < 0 || perm > 0777 || *cp != '\0') {
			err_print(IGNORING_LINE_IN, ln, LDEV_FILE);
			continue;
		}

		if ((dlist = strtok_r(NULL, LDEV_DELIMS, &lasts)) == NULL) {
			err_print(IGNORING_LINE_IN, ln, LDEV_FILE);
			continue;
		}

		dev = strtok_r(dlist, LDEV_DEV_DELIM, &devlasts);
		while (dev) {

			ldev = (struct login_dev *)s_zalloc(
			    sizeof (struct login_dev));
			ldev->ldev_console = s_strdup(console);
			ldev->ldev_perms = perm;

			/*
			 * the logical device name may contain '*' which
			 * we convert to a regular expression
			 */
			ldev->ldev_device = convert_to_re(dev);
			if (ldev->ldev_device &&
			    (rv = regcomp(&ldev->ldev_device_regex,
			    ldev->ldev_device, REG_EXTENDED))) {
				bzero(&ldev->ldev_device_regex,
				    sizeof (ldev->ldev_device_regex));
				err_print(REGCOMP_FAILED,
				    ldev->ldev_device, rv);
			}
			ldev->ldev_next = login_dev_cache;
			login_dev_cache = ldev;
			dev = strtok_r(NULL, LDEV_DEV_DELIM, &devlasts);
		}

		drv = strtok_r(NULL, LDEV_DRVLIST_DELIMS, &lasts);
		if (drv) {
			if (strcmp(drv, LDEV_DRVLIST_NAME) == 0) {

				drv = strtok_r(NULL, LDEV_DRV_DELIMS, &lasts);

				while (drv) {
					vprint(FILES_MID,
					    "logindevperm driver=%s\n", drv);

					/*
					 * create a linked list of driver
					 * names
					 */
					list = (struct driver_list *)
					    s_zalloc(
					    sizeof (struct driver_list));
					(void) strlcpy(list->driver_name, drv,
					    sizeof (list->driver_name));
					list->next = ldev->ldev_driver_list;
					ldev->ldev_driver_list = list;
					drv = strtok_r(NULL, LDEV_DRV_DELIMS,
					    &lasts);
				}
			}
		}
	}
	(void) fclose(fp);
}

/*
 * Tokens are separated by ' ', '\t', ':', '=', '&', '|', ';', '\n', or '\0'
 *
 * Returns DEVFSADM_SUCCESS if token found, DEVFSADM_FAILURE otherwise.
 */
static int
getnexttoken(char *next, char **nextp, char **tokenpp, char *tchar)
{
	char *cp;
	char *cp1;
	char *tokenp;

	cp = next;
	while (*cp == ' ' || *cp == '\t') {
		cp++;			/* skip leading spaces */
	}
	tokenp = cp;			/* start of token */
	while (*cp != '\0' && *cp != '\n' && *cp != ' ' && *cp != '\t' &&
	    *cp != ':' && *cp != '=' && *cp != '&' &&
	    *cp != '|' && *cp != ';') {
		cp++;			/* point to next character */
	}
	/*
	 * If terminating character is a space or tab, look ahead to see if
	 * there's another terminator that's not a space or a tab.
	 * (This code handles trailing spaces.)
	 */
	if (*cp == ' ' || *cp == '\t') {
		cp1 = cp;
		while (*++cp1 == ' ' || *cp1 == '\t')
			;
		if (*cp1 == '=' || *cp1 == ':' || *cp1 == '&' || *cp1 == '|' ||
		    *cp1 == ';' || *cp1 == '\n' || *cp1 == '\0') {
			*cp = NULL;	/* terminate token */
			cp = cp1;
		}
	}
	if (tchar != NULL) {
		*tchar = *cp;		/* save terminating character */
		if (*tchar == '\0') {
			*tchar = '\n';
		}
	}
	*cp++ = '\0';			/* terminate token, point to next */
	*nextp = cp;			/* set pointer to next character */
	if (cp - tokenp - 1 == 0) {
		return (DEVFSADM_FAILURE);
	}
	*tokenpp = tokenp;
	return (DEVFSADM_SUCCESS);
}

/*
 * read or reread the driver aliases file
 */
static void
read_driver_aliases_file(void)
{

	driver_alias_t *save;
	driver_alias_t *lst_tail;
	driver_alias_t *ap;
	static int cached = FALSE;
	FILE *afd;
	char line[256];
	char *cp;
	char *p;
	char t;
	int ln = 0;
	static struct stat cached_sb;
	struct stat current_sb;

	(void) stat(ALIASFILE, &current_sb);

	/* If already cached, check to see if it is still valid */
	if (cached == TRUE) {

		if (current_sb.st_mtime == cached_sb.st_mtime) {
			vprint(FILES_MID, "%s cache valid\n", ALIASFILE);
			return;
		}

		vprint(FILES_MID, "invalidating %s cache\n", ALIASFILE);
		while (driver_aliases != NULL) {
			free(driver_aliases->alias_name);
			free(driver_aliases->driver_name);
			save = driver_aliases;
			driver_aliases = driver_aliases->next;
			free(save);
		}
	} else {
		cached = TRUE;
	}

	(void) stat(ALIASFILE, &cached_sb);

	vprint(FILES_MID, "loading binding file: %s\n", ALIASFILE);

	if ((afd = fopen(ALIASFILE, "r")) == NULL) {
		err_print(FOPEN_FAILED, ALIASFILE, strerror(errno));
		devfsadm_exit(1);
		/*NOTREACHED*/
	}

	while (fgets(line, sizeof (line), afd) != NULL) {
		ln++;
		/* cut off comments starting with '#' */
		if ((cp = strchr(line, '#')) != NULL)
			*cp = '\0';
		/* ignore comment or blank lines */
		if (is_blank(line))
			continue;
		cp = line;
		if (getnexttoken(cp, &cp, &p, &t) == DEVFSADM_FAILURE) {
			err_print(IGNORING_LINE_IN, ln, ALIASFILE);
			continue;
		}
		if (t == '\n' || t == '\0') {
			err_print(DRV_BUT_NO_ALIAS, ln, ALIASFILE);
			continue;
		}
		ap = (struct driver_alias *)
		    s_zalloc(sizeof (struct driver_alias));
		ap->driver_name = s_strdup(p);
		if (getnexttoken(cp, &cp, &p, &t) == DEVFSADM_FAILURE) {
			err_print(DRV_BUT_NO_ALIAS, ln, ALIASFILE);
			free(ap->driver_name);
			free(ap);
			continue;
		}
		if (*p == '"') {
			if (p[strlen(p) - 1] == '"') {
				p[strlen(p) - 1] = '\0';
				p++;
			}
		}
		ap->alias_name = s_strdup(p);
		if (driver_aliases == NULL) {
			driver_aliases = ap;
			lst_tail = ap;
		} else {
			lst_tail->next = ap;
			lst_tail = ap;
		}
	}
	if (fclose(afd) == EOF) {
		err_print(FCLOSE_FAILED, ALIASFILE, strerror(errno));
	}
}

/*
 * return TRUE if alias_name is an alias for driver_name, otherwise
 * return FALSE.
 */
static int
alias(char *driver_name, char *alias_name)
{
	driver_alias_t *alias;

	/*
	 * check for a match
	 */
	for (alias = driver_aliases; alias != NULL; alias = alias->next) {
		if ((strcmp(alias->driver_name, driver_name) == 0) &&
		    (strcmp(alias->alias_name, alias_name) == 0)) {
			return (TRUE);
		}
	}
	return (FALSE);
}

/*
 * convenience functions
 */
static int
s_stat(const char *path, struct stat *sbufp)
{
	int rv;
retry:
	if ((rv = stat(path, sbufp)) == -1) {
		if (errno == EINTR)
			goto retry;
	}
	return (rv);
}

static void *
s_malloc(const size_t size)
{
	void *rp;

	rp = malloc(size);
	if (rp == NULL) {
		err_print(MALLOC_FAILED, size);
		devfsadm_exit(1);
		/*NOTREACHED*/
	}
	return (rp);
}

/*
 * convenience functions
 */
static void *
s_realloc(void *ptr, const size_t size)
{
	ptr = realloc(ptr, size);
	if (ptr == NULL) {
		err_print(REALLOC_FAILED, size);
		devfsadm_exit(1);
		/*NOTREACHED*/
	}
	return (ptr);
}

static void *
s_zalloc(const size_t size)
{
	void *rp;

	rp = calloc(1, size);
	if (rp == NULL) {
		err_print(CALLOC_FAILED, size);
		devfsadm_exit(1);
		/*NOTREACHED*/
	}
	return (rp);
}

char *
s_strdup(const char *ptr)
{
	void *rp;

	rp = strdup(ptr);
	if (rp == NULL) {
		err_print(STRDUP_FAILED, ptr);
		devfsadm_exit(1);
		/*NOTREACHED*/
	}
	return (rp);
}

static void
s_closedir(DIR *dirp)
{
retry:
	if (closedir(dirp) != 0) {
		if (errno == EINTR)
			goto retry;
		err_print(CLOSEDIR_FAILED, strerror(errno));
	}
}

static void
s_mkdirp(const char *path, const mode_t mode)
{
	vprint(CHATTY_MID, "mkdirp(%s, 0x%lx)\n", path, mode);
	if (mkdirp(path, mode) == -1) {
		if (errno != EEXIST) {
			err_print(MKDIR_FAILED, path, mode, strerror(errno));
		}
	}
}

static void
s_unlink(const char *file)
{
retry:
	if (unlink(file) == -1) {
		if (errno == EINTR || errno == EAGAIN)
			goto retry;
		if (errno != ENOENT) {
			err_print(UNLINK_FAILED, file, strerror(errno));
		}
	}
}

static void
add_verbose_id(char *mid)
{
	num_verbose++;
	verbose = s_realloc(verbose, num_verbose * sizeof (char *));
	verbose[num_verbose - 1] = mid;
}

/*
 * returns DEVFSADM_TRUE if contents is a minor node in /devices.
 * If mn_root is not NULL, mn_root is set to:
 *	if contents is a /dev node, mn_root = contents
 * 			OR
 *	if contents is a /devices node, mn_root set to the '/'
 *	following /devices.
 */
static int
is_minor_node(char *contents, char **mn_root)
{
	char *ptr;
	char device_prefix[100];

	(void) snprintf(device_prefix, sizeof (device_prefix), "../devices/");

	if ((ptr = strstr(contents, device_prefix)) != NULL) {
		if (mn_root != NULL) {
			/* mn_root should point to the / following /devices */
			*mn_root = ptr += strlen(device_prefix) - 1;
		}
		return (DEVFSADM_TRUE);
	}

	(void) snprintf(device_prefix, sizeof (device_prefix), "/devices/");

	if (strncmp(contents, device_prefix, strlen(device_prefix)) == 0) {
		if (mn_root != NULL) {
			/* mn_root should point to the / following /devices */
			*mn_root = contents + strlen(device_prefix) - 1;
		}
		return (DEVFSADM_TRUE);
	}

	if (mn_root != NULL) {
		*mn_root = contents;
	}
	return (DEVFSADM_FALSE);
}

/*
 * Add the specified property to nvl.
 * Returns:
 *   0	successfully added
 *   -1	an error occurred
 *   1	could not add the property for reasons not due to errors.
 */
static int
add_property(nvlist_t *nvl, di_prop_t prop)
{
	char *name;
	char *attr_name;
	int n, len;
	int32_t *int32p;
	int64_t *int64p;
	char *str;
	char **strarray;
	uchar_t *bytep;
	int rv = 0;
	int i;

	if ((name = di_prop_name(prop)) == NULL)
		return (-1);

	len = sizeof (DEV_PROP_PREFIX) + strlen(name);
	if ((attr_name = malloc(len)) == NULL)
		return (-1);

	(void) strlcpy(attr_name, DEV_PROP_PREFIX, len);
	(void) strlcat(attr_name, name, len);

	switch (di_prop_type(prop)) {
	case DI_PROP_TYPE_BOOLEAN:
		if (nvlist_add_boolean(nvl, attr_name) != 0)
			goto out;
		break;

	case DI_PROP_TYPE_INT:
		if ((n = di_prop_ints(prop, &int32p)) < 1)
			goto out;

		if (n <= (PROP_LEN_LIMIT / sizeof (int32_t))) {
			if (nvlist_add_int32_array(nvl, attr_name, int32p,
			    n) != 0)
				goto out;
		} else
			rv = 1;
		break;

	case DI_PROP_TYPE_INT64:
		if ((n = di_prop_int64(prop, &int64p)) < 1)
			goto out;

		if (n <= (PROP_LEN_LIMIT / sizeof (int64_t))) {
			if (nvlist_add_int64_array(nvl, attr_name, int64p,
			    n) != 0)
				goto out;
		} else
			rv = 1;
		break;

	case DI_PROP_TYPE_BYTE:
	case DI_PROP_TYPE_UNKNOWN:
		if ((n = di_prop_bytes(prop, &bytep)) < 1)
			goto out;

		if (n <= PROP_LEN_LIMIT) {
			if (nvlist_add_byte_array(nvl, attr_name, bytep, n)
			    != 0)
				goto out;
		} else
			rv = 1;
		break;

	case DI_PROP_TYPE_STRING:
		if ((n = di_prop_strings(prop, &str)) < 1)
			goto out;

		if ((strarray = malloc(n * sizeof (char *))) == NULL)
			goto out;

		len = 0;
		for (i = 0; i < n; i++) {
			strarray[i] = str + len;
			len += strlen(strarray[i]) + 1;
		}

		if (len <= PROP_LEN_LIMIT) {
			if (nvlist_add_string_array(nvl, attr_name, strarray,
			    n) != 0) {
				free(strarray);
				goto out;
			}
		} else
			rv = 1;
		free(strarray);
		break;

	default:
		rv = 1;
		break;
	}

	free(attr_name);
	return (rv);

out:
	free(attr_name);
	return (-1);
}

static void
free_dev_names(struct devlink_cb_arg *x)
{
	int i;

	for (i = 0; i < x->count; i++) {
		free(x->dev_names[i]);
		free(x->link_contents[i]);
	}
}

/* callback function for di_devlink_cache_walk */
static int
devlink_cb(di_devlink_t dl, void *arg)
{
	struct devlink_cb_arg *x = (struct devlink_cb_arg *)arg;
	const char *path;
	const char *content;

	if ((path = di_devlink_path(dl)) == NULL ||
	    (content = di_devlink_content(dl)) == NULL ||
	    (x->dev_names[x->count] = s_strdup(path)) == NULL)
		goto out;

	if ((x->link_contents[x->count] = s_strdup(content)) == NULL) {
		free(x->dev_names[x->count]);
		goto out;
	}

	x->count++;
	if (x->count >= MAX_DEV_NAME_COUNT)
		return (DI_WALK_TERMINATE);

	return (DI_WALK_CONTINUE);

out:
	x->rv = -1;
	free_dev_names(x);
	return (DI_WALK_TERMINATE);
}

/*
 * Lookup dev name corresponding to the phys_path.
 * phys_path is path to a node or minor node.
 * Returns:
 *	0 with *dev_name set to the dev name
 *		Lookup succeeded and dev_name found
 *	0 with *dev_name set to NULL
 *		Lookup encountered no errors but dev name not found
 *	-1
 *		Lookup failed
 */
static int
lookup_dev_name(char *phys_path, char **dev_name)
{
	struct devlink_cb_arg cb_arg;

	*dev_name = NULL;

	cb_arg.count = 0;
	cb_arg.rv = 0;
	(void) di_devlink_cache_walk(devlink_cache, NULL, phys_path,
	    DI_PRIMARY_LINK, &cb_arg, devlink_cb);

	if (cb_arg.rv == -1)
		return (-1);

	if (cb_arg.count > 0) {
		*dev_name = s_strdup(cb_arg.dev_names[0]);
		free_dev_names(&cb_arg);
		if (*dev_name == NULL)
			return (-1);
	}

	return (0);
}

static char *
lookup_disk_dev_name(char *node_path)
{
	struct devlink_cb_arg cb_arg;
	char *dev_name = NULL;
	int i;
	char *p;
	int len1, len2;

#define	DEV_RDSK	"/dev/rdsk/"
#define	DISK_RAW_MINOR	",raw"

	cb_arg.count = 0;
	cb_arg.rv = 0;
	(void) di_devlink_cache_walk(devlink_cache, NULL, node_path,
	    DI_PRIMARY_LINK, &cb_arg, devlink_cb);

	if (cb_arg.rv == -1 || cb_arg.count == 0)
		return (NULL);

	/* first try lookup based on /dev/rdsk name */
	for (i = 0; i < cb_arg.count; i++) {
		if (strncmp(cb_arg.dev_names[i], DEV_RDSK,
		    sizeof (DEV_RDSK) - 1) == 0) {
			dev_name = s_strdup(cb_arg.dev_names[i]);
			break;
		}
	}

	if (dev_name == NULL) {
		/* now try lookup based on a minor name ending with ",raw" */
		len1 = sizeof (DISK_RAW_MINOR) - 1;
		for (i = 0; i < cb_arg.count; i++) {
			len2 = strlen(cb_arg.link_contents[i]);
			if (len2 >= len1 &&
			    strcmp(cb_arg.link_contents[i] + len2 - len1,
			    DISK_RAW_MINOR) == 0) {
				dev_name = s_strdup(cb_arg.dev_names[i]);
				break;
			}
		}
	}

	free_dev_names(&cb_arg);

	if (dev_name == NULL)
		return (NULL);
	if (strlen(dev_name) == 0) {
		free(dev_name);
		return (NULL);
	}

	/* if the name contains slice or partition number strip it */
	p = dev_name + strlen(dev_name) - 1;
	if (isdigit(*p)) {
		while (p != dev_name && isdigit(*p))
			p--;
		if (*p == 's' || *p == 'p')
			*p = '\0';
	}

	return (dev_name);
}

static char *
lookup_lofi_dev_name(char *node_path, char *minor)
{
	struct devlink_cb_arg cb_arg;
	char *dev_name = NULL;
	int i;
	int len1, len2;

	cb_arg.count = 0;
	cb_arg.rv = 0;
	(void) di_devlink_cache_walk(devlink_cache, NULL, node_path,
	    DI_PRIMARY_LINK, &cb_arg, devlink_cb);

	if (cb_arg.rv == -1 || cb_arg.count == 0)
		return (NULL);

	/* lookup based on a minor name ending with ",raw" */
	len1 = strlen(minor);
	for (i = 0; i < cb_arg.count; i++) {
		len2 = strlen(cb_arg.link_contents[i]);
		if (len2 >= len1 &&
		    strcmp(cb_arg.link_contents[i] + len2 - len1,
		    minor) == 0) {
			dev_name = s_strdup(cb_arg.dev_names[i]);
			break;
		}
	}

	free_dev_names(&cb_arg);

	if (dev_name == NULL)
		return (NULL);
	if (strlen(dev_name) == 0) {
		free(dev_name);
		return (NULL);
	}

	return (dev_name);
}

static char *
lookup_network_dev_name(char *node_path, char *driver_name)
{
	char *dev_name = NULL;
	char phys_path[MAXPATHLEN];

	if (lookup_dev_name(node_path, &dev_name) == -1)
		return (NULL);

	if (dev_name == NULL) {
		/* dlpi style-2 only interface */
		(void) snprintf(phys_path, sizeof (phys_path),
		    "/pseudo/clone@0:%s", driver_name);
		if (lookup_dev_name(phys_path, &dev_name) == -1 ||
		    dev_name == NULL)
			return (NULL);
	}

	return (dev_name);
}

static char *
lookup_printer_dev_name(char *node_path)
{
	struct devlink_cb_arg cb_arg;
	char *dev_name = NULL;
	int i;

#define	DEV_PRINTERS	"/dev/printers/"

	cb_arg.count = 0;
	cb_arg.rv = 0;
	(void) di_devlink_cache_walk(devlink_cache, NULL, node_path,
	    DI_PRIMARY_LINK, &cb_arg, devlink_cb);

	if (cb_arg.rv == -1 || cb_arg.count == 0)
		return (NULL);

	/* first try lookup based on /dev/printers name */
	for (i = 0; i < cb_arg.count; i++) {
		if (strncmp(cb_arg.dev_names[i], DEV_PRINTERS,
		    sizeof (DEV_PRINTERS) - 1) == 0) {
			dev_name = s_strdup(cb_arg.dev_names[i]);
			break;
		}
	}

	/* fallback to the first name */
	if ((dev_name == NULL) && (cb_arg.count > 0))
		dev_name = s_strdup(cb_arg.dev_names[0]);

	free_dev_names(&cb_arg);

	return (dev_name);
}

/*
 * Build an nvlist containing all attributes for devfs events.
 * Returns nvlist pointer on success, NULL on failure.
 */
static nvlist_t *
build_event_attributes(char *class, char *subclass, char *node_path,
    di_node_t node, char *driver_name, int instance, char *minor)
{
	nvlist_t *nvl;
	int err = 0;
	di_prop_t prop;
	int count;
	char *prop_name;
	int x;
	char *dev_name = NULL;
	int dev_name_lookup_err = 0;

	if ((err = nvlist_alloc(&nvl, NV_UNIQUE_NAME_TYPE, 0)) != 0) {
		nvl = NULL;
		goto out;
	}

	if ((err = nvlist_add_int32(nvl, EV_VERSION, EV_V1)) != 0)
		goto out;

	if ((err = nvlist_add_string(nvl, DEV_PHYS_PATH, node_path)) != 0)
		goto out;

	if (strcmp(class, EC_DEV_ADD) != 0 &&
	    strcmp(class, EC_DEV_REMOVE) != 0)
		return (nvl);

	if (driver_name == NULL || instance == -1)
		goto out;

	if (strcmp(subclass, ESC_DISK) == 0) {
		/*
		 * While we're removing labeled lofi device, we will receive
		 * event for every registered minor device and lastly,
		 * an event with minor set to NULL, as in following example:
		 * class: EC_dev_remove subclass: disk
		 * node_path: /pseudo/lofi@1 driver: lofi minor: u,raw
		 * class: EC_dev_remove subclass: disk
		 * node_path: /pseudo/lofi@1 driver: lofi minor: NULL
		 *
		 * When we receive this last event with minor set to NULL,
		 * all lofi minor devices are already removed and the call to
		 * lookup_disk_dev_name() would result in error.
		 * To prevent name lookup error messages for this case, we
		 * need to filter out that last event.
		 */
		if (strcmp(class, EC_DEV_REMOVE) == 0 &&
		    strcmp(driver_name, "lofi") ==  0 && minor == NULL) {
			nvlist_free(nvl);
			return (NULL);
		}
		if ((dev_name = lookup_disk_dev_name(node_path)) == NULL) {
			dev_name_lookup_err = 1;
			goto out;
		}
	} else if (strcmp(subclass, ESC_NETWORK) == 0) {
		if ((dev_name = lookup_network_dev_name(node_path, driver_name))
		    == NULL) {
			dev_name_lookup_err = 1;
			goto out;
		}
	} else if (strcmp(subclass, ESC_PRINTER) == 0) {
		if ((dev_name = lookup_printer_dev_name(node_path)) == NULL) {
			dev_name_lookup_err = 1;
			goto out;
		}
	} else if (strcmp(subclass, ESC_LOFI) == 0) {
		/*
		 * The raw minor node is created or removed after the block
		 * node.  Lofi devfs events are dependent on this behavior.
		 * Generate the sysevent only for the raw minor node.
		 *
		 * If the lofi mapping is created, we will receive the following
		 * event: class: EC_dev_add subclass: lofi minor: NULL
		 *
		 * As in case of EC_dev_add, the minor is NULL pointer,
		 * to get device links created, we will need to provide the
		 * type of minor node for lookup_lofi_dev_name()
		 *
		 * If the lofi device is unmapped, we will receive following
		 * events:
		 * class: EC_dev_remove subclass: lofi minor: disk
		 * class: EC_dev_remove subclass: lofi minor: disk,raw
		 * class: EC_dev_remove subclass: lofi minor: NULL
		 */

		if (strcmp(class, EC_DEV_ADD) == 0 && minor == NULL)
			minor = "disk,raw";

		if (minor == NULL || strstr(minor, "raw") == NULL) {
			nvlist_free(nvl);
			return (NULL);
		}
		if ((dev_name = lookup_lofi_dev_name(node_path, minor)) ==
		    NULL) {
			dev_name_lookup_err = 1;
			goto out;
		}
	}

	if (dev_name) {
		if ((err = nvlist_add_string(nvl, DEV_NAME, dev_name)) != 0)
			goto out;
		free(dev_name);
		dev_name = NULL;
	}

	if ((err = nvlist_add_string(nvl, DEV_DRIVER_NAME, driver_name)) != 0)
		goto out;

	if ((err = nvlist_add_int32(nvl, DEV_INSTANCE, instance)) != 0)
		goto out;

	if (strcmp(class, EC_DEV_ADD) == 0) {
		/* add properties */
		count = 0;
		for (prop = di_prop_next(node, DI_PROP_NIL);
		    prop != DI_PROP_NIL && count < MAX_PROP_COUNT;
		    prop = di_prop_next(node, prop)) {

			if (di_prop_devt(prop) != DDI_DEV_T_NONE)
				continue;

			if ((x = add_property(nvl, prop)) == 0)
				count++;
			else if (x == -1) {
				if ((prop_name = di_prop_name(prop)) == NULL)
					prop_name = "";
				err_print(PROP_ADD_FAILED, prop_name);
				goto out;
			}
		}
	}

	return (nvl);

out:
	nvlist_free(nvl);

	if (dev_name)
		free(dev_name);

	if (dev_name_lookup_err) {
		/*
		 * If a lofi mount fails, the /devices node may well have
		 * disappeared by the time we run, so let's not complain.
		 */
		if (strcmp(subclass, ESC_LOFI) != 0)
			err_print(DEV_NAME_LOOKUP_FAILED, node_path);
	} else {
		err_print(BUILD_EVENT_ATTR_FAILED, (err) ? strerror(err) : "");
	}
	return (NULL);
}

static void
log_event(char *class, char *subclass, nvlist_t *nvl)
{
	sysevent_id_t eid;

	if (sysevent_post_event(class, subclass, "SUNW", DEVFSADMD,
	    nvl, &eid) != 0) {
		err_print(LOG_EVENT_FAILED, strerror(errno));
	}
}

/*
 * When devfsadmd needs to generate sysevents, they are queued for later
 * delivery this allows them to be delivered after the devlinks db cache has
 * been flushed guaranteeing that applications consuming these events have
 * access to an accurate devlinks db.  The queue is a FIFO, sysevents to be
 * inserted in the front of the queue and consumed off the back.
 */
static void
enqueue_sysevent(char *class, char *subclass, nvlist_t *nvl)
{
	syseventq_t *tmp;

	if ((tmp = s_zalloc(sizeof (*tmp))) == NULL)
		return;

	tmp->class = s_strdup(class);
	tmp->subclass = s_strdup(subclass);
	tmp->nvl = nvl;

	(void) mutex_lock(&syseventq_mutex);
	if (syseventq_front != NULL)
		syseventq_front->next = tmp;
	else
		syseventq_back = tmp;
	syseventq_front = tmp;
	(void) mutex_unlock(&syseventq_mutex);
}

static void
process_syseventq()
{
	(void) mutex_lock(&syseventq_mutex);
	while (syseventq_back != NULL) {
		syseventq_t *tmp = syseventq_back;

		vprint(CHATTY_MID, "sending queued event: %s, %s\n",
		    tmp->class, tmp->subclass);

		log_event(tmp->class, tmp->subclass, tmp->nvl);

		if (tmp->class != NULL)
			free(tmp->class);
		if (tmp->subclass != NULL)
			free(tmp->subclass);
		nvlist_free(tmp->nvl);
		syseventq_back = syseventq_back->next;
		if (syseventq_back == NULL)
			syseventq_front = NULL;
		free(tmp);
	}
	(void) mutex_unlock(&syseventq_mutex);
}

static void
build_and_enq_event(char *class, char *subclass, char *node_path,
    di_node_t node, char *minor)
{
	nvlist_t *nvl;

	vprint(CHATTY_MID, "build_and_enq_event(%s, %s, %s, 0x%8.8x)\n",
	    class, subclass, node_path, (int)node);

	if (node != DI_NODE_NIL)
		nvl = build_event_attributes(class, subclass, node_path, node,
		    di_driver_name(node), di_instance(node), minor);
	else
		nvl = build_event_attributes(class, subclass, node_path, node,
		    NULL, -1, minor);

	if (nvl) {
		enqueue_sysevent(class, subclass, nvl);
	}
}

/*
 * is_blank() returns 1 (true) if a line specified is composed of
 * whitespace characters only. otherwise, it returns 0 (false).
 *
 * Note. the argument (line) must be null-terminated.
 */
static int
is_blank(char *line)
{
	for (/* nothing */; *line != '\0'; line++)
		if (!isspace(*line))
			return (0);
	return (1);
}

/*
 * Functions to deal with the no-further-processing hash
 */

static void
nfphash_create(void)
{
	assert(nfp_hash == NULL);
	nfp_hash = s_zalloc(NFP_HASH_SZ * sizeof (item_t *));
}

static int
nfphash_fcn(char *key)
{
	int i;
	uint64_t sum = 0;

	for (i = 0; key[i] != '\0'; i++) {
		sum += (uchar_t)key[i];
	}

	return (sum % NFP_HASH_SZ);
}

static item_t *
nfphash_lookup(char *key)
{
	int	index;
	item_t  *ip;

	index = nfphash_fcn(key);

	assert(index >= 0);

	for (ip = nfp_hash[index]; ip; ip = ip->i_next) {
		if (strcmp(ip->i_key, key) == 0)
			return (ip);
	}

	return (NULL);
}

static void
nfphash_insert(char *key)
{
	item_t	*ip;
	int	index;

	index = nfphash_fcn(key);

	assert(index >= 0);

	ip = s_zalloc(sizeof (item_t));
	ip->i_key = s_strdup(key);

	ip->i_next = nfp_hash[index];
	nfp_hash[index] = ip;
}

static void
nfphash_destroy(void)
{
	int	i;
	item_t	*ip;

	for (i = 0; i < NFP_HASH_SZ; i++) {
		/*LINTED*/
		while (ip = nfp_hash[i]) {
			nfp_hash[i] = ip->i_next;
			free(ip->i_key);
			free(ip);
		}
	}

	free(nfp_hash);
	nfp_hash = NULL;
}

static int
devname_kcall(int subcmd, void *args)
{
	int error = 0;

	switch (subcmd) {
	case MODDEVNAME_LOOKUPDOOR:
		error = modctl(MODDEVNAME, subcmd, (uintptr_t)args);
		if (error) {
			vprint(INFO_MID, "modctl(MODDEVNAME, "
			    "MODDEVNAME_LOOKUPDOOR) failed - %s\n",
			    strerror(errno));
		}
		break;
	default:
		error = EINVAL;
		break;
	}
	return (error);
}

/* ARGSUSED */
static void
devname_lookup_handler(void *cookie, char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc)
{
	int32_t error = 0;
	door_cred_t dcred;
	struct dca_impl	dci;
	uint8_t	cmd;
	sdev_door_res_t res;
	sdev_door_arg_t *args;

	if (argp == NULL || arg_size == 0) {
		vprint(DEVNAME_MID, "devname_lookup_handler: argp wrong\n");
		error = DEVFSADM_RUN_INVALID;
		goto done;
	}
	vprint(DEVNAME_MID, "devname_lookup_handler\n");

	if (door_cred(&dcred) != 0 || dcred.dc_euid != 0) {
		vprint(DEVNAME_MID, "devname_lookup_handler: cred wrong\n");
		error = DEVFSADM_RUN_EPERM;
		goto done;
	}

	args = (sdev_door_arg_t *)argp;
	cmd = args->devfsadm_cmd;

	vprint(DEVNAME_MID, "devname_lookup_handler: cmd %d\n", cmd);
	switch (cmd) {
	case DEVFSADMD_RUN_ALL:
		/*
		 * run "devfsadm"
		 */
		dci.dci_root = "/";
		dci.dci_minor = NULL;
		dci.dci_driver = NULL;
		dci.dci_error = 0;
		dci.dci_flags = 0;
		dci.dci_arg = NULL;

		lock_dev();
		update_drvconf((major_t)-1, 0);
		dci.dci_flags |= DCA_FLUSH_PATHINST;

		pre_and_post_cleanup(RM_PRE);
		devi_tree_walk(&dci, DI_CACHE_SNAPSHOT_FLAGS, NULL);
		error = (int32_t)dci.dci_error;
		if (!error) {
			pre_and_post_cleanup(RM_POST);
			update_database = TRUE;
			unlock_dev(SYNC_STATE);
			update_database = FALSE;
		} else {
			if (DEVFSADM_DEBUG_ON) {
				vprint(INFO_MID, "devname_lookup_handler: "
				    "DEVFSADMD_RUN_ALL failed\n");
			}

			unlock_dev(SYNC_STATE);
		}
		break;
	default:
		/* log an error here? */
		error = DEVFSADM_RUN_NOTSUP;
		break;
	}

done:
	vprint(DEVNAME_MID, "devname_lookup_handler: error %d\n", error);
	res.devfsadm_error = error;
	(void) door_return((char *)&res, sizeof (struct sdev_door_res),
	    NULL, 0);
}


di_devlink_handle_t
devfsadm_devlink_cache(void)
{
	return (devlink_cache);
}

int
devfsadm_reserve_id_cache(devlink_re_t re_array[], enumerate_file_t *head)
{
	enumerate_file_t *entry;
	int nelem;
	int i;
	int subex;
	char *re;
	size_t size;
	regmatch_t *pmch;

	/*
	 * Check the <RE, subexp> array passed in and compile it.
	 */
	for (i = 0; re_array[i].d_re; i++) {
		if (re_array[i].d_subexp == 0) {
			err_print("bad subexp value in RE: %s\n",
			    re_array[i].d_re);
			goto bad_re;
		}

		re = re_array[i].d_re;
		if (regcomp(&re_array[i].d_rcomp, re, REG_EXTENDED) != 0) {
			err_print("reg. exp. failed to compile: %s\n", re);
			goto bad_re;
		}
		subex = re_array[i].d_subexp;
		nelem = subex + 1;
		re_array[i].d_pmatch = s_malloc(sizeof (regmatch_t) * nelem);
	}

	entry = head ? head : enumerate_reserved;
	for (; entry; entry = entry->er_next) {
		if (entry->er_id) {
			vprint(RSBY_MID, "entry %s already has ID %s\n",
			    entry->er_file, entry->er_id);
			continue;
		}
		for (i = 0; re_array[i].d_re; i++) {
			subex = re_array[i].d_subexp;
			pmch = re_array[i].d_pmatch;
			if (regexec(&re_array[i].d_rcomp, entry->er_file,
			    subex + 1, pmch, 0) != 0) {
				/* No match */
				continue;
			}
			size = pmch[subex].rm_eo - pmch[subex].rm_so;
			entry->er_id = s_malloc(size + 1);
			(void) strncpy(entry->er_id,
			    &entry->er_file[pmch[subex].rm_so], size);
			entry->er_id[size] = '\0';
			if (head) {
				vprint(RSBY_MID, "devlink(%s) matches RE(%s). "
				    "ID is %s\n", entry->er_file,
				    re_array[i].d_re, entry->er_id);
			} else {
				vprint(RSBY_MID, "rsrv entry(%s) matches "
				    "RE(%s) ID is %s\n", entry->er_file,
				    re_array[i].d_re, entry->er_id);
			}
			break;
		}
	}

	for (i = 0; re_array[i].d_re; i++) {
		regfree(&re_array[i].d_rcomp);
		assert(re_array[i].d_pmatch);
		free(re_array[i].d_pmatch);
	}

	entry = head ? head : enumerate_reserved;
	for (; entry; entry = entry->er_next) {
		if (entry->er_id == NULL)
			continue;
		if (head) {
			vprint(RSBY_MID, "devlink: %s\n", entry->er_file);
			vprint(RSBY_MID, "ID: %s\n", entry->er_id);
		} else {
			vprint(RSBY_MID, "reserve file entry: %s\n",
			    entry->er_file);
			vprint(RSBY_MID, "reserve file id: %s\n",
			    entry->er_id);
		}
	}

	return (DEVFSADM_SUCCESS);

bad_re:
	for (i = i-1; i >= 0; i--) {
		regfree(&re_array[i].d_rcomp);
		assert(re_array[i].d_pmatch);
		free(re_array[i].d_pmatch);
	}
	return (DEVFSADM_FAILURE);
}

/*
 * Return 1 if we have reserved links.
 */
int
devfsadm_have_reserved()
{
	return (enumerate_reserved ? 1 : 0);
}

/*
 * This functions errs on the side of caution. If there is any error
 * we assume that the devlink is  *not* reserved
 */
int
devfsadm_is_reserved(devlink_re_t re_array[], char *devlink)
{
	int match;
	enumerate_file_t estruct = {NULL};
	enumerate_file_t *entry;

	match = 0;
	estruct.er_file = devlink;
	estruct.er_id = NULL;
	estruct.er_next = NULL;

	if (devfsadm_reserve_id_cache(re_array, &estruct) != DEVFSADM_SUCCESS) {
		err_print("devfsadm_is_reserved: devlink (%s) does not "
		    "match RE\n", devlink);
		return (0);
	}
	if (estruct.er_id == NULL) {
		err_print("devfsadm_is_reserved: ID derived from devlink %s "
		    "is NULL\n", devlink);
		return (0);
	}

	entry = enumerate_reserved;
	for (; entry; entry = entry->er_next) {
		if (entry->er_id == NULL)
			continue;
		if (strcmp(entry->er_id, estruct.er_id) != 0)
			continue;
		match = 1;
		vprint(RSBY_MID, "reserve file entry (%s) and devlink (%s) "
		    "match\n", entry->er_file, devlink);
		break;
	}

	free(estruct.er_id);
	return (match);
}
