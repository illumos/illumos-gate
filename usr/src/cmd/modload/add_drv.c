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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <libelf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <wait.h>
#include <unistd.h>
#include <libintl.h>
#include <sys/modctl.h>
#include <sys/systeminfo.h>
#include <string.h>
#include <limits.h>
#include <locale.h>
#include <ftw.h>
#include <sys/sunddi.h>
#include <libdevinfo.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include "addrem.h"
#include "errmsg.h"
#include "plcysubr.h"

/*
 * globals needed for libdevinfo - there is no way to pass
 * private data to the find routine.
 */
struct dev_list {
	int clone;
	char *dev_name;
	char *driver_name;
	struct dev_list *next;
};

static char *kelf_desc = NULL;
static int kelf_type = ELFCLASSNONE;

static char *new_drv;
static struct dev_list *conflict_lst = NULL;

static int module_not_found(char *, char *, int, char **, int *);
static void usage();
static int update_minor_perm(char *, char *);
static int devfs_update_minor_perm(char *, char *, char *);
static int update_driver_classes(char *, char *);
static int drv_name_conflict(di_node_t);
static int devfs_node(di_node_t node, void *arg);
static int drv_name_match(char *, int, char *, char *);
static void print_drv_conflict_info(int);
static void check_dev_dir(int);
static int dev_node(const char *, const struct stat *, int, struct FTW *);
static void free_conflict_list(struct dev_list *);
static int clone(di_node_t node);
static int elf_type(char *, char **, int *);
static int correct_location(char *, char **, int *);
static int isaspec_drvmod_discovery();
static void remove_slashes(char *);
static int update_extra_privs(char *, char *privlist);
static int ignore_root_basedir();

int
main(int argc, char *argv[])
{
	int opt;
	major_t major_num;
	char driver_name[FILENAME_MAX + 1];
	int driver_name_size = sizeof (driver_name);
	char path_driver_name[MAXPATHLEN];
	int path_driver_name_size = sizeof (path_driver_name);
	char *perms = NULL;
	char *aliases = NULL;
	char *classes = NULL;
	char *policy = NULL;
	char *priv = NULL;
	int noload_flag = 0;
	int verbose_flag = 0;
	int force_flag = 0;
	int i_flag = 0;
	int c_flag = 0;
	int m_flag = 0;
	int cleanup_flag = 0;
	int server = 0;
	char *basedir = NULL;
	int is_unique;
	char *slash;
	int conflict;
	di_node_t root_node;	/* for device tree snapshot */
	char *drvelf_desc = NULL;
	int drvelf_type = ELFCLASSNONE;

	moddir = NULL;

	(void) setlocale(LC_ALL, "");
#if	!defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/*  must be run by root */

	if (geteuid() != 0) {
		(void) fprintf(stderr, gettext(ERR_NOT_ROOT));
		exit(1);
	}

	while ((opt = getopt(argc, argv, "vfm:ni:b:c:p:P:")) != EOF) {
		switch (opt) {
		case 'm' :
			m_flag = 1;
			perms = optarg;
			break;
		case 'f':
			force_flag++;
			break;
		case 'v':
			verbose_flag++;
			break;
		case 'n':
			noload_flag++;
			break;
		case 'i' :
			i_flag = 1;
			aliases = optarg;
			if (check_space_within_quote(aliases) == ERROR) {
				(void) fprintf(stderr, gettext(ERR_NO_SPACE),
				    aliases);
				exit(1);
			}
			break;
		case 'b' :
			server = 1;
			basedir = optarg;
			if (strcmp(basedir, "/") == 0 &&
			    ignore_root_basedir()) {
				server = 0;
				basedir = NULL;
			}
			break;
		case 'c':
			c_flag = 1;
			classes = optarg;
			break;
		case 'p':
			policy = optarg;
			break;
		case 'P':
			priv = optarg;
			break;
		case '?' :
		default:
			usage();
			exit(1);
		}
	}


	if (argv[optind] != NULL) {
		if (strlcpy(driver_name, argv[optind], driver_name_size) >=
		    driver_name_size) {
			(void) fprintf(stderr, gettext(ERR_DRVNAME_TOO_LONG),
			    driver_name_size, argv[optind]);
			exit(1);
		}

		/*
		 * check for extra args
		 */
		if ((optind + 1) != argc) {
			usage();
			exit(1);
		}

	} else {
		usage();
		exit(1);
	}

	/*
	 * Fail if add_drv was invoked with a pathname prepended to the
	 * driver_name argument.
	 *
	 * Check driver_name for any '/'s. If found, we assume that caller
	 * is trying to specify a pathname.
	 */

	slash = strchr(driver_name, '/');
	if (slash) {
		remove_slashes(driver_name);

		/* extract module name out of path */
		slash = strrchr(driver_name, '/');

		if (slash != NULL) {
			(void) fprintf(stderr, gettext(ERR_PATH_SPEC),
			    driver_name);
			(void) fprintf(stderr, gettext(ERR_INSTALL_FAIL),
			    ++slash);
			exit(1);
		}
	}
	new_drv = driver_name;

	/* set up add_drv filenames */
	if ((build_filenames(basedir)) == ERROR) {
		exit(1);
	}

	/* must be only running version of add_drv/rem_drv */
	enter_lock();

	if ((check_perms_aliases(m_flag, i_flag)) == ERROR)
		err_exit();

	if ((check_name_to_major(R_OK | W_OK)) == ERROR)
		err_exit();

	/*
	 * check validity of options
	 */
	if (m_flag) {
		if ((check_perm_opts(perms)) == ERROR) {
			usage();
			err_exit();
		}
	}

	if (i_flag) {
		if (aliases != NULL)
			if ((aliases_unique(aliases)) == ERROR)
				err_exit();
	}

	/* update kernel unless -b or -n */
	if (noload_flag == 0 && server == 0 &&
	    priv != NULL && check_priv_entry(priv, 1) != 0)
		err_exit();

	if (policy != NULL &&
	    (policy = check_plcy_entry(policy, driver_name, B_FALSE)) == NULL) {
		err_exit();
	}

	if ((unique_driver_name(driver_name, name_to_major,
	    &is_unique)) == ERROR)
		err_exit();

	if (is_unique == NOT_UNIQUE) {
		(void) fprintf(stderr, gettext(ERR_NOT_UNIQUE), driver_name);
		err_exit();
	}

	if (noload_flag == 0 && server == 0) {
		if (elf_type("/dev/ksyms", &kelf_desc, &kelf_type) == ERROR) {
			(void) fprintf(stderr, gettext(ERR_KERNEL_ISA));
			err_exit();
		}

		if (module_not_found(driver_name, path_driver_name,
		    path_driver_name_size, &drvelf_desc, &drvelf_type) ==
		    ERROR) {
			(void) fprintf(stderr, gettext(ERR_NOMOD), driver_name);
			err_exit();
		}

		/*
		 * If the driver location is incorrect but the kernel and driver
		 * are of the same ISA, suggest a fix.  If the driver location
		 * is incorrect and the ISA's mismatch, notify the user that
		 * this driver can not be loaded on this kernel.  In both cases,
		 * do not attempt to load the driver module.
		 */

		if (correct_location(path_driver_name, &drvelf_desc,
		    (&drvelf_type)) == ERROR) {
			noload_flag = 1;
			if (kelf_type == drvelf_type) {
				(void) fprintf(stderr,
				    gettext(ERR_SOL_LOCATION), driver_name,
				    driver_name);
			} else {
				(void) fprintf(stderr,
				    gettext(ERR_NOT_LOADABLE),
				    drvelf_desc, driver_name, kelf_desc);
			}

		/*
		 * The driver location is correct.  Verify that the kernel ISA
		 * and driver ISA match.  If they do not match, produce an error
		 * message and do not attempt to load the module.
		 */

		} else if (kelf_type != drvelf_type) {
			noload_flag = 1;
			(void) fprintf(stderr, gettext(ERR_ISA_MISMATCH),
			    kelf_desc, driver_name, drvelf_desc);
			(void) fprintf(stderr, gettext(ERR_NOT_LOADABLE),
			    drvelf_desc, driver_name, kelf_desc);
		}


		/*
		 * Check for a more specific driver conflict - see
		 * PSARC/1995/239
		 * Note that drv_name_conflict() can return -1 for error
		 * or 1 for a conflict.  Since the default is to fail unless
		 * the -f flag is specified, we don't bother to differentiate.
		 */
		if ((root_node = di_init("/", DINFOSUBTREE | DINFOMINOR))
		    == DI_NODE_NIL) {
			(void) fprintf(stderr, gettext(ERR_DEVTREE));
			conflict = -1;
		} else {
			conflict = drv_name_conflict(root_node);
			di_fini(root_node);
		}

		if (conflict) {
			/*
			 * if the force flag is not set, we fail here
			 */
			if (!force_flag) {
				(void) fprintf(stderr,
				    gettext(ERR_INSTALL_FAIL), driver_name);
				(void) fprintf(stderr, "Device managed by "
				    "another driver.\n");
				if (verbose_flag)
					print_drv_conflict_info(force_flag);
				err_exit();
			}
			/*
			 * The force flag was specified so we print warnings
			 * and install the driver anyways
			 */
			if (verbose_flag)
				print_drv_conflict_info(force_flag);
			free_conflict_list(conflict_lst);
		}
	}

	if ((update_name_to_major(driver_name, &major_num, server)) == ERROR) {
		err_exit();
	}

	cleanup_flag |= CLEAN_NAM_MAJ;


	if (m_flag) {
		cleanup_flag |= CLEAN_MINOR_PERM;
		if (update_minor_perm(driver_name, perms) == ERROR) {
			remove_entry(cleanup_flag, driver_name);
			err_exit();
		}
	}

	if (i_flag) {
		cleanup_flag |= CLEAN_DRV_ALIAS;
		if (update_driver_aliases(driver_name, aliases) == ERROR) {
			remove_entry(cleanup_flag, driver_name);
			err_exit();

		}
	}

	if (c_flag) {
		cleanup_flag |= CLEAN_DRV_CLASSES;
		if (update_driver_classes(driver_name, classes) == ERROR) {
			remove_entry(cleanup_flag, driver_name);
			err_exit();

		}
	}

	if (priv != NULL) {
		cleanup_flag |= CLEAN_DRV_PRIV;
		if (update_extra_privs(driver_name, priv) == ERROR) {
			remove_entry(cleanup_flag, driver_name);
			err_exit();
		}
	}

	if (policy != NULL) {
		cleanup_flag |= CLEAN_DEV_POLICY;
		if (update_device_policy(device_policy, policy, B_FALSE)
		    == ERROR) {
			remove_entry(cleanup_flag, driver_name);
			err_exit();
		}
	}

	if (noload_flag || server) {
		(void) fprintf(stderr, gettext(BOOT_CLIENT));
	} else {
		/*
		 * paranoia - if we crash whilst configuring the driver
		 * this might avert possible file corruption.
		 */
		sync();

		if (config_driver(driver_name, major_num, aliases, classes,
		    cleanup_flag, verbose_flag) == ERROR) {
			err_exit();
		}
		if (m_flag) {
			if (devfs_update_minor_perm(basedir,
			    driver_name, perms) == ERROR) {
				err_exit();
			}
		}
		if (!noload_flag)
			load_driver(driver_name, verbose_flag);
		else
			(void) fprintf(stderr, gettext(ERR_CONFIG_NOLOAD),
			    driver_name);
	}

	if (create_reconfig(basedir) == ERROR)
		(void) fprintf(stderr, gettext(ERR_CREATE_RECONFIG));

	cleanup_moddir();
	exit_unlock();

	if (verbose_flag) {
		(void) fprintf(stderr, gettext(DRIVER_INSTALLED), driver_name);
	}

	return (NOERR);
}

/*
 *	Searches for the driver module along the module path (returned
 *	from modctl) and returns a string (in drv_path) representing the path
 *	where drv_name was found.  ERROR is returned if function is unable
 *	to locate drv_name.
 */
int
module_not_found(char *drv_name, char *drv_path, int drv_path_size,
    char **drvelf_desc, int *drvelf_type_ptr)
{
	struct stat buf;
	char data [MAXMODPATHS];
	char pathsave [MAXMODPATHS];
	char *next = data;
	struct drvmod_dir *curdir = NULL;
	char foundpath[MAXPATHLEN];

	if (modctl(MODGETPATH, NULL, data) != 0) {
		(void) fprintf(stderr, gettext(ERR_MODPATH));
		return (ERROR);
	}
	(void) strcpy(pathsave, data);
	next = strtok(data, MOD_SEP);

	if (isaspec_drvmod_discovery() == ERROR)
		err_exit();

	curdir = moddir;
	while (curdir != NULL) {
		while (next != NULL) {
			(void) snprintf(foundpath, sizeof (foundpath),
			    "%s/drv/%s/%s", next, curdir->direc, drv_name);
			if ((stat(foundpath, &buf) == 0) &&
			    ((buf.st_mode & S_IFMT) == S_IFREG)) {
				if (elf_type(foundpath, drvelf_desc,
				    drvelf_type_ptr) == ERROR) {
					(void) fprintf(stderr,
					    gettext(ERR_INSTALL_FAIL),
					    drv_name);
					err_exit();
				}
				remove_slashes(foundpath);

				if (strlcpy(drv_path, foundpath, drv_path_size)
				    >= drv_path_size) {
					return (ERROR);
				}

				return (NOERR);
			}
			next = strtok((char *)NULL, MOD_SEP);
		}
		(void) strcpy(data, pathsave);
		next = strtok(data, MOD_SEP);
		curdir = curdir->next;
	}

	return (ERROR);
}

static void
usage()
{
	(void) fprintf(stderr, gettext(USAGE));
}

static int
update_driver_classes(
	char *driver_name,
	char *classes)
{
	/* make call to update the classes file */
	return (append_to_file(driver_name, classes, driver_classes,
	    ' ', "\t", 0));
}

static int
update_minor_perm(
	char *driver_name,
	char *perm_list)
{
	return (append_to_file(driver_name, perm_list, minor_perm,
	    ',', ":", 0));
}


/*
 * Complete the minor perm update by communicating the minor perm
 * data to the kernel.  This information is used by devfs to ensure
 * that devices always have the correct permissions when attached.
 * The minor perm file must be updated and the driver configured
 * in the system for this step to complete correctly.
 */
static int
devfs_update_minor_perm(
	char *basedir,
	char *driver_name,
	char *perm_list)
{
	int rval = 0;

	if (basedir == NULL || (strcmp(basedir, "/") == 0)) {
		if (devfs_add_minor_perm(driver_name,
		    log_minorperm_error) != 0) {
			(void) fprintf(stderr,
			    gettext(ERR_UPDATE_PERM), driver_name);
		}
	}
	return (rval);
}

static int
update_extra_privs(
	char *driver_name,
	char *privlist)
{
	return (append_to_file(driver_name, privlist, extra_privs,
	    ',', ":", 0));
}

/*
 * Check to see if the driver we are adding is a more specific
 * driver for a device already attached to a less specific driver.
 * In other words, see if this driver comes earlier on the compatible
 * list of a device already attached to another driver.
 * If so, the new node will not be created (since the device is
 * already attached) but when the system reboots, it will attach to
 * the new driver but not have a node - we need to warn the user
 * if this is the case.
 */
static int
drv_name_conflict(di_node_t root_node)
{
	/*
	 * walk the device tree checking each node
	 */
	if (di_walk_node(root_node, DI_WALK_SIBFIRST, NULL, devfs_node) == -1) {
		free_conflict_list(conflict_lst);
		conflict_lst = (struct dev_list *)NULL;
		(void) fprintf(stderr, gettext(ERR_DEVTREE));
		return (-1);
	}

	if (conflict_lst == NULL)
		/* no conflicts found */
		return (0);
	else
		/* conflicts! */
		return (1);
}

/*
 * called via di_walk_node().
 * called for each node in the device tree.  We skip nodes that:
 *	1. are not hw nodes (since they cannot have generic names)
 *	2. that do not have a compatible property
 *	3. whose node name = binding name.
 *	4. nexus nodes - the name of a generic nexus node would
 *	not be affected by a driver change.
 * Otherwise, we parse the compatible property, if we find a
 * match with the new driver before we find a match with the
 * current driver, then we have a conflict and we save the
 * node away.
 */
/*ARGSUSED*/
static int
devfs_node(di_node_t node, void *arg)
{
	char *binding_name, *node_name, *compat_names, *devfsnm;
	struct dev_list *new_entry;
	char strbuf[MAXPATHLEN];
	int n_names;

	/*
	 * if there is no compatible property, we don't
	 * have to worry about any conflicts.
	 */
	if ((n_names = di_compatible_names(node, &compat_names)) <= 0)
		return (DI_WALK_CONTINUE);

	/*
	 * if the binding name and the node name match, then
	 * either no driver existed that could be bound to this node,
	 * or the driver name is the same as the node name.
	 */
	binding_name = di_binding_name(node);
	node_name = di_node_name(node);
	if ((binding_name == NULL) || (strcmp(node_name, binding_name) == 0))
		return (DI_WALK_CONTINUE);

	/*
	 * we can skip nexus drivers since they do not
	 * have major/minor number info encoded in their
	 * /devices name and therefore won't change.
	 */
	if (di_driver_ops(node) & DI_BUS_OPS)
		return (DI_WALK_CONTINUE);

	/*
	 * check for conflicts
	 * If we do find that the new driver is a more specific driver
	 * than the driver already attached to the device, we'll save
	 * away the node name for processing later.
	 */
	if (drv_name_match(compat_names, n_names, binding_name, new_drv)) {
		devfsnm = di_devfs_path(node);
		(void) sprintf(strbuf, "%s%s", DEVFS_ROOT, devfsnm);
		di_devfs_path_free(devfsnm);
		new_entry = (struct dev_list *)calloc(1,
		    sizeof (struct dev_list));
		if (new_entry == (struct dev_list *)NULL) {
			(void) fprintf(stderr, gettext(ERR_NO_MEM));
			err_exit();
		}
		/* save the /devices name */
		if ((new_entry->dev_name = strdup(strbuf)) == NULL) {
			(void) fprintf(stderr, gettext(ERR_NO_MEM));
			free(new_entry);
			err_exit();
		}
		/* save the driver name */
		if ((new_entry->driver_name = strdup(di_driver_name(node)))
		    == NULL) {
			(void) fprintf(stderr, gettext(ERR_NO_MEM));
			free(new_entry->dev_name);
			free(new_entry);
			err_exit();
		}
		/* check to see if this is a clone device */
		if (clone(node))
			new_entry->clone = 1;

		/* add it to the list */
		new_entry->next = conflict_lst;
		conflict_lst = new_entry;
	}

	return (DI_WALK_CONTINUE);
}

static int
clone(di_node_t node)
{
	di_minor_t minor = DI_MINOR_NIL;

	while ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
		if (di_minor_type(minor) == DDM_ALIAS)
			return (1);
	}
	return (0);
}
/*
 * check to see if the new_name shows up on the compat list before
 * the cur_name (driver currently attached to the device).
 */
static int
drv_name_match(char *compat_names, int n_names, char *cur_name, char *new_name)
{
	int i, ret = 0;

	if (strcmp(cur_name, new_name) == 0)
		return (0);

	/* parse the coompatible list */
	for (i = 0; i < n_names; i++) {
		if (strcmp(compat_names, new_name) == 0) {
			ret = 1;
			break;
		}
		if (strcmp(compat_names, cur_name) == 0) {
			break;
		}
		compat_names += strlen(compat_names) + 1;
	}
	return (ret);
}

/*
 * A more specific driver is being added for a device already attached
 * to a less specific driver.  Print out a general warning and if
 * the force flag was passed in, give the user a hint as to what
 * nodes may be affected in /devices and /dev
 */
static void
print_drv_conflict_info(int force)
{
	struct dev_list *ptr;

	if (conflict_lst == NULL)
		return;
	if (force) {
		(void) fprintf(stderr,
		    "\nA reconfiguration boot must be performed to "
		    "complete the\n");
		(void) fprintf(stderr, "installation of this driver.\n");
	}

	if (force) {
		(void) fprintf(stderr,
		    "\nThe following entries in /devices will be "
		    "affected:\n\n");
	} else {
		(void) fprintf(stderr,
		    "\nDriver installation failed because the following\n");
		(void) fprintf(stderr,
		    "entries in /devices would be affected:\n\n");
	}

	ptr = conflict_lst;
	while (ptr != NULL) {
		(void) fprintf(stderr, "\t%s", ptr->dev_name);
		if (ptr->clone)
			(void) fprintf(stderr, " (clone device)\n");
		else
			(void) fprintf(stderr, "[:*]\n");
		(void) fprintf(stderr, "\t(Device currently managed by driver "
		    "\"%s\")\n\n", ptr->driver_name);
		ptr = ptr->next;
	}
	check_dev_dir(force);
}

/*
 * use nftw to walk through /dev looking for links that match
 * an entry in the conflict list.
 */
static void
check_dev_dir(int force)
{
	int  walk_flags = FTW_PHYS | FTW_MOUNT;
	int ft_depth = 15;

	if (force) {
		(void) fprintf(stderr, "\nThe following entries in /dev will "
		    "be affected:\n\n");
	} else {
		(void) fprintf(stderr, "\nThe following entries in /dev would "
		    "be affected:\n\n");
	}

	(void) nftw("/dev", dev_node, ft_depth, walk_flags);

	(void) fprintf(stderr, "\n");
}

/*
 * checks a /dev link to see if it matches any of the conlficting
 * /devices nodes in conflict_lst.
 */
/*ARGSUSED1*/
static int
dev_node(const char *node, const struct stat *node_stat, int flags,
	struct FTW *ftw_info)
{
	char linkbuf[MAXPATHLEN];
	struct dev_list *ptr;

	if (readlink(node, linkbuf, MAXPATHLEN) == -1)
		return (0);

	ptr = conflict_lst;

	while (ptr != NULL) {
		if (strstr(linkbuf, ptr->dev_name) != NULL)
			(void) fprintf(stderr, "\t%s\n", node);
		ptr = ptr->next;
	}
	return (0);
}


static void
free_conflict_list(struct dev_list *list)
{
	struct dev_list *save;

	/* free up any dev_list structs we allocated. */
	while (list != NULL) {
		save = list;
		list = list->next;
		free(save->dev_name);
		free(save);
	}
}

int
elf_type(char *file, char **elfdesc, int *elf_type_ptr)
{
	int fd;
	Elf *elf;
	char *ident;

	if ((fd = open(file, O_RDONLY)) < 0) {
		(void) fprintf(stderr, gettext(ERR_CANNOT_OPEN), file,
		    strerror(errno));
		return (ERROR);
	}
	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) fprintf(stderr, gettext(ERR_ELF_VERSION),
		    elf_errmsg(-1));
		(void) close(fd);
		return (ERROR);
	}
	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (elf_kind(elf) != ELF_K_ELF) {
		(void) fprintf(stderr, gettext(ERR_ELF_KIND), file);
		(void) elf_end(elf);
		(void) close(fd);
		return (ERROR);
	}
	ident = elf_getident(elf, 0);
	if (ident[EI_CLASS] == ELFCLASS32) {
		*elfdesc = "32";
		*elf_type_ptr = ELFCLASS32;
	} else if (ident[EI_CLASS] == ELFCLASS64) {
		*elfdesc = "64";
		*elf_type_ptr = ELFCLASS64;
	} else {
		*elfdesc = "none";
		*elf_type_ptr = ELFCLASSNONE;
	}
	(void) elf_end(elf);
	(void) close(fd);
	return (NOERR);
}

int
correct_location(char *drv_path, char **drvelf_desc, int *drvelf_type_ptr)
{

	char copy_drv_path[MAXPATHLEN];
	char *token = copy_drv_path;

	(void) strcpy(copy_drv_path, drv_path);

	if (elf_type(drv_path, drvelf_desc, drvelf_type_ptr) == ERROR) {
		err_exit();
	}
	token = strtok(copy_drv_path, DIR_SEP);
	while (token != NULL) {
		if (strcmp("drv", token) == 0) {
			token = strtok((char *)NULL, DIR_SEP);
			if (strcmp(DRVDIR64, token) == 0) {
				if (*drvelf_type_ptr == ELFCLASS64)
					return (NOERR);
				(void) fprintf(stderr, gettext(ERR_LOCATION),
				    *drvelf_desc, drv_path);
				return (ERROR);
			} else {
				if (*drvelf_type_ptr == ELFCLASS32)
					return (NOERR);
				(void) fprintf(stderr, gettext(ERR_LOCATION),
				    *drvelf_desc, drv_path);
				return (ERROR);
			}
		} else {
			token = strtok((char *)NULL, DIR_SEP);
		}
	}
	return (ERROR);
}

/*
 * Creates a two-element linked list of isa-specific subdirectories to
 * search for each driver, which is is used by the function
 * module_not_found() to convert the isa-independent modpath into an
 * isa-specific path .  The list is ordered depending on the machine
 * architecture and instruction set architecture, corresponding to the
 * order in which module_not_found() will search for the driver.  This
 * routine relies on an architecture not having more than two
 * sub-architectures (e.g., sparc/sparcv9 or i386/amd64).
 */
int
isaspec_drvmod_discovery()
{
	char arch[SYS_NMLN];

	moddir = (struct drvmod_dir *)calloc(1, sizeof (struct drvmod_dir));
	if (moddir == NULL) {
		(void) fprintf(stderr, gettext(ERR_NO_MEM));
		return (ERROR);
	}

	if (sysinfo(SI_ARCHITECTURE, arch, sizeof (arch)) == -1) {
		(void) fprintf(stderr, gettext(ERR_SYSINFO_ARCH));
		return (ERROR);
	}

	if (strcmp(arch, "sparc") == 0 || strcmp(arch, "i386") == 0) {
		moddir->next = (struct drvmod_dir *)
		    calloc(1, sizeof (struct drvmod_dir));
		if (moddir->next == NULL) {
			(void) fprintf(stderr, gettext(ERR_NO_MEM));
			return (ERROR);
		}
		if (kelf_type == ELFCLASS64) {
			(void) strcpy(moddir->direc, DRVDIR64);
			(void) strcpy(moddir->next->direc, "");
		} else {
			(void) strcpy(moddir->direc, "");
			(void) strcpy(moddir->next->direc, DRVDIR64);
		}
		moddir->next->next = NULL;
		return (NOERR);
	} else {
		(void) fprintf(stderr, gettext(ERR_ARCH_NOT_SUPPORTED), arch);
		return (ERROR);
	}
}

void
remove_slashes(char *path)
{
	char *slash = path;
	char *remain_str;
	int pathlen;

	while ((slash = strchr(slash, '/')) != NULL) {
		remain_str = ++slash;
		while (*remain_str == '/')
			++remain_str;
		if (slash != remain_str)
			(void) strcpy(slash, remain_str);
	}

	pathlen = strlen(path);
	if ((pathlen > 1) && path[pathlen - 1] == '/')
		path[pathlen - 1] = '\0';
}

/*
 * This is for ITU floppies to add packages to the miniroot
 */
static int
ignore_root_basedir(void)
{
	struct stat statbuf;

	return (stat("/ADD_DRV_IGNORE_ROOT_BASEDIR", &statbuf) == 0);
}
