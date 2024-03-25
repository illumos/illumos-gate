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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2020 Oxide Computer Company
 */

/*
 * fwflash.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <sys/queue.h>
#include <signal.h>
#include <locale.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <dirent.h>
#include <sys/varargs.h>
#include <libintl.h> /* for gettext(3c) */
#include <libdevinfo.h>
#include <libscf_priv.h>
#include <fwflash/fwflash.h>
#include <sys/modctl.h> /* for MAXMODCONFNAME */

/* global arg list */
int	fwflash_arg_list = 0;
char	*filelist[10];

/* exposed global args */
di_node_t rootnode;
struct PLUGINLIST *fw_pluginlist;
struct DEVICELIST *fw_devices;
struct vrfyplugin *verifier;
struct fw_plugin *self;
int fwflash_debug = 0;

/* are we writing to flash? */
static int fwflash_in_write = 0;

/*
 * If we *must* track the version string for fwflash, then
 * we should do so in this common file rather than the header
 * file since it will then be in sync with what the customer
 * sees. We should deprecate the "-v" option since it is not
 * actually of any use - it doesn't line up with Mercurial's
 * concept of the changeset.
 */
#define	FWFLASH_VERSION		"v1.9"
#define	FWFLASH_PROG_NAME	"fwflash"

static int get_fileopts(char *options);
static int flash_device_list();
static int flash_load_plugins();
static int fwflash_update(char *device, char *filename, int flags);
static int fwflash_read_file(char *device, char *filename);
static int fwflash_list_fw(char *class);
static int fwflash_load_verifier(char *drv, char *vendorid, char *fwimg);
static void fwflash_intr(int sig);
static void fwflash_handle_signals(void);
static void fwflash_usage(char *arg);
static void fwflash_version(void);
static int confirm_target(struct devicelist *thisdev, char *file);

/*
 * FWFlash main code
 */
int
main(int argc, char **argv)
{
	int		rv = FWFLASH_SUCCESS;
	int		i;
	int		ch;
	char		*read_file;
	extern char	*optarg;
	char		*devclass = NULL;
	char		*devpath = NULL;

	/* local variables from env */
	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it isn't. */
#endif

	(void) textdomain(TEXT_DOMAIN);

	read_file = NULL;

	if (argc < 2) {
		/* no args supplied */
		fwflash_usage(NULL);
		return (FWFLASH_FAILURE);
	}

	while ((ch = getopt(argc, argv, "hvylc:f:r:Qd:")) != EOF) {
		switch (ch) {
		case 'h':
			fwflash_arg_list |= FWFLASH_HELP_FLAG;
			break;
		case 'v':
			fwflash_arg_list |= FWFLASH_VER_FLAG;
			break;
		case 'y':
			fwflash_arg_list |= FWFLASH_YES_FLAG;
			break;
		case 'l':
			fwflash_arg_list |= FWFLASH_LIST_FLAG;
			break;
		case 'c':
			fwflash_arg_list |= FWFLASH_CLASS_FLAG;
			/* we validate later */
			devclass = strdup(optarg);
			break;
		case 'd':
			fwflash_arg_list |= FWFLASH_DEVICE_FLAG;
			devpath = strdup(optarg);
			break;
		case 'f':
			fwflash_arg_list |= FWFLASH_FW_FLAG;
			if ((rv = get_fileopts(optarg)) != FWFLASH_SUCCESS) {
				fwflash_usage(NULL);
				return (FWFLASH_FAILURE);
			}
			break;
		case 'r':
			fwflash_arg_list |= FWFLASH_READ_FLAG;
			read_file = strdup(optarg);
			break;
		case 'Q':
			/* NOT in the manpage */
			fwflash_debug = 1;
			break;
		/* illegal options */
		default:
			fwflash_usage(optarg);
			return (FWFLASH_FAILURE);
		}
	}

	/* Do Help */
	if ((fwflash_arg_list & FWFLASH_HELP_FLAG) ||
	    ((fwflash_arg_list & FWFLASH_DEVICE_FLAG) &&
	    !((fwflash_arg_list & FWFLASH_FW_FLAG) ||
	    (fwflash_arg_list & FWFLASH_READ_FLAG)))) {
		fwflash_usage(NULL);
		return (FWFLASH_SUCCESS);
	}

	/* Do Version */
	if (fwflash_arg_list == FWFLASH_VER_FLAG) {
		fwflash_version();
		return (FWFLASH_SUCCESS);
	}

	/* generate global list of devices */
	if ((rv = flash_load_plugins()) != FWFLASH_SUCCESS) {
		logmsg(MSG_ERROR,
		    gettext("Unable to load fwflash plugins\n"));
		fwflash_intr(0);
		return (rv);
	}

	if ((rv = flash_device_list()) != FWFLASH_SUCCESS) {
		logmsg(MSG_ERROR,
		    gettext("No flashable devices in this system\n"));
		fwflash_intr(0);
		return (rv);
	}

	/* Do list */
	if (fwflash_arg_list == (FWFLASH_LIST_FLAG) ||
	    fwflash_arg_list == (FWFLASH_LIST_FLAG | FWFLASH_CLASS_FLAG)) {
		rv = fwflash_list_fw(devclass);
		fwflash_intr(0);
		return (rv);
	}

	fwflash_handle_signals();

	/* Do flash update (write) */
	if ((fwflash_arg_list == (FWFLASH_FW_FLAG | FWFLASH_DEVICE_FLAG)) ||
	    (fwflash_arg_list == (FWFLASH_FW_FLAG | FWFLASH_DEVICE_FLAG |
	    FWFLASH_YES_FLAG))) {
		int fastreboot_disabled = 0;
		/* the update function handles the real arg parsing */
		i = 0;
		while (filelist[i] != NULL) {
			if ((rv = fwflash_update(devpath, filelist[i],
			    fwflash_arg_list)) == FWFLASH_SUCCESS) {
				/* failed ops have already been noted */
				if (!fastreboot_disabled &&
				    scf_fastreboot_default_set_transient(
				    B_FALSE) != SCF_SUCCESS)
					logmsg(MSG_ERROR, gettext(
					    "Failed to disable fast "
					    "reboot.\n"));
				else
					fastreboot_disabled = 1;
				logmsg(MSG_ERROR,
				    gettext("New firmware will be activated "
				    "after you reboot\n\n"));
			}
			++i;
		}

		fwflash_intr(0);
		return (rv);
	}

	/* Do flash read */
	if ((fwflash_arg_list == (FWFLASH_READ_FLAG | FWFLASH_DEVICE_FLAG)) ||
	    (fwflash_arg_list == (FWFLASH_READ_FLAG | FWFLASH_DEVICE_FLAG |
	    FWFLASH_YES_FLAG))) {
		rv = fwflash_read_file(devpath, read_file);
		fwflash_intr(0);
		return (rv);
	}

	fwflash_usage(NULL);

	return (FWFLASH_FAILURE);
}


static int
flash_load_plugins()
{

	int rval = FWFLASH_SUCCESS;
	DIR *dirp;
	struct dirent *plugdir;
	char *plugname;
	struct fw_plugin *tmpplug;
	struct pluginlist *tmpelem;
	void *sym;
	char *fwplugdirpath, *tempdirpath;


#define	CLOSEFREE()	{			\
	(void) dlclose(tmpplug->handle);	\
	free(tmpplug); }

	/*
	 * Procedure:
	 *
	 * cd /usr/lib/fwflash/identify
	 * open each .so file found therein
	 * dlopen(.sofile)
	 * if it's one of our plugins, add it to fw_pluginlist;
	 *
	 * functions we need here include dlopen and dlsym.
	 *
	 * If we get to the end and fw_pluginlist struct is empty,
	 * return FWFLASH_FAILURE so we return to the shell.
	 */

	if ((fwplugdirpath = calloc(1, MAXPATHLEN + 1)) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("Unable to malloc %d bytes while "
		    "trying to load plugins: %s\n"),
		    MAXPATHLEN + 1, strerror(errno));
		return (FWFLASH_FAILURE);
	}

	tempdirpath = getenv("FWPLUGINDIR");

	if ((fwflash_debug > 0) && (tempdirpath != NULL)) {
		(void) strlcpy(fwplugdirpath, tempdirpath,
		    strlen(tempdirpath) + 1);
	} else {
		(void) strlcpy(fwplugdirpath, FWPLUGINDIR,
		    strlen(FWPLUGINDIR) + 1);
	}

	if ((dirp = opendir(fwplugdirpath)) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("Unable to open %s\n"),
		    fwplugdirpath);
		return (errno);
	}

	if ((fw_pluginlist = calloc(1, sizeof (struct fw_plugin)))
	    == NULL) {
		logmsg(MSG_ERROR,
		    gettext("Unable to malloc %d bytes while "
		    "trying to load plugins: %s\n"),
		    sizeof (struct fw_plugin), strerror(errno));
		return (FWFLASH_FAILURE);
	}

	TAILQ_INIT(fw_pluginlist);

	while ((plugdir = readdir(dirp)) != NULL) {

		errno = 0; /* remove chance of false results */

		if ((plugdir->d_name[0] == '.') ||
		    (strstr(plugdir->d_name, ".so") == NULL)) {
			continue;
		}

		if ((plugname = calloc(1, MAXPATHLEN + 1)) == NULL) {
			logmsg(MSG_ERROR,
			    gettext("Unable to malloc %d bytes while "
			    "trying to load plugins: %s\n"),
			    MAXPATHLEN + 1, strerror(errno));
			return (FWFLASH_FAILURE);
		}

		(void) snprintf(plugname, MAXPATHLEN, "%s/%s",
		    fwplugdirpath, plugdir->d_name);

		/* start allocating storage */
		if ((tmpelem = calloc(1, sizeof (struct pluginlist)))
		    == NULL) {
			logmsg(MSG_ERROR,
			    gettext("Unable to malloc %d bytes while "
			    "trying to load plugins: %s\n"),
			    sizeof (struct pluginlist), strerror(errno));
			return (FWFLASH_FAILURE);
		}

		if ((tmpplug = calloc(1, sizeof (struct fw_plugin)))
		    == NULL) {
			logmsg(MSG_ERROR,
			    gettext("Unable to malloc %d bytes while "
			    "trying to load plugins: %s\n"),
			    sizeof (struct fw_plugin), strerror(errno));
			return (FWFLASH_FAILURE);
		}

		/* load 'er up! */
		tmpplug->handle = dlopen(plugname, RTLD_NOW);
		if (tmpplug->handle == NULL) {
			free(tmpplug);
			continue; /* assume there are other plugins */
		}

		if ((tmpplug->filename = calloc(1, strlen(plugname) + 1))
		    == NULL) {
			logmsg(MSG_ERROR,
			    gettext("Unable to allocate %d bytes for plugin "
			    "filename %s:%s\n"),
			    strlen(plugname) + 1, plugname,
			    strerror(errno));
			return (rval);
		}

		(void) strlcpy(tmpplug->filename, plugname,
		    strlen(plugname) + 1);

		/* now sanity check the file */
		if ((sym = dlsym(tmpplug->handle, "drivername"))
		    != NULL) {
			/* max length of drivername */
			tmpplug->drvname = calloc(1, MAXMODCONFNAME);

			/* are we doing double-time? */
			if (strncmp((char *)sym, plugdir->d_name,
			    MAXMODCONFNAME) != 0) {
				char *tempnm = calloc(1, MAXMODCONFNAME);

				(void) memcpy(tempnm, plugdir->d_name,
				    MAXMODCONFNAME);
				(void) strlcpy(tmpplug->drvname,
				    strtok(tempnm, "."),
				    strlen(plugdir->d_name) + 1);
				free(tempnm);
			} else {
				(void) strlcpy(tmpplug->drvname,
				    (char *)sym, strlen(sym) + 1);
			}
		} else {
			CLOSEFREE();
			continue;
		}
		if ((sym = dlsym(tmpplug->handle, "fw_readfw"))
		    != NULL) {
			tmpplug->fw_readfw = (int (*)())sym;
		} else {
			CLOSEFREE();
			continue;
		}
		if ((sym = dlsym(tmpplug->handle, "fw_writefw"))
		    != NULL) {
			tmpplug->fw_writefw = (int (*)())sym;
		} else {
			CLOSEFREE();
			continue;
		}

		if ((sym = dlsym(tmpplug->handle, "fw_identify"))
		    != NULL) {
			tmpplug->fw_identify =
			    (int (*)(int))sym;
		} else {
			CLOSEFREE();
			continue;
		}
		if ((sym = dlsym(tmpplug->handle, "fw_devinfo"))
		    != NULL) {
			tmpplug->fw_devinfo =
			    (int (*)(struct devicelist *))sym;
		} else {
			CLOSEFREE();
			continue;
		}

		if ((sym = dlsym(tmpplug->handle, "plugin_version")) != NULL) {
			if ((*(int *)sym) >= FWPLUGIN_VERSION_2) {
				if ((sym = dlsym(tmpplug->handle,
				    "fw_cleanup")) != NULL) {
					tmpplug->fw_cleanup =
					    (void (*)(struct devicelist *))sym;
				} else {
					logmsg(MSG_ERROR,
					    gettext("ERROR: v2 plugin (%s) "
					    "has no fw_cleanup function\n"),
					    tmpplug->filename);
					CLOSEFREE();
					continue;
				}
			} else {
				logmsg(MSG_INFO,
				    "Identification plugin %s defined "
				    "plugin_version < FWPLUGIN_VERSION_2 !");
			}
		}

		if ((tmpelem->drvname = calloc(1, MAXMODCONFNAME))
		    == NULL) {
			logmsg(MSG_ERROR,
			    gettext("Unable to allocate space for a"
			    "drivername %s\n"),
			    tmpplug->drvname);
			return (FWFLASH_FAILURE);
		}

		(void) strlcpy(tmpelem->drvname, tmpplug->drvname,
		    strlen(tmpplug->drvname) + 1);

		if ((tmpelem->filename = calloc(1,
		    strlen(tmpplug->filename) + 1)) == NULL) {
			logmsg(MSG_ERROR,
			    gettext("Unable to allocate %d bytes for "
			    "filename %s\n"),
			    strlen(tmpplug->filename) + 1,
			    tmpplug->filename);
			return (FWFLASH_FAILURE);
		}

		(void) strlcpy(tmpelem->filename, plugname,
		    strlen(plugname) + 1);
		tmpelem->plugin = tmpplug;

		/* CONSTCOND */
		TAILQ_INSERT_TAIL(fw_pluginlist, tmpelem, nextplugin);
	}

	if ((plugdir == NULL) && TAILQ_EMPTY(fw_pluginlist)) {
		return (FWFLASH_FAILURE);
	}

	if (errno != 0) {
		logmsg(MSG_ERROR,
		    gettext("Error reading directory entry in %s\n"),
		    fwplugdirpath);
		rval = errno;
	}

	free(fwplugdirpath);
	(void) closedir(dirp);
	return (rval);
}

/*
 * fwflash_load_verifier dlload()s the appropriate firmware image
 * verification plugin, and attaches the designated fwimg's fd to
 * the vrfyplugin structure so we only have to load the image in
 * one place.
 */
int
fwflash_load_verifier(char *drv, char *vendorid, char *fwimg)
{

	int rv = FWFLASH_FAILURE;
	int imgfd;
	char *fwvrfydirpath, *tempdirpath, *filename;
	char *clean; /* for the space-removed vid */
	struct stat fwstat;
	struct vrfyplugin *vrfy;
	void *vrfysym;

	/*
	 * To make flashing multiple firmware images somewhat more
	 * efficient, we start this function by checking whether a
	 * verifier for this device has already been loaded. If it
	 * has been loaded, we replace the imgfile information, and
	 * then continue as if we were loading for the first time.
	 */

	if (verifier != NULL) {
		verifier->imgsize = 0;
		verifier->flashbuf = 0; /* set by the verifier function */

		if (verifier->imgfile != NULL) {
			free(verifier->imgfile);
			verifier->imgfile = NULL;
		}

		if (verifier->fwimage != NULL) {
			free(verifier->fwimage);
			verifier->fwimage = NULL;
		}
	} else {
		if ((fwvrfydirpath = calloc(1, MAXPATHLEN + 1)) == NULL) {
			logmsg(MSG_ERROR,
			    gettext("Unable to allocate space for a firmware "
			    "verifier file(1)"));
			return (rv);
		}

		if ((filename = calloc(1, MAXPATHLEN + 1)) == NULL) {
			logmsg(MSG_ERROR,
			    gettext("Unable to allocate space "
			    "for a firmware verifier file(2)"));
			free(fwvrfydirpath);
			return (rv);
		}

		/*
		 * Since SCSI devices can have a vendor id of up to 8
		 * left-aligned and _space-padded_ characters, we first need to
		 * strip off any space characters before we try to make a
		 * filename out of it
		 */
		clean = strtok(vendorid, " ");
		if (clean == NULL) {
			/* invalid vendorid, something's really wrong */
			logmsg(MSG_ERROR,
			    gettext("Invalid vendorid (null) specified for "
			    "device\n"));
			free(filename);
			free(fwvrfydirpath);
			return (rv);
		}

		tempdirpath = getenv("FWVERIFYPLUGINDIR");

		if ((fwflash_debug > 0) && (tempdirpath != NULL)) {
			(void) strlcpy(fwvrfydirpath, tempdirpath,
			    strlen(tempdirpath) + 1);
		} else {
			(void) strlcpy(fwvrfydirpath, FWVERIFYPLUGINDIR,
			    strlen(FWVERIFYPLUGINDIR) + 1);
		}

		if ((vrfy = calloc(1, sizeof (struct vrfyplugin))) == NULL) {
			logmsg(MSG_ERROR,
			    gettext("Unable to allocate space "
			    "for a firmware verifier structure"));
			free(filename);
			free(fwvrfydirpath);
			return (rv);
		}

		errno = 0; /* false positive removal */

		(void) snprintf(filename, MAXPATHLEN, "%s/%s-%s.so",
		    fwvrfydirpath, drv, clean);
		if ((vrfy->handle = dlopen(filename, RTLD_NOW)) == NULL) {
			logmsg(MSG_INFO, gettext(dlerror()));
			logmsg(MSG_INFO,
			    gettext("\nUnable to open verification plugin "
			    "%s. Looking for %s-GENERIC plugin instead.\n"),
			    filename, drv);

			/* Try the drv-GENERIC.so form, _then_ die */
			bzero(filename, strlen(filename) + 1);
			(void) snprintf(filename, MAXPATHLEN,
			    "%s/%s-GENERIC.so", fwvrfydirpath, drv);

			if ((vrfy->handle = dlopen(filename, RTLD_NOW))
			    == NULL) {
				logmsg(MSG_INFO, gettext(dlerror()));
				logmsg(MSG_ERROR,
				    gettext("\nUnable to open either "
				    "verification plugin %s/%s-%s.so or "
				    "generic plugin %s.\nUnable to verify "
				    "firmware image. Aborting.\n"),
				    fwvrfydirpath, drv, clean, filename);
				free(filename);
				free(fwvrfydirpath);
				return (rv);
			}
		}

		if ((vrfy->filename = calloc(1, strlen(filename) + 1))
		    == NULL) {
			logmsg(MSG_ERROR,
			    gettext("Unable to allocate space to store "
			    "a verifier filename\n"));
			free(filename);
			free(fwvrfydirpath);
			free(vrfy->handle);
			return (rv);
		}
		(void) strlcpy(vrfy->filename, filename, strlen(filename) + 1);

		if ((vrfysym = dlsym(vrfy->handle, "vendorvrfy")) == NULL) {
			logmsg(MSG_ERROR,
			    gettext("%s is an invalid firmware verification "
			    "plugin."), filename);
			(void) dlclose(vrfy->handle);
			free(filename);
			free(fwvrfydirpath);
			free(vrfy);
			return (rv);
		} else {
			vrfy->vendorvrfy =
			    (int (*)(struct devicelist *))vrfysym;
		}

		vrfysym = dlsym(vrfy->handle, "vendor");

		if (vrfysym == NULL) {
			logmsg(MSG_ERROR,
			    gettext("Invalid vendor (null) in verification "
			    "plugin %s\n"), filename);
			(void) dlclose(vrfy->handle);
			free(vrfy);
			return (rv);
		} else {
			if (strncmp(vendorid, (char *)vrfysym,
			    strlen(vendorid)) != 0) {
				logmsg(MSG_INFO,
				    "Using a sym-linked (%s -> %s) "
				    "verification plugin\n",
				    vendorid, vrfysym);
				vrfy->vendor = calloc(1, strlen(vendorid) + 1);
			} else {
				vrfy->vendor = calloc(1, strlen(vrfysym) + 1);
			}
			(void) strlcpy(vrfy->vendor, (char *)vrfysym,
			    strlen(vendorid) + 1);
		}

		verifier = vrfy; /* a convenience variable */
		free(filename);
		free(fwvrfydirpath);
	}

	/*
	 * We don't do any verification that the fw image file is in
	 * an approved location, but it's easy enough to modify this
	 * function to do so. The verification plugin should provide
	 * sufficient protection.
	 */

	if ((imgfd = open(fwimg, O_RDONLY)) < 0) {
		logmsg(MSG_ERROR,
		    gettext("Unable to open designated firmware "
		    "image file %s: %s\n"),
		    (fwimg != NULL) ? fwimg : "(null)",
		    strerror(errno));
		rv = FWFLASH_FAILURE;
		goto cleanup;
	}

	if (stat(fwimg, &fwstat) == -1) {
		logmsg(MSG_ERROR,
		    gettext("Unable to stat() firmware image file "
		    "%s: %s\n"),
		    fwimg, strerror(errno));
		rv = FWFLASH_FAILURE;
		goto cleanup;
	} else {
		verifier->imgsize = fwstat.st_size;
		if ((verifier->fwimage = calloc(1, verifier->imgsize))
		    == NULL) {
			logmsg(MSG_ERROR,
			    gettext("Unable to load firmware image "
			    "%s: %s\n"),
			    fwimg, strerror(errno));
			rv = FWFLASH_FAILURE;
			goto cleanup;
		}
	}

	errno = 0;
	if ((rv = read(imgfd, verifier->fwimage,
	    (size_t)verifier->imgsize)) < verifier->imgsize) {
		/* we haven't read enough data, bail */
		logmsg(MSG_ERROR,
		    gettext("Failed to read sufficient data "
		    "(got %d bytes, expected %d bytes) from "
		    "firmware image file %s: %s\n"),
		    rv, verifier->imgsize,
		    verifier->filename, strerror(errno));
		rv = FWFLASH_FAILURE;
	} else {
		rv = FWFLASH_SUCCESS;
	}

	if ((verifier->imgfile = calloc(1, strlen(fwimg) + 1)) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("Unable to save name of firmware image\n"));
		rv = FWFLASH_FAILURE;
	} else {
		(void) strlcpy(verifier->imgfile, fwimg, strlen(fwimg) + 1);
	}

	if (rv != FWFLASH_SUCCESS) {
		/* cleanup and let's get outta here */
cleanup:
		free(verifier->filename);
		free(verifier->vendor);

		if (!(fwflash_arg_list & FWFLASH_READ_FLAG) &&
		    verifier->fwimage)
			free(verifier->fwimage);

		verifier->filename = NULL;
		verifier->vendor = NULL;
		verifier->vendorvrfy = NULL;
		verifier->fwimage = NULL;
		(void) dlclose(verifier->handle);
		verifier->handle = NULL;
		free(verifier);
		if (imgfd >= 0) {
			(void) close(imgfd);
		}
		verifier = NULL;
	}

	return (rv);
}

/*
 * cycles through the global list of plugins to find
 * each flashable device, which is added to fw_devices
 *
 * Each plugin's identify routine must allocated storage
 * as required.
 *
 * Each plugin's identify routine must return
 * FWFLASH_FAILURE if it cannot find any devices
 * which it handles.
 */
static int
flash_device_list()
{
	int rv = FWFLASH_FAILURE;
	int startidx = 0;
	int sumrv = 0;
	struct pluginlist *plugins;

	/* we open rootnode here, and close it in fwflash_intr */
	if ((rootnode = di_init("/", DINFOCPYALL|DINFOFORCE)) == DI_NODE_NIL) {
		logmsg(MSG_ERROR,
		    gettext("Unable to take device tree snapshot: %s\n"),
		    strerror(errno));
		return (rv);
	}

	if ((fw_devices = calloc(1, sizeof (struct devicelist))) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("Unable to malloc %d bytes while "
		    "trying to find devices: %s\n"),
		    sizeof (struct devicelist), strerror(errno));
		return (FWFLASH_FAILURE);
	}

	/* CONSTCOND */
	TAILQ_INIT(fw_devices);

	TAILQ_FOREACH(plugins, fw_pluginlist, nextplugin) {
		self = plugins->plugin;
		rv = plugins->plugin->fw_identify(startidx);

		logmsg(MSG_INFO,
		    gettext("fwflash:flash_device_list() got %d from "
		    "identify routine\n"), rv);

		/* only bump startidx if we've found at least one device */
		if (rv == FWFLASH_SUCCESS) {
			startidx += 100;
			sumrv++;
		} else {
			logmsg(MSG_INFO,
			    gettext("No flashable devices attached with "
			    "the %s driver in this system\n"),
			    plugins->drvname);
		}
	}

	if (sumrv > 0)
		rv = FWFLASH_SUCCESS;

	return (rv);
}

static int
fwflash_list_fw(char *class)
{
	int rv = 0;
	struct devicelist *curdev;
	int header = 1;

	TAILQ_FOREACH(curdev, fw_devices, nextdev) {

		/* we're either class-conscious, or we're not */
		if (((class != NULL) &&
		    ((strncmp(curdev->classname, "ALL", 3) == 0) ||
		    (strcmp(curdev->classname, class) == 0))) ||
		    (class == NULL)) {

			if (header != 0) {
				(void) fprintf(stdout,
				    gettext("List of available devices:\n"));
				header--;
			}
			/*
			 * If any plugin's fw_devinfo() function returns
			 * FWFLASH_FAILURE then we want to keep track of
			 * it. _Most_ plugins should always return
			 * FWFLASH_SUCCESS from this function. The only
			 * exception known at this point is the tavor plugin.
			 */
			rv += curdev->plugin->fw_devinfo(curdev);
		}
	}
	return (rv);
}

static int
fwflash_update(char *device, char *filename, int flags)
{

	int rv = FWFLASH_FAILURE;
	int needsfree = 0;
	int found = 0;
	struct devicelist *curdev;
	char *realfile;

	/*
	 * Here's how we operate:
	 *
	 * We perform some basic checks on the args, then walk
	 * through the device list looking for the device which
	 * matches. We then load the appropriate verifier for the
	 * image file and device, verify the image, then call the
	 * fw_writefw() function of the appropriate plugin.
	 *
	 * There is no "force" flag to enable you to flash a firmware
	 * image onto an incompatible device because the verifier
	 * will return FWFLASH_FAILURE if the image doesn't match.
	 */

	/* new firmware filename and device desc */
	if (filename == NULL) {
		logmsg(MSG_ERROR,
		    gettext("Invalid firmware filename (null)\n"));
		return (FWFLASH_FAILURE);
	}

	if (device == NULL) {
		logmsg(MSG_ERROR,
		    gettext("Invalid device requested (null)\n"));
		return (FWFLASH_FAILURE);
	}

	if ((realfile = calloc(1, PATH_MAX + 1)) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("Unable to allocate space for device "
		    "filename, operation might fail if %s is"
		    "a symbolic link\n"),
		    device);
		realfile = device;
	} else {
		/*
		 * If realpath() succeeds, then we have a valid
		 * device filename in realfile.
		 */
		if (realpath(device, realfile) == NULL) {
			logmsg(MSG_ERROR,
			    gettext("Unable to resolve device filename"
			    ": %s\n"),
			    strerror(errno));
			/* tidy up */
			free(realfile);
			/* realpath didn't succeed, use fallback */
			realfile = device;
		} else {
			needsfree = 1;
		}
	}

	logmsg(MSG_INFO,
	    gettext("fwflash_update: fw_filename (%s) device (%s)\n"),
	    filename, device);

	TAILQ_FOREACH(curdev, fw_devices, nextdev) {
		if (strcmp(curdev->access_devname, realfile) == 0) {
			found++;
			rv = fwflash_load_verifier(curdev->drvname,
			    curdev->ident->vid, filename);
			if (rv == FWFLASH_FAILURE) {
				logmsg(MSG_ERROR,
				    gettext("Unable to load verifier "
				    "for device %s\n"),
				    curdev->access_devname);
				return (FWFLASH_FAILURE);
			}
			rv = verifier->vendorvrfy(curdev);
			if (rv == FWFLASH_FAILURE) {
				/* the verifier prints a message */
				logmsg(MSG_INFO,
				    "verifier (%s) for %s :: %s returned "
				    "FWFLASH_FAILURE\n",
				    verifier->filename,
				    filename, curdev->access_devname);
				return (rv);
			}

			if (((flags & FWFLASH_YES_FLAG) == FWFLASH_YES_FLAG) ||
			    (rv = confirm_target(curdev, filename)) ==
			    FWFLASH_YES_FLAG) {
				logmsg(MSG_INFO,
				    "about to flash using plugin %s\n",
				    curdev->plugin->filename);
				rv = curdev->plugin->fw_writefw(curdev,
				    filename);
				if (rv == FWFLASH_FAILURE) {
					logmsg(MSG_ERROR,
					    gettext("Failed to flash "
					    "firmware file %s on "
					    "device %s: %d\n"),
					    filename,
					    curdev->access_devname, rv);
				}
			} else {
				logmsg(MSG_ERROR,
				    gettext("Flash operation not confirmed "
				    "by user\n"),
				    curdev->access_devname);
				rv = FWFLASH_FAILURE;
			}
		}
	}

	if (!found)
		/* report the same device that the user passed in */
		logmsg(MSG_ERROR,
		    gettext("Device %s does not appear "
		    "to be flashable\n"),
		    ((strncmp(device, realfile, strlen(device)) == 0) ?
		    realfile : device));

	if (needsfree)
		free(realfile);

	return (rv);
}

/*
 * We validate that the device path is in our global device list and
 * that the filename exists, then palm things off to the relevant plugin.
 */
static int
fwflash_read_file(char *device, char *filename)
{
	struct devicelist *curdev;
	int rv;
	int found = 0;

	/* new firmware filename and device desc */

	TAILQ_FOREACH(curdev, fw_devices, nextdev) {
		if (strncmp(curdev->access_devname, device,
		    MAXPATHLEN) == 0) {
			rv = curdev->plugin->fw_readfw(curdev, filename);

			if (rv != FWFLASH_SUCCESS)
				logmsg(MSG_ERROR,
				    gettext("Unable to write out firmware "
				    "image for %s to file %s\n"),
				    curdev->access_devname, filename);
			found++;
		}

	}

	if (!found) {
		logmsg(MSG_ERROR,
		    gettext("No device matching %s was found.\n"),
		    device);
		rv = FWFLASH_FAILURE;
	}

	return (rv);
}

static void
fwflash_usage(char *arg)
{

	(void) fprintf(stderr, "\n");
	if (arg != NULL) {
		logmsg(MSG_ERROR,
		    gettext("Invalid argument (%s) supplied\n"), arg);
	}

	(void) fprintf(stderr, "\n");

	(void) fprintf(stdout, gettext("Usage:\n\t"));
	(void) fprintf(stdout, gettext("fwflash [-l [-c device_class "
	    "| ALL]] | [-v] | [-h]\n\t"));
	(void) fprintf(stdout, gettext("fwflash [-f file1,file2,file3"
	    ",... | -r file] [-y] -d device_path\n\n"));
	(void) fprintf(stdout, "\n"); /* workaround for xgettext */

	(void) fprintf(stdout,
	    gettext("\t-l\t\tlist flashable devices in this system\n"
	    "\t-c device_class limit search to a specific class\n"
	    "\t\t\teg IB for InfiniBand, ses for SCSI Enclosures\n"
	    "\t-v\t\tprint version number of fwflash utility\n"
	    "\t-h\t\tprint this usage message\n\n"));
	(void) fprintf(stdout,
	    gettext("\t-f file1,file2,file3,...\n"
	    "\t\t\tfirmware image file list to flash\n"
	    "\t-r file\t\tfile to dump device firmware to\n"
	    "\t-y\t\tanswer Yes/Y/y to prompts\n"
	    "\t-d device_path\tpathname of device to be flashed\n\n"));

	(void) fprintf(stdout,
	    gettext("\tIf -d device_path is specified, then one of -f "
	    "<files>\n"
	    "\tor -r <file> must also be specified\n\n"));

	(void) fprintf(stdout,
	    gettext("\tIf multiple firmware images are required to be "
	    "flashed\n"
	    "\tthey must be listed together, separated by commas. The\n"
	    "\timages will be flashed in the order specified.\n\n"));

	(void) fprintf(stdout, "\n");
}

static void
fwflash_version(void)
{
	(void) fprintf(stdout, gettext("\n%s: "), FWFLASH_PROG_NAME);
	(void) fprintf(stdout, gettext("version %s\n"),
	    FWFLASH_VERSION);
}

static void
fwflash_intr(int sig)
{

	struct devicelist *thisdev, *tmpdev;
	struct pluginlist *thisplug, *tmpplug;

	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGTERM, SIG_IGN);
	(void) signal(SIGABRT, SIG_IGN);

	if (fwflash_in_write) {
		(void) fprintf(stderr,
		    gettext("WARNING: firmware image may be corrupted\n\t"));
		(void) fprintf(stderr,
		    gettext("Reflash firmware before rebooting!\n"));
	}

	if (sig > 0) {
		(void) logmsg(MSG_ERROR, gettext("\n"));
		(void) logmsg(MSG_ERROR,
		    gettext("fwflash exiting due to signal (%d)\n"), sig);
	}

	/*
	 * we need to close everything down properly, so
	 * call the plugin closure routines
	 */
	if (fw_devices != NULL) {
		TAILQ_FOREACH_SAFE(thisdev, fw_devices, nextdev, tmpdev) {
			TAILQ_REMOVE(fw_devices, thisdev, nextdev);
			if (thisdev->plugin->fw_cleanup != NULL) {
				/*
				 * If we've got a cleanup routine, it
				 * cleans up _everything_ for thisdev
				 */
				thisdev->plugin->fw_cleanup(thisdev);
			} else {
				/* free the components first */
				free(thisdev->access_devname);
				free(thisdev->drvname);
				free(thisdev->classname);
				if (thisdev->ident != NULL)
					free(thisdev->ident);
				/* We don't free address[] for old plugins */
				thisdev->ident = NULL;
				thisdev->plugin = NULL;
				free(thisdev);
			}
		}
	}

	if (fw_pluginlist != NULL) {
		TAILQ_FOREACH_SAFE(thisplug, fw_pluginlist, nextplugin,
		    tmpplug) {
			TAILQ_REMOVE(fw_pluginlist, thisplug, nextplugin);
			free(thisplug->filename);
			free(thisplug->drvname);
			free(thisplug->plugin->filename);
			free(thisplug->plugin->drvname);
			thisplug->filename = NULL;
			thisplug->drvname = NULL;
			thisplug->plugin->filename = NULL;
			thisplug->plugin->drvname = NULL;
			thisplug->plugin->fw_readfw = NULL;
			thisplug->plugin->fw_writefw = NULL;
			thisplug->plugin->fw_identify = NULL;
			thisplug->plugin->fw_devinfo = NULL;
			thisplug->plugin->fw_cleanup = NULL;
			(void) dlclose(thisplug->plugin->handle);
			thisplug->plugin->handle = NULL;
			free(thisplug->plugin);
			thisplug->plugin = NULL;
			free(thisplug);
		}
	}

	if (verifier != NULL) {
		free(verifier->filename);
		free(verifier->vendor);
		free(verifier->imgfile);
		free(verifier->fwimage);
		verifier->filename = NULL;
		verifier->vendor = NULL;
		verifier->vendorvrfy = NULL;
		verifier->imgfile = NULL;
		verifier->fwimage = NULL;
		(void) dlclose(verifier->handle);
		verifier->handle = NULL;
		free(verifier);
	}
	di_fini(rootnode);

	if (sig > 0)
		exit(FWFLASH_FAILURE);
}

static void
fwflash_handle_signals(void)
{
	if (signal(SIGINT, fwflash_intr) == SIG_ERR) {
		perror("signal");
		exit(FWFLASH_FAILURE);
	}

	if (signal(SIGTERM, fwflash_intr) == SIG_ERR) {
		perror("signal");
		exit(FWFLASH_FAILURE);
	}
}

static int
confirm_target(struct devicelist *thisdev, char *file)
{
	int resp;

	(void) fflush(stdin);
	(void) printf(gettext("About to update firmware on %s\n"),
	    thisdev->access_devname);
	(void) printf(gettext("with file %s.\n"
	    "Do you want to continue? (Y/N): "), file);

	resp = getchar();
	if (resp == 'Y' || resp == 'y') {
		return (FWFLASH_YES_FLAG);
	} else {
		logmsg(MSG_INFO, "flash operation NOT confirmed.\n");
	}

	(void) fflush(stdin);
	return (FWFLASH_FAILURE);
}

int
get_fileopts(char *options)
{

	int i;
	char *files;

	if (files = strtok(options, ",")) {
		/* we have more than one */
		if ((filelist[0] = calloc(1, MAXPATHLEN + 1)) == NULL) {
			logmsg(MSG_ERROR,
			    gettext("Unable to allocate space for "
			    "a firmware image filename\n"));
			return (FWFLASH_FAILURE);
		}
		(void) strlcpy(filelist[0], files, strlen(files) + 1);
		i = 1;

		logmsg(MSG_INFO, "fwflash: filelist[0]: %s\n",
		    filelist[0]);


		while (files = strtok(NULL, ",")) {
			if ((filelist[i] = calloc(1, MAXPATHLEN + 1))
			    == NULL) {
				logmsg(MSG_ERROR,
				    gettext("Unable to allocate space for "
				    "a firmware image filename\n"));
				return (FWFLASH_FAILURE);
			}
			(void) strlcpy(filelist[i], files,
			    strlen(files) + 1);
			logmsg(MSG_INFO, "fwflash: filelist[%d]: %s\n",
			    i, filelist[i]);
			++i;
		}
	} else {
		if ((filelist[0] = calloc(1, MAXPATHLEN + 1)) == NULL) {
			logmsg(MSG_ERROR,
			    gettext("Unable to allocate space for "
			    "a firmware image filename\n"));
			return (FWFLASH_FAILURE);
		}
		(void) strlcpy(filelist[0], options, strlen(files) + 1);
		logmsg(MSG_INFO, "fwflash: filelist[0]: %s\n",
		    filelist[0]);
	}
	return (FWFLASH_SUCCESS);
}

/*
 * code reuse - cheerfully borrowed from stmsboot_util.c
 */
void
logmsg(int severity, const char *msg, ...)
{
	va_list ap;

	if ((severity > MSG_INFO) ||
	    ((severity == MSG_INFO) && (fwflash_debug > 0))) {
		(void) fprintf(stderr, "%s: ", FWFLASH_PROG_NAME);
		va_start(ap, msg);
		(void) vfprintf(stderr, msg, ap);
		va_end(ap);
	}
}
