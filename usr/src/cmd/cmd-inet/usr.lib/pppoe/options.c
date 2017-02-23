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
 * PPPoE Server-mode daemon option parsing.
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <netdb.h>
#include <stropts.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/sppptun.h>

#include "common.h"
#include "logging.h"

#define	MAX_KEYWORD	4096	/* Maximum token length */
#define	MAX_NEST	32	/* Maximum ${$sub} nesting */
#define	MAXARGS		256	/* Maximum number of pppd arguments */

/*
 * Client filter entry.  These are linked in *reverse* order so that
 * the DAG created by file inclusion nesting works as expected.  Since
 * the administrator who wrote the configuration expects "first
 * match," this means that tests against the filter list must actually
 * use "last match."
 */
struct filter_entry {
	struct filter_entry *fe_prev;	/* Previous filter in list */
	struct ether_addr fe_mac;	/* MAC address */
	struct ether_addr fe_mask;	/* Mask for above address test */
	uchar_t fe_isexcept;	/* invert sense; exclude matching clients */
	uchar_t fe_prevcopy;		/* fe_prev points to copied list */
	uchar_t fe_unused[2];		/* padding */
};

/*
 * Note: I would like to make the strings and filters here const, but
 * I can't because they have to be passed to free() during parsing.  I
 * could work around this with offsetof() or data copies, but it's not
 * worth the effort.
 */
struct service_entry {
	const char *se_name;		/* Name of service */
	struct filter_entry *se_flist;	/* Pointer to list of client filters */
	uint_t se_flags;		/* SEF_* flags (below) */
	int se_debug;			/* Debug level (0=nodebug) */
	char *se_server;		/* Server (AC) name */
	char *se_pppd;			/* Options for pppd */
	char *se_path;			/* Path to pppd executable */
	char *se_extra;			/* Extra options */
	char *se_log;			/* Log file */
	uid_t se_uid;			/* User ID */
	gid_t se_gid;			/* Group ID */
};

#define	SEF_WILD	0x00000001	/* Offer in wildcard reply */
#define	SEF_NOWILD	0x00000002	/* Don't offer in wildcard */
#define	SEF_CFLIST	0x00000004	/* se_flist copied from global */
#define	SEF_CSERVER	0x00000008	/* se_server copied from global */
#define	SEF_CPPPD	0x00000010	/* se_pppd copied from global */
#define	SEF_CPATH	0x00000020	/* se_path copied from global */
#define	SEF_CEXTRA	0x00000040	/* se_extra copied from global */
#define	SEF_CLOG	0x00000080	/* se_log copied from global */
#define	SEF_UIDSET	0x00000100	/* se_uid has been set */
#define	SEF_GIDSET	0x00000200	/* se_gid has been set */
#define	SEF_DEBUGCLR	0x00000400	/* do not add se_debug from global */
#define	SEF_CDEV	0x00000800	/* copied devs (parse only) */

/*
 * One of these is allocated per lower-level stream (device) that is
 * referenced by the configuration files.  The queries are received
 * per device, and this structure allows us to find all of the
 * services that correspond to that device.
 */
struct device_entry {
	const char *de_name;
	const struct service_entry **de_services;
	int de_nservices;
};

/*
 * This is the parsed configuration.  While a new configuration is
 * being read, this is kept around until the new configuration is
 * ready, and then it is discarded in one operation.  It has an array
 * of device entries (as above) -- one per referenced lower stream --
 * and a pointer to the allocated parser information.  The latter is
 * kept around because we reuse pointers rather than reallocating and
 * copying the data.  There are thus multiple aliases to the dynamic
 * data, and the "owner" (for purposes of freeing the storage) is
 * considered to be this 'junk' list.
 */
struct option_state {
	const struct device_entry *os_devices;
	int os_ndevices;
	struct per_file *os_pfjunk;	/* Kept for deallocation */
	char **os_evjunk;		/* ditto */
};

/*
 * This is the root pointer to the current parsed options.
 * This cannot be const because it's passed to free() when reparsing
 * options.
 */
static struct option_state *cur_options;

/* Global settings for module-wide options. */
static struct service_entry glob_svc;

/*
 * *******************************************************************
 * Data structures generated during parsing.
 */

/* List of device names attached to one service */
struct device_list {
	struct device_list *dl_next;
	const char *dl_name;		/* Name of one device */
};

/* Entry for a single defined service. */
struct service_list {
	struct service_entry sl_entry;	/* Parsed service data */
	struct service_list *sl_next;	/* Next service entry */
	struct parse_state *sl_parse;	/* Back pointer to state */
	struct device_list *sl_dev;	/* List of devices */
	int sl_serial;			/* Serial number (conflict resolve) */
};
#define	SESERIAL(x)	((struct service_list *)&(x))->sl_serial
#define	ISGLOBAL(x)	((x) == &(x)->sl_parse->ps_cfile->pf_global)

/*
 * Structure allocated for each file opened.  File nesting is chained
 * in reverse order so that global option scoping works as expected.
 */
struct per_file {
	struct per_file *pf_prev;	/* Back chain */
	struct service_list pf_global;	/* Global (default) service context */
	struct service_list *pf_svc;	/* List of services */
	struct service_list *pf_svc_last;
	FILE *pf_input;			/* File for input */
	const char *pf_name;		/* File name */
	int pf_nsvc;			/* Count of services */
};

/* State of parser */
enum key_state {
	ksDefault, ksService, ksDevice, ksClient, ksClientE, ksServer,
	ksPppd, ksFile, ksPath, ksExtra, ksLog, ksUser, ksGroup
};

/*
 * Global parser state.  There is one of these structures, and it
 * exists only while actively parsing configuration files.
 */
struct parse_state {
	enum key_state ps_state;	/* Parser state */
	int ps_serial;			/* Service serial number */
	struct per_file *ps_files;	/* Parsed files */
	struct per_file *ps_cfile;	/* Current file */
	struct service_list *ps_csvc;	/* Current service */
	struct device_list *ps_star;	/* Wildcard device */
	int ps_flags;			/* PSF_* below */
	char **ps_evlist;		/* allocated environment variables */
	int ps_evsize;			/* max length; for realloc */
};

#define	PSF_PERDEV	0x0001		/* In a per-device file */
#define	PSF_SETLEVEL	0x0002		/* Set log level along the way */

/* Should be in a library somewhere. */
static char *
strsave(const char *str)
{
	char *newstr;

	if (str == NULL)
		return (NULL);
	newstr = (char *)malloc(strlen(str) + 1);
	if (newstr != NULL)
		(void) strcpy(newstr, str);
	return (newstr);
}

/*
 * Stop defining current service and revert to global definition.
 * This resolves any implicit references to global options by copying
 * ("inheriting") from the current global state.
 */
static void
close_service(struct service_list *slp)
{
	struct parse_state *psp;
	struct per_file *cfile;
	struct service_entry *sep;
	struct service_entry *sedefp;
	struct filter_entry *fep;

	assert(slp != NULL);
	psp = slp->sl_parse;
	cfile = psp->ps_cfile;

	/* If no current file, then nothing to close. */
	if (cfile == NULL)
		return;

	sep = &slp->sl_entry;

	/*
	 * Fix up filter pointers to make DAG.  First, locate
	 * the end of the filter list.
	 */
	if (sep->se_flags & SEF_CFLIST) {
		sep->se_flist = fep = NULL;
	} else {
		for (fep = sep->se_flist; fep != NULL; fep = fep->fe_prev)
			if (fep->fe_prev == NULL || fep->fe_prevcopy) {
				fep->fe_prev = NULL;
				break;
			}
	}
	if (slp == &cfile->pf_global) {
		/*
		 * If we're in a global context, then we're about to
		 * open a new service, so it's time to fix up the
		 * filter list so that it's usable as a reference.
		 * Loop through files from which we were included, and
		 * link up filters.  Note: closure may occur more than
		 * once here.
		 */
		/* We don't inherit from ourselves. */
		cfile = cfile->pf_prev;
		while (cfile != NULL) {
			if (fep == NULL) {
				sep->se_flist = fep =
				    cfile->pf_global.sl_entry.se_flist;
				sep->se_flags |= SEF_CFLIST;
			} else if (fep->fe_prev == NULL) {
				fep->fe_prev =
				    cfile->pf_global.sl_entry.se_flist;
				fep->fe_prevcopy = 1;
			}
			cfile = cfile->pf_prev;
		}
	} else {
		/*
		 * Loop through default options in current and all
		 * enclosing include files.  Inherit options.
		 */
		logdbg("service %s ends", slp->sl_entry.se_name);
		while (cfile != NULL) {
			/* Inherit from global service options. */
			if (slp->sl_dev == NULL) {
				slp->sl_dev = cfile->pf_global.sl_dev;
				sep->se_flags |= SEF_CDEV;
			}
			sedefp = &cfile->pf_global.sl_entry;
			if (fep == NULL) {
				sep->se_flist = fep = sedefp->se_flist;
				sep->se_flags |= SEF_CFLIST;
			} else if (fep->fe_prev == NULL) {
				fep->fe_prev = sedefp->se_flist;
				fep->fe_prevcopy = 1;
			}
			if (sep->se_server == NULL) {
				sep->se_server = sedefp->se_server;
				sep->se_flags |= SEF_CSERVER;
			}
			if (sep->se_pppd == NULL) {
				sep->se_pppd = sedefp->se_pppd;
				sep->se_flags |= SEF_CPPPD;
			}
			if (sep->se_path == NULL) {
				sep->se_path = sedefp->se_path;
				sep->se_flags |= SEF_CPATH;
			}
			if (sep->se_extra == NULL) {
				sep->se_extra = sedefp->se_extra;
				sep->se_flags |= SEF_CEXTRA;
			}
			if (sep->se_log == NULL) {
				sep->se_log = sedefp->se_log;
				sep->se_flags |= SEF_CLOG;
			}
			if (!(sep->se_flags & SEF_UIDSET) &&
			    (sedefp->se_flags & SEF_UIDSET)) {
				sep->se_uid = sedefp->se_uid;
				sep->se_flags |= SEF_UIDSET;
			}
			if (!(sep->se_flags & SEF_GIDSET) &&
			    (sedefp->se_flags & SEF_GIDSET)) {
				sep->se_gid = sedefp->se_gid;
				sep->se_flags |= SEF_GIDSET;
			}
			if (!(sep->se_flags & (SEF_WILD|SEF_NOWILD)))
				sep->se_flags |= sedefp->se_flags &
				    (SEF_WILD|SEF_NOWILD);
			if (!(sep->se_flags & SEF_DEBUGCLR)) {
				sep->se_debug += sedefp->se_debug;
				sep->se_flags |= sedefp->se_flags &
				    SEF_DEBUGCLR;
			}
			cfile = cfile->pf_prev;
		}
	}
	/* Revert to global definitions. */
	psp->ps_csvc = &psp->ps_cfile->pf_global;
}

/* Discard a dynamic device list */
static void
free_device_list(struct device_list *dlp)
{
	struct device_list *dln;

	while (dlp != NULL) {
		dln = dlp->dl_next;
		free(dlp);
		dlp = dln;
	}
}

/*
 * Handle "service <name>" -- finish up previous service definition
 * (if any) by copying from global state where necessary, and start
 * defining new service.
 */
static int
set_service(struct service_list *slp, const char *str)
{
	struct parse_state *psp;
	struct per_file *cfile;

	/* Finish current service */
	close_service(slp);

	/* Start new service */
	psp = slp->sl_parse;
	slp = (struct service_list *)calloc(sizeof (*slp) + strlen(str) + 1,
	    1);
	if (slp == NULL) {
		logerr("no memory for service \"%s\"", str);
		return (-1);
	}

	/* Add to end of list */
	cfile = psp->ps_cfile;
	if (cfile->pf_svc_last == NULL)
		cfile->pf_svc = slp;
	else
		cfile->pf_svc_last->sl_next = slp;
	cfile->pf_svc_last = slp;
	cfile->pf_nsvc++;

	/* Fill in initial service entry */
	slp->sl_entry.se_name = (const char *)(slp+1);
	(void) strcpy((char *)(slp+1), str);
	logdbg("service %s begins", slp->sl_entry.se_name);
	slp->sl_serial = psp->ps_serial++;
	slp->sl_parse = psp;

	/* This is now the current service that we're defining. */
	psp->ps_csvc = slp;
	return (0);
}

/*
 * Handle both "wildcard" and "nowildcard" options.
 */
static int
set_wildcard(struct service_list *slp, const char *str)
{
	/* Allow global context to switch back and forth without error. */
	if (!ISGLOBAL(slp) &&
	    (slp->sl_entry.se_flags & (SEF_WILD|SEF_NOWILD))) {
		logdbg("%s: extra \"%s\" ignored",
		    slp->sl_parse->ps_cfile->pf_name, str);
		return (0);
	}
	slp->sl_entry.se_flags =
	    (slp->sl_entry.se_flags & ~(SEF_WILD|SEF_NOWILD)) |
	    (*str == 'n' ? SEF_NOWILD : SEF_WILD);
	return (0);
}

/*
 * Handle "debug" option.
 */
/*ARGSUSED*/
static int
set_debug(struct service_list *slp, const char *str)
{
	slp->sl_entry.se_debug++;
	if (ISGLOBAL(slp) && (slp->sl_parse->ps_flags & PSF_SETLEVEL)) {
		log_level = slp->sl_entry.se_debug;
	}
	return (0);
}

/*
 * Handle "nodebug" option.
 */
/*ARGSUSED*/
static int
set_nodebug(struct service_list *slp, const char *str)
{
	slp->sl_entry.se_flags |= SEF_DEBUGCLR;
	slp->sl_entry.se_debug = 0;
	if (ISGLOBAL(slp) && (slp->sl_parse->ps_flags & PSF_SETLEVEL)) {
		log_level = slp->sl_entry.se_debug;
	}
	return (0);
}

/*
 * Handle all plain string options; "server", "pppd", "path", "extra",
 * and "log".
 */
static int
set_string(struct service_list *slp, const char *str)
{
	char **cpp;

	assert(!(slp->sl_entry.se_flags &
	    (SEF_CSERVER|SEF_CPPPD|SEF_CPATH|SEF_CEXTRA|SEF_CLOG)));
	switch (slp->sl_parse->ps_state) {
	case ksServer:
		cpp = &slp->sl_entry.se_server;
		break;
	case ksPppd:
		cpp = &slp->sl_entry.se_pppd;
		break;
	case ksPath:
		cpp = &slp->sl_entry.se_path;
		break;
	case ksExtra:
		cpp = &slp->sl_entry.se_extra;
		break;
	case ksLog:
		cpp = &slp->sl_entry.se_log;
		break;
	default:
		assert(0);
		return (-1);
	}
	if (*cpp != NULL)
		free(*cpp);
	*cpp = strsave(str);
	return (0);
}

/*
 * Handle "file <name>" option.  Close out current service (if any)
 * and begin parsing from new file.
 */
static int
set_file(struct service_list *slp, const char *str)
{
	FILE *fp;
	struct per_file *pfp;
	struct parse_state *psp;

	close_service(slp);

	if ((fp = fopen(str, "r")) == NULL) {
		logwarn("%s: %s: %s", slp->sl_parse->ps_cfile->pf_name, str,
		    mystrerror(errno));
		return (-1);
	}
	pfp = (struct per_file *)calloc(sizeof (*pfp) + strlen(str) + 1, 1);
	if (pfp == NULL) {
		logerr("no memory for parsing file %s", str);
		(void) fclose(fp);
		return (-1);
	}
	logdbg("config file %s open", str);

	/* Fill in new file structure. */
	pfp->pf_name = (const char *)(pfp+1);
	(void) strcpy((char *)(pfp+1), str);
	pfp->pf_input = fp;
	psp = slp->sl_parse;
	pfp->pf_prev = psp->ps_cfile;
	psp->ps_cfile = pfp;

	/* Start off in global context for this file. */
	psp->ps_csvc = &pfp->pf_global;
	pfp->pf_global.sl_parse = psp;
	pfp->pf_global.sl_entry.se_name = "<global>";
	return (0);
}

/*
 * Handle "device <list>" option.
 */
static int
set_device(struct service_list *slp, const char *str)
{
	struct parse_state *psp = slp->sl_parse;
	struct device_list *dlp;
	struct device_list *dln;
	struct device_list **dlpp;
	const char *cp;
	int len;

	/* Can't use this option in the per-device files. */
	if (psp->ps_flags & PSF_PERDEV) {
		logerr("\"device %s\" ignored in %s", str,
		    psp->ps_cfile->pf_name);
		return (0);
	}

	if (strcmp(str, "*") == 0 || strcmp(str, "all") == 0) {
		if (!(slp->sl_entry.se_flags & SEF_CDEV))
			free_device_list(slp->sl_dev);
		slp->sl_dev = psp->ps_star;
		slp->sl_entry.se_flags |= SEF_CDEV;
	} else {
		dlpp = &dlp;
		for (;;) {
			while (isspace(*str) || *str == ',')
				str++;
			if (*str == '\0')
				break;
			cp = str;
			while (*str != '\0' && !isspace(*str) && *str != ',')
				str++;
			len = str - cp;
			if ((len == 1 && *cp == '*') ||
			    (len == 3 && strncmp(cp, "all", 3) == 0)) {
				logerr("%s: cannot use %.*s in device list",
				    psp->ps_cfile->pf_name, len, cp);
				continue;
			}
			dln = (struct device_list *)malloc(sizeof (*dln) +
			    len + 1);
			if (dln == NULL) {
				logerr("no memory for device name");
				break;
			}
			dln->dl_name = (const char *)(dln + 1);
			/* Cannot use strcpy because cp isn't terminated. */
			(void) memcpy(dln + 1, cp, len);
			((char *)(dln + 1))[len] = '\0';
			logdbg("%s: device %s", psp->ps_cfile->pf_name,
			    dln->dl_name);
			*dlpp = dln;
			dlpp = &dln->dl_next;
		}
		*dlpp = NULL;

		dlpp = &slp->sl_dev;
		if (!(slp->sl_entry.se_flags & SEF_CDEV))
			while (*dlpp != NULL)
				dlpp = &(*dlpp)->dl_next;
		*dlpp = dlp;
		slp->sl_entry.se_flags &= ~SEF_CDEV;
	}

	return (0);
}

/*
 * Handle <list> portion of "client [except] <list>" option.  Attach
 * to list of filters in reverse order.
 */
static int
set_client(struct service_list *slp, const char *str)
{
	struct parse_state *psp = slp->sl_parse;
	struct filter_entry *fep;
	struct filter_entry *fen;
	const char *cp;
	int len;
	char hbuf[MAXHOSTNAMELEN];
	struct ether_addr ea;
	struct ether_addr mask;
	uchar_t *ucp;
	uchar_t *mcp;

	/* Head of list. */
	fep = slp->sl_entry.se_flist;
	for (;;) {
		while (isspace(*str) || *str == ',')
			str++;
		if (*str == '\0')
			break;
		cp = str;
		while (*str != '\0' && !isspace(*str) && *str != ',')
			str++;
		len = str - cp;
		(void) memcpy(hbuf, cp, len);
		hbuf[len] = '\0';
		mcp = mask.ether_addr_octet;
		mcp[0] = mcp[1] = mcp[2] = mcp[3] = mcp[4] = mcp[5] = 0xFF;
		if (ether_hostton(hbuf, &ea) != 0) {
			ucp = ea.ether_addr_octet;
			while (cp < str) {
				if (ucp >= ea.ether_addr_octet + sizeof (ea))
					break;
				if (*cp == '*') {
					*mcp++ = *ucp++ = 0;
					cp++;
				} else {
					if (!isxdigit(*cp))
						break;
					*ucp = hexdecode(*cp++);
					if (cp < str && isxdigit(*cp)) {
						*ucp = (*ucp << 4) |
						    hexdecode(*cp++);
					}
					ucp++;
					*mcp++ = 0xFF;
				}
				if (cp < str) {
					if (*cp != ':' || cp + 1 == str)
						break;
					cp++;
				}
			}
			if (cp < str) {
				logerr("%s: illegal Ethernet address %.*s",
				    psp->ps_cfile->pf_name, len, cp);
				continue;
			}
		}
		fen = (struct filter_entry *)malloc(sizeof (*fen));
		if (fen == NULL) {
			logerr("unable to allocate memory for filter");
			break;
		}
		fen->fe_isexcept = psp->ps_state == ksClientE;
		fen->fe_prevcopy = 0;
		(void) memcpy(&fen->fe_mac, &ea, sizeof (fen->fe_mac));
		(void) memcpy(&fen->fe_mask, &mask, sizeof (fen->fe_mask));
		fen->fe_prev = fep;
		fep = fen;
	}
	slp->sl_entry.se_flist = fep;
	return (0);
}

/*
 * Handle "user <name>" option.
 */
static int
set_user(struct service_list *slp, const char *str)
{
	struct passwd *pw;
	char *cp;
	uid_t myuid, uid;

	if ((pw = getpwnam(str)) == NULL) {
		uid = (uid_t)strtol(str, &cp, 0);
		if (str == cp || *cp != '\0') {
			logerr("%s:  bad user name \"%s\"",
			    slp->sl_parse->ps_cfile->pf_name, str);
			return (0);
		}
	} else {
		uid = pw->pw_uid;
	}
	slp->sl_entry.se_uid = uid;
	myuid = getuid();
	if (myuid != 0) {
		if (myuid == uid)
			return (0);
		logdbg("%s:  not root; ignoring attempt to set UID %d (%s)",
		    slp->sl_parse->ps_cfile->pf_name, uid, str);
		return (0);
	}
	slp->sl_entry.se_flags |= SEF_UIDSET;
	return (0);
}

/*
 * Handle "group <name>" option.
 */
static int
set_group(struct service_list *slp, const char *str)
{
	struct group *gr;
	char *cp;
	gid_t gid;

	if ((gr = getgrnam(str)) == NULL) {
		gid = (gid_t)strtol(str, &cp, 0);
		if (str == cp || *cp != '\0') {
			logerr("%s:  bad group name \"%s\"",
			    slp->sl_parse->ps_cfile->pf_name, str);
			return (0);
		}
	} else {
		gid = gr->gr_gid;
	}
	slp->sl_entry.se_gid = gid;
	if (getuid() != 0) {
		logdbg("%s:  not root; ignoring attempt to set GID %d (%s)",
		    slp->sl_parse->ps_cfile->pf_name, gid, str);
		return (0);
	}
	slp->sl_entry.se_flags |= SEF_GIDSET;
	return (0);
}

/*
 * This state machine is used to parse the configuration files.  The
 * "kwe_in" is the state in which the keyword is recognized.  The
 * "kwe_out" is the state that the keyword produces.
 */
struct kw_entry {
	const char *kwe_word;
	enum key_state kwe_in;
	enum key_state kwe_out;
	int (*kwe_func)(struct service_list *slp, const char *str);
};

static const struct kw_entry key_list[] = {
	{ "service",	ksDefault,	ksService,	NULL },
	{ "device",	ksDefault,	ksDevice,	NULL },
	{ "client",	ksDefault,	ksClient,	NULL },
	{ "except",	ksClient,	ksClientE,	NULL },
	{ "wildcard",	ksDefault,	ksDefault,	set_wildcard },
	{ "nowildcard",	ksDefault,	ksDefault,	set_wildcard },
	{ "server",	ksDefault,	ksServer,	NULL },
	{ "pppd",	ksDefault,	ksPppd,		NULL },
	{ "debug",	ksDefault,	ksDefault,	set_debug },
	{ "nodebug",	ksDefault,	ksDefault,	set_nodebug },
	{ "file",	ksDefault,	ksFile,		NULL },
	{ "path",	ksDefault,	ksPath,		NULL },
	{ "extra",	ksDefault,	ksExtra,	NULL },
	{ "log",	ksDefault,	ksLog,		NULL },
	{ "user",	ksDefault,	ksUser,		NULL },
	{ "group",	ksDefault,	ksGroup,	NULL },
	/* Wildcards only past this point. */
	{ "",		ksService,	ksDefault,	set_service },
	{ "",		ksDevice,	ksDefault,	set_device },
	{ "",		ksClient,	ksDefault,	set_client },
	{ "",		ksClientE,	ksDefault,	set_client },
	{ "",		ksServer,	ksDefault,	set_string },
	{ "",		ksPppd,		ksDefault,	set_string },
	{ "",		ksFile,		ksDefault,	set_file },
	{ "",		ksPath,		ksDefault,	set_string },
	{ "",		ksExtra,	ksDefault,	set_string },
	{ "",		ksLog,		ksDefault,	set_string },
	{ "",		ksUser,		ksDefault,	set_user },
	{ "",		ksGroup,	ksDefault,	set_group },
	{ NULL, ksDefault, ksDefault, NULL }
};

/*
 * Produce a string for the keyword that would have gotten us into the
 * current state.
 */
static const char *
after_key(enum key_state kstate)
{
	const struct kw_entry *kep;

	for (kep = key_list; kep->kwe_word != NULL; kep++)
		if (kep->kwe_out == kstate)
			return (kep->kwe_word);
	return ("nothing");
}

/*
 * Handle end-of-file processing -- close service, close file, revert
 * to global context in previous include file nest level.
 */
static void
file_end(struct parse_state *psp)
{
	struct per_file *pfp;

	/* Must not be in the middle of parsing a multi-word sequence now. */
	if (psp->ps_state != ksDefault) {
		logerr("%s ends with \"%s\"", psp->ps_cfile->pf_name,
		    after_key(psp->ps_state));
		psp->ps_state = ksDefault;
	}
	close_service(psp->ps_csvc);
	if ((pfp = psp->ps_cfile) != NULL) {
		/* Put this file on the list of finished files. */
		psp->ps_cfile = pfp->pf_prev;
		pfp->pf_prev = psp->ps_files;
		psp->ps_files = pfp;
		if (pfp->pf_input != NULL) {
			logdbg("file %s closed", pfp->pf_name);
			(void) fclose(pfp->pf_input);
			pfp->pf_input = NULL;
		}

		/* Back up to previous file, if any, and set global context. */
		if ((pfp = psp->ps_cfile) != NULL)
			psp->ps_csvc = &pfp->pf_global;
	}
}

/*
 * Dispatch a single keyword against the parser state machine or
 * handle an environment variable assignment.  The input is a string
 * containing the single word to be dispatched.
 */
static int
dispatch_keyword(struct parse_state *psp, const char *keybuf)
{
	const struct kw_entry *kep;
	int retv;
	char *cp;
	char *env;
	char **evlist;
	int len;

	retv = 0;
	for (kep = key_list; kep->kwe_word != NULL; kep++) {
		if (kep->kwe_in == psp->ps_state &&
		    (*kep->kwe_word == '\0' ||
		    strcasecmp(kep->kwe_word, keybuf) == 0)) {
			if (kep->kwe_func != NULL)
				retv = (*kep->kwe_func)(psp->ps_csvc, keybuf);
			psp->ps_state = kep->kwe_out;
			return (retv);
		}
	}
	if (strchr(keybuf, '=') != NULL) {
		if ((cp = strsave(keybuf)) == NULL) {
			logerr("no memory to save %s", keybuf);
			return (0);
		}
		len = (strchr(cp, '=') - cp) + 1;
		if ((evlist = psp->ps_evlist) == NULL) {
			psp->ps_evlist = evlist =
			    (char **)malloc(8 * sizeof (*evlist));
			if (evlist == NULL) {
				logerr("no memory for evlist");
				free(cp);
				return (0);
			}
			psp->ps_evsize = 8;
			evlist[0] = evlist[1] = NULL;
		} else {
			while ((env = *evlist) != NULL) {
				if (strncmp(cp, env, len) == 0)
					break;
				evlist++;
			}
			if (env == NULL &&
			    evlist-psp->ps_evlist >= psp->ps_evsize-1) {
				evlist = (char **)realloc(psp->ps_evlist,
				    (psp->ps_evsize + 8) * sizeof (*evlist));
				if (evlist == NULL) {
					logerr("cannot realloc evlist to %d",
					    psp->ps_evsize + 8);
					free(cp);
					return (0);
				}
				psp->ps_evlist = evlist;
				evlist += psp->ps_evsize - 1;
				psp->ps_evsize += 8;
				evlist[1] = NULL;
			}
		}
		logdbg("setenv \"%s\"", cp);
		if (*evlist != NULL)
			free(*evlist);
		*evlist = cp;
		return (0);
	}
	logerr("%s: unknown keyword '%s'", psp->ps_cfile->pf_name, keybuf);
	return (-1);
}

/*
 * Modified version of standard getenv; looks in locally-stored
 * environment first.  This function exists because we need to be able
 * to revert to the original environment during a reread (SIGHUP), and
 * the putenv() function overwrites that environment.
 */
static char *
my_getenv(struct parse_state *psp, char *estr)
{
	char **evlist, *ent;
	int elen;

	if (psp != NULL && (evlist = psp->ps_evlist) != NULL) {
		elen = strlen(estr);
		while ((ent = *evlist++) != NULL) {
			if (strncmp(ent, estr, elen) == 0 &&
			    ent[elen] == '=')
				return (ent + elen + 1);
		}
	}
	return (getenv(estr));
}

/*
 * Expand an environment variable at the end of current buffer and
 * return pointer to next spot in buffer for character append.  psp
 * context may be null.
 */
static char *
env_replace(struct parse_state *psp, char *keybuf, char kwstate)
{
	char *cpe;
	char *cp;

	if ((cp = strrchr(keybuf, kwstate)) != NULL) {
		if ((cpe = my_getenv(psp, cp + 1)) != NULL) {
			*cp = '\0';
			(void) strncat(cp, cpe,
			    MAX_KEYWORD - (cp - keybuf) - 1);
			keybuf[MAX_KEYWORD - 1] = '\0';
			cp += strlen(cp);
		} else {
			logerr("unknown variable \"%s\"", cp + 1);
		}
	} else {
		/* Should not occur. */
		cp = keybuf + strlen(keybuf);
	}
	return (cp);
}

/*
 * Given a character-at-a-time input function, get a delimited keyword
 * from the input.  This function handles the usual escape sequences,
 * quoting, commenting, and environment variable expansion.
 *
 * The standard wordexp(3C) function isn't used here because the POSIX
 * definition is hard to use, and the Solaris implementation is
 * resource-intensive and insecure.  The "hard-to-use" part is that
 * wordexp expands only variables from the environment, and can't
 * handle an environment overlay.  Instead, the caller must use the
 * feeble putenv/getenv interface, and rewinding to the initial
 * environment without leaking storage is hard.  The Solaris
 * implementation invokes an undocumented extensions via
 * fork/exec("/bin/ksh -\005 %s") for every invocation, and gathers
 * the expanded result with pipe.  This makes it slow to execute and
 * exposes the string being expanded to users with access to "ps -f."
 *
 * psp may be null; it's used only for environment variable expansion.
 * Input "flag" is 1 to ignore EOL, '#', and '$'; 0 for normal file parsing.
 *
 * Returns:
 *	0 - keyword parsed.
 *	1 - end of file; no keyword.
 *	2 - end of file after this keyword.
 */
static int
getkeyword(struct parse_state *psp, char *keybuf, int keymax,
    int (*nextchr)(void *), void *arg, int flag)
{
	char varnest[MAX_NEST];
	char *kbp;
	char *vnp;
	char chr;
	int ichr;
	char kwstate;
	static const char escstr[] = "a\ab\bf\fn\nr\r";
	const char *cp;

	keymax--;	/* Account for trailing NUL byte */

	kwstate = '\0';
	kbp = keybuf;
	vnp = varnest;
	for (;;) {
		ichr = (*nextchr)(arg);
		chr = (char)ichr;
	tryagain:
		switch (kwstate) {
		case '\\':	/* Start of unquoted escape sequence */
		case '|':	/* Start of escape sequence in double quotes */
		case '~':	/* Start of escape sequence in single quotes */
			/* Convert the character if we can. */
			if (chr == '\n')
				chr = '\0';
			else if (isalpha(chr) &&
			    (cp = strchr(escstr, chr)) != NULL)
				chr = cp[1];
			/* Revert to previous state */
			switch (kwstate) {
			case '\\':
				kwstate = 'A';
				break;
			case '|':
				kwstate = '"';
				break;
			case '~':
				kwstate = '\'';
				break;
			}
			break;
		case '"':	/* In double-quote string */
			if (!flag && chr == '$') {
				/* Handle variable expansion. */
				kwstate = '%';
				chr = '\0';
				break;
			}
				/* FALLTHROUGH */
		case '\'':	/* In single-quote string */
			if (chr == '\\') {
				/* Handle start of escape sequence */
				kwstate = kwstate == '"' ? '|' : '~';
				chr = '\0';
				break;
			}
			if (chr == kwstate) {
				/* End of quoted string; revert to normal */
				kwstate = 'A';
				chr = '\0';
			}
			break;
		case '$':	/* Start of unquoted variable name */
		case '%':	/* Start of variable name in quoted string */
			if (chr == '{') {
				/* Variable name is bracketed. */
				kwstate = chr =
				    kwstate == '$' ? '{' : '[';
				break;
			}
			*kbp++ = kwstate = kwstate == '$' ? '+' : '*';
				/* FALLTHROUGH */
		case '+':	/* Gathering unquoted variable name */
		case '*':	/* Gathering variable name in quoted string */
			if (chr == '$' &&
			    vnp < varnest + sizeof (varnest)) {
				*vnp++ = kwstate;
				kwstate = '$';
				chr = '\0';
				break;
			}
			if (!isalnum(chr) && chr != '_' &&
			    chr != '.' && chr != '-') {
				*kbp = '\0';
				kbp = env_replace(psp, keybuf, kwstate);
				if (vnp > varnest)
					kwstate = *--vnp;
				else
					kwstate = kwstate == '+' ?
					    'A' : '"';
				/* Go reinterpret in new context */
				goto tryagain;
			}
			break;
		case '{':	/* Gathering bracketed, unquoted var name */
		case '[':	/* Gathering bracketed, quoted var name */
			if (chr == '}') {
				*kbp = '\0';
				kbp = env_replace(psp, keybuf, kwstate);
				kwstate = kwstate == '{' ? 'A' : '"';
				chr = '\0';
			}
			break;
		case '#':	/* Comment before word state */
		case '@':	/* Comment after word state */
			if (chr == '\n' || chr == '\r' || ichr == EOF) {
				/* At end of line, revert to previous state */
				kwstate = kwstate == '#' ? '\0' : ' ';
				chr = '\0';
				break;
			}
			chr = '\0';
			break;
		case '\0':	/* Initial state; no word seen yet. */
			if (ichr == EOF || isspace(chr)) {
				chr = '\0';	/* Skip over leading spaces */
				break;
			}
			if (chr == '#') {
				kwstate = '#';
				chr = '\0';	/* Skip over comments */
				break;
			}
			/* Start of keyword seen. */
			kwstate = 'A';
			/* FALLTHROUGH */
		default:	/* Middle of keyword parsing. */
			if (ichr == EOF)
				break;
			if (isspace(chr)) {	/* Space terminates word */
				kwstate = ' ';
				break;
			}
			if (chr == '"' || chr == '\'' || chr == '\\') {
				kwstate = chr;	/* Begin quote or escape */
				chr = '\0';
				break;
			}
			if (flag)	/* Allow ignore; for string reparse */
				break;
			if (chr == '#') {	/* Comment terminates word */
				kwstate = '@';	/* Must consume comment also */
				chr = '\0';
				break;
			}
			if (chr == '$') {
				kwstate = '$';	/* Begin variable expansion */
				chr = '\0';
			}
			break;
		}
		/*
		 * If we've reached a space at the end of the word,
		 * then we're done.
		 */
		if (ichr == EOF || kwstate == ' ')
			break;
		/*
		 * If there's a character to store and space
		 * available, then add it to the string
		 */
		if (chr != '\0' && kbp < keybuf + keymax)
			*kbp++ = (char)chr;
	}

	*kbp = '\0';

	if (ichr == EOF) {
		return (kwstate == '\0' ? 1 : 2);
	}
	return (0);
}

/*
 * Fetch words from current file until all files are closed.  Handles
 * include files.
 */
static void
parse_from_file(struct parse_state *psp)
{
	char keybuf[MAX_KEYWORD];
	int retv;

	while (psp->ps_cfile != NULL && psp->ps_cfile->pf_input != NULL) {
		retv = getkeyword(psp, keybuf, sizeof (keybuf),
		    (int (*)(void *))fgetc, (void *)psp->ps_cfile->pf_input,
		    0);

		if (retv != 1)
			(void) dispatch_keyword(psp, keybuf);

		if (retv != 0)
			file_end(psp);
	}
}

/*
 * Open and parse named file.  This is for the predefined
 * configuration files in /etc/ppp -- it's not an error if any of
 * these are missing.
 */
static void
parse_file(struct parse_state *psp, const char *fname)
{
	struct stat sb;

	/* It's ok if any of these files are missing. */
	if (stat(fname, &sb) == -1 && errno == ENOENT)
		return;
	if (set_file(psp->ps_csvc, fname) == 0)
		parse_from_file(psp);
}

/*
 * Dispatch keywords from command line.  Handles any files included
 * from there.
 */
static void
parse_arg_list(struct parse_state *psp, int argc, char **argv)
{
	/* The first argument (program name) can be null. */
	if (--argc <= 0)
		return;
	while (--argc >= 0) {
		(void) dispatch_keyword(psp, *++argv);
		if (psp->ps_cfile->pf_input != NULL)
			parse_from_file(psp);
	}
}

/* Count length of dynamic device list */
static int
count_devs(struct device_list *dlp)
{
	int ndevs;

	ndevs = 0;
	for (; dlp != NULL; dlp = dlp->dl_next)
		ndevs++;
	return (ndevs);
}

/* Count number of devices named in entire file. */
static int
count_per_file(struct per_file *pfp)
{
	struct service_list *slp;
	int ndevs = 0;

	for (; pfp != NULL; pfp = pfp->pf_prev) {
		ndevs += count_devs(pfp->pf_global.sl_dev);
		for (slp = pfp->pf_svc; slp != NULL; slp = slp->sl_next)
			if (!(slp->sl_entry.se_flags & SEF_CDEV))
				ndevs += count_devs(slp->sl_dev);
	}
	return (ndevs);
}

/* Write device names into linear array. */
static const char **
devs_to_list(struct device_list *dlp, const char **dnames)
{
	for (; dlp != NULL; dlp = dlp->dl_next)
		*dnames++ = dlp->dl_name;
	return (dnames);
}

/* Write all device names from file into a linear array. */
static const char **
per_file_to_list(struct per_file *pfp, const char **dnames)
{
	struct service_list *slp;

	for (; pfp != NULL; pfp = pfp->pf_prev) {
		dnames = devs_to_list(pfp->pf_global.sl_dev, dnames);
		for (slp = pfp->pf_svc; slp != NULL; slp = slp->sl_next)
			if (!(slp->sl_entry.se_flags & SEF_CDEV))
				dnames = devs_to_list(slp->sl_dev, dnames);
	}
	return (dnames);
}

/* Compare device names; used with qsort */
static int
devcmp(const void *d1, const void *d2)
{
	return (strcmp(*(const char **)d1, *(const char **)d2));
}

/*
 * Get sorted list of unique device names among all defined and
 * partially defined services in all files.
 */
static const char **
get_unique_devs(struct parse_state *psp)
{
	int ndevs;
	const char **dnames;
	const char **dnp;
	const char **dnf;

	/*
	 * Count number of explicitly referenced devices among all
	 * services (including duplicates).
	 */
	ndevs = count_per_file(psp->ps_files);
	ndevs += count_per_file(psp->ps_cfile);
	if (ndevs <= 0) {
		return (NULL);
	}

	/* Sort and trim out duplicate devices. */
	dnames = (const char **)malloc((ndevs+1) * sizeof (const char *));
	if (dnames == NULL) {
		logerr("unable to allocate space for %d devices", ndevs + 1);
		return (NULL);
	}
	dnp = per_file_to_list(psp->ps_files, dnames);
	(void) per_file_to_list(psp->ps_cfile, dnp);
	qsort(dnames, ndevs, sizeof (const char *), devcmp);
	for (dnf = (dnp = dnames) + 1; dnf < dnames+ndevs; dnf++)
		if (strcmp(*dnf, *dnp) != 0)
			*++dnp = *dnf;
	*++dnp = NULL;

	/* Return array of pointers to names. */
	return (dnames);
}

/*
 * Convert data structures created by parsing process into data
 * structures used by service dispatch.  This gathers the unique
 * device (lower stream) names and attaches the services available on
 * each device to a list while triming duplicate services.
 */
static struct option_state *
organize_state(struct parse_state *psp)
{
	struct per_file *pfp;
	struct per_file *pftopp;
	struct service_list *slp;
	struct device_list *dlp;
	int ndevs;
	int nsvcs;
	const char **dnames;
	const char **dnp;
	struct device_entry *dep;
	struct option_state *osp;
	struct service_entry **sepp;
	struct service_entry **sebpp;
	struct service_entry **se2pp;

	/*
	 * Parsing is now done.
	 */
	close_service(psp->ps_csvc);
	psp->ps_csvc = NULL;
	if ((pfp = psp->ps_cfile) != NULL) {
		pfp->pf_prev = psp->ps_files;
		psp->ps_files = pfp;
		psp->ps_cfile = NULL;
	}

	/* Link the services from all files together for easy referencing. */
	pftopp = psp->ps_files;
	for (pfp = pftopp->pf_prev; pfp != NULL; pfp = pfp->pf_prev)
		if (pfp->pf_svc != NULL) {
			if (pftopp->pf_svc_last == NULL)
				pftopp->pf_svc = pfp->pf_svc;
			else
				pftopp->pf_svc_last->sl_next = pfp->pf_svc;
			pftopp->pf_svc_last = pfp->pf_svc_last;
			pfp->pf_svc = pfp->pf_svc_last = NULL;
		}

	/*
	 * Count up number of services per device, including
	 * duplicates but not including defaults.
	 */
	nsvcs = 0;
	for (slp = psp->ps_files->pf_svc; slp != NULL; slp = slp->sl_next)
		for (dlp = slp->sl_dev; dlp != NULL; dlp = dlp->dl_next)
			nsvcs++;

	/*
	 * Get the unique devices referenced by all services.
	 */
	dnames = get_unique_devs(psp);
	if (dnames == NULL) {
		logdbg("no devices referenced by any service");
		return (NULL);
	}
	ndevs = 0;
	for (dnp = dnames; *dnp != NULL; dnp++)
		ndevs++;

	/*
	 * Allocate room for main structure, device records, and
	 * per-device lists.  Worst case is all devices having all
	 * services; that's why we allocate for nsvcs * ndevs.
	 */
	osp = (struct option_state *)malloc(sizeof (*osp) +
	    ndevs * sizeof (*dep) + nsvcs * ndevs * sizeof (*sepp));
	if (osp == NULL) {
		logerr("unable to allocate option state structure");
		free(dnames);
		return (NULL);
	}

	/* We're going to succeed now, so steal these over. */
	osp->os_devices = dep = (struct device_entry *)(osp+1);
	osp->os_pfjunk = psp->ps_files;
	psp->ps_files = NULL;
	osp->os_evjunk = psp->ps_evlist;
	psp->ps_evlist = NULL;

	/* Loop over devices, install services, remove duplicates. */
	sepp = (struct service_entry **)(dep + ndevs);
	for (dnp = dnames; *dnp != NULL; dnp++) {
		dep->de_name = *dnp;
		dep->de_services = (const struct service_entry **)sepp;
		sebpp = sepp;
		for (slp = osp->os_pfjunk->pf_svc; slp != NULL;
		    slp = slp->sl_next)
			for (dlp = slp->sl_dev; dlp != NULL;
			    dlp = dlp->dl_next) {
				if (dlp->dl_name == *dnp ||
				    strcmp(dlp->dl_name, *dnp) == 0) {
					for (se2pp = sebpp; se2pp < sepp;
					    se2pp++)
						if ((*se2pp)->se_name ==
						    slp->sl_entry.se_name ||
						    strcmp((*se2pp)->
						    se_name, slp->sl_entry.
						    se_name) == 0)
							break;
					/*
					 * We retain a service if it's
					 * unique or if its serial
					 * number (position in the
					 * file) is greater than than
					 * any other.
					 */
					if (se2pp >= sepp)
						*sepp++ = &slp->sl_entry;
					else if (SESERIAL(**se2pp) <
					    SESERIAL(slp->sl_entry))
						*se2pp = &slp->sl_entry;
				}
			}
		/* Count up the services on this device. */
		dep->de_nservices = (const struct service_entry **)sepp -
		    dep->de_services;
		/* Ignore devices having no services at all. */
		if (dep->de_nservices > 0)
			dep++;
	}
	/* Count up the devices. */
	osp->os_ndevices = dep - osp->os_devices;
	/* Free the list of device names */
	free(dnames);
	return (osp);
}

/*
 * Free storage unique to a given service.  Pointers copied from other
 * services are ignored.
 */
static void
free_service(struct service_list *slp)
{
	struct filter_entry *fep;
	struct filter_entry *fen;

	if (!(slp->sl_entry.se_flags & SEF_CDEV))
		free_device_list(slp->sl_dev);
	if (!(slp->sl_entry.se_flags & SEF_CFLIST)) {
		fep = slp->sl_entry.se_flist;
		while (fep != NULL) {
			fen = fep->fe_prevcopy ? NULL : fep->fe_prev;
			free(fep);
			fep = fen;
		}
	}
	if (!(slp->sl_entry.se_flags & SEF_CPPPD) &&
	    slp->sl_entry.se_pppd != NULL)
		free(slp->sl_entry.se_pppd);
	if (!(slp->sl_entry.se_flags & SEF_CSERVER) &&
	    slp->sl_entry.se_server != NULL)
		free(slp->sl_entry.se_server);
	if (!(slp->sl_entry.se_flags & SEF_CPATH) &&
	    slp->sl_entry.se_path != NULL)
		free(slp->sl_entry.se_path);
	if (!(slp->sl_entry.se_flags & SEF_CEXTRA) &&
	    slp->sl_entry.se_extra != NULL)
		free(slp->sl_entry.se_extra);
	if (!(slp->sl_entry.se_flags & SEF_CLOG) &&
	    slp->sl_entry.se_log != NULL)
		free(slp->sl_entry.se_log);
}

/*
 * Free a linked list of services.
 */
static void
free_service_list(struct service_list *slp)
{
	struct service_list *sln;

	while (slp != NULL) {
		free_service(slp);
		sln = slp->sl_next;
		free(slp);
		slp = sln;
	}
}

/*
 * Free a linked list of files and all services in those files.
 */
static void
free_file_list(struct per_file *pfp)
{
	struct per_file *pfn;

	while (pfp != NULL) {
		free_service(&pfp->pf_global);
		free_service_list(pfp->pf_svc);
		pfn = pfp->pf_prev;
		free(pfp);
		pfp = pfn;
	}
}

/*
 * Free an array of local environment variables.
 */
static void
free_env_list(char **evlist)
{
	char **evp;
	char *env;

	if ((evp = evlist) != NULL) {
		while ((env = *evp++) != NULL)
			free(env);
		free(evlist);
	}
}

/*
 * Add a new device (lower stream) to the list for which we're the
 * PPPoE server.
 */
static void
add_new_dev(int tunfd, const char *dname)
{
	union ppptun_name ptn;

	(void) snprintf(ptn.ptn_name, sizeof (ptn.ptn_name), "%s:pppoed",
	    dname);
	if (strioctl(tunfd, PPPTUN_SCTL, &ptn, sizeof (ptn), 0) < 0) {
		logerr("PPPTUN_SCTL %s: %s", ptn.ptn_name, mystrerror(errno));
	} else {
		logdbg("added %s", ptn.ptn_name);
	}
}

/*
 * Remove an existing device (lower stream) from the list for which we
 * were the PPPoE server.
 */
static void
rem_old_dev(int tunfd, const char *dname)
{
	union ppptun_name ptn;

	(void) snprintf(ptn.ptn_name, sizeof (ptn.ptn_name), "%s:pppoed",
	    dname);
	if (strioctl(tunfd, PPPTUN_DCTL, &ptn, sizeof (ptn), 0) < 0) {
		logerr("PPPTUN_DCTL %s: %s", ptn.ptn_name, mystrerror(errno));
	} else {
		logdbg("removed %s", ptn.ptn_name);
	}
}

/*
 * Get a list of all of the devices currently plumbed for PPPoE.  This
 * is used for supporting the "*" and "all" device aliases.
 */
static void
get_device_list(struct parse_state *psp, int tunfd)
{
	struct device_list *dlp;
	struct device_list **dlpp;
	struct device_list *dlalt;
	struct device_list **dl2pp;
	struct device_list *dla;
	int i;
	union ppptun_name ptn;
	char *cp;

	/* First pass; just allocate space for all *:pppoe* devices */
	dlpp = &psp->ps_star;
	dl2pp = &dlalt;
	for (i = 0; ; i++) {
		ptn.ptn_index = i;
		if (strioctl(tunfd, PPPTUN_GNNAME, &ptn, sizeof (ptn),
		    sizeof (ptn)) < 0) {
			logerr("PPPTUN_GNNAME %d: %s", i, mystrerror(errno));
			break;
		}
		if (ptn.ptn_name[0] == '\0')
			break;
		if ((cp = strchr(ptn.ptn_name, ':')) == NULL ||
		    strncmp(cp, ":pppoe", 6) != 0 ||
		    (cp[6] != '\0' && strcmp(cp+6, "d") != 0))
			continue;
		*cp = '\0';
		dlp = (struct device_list *)malloc(sizeof (*dlp) +
		    strlen(ptn.ptn_name) + 1);
		if (dlp == NULL)
			break;
		dlp->dl_name = (const char *)(dlp + 1);
		(void) strcpy((char *)(dlp + 1), ptn.ptn_name);
		if (cp[6] == '\0') {
			*dlpp = dlp;
			dlpp = &dlp->dl_next;
		} else {
			*dl2pp = dlp;
			dl2pp = &dlp->dl_next;
		}
	}
	*dlpp = NULL;
	*dl2pp = NULL;

	/* Second pass; eliminate improperly plumbed devices */
	for (dlpp = &psp->ps_star; (dlp = *dlpp) != NULL; ) {
		for (dla = dlalt; dla != NULL; dla = dla->dl_next)
			if (strcmp(dla->dl_name, dlp->dl_name) == 0)
				break;
		if (dla == NULL) {
			*dlpp = dlp->dl_next;
			free(dlp);
		} else {
			dlpp = &dlp->dl_next;
		}
	}
	free_device_list(dlalt);

	/* Add in "*" so we can always handle dynamic plumbing. */
	dlp = (struct device_list *)malloc(sizeof (*dlp) + 2);
	if (dlp != NULL) {
		dlp->dl_name = (const char *)(dlp + 1);
		(void) strcpy((char *)(dlp + 1), "*");
		dlp->dl_next = psp->ps_star;
		psp->ps_star = dlp;
	}
}

/*
 * Set logging subsystem back to configured global default values.
 */
void
global_logging(void)
{
	log_for_service(glob_svc.se_log, glob_svc.se_debug);
}

/*
 * Handle SIGHUP -- reparse command line and all configuration files.
 * When reparsing is complete, free old parsed data and replace with
 * new.
 */
void
parse_options(int tunfd, int argc, char **argv)
{
	struct parse_state pstate;
	struct per_file *argpf;
	struct option_state *newopt;
	const char **dnames;
	const char **dnp;
	const struct device_entry *newdep, *newmax;
	const struct device_entry *olddep, *oldmax;
	int cmpval;
	struct service_entry newglobsvc, *mainsvc;

	/* Note that all per_file structures must be freeable */
	argpf = (struct per_file *)calloc(sizeof (*argpf), 1);
	if (argpf == NULL) {
		return;
	}
	(void) memset(&pstate, '\0', sizeof (pstate));
	pstate.ps_state = ksDefault;
	pstate.ps_cfile = argpf;
	pstate.ps_csvc = &argpf->pf_global;
	argpf->pf_global.sl_parse = &pstate;
	argpf->pf_name = "command line";

	/* Default is 1 -- errors only */
	argpf->pf_global.sl_entry.se_debug++;
	argpf->pf_global.sl_entry.se_name = "<global>";

	/* Get list of all devices */
	get_device_list(&pstate, tunfd);

	/* Parse options from command line and main configuration file. */
	pstate.ps_flags |= PSF_SETLEVEL;
	parse_arg_list(&pstate, argc, argv);
	parse_file(&pstate, "/etc/ppp/pppoe");
	pstate.ps_flags &= ~PSF_SETLEVEL;

	/*
	 * At this point, global options from the main configuration
	 * file are pointed to by ps_files, and options from command
	 * line are in argpf.  We need to pull three special options
	 * from these -- wildcard, debug, and log.  Note that the main
	 * options file overrides the command line.  This is
	 * intentional.  The semantics are such that the system
	 * behaves as though the main configuration file were
	 * "included" from the command line, and thus options there
	 * override the command line.  This may seem odd, but at least
	 * it's self-consistent.
	 */
	newglobsvc = argpf->pf_global.sl_entry;
	if (pstate.ps_files != NULL) {
		mainsvc = &pstate.ps_files->pf_global.sl_entry;
		if (mainsvc->se_log != NULL)
			newglobsvc.se_log = mainsvc->se_log;
		if (mainsvc->se_flags & (SEF_WILD|SEF_NOWILD))
			newglobsvc.se_flags =
			    (newglobsvc.se_flags & ~(SEF_WILD|SEF_NOWILD)) |
			    (mainsvc->se_flags & (SEF_WILD|SEF_NOWILD));
		if (mainsvc->se_flags & SEF_DEBUGCLR)
			newglobsvc.se_debug = 0;
		newglobsvc.se_debug += mainsvc->se_debug;
	}
	glob_svc = newglobsvc;
	global_logging();

	/* Get the list of devices referenced by configuration above. */
	dnames = get_unique_devs(&pstate);
	if (dnames != NULL) {
		/* Read per-device configuration files. */
		pstate.ps_flags |= PSF_PERDEV;
		for (dnp = dnames; *dnp != NULL; dnp++)
			parse_file(&pstate, *dnp);
		pstate.ps_flags &= ~PSF_PERDEV;
		free(dnames);
	}
	file_end(&pstate);

	/*
	 * Convert parsed data structures into per-device structures.
	 * (Invert the table.)
	 */
	newopt = organize_state(&pstate);

	/* If we're going to free the file name, then stop logging there. */
	if (newopt == NULL && glob_svc.se_log != NULL) {
		glob_svc.se_log = NULL;
		global_logging();
	}

	/*
	 * Unless an error has occurred, these pointers are normally
	 * all NULL.  Nothing is freed until the file is re-read.
	 */
	free_file_list(pstate.ps_files);
	free_file_list(pstate.ps_cfile);
	free_device_list(pstate.ps_star);
	free_env_list(pstate.ps_evlist);

	/*
	 * Match up entries on device list.  Detach devices no longer
	 * referenced.  Attach ones now referenced.  (The use of null
	 * pointers here may look fishy, but it actually works.
	 * NULL>=NULL is always true.)
	 */
	if (newopt != NULL) {
		newdep = newopt->os_devices;
		newmax = newdep + newopt->os_ndevices;
	} else {
		newdep = newmax = NULL;
	}
	if (cur_options != NULL) {
		olddep = cur_options->os_devices;
		oldmax = olddep + cur_options->os_ndevices;
	} else {
		olddep = oldmax = NULL;
	}
	while ((newdep != NULL && newdep < newmax) ||
	    (olddep != NULL && olddep < oldmax)) {
		if (newdep < newmax) {
			if (olddep >= oldmax) {
				add_new_dev(tunfd, newdep->de_name);
				newdep++;
			} else {
				cmpval = strcmp(newdep->de_name,
				    olddep->de_name);
				if (cmpval < 0) {
					/* Brand new device seen. */
					add_new_dev(tunfd, newdep->de_name);
					newdep++;
				} else if (cmpval == 0) {
					/* Existing device; skip it. */
					newdep++;
					olddep++;
				}
				/* No else clause -- removal is below */
			}
		}
		if (olddep < oldmax) {
			if (newdep >= newmax) {
				rem_old_dev(tunfd, olddep->de_name);
				olddep++;
			} else {
				cmpval = strcmp(newdep->de_name,
				    olddep->de_name);
				if (cmpval > 0) {
					/* Old device is gone */
					rem_old_dev(tunfd, olddep->de_name);
					olddep++;
				} else if (cmpval == 0) {
					/* Existing device; skip it. */
					newdep++;
					olddep++;
				}
				/* No else clause -- insert handled above */
			}
		}
	}

	/* Discard existing parsed data storage. */
	if (cur_options != NULL) {
		free_file_list(cur_options->os_pfjunk);
		free_env_list(cur_options->os_evjunk);
		free(cur_options);
	}
	/* Install new. */
	cur_options = newopt;
}

/*
 * Check if configured filters permit requesting client to use a given
 * service.  Note -- filters are stored in reverse order in order to
 * make file-inclusion work as expected.  Thus, the "first match"
 * filter rule becomes "last match" here.
 */
static boolean_t
allow_service(const struct service_entry *sep, const ppptun_atype *pap)
{
	const struct filter_entry *fep;
	const struct filter_entry *lmatch;
	boolean_t anynonexcept = B_FALSE;
	const uchar_t *upt;
	const uchar_t *macp;
	const uchar_t *maskp;
	int i;

	lmatch = NULL;
	for (fep = sep->se_flist; fep != NULL; fep = fep->fe_prev) {
		anynonexcept |= !fep->fe_isexcept;
		upt = pap->pta_pppoe.ptma_mac;
		macp = fep->fe_mac.ether_addr_octet;
		maskp = fep->fe_mask.ether_addr_octet;
		for (i = sizeof (pap->pta_pppoe.ptma_mac); i > 0; i--)
			if (((*macp++ ^ *upt++) & *maskp++) != 0)
				break;
		if (i <= 0)
			lmatch = fep;
	}

	if (lmatch == NULL) {
		/*
		 * Assume reject by default if any positive-match
		 * (non-except) filters are given.  Otherwise, if
		 * there are no positive-match filters, then
		 * non-matching means accept by default.
		 */
		return (!anynonexcept);
	}
	return (!lmatch->fe_isexcept);
}

/*
 * Locate available service(s) based on client request.  Assumes that
 * outp points to a buffer of at least size PPPOE_MSGMAX.  Creates a
 * PPPoE response message in outp.  Returns count of matched services
 * and (through *srvp) a pointer to the last (or only) service.  If
 * some error is found in the request, an error string is added and -1
 * is returned; the caller should just send the message without
 * alteration.
 */
int
locate_service(poep_t *poep, int plen, const char *iname, ppptun_atype *pap,
    uint32_t *outp, void **srvp)
{
	poep_t *opoe;
	const uint8_t *tagp;
	const char *cp;
	int ttyp;
	int tlen;
	int nsvcs;
	const struct device_entry *dep, *depe;
	const struct device_entry *wdep;
	const struct service_entry **sepp, **seppe;
	const struct service_entry *sep;
	char *str;
	boolean_t ispadi;

	ispadi = poep->poep_code == POECODE_PADI;
	opoe = poe_mkheader(outp, ispadi ? POECODE_PADO : POECODE_PADS, 0);

	*srvp = NULL;
	if (cur_options == NULL)
		return (0);

	/* Search for named device (lower stream) in tables. */
	dep = cur_options->os_devices;
	depe = dep + cur_options->os_ndevices;
	wdep = NULL;
	if ((cp = strchr(iname, ':')) != NULL)
		tlen = cp - iname;
	else
		tlen = strlen(iname);
	for (; dep < depe; dep++)
		if (strncmp(iname, dep->de_name, tlen) == 0 &&
		    dep->de_name[tlen] == '\0')
			break;
		else if (dep->de_name[0] == '*' && dep->de_name[1] == '\0')
			wdep = dep;
	if (dep >= depe)
		dep = wdep;
	/*
	 * Return if interface not found.  Zero-service case can't
	 * occur, since devices with no services aren't included in
	 * the list, but the code is just being safe here.
	 */
	if (dep == NULL || dep->de_services == NULL || dep->de_nservices <= 0)
		return (0);

	/*
	 * Loop over tags in client message and process them.
	 * Services must be matched against our list.  Host-Uniq and
	 * Relay-Session-Id must be copied to the reply.  All others
	 * must be discarded.
	 */
	nsvcs = 0;
	sepp = dep->de_services;
	tagp = (const uint8_t *)(poep + 1);
	while (poe_tagcheck(poep, plen, tagp)) {
		ttyp = POET_GET_TYPE(tagp);
		if (ttyp == POETT_END)
			break;
		tlen = POET_GET_LENG(tagp);
		switch (ttyp) {
		case POETT_SERVICE:	/* Service-Name */
			/*
			 * Allow only one.  (Note that this test works
			 * because there's always at least one service
			 * per device; otherwise, the device is
			 * removed from the list.)
			 */
			if (sepp != dep->de_services) {
				if (nsvcs != -1)
					(void) poe_add_str(opoe, POETT_NAMERR,
					    "Too many Service-Name tags");
				nsvcs = -1;
				break;
			}
			seppe = sepp + dep->de_nservices;
			if (tlen == 0) {
				/*
				 * If config specifies "nowild" in a
				 * global context, then we don't
				 * respond to wildcard PADRs.  The
				 * client must know the exact service
				 * name to get access.
				 */

				if (!ispadi && (glob_svc.se_flags & SEF_NOWILD))
					sepp = seppe;
				while (sepp < seppe) {
					sep = *sepp++;
					if (sep->se_name[0] == '\0' ||
					    (sep->se_flags & SEF_NOWILD) ||
					    !allow_service(sep, pap))
						continue;
					*srvp = (void *)sep;
					/*
					 * RFC requires that PADO includes the
					 * wildcard service request in response
					 * to PADI.
					 */
					if (ispadi && nsvcs == 0 &&
					    !(glob_svc.se_flags & SEF_NOWILD))
						(void) poe_tag_copy(opoe, tagp);
					nsvcs++;
					(void) poe_add_str(opoe, POETT_SERVICE,
					    sep->se_name);
					/* If PADR, then one is enough */
					if (!ispadi)
						break;
				}
				/* Just for generating error messages */
				if (nsvcs == 0)
					(void) poe_tag_copy(opoe, tagp);
			} else {
				/*
				 * Clients's requested service must appear in
				 * reply.
				 */
				(void) poe_tag_copy(opoe, tagp);

				/* Requested specific service; find it. */
				cp = (char *)POET_DATA(tagp);
				while (sepp < seppe) {
					sep = *sepp++;
					if (strlen(sep->se_name) == tlen &&
					    strncasecmp(sep->se_name, cp,
					    tlen) == 0) {
						if (allow_service(sep, pap)) {
							nsvcs++;
							*srvp = (void *)sep;
						}
						break;
					}
				}
			}
			/*
			 * Allow service definition to override
			 * AC-Name (concentrator [server] name) field.
			 */
			if (*srvp != NULL) {
				sep = (const struct service_entry *)*srvp;
				log_for_service(sep->se_log, sep->se_debug);
				str = "Solaris PPPoE";
				if (sep->se_server != NULL)
					str = sep->se_server;
				(void) poe_add_str(opoe, POETT_ACCESS, str);
			}
			break;
		/* Ones we should discard */
		case POETT_ACCESS:	/* AC-Name */
		case POETT_COOKIE:	/* AC-Cookie */
		case POETT_NAMERR:	/* Service-Name-Error */
		case POETT_SYSERR:	/* AC-System-Error */
		case POETT_GENERR:	/* Generic-Error */
		case POETT_HURL:	/* Host-URL */
		case POETT_MOTM:	/* Message-Of-The-Minute */
		case POETT_RTEADD:	/* IP-Route-Add */
		case POETT_VENDOR:	/* Vendor-Specific */
		case POETT_MULTI:	/* Multicast-Capable */
		default:
			break;
		/* Ones we should copy */
		case POETT_UNIQ:	/* Host-Uniq */
		case POETT_RELAY:	/* Relay-Session-Id */
			(void) poe_tag_copy(opoe, tagp);
			break;
		}
		tagp = POET_NEXT(tagp);
	}
	return (nsvcs);
}

/*
 * Like fgetc, but reads from a string.
 */
static int
sgetc(void *arg)
{
	char **cpp = (char **)arg;
	if (**cpp == '\0')
		return (EOF);
	return (*(*cpp)++);
}

/*
 * Given a service structure, launch pppd.  Called by handle_input()
 * in pppoed.c if locate_service() [above] finds exactly one service
 * matching a PADR.
 */
int
launch_service(int tunfd, poep_t *poep, void *srvp, struct ppptun_control *ptc)
{
	const struct service_entry *sep = (const struct service_entry *)srvp;
	const char *path;
	const char *extra;
	const char *pppd;
	const char *cp;
	pid_t pidv;
	int newtun;
	struct ppptun_peer ptp;
	union ppptun_name ptn;
	const char *args[MAXARGS];
	struct strbuf ctrl;
	struct strbuf data;
	const char **cpp;
	char *sptr;
	char *spv;
	int slen;
	int retv;
	char keybuf[MAX_KEYWORD];

	assert(sep != NULL);

	/* Get tunnel driver connection for new PPP session. */
	newtun = open(tunnam, O_RDWR);
	if (newtun == -1)
		goto syserr;

	/* Set this session up for standard PPP and client's address. */
	(void) memset(&ptp, '\0', sizeof (ptp));
	ptp.ptp_style = PTS_PPPOE;
	ptp.ptp_address = ptc->ptc_address;
	if (strioctl(newtun, PPPTUN_SPEER, &ptp, sizeof (ptp), sizeof (ptp)) <
	    0)
		goto syserr;
	ptp.ptp_rsessid = ptp.ptp_lsessid;
	if (strioctl(newtun, PPPTUN_SPEER, &ptp, sizeof (ptp), sizeof (ptp)) <
	    0)
		goto syserr;

	/* Attach the requested lower stream. */
	cp = strchr(ptc->ptc_name, ':');
	if (cp == NULL)
		cp = ptc->ptc_name + strlen(ptc->ptc_name);
	(void) snprintf(ptn.ptn_name, sizeof (ptn.ptn_name), "%.*s:pppoe",
	    cp-ptc->ptc_name, ptc->ptc_name);
	if (strioctl(newtun, PPPTUN_SDATA, &ptn, sizeof (ptn), 0) < 0)
		goto syserr;
	(void) snprintf(ptn.ptn_name, sizeof (ptn.ptn_name), "%.*s:pppoed",
	    cp-ptc->ptc_name, ptc->ptc_name);
	if (strioctl(newtun, PPPTUN_SCTL, &ptn, sizeof (ptn), 0) < 0)
		goto syserr;

	pidv = fork();
	if (pidv == (pid_t)-1)
		goto syserr;

	if (pidv == (pid_t)0) {
		/*
		 * Use syslog only in order to avoid mixing log messages
		 * in regular files.
		 */
		close_log_files();

		if ((path = sep->se_path) == NULL)
			path = "/usr/bin/pppd";
		if ((extra = sep->se_extra) == NULL)
			extra = "plugin pppoe.so directtty";
		if ((pppd = sep->se_pppd) == NULL)
			pppd = "";

		/* Concatenate these. */
		slen = strlen(path) + strlen(extra) + strlen(pppd) + 3;
		if ((sptr = (char *)malloc(slen)) == NULL)
			goto bail_out;
		(void) strcpy(sptr, path);
		(void) strcat(sptr, " ");
		(void) strcat(sptr, extra);
		(void) strcat(sptr, " ");
		(void) strcat(sptr, pppd);

		/* Parse out into arguments */
		cpp = args;
		spv = sptr;
		while (cpp < args + MAXARGS - 1) {
			retv = getkeyword(NULL, keybuf, sizeof (keybuf), sgetc,
			    (void *)&spv, 1);
			if (retv != 1)
				*cpp++ = strsave(keybuf);
			if (retv != 0)
				break;
		}
		*cpp = NULL;
		if (cpp == args)
			goto bail_out;

		/*
		 * Fix tunnel device on stdin/stdout and error file on
		 * stderr.
		 */
		if (newtun != 0 && dup2(newtun, 0) < 0)
			goto bail_out;
		if (newtun != 1 && dup2(newtun, 1) < 0)
			goto bail_out;
		if (newtun > 1)
			(void) close(newtun);
		if (tunfd > 1)
			(void) close(tunfd);
		(void) close(2);
		(void) open("/etc/ppp/pppoe-errors", O_WRONLY | O_APPEND |
		    O_CREAT, 0600);

		/*
		 * Change GID first, for obvious reasons.  Note that
		 * we log any problems to syslog, not the errors file.
		 * The errors file is intended for problems in the
		 * exec'd program.
		 */
		if ((sep->se_flags & SEF_GIDSET) &&
		    setgid(sep->se_gid) == -1) {
			cp = mystrerror(errno);
			reopen_log();
			logerr("setgid(%d): %s", sep->se_gid, cp);
			goto logged;
		}
		if ((sep->se_flags & SEF_UIDSET) &&
		    setuid(sep->se_uid) == -1) {
			cp = mystrerror(errno);
			reopen_log();
			logerr("setuid(%d): %s", sep->se_uid, cp);
			goto logged;
		}

		/* Run pppd */
		path = args[0];
		cp = strrchr(args[0], '/');
		if (cp != NULL && cp[1] != '\0')
			args[0] = cp+1;
		errno = 0;
		(void) execv(path, (char * const *)args);
		newtun = 0;

		/*
		 * Exec failure; attempt to log the problem and send a
		 * PADT to the client so that it knows the session
		 * went south.
		 */
	bail_out:
		cp = mystrerror(errno);
		reopen_log();
		logerr("\"%s\": %s", (sptr == NULL ? path : sptr), cp);
	logged:
		poep = poe_mkheader(pkt_output, POECODE_PADT, ptp.ptp_lsessid);
		poep->poep_session_id = htons(ptp.ptp_lsessid);
		(void) poe_add_str(poep, POETT_SYSERR, cp);
		(void) sleep(1);
		ctrl.len = sizeof (*ptc);
		ctrl.buf = (caddr_t)ptc;
		data.len = poe_length(poep) + sizeof (*poep);
		data.buf = (caddr_t)poep;
		if (putmsg(newtun, &ctrl, &data, 0) < 0) {
			logerr("putmsg %s: %s", ptc->ptc_name,
			    mystrerror(errno));
		}
		exit(1);
	}

	(void) close(newtun);

	/* Give session ID to client in reply. */
	poep->poep_session_id = htons(ptp.ptp_lsessid);
	return (1);

syserr:
	/* Peer doesn't know session ID yet; hope for the best. */
	retv = errno;
	if (newtun >= 0)
		(void) close(newtun);
	(void) poe_add_str(poep, POETT_SYSERR, mystrerror(retv));
	return (0);
}

/*
 * This is pretty awful -- it uses recursion to print a simple list.
 * It's just for debug, though, and does a reasonable job of printing
 * the filters in the right order.
 */
static void
print_filter_list(FILE *fp, struct filter_entry *fep)
{
	if (fep->fe_prev != NULL)
		print_filter_list(fp, fep->fe_prev);
	(void) fprintf(fp, "\t\t    MAC %s", ehost2(&fep->fe_mac));
	(void) fprintf(fp, ", mask %s%s\n", ehost2(&fep->fe_mask),
	    (fep->fe_isexcept ? ", except" : ""));
}

/*
 * Write summary of parsed configuration data to given file.
 */
void
dump_configuration(FILE *fp)
{
	const struct device_entry *dep;
	const struct service_entry *sep, **sepp;
	struct per_file *pfp;
	int i, j;

	(void) fprintf(fp, "Will%s respond to wildcard queries.\n",
	    (glob_svc.se_flags & SEF_NOWILD) ? " not" : "");
	(void) fprintf(fp,
	    "Global debug level %d, log to %s; current level %d\n",
	    glob_svc.se_debug,
	    ((glob_svc.se_log == NULL || *glob_svc.se_log == '\0') ?
	    "syslog" : glob_svc.se_log),
	    log_level);
	if (cur_options == NULL) {
		(void) fprintf(fp, "No current configuration.\n");
		return;
	}
	(void) fprintf(fp, "Current configuration:\n");
	(void) fprintf(fp, "    %d device(s):\n", cur_options->os_ndevices);
	dep = cur_options->os_devices;
	for (i = 0; i < cur_options->os_ndevices; i++, dep++) {
		(void) fprintf(fp, "\t%s: %d service(s):\n",
		    dep->de_name, dep->de_nservices);
		sepp = dep->de_services;
		for (j = 0; j < dep->de_nservices; j++, sepp++) {
			sep = *sepp;
			(void) fprintf(fp, "\t    %s: debug level %d",
			    sep->se_name, sep->se_debug);
			if (sep->se_flags & SEF_UIDSET)
				(void) fprintf(fp, ", UID %u", sep->se_uid);
			if (sep->se_flags & SEF_GIDSET)
				(void) fprintf(fp, ", GID %u", sep->se_gid);
			if (sep->se_flags & SEF_WILD)
				(void) fprintf(fp, ", wildcard");
			else if (sep->se_flags & SEF_NOWILD)
				(void) fprintf(fp, ", nowildcard");
			else
				(void) fprintf(fp, ", wildcard (default)");
			(void) putc('\n', fp);
			if (sep->se_server != NULL)
				(void) fprintf(fp, "\t\tserver \"%s\"\n",
				    sep->se_server);
			if (sep->se_pppd != NULL)
				(void) fprintf(fp, "\t\tpppd \"%s\"\n",
				    sep->se_pppd);
			if (sep->se_path != NULL)
				(void) fprintf(fp, "\t\tpath \"%s\"\n",
				    sep->se_path);
			if (sep->se_extra != NULL)
				(void) fprintf(fp, "\t\textra \"%s\"\n",
				    sep->se_extra);
			if (sep->se_log != NULL)
				(void) fprintf(fp, "\t\tlog \"%s\"\n",
				    sep->se_log);
			if (sep->se_flist != NULL) {
				(void) fprintf(fp, "\t\tfilter list:\n");
				print_filter_list(fp, sep->se_flist);
			}
		}
	}
	(void) fprintf(fp, "\nConfiguration read from:\n");
	for (pfp = cur_options->os_pfjunk; pfp != NULL; pfp = pfp->pf_prev) {
		(void) fprintf(fp, "    %s: %d service(s)\n", pfp->pf_name,
		    pfp->pf_nsvc);
	}
}
