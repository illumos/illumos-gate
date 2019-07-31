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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <pkgstrct.h>
#include <sys/stat.h>
#include <locale.h>
#include <libintl.h>
#include <pkginfo.h>
#include <instzones_api.h>
#include <pkglib.h>
#include <libinst.h>
#include <messages.h>

/* merg() return codes */
#define	MRG_SAME	0
#define	MRG_DIFFERENT	1
#define	MRG_REPLACE	2

/* typechg() return codes */
#define	TYPE_OK		0
#define	TYPE_WARNING	1
#define	TYPE_IGNORED	2
#define	TYPE_REPLACE	3
#define	TYPE_FATAL	4

/* message pool */
#define	ERR_OUTPUT	"unable to update package database"
#define	ERR_PINFO	"missing pinfo structure for <%s>"
#define	INFO_PROCESS	"   %2ld%% of information processed; continuing ..."

#define	WRN_NOTFILE	"WARNING: %s <no longer a regular file>"
#define	WRN_NOTSYMLN	"WARNING: %s <no longer a symbolic link>"
#define	WRN_NOTLINK	"WARNING: %s <no longer a linked file>"
#define	WRN_NOTDIR	"WARNING: %s <no longer a directory>"
#define	WRN_NOTCHAR	"WARNING: %s <no longer a character special device>"
#define	WRN_NOTBLOCK	"WARNING: %s <no longer a block special device>"
#define	WRN_NOTPIPE	"WARNING: %s <no longer a named pipe>"
#define	WRN_TOEXCL	"WARNING: cannot convert %s to an exclusive directory."
#define	WRN_ODDVERIFY	"WARNING: quick verify disabled for class %s."

#define	MSG_TYPIGN	"Object type change ignored."
#define	MSG_TYPE_ERR	"Package attempts fatal object type change."

extern char	*pkginst;
extern int	nosetuid, nocnflct, otherstoo;

/* pkgobjmap.c */
extern int	cp_cfent(struct cfent *cf_ent, struct cfextra *el_ent);

/* setlist.c */
extern void	cl_def_dverify(int idx);

char dbst = '\0';	/* usually set by installf() or removef() */

int files_installed(void);	/* return number of files installed. */

static int	errflg = 0;
static int	eptnum;
static int	installed;	/* # of files, already properly installed. */
static struct	pinfo	*pkgpinfo = (struct pinfo *)0;

static int	is_setuid(struct cfent *ent);
static int	is_setgid(struct cfent *ent);
static int	merg(struct cfextra *el_ent, struct cfent *cf_ent);
static int	do_like_ent(VFP_T *vfpo, struct cfextra *el_ent,
		    struct cfent *cf_ent, int ctrl);
static int	do_new_ent(VFP_T *vfpo, struct cfextra *el_ent, int ctrl);
static int	typechg(struct cfent *el_ent, struct cfent *cf_ent,
		    struct mergstat *mstat);

static void	set_change(struct cfextra *el_ent);
static void	chgclass(struct cfent *cf_ent, struct pinfo *pinfo);
static void	output(VFP_T *vfpo, struct cfent *ent, struct pinfo *pinfo);

/*
 * This scans the extlist (pkgmap) and matches them to the database, copying
 * out the modified contents to the file at tmpfp. It updates the mergstat
 * structures and deals with administrative defaults regarding setuid and
 * conflict.
 */

int
pkgdbmerg(PKGserver server, VFP_T *tmpvfp, struct cfextra **extlist)
{
	static	struct	cfent	cf_ent;	/* scratch area */
	struct	cfextra	*el_ent;	/* extlist entry under review */
	int	n;
	int	changed;
	int	assume_ok = 0;

	cf_ent.pinfo = (NULL);
	errflg = 0;
	installed = changed = 0;

	vfpRewind(tmpvfp);

	for (eptnum = 0; (el_ent = extlist[eptnum]) != NULL; eptnum++) {
		/*
		 * If there's an entry in the extlist at this position,
		 * process that entry.
		 */
		/* Metafiles don't get merged. */
		if ((el_ent->cf_ent.ftype == 'i') ||
			(el_ent->cf_ent.ftype == 'n')) {
			continue;
		}

		/*
		 * Copy cfextra structure for duplicated paths.
		 * This is not just an optimization, it is
		 * necessary for correct operation of algorithm.
		 */
		if ((eptnum > 0) && (strncmp(el_ent->cf_ent.path,
		    extlist[eptnum-1]->cf_ent.path, PATH_MAX) == 0)) {
			memcpy(extlist[eptnum], extlist[eptnum-1],
			    sizeof (struct cfextra));
			continue;
		}

		/*
		 * Normally dbst comes to us from installf() or
		 * removef() in order to specify their special
		 * database status codes. They cannot implement a
		 * quick verify (it just doesn't make sense). For
		 * that reason, we can test to see if we already have
		 * a special database status. If we don't (it's from
		 * pkgadd) then we can test to see if this is calling
		 * for a quick verify wherein we assume the install
		 * will work and fix it if it doesn't. In that case
		 * we set our own dbst to be ENTRY_OK.
		 */
		if (dbst == '\0') {
			if (cl_dvfy(el_ent->cf_ent.pkg_class_idx) ==
			    QKVERIFY) {
				assume_ok = 1;
			}
		} else {
			/*
			 * If we DO end up with an installf/quick
			 * verify combination, we fix that by simply
			 * denying the quick verify for this class.
			 * This forces everything to come out alright
			 * by forcing the standard assumptions as
			 * regards package database for the rest of
			 * the load.
			 */
			if (cl_dvfy(el_ent->cf_ent.pkg_class_idx) ==
			    QKVERIFY) {
				logerr(gettext(WRN_ODDVERIFY),
				    cl_nam(el_ent->cf_ent.pkg_class_idx));
				/*
				 * Set destination verification to
				 * default.
				 */
				cl_def_dverify(el_ent->cf_ent.pkg_class_idx);
			}
		}

		/*
		 * Comply with administrative requirements regarding
		 * setuid/setgid processes.
		 */
		if (is_setuid(&(el_ent->cf_ent))) {
			el_ent->mstat.setuid = 1;
		}
		if (is_setgid(&(el_ent->cf_ent))) {
			el_ent->mstat.setgid = 1;
		}

		/*
		 * If setuid/setgid processes are not allowed, reset
		 * those bits.
		 */
		if (nosetuid && (el_ent->mstat.setgid ||
		    el_ent->mstat.setuid)) {
			el_ent->cf_ent.ainfo.mode &= ~(S_ISUID | S_ISGID);
		}

		/* Search package database for this entry. */
		n = srchcfile(&cf_ent, el_ent->cf_ent.path, server);

		/*
		 * If there was an error, note it and return an error
		 * flag.
		 */
		if (n < 0) {
			char	*errstr = getErrstr();
			progerr(ERR_CFBAD);
			logerr(gettext("pathname: %s"),
			    (cf_ent.path && *cf_ent.path) ?
			    cf_ent.path : "Unknown");
			logerr(gettext("problem: %s"),
			    (errstr && *errstr) ? errstr : "Unknown");
			return (-1);
		/*
		 * If there was a match, then merge them into a
		 * single entry.
		 */
		} else if (n == 1) {
			/*
			 * If this package is overwriting a setuid or
			 * setgid process, set the status bits so we
			 * can inform the administrator.
			 */
			if (is_setuid(&cf_ent)) {
				el_ent->mstat.osetuid = 1;
			}

			if (is_setgid(&cf_ent)) {
				el_ent->mstat.osetgid = 1;
			}
			/*
			 * Detect if a symlink has changed to directory
			 * If so mark all the files/dir supposed to be
			 * iniside this dir, so that they are not miss
			 * understood by do_new_ent later as already
			 * installed.
			 */
			if ((cf_ent.ftype == 's') &&
			    (el_ent->cf_ent.ftype == 'd')) {
				int i;
				int plen = strlen(el_ent->cf_ent.path);
				for (i = eptnum + 1; extlist[i]; i++) {
					if (strncmp(el_ent->cf_ent.path,
					    extlist[i]->cf_ent.path,
					    plen) != 0)
						break;
					extlist[i]->mstat.parentsyml2dir
					    = 1;
				}
			}

			if (do_like_ent(tmpvfp, el_ent, &cf_ent, assume_ok)) {
				changed++;
			}

		} else {
			/*
			 * The file doesn't exist in the database.
			 */
			if (do_new_ent(tmpvfp, el_ent, assume_ok)) {
				changed++;
			}
		}
	}

	return (errflg ? -1 : changed);
}

/*
 * Merge a new entry with an installed package object of the same name and
 * insert that object into the package database. Obey administrative defaults
 * as regards conflicting files.
 */

static int
do_like_ent(VFP_T *vfpo, struct cfextra *el_ent, struct cfent *cf_ent, int ctrl)
{
	int	stflag, ignore, changed, mrg_result;

	ignore = changed = 0;

	/*
	 * Construct the record defining the current package. If there are
	 * other packages involved, this will be appended to the existing
	 * list. If this is an update of the same package, it will get merged
	 * with the existing record. If this is a preloaded record (like from
	 * a dryrun file), it will keep it's current pinfo pointer and will
	 * pass it on to the record from the contents file - because on the
	 * final continuation, the contents file will be wrong.
	 */
	if (el_ent->mstat.preloaded) {
		struct pinfo *pkginfo;

		/* Contents file is not to be trusted for this list. */
		pkginfo = cf_ent->pinfo;

		/* Free the potentially bogus list. */
		while (pkginfo) {
			struct pinfo *next;
			next = pkginfo->next;
			free(pkginfo);
			pkginfo = next;
		}

		cf_ent->pinfo = el_ent->cf_ent.pinfo;
	}

	pkgpinfo = eptstat(cf_ent, pkginst, DUP_ENTRY);

	stflag = pkgpinfo->status;

	if (otherstoo)
		el_ent->mstat.shared = 1;

	/* If it's marked for erasure, make it official */
	if (el_ent->cf_ent.ftype == RM_RDY) {
		if (!errflg) {
			pkgpinfo = eptstat(cf_ent, pkginst, RM_RDY);

			/*
			 * Get copy of status character in case the object is
			 * "shared" by a server, in which case we need to
			 * maintain the shared status after the entry is
			 * written to the package database with RM_RDY
			 * status. This is needed to support the `removef'
			 * command.
			 */
			stflag = pkgpinfo->status;
			pkgpinfo->status = RM_RDY;

			if (putcvfpfile(cf_ent, vfpo)) {
				progerr(gettext(ERR_OUTPUT));
				quit(99);
			}

			/*
			 * If object is provided by a server, allocate an
			 * info block and set the status to indicate this.
			 * This is needed to support the `removef' command.
			 */
			if (stflag == SERVED_FILE) {
				el_ent->cf_ent.pinfo =
				    (struct pinfo *)calloc(1,
				    sizeof (struct pinfo));
				el_ent->cf_ent.pinfo->next = NULL;
				el_ent->cf_ent.pinfo->status = SERVED_FILE;
			}
		}
		return (1);
	}

	/*
	 * If there is no package associated with it, there's something
	 * very wrong.
	 */
	if (!pkgpinfo) {
		progerr(gettext(ERR_PINFO), cf_ent->path);
		quit(99);
	}

	/*
	 * Do not allow installation if nocnflct is set and other packages
	 * reference this pathname. The cp_cfent() function below writes the
	 * information from the installed file over the new entry, so the
	 * package database will be unchanged.
	 *
	 * By the way, ftype "e" is often shared and that's OK, so ftype
	 * "e" doesn't count here.
	 */
	if ((nocnflct && el_ent->mstat.shared && el_ent->cf_ent.ftype != 'e')) {
		/*
		 * First set the attrchg and contchg entries for proper
		 * messaging in the install phase.
		 */
		set_change(el_ent);

		/*
		 * Now overwrite the new entry with the entry for the
		 * currently installed object.
		 */
		if (cp_cfent(cf_ent, el_ent) == 0)
			quit(99);

		ignore++;
	} else {
		mrg_result = merg(el_ent, cf_ent);

		switch (mrg_result) {
		    case MRG_SAME:
			break;

		    case MRG_DIFFERENT:
			changed++;
			break;

		    case MRG_REPLACE:
			/*
			 * We'll pick one or the other later. For now, cf_ent
			 * will have the fault value and el_ent will retain
			 * the other value. This is the only state that allows
			 * the database and the pkgmap to differ.
			 */

			el_ent->mstat.contchg = 1;	/* subject to change */
			ignore++;
			break;

		    default:
			break;
		}
	}

	/* el_ent structure now contains updated entry */
	if (!el_ent->mstat.contchg && !ignore) {
		/*
		 * We know the DB entry matches the pkgmap, so now we need to
		 * see if the actual object matches the pkgmap.
		 */
		set_change(el_ent);
	}

	if (!errflg) {
		if (ctrl == 1) {	/* quick verify assumes OK */
			/*
			 * The pkgpinfo entry is already correctly
			 * constructed. Look into dropping this soon.
			 */
			pkgpinfo = eptstat(&(el_ent->cf_ent), pkginst,
			    ENTRY_OK);

			if (stflag != DUP_ENTRY) {
				changed++;
			}

			/*
			 * We could trust the prior pkginfo entry, but things
			 * could have changed and  we need to update the
			 * fs_tab[] anyway. We check for a server object
			 * here.
			 */
			if (is_served(el_ent->server_path,
			    &(el_ent->fsys_value)))
				pkgpinfo->status = SERVED_FILE;
		} else {
			if (!ignore && el_ent->mstat.contchg) {
				pkgpinfo =
				    eptstat(&(el_ent->cf_ent), pkginst,
				    (dbst ? dbst : CONFIRM_CONT));
			} else if (!ignore && el_ent->mstat.attrchg) {
				pkgpinfo =
				    eptstat(&(el_ent->cf_ent), pkginst,
				    (dbst ? dbst : CONFIRM_ATTR));
			} else if (!ignore && el_ent->mstat.shared) {
				pkgpinfo =
				    eptstat(&(el_ent->cf_ent), pkginst,
				    dbst);
				changed++;
			} else if (stflag != DUP_ENTRY) {
				pkgpinfo = eptstat(&(el_ent->cf_ent),
				    pkginst, '\0');
				if (stflag != ENTRY_OK) {
					changed++;
				}
			}
		}

		if (mrg_result == MRG_REPLACE) {
			/*
			 * Put the original package database entry back into
			 * the package database for now.
			 */
			output(vfpo, cf_ent, pkgpinfo);
		} else {
			/* Put the merged entry into the package database. */
			output(vfpo, &(el_ent->cf_ent), pkgpinfo);
		}
	}

	if (pkgpinfo->aclass[0] != '\0') {
		(void) strcpy(el_ent->cf_ent.pkg_class, pkgpinfo->aclass);
	}

	/*
	 * If a sym link entry exists in the contents file and
	 * and the destination of the link does not exist on the the system
	 * then the contents file needs to be updated appropriately so a
	 * subsequent invocation of "installf -f" will create the destination.
	 */
	if (el_ent->mstat.contchg && pkgpinfo->status == INST_RDY) {
		changed++;
	}

	if (!(el_ent->mstat.preloaded))
		el_ent->cf_ent.pinfo = NULL;

	/*
	 * If no change during the merg and we don't have a case where types
	 * were different in odd ways, count this as installed.
	 */
	if (!el_ent->mstat.attrchg && !el_ent->mstat.contchg &&
	    !el_ent->mstat.replace)
		installed++;
	return (changed);
}

/* Insert an entirely new entry into the package database. */
static int
do_new_ent(VFP_T *vfpo, struct cfextra *el_ent, int ctrl)
{
	struct pinfo	*pinfo;
	char		*tp;
	int		changed = 0;

	if (el_ent->cf_ent.ftype == RM_RDY) {
		return (0);
	}

	tp = el_ent->server_path;
	/*
	 * Check the file/dir existence only if any of the parent directory
	 * of the file/dir has not changed from symbolic link to directory.
	 * At this time we are only doing a dry run, the symlink is not yet
	 * replaced, so if this is done directly then access will result in
	 * incorrect information in case a file with the same attr and cont
	 * exists in the link target.
	 */
	if ((!el_ent->mstat.parentsyml2dir) && (access(tp, F_OK) == 0)) {
		/*
		 * Path exists, and although its not referenced by any
		 * package we make it look like it is so it appears as a
		 * conflicting file in case the user doesn't want it
		 * installed. We set the rogue flag to distinguish this from
		 * package object conflicts if the administrator is queried
		 * about this later. Note that noconflict means NO conflict
		 * at the file level. Even rogue files count.
		 */
		el_ent->mstat.shared = 1;
		el_ent->mstat.rogue = 1;
		set_change(el_ent);
	} else {
		/* since path doesn't exist, we're changing everything */
		el_ent->mstat.rogue = 0;
		el_ent->mstat.contchg = 1;
		el_ent->mstat.attrchg = 1;
	}

	if (el_ent->cf_ent.ainfo.mode == WILDCARD) {
		if (el_ent->cf_ent.ftype == 'd') {
			el_ent->cf_ent.ainfo.mode = DEFAULT_MODE;
		} else {
			el_ent->cf_ent.ainfo.mode = DEFAULT_MODE_FILE;
		}
		logerr(WRN_SET_DEF_MODE, el_ent->cf_ent.path,
		    (int)el_ent->cf_ent.ainfo.mode);
	}

	if (strcmp(el_ent->cf_ent.ainfo.owner, DB_UNDEFINED_ENTRY) == 0)
		(void) strcpy(el_ent->cf_ent.ainfo.owner,
				DEFAULT_OWNER);
	if (strcmp(el_ent->cf_ent.ainfo.group, DB_UNDEFINED_ENTRY) == 0)
		(void) strcpy(el_ent->cf_ent.ainfo.group,
				DEFAULT_GROUP);

	/*
	 * Do not allow installation if nocnflct is set and this pathname is
	 * already in place. Since this entry is new (not associated with a
	 * package), we don't issue anything to the database we're building.
	 */
	if (nocnflct && el_ent->mstat.shared) {
		return (0);
	}

	if (!errflg) {
		if (el_ent->mstat.preloaded) {
			/* Add this package to the already established list. */
			pinfo = eptstat(&(el_ent->cf_ent), pkginst, DUP_ENTRY);
		} else {
			el_ent->cf_ent.npkgs = 1;
			pinfo = (struct pinfo *)calloc(1,
			    sizeof (struct pinfo));
			if (!pinfo) {
				progerr(gettext(ERR_MEMORY), errno);
				quit(99);
			}
			el_ent->cf_ent.pinfo = pinfo;
			(void) strcpy(pinfo->pkg, pkginst);
		}

		if (ctrl == 1) {	/* quick verify assumes OK */
			pinfo->status = dbst ? dbst : ENTRY_OK;
			/*
			 * The entry won't be verified, but the entry in the
			 * database isn't necessarily ENTRY_OK. If this is
			 * coming from a server, we need to note that
			 * instead.
			 */
			if (is_served(el_ent->server_path,
			    &(el_ent->fsys_value)))
				pinfo->status = SERVED_FILE;
		} else {
			pinfo->status = dbst ? dbst : CONFIRM_CONT;
		}

		output(vfpo, &(el_ent->cf_ent), pinfo);
		changed++;

		free(pinfo);
		el_ent->cf_ent.pinfo = NULL;
		}
	if (!el_ent->mstat.attrchg && !el_ent->mstat.contchg) {
		installed++;
	}

	return (changed);
}

int
files_installed(void)
{
	return (installed);
}

/*
 * This function determines if there is a difference between the file on
 * the disk and the file to be laid down. It set's mstat flags attrchg
 * and contchg accordingly.
 */
static void
set_change(struct cfextra *el_ent)
{
	int	n;
	char 	*tp;

	tp = el_ent->server_path;
	if ((el_ent->cf_ent.ftype == 'f') || (el_ent->cf_ent.ftype == 'e') ||
		(el_ent->cf_ent.ftype == 'v')) {
		if (cverify(0, &(el_ent->cf_ent.ftype), tp,
		    &(el_ent->cf_ent.cinfo), 1)) {
			el_ent->mstat.contchg = 1;
		} else if (!el_ent->mstat.contchg && !el_ent->mstat.attrchg) {
			if (averify(0, &(el_ent->cf_ent.ftype), tp,
			    &(el_ent->cf_ent.ainfo)))
				el_ent->mstat.attrchg = 1;
		}
	} else if (!el_ent->mstat.attrchg &&
		((el_ent->cf_ent.ftype == 'd') ||
		(el_ent->cf_ent.ftype == 'x') ||
		(el_ent->cf_ent.ftype == 'c') ||
		(el_ent->cf_ent.ftype == 'b') ||
		(el_ent->cf_ent.ftype == 'p'))) {
		n = averify(0, &(el_ent->cf_ent.ftype), tp,
		    &(el_ent->cf_ent.ainfo));
		if (n == VE_ATTR)
			el_ent->mstat.attrchg = 1;
		else if (n && (n != VE_EXIST)) {
			el_ent->mstat.contchg = 1;
		}
	} else if (!el_ent->mstat.attrchg &&
		((el_ent->cf_ent.ftype == 's') ||
		(el_ent->cf_ent.ftype == 'l'))) {
		n = averify(0, &(el_ent->cf_ent.ftype), tp,
		    &(el_ent->cf_ent.ainfo));
		if (n == VE_ATTR)
			el_ent->mstat.attrchg = 1;
		else if (n && (n == VE_EXIST)) {
			el_ent->mstat.contchg = 1;
		}
	}
}

static int
is_setuid(struct cfent *ent)
{
	return (((ent->ftype == 'f') || (ent->ftype == 'v') ||
		(ent->ftype == 'e')) &&
		(ent->ainfo.mode != BADMODE) &&
		(ent->ainfo.mode != WILDCARD) &&
		(ent->ainfo.mode & S_ISUID));
}

static int
is_setgid(struct cfent *ent)
{
	return (((ent->ftype == 'f') || (ent->ftype == 'v') ||
		(ent->ftype == 'e')) && (ent->ainfo.mode != BADMODE) &&
		(ent->ainfo.mode != WILDCARD) &&
		(ent->ainfo.mode & S_ISGID) &&
		(ent->ainfo.mode & (S_IEXEC|S_IXUSR|S_IXOTH)));
}

char *types[] = {
	"fev",	/* type 1, regular files */
	"s", 	/* type 2, symbolic links */
	"l", 	/* type 3, linked files */
	"dx", 	/* type 4, directories */
	"c", 	/* type 5, character special devices */
	"b", 	/* type 6, block special devices */
	"p", 	/* type 7, named pipes */
	NULL
};

/*
 * This determines if the ftype of the file on the disk and the file to be
 * laid down are close enough. If they aren't, this either returns an error
 * or displays a warning. This returns :
 *	TYPE_OK		they're identical or close enough
 *	TYPE_WARNING	they're pretty close (probably no problem)
 *	TYPE_IGNORED	the type change was not allowed
 *	TYPE_REPLACE	to be reviewed later - in endofclass() maybe
 *	TYPE_FATAL	something awful happened
 */
static int
typechg(struct cfent *el_ent, struct cfent *cf_ent, struct mergstat *mstat)
{
	int	i, etype, itype, retcode;

	/* If they are identical, return OK */
	if (cf_ent->ftype == el_ent->ftype)
		return (TYPE_OK);

	/*
	 * If package database entry is ambiguous, set it to the new entity's
	 * ftype
	 */
	if (cf_ent->ftype == BADFTYPE) {
		cf_ent->ftype = el_ent->ftype;
		return (TYPE_OK); /* do nothing; not really different */
	}

	/* If the new entity is ambiguous, wait for the verify */
	if (el_ent->ftype == BADFTYPE)
		return (TYPE_OK);

	/*
	 * If we're trying to convert an existing regular directory to an
	 * exclusive directory, this is very dangerous. We will continue, but
	 * we will deny the conversion.
	 */
	if (el_ent->ftype == 'x' && cf_ent->ftype == 'd') {
		logerr(gettext(WRN_TOEXCL), el_ent->path);
		return (TYPE_IGNORED);
	}

	etype = itype = 0;

	/* Set etype to that of the new entity */
	for (i = 0; types[i]; ++i) {
		if (strchr(types[i], el_ent->ftype)) {
			etype = i+1;
			break;
		}
	}

	/* Set itype to that in the package database. */
	for (i = 0; types[i]; ++i) {
		if (strchr(types[i], cf_ent->ftype)) {
			itype = i+1;
			break;
		}
	}

	if (itype == etype) {
		/* same basic object type */
		return (TYPE_OK);
	}

	retcode = TYPE_WARNING;

	/*
	 * If a simple object (like a file) is overwriting a directory, mark
	 * it for full inspection during installation.
	 */
	if (etype != 4 && itype == 4) {
		mstat->dir2nondir = 1;
		retcode = TYPE_REPLACE;
	}

	/* allow change, but warn user of possible problems */
	switch (itype) {
	    case 1:
		logerr(gettext(WRN_NOTFILE), el_ent->path);
		break;

	    case 2:
		logerr(gettext(WRN_NOTSYMLN), el_ent->path);
		break;

	    case 3:
		logerr(gettext(WRN_NOTLINK), el_ent->path);
		break;

	    case 4:
		logerr(gettext(WRN_NOTDIR), el_ent->path);
		break;

	    case 5:
		logerr(gettext(WRN_NOTCHAR), el_ent->path);
		break;

	    case 6:
		logerr(gettext(WRN_NOTBLOCK), el_ent->path);
		break;

	    case 7:
		logerr(gettext(WRN_NOTPIPE), el_ent->path);
		break;

	    default:
		break;
	}
	return (retcode);
}

/*
 * This function takes el_ent (the entry from the pkgmap) and cf_ent (the
 * entry from the package database) and merge them into el_ent. The rules
 * are still being figured out, but the comments should make the approach
 * pretty clear.
 *
 * RETURN CODES:
 *	MRG_DIFFERENT	The two entries are different and el_ent now contains
 *			the intended new entry to be installed.
 *	MRG_SAME	The two entries were identical and the old database
 *			entry will be replaced unchanged.
 *	MRG_REPLACE	One or the other entry will be used but the decision
 *			has to be made at install time.
 */
static int
merg(struct cfextra *el_ent, struct cfent *cf_ent)
{
	int	n, changed = 0;

	/*
	 * We need to change the original entry to make it look like the new
	 * entry (the eptstat() routine has already added appropriate package
	 * information, but not about 'aclass' which may represent a change
	 * in class from the previous installation.
	 *
	 * NOTE: elent->cf_ent.pinfo (the list of associated packages) is NULL
	 * upon entry to this function.
	 */

	el_ent->cf_ent.pinfo = cf_ent->pinfo;

	if (dbst == INST_RDY && el_ent->cf_ent.ftype == '?') {
		el_ent->cf_ent.ftype = cf_ent->ftype;
	}

	/*
	 * Evaluate the ftype change. Usually the ftype won't change. If it
	 * does it may be easy (s -> f), not allowed (d -> x), so complex we
	 * can't figure it 'til later (d -> s) or fatal (a hook for later).
	 */
	if (cf_ent->ftype != el_ent->cf_ent.ftype) {
		n = typechg(&(el_ent->cf_ent), cf_ent, &(el_ent->mstat));

		switch (n) {
		    case TYPE_OK:
			break;

		    /* This is an allowable change. */
		    case TYPE_WARNING:
			el_ent->mstat.contchg = 1;
			break;

		    /* Not allowed, but leaving it as is is OK. */
		    case TYPE_IGNORED:
			logerr(gettext(MSG_TYPIGN));
			if (cp_cfent(cf_ent, el_ent) == 0)
				quit(99);
			return (MRG_SAME);

		    /* Future analysis will reveal if this is OK. */
		    case TYPE_REPLACE:
			el_ent->mstat.replace = 1;
			return (MRG_REPLACE);

		    /* Kill it before it does any damage. */
		    case TYPE_FATAL:
			logerr(gettext(MSG_TYPE_ERR));
			quit(99);

		    default:
			break;
		}

		changed++;
	}

	/* Evaluate and merge the class. */
	if (strcmp(cf_ent->pkg_class, el_ent->cf_ent.pkg_class)) {
		/*
		 * we always allow a class change as long as we have
		 * consistent ftypes, which at this point we must
		 */
		changed++;
		if (strcmp(cf_ent->pkg_class, "?")) {
			(void) strcpy(pkgpinfo->aclass,
			    el_ent->cf_ent.pkg_class);
			(void) strcpy(el_ent->cf_ent.pkg_class,
			    cf_ent->pkg_class);
			chgclass(&(el_ent->cf_ent), pkgpinfo);
		}
	}

	/*
	 * Evaluate and merge based upon the ftype of the intended package
	 * database entry.
	 */
	if (((el_ent->cf_ent.ftype == 's') || (el_ent->cf_ent.ftype == 'l'))) {

		/* If both have link sources, then they need to be merged. */
		if (cf_ent->ainfo.local && el_ent->cf_ent.ainfo.local) {
			/*
			 * If both sources are identical, the merge is
			 * already done.
			 */
			if (strcmp(cf_ent->ainfo.local,
			    el_ent->cf_ent.ainfo.local) != 0) {
				changed++;

				/*
				 * Otherwise, if the pkgmap entry is
				 * ambiguous, it will inherit the database
				 * entry.
				 */
				if (strcmp(el_ent->cf_ent.ainfo.local,
				    "?") == 0) {
					(void) strlcpy(
						el_ent->cf_ent.ainfo.local,
						cf_ent->ainfo.local,
						PATH_MAX);
				} else {
					el_ent->mstat.contchg = 1;
				}
			}
		}
		return (changed ? MRG_DIFFERENT : MRG_SAME);

	} else if (el_ent->cf_ent.ftype == 'e') {

		/*
		 * The contents of edittable files are assumed to be changing
		 * since some class action script will be doing the work and
		 * we have no way of evaluating what it will actually do.
		 */
		el_ent->mstat.contchg = 1;
		changed++;
	} else if (((el_ent->cf_ent.ftype == 'f') ||
					(el_ent->cf_ent.ftype == 'v'))) {
		/*
		 * For regular files, Look at content information; a BADCONT
		 * in any el_ent field indicates the contents are unknown --
		 * since cf_ent is guaranteed to have a valid entry here (bad
		 * assumption?) this function will recognize this as a
		 * change. The ambiguous el_ent values will be evaluated and
		 * set later.
		 */

		if (cf_ent->cinfo.size != el_ent->cf_ent.cinfo.size) {
			changed++;
			el_ent->mstat.contchg = 1;
		} else if (cf_ent->cinfo.modtime !=
		    el_ent->cf_ent.cinfo.modtime) {
			changed++;
			el_ent->mstat.contchg = 1;
		} else if (cf_ent->cinfo.cksum != el_ent->cf_ent.cinfo.cksum) {
			changed++;
			el_ent->mstat.contchg = 1;
		}
	} else if (((el_ent->cf_ent.ftype == 'c') ||
					(el_ent->cf_ent.ftype == 'b'))) {
		/*
		 * For devices, if major or minor numbers are identical the
		 * merge is trivial. If the el_ent value is ambiguous (BAD),
		 * the cf_ent value is inherited. Otherwise, the el_ent value
		 * is preserved.
		 */
		if (cf_ent->ainfo.major != el_ent->cf_ent.ainfo.major) {
			changed++;
			if (el_ent->cf_ent.ainfo.major == BADMAJOR) {
				el_ent->cf_ent.ainfo.major =
				    cf_ent->ainfo.major;
			} else {
				el_ent->mstat.contchg = 1;
			}
		}
		if (cf_ent->ainfo.minor != el_ent->cf_ent.ainfo.minor) {
			changed++;
			if (el_ent->cf_ent.ainfo.minor == BADMINOR)
				el_ent->cf_ent.ainfo.minor =
				    cf_ent->ainfo.minor;
			else
				el_ent->mstat.contchg = 1;
		}
	}

	/*
	 * For mode, owner and group follow the same rules as above - if
	 * ambiguous, inherit, otherwise keep the new one.
	 */
	if (cf_ent->ainfo.mode != el_ent->cf_ent.ainfo.mode) {
		changed++;  /* attribute info is changing */
		if (el_ent->cf_ent.ainfo.mode == BADMODE) {
			el_ent->cf_ent.ainfo.mode = cf_ent->ainfo.mode;
		} else if (el_ent->cf_ent.ainfo.mode == WILDCARD) {
			/*
			 * If pkgmap has a '?' set for mode, use the mode from
			 * the pkg DB (contents file).
			 */
			el_ent->cf_ent.ainfo.mode = cf_ent->ainfo.mode;
			el_ent->mstat.attrchg = 0;
		} else {
			el_ent->mstat.attrchg = 1;
		}
	}
	if (strcmp(cf_ent->ainfo.owner, el_ent->cf_ent.ainfo.owner) != 0) {
		changed++;  /* attribute info is changing */
		if (strcmp(el_ent->cf_ent.ainfo.owner, BADOWNER) == 0)
			(void) strcpy(el_ent->cf_ent.ainfo.owner,
			    cf_ent->ainfo.owner);
		else
			el_ent->mstat.attrchg = 1;
	}
	if (strcmp(cf_ent->ainfo.group, el_ent->cf_ent.ainfo.group) != 0) {
		changed++;  /* attribute info is changing */
		if (strcmp(el_ent->cf_ent.ainfo.group, BADGROUP) == 0)
			(void) strcpy(el_ent->cf_ent.ainfo.group,
			    cf_ent->ainfo.group);
		else
			el_ent->mstat.attrchg = 1;
	}
	return (changed ? MRG_DIFFERENT : MRG_SAME);
}

/*
 * This puts the current entry into the package database in the appropriate
 * intermediate format for this stage of the installation. This also assures
 * the correct format for the various package object ftypes, stripping the
 * link name before storing a regular file and stuff like that.
 */

static void
output(VFP_T *vfpo, struct cfent *ent, struct pinfo *pinfo)
{
	short	svvolno;
	char	*svpt;

	/* output without volume information */
	svvolno = ent->volno;
	ent->volno = 0;

	pinfo->editflag = 0;
	if (((ent->ftype == 's') || (ent->ftype == 'l'))) {
		if (putcvfpfile(ent, vfpo)) {
			progerr(gettext(ERR_OUTPUT));
			quit(99);
		}
	} else {

		/* output without local pathname */
		svpt = ent->ainfo.local;
		ent->ainfo.local = NULL;
		if (putcvfpfile(ent, vfpo)) {
			progerr(gettext(ERR_OUTPUT));
			quit(99);
		}

		ent->ainfo.local = svpt;
		/*
		 * If this entry represents a file which is being edited, we
		 * need to store in memory the fact that it is an edittable
		 * file so that when we audit it after installation we do not
		 * worry about its contents; we do this by resetting the ftype
		 * to 'e' in the memory array which is later used to control
		 * the audit
		 */
		if (pinfo->editflag)
			ent->ftype = 'e';
	}
	/* restore volume information */
	ent->volno = svvolno;
}

static void
chgclass(struct cfent *cf_ent, struct pinfo *pinfo)
{
	struct pinfo *pp;
	char	*oldclass, newclass[CLSSIZ+1];
	int	newcnt, oldcnt;

	/*
	 * we use this routine to minimize the use of the aclass element by
	 * optimizing the use of the cf_ent->pkg_class element
	 */

	(void) strlcpy(newclass, pinfo->aclass, sizeof (newclass));
	newcnt = 1;

	oldclass = cf_ent->pkg_class;
	oldcnt = 0;

	/*
	 * count the number of times the newclass will be used and see if it
	 * exceeds the number of times the oldclass is referenced
	 */
	pp = cf_ent->pinfo;
	while (pp) {
		if (pp->aclass[0] != '\0') {
			if (strcmp(pp->aclass, newclass) == 0)
				newcnt++;
			else if (strcmp(pp->aclass, oldclass) == 0)
				oldcnt++;
		}
		pp = pp->next;
	}
	if (newcnt > oldcnt) {
		pp = cf_ent->pinfo;
		while (pp) {
			if (pp->aclass[0] == '\0') {
				(void) strcpy(pp->aclass, oldclass);
			} else if (strcmp(pp->aclass, newclass) == 0) {
				pp->aclass[0] = '\0';
			}
			pp = pp->next;
		}
		(void) strcpy(cf_ent->pkg_class, newclass);
	}
}
