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
 * Copyright (c) 2017 Peter Tribble.
 */

/*
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <libintl.h>
#include <dirent.h>
#include <pkgstrct.h>
#include <pkgdev.h>
#include <pkglocs.h>
#include <archives.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <wait.h>

/*
 * libinstzones includes
 */

#include <instzones_api.h>

/*
 * consolidation pkg command library includes
 */

#include <pkglib.h>

/*
 * local pkg command library includes
 */

#include <install.h>
#include <libinst.h>
#include <libadm.h>
#include <dryrun.h>
#include <messages.h>

/*
 * pkginstall local includes
 */

#include "pkginstall.h"

extern int		pkgverbose;
extern fsblkcnt_t	pkgmap_blks; 		/* main.c */

extern struct pkgdev pkgdev;

extern char	tmpdir[];
extern char	pkgbin[];
extern char	instdir[];
extern char	saveSpoolInstallDir[];
extern char	*pkginst;

extern int	dbchg;
extern int	nosetuid;
extern int	nocnflct;
extern int	warnflag;

#define	DMRG_DONE	-1

#define	ck_efile(s, p)	\
		((p->cinfo.modtime >= 0) && \
		p->ainfo.local && \
		cverify(0, &p->ftype, s, &p->cinfo, 1))

static int	eocflag;

/*
 * The variable below indicates that fix_attributes() will be inadequate
 * because a replacement was permitted.
 */
static int	repl_permitted = 0;

static int	domerg(struct cfextra **extlist, int part, int nparts,
			int myclass, char **srcp, char **dstp,
			char **r_updated);
static void	endofclass(struct cfextra **extlist, int myclass,
			int ckflag, PKGserver server, VFP_T **a_cfTmpVfp);
static int	fix_attributes(struct cfextra **, int);
static int	dir_is_populated(char *dirpath);
static boolean_t absolutepath(char *path);
static boolean_t parametricpath(char *path, char **relocpath);

/* Used to keep track of the entries in extlist that are regular files. */
struct reg_files {
	struct reg_files *next;
	int val;
};
static struct reg_files *regfiles_head = NULL;

/*
 * This is the function that actually installs one volume (usually that's
 * all there is). Upon entry, the extlist is entirely correct:
 *
 *	1. It contains only those files which are to be installed
 *	   from all volumes.
 *	2. The mode bits in the ainfo structure for each file are set
 *	   correctly in accordance with administrative defaults.
 *	3. mstat.setuid/setgid reflect what the status *was* before
 *	   pkgdbmerg() processed compliance.
 */
void
instvol(struct cfextra **extlist, char *srcinst, int part,
	int nparts, PKGserver pkgserver, VFP_T **a_cfTmpVfp,
	char **r_updated, char *a_zoneName)
{
	FILE		*listfp;
	char		*updated = (char *)NULL;
	char		*relocpath = (char *)NULL;
	char		*dstp;
	char		*listfile;
	char		*srcp;
	char		*pspool_loc;
	char		scrpt_dst[PATH_MAX];
	int		count;
	int		entryidx;	/* array of current package objects */
	int		n;
	int		nc = 0;
	int		pass;		/* pass count through the for loop. */
	int		tcount;
	struct cfent	*ept;
	struct cfextra	*ext;
	struct mergstat	*mstat;
	struct reg_files *rfp = NULL;

	/*
	 * r_updated is an optional parameter that can be passed in
	 * by the caller if the caller wants to know if any objects are
	 * updated. Do not initialize r_updated; the call to instvol
	 * could be cumulative and any previous update indication must not
	 * be disturbed - this flag is only set, it must never be reset.
	 * This flag is a "char *" pointer so that the object that was
	 * updated can be displayed in debugging output.
	 */

	if (part == 1) {
		pkgvolume(&pkgdev, srcinst, part, nparts);
	}

	tcount = 0;
	nc = cl_getn();

	/*
	 * For each class in this volume, install those files.
	 *
	 * NOTE : This loop index may be decremented by code below forcing a
	 * second trip through for the same class. This happens only when a
	 * class is split between an archive and the tree. Examples would be
	 * old WOS packages and the occasional class containing dynamic
	 * libraries which require special treatment.
	 */

	if (is_depend_pkginfo_DB() == B_FALSE) {
	    int		classidx;	/* the current class */

	    for (classidx = 0; classidx < nc; classidx++) {
		int pass_relative = 0;
		int rel_init = 0;

		eocflag = count = pass = 0;
		listfp = (FILE *)0;
		listfile = NULL;

		/* Now what do we pass to the class action script */

		if (cl_pthrel(classidx) == REL_2_CAS) {
			pass_relative = 1;
		}

		for (;;) {
			if (!tcount++) {
				/* first file to install */
				if (a_zoneName == (char *)NULL) {
					echo(MSG_INS_N_N, part, nparts);
				} else {
					echo(MSG_INS_N_N_LZ, part, nparts,
						a_zoneName);
				}
			}

			/*
			 * If there's an install class action script and no
			 * list file has been created yet, create that file
			 * and provide the pointer in listfp.
			 */
			if (cl_iscript(classidx) && !listfp) {
				/* create list file */
				putparam("TMPDIR", tmpdir);
				listfile = tempnam(tmpdir, "list");
				if ((listfp = fopen(listfile, "w")) == NULL) {
					progerr(ERR_WTMPFILE, listfile);
					quit(99);
				}
			}

			/*
			 * The following function goes through the package
			 * object list returning the array index of the next
			 * regular file. If it encounters a directory,
			 * symlink, named pipe or device, it just creates it.
			 */

			entryidx = domerg(extlist, (pass++ ? 0 : part), nparts,
				classidx, &srcp, &dstp, &updated);

			/* Evaluate the return code */
			if (entryidx == DMRG_DONE) {
				/*
				 * Set ept to the first entry in extlist
				 * which is guaranteed to exist so
				 * later checks against ept->ftype are
				 * not compared to NULL.
				 */
				ext = extlist[0];
				ept = &(ext->cf_ent);
				break; /* no more entries to process */
			}

			ext = extlist[entryidx];
			ept = &(ext->cf_ent);
			mstat = &(ext->mstat);

			/*
			 * If not installing from a partially spooled package
			 * (the "save/pspool" area), and the file contents can
			 * be changed (type is 'e' or 'v'), and the class is not
			 * "none": copy the file from the package (in pristine
			 * state with no actions performed) into the appropriate
			 * location in the packages destination "save/pspool"
			 * area.
			 */

			if ((!is_partial_inst()) &&
				((ept->ftype == 'e') || (ept->ftype == 'v')) &&
				(strcmp(ept->pkg_class, "none") != 0)) {

				if (absolutepath(ext->map_path) == B_TRUE &&
					parametricpath(ext->cf_ent.ainfo.local,
						&relocpath) == B_FALSE) {
					pspool_loc = ROOT;
				} else {
					pspool_loc = RELOC;
				}

				n = snprintf(scrpt_dst, PATH_MAX, "%s/%s/%s",
					saveSpoolInstallDir, pspool_loc,
					relocpath ? relocpath : ext->map_path);

				if (n >= PATH_MAX) {
					progerr(ERR_CREATE_PATH_2,
						saveSpoolInstallDir,
						ext->map_path);
					quit(99);
				}

				/* copy, preserve source file mode */

				if (cppath(MODE_SRC, srcp, scrpt_dst, 0644)) {
					warnflag++;
				}
			}

			/*
			 * If this isn't writeable anyway, it's not going
			 * into the list file. Only count it if it's going
			 * into the list file.
			 */
			if (is_fs_writeable(ext->cf_ent.path,
				&(ext->fsys_value)))
				count++;

			pkgvolume(&pkgdev, srcinst, part, nparts);

			/*
			 * If source verification is OK for this class, make
			 * sure the source we're passing to the class action
			 * script is useable.
			 */
			if (cl_svfy(classidx) != NOVERIFY) {
				if (cl_iscript(classidx) ||
					((ept->ftype == 'e') ||
					(ept->ftype == 'n'))) {
					if (ck_efile(srcp, ept)) {
						progerr(ERR_CORRUPT,
							srcp);
						logerr(getErrbufAddr());
						warnflag++;
						continue;
					}
				}
			}

			/*
			 * If there's a class action script for this class,
			 * just collect names in a temporary file
			 * that will be used as the stdin when the
			 * class action script is invoked.
			 */

			if ((cl_iscript(classidx)) &&
					((is_fs_writeable(ept->path,
						&(ext->fsys_value))))) {
				if (pass_relative) {
					if (!rel_init) {
						(void) fputs(instdir, listfp);
						(void) putc('\n', listfp);
						rel_init++;
					}
					(void) fputs(ext->map_path, listfp);
					(void) putc('\n', listfp);
				} else {
					(void) fputs(srcp ?
						srcp : "/dev/null", listfp);
					(void) putc(' ', listfp);
					(void) fputs(dstp, listfp);
					(void) putc('\n', listfp);
				}
				/*
				 * Note which entries in extlist are regular
				 * files to be installed via the class action
				 * script.
				 */
				if (regfiles_head == NULL) {
					assert(rfp == NULL);
					regfiles_head =
					    malloc(sizeof (struct reg_files));
					if (regfiles_head == NULL) {
						progerr(ERR_MEMORY, errno);
						quit(99);
					}
					regfiles_head->next = NULL;
					regfiles_head->val = entryidx;
					rfp = regfiles_head;
				} else {
					assert(rfp != NULL);
					rfp->next =
					    malloc(sizeof (struct reg_files));
					if (rfp->next == NULL) {
						progerr(ERR_MEMORY, errno);
						quit(99);
					}
					rfp = rfp->next;
					rfp->next = NULL;
					rfp->val = entryidx;
				}

				/*
				 * A warning message about unwritable targets
				 * in a class may be appropriate here.
				 */
				continue;
			}

			/*
			 * If not installing from a partially spooled package
			 * (the "save/pspool" area), and the file contents can
			 * be changed (type is 'e' or 'v') and the class
			 * identifier is not "none": copy the file from the
			 * package (in pristine state with no actions performed)
			 * into the appropriate location in the packages
			 * destination "save/pspool" area.
			 */

			if ((!is_partial_inst()) &&
			    ((ept->ftype == 'e') || (ept->ftype == 'v') &&
			    (strcmp(ept->pkg_class, "none") != 0))) {

				if (absolutepath(ext->map_path) == B_TRUE &&
					parametricpath(ext->cf_ent.ainfo.local,
						&relocpath) == B_FALSE) {
					pspool_loc = ROOT;
				} else {
					pspool_loc = RELOC;
				}

				n = snprintf(scrpt_dst, PATH_MAX, "%s/%s/%s",
					saveSpoolInstallDir, pspool_loc,
					relocpath ? relocpath : ext->map_path);

				if (n >= PATH_MAX) {
					progerr(ERR_CREATE_PATH_2,
						saveSpoolInstallDir,
						ext->map_path);
					quit(99);
				}

				/* copy, preserve source file mode */

				if (cppath(MODE_SRC, srcp, scrpt_dst, 0644)) {
					warnflag++;
				}
			}

			/*
			 * There are several tests here to determine
			 * how we're going to deal with objects
			 * intended for remote read-only filesystems.
			 * We don't use is_served() because this may be
			 * a server. We're actually interested in if
			 * it's *really* remote and *really* not
			 * writeable.
			 */

			n = is_remote_fs(ept->path, &(ext->fsys_value));
			if ((n != 0) &&
				!is_fs_writeable(ept->path,
				&(ext->fsys_value))) {

				/*
				 * Don't change the file, we can't write
				 * to it anyway.
				 */

				mstat->attrchg = 0;
				mstat->contchg = 0;

				/*
				 * If it's currently mounted, we can
				 * at least test it for existence.
				 */

				if (is_mounted(ept->path, &(ext->fsys_value))) {
					if (!isfile(NULL, dstp)) {
						echo(MSG_IS_PRESENT, dstp);
					} else {
						echo(WRN_INSTVOL_NONE, dstp);
					}
				} else {
					char *server_host;

					server_host = get_server_host(
						ext->fsys_value);

					/* If not, we're just stuck. */
					echo(WRN_INSTVOL_NOVERIFY,
						dstp, server_host);
				}

				continue;
			}

			/* echo output destination name */

			echo("%s", dstp);

			/*
			 * if no source then no need to copy/verify
			 */

			if (srcp == (char *)NULL) {
				continue;
			}

			/*
			 * If doing a partial installation (creating a
			 * non-global zone), extra steps need to be taken:
			 *
			 * If the file is not type 'e' and not type 'v' and
			 * the class is "none": then the file must already
			 * exist (as a result of the initial non-global zone
			 * installation which caused all non-e/v files to be
			 * copied from the global zone to the non-global
			 * zone). If this is the case, verify that the file
			 * exists and has the correct attributes.
			 */

			if (is_partial_inst() != 0) {

				/*
				 * if not type 'e|v' and class 'none', then the
				 * file must already exist.
				 */

				if ((ept->ftype != 'e') &&
					(ept->ftype != 'v') &&
					(strcmp(cl_nam(ept->pkg_class_idx),
								"none") == 0)) {

					/* is file changed? */
					n = finalck(ept, 1, 1, B_TRUE);

					/* not - ok - warn */
					if (n != 0) {
						/* output warning message */
						logerr(NOTE_INSTVOL_FINALCKFAIL,
						    pkginst, ext->map_path);
					}
					continue;
				}
			}

			/*
			 * Copy from source media to target path and fix file
			 * mode and permission now in case installation halted.
			 */

			/*
			 * If the filesystem is read-only don't attempt
			 * to copy a file. Just check that the content
			 * and attributes of the file are correct.
			 *
			 * Normally this doesn't happen, because files,
			 * which don't change, are not returned by
			 * domerg().
			 */
			n = 0;
			if (is_fs_writeable(ept->path,
			    &(ext->fsys_value)))
				n = cppath(MODE_SET|DIR_DISPLAY, srcp,
				    dstp, ept->ainfo.mode);

			if (n != 0) {
				warnflag++;
			} else if (!finalck(ept, 1, 1, B_FALSE)) {
				/*
				 * everything checks here
				 */
				mstat->attrchg = 0;
				mstat->contchg = 0;
			}

			/* NOTE: a package object was updated */

			if (updated == (char *)NULL) {
				echoDebug(DBG_INSTVOL_OBJ_UPDATED, dstp);
				updated = dstp;
			}
		}

		/*
		 * We have now completed processing of all pathnames
		 * associated with this volume and class.
		 */
		if (cl_iscript(classidx)) {
			/*
			 * Execute appropriate class action script
			 * with list of source/destination pathnames
			 * as the input to the script.
			 */

			if (chdir(pkgbin)) {
				progerr(ERR_CHGDIR, pkgbin);
				quit(99);
			}

			if (listfp) {
				(void) fclose(listfp);
			}

			/* nothing updated */

			echoDebug(DBG_INSTVOL_CAS_INFO, is_partial_inst(),
				updated ? updated : "");

			if ((is_partial_inst() != 0) &&
					(updated == (char *)NULL)) {

				/*
				 * installing in non-global zone, and no object
				 * has been updated (installed/verified):
				 * do not run the class action script.
				 */

				echoDebug(DBG_INSTVOL_NOT_RUNNING_CAS,
					a_zoneName ? a_zoneName : "?",
					eocflag ? "ENDOFCLASS" :
							cl_iscript(classidx),
					cl_nam(classidx),
					cl_iscript(classidx));

			} else {
				/* run the class action script */

				echoDebug(DBG_INSTVOL_RUNNING_CAS,
					a_zoneName ? a_zoneName : "?",
					eocflag ? "ENDOFCLASS" :
							cl_iscript(classidx),
					cl_nam(classidx),
					cl_iscript(classidx));

				/* Use ULIMIT if supplied. */
				set_ulimit(cl_iscript(classidx), ERR_CASFAIL);

				if (eocflag) {
					/*
					 * end of class detected.
					 * Since there are no more volumes which
					 * contain pathnames associated with
					 * this class, execute class action
					 * script with the ENDOFCLASS argument;
					 * we do this even if none of the path
					 * names associated with this class and
					 * volume needed installation to
					 * guarantee the class action script is
					 * executed at least once during package
					 * installation.
					 */
					if (pkgverbose) {
						n = pkgexecl((listfp ?
							listfile : CAS_STDIN),
							CAS_STDOUT,
							CAS_USER, CAS_GRP,
							SHELL, "-x",
							cl_iscript(classidx),
							"ENDOFCLASS", NULL);
					} else {
						n = pkgexecl(
							(listfp ?
							listfile : CAS_STDIN),
							CAS_STDOUT, CAS_USER,
							CAS_GRP, SHELL,
							cl_iscript(classidx),
							"ENDOFCLASS", NULL);
					}
					ckreturn(n, ERR_CASFAIL);
				} else if (count) {
					/* execute class action script */
					if (pkgverbose) {
						n = pkgexecl(listfile,
							CAS_STDOUT, CAS_USER,
							CAS_GRP, SHELL, "-x",
							cl_iscript(classidx),
							NULL);
					} else {
						n = pkgexecl(listfile,
							CAS_STDOUT, CAS_USER,
							CAS_GRP, SHELL,
							cl_iscript(classidx),
							NULL);
					}
					ckreturn(n, ERR_CASFAIL);
				}

				/*
				 * Ensure the mod times on disk match those
				 * in the pkgmap. In this case, call cverify
				 * with checksumming disabled, since the only
				 * action that needs to be done is to verify
				 * that the attributes are correct.
				 */

				if ((rfp = regfiles_head) != NULL) {
					while (rfp != NULL) {
					    ept = &(extlist[rfp->val]->cf_ent);
					    cverify(1, &ept->ftype, ept->path,
						&ept->cinfo, 0);
					    rfp = rfp->next;
					}
					regfiles_free();
				}

				clr_ulimit();

				if ((r_updated != (char **)NULL) &&
					(*r_updated == (char *)NULL) &&
					(updated == (char *)NULL)) {
					updated = "postinstall";
					echoDebug(DBG_INSTVOL_OBJ_UPDATED,
								updated);
				}
			}
			if (listfile) {
				(void) remove(listfile);
			}
		}

		if (eocflag && (!is_partial_inst() || (is_partial_inst() &&
			strcmp(cl_nam(classidx), "none") != 0))) {
			if (cl_dvfy(classidx) == QKVERIFY && !repl_permitted) {
				/*
				 * The quick verify just fixes everything.
				 * If it returns 0, all is well. If it
				 * returns 1, then the class installation
				 * was incomplete and we retry on the
				 * stuff that failed in the conventional
				 * way (without a CAS). this is primarily
				 * to accomodate old archives such as are
				 * found in pre-2.5 WOS; but, it is also
				 * used when a critical dynamic library
				 * is not archived with its class.
				 */
				if (!fix_attributes(extlist, classidx)) {
					/*
					 * Reset the CAS pointer. If the
					 * function returns 0 then there
					 * was no script there in the first
					 * place and we'll just have to
					 * call this a miss.
					 */
					if (cl_deliscript(classidx))
						/*
						 * Decrement classidx for
						 * next pass.
						 */
						classidx--;
				}
			} else {
				/*
				 * Finalize merge. This checks to make sure
				 * file attributes are correct and any links
				 * specified are created.
				 */
				(void) endofclass(extlist, classidx,
					(cl_iscript(classidx) ? 0 : 1),
					pkgserver, a_cfTmpVfp);
			}
		}
	    }
	}

	/*
	 * Instead of creating links back to the GZ files the logic is
	 * to let zdo recreate the files from the GZ then invoke pkgadd to
	 * install the editable files and skip over any 'f'type files.
	 * The commented out block is to create the links which should be
	 * removed once the current code is tested to be correct.
	 */

	/*
	 * Go through extlist creating links for 'f'type files
	 * if we're in a global zone. Note that this code lies
	 * here instead of in the main loop to support CAF packages.
	 * In a CAF package the files are installed by the i.none script
	 * and don't exist until all files are done being processed, thus
	 * the additional loop through extlist.
	 */

	/*
	 * output appropriate completion message
	 */

	if (is_depend_pkginfo_DB() == B_TRUE) {
		/* updating database only (hollow package) */
		if (a_zoneName == (char *)NULL) {
			echo(MSG_DBUPD_N_N, part, nparts);
		} else {
			echo(MSG_DBUPD_N_N_LZ, part, nparts, a_zoneName);
		}
	} else if (tcount == 0) {
		/* updating package (non-hollow package) */
		if (a_zoneName == (char *)NULL) {
			echo(MSG_INST_N_N, part, nparts);
		} else {
			echo(MSG_INST_N_N_LZ, part, nparts, a_zoneName);
		}
	}

	/*
	 * if any package objects were updated (not otherwise already in
	 * existence), set the updated flag as appropriate
	 */

	if (updated != (char *)NULL) {
		echoDebug(DBG_INSTVOL_OBJ_UPDATED, updated);
		if (r_updated != (char **)NULL) {
			*r_updated = updated;
		}
	}

}

/*
 * Name:	domerg
 * Description: For the specified class, review each entry and return the array
 *		index number of the next regular file to process. Hard links are
 *		skipped (they are created in endofclass() and directories,
 *		symlinks, pipes and devices are created here, as well as any
 *		file that already exists and has the correct attributes.
 * Arguments:	struct cfextra **extlist - [RO, *RW]
 *			- Pointer to list of cfextra structures representing
 *			  the pkgmap of the package to be installed
 *		int part - [RO, *RO]
 *			- the part of the package currently being processed;
 *			  packages begin with part "1" and proceed for the
 *			  number (nparts) that comprise the package (volume).
 *		int nparts - [RO, *RO]
 *			- the number of parts the package is divided into
 *		int myclass - [RO, *RO]
 *			- index into class array of the current class
 *		char **srcp - [RW, *RW]
 *			- pointer to pointer to string representing the source
 *			  path for the next package to process - if this
 *			  function returns != DMRG_DONE then this pointer is
 *			  set to a pointer to a string representing the source
 *			  path for the next object from the package to process
 *		char **dstp - [RW, *RW]
 *			- pointer to pointer to string representing the target
 *			  path for the next package to process - if this
 *			  function returns != DMRG_DONE then this pointer is
 *			  set to a pointer to a string representing the target
 *			  path for the next object from the package to process
 *		char **r_updated - [RO, *RW]
 *			- pointer to pointer to string - set if the last path
 *			  returned exists or does not need updating. This is
 *			  always set when a path to be installed exists and
 *			  has the correct contents.
 * Returns:	int
 *			!= DMRG_DONE - index into extlist of the next path to
 *				be processed - that needs to be installed/copied
 *			== DMRG_DONE - all entries processed
 */

static int
domerg(struct cfextra **extlist, int part, int nparts,
	int myclass, char **srcp, char **dstp,
	char **r_updated)
{
	boolean_t	stateFlag = B_FALSE;
	int		i;
	int		msg_ugid;
	static int	maxvol = 0;
	static int	svindx = 0;
	static int	svpart = 0;
	struct cfent	*ept = (struct cfent *)NULL;
	struct mergstat *mstat = (struct mergstat *)NULL;

	/* reset returned path pointers */

	*dstp = (char *)NULL;
	*srcp = (char *)NULL;

	/* set to start or continue based on which part being processed */

	if (part != 0) {
		maxvol = 0;
		svindx = 0;
		svpart = part;
	} else {
		i = svindx;
		part = svpart;
	}

	/*
	 * This goes through the pkgmap entries one by one testing them
	 * for inclusion in the package database as well as for validity
	 * against existing files.
	 */
	for (i = svindx; extlist[i]; i++) {
		ept = &(extlist[i]->cf_ent);
		mstat = &(extlist[i]->mstat);

		/* if this isn't the class of current interest, skip it */

		if (myclass != ept->pkg_class_idx) {
			continue;
		}

		/* if the class is invalid, announce it & exit */
		if (ept->pkg_class_idx == -1) {
			progerr(ERR_CLIDX, ept->pkg_class_idx,
			    (ept->path && *ept->path) ? ept->path : "unknown");
			logerr(gettext("pathname=%s"),
			    (ept->path && *ept->path) ? ept->path : "unknown");
			logerr(gettext("class=<%s>"),
			    (ept->pkg_class && *ept->pkg_class) ?
			    ept->pkg_class : "Unknown");
			logerr(gettext("CLASSES=<%s>"),
			    getenv("CLASSES") ? getenv("CLASSES") : "Not Set");
			quit(99);
		}

		/*
		 * Next check to see if we are going to try to delete a
		 * populated directory in some distressing way.
		 */
		if (mstat->dir2nondir)
			if (dir_is_populated(ept->path)) {
				logerr(WRN_INSTVOL_NOTDIR, ept->path);
				warnflag++;
				mstat->denied = 1;	/* install denied! */
				continue;
			} else {	/* Replace is OK. */
				/*
				 * Remove this directory, so it won't
				 * interfere with creation of the new object.
				 */
				if (rmdir(ept->path)) {
					/*
					 * If it didn't work, there's nothing
					 * we can do. To continue would
					 * likely corrupt the filesystem
					 * which is unacceptable.
					 */
					progerr(ERR_RMDIR, ept->path);
					quit(99);
				}

				repl_permitted = 1;	/* flag it */
			}

		/* adjust the max volume number appropriately */

		if (ept->volno > maxvol) {
			maxvol = ept->volno;
		}

		/* if this part goes into another volume, skip it */

		if (part != ept->volno) {
			continue;
		}

		/*
		 * If it's a conflicting file and it's not supposed to be
		 * installed, note it and skip.
		 */
		if (nocnflct && mstat->shared && ept->ftype != 'e') {
			if (mstat->contchg || mstat->attrchg) {
				echo(MSG_SHIGN, ept->path);
			}
			continue;
		}

		/*
		 * If we want to set uid or gid but user says no, note it.
		 * Remember that the actual mode bits in the structure have
		 * already been adjusted and the mstat flag is telling us
		 * about the original mode.
		 */
		if (nosetuid && (mstat->setuid || mstat->setgid)) {
			msg_ugid = 1;	/* don't repeat attribute message. */
			if (is_fs_writeable(ept->path,
				&(extlist[i]->fsys_value))) {
				if (!(mstat->contchg) && mstat->attrchg) {
					echo(MSG_UGMOD, ept->path);
				} else {
					echo(MSG_UGID, ept->path);
				}
			}
		} else {
			msg_ugid = 0;
		}

		switch (ept->ftype) {
			case 'l':	/* hard link */
				/* links treated as object "update/skip" */
				stateFlag = B_TRUE;
				continue; /* defer to final proc */

			case 's': /* for symlink, verify without fix first */
				/* links treated as object "update/skip" */
				stateFlag = B_TRUE;

				/* Do this only for default verify */
				if (cl_dvfy(myclass) == DEFAULT) {
					if (averify(0, &ept->ftype,
						ept->path, &ept->ainfo))
						echo(MSG_SLINK, ept->path);
				}

				/*FALLTHRU*/

			case 'd':	/* directory */
			case 'x':	/* exclusive directory */
			case 'c':	/* character special device */
			case 'b':	/* block special device */
			case 'p':	/* named pipe */
				/* these NOT treated as object "update/skip" */
				stateFlag = B_FALSE;

				/*
				 * If we can't get to it for legitimate reasons,
				 * don't try to verify it.
				 */
				if (is_remote_fs(ept->path,
				    &(extlist[i]->fsys_value)) &&
				    !is_fs_writeable(ept->path,
				    &(extlist[i]->fsys_value))) {
					mstat->attrchg = 0;
					mstat->contchg = 0;
					break;
				}

				if (averify(1, &ept->ftype, ept->path,
							&ept->ainfo) == 0) {
					mstat->contchg = mstat->attrchg = 0;
				} else {
					progerr(ERR_CREATE_PKGOBJ, ept->path);
					logerr(getErrbufAddr());
					warnflag++;
				}

				break;

			case 'i':	/* information file */
				/* not treated as object "update/skip" */
				stateFlag = B_FALSE;
				break;

			default:
				/* all files treated as object "update/skip" */
				stateFlag = B_TRUE;
				break;
		}

		/*
		 * Both contchg and shared flags have to be taken into
		 * account. contchg is set if the file is already present
		 * in the package database, if it does not exist or if it
		 * exists and is modified.
		 * The shared flag is set when 'e' or 'v' file is not
		 * present in the package database, exists and is not
		 * modified. It also has to be checked here.
		 * Shared flag is also set when file is present in package
		 * database and owned by more than one package, but for
		 * this case contchg has already been set.
		 */
		if (mstat->contchg || (mstat->shared &&
		    ((ept->ftype == 'e') || (ept->ftype == 'v')))) {
			*dstp = ept->path;
			if ((ept->ftype == 'f') || (ept->ftype == 'e') ||
				(ept->ftype == 'v')) {
				*srcp = ept->ainfo.local;
				if (is_partial_inst() != 0) {
					if (*srcp[0] == '~') {
						/* Done only for C style */
						char *tmp_ptr;
						tmp_ptr = extlist[i]->map_path;
						if (ept->ftype != 'f') {
							/*
							 * translate source
							 * pathname
							 */
							*srcp =
							    srcpath(instdir,
							    tmp_ptr,
							    part,
							    nparts);
						} else {
						/*
						 * instdir has the absolute path
						 * to saveSpoolInstallDir for
						 * the package. This is only
						 * useful for 'e','v' types.
						 *
						 * For 'f', we generate the
						 * absolute src path with the
						 * help of install root and the
						 * basedir.
						 */
							*srcp = trans_srcp_pi(
							    ept->ainfo.local);
						}
					} else {
						*srcp = extlist[i]->map_path;
					}
				} else {
					if (*srcp[0] == '~') {
						/* translate source pathname */
						*srcp = srcpath(instdir,
						    &(ept->ainfo.local[1]),
						    part, nparts);
					}
				}

				echoDebug(DBG_DOMERG_NO_SUCH_FILE,
					ept->ftype, cl_nam(ept->pkg_class_idx),
					ept->path);
			} else {
				/*
				 * At this point, we're returning a non-file
				 * that couldn't be created in the standard
				 * way. If it refers to a filesystem that is
				 * not writeable by us, don't waste the
				 * calling process's time.
				 */
				if (!is_fs_writeable(ept->path,
					&(extlist[i]->fsys_value))) {
					echoDebug(DBG_DOMERG_NOT_WRITABLE,
						ept->ftype,
						cl_nam(ept->pkg_class_idx),
						ept->path);
					continue;
				}

				*srcp = NULL;
				echoDebug(DBG_DOMERG_NOT_THERE,
					ept->ftype, cl_nam(ept->pkg_class_idx),
					ept->path);
			}

			svindx = i+1;
			backup(*dstp, 1);
			return (i);
		}

		if (mstat->attrchg) {
			backup(ept->path, 0);
			if (!msg_ugid)
				echo(MSG_ATTRIB, ept->path);

			/* fix the attributes now for robustness sake */
			if (averify(1, &ept->ftype,
				ept->path,
				&ept->ainfo) == 0) {
				mstat->attrchg = 0;
			}
		}

		/*
		 * package object exists, or does not need updating:
		 * treat the object as if it were "updated"
		 */

		/* LINTED warning: statement has no consequent: if */
		if ((stateFlag == B_FALSE) || (ept == (struct cfent *)NULL)) {
			/*
			 * the object in question is a directory or special
			 * file - the fact that this type of object already
			 * exists or does not need updating must not trigger
			 * the object updated indication - that would cause
			 * class action scripts to be run when installing a
			 * new non-global zone
			 */
		} else {
			if (r_updated != (char **)NULL) {
				if (*r_updated == (char *)NULL) {
					echoDebug(DBG_INSTVOL_OBJ_UPDATED,
								ept->path);
				}
				*r_updated = ept->path;
			}
		}
	}

	if (maxvol == part) {
		eocflag++;	/* endofclass */
	}

	return (DMRG_DONE);	/* no remaining entries on this volume */
}

/*
 * Determine if the provided directory is populated. Return 0 if so and 1 if
 * not. This also returns 0 if the dirpath is not a directory or if it does
 * not exist.
 */
static int
dir_is_populated(char *dirpath) {
	DIR	*dirfp;
	struct	dirent *drp;
	int	retcode = 0;

	if ((dirfp = opendir(dirpath)) != NULL) {
		while ((drp = readdir(dirfp)) != NULL) {
			if (strcmp(drp->d_name, ".") == 0) {
				continue;
			}
			if (strcmp(drp->d_name, "..") == 0) {
				continue;
			}
			/*
			 * If we get here, there's a real file in the
			 * directory
			 */
			retcode = 1;
			break;
		}
		(void) closedir(dirfp);
	}

	return (retcode);
}

/*
 * This is the function that cleans up the installation of this class.
 * This is where hard links get put in since the stuff they're linking
 * probably exists by now.
 */
static void
endofclass(struct cfextra **extlist, int myclass, int ckflag,
	PKGserver pkgserver, VFP_T **a_cfTmpVfp)
{
	char		*temppath;
	char 		*pspool_loc;
	char 		*relocpath = (char *)NULL;
	char 		scrpt_dst[PATH_MAX];
	int		flag;
	int		idx;
	int		n;
	struct cfent	*ept;	/* entry from the internal list */
	struct cfextra	entry;	/* entry from the package database */
	struct mergstat	*mstat;	/* merge status */
	struct pinfo	*pinfo;

	/* open the package database (contents) file */

	if (!ocfile(&pkgserver, a_cfTmpVfp, pkgmap_blks)) {
		quit(99);
	}

	echo(MSG_VERIFYING_CLASS, cl_nam(myclass));

	for (idx = 0; /* void */; idx++) {
		/* find next package object in this class */
		while (extlist[idx]) {
			if ((extlist[idx]->cf_ent.ftype != 'i') &&
				extlist[idx]->cf_ent.pkg_class_idx == myclass) {
				break;
			}
			idx++;
		}

		if (extlist[idx] == NULL)
			break;


		ept = &(extlist[idx]->cf_ent);
		mstat = &(extlist[idx]->mstat);

		temppath = extlist[idx]->client_path;

		/*
		 * At this point  the only difference between the entry
		 * in the contents file and the entry in extlist[] is
		 * that the status indicator contains CONFIRM_CONT.
		 * This function should return one or something is wrong.
		 */

		n = srchcfile(&(entry.cf_ent), temppath, pkgserver);

		if (n < 0) {
			char	*errstr = getErrstr();
			progerr(ERR_CFBAD);
			logerr(gettext("pathname=%s"),
				entry.cf_ent.path && *entry.cf_ent.path ?
				entry.cf_ent.path : "Unknown");
			logerr(gettext("problem=%s"),
				(errstr && *errstr) ? errstr : "Unknown");
			quit(99);
		} else if (n != 1) {
			/*
			 * Check if path should be in the package
			 * database.
			 */
			if ((mstat->shared && nocnflct)) {
				continue;
			}
			progerr(ERR_CFMISSING, ept->path);
			quit(99);
		}

		/*
		 * If merge was not appropriate for this object, now is the
		 * time to choose one or the other.
		 */
		if (mstat->denied) {
			/*
			 * If installation was denied AFTER the package
			 * database was updated, skip this. We've already
			 * announced the discrepancy and the verifications
			 * that follow will make faulty decisions based on
			 * the ftype, which may not be correct.
			 */
			progerr(ERR_COULD_NOT_INSTALL, ept->path);
			warnflag++;
		} else {
			if (mstat->replace)
				/*
				 * This replaces the old entry with the new
				 * one. This should never happen in the new
				 * DB since the entries are already identical.
				 */
				repl_cfent(ept, &(entry.cf_ent));

			/*
			 * Validate this entry and change the status flag in
			 * the package database.
			 */
			if (ept->ftype == RM_RDY) {
				(void) eptstat(&(entry.cf_ent), pkginst,
					STAT_NEXT);
			} else {
				/* check the hard link now. */
				if (ept->ftype == 'l') {
					if (averify(0, &ept->ftype,
						ept->path, &ept->ainfo)) {
						echo(MSG_HRDLINK,
							ept->path);
						mstat->attrchg++;
					}
				}

				/*
				 * Don't install or verify objects for
				 * remote, read-only filesystems.  We need
				 * only flag them as shared from some server.
				 * Otherwise, ok to do final check.
				 */
				if (is_remote_fs(ept->path,
					&(extlist[idx]->fsys_value)) &&
					!is_fs_writeable(ept->path,
					&(extlist[idx]->fsys_value))) {
					flag = -1;
				} else {
					flag = finalck(ept, mstat->attrchg,
						(ckflag ? mstat->contchg :
						(-1)), B_FALSE);
				}

				pinfo = entry.cf_ent.pinfo;

				/* Find this package in the list. */
				while (pinfo) {
					if (strcmp(pkginst, pinfo->pkg) == 0) {
						break;
					}
					pinfo = pinfo->next;
				}

				/*
				 * If this package owns this file, then store
				 * it in the database with the appropriate
				 * status. Need to check pinfo in case it
				 * points to NULL which could happen if
				 * pinfo->next = NULL above.
				 */
				if (pinfo) {
					if (flag < 0 || is_served(ept->path,
						&(extlist[idx]->fsys_value))) {
						/*
						 * This is provided to
						 * clients by a server.
						 */
						pinfo->status = SERVED_FILE;
					} else {
						/*
						 * It's either there or it's
						 * not.
						 */
						pinfo->status = (flag ?
							NOT_FND : ENTRY_OK);
					}
				}
			}
		}

		/*
		 * If not installing from a partially spooled package, the
		 * "save/pspool" area, and the file contents can be
		 * changed (type is 'e' or 'v'), and the class IS "none":
		 * copy the installed volatile file into the appropriate
		 * location in the packages destination "save/pspool" area.
		 */

		if ((!is_partial_inst()) &&
			((ept->ftype == 'e') || (ept->ftype == 'v')) &&
			(strcmp(ept->pkg_class, "none") == 0)) {

			if (absolutepath(extlist[idx]->map_path) == B_TRUE &&
				parametricpath(extlist[idx]->cf_ent.ainfo.local,
					&relocpath) == B_FALSE) {
				pspool_loc = ROOT;
			} else {
				pspool_loc = RELOC;
			}

			n = snprintf(scrpt_dst, PATH_MAX, "%s/%s/%s",
				saveSpoolInstallDir, pspool_loc,
				relocpath ? relocpath : extlist[idx]->map_path);

			if (n >= PATH_MAX) {
				progerr(ERR_CREATE_PATH_2,
					saveSpoolInstallDir,
					extlist[idx]->map_path);
				quit(99);
			}

			/* copy, preserve source file mode */

			if (cppath(MODE_SRC, ept->path, scrpt_dst, 0644)) {
				warnflag++;
			}
		}

		/*
		 * Now insert this potentially changed package database
		 * entry.
		 */
		if (entry.cf_ent.npkgs) {
			if (putcvfpfile(&(entry.cf_ent), *a_cfTmpVfp)) {
				quit(99);
			}
		}
	}

	n = swapcfile(pkgserver, a_cfTmpVfp, pkginst, dbchg);
	if (n == RESULT_WRN) {
		warnflag++;
	} else if (n == RESULT_ERR) {
		quit(99);
	}
}

/*
 * This function goes through and fixes all the attributes. This is called
 * out by using DST_QKVERIFY=this_class in the pkginfo file. The primary
 * use for this is to fix up files installed by a class action script
 * which is time-critical and reliable enough to assume likely success.
 * The first such format was for WOS compressed-cpio'd file sets.
 * The second format is the Class Archive Format.
 */
static int
fix_attributes(struct cfextra **extlist, int idx)
{
	struct	cfextra *ext;
	int	i, retval = 1;
	int 	nc = cl_getn();
	int	n;
	struct cfent *ept;
	struct mergstat *mstat;
	char scrpt_dst[PATH_MAX];
	char *pspool_loc;
	char *relocpath = (char *)NULL;

	for (i = 0; extlist[i]; i++) {
		ext = extlist[i];
		ept = &(extlist[i]->cf_ent);
		mstat = &(extlist[i]->mstat);

		/*
		 * We don't care about 'i'nfo files because, they
		 * aren't laid down, 'e'ditable files can change
		 * anyway, so who cares and 's'ymlinks were already
		 * fixed in domerg(); however, certain old WOS
		 * package symlinks depend on a bug in the old
		 * pkgadd which has recently been expunged. For
		 * those packages in 2.2, we repeat the verification
		 * of symlinks.
		 *
		 * By 2.6 or so, ftype == 's' should be added to this.
		 */
		if (ept->ftype == 'i' || ept->ftype == 'e' ||
			(mstat->shared && nocnflct))
			continue;

		if (mstat->denied) {
			progerr(ERR_COULD_NOT_INSTALL, ept->path);
			warnflag++;
			continue;
		}

		if (ept->pkg_class_idx < 0 || ept->pkg_class_idx > nc) {
			progerr(ERR_CLIDX, ept->pkg_class_idx,
			    (ept->path && *ept->path) ? ept->path : "unknown");
			continue;
		}

		/* If this is the right class, do the fast verify. */
		if (ept->pkg_class_idx == idx) {
			if (fverify(1, &ept->ftype, ept->path,
				&ept->ainfo, &ept->cinfo) == 0) {
				mstat->attrchg = 0;
				mstat->contchg =  0;
			} else	/* We'll try full verify later */
				retval = 0;
		}
		/*
		 * Need to copy the installed volitale file back to the
		 * partial spooled area if we are installing to a local zone
		 * or similar installation method.
		 */

		if ((!is_partial_inst()) &&
			((ept->ftype == 'e') || (ept->ftype == 'v')) &&
			(strcmp(ept->pkg_class, "none") == 0)) {

			if (absolutepath(ext->map_path) == B_TRUE &&
				parametricpath(ext->cf_ent.ainfo.local,
					&relocpath) == B_FALSE) {
				pspool_loc = ROOT;
			} else {
				pspool_loc = RELOC;
			}

			n = snprintf(scrpt_dst, PATH_MAX, "%s/%s/%s",
				saveSpoolInstallDir, pspool_loc,
				relocpath ? relocpath : ext->map_path);

			if (n >= PATH_MAX) {
				progerr(ERR_CREATE_PATH_2,
					saveSpoolInstallDir,
					ext->map_path);
				quit(99);
			}

			/* copy, preserve source file mode */

			if (cppath(MODE_SRC, ept->path, scrpt_dst, 0644)) {
				warnflag++;
			}
		}
	}

	return (retval);
}

/*
 * Check to see if first charcter in path is a '/'.
 *
 * Return:
 * 			B_TRUE - if path is prepended with '/'
 * 			B_FALSE - if not
 */
static boolean_t
absolutepath(char *path)
{
	assert(path != NULL);
	assert(path[0] != '\0');

	return (path[0] == '/' ? B_TRUE : B_FALSE);
}

/*
 * Check to see if path contains a '$' which makes it
 * a parametric path and therefore relocatable.
 *
 * Parameters:
 *             path - The path to determine if it is absolute
 *             relocpath - The value of the unconditioned path
 *                         i.e. $OPTDIR/usr/ls
 * Return:
 * 			B_TRUE - if path is a parametric path
 * 			B_FALSE - if not
 */
static boolean_t
parametricpath(char *path, char **relocpath)
{
	assert(path != NULL);
	assert(path[0] != '\0');

	/*
	 * If this is a valid parametric path then a '$' MUST occur at the
	 * first or second character.
	 */

	if (path[0] == '$' || path[1] == '$') {
		/*
		 * If a parametric path exists then when copying the
		 * path to the pspool directoy from the installing
		 * pkgs reloc directory we want to use the uncononditional
		 * varaiable path.
		 */
		*relocpath = (path + 1);
		return (B_TRUE);
	}
	return (B_FALSE);
}

void
regfiles_free()
{
	if (regfiles_head != NULL) {
		struct reg_files *rfp = regfiles_head->next;

		while (rfp != NULL) {
			free(regfiles_head);
			regfiles_head = rfp;
			rfp = regfiles_head->next;
		}
		free(regfiles_head);
		regfiles_head = NULL;
	}
}
