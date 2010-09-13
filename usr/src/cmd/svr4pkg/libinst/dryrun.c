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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pkgstrct.h>
#include <unistd.h>
#include <pkglib.h>
#include <libintl.h>
#include "libadm.h"
#include "libinst.h"
#include "dryrun.h"

#define	HDR_FSUSAGE	"#name remote_name writeable bfree bused ifree iused"

#define	ERR_NOCREAT	"cannot create %s."
#define	ERR_NOOPEN	"cannot open %s."
#define	ERR_NOWRITE	"cannot write to %s."
#define	ERR_NOREAD	"cannot read from %s."
#define	ERR_FSFAIL	"cannot construct filesystem table entry."
#define	ERR_BADTYPE	"cannot record %s dryrun from %s continuation file."
#define	ERR_NOCONT	"cannot install from continue file due to error " \
			    "stacking."

#define	ISUMASC_SUFFIX	".isum.asc"
#define	FSASC_SUFFIX	".fs.asc"
#define	IPOASC_SUFFIX	".ipo.asc"
#define	IBIN_SUFFIX	".inst.bin"

#define	MALCOUNT	5	/* package entries to allocate in a block */
#define	PKGNAMESIZE	32	/* package entries to allocate in a block */

extern struct cfextra **extlist;
extern char *pkginst;

static struct cfextra **extptr;
static int	dryrun_mode = 0;
static int	continue_mode = 0;
static int	this_exitcode = 0;

/* The dryrun and continuation filenames */
static char *dryrun_sumasc;
static char *dryrun_fsasc;
static char *dryrun_poasc;
static char *dryrun_bin;
static char *continue_bin;

/* These tell us if the actual files are initialized yet. */
static int dryrun_initialized = 0;
static int continue_initialized = 0;

static int this_type;		/* type of transaction from main.c */

static int pkg_handle = -1;
static int tot_pkgs;

/* Their associated file pointers */
static FILE *fp_dra;
static int fd_drb;
static int fd_cnb;

struct dr_pkg_entry {
	char pkginst[PKGNAMESIZE + 2];
	struct dr_pkg_entry *next;
};

static struct drinfo {
	unsigned partial_set:1;	/* 1 if a partial installation was detected. */
	unsigned partial:1;	/* 1 if a partial installation was detected. */
	unsigned runlevel_set:1;
	unsigned runlevel:1;	/* 1 if runlevel test returned an error. */
	unsigned pkgfiles_set:1;
	unsigned pkgfiles:1;
	unsigned depend_set:1;
	unsigned depend:1;
	unsigned space_set:1;
	unsigned space:1;
	unsigned conflict_set:1;
	unsigned conflict:1;
	unsigned setuid_set:1;
	unsigned setuid:1;
	unsigned priv_set:1;
	unsigned priv:1;
	unsigned pkgdirs_set:1;
	unsigned pkgdirs:1;
	unsigned reqexit_set:1;
	unsigned checkexit_set:1;

	int	type;		/* type of operation */
	int	reqexit;	/* request script exit code */
	int	checkexit;	/* checkinstall script exit code */
	int	exitcode;	/* overall program exit code. */

	struct dr_pkg_entry *packages;	/* pointer to the list of packages */

	int total_ext_recs;	/* total extlist entries */
	int total_fs_recs;	/* total fs_tab entries */
	int total_pkgs;		/* total number of dryrun packages */
	int do_not_continue;	/* error stacking is likely */
} dr_info;

static char	*exitmsg;	/* the last meaningful message printed */

/*
 * In the event that live continue (continue from a dryrun source only)
 * becomes a feature, it will be necessary to keep track of those events such
 * as multiply edited files and files dependent upon multiple class action
 * scripts that will lead to "tolerance stacking". Calling this function
 * states that we've lost the level of precision necessary for a live
 * continue.
 */
void
set_continue_not_ok(void)
{
	dr_info.do_not_continue = 1;
}

int
continue_is_ok(void)
{
	return (!dr_info.do_not_continue);
}

static void
wr_OK(FILE *fp, char *parameter, int set, int value)
{
	(void) fprintf(fp, "%s=%s\n", parameter,
		(set ? (value ? "OK" : "NOT_OK") : "NOT_TESTED"));
}

static void
add_pkg_to_list(char *pkgname)
{
	struct dr_pkg_entry **pkg_entry;

	if (pkg_handle == -1) {
		if ((pkg_handle = bl_create(MALCOUNT,
		    sizeof (struct dr_pkg_entry), "package dryrun")) == -1)
			return;
	}

	pkg_entry = &(dr_info.packages);

	while (*pkg_entry != NULL)
		pkg_entry = &((*pkg_entry)->next);

	/* LINTED pointer cast may result in improper alignment */
	*pkg_entry = (struct dr_pkg_entry *)bl_next_avail(pkg_handle);
	dr_info.total_pkgs++;

	(void) snprintf((*pkg_entry)->pkginst, PKGNAMESIZE, "%s%s",
		(pkgname ? pkgname : ""), ((this_exitcode == 0) ? "" : "-"));
}

static void
write_pkglist_ascii(void)
{
	struct dr_pkg_entry *pkg_entry;

	(void) fprintf(fp_dra, "PKG_LIST=\"");

	pkg_entry = dr_info.packages;
	while (pkg_entry) {
		(void) fprintf(fp_dra, " %s", pkg_entry->pkginst);
		pkg_entry = pkg_entry->next;
	}

	(void) fprintf(fp_dra, "\"\n");
}

static int
write_string(int fd, char *string)
{
	int string_size;

	if (string)
		string_size = strlen(string) + 1;
	else
		string_size = 0;

	if (write(fd, &string_size, sizeof (string_size)) == -1) {
		progerr(gettext(ERR_NOWRITE), dryrun_bin);
		return (0);
	}

	if (string_size > 0) {
		if (write(fd, string, string_size) == -1) {
			progerr(gettext(ERR_NOWRITE), dryrun_bin);
			return (0);
		}
	}

	return (1);
}

static char *
read_string(int fd, char *buffer)
{
	size_t string_size;

	if (read(fd, &(string_size), sizeof (string_size)) == -1) {
		progerr(gettext(ERR_NOREAD), continue_bin);
		return (NULL);
	}

	if (string_size != 0) {
		if (read(fd, buffer, string_size) == -1) {
			progerr(gettext(ERR_NOREAD), continue_bin);
			return (NULL);
		}
	} else {
		return (NULL);
	}

	return (buffer);
}

static void
write_dryrun_ascii()
{
	int n;
	char *fs_mntpt, *src_name;

	if ((fp_dra = fopen(dryrun_sumasc, "wb")) == NULL) {
		progerr(gettext(ERR_NOOPEN), dryrun_sumasc);
		return;
	}

	(void) fprintf(fp_dra, "DR_TYPE=%s\n", (dr_info.type == REMOVE_TYPE ?
	    "REMOVE" : "INSTALL"));

	(void) fprintf(fp_dra, "PKG_INSTALL_ROOT=%s\n", (((get_inst_root()) &&
	    (strcmp(get_inst_root(), "/") != 0)) ?
	    get_inst_root() : ""));

	write_pkglist_ascii();

	wr_OK(fp_dra, "CONTINUE", 1, !(dr_info.do_not_continue));

	wr_OK(fp_dra, "PARTIAL", dr_info.partial_set, dr_info.partial);

	wr_OK(fp_dra, "RUNLEVEL", dr_info.runlevel_set, dr_info.runlevel);

	(void) fprintf(fp_dra, "REQUESTEXITCODE=%d\n", dr_info.reqexit);

	(void) fprintf(fp_dra, "CHECKINSTALLEXITCODE=%d\n", dr_info.checkexit);

	wr_OK(fp_dra, "PKGFILES", dr_info.pkgfiles_set, dr_info.pkgfiles);

	wr_OK(fp_dra, "DEPEND", dr_info.depend_set, dr_info.depend);

	wr_OK(fp_dra, "SPACE", dr_info.space_set, dr_info.space);

	wr_OK(fp_dra, "CONFLICT", dr_info.conflict_set, dr_info.conflict);

	wr_OK(fp_dra, "SETUID", dr_info.setuid_set, dr_info.setuid);

	wr_OK(fp_dra, "PRIV", dr_info.priv_set, dr_info.priv);

	wr_OK(fp_dra, "PKGDIRS", dr_info.pkgdirs_set, dr_info.pkgdirs);

	(void) fprintf(fp_dra, "EXITCODE=%d\n", dr_info.exitcode);

	(void) fprintf(fp_dra, "ERRORMSG=%s\n", (exitmsg ? exitmsg : "NONE"));

	(void) fclose(fp_dra);

	if ((fp_dra = fopen(dryrun_fsasc, "wb")) == NULL) {
		progerr(gettext(ERR_NOOPEN), dryrun_fsasc);
		return;
	}

	(void) fprintf(fp_dra, "%s\nFSUSAGE=\\\n\"\\\n", HDR_FSUSAGE);

	for (n = 0; fs_mntpt = get_fs_name_n(n); n++) {
		int bfree, bused;
		bfree = get_blk_free_n(n);
		bused = get_blk_used_n(n);

		if (bfree || bused) {
			(void) fprintf(fp_dra, "%s %s %s %d %d %lu %lu \\\n",
			    fs_mntpt,
			    ((src_name = get_source_name_n(n)) ?
			    src_name : "none?"),
			    (is_fs_writeable_n(n) ? "TRUE" : "FALSE"),
			    bfree,
			    bused,
			    get_inode_free_n(n),
			    get_inode_used_n(n));
		}
	}

	dr_info.total_fs_recs = n;

	(void) fprintf(fp_dra, "\"\n");

	(void) fclose(fp_dra);

	if ((fp_dra = fopen(dryrun_poasc, "wb")) == NULL) {
		progerr(gettext(ERR_NOOPEN), dryrun_poasc);
		return;
	}

	dr_info.total_ext_recs = 0;

	(void) fprintf(fp_dra, "WOULD_INSTALL=\\\n\"\\\n");

	for (n = 0; extptr && extptr[n]; n++) {
		/*
		 * Write it out if it's a successful change or it is from the
		 * prior dryrun file (meaning it was a change back then).
		 */
		if ((this_exitcode == 0 &&
		    (extptr[n]->mstat.contchg || extptr[n]->mstat.attrchg)) ||
		    extptr[n]->mstat.preloaded) {
			(void) fprintf(fp_dra, "%c %s \\\n",
				extptr[n]->cf_ent.ftype,
				extptr[n]->client_path);

			/* Count it, if it's going into the dryrun file. */
			if (extptr[n]->cf_ent.ftype != 'i')
				dr_info.total_ext_recs++;
		}
	}

	(void) fprintf(fp_dra, "\"\n");

	(void) fclose(fp_dra);
}

/*
 * This writes out a dryrun file.
 */
static void
write_dryrun_bin()
{
	struct fstable *fs_entry;
	struct pinfo *pkginfo;
	struct dr_pkg_entry *pkg_entry;
	int n;
	int fsentry_size = sizeof (struct fstable);
	int extentry_size = sizeof (struct cfextra);
	int pinfoentry_size = sizeof (struct pinfo);

	if ((fd_drb = open(dryrun_bin,
	    O_RDWR | O_APPEND | O_TRUNC)) == -1) {
		progerr(gettext(ERR_NOOPEN), dryrun_bin);
		return;
	}

	/* Write the dryrun info table. */
	if (write(fd_drb, &dr_info, sizeof (struct drinfo)) == -1) {
		progerr(gettext(ERR_NOWRITE), dryrun_bin);
		return;
	}

	/* Write out the package instance list. */
	pkg_entry = dr_info.packages;
	while (pkg_entry) {
		if (write(fd_drb, pkg_entry->pkginst, PKGNAMESIZE) == -1) {
			progerr(gettext(ERR_NOWRITE), dryrun_bin);
			return;
		}
		pkg_entry = pkg_entry->next;
	}

	/* Write out the fstable records. */
	for (n = 0; n < dr_info.total_fs_recs; n++) {
		fs_entry = get_fs_entry(n);

		if (write(fd_drb, fs_entry, fsentry_size) == -1) {
			progerr(gettext(ERR_NOWRITE), dryrun_bin);
			return;
		}

		if (!write_string(fd_drb, fs_entry->name))
			return;

		if (!write_string(fd_drb, fs_entry->fstype))
			return;

		if (!write_string(fd_drb, fs_entry->remote_name))
			return;
	}

	/* Write out the package objects and their attributes. */
	for (n = 0; extptr && extptr[n]; n++) {
		/* Don't save metafiles. */
		if (extptr[n]->cf_ent.ftype == 'i')
			continue;

		/*
		 * If it's a new package object (not left over from the
		 * continuation file) and it indicates no changes to the
		 * system, skip it. Only files that will change the system
		 * are stored.
		 */
		if (extptr[n]->mstat.preloaded == 0 &&
		    !(this_exitcode == 0 &&
		    (extptr[n]->mstat.contchg || extptr[n]->mstat.attrchg)))
			continue;

		if (write(fd_drb, extptr[n], extentry_size) == -1) {
			progerr(gettext(ERR_NOWRITE), dryrun_bin);
			return;
		}

		if (!write_string(fd_drb, extptr[n]->cf_ent.path))
			return;

		if (!write_string(fd_drb, extptr[n]->cf_ent.ainfo.local))
			return;

		extptr[n]->cf_ent.pinfo = eptstat(&(extptr[n]->cf_ent),
		    pkginst, CONFIRM_CONT);

		/*
		 * Now all of the entries about the various packages that own
		 * this entry.
		 */
		pkginfo = extptr[n]->cf_ent.pinfo;

		do {
			if (write(fd_drb, pkginfo,
			    pinfoentry_size) == -1) {
				progerr(gettext(ERR_NOWRITE), dryrun_bin);
				return;
			}
			pkginfo = pkginfo->next;	/* May be several */
		} while (pkginfo);
	}

	(void) close(fd_drb);
}

static void
init_drinfo(void) {

	if (dr_info.partial != 0)
		dr_info.partial_set = 0;

	if (dr_info.runlevel != 0)
		dr_info.runlevel_set = 0;

	if (dr_info.pkgfiles != 0)
		dr_info.pkgfiles_set = 0;

	if (dr_info.depend != 0)
		dr_info.depend_set = 0;

	if (dr_info.space != 0)
		dr_info.space_set = 0;

	if (dr_info.conflict != 0)
		dr_info.conflict_set = 0;

	if (dr_info.setuid != 0)
		dr_info.setuid_set = 0;

	if (dr_info.priv != 0)
		dr_info.priv_set = 0;

	if (dr_info.pkgdirs != 0)
		dr_info.pkgdirs_set = 0;

	if (dr_info.reqexit == 0)
		dr_info.reqexit_set = 0;

	if (dr_info.checkexit == 0)
		dr_info.checkexit_set = 0;

	dr_info.packages = NULL;
	tot_pkgs = dr_info.total_pkgs;
	dr_info.total_pkgs = 0;
}

/*
 * This function reads in the various continuation file data in order to seed
 * the internal data structures.
 */
static boolean_t
read_continue_bin(void)
{
	int n;
	int fsentry_size = sizeof (struct fstable);
	int extentry_size = sizeof (struct cfextra);
	int pinfoentry_size = sizeof (struct pinfo);

	pkgobjinit();
	if (!init_pkgobjspace())
		return (B_FALSE);

	if ((fd_cnb = open(continue_bin, O_RDONLY)) == -1) {
		progerr(gettext(ERR_NOOPEN), continue_bin);
		return (B_FALSE);
	}

	/* Read the dryrun info structure. */
	if (read(fd_cnb, &dr_info, sizeof (struct drinfo)) == -1) {
		progerr(gettext(ERR_NOREAD), continue_bin);
		return (B_FALSE);
	}

	init_drinfo();

	if (this_type != dr_info.type) {
		progerr(gettext(ERR_BADTYPE),
		    (this_type == REMOVE_TYPE) ?
		    "a remove" : "an install",
		    (dr_info.type == REMOVE_TYPE) ?
		    "a remove" : "an install");
		return (B_FALSE);
	}

	/* Read in the dryrun package records. */
	for (n = 0; n < tot_pkgs; n++) {
		char pkg_name[PKGNAMESIZE];

		if (read(fd_cnb, &pkg_name, PKGNAMESIZE) == -1) {
			progerr(gettext(ERR_NOREAD), continue_bin);
			return (B_FALSE);
		}

		add_pkg_to_list(pkg_name);
	}

	/* Read in the fstable records. */
	for (n = 0; n < dr_info.total_fs_recs; n++) {
		struct fstable fs_entry;
		char name[PATH_MAX], remote_name[PATH_MAX];
		char fstype[200];

		if (read(fd_cnb, &fs_entry, fsentry_size) == -1) {
			progerr(gettext(ERR_NOREAD), continue_bin);
			return (B_FALSE);
		}

		if (read_string(fd_cnb, &name[0]) == NULL)
			return (B_FALSE);

		if (read_string(fd_cnb, &fstype[0]) == NULL)
			return (B_FALSE);

		if (read_string(fd_cnb, &remote_name[0]) == NULL)
			return (B_FALSE);

		if (load_fsentry(&fs_entry, name, fstype, remote_name)) {
			progerr(gettext(ERR_FSFAIL));
			return (B_FALSE);
		}
	}

	/* Read in the package objects and their attributes. */
	for (n = 0; n < dr_info.total_ext_recs; n++) {
		struct cfextra ext_entry;
		struct pinfo pinfo_area, *pinfo_ptr;
		char path[PATH_MAX], local[PATH_MAX], *local_ptr;

		if (read(fd_cnb, &ext_entry, extentry_size) == -1) {
			progerr(gettext(ERR_NOREAD), continue_bin);
			return (B_FALSE);
		}

		/*
		 * If the previous dryrun replaced a directory with a
		 * non-directory and we're going into *another* dryrun, we're
		 * stacking errors and continuation should not be permitted.
		 */
		if (ext_entry.mstat.dir2nondir && dryrun_mode)
			dr_info.do_not_continue = 1;

		/*
		 * Since we just read this from a continuation file; it is,
		 * by definition, preloaded.
		 */
		ext_entry.mstat.preloaded = 1;

		if (read_string(fd_cnb, &path[0]) == NULL)
			return (B_FALSE);

		local_ptr = read_string(fd_cnb, &local[0]);

		ext_entry.cf_ent.pinfo = NULL;

		/*
		 * Now all of the entries about the various packages that own
		 * this entry.
		 */
		do {
			if (read(fd_cnb, &pinfo_area, pinfoentry_size) == -1) {
				progerr(gettext(ERR_NOREAD), continue_bin);
				return (B_FALSE);

			}

			pinfo_ptr = eptstat(&(ext_entry.cf_ent),
			    pinfo_area.pkg, CONFIRM_CONT);

			if (pinfo_ptr->next) {
				pinfo_ptr = pinfo_ptr->next;
			} else {
				pinfo_ptr = NULL;
			}

		} while (pinfo_ptr);

		seed_pkgobjmap(&ext_entry, path, local_ptr);
	}

	(void) close(fd_cnb);

	/*
	 * Return as reading is done, so pkginstall doesn't
	 * read the same info from the system.
	 */

	return (B_TRUE);
}

int
in_dryrun_mode(void)
{
	return (dryrun_mode);
}

void
set_dryrun_mode(void)
{
	dryrun_mode = 1;
}

int
in_continue_mode(void)
{
	return (continue_mode);
}

void
set_continue_mode(void)
{
	continue_mode = 1;
}

/*
 * Initialize a dryrun file by assigning it a name and creating it
 * empty.
 */
static int
init_drfile(char **targ_ptr, char *path)
{
	int n;
	char *targ_file;

	*targ_ptr = strdup(path);
	targ_file = *targ_ptr;

	if (access(targ_file, W_OK) == 0) {
		(void) unlink(targ_file);
	}

	n = open(targ_file, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, 0644);
	if (n < 0) {
		progerr(gettext(ERR_NOCREAT), targ_file);
		return (0);
	} else {
		(void) close(n);
	}

	return (1);
}

/*
 * Initialize all required dryrun files and see that the target directory is
 * present. If all goes well, we're in dryrun mode. If it doesn't, we're not.
 */
void
init_dryrunfile(char *dr_dir)
{
	char temp_path[PATH_MAX];
	char *dot_pos = (temp_path+strlen(dr_dir)+7);

	/* First create or confirm the directory. */
	if (isdir(dr_dir) != 0) {
		(void) mkpath(dr_dir);
	}

	(void) snprintf(temp_path, sizeof (temp_path), "%s/dryrun", dr_dir);

	(void) strcpy(dot_pos, ISUMASC_SUFFIX);

	if (!init_drfile(&dryrun_sumasc, temp_path))
		return;

	(void) strcpy(dot_pos, FSASC_SUFFIX);

	if (!init_drfile(&dryrun_fsasc, temp_path))
		return;

	(void) strcpy(dot_pos, IPOASC_SUFFIX);

	if (!init_drfile(&dryrun_poasc, temp_path))
		return;

	(void) strcpy(dot_pos, IBIN_SUFFIX);

	if (!init_drfile(&dryrun_bin, temp_path))
		return;

	dryrun_initialized = 1;
}

void
init_contfile(char *cn_dir)
{
	char temp_path[PATH_MAX];

	/* First confirm the directory. */
	if (isdir(cn_dir) != 0)
		return;		/* no continuation directory */

	(void) snprintf(temp_path, sizeof (temp_path),
				"%s/dryrun%s", cn_dir, IBIN_SUFFIX);
	continue_bin = strdup(temp_path);

	if (access(continue_bin, W_OK) != 0) {
		free(continue_bin);
		return;
	}

	continue_initialized = 1;
}

void
set_dr_exitmsg(char *value)
{
	exitmsg = value;
}

void
set_dr_info(int type, int value)
{
	switch (type) {
	    case PARTIAL:
		if (dr_info.partial_set == 0) {
			dr_info.partial_set = 1;
			dr_info.partial = (value ? 1 : 0);
		}
		break;

	    case RUNLEVEL:
		if (dr_info.runlevel_set == 0) {
			dr_info.runlevel_set = 1;
			dr_info.runlevel = (value ? 1 : 0);
		}
		break;

	    case PKGFILES:
		if (dr_info.pkgfiles_set == 0) {
			dr_info.pkgfiles_set = 1;
			dr_info.pkgfiles = (value ? 1 : 0);
		}
		break;

	    case DEPEND:
		if (dr_info.depend_set == 0) {
			dr_info.depend_set = 1;
			dr_info.depend = (value ? 1 : 0);
		}
		break;

	    case SPACE:
		if (dr_info.space_set == 0) {
			dr_info.space_set = 1;
			dr_info.space = (value ? 1 : 0);
		}
		break;

	    case CONFLICT:
		if (dr_info.conflict_set == 0) {
			dr_info.conflict_set = 1;
			dr_info.conflict = (value ? 1 : 0);
		}
		break;

	    case SETUID:
		if (dr_info.setuid_set == 0) {
			dr_info.setuid_set = 1;
			dr_info.setuid = (value ? 1 : 0);
		}
		break;

	    case PRIV:
		if (dr_info.priv_set == 0) {
			dr_info.priv_set = 1;
			dr_info.priv = (value ? 1 : 0);
		}

		break;

	    case PKGDIRS:
		if (dr_info.pkgdirs_set == 0) {
			dr_info.pkgdirs_set = 1;
			dr_info.pkgdirs = (value ? 1 : 0);
		}

		break;

	    case REQUESTEXITCODE:
		if (dr_info.reqexit_set == 0) {
			dr_info.reqexit_set = 1;
			dr_info.reqexit = value;
		}

		break;

	    case CHECKEXITCODE:
		if (dr_info.checkexit_set == 0) {
			dr_info.checkexit_set = 1;
			dr_info.checkexit = value;
		}

		break;

	    case EXITCODE:
		if (dr_info.exitcode == 0) {
			dr_info.exitcode = value;
		}

		this_exitcode = value;

		break;

	    /* default to install if the value is kookie. */
	    case DR_TYPE:
		if (value == REMOVE_TYPE)
			this_type = REMOVE_TYPE;
		else
			this_type = INSTALL_TYPE;

		break;
	}
}

void
write_dryrun_file(struct cfextra **extlist)
{
	extptr = extlist;

	if (dryrun_initialized) {
		dr_info.type = this_type;

		add_pkg_to_list(pkginst);
		write_dryrun_ascii();
		write_dryrun_bin();

		if (dryrun_mode) {
			free(dryrun_sumasc);
			free(dryrun_fsasc);
			free(dryrun_poasc);
			free(dryrun_bin);
		}
	}
}

/*
 * Name:		read_continuation
 * Description:		If continuation is initialised, reads the
 *			continuation binary file. The path for the
 *			same is freed, if set,  as this is the last
 *			chance to do so.
 * Sets:		Error condition, through the pointer passed
 *			if read failed.
 * Returns:		B_TRUE - if the continuation binary file
 *			from previous dryrun is read successfully.
 *			B_FALSE - if either continuation is not initialised
 *			or read was not successful.
 */
boolean_t
read_continuation(int *error)
{
	boolean_t ret = B_FALSE;
	*error = 0;
	if (continue_initialized) {
		if (!read_continue_bin()) {
			continue_mode = 0;
			free(continue_bin);
			*error = -1;
			return (ret);
		}

		if (continue_mode) {
			free(continue_bin);
		}
		ret = B_TRUE;
	}
	return (ret);
}
