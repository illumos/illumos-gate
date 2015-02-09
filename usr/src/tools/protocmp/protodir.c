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

#include <stdio.h>
#include <sys/param.h>
#include <fcntl.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

#include "list.h"
#include "protodir.h"
#include "arch.h"
#include "exception_list.h"

#define	FS	" \t\n"

static char *
resolve_relative(const char *source, const char *link)
{
	char	*p;
	char	*l_next;
	char	*l_pos;
	static char	curpath[MAXPATHLEN];

	/* if absolute path - no relocation required */
	if (link[0] == '/')
		return (strcpy(curpath, link));

	(void) strcpy(curpath, source);
	p = rindex(curpath, '/');
	*p = '\0';
	l_pos = (char *)link;
	do {
		l_next = index(l_pos, '/');
		if (strncmp(l_pos, "../", 3) == 0) {
			if ((p = rindex(curpath, '/')) != NULL)
				*p = '\0';
			else
				curpath[0] = '\0';
		} else if (strncmp(l_pos, "./", 2)) {
			/* if not . then we process */
			if (curpath[0])
				(void) strcat(curpath, "/");
			if (l_next) {
				(void) strncat(curpath, l_pos,
				    (l_next - l_pos));
			} else
				(void) strcat(curpath, l_pos);
		}
		l_pos = l_next + 1;
	} while (l_next);

	return (curpath);
}


static int
parse_proto_line(const char *basedir, char *line, elem_list *list, short arch,
    const char *pkgname)
{
	char	*type, *class, *file, *src, *maj, *min, *perm, *owner, *group;
	char	p_line[BUFSIZ];
	elem	*dup;
	static elem *e = NULL;

	(void) strcpy(p_line, line);
	if (!e)
		e = (elem *)calloc(1, sizeof (elem));

	e->flag = 0;

	if (!(type  = strtok(p_line, FS))) {
		(void) fprintf(stderr, "error: bad line(type) : %s\n", line);
		return (-1);
	}

	e->file_type = type[0];

	if ((class = strtok(NULL, FS)) == NULL) {
		(void) fprintf(stderr, "error: bad line(class) : %s\n", line);
		return (-1);
	}

	/*
	 * Just ignore 'legacy' entries.  These are not present in the proto
	 * area at all.  They're phantoms.
	 */
	if (strcmp(class, "legacy") == 0)
		return (0);

	if (!(file  = strtok(NULL, FS))) {
		(void) fprintf(stderr, "error: bad line(file_name) : %s\n",
		    line);
		return (-1);
	}

	e->symsrc = NULL;
	if ((src = index(file, '=')) != NULL) {
		/*
		 * The '=' operator is subtly different for link and non-link
		 * entries.  For the hard or soft link case, the left hand side
		 * exists in the proto area and is created by the package.
		 *
		 * When the file is an editable file, it's very likely that the
		 * right hand side is only a fragment of that file, which is
		 * delivered by multiple packages in the consolidation.  Thus it
		 * can't exist in the proto area, and because we can't really
		 * know where the file's root directory is, we should skip the
		 * file.
		 *
		 * For all other filetypes, assume the right hand side is in the
		 * proto area.
		 */
		if (e->file_type == SYM_LINK_T || e->file_type == LINK_T) {
			*src++ = '\0';
			e->symsrc = strdup(src);
		} else if (e->file_type == EDIT_T) {
			return (0);
		} else {
			file = src + 1;
		}
	}

	/*
	 * if a basedir has a value, prepend it to the filename
	 */
	if (basedir[0])
		(void) strcat(strcat(strcpy(e->name, basedir), "/"), file);
	else
		(void) strcpy(e->name, file);

	if (e->file_type != SYM_LINK_T) {
		if ((e->file_type == CHAR_DEV_T) ||
		    (e->file_type == BLOCK_DEV_T)) {
			if (!(maj = strtok(NULL, FS))) {
				(void) fprintf(stderr,
				    "error: bad line(major number) : %s\n",
				    line);
				return (-1);
			}
			e->major = atoi(maj);

			if (!(min = strtok(NULL, FS))) {
				(void) fprintf(stderr,
				    "error: bad line(minor number) : %s\n",
				    line);
				return (-1);
			}
			e->minor = atoi(min);
		} else {
			e->major = -1;
			e->minor = -1;
		}

		if (!(perm = strtok(NULL, FS))) {
			(void) fprintf(stderr,
			    "error: bad line(permission) : %s\n", line);
			return (-1);
		}
		e->perm = strtol(perm, NULL, 8);

		if (!(owner = strtok(NULL, FS))) {
			(void) fprintf(stderr,
			    "error: bad line(owner) : %s\n", line);
			return (-1);
		}
		(void) strcpy(e->owner, owner);

		if (!(group = strtok(NULL, FS))) {
			(void) fprintf(stderr,
			    "error: bad line(group) : %s\n", line);
			return (-1);
		}
		(void) strcpy(e->group, group);
	}

	e->inode = 0;
	e->ref_cnt = 1;
	e->arch = arch;
	e->link_parent = NULL;

	if (!(dup = find_elem(list, e, FOLLOW_LINK))) {
		e->pkgs = add_pkg(NULL, pkgname); /* init pkgs list */
		add_elem(list, e);
		e = NULL;
		return (1);
	} else if (dup->file_type == DIR_T) {
		if (!(dup->pkgs = add_pkg(dup->pkgs, pkgname))) {
			/* add entry to pkgs */
			(void) fprintf(stderr,
			    "warning: %s: Duplicate entry for %s\n",
			    pkgname, dup->name);
			return (-1);
		}
		if (e->perm != dup->perm) {
			(void) fprintf(stderr,
			    "warning: %s: permissions %#o of %s do not match "
			    "previous permissions %#o\n",
			    pkgname, e->perm, dup->name, dup->perm);
		}
		if (strcmp(e->owner, dup->owner) != 0) {
			(void) fprintf(stderr,
			    "warning: %s: owner \"%s\" of %s does not match "
			    "previous owner \"%s\"\n",
			    pkgname, e->owner, dup->name, dup->owner);
		}
		if (strcmp(e->group, dup->group) != 0) {
			(void) fprintf(stderr,
			    "warning: %s: group \"%s\" of %s does not match "
			    "previous group \"%s\"\n",
			    pkgname, e->group, dup->name, dup->group);
		}
	} else {
		/*
		 * Signal an error only if this is something that's not on the
		 * exception list.
		 */
		(void) strcpy(e->name, file);
		if (find_elem(&exception_list, e, FOLLOW_LINK) == NULL) {
			(void) fprintf(stderr,
			    "warning: %s: duplicate entry for %s - ignored\n",
			    pkgname, e->name);
			return (-1);
		}
	}

	return (0);
}

static int
parse_proto_link(const char *basedir, char *line, elem_list *list, short arch,
    const char *pkgname)
{
	char	*type, *file, *src;
	char	p_line[BUFSIZ];
	elem	*p, *dup;
	elem	key;
	static elem	*e = NULL;


	(void) strcpy(p_line, line);
	if (!e)
		e = (elem *)calloc(1, sizeof (elem));

	e->flag = 0;
	type = strtok(p_line, FS);
	e->arch = arch;

	e->file_type = type[0];
	(void) strtok(NULL, FS);   /* burn class */

	file = strtok(NULL, FS);
	if ((src = index(file, '=')) != NULL) {
		*src++ = '\0';
		e->symsrc = strdup(src);
	} else {
		(void) fprintf(stderr,
		    "error: %s: hard link does not have destination (%s)\n",
		    pkgname, file);
		return (0);
	}

	/*
	 * if a basedir has a value, prepend it to the filename
	 */
	if (basedir[0])
		(void) strcat(strcat(strcpy(e->name, basedir), "/"), file);
	else
		(void) strcpy(e->name, file);

	/*
	 * now we need to find the file that we link to - to do this
	 * we build a key.
	 */

	src = resolve_relative(e->name, e->symsrc);
	(void) strcpy(key.name, src);
	key.arch = e->arch;
	if ((p = find_elem(list, &key, NO_FOLLOW_LINK)) == NULL) {
		(void) fprintf(stderr,
		    "error: %s: hardlink to non-existent file: %s=%s\n",
		    pkgname, e->name, e->symsrc);
		return (0);
	}
	if ((p->file_type == SYM_LINK_T) || (p->file_type == LINK_T)) {
		(void) fprintf(stderr,
		    "error: %s: hardlink must link to a file or directory "
		    "(not other links): %s=%s\n", pkgname, e->name, p->name);
		return (0);
	}
	e->link_parent = p;
	e->link_sib = p->link_sib;
	p->link_sib = e;
	p->ref_cnt++;
	e->inode = p->inode;
	e->perm = p->perm;
	e->ref_cnt = p->ref_cnt;
	e->major = p->major;
	e->minor = p->minor;
	(void) strcpy(e->owner, p->owner);
	(void) strcpy(e->group, p->owner);

	if (!(dup = find_elem(list, e, NO_FOLLOW_LINK))) {
		e->pkgs = add_pkg(NULL, pkgname); /* init pkgs list */
		e->link_sib = NULL;
		add_elem(list, e);
		e = NULL;
		return (1);
	} else {
		/*
		 * Signal an error only if this is something that's not on the
		 * exception list.
		 */
		(void) strcpy(e->name, file);
		if (find_elem(&exception_list, e, FOLLOW_LINK) == NULL) {
			(void) fprintf(stderr,
			    "warning: %s: duplicate entry for %s - ignored\n",
			    pkgname, e->name);
			return (-1);
		}
	}

	return (0);
}


/*
 * open up the pkginfo file and find the ARCH= and the BASEDIR= macros.
 * I will set the arch and basedir variables based on these fields.
 */
static void
read_pkginfo(const char *protodir, short *arch, char *basedir)
{
	char	pkginfofile[MAXPATHLEN];
	char	architecture[MAXPATHLEN];
	char	buf[BUFSIZ];
	FILE	*pkginfo_fp;
	int	hits = 0;
	int	i;
	int	index;


	architecture[0] = '\0';
	basedir[0] = '\0';
	*arch = P_ISA;

	/*
	 * determine whether the pkginfo file is a pkginfo.tmpl or
	 * a pkginfo file
	 */
	(void) strcat(strcat(strcpy(pkginfofile, protodir), "/"),
	    "pkginfo.tmpl");

	if ((pkginfo_fp = fopen(pkginfofile, "r")) == NULL) {
		(void) strcat(strcat(strcpy(pkginfofile, protodir), "/"),
		    "pkginfo");
		if ((pkginfo_fp = fopen(pkginfofile, "r")) == NULL) {
			perror(pkginfofile);
			return;
		}
	}


	while (fgets(buf, BUFSIZ, pkginfo_fp) && (hits != 3)) {
		if (strncmp(buf, "ARCH=", 5) == 0) {
			index = 0;
			/*
			 * remove any '"' in the ARCH field.
			 */
			for (i = 5; buf[i]; i++) {
				if (buf[i] != '"')
					architecture[index++] = buf[i];
			}
			/* -1 because above copy included '\n' */
			architecture[index-1] = '\0';
			hits += 1;
		} else if (strncmp(buf, "BASEDIR=", 8) == 0) {
			index = 0;
			/*
			 * remove any '"' in the BASEDIR field, and
			 * strip off a leading '/' if present.
			 */
			for (i = 8; buf[i]; i++) {
				if (buf[i] != '"' &&
				    (buf[i] != '/' || index != 0)) {
					buf[index++] = buf[i];
				}
			}
			/* -1 because above copy included '\n' */
			buf[index-1] = '\0';
			(void) strcpy(basedir, &buf[0]);
			hits += 2;
		}
	}
	(void) fclose(pkginfo_fp);

	if (architecture[0])
		if ((*arch = assign_arch(architecture)) == 0) {
			(void) fprintf(stderr,
			    "warning: Unknown architecture %s found in %s\n",
			    architecture, pkginfofile);
		}
}

/*
 * The first pass through the prototype file goes through and reads
 * in all the entries except 'hard links'.  Those must be processed
 * in a second pass.
 *
 * If any !includes are found in the prototype file this routine
 * will be called recursively.
 *
 * Args:
 *   protofile - full pathname to prototype file to be processed.
 *   protodir  - directory in which prototype file resides.
 *   list      - list to which elements will be added
 *   arch      - architecture of current prototype
 *   basedir   - basedir for package
 *   pkgname   - name of package
 *
 * Returns:
 *   returns number of items added to list.
 *
 */
static int
first_pass_prototype(const char *protofile, const char *protodir,
    elem_list *list, short arch, const char *basedir, const char *pkgname)
{
	int	elem_count = 0;
	FILE	*proto_fp;
	char	include_file[MAXPATHLEN];
	char	buf[BUFSIZ];

	if ((proto_fp = fopen(protofile, "r")) == NULL) {
		perror(protofile);
		return (0);
	}

	/*
	 * first pass through file - process everything but
	 * hard links.
	 */
	while (fgets(buf, BUFSIZ, proto_fp)) {
		int	rc;

		switch (buf[0]) {
		case FILE_T:
		case EDIT_T:
		case VOLATILE_T:
		case DIR_T:
		case SYM_LINK_T:
		case CHAR_DEV_T:
		case BLOCK_DEV_T:
			if ((rc = parse_proto_line(basedir, buf, list, arch,
			    pkgname)) >= 0) {
				elem_count += rc;
			} else {
				(void) fprintf(stderr,
				    "error: Errors found in %s\n", protofile);
			}
			break;
		case LINK_T:
		case 'i':
		case '#':
		case '\n':
			break;
		case '!':
			/* Is this an include statement - if so process */
			if (strncmp(buf, "!include", 8) == 0) {
				char *inc_file = (char *)(buf + 9);

				/* burn white space */
				while ((*inc_file == ' ') ||
				    (*inc_file == '\t'))
					inc_file++;
				if (*inc_file) {
					/* remove trailing \n */
					inc_file[strlen(inc_file) - 1] = '\0';
					(void) strcat(strcat(strcpy(
					    include_file, protodir), "/"),
					    inc_file);
					elem_count +=
					    first_pass_prototype(include_file,
					    protodir, list, arch, basedir,
					    pkgname);
				} else {
					(void) fprintf(stderr,
					    "warning: bad !include statement "
					    "in prototype %s : %s\n",
					    protofile, buf);
				}
			} else {
				(void) fprintf(stderr,
				    "warning: unexpected ! notation in "
				    "prototype %s : %s\n", protofile, buf);

			}
			break;
		default:
			(void) fprintf(stderr,
			    "warning: unexpected line in prototype %s : %s\n",
			    protofile, buf);
			break;
		}
	}

	(void) fclose(proto_fp);

	return (elem_count);
}

/*
 * The second pass through the prototype file goes through and reads
 * and processes only the 'hard links' in the prototype file.  These
 * are resolved and added accordingly to the elements list(list).
 *
 * If any !includes are found in the prototype file this routine
 * will be called recursively.
 *
 * Args:
 *   protofile - full pathname to prototype file to be processed.
 *   protodir  - directory in which prototype file resides.
 *   list      - list to which elements will be added
 *   arch      - architecture of current prototype
 *   basedir   - basedir for package
 *   pkgname   - package name
 *
 * Returns:
 *   returns number of items added to list.
 *
 */
static int
second_pass_prototype(const char *protofile, const char *protodir,
    elem_list *list, short arch, const char *basedir, const char *pkgname)
{
	FILE	*proto_fp;
	int	elem_count = 0;
	char	include_file[MAXPATHLEN];
	char	buf[BUFSIZ];

	if ((proto_fp = fopen(protofile, "r")) == NULL) {
		perror(protofile);
		return (0);
	}

	/*
	 * second pass through prototype file - process the hard links
	 * now.
	 */
	while (fgets(buf, BUFSIZ, proto_fp))
		if (buf[0] == LINK_T) {
			int	rc;

			if ((rc = parse_proto_link(basedir, buf, list, arch,
			    pkgname)) >= 0) {
				elem_count += rc;
			} else {
				(void) fprintf(stderr,
				    "error: Errors found in %s\n", protofile);
			}
		} else if (strncmp(buf, "!include", 8) == 0) {
			/*
			 * This is a file to include
			 */
			char *inc_file = (char *)(buf + 9);

			/* burn white space */
			while ((*inc_file == ' ') || (*inc_file == '\t'))
				inc_file++;

			if (*inc_file) {
				/* remove trailing \n */
				inc_file[strlen(inc_file) - 1] = '\0';
				/* build up include file name to be opened. */
				(void) strcat(strcat(strcpy(include_file,
				    protodir), "/"), inc_file);
				/*
				 * recursively call this routine to process the
				 * !include file.
				 */
				elem_count +=
				    second_pass_prototype(include_file,
				    protodir, list, arch, basedir, pkgname);
			} else {
				(void) fprintf(stderr,
				    "warning: Bad !include statement in "
				    "prototype %s : %s\n", protofile, buf);
			}
		}

		(void) fclose(proto_fp);

		return (elem_count);
}

/*
 * Args:
 *    pkgname  - name of package being processed
 *    protodir - pathname to package defs directory
 *    list     - List of elements read in, elements are added to this
 *		 as they are read in.
 *    verbose  - verbose output
 *
 * Returns:
 *    number of elements added to list
 */
int
process_package_dir(const char *pkgname, const char *protodir,
    elem_list *list, int verbose)
{
	struct stat	st_buf;
	char		protofile[MAXPATHLEN];
	char		basedir[MAXPATHLEN];
	short		arch;
	int		count = 0;


	/*
	 * skip any packages we've already handled (because of
	 * dependencies)
	 */
	if (processed_package(pkgname)) {
		return (0);
	}

	/*
	 * find the prototype file.  Legal forms of the name are:
	 *		prototype
	 *		prototype_<mach> (where mach == (sparc || i386 || ppc)
	 */
	(void) strcat(strcat(strcpy(protofile, protodir), "/"), "prototype");
	if (stat(protofile, &st_buf) < 0) {
		if (errno == ENOENT) {
			(void) strcat(strcat(strcat(strcpy(protofile,
			    protodir), "/"), "prototype"), PROTO_EXT);
			if (stat(protofile, &st_buf) < 0) {
				if (errno == ENOENT) {
					if (verbose) {
						(void) fprintf(stderr,
						    "warning: no prototype "
						    "file found in %s, "
						    "skipping...\n",
						    protodir);
					}
				} else
					perror(protofile);
				return (0);
			}
		} else {
			perror(protofile);
			return (0);
		}
	}

	mark_processed(pkgname);

	read_pkginfo(protodir, &arch, basedir);

	count += first_pass_prototype(protofile, protodir, list, arch,
	    basedir, pkgname);
	count += second_pass_prototype(protofile, protodir, list, arch,
	    basedir, pkgname);

	/* print_list(list); */
	return (count);
}

int
read_in_protodir(const char *dir_name, elem_list *list, int verbose)
{
	DIR		*p_dir;
	struct dirent	*dp;
	char		protodir[MAXPATHLEN];
	struct stat	st_buf;
	int		count = 0;

	if ((p_dir = opendir(dir_name)) == NULL) {
		perror(dir_name);
		exit(1);
	}

	list->type = PROTODIR_LIST;

	while ((dp = readdir(p_dir)) != NULL) {
		/*
		 * let's not check "." and ".." - I don't really like this
		 * but I wasn't really sure you could be sure that they
		 * are always the first two entries in the directory
		 * structure  - so I put it in the loop.
		 *
		 * Also - we skip all directories that are names .del-*.
		 * and any SCCS directories too.
		 */
		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0) ||
		    (strncmp(dp->d_name, ".del-", 5) == 0) ||
		    (strcmp(dp->d_name, "SCCS") == 0))
			continue;

		(void) strcat(strcat(strcpy(protodir, dir_name), "/"),
		    dp->d_name);
		if (stat(protodir, &st_buf) < 0) {
			perror(protodir);
			continue;
		}
		if (!S_ISDIR(st_buf.st_mode)) {
			if (verbose) {
				(void) fprintf(stderr,
				    "warning: %s not a directory\n", protodir);
			}
			continue;
		}

		count += process_dependencies(dp->d_name, dir_name, list,
		    verbose);

		count += process_package_dir(dp->d_name, protodir, list,
		    verbose);
	}

	if (verbose)
		(void) printf("read in %d lines\n", count);

	(void) closedir(p_dir);

	return (count);
}
