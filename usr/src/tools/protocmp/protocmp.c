/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/param.h>
#include <errno.h>
#include <unistd.h>
#include <ftw.h>

#include "list.h"
#include "protocmp.h"
#include "proto_list.h"
#include "protodir.h"
#include "exception_list.h"
#include "stdusers.h"

#define	MAX_PROTO_REFS			5
#define	MAX_EXCEPTION_FILES		5
#define	MAX_DEPTH			50

/*
 * default flag values
 */
static int check_group = 1;
static int set_group = 0;
static int check_user = 1;
static int set_user = 0;
static int check_perm = 1;
static int set_perm = 0;
static int check_link = 1;
static int check_sym = 1;
static int check_majmin = 1;

static elem_list first_list;
static char *first_file_name;

static elem_list second_list;
static char *second_file_name;

static FILE *need_add_fp;
static char *need_add_file;
static FILE *need_rm_fp;
static char *need_rm_file;
static FILE *differ_fp;
static char *differ_file;

static char *myname;

/*
 * default flag values
 */
static int verbose = 0;

static void
usage(void)
{
	(void) fputs("usage: protocmp [-gupGUPlmsLv] "
	    "[-e <exception-list> ...] "
	    "-d <protolist|pkg dir>\n\t[-d <protolist|pkg dir> ...] "
	    "[<protolist|pkg dir>...]|<root>]\n",
	    stderr);
	(void) fputs("   where:\n", stderr);
	(void) fputs("\t-g       : don't compare group\n", stderr);
	(void) fputs("\t-u       : don't compare owner\n", stderr);
	(void) fputs("\t-p       : don't compare permissions\n", stderr);
	(void) fputs("\t-G       : set group\n", stderr);
	(void) fputs("\t-U       : set owner\n", stderr);
	(void) fputs("\t-P       : set permissions\n", stderr);
	(void) fputs("\t-l       : don't compare link counts\n", stderr);
	(void) fputs("\t-m       : don't compare major/minor numbers\n",
	    stderr);
	(void) fputs("\t-s       : don't compare symlink values\n", stderr);
	(void) fputs("\t-d <protolist|pkg dir>:\n", stderr);
	(void) fputs("\t           proto list or packaging to check\n", stderr);
	(void) fputs("\t-e <file>: exceptions file\n", stderr);
	(void) fputs("\t-L       : list filtered exceptions\n", stderr);
	(void) fputs("\t-v       : verbose output\n", stderr);
	(void) fputs("\n"
"If any of the -[GUP] flags are given, then the final argument must be the\n"
"proto root directory itself on which to set permissions according to the\n"
"packaging data specified via -d options.\n", stderr);
}


static void
open_output_files(void)
{
	if ((need_add_fp =
	    fopen((need_add_file = tempnam(NULL, "add")), "w")) == NULL) {
		perror(need_add_file);
		exit(1);
	}

	if ((need_rm_fp =
	    fopen((need_rm_file = tempnam(NULL, "rm")), "w")) == NULL) {
		perror(need_rm_file);
		exit(1);
	}

	if ((differ_fp =
	    fopen((differ_file = tempnam(NULL, "diff")), "w")) == NULL) {
		perror(differ_file);
		exit(1);
	}
}

static void
close_output_files(void)
{
	(void) fclose(need_add_fp);
	(void) fclose(need_rm_fp);
	(void) fclose(differ_fp);
}

static void
print_file(char *file)
{
	FILE	*fp;
	int	count;
	char	buff[BUF_SIZE];

	if ((fp = fopen(file, "r")) == NULL) {
		perror(need_add_file);
	}

	while (count = fread(buff, sizeof (char), BUF_SIZE, fp))
		(void) fwrite(buff, sizeof (char), count, stdout);
	(void) fclose(fp);
}

static void
print_header(void)
{
	(void) printf("%c %-30s %-20s %-4s %-5s %-5s %-5s %-2s %2s %2s %-9s\n",
	    'T', "File Name", "Reloc/Sym name", "perm", "owner", "group",
	    "inode", "lnk", "maj", "min", "package(s)");
	(void) puts("-------------------------------------------------------"
	    "-----------------------------------------------------");
}

static void
print_results(void)
{
	(void) puts("*******************************************************");
	(void) puts("*");
	(void) printf("* Entries found in %s, but not found in %s\n",
	    first_file_name, second_file_name);
	(void) puts("*");
	(void) puts("*******************************************************");
	print_header();
	print_file(need_add_file);
	(void) puts("*******************************************************");
	(void) puts("*");
	(void) printf("* Entries found in %s, but not found in %s\n",
	    second_file_name, first_file_name);
	(void) puts("*");
	(void) puts("*******************************************************");
	print_header();
	print_file(need_rm_file);
	(void) puts("*******************************************************");
	(void) puts("*");
	(void) printf("* Entries that differ between %s and %s\n",
	    first_file_name, second_file_name);
	(void) puts("*");
	(void) printf("* filea == %s\n", first_file_name);
	(void) printf("* fileb == %s\n", second_file_name);
	(void) puts("*");
	(void) puts("*******************************************************");
	(void) fputs("Unit   ", stdout);
	print_header();
	print_file(differ_file);
}

static void
clean_up(void)
{
	(void) unlink(need_add_file);
	(void) unlink(need_rm_file);
	(void) unlink(differ_file);
}

/*
 * elem_compare(a,b)
 *
 * Args:
 *	a 		- element a
 *	b 		- element b
 *	different_types -
 *		value = 0  -> comparing two elements of same
 *			      type (eg: protodir elem vs. protodir elem).
 *		value != 0 -> comparing two elements of different type
 *			      (eg: protodir elem vs. protolist elem).
 *
 * Returns:
 *	0   - elements are identical
 *	>0  - elements differ
 *	      check flags to see which fields differ.
 */
static int
elem_compare(elem *a, elem *b, int different_types)
{
	int	res = 0;
	elem	*i, *j;

	/*
	 * if these are hard links to other files - those are the
	 * files that should be compared.
	 */
	i = a->link_parent ? a->link_parent : a;
	j = b->link_parent ? b->link_parent : b;

	/*
	 * We do not compare inodes - they always differ.
	 * We do not compare names because we assume that was
	 * checked before.
	 */

	/*
	 * Special rules for comparison:
	 *
	 * 1) if directory - ignore ref_cnt.
	 * 2) if sym_link - only check file_type & symlink
	 * 3) elem type of FILE_T, EDIT_T, & VOLATILE_T are equivilant when
	 *    comparing a protodir entry to a protolist entry.
	 */
	if (i->file_type != j->file_type) {
		if (different_types) {
			/*
			 * Check to see if filetypes are FILE_T vs.
			 * EDIT_T/VOLATILE_T/LINK_T comparisons.
			 */
			if ((i->file_type == FILE_T) &&
			    ((j->file_type == EDIT_T) ||
			    (j->file_type == VOLATILE_T) ||
			    (j->file_type == LINK_T))) {
				/*EMPTY*/
			} else if ((j->file_type == FILE_T) &&
			    ((i->file_type == EDIT_T) ||
			    (i->file_type == VOLATILE_T) ||
			    (i->file_type == LINK_T))) {
				/*EMPTY*/
			} else
				res |= TYPE_F;
		} else
			res |= TYPE_F;
	}

	/*
	 * if symlink - check the symlink value and then
	 * return.  symlink is the only field of concern
	 * in SYMLINKS.
	 */
	if (check_sym && ((res == 0) && (i->file_type == SYM_LINK_T))) {
		if ((!i->symsrc) || (!j->symsrc))
			res |= SYM_F;
		else {
			/*
			 * if either symlink starts with a './' strip it off,
			 * its irrelevant.
			 */
			if ((i->symsrc[0] == '.') && (i->symsrc[1] == '/'))
				i->symsrc += 2;
			if ((j->symsrc[0] == '.') && (j->symsrc[1] == '/'))
				j->symsrc += 2;

			if (strncmp(i->symsrc, j->symsrc, MAXNAME) != 0)
				res |= SYM_F;
		}
		return (res);
	}

	if ((i->file_type != DIR_T) && check_link &&
	    (i->ref_cnt != j->ref_cnt))
		res |= REF_F;
	if (check_user && (strncmp(i->owner, j->owner, TYPESIZE) != 0))
		res |= OWNER_F;
	if (check_group && (strncmp(i->group, j->group, TYPESIZE) != 0))
		res |= GROUP_F;
	if (check_perm && (i->perm != j->perm))
		res |= PERM_F;
	if (check_majmin && ((i->major != j->major) || (i->minor != j->minor)))
		res |= MAJMIN_F;

	return (res);
}

static void
print_elem(FILE *fp, elem *e)
{
	elem		p;
	pkg_list	*l;
	char		maj[TYPESIZE], min[TYPESIZE];
	char		perm[12], ref_cnt[12];

	/*
	 * If this is a LINK to another file, then adopt
	 * the permissions of that file.
	 */
	if (e->link_parent) {
		p = *((elem *)e->link_parent);
		(void) strcpy(p.name, e->name);
		p.symsrc = e->symsrc;
		p.file_type = e->file_type;
		e = &p;
	}

	if (!check_majmin || e->major == -1) {
		maj[0] = '-';
		maj[1] = '\0';
	} else {
		(void) sprintf(maj, "%d", e->major);
	}

	if (!check_majmin || e->minor == -1) {
		min[0] = '-';
		min[1] = '\0';
	} else {
		(void) sprintf(min, "%d", e->minor);
	}

	if (!check_perm) {
		perm[0] = '-';
		perm[1] = '\0';
	} else {
		(void) snprintf(perm, sizeof (perm), "%o", e->perm);
	}

	if (!check_link) {
		ref_cnt[0] = '-';
		ref_cnt[1] = '\0';
	} else {
		(void) snprintf(ref_cnt, sizeof (ref_cnt), "%d", e->ref_cnt);
	}

	(void) fprintf(fp, "%c %-30s %-20s %4s %-5s %-5s %6d %2s %2s %2s   ",
	    e->file_type, e->name,
	    check_sym && e->symsrc != NULL ? e->symsrc : "-", perm,
	    check_user ? e->owner : "-",
	    check_group ? e->group : "-",
	    e->inode, ref_cnt, maj, min);
	/*
	 * dump package list - if any.
	 */
	if (!e->pkgs)
		(void) fputs(" proto", fp);

	for (l = e->pkgs; l; l = l->next) {
		(void) fputc(' ', fp);
		(void) fputs(l->pkg_name, fp);
	}
	(void) fputc('\n', fp);
}

/*
 * do_compare(a,b)
 *
 * Args:
 *	different_types - see elem_compare() for explanation.
 */
static void
do_compare(elem *a, elem *b, int different_types)
{
	int	rc;

	if ((rc = elem_compare(a, b, different_types)) != 0) {
		(void) fputs("filea: ", differ_fp);
		print_elem(differ_fp, a);
		(void) fputs("fileb: ", differ_fp);
		print_elem(differ_fp, b);
		(void) fputs("    differ: ", differ_fp);

		if (rc & SYM_F)
			(void) fputs("symlink", differ_fp);
		if (rc & PERM_F)
			(void) fputs("perm ", differ_fp);
		if (rc & REF_F)
			(void) fputs("ref_cnt ", differ_fp);
		if (rc & TYPE_F)
			(void) fputs("file_type ", differ_fp);
		if (rc & OWNER_F)
			(void) fputs("owner ", differ_fp);
		if (rc & GROUP_F)
			(void) fputs("group ", differ_fp);
		if (rc & MAJMIN_F)
			(void) fputs("major/minor ", differ_fp);
		(void) putc('\n', differ_fp);
		(void) putc('\n', differ_fp);
	}
}

static void
check_second_vs_first(int verbose)
{
	int	i;
	elem	*cur;

	for (i = 0; i < second_list.num_of_buckets; i++) {
		for (cur = second_list.list[i]; cur; cur = cur->next) {
			if (!(cur->flag & VISITED_F)) {
				if ((first_list.type != second_list.type) &&
				    find_elem(&exception_list, cur,
				    FOLLOW_LINK)) {
					/*
					 * this entry is filtered, we don't
					 * need to do any more processing.
					 */
					if (verbose) {
						(void) printf(
						    "Filtered: Need Deletion "
						    "of:\n\t");
						print_elem(stdout, cur);
					}
					continue;
				}
				/*
				 * It is possible for arch specific files to be
				 * found in a protodir but listed as arch
				 * independent in a protolist file.  If this is
				 * a protodir vs. a protolist we will make
				 * that check.
				 */
				if ((second_list.type == PROTODIR_LIST) &&
				    (cur->arch != P_ISA) &&
				    (first_list.type != PROTODIR_LIST)) {
					/*
					 * do a lookup for same file, but as
					 * type ISA.
					 */
					elem	*e;

					e = find_elem_isa(&first_list, cur,
					    NO_FOLLOW_LINK);
					if (e) {
						do_compare(e, cur,
						    first_list.type -
						    second_list.type);
						continue;
					}
				}

				print_elem(need_rm_fp, cur);
			}
		}
	}
}

static void
check_first_vs_second(int verbose)
{
	int	i;
	elem	*e;
	elem	*cur;

	for (i = 0; i < first_list.num_of_buckets; i++) {
		for (cur = first_list.list[i]; cur; cur = cur->next) {
			if ((first_list.type != second_list.type) &&
			    find_elem(&exception_list, cur, FOLLOW_LINK)) {
				/*
				 * this entry is filtered, we don't need to do
				 * any more processing.
				 */
				if (verbose) {
					(void) printf("Filtered: Need "
					    "Addition of:\n\t");
					print_elem(stdout, cur);
				}
				continue;
			}

			/*
			 * Search package database for file.
			 */
			e = find_elem(&second_list, cur, NO_FOLLOW_LINK);

			/*
			 * It is possible for arch specific files to be found
			 * in a protodir but listed as arch independent in a
			 * protolist file.  If this is a protodir vs. a
			 * protolist we will make that check.
			 */
			if (!e && (first_list.type == PROTODIR_LIST) &&
			    (cur->arch != P_ISA) &&
			    (second_list.type != PROTODIR_LIST)) {
				/*
				 * do a lookup for same file, but as type ISA.
				 */
				e = find_elem_isa(&second_list, cur,
				    NO_FOLLOW_LINK);
			}

			if (!e && (first_list.type != PROTODIR_LIST) &&
			    (cur->arch == P_ISA) &&
			    (second_list.type == PROTODIR_LIST)) {
				/*
				 * do a lookup for same file, but as any
				 * type but ISA
				 */
				e = find_elem_mach(&second_list, cur,
				    NO_FOLLOW_LINK);
			}

			if (e == NULL)
				print_elem(need_add_fp, cur);
			else {
				do_compare(cur, e,
				    first_list.type - second_list.type);
				e->flag |= VISITED_F;
			}
		}
	}
}

static int
read_in_file(const char *file_name, elem_list *list)
{
	struct stat	st_buf;
	int		count = 0;

	if (stat(file_name, &st_buf) == 0) {
		if (S_ISREG(st_buf.st_mode)) {
			if (verbose) {
				(void) printf("file(%s): trying to process "
				    "as protolist...\n", file_name);
			}
			count = read_in_protolist(file_name, list, verbose);
		} else if (S_ISDIR(st_buf.st_mode)) {
			if (verbose)
				(void) printf("directory(%s): trying to "
				    "process as protodir...\n", file_name);
			count = read_in_protodir(file_name, list, verbose);
		} else {
			(void) fprintf(stderr,
			    "%s not a file or a directory.\n", file_name);
			usage();
			exit(1);
		}
	} else {
		perror(file_name);
		usage();
		exit(1);
	}

	return (count);
}

/* ARGSUSED */
static int
set_values(const char *fname, const struct stat *sbp, int otype,
    struct FTW *ftw)
{
	elem *ep;
	uid_t uid;
	gid_t gid;
	elem keyelem;
	mode_t perm;

	if (fname[0] == '\0' || fname[1] == '\0' || fname[2] == '\0')
		return (0);
	/* skip leading "./" */
	fname += 2;
	switch (otype) {
	case FTW_F:
	case FTW_D:
	case FTW_DP:
		if (strlcpy(keyelem.name, fname, sizeof (keyelem.name)) >=
		    sizeof (keyelem.name)) {
			(void) fprintf(stderr, "%s: %s: name too long\n",
			    myname, fname);
			return (1);
		}
		keyelem.arch = P_ISA;
		ep = find_elem(&first_list, &keyelem, NO_FOLLOW_LINK);
		if (ep == NULL) {
			ep = find_elem_mach(&first_list, &keyelem,
			    NO_FOLLOW_LINK);
		}
		/*
		 * Do nothing if this is a hard or symbolic link,
		 * since links don't have this information.
		 *
		 * Assume it's a file on the exception list if it's
		 * not found in the packaging.  Those are root:bin 755.
		 */
		if (ep != NULL &&
		    (ep->file_type == SYM_LINK_T || ep->file_type == LINK_T)) {
			return (0);
		}
		if (!set_group) {
			gid = -1;
		} else if (ep == NULL) {
			gid = 0;
		} else if ((gid = stdfind(ep->group, groupnames)) == -1) {
			(void) fprintf(stderr, "%s: %s: group '%s' unknown\n",
			    myname, fname, ep->group);
			return (1);
		}
		if (!set_user) {
			uid = -1;
		} else if (ep == NULL) {
			uid = 2;
		} else if ((uid = stdfind(ep->owner, usernames)) == -1) {
			(void) fprintf(stderr, "%s: %s: user '%s' unknown\n",
			    myname, fname, ep->owner);
			return (1);
		}
		if ((set_group && gid != -1 && gid != sbp->st_gid) ||
		    (set_user && uid != -1 && uid != sbp->st_uid)) {
			if (verbose) {
				const char *owner, *group;

				owner = ep == NULL ? "root" : ep->owner;
				group = ep == NULL ? "bin" : ep->group;
				if (set_group && set_user) {
					(void) printf("chown %s:%s %s\n",
					    owner, group, fname);
				} else if (set_user) {
					(void) printf("chown %s %s\n", owner,
					    fname);
				} else {
					(void) printf("chgrp %s %s\n", group,
					    fname);
				}
			}
			if (lchown(fname, uid, gid) == -1) {
				perror(fname);
				return (1);
			}
		}
		perm = ep == NULL ? 0755 : ep->perm;
		if (set_perm && ((perm ^ sbp->st_mode) & ~S_IFMT) != 0) {
			if (verbose)
				(void) printf("chmod %lo %s\n", perm, fname);
			if (chmod(fname, perm) == -1) {
				perror(fname);
				return (1);
			}
		}
		return (0);
	case FTW_DNR:
	case FTW_NS:
		(void) fprintf(stderr, "%s: %s: permission denied\n",
		    myname, fname);
		return (1);
	case FTW_SL:
	case FTW_SLN:
		return (0);
	default:
		return (1);
	}
}

int
main(int argc, char **argv)
{
	int	errflg = 0;
	int	i, c;
	int	list_filtered_exceptions = 0;
	int	n_proto_refs = 0;
	int	n_exception_files = 0;
	char	*proto_refs[MAX_PROTO_REFS];
	char	*exception_files[MAX_EXCEPTION_FILES];
	struct stat st_buf;

	if ((myname = argv[0]) == NULL)
		myname = "protocmp";

	while ((c = getopt(argc, argv, "gupGUPlmsLe:vd:")) != EOF) {
		switch (c) {
		case 's':
			check_sym = 0;
			break;
		case 'm':
			check_majmin = 0;
			break;
		case 'g':
			check_group = 0;
			break;
		case 'G':
			set_group = 1;
			break;
		case 'u':
			check_user = 0;
			break;
		case 'U':
			set_user = 1;
			break;
		case 'l':
			check_link = 0;
			break;
		case 'p':
			check_perm = 0;
			break;
		case 'P':
			set_perm = 1;
			break;
		case 'e':
			if (n_exception_files >= MAX_EXCEPTION_FILES) {
				errflg++;
				(void) fprintf(stderr,
				    "Only %d exception files supported\n",
				    MAX_EXCEPTION_FILES);
			} else {
				exception_files[n_exception_files++] = optarg;
			}
			break;
		case 'L':
			list_filtered_exceptions++;
			break;
		case 'v':
			verbose++;
			break;
		case 'd':
			if (n_proto_refs >= MAX_PROTO_REFS) {
				errflg++;
				(void) fprintf(stderr,
				    "Only %d proto references supported\n",
				    MAX_PROTO_REFS);
			} else {
				proto_refs[n_proto_refs++] = optarg;
			}
			break;
		case '?':
		default:
			errflg++;
			break;
		}
	}

	if (argc == optind || n_proto_refs == 0) {
		usage();
		exit(1);
	}

	if (set_group || set_user || set_perm) {
		if (optind != argc - 1) {
			usage();
			exit(1);
		}
		if (stat(argv[optind], &st_buf) == -1) {
			perror(argv[optind]);
			exit(1);
		}
		if (!S_ISDIR(st_buf.st_mode)) {
			(void) fprintf(stderr, "%s: %s: not a directory\n",
			    myname, argv[optind]);
			exit(1);
		}
	}

	init_list(&first_list, HASH_SIZE);
	init_list(&second_list, HASH_SIZE);
	init_list(&exception_list, HASH_SIZE);

	for (i = 0; i < n_exception_files; i++) {
		(void) read_in_exceptions(exception_files[i], verbose);
	}

	for (i = 0; i < n_proto_refs; i++) {
		first_file_name = proto_refs[i];
		(void) read_in_file(first_file_name, &first_list);
	}

	if (set_group || set_user || set_perm) {
		if (chdir(argv[optind]) == -1) {
			perror(argv[optind]);
			exit(1);
		}
		i = nftw(".", set_values, MAX_DEPTH, FTW_PHYS|FTW_DEPTH);
		if (i == -1) {
			perror("nftw");
			i = 1;
		}
		exit(i);
	}

	for (i = optind; i < argc; i++) {
		second_file_name = argv[i];
		(void) read_in_file(second_file_name, &second_list);
	}

	open_output_files();

	if (verbose)
		(void) puts("comparing build to packages...");

	check_first_vs_second(list_filtered_exceptions);

	if (verbose)
		(void) puts("checking over packages...");
	check_second_vs_first(list_filtered_exceptions);

	close_output_files();

	print_results();

	clean_up();

	return (0);
}
