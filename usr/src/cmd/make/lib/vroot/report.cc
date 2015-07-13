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
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <unistd.h>
#include <libintl.h>

#include <vroot/report.h>
#include <vroot/vroot.h>
#include <mk/defs.h>	/* for tmpdir */

static	FILE	*report_file;
static	FILE	*command_output_fp;
static	char	*target_being_reported_for;
static	char	*search_dir;
static  char	command_output_tmpfile[30];
static	int	is_path = 0;
static	char	sfile[MAXPATHLEN];
extern "C" {
static	void	(*warning_ptr) (char *, ...) = (void (*) (char *, ...)) NULL;
}

FILE *
get_report_file(void)
{
	return(report_file);
}

char *
get_target_being_reported_for(void)
{
	return(target_being_reported_for);
}

extern "C" {
static void
close_report_file(void)
{
	(void)fputs("\n", report_file);
	(void)fclose(report_file);
}
} // extern "C"

static void
clean_up(FILE *nse_depinfo_fp, FILE *merge_fp, char *nse_depinfo_file, char *merge_file, int unlinkf)
{
	fclose(nse_depinfo_fp);
	fclose(merge_fp);
	fclose(command_output_fp);
	unlink(command_output_tmpfile);
	if (unlinkf)
		unlink(merge_file);
	else
		rename(merge_file, nse_depinfo_file);
}


/*
 *  Update the file, if necessary.  We don't want to rewrite
 *  the file if we don't have to because we don't want the time of the file
 *  to change in that case.
 */

extern "C" {
static void
close_file(void)
{
	char		line[MAXPATHLEN+2];
	char		buf[MAXPATHLEN+2];
	FILE		*nse_depinfo_fp;
	FILE		*merge_fp;
	char		nse_depinfo_file[MAXPATHLEN];
	char		merge_file[MAXPATHLEN];
	char		lock_file[MAXPATHLEN];
	int		err;
	int		len;
	int		changed = 0;
	int		file_locked;

	fprintf(command_output_fp, "\n");
	fclose(command_output_fp);
	if ((command_output_fp = fopen(command_output_tmpfile, "r")) == NULL) {
		return;
	}
	sprintf(nse_depinfo_file, "%s/%s", search_dir, NSE_DEPINFO);
	sprintf(merge_file, "%s/.tmp%s.%d", search_dir, NSE_DEPINFO, getpid());
	sprintf(lock_file, "%s/%s", search_dir, NSE_DEPINFO_LOCK);
	err = file_lock(nse_depinfo_file, lock_file, &file_locked, 0);
	if (err) {
		if (warning_ptr != (void (*) (char *, ...)) NULL) {
			(*warning_ptr)(gettext("Couldn't write to %s"), nse_depinfo_file);
                      }
		unlink(command_output_tmpfile);
		return;
	}
	/* If .nse_depinfo file doesn't exist */
	if ((nse_depinfo_fp = fopen(nse_depinfo_file, "r+")) == NULL) {
		if (is_path) {
			if ((nse_depinfo_fp = 
			     fopen(nse_depinfo_file, "w")) == NULL) {
				fprintf(stderr, gettext("Cannot open `%s' for writing\n"),
				    nse_depinfo_file);
				unlink(command_output_tmpfile);

				unlink(lock_file);
				return;
			}
			while (fgets(line, MAXPATHLEN+2, command_output_fp) 
			       != NULL) {
				fprintf(nse_depinfo_fp, "%s", line);
			}
			fclose(command_output_fp);
		}
		fclose(nse_depinfo_fp);
		if (file_locked) {
			unlink(lock_file);
		}
		unlink(command_output_tmpfile);
		return;
	}
	if ((merge_fp = fopen(merge_file, "w")) == NULL) {
		fprintf(stderr, gettext("Cannot open %s for writing\n"), merge_file);
		if (file_locked) {
			unlink(lock_file);
		}
		unlink(command_output_tmpfile);
		return;
	}
	len = strlen(sfile);
	while (fgets(line, MAXPATHLEN+2, nse_depinfo_fp) != NULL) {
		if (strncmp(line, sfile, len) == 0 && line[len] == ':') {
			while (fgets(buf, MAXPATHLEN+2, command_output_fp) 
			       != NULL) {
				if (is_path) {
					fprintf(merge_fp, "%s", buf);
					if (strcmp(line, buf)) {
						/* changed */
						changed = 1;
					}
				}
				if (buf[strlen(buf)-1] == '\n') {
					break;
				}
			}
			if (changed || !is_path) {
				while (fgets(line, MAXPATHLEN, nse_depinfo_fp)
				       != NULL) {
					fputs(line, merge_fp);
				}
				clean_up(nse_depinfo_fp, merge_fp, 
					 nse_depinfo_file, merge_file, 0);
			} else {
				clean_up(nse_depinfo_fp, merge_fp, 
					 nse_depinfo_file, merge_file, 1);
			}
			if (file_locked) {
				unlink(lock_file);
			}
			unlink(command_output_tmpfile);
			return;
		} /* entry found */
		fputs(line, merge_fp);
	} 
	/* Entry never found.  Add it if there is a search path */
	if (is_path) {
		while (fgets(line, MAXPATHLEN+2, command_output_fp) != NULL) {
			fprintf(nse_depinfo_fp, "%s", line);
		}
	}
	clean_up(nse_depinfo_fp, merge_fp, nse_depinfo_file, merge_file, 1);
	if (file_locked) {
		unlink(lock_file);
	}
}

} // extern "C"

static void
report_dep(char *iflag, char *filename)
{

	if (command_output_fp == NULL) {
		sprintf(command_output_tmpfile, 
			"%s/%s.%d.XXXXXX", tmpdir, NSE_DEPINFO, getpid());
		int fd = mkstemp(command_output_tmpfile);
		if ((fd < 0) || (command_output_fp = fdopen(fd, "w")) == NULL) {
			return;
		}
		if ((search_dir = getenv("NSE_DEP")) == NULL) {
			return;
		}
		atexit(close_file);
		strcpy(sfile, filename);
		if (iflag == NULL || *iflag == '\0') {
			return;
		}
		fprintf(command_output_fp, "%s:", sfile);
	}
	fprintf(command_output_fp, " ");
	fprintf(command_output_fp, iflag);
	if (iflag != NULL) {
		is_path = 1;
	}
}

void
report_libdep(char *lib, char *flag)
{
	char		*ptr;
	char		filename[MAXPATHLEN];
	char		*p;

	if ((p= getenv(SUNPRO_DEPENDENCIES)) == NULL) {
		return;
	}
	ptr = strchr(p, ' ');
	if(ptr) {
		sprintf(filename, "%s-%s", ptr+1, flag);
		is_path = 1;
		report_dep(lib, filename);
	}
}

void
report_search_path(char *iflag)
{
	char		curdir[MAXPATHLEN];
	char		*sdir;
	char		*newiflag;
	char		filename[MAXPATHLEN];
	char		*p, *ptr;

	if ((sdir = getenv("NSE_DEP")) == NULL) {
		return;
	}
	if ((p= getenv(SUNPRO_DEPENDENCIES)) == NULL) {
		return;
	}
	ptr = strchr(p, ' ');
	if( ! ptr ) {
		return;
	}
	sprintf(filename, "%s-CPP", ptr+1);
	getcwd(curdir, sizeof(curdir));
	if (strcmp(curdir, sdir) != 0 && strlen(iflag) > 2 && 
	    iflag[2] != '/') {
		/* Makefile must have had an "cd xx; cc ..." */
		/* Modify the -I path to be relative to the cd */
		newiflag = (char *)malloc(strlen(iflag) + strlen(curdir) + 2);
		sprintf(newiflag, "-%c%s/%s", iflag[1], curdir, &iflag[2]);
		report_dep(newiflag, filename);
	} else {
		report_dep(iflag, filename);
	}
}

void
report_dependency(const char *name)
{
	register char	*filename;
	char		buffer[MAXPATHLEN+1];
	register char	*p;
	register char	*p2;
	char		nse_depinfo_file[MAXPATHLEN];

	if (report_file == NULL) {
		if ((filename= getenv(SUNPRO_DEPENDENCIES)) == NULL) {
			report_file = (FILE *)-1;
			return;
		}
		if (strlen(filename) == 0) {
			report_file = (FILE *)-1;
			return;
		}
		(void)strcpy(buffer, name);
		name = buffer;
		p = strchr(filename, ' ');
		if(p) {
			*p= 0;
		} else {
			report_file = (FILE *)-1;
			return;
		}
		if ((report_file= fopen(filename, "a")) == NULL) {
			if ((report_file= fopen(filename, "w")) == NULL) {
				report_file= (FILE *)-1;
				return;
			}
		}
		atexit(close_report_file);
		if ((p2= strchr(p+1, ' ')) != NULL)
			*p2= 0;
		target_being_reported_for= (char *)malloc((unsigned)(strlen(p+1)+1));
		(void)strcpy(target_being_reported_for, p+1);
		(void)fputs(p+1, report_file);
		(void)fputs(":", report_file);
		*p= ' ';
		if (p2 != NULL)
			*p2= ' ';
	}
	if (report_file == (FILE *)-1)
		return;
	(void)fputs(name, report_file);
	(void)fputs(" ", report_file);
}


