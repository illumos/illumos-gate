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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * patch /kernel/drv/md.conf file
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <meta.h>
#include <sys/lvm/md_mddb.h>

/*
 * magic strings in system
 */
#define	BEGROOTSTR	"* Begin MDD root info (do not edit)\n"
#define	ENDROOTSTR	"* End MDD root info (do not edit)\n"
#define	BEGMDDBSTR	"# Begin MDD database info (do not edit)\n"
#define	ENDMDDBSTR	"# End MDD database info (do not edit)\n"

/*
 * copy system file, yank root and database lines
 */
int
meta_systemfile_copy(
	char		*sname,		/* system file name */
	int		doroot,		/* remove mdd root stuff */
	int		domddb,		/* remove mdd database stuff */
	int		doit,		/* really copy file */
	int		verbose,	/* show what we're doing */
	char		**tname,	/* returned temp file name */
	FILE		**tfp,		/* returned open FILE */
	md_error_t	*ep		/* returned error */
)
{
	FILE		*fp;
	struct stat	sbuf;
	char		buf[MDDB_BOOTLIST_MAX_LEN];
	int		delroot = 0;
	int		delmddb = 0;

	/* check names */
	assert(sname != NULL);
	assert(tname != NULL);
	assert(tfp != NULL);

	/* get temp name */
	*tfp = NULL;
	*tname = Malloc(strlen(sname) + strlen(".tmp") + 1);
	(void) strcpy(*tname, sname);
	(void) strcat(*tname, ".tmp");

	/* copy system file, yank stuff */
	if (((fp = fopen(sname, "r")) == NULL) ||
	    (fstat(fileno(fp), &sbuf) != 0)) {
		if (errno != ENOENT) {
			(void) mdsyserror(ep, errno, sname);
			goto out;
		}
	}
	if (doit) {
		if ((*tfp = fopen(*tname, "w")) == NULL) {
			/*
			 * If we are on the miniroot we need to create
			 * files in /var/tmp. Opening a writable file
			 * in the miniroot result is EROFS error.
			 */
			if (errno != EROFS) {
				(void) mdsyserror(ep, errno, *tname);
				goto out;
			}
			Free(*tname);
			*tname = tempnam("/var/tmp", "svm_");
			if (*tname == NULL) {
				(void) mdsyserror(ep, errno, NULL);
				goto out;
			}
			if ((*tfp = fopen(*tname, "w")) == NULL) {
				(void) mdsyserror(ep, errno, *tname);
				goto out;
			}
		}
		if (fp != NULL) {
			if ((fchmod(fileno(*tfp), (sbuf.st_mode & 0777))
			    != 0) ||
			    (fchown(fileno(*tfp), sbuf.st_uid, sbuf.st_gid)
			    != 0)) {
				(void) mdsyserror(ep, errno, *tname);
				goto out;
			}
		}
	}
	if (verbose) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "Delete the following lines from %s:\n\n"), sname);
	}
	while ((fp != NULL) && (fgets(buf, sizeof (buf), fp) != NULL)) {
		if ((doroot) && (strcmp(buf, BEGROOTSTR) == 0)) {
			delroot = 1;
			if (verbose)
				(void) printf("%s", buf);
			continue;
		}
		if (delroot) {
			if (strcmp(buf, ENDROOTSTR) == 0)
				delroot = 0;
			if (verbose)
				(void) printf("%s", buf);
			continue;
		}
		if ((domddb) && (strcmp(buf, BEGMDDBSTR) == 0)) {
			delmddb = 1;
			if (verbose)
				(void) printf("%s", buf);
			continue;
		}
		if (delmddb) {
			if (strcmp(buf, ENDMDDBSTR) == 0)
				delmddb = 0;
			if (verbose)
				(void) printf("%s", buf);
			continue;
		}
		if (doit) {
			if (fputs(buf, *tfp) == EOF) {
				(void) mdsyserror(ep, errno, *tname);
				goto out;
			}
		}
	}
	if (fp != NULL) {
		if ((! feof(fp)) ||
		    (fclose(fp) != 0)) {
			(void) mdsyserror(ep, errno, sname);
			goto out;
		}
		fp = NULL;
	}
	if (verbose)
		(void) printf("\n");

	/* make sure we didn't stop mid-delete */
	if ((delroot) || (delmddb)) {
		(void) mderror(ep, MDE_SYSTEM_FILE, sname);
		goto out;
	}

	/* flush stuff */
	if (doit) {
		if ((fflush(*tfp) != 0) ||
		    (fsync(fileno(*tfp)) != 0)) {
			(void) mdsyserror(ep, errno, *tname);
			goto out;
		}
	}

	/* return success */
	return (0);

	/* cleanup, return error */
out:
	if (fp != NULL)
		(void) fclose(fp);
	if (*tname != NULL) {
		(void) unlink(*tname);
		Free(*tname);
	}
	if (*tfp != NULL)
		(void) fclose(*tfp);
	return (-1);
}

/*
 * append root on MD lines to system
 */
int
meta_systemfile_append_mdroot(
	mdname_t	*rootnp,	/* root device name */
	char		*sname,		/* system file name */
	char		*tname,		/* temp file name */
	FILE		*tfp,		/* temp FILE */
	int		ismeta,		/* is a metadevice */
	int		doit,		/* really patch file */
	int		verbose,	/* show what we're doing */
	md_error_t	*ep
)
{
	char		*longblkname;

	/* check names */
	assert(sname != NULL);
	assert(tname != NULL);
	assert(!doit || tfp != NULL);

	/* get root /devices name */
	if ((longblkname = metagetdevicesname(rootnp, ep)) == NULL)
		return (-1);

	/* add header */
	if (verbose) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "Add the following lines to %s:\n\n"), sname);
		(void) printf("%s", BEGROOTSTR);
	}
	if (doit) {
		if (fprintf(tfp, "%s", BEGROOTSTR) == EOF) {
			return (mdsyserror(ep, errno, tname));
		}
	}

	/* add rootdev */
	if (ismeta) {
		if (verbose)
			(void) printf("rootdev:%s\n", longblkname);
		if (doit) {
			if (fprintf(tfp, "rootdev:%s\n", longblkname) == EOF) {
				return (mdsyserror(ep, errno, tname));
			}
		}
	}

	/* add trailer */
	if (verbose) {
		(void) printf("%s\n", ENDROOTSTR);
	}
	if (doit) {
		if (fprintf(tfp, "%s", ENDROOTSTR) == EOF) {
			return (mdsyserror(ep, errno, tname));
		}
	}

	/* flush stuff */
	if (doit) {
		if ((fflush(tfp) != 0) ||
		    (fsync(fileno(tfp)) != 0)) {
			return (mdsyserror(ep, errno, tname));
		}
	}

	/* return success */
	return (0);
}

/*
 * parse mddb.cf line
 *
 * Caller of this routine needs to free the device id string that
 * is passed back during a successful return.
 */
static int
confline(
	char		*line,		/* line in file */
	char		**driver,	/* returned driver name */
	minor_t		*mnump,		/* returned minor number */
	daddr_t		*block,		/* returned block offset */
	char		**devid_char_pp	/* returned device id string */
)
{
	char		*p = line;
	int		chksum = 0;
	int		i;
	uint_t		devid_size;

	if (*p == '#') {
		return (-1);
	}
	*driver = p;
	while ((*p != ' ') && (*p != '\t'))
		chksum += *p++;
	if (*driver == p) {
		return (-1);
	}
	*p++ = '\0';
	*mnump = strtoul(p, &p, 10);
	chksum += *mnump;
	*block = strtol(p, &p, 10);
	chksum += *block;

	/* parse out devid */
	while ((*p == ' ') || (*p == '\t')) {
		p++;
	}
	i = strcspn(p, " \t");
	*devid_char_pp = Malloc(i+1);
	(void) strncpy(*devid_char_pp, p, i);
	(*devid_char_pp)[i] = '\0';
	devid_size = i;
	p += devid_size;
	for (i = 0; i < devid_size; i++) {
		chksum += (*devid_char_pp)[i];
	}

	chksum += strtol(p, &p, 10);
	if (chksum != 42) {
		Free (*devid_char_pp);
		devid_char_pp = NULL;
		return (-1);
	}
	return (0);
}

/*
 * append MDDB lines to system
 */
int
meta_systemfile_append_mddb(
	char		*cname,		/* mddb.cf file name */
	char		*sname,		/* system file name */
	char		*tname,		/* temp file name */
	FILE		*tfp,		/* temp FILE */
	int		doit,		/* really patch file */
	int		verbose,	/* show what we're doing */
	int		check,		/* if set check that mddb.cf is not */
					/* empty before updating md.conf    */
	md_error_t	*ep		/* returned error */
)
{
	FILE		*cfp = NULL;
	char		buf[1024];
	char		*p;
	int		i;
	char		*driver;
	minor_t		mnum;
	daddr_t		block;
	char		line[MDDB_BOOTLIST_MAX_LEN];
	char		entry[MDDB_BOOTLIST_MAX_LEN];
	char		*devid_char_p = NULL;
	struct stat	statbuf;

	/* check names */
	assert(cname != NULL);
	assert(sname != NULL);
	assert(tname != NULL);
	assert(!doit || tfp != NULL);

	/* open database conf file */
	if ((cfp = fopen(cname, "r")) == NULL) {
		(void) mdsyserror(ep, errno, cname);
		goto out;
	}
	/* Check that it is an ordinary file */
	if (stat(cname, &statbuf) != 0) {
		(void) mdsyserror(ep, errno, cname);
		goto out;
	}
	if ((statbuf.st_mode & S_IFMT) != S_IFREG) {
		(void) mderror(ep, MDE_MDDB_FILE, cname);
		goto out;
	}

	/* add header */
	if (verbose) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "Add the following lines to %s:\n\n"), sname);
		(void) printf("%s", BEGMDDBSTR);
	}
	if (doit) {
		if (fprintf(tfp, "%s", BEGMDDBSTR) == EOF) {
			(void) mdsyserror(ep, errno, tname);
			goto out;
		}
	}

	/* append database lines */
	while (((p = fgets(buf, sizeof (buf), cfp)) != NULL) &&
	    (confline(buf, &driver, &mnum, &block, &devid_char_p) != 0))
		;
	/*
	 * It is possible to be in a state where the md_devid_destroy flag
	 * has been set and the mdmonitor service not be enabled on reboot
	 * such that metadevadm doesn't get run and the entries in mddb.cf
	 * recreated.  The following checks for this condition and will not
	 * allow an empty mddb.cf to overwrite md.conf and lose the users
	 * configuration
	 */
	if (check && p == NULL) {
		(void) mderror(ep, MDE_MDDB_FILE, cname);
		goto out;
	}

	for (i = 1; ((p != NULL) && (i <= MDDB_MAX_PATCH)); ++i) {
		(void) snprintf(line, sizeof (line),
		    "mddb_bootlist%d=\"%s:%lu:%ld:%s",
		    i, driver, mnum, block, devid_char_p);
		if (devid_char_p != NULL) {
			free(devid_char_p);
			devid_char_p = NULL;
		}

		while ((p = fgets(buf, sizeof (buf), cfp)) != NULL) {
			if (confline(buf, &driver, &mnum, &block,
			    &devid_char_p) != 0) {
				continue;
			}
			(void) snprintf(entry, sizeof (entry), " %s:%lu:%ld:%s",
			    driver, mnum, block, devid_char_p);

			if ((strlen(line) + strlen(entry) + 4) > sizeof (line))
				break;
			(void) strcat(line, entry);
			if (devid_char_p != NULL) {
				free(devid_char_p);
				devid_char_p = NULL;
			}
		}
		if (verbose)
			/* CSTYLED */
			(void) printf("%s\";\n", line);
		if (doit) {
			/* CSTYLED */
			if (fprintf(tfp, "%s\";\n", line) <= 0) {
				(void) mdsyserror(ep, errno, tname);
				goto out;
			}
		}
	}

	if (devid_char_p != NULL) {
		free(devid_char_p);
		devid_char_p = NULL;
	}

	/* add trailer */
	if (verbose)
		(void) printf("%s\n", ENDMDDBSTR);
	if (doit) {
		if (fprintf(tfp, "%s", ENDMDDBSTR) == EOF) {
			(void) mdsyserror(ep, errno, tname);
			goto out;
		}
	}

	/* close database conf file */
	if (fclose(cfp) != 0) {
		cfp = NULL;
		(void) mdsyserror(ep, errno, cname);
		goto out;
	}
	cfp = NULL;

	/* flush stuff */
	if (doit) {
		if ((fflush(tfp) != 0) ||
		    (fsync(fileno(tfp)) != 0)) {
			(void) mdsyserror(ep, errno, tname);
			goto out;
		}
	}

	/* return success */
	return (0);

	/* cleanup, return error */
out:
	if (cfp != NULL)
		(void) fclose(cfp);
	return (-1);
}
