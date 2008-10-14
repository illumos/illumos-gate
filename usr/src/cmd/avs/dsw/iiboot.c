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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <sys/param.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <locale.h>
#include <langinfo.h>
#include <libintl.h>
#include <stdarg.h>
#include <ctype.h>

#include <sys/nsctl/cfg.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_errors.h>

#include <sys/nsctl/dsw.h>
#include <sys/nskernd.h>

#define	MAX_PROCESSES 64

int parseopts(int, char **, int *);
int read_resume_cfg();
int read_suspend_cfg();
void iiboot_usage(void);
extern char *basename(char *);

dsw_config_t *resume_list = 0;
dsw_ioctl_t *suspend_list = 0;
int	n_structs;
char *program;
char *cfg_cluster_tag = NULL;

volatile int fork_cnt;
volatile int fork_rc;

static void
iiboot_msg(char *prefix, spcs_s_info_t *status, char *string, va_list ap)
{
	if (status) {
		(void) fprintf(stderr, "II: %s\n", prefix);
		spcs_s_report(*status, stderr);
		spcs_s_ufree(status);
	} else {
		(void) fprintf(stderr, "%s: %s: ", program, prefix);
	}

	if (string && *string != '\0') {
		(void) vfprintf(stderr, string, ap);
	}

	(void) fprintf(stderr, "\n");
}

static void
iiboot_err(spcs_s_info_t *status, char *string, ...)
{
	va_list ap;
	va_start(ap, string);

	iiboot_msg(gettext("Error"), status, string, ap);

	va_end(ap);
	exit(1);
}

static void
iiboot_warn(spcs_s_info_t *status, char *string, ...)
{
	va_list ap;
	va_start(ap, string);

	iiboot_msg(gettext("warning"), status, string, ap);

	va_end(ap);
}

/* ARGSUSED */
static void
sigchld(int sig)
{
	int wait_loc = 0;

	wait(&wait_loc);
	if (WIFEXITED(wait_loc) && (WEXITSTATUS(wait_loc) == 0)) {
		;
		/*EMPTY*/
	} else {
		fork_rc = WEXITSTATUS(wait_loc);
	}

	if (fork_cnt > 0)
		--fork_cnt;
}


int
#ifdef lint
iiboot_lintmain(int argc, char *argv[])
#else
main(int argc, char *argv[])
#endif
{
	int pairs;
	pid_t pid = 0;
	int flag = 0;
	int i, j;
	int rc;
	int	ioctl_fd;
	void *ioarg;
	dsw_ioctl_t *ii_iop, ii_suspend;
	dsw_list_t args = {0};
	dsw_config_t *ii_cfgp, *lp = NULL;
	spcs_s_info_t ustatus;
	int max_processes = MAX_PROCESSES;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("ii");

	program = strdup(basename(argv[0]));

	if ((ioctl_fd = open(DSWDEV, O_RDWR, 0)) == -1) {
		spcs_log("ii", NULL, "iiboot open %s failed, errno %d",
			DSWDEV, errno);
		iiboot_err(NULL,
		    gettext("Failed to open Point-in-Time Copy control "
			    "device"));
	}

	if (parseopts(argc, argv, &flag))
		return (1);

	if (flag == DSWIOC_RESUME)
		pairs = read_resume_cfg();
	else
		pairs = -1;

	if (pairs == 0) {
#ifdef DEBUG
		iiboot_err(NULL,
		    gettext("Config contains no Point-in-Time Copy sets"));
#endif
		return (0);
	}

	if (cfg_cluster_tag == NULL && flag != DSWIOC_RESUME) {
		if (ioctl(ioctl_fd, DSWIOC_SHUTDOWN, 0) < 0) {
			spcs_log("ii", &ustatus, "iiboot shutdown failed");
			iiboot_err(NULL, gettext("SHUTDOWN ioctl error"));
		}
		return (0);
	} else if (cfg_cluster_tag != NULL && flag == DSWIOC_SUSPEND) {
		bzero(&ii_suspend, sizeof (dsw_ioctl_t));
		ii_suspend.status = spcs_s_ucreate();
		ii_suspend.flags = CV_IS_CLUSTER;
		strncpy(ii_suspend.shadow_vol, cfg_cluster_tag, DSW_NAMELEN);
		rc = ioctl(ioctl_fd, flag, &ii_suspend);
		if ((rc) && (errno != DSW_ECNOTFOUND)) {
			spcs_log("ii", &ii_suspend.status,
			    "iiboot resume cluster %s failed", cfg_cluster_tag);
			iiboot_err(&ii_suspend.status, gettext("ioctl error"));
			spcs_s_ufree(&ii_suspend.status);
			return (-1);
		}
		spcs_s_ufree(&ii_suspend.status);
		return (0);

	} else if ((cfg_cluster_tag != NULL) && (flag == DSWIOC_RESUME)) {
		/*
		 * If we are running in a Sun Cluster, this is a resume
		 * operation, get a list of all shadow volumes, where the
		 * shadow volumes match the shadows of the sets being resumed
		 */
		rc = ioctl(ioctl_fd, DSWIOC_LISTLEN, &args);
		if (rc == -1) {
			spcs_log("ii", NULL,
				"iiboot get LIST failed, errno %d", errno);
			iiboot_err(NULL,
				gettext("Failed to get LIST of Point-in-Time "
				    "sets"));
			return (-1);
		}

		args.status = spcs_s_ucreate();
		args.list_used = 0;
		args.list_size = rc + 4;
		lp = args.list = (dsw_config_t *)
		    malloc(args.list_size * sizeof (dsw_config_t));
		if (args.list == NULL) {
			iiboot_err(NULL,
				gettext("Failed to allocate memory"));
		}
		if (ioctl(ioctl_fd, DSWIOC_LIST, &args)  == -1) {
			spcs_log("ii", &args.status, "Failed to get LIST");
			iiboot_err(&args.status, gettext("ioctl error"));
		}
		spcs_s_ufree(&args.status);

		/* Remove all elements that are not in the resume list */
		for (j = args.list_used; j; j--) {
			for (i = 0; i < pairs; i++) {
				if (strcmp(lp->shadow_vol,
				    resume_list[i].shadow_vol) == 0) {
					if (strlen(lp->cluster_tag) == 0) {
						lp++;
						break;
					}
				}
			}
			if (i != pairs)
				continue;
			memmove(lp, lp + 1, j * sizeof (dsw_config_t));
			args.list_used--;
		}
	}

	sigset(SIGCHLD, sigchld);
	fork_cnt = fork_rc = 0;
	for (i = 0; i < pairs; i++) {
		ustatus = spcs_s_ucreate();
		if (flag == DSWIOC_RESUME) {
			ioarg = (void *) (ii_cfgp = (resume_list + i));
			ii_cfgp->status = ustatus;
			pid = fork();
		} else {
			ioarg = (void *) (ii_iop = (suspend_list + i));
			ii_iop->status = ustatus;
		}
		while (pid == -1) {		/* error forking */
			perror("fork");

			/* back off on the max processes and try again */
			--max_processes;
			if (fork_cnt > 0) {
				pause();
			}
			pid = fork();
		}

		if (pid > 0) {		/* this is parent process */
			++fork_cnt;
			while (fork_cnt > MAX_PROCESSES) {
				pause();
			}
			continue;
		}

		rc = ioctl(ioctl_fd, flag, ioarg);
		if (rc == SPCS_S_ERROR) {
			if (flag == DSWIOC_RESUME)
				spcs_log("ii", &ustatus,
					"iiboot resume %s failed",
					ii_cfgp->shadow_vol);
			else
				spcs_log("ii", &ustatus,
					"iiboot suspend %s failed",
					ii_iop->shadow_vol);
			iiboot_err(&ustatus, gettext("ioctl error"));
		}
		/* Resuming child */
		spcs_s_ufree(&ustatus);
		if (flag == DSWIOC_RESUME)
			exit(0);
	}

	/*
	 * Allow all processes to finish up before exiting
	 * Set rc for success
	 */
	while (fork_cnt > 0) {
		alarm(60);		/* wake up in 60 secs just in case */
		pause();
	}
	alarm(0);

	/* Disable duplicate shadows that were part of the implicit join */
	if ((j = args.list_used) != 0) {
		int setno;
		char key[CFG_MAX_KEY], buf[CFG_MAX_BUF], sn[CFG_MAX_BUF];
		CFGFILE *cfg;
		char *mst, *shd, *ctag;
		pid_t pid = fork();

		if (pid == -1) {
			iiboot_err(NULL, gettext("Failed to fork"));
			return (errno);
		} else if (pid > 0) {
			return (0);	/* Parent, OK exit */
		}

		for (j = args.list_used, lp = args.list; j; j--, lp++) {
		    setno = 0;
		    while (++setno) {

			/*
			 * Open the configuration database
			 */
			if (!(cfg = cfg_open(""))) {
			    iiboot_err(NULL, gettext("Failed to open dscfg"));
			    return (-1);
			}

			/* Sooner or later, this lock will be free */
			while (!cfg_lock(cfg, CFG_WRLOCK))
				sleep(2);

			snprintf(key, CFG_MAX_KEY, "ii.set%d", setno);
			if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0) {
				cfg_close(cfg);
				break;
			}

			/* For imported shadows, master must be special tag */
			mst = strtok(buf, " ");		/* master */
			shd = strtok(NULL, " ");	/* shadow */
			(void) strtok(NULL, " ");	/* bitmap */
			(void) strtok(NULL, " ");	/* mode */
			(void) strtok(NULL, " ");	/* overflow */
			ctag = strtok(NULL, " ");	/* cnode */

			/*
			 * For this record to be processed, the shadow volume
			 * name must match and the cluster tag must be blank
			 */
			if (strcmp(lp->shadow_vol, shd) || strcmp(ctag, "-")) {
				cfg_close(cfg);
				continue;
			}

			/* Derrive local cluster tag */
			if (cfg_l_dgname(lp->shadow_vol, sn, sizeof (sn)))
				ctag = sn;
			else
				iiboot_err(NULL, gettext(
					"Failed to device group for shadow %s"),
					lp->shadow_vol);

			/* disable master volume if not imported */
			if (strcmp(mst, II_IMPORTED_SHADOW))
			    if (cfg_vol_disable(cfg, mst, cfg_cluster_tag,
				"ii") < 0)
				iiboot_err(NULL, gettext(
				    "SV disable of master failed"));

			/*
			 * Delete the Imported Shadow set
			 */
			if (cfg_put_cstring(cfg, key, NULL, 0) < 0) {
				iiboot_err(NULL, gettext(
					"Failed to delete Imported shadow %s"),
					lp->shadow_vol);
			}

			/*
			 * SV disable shadow volume
			 */
			if (cfg_vol_disable(cfg, shd, NULL, "ii") < 0)
				iiboot_err(NULL, gettext(
					"SV disable of shadow failed"));

			/*
			 * Commit the delete
			 */
			cfg_commit(cfg);
			cfg_close(cfg);

			/*
			 * Open the configuration database
			 */
			if (!(cfg = cfg_open(""))) {
			    iiboot_err(NULL, gettext("Failed to open dscfg"));
			    return (-1);
			}

			/* Sooner or later, this lock will be free */
			while (!cfg_lock(cfg, CFG_WRLOCK))
				sleep(2);

			/* Set cluster tag for Shadow volume */
			cfg_vol_enable(cfg, shd, ctag, "ii");


			/*
			 * Commit the delete
			 */
			cfg_commit(cfg);
			cfg_close(cfg);
		    }
		}
	}
	return (fork_rc);
}

static int
set_is_offline(char *cflags)
{
	unsigned int flags;
	int conv;

	if (!cflags || !*cflags)
		return (0);

	/* convert flags to an int */
	conv = sscanf(cflags, "%x", &flags);
	return ((conv == 1) && ((flags & DSW_OFFLINE) != 0));
}

/*
 * read_resume_cfg()
 *
 * DESCRIPTION: Read the relevant config info via libcfg
 *
 * Outputs:
 *	int i			Number of Point-in-Time Copy sets
 *
 * Side Effects: The 0 to i-1 entries in the resume_list are filled.
 *
 */

int
read_resume_cfg()
{
	CFGFILE *cfg;
	int i;
	char *buf, **entry, *mst, *shd, *bmp, *ctag, *opt, *ptr;
	int valid_sets;
	dsw_config_t *p;
	static int offset = sizeof (NSKERN_II_BMP_OPTION);

	spcs_log("ii", NULL, "iiboot resume cluster tag %s",
			cfg_cluster_tag ? cfg_cluster_tag : "<none>");
	if ((cfg = cfg_open("")) == NULL) {
		spcs_log("ii", NULL, "iiboot cfg_open failed, errno %d",
			errno);
		iiboot_err(NULL, gettext("Error opening config"));
	}

	cfg_resource(cfg, cfg_cluster_tag);
	if (!cfg_lock(cfg, CFG_RDLOCK)) {
		spcs_log("ii", NULL, "iiboot CFG_RDLOCK failed, errno %d",
			errno);
		iiboot_err(NULL, gettext("Error locking config"));
	}

	/* Determine number of set, if zero return 0 */
	if ((n_structs = cfg_get_section(cfg, &entry, "ii")) == 0)
		return (0);

	resume_list = calloc(n_structs, sizeof (*resume_list));
	if (resume_list == NULL) {
		spcs_log("ii", NULL, "iiboot resume realloc failed, errno %d",
		    errno);
		iiboot_err(NULL, gettext("Resume realloc failed"));
	}

	valid_sets = 0;
	p = resume_list;
	for (i = 0; i < n_structs; i++) {
		buf = entry[i];
		mst = strtok(buf, " ");
		shd = strtok(NULL, " ");
		bmp = strtok(NULL, " ");
		(void) strtok(NULL, " ");	/* mode */
		(void) strtok(NULL, " ");	/* overflow */
		ctag = strtok(NULL, " ");	/* ctag */
		if (ctag)
			ctag += strspn(ctag, "-");
		opt = strtok(NULL, " ");

		if (!mst || !shd || !bmp)
			break;

		/* If cluster tags don't match, skip record */
		if ((cfg_cluster_tag && strcmp(ctag, cfg_cluster_tag)) ||
		    (!cfg_cluster_tag && strlen(ctag))) {
			free(buf);
			continue;
		}

		ptr = strstr(opt, NSKERN_II_BMP_OPTION "=");
		if (ptr && set_is_offline(ptr + offset)) {
			free(buf);
			continue;
		}

		strncpy(p->master_vol, mst, DSW_NAMELEN);
		strncpy(p->shadow_vol, shd, DSW_NAMELEN);
		strncpy(p->bitmap_vol, bmp, DSW_NAMELEN);
		if (ctag)
			strncpy(p->cluster_tag, ctag, DSW_NAMELEN);
		free(buf);
		++p;
		++valid_sets;
	}

	while (i < n_structs)
		free(entry[i++]);
	if (entry)
		free(entry);

	cfg_close(cfg);
	return (valid_sets);
}

/*
 * read_suspend_cfg()
 *
 * DESCRIPTION: Read the relevant config info via libcfg
 *
 * Outputs:
 *	int i			Number of Point-in-Time Copy sets
 *
 * Side Effects: The 0 to i-1 entries in the suspend_list are filled.
 *
 */

int
read_suspend_cfg()
{
	int rc;
	CFGFILE *cfg;
	int i;
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];
	int setnumber;
	dsw_ioctl_t *p;

	spcs_log("ii", NULL, "iiboot suspend cluster tag %s",
			cfg_cluster_tag ? cfg_cluster_tag : "<none>");

	if (cfg_cluster_tag == NULL) {
		return (1);
	}

	if ((cfg = cfg_open("")) == NULL) {
		spcs_log("ii", NULL, "iiboot cfg_open failed, errno %d",
			errno);
		iiboot_err(NULL, gettext("Error opening config"));
	}

	cfg_resource(cfg, cfg_cluster_tag);
	if (!cfg_lock(cfg, CFG_RDLOCK)) {
		spcs_log("ii", NULL, "iiboot CFG_RDLOCK failed, errno %d",
			errno);
		iiboot_err(NULL, gettext("Error locking config"));
	}


	/*CSTYLED*/
	for (i = 0; ; i++) {
		setnumber = i + 1;

		bzero(buf, CFG_MAX_BUF);
		(void) snprintf(key, sizeof (key), "ii.set%d", setnumber);
		rc = cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF);
		if (rc < 0)
			break;
		if (n_structs < setnumber) {
			n_structs += 2;
			suspend_list = realloc(suspend_list,
					sizeof (*suspend_list) * n_structs);
			if (suspend_list == NULL) {
			    spcs_log("ii", NULL,
			    "iiboot suspend realloc failed, errno %d",
			    errno);
			    iiboot_err(NULL, gettext("Suspend realloc failed"));
			}
		}
		p = suspend_list + i;

		(void) snprintf(key, sizeof (key), "ii.set%d.shadow",
		    setnumber);
		(void) cfg_get_cstring(cfg, key, p->shadow_vol, DSW_NAMELEN);

	}

	cfg_close(cfg);
	return (i);
}


int
parseopts(argc, argv, flag)
int argc;
char **argv;
int *flag;
{
	int  errflag = 0;
	int  Cflag = 0;
	char c;
	char inval = 0;

	while ((c = getopt(argc, argv, "hrsC:")) != -1) {
		switch (c) {
		case 'C':
			if (Cflag) {
				iiboot_warn(NULL,
				    gettext("-C specified multiple times"));
				iiboot_usage();
				return (-1);
			}

			Cflag++;
			cfg_cluster_tag = (optarg[0] == '-') ? NULL : optarg;
			break;

		case 'h':
			iiboot_usage();
			exit(0);
			/* NOTREACHED */

		case 'r':
			if (*flag)
				inval = 1;
			*flag = DSWIOC_RESUME;
			break;
		case 's':
			if (*flag)
				inval = 1;
			*flag = DSWIOC_SUSPEND;
			break;
		case '?':
			errflag++;
		}
	}

	if (inval) {
		iiboot_warn(NULL, gettext("Invalid argument combination"));
		errflag = 1;
	}

	if (!*flag || errflag) {
		iiboot_usage();
		return (-1);
	}

	return (0);
}

void
iiboot_usage()
{
	(void) fprintf(stderr, gettext("usage:\n"));
	(void) fprintf(stderr,
		gettext("\t%s -r [-C tag]\t\tresume\n"), program);
	(void) fprintf(stderr,
		gettext("\t%s -s [-C tag]\t\tsuspend\n"), program);
	(void) fprintf(stderr, gettext("\t%s -h\t\t\tthis help message\n"),
	    program);
}
