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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <syslog.h>
#include <signal.h>
#include <unistd.h>
#include <stropts.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <dmd_impl.h>
#include <mms_list.h>
#include <mms_network.h>
#include "mms_parser.h"
#include <mms_trace.h>
#include <netdb.h>
#include <watcher_impl.h>
#include <dirent.h>
#include <procfs.h>
#include <libscf.h>
#include <libcontract.h>
#include <sys/ctfs.h>
#include <sys/contract/process.h>
#include <host_ident.h>
#include <mms_cores.h>
#include <mms_cfg.h>
#include <net_cfg_service.h>
#include <mms_strapp.h>

static	char	*_SrcFile = __FILE__;
int	wcr_debug = MMS_SEV_DEVP;

wcr_wka_t 	wka;


typedef	void sigfunc(int, siginfo_t *, void *);
void wcr_chk_child_death(wcr_wka_t *wka);

/*
 * wcr_free_DM_LM
 *
 * Parameters:
 *	- DM_LM : ptr to wcr_DM_LM_t
 *
 * Free's memory inside a wcr_DM_LM_t
 * sets ptrs = NULL
 * caller should free struct itself if desired
 *
 * Return Values:
 *	none
 */
void
wcr_free_DM_LM(wcr_DM_LM_t *DM_LM_dev)
{
	if (DM_LM_dev->
	    wcr_DM_LM_union.wcr_DM.
	    wcr_DM_name != NULL) {
		free(DM_LM_dev->
		    wcr_DM_LM_union.wcr_DM.
		    wcr_DM_name);
		DM_LM_dev->
		    wcr_DM_LM_union.wcr_DM.
		    wcr_DM_name = NULL;

	}
	if (DM_LM_dev->
	    wcr_DM_LM_union.wcr_DM.
	    wcr_drive_name != NULL) {
		free(DM_LM_dev->
		    wcr_DM_LM_union.wcr_DM.
		    wcr_drive_name);
		DM_LM_dev->
		    wcr_DM_LM_union.wcr_DM.
		    wcr_drive_name = NULL;
	}
	if (DM_LM_dev->
	    wcr_host_name != NULL) {
		free(DM_LM_dev->
		    wcr_host_name);
		DM_LM_dev->
		    wcr_host_name = NULL;
	}
	if (DM_LM_dev->
	    wcr_DM_LM_union.wcr_DM.
	    wcr_dev_tar_path != NULL) {
		free(DM_LM_dev->
		    wcr_DM_LM_union.wcr_DM.
		    wcr_dev_tar_path);
		DM_LM_dev->
		    wcr_DM_LM_union.wcr_DM.
		    wcr_dev_tar_path = NULL;
	}
	if (DM_LM_dev->
	    wcr_disabled != NULL) {
		free(DM_LM_dev->
		    wcr_disabled);
		DM_LM_dev->
		    wcr_disabled = NULL;
	}
	if (DM_LM_dev->
	    wcr_DM_LM_union.wcr_LM.
	    wcr_LM_name != NULL) {
		free(DM_LM_dev->
		    wcr_DM_LM_union.wcr_LM.
		    wcr_LM_name);
		DM_LM_dev->
		    wcr_DM_LM_union.wcr_LM.
		    wcr_LM_name = NULL;
	}
	if (DM_LM_dev->
	    wcr_DM_LM_union.wcr_LM.
	    wcr_library_name != NULL) {
		free(DM_LM_dev->
		    wcr_DM_LM_union.wcr_LM.
		    wcr_library_name);
		DM_LM_dev->
		    wcr_DM_LM_union.wcr_LM.
		    wcr_library_name = NULL;
	}
	if (DM_LM_dev->
	    wcr_DM_LM_union.wcr_DM.
	    wcr_dev_mgr_path != NULL) {
		free(DM_LM_dev->
		    wcr_DM_LM_union.wcr_DM.
		    wcr_dev_mgr_path);
		DM_LM_dev->
		    wcr_DM_LM_union.wcr_DM.
		    wcr_dev_mgr_path = NULL;
	}

}


/*
 * wcr_alloc_DM_LM
 *
 * Parameters:
 *	none
 *
 * allocate a new wcr_DM_LM_t struct
 * initialize all pointers
 *
 * Return Values:
 *	NULL :				if alloc failed
 *	ptr to new wcr_DM_LM_t :	if alloc is successful
 *
 */
wcr_DM_LM_t *
wcr_alloc_DM_LM()
{
	wcr_DM_LM_t	*DM_LM_dev;

	DM_LM_dev =
	    (wcr_DM_LM_t *)malloc(sizeof (wcr_DM_LM_t));
	if (DM_LM_dev == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to mallor wcr_DM_LM_t: %s",
		    strerror(errno));
		return (NULL);
	}
	memset(DM_LM_dev, 0, sizeof (wcr_DM_LM_t));

	/* Initialize pointers */

	DM_LM_dev->wcr_DM_LM_union.wcr_DM.
	    wcr_DM_name = NULL;
	DM_LM_dev->
	    wcr_DM_LM_union.wcr_DM.
	    wcr_drive_name = NULL;
	DM_LM_dev->
	    wcr_host_name = NULL;
	DM_LM_dev->
	    wcr_DM_LM_union.wcr_DM.
	    wcr_dev_tar_path = NULL;
	DM_LM_dev->
	    wcr_disabled = NULL;
	DM_LM_dev->
	    wcr_DM_LM_union.wcr_LM.
	    wcr_LM_name = NULL;
	DM_LM_dev->
	    wcr_DM_LM_union.wcr_LM.
	    wcr_library_name = NULL;
	DM_LM_dev->
	    wcr_DM_LM_union.wcr_DM.
	    wcr_dev_mgr_path = NULL;

	return (DM_LM_dev);
}


/*
 * wcr_ssi_is_running()
 * checks to see if ssi process (prog) with owner (user) is running
 * returns true if the process is running, false if it is not.
 * passes back the pid of the running process
 */

int
wcr_ssi_is_running(char *prog, int *pid, int ssi_port)
{
	int		psdata;
	DIR		*procdir;
	struct dirent	*procdirp;
	psinfo_t	p;
	char		*fullpath;
	char		*ssiarg;
	char		*argcpy;
	int		i;

	mms_trace(MMS_DEVP,
	    "wcr_ssi_is_running: "
	    "check if %s is running on port %d",
	    prog, ssi_port);

	if ((procdir = opendir("/proc")) == NULL) {
		mms_trace(MMS_ERR, "opendir failure: %s\n", strerror(errno));
		return (0);
	}

	/* Look for the ssi process psinfo file */
	while ((procdirp = readdir(procdir)) != NULL) {
		if (strcmp(procdirp->d_name, ".") == 0 ||
		    strcmp(procdirp->d_name, "..") == 0)
			continue;
		else {
			fullpath =
			    mms_strapp(NULL,
			    "/proc/%s/psinfo", procdirp->d_name);
			if ((psdata = open(fullpath, O_RDONLY)) == -1)
				mms_trace(MMS_ERR,
				    "open failure: %s\n", strerror(errno));
			read(psdata, (void *) &p, sizeof (p));

			if (strcmp(p.pr_fname, "ssi") == 0) {
				/* ssi found, get the ssi's port */
				argcpy = strdup(p.pr_psargs);
				ssiarg = strtok(argcpy, " ");
				for (i = 0; i < 2; i++)
					ssiarg = strtok(NULL, " ");
				if (atoi(ssiarg) == ssi_port) {
					*pid = atoi(procdirp->d_name);
					close(psdata);
					closedir(procdir);
					free(fullpath);
					return (1);
				}
			}
			close(psdata);
		}
	}

	/* ssi wasn't found running on the port */
	close(psdata);
	closedir(procdir);
	free(fullpath);
	mms_trace(MMS_DEVP, "wcr_ssi_is_running: "
	    "didn't find a ssi running");

	return (0);
}


/*
 * Initialize message logging.
 */
static void
wcr_init_log()
{
	if (mms_trace_open(WCR_TRACE_FILE, MMS_ID_WCR, wcr_debug, -1, 1, 1)) {
		mms_trace(MMS_NOTICE, "Unable to open mms_trace file \"%s\"",
		    WCR_TRACE_FILE);
	}
}

/*
 * wcr_init_wka()
 *	-Initializes the watcher's work area.
 *	-Creates 2 lists, 1 list of wcr_dev type
 *	and 1 list of wcr_wka_DM_LM type
 *	-Saves the first device ordinal
 *	-Saves the host name of this watcher's host
 */

void
wcr_init_wka(wcr_wka_t *wka)
{
	memset(wka, 0, sizeof (wcr_wka_t));

	mms_list_create(&wka->wcr_wka_DM_LM_list, sizeof (wcr_DM_LM_t),
	    offsetof(wcr_DM_LM_t, wcr_DM_LM_next));

	mms_list_create(&wka->wcr_old_DM_LM_list, sizeof (wcr_DM_LM_t),
	    offsetof(wcr_DM_LM_t, wcr_DM_LM_next));

	mms_list_create(&wka->wcr_events, sizeof (wcr_event_t),
	    offsetof(wcr_event_t, wcr_event_next));

	mms_list_create(&wka->wcr_net_LM_list, sizeof (wcr_net_LM_t),
	    offsetof(wcr_net_LM_t, wcr_net_LM_next));

	wka->wcr_wka_next_ordinal = WCR_FIRST_DEV_ORDINAL;
	gethostname(wka->wcr_host_name, MAXHOSTNAMELEN);

	wka->wcr_mms_conn.mms_fd = -1;

	wka->wcr_cfd = -1;
}

void
wcr_net_cfg_free(mms_network_cfg_t *net_cfg, mms_list_t **mm_list)
{
	wcr_MM_t	*mm;
	wcr_MM_t	*next_mm;

	mms_net_cfg_free(net_cfg);
	(void) memset(net_cfg, 0, sizeof (mms_network_cfg_t));

	if (mm_list && *mm_list) {
		for (mm = mms_list_head(*mm_list);
		    mm != NULL;
		    mm = next_mm) {
			next_mm = mms_list_next(*mm_list, mm);
			mms_list_remove(*mm_list, mm);
			free(mm);
		}
		mms_list_destroy(*mm_list);
		free(*mm_list);
		*mm_list = NULL;
	}
}

/*
 * Read watcher network configuration file
 */
int
wcr_net_cfg_read(mms_network_cfg_t *net_cfg, mms_list_t **mm_list)
{
	wcr_MM_t	*mm = NULL;
	char		*p = NULL;
	char		*q = NULL;

	*mm_list = NULL;
	if (mms_net_cfg_service(net_cfg, "watcher", "MMP", "1.0")) {
		mms_trace(MMS_ERR, "net config read");
		mms_net_cfg_free(net_cfg);
		return (1);
	}

	*mm_list = (mms_list_t *)calloc(1, sizeof (mms_list_t));
	mms_list_create(*mm_list, sizeof (wcr_MM_t),
	    offsetof(wcr_MM_t, wcr_MM_next));

	p = net_cfg->cli_host;
	while (p != NULL) {
		if (q = strchr(p, ',')) {
			*q = '\0';
		}
		mms_trace(MMS_DEVP, "mm host %s port %s", p, net_cfg->cli_port);
		mm = (wcr_MM_t *)calloc(1, sizeof (wcr_MM_t));
		(void) snprintf(mm->wcr_mm_host, MAXHOSTNAMELEN, "%s", p);
		mms_list_insert_tail(*mm_list, mm);
		p = q;
		if (p != NULL) {
			p++;
		}
	}
	return (0);
}

/*
 * Initialize the watcher
 * This requires that the driver dmd must have been properly installed.
 * The config file dmd.conf has only one entry for instance 0.
 *	-Makes call to initialize the watcher's workarea
 *	-Fork and exit from parent to become daemon
 *	-Fill in wka_net_cfg struct with values from watcher's
 *	network config file
 *	-Open the watcher device
 */
int
wcr_init_watcher(wcr_wka_t *wka)
{
	int		fd;
	int		mms_trace_fd;
	pid_t		pid;
	int		i;
	mms_err_t	err;
	char		ebuf[MMS_EBUF_LEN];
	char		*corename;

	/*
	 * Init work area
	 */
	wcr_init_wka(wka);

	/*
	 * Init message logging
	 */
	wcr_init_log();

	/*
	 * Cores dir
	 */
	if (mms_set_core(MMS_CORES_DIR, NULL)) {
		mms_trace(MMS_ERR, "core setup %s", strerror(errno));
	}

	corename = mms_strapp(NULL, "core.mmswcr");
	/* Check to see how many core files exist */
	if (mms_man_cores(MMS_CORES_DIR, corename)) {
		mms_trace(MMS_ERR,
		    "wcr_init_watcher: mms_man_cores failed %s",
		    strerror(errno));
	}
	free(corename);

	/*
	 * Read config before becoming smf daemon
	 */
	if (wcr_net_cfg_read(&wka->wcr_wka_net_cfg, &wka->wcr_wka_MM_list)) {
		mms_trace(MMS_ERR, "Read network configuration failed");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/*
	 * Become a smf daemon
	 */
	if (pid = fork()) {
		/*
		 * Parent process
		 */
		if (pid == (pid_t)(-1)) {
			mms_trace(MMS_ERR, "fork - %s\n", strerror(errno));
			exit(1);
		} else {
			/* Successfully forked, parent exits */
			exit(0);
		}
	}

	/*
	 * In child.
	 */

	/*
	 * Close all opened files except mms_trace
	 */
	mms_trace_fd = mms_trace_get_fd();
	for (i = 0; i < OPEN_MAX; i++) {
		if (i != mms_trace_fd)
			close(i);
	}

	/*
	 * Become session leader
	 */
	setsid();

	/*
	 * Clear file mode create mask
	 */
	umask(0);

	/*
	 * Open the watcher device
	 */
	fd = open(WCR_WATCHER, O_RDWR);

	if (fd < 0) {
		if (errno == EBUSY) {
			mms_trace(MMS_ERR, "A watcher is already active");
			return (1);
		} else {
			mms_trace(MMS_ERR, "Unable to open watcher device: %s",
			    strerror(errno));
			return (1);
		}
	}

#ifdef	MMS_OPENSSL
	if (mms_ssl_client(&wka->wcr_wka_net_cfg, &wka->wcr_ssl_data, &err)) {
		mms_get_error_string(&err, ebuf, MMS_EBUF_LEN);
		mms_trace(MMS_ERR, "ssl init - %s", ebuf);
		return (1);
	}
#endif	/* MMS_OPENSSL */

	return (0);


}



/*
 * Initiate a session with MMS
 *	-Use mms_mmconnect to connect a mm from a mm list
 *	-Store the file descriptor
 */

int
wcr_init_session(wcr_wka_t *wka)
{
	int		err;
	char		*tag = NULL;
	wcr_MM_t	*mm = NULL;

	/* Get first mm from list */
	if (wka->wcr_wka_MM_list == NULL ||
	    (mm = mms_list_head(wka->wcr_wka_MM_list)) == NULL ||
	    mm->wcr_mm_host == NULL) {
		mms_trace(MMS_ERR, "empty mm list");
		exit(1);
	}

	/* Connect to MM */
	wka->wcr_connected = 0;
	while (!wka->wcr_connected) {
		if (wka->wcr_wka_sighup) {
			mms_trace(MMS_DEVP, "refresh mm list");
			return (1);
		}
		wka->wcr_wka_net_cfg.cli_host = mm->wcr_mm_host;
		mms_trace(MMS_DEVP, "mm host %s port %s\n",
		    wka->wcr_wka_net_cfg.cli_host,
		    wka->wcr_wka_net_cfg.cli_port);
		if (mms_mmconnect(&wka->wcr_wka_net_cfg,
		    wka->wcr_ssl_data,
		    &wka->wcr_mms_conn, &err, tag)) {
			mms_get_error_string(&wka->wcr_mms_conn.mms_err,
			    wka->wcr_mms_ebuf, MMS_EBUF_LEN);

			mms_trace(MMS_ERR, "Watcher failed to connect "
			    "to %s MM: (%d) %s",
			    mm->wcr_mm_host,
			    err,
			    wka->wcr_mms_ebuf);

			/* Get next mm from list */
			mm = mms_list_next(wka->wcr_wka_MM_list, mm);
			if (mm == NULL) {
				/* Reached end of mm list, start over */
				mm = mms_list_head(wka->wcr_wka_MM_list);
			}
			wcr_chk_child_death(wka);
			sleep(2);
		} else {
			wka->wcr_connected = 1;
			mms_trace(MMS_DEVP, "connected");
		}
	}
	strcpy(wka->wcr_mm_host, wka->wcr_wka_net_cfg.cli_host);
	return (0);
}

void
/* LINTED: wka may be used in the future */
wcr_build_struct(mms_par_node_t *attr, wcr_DM_LM_t *DM_LM_dev, wcr_wka_t *wka)
{

	mms_par_node_t	*name;
	mms_par_node_t	*value;

	mms_list_pair_foreach(&attr->pn_arglist, name,
	    value) {
		if (strcmp("DMName",
		    name->pn_string) == 0) {
			/* mms_trace(MMS_NOTICE,"*SET DMName*\n"); */
			DM_LM_dev->wcr_DM_flag =
			    1;
			DM_LM_dev->
			    wcr_DM_LM_union.wcr_DM.
			    wcr_DM_name = mms_strapp(DM_LM_dev->
			    wcr_DM_LM_union.wcr_DM.
			    wcr_DM_name, value->pn_string);
		}
		if (strcmp("DriveName",
		    name->pn_string) == 0) {
			/* mms_trace(MMS_NOTICE, "*SET DriveName*\n"); */
			DM_LM_dev->
			    wcr_DM_LM_union.wcr_DM.
			    wcr_drive_name = mms_strapp(DM_LM_dev->
			    wcr_DM_LM_union.wcr_DM.
			    wcr_drive_name, value->pn_string);
		}
		if (strcmp("DMTargetHost",
		    name->pn_string) == 0) {
			/* mms_trace(MMS_NOTICE, "*SET Hostname*\n"); */
			DM_LM_dev->
			    wcr_host_name = mms_strapp(DM_LM_dev->
			    wcr_host_name,
			    value->pn_string);
		}
		if (strcmp("DMTargetPath",
		    name->pn_string) == 0) {
			/* mms_trace(MMS_NOTICE, "*SET Path*\n"); */
			DM_LM_dev->
			    wcr_DM_LM_union.wcr_DM.
			    wcr_dev_tar_path = mms_strapp(DM_LM_dev->
			    wcr_DM_LM_union.wcr_DM.
			    wcr_dev_tar_path,
			    value->pn_string);
		}
		if (strcmp("DMDisabled",
		    name->pn_string) == 0) {
			/* mms_trace(MMS_NOTICE, "*SET DMDisabled*\n"); */
			DM_LM_dev->
			    wcr_disabled = mms_strapp(DM_LM_dev->
			    wcr_disabled,
			    value->pn_string);
		}
		if (strcmp("LMName",
		    name->pn_string) == 0) {
			/* mms_trace(MMS_NOTICE, "*SET LMName*\n"); */
			DM_LM_dev->wcr_DM_flag =
			    0;
			DM_LM_dev->
			    wcr_DM_LM_union.wcr_LM.
			    wcr_LM_name = mms_strapp(DM_LM_dev->
			    wcr_DM_LM_union.wcr_LM.
			    wcr_LM_name,
			    value->pn_string);
		}
		if (strcmp("LMTargetHost",
		    name->pn_string) == 0) {
			/* mms_trace(MMS_NOTICE, "*SET Hostname*\n"); */
			DM_LM_dev->
			    wcr_host_name = mms_strapp(DM_LM_dev->
			    wcr_host_name,
			    value->pn_string);
		}
		if (strcmp("LibraryName",
		    name->pn_string) == 0) {
			/* mms_trace(MMS_NOTICE, "*SET LibraryName*\n"); */
			DM_LM_dev->
			    wcr_DM_LM_union.wcr_LM.
			    wcr_library_name = mms_strapp(DM_LM_dev->
			    wcr_DM_LM_union.wcr_LM.
			    wcr_library_name,
			    value->pn_string);
		}
		if (strcmp("LMDisabled",
		    name->pn_string) == 0) {
			/* mms_trace(MMS_NOTICE, "*SET LMDisabled*\n"); */
			DM_LM_dev->
			    wcr_disabled = mms_strapp(DM_LM_dev->
			    wcr_disabled,
			    value->pn_string);
		}
	}
}

/*
 * wcr_attrlist()
 *	-This function takes a parsed node tree of the attrlist portion of a
 *	resonse from MM and adds the correct struct obj to the
 *	wcr_wka_DM_LM_list in the watcher work area
 */

void
wcr_attrlist(mms_par_node_t *cmd, wcr_wka_t *wka)
{


	mms_par_node_t	*text;
	mms_par_node_t	*attr;
	mms_par_node_t	*tw;
	mms_par_node_t	*work;
	wcr_DM_LM_t	*DM_LM_dev;

	tw = 0;
	for (text = mms_pn_lookup(cmd, "text", MMS_PN_CLAUSE, &tw);
	    text != NULL;
	    text = mms_pn_lookup(cmd, "text", MMS_PN_CLAUSE, &tw)) {


		work = NULL;
		for (attr = mms_pn_lookup(text, "attrlist",
		    MMS_PN_CLAUSE, &work);
		    attr != NULL;
		    attr = mms_pn_lookup(text, "attrlist",
		    MMS_PN_CLAUSE, &work)) {


			/* Create a new list node */
#if 1

			DM_LM_dev = wcr_alloc_DM_LM();
			if (DM_LM_dev == NULL) {
				mms_trace(MMS_ERR,
				    "Unable to mallor wcr_DM_LM_t: %s",
				    strerror(errno));
				return;
			}


#else
			DM_LM_dev =
			    (wcr_DM_LM_t *)malloc(sizeof (wcr_DM_LM_t));
			if (DM_LM_dev == NULL) {
				mms_trace(MMS_ERR,
				    "Unable to mallor wcr_DM_LM_t: %s",
				    strerror(errno));
			}
			memset(DM_LM_dev, 0, sizeof (wcr_DM_LM_t));
#endif
			/* end of list create */

			wcr_build_struct(attr, DM_LM_dev, wka);

			if (strcmp(DM_LM_dev->wcr_disabled, "true") == 0) {
				free(DM_LM_dev);
			} else {
				DM_LM_dev->wcr_del_pending = 0;
				mms_list_insert_tail(&wka->wcr_wka_DM_LM_list,
				    DM_LM_dev);
			}
		}
	}
}

/*
 * wcr_create_list
 *	-takes in a "success" response in xml, creates a parse node tree
 *	and passes the tree to wcr_attrlist to perform the actall list creation
 */

int
wcr_create_list(char *response, wcr_wka_t *wka)
{

	mms_par_node_t	*cmd = NULL;
	mms_list_t		err_list;
	mms_par_err_t	*err = NULL;
	int		rc;


	rc = mms_mmp_parse(&cmd, &err_list, response);
	mms_list_foreach(&err_list, err) {
		mms_trace(MMS_ERR, "error parse, "
		    "line %d, col %d, near token \"%s\", err code %d, %s\n",
		    err->pe_line,
		    err->pe_col,
		    err->pe_token,
		    err->pe_code,
		    err->pe_msg);
	}
	mms_pe_destroy(&err_list);
	if (rc) {
		mms_trace(MMS_ERR, "Parse Error: %s",
		    strerror(errno));
		mms_pn_destroy(cmd);
		return (MMS_ERROR);
	}

	if (mms_pn_lookup(cmd, "success", MMS_PN_KEYWORD, 0) != NULL) {

		if (mms_pn_lookup(cmd, "attrlist",
		    MMS_PN_CLAUSE, NULL) != NULL) {
			wcr_attrlist(cmd, wka);
		}
		rc = SUCCESS;

	} else if (mms_pn_lookup(cmd, "unacceptable",
	    MMS_PN_KEYWORD, 0) != NULL) {

		rc = UNACCEPTABLE;

	} else if (mms_pn_lookup(cmd, "cancelled",
	    MMS_PN_KEYWORD, 0) != NULL) {

		rc = CANCELLED;

	} else {
		rc = MMS_ERROR;
	}

	mms_pn_destroy(cmd);
	return (rc);
}

/*
 * wcr_indent
 *	-subroutine used to add "level" number of tabs to the file pointed at
 *	by fp
 */
void
wcr_indent(int level, FILE *fp)
{
	int	i;
	for (i = 0; i < level; i++) {
		fprintf(fp, "    ");
	}
}

/*
 * wcr_write_DM_cfg
 *	-this function performs the actual writing of a DM's config file
 *	-It takes in a single DM_LM_dev object, opens a file and writes the
 *	config information
 *	-files are named by the instance name followed by "_cfg.xml"
 *	(ex. dm1_cfg.xml)
 */

void
wcr_write_DM_cfg(wcr_DM_LM_t *DM_LM_dev, wcr_wka_t *wka)
{


	FILE *cfg_fp = NULL;
	char *cfg_file_name = NULL;
	char *hello = mms_obfpassword(wka->wcr_wka_net_cfg.cli_pass, 0);
	char *welcome = mms_obfpassword(wka->wcr_wka_net_cfg.mm_pass, 0);


	cfg_file_name = mms_strapp(cfg_file_name, WCR_DM_LM_CONFIG_NAME,
	    DM_LM_dev->wcr_DM_LM_union.wcr_DM.wcr_DM_name);

	if ((cfg_fp = fopen(cfg_file_name, "w")) == NULL) {
		mms_trace(MMS_ERR, "Unable to write to %s\n", cfg_file_name);
	}
	fprintf(cfg_fp,
	    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n\n");
	fprintf(cfg_fp,
	    "<!-- DM Configuration -->\n");
	fprintf(cfg_fp, "<dm_cfg>\n");
	wcr_indent(1, cfg_fp);
	fprintf(cfg_fp, "<!-- Network Configuration -->\n");
	wcr_indent(1, cfg_fp);
	fprintf(cfg_fp, "<mms_network_cfg\n");
	wcr_indent(2, cfg_fp);
	fprintf(cfg_fp, "host = \"%s\"\n", wka->wcr_wka_net_cfg.cli_host);
	wcr_indent(2, cfg_fp);
	fprintf(cfg_fp, "port = \"%s\"\n", wka->wcr_wka_net_cfg.cli_port);
	wcr_indent(2, cfg_fp);
	fprintf(cfg_fp, "name = \"%s\"\n",
	    DM_LM_dev->wcr_DM_LM_union.wcr_DM.
	    wcr_drive_name);
	wcr_indent(2, cfg_fp);
	fprintf(cfg_fp, "language = \"DMP\"\n");
	wcr_indent(2, cfg_fp);
	fprintf(cfg_fp, "instance = \"%s\"\n",
	    DM_LM_dev->wcr_DM_LM_union.wcr_DM.wcr_DM_name);
	wcr_indent(2, cfg_fp);
	fprintf(cfg_fp, "password = \"%s\"\n", hello);
	wcr_indent(2, cfg_fp);
	if (welcome) {
		fprintf(cfg_fp, "mm_password = \"%s\"\n", welcome);
	}
	if (wka->wcr_wka_net_cfg.ssl_enabled) {
		wcr_indent(2, cfg_fp);
		fprintf(cfg_fp, "ssl_enabled = \"true\"\n");
		if (wka->wcr_wka_net_cfg.ssl_cert_file) {
			wcr_indent(2, cfg_fp);
			fprintf(cfg_fp, "ssl_cert_file = \"%s\"\n",
			    wka->wcr_wka_net_cfg.ssl_cert_file);
		}
		if (wka->wcr_wka_net_cfg.ssl_pass) {
			wcr_indent(2, cfg_fp);
			fprintf(cfg_fp, "ssl_pass = \"%s\"\n",
			    wka->wcr_wka_net_cfg.ssl_pass);
		}
		if (wka->wcr_wka_net_cfg.ssl_pass_file) {
			wcr_indent(2, cfg_fp);
			fprintf(cfg_fp, "ssl_pass_file = \"%s\"\n",
			    wka->wcr_wka_net_cfg.ssl_pass_file);
		}
		if (wka->wcr_wka_net_cfg.ssl_crl_file) {
			wcr_indent(2, cfg_fp);
			fprintf(cfg_fp, "ssl_crl_file = \"%s\"\n",
			    wka->wcr_wka_net_cfg.ssl_crl_file);
		}
		if (wka->wcr_wka_net_cfg.ssl_peer_file) {
			wcr_indent(2, cfg_fp);
			fprintf(cfg_fp, "ssl_peer_file = \"%s\"\n",
			    wka->wcr_wka_net_cfg.ssl_peer_file);
		}
		if (wka->wcr_wka_net_cfg.ssl_cipher) {
			wcr_indent(2, cfg_fp);
			fprintf(cfg_fp, "ssl_cipher = \"%s\"\n",
			    wka->wcr_wka_net_cfg.ssl_cipher);
		}
	} else {
		wcr_indent(2, cfg_fp);
		fprintf(cfg_fp, "ssl_enabled = \"false\"\n");
	}
	wcr_indent(1, cfg_fp);
	fprintf(cfg_fp, "/>\n\n");
	wcr_indent(1, cfg_fp);
	fprintf(cfg_fp, "<!-- DM specific config goes here -->\n");
	wcr_indent(1, cfg_fp);
	fprintf(cfg_fp, "<dev_cfg\n");
	wcr_indent(2, cfg_fp);
	fprintf(cfg_fp, "path = \"%s\"\n",
	    DM_LM_dev->wcr_DM_LM_union.wcr_DM.wcr_dev_mgr_path);
	wcr_indent(2, cfg_fp);
	fprintf(cfg_fp, "target = \"%s\"\n",
	    DM_LM_dev->wcr_DM_LM_union.wcr_DM.wcr_dev_tar_path);
	wcr_indent(1, cfg_fp);
	fprintf(cfg_fp, "/>\n");
	fprintf(cfg_fp, "</dm_cfg>\n");
	chmod(cfg_file_name, S_IRUSR);
	fclose(cfg_fp);
	free(hello);
	free(welcome);
	free(cfg_file_name);

}

/*
 * wcr_write_LM_cfg
 *	-this function performs the actual writing of a LM's config file
 *	-It takes in a single DM_LM_dev object, opens a file and writes the
 *	config information
 *	-files are named by the instance name followed by "_cfg.xml"
 *	(ex. lm1_cfg.xml)
 */

void
wcr_write_LM_cfg(wcr_DM_LM_t *DM_LM_dev, wcr_wka_t *wka)
{
	FILE *cfg_fp = NULL;
	char *cfg_file_name = NULL;
	char *hello = mms_obfpassword(wka->wcr_wka_net_cfg.cli_pass, 0);
	char *welcome = mms_obfpassword(wka->wcr_wka_net_cfg.mm_pass, 0);

	cfg_file_name = mms_strapp(cfg_file_name, WCR_DM_LM_CONFIG_NAME,
	    DM_LM_dev->wcr_DM_LM_union.wcr_LM.wcr_LM_name);

	if ((cfg_fp = fopen(cfg_file_name, "w")) == NULL) {
		mms_trace(MMS_ERR, "Unable to write to %s\n", cfg_file_name);
	}
	fprintf(cfg_fp,
	    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n\n");
	fprintf(cfg_fp,
	    "<!-- LM Configuration -->\n");
	fprintf(cfg_fp, "<mms_cfg>\n");
	wcr_indent(1, cfg_fp);
	fprintf(cfg_fp, "<!-- Network Configuration -->\n");
	wcr_indent(1, cfg_fp);
	fprintf(cfg_fp, "<mms_network_cfg\n");
	wcr_indent(2, cfg_fp);
	fprintf(cfg_fp, "host = \"%s\"\n", wka->wcr_wka_net_cfg.cli_host);
	wcr_indent(2, cfg_fp);
	fprintf(cfg_fp, "port = \"%s\"\n", wka->wcr_wka_net_cfg.cli_port);
	wcr_indent(2, cfg_fp);
	fprintf(cfg_fp, "name = \"%s\"\n",
	    DM_LM_dev->wcr_DM_LM_union.wcr_LM.wcr_library_name);
	wcr_indent(2, cfg_fp);
	fprintf(cfg_fp, "language = \"LMP\"\n");
	wcr_indent(2, cfg_fp);
	fprintf(cfg_fp, "instance = \"%s\"\n",
	    DM_LM_dev->wcr_DM_LM_union.wcr_LM.wcr_LM_name);
	wcr_indent(2, cfg_fp);
	fprintf(cfg_fp, "password = \"%s\"\n", hello);
	wcr_indent(2, cfg_fp);
	if (welcome) {
		fprintf(cfg_fp, "mm_password = \"%s\"\n", welcome);
	}
	if (wka->wcr_wka_net_cfg.ssl_enabled) {
		wcr_indent(2, cfg_fp);
		fprintf(cfg_fp, "ssl_enabled = \"true\"\n");
		if (wka->wcr_wka_net_cfg.ssl_cert_file) {
			wcr_indent(2, cfg_fp);
			fprintf(cfg_fp, "ssl_cert_file = \"%s\"\n",
			    wka->wcr_wka_net_cfg.ssl_cert_file);
		}
		if (wka->wcr_wka_net_cfg.ssl_pass) {
			wcr_indent(2, cfg_fp);
			fprintf(cfg_fp, "ssl_pass = \"%s\"\n",
			    wka->wcr_wka_net_cfg.ssl_pass);
		}
		if (wka->wcr_wka_net_cfg.ssl_pass_file) {
			wcr_indent(2, cfg_fp);
			fprintf(cfg_fp, "ssl_pass_file = \"%s\"\n",
			    wka->wcr_wka_net_cfg.ssl_pass_file);
		}
		if (wka->wcr_wka_net_cfg.ssl_crl_file) {
			wcr_indent(2, cfg_fp);
			fprintf(cfg_fp, "ssl_crl_file = \"%s\"\n",
			    wka->wcr_wka_net_cfg.ssl_crl_file);
		}
		if (wka->wcr_wka_net_cfg.ssl_peer_file) {
			wcr_indent(2, cfg_fp);
			fprintf(cfg_fp, "ssl_peer_file = \"%s\"\n",
			    wka->wcr_wka_net_cfg.ssl_peer_file);
		}
		if (wka->wcr_wka_net_cfg.ssl_cipher) {
			wcr_indent(2, cfg_fp);
			fprintf(cfg_fp, "ssl_cipher = \"%s\"\n",
			    wka->wcr_wka_net_cfg.ssl_cipher);
		}
	} else {
		wcr_indent(2, cfg_fp);
		fprintf(cfg_fp, "ssl_enabled = \"false\"\n");
	}
	wcr_indent(1, cfg_fp);
	fprintf(cfg_fp, "/>\n");
	fprintf(cfg_fp, "</mms_cfg>\n");
	chmod(cfg_file_name, S_IRUSR);
	fclose(cfg_fp);
	free(hello);
	free(welcome);
	free(cfg_file_name);
}

/*
 * wcr_write_cfg
 *	-takes in the watcher's workarea
 *	-calls the approperate config write function
 */

int
wcr_write_cfg(wcr_wka_t *wka)
{
	wcr_DM_LM_t	*DM_LM_dev;
	mms_trace(MMS_NOTICE, "Writing  CFG Files");
	mms_list_foreach(&wka->wcr_wka_DM_LM_list, DM_LM_dev) {

		if (DM_LM_dev->wcr_DM_flag) {
			wcr_write_DM_cfg(DM_LM_dev, wka);
		} else {
			wcr_write_LM_cfg(DM_LM_dev, wka);
		}
	}
	return (0);
}
void
wcr_add_event(mms_par_node_t *cmd, wcr_wka_t *wka) {

	mms_par_node_t	*arg;
	mms_par_node_t	*work;
	mms_par_node_t	*value;

	char		*old_inst_name = NULL;
	char		*new_inst_name = NULL;
	char		*type = NULL;
	char		*object = NULL;
	char		*inst_name = NULL;

	wcr_event_t	*event_struct = NULL;

	int		debug = 0;

	if (mms_pn_lookup(cmd, "event",
	    MMS_PN_CMD, 0) != NULL) {
		if (debug) {
			mms_trace(MMS_NOTICE, "event"); }
		arg = mms_pn_lookup(cmd, "config",
					MMS_PN_CLAUSE, 0);
		if (arg) {
			if (debug) {
				mms_trace(MMS_NOTICE, " config"); }
		}
		work = NULL;
		if (arg && (value
			    = mms_pn_lookup(arg, NULL,
						MMS_PN_STRING,
						&work))) {
			if (debug) {
				mms_trace(MMS_NOTICE, "  object %s",
					value->pn_string); }

			object = value->pn_string;
		}
		if (arg && (value = mms_pn_lookup(arg,
						    NULL,
						    MMS_PN_STRING,
						    &work))) {
			if (debug) {
				mms_trace(MMS_NOTICE, "  type %s",
					value->pn_string); }

			type = value->pn_string;
		}
		if (arg && strcmp(value->pn_string, "change")
		    == 0) {
			if (value = mms_pn_lookup(arg, NULL,
						    MMS_PN_STRING,
						    &work)) {
				if (debug) {
					mms_trace(MMS_NOTICE,
					    "  new instance %s",
						value->pn_string); }

				new_inst_name = value->pn_string;
			}
			if (value && (value =
					mms_pn_lookup(arg,
							NULL,
							MMS_PN_STRING,
							&work))) {

				if (debug) {
					mms_trace(MMS_NOTICE,
					    "  old instance %s",
						value->pn_string); }

				old_inst_name = value->pn_string;
			}
		} else if (arg && (value =
				    mms_pn_lookup(arg, NULL,
						    MMS_PN_STRING,
						    &work))) {
			if (debug) {
				mms_trace(MMS_NOTICE, "  instance %s",
					value->pn_string); }
			inst_name = value->pn_string;
		}

	}
	event_struct =
		(wcr_event_t *)malloc(sizeof (wcr_event_t));
	if (event_struct == NULL) {
		mms_trace(MMS_ERR,
			"Unable to malloc wcr_event_t: %s",
			strerror(errno));
	}
	memset(event_struct, 0, sizeof (wcr_event_t));

	if (old_inst_name != NULL) {
		strlcpy(event_struct->wcr_old_inst_name, old_inst_name,
			sizeof (event_struct->wcr_old_inst_name)); }
	if (new_inst_name != NULL) {
		strlcpy(event_struct->wcr_new_inst_name, new_inst_name,
			sizeof (event_struct->wcr_new_inst_name)); }
	if (type != NULL) {
		strlcpy(event_struct->wcr_type, type,
			sizeof (event_struct->wcr_type)); }
	if (object != NULL) {
		strlcpy(event_struct->wcr_object, object,
			sizeof (event_struct->wcr_object)); }
	if (inst_name != NULL) {
		strlcpy(event_struct->wcr_inst_name, inst_name,
			sizeof (event_struct->wcr_inst_name)); }
	event_struct->wcr_done = 0;

	mms_list_insert_tail(&wka->wcr_events, event_struct);

}
/*
 * wcr_send_cmd
 *	-Takes a command string to send to MM and the watcher's work area
 *	-Coverts the command to xml
 *	-sends the command to MM using MM's filedescriptor and mms_writer
 *	-reads the response from MM using mms_reader
 *	-returns the second protion of the response ("success" half)
 */

char *
wcr_send_cmd(char *cmd_str, wcr_wka_t *wka)
{
	mms_par_node_t	*cmd = NULL;
	mms_list_t		err_list;
	int		len;
	char		*rsp = NULL;
	mms_par_err_t	*err = NULL;
	int		go = 1;
	int		rc;

	len = strlen(cmd_str);
	if (mms_writer(&wka->wcr_mms_conn,
	    cmd_str) != len) {
		mms_get_error_string(&wka->wcr_mms_err, wka->wcr_mms_ebuf,
		    MMS_EBUF_LEN);
		mms_trace(MMS_ERR, "mms_writer, "
		    "Write cmd failed: %s, %s",
		    strerror(errno), wka->wcr_mms_ebuf);
		mms_close(&wka->wcr_mms_conn);
		return (NULL);
	}
	mms_trace(MMS_INFO, "cmd is %s", cmd_str);
	while (go) {
		rsp = NULL;
		if (mms_reader(&wka->wcr_mms_conn, &rsp) <= 0) {
			mms_get_error_string(&wka->wcr_mms_err,
			    wka->wcr_mms_ebuf,
			    MMS_EBUF_LEN);
			mms_trace(MMS_ERR, "mms_reader,"
			    " Read cmd response failed: %s, %s",
			    strerror(errno), wka->wcr_mms_ebuf);
			mms_close(&wka->wcr_mms_conn);
			return (NULL);
		}
		mms_trace(MMS_DEBUG, "Read : %s", rsp);

		rc = mms_mmp_parse(&cmd, &err_list, rsp);
		mms_list_foreach(&err_list, err) {
			mms_trace(MMS_ERR, "error parse, "
			    "line %d, col %d, near token \"%s\", "\
			    "err code %d, %s\n",
			    err->pe_line,
			    err->pe_col,
			    err->pe_token,
			    err->pe_code,
			    err->pe_msg);
		}
		if (rc) {
			mms_trace(MMS_ERR, "Parse Error: %s",
			    strerror(errno));
			mms_pn_destroy(cmd);
			return (NULL);
		}
		if (mms_pn_lookup(cmd, "event",
		    MMS_PN_CMD, 0) != NULL) {
			wcr_add_event(cmd, wka);
			mms_pn_destroy(cmd);
			continue;
		}

		if (mms_pn_lookup(cmd,
		    "response", MMS_PN_CMD, 0)
		    == NULL) {
			mms_trace(MMS_ERR,
			    "Error- no command response to show: %s",
			    strerror(errno));
			mms_pn_destroy(cmd);
			return (NULL);
		}
		if (mms_pn_lookup(cmd,
		    "accepted", MMS_PN_KEYWORD, 0) != NULL) {
			mms_trace(MMS_DEBUG, "Command accepted");
			mms_pn_destroy(cmd);
		} else if (mms_pn_lookup(cmd,
		    "success", MMS_PN_KEYWORD, 0) != NULL) {
			mms_trace(MMS_DEBUG, "Command success");
			mms_pn_destroy(cmd);
			go = 0;
		}

	}
	return (rsp);
}

/*
 * wcr_get_config
 *	-takes in the watcher's workarea
 *	-creates a linked list of all DM and LM that are to be running
 *	on this watcher's host
 */



int
wcr_get_config(wcr_wka_t *wka)
{

	char		*cmd_str = NULL;
	char		*response = NULL;
	wcr_DM_LM_t	*DM_LM_dev = NULL;

	int num_dev = 0;
	/* generate show command for current WD host */

	/*  For DM's */
	cmd_str = mms_strapp(cmd_str, SHOW_DM_CMD_STRING, wka->wcr_host_name);

	if ((response = wcr_send_cmd(cmd_str, wka)) == NULL) {
		mms_trace(MMS_ERR,
		    "Error sending show command");
		free(cmd_str);
		return (1);
	}

	if (wcr_create_list(response, wka) == MMS_ERROR) {
		mms_trace(MMS_ERR,
		    "wcr_get_config: "
		    "internal error creating wka list");
	}

	mms_list_foreach(&wka->wcr_wka_DM_LM_list, DM_LM_dev) {

		DM_LM_dev->wcr_DM_LM_union.wcr_DM.wcr_dev_mgr_path =
		    mms_strapp(DM_LM_dev->
		    wcr_DM_LM_union.wcr_DM.wcr_dev_mgr_path,
		    WCR_DEV_MGR_PATH, num_dev+1);
		DM_LM_dev->wcr_DM_LM_union.wcr_DM.wcr_dev_number = num_dev+1;

		num_dev ++;


	}
	free(cmd_str);
	cmd_str = NULL;

	/* For LM's */
	cmd_str = mms_strapp(cmd_str, SHOW_LM_CMD_STRING, wka->wcr_host_name);

	if ((response = wcr_send_cmd(cmd_str, wka)) == NULL) {
		mms_trace(MMS_ERR, "Error sending lm show command");
		free(cmd_str);
		return (1);
	}
	if (wcr_create_list(response, wka) == MMS_ERROR) {
		mms_trace(MMS_ERR,
		    "wcr_get_config: "
		    "internal error creating wka list");
	}


	free(cmd_str);
	return (0);
}

/* Free a single net lm */
/* caller needs to free net_lm itself */
void
wcr_free_net_lm(wcr_net_LM_t *net_LM) {
	if (net_LM->wcr_lm_name)
		free(net_LM->wcr_lm_name);
}

/* Free all net_LM in the list */
void
wcr_free_all_ssi(wcr_wka_t *wka) {

	wcr_net_LM_t	*cur_net_LM;
	wcr_net_LM_t	*next_net_LM;

	for (cur_net_LM = mms_list_head(&wka->wcr_net_LM_list);
	    cur_net_LM != NULL;
	    cur_net_LM = next_net_LM) {
		next_net_LM =
		    mms_list_next(&wka->wcr_net_LM_list,
		    cur_net_LM);
		mms_list_remove(&wka->wcr_net_LM_list,
		    cur_net_LM);
		wcr_free_net_lm(cur_net_LM);
		free(cur_net_LM);
		cur_net_LM = NULL;
	}

}


/*
 * wcr_set_ssi:
 *	either insert this net_LM in the list
 *	or set an existing net_LM in the list
 *	to the values in the new net_LM
 */
int
wcr_set_ssi(wcr_wka_t *wka, wcr_net_LM_t *net_LM) {
	wcr_net_LM_t	*cur_net_LM;

	/* Check list to see if there is already a */
	/* net_LM for this lm */
	/* If so, set the ssi info on that and free net_LM */
	mms_list_foreach(&wka->wcr_net_LM_list,
	    cur_net_LM) {
		if (strcmp(cur_net_LM->wcr_lm_name,
		    net_LM->wcr_lm_name) == 0) {
			/* already have this LM */
			cur_net_LM->wcr_ssi_port =
			    net_LM->wcr_ssi_port;
			cur_net_LM->wcr_acsls_port =
			    net_LM->wcr_acsls_port;
			return (1);
		}
	}
	mms_list_insert_tail(&wka->wcr_net_LM_list,
	    net_LM);
	return (0);
}

/*
 * wcr_check_ssi
 *	looks at the current ssi list,
 *	if 2 lm's are set to use the same
 *	ssi port, but have different libraryip's
 *	send a message and return error
 */

int
wcr_check_ssi(wcr_wka_t *wka, wcr_net_LM_t *net_LM) {
	wcr_net_LM_t	*cur_net_LM = NULL;
	char 		*cmd_str = NULL;
	char 		*response = NULL;


	mms_list_foreach(&wka->wcr_net_LM_list, cur_net_LM) {
		if ((cur_net_LM->wcr_ssi_port ==
		    net_LM->wcr_ssi_port) &&
		    (strcmp(cur_net_LM->wcr_ssi_host,
		    net_LM->wcr_ssi_host) != 0)) {
			/* same ssi port and different hosts */
			mms_trace(MMS_ERR,
			    "wcr_check_ssi: "
			    "Conflicting ssi configuration, "
			    "same ssi port but different hosts: "
			    "%s %d %s , %s %d %s",
			    net_LM->wcr_lm_name,
			    net_LM->wcr_ssi_port,
			    net_LM->wcr_ssi_host,
			    cur_net_LM->wcr_lm_name,
			    cur_net_LM->wcr_ssi_port,
			    cur_net_LM->wcr_ssi_host);
			/* Send message 8000 */
			/* generate show command for current WD host */
			cmd_str = mms_strapp(cmd_str,
			    WCR_SSI_ERR_MSG,
			    wka->wcr_host_name,
			    net_LM->wcr_lm_name,
			    net_LM->wcr_ssi_port,
			    net_LM->wcr_ssi_host,
			    cur_net_LM->wcr_lm_name,
			    cur_net_LM->wcr_ssi_port,
			    cur_net_LM->wcr_ssi_host);
			/* Send MMP command to MM */
			if ((response = wcr_send_cmd(cmd_str, wka))
			    == NULL) {
				mms_trace(MMS_ERR,
				    "Error sending ssi error message");
			} else {
				free(response);
			}
			free(cmd_str);
			return (1);
		}
	}
	free(cmd_str);
	return (0);
}

/*
 * wcr_get_ssi
 *	-takes in the watcher's workarea
 *	-obtains the acsls's servers hostname from MM
 *	-if lm_name is NULL get ssi for the whole host
 *	-else get ssi info for just that lm
 */

/* ARGSUSED */
int
wcr_get_ssi(wcr_wka_t *wka, char *lm_name)
{

	/* Get SSI infor for this host */
	/* There may be more than one LM */


	int		rc;

	mms_par_node_t	*text_work = NULL;
	mms_par_node_t	*text_arg = NULL;
	mms_par_node_t	*lib_work = NULL;
	mms_par_node_t	*lib_arg = NULL;

	char 		*cmd_str = NULL;
	char 		*response = NULL;

	mms_list_t		err_list;
	mms_par_err_t	*err = NULL;
	mms_par_node_t	*cmd = NULL;

	char *cur_lmname = NULL;
	char *cur_libraryip = NULL;
	char *cur_acslsport = NULL;
	char *cur_ssiport = NULL;

	wcr_net_LM_t *net_LM = NULL;

	/* generate show command for current WD host */
	if (lm_name == NULL) {
		/* Get SSI for all LM's */
		/* delete the SSI list */
		cmd_str = mms_strapp(cmd_str,
		    SHOW_LM_SSI_STRING,
		    wka->wcr_host_name);
		wcr_free_all_ssi(wka);
	} else {
		cmd_str = mms_strapp(cmd_str,
		    SHOW_LM_SSI_STRING_NAME,
		    wka->wcr_host_name, lm_name);
	}
	/* Send MMP command to MM */
	if ((response = wcr_send_cmd(cmd_str, wka)) == NULL) {
		mms_trace(MMS_ERR,
		    "Error sending lm ssi show command");
		free(cmd_str);
		return (1);
	}
	/* Parse the response */
	rc = mms_mmp_parse(&cmd, &err_list, response);
	mms_list_foreach(&err_list, err) {
		mms_trace(MMS_ERR, "error parse, "
		    "line %d, col %d, near token \"%s\", err code %d, %s\n",
		    err->pe_line,
		    err->pe_col,
		    err->pe_token,
		    err->pe_code,
		    err->pe_msg);
	}
	mms_pe_destroy(&err_list);
	if (rc) {
		mms_trace(MMS_ERR, "Parse Error: %s", strerror(errno));
		mms_pn_destroy(cmd);
		free(cmd_str);
		return (1);
	}

	/* Check for success */
	if (mms_pn_lookup(cmd, "success", MMS_PN_KEYWORD, 0) == NULL) {
		mms_trace(MMS_ERR, "wcr_get_ssi did not get a successful "
		    "response: %s", strerror(errno));
		free(cmd_str);
		return (1);
	}
	/* For each text returned, create a wcr_net_LM struct */
	/* If there is already an existing wcr_net_LM with the same info */
	/* Don't make a duplicate */

	text_work = NULL;
	for (text_arg = mms_pn_lookup_arg(cmd, "text", NULL, &text_work);
	    text_arg != NULL;
	    text_arg = mms_pn_lookup_arg(cmd, "text", NULL, &text_work)) {

		if (cur_lmname)
			free(cur_lmname);
		if (cur_libraryip)
			free(cur_libraryip);
		if (cur_acslsport)
			free(cur_acslsport);
		if (cur_ssiport)
			free(cur_ssiport);
		cur_lmname = NULL;
		cur_libraryip = NULL;
		cur_acslsport = NULL;
		cur_ssiport = NULL;

		/* Get LMName */
		lib_work = NULL;
		if (mms_pn_lookup_arg(text_arg, "LMName",
		    NULL, &lib_work) == NULL) {
			mms_trace(MMS_ERR,
			    "wcr_get_ssi: "
			    "unable to find LMName in response");
			continue;
		}
		if ((lib_arg = mms_pn_lookup_arg(text_arg, NULL,
		    NULL, &lib_work)) == NULL) {
			mms_trace(MMS_ERR,
			    "wcr_get_ssi: "
			    "unable to find LMName in response");
			continue;
		}
		cur_lmname = strdup(lib_arg->pn_string);

		/* Get LibraryIP */
		lib_work = NULL;
		if (mms_pn_lookup_arg(text_arg, "LibraryIP",
		    NULL, &lib_work) == NULL) {
			mms_trace(MMS_ERR,
			    "wcr_get_ssi: "
			    "unable to find LibraryIP in response");
			continue;
		}
		if ((lib_arg = mms_pn_lookup_arg(text_arg, NULL,
		    NULL, &lib_work)) == NULL) {
			mms_trace(MMS_ERR,
			    "wcr_get_ssi: "
			    "unable to find LibraryIP in response");
			continue;
		}
		cur_libraryip = strdup(lib_arg->pn_string);

		/* Get LibraryACSLSPort */
		lib_work = NULL;
		if (mms_pn_lookup_arg(text_arg, "LibraryACSLSPort",
		    NULL, &lib_work) == NULL) {
			mms_trace(MMS_ERR,
			    "wcr_get_ssi: "
			    "unable to find LibraryACSLSPort in response");
			continue;
		}
		if ((lib_arg = mms_pn_lookup_arg(text_arg, NULL,
		    NULL, &lib_work)) == NULL) {
			mms_trace(MMS_ERR,
			    "wcr_get_ssi: "
			    "unable to find LibraryACSLSPort in response");
			continue;
		}
		cur_acslsport = strdup(lib_arg->pn_string);

		/* Get LMSSIPort */
		lib_work = NULL;
		if (mms_pn_lookup_arg(text_arg, "LMSSIPort",
		    NULL, &lib_work) == NULL) {
			mms_trace(MMS_ERR,
			    "wcr_get_ssi: "
			    "unable to find LMSSIPort in response");
			continue;
		}
		if ((lib_arg = mms_pn_lookup_arg(text_arg, NULL,
		    NULL, &lib_work)) == NULL) {
			mms_trace(MMS_ERR,
			    "wcr_get_ssi: "
			    "unable to find LMSSIPort in response");
			continue;
		}
		cur_ssiport = strdup(lib_arg->pn_string);


		if ((cur_lmname == NULL) ||
		    (cur_libraryip == NULL) ||
		    (cur_acslsport == NULL) ||
		    (cur_ssiport == NULL)) {
			mms_trace(MMS_ERR,
			    "wcr_get_ssi: "
			    "unable to get ACSLS/SSI "
			    "info from MM");
			continue;
		}
		mms_trace(MMS_DEVP,
		    "wcr_get_ssi:"
		    "ssi needed for %s, acsls ip=%s, acsls port=%s,"
		    " ssi port=%s",
		    cur_lmname, cur_libraryip, cur_acslsport,
		    cur_ssiport);
		/* Allocate a new struct for this ssi info */

		net_LM = NULL;
		net_LM = (wcr_net_LM_t *)calloc(1, sizeof (wcr_net_LM_t));
		if (net_LM == NULL) {
			mms_trace(MMS_ERR,
			    "wcr_get_ssi: "
			    "unable to calloc net_LM");
			continue;
		}
		/* Set values in net_LM */
		strcpy(net_LM->wcr_ssi_host, cur_libraryip);
		net_LM->wcr_ssi_port = atoi(cur_ssiport);
		if (strcmp(cur_acslsport, "") == 0) {
			net_LM->wcr_acsls_port = -1;
		} else {
			net_LM->wcr_acsls_port =
			    atoi(cur_acslsport);
		}
		net_LM->wcr_lm_name = cur_lmname;
		cur_lmname = NULL;
		/* insert net_LM into the list */
		/* Before insert check if this host already has an */
		/* ssi setup to run on cur_ssiport */
		/* If yes, send a message to MM indicating an incorrect */
		/* configuration */

		if (wcr_check_ssi(wka, net_LM)) {
			mms_trace(MMS_ERR,
			    "wcr_get_ssi: "
			    "incorrect ssi configuration, "
			    "do not attempt to start this ssi");
			wcr_free_net_lm(net_LM);
			free(net_LM);
			net_LM = NULL;
		} else {
			if (wcr_set_ssi(wka, net_LM)) {
				/* already had this net_LM */
				wcr_free_net_lm(net_LM);
				free(net_LM);
				net_LM = NULL;
			}

		}


	}

	/* Clean up memory */
	if (cur_lmname)
		free(cur_lmname);
	if (cur_libraryip)
		free(cur_libraryip);
	if (cur_acslsport)
		free(cur_acslsport);
	if (cur_ssiport)
		free(cur_ssiport);
	cur_lmname = NULL;
	cur_libraryip = NULL;
	cur_acslsport = NULL;
	cur_ssiport = NULL;
	mms_trace(MMS_DEVP,
	    "wcr_get_ssi:"
	    "finished getting ssi info");
	free(cmd_str);
	return (0);
}

/*
 * Configure drive and library managers
 * wcr_config()
 *	-Takes in the a watcher's workarea
 *	-creates a list of wcr_dev type that will be used to start DMs
 *	-writes config files for every DM and LM that is to be running
 *	on this watcher 's host
 */

int
wcr_config(wcr_wka_t *wka)
{
	wcr_DM_LM_t	*DM_LM_dev;

	/*
	 * Configure devices
	 */

	mms_list_foreach(&wka->wcr_wka_DM_LM_list, DM_LM_dev) {
		if (DM_LM_dev->wcr_DM_flag) {
			/*
			 * Verify the target device exists
			 */

			if (ioctl(wka->wcr_wka_fd, WCR_ADD_DEV,
			    wka->wcr_wka_next_ordinal) < 0) {
				mms_trace(MMS_ERR,
				    "Unable to add device %s, ordinal %d",
				    DM_LM_dev->
				    wcr_DM_LM_union.
				    wcr_DM.wcr_dev_tar_path,
				    wka->wcr_wka_next_ordinal);
			}
			/* dv->wcr_dev_flags |= WCR_DEV_START; */
			DM_LM_dev->wcr_DM_LM_union.wcr_DM.wcr_dev_ordinal
			    = wka->wcr_wka_next_ordinal;

			mms_trace(MMS_NOTICE, "For %s Ordinal is %d",
			    DM_LM_dev->
			    wcr_DM_LM_union.wcr_DM.wcr_DM_name,
			    DM_LM_dev->
			    wcr_DM_LM_union.wcr_DM.wcr_dev_ordinal);


			wka->wcr_wka_next_ordinal++;
		}
	}


	/*  Write the DM and LM config info to file */

	if (wcr_write_cfg(wka)) {
		mms_trace(MMS_ERR, "Unable to write cfg file");
		exit(1);
	}

	return (0);



}

void
wcr_prefork(wcr_wka_t *wka)
{
	int	rc;

	/*
	 * Setup separate contract for forked process
	 */
	if (wka->wcr_cfd == -1) {
		wka->wcr_cfd = open64(CTFS_ROOT "/process/template", O_RDWR);
		if (wka->wcr_cfd < 0) {
			mms_trace(MMS_ERR, "contract template open %s",
			    strerror(errno));
			return;
		}
		if (rc = ct_pr_tmpl_set_param(wka->wcr_cfd, CT_PR_PGRPONLY)) {
			mms_trace(MMS_ERR, "contract template set param %s",
			    strerror(rc));
			goto prefork_error;
		}
		if (rc = ct_tmpl_set_informative(wka->wcr_cfd,
		    CT_PR_EV_HWERR)) {
			mms_trace(MMS_ERR, "contract template set info %s",
			    strerror(rc));
			goto prefork_error;
		}
		if (rc = ct_pr_tmpl_set_fatal(wka->wcr_cfd, CT_PR_EV_HWERR)) {
			mms_trace(MMS_ERR, "contract template set fatal %s",
			    strerror(rc));
			goto prefork_error;
		}
		if (rc = ct_tmpl_set_critical(wka->wcr_cfd, CT_PR_EV_HWERR)) {
			mms_trace(MMS_ERR, "contract template set critical %s",
			    strerror(rc));
			goto prefork_error;
		}
	}
	if (rc = ct_tmpl_activate(wka->wcr_cfd)) {
		mms_trace(MMS_ERR, "contract template activate %s",
		    strerror(rc));
		goto prefork_error;
	}
	return;

prefork_error:
	if (wka->wcr_cfd >= 0)
		close(wka->wcr_cfd);
	wka->wcr_cfd = -1;
}

void
wcr_child_postfork(wcr_wka_t *wka)
{
	int	rc;

	/*
	 * Clear contract
	 */
	if (wka->wcr_cfd < 0) {
		mms_trace(MMS_ERR, "contract not open");
		return;
	}

	if (rc = ct_tmpl_clear(wka->wcr_cfd)) {
		mms_trace(MMS_ERR, "contract clear %s", strerror(rc));
	}
	close(wka->wcr_cfd);
}

void
wcr_parent_postfork(wcr_wka_t *wka, pid_t pid)
{
	int		rc;
	int		fd;
	char		path[PATH_MAX];
	ct_stathdl_t	st;
	ctid_t		latest;

	/*
	 * Abandon forked process contract
	 */
	if (wka->wcr_cfd < 0) {
		mms_trace(MMS_ERR, "contract not open");
		return;
	}

	if (rc = ct_tmpl_clear(wka->wcr_cfd)) {
		mms_trace(MMS_ERR, "contract clear %s", strerror(rc));
	}

	if (pid == -1) {
		mms_trace(MMS_ERR, "contract fork failed");
		return;
	}

	if ((fd = open64(CTFS_ROOT "/process/latest", O_RDONLY)) < 0) {
		mms_trace(MMS_ERR, "contract latest open %s", strerror(rc));
		return;
	}
	if (rc = ct_status_read(fd, CTD_COMMON, &st)) {
		mms_trace(MMS_ERR, "contract status read %s", strerror(rc));
		close(fd);
		return;
	}
	latest = ct_status_get_id(st);
	ct_status_free(st);
	(void) close(fd);

	snprintf(path, PATH_MAX, CTFS_ROOT "/all/%ld/ctl", latest);
	if ((fd = open64(path, O_WRONLY)) < 0) {
		mms_trace(MMS_ERR, "contract latest write open %s",
		    strerror(errno));
		return;
	}
	if (rc = ct_ctl_abandon(fd)) {
		mms_trace(MMS_ERR, "contract abandon", strerror(rc));
	}
	close(fd);
}

/*
 * wcr_exec_dm
 *	-This perfoms the fork and exec operations necessary to start a DM
 *	-It takes in the watcher work area and a wcr_dev_t dv on the DM to
 *	start
 */


void
wcr_exec_dm(wcr_wka_t *wka, wcr_DM_LM_t *DM_LM_dev)
{
	pid_t	pid;
	char	*cfg_name = NULL;
	char	*cmd_name = NULL;

	wcr_prefork(wka);
	if (pid = fork()) {
		wcr_parent_postfork(wka, pid);
		if (pid == (pid_t)(-1)) {
			/* Fork error */
			mms_trace(MMS_ERR, "Fork error for device : ");
			return;
		} else {
			/* In parent. Save dm's pid */
			DM_LM_dev->wcr_dev_pid = pid;
		}
	} else {
		wcr_child_postfork(wka);
		/*
		 * In child process.
		 * Close the watcher device.
		 */

		close(wka->wcr_wka_fd);

		/*
		 * Exec the drive/lib manager
		 */
		cfg_name = mms_strapp(cfg_name,
		    WCR_DM_LM_CONFIG_NAME,
		    DM_LM_dev->wcr_DM_LM_union.wcr_DM.wcr_DM_name);
		mms_trace(MMS_NOTICE, "EXEC a  DM - %s",
		    DM_LM_dev->wcr_DM_LM_union.wcr_DM.wcr_DM_name);
		cmd_name = mms_strapp(cmd_name,
		    WCR_DEV_MGR_PROG, "mmsdm");
		if (execl(cmd_name, cmd_name,
		    cfg_name, (char *)0)) {
			/* Can't exec the drive/lib manager */

			mms_trace(MMS_ERR, "Unable to execute program %s",
			    cmd_name);
			free(cmd_name);
			free(cfg_name);
			exit(-1);

		}
		free(cmd_name);
		free(cfg_name);
	}
}

void
wcr_exec_lm(wcr_wka_t *wka, wcr_DM_LM_t *DM_LM_dev)
{
	pid_t	pid;
	char	*cfg_name = NULL;
	char	*cmd_name = NULL;

	wcr_prefork(wka);
	if (pid = fork()) {
		wcr_parent_postfork(wka, pid);
		if (pid == (pid_t)(-1)) {
			/* Fork error */
			mms_trace(MMS_ERR, "Fork error for device : ");
			return;
		} else {
			/* In parent. Save lm's pid */
			DM_LM_dev->wcr_dev_pid = pid;
		}
	} else {
		wcr_child_postfork(wka);
		/*
		 * In child process.
		 * Close the watcher device.
		 */

		close(wka->wcr_wka_fd);

		/*
		 * Exec the drive/lib manager
		 */
		cfg_name = mms_strapp(cfg_name,
		    WCR_DM_LM_CONFIG_NAME,
		    DM_LM_dev->wcr_DM_LM_union.wcr_LM.wcr_LM_name);
		mms_trace(MMS_NOTICE, "EXEC a  LM - %s",
		    DM_LM_dev->wcr_DM_LM_union.wcr_LM.wcr_LM_name);
		cmd_name = mms_strapp(cmd_name,
		    WCR_DEV_MGR_PROG, "mmslm");
		if (execl(cmd_name, cmd_name,
		    cfg_name, (char *)0)) {
			/* Can't exec the drive/lib manager */

			mms_trace(MMS_ERR, "Unable to execute program %s",
			    cmd_name);
			free(cfg_name);
			free(cmd_name);
			exit(-1);

		}
		free(cfg_name);
		free(cmd_name);
	}
}


void
wcr_exec_ssi(wcr_wka_t *wka, wcr_net_LM_t *net_LM)
{
	pid_t	pid;
	char	*env_acs_hostname = NULL;
	char	*env_ssi_port = NULL;
	char	*env_acsls_port = NULL;
	char	*env_ssi_path = NULL;
	char	*cmd_name = NULL;
	char	*equ = NULL;

	int	proc;

	int	ssi_port = 0;


	char *ssi_path = NULL;

	/* Get SSI path from smf */
	if ((ssi_path = mms_cfg_alloc_getvar(MMS_CFG_SSI_PATH, NULL)) == NULL) {
		/* report service configuration repoistory scf_error() */
		mms_trace(MMS_ERR, "using default-path, ssi path cfg error");
		ssi_path = strdup("/opt/mms/bin/acsls");
	}


	mms_trace(MMS_DEVP,
	    "wcr_exec_ssi: "
	    "ssi for %s, acsls ip=%s, acsls port=%d,"
	    " ssi port=%d, ssi path=%s",
	    net_LM->wcr_lm_name,
	    net_LM->wcr_ssi_host,
	    net_LM->wcr_acsls_port,
	    net_LM->wcr_ssi_port,
	    ssi_path);


	if (net_LM->wcr_ssi_host[0] == '\0') {
		mms_trace(MMS_DEBUG, "No ssi configured on host %s",
		    wka->wcr_host_name);
		free(ssi_path);
		return;
	}

	if (wcr_ssi_is_running("ssi", &proc,
	    net_LM->wcr_ssi_port)) {

		if (proc == net_LM->wcr_dev_pid) {
			mms_trace(MMS_NOTICE, "ssi is required and "
			    "already running from previous start: "
			    "pid = %d, port=%d", proc,
			    net_LM->wcr_ssi_port);
		} else {
			mms_trace(MMS_NOTICE, "ssi is required, "
			    "but is already running: "
			    "pid = %d, port=%d",
			    proc, net_LM->wcr_ssi_port);
		}
		free(ssi_path);
		return;
	}

	mms_trace(MMS_OPER, "SSI configured to run on host %s, port %d",
	    net_LM->wcr_ssi_host,
	    net_LM->wcr_ssi_port);
	/* Set ACSLS Server Host */
	mms_trace(MMS_OPER,
	    "CSI_HOSTNAME = %s",
	    net_LM->wcr_ssi_host);
	env_acs_hostname = mms_strapp(env_acs_hostname,
	    "CSI_HOSTNAME=%s",
	    net_LM->wcr_ssi_host);
	putenv(env_acs_hostname);

	/* Set ACSLS Server port */
	if (net_LM->wcr_acsls_port != -1) {
		mms_trace(MMS_OPER,
		    "CSI_HOSTPORT = %d",
		    net_LM->wcr_acsls_port);
		env_acsls_port = mms_strapp(env_acsls_port,
		    "CSI_HOSTPORT=%d",
		    net_LM->wcr_acsls_port);
		putenv(env_acsls_port);
	} else {
		mms_trace(MMS_OPER,
		    "ACSLS server port not set, "
		    "ssi will use default "
		    "from portmapper");
	}

	/* Get the ACLS port number from MM */
	/* Pass the port number as an argument to t_ssi.sh */
	ssi_port = net_LM->wcr_ssi_port;
	if (ssi_port == 0) {
		mms_trace(MMS_ERR,
		    "wcr_exec_ssi: "
		    "unable to get acsls port number from MM, "
		    "trying default port, 50004");
		ssi_port = 50004;
	}
	/* Set the SSI port */
	mms_trace(MMS_OPER,
	    "ACSAPI_SSI_SOCKET = %d", ssi_port);
	env_ssi_port =
	    mms_strapp(env_ssi_port,
	    "ACSAPI_SSI_SOCKET=%d", ssi_port);
	putenv(env_ssi_port);

	/* Set path to ssi binary */
	mms_trace(MMS_OPER,
	    "MMS_SSI_PATH = %s",
	    ssi_path);
	env_ssi_path =
	    mms_strapp(env_ssi_path,
	    "MMS_SSI_PATH=%s",
	    ssi_path);
	putenv(env_ssi_path);

	wcr_prefork(wka);
	if (pid = fork()) {
		wcr_parent_postfork(wka, pid);

		if (env_ssi_path != NULL)
			free(env_ssi_path);
		if (env_ssi_port != NULL)
			free(env_ssi_port);
		if (env_acsls_port != NULL)
			free(env_acsls_port);
		if (env_acs_hostname != NULL)
			free(env_acs_hostname);

		if (pid == (pid_t)(-1)) {
			/* Fork error */
			mms_trace(MMS_ERR, "Fork error for device : ");
			free(ssi_path);
			return;
		} else {
			/* In parent. Save ssi's pid */
			net_LM->wcr_dev_pid = pid;
		}
	} else {
		wcr_child_postfork(wka);

		mms_trace(MMS_NOTICE, "In child process");

		/*
		 * In child process.
		 * Close the watcher device.
		 */
		close(wka->wcr_wka_fd);

		/*
		 * Exec the SSI daemon
		 */
		cmd_name = mms_strapp(cmd_name, WCR_SSI_SH, WCR_SSI_SCRIPT);
		equ = mms_strapp(equ, "%ld", (long)getpid());
		mms_trace(MMS_NOTICE, "EXEC a  SSI, pid - %s", equ);
		if (execl(cmd_name, WCR_SSI_SCRIPT, equ, (char *)0)) {
			/* Can't exec the ssi manager */
			mms_trace(MMS_ERR, "Unable to execute program %s",
			    cmd_name);
			if (cmd_name != NULL)
				free(cmd_name);
			if (equ != NULL)
				free(equ);
			if (env_ssi_path != NULL)
				free(env_ssi_path);
			if (env_ssi_port != NULL)
				free(env_ssi_port);
			if (env_acsls_port != NULL)
				free(env_acsls_port);
			if (env_acs_hostname != NULL)
				free(env_acs_hostname);
			exit(-1);
		}
		if (cmd_name != NULL)
			free(cmd_name);
		if (equ != NULL)
			free(equ);
		if (env_ssi_path != NULL)
			free(env_ssi_path);
		if (env_ssi_port != NULL)
			free(env_ssi_port);
		if (env_acsls_port != NULL)
			free(env_acsls_port);
		if (env_acs_hostname != NULL)
			free(env_acs_hostname);
	}
}


void
wcr_exec_all_ssi(wcr_wka_t *wka) {
	wcr_net_LM_t	*net_LM;
	mms_list_foreach(&wka->wcr_net_LM_list, net_LM) {
		wcr_exec_ssi(wka, net_LM);
	}
}

void
wcr_exec_one_ssi(wcr_wka_t *wka, char *lm_name) {
	wcr_net_LM_t	*net_LM;
	mms_list_foreach(&wka->wcr_net_LM_list, net_LM) {
		if (strcmp(lm_name,
		    net_LM->wcr_lm_name) == 0) {
			wcr_exec_ssi(wka, net_LM);
			return;
		}
	}
	mms_trace(MMS_ERR,
	    "wcr_exec_one_ssi: "
	    "coudln't find SSI info for %s"
	    " check configuration",
	    lm_name);
}

void
wcr_exec_lm_dm(wcr_wka_t *wka, wcr_DM_LM_t *DM_LM_dev)
{
	if (DM_LM_dev->wcr_DM_flag) {
		wcr_exec_dm(wka, DM_LM_dev);
	} else {
		wcr_exec_lm(wka, DM_LM_dev);
	}
}

void
wcr_start_lm_dm(wcr_wka_t *wka)
{
	wcr_DM_LM_t	*DM_LM_dev;
	mms_list_foreach(&wka->wcr_wka_DM_LM_list, DM_LM_dev) {
		wcr_exec_lm_dm(wka, DM_LM_dev);
	}
}

/*
 * wcr_sigchld
 *	-Counts the number of SIGCHILD signals caught
 */

void
/* LINTED: may be used in future */
wcr_sigchld(int sig, siginfo_t *sip, void *ucp)
{
	/*
	 * A drive/library manager has terminated
	 */

	mms_trace(MMS_NOTICE, "Caught SIGCHLD - %d", sig);
	wka.wcr_wka_sigchld++;
}

/*
 * wcr_sighup
 *	-Counts the number of SIGHUP signals caught
 */

void
/* LINTED: may be used in future */
wcr_sighup(int sig, siginfo_t *sip, void *ucp)
{
	/*
	 * Service configuration change
	 */

	mms_trace(MMS_NOTICE, "Caught SIGHUP - %d", sig);
	wka.wcr_wka_sighup = 1;
}

/* ARGSUSED */
void
wcr_sigterm(int sig, siginfo_t *sip, void *ucp)
{
	/*
	 * Service configuration change
	 */

	mms_trace(MMS_NOTICE, "Caught SIGTERM - %d", sig);
	mms_trace_flush();
	exit(0);
}

/*
 * wcr_signal
 *	-signal handler function
 */

void
wcr_signal(int sig, sigfunc *handler)
{
	/*
	 * Setup to catch signals
	 */
	struct sigaction	act, oact;

	memset(&act, 0, sizeof (act));
	act.sa_sigaction = handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_SIGINFO;
	if (sig != SIGALRM) {
		/*
		 * Allow alarm signal to interrupt
		 */
		act.sa_flags |= SA_RESTART;
	}
	if (sigaction(sig, &act, &oact) < 0) {
		mms_trace(MMS_ERR, "Can't set signal handler for signal %d: %s",
		    sig, strerror(errno));
		exit(1);
	}

}

/*
 * wcr_setup_sig_handler
 *	-sets up the signal handler function
 */

void
wcr_setup_sig_handler()
{
	/*
	 * Setup SIG_CHLD and SIGHUP handlers
	 */
	wcr_signal(SIGCHLD, wcr_sigchld);
	wcr_signal(SIGHUP, wcr_sighup);
	wcr_signal(SIGTERM, wcr_sigterm);
	mms_trace(MMS_NOTICE, "Set to catch SIGCHLD and SIGHUP");
}



void
wcr_del_died(wcr_wka_t *wka, pid_t pid) {
	wcr_DM_LM_t	*DM_LM_dev;

	mms_list_foreach(&wka->wcr_wka_DM_LM_list, DM_LM_dev) {
		if (DM_LM_dev->wcr_dev_pid == pid) {
			break;
		}
	}
	if (DM_LM_dev->wcr_DM_flag) {
		mms_trace(MMS_NOTICE, "DELETING DM Dev  %s",
		    DM_LM_dev->
		    wcr_DM_LM_union.wcr_DM.wcr_DM_name);
	} else {
		mms_trace(MMS_NOTICE, "DELETING LM Dev  %s",
		    DM_LM_dev->
		    wcr_DM_LM_union.wcr_LM.wcr_LM_name);
	}
	mms_list_remove(&wka->wcr_wka_DM_LM_list, DM_LM_dev);
	wcr_free_DM_LM(DM_LM_dev);
	free(DM_LM_dev);
	DM_LM_dev = NULL;
}




int
wcr_get_LM_DM(char *name, wcr_DM_LM_t **LM_DM, wcr_wka_t *wka)
{
	wcr_DM_LM_t	*DM_LM_dev = NULL;

	mms_list_foreach(&wka->wcr_wka_DM_LM_list, DM_LM_dev) {
		if (DM_LM_dev->wcr_DM_flag) {
			if (strcmp(name,
			    DM_LM_dev->wcr_DM_LM_union.
			    wcr_DM.wcr_DM_name) == 0) {
				*LM_DM =  DM_LM_dev;
				return (1);
			}
		} else if (strcmp(name,
		    DM_LM_dev->wcr_DM_LM_union.
		    wcr_LM.wcr_LM_name) == 0) {
			*LM_DM = DM_LM_dev;
			return (1);
		}
	}
	return (0);
}

void
wcr_print_LM_DM(wcr_wka_t *wka)
{
	wcr_DM_LM_t	*DM_LM_dev = NULL;
	char *dmname = NULL;
	char *drivename = NULL;
	char *lmname = NULL;
	char *libraryname = NULL;
	int printone = 0;
	mms_trace(MMS_DEBUG, "Current LM & DM list:");
	mms_list_foreach(&wka->wcr_wka_DM_LM_list, DM_LM_dev) {
		printone = 1;
		if (DM_LM_dev->wcr_DM_flag) {
			dmname = DM_LM_dev->wcr_DM_LM_union.
			    wcr_DM.wcr_DM_name;
			drivename = DM_LM_dev->wcr_DM_LM_union.
			    wcr_DM.wcr_drive_name;
			mms_trace(MMS_DEBUG,
			    "    DM, %s %s",
			    dmname, drivename);
		} else {
			lmname = DM_LM_dev->wcr_DM_LM_union.
			    wcr_LM.wcr_LM_name;
			libraryname = DM_LM_dev->wcr_DM_LM_union.
			    wcr_LM.wcr_library_name;
			mms_trace(MMS_DEBUG,
			    "    LM, %s %s",
			    lmname, libraryname);
		}

	}
	if (!printone) {
		mms_trace(MMS_DEBUG, "    *none*");
	}
}




/*
 * wcr_get_dev_number()
 * returns the next available device number, used for DM
 * (pigeon hole problem)
 */

int
wcr_get_dev_number(wcr_wka_t *wka)
{

	int			number_of_dev = 0;
	wcr_DM_LM_t		*LM_DM;
	int			match = 0;
	int			use = 0;
	int			i;

	mms_list_foreach(&wka->wcr_wka_DM_LM_list, LM_DM) {
		number_of_dev ++;
	}
	LM_DM = NULL;

	for (i = 1; i <= number_of_dev+1; i++) {
		match = 0;
		mms_list_foreach(&wka->wcr_wka_DM_LM_list, LM_DM) {
			if (i == LM_DM->
			    wcr_DM_LM_union.wcr_DM.wcr_dev_number) {
				match = 1;
			}
		}

		if (!match) {
			use = i;
			return (use);
		}
	}
	return (-1);
}

/*
 * wcr-is_LM_DM_disabled()
 * -Is LM/DM disabled
 */


int
wcr_is_LM_DM_disabled(char *response, char *inst)
{
	int		rc;
	mms_par_node_t	*cmd = NULL;
	mms_list_t		err_list;
	mms_par_node_t	*tw = NULL;
	mms_par_node_t	*text = NULL;
	mms_par_node_t	*work = NULL;
	mms_par_node_t	*attr = NULL;
	mms_par_node_t	*name = NULL;
	mms_par_node_t	*value = NULL;
	int		found;
	int		disabled;

	rc = mms_mmp_parse(&cmd, &err_list, response);
	mms_pe_destroy(&err_list);
	if (rc) {
		mms_pn_destroy(cmd);
		return (0);
	}

	tw = NULL;
	found = 0;
	for (text = mms_pn_lookup(cmd, "text", MMS_PN_CLAUSE, &tw);
	    text != NULL && !found;
	    text = mms_pn_lookup(cmd, "text", MMS_PN_CLAUSE, &tw)) {

		work = NULL;
		for (attr = mms_pn_lookup(text, "attrlist",
		    MMS_PN_CLAUSE, &work);
		    attr != NULL && !found;
		    attr = mms_pn_lookup(text, "attrlist",
		    MMS_PN_CLAUSE, &work)) {

			disabled = 0;
			mms_list_pair_foreach(&attr->pn_arglist, name,
			    value) {
				if (strcmp("DMName",
				    name->pn_string) == 0) {
					if (strcmp(inst,
					    value->pn_string) == 0) {
						found = 1;
					}
				} else if (strcmp("LMName",
				    name->pn_string) == 0) {
					if (strcmp(inst,
					    value->pn_string) == 0) {
						found = 1;
					}
				} else if (strcmp("DMDisabled",
				    name->pn_string) == 0) {
					disabled = strcmp("false",
					    value->pn_string);
				} else if (strcmp("LMDisabled",
				    name->pn_string) == 0) {
					disabled = strcmp("false",
					    value->pn_string);
				}
			}
		}
	}
	mms_pn_destroy(cmd);
	if (found && disabled) {
		return (1);
	}
	return (0);
}

/*
 * wcr-new_event()
 * -Need to get the config information for the new LM/DM
 * -Need to create a new LM/DM object and add it to the list
 * -Need to start process for the new object
 */


void
wcr_new_event(wcr_wka_t *wka, char *name, char *type)
{
	char			*cmd_str = NULL;

	char			*response = NULL;
	wcr_DM_LM_t		*new_LM_DM = NULL;
	int			num_dev = 1;
	wcr_DM_LM_t		*cur_LM_DM = NULL;
	int			rc;

	/* make sure object is not already in the list */
	wcr_print_LM_DM(wka);
	if (wcr_get_LM_DM(name, &new_LM_DM, wka)) {
		mms_trace(MMS_NOTICE,
		    "Duplicate LM/DM Found- Cannot create new");
		return;
	}

	new_LM_DM = NULL;

	/* Generate the correct show command */
	if (strcmp(type, "DM") == 0) {
		cmd_str = mms_strapp(cmd_str,
		    WCR_SHOW_NEW_DM, name,
		    wka->wcr_host_name);
		if ((num_dev = wcr_get_dev_number(wka)) == -1) {
			mms_trace(MMS_ERR, "Failed to get new dev number");
		}

	} else if (strcmp(type, "LM") == 0) {
		cmd_str = mms_strapp(cmd_str,
		    WCR_SHOW_NEW_LM, name,
		    wka->wcr_host_name);
	} else {
		mms_trace(MMS_ERR,
		    "Unknown type of New Event %s - %s not added",
		    type, name);
		return;
	}
	/* send the show command and add the new dev to the list */
	if ((response = wcr_send_cmd(cmd_str, wka)) == NULL) {
		mms_trace(MMS_ERR,
		    "Error sending command");
		free(cmd_str);
		return;
	}
	free(cmd_str);
	/* mms_trace(MMS_NOTICE, "response- %s", response); */
	rc = wcr_create_list(response, wka);

	/* select the new device and exec its binary */

	cur_LM_DM = NULL;
	if (!wcr_get_LM_DM(name, &cur_LM_DM, wka)) {
		if (rc == SUCCESS && wcr_is_LM_DM_disabled(response, name)) {
			mms_trace(MMS_NOTICE, "Found disabled DM/LM %s", name);
			return;
		}
		mms_trace(MMS_ERR, "Could NOT find new DM/LM %s", name);
		return;
	}

	/*
	 * Check if new dev is LM or DM,
	 * If LM, write cfg file and exec
	 * If DM, set up dev path, write cfg, and exec
	 */

	if (!cur_LM_DM->wcr_DM_flag) {
		/* check to see if SSI needs to be started */
		if (wcr_get_ssi(wka, name)) {
			mms_trace(MMS_ERR,
			    "Error getting ssi hostname");
		} else {
			wcr_exec_one_ssi(wka, name);
		}
		/* It is an LM */
		wcr_write_LM_cfg(cur_LM_DM, wka);
		wcr_exec_lm_dm(wka, cur_LM_DM);
		return;
	}

	cur_LM_DM->wcr_DM_LM_union.
	    wcr_DM.wcr_dev_number = num_dev;


	if (cur_LM_DM->
	    wcr_DM_LM_union.wcr_DM.
	    wcr_dev_mgr_path != NULL) {
		free(cur_LM_DM->
		    wcr_DM_LM_union.wcr_DM.
		    wcr_dev_mgr_path);
		cur_LM_DM->
		    wcr_DM_LM_union.wcr_DM.
		    wcr_dev_mgr_path = NULL;
	}
	cur_LM_DM->wcr_DM_LM_union.wcr_DM.wcr_dev_mgr_path =
	    mms_strapp(cur_LM_DM->wcr_DM_LM_union.wcr_DM.wcr_dev_mgr_path,
	    WCR_DEV_MGR_PATH, num_dev);

	if (ioctl(wka->wcr_wka_fd, WCR_ADD_DEV,
	    num_dev) < 0) {
		mms_trace(MMS_ERR, "Unable to add device %s, ordinal %d",
		    cur_LM_DM->wcr_DM_LM_union.wcr_DM.wcr_dev_tar_path,
		    num_dev);
	}
	/* dv->wcr_dev_flags |= WCR_DEV_START; */
	cur_LM_DM->wcr_DM_LM_union.wcr_DM.wcr_dev_ordinal
	    = num_dev;

	wcr_write_DM_cfg(cur_LM_DM, wka);
	wcr_exec_lm_dm(wka, cur_LM_DM);
}

void
wcr_change_died(wcr_wka_t *wka, pid_t pid) {
	wcr_DM_LM_t	*DM_LM_dev = NULL;
	char		*name = NULL;
	char		*type = NULL;

	mms_list_foreach(&wka->wcr_wka_DM_LM_list, DM_LM_dev) {
		if (DM_LM_dev->wcr_dev_pid == pid) {
			break;
		}
	}
	if (DM_LM_dev->wcr_DM_flag) {
		name = DM_LM_dev->
		    wcr_DM_LM_union.wcr_DM.wcr_DM_name;
		type = "DM";
	} else {
		name = DM_LM_dev->
		    wcr_DM_LM_union.wcr_LM.wcr_LM_name;
		type = "LM";
	}

	/* mms_list_remove(&wka->wcr_wka_DM_LM_list, DM_LM_dev); */
	mms_trace(MMS_NOTICE, "Obj to change is %s, type is %s", name, type);


	wcr_del_died(wka, pid);
	wcr_new_event(wka, name, type);
}

/*
 * wcr_del_event()
 * -Need to kill child LM/DM
 * -Need to delete LM/DM object from the list
 */

void
/* LINTED: type may be used later */
wcr_del_event(wcr_wka_t *wka, char *name, char *type)
{
	wcr_DM_LM_t *LM_DM = NULL;
	mms_trace(MMS_NOTICE, "Attempting to delete LM/DM - %s", name);

	if (!wcr_get_LM_DM(name, &LM_DM, wka)) {
		mms_trace(MMS_ERR, "Could NOT find DM/LM %s in list", name);
		return;
	}
	LM_DM->wcr_del_pending = 1;
	kill(LM_DM->wcr_dev_pid, SIGTERM);

	LM_DM = NULL;
}

/*
 * wcr_disable_event()
 * -Need to delete LM/DM object from the list
 */

void
/* LINTED: type may be used later */
wcr_disable_event(wcr_wka_t *wka, char *name, char *type)
{
	wcr_DM_LM_t *LM_DM = NULL;
	mms_trace(MMS_NOTICE, "Attempting to disable LM/DM - %s", name);

	if (!wcr_get_LM_DM(name, &LM_DM, wka)) {
		mms_trace(MMS_ERR, "Could NOT find DM/LM %s in list", name);
		return;
	}
	LM_DM->wcr_del_pending = 1;

	LM_DM = NULL;

}

/*
 * wcr_compare()
 * -Check for LM/DM object change.
 */

int
wcr_compare(wcr_DM_LM_t *LM_DM_1, wcr_DM_LM_t *LM_DM_2)
{
	int	changed = 0;

	if (LM_DM_1->wcr_DM_flag) {
		/* Compare DM attributes */
		if (strcmp(LM_DM_1->wcr_DM_LM_union.
		    wcr_DM.wcr_DM_name,
		    LM_DM_2->wcr_DM_LM_union.
		    wcr_DM.wcr_DM_name) != 0) {
			mms_trace(MMS_NOTICE, "LM_DM_1 - %s, LM_DM_2 - %s",
			    LM_DM_1->wcr_DM_LM_union.
			    wcr_DM.wcr_DM_name, LM_DM_2->wcr_DM_LM_union.
			    wcr_DM.wcr_DM_name);
			changed = 1;
		} else if (strcmp(LM_DM_1->wcr_DM_LM_union.
		    wcr_DM.wcr_dev_tar_path,
		    LM_DM_2->wcr_DM_LM_union.
		    wcr_DM.wcr_dev_tar_path) != 0) {
			mms_trace(MMS_NOTICE, "LM_DM_1 - %s, LM_DM_2 - %s",
			    LM_DM_1->wcr_DM_LM_union.
			    wcr_DM.wcr_dev_tar_path,
			    LM_DM_2->wcr_DM_LM_union.
			    wcr_DM.wcr_dev_tar_path);
			changed = 1;
		} else if (strcmp(LM_DM_1->wcr_DM_LM_union.
		    wcr_DM.wcr_drive_name,
		    LM_DM_2->wcr_DM_LM_union.
		    wcr_DM.wcr_drive_name) != 0) {
			mms_trace(MMS_NOTICE, "LM_DM_1 - %s, LM_DM_2 - %s",
			    LM_DM_1->wcr_DM_LM_union.
			    wcr_DM.wcr_drive_name,
			    LM_DM_2->wcr_DM_LM_union.
			    wcr_DM.wcr_drive_name);
			changed = 1;
		}

	} else {
		/* Compare LM attributes */
		if (strcmp(LM_DM_1->wcr_DM_LM_union.
		    wcr_LM.wcr_LM_name,
		    LM_DM_2->wcr_DM_LM_union.
		    wcr_LM.wcr_LM_name) != 0) {
			mms_trace(MMS_NOTICE, "LM_DM_1 - %s, LM_DM_2 - %s",
			    LM_DM_1->wcr_DM_LM_union.
			    wcr_LM.wcr_LM_name,
			    LM_DM_2->wcr_DM_LM_union.
			    wcr_LM.wcr_LM_name);
			changed = 1;
		} else if (strcmp(LM_DM_1->wcr_DM_LM_union.
		    wcr_LM.wcr_library_name,
		    LM_DM_2->wcr_DM_LM_union.
		    wcr_LM.wcr_library_name) != 0) {
			mms_trace(MMS_NOTICE, "LM_DM_1 - %s, LM_DM_2 - %s",
			    LM_DM_1->wcr_DM_LM_union.
			    wcr_LM.wcr_library_name,
			    LM_DM_2->wcr_DM_LM_union.
			    wcr_LM.wcr_library_name);
			changed = 1;
		}
	}
	return (changed);
}


/*
 * wcr_change_event()
 * -Need to kill child LM/DM
 * -Need to alter LM/DM object in the list
 * -Need to write a new config file
 * -Need to restart the LM/DM
 */

void
wcr_change_event(wcr_wka_t *wka, char *old_name, char *new_name, char *type)
{
	wcr_DM_LM_t		*LM_DM;
	char			*response = NULL;
	char			*cmd_str = NULL;
	wcr_DM_LM_t		*temp_LM_DM = NULL;
	mms_par_node_t		*cmd = NULL;
	mms_list_t		err_list;
	mms_par_err_t		*err = NULL;
	int			rc;
	mms_par_node_t		*text = NULL;
	mms_par_node_t		*tw = NULL;
	mms_par_node_t		*work = NULL;
	mms_par_node_t		*attr = NULL;
	int			changed = 0;


	mms_trace(MMS_NOTICE, "Attempting to change LM/DM - %s", old_name);

	if (!wcr_get_LM_DM(old_name, &LM_DM, wka)) {
		/*
		 * The LM/DM has already exited with a no restart exit code
		 * and has been removed from the active list
		 * this is likley due to an inncorrect user configuration
		 * call new event with the new name to re-config and start
		 * the LM/DM
		 */
		mms_trace(MMS_NOTICE, "Could NOT find DM/LM %s"\
		    " to change in active list",
		    old_name);
		wcr_new_event(wka, new_name, type);
		return;
	}
	/* The LM/DM to be changed is active so check for config changes */
	if (strcmp(type, "DM") == 0) {
		cmd_str = mms_strapp(cmd_str,
		    WCR_SHOW_NEW_DM, new_name,
		    wka->wcr_host_name);
	} else if (strcmp(type, "LM") == 0) {
		cmd_str = mms_strapp(cmd_str,
		    WCR_SHOW_NEW_LM, new_name,
		    wka->wcr_host_name);
	} else {
		mms_trace(MMS_ERR,
		    "Unknown type of change Event %s - %s not added",
		    type, new_name);
		return;
	}

	/* send the show command and add the new dev to the list */
	if ((response = wcr_send_cmd(cmd_str, wka)) == NULL) {
		mms_trace(MMS_ERR,
		    "Error sending command");
		free(cmd_str);
		return;
	}
	free(cmd_str);
	/* mms_trace(MMS_NOTICE, "response is %s", response); */
	/* Malloc memory for temporary LM DM */

#if 1

	temp_LM_DM = wcr_alloc_DM_LM();
	if (temp_LM_DM == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to mallor wcr_DM_LM_t: %s",
		    strerror(errno));
		return;
	}

#else
	temp_LM_DM =
	    (wcr_DM_LM_t *)malloc(sizeof (wcr_DM_LM_t));
	if (temp_LM_DM == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to mallor wcr_DM_LM_t: %s",
		    strerror(errno));
	}
	memset(temp_LM_DM, 0, sizeof (wcr_DM_LM_t));
#endif
	/* parse response */
	rc = mms_mmp_parse(&cmd, &err_list, response);
	mms_list_foreach(&err_list, err) {
		mms_trace(MMS_ERR, "error parse, "
		    "line %d, col %d, near token \"%s\", err code %d, %s\n",
		    err->pe_line,
		    err->pe_col,
		    err->pe_token,
		    err->pe_code,
		    err->pe_msg);
	}
	mms_pe_destroy(&err_list);
	if (rc) {
		mms_trace(MMS_ERR, "Parse Error: %s",
		    strerror(errno));
		mms_pn_destroy(cmd);
		return;
	}
	if (mms_pn_lookup(cmd, "success", MMS_PN_KEYWORD, 0) != NULL) {

		if (text = mms_pn_lookup(cmd, "attrlist",
		    MMS_PN_CLAUSE, NULL)) {
			tw = 0;
			for (text = mms_pn_lookup(cmd, "text",
			    MMS_PN_CLAUSE, &tw);
			    text != NULL;
			    text = mms_pn_lookup(cmd, "text",
			    MMS_PN_CLAUSE, &tw)) {
				work = NULL;
				for (attr = mms_pn_lookup(text, "attrlist",
				    MMS_PN_CLAUSE,
				    &work);
				    attr != NULL;
				    attr = mms_pn_lookup(text, "attrlist",
				    MMS_PN_CLAUSE,
				    &work)) {

					wcr_build_struct(attr,
					    temp_LM_DM, wka);
				}
			}
		}

		mms_pn_destroy(cmd);

	} else {
		mms_trace(MMS_ERR, "change event-cannot read"\
		    "successful response: %s",
		    strerror(errno));
	}

	/* compare temp to existing LM DM */

	changed = wcr_compare(temp_LM_DM, LM_DM);

	/* if changed set flage to true */
	if (changed) {
		mms_trace(MMS_NOTICE, "Sending lm SIGINT");
		LM_DM->wcr_change_pending = 1;
		kill(LM_DM->wcr_dev_pid, SIGINT);
	} else {
		mms_trace(MMS_NOTICE, "%s is unchanged", old_name);
	}

	free(response);
	wcr_free_DM_LM(temp_LM_DM);
	free(temp_LM_DM);

	LM_DM = NULL;

	/* test - print the names of all LM DM with change pending */
	mms_list_foreach(&wka->wcr_wka_DM_LM_list, LM_DM) {
		if (LM_DM->wcr_change_pending) {
			if (LM_DM->wcr_DM_flag) {
				mms_trace(MMS_NOTICE, "%s has change pending",
				    LM_DM->wcr_DM_LM_union.
				    wcr_DM.wcr_DM_name);
			} else {
				mms_trace(MMS_NOTICE, "%s has change pending",
				    LM_DM->wcr_DM_LM_union.
				    wcr_LM.wcr_LM_name);

			}

		}
	}

}

void
wcr_old_dev(pid_t pid, wcr_wka_t *wka)
{
	wcr_DM_LM_t	*DM_LM_dev;
	wcr_DM_LM_t	*next_DM_LM_dev;
	/* int		status; */


	for (DM_LM_dev = mms_list_head(&wka->wcr_old_DM_LM_list);
	    DM_LM_dev != NULL;
	    DM_LM_dev = next_DM_LM_dev) {
		next_DM_LM_dev = mms_list_next(&wka->wcr_old_DM_LM_list,
		    DM_LM_dev);
			if (DM_LM_dev->wcr_dev_pid == pid) {
			mms_list_remove(&wka->wcr_old_DM_LM_list, DM_LM_dev);
			break;
		}
	}
	if (DM_LM_dev) {
		wcr_free_DM_LM(DM_LM_dev);
		free(DM_LM_dev);
	} else {
		mms_trace(MMS_ERR, "No child process found with pid %d", pid);
	}
}

int
wcr_cmd_status(char *response)
{
	mms_par_node_t		*cmd = NULL;
	mms_list_t		err_list;
	mms_par_err_t		*err = NULL;
	int			rc;

	rc = mms_mmp_parse(&cmd, &err_list, response);
	mms_list_foreach(&err_list, err) {
		mms_trace(MMS_ERR, "error parse, "
		    "line %d, col %d, near token \"%s\", err code %d, %s\n",
		    err->pe_line,
		    err->pe_col,
		    err->pe_token,
		    err->pe_code,
		    err->pe_msg);
	}
	mms_pe_destroy(&err_list);
	if (rc) {
		mms_trace(MMS_ERR, "Parse Error: %d", rc);
		mms_pn_destroy(cmd);
		return (MMS_ERROR);
	}
	if (mms_pn_lookup(cmd, "success", MMS_PN_KEYWORD, 0) != NULL) {
		rc = SUCCESS;
	} else if (mms_pn_lookup(cmd, "unacceptable",
	    MMS_PN_KEYWORD, 0) != NULL) {
		rc = UNACCEPTABLE;
	} else if (mms_pn_lookup(cmd, "cancelled",
	    MMS_PN_KEYWORD, 0) != NULL) {
		rc = CANCELLED;
	} else {
		rc = MMS_ERROR;
	}
	mms_pn_destroy(cmd);
	return (rc);
}

void
wcr_set_privilege_level(wcr_wka_t *wka, char *level)
{
	char	*cmd_str = NULL;
	char	*response = NULL;
	int	rc;

	cmd_str = mms_strapp(cmd_str,
	    PRIVILEGE_CMD_STR, level);
	if ((response = wcr_send_cmd(cmd_str, wka)) == NULL) {
		mms_trace(MMS_ERR,
		    "Error sending %s privilege change",
		    level);
		free(cmd_str);
		return;
	}
	free(cmd_str);
	if ((rc = wcr_cmd_status(response)) != SUCCESS) {
		mms_trace(MMS_ERR,
		    "Error %d response for %s privilege change",
		    rc, level);
	}
	free(response);
}

void
wcr_set_dm_broken(wcr_wka_t *wka, wcr_DM_LM_t *DM_LM_dev)
{
	char	*cmd_str = NULL;
	char	*response = NULL;
	int	rc;

	cmd_str = mms_strapp(cmd_str,
	    ATTR_BROKEN_DM_CMD_STRING,
	    DM_LM_dev->wcr_DM_LM_union.wcr_DM.wcr_DM_name,
	    wka->wcr_host_name);
	if ((response = wcr_send_cmd(cmd_str, wka)) == NULL) {
		mms_trace(MMS_ERR,
		    "Error sending DM %s broken attribute change",
		    DM_LM_dev->wcr_DM_LM_union.wcr_DM.wcr_DM_name);
		free(cmd_str);
		return;
	}
	free(cmd_str);
	if ((rc = wcr_cmd_status(response)) != SUCCESS) {
		mms_trace(MMS_ERR,
		    "Error %d response for DM %s broken attribute change",
		    rc, DM_LM_dev->wcr_DM_LM_union.wcr_DM.wcr_DM_name);
	}
	free(response);
}

void
wcr_set_lm_broken(wcr_wka_t *wka, wcr_DM_LM_t *DM_LM_dev)
{
	char	*cmd_str = NULL;
	char	*response = NULL;
	int	rc;

	cmd_str = mms_strapp(cmd_str,
	    ATTR_BROKEN_LM_CMD_STRING,
	    DM_LM_dev->wcr_DM_LM_union.wcr_LM.wcr_LM_name,
	    wka->wcr_host_name);
	if ((response = wcr_send_cmd(cmd_str, wka)) == NULL) {
		mms_trace(MMS_ERR,
		    "Error sending LM %s broken attribute change",
		    DM_LM_dev->wcr_DM_LM_union.wcr_LM.wcr_LM_name);
		free(cmd_str);
		return;
	}
	free(cmd_str);
	if ((rc = wcr_cmd_status(response)) != SUCCESS) {
		mms_trace(MMS_ERR,
		    "Error %d response for LM %s broken attribute change",
		    rc, DM_LM_dev->wcr_DM_LM_union.wcr_LM.wcr_LM_name);
	}
	free(response);
}

void
wcr_set_lm_dm_broken(wcr_wka_t *wka, wcr_DM_LM_t *DM_LM_dev)
{
	wcr_set_privilege_level(wka, "system");
	if (DM_LM_dev->wcr_DM_flag) {
		wcr_set_dm_broken(wka, DM_LM_dev);
	} else {
		wcr_set_lm_broken(wka, DM_LM_dev);
	}
	wcr_set_privilege_level(wka, "administrator");
}

/*
 * wcr_chk_child_death
 *	-checks for death of children
 */
void
wcr_chk_child_death(wcr_wka_t *wka)
{
	pid_t		pid;
	wcr_DM_LM_t	*DM_LM_dev;
	int		status;
	time_t		cur_time;

	wcr_net_LM_t	*net_LM;

	do {

		if ((pid = waitpid((pid_t)-1, &status, WNOHANG)) == -1) {
			if (errno == EINTR) {
				/* Wait interrupted, will restart wait */
				continue;
			} else {
				mms_trace(MMS_ERR, "Waitpid Error - %s",
				    strerror(errno));
				return;
			}

		} else if (pid == 0) {
			/* No more sigchld */
			wka->wcr_wka_sigchld = 0;
			break;
		}

		mms_trace(MMS_NOTICE, "child pid %d died", pid);
		mms_list_foreach(&wka->wcr_wka_DM_LM_list, DM_LM_dev) {
			if (DM_LM_dev->wcr_dev_pid == pid) {
				break;
			}
		}

		if (DM_LM_dev == NULL) {
			mms_list_foreach(&wka->wcr_net_LM_list, net_LM) {
				if (net_LM->wcr_dev_pid == pid) {
					mms_trace(MMS_NOTICE,
					    "SSI exited with status - %d",
					    WEXITSTATUS(status));
					wcr_exec_ssi(wka, net_LM);
				} else {
					wcr_old_dev(pid, wka);
				}
			}
			continue;
		}

		if (DM_LM_dev->wcr_del_pending) {
			if (DM_LM_dev->wcr_DM_flag) {
				mms_trace(MMS_NOTICE,
				    "%s Exited with status %d -"\
				    " Del Pending",
				    DM_LM_dev->wcr_DM_LM_union.
				    wcr_DM.wcr_DM_name,
				    WEXITSTATUS(status));
			} else {
				mms_trace(MMS_NOTICE,
				    "%s Exited with status %d -"\
				    " Del Pending",
				    DM_LM_dev->wcr_DM_LM_union.
				    wcr_LM.wcr_LM_name,
				    WEXITSTATUS(status));
			}
			wcr_del_died(wka, pid);

		} else if (DM_LM_dev->wcr_change_pending) {
			if (DM_LM_dev->wcr_DM_flag) {
				mms_trace(MMS_NOTICE,
				    "%s Exited with status %d"\
				    " - Change Pending",
				    DM_LM_dev->wcr_DM_LM_union.
				    wcr_DM.wcr_DM_name,
				    WEXITSTATUS(status));
			} else {
				mms_trace(MMS_NOTICE,
				    "%s Exited with status %d"\
				    " - Change Pending",
				    DM_LM_dev->wcr_DM_LM_union.
				    wcr_LM.wcr_LM_name,
				    WEXITSTATUS(status));
			}
			DM_LM_dev->wcr_starts = 0;
			wcr_change_died(wka, pid);


		} else if (WIFEXITED(status) &&
		    ((WEXITSTATUS(status) == 1) ||
		    (WEXITSTATUS(status) == 0))) {
			if (DM_LM_dev->wcr_DM_flag) {
				mms_trace(MMS_NOTICE,
				    "%s Exited with status %d -"\
				    " No Restart",
				    DM_LM_dev->wcr_DM_LM_union.
				    wcr_DM.wcr_DM_name,
				    WEXITSTATUS(status));
			} else {
				mms_trace(MMS_NOTICE,
				    "%s Exited with status %d -"\
				    " No Restart",
				    DM_LM_dev->wcr_DM_LM_union.
				    wcr_LM.wcr_LM_name,
				    WEXITSTATUS(status));
			}
			/*
			 * DM or LM
			 * Exited with status == 1 or == 0
			 * Do not restart
			 */
			wcr_del_died(wka, pid);

		} else if (wka->wcr_connected == 0) {
			/*
			 * Watcher not connected to MM
			 */
			if (DM_LM_dev->wcr_DM_flag) {
				mms_trace(MMS_NOTICE,
				    "%s Exited with status %d -"
				    " Watcher not connected to MM",
				    DM_LM_dev->wcr_DM_LM_union.
				    wcr_DM.wcr_DM_name,
				    WEXITSTATUS(status));
			} else {
				mms_trace(MMS_NOTICE,
				    "%s Exited with status %d -"
				    " Watcher not connected to MM",
				    DM_LM_dev->wcr_DM_LM_union.
				    wcr_LM.wcr_LM_name,
				    WEXITSTATUS(status));
			}
			wcr_del_died(wka, pid);

		} else {
			if (DM_LM_dev->wcr_DM_flag) {
				mms_trace(MMS_NOTICE,
				    "%s Exited with status %d - Restart",
				    DM_LM_dev->wcr_DM_LM_union.
				    wcr_DM.wcr_DM_name,
				    WEXITSTATUS(status));
			} else {
				mms_trace(MMS_NOTICE,
				    "%s Exited with status %d - Restart",
				    DM_LM_dev->wcr_DM_LM_union.
				    wcr_LM.wcr_LM_name,
				    WEXITSTATUS(status));
			}

			/*
			 * Count number of restarts in a time period.
			 */
			time(&cur_time);
			if (WEXITSTATUS(status) == 2 ||
			    DM_LM_dev->wcr_starts == 0 ||
			    (cur_time - DM_LM_dev->wcr_time) > wka->wcr_time) {
				DM_LM_dev->wcr_time = cur_time;
				DM_LM_dev->wcr_starts = 1;
			} else {
				DM_LM_dev->wcr_starts++;
			}
			if (wka->wcr_starts != -1 &&
			    DM_LM_dev->wcr_starts >= wka->wcr_starts) {
				/*
				 * DM or LM
				 * Restarted n times in s seconds.
				 * Set broken and remove from list.
				 */
				mms_trace(MMS_ERR,
				    "%s restarting too quickly, "
				    "setting broken state.",
				    DM_LM_dev->wcr_DM_LM_union.
				    wcr_LM.wcr_LM_name);
				wcr_set_lm_dm_broken(wka, DM_LM_dev);
				wcr_del_died(wka, pid);
			} else {
				/*
				 * DM or LM
				 * Was aborted or exited w/ status != 1 or != 0
				 * Restart
				 */
				wcr_exec_lm_dm(wka, DM_LM_dev);
			}
		}
		/* LINTED: */
	} while (1);
}

void
wcr_change_dev_num(wcr_wka_t *wka, char *name, int num)
{
	wcr_DM_LM_t *new_LM_DM = NULL;

	mms_list_foreach(&wka->wcr_wka_DM_LM_list, new_LM_DM) {
		if (strcmp(name,
		    new_LM_DM->
		    wcr_DM_LM_union.wcr_DM.wcr_DM_name) == 0) {
			new_LM_DM->wcr_DM_LM_union.
			    wcr_DM.wcr_dev_number = num;

			if (new_LM_DM->
			    wcr_DM_LM_union.wcr_DM.
			    wcr_dev_mgr_path != NULL) {
				free(new_LM_DM->
				    wcr_DM_LM_union.wcr_DM.
				    wcr_dev_mgr_path);
				new_LM_DM->
				    wcr_DM_LM_union.wcr_DM.
				    wcr_dev_mgr_path = NULL;
			}
			new_LM_DM->wcr_DM_LM_union.
			    wcr_DM.wcr_dev_mgr_path =
			    mms_strapp(new_LM_DM->wcr_DM_LM_union.
			    wcr_DM.wcr_dev_mgr_path,
			    WCR_DEV_MGR_PATH, num);
			wcr_write_DM_cfg(new_LM_DM, wka);
		}
	}
}

int
wcr_set_notify(wcr_wka_t *wka) {
	char *cmd_str = NULL;
	char *response = NULL;

	cmd_str = mms_strapp(cmd_str, WCR_SET_NOTIFY);
	response = wcr_send_cmd(cmd_str, wka);
	free(cmd_str);
	if (response == NULL) {
		mms_trace(MMS_ERR,
		    "Error setting watcher notification ");
		return (1);
	} else {
		free(response);
	}
	return (0);


}

void
/* LINTED: sig_mask may be used later */
wcr_do_work(wcr_wka_t *wka, const  sigset_t  *sig_mask)
{
	mms_par_node_t	*cmd = NULL;
	mms_list_t		err_list;
	char		*rsp = NULL;
	mms_par_err_t	*err = NULL;
	int		rc;



	rsp = NULL;
	if (mms_reader(&wka->wcr_mms_conn, &rsp) <= 0) {
		mms_trace(MMS_ERR, "Read EOF: lost connection to MM");
		mms_close(&wka->wcr_mms_conn);
		return;
	}

	mms_trace(MMS_NOTICE, "EVENT is %s", rsp);

	rc = mms_mmp_parse(&cmd, &err_list, rsp);
	mms_list_foreach(&err_list, err) {
		mms_trace(MMS_ERR, "error parse, "
		    "line %d, col %d, near token \"%s\", "\
		    "err code %d, %s\n",
		    err->pe_line,
		    err->pe_col,
		    err->pe_token,
		    err->pe_code,
		    err->pe_msg);
	}

	if (rc) {
		mms_trace(MMS_ERR, "Parse Error: %s",
		    strerror(errno));
		mms_pn_destroy(cmd);
	}
	if (mms_pn_lookup(cmd, "event",
	    MMS_PN_CMD, 0) != NULL) {
		wcr_add_event(cmd, wka);
	}
	mms_pn_destroy(cmd);




}
void
wcr_proc_events(wcr_wka_t *wka)
{
	wcr_event_t *an_event = NULL;

	char		*old_inst_name = NULL;
	char		*new_inst_name = NULL;
	char		*type = NULL;
	char		*object = NULL;
	char		*inst_name = NULL;

	mms_list_foreach(&wka->wcr_events, an_event) {
		if (!an_event->wcr_done) {
			old_inst_name = an_event->wcr_old_inst_name;
			new_inst_name = an_event->wcr_old_inst_name;
			type = an_event->wcr_type;
			object = an_event->wcr_object;
			inst_name = an_event->wcr_inst_name;

			if (strcmp("new", type) == 0) {
				/* mms_trace(MMS_NOTICE, */
				/* "Found NEW event"); */
				wcr_new_event(wka, inst_name, object);
			} else if (strcmp("enable", type) == 0) {
				/* mms_trace(MMS_NOTICE, */
				/* "Found ENABLE event"); */
				wcr_new_event(wka, inst_name, object);
			} else if (strcmp("delete", type) == 0) {
				/* mms_trace(MMS_NOTICE, */
				/* "Found DELETE event"); */
				wcr_del_event(wka, inst_name, object);
			} else if (strcmp("disable", type) == 0) {
				/* mms_trace(MMS_NOTICE, */
				/* "Found DISABLE event"); */
				wcr_disable_event(wka, inst_name, object);
			} else if (strcmp("change", type) == 0) {
				/* mms_trace(MMS_NOTICE, */
				/*   "Found CHANGE event"); */
				wcr_change_event(wka,
				    old_inst_name,
				    new_inst_name,
				    object);
			} else {
				mms_trace(MMS_ERR, "Unknown Event Type");
			}
			an_event->wcr_done = 1;
		}
	}


}

int
wcr_prune(wcr_wka_t *wka)
{
	wcr_event_t *an_event;
	int found_not_done = 0;
	int remove;
	int go = 1;

	while (go) {
		remove = 0;
		mms_list_foreach(&wka->wcr_events, an_event) {
			if (an_event->wcr_done) {
				remove = 1;
				break;
			} else {
				found_not_done = 1;
			}
		}
		if (remove) {
			mms_list_remove(&wka->wcr_events, an_event);
			free(an_event);
		} else { go = 0; }
	}
	return (found_not_done);

}

/*
 * wcr_refresh()
 * -Read network configure file.
 * -Check for mm host change.
 */

void
wcr_refresh(wcr_wka_t *wka)
{
	mms_network_cfg_t	net_cfg;
	mms_list_t		*mm_list = NULL;
	wcr_MM_t		*mm = NULL;
	char			*mm_host = NULL;

	mms_trace(MMS_DEVP, "service refresh");

	/* read network config */
	if (wcr_net_cfg_read(&net_cfg, &mm_list)) {
		mms_trace(MMS_ERR, "config read");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/* determine if mm host changed */
	if (wka->wcr_wka_net_cfg.cli_host != NULL) {
		char	host[2][MMS_HOST_IDENT_LEN+1];
		char	ip[2][MMS_IP_IDENT_LEN+1];
		char	*ok[2];

		ok[0] = mms_host_ident(wka->wcr_wka_net_cfg.cli_host,
		    host[0], ip[0]);

		mms_list_foreach(mm_list, mm) {

			ok[1] = mms_host_ident(mm->wcr_mm_host, host[1], ip[1]);

			/* compare host names and ip addresses */
			if (strcmp(mm->wcr_mm_host,
			    wka->wcr_wka_net_cfg.cli_host) == 0 ||

			    (ok[0] && ok[1] && strcmp(ip[0], ip[1]) == 0)) {

				/* validate connection */
				if (fcntl(wka->wcr_mms_conn.mms_fd,
				    F_GETFD, 0) != -1) {
					mm_host = mm->wcr_mm_host;
				}
				break;
			}
		}
	}

	/* replace network config */
	wcr_net_cfg_free(&wka->wcr_wka_net_cfg, &wka->wcr_wka_MM_list);
	(void) memcpy(&wka->wcr_wka_net_cfg, &net_cfg,
	    sizeof (mms_network_cfg_t));
	wka->wcr_wka_MM_list = mm_list;
	wka->wcr_wka_net_cfg.cli_host = mm_host;

	/* handle mm host */
	if (wka->wcr_wka_net_cfg.cli_host) {
		mms_trace(MMS_NOTICE, "mm host unchanged");
		if (wcr_write_cfg(wka)) {
			mms_trace(MMS_ERR,
			    "Unable to write cfg file");
		}
	} else {
		mms_trace(MMS_NOTICE, "mm host changed");
		if (wka->wcr_mms_conn.mms_fd >= 0) {
			mms_close(&wka->wcr_mms_conn);
		}
	}
}

void
wcr_get_system(wcr_wka_t *wka)
{
	char			*response = NULL;
	int			rc;
	mms_list_t		err_list;
	mms_par_err_t		*err = NULL;
	mms_par_node_t		*cmd = NULL;
	mms_par_node_t		*work = NULL;
	mms_par_node_t		*value = NULL;


	wka->wcr_starts = 3;
	wka->wcr_time = 60;

	if ((response = wcr_send_cmd(SHOW_SYSTEM_CMD_STR, wka)) == NULL) {
		mms_trace(MMS_ERR,
		    "Error sending system settings show command");
		return;
	}

	rc = mms_mmp_parse(&cmd, &err_list, response);
	mms_list_foreach(&err_list, err) {
		mms_trace(MMS_ERR, "error parse, "
		    "line %d, col %d, near token \"%s\", err code %d, %s\n",
		    err->pe_line,
		    err->pe_col,
		    err->pe_token,
		    err->pe_code,
		    err->pe_msg);
	}
	mms_pe_destroy(&err_list);
	if (rc) {
		mms_trace(MMS_ERR, "Parse Error: %d", rc);
		goto cleanup;
	}

	if (mms_pn_lookup(cmd, "success", MMS_PN_KEYWORD, 0) == NULL) {
		mms_trace(MMS_ERR, "wcr_get_system did not get a successful "
		    "response");
		goto cleanup;
	}

	work = NULL;
	if (mms_pn_lookup(cmd, "WatcherStartsLimit",
	    MMS_PN_STRING, &work) != NULL) {
		if ((value = mms_pn_lookup(cmd, NULL,
		    MMS_PN_STRING, &work)) != NULL) {
			wka->wcr_starts = atoi(mms_pn_token(value));
			mms_trace(MMS_DEBUG, "wcr_starts %d", wka->wcr_starts);
		}
	}

	work = NULL;
	if (mms_pn_lookup(cmd, "WatcherTimeLimit",
	    MMS_PN_STRING, &work) != NULL) {
		if ((value = mms_pn_lookup(cmd, NULL,
		    MMS_PN_STRING, &work)) != NULL) {
			wka->wcr_time = atoi(mms_pn_token(value));
			mms_trace(MMS_DEBUG, "wcr_time %d", wka->wcr_time);
		}
	}

cleanup:
	mms_pn_destroy(cmd);
	free(response);
}

/*
 * wcr_reconnect()
 * -Connect to network configuration mm host.
 * -Reconcile existing LM/DMs with new connection configuration.
 * -Start new LM/DMs
 */

int
wcr_reconnect(wcr_wka_t *wka)
{
	mms_list_t		devmgr_list;
	wcr_DM_LM_t		*devmgr = NULL;
	wcr_DM_LM_t		*next_devmgr = NULL;
	wcr_DM_LM_t		*LM_DM = NULL;
	wcr_DM_LM_t		*next_LM_DM = NULL;
	wcr_event_t		*event = NULL;
	wcr_event_t		*next_event = NULL;
	int			found;
	int			rc;
	char			prev_mm_host[MAXHOSTNAMELEN];
	int			mm_changed;

	for (event = mms_list_head(&wka->wcr_events);
	    event != NULL;
	    event = next_event) {
		next_event = mms_list_next(&wka->wcr_events, event);
		mms_list_remove(&wka->wcr_events, event);
		free(event);
	}

	strcpy(prev_mm_host, wka->wcr_mm_host);
	if (wcr_init_session(wka)) {
		mms_trace(MMS_DEVP, "refreshed");
		return (1);
	}
	mm_changed = strcmp(prev_mm_host, wka->wcr_mm_host);

	wcr_get_system(wka);

	if (wcr_set_notify(wka)) {
		mms_trace(MMS_ERR, "notify");
		return (1);
	}

	if (wcr_write_cfg(wka)) {
		mms_trace(MMS_ERR,
		    "Unable to write cfg file");
	}

	mms_list_create(&devmgr_list, sizeof (wcr_DM_LM_t),
	    offsetof(wcr_DM_LM_t, wcr_DM_LM_next));

	for (LM_DM = mms_list_head(&wka->wcr_wka_DM_LM_list);
	    LM_DM != NULL;
	    LM_DM = next_LM_DM) {
		next_LM_DM = mms_list_next(&wka->wcr_wka_DM_LM_list, LM_DM);
		mms_list_remove(&wka->wcr_wka_DM_LM_list, LM_DM);
		mms_list_insert_tail(&devmgr_list, LM_DM);
	}

	if (wcr_get_config(wka)) {
		mms_trace(MMS_ERR, "get config");
		rc = 1;
		goto cleanup;
	}

	for (devmgr = mms_list_head(&devmgr_list);
	    devmgr != NULL;
	    devmgr = next_devmgr) {
		next_devmgr = mms_list_next(&devmgr_list, devmgr);
		found = 0;
		for (LM_DM = mms_list_head(&wka->wcr_wka_DM_LM_list);
		    LM_DM != NULL;
		    LM_DM = next_LM_DM) {
			next_LM_DM = mms_list_next(&wka->wcr_wka_DM_LM_list,
			    LM_DM);
			if (strcmp(LM_DM->wcr_DM_LM_union.
			    wcr_DM.wcr_DM_name,
			    devmgr->wcr_DM_LM_union.
			    wcr_DM.wcr_DM_name) == 0) {
				found = 1;
				break;
			}
		}
		if (found == 0 || LM_DM->wcr_DM_flag != devmgr->wcr_DM_flag) {
			/* not found or different type */
			mms_trace(MMS_NOTICE, "Sending %s SIGTERM",
			    devmgr->wcr_DM_LM_union.
			    wcr_DM.wcr_DM_name);
			devmgr->wcr_del_pending = 1;
			kill(devmgr->wcr_dev_pid, SIGTERM);
			mms_list_remove(&devmgr_list, devmgr);
			mms_list_insert_tail(&wka->wcr_old_DM_LM_list, devmgr);
		} else if (wcr_compare(LM_DM, devmgr)) {
			/* found, change */
			mms_trace(MMS_NOTICE, "Sending %s SIGINT",
			    devmgr->wcr_DM_LM_union.
			    wcr_DM.wcr_DM_name);
			kill(devmgr->wcr_dev_pid, SIGINT);
			LM_DM->wcr_dev_pid = devmgr->wcr_dev_pid;
			LM_DM->wcr_change_pending = 1;
			mms_list_remove(&wka->wcr_wka_DM_LM_list, LM_DM);
			mms_list_insert_head(&devmgr_list, LM_DM);
			mms_list_remove(&devmgr_list, devmgr);
			wcr_free_DM_LM(devmgr);
			free(devmgr);
		} else {
			/* found, no change */
			mms_trace(MMS_NOTICE, "Found Existing %s",
			    devmgr->wcr_DM_LM_union.
			    wcr_DM.wcr_DM_name);
			if (mm_changed) {
				/* point children at new mm host */
				mms_trace(MMS_NOTICE, "Sending %s SIGINT",
				    devmgr->wcr_DM_LM_union.
				    wcr_DM.wcr_DM_name);
				kill(devmgr->wcr_dev_pid, SIGINT);
			}
			mms_list_remove(&wka->wcr_wka_DM_LM_list, LM_DM);
			wcr_free_DM_LM(LM_DM);
			free(LM_DM);
		}
	}

	if (wcr_config(wka)) {
		mms_trace(MMS_ERR, "config");
		rc = 1;
		goto cleanup;
	}

	if (wcr_get_ssi(wka, NULL)) {
		mms_trace(MMS_ERR, "get ssi");
		rc = 1;
		goto cleanup;
	} else {
		wcr_exec_all_ssi(wka);
	}

	wcr_start_lm_dm(wka);

	rc = 0;

cleanup:
	/* add existing LM/DMs to list */
	for (devmgr = mms_list_head(&devmgr_list);
	    devmgr != NULL;
	    devmgr = next_devmgr) {
		next_devmgr = mms_list_next(&devmgr_list, devmgr);
		mms_list_remove(&devmgr_list, devmgr);
		mms_list_insert_tail(&wka->wcr_wka_DM_LM_list, devmgr);
	}
	mms_list_destroy(&devmgr_list);
	return (rc);
}

/*
 * wcr_connection()
 * -Handle service SIGHUP refresh
 * -Establish mm connection
 */

void
wcr_connection(wcr_wka_t *wka)
{
	int	rc = 0;

	do {
		if (wka->wcr_wka_sighup) {
			wka->wcr_wka_sighup = 0;
			wcr_refresh(wka);
		}
		if (fcntl(wka->wcr_mms_conn.mms_fd, F_GETFD, 0) == -1) {
			rc = wcr_reconnect(wka);
		}
	} while (rc);
}

int
/* LINTED: may be used later */
main(int argc, char **argv)
{

	sigset_t		cur_mask;
	sigset_t		new_mask;
	int			go = 1;
	fd_set			fdset;
	int			rc;

	/*
	 * Init the watcher
	 * -Initializes the watcher work area and device list
	 * -Becomes daemon
	 * -Reads cfg
	 * -Opens watcher device
	 */
	if (wcr_init_watcher(&wka)) {
		mms_trace(MMS_ERR, "Unable to initialize the watcher\n");
		exit(1);
	}

	mms_trace(MMS_INFO, "Watcher Starting...");


	/*
	 * Setup signal handlers
	 */
	wcr_setup_sig_handler();

	/*
	 * Setup singals to block
	 */
	sigemptyset(&new_mask);
	/* Block SIGCHLD which checking child death */
	sigaddset(&new_mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &new_mask, &cur_mask);


	while (go) {

		wcr_connection(&wka);

		FD_ZERO(&fdset);
		FD_SET(wka.wcr_mms_conn.mms_fd, &fdset);

		/* mms_trace(MMS_NOTICE, "Waiting for Event Notification\n"); */
		wcr_chk_child_death(&wka);
		while (wcr_prune(&wka)) {
			wcr_proc_events(&wka);
		}
		mms_trace(MMS_NOTICE, "Waiting on Pselect.....");
		mms_trace_flush();		   /* flush mms_trace buffer */
		rc = pselect(wka.wcr_mms_conn.mms_fd+1,
		    &fdset, NULL, NULL, NULL, &cur_mask);
		/* mms_trace(MMS_NOTICE, "Pselect returned %d error " */
		/* "code %d ", c, errno); */
		/* Process MMP commands. */
		/* mms_trace(MMS_NOTICE, "Do work"); */
		if (rc > 0) {
			wcr_do_work(&wka, &cur_mask);
		}

	}

#ifdef	MMS_OPENSSL
	mms_ssl_finish(wka.wcr_ssl_data);
#endif	/* MMS_OPENSSL */

	return (0);


}
