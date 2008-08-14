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
#include <pthread.h>
#include <synch.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <dirent.h>
#include <netdb.h>
#include <syslog.h>
#include <ctype.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <stropts.h>
#include <fcntl.h>
#include <strings.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <link.h>
#include <netdb.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/scsi/generic/sense.h>
#include <sys/scsi/generic/status.h>
#include <sys/mtio.h>
#include <sys/param.h>
#include <libgen.h>
#include <mms_list.h>
#include <mms_parser.h>
#include <dmd_impl.h>
#include <dm_impl.h>
#include <mms_network.h>
#include <dm_drive.h>
#include <mms_sym.h>
#include <dm_msg.h>
#include <mms_trace.h>
#include <mms_dmd.h>
#include <dm_proto.h>
#include <host_ident.h>
#include <mms_strapp.h>
#include <mms_cores.h>

static char	*_SrcFile = __FILE__;

static int		dm_debug = MMS_SEV_DEVP;	/* DM's default */
static int		dm_caught_usr1 = 0;
static int		dm_caught_usr2 = 0;
static int		dm_caught_term = 0;
static int		dm_caught_int = 0;
static dm_wka_t		dm_wka;
static drv_drive_t	drv_drv;
static drv_jtab_t	drv_jtab;
static drv_mount_t	drv_mount;
static drv_scsi_err_t	drv_scsi_err;
static uchar_t		drv_iobuf[DRV_IOBUF_LEN];
static drv_cart_access_t drv_dca;

dm_wka_t		*wka = &dm_wka;
drv_jtab_t		*jtab = &drv_jtab;
drv_mount_t		*mnt = &drv_mount;
drv_drive_t		*drv = &drv_drv;
drv_scsi_err_t		*serr = &drv_scsi_err;
drv_cart_access_t 	*dca = &drv_dca;
mms_list_t		dm_msg_hdr_list;

/*
 * Function name
 *	dm_init_log(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	open a trace file for DM.
 *
 * Note:
 *
 *
 */
void
dm_init_log(void)
{
	char		*trfile;

	trfile = mms_strnew("%s/%s.debug", DM_TRACE_DIR, DMNAME);
	if (mms_trace_open(trfile, MMS_ID_DM, dm_debug, -1, 1, 1)) {
		syslog(LOG_NOTICE, "Unable to open mms_trace file \"%s\"",
		    trfile);
	}
	free(trfile);
}

/*
 * Function name
 *	dm_init_wka
 *
 * Parameters:
 *	none
 *
 * Description:
 *	initialize work area.
 *	The work area hold objects needed by DM, including mutexes,
 *	condition variables, lists pointers, etc.
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

void
dm_init_wka(void)
{
	memset(wka, 0, sizeof (dm_wka_t));
	mms_list_create(&wka->dm_pend_ack_queue, sizeof (dm_command_t),
	    offsetof(dm_command_t, cmd_next));
	mms_list_create(&wka->dm_cmd_queue, sizeof (dm_command_t),
	    offsetof(dm_command_t, cmd_next));

	pthread_mutex_init(&wka->dm_io_mutex, NULL);
	pthread_mutex_init(&wka->dm_worker_mutex, NULL);
	pthread_mutex_init(&wka->dm_queue_mutex, NULL);
	pthread_mutex_init(&wka->dm_tdv_close_mutex, NULL);

	pthread_cond_init(&wka->dm_work_cv, NULL);
	pthread_cond_init(&wka->dm_tdv_close_cv, NULL);
	pthread_cond_init(&wka->dm_accept_cv, NULL);

	wka->dm_pid = getpid();
	gethostname(wka->dm_local_hostname, sizeof (wka->dm_local_hostname));

	memset(drv, 0, sizeof (drv_drv));
	memset(dca, 0, sizeof (drv_dca));
	drv->drv_iobuf = drv_iobuf;
	drv->drv_lbl_blksize = -1;
	drv->drv_file_blksize = -1;
	wka->dm_pwbuf_size = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (wka->dm_pwbuf_size <= 0) {
		wka->dm_pwbuf_size = 1024;
	}
	wka->dm_pwbuf = malloc(wka->dm_pwbuf_size);
	TRACE((MMS_DEVP, "dm_init_wka: wka initialized"));
}

/*
 * Function name
 *	dm_init_dev_lib(void *hdl)
 *
 * Parameters:
 *	hdl	pointer to the handle of the shared library that was
 *		opened by dlopen and contains device
 *		dependent code.
 *
 * Description:
 *	This function fills in the jump table used by DM to call device
 *	dependent functions and the drive table that holds some device
 *	specific information.
 *	DM initializes device libraries twice. Firstthe default library which
 *	has all the default functions and information. Then the device
 *	specific library which has only device specific information.
 *	Anything in the device specific library replaces those of the
 * default library.
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

void
dm_init_dev_lib(void *hdl, int init)
{
#define	DM_INIT_DRV(x, type) {						\
		addr = dlsym(hdl, # x);					\
		if (addr != NULL) {					\
			drv->x = type addr;				\
		} else if (init) {					\
			drv->x = NULL;					\
		}							\
	}

#define	DM_INIT_JTAB(x) {						\
		addr = dlsym(hdl, # x);					\
		if (addr != NULL) {					\
			jtab->x = (x ## _t *)addr;			\
		} else if (init) {					\
			jtab->x = NULL;					\
		}							\
	}

	void		*addr;

	DM_INIT_DRV(drv_prsv_supported, (int *));
	if (drv->drv_prsv_supported != NULL) {
		if (*(drv->drv_prsv_supported) == 1) {
			/* persistent reservation supported */
			wka->dm_flags |= DM_USE_PRSV;
		} else {
			wka->dm_flags &= ~DM_USE_PRSV;
		}
	}

	DM_INIT_DRV(drv_dev_dir, (char *));
	DM_INIT_DRV(drv_density, (mms_sym_t *));
	DM_INIT_DRV(drv_shape, (char **));
	DM_INIT_DRV(drv_shape_den, (drv_shape_density_t *));
	DM_INIT_DRV(drv_timeout, (drv_timeout_t *));
	DM_INIT_DRV(drv_drive_type, (char *));
	DM_INIT_DRV(drv_disallowed_cmds, (int *));
	DM_INIT_DRV(drv_num_disallowed_cmds, (int *));
	DM_INIT_DRV(drv_disallowed_ioctls, (int *));
	DM_INIT_DRV(drv_num_disallowed_ioctls, (int *));
	DM_INIT_DRV(drv_skaa_tab, (drv_skaa_t *));

	/*
	 * Fill the jump table with devlib functions
	 */
	DM_INIT_JTAB(drv_init_dev);
	DM_INIT_JTAB(drv_get_statistics);
	DM_INIT_JTAB(drv_get_density);
	DM_INIT_JTAB(drv_set_density);
	DM_INIT_JTAB(drv_mk_prsv_key);
	DM_INIT_JTAB(drv_disallowed);
	DM_INIT_JTAB(drv_rebind_target);
	DM_INIT_JTAB(drv_get_mounted);
	DM_INIT_JTAB(drv_get_drivetype);
	DM_INIT_JTAB(drv_get_targ);
	DM_INIT_JTAB(drv_set_blksize);
	DM_INIT_JTAB(drv_get_blksize);
	DM_INIT_JTAB(drv_read);
	DM_INIT_JTAB(drv_write);
	DM_INIT_JTAB(drv_get_capacity);
	DM_INIT_JTAB(drv_get_avail_capacity);
	DM_INIT_JTAB(drv_log_sense);
	DM_INIT_JTAB(drv_bind_raw_dev);

	/*
	 * The following are functions to execute scsi commands
	 */
	DM_INIT_JTAB(drv_clrerr);
	DM_INIT_JTAB(drv_proc_error);
	DM_INIT_JTAB(drv_inquiry);
	DM_INIT_JTAB(drv_req_sense);
	DM_INIT_JTAB(drv_wtm);
	DM_INIT_JTAB(drv_tur);
	DM_INIT_JTAB(drv_load);
	DM_INIT_JTAB(drv_unload);
	DM_INIT_JTAB(drv_rewind);
	DM_INIT_JTAB(drv_mode_sense);
	DM_INIT_JTAB(drv_mode_select);
	DM_INIT_JTAB(drv_seek);
	DM_INIT_JTAB(drv_tell);
	DM_INIT_JTAB(drv_fsf);
	DM_INIT_JTAB(drv_bsf);
	DM_INIT_JTAB(drv_fsb);
	DM_INIT_JTAB(drv_bsb);
	DM_INIT_JTAB(drv_eom);
	DM_INIT_JTAB(drv_get_pos);
	DM_INIT_JTAB(drv_mtgetpos);
	DM_INIT_JTAB(drv_mtrestpos);
	DM_INIT_JTAB(drv_locate);
	DM_INIT_JTAB(drv_blk_limit);
	DM_INIT_JTAB(drv_reserve);
	DM_INIT_JTAB(drv_release);
	DM_INIT_JTAB(drv_get_serial_num);
	DM_INIT_JTAB(drv_prsv_register);
	DM_INIT_JTAB(drv_prsv_reserve);
	DM_INIT_JTAB(drv_prsv_release);
	DM_INIT_JTAB(drv_prsv_clear);
	DM_INIT_JTAB(drv_prsv_preempt);
	DM_INIT_JTAB(drv_prsv_read_keys);
	DM_INIT_JTAB(drv_prsv_read_rsv);
	DM_INIT_JTAB(drv_get_write_protect);
	DM_INIT_JTAB(drv_set_compression);
}

/*
 * Function name
 *	dm_load_default_lib(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	loads the default library and initialize the jump table.
 *
 * Return code:
 *	0	success
 *	-1	failed
 *
 * Note:
 *
 *
 */

int
dm_load_default_lib(void)
{
	char		*libpath;

	memset(jtab, 0, sizeof (drv_jtab_t));

	/*
	 * Load the default device library
	 */
	libpath = mms_strnew("%s/%s", DM_DEV_LIB_DIR, "libdm_default.so");
	wka->dm_default_lib_hdl =
	    dlopen(libpath, RTLD_NOW | RTLD_GLOBAL | RTLD_PARENT);
	if (wka->dm_default_lib_hdl == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "default device library %s open error: %s",
		    libpath, dlerror()));
		free(libpath);
		return (-1);
	}

	/* Init jtab with default lib */
	dm_init_dev_lib(wka->dm_default_lib_hdl, 1);
	wka->dm_flags |= DM_DFLT_LIB_LOADED;
	TRACE((MMS_OPER, "device library %s initialized", libpath));
	free(libpath);
	return (0);
}

/*
 * Function name
 *	dm_load_devlib(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	get the device type and dlopen the device dependent library.
 *	initialize jump table with it.
 *
 * Return code:
 *	0	success
 *	-1	error
 *
 * Note:
 *
 *
 */

int
dm_load_devlib(void)
{
	char		*libpath;

	/*
	 * get device library name
	 */
	if (dm_get_dev_lib_name() != 0) {
		return (-1);
	}

	libpath = mms_strnew("%s/%s", DM_DEV_LIB_DIR, wka->dm_dev_lib);
	TRACE((MMS_DEVP, "Loading device library %s", libpath));
	wka->dm_dev_lib_hdl =
	    dlopen(libpath, RTLD_NOW | RTLD_GLOBAL | RTLD_PARENT);
	if (wka->dm_dev_lib_hdl == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "dynamic library open error: %s", dlerror()));
		free(libpath);
		return (-1);
	}

	/* Init jtab with device lib */
	dm_init_dev_lib(wka->dm_dev_lib_hdl, 0);
	wka->dm_flags |= DM_DEV_LIB_LOADED;
	dm_clear_dev();

	TRACE((MMS_OPER, "device library %s initialized", libpath));
	free(libpath);
	return (0);

}

/*
 * Function name
 *	dm_read_cfg(char *cfgname)
 *
 * Parameters:
 *	pointer to config file name
 *
 * Description:
 *	read the confige file passed to DM on the command line.
 *	Parse it and collect specified values.
 *
 * Return code:
 *	0	success
 *	-1	error
 *
 * Note:
 *
 *
 */

int
dm_read_cfg(char *cfgname)
{
	int		fd;
	struct	stat	statbuf;
	char		*buf;
	int		i;
	mms_par_node_t	*cfg;
	mms_par_node_t	*node;
	mms_par_node_t	*val;
	mms_par_err_t	*err;
	mms_list_t		err_list;
	char		*kw;

	fd = open(cfgname, O_RDONLY);
	if (fd < 0) {
		syslog(LOG_ERR, "Unable to open DM config file %s: %s\n",
		    cfgname, strerror(errno));
		DM_EXIT(DM_NO_RESTART);
	}

	/*
	 * Allocate a buffer to read in the entire config file
	 */
	if (fstat(fd, &statbuf)) {
		syslog(LOG_ERR, "Unable to stat DM config file %s: %s\n",
		    cfgname, strerror(errno));
		DM_EXIT(DM_NO_RESTART);
	}
	buf = malloc(statbuf.st_size + 1);
	if (buf == NULL) {
		syslog(LOG_ERR, "Unable to alloc buffer for "
		    "DM config file %s: %s\n", cfgname, strerror(errno));
		DM_EXIT(DM_NO_RESTART);
	}

	/*
	 * Read in config file
	 */
	i = read(fd, buf, statbuf.st_size);
	if (i < 0) {
		syslog(LOG_ERR, "Unable to read DM config file %s: %s\n",
		    cfgname, strerror(errno));
		DM_EXIT(DM_NO_RESTART);
	}
	buf[i] = '\0';

	/*
	 * Parse the config file
	 */
	i = mms_config_parse(&cfg, &err_list, buf);
	if (i < 0) {
		mms_list_foreach(&err_list, err) {
			syslog(LOG_ERR,
			    "line %d, col %d, near token \"%s\", "
			    "err code %d, %s\n",
			    err->pe_line,
			    err->pe_col,
			    err->pe_token,
			    err->pe_code, err->pe_msg);
		}
		syslog(LOG_ERR, "DM config file %s has errors\n", cfgname);
		DM_EXIT(DM_NO_RESTART);
	}
	free(buf);

	/*
	 * Pick up the args
	 */
	MMS_PN_LOOKUP(node, cfg, kw = "host", MMS_PN_KEYWORD, NULL);
	MMS_PN_LOOKUP(val, node, NULL, MMS_PN_STRING, NULL);
	wka->dm_host = strdup(mms_pn_token(val));

	MMS_PN_LOOKUP(node, cfg, kw = "port", MMS_PN_KEYWORD, NULL);
	MMS_PN_LOOKUP(val, node, NULL, MMS_PN_STRING, NULL);
	wka->dm_port = strdup(mms_pn_token(val));

	MMS_PN_LOOKUP(node, cfg, kw = "name", MMS_PN_KEYWORD, NULL);
	MMS_PN_LOOKUP(val, node, NULL, MMS_PN_STRING, NULL);
	DRVNAME = strdup(mms_pn_token(val));

	MMS_PN_LOOKUP(node, cfg, kw = "instance", MMS_PN_KEYWORD, NULL);
	MMS_PN_LOOKUP(val, node, NULL, MMS_PN_STRING, NULL);
	DMNAME = strdup(mms_pn_token(val));

	MMS_PN_LOOKUP(node, cfg, kw = "password", MMS_PN_KEYWORD, NULL);
	MMS_PN_LOOKUP(val, node, NULL, MMS_PN_STRING, NULL);
	wka->dm_passwd = strdup(mms_pn_token(val));

	if (node = mms_pn_lookup(cfg, kw = "mm_password",
	    MMS_PN_KEYWORD, NULL)) {
		MMS_PN_LOOKUP(val, node, NULL, MMS_PN_STRING, NULL);
		wka->dm_mm_passwd = strdup(mms_pn_token(val));
	}

	if (node = mms_pn_lookup(cfg, kw = "ssl_enabled",
	    MMS_PN_KEYWORD, NULL)) {
		MMS_PN_LOOKUP(val, node, NULL, MMS_PN_STRING, NULL);
		if (strcasecmp(mms_pn_token(val), "true") == 0)
			wka->dm_ssl_enabled = 1;
	}

	if (node = mms_pn_lookup(cfg, kw = "ssl_cert_file",
	    MMS_PN_KEYWORD, NULL)) {
		MMS_PN_LOOKUP(val, node, NULL, MMS_PN_STRING, NULL);
		wka->dm_ssl_cert_file = strdup(mms_pn_token(val));
	}

	if (node = mms_pn_lookup(cfg, kw = "ssl_pass",
	    MMS_PN_KEYWORD, NULL)) {
		MMS_PN_LOOKUP(val, node, NULL, MMS_PN_STRING, NULL);
		wka->dm_ssl_pass = strdup(mms_pn_token(val));
	}

	if (node = mms_pn_lookup(cfg, kw = "ssl_pass_file",
	    MMS_PN_KEYWORD, NULL)) {
		MMS_PN_LOOKUP(val, node, NULL, MMS_PN_STRING, NULL);
		wka->dm_ssl_pass_file = strdup(mms_pn_token(val));
	}

	if (node = mms_pn_lookup(cfg, kw = "ssl_crl_file",
	    MMS_PN_KEYWORD, NULL)) {
		MMS_PN_LOOKUP(val, node, NULL, MMS_PN_STRING, NULL);
		wka->dm_ssl_crl_file = strdup(mms_pn_token(val));
	}

	if (node = mms_pn_lookup(cfg, kw = "ssl_peer_file",
	    MMS_PN_KEYWORD, NULL)) {
		MMS_PN_LOOKUP(val, node, NULL, MMS_PN_STRING, NULL);
		wka->dm_ssl_peer_file = strdup(mms_pn_token(val));
	}

	if (node = mms_pn_lookup(cfg, kw = "ssl_cipher",
	    MMS_PN_KEYWORD, NULL)) {
		MMS_PN_LOOKUP(val, node, NULL, MMS_PN_STRING, NULL);
		wka->dm_ssl_cipher = strdup(mms_pn_token(val));
	}

	MMS_PN_LOOKUP(node, cfg, kw = "path", MMS_PN_KEYWORD, NULL);
	MMS_PN_LOOKUP(val, node, NULL, MMS_PN_STRING, NULL);
	wka->dm_drm_path = strdup(mms_pn_token(val));

	mms_pe_destroy(&err_list);
	mms_pn_destroy(cfg);

	return (0);

not_found:
	syslog(LOG_ERR, "Missing \"%s\" from DM config file %s\n", kw,
	    cfgname);
	DM_EXIT(DM_NO_RESTART);
	return (0);
}

/*
 * Function name
 *	dm_ssl_cfg(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	Configure SSL if it is enabled
 *
 * Return code:
 *	0	success
 *	DM_NO_RESTART	terminate DM if error
 *
 * Note:
 *
 *
 */

static int
dm_ssl_cfg(void)
{
	mms_network_cfg_t	net;
	mms_err_t	err;
	char		ebuf[MMS_EBUF_LEN];

#ifdef	MMS_OPENSSL
	if (wka->dm_ssl_enabled) {
		memset(&net, 0, sizeof (mms_network_cfg_t));
		net.ssl_enabled = wka->dm_ssl_enabled;
		net.ssl_cert_file = wka->dm_ssl_cert_file;
		net.ssl_pass = wka->dm_ssl_pass;
		net.ssl_pass_file = wka->dm_ssl_pass_file;
		net.ssl_crl_file = wka->dm_ssl_crl_file;
		net.ssl_peer_file = wka->dm_ssl_peer_file;
		net.ssl_cipher = wka->dm_ssl_cipher;
		if (mms_ssl_client(&net, &wka->dm_ssl_data, &err)) {
			mms_get_error_string(&err, ebuf, MMS_EBUF_LEN);
			TRACE((MMS_ERR, "ssl init - %s", ebuf));
			DM_EXIT(DM_NO_RESTART);
		}
	}
#endif	/* MMS_OPENSSL */

	return (0);
}

/*
 * Function name
 *	void dm_rem_old_handle(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	deletes handles left over from the previous
 *	run.
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

void
dm_rem_old_handle(void)
{
	DIR		*dirp;
	struct	dirent  *dp;
	int		len;
	char		*hdl;
	int		err;

	TRACE((MMS_DEVP, "dm_rem_old_handle: Removing old handles"));
	dirp = opendir(MMS_HDL_DIR);
	if (dirp == NULL) {
		err = errno;
		TRACE((MMS_CRIT, "Unable to open handle directory %s: %s",
		    MMS_HDL_DIR, strerror(err)));
		/*
		 * If directory doe not exist, then create one.
		 */
		if (err == ENOENT) {
			TRACE((MMS_DEBUG, "Createing handle directory %s",
			    MMS_HDL_DIR));
			/*
			 * create a directory named MMS_HDL_DIR,
			 * with read, write, and search permissions for
			 * owner and group, and with read and search
			 * permissions for others.
			 */
			if (mkdirp(MMS_HDL_DIR, 0755)) {
				/*
				 * create handle directory error
				 */
				err = errno;
				if (err == EEXIST) {
					TRACE((MMS_DEBUG, "%s "
					    "already created by another DM",
					    MMS_HDL_DIR));
					return;
				}
				TRACE((MMS_CRIT, "Unable to create handle "
				    "directory %s: %s",
				    MMS_HDL_DIR, strerror(err)));
				DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
				    "Unable to create handle directory %s: %s",
				    MMS_HDL_DIR, strerror(err)));
				DM_MSG_SEND((DM_ADM_ERR, 6529, NULL));
				DM_EXIT(DM_NO_RESTART);
			}
			/*
			 * Created new handle directoru
			 */
			TRACE((MMS_DEBUG, "created %s", MMS_HDL_DIR));
			return;
		}
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Unable to open handle directory %s: %s",
		    MMS_HDL_DIR, strerror(err)));
		DM_MSG_SEND((DM_ADM_ERR, 6525, NULL));
		DM_EXIT(DM_NO_RESTART);
	}

	len = strlen(wka->dm_hdl_prefix);
	while ((dp = readdir(dirp)) != NULL) {
		if (strncmp(dp->d_name, wka->dm_hdl_prefix, len) == 0) {
			/* found an old handle */
			hdl = mms_strapp(NULL,
			    "%s/%s", MMS_HDL_DIR, dp->d_name);
			TRACE((MMS_DEVP,
			    "dm_rem_old_handle: Removing handle %s",
			    dp->d_name));
			unlink(hdl);
			free(hdl);
		}
	}
	closedir(dirp);
}

/*
 * Function name
 *	dm_init(int argc, char **argv)
 *
 * Parameters:
 *	the command line arguments which is the pathname of
 *	the config file.
 *
 * Description:
 *	- close all files and reopen the std* files.
 *	- read config file
 *	- initialize log, wka and ssl
 *	- open the drm device
 *
 * Return code:
 *	0	success
 *	exit DM if error.
 *
 * Note:
 *
 *
 */

/* ARGSUSED */
int
dm_init(int argc, char **argv)
{
	int		i;
	int		retries = 0;
	char		*corename;

	TRACE((MMS_DEVP, "dm_init: Initializing DM"));

	/*
	 * Close all opened files.
	 */
	for (i = 0; i < OPEN_MAX; i++)
		close(i);

	/*
	 * Direct stdin, stdout and stderr to /dev/null
	 */
	fopen("/dev/null", "r");
	fopen("/dev/null", "w");
	fopen("/dev/null", "w");

	setsid();			/* become session leader */
	umask(0);			/* clear file mode create mask */

	mms_sort_sym_code(dm_msg_cat, dm_msg_cat_num);	/* sort msg catalog */

	dm_init_wka();

	/*
	 * Read config file
	 * Path of config file is argv[1]
	 */
	if (dm_read_cfg(argv[1])) {
		DM_EXIT(DM_NO_RESTART);
	}

	/* Move to where core files will be placed */
	if (mms_set_core(MMS_CORES_DIR, DMNAME)) {
		TRACE((MMS_ERR, "dm_init: DM's core setup failed %s",
		    strerror(errno)));
	}

	corename = mms_strnew("core.mmsdm.%s", DMNAME);
	/* Check to see how many core files exist */
	if (mms_man_cores(MMS_CORES_DIR, corename)) {
		TRACE((MMS_ERR, "dm_init: DM's mms_man_cores failed %s",
		    strerror(errno)));
	}
	free(corename);


	/*
	 * Init message logging
	 */
	dm_init_log();
	TRACE((MMS_OPER, "dm_init: ******** Starting DM %s ********",
	    DMNAME));

	/*
	 * Open the DM device
	 */
	while (dm_open_dm_device() < 0) {
		if (errno == EBUSY && retries <= DM_OPEN_RETRIES) {
			/* device is still opened */
			sleep(DM_OPEN_INTERVAL);
			retries++;
		}
		TRACE((MMS_ERR, "Unable to open DM device: %s",
		    strerror(errno)));
		DM_EXIT(DM_NO_RESTART);
	}

	/*
	 * Init ssl
	 */
	if (dm_ssl_cfg()) {
		DM_EXIT(DM_NO_RESTART);
	}

	/*
	 * Start session with SMM
	 */
	if (dm_init_session(0)) {
		TRACE((MMS_CRIT, "Unable to start a session with SMM"));
		DM_EXIT(DM_NO_RESTART);
	}

	return (0);
}

/*
 * Function name
 *	dm_get_dev_lib_name(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	Get device dependent library name and save it in work area.
 *	Library name is constructed from the vendor and product ID's from
 *	the inquiry data like this:
 *	lib<vendor>-<product>.o
 *	where :
 *	<vendor> is the vendor id with trailing blanks removed and
 *		each remaining blank substituted with a '_' character.
 *	<product> is the product id with trailing blanks removed and
 *		each remaining blank substituted with a '_' character.
 *
 * Return code:
 *	0	success
 *	-1	error
 *
 * Note:
 *
 *
 */

int
dm_get_dev_lib_name(void)
{
	char		vendor[9];
	char		prod[17];
	int		i;

	if (drv->drv_flags & DRV_FATAL) {
		return (EIO);
	}

	/*
	 * Read the inquiry data
	 */
	if (DRV_CALL(drv_get_drivetype, ())) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get vendor and product ID: %s",
		    strerror(errno)));
		mms_trace_flush();
		return (-1);
	}

	(void) strlcpy(vendor, drv->drv_vend, sizeof (vendor));
	/* trim trailing blanks */
	for (i = strlen(vendor) - 1; i >= 0 && vendor[i] == ' '; i--) {
		vendor[i] = '\0';
	}
	(void) strlcpy(prod, drv->drv_prod, sizeof (prod));
	for (i = strlen(prod) - 1; i >= 0 && prod[i] == ' '; i--) {
		prod[i] = '\0';
	}

	/* Convert remaining blanks to '_' */
	for (i = 0; vendor[i] != '\0'; i++) {
		if (vendor[i] == ' ') {
			vendor[i] = '_';
		}
	}
	for (i = 0; prod[i] != '\0'; i++) {
		if (prod[i] == ' ') {
			prod[i] = '_';
		}
	}

	wka->dm_dev_lib = mms_strnew("lib%s_%s.so", vendor, prod);
	TRACE((MMS_INFO, "Device lib name = %s", wka->dm_dev_lib));
	return (0);
}

/*
 * Function name
 *	dm_init_session(int retries)
 *
 * Parameters:
 *	number of retries
 *
 * Description:
 *	initialize a session with the Media Manager
 *	retry until success or until the number of retries is exceeded.
 *
 * Return code:
 *	fd		If a welcome response was received from MM, then
 *			this routine returns the file descriptor that the
 *			client will use to communicate with MM.
 *	MMS_ERROR	If an error occurred while processing or if an
 *			unwelcome response was receieved from MM.
 *
 *
 * Note:
 *
 *
 */

int
dm_init_session(int retries)
{
	int		rc;
	mms_network_cfg_t	cfg;
	int		err;
	char		*tag = NULL;

	TRACE((MMS_DEVP, "dm_init_session: Initializing session"));
	/*
	 * 0 retries means forever
	 */
	if (retries == 0) {
		retries = 0x7fffffff;
	}

	memset(&cfg, 0, sizeof (mms_network_cfg_t));
	cfg.cli_host = strdup(wka->dm_host);
	cfg.cli_port = strdup(wka->dm_port);
	cfg.cli_name = strdup(drv->drv_drvname);
	cfg.cli_inst = strdup(drv->drv_dmname);
	cfg.cli_lang = MMS_DMP_LANG;
	cfg.cli_vers = MMS_DMP_VERSION;
	cfg.cli_pass = strdup(wka->dm_passwd);
	if (wka->dm_mm_passwd) {
		cfg.mm_pass = strdup(wka->dm_mm_passwd);
	}

	for (; retries > 0; retries--) {
		if ((rc = mms_mmconnect(&cfg, wka->dm_ssl_data,
		    &wka->dm_mms_conn, &err, tag)) != 0) {
			/*
			 * Unable to connect to mm
			 */
			TRACE((MMS_WARN, "DM %s unable to connect "
			    "to MM: %d: %s", DMNAME,
			    err, mms_sym_code_to_str(err)));
			if (retries > 1) {
				wka->dm_flags |= DM_SILENT;
				sleep(DM_CONNECT_INTERVAL);
			} else {
				break;
			}
		} else {
			/*
			 * Successfully connected to MM
			 */
			wka->dm_flags &= ~DM_SILENT;
			wka->dm_flags |= DM_HAVE_SESSION;
			TRACE((MMS_OPER, "dm_init_session: "
			    "DM %s connected to MM on %s %s",
			    DMNAME, wka->dm_host, wka->dm_port));
			break;
		}
	}

	return (rc);
}

/*
 * Signal catching functions
 */

/*
 * Function name
 *	dm_sigusr1(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	SIGUSR1 catcher
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

void
dm_sigusr1(void)
{
	TRACE((MMS_DEVP, "dm_sigusr1: Caught SIGUSR1"));
	dm_caught_usr1 = 1;
}

/*
 * Function name
 *	dm_sigusr2(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	SIGUSR2 catcher
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

void
dm_sigusr2(void)
{
	TRACE((MMS_DEVP, "dm_sigusr2: Caught SIGUSR2"));
	dm_caught_usr2 = 1;
}


/*
 * Function name
 *	dm_sigint(void)
 *
 * Parameters:
 *	void
 *
 * Description:
 *	SIGINT catcher
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

void
dm_sigint(void)
{
	/*
	 * Terminate this drive manager
	 */
	TRACE((MMS_DEVP, "dm_sigint: Caught SIGINT"));
	mms_trace_flush();
	dm_caught_int = 1;
}

/*
 * Function name
 *	dm_sigterm(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	SIGTERM catcher
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

void
dm_sigterm(void)
{
	/*
	 * Terminate this drive manager
	 */
	TRACE((MMS_DEVP, "dm_sigterm: Caught SIGTERM"));
	mms_trace_flush();
	dm_caught_term = 1;
}

/*
 * Function name
 *	dm_sighup(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	SIGHUP catcher
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

void
dm_sighup(void)
{
	/*
	 * Ignore Sighup
	 */
	TRACE((MMS_DEVP, "dm_sighup: Caught SIGHUP"));
	mms_trace_flush();
	/* Ignore sighup */
}

/*
 * Function name
 *	dm_signal(int sig, void (*handler) ())
 *
 * Parameters:
 *	sig	signal number
 *	handler	signal handler
 *
 * Description:
 *	install signal handler
 *
 * Return code:
 *	none	if success
 *	exit	if error
 *
 * Note:
 *
 *
 */

void
dm_signal(int sig, void (*handler) ())
{
	/*
	 * Setup to catch signals
	 */
	struct	sigaction act, oact;

	TRACE((MMS_DEVP, "dm_signal: Setting signal handler"));
	memset(&act, 0, sizeof (act));
	act.sa_sigaction = handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sig != SIGALRM) {
		/*
		 * Allow alarm signal to interrupt
		 */
		act.sa_flags |= SA_RESTART;
	}
	if (sigaction(sig, &act, &oact) < 0) {
		TRACE((MMS_ERR, "Can't set signal handler for "
		    "signal %d: %s", sig, strerror(errno)));
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Unable to set signal handler for "
		    "signal %d: %s", sig, strerror(errno)));
		DM_MSG_SEND((DM_ADM_ERR, 6525, NULL));
		DM_EXIT(DM_NO_RESTART);
	}
}

/*
 * Function name
 *	dm_setup_sig_handler(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	setup to install all signal handlers
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */


void
dm_setup_sig_handler(void)
{
	/*
	 * Setup SIGTERM handler
	 * Terminate drive manager
	 */
	TRACE((MMS_DEVP, "dm_setup_sig_handler: Catching SIGTERM"));
	dm_signal(SIGTERM, dm_sigterm);

	/*
	 * Setup SIGUSR1 handler
	 * Driver request
	 */
	TRACE((MMS_DEVP, "dm_setup_sig_handler: Catching SIGUSR1"));
	dm_signal(SIGUSR1, dm_sigusr1);

	/*
	 * Setup SIGUSR2 handler
	 * tdv device closed
	 */
	TRACE((MMS_DEVP, "dm_setup_sig_handler: Catching SIGUSR2"));
	dm_signal(SIGUSR2, dm_sigusr2);

	/*
	 * Setup SIGHUP handler
	 */
	TRACE((MMS_DEVP, "dm_setup_sig_handler: Catching SIGHUP"));
	dm_signal(SIGHUP, dm_sighup);

	/*
	 * Setup SIGINT handler
	 */
	TRACE((MMS_DEVP, "dm_setup_sig_handler: Catching SIGINT"));
	dm_signal(SIGINT, dm_sigint);
}

int
main(int argc, char **argv)
{
	sigset_t	new_mask;
	sigset_t	old_mask;
	pthread_t	tid;
	int		rc = 0;
	fd_set		fdset;
	timespec_t	*tvp;
	int		nfds;
	int		always = 1;

	/*
	 * Initialize message
	 */
	mms_list_create(&dm_msg_hdr_list, sizeof (dm_msg_hdr_t),
	    offsetof(dm_msg_hdr_t, msg_next));
	dm_msg_create_hdr();

	/*
	 * Init the drive manager
	 */
	if (dm_init(argc, argv)) {
		TRACE((MMS_ERR,
		    "Unable to initialize the drive manager\n"));
		DM_EXIT(DM_NO_RESTART);
	}

	/*
	 * Create handle prefix
	 */
	wka->dm_hdl_prefix = mms_strapp(NULL,
	    "%s.%s.%s",
	    wka->dm_local_hostname, DMNAME, DRVNAME);

	/*
	 * Setup to block signals DM cares about.
	 * This is inherited by the worker thread so that it will not
	 * be interrupted by signals.
	 */
	sigemptyset(&new_mask);
	sigaddset(&new_mask, SIGUSR1);
	sigaddset(&new_mask, SIGUSR2);
	sigaddset(&new_mask, SIGINT);
	sigaddset(&new_mask, SIGTERM);
	sigaddset(&new_mask, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask);

	/*
	 * DM successfully started
	 */
	TRACE((MMS_OPER, "DM initialized: DMName = %s, DriveName = %s",
	    DMNAME, DRVNAME));
	/*
	 * Start processing threads.
	 */
	pthread_create(&tid, NULL, dm_worker, wka);

	/*
	 * Setup signal handlers
	 */
	dm_setup_sig_handler();

	/*
	 * Main loop
	 */
	while (always) {

		/* wakeup worker thread to do work */
		pthread_mutex_lock(&wka->dm_worker_mutex);
		wka->dm_work_todo = 1;
		pthread_cond_broadcast(&wka->dm_work_cv);
		pthread_mutex_unlock(&wka->dm_worker_mutex);

		/*
		 * Setup for pselect
		 */
		nfds = 0;
		if (wka->dm_flags & DM_HAVE_SESSION) {
			nfds = wka->dm_mms_conn.mms_fd + 1;
			FD_ZERO(&fdset);
			FD_SET(wka->dm_mms_conn.mms_fd, &fdset);
			tvp = NULL;
		}

		/*
		 * pselect will unblock signals blocked earlier
		 */
		rc = pselect(nfds, &fdset, NULL, NULL, tvp, &old_mask);

		if (dm_caught_term) {
			dm_caught_term = 0;
			TRACE((MMS_DEBUG, "DM exit: caught SIGTERM"));
			DM_EXIT(DM_NO_RESTART);
		}

		if (dm_caught_int) {
			dm_caught_int = 0;
			TRACE((MMS_DEBUG, "DM restart: caught SIGINT"));
			DM_EXIT(DM_RESTART);
		}

		if (dm_caught_usr2) {
			dm_caught_usr2 = 0;
			TRACE((MMS_DEBUG, "caught SIGUSR2: "
			    "Waking up waiting command"));
			pthread_mutex_lock(&wka->dm_tdv_close_mutex);
			pthread_cond_broadcast(&wka->dm_tdv_close_cv);
			pthread_mutex_unlock(&wka->dm_tdv_close_mutex);
		}

		if (dm_caught_usr1) {
			dm_caught_usr1 = 0;
			dm_get_request();
		}

		if (rc > 0) {
			/* Input pending */
			if (FD_ISSET(wka->dm_mms_conn.mms_fd, &fdset)) {
				/* Read input and put it on input list */
				dm_read_input();
			}
		}

		/*
		 * If connection to MM is closed, try reconnect
		 */
		if ((wka->dm_flags & DM_HAVE_SESSION) == 0) {
			wka->dm_flags |= DM_SILENT;
			dm_restart_session();
			wka->dm_flags &= ~DM_SILENT;
		}
		if (wka->dm_flags & DM_HAVE_SESSION) {
			/* Try sending accept again */
			pthread_mutex_lock(&wka->dm_queue_mutex);
			if (!mms_list_empty(&wka->dm_pend_ack_queue)) {
				pthread_mutex_unlock(&wka->dm_queue_mutex);
				dm_accept_cmds();
				pthread_mutex_lock(&wka->dm_queue_mutex);
			}
			pthread_mutex_unlock(&wka->dm_queue_mutex);
		}

	}
	return (0);
}

/*
 * Function name
 *	dm_restart_session(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	restart a session with MM if it was disconnected
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

void
dm_restart_session(void)
{
	TRACE((MMS_OPER, "dm_restart_session: Restarting session"));
	(void) dm_init_session(1);
}

/*
 * Function name
 *	dm_worker(void *arg)
 *
 * Parameters:
 *	arg	work area pointer
 *
 * Description:
 *	main loop of worker thread. This is where all the work is done.
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

void *
dm_worker(void *arg)
{
	dm_wka_t	*wka = arg;
	int		always = 1;

	TRACE((MMS_DEVP, "dm_worker: Starting worker thread"));

	dm_msg_create_hdr();

	/*
	 * Remove old handles created by this DM
	 */
	dm_rem_old_handle();

	/*
	 * Dispatch any commands from MM
	 */
	dm_dispatch_cmds();

	/*
	 * Wait for work to do
	 */
	while (always) {
		mms_trace_flush();		/* flush mms_trace buffer */
		/*
		 * Wait for work to do
		 */
		pthread_mutex_lock(&wka->dm_worker_mutex);
		while (wka->dm_work_todo == 0) {
			pthread_cond_wait(&wka->dm_work_cv,
			    &wka->dm_worker_mutex);
		}
		wka->dm_work_todo = 0;
		pthread_mutex_unlock(&wka->dm_worker_mutex);

		if (wka->dm_flags & DM_HAVE_SESSION) {
			/*
			 * Update capacity
			 */
			if (wka->dm_flags & DM_SEND_CAPACITY) {
				(void) dm_send_capacity(&drv->drv_cap);
				wka->dm_flags &= ~DM_SEND_CAPACITY;
			}
			/*
			 * Update EOF pos
			 */
			if (wka->dm_flags & DM_SEND_EOF_POS) {
				(void) dm_send_eof_pos();
				wka->dm_flags &= ~DM_SEND_EOF_POS;
			}
		}

		if (wka->dm_request) {
			dm_proc_request();
		}

		dm_dispatch_cmds();
	}
	return (NULL);
}

/*
 * Function name
 *	dm_exit(int code, char *file, int line)
 *
 * Parameters:
 *	code	exit code, DM_RESTART/DM_NO_RESTART
 *	file	source file from which dm_exit is called
 *	line	line number in file
 *
 * Description:
 *	close and flush trace file before exiting
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

/*
 * Exit DM
 */
void
dm_exit(int code, char *file, int line)
{
	TRACE((MMS_OPER, "######## Exiting DM %s, from "
	    "file %s, line %d with %s ########",
	    DMNAME, file, line,
	    code == DM_NO_RESTART ? "DM_NO_RESTART" : "DM_RESTART"));
	mms_trace_close();
	exit(code);
}

/*
 * Function name
 *	dm_mk_prsv_key(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	Make a persistent reservation key
 *	1st 4 bytes are a constant character array (DRV_PRSV_KEY_PFX)
 *	followed by 4 bytes of IP mms_address (in hex).
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

void
dm_mk_prsv_key(void)
{
	char		host_name[MMS_HOST_IDENT_LEN + 1];
	char		host_ip[MMS_IP_IDENT_LEN + 1];
	char		*ipp;
	char		*cp;
	int		tmp;
	uint32_t	ip = 0;
	char		dumpbuf[512];
	int		i;

	/*
	 * Get IP mms_address - a string
	 */
	(void) mms_host_info(host_name, host_ip);
	TRACE((MMS_DEVP, "host_ip = %s", host_ip));

	/*
	 * Convert to 4 hex digits.
	 */
	ipp = host_ip;
	for (i = 0; i < 4; i++) {
		cp = strchr(ipp, '.');
		if (cp != NULL) {
			*cp = '\0';
		}
		sscanf(ipp, "%d", &tmp);
		ip |= (tmp << ((4 - i - 1) * 8));
		ipp = cp + 1;
	}

	(void) memcpy((char *)drv->drv_prsv_key, DRV_PRSV_KEY_PFX,
	    sizeof (drv->drv_prsv_key));
	int32_to_char(ip, (uchar_t *)drv->drv_prsv_key + 4, 4);

	(void) mms_trace_dump((char *)drv->drv_prsv_key, 8,
	    dumpbuf, sizeof (dumpbuf));
	TRACE((MMS_DEVP, "PRSV key: %s", dumpbuf));

	/*
	 * Tell driver
	 */
	ioctl(wka->dm_drm_fd, DRM_PRSV_KEY, drv->drv_prsv_key);
}

/*
 * Function name
 *	dm_silent(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	return silent mode status
 *
 * Return code:
 *	0	not silent
 *	> 0	silent
 *
 * Note:
 *
 *
 */

int
dm_silent(void)
{
	return (wka->dm_flags & DM_SILENT);
}

/*
 * Function name
 *	dm_trace(mms_trace_sev_t severity, char *file, int line, char *fmt, ...)
 *
 * Parameters:
 *	severity	severity of trace msg
 *	file		source filename
 *	line		source file line number
 *	fmt, ...	format and args of printf
 *
 * Description:
 *	trace function for DM. If in silent mode, don't trace.
 *
 * Return code:
 *	1	dm_trace returns 1 in macro DRV_CALL so that it may
 *		trace and call the function.
 *
 * Note:
 *
 *
 */

int
dm_trace(mms_trace_sev_t severity, char *file, int line, char *fmt, ...)
{
	va_list		args;

	if (!dm_silent()) {
		va_start(args, fmt);
		mms_trace_va(severity, file, line, fmt, args);
		va_end(args);
	}
	return (1);
}
