/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/* Copyright (c) 2007, The Storage Networking Industry Association. */
/* Copyright (c) 1996, 1997 PDC, Network Appliance. All Rights Reserved */
/* Copyright 2014 Nexenta Systems, Inc.  All rights reserved. */

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#include <sys/mntio.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <sys/scsi/scsi.h>
#include <unistd.h>
#include <sys/systeminfo.h>
#include "ndmpd_common.h"
#include "ndmpd.h"

static void simple_get_attrs(ulong_t *attributes);

/*
 * Number of environment variable for the file system
 * info in V3 net_fs_info.
 */
#define	V3_N_FS_ENVS	4

/*
 * Is the file system a valid one to be reported to the
 * clients?
 */
#define	IS_VALID_FS(fs) (fs && ( \
	strcasecmp(fs->mnt_fstype, MNTTYPE_UFS) == 0 || \
	strcasecmp(fs->mnt_fstype, MNTTYPE_ZFS) == 0 || \
	strcasecmp(fs->mnt_fstype, MNTTYPE_NFS) == 0 || \
	strcasecmp(fs->mnt_fstype, MNTTYPE_NFS3) == 0 || \
	strcasecmp(fs->mnt_fstype, MNTTYPE_NFS4) == 0))

#define	MNTTYPE_LEN	10

extern struct fs_ops sfs2_ops;
extern struct fs_ops sfs2cpv_ops;


/*
 * ************************************************************************
 * NDMP V2 HANDLERS
 * ************************************************************************
 */

/*
 * ndmpd_config_get_host_info_v2
 *
 * This handler handles the ndmp_config_get_host_info request.
 * Host specific information is returned.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_config_get_host_info_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_config_get_host_info_reply_v2 reply;
	ndmp_auth_type auth_types[2];
	char buf[HOSTNAMELEN + 1];
	struct utsname uts;
	char hostidstr[16];
	ulong_t hostid;

	(void) memset((void*)&reply, 0, sizeof (reply));
	(void) memset(buf, 0, sizeof (buf));
	(void) gethostname(buf, sizeof (buf));

	reply.error = NDMP_NO_ERR;
	reply.hostname = buf;
	(void) uname(&uts);
	reply.os_type = uts.sysname;
	reply.os_vers = uts.release;

	if (sysinfo(SI_HW_SERIAL, hostidstr, sizeof (hostidstr)) < 0) {
		NDMP_LOG(LOG_DEBUG, "sysinfo error: %m.");
		reply.error = NDMP_UNDEFINED_ERR;
	}

	/*
	 * Convert the hostid to hex. The returned string must match
	 * the string returned by hostid(1).
	 */
	hostid = strtoul(hostidstr, 0, 0);
	(void) snprintf(hostidstr, sizeof (hostidstr), "%lx", hostid);
	reply.hostid = hostidstr;

	auth_types[0] = NDMP_AUTH_TEXT;
	reply.auth_type.auth_type_len = 1;
	reply.auth_type.auth_type_val = auth_types;

	ndmp_send_reply(connection, (void *) &reply,
	    "sending ndmp_config_get_host_info reply");
}


/*
 * ndmpd_config_get_butype_attr_v2
 *
 * This handler handles the ndmp_config_get_butype_attr request.
 * Information about the specified backup type is returned.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_config_get_butype_attr_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_config_get_butype_attr_request *request;
	ndmp_config_get_butype_attr_reply reply;

	request = (ndmp_config_get_butype_attr_request *)body;

	reply.error = NDMP_NO_ERR;

	if (strcmp(request->name, "dump") == 0) {
		(void) simple_get_attrs(&reply.attrs);
	} else if (strcmp(request->name, "tar") == 0) {
		reply.attrs = NDMP_NO_BACKUP_FILELIST;
	} else {
		NDMP_LOG(LOG_ERR, "Invalid backup type: %s.", request->name);
		NDMP_LOG(LOG_ERR,
		    "Supported backup types are 'dump' and 'tar' only.");
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
	}

	ndmp_send_reply(connection, (void *) &reply,
	    "sending ndmp_config_get_butype_attr reply");
}


/*
 * ndmpd_config_get_mover_type_v2
 *
 * This handler handles the ndmp_config_get_mover_type request.
 * Information about the supported mover types is returned.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_config_get_mover_type_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_config_get_mover_type_reply reply;
	ndmp_addr_type types[2];

	types[0] = NDMP_ADDR_LOCAL;
	types[1] = NDMP_ADDR_TCP;

	reply.error = NDMP_NO_ERR;
	reply.methods.methods_len = 2;
	reply.methods.methods_val = types;

	ndmp_send_reply(connection, (void *) &reply,
	    "sending ndmp_config_get_mover_type reply");
}



/*
 * ndmpd_config_get_auth_attr_v2
 *
 * This handler handles the ndmp_config_get_auth_attr request.
 * Authorization type specific information is returned.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_config_get_auth_attr_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_config_get_auth_attr_request *request;
	ndmp_config_get_auth_attr_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	request = (ndmp_config_get_auth_attr_request *)body;

	reply.error = NDMP_NO_ERR;
	reply.server_attr.auth_type = request->auth_type;

	switch (request->auth_type) {
	case NDMP_AUTH_TEXT:
		break;
	case NDMP_AUTH_MD5:
		/* Create a 64 byte random session challenge */
		randomize(session->ns_challenge, MD5_CHALLENGE_SIZE);
		(void) memcpy(reply.server_attr.ndmp_auth_attr_u.challenge,
		    session->ns_challenge, MD5_CHALLENGE_SIZE);
		break;
	case NDMP_AUTH_NONE:
		/* FALL THROUGH */
	default:
		NDMP_LOG(LOG_ERR, "Invalid authentication type: %d.",
		    request->auth_type);
		NDMP_LOG(LOG_ERR,
		    "Supported authentication types are md5 and cleartext.");
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		break;
	}

	ndmp_send_reply(connection, (void *) &reply,
	    "sending ndmp_config_get_auth_attr reply");
}


/*
 * ************************************************************************
 * NDMP V3 HANDLERS
 * ************************************************************************
 */

/*
 * ndmpd_config_get_host_info_v3
 *
 * This handler handles the ndmp_config_get_host_info request.
 * Host specific information is returned.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_config_get_host_info_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_config_get_host_info_reply_v3 reply;
	char buf[HOSTNAMELEN+1];
	struct utsname uts;
	char hostidstr[16];
	ulong_t hostid;

	(void) memset((void*)&reply, 0, sizeof (reply));
	(void) memset(buf, 0, sizeof (buf));
	(void) gethostname(buf, sizeof (buf));


	reply.error = NDMP_NO_ERR;
	reply.hostname = buf;
	(void) uname(&uts);
	reply.os_type = uts.sysname;
	reply.os_vers = uts.release;

	if (sysinfo(SI_HW_SERIAL, hostidstr, sizeof (hostidstr)) < 0) {

		NDMP_LOG(LOG_DEBUG, "sysinfo error: %m.");
		reply.error = NDMP_UNDEFINED_ERR;
	}

	/*
	 * Convert the hostid to hex. The returned string must match
	 * the string returned by hostid(1).
	 */
	hostid = strtoul(hostidstr, 0, 0);
	(void) snprintf(hostidstr, sizeof (hostidstr), "%lx", hostid);
	reply.hostid = hostidstr;

	ndmp_send_reply(connection, (void *) &reply,
	    "sending ndmp_config_get_host_info reply");
}


/*
 * ndmpd_config_get_connection_type_v3
 *
 * This handler handles the ndmp_config_get_connection_type_request.
 * A list of supported data connection types is returned.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_config_get_connection_type_v3(ndmp_connection_t *connection,
    void *body)
{
	ndmp_config_get_connection_type_reply_v3 reply;
	ndmp_addr_type addr_types[2];

	(void) memset((void*)&reply, 0, sizeof (reply));

	reply.error = NDMP_NO_ERR;

	addr_types[0] = NDMP_ADDR_LOCAL;
	addr_types[1] = NDMP_ADDR_TCP;
	reply.addr_types.addr_types_len = 2;
	reply.addr_types.addr_types_val = addr_types;

	ndmp_send_reply(connection, (void *) &reply,
	    "sending config_get_connection_type_v3 reply");
}



/*
 * ndmpd_config_get_auth_attr_v3
 *
 * This handler handles the ndmp_config_get_auth_attr request.
 * Authorization type specific information is returned.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_config_get_auth_attr_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_config_get_auth_attr_request *request;
	ndmp_config_get_auth_attr_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	request = (ndmp_config_get_auth_attr_request *)body;

	(void) memset((void*)&reply, 0, sizeof (reply));
	reply.error = NDMP_NO_ERR;
	reply.server_attr.auth_type = request->auth_type;

	switch (request->auth_type) {
	case NDMP_AUTH_TEXT:
		break;
	case NDMP_AUTH_MD5:
		/* Create a 64 bytes random session challenge */
		randomize(session->ns_challenge, MD5_CHALLENGE_SIZE);
		(void) memcpy(reply.server_attr.ndmp_auth_attr_u.challenge,
		    session->ns_challenge, MD5_CHALLENGE_SIZE);
		break;
	case NDMP_AUTH_NONE:
		/* FALL THROUGH */
	default:
		NDMP_LOG(LOG_ERR, "Invalid authentication type: %d.",
		    request->auth_type);
		NDMP_LOG(LOG_ERR,
		    "Supported authentication types are md5 and cleartext.");
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		break;
	}

	ndmp_send_reply(connection, (void *) &reply,
	    "sending ndmp_config_get_auth_attr_v3 reply");
}


/*
 * ndmpd_config_get_butype_info_v3
 *
 * This handler handles the ndmp_config_get_butype_info_request.
 * Information about all supported backup types are returned.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_config_get_butype_info_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_config_get_butype_info_reply_v3 reply;
	ndmp_butype_info info[3];
	ndmp_pval envs[8];
	ulong_t attrs;
	ndmp_pval *envp = envs;

	ndmp_pval zfs_envs[9];
	ulong_t zfs_attrs;
	ndmp_pval *zfs_envp = zfs_envs;

	(void) memset((void*)&reply, 0, sizeof (reply));

	/*
	 * Supported environment variables and their default values
	 * for dump and tar.
	 *
	 * The environment variables for dump and tar format are the
	 * same, because we use the same backup engine for both.
	 */
	NDMP_SETENV(envp, "PREFIX", "");
	NDMP_SETENV(envp, "TYPE", "");
	NDMP_SETENV(envp, "DIRECT", "n");
	NDMP_SETENV(envp, "HIST", "n");
	NDMP_SETENV(envp, "FILESYSTEM", "");
	NDMP_SETENV(envp, "LEVEL", "0");
	NDMP_SETENV(envp, "UPDATE", "TRUE");
	NDMP_SETENV(envp, "BASE_DATE", "");

	attrs = NDMP_BUTYPE_BACKUP_FILE_HISTORY |
	    NDMP_BUTYPE_RECOVER_FILELIST |
	    NDMP_BUTYPE_BACKUP_DIRECT |
	    NDMP_BUTYPE_BACKUP_INCREMENTAL |
	    NDMP_BUTYPE_BACKUP_UTF8 |
	    NDMP_BUTYPE_RECOVER_UTF8;

	/* If DAR supported */
	if (ndmp_dar_support)
		attrs |= NDMP_BUTYPE_RECOVER_DIRECT;

	/* tar backup type */
	info[0].butype_name = "tar";
	info[0].default_env.default_env_len = ARRAY_LEN(envs, ndmp_pval);
	info[0].default_env.default_env_val = envs;
	info[0].attrs = attrs;

	/* dump backup type */
	info[1].butype_name = "dump";
	info[1].default_env.default_env_len = ARRAY_LEN(envs, ndmp_pval);
	info[1].default_env.default_env_val = envs;
	info[1].attrs = attrs;

	/*
	 * Supported environment variables and their default values
	 * for type "zfs."
	 */

	NDMP_SETENV(zfs_envp, "PREFIX", "");
	NDMP_SETENV(zfs_envp, "FILESYSTEM", "");
	NDMP_SETENV(zfs_envp, "TYPE", "zfs");
	NDMP_SETENV(zfs_envp, "HIST", "n");
	NDMP_SETENV(zfs_envp, "LEVEL", "0");
	NDMP_SETENV(zfs_envp, "ZFS_MODE", "recursive");
	NDMP_SETENV(zfs_envp, "ZFS_FORCE", "FALSE");
	NDMP_SETENV(zfs_envp, "UPDATE", "TRUE");
	NDMP_SETENV(zfs_envp, "DMP_NAME", "level");

	zfs_attrs = NDMP_BUTYPE_BACKUP_UTF8 |
	    NDMP_BUTYPE_RECOVER_UTF8 |
	    NDMP_BUTYPE_BACKUP_DIRECT |
	    NDMP_BUTYPE_BACKUP_INCREMENTAL;

	/* zfs backup type */
	info[2].butype_name = "zfs";
	info[2].default_env.default_env_len = ARRAY_LEN(zfs_envs, ndmp_pval);
	info[2].default_env.default_env_val = zfs_envs;
	info[2].attrs = zfs_attrs;

	reply.error = NDMP_NO_ERR;
	reply.butype_info.butype_info_len = ARRAY_LEN(info, ndmp_butype_info);
	reply.butype_info.butype_info_val = info;

	ndmp_send_reply(connection, (void *)&reply,
	    "sending ndmp_config_get_butype_info reply");
}

/*
 * ndmpd_config_get_fs_info_v3
 *
 * This handler handles the ndmp_config_get_fs_info_request.
 * Information about all mounted file systems is returned.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_config_get_fs_info_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_config_get_fs_info_reply_v3 reply;
	ndmp_fs_info_v3 *fsip = NULL, *fsip_save = NULL; /* FS info pointer */
	int len = 0, nmnt, fd;
	int log_dev_len;
	FILE *fp = NULL;
	struct mnttab mt, *fs;
	struct statvfs64 stat_buf;
	ndmp_pval *envp, *save;

	(void) memset((void*)&reply, 0, sizeof (reply));
	reply.error = NDMP_NO_ERR;

	if ((fd = open(MNTTAB, O_RDONLY)) == -1) {
		NDMP_LOG(LOG_ERR, "File mnttab open error: %m.");
		reply.error = NDMP_UNDEFINED_ERR;
		goto send_reply;
	}

	/* nothing was found, send an empty reply */
	if (ioctl(fd, MNTIOC_NMNTS, &nmnt) != 0 || nmnt <= 0) {
		(void) close(fd);
		NDMP_LOG(LOG_ERR, "No file system found.");
		goto send_reply;
	}

	fp = fdopen(fd, "r");
	if (!fp) {
		(void) close(fd);
		NDMP_LOG(LOG_ERR, "File mnttab open error: %m.");
		reply.error = NDMP_UNDEFINED_ERR;
		goto send_reply;
	}

	fsip_save = fsip = ndmp_malloc(sizeof (ndmp_fs_info_v3) * nmnt);
	if (!fsip) {
		(void) fclose(fp);
		reply.error = NDMP_NO_MEM_ERR;
		goto send_reply;
	}

	/*
	 * Re-read the directory and set up file system information.
	 */
	rewind(fp);
	while (len < nmnt && (getmntent(fp, &mt) == 0))

	{
		fs = &mt;
		log_dev_len = strlen(mt.mnt_mountp)+2;
		if (!IS_VALID_FS(fs))
			continue;

		fsip->fs_logical_device = ndmp_malloc(log_dev_len);
		fsip->fs_type = ndmp_malloc(MNTTYPE_LEN);
		if (!fsip->fs_logical_device || !fsip->fs_type) {
			free(fsip->fs_logical_device);
			free(fsip->fs_type);
			reply.error = NDMP_NO_MEM_ERR;
			break;
		}
		(void) snprintf(fsip->fs_type, MNTTYPE_LEN, "%s",
		    fs->mnt_fstype);
		(void) snprintf(fsip->fs_logical_device, log_dev_len, "%s",
		    fs->mnt_mountp);
		fsip->invalid = 0;

		if (statvfs64(fs->mnt_mountp, &stat_buf) < 0) {
			NDMP_LOG(LOG_DEBUG,
			    "statvfs(%s) error.", fs->mnt_mountp);
			fsip->fs_status =
			    "statvfs error: unable to determine filesystem"
			    " attributes";
		} else {
			fsip->invalid = 0;
			fsip->total_size =
			    long_long_to_quad((u_longlong_t)stat_buf.f_frsize *
			    (u_longlong_t)stat_buf.f_blocks);
			fsip->used_size =
			    long_long_to_quad((u_longlong_t)stat_buf.f_frsize *
			    (u_longlong_t)(stat_buf.f_blocks-stat_buf.f_bfree));

			fsip->avail_size =
			    long_long_to_quad((u_longlong_t)stat_buf.f_frsize *
			    (u_longlong_t)stat_buf.f_bfree);
			fsip->total_inodes =
			    long_long_to_quad((u_longlong_t)stat_buf.f_files);
			fsip->used_inodes =
			    long_long_to_quad((u_longlong_t)(stat_buf.f_files -
			    stat_buf.f_ffree));
			fsip->fs_status = "";
		}
		save = envp = ndmp_malloc(sizeof (ndmp_pval) * V3_N_FS_ENVS);
		if (!envp) {
			free(fsip->fs_logical_device);
			free(fsip->fs_type);
			reply.error = NDMP_NO_MEM_ERR;
			break;
		}
		(void) memset((void*)save, 0,
		    V3_N_FS_ENVS * sizeof (ndmp_pval));

		fsip->fs_env.fs_env_val = envp;
		NDMP_SETENV(envp, "LOCAL", "y");
		NDMP_SETENV(envp, "TYPE", fsip->fs_type);
		NDMP_SETENV(envp, "AVAILABLE_BACKUP", "tar,dump");

		if (FS_READONLY(fs) == 0) {
			NDMP_SETENV(envp, "AVAILABLE_RECOVERY", "tar,dump");
		}

		fsip->fs_env.fs_env_len = envp - save;
		len++;
		fsip++;
	}
	(void) fclose(fp);

send_reply:
	if (reply.error == NDMP_NO_ERR) {
		reply.fs_info.fs_info_len = len;
		reply.fs_info.fs_info_val = fsip_save;
	}
	ndmp_send_reply(connection, (void *)&reply,
	    "error sending ndmp_config_get_fs_info reply");

	while (fsip > fsip_save) {
		fsip--;
		free(fsip->fs_logical_device);
		free(fsip->fs_env.fs_env_val);
		free(fsip->fs_type);
	}

	free(fsip);
}


/*
 * ndmpd_config_get_tape_info_v3
 *
 * This handler handles the ndmp_config_get_tape_info_request.
 * Information about all connected tape drives is returned.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_config_get_tape_info_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_config_get_tape_info_reply_v3 reply;
	ndmp_device_info_v3 *tip, *tip_save = NULL; /* tape info pointer */
	ndmp_device_capability_v3 *dcp;
	ndmp_device_capability_v3 *dcp_save = NULL; /* dev capability pointer */
	int i, n, max;
	sasd_drive_t *sd;
	scsi_link_t *sl;
	ndmp_pval *envp, *envp_save = NULL;
	ndmp_pval *envp_head;

	(void) memset((void*)&reply, 0, sizeof (reply));
	max = sasd_dev_count();

	tip_save = tip = ndmp_malloc(sizeof (ndmp_device_info_v3) * max);
	dcp_save = dcp = ndmp_malloc(sizeof (ndmp_device_capability_v3) * max);
	envp_save = envp = ndmp_malloc(sizeof (ndmp_pval) * max * 3);
	if (!tip_save || !dcp_save || !envp_save) {
		free(tip_save);
		free(dcp_save);
		free(envp_save);
		reply.error = NDMP_NO_MEM_ERR;
		ndmp_send_reply(connection, (void *)&reply,
		    "error sending ndmp_config_get_tape_info reply");
		return;
	}

	reply.error = NDMP_NO_ERR;

	for (i = n = 0; i < max; i++) {
		if (!(sl = sasd_dev_slink(i)) || !(sd = sasd_drive(i)))
			continue;
		if (sl->sl_type != DTYPE_SEQUENTIAL)
			continue;
		/*
		 * Don't report dead links.
		 */
		if ((access(sd->sd_name, F_OK) == -1) && (errno == ENOENT))
			continue;

		NDMP_LOG(LOG_DEBUG,
		    "model \"%s\" dev \"%s\"", sd->sd_id, sd->sd_name);

		envp_head = envp;
		NDMP_SETENV(envp, "EXECUTE_CDB", "b");
		NDMP_SETENV(envp, "SERIAL_NUMBER", sd->sd_serial);
		NDMP_SETENV(envp, "WORLD_WIDE_NAME", sd->sd_wwn);

		tip->model = sd->sd_id; /* like "DLT7000	 " */
		tip->caplist.caplist_len = 1;
		tip->caplist.caplist_val = dcp;
		dcp->device = sd->sd_name; /* like "isp1t060" */
		dcp->attr = 0;
		dcp->capability.capability_len = 3;
		dcp->capability.capability_val = envp_head;
		tip++;
		dcp++;
		n++;
	}

	NDMP_LOG(LOG_DEBUG, "n %d", n);

	/*
	 * We should not receive the get_tape_info when three-way backup is
	 * running and we are acting as just data, but some clients try
	 * to get the Tape information anyway.
	 */
	if (n == 0 || max <= 0) {
		reply.error = NDMP_NO_DEVICE_ERR;
		ndmp_send_reply(connection, (void *)&reply,
		    "error sending ndmp_config_get_tape_info reply");
		free(tip_save); free(dcp_save); free(envp_save);
		return;
	}


	reply.tape_info.tape_info_len = n;
	reply.tape_info.tape_info_val = tip_save;

	ndmp_send_reply(connection, (void *)&reply,
	    "error sending ndmp_config_get_tape_info reply");

	free(tip_save);
	free(dcp_save);
	free(envp_save);
}


/*
 * ndmpd_config_get_scsi_info_v3
 *
 * This handler handles the ndmp_config_get_tape_scsi_request.
 * Information about all connected scsi tape stacker and jukeboxes
 * is returned.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_config_get_scsi_info_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_config_get_scsi_info_reply_v3 reply;
	ndmp_device_info_v3 *sip, *sip_save;
	ndmp_device_capability_v3 *dcp, *dcp_save;
	int i, n, max;
	sasd_drive_t *sd;
	scsi_link_t *sl;
	ndmp_pval *envp, *envp_save = NULL;
	ndmp_pval *envp_head;

	(void) memset((void*)&reply, 0, sizeof (reply));
	max = sasd_dev_count();
	sip_save = sip = ndmp_malloc(sizeof (ndmp_device_info_v3) * max);
	dcp_save = dcp = ndmp_malloc(sizeof (ndmp_device_capability_v3) * max);
	envp_save = envp = ndmp_malloc(sizeof (ndmp_pval) * max * 2);
	if (!sip_save || !dcp_save || !envp_save) {
		free(sip_save);
		free(dcp_save);
		free(envp_save);
		reply.error = NDMP_NO_MEM_ERR;
		ndmp_send_reply(connection, (void *)&reply,
		    "error sending ndmp_config_get_scsi_info reply");
		return;
	}

	reply.error = NDMP_NO_ERR;
	for (i = n = 0; i < max; i++) {
		if (!(sl = sasd_dev_slink(i)) || !(sd = sasd_drive(i)))
			continue;
		if (sl->sl_type != DTYPE_CHANGER)
			continue;
		/*
		 * Don't report dead links.
		 */
		if ((access(sd->sd_name, F_OK) == -1) && (errno == ENOENT))
			continue;

		NDMP_LOG(LOG_DEBUG,
		    "model \"%s\" dev \"%s\"", sd->sd_id, sd->sd_name);

		envp_head = envp;
		NDMP_SETENV(envp, "SERIAL_NUMBER", sd->sd_serial);
		NDMP_SETENV(envp, "WORLD_WIDE_NAME", sd->sd_wwn);

		sip->model = sd->sd_id; /* like "Powerstor L200  " */
		sip->caplist.caplist_len = 1;
		sip->caplist.caplist_val = dcp;
		dcp->device = sd->sd_name; /* like "isp1m000" */

		dcp->attr = 0;
		dcp->capability.capability_len = 2;
		dcp->capability.capability_val = envp_head;
		sip++;
		dcp++;
		n++;
	}

	NDMP_LOG(LOG_DEBUG, "n %d", n);

	reply.scsi_info.scsi_info_len = n;
	reply.scsi_info.scsi_info_val = sip_save;

	ndmp_send_reply(connection, (void *)&reply,
	    "error sending ndmp_config_get_scsi_info reply");

	free(sip_save);
	free(dcp_save);
	free(envp_save);
}


/*
 * ndmpd_config_get_server_info_v3
 *
 * This handler handles the ndmp_config_get_server_info request.
 * Host specific information is returned.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_config_get_server_info_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_config_get_server_info_reply_v3 reply;
	ndmp_auth_type auth_types[2];
	char rev_number[10];
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	(void) memset((void*)&reply, 0, sizeof (reply));
	reply.error = NDMP_NO_ERR;

	if (connection->conn_authorized ||
	    session->ns_protocol_version != NDMPV4) {
		reply.vendor_name = VENDOR_NAME;
		reply.product_name = PRODUCT_NAME;
		(void) snprintf(rev_number, sizeof (rev_number), "%d",
		    ndmp_ver);
		reply.revision_number = rev_number;
	} else {
		reply.vendor_name = "\0";
		reply.product_name = "\0";
		reply.revision_number = "\0";
	}

	NDMP_LOG(LOG_DEBUG,
	    "vendor \"%s\", product \"%s\" rev \"%s\"",
	    reply.vendor_name, reply.product_name, reply.revision_number);

	auth_types[0] = NDMP_AUTH_TEXT;
	auth_types[1] = NDMP_AUTH_MD5;
	reply.auth_type.auth_type_len = ARRAY_LEN(auth_types, ndmp_auth_type);
	reply.auth_type.auth_type_val = auth_types;

	ndmp_send_reply(connection, (void *)&reply,
	    "error sending ndmp_config_get_server_info reply");
}



/*
 * ************************************************************************
 * NDMP V4 HANDLERS
 * ************************************************************************
 */

/*
 * ndmpd_config_get_butype_info_v4
 *
 * This handler handles the ndmp_config_get_butype_info_request.
 * Information about all supported backup types are returned.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_config_get_butype_info_v4(ndmp_connection_t *connection, void *body)
{
	ndmp_config_get_butype_info_reply_v4 reply;
	ndmp_butype_info info[3];

	ndmp_pval envs[12];
	ulong_t attrs;
	ndmp_pval *envp = envs;

	ndmp_pval zfs_envs[11];
	ulong_t zfs_attrs;
	ndmp_pval *zfs_envp = zfs_envs;


	(void) memset((void*)&reply, 0, sizeof (reply));

	/*
	 * Supported environment variables and their default values
	 * for dump and tar.
	 *
	 * The environment variables for dump and tar format are the
	 * same, because we use the same backup engine for both.
	 */
	NDMP_SETENV(envp, "FILESYSTEM", "");
	NDMP_SETENV(envp, "DIRECT", "n");
	NDMP_SETENV(envp, "RECURSIVE", "n");
	NDMP_SETENV(envp, "TYPE", "");
	NDMP_SETENV(envp, "USER", "");
	NDMP_SETENV(envp, "HIST", "n");
	NDMP_SETENV(envp, "PATHNAME_SEPARATOR", "/");
	NDMP_SETENV(envp, "LEVEL", "0");
	NDMP_SETENV(envp, "EXTRACT", "y");
	NDMP_SETENV(envp, "UPDATE", "y");
	NDMP_SETENV(envp, "CMD", "");
	NDMP_SETENV(envp, "BASE_DATE", "");

	attrs = NDMP_BUTYPE_RECOVER_FILELIST |
	    NDMP_BUTYPE_BACKUP_DIRECT |
	    NDMP_BUTYPE_BACKUP_INCREMENTAL |
	    NDMP_BUTYPE_BACKUP_UTF8 |
	    NDMP_BUTYPE_RECOVER_UTF8 |
	    NDMP_BUTYPE_BACKUP_FH_FILE |
	    NDMP_BUTYPE_BACKUP_FH_DIR |
	    NDMP_BUTYPE_RECOVER_FH_FILE |
	    NDMP_BUTYPE_RECOVER_FH_DIR;

	/* If DAR supported */
	if (ndmp_dar_support)
		attrs |= NDMP_BUTYPE_RECOVER_DIRECT;

	/* tar backup type */
	info[0].butype_name = "tar";
	info[0].default_env.default_env_len = ARRAY_LEN(envs, ndmp_pval);
	info[0].default_env.default_env_val = envs;
	info[0].attrs = attrs;

	/* dump backup type */
	info[1].butype_name = "dump";
	info[1].default_env.default_env_len = ARRAY_LEN(envs, ndmp_pval);
	info[1].default_env.default_env_val = envs;
	info[1].attrs = attrs;

	/*
	 * Supported environment variables and their default values
	 * for type "zfs."
	 */

	NDMP_SETENV(zfs_envp, "USER", "");
	NDMP_SETENV(zfs_envp, "CMD", "");
	NDMP_SETENV(zfs_envp, "FILESYSTEM", "");
	NDMP_SETENV(zfs_envp, "PATHNAME_SEPARATOR", "/");
	NDMP_SETENV(zfs_envp, "TYPE", "zfs");
	NDMP_SETENV(zfs_envp, "HIST", "n");
	NDMP_SETENV(zfs_envp, "LEVEL", "0");
	NDMP_SETENV(zfs_envp, "ZFS_MODE", "recursive");
	NDMP_SETENV(zfs_envp, "ZFS_FORCE", "n");
	NDMP_SETENV(zfs_envp, "UPDATE", "y");
	NDMP_SETENV(zfs_envp, "DMP_NAME", "level");

	zfs_attrs = NDMP_BUTYPE_BACKUP_UTF8 |
	    NDMP_BUTYPE_RECOVER_UTF8 |
	    NDMP_BUTYPE_BACKUP_DIRECT |
	    NDMP_BUTYPE_BACKUP_INCREMENTAL;

	/* zfs backup type */
	info[2].butype_name = "zfs";
	info[2].default_env.default_env_len = ARRAY_LEN(zfs_envs, ndmp_pval);
	info[2].default_env.default_env_val = zfs_envs;
	info[2].attrs = zfs_attrs;

	reply.error = NDMP_NO_ERR;
	reply.butype_info.butype_info_len = ARRAY_LEN(info, ndmp_butype_info);
	reply.butype_info.butype_info_val = info;

	ndmp_send_reply(connection, (void *)&reply,
	    "sending ndmp_config_get_butype_info reply");
}


/*
 * ndmpd_config_get_ext_list_v4
 *
 * This handler handles the ndmpd_config_get_ext_list_v4 request.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_config_get_ext_list_v4(ndmp_connection_t *connection, void *body)
{
	ndmp_config_get_ext_list_reply_v4 reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	(void) memset((void*)&reply, 0, sizeof (reply));

	if (session->ns_set_ext_list) {
		/*
		 * Illegal request if extensions have already been selected.
		 */
		NDMP_LOG(LOG_ERR, "Extensions have already been selected.");
		reply.error = NDMP_EXT_DANDN_ILLEGAL_ERR;
	} else {
		/*
		 * Reply with an empty set of extensions.
		 */
		session->ns_get_ext_list = B_TRUE;
		reply.error = NDMP_NO_ERR;
	}

	reply.class_list.class_list_val = NULL;
	reply.class_list.class_list_len = 0;

	ndmp_send_reply(connection, (void *)&reply,
	    "error sending ndmp_config_get_ext_list reply");
}

/*
 * ndmpd_config_set_ext_list_v4
 *
 * This handler handles the ndmpd_config_get_ext_list_v4 request.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_config_set_ext_list_v4(ndmp_connection_t *connection, void *body)
{
	ndmp_config_set_ext_list_reply_v4 reply;
	ndmp_config_set_ext_list_request_v4 *request;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	request = (ndmp_config_set_ext_list_request_v4 *)body;

	(void) memset((void*)&reply, 0, sizeof (reply));

	if (!session->ns_get_ext_list) {
		/*
		 * The DMA is required to issue a NDMP_GET_EXT_LIST request
		 * prior sending a NDMP_SET_EXT_LIST request.
		 */
		NDMP_LOG(LOG_ERR, "No prior ndmp_config_get_ext_list issued.");
		reply.error = NDMP_PRECONDITION_ERR;
	} else if (session->ns_set_ext_list) {
		/*
		 * Illegal request if extensions have already been selected.
		 */
		NDMP_LOG(LOG_ERR, "Extensions have already been selected.");
		reply.error = NDMP_EXT_DANDN_ILLEGAL_ERR;
	} else {
		/*
		 * We currently do not support any extensions, but the DMA
		 * may test NDMP_CONFIG_SET_EXT_LIST with an empty list.
		 */
		if (request->ndmp_selected_ext.ndmp_selected_ext_len != 0) {
			reply.error = NDMP_CLASS_NOT_SUPPORTED_ERR;
		} else {
			session->ns_set_ext_list = B_TRUE;
			reply.error = NDMP_NO_ERR;
		}
	}

	ndmp_send_reply(connection, (void *)&reply,
	    "error sending ndmp_config_set_ext_list reply");
}



/*
 * ************************************************************************
 * LOCALS
 * ************************************************************************
 */

/*
 * simple_get_attrs
 *
 * Set the default attrs for dump mode
 *
 * Parameters:
 *   attributes (output) - the attributes for dump mode
 *
 * Returns:
 *   void
 */
static void
simple_get_attrs(ulong_t *attributes)
{
	*attributes = NDMP_NO_RECOVER_FHINFO;
}
