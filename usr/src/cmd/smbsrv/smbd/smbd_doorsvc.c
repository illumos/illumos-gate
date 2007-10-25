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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SMBd door server
 */

#include <alloca.h>
#include <door.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <varargs.h>
#include <stdio.h>
#include <synch.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <strings.h>
#include <smbsrv/smb_door_svc.h>
#include <smbsrv/smb_common_door.h>


static int smb_doorsrv_fildes = -1;
static mutex_t smb_doorsrv_mutex;

static void smb_door_srv_func(void *cookie, char *ptr, size_t size,
    door_desc_t *dp, uint_t n_odesc);

/*
 * smb_door_srv_start
 *
 * Start the smbd door service.  Create and bind to a door.
 * Returns 0 on success. Otherwise, -1.
 */
int
smb_door_srv_start()
{
	int newfd;

	(void) mutex_lock(&smb_doorsrv_mutex);

	if (smb_doorsrv_fildes != -1) {
		(void) fprintf(stderr, "smb_doorsrv_start: already started");
		(void) mutex_unlock(&smb_doorsrv_mutex);
		return (-1);
	}

	if ((smb_doorsrv_fildes = door_create(smb_door_srv_func,
	    SMB_DR_SVC_COOKIE, DOOR_UNREF)) < 0) {
		(void) fprintf(stderr, "smb_doorsrv_start: door_create: %s",
		    strerror(errno));
		smb_doorsrv_fildes = -1;
		(void) mutex_unlock(&smb_doorsrv_mutex);
		return (-1);
	}

	(void) unlink(SMB_DR_SVC_NAME);

	if ((newfd = creat(SMB_DR_SVC_NAME, 0644)) < 0) {
		(void) fprintf(stderr, "smb_doorsrv_start: open: %s",
		    strerror(errno));
		(void) door_revoke(smb_doorsrv_fildes);
		smb_doorsrv_fildes = -1;
		(void) mutex_unlock(&smb_doorsrv_mutex);
		return (-1);
	}

	(void) close(newfd);
	(void) fdetach(SMB_DR_SVC_NAME);

	if (fattach(smb_doorsrv_fildes, SMB_DR_SVC_NAME) < 0) {
		(void) fprintf(stderr, "smb_doorsrv_start: fattach: %s",
		    strerror(errno));
		(void) door_revoke(smb_doorsrv_fildes);
		smb_doorsrv_fildes = -1;
		(void) mutex_unlock(&smb_doorsrv_mutex);
		return (-1);
	}

	(void) mutex_unlock(&smb_doorsrv_mutex);
	return (0);
}


/*
 * smb_door_srv_stop
 *
 * Stop the smbd door service.
 */
void
smb_door_srv_stop(void)
{
	(void) mutex_lock(&smb_doorsrv_mutex);

	if (smb_doorsrv_fildes != -1) {
		(void) fdetach(SMB_DR_SVC_NAME);
		(void) door_revoke(smb_doorsrv_fildes);
		smb_doorsrv_fildes = -1;
	}

	(void) mutex_unlock(&smb_doorsrv_mutex);
}

/*
 * smb_door_err_hdlr
 *
 * Encode the appropriate error code to the first 4-byte of the result
 * buffer upon any door operation failure.
 */
static char *
smb_door_srv_err_hdlr(int stat, size_t *rbufsize)
{
	char *rbuf;

	if ((rbuf = smb_dr_set_res_stat(stat, rbufsize)) == NULL) {
		*rbufsize = 0;
		return (NULL);
	}

	return (rbuf);
}

/*
 * smb_door_srv_func
 *
 * This function will determine the opcode by decoding the first 4-byte of
 * the argument buffer passed by a door client.  The corresponding door
 * operation will be looked up from the optab and get invoked.
 * Basically, any door operation will takes the argument buffer as its
 * parameter, and generates the result buffer.
 */
/*ARGSUSED*/
void
smb_door_srv_func(void *cookie, char *argp, size_t arg_size, door_desc_t *dp,
    uint_t n_desc)
{
	char *resbuf = NULL, *tmpbuf = NULL;
	size_t rbufsize = 0;
	int opcode;
	int err;
	smb_dr_op_t smbop;

	if ((opcode = smb_dr_get_opcode(argp, arg_size)) < 0) {
		tmpbuf = smb_door_srv_err_hdlr(SMB_DR_OP_ERR_DECODE,
		    &rbufsize);
		goto door_return;
	}

	syslog(LOG_DEBUG, "smb_door_srv_func: execute server routine"
	    "(opcode=%d)", opcode);
	if (smb_dr_is_valid_opcode(opcode) != 0) {
		tmpbuf = smb_door_srv_err_hdlr(SMB_DR_OP_ERR_INVALID_OPCODE,
		    &rbufsize);
	} else {
		smbop = smb_doorsrv_optab[opcode];
		if ((tmpbuf = smbop(argp + sizeof (opcode),
		    arg_size - sizeof (opcode), dp, n_desc,
		    &rbufsize, &err)) == NULL)
			tmpbuf = smb_door_srv_err_hdlr(err, &rbufsize);
	}

door_return:
	if (tmpbuf) {
		if ((resbuf = (char *)alloca(rbufsize)) == NULL)
			rbufsize = 0;
		else
			(void) memcpy(resbuf, tmpbuf, rbufsize);
		free(tmpbuf);
	}

	(void) door_return(resbuf, rbufsize, NULL, 0);
	/*NOTREACHED*/
}
