/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Replace the smb_shr_load() function in libmlsvc, because
 * fksmbd doesn't want the real shares known by libshare,
 * instead preferring its own (fake) list of shares.
 */

#include <sys/types.h>


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>
#include <libshare.h>
#include <unistd.h>
#include <note.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbns.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/smb_share.h>
#include <smbsrv/smb.h>

static void
new_share(char *name, char *path, char *comment, int flags)
{
	smb_share_t si;

	bzero(&si, sizeof (si));
	(void) strlcpy(si.shr_name, name, MAXNAMELEN);
	(void) strlcpy(si.shr_path, path, MAXPATHLEN);
	(void) strlcpy(si.shr_cmnt, comment, SMB_SHARE_CMNT_MAX);
	si.shr_flags = flags;
	if (smb_shr_add(&si) != 0) {
		syslog(LOG_ERR, "failed to add test share: %s",
		    si.shr_name);
	}
}

/*
 * This function loads a list of shares from a text file, where
 * each line of the file contains:
 * name path comment
 *
 * This is only for fksmbd, for testing.
 */
void
shr_load_file(char *shr_file)
{
	char linebuf[1024];
	FILE *fp;
	char *p;
	char *name, *path, *comment;

	fp = fopen(shr_file, "r");
	if (fp == NULL) {
		perror(shr_file);
		return;
	}

	while ((p = fgets(linebuf, sizeof (linebuf), fp)) != NULL) {

		name = p;
		p = strpbrk(p, " \t\n");
		if (p == NULL)
			continue;
		*p++ = '\0';

		path = p;
		p = strpbrk(p, " \t\n");
		if (p == NULL)
			comment = "";
		else {
			*p++ = '\0';

			comment = p;
			p = strchr(p, '\n');
			if (p != NULL)
				*p++ = '\0';
		}
		new_share(name, path, comment, 0);
	}
	(void) fclose(fp);
}

/*ARGSUSED*/
void *
smb_shr_load(void *args)
{
	char *shr_file;
	_NOTE(ARGUNUSED(args))

	/*
	 * Not loading the real shares in fksmbd because that
	 * tries to enable the network/smb/server service.
	 * Also, we won't generally have access to everything
	 * in the real shares, because fksmbd runs (only) with
	 * the credentials of the user who runs it.
	 */
	new_share("test", "/var/smb/test", "fksmbd test share",
	    SMB_SHRF_GUEST_OK);

	/* Allow creating lots of shares for testing. */
	shr_file = getenv("FKSMBD_SHARE_FILE");
	if (shr_file != NULL)
		shr_load_file(shr_file);

	return (NULL);
}
