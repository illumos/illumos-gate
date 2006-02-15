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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libintl.h>
#include <time.h>
#include <pwd.h>
#include <auth_attr.h>
#include <auth_list.h>
#include <secdb.h>

#include "transport.h"
#include "util.h"
#include "mmc.h"
#include "msgs.h"
#include "misc_scsi.h"
#include "main.h"
#include "trackio.h"
#include "bstream.h"

char strbuf[81];
int priv_change_needed = 0;

void *
my_zalloc(size_t size)
{
	void *ret;

	ret = malloc(size);
	if (ret == NULL) {

		/* Lets wait a sec. and try again */
		if (errno == EAGAIN) {
			(void) sleep(1);
			ret = malloc(size);
		}

		if (ret == NULL) {
			(void) err_msg("%s\n", gettext(strerror(errno)));
			(void) err_msg(gettext(
			    "Memory allocation failure, Exiting...\n"));
			exit(1);
		}
	}
	(void) memset(ret, 0, size);
	return (ret);
}

/*
 * Prints a string after going back pos number of steps.
 * Mainly used to show %age complete.
 */
int
str_print(char *str, int pos)
{
	if ((pos > 0) && (pos < 80)) {
		(void) memset(strbuf, 8, pos);
		strbuf[pos] = 0;
		(void) printf(strbuf);
		(void) memset(strbuf, ' ', pos);
		strbuf[pos] = 0;
		(void) printf(strbuf);
		(void) memset(strbuf, 8, pos);
		strbuf[pos] = 0;
		(void) printf(strbuf);
	}

	(void) printf("%s", str);
	(void) fflush(stdout);
	return (strlen(str));
}

/*
 * dump the trackio_error struct.
 */
void
print_trackio_error(struct trackio_error *te)
{
	char *msg, *msg1;

	msg = gettext("System could not supply data at the required rate.\n");
	msg1 = gettext("Try using a lower speed for write\n");

	switch (te->err_type) {
	case TRACKIO_ERR_SYSTEM:
		err_msg(gettext("System error: %s\n"), strerror(te->te_errno));
		return;
	case TRACKIO_ERR_TRANSPORT:
		err_msg(gettext("Transport mechanism error:\n"));
		if (te->status == 2) {
			if ((te->key == 3) && (te->asc == 0x0c) &&
			    (te->ascq == 9)) {
				err_msg(msg);
				err_msg(msg1);
				return;
			}
			if (te->key == 3) {
				err_msg(gettext("Bad media.\n"));
				return;
			}
			if (debug) {
				err_msg("Sense key %x, asc/asq %x/%x\n",
				    te->key, te->asc, te->ascq);
			} else {
				err_msg(gettext("I/O error\n"));
			}
			return;
		}
		if (te->te_errno != 0)
			err_msg("%s\n", strerror(te->te_errno));
		return;
	case TRACKIO_ERR_USER_ABORT:
		err_msg(gettext("User abort.\n"));
		return;
	default:
		err_msg(gettext("Unknown error type.\n"));
		if (debug) {
			err_msg("Trackio err type %d\n", te->err_type);
		}
	}
}

char *
get_err_str(void)
{
	if (str_errno != 0)
		return (str_errno_to_string(str_errno));
	return (strerror(errno));
}

int
get_audio_type(char *ext)
{
	if ((strcasecmp(ext, "au") == 0) ||
	    (strcasecmp(ext, "sun") == 0))
		return (AUDIO_TYPE_SUN);
	if ((strcasecmp(ext, "wav") == 0) ||
	    (strcasecmp(ext, "riff") == 0))
		return (AUDIO_TYPE_WAV);
	if (strcasecmp(ext, "cda") == 0)
		return (AUDIO_TYPE_CDA);
	if (strcasecmp(ext, "aur") == 0)
		return (AUDIO_TYPE_AUR);

	return (-1);
}

/*
 * common routines for showing progress.
 */

int progress_pos;
static uint64_t last_total;
time_t tm;

void
init_progress(void)
{
	progress_pos = 0;
	last_total = 0;
	tm = time(NULL);
}

int
progress(int64_t arg, int64_t completed)
{
	char s[BUFSIZE];
	uint64_t total = (uint64_t)arg;

	if (completed == -1) {
		/* Got ^C. Add 2 to progress pos to compensate for ^ and C */
		progress_pos = str_print("(flushing ...)", progress_pos+2);
		return (0);
	}
	if (total == 0) {
		if (tm != time(NULL)) {
			tm = time(NULL);
			(void) snprintf(s, BUFSIZE,
			    gettext("%d bytes written"), completed);

			progress_pos = str_print(s, progress_pos);
		}
	} else {
		total = (((uint64_t)completed) * 100)/total;
		if (total == last_total)
			return (0);
		last_total = total;
		if (total > 100) {
			/* There is clearly a miscalculation somewhere */
			if (debug)
				(void) printf("\nWrote more than 100 %% !!\n");
			return (0);
		}
		if (total == 100) {
			/* l10n_NOTE : 'done' as in "Writing track 1...done"  */
			(void) snprintf(s, BUFSIZE, gettext("done.\n"));
		} else {
			(void) snprintf(s, BUFSIZE, "%d %%", (uint_t)total);
		}
		progress_pos = str_print(s, progress_pos);
	}
	return (0);
}

void
raise_priv(void)
{
	if (priv_change_needed && (cur_uid != 0)) {
		if (seteuid(0) == 0)
			cur_uid = 0;
	}
}

void
lower_priv(void)
{
	if (priv_change_needed && (cur_uid == 0)) {
		if (seteuid(ruid) == 0)
			cur_uid = ruid;
	}
}

int
check_auth(uid_t uid)
{
	struct passwd *pw;


	pw = getpwuid(uid);

	if (pw == NULL) {
		/* fail if we cannot get password entry */
		return (0);
	}

	/*
	 * check in the RBAC authority files to see if
	 * the user has permission to use CDRW
	 */
	if (chkauthattr(CDRW_AUTH, pw->pw_name) != 1) {
		/* user is not in database, return failure */
		return (0);
	} else {
		return (1);
	}
}

/*
 * This will busy delay in ms milliseconds. Needed for cases
 * where 1 sec wait is too long. This is needed for some newer
 * drives which can empty the drive cache very quickly.
 */
void
ms_delay(uint_t ms)
{

	hrtime_t start, req;

	start = gethrtime();
	req = start + ((hrtime_t)ms * 1000000);

	while (gethrtime() < req)
		yield();
}
