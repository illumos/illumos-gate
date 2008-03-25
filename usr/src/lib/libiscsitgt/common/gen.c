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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Support routines for library
 */
#include <errno.h>
#include <strings.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <libscf.h>
#include <door.h>
#include <libxml/xmlreader.h>
#include <sys/mman.h>

#include "iscsitgt_impl.h"

#define	WAIT_FOR_SERVICE	15
#define	WAIT_FOR_DOOR		15
static char *service = "system/iscsitgt:default";

static Boolean_t check_and_online(int);

tgt_node_t *
tgt_door_call(char *str, int smf_flags)
{
	tgt_node_t		*n		= NULL;
	door_arg_t		d;
	int			s;
	int			allocated;
	xmlTextReaderPtr	r;
	char			*door_buf	= NULL;

	/*
	 * Setup the door pointers for the initial try.
	 */
	allocated = MAX(DOOR_MIN_SPACE, strlen(str) + 1);
	if ((door_buf = malloc(allocated)) == NULL)
		return (NULL);
	(void) strncpy(door_buf, str, allocated);
	bzero(&d, sizeof (d));
	d.data_ptr	= door_buf;
	d.data_size	= allocated;
	d.rbuf		= door_buf;
	d.rsize		= allocated;

	/*
	 * It's entirely possible that we'll be sending this request more
	 * than once. In the case of a list operation it's unknown how much
	 * data will be required, so the request will be sent and the daemon
	 * will return information on how large of a buffer is needed.
	 * It possible that the second request, with a larger buffer, also
	 * fails with not enough space since between the first and second
	 * calls a third party could have created another target increasing
	 * the space required. This is not an error, just need to handle it.
	 */
	do {
		/*
		 * Open the door and if that doesn't work or the first door call
		 * fails, try to bring the service online. Then repeat one
		 * more time. If the second attempt at the door_call fails
		 * then bail out.
		 */
		if (((s = open(ISCSI_TARGET_MGMT_DOOR, 0)) == -1) ||
		    (door_call(s, &d) == -1)) {
			if (s != -1) {
				(void) close(s);
				s = -1;
			}
			if (check_and_online(smf_flags) == False) {
				goto error;
			} else if ((s = open(ISCSI_TARGET_MGMT_DOOR, 0)) ==
			    -1) {
				goto error;
			} else if (door_call(s, &d) == -1) {
				goto error;
			}
		}

		if (d.rbuf == NULL)
			goto error;

		if ((r = (xmlTextReaderPtr)xmlReaderForMemory(d.rbuf,
		    strlen(d.rbuf), NULL, NULL, 0)) == NULL)
			goto error;

		while (xmlTextReaderRead(r) == 1)
			if (tgt_node_process(r, &n) == False)
				break;
		xmlFreeTextReader(r);

		/*
		 * Check to see if our request failed to provide enough
		 * buffer room. This can occur if:
		 * (1) The request caused an error and the message
		 *    is larger than the request.
		 * (2) We're requesting a configuration list which is
		 *    fairly large and need to reissue the request with
		 *    a larger buffer, which the daemon is kind enough
		 *    to tell us the size needed.
		 */
		if (tgt_find_value_int(n, XML_ELEMENT_MORESPACE,
		    &allocated) == True) {

			tgt_node_free(n);
			n = NULL;

			/*
			 * It's possible that we've already done a request
			 * with a larger buffer, but before we could reissue
			 * the request the results got bigger. Targets being
			 * added to the configuration would be the common
			 * cause of this condition.
			 */
			if (door_buf != NULL)
				free(door_buf);

			if ((door_buf = malloc(allocated)) == NULL)
				goto error;

			(void) strncpy(door_buf, str, allocated);
			d.data_ptr	= door_buf;
			d.data_size	= allocated;
			d.rbuf		= door_buf;
			d.rsize		= allocated;
		}

		(void) close(s);
		s = -1;
	} while (n == NULL);

error:
	if (door_buf)
		free(door_buf);
	(void) close(s);
	return (n);
}

static Boolean_t
is_online(void)
{
	char		*s;
	Boolean_t	rval = False;

	if (getenv("iscsitgt_no_daemon") != NULL) {
		rval = True;
	} else {
		if ((s = smf_get_state(service)) != NULL) {
			if (strcmp(s, SCF_STATE_STRING_ONLINE) == 0)
				rval = True;
			free(s);
		}
	}

	return (rval);
}

static Boolean_t
is_auto_enabled(void)
{
	scf_simple_prop_t	*prop;
	uint8_t			*ret;
	Boolean_t		rval = True;

	if ((prop = scf_simple_prop_get(NULL, service, "application",
	    "auto_enable")) == NULL)
		return (True);

	if ((ret = scf_simple_prop_next_boolean(prop)) != NULL)
		rval = (*ret != 0);

	scf_simple_prop_free(prop);

	return (rval);
}

static Boolean_t
check_and_online(int smf_flags)
{
	int	i;
	int	fd;
	door_arg_t	d;

	if (!is_online()) {
		if (!is_auto_enabled())
			return (False);

		if (smf_enable_instance(service, smf_flags) != 0)
			return (False);

		for (i = 0; i < WAIT_FOR_SERVICE; i++) {
			if (is_online() == True)
				break;
			(void) sleep(1);
		}

		if (i == WAIT_FOR_SERVICE)
			return (False);
	}

	for (i = 0; i < WAIT_FOR_DOOR; i++) {
		if ((fd = open(ISCSI_TARGET_MGMT_DOOR, 0)) >= 0) {
			/*
			 * There's at least a file with the same name as our
			 * door. Let's see if someone is currently answering
			 * by sending an empty XML request.
			 */
			d.data_ptr	= "<config></config>";
			d.data_size	= strlen(d.data_ptr) + 1;
			d.desc_ptr	= NULL;
			d.desc_num	= 0;
			d.rbuf		= NULL;
			d.rsize		= 0;

			if (door_call(fd, &d) == 0) {
				/*
				 * The daemon is now ready to handle requests.
				 */
				(void) close(fd);
				return (True);
			} else
				(void) close(fd);

		}
		if (!is_online())
			break;
		(void) sleep(1);
	}
	return (False);
}

/*
 * Not using Boolean_t here, since that is a
 * private type to the library
 */
int
iscsitgt_svc_online()
{
	return ((is_online() == True) ? 0 : 1);
}
