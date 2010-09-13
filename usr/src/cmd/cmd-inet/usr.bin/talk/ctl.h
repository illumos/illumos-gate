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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* ctl.h describes the structure that talk and talkd pass back
   and forth
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define NAME_SIZE 9
#define TTY_SIZE 16
#define HOST_NAME_LENGTH 256

#define MAX_LIFE 60 /* maximum time an invitation is saved by the
			 talk daemons */
#define RING_WAIT 30  /* time to wait before refreshing invitation 
			 should be 10's of seconds less than MAX_LIFE */

    /* the values for type */

#define LEAVE_INVITE 0
#define LOOK_UP 1
#define DELETE 2
#define ANNOUNCE 3

    /* the values for answer */

#define SUCCESS 0
#define NOT_HERE 1
#define FAILED 2
#define MACHINE_UNKNOWN 3
#define PERMISSION_DENIED 4
#define UNKNOWN_REQUEST 5

typedef struct ctl_response CTL_RESPONSE;

struct ctl_response {
    char type;
    char answer;
    int id_num;
    struct sockaddr_in addr;
};

typedef struct ctl_msg CTL_MSG;

struct ctl_msg {
    char type;
    char l_name[NAME_SIZE];
    char r_name[NAME_SIZE];
    int id_num;
    pid_t pid;
    char r_tty[TTY_SIZE];
    struct sockaddr_in addr;
    struct sockaddr_in ctl_addr;
};
