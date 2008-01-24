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
 * The copyright in this file is taken from the original Leach & Salz
 * UUID specification, from which this implementation is derived.
 */

/*
 * Copyright (c) 1990- 1993, 1996 Open Software Foundation, Inc.
 * Copyright (c) 1989 by Hewlett-Packard Company, Palo Alto, Ca. &
 * Digital Equipment Corporation, Maynard, Mass.  Copyright (c) 1998
 * Microsoft.  To anyone who acknowledges that this file is provided
 * "AS IS" without any express or implied warranty: permission to use,
 * copy, modify, and distribute this file for any purpose is hereby
 * granted without fee, provided that the above copyright notices and
 * this notice appears in all source code copies, and that none of the
 * names of Open Software Foundation, Inc., Hewlett-Packard Company,
 * or Digital Equipment Corporation be used in advertising or
 * publicity pertaining to distribution of the software without
 * specific, written prior permission.  Neither Open Software
 * Foundation, Inc., Hewlett-Packard Company, Microsoft, nor Digital
 * Equipment Corporation makes any representations about the
 * suitability of this software for any purpose.
 */

/*
 * Module:		uuid.c
 *
 * Description:		This module is the workhorse for generating abstract
 *			UUIDs.  It delegates system-specific tasks (such
 *			as obtaining the node identifier or system time)
 *			to the sysdep module.
 */

#include <ctype.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <thread.h>
#include <synch.h>
#include "uuid_misc.h"

#define	STATE_LOCATION		"/var/sadm/system/uuid_state"
#define	URANDOM_PATH		"/dev/urandom"
#define	MAX_RETRY		8
#define	VER1_MASK		0xefff

static	mutex_t			ulock = DEFAULTMUTEX;

uint16_t	_get_random(void);
void		_get_current_time(uuid_time_t *);
void		struct_to_string(uuid_t, struct uuid *);
void		string_to_struct(struct uuid *, uuid_t);
int		get_ethernet_address(uuid_node_t *);

/*
 * local functions
 */
static	int	_lock_state(char *);
static	void	_unlock_state(int);
static	void	_read_state(int, uint16_t *, uuid_time_t *,
		    uuid_node_t *);
static	int	_write_state(int, uint16_t, uuid_time_t, uuid_node_t);
static	void 	_format_uuid(struct uuid *, uint16_t, uuid_time_t,
		    uuid_node_t);
static	void	fill_random_bytes(uchar_t *, int);
static	int	uuid_create(struct uuid *);

static	void	gen_ethernet_address(uuid_node_t *);
/*
 * Name:		uuid_create.
 *
 * Description:	Generates a uuid based on Version 1 format
 *
 * Returns:	0 on success, -1 on Error
 */
static int
uuid_create(struct uuid *uuid)
{
	uuid_time_t	timestamp, last_time;
	uint16_t	clockseq = 0;
	uuid_node_t	last_node;
	uuid_node_t	system_node;
	int		locked_state_fd;
	int		non_unique = 0;

	if (mutex_lock(&ulock) != 0) {
	    return (-1);
	}

	gen_ethernet_address(&system_node);
	/*
	 * acquire system wide lock so we're alone
	 */
	locked_state_fd = _lock_state(STATE_LOCATION);
	if (locked_state_fd < 0) {
	    /* couldn't create and/or lock state; don't have access */
	    non_unique++;
	} else {
	    /* read saved state from disk */
	    _read_state(locked_state_fd, &clockseq, &last_time,
			&last_node);
	}

	if (clockseq == 0) {
	    /* couldn't read clock sequence; generate a random one */
	    clockseq = _get_random();
	    non_unique++;
	}
	if (memcmp(&system_node, &last_node, sizeof (uuid_node_t)) != 0) {
	    clockseq++;
	}

	/*
	 * get current time
	 */
	_get_current_time(&timestamp);

	/*
	 * If timestamp is not set or is not in the past,
	 * increment clock sequence.
	 */
	if ((last_time == 0) || (last_time >= timestamp)) {
	    clockseq++;
	    last_time = timestamp;
	}

	if (non_unique)
		system_node.nodeID[0] |= 0x80;
	/*
	 * stuff fields into the UUID
	 */
	_format_uuid(uuid, clockseq, timestamp, system_node);
	if ((locked_state_fd >= 0) &&
		(_write_state(locked_state_fd, clockseq, timestamp,
		system_node) == -1)) {
	    _unlock_state(locked_state_fd);
	    (void) mutex_unlock(&ulock);
	    return (-1);
	}
	/*
	 * Unlock system-wide lock
	 */
	_unlock_state(locked_state_fd);
	(void) mutex_unlock(&ulock);
	return (0);
}

/*
 * Name:	gen_ethernet_address
 *
 * Description: Fills system_node with Ethernet address if available,
 *		else fills random numbers
 *
 * Returns:	Nothing
 */
static void
gen_ethernet_address(uuid_node_t *system_node)
{
	uchar_t		node[6];

	if (get_ethernet_address(system_node) != 0) {
		fill_random_bytes(node, 6);
		(void) memcpy(system_node->nodeID, node, 6);
		/*
		 * use 8:0:20 with the multicast bit set
		 * to avoid namespace collisions.
		 */
		system_node->nodeID[0] = 0x88;
		system_node->nodeID[1] = 0x00;
		system_node->nodeID[2] = 0x20;
	}
}

/*
 * Name:	_format_uuid
 *
 * Description: Formats a UUID, given the clock_seq timestamp,
 * 		and node address.  Fills in passed-in pointer with
 *		the resulting uuid.
 *
 * Returns:	None.
 */
static void
_format_uuid(struct uuid *uuid, uint16_t clock_seq,
    uuid_time_t timestamp, uuid_node_t node)
{

	/*
	 * First set up the first 60 bits from the timestamp
	 */
	uuid->time_low = (uint32_t)(timestamp & 0xFFFFFFFF);
	uuid->time_mid = (uint16_t)((timestamp >> 32) & 0xFFFF);
	uuid->time_hi_and_version = (uint16_t)((timestamp >> 48) &
	    0x0FFF);

	/*
	 * This is version 1, so say so in the UUID version field (4 bits)
	 */
	uuid->time_hi_and_version |= (1 << 12);

	/*
	 * Now do the clock sequence
	 */
	uuid->clock_seq_low = clock_seq & 0xFF;

	/*
	 * We must save the most-significant 2 bits for the reserved field
	 */
	uuid->clock_seq_hi_and_reserved = (clock_seq & 0x3F00) >> 8;

	/*
	 * The variant for this format is the 2 high bits set to 10,
	 * so here it is
	 */
	uuid->clock_seq_hi_and_reserved |= 0x80;

	/*
	 * write result to passed-in pointer
	 */
	(void) memcpy(&uuid->node_addr, &node, sizeof (uuid->node_addr));
}

/*
 * Name:	_read_state
 *
 * Description: Reads non-volatile state from a (possibly) saved statefile.
 * 		For each non-null pointer passed-in, the corresponding
 *		information from the statefile is filled in.
 *		the resulting uuid.
 *
 * Returns:	Nothing.
 */
static void
_read_state(int fd, uint16_t *clockseq,
    uuid_time_t *timestamp, uuid_node_t *node)
{
	uuid_state_t	vol_state;

	bzero(node, sizeof (uuid_node_t));
	*timestamp = 0;
	*clockseq = 0;

	if (read(fd, &vol_state, sizeof (vol_state)) < sizeof (vol_state)) {
		/* This file is being accessed the first time */
		return;
	}

	*node = vol_state.node;
	*timestamp = vol_state.ts;
	*clockseq = vol_state.cs;
}


/*
 * Name:	_write_state
 *
 * Description: Writes non-volatile state from the passed-in information.
 *
 * Returns:	-1 on error, 0 otherwise.
 */
static int
_write_state(int fd, uint16_t clockseq,
    uuid_time_t timestamp, uuid_node_t node)
{
	uuid_state_t	vol_state;

	vol_state.cs = clockseq;
	vol_state.ts = timestamp;
	vol_state.node = node;
	/*
	 * seek to beginning of file and write data
	 */
	if (lseek(fd, 0, SEEK_SET) != -1) {
	    if (write(fd, &vol_state, sizeof (uuid_state_t)) != -1) {
		return (0);
	    }
	}
	return (-1);
}



/*
 * Name:	_uuid_print
 *
 * Description:	Prints a nicely-formatted uuid to stdout.
 *
 * Returns:	None.
 *
 */
void
uuid_print(struct uuid u)
{
	int i;

	(void) printf("%8.8x-%4.4x-%4.4x-%2.2x%2.2x-", u.time_low, u.time_mid,
	    u.time_hi_and_version, u.clock_seq_hi_and_reserved,
	    u.clock_seq_low);
	for (i = 0; i < 6; i++)
		(void) printf("%2.2x", u.node_addr[i]);
	(void) printf("\n");
}

/*
 * Name:	_lock_state
 *
 * Description:	Locks down the statefile, by first creating the file
 *		if it doesn't exist.
 *
 * Returns:	A non-negative file descriptor referring to the locked
 *		state file, if it was able to be created and/or locked,
 *		or -1 otherwise.
 */
static int
_lock_state(char *loc)
{
	int fd;
	struct flock lock;

	fd = open(loc, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);

	if (fd < 0) {
		return (-1);
	}

	lock.l_type = F_WRLCK;
	lock.l_start = 0;
	lock.l_whence = SEEK_SET;
	lock.l_len = 0;

	if (fcntl(fd, F_SETLKW, &lock) == -1) {
		/*
		 * File could not be locked, bail
		 */
		(void) close(fd);
		return (-1);
	}
	return (fd);
}

/*
 * Name:	_unlock_state
 *
 * Description:	Unlocks a locked statefile, and close()'s the file.
 *
 * Returns:	Nothing.
 */
void
_unlock_state(int fd)
{
	struct flock lock;

	lock.l_type = F_UNLCK;
	lock.l_start = 0;
	lock.l_whence = SEEK_SET;
	lock.l_len = 0;

	(void) fcntl(fd, F_SETLK, &lock);
	(void) close(fd);
}

/*
 * Name:	fill_random_bytes
 *
 * Description:	fills buf with random numbers - nbytes is the number of bytes
 *		to fill-in. Tries to use /dev/urandom random number generator-
 *		if that fails for some reason, it retries MAX_RETRY times. If
 *		it still fails then it uses srand48(3C)
 *
 * Returns:	Nothing.
 */
static void
fill_random_bytes(uchar_t *buf, int nbytes)
{
	int i, fd, retries = 0;

	fd = open(URANDOM_PATH, O_RDONLY);
	if (fd >= 0) {
	    while (nbytes > 0) {
		i = read(fd, buf, nbytes);
		if ((i < 0) && (errno == EINTR)) {
		    continue;
		}
		if (i <= 0) {
		    if (retries++ == MAX_RETRY)
			break;
		    continue;
		}
		nbytes -= i;
		buf += i;
		retries = 0;
	    }
	    if (nbytes == 0) {
		(void) close(fd);
		return;
	    }
	}
	for (i = 0; i < nbytes; i++) {
	    *buf++ = _get_random() & 0xFF;
	}
	if (fd >= 0) {
	    (void) close(fd);
	}
}

/*
 * Name:	struct_to_string
 *
 * Description:	Unpacks the structure members in "struct uuid" to a char
 *		string "uuid_t".
 *
 * Returns:	Nothing.
 */
void
struct_to_string(uuid_t ptr, struct uuid *uu)
{
	uint_t		tmp;
	uchar_t		*out = ptr;

	tmp = uu->time_low;
	out[3] = (uchar_t)tmp;
	tmp >>= 8;
	out[2] = (uchar_t)tmp;
	tmp >>= 8;
	out[1] = (uchar_t)tmp;
	tmp >>= 8;
	out[0] = (uchar_t)tmp;

	tmp = uu->time_mid;
	out[5] = (uchar_t)tmp;
	tmp >>= 8;
	out[4] = (uchar_t)tmp;

	tmp = uu->time_hi_and_version;
	out[7] = (uchar_t)tmp;
	tmp >>= 8;
	out[6] = (uchar_t)tmp;

	tmp = uu->clock_seq_hi_and_reserved;
	out[8] = (uchar_t)tmp;
	tmp = uu->clock_seq_low;
	out[9] = (uchar_t)tmp;

	(void) memcpy(out+10, uu->node_addr, 6);

}

/*
 * Name:	string_to_struct
 *
 * Description:	Packs the values in the "uuid_t" string into "struct uuid".
 *
 * Returns:	Nothing
 */
void
string_to_struct(struct uuid *uuid, uuid_t in)
{

	uchar_t 	*ptr;
	uint_t		tmp;

	ptr = in;

	tmp = *ptr++;
	tmp = (tmp << 8) | *ptr++;
	tmp = (tmp << 8) | *ptr++;
	tmp = (tmp << 8) | *ptr++;
	uuid->time_low = tmp;

	tmp = *ptr++;
	tmp = (tmp << 8) | *ptr++;
	uuid->time_mid = tmp;

	tmp = *ptr++;
	tmp = (tmp << 8) | *ptr++;
	uuid->time_hi_and_version = tmp;

	tmp = *ptr++;
	uuid->clock_seq_hi_and_reserved = tmp;

	tmp = *ptr++;
	uuid->clock_seq_low = tmp;

	(void) memcpy(uuid->node_addr, ptr, 6);

}

/*
 * Name:	uuid_generate_random
 *
 * Description:	Generates UUID based on DCE Version 4
 *
 * Returns:	Nothing. uu contains the newly generated UUID
 */
void
uuid_generate_random(uuid_t uu)
{

	struct uuid	uuid;

	if (uu == NULL)
	    return;

	(void) memset(uu, 0, sizeof (uuid_t));
	(void) memset(&uuid, 0, sizeof (struct uuid));

	fill_random_bytes(uu, sizeof (uuid_t));
	string_to_struct(&uuid, uu);
	/*
	 * This is version 4, so say so in the UUID version field (4 bits)
	 */
	uuid.time_hi_and_version |= (1 << 14);
	/*
	 * we don't want the bit 1 to be set also which is for version 1
	 */
	uuid.time_hi_and_version &= VER1_MASK;

	/*
	 * The variant for this format is the 2 high bits set to 10,
	 * so here it is
	 */
	uuid.clock_seq_hi_and_reserved |= 0x80;

	/*
	 * Set MSB of Ethernet address to 1 to indicate that it was generated
	 * randomly
	 */
	uuid.node_addr[0] |= 0x80;
	struct_to_string(uu, &uuid);
}

/*
 * Name:	uuid_generate_time
 *
 * Description:	Generates UUID based on DCE Version 1.
 *
 * Returns:	Nothing. uu contains the newly generated UUID.
 */
void
uuid_generate_time(uuid_t uu)
{
	struct uuid uuid;

	if (uu == NULL)
	    return;

	if (uuid_create(&uuid) == -1) {
	    uuid_generate_random(uu);
	    return;
	}
	struct_to_string(uu, &uuid);
}

/*
 * Name:	uuid_generate
 *
 * Description:	Creates a new UUID. The uuid will be generated based on
 *		high-quality randomness from /dev/urandom, if available by
 *		calling uuid_generate_random. If it failed to generate UUID
 *		then uuid_generate will call uuid_generate_time.
 *
 * Returns:	Nothing. uu contains the newly generated UUID.
 */
void
uuid_generate(uuid_t uu)
{
	int fd;

	if (uu == NULL) {
	    return;
	}
	fd = open(URANDOM_PATH, O_RDONLY);
	if (fd >= 0) {
	    (void) close(fd);
	    uuid_generate_random(uu);
	} else {
	    (void) uuid_generate_time(uu);
	}
}

/*
 * Name:	uuid_copy
 *
 * Description:	The uuid_copy function copies the UUID variable src to dst
 *
 * Returns:	Nothing
 */
void
uuid_copy(uuid_t dst, uuid_t src)
{

	(void) memcpy(dst, src, UUID_LEN);
}

/*
 * Name:	uuid_clear
 *
 * Description:	The uuid_clear function sets the value of the supplied uuid
 *		variable uu, to the NULL value.
 *
 * Returns:	Nothing
 */
void
uuid_clear(uuid_t uu)
{
	(void) memset(uu, 0, UUID_LEN);
}

/*
 * Name:	uuid_unparse
 *
 * Description:	This function converts the supplied UUID uu from the internal
 *		binary format into a 36-byte string (plus trailing null char)
 *		and stores this value in the character string pointed to by out
 *
 * Returns:	Nothing.
 */
void
uuid_unparse(uuid_t uu, char *out)
{
	struct uuid 	uuid;
	uint16_t	clock_seq;
	char		etheraddr[13];
	int		index = 0, i;

	/* basic sanity checking */
	if (uu == NULL) {
	    return;
	}

	/* XXX user should have allocated enough memory */
	/*
	 * if (strlen(out) < UUID_PRINTABLE_STRING_LENGTH) {
	 * return;
	 * }
	 */
	string_to_struct(&uuid, uu);
	clock_seq = uuid.clock_seq_hi_and_reserved;
	clock_seq = (clock_seq  << 8) | uuid.clock_seq_low;
	for (i = 0; i < 6; i++) {
	    (void) sprintf(&etheraddr[index++], "%.2x", uuid.node_addr[i]);
	    index++;
	}
	etheraddr[index] = '\0';

	(void) snprintf(out, 25, "%08x-%04x-%04x-%04x-",
	    uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
		clock_seq);
	(void) strlcat(out, etheraddr, UUID_PRINTABLE_STRING_LENGTH);
}

/*
 * Name:	uuid_is_null
 *
 * Description:	The uuid_is_null function compares the value of the supplied
 *		UUID variable uu to the NULL value. If the value is equal
 *		to the NULL UUID, 1 is returned, otherwise 0 is returned.
 *
 * Returns:	0 if uu is NOT null, 1 if uu is NULL.
 */
int
uuid_is_null(uuid_t uu)
{
	int		i;
	uuid_t		null_uu;

	(void) memset(null_uu, 0, sizeof (uuid_t));
	i = memcmp(uu, null_uu, sizeof (uuid_t));
	if (i == 0) {
	/* uu is NULL uuid */
	    return (1);
	} else {
	    return (0);
	}
}

/*
 * Name:	uuid_parse
 *
 * Description:	uuid_parse converts the UUID string given by 'in' into the
 *		internal uuid_t format. The input UUID is a string of the form
 *		cefa7a9c-1dd2-11b2-8350-880020adbeef in printf(3C) format.
 *		Upon successfully parsing the input string, UUID is stored
 *		in the location pointed to by uu
 *
 * Returns:	0 if the UUID is successfully stored, -1 otherwise.
 */
int
uuid_parse(char *in, uuid_t uu)
{

	char		*ptr, buf[3];
	int		i;
	struct uuid	uuid;
	uint16_t	clock_seq;

	/* do some sanity checking */
	if ((strlen(in) != 36) || (uu == NULL) || (in[36] != '\0')) {
	    return (-1);
	}

	ptr = in;
	for (i = 0; i < 36; i++, ptr++) {
	    if ((i == 8) || (i == 13) || (i == 18) || (i == 23)) {
		if (*ptr != '-') {
		    return (-1);
		}
	    } else {
		if (!isxdigit(*ptr)) {
		    return (-1);
		}
	    }
	}

	uuid.time_low = strtoul(in, NULL, 16);
	uuid.time_mid = strtoul(in+9, NULL, 16);
	uuid.time_hi_and_version = strtoul(in+14, NULL, 16);
	clock_seq = strtoul(in+19, NULL, 16);
	uuid.clock_seq_hi_and_reserved = (clock_seq & 0xFF00) >> 8;
	uuid.clock_seq_low = (clock_seq & 0xFF);

	ptr = in+24;
	buf[2] = '\0';
	for (i = 0; i < 6; i++) {
	    buf[0] = *ptr++;
	    buf[1] = *ptr++;
	    uuid.node_addr[i] = strtoul(buf, NULL, 16);
	}
	struct_to_string(uu, &uuid);
	return (0);
}

/*
 * Name:	uuid_time
 *
 * Description:	uuid_time extracts the time at which the supplied UUID uu
 *		was created. This function can only extract the creation
 *		time for UUIDs created with the uuid_generate_time function.
 *		The time at which the UUID was created, in seconds and
 *		microseconds since the epoch is stored in the location
 *		pointed to by ret_tv.
 *
 * Returns:	The time at which the UUID was created, in seconds since
 *		January  1, 1970 GMT (the epoch). -1 otherwise.
 */
time_t
uuid_time(uuid_t uu, struct timeval *ret_tv)
{
	struct uuid	uuid;
	uint_t		high;
	struct timeval	tv;
	u_longlong_t	clock_reg;
	uint_t		tmp;
	uint8_t		clk;

	string_to_struct(&uuid, uu);
	tmp = (uuid.time_hi_and_version & 0xF000) >> 12;
	clk = uuid.clock_seq_hi_and_reserved;

	/* check if uu is NULL, Version = 1 of DCE and Variant = 0b10x */
	if ((uu == NULL) || ((tmp & 0x01) != 0x01) || ((clk & 0x80) != 0x80)) {
	    return (-1);
	}
	high = uuid.time_mid | ((uuid.time_hi_and_version & 0xFFF) << 16);
	clock_reg = uuid.time_low | ((u_longlong_t)high << 32);

	clock_reg -= (((u_longlong_t)0x01B21DD2) << 32) + 0x13814000;
	tv.tv_sec = clock_reg / 10000000;
	tv.tv_usec = (clock_reg % 10000000) / 10;

	if (ret_tv) {
	    *ret_tv = tv;
	}

	return (tv.tv_sec);
}
