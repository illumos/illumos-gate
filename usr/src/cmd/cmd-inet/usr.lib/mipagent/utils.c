/*
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Copyright (c) 1987 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley. The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file: utils.c
 *
 * This file contains the miscellaneous routines
 * that don't seem to belong anywhere else, such
 * as randomizers, address conversion, character
 * manipulation, etc.
 */

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <syslog.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "mip.h"
#include "agent.h"
#include "auth.h"

#define	SECONDS_IN_A_DAY	86400
#define	NTP_ADJUSTMENT	(SECONDS_IN_A_DAY *(((uint32_t)365*70) + 17))

#define	_POSIX_THREAD_SAFE_FUNCTIONS	1

extern int logVerbosity;

/* --------------------- debug utils ------------------------- */
/*
 * Function: hexdump
 *
 * Arguments: message, buffer, length
 *
 * Description: This function will dump out a buffer to stderr in hex and
 *              ascii.  It is usefull in debugging.
 *
 * Returns: void
 *
 */
int
hexdump(char *message, unsigned char *buffer, int length)
{
	int i;
	char text[17];
	char TmpBuf[30];
	char output[200];
	int offset = 0;
	int currBytes;
	int result;
	static pthread_mutex_t hexdumpMutex = PTHREAD_MUTEX_INITIALIZER;

	if (!length) {
		/* don't waste our time with empty buffers */
		return (0);
	}

	result = pthread_mutex_lock(&hexdumpMutex);
	if (result) {
		(void) fprintf(stderr, "Hexdump: Unable to unlock mutex");
		return (-1);
	}

	text[16] = 0; /* Null our buffer, so we only have to do it once */
	output[0] = 0;

	(void) fprintf(stderr, "%s:\n", message);

	/* for	 each line . . */
	if (length <= 16)
		currBytes = length;
	else
		currBytes = 16;
	length -= currBytes;

	while (currBytes > 0) {
		(void) sprintf(TmpBuf, "0x%08x: ", offset);
		(void) strcat(output, TmpBuf);

		for (i = 0; i < currBytes; i++) {
			(void) sprintf(TmpBuf, "%02x ", buffer[offset+i]);
			(void) strcat(output, TmpBuf);
			if (i == 7)
				(void) strcat(output, "  ");
			text[i] = isprint(buffer[offset+i]) ?
			    buffer[offset + i] : '.';
		}

		for (i = currBytes; i < 16; i++) {
			(void) strcat(output, "   ");
			if (i == 7)
				(void) strcat(output, "  ");
			text[i] = ' ';
		}

		(void) strcat(output, "| ");
		(void) strcat(output, text);
		(void) fprintf(stderr, "%s\n", output);
		output[0] = 0;
		offset += currBytes;

		if (length <= 16)
			currBytes = length;
		else
			currBytes = 16;
		length -= currBytes;
	}

	result = pthread_mutex_unlock(&hexdumpMutex);
	if (result) {
		(void) fprintf(stderr, "Hexdump: Unable to unlock mutex");
	}

	return (0);
} /* hexdump */



/* --------------------- Platform-specific utilities -------------------- */

/*
 * Function: randomInit
 *
 * Arguments:
 *
 * Description: initialize the random number generator
 *
 * Returns:
 */
void
randomInit()
{
	struct timeval time;

	if (gettimeofday(&time, 0) < 0) {
	    syslog(LOG_INFO,
		"Gettimeofday failed in randominit(), using fixed seed.");
	    srand48(181067);
	} else {
	    srand48(time.tv_sec);
	}
}


/*
 * Function: randomLong
 *
 * Arguments:
 *
 * Description:	This function is used to retrieve a random
 *		32-bit value.
 *
 * Returns:	random value
 */
uint32_t
getRandomValue()
{
	return ((unsigned long) lrand48());
}

/*
 * Function: CurrentTimeNTPSec
 *
 * Arguments:
 *
 * Description: Returns the number of seconds elapsed since
 *		Jan 1, 1990. Only the higher 32 bits of the 64-bit
 *		quantity representing current time in NTP format.
 *
 * Returns: uint32_t - the number of seconds since Jan 1, 1990.
 */
uint32_t
CurrentTimeNTPSec()
{
	struct timeval time;

	if (gettimeofday(&time, 0) < 0) {
	    syslog(LOG_ERR,
		"Error: gettimeofday failed in CurrentTimeNTPSec()");
	    return (0);
	} else {
	    return ((uint32_t)(time.tv_sec + NTP_ADJUSTMENT));
	}
}


/*
 * Function: sprintTime
 *
 * Arguments:	buffer - Pointer to output buffer
 *		buflen - Length of output buffer
 *
 * Description: Print the current time in buffer. If buffer is large
 *		enough, the current time is printed in the format:
 *			Fri Sep 13 00:00:00 1986\0
 *
 *		This function is used for debugging purposes only.
 *
 * Returns: If successful, a pointer to the buffer is returned, otherwise
 *		NULL is returned.
 */
char *
sprintTime(char *buffer, int buflen)
{
	struct timeval clock;

	if (buflen >= 26) {
	    (void)  gettimeofday(&clock, 0);
#ifndef lint
	    /* Lint has a problem picking the right one */
#ifdef _POSIX_THREAD_SAFE_FUNCTIONS
	    ctime_r((time_t *)&(clock.tv_sec), buffer);
#else
	    ctime_r((time_t *)&(clock.tv_sec), buffer, buflen);
#endif /* _POSIX_THREAD_SAFE_FUNCTIONS */
#endif /* lint */
	    buffer[24] = '\0';
	    return (buffer);
	} else {
	    return ("");
	}
}


/*
 * Function: sprintRelativeTime
 *
 * Arguments:	buffer - Pointer to output buffer
 *		buflen - Length of output buffer
 *
 * Description: Print relative time since first call to this routine
 *		in the form:
 *			seconds.xxxxxx\0
 *
 *		This function is used for debugging purposes only.
 *
 * Returns: If successful, a pointer to the buffer is returned, otherwise
 *		NULL is returned.
 */
char
*sprintRelativeTime(char *buffer, int buflen)
{
	static int i = 0;
	static struct timeval starttime;
	static struct timeval now;
	time_t diff_sec;
	useconds_t diff_usec;

	if (buflen < 20) {
	    return ("");
	}

	if (i == 0) {
	    (void) gettimeofday(&starttime, 0);
	    (void) sprintf(buffer, "%d.%06d", 0, 0);
	    i = 1;
	} else {
	    (void) gettimeofday(&now, 0);
	    diff_sec = now.tv_sec - starttime.tv_sec;
	    if (now.tv_usec < starttime.tv_usec) {
		diff_usec = 1000000 + now.tv_usec - starttime.tv_usec;
		diff_sec -= 1;
	    } else {
		diff_usec = now.tv_usec - starttime.tv_usec;
	    }
	    (void) sprintf(buffer, "%ld.%06d", diff_sec, diff_usec);
	}

	return (buffer);
}


/* --------------------- Platform-independent utilities -------------------- */

/*
 * Function: inChecksum
 *
 * Arguments:	addr - Pointer to address
 *		len - length of address
 *
 * Description: Compute the internet checksum for len number of
 *		bytes starting at addr
 *
 * Returns: a unsigned short containing the checksum.
 */
unsigned short
inChecksum(unsigned short *addr, int len)
{
	register int nleft = len;
	register unsigned short *w = addr;
	register unsigned short answer;
	unsigned short odd_byte = 0;
	register int sum = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1) {
	    sum += *w++;
	    nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
	    *(unsigned char *)(&odd_byte) = *(unsigned char *)w;
	    sum += odd_byte;
	}

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;			/* truncate to 16 bits */
	return (answer);
}


/*
 * Function: hwAddrWrite
 *
 * Arguments:	hwaddr - Pointer to the string containing
 *			the MAC address
 *		hwStr - Pointer to the output buffer
 *
 * Description: This function will convert a MAC address
 *		to a text format (e.g. aa:bb:cc:dd:ee:ff).
 *
 * Returns: a pointer to the output buffer
 */
char *
hwAddrWrite(unsigned char hwaddr[], char *hwStr)  {

	(void) sprintf(hwStr, "%x:%x:%x:%x:%x:%x",
		(unsigned char) hwaddr[0],
		(unsigned char) hwaddr[1],
		(unsigned char) hwaddr[2],
		(unsigned char) hwaddr[3],
		(unsigned char) hwaddr[4],
		(unsigned char) hwaddr[5]);

	return (hwStr);
}


/*
 * Function: ntoa
 *
 * Arguments:	addr_long - Address
 *		addr_string - Pointer to the output buffer
 *
 * Description: Converts the long value in addr_long to an internet
 *		address of the type a.b.c.d in addr_string and
 *		returns a pointer to addr_string.
 *
 *		NOTE: addr_long is in network byte order and
 *		addr_string is assumed to be long enough (at
 *		least INET_ADDRSTRLEN in length).
 *
 *		By having the caller supply its own buffer, we try
 *		to avoid problems associated with multiple threads
 *		writing the same buffer concurrently.
 *
 * Returns: the pointer to the output buffer
 */
char *
ntoa(uint32_t addr_long, char *addr_string)
{
	uint32_t    temp;

	temp = ntohl(addr_long);
	(void) sprintf(addr_string, "%d.%d.%d.%d",
	    ((temp >> 24) & 0xff), ((temp >> 16) & 0xff),
	    ((temp >> 8) & 0xff), (temp & 0xff));
	return (addr_string);
}




/*
 * Function: hexDigit
 *
 * Arguments:	c - character
 *
 * Description: This function is used to determine if a character
 *		is a valid hex digit, and returns the decimal
 *		equivalent.
 *
 * Returns: int, -1 if the character is not a valid hex digit.
 *		Otherwise, the decimal value is returned.
 */
static int
hexDigit(int c)
{
	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);

	return (-1);
}


/*
 * Function: hexConvert
 *
 * Arguments:	key - Pointer to output buffer
 *		len - length of key
 *		keystr - Pointer to input buffer containing the key.
 *
 * Description: Convert a string of hexadecimal digits into an array
 *		of len bytes each containing a byte represented by a
 *		pair of hex digits, e.g. keystr="12abC4De" is converted
 *		to key[]={0x12, 0xab, 0xC4, 0xDe} key has space for
 *		len bytes only.
 *
 * Returns: int, Returns -1 if the key has invalid data
 */
int
hexConvert(char *key, int len, char *keystr)
{
	int i, d1, d2;

	for (i = 0; i < len; ++i) {
	    if ((d1 = hexDigit(*keystr++)) == -1)
		return (-1);
	    if ((d2 = hexDigit(*keystr++)) == -1)
		return (-1);
	    *key++ = d1*16 + d2;
	}

	return (0);
}


/*
 * Function: prefixLen
 *
 * Arguments:	netmask - Network Mask
 *
 * Description: Computes prefix length of a network mask. Assumes
 *		it is the same as the number of bits set to one.
 *
 * Returns: int, containing the netmask bits.
 */
int
prefixLen(uint32_t netmask)
{
	int len = 0;

	while (netmask) {
	    len++;
	    netmask &= (netmask - 1);
	}

	return (len);
}

/*
 * Function: printBuffer
 *
 * Arguments:	buffer - Pointer to input buffer
 *		buflen - Length of data in buffer
 *
 * Description: Prints a buffer in hexadecimal
 *
 * Returns:
 */
void
printBuffer(unsigned char buffer[], int buflen)
{
	unsigned int i;

	if (buflen == 6) {
	    /* Is likely an ethernet address */
	    for (i = 0; i < buflen; i++) {
		mipverbose(("%02x", buffer[i]));
		if (i < (buflen-1))
			mipverbose((":"));
	    }
	} else {
	    /* Short enough to be printed in one shot */
	    if (buflen <= 16) {
		for (i = 0; i < buflen; i++)
			mipverbose(("%02x", buffer[i]));
	    } else {
		/* Possibly a packet */
		mipverbose(("\t"));
		for (i = 0; i < buflen; i++) {
			mipverbose(("%02x", buffer[i]));
			if ((i % 2) == 1)
				mipverbose((" "));
			if ((i % 16) == 15)
				mipverbose(("\n\t"));
		}
	    }
	}

	(void) fflush(stdout);
}


/*
 * Function: printMaAdvConfigEntry
 *
 * Arguments:	macep - Pointer to the interface entry.
 *		p1 - unused
 *
 * Description: Prints the contents of a MaAdvConfigEntry
 *
 * Returns:
 */
/* ARGSUSED */
static boolean_t
printMaAdvConfigEntry(void *entry, uint32_t p1)
{
	MaAdvConfigEntry *macep = entry;
	char addr[20];

	mipverbose(("MaAdvConfigEntry contents:\n"));
	mipverbose(("\tInterface: %s\n", macep->maIfaceName));
	mipverbose(("\tAddress  : %s\n", ntoa(macep->maIfaceAddr, addr)));
	mipverbose(("\tNetmask  : %s\n", ntoa(macep->maIfaceNetmask, addr)));
	if ((macep->maIfaceFlags & IFF_POINTOPOINT) == 0) {
		mipverbose(("\tHWaddr   : "));
		if (logVerbosity > 2) printBuffer(macep->maIfaceHWaddr, 6);
		mipverbose(("\n"));
	}
	mipverbose(("\tAdv seq# : %d\n", macep->maAdvSeqNum));
	mipverbose(("\tFlags    : %x (RBHFMGV_)\n", macep->maAdvServiceFlags));
	mipverbose(("\tPrefix   : %s\n",
		macep->maAdvPrefixLenInclusion ? "Yes" : "No"));

	return (_B_TRUE);
}

#ifdef FIREWALL_SUPPORT
/*
 * Function: printProtectedDomainInfo
 *
 * Arguments:	domainInfo - Pointer to the Domain Info
 *		entry.
 *
 * Description: Prints information about a DomainInfo
 *
 * Returns:
 */
void
printProtectedDomainInfo(DomainInfo domainInfo)
{
	int i;
	char addrstr1[INET_ADDRSTRLEN], addrstr2[INET_ADDRSTRLEN];

	if (domainInfo.addrIntervalCnt > 0) {
	    mipverbose(("Protected Domain Info:  Address - Netmask pairs\n"));
	    for (i = 0; i < domainInfo.addrIntervalCnt; i++) {
		mipverbose(("         %s/%s\n",
			ntoa(domainInfo.addr[i], addr1),
			ntoa(domainInfo.netmask[i], addr2)));
	    }
	}

	if (domainInfo.firewallCnt > 0) {
	    mipverbose(("No. of firewalls : %d\n", domainInfo.firewallCnt));
	    mipverbose(("List of firewall addresses : "));
	    for (i = 0; i < domainInfo.firewallCnt; i++) {
		mipverbose(("%s ", ntoa(domainInfo.fwAddr[i], addr1)));
	    }
	}

	mipverbose(("\n"));
	fflush(stdout);
}
#endif /* FIREWALL_SUPPORT */

/*
 * Function: printMaAdvConfigHash
 *
 * Arguments:	htbl - Pointer to the Hash Table
 *
 * Description: This function will print information about
 *		all interfaces in the hash.
 *
 * Returns:
 */
void
printMaAdvConfigHash(struct hash_table *htbl)
{

	mipverbose(("------ MaAdvConfigHash contents ------\n"));

	getAllHashTableEntries(htbl, printMaAdvConfigEntry, LOCK_READ, 0,
	    _B_FALSE);
}

#if 0
/*
 * Function: printFaVisitorEntry
 *
 * Arguments: favep - Pointer to the visitor entry
 *
 * Description:	Prints the contents of a FaVisitorEntry. This
 *		function is not currently in use today, but will
 *		if static visitor entries are implemented.
 *
 * Returns:
 */
/* ARGSUSED */
static boolean_t
printFaVisitorEntry(void *entry, uint32_t p1)
{
	FaVisitorEntry *favep = entry;
	time_t currentTime;
	char addr[INET_ADDRSTRLEN];
	struct ether_addr	ether;

	mipverbose(("FaVisitorEntry contents:\n"));
	mipverbose(("\tVisitor  : %s\n", ntoa(favep->faVisitorAddr, addr)));
	mipverbose(("\tIface    : %s\n",
				ntoa(favep->faVisitorIfaceAddr, addr)));
	mipverbose(("\tStatus   : %s\n", (favep->faVisitorRegIsAccepted ?
			"Accepted" : "Pending")));
	mipverbose(("\tTimeGrant: %ld\n", favep->faVisitorTimeGranted));
	GET_TIME(currentTime);
	mipverbose(("\tTimeLeft : %ld\n",
		currentTime - favep->faVisitorTimeExpires));
	mipverbose(("\tHomeAddr : %s\n", ntoa(favep->faVisitorHomeAddr, addr)));
	mipverbose((
	    "\tHomeAgent: %s\n", ntoa(favep->faVisitorHomeAgentAddr, addr)));
	mipverbose(("\tCOAddr   : %s\n", ntoa(favep->faVisitorCOAddr, addr)));
	mipverbose(("\tReg Flag : %x (SBDMGV__)\n", favep->faVisitorRegFlags));
	mipverbose(("\tID High  : %x\n", favep->faVisitorRegIDHigh));
	mipverbose(("\tID Low   : %x\n", favep->faVisitorRegIDLow));
	mipverbose(("\tIf. idx	: %d\n", favep->faVisitorInIfindex));
	if (faevp->faVisitorSlla.sdl_data != NULL) {
		(void) memcpy(ether.ether_addr_octet,
		    faevp->faVisitorSlla.sdl_data, ETHERADDRL);
		mipverbose(("\tMN SLLA	: %s\n", ether_ntoa(&ether)));
	} else
		mipverbose(("\tMN SLLA	: unknown\n"));
	return (_B_TRUE);
}


/*
 * Function: printFaVisitorHash
 *
 * Arguments:	htbl - Pointer to the Hash Table
 *
 * Description: Prints information about all visitor entries
 *		in the hash table. This function is not
 *		currently in use today, but will if static
 *		visitor entries are implemented.
 *
 * Returns:
 */
void
printFaVisitorHash(struct hash_table *htbl)
{
	mipverbose(("------ FaVisitorHash contents ------\n"));

	getAllHashTableEntries(htbl, printFaVisitorEntry, LOCK_READ, 0,
	    _B_FALSE);

}


/*
 * Function: printFaUnreachableEntry
 *
 * Arguments:	fauep - Pointer to the unreachable entry.
 *
 * Description: Prints the contents of a FaUnreachableEntry.
 *		This function is not currently in use, but could
 *		be if a feature was implemented that allowed
 *		blocking of access (statically) to a Home Agent.
 *
 * Returns:
 */
/* ARGSUSED */
static boolean_t
printFaUnreachableEntry(void *entry, uint32_t p1)
{
	FaUnreachableEntry *fauep = entry;
	char addr[INET_ADDRSTRLEN];

	mipverbose(("FaUnreachableEntry contents:\n"));
	mipverbose(("\tAddr     : %s\n", ntoa(fauep->faUnreachableAddr, addr)));
	mipverbose(("\tExpires : %ld\n", fauep->faUnreachableTimeExpires));
	return (_B_TRUE);
}


/*
 * Function: printFaUnreachableHash
 *
 * Arguments:	htbl - Pointer to the Hash Table.
 *
 * Description: Prints out information about all unreachable
 *		entries in the hash.
 *
 *		This function is not currently in use, but could
 *		be if a feature was implemented that allowed
 *		blocking of access (statically) to a Home Agent.
 *
 * Returns:
 */
void
printFaUnreachableHash(struct hash_table *htbl)
{
	mipverbose(("------ FaUnreachableHash contents ------\n"));

	getAllHashTableEntries(htbl, printFaUnreachableEntry, LOCK_READ, 0,
	    _B_FALSE);
}
#endif

/* Prints the contents of a HaBindingEntry. */
/*
 * Function: printHaBindingEntry
 *
 * Arguments:	habep - Pointer to the Binding Entry
 *
 * Description: This function will print out the contents
 *		of a binding entry. This function is not currently
 *		in use, and could be if static bindings were
 *		implemented.
 *
 * Returns:
 */
#ifndef lint
boolean_t
printHaBindingEntry(void *entry, uint32_t p1)
{
	HaBindingEntry *habep = entry;
	char addr[INET_ADDRSTRLEN];
	time_t currentTime;

	mipverbose(("HaBindingEntry contents:\n"));
	mipverbose(("\tMN addr  : %s\n", ntoa(habep->haBindingMN, addr)));
	mipverbose(("\tCO addr  : %s\n", ntoa(habep->haBindingCOA, addr)));
	mipverbose(("\tSrc addr : %s\n", ntoa(habep->haBindingSrcAddr, addr)));
	mipverbose(("\tSrc port : %d\n", habep->haBindingSrcPort));
	mipverbose(("\tTimeGrant: %ld\n", habep->haBindingTimeGranted));
	GET_TIME(currentTime);
	mipverbose(("\tExpires : %ld\n",
		currentTime - habep->haBindingTimeExpires));
	mipverbose((
		"\tReg Flag : %x (SBDMGV__)\n", habep->haBindingRegFlags));

	return (_B_TRUE);
}

/*
 * Function: printHaBindingHash
 *
 * Arguments:	htbl - Pointer to the Hash Table
 *
 * Description: This function will print out the contents
 *		of all binding entries in the hash. This
 *		function is not currently in use, and could
 *		be if static bindings were implemented.
 *
 * Returns:
 */
void
printHaBindingHash(struct hash_table *htbl)
{

	mipverbose(("------ HaBindingHash contents ------\n"));

	getAllHashTableEntries(htbl, printHaBindingEntry, LOCK_READ, 0,
	    _B_FALSE);
}

#endif /* lint */
/*
 * Function: printMSAE
 *
 * Arguments:	msae - Pointer to the Security Assoc Entry
 *
 * Description: This function will print out the contents of
 *		a security association entry.
 *
 * Returns:
 */
static void
printMSAE(MipSecAssocEntry *msae)
{
	mipverbose(("\tMipSecAssocEntry contents:\n"));
	mipverbose(("\tSPI %d\n", msae->mipSecSPI));
	mipverbose(("\tAlgo type %d\n", msae->mipSecAlgorithmType));
	mipverbose(("\tAlgo Mode %d\n", msae->mipSecAlgorithmMode));
	mipverbose(("\tKey Len %d\n", msae->mipSecKeyLen));
	mipverbose(("\tReplay method %d\n", msae->mipSecReplayMethod));
}


/*
 * Function: printHaMobileNodeEntry
 *
 * Arguments:	hamne - Pointer to the Mobile Node Entry
 *
 * Description: This function will print the contents of a
 *		Mobile Node Entry.
 *
 * Returns:
 */
static boolean_t
printHaMobileNodeEntry(void *entry, uint32_t p1)
{
	HaMobileNodeEntry *hamne = entry;
	HaBindingEntry *habep;
	MipSecAssocEntry *mnsae;
	char addr[INET_ADDRSTRLEN];

	mipverbose(("HaMobileNodeEntry contents:\n"));
	mipverbose(("\tMN addr %s\n", ntoa(hamne->haMnAddr, addr)));
	mipverbose((
	    "\tHA's Iface Addr %s\n", ntoa(hamne->haBindingIfaceAddr, addr)));
	mipverbose(("\tID High: 0x%x\n", hamne->haMnRegIDHigh));
	mipverbose(("\tID Low : 0x%x\n", hamne->haMnRegIDLow));
	mipverbose(("\tMN binding count %d\n", hamne->haMnBindingCnt));

	habep = hamne->bindingEntries;

	while (habep) {
		mipverbose(("\tHaMobileNodeEntry BindingEntry contents:\n"));
		mipverbose(("\t\tMN addr  : %s\n", ntoa(habep->haBindingMN,
		    addr)));
		mipverbose(("\t\tCO addr  : %s\n", ntoa(habep->haBindingCOA,
		    addr)));
		mipverbose(("\t\tSrc addr : %s\n", ntoa(habep->haBindingSrcAddr,
		    addr)));
		mipverbose(("\t\tSrc port : %d\n", habep->haBindingSrcPort));
		mipverbose((
			"\t\tTimeGrant: %ld\n", habep->haBindingTimeGranted));
		mipverbose(("\t\tExpires : %ld\n",
		    p1 - habep->haBindingTimeExpires));
		mipverbose(("\t\tReg Flag : %x (SBDMGV__)\n",
		    habep->haBindingRegFlags));
		habep = habep->next;
	}

	if ((mnsae = findSecAssocFromSPI(hamne->haMnSPI,
		LOCK_READ)) != NULL) {
		printMSAE(mnsae);
		(void) rw_unlock(&mnsae->mipSecNodeLock);
	}

	return (_B_TRUE);
}


/*
 * Print HaMobileNodeHash contents
 */
/*
 * Function: printHaMobileNodeHash
 *
 * Arguments: htbl - Pointer to the Hash Table
 *
 * Description: This function will print the contents
 *		of all Mobile Node Entries in the hash.
 *
 * Returns:
 */
void
printHaMobileNodeHash(struct hash_table *htbl)
{
	time_t currentTime;

	mipverbose(("------ HaMobileNodeHash contents ------\n"));

	GET_TIME(currentTime);

	getAllHashTableEntries(htbl, printHaMobileNodeEntry, LOCK_READ,
	    currentTime, _B_FALSE);
} /* printHaMobileNodeHash */
