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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file: agentInit.c
 *
 * This file contains the functions necessary to read
 * and parse the /etc/inet/mipagent.conf configuration
 * file.
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <alloca.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/resource.h>
#include <net/pfkeyv2.h> /* ipsec */
#include <net/if.h>	/* ipsec */

#include <sys/utsname.h>

#include "mip.h"
#include "agent.h"
#include "conflib.h"
#include "pool.h"
#include "setup.h"
#include "mipagentstat_door.h"

/* Common to all mobility agents */
extern struct hash_table maAdvConfigHash;
extern char   maNai[MAX_NAI_LENGTH];

/* Foreign Agent specific data structures. */
extern struct hash_table faVisitorHash;

/* Home Agent specific data structures. */
extern struct hash_table haMobileNodeHash;

/* This table stores all of the Security Violations */
extern struct hash_table mipSecViolationHash;


/* Home Agent specific data structures. */
#ifdef FIREWALL_SUPPORT
extern DomainInfo domainInfo;
#endif /* FIREWALL_SUPPORT */

extern uint32_t subagent_addr;

/*
 * This table stores all of the Security Assocations
 */
extern HashTable mipSecAssocHash;

/*
 * This table has one entry for each known Mobility Agent
 */
extern HashTable mipAgentHash;

/*
 * This table has one entry for each pool defined in the config file
 */
extern HashTable mipPoolHash;

/*
 * This table has one entry for each active tunnel number
 */
extern HashTable mipTunlHash;

/* Other external declarations */
extern int  logVerbosity;
#ifdef RADIUS_ENABLED
extern int  radiusEnabled;
extern char radiusSharedLibrary[];
#endif /* RADIUS_ENABLED */
extern int visitorEntryHighWaterMark;
extern int visitorEntryLowWaterMark;
extern int  IDfreshnessSlack;

extern int  advLifetime;
extern int  periodicInterval;

extern boolean_t faNAIadv;
extern boolean_t faChallengeAdv;
extern boolean_t mfAuthRequired;
extern boolean_t fhAuthRequired;
extern boolean_t shutdown_flag;
extern boolean_t daemonize;
extern int performanceInterval;
extern boolean_t disableSNMP;

boolean_t ipsec_loaded = _B_FALSE;  /* presume we're not secure */
boolean_t ipsec_ah_loaded = _B_FALSE;
boolean_t ipsec_esp_loaded = _B_FALSE;

extern char *ipsec_policy_string[];
extern char *validIPsecAction[];

/* AAA Globals */
extern unsigned short gbl_aaaPort;
extern char gbl_aaaHost[];
extern AAA_Protocol_Code aaaProtocol;

/*
 * Default Values...
 */
extern uint32_t defaultPool;
extern uint32_t defaultNodeSPI;

extern char	*ntoa(uint32_t, char *);
extern char	*sprintTime(char *, int);
extern char	*sprintRelativeTime(char *, int);
extern void	HAinitID(uint32_t *, uint32_t *, int);
extern int	hexConvert(char *, int, char *);
#ifdef FIREWALL_SUPPORT
extern void	printProtectedDomainInfo(DomainInfo);
#endif /* FIREWALL_SUPPORT */

/* OS-specific initialization for Mobile IP */
extern void OScleanup();

/* Called when SIGUSR1 is received to save state. */
extern int saveAgentState(void);

extern void delFAVEptr(FaVisitorEntry *, boolean_t, uint32_t);
extern void delHABEent(HaMobileNodeEntry *, HaBindingEntry *);

extern int killDispatcherTaskThread();
extern int killPeriodicTaskThread();
extern int killSNMPTaskThread();
extern int killAAATaskThread();
extern int killStatServer();
extern void printMaAdvConfigHash(struct hash_table *);

extern void randomInit();
extern int InitNet();
extern void printHaMobileNodeHash(struct hash_table *);

extern int getdomainname(char *, int);

extern int installIPsecPolicy(char *);
extern int removeIPsecPolicy(char *);
extern int formIPsecBits(int, char *, char *, char *, size_t);

typedef struct {
	char *string;
	uint32_t  value;
} Str2Int;

/* YES(x) simply checks to see if the string begins with a y. */
#define	YES(x)	((tolower(x) == 'y') ? 1 : 0)

/*
 * FA(x) needs to check if the FA is included in the setting.  This happens
 *     if the setting is "yes", "both" or "fa" [and NOT when the setting is
 *     "no", "none", or "ha").
 */
#define	FA(x)	(((tolower(x) == 'y') || \
		    (tolower(x) == 'b') || \
		    (tolower(x) == 'f')) ? 1 : 0)

/*
 *	Macros to produce a quoted string containing the value of a
 *	preprocessor macro. For example, if SIZE is defined to be 256,
 *	VAL2STR(SIZE) is "256". This is used to construct format
 *	strings for scanf-family functions below.
 */
#define	QUOTE(x)	#x
#define	VAL2STR(x)	QUOTE(x)

/* The analogous HA(x) is not needed [yet] */

#define	MAX_BUFFER_SIZE		1024
#define	MAX_KEY_STRING_LEN	256
#define	MAX_TAG_SIZE		30


/*
 * Function: daemonInit
 *
 * Arguments:
 *
 * Description: This function will deamonize the agent
 *
 * Returns: int, -1 if the deamon could not be started.
 */
static int
daemonInit()
{
	switch (fork()) {
	case -1:
	    perror("mipagent: can not fork");
	    return (-1);
	case 0:
	    break;
	default:
	    exit(0);
	}

	/*
	 * Close existing file descriptors, open "/dev/null" as
	 * standard input, output, and error, and detach from
	 * controlling terminal.
	 */
	closefrom(0);
	(void) open("/dev/null", O_RDONLY);
	(void) open("/dev/null", O_WRONLY);
	(void) dup(1);
	(void) setsid();

	(void) chdir("/");		/* change working directory */
	(void) umask(0);		/* clear file mode creation mask */
	return (0);
}



/*
 * Function: get_ipsec_support
 *
 * Parameters:	s			the PF_KEY socket
 *		struct sadb_msg	*msg	pointer to message buffer
 *		uint8_t satype		which SA type (ah, or esp)
 *		int seq			The sequence number to increment/use.
 *
 * Description: Builds, and writes an sadb_message to s, then reads until it
 *	gets the appropriate message, and returns the length so the caller
 *	knows how many bytes to parse.
 *
 * Returns:	-1 on error.
 *		The length of what was put in msg on success.
 */
int
get_ipsec_support(int s, struct sadb_msg *msg, uint8_t satype, int seq)
{
	/* Note: parsing the <base, supported> msg requires an ipsec_req_t */
	int len; /* what we'll return */
	uint32_t mypid = getpid();

	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = SADB_REGISTER;
	msg->sadb_msg_satype = satype;
	msg->sadb_msg_len = SADB_8TO64(sizeof (*msg));
	msg->sadb_msg_reserved = msg->sadb_msg_errno = 0;
	msg->sadb_msg_seq = seq++;
	msg->sadb_msg_pid = mypid;

	if ((len = write(s, (void *)msg, sizeof (*msg))) < 0) {
		syslog(LOG_WARNING, "Can't determine state of ipsec support.");
		return (-1);
	}

	/* don't let stale data in msg confuse our read! */
	bzero(msg, sizeof (*msg));

	/* send a <base> message to the kernel, get back <base, supported> */
	do {
		len = read(s, msg, MAX_IPSEC_GET_SIZE);
	} while (msg->sadb_msg_type != SADB_REGISTER &&
		msg->sadb_msg_pid != mypid &&
		msg->sadb_msg_seq != seq);

	return (msg->sadb_msg_errno != 0 ? -1 : len);
}

/*
 * Function: IsIPsecLoaded()
 *
 * Description: uses a PF_KEY socket to determine if AH and/or ESP are loaded.
 *     the globals ipsec_ah_loaded, and ipsec_esp_loaded are set directly for
 *     reference during init.
 */
boolean_t
IsIPsecLoaded()
{
	uint64_t msg_buffer[MAX_IPSEC_GET_SIZE] = { 0 };
	struct sadb_msg *msg = (struct sadb_msg *)msg_buffer;
	int s;
	uint32_t seq = FINE_STRUCT_CONST;

	if ((s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2)) < 0) {
		/* Curious.  We're root, or mipagent would've stopped by now */
		return (_B_FALSE);
	}

	/* AH support? */
	if (get_ipsec_support(s, (void *)msg, SADB_SATYPE_AH, seq) > 0)
		/* we got something back, so ah is supported */
		ipsec_ah_loaded = _B_TRUE;

	/* ESP support? */
	if (get_ipsec_support(s, (void *)msg, SADB_SATYPE_ESP, seq) > 0)
		/* we got something back, so esp is supported */
		ipsec_esp_loaded = _B_TRUE;

	(void) close(s);
	return (_B_TRUE);
}



/*
 * Funcition: setIPsecSAFlags
 *
 * Arguments:	ipsr_p - pointer to an ipsec_req_t containing the ipsec policy.
 *		type   - the type of service this policy is for (request, ...).
 *
 * Description: setIPsecSAFlags looks at the details of the ipsec policy, and
 *		returns a bit-field of what the policy is requiring in terms of
 *		AH and ESP support.
 *
 * Returns:	The bit field indicating what of AH and ESP type is requiring.
 */
uint8_t
setIPsecSAFlags(ipsec_req_t *ipsr_p, int type)
{
	uint8_t	bitfield = 0;

	/* type defines how we set our bits.  For now use low-order bits */
	if (ipsr_p->ipsr_auth_alg)
		bitfield |= IPSEC_REQUEST_AH;

	if ((ipsr_p->ipsr_esp_alg) || (ipsr_p->ipsr_esp_auth_alg))
		bitfield |= IPSEC_REQUEST_ESP;

	/* Shift depending on the actual type */
	switch (type) {
	case IPSEC_REQUEST:
		return (bitfield);

	case IPSEC_REPLY:
		return (bitfield << 2);

	case IPSEC_TUNNEL:
		return (bitfield << 4);

	case IPSEC_REVERSE_TUNNEL:
		return (bitfield << 6);

	default:
		syslog(LOG_WARNING, "setIPsecSAFlags: unknown IPsec "
		    "configuration type %d\n", type);
		break;
	}

	return (0);
}

/*
 * ParseAgentIPsecPolicy
 *
 * Arguments: mae     - A pointer to a MobilityAgentEntry struct containing
 *                      information about an agent-peer with which we may have
 *                      to add IPsec security associations.
 *            ipsType - Identifies the type of IPsec Policy we're parsing.
 *            ipsp    - The string that may contain one or two IPsec Policies.
 *                      Keywords to look for are 'apply' and 'permit', and if
 *                      both appear, the policies MUST be separated by a ':'.
 *
 * Description: We need to sanity check the policies pointed to by ipsp, and
 *              put them into the correct placeholder in the MobilityAgentEntry
 *              structure.  We return the relavent bits in mpIPsecFlags so the
 *              caller knows which policies were found.
 *
 *              Note: there can never be more than two bits set at once, one
 *		    for the permit, and one for the apply of this ipsType,
 *                  so a return of -1 is quite revealing!
 */
int
ParseAgentIPsecPolicy(MobilityAgentEntry *mae, int ipsType, char *ipsp)
{
	uint8_t	ipsFlags = 0;  /* (will become) what we'll return */
	int i;
	char *p, *freeP, *lasts;
	char *ipsPolicy[IPSEC_ORDER] = {NULL, NULL};
	int policies_found = 0;

	/* Oh, sanity... */
	if ((mae == NULL) || (ipsp == NULL))
		return (-1);

	if ((p = strdup(ipsp)) == NULL)
		return (-1);

	freeP = p;  /* strtok_r() is destructive! */

	/* lets just deal with lower case */
	for (i = 0; i < strlen(ipsp); i++)
		ipsp[i] = tolower(ipsp[i]);

	/*
	 * ipsec policies can only be passed one-at-a-time, so thunk if needed.
	 *
	 * Note: we don't know which order the user's put his actions in,
	 * so we have to always start at the begining of validIPsecAction[]s.
	 */
	while (strtok_r(p, IPSP_SEPARATOR, &lasts) != NULL) {

		if (++policies_found > IPSEC_ORDER) {
			char peerAddr[IPv4_ADDR_LEN];
			(void) ntoa(mae->maAddr, peerAddr);

			/* Tell the user they have too many */
			syslog(LOG_CRIT, "[Address %s] %s: too many actions.",
			    peerAddr, IPSEC_POLICY_STRING(ipsType));
			(void) free(freeP);
			return (-1);
		}

		for (i = 0; validIPsecAction[i] != NULL; i++) {
			/*
			 * Fill a corresponding empty array with a policy
			 * containing this validIPsecAction[].
			 */
			if ((ipsPolicy[i] == NULL) &&
			    ((ipsPolicy[i] = strstr(p, validIPsecAction[i]))
			    != NULL)) {
				/* something new to parse */
				char peerAddr[IPv4_ADDR_LEN];

				(void) ntoa(mae->maAddr, peerAddr);

				switch (ipsType) {
				case IPSEC_REQUEST:
					if (isIPsecPolicyValid(ipsPolicy[i],
					    &(mae->maIPsecRequestIPSR[i]))
					    != _B_TRUE) {
						(void) free(freeP);
						return (-1);
					}

					/* policy is OK (and parsed)! */
					if (formIPsecBits(REQUEST(i),
					    peerAddr, ipsPolicy[i],
					    &mae->maIPsecRequest[i][0],
					    sizeof (mae->maIPsecRequest[i]))
					    < 0) {
						(void) free(freeP);
						return (-1);
					}

					/* set SA flags */
					mae->maIPsecSAFlags[i] |=
					    setIPsecSAFlags(
						&mae->maIPsecRequestIPSR[i],
						ipsType);

					/* Remember we did this */
					ipsFlags |= REQUEST(i);
					break;

				case IPSEC_REPLY:
					if (isIPsecPolicyValid(ipsPolicy[i],
					    &(mae->maIPsecReplyIPSR[i]))
					    != _B_TRUE) {
						(void) free(freeP);
						return (-1);
					}
					/* policy is OK (and parsed)! */
					if (formIPsecBits(REPLY(i),
					    peerAddr, ipsPolicy[i],
					    &mae->maIPsecReply[i][0],
					    sizeof (mae->maIPsecReply[i]))
					    < 0) {
						(void) free(freeP);
						return (-1);
					}

					/* set SA flags */
					mae->maIPsecSAFlags[i] |=
					    setIPsecSAFlags(
					    &mae->maIPsecReplyIPSR[i],
					    ipsType);

					/* Remember we did this */
					ipsFlags |= REPLY(i);
					break;

					/*
					 * For the tunnel policies, we pass the
					 * IPSR bits into the ioctl(), so we
					 * don't need to form the ASCII policy.
					 */
				case IPSEC_TUNNEL:
					if (isIPsecPolicyValid(ipsPolicy[i],
					    &(mae->maIPsecTunnelIPSR[i]))
					    != _B_TRUE) {
						(void) free(freeP);
						return (-1);
					}
					/* policy is OK (and parsed)! */

					/* set SA flags */
					mae->maIPsecSAFlags[i] |=
					    setIPsecSAFlags(
					    &mae->maIPsecTunnelIPSR[i],
					    ipsType);

					/* Remember we did this */
					ipsFlags |= TUNNEL(i);
					break;

				case IPSEC_REVERSE_TUNNEL:
					if (isIPsecPolicyValid(ipsPolicy[i],
					    &(mae->maIPsecReverseTunnelIPSR[i]))
					    != _B_TRUE) {
						(void) free(freeP);
						return (-1);
					}
					/* policy is OK (and parsed)! */

					/* set SA flags */
					mae->maIPsecSAFlags[i] |=
					    setIPsecSAFlags(
					    &mae->maIPsecReverseTunnelIPSR[i],
					    ipsType);

					/* Remember we did this */
					ipsFlags |= REVERSE_TUNNEL(i);
					break;

				}
			}
		}

		/* setup for the next policy */
		p = NULL;
	}

	/* we're out of policies */
	(void) free(freeP);

	/* reveal what we found */
	return (ipsFlags);

}


/*
 * Function: setupSPI
 *
 * Arguments:	configFile - Pointer to config file
 *		SPIstr - Pointer to the section
 *
 * Description: This function will process an [SPI x] section.
 *		If the section is valid, we will create the
 *		static security assocation entry.
 *
 * Returns: int - 0 if successful.
 */
static int
setupSPI(char *configFile, char *SPIstr)
{
	int rc;
	int i;
	char buffer[MAX_BUFFER_SIZE+1];
	/* Agent Node */
	char Key[MAX_KEY_STRING_LEN];
	int32_t SPI, replayMethod = NONE;
	char mipSecKey[MAX_KEY_LEN];
	MipSecAssocEntry *entry;
	Str2Int replayMethods[] = {
		{ "none", NONE },
		{ "timestamps", TIMESTAMPS },
		{ NULL, NULL }};

	/* SPI Definition */
	rc = sscanf(SPIstr, "%" VAL2STR(MAX_BUFFER_SIZE) "s %d", buffer, &SPI);
	if (rc != 2) {
		syslog(LOG_CRIT, "Error: Invalid SPI Section [%s]", SPIstr);
		return (-1);
	}
	rc = GetPrivateProfileString(SPIstr, "ReplayMethod",
	    "", buffer, MAX_KEY_STRING_LEN, configFile);
	/*
	 * GetPrivateProfileString() returns "-2" for all
	 * configuration file loading and parsing errors.
	 * Hence, to catch those errors, there is a check
	 * for rc == -2 here.
	 */
	if (rc == -2) {
		syslog(LOG_ERR, " Unable to read %s tags :%s", SPIstr,
		    ErrorString);
		return (-1);
	}
	if (*buffer == '\0') {
	    syslog(LOG_CRIT, "Problem reading SPI <%d>. No ReplayMethod", SPI);
	    return (-1);
	}

	/* Check the replay method */
	for (i = 0; replayMethods[i].string; i++) {
		if (!strcasecmp(buffer, replayMethods[i].string)) {
			replayMethod = replayMethods[i].value;
			break;
		}
	}
	if (replayMethods[i].string == NULL) {
	    syslog(LOG_CRIT, "Error: Invalid replay method in section [%s]."
		"Possible values are (none or timestamps)", SPIstr);
	    return (-1);
	}

	rc = GetPrivateProfileString(SPIstr, "Key", "", Key,
	    MAX_KEY_STRING_LEN, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, " Unable to read %s tags :%s", SPIstr,
		    ErrorString);
		return (-1);
	}

	if (Key[0] == 0) {
		syslog(LOG_CRIT, "Problem reading SPI <%d>.  No Key", SPI);
		return (-1);
	}

	if (hexConvert((char *)mipSecKey,
	    strlen(Key)/2, Key) < 0) {
		syslog(LOG_CRIT, "Problem Converting key <%s>", Key);
		return (-2);
	}

	/*
	 * Now we create the Security Assocation
	 */
	entry = CreateSecAssocEntry(_B_FALSE, SPI, replayMethod, MD5,
	    PREFIXSUFFIX, strlen(Key)/2, mipSecKey, 0);

	if (entry == NULL) {
		syslog(LOG_CRIT, "Unable to create SPI %d", SPI);
		return (-2);
	}

	/*
	 * The Create function ends up locking the node, so
	 * we need to free it.
	 */
	(void) rw_unlock(&entry->mipSecNodeLock);

	return (0);

} /* setupSPI */

/*
 * Function: setupAddress
 *
 * Arguments:	configFile - Pointer to config file
 *		Address - Pointer to the section
 *
 * Description: This function will process an [Address x] section.
 *		If the section is valid, we will create the
 *		static Mobile Node or Mobility Agent entry.
 *
 *		This function supports three different types
 *		of addresses:
 *		x.x.x.x - Normal IP Address format
 *		xxx@yyy - Network Access Identifier (up to 256 characters)
 *		Default-Node - Default Mobile Node Config
 *
 * Returns: int - 0 if successful.
 */
static int
setupAddress(char *configFile, char *Address)
{
	int32_t rc;
	char buffer[MAX_BUFFER_SIZE+1];
	char nodeID[MAX_NAI_LENGTH+1];
	int32_t SPI, Pool;
	char *NAI = NULL;

	/* Check what we were passed!!! */
	if ((configFile == NULL) || (Address == NULL)) {
		syslog(LOG_CRIT,
		    "Error: Invalid Address passed to setupAddress.");
		return (-1);
	}

	/*
	 * Mobile Node Definition -
	 */
	rc = sscanf(Address,
	    "%" VAL2STR(MAX_BUFFER_SIZE) "s "
	    "%" VAL2STR(MAX_NAI_LENGTH) "s",
	    buffer, nodeID);
	if (rc != 2) {
	    syslog(LOG_CRIT, "Error: Invalid Address Section <%s>.", Address);
	    return (-1);
	}

	if (strlen(nodeID) >= MAX_NAI_LENGTH) {
		syslog(LOG_CRIT,
		    "Error: NAI too long in [%s...] section of config file.\n",
		    Address);
		return (-1);
	}

	rc = GetPrivateProfileString(Address, "Type", "", buffer,
	    MAX_TAG_SIZE, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, " Unable to read %s tags: %s", Address,
		    ErrorString);
		return (-1);
	}
	if (!*buffer) {
		syslog(LOG_CRIT, "Error: Must specify \"Type\" in addresses."
		    "Error in section [%s]", Address);
		return (-1);
	}

	/* Figure out what type of address this is */
	if (!strncasecmp(nodeID, "Node-Default", 12)) {
		/*
		 * This is a default entry.... Fun and Joy!!
		 */
		SPI = GetPrivateProfileInt(Address, "SPI", -1, configFile);
		if (SPI == -1) {
		    syslog(LOG_CRIT,
			"Problem reading MobileNode <%s>. No SPI", Address);
		    return (-1);
		}
		Pool = GetPrivateProfileInt(Address, "Pool", -1,
		    configFile);

		/*
		 * The default SPI MUST be present, however the Pool is
		 * optional.
		 */
		defaultNodeSPI = SPI;
		if (Pool != -1) {
			defaultPool = Pool;
		}
	/* Figure out what type of address this is */
	} else if (!strncasecmp(buffer, "Node", 4)) {
		HaMobileNodeEntry *entry;

		SPI = GetPrivateProfileInt(Address, "SPI", -1, configFile);
		if (SPI == -1) {
			syslog(LOG_CRIT,
			    "Problem reading MobileNode <%s>.  No SPI",
			    Address);
			return (-1);
		}

		NAI = strchr(nodeID, '@');
		Pool = GetPrivateProfileInt(Address, "Pool", -1, configFile);

		/*
		 * We don't need a pool every time we have an NAI (FA-only
		 * config, for example; NAIs are used for more than obtaining
		 * an address these days).  If we end up being this node's HA
		 * and it needs an address, but there's none to give it (that
		 * is, we have a broken config, read: user error), then we'll
		 * reply with 130 "insufficient resources", and (hopefully)
		 * log the appropriate error in the user-feedback nicities.
		 */
		if (Pool != -1) {
			/*
			 * If the MN will need a pool, it implies we'll need
			 * an NAI for identification!
			 */
			if (NAI == NULL) {
			    syslog(LOG_CRIT,
				"Problem reading MobileNode <%s>.  "
				"Pool invalid for non-NAI addresses", Address);
			    return (-1);
			}
		} else {
			Pool = 0; /* don't pass -1 into Create...(). */
		}

		/*
		 * And we create the Mobile Node
		 */
		if (NAI != NULL) {
			entry = CreateMobileNodeEntry(_B_FALSE, INADDR_ANY,
			    nodeID, strlen(nodeID), 0, SPI, NULL, Pool);
		} else {
			entry = CreateMobileNodeEntry(_B_FALSE,
			    inet_addr(nodeID), NULL, 0, 0, SPI, NULL, Pool);
		}

		if (entry == NULL) {
			syslog(LOG_CRIT,
			    "Unable to create MN-HA for %s", nodeID);
			return (-2);
		}

		/*
		 * A successful Create...() function ends up locking the node,
		 * so we need to unlock it.
		 */
		(void) rw_unlock(&entry->haMnNodeLock);

	} else if (strncasecmp(buffer, "Agent", 5) == 0) {
		/* Agent Node */
		int32_t SPI;
		char IPSPolicy[MAX_IPSEC_POLICY_SIZE] = "";
		MobilityAgentEntry *maEntry;

		NAI = strchr(nodeID, '@');
		if (NAI) {
			syslog(LOG_CRIT,
			    "Error: NAIs invalid for Agent Addresses");
			return (-1);
		}

		/*
		 * The assumption, then, is nodeID is a dotted-decimal
		 * address.  Even if not, we can use it to identify to
		 * the user which [Address *] section we're flagging.
		 *
		 * The SPI is for identifying the usual MD5 agent-agent
		 * SA/authentication, and has nothing to do with the SPI
		 * used by ipsec!
		 */
		SPI = GetPrivateProfileInt(Address, "SPI", -1, configFile);
		if (SPI == -1) {
			syslog(LOG_CRIT,
			    "Problem reading FA-HA-auth Node <%s>. No SPI",
			    nodeID);
			return (-1);
		}

		maEntry = CreateMobilityAgentEntry(_B_FALSE,
		    (ipaddr_t)inet_addr(nodeID), SPI, 0);

		if (maEntry == NULL) {
		    syslog(LOG_CRIT,
			"Unable to create HA-FA for %s", nodeID);
		    return (-2);
		}

		/* Check to see if there are any IPsec policies to apply */
		if (GetPrivateProfileString(Address, "IPsecRequest",
		    "", IPSPolicy, MAX_IPSEC_POLICY_SIZE, configFile) == -2) {
			syslog(LOG_CRIT,
			    "Catastrophic failure while trying to get "
			    "IPsecRequest configuration in the %s section "
			    "of %s.  Please verify file integrity.",
			    Address, configFile);
			return (-1);
		}

		if (*IPSPolicy) {
			/*
			 * The first time we could have found an IPSec policy
			 * as restoring our state is done after we init.  Note:
			 * we don't support NAIs, or MA-MA authenticators.
			 */
			if (ParseAgentIPsecPolicy(maEntry, IPSEC_REQUEST,
			    IPSPolicy) < 0) {
				/* syslog the error, and fail */
				syslog(LOG_CRIT, "Problem parsing "
				    "IPsecRequest in [%s] section of %s.",
				    Address, configFile);

				/* mipagent fails in these cases. */
				return (-1);
			}
		}

		if (GetPrivateProfileString(Address, "IPsecReply",
		    "", IPSPolicy, MAX_IPSEC_POLICY_SIZE, configFile) == -2) {
			syslog(LOG_CRIT,
			    "Catastrophic failure while trying to get "
			    "IPsecReply configuration in the %s section "
			    "of %s.  Please verify file integrity.",
			    Address, configFile);
			return (-1);
		}

		if (*IPSPolicy) {
			/* parse it into it's individual properties */
			if (ParseAgentIPsecPolicy(maEntry, IPSEC_REPLY,
			    IPSPolicy) < 0) {
				/* syslog the error, and fail. */
				syslog(LOG_CRIT, "Problem parsing IPsecReply"
				    " policy in [%s] section of %s",
				    Address, configFile);

				/* mipagent fails in these cases. */
				return (-1);
			}
		}

		if (GetPrivateProfileString(Address, "IPsecTunnel",
		    "", IPSPolicy, MAX_IPSEC_POLICY_SIZE, configFile) == -2) {
			syslog(LOG_CRIT,
			    "Catastrophic failure while trying to get "
			    "IPsecTunnel configuration in the %s section of %s."
			    "  Please verify file integrity.",
			    Address, configFile);
			return (-1);
		}


		if (*IPSPolicy) {
			/* parse it into it's individual properties */
			if (ParseAgentIPsecPolicy(maEntry, IPSEC_TUNNEL,
			    IPSPolicy) < 0) {
				/* syslog the error, and fail. */
				syslog(LOG_CRIT, "Problem parsing IPsecTunnel"
				    " policy in [%s] section of %s",
				    Address, configFile);

				/* mipagent fails in these cases. */
				return (-1);
			}
		}

		/*
		 * ipsec only supports symmetric tunnel policies, so we can't
		 * support asymmetric tunnel policies yet.  When ipsec supports
		 * multiple per-socket policies, that will (likely) change.
		 * Note that if this GetPrivateProfileString() returns -2, we
		 * don't care.
		 */
		(void) GetPrivateProfileString(Address, "IPsecReverseTunnel",
		    "", IPSPolicy, MAX_IPSEC_POLICY_SIZE, configFile);

		if (*IPSPolicy)
			/*
			 * If the user tried the obvious tag, then at least
			 * warn them asymmetric tunnel policies are not
			 * supported at this time.
			 */
			syslog(LOG_WARNING, "Found [%s] setting for "
			    "IPSecReverseTunnel.  Asymmetric IPsec tunnel "
			    "policies are not supported at this time.  Setting"
			    " reverse tunnel policies to conform to forward"
			    " tunnel settings.", Address);

		/* Make the tunnel policies symmetric (for mipagentstat) */
		if (maEntry->maIPsecSAFlags[IPSEC_APPLY] & IPSEC_TUNNEL_AH)
			/* tunnel apply = HA, so we set reverse tunnel permit */
			maEntry->maIPsecSAFlags[IPSEC_PERMIT] |=
			    IPSEC_REVERSE_TUNNEL_AH;

		if (maEntry->maIPsecSAFlags[IPSEC_APPLY] & IPSEC_TUNNEL_ESP)
			/* tunnel apply = HA, so we set reverse tunnel permit */
			maEntry->maIPsecSAFlags[IPSEC_PERMIT] |=
			    IPSEC_REVERSE_TUNNEL_ESP;

		if (maEntry->maIPsecSAFlags[IPSEC_PERMIT] & IPSEC_TUNNEL_AH)
			/* tunnel permit = FA, so we set reverse tunnel apply */
			maEntry->maIPsecSAFlags[IPSEC_APPLY] |=
			    IPSEC_REVERSE_TUNNEL_AH;

		if (maEntry->maIPsecSAFlags[IPSEC_PERMIT] & IPSEC_TUNNEL_ESP)
			/* tunnel permit = FA, so we set reverse tunnel apply */
			maEntry->maIPsecSAFlags[IPSEC_APPLY] |=
			    IPSEC_REVERSE_TUNNEL_ESP;

		/* if the user wants to use ipsec, see if we can */
		if ((ipsec_loaded == _B_FALSE) &&
		    (maEntry->maIPsecSAFlags[IPSEC_APPLY] ||
		    maEntry->maIPsecSAFlags[IPSEC_PERMIT])) {
			/* load, if not loaded */
			if (IsIPsecLoaded() == _B_FALSE)
				syslog(LOG_WARNING,
				    "Can't determine ipsec state.  Configured "
				    "[%s] IPsec policies may fail to install!",
				    Address);
			else
				ipsec_loaded = _B_TRUE;
		}

		/* Is AH or ESP protection requested, but not offered? */
		if ((!ipsec_ah_loaded) &&
		    IPSEC_ANY_AH(maEntry->maIPsecSAFlags[IPSEC_APPLY] |
		    maEntry->maIPsecSAFlags[IPSEC_PERMIT]))
			/* --><-- user wants, not available (now) */
			syslog(LOG_WARNING, "[%s] is configured to use "
			    "IPsec AH protections, but AH is not "
			    "provided/loaded at this time.", Address);

		if ((!ipsec_esp_loaded) &&
		    IPSEC_ANY_ESP(maEntry->maIPsecSAFlags[IPSEC_APPLY] |
		    maEntry->maIPsecSAFlags[IPSEC_PERMIT]))
			/* --><-- user wants, not available (now) */
			syslog(LOG_WARNING, "[%s] is configured to use "
			    "IPsec ESP protection, but ESP is not"
			    "provided/loaded at this time.", Address);

		/*
		 * "IPsecRequest permit {properties}" are for HAs receiving
		 * registration requests from FAs, and so we need to be
		 * ready to receive these (they'll be unannounced).
		 * Pass down any of these policies now.  Note: we don't check
		 * to see if it's been installed because we just read the
		 * policy, and we haven't called AgentRestoreState() yet!
		 */
		if (IPSEC_REQUEST_ANY(maEntry->maIPsecSAFlags[IPSEC_PERMIT])) {
			/*
			 * We found an IPsecRequest permit.  Do whatever
			 * we do to install the ipsec policy.
			 */
			if (installIPsecPolicy(
			    maEntry->maIPsecRequest[IPSEC_PERMIT]) < 0) {
				syslog(LOG_CRIT,
				    "Could not install %s for [Address %s]: %s",
				    IPSEC_POLICY_STRING(IPSEC_REQUEST_PERMIT),
				    nodeID,
				    maEntry->maIPsecRequest[IPSEC_PERMIT]);

				/* we're exiting, but unlock anyway */
				(void) rw_unlock(&maEntry->maNodeLock);

				/* mipagent fails to load at these times */
				return (-1);
			} else
				/*
				 * success, set the flag.  Note: this is NOT
				 * technically an agent-peer until we have
				 * a mobile node registered with it!
				 */
				maEntry->maIPsecFlags |= IPSEC_REQUEST_PERMIT;
		}

		/* done processing type = agent, UNLOCK! */
		(void) rw_unlock(&maEntry->maNodeLock);

		return (0);
	} else {
		syslog(LOG_CRIT,
		    "Error: invalid type in section [%s]", Address);
		return (-1);
	}

	return (0);

} /* setupAddress */


/*
 * Function: setupInterface
 *
 * Arguments:	configFile - Pointer to config file
 *		Interface - Pointer to the interface section
 *
 * Description: This function will process an [Interface x] section.
 *		If the section is valid, we will create the
 *		static Interface entry.
 *
 * Returns: int - 0 if successful.
 */
static int
setupInterface(char *configFile, char *Interface)
{
	int32_t rc;
	char buffer[MAX_BUFFER_SIZE];
	/* Interface definition */
	char dev[LIFNAMSIZ+1];
	char devAddr[INET_ADDRSTRLEN+1];
	int32_t ServicesFlags = ADV_IS_HOME_AGENT | ADV_IS_FOREIGN_AGENT;
	uint8_t reverseTunnelAllowed = RT_NONE;
	uint8_t reverseTunnelRequired = RT_NONE;
	boolean_t PrefixFlags = _B_TRUE;
	boolean_t advertiseOnBcast = _B_FALSE;
	int	advInitCount = 1;
	int	advInterval;
	boolean_t	advLimitUnsolicited = _B_FALSE;
	int i;
	/*
	 * We need a local regLifetime variable
	 */
	int  regLifetime;

	Str2Int flagTable[] = {
		{ "homeAgent", ADV_IS_HOME_AGENT},
		{ "foreignAgent", ADV_IS_FOREIGN_AGENT},
		{ "registrationRequired", ADV_REGISTRATION_REQUIRED},
#ifdef ENABLE_ALL_FLAGS
		{ "minEncap", ADV_MIN_ENCAP},
		{ "greEncap", ADV_GRE_ENCAP},
		{ "vjCompression", ADV_VJ_COMPRESSION},
#endif
		{ "reverseTunnel", ADV_REVERSE_TUNNEL},
		{ NULL, 0 }};



	/* Search the file for Advertisements tags */
	for (i = 0; flagTable[i].string; i++) {
		rc = GetPrivateProfileString(Interface, flagTable[i].string,
		    "", buffer, MAX_FN_LEN, configFile);
		if (rc == -2) {
			syslog(LOG_ERR, "Unable to read advertisement tags :%s",
			    ErrorString);
			return (-1);
		}

		if (*buffer) {
			/*
			 * If we're talking "reverseTunnel", then we only
			 * advertise what the setting for the FA is.  This is
			 * because the only MNs that care about what's in these
			 * becons are those that are visiting this subnet, so
			 * if the setting for HA is no, but the setting for FA
			 * is yes, advertise them.
			 */
			if (strcmp(flagTable[i].string, "reverseTunnel") == 0) {
				if (FA(*buffer)) {
					ServicesFlags |= flagTable[i].value;
				} else {
					ServicesFlags &= ~flagTable[i].value;
				}
				continue;
			}

			/* every other setting is simply yes/no... */
			if (YES(*buffer)) {
				ServicesFlags |= flagTable[i].value;
			} else {
				ServicesFlags &= ~flagTable[i].value;
			}
		}
	}

	/* regLifetime */
	rc = GetPrivateProfileInt(Interface, "regLifetime", -1, configFile);
	if (rc != -1)
		regLifetime = rc;

	/* advLifetime */
	rc = GetPrivateProfileInt(Interface, "advLifetime", -1, configFile);
	if (rc != -1)
		advLifetime = rc;

	/* periodicInterval */
	rc = GetPrivateProfileInt(Interface, "advFrequency",
	    DEFAULT_ADVERTISEMENT_INTERVAL, configFile);

	advInterval = rc;

	if (advInterval < DEFAULT_MIN_INTERVAL)
		advInterval = DEFAULT_ADVERTISEMENT_INTERVAL;
	else if (advInterval > (int)(advLifetime/3)) {
		syslog(LOG_WARNING,
		    "advFrequency value exceeds recommended value: "
		    "less than or equal to %d",
		    (int)(advLifetime/3));
	}
	/* AdvInitCount */
	advInitCount = GetPrivateProfileInt(Interface,
	    "advInitCount", 1, configFile);
	if (advInitCount < (uint8_t)ADV_INIT_COUNT_MIN)
		advInitCount = ADV_INIT_COUNT_DEFAULT;

	/* AdvLimitUnsolicited */
	rc = GetPrivateProfileString(Interface, "advLimitUnsolicited",
	    "no", buffer, MAX_BUFFER_SIZE, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, "Unable to read advertisement tags: %s",
		    ErrorString);
		return (-1);
	}

	if (strcasecmp(buffer, "yes") == 0) {
		advLimitUnsolicited = _B_TRUE;
	}
	if (advLimitUnsolicited == _B_FALSE)
		advInitCount = 1;

	/* Is Reverse Tunneling allowed on this interface? */
	rc = GetPrivateProfileString(Interface, "reverseTunnel",
	    "no", buffer, MAX_FN_LEN, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, "Unable to read advertisement tags: %s",
		    ErrorString);
		return (-1);
	}

	/* We support differenct HA and FA reverseTunnelAllowed settings. */
	if (!strcasecmp(buffer, "no")) {
		reverseTunnelAllowed = RT_NONE;
	}

	if (!strcasecmp(buffer, "none")) {
		reverseTunnelAllowed = RT_NONE;
	}

	if (!strcasecmp(buffer, "ha")) {
		reverseTunnelAllowed = RT_HA;
	}

	if (!strcasecmp(buffer, "fa")) {
		reverseTunnelAllowed = RT_FA;
	}

	if (!strcasecmp(buffer, "yes")) {
		reverseTunnelAllowed = RT_BOTH;
	}
	if (!strcasecmp(buffer, "both")) {
		reverseTunnelAllowed = RT_BOTH;
	}

	/* Is Reverse Tunneling required on this interface? */
	rc = GetPrivateProfileString(Interface, "reverseTunnelRequired",
	    "no", buffer, MAX_FN_LEN, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, "Unable to read advertisement tags: %s",
		    ErrorString);
		return (-1);
	}

	/* We support differenct HA and FA reverseTunnelRequired settings */
	if (!strcasecmp(buffer, "no")) {
		reverseTunnelRequired = RT_NONE;
	}

	if (!strcasecmp(buffer, "none")) {
		reverseTunnelRequired = RT_NONE;
	}

	if (!strcasecmp(buffer, "ha")) {
		reverseTunnelRequired = RT_HA;
	}

	if (!strcasecmp(buffer, "fa")) {
		reverseTunnelRequired = RT_FA;
	}

	if (!strcasecmp(buffer, "yes")) {
		reverseTunnelRequired = RT_BOTH;
	}
	if (!strcasecmp(buffer, "both")) {
		reverseTunnelRequired = RT_BOTH;
	}

	rc = sscanf(Interface,
	    "%" VAL2STR(LIFNAMSIZ) "s "
	    "%" VAL2STR(INET_ADDRSTRLEN) "s",
	    devAddr, dev);
	if (rc != 2) {
		syslog(LOG_CRIT, "Error: Invalid Advertisement Section <%s>",
		    Interface);
		return (-1);
	}

	rc = GetPrivateProfileString(Interface, "prefixLengthExt",
	    "", buffer, MAX_FN_LEN, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, "Unable to read advertisement tags: %s",
		    ErrorString);
		return (-1);
	}
	if (*buffer) {
		if (YES(*buffer)) {
			PrefixFlags = _B_TRUE;
		} else {
			PrefixFlags = _B_FALSE;
		}
	}


	/* advertiseOnBcast */
	rc = GetPrivateProfileString(Interface, "advertiseOnBcast",
	    "", buffer, MAX_FN_LEN, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, "Unable to read advertisement tags: %s",
		    ErrorString);
		return (-1);
	}
	if (*buffer) {
		if (YES(*buffer)) {
			advertiseOnBcast = _B_TRUE;
		} else {
			advertiseOnBcast = _B_FALSE;
		}
	}

	/*
	 * Note that the CreateInterfaceEntry does NOT lock the node
	 * and simply returns an int. Last argument is B_FALSE for static
	 * entries
	 */
	if (CreateInterfaceEntry(dev, regLifetime, advertiseOnBcast,
	    DEFAULT_MIN_INTERVAL, DEFAULT_MAX_INTERVAL, advLifetime,
	    0, ServicesFlags, PrefixFlags, reverseTunnelAllowed,
	    reverseTunnelRequired, advLimitUnsolicited, advInitCount,
	    advInterval, _B_FALSE)) {
		syslog(LOG_CRIT, "Unable to create Interface");
		return (-2);
	}

	return (0);

} /* setupInterface */

/*
 * Function: setupPool
 *
 * Arguments:	configFile - Pointer to config file
 *		Poolstr - Pointer to the section
 *
 * Description: This function will process an [Pool x] section.
 *		If the section is valid, we will create the
 *		static Pool entry.
 *
 * Returns: int - 0 if successful.
 */
static int
setupPool(char *configFile, char *Poolstr)
{
	Pool *entry;
	int32_t rc;
	char buffer[MAX_BUFFER_SIZE+1];
	uint32_t poolId;
	uint32_t poolBaseAddr;
	int32_t poolSize;

	/* SPI Definition */
	rc = sscanf(Poolstr, "%" VAL2STR(MAX_BUFFER_SIZE) "s %u",
	    buffer, &poolId);
	if (rc != 2) {
		syslog(LOG_CRIT, "Error: Invalid Pool Section [%s]", Poolstr);
		return (-1);
	}

	rc = GetPrivateProfileString(Poolstr, "BaseAddress",
	    "", buffer, MAX_KEY_STRING_LEN, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, "Unable to read %s tags: %s", Poolstr,
		    ErrorString);
		return (-1);
	}
	if (*buffer == '\0') {
	    syslog(LOG_CRIT,
			"Problem reading Pool <%d>. No BaseAddress", poolId);
	    return (-1);
	}
	poolBaseAddr = inet_addr(buffer);

	poolSize = GetPrivateProfileInt(Poolstr, "Size", -1, configFile);
	if (poolSize == -1) {
	    syslog(LOG_CRIT, "Problem reading Pool <%d>. No Pool Size", poolId);
	    return (-1);
	}

	/*
	 * Now we create the Security Assocation
	 */
	if ((entry = CreateAddressPool(poolId, poolBaseAddr,
	    poolSize)) == NULL) {
		syslog(LOG_CRIT, "Unable to create Pool %d", poolId);
		return (-2);
	}

	/*
	 * The Create function ends up locking the node, so
	 * we need to free it.
	 */
	(void) rw_unlock(&entry->poolNodeLock);

	return (0);

} /* setupPool */

/*
 * Function: readGSPs
 *
 * Arguments:	configFile - Pointer to config file
 *
 * Description:	This function will parse the
 *		[GlobalSecurityParameters] section in the
 *		config file.
 *
 * Returns:	void
 */
static void
readGSPs(char *configFile)
{
	int32_t rc;
	char buffer[MAX_BUFFER_SIZE];
	char *GSP = "GlobalSecurityParameters";
	int32_t strlenmax;

	/* IDfreshnessSlack */
	rc = GetPrivateProfileInt(GSP, "maxClockSkew", -1, configFile);
	if (rc != -1)
		IDfreshnessSlack = rc;

	/*
	 * Is inter-Mobility-Agent Authentication Required?
	 */
	rc = GetPrivateProfileString(GSP, "HA-FAauth",
		"", buffer, MAX_FN_LEN, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, "Unable to read %s tags: %s", GSP,
		    ErrorString);
		exit(1);
	}
	if (*buffer) {
		if (YES(*buffer))
			fhAuthRequired = _B_TRUE;
		else
			fhAuthRequired = _B_FALSE;
	}

	/*
	 * Is Authentication between the Mobile Node and the Foreign
	 * agent required?
	 */
	rc = GetPrivateProfileString(GSP, "MN-FAauth",
		"", buffer, MAX_FN_LEN, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, "Unable to read %s tags: %s", GSP,
		    ErrorString);
		exit(1);
	}
	if (*buffer) {
		if (YES(*buffer))
			mfAuthRequired = _B_TRUE;
		else
			mfAuthRequired = _B_FALSE;
	}

	/*
	 * Should we be advertising the challenge?
	 */
	rc = GetPrivateProfileString(GSP, "Challenge",
		"", buffer, MAX_FN_LEN, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, "Unable to read %s tags: %s", GSP,
		    ErrorString);
		exit(1);
	}
	if (*buffer) {
		if (YES(*buffer))
			faChallengeAdv = _B_TRUE;
		else
			faChallengeAdv = _B_FALSE;
	}

	/*
	 * What is our key distribution strategy?
	 */
	rc = GetPrivateProfileString(GSP, "KeyDistribution",
		"", buffer, MAX_FN_LEN, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, "Unable to read %s tags: %s", GSP,
		    ErrorString);
		exit(1);
	}
	strlenmax = MAX_FN_LEN - 1;
	if (!strncasecmp(buffer, "diameter", strlenmax)) {
		aaaProtocol = DIAMETER;
	} else if (!strncasecmp(buffer, "radius", strlenmax)) {
		aaaProtocol = RADIUS;
	}

#ifdef RADIUS_ENABLED
	/* Radius Library */
	rc = GetPrivateProfileString(GSP, "RadiusSharedLibrary",
		"", radiusSharedLibrary, MAX_FN_LEN, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, "Unable to read %s tags: %s", GSP,
		    ErrorString);
		return (-1);
	}
	if (*radiusSharedLibrary) {
		syslog(LOG_CRIT, "ERROR!!! --- RADIUS SUPPORT BROKEN!");
		radiusEnabled = 0;
	}
#endif /* RADIUS_ENABLED */
	return;

} /* readGSPs */

/*
 * Function: readAAASettings
 *
 * Arguments:	configFile - Pointer to config file
 *
 * Description:	This function will parse the
 *		[AAASettings] section in the config file.
 *
 * Returns:	void
 */

/* ARGSUSED */
static void
readAAASettings(char *configFile)
{
#ifdef TEST_DIAMETER
	char buffer[MAX_BUFFER_SIZE];
	char *AAASettings = "AAASettings";
	int  rc;
#endif

	/* First, set the defaults */
	gbl_aaaPort = AAA_PORT;
	(void) strcpy(gbl_aaaHost, LOOPBACK);

	/*
	 * The only time we would ever want these configurable is during
	 * testing.  So, only enable them when TEST_DIAMETER is defined.
	 */

#ifdef TEST_DIAMETER

	/* Server */
	(void) GetPrivateProfileString(AAASettings, "Server",
		"", buffer, MAX_FN_LEN, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, "Unable to read AAASettings tags :%s",
		    ErrorString);
		return (-1);
	}
	if (*buffer) {
		(void) strncpy(gbl_aaaHost, buffer,
		    MIN(MAX_SERVER_NAME_LEN,
			MAX_BUFFER_SIZE));
		gbl_aaaHost[MAX_SERVER_NAME_LEN - 1] = 0;
	}

	/* Port */
	rc = GetPrivateProfileInt(AAASettings, "Port", -1,
	    configFile);
	if (rc != -1)
		gbl_aaaPort = (short)rc;

	mipverbose(("WARNING: Changing DIAMETER host/port to"
	    " %s:%d for testing!\n",
	    gbl_aaaHost, gbl_aaaPort));
#endif
	return;

} /* readGSPs */

/*
 * Function: readGeneral
 *
 * Arguments:	configFile - Pointer to config file
 *
 * Description:	This function will parse the
 *		[General] section in the config file.
 *
 * Returns: int - 0 if successful.
 */
static int
readGeneral(char *configFile)
{
	int32_t rc;
	char buffer[MAX_BUFFER_SIZE];
	char *General = "General";
	int i;
	Str2Int debugLevels[] = {
		{ "quiet", 0 },
		{ "low", 1 },
		{ "norm", 2 },
		{ "all", 3 },
		{ NULL, NULL }};

	/* Debug Level */
	rc = GetPrivateProfileString(General, "logVerbosity", "", buffer,
	    MAX_TAG_SIZE, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, "Unable to read General tags :%s",
		    ErrorString);
		return (-1);
	}
	if (*buffer) {
		for (i = 0; debugLevels[i].string; i++) {
			if (!strcasecmp(buffer, debugLevels[i].string)) {
				logVerbosity = debugLevels[i].value;
				break;
			}
		}
		if (!debugLevels[i].string) {
			/* Broke out of loop! */
			syslog(LOG_CRIT, "Bad logVerbosity level.  Should be"
			    " one of (quiet, low, norm, or all)");
			return (-1);
		}
	}

	/*
	 * Should we be advertising our NAI?
	 */
	rc = GetPrivateProfileString(General, "AdvertiseNAI", "", buffer,
	    MAX_FN_LEN, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, "Unable to read General tags :%s",
		    ErrorString);
		return (-1);
	}
	if (*buffer) {
		if (YES(*buffer))
			faNAIadv = _B_TRUE;
		else
			faNAIadv = _B_FALSE;
	}

	/* Visitor Entry High Water Mark */
	rc = GetPrivateProfileInt(General, "visitorHighWaterMark", -1,
	    configFile);
	if (rc != -1)
		visitorEntryHighWaterMark = rc;

	/* Visitor Entry Low Water Mark */
	rc = GetPrivateProfileInt(General, "visitorLowWaterMark", -1,
	    configFile);
	if (rc != -1)
		visitorEntryLowWaterMark = rc;

	/* periodicInterval - This one is undocumented. */
	rc = GetPrivateProfileInt(General, "GarbageCollectionFrequency",
	    -1, configFile);
	if (rc != -1) {
		/*
		 * Magic numbers. Given that this is a faily dangerous
		 * feature, we need to restrict the values one can
		 * configure.
		 */
		if (rc < MIN_GARBAGE_COLLECTION_INTERVAL) {
			rc = MIN_GARBAGE_COLLECTION_INTERVAL;
		} else if (rc > MAX_GARBAGE_COLLECTION_INTERVAL) {
			rc = MAX_GARBAGE_COLLECTION_INTERVAL;
		}
		periodicInterval = rc;
	}

	/* performance checking interval - This one is undocumented. */
	rc = GetPrivateProfileInt(General, "PerformanceCheckInterval",
	    -1, configFile);
	if (rc != -1) {
		performanceInterval = rc;
	}


	/*
	 * Should we be advertising our NAI?
	 */
	rc = GetPrivateProfileString(General, "Daemonize", "", buffer,
	    MAX_FN_LEN, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, "Unable to read General tags :%s",
		    ErrorString);
		return (-1);
	}
	if (*buffer) {
		if (YES(*buffer))
			daemonize = _B_TRUE;
		else
			daemonize = _B_FALSE;
	}

	/*
	 * Should SNMP be disabled?
	 */
	rc = GetPrivateProfileString(General, "DisableSNMP", "", buffer,
	    MAX_FN_LEN, configFile);
	if (rc == -2) {
		syslog(LOG_ERR, "Unable to read General tags :%s",
		    ErrorString);
		return (-1);
	}
	if (*buffer) {
		if (YES(*buffer))
			disableSNMP = _B_TRUE;
		else
			disableSNMP = _B_FALSE;
	}

	return (0);
} /* readGeneral */


/*
 * Function: memswp
 *
 * Arguments:	A - Pointer to buffer
 *		B - Pointer to buffer
 *		length - length
 *
 * Description:	This function will swap the contents
 *		of A and B.
 *
 * Returns: int - 0 if successful.
 */
static void
memswp(char *A, char *B, int length)
{
	char *temp;
	temp = alloca(length);
	if (!temp) {
		syslog(LOG_CRIT, "Unable to allocate from the heap");
		return;
	}

	(void) memcpy(temp, A, length);
	(void) memcpy(A, B, length);
	(void) memcpy(B, temp, length);
}


/*
 * Function: sortSections
 *
 * Arguments:	Sections - Pointer to sections
 *		numSections - Number of sections
 *		sectionSize - Size of section
 *
 * Description: Since we have to have the Pools and SPIs defined
 * before we add an address, move all of the addresses to the end
 * of the sections. Use a single pass, starting at the end, and
 * doing a direct swap.
 *
 * Returns:
 */
static void
sortSections(char *Sections, int numSections, int sectionSize)
{
	int i;
	int j = -1;

	for (i = numSections-1; i >= 0; i--) {
		if (strncasecmp(&Sections[i*sectionSize], "Address", 7)) {
			/* Ok, we're stuck at a non-address, find one */
			/* to exchange with us */
			if (j < 0)
				j = i-1;

			for (; j >= 0; j--) {
				if (!strncasecmp(&Sections[j*sectionSize],
				    "Address", 7)) {
					/* Found one!  Swap it */
					memswp(&Sections[i*sectionSize],
					    &Sections[j*sectionSize],
					    sectionSize);
					/* break out of inner for loop */
					break;
				}
			}
			/* Check to see if we're finished */
			if (j < 0)
				return;
		}
	}
} /* sortSections */

/*
 * Function: readConfigInfo
 *
 * Arguments:	configFile - Pointer to filename
 *
 * Description: Read configuration information for the mobility
 *		agent from file
 *
 * Returns: int - 0 if successful
 */
static int
readConfigInfo(char *configFile)
{
	char *Sections;
	int  numSections, sectionSize;

#ifdef FIREWALL_SUPPORT
	domainInfo.addrIntervalCnt = 0;
	domainInfo.firewallCnt = 0;
#endif /* FIREWALL_SUPPORT */

	if (readGeneral(configFile)) {
		return (-1);
	}

	readGSPs(configFile);

	readAAASettings(configFile);

	/*
	 * Ok, now is when it gets a little complex.  Read in all the
	 * section names, then add Interfaces and Mobile nodes as they
	 * come up.
	 */
	Sections = IniListSections(configFile, &numSections, &sectionSize);

	/*
	 * We need to check for NULL return from iniListSections,
	 * otherwise we would be accessing a NULL pointer.
	 */
	if (Sections != NULL) {
		int i;

		sortSections(Sections, numSections, sectionSize);

		for (i = 0; i < numSections; i++) {
			if (!strncasecmp(&Sections[i*sectionSize],
			    "Advertisements", 14)) {
				if (setupInterface(configFile,
				    &Sections[i*sectionSize]))
					return (-1);
			} else if (!strncasecmp(&Sections[i*sectionSize],
			    "Address", 7)) {
				if (setupAddress(configFile,
				    &Sections[i*sectionSize]))
					return (-1);
			} else if (!strncasecmp(&Sections[i*sectionSize],
			    "SPI", 3)) {
				if (setupSPI(configFile,
				    &Sections[i*sectionSize]))
					return (-1);
			} else if (!strncasecmp(&Sections[i*sectionSize],
			    "Pool", 4)) {
				if (setupPool(configFile,
				    &Sections[i*sectionSize]))
					return (-1);
			}
#ifdef FIREWALL_SUPPORT
			/*
			 * XXX: Does this section need some enhancement ?.
			 */
			else if (!strncasecmp(&Sections[i*sectionSize],
			    "Firewall", 8)) {
				char Firewall[INET_ADDRSTRLEN+1];
				sscanf(&Sections[i*sectionSize],
				    "%*s %" VAL2STR(INET_ADDRSTRLEN) "s",
				    Firewall);

				domainInfo.fwAddr[domainInfo.firewallCnt++] =
				    inet_addr(Firewall);
			} /* end If */
#endif /* FIREWALL_SUPPORT */

		} /* End for() each section */
	}

	if (Sections != NULL) {
		free(Sections);
	}

	return (0);

} /* readConfigInfo */


/*
 * Function: InitSockets
 *
 * Arguments:	pointer to MaAdvConfigEntry
 *
 * Description: This function will open the ICMP, BCAST and
 *		the multicast socket, and will bind on all
 *		interfaces configured. A specific Join must
 *		be done for multicast on each interface.
 *
 * Returns: int, 0 if successful
 */
int
InitSockets(MaAdvConfigEntry *entry)
{
	int sid;
	int enable = 1;
	unsigned int ifceno;
	char addrstr1[40];
	struct sockaddr_in sa;
	struct ip_mreq imr;
	struct in_addr ifaddr;

	mipverbose(("Creating ICMP socket.\n"));


	/*
	 * First off, let's get the interface number.
	 */
	ifceno = if_nametoindex(entry->maIfaceName);

	if (ifceno == 0) {
		syslog(LOG_ERR,
		    "Unable to get interface number for %s",
		    entry->maIfaceName);
		return (-1);
	}

	/* Get a socket to receive ICMPs on. */
	if ((sid = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		syslog(LOG_CRIT,
		    "socket()Error: Couldn't create ICMP socket " \
		    "in InitSockets.");
		return (-1);
	}

	/*
	 * Just in case we advertise on 255.255.255.255, enable
	 * bcast
	 */
	enable = 1;
	if (setsockopt(sid, SOL_SOCKET, SO_BROADCAST,
	    (char *)&enable, sizeof (int)) < 0) {
		syslog(LOG_CRIT, "SO_BROADCAST on ICMPsock failed");
		return (-1);

	}

	if (setsockopt(sid, IPPROTO_IP, IP_BOUND_IF, (char *)&ifceno,
	    sizeof (char *))) {
			syslog(LOG_ERR,
			    "Unable to bind socket to interface %d", ifceno);
			return (-1);
	}

	/*
	 * Enable IP_XMIT_IF here so that we don't need to
	 * turn it on sendICMPmessage everytime we send
	 * multicast adv. IP_XMIT_IF will have to be set
	 * for all PPP interfaces, because there may be
	 * cases when PPP local and remote end both have
	 * non-unique addresses ( ex: private address)
	 */
	if (entry->maIfaceFlags & IFF_POINTOPOINT) {
		/*
		 * set IP_XMIT_IF
		 */
		if (setsockopt(sid, IPPROTO_IP, IP_XMIT_IF,
		    &ifceno, sizeof (ifceno)) < 0) {
			syslog(LOG_ERR,
			    "setsockopt() couldn't set IP_XMIT_IF"
			    "on Adv socket for interface id %d",
			    ifceno);
			return (-1);
		}
	} else {
		/*
		 * For non-pointtopoint interfaces we are still
		 * setting IP_MULTICAST_IF, as we expect to have
		 * unique ifaddr in this case.
		 * We can take advantage of cached routing entry
		 * too.
		 */
		ifaddr.s_addr = entry->maIfaceAddr;
		if (setsockopt(sid, IPPROTO_IP, IP_MULTICAST_IF,
		    (char *)&ifaddr, sizeof (ifaddr)) == -1) {
			syslog(LOG_ERR,
			    "setsockopt() Couldn't set multicast"
			    "on socket");
			return (-1);
		}
	}
	entry->maIfaceIcmpSock = sid;


	/*
	 * Create and bind the socket to monitor the
	 * unicast interface addr
	 */

	if ((sid = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	    syslog(LOG_CRIT,
		"socket()Error: Couldn't create unicast UDP " \
		"socket - to monitor unicast interface addr");
	    return (-1);
	}

	if (setsockopt(sid, SOL_SOCKET, SO_REUSEADDR,
		(char *)&enable, sizeof (int)) < 0) {
		syslog(LOG_NOTICE, "setsockopt() failed." \
		    "socket - to monitor unicast interface addr");
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(MIP_PORT);
	sa.sin_addr.s_addr = entry->maIfaceAddr;

	mipverbose(("Binding UDP socket to %s port %d.\n",
	    ntoa(sa.sin_addr.s_addr, addrstr1), ntohs(sa.sin_port)));
	if (bind(sid, (struct sockaddr *)&sa, sizeof (sa)) < 0) {
		syslog(LOG_CRIT,
		"bind() Error: Could not bind unicast socket." \
		    "(maIfaceaddr): %m");
		return (-1);
	}
	/*
	 * ToDO: Verify whether IP_RECV[IF|SLLA|TTL] socket
	 * options to be set here. This socket is used for
	 * broadcasting advertisements.
	 */

	if (setsockopt(sid, IPPROTO_IP, IP_RECVIF, &enable,
	    sizeof (int)) < 0) {
		syslog(LOG_ERR, "setsockopt IP_RECVIF "
		    "(maIfaceAddr):%m");
		return (-1);
	}


	if (setsockopt(sid, IPPROTO_IP, IP_RECVSLLA, &enable,
	    sizeof (int)) < 0) {
		syslog(LOG_ERR, "setsockopt IP_RECVSLLA " \
		    "(maIfaceAddr): %m");
		return (-1);
	}

	if (setsockopt(sid, IPPROTO_IP, IP_RECVTTL, &enable,
	    sizeof (int)) < 0) {
		syslog(LOG_ERR, "setsockopt IP_RECVTTL " \
		    "(maIfaceAddr): %m");
		return (-1);
	}
	if (setsockopt(sid, IPPROTO_IP, IP_BOUND_IF, (char *)&ifceno,
	    sizeof (char *))) {
		syslog(LOG_ERR,
		    "Unable to bind socket to interface %d", ifceno);
		return (-1);
	}

	entry->maIfaceUnicastSock = sid;

	/*
	 * PPP interfaces would not receive any broadcast packets.
	 * Therefore we don't need to bind to broadcast addresses.
	 */
	if ((entry->maIfaceFlags & IFF_POINTOPOINT) == 0) {
		/*
		 * Create and bind the socket to monitor
		 * the bcast interface addr
		 */
		if ((sid = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			syslog(LOG_CRIT,
			    "socket()Error:Couldn't create broadcast "
			    "UDP socket");
			return (-1);
		}

		if (setsockopt(sid, SOL_SOCKET, SO_REUSEADDR,
		    (char *)&enable, sizeof (int)) < 0) {
			syslog(LOG_NOTICE, "setsockopt() failed " \
			    "on the broadcast UDP socket");
		}

		sa.sin_family = AF_INET;
		sa.sin_port = htons(MIP_PORT);
		sa.sin_addr.s_addr = inet_addr(LINK_BCAST_ADDR);

		mipverbose(("Binding UDP socket to %s port %d.\n",
		    ntoa(sa.sin_addr.s_addr, addrstr1),
		    ntohs(sa.sin_port)));
		if (bind(sid, (struct sockaddr *)&sa,
		    sizeof (sa)) < 0) {
			syslog(LOG_CRIT,
			    "bind Error: Could not bind broadcast "
			    "socket - to monitor the bcast interface "
			    "addr");
			return (-1);
		}

		/*
		 * TODO: Verify whether IP_RECV* sockets are useful
		 * in this socket which binds itself to link_broadcast
		 * address.
		 */

		if (setsockopt(sid, IPPROTO_IP, IP_RECVIF, &enable,
		    sizeof (int)) < 0) {
			syslog(LOG_ERR, "setsockopt IP_RECVIF failed " \
			    "(LINK_BCAST_ADDR): %m");
			return (-1);
		}

		if (setsockopt(sid, IPPROTO_IP, IP_RECVSLLA, &enable,
		    sizeof (int)) < 0) {
			syslog(LOG_ERR,
			    "setsockopt IP_RECVSLLA failed "
			    "(LINK_BCAST_ADDR): %m");
			return (-1);
		}

		if (setsockopt(sid, IPPROTO_IP, IP_RECVTTL, &enable,
		    sizeof (int)) < 0) {
			syslog(LOG_ERR,
			    "setsockopt IP_RECVTTL failed "
			    "(LINK_BCAST_ADDR): %m");
			return (-1);
		}

		if (setsockopt(sid, IPPROTO_IP, IP_BOUND_IF,
		    (char *)&ifceno, sizeof (char *))) {
			(void) fprintf(stderr,
			    "Unable to bind socket to interface %d",
			    ifceno);
			return (-1);
		}

		entry->maIfaceBcastSock = sid;

		/*
		 * Create and bind the socket to monitor
		 * the directed bcast interface addr
		 */
		if ((sid = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		    syslog(LOG_CRIT,
			"socket()Error:Couldn't create broadcast UDP "
			"socket");
		    return (-1);
		}

		if (setsockopt(sid, SOL_SOCKET, SO_REUSEADDR,
		    (char *)&enable, sizeof (int)) < 0) {
			syslog(LOG_NOTICE, "setsockopt() failed " \
			    "on broadcast UDP socket");
		}

		sa.sin_family = AF_INET;
		sa.sin_port = htons(MIP_PORT);
		sa.sin_addr.s_addr = GENERATE_NET_BROADCAST_ADDR(entry);

		mipverbose(("Binding UDP socket to %s port %d.\n",
		    ntoa(sa.sin_addr.s_addr, addrstr1),
		    ntohs(sa.sin_port)));
		if (bind(sid, (struct sockaddr *)&sa,
		    sizeof (sa)) < 0) {
			syslog(LOG_CRIT,
			    "bind Error: Could not bind broadcast "
			    "socket.");
			return (-1);
		}

		/*
		 * Setting option on socket bound to NET_BROADCAST_ADDR
		 */
		if (setsockopt(sid, IPPROTO_IP, IP_RECVIF, &enable,
		    sizeof (int)) < 0) {
			syslog(LOG_ERR, "setsockopt IP_RECVIF "
			    "(NET_BROADCAST_ADDR): %m");
			return (-1);
		}


		if (setsockopt(sid, IPPROTO_IP, IP_RECVSLLA, &enable,
		    sizeof (int)) < 0) {
			syslog(LOG_ERR, "setsockopt IP_RECVSLLA ",
			    "(NET_BROADCAST_ADDR): %m");
			return (-1);
		}


		if (setsockopt(sid, IPPROTO_IP, IP_RECVTTL, &enable,
		    sizeof (int)) < 0) {
			syslog(LOG_ERR, "setsockopt IP_RECVTTL "
			    "(NET_BROADCAST_ADDR): %m");
			return (-1);
		}

		if (setsockopt(sid, IPPROTO_IP, IP_BOUND_IF,
		    (char *)&ifceno, sizeof (char *))) {
			syslog(LOG_ERR,
			    "Unable to bind socket to interface %d",
			    ifceno);
			return (-1);
		}

		enable = 1;
		if (setsockopt(sid, SOL_SOCKET, SO_REUSEADDR,
		    (char *)&enable, sizeof (int)) < 0) {
			syslog(LOG_NOTICE, "setsockopt() " \
			    "(NET_BROADCAST_ADDR): %m");
		}

		entry->maIfaceDirBcastSock = sid;
	} else {
		/* Set fd to -1 */
		entry->maIfaceBcastSock = -1;
		entry->maIfaceDirBcastSock = -1;
	}

	/*
	 * Create and bind the socket to monitor
	 * the multicast advertisement traffic (224.0.0.1
	 * and 224.0.0.2)
	 */

	if ((sid = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		syslog(LOG_CRIT,
		    "socket() Error: Couldn't create ICMP socket " \
		    "in InitSockets to monitor mcast advertisement.");
		return (-1);
	}

	if (setsockopt(sid, IPPROTO_IP, IP_RECVIF, &enable,
	    sizeof (int)) < 0) {
		syslog(LOG_ERR, "setsockopt IP_RECVIF failed...%s",
			strerror(errno));
		return (-1);
	}

	if (setsockopt(sid, IPPROTO_IP, IP_BOUND_IF, (char *)&ifceno,
	    sizeof (char *))) {
		syslog(LOG_ERR,
		    "Unable to bind socket to interface %d", ifceno);
		return (-1);
	}

	/*
	 * Join multicast groups so we can receive ICMP messages
	 * on this interface sent to 224.0.0.1
	 */
	imr.imr_multiaddr.s_addr = inet_addr(LINK_MCAST_ADV_ADDR);
	imr.imr_interface.s_addr = entry->maIfaceAddr;

	if (setsockopt(sid, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		(char *)&imr, sizeof (struct ip_mreq)) < 0) {
		syslog(LOG_NOTICE,
			"Could not join multicast group 224.0.0.1");
	} else {
	    mipverbose(("Joined %s on interface %s.\n",
		LINK_MCAST_ADV_ADDR,
		ntoa(entry->maIfaceAddr, addrstr1)));
	}

	/*
	 * Join multicast groups so we can receive ICMP messages
	 * on this interface sent to 224.0.0.2.
	 */
	imr.imr_multiaddr.s_addr = inet_addr(LINK_MCAST_ADV_ADDR2);
	imr.imr_interface.s_addr = entry->maIfaceAddr;
	if (setsockopt(sid, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		(char *)&imr, sizeof (struct ip_mreq)) < 0) {
		syslog(LOG_NOTICE,
			"Could not join multicast group 224.0.0.2");
	} else {
	    mipverbose(("Joined %s on interface %s.\n",
		LINK_MCAST_ADV_ADDR2,
		ntoa(entry->maIfaceAddr, addrstr1)));
	}


	entry->maIfaceAdvMulticastSock = sid;

	/*
	 * Create and bind the socket to monitor
	 * the multicast registration traffic (224.0.0.11)
	 */
	if ((sid = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	    syslog(LOG_CRIT,
		"socket()Error:Couldn't create broadcast UDP socket " \
		"to monitor multicast registration traffic.");
	    return (-1);
	}

	if (setsockopt(sid, SOL_SOCKET, SO_REUSEADDR,
		(char *)&enable, sizeof (int)) < 0) {
	    syslog(LOG_NOTICE, "setsockopt() failed for broadcast " \
		"UDP socket to monitor mcast registration traffic.");
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(MIP_PORT);
	sa.sin_addr.s_addr = inet_addr(LINK_MCAST_REG_ADDR);

	mipverbose(("Binding UDP socket to %s port %d.\n",
	    ntoa(sa.sin_addr.s_addr, addrstr1), ntohs(sa.sin_port)));
	if (bind(sid, (struct sockaddr *)&sa, sizeof (sa)) < 0) {
		syslog(LOG_CRIT,
		    "bind Error: Could not bind broadcast socket.");
		return (-1);
	}
	/* Set socket option for socket bound to 224.0.0.11 */

	if (setsockopt(sid, IPPROTO_IP, IP_RECVIF, &enable,
	    sizeof (int)) < 0) {
		syslog(LOG_ERR, "setsockopt IP_RECVIF " \
		    "(LINK_MCAST_REG_ADDR): %m");
		return (-1);
	}


	if (setsockopt(sid, IPPROTO_IP, IP_RECVSLLA, &enable,
	    sizeof (int)) < 0) {
		syslog(LOG_ERR, "setsockopt IP_RECVSLLA " \
		    "(LINK_MCAST_REG_ADDR): %m");
		return (-1);
	}

	if (setsockopt(sid, IPPROTO_IP, IP_RECVTTL, &enable,
	    sizeof (int)) < 0) {
		syslog(LOG_ERR, "setsockopt IP_RECVTTL " \
		    "(LINK_MCAST_REG_ADDR): %m");
		return (-1);
	}
	if (setsockopt(sid, IPPROTO_IP, IP_BOUND_IF, (char *)&ifceno,
	    sizeof (char *))) {
		syslog(LOG_ERR,
		    "Unable to bind socket to interface %d", ifceno);
		return (-1);
	}


	/*
	 * Join 224.0.0.11 so we can receive Registration Requests
	 * from the multicast address.
	 */
	imr.imr_multiaddr.s_addr = inet_addr(LINK_MCAST_REG_ADDR);
	imr.imr_interface.s_addr = entry->maIfaceAddr;
	if (setsockopt(sid, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		(char *)&imr, sizeof (struct ip_mreq)) < 0) {
		syslog(LOG_NOTICE,
		    "Could not join multicast group 224.0.0.11");
	} else {
	    mipverbose(("Joined %s on interface %s.\n",
		LINK_MCAST_REG_ADDR,
		ntoa(entry->maIfaceAddr, addrstr1)));

	}

	entry->maIfaceRegMulticastSock = sid;


	return (0);
}


/*
 * Function: deleteMobileNodeEntryHashHelper
 *
 * Arguments:	entry - Pointer to Mobile Node Entry
 *		p1 - First parameter to match (current time)
 *
 * Description: This function is used as the Hash Table Helper routine
 *		for Finalize() when we need to delete all
 *		mobile node entries, and will be called by
 *		getAllHashTableEntries().
 *
 * Returns:	_B_TRUE if the entry matches the desired criteria,
 *		otherwise _B_FALSE.
 */
/* ARGSUSED */
static boolean_t
deleteMobileNodeEntryHashHelper(void *entry, uint32_t p1)
{
	HaMobileNodeEntry *hentry = entry;
	HaBindingEntry *bindingEntry;
	HaBindingEntry *next_entry;

	bindingEntry = hentry->bindingEntries;
	while (bindingEntry) {
		next_entry = bindingEntry->next;
		delHABEent(hentry, bindingEntry);
		free(bindingEntry);
		bindingEntry = next_entry;
	}


	return (_B_FALSE);
}

/*
 * Function: deleteVisitorEntryHashHelper
 *
 * Arguments:	entry - Pointer to Mobile Node Entry
 *		p1 - First parameter to match (current time)
 *
 * Description: This function is used as the Hash Table Helper routine
 *		for Finalize() when we need to delete all
 *		visitor entries, and will be called by
 *		getAllHashTableEntries().
 *
 * Returns:	_B_TRUE if the entry matches the desired criteria,
 *		otherwise _B_FALSE.
 */
/* ARGSUSED */
static boolean_t
deleteVisitorEntryHashHelper(void *entry, uint32_t p1)
{
	FaVisitorEntry *faEntry = entry;

	delFAVEptr(faEntry, _B_TRUE, REASON_UNKNOWN);
	free(faEntry);
	return (_B_FALSE);
}

/*
 * This funciton cleans up whatever registration policy is
 * flagged as remaining.  We don't clean up tunnels policy
 * because that is done when the tunnel in encaprem() or
 * decaprem().  We return _B_FALSE since we want the entry
 * to be freed.
 */
/* ARGSUSED */
static boolean_t
deleteIPsecSAHashHelper(void *entry, uint32_t p1)
{
	MobilityAgentEntry *mae = entry;
	int i;

	for (i = FIRST_IPSEC_ACTION; i < LAST_IPSEC_ACTION; i++) {
		if (mae->maIPsecFlags & REQUEST(i))
			(void) removeIPsecPolicy(mae->maIPsecRequest[i]);

		if (mae->maIPsecFlags & REPLY(i))
			(void) removeIPsecPolicy(mae->maIPsecReply[i]);
	}

	return (_B_FALSE);
}


/*
 * Function: Finalize
 *
 * Arguments:	signo - signal
 *
 * Description: This function is the signal handler and is
 *		called when the agent is terminating. This
 *		function will destroy all of the threads,
 *		and free all of the binding and visitor entries
 *		which will clean up the Tunnel interfaces and the
 *		routing entries.
 *
 * Returns:
 */
/* ARGSUSED */
void
Finalize(int signo)
{
	char relativeTime[MAX_TIME_STRING_SIZE];
	char currentTime[MAX_TIME_STRING_SIZE];

	syslog(LOG_INFO, "---- %s (%s) ----",
	    sprintTime(currentTime, MAX_TIME_STRING_SIZE),
	    sprintRelativeTime(relativeTime, MAX_TIME_STRING_SIZE));

	shutdown_flag = _B_TRUE;

	/*
	 * First we need to kill all of the threads to ensure that no one
	 * will try to step on our toes. This will ensure that no other
	 * threads try to access any of the HashTables that we will need
	 * next.
	 */
	syslog(LOG_INFO, "<<< Shutting down threads >>>");

	mipverbose(("<<< Shutting down threads >>>\n"));
	if (DynamicInterface)
		(void) killDynamicInterfaceThread();
	(void) killDispatcherTaskThread();
	(void) killPeriodicTaskThread();
	(void) killSNMPTaskThread();
	(void) killAAATaskThread();
	(void) killStatServer();

	/*
	 * Save the state of the entire agent (mobile node entries,
	 * (dynamic) security associations, IPsec SAs, and binding
	 * entries.  This allows subsequent restoration of the state.
	 */
	(void) saveAgentState();

	/*
	 * Let's delete all of the Mobile Node binding entries
	 * so we end up cleaning up our tunnel interfaces. Note that
	 * since we are coming down, we will not request any locks,
	 * since that could get the signal handler in a deadlock
	 * situation.
	 */
	syslog(LOG_INFO, "<<< Cleaning up mobility bindings >>>");
	getAllHashTableEntries(&haMobileNodeHash,
	    deleteMobileNodeEntryHashHelper, LOCK_NONE, 0, _B_TRUE);


	/*
	 * Let's delete all of the Mobile Node binding entries
	 * so we end up cleaning up our routes. Note that
	 * since we are coming down, we will not request any locks,
	 * since that could get the signal handler in a deadlock
	 * situation.
	 */
	syslog(LOG_INFO, "<<< Cleaning up accepted visitor entries >>>");
	getAllHashTableEntries(&faVisitorHash,
	    deleteVisitorEntryHashHelper, LOCK_NONE, 0, _B_TRUE);

	/*
	 * Finally clean up any IPsec policies we have installed!  We don't
	 * do this above, because cleaning out the FA removed those
	 * specific to the FA, now we'll clean up the rest.
	 */
	syslog(LOG_INFO, "<<< Cleaning up all remaining IPsec policies >>>");
	getAllHashTableEntries(&mipAgentHash, deleteIPsecSAHashHelper,
	    LOCK_NONE, 0, _B_TRUE);

	OScleanup();

	syslog(LOG_INFO, "Terminated by signal (SIGTERM or SIGINT)");

	exit(1);
}

/*
 * Function: docleanup
 *
 * Arguments:
 *
 * Description: This function is called when the AAA connection
 *		to mipagent is down.  The function will
 *		free all of the binding and visitor entries
 *		which will clean up the Tunnel interfaces and the
 *		routing entries.
 * Returns:
 */
void
docleanup(void)
{
	char relativeTime[MAX_TIME_STRING_SIZE];
	char currentTime[MAX_TIME_STRING_SIZE];

	syslog(LOG_INFO, "---- %s (%s) ----",
	    sprintTime(currentTime, MAX_TIME_STRING_SIZE),
	    sprintRelativeTime(relativeTime, MAX_TIME_STRING_SIZE));
	mipverbose(("mipagent-AAA connection is down\n"));

	/*
	 * Let's delete all of the Mobile Node binding entries
	 * so we end up cleaning up our tunnel interfaces.
	 */
	syslog(LOG_INFO, "<<< Cleaning up mobility bindings >>>");
	getAllHashTableEntries(&haMobileNodeHash,
	    deleteMobileNodeEntryHashHelper, LOCK_NONE, 0, _B_TRUE);

	/*
	 * Let's delete all of the Mobile Node binding entries
	 * so we end up cleaning up our routes.
	 */
	syslog(LOG_INFO, "<<< Cleaning up accepted visitor entries >>>");
	getAllHashTableEntries(&faVisitorHash,
	    deleteVisitorEntryHashHelper, LOCK_NONE, 0, _B_TRUE);
}


/*
 * Function: SetSigHandlers
 *
 * Arguments: Set up handlers for various signals
 *
 * Description:
 *
 * Returns:
 */
static void
SetSigHandlers()
{
	if (signal(SIGINT, Finalize) == SIG_ERR) {
		syslog(LOG_CRIT,
			"signal() Error: failed to set handler for SIGINT.");
	}

	if (signal(SIGTERM, Finalize) == SIG_ERR) {
		syslog(LOG_CRIT,
			"signal() Error: failed to set handler for SIGTERM.");
	}
}


/*
 * Function: showConfigInfo
 *
 * Arguments:
 *
 * Description: This function will print out the current
 *		configuration of the agent.
 *
 * Returns:
 */
static void
showConfigInfo()
{

	mipverbose(("LogLevel                   : %d\n", logVerbosity));
#ifdef RADIUS_ENABLED
	mipverbose(("RadiusEnabled                : %d\n", radiusEnabled));
	if (radiusEnabled)
	    mipverbose(("   RadiusSharedLibrary       : %s\n",
				radiusSharedLibrary));
#endif /* RADIUS_ENABLED */
	mipverbose(("PeriodicInterval             : %d\n", periodicInterval));
/*
 * No longer used
 *	mipverbose(("AdvLifetime                  : %d\n", advLifetime));
 *	mipverbose(("RegLifetime                  : %d\n", regLifetime));
 */
	mipverbose(("IDfreshnessSlack             : %d\n", IDfreshnessSlack));
	mipverbose(("\n"));
	printMaAdvConfigHash(&maAdvConfigHash);
	mipverbose(("\n"));
	printHaMobileNodeHash(&haMobileNodeHash);
	mipverbose(("\n"));
#ifdef FIREWALL_SUPPORT
	printProtectedDomainInfo(domainInfo);
#endif /* FIREWALL_SUPPORT */
	mipverbose(("\n"));
}


/*
 * Function: Initialize
 *
 * Arguments:	configFile - Pointer to the config file name
 *
 * Description: This is the main initialization function. This
 *		function will initialize the hash tables, retrieve
 *		our NAI, read the config file and initialize the
 *		network interfaces.
 *
 * Returns: int, 0 if successful
 */
int
Initialize(char *configFile)
{
	struct utsname name;
	char   domainname[MAX_NAI_LENGTH];
	char currentTime[MAX_TIME_STRING_SIZE];
	char relativeTime[MAX_TIME_STRING_SIZE];
	struct hash_table *htbl;
	struct hash_entry *pentry;
	int i;

	/* Make sure we are running as root. */
	if (getuid()) {
		(void) fprintf(stderr,
		    "mipagent: Error: must be run by root\n");
		return (-1);
	}

	openlog("mipagent", LOG_CONS, LOG_DAEMON);

	syslog(LOG_INFO, "Mobile IP agent started ...");
	syslog(LOG_INFO, "---- %s (%s) ----",
	sprintTime(currentTime, MAX_TIME_STRING_SIZE),
	sprintRelativeTime(relativeTime, MAX_TIME_STRING_SIZE));

	/* Initiate global DynamicInterface variables here */
	DynamicInterface = _B_FALSE;
	dynamicIfaceHead = NULL;

	/* Can we find, and read our config file? */
	if (access(configFile, R_OK) < 0) {
		/*
		 * config file non existent, or can't be read...
		 *    keel over verbosely (is there an other way?)
		 */
		syslog(LOG_CRIT, "Config file non-existent, or not readable.");
		syslog(LOG_CRIT, "Cannot load initialization settings, "
		    "access() error %m.");
		syslog(LOG_CRIT, "-> See mipagent(1M).");

		/* Spit a critical startup error to the user, too */
		(void) fprintf(stderr, "Error: config file non-existent, "
		    "or not readable, cannot initialize.\n");
		(void) fprintf(stderr, "-> See mipagent(1M) for more info.\n");

		/* tell the calling function it can keel over now. */
		return (-1);
	}

	/* Initialize random number generator */
	randomInit();

	/* Get the hosts' Network Access Identifier */
	if (uname(&name) < 0) {
		syslog(LOG_CRIT, "Error 1: Unable to get our own identity.");
		return (-1);
	}

	errno = 0;
	(void) getdomainname(domainname, sizeof (domainname));
	if (errno != 0) {
		syslog(LOG_CRIT, "Error 2: Unable to get our own identity.");
		return (-1);
	}

	(void) strcpy(maNai, name.nodename);
	(void) strcat(maNai, "@");
	(void) strcat(maNai, domainname);

	syslog(LOG_INFO, "Our NAI is %s", maNai);

	/*
	 * Initialize the hash tables
	 */
	if (InitHash(&faVisitorHash)) {
		syslog(LOG_CRIT, "Unable to initialize visitor hash table");
		return (-1);
	}

	if (InitHash(&maAdvConfigHash)) {
		syslog(LOG_CRIT, "Unable to initialize interface hash table");
		return (-1);
	}

	if (InitHash(&haMobileNodeHash)) {
		syslog(LOG_CRIT, "Unable to initialize mobile node hash table");
		return (-1);
	}

	if (InitHash(&mipSecAssocHash)) {
	    syslog(LOG_CRIT,
		"Unable to initialize security associations hash table");
	    return (-1);
	}

	if (InitHash(&mipAgentHash)) {
		syslog(LOG_CRIT, "Unable to initialize agents hash table");
		return (-1);
	}

	if (InitHash(&mipSecViolationHash)) {
	    syslog(LOG_CRIT,
			"Unable to initialize security violation hash table");
	    return (-1);
	}

	if (InitHash(&mipPoolHash)) {
		syslog(LOG_CRIT, "Unable to initialize pool hash table");
		return (-1);
	}

	if (InitHash(&mipTunlHash)) {
		syslog(LOG_CRIT, "Unable to initialize tunnel hash table");
		return (-1);
	}

	/* Initialize maAdvConfigTable and haMobileNodeTable from file */
	if (readConfigInfo(configFile) < 0) {
	    syslog(LOG_CRIT, "Error: Start up configuration unsuccessful.");
	    return (-1);
	}


	/*
	 * Initialize itself as a daemon
	 */
	if (daemonize == _B_TRUE) {
		if (daemonInit() == -1)
			exit(1);
	}

	showConfigInfo();

	/* OS-specific initialization of tunneling module etc */
	if (InitNet() == -1) {
		syslog(LOG_CRIT, "InitNet failed");
		return (-1);
	}

	/* OS-neutral, socket initialization */
	htbl = &maAdvConfigHash;
	for (i = 0; i < HASH_TBL_SIZE && htbl->size; i++) {
		pentry = htbl->buckets[i];
		while (pentry != NULL) {
			if (InitSockets((MaAdvConfigEntry *)pentry->data) < 0) {
				syslog(LOG_CRIT, "InitSockets failed.");
				return (-1);
			}
			pentry = pentry->next;
		}
	}

	/* Set up periodic house keeping and other chores */
	SetSigHandlers();

	return (0);
}
