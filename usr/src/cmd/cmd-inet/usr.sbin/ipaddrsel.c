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

#include <libintl.h>
#include <locale.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <stropts.h>
#include <sys/conf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inet/ip.h>
#include <inet/ip6_asp.h>

/*
 * The size of the table we initially use to retrieve the kernel's policy
 * table.  If this value is too small, we use the value returned from the
 * SIOCGIP6ADDRPOLICY ioctl.
 */
#define	KERN_POLICY_SIZE	32
#define	IPV6DAS_MAXLINELEN	1024
#define	IPV6DAS_MAXENTRIES	512

typedef enum {
	IPV6DAS_PRINTPOLICY,
	IPV6DAS_SETPOLICY,
	IPV6DAS_SETDEFAULT
} ipv6das_cmd_t;

static char *myname;	/* Copied from argv[0] */

static int	parseconf(const char *, ip6_asp_t **);
static int	setpolicy(int, ip6_asp_t *, int);
static int	printpolicy(int);
static int	ip_mask_to_plen_v6(const in6_addr_t *);
static in6_addr_t *ip_plen_to_mask_v6(int, in6_addr_t *);
static int	strioctl(int, int, void *, int);
static void	usage(void);

int
main(int argc, char **argv)
{
	int		opt, status, sock, count;
	char		*conf_filename;
	ipv6das_cmd_t	ipv6das_cmd = IPV6DAS_PRINTPOLICY;
	ip6_asp_t	*policy_table;

	myname = *argv;

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

	(void) textdomain(TEXT_DOMAIN);

	while ((opt = getopt(argc, argv, "df:")) != EOF)
		switch (opt) {
		case 'd':
			ipv6das_cmd = IPV6DAS_SETDEFAULT;
			break;
		case 'f':
			conf_filename = optarg;
			ipv6das_cmd = IPV6DAS_SETPOLICY;
			break;
		default:
			usage();
			return (EXIT_FAILURE);
		}
	if (argc > optind) {
		/* shouldn't be any extra args */
		usage();
		return (EXIT_FAILURE);
	}

	/* Open a socket that we can use to send ioctls down to IP. */
	if ((sock = socket(PF_INET6, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		return (EXIT_FAILURE);
	}

	switch (ipv6das_cmd) {
	case IPV6DAS_SETPOLICY:
		if ((count = parseconf(conf_filename, &policy_table)) <= 0)
			return (EXIT_FAILURE);
		status = setpolicy(sock, policy_table, count);
		free(policy_table);
		break;
	case IPV6DAS_SETDEFAULT:
		status = setpolicy(sock, NULL, 0);
		break;
	case IPV6DAS_PRINTPOLICY:
	default:
		status = printpolicy(sock);
		break;
	}

	(void) close(sock);
	return (status);
}

/*
 * parseconf(filename, new_policy)
 *
 * Parses the file identified by filename, filling in new_policy
 * with the address selection policy table specified in filename.
 * Returns -1 on failure, or the number of table entries found
 * on success.
 */
static int
parseconf(const char *filename, ip6_asp_t **new_policy)
{
	FILE		*fp;
	char		line[IPV6DAS_MAXLINELEN];
	char		*cp, *end;
	char		*prefixstr;
	uint_t		lineno = 0, entryindex = 0;
	int		plen, precedence;
	char		*label;
	size_t		labellen;
	int		retval;
	ip6_asp_t	tmp_policy[IPV6DAS_MAXENTRIES];
	boolean_t	have_default = B_FALSE;
	in6_addr_t	prefix, mask;
	boolean_t	comment_found = B_FALSE, end_of_line = B_FALSE;

	if ((fp = fopen(filename, "r")) == NULL) {
		perror(filename);
		return (-1);
	}

	while (fgets(line, sizeof (line), fp) != NULL) {
		if (entryindex == IPV6DAS_MAXENTRIES) {
			(void) fprintf(stderr,
			    gettext("%s: too many entries\n"), filename);
			retval = -1;
			goto end_parse;
		}

		lineno++;
		cp = line;

		/* Skip leading whitespace */
		while (isspace(*cp))
			cp++;

		/* Is this a comment or blank line? */
		if (*cp == '#' || *cp == '\0')
			continue;

		/*
		 * Anything else must be of the form:
		 * <IPv6-addr>/<plen> <precedence> <label>
		 */
		prefixstr = cp;
		if ((cp = strchr(cp, '/')) == NULL) {
			(void) fprintf(stderr,
			    gettext("%s: invalid prefix on line %d: %s\n"),
			    filename, lineno, prefixstr);
			continue;
		}
		*cp = '\0';
		if (inet_pton(AF_INET6, prefixstr, &prefix) != 1) {
			(void) fprintf(stderr,
			    gettext("%s: invalid prefix on line %d: %s\n"),
			    filename, lineno, prefixstr);
			continue;
		}
		cp++;

		errno = 0;
		plen = strtol(cp, &end, 10);
		if (cp == end || errno != 0) {
			(void) fprintf(stderr,
			    gettext("%s: invalid prefix length on line %d\n"),
			    filename, lineno);
			continue;
		}
		if (ip_plen_to_mask_v6(plen, &mask) == NULL) {
			(void) fprintf(stderr,
			    gettext("%s: invalid prefix length on line %d:"
			    " %d\n"), filename, lineno, plen);
			continue;
		}
		cp = end;

		errno = 0;
		precedence = strtol(cp, &end, 10);
		if (cp == end || precedence < 0 || errno != 0) {
			(void) fprintf(stderr,
			    gettext("%s: invalid precedence on line %d\n"),
			    filename, lineno);
			continue;
		}
		cp = end;

		while (isspace(*cp))
			cp++;
		label = cp;
		/*
		 * NULL terminate the label string.  The label string is
		 * composed of non-blank characters, and can optionally be
		 * followed by a comment.
		 */
		while (*cp != '\0' && !isspace(*cp) && *cp != '#')
			cp++;
		if (*cp == '#')
			comment_found = B_TRUE;
		else if (*cp == '\0' || *cp == '\n')
			end_of_line = B_TRUE;
		*cp = '\0';

		labellen = cp - label;
		if (labellen == 0) {
			(void) fprintf(stderr,
			    gettext("%s: missing label on line %d\n"),
			    filename, lineno);
			continue;
		}
		if (labellen >= IP6_ASP_MAXLABELSIZE) {
			(void) fprintf(stderr,
			    gettext("%s: label too long on line %d, labels "
			    "have a %d character limit.\n"), filename, lineno,
			    IP6_ASP_MAXLABELSIZE - 1);
			continue;
		}

		tmp_policy[entryindex].ip6_asp_prefix = prefix;
		tmp_policy[entryindex].ip6_asp_mask = mask;
		tmp_policy[entryindex].ip6_asp_precedence = precedence;
		/*
		 * We're specifically using strncpy() to copy the label
		 * to take advantage of the fact that strncpy will add
		 * NULL characters to the target string up to the given
		 * length, so don't change the call to strncpy() with
		 * out also taking into account this requirement.  The
		 * labels are stored in the kernel in that way in order
		 * to make comparisons more efficient: all 16 bytes of
		 * the labels are compared to each other; random bytes
		 * after the NULL terminator would yield incorrect
		 * comparisons.
		 */
		(void) strncpy(tmp_policy[entryindex].ip6_asp_label, label,
		    IP6_ASP_MAXLABELSIZE);

		/*
		 * Anything else on the line should be a comment; print
		 * a warning if that's not the case.
		 */
		if (!comment_found && !end_of_line) {
			cp++;
			while (*cp != '\0' && isspace(*cp) && *cp != '#')
				cp++;
			if (*cp != '\0' && *cp != '#') {
				(void) fprintf(stderr,
				    gettext("%s: characters following label "
				    "on line %d will be ignored\n"),
				    filename, lineno);
			}
		}

		if (IN6_IS_ADDR_UNSPECIFIED(&prefix) && plen == 0)
			have_default = B_TRUE;

		comment_found = B_FALSE;
		end_of_line = B_FALSE;
		entryindex++;
	}

	if (!have_default) {
		(void) fprintf(stderr,
		    gettext("%s: config doesn't contain a default entry.\n"),
		    filename);
		retval = -1;
		goto end_parse;
	}

	/* Allocate the caller's array. */
	if ((*new_policy = malloc(entryindex * sizeof (ip6_asp_t))) == NULL) {
		perror("malloc");
		retval = -1;
		goto end_parse;
	}

	(void) memcpy(*new_policy, tmp_policy, entryindex * sizeof (ip6_asp_t));
	retval = entryindex;

end_parse:
	(void) fclose(fp);
	return (retval);
}

/*
 * setpolicy(sock, new_policy, count)
 *
 * Sends an SIOCSIP6ADDRPOLICY ioctl to the kernel to set the address
 * selection policy table pointed to by new_policy.  count should be
 * the number of entries in the table; sock should be an open INET6
 * socket.  Returns EXIT_FAILURE or EXIT_SUCCESS.
 */
static int
setpolicy(int sock, ip6_asp_t *new_policy, int count)
{
	if (strioctl(sock, SIOCSIP6ADDRPOLICY, new_policy,
	    count * sizeof (ip6_asp_t)) < 0) {
		perror("SIOCSIP6ADDRPOLICY");
		return (EXIT_FAILURE);
	}
	return (EXIT_SUCCESS);
}

/*
 * printpolicy(sock)
 *
 * Queries the kernel for the current address selection policy using
 * the open socket sock, and prints the result.  Returns EXIT_FAILURE
 * if the table cannot be obtained, or EXIT_SUCCESS if the table is
 * obtained and printed successfully.
 */
static int
printpolicy(int sock)
{
	ip6_asp_t	policy[KERN_POLICY_SIZE];
	ip6_asp_t	*policy_ptr = policy;
	int		count, policy_index;
	char		prefixstr[INET6_ADDRSTRLEN + sizeof ("/128")];

	if ((count = strioctl(sock, SIOCGIP6ADDRPOLICY, policy_ptr,
	    KERN_POLICY_SIZE * sizeof (ip6_asp_t))) < 0) {
		perror("SIOCGIP6ADDRPOLICY");
		return (EXIT_FAILURE);
	}
	if (count > KERN_POLICY_SIZE) {
		policy_ptr = malloc(count * sizeof (ip6_asp_t));
		if (policy_ptr == NULL) {
			perror("malloc");
			return (EXIT_FAILURE);
		}
		if ((count = strioctl(sock, SIOCGIP6ADDRPOLICY, policy_ptr,
		    count * sizeof (ip6_asp_t))) < 0) {
			perror("SIOCGIP6ADDRPOLICY");
			return (EXIT_FAILURE);
		}
	}

	if (count == 0) {
		/*
		 * There should always at least be a default entry in the
		 * policy table, so the minimum acceptable value of
		 * policy_count is 1.
		 */
		(void) fprintf(stderr, gettext("%s: ERROR: "
		    "IPv6 address selection policy is empty.\n"), myname);
		return (EXIT_FAILURE);
	}

	/*
	 * The format printed here must also be parsable by parseconf(),
	 * since we expect users to be able to redirect this output to
	 * a usable configuration file if need be.
	 */
	(void) printf("# Prefix                  "
		"                    Precedence Label\n");
	for (policy_index = 0; policy_index < count; policy_index++) {
		(void) snprintf(prefixstr, sizeof (prefixstr), "%s/%d",
		    inet_ntop(AF_INET6,
			&policy_ptr[policy_index].ip6_asp_prefix, prefixstr,
			sizeof (prefixstr)),
		    ip_mask_to_plen_v6(&policy_ptr[policy_index].ip6_asp_mask));
		(void) printf("%-45s %10d %s\n", prefixstr,
		    policy_ptr[policy_index].ip6_asp_precedence,
		    policy_ptr[policy_index].ip6_asp_label);
	}

	if (policy_ptr != policy)
		free(policy_ptr);
	return (EXIT_SUCCESS);
}

/*
 * ip_mask_to_plen_v6(v6mask)
 *
 * This function takes a mask and returns number of bits set in the
 * mask (the represented prefix length).  Assumes a contigious mask.
 */
int
ip_mask_to_plen_v6(const in6_addr_t *v6mask)
{
	uint8_t		bits;
	uint32_t	mask;
	int		i;

	if (v6mask->_S6_un._S6_u32[3] == 0xffffffff) /* check for all ones */
		return (IPV6_ABITS);

	/* Find number of words with 32 ones */
	bits = 0;
	for (i = 0; i < 4; i++) {
		if (v6mask->_S6_un._S6_u32[i] == 0xffffffff) {
			bits += 32;
			continue;
		}
		break;
	}

	/*
	 * Find number of bits in the last word by searching
	 * for the first one from the right
	 */
	mask = ntohl(v6mask->_S6_un._S6_u32[i]);
	if (mask == 0)
		return (bits);

	return (bits + 32 - (ffs(mask) - 1));
}

/*
 * ip_plen_to_mask_v6(plen, bitmask)
 *
 * Convert a prefix length to the mask for that prefix.
 * Returns the argument bitmask.
 */
in6_addr_t *
ip_plen_to_mask_v6(int plen, in6_addr_t *bitmask)
{
	uint32_t *ptr;

	if (plen > IPV6_ABITS || plen < 0)
		return (NULL);

	(void) memset(bitmask, 0, sizeof (in6_addr_t));
	if (plen == 0)
		return (bitmask);

	ptr = (uint32_t *)bitmask;
	while (plen > 32) {
		*ptr++ = 0xffffffffU;
		plen -= 32;
	}
	*ptr = htonl(0xffffffffU << (32 - plen));
	return (bitmask);
}

/*
 * strioctl(fd, cmd, ptr, ilen)
 *
 * Passes an I_STR ioctl to fd.  The ioctl type is specified by cmd, and
 * any date to be sent down is specified by a pointer to the buffer (ptr)
 * and the buffer size (ilen).  Returns the return value from the ioctl()
 * call.
 */
static int
strioctl(int fd, int cmd, void *ptr, int ilen)
{
	struct strioctl str;
	int retv;

	str.ic_cmd = cmd;
	str.ic_timout = 0;
	str.ic_len = ilen;
	str.ic_dp = ptr;

	while ((retv = ioctl(fd, I_STR, &str)) == -1) {
		if (errno != EINTR)
			break;
	}
	return (retv);
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "Usage: %s\n"
	    "       %s -f <filename>\n"
	    "       %s -d\n"), myname, myname, myname);
}
