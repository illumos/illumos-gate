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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <nlist.h>

#include "snmp_msg.h"
#include "impl.h"
#include "trace.h"
#include "snmp.h"
#include "pdu.h"
#include "trap.h"
#include "error.h"
#include "oid.h"
#include "usage.h"


#include "sea_i18n.h"


static int is_number (char *buf); 

int
main(int argc, char *argv[])
{
    extern char *optarg;
	extern int optind;
	int opt;

	char hostname[MAXHOSTNAMELEN];
	IPAddress ip_address;
	IPAddress my_ip_addr;	
	Oid *enterprise;
	int generic, specific, level; 
	SNMP_variable *variables;
	struct hostent *hp;
	int trap_port = -1;
	u_long time_stamp = (u_long)-1;
	int enterprise_flag= 0, a_flag = 0, i_flag = 0;
	
	optind = 1;
	
	/* the default host name is local host */
	gethostname(hostname, sizeof(hostname)); 

	/* default Oid for enterprise is sun */
	enterprise = &sun_oid; 

	/* generic, specific */
	generic = 6; 
	specific = 1;


        {
        char domain_path[MAXPATHLEN];

        setlocale(LC_ALL, "");

        sprintf(domain_path, SEA_LOCALE_PATH);

        bindtextdomain(DOMAIN_MGET, domain_path);
        bindtextdomain(DOMAIN_SGET,   domain_path);
        bindtextdomain(DOMAIN_LIBGET,   domain_path);
        bindtextdomain(DOMAIN_LGET, domain_path);
        bindtextdomain(DOMAIN_FGET,  domain_path);  /* formatting string */
        }


	/* get command-line options */
    while ((opt = getopt(argc, argv, "h:c:e:E:g:s:i:t:a:T:p:")) != EOF) {
		switch (opt) {
			case 'T':
				level = atoi(optarg);
				if(trace_set(level, error_label)){
					fprintf(stderr, " %d is not a valid trace level!\n",
							level); 
					usage();
				}
				break; 
			case 'h':		/* host to send trap to */
				if (strlcpy(hostname, optarg, sizeof (hostname))
					> MAXHOSTNAMELEN) {
					fprintf(stderr, "%s: hostname too long!\
						\n", optarg);
					exit(1);
				}
			case 'c':
				trap_community = optarg; 
				break; 
			case 'e':
				if (enterprise_flag) {
					usage();
				}				  
				enterprise = SSAOidStrToOid(optarg,error_label);
				if (!enterprise){ /* error */
					fprintf(stderr,
							"%s: not a valid enterprise oid string!\n",
							optarg);
					usage();
				}
				enterprise_flag = 1; 
				break; 
			case 'E':
				if (enterprise_flag) {
					usage();
				}
				enterprise = get_oid(optarg);
				if (!enterprise) {
					usage();
				}
				enterprise_flag = 1; 
				break; 
			case 'g':         /* generic trap type */
				if (is_number(optarg))
					usage(); 
				generic = atoi(optarg);
				if ((generic > 6 ) || (generic < 0))
					usage(); 
				break;
			case 's':         /* specific trap type */
				if (is_number(optarg))
					usage(); 
				specific = atoi(optarg);
				break;
			case 'i':
				if (name_to_ip_address(optarg,
									   &my_ip_addr,
									   error_label)) {
					usage();
				}
				i_flag = 1; 
				break; 
			case 't': /* timestamp */
				time_stamp = atol(optarg);
				break;
			case 'p':
				if (is_number(optarg))
					usage(); 
				trap_port = atoi(optarg);
				break; 
			case 'a':         /* attribute information */
				if ((variables = get_variable(optarg))== NULL){
					fprintf(stderr,
							"%s: not a valid variable!\n", optarg); 
					usage();
				}
				a_flag = 1; 
				break;
			case '?':		/* usage help */
				usage();
				break; 
			default:
				usage();
				break;
		}  /* switch */
	}/* while */

	if ((optind != argc) || (!a_flag))
		usage();
   
	if ((ip_address.s_addr = inet_addr(hostname)) == -1 ) {
		if ((hp = gethostbyname(hostname)) == NULL) {
			fprintf(stderr, "\n%s is not a valid hostname!\n\n", hostname);
			usage(); 
		}
		memcpy(&(ip_address.s_addr), hp->h_addr, hp->h_length);
	}



	/* some trace message */
	
	if (trap_send_with_more_para(&ip_address,
								 my_ip_addr, trap_community, i_flag,
								 enterprise,
								 generic,
								 specific,
								 trap_port,
								 time_stamp,
								 variables,
								 error_label)) {
		fprintf(stderr, "trap_send not success!\n\n");
		return (-1);
	} else {
		return (0);
	}

/*	if (trap_send(&ip_address,
				  enterprise,
				  generic,
				  specific,
				  variables,
				  error_label)) {
		fprintf(stderr, "trap_send not success!\n\n");
	}	 */
}



static int is_number (buf)
char *buf;
{
	int len, i;

	if (buf == NULL)
		return (-1);
	
	len = strlen(buf);
	for (i= 0; i < len; i++) 
		if (!isdigit(buf[i])) {
		fprintf(stderr, "\n%s is not a valid generic or specific trap type number!\n\n", buf);
		return(-1);
		}
	return (0);
}
	
