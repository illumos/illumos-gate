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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <rpcsvc/nis.h>

#define	LOCAL_PREF	"/var/nis/client_info"
#define	LOCAL_TMP	"/var/nis/client_info.tmp"
#define	TABLE		"client_info"
#define	TABLE_TYPE	"client_info_tbl"
#define	NCOLS	4

#define	PREF_SRVR	"pref_srvr"
#define	PREF_TYPE	"pref_type"

#define	OP_TEST		1
#define	OP_FLUSH	2
#define	OP_GLOBAL	3
#define	OP_LOCAL	4
#define	OP_ADD		5
#define	OP_MODIFY	6
#define	OP_UPDATE	7
#define	OP_REMOVE	8
#define	OP_DELETE	9
#define	OP_LIST		10

struct server_list {
	char *client;
	char *options;
	char **list;
	char **interface;
	int *weight;
	int count;
	int alloc;
	int ntoken;
	char *tokens[20];
	char *token_buff;
};
typedef struct server_list server_list;
int debug = 0;
int verbose = 0;
int entry_found = 0;
static int old_format = 0;

void	get_local_servers(server_list *, char *, int);
void	parse_preference(server_list *, char *, char *, char *);
int	parse_info(server_list *, char *, char **, char **);
void	parse_server(char *, char **, char **, int *);
void	server_list_init(server_list *);
void	server_list_clear(server_list *);
void	server_list_add(server_list *, char *);
int	server_list_remove(server_list *, char *);
void	server_list_print(server_list *, FILE *);
void	get_servers(server_list *, char *, char *, int);
void	remove_local_servers(server_list *);
void	remove_servers(server_list *, char *);
void	update_local_servers(server_list *);
void	update_servers(server_list *, char *);
void	create_table(char *, char *);
void	convert_old2new(server_list *, char *);
int	print_tokens(FILE *, server_list *, char *);
void	print_local_servers(server_list *, char *);
void	print_servers(server_list *, char *, char *);
int 	flush_cache(char *);

extern nis_object nis_default_obj;

extern ulong_t __inet_get_addr(void *, int);
extern void *__inet_get_local_interfaces();
extern void __inet_free_local_interfaces(void *);
extern char *__inet_get_networka(void *, int);
extern int __inet_address_count(void *);


void
usage(char *s)
{
	fprintf(stderr, "\t%s -a {-L|-G} [-o <opt-string>] [-d domain] ", s);
	fprintf(stderr, "[-C client] {<server-list>} ...\n");

	fprintf(stderr, "\t%s -l {-L|-G} [-C client]\n", s);

	fprintf(stderr, "\t%s -m {-L|-G} [-o <opt-string>] [-d domain] ", s);
	fprintf(stderr, "[-C client] {<old-server>=<new-server>} ...\n");

	fprintf(stderr, "\t%s -r {-L|-G} [-o <opt-string>] [-d domain] ", s);
	fprintf(stderr, "[-C client] {<server-list>} ...\n");

	fprintf(stderr, "\t%s -u {-L|-G} [-o <opt-string>] [-d domain] ", s);
	fprintf(stderr, "[-C client] {<server-list>}\n");

	fprintf(stderr, "\t%s -x {-L|-G} [-d domain] [-C client]\n", s);

	fprintf(stderr, "\t%s -F\n", s);

	exit(1);
}

int
main(int argc, char **argv)
{
	int c;
	int op;
	int subop;
	int op_count = 0;
	int subop_count = 0;
	char *options = NULL;
	char *domain = NULL;
	char *client = NULL;
	int create = 0;
	server_list servers;

	while ((c = getopt(argc, argv, "vZTFLGalmurxo:d:C:")) != EOF) {
		switch (c) {
		    case 'T':
			op_count++;
			op = OP_TEST;
			break;
		    case 'F':
			if (geteuid() != (uid_t)0) {
				fprintf(stderr,
					"%s: -F option must be run as root.\n",
					argv[0]);
				exit(1);
			}
			op_count++;
			op = OP_FLUSH;
			break;
		    case 'L':
			op_count++;
			op = OP_LOCAL;
			break;
		    case 'G':
			op_count++;
			op = OP_GLOBAL;
			break;
		    case 'a':
			subop_count++;
			subop = OP_ADD;
			create = 1;
			break;
		    case 'l':
			subop_count++;
			subop = OP_LIST;
			break;
		    case 'm':
			subop_count++;
			subop = OP_MODIFY;
			break;
		    case 'u':
			subop_count++;
			subop = OP_UPDATE;
			break;
		    case 'r':
			subop_count++;
			subop = OP_REMOVE;
			break;
		    case 'x':
			subop_count++;
			subop = OP_DELETE;
			break;
		    case 'o':
			options = optarg;
			break;
		    case 'd':
			domain = optarg;
			break;
		    case 'C':
			client = optarg;
			break;
		    case 'Z':
			debug = 1;
			break;
		    case 'v':
			verbose = 1;
			break;
		    default:
			usage(argv[0]);
			break;
		}
	}

	if (op_count == 0) {
		fprintf(stderr,
			"%s:  one of -L, -G, -T, or -F must be specified\n",
			argv[0]);
		usage(argv[0]);
	} else if (op_count != 1) {
		fprintf(stderr,
			"%s:  only one of -L, -G, -T, or -F may be specified\n",
			argv[0]);
		usage(argv[0]);
	}
	if (op == OP_LOCAL || op == OP_GLOBAL) {
		if (subop_count == 0) {
			fprintf(stderr,
			"%s:  one of -a, -l, -m, -r, or -x must be specified\n",
			argv[0]);
			usage(argv[0]);
		} else if (subop_count != 1) {
			fprintf(stderr,
		"%s:  only one of -a, -l, -m, -r, or -x may be specified\n",
			argv[0]);
			usage(argv[0]);
		}
	}

	if (!nis_defaults_init(NULL))
		exit(1);

	if (op == OP_TEST) {
		exit(0);
	}

	if (op == OP_FLUSH) {
		exit(flush_cache(argv[0]));
	}

	/* OP_LOCAL or OP_GLOBAL */
	if (subop == OP_LIST) {
		/* listing the clint_info */
		if (op == OP_LOCAL)
			print_local_servers(&servers, client);
		else {
			if (domain == NULL)
				domain = nis_local_directory();
			print_servers(&servers, domain, client);
		}
		exit(0);
	}
	if (geteuid() != (uid_t)0) {
		fprintf(stderr,
			"%s: -L option must be run as root except to list "
			"the preferred server information (the -l option)\n",
			argv[0]);
		exit(1);
	}

	if (client == NULL) {
		client = (char *)malloc(256 * sizeof (char));
		if (client == NULL) {
			fprintf(stderr, "out of memory\n");
			exit(1);
		}
		if (gethostname(client, 256)) {
			perror("gethostname()");
			exit(1);
		}
	}

	if (op == OP_LOCAL)
		get_local_servers(&servers, client, create);
	else {
		if (domain == NULL)
			domain = nis_local_directory();
		get_servers(&servers, domain, client, create);
	}

	if (client)
		servers.client = client;
	if (options) {
		if (*options && (strcasecmp(options, "all") != 0) &&
				(strcasecmp(options, "pref_only") != 0)) {
			fprintf(stderr, "%s: invalid option specified.\n",
				options);
			fprintf(stderr,
			"Valid options are \"all\" and \"pref_only\".\n");
			exit(1);
			}
		servers.options = options;
	}

	if (subop == OP_ADD) {
		for (; optind < argc; optind++) {
			char *buf, *name, *p;
			buf = strdup(argv[optind]);
			name = buf;
			do {
				if (p = strchr(name, ','))
					*p++ = '\0';
				if (verbose)
					printf("Adding server %s...\n",
						name);
				server_list_add(&servers, name);
				name = p;
			} while (p);
			free(buf);
		}
	} else if (subop == OP_UPDATE) {
		server_list_clear(&servers);
		for (; optind < argc; optind++) {
			char *buf, *name, *p;
			buf = strdup(argv[optind]);
			name = buf;
			do {
				if (p = strchr(name, ','))
					*p++ = '\0';
				if (verbose)
					printf("Updating server %s...\n",
						name);
				server_list_add(&servers, name);
				name = p;
			} while (p);
			free(buf);
		}
	} else if (subop == OP_MODIFY) {
		for (; optind < argc; optind++) {
			char *p, tmp[100];
			strcpy(tmp, argv[optind]);
			p = strchr(tmp, '=');
			if (p == NULL) {
				fprintf(stderr,
					"%s: Ignored (invalid format)\n", tmp);
				continue;
			}
			*p++ = '\0';
			if (!server_list_remove(&servers, tmp))
				fprintf(stderr, "%s: not found\n", tmp);
			else {
				if (verbose)
					printf("Modifying server %s...\n", tmp);
				server_list_add(&servers, p);
			}
		}
	} else if (subop == OP_REMOVE) {
		for (; optind < argc; optind++) {
			char *buf, *name, *p;
			buf = strdup(argv[optind]);
			name = buf;
			do {
				if (p = strchr(name, ','))
					*p++ = '\0';
				if (verbose)
					printf("Removing server %s...\n",
						name);
				(void) server_list_remove(&servers, name);
				name = p;
			} while (p);
			free(buf);
		}
	}

	if (subop == OP_DELETE) {
		if (verbose)
			printf("Deleting entry %s...\n", servers.client);
		if (op == OP_LOCAL) {
			remove_local_servers(&servers);
			(void) flush_cache(argv[0]);
		} else
			remove_servers(&servers, domain);
	} else {
		if (op == OP_LOCAL) {
			update_local_servers(&servers);
			(void) flush_cache(argv[0]);
		} else
			update_servers(&servers, domain);
	}
	return (0);
}


void
server_list_init(server_list *servers)
{
	int i;

	servers->options = "";
	servers->client = "";
	servers->count = 0;
	servers->alloc = 5;
	servers->list = (char **)malloc(servers->alloc * sizeof (char *));
	servers->interface = (char **)malloc(servers->alloc * sizeof (char *));
	servers->weight = (int *)malloc(servers->alloc * sizeof (int));
	if (servers->weight == NULL || servers->list == NULL) {
		fprintf(stderr, "out of memory (1)\n");
		exit(1);
	}
	for (i = 0; i < servers->count; i++) {
		servers->interface[i] = NULL;
		servers->list[i] = NULL;
		servers->weight[i] = -1;
	}
	servers->ntoken = 0;
	servers->token_buff = NULL;
}

void
server_list_reinit(server_list *servers)
{
	server_list_clear(servers);
	servers->options = "";
	servers->client = "";
}

void
server_list_clear(server_list *servers)
{
	int i;

	for (i = 0; i < servers->count; i++) {
		if (servers->list[i])
			free(servers->list[i]);
		servers->list[i] = NULL;
		if (servers->interface[i])
			free(servers->interface[i]);
		servers->interface[i] = NULL;
		servers->weight[i] = -1;
	}
	servers->count = 0;
	if (servers->ntoken > 0) {
		servers->ntoken = 0;
		free(servers->token_buff);
		servers->token_buff = NULL;
	}
}

void
server_list_add(server_list *servers, char *s)
{
	int i;
	char *host, *interface;
	int weight;

	if (s == NULL || *s == NULL)
		return;

	if (debug)
		printf("server_list_add: [%d] %s\n", servers->count, s);

	parse_server(s, &host, &interface, &weight);

	for (i = 0; i < servers->count; i++) {
		if (strcasecmp(servers->list[i], host) == 0) {
			if (interface) {
				if (servers->interface[i] &&
					strcasecmp(servers->interface[i],
							interface) == 0) {
					servers->weight[i] = weight;
					return;
				}
			} else {
				if (!servers->interface[i]) {
					/*
					 * For exact match.  Both interfaces
					 * must be NULL.
					 */
					servers->weight[i] = weight;
					return;
				}
			}
		}
	}

	if (servers->count + 1 > servers->alloc) {
		servers->alloc += 5;
		servers->list = (char **)realloc((char *)servers->list,
				servers->alloc * sizeof (char *));
		servers->interface =
				(char **)realloc((char *)servers->interface,
				servers->alloc * sizeof (char *));

		if (servers->list == NULL || servers->interface == NULL) {
			fprintf(stderr, "out of memory (2)\n");
			exit(1);
		}
	}
	servers->list[servers->count] = host;
	servers->interface[servers->count] = interface;
	servers->weight[servers->count] = weight;
	if (debug)
		printf("server_list_add: count=%d l=<%s> i=<%s> w=%d\n",
		servers->count, servers->list[servers->count],
		(servers->interface[servers->count]) ?
			servers->interface[servers->count] : "",
		servers->weight[servers->count]);
	servers->count += 1;
}

int
server_list_remove(server_list *servers, char *s)
{
	int i;
	char *host, *interface;
	int weight;

	if (s == NULL || *s == NULL)
		return (0);

	if (debug)
		printf("server_list_remove: [%d] %s\n", servers->count, s);

	parse_server(s, &host, &interface, &weight);

	for (i = 0; i < servers->count; i++) {
		if (strcasecmp(servers->list[i], host) == 0) {
			/*
			 * If interface is not defined, then it will match
			 * the first client entry.
			 * If interface is defined, then it must match
			 * the interface in the server list.
			 */
			if (interface) {
				if (servers->interface[i] &&
					strcasecmp(servers->interface[i],
							interface) == 0)
					break;
			} else {
				if (!servers->interface[i]) {
					/*
					 * For exact match.  Both interfaces
					 * must be NULL.
					 */
					break;
				}
			}
		}
	}

	if (i >= servers->count)
		return (0);		/* not in list */

	if (servers->list[i]) {
		free(servers->list[i]);
	}
	if (servers->interface[i]) {
		free(servers->interface[i]);
	}
	servers->list[i] = NULL;
	servers->interface[i] = NULL;
	servers->weight[i] = -1;

	for (; i < servers->count - 1; i++) {
		servers->list[i] = servers->list[i+1];
		servers->interface[i] = servers->interface[i+1];
		servers->weight[i] = servers->weight[i+1];
	}

	servers->count -= 1;
	if (debug)
		printf("server_list_remove: removed =%s\n", host);
	return (1);
}

void
server_list_print(server_list *servers, FILE *fp)
{
	int i;
	int len, l;

	if (debug) {
		printf("server_list_print: client=%s", servers->client);
	}
	if (servers->count == 0) {
		char buf[50];
		strcpy(buf, servers->client);
		strcat(buf, "\t");
		if (print_tokens(fp, servers, buf)) {
			if (debug)
				printf("\n");
			fprintf(fp, "\n");
		} else
			fprintf(stderr,
	"This became an empty entry. Removing it from the file\n");
		return;
	}

	fprintf(fp, "%s", servers->client);
	len = strlen(servers->client);
	for (i = 0; i < servers->count; i++) {
		if (i == 0) {
			if (debug)
				printf("\t%s=", PREF_SRVR);
			fprintf(fp, "\t%s=", PREF_SRVR);
			len += strlen(PREF_SRVR) + 1;
		} else {
			if (debug)
				printf(",");
			fprintf(fp, ",");
			l = strlen(servers->list[i]) + 1;
			if (servers->interface[i])
				l += strlen(servers->interface[i]) + 2;
			len += l;
			if (len > 75) {
				if (debug)
					printf("\\\n\t");
				fprintf(fp, "\\\n\t");
				len = l;
			}
		}
		if (debug)
			printf("%s", servers->list[i]);
		fprintf(fp, "%s", servers->list[i]);
		if (servers->interface[i]) {
			if (debug)
				printf("/%s", servers->interface[i]);
			fprintf(fp, "/%s", servers->interface[i]);
		}
		if (servers->weight[i] != -1) {
			if (debug)
				printf("(%d)", servers->weight[i]);
			fprintf(fp, "(%d)", servers->weight[i]);
		}
	}
	if (*servers->options) {
		char *tab;
		if (servers->count > 0)
			tab = " ";
		else
			tab = "\t";
		if (debug)
			printf("%s%s=%s", tab, PREF_TYPE,
					servers->options);
		fprintf(fp, "%s%s=%s", tab, PREF_TYPE,
					servers->options);
	}
	(void) print_tokens(fp, servers, " ");

	if (debug)
		printf("\n");
	fprintf(fp, "\n");

}


void
server_list_dump(char *value, FILE *fp)
{
	int len, n;
	char *p, *pe;
	char buf[100];

	len = strlen(value);
	if (debug)
		printf("server_list_dump: [%d] <%s>\n", len, value);
	p = value;
	for (; len > 80; ) {
		pe = strpbrk(p + 70, " ,\t");
		n = pe - p + 1;
		strncpy(buf, p, n);
		buf[n] = '\0';
		if (debug)
			printf("%s\\\n\t", buf);
		fprintf(fp, "%s\\\n\t", buf);
		len -= n;
		p = pe + 1;
	}
	if (debug)
		printf("%s\n", p);
	fprintf(fp, "%s\n", p);
}



void
parse_server(char *value, char **server, char **interface, int *weight)
{
	char *p, *buf;
	char *s = NULL, *i = NULL;
	int w = -1;

	*weight = -1;
	*server = NULL;
	*interface = NULL;

	if (value == NULL || *value == '\0')
		return;

	buf = strdup(value);
	s = buf;

	while ((p = strpbrk(buf, "/(")) != NULL) {
		switch (*p) {
		    case '/':
			if (i != NULL) {
				fprintf(stderr, "%s : invalid format\n",
						value);
				exit(1);
			}
			*p = '\0';
			i = ++p;
			if (debug)
				printf("parse_server: interface=%s\n", i);
			break;
		    case '(':
			if (w != -1) {
				fprintf(stderr, "%s : invalid format\n",
						value);
				exit(1);
			}
			*p = '\0';
			w = atoi(++p);
			p = strchr(p, ')');
			if (debug)
				printf("parse_server: weight=%d\n", w);
			break;
		}
		buf = p;
	}

	*server = strdup(s);
	if (*server == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	*weight = w;
	if (i != NULL) {
		/* check if the interface specified is a legal IP address */
		struct in_addr	in4;
		struct in6_addr	in6;
		sa_family_t	af;

		af = strchr(i, ':') != 0 ? AF_INET6 : AF_INET;
		if (inet_pton(af, i,
			(af == AF_INET6) ? (void *)&in6 : (void *)&in4) != 1) {
			fprintf(stderr, "%s: invalid interface.\n", i);
			fprintf(stderr,
		"This should be the internet address for the interface.\n");
			exit(1);
		}
		*interface = strdup(i);
		if (*interface == NULL) {
			fprintf(stderr, "out of memory\n");
			exit(1);
		}
	}

	if (debug)
		printf("parse_server: server=%s, weight=%d, interface=%s\n",
			*server, *weight, (*interface)? *interface : "");
}


int
break_tokens(server_list *servers, char *info)
{
	char *p;

	if (debug)
		printf("break_tokens: %s\n", info);

	if (servers->ntoken != 0 && servers->token_buff) {
		free(servers->token_buff);
		servers->token_buff = NULL;
		servers->ntoken = 0;
	}
	servers->token_buff = strdup(info);
	p = servers->token_buff;
	while (*p) {
		/* skip spaces */
		while (*p && isspace(*p))
			p++;
		if (*p == '\0')
			break;
		/* assign token */
		servers->tokens[servers->ntoken] = p;

		/* find the end of token */
		while (*p && !isspace(*p))
			p++;
		if (*p != '\0') {
			*p = '\0';
			p++;
		}
		if (debug)
			printf("break_tokens: [%d]=%s\n", servers->ntoken,
				servers->tokens[servers->ntoken]);
		servers->ntoken++;
	}
	return (servers->ntoken);
}



int
print_tokens(FILE *fp, server_list * servers, char *h)
{
	int i;
	int count = 0;
	int first = 1;

	for (i = 0; i < servers->ntoken; i++) {
		if (servers->tokens[i][0] != '\0') {
			if (debug)
				printf("%s%s", (first) ? h : " ",
						servers->tokens[i]);
			fprintf(fp, "%s%s", (first) ? h : " ",
						servers->tokens[i]);
			first = 0;
			count++;
		}
	}
	return (count);
}



int
parse_info(server_list *servers, char *info, char **hosts, char **options)
{
	char *p1 = NULL;
	int i, n;

	if ((info == NULL) || (*info == '\0')) {
		*hosts = NULL;
		*options = NULL;
		return (1);
	}

	/* parse hosts */
	n = break_tokens(servers, info);
	for (i = 0; i < n; i++) {
		if (debug)
			printf("parse_info: servers->tokens[%d]=%s\n", i,
						servers->tokens[i]);
		if (strncmp(servers->tokens[i], PREF_SRVR,
					strlen(PREF_SRVR)) == 0) {
			/* preferred servers */
			p1 = servers->tokens[i] + strlen(PREF_SRVR);
			if (*p1 != '=' || *hosts != NULL)
				/* invalid format */
				return (0);
			*hosts = strdup(p1 + 1);
			if (*hosts == NULL) {
				fprintf(stderr, "out of memory\n");
				exit(1);
			}
			servers->tokens[i][0] = '\0';
			if (debug)
				printf("parse_info: hosts=%s\n", *hosts);
		} else if (strncmp(servers->tokens[i], PREF_TYPE,
					strlen(PREF_TYPE)) == 0) {
			/* preferred types */
			p1 = servers->tokens[i] + strlen(PREF_TYPE);
			if (*p1 != '=' || *options != NULL)
				/* invalid format */
				return (0);
			*options = strdup(p1 + 1);
			if (*options == NULL) {
				fprintf(stderr, "out of memory\n");
				exit(1);
			}
			servers->tokens[i][0] = '\0';
			if (*options[0] && (strcasecmp(*options, "all") != 0) &&
				(strcasecmp(*options, "pref_only") != 0)) {
				fprintf(stderr, "%s: invalid option.\n",
					*options);
				fprintf(stderr,
			"Valid options are \"all\" and \"pref_only\".\n");
				exit(1);
			}
			if (debug)
				printf("parse_info: options=%s\n", *options);
		}
	}

	return (1);
}


void
parse_preference(server_list *servers, char *client, char *hosts, char *options)
{
	char *value;

	/* parse client */
	servers->client = client;
	if (debug)
		printf("parse_preference: hosts=%s\n", hosts);

	/* parse hosts */
	while (*hosts) {
		value = hosts;
		while (*hosts && !isspace(*hosts) && *hosts != ',')
			hosts++;

		if (hosts && *hosts)
			*hosts++ = '\0';

		while (hosts && *hosts == ',')
			hosts++;

		server_list_add(servers, value);
	}

	/* parse options */
	servers->options = options;
}


char *
get_line(FILE *fp)
{
	char *p;
	int len, cont = 0;
	char *value = NULL;
	char buf[1024];

	while ((p = fgets(buf, sizeof (buf), fp)) != NULL) {
		cont = 0;
		len = strlen(p);
		if ((len - 1 >= 0) && (p[len - 1] == '\n'))
			p[len - 1] = '\0';
		if ((len - 2 >= 0) && (p[len - 2] == '\\')) {
			cont = 1;
			p[len - 2] = '\0';
		}

		if (value == NULL) {
			value = strdup(p);
			if (value == 0) {
				fprintf(stderr, "out of memory (3)\n");
				exit(1);
			}
		} else {
			value = (char *)realloc(value,
				strlen(value) + len + 2);
			if (value == 0) {
				fprintf(stderr, "out of memory (3)\n");
				exit(1);
			}
			while (*p && isspace(*p))
				p++;
			strcat(value, p);
		}
		if (!cont)
			break;  /* complete line */
	}
	if (debug && value != NULL)
		printf("get_line: text=%s\n", value);

	return (value);
}


void
get_local_servers(server_list *servers, char *target, int create)
{
	FILE *fp;
	char *value = NULL;
	char *client = NULL;
	char *hosts = NULL;
	char *option = NULL;
	char *info = NULL;
	char *p = NULL;

	server_list_init(servers);
	fp = fopen(LOCAL_PREF, "r");
	if (fp == NULL) {
		if (create) {
			/*
			 * Allow it to continue...
			 * File will be created in update_local_servers()
			 */
			return;
		} else {
			fprintf(stderr, "%s does not exist\n", LOCAL_PREF);
			exit(1);
		}
	}

	while ((value = get_line(fp)) != NULL) {
		hosts = NULL;
		option = NULL;
		client = value;
		p = strpbrk(value, " \t");
		if (p == NULL) {
			fprintf(stderr, "%s: %s\n", LOCAL_PREF, value);
			fprintf(stderr, "Invalid format\n");
			exit(1);
		}

		*p++ = '\0';
		while (*p && isspace(*p))
			p++;
		info = p;
		if (!parse_info(servers, info, &hosts, &option)) {
			fprintf(stderr,
				"Error found while parsing local file\n");
			fprintf(stderr, "Please see manpage\n");
			exit(1);
		}

		if (client == NULL)
			client = "";
		if (hosts == NULL)
			hosts = "";
		if (option == NULL)
			option = "";

		parse_preference(servers, client, hosts, option);

		if (strcasecmp(client, target) == 0)
			break;

		server_list_reinit(servers);
		free(value);
		value = NULL;
		if (*hosts == '\0')
			free(hosts);
		if (*option == '\0')
			free(option);
	}

	fclose(fp);
}

void
get_servers(server_list *servers, char *domain, char *client, int create)
{
	char *hosts = NULL;
	char *options = NULL;
	char name[NIS_MAXNAMELEN];
	nis_result *res;
	nis_object *obj;
	ulong_t flags = FOLLOW_PATH|FOLLOW_LINKS|EXPAND_NAME;

	entry_found = 0;
	/* first check to see if table exists */
	sprintf(name, "%s.org_dir.%s", TABLE, domain);
	res = nis_lookup(name, flags);
	if (res == 0) {
		fprintf(stderr, "nis_lookup failed\n");
		nis_perror(NIS_NOMEMORY, name);
		exit(1);
	}

	server_list_init(servers);
	if (res->status == NIS_NOTFOUND || res->status == NIS_NOSUCHTABLE) {
		if (create) {
			create_table(name, domain);
			res->status = NIS_SUCCESS;
			return;
		} else {
			nis_perror(res->status, "finding table");
			exit(1);
		}
	}

	obj = res->objects.objects_val;
	if (obj->TA_data.ta_cols.ta_cols_len == 2)
		old_format = 1;	/* need old format for back compat */
	else
		old_format = 0;

	if (old_format)
		sprintf(name,
			"[client=%s],%s.org_dir.%s", client, TABLE, domain);
	else
		sprintf(name,
			"[client=%s,attr=%s],%s.org_dir.%s", client, PREF_SRVR,
			TABLE, domain);
	res = nis_list(name, flags, 0, 0);
	if (res == 0) {
		fprintf(stderr, "nis_list failed\n");
		nis_perror(NIS_NOMEMORY, name);
		exit(1);
	}
	if (res->status == NIS_NOTFOUND) {
		return;
	}

	if (res->status != NIS_SUCCESS) {
		nis_perror(res->status, name);
		exit(1);
	}

	entry_found = 1;
	obj = res->objects.objects_val;
	client = ENTRY_VAL(obj, 0);
	if (old_format) {
		char *info = ENTRY_VAL(obj, 1);
		if (!parse_info(servers, info, &hosts, &options)) {
			printf(
		    "Error found while parsing the table information\n");
			printf("Please see manpage.\n");
			exit(1);
		}
	} else {
		hosts = ENTRY_VAL(obj, 2);
		options = ENTRY_VAL(obj, 3);
	}

	if (client == NULL)
		client = "";
	if (hosts == NULL)
		hosts = "";
	if (options == NULL)
		options = "";

	parse_preference(servers, client, hosts, options);
}

void
remove_local_servers(server_list *target)
{
	FILE *fpin;
	FILE *fpout;
	char *value;
	char *client;
	char *p;

	fpout = fopen(LOCAL_TMP, "w");
	if (fpout == NULL) {
		fprintf(stderr, "can't open %s for output\n", LOCAL_TMP);
		exit(1);
	}

	fpin = fopen(LOCAL_PREF, "r");
	if (fpin != NULL) {
		while ((value = get_line(fpin)) != NULL) {
			client = value;
			p = strpbrk(value, " \t");
			if (p == NULL) {
				fprintf(stderr, "%s: %s\n", LOCAL_PREF, value);
				fprintf(stderr, "Invalid format\n");
				exit(1);
			}
			if (strncasecmp(client, target->client, p - value)
								!= 0) {
				/* skip this line */
				server_list_dump(value, fpout);
			}
		}
		fclose(fpin);
	} else {
		/* local file does not exist */
		fclose(fpout);
		unlink(LOCAL_TMP);
		fprintf(stderr, "%s does not exist\n", LOCAL_PREF);
		exit(1);
	}
	if (fclose(fpout) != 0 || rename(LOCAL_TMP, LOCAL_PREF) == -1) {
		unlink(LOCAL_TMP);
		perror(LOCAL_TMP);
		exit(1);
	}
}

void
remove_servers(server_list *servers, char *domain)
{
	char name[NIS_MAXNAMELEN];
	nis_result *res;
	ulong_t flags = FOLLOW_PATH|FOLLOW_LINKS|EXPAND_NAME;

	if (debug)
		printf("remove_servers: removing %s\n", servers->client);
	if (old_format)
		sprintf(name, "[client=%s],%s.org_dir.%s",
			servers->client, TABLE, domain);
	else
		sprintf(name, "[client=%s,attr=%s],%s.org_dir.%s",
			servers->client, PREF_SRVR, TABLE, domain);
	res = nis_remove_entry(name, NULL, flags);
	if (res == 0) {
		fprintf(stderr, "nis_remove_entry failed\n");
		nis_perror(NIS_NOMEMORY, name);
		exit(1);
	}
	if (res->status == NIS_NOTFOUND) {
		return;
	}
	if (res->status != NIS_SUCCESS) {
		nis_perror(res->status, name);
		exit(1);
	}
}

void
update_local_servers(server_list *target)
{
	FILE *fpin;
	FILE *fpout;
	char *value = NULL;
	char *client;
	char *p;

	fpout = fopen(LOCAL_TMP, "w");
	if (fpout == NULL) {
		fprintf(stderr, "can't open %s for output\n", LOCAL_TMP);
		exit(1);
	}

	fpin = fopen(LOCAL_PREF, "r");
	if (fpin != NULL) {
		while ((value = get_line(fpin)) != NULL) {
			client = value;
			p = strpbrk(value, " \t");
			if (p == NULL) {
				fprintf(stderr, "%s: %s\n", LOCAL_PREF, value);
				fprintf(stderr, "Invalid format\n");
				exit(1);
			}
			if (strncasecmp(client, target->client, p - value)
								!= 0) {
				/* skip this line */
				server_list_dump(value, fpout);
			}
		}
		fclose(fpin);
	}

	server_list_print(target, fpout);

	if (fclose(fpout) != 0 || rename(LOCAL_TMP, LOCAL_PREF) == -1) {
		unlink(LOCAL_TMP);
		perror(LOCAL_TMP);
		exit(1);
	}
}

void
update_servers(server_list *servers, char *domain)
{
	int i;
	int len = 0, bufsize = 1000;
	char *buf, *optbuf;
	entry_col cols[NCOLS];
	nis_object eobj;
	nis_result *res;
	char table[NIS_MAXNAMELEN];
	char tmp[10], lbuf[100];
	int first = 1;

	if (old_format)
		convert_old2new(servers, domain);

	buf = (char *)malloc(bufsize * sizeof (char));
	if (buf == NULL) {
		fprintf(stderr, "out of memory (4)\n");
		exit(1);
	}
	optbuf = (char *)malloc(bufsize * sizeof (char));
	if (optbuf == NULL) {
		fprintf(stderr, "out of memory (4)\n");
		exit(1);
	}

	buf[0] = optbuf[0] = '\0';
	if (servers->count > 0) {
		if (debug)
			printf("update_servers:\n");
		for (i = 0; i < servers->count; i++) {
			if (i != 0) {
				lbuf[0] = ',';
				lbuf[1] = '\0';
			} else
				lbuf[0] = '\0';
			if (debug)
				printf("adding %d:  %s\n", i, servers->list[i]);
			strcat(lbuf, servers->list[i]);
			if (servers->interface[i]) {
				if (debug)
					printf("/%s", servers->interface[i]);
				strcat(lbuf, "/");
				strcat(lbuf, servers->interface[i]);
			}
			if (servers->weight[i] != -1) {
				if (debug)
					printf("(%d)", servers->weight[i]);
				sprintf(tmp, "(%d)", servers->weight[i]);
				strcat(lbuf, tmp);
			}
			len += strlen(lbuf);
			if (len  > bufsize) {
				bufsize += 1000;
				buf = (char *)realloc(buf, bufsize *
					sizeof (char));
			}
			strcat(buf, lbuf);
			first = 0;
		}
	}

	bufsize = 1000;
	len = 0;
	if (servers->options && *(servers->options)) {
		lbuf[0] = '\0';
		if (debug)
			printf("update_servers: pref_type = %s\n",
					servers->options);
		strcat(lbuf, servers->options);
		len += strlen(lbuf);
		if (len  > bufsize) {
			bufsize += 50;
			optbuf = (char *)realloc
				(optbuf, bufsize * sizeof (char));
		}
		strcat(optbuf, lbuf);
		first = 0;
	}

	if (strlen(buf) == 0) {
		if (entry_found) {
			fprintf(stderr,
		"This became an empty entry. Removing it from the table\n");
			remove_servers(servers, domain);
		}
		exit(0);
	}

	if (debug)
		printf("info=%s, %s\n", buf, optbuf);

	cols[0].ec_flags = 0;
	cols[0].ec_value.ec_value_val = servers->client;
	cols[0].ec_value.ec_value_len = strlen(servers->client) + 1;

	cols[1].ec_flags = 0;
	cols[1].ec_value.ec_value_val = PREF_SRVR;
	cols[1].ec_value.ec_value_len = strlen(PREF_SRVR) + 1;

	cols[2].ec_flags = 0;
	cols[2].ec_value.ec_value_val = buf;
	cols[2].ec_value.ec_value_len = strlen(buf) + 1;

	cols[3].ec_flags = 0;
	cols[3].ec_value.ec_value_val = optbuf;
	cols[3].ec_value.ec_value_len = strlen(optbuf) + 1;

	eobj = nis_default_obj;
	eobj.zo_data.zo_type = ENTRY_OBJ;
	eobj.EN_data.en_type = TABLE_TYPE;
	eobj.EN_data.en_cols.en_cols_len = NCOLS;
	eobj.EN_data.en_cols.en_cols_val = cols;

	sprintf(table, "%s.org_dir.%s", TABLE, domain);
	if (debug)
		printf("calling nis_add_entry...");
	res = nis_add_entry(table, &eobj, ADD_OVERWRITE);
	if (debug)
		printf("Done\n");
	if (res == 0) {
		fprintf(stderr, "nis_add_entry failed\n");
		nis_perror(NIS_NOMEMORY, table);
		exit(1);
	} else if (res->status != NIS_SUCCESS) {
		nis_perror(res->status, table);
		exit(1);
	}
}

/*
 * table_col cols[] = {
 * 	"client", TA_SEARCHABLE, 0,
 * 	"servers", 0, 0,
 * 	"options", 0, 0,
 * };
 */

void
create_table(char *name, char *domain)
{
	nis_object tobj;
	nis_result *res;
	int ncols = NCOLS;
	table_col cols[NCOLS];
	char gname[NIS_MAXNAMELEN];

	if (debug)
		printf("creating table\n");
	cols[0].tc_name = "client";
	cols[0].tc_flags = TA_SEARCHABLE | TA_CASE;
	cols[0].tc_rights = nis_default_obj.zo_access;

	cols[1].tc_name = "attr";
	cols[1].tc_flags = TA_SEARCHABLE | TA_CASE;
	cols[1].tc_rights = nis_default_obj.zo_access;

	cols[2].tc_name = "info";
	cols[2].tc_flags = 0;
	cols[2].tc_rights = nis_default_obj.zo_access;

	cols[3].tc_name = "flags";
	cols[3].tc_flags = 0;
	cols[3].tc_rights = nis_default_obj.zo_access;

	tobj = nis_default_obj;
	sprintf(gname, "admin.%s", domain);
	tobj.zo_group = gname;
	tobj.zo_access |= ((NIS_READ_ACC | NIS_MODIFY_ACC | NIS_CREATE_ACC |
			    NIS_DESTROY_ACC) << 8);
	tobj.zo_data.zo_type = TABLE_OBJ;
	tobj.TA_data.ta_type = TABLE_TYPE;
	tobj.TA_data.ta_maxcol = ncols;
	tobj.TA_data.ta_sep = ' ';
	tobj.TA_data.ta_path = "";
	tobj.TA_data.ta_cols.ta_cols_len = ncols;
	tobj.TA_data.ta_cols.ta_cols_val = cols;
	if (debug)
		printf("calling nis_add %s\n", name);
	res = nis_add(name, &tobj);
	if (res == NULL) {
		fprintf(stderr, "nis_add failed\n");
		nis_perror(NIS_NOMEMORY, name);
		exit(1);
	}
	if (res->status != NIS_SUCCESS) {
		nis_perror(res->status, name);
		exit(1);
	}

}

void
convert_old2new(server_list *servers, char *domain)
{
	nis_result *old_res, *res;
	char name[NIS_MAXNAMELEN];
	nis_object eobj;
	int i;
	ulong_t flags = FOLLOW_PATH|FOLLOW_LINKS|EXPAND_NAME;

	if (debug)
		printf("Converting table\n");
	/* dump old table */
	if (debug)
		printf("dumping old table...");
	sprintf(name, "%s.org_dir.%s", TABLE, domain);
	old_res = nis_list(name, flags, 0, 0);
	if (old_res == 0) {
		fprintf(stderr, "failed to convert %s to new format\n",
			TABLE);
		fprintf(stderr, "while dumping table\n");
		fprintf(stderr, "nis_list failed\n");
		nis_perror(NIS_NOMEMORY, name);
		exit(1);
	}
	if (old_res->status != NIS_SUCCESS) {
		fprintf(stderr, "failed to convert %s to new format\n",
			TABLE);
		fprintf(stderr, "while dumping table\n");
		nis_perror(old_res->status, name);
		exit(1);
	}
	if (debug)
		printf("done\n");

	/* delete old table */
	if (debug)
		printf("cleaning out old table...");
	res = nis_remove_entry(name, NULL, flags|REM_MULTIPLE);
	if (res == 0) {
		fprintf(stderr, "failed to convert %s to new format\n",
			TABLE);
		fprintf(stderr, "while cleaning out table\n");
		fprintf(stderr, "nis_remove_entry failed\n");
		nis_perror(NIS_NOMEMORY, name);
		exit(1);
	}
	if (res->status != NIS_SUCCESS) {
		fprintf(stderr, "failed to convert %s to new format\n",
			TABLE);
		fprintf(stderr, "while cleaning out table\n");
		nis_perror(res->status, name);
		exit(1);
	}
	if (debug)
		printf("done\n");
	if (debug)
		printf("removing old table...");
	res = nis_remove(name, NULL);
	if (res == 0) {
		fprintf(stderr, "failed to convert %s to new format\n",
			TABLE);
		fprintf(stderr, "while deleting table\n");
		fprintf(stderr, "nis_remove failed\n");
		nis_perror(NIS_NOMEMORY, name);
		exit(1);
	}
	if (res->status != NIS_SUCCESS) {
		fprintf(stderr, "failed to convert %s to new format\n",
			TABLE);
		fprintf(stderr, "while deleting table\n");
		nis_perror(res->status, name);
		exit(1);
	}
	if (debug)
		printf("done\n");

	/* create new table */
	create_table(name, domain);

	/* reload table with info from old table */
	if (debug)
		printf("reloading table in new format\n");
	eobj = nis_default_obj;
	eobj.zo_data.zo_type = ENTRY_OBJ;
	eobj.EN_data.en_type = TABLE_TYPE;
	eobj.EN_data.en_cols.en_cols_len = NCOLS;

	for (i = 0; i < old_res->objects.objects_len; i++) {
		nis_object *obj;
		char *hosts, *options;
		entry_col cols[NCOLS];

		hosts = options = NULL;
		obj = &(old_res->objects.objects_val[i]);
		/* copy client column */
		cols[0].ec_flags = 0;
		cols[0].ec_value.ec_value_len = ENTRY_LEN(obj, 0);
		cols[0].ec_value.ec_value_val = ENTRY_VAL(obj, 0);

		/* fill in pref_srvr column */
		cols[1].ec_flags = 0;
		cols[1].ec_value.ec_value_val = PREF_SRVR;
		cols[1].ec_value.ec_value_len = strlen(PREF_SRVR) + 1;

		/* extract servers and options */
		parse_info(servers, ENTRY_VAL(obj, 1), &hosts, &options);
		if (hosts == NULL)
			hosts = "";
		if (options == NULL)
			options = "";
		if (debug) {
			printf("convert_old2new: hosts = %s\n", hosts);
			printf("convert_old2new: options = %s\n", options);
		}

		/* fill in servers column */
		cols[2].ec_flags = 0;
		cols[2].ec_value.ec_value_val = hosts;
		cols[2].ec_value.ec_value_len = strlen(hosts) + 1;

		/* fill in options column */
		cols[3].ec_flags = 0;
		cols[3].ec_value.ec_value_val = options;
		cols[3].ec_value.ec_value_len = strlen(options) + 1;

		/* add the new entry */
		eobj.EN_data.en_cols.en_cols_val = cols;
		if (debug)
			printf("convert_old2new: calling nis_add_entry...");
		res = nis_add_entry(name, &eobj, ADD_OVERWRITE);
		if (debug)
			printf("Done\n");
		if (res == 0) {
			fprintf(stderr, "failed to convert %s to new format\n",
				TABLE);
			fprintf(stderr, "while repopulating table\n");
			fprintf(stderr, "nis_add_entry failed\n");
			nis_perror(NIS_NOMEMORY, TABLE);
			exit(1);
		} else if (res->status != NIS_SUCCESS) {
			fprintf(stderr, "failed to convert %s to new format\n",
				TABLE);
			fprintf(stderr, "while repopulating table\n");
			nis_perror(res->status, TABLE);
			exit(1);
		}
	}
	nis_freeresult(old_res);
	if (debug)
		printf("finished convert_old2new\n");
}

void
print_info(char *client, char *hosts, char *option)
{
	static int first = 1;

	if (!(client && *client && hosts && *hosts && option))
		return;

	if (first) {
		fprintf(stdout, "client\tinformation\n");
		fprintf(stdout, "------\t-----------\n");
		first = 0;
	}
	fprintf(stdout, "%s\t%s=%s", client, PREF_SRVR, hosts);
	if (*option)
		fprintf(stdout, "\t%s=%s", PREF_TYPE, option);
	fprintf(stdout, "\n");
}

void
print_local_servers(server_list *servers, char *target)
{
	FILE *fp;
	char *value = NULL;
	char *client = NULL;
	char *hosts = NULL;
	char *option = NULL;
	char *info = NULL;
	char *p = NULL;

	fp = fopen(LOCAL_PREF, "r");
	if (fp == NULL)
		return;

	server_list_init(servers);
	while ((value = get_line(fp)) != NULL) {
		hosts = NULL;
		option = NULL;
		client = value;
		p = strpbrk(value, " \t");
		if (p == NULL) {
			fprintf(stderr, "%s: %s\n", LOCAL_PREF, value);
			fprintf(stderr, "Invalid format\n");
			exit(1);
		}

		*p++ = '\0';
		while (*p && isspace(*p))
			p++;
		info = p;
		if (!parse_info(servers, info, &hosts, &option)) {
			fprintf(stderr,
				"Error found while parsing local file\n");
			fprintf(stderr, "Please see manpage\n");
			exit(1);
		}

		if (client == NULL)
			client = "";
		if (hosts == NULL)
			hosts = "";
		if (option == NULL)
			option = "";

		if (target && *target) {
			if (strcasecmp(client, target) == 0) {
				print_info(client, hosts, option);
				fclose(fp);
				return;
			}
		} else {
			/* list all entries */
			print_info(client, hosts, option);
		}

		server_list_reinit(servers);
		free(value);
		value = NULL;
		if (*hosts == '\0')
			free(hosts);
		if (*option == '\0')
			free(option);
	}

	fclose(fp);
}


int
print_line(char *tab, nis_object *ent, void *udata)
{
	static int first = 1;
	char *hosts = NULL, *client = NULL, *options = NULL, *info = NULL;
	server_list servers;

	server_list_init(&servers);
	client = ENTRY_VAL(ent, 0);
	if (old_format) {
		info = ENTRY_VAL(ent, 1);
		if (!parse_info(&servers, info, &hosts, &options)) {
			printf(
		    "Error found while parsing the table information\n");
			printf("Please see manpage.\n");
			exit(1);
		}
	} else {
		hosts = ENTRY_VAL(ent, 2);
		options = ENTRY_VAL(ent, 3);
	}

	if (!(client && *client && hosts && *hosts))
		return (0);

	if (first) {
		fprintf(stdout, "client\t\tinformation\n");
		fprintf(stdout, "------\t\t-----------\n");
		first = 0;
	}
	fprintf(stdout, "%s\t%s=%s", client, PREF_SRVR, hosts);
	if (options && *options)
		fprintf(stdout, "\t%s=%s", PREF_TYPE, options);
	fprintf(stdout, "\n");
	return (0);
}


void
print_servers(server_list *servers, char *domain, char *client)
{
	char *hosts = NULL;
	char *options = NULL;
	char *info = NULL;
	char name[NIS_MAXNAMELEN];
	nis_result *res;
	nis_object *obj;
	ulong_t flags = FOLLOW_PATH|FOLLOW_LINKS|EXPAND_NAME;

	/* first check to see if table exists */
	sprintf(name, "%s.org_dir.%s", TABLE, domain);
	res = nis_lookup(name, flags);
	if (res == 0 || res->status != NIS_SUCCESS)
		return;

	obj = res->objects.objects_val;
	if (obj->TA_data.ta_cols.ta_cols_len == 2)
		old_format = 1;	/* need old format for back compat */
	else
		old_format = 0;

	if (client && *client) {
		server_list_init(servers);
		/* specific client lookcup */
		if (old_format)
			sprintf(name, "[client=%s],%s.org_dir.%s",
				client, TABLE, domain);
		else
			sprintf(name, "[client=%s,attr=%s],%s.org_dir.%s",
				client, PREF_SRVR, TABLE, domain);
		res = nis_list(name, flags, 0, 0);
		if (res == 0) {
			fprintf(stderr, "nis_list failed\n");
			nis_perror(NIS_NOMEMORY, name);
			exit(1);
		}
		if (res->status == NIS_NOTFOUND) {
			return;
		} else if (res->status != NIS_SUCCESS) {
			nis_perror(res->status, name);
			exit(1);
		}

		obj = res->objects.objects_val;
		client = ENTRY_VAL(obj, 0);
		if (old_format) {
			info = ENTRY_VAL(obj, 1);
			if (!parse_info(servers, info, &hosts, &options)) {
				printf(
		    "Error found while parsing the table information\n");
				printf("Please see manpage.\n");
				exit(1);
			}
		} else {
			hosts = ENTRY_VAL(obj, 2);
			options = ENTRY_VAL(obj, 3);
		}

		if (client == NULL)
			client = "";
		if (hosts == NULL)
			hosts = "";
		if (options == NULL)
			options = "";

		print_info(client, hosts, options);
		return;
	}

	/* list all entries */
	sprintf(name, "%s.org_dir.%s", TABLE, domain);

	res = nis_list(name, flags, print_line, 0);
	if ((res->status != NIS_CBRESULTS) && (res->status != NIS_NOTFOUND)) {
		nis_perror(res->status, "can't list table");
		exit(1);
	}

}

/*
 * This routine sends a signal to the local Cache manager to flush the
 * internal server list.
 * Return values:
 *	0: signal sent sucessfully
 *	1: signal failed
 */
int
flush_cache(char *prog)
{

	char *cmd = "kill -HUP `ps -e |"
		" awk '{if ($4 == \"nis_cach\") printf(\"%d \", $1);}'`"
		" 2> /dev/null";

	if (system(cmd) != 0) {
		/* error or nis_cachemgr not running */
		fprintf(stderr,
			"%s: Unable to flush the cache manager.", prog);
		fprintf(stderr,
			"\tThe cache manager is possibly down.");
		return (1);
	}
	return (0);
}
