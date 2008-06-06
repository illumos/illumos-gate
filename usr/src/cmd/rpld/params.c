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

#include <stdio.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <poll.h>
#include <errno.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <syslog.h>
#include <net/if.h>
#include "rpld.h"
#include "dluser.h"

#define	MAXIFS		256

extern char	configFile[];
extern int	debugLevel;
extern int	debugDest;
extern int	maxClients;
extern int	backGround;
extern char	logFile[];
extern unsigned long	delayGran;
extern unsigned long	startDelay;
extern int	frameSize;
extern char	ifName[];
extern char	debugmsg[];
extern FILE	*log_str;
extern int	ifUnit;
extern int	ppanum;
extern int	need_llc;

void usage(void);
void getdevice(uchar_t *, uchar_t *);

int
parseargs(int argc, char *argv[], char *envp[])
{
	int	c;
	int	err = 0;
	int	ip_fd;
	int	numifs;
	struct 	ifreq	*reqbuf;
	struct	ifreq	*ifr;
	char	*device;
	int	unit;
	struct	ifconf	ifconf;
	unsigned	bufsize;
	char	devbuf[MAXPATHLEN];
	int	aflag = 0;
	int	curr_ppa = 0;
	extern	char *optarg;
	extern	int   optind;
	extern	int   opterr;
	int	n;
	int	more = 0;
	char	_ifName[MAXPATHLEN] = "";
	int	_ifUnit = 0;
	int	_need_llc;

	opterr = 0;

	/*
	 * Expects at least 2 arguments: program name and the network
	 * interface name, or the program name with -a option.
	 */
	if (argc < 2) {
		usage();
		return (-1);
	}

	debugLevel = MSG_ERROR_1;	/* at least when it fails, we know */
	debugDest = DEST_CONSOLE;	/* why at the console */

	/*
	 * Check if either the -a option or a /dev/deviceN path is specified.
	 * At the same time look for an alternate config file.
	 * After this checking, optind is positioned to the next thing on
	 * the command line after all the options.
	 */
	optind = 1;
	while ((c = getopt(argc, argv, "af:d:D:M:b:l:s:g:z:")) != -1) {
		switch (c) {
		case 'a':
			aflag = 1;
			break;
		case 'f': 	/* alternate config file */
			if (strlcpy(configFile, optarg,
			    MAXPATHLEN) >= MAXPATHLEN) {
				printf("Alternate config file too long\n");
				return (-1);
			}
			break;
		case '?':
			usage();
			return (-1);
		}
	}

	if (!aflag) {
		if ((argv[optind] == NULL) || (argv[optind][0] == '\0')) {
			/* neither -a nor device name is specified */
			usage();
			return (-1);
		} else {
			/* potentially a correct device name is specified */
			int	i;

			if (strlcpy(ifName, argv[optind],
			    MAXPATHLEN) >= MAXPATHLEN) {
				printf("Network interface name too long\n");
				return (-1);
			}

			/* must have a PPA number */
			i = strlen(ifName) - 1;
			if ((ifName[i] < '0') || (ifName[i] > '9')) {
				usage();
				return (-1);
			}

			/* extract the PPA number and device path */
			while (i) {
				if ((ifName[i] < '0') || (ifName[i] > '9'))
					break;
				else
					i--;
			}

			if (i) {
				ifUnit = atoi(&ifName[i+1]);
				ifName[i+1] = '\0';
			} else {
				usage();
				return (-1);
			}
		}
	} else {
		/* cannot have both -a and device */
		if (argv[optind] && argv[optind][0]) {
			usage();
			return (-1);
		}
	}


	/* Read the configuration file now */
#define	NOTRUNNING	0
	readconfig(NOTRUNNING);

	/* Now override any parameters with command line options */
	optind = 1;
	while ((c = getopt(argc, argv, "af:d:D:M:b:l:s:g:z:")) != -1) {
		switch (c) {
		case 'd':	/* debug level */
			debugLevel = atoi(optarg);
			break;
		case 'D':	/* debug output destination */
			debugDest = atoi(optarg);
			break;
		case 'M':	/* max clients */
			maxClients = atoi(optarg);
			break;
		case 'b':	/* background mode */
			backGround = atoi(optarg);
			break;
		case 'l':	/* alt. log file name */
			if (strlcpy(logFile, optarg,
			    MAXPATHLEN) >= MAXPATHLEN) {
				printf("Alternate log file too long\n");
				return (-1);
			}
			break;
		case 's':	/* start delay count */
			startDelay = atol(optarg);
			break;
		case 'g':	/* granularity */
			delayGran = atol(optarg);
			break;
		case 'z':	/* frame size */
			frameSize = atoi(optarg);
			break;
		case '?':
			err++;
		}
	}

	if (debugLevel && (open_debug_dest() < 0)) {
		printf("Cannot open specified debug destination\n");
		return (-1);
	}

	/* debugLevel and debugDest finally has meaning now */

	if (debugLevel < MSG_NONE || debugLevel > MSG_ALWAYS) {
		sprintf(debugmsg,
		    "Debug level out of range.  Legal range is 0-9.\n");
		senddebug(MSG_FATAL);
		err++;
	}

	if (backGround && debugDest == DEST_CONSOLE) {
		if (debugLevel >= MSG_FATAL) {
			sprintf(debugmsg, "Cannot run in background while "
			    "sending debug information to console.\n");
			senddebug(MSG_FATAL);
		}
		err++;
	}

	if ((long)delayGran < 0) {
		if (debugLevel >= MSG_FATAL) {
			sprintf(debugmsg,
			    "Cannot have negative delay granularity.\n");
			senddebug(MSG_FATAL);
		}
		err++;
	}

	if (err) {
		usage();
		return (-1);
	}

	if (aflag) {
		/*
		 * Find all the network interfaces and start a server on
		 * each of them.
		 */
		if ((ip_fd = open("/dev/ip", 0)) < 0) {
			if (debugLevel >= MSG_FATAL) {
				sprintf(debugmsg,
				    "Failed to open IP, -a option failed.\n");
				senddebug(MSG_FATAL);
			}
			return (-1);
		}

		/* ask IP for the list of configured interfaces */
#ifdef SIOCGIFNUM
		if (ioctl(ip_fd, SIOCGIFNUM, (char *)&numifs) < 0) {
			if (debugLevel >= MSG_FATAL) {
				sprintf(debugmsg,
				    "Failed ioctl(SIOCGIFNUM)\n");
				senddebug(MSG_FATAL);
			}
			close(ip_fd);
			return (-1);
		}
#else
		numifs = MAXIFS;
#endif
		bufsize = numifs*sizeof (struct ifreq);
		reqbuf = (struct ifreq *)malloc(bufsize);
		if (reqbuf == NULL) {
			if (debugLevel >= MSG_FATAL) {
				sprintf(debugmsg, "Failed to allocate memory "
				"to look up configured interfaces in IP.\n");
				senddebug(MSG_FATAL);
				sprintf(debugmsg, "-a option failed.\n");
				senddebug(MSG_FATAL);
			}
			close(ip_fd);
			return (-1);
		}
		ifconf.ifc_len = bufsize;
		ifconf.ifc_buf = (caddr_t)reqbuf;
		if (ioctl(ip_fd, SIOCGIFCONF, (char *)&ifconf) < 0) {
			if (debugLevel >= MSG_FATAL) {
				sprintf(debugmsg,
				    "SIOCGIFCONF failed, -a option failed.\n");
				senddebug(MSG_FATAL);
			}
			close(ip_fd);
			free(reqbuf);
			return (-1);
		}

		/*
		 * Fork and pass discovered interface name through the
		 * global variables ifName and ifUnit
		 */
		for (ifr = ifconf.ifc_req; ifconf.ifc_len > 0;
		    ifr++, ifconf.ifc_len -= sizeof (struct ifreq)) {
			if (ioctl(ip_fd, SIOCGIFFLAGS, (char *)ifr) < 0) {
				if (debugLevel >= MSG_FATAL) {
					sprintf(debugmsg,
					    "ioctl SIOCGIFFLAGS failed.\n");
					senddebug(MSG_FATAL);
				}
				free(reqbuf);
				close(ip_fd);
				return (-1);
			}
			if ((ifr->ifr_flags & IFF_LOOPBACK) ||
			    !(ifr->ifr_flags & IFF_BROADCAST) ||
			    !(ifr->ifr_flags & IFF_UP) ||
			    (ifr->ifr_flags & IFF_NOARP) ||
			    (ifr->ifr_flags & IFF_POINTOPOINT))
				continue;

			if (strchr(ifr->ifr_name, ':') != NULL)
				/*
				 * rpld only cares about DLPI devices and only
				 * the physical IP interfaces correspond to
				 * a DLPI device.
				 */
				continue;

			/*
			 * check if this interface needs LLC and if so,
			 * remember which PPA in LLC to use.  Assume that
			 * only llc1 is used.
			 */
			(void) strlcpy(devbuf, "/dev/", MAXPATHLEN);
			getdevice((uchar_t *)ifr->ifr_name,
			    (uchar_t *)&devbuf[5]);
			(void) strlcpy(ifName, devbuf, MAXPATHLEN);
			ifUnit = unit = getunit(ifr->ifr_name);
			if (debugLevel >= MSG_INFO_1) {
				sprintf(debugmsg, "found interface = %s%d\n",
							ifName, ifUnit);
				senddebug(MSG_INFO_1);
			}

			if (llc_is_needed(ifName, ifUnit)) {
				need_llc = 1;
			} else
				need_llc = 0;

			if (more) {
				switch (fork()) {
				case -1:	/* failure */
					free(reqbuf);
					close(ip_fd);
					if (debugLevel >= MSG_FATAL) {
						sprintf(debugmsg, "Fork() "
						    "failed to run rpld on "
						    "interface %s%d\n", ifName,
						    ifUnit);
						senddebug(MSG_FATAL);
					}
					return (-1);
					break;
				case 0: 	/* child */
					free(reqbuf);
					close(ip_fd);
					if (debugLevel >= MSG_INFO_2)
						dumpparams();
					return (0);
				default:	/* parent */
					break;
				}

				/* prepare for next ppanum for LLC */
				ppanum++;
			}

			/*
			 * retain the first found interface for the
			 * parent process
			 */
			if (!more) {
				more = 1;
				(void) strlcpy(_ifName, ifName, MAXPATHLEN);
				_ifUnit = ifUnit;
				_need_llc = need_llc;
			}
		} /* for */

		free(reqbuf);
		close(ip_fd);

	} /* aflag */

	/* parent always use ppanum of 0 */
	ppanum = 0;
	(void) strlcpy(ifName, _ifName, MAXPATHLEN);
	ifUnit = _ifUnit;
	need_llc = _need_llc;

	if (debugLevel >= MSG_INFO_2)
		dumpparams();

	return (0);
}

/* returns 1 if need LLC, 0 if not, -1 if error occurs */
int
llc_is_needed(char *devname, int ifUnit)
{
	int		if_fd;
	dl_info_t	if_info;
	struct strbuf	ctl;
	char		resultbuf[MAXPRIMSZ];
	union DL_primitives *dlp = (union DL_primitives *)resultbuf;
	unsigned char	node_address[6];
	int		flags = 0;

	/* open this device */
	if ((if_fd = dl_open(ifName, O_RDWR, NULL)) < 0) {
		return (-1);
	}

	/* query information about this device */
	if (dl_info(if_fd, &if_info) < 0) {
		dl_close(if_fd);
		return (-1);
	}

	/*
	 * Check if we need to use the LLC module.  This is needed if:
	 * 1. a DL_INFO_REQ determines that the device is of type DL_ETHER
	 * 2. an attempt to do a DL_TEST_REQ to yourself does not return
	 *    an error ack for non-DL_ETHER devices.
	 */
	if (if_info.mac_type == DLTYPE_ETHER) {
		dl_close(if_fd);
		return (1);
	} else {
		struct pollfd pfd;
		int rc;

		if (debugLevel >= MSG_INFO_1) {
			sprintf(debugmsg,
			    "Need to determine if LLC driver is needed\n");
			senddebug(MSG_INFO_1);
		}

		/* attach to ifUnit */
		if (dl_attach(if_fd, ifUnit) < 0) {
			dl_close(if_fd);
			return (-1);
		}

		/* find out own node address for use in test */
		if (dlpi_get_phys(if_fd, node_address) != 0) {
			dl_close(if_fd);
			return (-1);
		}

		dlp->test_req.dl_primitive = DL_TEST_REQ;
		dlp->test_req.dl_flag = 0;
		dlp->test_req.dl_dest_addr_length = 7;
		dlp->test_req.dl_dest_addr_offset = DL_TEST_REQ_SIZE;
		memcpy(&resultbuf[DL_TEST_REQ_SIZE], node_address, 6);
		resultbuf[DL_TEST_REQ_SIZE+6] = (unsigned char)0xfc;

		ctl.len = DL_TEST_REQ + 7;
		ctl.buf = resultbuf;
		if (putmsg(if_fd, &ctl, NULL, 0) < 0) {
			if (debugLevel >= MSG_FATAL) {
				sprintf(debugmsg,
			"putmsg() failed in DL_TEST_REQ, errno = %d\n", errno);
				senddebug(MSG_FATAL);
			}
			dl_close(if_fd);
			return (-1);
		}

		pfd.fd = if_fd;
		pfd.events = POLLIN | POLLPRI | POLLERR;
		rc = poll(&pfd, 1, 10); /* 10 millisec timeout */
		if (rc == 0) {
			/* no reply message, assume LLC is available */
		} else if (rc > 0) {
			ctl.maxlen = MAXPRIMSZ;
			ctl.buf = resultbuf;
			if (getmsg(if_fd, &ctl, NULL, &flags) < 0) {
				if (debugLevel >= MSG_FATAL) {
					sprintf(debugmsg,
			"getmsg() failed in DL_TEST_REQ, errno = %d\n", errno);
					senddebug(MSG_FATAL);
				}
				dl_close(if_fd);
				return (-1);
			}
			if (dlp->dl_primitive == DL_ERROR_ACK) {
				dl_close(if_fd);
				return (1);
			}
		} else {
			/* error occurs */
			dl_close(if_fd);
			return (-1);
		}
	}
	dl_close(if_fd);
	return (0);
}

/*
 * Read the configuration parameters in the config file.
 * Different actions are required if the server is already running or not
 */
int
readconfig(int running)
{
	FILE	*fstr;
	int	i, n;
	char	line[80];
	int	lineno = 0;
	int	done = 0;
	int	debugDestChange;
	unsigned int newDebugDest;
	int	logFileChange;
	char	newLogFile[MAXPATHLEN];

	if ((fstr = fopen(configFile, "r")) == NULL) {
		if (running) {
			if (debugLevel >= MSG_ERROR_1) {
				sprintf(debugmsg,
				    "Cannot open config file %s\n", configFile);
				senddebug(MSG_ERROR_1);
			}
		} else {
			printf("Cannot open config file %s.\n", configFile);
		}

		/*
		 * If already running, do not fall back to use the default
		 * config file.
		 */
		if (running)
			return (0);

		/* Try to use default config file if not already done so */
		if (strcmp(configFile, DFT_CONFIGFILE) != 0) {
			printf("Using the default config file %s\n",
			    DFT_CONFIGFILE);
			(void) strlcpy(configFile, DFT_CONFIGFILE, MAXPATHLEN);
			if ((fstr = fopen(configFile, "r")) == NULL) {
				if (running && debugLevel >= MSG_ERROR_1) {
					sprintf(debugmsg, "Cannot open "
					    "default config file. Using "
					    "default values.\n");
					senddebug(MSG_ERROR_1);
				} else {
					printf("Cannot open default config "
					    "file. Using default values.\n");
				}
				return (0);
			}
		} else {
			return (0);
		}
	}

	if (running && (debugLevel >= MSG_INFO_1)) {
		sprintf(debugmsg, "Reading config file %s\n", configFile);
		senddebug(MSG_INFO_1);
	}

	do {
		lineno++;
		n = readline(fstr, line, 80);

		if (line[0] == '\0' || line[0] == COMMENT_CHAR)
			continue;
		/*
		 * We now scan the input line and put a NULL at the
		 * end of the keyword token.  This way, we can compare
		 * the keyword token by strcmp(line, "...")
		 *
		 * At the same time, we find the start of the value
		 * token so that we can retrieve the value by something
		 * like atoi(&line[i])
		 */
		i = 0;
		while (line[i] != ' ' && line[i] != TAB)
			i++;
		line[i++] = '\0';	/* put NULL after keyword token */

		while (line[i] < '0' || line[i] > 'z' ||
		    (line[i] > '9' && line[i] < 'A') ||
		    (line[i] > 'Z' && line[i] < 'a'))
			i++;

		if (strcmp(line, "DebugLevel") == 0)
			debugLevel = atoi(&line[i]);
		else if (strcmp(line, "DebugDest") == 0) {
			if (!running) {
				debugDest = atoi(&line[i]);
			} else {
				debugDestChange = 0;
				newDebugDest = atoi(&line[i]);

				if (debugDest == atoi(&line[i]))
					continue;
				/*
				 * Don't allow running in background to
				 * re-acquire the controlling terminal
				 */
				if (backGround &&
				    atoi(&line[i]) == DEST_CONSOLE)
					continue;
				/*
				 * We have determined that there is a
				 * legal change of the debug destination.
				 * However, we cannot do the actual change
				 * now because the log file may also change.
				 * So we set a flag and do it later.
				 */
				debugDestChange = 1;
			}
		} else if (strcmp(line, "MaxClients") == 0) {
			/* can be -1 which means unlimited */
			if (line[i-1] == '-')
				i--;
			maxClients = atoi(&line[i]);
		} else if (strcmp(line, "BackGround") == 0) {
			if (!running)
				backGround = atoi(&line[i]);
		} else if (strcmp(line, "LogFile") == 0) {
			if (line[i-1] == '/')
				i--;
			if (!running) {
				(void) strlcpy(logFile, &line[i], MAXPATHLEN);
			} else {
				logFileChange = 0;
				(void) strlcpy(newLogFile, &line[i],
				    MAXPATHLEN);
				if (strcmp(newLogFile, logFile) == 0)
					continue;
				else
					logFileChange = 1;
			}
		} else if (strcmp(line, "DelayGran") == 0)
			delayGran = atol(&line[i]);
		else if (strcmp(line, "StartDelay") == 0)
			startDelay = atol(&line[i]);
		else if (strcmp(line, "FrameSize") == 0)
			frameSize = atoi(&line[i]);
		else if (strcmp(line, "end") == 0)
			done = 1;
	} while (!done);

	fclose(fstr);

	if (running) {
		if (debugDestChange || logFileChange) {
			switch (debugDest) {
			case DEST_SYSLOGD:
				closelog();
				break;
			case DEST_LOGFILE:
				if (log_str != NULL)
					fclose(log_str);
				log_str = NULL;
				break;
			}
			debugDest = newDebugDest;
			switch (debugDest) {
			case DEST_SYSLOGD:
				openlog("rpld", LOG_PID, LOG_DAEMON);
				break;
			case DEST_LOGFILE:
				log_str = fopen(newLogFile, "a+");
				if (log_str == NULL) {
					/* cannot open the new log file */
					/* reopen the old one and use that */
					log_str = fopen(logFile, "a+");
					if (log_str == NULL) {
						/* we are doomed */
						;
					}
					setbuf(log_str, (char *)NULL);
					if (debugLevel >= MSG_FATAL) {
						sprintf(debugmsg, "Cannot "
						    "open new log file %s\n",
						    newLogFile);
						senddebug(MSG_FATAL);
						sprintf(debugmsg, "Re-using "
						    "old log file %s\n",
						    logFile);
						senddebug(MSG_FATAL);
					}
				} else {
					(void) strlcpy(logFile, newLogFile,
					    MAXPATHLEN);
					setbuf(log_str, (char *)NULL);
				}
				break;
			}
		}
	}
	return (0);
}

int
readline(FILE *str, char *buf, int count)
{
	int	i = 0;
	int	done = 0;
	int	ch;

	while (!done && i < count) {
		ch = getc(str);
		if (ch == LF || ch == CR || ch == EOF) {
			done = 1;
		} else {
			buf[i++] = ch;
		}
	}
	buf[i] = '\0';
	return (i);
}

int
open_debug_dest(void)
{
	if (debugDest == DEST_LOGFILE) {
		if (log_str != NULL)
			fclose(log_str);
		log_str = fopen(logFile, "a+");
		if (log_str == NULL) {
			if (debugLevel >= MSG_FATAL) {
				sprintf(debugmsg, "Cannot open log file %s\n",
				    logFile);
				senddebug(MSG_FATAL);
			}
			return (-1);
		}
		setbuf(log_str, (char *)NULL);
	}

	if (debugDest == DEST_SYSLOGD) {
		openlog("rpld", LOG_PID, LOG_DAEMON);
	}

	return (0);
}

void
usage(void)
{
	printf("\n");
	printf("Usage:	 rpld [options] <network_interface_name>\n");
	printf("      	 rpld -a [options]\n");
	printf("Options:\n");
	printf("	-f file	  # set alternate config file\n");
	printf("	-d num	  # set debug level (0-9), 0=nil, 9=most\n");
	printf("	-D num	  # set debug destination, 0=console, "
	    "1=syslogd, 2=logfile\n");
	printf("	-M num	  # set max simultaneous clients, "
	    "-1=unlimited\n");
	printf("	-b num	  # set background mode, 1=background, "
	    "0=not\n");
	printf("	-l file	  # set alternate log file\n");
	printf("	-s num	  # set start delay count\n");
	printf("	-g num	  # set delay granularity\n");
	printf("\n");
}

/*
 * Pick out leading alphabetic part of string 's'.
 */
void
getdevice(uchar_t *s, uchar_t *dev)
{
	while (isalpha(*s))
		*dev++ = *s++;
	*dev = '\0';
}

/*
 * Pick out trailing numeric part of string 's' and return int.
 */
int
getunit(char *s)
{
	char	intbuf[128];
	char	*p = intbuf;

	while (isalpha(*s))
		s++;
	while (isdigit(*s))
		*p++ = *s++;
	*p = '\0';
	return (atoi(intbuf));
}
