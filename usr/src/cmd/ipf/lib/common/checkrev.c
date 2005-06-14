/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id: checkrev.c,v 1.9 2003/04/27 17:09:46 darrenr Exp $
 */

#include <sys/ioctl.h>
#include <fcntl.h>

#include "ipf.h"
#include "ipl.h"

int checkrev(ipfname)
char *ipfname;
{
	struct friostat fio, *fiop = &fio;
	ipfobj_t ipfo;
	int vfd;

	bzero((caddr_t)&ipfo, sizeof(ipfo));
	ipfo.ipfo_rev = IPFILTER_VERSION;
	ipfo.ipfo_size = sizeof(*fiop);
	ipfo.ipfo_ptr = (void *)fiop;
	ipfo.ipfo_type = IPFOBJ_IPFSTAT;

	if ((vfd = open(ipfname, O_RDONLY)) == -1) {
		perror("open device");
		return -1;
	}

	if (ioctl(vfd, SIOCGETFS, &ipfo)) {
		perror("ioctl(SIOCGETFS)");
		close(vfd);
		return -1;
	}
	close(vfd);

	if (strncmp(IPL_VERSION, fio.f_version, sizeof(fio.f_version))) {
		return -1;
	}
	return 0;
}
