/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "ipf.h"
#include "ipt.h"
#include <sys/ioctl.h>
#include <sys/file.h>

extern	char	*optarg;
extern	struct frentry	*ipfilter[2][2];
extern	struct ipread	snoop, etherf, tcpd, pcap, iptext, iphex;
extern	struct ifnet	*get_unit __P((char *, int, ipf_stack_t *));
extern	void	init_ifp __P((void));

int	opts = OPT_DONOTHING;
int	use_inet6 = 0;
int	pfil_delayed_copy = 0;
int	main __P((int, char *[]));
int	loadrules __P((char *, int));
int	kmemcpy __P((char *, long, int));
int     kstrncpy __P((char *, long, int n));
void	dumpnat __P((ipf_stack_t *ifs));
void	dumpstate __P((ipf_stack_t *ifs));
void	dumplookups __P((ipf_stack_t *ifs));
void	dumpgroups __P((ipf_stack_t *ifs));
void	drain_log __P((char *, ipf_stack_t *ifs));
void	fixv4sums __P((mb_t *, ip_t *));
ipf_stack_t *get_ifs __P((void));
ipf_stack_t *create_ifs __P((void));


#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(SOLARIS) || \
	(_BSDI_VERSION >= 199701) || (__FreeBSD_version >= 300000) || \
	defined(__osf__) || defined(linux)
int ipftestioctl __P((int, ioctlcmd_t, ...));
int ipnattestioctl __P((int, ioctlcmd_t, ...));
int ipstatetestioctl __P((int, ioctlcmd_t, ...));
int ipauthtestioctl __P((int, ioctlcmd_t, ...));
int ipscantestioctl __P((int, ioctlcmd_t, ...));
int ipsynctestioctl __P((int, ioctlcmd_t, ...));
int ipooltestioctl __P((int, ioctlcmd_t, ...));
#else
int ipftestioctl __P((dev_t, ioctlcmd_t, void *));
int ipnattestioctl __P((dev_t, ioctlcmd_t, void *));
int ipstatetestioctl __P((dev_t, ioctlcmd_t, void *));
int ipauthtestioctl __P((dev_t, ioctlcmd_t, void *));
int ipsynctestioctl __P((dev_t, ioctlcmd_t, void *));
int ipscantestioctl __P((dev_t, ioctlcmd_t, void *));
int ipooltestioctl __P((dev_t, ioctlcmd_t, void *));
#endif

static	ioctlfunc_t	iocfunctions[IPL_LOGSIZE] = { ipftestioctl,
						      ipnattestioctl,
						      ipstatetestioctl,
						      ipauthtestioctl,
						      ipsynctestioctl,
						      ipscantestioctl,
						      ipooltestioctl,
						      NULL };


int main(argc,argv)
int argc;
char *argv[];
{
	char	*datain, *iface, *ifname, *logout;
	int	fd, i, dir, c, loaded, dump, hlen;
	struct	ifnet	*ifp;
	struct	ipread	*r;
	mb_t	mb, *m;
	ip_t	*ip;
	ipf_stack_t *ifs;

	m = &mb;
	dir = 0;
	dump = 0;
	hlen = 0;
	loaded = 0;
	r = &iptext;
	iface = NULL;
	logout = NULL;
	ifname = "anon0";
	datain = NULL;

	initparse();
	ifs = create_ifs();

#if defined(IPFILTER_DEFAULT_BLOCK)
        ifs->ifs_fr_pass = FR_BLOCK|FR_NOMATCH;
#else
        ifs->ifs_fr_pass = (IPF_DEFAULT_PASS)|FR_NOMATCH;
#endif
	ipftuneable_alloc(ifs);
	
	MUTEX_INIT(&ifs->ifs_ipf_rw, "ipf rw mutex");
	MUTEX_INIT(&ifs->ifs_ipf_timeoutlock, "ipf timeout lock");
	RWLOCK_INIT(&ifs->ifs_ipf_global, "ipf filter load/unload mutex");
	RWLOCK_INIT(&ifs->ifs_ipf_mutex, "ipf filter rwlock");
	RWLOCK_INIT(&ifs->ifs_ipf_ipidfrag, "ipf IP NAT-Frag rwlock");
	RWLOCK_INIT(&ifs->ifs_ipf_frcache, "ipf rule cache rwlock");

	fr_loginit(ifs);
	fr_authinit(ifs);
	fr_fraginit(ifs);
	fr_stateinit(ifs);
	fr_natinit(ifs);
	appr_init(ifs);
	ip_lookup_init(ifs);
	ifs->ifs_fr_running = 1;

	while ((c = getopt(argc, argv, "6bdDF:i:I:l:N:P:or:RT:vxX")) != -1)
		switch (c)
		{
		case '6' :
#ifdef	USE_INET6
			use_inet6 = 1;
#else
			fprintf(stderr, "IPv6 not supported\n");
			exit(1);
#endif
			break;
		case 'b' :
			opts |= OPT_BRIEF;
			break;
		case 'd' :
			opts |= OPT_DEBUG;
			break;
		case 'D' :
			dump = 1;
			break;
		case 'F' :
			if (strcasecmp(optarg, "pcap") == 0)
				r = &pcap;
			else if (strcasecmp(optarg, "etherfind") == 0)
				r = &etherf;
			else if (strcasecmp(optarg, "snoop") == 0)
				r = &snoop;
			else if (strcasecmp(optarg, "tcpdump") == 0)
				r = &tcpd;
			else if (strcasecmp(optarg, "hex") == 0)
				r = &iphex;
			else if (strcasecmp(optarg, "text") == 0)
				r = &iptext;
			break;
		case 'i' :
			datain = optarg;
			break;
		case 'I' :
			ifname = optarg;
			break;
		case 'l' :
			logout = optarg;
			break;
		case 'o' :
			opts |= OPT_SAVEOUT;
			break;
		case 'r' :
			if (ipf_parsefile(-1, ipf_addrule, iocfunctions,
					  optarg) == -1)
				return -1;
			loaded = 1;
			break;
		case 'R' :
			opts |= OPT_NORESOLVE;
			break;
		case 'v' :
			opts |= OPT_VERBOSE;
			break;
		case 'N' :
			if (ipnat_parsefile(-1, ipnat_addrule, ipnattestioctl,
					    optarg) == -1)
				return -1;
			loaded = 1;
			opts |= OPT_NAT;
			break;
		case 'P' :
			if (ippool_parsefile(-1, optarg, ipooltestioctl) == -1)
				return -1;
			loaded = 1;
			break;
		case 'T' :
			ipf_dotuning(-1, optarg, ipftestioctl);
			break;
		case 'x' :
			opts |= OPT_HEX;
			break;
		}

	if (loaded == 0) {
		(void)fprintf(stderr,"no rules loaded\n");
		exit(-1);
	}

	if (opts & OPT_SAVEOUT)
		init_ifp();

	if (datain)
		fd = (*r->r_open)(datain);
	else
		fd = (*r->r_open)("-");

	if (fd < 0)
		exit(-1);

	ip = MTOD(m, ip_t *);
	while ((i = (*r->r_readip)(MTOD(m, char *), sizeof(m->mb_buf),
				    &iface, &dir)) > 0) {
		if (iface == NULL || *iface == '\0')
			iface = ifname;
		ifp = get_unit(iface, IP_V(ip), ifs);
		if (ifp == NULL) {
			fprintf(stderr, "out of memory\n");
			exit(1);
		}
		if (!use_inet6) {
			ip->ip_off = ntohs(ip->ip_off);
			ip->ip_len = ntohs(ip->ip_len);
			if (r->r_flags & R_DO_CKSUM)
				fixv4sums(m, ip);
			hlen = IP_HL(ip) << 2;
		}
#ifdef	USE_INET6
		else
			hlen = sizeof(ip6_t);
#endif
		/* ipfr_slowtimer(); */
		m = &mb;
		m->mb_len = i;
		i = fr_check(ip, hlen, ifp, dir, &m, ifs);
		if ((opts & OPT_NAT) == 0)
			switch (i)
			{
			case -4 :
				(void)printf("preauth");
				break;
			case -3 :
				(void)printf("account");
				break;
			case -2 :
				(void)printf("auth");
				break;
			case -1 :
				(void)printf("block");
				break;
			case 0 :
				(void)printf("pass");
				break;
			case 1 :
				(void)printf("nomatch");
				break;
			case 3 :
				(void)printf("block return-rst");
				break;
			case 4 :
				(void)printf("block return-icmp");
				break;
			case 5 :
				(void)printf("block return-icmp-as-dest");
				break;
			default :
				(void)printf("recognised return %#x\n", i);
				break;
			}
		if (!use_inet6) {
			ip->ip_off = htons(ip->ip_off);
			ip->ip_len = htons(ip->ip_len);
		}

		if (!(opts & OPT_BRIEF)) {
			putchar(' ');
			printpacket(ip);
			printf("--------------");
		} else if ((opts & (OPT_BRIEF|OPT_NAT)) == (OPT_NAT|OPT_BRIEF))
			printpacket(ip);
		if (dir && (ifp != NULL) && IP_V(ip) && (m != NULL))
#if  defined(__sgi) && (IRIX < 60500)
			(*ifp->if_output)(ifp, (void *)m, NULL);
#else
# if TRU64 >= 1885
			(*ifp->if_output)(ifp, (void *)m, NULL, 0, 0);
# else
			(*ifp->if_output)(ifp, (void *)m, NULL, 0);
# endif
#endif
		if ((opts & (OPT_BRIEF|OPT_NAT)) != (OPT_NAT|OPT_BRIEF))
			putchar('\n');
		dir = 0;
		if (iface != ifname) {
			free(iface);
			iface = ifname;
		}
		m = &mb;
	}
	(*r->r_close)();

	if (logout != NULL) {
		drain_log(logout, ifs);
	}

	if (dump == 1)  {
		dumpnat(ifs);
		dumpstate(ifs);
		dumplookups(ifs);
		dumpgroups(ifs);
	}

	fr_deinitialise(ifs);

	return 0;
}


#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(SOLARIS) || \
	(_BSDI_VERSION >= 199701) || (__FreeBSD_version >= 300000) || \
	defined(__osf__) || defined(linux)
int ipftestioctl(int dev, ioctlcmd_t cmd, ...)
{
	caddr_t data;
	va_list ap;
	int i;

	va_start(ap, cmd);
	data = va_arg(ap, caddr_t);
	va_end(ap);

	i = iplioctl(IPL_LOGIPF, cmd, data, FWRITE|FREAD);
	if (opts & OPT_DEBUG)
		fprintf(stderr, "iplioctl(IPF,%#x,%p) = %d\n",
			(u_int)cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int ipnattestioctl(int dev, ioctlcmd_t cmd, ...)
{
	caddr_t data;
	va_list ap;
	int i;

	va_start(ap, cmd);
	data = va_arg(ap, caddr_t);
	va_end(ap);

	i = iplioctl(IPL_LOGNAT, cmd, data, FWRITE|FREAD);
	if (opts & OPT_DEBUG)
		fprintf(stderr, "iplioctl(NAT,%#x,%p) = %d\n",
			(u_int)cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int ipstatetestioctl(int dev, ioctlcmd_t cmd, ...)
{
	caddr_t data;
	va_list ap;
	int i;

	va_start(ap, cmd);
	data = va_arg(ap, caddr_t);
	va_end(ap);

	i = iplioctl(IPL_LOGSTATE, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "iplioctl(STATE,%#x,%p) = %d\n",
			(u_int)cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int ipauthtestioctl(int dev, ioctlcmd_t cmd, ...)
{
	caddr_t data;
	va_list ap;
	int i;

	va_start(ap, cmd);
	data = va_arg(ap, caddr_t);
	va_end(ap);

	i = iplioctl(IPL_LOGAUTH, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "iplioctl(AUTH,%#x,%p) = %d\n",
			(u_int)cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int ipscantestioctl(int dev, ioctlcmd_t cmd, ...)
{
	caddr_t data;
	va_list ap;
	int i;

	va_start(ap, cmd);
	data = va_arg(ap, caddr_t);
	va_end(ap);

	i = iplioctl(IPL_LOGSCAN, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "iplioctl(SCAN,%#x,%p) = %d\n",
			(u_int)cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int ipsynctestioctl(int dev, ioctlcmd_t cmd, ...)
{
	caddr_t data;
	va_list ap;
	int i;

	va_start(ap, cmd);
	data = va_arg(ap, caddr_t);
	va_end(ap);

	i = iplioctl(IPL_LOGSYNC, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "iplioctl(SYNC,%#x,%p) = %d\n",
			(u_int)cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int ipooltestioctl(int dev, ioctlcmd_t cmd, ...)
{
	caddr_t data;
	va_list ap;
	int i;

	va_start(ap, cmd);
	data = va_arg(ap, caddr_t);
	va_end(ap);

	i = iplioctl(IPL_LOGLOOKUP, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "iplioctl(POOL,%#x,%p) = %d\n",
			(u_int)cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}
#else
int ipftestioctl(dev, cmd, data)
dev_t dev;
ioctlcmd_t cmd;
void *data;
{
	int i;

	i = iplioctl(IPL_LOGIPF, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "iplioctl(IPF,%#x,%p) = %d\n", cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int ipnattestioctl(dev, cmd, data)
dev_t dev;
ioctlcmd_t cmd;
void *data;
{
	int i;

	i = iplioctl(IPL_LOGNAT, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "iplioctl(NAT,%#x,%p) = %d\n", cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int ipstatetestioctl(dev, cmd, data)
dev_t dev;
ioctlcmd_t cmd;
void *data;
{
	int i;

	i = iplioctl(IPL_LOGSTATE, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "iplioctl(STATE,%#x,%p) = %d\n", cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int ipauthtestioctl(dev, cmd, data)
dev_t dev;
ioctlcmd_t cmd;
void *data;
{
	int i;

	i = iplioctl(IPL_LOGAUTH, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "iplioctl(AUTH,%#x,%p) = %d\n", cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int ipsynctestioctl(dev, cmd, data)
dev_t dev;
ioctlcmd_t cmd;
void *data;
{
	int i;

	i = iplioctl(IPL_LOGSYNC, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "iplioctl(SYNC,%#x,%p) = %d\n", cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int ipscantestioctl(dev, cmd, data)
dev_t dev;
ioctlcmd_t cmd;
void *data;
{
	int i;

	i = iplioctl(IPL_LOGSCAN, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "iplioctl(SCAN,%#x,%p) = %d\n", cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int ipooltestioctl(dev, cmd, data)
dev_t dev;
ioctlcmd_t cmd;
void *data;
{
	int i;

	i = iplioctl(IPL_LOGLOOKUP, cmd, data, FWRITE|FREAD);
	if (opts & OPT_DEBUG)
		fprintf(stderr, "iplioctl(POOL,%#x,%p) = %d\n", cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}
#endif


int kmemcpy(addr, offset, size)
char *addr;
long offset;
int size;
{
	bcopy((char *)offset, addr, size);
	return 0;
}


int kstrncpy(buf, pos, n)
char *buf;
long pos;
int n;
{
	char *ptr;

	ptr = (char *)pos;

	while ((n-- > 0) && (*buf++ = *ptr++))
		;
	return 0;
}


/*
 * Display the built up NAT table rules and mapping entries.
 */
void dumpnat(ifs)
	ipf_stack_t *ifs;
{
	ipnat_t	*ipn;
	nat_t	*nat;

	printf("List of active MAP/Redirect filters:\n");
	for (ipn = ifs->ifs_nat_list; ipn != NULL; ipn = ipn->in_next)
		printnat(ipn, opts & (OPT_DEBUG|OPT_VERBOSE));
	printf("\nList of active sessions:\n");
	for (nat = ifs->ifs_nat_instances; nat; nat = nat->nat_next) {
		printactivenat(nat, opts, 0);
		if (nat->nat_aps)
			printaps(nat->nat_aps, opts);
	}
}


/*
 * Display the built up state table rules and mapping entries.
 */
void dumpstate(ifs)
	ipf_stack_t *ifs;
{
	ipstate_t *ips;

	printf("List of active state sessions:\n");
	for (ips = ifs->ifs_ips_list; ips != NULL; )
		ips = printstate(ips, opts & (OPT_DEBUG|OPT_VERBOSE),
				 ifs->ifs_fr_ticks);
}


void dumplookups(ifs)
	ipf_stack_t *ifs;
{
	iphtable_t *iph;
	ip_pool_t *ipl;
	int i;

	printf("List of configured pools\n");
	for (i = 0; i < IPL_LOGSIZE; i++)
		for (ipl = ifs->ifs_ip_pool_list[i]; ipl != NULL;
		    ipl = ipl->ipo_next)
			printpool(ipl, bcopywrap, NULL, opts);

	printf("List of configured hash tables\n");
	for (i = 0; i < IPL_LOGSIZE; i++)
		for (iph = ifs->ifs_ipf_htables[i]; iph != NULL;
		     iph = iph->iph_next)
			printhash(iph, bcopywrap, NULL, opts);
}


void dumpgroups(ifs)
	ipf_stack_t *ifs;
{
	frgroup_t *fg;
	frentry_t *fr;
	int i;

	printf("List of groups configured (set 0)\n");
	for (i = 0; i < IPL_LOGSIZE; i++)
		for (fg =  ifs->ifs_ipfgroups[i][0]; fg != NULL;
		    fg = fg->fg_next) {
			printf("Dev.%d. Group %s Ref %d Flags %#x\n",
				i, fg->fg_name, fg->fg_ref, fg->fg_flags);
			for (fr = fg->fg_start; fr != NULL; fr = fr->fr_next) {
#ifdef	USE_QUAD_T
				printf("%qu ",(unsigned long long)fr->fr_hits);
#else
				printf("%ld ", fr->fr_hits);
#endif
				printfr(fr, ipftestioctl);
			}
		}

	printf("List of groups configured (set 1)\n");
	for (i = 0; i < IPL_LOGSIZE; i++)
		for (fg =  ifs->ifs_ipfgroups[i][1]; fg != NULL;
		    fg = fg->fg_next) {
			printf("Dev.%d. Group %s Ref %d Flags %#x\n",
				i, fg->fg_name, fg->fg_ref, fg->fg_flags);
			for (fr = fg->fg_start; fr != NULL; fr = fr->fr_next) {
#ifdef	USE_QUAD_T
				printf("%qu ",(unsigned long long)fr->fr_hits);
#else
				printf("%ld ", fr->fr_hits);
#endif
				printfr(fr, ipftestioctl);
			}
		}
}


void drain_log(filename, ifs)
char *filename;
ipf_stack_t *ifs;
{
	char buffer[DEFAULT_IPFLOGSIZE];
	struct iovec iov;
	struct uio uio;
	size_t resid;
	int fd, i;

	fd = open(filename, O_CREAT|O_TRUNC|O_WRONLY, 0644);
	if (fd == -1) {
		perror("drain_log:open");
		return;
	}

	for (i = 0; i <= IPL_LOGMAX; i++)
		while (1) {
			bzero((char *)&iov, sizeof(iov));
			iov.iov_base = buffer;
			iov.iov_len = sizeof(buffer);

			bzero((char *)&uio, sizeof(uio));
			uio.uio_iov = &iov;
			uio.uio_iovcnt = 1;
			uio.uio_resid = iov.iov_len;
			resid = uio.uio_resid;

			if (ipflog_read(i, &uio, ifs) == 0) {
				/*
				 * If nothing was read then break out.
				 */
				if (uio.uio_resid == resid)
					break;
				write(fd, buffer, resid - uio.uio_resid);
			} else
				break;
	}

	close(fd);
}


void fixv4sums(m, ip)
mb_t *m;
ip_t *ip;
{
	u_char *csump, *hdr;

	ip->ip_sum = 0;
	ip->ip_sum = ipf_cksum((u_short *)ip, IP_HL(ip) << 2);

	csump = (u_char *)ip;
	csump += IP_HL(ip) << 2;

	switch (ip->ip_p)
	{
	case IPPROTO_TCP :
		hdr = csump;
		csump += offsetof(tcphdr_t, th_sum);
		break;
	case IPPROTO_UDP :
		hdr = csump;
		csump += offsetof(udphdr_t, uh_sum);
		break;
	default :
		csump = NULL;
		hdr = NULL;
		break;
	}
	if (hdr != NULL) {
		*csump = 0;
		*(u_short *)csump = fr_cksum(m, ip, ip->ip_p, hdr);
	}
}

ipf_stack_t *gifs;

/*
 * Allocate and keep pointer for get_ifs()
 */
ipf_stack_t *
create_ifs()
{
	ipf_stack_t *ifs;

	KMALLOCS(ifs, ipf_stack_t *, sizeof (*ifs));
	bzero(ifs, sizeof (*ifs));
	gifs = ifs;
	return (ifs);
}

ipf_stack_t *
get_ifs()
{
	return (gifs);
}
