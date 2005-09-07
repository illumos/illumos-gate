/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id: printfr.c,v 1.37 2003/06/03 16:01:12 darrenr Exp $
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ipf.h"


void printlookup(addr, mask)
i6addr_t *addr, *mask;
{
	switch (addr->iplookuptype)
	{
	case IPLT_POOL :
		printf("pool/");
		break;
	case IPLT_HASH :
		printf("hash/");
		break;
	default :
		printf("lookup(%x)=", addr->iplookuptype);
		break;
	}

	printf("%u", addr->iplookupnum);
	if (opts & OPT_UNDEF) {
		if (mask->iplookupptr == NULL) {
			printf("(!)");
		}
	}
}


/*
 * print the filter structure in a useful way
 */
void	printfr(fp, iocfunc)
struct	frentry	*fp;
ioctlfunc_t	iocfunc;
{
	struct protoent	*p;
	u_short	sec[2];
	u_32_t type;
	u_char *t;
	char *s;
	int pr;

	pr = -2;
	type = fp->fr_type & ~FR_T_BUILTIN;

	if ((fp->fr_type & FR_T_BUILTIN) != 0)
		printf("# Builtin: ");

	if (fp->fr_type == FR_T_CALLFUNC) {
		;
	} else if (fp->fr_func != NULL) {
		printf("call");
		if ((fp->fr_flags & FR_CALLNOW) != 0)
			printf(" now");
		s = kvatoname(fp->fr_func, iocfunc);
		printf(" %s/%u", s ? s : "?", fp->fr_arg);
	} else if (FR_ISPASS(fp->fr_flags))
		printf("pass");
	else if (FR_ISBLOCK(fp->fr_flags)) {
		printf("block");
		if (fp->fr_flags & FR_RETICMP) {
			if ((fp->fr_flags & FR_RETMASK) == FR_FAKEICMP)
				printf(" return-icmp-as-dest");
			else if ((fp->fr_flags & FR_RETMASK) == FR_RETICMP)
				printf(" return-icmp");
			if (fp->fr_icode) {
				if (fp->fr_icode <= MAX_ICMPCODE)
					printf("(%s)",
						icmpcodes[(int)fp->fr_icode]);
				else
					printf("(%d)", fp->fr_icode);
			}
		} else if ((fp->fr_flags & FR_RETMASK) == FR_RETRST)
			printf(" return-rst");
	} else if ((fp->fr_flags & FR_LOGMASK) == FR_LOG) {
		printlog(fp);
	} else if (FR_ISACCOUNT(fp->fr_flags))
		printf("count");
	else if (FR_ISAUTH(fp->fr_flags))
		printf("auth");
	else if (FR_ISPREAUTH(fp->fr_flags))
		printf("preauth");
	else if (FR_ISNOMATCH(fp->fr_flags))
		printf("nomatch");
	else if (FR_ISSKIP(fp->fr_flags))
		printf("skip %u", fp->fr_arg);
	else {
		printf("%x", fp->fr_flags);
	}

	if (fp->fr_flags & FR_OUTQUE)
		printf(" out ");
	else
		printf(" in ");

	if (((fp->fr_flags & FR_LOGB) == FR_LOGB) ||
	    ((fp->fr_flags & FR_LOGP) == FR_LOGP)) {
		printlog(fp);
		putchar(' ');
	}

	if (fp->fr_flags & FR_QUICK)
		printf("quick ");

	if (*fp->fr_ifname) {
		printifname("on ", fp->fr_ifname, fp->fr_ifa);
		if (*fp->fr_ifnames[1] && strcmp(fp->fr_ifnames[1], "*"))
			printifname(",", fp->fr_ifnames[1], fp->fr_ifas[1]);
		putchar(' ');

		if (*fp->fr_dif.fd_ifname)
			print_toif("dup-to", &fp->fr_dif);
		if (*fp->fr_tif.fd_ifname)
			print_toif("to", &fp->fr_tif);
		if (fp->fr_flags & FR_FASTROUTE)
			printf("fastroute ");

		if ((*fp->fr_ifnames[2] && strcmp(fp->fr_ifnames[2], "*")) ||
		    (*fp->fr_ifnames[3] && strcmp(fp->fr_ifnames[3], "*"))) {
			if (fp->fr_flags & FR_OUTQUE)
				printf("in-via ");
			else
				printf("out-via ");

			if (*fp->fr_ifnames[2]) {
				printifname("", fp->fr_ifnames[2],
					    fp->fr_ifas[2]);
				putchar(' ');

				if (*fp->fr_ifnames[3]) {
					printifname(",", fp->fr_ifnames[3],
						    fp->fr_ifas[3]);
				}
			}
		}
	}

	if (type == FR_T_IPF) {
		if (fp->fr_mip.fi_tos)
			printf("tos %#x ", fp->fr_tos);
		if (fp->fr_mip.fi_ttl)
			printf("ttl %d ", fp->fr_ttl);
		if (fp->fr_flx & FI_TCPUDP) {
			printf("proto tcp/udp ");
			pr = -1;
		} else if (fp->fr_mip.fi_p) {
			pr = fp->fr_ip.fi_p;
			if ((p = getprotobynumber(fp->fr_proto)))
				printf("proto %s ", p->p_name);
			else
				printf("proto %d ", fp->fr_proto);
		}
	}

	if (type == FR_T_NONE) {
		printf("all");
	} else if (type == FR_T_IPF) {
		printf("from %s", fp->fr_flags & FR_NOTSRCIP ? "!" : "");
		if (fp->fr_satype != FRI_NORMAL) {
			printf("%s", fp->fr_ifname);
			if (fp->fr_satype == FRI_BROADCAST)
				printf("/bcast");
			else if (fp->fr_satype == FRI_NETWORK)
				printf("/net");
			else if (fp->fr_satype == FRI_NETMASKED)
				printf("/netmasked");
			else if (fp->fr_satype == FRI_PEERADDR)
				printf("/peer");
			else if (fp->fr_satype == FRI_LOOKUP)
				printlookup(&fp->fr_ip.fi_src,
					    &fp->fr_mip.fi_src);
			else
				printmask((u_32_t *)&fp->fr_smsk.s_addr);
		} else
			printhostmask(fp->fr_v, (u_32_t *)&fp->fr_src.s_addr,
				      (u_32_t *)&fp->fr_smsk.s_addr);
		if (fp->fr_scmp)
			printportcmp(pr, &fp->fr_tuc.ftu_src);

		printf(" to %s", fp->fr_flags & FR_NOTDSTIP ? "!" : "");
		if (fp->fr_datype != FRI_NORMAL) {
			printf("%s", fp->fr_ifname);
			if (fp->fr_datype == FRI_BROADCAST)
				printf("/bcast");
			else if (fp->fr_datype == FRI_NETWORK)
				printf("/net");
			else if (fp->fr_datype == FRI_NETMASKED)
				printf("/netmasked");
			else if (fp->fr_datype == FRI_PEERADDR)
				printf("/peer");
			else if (fp->fr_datype == FRI_LOOKUP)
				printlookup(&fp->fr_ip.fi_dst,
					    &fp->fr_mip.fi_dst);
			else
				printmask((u_32_t *)&fp->fr_dmsk.s_addr);
		} else
			printhostmask(fp->fr_v, (u_32_t *)&fp->fr_dst.s_addr,
				      (u_32_t *)&fp->fr_dmsk.s_addr);
		if (fp->fr_dcmp)
			printportcmp(pr, &fp->fr_tuc.ftu_dst);

		if ((fp->fr_flx & FI_WITH) || (fp->fr_mflx & FI_WITH) ||
		    fp->fr_optbits || fp->fr_optmask ||
		    fp->fr_secbits || fp->fr_secmask) {
			printf(" with");
			if (fp->fr_optbits || fp->fr_optmask ||
			    fp->fr_secbits || fp->fr_secmask) {
				sec[0] = fp->fr_secmask;
				sec[1] = fp->fr_secbits;
				if (fp->fr_v == 4)
					optprint(sec, fp->fr_optmask,
						 fp->fr_optbits);
#ifdef	USE_INET6
				else
					optprintv6(sec, fp->fr_optmask,
						   fp->fr_optbits);
#endif
			} else if (fp->fr_mflx & FI_OPTIONS) {
				if (!(fp->fr_flx & FI_OPTIONS))
					printf(" not");
				printf(" ipopts");
			}
			if (fp->fr_mflx & FI_SHORT) {
				if (!(fp->fr_flx & FI_SHORT))
					printf(" not");
				printf(" short");
			}
			if (fp->fr_mflx & FI_FRAG) {
				if (!(fp->fr_flx & FI_FRAG))
					printf(" not");
				printf(" frag");
			}
			if (fp->fr_mflx & FI_NATED) {
				if (!(fp->fr_flx & FI_NATED))
					printf(" not");
				printf(" nat");
			}
			if (fp->fr_mflx & FI_MULTICAST) {
				if (!(fp->fr_flx & FI_MULTICAST))
					printf(" not");
				printf(" multicast");
			}
			if (fp->fr_mflx & FI_BROADCAST) {
				if (!(fp->fr_flx & FI_BROADCAST))
					printf(" not");
				printf(" bcast");
			}
			if (fp->fr_mflx & FI_MBCAST) {
				if (!(fp->fr_flx & FI_MBCAST))
					printf(" not");
				printf(" mbcast");
			}
			if (fp->fr_mflx & FI_STATE) {
				if (!(fp->fr_flx & FI_STATE))
					printf(" not");
				printf(" state");
			}
			if (fp->fr_mflx & FI_BADNAT) {
				if (!(fp->fr_flx & FI_BADNAT))
					printf(" not");
				printf(" bad-nat");
			}
			if (fp->fr_mflx & FI_BAD) {
				if (!(fp->fr_flx & FI_BAD))
					printf(" not");
				printf(" bad");
			}
			if (fp->fr_mflx & FI_OOW) {
				if (!(fp->fr_flx & FI_OOW))
					printf(" not");
				printf(" oow");
			}
			if (fp->fr_mflx & FI_LOWTTL) {
				if (!(fp->fr_flx & FI_LOWTTL))
					printf(" not");
				printf(" lowttl");
			}
			if (fp->fr_mflx & FI_BADSRC) {
				if (!(fp->fr_flx & FI_BADSRC))
					printf(" not");
				printf(" bad-src");
			}
		}
		if (fp->fr_proto == IPPROTO_ICMP && fp->fr_icmpm) {
			int	type = fp->fr_icmp, code;

			type = ntohs(fp->fr_icmp);
			code = type & 0xff;
			type /= 256;
			if (type < (sizeof(icmptypes) / sizeof(char *) - 1) &&
			    icmptypes[type])
				printf(" icmp-type %s", icmptypes[type]);
			else
				printf(" icmp-type %d", type);
			if (ntohs(fp->fr_icmpm) & 0xff)
				printf(" code %d", code);
		}
		if ((fp->fr_proto == IPPROTO_TCP) &&
		    (fp->fr_tcpf || fp->fr_tcpfm)) {
			printf(" flags ");
			if (fp->fr_tcpf & ~TCPF_ALL)
				printf("0x%x", fp->fr_tcpf);
			else
				for (s = flagset, t = flags; *s; s++, t++)
					if (fp->fr_tcpf & *t)
						(void)putchar(*s);
			if (fp->fr_tcpfm) {
				(void)putchar('/');
				if (fp->fr_tcpfm & ~TCPF_ALL)
					printf("0x%x", fp->fr_tcpfm);
				else
					for (s = flagset, t = flags; *s;
					     s++, t++)
						if (fp->fr_tcpfm & *t)
							(void)putchar(*s);
			}
		}
#ifdef IPFILTER_BPF
	} else if (type == FR_T_BPFOPC) {
		u_32_t *bp;
		int i;

		printf("{");
		i = fp->fr_dsize / sizeof(*bp);

		for (bp = fp->fr_data; i; i--, bp++)
			printf(" 0x%08x", *bp);

		printf(" }");
#endif
	} else if (type == FR_T_COMPIPF) {
		;
	} else if (type == FR_T_CALLFUNC) {
		printf("call function at %p", fp->fr_data);
	} else {
		printf("[unknown filter type %#x]", fp->fr_type);
	}

	if (fp->fr_flags & FR_KEEPSTATE) {
		printf(" keep state");
		if ((fp->fr_flags & (FR_STSTRICT|FR_NEWISN)) ||
		    (fp->fr_statemax != 0) || (fp->fr_age[0] != 0)) {
			printf(" (");
			if (fp->fr_statemax != 0)
				printf(" limit %u", fp->fr_statemax);
			if (fp->fr_flags & FR_FRSTRICT)
				printf(" strict");
			if (fp->fr_flags & FR_NEWISN)
				printf(" newisn");
			if (fp->fr_age[0] || fp->fr_age[1])
				printf(" age %d/%d", fp->fr_age[0],
				       fp->fr_age[1]);
			printf(" )");
		}
	}
	if (fp->fr_flags & FR_KEEPFRAG) {
		printf(" keep frags");
		if (fp->fr_flags & (FR_FRSTRICT)) {
			printf(" (");
			if (fp->fr_flags & FR_FRSTRICT)
				printf(" strict");
			printf(" )");
				
		}
	}
	if (fp->fr_isc != (struct ipscan *)-1) {
		if (fp->fr_isctag[0])
			printf(" scan %s", fp->fr_isctag);
		else
			printf(" scan *");
	}
	if (*fp->fr_grhead != '\0')
		printf(" head %s", fp->fr_grhead);
	if (*fp->fr_group != '\0')
		printf(" group %s", fp->fr_group);
	if (fp->fr_logtag != FR_NOLOGTAG)
		printf(" log-tag %u", fp->fr_logtag);
	if (fp->fr_pps)
		printf(" pps %d", fp->fr_pps);
	(void)putchar('\n');
}
