
#include "ipf.h"

char *hostname(v, ip)
int v;
void *ip;
{
#ifdef  USE_INET6
	static char hostbuf[MAXHOSTNAMELEN+1];
#endif
	struct in_addr ipa;

	if (v == 4) {
		ipa.s_addr = *(u_32_t *)ip;
		return inet_ntoa(ipa);
	}
#ifdef  USE_INET6
	(void) inet_ntop(AF_INET6, ip, hostbuf, sizeof(hostbuf) - 1);
	hostbuf[MAXHOSTNAMELEN] = '\0';
	return hostbuf;
#else
	return "IPv6";
#endif
}
