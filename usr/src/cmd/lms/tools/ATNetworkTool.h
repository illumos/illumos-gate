/*******************************************************************************
 * Copyright (C) 2004-2008 Intel Corp. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of Intel Corp. nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL Intel Corp. OR THE CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

#ifndef _AT_NETWORK_TOOL_H_
#define _AT_NETWORK_TOOL_H_

#include <string>
#include <set>
#include <vector>
#include <map>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

class ATAddress
{
private:
	struct sockaddr_storage ip;

public:

	ATAddress()
	{
		memset(&(this->ip), 0, sizeof(struct sockaddr_storage));
	};

	ATAddress(const ATAddress &y)
	{
		memcpy(&(this->ip), y.addr(), sizeof(struct sockaddr_storage));
	};

	ATAddress(const struct sockaddr *yip)
	{
		memset(&(this->ip), 0, sizeof(struct sockaddr_storage));
		memcpy(&(this->ip), yip, saSize(yip));
	};

	ATAddress(const ATAddress &y, in_port_t yport)
	{
		memcpy(&(this->ip), y.addr(), sizeof(struct sockaddr_storage));
		ATAddress::saSetPort((const struct sockaddr *)&(this->ip), yport);
	};

	ATAddress(const struct sockaddr *yip, in_port_t yport)
	{
		memset(&(this->ip), 0, sizeof(struct sockaddr_storage));
		memcpy(&(this->ip), yip, saSize(yip));
		ATAddress::saSetPort((const struct sockaddr *)&(this->ip), yport);
	};

	static void saSetPort(const struct sockaddr *ip, in_port_t yport)
	{
		switch (ip->sa_family) {
		case AF_INET6:
			((struct sockaddr_in6 *)ip)->sin6_port = htons(yport);
			break;

		case AF_INET:
			((struct sockaddr_in *)ip)->sin_port = htons(yport);
			break;
		}
	}

	static bool saIsInet(const struct sockaddr *ip)
	{
		return ((ip->sa_family == AF_INET) || (ip->sa_family == AF_INET6));
	};

	static unsigned int saSize(const struct sockaddr *ip)
	{
		switch (ip->sa_family) {
		case AF_INET6:
			return sizeof(struct sockaddr_in6);
			break;

		case AF_INET:
			return sizeof(struct sockaddr_in);
			break;

		default:
			return 0;
		}
	};

	static in_port_t saInPort(const struct sockaddr *ip)
	{
		switch (ip->sa_family) {
		case AF_INET6:
			return ntohs(((struct sockaddr_in6 *)ip)->sin6_port);
			break;

		case AF_INET:
			return ntohs(((struct sockaddr_in *)ip)->sin_port);
			break;

		default:
			return 0;
		}
	};

	static const void *saInAddr(const struct sockaddr *ip, size_t &asize)
	{
		switch (ip->sa_family) {
		case AF_INET6:
			asize = sizeof(in6_addr);
			return (const void *)&(((struct sockaddr_in6 *)ip)->sin6_addr);
			break;

		case AF_INET:
			asize = sizeof(in_addr);
			return (const void *)&(((struct sockaddr_in *)ip)->sin_addr);
			break;

		default:
			asize = 0;
			return NULL;
		}
	};

	static const char *saInNtoP(const struct sockaddr *ip, char *buf, size_t buflen)
	{
		if (!ATAddress::saIsInet(ip)) {
			return NULL;
		}

		size_t asize;
		const void *src = ATAddress::saInAddr(ip, asize);
		if (NULL == src) {
			return NULL;
		}
		return inet_ntop(ip->sa_family, src, buf, buflen);
	};

	sa_family_t family() const { return ip.ss_family; };

	bool isInet() const { return ((ip.ss_family == AF_INET) || (ip.ss_family == AF_INET6)); };

	unsigned int size() const
	{
		return ATAddress::saSize((const struct sockaddr *)&(this->ip));
	};

	const struct sockaddr *addr() const
	{
		return (const struct sockaddr *)&ip;
	};

	in_port_t inPort() const
	{
		return ATAddress::saInPort((const struct sockaddr *)&(this->ip));
	};

	const void *inAddr(size_t &asize) const
	{
		return ATAddress::saInAddr((const struct sockaddr *)&(this->ip), asize);
	};

	const char *inNtoP(char *buf, size_t buflen)
	{
		return ATAddress::saInNtoP((const struct sockaddr *)&(this->ip), buf, buflen);
	};

	ATAddress &operator=(const ATAddress &y)
	{
		if (this != &y) {
			memcpy(&(this->ip), y.addr(), sizeof(struct sockaddr_storage));
		}
		return *this;
	};

	ATAddress &operator=(const struct sockaddr &yip)
	{
		memset(&(this->ip), 0, sizeof(struct sockaddr_storage));
		memcpy(&(this->ip), &yip, saSize(&yip));
		return *this;
	};

	int compare(const ATAddress &y) const
	{
		if (this->family() != y.family()) {
			return (this->family() - y.family());
		}

		size_t asize = 0;
		const void *a = this->inAddr(asize);
		const void *b = y.inAddr(asize);
		if ((0 != asize) && (NULL != a) && (NULL != b)) {
			int adiff = memcmp(a, b, asize);
			if (adiff != 0) {
				return adiff;
			}
		}

		in_port_t ap = this->inPort();
		in_port_t bp = y.inPort();
		if ((ap == 0) || (bp == 0)) {
			return 0;
		}
		if (ap != bp) {
			return (ap - bp);
		}

		return memcmp(&(this->ip), y.addr(), this->size());
	};

	bool operator<(const ATAddress &y) const
	{
		if (this == &y) {
			return false;
		}
		return (this->compare(y) < 0);
	};

	bool operator>(const ATAddress &y) const
	{
		if (this == &y) {
			return false;
		}
		return (this->compare(y) > 0);
	};

	bool operator==(const ATAddress &y) const
	{
		if (this == &y) {
			return true;
		}
		if (this->family() != y.family()) {
			return false;
		}
		return (memcmp(&(this->ip), y.addr(), this->size()) == 0);
	};

	bool operator!=(const ATAddress &y) const
	{
		if (this == &y) {
			return false;
		}
		if (this->family() != y.family()) {
			return true;
		}
		return (memcmp(&(this->ip), y.addr(), this->size()) != 0);
	};

	static bool IsAddressIP(const char *address, int family = AF_INET)
	{
		struct sockaddr_storage inaddr;

		if (address == NULL) {
			return false;
		}
		return (0 < inet_pton(family, address, &inaddr));
	};
};


typedef std::set<ATAddress> ATAddressList;
typedef std::map<ATAddress, std::string> ATDomainMap;
typedef std::vector<int> ATSocketList;

class ATNetworkTool
{
public:
	static const int DefaultBacklog = 5;
	static const int DefaultFamily = AF_INET;
	static const int AF_XINETX = AF_MAX + 10;

	/* Gets Domain name from Hostname
	 * @param name hostname
	 * @param domain [out] domain name
	 * @return bool true if success, false if domain unknown
	 */
	static bool GetHostNameDomain(const char *name, std::string &domain);

	/* Gets Domain name from IP
	 * @param ip address
	 * @param domain [out] domain name
	 * @param error [out] error code
	 * @return bool true if success, false if domain unknown
	 */
	static bool GetIPDomain(const ATAddress &ip, std::string &domain, int &error);

	/* Gets Domain name from host entry
	 * @param hent pointer to host entry structure
	 * @param domain [out] domain name
	 * @return bool true if success, false if domain unknown
	 */
	static bool GetHentDomain(struct hostent *hent, std::string &domain);

	/* Gets Domain name from socket
	 * @param sock checked socket
	 * @param domain [out] domain name
	 * @param error [out] error code
	 * @return int ==1 if success, <0 on error, ==0 if no domain
	 */
	static int GetSockDomain(int sock, std::string &domain, int &error);

	/* Gets all local (IPv4/6) from local running network interfaces
	 * @param addresses [out] set of local IP addresses
	 * @param error [out] error code
	 * @param family filtered address family
	 * @param withloopback true if get loopback addresses too
	 * @return int ==0 if success, !=0 on error
	 */
	static int GetLocalIPs(ATAddressList &addresses, int &error,
				int family = ATNetworkTool::AF_XINETX,
				bool withloopback = false);

	/* Gets all local domains from local running network interfaces
	 * @param domains [out] map of <local IP address> => <domain name>
	 * @param error [out] error code
	 * @param family filtered address family
	 * @return int ==0 if success, !=0 on error
	 */
	static int GetLocalNetDomains(ATDomainMap &domains, int &error,
				int family = ATNetworkTool::AF_XINETX);

	/* Gets all (IPv4/6) network interfaces of socket peer
	 * @param addresses [out] set of peer IP addresses
	 * @param error [out] error code
	 * @param family filtered address family
	 * @param zeroport set port to 0 in result list
	 * @return int ==0 if success, !=0 on error
	 */
	static int GetSockPeerIPs(int sock, ATAddressList &addresses,
				int &error,
				int family = ATNetworkTool::AF_XINETX,
				bool zeroport = false);

	/* Checks if socket peer is (IPv4/6) local address
	 * @param sock checked socket
	 * @param error [out] error code
	 * @param family filtered address family
	 * @return int ==1 if peer is local, ==0 if remote, <0 on error
	 */
	static int IsSockPeerLocal(int sock, int &error,
				int family = ATNetworkTool::AF_XINETX);

	/* Closes socket
	 * @param s socket to close
	 * @return int ==0 if success, !=0 on error
	 */
	static int CloseSocket(int s);

	/* Sets/removes O_NONBLOCKING flag to socket
	 * @param s socket
	 * @param block - true to set flag, false to remove flag
	 * @return int ==0 if success, !=0 on error
	 */
	static int SetNonBlocking(int s, bool block = true);

	/* Creates socket
	 * @param addr socket parameters
	 * @param error [out] error code
	 * @return int !=-1 socket, ==-1 on error
	 */
	static int CreateSocket(const struct addrinfo *addr, int &error);

	/* Creates socket
	 * @param addr socket address
	 * @param addrlen socket address length
	 * @param error [out] error code
	 * @param family socket expected family
	 * @param socktype socket type
	 * @param protocol socket protocol
	 * @return int !=-1 socket, ==-1 on error
	 */
	static int CreateSocket(const struct sockaddr *addr, socklen_t addrlen,
				int &error,
				int family = ATNetworkTool::DefaultFamily,
				int socktype = SOCK_STREAM, int protocol = 0);

	/* Creates server listening socket
	 * @param addr socket parameters
	 * @param error [out] error code
	 * @param nonblocking true for nonblocking socket
	 * @param backlog listening backlog
	 * @return int !=-1 socket, ==-1 on error
	 */
	static int CreateServerSocket(const struct addrinfo *addr,
				int &error, bool nonblocking = true,
				int backlog = ATNetworkTool::DefaultBacklog);

	/* Creates server listening sockets
	 * @param sockets [out] list of created server listening sockets
	 * @param port listening port
	 * @param error [out] error code
	 * @param loopback true to listen only on loopback
	 * @param nonblocking true for nonblocking sockets
	 * @param family sockets expected family
	 * @param socktype sockets type
	 * @param protocol sockets protocol
	 * @param backlog listening backlog
	 * @param one true if want create only one socket
	 * @return int >=0 number of created server sockets, ==-1 on error
	 */
	static int CreateServerSockets(ATSocketList &sockets, in_port_t port,
				int &error,
				bool loopback = false, bool nonblocking = true,
				int family = ATNetworkTool::AF_XINETX,
				int socktype = SOCK_STREAM, int protocol = 0,
				int backlog = ATNetworkTool::DefaultBacklog,
				bool one = false);
	static int CreateServerSockets(ATSocketList &sockets, const char *port,
				int &error,
				bool loopback = false, bool nonblocking = true,
				int family = ATNetworkTool::AF_XINETX,
				int socktype = SOCK_STREAM, int protocol = 0,
				int backlog = ATNetworkTool::DefaultBacklog,
				bool one = false);

	/* Creates one server listening socket
	 * @param port listening port
	 * @param error [out] error code
	 * @param loopback true to listen only on loopback
	 * @param nonblocking true for nonblocking sockets
	 * @param family sockets expected family
	 * @param socktype sockets type
	 * @param protocol sockets protocol
	 * @param backlog listening backlog
	 * @return int !=-1 socket, ==-1 on error
	 */
	static int CreateServerSocket(in_port_t port,
				int &error,
				bool loopback = false, bool nonblocking = true,
				int family = ATNetworkTool::AF_XINETX,
				int socktype = SOCK_STREAM, int protocol = 0,
				int backlog = ATNetworkTool::DefaultBacklog);
	static int CreateServerSocket(const char *port,
				int &error,
				bool loopback = false, bool nonblocking = true,
				int family = ATNetworkTool::AF_XINETX,
				int socktype = SOCK_STREAM, int protocol = 0,
				int backlog = ATNetworkTool::DefaultBacklog);

	/* Connects to local socket
	 * @param sock socket to connect to
	 * @param error [out] error code
	 * @param loopback true to use loopback, false to use any local address
	 * @param socktype sockets type
	 * @param protocol sockets protocol
	 * @return int !=-1 socket, ==-1 on error
	 */
	static int ConnectToSocket(int sock,
				int &error, bool loopback = true,
				int socktype = SOCK_STREAM, int protocol = 0);

	/* Connects to address
	 * @param addr destination address parameters
	 * @param error [out] error code
	 * @param loopback true to use loopback, false to use any local address
	 * @return int !=-1 socket, ==-1 on error
	 */
	static int ConnectSocket(struct addrinfo *addr,
				int &error, bool loopback = false);

	/* Connects to address
	 * @param addr destination address
	 * @param addrlen socket address length
	 * @param error [out] error code
	 * @param loopback true to use loopback, false to use any local address
	 * @param family sockets expected family
	 * @param socktype sockets type
	 * @param protocol sockets protocol
	 * @return int !=-1 socket, ==-1 on error
	 */
	static int ConnectSocket(const struct sockaddr *addr, socklen_t addrlen,
				int &error, bool loopback = false,
				int family = ATNetworkTool::AF_XINETX,
				int socktype = SOCK_STREAM, int protocol = 0);

	/* Connects to address
	 * @param hostname name of destination host
	 * @param port destination port
	 * @param error [out] error code
	 * @param family sockets expected family
	 * @param socktype sockets type
	 * @param protocol sockets protocol
	 * @return int !=-1 socket, ==-1 on error
	 */
	static int Connect(const char *host, in_port_t port,
				int &error,
				int family = ATNetworkTool::AF_XINETX,
				int socktype = SOCK_STREAM, int protocol = 0);
	static int Connect(const char *host, const char *port,
				int &error,
				int family = ATNetworkTool::AF_XINETX,
				int socktype = SOCK_STREAM, int protocol = 0);

	/* Connects to loopback port
	 * @param port destination port
	 * @param error [out] error code
	 * @param family sockets expected family
	 * @param socktype sockets type
	 * @param protocol sockets protocol
	 * @return int !=-1 socket, ==-1 on error
	 */
	static int ConnectLoopback(in_port_t port,
				int &error,
				int family = ATNetworkTool::AF_XINETX,
				int socktype = SOCK_STREAM, int protocol = 0);
	static int ConnectLoopback(const char *port,
				int &error,
				int family = ATNetworkTool::AF_XINETX,
				int socktype = SOCK_STREAM, int protocol = 0);

	/* Returns local port associated with socket
	 * @param sock socket
	 * @return unsigned int port number, or 0 - on error
	 */
	static unsigned int GetLocalPort(int sock);

	/* Accepts connection on sockets - returns address or error
	 * @param s socket accepting connection
	 * @param address [out] peer address of accepted connection
	 * @param error [out] error code
	 * @param nonblocking true for nonblocking sockets
	 * @return int !=-1 socket, ==-1 on error
	 */
	static int Accept(int s, ATAddress &address,
			  int &error, bool nonblocking = true);
};

#endif //_AT_NETWORK_TOOL_H_

