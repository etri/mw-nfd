/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
*
 * Copyright (c) 2019-2021,  HII of ETRI.
 *
 * This file is part of MW-NFD (Named Data Networking Forwarding Daemon).
 * See AUTHORS.md for complete list of NFD authors and contributors.
 *
 * MW-NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * MW-NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * MW-NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <ctime>
#include <stdint.h>
#include <boost/atomic.hpp>
#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <iostream>
#include <arpa/inet.h>

#if defined(__linux__)
#include <linux/if_packet.h>
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <sys/uio.h>
#include <linux/fib_rules.h>
#include <linux/if_addrlabel.h>
#include <linux/if_bridge.h>

#include "iproute.hpp"


namespace nfd {

	static int __rtnl_recvmsg(int fd, struct msghdr *msg, int flags)
	{
		int len;

		do {
			len = recvmsg(fd, msg, flags);
		} while (len < 0 && (errno == EINTR || errno == EAGAIN));

		if (len < 0) {
			fprintf(stderr, "netlink receive error %s (%d)\n",
					strerror(errno), errno);
			return -errno;
		}

		if (len == 0) {
			fprintf(stderr, "EOF on netlink\n");
			return -ENODATA;
		}

		return len;
	}

	static int rtnl_recvmsg(int fd, struct msghdr *msg, char **answer)
	{
		struct iovec *iov = msg->msg_iov;
		char *buf;
		int len;

		iov->iov_base = NULL;
		iov->iov_len = 0;

		len = __rtnl_recvmsg(fd, msg, MSG_PEEK | MSG_TRUNC);
		if (len < 0)
			return len;

		if (len < 32768)
			len = 32768;
		buf = (char *)malloc(len);
		if (!buf) {
			fprintf(stderr, "malloc error: not enough buffer\n");
			return -ENOMEM;
		}

		iov->iov_base = buf;
		iov->iov_len = len;

		len = __rtnl_recvmsg(fd, msg, 0);
		if (len < 0) {
			free(buf);
			return len;
		}

		if (answer){
			*answer = buf;
		}else
			free(buf);

		return len;
	}

	int rcvbuf = 1024 * 1024;

	int rtnl_open_byproto(struct rtnl_handle *rth, unsigned int subscriptions)
	{
		socklen_t addr_len;
		int sndbuf = 32768;
		int one = 1;

		memset(rth, 0, sizeof(*rth));

		rth->proto = NETLINK_ROUTE;
		rth->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
		if (rth->fd < 0) {
			perror("Cannot open netlink socket");
			return -1;
		}

		if (setsockopt(rth->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
			perror("SO_SNDBUF");
			return -1;
		}

		if (setsockopt(rth->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
			perror("SO_RCVBUF");
			return -1;
		}

		/* Older kernels may no support extended ACK reporting */
		setsockopt(rth->fd, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one));

		memset(&rth->local, 0, sizeof(rth->local));
		rth->local.nl_family = AF_NETLINK;
		rth->local.nl_groups = subscriptions;

		if (bind(rth->fd, (struct sockaddr *)&rth->local, sizeof(rth->local)) < 0) {
			perror("Cannot bind netlink socket");
			return -1;
		}
		addr_len = sizeof(rth->local);
		if (getsockname(rth->fd, (struct sockaddr *)&rth->local, &addr_len) < 0) {
			perror("Cannot getsockname");
			return -1;
		}
		if (addr_len != sizeof(rth->local)) {
			fprintf(stderr, "Wrong address length %d\n", addr_len);
			return -1;
		}
		if (rth->local.nl_family != AF_NETLINK) {
			fprintf(stderr, "Wrong address family %d\n",
					rth->local.nl_family);
			return -1;
		}
		//modori
		rth->seq = std::time(NULL);
		return 0;
	}

	static int __rtnl_talk_iov(struct rtnl_handle *rtnl, struct iovec *iov,
			size_t iovlen, struct nlmsghdr **answer,
			bool show_rtnl_err, nl_ext_ack_fn_t errfn)
	{
		struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
		struct iovec riov;
		struct msghdr msg = {
			.msg_name = &nladdr,
			.msg_namelen = sizeof(nladdr),
			.msg_iov = iov,
			.msg_iovlen = iovlen,
		};
		unsigned int seq = 0;
		struct nlmsghdr *h;
		int i, status;
		char *buf;

		for (i = 0; i < iovlen; i++) {
			h = (struct nlmsghdr *)iov[i].iov_base;
			h->nlmsg_seq = seq = ++rtnl->seq;
			if (answer == NULL)
				h->nlmsg_flags |= NLM_F_ACK;
		}

		status = sendmsg(rtnl->fd, &msg, 0);
		if (status < 0) {
			perror("Cannot talk to rtnetlink");
			return -1;
		}

		/* change msg to use the response iov */
		msg.msg_iov = &riov;
		msg.msg_iovlen = 1;
		i = 0;
		while (1) {
next:
			status = rtnl_recvmsg(rtnl->fd, &msg, &buf);
			++i;

			if (status < 0)
				return status;

			if (msg.msg_namelen != sizeof(nladdr)) {
				fprintf(stderr, "sender address length == %d\n", msg.msg_namelen);
				return -1;
			}

			for (h = (struct nlmsghdr *)buf; status >= sizeof(*h); ) {
				int len = h->nlmsg_len;
				int l = len - sizeof(*h);

				if (l < 0 || len > status) {
					if (msg.msg_flags & MSG_TRUNC) {
						fprintf(stderr, "Truncated message\n");
						free(buf);
						return -1;
					}
					fprintf(stderr, "!!!malformed message: len=%d\n", len);
					return -1;
				}

				if (nladdr.nl_pid != 0 ||
						h->nlmsg_pid != rtnl->local.nl_pid ||
						h->nlmsg_seq > seq || h->nlmsg_seq < seq - iovlen) {
					/* Don't forget to skip that message. */
					status -= NLMSG_ALIGN(len);
					h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
					continue;
				}

				if (h->nlmsg_type == NLMSG_ERROR) {
					struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
					int error = err->error;

					if (l < sizeof(struct nlmsgerr)) {
						fprintf(stderr, "ERROR truncated\n");
						free(buf);
						return -1;
					}

					if (!error) {
						/* check messages from kernel */
						//modori
						//nl_dump_ext_ack(h, errfn);
						printf("000000000000000000\n");
					} else {
						errno = -error;

						//modori
						//if (rtnl->proto != NETLINK_SOCK_DIAG && show_rtnl_err)
							//rtnl_talk_error(h, err, errfn);
						printf("rtnl_talk_error\n");
						fprintf(stderr, "RTNETLINK answers: %s\n",
								        strerror(-err->error));
						return -1;
					}

					if (answer)
						*answer = (struct nlmsghdr *)buf;
					else
						free(buf);

					if (i < iovlen)
						goto next;
					return error ? -i : 0;
				}

				if (answer) {
					*answer = (struct nlmsghdr *)buf;
					return 0;
				}

				fprintf(stderr, "Unexpected reply!!!\n");

				status -= NLMSG_ALIGN(len);
				h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
			}
			free(buf);

			if (msg.msg_flags & MSG_TRUNC) {
				fprintf(stderr, "Message truncated\n");
				continue;
			}

			if (status) {
				fprintf(stderr, "!!!Remnant of size %d\n", status);
				return -1;
			}
		}
		return 0;
	}

	int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, struct nlmsghdr **answer)
	{
		struct iovec iov = {
			.iov_base = n, 
			.iov_len = n->nlmsg_len
		};   

		return __rtnl_talk_iov(rtnl, &iov, 1, answer, true, NULL);
	}

	int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
			int len, unsigned short flags)
	{       
		unsigned short type;

		memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
		while (RTA_OK(rta, len)) {
			type = rta->rta_type & ~flags;
			if ((type <= max) && (!tb[type]))
				tb[type] = rta;
			rta = RTA_NEXT(rta, len);
		}           
		if (len)
			fprintf(stderr, "!!!Deficit %d, rta_len=%d\n",
					len, rta->rta_len);
		return 0;
	} 

	static inline __u32 rta_getattr_u32(const struct rtattr *rta)
	{
		    return *(__u32 *)RTA_DATA(rta);
	}

	static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb)
	{
		__u32 table = r->rtm_table;

		if (tb[RTA_TABLE])
			table = rta_getattr_u32(tb[RTA_TABLE]);
		return table;
	}

	int af_bit_len(int af)
	{
		switch (af) {
			case AF_INET6:
				return 128;
			case AF_INET:
				return 32;
			case AF_DECnet:
				return 16;
			case AF_IPX:
				return 80;
			case AF_MPLS:
				return 20;
		}       

		return 0;   
	} 

	int preferred_family = AF_UNSPEC;
	
	int inet_addr_match(const inet_prefix *a, const inet_prefix *b, int bits)
	{
		const __u32 *a1 = a->data;
		const __u32 *a2 = b->data;
		int words = bits >> 0x05;

		bits &= 0x1f;

		if (words)
			if (memcmp(a1, a2, words << 2))
				return -1;

		if (bits) {
			__u32 w1, w2;
			__u32 mask;

			w1 = a1[words];
			w2 = a2[words];

			mask = htonl((0xffffffff) << (0x20 - bits));

			if ((w1 ^ w2) & mask)
				return 1;
		}

		return 0;
	}

	int ll_addr_a2n(char *lladdr, int len, char *arg)
	{           
		if (strchr(arg, '.')) {
			inet_prefix pfx;
			if (get_addr_1(&pfx, arg, AF_INET)) {
				fprintf(stderr, "\"%s\" is invalid lladdr.\n", arg);
				return -1;
			}
			if (len < 4)
				return -1;
			memcpy(lladdr, pfx.data, 4);
			return 4;
		} else {
			int i;

			for (i = 0; i < len; i++) {
				int temp;
				char *cp = strchr(arg, ':');
				if (cp) {
					*cp = 0;
					cp++;
				}
				if (sscanf(arg, "%x", &temp) != 1) {
					fprintf(stderr, "\"%s\" is invalid lladdr.\n",
							arg);
					return -1;
				}
				if (temp < 0 || temp > 255) {
					fprintf(stderr, "\"%s\" is invalid lladdr.\n",
							arg);
					return -1;
				}
				lladdr[i] = temp;
				if (!cp)
					break;
				arg = cp;
			}
			return i + 1;
		}
	}
	int mask2bits(__u32 netmask)
	{
		unsigned int bits = 0;
		__u32 mask = ntohl(netmask);
		__u32 host = ~mask;

		/* a valid netmask must be 2^n - 1 */
		if ((host & (host + 1)) != 0)
			return -1;

		for (; mask; mask <<= 1)
			++bits;
		return bits;
	}

	int get_unsigned(unsigned int *val, const char *arg, int base)
	{
		unsigned long res;
		char *ptr;

		if (!arg || !*arg)
			return -1;

		res = strtoul(arg, &ptr, base);

		/* empty string or trailing non-digits */
		if (!ptr || ptr == arg || *ptr)
			return -1;

		/* overflow */
		if (res == ULONG_MAX && errno == ERANGE)
			return -1;

		/* out side range of unsigned */
		if (res > UINT_MAX)
			return -1;

		*val = res;
		return 0;
	}



	static struct
	{
		unsigned int tb;
		int cloned;
		int flushed;
		char *flushb;
		int flushp;
		int flushe;
		int protocol, protocolmask;
		int scope, scopemask;
		__u64 typemask;
		int tos, tosmask;
		int iif, iifmask;
		int oif, oifmask;
		int mark, markmask;
		int realm, realmmask;
		__u32 metric, metricmask;
		inet_prefix rprefsrc;
		inet_prefix rvia;
		inet_prefix rdst;
		inet_prefix mdst;
		inet_prefix rsrc;
		inet_prefix msrc;
	} filter;


	int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
	{   
		return parse_rtattr_flags(tb, max, rta, len, 0);
	}   

	int get_rta_if(const struct rtattr *rta, const char *prefix)
	{
		//const char *ifname = ll_index_to_name(rta_getattr_u32(rta));
		printf("GotIfIndex: %d\n", rta_getattr_u32(rta));
		return rta_getattr_u32(rta);
	}

	int get_if_index(struct nlmsghdr *n)
	{
		int ifIndex = -1;
		struct rtmsg *r = ( struct rtmsg *)NLMSG_DATA(n);
		int len = n->nlmsg_len;
		struct rtattr *tb[RTA_MAX+1];

		if (n->nlmsg_type != RTM_NEWROUTE && n->nlmsg_type != RTM_DELROUTE) {
			fprintf(stderr, "Not a route: %08x %08x %08x\n", n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
			return -1;
		}
		if (filter.flushb && n->nlmsg_type != RTM_NEWROUTE)
			return 0;
		len -= NLMSG_LENGTH(sizeof(*r));
		if (len < 0) {
			fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
			return -1;
		}

		//af_bit_len(r->rtm_family);

		parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);
		rtm_get_table(r, tb);

		if (tb[RTA_OIF] && filter.oifmask != -1)
			ifIndex = get_rta_if(tb[RTA_OIF], "dev");

		return ifIndex;
	}

	static int get_netmask(unsigned int *val, char *arg, int base)
	{
		inet_prefix addr;

		if (!get_unsigned(val, arg, base))
			return 0;

		/* try converting dotted quad to CIDR */
		if (!get_addr_1(&addr, arg, AF_INET) && addr.family == AF_INET) {
			int b = mask2bits(addr.data[0]);

			if (b >= 0) {
				*val = b;
				return 0;
			}
		}

		return -1;
	}


	static int get_addr_ipv4(__u8 *ap, const char *cp)
	{
		int i;

		for (i = 0; i < 4; i++) {
			unsigned long n;
			char *endp;

			n = strtoul(cp, &endp, 0);
			if (n > 255)
				return -1;  /* bogus network value */

			if (endp == cp) /* no digits */
				return -1;

			ap[i] = n;

			if (*endp == '\0')
				break;

			if (i == 3 || *endp != '.')
				return -1;  /* extra characters */
			cp = endp + 1;
		}

		return 1;
	}


	static int af_byte_len(int af)
	{
		    return af_bit_len(af) / 8;
	}

	static int __get_addr_1(inet_prefix *addr, char *name, int family)
	{
		memset(addr, 0, sizeof(*addr));

		if (strcmp(name, "default") == 0) {
			if ((family == AF_DECnet) || (family == AF_MPLS))
				return -1;
			addr->family = family;
			addr->bytelen = af_byte_len(addr->family);
			addr->bitlen = -2;
			addr->flags |= PREFIXLEN_SPECIFIED;
			return 0;
		}

		if (strcmp(name, "all") == 0 ||
				strcmp(name, "any") == 0) {
			if ((family == AF_DECnet) || (family == AF_MPLS))
				return -1;
			addr->family = family;
			addr->bytelen = 0;
			addr->bitlen = -2;
			return 0;
		}

		if (family == AF_PACKET) {
			int len;

			len = ll_addr_a2n((char *) &addr->data, sizeof(addr->data), name);
			if (len < 0)
				return -1;

			addr->family = AF_PACKET;
			addr->bytelen = len;
			addr->bitlen = len * 8;
			return 0;
		}

		if (strchr(name, ':')) {
			addr->family = AF_INET6;
			if (family != AF_UNSPEC && family != AF_INET6)
				return -1;
			if (inet_pton(AF_INET6, name, addr->data) <= 0)
				return -1;
			addr->bytelen = 16;
			addr->bitlen = -1;
			return 0;
		}

		addr->family = AF_INET;
		if (family != AF_UNSPEC && family != AF_INET)
			return -1;

		if (get_addr_ipv4((__u8 *)addr->data, name) <= 0)
			return -1;

		addr->bytelen = 4;
		addr->bitlen = -1;
		return 0;
	}


	static void set_address_type(inet_prefix *addr)
	{
		switch (addr->family) {
			case AF_INET:
				if (!addr->data[0])
					addr->flags |= ADDRTYPE_INET_UNSPEC;
				else if (IN_MULTICAST(ntohl(addr->data[0])))
					addr->flags |= ADDRTYPE_INET_MULTI;
				else
					addr->flags |= ADDRTYPE_INET;
				break;
			case AF_INET6:
				if (IN6_IS_ADDR_UNSPECIFIED(addr->data))
					addr->flags |= ADDRTYPE_INET_UNSPEC;
				else if (IN6_IS_ADDR_MULTICAST(addr->data))
					addr->flags |= ADDRTYPE_INET_MULTI;
				else
					addr->flags |= ADDRTYPE_INET;
				break;
		}
	}

	int get_addr_1(inet_prefix *addr, char *name, int family)
	{
		int ret;

		ret = __get_addr_1(addr, name, family);
		if (ret)
			return ret;

		set_address_type(addr);
		return 0;
	}


	int get_prefix_1(inet_prefix *dst, char *arg, int family)
	{
		char *slash;
		int err, bitlen, flags;

		slash = strchr(arg, '/');
		if (slash)
			*slash = 0;

		err = get_addr_1(dst, arg, family);

		if (slash)
			*slash = '/';

		if (err)
			return err;

		bitlen = af_bit_len(dst->family);

		flags = 0;
		if (slash) {
			unsigned int plen;

			if (dst->bitlen == -2)
				return -1;
			if (get_netmask(&plen, slash + 1, 0))
				return -1;
			if (plen > bitlen)
				return -1;

			flags |= PREFIXLEN_SPECIFIED;
			bitlen = plen;
		} else {
			if (dst->bitlen == -2)
				bitlen = 0;
		}

		dst->flags |= flags;
		dst->bitlen = bitlen;

		return 0;
	}


	int get_prefix(inet_prefix *dst, char *arg, int family)
	{           
		if (family == AF_PACKET) {
			fprintf(stderr, "Error: \"%s\" may be inet prefix, but it is not allowed in this context.\n", arg);
			return -1;
		}       

		if (get_prefix_1(dst, arg, family)) {
			return -1;
		}           
		return 0;
	} 

#define NLMSG_TAIL(nmsg) \
	    ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

	int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen)   
	{           
		int len = RTA_LENGTH(alen);
		struct rtattr *rta;

		if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
			fprintf(stderr, "addattr_l ERROR: message exceeded bound of %d\n", maxlen);
			return -1;  
		}           
		rta = NLMSG_TAIL(n);
		rta->rta_type = type;
		rta->rta_len = len;
		if (alen)
			memcpy(RTA_DATA(rta), data, alen);
		n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
		return 0;
	}  

	int getIfIndexFromRt(const char * addrIn)
	{
		int ifIndex=-1;

		struct {
			struct nlmsghdr n;
			struct rtmsg        r;   
			char            buf[1024];
		} req;
		
		req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
		req.n.nlmsg_flags = NLM_F_REQUEST;
		req.n.nlmsg_type = RTM_GETROUTE;
		req.r.rtm_family = preferred_family;
		req.r.rtm_flags = 0;
		req.r.rtm_flags |= RTM_F_LOOKUP_TABLE;

		struct nlmsghdr *answer;

		inet_prefix addr;
		char *tmp = const_cast<char*>(addrIn);

		if( get_prefix(&addr, tmp, req.r.rtm_family) == -1 ){
			fprintf(stderr, "Error: ifIndex:%d.\n", ifIndex);
			return ifIndex;
		}

		if (req.r.rtm_family == AF_UNSPEC)
			req.r.rtm_family = addr.family;
		if (addr.bytelen)
			addattr_l(&req.n, sizeof(req), RTA_DST, &addr.data, addr.bytelen);

		if (req.r.rtm_family == AF_INET && addr.bitlen != 32) {
			fprintf(stderr, "Warning: /%u as prefix is invalid, only /32 (or none) is supported.\n", addr.bitlen);
			req.r.rtm_dst_len = 32;
		} else if (req.r.rtm_family == AF_INET6 && addr.bitlen != 128) {
			fprintf(stderr, "Warning: /%u as prefix is invalid, only /128 (or none) is supported.\n", addr.bitlen);
			req.r.rtm_dst_len = 128;
		} else
			req.r.rtm_dst_len = addr.bitlen;

		req.r.rtm_family = AF_INET;
		struct rtnl_handle rth;
		rtnl_open_byproto(&rth, 0);

		rtnl_talk(&rth, &req.n, &answer) ;

		ifIndex = get_if_index(answer);
//		close(rth->fd);
		return ifIndex;
	}

} // namespace mw-nfd

