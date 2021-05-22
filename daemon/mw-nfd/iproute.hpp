
/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2019-2021,  HII of ETRI.
 *
 * This file is part of MW-NFD (Named Data Networking Multi-Worker Forwarding Daemon).
 * See README.md for complete list of NFD authors and contributors.
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
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MW_NFD_IPROUTE_HPP
#define MW_NFD_IPROUTE_HPP

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

namespace nfd {
#define SPRINT_BSIZE 64
#define SPRINT_BUF(x)   char x[SPRINT_BSIZE]
	struct rtnl_handle {
		int         fd;
		struct sockaddr_nl  local;
		struct sockaddr_nl  peer;
		__u32           seq;
		__u32           dump;
		int         proto;
		FILE               *dump_fp;
#define RTNL_HANDLE_F_LISTEN_ALL_NSID       0x01
#define RTNL_HANDLE_F_SUPPRESS_NLERR        0x02
#define RTNL_HANDLE_F_STRICT_CHK        0x04
		int         flags;
	};

	typedef int (*nl_ext_ack_fn_t)(const char *errmsg, uint32_t off,
			const struct nlmsghdr *inner_nlh);


	typedef struct
	{
		__u16 flags;
		__u16 bytelen;
		__s16 bitlen;
		/* These next two fields match rtvia */
		__u16 family;
		__u32 data[64];
	} inet_prefix;

	enum {     
		PREFIXLEN_SPECIFIED = (1 << 0),
		ADDRTYPE_INET       = (1 << 1),
		ADDRTYPE_UNSPEC     = (1 << 2),
		ADDRTYPE_MULTI      = (1 << 3),

		ADDRTYPE_INET_UNSPEC    = ADDRTYPE_INET | ADDRTYPE_UNSPEC,
		ADDRTYPE_INET_MULTI = ADDRTYPE_INET | ADDRTYPE_MULTI
	};    
	 int get_addr_1(inet_prefix *addr, char *name, int family);
	 //static int __get_addr_1(inet_prefix *addr, char *name, int family);

int getIfIndexFromRt(const char * addrIn);
} // namespace mw-nfd

#endif // MW_NFD_DAEMON_COMMON_GLOBAL_HPP
