//
// ip/impl/network_v4.ipp
// ~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2020 Christopher M. Kohlhoff (chris at kohlhoff dot com)
// Copyright (c) 2014 Oliver Kowalke (oliver dot kowalke at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_ASIO_IP_IMPL_NETWORK_V4_IPP
#define BOOST_ASIO_IP_IMPL_NETWORK_V4_IPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <boost/asio/detail/config.hpp>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <boost/asio/error.hpp>
#include <boost/asio/detail/throw_error.hpp>
#include <boost/asio/detail/throw_exception.hpp>
#include "network_v4.hpp"

#include <boost/asio/detail/push_options.hpp>

namespace boost {
namespace asio {
namespace ip {

network_v4::network_v4(const address_v4& addr, unsigned short prefix_len)
  : address_(addr),
    prefix_length_(prefix_len)
{
  if (prefix_len > 32)
  {
    std::out_of_range ex("prefix length too large");
    boost::asio::detail::throw_exception(ex);
  }
}

network_v4::network_v4(const address_v4& addr, const address_v4& mask)
  : address_(addr),
    prefix_length_(0)
{
#if 1
  address_v4::bytes_type mask_bytes = mask.to_bytes();
  bool finished = false;
  for (std::size_t i = 0; i < mask_bytes.size(); ++i)
  {
    if (finished)
    {
      if (mask_bytes[i])
      {
        std::invalid_argument ex("non-contiguous netmask");
        boost::asio::detail::throw_exception(ex);
      }
      continue;
    }
    else
    {
      switch (mask_bytes[i])
      {
      case 255:
        prefix_length_ += 8;
        break;
      case 254: // prefix_length_ += 7
        prefix_length_ += 1;
        [[gnu::fallthrough]];
      case 252: // prefix_length_ += 6
        prefix_length_ += 1;
        [[gnu::fallthrough]];
      case 248: // prefix_length_ += 5
        prefix_length_ += 1;
        [[gnu::fallthrough]];
      case 240: // prefix_length_ += 4
        prefix_length_ += 1;
        [[gnu::fallthrough]];
      case 224: // prefix_length_ += 3
        prefix_length_ += 1;
        [[gnu::fallthrough]];
      case 192: // prefix_length_ += 2
        prefix_length_ += 1;
        [[gnu::fallthrough]];
      case 128: // prefix_length_ += 1
        prefix_length_ += 1;
        [[gnu::fallthrough]];
      case 0:   // nbits += 0
        finished = true;
        break;
      default:
        std::out_of_range ex("non-contiguous netmask");
        boost::asio::detail::throw_exception(ex);
      }
    }
  }
#endif
}

address_v4 network_v4::netmask() const// BOOST_ASIO_NOEXCEPT
{
  uint32_t nmbits = 0xffffffff;
  if (prefix_length_ == 0)
    nmbits = 0;
  else
    nmbits = nmbits << (32 - prefix_length_);
  return address_v4(nmbits);
}

#if 0
address_v4_range network_v4::hosts() const BOOST_ASIO_NOEXCEPT
{
  return is_host()
    ? address_v4_range(address_, address_v4(address_.to_uint() + 1))
    : address_v4_range(address_v4(network().to_uint() + 1), broadcast());
}
#endif

bool network_v4::is_subnet_of(const network_v4& other) const
{
  if (other.prefix_length_ >= prefix_length_)
    return false; // Only real subsets are allowed.
  const network_v4 me(address_, other.prefix_length_);
  return other.canonical() == me.canonical();
}

std::string network_v4::to_string() const
{
  boost::system::error_code ec;
  std::string addr = to_string(ec);
  boost::asio::detail::throw_error(ec);
  return addr;
}

std::string network_v4::to_string(boost::system::error_code& ec) const
{
  using namespace std; // For sprintf.
  ec = boost::system::error_code();
  char prefix_len[16];
#if defined(BOOST_ASIO_HAS_SECURE_RTL)
  sprintf_s(prefix_len, sizeof(prefix_len), "/%u", prefix_length_);
#else // defined(BOOST_ASIO_HAS_SECURE_RTL)
  sprintf(prefix_len, "/%u", prefix_length_);
#endif // defined(BOOST_ASIO_HAS_SECURE_RTL)
  return address_.to_string() + prefix_len;
}

network_v4 make_network_v4(const char* str)
{
  return make_network_v4(std::string(str));
}

network_v4 make_network_v4(const char* str, boost::system::error_code& ec)
{
  return make_network_v4(std::string(str), ec);
}

network_v4 make_network_v4(const std::string& str)
{
  boost::system::error_code ec;
  network_v4 net = make_network_v4(str, ec);
  boost::asio::detail::throw_error(ec);
  return net;
}

network_v4 make_network_v4(const std::string& str,
    boost::system::error_code& ec)
{
  std::string::size_type pos = str.find_first_of("/");

  if (pos == std::string::npos)
  {
    ec = boost::asio::error::invalid_argument;
    return network_v4();
  }

  if (pos == str.size() - 1)
  {
    ec = boost::asio::error::invalid_argument;
    return network_v4();
  }

  std::string::size_type end = str.find_first_not_of("0123456789", pos + 1);
  if (end != std::string::npos)
  {
    ec = boost::asio::error::invalid_argument;
    return network_v4();
  }

  //const address_v4 addr = make_address_v4(str.substr(0, pos), ec);
  const address_v4 addr = address_v4::from_string(str.substr(0, pos));
  if (ec)
    return network_v4();

  const int prefix_len = std::atoi(str.substr(pos + 1).c_str());
  if (prefix_len < 0 || prefix_len > 32)
  {
    ec = boost::asio::error::invalid_argument;
    return network_v4();
  }

  return network_v4(addr, static_cast<unsigned short>(prefix_len));
}


} // namespace ip
} // namespace asio
} // namespace boost

//#include <boost/asio/detail/pop_options.hpp>

#endif // BOOST_ASIO_IP_IMPL_NETWORK_V4_IPP

#if 0
#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//using namespace asio;
  namespace ip = boost::asio::ip;


int main()
{
    ip::network_v4 net1(ip::address_v4::from_string("192.168.1.1"), 24);
    ip::network_v4 net2(ip::address_v4::from_string("192.168.1.9"), 24);
        //ip::address_v4::from_string("255.255.255.0"));

        std::cout << "net1:" << net1.netmask().to_string() << std::endl;

ip::address_v4 addr3 = ip::address_v4::from_string("1.1.1.0");
ip::network_v4 net3 = ip::make_network_v4("1.1.1.1/8");
ip::network_v4 net4 = ip::make_network_v4("1.9.1.100/8");

    if(net3.network() ==net4.network()){
        std::cout << "equal" << std::endl;
    }else
        std::cout << "Not equal" << std::endl;

         struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char address[NI_MAXHOST];
    char netmask[NI_MAXHOST];

   if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

   /* Walk through linked list, maintaining head pointer so we
       can free list later */

   for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

       family = ifa->ifa_addr->sa_family;

       /* Display interface name and family (including symbolic
           form of the latter for the common families) */

       /* For an AF_INET* interface address, display the address */

       memset(address, '\0', NI_MAXHOST);
       memset(netmask, '\0', NI_MAXHOST);

       //if (family == AF_INET || family == AF_INET6) {
       if (family == AF_INET ) {
            s = getnameinfo(ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) :
                                          sizeof(struct sockaddr_in6),
                    address, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            s = getnameinfo(ifa->ifa_netmask, (family == AF_INET) ? sizeof(struct sockaddr_in) :
                                          sizeof(struct sockaddr_in6),
                    netmask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            printf("\taddress: <%s>/%s\n", address, netmask);


#if 1
            ip::network_v4 ss(ip::address_v4::from_string(address), 
                ip::address_v4::from_string(netmask));

            ip::network_v4 input(ip::address_v4::from_string("192.168.0.10"), 
                ip::address_v4::from_string(netmask));

    if(ss.network() ==input.network()){
        std::cout << "equal network:" << ss.network().to_string() <<"/" << netmask << "/" << if_nametoindex(ifa->ifa_name)<< std::endl;
    }else
        std::cout << "Not equal" << std::endl;
#endif
        }
    }

   freeifaddrs(ifaddr);
    exit(EXIT_SUCCESS);
}

#endif
