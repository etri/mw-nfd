
/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2019-2021,  Electronics and Telecommunications Research Institute.
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

#ifndef BOOST_ASIO_IP_NETWORK_V4_HPP
#define BOOST_ASIO_IP_NETWORK_V4_HPP

#include <boost/asio/detail/config.hpp>
#include <string>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/system/error_code.hpp>
//#include <boost/asio/ip/address_v4_range.hpp>

#include <boost/asio/detail/push_options.hpp>

namespace boost {
namespace asio {
namespace ip {

class network_v4
{
public:
  /// Default constructor.
  network_v4() //BOOST_ASIO_NOEXCEPT
    : address_(),
      prefix_length_(0)
  {
  }

  /// Construct a network based on the specified address and prefix length.
  network_v4(const address_v4& addr, unsigned short prefix_len);

  /// Construct network based on the specified address and netmask.
  network_v4(const address_v4& addr, const address_v4& mask);

  /// Copy constructor.
  network_v4(const network_v4& other) 
    : address_(other.address_),
      prefix_length_(other.prefix_length_)
  {
  }

#if defined(BOOST_ASIO_HAS_MOVE)
  /// Move constructor.
  network_v4(network_v4&& other)
    : address_(BOOST_ASIO_MOVE_CAST(address_v4)(other.address_)),
      prefix_length_(other.prefix_length_)
  {
  }
#endif // defined(BOOST_ASIO_HAS_MOVE)

  /// Assign from another network.
  network_v4& operator=(const network_v4& other)
  {
    address_ = other.address_;
    prefix_length_ = other.prefix_length_;
    return *this;
  }

#if defined(BOOST_ASIO_HAS_MOVE)
  /// Move-assign from another network.
  network_v4& operator=(network_v4&& other) //BOOST_ASIO_NOEXCEPT
  {
    address_ = BOOST_ASIO_MOVE_CAST(address_v4)(other.address_);
    prefix_length_ = other.prefix_length_;
    return *this;
  }
#endif // defined(BOOST_ASIO_HAS_MOVE)

  /// Obtain the address object specified when the network object was created.
  address_v4 address() const //BOOST_ASIO_NOEXCEPT
  {
    return address_;
  }

  /// Obtain the prefix length that was specified when the network object was
  /// created.
  unsigned short prefix_length() const //BOOST_ASIO_NOEXCEPT
  {
    return prefix_length_;
  }

  /// Obtain the netmask that was specified when the network object was created.
  address_v4 netmask() const; //BOOST_ASIO_NOEXCEPT;

  /// Obtain an address object that represents the network address.
  address_v4 network() const //BOOST_ASIO_NOEXCEPT
  {
    return address_v4(address_.to_ulong() & netmask().to_ulong());
  }

  /// Obtain an address object that represents the network's broadcast address.
  address_v4 broadcast() const //BOOST_ASIO_NOEXCEPT
  {
    return address_v4(network().to_ulong() | (netmask().to_ulong() ^ 0xFFFFFFFF));
  }

  /// Obtain an address range corresponding to the hosts in the network.
  //address_v4_range hosts() const ;//BOOST_ASIO_NOEXCEPT;

  /// Obtain the true network address, omitting any host bits.
  network_v4 canonical() const //BOOST_ASIO_NOEXCEPT
  {
    return network_v4(network(), netmask());
  }

  /// Test if network is a valid host address.
  bool is_host() const //BOOST_ASIO_NOEXCEPT
  {
    return prefix_length_ == 32;
  }

  /// Test if a network is a real subnet of another network.
  bool is_subnet_of(const network_v4& other) const;

  /// Get the network as an address in dotted decimal format.
  std::string to_string() const;

  /// Get the network as an address in dotted decimal format.
  std::string to_string(boost::system::error_code& ec) const;

  /// Compare two networks for equality.
  friend bool operator==(const network_v4& a, const network_v4& b)
  {
    return a.address_ == b.address_ && a.prefix_length_ == b.prefix_length_;
  }

  /// Compare two networks for inequality.
  friend bool operator!=(const network_v4& a, const network_v4& b)
  {
    return !(a == b);
  }

private:
  address_v4 address_;
  unsigned short prefix_length_;
};

inline network_v4 make_network_v4(
    const address_v4& addr, unsigned short prefix_len)
{
  return network_v4(addr, prefix_len);
}

inline network_v4 make_network_v4(
    const address_v4& addr, const address_v4& mask)
{
  return network_v4(addr, mask);
}

network_v4 make_network_v4(const char* str);

network_v4 make_network_v4(
    const char* str, boost::system::error_code& ec);

network_v4 make_network_v4(const std::string& str);

network_v4 make_network_v4(
    const std::string& str, boost::system::error_code& ec);

template <typename Elem, typename Traits>
std::basic_ostream<Elem, Traits>& operator<<(
    std::basic_ostream<Elem, Traits>& os, const network_v4& net);

} // namespace ip
} // namespace asio
} // namespace boost

#include <boost/asio/detail/pop_options.hpp>

#endif // BOOST_ASIO_IP_NETWORK_V4_HPP
