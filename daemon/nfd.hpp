/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2019,  Regents of the University of California,
 *                           Arizona Board of Regents,
 *                           Colorado State University,
 *                           University Pierre & Marie Curie, Sorbonne University,
 *                           Washington University in St. Louis,
 *                           Beijing Institute of Technology,
 *                           The University of Memphis.
 *
 * This file is part of NFD (Named Data Networking Forwarding Daemon).
 * See AUTHORS.md for complete list of NFD authors and contributors.
 *
 * NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NFD_DAEMON_NFD_HPP
#define NFD_DAEMON_NFD_HPP


#include <ndn-cxx/face.hpp>
#include <ndn-cxx/mgmt/dispatcher.hpp>
#include <ndn-cxx/net/network-monitor.hpp>
#include <ndn-cxx/security/key-chain.hpp>

#include "common/config-file.hpp"
#include "fw/face-table.hpp"
#include "mw-nfd/forwarder-remote-access.hpp"

namespace nfd {

class FaceTable;
class Forwarder;

class CommandAuthenticator;
class ForwarderStatusManager;
//ETRI
class FaceManager;
class FibManager;
class CsManager;
class StrategyChoiceManager;

namespace face {
class Face;
class FaceSystem;
} // namespace face

/**
 * \brief Class representing the NFD instance.
 *
 * This class is used to initialize all components of NFD.
 */
class Nfd : noncopyable
{
public:
  /**
   * \brief Create NFD instance using an absolute or relative path to a configuration file.
   */
  Nfd(const std::string& configFile, ndn::KeyChain& keyChain);

  /**
   * \brief Create NFD instance using a parsed ConfigSection.
   *
   * This version of the constructor is more appropriate for integrated environments,
   * such as NS-3 or Android.
   *
   * \note When using this version of the constructor, error messages will show
   *       "internal://nfd.conf" when referring to configuration errors.
   */
  Nfd(const ConfigSection& config, ndn::KeyChain& keyChain);


  /**
   * \brief Destructor.
   */
  ~Nfd();

  /**
   * \brief Perform initialization of NFD instance.
   *
   * After initialization, NFD can be started by invoking `getGlobalIoService().run()`.
   */
  void
  initialize();


  /**
   * \brief Reload configuration file and apply updates (if any).
   */
  void
  reloadConfigFile();

  std::shared_ptr<FaceTable> getFaceTable()
  { 
      return m_faceTable;
  }

  bool config_bulk_fib(FaceId faceId0, FaceId faceId1, std::string fib_path);

  void onInterestRemoteAccess(const ndn::Name& name, const ndn::Interest& interest);

private:
  explicit
  Nfd(ndn::KeyChain& keyChain);

  void
  configureLogging();

  void
  initializeManagement();

  void
  reloadConfigFileFaceSection();


private:
  std::string m_configFile;
  ConfigSection m_configSection;

  shared_ptr<FaceTable> m_faceTable;
  unique_ptr<face::FaceSystem> m_faceSystem;
  unique_ptr<Forwarder> m_forwarder;

  ndn::KeyChain& m_keyChain;
  shared_ptr<face::Face> m_internalFace;
  shared_ptr<ndn::Face> m_internalClientFace;

  shared_ptr<face::Face> m_internalFaceRemoteAccess;
  shared_ptr<ndn::Face> m_internalClientFaceRemoteAccess;

  unique_ptr<ndn::mgmt::Dispatcher> m_dispatcher;
  shared_ptr<CommandAuthenticator> m_authenticator;
  unique_ptr<ForwarderStatusManager> m_forwarderStatusManager;
//ETRI
  unique_ptr<FaceManager> m_faceManager;
  unique_ptr<FibManager> m_fibManager;
  unique_ptr<CsManager> m_csManager;
  unique_ptr<StrategyChoiceManager> m_strategyChoiceManager;

  shared_ptr<ndn::net::NetworkMonitor> m_netmon;
  scheduler::ScopedEventId m_reloadConfigEvent;

	boost::asio::signal_set m_fibSignalSet;

	int m_face1;
	int m_face2;

};

} // namespace nfd

#endif // NFD_DAEMON_NFD_HPP
