
/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2021,  HII of ETRI,
 *
 * This file is part of MW-NFD (Named Data Networking Multi-Worker Forwarding Daemon).
 * See README.md for complete list of NFD authors and contributors.
 *
 * MW-NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * WM-NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MW_NFD_WORKER_HPP
#define MW_NFD_WORKER_HPP

#include "common/config-file.hpp"
#include "fw/face-table.hpp"
#include "fw/forwarder.hpp"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/lp/packet.hpp>
#include <ndn-cxx/mgmt/dispatcher.hpp>
#include <ndn-cxx/net/network-monitor.hpp>
#include <ndn-cxx/net/network-interface.hpp>
#include <ndn-cxx/mgmt/nfd/face-monitor.hpp>
#include <ndn-cxx/mgmt/nfd/face-event-notification.hpp>
#include <face/transport.hpp>
#include <face/link-service.hpp>
#include <face/generic-link-service.hpp>

#include <boost/asio.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/dynamic_bitset.hpp>

#include <string>
#include <set>


namespace nfd {

class CommandAuthenticator;
class ForwarderStatusManager;
class FaceManager;
class FibManager;
class CsManager;
class StrategyChoiceManager;

namespace face {
class Face;
class FaceSystem;
} // namespace face

extern shared_ptr<FaceTable> g_faceTable;

/**
 * \brief Class representing the MW-NFD instance.
 *
 * This class is used to initialize all components of MW-NFD.
 */
class MwNfd : noncopyable
{
public:
	~MwNfd();

	void processNfdcCommand( char * );
	void initialize(uint32_t);

	void setFaceTable(std::shared_ptr<FaceTable> faceTable)
	{
		m_faceTable = faceTable;
	}

	void handleNfdcCommand();

	void runWorker();

	explicit MwNfd(int8_t wid, boost::asio::io_service*, bool,const std::string&);

	void decodeNetPacketFromMq(const shared_ptr<ndn::Buffer> buffer, 
			size_t faceId, EndpointId ep);
	void decodeNetPacketFromMq2(shared_ptr<const ndn::Buffer> buffer, 
			size_t faceId, EndpointId ep);
	//void processNfdcCommand( void * );

	std::tuple<uint64_t,uint64_t,uint64_t> getLinkServiceCounters(FaceId);

Fib& getFibTable();
Cs& getCsTable();
const ForwarderCounters &getCountersInfo();
StrategyChoice& getStrategyChoiceTable();
NameTree& getNameTreeTable();
Pit & getPitTable();
Measurements& getMeasurementsTable();
  void prepareBulkFibTest(std::string port0, std::string port1);

  bool config_bulk_fib(FaceId faceId0, FaceId faceId1, bool);

  uint8_t getWorkerId(){return m_workerId;}

private:

  void configureLogging();

  void initializeManagement();
private:
bool bulk_test_case_01();
void nfdc_process(const boost::system::error_code& error, size_t bytes_recvd);
#ifndef ETRI_NFD_ORG_ARCH
 void terminate(const boost::system::error_code& error, int signalNo);
#endif

  ConfigSection m_configSection;

  shared_ptr<FaceTable> m_faceTable;
  unique_ptr<face::FaceSystem> m_faceSystem;
  unique_ptr<Forwarder> m_forwarder;

//  ndn::KeyChain& m_keyChain;
  shared_ptr<face::Face> m_internalFace;
  shared_ptr<ndn::Face> m_internalClientFace;
  unique_ptr<ndn::mgmt::Dispatcher> m_dispatcher;
  shared_ptr<CommandAuthenticator> m_authenticator;
  unique_ptr<ForwarderStatusManager> m_forwarderStatusManager;
  unique_ptr<FaceManager> m_faceManager;
  unique_ptr<FibManager> m_fibManager;
  unique_ptr<CsManager> m_csManager;
  unique_ptr<StrategyChoiceManager> m_strategyChoiceManager;

  shared_ptr<ndn::net::NetworkMonitor> m_netmon;
  int8_t m_workerId;
  boost::asio::signal_set m_terminationSignalSet;
  boost::asio::signal_set m_fibSignalSet;

  enum { max_length = 1024 };

public:
private:
    int m_face1;
    int m_face0;
  	bool m_done;
    uint32_t m_inputWorkers;

    boost::asio::io_service* m_ios;
    int m_sockNfdcCmd;
	std::string m_bulkFibPort0;
	std::string m_bulkFibPort1;
	const std::string& m_configFile;
	std::map<FaceId, std::shared_ptr<nfd::face::GenericLinkService> > m_genericLinkServiceList;
	nfd::face::Face *m_face;
	bool m_wantFibSharding;
	bool m_setReservedFace;
	struct sockaddr_un m_localAddr;
	bool m_doneBulk;
};

} // namespace nfd

#endif 
