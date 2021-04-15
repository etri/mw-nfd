/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2018,  Regents of the University of California,
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

#include "forwarder-status-manager.hpp"
#include "fw/forwarder.hpp"
#include "face/face.hpp"
#include "core/version.hpp"

#include "mw-nfd/mw-nfd-global.hpp"


#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-info.hpp>


#include <sstream>
#include <map>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

using boost::property_tree::ptree;
using boost::property_tree::read_json;
using boost::property_tree::write_json;


#ifdef ETRI_DEBUG_COUNTERS
size_t g_nEnqMiss[COUNTERS_MAX];
size_t g_nDropped[COUNTERS_MAX];
size_t g_nIfDropped[COUNTERS_MAX];
#endif

#include <iostream>


using namespace ndn;
NFD_LOG_INIT(ForwarderStatusManager);

namespace nfd {

static const time::milliseconds STATUS_FRESHNESS(5000);

ForwarderStatusManager::ForwarderStatusManager(Forwarder& forwarder, Dispatcher& dispatcher)
  : m_forwarder(forwarder)
  , m_dispatcher(dispatcher)
  , m_startTimestamp(time::system_clock::now())
{
  m_dispatcher.addStatusDataset("status/general", ndn::mgmt::makeAcceptAllAuthorization(),
                                bind(&ForwarderStatusManager::listGeneralStatus, this, _1, _2, _3));
#ifdef ETRI_DEBUG_COUNTERS
	memset(g_nEnqMiss, '\0',sizeof(size_t)*COUNTERS_MAX);
memset(g_nDropped,'\0',sizeof(size_t)*COUNTERS_MAX);
memset(g_nIfDropped,'\0',sizeof(size_t)*COUNTERS_MAX);
#endif
}

ndn::nfd::ForwarderStatus
ForwarderStatusManager::collectGeneralStatus()
{
  ndn::nfd::ForwarderStatus status;

  status.setNfdVersion(NFD_VERSION_BUILD_STRING);
  status.setStartTimestamp(m_startTimestamp);
  status.setCurrentTimestamp(time::system_clock::now());

#ifndef ETRI_NFD_ORG_ARCH
  size_t nNameTree=0;
  size_t nFib=m_forwarder.getFib().size();
  size_t nPit=0;
  size_t nM=0;
  size_t nCs=0;
  size_t nExCs=0;
  size_t nInInterests=0;
  size_t nOutInterests=0;
  size_t nInData=0;
  size_t nOutData=0;
  size_t nInNacks=0;
  size_t nOutNacks=0;
  size_t nSatisfiedInterests=0;
  size_t nUnsatisfiedInterests=0;

  int32_t workers = getForwardingWorkers();

  uint64_t __attribute__((unused)) inInt[16]={0,};
  uint64_t __attribute__((unused)) outInt[16]={0,};
  uint64_t __attribute__((unused)) inData[16]={0,};
  uint64_t __attribute__((unused)) outData[16]={0,};

  nNameTree+=m_forwarder.getNameTree().size();
  nFib += m_forwarder.getFib().size();
  nPit += m_forwarder.getPit().size();
  nM +=  m_forwarder.getMeasurements().size();
  nCs +=m_forwarder.getCs().size();
  nExCs +=m_forwarder.getCs().sizeExact();

  const ForwarderCounters& counters = m_forwarder.getCounters();
  nInInterests+=(counters.nInInterests);
        nOutInterests +=(counters.nOutInterests);
        nInData +=(counters.nInData);
        nOutData += (counters.nOutData);
        nInNacks += (counters.nInNacks);
        nOutNacks += (counters.nOutNacks);
        nSatisfiedInterests += (counters.nSatisfiedInterests);
        nUnsatisfiedInterests +=(counters.nUnsatisfiedInterests);

  for(int32_t i=0;i<workers;i++){

      auto worker = getMwNfd(i);

      nNameTree += worker->getNameTreeTable().size();
      nFib += worker->getFibTable().size();
      nPit += worker->getPitTable().size();
      nM += worker->getMeasurementsTable().size();
      nCs += worker->getCsTable().size();
      nExCs += worker->getCsTable().sizeExact();


    const ForwarderCounters& counters = worker->getCountersInfo();
    nInInterests += counters.nInInterests;
    nOutInterests += counters.nOutInterests;
    nInData += counters.nInData;
    nOutData += counters.nOutData;
    nInNacks += counters.nInNacks;
    nOutNacks += counters.nOutNacks;
    nSatisfiedInterests += counters.nSatisfiedInterests;
    nUnsatisfiedInterests += counters.nUnsatisfiedInterests;


#if 0 //def ETRI_DEBUG_COUNTERS
    for(int i=0;i<COUNTERS_MAX;i++){
        if( counters.nFaceCounters[i][0] != 0 or counters.nFaceCounters[i][1] != 0 or counters.nFaceCounters[i][2] != 0 or counters.nFaceCounters[i][3] != 0)
        {
            inInt[i] += counters.nFaceCounters[i][0];
            outInt[i] += counters.nFaceCounters[i][1];
            inData[i] += counters.nFaceCounters[i][2];
            outData[i] += counters.nFaceCounters[i][3];
        }
    }
#endif

  }

#ifdef ETRI_DEBUG_COUNTERS
    for(int i=0;i<COUNTERS_MAX;i++){
        if( inInt[i]!=0 or outInt[i]!= 0 or inData[i]!=0 or outData[i]!=0){
            std::cout << "Face(" << i+face::FACEID_RESERVED_MAX << ") - Total nFaceCounters: " << inInt[i] << "/" << outInt[i] <<
                        "/" << inData[i] << "/" << outData[i] << std::endl;
        }

        if(g_nEnqMiss[i]!=0)
            std::cout << "Face(" <<  i+face::FACEID_RESERVED_MAX << ") - nEnqueueMiss: " << g_nEnqMiss[i] << std::endl;

        if(g_nDropped[i]!=0)
            std::cout << "Face(" << i+face::FACEID_RESERVED_MAX << ") - nDrooped(Pcap) Packets: " << g_nDropped[i] << std::endl;
        if(g_nIfDropped[i]!=0)
            std::cout << "Face(" << i+face::FACEID_RESERVED_MAX << ") - nIfDrooped(Pcap) Packets: " << g_nIfDropped[i] << std::endl;
    }
#endif

  status.setNNameTreeEntries(nNameTree);
  status.setNFibEntries(nFib);
  status.setNPitEntries(nPit);
  status.setNMeasurementsEntries(nM);

	size_t nCsEntries = 0;
	int size = sizeof(size_t);
	nCsEntries = (nCs << ((size/2)*8));
	nCsEntries |= nExCs;
	//std::cout << "nCs:" << nCs << std::endl;
	//std::cout << "nExCs:" << nExCs << std::endl;
	//std::cout << std::bitset<64>(nCsEntries) << std::endl;

  status.setNCsEntries(nCsEntries);

  status.setNInInterests(nInInterests)
        .setNOutInterests(nOutInterests)
        .setNInData(nInData)
        .setNOutData(nOutData)
        .setNInNacks(nInNacks)
        .setNOutNacks(nOutNacks)
        .setNSatisfiedInterests(nSatisfiedInterests)
        .setNUnsatisfiedInterests(nUnsatisfiedInterests);
#else
  status.setNNameTreeEntries(m_forwarder.getNameTree().size());
  status.setNFibEntries(m_forwarder.getFib().size());
  status.setNPitEntries(m_forwarder.getPit().size());
  status.setNMeasurementsEntries(m_forwarder.getMeasurements().size());
  status.setNCsEntries(m_forwarder.getCs().size());

  const ForwarderCounters& counters = m_forwarder.getCounters();
  status.setNInInterests(counters.nInInterests)
        .setNOutInterests(counters.nOutInterests)
        .setNInData(counters.nInData)
        .setNOutData(counters.nOutData)
        .setNInNacks(counters.nInNacks)
        .setNOutNacks(counters.nOutNacks)
        .setNSatisfiedInterests(counters.nSatisfiedInterests)
        .setNUnsatisfiedInterests(counters.nUnsatisfiedInterests);
#endif

  return status;
}

void
ForwarderStatusManager::listGeneralStatus(const Name& topPrefix, const Interest& interest,
                                          ndn::mgmt::StatusDatasetContext& context)
{

	//std::cout << "listGeneralStatus : " << interest << std::endl;
  context.setExpiry(STATUS_FRESHNESS);

  auto status = this->collectGeneralStatus();
  const Block& wire = status.wireEncode();
  wire.parse();
  for (const auto& subblock : wire.elements()) {
    context.append(subblock);
  }
  context.end();

}

} // namespace nfd
