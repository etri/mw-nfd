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
#include "core/version.hpp"

#include "mw-nfd/mw-nfd-global.hpp"

size_t nEnqMiss[128];
size_t nDropped[128];
size_t nIfDropped[128];

namespace nfd {

static const time::milliseconds STATUS_FRESHNESS(5000);

ForwarderStatusManager::ForwarderStatusManager(Forwarder& forwarder, Dispatcher& dispatcher)
  : m_forwarder(forwarder)
  , m_dispatcher(dispatcher)
  , m_startTimestamp(time::system_clock::now())
{
  m_dispatcher.addStatusDataset("status/general", ndn::mgmt::makeAcceptAllAuthorization(),
                                bind(&ForwarderStatusManager::listGeneralStatus, this, _1, _2, _3));
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
  size_t nFib=0;
  size_t nPit=0;
  size_t nM=0;
  size_t nCs=0;
  size_t nInInterests=0;
  size_t nOutInterests=0;
  size_t nInData=0;
  size_t nOutData=0;
  size_t nInNacks=0;
  size_t nOutNacks=0;
  size_t nSatisfiedInterests=0;
  size_t nUnsatisfiedInterests=0;


  int32_t workers = getForwardingWorkers();
  uint64_t inInt[16]={0,};
  uint64_t outInt[16]={0,};
  uint64_t inData[16]={0,};
  uint64_t outData[16]={0,};

  for(int32_t i=0;i<workers;i++){

      auto worker = getMwNfd(i);

      nNameTree += worker->getNameTreeTable().size();
      nFib += worker->getFibTable().size();
      nPit += worker->getPitTable().size();
      nM += worker->getMeasurementsTable().size();
      nCs += worker->getCsTable().size();


    const ForwarderCounters& counters = worker->getCountersInfo();
    nInInterests += counters.nInInterests;
    nOutInterests += counters.nOutInterests;
    nInData += counters.nInData;
    nOutData += counters.nOutData;
    nInNacks += counters.nInNacks;
    nOutNacks += counters.nOutNacks;
    nSatisfiedInterests += counters.nSatisfiedInterests;
    nUnsatisfiedInterests += counters.nUnsatisfiedInterests;


#ifdef WITH_COUNTERS
    for(int i=0;i<8;i++){
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

    for(int i=0;i<8;i++){
        if( inInt[i]!=0 or outInt[i]!= 0 or inData[i]!=0 or outData[i]!=0){
            getGlobalLogger().info("Face({}) - Total nFaceCounters: {}/{}/{}/{}" , 
                    i+face::FACEID_RESERVED_MAX, 
                    inInt[i], outInt[i], inData[i], outData[i]
                    );
        }

        if(nEnqMiss[i]!=0)
            getGlobalLogger().info("Face({}) - nEnqMiss: {}" , i+face::FACEID_RESERVED_MAX, nEnqMiss[i]);

        if(nDropped[i]!=0)
            getGlobalLogger().info("Face({}) - nDrooped: {}" , i+face::FACEID_RESERVED_MAX, nDropped[i]);
        if(nDropped[i]!=0)
            getGlobalLogger().info("Face({}) - nIfDrooped: {}" , i+face::FACEID_RESERVED_MAX, nIfDropped[i]);
    }

  status.setNNameTreeEntries(nNameTree);
  status.setNFibEntries(nFib);
  status.setNPitEntries(nPit);
  status.setNMeasurementsEntries(nM);
  status.setNCsEntries(nCs);

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
