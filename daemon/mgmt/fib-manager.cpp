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

#include "fib-manager.hpp"
#include "mw-nfd/mw-nfd-global.hpp"

#include "common/logger.hpp"
#include "fw/face-table.hpp"
#include "fw/scope-prefix.hpp"
#include "table/fib.hpp"

#include <ndn-cxx/lp/tags.hpp>
#include <ndn-cxx/mgmt/nfd/fib-entry.hpp>

#include <boost/range/adaptor/transformed.hpp>
#include <iostream>
#include <map>

namespace nfd {

NFD_LOG_INIT(FibManager);

FibManager::FibManager(Fib& fib, const FaceTable& faceTable,
                       Dispatcher& dispatcher, CommandAuthenticator& authenticator)
  : ManagerBase("fib", dispatcher, authenticator)
  , m_fib(fib)
  , m_faceTable(faceTable)
{
  registerCommandHandler<ndn::nfd::FibAddNextHopCommand>("add-nexthop",
    bind(&FibManager::addNextHop, this, _2, _3, _4, _5));
  registerCommandHandler<ndn::nfd::FibRemoveNextHopCommand>("remove-nexthop",
    bind(&FibManager::removeNextHop, this, _2, _3, _4, _5));

  registerStatusDatasetHandler("list", bind(&FibManager::listEntries, this, _1, _2, _3));
}

void
FibManager::addNextHop(const Name& topPrefix, const Interest& interest,
                       ControlParameters parameters,
                       const ndn::mgmt::CommandContinuation& done)
{
  setFaceForSelfRegistration(interest, parameters);
  const Name& prefix = parameters.getName();
  FaceId faceId = parameters.getFaceId();
  uint64_t cost = parameters.getCost();

  std::cout << "prefix: " << prefix << " addNextHop: " << parameters.getFlags() << std::endl;

  if (prefix.size() > Fib::getMaxDepth()) {
    NFD_LOG_DEBUG("fib/add-nexthop(" << prefix << ',' << faceId << ',' << cost <<
                  "): FAIL prefix-too-long");
   setGlobalNetName(false);
    return done(ControlResponse(414, "FIB entry prefix cannot exceed " +
                                to_string(Fib::getMaxDepth()) + " components"));
  }

  Face* face = m_faceTable.get(faceId);
  if (face == nullptr) {
    NFD_LOG_DEBUG("fib/add-nexthop(" << prefix << ',' << faceId << ',' << cost <<
                  "): FAIL unknown-faceid");
   setGlobalNetName(false);
    return done(ControlResponse(410, "Face not found"));
  }

#ifndef ETRI_NFD_ORG_ARCH
    if( !prefix.compare( 0, 1, "localhost") or getForwardingWorkers()==0){
      fib::Entry* entry = m_fib.insert(prefix).first;
      m_fib.addOrUpdateNextHop(*entry, *face, cost);
    }else{
        emitMwNfdcCommand(-1, MW_NFDC_MGR_FIB, MW_NFDC_VERB_ADD, parameters, getGlobalNetName());
        setGlobalNetName(false);
    }
#else

    fib::Entry* entry = m_fib.insert(prefix).first;
    m_fib.addOrUpdateNextHop(*entry, *face, cost);

    NFD_LOG_TRACE("fib/add-nexthop(" << prefix << ',' << faceId << ',' << cost << "): OK");

#endif

    parameters.unsetFlags();
  return done(ControlResponse(200, "Success").setBody(parameters.wireEncode()));
}

void
FibManager::removeNextHop(const Name& topPrefix, const Interest& interest,
                          ControlParameters parameters,
                          const ndn::mgmt::CommandContinuation& done)
{
  setFaceForSelfRegistration(interest, parameters);
  const Name& prefix = parameters.getName();
  FaceId faceId = parameters.getFaceId();

  done(ControlResponse(200, "Success").setBody(parameters.wireEncode()));

  Face* face = m_faceTable.get(faceId);
  if (face == nullptr) {
    NFD_LOG_TRACE("fib/remove-nexthop(" << prefix << ',' << faceId << "): OK no-face");
    return;
  }

  if(getForwardingWorkers()>0)
	  emitMwNfdcCommand(-1, MW_NFDC_MGR_FIB, MW_NFDC_VERB_REMOVE, parameters, getGlobalNetName());
  else{
	  fib::Entry* entry = m_fib.findExactMatch(parameters.getName());
	  if (entry == nullptr) {
		  NFD_LOG_TRACE("fib/remove-nexthop(" << prefix << ',' << faceId << "): OK no-entry");
		  return;
	  }

	  auto status = m_fib.removeNextHop(*entry, *face);
	  switch (status) {
		  case Fib::RemoveNextHopResult::NO_SUCH_NEXTHOP:
			  NFD_LOG_TRACE("fib/remove-nexthop(" << prefix << ',' << faceId << "): OK no-nexthop");
			  break;
		  case Fib::RemoveNextHopResult::FIB_ENTRY_REMOVED:
			  NFD_LOG_TRACE("fib/remove-nexthop(" << prefix << ',' << faceId << "): OK entry-erased");
			  break;
		  case Fib::RemoveNextHopResult::NEXTHOP_REMOVED:
			  NFD_LOG_TRACE("fib/remove-nexthop(" << prefix << ',' << faceId << "): OK nexthop-removed");
			  break;
	  }
  }
}

void
FibManager::listEntries(const Name& topPrefix, const Interest& interest,
                        ndn::mgmt::StatusDatasetContext& context)
{
  std::map<std::string,int> tmpMap;
  std::pair<std::map<std::string,int>::iterator,bool> ret;

#ifdef ETRI_NFD_ORG_ARCH
  for (const auto& entry : m_fib) {
    const auto& nexthops = entry.getNextHops() |
                           boost::adaptors::transformed([] (const fib::NextHop& nh) {
                             return ndn::nfd::NextHopRecord()
                                 .setFaceId(nh.getFace().getId())
                                 .setCost(nh.getCost());
                           });

    context.append(ndn::nfd::FibEntry()
                   .setPrefix(entry.getPrefix())
                   .setNextHopRecords(std::begin(nexthops), std::end(nexthops))
                   .wireEncode());
  }

#else
  // added by ETRI(modori) on 20200913
  size_t listSize=0;
  for (const auto& entry : m_fib) {
    const auto& nexthops = entry.getNextHops() |
                           boost::adaptors::transformed([] (const fib::NextHop& nh) {
                             return ndn::nfd::NextHopRecord()
                                 .setFaceId(nh.getFace().getId())
                                 .setCost(nh.getCost());
                           });

                    ret = tmpMap.insert( std::pair<std::string, int>(entry.getPrefix().toUri(), 0) ); 
                    if(ret.second==false)
                        continue;

    auto blk = ndn::nfd::FibEntry()
                   .setPrefix(entry.getPrefix())
                   .setNextHopRecords(std::begin(nexthops), std::end(nexthops))
                   .wireEncode();
    context.append(blk);

    listSize += blk.size();
  }

  int32_t workers = getForwardingWorkers();
  for(int32_t i=0;i<workers;i++){
      auto worker = getMwNfd(i);
      if(worker==nullptr)
          continue;

		  for (const auto& entry : worker->getFibTable()) {
				  const auto& nexthops = entry.getNextHops() |
						  boost::adaptors::transformed([] (const fib::NextHop& nh) {
										  return ndn::nfd::NextHopRecord()
										  .setFaceId(nh.getFace().getId())
										  .setCost(nh.getCost());
										  });

                    ret = tmpMap.insert( std::pair<std::string, int>(entry.getPrefix().toUri(), 0) ); 
                    if(ret.second==false)
                        continue;
    auto blk = ndn::nfd::FibEntry()
                   .setPrefix(entry.getPrefix())
                   .setNextHopRecords(std::begin(nexthops), std::end(nexthops))
                   .wireEncode();

    listSize += blk.size();
                    // ndn::MAX_NDN_PACKET_SIZE
                    if( listSize < 4096 )
                        context.append(blk);
		  }
  }

#endif

  context.end();
}

void
FibManager::setFaceForSelfRegistration(const Interest& request, ControlParameters& parameters)
{
  bool isSelfRegistration = (parameters.getFaceId() == 0);
  if (isSelfRegistration) {
    shared_ptr<lp::IncomingFaceIdTag> incomingFaceIdTag = request.getTag<lp::IncomingFaceIdTag>();
    // NDNLPv2 says "application MUST be prepared to receive a packet without IncomingFaceId field",
    // but it's fine to assert IncomingFaceId is available, because InternalFace lives inside NFD
    // and is initialized synchronously with IncomingFaceId field enabled.
    BOOST_ASSERT(incomingFaceIdTag != nullptr);
    parameters.setFaceId(*incomingFaceIdTag);
  }
}

} // namespace nfd
