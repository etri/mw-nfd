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

#include "cs-manager.hpp"
#include "fw/forwarder-counters.hpp"
#include "table/cs.hpp"
#include "mw-nfd/mw-nfd-global.hpp"

#include <ndn-cxx/mgmt/nfd/cs-info.hpp>

namespace nfd {

constexpr size_t CsManager::ERASE_LIMIT;

CsManager::CsManager(Cs& cs, const ForwarderCounters& fwCounters,
                     Dispatcher& dispatcher, CommandAuthenticator& authenticator)
  : ManagerBase("cs", dispatcher, authenticator)
  , m_cs(cs)
  , m_fwCounters(fwCounters)
{
  registerCommandHandler<ndn::nfd::CsConfigCommand>("config",
    bind(&CsManager::changeConfig, this, _4, _5));
  registerCommandHandler<ndn::nfd::CsEraseCommand>("erase",
    bind(&CsManager::erase, this, _4, _5));

  registerStatusDatasetHandler("info", bind(&CsManager::serveInfo, this, _1, _2, _3));
}

#ifndef ETRI_NFD_ORG_ARCH
void
CsManager::changeConfig(const ControlParameters& parameters,
                        const ndn::mgmt::CommandContinuation& done)
{
  using ndn::nfd::CsFlagBit;

  int32_t workers = getForwardingWorkers();
  for(int32_t i=0;i<workers;i++){
      auto worker = getMwNfd(i);
      if(worker==nullptr)
          continue;
      if (parameters.hasCapacity()) {
          worker->getCsTable().setLimit(parameters.getCapacity());
      }

      if (parameters.hasFlagBit(CsFlagBit::BIT_CS_ENABLE_ADMIT)) {
          worker->getCsTable().enableAdmit(parameters.getFlagBit(CsFlagBit::BIT_CS_ENABLE_ADMIT));
      }

      if (parameters.hasFlagBit(CsFlagBit::BIT_CS_ENABLE_SERVE)) {
          worker->getCsTable().enableServe(parameters.getFlagBit(CsFlagBit::BIT_CS_ENABLE_SERVE));
      }

  }

  ControlParameters body;

  auto worker = getMwNfd(0);
  if(worker==nullptr){
    done(ControlResponse(501, "InternalError").setBody(body.wireEncode()));
  }

  body.setCapacity(worker->getCsTable().getLimit());
  body.setFlagBit(CsFlagBit::BIT_CS_ENABLE_ADMIT, worker->getCsTable().shouldAdmit(), false);
  body.setFlagBit(CsFlagBit::BIT_CS_ENABLE_SERVE, worker->getCsTable().shouldServe(), false);
  done(ControlResponse(200, "OK").setBody(body.wireEncode()));
}
#else

void
CsManager::changeConfig(const ControlParameters& parameters,
                                const ndn::mgmt::CommandContinuation& done)
{
    using ndn::nfd::CsFlagBit;

    if (parameters.hasCapacity()) {
        m_cs.setLimit(parameters.getCapacity());
    }

    if (parameters.hasFlagBit(CsFlagBit::BIT_CS_ENABLE_ADMIT)) {
        m_cs.enableAdmit(parameters.getFlagBit(CsFlagBit::BIT_CS_ENABLE_ADMIT));
    }

    if (parameters.hasFlagBit(CsFlagBit::BIT_CS_ENABLE_SERVE)) {
        m_cs.enableServe(parameters.getFlagBit(CsFlagBit::BIT_CS_ENABLE_SERVE));
    }

    ControlParameters body;
    body.setCapacity(m_cs.getLimit());
    body.setFlagBit(CsFlagBit::BIT_CS_ENABLE_ADMIT, m_cs.shouldAdmit(), false);
    body.setFlagBit(CsFlagBit::BIT_CS_ENABLE_SERVE, m_cs.shouldServe(), false);
    done(ControlResponse(200, "OK").setBody(body.wireEncode()));
}
#endif

#ifndef ETRI_NFD_ORG_ARCH
void
CsManager::erase(const ControlParameters& parameters,
                 const ndn::mgmt::CommandContinuation& done)
{
  ControlParameters body;
  body.setName(parameters.getName());

// added by ETRI(modori) on 20200914
  size_t nTotalErased = 0;
  auto pa = make_shared<ndn::nfd::ControlParameters>(parameters);
  nTotalErased = emitMwNfdcCommand(-1, MW_NFDC_MGR_CS, MW_NFDC_VERB_ERASE, nullptr, pa, false);

  body.setCount(nTotalErased);
  done(ControlResponse(200, "OK").setBody(body.wireEncode()));

}

#else

    void
CsManager::erase(const ControlParameters& parameters,
        const ndn::mgmt::CommandContinuation& done)
{
    size_t count = parameters.hasCount() ?
        parameters.getCount() :
        std::numeric_limits<size_t>::max();
    m_cs.erase(parameters.getName(), std::min(count, ERASE_LIMIT),
            [=] (size_t nErased) {
            ControlParameters body;
            body.setName(parameters.getName());
            body.setCount(nErased);
            if (nErased == ERASE_LIMIT && count > ERASE_LIMIT) {
            m_cs.find(Interest(parameters.getName()).setCanBePrefix(true),
                    [=] (const Interest&, const Data&) mutable {
                    body.setCapacity(ERASE_LIMIT);
                    done(ControlResponse(200, "OK").setBody(body.wireEncode()));
                    },
                    [=] (const Interest&) {
                    done(ControlResponse(200, "OK").setBody(body.wireEncode()));
                    });
            }
            else {
            done(ControlResponse(200, "OK").setBody(body.wireEncode()));
            }
            });
}

#endif

#ifndef ETRI_NFD_ORG_ARCH
void
CsManager::serveInfo(const Name& topPrefix, const Interest& interest,
                     ndn::mgmt::StatusDatasetContext& context) const
{
  ndn::nfd::CsInfo info;

#if 1
  int32_t workers = getForwardingWorkers();
  size_t NEntries = 0;
  size_t NHits = 0;
  size_t NMisses = 0;
  info.setCapacity(m_cs.getLimit());
  info.setEnableAdmit(m_cs.shouldAdmit());
  info.setEnableServe(m_cs.shouldServe());

  for(int32_t i=0;i<workers;i++){
      auto worker = getMwNfd(i);
      NEntries += worker->getCsTable().size();
      NHits += worker->getCountersInfo().nCsHits;
      NMisses += worker->getCountersInfo().nCsMisses;

  }
    info.setNEntries(NEntries);
    info.setNHits(NHits);
    info.setNMisses(NMisses);
#else
  info.setCapacity(m_cs.getLimit());
  info.setEnableAdmit(m_cs.shouldAdmit());
  info.setEnableServe(m_cs.shouldServe());
  info.setNEntries(m_cs.size());
  info.setNHits(m_fwCounters.nCsHits);
  info.setNMisses(m_fwCounters.nCsMisses);

#endif

  context.append(info.wireEncode());
  context.end();
}

#else
void
CsManager::serveInfo(const Name& topPrefix, const Interest& interest,
                             ndn::mgmt::StatusDatasetContext& context) const
{
    ndn::nfd::CsInfo info;
    info.setCapacity(m_cs.getLimit());
    info.setEnableAdmit(m_cs.shouldAdmit());
    info.setEnableServe(m_cs.shouldServe());
    info.setNEntries(m_cs.size());
    info.setNHits(m_fwCounters.nCsHits);
    info.setNMisses(m_fwCounters.nCsMisses);

    context.append(info.wireEncode());
    context.end();
}
#endif

} // namespace nfd
