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

#include <chrono>
#include <thread>
#include <memory>
#include <iostream>

#include "nfd.hpp"
#include "common/global.hpp"
#include "common/logger.hpp"
#include "common/privilege-helper.hpp"
#include "mw-nfd/mw-nfd-global.hpp"
#include "common/city-hash.hpp"
#include "face/face-system.hpp"
#include "face/protocol-factory.hpp"
#include "face/udp-factory.hpp"
#include "face/internal-face.hpp"
#include "face/null-face.hpp"
#include "fw/face-table.hpp"
#include "fw/forwarder.hpp"
#include "mgmt/cs-manager.hpp"
#include "mgmt/face-manager.hpp"
#include "mgmt/fib-manager.hpp"
#include "mgmt/forwarder-status-manager.hpp"
#include "mgmt/general-config-section.hpp"
#include "mgmt/log-config-section.hpp"
#include "mgmt/strategy-choice-manager.hpp"
#include "mgmt/tables-config-section.hpp"
#include <ndn-cxx/security/signing-info.hpp>

#include <boost/property_tree/info_parser.hpp>

namespace nfd {

std::shared_ptr<FaceTable> g_faceTable=nullptr;

NFD_LOG_INIT(Nfd);

const std::string INTERNAL_CONFIG("internal://nfd.conf");

Nfd::Nfd(ndn::KeyChain& keyChain)
  : m_keyChain(keyChain)
  , m_netmon(make_shared<ndn::net::NetworkMonitor>(getGlobalIoService()))
  , m_fibSignalSet(getGlobalIoService())
{
  // Disable automatic verification of parameters digest for decoded Interests.
  Interest::setAutoCheckParametersDigest(false);

//  m_fibSignalSet.add(SIGQUIT);
 // m_fibSignalSet.add(SIGUSR2);
}

Nfd::Nfd(const std::string& configFile, ndn::KeyChain& keyChain)
  : Nfd(keyChain)
{
  m_configFile = configFile;
}

Nfd::Nfd(const ConfigSection& config, ndn::KeyChain& keyChain)
  : Nfd(keyChain)
{
  m_configSection = config;
}

// It is necessary to explicitly define the destructor, because some member variables (e.g.,
// unique_ptr<Forwarder>) are forward-declared, but implicitly declared destructor requires
// complete types for all members when instantiated.
Nfd::~Nfd() = default;

Forwarder* g_mgmt_forwarder;

void Nfd::initialize()
{
  configureLogging();
  g_faceTable = m_faceTable = make_shared<FaceTable>();

  m_faceTable->addReserved(face::makeNullFace(), face::FACEID_NULL);
  m_faceTable->addReserved(face::makeNullFace(FaceUri("contentstore://")), face::FACEID_CONTENT_STORE);
  m_faceSystem = make_unique<face::FaceSystem>(*m_faceTable, m_netmon);
	g_faceSystem = m_faceSystem.get();

  m_forwarder = make_unique<Forwarder>(*m_faceTable);
  g_mgmt_forwarder = m_forwarder.get();

  initializeManagement();

  PrivilegeHelper::drop();

  m_netmon->onNetworkStateChanged.connect([this] {
    // delay stages, so if multiple events are triggered in short sequence,
    // only one auto-detection procedure is triggered
    m_reloadConfigEvent = getScheduler().schedule(5_s, [this] {
      NFD_LOG_INFO("Network change detected, reloading face section of the config file...");
      reloadConfigFileFaceSection();
    });
  });

  if(getBulkFibTest()){
      /* added by modori to support UDP bulk Test on 2k210503 */
      FaceUri remoteUri0(g_bulkFibTestPort0);
      FaceUri remoteUri1(g_bulkFibTestPort1);
      int  __attribute__((unused)) ret;
      if(remoteUri0.getScheme()=="udp4" or remoteUri0.getScheme()=="tcp4") {
          std::string cmd = "nfdc face create ";
          cmd.append(g_bulkFibTestPort0);
          ret=system(cmd.c_str());
      }
      if(remoteUri1.getScheme()=="udp4" or remoteUri1.getScheme()=="tcp4") {
          std::string cmd = "nfdc face create ";
          cmd.append(g_bulkFibTestPort1);
          ret=system(cmd.c_str());
      }
  }

#ifdef ETRI_NFD_ORG_ARCH
    if(getBulkFibTest()){
        getScheduler().schedule(5_s, [this] {
                try{

		bool done = false;
		FaceId faceId0 = 0;
		FaceId faceId1 = 0;

		FaceUri uri0;
		FaceUri uri1;

		FaceUri faceUri0(g_bulkFibTestPort0);
		FaceUri faceUri1(g_bulkFibTestPort1);

		do{ 
		FaceTable::const_iterator it; 
		FaceUri uri;

		//std::cout << "g_bulkFibTestPort0: " << g_bulkFibTestPort0 << std::endl;
		for ( it=m_faceTable->begin(); it != m_faceTable->end() ;it++ ) { 

		if( faceUri0.getScheme()=="udp4"){
			uri0 = it->getRemoteUri();
		}else if( faceUri0.getScheme()=="tcp4")
			uri0 = it->getRemoteUri();
		else if( faceUri0.getScheme()=="ether")
			uri0 = it->getLocalUri();
		else if( faceUri0.getScheme()=="dev")
			uri0 = it->getLocalUri();
		else
			uri0 = it->getLocalUri();

		if( faceUri1.getScheme()=="udp4"){
			uri1 = it->getRemoteUri();
		}else if( faceUri1.getScheme()=="tcp4")
			uri1 = it->getRemoteUri();
		else if( faceUri1.getScheme()=="ether")
			uri1 = it->getLocalUri();
		else if( faceUri1.getScheme()=="dev")
			uri1 = it->getLocalUri();
		else
			uri1 = it->getLocalUri();

		if( uri0.getScheme() == faceUri0.getScheme() ){
			if( uri0.getHost() == faceUri0.getHost() ){
				faceId0 = it->getId();
			}
		}

		if( uri1.getScheme() == faceUri1.getScheme() ){
			if( uri1.getHost() == faceUri1.getHost() ){
				faceId1 = it->getId();
			}
		}


		if( faceId0 != 0 and faceId1 != 0 ){
			config_bulk_fib(faceId0, faceId1, getBulkFibFilePath());
			done = true;
		}   
		}
		}while(!done);

		}catch(const std::exception& e){
		}
        });
    }
#endif

}


bool Nfd::config_bulk_fib(FaceId faceId0, FaceId faceId1, std::string fib_path)
{
    FILE *fp;
    char line[1024]={0,};
    uint64_t cost = 0;
    int ndx = 0;
    int line_cnt=0;
    FaceUri uri;
    FaceId nextHopId;
    size_t fibs=0;
    char* ptr __attribute__((unused));

    fp =  fopen (fib_path.c_str(), "r");

    if (fp==NULL) {
        return false;
    }

    while ( !feof(fp) ) {
        ptr=fgets(line, sizeof(line), fp);
        line_cnt ++;
    }
    line_cnt -=1;
    fclose(fp);

    fp =  fopen (fib_path.c_str(), "r");

    while ( !feof(fp) ) {
        ptr = fgets(line, sizeof(line), fp);
        if(strlen(line)==0) continue;
        if(line[0]=='"') continue;

        line[strlen(line)-1]='\0';
        Name prefix(line);

        if(prefix.size() <=0){
            ndx++;
            continue;
        }

        if(ndx >= line_cnt/2){
            nextHopId = faceId0;
        }else{
            nextHopId = faceId1;
        }

        Face* face = m_faceTable->get(nextHopId);

        fib::Entry * entry = m_forwarder->getFib().insert(prefix).first;
        if(entry!=nullptr){
            m_forwarder->getFib().addOrUpdateNextHop(*entry, *face, cost);
            fibs += 1;
        }

        ndx++;
        memset(line, '\0', sizeof(line));
    }
    fclose(fp);

    return true;
}

void
Nfd::configureLogging()
{
  ConfigFile config(&ConfigFile::ignoreUnknownSection);
  log::setConfigFile(config);

  if (!m_configFile.empty()) {
    config.parse(m_configFile, true);
    config.parse(m_configFile, false);
  }
  else {
    config.parse(m_configSection, true, INTERNAL_CONFIG);
    config.parse(m_configSection, false, INTERNAL_CONFIG);
  }
}

inline void
ignoreRibAndLogSections(const std::string& filename, const std::string& sectionName,
                        const ConfigSection& section, bool isDryRun)
{
  // Ignore "log" and "rib" sections, but raise an error if we're missing a
  // handler for an NFD section.
  if (sectionName == "rib" || sectionName == "log" || sectionName =="mw-nfd") {
    // do nothing
  }
  else {
    // missing NFD section
    ConfigFile::throwErrorOnUnknownSection(filename, sectionName, section, isDryRun);
  }
}

void Nfd::onInterestRemoteAccess(const ndn::Name& name, const ndn::Interest& interest)
{
#ifndef ETRI_NFD_ORG_ARCH
    //if (interestName[-2].isVersion()) {
        //m_forwarderRemoteAccess.replyFromStore(interest, *m_internalClientFaceRemoteAccess);
    //}else
        m_forwarderRemoteAccess.publish(name, interest, *m_internalClientFaceRemoteAccess);
#endif
    return;
}

void
Nfd::initializeManagement()
{
  std::tie(m_internalFace, m_internalClientFace) = face::makeInternalFace(m_keyChain);
  m_faceTable->addReserved(m_internalFace, face::FACEID_INTERNAL_FACE);

  m_dispatcher = make_unique<ndn::mgmt::Dispatcher>(*m_internalClientFace, m_keyChain);
  m_authenticator = CommandAuthenticator::create();

  m_faceManager = make_unique<FaceManager>(*m_faceSystem, *m_dispatcher, *m_authenticator);
  m_fibManager = make_unique<FibManager>(m_forwarder->getFib(), *m_faceTable,
                                         *m_dispatcher, *m_authenticator);
  m_csManager = make_unique<CsManager>(m_forwarder->getCs(), m_forwarder->getCounters(),
                                       *m_dispatcher, *m_authenticator);
  m_strategyChoiceManager = make_unique<StrategyChoiceManager>(m_forwarder->getStrategyChoice(),
                                                               *m_dispatcher, *m_authenticator);

  m_forwarderStatusManager = make_unique<ForwarderStatusManager>(*m_forwarder, *m_dispatcher);

  ConfigFile config(&ignoreRibAndLogSections);
  general::setConfigFile(config);

  TablesConfigSection tablesConfig(*m_forwarder);
  tablesConfig.setConfigFile(config);

  m_authenticator->setConfigFile(config);
  m_faceSystem->setConfigFile(config);

  // parse config file
  if (!m_configFile.empty()) {
    config.parse(m_configFile, true);
    config.parse(m_configFile, false);
  }
  else {
    config.parse(m_configSection, true, INTERNAL_CONFIG);
    config.parse(m_configSection, false, INTERNAL_CONFIG);
  }

  tablesConfig.ensureConfigured();

  // add FIB entry for NFD Management Protocol
  Name topPrefix("/localhost/nfd");
  fib::Entry* entry = m_forwarder->getFib().insert(topPrefix).first;
  m_forwarder->getFib().addOrUpdateNextHop(*entry, *m_internalFace, 0);
  m_dispatcher->addTopPrefix(topPrefix, false);

  std::tie(m_internalFaceRemoteAccess, m_internalClientFaceRemoteAccess) = face::makeInternalFace(m_keyChain);
  m_faceTable->addReserved(m_internalFaceRemoteAccess, FACEID_REMOTE_ACCESS);
  m_internalClientFaceRemoteAccess->setInterestFilter(getRouterName()+"/nfd/status", 
          std::bind(&Nfd::onInterestRemoteAccess, this, _1, _2)
          );
}

void
Nfd::reloadConfigFile()
{
  configureLogging();

  ConfigFile config(&ignoreRibAndLogSections);
  general::setConfigFile(config);

  TablesConfigSection tablesConfig(*m_forwarder);
  tablesConfig.setConfigFile(config);

  m_authenticator->setConfigFile(config);
  m_faceSystem->setConfigFile(config);

  if (!m_configFile.empty()) {
    config.parse(m_configFile, false);
  }
  else {
    config.parse(m_configSection, false, INTERNAL_CONFIG);
  }
}

void
Nfd::reloadConfigFileFaceSection()
{
  ConfigFile config(&ConfigFile::ignoreUnknownSection);
  m_faceSystem->setConfigFile(config);

  if (!m_configFile.empty()) {
      config.parse(m_configFile, false);
  }
  else {
      config.parse(m_configSection, false, INTERNAL_CONFIG);
  }
}

} // namespace nfd
