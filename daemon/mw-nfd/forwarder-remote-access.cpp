
#include "forwarder-remote-access.hpp"
#include "fw/forwarder.hpp"
#include "face/face.hpp"
#include "core/version.hpp"
#include "face/face-system.hpp"
#include "face/protocol-factory.hpp"

#include "mw-nfd/mw-nfd-global.hpp"

#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-info.hpp>
#include <ndn-cxx/security/validator-null.hpp>
#include <ndn-cxx/security/validator-config.hpp>
#include <ndn-cxx/security/certificate-fetcher-direct-fetch.hpp>

#include <ndn-cxx/mgmt/nfd/face-status.hpp>
#include <ndn-cxx/mgmt/nfd/fib-entry.hpp>

#include <sstream>
#include <map>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/iostreams/operations.hpp>
#include <boost/iostreams/read.hpp>

using boost::property_tree::ptree;
using boost::property_tree::read_json;
using boost::property_tree::write_json;

#include <iostream>

using namespace ndn;
NFD_LOG_INIT(ForwarderRemoteAccess);

namespace nfd {

static const time::milliseconds STATUS_FRESHNESS(5000);

extern shared_ptr<FaceTable> g_faceTable;
extern Forwarder* g_mgmt_forwarder;

ForwarderRemoteAccess::ForwarderRemoteAccess( size_t imsLimit)
	:m_ims(imsLimit)
{
}

ndn::nfd::ForwarderStatus
ForwarderRemoteAccess::collectGeneralStatus()
{
  ndn::nfd::ForwarderStatus status;

  status.setNfdVersion(NFD_VERSION_BUILD_STRING);
  status.setStartTimestamp(g_startTimestamp);
  status.setCurrentTimestamp(time::system_clock::now());

  size_t nNameTree=0;
  size_t nFib=g_mgmt_forwarder->getFib().size();
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

  uint64_t __attribute__((unused)) inInt[16]={0,};
  uint64_t __attribute__((unused)) outInt[16]={0,};
  uint64_t __attribute__((unused)) inData[16]={0,};
  uint64_t __attribute__((unused)) outData[16]={0,};

  nNameTree+=g_mgmt_forwarder->getNameTree().size();
  nFib += g_mgmt_forwarder->getFib().size();
  nPit += g_mgmt_forwarder->getPit().size();
  nM +=  g_mgmt_forwarder->getMeasurements().size();
  nCs +=g_mgmt_forwarder->getCs().size();
  const ForwarderCounters& counters = g_mgmt_forwarder->getCounters();
  nInInterests+=(counters.nInInterests);
        nOutInterests +=(counters.nOutInterests);
        nInData +=(counters.nInData);
        nOutData += (counters.nOutData);
        nInNacks += (counters.nInNacks);
        nOutNacks += (counters.nOutNacks);
        nSatisfiedInterests += (counters.nSatisfiedInterests);
        nUnsatisfiedInterests +=(counters.nUnsatisfiedInterests);

#ifndef ETRI_NFD_ORG_ARCH
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
  }
#endif

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
  return status;
}

void ForwarderRemoteAccess::formatStatusJson( ptree& parent, const ndn::nfd::ForwarderStatus& item)
{
	ptree pt;
#if 1
  pt.put ("version", item.getNfdVersion());
  pt.put ("startTime", item.getStartTimestamp());
  pt.put ("currentTime", item.getCurrentTimestamp());
  pt.put ("uptime", time::duration_cast<time::seconds>(item.getCurrentTimestamp()-item.getStartTimestamp()));
  pt.put ("nNameTreeEntries", item.getNNameTreeEntries());
  pt.put ("nFibEntries", item.getNFibEntries());
  pt.put ("nPitEntries", item.getNPitEntries());
  pt.put ("nMeasurementsEntries", item.getNMeasurementsEntries());
  pt.put ("nCsEntries", item.getNCsEntries());
	pt.put("packetCounters.incomingPackets.nInterests", item.getNInInterests());
	pt.put("packetCounters.incomingPackets.nData", item.getNInData());
	pt.put("packetCounters.incomingPackets.nNacks", item.getNInNacks());
	pt.put("packetCounters.outgoingPackets.nInterests", item.getNOutInterests());
	pt.put("packetCounters.outgoingPackets.nData", item.getNOutData());
	pt.put("packetCounters.outgoingPackets.nNacks", item.getNOutNacks());
  pt.put ("nSatisfiedInterests", item.getNSatisfiedInterests());
  pt.put ("nUnsatisfiedInterests", item.getNUnsatisfiedInterests());
#endif

parent.add_child("nfdStatus.generalStatus", pt);
}

void ForwarderRemoteAccess::formatChannelsJson( ptree& parent )
{
	ptree pt;

	auto factories = g_faceSystem->listProtocolFactories();
  	for (const auto* factory : factories) {
    for (const auto& channel : factory->getChannels()) {
    	ptree ch_node;
    	ch_node.put("localUri", channel->getUri().toString());
    	pt.push_back(std::make_pair("", ch_node));
    }
  }

	parent.add_child("nfdStatus.channels.channel", pt);
}

template<typename T>
static void
copyMtu(const Face& face, T& to)
{
  if (face.getMtu() >= 0) {
    to.setMtu(std::min<size_t>(face.getMtu(), ndn::MAX_NDN_PACKET_SIZE));
  }
  else if (face.getMtu() == face::MTU_UNLIMITED) {
    to.setMtu(ndn::MAX_NDN_PACKET_SIZE);
  }
}

template<typename T>
static void
copyFaceProperties(const Face& face, T& to)
{
  to.setFaceId(face.getId())
    .setRemoteUri(face.getRemoteUri().toString())
    .setLocalUri(face.getLocalUri().toString())
    .setFaceScope(face.getScope())
    .setFacePersistency(face.getPersistency())
    .setLinkType(face.getLinkType());

  auto linkService = dynamic_cast<face::GenericLinkService*>(face.getLinkService());
  if (linkService != nullptr) {
    const auto& options = linkService->getOptions();
    to.setFlagBit(ndn::nfd::BIT_LOCAL_FIELDS_ENABLED, options.allowLocalFields)
      .setFlagBit(ndn::nfd::BIT_LP_RELIABILITY_ENABLED, options.reliabilityOptions.isEnabled)
      .setFlagBit(ndn::nfd::BIT_CONGESTION_MARKING_ENABLED, options.allowCongestionMarking);
  }
}

static ndn::nfd::FaceStatus
makeFaceStatus(const Face& face, const time::steady_clock::TimePoint& now)
{
  ndn::nfd::FaceStatus status;
  copyFaceProperties(face, status);

  auto expirationTime = face.getExpirationTime();
  if (expirationTime != time::steady_clock::TimePoint::max()) {
    status.setExpirationPeriod(std::max(0_ms,
                                        time::duration_cast<time::milliseconds>(expirationTime - now)));
  }

  auto linkService = dynamic_cast<face::GenericLinkService*>(face.getLinkService());
  if (linkService != nullptr) {
    const auto& options = linkService->getOptions();
    status.setBaseCongestionMarkingInterval(options.baseCongestionMarkingInterval)
          .setDefaultCongestionThreshold(options.defaultCongestionThreshold);
  }

  copyMtu(face, status);
  uint64_t nInInterests=0;
        uint64_t nOutInterests=0;
        uint64_t nInData=0;
        uint64_t nOutData=0;
        uint64_t nInNacks=0;
        uint64_t nOutNacks=0;
        uint64_t nInBytes=0;
        uint64_t nOutBytes=0;

        const auto& counters = face.getCounters();

        nInInterests +=counters.nInInterests;
    nOutInterests +=counters.nOutInterests;
    nInData +=counters.nInData;
    nOutData +=counters.nOutData;
    nInNacks +=counters.nInNacks;
    nOutNacks +=counters.nOutNacks;
    nInBytes +=counters.nInBytes;
    nOutBytes +=counters.nOutBytes;;


    uint64_t nIIs=0;
        uint64_t nIDs=0;
        uint64_t nINs=0;
        for(int i=0;i<getForwardingWorkers();i++){
                auto worker = getMwNfd(i);
                if(face.getId()==face::FACEID_INTERNAL_FACE) continue;
                if(face.getId()==face::FACEID_CONTENT_STORE) continue;
                if(worker!=nullptr){
#ifndef ETRI_NFD_ORG_ARCH
                        std::tie(nIIs, nIDs, nINs)=worker->getLinkServiceCounters(face.getId());
#endif
                        nInInterests +=nIIs;
                        nInData += nIDs;
                        nInNacks += nINs;
                }
        }
  status.setNInInterests(nInInterests)
        .setNOutInterests(nOutInterests)
        .setNInData(nInData)
        .setNOutData(nOutData)
        .setNInNacks(nInNacks)
        .setNOutNacks(nOutNacks)
        .setNInBytes(nInBytes)
        .setNOutBytes(nOutBytes);

  return status;
}
void ForwarderRemoteAccess::formatFacesJson( ptree& parent )
{
    ptree pt;
    auto now = time::steady_clock::now();

    for (const auto& face : *g_faceTable) {

        ptree face_node;
        ndn::nfd::FaceStatus status = makeFaceStatus(face, now);
        face_node.put("faceId", status.getFaceId());
        face_node.put("remoteUri", status.getRemoteUri());
        face_node.put("localUri", status.getLocalUri());

        if (status.hasExpirationPeriod()) {
            face_node.put("expirationPeriod", status.getExpirationPeriod());
        }

        face_node.put("faceScope", status.getFaceScope());
        face_node.put("facePersistency", status.getFacePersistency());
        face_node.put("linkeType", status.getLinkType());

        if (!status.hasBaseCongestionMarkingInterval() && !status.hasDefaultCongestionThreshold()) {
            face_node.put("congestion", "null");
        } else {
            if (status.hasBaseCongestionMarkingInterval()) {
                face_node.put("congestion.baseMarkingInterval", status.getBaseCongestionMarkingInterval());
            }
            if (status.hasDefaultCongestionThreshold()) {
                face_node.put("congestion.defaultThreshold", status.getDefaultCongestionThreshold());
            }
        }

        if (status.hasMtu()) {
            face_node.put("mtu", status.getMtu());
        }

        if (status.getFlags() == 0) {
            face_node.put("flags", "null");
        }
        else {
            face_node.put("flags.localFieldsEnabled", status.getFlagBit(ndn::nfd::BIT_LOCAL_FIELDS_ENABLED));
            face_node.put("flags.lpReliabilityEnabled", status.getFlagBit(ndn::nfd::BIT_LP_RELIABILITY_ENABLED));
            face_node.put("flags.congestionMarkingEnabled", status.getFlagBit(ndn::nfd::BIT_CONGESTION_MARKING_ENABLED));
        }

        face_node.put("packetCounters.incomingPackets.nInterests", status.getNInInterests());
        face_node.put("packetCounters.incomingPackets.nData", status.getNInData());
        face_node.put("packetCounters.incomingPackets.nNacks", status.getNInNacks());
        face_node.put("packetCounters.outgoingPackets.nInterests", status.getNOutInterests());
        face_node.put("packetCounters.outgoingPackets.nData", status.getNOutData());
        face_node.put("packetCounters.outgoingPackets.nNacks", status.getNOutNacks());

        face_node.put("byteCounters.incomingBytes", status.getNInBytes());
        face_node.put("byteCounters.outgoingBytes", status.getNOutBytes());
        pt.push_back(std::make_pair("", face_node));
    }
    parent.add_child("nfdStatus.faces.face", pt);
}
void ForwarderRemoteAccess::formatRibJson( ptree& parent )
{
    ptree pt;
    parent.add_child("nfdStatus.rib", pt);
}
void ForwarderRemoteAccess::formatFibJson( ptree& parent )
{
    ptree pt;

    for (const auto& entry : g_mgmt_forwarder->getFib()) {
        const auto& nexthops = entry.getNextHops() |
            boost::adaptors::transformed([] (const fib::NextHop& nh) {
                    return ndn::nfd::NextHopRecord()
                    .setFaceId(nh.getFace().getId())
                    .setCost(nh.getCost());
                    });

        ndn::nfd::FibEntry fib;
        fib.setPrefix(entry.getPrefix());
        fib.setNextHopRecords(std::begin(nexthops), std::end(nexthops)) ;
        ptree fib_node;
        fib_node.put("prefix", fib.getPrefix());

#if 1
        for (const ndn::nfd::NextHopRecord& nh : fib.getNextHopRecords()) {
            fib_node.put("nextHops.nexthop.faceId", nh.getFaceId());
            fib_node.put("nextHops.nexthop.cost", nh.getCost());
        }
#endif

        pt.push_back(std::make_pair("", fib_node));
    }


    int32_t workers = getForwardingWorkers();

#ifndef ETRI_NFD_ORG_ARCH
    for(int32_t i=0;i<workers;i++){
        auto worker = getMwNfd(i);
        if(worker==nullptr){
            continue;
        }

        for (const auto& entry : worker->getFibTable()) {
            const auto& nexthops = entry.getNextHops() |
                boost::adaptors::transformed([] (const fib::NextHop& nh) {
                        return ndn::nfd::NextHopRecord()
                        .setFaceId(nh.getFace().getId())
                        .setCost(nh.getCost());
                        });

            ndn::nfd::FibEntry fib;
            fib.setPrefix(entry.getPrefix());
            fib.setNextHopRecords(std::begin(nexthops), std::end(nexthops)) ;

            ptree fib_node;
            fib_node.put("prefix", fib.getPrefix());

            for (const ndn::nfd::NextHopRecord& nh : fib.getNextHopRecords()) {
                fib_node.put("nextHops.nexthop.faceId", nh.getFaceId());
                fib_node.put("nextHops.nexthop.cost", nh.getCost());
            }
            pt.push_back(std::make_pair("", fib_node));

        }
    }
#endif
    parent.add_child("nfdStatus.fib.fibEntry", pt);
}

void ForwarderRemoteAccess::formatScJson( ptree& parent )
{
	ptree pt;
#ifndef ETRI_NFD_ORG_ARCH
 auto worker = getMwNfd(0);
        if(worker!=nullptr){
                for (const auto& i : worker->getStrategyChoiceTable()) {
    	ptree ns;
    	ns.put("namespace", i.getPrefix().toUri());
    	ns.put("strategy.name", i.getStrategyInstanceName().toUri());
    	pt.push_back(std::make_pair("", ns));

                }
        }else{
                for (const auto& i : g_mgmt_forwarder->getStrategyChoice()) {
    	ptree ns;
    	ns.put("namespace", i.getPrefix().toUri());
    	ns.put("strategy.name", i.getStrategyInstanceName().toUri());
    	pt.push_back(std::make_pair("", ns));

		}
        }
#endif
	parent.add_child("nfdStatus.strategyChoices.strategyChoice", pt);
}
void ForwarderRemoteAccess::formatCsJson( ptree& parent )
{
        //ndn::nfd::CsInfo info;

	ptree pt;
        int32_t workers = getForwardingWorkers();
        size_t NEntries = 0;
        size_t NHits = 0;
        size_t NMisses = 0;
        size_t NCapa = 0;

#ifndef ETRI_NFD_ORG_ARCH
        if(workers==0){
          //      NCapa += m_cs.getLimit();
           //     info.setEnableAdmit(m_cs.shouldAdmit());
            //    info.setEnableServe(m_cs.shouldServe());
        }else{

                for(int32_t i=0;i<workers;i++){
                        auto worker = getMwNfd(i);
                        NCapa += worker->getCsTable().getLimit();
                        NEntries += worker->getCsTable().size();
                        NHits += worker->getCountersInfo().nCsHits;
                        NMisses += worker->getCountersInfo().nCsMisses;

                }
        }
#endif

        NEntries += g_mgmt_forwarder->getCs().size();

  pt.put ("capacity", NCapa);
  pt.put ("nEntries", NEntries);
  pt.put ("nHits", NHits);
  pt.put ("nMisses", NMisses);
parent.add_child("nfdStatus.cs", pt);
}

std::string
ForwarderRemoteAccess::prepareNextData()
{
    ptree nfd_info;
    auto status = this->collectGeneralStatus();
    formatStatusJson(nfd_info, status);
    formatChannelsJson(nfd_info);
    formatFacesJson(nfd_info);
    formatFibJson(nfd_info);
    formatRibJson(nfd_info);
    formatCsJson(nfd_info);
    formatScJson(nfd_info);

    std::ostringstream buf;
    write_json (buf, nfd_info, false);
    std::string nfdStatus = buf.str();
    return nfdStatus;
}

bool
ForwarderRemoteAccess::replyFromStore(const ndn::Interest& interest, ndn::Face &face)
{
	auto it = m_ims.find(interest);

	//std::cout << "replyFromStore: " << interest << std::endl;
	if (it != nullptr) {
		face.put(*it);
		return true;
	}
	return false;
}

void
ForwarderRemoteAccess::publish(const ndn::Name& dataName, const Interest& interest, ndn::Face &face)
{

    const ndn::Name& interestName = interest.getName();
    uint64_t interestSegment = 0;
    if (interestName[-1].isSegment()) {
        interestSegment = interestName[-1].toSegment();
    }

    if(interestSegment==0){
        m_nfdStatus = prepareNextData();
//	std::cout << "m_nfdStatus: " << m_nfdStatus.length() << std::endl;
    }

    auto buffer = std::make_shared<const ndn::Buffer>(m_nfdStatus.c_str(), m_nfdStatus.length());

    const uint8_t* rawBuffer = buffer->data();
    const uint8_t* segmentBegin = rawBuffer;
    const uint8_t* end = rawBuffer + buffer->size();

    size_t maxPacketSize = (ndn::MAX_NDN_PACKET_SIZE >> 1); 

    uint64_t totalSegments = buffer->size() / maxPacketSize;

    ndn::Name segmentPrefix(dataName);
    segmentPrefix.appendVersion();

    uint64_t segmentNo = 0;
    do {
        const uint8_t* segmentEnd = segmentBegin + maxPacketSize;
        if (segmentEnd > end) {
            segmentEnd = end;
        }   

        ndn::Name segmentName(segmentPrefix);
        segmentName.appendSegment(segmentNo);

        // We get a std::exception: bad_weak_ptr from m_ims if we don't use shared_ptr for data
        auto data = std::make_shared<ndn::Data>(segmentName);
	//auto pit = interest.getTag<lp::PitToken>();
	//if(pit!=nullptr) data->setTag(pit);
        data->setContent(segmentBegin, segmentEnd - segmentBegin);
        data->setFreshnessPeriod(1_s);
        data->setFinalBlock(ndn::name::Component::fromSegment(totalSegments));

        segmentBegin = segmentEnd;
	std::string key;
        //m_keyChain.sign(*data,  security::SigningInfo(security::SigningInfo::SIGNER_TYPE_SHA256));
        //m_keyChain.sign(*data,  security::SigningInfo(key));
        //m_keyChain.sign(*data,  security::SigningInfo(security::SigningInfo::SIGNER_TYPE_ID, "/etri"));
        m_keyChain.sign(*data);

        // Put on face only the segment which has a pending interest
        // otherwise the segment is unsolicited
        if (interestSegment == segmentNo) {
            face.put(*data);
        }   

	m_ims.insert(*data, 4_s);
	getScheduler().schedule(4_s, [this, segmentName] { 
			m_ims.erase(segmentName); });

        ++segmentNo;
    } while (segmentBegin < end);

    //std::cout << "ims_size:" << m_ims.size() << ", segmentNo: " << segmentNo << std::endl;
}



} // namespace nfd
