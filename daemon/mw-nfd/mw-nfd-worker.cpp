
#include <chrono>
#include <thread>
#include <memory>

#include "mw-nfd-worker.hpp"
#include "common/global.hpp"
#include "mw-nfd-global.hpp"
#include "common/privilege-helper.hpp"
#include "face/face-system.hpp"
#include "face/internal-face.hpp"
#include "face/null-face.hpp"
#include "face/link-service.hpp"
#include "face/generic-link-service.hpp"
#include "fw/face-table.hpp"
#include "fw/forwarder.hpp"
#include "fw/scope-prefix.hpp"
#include "mgmt/cs-manager.hpp"
#include "mgmt/face-manager.hpp"
#include "mgmt/fib-manager.hpp"
#include "mgmt/forwarder-status-manager.hpp"
#include "mgmt/general-config-section.hpp"
#include "mgmt/log-config-section.hpp"
#include "mgmt/strategy-choice-manager.hpp"
#include "mgmt/tables-config-section.hpp"
#include <ndn-cxx/meta-info.hpp>
#include <ndn-cxx/lp/packet.hpp>
#include <ndn-cxx/lp/pit-token.hpp>
#include <ndn-cxx/lp/tags.hpp>
#include <ndn-cxx/encoding/block.hpp>
#include <ndn-cxx/encoding/buffer.hpp>
#include <ndn-cxx/net/ethernet.hpp>
#include "table/cleanup.hpp"

#include <sys/types.h> 
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/fcntl.h>

#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <ostream>
#include <boost/iostreams/device/file.hpp>
#include <boost/iostreams/stream.hpp>
#include <ndn-cxx/transport/unix-transport.hpp>

#include "face/lp-reassembler.hpp"
#include "common/city-hash.hpp"

#include "mgmt/cs-manager.hpp"
#include <ndn-cxx/mgmt/nfd/fib-entry.hpp>

nfd::face::Face *face0=nullptr;
nfd::face::Face *face1=nullptr;

namespace io = boost::iostreams;
extern std::map<std::string, int32_t> g_inputWorkerList;

using namespace std;

namespace nfd {
extern shared_ptr<FaceTable> g_faceTable;


MwNfd::MwNfd(int8_t wid, boost::asio::io_service* ios, ndn::KeyChain& keyChain, const nfd::face::GenericLinkService::Options& options)
    : m_keyChain(keyChain)
  , m_logger(getGlobalLogger())
  , m_workerId(wid)
  , m_terminationSignalSet(*ios)
  , m_fibSignalSet(*ios)
  , nInNetInvalid(0)
  , nInInterests(1)
  , nInDatas(1)
  , nInNacks(0)
    ,m_done(false)
,m_reassembler(options.reassemblerOptions)
    ,m_face(std::move(make_shared<ndn::UnixTransport>("/var/run/nfd.sock")), getGlobalIoService(), m_keyChain)
    ,m_faceMonitor(m_face)

    {
        // Disable automatic verification of parameters digest for decoded Interests.
    //    Interest::setAutoCheckParametersDigest(false);
        m_terminationSignalSet.add(SIGINT);
        m_terminationSignalSet.add(SIGTERM);
        m_terminationSignalSet.async_wait(bind(&MwNfd::terminate, this, _1, _2));
        m_done = false;
        m_ios = ios;

        struct addrinfo hints, *servinfo, *p;
        int rv;

        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_PASSIVE; // use my IP

        if ((rv = getaddrinfo(NULL, std::to_string(MW_NFDC_PORT+wid).c_str(), &hints, &servinfo)) != 0) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        }

        // loop through all the results and bind to the first we can
        for(p = servinfo; p != NULL; p = p->ai_next) {
            if ((m_sockNfdcCmd = socket(p->ai_family, p->ai_socktype,
                            p->ai_protocol)) == -1) {
                perror("listener: socket");
                continue;
            }

            if (bind(m_sockNfdcCmd, p->ai_addr, p->ai_addrlen) == -1) {
                close(m_sockNfdcCmd);
                perror("listener: bind");
                continue;
            }

            break;
        }

        fcntl(m_sockNfdcCmd, F_SETFL, O_NONBLOCK); 

        if (p == NULL) {
            fprintf(stderr, "listener: failed to bind socket\n");
        }

        freeaddrinfo(servinfo);


        m_faceMonitor.onNotification.connect(bind(&MwNfd::onNotification, this, _1));
        m_faceMonitor.start();
    }

// It is necessary to explicitly define the destructor, because some member variables (e.g.,
// unique_ptr<Forwarder>) are forward-declared, but implicitly declared destructor requires
// complete types for all members when instantiated.
MwNfd::~MwNfd() = default;

void
    MwNfd::onNotification(const ndn::nfd::FaceEventNotification& notification)
    {
        if (notification.getKind() == ndn::nfd::FACE_EVENT_DESTROYED) {
            nfd::face::Face * face = m_faceTable->get(notification.getFaceId());
            if(face!=nullptr){
                cleanupOnFaceRemoval(
                    m_forwarder->getNameTree(), 
                    m_forwarder->getFib(), 
                    m_forwarder->getPit(), 
                    *face);
            }
        }
    }


Fib& MwNfd::getFibTable()
{
	return m_forwarder->getFib();
}
Cs& MwNfd::getCsTable()
{
	return m_forwarder->getCs();
}

const ForwarderCounters& MwNfd::getCountersInfo()
{
    return m_forwarder->getCounters();
}

StrategyChoice& MwNfd::getStrategyChoiceTable()
{
    return m_forwarder->getStrategyChoice();
}

NameTree& MwNfd::getNameTreeTable()
{
    return m_forwarder->getNameTree();
}

Pit &MwNfd::getPitTable()
{
    return m_forwarder->getPit();
}

Measurements& MwNfd::getMeasurementsTable()
{
    
    return m_forwarder->getMeasurements();
}

#if 1
void MwNfd::handleNfdcCommand()
{
using ndn::nfd::CsFlagBit;

    struct sockaddr_storage their_addr;
    char buf[1024]={0,};
    int numbytes;
    socklen_t addr_len;

    mw_nfdc_ptr nfdc = (mw_nfdc_ptr)buf;

    addr_len = sizeof their_addr;
    if ((numbytes = recvfrom(m_sockNfdcCmd, buf, sizeof(mw_nfdc) , 0,
                    (struct sockaddr *)&their_addr, &addr_len)) == -1) {
        //perror("recvfrom");
        return;
    }

    if(numbytes>0){

        if(nfdc->parameters!=nullptr and m_workerId==0){
            //m_logger.info("nfdc - MGR:{}, Verb:{}", MW_NFDC_MGR_FIELD[nfdc->mgr], MW_NFDC_VERB_FIELD[nfdc->verb]);
            //std::cout << *nfdc->parameters << std::endl;
        }

        if(nfdc->mgr == MW_NFDC_MGR_FIB){

            if(nfdc->verb == MW_NFDC_VERB_ADD){

                const Name& prefix = nfdc->parameters->getName();
                FaceId faceId = nfdc->parameters->getFaceId();
                uint64_t cost = nfdc->parameters->getCost();
                Face* face = m_faceTable->get(faceId);
                if (face == nullptr) {
                    nfdc->ret = MW_NFDC_CMD_NOK;
                    goto response;
                }

				if(prefix.size() <=0){
					m_logger.info("prefix.size({}) is {}", prefix.size());
                    nfdc->ret = MW_NFDC_CMD_NOK;
                    goto response;
				}

                // for network name parameter
                if( nfdc->netName ){
                    fib::Entry* entry = m_forwarder->getFib().insert(prefix).first;
                    getFibTable().addOrUpdateNextHop(*entry, *face, cost);
					//m_logger.info("Worker[{}] added prefix into FIB with net-name", m_workerId);
                    goto response;
                }

                if(prefix.size() >= getPrefixLength4Distribution() and getFibSharding() ){
				    auto block = prefix.wireEncode();
                    int32_t wid;//, ndnType;
                    //std::tie(ndnType, wid) = dissectNdnPacket(prefix.wireEncode().wire(), prefix.wireEncode().size());
                    wid = computeWorkerId(block.wire(), block.size());
                    if(wid!=m_workerId){
                        nfdc->ret = MW_NFDC_CMD_NOK;
                        goto response;
                    }
                }
					//m_logger.info("Worker[{}] added prefix into FIB({})", m_workerId, prefix.toUri());
                fib::Entry* entry = m_forwarder->getFib().insert(prefix).first;
                getFibTable().addOrUpdateNextHop(*entry, *face, cost);

            }else if(nfdc->verb == MW_NFDC_VERB_REMOVE){
                const Name& prefix = nfdc->parameters->getName();
                FaceId faceId = nfdc->parameters->getFaceId();
                Face* face = m_faceTable->get(faceId);
                if (face == nullptr) {
                    nfdc->ret = MW_NFDC_CMD_NOK;
                    goto response;
                }
                fib::Entry* entry = m_forwarder->getFib().findExactMatch(prefix);
                m_forwarder->getFib().removeNextHop(*entry, *face);
            }else if(nfdc->verb == MW_NFDC_VERB_LIST){
            }
        }else if(nfdc->mgr == MW_NFDC_MGR_FACE){
            if(nfdc->verb == MW_NFDC_VERB_DESTROYED){
                FaceId faceId = nfdc->parameters->getFaceId();
                Face* face = m_faceTable->get(faceId);
                if(face!=nullptr){
                    cleanupOnFaceRemoval(
                        m_forwarder->getNameTree(), 
                        m_forwarder->getFib(), 
                        m_forwarder->getPit(), 
                        *face);
                }else
                    m_logger.info("None Face {}", faceId);

            }
        }else if(nfdc->mgr == MW_NFDC_MGR_CS){
            nfd::cs::Cs &cs = m_forwarder->getCs();
            if(nfdc->verb == MW_NFDC_VERB_CONFIG){
                if (nfdc->parameters->hasCapacity()) {
                    cs.setLimit(nfdc->parameters->getCapacity());
                }

                if (nfdc->parameters->hasFlagBit(CsFlagBit::BIT_CS_ENABLE_ADMIT)) {
                    cs.enableAdmit(nfdc->parameters->getFlagBit(CsFlagBit::BIT_CS_ENABLE_ADMIT));
                }

                if (nfdc->parameters->hasFlagBit(CsFlagBit::BIT_CS_ENABLE_SERVE)) {
                    cs.enableServe(nfdc->parameters->getFlagBit(CsFlagBit::BIT_CS_ENABLE_SERVE));
                }

            }else if(nfdc->verb == MW_NFDC_VERB_ERASE){
                size_t count = nfdc->parameters->hasCount() ?
                    nfdc->parameters->getCount() :
                    std::numeric_limits<size_t>::max();
                size_t erased = 0;
#if 1
                cs.erase(nfdc->parameters->getName(), std::min(count, CsManager::ERASE_LIMIT), 
                        [&] (size_t nErased) {

                        erased = nErased;
                        if (nErased == CsManager::ERASE_LIMIT && count > CsManager::ERASE_LIMIT) {
                        cs.find(Interest(nfdc->parameters->getName()).setCanBePrefix(true),
                                [=] (const Interest&, const Data&) mutable {
                                //done(ControlResponse(200, "OK").setBody(body.wireEncode()));
                                },
                                [=] (const Interest&) {
                                //done(ControlResponse(200, "OK").setBody(body.wireEncode()));
                                });
                        }
                        else {
                        //done(ControlResponse(200, "OK").setBody(body.wireEncode()));
                        }
                        }
                        );

                nfdc->retval = erased;
#endif

            }else if(nfdc->verb == MW_NFDC_VERB_INFO){
            }
        }else if(nfdc->mgr == MW_NFDC_MGR_STRATEGY){
            StrategyChoice& sc = m_forwarder->getStrategyChoice();
            const Name& prefix = nfdc->parameters->getName();
            const Name& strategy = nfdc->parameters->getStrategy();

            switch(nfdc->verb){
                case MW_NFDC_VERB_SET:
                    {
                        StrategyChoice::InsertResult res = sc.insert(prefix, strategy);
                    }
                    break;
                case MW_NFDC_VERB_UNSET:
                    sc.erase(nfdc->parameters->getName());
                    break;
                case MW_NFDC_VERB_LIST:
                    break;
                default:
                    break;
            }
        }else{
            nfdc->ret = MW_NFDC_CMD_NOK;
        }

    }else
        nfdc->ret = MW_NFDC_CMD_NOK;

response:
    sendto(m_sockNfdcCmd, buf, sizeof(mw_nfdc), 0, (struct sockaddr*)&their_addr, sizeof(their_addr));

}
#endif

void MwNfd::terminate(const boost::system::error_code& error, int signalNo)
{
    close(m_sockNfdcCmd);
    m_done=true;
}

void MwNfd::initialize(uint32_t input_workers)
{

	if(g_faceTable == nullptr){

	getGlobalLogger().info("The ForwardingWorker({}) ERROR:: Global faceTable is nullptr", m_workerId);
	return;
	}
	m_faceTable = g_faceTable;
  
  m_forwarder = make_unique<Forwarder>(*m_faceTable, *m_ios, m_workerId);

  initializeManagement();

	m_logger.info("The ForwardingWorker({}) is running with inputWorkers[mgmt+worker:{}]", m_workerId, input_workers);
  m_inputWorkers = input_workers;

}

void
MwNfd::initializeManagement()
{
  StrategyChoice& sc = m_forwarder->getStrategyChoice();
  if (!sc.insert("/", "/localhost/nfd/strategy/best-route")) {
  }
  if (!sc.insert("/localhost", "/localhost/nfd/strategy/multicast")) {
  }
  if (!sc.insert("/localhost/nfd", "/localhost/nfd/strategy/best-route")) {
  }
  if (!sc.insert("/ndn/broadcast", "/localhost/nfd/strategy/multicast")) {
  }
}

void MwNfd::bulk_test_case_01()
{
	if(getBulkFibTest()){
		bool done = false;
		FaceId faceId0 = 0;
		FaceId faceId1 = 0;

			do{
					FaceTable::const_iterator it;
					FaceUri uri;

					for ( it=m_faceTable->begin(); it != m_faceTable->end() ;it++ ) {

							uri = it->getLocalUri();

							if( uri.getHost() == m_bulkFibPort0 ){
									faceId0 = it->getId();
							}

							if( uri.getHost() == m_bulkFibPort1 ){
									faceId1 = it->getId();
							}
					}

					if( faceId0 != 0 and faceId1 != 0 ){
							config_bulk_fib(faceId0, faceId1, getFibSharding());
							done = true;
					}
					std::this_thread::sleep_for(std::chrono::milliseconds(200));
			}while(!done);
	}
}

void MwNfd::runWorker()
{
    int32_t iw=1;

    NDN_MSG msg;

    NDN_MSG items[DEQUEUE_BULK_MAX];
    int deq=0;
    size_t cnt=0;
    int i;

    int32_t inputWorkers = m_inputWorkers *2;

    bulk_test_case_01();

    do{
        for(iw=0; iw < inputWorkers; iw+=2){
                deq = nfd::g_dcnMoodyMQ[iw+1][m_workerId]->try_dequeue_bulk(items, DEQUEUE_BULK_MAX-1); // for Data
                for(i=0;i<deq;i++){
                    decodeNetPacketFromMq(items[i].buffer, items[i].face, items[i].endpoint);
                    cnt = 0;
                }
                if(deq==0) cnt +=1;
        }

        for(iw=0; iw < inputWorkers; iw+=2){
                deq = nfd::g_dcnMoodyMQ[iw][m_workerId]->try_dequeue_bulk(items, DEQUEUE_BULK_MAX-1); // for Interest
                for(i=0;i<deq;i++){
                    decodeNetPacketFromMq(items[i].buffer, items[i].face, items[i].endpoint);
                    cnt = 0;
                }
                if(deq==0) cnt +=1;
        }

        if(cnt > 0 and cnt > 10000){
            m_ios->poll();
            handleNfdcCommand();
            cnt=1;
        }

    }while(!m_done);

}

void MwNfd::decodeNetPacketFromMq( const shared_ptr<ndn::Buffer> buffer,
        const shared_ptr<ndn::Interest> interest, 
        const shared_ptr<ndn::Data> data, 
        const nfd::face::Face *face,
        EndpointId endpoint,
        uint32_t type)
{
    if(type==0){
        decodeNetPacketFromMq(buffer, face, endpoint);
    }else if(type==1){
        m_forwarder->onIncomingInterest(FaceEndpoint(*face, endpoint), *interest, m_workerId);
        ++nInInterests;
    }else if(type==2){
        m_forwarder->onIncomingData(FaceEndpoint(*face, endpoint), *data);
        ++nInDatas;
    }else{
        std::cout << "Error: Unknown Msg Type: " << type << std::endl;
    }
}

void MwNfd::decodeNetPacketFromMq(const shared_ptr<ndn::Buffer> buffer, 
        const nfd::face::Face *face, EndpointId endpoint)
{

    Block packet(buffer->data(), buffer->size()) ;

    try {
        lp::Packet pkt(packet);

        if (!pkt.has<lp::FragmentField>()) {
            m_logger.info("received IDLE packet: DROP");
            return;
        }   

        bool isReassembled = false;
        Block netPkt;
        lp::Packet firstPkt;

        std::tie(isReassembled, netPkt, firstPkt) = m_reassembler.receiveFragment(endpoint, pkt);

        if (isReassembled) {
            try {
                switch (netPkt.type()) {
                    case tlv::Interest:
                        if (firstPkt.has<lp::NackField>()) {
                            //this->decodeNack(netPkt, firstPkt, endpoint);
                        }   
                        else {
                            decodeInterest(netPkt, firstPkt, endpoint, face);
                        }   
                        break;
                    case tlv::Data:
                            decodeData(netPkt, firstPkt, endpoint, face);
                        break;
                    default:
                        ++this->nInNetInvalid;
                        return;
                }
            } catch (const tlv::Error& e) {
                ++this->nInNetInvalid;
            }
        }   
    } catch (const tlv::Error& e) {
        //++this->nInLpInvalid;
        m_logger.info("received LPInvalid packet: DROP");
    }   
}

void MwNfd::decodeInterest(const Block& netPkt, const lp::Packet& firstPkt, const EndpointId endpointId, const Face* face)
{
    if(face==nullptr){
        m_logger.info("MwNfd({}):: IngressFace is NULL...");
        return;
    }
    auto interest = make_shared<Interest>(netPkt);

    auto linkService = dynamic_cast<nfd::face::GenericLinkService*>(face->getLinkService());
    const auto& options = linkService->getOptions();

    if (firstPkt.has<lp::NextHopFaceIdField>()) {
        if (options.allowLocalFields) {
            interest->setTag(make_shared<lp::NextHopFaceIdTag>(firstPkt.get<lp::NextHopFaceIdField>()));
        }   
        else {
            m_logger.info("received NextHopFaceId, but local fields disabled: DROP");
            return;
        }   
    }

    if (firstPkt.has<lp::CachePolicyField>()) {
        ++nInNetInvalid;
        m_logger.info("received CachePolicy with Interest: DROP");
        return;
    }

    if (firstPkt.has<lp::IncomingFaceIdField>()) {
        m_logger.info("received IncomingFaceId: IGNORE");
    }

    if (firstPkt.has<lp::CongestionMarkField>()) {
        interest->setTag(make_shared<lp::CongestionMarkTag>(firstPkt.get<lp::CongestionMarkField>()));
    }

    if (firstPkt.has<lp::NonDiscoveryField>()) {
        if (options.allowSelfLearning) {
            interest->setTag(make_shared<lp::NonDiscoveryTag>(firstPkt.get<lp::NonDiscoveryField>()));
        } else {
            m_logger.info("received NonDiscovery, but self-learning disabled: IGNORE");
        }
    }

    if (firstPkt.has<lp::PrefixAnnouncementField>()) {
        ++nInNetInvalid;
        m_logger.info("received PrefixAnnouncement with Interest: DROP");
        return;
    }

    if (firstPkt.has<lp::PitTokenField>()) { 
        interest->setTag(make_shared<lp::PitToken>(firstPkt.get<lp::PitTokenField>()));
    }

    m_forwarder->onIncomingInterest(FaceEndpoint(*face, endpointId), *interest, m_workerId);
    ++nInInterests;
}

void MwNfd::decodeData(const Block& netPkt, const lp::Packet& firstPkt, const EndpointId endpointId, const Face* face)
{

    if(face==nullptr){
        m_logger.info("MwNfd({}):: IngressFace is NULL...");
        return;
    }
    auto data = make_shared<Data>(netPkt);

    auto linkService = dynamic_cast<nfd::face::GenericLinkService*>(face->getLinkService());
    const auto& options = linkService->getOptions();

    if (firstPkt.has<lp::NackField>()) {
        ++nInNetInvalid;
        m_logger.info("received Nack with Data: DROP");
        return;
    }

    if (firstPkt.has<lp::NextHopFaceIdField>()) {
        ++nInNetInvalid;
        m_logger.info("received NextHopFaceId with Data: DROP");
        return;
    }

    if (firstPkt.has<lp::CachePolicyField>()) {
        // CachePolicy is unprivileged and does not require allowLocalFields option.  
        // In case of an invalid CachePolicyType, get<lp::CachePolicyField> will throw,
        // so it's unnecessary to check here.
        data->setTag(make_shared<lp::CachePolicyTag>(firstPkt.get<lp::CachePolicyField>()));
    }

    if (firstPkt.has<lp::IncomingFaceIdField>()) {
        m_logger.info("received IncomingFaceId: IGNORE");
    }

    if (firstPkt.has<lp::CongestionMarkField>()) {
        data->setTag(make_shared<lp::CongestionMarkTag>(firstPkt.get<lp::CongestionMarkField>()));
    }

    if (firstPkt.has<lp::NonDiscoveryField>()) {
        ++nInNetInvalid;
        m_logger.info("received NonDiscovery with Data: DROP");
        return;
    }

    if (firstPkt.has<lp::PrefixAnnouncementField>()) {
        if (options.allowSelfLearning) {
            data->setTag(make_shared<lp::PrefixAnnouncementTag>(firstPkt.get<lp::PrefixAnnouncementField>()));
        }   else {
            m_logger.info("received PrefixAnnouncement, but self-learning disabled: IGNORE");
        }   
    }

    if (firstPkt.has<lp::PitTokenField>()) {
        data->setTag(make_shared<lp::PitToken>(firstPkt.get<lp::PitTokenField>()));
    	//m_logger.info("received PitToken...");
    }

    m_forwarder->onIncomingData(FaceEndpoint(*face, endpointId), *data);

    ++nInDatas;
}

void MwNfd::decodeNack(const Block& netPkt, const lp::Packet& firstPkt, const EndpointId endpointId, const Face *face)
{
#if 0
    lp::Nack nack((Interest(netPkt)));
    nack.setHeader(firstPkt.get<lp::NackField>());

    if (firstPkt.has<lp::NextHopFaceIdField>()) {
        ++nInNetInvalid;
        m_logger.info("received NextHopFaceId with Nack: DROP");
        return;
    }

    if (firstPkt.has<lp::CachePolicyField>()) {
        ++nInNetInvalid;
        m_logger.info("received CachePolicy with Nack: DROP");
        return;
    }

    if (firstPkt.has<lp::IncomingFaceIdField>()) {
        m_logger.info("received IncomingFaceId: IGNORE");
    }

    if (firstPkt.has<lp::CongestionMarkField>()) {
        nack.setTag(make_shared<lp::CongestionMarkTag>(firstPkt.get<lp::CongestionMarkField>()));
    }

    if (firstPkt.has<lp::NonDiscoveryField>()) {
        ++nInNetInvalid;
        m_logger.info("received NonDiscovery with Nack: DROP");
        return;
    }

    if (firstPkt.has<lp::PrefixAnnouncementField>()) {
        ++nInNetInvalid;
        m_logger.info("received PrefixAnnouncement with Nack: DROP");
        return;
    }

    //nfd::face::Face *face = m_faceTable->get(faceId);

    m_forwarder->startProcessNack(FaceEndpoint(*face, endpointId), nack);
#endif
    ++nInNacks;
}

bool MwNfd::config_bulk_fib(FaceId faceId0, FaceId faceId1, bool sharding, bool dpdk)
{
		m_logger.info("MW-NFD is setting the bulk fib: face0:{}/face1:{}, sharding:{}, with-DPDK:{}", faceId0, faceId1, sharding, dpdk);
		FILE *fp;
		char line[1024]={0,};
		uint64_t cost = 0;
		int ndx = 0;
		int line_cnt=0;
		FaceUri uri;
		FaceId nextHopId;
		int32_t wid;//, ndnType;
        size_t fibs=0;

#if 1
		fp =  fopen (getBulkFibFilePath().c_str(), "r");

		if (fp==NULL) {
			m_logger.info("MW-NFD: bulk_fib_test: can't read bulk-fib-file:{}", getBulkFibFilePath());
            return false;
		}

		while ( !feof(fp) ) {
            fgets(line, sizeof(line), fp);
            line_cnt ++;
		}
		line_cnt -=1;
		fclose(fp);
#endif
		fp =  fopen (getBulkFibFilePath().c_str(), "r");

		while ( !feof(fp) ) {
				fgets(line, sizeof(line), fp);
				if(strlen(line)==0) continue;
				if(line[0]=='"') continue;

				line[strlen(line)-1]='\0';
				Name prefix(line);

				if(prefix.size() <=0){
						m_logger.info("prefix.size({}) is {}", prefix.size());
						ndx++;
						continue;
				}

                nextHopId = 0;

				if(dpdk == true and ndx >= line_cnt/2){
                    nextHopId = faceId0;
				}else if(dpdk == false){ 
                    if(ndx >= line_cnt/2)
                        nextHopId = faceId0;
                    else
                        nextHopId = faceId1;
				}

				Face* face = m_faceTable->get(nextHopId);

                if(prefix.size() >= getPrefixLength4Distribution() and sharding ){
                    //std::tie(ndnType, wid) = dissectNdnPacket(prefix.wireEncode().wire(), prefix.wireEncode().size());
                    wid = computeWorkerId(prefix.wireEncode().wire(), prefix.wireEncode().size());
                    if(wid!=m_workerId){
				        ndx++;
                        continue;
                    }
                }

                fib::Entry * entry = getFibTable().insert(prefix).first;
                getFibTable().addOrUpdateNextHop(*entry, *face, cost);
                fibs += 1;

				ndx++;
				memset(line, '\0', sizeof(line));
		}
		fclose(fp);
		m_logger.info("ForwardingWorker[{}] - Bulk FIB Insertion End(Fib's Entries:{})..." , m_workerId, getFibTable().size());

        return true;
}

bool MwNfd::config_bulk_fib(FaceId faceId0, FaceId faceId1, bool sharding)
{
		m_logger.info("MW-NFD is setting the bulk fib: face0:{}/face1:{}, sharding:{}", faceId0, faceId1, sharding);
		FILE *fp;
		char line[1024]={0,};
		uint64_t cost = 0;
		int ndx = 0;
		int line_cnt=0;
		FaceUri uri;
		FaceId nextHopId;
		int32_t wid;//, ndnType;
        size_t fibs=0;

		fp =  fopen (getBulkFibFilePath().c_str(), "r");

		if (fp==NULL) {
			m_logger.info("MW-NFD: bulk_fib_test: can't read bulk-fib-file:{}", getBulkFibFilePath());
            return false;
		}

		while ( !feof(fp) ) {
            fgets(line, sizeof(line), fp);
            line_cnt ++;
		}
		line_cnt -=1;
		fclose(fp);

		fp =  fopen (getBulkFibFilePath().c_str(), "r");

		while ( !feof(fp) ) {
				fgets(line, sizeof(line), fp);
				if(strlen(line)==0) continue;
				if(line[0]=='"') continue;

				line[strlen(line)-1]='\0';
				Name prefix(line);

				if(prefix.size() <=0){
						m_logger.info("prefix.size({}) is {}", prefix.size());
						ndx++;
						continue;
				}

				if(ndx >= line_cnt/2){
                    nextHopId = faceId0;
				}else{
                    nextHopId = faceId1;
				}

				Face* face = m_faceTable->get(nextHopId);

                if(prefix.size() >= getPrefixLength4Distribution() and sharding ){
                    //std::tie(ndnType, wid) = dissectNdnPacket(prefix.wireEncode().wire(), prefix.wireEncode().size());
                    wid = computeWorkerId(prefix.wireEncode().wire(), prefix.wireEncode().size());
                    if(wid!=m_workerId){
				        ndx++;
                        continue;
                    }
                }

                fib::Entry * entry = getFibTable().insert(prefix).first;
                getFibTable().addOrUpdateNextHop(*entry, *face, cost);
                fibs += 1;

				ndx++;
				memset(line, '\0', sizeof(line));
		}
		fclose(fp);
		m_logger.info("ForwardingWorker[{}] - Bulk FIB Insertion End(Fib's Entries:{})..." , m_workerId, getFibTable().size());

        return true;
}

 void MwNfd::prepareBulkFibTest(std::string port0, std::string port1)
  {
        m_bulkFibPort0 = port0;
        m_bulkFibPort1 = port1;
        //getGlobalLogger().info("preparing for BulkFibTest : bulkFibPort0:{} / bulkFibPort0:{}",
                //m_bulkFibPort0 , m_bulkFibPort1 );
  }


} // namespace nfd
