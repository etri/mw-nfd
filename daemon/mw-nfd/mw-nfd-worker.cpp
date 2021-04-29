
#include <chrono>
#include <thread>
#include <memory>

#include "mw-nfd-worker.hpp"
#include "mw-nfd-global.hpp"
#include "common/global.hpp"
#include "common/logger.hpp"
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
 #include <ndn-cxx/util/logging.hpp>
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
#include <boost/property_tree/info_parser.hpp>
#include <ndn-cxx/transport/unix-transport.hpp>
#include <boost/asio/deadline_timer.hpp>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/posix_time/posix_time_duration.hpp>
#include <boost/date_time/microsec_time_clock.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/format.hpp>

#include "face/lp-reassembler.hpp"
#include "common/city-hash.hpp"

#include "mgmt/cs-manager.hpp"
#include <ndn-cxx/mgmt/nfd/fib-entry.hpp>

#include <iostream>

nfd::face::Face *face0=nullptr;
nfd::face::Face *face1=nullptr;

namespace io = boost::iostreams;
extern std::map<std::string, int32_t> g_inputWorkerList;
extern  bool g_mwNfdCmdFlags[MW_NFD_WORKER];

using namespace std;

NFD_LOG_INIT(MwNfd);

namespace nfd {

MwNfd::MwNfd(int8_t wid, boost::asio::io_service* ios, bool fibSharding, const std::string& conf)
  : m_workerId(wid)
  , m_terminationSignalSet(*ios)
  , m_fibSignalSet(*ios)
    ,m_done(false)
    ,m_configFile(conf)
,m_wantFibSharding(fibSharding)
,m_setReservedFace(false)
,m_doneBulk(false)
	{
		// Disable automatic verification of parameters digest for decoded Interests.
		//    Interest::setAutoCheckParametersDigest(false);
		m_terminationSignalSet.add(SIGINT);
		m_terminationSignalSet.add(SIGTERM);

#ifndef ETRI_NFD_ORG_ARCH
		m_terminationSignalSet.async_wait(bind(&MwNfd::terminate, this, _1, _2));
#endif
		m_ios = ios;

#if 0
		/*
		 * It is necessary to support
		 */
		struct sockaddr_in servaddr;
		m_sockNfdcCmd = socket(AF_INET, SOCK_DGRAM, 0);
		memset(&servaddr, 0, sizeof(servaddr));
		servaddr.sin_family    = AF_INET; // IPv4 
		servaddr.sin_addr.s_addr = INADDR_ANY; 
		servaddr.sin_port = htons(MW_NFDC_PORT+wid); 
		socklen_t len = sizeof servaddr;
		if ( bind(m_sockNfdcCmd, (const struct sockaddr *)&servaddr,  len) < 0 ) 
		{ 
			perror("mw-nfd bind failed"); 
			exit(EXIT_FAILURE); 
		} 
#else

		struct sockaddr_in servaddr;
		m_sockNfdcCmd = socket(AF_INET, SOCK_DGRAM, 0);
		memset(&servaddr, 0, sizeof(servaddr));
		servaddr.sin_family    = AF_INET; // IPv4 
		servaddr.sin_addr.s_addr = INADDR_ANY; 
		servaddr.sin_port = htons(MW_NFDC_PORT+wid); 
		socklen_t len = sizeof servaddr;
		if ( bind(m_sockNfdcCmd, (const struct sockaddr *)&servaddr,  len) < 0 ) 
		{ 
			perror("mw-nfd bind failed"); 
			exit(EXIT_FAILURE); 
		} 

		fcntl(m_sockNfdcCmd, F_SETFL, O_NONBLOCK); 

/*
	m_sockNfdcCmd = socket(PF_LOCAL, SOCK_DGRAM, 0);

	std::string SOCK_LOCALFILE = "/tmp/.mw-nfd-" + std::to_string(wid);

	if ( 0 == access( SOCK_LOCALFILE.c_str(), F_OK))
      unlink( SOCK_LOCALFILE.c_str());

	memset(&m_localAddr, 0, sizeof(m_localAddr));
	m_localAddr.sun_family = AF_UNIX;
	strcpy(m_localAddr.sun_path, SOCK_LOCALFILE.c_str());
	if (bind(m_sockNfdcCmd, (struct sockaddr *)&m_localAddr, sizeof(m_localAddr)) < 0) {
		perror("bind");
	}
*/
#endif
				nfd::face::GenericLinkService::Options options;
				auto gls = std::make_shared<nfd::face::GenericLinkService>(options);
			
				gls->afterReceiveInterest.connect(
				[this] (const Interest& interest, const EndpointId& endpointId) {
    				this->m_forwarder->onIncomingInterest(FaceEndpoint(*m_face, endpointId), interest, this->m_workerId);
                    });		
				gls->afterReceiveData.connect(
				[this] (const Data& data, const EndpointId& endpointId) {
    				this->m_forwarder->onIncomingData(FaceEndpoint(*m_face, endpointId), data);
                    });		
				gls->afterReceiveNack.connect(
				[this] (const lp::Nack& nack, const EndpointId& endpointId) {
					this->m_forwarder->startProcessNack(FaceEndpoint(*m_face, endpointId), nack);
                    });		

				m_genericLinkServiceList.insert ( std::pair<FaceId,shared_ptr<nfd::face::GenericLinkService>>(1,std::move(gls)) );

	}

MwNfd::~MwNfd() = default;

#ifndef ETRI_NFD_ORG_ARCH

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

/*
* This Function handles MW-NFD's control commands sent from Management Module.
*/
void MwNfd::handleNfdcCommand()
{

	struct sockaddr_un their_addr;
    char buf[MW_NFD_CMD_BUF_SIZE]={0,};
    int numbytes=-2;
    socklen_t addr_len;

    //mw_nfdc_ptr nfdc = (mw_nfdc_ptr)buf;

    addr_len = sizeof their_addr;
    numbytes = recvfrom(m_sockNfdcCmd, buf, sizeof(buf) , 0,
			(struct sockaddr *)&their_addr, &addr_len);

    if (numbytes <= 0) {
        return;
	}
	
	processNfdcCommand(buf);
	numbytes = sendto(m_sockNfdcCmd, buf, sizeof(buf), 0, (struct sockaddr*)&their_addr, sizeof(their_addr));
}

void MwNfd::processNfdcCommand( char * cmd)
{
	using ndn::nfd::CsFlagBit;
	mw_nfdc_ptr nfdc = (mw_nfdc_ptr)cmd;
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

			if(prefix.size() > Fib::getMaxDepth()){
				NFD_LOG_WARN("prefix.size({}) is " << prefix.size());
				nfdc->ret = MW_NFDC_CMD_NOK;
				goto response;
			}

			// for network name parameter
			if( nfdc->netName ){
				fib::Entry* entry = m_forwarder->getFib().insert(prefix).first;
				getFibTable().addOrUpdateNextHop(*entry, *face, cost);
				goto response;
			}

			if(m_wantFibSharding){
				if(prefix.size() >= getPrefixLength4Distribution() and m_wantFibSharding ){
					auto block = prefix.wireEncode();
					int32_t wid;//, ndnType;
					wid = computeWorkerId(block.wire(), block.size());
					if(wid!=m_workerId){
						nfdc->ret = MW_NFDC_CMD_NOK;
						goto response;
					}
				}
			}
			fib::Entry* entry = m_forwarder->getFib().insert(prefix).first;
			if(entry!=nullptr)
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
			if(entry!=nullptr){
#ifdef __linux__
#endif
				m_forwarder->getFib().removeNextHop(*entry, *face);
			}else{

#ifdef __linux__
#endif
				}
		}else if(nfdc->verb == MW_NFDC_VERB_LIST){
		}
	}else if(nfdc->mgr == MW_NFDC_MGR_FACE){
		if(nfdc->verb == MW_NFDC_VERB_CREATE){

				FaceId faceId = nfdc->parameters->getFaceId();
#ifdef __linux__
				NFD_LOG_INFO("Face Created - Face " << faceId << " on CPU " <<  sched_getcpu());
#endif
				nfd::face::GenericLinkService::Options options;
				auto gls = std::make_shared<nfd::face::GenericLinkService>(options);
			
				gls->afterReceiveInterest.connect(
				[this] (const Interest& interest, const EndpointId& endpointId) {
    				this->m_forwarder->onIncomingInterest(FaceEndpoint(*m_face, endpointId), interest, this->m_workerId);
                    });		
				gls->afterReceiveData.connect(
				[this] (const Data& data, const EndpointId& endpointId) {
    				this->m_forwarder->onIncomingData(FaceEndpoint(*m_face, endpointId), data);
                    });		
				gls->afterReceiveNack.connect(
				[this] (const lp::Nack& nack, const EndpointId& endpointId) {
					this->m_forwarder->startProcessNack(FaceEndpoint(*m_face, endpointId), nack);
                    });		

				m_genericLinkServiceList.insert ( std::pair<FaceId,shared_ptr<nfd::face::GenericLinkService>>(faceId,std::move(gls)) );

				if(m_setReservedFace==false){
					m_face =m_faceTable->get(face::FACEID_NULL);	
					auto gls = std::make_shared<nfd::face::GenericLinkService>(options);

					gls->afterReceiveInterest.connect(
							[this] (const Interest& interest, const EndpointId& endpointId) {
							this->m_forwarder->onIncomingInterest(FaceEndpoint(*m_face, endpointId), interest, this->m_workerId);
							});		
					gls->afterReceiveData.connect(
							[this] (const Data& data, const EndpointId& endpointId) {
							this->m_forwarder->onIncomingData(FaceEndpoint(*m_face, endpointId), data);
							});		
					gls->afterReceiveNack.connect(
							[this] (const lp::Nack& nack, const EndpointId& endpointId) {
							this->m_forwarder->startProcessNack(FaceEndpoint(*m_face, endpointId), nack);
							});		

					m_genericLinkServiceList.insert ( std::pair<FaceId,shared_ptr<nfd::face::GenericLinkService>>(face::FACEID_NULL,std::move(gls)) );
					m_setReservedFace = true;
				}

		}else if(nfdc->verb == MW_NFDC_VERB_DESTROYED){
			FaceId faceId = nfdc->parameters->getFaceId();
			Face* face1 = m_faceTable->get(faceId);
			if(face1!=nullptr){
				cleanupOnFaceRemoval( m_forwarder->getNameTree(), m_forwarder->getFib(), m_forwarder->getPit(), *face1);
#ifdef __linux__
				NFD_LOG_INFO("Face Destroy - Face " << faceId << " on CPU " <<  sched_getcpu());
#endif
			}else{
#ifdef __linux__
				NFD_LOG_INFO("Face Destroy - None Face " << faceId << " on CPU " <<  sched_getcpu());
#endif
			}

			m_genericLinkServiceList.erase(faceId);
		}
	}else if(nfdc->mgr == MW_NFDC_MGR_CS){
		nfd::cs::Cs &cs = m_forwarder->getCs();
		if(nfdc->verb == MW_NFDC_VERB_CONFIG){
			if (nfdc->parameters->hasCapacity()) {
				cs.setLimit(nfdc->parameters->getCapacity());
				nfdc->retval = nfdc->parameters->getCapacity();
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

response:
	//sendto(m_sockNfdcCmd, buf, sizeof(buf), 0, (struct sockaddr*)&their_addr, sizeof(their_addr));
	return;
}

void MwNfd::terminate(const boost::system::error_code& error, int signalNo)
{
    close(m_sockNfdcCmd);
    m_done=true;
}

void MwNfd::initialize(uint32_t input_workers)
{

	if(g_faceTable == nullptr){

	return;
	}
	m_faceTable = g_faceTable;
  
  m_forwarder = make_unique<Forwarder>(*m_faceTable, *m_ios, m_workerId);

  initializeManagement();

	NFD_LOG_INFO("The ForwardingWorker(" << m_workerId << ") is running with inputWorkers[mgmt+input:" << input_workers << "]");
  m_inputWorkers = input_workers;

	Name rtPrefix(getRouterName()+"/nfd");
	fib::Entry* entry = m_forwarder->getFib().insert(rtPrefix).first;
    auto m_internalFace = m_faceTable->get(face::FACEID_INTERNAL_FACE);
	m_forwarder->getFib().addOrUpdateNextHop(*entry, *m_internalFace, 0);

}

void
MwNfd::initializeManagement()
{
#ifdef __linux__
	//NFD_LOG_INFO("Config File: " << m_configFile << " on CPU " <<  sched_getcpu());
#endif

	ConfigSection config;
	boost::property_tree::read_info(m_configFile, config);
	StrategyChoice& strategy_choice = m_forwarder->getStrategyChoice();

	auto scs = config.get_child("tables.strategy_choice");
	for (const auto& prefixAndStrategy : scs) {
		Name prefix(prefixAndStrategy.first);
		Name strategy(prefixAndStrategy.second.get_value<std::string>());
		strategy_choice.insert(prefix, strategy);
	}
	auto network_region = config.get_child("tables.network_region");

	auto& nrt = m_forwarder->getNetworkRegionTable();
	nrt.clear();
	for (const auto& pair : network_region) {
		nrt.insert(Name(pair.first));
	}

	auto sCsMaxPackets = config.get_child_optional("tables.cs_max_packets");
	auto nCsMaxPackets = sCsMaxPackets->get_value<std::size_t>();

	nCsMaxPackets /= getForwardingWorkers();

	auto&& policyName = config.get<std::string>("tables.cs_policy", "lru");

	unique_ptr<cs::Policy> csPolicy;
	csPolicy = cs::Policy::create(policyName);
	if (csPolicy == nullptr) {
		NDN_THROW(ConfigFile::Error("Unknown cs_policy '" + policyName + "' in section 'tables'"));
	}

	m_forwarder->getCs().setLimit(nCsMaxPackets);
	if (m_forwarder->getCs().size() == 0 && csPolicy != nullptr) {
		m_forwarder->getCs().setPolicy(std::move(csPolicy));
	}

}

bool MwNfd::bulk_test_case_01()
{
	if(getBulkFibTest()){
		FaceId faceId0 = 0;
		FaceId faceId1 = 0;

		FaceTable::const_iterator it;
		FaceUri uri;
		FaceUri faceUri0;
		FaceUri faceUri1;
		faceUri0.parse(m_bulkFibPort0);	
		faceUri1.parse(m_bulkFibPort1);	

		for ( it=m_faceTable->begin(); it != m_faceTable->end() ;it++ ) {

			if( faceUri0.getScheme()=="udp4"){
				uri = it->getRemoteUri();
			}else if( faceUri0.getScheme()=="tcp4")
				uri = it->getRemoteUri();
			else if( faceUri0.getScheme()=="ether")
				uri = it->getLocalUri();
			else if( faceUri0.getScheme()=="dev")
				uri = it->getLocalUri();
			else
				uri = it->getLocalUri();

			if( uri.getScheme() == faceUri0.getScheme() ){
				if( uri.getHost() == faceUri0.getHost() ){
					faceId0 = it->getId();
				}
			}

			if( uri.getScheme() == faceUri1.getScheme() ){
				if( uri.getHost() == faceUri1.getHost() ){
					faceId1 = it->getId();
				}
			}
		}

		if( faceId0 != 0 and faceId1 != 0 ){
			config_bulk_fib( faceId0, faceId1, m_wantFibSharding );
			return true;
		}else
			return false;
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}else
		return true;
}

void MwNfd::runWorker()
{
	int32_t iw=1;

	NDN_MSG msg;

	NDN_MSG items[DEQUEUE_BULK_MAX];
	int deq=0, idx;

	int32_t inputMQs = m_inputWorkers *2;

	do{

		if(getCommandRx(m_workerId)==true){
			handleNfdcCommand();
		}
		for(iw=0; iw < inputMQs; iw+=2){
			deq = nfd::g_dcnMoodyMQ[iw+1][m_workerId]->try_dequeue_bulk(items, DEQUEUE_BULK_MAX-1); // for Data
			for(idx=0;idx<deq;idx++){
				decodeNetPacketFromMq(items[idx].buffer, items[idx].faceId, items[idx].endpoint);
			}
		}

		for(iw=0; iw < inputMQs; iw+=2){
			deq = nfd::g_dcnMoodyMQ[iw][m_workerId]->try_dequeue_bulk(items, DEQUEUE_BULK_MAX-1); // for Interest
			for(idx=0;idx<deq;idx++){
				decodeNetPacketFromMq(items[idx].buffer, items[idx].faceId, items[idx].endpoint);
			}
		}

		if(g_workerTimerTriggerList[m_workerId]){
			m_ios->poll();
			g_workerTimerTriggerList[m_workerId] = false;
			if(m_doneBulk==false){
				m_doneBulk= bulk_test_case_01(); 
			}
		}

	}while(!m_done);

}

void MwNfd::decodeNetPacketFromMq(const shared_ptr<ndn::Buffer> buffer, 
		size_t faceId,
		EndpointId endpoint)
{
    m_face = m_faceTable->get(faceId);
	if(m_face==nullptr){
#ifdef __linux__
		NFD_LOG_WARN("There is no face Entry with " << faceId << " on CPU " << sched_getcpu());
#endif
		return;
	}

    Block packet(buffer->data(), buffer->size()) ;

	std::map<FaceId,std::shared_ptr<nfd::face::GenericLinkService>>::iterator it;
	it = m_genericLinkServiceList.find(faceId);
	//if( faceId != face::FACEID_INTERNAL_FACE and it == m_genericLinkServiceList.end() ){
	if( it == m_genericLinkServiceList.end() ){
#ifdef __linux__
		NFD_LOG_WARN("There is no LinkService(for decodeNetPacketFromMq) Entry with " << faceId << " on CPU " << sched_getcpu());
#endif
		return;
	}

	std::shared_ptr<nfd::face::GenericLinkService> mw_linkservice = it->second;

	mw_linkservice->receivePacket(packet, endpoint);
}

bool MwNfd::config_bulk_fib(FaceId faceId0, FaceId faceId1, bool sharding)
{
		NFD_LOG_INFO("MW-NFD is setting the bulk fib: face0:"<< faceId0 <<  "/face1:" << faceId1 <<", sharding:" << sharding);
		FILE *fp;
		char line[1024]={0,};
		uint64_t cost = 0;
		int ndx = 0;
		int line_cnt=0;
		FaceUri uri;
		FaceId nextHopId;
		int32_t wid;//, ndnType;
        char* ptr __attribute__((unused));

		fp =  fopen (getBulkFibFilePath().c_str(), "r");

		if (fp==NULL) {
			//getGlobalLogger().info("MW-NFD: bulk_fib_test: can't read bulk-fib-file:{}", getBulkFibFilePath());
            return false;
		}

		while ( !feof(fp) ) {
            ptr=fgets(line, sizeof(line), fp);
            line_cnt ++;
		}
		line_cnt -=1;
		fclose(fp);

		fp =  fopen (getBulkFibFilePath().c_str(), "r");

		while ( !feof(fp) ) {
				ptr = fgets(line, sizeof(line), fp);
				if(strlen(line)==0) continue;
				if(line[0]=='"') continue;

				line[strlen(line)-1]='\0';
				Name prefix(line);

				if(prefix.size() <=0){
						//getGlobalLogger().info("prefix.size({}) is {}", prefix.size());
						ndx++;
						continue;
				}

				if(ndx >= line_cnt/2){
                    nextHopId = faceId0;
				}else{
                    nextHopId = faceId1;
				}

				Face* face = m_faceTable->get(nextHopId);

                if( sharding and prefix.size() >= getPrefixLength4Distribution() ){
                    wid = computeWorkerId(prefix.wireEncode().wire(), prefix.wireEncode().size());
                    if(wid!=m_workerId){
				        ndx++;
                        continue;
                    }
                }

                fib::Entry * entry = getFibTable().insert(prefix).first;
				if(entry!=nullptr){
                	getFibTable().addOrUpdateNextHop(*entry, *face, cost);
				}

				ndx++;
				memset(line, '\0', sizeof(line));
		}
		fclose(fp);

#ifdef __linux__
		NFD_LOG_INFO("Worker(" << sched_getcpu() << ") Fib Size: " << getFibTable().size());
#endif
        return true;
}

std::tuple<uint64_t,uint64_t,uint64_t> MwNfd::getLinkServiceCounters(FaceId faceId)
{
	auto it = m_genericLinkServiceList.find(faceId);
	if( it == m_genericLinkServiceList.end() ){
#ifdef __linux__
		NFD_LOG_WARN("There is no LinkService(for Counters) Entry with " << faceId << " on CPU " << sched_getcpu());
#endif
		nfd::face::GenericLinkServiceCounters dummy;
		return std::make_tuple(0,0,0);
	}

	std::shared_ptr<nfd::face::GenericLinkService> mw_linkservice = it->second;

	const auto& counters = mw_linkservice->getCounters();
	uint64_t II = counters.nInInterests;
	uint64_t ID = counters.nInData;
	uint64_t IN = counters.nInNacks;
	return std::make_tuple(II, ID, IN);

}

 void MwNfd::prepareBulkFibTest(std::string port0, std::string port1)
  {
        m_bulkFibPort0 = port0;
        m_bulkFibPort1 = port1;
        //getGlobalLogger().info("preparing for BulkFibTest : bulkFibPort0:{} / bulkFibPort0:{}",
                //m_bulkFibPort0 , m_bulkFibPort1 );
  }

#endif
} // namespace nfd
