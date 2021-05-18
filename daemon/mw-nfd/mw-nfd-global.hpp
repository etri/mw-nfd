
/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2019-2021,  HII of ETRI.
 *
 * This file is part of MW-NFD (Named Data Networking Multi-Worker Forwarding Daemon).
 * See README.md for complete list of NFD authors and contributors.
 *
 * MW-NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * MW-NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MW_NFD_COMMON_GLOBAL_HPP
#define MW_NFD_COMMON_GLOBAL_HPP

#include <iostream>
#include <string>

#include "core/common.hpp"
#include "fw/forwarder-counters.hpp"
#include "face/face.hpp"
#include "network_v4.hpp"
#include "table/pit-entry.hpp"
#include "concurrentqueue.h"
#include "mw-nfd-worker.hpp"

#include <ndn-cxx/mgmt/nfd/control-parameters.hpp>
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>

static const uint32_t MW_NFD_WORKER = 64;

#define DEQUEUE_BULK_MAX 32
#define ROUTE_FLAGS_NET_NAME 32
#define DCN_LOCALHOST_PREFIX 65535
#define DCN_MAX_WORKERS 128

using boost::multi_index_container;
using namespace boost::multi_index;


struct ioservice
{
    int         coreId;
    boost::asio::io_service* ios;
    std::string ifName;
    int         ifIndex;

    ioservice(int id_,std::string name_,int if_):coreId(id_),ifName(name_),ifIndex(if_){}

    friend std::ostream& operator<<(std::ostream& os,const ioservice& e)
    {
        os<<e.coreId<<" "<<e.ifName<<" "<<e.ifIndex<<std::endl;
        return os;
    }
};

struct coreId{};
struct ifName{};
struct ifIndex{};

typedef multi_index_container<
ioservice,
    indexed_by<
    ordered_unique<
    tag<coreId>,  BOOST_MULTI_INDEX_MEMBER(ioservice,int,coreId)>,
    ordered_non_unique<
    tag<ifName>,BOOST_MULTI_INDEX_MEMBER(ioservice,std::string,ifName)>,
    ordered_non_unique<
    tag<ifIndex>, BOOST_MULTI_INDEX_MEMBER(ioservice,int,ifIndex)> >
> ioservice_set;

#if 1
enum MwNfdcMgrField{
    MW_NFDC_MGR_FIB ,
        MW_NFDC_MGR_FACE, 
        MW_NFDC_MGR_CS, 
        MW_NFDC_MGR_STRATEGY ,
        MW_NFDC_MGR_FWD ,
        MW_NFDC_MGR_UNBOUND 

};

enum MwNfdcCmdResult{
    MW_NFDC_CMD_OK,
    MW_NFDC_CMD_NOK
};

enum MwNfdcVerbField{
    MW_NFDC_VERB_ADD ,
    MW_NFDC_VERB_REMOVE,
    MW_NFDC_VERB_SET ,
    MW_NFDC_VERB_UNSET ,
    MW_NFDC_VERB_LIST ,
    MW_NFDC_VERB_INFO ,
    MW_NFDC_VERB_CONFIG ,
    MW_NFDC_VERB_ERASE ,
    MW_NFDC_VERB_STATUS ,
    MW_NFDC_VERB_CREATE ,
    MW_NFDC_VERB_DESTROYED ,
    MW_NFDC_VERB_UNBOUND 
};


const std::string MW_NFDC_MGR_FIELD[MW_NFDC_MGR_UNBOUND] = {
    "Fib",
    "Face",
    "CS",
    "Strategy",
    "Forwarder"
};
const std::string MW_NFDC_VERB_FIELD[MW_NFDC_VERB_UNBOUND] = {
    "Add",
    "Remove",
    "Set",
    "Unset",
    "List",
    "Info",
    "Config",
    "Erase",
    "Status"
    "Destroy",
};
#endif

namespace nfd {

extern face::FaceSystem* g_faceSystem;
extern time::system_clock::TimePoint g_startTimestamp;

extern std::string g_bulkFibTestPort0;
extern std::string g_bulkFibTestPort1;
extern bool g_workerTimerTriggerList[DCN_MAX_WORKERS];

#define FACEID_REMOTE_ACCESS 2

	typedef struct pit_token_st {
		uint8_t workerId;
		uint8_t CanBePrefix;
        uint64_t hashValue;
	} ST_PIT_TOKEN ;

    using namespace moodycamel;
    using namespace boost::lockfree;

#define MOODYCAMEL

    static const uint32_t MW_NFDC_PORT = 3003;
    static const uint32_t MQ_ARRAY_MAX_SIZE = MW_NFD_WORKER*2;
#ifdef __ARM_ARCH
    #define CAPACITY 512 
#else
    #define CAPACITY 2*1024
#endif


	#define MW_NFD_CMD_BUF_SIZE 128

#define MW_NFD_TRIGGER_TMR 1

    struct NdnTraits : public moodycamel::ConcurrentQueueDefaultTraits
    {
               static const size_t BLOCK_SIZE = CAPACITY;
    };

    typedef struct mw_nfdc_cmd {
        int32_t mgr;
        int32_t verb;
        int32_t ret;
        size_t retval;
        bool netName;
        std::shared_ptr<ndn::Interest> interest;
        std::shared_ptr<ndn::nfd::ControlParameters> parameters;
    }mw_nfdc, *mw_nfdc_ptr;

	void setBulkFibFilePath(std::string);
	void setBulkFibTest();
	void setOutgoingMwNfd();
	void setOutgoingMwNfdWorkers(int);
	int getOutgoingMwNfdWorkers();
	std::string getBulkFibFilePath();
	bool getOutgoingMwNfd();
	bool getBulkFibTest();

    size_t emitMwNfdcCommand(int, int, int,ndn::nfd::ControlParameters, bool);

    typedef struct st_ndn_out_msg {
        //std::shared_ptr<ndn::Interest> interest;
        //std::shared_ptr<ndn::Data> data;
        const ndn::Interest* interest;
        const ndn::Data* data;
			const lp::Nack *nack;
			nfd::face::FaceId face;
			uint64_t type;
		}NDN_OUT_MSG;

    typedef struct st_ndn_msg {
        std::shared_ptr<ndn::Buffer> buffer;
        std::shared_ptr<ndn::Interest> interest;
        std::shared_ptr<ndn::Data> data;
        nfd::face::EndpointId endpoint;
		size_t faceId;
        uint32_t iwId;
        uint32_t type; //Buffer(0), Interest(1), Data(2)
    }NDN_MSG;

    using MoodyMQ = std::shared_ptr<moodycamel::ConcurrentQueue<NDN_MSG, NdnTraits>>;
    extern    nfd::MoodyMQ g_dcnMoodyMQ[MQ_ARRAY_MAX_SIZE][MQ_ARRAY_MAX_SIZE];

    using MoodyMQ2 = std::shared_ptr<moodycamel::ConcurrentQueue<ndn::Block, NdnTraits>>;
    extern    nfd::MoodyMQ2 g_dcnMoodyOutMQ[MQ_ARRAY_MAX_SIZE];

    using BoostMQ = std::shared_ptr< boost::lockfree::spsc_queue<NDN_MSG, boost::lockfree::capacity<CAPACITY>> >;
    extern    nfd::BoostMQ g_dcnBoostMQ[MQ_ARRAY_MAX_SIZE][MQ_ARRAY_MAX_SIZE];

	void setMwNfd(int8_t wid, std::shared_ptr<nfd::MwNfd> mwNfd);
	std::shared_ptr<nfd::MwNfd> getMwNfd(int8_t wid);

    void mq_allocation();
    
    bool getGlobalNetName();
    void setGlobalNetName(bool);

    bool dcnReceivePacket(const uint8_t *, size_t, uint64_t);

int getIfIndex(const char *addr);
int32_t computeWorkerId( const uint8_t *wire, size_t size );
std::tuple<bool, uint32_t, int32_t> dissectNdnPacket( const uint8_t *wire, size_t size );

void setPrefixLength4Distribution(size_t);
size_t getPrefixLength4Distribution();
void setForwardingWorkers(int8_t);
int8_t  getForwardingWorkers();
//void setFibSharding(bool);
//bool getFibSharding();

boost::asio::io_service*
getGlobalIoService(int);
void setGlobalIoService(int, boost::asio::io_service*);

int32_t getGlobalIwId();
void setGlobalIwId(int32_t id);

bool getCommandRx(size_t);
void setCommandRx(size_t, bool val);
void resetCommandRx();

void print_payload(const u_char *payload,int len);

std::string getRouterName();
void setRouterName(std::string);

} // namespace mw-nfd

#endif // MW_NFD_DAEMON_COMMON_GLOBAL_HPP
