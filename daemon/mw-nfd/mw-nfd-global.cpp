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

#include <stdlib.h>
#include <boost/atomic.hpp>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include "common/global.hpp"
#include "mw-nfd-global.hpp"
#include "common/city-hash.hpp"

int8_t g_forwardingWorkers=0;

std::shared_ptr<nfd::MwNfd> g_mwNfds[MW_NFD_WORKER];

int g_sockMwNfdCommand[MW_NFD_WORKER];
int nfdcSocket=0;

namespace nfd {

int g_prefixLength4Distribution;
bool g_bulkFibTest=false;
std::string g_bulkFibFilePath;
bool g_fibSharding=true;

bool g_mwNfdParameters=0;

std::map<uint64_t/*MessageIdentifier*/, int32_t/*worker-id*/> g_fragmentMap;

void setGlobalNetName(bool val)
{
    g_mwNfdParameters=val;
}

bool getGlobalNetName()
{
    return g_mwNfdParameters;
}

void setFibSharding(bool val)
{
		g_fibSharding= val;
}

bool getFibSharding()
{
		return g_fibSharding;
}

void setBulkFibFilePath(std::string val)
{
	g_bulkFibFilePath=val;
}
void setBulkFibTest(bool val)
{

		g_bulkFibTest=val;
}
std::string getBulkFibFilePath()
{
 return g_bulkFibFilePath;	
}
bool getBulkFibTest()
{
	return g_bulkFibTest;
}
void setPrefixLength4Distribution(size_t size)
{
    g_prefixLength4Distribution = size;
}

size_t getPrefixLength4Distribution()
{
    return g_prefixLength4Distribution;
}


void setMwNfd(int8_t wid, std::shared_ptr<nfd::MwNfd> mwNfd)
{
		g_mwNfds[wid]=mwNfd;
}
std::shared_ptr<nfd::MwNfd> getMwNfd(int8_t wid)
{
		return g_mwNfds[wid];
}

size_t emitMwNfdcCommand(int wid/*-1, all emit*/, int mgr, int verb, std::shared_ptr<ndn::Interest> interest, 
    std::shared_ptr<ndn::nfd::ControlParameters> parameters, bool netName)
{
    int i, numbytes;
    char buf[128]={0,};
    mw_nfdc_ptr nfdc = (mw_nfdc_ptr)buf;
    struct sockaddr_in worker, their;
    fd_set readfds;
    size_t retval=0;
    size_t ret=0;

    nfdc->mgr = mgr;
    nfdc->verb = verb;
    nfdc->ret = MW_NFDC_CMD_OK;
    nfdc->netName = netName;
    nfdc->interest = interest;
    nfdc->parameters = parameters;

    memset(&worker, 0, sizeof(worker));
    worker.sin_family = AF_INET;
    worker.sin_addr.s_addr = inet_addr("127.0.0.1");

    FD_ZERO(&readfds);
    std::map<int, int> retMap;

    socklen_t addr_len;
    addr_len = sizeof their;

	if(nfdcSocket==0)
		nfdcSocket = socket(PF_INET, SOCK_DGRAM, 0);

    for(i=0;i<g_forwardingWorkers;i++){
        worker.sin_port = htons(MW_NFDC_PORT+i);

        numbytes = sendto(nfdcSocket, buf, sizeof(mw_nfdc), 0,
                        (struct sockaddr*)&worker, sizeof(worker));

        if( mgr == MW_NFDC_MGR_CS and verb == MW_NFDC_VERB_ERASE){
			numbytes = recvfrom(i, buf, sizeof(mw_nfdc), 0,
					(struct sockaddr*)&their, &addr_len);
			if(numbytes){
                retval += nfdc->retval;
                ret = nfdc->ret;
            }
        }
    }

    if( mgr == MW_NFDC_MGR_CS and verb == MW_NFDC_VERB_ERASE)
        return retval;

    return ret;
}

int32_t computeWorkerId(const uint8_t *wire, size_t size)
{
    uint32_t type = 0;
    uint64_t length = 0;
    int nameComponentCnt = 0;
    size_t hash=0;

    const uint8_t* pos = wire;
    const uint8_t* end = wire+size;

    do{ 
        tlv::readType(pos, end, type);
        tlv::readVarNumber(pos, end, length);

	if( !memcmp(pos, "localhost", 9) ){
		return DCN_LOCALHOST_PREFIX;
	}

        if(type == tlv::GenericNameComponent){
            hash ^= CityHash64( (char *)pos, length       );  
            ++nameComponentCnt;
            if(nameComponentCnt==g_prefixLength4Distribution)
                break;

            pos += length;
        }   

    }while(pos!=end);

    return (hash % g_forwardingWorkers);
}

std::tuple<uint32_t, int32_t> 
dissectNdnPacket( const uint8_t *wire, size_t size  )
{
    uint32_t type=0;
    int worker=-1;
    int pitToken=-1;
    uint64_t length;
    const uint8_t* pos = wire;
    const uint8_t* end = wire + size;
    uint32_t packetType = 0;  
    uint64_t seq=0, index=0, count=0;
    bool isFrag = false;

    if( wire[0]==0x64 ){

        tlv::readType(pos, end, packetType);  
        tlv::readVarNumber(pos, end, length);  

        do{   
            tlv::readType(pos, end, type);  
            tlv::readVarNumber(pos, end, length);  

            if(type == ndn::lp::tlv::FragCount){  
                if( length == 1 )
                    count = pos[0];
                else{
                    memcpy(&count, pos, length);
                    boost::endian::big_to_native(count);
                }
            }

            if(type == ndn::lp::tlv::FragIndex){  
                if( length == 1 )
                    index = pos[0];
                else{
                    memcpy(&index, pos, length);
                    boost::endian::big_to_native(index);
                }

            }

            if(type == ndn::lp::tlv::Sequence){  
                memcpy(&seq, pos, length);
                boost::endian::big_to_native_inplace(seq);
                isFrag = true;
            }

            if(type == ndn::lp::tlv::TxSequence){   //for Reliability

            }

            if(type == ndn::lp::tlv::PitToken){  
                worker = pitToken = pos[0];  
            }  
            if(type == ndn::lp::tlv::Fragment){  
                if( index != 0 ) break;
                continue;  
            }  
            if(type == tlv::Name){   
                worker=computeWorkerId(pos, length);  
                break;  
            }  

            if(type == tlv::Interest or type==tlv::Data){   
                packetType = type;  
                continue;  
            }  

            pos += length;  

        }while(pos!=end);  

#if 1
            if(packetType != tlv::Interest and pitToken!=-1){
                worker = pitToken; 
                if(count>0)
                    g_fragmentMap.insert( std::pair<uint64_t, int32_t>(seq-index, pitToken) );
            }else if(isFrag){
                if(index==0){
                    g_fragmentMap.insert( std::pair<uint64_t, int32_t>(seq-index, worker) );
                }else{
                    worker = g_fragmentMap.find(seq-index)->second;
                    if(index == (count-1))
                        g_fragmentMap.erase(seq-index);
                }
            }
#endif

    }else{


        tlv::readType(pos, end, packetType);  
        tlv::readVarNumber(pos, end, length);  

        tlv::readType(pos, end, type);  
        tlv::readVarNumber(pos, end, length);  
        if(type == tlv::Name){   
            worker=computeWorkerId(pos, length);  
        }  

    }
    return std::make_tuple(packetType, worker);
}


int get_interface_number_by_device_name(int socket_fd, std::string interface_name) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    if (interface_name.size() > IFNAMSIZ) {
        return -1;

    }

    strncpy(ifr.ifr_name, interface_name.c_str(), sizeof(ifr.ifr_name));

    if (ioctl(socket_fd, SIOCGIFINDEX, &ifr) == -1) {
        return -1;

    }

    return ifr.ifr_ifindex;

}

MoodyMQ g_dcnMoodyMQ[MQ_ARRAY_MAX_SIZE][MQ_ARRAY_MAX_SIZE]={nullptr,};
MoodyMQ g_dcnMoodyOutMQ[MQ_ARRAY_MAX_SIZE][MQ_ARRAY_MAX_SIZE]={nullptr,};
BoostMQ g_dcnBoostMQ[MQ_ARRAY_MAX_SIZE][MQ_ARRAY_MAX_SIZE]={nullptr,};

void mq_allocation()
{
    uint32_t i,j;

    for(i=0;i<MQ_ARRAY_MAX_SIZE;i++){
        for(j=0;j<MQ_ARRAY_MAX_SIZE;j++){
            g_dcnMoodyMQ[i][j] = std::make_shared<moodycamel::ConcurrentQueue<NDN_MSG, NdnTraits>>();
            g_dcnMoodyOutMQ[i][j] = std::make_shared<moodycamel::ConcurrentQueue<NDN_MSG, NdnTraits>>();
        }
    }
}

thread_local int32_t g_iwId;

#if 0
static unique_ptr<ForwarderCounters> g_counters;

static size_t g_fibEntries;
static size_t g_csEntries;
static size_t g_mtEntries;
static size_t g_nteEntries;
static size_t g_pitEntries;
#endif

static shared_ptr<spdlog::logger> g_logService=nullptr;

namespace ip = boost::asio::ip;

#define MAX_IO_CAPA 256

boost::asio::io_service* g_ioServiceArray[MAX_IO_CAPA]={nullptr,};

boost::asio::io_service* getGlobalIoService(int idx)
{
    if( idx < MAX_IO_CAPA ){
        if( g_ioServiceArray[idx] != nullptr ){
            //getGlobalLogger().info("getGlobalIoService() got IOS of {}" , idx);
            return g_ioServiceArray[idx];
        }else{
            //getGlobalLogger().info("getGlobalIoService() got 0-Main IOS of {}" , idx );
            return &getMainIoService();
        }
    }
    //getGlobalLogger().info("getGlobalIoService() got 1-Main IOS of {}", idx);
    return &getMainIoService();
}

int32_t getGlobalIwId()
{
    return g_iwId;
}

void setGlobalIwId(int32_t id)
{
    g_iwId = id;
}

void setGlobalIoService(int idx, boost::asio::io_service* ios)
{
    g_ioServiceArray[idx] = ios;
}

int32_t getIfIndex(const char *addr)
{

	struct ifaddrs *ifaddr, *ifa;
	int family, s;
	char host[NI_MAXHOST];
	char netmask[NI_MAXHOST];

	if (getifaddrs(&ifaddr) == -1) {
		getGlobalLogger().info("getifaddrs Error--------------");
		return 0;
	}

	/* Walk through linked list, maintaining head pointer so we can free list later */

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		family = ifa->ifa_addr->sa_family;

		if (family == AF_INET) {
			s = getnameinfo(ifa->ifa_addr,
					(family == AF_INET) ? sizeof(struct sockaddr_in) :
					sizeof(struct sockaddr_in6),
					host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if (s != 0) {
				printf("getnameinfo() address failed: %s\n", gai_strerror(s));
				return 0;
			}
			s = getnameinfo(ifa->ifa_netmask,
					(family == AF_INET) ? sizeof(struct sockaddr_in) :
					sizeof(struct sockaddr_in6),
					netmask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if (s != 0) {
				printf("getnameinfo() netmask failed: %s\n", gai_strerror(s));
				return 0;
			}

			ip::network_v4 host_v4(ip::address_v4::from_string(host), 
					ip::address_v4::from_string(netmask));

			ip::network_v4 addr_v4(ip::address_v4::from_string(addr), 
					ip::address_v4::from_string(netmask));

			if(host_v4.network() ==addr_v4.network()){
				return if_nametoindex(ifa->ifa_name);
			}
		}
	}

	freeifaddrs(ifaddr);

	return 0;
}

int8_t getForwardingWorkers()
{
    return g_forwardingWorkers;
}

void setForwardingWorkers(int8_t cap)
{
    g_forwardingWorkers = cap;
}

spdlog::logger& getGlobalLogger()
{
    return *g_logService;
}

shared_ptr<spdlog::logger> makeGlobalLogger(std::string path)
{
    if(path == "stdout" )
        g_logService = spdlog::stdout_color_mt("MW-NFD");
    else{
        // Create a daily logger - a new file is created every d    ay on 8:00am
        g_logService = spdlog::daily_logger_mt("dcn-daily-logger", path, 8, 0);
    }

    return g_logService;
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

} // namespace mw-nfd

