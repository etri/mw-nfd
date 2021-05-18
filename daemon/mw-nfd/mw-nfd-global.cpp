/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2019-2021,  HII of ETRI.
 *
 * This file is part of MW-NFD (Named Data Networking Forwarding Daemon).
 * See AUTHORS.md for complete list of NFD authors and contributors.
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
 * MW-NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdint.h>
#include <boost/atomic.hpp>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#if defined(__linux__)
#include <linux/if_packet.h>
#endif
#include <net/ethernet.h> /* the L2 protocols */
#include "common/global.hpp"
#include "mw-nfd-global.hpp"
#include "common/city-hash.hpp"

int8_t g_forwardingWorkers=0;

std::shared_ptr<nfd::MwNfd> g_mwNfds[MW_NFD_WORKER];

int g_sockMwNfdCommand[MW_NFD_WORKER];
int g_nfdcSocket=0;

#ifdef ETRI_DEBUG_COUNTERS
extern size_t g_nEnqMiss[COUNTERS_MAX];
#endif

namespace nfd {

time::system_clock::TimePoint g_startTimestamp(time::system_clock::now());
bool g_commandRxFlag[DCN_MAX_WORKERS];
void resetCommandRx()
{
	for(int i=0;i<DCN_MAX_WORKERS;i++)
		g_commandRxFlag[i]=false;
}
bool getCommandRx(size_t idx)
{
	return g_commandRxFlag[idx];
}
void setCommandRx(size_t idx, bool val)
{
	g_commandRxFlag[idx] = val;
}

bool g_workerTimerTriggerList[DCN_MAX_WORKERS];

int g_prefixLength4Distribution;
bool g_bulkFibTest=false;
bool g_outgoingMwNfd=false;
int g_outgoingMwNfdWorkers=0;
std::string g_bulkFibFilePath;
bool g_fibSharding=true;

face::FaceSystem *g_faceSystem;

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

std::string g_routerName="N/A";
void setRouterName(std::string val)
{
		g_routerName= val;
}

std::string getRouterName()
{
		return g_routerName;
}

void setBulkFibFilePath(std::string val)
{
	g_bulkFibFilePath=val;
}
void setOutgoingMwNfd()
{
		g_outgoingMwNfd=true;
}
void setBulkFibTest()
{
		g_bulkFibTest=true;
}
std::string getBulkFibFilePath()
{
 return g_bulkFibFilePath;	
}
void setOutgoingMwNfdWorkers(int cnt)
{
	g_outgoingMwNfdWorkers=cnt;
	if(cnt>0)
		g_outgoingMwNfd=true;
}
int getOutgoingMwNfdWorkers()
{
	return g_outgoingMwNfdWorkers;
}
bool getOutgoingMwNfd()
{
	return g_outgoingMwNfd;
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

size_t emitMwNfdcCommand(int wid/*-1, all emit*/, int mgr, int verb,
    ndn::nfd::ControlParameters parameters, bool netName)
{
#if 0
    int i,numbytes;
    char buf[MW_NFD_CMD_BUF_SIZE]={0,};
    mw_nfdc_ptr nfdc = (mw_nfdc_ptr)buf;
    size_t retval=0;
    size_t ret=0;
	auto params = make_shared<ndn::nfd::ControlParameters>(parameters);

	#define  SOCK_LOCALFILE   "/tmp/.mw-nfd-cli"
	
	int    sock;
   	struct sockaddr_un   local_addr;
   	struct sockaddr_un   target_addr;

	for(i=0;i<g_forwardingWorkers;i++){

		std::string SOCK_WORKERFILE = "/tmp/.mw-nfd-" + std::to_string(i);

		if ( 0 == access( SOCK_LOCALFILE, F_OK))
      		unlink( SOCK_LOCALFILE);

		sock  = socket( PF_FILE, SOCK_DGRAM, 0);
   
		if( -1 == sock)
		{
			printf( "failed to create socket\n");
			continue;
		}

		memset( &local_addr, 0, sizeof( local_addr));
		local_addr.sun_family        = AF_UNIX;
		strcpy( local_addr.sun_path, SOCK_LOCALFILE);

		if( -1 == bind( sock, (struct sockaddr*)&local_addr, sizeof( local_addr))) {
			printf( "failed for bind()\n");
			close(sock);
			continue;
		}

		memset( &target_addr, 0, sizeof( target_addr));
		target_addr.sun_family        = AF_UNIX;
		strcpy( target_addr.sun_path, SOCK_WORKERFILE.c_str());

		nfdc->mgr = mgr;
		nfdc->verb = verb;
		nfdc->ret = MW_NFDC_CMD_OK;
		nfdc->netName = netName;
		nfdc->parameters = params;

		numbytes = sendto(sock, buf, sizeof(buf), 0,
				(struct sockaddr*)&target_addr, sizeof( target_addr));

		setCommandRx(i, true);
		if( numbytes == sizeof(buf)){
			memset(buf, '\0', sizeof(buf));
			numbytes = 0;
			numbytes = recvfrom(sock, buf, sizeof(buf), 0, NULL,0);

			if(numbytes){
				retval += nfdc->retval;
				ret = nfdc->ret;
			}
		}else{
            //std::cout << "mgmt::Can't send worker: " << i << " command." << std::cout ;
        }

		setCommandRx(i, false);
		close(sock);
	}

#else

 int i,numbytes;
    char buf[MW_NFD_CMD_BUF_SIZE]={0,};
    mw_nfdc_ptr nfdc = (mw_nfdc_ptr)buf;
    struct sockaddr_in worker, their;
    size_t retval=0;
    size_t ret=0;

	memset(&worker, 0, sizeof(worker));
	worker.sin_family = AF_INET;
	worker.sin_addr.s_addr = inet_addr("127.0.0.1");

	socklen_t addr_len;

	if(g_nfdcSocket==0){
		g_nfdcSocket = socket(AF_INET, SOCK_DGRAM, 0);
	}

	addr_len = sizeof worker;

	auto params = make_shared<ndn::nfd::ControlParameters>(parameters);

	for(i=0;i<g_forwardingWorkers;i++){
		worker.sin_port = htons(MW_NFDC_PORT+i);

		nfdc->mgr = mgr;
		nfdc->verb = verb;
		nfdc->ret = MW_NFDC_CMD_OK;
		nfdc->netName = netName;
		nfdc->parameters = params;

		numbytes = sendto(g_nfdcSocket, buf, sizeof(buf), 0,
				(struct sockaddr*)&worker, addr_len);

		setCommandRx(i, true);
		if( numbytes == sizeof(buf)){
			memset(buf, '\0', sizeof(buf));
			numbytes = 0;
			numbytes = recvfrom(g_nfdcSocket, buf, sizeof(buf), 0,
					(struct sockaddr*)&their, &addr_len);

			if(numbytes){
				retval += nfdc->retval;
				ret = nfdc->ret;
			}
		}else{
            //std::cout << "mgmt::Can't send worker: " << i << " command." << std::cout ;
        }

		setCommandRx(i, false);
	}
#endif
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

    bool ret __attribute__((unused));

    do{ 
        ret=tlv::readType(pos, end, type);
        ret=tlv::readVarNumber(pos, end, length);

	if( !memcmp(pos, "localhost", 9) or g_forwardingWorkers==0){
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

std::tuple<bool, uint32_t, int32_t> 
dissectNdnPacket( const uint8_t *wire, size_t size  )
{
    uint32_t type=0;
    int64_t worker=-1;
    int64_t pitToken=-1;
    uint64_t length;
    const uint8_t* pos = wire;
    const uint8_t* end = wire + size;
    uint32_t packetType = 0;  
    uint64_t seq=0, index=0, count=0;
    bool isFrag = false;
    bool ret __attribute__((unused));

//std::cout << "dissectNdnPacket: " << size << std::endl;
    if( wire[0]==0x64 ){

        ret=tlv::readType(pos, end, packetType);  
        ret=tlv::readVarNumber(pos, end, length);  

        do{   
            ret=tlv::readType(pos, end, type);  

			if(ret==false)
    			return std::make_tuple(false, ndn::lp::tlv::LpPacket, worker);

            ret=tlv::readVarNumber(pos, end, length);  
			if(ret==false)
    			return std::make_tuple(false, ndn::lp::tlv::LpPacket, worker);

			//std::cout << std::hex << "Type: " << type << std::endl;
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
                //worker = pitToken = pos[0]; 
                ST_PIT_TOKEN *tok = (ST_PIT_TOKEN *)pos;
                worker = pitToken = tok->workerId;  
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
    }else{
        ret = tlv::readType(pos, end, packetType);  
        ret = tlv::readVarNumber(pos, end, length);  

        ret = tlv::readType(pos, end, type);  
        ret = tlv::readVarNumber(pos, end, length);  
        if(type == tlv::Name){   
            worker=computeWorkerId(pos, length);  
        }  
    }
    return std::make_tuple(true, packetType, worker);
}

MoodyMQ g_dcnMoodyMQ[MQ_ARRAY_MAX_SIZE][MQ_ARRAY_MAX_SIZE]={nullptr,};
//MoodyMQ2 g_dcnMoodyOutMQ[MQ_ARRAY_MAX_SIZE]={nullptr,};
BoostMQ g_dcnBoostMQ[MQ_ARRAY_MAX_SIZE][MQ_ARRAY_MAX_SIZE]={nullptr,};

void mq_allocation()
{
    uint32_t i,j;

    for(i=0;i<MQ_ARRAY_MAX_SIZE;i++){
			//g_dcnMoodyOutMQ[i] = std::make_shared<moodycamel::ConcurrentQueue<NDN_OUT_MSG, NdnTraits>>();
        for(j=0;j<MQ_ARRAY_MAX_SIZE;j++){
            g_dcnMoodyMQ[i][j] = std::make_shared<moodycamel::ConcurrentQueue<NDN_MSG, NdnTraits>>();
        }
    }
}

thread_local int32_t g_iwId;

namespace ip = boost::asio::ip;

#define MAX_IO_CAPA 256

boost::asio::io_service* g_ioServiceArray[MAX_IO_CAPA]={nullptr,};

boost::asio::io_service* getGlobalIoService(int idx)
{
	if(idx < 0) idx=0;
    if( idx < MAX_IO_CAPA ){
        if( g_ioServiceArray[idx] != nullptr ){
            return g_ioServiceArray[idx];
        }else{
            return &getGlobalIoService();
        }
    }
    return &getGlobalIoService();
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

int getIfIndex(const char *addr)
{

	struct ifaddrs *ifaddr, *ifa;
	int family, s;
	char host[NI_MAXHOST];
	char netmask[NI_MAXHOST];

	if (getifaddrs(&ifaddr) == -1) {
#ifndef ETRI_NFD_ORG_ARCH
		std::cout << "getifaddrs Error--------------: " << addr << std::endl;
#endif
		return -1;
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
				return -1;
			}
			s = getnameinfo(ifa->ifa_netmask,
					(family == AF_INET) ? sizeof(struct sockaddr_in) :
					sizeof(struct sockaddr_in6),
					netmask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if (s != 0) {
				printf("getnameinfo() netmask failed: %s\n", gai_strerror(s));
				return -1;
			}

			if(!strcmp(host, "127.0.0.1"))
				continue;

			printf("Host: %s/netmask:%s\n", host, netmask);
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

	return -1;
}

int8_t getForwardingWorkers()
{
    return g_forwardingWorkers;
}

void setForwardingWorkers(int8_t cap)
{
    g_forwardingWorkers = cap;
}


/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

bool dcnReceivePacket(const uint8_t * pkt, size_t len, uint64_t face)
{
	std::cout << "dcnReceivePacket on CPU " << sched_getcpu() << std::endl;
#ifdef ETRI_NFD_ORG_ARCH
	return false;
#else
    int32_t packetType=0;
    int32_t worker=0;
    bool isOk=false;
    bool ret __attribute__((unused));
    std::tie(isOk, packetType, worker) = dissectNdnPacket( pkt, len );

    if( !isOk ){
        if(packetType==ndn::lp::tlv::LpPacket)
        return false;
    }

    if(worker==DCN_LOCALHOST_PREFIX){
        return false;
    }

    if(packetType>=0 and worker >=0){
        NDN_MSG msg;
        msg.buffer = make_shared<ndn::Buffer>( pkt, len );
        msg.endpoint = 0;
        msg.type = 0; // Buffer type
        msg.faceId = face;

        if(packetType==tlv::Interest)
            ret = nfd::g_dcnMoodyMQ[ getGlobalIwId() ][worker]->try_enqueue(msg);
        else
            ret = nfd::g_dcnMoodyMQ[ getGlobalIwId()+1 ][worker]->try_enqueue(msg);
#ifdef ETRI_DEBUG_COUNTERS
        if(ret==false) g_nEnqMiss[face-face::FACEID_RESERVED_MAX]+=1;
#endif
    }   


    return true;
#endif
}


} // namespace mw-nfd

