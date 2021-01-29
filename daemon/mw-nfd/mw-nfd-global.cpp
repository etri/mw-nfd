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
bool g_mwNfdCmdFlags[MW_NFD_WORKER];
int g_nfdcSocket=0;

namespace nfd {

bool g_commandRxFlag[128];
void resetCommandRx()
{
	for(int i=0;i<128;i++)
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

size_t emitMwNfdcCommand(int wid/*-1, all emit*/, int mgr, int verb,// std::shared_ptr<ndn::Interest> interest, 
    //std::shared_ptr<ndn::nfd::ControlParameters> parameters, bool netName)
    ndn::nfd::ControlParameters parameters, bool netName)
{
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
		}else
			getGlobalLogger().info("mgmt::Can't send worker:{} command", i);

		setCommandRx(i, false);
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

    bool ret __attribute__((unused));

    do{ 
        ret=tlv::readType(pos, end, type);
        ret=tlv::readVarNumber(pos, end, length);

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
    bool ret __attribute__((unused));

    if( wire[0]==0x64 ){

        ret=tlv::readType(pos, end, packetType);  
        ret=tlv::readVarNumber(pos, end, length);  

        do{   
            ret=tlv::readType(pos, end, type);  
            ret=tlv::readVarNumber(pos, end, length);  

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

#if !defined(ETRI_NFD_ORG_ARCH)
static shared_ptr<spdlog::logger> g_logService=nullptr;
#endif

namespace ip = boost::asio::ip;

#define MAX_IO_CAPA 256

boost::asio::io_service* g_ioServiceArray[MAX_IO_CAPA]={nullptr,};

boost::asio::io_service* getGlobalIoService(int idx)
{
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

int32_t getIfIndex(const char *addr)
{

	struct ifaddrs *ifaddr, *ifa;
	int family, s;
	char host[NI_MAXHOST];
	char netmask[NI_MAXHOST];

	if (getifaddrs(&ifaddr) == -1) {
#if !defined(ETRI_NFD_ORG_ARCH)
		std::cout << "getifaddrs Error--------------: " << addr << std::endl;
#endif
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

			if( !strcmp(host, "127.0.0.1"))
				return 0;

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

#if !defined(ETRI_NFD_ORG_ARCH)
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
#endif


} // namespace mw-nfd

