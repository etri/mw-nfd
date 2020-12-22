
#include "input-thread.hpp"
#include "common/global.hpp"
#include "mw-nfd-global.hpp"
#include "common/logger.hpp"
#include "face/protocol-factory.hpp"
#include "face/unicast-udp-transport.hpp"
#include <boost/chrono.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>

#include <boost/lexical_cast.hpp>
#include <ndn-cxx/transport/unix-transport.hpp>
#include <ifaddrs.h>

namespace nfd {

extern std::shared_ptr<FaceTable> g_faceTable;

namespace ip = boost::asio::ip;
namespace net = ndn::net;

using namespace nfd::face;

InputThread::InputThread()
  : m_faceTable(nullptr)
  , m_logger(getGlobalLogger())
  , m_terminationSignalSet(getGlobalIoService())
	,m_ifIndex(0)
{

  m_terminationSignalSet.add(SIGINT);
  m_terminationSignalSet.add(SIGTERM);
  m_terminationSignalSet.async_wait(bind(&InputThread::terminate, this, _1, _2));

  m_local.assign({{"subnet", "127.0.0.0/8"}, {"subnet", "::1/128"}}, {});
}

InputThread::~InputThread() = default;

ndn::nfd::FaceScope
InputThread::determineFaceScopeFromAddresses(const boost::asio::ip::address& local,
        const boost::asio::ip::address& remote) const
{
    //m_logger.info("determineFaceScopeFromAddresses...");
    if (m_local(local) && m_local(remote)) {
        return ndn::nfd::FACE_SCOPE_LOCAL;
    }
    return ndn::nfd::FACE_SCOPE_NON_LOCAL;
}

bool InputThread::createTcpFactory(const string ifname)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;

    struct sockaddr_in *sin;

    memset(&ifr, 0x00, sizeof(ifr));

    strcpy(ifr.ifr_name, ifname.c_str());

    if(ioctl(fd,SIOCGIFADDR,&ifr)<0){
        m_logger.info("TCPFactory-Error - SIOCGIFADDR: {}", ifname);
        return false;
    }

    sin = (sockaddr_in*)&ifr.ifr_addr;
    m_logger.info("InputThread's createTcpFactory - {}" , inet_ntoa(sin->sin_addr) );

    tcp::Endpoint endpoint(boost::asio::ip::address_v4::from_string(inet_ntoa(sin->sin_addr)), 6363);
    m_tcpChannel = make_shared<nfd::face::TcpChannel>(endpoint, true,
         bind(&InputThread::determineFaceScopeFromAddresses, this, _1, _2));

    m_tcpChannel->listen( [this] (auto face) { 
        //m_logger.info("InputThread's tcpChannel::face->getMqOffset: {}" , face->getIwId() );
        this->m_faceTable->add(std::move(face)); 
        
        } , nullptr);

    close(fd);

    return true;
}

void InputThread::onFaceSystemUdpFace(std::string remote, uint16_t port, std::string local, size_t nBytesReceived)
{
	m_logger.info("InputThread's onFaceSystemUdpFace - {}/{}/{}/{}", remote, port, local, nBytesReceived);
	auto opts = make_unique<nfd::face::GenericLinkService::Options>();
	opts->allowFragmentation = true;
	opts->allowReassembly = true;
	time::seconds idle(600);

	FaceUri remoteUri;

	bool ret =false; 
	if(ret == false){
		//m_logger.info("RemoteUri Parsing Error: {}", tokens[2]);
		return;
	}

	face::FaceParams faceParams;
	faceParams.persistency = ndn::nfd::FACE_PERSISTENCY_ON_DEMAND;
	faceParams.mtu = 1500; // must be replaced with getInf

	if(remoteUri.getScheme()=="udp4"){
		udp::Endpoint remoteEndpoint(boost::asio::ip::address_v4::from_string(remote), port);
		udp::Endpoint localEndpoint(boost::asio::ip::address_v4::from_string(local), port);

		ip::udp::socket socket(getGlobalIoService(), localEndpoint.protocol());
		socket.set_option(ip::udp::socket::reuse_address(true));
		socket.bind(localEndpoint);
		socket.connect(remoteEndpoint);

		auto transport = make_unique<UnicastUdpTransport>(std::move(socket), faceParams.persistency, idle, faceParams.mtu);

		int32_t idx = getIfIndex(transport->getLocalUri().getHost().c_str());
		if( idx!=-1 and m_ifIndex == idx ){
			auto linkService = make_unique<nfd::face::GenericLinkService>(*opts); //dcn_mode
			auto face = make_shared<nfd::face::Face>(std::move(linkService), std::move(transport));

			FaceId faceId = this->m_faceTable->add(std::move(face));
			m_logger.info("InputThread({}) - ifIndx/faceId: {}/{}", m_Id, m_ifIndex, faceId);

			m_faceIdSet.insert(faceId);

			if(nBytesReceived){
		//		transport->receiveDatagram(m_receiveBuffer.data(), nBytesReceived, error);
			}
		}
	}
}
void InputThread::onFaceSystemEthUcFace(std::string ifname, std::string address)
{
}

void InputThread::onFaceSystemEthMcFace(std::string ifname, std::string address)
{
	if( ifname.compare(m_ifName) ){
		//m_logger.info("IW's onFaceSystemEthMcFace - {}/{}, Ignored", ifname, m_ifName);
		return;
	}
	m_logger.info("InputThread({}) - onFaceSystemEthMcFace - {} - myIfname:{}, Acceped", m_Id, ifname, m_ifName);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;

	memset(&ifr, 0x00, sizeof(ifr));

	strcpy(ifr.ifr_name, ifname.c_str());
	ioctl(fd,SIOCGIFHWADDR,&ifr);

	auto netif = ndn::net::NetworkMonitorStub::makeNetworkInterface();

	netif->setEthernetAddress(
			ethernet::Address(
				ifr.ifr_hwaddr.sa_data[0],
				ifr.ifr_hwaddr.sa_data[1],
				ifr.ifr_hwaddr.sa_data[2],
				ifr.ifr_hwaddr.sa_data[3],
				ifr.ifr_hwaddr.sa_data[4],
				ifr.ifr_hwaddr.sa_data[5]
				));

	ioctl(fd, SIOCGIFMTU, &ifr);
	netif->setMtu(ifr.ifr_mtu);

	ioctl(fd, SIOCGIFINDEX, &ifr);

	m_ifIndex = ifr.ifr_ifindex;

	netif->setIndex(ifr.ifr_ifindex);
	netif->setName(ifname);

	netif->setType(ndn::net::InterfaceType::ETHERNET);

	ioctl(fd, SIOCGIFFLAGS, &ifr);
	netif->setFlags(ifr.ifr_flags);

	netif->setState(ndn::net::InterfaceState::RUNNING);

	auto opts = make_unique<nfd::face::GenericLinkService::Options>();
	opts->allowFragmentation = true;
	opts->allowReassembly = true;

	auto linkService = make_unique<nfd::face::GenericLinkService>(*opts); //dcn_mode
	auto transport = 
		make_unique<nfd::face::MulticastEthernetTransport>(*netif, 
				ethernet::Address::fromString(address), 
				ndn::nfd::LINK_TYPE_MULTI_ACCESS);

	auto face = make_shared<nfd::face::Face>(std::move(linkService), std::move(transport));

	m_faceTable->add(std::move(face));

	close(fd);
}

void InputThread::onNfdcFaceCmd(std::string cmd)
{
	m_logger.info("InputThread's IncomingFaceCmd - {}", cmd);
	vector<string> tokens;
	boost::split(tokens, cmd, boost::is_any_of(","));

	if( tokens[0]=="face" ){

		if(tokens[1]=="create"){
			//face,create,udp4://10.0.2.1:6363,://
			//

			auto opts = make_unique<nfd::face::GenericLinkService::Options>();
			opts->allowFragmentation = true;
			opts->allowReassembly = true;
    			time::seconds idle(600);

			FaceUri remoteUri;
			FaceUri localUri;

			bool ret = remoteUri.parse(tokens[2]);
			if(ret == false){
				m_logger.info("RemoteUri Parsing Error: {}", tokens[2]);
				return;
			}
			ret = remoteUri.parse(tokens[3]);

			face::FaceParams faceParams;
			faceParams.persistency = ndn::nfd::FACE_PERSISTENCY_ON_DEMAND;

			if(remoteUri.getScheme()=="udp4"){
				udp::Endpoint remoteEndpoint(boost::asio::ip::address_v4::from_string(remoteUri.getHost()), atoi(remoteUri.getPort().c_str()));
				udp::Endpoint localEndpoint(ip::udp::v4(), atoi(remoteUri.getPort().c_str()));

				ip::udp::socket socket(getGlobalIoService(), localEndpoint.protocol());
				socket.set_option(ip::udp::socket::reuse_address(true));
				socket.bind(localEndpoint);
				socket.connect(remoteEndpoint);

				auto transport = make_unique<UnicastUdpTransport>(std::move(socket), faceParams.persistency, idle, faceParams.mtu);
				m_logger.info("local:{}", transport->getLocalUri().toString());

				int32_t idx = getIfIndex(transport->getLocalUri().getHost().c_str());
				if( idx!=-1 and m_ifIndex == idx ){
					auto linkService = make_unique<nfd::face::GenericLinkService>(*opts); //dcn_mode
					auto face = make_shared<nfd::face::Face>(std::move(linkService), std::move(transport));

					FaceId faceId = this->m_faceTable->add(std::move(face));
					m_logger.info("InputThread({}) - UDP - ifIndx/faceId: {}/{}", m_Id, m_ifIndex, faceId);

					m_faceIdSet.insert(faceId);
				}
			}else if(remoteUri.getScheme()=="tcp4"){

			}
		}else if(tokens[1]=="update"){
		}else if(tokens[1]=="destroy"){
			//nfdc face destroy 300
			//nfdc face destroy udp4://192.0.2.1:6363
			int32_t faceId = boost::lexical_cast<uint32_t>(tokens[2]);
			if( m_faceIdSet.find(faceId) != m_faceIdSet.end() ){
				Face *face = m_faceTable->get(faceId);
				if (face != nullptr) {
					face->close();
				}
			}
		}
	} else {
	}
}

bool InputThread::createUdpFactory(const string ifname)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;

    struct sockaddr_in *sin;

    memset(&ifr, 0x00, sizeof(ifr));

    strcpy(ifr.ifr_name, ifname.c_str());

    if(ioctl(fd,SIOCGIFADDR,&ifr)<0){
        m_logger.info("InputThread's UDP-Factory-Error - SIOCGIFADDR");
        return false;
    }

    sin = (sockaddr_in*)&ifr.ifr_addr;
    m_logger.info("InputThread's createUdpFactory - {}" , inet_ntoa(sin->sin_addr) );

    time::seconds idle(600);
    bool marking=true;
    udp::Endpoint endpoint(boost::asio::ip::address_v4::from_string(inet_ntoa(sin->sin_addr)), 6363);
    m_udpChannel = std::make_shared<nfd::face::UdpChannel>(endpoint, idle, marking);

    m_udpChannel->listen( [this] (auto face) { 
        this->m_faceTable->add(std::move(face)); } , nullptr);

    close(fd);
    return true;
}

bool InputThread::applyEthernetToNetif(const string ifname)
{

    m_logger.info("McastConfigToNetif - {}", ifname);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;

    memset(&ifr, 0x00, sizeof(ifr));

    strcpy(ifr.ifr_name, ifname.c_str());
    ioctl(fd,SIOCGIFHWADDR,&ifr);

    auto netif = ndn::net::NetworkMonitorStub::makeNetworkInterface();

    netif->setEthernetAddress(
        ethernet::Address(
            ifr.ifr_hwaddr.sa_data[0],
            ifr.ifr_hwaddr.sa_data[1],
            ifr.ifr_hwaddr.sa_data[2],
            ifr.ifr_hwaddr.sa_data[3],
            ifr.ifr_hwaddr.sa_data[4],
            ifr.ifr_hwaddr.sa_data[5]
        ));

    ioctl(fd, SIOCGIFMTU, &ifr);
    netif->setMtu(ifr.ifr_mtu);

    ioctl(fd, SIOCGIFINDEX, &ifr);

    m_ifIndex = ifr.ifr_ifindex;

    netif->setIndex(ifr.ifr_ifindex);
    netif->setName(ifname);

    netif->setType(ndn::net::InterfaceType::ETHERNET);

    ioctl(fd, SIOCGIFFLAGS, &ifr);
    netif->setFlags(ifr.ifr_flags);

    netif->setState(ndn::net::InterfaceState::RUNNING);

    auto opts = make_unique<nfd::face::GenericLinkService::Options>();
    opts->allowFragmentation = true;
    opts->allowReassembly = true;

    auto linkService = make_unique<nfd::face::GenericLinkService>(*opts); //dcn_mode
    auto transport = 
        make_unique<nfd::face::MulticastEthernetTransport>(*netif, 
            ethernet::Address::fromString("01:00:5E:00:17:AA"), 
            ndn::nfd::LINK_TYPE_MULTI_ACCESS);

    auto face = make_shared<nfd::face::Face>(std::move(linkService), std::move(transport));

    close(fd);

    return true;
}

void InputThread::initialize(int32_t Id, const string ifname)
{
    m_logger.info("initializing InputThread-InputThreadId:{}/Physical Port:{}.", Id, ifname);

    m_faceTable = g_faceTable;
    m_Id = Id;
    m_ifName = ifname;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;

    if(fd > 0){
	    memset(&ifr, 0x00, sizeof(ifr));

	    strcpy(ifr.ifr_name, ifname.c_str());
	    ioctl(fd, SIOCGIFINDEX, &ifr);
	    m_ifIndex = ifr.ifr_ifindex;

        setGlobalIoService(m_ifIndex, &getGlobalIoService());
        
	//    m_logger.info("InputThread({}) - {} - ifIndex:{}", m_Id, ifname, m_ifIndex);

	    close(fd);
    }else
	    m_logger.info("InputThread({}) - {} - ERROR ++++++++ ifIndex:{}", m_Id, ifname, m_ifIndex);

    createTcpFactory(ifname);
}

void InputThread::run()
{

    
    do{
        getGlobalIoService().poll();
    }while(1);
}


} // namespace nfd
