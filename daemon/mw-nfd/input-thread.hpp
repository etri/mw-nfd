
#ifndef NFD_IW_NFD_HPP
#define NFD_IW_NFD_HPP

#include <spdlog/spdlog.h>
#include "face/face.hpp"
#include "common/global.hpp"
#include "fw/face-table.hpp"

#include "face/multicast-ethernet-transport.hpp"
#include "face/generic-link-service.hpp"
#include "face/network-predicate.hpp"
#include "face/tcp-channel.hpp"
#include "face/udp-channel.hpp"
#include "face/ethernet-channel.hpp"
#include <ndn-cxx/net/network-monitor-stub.hpp>
#include <ndn-cxx/face.hpp>
#include "face/udp-factory.hpp"
#include "face/protocol-factory.hpp"

#include <string>
#include <iostream>

namespace nfd {

namespace face {
class Face;
} // namespace face

using namespace std;

class InputThread : noncopyable
{
    public:
        explicit
            InputThread();

        ~InputThread();

        void initialize(int32_t, const std::string ifname);
        bool applyEthernetToNetif(const string ifname);
        bool createTcpFactory(const string ifname);
        bool createUdpFactory(const string ifname);

         void terminate(const boost::system::error_code& error, int signalNo)
         {
                 //systemdNotify("STOPPING=1");
                 getGlobalIoService().stop();
         }

         void onNfdcFaceCmd(std::string);
         void onFaceSystemEthMcFace(std::string, std::string);
         void onFaceSystemEthUcFace(std::string, std::string);
         void onFaceSystemUdpFace(std::string, uint16_t, std::string, size_t);

         void run();

    private:
        ndn::nfd::FaceScope
            determineFaceScopeFromAddresses(const boost::asio::ip::address& local,
                    const boost::asio::ip::address& remote) const;


                    void on_interest(const ndn::Interest &interest);

    private:
        shared_ptr<nfd::FaceTable> m_faceTable;
        spdlog::logger& m_logger;

        boost::asio::signal_set m_terminationSignalSet;
        nfd::face::IpAddressPredicate m_local;
        shared_ptr<nfd::face::TcpChannel> m_tcpChannel;
        shared_ptr<nfd::face::UdpChannel> m_udpChannel;
        shared_ptr<nfd::face::EthernetChannel> m_ethChannel;

        shared_ptr<ndn::Face> m_face;

        int32_t m_Id;
        //int32_t m_workers;
        int32_t m_ifIndex;
	std::string m_ifName;
	std::set<FaceId> m_faceIdSet;
	std::set<std::string> m_ipAddressSet;

};

} // namespace nfd

#endif // NFD_DAEMON_NFD_HPP
