
#ifndef MW_NFD_WORKER_HPP
#define MW_NFD_WORKER_HPP

#include "common/config-file.hpp"
#include "fw/face-table.hpp"
#include "fw/forwarder.hpp"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/lp/packet.hpp>
#include <ndn-cxx/mgmt/dispatcher.hpp>
#include <ndn-cxx/net/network-monitor.hpp>
#include <ndn-cxx/net/network-interface.hpp>
#include <ndn-cxx/mgmt/nfd/face-monitor.hpp>
#include <ndn-cxx/mgmt/nfd/face-event-notification.hpp>
#include <face/transport.hpp>
#include <face/link-service.hpp>
#include <face/generic-link-service.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <boost/asio.hpp>
#include <boost/exception/diagnostic_information.hpp>

#include <string>

namespace nfd {

class CommandAuthenticator;
class ForwarderStatusManager;
class FaceManager;
class FibManager;
class CsManager;
class StrategyChoiceManager;

namespace face {
class Face;
class FaceSystem;
} // namespace face

/**
 * \brief Class representing the MW-NFD instance.
 *
 * This class is used to initialize all components of MW-NFD.
 */
class MwNfd : noncopyable
{
public:
  ~MwNfd();

  void initialize(uint32_t);

  void setFaceTable(std::shared_ptr<FaceTable> faceTable)
  {
        m_faceTable = faceTable;
  }

  void handleNfdcCommand();

  void runWorker();

  explicit MwNfd(int8_t wid, boost::asio::io_service*, ndn::KeyChain&, const nfd::face::GenericLinkService::Options& options);

    void decodeNetPacketFromMq(const shared_ptr<ndn::Buffer> buffer,
            const shared_ptr<ndn::Interest> 
            , const shared_ptr<ndn::Data>, 
            //uint64_t faceId, 
            const nfd::face::Face *face,
            EndpointId ep, uint32_t);
    void decodeNetPacketFromMq(const shared_ptr<ndn::Buffer> buffer, 
            const nfd::face::Face *face,
            //uint64_t faceId, 
            EndpointId ep);

Fib& getFibTable();
Cs& getCsTable();
const ForwarderCounters &getCountersInfo();
StrategyChoice& getStrategyChoiceTable();
NameTree& getNameTreeTable();
Pit & getPitTable();
Measurements& getMeasurementsTable();
  void prepareBulkFibTest(std::string port0, std::string port1);

  bool config_bulk_fib(FaceId faceId0, FaceId faceId1, bool);
  bool config_bulk_fib(FaceId faceId0, FaceId faceId1, bool, bool);

  uint8_t getWorkerId(){return m_workerId;}

private:

  void configureLogging();

  void initializeManagement();

  void decodeInterest(const Block& netPkt, const lp::Packet& firstPkt, const EndpointId , const Face*);
  void decodeData(const Block& netPkt, const lp::Packet& firstPkt, const EndpointId, const Face*);
  void decodeNack(const Block& netPkt, const lp::Packet& firstPkt, const EndpointId, const Face*);

  void on_register_failed(){}

  

private:
void bulk_test_case_01();
void nfdc_process(const boost::system::error_code& error, size_t bytes_recvd);
 void terminate(const boost::system::error_code& error, int signalNo);
 void onNotification(const ndn::nfd::FaceEventNotification& notification);

  ConfigSection m_configSection;

  shared_ptr<FaceTable> m_faceTable;
  unique_ptr<face::FaceSystem> m_faceSystem;
  unique_ptr<Forwarder> m_forwarder;

  ndn::KeyChain& m_keyChain;
  shared_ptr<face::Face> m_internalFace;
  shared_ptr<ndn::Face> m_internalClientFace;
  unique_ptr<ndn::mgmt::Dispatcher> m_dispatcher;
  shared_ptr<CommandAuthenticator> m_authenticator;
  unique_ptr<ForwarderStatusManager> m_forwarderStatusManager;
  unique_ptr<FaceManager> m_faceManager;
  unique_ptr<FibManager> m_fibManager;
  unique_ptr<CsManager> m_csManager;
  unique_ptr<StrategyChoiceManager> m_strategyChoiceManager;

  spdlog::logger& m_logger;

  shared_ptr<ndn::net::NetworkMonitor> m_netmon;
  scheduler::ScopedEventId m_reloadConfigEvent;
  int8_t m_workerId;
  boost::asio::signal_set m_terminationSignalSet;
  boost::asio::signal_set m_fibSignalSet;

  enum { max_length = 1024 };

    uint64_t nInNetInvalid;
    uint64_t nInInterests;

    uint64_t nInDatas;
    uint64_t nInNacks;

    int m_face1;
    int m_face0;
  bool m_done;
    uint32_t m_inputWorkers;

    boost::asio::io_service* m_ios;
    int m_sockNfdcCmd;
	std::string m_bulkFibPort0;
	std::string m_bulkFibPort1;

    nfd::face::LpReassembler m_reassembler;
    ndn::Face m_face;

    ndn::nfd::FaceMonitor m_faceMonitor;
};

} // namespace nfd

#endif 
