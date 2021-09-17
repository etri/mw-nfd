
#ifndef NFD_DAEMON_MGMT_FORWARDER_STATUS_REMOTE_HPP
#define NFD_DAEMON_MGMT_FORWARDER_STATUS_REMOTE_HPP

#include <map>

#include "face/face-system.hpp"
#include "fw/face-table.hpp"

#include <ndn-cxx/face.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

using boost::property_tree::ptree;

#include <ndn-cxx/mgmt/nfd/forwarder-status.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-info.hpp>
#include <ndn-cxx/ims/in-memory-storage-fifo.hpp>
#include <ndn-cxx/transport/unix-transport.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/mgmt/nfd/controller.hpp>
#include <ndn-cxx/mgmt/nfd/face-monitor.hpp>


using std::map;

namespace nfd {

class ForwarderRemoteAccess: noncopyable
{
public:
  ForwarderRemoteAccess(ndn::KeyChain& keyChain);
  void publish(const ndn::Name &, const ndn::Interest &);
  void ribPublish(const ndn::Name &, const ndn::Interest &);

    bool replyFromStore(const ndn::Interest& interestName, ndn::Face &);

    std::string prepareNextData(const ndn::Name &);


void onNotification(const ndn::nfd::FaceEventNotification& notification);
private:
  ndn::nfd::ForwarderStatus
  collectGeneralStatus();


	void formatStatusJson( ptree &, const ndn::nfd::ForwarderStatus&);
	void formatCsJson( ptree & );
	void formatScJson( ptree & );
	void formatFacesJson( ptree & );
	void formatChannelsJson( ptree & );
	void formatRibJson( ptree & );
	void formatFibJson( ptree & );
	  ndn::KeyChain& m_keyChain;
      std::string m_nfdStatus;

  std::vector<shared_ptr<Data>> m_store;
  std::vector<shared_ptr<Data>> m_rib_store;
  ndn::Face m_face;
  ndn::nfd::Controller m_nfdController;
//  ndn::nfd::FaceMonitor m_faceMonitor;
};

} // namespace nfd

#endif // NFD_DAEMON_MGMT_FORWARDER_STATUS_HPP
