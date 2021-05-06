
#ifndef NFD_DAEMON_MGMT_FORWARDER_STATUS_REMOTE_HPP
#define NFD_DAEMON_MGMT_FORWARDER_STATUS_REMOTE_HPP

#include "face/face-system.hpp"
#include "fw/face-table.hpp"

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

using boost::property_tree::ptree;

#include <ndn-cxx/mgmt/nfd/forwarder-status.hpp>

namespace nfd {

class ForwarderStatusRemote: noncopyable
{
public:
  ForwarderStatusRemote();

private:
  ndn::nfd::ForwarderStatus
  collectGeneralStatus();

  /** \brief provide general status dataset
   */
  void
  listGeneralRemoteStatus(const Interest& interest);

	void formatStatusJson( ptree &, const ndn::nfd::ForwarderStatus&);
	void formatCsJson( ptree & );
	void formatScJson( ptree & );
	void formatFacesJson( ptree & );
	void formatChannelsJson( ptree & );
	void formatRibJson( ptree & );
	void formatFibJson( ptree & );


private:
  time::system_clock::TimePoint m_startTimestamp;
};

} // namespace nfd

#endif // NFD_DAEMON_MGMT_FORWARDER_STATUS_HPP
