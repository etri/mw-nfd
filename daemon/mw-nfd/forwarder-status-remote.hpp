
#ifndef NFD_DAEMON_MGMT_FORWARDER_STATUS_REMOTE_HPP
#define NFD_DAEMON_MGMT_FORWARDER_STATUS_REMOTE_HPP

#include "face/face-system.hpp"
#include "fw/face-table.hpp"

#include <ndn-cxx/face.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

using boost::property_tree::ptree;

#include <ndn-cxx/mgmt/nfd/forwarder-status.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-info.hpp>

namespace nfd {

class ForwarderStatusRemote: noncopyable
{
public:
  ForwarderStatusRemote();
bool
  getNfdGeneralStatus(const Interest &, ndn::Face &);

static shared_ptr<Data>
    makeDataSegment(const uint8_t buffer [], int len, const Name& baseName, uint64_t segment, bool isFinal)
    {
        auto data = make_shared<Data>(Name(baseName).appendSegment(segment));
        data->setFreshnessPeriod(1_s);
        data->setContent(buffer, len);
        if (isFinal) {
            data->setFinalBlock(data->getName()[-1]);
        }   

        return data;
    }

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
};

} // namespace nfd

#endif // NFD_DAEMON_MGMT_FORWARDER_STATUS_HPP
