
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

using std::map;

namespace nfd {

static const uint64_t DEFAULT_BLOCK_SIZE = 1000;
static const uint64_t DEFAULT_INTEREST_LIFETIME = 4000;
static const uint64_t DEFAULT_FRESHNESS_PERIOD = 10000;
static const uint64_t DEFAULT_CHECK_PERIOD = 1000;
static const size_t PRE_SIGN_DATA_COUNT = 11;

class ForwarderStatusRemote: noncopyable
{
public:
  ForwarderStatusRemote();
  bool
  getNfdGeneralStatus(const ndn::Name &, const Interest &, ndn::Face &);

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

	void prepareNextData(const ndn::Interest&, uint64_t );


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
	size_t m_currentSegmentNo;
	bool m_isFinished;
	using DataContainer = std::map<uint64_t, shared_ptr<ndn::Data>>;
	  DataContainer m_data;
	  ndn::KeyChain m_keyChain;
};

} // namespace nfd

#endif // NFD_DAEMON_MGMT_FORWARDER_STATUS_HPP
