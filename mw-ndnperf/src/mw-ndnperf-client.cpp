#include <ndn-cxx/name.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/transport/tcp-transport.hpp>
#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/lp/nack.hpp>
#include <ndn-cxx/lp/pit-token.hpp>
#include <ndn-cxx/util/time.hpp>
#include "ndn-cxx/security/verification-helpers.hpp"
#include "ndn-cxx/security/transform/public-key.hpp"

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/thread.hpp>


#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/info_parser.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/lexical_cast.hpp>

#include <string>
#include <chrono>
#include <iostream>
#include <csignal>
#include <thread>
#include <ctime>

#include "blockingconcurrentqueue.h"

static const std::string DEFAULT_PREFIX = "mw-ndnperf";
static const int DEFAULT_WINDOW = 32;
static const int DEFAULT_INTERVAL = 100;
static const int DEFAULT_PREFIX_LIST_SIZE = 100000;
static const bool DEFAULT_DIGEST = true;
static const int DEFAULT_ADD_SIZE = 10;
static const bool DEFAULT_CANBEPREFIX = false;
static const bool DEFAULT_MUSTBEFRESH = false;

static bool g_stop = false;

using ConfigSection = boost::property_tree::ptree;
using OptionalConfigSection = boost::optional<const ConfigSection&>;

using namespace ndn;

std::shared_ptr<boost::asio::io_service> io_svc[10];

class Client {
private:
		std::shared_ptr<boost::asio::signal_set> m_signalSet;
    std::shared_ptr<boost::asio::deadline_timer> m_timer;
		shared_ptr<Face> m_faces[10];
		std::string m_prefix;
    size_t m_window = DEFAULT_WINDOW;
    size_t m_interval = DEFAULT_INTERVAL;
    bool m_digest = DEFAULT_DIGEST;
    bool m_first = true;
    std::atomic<uint64_t> m_payload_size {0};
    uint64_t m_pkt_count[8] = {0,};
    std::atomic<uint64_t> m_rtt {0};
    size_t m_ptime[8] = {0,};
		size_t m_max_cnt = 0;
		std::atomic<uint64_t>  m_data_cnt {0};
		long m_total_cnt = 0;

    boost::thread_group m_threadGroup;

		long m_interest_cnt[10] = {0,};
    std::ofstream _file;

		std::vector<Interest> m_prefixList;
		int m_keyType = 200;
		std::vector<size_t>& m_cores;

		int m_bulk = 0;
		size_t m_concurrency = 0;
		size_t m_prefix_list_size = 0;
    bool m_canbeprefix = DEFAULT_CANBEPREFIX;
    bool m_mustbefresh = DEFAULT_MUSTBEFRESH;
    std::atomic<uint64_t> m_peakRtt {0};
    Name m_peakName;

public:
    Client(std::string prefix, size_t window, size_t interval, bool digest, std::vector<size_t> &cores, size_t prefix_list_size, bool canbeprefix, bool mustbefresh);

    ~Client() = default;

    int run(int i);

		void waitNextDisplay(); 

    void onNack(const Interest &interest, const lp::Nack &nack);

    void onData(const Interest &interest, const Data &data, std::chrono::steady_clock::time_point start, int i);

    void onTimeout(const Interest &interest, int n, std::chrono::steady_clock::time_point start, int i);

    void display();

		bool makePrefixList();

		void generateTraffic(boost::asio::deadline_timer& timer);

		void process(int i, int core);

		void stop();

		void start();

    void on_data(const Data &data, std::chrono::steady_clock::time_point start, int i);

    void gen_random(char *s, size_t len) {
        static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        for (size_t i = 0; i < len; ++i) {
            s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
        }

        s[len] = 0;
    }
};

Client::Client(std::string prefix, size_t window, size_t interval, bool digest, std::vector<size_t> &cores, size_t prefix_list_size, bool canbeprefix, bool mustbefresh)
        : m_prefix(prefix)
        , m_window(window)
				, m_interval(interval) 
        , m_digest(digest)
				, m_cores(cores)
				, m_prefix_list_size(prefix_list_size)
				, m_canbeprefix(canbeprefix)
				, m_mustbefresh(mustbefresh)
{
        io_svc[0] = std::make_shared<boost::asio::io_service>();
        m_signalSet = std::make_shared<boost::asio::signal_set>(*io_svc[0], SIGINT, SIGTERM);
        m_timer = std::make_shared<boost::asio::deadline_timer>(*io_svc[0]);
}

bool Client::makePrefixList() {

	std::cout << "Prefix Name = " << m_prefix << " list size = " << m_prefix_list_size << ", CanBePrefix = " << m_canbeprefix << ", MustBeFresh = " << m_mustbefresh << std::endl;

  int mark = 0;
  int mark2 = 0;


	for (size_t line_cnt = 0; line_cnt < m_prefix_list_size; line_cnt++ ) { 
			char *chararray = new char[DEFAULT_ADD_SIZE * m_concurrency];
      
      mark = line_cnt % m_concurrency;
      mark2 = line_cnt % 5;
			gen_random(chararray,  mark * 2 + mark2);

#if 1
			Name name(m_prefix);
      name.append(std::to_string(mark));
			name.append(std::to_string(line_cnt));
#else

      Name name(std::to_string(mark));

      if(mark == 0) {
			  name.append(chararray).append(std::to_string(line_cnt));
      } else {
			  name.append(chararray).append(std::to_string(line_cnt));
      }
#endif

			Interest interest(name);
			interest.setMustBeFresh(m_mustbefresh);
			interest.setCanBePrefix(m_canbeprefix);
			m_prefixList.push_back(interest);   
	}

	std::cout << "Prefix List Size = " << m_prefixList.size() << std::endl;
	m_max_cnt = m_prefixList.size();
	m_bulk = m_max_cnt / m_concurrency;
	return true;
}

void Client::start() {

		std::cout << "MW-NDNPerf Start !! " << std::endl;
		m_concurrency = m_cores.size();
		std::cout << "Concurrency = " << m_concurrency << std::endl;

		//makePrefixList();

    size_t i = 0;

		m_faces[0] = make_shared<Face>(*io_svc[0]);

    for(i=1; i< m_concurrency; i++) {
      io_svc[i] = std::make_shared<boost::asio::io_service>();
      m_faces[i] = make_shared<Face>(*io_svc[i]);
    }

    i=0;
    for(std::vector<size_t>::iterator it = m_cores.begin(); it!=m_cores.end(); ++it) {
			m_threadGroup.create_thread(boost::bind(&Client::process, this, i, *it));
			i++;
		}
		m_threadGroup.create_thread(boost::bind(&Client::waitNextDisplay, this));

}

void Client::process(int i, int core)
{
    std::cout << "Client start with window = " << m_window << ", Interval = " << m_interval << "ms" <<std::endl;

		size_t line_cnt = 0;

		std::cout << "Process  on CPU: " << core << std::endl;
		cpu_set_t  mask;
		CPU_ZERO(&mask);
		CPU_SET(core, &mask); 
		int ret  = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);

		std::cout << "rsched_setaffiniti's ret: " << ret << std::endl;

		m_threadGroup.create_thread(boost::bind(&Face::processEvents, m_faces[i].get(), time::milliseconds::zero(), false));

#if 0
		for (line_cnt = 0; line_cnt < m_window; ++line_cnt) {
			line_idx = (m_bulk * i) + line_cnt;
			std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
			m_faces[i]->expressInterest(m_prefixList[line_idx], boost::bind(&Client::onData, this, _1, _2, start, i),
														boost::bind(&Client::onNack, this, _1, _2),
														boost::bind(&Client::onTimeout, this, _1, 2, start, i));
			++m_interest_cnt[i];
		}
#else
		for (line_cnt = 0; line_cnt < m_window; ++line_cnt) {
			Name name(m_prefix);
      name.append(std::to_string(i));
			name.append(std::to_string(++m_interest_cnt[i]));
			Interest interest(name);
			interest.setMustBeFresh(m_mustbefresh);
			interest.setCanBePrefix(m_canbeprefix);

			std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
			m_faces[i]->expressInterest(interest, boost::bind(&Client::onData, this, _1, _2, start, i),
														boost::bind(&Client::onNack, this, _1, _2),
														boost::bind(&Client::onTimeout, this, _1, 2, start, i));
		}
#endif
}

void Client::waitNextDisplay() {
    m_timer->expires_from_now(boost::posix_time::seconds(2));
    m_timer->async_wait(boost::bind(&Client::display, this));
}

void Client::onNack(const Interest &interest, const lp::Nack &nack) {
    std::cout << "Nack receive : " << nack.getReason() << std::endl;
}

void Client::onData(const Interest &interest, const Data &data, std::chrono::steady_clock::time_point start, int i) {

    uint64_t rtt = 0;
		++m_data_cnt;
    m_rtt += std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
    rtt = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();

    if(m_peakRtt < rtt) {
      m_peakRtt = rtt;
      m_peakName = interest.getName();
    }

    if (m_first) {
				m_keyType = data.getSignatureInfo().getSignatureType();
        std::cout << "Server signature type(0:Sha256, 1:Sha256WithRsa, 3:Sha256WithEcdsa, 4:HmacWithSha256) = " << m_keyType << std::endl;
        std::cout << "Server packet size= " << data.getContent().value_size() << std::endl;
        m_first = false;
    }

    std::chrono::steady_clock::time_point new_start = std::chrono::steady_clock::now();

		if(m_digest) {
			switch (m_keyType) {
				case tlv::DigestSha256 :
					if(security::verifyDigest(data, DigestAlgorithm::SHA256)) {
        		//std::cout << "verifyDigest is OK, " << data.getName().toUri() << std::endl;
					}
				case tlv::SignatureSha256WithRsa :
				case tlv::SignatureSha256WithEcdsa :
				case tlv::SignatureHmacWithSha256:
					break;
			}
		} 

		m_payload_size += data.getContent().value_size();

#if 0
		int line_cnt = (++m_interest_cnt[i] + (m_bulk * i)) % m_max_cnt;
		m_faces[i]->expressInterest(m_prefixList[line_cnt], boost::bind(&Client::onData, this, _1, _2, new_start, i),
													boost::bind(&Client::onNack, this, _1, _2),
													boost::bind(&Client::onTimeout, this, _1, 2, start, i));
#else
			Name name(m_prefix);
      name.append(std::to_string(i));
			name.append(std::to_string(++m_interest_cnt[i]));
			Interest interest(name);
			interest.setMustBeFresh(m_mustbefresh);
			interest.setCanBePrefix(m_canbeprefix);

			std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
			m_faces[i]->expressInterest(interest, boost::bind(&Client::onData, this, _1, _2, start, i),
														boost::bind(&Client::onNack, this, _1, _2),
														boost::bind(&Client::onTimeout, this, _1, 2, start, i));
#endif

		m_ptime[i] += std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - new_start).count();
    if(m_interval > 0) {
	    std::this_thread::sleep_for(std::chrono::milliseconds(m_interval));
    }
}

void Client::onTimeout(const Interest &interest, int n, std::chrono::steady_clock::time_point start, int i) {
    if (n > 0) {
        Interest new_interest(interest);
        new_interest.refreshNonce();
				m_faces[i]->expressInterest(new_interest, boost::bind(&Client::onData, this, _1, _2, start, i),
															boost::bind(&Client::onNack, this, _1, _2),
															boost::bind(&Client::onTimeout, this, _1, n - 1, start, i));
    } else {
        std::cout << "Timeout for interest " << interest.getName().toUri() << std::endl;
    }
}

void Client::display() {
    static char mbstr[32];

    time_t time = std::time(NULL);

		size_t pay_load = m_payload_size >> 8;
		m_total_cnt += m_data_cnt;

		size_t rtt = m_rtt;

		if(m_data_cnt > 0) {
			rtt = rtt / m_data_cnt ;
		} else {
			rtt = 0;
		}

		std::strftime(mbstr, sizeof(mbstr), "%c - ", std::localtime(&time));
		std::cout << mbstr << pay_load << " Kbps (" << (m_data_cnt / 2) << " pkt/s) - latency = " << rtt << " us, peak = " << m_peakRtt << " us name = " << m_peakName << std::endl;

		m_payload_size = 0;
		m_data_cnt = 0;
		m_rtt = 0;
		m_peakRtt = 0;
    waitNextDisplay();
}

void
Client::stop()
{
		std::cout << "Waiting for other threads... " << std::endl;
		for(size_t i = 0; i < m_concurrency; i++) {
   		m_faces[i]->getIoService().stop();
		}

		m_threadGroup.join_all();
}

void signalHandler(int signum) {
    g_stop = true;
}

static void
printUsage(std::ostream& os, const std::string& programName)
{
  os << "Usage: " << programName << " [OPTIONS...]\n"
     << "\n"
     << "Options:\n"
     << "    -f <FILE>   Path to configuration file\n"
     << "    -h          Display this help message\n"
     << "    -V          Display version information\n"
     << std::endl;
}

int main(int argc, char *argv[]) {
    size_t window_size = DEFAULT_WINDOW;
    size_t interval = DEFAULT_INTERVAL;
    size_t prefix_list_size = DEFAULT_PREFIX_LIST_SIZE;
    bool digest = DEFAULT_DIGEST;
    bool canbeprefix = DEFAULT_CANBEPREFIX;
    bool mustbefresh = DEFAULT_MUSTBEFRESH;
		std::string prefix("mw-ndnperf");

		std::string programName(argv[0]);
		std::string confFileName("mw-ndnperf-client.conf");

		std::vector<size_t> core_assign;

		int opt;
		while((opt=getopt(argc, argv, "hf:V")) != -1){

		switch (opt) { 
			case 'h':
				printUsage(std::cout, programName);
				return 0;
			case 'f':
				confFileName = optarg; 
				break;  
			case 'V':
				std::cout << "MW-NDNPERF-0.7.1" << std::endl;
				return 0;
			default:
				printUsage(std::cerr, programName);
				return 2;
			}
		}

		std::ifstream inputFile;
		inputFile.open(confFileName.c_str());
		if (!inputFile.is_open()) {
			std::string msg = "Failed to read configuration file: ";
			msg += confFileName;
			std::cerr << msg << std::endl;
			return false;
		}

		ConfigSection pt;
		try {
			boost::property_tree::read_info(inputFile, pt);
		}
		catch (const boost::property_tree::info_parser_error& error) {
			std::stringstream msg;
			std::cerr << "Failed to parse configuration file " << std::endl;
			std::cerr << confFileName << std::endl;
			return 0;
		}

		for (const auto& tn : pt) {

			std::string val = tn.second.data();

			if( tn.first == "process-core" ){
				std::cout << "process-core[s]: " << val << std::endl;
				std::vector<std::string> strs;
				boost::split(strs,val,boost::is_any_of(","));
				for(std::vector<std::string>::iterator it = strs.begin();it!=strs.end();++it)
				{
					//std::cout << "core: " << boost::lexical_cast<size_t>(*it) << std::endl;
					core_assign.push_back(boost::lexical_cast<size_t>(*it));
				}
			}
			if( tn.first == "window-size" )
				window_size = boost::lexical_cast<size_t>(val);

			if( tn.first == "prefix" )
				prefix = boost::lexical_cast<std::string>(val);

			if( tn.first == "digest" )
				digest = boost::lexical_cast<size_t>(val);

			if( tn.first == "prefix_list_size" )
				prefix_list_size = boost::lexical_cast<size_t>(val);

			if( tn.first == "interval" )
				interval = boost::lexical_cast<size_t>(val);

			if( tn.first == "can_be_prefix" )
				canbeprefix = boost::lexical_cast<size_t>(val);

			if( tn.first == "must_be_fresh" )
				mustbefresh = boost::lexical_cast<size_t>(val);

		}

		inputFile.close();
	
    Client client(prefix, window_size, interval, digest, core_assign, prefix_list_size, canbeprefix, mustbefresh);

		signal(SIGINT, signalHandler);

		client.start();

		do {
			sleep(15);
		} while(!g_stop);

		client.stop();

		return 0;
}
