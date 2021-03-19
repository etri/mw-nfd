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

static const int DEFAULT_WINDOW = 32;
static const int DEFAULT_INTERVAL = 100;
static const int DEFAULT_TEST_TIME = 60;
static const bool DEFAULT_DIGEST = true;

using ConfigSection = boost::property_tree::ptree;
using OptionalConfigSection = boost::optional<const ConfigSection&>;
using namespace ndn;

class Client {
private:
    boost::asio::io_service m_ioService;

		boost::asio::signal_set m_signalSet;
    boost::asio::deadline_timer m_timer;
    size_t m_window = DEFAULT_WINDOW;
    bool m_digest = DEFAULT_DIGEST;
    size_t m_interval = DEFAULT_INTERVAL;

    bool m_first = true;
    size_t m_payload_size[8] = {0,};
    size_t m_pkt_count[8] = {0,};
    size_t m_rtt[8] = {0,};
    size_t m_ptime[8] = {0,};
		size_t m_max_cnt = 0;

    boost::thread_group m_threadGroup;

    size_t m_current_packet[8] = {0,};
    std::ofstream _file;

		std::vector<std::string> m_prefixList;
		int m_keyType = 200;
		unique_ptr<Face> m_face[8];
		std::vector<size_t>& m_cores;

		lp::PitToken *m_pitToken;
		int m_bulk = 0;
		int m_concurrency = 0;

public:
    Client(size_t interval, size_t window, size_t test_time, bool digest, std::vector<size_t> &cores);

    ~Client() = default;

    int run();

		void waitNextDisplay(); 

    void onNack(const Interest &interest, const lp::Nack &nack);

    void onData(const Interest &interest, const Data &data, std::chrono::steady_clock::time_point start, int i, int core);

    void onTimeout(const Interest &interest, int n, std::chrono::steady_clock::time_point start, int i, int core);

    void display();

		bool readPrefixList();

		void generateTraffic(boost::asio::deadline_timer& timer);

		void sendTraffic(int i, int core);

		void stop();

		void start();
		
};

Client::Client(size_t interval, size_t window, size_t test_time, bool digest, std::vector<size_t> &cores)
				: m_signalSet(m_ioService, SIGINT, SIGTERM)
				, m_timer(m_ioService)
        , m_window(window)
        , m_digest(digest)
				, m_interval(interval) 
				, m_cores(cores)
{
}

bool Client::readPrefixList() {
	FILE *fp;                    
  int line_cnt=0;              
  
  char line[1024]={0,};        
  char *bulk_fib_file = (char *)"/usr/local/etc/ndn/fib-bulk.txt";

  fp =  fopen (bulk_fib_file, "r");

	if (fp==NULL) {
			std::cout << "NFD: bulk_fib_test: can't read bulk-fib-file:" << bulk_fib_file << std::endl;                               return false;
  }

  char* unused __attribute__((unused));

	while ( !feof(fp) ) { 
			unused = fgets(line, sizeof(line), fp);  
			if(strlen(line)==0) continue;   
			if(line[0]=='"') continue;      

			line[strlen(line)-1]='\0';      
			line_cnt++;

			m_prefixList.push_back(line);   
			
			memset(line, '\0', sizeof(line));
	}

	std::cout << "Prefix List Size = " << m_prefixList.size() << std::endl;
	m_max_cnt = m_prefixList.size();
	fclose(fp);
	return true;
}

void Client::start() {

		std::cout << "MW-NDNPerf Start !! " << std::endl;
		m_concurrency = m_cores.size();
		std::cout << "Concurrency = " << m_concurrency << std::endl;

		const uint8_t VALUE[] = {0x11, 0x12, 0x13, 0x14};
		auto b= std::make_shared<Buffer>(VALUE, sizeof(VALUE));
		lp::PitToken pitToken(std::make_pair(b->begin(), b->end()) );
		m_pitToken = &pitToken;

		readPrefixList();
		m_bulk = m_max_cnt / m_cores.size();

		int i =0;
    for(std::vector<size_t>::iterator it = m_cores.begin(); it!=m_cores.end(); ++it) {
				m_face[i] = make_unique<Face>(m_ioService);
				m_threadGroup.create_thread(boost::bind(&Face::processEvents, m_face[i].get(), time::milliseconds::zero(), false));
				m_threadGroup.create_thread(boost::bind(&Client::sendTraffic, this, i, *it));
				i++;
		}
		m_threadGroup.create_thread(boost::bind(&Client::waitNextDisplay, this));
}

void Client::sendTraffic(int i, int core)
{
    std::cout << "Client start with window = " << m_window << ", Interval = " << m_interval << "ms" <<std::endl;

		const uint8_t VALUE[] = {0x11, 0x12, 0x13, 0x14};
		auto b= std::make_shared<Buffer>(VALUE, sizeof(VALUE));
		lp::PitToken pitToken(std::make_pair(b->begin(), b->end()) );

		std::cout << "process on CPU: " << core << std::endl;
		cpu_set_t  mask;
		CPU_ZERO(&mask);
		CPU_SET(core, &mask); 
		int ret  = sched_setaffinity(getpid(), sizeof(mask), &mask);
		std::cout << "rsched_setaffiniti's ret: " << ret << std::endl;

    int line_cnt = m_bulk * i;;
		int limit = line_cnt + m_window;
 
    for (; line_cnt < limit; ++line_cnt) {
				Interest interest(Name(m_prefixList[line_cnt]));
        interest.setMustBeFresh(true);
        interest.setCanBePrefix(false);
				interest.setTag(std::make_shared<lp::PitToken>(pitToken));
				std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

				m_face[i]->expressInterest(interest, boost::bind(&Client::onData, this, _1, _2, start, i, core),
															boost::bind(&Client::onNack, this, _1, _2),
															boost::bind(&Client::onTimeout, this, _1, 2, start, i, core));
				m_current_packet[i]++;
    }
} 

void Client::waitNextDisplay() {
    m_timer.expires_from_now(boost::posix_time::seconds(2));
    m_timer.async_wait(boost::bind(&Client::display, this));
}

void Client::onNack(const Interest &interest, const lp::Nack &nack) {
    std::cout << "Nack receive : " << nack.getReason() << std::endl;
}

void Client::onData(const Interest &interest, const Data &data, std::chrono::steady_clock::time_point start, int i, int core) {

		cpu_set_t  mask;
		CPU_ZERO(&mask);
		CPU_SET(core, &mask); 
		int ret  = sched_setaffinity(getpid(), sizeof(mask), &mask);

    m_rtt[i] += std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
    if (m_first) {
				m_keyType = data.getSignatureInfo().getSignatureType();
        std::cout << "Server signature type(0:Sha256, 1:Sha256WithRsa, 3:Sha256WithEcdsa, 4:HmacWithSha256) = " << m_keyType << std::endl;
        std::cout << "Server packet size = " << data.getContent().value_size() << std::endl;
        m_first = false;
    }

    std::chrono::steady_clock::time_point new_start = std::chrono::steady_clock::now();

		if(m_digest) {
			switch (m_keyType) {
				case tlv::DigestSha256 :
				case tlv::SignatureSha256WithRsa :
				case tlv::SignatureSha256WithEcdsa :
				case tlv::SignatureHmacWithSha256:
					break;
			}
		} 

		++m_pkt_count[i];
		m_payload_size[i] += data.getContent().value_size();

		int line_cnt = (m_current_packet[i]  % m_bulk) + (m_bulk * i);
		Interest new_interest(Name(m_prefixList[line_cnt]));
    new_interest.setMustBeFresh(true);
    new_interest.setCanBePrefix(false);
		new_interest.setTag(std::make_shared<lp::PitToken>(*m_pitToken));
		m_face[i]->expressInterest(new_interest, boost::bind(&Client::onData, this, _1, _2, new_start, i, core),
													boost::bind(&Client::onNack, this, _1, _2),
													boost::bind(&Client::onTimeout, this, _1, 2, start, i, core));
		m_current_packet[i]++;
		m_ptime[i] += std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - new_start).count();
		std::this_thread::sleep_for(std::chrono::milliseconds(m_interval));
}

void Client::onTimeout(const Interest &interest, int n, std::chrono::steady_clock::time_point start, int i, int core) {
    if (n > 0) {
        Interest new_interest(interest);
        new_interest.refreshNonce();
				m_face[i]->expressInterest(new_interest, boost::bind(&Client::onData, this, _1, _2, start, i, core),
															boost::bind(&Client::onNack, this, _1, _2),
															boost::bind(&Client::onTimeout, this, _1, n - 1, start, i, core));
    } else {
        std::cout << "Timeout for interest " << interest.getName().toUri() << std::endl;
    }
}

void Client::display() {
    static char mbstr[32];

    time_t time = std::time(NULL);

		size_t p_count = 0;
		size_t rtt = 0;
		size_t pay_load = 0;
		size_t times = 0;
		bool detail_info = false;

		for(int i=0;i<m_concurrency;i++) {
			p_count += m_pkt_count[i];
			rtt += m_rtt[i];
			pay_load += m_payload_size[i];
			times += m_ptime[i];
			std::strftime(mbstr, sizeof(mbstr), "%c - ", std::localtime(&time));
			if((m_concurrency > 1) && detail_info) {
				std::cout << mbstr << "[" << i <<"] " <<(m_payload_size[i] >>= 8) << " Kbps ( " << (m_pkt_count[i] / 2) << " pkt/s) - latency = " << (m_rtt[i] /= m_pkt_count[i] != 0 ? m_pkt_count[i] : -1) << " us" << "  ptime = " << (m_ptime[i] /= m_pkt_count[i] != 0 ? m_pkt_count[i] : -1) << " us" << std::endl;
			}
		}

		std::strftime(mbstr, sizeof(mbstr), "%c - ", std::localtime(&time));
		std::cout << mbstr << "[S] " << (pay_load >>= 8) << " Kbps ( " << (p_count / 2) << " pkt/s) - latency = " << (rtt /= p_count != 0 ? p_count : -1) << " us" << "  ptime = " << (times /= p_count != 0 ? p_count : -1) << " us" << std::endl;

		for(int i=0;i<m_concurrency;i++) {
			m_rtt[i] = 0;
			m_payload_size[i] = 0;
			m_pkt_count[i] = 0;
			m_ptime[i] = 0;
		}
    waitNextDisplay();
}

void
Client::stop()
{
		std::cout << "Waiting for other threads... " << std::endl;
		for(int i=0;i<m_concurrency;i++) {
    	m_face[i]->getIoService().stop();
		}

		m_threadGroup.join_all();
    m_ioService.stop();
}

static bool stop = false;
void signalHandler(int signum) {
    stop = true;
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
    size_t test_time = DEFAULT_TEST_TIME;
    bool digest = DEFAULT_DIGEST;

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

			//const std::string& sectionName = tn.first;
			//const ConfigSection& section = tn.second;

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

			if( tn.first == "digest" )
				digest = boost::lexical_cast<size_t>(val);

			if( tn.first == "test-time" )
				test_time = boost::lexical_cast<size_t>(val);

			if( tn.first == "interval" )
				interval = boost::lexical_cast<size_t>(val);
		}

		inputFile.close();

    Client client(interval, window_size, test_time, digest, core_assign);

		signal(SIGINT, signalHandler);

		client.start();

		do {
			sleep(15);
		} while(!stop);

		client.stop();

		return 0;
}
