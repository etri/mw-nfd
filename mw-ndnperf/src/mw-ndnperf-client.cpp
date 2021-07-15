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

#define USING_QUEUE 1
#define SLEEP_STEP_NS 1000L
#define MAX_SLEEP_NS  128000L
#define ZERO_BULK_TH    5L

static const std::string DEFAULT_PREFIX = "mw-ndnperf";
static const int DEFAULT_WINDOW = 32;
static const int DEFAULT_INTERVAL = 100;
static const bool DEFAULT_VERIFY = true;
static const bool DEFAULT_CANBEPREFIX = false;
static const bool DEFAULT_MUSTBEFRESH = false;
static const int MAX_THREAD = 30;
static const int MAX_PREFIX_LIST = 100;

static bool g_stop = false;

using ConfigSection = boost::property_tree::ptree;
using OptionalConfigSection = boost::optional<const ConfigSection&>;

using namespace ndn;

std::shared_ptr<boost::asio::io_service> io_svc[MAX_THREAD];

class Client {
private:
		std::shared_ptr<boost::asio::signal_set> m_signalSet;
    std::shared_ptr<boost::asio::deadline_timer> m_timer;
		shared_ptr<Face> m_faces[MAX_THREAD];
		std::string m_prefix;
		size_t m_max_cnt = DEFAULT_WINDOW;
    size_t m_window = DEFAULT_WINDOW;
    size_t m_interval = DEFAULT_INTERVAL;
    bool m_verify = DEFAULT_VERIFY;
    std::atomic<bool> m_first {true};
    std::atomic<bool> m_findkey {false};
    std::atomic<uint64_t> m_payload_size {0};
    std::atomic<uint64_t> m_rtt {0};
		std::atomic<uint64_t>  m_data_cnt {0};
		std::atomic<uint64_t>  m_total_cnt {0};

    boost::thread_group m_threadGroup;

		long m_interest_cnt[MAX_PREFIX_LIST] = {0,};

		std::vector<Name> m_prefixList;
		int m_keyType = 200;
		size_t m_multi_face = 0;
		std::vector<size_t>& m_cores;
		int m_max_core = 0;

		int m_bulk = 0;
		size_t m_concurrency = 0;
    bool m_canbeprefix = DEFAULT_CANBEPREFIX;
    bool m_mustbefresh = DEFAULT_MUSTBEFRESH;
    std::atomic<uint64_t> m_peakRtt {0};
    Name m_peakName;
    std::atomic<uint64_t> m_gapTime {0};
    std::chrono::steady_clock::time_point m_startTime;
		bool m_proceesFlag[MAX_THREAD] = {0,};

    KeyChain m_keychain;
    security::Identity m_identity;

		moodycamel::ConcurrentQueue<std::pair<std::shared_ptr<Data>, size_t >> m_dataQueue;

public:
    Client(std::string prefix, size_t prefixList, size_t window, size_t interval, bool verify, size_t multiface, std::vector<size_t> &cores, bool canbeprefix, bool mustbefresh);

    ~Client() = default;

    int run(int i);

		void waitNextDisplay(); 

    void onNack(const Interest &interest, const lp::Nack &nack);

    void onData(const Interest &interest, const Data &data, std::chrono::steady_clock::time_point start, int i, int line_cnt);

    void onTimeout(const Interest &interest, int n, std::chrono::steady_clock::time_point start, int i, int line_cnt);

		void onDataQueue(const Interest &interest, const Data &data, std::chrono::steady_clock::time_point start, int i, int line_cnt);

		void processDataQueue(int i, int core);

    void display();

		bool readPrefixList();

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

Client::Client(std::string prefix, size_t prefixList, size_t window, size_t interval, bool verify, size_t multiface, std::vector<size_t> &cores, bool canbeprefix, bool mustbefresh)
        : m_prefix(prefix)
        , m_max_cnt(prefixList)
        , m_window(window)
				, m_interval(interval) 
        , m_verify(verify)
				, m_multi_face(multiface)
				, m_cores(cores)
				, m_canbeprefix(canbeprefix)
				, m_mustbefresh(mustbefresh)
{
        io_svc[0] = std::make_shared<boost::asio::io_service>();
        m_signalSet = std::make_shared<boost::asio::signal_set>(*io_svc[0], SIGINT, SIGTERM);
        m_timer = std::make_shared<boost::asio::deadline_timer>(*io_svc[0]);
}

bool Client::readPrefixList() {
      FILE *fp;                       
      size_t line_cnt=0;              
      
      char line[1024]={0,};           
      char *prefix_list = (char *)"./prefix-list.txt";                                                                                                    
      fp =  fopen (prefix_list, "r");                                                                                                                       
      if (fp==NULL) {
          std::cout << "MW-NDNPERF can't read prefix-list.txt file:" << prefix_list << std::endl;                               
					return false;             
      }

      char* unused __attribute__((unused));                                                                                                               

      while ( !feof(fp) && (line_cnt < m_max_cnt) ) { 
          unused = fgets(line, sizeof(line), fp);                                                                                                         
          if(strlen(line)==0) continue;   
          if(line[0]=='"') continue;      

          line[strlen(line)-1]='\0';      
          line_cnt++;

          Name name(line);
          m_prefixList.push_back(name);                                                                                                                   
          
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
    if(m_concurrency > MAX_THREAD) {
      m_concurrency = MAX_THREAD;
    }

		m_max_core = m_cores[m_concurrency-1] + 1;

		std::cout << "Concurrency = " << m_concurrency << ", max_core = " << m_max_core << std::endl;

    size_t i = 0;

		m_faces[0] = make_shared<Face>(*io_svc[0]);

    for(i=1; i< m_multi_face; i++) {
      io_svc[i] = std::make_shared<boost::asio::io_service>();
      m_faces[i] = make_shared<Face>(*io_svc[i]);
    }

		readPrefixList();

    i=0;
    for(std::vector<size_t>::iterator it = m_cores.begin(); it!=m_cores.end(); ++it) {
			m_threadGroup.create_thread(boost::bind(&Client::process, this, i, *it));
#if USING_QUEUE
			m_threadGroup.create_thread(boost::bind(&Client::processDataQueue, this, i, m_max_core +i));
#endif
			i++;
		}
		m_threadGroup.create_thread(boost::bind(&Client::waitNextDisplay, this));

}

void Client::process(int i, int core)
{
    std::cout << "Client start with window = " << m_window << ", Interval = " << m_interval << "ms" <<std::endl;

		size_t line_cnt = 0;
		size_t win_cnt = 0;

		std::cout << "Process  on CPU: " << core << std::endl;
		cpu_set_t  mask;
		CPU_ZERO(&mask);
		CPU_SET(core, &mask); 
		int ret  = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);

		std::cout << "rsched_setaffiniti's ret: " << ret << std::endl;

		size_t face_idx = 0;
    face_idx = i % m_multi_face;

		for (line_cnt = 0; line_cnt < m_max_cnt; ++line_cnt) {
			if((line_cnt % m_multi_face) == face_idx) {
				for (win_cnt = 0; win_cnt < m_window; ++win_cnt) {
					Name name = m_prefixList[line_cnt];
					name.append(std::to_string(++m_interest_cnt[line_cnt]));
					Interest interest(name);
					interest.setMustBeFresh(m_mustbefresh);
					interest.setCanBePrefix(m_canbeprefix);

					std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
#if	USING_QUEUE 
					m_faces[face_idx]->expressInterest(interest, boost::bind(&Client::onDataQueue, this, _1, _2, start, i, line_cnt),
																boost::bind(&Client::onNack, this, _1, _2),
																boost::bind(&Client::onTimeout, this, _1, 2, start, i, line_cnt));
#else
					m_faces[face_idx]->expressInterest(interest, boost::bind(&Client::onData, this, _1, _2, start, i, line_cnt),
																boost::bind(&Client::onNack, this, _1, _2),
																boost::bind(&Client::onTimeout, this, _1, 2, start, i, line_cnt));
#endif
				}
			}
		}

    if( !m_proceesFlag[face_idx]) {
      m_proceesFlag[face_idx] = 1;
      std::cout << "processEvents face_idx = " << face_idx <<" on CPU: " << core << std::endl;
			m_faces[face_idx]->processEvents(time::milliseconds::zero(), true);
    }

}

void Client::waitNextDisplay() {
    m_timer->expires_from_now(boost::posix_time::seconds(2));
    m_timer->async_wait(boost::bind(&Client::display, this));
}

void Client::onNack(const Interest &interest, const lp::Nack &nack) {
    std::cout << "Nack receive : " << nack.getReason() << std::endl;
}

void Client::onData(const Interest &interest, const Data &data, std::chrono::steady_clock::time_point start, int i, int line_cnt) {

		++m_data_cnt;
		++m_total_cnt;
    m_rtt += std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();

    if (m_first) {
        m_first = false;
				m_keyType = data.getSignatureInfo().getSignatureType();
        std::cout << "Server signature type(0:Sha256, 1:Sha256WithRsa, 3:Sha256WithEcdsa, 4:HmacWithSha256) = " << m_keyType << std::endl;
        std::cout << "Server packet size= " << data.getContent().value_size() << std::endl;
		    m_payload_size = data.getContent().value_size();
        m_startTime = std::chrono::steady_clock::now();

        if(m_keyType) {
          auto it = m_keychain.getPib().getIdentities().find(m_prefix);

          if(it != m_keychain.getPib().getIdentities().end()) {
            m_identity = *it;
            security::Key key = m_identity.getDefaultKey();
            std::cout << "Find " << m_prefix << " key " << key.getName() << "\n"
                      << key.getDefaultCertificate() << std::endl;
            m_findkey = true;
          } else {
            std::cout << "Not Find " << m_prefix << " key !!!! " << std::endl;
          }
        }
    }
    
		if(m_verify) {
			switch (m_keyType) {
				case tlv::DigestSha256 :
					if(security::verifyDigest(data, DigestAlgorithm::SHA256)) {
        		//std::cout << "verifyDigest is OK, " << data.getName().toUri() << std::endl;
					}
					break;
				case tlv::SignatureSha256WithRsa :
				case tlv::SignatureSha256WithEcdsa :
          if(m_findkey) {
            if(security::verifySignature(data, m_identity.getDefaultKey())) {
              //std::cout << "verifySignature is OK, " << data.getName().toUri() << std::endl;
            } else {
              std::cout << "verifySignature is Error, " << data.getName().toUri() << std::endl;
            }
          }
				case tlv::SignatureHmacWithSha256:
					break;
			}
		} 

    Name name = m_prefixList[line_cnt];
    name.append(std::to_string(++m_interest_cnt[line_cnt]));

    Interest new_interest(name);
    new_interest.setMustBeFresh(m_mustbefresh);
    new_interest.setCanBePrefix(m_canbeprefix);

		size_t face_idx = 0;
    face_idx = i % m_multi_face;

    std::chrono::steady_clock::time_point new_start = std::chrono::steady_clock::now();
    m_faces[face_idx]->expressInterest(new_interest, boost::bind(&Client::onData, this, _1, _2, new_start, i, line_cnt),
                          boost::bind(&Client::onNack, this, _1, _2),
                          boost::bind(&Client::onTimeout, this, _1, 2, new_start, i, line_cnt));

    if(m_interval > 0) {
	    std::this_thread::sleep_for(std::chrono::milliseconds(m_interval));
    }
}
void Client::onDataQueue(const Interest &interest, const Data &data, std::chrono::steady_clock::time_point start, int i, int line_cnt) {

		++m_data_cnt;
		++m_total_cnt;
    m_rtt += std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();

    if (m_first) {
        m_first = false;
				m_keyType = data.getSignatureInfo().getSignatureType();
        std::cout << "Server signature type(0:Sha256, 1:Sha256WithRsa, 3:Sha256WithEcdsa, 4:HmacWithSha256) = " << m_keyType << std::endl;
        std::cout << "Server packet size= " << data.getContent().value_size() << std::endl;
		    m_payload_size = data.getContent().value_size();
        m_startTime = std::chrono::steady_clock::now();

        if(m_keyType) {
          auto it = m_keychain.getPib().getIdentities().find(m_prefix);

          if(it != m_keychain.getPib().getIdentities().end()) {
            m_identity = *it;
            security::Key key = m_identity.getDefaultKey();
            std::cout << "Find " << m_prefix << " key " << key.getName() << "\n"
                      << key.getDefaultCertificate() << std::endl;
            m_findkey = true;
          } else {
            std::cout << "Not Find " << m_prefix << " key !!!! " << std::endl;
          }
        }
    }
		m_dataQueue.enqueue(std::make_pair(std::make_shared<Data>(data), line_cnt));
}

void Client::processDataQueue(int i, int core) {
    
		std::cout << "processDataQueue on CPU: " << core << std::endl;
    cpu_set_t  mask;
    CPU_ZERO(&mask);
    CPU_SET(core, &mask); 
    int ret  = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);
    std::cout << "rsched_setaffiniti's ret: " << ret << std::endl;
    std::pair<std::shared_ptr<Data>, size_t> data_line[10];
    size_t j = 0;
    size_t bulk_size = 0;
    int line_cnt = 0;
		size_t zero_bulk_cnt = 0;
    struct timespec request{0,0};

    while (!g_stop) {
        bulk_size = m_dataQueue.try_dequeue_bulk(data_line, 3);
				if(bulk_size) {
					for(j = 0; j < bulk_size; j++) {
						//m_payload_size += data_line[j].first->getContent().value_size();
						line_cnt = data_line[j].second;

						if(m_verify) {
							switch (m_keyType) {
								case tlv::DigestSha256 :
									if(security::verifyDigest(*data_line[j].first, DigestAlgorithm::SHA256)) {
										//std::cout << "verifyDigest is OK, " << data.getName().toUri() << std::endl;
									}
								case tlv::SignatureSha256WithRsa :
								case tlv::SignatureSha256WithEcdsa :
								case tlv::SignatureHmacWithSha256:
									break;
							}
						}

						Name name = m_prefixList[line_cnt];
						name.append(std::to_string(++m_interest_cnt[line_cnt]));

						Interest new_interest(name);
						new_interest.setMustBeFresh(m_mustbefresh);
						new_interest.setCanBePrefix(m_canbeprefix);

						size_t face_idx = 0;
						face_idx = i % m_multi_face;

						std::chrono::steady_clock::time_point new_start = std::chrono::steady_clock::now();
						m_faces[face_idx]->expressInterest(new_interest, boost::bind(&Client::onDataQueue, this, _1, _2, new_start, i, line_cnt),
																	boost::bind(&Client::onNack, this, _1, _2),
																	boost::bind(&Client::onTimeout, this, _1, 2, new_start, i, line_cnt));

						if(m_interval > 0) {
							std::this_thread::sleep_for(std::chrono::milliseconds(m_interval));
						}
				}
				bulk_size = 0;
				zero_bulk_cnt =0;
				request.tv_nsec = 0;
			} else {
				zero_bulk_cnt++;
				if(zero_bulk_cnt > ZERO_BULK_TH) {
					request.tv_nsec = std::min(request.tv_nsec + SLEEP_STEP_NS, MAX_SLEEP_NS); 
					nanosleep(&request, NULL);      
				}        
			}
		}
}

void Client::onTimeout(const Interest &interest, int n, std::chrono::steady_clock::time_point start, int i, int line_cnt) {
		size_t face_idx = 0;
    face_idx = i % m_multi_face;
    if (n > 0) {
        Interest new_interest(interest);
        new_interest.refreshNonce();
#if USING_QUEUE
				m_faces[face_idx]->expressInterest(new_interest, boost::bind(&Client::onDataQueue, this, _1, _2, start, i, line_cnt),
															boost::bind(&Client::onNack, this, _1, _2),
															boost::bind(&Client::onTimeout, this, _1, n - 1, start, i, line_cnt));
#else
				m_faces[face_idx]->expressInterest(new_interest, boost::bind(&Client::onData, this, _1, _2, start, i, line_cnt),
															boost::bind(&Client::onNack, this, _1, _2),
															boost::bind(&Client::onTimeout, this, _1, n - 1, start, i, line_cnt));
#endif
				
    } else {
        std::cout << "Timeout for interest " << interest.getName().toUri() << std::endl;
    }
}

void Client::display() {
    static char mbstr[32];
    uint64_t data_cnt = 0;
    uint64_t payload_sum = 0;
    uint64_t rtt = 0;

    time_t time = std::time(NULL);

    data_cnt = m_data_cnt;
		m_data_cnt = 0;
		rtt = m_rtt;
		m_rtt = 0;

		payload_sum = (data_cnt * m_payload_size) >> 8;
    rtt /= data_cnt!=0 ? data_cnt : -1;

		std::strftime(mbstr, sizeof(mbstr), "%c - ", std::localtime(&time));
		std::cout << mbstr << payload_sum << " Kbps (" << (data_cnt >> 1) << " pkt/s) - latency = " << rtt << " us" << std::endl;
    waitNextDisplay();
}

void
Client::stop()
{
		uint64_t testTime= std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - m_startTime).count() / 1000000;
		std::cout << "Waiting for other threads... " << std::endl;
		for(size_t i = 0; i < m_multi_face; i++) {
   		m_faces[i]->getIoService().stop();
		}

		m_threadGroup.join_all();
    
    size_t pps = m_total_cnt / testTime ;
    size_t kbps = (pps * m_payload_size) >> 7;
    double giga = 1024 * 1024;
    double gbps = kbps / giga;

    std::cout.precision(3);
    std::cout << " Payload Size = " << m_payload_size << std::endl;
		std::cout << " Total Test Time = " << testTime<< " s, "<< kbps <<" Kbps(" << gbps << "G), " <<pps << " pkt/s" << std::endl;
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
    size_t prefix_list = DEFAULT_WINDOW;
    size_t interval = DEFAULT_INTERVAL;
    bool verify = DEFAULT_VERIFY;
    bool canbeprefix = DEFAULT_CANBEPREFIX;
    bool mustbefresh = DEFAULT_MUSTBEFRESH;
		std::string prefix("mw-ndnperf");

		std::string programName(argv[0]);
		std::string confFileName("mw-ndnperf-client.conf");

		size_t multi_face = 1;
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

			if( tn.first == "multi-face" ) {
				std::cout << "multi-face: " << val << std::endl;
        multi_face = boost::lexical_cast<size_t>(val);
			}

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

			if( tn.first == "prefix-list" )
				prefix_list = boost::lexical_cast<size_t>(val);

			if( tn.first == "prefix" )
				prefix = boost::lexical_cast<std::string>(val);

			if( tn.first == "verify" )
				verify = boost::lexical_cast<size_t>(val);

			if( tn.first == "interval" )
				interval = boost::lexical_cast<size_t>(val);

			if( tn.first == "can_be_prefix" )
				canbeprefix = boost::lexical_cast<size_t>(val);

			if( tn.first == "must_be_fresh" )
				mustbefresh = boost::lexical_cast<size_t>(val);

		}

		inputFile.close();
	
    Client client(prefix, prefix_list, window_size, interval, verify, multi_face, core_assign, canbeprefix, mustbefresh);

		signal(SIGINT, signalHandler);

		client.start();

		do {
			sleep(15);
		} while(!g_stop);

		client.stop();

		return 0;
}
