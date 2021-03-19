/*    
Copyright (C) 2015-2017  Xavier MARCHAL

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <ndn-cxx/face.hpp>
#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-info.hpp>
#include <ndn-cxx/encoding/buffer.hpp>
#include <ndn-cxx/lp/pit-token.hpp>
#include <ndn-cxx/lp/tags.hpp>

#include <boost/asio.hpp>
#include <boost/thread.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/info_parser.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/lexical_cast.hpp>

#include <iostream>
#include <fstream>
#include <chrono>
#include <ctime>
#include <string>

#include "blockingconcurrentqueue.h"

using namespace ndn;
using ConfigSection = boost::property_tree::ptree;
using OptionalConfigSection = boost::optional<const ConfigSection&>;

// global constants and variables
namespace global {
    const size_t DEFAULT_THREAD_COUNT = boost::thread::hardware_concurrency();
    const char *DEFAULT_PREFIX = "/throughput";
    const tlv::SignatureTypeValue DEFAULT_SIGNATURE_TYPE = tlv::DigestSha256;
    const size_t DEFAULT_RSA_KEY_SIZE = 2048;
    const size_t DEFAULT_EC_KEY_SIZE = 256;
    const size_t DEFAULT_CHUNK_SIZE = 8192;
    const size_t DEFAULT_FRESHNESS = 0;
}

class Server {
private:
    void gen_random(char *s, size_t len) {
        static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        for (size_t i = 0; i < len; ++i) {
            s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
        }

        s[len] = 0;
    }

    bool m_stop = false;

		const size_t m_master_core;
    const Name m_prefix;
    boost::thread_group m_thread_pool;

    Face m_face;
    KeyChain m_keychain;
    security::Identity m_identity;
    const tlv::SignatureTypeValue m_key_type;
    size_t m_key_size = 0;
    security::Key m_key;

    moodycamel::BlockingConcurrentQueue<std::pair<Interest, std::chrono::steady_clock::time_point>> m_queue;

    // vars for pre computed part of Data packets
    Block m_content;
    const size_t m_payload_size;
    const time::milliseconds m_freshness;

    // array for statistics
    int *m_log_vars; // may be less accurate than atomic variables but no sync required

		std::vector<size_t>& m_cores;

public:
    Server(size_t master_core, const char *prefix, tlv::SignatureTypeValue key_type, size_t key_size,
           size_t payload_size, size_t freshness, std::vector<size_t> &cores)
        : m_master_core(master_core)
        , m_prefix(prefix)
        , m_face()
        , m_key_type(key_type)
        , m_key_size(key_size)
        , m_payload_size(payload_size) 
        , m_freshness(freshness) 
        , m_cores(cores) 
		{
        if (m_key_type != tlv::DigestSha256) {
            auto it = m_keychain.getPib().getIdentities().find(m_prefix);
            m_identity = it != m_keychain.getPib().getIdentities().end() ? *it : m_keychain.createIdentity(prefix);

            switch (m_key_type) {
                default:
                case tlv::SignatureSha256WithRsa: {
                    if(m_key_size < 1024) {
                        m_key_size = global::DEFAULT_RSA_KEY_SIZE;
                    }
                    std::cout << "Generating new " << m_key_size << " bits RSA key pair" << std::endl;
                    m_key = m_keychain.createKey(m_identity, RsaKeyParams(m_key_size));
                    break;
                }
                case tlv::SignatureSha256WithEcdsa: {
                    if(m_key_size != 256 && m_key_size != 384) {
                        m_key_size = global::DEFAULT_EC_KEY_SIZE;
                    }
                    std::cout << "Generating new " << m_key_size << " bits ECDSA key pair" << std::endl;
                    m_key = m_keychain.createKey(m_identity, EcKeyParams(m_key_size));
                    break;
                }
            }

            std::cout << "Using key " << m_key.getName() << "\n"
                      << m_key.getDefaultCertificate() << std::endl;
        } else {
            std::cout << "Using SHA-256 signature" << std::endl;
        }

        std::cout << "Concurrency = " << cores.size() << std::endl;

        m_log_vars = new int[cores.size() * 4](); // [concurrency][0: payload sum, 1: packet count, 2:qtime, 3: ptime]

        // build once for all the data carried by the packets (packets generated from files ignore this)
        char *chararray = new char[payload_size];
        gen_random(chararray, payload_size);
        shared_ptr<Buffer> buf = make_shared<Buffer>(&chararray[0], payload_size);
        m_content = Block(tlv::Content, buf);
        std::cout << "Payload size = " << m_content.value_size() << " Bytes" << std::endl;
        std::cout << "Freshness = " << freshness << " ms" << std::endl;
    }

    ~Server() = default;

    void start() {
				Name name("/");
        m_face.setInterestFilter(name, bind(&Server::on_interest, this, _2), bind(&Server::on_register_failed, this));

				int i =0;
        for(std::vector<size_t>::iterator it = m_cores.begin(); it!=m_cores.end(); ++it) {
            m_thread_pool.create_thread(boost::bind(&Server::process, this, &m_log_vars[i * 4], *it));
						i++;
        }
        std::cout << "Start server with " << m_cores.size() << " signing threads" << std::endl;
        m_thread_pool.create_thread(boost::bind(&Server::display, this));
        m_thread_pool.create_thread(boost::bind(&Face::processEvents, &m_face, time::milliseconds::zero(), false));
    }

    void stop() {
        // stop the threads
        std::cout << "Waiting for other threads... " << std::endl;
        m_stop = true;
        Name name(m_prefix);
        name.append("dummy");
				Interest interest(name);
        m_face.getIoService().stop();
        for (size_t i = 0; i < m_cores.size(); ++i) {
            m_queue.enqueue(std::make_pair(interest, std::chrono::steady_clock::now()));
        }
        m_thread_pool.join_all();

        // clean up
        if (m_key_type > 0) {
            std::cout << "Deleting generated key... " << std::endl;
            m_keychain.deleteKey(m_identity, m_key);
        }
    }

    void process(int *const i, int core) {
        // thread must own its own keychain since RSA or ECDSA will segfault with 2+ threads
        KeyChain keychain;
        std::pair<Interest, std::chrono::steady_clock::time_point> pair;
        std::ifstream file;

				std::cout << "process on CPU: " << core << std::endl;
		
				cpu_set_t  mask;
				CPU_ZERO(&mask);
				CPU_SET(core, &mask);
				int ret  = sched_setaffinity(getpid(), sizeof(mask), &mask);
				std::cout << "rsched_setaffiniti's ret: " << ret << std::endl;

        while (!m_stop) {
            m_queue.wait_dequeue(pair);
            Name name = pair.first.getName();

						auto pitToken = pair.first.getTag<lp::PitToken>();

            auto start = std::chrono::steady_clock::now();
            i[2] += std::chrono::duration_cast<std::chrono::microseconds>(start - pair.second).count();

            auto data = make_shared<Data>(name);
            data->setFreshnessPeriod(m_freshness);

						if(pitToken != nullptr) {       
							data->setTag(pair.first.getTag<lp::PitToken>());
						}

						data->setContent(m_content);
						i[0] += m_payload_size;

            if (m_key_type != tlv::DigestSha256) {
                keychain.sign(*data, security::SigningInfo(m_key));
            } else {
                // sign with DigestSha256
                keychain.sign(*data, security::SigningInfo(security::SigningInfo::SIGNER_TYPE_SHA256));
            }
            m_face.put(*data);

            ++i[1];
            i[3] += std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
        }
    }

    void display() {
        std::time_t time;
        char mbstr[32];
        int log_vars[8] = {}; // [0: payload sum, 1: packet count, 2:qtime, 3: ptime][1: new, 2: last]
        while (!m_stop) {
            // accumulate value and compare with last
            for (int i = 0; i < 8; i += 2) {
                log_vars[i + 1] = -log_vars[i];
                log_vars[i] = 0;
            }
            for (size_t i = 0; i < m_cores.size(); ++i) {
                for (int j = 0; j < 4; ++j) {
                    log_vars[2 * j] += m_log_vars[4 * i + j];
                }
            }
            for (int i = 0; i < 8; i += 2) {
                log_vars[i + 1] += log_vars[i];
            }
            log_vars[1] >>= 8; // in kilobits per second each 2 seconds (10 + 1 - 3), in decimal 8/(1024*2);
            log_vars[5] /= log_vars[3] != 0 ? log_vars[3] : -1; // negative value if unusual
            log_vars[7] /= log_vars[3] != 0 ? log_vars[3] : -1; // negative value if unusual
            log_vars[3] >>= 1; // per second each 2 seconds
            time = std::time(NULL);
            std::strftime(mbstr, sizeof(mbstr), "%c - ", std::localtime(&time));
            std::cout << mbstr << log_vars[1] << " Kbps( " << log_vars[3] << " pkt/s) - qtime= " << log_vars[5] << " us, ptime= " << log_vars[7] << " us" << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }

    void on_interest(const Interest &interest) {
        // it may be me but when i use multiple threads with m_face.processEvent(),
        // the sum of the workloads is equivalent to a single thread
        m_queue.enqueue(std::make_pair(interest, std::chrono::steady_clock::now()));
    }

    void on_register_failed(){
        std::cerr << "Failed to register prefix " << m_prefix << std::endl;
        std::exit(-1);
    }
};

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
    // default values
    const char *prefix = global::DEFAULT_PREFIX;
    tlv::SignatureTypeValue key_type = global::DEFAULT_SIGNATURE_TYPE;
    size_t key_size = 0;
    size_t payload_size = global::DEFAULT_CHUNK_SIZE;
    size_t freshness = global::DEFAULT_FRESHNESS;

		std::string programName(argv[0]);
		std::string confFileName("mw-ndnperf-server.conf");
		size_t master_core = 0;

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

			if( tn.first == "master-core" )
				master_core = boost::lexical_cast<size_t>(val);

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

			if( tn.first == "signature-type" ){
				if( val == "DigestSha256" )
					key_type = tlv::DigestSha256;
				else if( val == "SignatureSha256WithRsa" )
					key_type = tlv::SignatureSha256WithRsa;
				else if( val == "SignatureSha256WithEcdsa" )
					key_type = tlv::SignatureSha256WithEcdsa;
				else	
					key_type = tlv::DigestSha256;
			}
			if( tn.first == "chunk-size" )
				payload_size = boost::lexical_cast<size_t>(val);

			if( tn.first == "rsa-key-size" or tn.first == "ec-key-size" )
				key_size = boost::lexical_cast<size_t>(val);

			if( tn.first == "freshness" )
				freshness = boost::lexical_cast<size_t>(val);
		}

		inputFile.close();

		Server server(master_core, prefix, key_type, key_size, payload_size, freshness, core_assign);
    signal(SIGINT, signalHandler);
    server.start();

    do {
        sleep(15);
    } while (!stop);

    server.stop();

    return 0;
}
