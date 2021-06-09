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
#include <boost/logic/tribool.hpp>

#include <iostream>
#include <fstream>
#include <chrono>
#include <ctime>
#include <stdlib.h>
#include <string>
#include <atomic>

#include "blockingconcurrentqueue.h"

using namespace ndn;
using ConfigSection = boost::property_tree::ptree;
using OptionalConfigSection = boost::optional<const ConfigSection&>;

#define SLEEP_STEP_NS 1000L
#define MAX_SLEEP_NS  128000L
#define ZERO_BULK_TH    5L

// global constants and variables
namespace global {
    const size_t DEFAULT_THREAD_COUNT = boost::thread::hardware_concurrency();
    const char *DEFAULT_PREFIX = "/mw-ndnperf";
    const tlv::SignatureTypeValue DEFAULT_SIGNATURE_TYPE = tlv::DigestSha256;
    const size_t DEFAULT_RSA_KEY_SIZE = 2048;
    const size_t DEFAULT_EC_KEY_SIZE = 256;
    const size_t DEFAULT_CHUNK_SIZE = 8192;
    const size_t DEFAULT_FRESHNESS = 0;
}

std::shared_ptr<boost::asio::io_service> io_svc[10];

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
    std::string m_prefix;
    boost::thread_group m_thread_pool;
    shared_ptr<Face> m_faces[10];

    KeyChain m_keychain;
    security::Identity m_identity;
    const tlv::SignatureTypeValue m_key_type;
    size_t m_key_size = 0;
    security::Key m_key;

    moodycamel::ConcurrentQueue<std::pair<std::shared_ptr<Interest>, int >> m_queue;

    // vars for pre computed part of Data packets
    std::shared_ptr<boost::asio::deadline_timer> m_timer;
    Block m_content;
    const size_t m_payload_size;
    const time::milliseconds m_freshness;

		std::vector<size_t>& m_cores;
		std::vector<std::string> m_prefixList;
		size_t m_max_cnt = 0;
		int m_sendTime = 0;

    size_t m_multi_face = 0;
    bool m_proceesFlag[10] = {0,};
    std::atomic<uint64_t> m_stat_pkt {0};
    std::atomic<uint64_t> m_stat_time {0};

    std::atomic<uint64_t> m_gapCount {0};
    std::chrono::steady_clock::time_point m_gapTime = std::chrono::steady_clock::now();

public:
    Server(std::string prefix, tlv::SignatureTypeValue key_type, size_t key_size,
           size_t payload_size, size_t freshness, std::vector<size_t> &cores, size_t multi_face)
        : m_prefix(prefix)
        , m_key_type(key_type)
        , m_key_size(key_size)
        , m_payload_size(payload_size) 
        , m_freshness(freshness) 
        , m_cores(cores) 
        , m_multi_face(multi_face) 
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

        for(size_t  i=0; i< cores.size(); i++) {
          io_svc[i] = std::make_shared<boost::asio::io_service>();
          m_faces[i] = make_shared<Face>(*io_svc[i]);
        }

        m_timer = std::make_shared<boost::asio::deadline_timer>(*io_svc[0]);

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

				int i =0;
        for(std::vector<size_t>::iterator it = m_cores.begin(); it!=m_cores.end(); ++it) {
            m_thread_pool.create_thread(boost::bind(&Server::process, this, i, *it));
            m_thread_pool.create_thread(boost::bind(&Server::makeData, this, i, *it+10));
            std::this_thread::sleep_for(std::chrono::seconds(1));
						i++;
        }
        std::cout << "Start server with " << m_cores.size() << " signing threads" << std::endl;
        m_thread_pool.create_thread(boost::bind(&Server::display, this));
    }

    void stop() {
        // stop the threads
        std::cout << "Waiting for other threads... " << std::endl;
        m_stop = true;
				Name name(m_prefix);
        name.append("dummy");
				Interest interest(name);
        for (size_t i = 0; i < m_cores.size(); ++i) {
            m_faces[i]->getIoService().stop();
            m_queue.enqueue(std::make_pair(std::make_shared<Interest>(interest), i));
        }
        m_thread_pool.join_all();

        // clean up
        if (m_key_type > 0) {
            std::cout << "Deleting generated key... " << std::endl;
            m_keychain.deleteKey(m_identity, m_key);
        }
    }

    void process(int i, int core) {
				std::cout << "process on CPU: " << core << std::endl;
				cpu_set_t  mask;
				CPU_ZERO(&mask);
				CPU_SET(core, &mask);
				int ret  = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);
				std::cout << "rsched_setaffiniti's ret: " << ret << std::endl;

				Name name(m_prefix);
				name.append(std::to_string(i));

        size_t face_idx = 0;

        face_idx = i % m_multi_face;
        if( !m_proceesFlag[face_idx]) {
          m_thread_pool.create_thread(boost::bind(&Face::processEvents, m_faces[face_idx].get(), time::milliseconds::zero(), false));
          m_proceesFlag[face_idx] = 1;
				  std::cout << "processEvents face_idx = " << face_idx <<" on CPU: " << core << std::endl;
        }
        m_faces[face_idx]->setInterestFilter(name, bind(&Server::on_interest, this, _2, face_idx), bind(&Server::on_register_failed, this, _2, 1));
				std::cout << "setInterestFilter face = "<< face_idx << " core = " << core << " name =  " << name << std::endl;

    }

    void makeData(int i, int core) {
        // thread must own its own keychain since RSA or ECDSA will segfault with 2+ threads
        KeyChain keychain;
				std::cout << "makeData on CPU: " << core << std::endl;
				cpu_set_t  mask;
				CPU_ZERO(&mask);
				CPU_SET(core, &mask);
				int ret  = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);
				std::cout << "rsched_setaffiniti's ret: " << ret << std::endl;
				size_t bulk_size = 0;
				size_t j = 0;
				size_t face_idx = 0;
				size_t zero_bulk_cnt = 0;
        struct timespec request{0,0};

        std::pair<std::shared_ptr<Interest>, int> interest_pairs[10];
        while (!m_stop) {
					bulk_size = m_queue.try_dequeue_bulk(interest_pairs, 3);

          if(bulk_size) {
            for(j = 0; j < bulk_size; j++) {

              auto start = std::chrono::steady_clock::now();

              Name name = interest_pairs[j].first->getName();

              auto pitToken = interest_pairs[j].first->getTag<lp::PitToken>();

              auto data = make_shared<Data>(name);
              data->setFreshnessPeriod(m_freshness);

              if(pitToken != nullptr) {       
                data->setTag(pitToken);
                //std::cout << "PitToken = " << *pitToken << std::endl;
              }

              data->setContent(m_content);
              ++m_stat_pkt;

              if (m_key_type != tlv::DigestSha256) {
                  keychain.sign(*data, security::SigningInfo(m_key));
              } else {
                  // sign with DigestSha256
                  keychain.sign(*data, security::SigningInfo(security::SigningInfo::SIGNER_TYPE_SHA256));
              }

              face_idx = interest_pairs[j].second;

              m_faces[face_idx]->put(*data);
              m_stat_time += std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
            }
            bulk_size = 0;
            zero_bulk_cnt = 0;
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

    void on_interest(const Interest &interest, int i) {
				//std::cout << "receive interest : " << interest << std::endl;

        m_queue.enqueue(std::make_pair(std::make_shared<Interest>(interest), i));
    }

    void display() {
        std::time_t time;
        char mbstr[32];
        uint64_t payload_sum = 0;
        uint64_t packet_count = 0;
        uint64_t process_time = 0;

        packet_count = m_stat_pkt;
        m_stat_pkt = 0;
        process_time = m_stat_time;
        m_stat_time = 0;

        payload_sum = (packet_count * m_payload_size ) >> 8; // in kilobits per second each 2 seconds (10 + 1 - 3), in decimal 8/(1024*2);
        process_time /=  packet_count!= 0 ? packet_count : -1; // negative value if unusual
        packet_count >>= 1; // per second each 2 seconds

        time = std::time(NULL);
        std::strftime(mbstr, sizeof(mbstr), "%c - ", std::localtime(&time));
        std::cout << mbstr << payload_sum << " Kbps( " << packet_count << " pkt/s) " << ", ptime= " << process_time << " us " <<  std::endl;
        waitNextDisplay();
    }

    void waitNextDisplay() {    
      m_timer->expires_from_now(boost::posix_time::seconds(2));
      m_timer->async_wait(boost::bind(&Server::display, this));  
    }

    void on_register_failed(std::string reason, int index){
        std::cerr << "Failed to register prefix[" << index <<"] = " << m_prefixList[index] << " reason = " << reason << std::endl;
        //std::exit(-1);
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
    std::string prefix("mw-ndnperf");
    tlv::SignatureTypeValue key_type = global::DEFAULT_SIGNATURE_TYPE;
    size_t key_size = 0;
    size_t multi_face = 1;
    size_t payload_size = global::DEFAULT_CHUNK_SIZE;
    size_t freshness = global::DEFAULT_FRESHNESS;

		std::string programName(argv[0]);
		std::string confFileName("mw-ndnperf-server.conf");

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

      if( tn.first == "prefix" )
        prefix = boost::lexical_cast<std::string>(val);

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

			if( tn.first == "multi-face" )
				multi_face = boost::lexical_cast<size_t>(val);
		}

		inputFile.close();

		Server server(prefix, key_type, key_size, payload_size, freshness, core_assign, multi_face);
    signal(SIGINT, signalHandler);
    server.start();

    do {
        sleep(15);
    } while (!stop);

    server.stop();

    return 0;
}
