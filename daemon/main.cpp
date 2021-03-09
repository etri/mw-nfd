
#ifndef ETRI_NFD_ORG_ARCH
#include "mw-nfd/input-thread.hpp"
#include "mw-nfd/mw-nfd-worker.hpp"
#include "mw-nfd/mw-nfd-global.hpp"
#endif

#include "nfd.hpp"
#include "rib/service.hpp"
#include "common/global.hpp"
#include "common/logger.hpp"
#include "common/privilege-helper.hpp"
#include "core/version.hpp"

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/property_tree/info_parser.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/tokenizer.hpp>
#include <boost/filesystem.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <boost/asio/steady_timer.hpp>
#include <boost/asio.hpp>

#include <atomic>
#include <condition_variable>
#include <iostream>
#include <thread>

#include <ndn-cxx/util/logging.hpp>
#include <ndn-cxx/version.hpp>

#ifdef HAVE_LIBPCAP
#include <pcap/pcap.h>
#endif
#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif
#ifdef HAVE_WEBSOCKET
#include <websocketpp/version.hpp>
#endif

#define RELAY_MODE_ENABLED

namespace po = boost::program_options;
using namespace std;
using namespace boost;
namespace ip = boost::asio::ip;

NFD_LOG_INIT(Main);

namespace nfd {
/** \brief Executes NFD with RIB manager
 *
 *  NFD (main forwarding procedure) and RIB manager execute in two different threads.
 *  Each thread has its own instances of global io_service and global scheduler.
 *
 *  When either of the daemons fails, execution of non-failed daemon will be terminated as
 *  well.  In other words, when NFD fails, RIB manager will be terminated; when RIB manager
 *  fails, NFD will be terminated.
 */

#ifndef ETRI_NFD_ORG_ARCH
std::set<int8_t> g_dcnWorkerList;
std::map<std::string, uint8_t> g_inputWorkerList;
std::string g_bulkFibTestPort0;
std::string g_bulkFibTestPort1;
bool g_wantFibSharding=false;

static void configMwNfdConfig(const std::string configFileName)
{
    std::string user;
    std::string group;
    OptionalConfigSection opt;

    ConfigSection config;
    boost::property_tree::read_info(configFileName, config);
    auto mw_nfd_section = config.get_child("mw-nfd");
    bool alreadyProcessForwarding = false;

    setBulkFibTest(false);

    for(const auto& section : mw_nfd_section) {

        if( section.first == "input-thread-core-assign"){
            auto inputs = config.get_child("mw-nfd.input-thread-core-assign");
                for (const auto& input : inputs) {
                    auto ret = g_inputWorkerList.emplace( input.first, input.second.get_value<std::uint8_t>() );
					if(ret.second == false){
                		std::cerr << "There are Same Physical Port :" << input.first << std::endl;
                		exit(0);
					}
                }
        }else if( section.first == "forwarding-worker-core-assign"){
            if(alreadyProcessForwarding==true)
            {
                std::cerr << "There are double forwarding-worker-core-assign sections on mw-nfd section in mw-nfd.conf" << "\n";
                exit(0);
            }
            auto cores = config.get("mw-nfd.forwarding-worker-core-assign", "1,2");

			boost::char_separator<char> sep(",");
			typedef boost::tokenizer< boost::char_separator<char> > t_tokenizer;
			t_tokenizer tok(cores, sep);
			for (t_tokenizer::iterator beg = tok.begin(); beg != tok.end(); ++beg)
			{   
				string core = *beg;
				if( core.find("-") != string::npos ){
					int start, end;
					sscanf(core.c_str(), "%d-%d", &start, &end);
					if( end <= start ){
						std::cerr << "core list error: " << core << " in mw-nfd.forwarding-worker-core-assign section" << std::endl;
						exit(0);
					}   
					for(int i=start;i<=end;i++)
						g_dcnWorkerList.insert(i);
				}else
					g_dcnWorkerList.insert(atoi(core.c_str()));
			}   


            alreadyProcessForwarding = true;
        }else if( section.first == "fib-sharding"){
            std::string wantFibSharding = config.get("mw-nfd.fib-sharding","no");
			if(wantFibSharding=="yes")
				g_wantFibSharding=true;
        }else if( section.first == "prefix-length-for-distribution"){

            setPrefixLength4Distribution(config.get<std::size_t>("mw-nfd.prefix-length-for-distribution",2));

        }else if( section.first == "bulk-fib-test"){
            auto bulks = config.get_child("mw-nfd.bulk-fib-test");
            setBulkFibTest(true);
            for (const auto& bulk : bulks) {
                if(bulk.first=="bulk-fib-file-path")
                    setBulkFibFilePath(bulk.second.get_value<std::string>());
                else if(bulk.first=="bulk-fib-test-port0")
                    g_bulkFibTestPort0 = bulk.second.get_value<std::string>();
                else if(bulk.first=="bulk-fib-test-port1")
                    g_bulkFibTestPort1 = bulk.second.get_value<std::string>();
            }
        }
    }

    if( g_inputWorkerList.size() > 0 and g_dcnWorkerList.size() > 0){

	    for(auto in:g_inputWorkerList){

	        for(auto wrk:g_dcnWorkerList){
                if(in.second == wrk){
                    std::cerr << "Error!!! Using Same core Number(" << wrk << ") both InputThread and WorkerThread" << std::endl;
                    exit(0);
                }
            }
        }

    }
}

#endif

void forwardingWorkerTimerTrigger(const boost::system::error_code& /*e*/,
            boost::shared_ptr< boost::asio::deadline_timer > t,
            int wid)
{
    if( nfd::g_workerTimerTriggerList[wid]==false )
        nfd::g_workerTimerTriggerList[wid]=true;

    t->expires_at(t->expires_at() + boost::posix_time::milliseconds(MW_NFD_TRIGGER_TMR));
    t->async_wait(boost::bind(forwardingWorkerTimerTrigger,
        boost::asio::placeholders::error, t, wid));

}

class NfdRunner : noncopyable
{
public:
  explicit
  NfdRunner(const std::string& configFile)
    : m_nfd(configFile, m_nfdKeyChain)
    , m_configFile(configFile)
    , m_terminationSignalSet(getGlobalIoService())
    , m_reloadSignalSet(getGlobalIoService())
  {
    m_terminationSignalSet.add(SIGINT);
    m_terminationSignalSet.add(SIGTERM);
    m_terminationSignalSet.async_wait(bind(&NfdRunner::terminate, this, _1, _2));

    m_reloadSignalSet.add(SIGHUP);
    m_reloadSignalSet.async_wait(bind(&NfdRunner::reload, this, _1, _2));

  }

  void initialize()
  {
    m_nfd.initialize();
  }

  int
  run()
  {
    // Return value: a non-zero value is assigned when either NFD or RIB manager (running in
    // a separate thread) fails.

    std::atomic_int retval(0);

    boost::asio::io_service* const mainIo = &getGlobalIoService();
    setMainIoService(mainIo);
    boost::asio::io_service* ribIo = nullptr;

    for(int i=0; i<getForwardingWorkers();i++){

        boost::shared_ptr< boost::asio::deadline_timer > timer(
                new boost::asio::deadline_timer( getMainIoService())
                );
        timer->expires_from_now( boost::posix_time::milliseconds( 3 ) );
        timer->async_wait(boost::bind(forwardingWorkerTimerTrigger,
                    boost::asio::placeholders::error, timer, i));
    }

    // Mutex and conditional variable to implement synchronization between main and RIB manager
    // threads:
    // - to block main thread until RIB manager thread starts and initializes ribIo (to allow
    //   stopping it later)
    std::mutex m;
    std::condition_variable cv;

    std::thread ribThread([configFile = m_configFile, &retval, &ribIo, mainIo, &cv, &m] {
      {
        std::lock_guard<std::mutex> lock(m);
        ribIo = &getGlobalIoService();
        BOOST_ASSERT(ribIo != mainIo);
        setRibIoService(ribIo);
      }
      cv.notify_all(); // notify that ribIo has been assigned

      try {
        ndn::KeyChain ribKeyChain;
        // must be created inside a separate thread
        rib::Service ribService(configFile, ribKeyChain);
        getGlobalIoService().run(); // ribIo is not thread-safe to use here
      }
      catch (const std::exception& e) {
        NFD_LOG_FATAL(boost::diagnostic_information(e));
        retval = 1;
        mainIo->stop();
      }

      {
        std::lock_guard<std::mutex> lock(m);
        ribIo = nullptr;
      }
    });

    {
      // Wait to guarantee that ribIo is properly initialized, so it can be used to terminate
      // RIB manager thread.
      std::unique_lock<std::mutex> lock(m);
      cv.wait(lock, [&ribIo] { return ribIo != nullptr; });
        retval = 0;
    }

    try {
      systemdNotify("READY=1");

      mainIo->run();
    }
    catch (const std::exception& e) {
      NFD_LOG_FATAL(boost::diagnostic_information(e));
      retval = 1;
    }
    catch (const PrivilegeHelper::Error& e) {
      NFD_LOG_FATAL(e.what());
      retval = 4;
    }

    {
      std::cout << "ribIo is guaranteed to be alive at this point.."  << std::endl;
      std::lock_guard<std::mutex> lock(m);
      if (ribIo != nullptr) {
        ribIo->stop();
        ribIo = nullptr;
      }
    }
    ribThread.join();

    return retval;
  }

  static void
  systemdNotify(const char* state)
  {
#ifdef HAVE_SYSTEMD
    sd_notify(0, state);
#endif
  }

private:
  void
  terminate(const boost::system::error_code& error, int signalNo)
  {
    if (error)
      return;

    NFD_LOG_INFO("Caught signal " << signalNo << " (" << ::strsignal(signalNo) << "), exiting...");

    systemdNotify("STOPPING=1");
    getGlobalIoService().stop();
  }

  void
  reload(const boost::system::error_code& error, int signalNo)
  {
    if (error)
      return;

    NFD_LOG_INFO("Caught signal " << signalNo << " (" << ::strsignal(signalNo) << "), reloading...");

    systemdNotify("RELOADING=1");
    m_nfd.reloadConfigFile();
    systemdNotify("READY=1");

    m_reloadSignalSet.async_wait(bind(&NfdRunner::reload, this, _1, _2));
  }

private:
  ndn::KeyChain           m_nfdKeyChain;
  Nfd                     m_nfd;
  std::string             m_configFile;

  boost::asio::signal_set m_terminationSignalSet;
  boost::asio::signal_set m_reloadSignalSet;
};

static void
printUsage(std::ostream& os, const char* programName, const po::options_description& opts)
{
    os << "Usage: " << programName << " [options]\n"
        << "\n"
        << "Run the NDN Forwarding Daemon (NFD)\n"
        << "\n"
        << opts;
}

static void
printAddedFeatures(std::ostream& os)
{
#ifdef ETRI_DEBUG_COUNTERS
    //std::cout << "***+ Running NFD Original Archecture..." << std::endl;
    std::cout << "   +-- with ETRI-DEBUG-COUNTERS." << std::endl;
#endif
#ifdef ETRI_NFD_ORG_ARCH
    std::cout << "   +-- with ETRI-NFD-ORG-ARCH." << std::endl;
#endif
#ifdef ETRI_DUAL_CS
    std::cout << "   +-- with WITH-DUAL-CS." << std::endl;
#endif
#ifdef ETRI_PITTOKEN_HASH
    std::cout << "   +-- with WITH-PITTOKEN-HASH." << std::endl;
#endif

    std::cout << "\n \n" << std::endl;
    //std::cout << "\n *v* Visit https://www.etri.re.kr *v*\n" << std::endl;
cout << "	                  {}\n";
cout << "	  ,   A           {}\n";
cout << "	 / \\, | ,        .--.\n";
cout << "	|  =|= >        /.--.\\\n";
cout << "	 \\ /` | `       |====|\n";
cout << "	  `   |         |`::`|\n";
cout << "	      |     .-;`\\..../`;_.-^-._\n";
cout << "	     /\\\\/  /  |...::..|`   :   `|                ::::::::::: :::::::::\n";
cout << "	     |:'\\ |   /'''::''|   .:.   |                   :+:     :+:    :+:\n";
cout << "	      \\ /\\;-,/\\   ::  |..MWNFD..|                  +:+     +:+    +:+\n";
cout << "	      |\\ <` >  >._::_.| ':NDN:' |                 +#+     +#++:++#+\n";
cout << "	      | `""`_/   ^^/>/> |   ':'   |                +#+     +#+\n";
cout << "	      |       |       \\    :    /               #+#     #+#\n";
cout << "	      |       |        \\   :   /           ########### ###\n";
cout << "	      |       |___/\\___|`-.:.-`\n";
cout << "	      |        \\_ || _/    `\n";
cout << "	      |        <_ >< _>\n";
cout << "	      |        |  ||  |\n";
cout << "	      |        |  ||  |\n";
cout << "	      |       _\\.:||:./_\n";
cout << "	      | ETRI /____/\\____\\\n";
cout << "\n";
//cout << ".:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*:._.:*~*: https://www.etri.re.kr :*~*:" << endl;
cout << ".:*~*: https://github.com/etri/MW-NFD.git :*~*._.:*~*: https://www.ETRI.re.kr :*~*:" << endl;
cout << "\n\n\n" << endl;
}

static void
printLogModules(std::ostream& os)
{
    const auto& modules = ndn::util::Logging::getLoggerNames();
// ETRI
//    std::copy(modules.begin(), modules.end(), ndn::make_ostream_joiner(os, "\n"));
    os << std::endl;
}

} // namespace nfd

#ifdef ETRI_NFD_ORG_ARCH

int main(int argc, char** argv)
{
    std::cout << std::endl;
    std::cout << " *v* Running NFD Original Archecture..." << std::endl;
	nfd::printAddedFeatures(std::cout);

    using namespace nfd;

    std::string configFile = DEFAULT_CONFIG_FILE;

    po::options_description description("Options");
    description.add_options()
        ("help,h",    "print this message and exit")
        ("version,V", "show version information and exit")
        ("config,c",  po::value<std::string>(&configFile),
         "path to configuration file (default: " DEFAULT_CONFIG_FILE ")")
        ("modules,m", "list available logging modules")
        ;

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, description), vm);
        po::notify(vm);
    }
    catch (const std::exception& e) {
        // Cannot use NFD_LOG_* macros here, because the logging subsystem is not initialized yet
        // at this point. Moreover, we don't want to clutter error messages related to command-line
        // parsing with timestamps and other useless text added by the macros.
        std::cerr << "ERROR: " << e.what() << "\n\n";
        printUsage(std::cerr, argv[0], description);
        return 2;
    }

    if (vm.count("help") > 0) {
        printUsage(std::cout, argv[0], description);
        return 0;
    }

    if (vm.count("version") > 0) {
        std::cout << NFD_VERSION_BUILD_STRING << std::endl;
        return 0;
    }

    if (vm.count("modules") > 0) {
        printLogModules(std::cout);
        return 0;
    }

    const std::string boostBuildInfo =
        "with Boost version " + to_string(BOOST_VERSION / 100000) +
        "." + to_string(BOOST_VERSION / 100 % 1000) +
        "." + to_string(BOOST_VERSION % 100);
    const std::string pcapBuildInfo =
#ifdef HAVE_LIBPCAP
        "with " + std::string(pcap_lib_version());
#else
    "without libpcap";
#endif
    const std::string wsBuildInfo =
#ifdef HAVE_WEBSOCKET
        "with WebSocket++ version " + to_string(websocketpp::major_version) +
        "." + to_string(websocketpp::minor_version) +
        "." + to_string(websocketpp::patch_version);
#else
    "without WebSocket++";
#endif

    std::clog << "NFD version " << NFD_VERSION_BUILD_STRING << " starting\n"
        << "Built with " BOOST_COMPILER ", with " BOOST_STDLIB
        ", " << boostBuildInfo <<
        ", " << pcapBuildInfo <<
        ", " << wsBuildInfo <<
        ", with ndn-cxx version " NDN_CXX_VERSION_BUILD_STRING
        << std::endl;

    NfdRunner runner(configFile);
    try {
        runner.initialize();
    }
    catch (const boost::filesystem::filesystem_error& e) {
        NFD_LOG_FATAL(boost::diagnostic_information(e));
        return e.code() == boost::system::errc::permission_denied ? 4 : 1;
    }
    catch (const std::exception& e) {
        NFD_LOG_FATAL(boost::diagnostic_information(e));
        return 1;
    }
    catch (const PrivilegeHelper::Error& e) {
        // PrivilegeHelper::Errors do not inherit from std::exception
        // and represent seteuid/gid failures
        NFD_LOG_FATAL(e.what());
        return 4;
    }

    return runner.run();
}

#else


int main(int argc, char** argv)
{

  using namespace nfd;

    std::string configFile = DEFAULT_CONFIG_FILE;
    std::string core_list = DEFAULT_CONFIG_FILE;

    po::options_description description("Options");
    description.add_options()
        ("help,h",    "print this message and exit")
        ("version,V", "show version information and exit")
        ("config,c",  po::value<std::string>(&configFile),
         "path to configuration file (default: " DEFAULT_CONFIG_FILE ")")
        ("modules,m", "list available logging modules")
        ;

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, description), vm);
        po::notify(vm);
    }
    catch (const std::exception& e) {
        // Cannot use NFD_LOG_* macros here, because the logging subsystem is not initialized yet
        // at this point. Moreover, we don't want to clutter error messages related to command-line
        // parsing with timestamps and other useless text added by the macros.
        std::cerr << "ERROR: " << e.what() << "\n\n";
        printUsage(std::cerr, argv[0], description);
        return 2;
    }

    if (vm.count("help") > 0) {
        printUsage(std::cout, argv[0], description);
        return 0;
    }

    if (vm.count("version") > 0) {
        std::cout << NFD_VERSION_BUILD_STRING << std::endl;
        return 0;
    }

    if (vm.count("modules") > 0) {
        printLogModules(std::cout);
        return 0;
    }

#if defined(__linux__)
	cpu_set_t  mask;
	CPU_ZERO(&mask);
	//CPU_SET(std::thread::hardware_concurrency()-1, &mask);
	CPU_SET(0, &mask);
	sched_setaffinity(getpid(), sizeof(mask), &mask);
#elif defined(__APLLE__)
	processor_set_t mask;
	//processor_assign(getpid(), mask, true);
#endif

	resetCommandRx();

    //ConfigFile config(&ignoreConfigSections);
    //config.addSectionHandler("mw-nfd", &onMwNfdConfig);
    //config.parse(configFile, false);
    configMwNfdConfig(configFile);

    NFD_LOG_INFO("");;
    std::cout << " *v* Running MW-NFD Archecture..." << std::endl;
	nfd::printAddedFeatures(std::cout);

    const std::string boostBuildInfo =
        "with Boost version " + to_string(BOOST_VERSION / 100000) +
        "." + to_string(BOOST_VERSION / 100 % 1000) +
        "." + to_string(BOOST_VERSION % 100);
    const std::string pcapBuildInfo =
#ifdef HAVE_LIBPCAP
        "with " + std::string(pcap_lib_version());
#else
    "without libpcap";
#endif
    const std::string wsBuildInfo =
#ifdef HAVE_WEBSOCKET
        "with WebSocket++ version " + to_string(websocketpp::major_version) +
        "." + to_string(websocketpp::minor_version) +
        "." + to_string(websocketpp::patch_version);
#else
    "without WebSocket++";
#endif

    std::clog << "NFD version " << NFD_VERSION_BUILD_STRING << " starting\n"
        << "Built with " BOOST_COMPILER ", with " BOOST_STDLIB
        ", " << boostBuildInfo <<
        ", " << pcapBuildInfo <<
        ", " << wsBuildInfo <<
        ", with ndn-cxx version " NDN_CXX_VERSION_BUILD_STRING
        << std::endl;
    boost::thread_group tg;


    std::mutex m;
    std::condition_variable cv;
    std::atomic_int retval(0);

    uint32_t worker_cores = g_dcnWorkerList.size();
    nfd::setForwardingWorkers(worker_cores);

    for(int i=0;i<DCN_MAX_WORKERS;i++)
        g_workerTimerTriggerList[i]=true;

    NfdRunner runner(configFile);
    runner.initialize();

	uint32_t coreId;
	nfd::mq_allocation();

	int8_t workerId=2; // 0 is for mainThread


	for(auto & x:g_inputWorkerList){

		string if_name = x.first;
		coreId = x.second;

		tg.create_thread( [workerId, coreId, if_name]{

#if defined(__linux__)
				cpu_set_t cpuset;
				CPU_ZERO(&cpuset);
				CPU_SET(coreId, &cpuset);
				int rc = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), (cpu_set_t*)&cpuset);

				if (rc != 0) {
                std::cerr << "The Input Thread : Error calling pthread_setaffinity_np: " << rc << "\n";
                    exit(0);
				}

				NFD_LOG_INFO("The Input-Thread is Running with core#: "<< coreId << "/worker#:" << workerId << " TID:" << sched_getcpu()); 

#elif defined(__APLLE__)
	processor_set_t mask;
	//processor_assign(getpid(), mask, true);
#endif


				setGlobalIwId(workerId);

				try{
				InputThread iw;
				iw.initialize(workerId, if_name);
				iw.run();
				}catch (const std::exception& e) {
					//mainIo->stop();
				}

		});
		workerId +=2;
	}

	workerId =0;

    for(auto core : g_dcnWorkerList){
        coreId = core;

        tg.create_thread( [ workerId, coreId, &cv, &m, &retval, configFile]{

#if defined(__linux__)
                cpu_set_t cpuset;
                CPU_ZERO(&cpuset);
                CPU_SET(coreId, &cpuset);
                int rc = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), (cpu_set_t*)&cpuset);

                if (rc != 0) {
                std::cerr << "MW-NFD Thread ERROR+++ when calling pthread_setaffinity_np(): " << rc << "\n";
                    exit(0);
                }
                NFD_LOG_INFO("MW-NFD-Worker(" << coreId <<")");
#elif defined(__APLLE__)
                processor_set_t mask;
                //processor_assign(getpid(), mask, true);
#endif

                try{
                    auto mwNfd = std::make_shared<nfd::MwNfd>(workerId, &getGlobalIoService(), g_wantFibSharding, configFile);
                    {
                        std::unique_lock<std::mutex> lock(m);
                        cv.wait(lock, [&retval] { return retval == 1; });
                    }   
                    setMwNfd(workerId, mwNfd);
                    mwNfd->initialize( g_inputWorkerList.size()+1 );

                    if(getBulkFibTest())
                        mwNfd->prepareBulkFibTest(g_bulkFibTestPort0, g_bulkFibTestPort1);

                    mwNfd->runWorker();

                }catch (const std::exception& e) {
                }
        });
        workerId +=1;
    }

    try {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	    {
		    std::lock_guard<std::mutex> lock(m);
		    retval = 1;
	    }
	    cv.notify_all();
    }
    catch (const boost::filesystem::filesystem_error& e) {
        NFD_LOG_FATAL(boost::diagnostic_information(e));
        return e.code() == boost::system::errc::permission_denied ? 4 : 1;
    }
    catch (const std::exception& e) {
        NFD_LOG_FATAL(boost::diagnostic_information(e));
        return 1;
    }
    catch (const PrivilegeHelper::Error& e) {
        // PrivilegeHelper::Errors do not inherit from std::exception
        // and represent seteuid/gid failures
        NFD_LOG_FATAL(e.what());
        return 4;
    }

    return runner.run();
}

#endif
