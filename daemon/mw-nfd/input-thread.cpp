
#include "input-thread.hpp"
#include "common/global.hpp"
#include "mw-nfd-global.hpp"

#include <ctime> 

#if defined(__linux__)
#include <linux/sockios.h>
#include <sys/ioctl.h>
#elif defined(__APPLE__)
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#endif

/*
	For Input Thread io_service.poll debugging 
#ifdef ETRI_DEBUG_COUNTERS	
extern size_t g_nInputPollEvent[8][400];
#endif 
*/
#define SLEEP_STEP_NS		10000UL
#define MAX_ZERO_EVENT_TH	500UL	
#define	MIN_ZERO_EVENT_TH	1UL

NFD_LOG_INIT(InputThread);
namespace nfd {

InputThread::InputThread()
  : m_terminationSignalSet(getGlobalIoService())
{

  m_terminationSignalSet.add(SIGINT);
  m_terminationSignalSet.add(SIGTERM);
  m_terminationSignalSet.async_wait(bind(&InputThread::terminate, this, _1, _2));

}

InputThread::~InputThread() = default;

#ifndef ETRI_NFD_ORG_ARCH

void InputThread::initialize(int32_t Id, const string ifname)
{
    //getGlobalLogger().info("initializing InputThread-InputThreadId:{}/Physical Port:{}.", Id, ifname);
    NFD_LOG_INFO( "initializing InputThread(" << Id << ")/Physical Port:" << ifname  );;
	int ifIndex = 0;

	m_Id = Id;

	ifIndex= if_nametoindex(ifname.c_str());

	NFD_LOG_INFO("InputThread(" << Id << ") - ifIndex: " <<  ifIndex);
	setGlobalIoService(ifIndex, &getGlobalIoService());
}

void InputThread::run()
{
	size_t event_count = 0;
	size_t zero_event_cnt = 0;
	size_t zero_event_th = MAX_ZERO_EVENT_TH;
	bool  prev_zero_event = false; 
	struct timespec request{0,SLEEP_STEP_NS};

//#define ETRI_PERF

	do{
#ifndef ETRI_POWER_OPTIMIZE
		event_count = getGlobalIoService().poll();
/*
#ifdef ETRI_DEBUG_COUNTERS
		if (event_count < 400) {
			g_nInputPollEvent[m_Id][event_count]++;
		} 
		else { 
			g_nInputPollEvent[m_Id][400]++;
		}
#endif
*/

/* 
   For power-saving in idle time (default mode): 
   Add nanosleep(SLEEP_STEP_NS) when consecutive zero event receiving (zero_event_th times) happens, 
   and double the zero_event_th up to MAX_ZERO_EVENT_TH. 
   zero_event_th is reset to MAX_ZERO_EVENT_TH when any event is received.
   This reduces cpu load of input threads in idle time from 100% to 7.4% 
*/
		if (event_count == 0) {
			if (++zero_event_cnt > zero_event_th) {
				zero_event_th = (prev_zero_event) ? std::max(zero_event_th/2, MIN_ZERO_EVENT_TH) : MAX_ZERO_EVENT_TH; 
				nanosleep(&request, NULL);
				zero_event_cnt = 0;
				prev_zero_event = true; 
			}
		} 
		else {
			prev_zero_event = false;
		}
#else
/*
   IoSevice.run() takes less power and shows similiar throughput in most cases, but the maximum throughput for many workers 
   can be reduced (about 7% for 14 forwarding workers and two input threads) 
   This reduces cpu load of input thread in idle time from 100% to 2.7% 
*/
		getGlobalIoService().run();
#endif

	}while(1);

}
#endif

} // namespace nfd
