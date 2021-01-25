
#include "input-thread.hpp"
#include "common/global.hpp"
#include "mw-nfd-global.hpp"

#if defined(__linux__)
#include <linux/sockios.h>
#include <sys/ioctl.h>
#elif defined(__APPLE__)
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#endif

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
    getGlobalLogger().info("initializing InputThread-InputThreadId:{}/Physical Port:{}.", Id, ifname);
	int ifIndex = 0;

	ifIndex= if_nametoindex(ifname.c_str());

	getGlobalLogger().info("InputThread({}) - ifIndex: {} ... ", Id, ifIndex);
	setGlobalIoService(ifIndex, &getGlobalIoService());
}

void InputThread::run()
{
	getGlobalIoService().run();
}
#endif

} // namespace nfd
