
#include <chrono>
#include <thread>
#include <memory>

#include "outgoing-nfd-worker.hpp"
#include "mw-nfd-global.hpp"
#include "common/logger.hpp"
#include "face/face.hpp"

#include <sys/types.h> 
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/fcntl.h>

#include <ostream>
#include <iostream>

using namespace std;

NFD_LOG_INIT(OutgoingMwNfd);

namespace nfd {

extern shared_ptr<FaceTable> g_faceTable;

OutgoingMwNfd::OutgoingMwNfd(int8_t wid)
  : m_workerId(wid)
    ,m_done(false)
	{
	//	m_terminationSignalSet.add(SIGINT);
	//	m_terminationSignalSet.add(SIGTERM);

	}

OutgoingMwNfd::~OutgoingMwNfd() = default;

#ifndef ETRI_NFD_ORG_ARCH

void OutgoingMwNfd::terminate(const boost::system::error_code& error, int signalNo)
{
    m_done=true;
}
#endif
void OutgoingMwNfd::runOutgoingWorker()
{
	//NDN_OUT_MSG msg;

	NDN_OUT_MSG items[DEQUEUE_BULK_MAX];
	int deq=0, idx;
	Face *face;

	do{

		deq = nfd::g_dcnMoodyOutMQ[m_workerId]->try_dequeue_bulk(items, DEQUEUE_BULK_MAX-1); // for Data
		for(idx=0;idx<deq;idx++){
			face = g_faceTable->get(items[idx].face);
			if(face){
				std::cout << "OutgoingFace: " << face->getId() << std::endl;
				face->sendInterest(*items[idx].interest);
			}
	    }

	}while(!m_done);

}

} // namespace nfd
