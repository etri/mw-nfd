
#include <chrono>
#include <thread>
#include <memory>

#include "output-nfd-worker.hpp"
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

NFD_LOG_INIT(OutputWorkerThread);

namespace nfd {

extern shared_ptr<FaceTable> g_faceTable;

OutputWorkerThread::OutputWorkerThread(int8_t wid)
  : m_workerId(wid)
    ,m_done(false)
	{
		NDN_LOG_INFO( m_workerId << " - OutputThread" );
	//	m_terminationSignalSet.add(SIGINT);
	//	m_terminationSignalSet.add(SIGTERM);

	}

OutputWorkerThread::~OutputWorkerThread() = default;

#ifndef ETRI_NFD_ORG_ARCH

void OutputWorkerThread::terminate(const boost::system::error_code& error, int signalNo)
{
    m_done=true;
}
#endif
void OutputWorkerThread::run()
{
	//NDN_OUT_MSG msg;

	NDN_OUT_MSG items[DEQUEUE_BULK_MAX];
	int deq=0, idx;
	Face *face;

	do{

		deq = nfd::g_dcnMoodyOutMQ[m_workerId]->try_dequeue_bulk(items, DEQUEUE_BULK_MAX-1);
		for(idx=0;idx<deq;idx++){
			face = g_faceTable->get(items[idx].face);
		//		std::cout << m_workerId << " - OutgoingFace: " <<std::endl;
			if(face){
				int  __attribute__((unused)) id = m_workerId;
		//		std::cout << "ID: " << id << "- OutgoingFace: " << face->getId() << ", Type: " << items[idx].type << ", cpu: " << sched_getcpu() << std::endl ;
				if(items[idx].type==0x05){
					face->sendInterest(*items[idx].interest);
				}else if(items[idx].type==0x06){
					face->sendData(*items[idx].data);
				}else if(items[idx].type==800){
					face->sendNack(*items[idx].nack);
				}
			}
	    }

	}while(!m_done);

}

} // namespace nfd
