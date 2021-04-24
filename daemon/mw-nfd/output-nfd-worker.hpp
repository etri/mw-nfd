
/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2021,  HII of ETRI,
 *
 * This file is part of MW-NFD (Named Data Networking Multi-Worker Forwarding Daemon).
 * See README.md for complete list of NFD authors and contributors.
 *
 * MW-NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * WM-NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef OUTPUT_NFD_WORKER_HPP
#define OUTPut_NFD_WORKER_HPP

#include <face/transport.hpp>
#include <face/link-service.hpp>
#include <face/generic-link-service.hpp>

namespace nfd {

/**
 * \brief Class representing the MW-NFD instance.
 *
 * This class is used to initialize all components of MW-NFD.
 */
class OutputWorkerThread : noncopyable
{
public:
	explicit OutputWorkerThread(int8_t wid);
	~OutputWorkerThread();
	void run();

private:
#ifndef ETRI_NFD_ORG_ARCH
 void terminate(const boost::system::error_code& error, int signalNo);
#endif

  int8_t m_workerId;
  	bool m_done;
};

} // namespace nfd

#endif 
