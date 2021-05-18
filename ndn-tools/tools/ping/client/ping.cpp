/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2019,  Arizona Board of Regents.
 *
 * This file is part of ndn-tools (Named Data Networking Essential Tools).
 * See AUTHORS.md for complete list of ndn-tools authors and contributors.
 *
 * ndn-tools is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * ndn-tools is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ndn-tools, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author: Jerald Paul Abraham <jeraldabraham@email.arizona.edu>
 * @author: Eric Newberry <enewberry@email.arizona.edu>
 * @author: Teng Liang <philoliang@email.arizona.edu>
 */

#include "ping.hpp"
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/util/segment-fetcher.hpp>
#include <ndn-cxx/security/validator-config.hpp>
#include <ndn-cxx/security/validator-null.hpp>
#include <ndn-cxx/security/certificate-fetcher-direct-fetch.hpp>
#include "ndn-cxx/security/certificate-fetcher-offline.hpp"

namespace ndn {
namespace ping {
namespace client {

    class DummyValidationPolicy : public security::v2::ValidationPolicy
    {
        public:
              /** \brief constructor
               *    *  \param shouldAccept whether to accept or reject all validation requests
               *       */
              explicit
                    DummyValidationPolicy(bool shouldAccept = true)
                      {
                              this->setResult(shouldAccept);
                                }

                /** \brief change the validation result
                 *    *  \param shouldAccept whether to accept or reject all validation requests
                 *       */
                void
                      setResult(bool shouldAccept)
                        {
                                m_decide = [shouldAccept] (const Name&) { return shouldAccept; };
                                  }

                  /** \brief set a callback for validation
                   *    *  \param cb a callback which receives the Interest/Data name for each validation request;
                   *       *            its return value determines the validation result
                   *          */
                  void
                        setResultCallback(const function<bool(const Name&)>& cb) 
                          {
                                  m_decide = cb; 
                                    }

        protected:
                    void
                          checkPolicy(const Data& data, const shared_ptr<security::v2::ValidationState>& state,
                                                const ValidationContinuation& continueValidation) override
                            {
                                    if (m_decide(data.getName())) {
                                              continueValidation(nullptr, state);
                                                  }   
                                        else {
                                                  state->fail(security::v2::ValidationError::NO_ERROR);
                                                      }   
                                          }

                      void
                            checkPolicy(const Interest& interest, const shared_ptr<security::v2::ValidationState>& state,
                                                  const ValidationContinuation& continueValidation) override
                              {
                                      if (m_decide(interest.getName())) {
                                                continueValidation(nullptr, state);
                                                    }   
                                          else {
                                                    state->fail(security::v2::ValidationError::NO_ERROR);
                                                        }   
                                            }

        private:
                        function<bool(const Name&)> m_decide;
    };

    class DummyValidator : public security::v2::Validator
    {
        public:
              explicit
                    DummyValidator(bool shouldAccept = true)
                        : security::v2::Validator(make_unique<DummyValidationPolicy>(shouldAccept),
                                                              make_unique<security::v2::CertificateFetcherOffline>())
                            {
                                  }

                DummyValidationPolicy&
                      getPolicy()
                        {
                                return static_cast<DummyValidationPolicy&>(security::v2::Validator::getPolicy());
                                  }
    };


Ping::Ping(Face& face, const Options& options)
  : m_options(options)
  , m_nSent(0)
  , m_nextSeq(options.startSeq)
  , m_nOutstanding(0)
  , m_face(face)
  , m_scheduler(m_face.getIoService())
{
  if (m_options.shouldGenerateRandomSeq) {
    m_nextSeq = random::generateWord64();
  }
}

void
Ping::start()
{
  performPing();
}

void
Ping::stop()
{
  m_nextPingEvent.cancel();
}

 void
onError(uint32_t errorCode)
{
}

    void
onComplete(ConstBufferPtr data)
{
}

    void
onInOrderComplete()
{
}

    void
onInOrderData(ConstBufferPtr data)
{
}



static std::unique_ptr<ndn::security::CertificateFetcherDirectFetch>
makeCertificateFetcher(ndn::Face& face)
{
      auto fetcher = std::make_unique<ndn::security::CertificateFetcherDirectFetch>(face);
        fetcher->setSendDirectInterestOnly(true);
          return fetcher;
}


void
Ping::performPing()
{
  BOOST_ASSERT((m_options.nPings < 0) || (m_nSent < m_options.nPings));

  //Interest interest(makePingName(m_nextSeq));
  Interest interest("/dcn/etri/hii/%C1.Router/DCN-05/nfd/status");
  interest.setCanBePrefix(true);
  interest.setMustBeFresh(true);
  interest.setInterestLifetime(m_options.timeout);

#if 0
  auto now = time::steady_clock::now();
  m_nextSeq =0;
  m_face.expressInterest(interest,
                         bind(&Ping::onData, this, _2, m_nextSeq, now),
                         bind(&Ping::onNack, this, _2, m_nextSeq, now),
                         bind(&Ping::onTimeout, this, m_nextSeq));

#else
  ndn::util::SegmentFetcher::Options options;
     options.interestLifetime = ndn::time::seconds(4);
     ndn::security::v2::ValidatorNull acceptValidator;

     ndn::security::ValidatorConfig validator(makeCertificateFetcher(m_face));

     validator.load("./val.conf");

      auto fetcher = ndn::util::SegmentFetcher::start(m_face, interest, acceptValidator, options);


      fetcher->afterSegmentValidated.connect([this] (const ndn::Data& data) {
              std::cout << data << std::endl; 
              });

      fetcher->onComplete.connect([=] (const ndn::ConstBufferPtr& bufferPtr) {
              std::cout << bufferPtr << std::endl; 
              });

      fetcher->onError.connect([=] (uint32_t errorCode, const std::string& msg) {
              std::cout << "error Code:" << errorCode << ", msg: " << msg << std::endl; 
              exit(0);
              });

#endif

#if 0
  ++m_nextSeq;
  ++m_nOutstanding;

  if ((m_options.nPings < 0) || (m_nSent < m_options.nPings)) {
    m_nextPingEvent = m_scheduler.schedule(m_options.interval, [this] { performPing(); });
  }
  else {
    finish();
  }
#endif
}

void
Ping::onData(const Data &data, uint64_t seq, const time::steady_clock::TimePoint& sendTime)
{
    seq +=1;
  time::nanoseconds rtt = time::steady_clock::now() - sendTime;
  std::cout << data << std::endl;
  Name name("/dcn/etri/hii/%C1.Router/DCN-05/nfd/status");
  name.appendSegment(seq);
  Interest interest(name);
  interest.setCanBePrefix(true);
  interest.setMustBeFresh(true);
  interest.setInterestLifetime(m_options.timeout);


  auto now = time::steady_clock::now();
  m_face.expressInterest(interest,
          bind(&Ping::onData, this, _2, m_nextSeq, now),
          bind(&Ping::onNack, this, _2, m_nextSeq, now),
          bind(&Ping::onTimeout, this, m_nextSeq));

  //afterData(seq, rtt);
  //finish();
}

void
Ping::onNack(const lp::Nack& nack, uint64_t seq, const time::steady_clock::TimePoint& sendTime)
{
  time::nanoseconds rtt = time::steady_clock::now() - sendTime;
  afterNack(seq, rtt, nack.getHeader());
  finish();
}

void
Ping::onTimeout(uint64_t seq)
{
  afterTimeout(seq);
  finish();
}

void
Ping::finish()
{
  if (--m_nOutstanding >= 0) {
    return;
  }
  afterFinish();
}

Name
Ping::makePingName(uint64_t seq) const
{
  Name name(m_options.prefix);

  name.append("ping");
  if (!m_options.clientIdentifier.empty()) {
    name.append(m_options.clientIdentifier);
  }
  name.append(to_string(seq));

  return name;
}

} // namespace client
} // namespace ping
} // namespace ndn
