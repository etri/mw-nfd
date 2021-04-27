/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2019,  Regents of the University of California,
 *                           Arizona Board of Regents,
 *                           Colorado State University,
 *                           University Pierre & Marie Curie, Sorbonne University,
 *                           Washington University in St. Louis,
 *                           Beijing Institute of Technology,
 *                           The University of Memphis.
 *
 * This file is part of NFD (Named Data Networking Forwarding Daemon).
 * See AUTHORS.md for complete list of NFD authors and contributors.
 *
 * NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "cs.hpp"
#include "common/logger.hpp"
#include "core/algorithm.hpp"
#include "fw/forwarder.hpp"
#include "mw-nfd/mw-nfd-global.hpp"

#include <ndn-cxx/lp/tags.hpp>
#include <ndn-cxx/util/concepts.hpp>
#include <ndn-cxx/lp/pit-token.hpp>

namespace nfd {
namespace cs {

NFD_LOG_INIT(ContentStore);

static unique_ptr<Policy>
makeDefaultPolicy()
{
  return Policy::create("lru");
}

Cs::Cs(size_t nMaxPackets)
{
  setPolicyImpl(makeDefaultPolicy());
  m_policy->setLimit(nMaxPackets);
}

void
Cs::insert(const Data& data, bool isUnsolicited)
{
  if (!m_shouldAdmit || m_policy->getLimit() == 0) {
    return;
  }
  NFD_LOG_DEBUG("insert " << data.getName());

  // recognize CachePolicy
  shared_ptr<lp::CachePolicyTag> tag = data.getTag<lp::CachePolicyTag>();
  if (tag != nullptr) {
    lp::CachePolicyType policy = tag->get().getPolicy();
    if (policy == lp::CachePolicyType::NO_CACHE) {
      return;
    }
  }

#ifndef ETRI_DUAL_CS
	const_iterator it;
  bool isNewEntry = false;
	std::tie(it, isNewEntry) = m_table.emplace(data.shared_from_this(), isUnsolicited);
	Entry& entry = const_cast<Entry&>(*it);

	entry.updateFreshUntil();

	if (!isNewEntry) { // existing entry
		// XXX This doesn't forbid unsolicited Data from refreshing a solicited entry.
		if (entry.isUnsolicited() && !isUnsolicited) {
			entry.clearUnsolicited();
		}
		m_policy->afterRefresh(it);
		NFD_LOG_DEBUG("insert -> afterRefresh" );
	}
	else {
		m_policy->afterInsert(it);
		NFD_LOG_DEBUG("insert -> afterInsert" );
	}

#else
	bool isCanBePrefix = 1;
	auto token = data.getTag<lp::PitToken>();
	if(token!=nullptr){
		ST_PIT_TOKEN  *pitToken = (ST_PIT_TOKEN *)token->data();
		isCanBePrefix = pitToken->CanBePrefix;
	}else {
		NFD_LOG_DEBUG("PitToken is NULL");
	}

  bool isNewEntry = false;
	if(isCanBePrefix) {
	  NFD_LOG_DEBUG("insert -> m_table" );
  	const_iterator it;
	  std::tie(it, isNewEntry) = m_table.emplace(data.shared_from_this(), isUnsolicited);
  	Entry& entry = const_cast<Entry&>(*it);
		entry.updateFreshUntil();

		if (!isNewEntry) { // existing entry
			// XXX This doesn't forbid unsolicited Data from refreshing a solicited entry.
			if (entry.isUnsolicited() && !isUnsolicited) {
				entry.clearUnsolicited();
			}
			m_policy->afterRefresh(it);
		}
		else {
			m_policy->afterInsert(it);
			//NFD_LOG_DEBUG("insert -> afterInsert" );
		}
	} else {
	  NFD_LOG_DEBUG("insert -> m_tableExact" );
  	const_iterator_exact it;
  	Entry entry(data.shared_from_this(), isUnsolicited);
	  std::tie(it, isNewEntry) = m_tableExact.emplace(std::make_pair(data.getName(), entry));
		entry.updateFreshUntil();

		if (!isNewEntry) { // existing entry
			// XXX This doesn't forbid unsolicited Data from refreshing a solicited entry.
			if (entry.isUnsolicited() && !isUnsolicited) {
				entry.clearUnsolicited();
			}
  		m_policy->beforeEraseExact(it);
			m_tableExact.erase(it);
	  	std::tie(it, isNewEntry) = m_tableExact.emplace(std::make_pair(data.getName(), entry));
			m_policy->afterInsertExact(it);
			NFD_LOG_DEBUG("replace -> afterInsert" );
		}
		else {
			m_policy->afterInsertExact(it);
			NFD_LOG_DEBUG("insert -> afterInsert" );
		}
	}
#endif

}

#ifdef ETRI_DUAL_CS
Cs::const_iterator_exact
Cs::findExactMatch(const std::shared_ptr<Data>& data) const
{
  auto const_iter = m_tableExact.find(data->getName());
  return const_iter;
}

Cs::const_iterator_exact
Cs::findExactMatch(const Name& name) const
{
  NFD_LOG_DEBUG("findExactMatch " << name);
  auto const_iter = m_tableExact.find(name);
  return const_iter;
}

Cs::const_iterator_exact
Cs::findImplExact(const Interest& interest) const
{
  NFD_LOG_DEBUG("findImplExact interest name = " << interest.getName());

  if (!m_shouldServe || m_policy->getLimit() == 0) {
    return m_tableExact.end();
  }

	const Name& interestName =interest.getName();

	if(interestName.get(-1).isImplicitSha256Digest()) {
		const Name& prefix = interestName.getPrefix(-1);
  	NFD_LOG_DEBUG("findImplExact find name = " << prefix);
		auto match = m_tableExact.find(prefix);

		if (match == m_tableExact.end()) {
			NFD_LOG_DEBUG("findImplExact " << interest.getName() << " no-match");
			return m_tableExact.end();
		}
  	if (interest.getMustBeFresh() && !match->second.isFresh()) {
			NFD_LOG_DEBUG("findImplExact " << interest.getName() << " MustBeFresh");
			return m_tableExact.end();
		}
		NFD_LOG_DEBUG("findImplExact " << interest.getName() << " matching ");
		m_policy->beforeUseExact(match);
		return match;
	} else {

		auto match = m_tableExact.find(interest.getName());

		if (match == m_tableExact.end()) {
			NFD_LOG_DEBUG("findImplExact " << interest.getName() << " no-match");
			return m_tableExact.end();
		}
  	if (interest.getMustBeFresh() && !match->second.isFresh()) {
			NFD_LOG_DEBUG("findImplExact " << interest.getName() << " MustBeFresh");
			return m_tableExact.end();
		}
		NFD_LOG_DEBUG("findImplExact " << interest.getName() << " matching ");
		m_policy->beforeUseExact(match);
		return match;
	}
}

size_t
Cs::eraseImplExact(const Name& exact, size_t limit)
{
  NFD_LOG_DEBUG("eraseImplExact: name " << exact << " " );
  auto match = findExactMatch(exact);

  if (match == m_tableExact.end()) {
    NFD_LOG_DEBUG("eraseImplExact: find " << exact << " no-match");
    return 0;
  }

  m_policy->beforeEraseExact(match);
  m_tableExact.erase(match);

  return 1;
}
#endif

std::pair<Cs::const_iterator, Cs::const_iterator>
Cs::findPrefixRange(const Name& prefix) const
{
  auto first = m_table.lower_bound(prefix);
  auto last = m_table.end();
  if (prefix.size() > 0) {
    last = m_table.lower_bound(prefix.getSuccessor());
  }
  return {first, last};
}

size_t
Cs::eraseImpl(const Name& prefix, size_t limit)
{
  NFD_LOG_DEBUG("eraseImpl: prefix " << prefix << " " );
  const_iterator i, last;
  std::tie(i, last) = findPrefixRange(prefix);

  size_t nErased = 0;
  while (i != last && nErased < limit) {
    m_policy->beforeErase(i);
    i = m_table.erase(i);
    ++nErased;
  }
  return nErased;
}

Cs::const_iterator
Cs::findImpl(const Interest& interest) const
{
  NFD_LOG_DEBUG("findImpl interest name = " << interest.getName() << "start. ");

  if (!m_shouldServe || m_policy->getLimit() == 0) {
    return m_table.end();
  }

  const Name& prefix = interest.getName();
  auto range = findPrefixRange(prefix);
  auto match = std::find_if(range.first, range.second,
                            [&interest] (const auto& entry) { return entry.canSatisfy(interest); });

  if (match == range.second) {
    NFD_LOG_DEBUG("find " << prefix << " no-match");
    return m_table.end();
  }
  NFD_LOG_DEBUG("find " << prefix << " matching " << match->getName());
  m_policy->beforeUse(match);
  return match;
}

void
Cs::dump()
{
  NFD_LOG_DEBUG("dump table");
  for (const Entry& entry : m_table) {
    NFD_LOG_TRACE(entry.getFullName());
  }
}

void
Cs::setPolicy(unique_ptr<Policy> policy)
{
  BOOST_ASSERT(policy != nullptr);
  BOOST_ASSERT(m_policy != nullptr);
  size_t limit = m_policy->getLimit();
  this->setPolicyImpl(std::move(policy));
  m_policy->setLimit(limit);
}

void
Cs::setPolicyImpl(unique_ptr<Policy> policy)
{
  NFD_LOG_DEBUG("set-policy " << policy->getName());
  m_policy = std::move(policy);
  m_beforeEvictConnection = m_policy->beforeEvict.connect([this] (auto it) { m_table.erase(it); });
#ifdef ETRI_DUAL_CS
  m_beforeEvictExactConnection = m_policy->beforeEvictExact.connect([this] (auto it) { m_tableExact.erase(it); });
#endif

  m_policy->setCs(this);
  BOOST_ASSERT(m_policy->getCs() == this);
}

void
Cs::enableAdmit(bool shouldAdmit)
{
  if (m_shouldAdmit == shouldAdmit) {
    return;
  }
  m_shouldAdmit = shouldAdmit;
  NFD_LOG_INFO((shouldAdmit ? "Enabling" : "Disabling") << " Data admittance");
}

void
Cs::enableServe(bool shouldServe)
{
  if (m_shouldServe == shouldServe) {
    return;
  }
  m_shouldServe = shouldServe;
  NFD_LOG_INFO((shouldServe ? "Enabling" : "Disabling") << " Data serving");
}

} // namespace cs
} // namespace nfd
