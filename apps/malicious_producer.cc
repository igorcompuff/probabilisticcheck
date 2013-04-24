/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2011 University of California, Los Angeles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Ilya Moiseenko <iliamo@cs.ucla.edu>
 *         Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "malicious_producer.h"
#include "ns3/log.h"
#include "ns3/ndn-interest.h"
#include "ns3/ndn-content-object.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"

#include "ns3/ndn-app-face.h"
#include "ns3/ndn-fib.h"

#include "ns3/ndnSIM/utils/ndn-fw-hop-count-tag.h"

#include <boost/ref.hpp>
#include <boost/lambda/lambda.hpp>
#include <boost/lambda/bind.hpp>
namespace ll = boost::lambda;

NS_LOG_COMPONENT_DEFINE ("ndn.MaliciousProducer");

namespace ns3 {
namespace ndn {

NS_OBJECT_ENSURE_REGISTERED (MaliciousProducer);
    
TypeId
MaliciousProducer::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::ndn::MaliciousProducer")
    .SetGroupName ("Ndn")
    .SetParent<App> ()
    .AddConstructor<MaliciousProducer> ()
    .AddAttribute ("PayloadSize", "Virtual payload size for Content packets",
                   UintegerValue (1024),
                   MakeUintegerAccessor(&MaliciousProducer::m_virtualPayloadSize),
                   MakeUintegerChecker<uint32_t>())
    .AddAttribute ("Freshness", "Freshness of data packets, if 0, then unlimited freshness",
                   TimeValue (Seconds (0)),
                   MakeTimeAccessor (&MaliciousProducer::m_freshness),
                   MakeTimeChecker ())
    ;
        
  return tid;
}
    
MaliciousProducer::MaliciousProducer ()
{
  // NS_LOG_FUNCTION_NOARGS ();
}

// inherited from Application base class.
void
MaliciousProducer::StartApplication ()
{
  NS_LOG_FUNCTION_NOARGS ();
  NS_ASSERT (GetNode ()->GetObject<Fib> () != 0);

  App::StartApplication ();

  NS_LOG_DEBUG ("NodeID: " << GetNode ()->GetId ());
  
  Ptr<ndn::Fib> fib = GetNode()->GetObject<ndn::Fib>();
  Ptr<ndn::fib::Entry> fibEntry = fib->Add("/", m_face, 0);
  fibEntry->UpdateStatus(m_face, ndn::fib::FaceMetric::NDN_FIB_GREEN);
}

void
MaliciousProducer::StopApplication ()
{
  NS_LOG_FUNCTION_NOARGS ();
  NS_ASSERT (GetNode ()->GetObject<Fib> () != 0);

  App::StopApplication ();
}


void
MaliciousProducer::OnInterest (const Ptr<const InterestHeader> &interest, Ptr<Packet> origPacket)
{
  App::OnInterest (interest, origPacket); // tracing inside

  NS_LOG_FUNCTION (this << interest);

  if (!m_active) return;
    
  static ContentObjectTail tail;
  Ptr<ContentObjectHeader> header = Create<ContentObjectHeader> ();
  header->SetName (Create<NameComponents> (interest->GetName ()));
  header->SetFreshness (m_freshness);
  header->Corrupt();

  NS_LOG_INFO ("node("<< GetNode()->GetId() <<") respodning with ContentObject:\n" << boost::cref(*header));
  
  Ptr<Packet> packet = Create<Packet> (m_virtualPayloadSize);
  
  packet->AddHeader (*header);
  packet->AddTrailer (tail);

  // Echo back FwHopCountTag if exists
  FwHopCountTag hopCountTag;
  if (origPacket->RemovePacketTag (hopCountTag))
    {
      packet->AddPacketTag (hopCountTag);
    }

  m_protocolHandler (packet);
  
  m_transmittedContentObjects (header, packet, this, m_face);
}

} // namespace ndn
} // namespace ns3
