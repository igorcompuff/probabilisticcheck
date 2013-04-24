#ifndef CUSTOM_FLOODING_H
#define CUSTOM_FLOODING_H

#include "ns3/log.h"
#include "ns3/ndn-forwarding-strategy.h"
#include "ns3/ndn-l3-protocol.h"
#include "ns3/ndnSIM/model/fw/flooding.h"
#include "ns3/core-module.h"

#include <set>

namespace ns3 {
namespace ndn {
namespace fw {

typedef Flooding BaseStrategy;

struct ContentObjectTimeOut
{
	Ptr<Face> face;
	Ptr<const ContentObjectHeader> header;
	Ptr<Packet> payload;
	Ptr<const Packet> origPacket;
	Time timeout;

	bool operator () (const ContentObjectTimeOut& co1, const ContentObjectTimeOut& co2) const
	{
		return co1.timeout < co2.timeout;
	}
};

struct InterestTimeOut
{
	Ptr<Face> face;
	Ptr<const InterestHeader> header;
	Ptr<const Packet> origPacket;
	Time timeout;

	bool operator () (const InterestTimeOut& int1, const InterestTimeOut& int2) const
	{
		return int1.timeout < int2.timeout;
	}
};

class CustomFlooding: public BaseStrategy
{
	private:

	int GetFactor();
	Time GetRandomTime();

	std::set<ContentObjectTimeOut, ContentObjectTimeOut> m_contentTimeoutset;
	std::set<InterestTimeOut, InterestTimeOut> m_interestTimeoutset;
	UniformVariable m_rand;
	public:

	  static TypeId GetTypeId ();

	  static std::string GetLogName ();

	  virtual bool CheckSignature (Ptr<const ContentObjectHeader> header);

	  void sendInterests();
	  void sendContents();

	  //Constructor
	  CustomFlooding ();

	  // from ndn-forwarding-strategy
	  virtual void OnData (Ptr<Face> face, Ptr<const ContentObjectHeader> header, Ptr<Packet> payload,
			  	  	  	   Ptr<const Packet> origPacket);

	  virtual void OnInterest (Ptr<Face> inFace, Ptr<const InterestHeader> header, Ptr<const Packet> origPacket);

	protected:
	  static LogComponent g_log;
	  double m_probability;

};



} // namespace fw
} // namespace ndn
} // namespace ns3

#endif // CUSTOM_STRATEGY_H
