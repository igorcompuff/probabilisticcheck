#include "custom.h"
#include "ns3/ndn-fib.h"
#include "ns3/ndn-fib-entry.h"
#include "ns3/ndn-pit-entry.h"
#include "ns3/ndn-interest.h"
#include "ns3/ndn-content-object.h"
#include "ns3/string.h"
#include <boost/ref.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/lambda/lambda.hpp>
#include <boost/lambda/bind.hpp>
#include <cstdlib>
#include <ctime>

namespace ns3 {
namespace ndn {
namespace fw {

NS_OBJECT_ENSURE_REGISTERED(CustomFlooding);

LogComponent CustomFlooding::g_log = LogComponent (CustomFlooding::GetLogName ().c_str ());

std::string
CustomFlooding::GetLogName ()
{
	return "ndn.fw.CustomFlooding";
}

TypeId
CustomFlooding::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::ndn::fw::CustomFlooding")
		.SetGroupName ("Ndn")
		.SetParent <BaseStrategy> ()
		.AddConstructor <CustomFlooding> ()
		.AddAttribute ("Probability", "Probability of signature check",
		               StringValue ("1.0"),
		               MakeDoubleAccessor (&CustomFlooding::m_probability),
		               MakeDoubleChecker<double> ())
		;
	return tid;
}

CustomFlooding::CustomFlooding ():m_rand(0.0, 0.1)
{
	srand(time(NULL));
	Simulator::Schedule(GetRandomTime(), &CustomFlooding::sendInterests, this);
	Simulator::Schedule(GetRandomTime(), &CustomFlooding::sendContents, this);
}

int
CustomFlooding::GetFactor()
{
	return (int)(m_probability * RAND_MAX);
}

void
CustomFlooding::OnData (Ptr<Face> face,
						Ptr<const ContentObjectHeader> header,
						Ptr<Packet> payload,
						Ptr<const Packet> origPacket)
{
	Time timeout = Simulator::Now() + GetRandomTime();

	ContentObjectTimeOut objTimeout = {face,header,payload, origPacket, timeout};

	m_contentTimeoutset.insert(objTimeout);
}

void
CustomFlooding::OnInterest (Ptr<Face> inFace, Ptr<const InterestHeader> header, Ptr<const Packet> origPacket)
{
	Time timeout = Simulator::Now() + GetRandomTime();

	InterestTimeOut intTimeout = {inFace, header, origPacket, timeout};

	m_interestTimeoutset.insert(intTimeout);
}

Time
CustomFlooding::GetRandomTime()
{
	Time time = Time::FromDouble(m_rand.GetValue(), Time::MS);

	return time;
}

void
CustomFlooding::sendInterests()
{
	std::set<InterestTimeOut, InterestTimeOut>::iterator it;
	bool over = false;

	while (!m_interestTimeoutset.empty() && !over)
	{
		it = m_interestTimeoutset.begin();

		if (it->timeout <= Simulator::Now())
		{
					BaseStrategy::OnInterest(it->face, it->header, it->origPacket);
					m_interestTimeoutset.erase(it);
		}
		else
		{
			over = true;
		}
	}

	Simulator::Schedule(GetRandomTime(), &CustomFlooding::sendInterests, this);
}

void
CustomFlooding::sendContents()
{
	std::set<ContentObjectTimeOut, ContentObjectTimeOut>::iterator it;
	bool over = false;

	while (!m_contentTimeoutset.empty() && !over)
	{
		it = m_contentTimeoutset.begin();

		if (it->timeout <= Simulator::Now())
		{
			BaseStrategy::OnData(it->face, it->header, it->payload, it->origPacket);
			m_contentTimeoutset.erase(it);
		}
		else
		{
			over = true;
		}
	}

	Simulator::Schedule(GetRandomTime(), &CustomFlooding::sendContents, this);
}

bool CustomFlooding::CheckSignature (Ptr<const ContentObjectHeader> header)
{
	bool result = true;

	int p = rand();
	int k = GetFactor();

	if (p < k) // Pr[p < k] = Pr[0] + Pr[1] + ... + Pr[k-1] = k * 1/Rand_max;
	{
		result = !header->IsCorrupted();

		uint32_t seq = boost::lexical_cast<uint32_t>(header->GetName().GetComponents().back());

		NS_LOG_INFO("Checked: " << seq);
	}

	return result;
}

} // namespace fw
} // namespace ndn
} // namespace ns3
