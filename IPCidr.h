/*
	Author:		Steven Bremner
	Date:		June 3, 2014

	Description:
		Library for parsing IP addr from CIDR to IP + mask
*/

#ifndef IPCIDR_H
	#define IPCIDR_H

#include "includes.h"

typedef struct _IPCidr{
	unsigned int IPaddr;
	unsigned int range;

	_IPCidr() : IPaddr(0), range(0) { }

	inline bool InRange(unsigned int _ip) {
		unsigned int netmask = ~(~(unsigned int(0)) >> range);

		return (_ip & netmask) == (IPaddr & netmask);
	}

} IPCidr;

std::string IntIPToString(unsigned int _ip)
{
	//xxx.xxx.xxx.xxx\0 (max shuold be 16 characters including null)
	char buf[256];
	sprintf(buf, "%u.%u.%u.%u", (_ip >> 24) & 0xFF, (_ip >> 16) & 0xFF, (_ip >> 8) & 0xFF, _ip & 0xFF);

	return std::string(buf);
}

IPCidr getCIDR(std::string _cidrStr)
{
	IPCidr _cidr;
	unsigned int octet[4];

	if(sscanf(_cidrStr.c_str(), "%d.%d.%d.%d/%d", &octet[0], &octet[1], &octet[2], &octet[3], &_cidr.range) != 5)
	{
		//we didn't scan all 5... must have a scanning error
		#ifdef DEBUG
			printf("[DEBUG] :: %s", "Error - CIDR notation was provided incorrectly");
		#endif

		exit(-1);
	}

	//Put the IP octets into the int
	_cidr.IPaddr |= (octet[0] << 24);
	_cidr.IPaddr |= (octet[1] << 16);
	_cidr.IPaddr |= (octet[2] << 8);
	_cidr.IPaddr |= octet[3];

	if(_cidr.range < 0 || _cidr.range > 31)
	{
		return _IPCidr(); //just return an empty CIDR IP if the input is bad
	}

	return _cidr; //this is the address we built
}


#endif