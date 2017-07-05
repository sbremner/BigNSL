/*
	Author:		Steven Bremner
	Date:		June 3, 2014

	Description:
		Library for perform nslookup commands
*/

#ifndef NSL_H
	#define NSL_H

#include "includes.h"
#include "IPCidr.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <vector>

// link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

static void initWSA(void)
{
	#ifdef _WIN32
		WSADATA data;
		if (WSAStartup (MAKEWORD(1, 1), &data) != 0)
		{
			fputs ("Could not initialise Winsock.\n", stderr);
			exit (1);
		}
	#endif
}

static void uninitWSA (void)
{
	#ifdef _WIN32
		WSACleanup ();
	#endif
}

std::string getHostFromIP(unsigned int _ip)
{
	DWORD dwRetval;

    struct sockaddr_in saGNI;
    char hostname[NI_MAXHOST];
    char servInfo[NI_MAXSERV];
    u_short port = 27015;

	saGNI.sin_family = AF_INET;
	saGNI.sin_addr.s_addr = inet_addr(IntIPToString(_ip).c_str());
    saGNI.sin_port = htons(port);

	// Call getnameinfo
    dwRetval = getnameinfo((struct sockaddr *) &saGNI,
                           sizeof (struct sockaddr),
                           hostname,
                           NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);

	if(dwRetval != 0)
	{
		//failed
		return std::string("Error:").append(IntIPToString(_ip));
	}
	else
	{
		return std::string(hostname);
	}
}

std::string getHostFromIP(std::string _ip)
{
	DWORD dwRetval;

    struct sockaddr_in saGNI;
    char hostname[NI_MAXHOST];
    char servInfo[NI_MAXSERV];
    u_short port = 27015;

	saGNI.sin_family = AF_INET;
	saGNI.sin_addr.s_addr = inet_addr(_ip.c_str());
    saGNI.sin_port = htons(port);

	// Call getnameinfo
    dwRetval = getnameinfo((struct sockaddr *) &saGNI,
                           sizeof (struct sockaddr),
                           hostname,
                           NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);

	if(dwRetval != 0)
	{
		//failed
		return "";
	}
	else
	{
		return std::string(hostname);
	}
}

std::vector<std::string> getIPsFromHost(std::string hostname)
{
	std::vector<std::string> hostIPs;

	hostent * record = gethostbyname(hostname.c_str());

	if(record == NULL)
	{
		DWORD dwError = WSAGetLastError();

        if (dwError != 0) {
            if (dwError == WSAHOST_NOT_FOUND) {
                printf("Host not found\n");
            } else if (dwError == WSANO_DATA) {
                printf("No data record found\n");
            } else {
                printf("Function failed with error: %ld\n", dwError);
            }
        }
		
		return hostIPs; //no valid record
	}

	in_addr * address = (in_addr * )record->h_addr_list[0];

	//First found
	//printf("found @ %s\n", inet_ntoa(*address));
	hostIPs.push_back(std::string(inet_ntoa(*address)));

	//There could be many ip address
	//NOTE: We should factor in for multiple addresses later
	for(int k = 1; record->h_addr_list[k] != NULL; k++)
	{
		//printf(" Alt[%d] :: %s\n", k, inet_ntoa(*((in_addr * )record->h_addr_list[k])));
		hostIPs.push_back(std::string(inet_ntoa(*((in_addr * )record->h_addr_list[k]))));
	}

	return hostIPs;
}

bool validateIpAddress(const std::string &ipAddress)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress.c_str(), &(sa.sin_addr));
    return result != 0;
}

#endif