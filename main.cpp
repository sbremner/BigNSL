/*
	Author:		Steven Bremner
	Date:		April 23, 2014

	Description:
		A tool for performing nslookup command (DNS requests) on a large
        input set of data.
*/

#include "includes.h"

#include "argopts.h" //custom arg parsing library
#include "banners.h" //used by opthandler function
#include "IPCidr.h"
#include "NSL.h"

#include <regex>
#include <vector>

//All the possible variables required to be stored from the opts
FILE * iFile = NULL;
FILE * oFile = NULL;
IPCidr cidrRange;
std::string lookupStr = "";
std::string range = "";
int * captureGroups = NULL;
int groupCount = 0;

//unsigned int captureGroup = 0;

//flag selected (default false)
bool countflag = false, printflag = false, uniqueoutput = false;

void cleanup(void)
{
	if(iFile != NULL){
		fclose(iFile);
	}

	if(oFile != NULL){
		fclose(oFile);
	}
}

void opthandler(OPTIONS opts)
{
	//Used for looping through the params below
	PARAM p;

	//Loop 
	while((p = opts.nextarg()) != INVALID_PARAM)
	{
		std::string flag = p.getflag();

		if(flag == "-h" || flag == "-H" || flag == "--help")
		{
			printusage(opts.execPath);
			exit(-1); //if help flag is toggled we won't actually do anything else
		}
		else if(flag == "-n" || flag == "-N" || flag == "--nslookup")
		{
			//Requires data: <IP Addr | domain>
			lookupStr = p.getdata();
			assert(lookupStr != "");
		}
		else if(flag == "-f" || flag == "-F" || flag == "--file")
		{
			//Requires data: <file>
			std::string data = p.getdata();
			assert(data != "");

			iFile = fopen(data.c_str(), "r");

			assert(iFile != NULL);
		}
		else if(flag == "-r" || flag == "-R" || flag == "--range")
		{
			//Requires data: <CIDR Range>
			range = p.getdata();
			assert(range != "");
			
			cidrRange = getCIDR(range);
			assert(cidrRange.IPaddr != 0);
		}
		else if(flag == "-o" || flag == "-O" || flag == "--output")
		{
			//Requires data: <file>
			std::string data = p.getdata();
			assert(data != "");

			oFile = fopen(data.c_str(), "w");
			assert(oFile != NULL);
		}
		else if(flag == "-p" || flag == "-P" || flag == "--print")
		{
			//prints the output to the screen
			printflag = true;
		}
	}

	#ifdef DEBUG
		printf("Finished handling opts\n");
	#endif

}

void optexec()
{
	printf("Beginning execution...\n\n");

	//Perform BigNSL on the CIDR Range inside here
	if(range != ""){
		
		initWSA(); //init the socket work
		
		unsigned int _ip = cidrRange.IPaddr;

		std::string hostname = "";

		do
		{
			hostname = getHostFromIP(IntIPToString(_ip));

			if(hostname != "")
			{
				if(printflag) fprintf(stdout, "%s,%s\n", IntIPToString(_ip).c_str(), hostname.c_str());
				if(oFile != NULL) fprintf(oFile, "%s,%s\n", IntIPToString(_ip).c_str(), hostname.c_str());
			}

		}while(cidrRange.InRange(++_ip));

		uninitWSA(); //cleanup the socket work
	}

	if(iFile != NULL)
	{
		unsigned int bufsz = 256;
		char * buf = (char *)malloc(sizeof(char) * bufsz);

		initWSA(); //init the socket work

		while(fgets(buf,bufsz, iFile) != NULL)
		{
			int len = strlen(buf);
			
			if(len == (bufsz - 1) && buf[bufsz - 2] != '\n')
			{
				//Need to resize if we are in here
				#ifdef DEBUG
					printf("DEBUG :: Need to resize from %d to %d\n", bufsz, bufsz*2);
				#endif

				bufsz *= 2; //double our buffer size;
				free(buf);
				buf = (char *)malloc(sizeof(char) * bufsz);
				
				//move our file pointer back and we will re-read the data
				fseek(iFile, -len, SEEK_CUR);
			}
			else
			{
				std::string data = std::string(buf);
				//remove the new line chars from the string (causes issues with gethostbyname)
				data.erase(std::remove(data.begin(), data.end(), '\n'), data.end());

				if(validateIpAddress(data)){
					std::string hostinfo = getHostFromIP(data);

					if(hostinfo != "")
					{
						if(printflag) fprintf(stdout, "%s,%s\n", data.c_str(), hostinfo.c_str());
						if(oFile != NULL) fprintf(oFile, "%s,%s\n", data.c_str(), hostinfo.c_str());
					}
				}
				else{
					std::vector<std::string> hosts = getIPsFromHost(data);

					for each(std::string h in hosts)
					{
						if(h != "")
						{
							if(printflag) fprintf(stdout, "%s,%s\n", data.c_str(), h.c_str());
							if(oFile != NULL) fprintf(oFile, "%s,%s\n", data.c_str(), h.c_str());
						}
					}
				}
			}
		}

		uninitWSA(); //cleanup the socket work
	}

	//Basic NSLookup here
	if(lookupStr != "")
	{
		initWSA(); //init the socket work

		//do a normal nslookup on the input string
		if(validateIpAddress(lookupStr)){
			std::string host = getHostFromIP(lookupStr);
			printf("Found: %s\n\n", host.c_str());
		}
		else{
			
			printf("Checking host [%s]... ", lookupStr.c_str());

			std::vector<std::string> hostList = getIPsFromHost(lookupStr);

			printf(" found %d valid IP addresses\n", hostList.size());

			for each(std::string h in hostList)
			{
				printf("%s,%s\n", lookupStr.c_str(), h.c_str());
			}
		}

		uninitWSA(); //cleanup the socket work
	}
}

int main(int argc, char * argv[])
{
	OPTIONS opts;

	atexit(cleanup);

	if(argc <= 1)
	{
		//no arguments provided... print usage
		printusage(std::string(argv[0]));
		return 0;
	}

	getargs(argc, argv, &opts);

	//printopts(opts);

	opthandler(opts);

	//this should execute the command (args should be populated in the opthandler function
	optexec();

	printbanner();

	return 0;
}