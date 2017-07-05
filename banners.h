/*
	Author:		Steven Bremner
	Date:		June 3, 2014

	Description:
		All of the banners used by the opthandler in main.cpp
*/

#ifndef BANNERS_H
	#define BANNERS_H

#include "includes.h"

inline void printbanner()
{
	printf("%s%-10s%s%-10s%s%-10s%s%s",
		"-------------------------\n\n",
		"Author:", "Steven Bremner\n",
		"Date:", "June 3, 2014\n",
		"\nThanks for using the BIG nslookup tool from SteveInternals!\n"
	);

}

inline void printexamples(std::string execPath)
{
	printf("Examples:\n\n");

	//Example 1
	printf(" Performs BigNSL on the single IP specified\n");
	printf("\t%s 10.248.17.71\n\n", execPath.c_str());

	//Example 2
	printf(" Perform BigNSL on all domains in the input file\n");
	printf("\t%s -f \"infile.txt\" -o \"outfile.txt\"\n\n", execPath.c_str());

	//Example 3
	printf(" Perform BigNSL on all IPs in the provided CIDR IP Range and print to screen\n");
	printf("\t%s --range 10.248.17.0/24 --print\n\n", execPath.c_str());
}

inline void printusage(std::string execPath)
{
	printf("\nUsage for %s:\n\n", execPath.c_str());
	printf(" %-24s\t%s\n\n", "-n, -N, --nslookup <IP Addr | domain>", "performs nslookup (must be last arg - don't use print)");
	printf(" %-24s\t%s\n\n", "-f,-F,--file <file>", "input file to be parsed");
	printf(" %-24s\t%s\n\n", "-r,-R,--range <IP Range>", "CIDR Notated IP Range to be used for lookup");
	printf(" %-24s\t%s\n\n", "-o,-O,--output <file>", "specifies output file to write results");
	printf(" %-24s\t%s\n\n", "-p,-P,--print", "prints the results to the screen (must be last arg)");
	printf(" %-24s\t%s\n\n", "-h,-H,--help", "prints the usage or help page");

	printexamples(execPath);

	printbanner();
}

#endif