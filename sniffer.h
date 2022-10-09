#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap/pcap.h>

void processPacket(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void sniffToCli(int argc, char *argv[]);
void sniffToFile(int argc, char *argv[], char *path);

#endif