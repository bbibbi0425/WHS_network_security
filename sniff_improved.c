#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

#include "myheader.h"
#include <ctype.h>

#include <ctype.h>
#include <stdio.h>

void extract_readable_strings(const u_char *payload, int len) {
    printf("Extracted ASCII strings (length ≥ 5):\n");

    int i = 0;
    while (i < len) {
        // 시작 위치 저장
        int start = i;

        // 연속된 출력 가능한 문자 찾기
        while (i < len && isprint(payload[i])) {
            i++;
        }

        int str_len = i - start;

        // 문자열 길이 기준 필터 (5자 이상만 출력)
        if (str_len >= 5) {
            printf("  → ");
            for (int j = start; j < i; j++) {
                printf("%c", payload[j]);
            }
            printf("\n");
        }

        // 다음 문자로 이동
        i++;
    }
}


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    if (header->caplen < sizeof(struct ethheader)) {
        printf("[!] Packet too short for Ethernet header\n");
        return;
    }

    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) != 0x0800) {
        printf("[!] Not an IP packet. Skipping...\n");
        return;
    }

    if (header->caplen < sizeof(struct ethheader) + sizeof(struct ipheader)) {
        printf("[!] Packet too short for IP header\n");
        return;
    }

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    int ip_header_len = ip->iph_ihl * 4;

    if (header->caplen < sizeof(struct ethheader) + ip_header_len) {
        printf("[!] IP header length exceeds captured packet length\n");
        return;
    }

    printf("Ethernet src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("Ethernet dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    printf("From: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("To  : %s\n", inet_ntoa(ip->iph_destip));

    if (ip->iph_protocol == IPPROTO_TCP) {
        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

        int tcp_header_len = TH_OFF(tcp) * 4;
        int total_header_len = sizeof(struct ethheader) + ip_header_len + tcp_header_len;

        if (header->caplen < total_header_len) {
            printf("[!] Incomplete TCP header. Skipping...\n");
            return;
        }

        printf("TCP src port: %d\n", ntohs(tcp->tcp_sport));
        printf("TCP dst port: %d\n", ntohs(tcp->tcp_dport));

        int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;
        const u_char *payload = packet + total_header_len;

	// 문자열 추출 함수 호출
	extract_readable_strings(payload, payload_len);	

        if (payload_len > 0 && header->caplen >= total_header_len + payload_len) {
            printf("Payload (%d bytes): \n", payload_len);
            for (int i = 0; i < payload_len && i < 200; i++) {
                printf("%c", payload[i]);
            }
            printf("\n");
        } else {
            printf("No payload or insufficient packet length.\n");
        }
    }

    printf("==============================================\n");
}


int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name ens160
  handle = pcap_open_live("ens160", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}


