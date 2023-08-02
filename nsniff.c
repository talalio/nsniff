/*
 * nsniff.c
 */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>

int link_hdr_length = 0;

void call_me(u_char *user, const struct pcap_pkthdr *pkthdr,
             const u_char *packetd_ptr) {
  packetd_ptr += link_hdr_length;
  struct ip *ip_hdr = (struct ip *)packetd_ptr;

  char *packet_srcip = inet_ntoa(ip_hdr->ip_src);
  char *packet_dstip = inet_ntoa(ip_hdr->ip_dst);
  int packet_id = ntohs(ip_hdr->ip_id), packet_ttl = ip_hdr->ip_ttl,
      packet_tos = ip_hdr->ip_tos, packet_len = ntohs(ip_hdr->ip_len),
      packet_hlen = ip_hdr->ip_hl;

  printf("************************************"
         "**************************************\n");
  printf("ID: %d | SRC: %s | DST: %s | TOS: 0x%x | TTL: %d\n", packet_id,
         packet_srcip, packet_dstip, packet_tos, packet_ttl);

  packetd_ptr += (4 * packet_hlen);
  int protocol_type = ip_hdr->ip_p;

  struct tcphdr *tcp_header;
  struct udphdr *udp_header;
  struct icmp *icmp_header;
  int src_port, dst_port;

  switch (protocol_type) {
  case IPPROTO_TCP:
    tcp_header = (struct tcphdr *)packetd_ptr;
    src_port = tcp_header->th_sport;
    dst_port = tcp_header->th_dport;
    printf("PROTO: TCP | FLAGS: %c/%c/%c | SPORT: %d | DPORT: %d |\n",
           (tcp_header->th_flags & TH_SYN ? 'S' : '-'),
           (tcp_header->th_flags & TH_ACK ? 'A' : '-'),
           (tcp_header->th_flags & TH_URG ? 'U' : '-'), src_port, dst_port);
    break;
  case IPPROTO_UDP:
    udp_header = (struct udphdr *)packetd_ptr;
    src_port = udp_header->uh_sport;
    dst_port = udp_header->uh_dport;
    printf("PROTO: UDP | SPORT: %d | DPORT: %d |\n", src_port, dst_port);
    break;
  case IPPROTO_ICMP:
    icmp_header = (struct icmp *)packetd_ptr;
    int icmp_type = icmp_header->icmp_type;
    int icmp_type_code = icmp_header->icmp_code;
    printf("PROTO: ICMP | TYPE: %d | CODE: %d |\n", icmp_type, icmp_type_code);
    break;
  }
}

int main(int argc, char const *argv[]) {
  char *device = "enp0s3";
  char error_buffer[PCAP_ERRBUF_SIZE];
  int packets_count = 10;

  pcap_t *dev = pcap_open_live(device, BUFSIZ, 0, -1, error_buffer);

  if (dev == NULL) {
    printf("ERR: pcap_open_live() %s\n", error_buffer);
    exit(1);
  }

  struct bpf_program bpf;
  bpf_u_int32 netmask;

  char *filters = "host www.duckduckgo.com";

  if (pcap_compile(dev, &bpf, filters, 0, netmask) == PCAP_ERROR) {
    printf("ERR: pcap_compile() %s", pcap_geterr(dev));
  }

  if (pcap_setfilter(dev, &bpf)) {
    printf("ERR: pcap_setfilter() %s", pcap_geterr(dev));
  }

  int link_hdr_type = pcap_datalink(dev);

  switch (link_hdr_type) {
  case DLT_NULL:
    link_hdr_length = 4;
    break;
  case DLT_EN10MB:
    link_hdr_length = 14;
    break;
  default:
    link_hdr_length = 0;
  }

  if (pcap_loop(dev, packets_count, call_me, (u_char *)NULL)) {
    printf("ERR: pcap_loop() failed!\n");
    exit(1);
  }

  return 0;
}