#include <cstdint>

#include <pcap.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "decode.h"

decode *D;
FILE *f_out;
unsigned long long counter;
size_t pkt_size;
u_char* out_pkt;

struct vlan_header {
  uint16_t vlan_tci;
  uint16_t eth_proto;
};

void itoip(int32_t *ip, int8_t *bytes) {
  bytes[3] = (*ip) & 0xFF;
  bytes[2] = ((*ip) >> 8) & 0xFF;
  bytes[1] = ((*ip) >> 16) & 0xFF;
  bytes[0] = ((*ip) >> 24) & 0xFF;
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  struct ether_header *eth;
  struct vlan_header *vlan1, *vlan2;
  struct ip *ip;
  struct tcphdr *tcp;

  bool has_path = false;
  int32_t saddr, daddr;
  int8_t sbytes[4], dbytes[4];
  int16_t vlan_tags[2];
  int8_t vlan_len = 0;
  int32_t path_vec[6] = { -1, -1, -1, -1, -1, -1};

  int ip_start = 14;  // IP header starts at offset 14 into the packet

  eth = (struct ether_header*) packet;
  if (ntohs(eth->ether_type) == ETHERTYPE_VLAN) {
    has_path = true;
    vlan1 = (struct vlan_header*) (packet + sizeof(struct ether_header));
    vlan_tags[vlan_len++] = vlan1->vlan_tci;
    ip_start += sizeof(struct vlan_header);

    if (ntohs(vlan1->eth_proto) == ETHERTYPE_VLAN) {
      vlan2 = vlan1 + 1;
      vlan_tags[vlan_len++] = vlan2->vlan_tci;
      ip_start += sizeof(struct vlan_header);
    }

    if (ntohs(vlan1->eth_proto) != ETHERTYPE_IP) {
      fprintf(stderr, "!!! Not an IP packet !!!\n");
      return;
    }
  } else if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
    fprintf(stderr, "!!! Unknown ether_type, no VLAN tags !!!\n");
    return;
  }
  eth->ether_type = ETHERTYPE_IP;

  ip = (struct ip*) (packet + ip_start);
  ip->ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + 6 * sizeof(int32_t);

  if (ip->ip_p != IPPROTO_TCP) {
    fprintf(stderr, "!!! Not a tcp packet !!!\n");
    return;
  }

  tcp = (struct tcphdr*) (packet + ip_start + 20);

  if (has_path) {
    saddr = ip->ip_src.s_addr;
    saddr = ntohl(saddr);
    daddr = ip->ip_dst.s_addr;
    daddr = ntohl(daddr);
    itoip(&saddr, sbytes);
    itoip(&daddr, dbytes);

    list<int32_t> path;
    D->decode_path(vlan_tags, vlan_len, sbytes, dbytes, &path);

    typedef list<int32_t>::iterator list_it;
    size_t pos = 0;
    for (list_it it = path.begin(); it != path.end(); it++)
      path_vec[pos++] = *it;
  }

  // Create new packet
  memcpy(out_pkt, eth, sizeof(struct ether_header));
  memcpy(out_pkt + sizeof(struct ether_header), ip, sizeof(struct ip));
  memcpy(out_pkt + sizeof(struct ether_header) + sizeof(struct ip), tcp,
         sizeof(struct tcphdr));
  memcpy(out_pkt + sizeof(struct ether_header) + sizeof(struct ip)
         + sizeof(struct tcphdr), path_vec, 6 * sizeof(int32_t));

  fwrite(out_pkt, pkt_size, 1, f_out);

  if (++counter % 100000 == 0) {
    fprintf(stderr, "Processed %lld packets\n", counter);
  }
}

int main(int argc, char** argv) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s [input-pcap] [output-pcap]\n", argv[0]);
    return 1;
  }

  char* in = argv[1];
  char* out = argv[2];

  f_out = fopen(out, "w");

  decode d(4);  // Hard-coded for now
  D = &d;

  counter = 0;
  pkt_size = sizeof(struct ether_header) + sizeof(struct ip)
             + sizeof(struct tcphdr) + 6 * sizeof(int32_t);

  assert(pkt_size == 78);
  out_pkt = new u_char[pkt_size];

  char errbuff[PCAP_ERRBUF_SIZE];

  pcap_t* pcap = pcap_open_offline(in, errbuff);
  if (pcap == NULL) {
    fprintf(stderr, "pcap_open_offline() failure: %s\n", errbuff);
    return 1;
  }

  // start packet processing loop
  if (pcap_loop(pcap, 0, packet_handler, NULL) < 0) {
    fprintf(stderr, "pcap_loop() failure: %s\n", pcap_geterr(pcap));
    fprintf(stderr, "[END] Processed %lld packets\n", counter);
    fclose(f_out);
    delete out_pkt;
    return 1;
  }

  fprintf(stderr, "[END] Processed %lld packets\n", counter);
  fclose(f_out);
  delete out_pkt;

  return 0;
}