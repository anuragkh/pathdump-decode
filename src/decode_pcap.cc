#include <pcap.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "decode.h"

#define MAX_PATH_LEN 6

decode *D;
FILE *f_out;
unsigned long long counter;
size_t pkt_size;
u_char* out_pkt;
uint32_t dst_ip;

uint32_t ip_string_to_uint32(const char* ip) {
  unsigned char tmp[4];
  sscanf(ip, "%hhu.%hhu.%hhu.%hhu", &tmp[3], &tmp[2], &tmp[1], &tmp[0]);
  return tmp[0] | tmp[1] << 8 | tmp[2] << 16 | tmp[3] << 24;
}

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
  int32_t path_vec[MAX_PATH_LEN] = { -1, -1, -1, -1, -1, -1};

  // IP header starts at offset 14 into the packet if there are no vlan headers
  int ip_start = 14;  

  // Parse eth header
  eth = (struct ether_header*) packet;

  // Parse VLAN headers if any
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

  // Parse IP header
  ip = (struct ip*) (packet + ip_start);
  if (ip->ip_p != IPPROTO_TCP) {
    fprintf(stderr, "!!! Not a tcp packet !!!\n");
    return;
  }

  if (ntohl(ip->ip_dst.s_addr) != dst_ip) {
    //fprintf(stderr, "!!! Not an incoming packet !!!\n");
    return;
  }

  // Parse TCP header
  tcp = (struct tcphdr*) (packet + ip_start + 20);

  // If the packet header has VLAN tags, decode the path info
  if (has_path) {
    saddr = ip->ip_src.s_addr;
    saddr = ntohl(saddr);
    daddr = ip->ip_dst.s_addr;
    daddr = ntohl(daddr);
    itoip(&saddr, sbytes);
    itoip(&daddr, dbytes);

    list<int32_t> path;
    D->decode_path(vlan_tags, vlan_len, sbytes, dbytes, &path);

    size_t pos = 0;
    typedef list<int32_t>::iterator list_it;
    for (list_it it = path.begin(); it != path.end(); it++) {
      path_vec[pos++] = *it;
#ifdef PRINT_PATH
      fprintf(stderr, "%d ", *it);
#endif // PRINT_PATH
    }
#ifdef PRINT_PATH
      fprintf(stderr, "\n");
#endif // PRINT_PATH
  }

  // Create new packet
  // Copy eth header
  eth->ether_type = ETHERTYPE_IP;
  memcpy(out_pkt, eth, sizeof(struct ether_header));

  // Copy ip header
  ip->ip_len = sizeof(struct ip) + sizeof(struct tcphdr) +
               MAX_PATH_LEN * sizeof(int32_t);
  memcpy(out_pkt + sizeof(struct ether_header), ip, sizeof(struct ip));

  // Copy tcp header
  memcpy(out_pkt + sizeof(struct ether_header) + sizeof(struct ip), tcp,
         sizeof(struct tcphdr));

  // Copy path vector
  memcpy(out_pkt + sizeof(struct ether_header) + sizeof(struct ip)
         + sizeof(struct tcphdr), path_vec, MAX_PATH_LEN * sizeof(int32_t));

  fwrite(out_pkt, pkt_size, 1, f_out);

  if (++counter % 100000 == 0) {
    fprintf(stderr, "Processed %lld packets\n", counter);
  }
}

int main(int argc, char** argv) {
  if (argc != 4) {
    fprintf(stderr, "Usage: %s [input-pcap] [output-pcap] [dst-ip]\n", argv[0]);
    return 1;
  }

  char* in = argv[1];
  char* out = argv[2];
  char* dstip = argv[3];
  dst_ip = ip_string_to_uint32(dstip);

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