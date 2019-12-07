#include "router_hal.h"
#include "rip.h"
#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vector>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern std::vector<RoutingTableEntry> getRoutingTable();
extern std::vector<RipEntry> getRipRoutingTable();
extern uint32_t toEndian(uint32_t num);
extern RoutingTableEntry toRoutingTableEntry(RipEntry rip, uint32_t if_index, uint32_t timestamp);
extern RipEntry toRipEntry(RoutingTableEntry entry, uint32_t metric);
extern unsigned short getChecksum(uint8_t *packet, int start, int end);
extern void setupIPPacket(uint8_t *packet);
extern void setupICMPPacket(uint8_t *output, uint8_t *packet);

macaddr_t multicast_addr = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x16};

uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a, 0x0103000a};

int main(int argc, char *argv[]) {
  // <1>. 获取本机网卡信息
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }
  
  // Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD;i++) {
    RoutingTableEntry entry = {
      .addr = addrs[i], // big endian
      .len = 24, // small endian
      .if_index = i, // small endian
      .nexthop = 0, // big endian, means direct
      .metric = 0,
      .timestamp = 0
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 30 * 1000) {
      // What to do?
      printf("Timer\n");
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac,
                                  dst_mac, 1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // 1. 检查是否是合法的 IP 包，可以用你编写的 validateIPChecksum 函数，还需要一些额外的检查
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian 
    memcpy(&src_addr, &packet[12], sizeof(in_addr_t));
    memcpy(&dst_addr, &packet[16], sizeof(in_addr_t));
    src_addr = __builtin_bswap32(src_addr);
    dst_addr = __builtin_bswap32(dst_addr);

    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD;i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // TODO: Handle rip multicast address?

    if (dst_is_me) {
      // TODO: RIP?
      RipPacket rip;
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          // request
          RipPacket resp;
          // TODO: fill resp
          resp.command = 2;
          std::vector<RoutingTableEntry> routers = getRoutingTable();
          resp.numEntries = routers.size();
          for (int i=0; i < routers.size(); i++) {
            resp.entries[i] = toRipEntry(routers.at(i), 1);
          }
          // assemble
          // IP
          setupIPPacket(output);

          // Source
          output[12] = dst_addr;
          output[13] = dst_addr >> 8;
          output[14] = dst_addr >> 16;
          output[15] = dst_addr >> 24;

          // Destination
          output[16] = src_addr;
          output[17] = src_addr >> 8;
          output[18] = src_addr >> 16;
          output[19] = src_addr >> 24;

          // RIP
          uint32_t rip_len = assemble(&resp, &output[20 + 8]);

          // Total Length
          output[2] = (rip_len+20+8) >> 8;
          output[3] = rip_len+20+8;

          // UDP len
          output[24] = (rip_len+8) >> 8;
          output[25] = rip_len+8;

          // ip checksum
          output[10] = 0x00;
          output[11] = 0x00;
          unsigned short answer = getChecksum(output, 0, 20);
          output[10] = answer >> 8;
          output[11] = answer;

          // udp checksum
          answer = getChecksum(output, 8, 8+12+8+rip_len); // start from 8, add 12(part of IP), add 8(UDP), and data
          output[26] = answer >> 8;
          output[27] = answer;
          // checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
          // send it back
          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
          printf("%ud", src_addr);
        } else {
          // response
          uint32_t nexthop, dest_if;
          std::vector<RoutingTableEntry> routers = getRoutingTable();
          std::vector<RipEntry> ripOfRouter = getRipRoutingTable();
          std::vector<RipEntry> deleted;
          for (int i=0; i<rip.numEntries; i++) {
            if(rip.entries[i].metric+1 > 16) {
              update(false, toRoutingTableEntry(rip.entries[i], 0, 0)); // delete route entry
              rip.entries[i].metric++;
              deleted.push_back(rip.entries[i]);
            } else {
              // 
              uint32_t query_if_index, query_nexthop, query_metric;
              if(query(rip.entries[i].addr, &query_nexthop, &query_if_index, &query_metric)) {
                if (rip.entries[i].metric+1 <= query_metric) {
                  rip.entries[i].metric++;
                  update(true, toRoutingTableEntry(rip.entries[i], if_index, 0));
                }
              } else {
                update(true, toRoutingTableEntry(rip.entries[i], if_index, 0)); // insert if rip is not found in routing table
              }
            }
          }

          // assembling "to delete" packet
          RipPacket deletedPacket;
          deletedPacket.numEntries = deleted.size();
          for (int i=0; i<deletedPacket.numEntries; i ++) {
            deletedPacket.entries[i] = deleted.at(i);
            deletedPacket.entries[i].metric = __builtin_bswap32 (uint32_t(1));
          }

          // assembling "to update" packet
          std::vector<RoutingTableEntry> routers = getRoutingTable();
          RipPacket updatePacket;
          updatePacket.numEntries = routers.size();
          for (int i=0; i<updatePacket.numEntries; i++) {
            updatePacket.entries[i] = toRipEntry(routers.at(i), 1);
          }

          // assemble
          setupIPPacket(output);

          // Source
          output[12] = dst_addr;
          output[13] = dst_addr >> 8;
          output[14] = dst_addr >> 16;
          output[15] = dst_addr >> 24;

          // if there are deleted rips
          if (!deleted.empty()) {
            for(int i=0; i<N_IFACE_ON_BOARD; i++) {
              if(i!=if_index) {
                
                // dst addr
                output[16] = addrs[i];
                output[17] = addrs[i] >> 8;
                output[18] = addrs[i] >> 16;
                output[19] = addrs[i] >> 24;

                uint32_t rip_len = assemble(&deletedPacket, &output[20 + 8]);

                // Total Length
                output[2] = (rip_len+20+8) >> 8;
                output[3] = rip_len+20+8;

                // UDP len
                output[24] = (rip_len+8) >> 8;
                output[25] = rip_len+8;

                // ip checksum
                output[10] = 0x00;
                output[11] = 0x00;
                unsigned short answer = getChecksum(output, 0, 20);
                output[10] = answer >> 8;
                output[11] = answer;

                // udp checksum
                answer = getChecksum(output, 8, 8+12+8+rip_len);
                output[26] = answer >> 8;
                output[27] = answer;
                HAL_SendIPPacket(i, output, rip_len + 20 + 8, multicast_addr);
              }
            }
          }

          // send new routing table to all ports
          for(int i=0; i<N_IFACE_ON_BOARD; i++) {
            // dst addr
            output[16] = addrs[i];
            output[17] = addrs[i] >> 8;
            output[18] = addrs[i] >> 16;
            output[19] = addrs[i] >> 24;

            uint32_t rip_len = assemble(&updatePacket, &output[20 + 8]);

            // Total Length
            output[2] = (rip_len+20+8) >> 8;
            output[3] = rip_len+20+8;

            // UDP len
            output[24] = (rip_len+8) >> 8;
            output[25] = rip_len+8;

            // ip checksum
            output[10] = 0x00;
            output[11] = 0x00;
            unsigned short answer = getChecksum(output, 0, 20);
            output[10] = answer >> 8;
            output[11] = answer;

            // udp checksum
            answer = getChecksum(output, 8, 8+12+8+rip_len);
            output[26] = answer >> 8;
            output[27] = answer;
            HAL_SendIPPacket(i, output, rip_len + 20 + 8, multicast_addr);
          }
        }
      } else {
        // forward
        // beware of endianness
        uint32_t nexthop, dest_if, metric;
        if (query(src_addr, &nexthop, &dest_if, &metric)) {
          // found
          macaddr_t dest_mac;
          // direct routing
          if (nexthop == 0) {
            nexthop = dst_addr;
          }
          if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
            // found
            memcpy(output, packet, res);
            // update ttl and checksum
            forward(output, res);
            // TODO: you might want to check ttl=0 case
            // 当TTL=0， 建议构造一个 ICMP Time Exceeded 返回给发送者
            if (output[8] == 0x00) {
              // ICMP type
              output[0] = 0x0b;
              // ICMP code
              output[1] = 0x00;
              
              setupICMPPacket(output, packet);

              // calculate checksum
              unsigned short answer = getChecksum(output, 0, 36);
              output[2] = answer >> 8;
              output[3] = answer;
              HAL_SendIPPacket(if_index, output, 36, src_mac); // 36 is the length of a ICMP packet: 8(head of icmp) + 28(ip head + first 8 bytes of ip data)
            } else {
              HAL_SendIPPacket(dest_if, output, res, dest_mac);
            }
          } else {
            // not found
            // 如果没查到下一跳的 MAC 地址，HAL 会自动发出 ARP 请求，在对方回复后，下次转发时就知道了
          }
        } else {
          // not found
          // 如果没查到目的地址的路由，返回一个 ICMP Destination Network Unreachable
          // ICMP type
          output[0] = 0x03;
          // ICMP code
          output[1] = 0x00;

          setupICMPPacket(output, packet);

          // calculate checksum
          unsigned short answer = getChecksum(output, 0, 36);
          output[2] = answer >> 8;
          output[3] = answer;
          HAL_SendIPPacket(if_index, output, 36, src_mac); // 36 is the length of a ICMP packet: 8(head of icmp) + 28(ip head + first 8 bytes of ip data)
        }
      }
    }
  }
  return 0;
}