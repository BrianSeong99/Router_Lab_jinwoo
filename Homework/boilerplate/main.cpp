#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <iostream>

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
extern int getUDPChecksum(uint8_t* pac);

macaddr_t multicast_mac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09}; // 01:00:5e:00:00:09
in_addr_t multicast_addr = 0x090000e0; // 224.0.0.9

uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1 (192.168.3.2)
// 1: 10.0.1.1 (192.168.4.1)
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0103a8c0, 0x0101a8c0, 0x0102000a,
                                     0x0103000a};

int main(int argc, char *argv[]) {
  // <1>. 获取本机网卡信息
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
      .addr = addrs[i] & 0xffffff, // big endian
      .len = 24, // small endian
      .if_index = i, // small endian
      .nexthop = 0, // big endian, means direct
      .metric = 1,
      .timestamp = 0
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      // What to do?
      // send complete routing table to every interface
      // ref. RFC2453 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09

      std::vector<RoutingTableEntry> routers = getRoutingTable();
      // send new routing table to all ports
      for(int i=0; i<N_IFACE_ON_BOARD; i++) {
	for (int routeIndex = 0; routeIndex < routers.size(); routeIndex+=25) { 
          RipPacket ripPacket_o;
          //ripPacket_o.numEntries = routers.size();
          ripPacket_o.command = 2;
	  int j;
          for (j=routeIndex; j<(routers.size() < routeIndex+25 ? routers.size() : routeIndex+25); j++) {
            if (routers.at(j).nexthop != 0 && routers.at(j).if_index == i) {
              ripPacket_o.entries[j] = toRipEntry(routers.at(j), 16);
            } else if (routers.at(j).nexthop == 0) {
              ripPacket_o.entries[j] = toRipEntry(routers.at(j), 1);
            } else {
              ripPacket_o.entries[j] = toRipEntry(routers.at(j), routers.at(j).metric);
            }
            ripPacket_o.entries[j].nexthop = 0;
            // ripPacket_o.entries[i].metric = __builtin_bswap32(ripPacket_o.entries[i].metric);
            // std::cout << "30: entries[i].metric: " << routers.at(i).metric << " " << ripPacket_o.entries[i].metric << std::endl;
          }
	  ripPacket_o.numEntries = j-routeIndex+1;

          // assemble
          setupIPPacket(output);

          // Dest addr
          output[16] = multicast_addr;
          output[17] = multicast_addr >> 8;
          output[18] = multicast_addr >> 16;
          output[19] = multicast_addr >> 24;

          // Src addr
          output[12] = addrs[i];
          output[13] = addrs[i] >> 8;
          output[14] = addrs[i] >> 16;
          output[15] = addrs[i] >> 24;

          uint32_t rip_len = assemble(&ripPacket_o, &output[20 + 8]);

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
          output[26] = 0x00;
          output[27] = 0x00;
          // answer = getUDPChecksum(output);
          // output[26] = answer >> 8;
          // output[27] = answer;
          HAL_SendIPPacket(i, output, rip_len + 20 + 8, multicast_mac);
      	}
      }

      std::cout << "\n" << "addr\tif\tlen\tmetric\tnexthop\n";
      for (int i=0; i<routers.size(); i++) {
        std::cout  << std::hex << routers.at(i).addr << "\t";
        std::cout << std::dec << routers.at(i).if_index << "\t"
        << routers.at(i).len << "\t"
        << routers.at(i).metric << "\t"
        << std::hex << routers.at(i).nexthop << std::endl;
      }

      printf("30s Timer\n");
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
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

    // std::cout << "after time 30, before receive analysis: " << std::hex << packet << " res: " << res << std::endl;

    // 1. 检查是否是合法的 IP 包，可以用你编写的 validateIPChecksum 函数，还需要一些额外的检查
    
    uint8_t version = packet[0] >> 4;
    if(version != 4 && version != 6) {
      printf("Invalid version\n");
      continue;
    }

    uint8_t TTL = packet[8];
    if(TTL <= 0) {
      printf("Invalid TTL\n");
      continue;
    }
    
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian 
    memcpy(&src_addr, &packet[12], sizeof(in_addr_t));
    memcpy(&dst_addr, &packet[16], sizeof(in_addr_t));
    // src_addr = __builtin_bswap32(src_addr);
    // dst_addr = __builtin_bswap32(dst_addr);

    // 2. check whether dst is me
    bool dst_is_me = false;
    // std::cout << "dst_addr: " << std::hex << dst_addr << " multicast_addr: " << std::hex << multicast_addr << std::endl;
    if (memcmp(&dst_addr, &multicast_addr, sizeof(in_addr_t)) == 0) {
      // std::cout << dst_addr << " " << multicast_addr << " " << true << std::endl;
      dst_is_me = true;
    } else {
      for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
        if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
          dst_is_me = true;
          break;
        }
      }
    }

    // TODO: Handle rip multicast address(224.0.0.9)?
    // std::cout << "before dst_is_me if: " << dst_is_me << std::endl;
    if (dst_is_me) {
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        std::cout << "disassemble-";
        if (rip.command == 1) {
          std::cout << "request: " << std::endl;
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab

          // std::cout << "probably here then" << std::endl;
          RipPacket resp;
          // std::cout << "after resp definition" << std::endl;

          // TODO: fill resp
          resp.command = 2;
          // std::cout << "before getRoutingTable" << std::endl;
          std::vector<RoutingTableEntry> routers = getRoutingTable();
          // std::cout << "before size: " << std::endl;

          resp.numEntries = routers.size();
          // std::cout << "after size: " << std::endl;
          for (int i=0; i < routers.size(); i++) {
            if (routers.at(i).nexthop != 0 && routers.at(i).if_index == if_index) {
              resp.entries[i] = toRipEntry(routers.at(i), 16);
            } else {
              resp.entries[i] = toRipEntry(routers.at(i), routers.at(i).metric);
            }
            resp.entries[i].nexthop = 0;
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
          output[26] = 0x00;
          output[27] = 0x00;
          // answer = getUDPChecksum(output); // start from 8, add 12(part of IP), add 8(UDP), and data
          // output[26] = answer >> 8;
          // output[27] = answer;
          // checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
          // send it back
          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
	        std::cout << "request send back to: " << src_addr << std::endl;
        } else {
          std::cout << "response: " << std::endl;
          // 3a.2 response, ref. RFC2453 3.9.2
          // update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // what is missing from RoutingTableEntry?
          // TODO: use query and update
          // triggered updates? ref. RFC2453 3.10.1
          uint32_t nexthop, dest_if;
          // std::cout << "before define routers" << std::endl;
          std::vector<RipEntry> ripOfRouter = getRipRoutingTable();
          // std::cout << "before define deleted" << std::endl;
          std::vector<RoutingTableEntry> deleted;
          // std::cout << "after define routers and deleted" << std::endl;
          for (int i=0; i<rip.numEntries; i++) {
            // std::cout << "i" << std::endl;
            // std::cout << std::hex << "response rip addr: " << rip.entries[i].addr << std::endl;
            // std::cout << std::hex << "response rip mask: " << rip.entries[i].mask << std::endl;
            // std::cout << std::hex << "response rip metric: " << rip.entries[i].metric << std::endl;
            // std::cout << std::hex << "response rip nexthop: " << rip.entries[i].nexthop << std::endl;

            rip.entries[i].metric = __builtin_bswap32(rip.entries[i].metric);
            uint32_t query_if_index, query_nexthop, query_metric;
            bool tmp = query(rip.entries[i].addr, &query_nexthop, &query_if_index, &query_metric);
            if(rip.entries[i].metric+1 > 16 
            && src_addr != 0x0203a8c0 // reverse poisoning detection // && src_addr != 0x0204a8c0
            && memcmp(&(rip.entries[i].nexthop), &query_nexthop, sizeof(uint32_t))) {
              rip.entries[i].metric++;
              RoutingTableEntry entry = toRoutingTableEntry(rip.entries[i], query_if_index, 0);
              update(false, entry); // delete route entry
              deleted.push_back(entry);
            } else {
              // update
              if (rip.entries[i].nexthop == (uint32_t)0x00000000) {
                rip.entries[i].nexthop = src_addr;
              }
              if(tmp) {
                if (rip.entries[i].metric+1 <= query_metric) {
                  rip.entries[i].metric++;
                  update(true, toRoutingTableEntry(rip.entries[i], if_index, 0));
                }
              } else {
                rip.entries[i].metric++;
                update(true, toRoutingTableEntry(rip.entries[i], if_index, 0)); // insert if rip is not found in routing table
              }
            }
          }

          //// assemble
          //setupIPPacket(output);

          //// Dest addr
          //output[16] = multicast_addr;
          //output[17] = multicast_addr >> 8;
          //output[18] = multicast_addr >> 16;
          //output[19] = multicast_addr >> 24;

          //// if there are deleted rips
          //if (!deleted.empty()) {
            //for(int i=0; i<N_IFACE_ON_BOARD; i++) {
             // if(i!=if_index) {

               // // assembling "to delete" packet
               // RipPacket deletedPacket;
               // deletedPacket.numEntries = deleted.size();
               // deletedPacket.command = 2;
               // for (int j=0; j<deletedPacket.numEntries; j++) {
               //   if (deleted.at(j).nexthop != 0 && deleted.at(j).if_index == i) {
                 //   deletedPacket.entries[j] = toRipEntry(deleted.at(j), 16);
                 // } else {
                  //  deletedPacket.entries[j] = toRipEntry(deleted.at(j), deleted.at(j).metric);
                 // }
                 // deletedPacket.entries[j].nexthop = 0;
              //  }
                
                // Src addr
               // output[12] = addrs[i];
               // output[13] = addrs[i] >> 8;
               // output[14] = addrs[i] >> 16;
               // output[15] = addrs[i] >> 24;

               // uint32_t rip_len = assemble(&deletedPacket, &output[20 + 8]);

               // // Total Length
               // output[2] = (rip_len+20+8) >> 8;
               // output[3] = rip_len+20+8;

               // // UDP len
               // output[24] = (rip_len+8) >> 8;
               // output[25] = rip_len+8;

               // // ip checksum
               // output[10] = 0x00;
               // output[11] = 0x00;
               // unsigned short answer = getChecksum(output, 0, 20);
               // output[10] = answer >> 8;
               // output[11] = answer;

               // // udp checksum
               // output[26] = 0x00;
               // output[27] = 0x00;
               // // answer = getUDPChecksum(output);
               // // output[26] = answer >> 8;
               // // output[27] = answer;
               // HAL_SendIPPacket(i, output, rip_len + 20 + 8, multicast_mac);

             // }
            //}
          //}

          //// send new routing table to all ports
          //for(int i=0; i<N_IFACE_ON_BOARD; i++) {
           // // assembling "to update" packet
           // std::vector<RoutingTableEntry> routers = getRoutingTable();
           // RipPacket updatePacket;
           // updatePacket.numEntries = routers.size();
           // updatePacket.command = 2;
           // for (int j=0; j<updatePacket.numEntries; j++) {
           //   if (routers.at(j).nexthop != 0 && routers.at(j).if_index == i) {
           //     updatePacket.entries[j] = toRipEntry(routers.at(j), 16);
           //   } else {
           //     updatePacket.entries[j] = toRipEntry(routers.at(j), routers.at(j).metric);
           //   }
           //   updatePacket.entries[j].nexthop = 0;
           // }

           // // Src addr
           // output[12] = addrs[i];
           // output[13] = addrs[i] >> 8;
           // output[14] = addrs[i] >> 16;
           // output[15] = addrs[i] >> 24;

           // uint32_t rip_len = assemble(&updatePacket, &output[20 + 8]);

           // // Total Length
           // output[2] = (rip_len+20+8) >> 8;
           // output[3] = rip_len+20+8;

           // // UDP len
           // output[24] = (rip_len+8) >> 8;
           // output[25] = rip_len+8;

           // // ip checksum
           // output[10] = 0x00;
           // output[11] = 0x00;
           // unsigned short answer = getChecksum(output, 0, 20);
           // output[10] = answer >> 8;
           // output[11] = answer;

           // // udp checksum
           // output[26] = 0x00;
           // output[27] = 0x00;
           // // answer = getChecksum(output, 8, 8+12+8+rip_len);
           // // output[26] = answer >> 8;
           // // output[27] = answer;
           // HAL_SendIPPacket(i, output, rip_len + 20 + 8, multicast_mac);

	   // // std::cout << "response UPDATE packet sent from " << i << " to " << multicast_mac << std::endl;
         // }
        }
      }
    } else {
        // 3b.1 dst is not me
        // forward
        // beware of endianness
        uint32_t nexthop, dest_if, metric;
        if (query(dst_addr, &nexthop, &dest_if, &metric)) {
          // found
          macaddr_t dest_mac;
          // direct routing
          if (nexthop == 0) {
            nexthop = dst_addr;
          }
          if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
            std::cout << "after ARP: " << dest_if << " " << std::hex << nexthop << std::endl;
            // found
            memcpy(output, packet, res);
            // update ttl and checksum
            std::cout << "forward status: " <<
            forward(output, res) << std::endl;
            // TODO: you might want to check ttl=0 case
            // 当TTL=0， 建议构造一个 ICMP Time Exceeded 返回给发送者
            if (output[8] == 0x00) {
              setupIPPacket(output);

              output[12] = 

              // ICMP type
              output[20] = 0x0b;
              // ICMP code
              output[21] = 0x00;
              
              setupICMPPacket(output, packet);

              // calculate checksum
              unsigned short answer = getChecksum(output, 0, 36);
              output[2] = answer >> 8;
              output[3] = answer;
              HAL_SendIPPacket(if_index, output, 36, src_mac); // 36 is the length of a ICMP packet: 8(head of icmp) + 28(ip head + first 8 bytes of ip data)
		
              printf("IP TTL timeout for %x\n", src_addr);
            } else {
                HAL_SendIPPacket(dest_if, output, res, dest_mac);
                std::cout << "forware IP packet sent from " 
                << std::dec << dest_if << " to addr:" << std::hex << dst_addr 
                << " mac: " << std::hex 
                << (int)dest_mac[0] << ":" 
                << (int)dest_mac[1] << ":"
                << (int)dest_mac[2] << ":" 
                << (int)dest_mac[3] << ":" 
                << (int)dest_mac[4] << ":" 
                << (int)dest_mac[5] << std::endl;
            }
          } else {
            // not found
            // 如果没查到下一跳的 MAC 地址，HAL 会自动发出 ARP 请求，在对方回复后，下次转发时就知道了
            // you can drop it
            printf("ARP not found for %x\n", nexthop);
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
          printf("IP not found for %x\n", src_addr);
        }
      }
  }
  return 0;
}
