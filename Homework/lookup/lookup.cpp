#include "router.h"
#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <sstream>

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/
std::vector<RoutingTableEntry> routers;

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
  int index = -1;
  for (int i=0; i<routers.size(); i++) {
    if (routers.at(i).addr == entry.addr && routers.at(i).len == entry.len) {
      index = i;
    }
  }
  if (insert) {
    if (index != -1) {
      routers.at(index) = entry;
    } else {
      routers.push_back(entry);
    }
  } else {
    if (index != -1) routers.erase(routers.begin() + index);
  }
}

std::string toHex(int addr) {
  std::stringstream ss;
  ss << std::hex << addr;
  return ss.str();
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric) {
  std::string addr_str = toHex((int)addr);
  int max = -1, max_i = -1;
  for (int i=0; i<routers.size(); i++) {
    std::string tmp = toHex((int)routers.at(i).addr);
    if (addr_str.find(tmp) != -1 && max < (int)tmp.size()) {
      max = tmp.length();
      max_i = i;
    }
  }
  if (max_i != -1) {
    *nexthop = routers.at(max_i).nexthop;
    *if_index = routers.at(max_i).if_index;
    *metric = routers.at(max_i).metric;
    return true;
  } else {
    return false;
  }
}

std::vector<RoutingTableEntry> getRoutingTable() {
  return routers;
}

std::vector<RipEntry> getRipRoutingTable() {
  std::vector<RipEntry> rips;
  for (int i=0; i < routers.size(); i++) {
    rips.at(i).addr = routers.at(i).addr;
    rips.at(i).mask = __builtin_bswap32 (toEndian(routers.at(i).len));
    rips.at(i).metric = __builtin_bswap32 (routers.at(i).metric);
    rips.at(i).nexthop = routers.at(i).nexthop;
  }
}

uint32_t toEndian(uint32_t num) {
  uint32_t tmp = 0;
  for (uint32_t i=0; i<num; i++) {
    tmp = tmp<<1 + 1;
  }
  tmp = tmp << (32-num);
  return tmp;
}

// big endian to digit
uint32_t toDigit(uint32_t endian) {
  uint32_t counter = 0;
  for (int i = 0; i < 32; i++) {
    if (endian & 0x1 == 1) {
      counter++;
      endian = endian >> 1;
    } else {
      break;
    }
  }
  return counter;
}

RoutingTableEntry toRoutingTableEntry(RipEntry rip, uint32_t if_index, uint32_t timestamp) {
  RoutingTableEntry entry;
  entry.addr = rip.addr;
  entry.if_index = if_index;
  entry.len = toDigit(rip.mask);
  entry.nexthop = rip.nexthop;
  entry.timestamp = timestamp;
}

RipEntry toRipEntry(RoutingTableEntry entry, uint32_t metric) {
  RipEntry rip;
  rip.addr = entry.addr;
  rip.mask = __builtin_bswap32 (toEndian(entry.len));
  rip.metric = __builtin_bswap32 (uint32_t(metric));
  rip.nexthop = entry.nexthop;
}