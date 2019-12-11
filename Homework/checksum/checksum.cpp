#include <stdint.h>
#include <stdlib.h>
#include <iostream>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // std::cout << "packet[0]: " << packet[0] << " " << len << std::endl;
  int hLength = (int)(packet[0]&0xf) * 4;
  int sum = 0;
  for (int i = 0; i < hLength; i++) {
    if (i % 2 == 0) {
      sum += ((int) packet[i]) << 8;
    } else {
      sum += ((int) packet[i]);
    }
  }

  sum = (sum & 0xffff) + (sum >> 16);
  sum += (sum >> 16);
  unsigned short answer = ~sum;
  if (answer == 0x0000) {
    return true;
  }
  return false;
}

unsigned short getChecksum(uint8_t *packet, int start, int end) {
  int sum = 0;
  for (int i = start; i < end; i++) {
    if (i % 2 == 0) {
      sum += ((int) packet[i]) << 8;
    } else {
      sum += ((int) packet[i]);
    }
  }
  sum = (sum & 0xffff) + (sum >> 16);
  sum += (sum >> 16);
  unsigned short answer = ~sum;
  return answer;
}

int getUDPChecksum(uint8_t* pac) {
  int UDPchecksum = 0;
  uint16_t UDPLength = (((int)pac[24]) << 8) + pac[25];
  for(int i = 12;i < 20;i++) {
    if(i % 2 == 0) {
      UDPchecksum += ((int)pac[i]) << 8;
    } else {
      UDPchecksum += (int)pac[i];
    }
  }
  UDPchecksum += 0x11;
  UDPchecksum += UDPLength;
  //UDP header
  for(int i = 20;i < 26;i++) {
    if(i % 2 == 0) {
      UDPchecksum += ((int)pac[i]) << 8;
    } else {
      UDPchecksum += (int)pac[i];
    }
  }
  UDPchecksum = (UDPchecksum >> 16) + (UDPchecksum & 0xffff);
  UDPchecksum += (UDPchecksum >> 16);
  UDPchecksum = ~UDPchecksum;
  return UDPchecksum;
}
