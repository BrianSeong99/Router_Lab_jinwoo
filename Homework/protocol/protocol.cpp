#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'z', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
<<<<<<< HEAD
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， z 是否为 0，
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
=======
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
>>>>>>> 500c0f34ab02962e0278743fc3bb64e46dc0777f
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {

    uint8_t command = packet[28];
    uint8_t version = packet[29];
    output->numEntries = 0;
    output->command = packet[28];

    if(
        (
            ((int)packet[2] << 8 + packet[3] > len)                     // check total length vs len
            || (command != 0x01 && command != 0x02)                     // check if command is 1 or 2
            || (version != 0x02)                                        // check if version is 2
            || ((uint16_t)(((int)packet[30]<<8)+packet[31]) != 0x0000)  // check if zero is 0
        )
    ) return false;

    int packetsNum = ((((int)packet[2])<<8)+packet[3]-(packet[0]&0xf)*4) / 20;

    for(int i=0; i<packetsNum; i++) {
        uint16_t family = ((int)packet[32+i*20]<<8) + packet[33+i*20];
        if((command==0x02 && family==0x0002) || (command==0x01 && family==0x0000)) {
            uint32_t metric=((int)packet[48+i*20]<<24)+((int)packet[49+i*20]<<16)+((int)packet[50+i*20]<<8)+packet[51+i*20];
            if(metric >= 1 && metric <= 16) {                           // check metric
                uint32_t mask=((int)packet[40+i*20]<<24)+((int)packet[41+i*20]<<16)+((int)packet[42+i*20]<<8)+packet[43+i*20];
                
                int count=0;
                uint8_t curr;
                uint8_t before = mask & 0xf;
                for(int i=1; i<8; i++) {                                // check mask
                    mask = mask >> 4;
                    curr = mask & 0xf;
                    if(curr != before) count++;
                    before = curr;
                }
                if(count > 1) return false;

                int numEntry = output->numEntries;
                output->entries[numEntry].addr=((int)packet[39+i*20]<<24)+((int)packet[38+i*20]<<16)+((int)packet[37+i*20]<<8)+packet[36+i*20];
                output->entries[numEntry].mask=((int)packet[43+i*20]<<24)+((int)packet[42+i*20]<<16)+((int)packet[41+i*20]<<8)+packet[40+i*20];;
                output->entries[numEntry].metric=((int)packet[51+i*20]<<24)+((int)packet[50+i*20]<<16)+((int)packet[49+i*20]<<8)+packet[48+i*20];
                output->entries[numEntry].nexthop=((int)packet[47+i*20]<<24)+((int)packet[46+i*20]<<16)+((int)packet[45+i*20]<<8)+packet[44+i*20];
                output->numEntries++; 
            }
            else return false;
        }
        else return false;
    }
    return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、z、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
    buffer[0]=rip->command;
    buffer[1]=0x2;
    buffer[2]=0x00;
    buffer[3]=0x00;

    for(int i=0; i<rip->numEntries; i++){
        RipEntry entry = rip->entries[i];  

        // family
        if(rip->command==0x02){
            buffer[4+i*20]=0x00;
            buffer[5+i*20]=0x02;
        }
        else{
            buffer[4+i*20]=0x00;
            buffer[5+i*20]=0x00;
        }

        // route tag
        buffer[6+i*20]=0x00;
        buffer[7+i*20]=0x00;

        // ip
        buffer[8+i*20]=entry.addr;
        buffer[9+i*20]=entry.addr>>8;
        buffer[10+i*20]=entry.addr>>16;
        buffer[11+i*20]=entry.addr>>24;

        // mask
        buffer[12+i*20]=entry.mask;
        buffer[13+i*20]=entry.mask>>8;
        buffer[14+i*20]=entry.mask>>16;
        buffer[15+i*20]=entry.mask>>24;

        // nexthop
        buffer[16+i*20]=entry.nexthop;
        buffer[17+i*20]=entry.nexthop>>8;
        buffer[18+i*20]=entry.nexthop>>16;
        buffer[19+i*20]=entry.nexthop>>24;

        // metrics
        buffer[20+i*20]=entry.metric;
        buffer[21+i*20]=entry.metric>>8;
        buffer[22+i*20]=entry.metric>>16;
        buffer[23+i*20]=entry.metric>>24;
    }
    return (rip->numEntries)*20+4;
}
