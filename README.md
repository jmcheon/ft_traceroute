# ft_traceroute

## Structs
### struct sockaddr_in
sin stands for **S**ocket **I**nternet **N**etwork
```c
struct sockaddr_in {
    short            sin_family;   // 1. Address system (always AF_INET - meaning IPv4)
    unsigned short   sin_port;     // 2. Port nnumber (가고 싶은 방 번호, 네트워크 바이트 정렬 필요)
    struct in_addr   sin_addr;     // 3. IP address (실제 4바이트짜리 주소 구조체)
    char             sin_zero[8];  // 4. Padding (자리를 맞추기 위한 빈 공간, 다 0으로 채움)
};
```
### struct in_addr
### struct ip
### struct icmp


## Raw Socket Parsing
```
  buf (pointer starting point)
   │
   ▼
┌──────────────────────────┬──────────────────────────┬──────────────────────────┐
│      IP Header           │       ICMP Header        │      Original IP...      │
│    (normally 20byte)     │       (8byte)            │      (remaining data)    │
└──────────────────────────┴──────────────────────────┴──────────────────────────┘
▲                          ▲
│                          │
├──── IP Header Length ────┤
│     (ip->ip_hl * 4)      │
```
