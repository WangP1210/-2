# -2
试用2
int icmp_unpack(char* buf, int len)
{
    int iphdr_len;
    struct timeval begin_time, recv_time, offset_time;
    int rtt;  //round trip time

    struct ip* ip_hdr = (struct ip *)buf;
    iphdr_len = ip_hdr->ip_hl*4;
    struct icmp* icmp = (struct icmp*)(buf+iphdr_len); //使指针跳过IP头指向ICMP头
    len-=iphdr_len;  //icmp包长度
    if(len < 8)   //判断长度是否为ICMP包长度
    {
        fprintf(stderr, "Invalid icmp packet.Its length is less than 8\n");
        return -1;
    }

    //判断该包是ICMP回送回答包且该包是我们发出去的
    if((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == (pid & 0xffff))) 
    {
        if((icmp->icmp_seq < 0) || (icmp->icmp_seq > PACKET_SEND_MAX_NUM))
        {
            fprintf(stderr, "icmp packet seq is out of range!\n");
            return -1;
        }

        ping_packet[icmp->icmp_seq].flag = 0;
        begin_time = ping_packet[icmp->icmp_seq].begin_time;  //去除该包的发出时间
        gettimeofday(&recv_time, NULL);

        offset_time = cal_time_offset(begin_time, recv_time);
        rtt = offset_time.tv_sec*1000 + offset_time.tv_usec/1000; //毫秒为单位

        printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%d ms\n",
            len, inet_ntoa(ip_hdr->ip_src), icmp->icmp_seq, ip_hdr->ip_ttl, rtt);        

    }
    else
    {
        fprintf(stderr, "Invalid ICMP packet! Its id is not matched!\n");
        return -1;
    }
    return 0;
}
