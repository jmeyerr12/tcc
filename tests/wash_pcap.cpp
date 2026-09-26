#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <string>
#include <array>
#include <vector>
using Bytes=std::vector<uint8_t>;
void check(bool ok,const char* msg){if(!ok)throw std::runtime_error(msg);}
uint16_t be16(const Bytes& p,size_t n){return uint16_t(p[n])<<8|p[n+1];}
uint32_t sum(const Bytes& p,size_t n,size_t end){uint32_t s=0;for(;n<end;n+=2)s+=(uint32_t(p[n])<<8)+(n+1<end?p[n+1]:0);return s;}
bool valid(uint32_t s){while(s>>16)s=(s&65535)+(s>>16);return s==65535;}
int main(int argc,char** argv){try{
    check(argc==5,"uso: wash_pcap objeto_bpf resumo.txt entrada.pcap saida.pcap");
    check(std::string(argv[3])!=argv[4],"input and output must differ");
    std::ifstream summary(argv[2]);check(bool(summary),"open interval summary");
    std::vector<std::array<uint32_t,2>> intervals;
    std::string line;bool merged=false;
    while(std::getline(summary,line)) {
        if(line=="Merged:"){merged=true;continue;}
        if(!merged)continue;
        if(line.empty())break;
        long long start,end;char dash;std::istringstream row(line);
        check(bool(row>>start>>dash>>end) && dash=='-' && (row>>std::ws).eof(),"invalid merged interval");
        check(start>=0 && end>=start && end<2048 && intervals.size()<16,"interval outside xdp limits");
        check(intervals.empty() || start>intervals.back()[1],"intervals must be sorted and disjoint");
        intervals.push_back({{uint32_t(start),uint32_t(end)}});
    }
    check(merged && !intervals.empty(),"missing merged intervals");
    rlimit limit={RLIM_INFINITY,RLIM_INFINITY};check(setrlimit(RLIMIT_MEMLOCK,&limit)==0,"setrlimit");
    auto obj=bpf_object__open_file(argv[1],nullptr);check(obj && !libbpf_get_error(obj),"open bpf object");
    check(bpf_object__load(obj)==0,"load bpf object");
    auto prog=bpf_object__find_program_by_name(obj,"xdp_ids_func");check(prog,"program not found");
    int map=bpf_object__find_map_fd_by_name(obj,"intervals_map"),cnt=bpf_object__find_map_fd_by_name(obj,"interval_cnt");
    for(uint32_t i=0;i<intervals.size();++i)check(bpf_map_update_elem(map,&i,intervals[i].data(),BPF_ANY)==0,"interval map update");
    uint32_t zero=0,count=intervals.size();check(bpf_map_update_elem(cnt,&zero,&count,BPF_ANY)==0,"count map update");
    std::ifstream in(argv[3],std::ios::binary);std::ofstream out(argv[4],std::ios::binary);
    check(bool(in)&&bool(out),"open pcap");uint32_t gh[6];in.read((char*)gh,24);
    check(in.gcount()==24 && gh[0]==0xa1b2c3d4 && gh[5]==1,"expected little-endian ethernet pcap");out.write((char*)gh,24);
    size_t packets=0,bytesIn=0,bytesOut=0;
    for(;;){uint32_t h[4];in.read((char*)h,16);if(!in.gcount()&&in.eof())break;
        check(in.gcount()==16 && h[2]<=65535 && h[2]==h[3],"invalid pcap record");Bytes p(h[2]),q(65536);
        in.read((char*)p.data(),p.size());check(size_t(in.gcount())==p.size(),"truncated packet");
        check(p.size()>=42 && be16(p,12)==0x800 && p[14]==0x45,"expected ipv4 without options");
        check(p[23]==6 || p[23]==17,"expected tcp/udp");
        check(p[23]!=6 || p.size()>=54,"truncated tcp header");
        check(!(be16(p,20)&0x3fff),"fragmented input is outside this test");
        size_t l4= p[23]==6?size_t(p[46]>>4)*4:8;
        check(p[23]!=6 || l4>=20,"invalid tcp header size");
        size_t off=34+l4;check(off<=p.size() && be16(p,16)+14u==p.size(),"invalid lengths");
        check(p.size()-off<=2048,"payload exceeds xdp limit");
        check(p[23]!=17 || be16(p,38)==p.size()-34,"invalid input udp length");
        check(valid(sum(p,14,34)) && valid(sum(p,26,34)+p[23]+p.size()-34+sum(p,34,p.size())),"bad input checksum");
        Bytes expected;for(auto& r:intervals)for(size_t j=r[0];j<=r[1] && off+j<p.size();++j)expected.push_back(p[off+j]);
        bpf_prog_test_run_attr test={};test.prog_fd=bpf_program__fd(prog);test.repeat=1;
        test.data_in=p.data();test.data_size_in=p.size();test.data_out=q.data();test.data_size_out=q.size();
        check(bpf_prog_test_run_xattr(&test)==0,"bpf test run");check(test.retval==2,"xdp did not pass packet");q.resize(test.data_size_out);
        check(q.size()==off+expected.size(),"wrong output size");check(std::equal(expected.begin(),expected.end(),q.begin()+off),"wrong output payload");
        for(size_t i=0;i<off;++i) {
            bool updated=i==16 || i==17 || i==24 || i==25 ||
                         (p[23]==6 ? i==50 || i==51 : i>=38 && i<=41);
            check(updated || p[i]==q[i],"unexpected header change");
        }
        check(std::equal(p.begin(),p.begin()+14,q.begin()),"ethernet header changed");
        check(std::equal(p.begin()+26,p.begin()+38,q.begin()+26),"addresses/ports changed");
        if(p[23]==6)check(std::equal(p.begin()+38,p.begin()+50,q.begin()+38),"tcp sequence/ack/flags/window changed");
        else check(be16(q,38)==q.size()-34,"udp length mismatch");
        check(be16(q,16)+14u==q.size(),"ip length mismatch");
        check(valid(sum(q,14,34)) && valid(sum(q,26,34)+q[23]+q.size()-34+sum(q,34,q.size())),"bad output checksum");
        h[2]=h[3]=q.size();out.write((char*)h,16);out.write((char*)q.data(),q.size());check(bool(out),"pcap write");
        ++packets;bytesIn+=p.size();bytesOut+=q.size();
    }
    check(packets>0,"empty pcap: no packet tested");
    bpf_object__close(obj);std::cout<<"PASS: "<<packets<<" packets, "<<bytesIn<<" -> "<<bytesOut<<" bytes; payload, lengths, headers and checksums verified\n";
}catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}}
