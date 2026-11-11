// Zohaib Umer | 23i-0528 | CS3002 Assignment 2, Part D
// Reproducible SmartLock v1 vs v2 measurements. C++17 / OpenSSL.
// Usage: benchmark handshake v1|v2 INSTANCE HOST COUNT
//        benchmark records v1|v2 INSTANCE COUNT_PER_RUN RUNS
// CSV to stdout. Debug information to stderr.
#include "slink.hpp"
#include "pki.hpp"
#include "dh2048.hpp"
#include "securelink2.hpp"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>
using Clock=std::chrono::steady_clock;
using Bytes=std::vector<uint8_t>;
static double elapsed_us(Clock::time_point a,Clock::time_point b){return std::chrono::duration<double,std::micro>(b-a).count();}
static std::string join(const std::vector<std::string>& vs){std::string s;for(auto &x:vs){if(!s.empty())s+=',';s+=x;}return s;}
static void row(const std::string& vers,const char* metric,int run,double value,const char* unit){std::cout << vers << ',' << metric << ',' << run << ',' << std::fixed << std::setprecision(6) << value << ',' << unit << '\n';}
static int connect_tcp(const std::string& host,int port){int fd=socket(AF_INET,SOCK_STREAM,0);if(fd<0)throw std::runtime_error("socket failed");struct timeval timeout{5,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof timeout);sockaddr_in sa{};sa.sin_family=AF_INET;sa.sin_port=htons(port);if(inet_pton(AF_INET,host.c_str(),&sa.sin_addr)!=1)throw std::runtime_error("invalid IPv4");if(connect(fd,(sockaddr*)&sa,sizeof sa)<0){close(fd);throw std::runtime_error("connection failed");}return fd;}
static void handshake_v1(const std::map<std::string,std::string>& cfg,const std::string& host,int port,int run){
 auto start=Clock::now();int s=connect_tcp(host,port);slink::Reader r(s);slink::Msg m;
 slink::send_msg(s,{{"type","HELLO"},{"suites","AES256-GCM,AES128-GCM,NULL"}});
 if(!r.recv(m)||m["type"]!="SUITE")throw std::runtime_error("v1 suite failure");
 auto suite=m["suite"];
 if(!r.recv(m)||m["type"]!="CERT")throw std::runtime_error("v1 cert failure");
 slink::send_msg(s,{{"type","PAIR"},{"hub",cfg.at("hub_id")},{"pinhash",slink::md5hex(cfg.at("pin"))}});
 if(!r.recv(m)||m["type"]!="DH")throw std::runtime_error("v1 DH failure");
 uint64_t p=std::stoull(m["p"]),g=std::stoull(m["g"]),B=std::stoull(m["B"]);
 std::mt19937_64 rng(std::random_device{}());uint64_t a=2+rng()%(p-3);
 slink::send_msg(s,{{"type","DHCLIENT"},{"A",std::to_string(slink::modexp(g,a,p))}});
 auto key=slink::session_key(slink::modexp(B,a,p),suite);auto nonce=slink::from_hex(cfg.at("static_nonce"));
 if(!r.recv(m)||m["type"]!="MSG")throw std::runtime_error("v1 greeting failure");
 auto greeting=slink::record_decrypt(suite,key,slink::from_hex(m["nonce"]),slink::from_hex(m["ct"]));
 if(greeting.find("Paired with SmartLock")!=0)throw std::runtime_error("unexpected v1 greeting");
 auto stop=Clock::now();row("v1","handshake_us",run,elapsed_us(start,stop),"us");
 slink::send_msg(s,{{"type","MSG"},{"nonce",cfg.at("static_nonce")},{"ct",slink::to_hex(slink::record_encrypt(suite,key,nonce,"QUIT"))}});
 close(s);
}
static void handshake_v2(const std::map<std::string,std::string>& cfg,const std::string& host,int port,int run){
 auto start=Clock::now();int s=connect_tcp(host,port);slink::Reader r(s);slink::Msg m;
 auto offer=join(sl2::strong_suites());slink::send_msg(s,{{"type","HELLO"},{"suites",offer}});
 if(!r.recv(m)||m["type"]!="SUITE")throw std::runtime_error("v2 suite failure");
 auto suite=m["suite"];
 if(suite!="AES256-GCM"&&suite!="AES128-GCM")throw std::runtime_error("insecure suite");
 if(!r.recv(m)||m["type"]!="CERT")throw std::runtime_error("v2 cert failure");
 auto pub=slink::b64dec(m["pubkey"]);if(pub!=slink::b64dec(cfg.at("rsa_pub_b64")))throw std::runtime_error("pin mismatch");
 EVP_PKEY*dev=pki::load_pub(pub);if(!pki::verify(dev,m["name"]+pub,slink::from_hex(m["sig"])))throw std::runtime_error("bad cert");
 slink::send_msg(s,{{"type","PAIR"},{"hub",cfg.at("hub_id")},{"pinhash",slink::md5hex(cfg.at("pin"))}});
 if(!r.recv(m)||m["type"]!="DH")throw std::runtime_error("v2 DH failure");
 auto B=m["B"];if(!pki::verify(dev,offer+"|"+suite+"|"+B,slink::from_hex(m["sig"])))throw std::runtime_error("bad DH signature");
 EVP_PKEY_free(dev);
 std::string apriv,apub;dh2048::keygen(apriv,apub);slink::send_msg(s,{{"type","DHCLIENT"},{"A",apub}});
 auto shared=dh2048::shared(B,apriv);auto s2c=sl2::derive_key(shared,suite,"s2c");auto c2s=sl2::derive_key(shared,suite,"c2s");
 if(!r.recv(m)||m["type"]!="MSG")throw std::runtime_error("v2 greeting failure");
 auto greeting=sl2::open_record(s2c,slink::from_hex(m["rec"]),0);
 if(greeting.find("Paired with SmartLock")!=0)throw std::runtime_error("unexpected v2 greeting");
 auto stop=Clock::now();row("v2","handshake_us",run,elapsed_us(start,stop),"us");
 slink::send_msg(s,{{"type","MSG"},{"rec",slink::to_hex(sl2::seal(c2s,0,"QUIT"))}});
 close(s);
}
static void records(const std::map<std::string,std::string>& cfg,const std::string& version,int n,int runs){
 if(n<10000||runs<5)throw std::runtime_error("need at least 10000 records and 5 runs");
 std::string pt(1024,'A');for(int i=0;i<1024;++i)pt[i]=char('A'+(i%23));
 auto nonce=slink::from_hex(cfg.at("static_nonce"));
 Bytes k1=slink::session_key(0x123456789ULL,"AES256-GCM");
 Bytes seed(256);for(size_t i=0;i<seed.size();++i)seed[i]=uint8_t((i*7+19)&255);
 Bytes k2=sl2::derive_key(seed,"AES256-GCM","c2s");
 // Record wire overhead: tab-separated key:value protocol, hex-encoded record payload.
 auto sample=version=="v1"?slink::record_encrypt("AES256-GCM",k1,nonce,pt):sl2::seal(k2,0,pt);
 auto wire=version=="v1"? std::string("ct:")+slink::to_hex(sample)+"\tnonce:"+cfg.at("static_nonce")+"\ttype:MSG\n" : std::string("rec:")+slink::to_hex(sample)+"\ttype:MSG\n";
 row(version,"wire_record_bytes",0,double(wire.size()),"bytes");
 row(version,"wire_overhead_bytes",0,double(wire.size())-pt.size(),"bytes");
 std::vector<Bytes> samples; samples.reserve(n);
 for(int run=1;run<=runs;++run){
  samples.clear();auto t0=Clock::now();
  for(int i=0;i<n;++i){if(version=="v1")samples.push_back(slink::record_encrypt("AES256-GCM",k1,nonce,pt));else samples.push_back(sl2::seal(k2,(uint64_t)i,pt));}
  auto t1=Clock::now();
  for(int i=0;i<n;++i){auto recovered=(version=="v1"?slink::record_decrypt("AES256-GCM",k1,nonce,samples[i]):sl2::open_record(k2,samples[i],(uint64_t)i));if(recovered!=pt)throw std::runtime_error("record roundtrip failed");}
  auto t2=Clock::now();double enc=elapsed_us(t0,t1),dec=elapsed_us(t1,t2);double mb=double(n*pt.size())/1000000.;
  row(version,"protect_us_per_record",run,enc/n,"us");row(version,"open_us_per_record",run,dec/n,"us");
  row(version,"protect_MBps",run,mb/(enc/1000000.),"MBps");row(version,"open_MBps",run,mb/(dec/1000000.),"MBps");
 }
}
int main(int argc,char**argv){
 try{
 if(argc<5){std::cerr<<"Usage: benchmark handshake VERSION INSTANCE HOST COUNT | records VERSION INSTANCE N RUNS\n";return 1;}
 std::string mode=argv[1],version=argv[2];if(version!="v1"&&version!="v2")throw std::runtime_error("bad version");
 auto cfg=slink::read_config(argv[3]);std::cout<<"version,metric,run,value,unit\n";
 if(mode=="handshake"){
  if(argc!=6)throw std::runtime_error("handshake args");
  int n=std::stoi(argv[5]);if(n<30)throw std::runtime_error("at least 30 handshake runs");
  for(int i=1;i<=n;++i){if(version=="v1")handshake_v1(cfg,argv[4],std::stoi(cfg.at("port")),i);else handshake_v2(cfg,argv[4],std::stoi(cfg.at("port")),i);}
 }else if(mode=="records"){
  if(argc!=6)throw std::runtime_error("records args");
  records(cfg,version,std::stoi(argv[4]),std::stoi(argv[5]));
 }else throw std::runtime_error("unknown mode");
 }catch(const std::exception&e){std::cerr<<"ERROR: "<<e.what()<<"\n";return 2;}
}
