#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <queue>
#include <condition_variable>

// OpenSSL for HMAC/SHA-256 (Apache-2.0)
#include <openssl/evp.h>
#include <openssl/hmac.h>

// nlohmann/json (MIT) — place json.hpp next to this file or point -I to it
#include "json.hpp"
using json = nlohmann::json;

#ifdef WITH_OQS
#include <oqs/oqs.h>
#endif

using namespace std::chrono_literals;


// Forward declarations for CLI dependencies
struct Config;
extern const char* JADA_VERSION;

// -------------------- Simple CLI utilities --------------------
struct CliTarget { std::string host="127.0.0.1"; uint16_t port=0; };

static bool parse_hostport(const std::string& s, uint16_t default_port, std::string& host_out, uint16_t& port_out){
    std::string host=s; std::string portstr;
    // strip scheme if present: e.g., http://host:port/path
    size_t pos_scheme = host.find("://");
    if (pos_scheme != std::string::npos) host = host.substr(pos_scheme+3);
    // cut path if present
    size_t pos_path = host.find('/');
    if (pos_path != std::string::npos) host = host.substr(0, pos_path);
    // IPv6 [host]:port
    if (!host.empty() && host.front()=='['){
        size_t rb = host.find(']');
        if (rb != std::string::npos){
            std::string inside = host.substr(1, rb-1);
            if (rb+1 < host.size() && host[rb+1]==':') portstr = host.substr(rb+2);
            host = inside;
        }
    } else {
        // host:port (last colon wins to tolerate IPv6 without brackets poorly)
        size_t colon = host.rfind(':');
        if (colon != std::string::npos && colon+1 < host.size()){
            portstr = host.substr(colon+1);
            // if port isn't numeric, treat as no port (domain with colon in name is rare)
            bool numeric = !portstr.empty() && std::all_of(portstr.begin(), portstr.end(), ::isdigit);
            if (numeric) host = host.substr(0, colon);
            else portstr.clear();
        }
    }
    if (host.empty()) host = "127.0.0.1";
    host_out = host;
    if (!portstr.empty()) { try { port_out = (uint16_t)std::stoi(portstr); } catch(...) { port_out = default_port; } }
    else port_out = default_port;
    return true;
}

static bool cli_connect_and_exchange_dns(const std::string& host, uint16_t port,
                                         const std::string& line, std::string& out){
    struct addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    struct addrinfo* res=nullptr;
    std::string portstr = std::to_string(port);
    int rc = getaddrinfo(host.c_str(), portstr.c_str(), &hints, &res);
    if (rc != 0) return false;
    int fd = -1; struct addrinfo* p;
    for (p = res; p != nullptr; p = p->ai_next){
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        ::close(fd); fd = -1;
    }
    if (res) freeaddrinfo(res);
    if (fd < 0) return false;
    std::string msg = line; if (msg.empty() || msg.back()!='\n') msg.push_back('\n');
    if (send(fd, msg.data(), msg.size(), 0) < 0){ ::close(fd); return false; }
    // read until newline
    char buf[8192]; out.clear();
    for(;;){
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.append(buf, buf+n);
        if (!out.empty() && out.back()=='\n') break;
    }
    ::close(fd);
    return !out.empty();
}

static std::vector<std::string> cli_split_args(const std::string& s){
    std::vector<std::string> a; std::string cur; bool inq=false; char q=0; bool esc=false;
    for(char c: s){
        if (esc){ cur.push_back(c); esc=false; continue; }
        if (c=='\\'){ esc=true; continue; }
        if (inq){
            if (c==q){ inq=false; continue; }
            cur.push_back(c); continue;
        }
        if (c=='"' || c=='\''){ inq=true; q=c; continue; }
        if (c==' ' || c=='\t'){
            if (!cur.empty()){ a.push_back(cur); cur.clear(); }
            continue;
        }
        cur.push_back(c);
    }
    if (!cur.empty()) a.push_back(cur);
    return a;
}

static bool run_cli(int api_port, const std::optional<std::string>& cli_target_opt){
    CliTarget tgt;
    tgt.port = (uint16_t)api_port;
    bool detached=false;
    if (cli_target_opt){
        parse_hostport(*cli_target_opt, (uint16_t)api_port, tgt.host, tgt.port);
    }
    std::cout << "🐶 Jada " << JADA_VERSION << "\n";
    std::cout << "CLI target: " << tgt.host << ":" << tgt.port << "\n";
    std::cout << "Type 'help' for commands. Ctrl-D or 'exit' to quit. Use 'detach' to leave the CLI and keep the node running.\n";
    std::string line;
    while (std::cout << "jada> " && std::getline(std::cin, line)){
        std::string s; for(char& c: line) if (c=='\r') c=' ';
        auto args = cli_split_args(line);
        if (args.empty()) continue;
        auto cmd = args[0];
        if (cmd=="exit" || cmd=="quit"){ detached=false; break; }
        if (cmd=="detach"){ detached=true; break; }
        if (cmd=="help"){
            std::cout
              << "Commands:\n"
              << "  put <key> <value> [ttl=SECONDS] [infinite=true|false]\n"
              << "  get <key>\n"
              << "  group.put <group> <k=v> [k=v ...] [ttl=SECONDS] [infinite=true|false]\n"
              << "  group.get <group>\n"
              << "  nearest <hex_target>\n"
              << "  cli [host[:port]|url]   show or set CLI target\n"
              << "  help, exit, quit\n";
            continue;
        }
        if (cmd=="cli"){
            if (args.size()==1){
                std::cout<<"CLI target: "<<tgt.host<<":"<<tgt.port<<"\n";
                continue;
            } else {
                std::string host_in=args[1]; std::string h; uint16_t p;
                if (!parse_hostport(host_in, (uint16_t)api_port, h, p)){
                    std::cout<<"error: invalid host:port\n"; continue;
                }
                tgt.host=h; tgt.port=p;
                std::cout<<"CLI target set to: "<<tgt.host<<":"<<tgt.port<<"\n";
                continue;
            }
        }
        json j;
        if (cmd=="put"){
            if (args.size()<3){ std::cout<<"error: put requires <key> <value>\n"; continue; }
            j["op"]="put"; j["key"]=args[1]; j["value"]=args[2];
            for (size_t i=3;i<args.size();++i){
                if (args[i].rfind("ttl=",0)==0) j["ttl"]=std::stoi(args[i].substr(4));
                else if (args[i].rfind("infinite=",0)==0){ auto v=args[i].substr(9); j["infinite"]=(v=="true"||v=="1"); }
            }
        } else if (cmd=="get"){
            if (args.size()<2){ std::cout<<"error: get requires <key>\n"; continue; }
            j["op"]="get"; j["key"]=args[1];
        } else if (cmd=="group.put"){
            if (args.size()<3){ std::cout<<"error: group.put requires <group> and at least one k=v pair\n"; continue; }
            j["op"]="group.put"; j["group"]=args[1]; j["items"]=json::array();
            size_t i=2;
            for (; i<args.size(); ++i){
                if (args[i].find('=')==std::string::npos) break;
                auto pos=args[i].find('=');
                std::string k=args[i].substr(0,pos), v=args[i].substr(pos+1);
                j["items"].push_back({{"key",k},{"value",v}});
            }
            for (; i<args.size(); ++i){
                if (args[i].rfind("ttl=",0)==0) j["ttl"]=std::stoi(args[i].substr(4));
                else if (args[i].rfind("infinite=",0)==0){ auto v=args[i].substr(9); j["infinite"]=(v=="true"||v=="1"); }
            }
        } else if (cmd=="group.get"){
            if (args.size()<2){ std::cout<<"error: group.get requires <group>\n"; continue; }
            j["op"]="group.get"; j["group"]=args[1];
        } else if (cmd=="nearest"){
            if (args.size()<2){ std::cout<<"error: nearest requires <hex_target>\n"; continue; }
            j["op"]="nearest"; j["target"]=args[1];
        } else {
            std::cout<<"error: unknown command '"<<cmd<<"' (type 'help')\n"; continue;
        }
        std::string resp;
        std::string payload = j.dump();
        if (!cli_connect_and_exchange_dns(tgt.host, tgt.port, payload, resp)){
            std::cout<<"error: failed to reach API at "<<tgt.host<<":"<<tgt.port<<"\n";
            continue;
        }
        std::cout<<resp;
    }
    return detached;
}
// -------------------- Globals for ID sizing --------------------
static int   g_id_bits  = 160; // default
static int   g_id_bytes = 20;  // derived
static void  set_id_bits(int bits){ g_id_bits = (bits==128?128:160); g_id_bytes = g_id_bits/8; }

// -------------------- Helpers --------------------
static inline std::string readFile(const std::string& path){
    std::ifstream f(path);
    std::stringstream ss; ss<<f.rdbuf(); return ss.str();
}
static inline std::string trim(const std::string& s){
    size_t a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    return s.substr(a, b - a + 1);
}
static uint64_t nowMs(){
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

static std::string hexOf(const uint8_t* p, size_t n){
    std::ostringstream oss; oss<<std::hex<<std::setfill('0');
    for(size_t i=0;i<n;i++) oss<<std::setw(2)<<(int)p[i];
    return oss.str();
}
static std::string binToHex(const std::string& s){ return hexOf(reinterpret_cast<const uint8_t*>(s.data()), s.size()); }
static int hv(char c){
    if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return 10+(c-'a');
    if(c>='A'&&c<='F')return 10+(c-'A'); return -1;
}

// -------------------- Config --------------------
struct Config {
    int K = 20;
    int ALPHA = 3;
    int REQUEST_TIMEOUT_MS = 3000;
    int REPUBLISH_PERIOD_SEC = 3600;
    int VALUE_TTL_SEC = 86400;
    int SNAPSHOT_PERIOD_SEC = 300;
    int rpc_port = 5555;
    int api_port = 8080;
    std::string snapshot_path;
    std::string secret;
    std::vector<std::string> bootstrap;
    std::optional<std::string> node_id_hex;
    int id_bits = 160;            // 128 or 160
    bool pq_sign = false;         // enable if built WITH_OQS (experimental)
    std::string pq_scheme = "DILITHIUM_2";
};

static Config loadConfig(const std::string& path){
    Config cfg; std::string js = readFile(path); if (js.empty()) { set_id_bits(cfg.id_bits); return cfg; }
    try{
        auto j = json::parse(js);
        auto get = [&](const char* k){ return j.contains(k); };
        if (get("K")) cfg.K = (int)j["K"].get<int>();
        if (get("ALPHA")) cfg.ALPHA = (int)j["ALPHA"].get<int>();
        if (get("request_timeout_ms")) cfg.REQUEST_TIMEOUT_MS = (int)j["request_timeout_ms"].get<int>();
        if (get("republish_period_sec")) cfg.REPUBLISH_PERIOD_SEC = (int)j["republish_period_sec"].get<int>();
        if (get("value_ttl_sec")) cfg.VALUE_TTL_SEC = (int)j["value_ttl_sec"].get<int>();
        if (get("snapshot_period_sec")) cfg.SNAPSHOT_PERIOD_SEC = (int)j["snapshot_period_sec"].get<int>();
        if (get("rpc_port")) cfg.rpc_port = (int)j["rpc_port"].get<int>();
        if (get("api_port")) cfg.api_port = (int)j["api_port"].get<int>();
        if (get("snapshot_path")) cfg.snapshot_path = j["snapshot_path"].get<std::string>();
        if (get("secret")) cfg.secret = j["secret"].get<std::string>();
        if (get("bootstrap")) cfg.bootstrap = j["bootstrap"].get<std::vector<std::string>>();
        if (get("node_id")) cfg.node_id_hex = j["node_id"].get<std::string>();
        if (get("id_bits")) cfg.id_bits = (int)j["id_bits"].get<int>();
        if (get("pq_sign")) cfg.pq_sign = j["pq_sign"].get<bool>();
        if (get("pq_scheme")) cfg.pq_scheme = j["pq_scheme"].get<std::string>();
    } catch(...){}
    set_id_bits(cfg.id_bits);
    return cfg;
}

// -------------------- NodeID (variable length) --------------------
struct NodeID {
    std::vector<uint8_t> b; // size = g_id_bytes
    NodeID(){ b.resize(g_id_bytes); }
    explicit NodeID(const std::vector<uint8_t>& v){ b=v; if ((int)b.size()!=g_id_bytes) b.resize(g_id_bytes,0); }
    std::string hex() const {
        std::ostringstream oss; oss<<std::hex<<std::setfill('0');
        for(int i=0;i<g_id_bytes;i++) oss<<std::setw(2)<<(int)b[i];
        return oss.str();
    }
    static NodeID fromHex(const std::string& h){
        NodeID id; std::string s=h; int need = g_id_bytes*2;
        if ((int)s.size()<need) s = std::string(need - (int)s.size(),'0') + s;
        for (int i=0;i<g_id_bytes;i++){
            int hi=hv(s[2*i]), lo=hv(s[2*i+1]);
            if (hi<0||lo<0){ id.b[i]=0; } else id.b[i]=(uint8_t)((hi<<4)|lo);
        }
        return id;
    }
    static NodeID random(){
        NodeID id; std::random_device rd; for (int i=0;i<g_id_bytes;i++) id.b[i]=(uint8_t)rd();
        return id;
    }
    
};

static inline bool closerByXor(const NodeID& a, const NodeID& b, const NodeID& tgt){
    for (int i=0;i<g_id_bytes;i++){
        uint8_t xa=a.b[i]^tgt.b[i], xb=b.b[i]^tgt.b[i];
        if (xa!=xb) return xa<xb;
    }
    return false;
}

// -------------------- Crypto (OpenSSL HMAC) --------------------
static std::string hmac_sha256_hex(const std::string& key, const std::string& msg){
    unsigned int len=0; unsigned char mac[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), key.data(), (int)key.size(),
         (const unsigned char*)msg.data(), msg.size(), mac, &len);
    return hexOf(mac, len);
}

// -------------------- Optional PQ signatures (liboqs) --------------------
struct PQKeypair {
    bool enabled=false; std::string scheme; std::string pub; std::string priv;
#ifdef WITH_OQS
    OQS_SIG* sig=nullptr; ~PQKeypair(){ if (sig) { OQS_SIG_free(sig); } }
#endif
};

#ifdef WITH_OQS
static bool pq_init(PQKeypair& kp, const std::string& scheme){
    kp.sig = OQS_SIG_new(scheme.c_str()); if (!kp.sig) return false;
    std::vector<uint8_t> pub(kp.sig->length_public_key), priv(kp.sig->length_secret_key);
    if (OQS_SIG_keypair(kp.sig, pub.data(), priv.data()) != OQS_SUCCESS) return false;
    kp.pub.assign((char*)pub.data(), (char*)pub.data()+pub.size());
    kp.priv.assign((char*)priv.data(), (char*)priv.data()+priv.size());
    kp.scheme = scheme; kp.enabled = true; return true;
}
static std::string pq_sign(const PQKeypair& kp, const std::string& msg){
    if (!kp.enabled) return {};
    std::vector<uint8_t> sig(kp.sig->length_signature); size_t siglen=0;
    if (OQS_SIG_sign(kp.sig, sig.data(), &siglen, (const uint8_t*)msg.data(), msg.size(),
                     (const uint8_t*)kp.priv.data())!=OQS_SUCCESS) return {};
    return std::string((char*)sig.data(), (char*)sig.data()+siglen);
}
static bool pq_verify(const PQKeypair& kp, const std::string& msg, const std::string& sig){
    if (!kp.enabled) return false;
    return OQS_SIG_verify(kp.sig, (const uint8_t*)msg.data(), msg.size(),
                          (const uint8_t*)sig.data(), sig.size(),
                          (const uint8_t*)kp.pub.data())==OQS_SUCCESS;
}
#else
static bool pq_init(PQKeypair& kp, const std::string& scheme){ (void)kp;(void)scheme; return false; }
static std::string pq_sign(const PQKeypair& kp, const std::string& msg){ (void)kp;(void)msg; return {}; }
static bool pq_verify(const PQKeypair& kp, const std::string& msg, const std::string& sig){ (void)kp;(void)msg;(void)sig; return false; }
#endif

// -------------------- Routing table --------------------
struct Contact { NodeID id; std::string ip; uint16_t port{}; std::chrono::steady_clock::time_point lastSeen{}; };

struct RoutingTable{
    NodeID self; int K; struct Bucket{ std::deque<Contact> q; };
    std::vector<Bucket> buckets; std::mutex mtx;
    RoutingTable(const NodeID& s, int k):self(s),K(k),buckets(g_id_bits){}
    int prefixLen(const NodeID& id){
        int d=0; for (int i=0;i<g_id_bytes;i++){
            uint8_t x=self.b[i]^id.b[i]; if (!x){ d+=8; continue; }
            while((x & 0x80)==0){ d++; x<<=1; } break;
        } return d;
    }
    template <class PingCb>
    void insert(const Contact& c, PingCb ping_cb){
        std::scoped_lock lk(mtx); int b=std::clamp(prefixLen(c.id),0,g_id_bits-1); auto& buck=buckets[b];
        for (auto it=buck.q.begin(); it!=buck.q.end(); ++it){
            if (it->id.hex()==c.id.hex()){ Contact t=*it; t.ip=c.ip; t.port=c.port; t.lastSeen=std::chrono::steady_clock::now(); buck.q.erase(it); buck.q.push_back(t); return; }
        }
        if ((int)buck.q.size()<K){ Contact t=c; t.lastSeen=std::chrono::steady_clock::now(); buck.q.push_back(t); return; }
        auto lru=buck.q.front(); if (!ping_cb(lru)){ buck.q.pop_front(); Contact t=c; t.lastSeen=std::chrono::steady_clock::now(); buck.q.push_back(t); }
    }
    std::vector<Contact> nearest(const NodeID& target, int limit){
        std::scoped_lock lk(mtx); std::vector<Contact> all;
        for (auto& b: buckets) for (auto& c: b.q) all.push_back(c);
        std::sort(all.begin(), all.end(), [&](const Contact&a,const Contact&b){ return closerByXor(a.id,b.id,target); });
        std::vector<Contact> out; std::set<std::string> seen;
        for (auto& c: all){ if (seen.insert(c.id.hex()).second){ out.push_back(c); if ((int)out.size()>=limit) break; } }
        return out;
    }
    std::string toJSON(){
        std::scoped_lock lk(mtx); json j; j["self"]=self.hex(); j["K"]=K; j["id_bits"]=g_id_bits; j["buckets"]=json::array();
        for (int i=0;i<g_id_bits;i++){ json arr=json::array(); for (auto& c: buckets[i].q) arr.push_back({{"id",c.id.hex()},{"ip",c.ip},{"port",c.port}}); j["buckets"].push_back(arr); }
        return j.dump();
    }
    
};

// -------------------- KV store --------------------
struct ValueRecord{ std::string value; std::chrono::steady_clock::time_point expiresAt{}; bool infinite{false}; bool publisher{false}; };
struct KVStore{
    std::mutex mtx; std::unordered_map<std::string,ValueRecord> m;
    void put(const NodeID& key, const std::string& v, std::chrono::seconds ttl, bool infinite=false, bool publisher=false){
        std::scoped_lock lk(mtx); ValueRecord rec; rec.value=v; rec.infinite=infinite; rec.publisher=publisher;
        rec.expiresAt = infinite? std::chrono::steady_clock::time_point::max() : (std::chrono::steady_clock::now()+ttl);
        m[key.hex()] = rec;
    }
    std::optional<std::string> getFresh(const NodeID& key){
        std::scoped_lock lk(mtx); auto it=m.find(key.hex()); if (it==m.end()) return std::nullopt;
        if (!it->second.infinite && std::chrono::steady_clock::now()>it->second.expiresAt) return std::nullopt;
        return it->second.value;
    }
    std::vector<std::pair<NodeID,ValueRecord>> publishers(){
        std::scoped_lock lk(mtx); std::vector<std::pair<NodeID,ValueRecord>> v;
        for (auto& [h,rec]: m){ if (!rec.publisher) continue; NodeID id=NodeID::fromHex(h); v.push_back({id,rec}); }
        return v;
    }
    std::string toJSON(){ std::scoped_lock lk(mtx); json j; for (auto& [h,rec]: m){ j[h]={{"value",rec.value},{"infinite",rec.infinite}}; } return j.dump(); }
};

// -------------------- Wire protocol --------------------
enum MsgType: uint8_t { PING=1,PONG=2,FIND_NODE=3,FIND_NODE_RES=4,FIND_VALUE=5,FIND_VALUE_RES=6,STORE=7,STORE_ACK=8 };

struct RpcResponse{ MsgType type; NodeID from; std::string payload; sockaddr_in src{}; };

// -------------------- Simple thread pool --------------------
class ThreadPool{
    std::vector<std::thread> workers; std::mutex m; std::condition_variable cv; bool stop=false; std::queue<std::function<void()>> q;
public:
    explicit ThreadPool(size_t n){
        for(size_t i=0;i<n;i++){
            workers.emplace_back([this]{
                for(;;){
                    std::function<void()> job;
                    { std::unique_lock<std::mutex> lk(m);
                      cv.wait(lk,[&]{ return stop || !q.empty(); });
                      if (stop && q.empty()) return;
                      job=std::move(q.front()); q.pop();
                    }
                    job();
                }
            });
        }
    }
    ~ThreadPool(){ { std::scoped_lock lk(m); stop=true; } cv.notify_all(); for(auto& w:workers) if(w.joinable()) w.join(); }
    template<class F> void enqueue(F&& f){ { std::scoped_lock lk(m); q.emplace(std::forward<F>(f)); } cv.notify_one(); }
};

// -------------------- DHT Node --------------------
class DhtNode {
public:
    static constexpr size_t CFG_UDP_VALUE_MAX = 1024; // ~MTU-safe

    Config cfg; NodeID self; std::string pubkey; std::string secret; int sock{-1}; std::atomic<bool> running{false};
    RoutingTable rt; KVStore kv; PQKeypair pq;

    std::thread recvThread, republishThread, refreshThread, snapshotThread;
    std::thread apiAcceptThread; ThreadPool* apiWorkers{nullptr};

    std::mutex pendingMtx; struct Pending{ std::promise<RpcResponse> prom; uint64_t startMs; int timeoutMs; }; std::unordered_map<uint64_t, Pending> pending;

    ThreadPool lookupPool{4};

    DhtNode(const Config& c) : cfg(c), self(c.node_id_hex ? NodeID::fromHex(*c.node_id_hex) : NodeID::random()), rt(self, c.K) {
        secret = cfg.secret; pubkey = std::string("jada_pubkey_")+ self.hex(); if (cfg.pq_sign) { pq_init(pq, cfg.pq_scheme); }
    }
    ~DhtNode(){ if (apiWorkers){ delete apiWorkers; apiWorkers=nullptr; } }

    bool start(){
        sock = ::socket(AF_INET, SOCK_DGRAM, 0); if (sock<0){ perror("socket"); return false; }
        int yes=1; setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=htons(cfg.rpc_port); addr.sin_addr.s_addr=INADDR_ANY;
        if (bind(sock,(sockaddr*)&addr,sizeof(addr))<0){ perror("bind"); ::close(sock); sock=-1; return false; }
        running=true;
        recvThread = std::thread(&DhtNode::recvLoop,this);
        republishThread = std::thread(&DhtNode::republishLoop,this);
        refreshThread = std::thread(&DhtNode::refreshLoop,this);
        if (!cfg.snapshot_path.empty()) snapshotThread = std::thread(&DhtNode::snapshotLoop,this);
        apiWorkers = new ThreadPool(4);
        apiAcceptThread = std::thread(&DhtNode::apiLoop,this);
        std::cout << "[node] started id=" << self.hex()
                  << " (" << g_id_bits << "b) rpc_port=" << cfg.rpc_port
                  << " api_port=" << cfg.api_port
                  << " pq=" << (pq.enabled ? "on" : "off") << "\n";
        return true;
    }
    void stop(){
        if (!running) return; running=false;
        if (sock>=0){ ::shutdown(sock, SHUT_RDWR); ::close(sock); sock=-1; }
        if (recvThread.joinable()) recvThread.join();
        if (republishThread.joinable()) republishThread.join();
        if (refreshThread.joinable()) refreshThread.join();
        if (snapshotThread.joinable()) snapshotThread.join();
        if (apiAcceptThread.joinable()) apiAcceptThread.join();
    }

    bool bootstrapOne(const std::string& hostport){
        auto pos = hostport.find(':');
        if (pos==std::string::npos) return false;
        std::string ip=hostport.substr(0,pos); uint16_t p=(uint16_t)std::stoi(hostport.substr(pos+1));
        sockaddr_in dest{}; dest.sin_family=AF_INET; dest.sin_port=htons(p); inet_pton(AF_INET, ip.c_str(), &dest.sin_addr);
        auto r = request(PING, pubkey, dest); if (!r || r->type!=PONG) return false;
        Contact c; c.id=r->from; c.ip=ip; c.port=p;
        rt.insert(c, [&](const Contact& who){ return pingContact(who); });
        iterativeFindNode(self);
        return true;
    }

    // --------------- JSON API (TCP, worker pool) ---------------
    static ssize_t sendall(int fd, const char* buf, size_t len){
        size_t off=0; while(off<len){
            ssize_t n=::send(fd, buf+off, len-off, 0);
            if (n<0){ if (errno==EINTR) continue; return -1; }
            if (n==0) return off; off+=n;
        } return off;
    }

    // Multi-line JSON framing using brace/quote state machine
    static std::vector<std::string> frameJsonChunks(std::string& buffer){
        std::vector<std::string> out;
        size_t i=0;
        int depth=0;
        bool inStr=false;
        bool esc=false;
        size_t start=std::string::npos;

        while (i<buffer.size()){
            char c=buffer[i];
            if (!inStr){
                if (c=='"'){ inStr=true; }
                else if (c=='{'){ if (depth==0) start=i; depth++; }
                else if (c=='}'){
                    if (depth>0){
                        depth--;
                        if (depth==0 && start!=std::string::npos){
                            out.push_back(buffer.substr(start, i-start+1));
                            start=std::string::npos;
                        }
                    }
                }
            } else {
                if (esc) { esc=false; }
                else if (c=='\\') { esc=true; }
                else if (c=='"') { inStr=false; }
            }
            ++i;
        }

        if (!out.empty()){
            size_t lastEnd = buffer.rfind(out.back());
            buffer.erase(0, lastEnd + out.back().size());
        } else if (buffer.size() > (1u<<20)) {
            buffer.clear();
        }
        return out;
    }

    void apiLoop(){
        int s = ::socket(AF_INET, SOCK_STREAM, 0); if (s<0) return;
        int yes=1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        sockaddr_in a{}; a.sin_family=AF_INET; a.sin_port=htons(cfg.api_port); a.sin_addr.s_addr=INADDR_ANY;
        if (bind(s,(sockaddr*)&a,sizeof(a))<0){ perror("api bind"); ::close(s); return; }
        if (listen(s, 64)<0){ perror("listen"); ::close(s); return; }
        std::cout << "[api] listening on " << cfg.api_port << " (framed JSON; multiline OK)\n";
        while (running){
            sockaddr_in cli{}; socklen_t cl=sizeof(cli);
            int cfd = accept(s,(sockaddr*)&cli,&cl); if (cfd<0) continue;
            fcntl(cfd, F_SETFL, O_NONBLOCK);
            apiWorkers->enqueue([this,cfd]{ handleClient(cfd); });
        }
        ::close(s);
    }
    void handleClient(int cfd){
        std::string buffer; char tmp[2048];
        for(;;){
            ssize_t n = recv(cfd, tmp, sizeof(tmp), 0);
            if (n<0){ if (errno==EAGAIN||errno==EWOULDBLOCK){ std::this_thread::sleep_for(10ms); continue; } break; }
            if (n==0) break;
            buffer.append(tmp, tmp+n);
            auto msgs = frameJsonChunks(buffer);
            for (auto& m: msgs){
                std::string resp = handleJson(m);
                resp.push_back('\n');
                if (sendall(cfd, resp.data(), resp.size())<0) { break; }
            }
        }
        ::close(cfd);
    }

    static std::string ok(const json& j){ json r = j; r["ok"]=true; return r.dump(); }
    static std::string err(const std::string& e){ json r; r["ok"]=false; r["error"]=e; return r.dump(); }

    static NodeID groupIndexKey(const std::string& name){
        unsigned char md[EVP_MAX_MD_SIZE]; unsigned int mdlen=0; std::string msg = std::string("group:")+name;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new(); EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr); EVP_DigestUpdate(ctx, msg.data(), msg.size()); EVP_DigestFinal_ex(ctx, md, &mdlen); EVP_MD_CTX_free(ctx);
        NodeID id; for(int i=0;i<g_id_bytes;i++) id.b[i]=md[i]; return id;
    }

    // Interpret user-provided "key": if hex, use it; else hash text to NodeID
    static NodeID parseUserKey(const std::string& keyStr){
        auto is_hex = [](char c){ return (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'); };
        bool hexlike = !keyStr.empty();
        for(char c : keyStr){ if (!is_hex(c)) { hexlike=false; break; } }
        if (hexlike){
            return NodeID::fromHex(keyStr);
        } else {
            unsigned char md[EVP_MAX_MD_SIZE]; unsigned int mdlen=0;
            EVP_MD_CTX* ctx = EVP_MD_CTX_new(); EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
            EVP_DigestUpdate(ctx, keyStr.data(), keyStr.size());
            EVP_DigestFinal_ex(ctx, md, &mdlen); EVP_MD_CTX_free(ctx);
            NodeID id; for(int i=0;i<g_id_bytes;i++) id.b[i]=md[i]; return id;
        }
    }

    // Token = HMAC(secret, NodeID||rpc_port||timeslice)
    std::string issueToken(){
        using std::chrono::system_clock;
        auto now=system_clock::now(); auto mins = std::chrono::duration_cast<std::chrono::minutes>(now.time_since_epoch()).count();
        long slice = mins/5; std::ostringstream msg; msg<<self.hex()<<":"<<cfg.rpc_port<<":"<<slice; return hmac_sha256_hex(secret, msg.str());
    }
    bool verifyToken(const std::string& token, const NodeID& claimed){
        using std::chrono::system_clock;
        auto now=system_clock::now(); auto mins = std::chrono::duration_cast<std::chrono::minutes>(now.time_since_epoch()).count();
        for (long d=-1; d<=1; ++d){
            long slice=(mins/5)+d; std::ostringstream msg; msg<<claimed.hex()<<":"<<cfg.rpc_port<<":"<<slice;
            if (token==hmac_sha256_hex(secret, msg.str())) return true;
        } return false;
    }

    // Serialize/deserialize node lists (carry idLen per contact)
    static std::string serNode(const Contact& c){
        std::string s; if (c.ip.size()>255) return {};
        s.push_back((char)c.ip.size()); s+=c.ip;
        uint16_t p = htons(c.port); s.append((char*)&p,(char*)&p+2);
        s.push_back((char)g_id_bytes);
        s.append((char*)c.id.b.data(), (char*)c.id.b.data()+g_id_bytes);
        return s;
    }
    static std::optional<Contact> desNode(const char* &p, const char* end){
        if (p>=end) return std::nullopt; uint8_t L=(uint8_t)*p++;
        if (end-p < L+2+1) return std::nullopt; Contact c;
        c.ip.assign(p,p+L); p+=L; uint16_t port; std::memcpy(&port,p,2); p+=2; c.port=ntohs(port);
        uint8_t idL=(uint8_t)*p++; if (end-p < idL) return std::nullopt;
        c.id = NodeID(); c.id.b.assign((uint8_t*)p,(uint8_t*)p+idL);
        if ((int)c.id.b.size()!=g_id_bytes) c.id.b.resize(g_id_bytes,0);
        p+=idL; return c;
    }
    static std::string serNodeList(const std::vector<Contact>& v, int K){
        std::string s; s.push_back((char)std::min<int>((int)v.size(),K)); for (int i=0;i<(int)v.size() && i<K;i++) s+=serNode(v[i]); return s;
    }
    static std::vector<Contact> desNodeList(const char* p, const char* end){
        std::vector<Contact> out; if (p>=end) return out; uint8_t n=(uint8_t)*p++; for (int i=0;i<n;i++){ auto c=desNode(p,end); if (!c) break; out.push_back(*c); } return out;
    }

    // --------------- JSON handlers ---------------
    std::string handleJson(const std::string& js){
        json j; try{ j = json::parse(js); } catch(...){ return err("invalid_json"); }
        if (!j.contains("op")) return err("missing op"); std::string op=j["op"].get<std::string>();

        if (op=="put"){
            if(!j.contains("key")||!j.contains("value")) return err("missing key or value");
            NodeID key = parseUserKey(j["key"].get<std::string>());
            std::string val = j["value"].get<std::string>();
            bool infinite=j.value("infinite",false); int ttl=j.value("ttl",  cfg.VALUE_TTL_SEC);
            if (val.size()>CFG_UDP_VALUE_MAX) return err("value too large (>1024B)");
            kv.put(key, val, std::chrono::seconds(ttl), infinite, true);
            auto nodes = iterativeFindNode(key);
            std::string tok = issueToken();
            for (auto& c: nodes) rpcStore(c, key, val, (uint32_t)ttl, infinite, tok);
            return ok({{"msg","stored"},{"key",key.hex()},{"value",val},{"infinite",infinite}});
        } else if (op=="get"){
            if(!j.contains("key")) return err("missing key");
            NodeID key = parseUserKey(j["key"].get<std::string>());
            if (auto v=kv.getFresh(key)) return ok({{"value",*v}});
            if (auto r=iterativeFindValue(key)) return ok({{"value",*r}});
            return err("not_found");
        } else if (op=="group.put"){
            if(!j.contains("group")||!j.contains("items")) return err("missing group/items");
            std::string gname=j["group"].get<std::string>();
            auto items=j["items"].get<std::vector<json>>();
            bool infinite=j.value("infinite",false); int ttl=j.value("ttl",  cfg.VALUE_TTL_SEC);
            std::vector<std::pair<NodeID,std::string>> kvs; kvs.reserve(items.size());
            for (auto& it : items){
                NodeID k = parseUserKey(it["key"].get<std::string>());
                std::string v=it["value"].get<std::string>();
                if (v.size()>CFG_UDP_VALUE_MAX) return err("value too large (>1024B)");
                kvs.push_back({k,v});
            }
            std::string tok = issueToken();
            for (auto& pr: kvs){
                kv.put(pr.first, pr.second, std::chrono::seconds(ttl), infinite, true);
                auto nodes = iterativeFindNode(pr.first);
                for (auto& c: nodes) rpcStore(c, pr.first, pr.second, (uint32_t)ttl, infinite, tok);
            }
            NodeID gkey = groupIndexKey(gname); json idx; idx["group"]=gname; idx["items"]=json::array();
            for (auto& pr: kvs) idx["items"].push_back(pr.first.hex());
            std::string idxs=idx.dump();
            kv.put(gkey, idxs, std::chrono::seconds(ttl), infinite, true);
            auto gnodes=iterativeFindNode(gkey); for (auto& c: gnodes) rpcStore(c, gkey, idxs, (uint32_t)ttl, infinite, tok);
            return ok({{"stored_group",gname}});
        } else if (op=="group.get"){
            if(!j.contains("group")) return err("missing group");
            std::string gname=j["group"].get<std::string>(); NodeID gkey=groupIndexKey(gname);
            std::optional<std::string> idx = kv.getFresh(gkey); if(!idx) if (auto r=iterativeFindValue(gkey)) idx=r; if (!idx) return err("not_found");
            json ij; try{ ij=json::parse(*idx);}catch(...){ return err("index_parse_error"); }
            std::vector<std::string> keys; if (ij.contains("items")) keys = ij["items"].get<std::vector<std::string>>();
            json out; out["ok"]=true; out["group"]=gname; out["items"]=json::array();
            for (auto& kh: keys){
                NodeID k=parseUserKey(kh); auto v=kv.getFresh(k); if (!v){ if (auto r=iterativeFindValue(k)) v=r; } if (!v) continue;
                out["items"].push_back({{"key",kh},{"value",*v}});
            }
            return out.dump();
        } else if (op=="nearest"){
            if(!j.contains("target")) return err("missing target"); NodeID target=NodeID::fromHex(j["target"].get<std::string>());
            auto v=rt.nearest(target, cfg.K); json o; o["ok"]=true; o["nodes"]=json::array();
            for (auto& c: v) o["nodes"].push_back({{"id",c.id.hex()},{"ip",c.ip},{"port",c.port}});
            return o.dump();
        } else {
            return err("unknown op");
        }
    }

    // --------------- DHT internals (dynamic header) ---------------
    // Build MAC input = rpcId(8)|type(1)|idLen(1)|payloadLen(2)|fromId|payload
    static std::string buildMacMsg(uint64_t rpcId, MsgType type, uint16_t payloadLen, const NodeID& from, const std::string& payload){
        std::string m; uint64_t be=htobe64(rpcId); m.append((char*)&be,(char*)&be+8);
        m.push_back((char)type); m.push_back((char)g_id_bytes);
        uint16_t pl=htons(payloadLen); m.append((char*)&pl,(char*)&pl+2);
        m.append((char*)from.b.data(), (char*)from.b.data()+g_id_bytes); m+=payload; return m;
    }

    static void writeHeader(std::string& buf, uint64_t rpcId, MsgType type, uint16_t payloadLen, const std::string& macHex, uint16_t sigLen){
        buf.resize(0); buf.reserve(8+1+1+2+32+2);
        uint64_t be = htobe64(rpcId); buf.append((char*)&be,(char*)&be+8); buf.push_back((char)type); buf.push_back((char)g_id_bytes);
        uint16_t pl=htons(payloadLen); buf.append((char*)&pl,(char*)&pl+2);
        // macHex (64 chars) -> 32 raw bytes
        std::string mac; mac.reserve(32);
        for (int i=0;i<64;i+=2){ int hi=hv(macHex[i]), lo=hv(macHex[i+1]); char b=(char)((hi<<4)|lo); mac.push_back(b); }
        buf.append(mac.data(), mac.data()+32);
        uint16_t sl=htons(sigLen); buf.append((char*)&sl,(char*)&sl+2);
    }

    std::optional<RpcResponse> request(MsgType type, const std::string& payload, const sockaddr_in& dest){
        uint64_t rpcId = rand64(); uint16_t paylen = (uint16_t)payload.size();
        std::string macMsg = buildMacMsg(rpcId, type, paylen, self, payload);
        std::string sig; if (pq.enabled){ sig = pq_sign(pq, macMsg); }
        std::string mac = hmac_sha256_hex(secret, macMsg);
        std::string buf; writeHeader(buf, rpcId, type, paylen, mac, (uint16_t)sig.size());
        buf.append((char*)self.b.data(), (char*)self.b.data()+g_id_bytes);
        if (!payload.empty()) buf.append(payload.data(), payload.data()+payload.size());
        if (!sig.empty()) buf.append(sig.data(), sig.data()+sig.size());
        std::promise<RpcResponse> prom; auto fut = prom.get_future();
        { std::scoped_lock lk(pendingMtx); pending[rpcId] = Pending{std::move(prom), nowMs(), cfg.REQUEST_TIMEOUT_MS}; }
        sendto(sock, buf.data(), buf.size(), 0, (sockaddr*)&dest, sizeof(dest));
        if (fut.wait_for(std::chrono::milliseconds(cfg.REQUEST_TIMEOUT_MS))==std::future_status::ready){ return fut.get(); }
        { std::scoped_lock lk(pendingMtx); pending.erase(rpcId); }
        return std::nullopt;
    }

    void reply(uint64_t rpcId, MsgType type, const std::string& payload, const sockaddr_in& dest){
        uint16_t paylen=(uint16_t)payload.size();
        std::string macMsg = buildMacMsg(rpcId, type, paylen, self, payload);
        std::string sig; if (pq.enabled){ sig=pq_sign(pq, macMsg); }
        std::string mac=hmac_sha256_hex(secret, macMsg);
        std::string buf; writeHeader(buf, rpcId, type, paylen, mac, (uint16_t)sig.size());
        buf.append((char*)self.b.data(), (char*)self.b.data()+g_id_bytes);
        if (!payload.empty()) buf.append(payload.data(), payload.data()+payload.size());
        if (!sig.empty()) buf.append(sig.data(), sig.data()+sig.size());
        sendto(sock, buf.data(), buf.size(), 0, (sockaddr*)&dest, sizeof(dest));
    }

    void recvLoop(){
        char buf[8192];
        while(running){
            sockaddr_in src{}; socklen_t sl=sizeof(src);
            ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&src, &sl);
            if (n<=0){ if (!running) break; continue; }
            const char* p=buf; const char* end=buf+n;
            if (end-p < 8+1+1+2+32+2) continue;
            uint64_t rpcId; std::memcpy(&rpcId,p,8); rpcId=be64toh(rpcId); p+=8;
            MsgType type=(MsgType)*p++; uint8_t idLen=(uint8_t)*p++;
            uint16_t payloadLen; std::memcpy(&payloadLen,p,2); payloadLen=ntohs(payloadLen); p+=2;
            std::string macRaw(p,p+32); p+=32; uint16_t sigLen; std::memcpy(&sigLen,p,2); sigLen=ntohs(sigLen); p+=2;
            if (end-p < idLen+payloadLen+sigLen) continue;
            NodeID from; from.b.assign((uint8_t*)p,(uint8_t*)p+idLen);
            if ((int)from.b.size()!=g_id_bytes) from.b.resize(g_id_bytes,0); p+=idLen;
            std::string payload(p,p+payloadLen); p+=payloadLen;
            std::string sig; if (sigLen) sig.assign(p,p+sigLen);

            // verify MAC
            std::string macMsg = buildMacMsg(rpcId, type, payloadLen, from, payload);
            std::string expectHex = hmac_sha256_hex(secret, macMsg);
            std::string expectRaw; expectRaw.reserve(32);
            for (int i=0;i<64;i+=2){ int hi=hv(expectHex[i]), lo=hv(expectHex[i+1]); expectRaw.push_back((char)((hi<<4)|lo)); }
            if (macRaw!=expectRaw) continue;
            if (pq.enabled && sigLen>0){ if (!pq_verify(pq, macMsg, sig)) continue; }

            switch(type){
                case PING: {
                    reply(rpcId, PONG, pubkey, src);
                } break;
                case PONG: {
                    fulfill(rpcId, type, payload, src, from);
                } break;
                case FIND_NODE: {
                    if ((int)payload.size()<g_id_bytes) break;
                    NodeID target; target.b.assign((uint8_t*)payload.data(), (uint8_t*)payload.data()+g_id_bytes);
                    auto near = rt.nearest(target, cfg.K); std::string pl = serNodeList(near, cfg.K); reply(rpcId, FIND_NODE_RES, pl, src);
                } break;
                case FIND_NODE_RES: {
                    fulfill(rpcId, type, payload, src, from);
                } break;
                case FIND_VALUE: {
                    if ((int)payload.size()<g_id_bytes) break;
                    NodeID key; key.b.assign((uint8_t*)payload.data(), (uint8_t*)payload.data()+g_id_bytes);
                    auto v=kv.getFresh(key);
                    if (v){
                        if (v->size()>CFG_UDP_VALUE_MAX){ reply(rpcId, FIND_VALUE_RES, std::string(), src); }
                        else { reply(rpcId, FIND_VALUE_RES, *v, src); }
                    } else {
                        auto near=rt.nearest(key, cfg.K); std::string pl=serNodeList(near, cfg.K); reply(rpcId, FIND_VALUE_RES, pl, src);
                    }
                } break;
                case FIND_VALUE_RES: {
                    fulfill(rpcId, type, payload, src, from);
                } break;
                case STORE: {
                    const char* q=payload.data(); const char* e=q+payload.size();
                    if (e-q < g_id_bytes+2+1+2) break;
                    NodeID key; key.b.assign((uint8_t*)q,(uint8_t*)q+g_id_bytes); q+=g_id_bytes;
                    uint16_t ttl; std::memcpy(&ttl,q,2); ttl=ntohs(ttl); q+=2;
                    uint8_t flags=*q++; uint16_t vlen; std::memcpy(&vlen,q,2); q+=2; vlen=ntohs(vlen);
                    if (e-q < vlen+64) break;
                    std::string val(q,q+vlen); q+=vlen; std::string tokenHex(q,q+64);
                    if (!verifyToken(tokenHex, from)) break; bool infinite = (flags & 1);
                    kv.put(key, val, std::chrono::seconds(ttl), infinite, false);
                    reply(rpcId, STORE_ACK, "", src);
                } break;
                case STORE_ACK: {
                    fulfill(rpcId, type, std::string(), src, from);
                } break;
                default: break;
            }

            Contact c; c.id=from; c.port=ntohs(src.sin_port);
            char ipbuf[64]; inet_ntop(AF_INET, &src.sin_addr, ipbuf, sizeof(ipbuf)); c.ip=ipbuf;
            rt.insert(c, [&](const Contact& who){ return pingContact(who); });
            cleanupPending();
        }
    }

    void fulfill(uint64_t rpcId, MsgType t, std::string payload, const sockaddr_in& src, const NodeID& from){
        std::scoped_lock lk(pendingMtx); auto it=pending.find(rpcId); if (it==pending.end()) return; RpcResponse r{t,from,payload,src}; it->second.prom.set_value(r); pending.erase(it);
    }
    void cleanupPending(){
        std::scoped_lock lk(pendingMtx); uint64_t n=nowMs();
        for (auto it=pending.begin(); it!=pending.end();){
            if (n - it->second.startMs > (uint64_t)it->second.timeoutMs) it=pending.erase(it); else ++it;
        }
    }

    bool pingContact(const Contact& who){
        sockaddr_in d{}; d.sin_family=AF_INET; d.sin_port=htons(who.port); inet_pton(AF_INET, who.ip.c_str(), &d.sin_addr);
        auto r = request(PING, pubkey, d); return r && r->type==PONG;
    }

    uint64_t rand64(){ static thread_local std::mt19937_64 g(std::random_device{}()); return g(); }

    // RPC helpers
    std::optional<std::vector<Contact>> rpcFindNode(const Contact& to, const NodeID& target){
        std::string pl; pl.append((char*)target.b.data(), (char*)target.b.data()+g_id_bytes);
        sockaddr_in d{}; d.sin_family=AF_INET; d.sin_port=htons(to.port); inet_pton(AF_INET, to.ip.c_str(), &d.sin_addr);
        auto r = request(FIND_NODE, pl, d); if (!r || r->type!=FIND_NODE_RES) return std::nullopt;
        const char* p=r->payload.data(); const char* end=p+r->payload.size(); return desNodeList(p,end);
    }
    std::optional<std::string> rpcFindValue(const Contact& to, const NodeID& key){
        std::string pl; pl.append((char*)key.b.data(), (char*)key.b.data()+g_id_bytes);
        sockaddr_in d{}; d.sin_family=AF_INET; d.sin_port=htons(to.port); inet_pton(AF_INET, to.ip.c_str(), &d.sin_addr);
        auto r = request(FIND_VALUE, pl, d); if (!r || r->type!=FIND_VALUE_RES) return std::nullopt;
        const char* p=r->payload.data(); const char* end=p+r->payload.size();
        if (r->payload.size()>=1 && (uint8_t)r->payload[0] <= cfg.K){ auto maybe=desNodeList(p,end); if (!maybe.empty()) return std::nullopt; }
        return r->payload;
    }
    void rpcStore(const Contact& to, const NodeID& key, const std::string& value, uint32_t ttl, bool infinite, const std::string& tokenHex){
        if (value.size()>CFG_UDP_VALUE_MAX) return; std::string pl;
        pl.append((char*)key.b.data(), (char*)key.b.data()+g_id_bytes);
        uint16_t t=htons((uint16_t)std::min<uint32_t>(ttl, 65535)); pl.append((char*)&t,(char*)&t+2);
        uint8_t flags = infinite?1:0; pl.push_back((char)flags);
        uint16_t vl=htons((uint16_t)value.size()); pl.append((char*)&vl,(char*)&vl+2); pl.append(value.data(), value.data()+value.size());
        std::string tok = tokenHex; if (tok.size()<64) tok.append(64-tok.size(),'0'); if (tok.size()>64) tok.resize(64); pl.append(tok.data(), tok.data()+64);
        sockaddr_in d{}; d.sin_family=AF_INET; d.sin_port=htons(to.port); inet_pton(AF_INET, to.ip.c_str(), &d.sin_addr);
        request(STORE, pl, d);
    }

    std::vector<Contact> iterativeFindNode(const NodeID& target){
        auto shortlist = rt.nearest(target, cfg.K); std::set<std::string> queried;
        auto bestId = shortlist.empty()? self : shortlist[0].id;
        while (true){
            std::vector<Contact> batch; for (auto& c : shortlist) if ((int)batch.size()<cfg.ALPHA && !queried.count(c.id.hex())) batch.push_back(c);
            if (batch.empty()) break;
            std::vector<std::future<std::optional<std::vector<Contact>>>> futs; futs.reserve(batch.size());
            for (auto& c: batch){
                queried.insert(c.id.hex());
                auto pr = std::make_shared<std::promise<std::optional<std::vector<Contact>>>>();
                auto fut=pr->get_future();
                lookupPool.enqueue([this,c,pr,target]() mutable { auto r = rpcFindNode(c, target); pr->set_value(r); });
                futs.push_back(std::move(fut));
            }
            bool anyCloser=false; for (auto& f: futs){ auto res=f.get(); if (!res) continue; for (auto& n: *res){ rt.insert(n, [&](const Contact& w){ return pingContact(w); }); shortlist.push_back(n); } }
            std::sort(shortlist.begin(), shortlist.end(), [&](const Contact&a,const Contact&b){ return closerByXor(a.id,b.id,target); });
            std::vector<Contact> ded; std::set<std::string> seen; for (auto& c: shortlist){ if (seen.insert(c.id.hex()).second){ ded.push_back(c); if ((int)ded.size()>=cfg.K) break; } }
            if (!ded.empty() && closerByXor(ded[0].id, bestId, target)){ anyCloser=true; bestId=ded[0].id; }
            shortlist.swap(ded);
            if (!anyCloser){
                std::vector<Contact> more; for (auto& c: shortlist) if (!queried.count(c.id.hex())) more.push_back(c);
                if (more.empty()) break; size_t budget=std::min<size_t>(cfg.K, more.size()); std::vector<std::future<std::optional<std::vector<Contact>>>> futs2;
                for (size_t i=0;i<budget; ++i){
                    auto c=more[i]; queried.insert(c.id.hex());
                    auto pr = std::make_shared<std::promise<std::optional<std::vector<Contact>>>>();
                    auto fut=pr->get_future();
                    lookupPool.enqueue([this,c,pr,target]() mutable { auto r = rpcFindNode(c, target); pr->set_value(r); });
                    futs2.push_back(std::move(fut));
                }
                for (auto& f: futs2){ auto res=f.get(); if (!res) continue; for (auto& n: *res){ rt.insert(n, [&](const Contact& w){ return pingContact(w); }); shortlist.push_back(n); } }
                std::sort(shortlist.begin(), shortlist.end(), [&](const Contact&a,const Contact&b){ return closerByXor(a.id,b.id,target); });
                std::vector<Contact> ded2; std::set<std::string> seen2; for (auto& c: shortlist){ if (seen2.insert(c.id.hex()).second){ ded2.push_back(c); if ((int)ded2.size()>=cfg.K) break; } } shortlist.swap(ded2);
                break;
            }
        }
        return shortlist;
    }

    std::optional<std::string> iterativeFindValue(const NodeID& key){
        auto shortlist = rt.nearest(key, cfg.K); std::set<std::string> queried;
        while(true){
            std::vector<Contact> batch; for (auto& c: shortlist) if ((int)batch.size()<cfg.ALPHA && !queried.count(c.id.hex())) batch.push_back(c);
            if (batch.empty()) break;
            std::vector<std::future<std::optional<std::string>>> futs;
            for (auto& c: batch){
                queried.insert(c.id.hex());
                auto pr = std::make_shared<std::promise<std::optional<std::string>>>();
                auto fut=pr->get_future();
                lookupPool.enqueue([this,c,pr,key]() mutable { auto r = rpcFindValue(c, key); pr->set_value(r); });
                futs.push_back(std::move(fut));
            }
            bool found=false; std::optional<std::string> val;
            for (auto& f: futs){
                auto res=f.get();
                if (res.has_value()){ val = *res; found=true; break; }
            }
            if (found){
                auto nodes = rt.nearest(key, cfg.K); std::string tok = issueToken();
                for (auto& c: nodes){ if (val && val->size()<=CFG_UDP_VALUE_MAX) rpcStore(c, key, *val, (uint32_t)cfg.VALUE_TTL_SEC, false, tok); }
                return val;
            }
            break;
        }
        return std::nullopt;
    }

    // Background loops
    void republishLoop(){
        while (running){
            std::this_thread::sleep_for(std::chrono::seconds(cfg.REPUBLISH_PERIOD_SEC));
            auto pubs = kv.publishers(); std::string tok = issueToken();
            for (auto& [key, rec] : pubs){
                auto nodes = iterativeFindNode(key); uint32_t ttl = (uint32_t)cfg.VALUE_TTL_SEC;
                for (auto& n : nodes) if (rec.value.size()<=CFG_UDP_VALUE_MAX) rpcStore(n, key, rec.value, ttl, rec.infinite, tok);
            }
        }
    }
    void refreshLoop(){
        while (running){
            std::this_thread::sleep_for(1h);
            NodeID target=self; std::random_device rd; std::mt19937 rng(rd()); std::uniform_int_distribution<int> dist(0,g_id_bits-1);
            int flip=dist(rng); int byte=flip/8; int bit=7-(flip%8); target.b[byte]^=(1u<<bit); iterativeFindNode(target);
        }
    }
    void snapshotLoop(){
        while (running){
            std::this_thread::sleep_for(std::chrono::seconds(cfg.SNAPSHOT_PERIOD_SEC));
            if (cfg.snapshot_path.empty()) continue;
            json j;
            j["nodeId"]   = self.hex();
            j["id_bits"]  = g_id_bits;
            j["routing"]  = json::parse(rt.toJSON());
            j["kv"]       = json::parse(kv.toJSON());
            std::ofstream f(cfg.snapshot_path, std::ios::trunc); if (!f.good()) continue; f << j.dump(2) << "\n";
        }
    }
    
};

// -------------------- CLI --------------------
const char* JADA_VERSION = "0.1.0";

static void printHelp(const char* argv0){
    std::cout
      << "Jada " << JADA_VERSION << "\n"
      << "\n"
      << "Usage:\n"
      << "  " << argv0 << " [--cli <host:port>]\n"
      << "  " << argv0 << " [--config <path>] [--daemon] [-h|--help] [--version]\n"
      << "\n"
      << "Description:\n"
      << "  Jada is a lightweight Kademlia DHT with single-value and grouped-collection\n"
      << "  operations, a framed JSON TCP API, and an authenticated UDP RPC layer.\n"
      << "\n"
      << "Options:\n"
      << "  --config <path>   Path to config.json (default: ./config.json)\n"
      << "  -h, --help        Show this help and exit\n"
      << "  --version         Print version and exit\n"
      << "  --cli <host:port>  Set initial CLI target (host may be domain/IP/URL)\n"
      << "\n"
      << "Modes:\n"
      << "  CLI mode:    No flags or --cli <host:port> -> opens interactive shell.\n"
      << "  Node mode:   Any of --config/--daemon -> runs Jada node (no CLI).\n"
      << "\n"
      << "Interactive CLI:\n"
      << "  Run \"jada\" with no flags to start the node and open a CLI shell.\n"
      << "  Use \"cli [host[:port]|url]\" inside the shell to view or change target.\n"
      << "  Use \"detach\" to leave an attached CLI (not applicable in CLI-only mode).\n"
      << "  Use --daemon to start the node without the CLI.\n"
      << "\n"
      << "Modes:\n"
      << "  CLI mode:    No flags or --cli <host:port> -> opens interactive shell.\n"
      << "  Node mode:   Any of --config/--daemon -> runs Jada node (no CLI).\n"
      << "\n"
      << "Interactive CLI:\n"
      << "  Run \"jada\" with no flags to start the node and open a CLI shell.\n"
      << "  Use --daemon to start the node without the CLI.\n"
      << "\n"
      << "Config keys (config.json):\n"
      << "  rpc_port (int)                UDP port for DHT RPC (default 5555)\n"
      << "  api_port (int)                TCP port for JSON API (default 8080)\n"
      << "  secret (string)               Shared secret for HMAC tokens\n"
      << "  K (int)                       Kademlia replication factor (default 20)\n"
      << "  ALPHA (int)                   Parallel lookup concurrency (default 3)\n"
      << "  request_timeout_ms (int)      RPC timeout in milliseconds (default 3000)\n"
      << "  republish_period_sec (int)    Republishing interval (default 3600)\n"
      << "  value_ttl_sec (int)           Default value TTL in seconds (default 86400)\n"
      << "  snapshot_period_sec (int)     Snapshot interval (default 300)\n"
      << "  snapshot_path (string)        Path to write periodic snapshots (optional)\n"
      << "  bootstrap ([\"ip:port\"])      List of bootstrap peers\n"
      << "  node_id (hex|string)          Fixed NodeID hex or any text (optional)\n"
      << "  id_bits (128|160)             NodeID size in bits (default 160)\n"
      << "  pq_sign (bool)                Enable PQ signatures (experimental)\n"
      << "  pq_scheme (string)            PQ scheme name (e.g., DILITHIUM_2)\n"
      << "\n"
      << "API examples (TCP JSON):\n"
      << "  echo '{\"op\":\"put\",\"key\":\"alpha\",\"value\":\"bravo\",\"ttl\":3600}' | nc 127.0.0.1 8080\n"
      << "  echo '{\"op\":\"get\",\"key\":\"alpha\"}' | nc 127.0.0.1 8080\n"
      << "  echo '{\"op\":\"group.put\",\"group\":\"dns\",\"items\":[{\"key\":\"a1\",\"value\":\"1.2.3.4\"}]}' | nc 127.0.0.1 8080\n"
      << "  echo '{\"op\":\"group.get\",\"group\":\"dns\"}' | nc 127.0.0.1 8080\n"
      << "\n"
      << "Notes:\n"
      << "  - UDP RPC listens on INADDR_ANY, so LAN/WAN peers can connect if the port is reachable.\n"
      << "  - NAT requires at least one publicly reachable bootstrap or port forwarding.\n"
      << "  - PQ signature support requires building with -DWITH_OQS and linking liboqs; it is experimental.\n";
}

namespace jada {

int run_jada(int argc, char** argv){
    // Decide between CLI mode (default) and Node mode (if --config/--daemon present)
    bool daemon_mode = false;
    bool node_mode = false;
    std::optional<std::string> cli_target;
    std::string cfgPath = "config.json";

    for (int i=1;i<argc;i++){
        std::string a=argv[i];
        if (a=="--config" && i+1<argc){ cfgPath=argv[++i]; node_mode=true; }
        else if (a=="--daemon"){ daemon_mode=true; node_mode=true; }
        else if (a=="--cli" && i+1<argc){ cli_target = argv[++i]; }
        else if (a=="--help" || a=="-h"){ printHelp(argv[0]); return 0; }
        else if (a=="--version"){ std::cout<<JADA_VERSION<<"\n"; return 0; }
        else {
            std::cerr<<"Unknown option: "<<a<<"\n";
            printHelp(argv[0]);
            return 1;
        }
    }

    if (!node_mode){
        // CLI-only mode: connect to target (default 127.0.0.1:8080) and run shell
        int api_port_default = 8080;
        (void)daemon_mode; // ignored in CLI mode
        return run_cli(api_port_default, cli_target) ? 0 : 0;
    }

    // Node mode
    Config cfg = loadConfig(cfgPath);
    DhtNode node(cfg);
    if (!node.start()) return 1;
    for (auto& hp : cfg.bootstrap){
        bool ok = node.bootstrapOne(hp);
        std::cout<<"[boot] "<<hp<<" -> "<<(ok?"ok":"fail")<<"\n";
    }
    // Node runs without CLI in this mode
    for(;;) std::this_thread::sleep_for(std::chrono::hours(24));
    return 0;
}

}
