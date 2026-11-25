# MikroTik Proxy Dashboard (RB5009 / RouterOS 7.25)

Hệ thống **LAN Proxy Dashboard & Transparent Gateway** chuẩn production, thiết kế chuyên biệt cho MikroTik RouterOS 7.25+ (`RB5009UG+S+`) đóng gói dưới dạng container `linux/arm64` siêu nhẹ với kiến trúc **Zero-Leak (Không rò rỉ IP/DNS/IPv6/WebRTC)**.

---

## 1. Tính Năng Nổi Bật

- **Hỗ trợ 7 Giao thức Proxy**: HTTP, HTTPS, SOCKS5, Shadowsocks (SIP002 & legacy), Trojan, VLESS (Reality & Vision), VMess (WebSocket & gRPC).
- **Dán Nhanh URI Đa Tuyến**: Hỗ trợ dán hàng loạt link proxy (`socks5://`, `vless://`, `vmess://`, `ss://`, `trojan://`, `host:port:user:pass`) tự động phân tích và import.
- **Live Proxy Tester**: Kiểm tra thời gian thực mọi proxy bằng một tiến trình `sing-box` thu nhỏ (ephemeral instance), đo độ trễ ms, lấy Exit IP thật, quốc gia, ISP.
- **Hệ Thống Bảo Vệ 6 Tầng (Zero-Leak Guard)**:
  1. **Layer 1: Static IP Binding**: Tự động chuyển DHCP lease sang Static để thiết bị không bị đổi IP.
  2. **Layer 2: Policy Routing**: Định tuyến qua routing table `via-proxy` chỉ áp dụng cho danh sách `PROXY_DEVICES`.
  3. **Layer 3: RouterOS Kill-Switch**: Tự động chặn mọi kết nối trực tiếp nếu proxy hoặc container gặp sự cố, không bao giờ lộ IP thật.
  4. **Layer 4: IPv6 Hardware Block**: Chặn hoàn toàn IPv6 ở mức phần cứng theo địa chỉ MAC tại tầng Firewall của RouterOS.
  5. **Layer 5: DNS Hijack & FakeIP**: Bắt toàn bộ DNS UDP/TCP Port 53 chuyển hướng về `sing-box` FakeIP (`198.18.0.0/15`) và TCP DoH qua proxy. Chặn `AAAA`, `HTTPS`, `SVCB` để triệt tiêu rò rỉ HTTP/3 QUIC.
  6. **Layer 6: sing-box Fail-Closed Engine**: Tự động ngắt kết nối UDP STUN (triệt tiêu rò rỉ WebRTC) đối với các proxy không có UDP, tự động ép QUIC fallback về TCP.
- **Embedded Web Dashboard**: Giao diện tiếng Việt dark-slate hiện đại, responsive cho MacBook & điện thoại di động, **100% Offline trên mạng LAN** (không dùng CDN ngoài).
- **Bảo Mật Cao Cấp**:
  - Xác thực mật khẩu bằng `bcrypt`.
  - Cookie phiên đăng nhập `HttpOnly`, `SameSite=Strict`, ký HMAC-SHA256 với khóa ngẫu nhiên 32-byte lưu quyền `0600`.
  - Tự động khóa IP (Rate-limiting) khi đăng nhập sai quá 5 lần / 60 giây.
  - Tự động che giấu mật khẩu, token, uuid trong nhật ký (Sanitized Logs).

---

## 2. Thông Số Môi Trường Mặc Định (`home-01`)

| Tham số | Giá trị mặc định | Mô tả |
| :--- | :--- | :--- |
| **LAN Bridge** | `10.88.88.0/24` (`10.88.88.1`) | Mạng LAN chính cho máy tính & điện thoại |
| **Container Bridge** | `10.10.10.0/24` (`10.10.10.1`) | Mạng bridge nội bộ dành cho Containers |
| **Container IP** | `10.10.10.16/24` | IP gán cho veth của container (`veth-proxy`) |
| **Dashboard Port** | `:8080` | Cổng HTTP Web Dashboard (`http://10.10.10.16:8080`) |
| **Persistent Data** | `/data` | Nơi lưu `state.json`, `session.key`, `sing-box.json`, `cache.db` |

---

## 3. Hướng Dẫn Cấu Hình RouterOS 7.25

### Bước 1: Tạo Routing Table & Định Tuyến (Policy Routing)
```routeros
/routing/table add name=via-proxy fib

# Thêm định tuyến mặc định cho bảng via-proxy trỏ về container gateway (10.10.10.16)
/ip/route add dst-address=0.0.0.0/0 gateway=10.10.10.16 routing-table=via-proxy

# Tạo routing rule ép danh sách PROXY_DEVICES đi qua bảng via-proxy
/routing/rule add action=lookup-only-in-table interface=BridgeLAN table=via-proxy src-address=10.88.88.0/24 comment="proxy-dash:policy-routing"
```

### Bước 2: Tạo Firewall Kill-Switch & DNS Hijack
```routeros
# Kill-Switch: Chặn mọi gói tin từ PROXY_DEVICES cố tình thoát trực tiếp ra WAN
/ip/firewall/filter
add chain=forward action=drop src-address-list=PROXY_DEVICES out-interface-list=WAN comment="proxy-dash-killswitch" place-before=1

# DNS Hijack: Chuyển hướng toàn bộ truy vấn DNS Port 53 của PROXY_DEVICES về container
/ip/firewall/nat
add chain=dstnat action=dst-nat to-addresses=10.10.10.16 to-ports=53 protocol=udp src-address-list=PROXY_DEVICES dst-port=53 comment="proxy-dash:dns-hijack-udp"
add chain=dstnat action=dst-nat to-addresses=10.10.10.16 to-ports=53 protocol=tcp src-address-list=PROXY_DEVICES dst-port=53 comment="proxy-dash:dns-hijack-tcp"
```

### Bước 3: Tạo Khóa Hash Mật Khẩu Dashboard
Chạy lệnh sau trên máy tính của bạn trước khi triển khai:
```bash
./proxy-dash --hash-password
# Nhập mật khẩu quản trị của bạn, output sẽ là chuỗi hash bcrypt (ví dụ: $2a$10$...)
```

### Bước 4: Khởi Chạy Container Trên MikroTik
Sao chép file `dist/proxy-gw-arm64.tar` vào ổ lưu trữ của router (ví dụ USB hoặc SSD gắn ngoài):
```routeros
/container/config/set registry-url="" tmpdir=disk1/tmp

# Tạo veth interface cho container
/interface/veth add name=veth-proxy address=10.10.10.16/24 gateway=10.10.10.1
/interface/bridge/port add bridge=containers interface=veth-proxy

# Tạo danh sách biến môi trường (envs)
/container/envs add name=proxy_envs key=DASHBOARD_PASSWORD_HASH value="<CHUỖI_BCRYPT_HASH_Ở_BƯỚC_3>"
/container/envs add name=proxy_envs key=MIKROTIK_URL value="https://10.88.88.1"
/container/envs add name=proxy_envs key=MIKROTIK_USER value="admin"
/container/envs add name=proxy_envs key=MIKROTIK_PASS value="<MẬT_KHẨU_ROUTEROS>"
/container/envs add name=proxy_envs key=MIKROTIK_INSECURE_TLS value="true"
/container/envs add name=proxy_envs key=LAN_CIDR value="10.88.88.0/24"
/container/envs add name=proxy_envs key=CONTAINER_GW value="10.10.10.1"

# Tạo mount directory cho dữ liệu cấu hình
/container/mounts add name=proxy_data src=disk1/proxy-data dst=/data

# Nạp container từ file tar
/container/add file=disk1/proxy-gw-arm64.tar interface=veth-proxy envlist=proxy_envs mounts=proxy_data start-on-boot=yes

# Khởi động container
/container/start [find file="disk1/proxy-gw-arm64.tar"]
```

Sau khi container chạy, truy cập vào trình duyệt:
👉 `http://10.10.10.16:8080` (hoặc cấu hình thêm Port Forward trên router để truy cập từ mạng LAN).

---

## 4. Kiểm Thử Đơn Vị (Unit Tests)

Dự án bao gồm bộ unit test toàn diện kiểm tra 100% các chức năng cốt lõi:
```bash
go test -v ./...
```
- Phân tích cú pháp 7 giao thức proxy + xử lý định dạng lỗi/malformed.
- Kiểm tra tính hợp lệ của cấu hình sing-box bằng chính binary `sing-box check`.
- Kiểm tra xác thực bcrypt, ký HMAC-SHA256, từ chối cookie bị can thiệp và cơ chế chống brute-force Rate-Limit.
- Giả lập RouterOS v7 REST API (Static Lease, Address-List, IPv6 Rules, Flush Connections).

---

## 5. Đóng Gói Container ARM64

Để build file `.tar` triển khai cho MikroTik RB5009:
```bash
./scripts/build-arm64-tar.sh
```
Kết quả file xuất ra tại: `dist/proxy-gw-arm64.tar`.
