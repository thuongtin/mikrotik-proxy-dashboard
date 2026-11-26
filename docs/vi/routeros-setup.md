[English](../routeros-setup.md) | **Tiếng Việt**

# Thiết lập RouterOS

Hướng dẫn cài đặt lần đầu trên RouterOS 7 có hỗ trợ container (đã dùng với RB5009UG+S+, RouterOS 7.25). Các giá trị mẫu bên dưới theo môi trường mặc định; đổi lại cho khớp mạng của bạn.

Phần rule nền ở mục 3 lấy từ một cấu hình router đang chạy. Những lệnh chưa được chạy thử trên router thật đều có ghi chú riêng.

| Thành phần | Giá trị mẫu |
| :--- | :--- |
| LAN | `10.88.88.0/24`, gateway `10.88.88.1`, bridge `BridgeLAN` |
| Bridge container | `containers`, `10.10.10.0/24`, gateway `10.10.10.1` |
| Container | `10.10.10.16`, interface `veth-proxy` |
| Bảng định tuyến | `via-proxy` |
| Address-list | `PROXY_DEVICES` |
| Thư mục dữ liệu | `disk1/proxy-data` gắn vào `/data` |

> **Trước khi bắt đầu:** xuất cấu hình hiện tại (`/export file=before-proxy-dash`) để có đường lùi. Làm từng bước, kiểm tra mạng LAN vẫn bình thường sau mỗi bước.

## 1. Tài khoản riêng cho dashboard

Không dùng `admin`. Tạo một nhóm quyền hẹp và một tài khoản chỉ đăng nhập được từ địa chỉ container:

```routeros
/user/group add name=proxy-dash policy=read,write,api,rest-api,!local,!telnet,!ssh,!ftp,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon
/user add name=proxy-dash group=proxy-dash address=10.10.10.16/32 password="<mat-khau-rieng>"
```

Bộ quyền trên là đề xuất từ việc đọc code (dashboard chỉ đọc và ghi qua REST API), **chưa được kiểm chứng trên router thật**. Nếu dashboard báo lỗi quyền khi gán thiết bị, xem log RouterOS để biết policy còn thiếu rồi bổ sung đúng policy đó.

## 2. REST API qua HTTPS

Dashboard gọi `MIKROTIK_URL` (mặc định `https://10.88.88.1`). Bật dịch vụ `www-ssl` với một chứng chỉ, và giới hạn nguồn truy cập:

```routeros
/ip/service set www-ssl disabled=no certificate=<ten-chung-chi> address=10.10.10.16/32,10.88.88.0/24
```

Dải `address` phải chứa địa chỉ container. Host trong `MIKROTIK_URL` phải là một địa chỉ router nghe được từ container (`10.88.88.1` hoặc gateway của bridge container `10.10.10.1`), **và phải có trong SAN của chứng chỉ**. Nên dùng `https://10.88.88.1`: chứng chỉ router thường cấp cho địa chỉ LAN, còn `10.10.10.1` hiếm khi có trong SAN. Dải `10.88.88.0/24` nằm trong `EXCLUDE_CIDRS` nên kết nối tới router không đi qua `tun0`, và rule firewall `proxy-dash:allow-router-api` không giới hạn địa chỉ đích.

### Xác minh chứng chỉ

Mặc định dashboard **xác minh chứng chỉ** của router. Với chứng chỉ tự ký, cần hai điều kiện:

1. Chứng chỉ có SAN khớp host trong `MIKROTIK_URL`. Gọi bằng IP thì SAN phải có `IP:<địa chỉ đó>`; chỉ có common-name là không đủ.
2. Dashboard có file PEM của chứng chỉ đó (hoặc của CA đã ký nó), khai báo qua `MIKROTIK_CA_FILE`.

Tạo chứng chỉ tự ký có đủ SAN (bỏ qua nếu chứng chỉ đang dùng đã có SAN đúng):

```routeros
/certificate add name=proxy-dash-tls common-name=10.88.88.1 subject-alt-name=IP:10.88.88.1,IP:10.10.10.1 key-usage=digital-signature,key-encipherment,tls-server days-valid=3650
/certificate sign proxy-dash-tls
/ip/service set www-ssl certificate=proxy-dash-tls
```

Xuất phần công khai của chứng chỉ (không kèm khóa riêng) ra file PEM:

```routeros
/certificate export-certificate proxy-dash-tls file-name=router-ca
```

Lệnh trên tạo `router-ca.crt` trong Files. Chép file đó vào thư mục dữ liệu của container với tên `router-ca.pem` (ví dụ `disk1/proxy-data/router-ca.pem`), rồi đặt `MIKROTIK_CA_FILE=/data/router-ca.pem`. Đừng đặt `export-passphrase`: có passphrase thì RouterOS xuất kèm khóa riêng, thứ không được rời khỏi router.

Dashboard không đọc được file, hoặc file không chứa chứng chỉ PEM nào, thì dừng ngay lúc khởi động và ghi rõ lý do trong log. Chứng chỉ sai SAN thì dashboard chạy nhưng mọi lệnh gọi router đều lỗi, và trang trạng thái báo các lớp "không kiểm tra được".

`MIKROTIK_INSECURE_TLS=true` tắt hẳn việc xác minh. Chỉ dùng tạm trong lúc chuẩn bị chứng chỉ; mỗi lần khởi động container in một dòng cảnh báo. Xem mục M4 trong [security.md](security.md).

### Khi tài khoản không có quyền xuất chứng chỉ

`/certificate export-certificate` cần quyền `sensitive`. Tài khoản thiếu quyền này nhận lỗi `not enough permissions (9)`. Khi đó lấy CA ngay từ TLS handshake, rồi đối chiếu với router trước khi tin:

```bash
openssl s_client -connect 10.88.88.1:443 -showcerts </dev/null 2>/dev/null > chain.txt
# Certificate thứ hai trong chain.txt là CA (subject = issuer, CA:TRUE); lưu thành router-ca.pem.
openssl x509 -in router-ca.pem -noout -serial -ext subjectKeyIdentifier
```

Serial và SKID phải khớp `/certificate/print detail` trên router. Kiểm thêm SKID đúng là SHA-1 của khóa công khai (RFC 5280, cách 1), vì SKID chỉ là một trường trong chứng chỉ. Đừng so trường `fingerprint` của RouterOS với `openssl x509 -fingerprint -sha256`: trên RouterOS 7.25.1, hai giá trị này khác nhau dù là cùng một chứng chỉ. Cuối cùng thử `curl --cacert router-ca.pem https://10.88.88.1/rest/system/identity`: mã 401 nghĩa là TLS đã qua, curl exit 60 nghĩa là chứng chỉ hoặc SAN sai.

> Cách làm này đã được kiểm trên RouterOS 7.25.1 với chứng chỉ `www-ssl` do một CA cục bộ của RouterOS ký; router gửi kèm CA trong chuỗi. Các lệnh `/certificate add` và `sign` ở trên vẫn **chưa được chạy thử**.

## 3. Rule nền (làm một lần)

### Bảng định tuyến và tuyến mặc định qua container

```routeros
/routing/table add name=via-proxy fib
/ip/route add dst-address=0.0.0.0/0 gateway=10.10.10.16 routing-table=via-proxy
```

### Policy routing

Chỉ lưu lượng của thiết bị trong `PROXY_DEVICES` được đưa vào bảng `via-proxy`. Việc chọn thiết bị do mangle đảm nhận, vì `/routing/rule` của RouterOS không lọc được theo address-list.

Trước hết, một address-list gom các dải nội bộ mà thiết bị vẫn cần tới trực tiếp (máy in, NAS, chính dashboard):

```routeros
/ip/firewall/address-list add list=LAN address=10.88.88.0/24
/ip/firewall/address-list add list=LAN address=10.10.10.0/24
```

Bốn rule mangle, **đúng thứ tự này**:

```routeros
/ip/firewall/mangle add chain=prerouting action=accept in-interface=BridgeLAN dst-address-list=LAN comment="proxy-dash:bypass-lan"
/ip/firewall/mangle add chain=prerouting action=accept protocol=udp dst-port=53 in-interface=BridgeLAN src-address-list=PROXY_DEVICES comment="proxy-dash:bypass-dns-udp"
/ip/firewall/mangle add chain=prerouting action=accept protocol=tcp dst-port=53 in-interface=BridgeLAN src-address-list=PROXY_DEVICES comment="proxy-dash:bypass-dns-tcp"
/ip/firewall/mangle add chain=prerouting action=mark-routing new-routing-mark=via-proxy passthrough=no src-address-list=PROXY_DEVICES in-interface=BridgeLAN dst-address-type=!local comment="proxy-dash:mark-routing"
```

- Rule 1 để lưu lượng nội bộ đi như bình thường.
- Rule 2 và 3 để gói DNS không bị đánh dấu; chúng sẽ được rule DNS hijack bên dưới chuyển tới `sing-box`.
- Rule 4 đánh dấu mọi thứ còn lại của thiết bị đã gán.

Routing rule buộc gói đã đánh dấu chỉ được tra bảng `via-proxy`:

```routeros
/routing/rule add action=lookup-only-in-table routing-mark=via-proxy table=via-proxy comment="proxy-dash:strict-table"
```

`lookup-only-in-table` là điểm mấu chốt: nếu bảng `via-proxy` không có tuyến nào dùng được (tuyến bị tắt, bị xóa, hoặc interface của container mất), gói tin bị bỏ chứ không rơi về bảng `main`. Dùng `action=lookup` thì gói sẽ rơi về `main` và đi thẳng ra WAN; dashboard báo cảnh báo ở lớp L2 trong trường hợp đó.

Thiết bị chưa gán không khớp rule nào ở trên và đi mạng như cũ.

### Kill-switch

```routeros
/ip/firewall/filter add chain=forward action=drop src-address-list=PROXY_DEVICES out-interface-list=WAN comment="proxy-dash-killswitch" place-before=1
```

Yêu cầu:

- Interface list `WAN` phải chứa **mọi** đường ra Internet (PPPoE, WAN dự phòng, LTE). Thiếu một đường là thiếu bảo vệ ở đường đó.
- Rule phải đứng trước các rule `accept` established/related và fasttrack trong chain `forward`. Kiểm tra bằng `/ip/firewall/filter print`.
- Giữ nguyên comment `proxy-dash-killswitch`. Dashboard tìm rule theo comment này, rồi kiểm tra rule có đang bật, đúng chain `forward`, action `drop` hoặc `reject`, đúng `src-address-list=PROXY_DEVICES` hay không. Thiếu interface ra, hoặc có rule accept đứng trước nhận cả kết nối mới, thì lớp L3 báo cảnh báo. Phần kiểm tra vị trí là ước lượng: rule accept có điều kiện hẹp (theo cổng, theo đích) vẫn có thể bị cảnh báo nhầm.
- Nếu dùng fasttrack, loại trừ `PROXY_DEVICES` khỏi rule fasttrack để gói của thiết bị đã gán luôn đi qua firewall.

Đây là lớp quan trọng nhất: mỗi lần `sing-box` khởi động lại, kill-switch là thứ chắc chắn chặn gói tin đi thẳng ra WAN. Forward guard trong container ([mục 7](#7-forward-guard-trong-container)) là lớp thứ hai, nhưng không phải router nào cũng cài được.

### DNS hijack

```routeros
/ip/firewall/nat add chain=dstnat action=dst-nat to-addresses=10.10.10.16 to-ports=53 protocol=udp src-address-list=PROXY_DEVICES dst-port=53 comment="proxy-dash:dns-hijack-udp"
/ip/firewall/nat add chain=dstnat action=dst-nat to-addresses=10.10.10.16 to-ports=53 protocol=tcp src-address-list=PROXY_DEVICES dst-port=53 comment="proxy-dash:dns-hijack-tcp"
```

## 4. Container

```routeros
/interface/veth add name=veth-proxy address=10.10.10.16/24 gateway=10.10.10.1
/interface/bridge/port add bridge=containers interface=veth-proxy

/container/envs add name=proxy_envs key=DASHBOARD_PASSWORD_HASH value="<bcrypt-hash>"
/container/envs add name=proxy_envs key=MIKROTIK_URL value="https://10.88.88.1"
/container/envs add name=proxy_envs key=MIKROTIK_USER value="proxy-dash"
/container/envs add name=proxy_envs key=MIKROTIK_PASS value="<mat-khau-rieng>"
/container/envs add name=proxy_envs key=MIKROTIK_CA_FILE value="/data/router-ca.pem"
/container/envs add name=proxy_envs key=FORWARD_GUARD value="auto"

/container/mounts add name=proxy_data src=disk1/proxy-data dst=/data
/container/add file=disk1/proxy-gw-arm64.tar interface=veth-proxy envlist=proxy_envs mounts=proxy_data root-dir=disk1/proxy-gw start-on-boot=yes logging=yes
```

**Phải escape mọi dấu `$` trong mã băm mật khẩu.** Mã băm bcrypt có dạng `$2a$10$` rồi thêm 53 ký tự. Trong terminal RouterOS và trong script, dấu `$` trong chuỗi được hiểu là tên biến: mã băm không escape sẽ bị lưu thành giá trị rỗng hoặc bị cắt, và không mật khẩu nào khớp được. Viết mỗi `$` thành `\$`:

```routeros
/container/envs add name=proxy_envs key=DASHBOARD_PASSWORD_HASH value="\$2a\$10\$<phan-con-lai-cua-ma-bam>"
```

Để escape nhanh một mã băm, đặt nó giữa hai dấu nháy đơn:

```bash
printf '%s\n' '<ma-bam-bcrypt>' | sed 's/\$/\\$/g'
```

Quy tắc này chỉ áp dụng cho terminal và script. Trong Winbox hoặc WebFig, dán mã băm nguyên dạng, không thêm dấu `\`. Nếu nhập đúng mật khẩu mà vẫn không đăng nhập được, chạy `/container/envs print where key=DASHBOARD_PASSWORD_HASH`: giá trị phải bắt đầu bằng `$2a$` và dài đúng 60 ký tự.

Tải `dist/proxy-gw-arm64.tar` lên `disk1/` và chép `router-ca.pem` vào `disk1/proxy-data/` trước khi chạy lệnh cuối. Danh sách biến môi trường đầy đủ nằm trong [README](../../README.vi.md#cấu-hình).

Lưu ý về bí mật: giá trị trong `/container/envs` nằm trong cấu hình router và xuất hiện khi `/export show-sensitive`. Không dán các giá trị này vào chat, ticket hay file commit.

### Dừng container

Khi chạy `/container/stop`, RouterOS đọc `SigCgt` trong `/proc/1/status` của container trước. Nếu PID 1 không có handler cho SIGTERM, RouterOS ghi log `signal 15 (Terminated) not caught, kill immediately` và gửi SIGKILL ngay, không chờ `stop-time`. Vì thế `entrypoint.sh` giữ vai trò PID 1 bằng `trap` của shell và chuyển tín hiệu cho proxy-dash. Đừng đặt `tini` hay `dumb-init` phía trước: chúng nhận tín hiệu bằng `sigtimedwait`, và RouterOS coi đó là "not caught". `scripts/build-arm64-tar.sh` kiểm bit SigCgt và chạy thử `docker stop` thật trước khi chấp nhận một image.

Khi dừng êm, log có `Shutting down gracefully...`, `proxy-dash exited cleanly` và `exited with status 0`. Nếu thấy quá trình dừng bị cắt ngang, hãy tăng thời gian chờ:

```routeros
/container/set [find name=proxy-gw] stop-time=20s
```

Tham khảo: [tikoci/app-t3code#25](https://github.com/tikoci/app-t3code/issues/25).

## 5. Giới hạn ai mở được dashboard

Dashboard chạy HTTP thuần ở cổng 8080. Chỉ cho máy quản trị truy cập:

```routeros
/ip/firewall/address-list add list=PROXY_ADMINS address=<ip-may-quan-tri>
/ip/firewall/filter add chain=forward action=drop dst-address=10.10.10.16 protocol=tcp dst-port=8080 src-address-list=!PROXY_ADMINS comment="proxy-dash:admin-only"
```

Đặt rule này trước rule accept established/related. Không tạo dst-nat từ WAN vào cổng 8080.

## 6. Siết thêm (khuyến nghị)

Thiết bị tự đặt IP tĩnh khác, hoặc đổi địa chỉ MAC, sẽ rời khỏi `PROXY_DEVICES` và đi mạng trực tiếp. Để chặn:

```routeros
/ip/dhcp-server set [find interface=BridgeLAN] add-arp=yes
/interface/bridge set BridgeLAN arp=reply-only
```

Sau hai lệnh này, chỉ thiết bị nhận IP qua DHCP mới liên lạc được với router. **Mọi thiết bị đặt IP tĩnh bằng tay (máy in, camera, NAS) sẽ mất kết nối** cho tới khi bạn thêm ARP tĩnh hoặc chuyển chúng sang DHCP. Lập danh sách các thiết bị đó trước khi bật.

## 7. Forward guard trong container

Khi khởi động, `entrypoint.sh` cài một nhóm rule iptables trong chính container: policy của chain `FORWARD` là DROP, chỉ cho gói đi vào hoặc đi ra qua `tun0`, và gói tới các dải trong `EXCLUDE_CIDRS`. Nhờ đó, lúc `sing-box` dừng hoặc đang khởi động lại, container không tự chuyển tiếp gói của thiết bị thẳng ra uplink.

Biến `FORWARD_GUARD` quyết định cách xử lý:

| Giá trị | Hành vi |
| :--- | :--- |
| `auto` (mặc định) | Cài rule. Không cài được thì in cảnh báo và chạy tiếp |
| `enforce` | Cài rule. Không cài được thì container không khởi động |
| `off` | Không đụng tới iptables |

**Giới hạn đã biết của RouterOS.** Kernel của RouterOS chỉ mở một phần netfilter cho container. Người dùng trên forum MikroTik đã gặp việc `iptables` trong container không hoạt động, và hỗ trợ MikroTik từng trả lời rằng không có iptables cho code bên thứ ba. Forward guard đã được chạy thử trên Docker (kernel Linux thường), **chưa được chạy thử trên RouterOS**. Vì vậy:

1. Lần đầu luôn để `FORWARD_GUARD=auto`.
2. Xem log container (`/log print where topics~"container"`). Tìm một trong hai dòng:
   - `Forward guard active (...)`: đã cài được.
   - `WARNING: forward guard could NOT be installed`: kernel từ chối.
3. Trên dashboard, lớp L6 đạt khi guard đã cài; báo cảnh báo khi guard không cài được hoặc đang tắt.
4. Chỉ chuyển sang `FORWARD_GUARD=enforce` sau khi đã thấy dòng `active`. Đặt `enforce` trên router không hỗ trợ thì container sẽ không lên.

Guard không cài được không có nghĩa là hở: kill-switch ở mục 3 vẫn chặn ở phía router. Nó chỉ có nghĩa là bạn còn một lớp chặn thay vì hai, nên càng phải chạy đủ phần "Thử tình huống hỏng" bên dưới.

Nguồn tham khảo (tra cứu tháng 11 năm 2026):

- [Tailscale container: iptables not working](https://forum.mikrotik.com/t/tailscale-container-iptables-not-working/172271)
- [RouterOS 7.24: privileged containers](https://forum.mikrotik.com/t/routeros-7-24-privileged-containers/272219)
- [Lack of TPROXY module in RouterOS kernel and Docker containers](https://forum.mikrotik.com/t/lack-of-tproxy-module-in-routeros-kernel-and-docker-containers/164452)
- [Feature request: nftables netdev ingress hook in containers](https://forum.mikrotik.com/t/feature-request-enable-nftables-netdev-family-ingress-hook-in-containers/272351)

## Kiểm tra sau cài đặt

Trên router:

- [ ] `/routing/table print` có `via-proxy`
- [ ] `/ip/route print where routing-table=via-proxy` có tuyến mặc định, trạng thái active
- [ ] `/ip/firewall/mangle print where comment~"proxy-dash:"` có đủ bốn rule, đúng thứ tự, rule `mark-routing` đứng cuối
- [ ] `/routing/rule print where table=via-proxy` có rule `lookup-only-in-table`, không disabled
- [ ] `/ip/firewall/filter print where comment~"killswitch"` có rule, không disabled, đứng trước fasttrack
- [ ] `/ip/firewall/nat print where comment~"dns-hijack"` có đủ hai rule UDP và TCP
- [ ] `/container print` trạng thái `running`
- [ ] Log container không có dòng lỗi TLS khi gọi router, và có dòng về forward guard (`active` hoặc cảnh báo)

Trên dashboard:

- [ ] Trang trạng thái không có lớp nào báo lỗi hoặc "không kiểm tra được"
- [ ] Lớp L6 đạt, hoặc báo cảnh báo với lý do đúng là forward guard không cài được

Trên một thiết bị đã gán proxy:

- [ ] IP hiển thị ở `ipleak.net` là exit IP của proxy
- [ ] `browserleaks.com/dns` không thấy DNS của nhà mạng
- [ ] `browserleaks.com/webrtc` không thấy IP WAN thật
- [ ] `test-ipv6.com` báo không có IPv6

Thử tình huống hỏng:

- [ ] Dừng container (`/container stop`), thiết bị đã gán **mất mạng**, không tự chuyển sang đi trực tiếp
- [ ] Khởi động lại container, thiết bị có mạng lại qua proxy
- [ ] Một thiết bị chưa gán proxy vẫn có mạng bình thường suốt quá trình

## Gỡ bỏ

Bỏ gán toàn bộ thiết bị trên dashboard trước, rồi:

```routeros
/container stop [find interface=veth-proxy]
/container remove [find interface=veth-proxy]
/ip/firewall/nat remove [find comment~"proxy-dash:dns-hijack"]
/ip/firewall/filter remove [find comment="proxy-dash-killswitch"]
/ip/firewall/filter remove [find comment="proxy-dash:admin-only"]
/ipv6/firewall/filter remove [find comment~"proxy-dash-ipv6-"]
/ip/firewall/address-list remove [find list=PROXY_DEVICES]
/ip/firewall/mangle remove [find comment~"proxy-dash:"]
/routing/rule remove [find comment="proxy-dash:strict-table"]
/ip/route remove [find routing-table=via-proxy]
/routing/table remove [find name=via-proxy]
/user remove proxy-dash
/user/group remove proxy-dash
```

Các DHCP lease đã chuyển thành static vẫn giữ nguyên; đổi lại bằng tay nếu cần. Address-list `LAN` và chứng chỉ cũng được giữ lại vì có thể đang được rule khác dùng.
