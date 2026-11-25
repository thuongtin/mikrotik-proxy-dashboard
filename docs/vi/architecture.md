[English](../architecture.md) | **Tiếng Việt**

# Kiến trúc

## Tổng quan

Một binary Go duy nhất (`proxy-dash`) chạy trong container cùng với `sing-box`:

- `proxy-dash` phục vụ dashboard và REST API ở cổng 8080, lưu trạng thái vào `/data/state.json`, gọi REST API của RouterOS để thêm và gỡ rule, sinh cấu hình cho `sing-box` và giám sát tiến trình đó.
- `sing-box` nhận lưu lượng mà router dẫn vào container, chọn outbound theo IP nguồn và trả lời DNS.

Phụ thuộc ngoài thư viện chuẩn: `golang.org/x/crypto` (chỉ dùng bcrypt). Frontend là HTML, CSS, JavaScript thuần, nhúng vào binary bằng `embed`.

## Cấu trúc thư mục

| Đường dẫn | Vai trò |
| :--- | :--- |
| `main.go` | Điểm vào: nạp cấu hình, khởi tạo các thành phần, cờ `--hash-password` và `--version` |
| `internal/config` | Đọc biến môi trường, giá trị mặc định |
| `internal/auth` | Đăng nhập bcrypt, cookie phiên ký HMAC-SHA256, giới hạn đăng nhập sai (5 lần trong 60 giây thì khóa 5 phút) |
| `internal/state` | Lưu proxy và gán thiết bị vào `state.json`, ghi kiểu atomic |
| `internal/proxy` | Mô hình proxy, parser URI, chuyển sang outbound của `sing-box`, kiểm tra proxy |
| `internal/singbox` | Sinh `sing-box.json`, giám sát tiến trình (khởi động, dừng, tự chạy lại sau 3 giây khi chết) |
| `internal/mikrotik` | REST client RouterOS: DHCP lease, ARP, address-list, firewall IPv6, connection tracking, trạng thái LeakGuard |
| `internal/web` | HTTP handler, định tuyến API, phục vụ file tĩnh |
| `web/dist` | Frontend thuần, không build step: `index.html` (khung trang và SVG sprite), `theme.js` (áp theme sáng/tối trước khi vẽ), `app.js` (dựng DOM bằng `textContent`, không dùng `innerHTML`), `style.css`. Chạy dưới CSP chặn script nội tuyến và tài nguyên ngoài |
| `entrypoint.sh` | Chuẩn bị mạng trong container (bật `ip_forward`, tắt `rp_filter`, thêm route về LAN, cài forward guard) rồi chạy `proxy-dash` |
| `Dockerfile`, `scripts/build-arm64-tar.sh` | Build image `linux/arm64` và đóng gói thành file tar cho RouterOS |

## Luồng gán proxy cho một thiết bị

`PUT /api/devices/{ip}/assignment` với body `{mac, nickname, proxyId}`:

1. Kiểm tra đầu vào: IP nằm trong `LAN_CIDR`, MAC là địa chỉ 48 bit hợp lệ (bắt buộc), biệt danh không quá dài và không có ký tự điều khiển, proxy tồn tại. Sai thì trả 400 hoặc 404, chưa đụng tới router.
2. Chuyển DHCP lease của thiết bị thành static (lớp L1). Bước `lease`.
3. Thêm IP vào address-list `PROXY_DEVICES`. Từ lúc này router dẫn lưu lượng của thiết bị vào container, kill-switch và DNS hijack bắt đầu áp dụng. Bước `address-list`.
4. Thêm hai rule IPv6 reject theo MAC, ở chain `forward` và `input`, comment `proxy-dash-ipv6-fwd:<mac>` và `proxy-dash-ipv6-in:<mac>` (lớp L4). Bước `ipv6`.
5. Lưu gán vào `state.json`. Bước `state`.
6. Sinh lại `sing-box.json`, chạy `sing-box check`, rồi khởi động lại `sing-box`. Bước `singbox`.
7. Xóa các kết nối đang mở của thiết bị trong connection tracking để ép đi tuyến mới. Bước `flush`.

Các thao tác ghi chạy tuần tự, mỗi lúc một thao tác (khóa `opMu`).

**Khi một bước hỏng:** API trả HTTP 500 với body `{error, step, applied}`. `step` là tên bước hỏng. `applied=false` nghĩa là thay đổi không có hiệu lực: các bước đã làm trên router được gỡ lại và gán cũ trong state được khôi phục; nếu chính việc hoàn tác hỏng thì `error` nói rõ phần nào còn sót. `applied=true` nghĩa là gán đã có hiệu lực nhưng bước dọn dẹp cuối hỏng (ví dụ không cắt được kết nối cũ).

**Bỏ gán** (`DELETE`) theo thứ tự: gỡ khỏi `PROXY_DEVICES`, gỡ rule IPv6 (hỏng thì thêm lại address-list để thiết bị không rơi vào trạng thái nửa vời), xóa gán trong state, nạp lại `sing-box`, cắt kết nối. Từ bước xóa gán trở đi, lỗi được báo với `applied=true`.

Đây chưa phải giao dịch thật: nếu router mất kết nối đúng lúc hoàn tác thì router và state vẫn có thể lệch nhau. Nút đồng bộ (`POST /api/system/reconcile`) đưa router về khớp với state.

## Cấu hình sing-box được sinh ra

**Inbound**

- `tun0`: địa chỉ `172.19.0.1/30`, MTU 1400, `auto_route`, stack `mixed`, loại trừ các dải trong `EXCLUDE_CIDRS`.
- `dns-in`: lắng nghe `0.0.0.0:53`, nhận DNS mà router chuyển về.

**DNS**

- `dns-bootstrap`: UDP tới `CONTAINER_GW`, chỉ để phân giải tên miền của máy chủ proxy.
- `dns-fakeip`: trả địa chỉ giả trong dải `198.18.0.0/15`.
- `dns-doh-<id>`: DoH tới `1.1.1.1`, đi qua outbound của proxy tương ứng.
- Quy tắc: reject `AAAA`, `HTTPS`, `SVCB`; truy vấn `A` từ thiết bị đã gán nhận FakeIP với TTL 1 giây (mặc định 600 giây của sing-box khiến thiết bị vừa chuyển về đi thẳng không vào được web trong nhiều phút, vì bộ nhớ đệm DNS của nó còn giữ địa chỉ FakeIP không định tuyến được); truy vấn khác đi DoH qua proxy của thiết bị; còn lại reject.

**Route**

1. Sniff giao thức, bắt DNS.
2. Reject IPv6.
3. Theo từng IP nguồn: nếu proxy không hỗ trợ UDP thì reject UDP; còn lại đi outbound `proxy-<id>`.
4. Reject đích là địa chỉ riêng.
5. Reject tất cả những gì còn lại. Không có outbound direct cho lưu lượng của thiết bị.

## API

Mọi endpoint dưới `/api`, trừ đăng nhập, đều yêu cầu cookie phiên.

| Method | Đường dẫn | Việc làm |
| :--- | :--- | :--- |
| POST | `/api/auth/login` | Đăng nhập, body `{password}` |
| POST | `/api/auth/logout` | Đăng xuất |
| GET | `/api/auth/me` | Kiểm tra phiên |
| GET | `/api/devices` | Danh sách thiết bị LAN kèm trạng thái gán |
| PUT | `/api/devices/{ip}/assignment` | Gán proxy, body `{mac, nickname, proxyId}` |
| DELETE | `/api/devices/{ip}/assignment` | Bỏ gán |
| PUT | `/api/devices/{ip}/nickname` | Đặt biệt danh, body `{nickname}` |
| POST | `/api/devices/{ip}/flush` | Cắt kết nối đang mở của thiết bị |
| GET | `/api/proxies` | Danh sách proxy, không kèm mật khẩu hay UUID |
| POST | `/api/proxies` | Thêm proxy; ID do server sinh |
| POST | `/api/proxies/import` | Thêm nhiều proxy từ văn bản, body `{text, defaultProto}` |
| GET, PUT, DELETE | `/api/proxies/{id}` | Xem, sửa, xóa một proxy; xóa proxy đang gán trả 409 |
| POST | `/api/proxies/{id}/test` | Kiểm tra proxy |
| GET | `/api/system/status` | Trạng thái sáu lớp và `sing-box` |
| POST | `/api/system/reconcile` | Đồng bộ lại rule trên router theo state và nạp lại `sing-box` |
| POST | `/api/system/flush-all` | Cắt kết nối của mọi thiết bị đã gán |
| GET | `/api/system/logs` | Log gần đây của `sing-box` |

Quy ước chung:

- Sai method trả 405 kèm header `Allow`. Body lớn hơn 1 MiB bị từ chối.
- Proxy trả về có `hasPassword` và `hasUuid` thay cho giá trị thật. Khi `PUT`, để trống mật khẩu hoặc UUID nghĩa là giữ giá trị cũ (nếu không đổi giao thức).
- Xóa proxy đang được gán trả 409 với `{error, devices}`.
- Thao tác nhiều bước hỏng trả 500 với `{error, step, applied}` như mô tả ở trên.
- `sing-box` chỉ mang những proxy đang có thiết bị, nên thêm, nhập hay xóa proxy chưa gán không khởi động lại `sing-box`.
- `/api/system/status` trả từng lớp với trạng thái `ok`, `warning`, `error` hoặc `unknown`, và trạng thái tổng thể `protected`, `degraded`, `unknown` hoặc `unprotected`.

Giao diện hiện chưa có chức năng sửa proxy, dù API đã hỗ trợ `PUT`.

## Dữ liệu trong `/data`

| File | Nội dung | Nhạy cảm |
| :--- | :--- | :--- |
| `state.json` | Danh sách proxy (kèm mật khẩu, UUID), gán thiết bị, kết quả test gần nhất | Có |
| `session.key` | Khóa ký cookie phiên, tự sinh lần chạy đầu | Có |
| `sing-box.json` | Cấu hình `sing-box` sinh ra, chứa thông tin đăng nhập proxy | Có |
| `cache.db` | Bộ nhớ đệm FakeIP của `sing-box` | Không |
| `router-ca.pem` (tùy chọn) | Chứng chỉ CA của router, nếu đặt `MIKROTIK_CA_FILE` trỏ vào đây | Không |

Sao lưu `state.json` và `session.key` là đủ để dựng lại. Xóa `session.key` làm mọi phiên đăng nhập hiện có mất hiệu lực.

## Thứ dashboard sở hữu trên router

Dashboard chỉ tạo và xóa các mục sau, nhận diện qua comment:

- Mục trong address-list `PROXY_DEVICES`, comment `proxy-dash:<mac>`
- Rule `/ipv6/firewall/filter` có comment bắt đầu bằng `proxy-dash-ipv6-`
- Cờ static trên DHCP lease của thiết bị đã gán

Bảng định tuyến, routing rule, rule mangle, kill-switch và NAT DNS do người quản trị tạo tay; dashboard chỉ đọc để báo trạng thái. Nút đồng bộ chỉ sửa ba loại mục ở trên: thêm mục thiếu, gỡ mục address-list thừa và rule IPv6 mồ côi.

Trong container, `entrypoint.sh` còn sở hữu các rule iptables của forward guard (chain `FORWARD`); chúng mất khi container dừng.
