[English](../security.md) | **Tiếng Việt**

# Bảo mật

Tài liệu này ghi lại mô hình đe dọa, các điểm yếu tìm thấy trong đợt rà soát code ngày 2026-11-25, và việc cần làm để siết lại.

**Phạm vi rà soát:** toàn bộ code Go, frontend, Dockerfile, entrypoint và README. Một cấu hình RouterOS 7.25.1 đang chạy cũng đã được đối chiếu ở chế độ chỉ đọc: filter, NAT, mangle, routing rule, routing table, address-list và IP service.

**Trạng thái:** giai đoạn 1 đã vá trong code ngày 2026-11-25. Mỗi mục bên dưới ghi rõ **Đã vá**, **Vá một phần** hoặc **Còn mở**. Kiểm tra đã chạy: `go vet`, `go test` (7 package), `staticcheck`, `govulncheck` (không có lỗ hổng khi build bằng Go 1.27.4, là toolchain của image).

**Chưa kiểm chứng trên thiết bị thật:** bản vá chưa được triển khai lên router. Riêng forward guard trong container mới chỉ thử trên kernel Docker, chưa thử trên kernel RouterOS (xem H3).

## Mô hình đe dọa

Thứ cần bảo vệ:

1. IP thật của thiết bị đã gán proxy (không lộ qua IPv4, IPv6, DNS, WebRTC).
2. Thông tin đăng nhập proxy (mật khẩu, UUID) lưu trong `state.json`.
3. Quyền điều khiển router: dashboard giữ một tài khoản RouterOS có quyền ghi.

Ai có thể tấn công:

| Tác nhân | Khả năng |
| :--- | :--- |
| Nhà cung cấp proxy | Thấy và sửa được mọi lưu lượng không mã hóa đi qua proxy của họ, kể cả lúc dashboard test proxy |
| Thiết bị trong LAN | Gửi được request tới dashboard, nghe lén được HTTP trong cùng mạng, tự đổi IP hoặc MAC |
| Người dùng thiết bị đã gán | Muốn thoát proxy để đi mạng trực tiếp |
| Website mà thiết bị truy cập | Dò IP thật qua WebRTC, DNS, IPv6 |

Ngoài phạm vi: kẻ tấn công đã chiếm được router, tấn công vật lý, lỗi trong `sing-box` hay RouterOS.

## Điểm yếu đã biết

### Mức cao

**H1. Stored XSS qua kết quả kiểm tra proxy. Đã vá, còn một phần nhỏ.**
Trước đây `app.js` chèn `exitIp`, `countryCode` và MAC vào `innerHTML` không escape, trong khi hai giá trị đầu đến từ `http://ip-api.com` qua chính proxy đang được test. Một proxy độc hại chèn được script vào phiên quản trị.
*Đã làm:* frontend dựng toàn bộ DOM bằng `createElement` và `textContent`, không còn chỗ nào gán `innerHTML` từ dữ liệu API (`web/dist/app.js`); backend chỉ nhận `exitIp` là IP hợp lệ, `countryCode` đúng hai chữ cái, các nhãn còn lại bị cắt độ dài và bỏ ký tự điều khiển (`internal/proxy/sanitize.go`); thêm Content-Security-Policy không cho script nội tuyến (`internal/web/handler.go`).
*Còn lại:* lần tra cứu đầu vẫn gọi `http://ip-api.com` (bản miễn phí không có HTTPS), nên nhà cung cấp proxy vẫn làm giả được quốc gia, ISP hiển thị. Dữ liệu giả không còn chạy được script, chỉ sai thông tin.

**H2. Vượt giới hạn đăng nhập sai bằng header giả. Đã vá.**
IP client nay lấy từ `RemoteAddr` (`GetClientIP` trong `internal/auth/auth.go`); `X-Forwarded-For` và `X-Real-IP` bị bỏ qua. Nếu sau này đặt dashboard sau reverse proxy thì mọi client sẽ chung một IP, khi đó cần thêm cấu hình danh sách proxy tin cậy.

**H3. Kill-switch chỉ được kiểm tra bằng comment, container không tự chặn forward. Đã vá trong code, chưa kiểm chứng trên RouterOS.**
*Đã làm, phía dashboard:* lớp L3 tìm rule theo comment `proxy-dash-killswitch` rồi kiểm tra từng thuộc tính: không disabled, không invalid, `chain=forward`, `action` là `drop` hoặc `reject`, `src-address-list=PROXY_DEVICES`. Thiếu `out-interface` hoặc `out-interface-list`, hoặc có rule accept đứng trước có thể cho kết nối mới đi qua, thì báo cảnh báo (`layerKillSwitch` trong `internal/mikrotik/status.go`).
*Đã làm, phía container:* `entrypoint.sh` cài forward guard: policy FORWARD là DROP, chỉ cho gói đi ra `tun0`, đi vào từ `tun0`, hoặc có đích trong `EXCLUDE_CIDRS`. Khi `sing-box` dừng, `tun0` biến mất và mọi gói forward bị chặn ngay trong container.
*Giới hạn cần biết:*
- RouterOS chỉ mở một phần netfilter cho container, nên guard có thể không cài được. Khi đó container vẫn chạy (chế độ `auto`), log in cảnh báo, lớp L6 báo cảnh báo và trạng thái tổng thể là `degraded`. Kill-switch trên router vẫn là lớp chặn chính. Chi tiết và nguồn ở [routeros-setup.md](routeros-setup.md#7-forward-guard-trong-container).
- Phép kiểm tra vị trí kill-switch là ước lượng: nó bỏ qua rule accept chỉ dành cho kết nối established, related, và rule loại trừ `PROXY_DEVICES`, nhưng không đánh giá địa chỉ hay interface. Một rule accept vô hại đứng trước vẫn có thể gây cảnh báo nhầm.

**H4. Thiết bị tự thoát proxy bằng cách đổi IP hoặc MAC. Còn mở (giai đoạn 2).**
Toàn bộ cơ chế dựa trên IP nguồn nằm trong `PROXY_DEVICES` và rule IPv6 theo MAC. Thiết bị tự đặt IP tĩnh khác trong LAN, hoặc điện thoại bật MAC ngẫu nhiên, sẽ không còn khớp rule nào và đi mạng trực tiếp.
*Hướng vá:* bật `add-arp=yes` và `arp=reply-only` (xem [routeros-setup.md](routeros-setup.md#6-siết-thêm-khuyến-nghị)); dashboard cảnh báo khi MAC của IP đã gán thay đổi hoặc là MAC ngẫu nhiên (bit locally administered).

### Mức trung bình

**M1. Trạng thái LeakGuard báo sai. Đã vá.**
Cả sáu lớp nay được kiểm tra thật (`internal/mikrotik/status.go`):

| Lớp | Điều kiện để báo đạt |
| :--- | :--- |
| L1 | Mỗi thiết bị đã gán có DHCP lease đúng IP và MAC, không disabled, không dynamic |
| L2 | Có bảng `via-proxy`; có routing rule đang bật trỏ vào bảng; có rule mangle `mark-routing` theo `PROXY_DEVICES` hoặc routing rule có nguồn; mọi thiết bị đã gán có trong `PROXY_DEVICES` |
| L3 | Xem H3 |
| L4 | Mỗi MAC đã gán có đủ hai rule IPv6 (`forward` và `input`), đúng MAC, action là drop hoặc reject, không đứng sau rule accept |
| L5 | Có rule `dst-nat` cho cả UDP và TCP, `dst-port` chứa đúng cổng 53 (hiểu danh sách và khoảng cổng), không bị rule NAT khác bắt cổng 53 trước |
| L6 | `sing-box` đang chạy và forward guard ở trạng thái `active` |

Lớp nào không đọc được từ router thì báo `unknown` ("không kiểm tra được") thay vì báo đạt. Trạng thái tổng thể có bốn giá trị: `protected`, `degraded`, `unknown`, `unprotected`.

**M2. Xóa proxy làm thiết bị mất mạng mà giao diện báo ngược lại. Đã vá.**
Proxy đang được gán không xóa được nữa: API trả 409 kèm danh sách thiết bị, giao diện yêu cầu bỏ gán hoặc chuyển thiết bị sang proxy khác trước (`handleProxyDelete`, `DeleteProxy`).

**M3. Không có giám sát định kỳ. Còn mở (giai đoạn 2).**
`Reconcile` nay báo mọi lỗi, thêm rule thiếu, gỡ mục address-list thừa và dọn rule IPv6 mồ côi, nhưng vẫn chỉ chạy lúc khởi động và khi bấm đồng bộ. Ai đó sửa firewall trên router thì dashboard chỉ biết khi có người mở trang trạng thái.
*Hướng vá:* watchdog chạy định kỳ, ghi lại sai lệch, tự sửa những gì dashboard sở hữu.

**M4. Kết nối tới router không xác minh chứng chỉ và dùng tài khoản admin. Vá một phần.**
*Đã làm:* mặc định nay là xác minh chứng chỉ. `MIKROTIK_CA_FILE` nhận file PEM của CA hoặc của chính chứng chỉ tự ký. `MIKROTIK_INSECURE_TLS=true` vẫn còn để dùng tạm, mỗi lần khởi động in cảnh báo.
*Thay đổi phá vỡ tương thích:* triển khai cũ không đặt biến nào sẽ không kết nối được router sau khi nâng cấp, cho tới khi đặt `MIKROTIK_CA_FILE` hoặc tạm bật lại `MIKROTIK_INSECURE_TLS=true`. Chứng chỉ của router phải có SAN khớp host trong `MIKROTIK_URL`.
*Còn lại:* `MIKROTIK_USER` mặc định vẫn là `admin`; việc dùng tài khoản quyền hẹp mới chỉ là hướng dẫn trong [routeros-setup.md](routeros-setup.md).

**M5. Dashboard HTTP thuần, phiên không thu hồi được. Còn mở (giai đoạn 2).**
Mật khẩu và cookie đi dạng rõ trong LAN. Cookie không có cờ `Secure`. Phiên là token tự ký sống 24 giờ; đăng xuất hay đổi mật khẩu không vô hiệu được token đã cấp.
*Hướng vá:* hỗ trợ TLS; lưu phiên phía server để thu hồi được; đổi mật khẩu thì hủy mọi phiên.

**M6. API trả mật khẩu proxy về trình duyệt. Đã vá.**
Phản hồi của `/api/proxies` không còn chứa mật khẩu hay UUID, chỉ có `hasPassword` và `hasUuid`. Khi sửa proxy, để trống hai trường này nghĩa là giữ giá trị cũ. Bí mật vẫn nằm dạng rõ trong `state.json` và `sing-box.json` trên đĩa.

**M7. Lỗi bị nuốt. Đã vá.**
Gán, bỏ gán, nạp lại `sing-box` và đồng bộ đều trả lỗi thật. Thao tác nhiều bước trả `{error, step, applied}`: `step` là bước hỏng, `applied` cho biết thay đổi đã có hiệu lực hay đã được hoàn tác. Khi gán hỏng giữa chừng, các bước đã làm trên router được gỡ lại; nếu chính việc hoàn tác hỏng thì thông báo nói rõ.

**M8. Routing rule trong hướng dẫn cũ áp cho cả dải LAN. Tài liệu đã sửa; phần tự thiết lập còn mở (giai đoạn 2).**
[routeros-setup.md](routeros-setup.md#policy-routing) đã được viết lại: dùng rule mangle `mark-routing` chỉ cho `PROXY_DEVICES` cùng routing rule theo `routing-mark`. Dashboard vẫn chưa tự tạo các rule nền này.

### Mức thấp

- **L1. Đã vá.** Body request giới hạn 1 MiB; có CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
- **L2. Đã vá.** Mọi endpoint kiểm tra method, sai thì trả 405 kèm header `Allow`.
- **L3. Đã vá.** MAC phải là địa chỉ 48 bit hợp lệ; biệt danh bị giới hạn độ dài và không được chứa ký tự điều khiển. Gán thiết bị bắt buộc có MAC.
- **L4. Đã vá.** ID proxy do server sinh, ID từ client bị bỏ qua.
- **L5. Còn mở.** Nhận diện gateway bằng `strings.HasSuffix(ip, ".1")` (`handler.go`, `devices.go`) thay vì so với địa chỉ gateway thật. Nếu gateway của LAN không kết thúc bằng `.1` thì vẫn gán proxy được cho chính gateway.
- **L6. Vá một phần.** Phản hồi của RouterOS nay được đọc có giới hạn kích thước và lỗi có kiểu riêng (`APIError`). Thông báo lỗi trả về giao diện vẫn chứa nội dung lỗi của RouterOS.
- **L7. Vá một phần.** Ba image nền đã ghim theo phiên bản và digest; `golang.org/x/crypto` lên v0.59.0; `govulncheck`, `go vet`, `go test` chạy trong quy trình build. Còn lại: binary vẫn nén bằng upx, tiến trình vẫn chạy quyền root (cần cho TUN và iptables).
- **L8. Còn mở.** Bộ giới hạn đăng nhập không dọn bản ghi cũ; `stopLocked` trong supervisor nhả khóa giữa chừng; bộ test proxy chọn cổng trống rồi mới dùng (có khe hở); mỗi thao tác tải toàn bộ bảng từ router rồi lọc phía client.
- **L9. Còn mở.** DoH cố định `1.1.1.1`, không đổi được.

Ghi chú về `govulncheck`: kết quả sạch là với Go 1.27.4 trong image build. Go 1.26.4 có lỗ hổng trong thư viện chuẩn (đã sửa ở 1.26.5 và 1.26.6), nên đừng phát hành binary build ngoài Docker bằng bản Go đó.

## Danh sách việc cần làm khi triển khai

- [ ] Build lại image bằng `scripts/build-arm64-tar.sh` và nạp lên router; image build trước các bản vá này không chứa chúng
- [ ] Xuất chứng chỉ (hoặc CA) của router, đặt vào `/data`, khai báo `MIKROTIK_CA_FILE`; kiểm tra SAN khớp host trong `MIKROTIK_URL`
- [ ] Sau khi container chạy, xem log để biết forward guard là `active` hay `unavailable`; chỉ đặt `FORWARD_GUARD=enforce` khi đã thấy `active`
- [ ] Mở trang trạng thái, xử lý mọi lớp không ở trạng thái đạt
- [ ] Tạo tài khoản RouterOS riêng, quyền hẹp, giới hạn theo địa chỉ container
- [ ] Giới hạn truy cập cổng 8080 chỉ cho máy quản trị
- [ ] Bật `add-arp=yes` và `arp=reply-only` sau khi đã liệt kê thiết bị IP tĩnh
- [ ] Tắt MAC ngẫu nhiên trên điện thoại, máy tính đã gán proxy
- [ ] Sau mỗi lần gán, tự kiểm tra rò rỉ trên chính thiết bị đó
- [ ] Đặt mật khẩu dashboard dài, không dùng lại ở nơi khác

Việc sửa code còn lại: H4, M3, M5, phần tự thiết lập của M8, rồi L5, L8, L9. Kế hoạch theo giai đoạn nằm ở [roadmap.md](roadmap.md).

## Báo lỗi bảo mật

Báo lỗ hổng một cách riêng tư theo hướng dẫn trong [SECURITY.md](../../SECURITY.md), không mở issue công khai. Ghi lại file, dòng, cách tái hiện và ảnh hưởng. Không đính kèm `state.json`, giá trị biến môi trường hay bản export cấu hình router có bí mật.
