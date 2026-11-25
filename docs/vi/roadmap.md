[English](../roadmap.md) | **Tiếng Việt**

# Lộ trình

Lộ trình đề xuất sau đợt rà soát ngày 2026-11-25. Giai đoạn 1 đã vá trong code ngày 2026-11-25; giai đoạn 2 và 3 vẫn là kế hoạch. Mã trong ngoặc (H1, M2...) trỏ tới [security.md](security.md).

## Giai đoạn 1: vá điểm yếu

Mục tiêu: những gì dashboard báo phải đúng với thực tế, và phiên quản trị không bị chiếm.

**Trạng thái: đã vá trong code, chưa kiểm chứng trên router thật.** Muốn triển khai cần build lại image và nạp lên router. Forward guard mới thử trên kernel Docker, chưa thử trên kernel RouterOS.

| Việc | Giải quyết | Trạng thái |
| :--- | :--- | :--- |
| Escape mọi giá trị động ở frontend, kiểm tra `exitIp` và `countryCode` ở backend, thêm CSP | H1 | Xong. Lần tra cứu đầu vẫn qua `http://ip-api.com` |
| Lấy IP client từ `RemoteAddr` | H2 | Xong |
| Kiểm tra kill-switch theo thuộc tính và vị trí rule | H3 | Xong. Phần vị trí là ước lượng, có thể cảnh báo nhầm |
| Rule trong container: drop gói forward không ra `tun0` | H3 | Xong trong `entrypoint.sh`, image thêm `iptables-legacy`. Trên RouterOS có thể rơi về `unavailable`, khi đó lớp L6 báo cảnh báo |
| Chặn xóa proxy đang được gán | M2 | Xong. API trả 409 kèm danh sách thiết bị |
| Trả lỗi thật khi gán, bỏ gán, nạp lại `sing-box` | M7 | Xong. Có hoàn tác và báo bước hỏng |
| Kiểm tra thật sáu lớp; siết khớp cổng ở L5; thêm trạng thái "không kiểm tra được" | M1 | Xong |
| Che mật khẩu proxy trong phản hồi API | M6 | Xong |
| Giới hạn body, header bảo mật, kiểm tra method, kiểm tra định dạng MAC và biệt danh, sinh ID proxy phía server | L1 đến L4 | Xong |
| Thêm `MIKROTIK_CA_FILE`, đổi mặc định sang xác minh chứng chỉ | M4 | Xong. Phá vỡ tương thích: triển khai cũ phải khai báo CA. Tài khoản mặc định vẫn là `admin` |
| Ghim phiên bản image, nâng `x/crypto`, chạy `govulncheck` trong quy trình build | L7 | Xong. Còn upx và chạy quyền root |

Việc còn lại trước khi coi giai đoạn 1 là xong hẳn:

- Triển khai lên router thật và xác nhận sáu lớp báo đúng với cấu hình đang chạy.
- Xác nhận forward guard cài được trên kernel RouterOS, hoặc ghi nhận là không cài được.
- Khai báo CA của router và kiểm tra SAN của chứng chỉ khớp host trong `MIKROTIK_URL`.

## Giai đoạn 2: vận hành tin cậy

Mục tiêu: phát hiện và sửa sai lệch mà không cần người ngồi canh.

- **Watchdog:** kiểm tra sáu lớp định kỳ, so sánh state với router, tự sửa phần dashboard sở hữu, ghi lại phần không tự sửa được. (M3)
- **Tự thiết lập rule nền:** nút "Thiết lập router" tạo bảng định tuyến, kill-switch, NAT DNS có xem trước thay đổi, thay cho việc gõ tay. Giải quyết luôn vấn đề routing rule. (M8)
- **Kiểm tra proxy định kỳ:** đo lại theo lịch, lưu lịch sử độ trễ, đánh dấu proxy chết.
- **Nhật ký thao tác:** ai đăng nhập, gán gì, lúc nào, thành công hay lỗi.
- **Phiên có thu hồi:** danh sách phiên đang mở, đăng xuất từ xa, đổi mật khẩu trên giao diện. (M5)
- **Sửa proxy trên giao diện:** API đã có, chỉ thiếu form.
- **Sao lưu và khôi phục:** xuất, nhập `state.json` có mã hóa bằng mật khẩu.
- **Cảnh báo đổi MAC:** phát hiện MAC ngẫu nhiên và MAC thay đổi trên IP đã gán. (H4)
- **Nạp lại cấu hình ít gián đoạn hơn:** thêm, nhập, xóa proxy chưa gán đã không còn khởi động lại `sing-box` (làm ở giai đoạn 1). Còn lại: bỏ qua khi cấu hình sinh ra không đổi; cân nhắc tách tiến trình theo nhóm thiết bị.
- **HTTPS cho dashboard:** chứng chỉ tự ký sinh sẵn hoặc nạp chứng chỉ riêng. (M5)

## Giai đoạn 3: mở rộng tính năng

Sắp theo giá trị ước lượng so với công sức.

| Tính năng | Mô tả | Phụ thuộc |
| :--- | :--- | :--- |
| Nhóm proxy và tự chuyển dự phòng | Gán thiết bị vào một nhóm; proxy chết thì tự chuyển sang proxy khác trong nhóm (`urltest`, `selector` của `sing-box`) | Kiểm tra proxy định kỳ |
| Nhóm thiết bị | Gán một lần cho cả nhóm (ví dụ "Điện thoại công việc") | |
| Thông báo | Telegram hoặc webhook khi proxy chết, lớp bảo vệ lệch, đăng nhập lạ | Watchdog |
| Thống kê lưu lượng | Dung lượng và số kết nối theo thiết bị, theo proxy | API thống kê của `sing-box` |
| Nhập từ subscription URL | Tự cập nhật danh sách proxy từ nhà cung cấp | Kiểm tra dữ liệu đầu vào chặt (xem H1) |
| Định tuyến theo tên miền | Một số tên miền đi proxy khác hoặc bị chặn (rule-set) | |
| DoH tùy chọn | Chọn máy chủ DoH theo từng proxy | L9 |
| Lịch gán | Bật, tắt proxy cho thiết bị theo giờ | |
| Nhiều tài khoản, xác thực hai bước | Phân quyền xem và sửa; TOTP | Phiên có thu hồi |
| IPv6 qua proxy | Thay vì chặn hẳn, chuyển IPv6 qua proxy có hỗ trợ | Cần thiết kế lại L4 |

## Nguyên tắc khi thêm tính năng

- Lỗi thì ngắt mạng, không bao giờ rơi về đi trực tiếp.
- Mỗi lớp bảo vệ phải có phép kiểm tra tự động tương ứng; chưa kiểm tra được thì giao diện phải nói là chưa.
- Dữ liệu đến từ proxy, từ router, từ người dùng đều coi là không tin cậy khi hiển thị.
- Thao tác ghi lên router phải có ghi nhật ký và có cách hoàn tác.
