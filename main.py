import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import subprocess
import os
import hashlib
import threading
from collections import defaultdict
from asn1crypto import x509

# 密码套件映射表
cipher_suite_mapping = {
    'c013': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    'c030': 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'c02f': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    '0001': 'SSL_RSA_WITH_NULL_MD5',
    '0002': 'SSL_RSA_WITH_NULL_SHA',
    '0004': 'SSL_RSA_WITH_RC4_128_MD5',
    '0005': 'SSL_RSA_WITH_RC4_128_SHA',
    '000a': 'SSL_RSA_WITH_3DES_EDE_CBC_SHA',
    '0016': 'TLS_RSA_WITH_AES_128_CBC_SHA',
    '0017': 'TLS_RSA_WITH_AES_256_CBC_SHA',
    '002f': 'TLS_RSA_AES_128_CBC_SHA',
    '0033': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
    '0035': 'TLS_RSA_WITH_AES_256_CBC_SHA',
    '0039': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
    '008c': 'TLS_PSK_WITH_AES_128_CBC_SHA',
    '008d': 'TLS_PSK_WITH_AES_256_CBC_SHA',
    '0090': 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA',
    '0091': 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA',
    '0094': 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA',
    '0095': 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA',
    '00ae': 'TLS_PSK_WITH_AES_128_CBC_SHA256',
    '00af': 'TLS_PSK_WITH_AES_256_CBC_SHA384',
    '00b2': 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256',
    '00b3': 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384',
    '00b6': 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256',
    '00b7': 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384',
    '003c': 'TLS_RSA_WITH_AES_128_CBC_SHA256',
    '003d': 'TLS_RSA_WITH_AES_256_CBC_SHA256',
    '0067': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
    '006b': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
    '009c': 'TLS_RSA_WITH_AES_128_GCM_SHA256',
    '009d': 'TLS_RSA_WITH_AES_256_GCM_SHA384',
    '009e': 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
    '009f': 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
    '00a8': 'TLS_PSK_WITH_AES_128_GCM_SHA256',
    '00a9': 'TLS_PSK_WITH_AES_256_GCM_SHA384',
    '00aa': 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256',
    '00ab': 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384',
    '00ac': 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256',
    '00ad': 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384',
    'cca8': 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    'cca9': 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    'ccaa': 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    'ccab': 'TLS_PSK_WITH_CHACHA20_POLY1305_SHA256',
    'ccac': 'TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
    'ccad': 'TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
    'ccae': 'TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256',
    '1301': 'TLS_AES_128_GCM_SHA256',
    '1302': 'TLS_AES_256_GCM_SHA384',
    '1303': 'TLS_CHACHA20_POLY1305_SHA256',
    'e011': 'ECDHE_SM4_CBC_SM3',
    'e051': 'ECDHE_SM4_GCM_SM3',
    'e013': 'ECC_SM4_CBC_SM3',
    'e053': 'ECC_SM4_GCM_SM3',
    'e015': 'IBSDH_SM4_CBC_SM3',
    'e055': 'IBSDH_SM4_GCM_SM3',
    'e017': 'IBC_SM4_CBC_SM3',
    'e057': 'IBC_SM4_GCM_SM3',
    'e019': 'RSA_SM4_CBC_SM3',
    'e059': 'RSA_SM4_GCM_SM3',
    'e01c': 'RSA_SM4_CBC_SHA256',
    'e05a': 'RSA_SM4_GCM_SHA256'
}

# 签名算法映射
SIG_ALG_MAPPING = {
    b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01': 'rsa',
    b'\x06\x08\x2a\x81\x1c\xcf\x55\x01\x82\x2d': 'sm2',
    b'\x06\x05\x2b\x0e\x03\x02\x1d': 'sha256withrsaencryption',
    b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b': 'sha256withrsa',
    b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01': 'sm3withsm2',
    b'\x06\x08*\x81\x1c\xcfU\x01\x83u':'sm3withsm2',
    b'\x06\x05\x2b\x0e\x03\x02\x1c': 'sha224withrsa',
    b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c': 'sha512withrsa',
    b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d': 'sha3-384withrsa',
    b'\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01': 'ed25519',
    b'\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02': 'ed448',
    b'\x06\x07\x2a\x86\x48\xce\x3d\x02\x01': 'md5withrsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07': 'ecdsa-with-sha1',
    b'\x06\x05\x2b\x24\x03\x01\x01': 'dsa',
    b'\x06\x07\x2a\x86\x48\xce\x3d\x04\x01': 'sha1withrsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x01\x04': 'sha224withrsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x01\x05': 'sha256withrsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x01\x06': 'sha384withrsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x01\x07': 'sha512withrsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x01\x02': 'sha1withdsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x01\x03': 'sha1withecdsa',
    b'\x06\x05\x2b\x0e\x03\x02\x1e': 'sha3-224withrsa',
    b'\x06\x05\x2b\x0e\x03\x02\x1f': 'sha3-256withrsa',
    b'\x06\x05\x2b\x0e\x03\x02\x20': 'sha3-384withrsa',
    b'\x06\x05\x2b\x0e\x03\x02\x21': 'sha3-512withrsa',
    b'\x06\x07\x2a\x86\x48\xce\x3d\x04\x02': 'sha1withrsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x01': 'sha224withecdsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02': 'sha256withecdsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x03': 'sha384withecdsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x04': 'sha512withecdsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x05': 'sha512-224withecdsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x06': 'sha512-256withecdsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x07': 'sha3-224withecdsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x08': 'sha3-256withecdsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x09': 'sha3-384withecdsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x0a': 'sha3-512withecdsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x0b': 'sha3-224withrsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x0c': 'sha3-256withrsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x0d': 'sha3-384withrsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x0e': 'sha3-512withrsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x0f': 'sha3-224withdsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x10': 'sha3-256withdsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x11': 'sha3-384withdsa',
    b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x12': 'sha3-512withdsa'
}


class PCAPParserApp:
    def __init__(self, root):
        self.root = root
        root.title("安全协议数据提取器v2.0-Tshark")
        root.geometry("1100x600")
        self.create_widgets()
        self.processing = False
        self.encrypted_data = []
        self.cipher_suite_info = []
        self.selected_protocols = {"TLS": True, "ESP": True}
        self.ip_filter = None
        self.certificates = []
        self.tcp_streams = {}
        self.seen_cert_hashes = set()
        self.current_file_path = None
        self.tshark_path = r"D:\Wireshark\tshark.exe"

    def create_widgets(self):
        main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_paned.pack(fill=tk.BOTH, expand=True)

        left_frame = ttk.Frame(main_paned, width=800)
        main_paned.add(left_frame, weight=1)

        right_frame = ttk.Frame(main_paned, width=300, padding=10)
        main_paned.add(right_frame)

        # 协议选择
        protocol_frame = ttk.LabelFrame(right_frame, text="协议选择", padding=10)
        protocol_frame.pack(fill=tk.X)
        self.tls_var = tk.BooleanVar(value=True)
        self.esp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(protocol_frame, text="TLS应用数据", variable=self.tls_var).pack(anchor=tk.W)
        ttk.Checkbutton(protocol_frame, text="IPSec ESP载荷", variable=self.esp_var).pack(anchor=tk.W)

        # IP过滤
        ip_filter_frame = ttk.LabelFrame(right_frame, text="IP过滤条件", padding=10)
        ip_filter_frame.pack(fill=tk.X)
        tk.Label(ip_filter_frame, text="源IP (IPa)").grid(row=0, column=0, sticky="w", pady=5)
        self.ip_a_entry = ttk.Entry(ip_filter_frame)
        self.ip_a_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Label(ip_filter_frame, text="目的IP (IPb)").grid(row=1, column=0, sticky="w", pady=5)
        self.ip_b_entry = ttk.Entry(ip_filter_frame)
        self.ip_b_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(ip_filter_frame, text="应用筛选", command=self.apply_ip_filter).grid(row=2, columnspan=2, pady=10)

        # 证书与密码套件信息区域
        cert_export_frame = ttk.LabelFrame(right_frame, text="证书与密码套件信息", padding=10)
        cert_export_frame.pack(fill=tk.X)
        self.cert_output = scrolledtext.ScrolledText(cert_export_frame, height=16, wrap=tk.WORD, width=40)
        self.cert_output.pack(fill=tk.X)
        self.btn_export_cert = ttk.Button(cert_export_frame, text="导出证书", command=self.export_certificate)
        self.btn_export_cert.pack(pady=10)

        # 控制区域
        control_frame = ttk.Frame(left_frame, padding=10)
        control_frame.pack(fill=tk.X)
        self.btn_open = ttk.Button(control_frame, text="打开抓包文件", command=self.open_file)
        self.btn_open.pack(side=tk.LEFT, padx=5)
        self.btn_save = ttk.Button(control_frame, text="保存结果", command=self.save_result, state=tk.DISABLED)
        self.btn_save.pack(side=tk.LEFT, padx=5)
        self.btn_copy = ttk.Button(control_frame, text="复制到剪贴板", command=self.copy_to_clipboard,
                                   state=tk.DISABLED)
        self.btn_copy.pack(side=tk.LEFT, padx=5)
        self.btn_save_sample = ttk.Button(control_frame, text="保存样本", command=self.save_sample, state=tk.DISABLED)
        self.btn_save_sample.pack(side=tk.LEFT, padx=5)
        self.progress = ttk.Progressbar(control_frame, mode='determinate')
        self.progress.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=5)

        # 结果展示
        result_frame = ttk.Frame(left_frame, padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True)
        self.txt_result = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD)
        self.txt_result.pack(fill=tk.BOTH, expand=True)

        # 状态栏
        self.status_frame = ttk.Frame(self.root, relief=tk.SUNKEN, height=30)
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        self.status = tk.Label(self.status_frame, text="就绪", anchor='w')
        self.status.pack(side=tk.LEFT, padx=10, pady=5)
        self.footer = tk.Label(self.status_frame, text="©Draina 2025.2于中远科技 版权所有 | 版本 2.0", anchor='e')
        self.footer.pack(side=tk.RIGHT, padx=10, pady=5)

    # IP过滤
    def apply_ip_filter(self):
        ip_a = self.ip_a_entry.get().strip()
        ip_b = self.ip_b_entry.get().strip()
        if ip_a and ip_b:
            if self.validate_ip(ip_a) and self.validate_ip(ip_b):
                self.ip_filter = (ip_a, ip_b)
                self.status.config(text=f"已应用筛选条件：源IP={ip_a}，目的IP={ip_b}")
            else:
                self.status.config(text="警告：IP地址格式不正确，请输入有效IPv4/IPv6地址")
        else:
            self.ip_filter = None
            self.status.config(text="已取消IP筛选条件")

        if self.current_file_path and not self.processing:
            self.start_processing(self.current_file_path)

    def validate_ip(self, ip):
        import socket
        try:
            socket.inet_aton(ip)   #尝试将输入的 IP 地址转换为二进制格式（32 位无符号整数）。如果成功，说明输入是一个有效的 IPv4 地址
            return True
        except socket.error:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, ip)   #尝试将输入的 IP 地址转换为二进制格式（128 位无符号整数）。如果成功，说明输入是一个有效的 IPv6 地址
            return True
        except socket.error:
            return False

    def open_file(self):
        if not self.processing:
            file_path = filedialog.askopenfilename(
                filetypes=[("PCAPNG或PCAP文件", "*.pcapng;*.pcap"), ("所有文件", "*.*")]
            )
            if file_path:
                self.selected_protocols = {  #选择文件后，获取复选框的选中状态
                    "TLS": self.tls_var.get(),
                    "ESP": self.esp_var.get()
                }
                self.start_processing(file_path)

    def start_processing(self, file_path):
        self.processing = True
        self.current_file_path = file_path
        filename = os.path.basename(file_path)
        self.root.title(f"安全协议数据提取器v2.0-Tshark —— {filename}")
        self.btn_open.config(state=tk.DISABLED)
        self.btn_save.config(state=tk.DISABLED)
        self.btn_copy.config(state=tk.DISABLED)
        self.btn_save_sample.config(state=tk.DISABLED)
        self.progress["value"] = 0                      #进度条从头开始
        self.txt_result.delete(1.0, tk.END)
        self.cert_output.delete(1.0, tk.END)
        self.status.config(text="正在解析文件...若文件较大请耐心等待(Tshark版不支持实时进度条)")
        self.cipher_suite_info = []
        self.certificates = []         # 套件、证书列表初始化
        self.sessions = {}
        self.tcp_streams = {}
        self.seen_cert_hashes = set()  # 重置证书哈希集合
        self.selected_protocols = {
            "TLS": self.tls_var.get(),
            "ESP": self.esp_var.get()
        }
        threading.Thread(
            target=self.process_pcap,
            args=(file_path,),
            daemon=True                # 守护线程：主程序退出自动终止
        ).start()

    def process_pcap(self, file_path):
        try:
            self.encrypted_data = []
            self.cipher_suite_info = []
            self.certificates = []
            self.seen_cert_hashes = set()

            # 构建基础过滤器
            base_filter = []
            if self.ip_filter:
                ip_a, ip_b = self.ip_filter
                base_filter.append(f"(ip.src=={ip_a}&&ip.dst=={ip_b})||(ip.src=={ip_b}&&ip.dst=={ip_a})")

            # 处理TLS相关数据
            if self.selected_protocols["TLS"]:
                tls_filter = "tls"
                if base_filter:
                    tls_filter = f"({tls_filter})&&({'&&'.join(base_filter)})"
                self.process_tls_data(file_path, tls_filter)

            # 处理ESP数据
            if self.selected_protocols["ESP"]:
                esp_filter = "esp"
                if base_filter:
                    esp_filter = f"({esp_filter})&&({'&&'.join(base_filter)})"
                self.process_esp_data(file_path, esp_filter)

            # 处理IKE相关数据（为ESP补充证书(套件抓不到，先写着吧)）
            if self.selected_protocols["ESP"]:
                ike_filter = "isakmp"
                if base_filter:
                    ike_filter = f"({ike_filter})&&({'&&'.join(base_filter)})"
                self.process_ike_data(file_path, ike_filter)

            self.root.after(0, self.show_result)
            self.root.after(0, self.show_combined_info)
        except Exception as e:
            self.root.after(0, self.show_error, str(e))
        finally:
            self.processing = False

    def process_ike_data(self, file_path, display_filter):
        """处理IKE协商的加密套件和证书 套件没法处理 占位先"""
        self.process_ike_certificates(file_path, display_filter)
        #self.process_ike_ciphersuites(file_path, display_filter)

    def process_ike_certificates(self, file_path, display_filter):
        """提取IKE证书"""
        command = [
            self.tshark_path,
            '-r', file_path,
            '-Y', f'isakmp.cert.data&&{display_filter}',
            '-T', 'fields',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'udp.payload'
        ]
        lines = self.run_tshark_command(command)

        for line in lines:
            parts = line.split('\t')
            if len(parts) < 3:
                continue
            src_ip, dst_ip, certs_hex = parts
            try:
                # 将udp.payload转换为字节流
                payload_bytes = bytes.fromhex(certs_hex.replace(':', ''))
                cert_list = []

                # 遍历字节流，查找证书的开始标志3082
                index = 0
                while index < len(payload_bytes):
                    # 查找3082的起始位置
                    if index + 1 < len(payload_bytes) and payload_bytes[index] == 0x30 and payload_bytes[
                        index + 1] == 0x82:
                        # 向前取两字节为证书报文总长度（单位为字节）
                        if index + 3 < len(payload_bytes):
                            length_bytes = payload_bytes[index + 2:index + 4]
                            cert_length = (length_bytes[0] << 8) | length_bytes[1]
                        else:
                            cert_length = 0  # 如果长度不足，设置默认值

                        # 计算证书的结束位置
                        cert_end = index + 4 + cert_length  # 4是3082和长度占用的字节数
                        # 提取证书数据
                        cert_data = payload_bytes[index:cert_end]
                        # 将3082前面的字节全部消除，作为证书16进制字符串
                        cert_hex = cert_data.hex().upper()
                        # 添加到证书列表
                        cert_list.append(cert_hex)

                        # 更新索引到证书结束位置
                        index = cert_end
                    else:
                        # 如果当前字节不是3082的起始字节，继续遍历
                        index += 1

                # 处理提取到的证书
                for cert_hex in cert_list:
                    cert_der = bytes.fromhex(cert_hex)
                    self.process_single_cert(cert_der, src_ip, dst_ip)

            except ValueError:
                continue

    def process_tls_data(self, file_path, display_filter):
        # 处理应用数据
        self.process_tls_appdata(file_path, display_filter)
        # 处理密码套件
        self.process_ciphersuites(file_path, display_filter)
        # 处理证书
        self.process_certificates(file_path, display_filter)

    def run_tshark_command(self, command):
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True
            )
            return result.stdout.splitlines()
        except subprocess.CalledProcessError as e:
            error_msg = f"tshark错误: {e.stderr}"
            self.root.after(0, self.show_error, error_msg)
            return []

    def process_tls_appdata(self, file_path, display_filter):
        command = [
            self.tshark_path,
            '-r', file_path,
            '-Y', f'tls.app_data&&{display_filter}',
            '-T', 'fields',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'tls.record.version',
            '-e', 'tls.app_data'
        ]
        lines = self.run_tshark_command(command)

        for line in lines:
            parts = line.split('\t')
            if len(parts) < 6:
                continue
            src_ip, dst_ip, sport, dport, version, data_hex = parts
            try:
                data = bytes.fromhex(data_hex)
                self.encrypted_data.append({
                    'proto': 'TLS',
                    'version': version,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'sport': sport,
                    'dport': dport,
                    'data': data
                })
            except ValueError:
                continue

    def process_ciphersuites(self, file_path, display_filter):
        command = [
            self.tshark_path,
            '-r', file_path,
            '-Y', f'tls.handshake.type==2&&{display_filter}',
            '-T', 'fields',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tls.handshake.ciphersuite'
        ]
        lines = self.run_tshark_command(command)

        for line in lines:
            parts = line.split('\t')
            if len(parts) < 3:
                continue
            src_ip, dst_ip, suite = parts
            self.cipher_suite_info.append((src_ip, dst_ip, suite))

        for line in lines:
            parts = line.split('\t')
            if len(parts) < 3:
                continue
            src_ip, dst_ip, suite = parts
            sorted_ips = sorted([src_ip, dst_ip])
            cipher_name = suite
            self.cipher_suite_info.append((sorted_ips[0], sorted_ips[1], cipher_name))

    def process_certificates(self, file_path, display_filter):
        command = [
            self.tshark_path,
            '-r', file_path,
            '-Y', f'tls.handshake.type==11&&{display_filter}',
            '-T', 'fields',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tls.handshake.certificate'
        ]
        lines = self.run_tshark_command(command)

        for line in lines:
            parts = line.split('\t')
            if len(parts) < 3:
                continue
            src_ip, dst_ip, certs_hex = parts
            try:
                certs = certs_hex.split(',')
                for cert_hex in certs:
                    cert_der = bytes.fromhex(cert_hex)
                    self.process_single_cert(cert_der, src_ip, dst_ip)
            except ValueError:
                continue

    def process_single_cert(self, cert_der, src_ip, dst_ip):
        cert_hash = hashlib.sha256(cert_der).hexdigest()
        if cert_hash in self.seen_cert_hashes:
            return
        self.seen_cert_hashes.add(cert_hash)

        try:
            cert = x509.Certificate.load(cert_der)
            sig_alg = cert['signature_algorithm']['algorithm']
            oid_bytes = sig_alg.dump()
            sig_name = SIG_ALG_MAPPING.get(oid_bytes, "未知算法")
            print(oid_bytes)
        except Exception as e:
            sig_name = f"解析失败: {str(e)}"

        # 修改点：保留原始IP顺序
        self.certificates.append({
            'ip_pair': f"{src_ip} -> {dst_ip}",  # 使用箭头明确方向
            'cert': cert_der,
            'cert_hash': cert_hash,
            'sig_alg': sig_name
        })

    def process_esp_data(self, file_path, display_filter):
        command = [
            self.tshark_path,
            '-r', file_path,
            '-Y', f'esp&&{display_filter}',
            '-T', 'fields',
            '-e', 'esp.spi',
            '-e', 'esp.sequence',
            '-e', 'udp.payload',
            '-e', 'ip.src',
            '-e', 'ip.dst'
        ]
        lines = self.run_tshark_command(command)


        for line in lines:
            parts = line.split('\t')
            if len(parts) != 5:
                continue
            spi_hex, seq_hex, data_hex, src_ip, dst_ip = parts
            try:
                # 清理十六进制数据
                spi = int(spi_hex.strip().replace('0x', ''), 16) if spi_hex.strip() else 0
                seq = int(seq_hex.strip().replace('0x', ''), 16) if seq_hex.strip() else 0
                data = bytes.fromhex(data_hex.replace(':', '')) if data_hex else b''
                if len(data) >= 16:
                    truncated_data = data[16:]
                else:
                    continue

                self.encrypted_data.append({
                    'proto': 'ESP',
                    'spi': spi,
                    'seq': seq,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'data': truncated_data
                })
            except ValueError as e:
                print(f"解析ESP数据失败: {e}")
                continue

    def update_progress(self, current, total):
        # 由于tshark无法获取进度，保持原有逻辑
        self.progress["value"] = 100
        self.status.config(text="解析完成")

    def show_result(self):
        self.progress["value"] = 100
        self.btn_open.config(state=tk.NORMAL)
        save_state = tk.NORMAL if self.encrypted_data else tk.DISABLED
        self.btn_save.config(state=save_state)
        self.btn_copy.config(state=save_state)
        self.btn_save_sample.config(state=save_state)

        if self.encrypted_data:
            output = []
            for idx, entry in enumerate(self.encrypted_data, 1):
                if entry['proto'] == 'TLS':
                    info = (f"[TLS{entry['version']}记录 #{idx} | "
                            f"{entry['src_ip']}:{entry['sport']} -> {entry['dst_ip']}:{entry['dport']} | "
                            f"长度 {len(entry['data'])} bytes:\n{entry['data'].hex()}\n")
                elif entry['proto'] == 'ESP':
                    info = (f"[ESP记录 #{idx} | SPI: 0x{entry['spi']:08x} 序列号: {entry['seq']} | "
                            f"{entry['src_ip']} -> {entry['dst_ip']}\n"
                            f"加密载荷长度 {len(entry['data'])} bytes:\n{entry['data'].hex()}\n")
                output.append(info)
            self.txt_result.insert(tk.END, "\n".join(output))
        else:
            self.txt_result.insert(tk.END, "未找到匹配的加密数据。\n")

        seen_ciphers = set()
        current_filter = self.ip_filter
        if current_filter:
            filtered_ips = sorted([current_filter[0], current_filter[1]])
        else:
            filtered_ips = None
        for src_ip, dst_ip, cs in self.cipher_suite_info:
            if current_filter:
                current_ips = sorted([src_ip, dst_ip])
                if current_ips != filtered_ips:
                    continue
            seen_ciphers.add(f"{src_ip}-{dst_ip}-{cs}")
        # 新增统计信息
        cipher_count = len(seen_ciphers)
        cert_count = len(self.seen_cert_hashes)
        encrypted_count = len(self.encrypted_data)
        # 更新统计信息（新增ESP统计）
        esp_count = sum(1 for e in self.encrypted_data if e['proto'] == 'ESP')
        tls_count = sum(1 for e in self.encrypted_data if e['proto'] == 'TLS')
        status_text = (f"解析完成: {encrypted_count}条数据 (TLS: {tls_count}, ESP: {esp_count}) | "
                       f"{cipher_count}组套件 | {cert_count}张证书")
        self.status.config(text=status_text)

    def show_combined_info(self):
        output = []
        seen_ciphers = set()
        seen_certs = set()

        # 获取当前过滤条件（保持原始顺序）
        current_filter = self.ip_filter
        if current_filter:
            filtered_ips = (current_filter[0], current_filter[1])  # 保持原始顺序

        # 密码套件信息处理（保持原始顺序）
        output.append("=== 密码套件信息(仅TLS) ===")
        for src_ip, dst_ip, cs in self.cipher_suite_info:
            # 应用IP过滤（考虑双向）
            if current_filter:
                if (src_ip, dst_ip) != filtered_ips and (dst_ip, src_ip) != filtered_ips:
                    continue

            key = f"{src_ip}-{dst_ip}-{cs}"
            if key not in seen_ciphers:
                seen_ciphers.add(key)
                cs_name = cipher_suite_mapping.get(cs[2:], f"未知套件")
                output.append(f"{src_ip} -> {dst_ip}: {cs_name} {cs})")

        # 证书信息处理（保持原始顺序）
        output.append("\n==== 证书信息 ====")
        server_found = False
        client_found = False

        for cert in self.certificates:
            # 应用IP过滤（考虑双向）
            if current_filter:
                cert_src, cert_dst = cert['ip_pair'].split(' -> ')
                if (cert_src, cert_dst) != filtered_ips and (cert_dst, cert_src) != filtered_ips:
                    continue

            cert_hash = cert['cert_hash']
            if cert_hash in seen_certs:
                continue
            seen_certs.add(cert_hash)

            output.append(
                f"{cert['ip_pair']}\n"
                f"签名算法为{cert['sig_alg']}  哈希={cert_hash[:16]}"
            )

        self.cert_output.delete(1.0, tk.END)
        self.cert_output.insert(tk.END, "\n".join(output))

    def export_certificate(self):
        if not self.certificates:
            self.status.config(text="没有证书可供导出")
            return

        # 让用户选择保存目录
        save_dir = filedialog.askdirectory(title="选择证书保存目录")
        if not save_dir:  # 用户取消选择
            self.status.config(text="已取消证书导出")
            return

        seen_hashes = set()
        exported = 0

        for cert in self.certificates:
            # 仅通过证书内容哈希去重
            if cert['cert_hash'] in seen_hashes:
                continue
            seen_hashes.add(cert['cert_hash'])

            # 文件名保留会话信息但去重核心是哈希
            ip_part = cert['ip_pair'].replace(' ', '_').replace('<->', '_').replace('>', '').replace('-', '')
            filename = f"{ip_part}_{cert['sig_alg']}_{cert['cert_hash'][:12]}.cer"

            # 构建完整保存路径
            save_path = os.path.join(save_dir, filename)

            try:
                with open(save_path, 'wb') as f:
                    f.write(cert['cert'])
                exported += 1
            except Exception as e:
                print(f"证书导出失败: {e}")
                self.status.config(text=f"部分证书导出失败：{str(e)}")
                return

        self.status.config(text=f"成功导出{exported}个证书到：{save_dir}")

    def save_result(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("文本文件", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                file.write(self.txt_result.get(1.0, tk.END))
            self.status.config(text="结果已保存")

    def save_sample(self):
        if self.encrypted_data:
            file_path = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("二进制文件", "*.bin")])
            if file_path:
                with open(file_path, "wb") as file:
                    file.write(b''.join([data for proto, data in self.encrypted_data]))
                total_bits = sum(len(data) * 8 for _, data in self.encrypted_data)
                self.status.config(text=f"样本已保存为二进制文件，总比特数为 {total_bits} bit")
        else:
            self.status.config(text="没有可供保存的样本数据")


    def copy_to_clipboard(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.txt_result.get(1.0, tk.END))
        self.status.config(text="结果已复制到剪贴板")

    def show_error(self, message):
        self.status.config(text=f"错误: {message}")
        self.processing = False
        self.btn_open.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = PCAPParserApp(root)
    root.mainloop()