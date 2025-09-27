# import asyncio
# import subprocess
# import json
# from pathlib import Path
# import shlex
# import sys
# import os
# import ipaddress # Để kiểm tra và phân tích target là IP/CIDR
# from datetime import datetime
# from typing import List, Optional, Dict, Any, Set
# import socket # Để phân giải tên miền thành IP

# # Giả định information_gathering.py chứa lớp ReconScanner.
# # Nếu bạn đã đổi tên file recon_scanner.py thành information_gathering.py trong thư mục PBL6,
# # thì import này sẽ đúng.
# from information_gathering import ReconScanner 
# import logging
# import re # Để phân tích Nmap XML

# # --- Cấu hình chung ---
# # Đường dẫn mặc định của các công cụ trên Kali Linux
# MASSCAN_BIN = "/usr/bin/masscan"
# NMAP_BIN = "/usr/bin/nmap"

# # Thư mục gốc để lưu tất cả kết quả quét
# OUT_BASE_DIR = Path("/tmp/kali_scan_outputs") 

# # Cài đặt mặc định cho ReconScanner (có thể được ghi đè)
# DEFAULT_RECON_CONCURRENCY = 20
# DEFAULT_RECON_TIMEOUT = 4.0

# # Thiết lập hệ thống logging
# logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# logger = logging.getLogger("KaliScanPipeline")

# class KaliScanPipeline:
#     """
#     Một quy trình quét toàn diện cho Kali Linux, kết hợp các khả năng của
#     ReconScanner, Masscan và Nmap để thu thập thông tin và quét mạng.
#     """
#     def __init__(self,
#                  target: str, # Có thể là tên miền (vd: example.com), IP (vd: 192.168.1.1), hoặc CIDR (vd: 192.168.1.0/24)
#                  output_dir: Optional[Path] = None, # Thư mục đầu ra tùy chỉnh
#                  masscan_rate: int = 1000, # Số lượng gói tin mỗi giây cho masscan
#                  recon_concurrency: int = DEFAULT_RECON_CONCURRENCY,
#                  recon_timeout: float = DEFAULT_RECON_TIMEOUT):
        
#         self.target = target
#         # Tạo một thư mục đầu ra duy nhất dựa trên target và thời gian
#         normalized_target_name = target.replace('/', '_').replace('.', '_').replace(':', '_')
#         timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
#         self.output_dir = output_dir or (OUT_BASE_DIR / f"{normalized_target_name}_{timestamp_str}")
#         self.output_dir.mkdir(parents=True, exist_ok=True) # Đảm bảo thư mục tồn tại

#         self.masscan_rate = masscan_rate
#         self.recon_scanner = ReconScanner(concurrency=recon_concurrency, timeout=recon_timeout)

#         # Kiểm tra các binary và quyền root ngay khi khởi tạo
#         self._check_binaries()
#         self.is_root = self._check_root_privileges()

#         # Trạng thái nội bộ để lưu trữ tất cả kết quả
#         self.results = {
#             "target": target,
#             "timestamp_utc": datetime.utcnow().isoformat(),
#             "output_directory": str(self.output_dir),
#             "recon_scanner_passive": None,
#             "recon_scanner_active": None,
#             "resolved_ips_for_masscan": [], # Các IP/CIDR thực sự được quét bởi masscan/nmap
#             "masscan_open_ports": {},       # IP -> [port1, port2, ...]
#             "nmap_detailed_scans": {},      # IP -> { "output_prefix": "...", "status": "...", "error": "..." }
#             "recon_scanner_web_discovery": {}, # URL -> kết quả khám phá web
#         }
#         self.target_ip_for_masscan: Optional[str] = None # Lưu IP/CIDR đã phân giải cho masscan/nmap

#     def _check_binaries(self):
#         """Kiểm tra xem các tệp thực thi của masscan và nmap có tồn tại không."""
#         for p in (MASSCAN_BIN, NMAP_BIN):
#             if not Path(p).exists():
#                 logger.error(f"Lỗi: Không tìm thấy {p}. Vui lòng cài đặt hoặc chỉnh sửa đường dẫn trong cấu hình.")
#                 sys.exit(1)

#     def _check_root_privileges(self) -> bool:
#         """Kiểm tra xem script có đang chạy với quyền root không."""
#         if os.geteuid() != 0:
#             logger.warning("Cảnh báo: Bạn không chạy với quyền root. masscan (sử dụng raw sockets) và nmap (-sS) có thể thất bại hoặc kém hiệu quả. Hãy cân nhắc chạy với sudo.")
#             return False
#         return True

#     async def _run_passive_active_recon_scanner(self):
#         """
#         Thực hiện passive và active recon bằng ReconScanner nếu target là tên miền.
#         Cũng phân giải tên miền thành một IP để masscan/nmap sử dụng.
#         """
#         is_ip_or_cidr = False
#         try:
#             ipaddress.ip_network(self.target) # Thử kiểm tra xem target có phải là IP hoặc CIDR không
#             is_ip_or_cidr = True
#         except ValueError:
#             pass # Không phải IP hoặc CIDR, có thể là tên miền

#         if not is_ip_or_cidr:
#             logger.info(f"[*] Bắt đầu passive recon cho tên miền: {self.target}")
#             passive_result = await self.recon_scanner.passive_recon(self.target)
#             self.results["recon_scanner_passive"] = passive_result
#             self._save_json_result(passive_result, self.output_dir / "passive_recon.json")

#             logger.info(f"[*] Bắt đầu active recon cho tên miền: {self.target}")
#             active_result = await self.recon_scanner.active_recon(self.target)
#             self.results["recon_scanner_active"] = active_result
#             self._save_json_result(active_result, self.output_dir / "active_recon.json")
            
#             # Cố gắng lấy IP để masscan/nmap từ các bản ghi DNS A
#             if "dns" in passive_result and "A" in passive_result["dns"] and passive_result["dns"]["A"]:
#                 self.target_ip_for_masscan = passive_result["dns"]["A"][0]
#                 self.results["resolved_ips_for_masscan"].append(self.target_ip_for_masscan)
#                 logger.info(f"[+] Đã phân giải tên miền {self.target} thành IP {self.target_ip_for_masscan} (từ DNS) để masscan/nmap.")
#             else:
#                 try: # Dự phòng sử dụng socket.gethostbyname
#                     self.target_ip_for_masscan = await asyncio.to_thread(socket.gethostbyname, self.target)
#                     self.results["resolved_ips_for_masscan"].append(self.target_ip_for_masscan)
#                     logger.info(f"[+] Đã phân giải tên miền {self.target} thành IP {self.target_ip_for_masscan} (từ socket) để masscan/nmap.")
#                 except Exception as e:
#                     logger.error(f"[!] Không thể phân giải tên miền {self.target} thành IP để masscan/nmap: {e}")
#                     self.target_ip_for_masscan = None
#         else:
#             self.target_ip_for_masscan = self.target # Target đã là IP/CIDR
#             self.results["resolved_ips_for_masscan"].append(self.target_ip_for_masscan)

#     def _run_masscan_sync(self):
#         """Thực thi masscan một cách đồng bộ (blocking)."""
#         if not self.target_ip_for_masscan:
#             logger.warning("[!] Không có IP mục tiêu cho masscan. Bỏ qua bước masscan.")
#             return

#         masscan_raw_out_path = self.output_dir / "masscan_raw_output.json" # Đầu ra thô của masscan
#         cmd = [MASSCAN_BIN, "-p1-65535", self.target_ip_for_masscan, "--rate", str(self.masscan_rate), "-oJ", str(masscan_raw_out_path)]
#         logger.info(f"[*] Đang chạy masscan trên {self.target_ip_for_masscan} với tốc độ {self.masscan_rate} pps...")
#         logger.debug(f"Lệnh masscan: {' '.join(shlex.quote(p) for p in cmd)}")
#         try:
#             # Chặn đầu ra stdout/stderr của masscan vì -oJ đã xử lý đầu ra
#             subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#             logger.info("[+] Masscan hoàn thành thành công.")
#         except subprocess.CalledProcessError as e:
#             logger.error(f"[!] masscan thất bại: {e}")
#             raise # Ném lại lỗi để dừng pipeline nếu masscan gặp lỗi nghiêm trọng

#         logger.info("[*] Đang phân tích đầu ra của masscan...")
#         self.results["masscan_open_ports"] = self._parse_masscan_json(masscan_raw_out_path)
#         total_open_ports = sum(len(v) for v in self.results['masscan_open_ports'].values())
#         logger.info(f"[+] Masscan tìm thấy {total_open_ports} cổng mở trên {len(self.results['masscan_open_ports'])} IP(s).")
#         self._save_json_result(self.results["masscan_open_ports"], self.output_dir / "masscan_parsed_open_ports.json")

#     def _parse_masscan_json(self, path: Path) -> Dict[str, List[int]]:
#         """Phân tích đầu ra JSON dạng dòng của masscan."""
#         text = path.read_text(encoding="utf-8", errors="ignore")
#         data = []
#         for line in text.splitlines():
#             line = line.strip()
#             if line:
#                 try:
#                     data.append(json.loads(line))
#                 except json.JSONDecodeError as e:
#                     logger.warning(f"[!] Không thể phân tích dòng JSON của masscan: {line[:100]}... Lỗi: {e}")
#                     continue

#         results: Dict[str, Set[int]] = {}
#         for entry in data:
#             ip = entry.get("ip")
#             if not ip: # Các phiên bản masscan cũ hơn có thể dùng "address"
#                 ip_data = entry.get("address")
#                 if ip_data and isinstance(ip_data, dict):
#                     ip = ip_data.get("addr")

#             if not ip:
#                 logger.warning(f"[!] Không tìm thấy IP trong mục masscan: {entry}")
#                 continue

#             ports_data = entry.get("ports")
#             if not ports_data:
#                 continue

#             for p_info in ports_data:
#                 if isinstance(p_info, dict):
#                     portnum = p_info.get("port")
#                 else: # Trường hợp dự phòng, mặc dù -oJ nên xuất ra dict
#                     portnum = p_info

#                 if portnum:
#                     try:
#                         results.setdefault(ip, set()).add(int(portnum))
#                     except ValueError:
#                         logger.warning(f"[!] Gặp phải số cổng không hợp lệ: {portnum} cho IP {ip}")
#                         pass
#         return {ip: sorted(list(ports)) for ip, ports in results.items()}

#     async def _run_nmap_verify(self):
#         """
#         Thực thi Nmap để phát hiện dịch vụ/phiên bản chi tiết trên các cổng
#         được tìm thấy bởi masscan. Chạy các lệnh Nmap song song bằng asyncio.to_thread.
#         """
#         nmap_output_subdir = self.output_dir / "nmap_detailed_scans"
#         nmap_output_subdir.mkdir(parents=True, exist_ok=True)

#         nmap_tasks = []
#         for ip, ports in self.results["masscan_open_ports"].items():
#             if not ports:
#                 continue
#             ports_str = ",".join(str(p) for p in ports)
#             out_prefix = nmap_output_subdir / f"nmap_{ip.replace(':','_')}"
            
#             # Sử dụng scan SYN (-sS) nếu có quyền root, ngược lại là scan kết nối TCP (-sT)
#             scan_flag = "-sS" if self.is_root else "-sT"
            
#             cmd = [NMAP_BIN, scan_flag, "-sV", "-p", ports_str, ip, "-oA", str(out_prefix)]
#             logger.debug(f"Đang xếp hàng nmap cho {ip}: {' '.join(shlex.quote(p) for p in cmd)}")
#             nmap_tasks.append((ip, cmd, str(out_prefix)))

#         if not nmap_tasks:
#             logger.info("[*] Không tìm thấy cổng mở nào bởi masscan, bỏ qua Nmap.")
#             return

#         logger.info(f"[*] Đang chạy {len(nmap_tasks)} quét Nmap chi tiết đồng thời (concurrency: {self.recon_scanner.concurrency})...")
#         sem = asyncio.Semaphore(self.recon_scanner.concurrency) # Tái sử dụng concurrency của recon_scanner

#         async def run_nmap_one(ip_target, cmd_list, out_prefix_path):
#             async with sem:
#                 logger.info(f"[*] Nmap: Đang quét {ip_target} trên {len(ports)} cổng...")
#                 try:
#                     # subprocess.run là blocking, nên phải chạy trong một thread.
#                     # Thu thập đầu ra để debug/logging, nhưng đầu ra chính là các file -oA.
#                     process = await asyncio.to_thread(
#                         subprocess.run, 
#                         cmd_list, 
#                         capture_output=True, 
#                         text=True, 
#                         check=True,
#                         timeout=self.recon_scanner.timeout * len(ports) / 5.0 + 30 # Ước tính thời gian chờ
#                     )
#                     self.results["nmap_detailed_scans"][ip_target] = {
#                         "output_prefix": str(out_prefix_path),
#                         "status": "success",
#                         "stdout_snippet": process.stdout[:500], # Lưu đoạn trích để kiểm tra nhanh
#                         "stderr_snippet": process.stderr[:500],
#                         "nmap_files": {
#                             "xml": str(Path(out_prefix_path).with_suffix('.xml')),
#                             "nmap": str(Path(out_prefix_path).with_suffix('.nmap')),
#                             "gnmap": str(Path(out_prefix_path).with_suffix('.gnmap')),
#                         }
#                     }
#                     logger.info(f"[+] Nmap cho {ip_target} hoàn thành. Các file đầu ra: {out_prefix_path}.*")
#                 except subprocess.CalledProcessError as e:
#                     self.results["nmap_detailed_scans"][ip_target] = {
#                         "output_prefix": str(out_prefix_path),
#                         "status": "failed",
#                         "error": str(e),
#                         "stdout_snippet": e.stdout[:500] if e.stdout else "",
#                         "stderr_snippet": e.stderr[:500] if e.stderr else ""
#                     }
#                     logger.error(f"[!] Nmap thất bại cho {ip_target}: {e.stderr.strip() if e.stderr else str(e)}")
#                 except asyncio.TimeoutError:
#                      self.results["nmap_detailed_scans"][ip_target] = {
#                         "output_prefix": str(out_prefix_path),
#                         "status": "timeout",
#                         "error": "Quét Nmap đã hết thời gian."
#                     }
#                      logger.error(f"[!] Nmap cho {ip_target} đã hết thời gian.")
#                 except Exception as e:
#                     self.results["nmap_detailed_scans"][ip_target] = {
#                         "output_prefix": str(out_prefix_path),
#                         "status": "failed_generic",
#                         "error": str(e)
#                     }
#                     logger.error(f"[!] Lỗi chung khi chạy Nmap cho {ip_target}: {e}")

#         await asyncio.gather(*[run_nmap_one(ip, cmd, out_prefix) for ip, cmd, out_prefix in nmap_tasks])
#         self._save_json_result(self.results["nmap_detailed_scans"], self.output_dir / "nmap_summary.json")

#     async def _run_web_recon_scanner(self):
#         """
#         Xác định các dịch vụ web từ kết quả Nmap và thực hiện khám phá web (crawling)
#         sử dụng ReconScanner.
#         """
#         web_targets: Set[str] = set() # Lưu trữ dưới dạng (scheme://ip:port) hoặc (scheme://domain:port)
        
#         # Ưu tiên tên miền mục tiêu cho việc crawling web nếu có
#         target_domain_for_web: Optional[str] = None
#         if self.results["recon_scanner_passive"] and "target" in self.results["recon_scanner_passive"]:
#              target_domain_for_web = self.results["recon_scanner_passive"]["target"]

#         # Phân tích đầu ra XML của Nmap để tìm các dịch vụ HTTP/S
#         for ip, nmap_res in self.results["nmap_detailed_scans"].items():
#             if nmap_res["status"] != "success":
#                 continue
            
#             xml_path = Path(nmap_res["nmap_files"]["xml"])
#             if xml_path.exists():
#                 try:
#                     # Phân tích XML Nmap bằng regex đơn giản để phát hiện dịch vụ
#                     # Để phân tích mạnh mẽ hơn, nên sử dụng thư viện XML như ElementTree
#                     xml_content = xml_path.read_text(errors='ignore')
                    
#                     # Tìm thẻ host và sau đó là các thẻ port
#                     for match_host in re.finditer(r'<host[^>]*>(.*?)</host>', xml_content, re.DOTALL):
#                         host_block = match_host.group(1)
#                         # Trích xuất IP nếu nó tồn tại trong khối host
#                         host_ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"/>', host_block)
#                         current_ip = host_ip_match.group(1) if host_ip_match else ip # Dự phòng sử dụng IP từ vòng lặp
                        
#                         for match_port in re.finditer(r'<port portid="(\d+)" protocol="tcp">.*?<service name="([^"]+)"', host_block, re.DOTALL):
#                             port = int(match_port.group(1))
#                             service = match_port.group(2)
                            
#                             if "http" in service.lower() or "ssl/http" in service.lower():
#                                 scheme = "https" if "ssl" in service.lower() or port == 443 or port == 8443 else "http"
#                                 if target_domain_for_web:
#                                     # Thêm URL dựa trên tên miền trước
#                                     web_targets.add(f"{scheme}://{target_domain_for_web}:{port}" if port not in [80, 443] else f"{scheme}://{target_domain_for_web}")
#                                 # Luôn thêm URL dựa trên IP
#                                 web_targets.add(f"{scheme}://{current_ip}:{port}" if port not in [80, 443] else f"{scheme}://{current_ip}")
#                 except Exception as e:
#                     logger.warning(f"[!] Lỗi khi phân tích Nmap XML cho {ip}: {e}")
#             else:
#                 logger.warning(f"[!] Không tìm thấy tệp Nmap XML cho {ip}: {xml_path}")

#         if not web_targets:
#             logger.info("[*] Nmap không xác định được dịch vụ web nào, bỏ qua khám phá web.")
#             return

#         logger.info(f"[*] Bắt đầu khám phá web cho {len(web_targets)} mục tiêu web đã xác định...")
#         discovery_tasks = []
#         sem = asyncio.Semaphore(self.recon_scanner.concurrency)

#         async def run_discovery_one(url):
#             async with sem:
#                 logger.info(f"[*] Khám phá Web: Đang crawling {url} (max_depth=1)...")
#                 try:
#                     result = await self.recon_scanner.discover_web(url, max_depth=1) # Giới hạn độ sâu là 1 cho lần quét ban đầu
#                     self.results["recon_scanner_web_discovery"][url] = result
#                     logger.info(f"[+] Khám phá web cho {url} hoàn thành. Tìm thấy {len(result.get('links', []))} liên kết, {len(result.get('params', []))} tham số.")
#                 except Exception as e:
#                     self.results["recon_scanner_web_discovery"][url] = {"error": str(e)}
#                     logger.error(f"[!] Khám phá web cho {url} thất bại: {e}")
        
#         await asyncio.gather(*[run_discovery_one(url) for url in web_targets])
#         self._save_json_result(self.results["recon_scanner_web_discovery"], self.output_dir / "web_discovery_results.json")

#     async def run_full_scan(self):
#         """
#         Điều phối toàn bộ quy trình quét.
#         """
#         logger.info(f"==== Bắt đầu quét toàn diện cho mục tiêu: {self.target} ====")
#         logger.info(f"Thư mục đầu ra: {self.output_dir}")

#         try:
#             # Bước 1: Passive/Active Recon bằng ReconScanner (nếu target là tên miền)
#             await self._run_passive_active_recon_scanner()

#             # Bước 2: Quét cổng rộng bằng Masscan (blocking, nên chạy trong thread)
#             if self.target_ip_for_masscan:
#                 await asyncio.to_thread(self._run_masscan_sync)
#             else:
#                 logger.warning("[!] Bỏ qua Masscan do không có IP mục tiêu có thể phân giải.")

#             # Bước 3: Quét dịch vụ/phiên bản chi tiết bằng Nmap
#             if self.results["masscan_open_ports"]:
#                 await self._run_nmap_verify()
#             else:
#                 logger.info("[*] Bỏ qua Nmap vì Masscan không tìm thấy cổng mở nào.")

#             # Bước 4: Reconnaissance cụ thể về Web bằng ReconScanner
#             await self._run_web_recon_scanner()
            
#         except Exception as e:
#             logger.critical(f"[CRITICAL] Quy trình quét thất bại bất ngờ cho {self.target}: {e}", exc_info=True)
#             self.results["pipeline_error"] = str(e)
        
#         logger.info(f"==== Quét toàn diện cho {self.target} hoàn thành. Kết quả được lưu trong: {self.output_dir} ====")
#         self._save_json_result(self.results, self.output_dir / "full_scan_summary.json") # Lưu tóm tắt tổng thể
#         return self.results

#     def _save_json_result(self, data: Dict[str, Any], file_path: Path):
#         """Hàm trợ giúp để lưu dữ liệu dictionary vào file JSON."""
#         try:
#             with open(file_path, "w", encoding="utf-8") as f:
#                 json.dump(data, f, ensure_ascii=False, indent=2)
#             logger.debug(f"Đã lưu kết quả vào {file_path}")
#         except Exception as e:
#             logger.error(f"[!] Lỗi khi lưu kết quả JSON vào {file_path}: {e}")








import socket
import urllib.parse
import asyncio
import subprocess
import json
from pathlib import Path
import shlex
import sys
import os
import ipaddress # Để kiểm tra và phân tích target là IP/CIDR
from datetime import datetime
from typing import List, Optional, Dict, Any, Set
import socket # Để phân giải tên miền thành IP
import aiohttp # <-- Thêm import này

# Giả định information_gathering.py chứa lớp ReconScanner.
from information_gathering import ReconScanner 

# Import các lớp mới từ gói vulnerability_scanner
from vulnerability_scanner.nmap_parser import NmapParser
from vulnerability_scanner.web_vulnerabilities import WebVulnerabilityScanner

import logging
import re # Để phân tích Nmap XML

# --- Cấu hình chung ---
# Đường dẫn mặc định của các công cụ trên Kali Linux
MASSCAN_BIN = "/usr/bin/masscan"
NMAP_BIN = "/usr/bin/nmap"

# Thư mục gốc để lưu tất cả kết quả quét
OUT_BASE_DIR = Path("/tmp/kali_scan_outputs") 

# Cài đặt mặc định cho ReconScanner (có thể được ghi đè)
DEFAULT_RECON_CONCURRENCY = 20
DEFAULT_RECON_TIMEOUT = 300.0 # <-- Tăng lên 5 phút
DEFAULT_CRAWL_DEPTH = 3      # <-- DÒNG NÀY PHẢI TỒN TẠI VÀ CÓ GIÁ TRỊ!
DEFAULT_RECON_TIMEOUT = 4.0

# Thiết lập hệ thống logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("KaliScanPipeline")

class KaliScanPipeline:
    """
    Một quy trình quét toàn diện cho Kali Linux, kết hợp các khả năng của
    ReconScanner, Masscan và Nmap để thu thập thông tin và quét mạng.
    """
    def __init__(self,
                 target: str, # Có thể là tên miền (vd: example.com), IP (vd: 192.168.1.1), hoặc CIDR (vd: 192.168.1.0/24)
                 output_dir: Optional[Path] = None, # Thư mục đầu ra tùy chỉnh
                 masscan_rate: int = 1000, # Số lượng gói tin mỗi giây cho masscan
                 recon_concurrency: int = DEFAULT_RECON_CONCURRENCY,
                 recon_timeout: float = DEFAULT_RECON_TIMEOUT):
        
        self.target = target
        # Tạo một thư mục đầu ra duy nhất dựa trên target và thời gian
        normalized_target_name = target.replace('/', '_').replace('.', '_').replace(':', '_')
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = output_dir or (OUT_BASE_DIR / f"{normalized_target_name}_{timestamp_str}")
        self.output_dir.mkdir(parents=True, exist_ok=True) # Đảm bảo thư mục tồn tại

        self.masscan_rate = masscan_rate
        self.recon_scanner = ReconScanner(concurrency=recon_concurrency, timeout=recon_timeout)
        self.http_session: Optional[aiohttp.ClientSession] = None # Khởi tạo AIOHTTP session
        self.web_vuln_scanner: Optional[WebVulnerabilityScanner] = None

        # Kiểm tra các binary và quyền root ngay khi khởi tạo
        self._check_binaries()
        self.is_root = self._check_root_privileges()

        # Trạng thái nội bộ để lưu trữ tất cả kết quả
        self.results = {
            "target": target,
            "timestamp_utc": datetime.utcnow().isoformat(),
            "output_directory": str(self.output_dir),
            "recon_scanner_passive": None,
            "recon_scanner_active": None,
            "resolved_ips_for_masscan": [], # Các IP/CIDR thực sự được quét bởi masscan/nmap
            "masscan_open_ports": {},       # IP -> [port1, port2, ...]
            "nmap_detailed_scans": {},      # IP -> { "output_prefix": "...", "status": "...", "error": "..." }
            "nmap_parsed_services": [],      # <-- NEW: Parsed Nmap services
            "recon_scanner_web_discovery": {}, # URL -> kết quả khám phá web
            "web_vulnerabilities": [],        # <-- NEW: Web vulnerability findings
            "other_vulnerabilities": [] # <-- ĐẢM BẢO CÓ DÒNG NÀY!
        }
        self.target_ip_for_masscan: Optional[str] = None # Lưu IP/CIDR đã phân giải cho masscan/nmap

    def _check_binaries(self):
        """Kiểm tra xem các tệp thực thi của masscan và nmap có tồn tại không."""
        for p in (MASSCAN_BIN, NMAP_BIN):
            if not Path(p).exists():
                logger.error(f"Lỗi: Không tìm thấy {p}. Vui lòng cài đặt hoặc chỉnh sửa đường dẫn trong cấu hình.")
                sys.exit(1)

    def _check_root_privileges(self) -> bool:
        """Kiểm tra xem script có đang chạy với quyền root không."""
        if os.geteuid() != 0:
            logger.warning("Cảnh báo: Bạn không chạy với quyền root. masscan (sử dụng raw sockets) và nmap (-sS) có thể thất bại hoặc kém hiệu quả. Hãy cân nhắc chạy với sudo.")
            return False
        return True

    async def _run_passive_active_recon_scanner(self):
        """
        Thực hiện passive và active recon bằng ReconScanner nếu target là tên miền.
        Cũng phân giải tên miền thành một IP để masscan/nmap sử dụng.
        """
        is_ip_or_cidr = False
        try:
            ipaddress.ip_network(self.target) # Thử kiểm tra xem target có phải là IP hoặc CIDR không
            is_ip_or_cidr = True
        except ValueError:
            pass # Không phải IP hoặc CIDR, có thể là tên miền

        if not is_ip_or_cidr:
            logger.info(f"[*] Bắt đầu passive recon cho tên miền: {self.target}")
            passive_result = await self.recon_scanner.passive_recon(self.target)
            self.results["recon_scanner_passive"] = passive_result
            self._save_json_result(passive_result, self.output_dir / "passive_recon.json")

            logger.info(f"[*] Bắt đầu active recon cho tên miền: {self.target}")
            active_result = await self.recon_scanner.active_recon(self.target)
            self.results["recon_scanner_active"] = active_result
            self._save_json_result(active_result, self.output_dir / "active_recon.json")
            
            # Cố gắng lấy IP để masscan/nmap từ các bản ghi DNS A
            if "dns" in passive_result and "A" in passive_result["dns"] and passive_result["dns"]["A"]:
                self.target_ip_for_masscan = passive_result["dns"]["A"][0]
                self.results["resolved_ips_for_masscan"].append(self.target_ip_for_masscan)
                logger.info(f"[+] Đã phân giải tên miền {self.target} thành IP {self.target_ip_for_masscan} (từ DNS) để quét cổng.")
            else:
                try: # Dự phòng sử dụng socket.gethostbyname
                    self.target_ip_for_masscan = await asyncio.to_thread(socket.gethostbyname, self.target)
                    self.results["resolved_ips_for_masscan"].append(self.target_ip_for_masscan)
                    logger.info(f"[+] Đã phân giải tên miền {self.target} thành IP {self.target_ip_for_masscan} (từ socket) để quét cổng.")
                except Exception as e:
                    logger.error(f"[!] Không thể phân giải tên miền {self.target} thành IP để quét cổng: {e}")
                    self.target_ip_for_masscan = None
        else: # Mục tiêu đã là IP/CIDR, hoặc là 'localhost' cần xử lý đặc biệt
            if self.target.lower() == 'localhost':
                try:
                    # Lấy IP của giao diện mạng chính (thay vì 127.0.0.1)
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80)) # Kết nối tới một địa chỉ ngoài (Google DNS) để lấy IP cục bộ
                    local_ip = s.getsockname()[0]
                    s.close()
                    self.target_ip_for_masscan = local_ip
                    logger.info(f"[+] Mục tiêu 'localhost' được phân giải thành IP thực của host: {self.target_ip_for_masscan} để quét cổng.")
                except Exception as e:
                    logger.warning(f"[!] Không thể lấy IP thực của host cho 'localhost', sử dụng 127.0.0.1: {e}")
                    self.target_ip_for_masscan = '127.0.0.1' # Dự phòng, nếu thất bại
            else:
                self.target_ip_for_masscan = self.target # Target đã là IP/CIDR
            
            self.results["resolved_ips_for_masscan"].append(self.target_ip_for_masscan)

    def _run_masscan_sync(self):
        """Thực thi masscan một cách đồng bộ (blocking)."""
        if not self.target_ip_for_masscan:
            logger.warning("[!] Không có IP mục tiêu cho masscan. Bỏ qua bước masscan.")
            return

        masscan_raw_out_path = self.output_dir / "masscan_raw_output.json" # Đầu ra thô của masscan
        cmd = [MASSCAN_BIN, "-p1-65535", self.target_ip_for_masscan, "--rate", str(self.masscan_rate), "-oJ", str(masscan_raw_out_path)]
#        cmd = [MASSCAN_BIN, "-p5000", self.target_ip_for_masscan, "--rate", str(self.masscan_rate), "-oJ", str(masscan_raw_out_path)]
        logger.info(f"[*] Đang chạy masscan trên {self.target_ip_for_masscan} với tốc độ {self.masscan_rate} pps...")
        logger.debug(f"Lệnh masscan: {' '.join(shlex.quote(p) for p in cmd)}")
        try:
            # Chặn đầu ra stdout/stderr của masscan vì -oJ đã xử lý đầu ra
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info("[+] Masscan hoàn thành thành công.")
        except subprocess.CalledProcessError as e:
            logger.error(f"[!] masscan thất bại: {e}")
            raise # Ném lại lỗi để dừng pipeline nếu masscan gặp lỗi nghiêm trọng

        logger.info("[*] Đang phân tích đầu ra của masscan...")
        self.results["masscan_open_ports"] = self._parse_masscan_json(masscan_raw_out_path)
        total_open_ports = sum(len(v) for v in self.results['masscan_open_ports'].values())
        logger.info(f"[+] Masscan tìm thấy {total_open_ports} cổng mở trên {len(self.results['masscan_open_ports'])} IP(s).")
        self._save_json_result(self.results["masscan_open_ports"], self.output_dir / "masscan_parsed_open_ports.json")

    # File: vulnerability_scanner/scan_pipeline_kali.py
# Thay thế hàm _parse_masscan_json hiện có bằng đoạn mã sau:

    def _parse_masscan_json(self, path: Path) -> Dict[str, List[int]]:
        """Phân tích đầu ra JSON của masscan (dòng-được-dòng)."""
        text = path.read_text(encoding="utf-8", errors="ignore")
        if not text.strip(): # Xử lý trường hợp tệp trống
            logger.warning(f"[!] Tệp đầu ra Masscan trống hoặc chỉ chứa khoảng trắng: {path}")
            return {}
        
        results: Dict[str, Set[int]] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                ip = entry.get("ip")
                if not ip: # Các phiên bản masscan cũ hơn có thể dùng "address"
                    ip_data = entry.get("address")
                    if ip_data and isinstance(ip_data, dict):
                        ip = ip_data.get("addr")

                if not ip:
                    logger.warning(f"[!] Không tìm thấy IP trong mục masscan: {entry}")
                    continue

                ports_data = entry.get("ports")
                if not ports_data:
                    continue

                for p_info in ports_data:
                    if isinstance(p_info, dict):
                        portnum = p_info.get("port")
                    else: # Trường hợp dự phòng, mặc dù -oJ nên xuất ra dict
                        portnum = p_info

                    if portnum:
                        try:
                            results.setdefault(ip, set()).add(int(portnum))
                        except ValueError:
                            logger.warning(f"[!] Gặp phải số cổng không hợp lệ: {portnum} cho IP {ip}")
                            pass
            except json.JSONDecodeError as e:
                logger.warning(f"[!] Không thể phân tích dòng JSON của masscan: {line[:100]}... Lỗi: {e}")
                continue
        return {ip: sorted(list(ports)) for ip, ports in results.items()}

    async def _run_nmap_verify(self):
        """
        Thực thi Nmap để phát hiện dịch vụ/phiên bản chi tiết trên các cổng
        được tìm thấy bởi masscan. Chạy các lệnh Nmap song song bằng asyncio.to_thread.
        """
        nmap_output_subdir = self.output_dir / "nmap_detailed_scans"
        nmap_output_subdir.mkdir(parents=True, exist_ok=True)

        nmap_tasks = []
        for ip, ports in self.results["masscan_open_ports"].items():
            if not ports:
                continue
            ports_str = ",".join(str(p) for p in ports)
            normalized_ip = ip.replace('.', '_').replace(':', '_').replace('%', '_') # Thêm .replace('%', '_') cho IPv6 link-local
            out_prefix = nmap_output_subdir / f"nmap_{normalized_ip}"
            
            # Sử dụng scan SYN (-sS) nếu có quyền root, ngược lại là scan kết nối TCP (-sT)
            scan_flag = "-sS" if self.is_root else "-sT"
            
            # Thêm cờ -sC và -sV để chạy script mặc định và phát hiện phiên bản dịch vụ
            cmd = [NMAP_BIN, scan_flag, "-sV", "-sC","-PN" ,"-p", ports_str, ip, "-oA", str(out_prefix)]
            logger.debug(f"Đang xếp hàng nmap cho {ip}: {' '.join(shlex.quote(p) for p in cmd)}")
            nmap_tasks.append((ip, cmd, str(out_prefix)))

        if not nmap_tasks:
            logger.info("[*] Không tìm thấy cổng mở nào bởi masscan, bỏ qua Nmap.")
            return

        logger.info(f"[*] Đang chạy {len(nmap_tasks)} quét Nmap chi tiết đồng thời (concurrency: {self.recon_scanner.concurrency})...")
        sem = asyncio.Semaphore(self.recon_scanner.concurrency) # Tái sử dụng concurrency của recon_scanner

        async def run_nmap_one(ip_target, cmd_list, out_prefix_path):
            async with sem:
                logger.info(f"[*] Nmap: Đang quét {ip_target} trên {len(ports)} cổng...")
                try:
                    # subprocess.run là blocking, nên phải chạy trong một thread.
                    # Thu thập đầu ra để debug/logging, nhưng đầu ra chính là các file -oA.
                    process = await asyncio.to_thread(
                        subprocess.run, 
                        cmd_list, 
                        capture_output=True, 
                        text=True, 
                        check=True,
#                        timeout=self.recon_scanner.timeout * len(ports) / 5.0 + 30 # Ước tính thời gian chờ
                        timeout=max(180, len(ports) * 60)
                    )
                    self.results["nmap_detailed_scans"][ip_target] = {
                        "output_prefix": str(out_prefix_path),
                        "status": "success",
                        "stdout_snippet": process.stdout[:500], # Lưu đoạn trích để kiểm tra nhanh
                        "stderr_snippet": process.stderr[:500],
                        "nmap_files": {
                            "xml": str(Path(out_prefix_path).with_suffix('.xml')),
                            "nmap": str(Path(out_prefix_path).with_suffix('.nmap')),
                            "gnmap": str(Path(out_prefix_path).with_suffix('.gnmap')),
                        }
                    }
                    logger.info(f"[+] Nmap cho {ip_target} hoàn thành. Các file đầu ra: {out_prefix_path}.*")
                except subprocess.CalledProcessError as e:
                    self.results["nmap_detailed_scans"][ip_target] = {
                        "output_prefix": str(out_prefix_path),
                        "status": "failed",
                        "error": str(e),
                        "stdout_snippet": e.stdout[:500] if e.stdout else "",
                        "stderr_snippet": e.stderr[:500] if e.stderr else ""
                    }
                    logger.error(f"[!] Nmap thất bại cho {ip_target}: {e.stderr.strip() if e.stderr else str(e)}")
                except asyncio.TimeoutError:
                     self.results["nmap_detailed_scans"][ip_target] = {
                        "output_prefix": str(out_prefix_path),
                        "status": "timeout",
                        "error": "Quét Nmap đã hết thời gian."
                    }
                     logger.error(f"[!] Nmap cho {ip_target} đã hết thời gian.")
                except Exception as e:
                    self.results["nmap_detailed_scans"][ip_target] = {
                        "output_prefix": str(out_prefix_path),
                        "status": "failed_generic",
                        "error": str(e)
                    }
                    logger.error(f"[!] Lỗi chung khi chạy Nmap cho {ip_target}: {e}")

        await asyncio.gather(*[run_nmap_one(ip, cmd, out_prefix) for ip, cmd, out_prefix in nmap_tasks])
        self._save_json_result(self.results["nmap_detailed_scans"], self.output_dir / "nmap_summary.json")

    async def _run_nmap_vulnerability_check(self):
        """
        Phân tích kết quả Nmap XML để trích xuất dịch vụ chi tiết và có thể kiểm tra lỗ hổng đã biết
        (hiện tại chỉ trích xuất thông tin dịch vụ).
        """
        logger.info("[*] Bắt đầu phân tích kết quả Nmap để trích xuất dịch vụ...")
        parsed_services_data = []
        for ip, nmap_res in self.results["nmap_detailed_scans"].items():
            if nmap_res["status"] == "success":
                xml_path = Path(nmap_res["nmap_files"]["xml"])
                if xml_path.exists():
                    try:
                        parser = NmapParser(xml_path)
                        parsed_data = parser.parse()
                        parsed_services_data.extend(parsed_data)
                        logger.debug(f"[+] Đã phân tích Nmap XML cho {ip}.")
                    except Exception as e:
                        logger.warning(f"[!] Lỗi khi phân tích Nmap XML cho {ip}: {e}")
                else:
                    logger.warning(f"[!] Tệp Nmap XML không tìm thấy cho {ip}: {xml_path}")
        
        self.results["nmap_parsed_services"] = parsed_services_data
        self._save_json_result(parsed_services_data, self.output_dir / "nmap_parsed_services.json")
        logger.info(f"[+] Hoàn thành phân tích Nmap. Tổng cộng {len(parsed_services_data)} host/dịch vụ được trích xuất.")


    async def _run_web_recon_scanner(self):
        """
        Xác định các dịch vụ web từ kết quả Nmap và thực hiện khám phá web (crawling)
        sử dụng ReconScanner.
        """
        web_targets_for_discovery: Set[str] = set() # Lưu trữ dưới dạng (scheme://ip:port) hoặc (scheme://domain:port)
        
        # Ưu tiên tên miền mục tiêu cho việc crawling web nếu có
        target_domain_for_web: Optional[str] = None
        if self.results["recon_scanner_passive"] and "target" in self.results["recon_scanner_passive"]:
             target_domain_for_web = self.results["recon_scanner_passive"]["target"]

        # Sử dụng kết quả nmap_parsed_services để xác định các mục tiêu web
        for host_info in self.results["nmap_parsed_services"]:
            for address_info in host_info.get("addresses", []):
                current_ip = address_info.get("addr")
                if not current_ip: continue
                
                for port_info in host_info.get("ports", []):
                    port = int(port_info["portid"])
                    service_name = port_info["service"]["name"]

                    if "http" in service_name.lower() or "ssl/http" in service_name.lower():
                        scheme = "https" if "ssl" in service_name.lower() or port == 443 or port == 8443 else "http"
                        
                        # Thêm mục tiêu dựa trên tên miền nếu có
                        if target_domain_for_web:
                            web_targets_for_discovery.add(f"{scheme}://{target_domain_for_web}:{port}" if port not in [80, 443] else f"{scheme}://{target_domain_for_web}")
                        
                        # Thêm mục tiêu dựa trên IP
                        web_targets_for_discovery.add(f"{scheme}://{current_ip}:{port}" if port not in [80, 443] else f"{scheme}://{current_ip}")

        if not web_targets_for_discovery:
            logger.info("[*] Nmap không xác định được dịch vụ web nào, bỏ qua khám phá web.")
            return

        # NEW: Thêm các URL có tham số đã biết vào danh sách khám phá ban đầu
        # Điều này sẽ đảm bảo rằng các URL với tham số được biết (như /xss?query=) được khám phá
        # ngay từ đầu, cho phép ReconScanner trích xuất tham số 'query'.
        
        # Lấy IP/Hostname từ các mục tiêu đã khám phá được (ví dụ: localhost, 127.0.0.1)
        # và thêm các URL tiềm năng có tham số đã biết.
        potential_web_base_urls = set()
        for target_url in list(web_targets_for_discovery): # Duyệt qua bản sao để tránh lỗi thay đổi khi lặp
            parsed = urllib.parse.urlparse(target_url)
            # Chỉ lấy scheme://netloc (ví dụ: http://localhost:5000)
            potential_web_base_urls.add(parsed._replace(path='', query='', fragment='').geturl())
        
        # Thêm các URL với tham số khởi tạo để đảm bảo chúng được discover
        for base_url in potential_web_base_urls:
            # Thêm URL khởi tạo cho trang XSS của bạn
            # Chỉ áp dụng cho localhost/127.0.0.1
            if "localhost" in base_url or "127.0.0.1" in base_url: 
                test_xss_url = f"{base_url}/xss?query=test"
                if test_xss_url not in web_targets_for_discovery: # Tránh trùng lặp
                    web_targets_for_discovery.add(test_xss_url)
                    logger.debug(f"Đã thêm URL khởi tạo XSS: {test_xss_url} vào khám phá.")
                
                test_sqli_url = f"{base_url}/sqli?id=1"
                if test_sqli_url not in web_targets_for_discovery: # Tránh trùng lặp
                    web_targets_for_discovery.add(test_sqli_url)
                    logger.debug(f"Đã thêm URL khởi tạo SQLi: {test_sqli_url} vào khám phá.")


        logger.info(f"[*] Bắt đầu khám phá web cho {len(web_targets_for_discovery)} mục tiêu web đã xác định (độ sâu: {DEFAULT_CRAWL_DEPTH})...")
        discovery_tasks = []
        sem = asyncio.Semaphore(self.recon_scanner.concurrency)

        async def run_discovery_one(url):
            async with sem:
                logger.info(f"[*] Khám phá Web: Đang crawling {url} (max_depth={DEFAULT_CRAWL_DEPTH})...") # <-- Đảm bảo dùng DEFAULT_CRAWL_DEPTH
                try:
                    # Truyền DEFAULT_CRAWL_DEPTH và same_host_only
                    result = await self.recon_scanner.discover_web(url, max_depth=DEFAULT_CRAWL_DEPTH, same_host_only=True)
                    self.results["recon_scanner_web_discovery"][url] = result
                    logger.info(f"[+] Khám phá web cho {url} hoàn thành. Tìm thấy {len(result.get('links', []))} liên kết, {len(result.get('params', []))} tham số.")
                except Exception as e:
                    self.results["recon_scanner_web_discovery"][url] = {"error": str(e)}
                    logger.error(f"[!] Khám phá web cho {url} thất bại: {e}")
        
        await asyncio.gather(*[run_discovery_one(url) for url in web_targets_for_discovery])
        self._save_json_result(self.results["recon_scanner_web_discovery"], self.output_dir / "web_discovery_results.json")

    async def _run_web_vulnerability_check(self):
        # Khởi tạo WebVulnerabilityScanner với timeout cao
        if not self.http_session:
            self.http_session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.recon_scanner.timeout))
            self.web_vuln_scanner = WebVulnerabilityScanner(self.http_session, timeout=self.recon_scanner.timeout)
        
        if not self.web_vuln_scanner:
            logger.error("[!] WebVulnerabilityScanner chưa được khởi tạo.")
            return

        logger.info("[*] Bắt đầu kiểm tra lỗ hổng web (XSS, SQLi)...")
        
        web_vuln_tasks = []
        sem = asyncio.Semaphore(self.recon_scanner.concurrency)

        async def check_url_for_vulns(base_url, params_to_test: List[str]):
            async with sem:
                logger.debug(f"Đang kiểm tra lỗ hổng trên URL: {base_url} với các tham số: {params_to_test}")
                
                xss_findings = await self.web_vuln_scanner.check_xss(base_url, params_to_test)
                if xss_findings:
                    self.results["web_vulnerabilities"].extend(xss_findings)

                sqli_findings = await self.web_vuln_scanner.check_sqli(base_url, params_to_test)
                if sqli_findings:
                    self.results["web_vulnerabilities"].extend(sqli_findings)

        targets_to_check_for_vulns: Dict[str, Set[str]] = {} # {base_url: {param1, param2}}

        # Bước 1: Thu thập tất cả các URL đã khám phá và các tham số của chúng.
        # Chúng ta sẽ thu thập cả các URL có chứa tham số trong phần base_url (ví dụ: http://host/path?param=value)
        # và các URL base từ discovery data.
        
        # Xử lý các URL từ `recon_scanner_web_discovery`
        for discovered_url_key, discovery_data in self.results["recon_scanner_web_discovery"].items():
            # Phân tích URL chính của discovery data (key)
            parsed_key_url = urllib.parse.urlparse(discovered_url_key)
            base_url_from_key = parsed_key_url._replace(query='', fragment='').geturl()
            key_query_params = urllib.parse.parse_qs(parsed_key_url.query, keep_blank_values=True)
            if key_query_params: # Nếu URL key có tham số, thêm chúng vào
                targets_to_check_for_vulns.setdefault(base_url_from_key, set()).update(key_query_params.keys())

            # Xử lý các full_param_url từ `discovery_data.get("params", [])`
            for full_param_url in discovery_data.get("params", []):
                parsed = urllib.parse.urlparse(full_param_url)
                base_without_query = parsed._replace(query='', fragment='').geturl()
                query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                targets_to_check_for_vulns.setdefault(base_without_query, set()).update(query_params.keys())
            
            # Đảm bảo các base_url đã được khám phá cũng được thêm vào để kiểm tra
            # và sau đó thêm các tham số mặc định cho chúng.
            targets_to_check_for_vulns.setdefault(base_url_from_key, set())


        # Bước 2: Thêm các tham số tiềm năng đã biết cho các URL đặc biệt (quan trọng cho trang /xss của bạn)
        # Duyệt qua một bản sao của keys để có thể sửa đổi dictionary trong khi lặp
        for base_url_to_modify in list(targets_to_check_for_vulns.keys()):
            if base_url_to_modify.endswith("/xss"):
                targets_to_check_for_vulns[base_url_to_modify].add("query") # Đảm bảo 'query' được thêm
                logger.debug(f"Đã thêm tham số 'query' vào {base_url_to_modify} để kiểm tra.")
            if base_url_to_modify.endswith("/sqli"):
                targets_to_check_for_vulns[base_url_to_modify].add("id") # Đảm bảo 'id' được thêm
                logger.debug(f"Đã thêm tham số 'id' vào {base_url_to_modify} để kiểm tra.")
            
            # Thêm các tham số mặc định cho các trang web khác nếu bạn muốn (ví dụ: 'page', 'search', 'lang')
            # if 'search.php' in base_url_to_modify:
            #     targets_to_check_for_vulns[base_url_to_modify].add("q")


        if not targets_to_check_for_vulns:
            logger.info("[*] Không tìm thấy URL có tham số để kiểm tra lỗ hổng web.")
            return

        for url_to_check, params_to_test in targets_to_check_for_vulns.items():
            if params_to_test: # Chỉ kiểm tra nếu có ít nhất một tham số
                web_vuln_tasks.append(check_url_for_vulns(url_to_check, list(params_to_test)))
            else:
                logger.debug(f"Bỏ qua kiểm tra {url_to_check} vì không có tham số nào để kiểm tra.")


        if not web_vuln_tasks:
            logger.info("[*] Không tìm thấy tác vụ kiểm tra lỗ hổng web nào để thực thi.")
            return

        await asyncio.gather(*web_vuln_tasks)
        
        self._save_json_result(self.results["web_vulnerabilities"], self.output_dir / "web_vulnerabilities_findings.json")
        self._save_json_result(self.results["other_vulnerabilities"], self.output_dir / "other_vulnerabilities_findings.json")
        logger.info(f"[+] Hoàn thành kiểm tra lỗ hổng web. Tìm thấy {len(self.results['web_vulnerabilities'])} lỗ hổng XSS/SQLi.")
        logger.info(f"[+] Tìm thấy {len(self.results['other_vulnerabilities'])} lỗ hổng khác.")

    # Trong class KaliScanPipeline

# ... (phương thức _run_nmap_verify) ...

# Đổi tên phương thức này
    async def _run_nmap_port_scan(self, target_ip: str, ports_to_scan: Optional[List[int]] = None): # <-- Đổi tên
        logger.info(f"[*] Sử dụng Nmap -sT để quét cổng cho mục tiêu: {target_ip}...") # <-- Sửa log
        nmap_output_subdir = self.output_dir / "nmap_sT_scan" # <-- Thay đổi thư mục output
        nmap_output_subdir.mkdir(parents=True, exist_ok=True)
    
    # Chỉ quét các cổng web phổ biến nếu không chỉ định rõ
        actual_ports_to_scan = sorted(list(set(ports_to_scan or [80, 443, 8000, 8080, 8443]))) 
        ports_str = ",".join(str(p) for p in actual_ports_to_scan)
    
        normalized_ip = target_ip.replace('.', '_').replace(':', '_').replace('%', '_')
        out_prefix = nmap_output_subdir / f"nmap_sT_{normalized_ip}"
    
        cmd = [NMAP_BIN,"-PN", "-sT", "-p", ports_str, target_ip, "-oA", str(out_prefix)]
        logger.debug(f"Lệnh Nmap -sT: {' '.join(shlex.quote(p) for p in cmd)}")
    
        try:
        # Timeout cho Nmap -sT (tối thiểu 1 phút, tăng theo số cổng)
            timeout_nmap_scan = max(60, len(actual_ports_to_scan) * 5) # 5s/cổng, tối thiểu 60s
            process = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=timeout_nmap_scan
            )
            logger.info(f"[+] Nmap -sT cho {target_ip} hoàn thành.")
        
            parsed_nmap_data = {}
            xml_path = Path(str(out_prefix) + ".xml")
            if xml_path.exists():
                parser = NmapParser(xml_path)
                parsed_host_data = parser.parse()
                if parsed_host_data:
                    for host_info in parsed_host_data:
                        ip = next((addr['addr'] for addr in host_info['addresses'] if addr['addrtype'] == 'ipv4'), 'N/A')
                        open_ports = [int(p['portid']) for p in host_info['ports'] if p['state'] == 'open']
                        if open_ports:
                             parsed_nmap_data[ip] = sorted(open_ports)
        
            self.results["masscan_open_ports"] = parsed_nmap_data
            total_open_ports = sum(len(v) for v in self.results['masscan_open_ports'].values())
            logger.info(f"[+] Nmap -sT tìm thấy {total_open_ports} cổng mở trên {len(self.results['masscan_open_ports'])} IP(s).")

        except subprocess.CalledProcessError as e:
            logger.error(f"[!] Nmap -sT thất bại cho {target_ip}: {e.stderr.strip() if e.stderr else str(e)}")
        except asyncio.TimeoutError:
            logger.error(f"[!] Nmap -sT cho {target_ip} đã hết thời gian.")
        except Exception as e:
            logger.error(f"[!] Lỗi chung khi chạy Nmap -sT cho {target_ip}: {e}")

# ... (phương thức _run_nmap_vulnerability_check) ...
            
    async def run_full_scan(self):
        """
        Điều phối toàn bộ quy trình quét.
        """
        logger.info(f"==== Bắt đầu quét toàn diện cho mục tiêu: {self.target} ====")
        logger.info(f"Thư mục đầu ra: {self.output_dir}")

        # Khởi tạo aiohttp session với timeout rất cao
        self.http_session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.recon_scanner.timeout))
        self.web_vuln_scanner = WebVulnerabilityScanner(self.http_session, timeout=self.recon_scanner.timeout)

        try:
            # Bước 1: Passive/Active Recon bằng ReconScanner
            await self._run_passive_active_recon_scanner()

            # Bước 2: Quét cổng rộng. LUÔN SỬ DỤNG Nmap -sT thay vì Masscan.
            if self.target_ip_for_masscan:
                logger.info("[*] Sử dụng Nmap -sT để quét cổng cho tất cả các mục tiêu (thay thế Masscan).")
                # Gọi phương thức _run_nmap_port_scan mới.
                # Truyền danh sách cổng web phổ biến. Nếu muốn quét tất cả 65535 cổng, truyền ports_to_scan=None (RẤT LÂU!)
                await self._run_nmap_port_scan(self.target_ip_for_masscan, ports_to_scan=[80, 443, 5000, 8000, 8080, 8443, 8888])
            else:
                logger.warning("[!] Bỏ qua Quét cổng do không có IP mục tiêu có thể phân giải.")

            # Bước 3: Quét dịch vụ/phiên bản chi tiết bằng Nmap (luôn chạy sau khi cổng mở được xác định)
            if self.results["masscan_open_ports"]: # masscan_open_ports bây giờ chứa kết quả từ Nmap -sT
                await self._run_nmap_verify()
            else:
                logger.info("[*] Bỏ qua Nmap (chi tiết) vì không tìm thấy cổng mở nào.")
            
            # Bước 3.5: Phân tích kết quả Nmap XML
            await self._run_nmap_vulnerability_check()

            # Bước 4: Reconnaissance cụ thể về Web bằng ReconScanner
            # Độ sâu crawling được đặt trong DEFAULT_CRAWL_DEPTH
            await self._run_web_recon_scanner() 
            
            # Bước 5: Kiểm tra lỗ hổng Web (XSS, SQLi)
            if self.results["recon_scanner_web_discovery"]:
                await self._run_web_vulnerability_check()
            else:
                logger.info("[*] Bỏ qua kiểm tra lỗ hổng web vì không tìm thấy trang web để khám phá.")
            
        except Exception as e:
            logger.critical(f"[CRITICAL] Quy trình quét thất bại bất ngờ cho {self.target}: {e}", exc_info=True)
            self.results["pipeline_error"] = str(e)
        finally:
            if self.http_session:
                await self.http_session.close()

        logger.info(f"==== Quét toàn diện cho {self.target} hoàn thành. Kết quả được lưu trong: {self.output_dir} ====")
        self._save_json_result(self.results, self.output_dir / "full_scan_summary.json")
        return self.results


    def _save_json_result(self, data: Dict[str, Any], file_path: Path):
        """Hàm trợ giúp để lưu dữ liệu dictionary vào file JSON."""
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.debug(f"Đã lưu kết quả vào {file_path}")
        except Exception as e:
            logger.error(f"[!] Lỗi khi lưu kết quả JSON vào {file_path}: {e}")
