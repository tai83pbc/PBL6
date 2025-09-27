import asyncio
import sys
import logging
from scan_pipeline_kali import KaliScanPipeline # Import class từ file scan_pipeline_kali.py

# Thiết lập logging cho file main.py
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("MainScanner")

async def main():
    """
    Điểm vào chính của ứng dụng quét.
    Phân tích các đối số dòng lệnh và khởi chạy KaliScanPipeline.
    """
    if len(sys.argv) < 2:
        print("Cách dùng: sudo python3 main.py <target_domain_or_ip_or_cidr> [masscan_rate_pps]")
        print("Ví dụ: sudo python3 main.py example.com")
        print("Ví dụ: sudo python3 main.py 192.168.1.1 5000")
        print("Ví dụ: sudo python3 main.py 192.168.1.0/24")
        sys.exit(1)

    target_input = sys.argv[1]
    masscan_rate_input = int(sys.argv[2]) if len(sys.argv) >= 3 else 1000

    logger.info(f"Khởi tạo quy trình quét cho mục tiêu: {target_input} (Masscan rate: {masscan_rate_input} pps)")
    pipeline = KaliScanPipeline(target=target_input, masscan_rate=masscan_rate_input)
    
    final_results = await pipeline.run_full_scan()

    # In ra một bản tóm tắt cuối cùng từ kết quả
    logger.info("\n=== Tóm tắt Quét Tổng thể ===")
    logger.info(f"Mục tiêu: {final_results['target']}")
    logger.info(f"Thư mục đầu ra: {final_results['output_directory']}")
    
    if final_results['recon_scanner_passive']:
        logger.info("  Passive Recon: OK")
    if final_results['recon_scanner_active']:
        logger.info("  Active Recon: OK")
    if final_results['masscan_open_ports']:
        total_masscan_ports = sum(len(v) for v in final_results['masscan_open_ports'].values())
        logger.info(f"  Masscan: Tìm thấy {total_masscan_ports} cổng mở trên {len(final_results['masscan_open_ports'])} IP(s).")
    
    if final_results['nmap_detailed_scans']:
        success_nmap_count = sum(1 for res in final_results['nmap_detailed_scans'].values() if res.get('status') == 'success')
        total_nmap_scans = len(final_results['nmap_detailed_scans'])
        logger.info(f"  Nmap: Hoàn thành {success_nmap_count}/{total_nmap_scans} quét chi tiết.")
    
    # NEW: Hiển thị dịch vụ Nmap đã phân tích
    if final_results['nmap_parsed_services']:
        total_parsed_services = sum(len(host.get('ports', [])) for host in final_results['nmap_parsed_services'])
        logger.info(f"  Nmap Parser: Tìm thấy {total_parsed_services} dịch vụ trên {len(final_results['nmap_parsed_services'])} host(s).")

    if final_results['recon_scanner_web_discovery']:
        total_web_links = sum(len(res.get('links',[])) for res in final_results['recon_scanner_web_discovery'].values() if res.get('links'))
        total_web_params = sum(len(res.get('params',[])) for res in final_results['recon_scanner_web_discovery'].values() if res.get('params'))
        logger.info(f"  Khám phá Web: Tìm thấy {total_web_links} liên kết và {total_web_params} tham số trên các mục tiêu web.")
    
    # NEW: Hiển thị các lỗ hổng web
    if final_results['web_vulnerabilities']:
        logger.info(f"  Lỗ hổng Web: Tìm thấy {len(final_results['web_vulnerabilities'])} lỗ hổng tiềm năng:")
        for vuln in final_results['web_vulnerabilities']:
            logger.info(f"    - Loại: {vuln['type']}, URL: {vuln['url']}, Tham số: {vuln.get('param', 'N/A')}, Payload: {vuln.get('payload', 'N/A')[:50]}...")
    else:
        logger.info("  Lỗ hổng Web: Không tìm thấy lỗ hổng web tiềm năng.")

    if final_results.get('pipeline_error'):
        logger.error(f"  Quy trình gặp lỗi nghiêm trọng: {final_results['pipeline_error']}")
    else:
        logger.info("  Quy trình quét hoàn thành không có lỗi nghiêm trọng.")


if __name__ == "__main__":
    asyncio.run(main())