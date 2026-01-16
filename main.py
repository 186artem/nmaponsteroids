import nmap
import requests
import json
import argparse
from datetime import datetime
import sys

class NetworkCVEScanner:
    def __init__(self, target):
        self.target = target
        self.scanner = nmap.PortScanner()
        self.results = {}
    def perform_scan(self, arguments='-sV -sC'):
        print(f"[*] Запущено nmap сканирование {self.target}")
        print(f"[*] Аргументы: {arguments}")
        try:
            self.scanner.scan(self.target, arguments=arguments)
            print(f"[+] Сканирование завершено")
            return True
        except Exception as e:
            print(f"[-] Ошибка сканирования: {e}")
            return False
    def parse_scan_results(self):
        for host in self.scanner.all_hosts():
            print(f"\n[*] Анализ хоста: {host}")
            print(f"[*] Статус: {self.scanner[host].state()}")
            self.results[host] = {
                'hostname': self.scanner[host].hostname(),
                'state': self.scanner[host].state(),
                'services': []
            }
            for proto in self.scanner[host].all_protocols():
                ports = self.scanner[host][proto].keys()
                for port in ports:
                    service_info = self.scanner[host][proto][port]

                    service_data = {
                        'port': port,
                        'protocol': proto,
                        'state': service_info.get('state', 'unknown'),
                        'service': service_info.get('name', 'unknown'),
                        'product': service_info.get('product', ''),
                        'version': service_info.get('version', ''),
                        'extrainfo': service_info.get('extrainfo', ''),
                        'cves': []
                    }
                    self.results[host]['services'].append(service_data)
                    print(f"\n  Порт: {port}/{proto}")
                    print(f"  Сервис: {service_data['service']}")
                    print(f"  Продукт: {service_data['product']}")
                    print(f"  Версия: {service_data['version']}")
    def search_cves_nvd(self, product, version):
        if not product or product == 'unknown':
            return []
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        keyword = f"{product}"
        if version:
            keyword += f" {version}"
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': 10
        }
        try:
            response = requests.get(base_url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                cves = []
                if 'vulnerabilities' in data:
                    for item in data['vulnerabilities']:
                        cve = item.get('cve', {})
                        cve_id = cve.get('id', '')
                        descriptions = cve.get('descriptions', [])
                        description = descriptions[0].get('value', '') if descriptions else ''
                        metrics = cve.get('metrics', {})
                        cvss_data = {}
                        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                            cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                            cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                        base_score = cvss_data.get('baseScore', 'N/A')
                        severity = cvss_data.get('baseSeverity', 'N/A')
                        cves.append({
                            'id': cve_id,
                            'description': description[:200] + '...' if len(description) > 200 else description,
                            'score': base_score,
                            'severity': severity
                        })
                return cves
            else:
                print(f"  [-] NVD API вернул статус {response.status_code}")
                return []
        except Exception as e:
            print(f"  [-] Ошибка поиска CVE: {e}")
            return []
    def search_all_cves(self):
        print("\n[*] Поиск CVE...")
        for host, data in self.results.items():
            for service in data['services']:
                product = service['product']
                version = service['version']
                if product and product != 'unknown':
                    print(f"\n  [*] Поиск CVE для {product} {version}")
                    cves = self.search_cves_nvd(product, version)
                    service['cves'] = cves
                    if cves:
                        print(f"  [+] Найдено {len(cves)} возможных CVE")
                        for cve in cves[:3]:  # Show first 3
                            print(f"      - {cve['id']} (Рейтинг: {cve['score']}, Серьезность: {cve['severity']})")
                    else:
                        print(f"  [-] CVE не найдены")
    def generate_report(self, output_file=None):
        report = {
            'scan_time': datetime.now().isoformat(),
            'target': self.target,
            'results': self.results
        }
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Отчет сохранен в файл {output_file}")
        print("\n" + "=" * 60)
        print("РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ")
        print("=" * 60)
        for host, data in self.results.items():
            print(f"\nХост: {host} ({data['hostname']})")
            print(f"Статус: {data['state']}")
            print(f"Найдено сервсисов: {len(data['services'])}")
            for service in data['services']:
                print(f"\n  {service['port']}/{service['protocol']} - {service['service']}")
                print(f"  Продукт: {service['product']} {service['version']}")
                if service['cves']:
                    print(f"  Найдено CVE: {len(service['cves'])}")
                    for cve in service['cves']:
                        print(f"    • {cve['id']} - Серьезность: {cve['severity']} (Рейтинг: {cve['score']})")
                        print(f"      {cve['description']}")
def main():
    parser = argparse.ArgumentParser(
        description='Сканер портов с поиском CVE',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python main.py -t 192.168.1.1
  python main.py -t 192.168.1.0/24 -a "-sV -p 1-1000"
  python main.py -t scanme.nmap.org -o report.json
        """
    )
    parser.add_argument('-t', '--target', required=True,
                        help='IP-адрес, hostname или CIDR-диапазон цели')
    parser.add_argument('-a', '--arguments', default='-sV -sC',
                        help='Аргументы nmap (по умолчанию: -sV -sC)')
    parser.add_argument('-o', '--output',
                        help='Имя файла, куда будет сохранен JSON-отчет')
    parser.add_argument('--no-cve', action='store_true',
                        help='Не искать CVE')
    args = parser.parse_args()
    try:
        scanner = NetworkCVEScanner(args.target)
        if not scanner.perform_scan(args.arguments):
            sys.exit(1)
        scanner.parse_scan_results()
        if not args.no_cve:
            scanner.search_all_cves()
        scanner.generate_report(args.output)
    except KeyboardInterrupt:
        print("\n[!] Сканирование преравно пользователем")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
