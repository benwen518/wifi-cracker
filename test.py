import subprocess
import re
import concurrent.futures
import itertools
import string
import time
import hashlib
import numpy as np
from queue import Queue

# 使用哈希优化密码验证
def hash_password(password):
    """
    使用 SHA-256 对密码进行哈希计算
    """
    return hashlib.sha256(password.encode('utf-8')).digest()

def decode_unicode_escaped_string(s):
    """
    尝试解码 Unicode 转义形式的字符串。
    如果失败，则返回原始字符串。
    """
    try:
        # 尝试直接解码
        return s.encode('utf-8').decode('unicode_escape')
    except (ValueError, UnicodeDecodeError):
        try:
            # 尝试 GBK 解码（Windows 常用编码）
            return s.encode('gbk', errors='replace').decode('gbk')
        except (ValueError, UnicodeDecodeError):
            try:
                # 检查是否是十六进制字符串并尝试解码
                return bytes.fromhex(s).decode('utf-8')
            except (ValueError, UnicodeDecodeError):
                return s  # 返回原始字符串

def parse_wifi_block(block):
    """
    解析单个 Wi-Fi 网络块，提取 SSID、信号强度和加密方式。
    """
    try:
        ssid_match = re.search(r"SSID\s+\d+\s+:\s(.+)", block)
        signal_match = re.search(r"Signal\s+:\s(\d+)%", block)
        auth_match = re.search(r"Authentication\s+:\s(.+)", block)

        ssid = ssid_match.group(1).strip() if ssid_match else "Unknown"
        signal_strength = int(signal_match.group(1).strip()) if signal_match else 0
        encryption = auth_match.group(1).strip() if auth_match else "Unknown"

        ssid = decode_unicode_escaped_string(ssid)

        return {
            "SSID": ssid,
            "Signal (%)": signal_strength,
            "Encryption": encryption
        }
    except Exception as e:
        print(f"解析 Wi-Fi 块时出错：{e}")
        return None

def scan_wifi_networks():
    """
    扫描 Wi-Fi 网络，返回解析后的网络信息列表。
    """
    try:
        result = subprocess.check_output(
            "netsh wlan show networks mode=bssid", shell=True, encoding="gbk", errors="ignore"
        )
        print("\n完整输出（调试用）:\n", result)
    except subprocess.CalledProcessError as e:
        print(f"Wi-Fi 扫描失败: {e}")
        return []
    except Exception as e:
        print(f"未知错误: {e}")
        return []

    blocks = result.split("\n\n")
    with concurrent.futures.ThreadPoolExecutor() as executor:
        wifi_networks = list(filter(None, executor.map(parse_wifi_block, blocks)))

    wifi_networks.sort(key=lambda x: x["Signal (%)"], reverse=True)
    return wifi_networks

def dynamic_password_generator(start_length=8, max_length=8):
    """
    动态生成密码，从指定长度开始生成。
    """
    chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
    special_chars = "!@#$%^&*"

    for length in range(start_length, max_length + 1):
        for combination in itertools.product(chars + special_chars, repeat=length):
            yield ''.join(combination)

def batch_check_password_cpu(passwords, correct_password_hash, batch_size=1000):
    """
    利用 CPU 进行批量密码验证。
    """
    results = []
    for i in range(0, len(passwords), batch_size):
        batch = passwords[i:i + batch_size]

        hashed_batch = [hash_password(pw) for pw in batch]
        for pw, hashed_pw in zip(batch, hashed_batch):
            if hashed_pw == correct_password_hash:
                results.append(pw)

    return results

def password_cracker_cpu(password_generator, correct_password_hash, max_batches=100):
    """
    使用 CPU 批量破解密码
    """
    batch = []
    for password in password_generator:
        batch.append(password)

        if len(batch) >= max_batches:
            matched = batch_check_password_cpu(batch, correct_password_hash)
            if matched:
                return matched[0]
            batch = []

    if batch:
        matched = batch_check_password_cpu(batch, correct_password_hash)
        if matched:
            return matched[0]

    return None

def is_correct_password(ssid, password):
    """
    模拟密码验证过程。
    """
    correct_passwords = {
        "zhongqi": "SafePass2023",
        "Redmi Note 12T Pro": "Redmi2023",
    }
    return correct_passwords.get(ssid) == password

def main():
    print("正在扫描 Wi-Fi 网络，请稍候...")

    networks = scan_wifi_networks()

    if not networks:
        print("未发现可用的 Wi-Fi 网络。请检查 Wi-Fi 是否开启。")
        return

    print("\n发现以下 Wi-Fi 网络（按信号强度排序）：")
    for i, net in enumerate(networks):
        print(f"{i + 1}. SSID: {net['SSID']}, 信号强度: {net['Signal (%)']}%, 加密方式: {net['Encryption']}")

    while True:
        try:
            selected_index = int(input("\n请选择一个 Wi-Fi 网络 (输入编号): ")) - 1
            if 0 <= selected_index < len(networks):
                break
            else:
                print("无效选择，请输入正确的编号！")
        except ValueError:
            print("输入无效，请输入一个数字编号。")

    selected_network = networks[selected_index]
    print(f"您选择了 Wi-Fi 网络: {selected_network['SSID']}")

    password_generator = dynamic_password_generator(start_length=8)
    correct_password_hash = hash_password("Redmi2023")  # 示例密码

    result = password_cracker_cpu(password_generator, correct_password_hash)

    if result:
        print(f"\n密码破解成功！Wi-Fi: {selected_network['SSID']}, 密码: {result}")
    else:
        print("\n密码破解失败，未找到匹配的 密码。")

if __name__ == "__main__":
    main()
    print("密码破解完成。")
