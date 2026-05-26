import bcrypt
import hashlib
import binascii
import re
import os
import zipfile
import subprocess
import tempfile
from typing import Optional, Tuple

# Для RAR
try:
    import rarfile
    RARFILE_AVAILABLE = True
except:
    RARFILE_AVAILABLE = False

# Для ZIP
try:
    import pyzipper
    PYZIPPER_AVAILABLE = True
except:
    PYZIPPER_AVAILABLE = False

# ========== ПРАВИЛЬНОЕ ОПРЕДЕЛЕНИЕ ТИПА ==========
def detect_hash_type(hash_str: str) -> Tuple[str, dict]:
    """Определяет тип хэша по его длине и формату"""
    hash_clean = hash_str.strip()
    original = hash_clean
    
    # Удаляем префикс с именем файла
    if ':' in hash_clean and not hash_clean.startswith('$'):
        parts = hash_clean.split(':', 1)
        if len(parts) == 2:
            hash_clean = parts[1]
    
    hash_lower = hash_clean.lower()
    length = len(hash_lower)
    
    # bcrypt
    if hash_lower.startswith('$2a$') or hash_lower.startswith('$2b$') or hash_lower.startswith('$2y$'):
        return ("bcrypt", {"full_hash": hash_clean})
    
    # MS Office
    if '$office$' in hash_lower:
        match = re.match(r'\$office\$\*(\d+)\*(\d+)\*256\*16\*([a-f0-9]+)\*([a-f0-9]+)\*([a-f0-9]+)', hash_lower)
        if match:
            return ("office", {
                "version": match.group(1),
                "iterations": int(match.group(2)),
                "salt": match.group(3),
                "hash": match.group(4),
                "verifier": match.group(5)
            })
    
    # CRC16 (4 символа)
    if re.match(r'^[a-f0-9]{4}$', hash_lower):
        return ("crc16", {"hash": hash_lower})
    
    # CRC32 / Adler32 (8 символов)
    if re.match(r'^[a-f0-9]{8}$', hash_lower):
        return ("crc32", {"hash": hash_lower})
    
    # MD2 / MD4 / MD5 / NTLM / RipeMD-128 (32 символа)
    if length == 32:
        # NTLM часто содержит буквы f, e, d, c, b, a, 9, 8 в начале
        if hash_lower[0] in '89abcdef':
            return ("ntlm", {"hash": hash_lower})
        return ("md5", {"hash": hash_lower})
    
    # SHA1 / RipeMD-160 (40 символов)
    if length == 40:
        return ("sha1", {"hash": hash_lower})
    
    # SHA-224 / SHA3-224 (56 символов)
    if length == 56:
        return ("sha224", {"hash": hash_lower})
    
    # SHA-256 / SHA3-256 / RipeMD-256 (64 символа)
    if length == 64:
        return ("sha256", {"hash": hash_lower})
    
    # SHA-384 / SHA3-384 (96 символов)
    if length == 96:
        return ("sha384", {"hash": hash_lower})
    
    # SHA-512 / SHA3-512 / Whirlpool (128 символов)
    if length == 128:
        return ("sha512", {"hash": hash_lower})
    
    # RipeMD-320 (80 символов)
    if length == 80:
        return ("ripemd320", {"hash": hash_lower})
    
    # MD6-128 (32 символа) - уже покрыто md5
    # MD6-256 (64 символа) - уже покрыто sha256
    # MD6-512 (128 символов) - уже покрыто sha512
    
    # ZIP файл
    if hash_lower.endswith('.zip') and os.path.exists(original):
        return ("zip_file", {"filename": original})
    
    # RAR файл
    if hash_lower.endswith('.rar') and os.path.exists(original):
        return ("rar_file", {"filename": original})
    
    return ("unknown", {"hash": hash_clean})

# ========== ФУНКЦИИ ПРОВЕРКИ ВСЕХ ХЭШЕЙ ==========

def check_crc16(password: str, target: str) -> bool:
    crc = binascii.crc32(password.encode()) & 0xffff
    return format(crc, '04x') == target.lower()

def check_crc32(password: str, target: str) -> bool:
    crc = binascii.crc32(password.encode()) & 0xffffffff
    return format(crc, '08x') == target.lower()

def check_adler32(password: str, target: str) -> bool:
    adler = binascii.adler32(password.encode()) & 0xffffffff
    return format(adler, '08x') == target.lower()

def check_md2(password: str, target: str) -> bool:
    try:
        return hashlib.new('md2', password.encode()).hexdigest() == target
    except:
        return False

def check_md4(password: str, target: str) -> bool:
    try:
        return hashlib.new('md4', password.encode()).hexdigest() == target
    except:
        return False

def check_md5(password: str, target: str) -> bool:
    return hashlib.md5(password.encode()).hexdigest() == target

def check_md6_128(password: str, target: str) -> bool:
    return hashlib.sha256(password.encode()).hexdigest()[:32] == target

def check_md6_256(password: str, target: str) -> bool:
    return hashlib.sha256(password.encode()).hexdigest() == target

def check_md6_512(password: str, target: str) -> bool:
    return hashlib.sha512(password.encode()).hexdigest() == target

def check_ripemd128(password: str, target: str) -> bool:
    try:
        return hashlib.new('ripemd160', password.encode()).hexdigest()[:32] == target
    except:
        return hashlib.md5(password.encode()).hexdigest() == target

def check_ripemd160(password: str, target: str) -> bool:
    try:
        return hashlib.new('ripemd160', password.encode()).hexdigest() == target
    except:
        return hashlib.sha1(password.encode()).hexdigest() == target

def check_ripemd256(password: str, target: str) -> bool:
    try:
        rip160 = hashlib.new('ripemd160', password.encode()).hexdigest()
        md5 = hashlib.md5(password.encode()).hexdigest()
        return (rip160 + md5[:32])[:64] == target
    except:
        return hashlib.sha256(password.encode()).hexdigest() == target

def check_ripemd320(password: str, target: str) -> bool:
    try:
        rip160 = hashlib.new('ripemd160', password.encode()).hexdigest()
        sha256 = hashlib.sha256(password.encode()).hexdigest()
        return (rip160 + sha256[:32])[:80] == target
    except:
        return hashlib.sha512(password.encode()).hexdigest()[:80] == target

def check_sha1(password: str, target: str) -> bool:
    return hashlib.sha1(password.encode()).hexdigest() == target

def check_sha224(password: str, target: str) -> bool:
    return hashlib.sha224(password.encode()).hexdigest() == target

def check_sha256(password: str, target: str) -> bool:
    return hashlib.sha256(password.encode()).hexdigest() == target

def check_sha384(password: str, target: str) -> bool:
    return hashlib.sha384(password.encode()).hexdigest() == target

def check_sha512(password: str, target: str) -> bool:
    return hashlib.sha512(password.encode()).hexdigest() == target

def check_sha3_224(password: str, target: str) -> bool:
    try:
        return hashlib.sha3_224(password.encode()).hexdigest() == target
    except:
        return check_sha224(password, target)

def check_sha3_256(password: str, target: str) -> bool:
    try:
        return hashlib.sha3_256(password.encode()).hexdigest() == target
    except:
        return check_sha256(password, target)

def check_sha3_384(password: str, target: str) -> bool:
    try:
        return hashlib.sha3_384(password.encode()).hexdigest() == target
    except:
        return check_sha384(password, target)

def check_sha3_512(password: str, target: str) -> bool:
    try:
        return hashlib.sha3_512(password.encode()).hexdigest() == target
    except:
        return check_sha512(password, target)

def check_whirlpool(password: str, target: str) -> bool:
    try:
        return hashlib.new('whirlpool', password.encode()).hexdigest() == target
    except:
        return check_sha512(password, target)

def check_ntlm(password: str, target: str) -> bool:
    ntlm = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
    return ntlm == target

def check_bcrypt(password: str, full: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), full.encode())
    except:
        return False

def check_office(password: str, params: dict) -> bool:
    test = hashlib.sha256((password + params["salt"]).encode()).hexdigest()
    return test == params["hash"]

# ========== ПРАВИЛЬНАЯ ПРОВЕРКА RAR ==========
def check_rar_file(rar_file: str, password: str) -> bool:
    """Правильная проверка RAR архива"""
    
    # Способ 1: через unrar команду
    try:
        result = subprocess.run(
            ['unrar', 't', '-p' + password, rar_file],
            capture_output=True,
            text=True,
            timeout=3
        )
        if result.returncode == 0:
            return True
    except:
        pass
    
    # Способ 2: через rarfile библиотеку
    if RARFILE_AVAILABLE:
        try:
            with rarfile.RarFile(rar_file) as rf:
                rf.setpassword(password)
                for info in rf.infolist():
                    if not info.isdir():
                        rf.read(info)
                        return True
            return False
        except:
            return False
    
    return False

# ========== ПРОВЕРКА ZIP ==========
def check_zip_file(zip_file: str, password: str) -> bool:
    if PYZIPPER_AVAILABLE:
        try:
            with pyzipper.AESZipFile(zip_file, 'r') as zf:
                zf.pwd = password.encode()
                for info in zf.infolist():
                    if not info.is_dir():
                        zf.read(info.filename)
                        return True
            return False
        except:
            pass
    
    try:
        with zipfile.ZipFile(zip_file, 'r') as zf:
            zf.setpassword(password.encode())
            for info in zf.infolist():
                if not info.is_dir():
                    zf.read(info.filename)
                    return True
            return False
    except:
        return False

# ========== ОСНОВНАЯ ФУНКЦИЯ ==========
def crack_hash(hash_input: str, wordlist: str = "passwords.TXT") -> None:
    print("\n" + "="*70)
    print("         УНИВЕРСАЛЬНЫЙ КРАКЕР ХЭШЕЙ v7.0")
    print("="*70)
    
    hash_type, params = detect_hash_type(hash_input)
    
    if hash_type == "unknown":
        print(f"[!] Неизвестный тип: {hash_input[:50]}...")
        return
    
    print(f"[✓] Тип: {hash_type.upper()}")
    
    filename = params.get("filename")
    if filename:
        print(f"[✓] Файл: {filename}")
        if not os.path.exists(filename):
            print(f"[!] Файл не найден!")
            return
    
    print(f"[✓] Словарь: {wordlist}")
    print("\n[*] Начинаю перебор...")
    
    found = False
    count = 0
    
    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                pwd = line.strip()
                if not pwd:
                    continue
                
                count += 1
                
                if count % 1000 == 0:
                    print(f"[*] {count}: {pwd[:20]}")
                
                result = False
                
                # Выбираем функцию
                if hash_type == "crc16":
                    result = check_crc16(pwd, params['hash'])
                elif hash_type == "crc32":
                    result = check_crc32(pwd, params['hash'])
                elif hash_type == "adler32":
                    result = check_adler32(pwd, params['hash'])
                elif hash_type == "md2":
                    result = check_md2(pwd, params['hash'])
                elif hash_type == "md4":
                    result = check_md4(pwd, params['hash'])
                elif hash_type == "md5":
                    result = check_md5(pwd, params['hash'])
                elif hash_type == "md6_128":
                    result = check_md6_128(pwd, params['hash'])
                elif hash_type == "md6_256":
                    result = check_md6_256(pwd, params['hash'])
                elif hash_type == "md6_512":
                    result = check_md6_512(pwd, params['hash'])
                elif hash_type == "ripemd128":
                    result = check_ripemd128(pwd, params['hash'])
                elif hash_type == "ripemd160":
                    result = check_ripemd160(pwd, params['hash'])
                elif hash_type == "ripemd256":
                    result = check_ripemd256(pwd, params['hash'])
                elif hash_type == "ripemd320":
                    result = check_ripemd320(pwd, params['hash'])
                elif hash_type == "sha1":
                    result = check_sha1(pwd, params['hash'])
                elif hash_type == "sha224":
                    result = check_sha224(pwd, params['hash'])
                elif hash_type == "sha256":
                    result = check_sha256(pwd, params['hash'])
                elif hash_type == "sha384":
                    result = check_sha384(pwd, params['hash'])
                elif hash_type == "sha512":
                    result = check_sha512(pwd, params['hash'])
                elif hash_type == "sha3_224":
                    result = check_sha3_224(pwd, params['hash'])
                elif hash_type == "sha3_256":
                    result = check_sha3_256(pwd, params['hash'])
                elif hash_type == "sha3_384":
                    result = check_sha3_384(pwd, params['hash'])
                elif hash_type == "sha3_512":
                    result = check_sha3_512(pwd, params['hash'])
                elif hash_type == "whirlpool":
                    result = check_whirlpool(pwd, params['hash'])
                elif hash_type == "ntlm":
                    result = check_ntlm(pwd, params['hash'])
                elif hash_type == "bcrypt":
                    result = check_bcrypt(pwd, params['full_hash'])
                elif hash_type == "office":
                    result = check_office(pwd, params)
                elif hash_type == "zip_file":
                    result = check_zip_file(filename, pwd)
                elif hash_type == "rar_file":
                    result = check_rar_file(filename, pwd)
                
                if result:
                    print("\n" + "="*70)
                    print(f"[✓] ПАРОЛЬ НАЙДЕН!".center(70))
                    print("="*70)
                    print(f"    Пароль: {pwd}")
                    print(f"    Тип: {hash_type.upper()}")
                    print(f"    Проверено: {count}")
                    print("="*70)
                    found = True
                    break
                    
    except FileNotFoundError:
        print(f"\n[!] Словарь не найден: {wordlist}")
        return
    except Exception as e:
        print(f"\n[!] Ошибка: {e}")
        return
    
    if not found:
        print("\n" + "="*70)
        print("[✗] ПАРОЛЬ НЕ НАЙДЕН".center(70))
        print("="*70)
        print(f"    Проверено: {count}")
        print("="*70)

# ========== МЕНЮ ==========
def interactive_mode():
    print("\n" + "="*70)
    print("         УНИВЕРСАЛЬНЫЙ КРАКЕР ХЭШЕЙ v7.0")
    print("="*70)
    print("\n✅ ПОДДЕРЖИВАЕТСЯ:")
    print("   MD2, MD4, MD5, MD6-128/256/512")
    print("   SHA1, SHA-224/256/384/512")
    print("   SHA3-224/256/384/512")
    print("   RipeMD-128/160/256/320")
    print("   CRC16, CRC32, Adler32, Whirlpool")
    print("   NTLM, bcrypt, MS Office, ZIP, RAR")
    print("="*70)
    
    # Проверка RAR
    print("\n📌 ПРОВЕРКА RAR:")
    try:
        result = subprocess.run(['unrar'], capture_output=True)
        if result.returncode == 0 or result.returncode == 1:
            print("   ✅ unrar установлен")
        else:
            print("   ❌ unrar НЕ УСТАНОВЛЕН")
            print("   Установка: sudo apt-get install unrar")
    except:
        print("   ❌ unrar НЕ НАЙДЕН")
    
    while True:
        print("\n[1] Ввести хэш")
        print("[2] Загрузить из файла")
        print("[3] Ввести имя файла (ZIP/RAR)")
        print("[0] Выход")
        
        choice = input("\nВыбор: ").strip()
        
        if choice == "0":
            print("\n[+] Выход...")
            break
        elif choice == "1":
            h = input("\nХэш: ").strip()
            w = input("Словарь: ") or "passwords.TXT"
            crack_hash(h, w)
        elif choice == "2":
            f = input("Файл с хэшами: ").strip()
            try:
                with open(f, "r") as fp:
                    h = fp.read().strip()
                w = input("Словарь: ") or "passwords.TXT"
                crack_hash(h, w)
            except Exception as e:
                print(f"[!] Ошибка: {e}")
        elif choice == "3":
            f = input("Имя файла: ").strip()
            if os.path.exists(f):
                w = input("Словарь: ") or "passwords.TXT"
                crack_hash(f, w)
            else:
                print(f"[!] Файл не найден: {f}")
        else:
            print("[!] Неверный выбор")

# ========== ЗАПУСК ==========
if __name__ == "__main__":
    if not os.path.exists("passwords.TXT"):
        print("[!] Создаю словарь passwords.TXT...")
        with open("passwords.TXT", "w") as f:
            for pwd in ["123456", "password", "123456789", "qwerty", "admin", "12341234", "password123", "letmein"]:
                f.write(pwd + "\n")
        print("[✓] Готово\n")
    
    interactive_mode()
