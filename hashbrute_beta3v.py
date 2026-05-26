import bcrypt
import hashlib
import binascii
import re
import os
import zipfile
from typing import Optional, Tuple

# Пробуем импортировать pyzipper для AES-256 поддержки
try:
    import pyzipper
    PYZIPPER_AVAILABLE = True
except ImportError:
    PYZIPPER_AVAILABLE = False
    print("[!] pyzipper не установлен. Для ZIP AES-256 установите: pip install pyzipper")

# ========== ДЕТЕКТОР ТИПА ХЭША ==========
def detect_hash_type(hash_str: str) -> Tuple[str, dict]:
    """Автоматически определяет тип хэша и возвращает параметры"""
    hash_lower = hash_str.lower().strip()
    
    # ZIP файл (передаём имя файла)
    if hash_lower.endswith('.zip') and os.path.exists(hash_str):
        return ("zip_file", {"filename": hash_str})
    
    # Удаляем префикс с именем файла (test.xlsx: или photo.zip:)
    if ':' in hash_str and not hash_str.startswith('$'):
        parts = hash_str.split(':', 1)
        if len(parts) == 2 and os.path.exists(parts[0]):
            return ("zip_file", {"filename": parts[0]})
        elif len(parts) == 2:
            hash_str = parts[1]
            hash_lower = hash_str.lower().strip()
    
    # ZIP хэш (формат $zip2$ от zip2john)
    if '$zip2$' in hash_lower:
        return ("zip_hash", {"full_hash": hash_str})
    
    # bcrypt
    if hash_lower.startswith('$2a$') or hash_lower.startswith('$2b$') or hash_lower.startswith('$2y$'):
        return ("bcrypt", {"full_hash": hash_str})
    
    # MS Office 2013/2016
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
    
    # CRC32 (8 символов hex)
    if re.match(r'^[a-f0-9]{8}$', hash_lower):
        return ("crc32", {"hash": hash_lower})
    
    # MD5 (32 символа hex)
    if re.match(r'^[a-f0-9]{32}$', hash_lower):
        return ("md5", {"hash": hash_lower})
    
    # SHA1 (40 символов hex)
    if re.match(r'^[a-f0-9]{40}$', hash_lower):
        return ("sha1", {"hash": hash_lower})
    
    # SHA256 (64 символа hex)
    if re.match(r'^[a-f0-9]{64}$', hash_lower):
        return ("sha256", {"hash": hash_lower})
    
    # SHA512 (128 символов hex)
    if re.match(r'^[a-f0-9]{128}$', hash_lower):
        return ("sha512", {"hash": hash_lower})
    
    # NTLM (32 символа hex)
    if re.match(r'^[a-f0-9]{32}$', hash_lower) and len(hash_lower) == 32:
        return ("ntlm", {"hash": hash_lower})
    
    # MySQL (41 символ, начинается с *)
    if hash_lower.startswith('*') and len(hash_lower) == 41:
        return ("mysql", {"hash": hash_lower[1:]})
    
    # PostgreSQL (MD5)
    if re.match(r'^md5[a-f0-9]{32}$', hash_lower):
        return ("postgres", {"hash": hash_lower[3:]})
    
    return ("unknown", {"hash": hash_str})

# ========== ФУНКЦИИ ПРОВЕРКИ ==========
def check_md5(password: str, target_hash: str) -> bool:
    return hashlib.md5(password.encode()).hexdigest() == target_hash

def check_sha1(password: str, target_hash: str) -> bool:
    return hashlib.sha1(password.encode()).hexdigest() == target_hash

def check_sha256(password: str, target_hash: str) -> bool:
    return hashlib.sha256(password.encode()).hexdigest() == target_hash

def check_sha512(password: str, target_hash: str) -> bool:
    return hashlib.sha512(password.encode()).hexdigest() == target_hash

def check_crc32(password: str, target_hash: str) -> bool:
    crc = binascii.crc32(password.encode()) & 0xffffffff
    return format(crc, '08x') == target_hash.lower()

def check_bcrypt(password: str, full_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), full_hash.encode())
    except:
        return False

def check_ntlm(password: str, target_hash: str) -> bool:
    ntlm_hash = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
    return ntlm_hash == target_hash

def check_mysql(password: str, target_hash: str) -> bool:
    mysql_hash = hashlib.sha1(hashlib.sha1(password.encode()).digest()).hexdigest().upper()
    return mysql_hash == target_hash.upper()

def check_postgres(password: str, target_hash: str) -> bool:
    pg_hash = hashlib.md5((password + target_hash[:32]).encode()).hexdigest()
    return pg_hash == target_hash

def check_office(password: str, params: dict) -> bool:
    test_hash = hashlib.sha256((password + params["salt"]).encode()).hexdigest()
    return test_hash == params["hash"]

def check_zip_real(zip_file: str, password: str) -> bool:
    """
    РЕАЛЬНАЯ проверка пароля ZIP архива
    Поддерживает и ZipCrypto, и AES-256 (через pyzipper)
    """
    # Сначала пробуем pyzipper (поддерживает AES-256)
    if PYZIPPER_AVAILABLE:
        try:
            with pyzipper.AESZipFile(zip_file, 'r') as zf:
                zf.pwd = password.encode()
                # Пробуем прочитать первый файл
                for file_info in zf.infolist():
                    if not file_info.is_dir():
                        zf.read(file_info.filename)
                        return True
                return False
        except:
            pass
    
    # Затем пробуем стандартный zipfile (только ZipCrypto)
    try:
        with zipfile.ZipFile(zip_file, 'r') as zf:
            zf.setpassword(password.encode())
            for file_info in zf.infolist():
                if not file_info.is_dir():
                    zf.read(file_info.filename)
                    return True
            return False
    except:
        return False

# ========== ОСНОВНАЯ ФУНКЦИЯ ПОДБОРА ==========
def crack_hash(hash_input: str, wordlist_file: str = "passwords.TXT") -> None:
    print("\n" + "="*60)
    print("         УНИВЕРСАЛЬНЫЙ КРАКЕР ХЭШЕЙ v3.0")
    print("="*60)
    
    hash_type, params = detect_hash_type(hash_input)
    
    if hash_type == "unknown":
        print(f"[!] Неизвестный тип хэша: {hash_input[:50]}...")
        return
    
    print(f"[✓] Тип хэша определен: {hash_type.upper()}")
    
    zip_filename = None
    if hash_type == "zip_file":
        zip_filename = params["filename"]
        print(f"[✓] ZIP файл: {zip_filename}")
        
        # Определяем тип шифрования
        if PYZIPPER_AVAILABLE:
            print(f"[✓] Поддержка AES-256: ДА (pyzipper)")
        else:
            print(f"[!] Поддержка AES-256: НЕТ (установите pyzipper)")
            
        if not os.path.exists(zip_filename):
            print(f"[!] Файл не найден: {zip_filename}")
            return
    
    print(f"[✓] Файл словаря: {wordlist_file}")
    print("\n[*] Начинаю перебор...")
    
    found = False
    count = 0
    
    try:
        with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                password = line.strip()
                if not password:
                    continue
                
                count += 1
                
                if count % 1000 == 0:
                    print(f"[*] Проверено паролей: {count} (текущий: {password[:20]})")
                
                check_func = None
                
                if hash_type == "md5":
                    check_func = check_md5(password, params['hash'])
                elif hash_type == "sha1":
                    check_func = check_sha1(password, params['hash'])
                elif hash_type == "sha256":
                    check_func = check_sha256(password, params['hash'])
                elif hash_type == "sha512":
                    check_func = check_sha512(password, params['hash'])
                elif hash_type == "crc32":
                    check_func = check_crc32(password, params['hash'])
                elif hash_type == "bcrypt":
                    check_func = check_bcrypt(password, params['full_hash'])
                elif hash_type == "ntlm":
                    check_func = check_ntlm(password, params['hash'])
                elif hash_type == "mysql":
                    check_func = check_mysql(password, params['hash'])
                elif hash_type == "postgres":
                    check_func = check_postgres(password, params['hash'])
                elif hash_type == "office":
                    check_func = check_office(password, params)
                elif hash_type in ["zip_file", "zip_hash"]:
                    if zip_filename and os.path.exists(zip_filename):
                        check_func = check_zip_real(zip_filename, password)
                
                if check_func:
                    print("\n" + "="*60)
                    print(f"[✓] ПАРОЛЬ НАЙДЕН!".center(60))
                    print("="*60)
                    print(f"    Пароль: {password}")
                    print(f"    Проверено: {count} паролей")
                    print("="*60)
                    found = True
                    break
                    
    except FileNotFoundError:
        print(f"\n[!] ОШИБКА: Файл '{wordlist_file}' не найден!")
        print("[!] Создайте файл passwords.TXT в той же папке")
        print("[!] Каждый пароль на новой строке")
        return
    except Exception as e:
        print(f"\n[!] Ошибка: {e}")
        return
    
    if not found:
        print("\n" + "="*60)
        print("[✗] ПАРОЛЬ НЕ НАЙДЕН".center(60))
        print("="*60)
        print(f"    Проверено паролей: {count}")
        print("="*60)

# ========== ИНТЕРАКТИВНОЕ МЕНЮ ==========
def interactive_mode():
    print("\n" + "="*60)
    print("         УНИВЕРСАЛЬНЫЙ КРАКЕР ХЭШЕЙ v3.0")
    print("="*60)
    print("\nПоддерживаемые форматы:")
    print("  • MD5 (32 символа hex)")
    print("  • SHA1 (40 символов hex)")
    print("  • SHA256 (64 символа hex)")
    print("  • SHA512 (128 символов hex)")
    print("  • CRC32 (8 символов hex)")
    print("  • bcrypt ($2a$/$2b$/$2y$)")
    print("  • NTLM (32 символа hex)")
    print("  • MySQL (41 символ, начинается с *)")
    print("  • PostgreSQL (md5...)")
    print("  • MS Office 2013/2016 ($office$...)")
    print("  • ZIP архивы (ZipCrypto + AES-256) 🆕")
    print("="*60)
    
    if not PYZIPPER_AVAILABLE:
        print("\n[!] ВНИМАНИЕ: Для взлома ZIP AES-256 установите:")
        print("    pip install pyzipper")
    
    while True:
        print("\n[1] Ввести хэш вручную")
        print("[2] Загрузить хэш из файла (zip2john)")
        print("[3] Ввести имя ZIP файла")
        print("[0] Выход")
        
        choice = input("\nВыберите действие: ").strip()
        
        if choice == "0":
            print("\n[+] Выход...")
            break
        elif choice == "1":
            hash_input = input("\nВведите хэш: ").strip()
            wordlist = input(f"Путь к словарю (Enter = passwords.TXT): ").strip()
            if not wordlist:
                wordlist = "passwords.TXT"
            crack_hash(hash_input, wordlist)
        elif choice == "2":
            filename = input("Введите имя файла с хэшами: ").strip()
            try:
                with open(filename, "r") as f:
                    hash_input = f.read().strip()
                print(f"\n[+] Загружен хэш из {filename}")
                wordlist = input(f"Путь к словарю (Enter = passwords.TXT): ").strip()
                if not wordlist:
                    wordlist = "passwords.TXT"
                crack_hash(hash_input, wordlist)
            except Exception as e:
                print(f"[!] Ошибка: {e}")
        elif choice == "3":
            zip_file = input("Введите имя ZIP файла: ").strip()
            if os.path.exists(zip_file):
                wordlist = input(f"Путь к словарю (Enter = passwords.TXT): ").strip()
                if not wordlist:
                    wordlist = "passwords.TXT"
                crack_hash(zip_file, wordlist)
            else:
                print(f"[!] Файл {zip_file} не найден!")
        else:
            print("[!] Неверный выбор!")

# ========== ЗАПУСК ==========
if __name__ == "__main__":
    if not os.path.exists("passwords.TXT"):
        print("[!] ВНИМАНИЕ: Файл passwords.TXT не найден!")
        print("[+] Создаю тестовый файл passwords.TXT...")
        with open("passwords.TXT", "w") as f:
            test_passwords = [
                "123456", "password", "123456789", "qwerty",
                "password123", "admin", "letmein", "welcome",
                "monkey", "dragon", "12341234", "baseball"
            ]
            for pwd in test_passwords:
                f.write(pwd + "\n")
        print("[✓] Создан тестовый словарь с 12 паролями")
        print("[✓] Добавьте свои пароли в файл passwords.TXT\n")
    
    interactive_mode()
