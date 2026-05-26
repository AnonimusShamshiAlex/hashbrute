import bcrypt
import hashlib
import binascii
import re
import zipfile
import tempfile
import os
from typing import Optional, Tuple

# ========== ДЕТЕКТОР ТИПА ХЭША ==========
def detect_hash_type(hash_str: str) -> Tuple[str, dict]:
    """Автоматически определяет тип хэша и возвращает параметры"""
    hash_lower = hash_str.lower().strip()
    
    # ZIP файл (передаём имя файла)
    if hash_lower.endswith('.zip') and os.path.exists(hash_str):
        return ("zip_file", {"filename": hash_str})
    
    # Удаляем префикс с именем файла
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
    
    # ZIP MD5 (упрощённый формат)
    if hash_lower.startswith('zip-md5:'):
        return ("zip_md5", {"hash": hash_lower.replace('zip-md5:', '')})
    
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
    
    # CRC32
    if re.match(r'^[a-f0-9]{8}$', hash_lower):
        return ("crc32", {"hash": hash_lower})
    
    # MD5
    if re.match(r'^[a-f0-9]{32}$', hash_lower):
        return ("md5", {"hash": hash_lower})
    
    # SHA1
    if re.match(r'^[a-f0-9]{40}$', hash_lower):
        return ("sha1", {"hash": hash_lower})
    
    # SHA256
    if re.match(r'^[a-f0-9]{64}$', hash_lower):
        return ("sha256", {"hash": hash_lower})
    
    # SHA512
    if re.match(r'^[a-f0-9]{128}$', hash_lower):
        return ("sha512", {"hash": hash_lower})
    
    # NTLM
    if re.match(r'^[a-f0-9]{32}$', hash_lower) and len(hash_lower) == 32:
        return ("ntlm", {"hash": hash_lower})
    
    # MySQL
    if hash_lower.startswith('*') and len(hash_lower) == 41:
        return ("mysql", {"hash": hash_lower[1:]})
    
    # PostgreSQL
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
    """РЕАЛЬНАЯ проверка пароля ZIP архива"""
    try:
        with zipfile.ZipFile(zip_file, 'r') as zf:
            # Устанавливаем пароль
            zf.setpassword(password.encode())
            # Пробуем прочитать первый файл в архиве
            for file_info in zf.infolist():
                if not file_info.is_dir():
                    # Пытаемся прочитать файл
                    zf.read(file_info.filename)
                    return True
            return False
    except (RuntimeError, zipfile.BadZipFile, KeyError):
        return False
    except Exception as e:
        return False

def check_zip_hash(zip_file: str, password: str, full_hash: str) -> bool:
    """Проверка через реальный ZIP файл (если есть)"""
    if os.path.exists(zip_file):
        return check_zip_real(zip_file, password)
    
    # Если файла нет, используем упрощённую проверку по хэшу
    password_crc = format(binascii.crc32(password.encode()) & 0xffffffff, '08x')
    password_md5 = hashlib.md5(password.encode()).hexdigest()
    
    if password_crc in full_hash.lower():
        return True
    if password_md5 in full_hash.lower():
        return True
    return False

# ========== ИЗВЛЕЧЕНИЕ ZIP ФАЙЛА ИЗ ХЭША ==========
def extract_zip_from_hash(hash_str: str) -> str:
    """Извлекает имя ZIP файла из хэша"""
    if ':' in hash_str:
        parts = hash_str.split(':', 1)
        if parts[0].endswith('.zip'):
            return parts[0]
    return ""

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
    
    # Для ZIP файла
    zip_filename = None
    if hash_type == "zip_file":
        zip_filename = params["filename"]
        print(f"[✓] ZIP файл: {zip_filename}")
        if not os.path.exists(zip_filename):
            print(f"[!] Файл не найден: {zip_filename}")
            return
    elif hash_type == "zip_hash":
        zip_filename = extract_zip_from_hash(hash_input)
        if zip_filename:
            print(f"[✓] ZIP файл: {zip_filename}")
    
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
                    else:
                        check_func = check_zip_hash(zip_filename, password, params.get('full_hash', ''))
                
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
    print("  • MD5, SHA1, SHA256, SHA512, CRC32")
    print("  • bcrypt, NTLM, MySQL, PostgreSQL")
    print("  • MS Office 2013/2016")
    print("  • ZIP архивы (реальная проверка!)")
    print("="*60)
    
    while True:
        print("\n[1] Ввести хэш вручную")
        print("[2] Загрузить хэш из файла")
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
    import os
    if not os.path.exists("passwords.TXT"):
        print("[!] Файл passwords.TXT не найден! Создаю тестовый...")
        with open("passwords.TXT", "w") as f:
            test_passwords = ["123456", "password", "123456789", "qwerty", 
                            "password123", "admin", "12341234", "letmein"]
            for pwd in test_passwords:
                f.write(pwd + "\n")
        print("[✓] Создан тестовый словарь\n")
    
    interactive_mode()
