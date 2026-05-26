#!/usr/bin/env python3
import subprocess
import tempfile
import os

def print_banner():
    print("\n" + "="*60)
    print("         RAR ПАРОЛЬ КРАКЕР v2.0")
    print("="*60)

def print_found(password: str, count: int):
    print("\n" + "="*60)
    print("🎉🎉🎉   ПАРОЛЬ НАЙДЕН!   🎉🎉🎉")
    print("="*60)
    print(f"\n    🔑 ПАРОЛЬ: {password}")
    print(f"    🔢 ПРОВЕРЕНО: {count} паролей")
    print("\n" + "="*60)

def print_not_found(count: int):
    print("\n" + "="*60)
    print("❌❌❌   ПАРОЛЬ НЕ НАЙДЕН   ❌❌❌")
    print("="*60)
    print(f"\n    🔢 ПРОВЕРЕНО: {count} паролей")
    print("="*60)

def check_rar_real(rar_file: str, password: str) -> bool:
    """Реальная проверка пароля RAR"""
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                ['unrar', 'x', '-p' + password, rar_file, tmpdir],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Проверяем, что файлы извлечены
            if result.returncode == 0 and len(os.listdir(tmpdir)) > 0:
                return True
            return False
    except:
        return False

def crack_rar(rar_file: str, wordlist: str = "passwords.txt"):
    print_banner()
    
    if not os.path.exists(rar_file):
        print(f"\n    ❌ ФАЙЛ НЕ НАЙДЕН: {rar_file}")
        return
    
    if not os.path.exists(wordlist):
        print(f"\n    ❌ СЛОВАРЬ НЕ НАЙДЕН: {wordlist}")
        print("    📝 СОЗДАЮ ТЕСТОВЫЙ СЛОВАРЬ...")
        with open(wordlist, "w") as f:
            test_passwords = [
                "123456", "password", "123456789", "qwerty",
                "admin", "12341234", "password123", "shamshi006",
                "letmein", "welcome", "monkey", "dragon"
            ]
            for pwd in test_passwords:
                f.write(pwd + "\n")
        print(f"    ✓ СОЗДАН {wordlist}")
    
    print(f"\n    📦 ФАЙЛ: {rar_file}")
    print(f"    📖 СЛОВАРЬ: {wordlist}")
    print(f"\n    🚀 НАЧИНАЮ ПЕРЕБОР...\n")
    
    found = False
    count = 0
    
    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                pwd = line.strip()
                if not pwd:
                    continue
                
                count += 1
                print(f"    [{count:>4}] ПРОВЕРКА: {pwd[:25]}")
                
                if check_rar_real(rar_file, pwd):
                    print_found(pwd, count)
                    found = True
                    break
                    
    except Exception as e:
        print(f"\n    ❌ ОШИБКА: {e}")
        return
    
    if not found:
        print_not_found(count)

def interactive():
    print_banner()
    
    while True:
        print("\n" + "-"*60)
        print("    [1] 🚀 ВЗЛОМАТЬ RAR ФАЙЛ")
        print("    [0] 🚪 ВЫХОД")
        print("-"*60)
        
        choice = input("\n    ВЫБОР: ").strip()
        
        if choice == "0":
            print("\n    👋 ДО СВИДАНИЯ!\n")
            break
        elif choice == "1":
            rar = input("\n    ВВЕДИТЕ ИМЯ RAR ФАЙЛА: ").strip()
            if not rar:
                print("    ❌ ИМЯ ФАЙЛА НЕ МОЖЕТ БЫТЬ ПУСТЫМ!")
                continue
            
            wordlist = input("    ВВЕДИТЕ ИМЯ СЛОВАРЯ (Enter = passwords.txt): ").strip()
            if not wordlist:
                wordlist = "passwords.txt"
            
            crack_rar(rar, wordlist)
        else:
            print("    ❌ НЕВЕРНЫЙ ВЫБОР!")

if __name__ == "__main__":
    interactive()
