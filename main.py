import bcrypt

input_hash = input("Введите bcrypt-хэш: ").strip().encode()

found = False
count = 0  # Счётчик проверенных паролей

with open("passwords.txt", "r", encoding="utf-8") as f:
    for line in f:
        password = line.strip().encode()
        count += 1
        print(f"Проверка #{count}: {password.decode()}")
        if bcrypt.checkpw(password, input_hash):
            print(f"Пароль найден: {password.decode()}")
            found = True
            break

if not found:
    print("Пароль из списка не подходит к этому хэшу.")
