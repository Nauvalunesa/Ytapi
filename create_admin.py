import json
import os
from datetime import datetime, timedelta
from passlib.context import CryptContext

# Setup password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_user_input():
    """Get admin user details from user input"""
    print("🚀 SETUP ADMIN USER - YOUTUBE DOWNLOADER API")
    print("=" * 50)
    print("Masukkan detail admin user:")
    print()
    
    # Get username
    while True:
        username = input("👤 Username admin: ").strip()
        if username:
            break
        print("❌ Username tidak boleh kosong!")
    
    # Get password
    while True:
        password = input("🔑 Password admin: ").strip()
        if len(password) >= 6:
            break
        print("❌ Password minimal 6 karakter!")
    
    # Get email
    while True:
        email = input("📧 Email admin: ").strip()
        if "@" in email and "." in email:
            break
        print("❌ Format email tidak valid!")
    
    # Get phone number
    while True:
        phone = input("📱 Nomor WhatsApp (contoh: 6285336580720): ").strip()
        if phone.isdigit() and len(phone) >= 10:
            break
        print("❌ Nomor WhatsApp tidak valid!")
    
    # Get role duration
    while True:
        try:
            days = int(input("⏰ Durasi role (hari, contoh: 9999): "))
            if days > 0:
                break
            print("❌ Durasi harus lebih dari 0!")
        except ValueError:
            print("❌ Masukkan angka yang valid!")
    
    # Get role type
    print("\n👑 Pilih role admin:")
    roles = [
        "pencariawal", "penjelajahmuda", "masterpro", 
        "strategiselit", "visionerlegendaris", "penguasa"
    ]
    
    for i, role in enumerate(roles, 1):
        print(f"  {i}. {role}")
    
    while True:
        try:
            choice = int(input("Pilih role (1-6): "))
            if 1 <= choice <= 6:
                selected_role = roles[choice - 1]
                break
            print("❌ Pilihan tidak valid!")
        except ValueError:
            print("❌ Masukkan angka yang valid!")
    
    return {
        'username': username,
        'password': password,
        'email': email,
        'phone': phone,
        'days': days,
        'role': selected_role
    }

def create_admin_user():
    """Create admin user with user input"""
    
    # Create user directory if not exists
    user_dir = "user"
    os.makedirs(user_dir, exist_ok=True)
    
    # Get user input
    admin_info = get_user_input()
    
    # Check if user already exists
    admin_file = os.path.join(user_dir, f"{admin_info['username']}.json")
    if os.path.exists(admin_file):
        overwrite = input(f"\n⚠️  User '{admin_info['username']}' sudah ada. Timpa? (y/n): ").lower()
        if overwrite != 'y':
            print("❌ Pembuatan admin dibatalkan.")
            return
    
    # Hash password
    password_hash = pwd_context.hash(admin_info['password'])
    
    # Calculate expiration date
    expired_date = datetime.now() + timedelta(days=admin_info['days'])
    
    # Create admin user structure
    admin_data = {
        "username": admin_info['username'],
        "email": admin_info['email'],
        "password_hash": password_hash,
        "phone_number": admin_info['phone'],
        "created_at": datetime.now().isoformat(),
        "is_active": True,
        "roles": [
            {
                "role_name": admin_info['role'],
                "expired_at": expired_date.isoformat(),
                "created_at": datetime.now().isoformat()
            }
        ],
        "api_keys": [
            {
                "api_key": f"api_{admin_info['username']}_admin_{datetime.now().strftime('%Y%m%d')}",
                "created_at": datetime.now().isoformat(),
                "is_active": True
            }
        ],
        "ip_addresses": [
            {
                "ip_address": "127.0.0.1",
                "created_at": datetime.now().isoformat(),
                "is_active": True
            }
        ]
    }
    
    # Save admin user file
    with open(admin_file, 'w', encoding='utf-8') as f:
        json.dump(admin_data, f, indent=2, ensure_ascii=False)
    
    print("\n🎉 ADMIN USER BERHASIL DIBUAT!")
    print("=" * 50)
    print(f"👤 Username: {admin_info['username']}")
    print(f"🔑 Password: {admin_info['password']}")
    print(f"📧 Email: {admin_info['email']}")
    print(f"📱 Phone: {admin_info['phone']}")
    print(f"👑 Role: {admin_info['role']}")
    print(f"⏰ Durasi: {admin_info['days']} hari")
    print(f"📅 Expired: {expired_date.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🔐 API Key: {admin_data['api_keys'][0]['api_key']}")
    print("=" * 50)
    print("✅ Admin siap digunakan!")
    print("🌐 Login di: http://localhost:8000/login")
    print("🚀 Akses penuh ke dashboard tersedia!")

if __name__ == "__main__":
    try:
        create_admin_user()
    except KeyboardInterrupt:
        print("\n\n❌ Pembuatan admin dibatalkan oleh user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
