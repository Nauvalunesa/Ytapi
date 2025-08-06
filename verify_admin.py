import json
import os
from datetime import datetime

def verify_admin_user():
    """Verify admin user exists and show details"""
    
    admin_file = "user/admin.json"
    
    if not os.path.exists(admin_file):
        print("❌ Admin user belum dibuat!")
        print("🔧 Jalankan: python create_admin.py")
        return
    
    try:
        with open(admin_file, 'r', encoding='utf-8') as f:
            admin_data = json.load(f)
        
        print("✅ ADMIN USER DITEMUKAN!")
        print("=" * 40)
        print(f"👤 Username: {admin_data['username']}")
        print(f"📧 Email: {admin_data['email']}")
        print(f"📱 Phone: {admin_data['phone_number']}")
        print(f"📅 Created: {admin_data['created_at']}")
        print(f"🔄 Active: {admin_data['is_active']}")
        
        # Check roles
        if admin_data.get('roles'):
            for role in admin_data['roles']:
                expired_date = datetime.fromisoformat(role['expired_at'])
                days_left = (expired_date - datetime.now()).days
                print(f"👑 Role: {role['role_name']}")
                print(f"⏰ Expired: {role['expired_at']}")
                print(f"📊 Sisa: {days_left} hari")
        
        # Check API keys
        active_keys = [k for k in admin_data.get('api_keys', []) if k.get('is_active')]
        print(f"🔐 API Keys: {len(active_keys)} aktif")
        
        # Check IPs
        active_ips = [ip for ip in admin_data.get('ip_addresses', []) if ip.get('is_active')]
        print(f"🌐 IP Addresses: {len(active_ips)} aktif")
        
        print("=" * 40)
        print("🎯 Status: ADMIN SIAP DIGUNAKAN!")
        
    except Exception as e:
        print(f"❌ Error reading admin file: {e}")

if __name__ == "__main__":
    verify_admin_user()
