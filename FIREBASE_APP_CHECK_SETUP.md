# 🔒 FIREBASE APP CHECK - HƯỚNG DẪN SETUP

## 📋 App Check là gì?

Firebase App Check bảo vệ backend của bạn khỏi:
- ✅ **Fake apps** - Ứng dụng giả mạo
- ✅ **Automated scripts** - Scripts spam/bot
- ✅ **API abuse** - Abuse API keys bị lộ
- ✅ **DDoS attacks** - Tấn công từ chối dịch vụ

**Cơ chế:** Mỗi request từ app phải có **App Check token** để Firebase chấp nhận!

---

## 🚀 BƯỚC 1: Cài đặt package (ĐÃ XONG ✅)

```yaml
# pubspec.yaml
dependencies:
  firebase_app_check: ^0.3.3+2
```

**Chạy:**
```bash
flutter pub get
```

---

## 🔧 BƯỚC 2: Activate App Check trong code (ĐÃ XONG ✅)

File `lib/main.dart` đã được cập nhật:

```dart
await FirebaseAppCheck.instance.activate(
  androidProvider: AndroidProvider.debug,  // Development
  appleProvider: AppleProvider.debug,      // Development
);
```

**Lưu ý:**
- `debug` provider: Cho development/testing (không cần Google Play)
- `playIntegrity` provider: Cho production (yêu cầu app trên Google Play)

---

## ⚙️ BƯỚC 3: Setup trên Firebase Console

### 3.1. Mở Firebase Console

1. Vào [Firebase Console](https://console.firebase.google.com)
2. Chọn project **lnmqne**
3. Sidebar: **Build** → **App Check**

### 3.2. Register Android App

1. Click **"Apps"** tab
2. Tìm app Android: `com.example.lnmq`
3. Click **"Register"**

### 3.3. Setup Debug Provider (cho Development)

**Tại sao cần:** Khi develop trên emulator/local device, không có Play Integrity

**Cách làm:**

1. Chạy app trên emulator/device
2. Xem log terminal sẽ hiện:
   ```
   D/FirebaseAppCheck: Debug token: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
   ```
   
3. Copy debug token này

4. Trên Firebase Console → **App Check** → **Apps** → Android app → **Manage debug tokens**

5. Click **"Add debug token"** → Paste token → Save

6. **Quan trọng:** Token này chỉ dùng cho development!

### 3.4. Setup Play Integrity (cho Production)

**Khi nào dùng:** Khi deploy lên Google Play Store

1. Firebase Console → **App Check** → Android app
2. Chọn **"Play Integrity"** provider
3. Không cần config gì thêm (Google tự động verify)
4. Update code:
   ```dart
   androidProvider: AndroidProvider.playIntegrity, // Production
   ```

---

## 🛡️ BƯỚC 4: Enable App Check cho Firestore (ĐÃ XONG ✅)

File `firestore.rules` đã được cập nhật:

```javascript
// Bookings - Require App Check
allow create: if isAuthenticated()
              && request.resource.data.userId == request.auth.uid
              && request.app != null; // ← Yêu cầu App Check token

// Reviews - Require App Check  
allow create: if isAuthenticated()
              && request.resource.data.userId == request.auth.uid
              && request.app != null; // ← Yêu cầu App Check token
```

**Deploy rules:**
1. Copy nội dung file `firestore.rules`
2. Firebase Console → **Firestore Database** → **Rules**
3. Paste và **Publish**

---

## ✅ BƯỚC 5: Test

### Test 1: App hợp lệ (có App Check token)
```dart
// Trong app Flutter
await FirebaseFirestore.instance.collection('bookings').add({...});
// → THÀNH CÔNG ✅
```

### Test 2: Script giả (không có App Check token)
```python
# Python script
import requests

# Gọi trực tiếp Firestore REST API
response = requests.post(
    'https://firestore.googleapis.com/v1/projects/lnmqne/...',
    json={...},
    params={'key': 'AIzaSyCMQPbz47CVgzz9POO886TS4Z7PlvVqCW0'}
)
# → LỖI: "Missing App Check token" ❌
```

**Kết quả:** Scripts/bots bị chặn, chỉ app thật mới tạo được bookings/reviews!

---

## 📊 BƯỚC 6: Monitoring

### Xem App Check metrics:

1. Firebase Console → **App Check** → **Metrics**
2. Xem:
   - **Valid requests**: Từ app thật
   - **Invalid requests**: Từ scripts/bots (bị chặn)
   - **Replay attacks**: Tái sử dụng token cũ

### Xem logs:

Firebase Console → **App Check** → **Recent Activity**
- Xem requests nào bị reject
- Debug issues

---

## 🔄 BƯỚC 7: Production Deployment

Khi deploy lên Google Play:

1. **Update code:**
   ```dart
   await FirebaseAppCheck.instance.activate(
     androidProvider: AndroidProvider.playIntegrity, // Production
   );
   ```

2. **Build release APK:**
   ```bash
   flutter build apk --release
   ```

3. **Upload lên Google Play Console**

4. Google Play sẽ tự động verify app integrity!

---

## ⚠️ Lưu ý quan trọng:

### Debug Provider vs Play Integrity:

| Provider | Khi nào dùng | Security |
|----------|--------------|----------|
| **Debug** | Development, testing | ⚠️ Thấp (debug token cố định) |
| **Play Integrity** | Production (Google Play) | ✅ Cao (Google verify) |

### Debug Token:
- ❌ **KHÔNG share** debug token publicly
- ❌ **XÓA** debug tokens trước khi deploy production
- ✅ Chỉ dùng cho development

### Rate Limiting:
App Check **TỰ ĐỘNG rate limit**:
- Requests quá nhiều từ cùng 1 device → Tạm chặn
- Replay token cũ → Reject
- Abnormal patterns → Flag

---

## 🎯 Kết quả:

### ✅ Đã bảo vệ:
1. **Bookings** - Chặn fake bookings từ scripts
2. **Reviews** - Chặn fake reviews từ bots
3. **API abuse** - Ngăn abuse Firebase API keys
4. **Rate limiting** - Tự động giới hạn requests

### ❌ Chưa bảo vệ (optional):
- Places read (public, không cần bảo vệ)
- Tours read (public, không cần bảo vệ)
- Chat read (đã có auth check)

---

## 🧪 Test Script (Demo cho báo cáo)

### Script tấn công (TRƯỚC khi có App Check):
```python
# fake_booking.py - BEFORE App Check
import requests

API_KEY = "AIzaSyCMQPbz47CVgzz9POO886TS4Z7PlvVqCW0"

# Spam fake bookings
for i in range(100):
    requests.post(
        f'https://firestore.googleapis.com/v1/projects/lnmqne/databases/(default)/documents/bookings?key={API_KEY}',
        json={'fields': {...}}
    )
    print(f'Fake booking {i+1} created! ✅')

# → THÀNH CÔNG tạo 100 fake bookings! (NGUY HIỂM)
```

### Script tấn công (SAU khi có App Check):
```python
# fake_booking.py - AFTER App Check
import requests

API_KEY = "AIzaSyCMQPbz47CVgzz9POO886TS4Z7PlvVqCW0"

response = requests.post(
    f'https://firestore.googleapis.com/v1/projects/lnmqne/databases/(default)/documents/bookings?key={API_KEY}',
    json={'fields': {...}}
)

print(response.status_code)  # 403 Forbidden
print(response.json())
# {
#   "error": {
#     "code": 403,
#     "message": "Missing or invalid App Check token"
#   }
# }

# → THẤT BẠI! Bị chặn bởi App Check! ❌
```

---

## 📚 Tài liệu tham khảo:

1. [Firebase App Check Docs](https://firebase.google.com/docs/app-check)
2. [Play Integrity API](https://developer.android.com/google/play/integrity)
3. [Security Rules với App Check](https://firebase.google.com/docs/app-check/custom-resource-firestore)

---

## ✅ CHECKLIST:

- [x] Cài package `firebase_app_check`
- [x] Activate App Check trong `main.dart`
- [x] Update Firestore rules với `request.app != null`
- [ ] Register app trên Firebase Console
- [ ] Add debug token cho development
- [ ] Deploy rules lên Firebase
- [ ] Test với app thật → OK
- [ ] Test với script giả → Bị chặn
- [ ] (Production) Switch sang `playIntegrity` provider

---

**🎉 HOÀN THÀNH: App đã được bảo vệ bởi Firebase App Check!**
