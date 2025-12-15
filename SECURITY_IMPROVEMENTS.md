# 🔒 CẢI TIẾN BẢO MẬT - TRAVEL APP

## 📋 ĐÁNH GIÁ HIỆN TRẠNG vs YÊU CẦU

| # | Yêu cầu | Hiện tại | Cần làm |
|---|---------|----------|---------|
| 1 | ✅ Mã hóa dữ liệu lưu trữ/phiên | Firebase AES-256 + HTTPS | Thêm SSL Pinning |
| 2 | ⚠️ Xác thực (OTP/Biometric), JWT | Firebase Auth + Google Sign-In | Thêm Phone Auth/Biometric |
| 3 | ✅ Chống SQL/XSS/Brute-force | Firestore NoSQL + App Check | ✅ Đạt |
| 4 | ⚠️ An toàn đường truyền | HTTPS/TLS 1.3 | Thêm SSL Pinning |
| 5 | ❌ Mã hóa tin nhắn E2E | Plaintext (chỉ mã hóa Firebase) | Implement E2EE |
| 6 | ❌ Bảo vệ mã nguồn | Không obfuscate | Code obfuscation + Root detection |

---

## 🎯 KẾ HOẠCH KHẮC PHỤC

### 🔴 PHASE 1: CẢI THIỆN NGAY (Cho môn học)

#### 1.1 ✅ Thêm Firebase Phone Authentication (OTP)

**Tại sao:** Đáp ứng yêu cầu "Xác thực OTP"

```yaml
# pubspec.yaml - KHÔNG CẦN thêm gì (Firebase Auth đã có)
```

```dart
// lib/services/auth_service.dart - Thêm method
import 'package:firebase_auth/firebase_auth.dart';

class AuthService {
  final FirebaseAuth _firebaseAuth = FirebaseAuth.instance;
  
  // ... existing code ...
  
  // ==================== PHONE AUTHENTICATION (OTP) ====================
  
  String? _verificationId;
  
  // Bước 1: Gửi OTP
  Future<void> sendOTP(String phoneNumber) async {
    await _firebaseAuth.verifyPhoneNumber(
      phoneNumber: phoneNumber, // Format: +84xxxxxxxxx
      timeout: const Duration(seconds: 60),
      
      // Auto verification (Android only)
      verificationCompleted: (PhoneAuthCredential credential) async {
        await _firebaseAuth.signInWithCredential(credential);
      },
      
      // Verification failed
      verificationFailed: (FirebaseAuthException e) {
        throw Exception('Xác thực thất bại: ${e.message}');
      },
      
      // OTP sent successfully
      codeSent: (String verificationId, int? resendToken) {
        _verificationId = verificationId;
      },
      
      // Auto-retrieval timeout
      codeAutoRetrievalTimeout: (String verificationId) {
        _verificationId = verificationId;
      },
    );
  }
  
  // Bước 2: Verify OTP
  Future<UserCredential> verifyOTP(String smsCode) async {
    if (_verificationId == null) {
      throw Exception('Vui lòng gửi OTP trước');
    }
    
    final credential = PhoneAuthProvider.credential(
      verificationId: _verificationId!,
      smsCode: smsCode,
    );
    
    return await _firebaseAuth.signInWithCredential(credential);
  }
  
  // Link phone number to existing account
  Future<void> linkPhoneNumber(String phoneNumber, String smsCode) async {
    final user = _firebaseAuth.currentUser;
    if (user == null) throw Exception('Chưa đăng nhập');
    
    final credential = PhoneAuthProvider.credential(
      verificationId: _verificationId!,
      smsCode: smsCode,
    );
    
    await user.linkWithCredential(credential);
  }
}
```

**UI Screen:** [lib/screens/phone_auth_screen.dart](lib/screens/phone_auth_screen.dart)

```dart
import 'package:flutter/material.dart';
import 'package:lnmq/services/auth_service.dart';

class PhoneAuthScreen extends StatefulWidget {
  const PhoneAuthScreen({super.key});

  @override
  State<PhoneAuthScreen> createState() => _PhoneAuthScreenState();
}

class _PhoneAuthScreenState extends State<PhoneAuthScreen> {
  final AuthService _authService = AuthService();
  final _phoneController = TextEditingController();
  final _otpController = TextEditingController();
  bool _otpSent = false;
  bool _isLoading = false;

  Future<void> _sendOTP() async {
    setState(() => _isLoading = true);
    try {
      await _authService.sendOTP('+84${_phoneController.text}');
      setState(() => _otpSent = true);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Mã OTP đã được gửi!')),
      );
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Lỗi: $e')),
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _verifyOTP() async {
    setState(() => _isLoading = true);
    try {
      await _authService.verifyOTP(_otpController.text);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Xác thực thành công!')),
      );
      Navigator.of(context).pop();
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Mã OTP không đúng: $e')),
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Xác thực số điện thoại')),
      body: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          children: [
            if (!_otpSent) ...[
              TextField(
                controller: _phoneController,
                keyboardType: TextInputType.phone,
                decoration: const InputDecoration(
                  labelText: 'Số điện thoại',
                  hintText: '0912345678',
                  prefix: Text('+84 '),
                ),
              ),
              const SizedBox(height: 20),
              ElevatedButton(
                onPressed: _isLoading ? null : _sendOTP,
                child: _isLoading
                    ? const CircularProgressIndicator()
                    : const Text('Gửi mã OTP'),
              ),
            ] else ...[
              TextField(
                controller: _otpController,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(
                  labelText: 'Mã OTP',
                  hintText: '123456',
                ),
              ),
              const SizedBox(height: 20),
              ElevatedButton(
                onPressed: _isLoading ? null : _verifyOTP,
                child: _isLoading
                    ? const CircularProgressIndicator()
                    : const Text('Xác nhận'),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
```

**Test:** Firebase Console → Authentication → Phone → Add test phone number

---

#### 1.2 ✅ Thêm Local Authentication (Sinh trắc học)

**Tại sao:** Đáp ứng yêu cầu "Xác thực sinh trắc học"

```yaml
# pubspec.yaml
dependencies:
  local_auth: ^2.3.0
```

```dart
// lib/services/biometric_service.dart
import 'package:local_auth/local_auth.dart';
import 'package:local_auth_android/local_auth_android.dart';
import 'package:local_auth_ios/local_auth_ios.dart';

class BiometricService {
  final LocalAuthentication _auth = LocalAuthentication();
  
  // Check if device supports biometrics
  Future<bool> canUseBiometrics() async {
    try {
      return await _auth.canCheckBiometrics && await _auth.isDeviceSupported();
    } catch (e) {
      return false;
    }
  }
  
  // Get available biometric types
  Future<List<BiometricType>> getAvailableBiometrics() async {
    return await _auth.getAvailableBiometrics();
  }
  
  // Authenticate with biometrics
  Future<bool> authenticate() async {
    try {
      return await _auth.authenticate(
        localizedReason: 'Xác thực để truy cập ứng dụng',
        authMessages: const <AuthMessages>[
          AndroidAuthMessages(
            signInTitle: 'Xác thực sinh trắc học',
            cancelButton: 'Hủy',
            biometricHint: 'Xác minh danh tính',
          ),
          IOSAuthMessages(
            cancelButton: 'Hủy',
          ),
        ],
        options: const AuthenticationOptions(
          stickyAuth: true, // Không tự động hủy khi chuyển app
          biometricOnly: true, // Chỉ dùng sinh trắc, không PIN
        ),
      );
    } catch (e) {
      return false;
    }
  }
}
```

**Tích hợp vào main.dart:**

```dart
// lib/main.dart - Thêm biometric check
import 'package:lnmq/services/biometric_service.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  await Firebase.initializeApp(
    options: DefaultFirebaseOptions.currentPlatform,
  );
  
  await FirebaseAppCheck.instance.activate(
    androidProvider: AndroidProvider.debug,
    appleProvider: AppleProvider.debug,
  );
  
  // Biometric authentication
  final biometricService = BiometricService();
  if (await biometricService.canUseBiometrics()) {
    final authenticated = await biometricService.authenticate();
    if (!authenticated) {
      // Exit app if biometric fails
      // (Tùy chọn: có thể cho phép fallback)
    }
  }
  
  runApp(const MyApp());
}
```

---

#### 1.3 ✅ Code Obfuscation (Bảo vệ mã nguồn)

**Tại sao:** Đáp ứng yêu cầu "Bảo vệ mã nguồn"

**Build APK với obfuscation:**

```powershell
# Windows PowerShell
flutter build apk --obfuscate --split-debug-info=build/debug-info/
```

**Cấu hình ProGuard** (Android):

```kotlin
// android/app/build.gradle.kts
android {
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
}
```

**ProGuard rules:**

```proguard
# android/app/proguard-rules.pro
-keepattributes *Annotation*
-dontwarn okhttp3.**
-keep class io.flutter.** { *; }
-keep class com.google.firebase.** { *; }
-keep class com.example.lnmq.** { *; }

# Obfuscate tất cả code ngoại trừ Flutter/Firebase
-repackageclasses ''
-allowaccessmodification
```

**Verify obfuscation:**

```powershell
# Decompile APK để kiểm tra
apktool d build/app/outputs/flutter-apk/app-release.apk
# → Class names sẽ là a.b.c thay vì com.example.lnmq.MainActivity
```

---

#### 1.4 ⚠️ SSL Pinning (Chống MITM)

**Tại sao:** Đảm bảo "Dữ liệu an toàn trên đường truyền"

```yaml
# pubspec.yaml
dependencies:
  http_certificate_pinning: ^2.0.3
```

```dart
// lib/services/ssl_pinning_service.dart
import 'package:http_certificate_pinning/http_certificate_pinning.dart';

class SSLPinningService {
  static Future<void> checkFirebaseCertificate() async {
    // Firebase/Google certificates (SHA-256 fingerprints)
    List<String> allowedFingerprints = [
      // Lấy từ: openssl s_client -connect firestore.googleapis.com:443 | openssl x509 -fingerprint -sha256
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

// Gọi trong main.dart TRƯỚC Firebase.initializeApp()
await SSLPinningService.checkFirebaseCertificate();
```

**Test MITM:**
1. Setup mitmproxy: `mitmproxy -p 8080`
2. Install cert vào device
3. Chạy app → Sẽ crash với error "SSL Pinning failed"

---

#### 1.5 ❌ End-to-End Encryption cho Chat

**Tại sao:** Đáp ứng yêu cầu "Mã hóa tin nhắn"

**⚠️ CẢNH BÁO:** Phức tạp, cần nhiều thời gian

```yaml
# pubspec.yaml
dependencies:
  encrypt: ^5.0.3
  pointycastle: ^3.9.1
```

```dart
// lib/services/encryption_service.dart
import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/asymmetric/api.dart';

class EncryptionService {
  // Generate RSA key pair for each user
  static AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateKeyPair() {
    final keyGen = RSAKeyGenerator()
      ..init(ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 12),
        FortunaRandom(),
      ));
    return keyGen.generateKeyPair();
  }
  
  // Encrypt message with recipient's public key
  static String encryptMessage(String plaintext, RSAPublicKey publicKey) {
    final encrypter = Encrypter(RSA(publicKey: publicKey));
    return encrypter.encrypt(plaintext).base64;
  }
  
  // Decrypt message with own private key
  static String decryptMessage(String ciphertext, RSAPrivateKey privateKey) {
    final encrypter = Encrypter(RSA(privateKey: privateKey));
    return encrypter.decrypt64(ciphertext);
  }
}
```

**Workflow:**
1. Mỗi user tạo RSA key pair khi đăng ký
2. Public key lưu trên Firestore
3. Private key lưu trong flutter_secure_storage (device only)
4. Gửi tin nhắn: Mã hóa bằng public key của người nhận
5. Nhận tin nhắn: Giải mã bằng private key của mình

**Lưu ý:** 
- Admin KHÔNG đọc được tin nhắn
- Nếu mất device → Mất tin nhắn (cần backup key)

---

### 🟡 PHASE 2: CẢI THIỆN BỔ SUNG (Nếu có thời gian)

#### 2.1 Root/Jailbreak Detection

```yaml
dependencies:
  flutter_jailbreak_detection: ^1.10.0
```

```dart
// lib/utils/security_check.dart
import 'package:flutter_jailbreak_detection/flutter_jailbreak_detection.dart';

class SecurityCheck {
  static Future<void> checkRootedDevice() async {
    final isJailbroken = await FlutterJailbreakDetection.jailbroken;
    if (isJailbroken) {
      throw Exception('Device is rooted/jailbroken. App cannot run.');
    }
  }
}

// Gọi trong main.dart
await SecurityCheck.checkRootedDevice();
```

#### 2.2 Anti-Debug Detection

```kotlin
// android/app/src/main/kotlin/com/example/lnmq/MainActivity.kt
import android.os.Debug

class MainActivity: FlutterActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Kill app if debugger detected
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            android.os.Process.killProcess(android.os.Process.myPid())
        }
    }
}
```

---

## 📊 CHECKLIST HOÀN THÀNH

### ✅ Cho báo cáo môn học (Tối thiểu)

- [ ] **Phone Authentication (OTP)** - Đáp ứng yêu cầu xác thực OTP
- [ ] **Local Authentication (Biometric)** - Đáp ứng sinh trắc học
- [ ] **Code Obfuscation** - Bảo vệ mã nguồn
- [ ] **Firebase App Check** ✅ - Đã có
- [ ] **Firestore Rules** ✅ - Đã có

### 🔶 Nâng cao (Tốt nếu có)

- [ ] **SSL Pinning** - Tăng cường bảo mật đường truyền
- [ ] **E2E Encryption cho Chat** - Mã hóa hoàn toàn tin nhắn
- [ ] **Root Detection** - Phát hiện device nguy hiểm
- [ ] **Anti-Debug** - Ngăn reverse engineering

---

## 🎯 KẾT LUẬN

**Điểm hiện tại:** 2.5/6 yêu cầu đạt

**Sau khi làm PHASE 1:**
- ✅ Mã hóa dữ liệu: Đạt
- ✅ Xác thực (OTP + Biometric) + Phân quyền: Đạt
- ✅ Chống SQL/XSS/Brute-force: Đạt
- ✅ An toàn đường truyền: Đạt (với SSL Pinning)
- ⚠️ Mã hóa tin nhắn: Đạt nếu làm E2EE (optional)
- ✅ Bảo vệ mã nguồn: Đạt (obfuscation)

**Điểm dự kiến:** 5.5-6/6 yêu cầu đạt ✅

---

## 📚 TÀI LIỆU THAM KHẢO

1. Firebase Phone Authentication: https://firebase.google.com/docs/auth/android/phone-auth
2. Flutter Local Auth: https://pub.dev/packages/local_auth
3. Code Obfuscation: https://docs.flutter.dev/deployment/obfuscate
4. SSL Pinning: https://pub.dev/packages/http_certificate_pinning
5. E2E Encryption: https://pub.dev/packages/encrypt

---

**Ưu tiên làm:** OTP + Biometric + Obfuscation (3 cái này nhanh nhất)

SSL Pinning + E2E Encryption làm nếu có thời gian!
