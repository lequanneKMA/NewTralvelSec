import 'package:flutter/material.dart';
import 'package:lnmq/services/auth_service.dart';
import 'package:cloud_firestore/cloud_firestore.dart';

class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  final AuthService _authService = AuthService();
  bool _isLoading = false;

  void _signInWithGoogle() async {
    setState(() => _isLoading = true);
    try {
      final user = await _authService.signInWithGoogle();
      if (user != null) {
        // Đảm bảo user đã có document trên Firestore
        final userRef = FirebaseFirestore.instance.collection('users').doc(user.uid);
        final doc = await userRef.get();

        // Nếu chưa có, tạo mới với role mặc định là user
        if (!doc.exists) {
          await userRef.set({
            'email': user.email,
            'displayName': user.displayName,
            'role': 'user', // hoặc 'admin' nếu bạn muốn test
            'createdAt': FieldValue.serverTimestamp(),
          });
        }

        // Không cần điều hướng thủ công, StreamBuilder trong main.dart sẽ tự động xử lý
        // khi authStateChanges được trigger
      }
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Lỗi đăng nhập Google: $e')),
      );
    } finally {
  if (mounted) setState(() => _isLoading = false);
}
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.white,
      body: Stack(
        children: [
          // Background image
          Positioned.fill(
            child: Image.asset(
              'assets/images/auth_background.jpg',
              fit: BoxFit.cover,
            ),
          ),
          // Nội dung đăng nhập
          SafeArea(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 32), // Tăng padding ngang
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.center, // Căn giữa nội dung
                children: [
                  const SizedBox(height: 60),
                  Image.asset(
                    'assets/images/app_logo.png',
                    height: 150,
                  ),
                  const SizedBox(height: 60),
                  const Text(
                    'VIỆT NAM TRAVEL',
                    style: TextStyle(
                      fontSize: 30,
                      fontWeight: FontWeight.bold,
                      color: Color.fromARGB(255, 2, 103, 255),
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 20),
                  const Text(
                    'Khám phá và trải nghiệm du lịch Việt Nam dễ dàng hơn bao giờ hết!',
                    style: TextStyle(
                      fontSize: 16,
                      color: Colors.black87,
                      fontWeight: FontWeight.w600,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const Spacer(),
                  Padding(
                    padding: const EdgeInsets.only(bottom: 40),
                    child: _isLoading
                        ? const CircularProgressIndicator()
                        : ElevatedButton.icon(
                            icon: Image.asset('assets/icons/google.png', height: 24),
                            label: const Text('Đăng nhập với Google'),
                            style: ElevatedButton.styleFrom(
                              backgroundColor: Colors.white,
                              foregroundColor: Colors.black87,
                              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
                              textStyle: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                              elevation: 2,
                              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                              side: const BorderSide(color: Colors.blueAccent),
                            ),
                            onPressed: _signInWithGoogle,
                          ),
                  ),
                  const SizedBox(height: 12),
                  const Text(
                    '© 2025 LNMQ Travel',
                    style: TextStyle(fontSize: 14, color: Colors.grey),
                  ),
                  const SizedBox(height: 8),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}