import 'package:flutter/material.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_app_check/firebase_app_check.dart';
import 'package:lnmq/firebase_options.dart';
import 'package:lnmq/screens/auth_screen.dart';
import 'package:lnmq/screens/home_screen.dart';
import 'package:lnmq/admin_screens/admin_home_screen.dart';
import 'package:lnmq/services/security_service.dart';
// import 'package:lnmq/utils/migrate_chat_data.dart'; // Sửa đường dẫn

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  // ==================== SECURITY CHECK ====================
  // Check device security (root detection)
  print('🔍 Checking device security...');
  final securityStatus = await SecurityService.checkDeviceSecurity();
  print('Device Security Status: $securityStatus');
  
  if (securityStatus['isRooted'] == true) {
    print('⚠️ WARNING: Device is rooted!');
    // Trong production, có thể exit app hoặc show warning
    // SystemNavigator.pop(); // Exit app
  }
  // ==================== END SECURITY CHECK ====================
  
  // Initialize Firebase
  await Firebase.initializeApp(
    options: DefaultFirebaseOptions.currentPlatform,
  );
  
  // ==================== FIREBASE APP CHECK ====================
  // Layer 1: Firebase App Check (basic protection)
  await FirebaseAppCheck.instance.activate(
    androidProvider: AndroidProvider.debug, // Dev only
    appleProvider: AppleProvider.debug,
  );
  print('🔒 Firebase App Check activated');
  // ==================== END APP CHECK ====================
  
  // THÊM: Chạy migration một lần khi app khởi động (optional)
  // Uncomment dòng này nếu muốn auto-migrate:
  // await runMigration();
  
  runApp(const MyApp());
}

// Future<void> runMigration() async {
//   try {
//     await migrateChatData();
//   } catch (e) {
//     print('Lỗi migration: $e');
//   }
// }

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Travel App Vietnam',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        fontFamily: 'BeVietnamPro',
        primarySwatch: Colors.blue,
        visualDensity: VisualDensity.adaptivePlatformDensity,
        appBarTheme: const AppBarTheme(
          backgroundColor: Colors.transparent,
          elevation: 0,
          iconTheme: IconThemeData(color: Colors.black87),
          titleTextStyle: TextStyle(color: Colors.black87, fontSize: 20, fontWeight: FontWeight.bold),
        ),
      ),
      home: StreamBuilder<User?>(
        stream: FirebaseAuth.instance.authStateChanges(),
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const Scaffold(body: Center(child: CircularProgressIndicator()));
          }

          if (snapshot.hasData) {
            final user = snapshot.data!;
            return FutureBuilder<DocumentSnapshot>(
              future: FirebaseFirestore.instance.collection('users').doc(user.uid).get(),
              builder: (context, userSnapshot) {
                if (userSnapshot.connectionState == ConnectionState.waiting) {
                  return const Scaffold(body: Center(child: CircularProgressIndicator()));
                }
                
                final data = userSnapshot.data?.data() as Map<String, dynamic>?;
                final isAdmin = data?['role'] == 'admin' || data?['isAdmin'] == true;
                
                return isAdmin ? const AdminHomeScreen() : const HomeScreen();
              },
            );
          }

          return const AuthScreen();
        },
      ),
    );
  }
}