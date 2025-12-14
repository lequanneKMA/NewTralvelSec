// lib/services/auth_service.dart
import 'package:firebase_auth/firebase_auth.dart';
import 'package:cloud_firestore/cloud_firestore.dart'; 
import 'package:lnmq/models/user_model.dart';
import 'package:google_sign_in/google_sign_in.dart';

class AuthService {
  final FirebaseAuth _firebaseAuth = FirebaseAuth.instance;
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;
  final GoogleSignIn _googleSignIn = GoogleSignIn();

  User? getCurrentUser() {
    return _firebaseAuth.currentUser;
  }

  // ĐĂNG XUẤT HOÀN TOÀN
  Future<void> signOut() async {
    try {
      // 1. Sign out Firebase Auth
      await _firebaseAuth.signOut();
      
      // 2. Sign out Google 
      await _googleSignIn.signOut();
      
      // 3. Disconnect Google account hoàn toàn
      await _googleSignIn.disconnect();
    } catch (e) {
      rethrow;
    }
  }

  // ĐĂNG NHẬP GOOGLE DUY NHẤT
  Future<User?> signInWithGoogle() async {
    try {
      // Đảm bảo signed out trước khi sign in
      await _googleSignIn.signOut();
      
      final GoogleSignInAccount? googleUser = await _googleSignIn.signIn();
      if (googleUser == null) return null; // User hủy đăng nhập

      final GoogleSignInAuthentication googleAuth = await googleUser.authentication;
      final credential = GoogleAuthProvider.credential(
        accessToken: googleAuth.accessToken,
        idToken: googleAuth.idToken,
      );

      UserCredential userCredential = await _firebaseAuth.signInWithCredential(credential);
      User? user = userCredential.user;

      // CHỈ CẬP NHẬT THÔNG TIN, KHÔNG TẠO MỚI
      if (user != null) {
        await _createOrUpdateUserDocument(user);
      }

      return user;
    } catch (e) {
      rethrow;
    }
  }

  // TẠO HOẶC CẬP NHẬT USER DOCUMENT
  Future<void> _createOrUpdateUserDocument(User user) async {
    try {
      final userDoc = await _firestore.collection('users').doc(user.uid).get();
      
      if (!userDoc.exists) {
        // Tạo mới user
        await _firestore.collection('users').doc(user.uid).set(AppUser(
          uid: user.uid,
          email: user.email ?? '',
          displayName: user.displayName ?? '',
          photoUrl: user.photoURL,
          favoritePlaceIds: [],
          createdAt: DateTime.now(),
          lastLoginAt: DateTime.now(),
        ).toFirestore());
      } else {
        // Cập nhật lastLoginAt cho user có sẵn
        await _firestore.collection('users').doc(user.uid).update({
          'lastLoginAt': FieldValue.serverTimestamp(),
        });
      }
    } catch (e) {
      rethrow;
    }
  }

  // CẬP NHẬT PROFILE
  Future<void> updateUserProfile({
    String? displayName,
    String? photoUrl,
  }) async {
    User? user = _firebaseAuth.currentUser;
    if (user != null) {
      if (displayName != null) {
        await user.updateDisplayName(displayName);
      }
      if (photoUrl != null) {
        await user.updatePhotoURL(photoUrl);
      }
      await user.reload();
    }
  }

  // KIỂM TRA ADMIN
  Future<bool> isAdmin() async {
    final user = _firebaseAuth.currentUser;
    if (user == null) return false;
    
    try {
      final doc = await _firestore.collection('users').doc(user.uid).get();
      return doc.data()?['role'] == 'admin' || doc.data()?['isAdmin'] == true;
    } catch (e) {
      return false;
    }
  }

  // AUTH STATE STREAM
  Stream<User?> get authStateChanges => _firebaseAuth.authStateChanges();
}