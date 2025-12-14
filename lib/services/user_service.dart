import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:lnmq/models/user_model.dart';

class UserService {
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;
  final FirebaseAuth _auth = FirebaseAuth.instance;

  static const String _usersCollection = 'users';

  // Lấy thông tin người dùng từ Firestore (Real-time updates)
  Stream<AppUser?> getUserData(String uid) {
    return _firestore.collection(_usersCollection).doc(uid).snapshots().map((doc) {
      if (doc.exists) {
        return AppUser.fromFirestore(doc);
      }
      return null;
    });
  }

  // Stream<AppUser?> của user hiện tại (real-time)
  Stream<AppUser?> getCurrentUserStream() {
    return _auth.authStateChanges().asyncExpand((user) {
      if (user == null) return Stream.value(null);
      return getUserData(user.uid);
    });
  }

  // Cập nhật thông tin người dùng (ví dụ: thêm/xóa địa điểm yêu thích)
  Future<void> updateUserData(String uid, Map<String, dynamic> data) async {
    try {
      await _firestore.collection(_usersCollection).doc(uid).update(data);
    } catch (e) {
      rethrow;
    }
  }

  // Thêm địa điểm vào danh sách yêu thích
  Future<void> addFavoritePlace(String placeId) async {
    User? currentUser = _auth.currentUser;
    if (currentUser == null) {
      throw Exception("Người dùng chưa đăng nhập.");
    }
    try {
      await _firestore.collection(_usersCollection).doc(currentUser.uid).update({
        'favoritePlaceIds': FieldValue.arrayUnion([placeId]),
      });
    } catch (e) {
      rethrow;
    }
  }

  // Xóa địa điểm khỏi danh sách yêu thích
  Future<void> removeFavoritePlace(String placeId) async {
    User? currentUser = _auth.currentUser;
    if (currentUser == null) {
      throw Exception("Người dùng chưa đăng nhập.");
    }
    try {
      await _firestore.collection(_usersCollection).doc(currentUser.uid).update({
        'favoritePlaceIds': FieldValue.arrayRemove([placeId]),
      });
    } catch (e) {
      rethrow;
    }
  }

  // Kiểm tra xem địa điểm có trong danh sách yêu thích của người dùng không
  Future<bool> isPlaceFavorite(String placeId) async {
    User? currentUser = _auth.currentUser;
    if (currentUser == null) {
      return false;
    }
    try {
      DocumentSnapshot userDoc = await _firestore.collection(_usersCollection).doc(currentUser.uid).get();
      if (userDoc.exists) {
        AppUser appUser = AppUser.fromFirestore(userDoc);
        return appUser.favoritePlaceIds.contains(placeId);
      }
      return false;
    } catch (e) {
      return false;
    }
  }

  // Cập nhật profile với thông tin chi tiết
  Future<void> updateUserProfile({
    String? displayName,
    String? phoneNumber,
    String? address,
    DateTime? birthdate,
    String? gender,
    String? emergencyContactName,
    String? emergencyContactPhone,
    String? nationalId,
    String? occupation,
    List<String>? travelPreferences,
    String? photoUrl,
  }) async {
    User? currentUser = _auth.currentUser;
    if (currentUser == null) return;

    Map<String, dynamic> updateData = {};
    
    if (displayName != null) updateData['displayName'] = displayName;
    if (phoneNumber != null) updateData['phoneNumber'] = phoneNumber;
    if (address != null) updateData['address'] = address;
    if (birthdate != null) updateData['birthdate'] = Timestamp.fromDate(birthdate);
    if (gender != null) updateData['gender'] = gender;
    if (emergencyContactName != null) updateData['emergencyContactName'] = emergencyContactName;
    if (emergencyContactPhone != null) updateData['emergencyContactPhone'] = emergencyContactPhone;
    if (nationalId != null) updateData['nationalId'] = nationalId;
    if (occupation != null) updateData['occupation'] = occupation;
    if (travelPreferences != null) updateData['travelPreferences'] = travelPreferences;
    if (photoUrl != null) updateData['photoUrl'] = photoUrl;

    // Thêm timestamp cập nhật
    updateData['updatedAt'] = FieldValue.serverTimestamp();

    await _firestore
        .collection(_usersCollection)
        .doc(currentUser.uid)
        .update(updateData);
  }

  // Method để tạo user document nếu chưa tồn tại
  Future<void> createUserDocument(String uid, {
    required String email,
    String? displayName,
    String? photoUrl,
  }) async {
    await _firestore.collection(_usersCollection).doc(uid).set({
      'email': email,
      'displayName': displayName,
      'photoUrl': photoUrl,
      'favoritePlaceIds': [],
      'isAdmin': false,
      'createdAt': FieldValue.serverTimestamp(),
      'lastLoginAt': FieldValue.serverTimestamp(),
    });
  }

  // Method để update last login
  Future<void> updateLastLogin(String uid) async {
    await _firestore.collection(_usersCollection).doc(uid).update({
      'lastLoginAt': FieldValue.serverTimestamp(),
    });
  }

  // Method để toggle favorite place (dùng cách mới)
  Future<void> toggleFavoritePlace(String placeId) async {
    User? currentUser = _auth.currentUser;
    if (currentUser == null) return;

    // Kiểm tra xem có phải favorite không
    bool isFavorite = await isPlaceFavorite(placeId);
    
    if (isFavorite) {
      await removeFavoritePlace(placeId);
    } else {
      await addFavoritePlace(placeId);
    }
  }

  // Method để kiểm tra user có phải admin không
  Future<bool> isAdmin(String uid) async {
    DocumentSnapshot doc = await _firestore.collection(_usersCollection).doc(uid).get();
    if (doc.exists) {
      return doc.get('isAdmin') ?? false;
    }
    return false;
  }
}