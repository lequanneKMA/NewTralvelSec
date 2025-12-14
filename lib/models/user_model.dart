// lib/models/user_model.dart
import 'package:cloud_firestore/cloud_firestore.dart';

class AppUser { // Đổi tên class từ User thành AppUser để tránh xung đột với firebase_auth.User
  final String uid;
  final String email;
  final String? displayName;
  final String? photoUrl;
  final List<String> favoritePlaceIds; // <<< THÊM DÒNG NÀY
  final bool isAdmin;
  final DateTime createdAt;
  final DateTime? lastLoginAt;
  
  // Thông tin cá nhân mở rộng
  final String? phoneNumber;
  final String? address;
  final DateTime? birthdate;
  final String? gender;
  final String? emergencyContactName;
  final String? emergencyContactPhone;
  final String? nationalId;
  final String? occupation;
  final List<String>? travelPreferences;

  AppUser({
    required this.uid,
    required this.email,
    this.displayName,
    this.photoUrl,
    this.favoritePlaceIds = const [], // Khởi tạo mặc định là danh sách rỗng
    this.isAdmin = false,
    required this.createdAt,
    this.lastLoginAt,
    // Thông tin mở rộng
    this.phoneNumber,
    this.address,
    this.birthdate,
    this.gender,
    this.emergencyContactName,
    this.emergencyContactPhone,
    this.nationalId,
    this.occupation,
    this.travelPreferences,
  });

  // Constructor để tạo AppUser từ Firestore DocumentSnapshot
  factory AppUser.fromFirestore(DocumentSnapshot doc) {
    Map<String, dynamic> data = doc.data() as Map<String, dynamic>;
    return AppUser(
      uid: doc.id,
      email: data['email'] ?? '',
      displayName: data['displayName'],
      photoUrl: data['photoUrl'],
      favoritePlaceIds: List<String>.from(data['favoritePlaceIds'] ?? []), // Đọc danh sách ID
      isAdmin: data['isAdmin'] ?? false,
      createdAt: (data['createdAt'] as Timestamp?)?.toDate() ?? DateTime.now(),
      lastLoginAt: (data['lastLoginAt'] as Timestamp?)?.toDate(),
      // Thông tin mở rộng
      phoneNumber: data['phoneNumber'],
      address: data['address'],
      birthdate: (data['birthdate'] as Timestamp?)?.toDate(),
      gender: data['gender'],
      emergencyContactName: data['emergencyContactName'],
      emergencyContactPhone: data['emergencyContactPhone'],
      nationalId: data['nationalId'],
      occupation: data['occupation'],
      travelPreferences: data['travelPreferences'] != null 
          ? List<String>.from(data['travelPreferences']) 
          : null,
    );
  }

  // Phương thức để chuyển AppUser thành Map<String, dynamic> để lưu vào Firestore
  Map<String, dynamic> toFirestore() {
    return {
      'email': email,
      'displayName': displayName,
      'photoUrl': photoUrl,
      'favoritePlaceIds': favoritePlaceIds,
      'isAdmin': isAdmin,
      'createdAt': Timestamp.fromDate(createdAt),
      'lastLoginAt': lastLoginAt != null ? Timestamp.fromDate(lastLoginAt!) : null,
      // Thông tin mở rộng
      'phoneNumber': phoneNumber,
      'address': address,
      'birthdate': birthdate != null ? Timestamp.fromDate(birthdate!) : null,
      'gender': gender,
      'emergencyContactName': emergencyContactName,
      'emergencyContactPhone': emergencyContactPhone,
      'nationalId': nationalId,
      'occupation': occupation,
      'travelPreferences': travelPreferences,
    };
  }

  AppUser copyWith({
    String? email,
    String? displayName,
    String? photoUrl,
    List<String>? favoritePlaceIds,
    bool? isAdmin,
    DateTime? createdAt,
    DateTime? lastLoginAt,
    // Thông tin mở rộng
    String? phoneNumber,
    String? address,
    DateTime? birthdate,
    String? gender,
    String? emergencyContactName,
    String? emergencyContactPhone,
    String? nationalId,
    String? occupation,
    List<String>? travelPreferences,
  }) {
    return AppUser(
      uid: uid,
      email: email ?? this.email,
      displayName: displayName ?? this.displayName,
      photoUrl: photoUrl ?? this.photoUrl,
      favoritePlaceIds: favoritePlaceIds ?? this.favoritePlaceIds,
      isAdmin: isAdmin ?? this.isAdmin,
      createdAt: createdAt ?? this.createdAt,
      lastLoginAt: lastLoginAt ?? this.lastLoginAt,
      // Thông tin mở rộng
      phoneNumber: phoneNumber ?? this.phoneNumber,
      address: address ?? this.address,
      birthdate: birthdate ?? this.birthdate,
      gender: gender ?? this.gender,
      emergencyContactName: emergencyContactName ?? this.emergencyContactName,
      emergencyContactPhone: emergencyContactPhone ?? this.emergencyContactPhone,
      nationalId: nationalId ?? this.nationalId,
      occupation: occupation ?? this.occupation,
      travelPreferences: travelPreferences ?? this.travelPreferences,
    );
  }
}