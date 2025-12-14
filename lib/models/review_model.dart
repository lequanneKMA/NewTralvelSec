// lib/models/review_model.dart
import 'package:cloud_firestore/cloud_firestore.dart';

class Review {
  final String id; // ID của review
  final String placeId; // ID của địa điểm được đánh giá
  final String userId;
  final String placeName; // ID của người dùng đánh giá
  final String userName; // Tên người dùng đánh giá
  final double rating; // Điểm đánh giá (ví dụ: 1.0 - 5.0)
  final String comment; // Bình luận
  final DateTime timestamp; // Thời gian đánh giá

  Review({
    required this.id,
    required this.placeId,
    required this.placeName,
    required this.userId,
    required this.userName,
    required this.rating,
    required this.comment,
    required this.timestamp,
  });

  // Constructor để tạo Review từ Firestore DocumentSnapshot
  factory Review.fromFirestore(DocumentSnapshot doc) {
    Map<String, dynamic> data = doc.data() as Map<String, dynamic>;
    return Review(
      id: doc.id,
      placeId: data['placeId'] ?? '',
      placeName: data['placeName'] ?? 'Unknown Place', // Đọc từ Firestore
      userId: data['userId'] ?? '', // Đọc từ Firestore
      userName: data['userName'] ?? 'Ẩn danh',
      rating: (data['rating'] as num?)?.toDouble() ?? 0.0,
      comment: data['comment'] ?? '',
      timestamp: (data['timestamp'] as Timestamp?)?.toDate() ?? DateTime.now(),
    );
  }

  // Phương thức để chuyển Review thành Map<String, dynamic> để lưu vào Firestore
  Map<String, dynamic> toFirestore() {
    return {
      'placeId': placeId,
      'placeName': placeName, // Thêm vào Map
      'userId': userId,       // Thêm vào Map
      'userName': userName,
      'rating': rating,
      'comment': comment,
      'timestamp': Timestamp.fromDate(timestamp),
    };
  }
}