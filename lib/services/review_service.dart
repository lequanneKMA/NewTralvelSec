// lib/services/review_service.dart
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart'; // Để lấy thông tin người dùng hiện tại
import 'package:lnmq/models/review_model.dart'; // Đảm bảo đúng 'lnmq'
import 'package:lnmq/models/place_model.dart'; // Đảm bảo đúng 'lnmq'

class ReviewService {
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;
  final FirebaseAuth _auth = FirebaseAuth.instance;

  static const String _reviewsCollection = 'reviews';
  static const String _placesCollection = 'places'; // Tên collection của địa điểm

  // 1. Thêm một đánh giá mới
  // CẬP NHẬT CHỮ KÝ HÀM ĐỂ NHẬN CÁC THAM SỐ CẦN THIẾT
  Future<void> addReview(String placeId, double rating, String comment) async {
    User? currentUser = _auth.currentUser;
    if (currentUser == null) {
      throw Exception("Bạn cần đăng nhập để gửi đánh giá.");
    }

    try {
      // Bắt đầu một batch write để đảm bảo cả review và place rating được cập nhật đồng thời
      WriteBatch batch = _firestore.batch();

      // Lấy thông tin tên địa điểm để lưu vào review
      final placeDoc = await _firestore.collection(_placesCollection).doc(placeId).get();
      if (!placeDoc.exists) {
        throw Exception("Địa điểm với ID $placeId không tồn tại.");
      }
      final placeName = placeDoc['name'] ?? 'Unknown Place';

      // Lấy tên người dùng hiện tại
      String userName = currentUser.displayName ?? currentUser.email ?? 'Ẩn danh';

      // Tạo đối tượng Review
      final newReview = Review(
        id: '', // Firestore sẽ tạo ID
        placeId: placeId,
        placeName: placeName, // Lưu tên địa điểm
        userId: currentUser.uid, // Lưu ID người dùng
        userName: userName,
        rating: rating,
        comment: comment,
        timestamp: DateTime.now(),
      );

      // Thêm review vào collection 'reviews'
      DocumentReference reviewRef = _firestore.collection(_reviewsCollection).doc();
      batch.set(reviewRef, newReview.toFirestore());

      // Cập nhật điểm đánh giá của địa điểm
      DocumentReference placeRef = _firestore.collection(_placesCollection).doc(placeId);
      DocumentSnapshot currentPlaceDoc = await placeRef.get();

      if (currentPlaceDoc.exists) {
        Place currentPlace = Place.fromFirestore(currentPlaceDoc);
        int newReviewCount = currentPlace.reviewCount + 1;
        // Tính tổng điểm đánh giá cũ và thêm điểm mới
        double oldTotalRating = currentPlace.rating * currentPlace.reviewCount;
        double newTotalRating = oldTotalRating + rating;
        double newAverageRating = newTotalRating / newReviewCount;

        batch.update(placeRef, {
          'rating': newAverageRating,
          'reviewCount': newReviewCount,
        });
      } else {
        throw Exception('Địa điểm với ID $placeId không tồn tại để cập nhật đánh giá.');
      }

      await batch.commit();
    } catch (e) {
      rethrow;
    }
  }

  // 2. Lấy tất cả các đánh giá cho một địa điểm cụ thể
  Stream<List<Review>> getReviewsForPlace(String placeId) {
    return _firestore
        .collection(_reviewsCollection)
        .where('placeId', isEqualTo: placeId)
        .orderBy('timestamp', descending: true) // Sắp xếp theo thời gian mới nhất
        .snapshots()
        .map((snapshot) {
      return snapshot.docs.map((doc) => Review.fromFirestore(doc)).toList();
    });
  }

  // 3. Lấy tất cả các đánh giá của một người dùng cụ thể
  Future<List<Review>> getReviewsForUser(String userId) async {
    try {
      final QuerySnapshot snapshot = await _firestore
          .collection(_reviewsCollection)
          .where('userId', isEqualTo: userId)
          .orderBy('timestamp', descending: true)
          .get(); // Sử dụng .get() vì đây là Future, không phải Stream

      return snapshot.docs.map((doc) => Review.fromFirestore(doc)).toList();
    } catch (e) {
      rethrow;
    }
  }

  // TODO: Có thể thêm các hàm updateReview, deleteReview sau này
}