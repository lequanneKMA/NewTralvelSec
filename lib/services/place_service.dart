// lib/services/place_service.dart
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:lnmq/models/place_model.dart'; // Import Place model

class PlaceService {
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;

  static const String _placesCollection = 'places';

  // 1. Thêm một địa điểm mới vào Firestore
  Future<void> addPlace(Place place) async {
    try {
      // Sử dụng add để Firestore tự tạo ID tài liệu
      await _firestore.collection(_placesCollection).add(place.toFirestore());
    } catch (e) {
      rethrow; // Ném lại lỗi để xử lý ở UI
    }
  }

  // 2. Lấy tất cả các địa điểm từ Firestore (Real-time updates)
  Stream<List<Place>> getPlaces() {
    return _firestore.collection(_placesCollection).snapshots().map((snapshot) {
      return snapshot.docs.map((doc) => Place.fromFirestore(doc)).toList();
    });
  }

  // 3. Lấy một địa điểm theo ID
  Future<Place?> getPlaceById(String placeId) async {
    try {
      DocumentSnapshot doc = await _firestore.collection(_placesCollection).doc(placeId).get();
      if (doc.exists) {
        return Place.fromFirestore(doc);
      } else {
        return null;
      }
    } catch (e) {
      rethrow;
    }
  }

  // 4. Cập nhật thông tin của một địa điểm
  Future<void> updatePlace(Place place) async {
    try {
      await _firestore.collection(_placesCollection).doc(place.id).update(place.toFirestore());
    } catch (e) {
      rethrow;
    }
  }

  // 5. Xóa một địa điểm
  Future<void> deletePlace(String placeId) async {
    try {
      await _firestore.collection(_placesCollection).doc(placeId).delete();
    } catch (e) {
      rethrow;
    }
  }


// 6. Lấy nhiều địa điểm theo danh sách ID
  Future<List<Place>> getPlacesByIds(List<String> placeIds) async {
    if (placeIds.isEmpty) {
      return [];
    }
    try {
      // Firestore cho phép truy vấn 'whereIn' tối đa 10 ID
      // Nếu có nhiều hơn 10 ID, bạn sẽ cần chia nhỏ truy vấn hoặc xử lý khác
      // Với số lượng nhỏ, whereIn là đủ
      final QuerySnapshot snapshot = await _firestore
          .collection(_placesCollection)
          .where(FieldPath.documentId, whereIn: placeIds)
          .get();

      return snapshot.docs.map((doc) => Place.fromFirestore(doc)).toList();
    } catch (e) {
      rethrow;
    }
  }
  // 7. Tìm kiếm địa điểm theo tên
  Stream<List<Place>> searchPlaces(String query) {
    if (query.isEmpty) {
      // Nếu query rỗng, trả về tất cả địa điểm (hoặc rỗng tùy ý)
      return getPlaces(); // Hoặc Stream.value([]) nếu bạn muốn rỗng
    }
    final String lowerCaseQuery = query.toLowerCase();

    return _firestore
        .collection(_placesCollection)
        .where('name', isGreaterThanOrEqualTo: query)
        .where('name', isLessThanOrEqualTo: '${query}\uf8ff')
        .orderBy('name') // Cần orderBy trên trường bạn đang filter
        .snapshots()
        .map((snapshot) {
      final List<Place> allPlaces = snapshot.docs.map((doc) => Place.fromFirestore(doc)).toList();
      return allPlaces.where((place) =>
          place.name.toLowerCase().contains(lowerCaseQuery) || // Tìm trong tên
          place.description.toLowerCase().contains(lowerCaseQuery) // Tìm trong mô tả
      ).toList();
    });
  }

}
  