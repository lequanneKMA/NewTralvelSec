// lib/models/place_model.dart
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:intl/intl.dart';

// Danh mục tập trung, chỉ cần sửa ở đây
const List<String> allCategories = [
  'Biển',
  'Núi',
  'Thành phố',
  'Rừng',
  'Di tích',
  'Ẩm thực',
  'Khác',
];

class Place {
  final String id;
  final String name;
  final String description;
  final List<String> imageUrls;
  final List<String> categories;
  final String location;
  final double rating;
  final String category;
  final int reviewCount;
  final String bestTimeToVisit;
  final int? minPrice;
  final int? maxPrice;

  final List<String> filterCategories = [
  'Phổ biến', 
  ...allCategories, 
];

  // Getter để format giá tiền
  String get formattedMinPrice {
    if (minPrice == null) return '';
    return NumberFormat('#,###', 'vi_VN').format(minPrice!);
  }

  String get formattedMaxPrice {
    if (maxPrice == null) return '';
    return NumberFormat('#,###', 'vi_VN').format(maxPrice!);
  }

  String get formattedPriceRange {
    if (minPrice != null && maxPrice != null) {
      return '${formattedMinPrice} - ${formattedMaxPrice} VNĐ';
    } else if (minPrice != null) {
      return 'Từ ${formattedMinPrice} VNĐ';
    } else if (maxPrice != null) {
      return 'Đến ${formattedMaxPrice} VNĐ';
    } else {
      return 'Không rõ';
    }
  }

  Place({
    required this.id,
    required this.name,
    required this.description,
    required this.imageUrls,
    required this.location,
    required this.category,
    this.rating = 0.0,
    this.reviewCount = 0,
    this.categories = const [],
    this.bestTimeToVisit = '',
    this.minPrice,
    this.maxPrice,
  });

  factory Place.fromFirestore(DocumentSnapshot doc) {
    Map data = doc.data() as Map<String, dynamic>;
    return Place(
      id: doc.id,
      name: data['name'] ?? '',
      description: data['description'] ?? '',
      imageUrls: List<String>.from(data['imageUrls'] ?? []),
      category: data['category'] ?? 'Khác',
      location: data['location'] ?? '',
      rating: (data['rating'] ?? 0.0).toDouble(),
      reviewCount: (data['reviewCount'] ?? 0).toInt(),
      categories: List<String>.from(data['categories'] ?? []),
      bestTimeToVisit: data['bestTimeToVisit'] ?? '',
      minPrice: data['minPrice'],
      maxPrice: data['maxPrice'],
    );
  }

  Map<String, dynamic> toFirestore() {
    return {
      'name': name,
      'description': description,
      'imageUrls': imageUrls,
      'location': location,
      'category': category,
      'rating': rating,
      'reviewCount': reviewCount,
      'categories': categories,
      'bestTimeToVisit': bestTimeToVisit,
      'minPrice': minPrice,
      'maxPrice': maxPrice,
    };
  }

  @override
  String toString() {
    return 'Place(id: $id, name: $name, location: $location, rating: $rating, minPrice: $minPrice, maxPrice: $maxPrice)';
  }
}