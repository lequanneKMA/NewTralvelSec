// lib/widgets/place_card.dart
import 'package:flutter/material.dart';
import 'package:lnmq/models/place_model.dart';
import 'package:lnmq/screens/place_detail_screen.dart'; // <<< THÊM DÒNG NÀY

class PlaceCard extends StatelessWidget {
  final Place place;

  const PlaceCard({super.key, required this.place});

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.symmetric(vertical: 8.0),
      elevation: 4.0,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(15.0)),
      child: InkWell( // Sử dụng InkWell để tạo hiệu ứng khi nhấn
        onTap: () {
          // BỎ COMMENT DÒNG NÀY VÀ ĐẢM BẢO PLACE_DETAIL_SCREEN ĐƯỢC IMPORT
          Navigator.of(context).push(
            MaterialPageRoute(
              builder: (context) => PlaceDetailScreen(placeId: place.id), // Truyền place.id
            ),
          );
         
        },
        borderRadius: BorderRadius.circular(15.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            ClipRRect(
              borderRadius: const BorderRadius.vertical(top: Radius.circular(15.0)),
              child: Image.network(
                place.imageUrls.isNotEmpty ? place.imageUrls[0] : 'https://via.placeholder.com/150', // Sử dụng hình ảnh đầu tiên hoặc placeholder
                height: 200,
                width: double.infinity,
                fit: BoxFit.cover,
                loadingBuilder: (context, child, loadingProgress) {
                  if (loadingProgress == null) return child;
                  return Container(
                    height: 200,
                    width: double.infinity,
                    color: Colors.grey[300],
                    child: Center(
                      child: CircularProgressIndicator(
                        value: loadingProgress.expectedTotalBytes != null
                            ? loadingProgress.cumulativeBytesLoaded / loadingProgress.expectedTotalBytes!
                            : null,
                      ),
                    ),
                  );
                },
                errorBuilder: (context, error, stackTrace) {
                  return Container(
                    height: 200,
                    width: double.infinity,
                    color: Colors.grey[300],
                    child: const Icon(Icons.broken_image, size: 50, color: Colors.grey),
                    alignment: Alignment.center,
                  );
                },
              ),
            ),
            Padding(
              padding: const EdgeInsets.all(12.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    place.name,
                    style: const TextStyle(
                      fontSize: 20,
                      fontWeight: FontWeight.bold,
                      color: Colors.black87,
                    ),
                  ),
                  const SizedBox(height: 8.0),
                  Row(
                    children: [
                      Icon(Icons.location_on, size: 16, color: Colors.grey[600]),
                      const SizedBox(width: 4),
                      Text(
                        place.location,
                        style: TextStyle(fontSize: 14, color: Colors.grey[700]),
                      ),
                      const Spacer(),
                      Icon(Icons.star, size: 16, color: Colors.amber),
                      Text(
                        '${place.rating.toStringAsFixed(1)} (${place.reviewCount})',
                        style: TextStyle(fontSize: 14, color: Colors.grey[700]),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8.0),
                  Text(
                    place.description,
                    maxLines: 2, // Giới hạn mô tả chỉ 2 dòng
                    overflow: TextOverflow.ellipsis, // Hiển thị ... nếu quá dài
                    style: TextStyle(fontSize: 14, color: Colors.grey[600]),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}