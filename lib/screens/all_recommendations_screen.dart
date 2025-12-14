import 'package:flutter/material.dart';
import 'package:lnmq/models/place_model.dart';
import 'package:lnmq/services/review_service.dart';
import 'package:lnmq/screens/place_detail_screen.dart';

class AllRecommendationsScreen extends StatefulWidget {
  final List<Place> places;
  
  const AllRecommendationsScreen({
    super.key,
    required this.places,
  });

  @override
  State<AllRecommendationsScreen> createState() => _AllRecommendationsScreenState();
}

class _AllRecommendationsScreenState extends State<AllRecommendationsScreen> {
  final ReviewService _reviewService = ReviewService();
  List<PlaceWithRating> _sortedPlaces = [];
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadAndSortPlaces();
  }

  Future<void> _loadAndSortPlaces() async {
    List<PlaceWithRating> placesWithRatings = [];
    
    for (Place place in widget.places) {
      try {
        // Lấy reviews cho từng địa điểm
        final reviews = await _reviewService.getReviewsForPlace(place.id).first;
        
        double avgRating = 0.0;
        int reviewCount = reviews.length;
        
        if (reviewCount > 0) {
          double totalRating = 0.0;
          for (var review in reviews) {
            totalRating += review.rating;
          }
          avgRating = totalRating / reviewCount;
        }
        
        placesWithRatings.add(PlaceWithRating(
          place: place,
          avgRating: avgRating,
          reviewCount: reviewCount,
        ));
      } catch (e) {
        // Nếu có lỗi, vẫn thêm địa điểm với rating 0
        placesWithRatings.add(PlaceWithRating(
          place: place,
          avgRating: 0.0,
          reviewCount: 0,
        ));
      }
    }
    
    // Sắp xếp theo rating từ cao xuống thấp, rồi theo số lượng review
    placesWithRatings.sort((a, b) {
      if (a.avgRating != b.avgRating) {
        return b.avgRating.compareTo(a.avgRating); // Rating cao hơn lên trước
      }
      return b.reviewCount.compareTo(a.reviewCount); // Nhiều review hơn lên trước
    });
    
    setState(() {
      _sortedPlaces = placesWithRatings;
      _isLoading = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.grey[50],
      appBar: AppBar(
        title: const Text(
          'Tất cả gợi ý',
          style: TextStyle(
            fontSize: 20,
            fontWeight: FontWeight.bold,
            color: Colors.black87,
          ),
        ),
        backgroundColor: Colors.white,
        foregroundColor: Colors.black87,
        elevation: 0.5,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => Navigator.pop(context),
        ),
      ),
      body: _isLoading
          ? const Center(
              child: CircularProgressIndicator(),
            )
          : ListView.builder(
              padding: const EdgeInsets.all(16),
              itemCount: _sortedPlaces.length,
              itemBuilder: (context, index) {
                final placeWithRating = _sortedPlaces[index];
                return _buildRecommendationCard(context, placeWithRating, index); // THÊM index vào đây
              },
            ),
    );
  }

  Widget _buildRecommendationCard(BuildContext context, PlaceWithRating placeWithRating, int index) { // THÊM parameter index
    final place = placeWithRating.place;
    final avgRating = placeWithRating.avgRating;
    final reviewCount = placeWithRating.reviewCount;
    
    return Container(
      margin: const EdgeInsets.only(bottom: 16),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(16),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.08),
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: () {
            Navigator.push(
              context,
              MaterialPageRoute(
                builder: (context) => PlaceDetailScreen(placeId: place.id),
              ),
            );
          },
          borderRadius: BorderRadius.circular(16),
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Row(
              children: [
                // Ảnh địa điểm
                ClipRRect(
                  borderRadius: BorderRadius.circular(12),
                  child: SizedBox(
                    width: 100,
                    height: 100,
                    child: Stack(
                      children: [
                        place.imageUrls.isNotEmpty
                            ? Image.network(
                                place.imageUrls[0],
                                fit: BoxFit.cover,
                                width: 100,
                                height: 100,
                                errorBuilder: (context, error, stackTrace) => Container(
                                  color: Colors.grey[300],
                                  child: const Icon(
                                    Icons.image,
                                    color: Colors.grey,
                                    size: 40,
                                  ),
                                ),
                              )
                            : Container(
                                color: Colors.grey[300],
                                child: const Icon(
                                  Icons.image,
                                  color: Colors.grey,
                                  size: 40,
                                ),
                              ),
                        
                        // Badge ranking nếu là top 3
                        if (index < 3)
                          Positioned(
                            top: 8,
                            left: 8,
                            child: Container(
                              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                              decoration: BoxDecoration(
                                color: index == 0 
                                    ? Colors.amber 
                                    : index == 1 
                                        ? Colors.grey[400] 
                                        : Colors.orange[300],
                                borderRadius: BorderRadius.circular(8),
                              ),
                              child: Text(
                                '#${index + 1}',
                                style: const TextStyle(
                                  fontSize: 10,
                                  fontWeight: FontWeight.bold,
                                  color: Colors.white,
                                ),
                              ),
                            ),
                          ),
                      ],
                    ),
                  ),
                ),
                
                const SizedBox(width: 16),
                
                // Thông tin địa điểm
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        place.name,
                        style: const TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                          color: Colors.black87,
                        ),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 6),
                      Row(
                        children: [
                          const Icon(Icons.location_on, size: 16, color: Colors.grey),
                          const SizedBox(width: 4),
                          Expanded(
                            child: Text(
                              place.location,
                              style: const TextStyle(
                                fontSize: 14,
                                color: Colors.grey,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      
                      // Rating và review count (dùng dữ liệu đã load)
                      if (reviewCount > 0)
                        Row(
                          children: [
                            const Icon(Icons.star, size: 16, color: Colors.amber),
                            const SizedBox(width: 4),
                            Text(
                              avgRating.toStringAsFixed(1),
                              style: const TextStyle(
                                fontSize: 14,
                                fontWeight: FontWeight.w500,
                                color: Colors.black87,
                              ),
                            ),
                            const SizedBox(width: 8),
                            Text(
                              '($reviewCount reviews)',
                              style: const TextStyle(
                                fontSize: 12,
                                color: Colors.grey,
                              ),
                            ),
                          ],
                        )
                      else
                        const Text(
                          'Chưa có đánh giá',
                          style: TextStyle(
                            fontSize: 12,
                            color: Colors.grey,
                          ),
                        ),
                      
                      const SizedBox(height: 8),
                      
                      // Giá tiền (nếu có)
                      if (place.formattedPriceRange.isNotEmpty)
                        Text(
                          place.formattedPriceRange,
                          style: const TextStyle(
                            fontSize: 14,
                            fontWeight: FontWeight.bold,
                            color: Colors.green,
                          ),
                        ),
                    ],
                  ),
                ),

              ],
            ),
          ),
        ),
      ),
    );
  }
}

// Helper class để lưu place với rating
class PlaceWithRating {
  final Place place;
  final double avgRating;
  final int reviewCount;

  PlaceWithRating({
    required this.place,
    required this.avgRating,
    required this.reviewCount,
  });
}