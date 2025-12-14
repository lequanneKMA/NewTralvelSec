import 'package:flutter/material.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:lnmq/services/auth_service.dart' as auth_service;
import 'package:lnmq/services/place_service.dart';
import 'package:lnmq/models/place_model.dart';
import 'package:lnmq/models/review_model.dart';
import 'package:lnmq/screens/favorite_places_screen.dart';
import 'package:lnmq/screens/profile_screen.dart';
import 'package:lnmq/screens/search_screen.dart';
import 'package:lnmq/screens/book_tour_screen.dart';
import 'package:lnmq/screens/place_detail_screen.dart';
import 'package:lnmq/services/review_service.dart';
import 'package:lnmq/screens/all_recommendations_screen.dart'; // Import màn hình xem tất cả gợi ý

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final auth_service.AuthService _authService = auth_service.AuthService();
  final PlaceService _placeService = PlaceService();
  final ReviewService _reviewService = ReviewService();
  int _selectedIndex = 0;
  int _selectedCategoryIndex = 0; // Khai báo biến danh mục

  // Danh sách các danh mục để lọc địa điểm
  final List<String> filterCategories = [
    'Phổ biến',
    'Biển',
    'Núi',
    'Thành phố',
    'Rừng',
    'Di tích',
    'Ẩm thực',
    'Khác',
  ];
  Widget _homeTabContent() {
    return StreamBuilder<List<Place>>(
      stream: _placeService.getPlaces(),
      builder: (context, snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting) {
          return const Center(child: CircularProgressIndicator());
        }
        if (snapshot.hasError) {
          return Center(child: Text('Lỗi tải dữ liệu: ${snapshot.error}'));
        }
        if (!snapshot.hasData || snapshot.data!.isEmpty) {
          return const Center(child: Text('Chưa có địa điểm nào được thêm.'));
        }
        final places = snapshot.data!;

        // Đặt đoạn lọc này ở đây
        List<Place> filteredPlaces = _selectedCategoryIndex == 0
            ? places // "Phổ biến" => không lọc
            : places.where((place) =>
                place.category == filterCategories[_selectedCategoryIndex] ||
                place.categories.contains(filterCategories[_selectedCategoryIndex])
              ).toList();

        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [            // Phần 1: Danh sách địa điểm lướt ngang
            SizedBox(
              height: 160, // Tăng chiều cao
              child: ListView.builder(
                scrollDirection: Axis.horizontal,
                padding: const EdgeInsets.symmetric(horizontal: 16),
                itemCount: filteredPlaces.length,
                itemBuilder: (context, index) {
                  final place = filteredPlaces[index];
                  return GestureDetector(
                    onTap: () {
                      // Navigate to PlaceDetailScreen
                      Navigator.push(
                        context,
                        MaterialPageRoute(
                          builder: (context) => PlaceDetailScreen(placeId: place.id),
                        ),
                      );
                    },
                    child: Container(
                      margin: EdgeInsets.only(right: index == filteredPlaces.length - 1 ? 0 : 16),
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(20),
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black.withOpacity(0.15), // Thêm shadow cho thẻ địa điểm
                            blurRadius: 15,
                            offset: const Offset(0, 5),
                            spreadRadius: 0,
                          ),
                        ],
                      ),
                      child: ClipRRect(
                        borderRadius: BorderRadius.circular(20),
                        child: SizedBox(
                          width: 280, // Tăng chiều rộng
                          height: 160, // Tăng chiều cao
                          child: Stack(
                            children: [
                              // Ảnh nền
                              Positioned.fill(
                                child: Image.network(
                                  place.imageUrls.isNotEmpty ? place.imageUrls[0] : '',
                                  fit: BoxFit.cover,
                                  errorBuilder: (context, error, stackTrace) => Container(
                                    color: Colors.grey[300],
                                    child: const Icon(Icons.image, color: Colors.grey, size: 40),
                                  ),
                                ),
                              ),
                              // Badge vị trí góc trên phải
                              Positioned(
                                top: 12,
                                right: 12,
                                child: Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                                  decoration: BoxDecoration(
                                    color: Colors.white.withOpacity(0.92),
                                    borderRadius: BorderRadius.circular(12),
                                  ),
                                  child: Row(
                                    mainAxisSize: MainAxisSize.min,
                                    children: [
                                      const Icon(Icons.location_on, color: Colors.black87, size: 14),
                                      const SizedBox(width: 2),
                                      Text(
                                        place.location,
                                        style: const TextStyle(
                                          fontSize: 12,
                                          color: Colors.black87,
                                          fontWeight: FontWeight.w500,
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                              // Gradient overlay phía dưới
                              Positioned(
                                left: 0,
                                right: 0,
                                bottom: 0,
                                height: 40,
                                child: Container(
                                  decoration: BoxDecoration(
                                    gradient: LinearGradient(
                                      begin: Alignment.topCenter,
                                      end: Alignment.bottomCenter,
                                      colors: [
                                        Colors.transparent,
                                        Colors.black.withOpacity(0.7),
                                      ],
                                    ),
                                  ),
                                ),
                              ),
                              // Tên địa điểm
                              Positioned(
                                left: 12,
                                bottom: 12,
                                right: 12,
                                child: Text(
                                  place.name,
                                  style: const TextStyle(
                                    color: Colors.white,
                                    fontWeight: FontWeight.bold,
                                    fontSize: 16,
                                    shadows: [
                                      Shadow(
                                        offset: Offset(0.5, 0.5),
                                        blurRadius: 2,
                                        color: Colors.black87,
                                      ),
                                    ],
                                  ),
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                            ], // Đóng children của Stack
                          ), // Đóng Stack
                        ), // Đóng SizedBox
                      ), // Đóng ClipRRect
                    ),
                  );
                },
              ),
            ),
            
            const SizedBox(height: 24),
            
            // Phần 2: Section Recommendation với rating và review count
            if (places.isNotEmpty)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: Column(
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        const Text(
                          'Gợi ý cho bạn',
                          style: TextStyle(
                            fontSize: 20,
                            fontWeight: FontWeight.bold,
                            color: Colors.black87,
                          ),
                        ),
                        TextButton(
                          onPressed: () {
                            // Navigate to see all recommendations - THÊM TÍNH NĂNG NÀY
                            Navigator.push(
                              context,
                              MaterialPageRoute(
                                builder: (context) => AllRecommendationsScreen(places: places),
                              ),
                            );
                          },
                          child: const Text(
                            'Xem thêm',
                            style: TextStyle(
                              fontSize: 14,
                              color: Colors.blue,
                              fontWeight: FontWeight.w500,
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    
                    // Single recommendation item với rating và review count từ ReviewService
                    StreamBuilder<List<Review>>(
                      stream: _reviewService.getReviewsForPlace(places.first.id),
                      builder: (context, reviewSnapshot) {
                        // Tính toán rating và review count
                        double rating = 0.0;
                        int reviewCount = 0;
                        
                        if (reviewSnapshot.hasData && reviewSnapshot.data!.isNotEmpty) {
                          final reviews = reviewSnapshot.data!;
                          reviewCount = reviews.length;
                          double totalRating = 0.0;
                          for (var review in reviews) {
                            totalRating += review.rating;
                          }
                          rating = totalRating / reviewCount;
                        }
                        
                        final place = places.first;
                        
                        return GestureDetector(
                          onTap: () {
                            Navigator.push(
                              context,
                              MaterialPageRoute(
                                builder: (context) => PlaceDetailScreen(placeId: place.id),
                              ),
                            );
                          },
                          child: Container(
                            padding: const EdgeInsets.all(12),
                            decoration: BoxDecoration(
                              color: Colors.white,
                              borderRadius: BorderRadius.circular(12),
                              boxShadow: [
                                BoxShadow(
                                  color: Colors.black.withOpacity(0.12), // Tăng shadow cho thẻ gợi ý
                                  blurRadius: 12,
                                  offset: const Offset(0, 4),
                                  spreadRadius: 0,
                                ),
                              ],
                            ),
                            child: Row(
                              children: [
                                // Ảnh nhỏ bên trái
                                ClipRRect(
                                  borderRadius: BorderRadius.circular(10),
                                  child: SizedBox(
                                    width: 80,
                                    height: 80,
                                    child: place.imageUrls.isNotEmpty
                                        ? Image.network(
                                            place.imageUrls[0],
                                            fit: BoxFit.cover,
                                            errorBuilder: (context, error, stackTrace) => Container(
                                              color: Colors.grey[300],
                                              child: const Icon(Icons.image, color: Colors.grey, size: 30),
                                            ),
                                          )
                                        : Container(
                                            color: Colors.grey[300],
                                            child: const Icon(Icons.image, color: Colors.grey, size: 30),
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
                                        maxLines: 1,
                                        overflow: TextOverflow.ellipsis,
                                      ),
                                      const SizedBox(height: 4),
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
                                      
                                      // Rating và review count từ ReviewService
                                      if (reviewSnapshot.connectionState == ConnectionState.waiting)
                                        const Row(
                                          children: [
                                            SizedBox(
                                              width: 12,
                                              height: 12,
                                              child: CircularProgressIndicator(strokeWidth: 2),
                                            ),
                                            SizedBox(width: 8),
                                            Text(
                                              'Đang tải...',
                                              style: TextStyle(fontSize: 12, color: Colors.grey),
                                            ),
                                          ],
                                        )
                                      else if (reviewCount > 0)
                                        Row(
                                          children: [
                                            const Icon(Icons.star, size: 16, color: Colors.amber),
                                            const SizedBox(width: 4),
                                            Text(
                                              rating.toStringAsFixed(1),
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
                                    ],
                                  ),
                                ),
  
                              ],
                            ),
                          ),
                        );
                      },
                    ),
                  ],
                ),
              ),
          ],
        );
      },
    );
  }

  Widget _getTabContent() {
    switch (_selectedIndex) {
      case 0:
        return _homeTabContent(); // Trang chủ, luôn build lại khi setState
      case 1:
        return const FavoritePlacesScreen();
      case 2:
        return const BookTourScreen();
      case 3:
        return const ProfileScreen();
      default:
        return _homeTabContent();
    }
  }

  // Tách riêng AppBar cho trang chủ
  Widget _buildHomeAppBar() {
    User? currentUser = _authService.getCurrentUser();
    String? userEmail = currentUser?.email;
    String displayName = currentUser?.displayName ?? userEmail?.split('@')[0] ?? 'Khách';
    String? photoUrl = currentUser?.photoURL;

    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 24, 16, 0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Chữ nhỏ: "Hello, Vanessa"
                    Text(
                      'Chào, $displayName',
                      style: const TextStyle(
                        fontSize: 15, // nhỏ lại
                        fontWeight: FontWeight.w300,
                        color: Colors.black54,
                        letterSpacing: 0.1,
                      ),
                    ),
                    
                    // Chữ lớn: "Welcome to TripGlide"
                    Text(
                      'Bạn muốn đi đâu ?',
                      style: const TextStyle(
                        fontSize: 30, // to lên
                        fontWeight: FontWeight.bold,
                        color: Colors.black,
                      ),
                    ),
                  ],
                ),
              ),
              GestureDetector(
                onTap: () {
                  setState(() {
                    _selectedIndex = 3;
                  });
                },
                child: CircleAvatar(
                  radius: 24,
                  backgroundColor: Colors.grey[300],
                  backgroundImage: photoUrl != null ? NetworkImage(photoUrl) : null,
                  child: photoUrl == null
                      ? const Icon(Icons.person, color: Colors.white, size: 28)
                      : null,
                ),
              ),
            ],
          ),
          const SizedBox(height: 24),
          Row(
            children: [
              Expanded(
                child: GestureDetector(
                  onTap: () {
                    Navigator.push(
                      context,
                      MaterialPageRoute(builder: (context) => const SearchScreen()),
                    );
                  },
                  child: Container(
                    height: 48,
                    padding: const EdgeInsets.symmetric(horizontal: 16),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(16),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withOpacity(0.15), // Tăng độ đậm shadow
                          blurRadius: 12, // Tăng blur
                          offset: const Offset(0, 4), // Tăng offset
                          spreadRadius: 0,
                        ),
                      ],
                    ),
                    child: Row(
                      children: const [
                        Icon(Icons.search, color: Colors.grey, size: 26),
                        SizedBox(width: 10),
                        Text(
                          'Tìm kiếm địa điểm',
                          style: TextStyle(color: Colors.grey, fontSize: 16),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 12),
            ],
          ),
          const SizedBox(height: 16),
          // Thanh chọn danh mục
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: List.generate(filterCategories.length, (index) {
                final bool isSelected = _selectedCategoryIndex == index;
                return Padding(
                  padding: EdgeInsets.only(right: 8),
                  child: GestureDetector(
                    onTap: () {
                      setState(() {
                        _selectedCategoryIndex = index;
                      });
                    },
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 10),
                      decoration: BoxDecoration(
                        color: isSelected ? Colors.redAccent : Colors.white,
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(
                          color: isSelected ? Colors.redAccent : Colors.grey.shade300,
                          width: 1,
                        ),
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black.withOpacity(0.12), // Thêm shadow cho thẻ danh mục
                            blurRadius: 8,
                            offset: const Offset(0, 3),
                            spreadRadius: 0,
                          ),
                        ],
                      ),
                      child: Row(
                        children: [
                          Icon(
                            // Đặt icon phù hợp từng danh mục nếu muốn
                            index == 0
                                ? Icons.local_fire_department
                                : index == 1
                                    ? Icons.beach_access
                                    : index == 2
                                        ? Icons.terrain
                                        : index == 3
                                            ? Icons.location_city
                                            : index == 4
                                                ? Icons.forest
                                                : index == 5
                                                    ? Icons.account_balance
                                                    : index == 6
                                                        ? Icons.restaurant
                                                        : Icons.category,
                            color: isSelected ? Colors.white : Colors.grey,
                            size: 18,
                          ),
                          const SizedBox(width: 6),
                          Text(
                            filterCategories[index],
                            style: TextStyle(
                              color: isSelected ? Colors.white : Colors.grey[700],
                              fontWeight: FontWeight.w500,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                );
              }),
            ),
          ),
          const SizedBox(height: 16),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF7F7F7),
      body: SafeArea(
        child: Column(
          children: [
            // Chỉ hiển thị AppBar tùy chỉnh khi đang ở trang chủ (index 0)
            if (_selectedIndex == 0) _buildHomeAppBar(),
            Expanded(
              child: _getTabContent(),
            ),
          ],
        ),
      ),
      bottomNavigationBar: BottomNavigationBar(
        items: [
          BottomNavigationBarItem(
            icon: Icon(Icons.home),
            activeIcon: Icon(Icons.home, color: Colors.blueAccent),
            label: 'Trang chủ',
          ), 
          BottomNavigationBarItem(
            icon: Icon(Icons.favorite),
            activeIcon: Icon(Icons.favorite),
            label: 'Yêu thích',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.card_travel),
            activeIcon: Icon(Icons.card_travel, color: Colors.blueAccent),
            label: 'Đặt tour',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.person),
            activeIcon: Icon(Icons.person, color: Colors.blueAccent),
            label: 'Cá nhân',
          ),
        ],
        currentIndex: _selectedIndex,
        selectedItemColor: Colors.blueAccent,
        unselectedItemColor: Colors.grey,
        onTap: (index) {
          setState(() {
            _selectedIndex = index;
          });
        },
        backgroundColor: Colors.white,
        elevation: 10,
        type: BottomNavigationBarType.fixed,
      ),
    );
  }
}