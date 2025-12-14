import 'dart:io';
import 'package:flutter/material.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:image_picker/image_picker.dart';
import 'package:lnmq/models/place_model.dart';
import 'package:lnmq/services/storage_service.dart';

class ManagePlaceScreen extends StatefulWidget {
  const ManagePlaceScreen({super.key});

  @override
  State<ManagePlaceScreen> createState() => _ManagePlaceScreenState();
}

class _ManagePlaceScreenState extends State<ManagePlaceScreen> {
  final StorageService _storageService = StorageService();
  final TextEditingController _searchController = TextEditingController();
  String _searchQuery = '';

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  void _showPlaceDialog({DocumentSnapshot? place}) {
    final TextEditingController nameController = TextEditingController(text: place?['name'] ?? '');
    final TextEditingController descController = TextEditingController(text: place?['description'] ?? '');
    final TextEditingController locationController = TextEditingController(text: place?['location'] ?? '');
    final TextEditingController bestTimeController = TextEditingController(text: place?['bestTimeToVisit'] ?? '');
    final TextEditingController minPriceController = TextEditingController(
      text: place?['minPrice'] != null ? place!['minPrice'].toString() : '',
    );
    final TextEditingController maxPriceController = TextEditingController(
      text: place?['maxPrice'] != null ? place!['maxPrice'].toString() : '',
    );
    
    // Danh sách ảnh hiện tại và ảnh mới
    List<String> existingImageUrls = place != null && place['imageUrls'] != null 
        ? List<String>.from(place['imageUrls']) 
        : [];
    List<File> newImageFiles = [];
    bool isUploading = false;

    // Sử dụng danh mục tập trung từ place_model.dart
    List<String> selectedCategories = place != null && place['categories'] != null
        ? List<String>.from(place['categories'])
        : [];

    Future<void> _pickImages() async {
      final picker = ImagePicker();
      final pickedFiles = await picker.pickMultiImage(imageQuality: 80);
      if (pickedFiles.isNotEmpty) {
        setState(() {
          newImageFiles.addAll(pickedFiles.map((file) => File(file.path)));
        });
        // ignore: use_build_context_synchronously
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Đã chọn ${pickedFiles.length} ảnh mới.'))
        );
      }
    }

    void _removeExistingImage(int index) {
      setState(() {
        existingImageUrls.removeAt(index);
      });
    }

    void _removeNewImage(int index) {
      setState(() {
        newImageFiles.removeAt(index);
      });
    }

    showDialog(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setState) => AlertDialog(
          title: Text(place == null ? 'Thêm địa điểm mới' : 'Sửa địa điểm'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                // Phần hiển thị ảnh
                Container(
                  width: double.infinity,
                  decoration: BoxDecoration(
                    border: Border.all(color: Colors.grey),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Column(
                    children: [
                      // Header với nút thêm ảnh
                      Padding(
                        padding: const EdgeInsets.all(8.0),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Ảnh địa điểm (${existingImageUrls.length + newImageFiles.length})',
                              style: const TextStyle(fontWeight: FontWeight.bold),
                            ),
                            const SizedBox(height: 8),
                            SizedBox(
                              width: double.infinity,
                              child: ElevatedButton.icon(
                                onPressed: _pickImages,
                                icon: const Icon(Icons.add_photo_alternate, size: 18),
                                label: const Text('Chọn ảnh'),
                                style: ElevatedButton.styleFrom(
                                  padding: const EdgeInsets.symmetric(vertical: 10),
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                      
                      // Grid hiển thị ảnh hiện tại
                      if (existingImageUrls.isNotEmpty) ...[
                        const Divider(),
                        const Padding(
                          padding: EdgeInsets.symmetric(horizontal: 8.0),
                          child: Align(
                            alignment: Alignment.centerLeft,
                            child: Text('Ảnh hiện tại:', style: TextStyle(fontWeight: FontWeight.w500)),
                          ),
                        ),
                        Container(
                          height: 120,
                          padding: const EdgeInsets.all(8),
                          child: ListView.builder(
                            scrollDirection: Axis.horizontal,
                            itemCount: existingImageUrls.length,
                            itemBuilder: (context, index) {
                              return Container(
                                margin: const EdgeInsets.only(right: 8),
                                child: Stack(
                                  children: [
                                    ClipRRect(
                                      borderRadius: BorderRadius.circular(8),
                                      child: Image.network(
                                        existingImageUrls[index],
                                        width: 100,
                                        height: 100,
                                        fit: BoxFit.cover,
                                        errorBuilder: (context, error, stackTrace) => Container(
                                          width: 100,
                                          height: 100,
                                          color: Colors.grey[300],
                                          child: const Icon(Icons.error),
                                        ),
                                      ),
                                    ),
                                    Positioned(
                                      top: 4,
                                      right: 4,
                                      child: GestureDetector(
                                        onTap: () => _removeExistingImage(index),
                                        child: Container(
                                          padding: const EdgeInsets.all(2),
                                          decoration: const BoxDecoration(
                                            color: Colors.red,
                                            shape: BoxShape.circle,
                                          ),
                                          child: const Icon(
                                            Icons.close,
                                            color: Colors.white,
                                            size: 16,
                                          ),
                                        ),
                                      ),
                                    ),
                                  ],
                                ),
                              );
                            },
                          ),
                        ),
                      ],
                      
                      // Grid hiển thị ảnh mới
                      if (newImageFiles.isNotEmpty) ...[
                        const Divider(),
                        const Padding(
                          padding: EdgeInsets.symmetric(horizontal: 8.0),
                          child: Align(
                            alignment: Alignment.centerLeft,
                            child: Text('Ảnh mới thêm:', style: TextStyle(fontWeight: FontWeight.w500)),
                          ),
                        ),
                        Container(
                          height: 120,
                          padding: const EdgeInsets.all(8),
                          child: ListView.builder(
                            scrollDirection: Axis.horizontal,
                            itemCount: newImageFiles.length,
                            itemBuilder: (context, index) {
                              return Container(
                                margin: const EdgeInsets.only(right: 8),
                                child: Stack(
                                  children: [
                                    ClipRRect(
                                      borderRadius: BorderRadius.circular(8),
                                      child: Image.file(
                                        newImageFiles[index],
                                        width: 100,
                                        height: 100,
                                        fit: BoxFit.cover,
                                      ),
                                    ),
                                    Positioned(
                                      top: 4,
                                      right: 4,
                                      child: GestureDetector(
                                        onTap: () => _removeNewImage(index),
                                        child: Container(
                                          padding: const EdgeInsets.all(2),
                                          decoration: const BoxDecoration(
                                            color: Colors.red,
                                            shape: BoxShape.circle,
                                          ),
                                          child: const Icon(
                                            Icons.close,
                                            color: Colors.white,
                                            size: 16,
                                          ),
                                        ),
                                      ),
                                    ),
                                  ],
                                ),
                              );
                            },
                          ),
                        ),
                      ],
                      
                      // Placeholder khi chưa có ảnh
                      if (existingImageUrls.isEmpty && newImageFiles.isEmpty)
                        Container(
                          height: 120,
                          child: const Center(
                            child: Column(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                Icon(Icons.add_photo_alternate, size: 40, color: Colors.grey),
                                SizedBox(height: 8),
                                Text('Chưa có ảnh nào', style: TextStyle(color: Colors.grey)),
                              ],
                            ),
                          ),
                        ),
                    ],
                  ),
                ),
                
                const SizedBox(height: 16),
                TextField(
                  controller: nameController,
                  decoration: const InputDecoration(labelText: 'Tên địa điểm'),
                ),
                TextField(
                  controller: descController,
                  decoration: const InputDecoration(labelText: 'Mô tả'),
                  maxLines: 2,
                ),
                TextField(
                  controller: locationController,
                  decoration: const InputDecoration(labelText: 'Vị trí'),
                ),
                const SizedBox(height: 8),
                Align(
                  alignment: Alignment.centerLeft,
                  child: Text('Danh mục:', style: TextStyle(fontWeight: FontWeight.bold)),
                ),
                const SizedBox(height: 8),
                Wrap(
                  spacing: 8,
                  children: allCategories.map((cat) {
                    final isSelected = selectedCategories.contains(cat);
                    return FilterChip(
                      label: Text(cat),
                      selected: isSelected,
                      onSelected: (selected) {
                        setState(() {
                          if (selected) {
                            selectedCategories.add(cat);
                          } else {
                            selectedCategories.remove(cat);
                          }
                        });
                      },
                    );
                  }).toList(),
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: bestTimeController,
                  decoration: const InputDecoration(labelText: 'Thời điểm lý tưởng'),
                ),
                Row(
                  children: [
                    Expanded(
                      child: TextField(
                        controller: minPriceController,
                        keyboardType: TextInputType.number,
                        decoration: const InputDecoration(labelText: 'Giá từ (VNĐ)'),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: TextField(
                        controller: maxPriceController,
                        keyboardType: TextInputType.number,
                        decoration: const InputDecoration(labelText: 'Đến (VNĐ)'),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Hủy'),
            ),
            ElevatedButton(
              onPressed: isUploading ? null : () async {
                setState(() {
                  isUploading = true;
                });

                try {
                  // Upload ảnh mới
                  List<String> newImageUrls = [];
                  if (newImageFiles.isNotEmpty) {
                    for (File imageFile in newImageFiles) {
                      String? imageUrl = await _storageService.uploadImage(imageFile, 'places');
                      if (imageUrl != null) {
                        newImageUrls.add(imageUrl);
                      }
                    }
                  }

                  // Kết hợp ảnh cũ và ảnh mới
                  List<String> allImageUrls = [...existingImageUrls, ...newImageUrls];

                  final placeData = {
                    'name': nameController.text,
                    'description': descController.text,
                    'location': locationController.text,
                    'categories': selectedCategories,
                    'bestTimeToVisit': bestTimeController.text,
                    'minPrice': int.tryParse(minPriceController.text),
                    'maxPrice': int.tryParse(maxPriceController.text),
                    'imageUrls': allImageUrls,
                  };

                  if (place == null) {
                    await FirebaseFirestore.instance.collection('places').add(placeData);
                  } else {
                    await FirebaseFirestore.instance.collection('places').doc(place.id).update(placeData);
                  }
                  
                  // ignore: use_build_context_synchronously
                  Navigator.of(context).pop();
                  // ignore: use_build_context_synchronously
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text(place == null ? 'Đã thêm địa điểm thành công!' : 'Đã cập nhật địa điểm thành công!'))
                  );
                } catch (e) {
                  // ignore: use_build_context_synchronously
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('Lỗi: $e'))
                  );
                } finally {
                  setState(() {
                    isUploading = false;
                  });
                }
              },
              child: isUploading 
                  ? const Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        ),
                        SizedBox(width: 8),
                        Text('Đang lưu...'),
                      ],
                    )
                  : Text(place == null ? 'Lưu' : 'Cập nhật'),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _deletePlace(String docId) async {
    await FirebaseFirestore.instance.collection('places').doc(docId).delete();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Quản lý địa điểm'),
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(60),
          child: Padding(
            padding: const EdgeInsets.all(8.0),
            child: TextField(
              controller: _searchController,
              decoration: InputDecoration(
                hintText: 'Tìm kiếm địa điểm theo tên, mô tả hoặc vị trí...',
                prefixIcon: const Icon(Icons.search),
                suffixIcon: _searchController.text.isNotEmpty
                    ? IconButton(
                        icon: const Icon(Icons.clear),
                        onPressed: () {
                          setState(() {
                            _searchController.clear();
                            _searchQuery = '';
                          });
                        },
                      )
                    : null,
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                ),
                filled: true,
                fillColor: Colors.white,
              ),
              onChanged: (value) {
                setState(() {
                  _searchQuery = value.toLowerCase();
                });
              },
            ),
          ),
        ),
      ),
      body: StreamBuilder<QuerySnapshot>(
        stream: FirebaseFirestore.instance.collection('places').snapshots(),
        builder: (context, snapshot) {
          if (!snapshot.hasData) return const Center(child: CircularProgressIndicator());
          
          final allPlaces = snapshot.data!.docs;
          
          // Lọc địa điểm theo từ khóa tìm kiếm
          final filteredPlaces = allPlaces.where((place) {
            if (_searchQuery.isEmpty) return true;
            
            final data = place.data() as Map<String, dynamic>;
            final name = (data['name'] ?? '').toString().toLowerCase();
            final description = (data['description'] ?? '').toString().toLowerCase();
            final location = (data['location'] ?? '').toString().toLowerCase();
            final categories = data['categories'] != null 
                ? (data['categories'] as List).join(' ').toLowerCase()
                : '';
            
            return name.contains(_searchQuery) || 
                   description.contains(_searchQuery) || 
                   location.contains(_searchQuery) ||
                   categories.contains(_searchQuery);
          }).toList();
          
          if (filteredPlaces.isEmpty) {
            return Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    _searchQuery.isEmpty ? Icons.landscape : Icons.search_off,
                    size: 64,
                    color: Colors.grey,
                  ),
                  const SizedBox(height: 16),
                  Text(
                    _searchQuery.isEmpty 
                        ? 'Chưa có địa điểm nào.' 
                        : 'Không tìm thấy địa điểm phù hợp.',
                    style: const TextStyle(
                      fontSize: 18,
                      color: Colors.grey,
                    ),
                  ),
                  if (_searchQuery.isNotEmpty) ...[
                    const SizedBox(height: 8),
                    TextButton(
                      onPressed: () {
                        setState(() {
                          _searchController.clear();
                          _searchQuery = '';
                        });
                      },
                      child: const Text('Xóa bộ lọc'),
                    ),
                  ],
                ],
              ),
            );
          }
          
          return ListView.builder(
            itemCount: filteredPlaces.length,
            itemBuilder: (context, index) {
              final data = filteredPlaces[index].data() as Map<String, dynamic>;
              final imageUrls = data['imageUrls'] != null ? List<String>.from(data['imageUrls']) : <String>[];
              return Card(
                margin: const EdgeInsets.symmetric(vertical: 8, horizontal: 12),
                child: ListTile(
                  leading: imageUrls.isNotEmpty
                      ? Stack(
                          children: [
                            ClipRRect(
                              borderRadius: BorderRadius.circular(8),
                              child: Image.network(imageUrls[0], width: 56, height: 56, fit: BoxFit.cover),
                            ),
                            if (imageUrls.length > 1)
                              Positioned(
                                bottom: 2,
                                right: 2,
                                child: Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
                                  decoration: BoxDecoration(
                                    color: Colors.black.withOpacity(0.7),
                                    borderRadius: BorderRadius.circular(8),
                                  ),
                                  child: Text(
                                    '+${imageUrls.length - 1}',
                                    style: const TextStyle(color: Colors.white, fontSize: 10),
                                  ),
                                ),
                              ),
                          ],
                        )
                      : const Icon(Icons.landscape, size: 40, color: Colors.grey),
                  title: Text(data['name'] ?? ''),
                  subtitle: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(data['description'] ?? ''),
                      if (imageUrls.isNotEmpty)
                        Text(
                          '${imageUrls.length} ảnh',
                          style: TextStyle(fontSize: 12, color: Colors.grey[600]),
                        ),
                    ],
                  ),
                  trailing: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      IconButton(
                        icon: const Icon(Icons.edit, color: Colors.blueAccent),
                        onPressed: () => _showPlaceDialog(place: filteredPlaces[index]),
                        tooltip: 'Sửa',
                      ),
                      IconButton(
                        icon: const Icon(Icons.delete, color: Colors.redAccent),
                        onPressed: () => _deletePlace(filteredPlaces[index].id),
                        tooltip: 'Xóa',
                      ),
                    ],
                  ),
                ),
              );
            },
          );
        },
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _showPlaceDialog(),
        child: const Icon(Icons.add),
        tooltip: 'Thêm địa điểm mới',
      ),
    );
  }
}