import 'package:flutter/material.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:intl/intl.dart';

class ManageTourScreen extends StatefulWidget {
  const ManageTourScreen({super.key});

  @override
  State<ManageTourScreen> createState() => _ManageTourScreenState();
}

class _ManageTourScreenState extends State<ManageTourScreen> {
  final TextEditingController _searchController = TextEditingController();
  String _searchQuery = '';

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  void _showTourDialog({DocumentSnapshot? tour}) {
    final TextEditingController nameController = TextEditingController(text: tour?['name'] ?? '');
    final TextEditingController descController = TextEditingController(text: tour?['description'] ?? '');
    final TextEditingController priceController = TextEditingController(text: tour?['price']?.toString() ?? '');
    final TextEditingController itineraryController = TextEditingController(
      text: tour != null && tour['itinerary'] != null ? (tour['itinerary'] as List).join('\n') : '',
    );

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(tour == null ? 'Thêm tour mới' : 'Sửa tour'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: nameController,
                decoration: const InputDecoration(labelText: 'Tên tour'),
              ),
              TextField(
                controller: descController,
                decoration: const InputDecoration(labelText: 'Mô tả'),
              ),
              TextField(
                controller: priceController,
                decoration: const InputDecoration(labelText: 'Giá 1 người'),
                keyboardType: TextInputType.number,
              ),
              TextField(
                controller: itineraryController,
                decoration: const InputDecoration(labelText: 'Lịch trình (mỗi dòng 1 mục)'),
                maxLines: 5,
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Hủy'),
          ),
          TextButton(
            onPressed: () async {
              final name = nameController.text.trim();
              final desc = descController.text.trim();
              final price = int.tryParse(priceController.text.trim()) ?? 0;
              final itinerary = itineraryController.text.trim().isEmpty
                  ? []
                  : itineraryController.text.trim().split('\n');
              if (name.isEmpty) return;
              final data = {
                'name': name,
                'description': desc,
                'price': price,
                'itinerary': itinerary,
              };
              if (tour == null) {
                await FirebaseFirestore.instance.collection('tours').add(data);
              } else {
                await tour.reference.update(data);
              }
              if (mounted) Navigator.pop(context);
            },
            child: const Text('Lưu'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Quản lý Tour'),
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(60),
          child: Padding(
            padding: const EdgeInsets.all(8.0),
            child: TextField(
              controller: _searchController,
              decoration: InputDecoration(
                hintText: 'Tìm kiếm tour theo tên hoặc mô tả...',
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
        stream: FirebaseFirestore.instance.collection('tours').snapshots(),
        builder: (context, snapshot) {
          if (!snapshot.hasData) return const Center(child: CircularProgressIndicator());
          
          final allTours = snapshot.data!.docs;
          
          // Lọc tours theo từ khóa tìm kiếm
          final filteredTours = allTours.where((tour) {
            if (_searchQuery.isEmpty) return true;
            
            final name = (tour['name'] ?? '').toString().toLowerCase();
            final description = (tour['description'] ?? '').toString().toLowerCase();
            
            return name.contains(_searchQuery) || description.contains(_searchQuery);
          }).toList();
          
          if (filteredTours.isEmpty) {
            return Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    _searchQuery.isEmpty ? Icons.tour : Icons.search_off,
                    size: 64,
                    color: Colors.grey,
                  ),
                  const SizedBox(height: 16),
                  Text(
                    _searchQuery.isEmpty 
                        ? 'Chưa có tour nào.' 
                        : 'Không tìm thấy tour phù hợp.',
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
            itemCount: filteredTours.length,
            itemBuilder: (context, index) {
              final tour = filteredTours[index];              return ListTile(
                title: Text(tour['name'] ?? ''),
                subtitle: Text('Giá: ${tour['price'] != null ? NumberFormat('#,###', 'vi_VN').format(tour['price']) : ''} VNĐ\n${tour['description'] ?? ''}'),
                isThreeLine: true,
                trailing: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    IconButton(
                      icon: const Icon(Icons.edit, color: Colors.blue),
                      onPressed: () => _showTourDialog(tour: tour),
                    ),
                    IconButton(
                      icon: const Icon(Icons.delete, color: Colors.red),
                      onPressed: () async {
                        await tour.reference.delete();
                      },
                    ),
                  ],
                ),
                onTap: () {
                  // Xem chi tiết hoặc sửa
                  _showTourDialog(tour: tour);
                },
              );
            },
          );
        },
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _showTourDialog(),
        child: const Icon(Icons.add),
        tooltip: 'Thêm tour mới',
      ),
    );
  }
}