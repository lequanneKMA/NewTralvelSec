import 'package:flutter/material.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:lnmq/models/user_model.dart';

class ManageUserScreen extends StatefulWidget {
  const ManageUserScreen({super.key});

  @override
  State<ManageUserScreen> createState() => _ManageUserScreenState();
}

class _ManageUserScreenState extends State<ManageUserScreen> {
  final TextEditingController _searchController = TextEditingController();
  String _searchQuery = '';

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Quản lý thông tin người dùng', style: TextStyle(color: Colors.white)),
        backgroundColor: Colors.blueAccent,
        foregroundColor: Colors.white,
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(70),
          child: Padding(
            padding: const EdgeInsets.all(16.0),
            child: TextField(
              controller: _searchController,
              decoration: InputDecoration(
                hintText: 'Tìm kiếm theo tên, email...',
                prefixIcon: const Icon(Icons.search),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(10),
                  borderSide: BorderSide.none,
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
        stream: FirebaseFirestore.instance.collection('users').snapshots(),
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator());
          }

          if (snapshot.hasError) {
            return Center(child: Text('Lỗi: ${snapshot.error}'));
          }

          if (!snapshot.hasData || snapshot.data!.docs.isEmpty) {
            return const Center(child: Text('Chưa có tài khoản nào.'));
          }

          List<AppUser> users = snapshot.data!.docs
              .map((doc) => AppUser.fromFirestore(doc))
              .where((user) {
                // BỎ TÀI KHOẢN ADMIN
                if (user.isAdmin) return false;
                
                if (_searchQuery.isEmpty) return true;
                return user.displayName?.toLowerCase().contains(_searchQuery) == true ||
                       user.email.toLowerCase().contains(_searchQuery) ||
                       user.phoneNumber?.toLowerCase().contains(_searchQuery) == true;
              })
              .toList();

          // Sắp xếp theo thời gian tạo (mới nhất trước)
          users.sort((a, b) => b.createdAt.compareTo(a.createdAt));

          return ListView.builder(
            padding: const EdgeInsets.all(16),
            itemCount: users.length,
            itemBuilder: (context, index) {
              final user = users[index];
              return _buildUserCard(user);
            },
          );
        },
      ),
    );
  }

  Widget _buildUserCard(AppUser user) {
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      elevation: 2,
      child: InkWell(
        onTap: () => _showUserDetailDialog(user),
        borderRadius: BorderRadius.circular(8),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              // Avatar
              CircleAvatar(
                radius: 30,
                backgroundColor: Colors.grey[300],
                backgroundImage: user.photoUrl != null ? NetworkImage(user.photoUrl!) : null,
                child: user.photoUrl == null
                    ? Text(
                        user.displayName?.isNotEmpty == true 
                            ? user.displayName![0].toUpperCase() 
                            : user.email[0].toUpperCase(),
                        style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
                      )
                    : null,
              ),
              const SizedBox(width: 16),
              
              // Thông tin user
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      user.displayName ?? 'Chưa đặt tên',
                      style: const TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      user.email,
                      style: TextStyle(
                        fontSize: 14,
                        color: Colors.grey[600],
                      ),
                    ),
                    if (user.phoneNumber?.isNotEmpty == true) ...[
                      const SizedBox(height: 2),
                      Text(
                        user.phoneNumber!,
                        style: TextStyle(
                          fontSize: 14,
                          color: Colors.grey[600],
                        ),
                      ),
                    ],
                    const SizedBox(height: 4),
                    Text(
                      'Tham gia: ${_formatDate(user.createdAt)}',
                      style: TextStyle(
                        fontSize: 12,
                        color: Colors.grey[500],
                      ),
                    ),
                  ],
                ),
              ),
              
              // Số địa điểm yêu thích
              Column(
                children: [
                  Icon(Icons.favorite, color: Colors.red[300], size: 20),
                  Text(
                    '${user.favoritePlaceIds.length}',
                    style: const TextStyle(fontWeight: FontWeight.bold),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showUserDetailDialog(AppUser user) {
    showDialog(
      context: context,
      builder: (context) => Dialog(
        child: Container(
          width: MediaQuery.of(context).size.width * 0.9,
          height: MediaQuery.of(context).size.height * 0.8,
          child: Column(
            children: [
              // Header
              Container(
                padding: const EdgeInsets.all(16),
                decoration: const BoxDecoration(
                  color: Colors.blueAccent,
                  borderRadius: BorderRadius.only(
                    topLeft: Radius.circular(8),
                    topRight: Radius.circular(8),
                  ),
                ),
                child: Row(
                  children: [
                    CircleAvatar(
                      radius: 25,
                      backgroundColor: Colors.white.withOpacity(0.3),
                      backgroundImage: user.photoUrl != null ? NetworkImage(user.photoUrl!) : null,
                      child: user.photoUrl == null
                          ? Text(
                              user.displayName?.isNotEmpty == true 
                                  ? user.displayName![0].toUpperCase() 
                                  : user.email[0].toUpperCase(),
                              style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: Colors.white),
                            )
                          : null,
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            user.displayName ?? 'Chưa đặt tên',
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          Text(
                            'THÔNG TIN CHI TIẾT',
                            style: TextStyle(
                              color: Colors.white.withOpacity(0.9),
                              fontSize: 12,
                            ),
                          ),
                        ],
                      ),
                    ),
                    IconButton(
                      onPressed: () => Navigator.pop(context),
                      icon: const Icon(Icons.close, color: Colors.white),
                    ),
                  ],
                ),
              ),
              
              // Content
              Expanded(
                child: SingleChildScrollView(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _buildInfoSection('Thông tin cơ bản', [
                        _buildInfoRow('Email', user.email),
                        _buildInfoRow('Tên hiển thị', user.displayName ?? 'Chưa đặt'),
                        _buildInfoRow('Số điện thoại', user.phoneNumber ?? 'Chưa cập nhật'),
                        _buildInfoRow('Địa chỉ', user.address ?? 'Chưa cập nhật'),
                        _buildInfoRow('Ngày sinh', user.birthdate != null ? _formatDate(user.birthdate!) : 'Chưa cập nhật'),
                        _buildInfoRow('Giới tính', user.gender ?? 'Chưa cập nhật'),
                        _buildInfoRow('Nghề nghiệp', user.occupation ?? 'Chưa cập nhật'),
                      ]),
                      
                      const SizedBox(height: 16),
                      
                      _buildInfoSection('Thông tin liên hệ khẩn cấp', [
                        _buildInfoRow('Tên người liên hệ', user.emergencyContactName ?? 'Chưa cập nhật'),
                        _buildInfoRow('SĐT khẩn cấp', user.emergencyContactPhone ?? 'Chưa cập nhật'),
                      ]),
                      
                      const SizedBox(height: 16),
                      
                      _buildInfoSection('Thông tin thống kê', [
                        _buildInfoRow('Số CCCD/CMND', user.nationalId ?? 'Chưa cập nhật'),
                        _buildInfoRow('Ngày tham gia', _formatDate(user.createdAt)),
                        _buildInfoRow('Lần đăng nhập cuối', user.lastLoginAt != null ? _formatDate(user.lastLoginAt!) : 'Chưa có dữ liệu'),
                        _buildInfoRow('Số địa điểm yêu thích', '${user.favoritePlaceIds.length}'),
                      ]),
                      
                      if (user.travelPreferences?.isNotEmpty == true) ...[
                        const SizedBox(height: 16),
                        _buildInfoSection('Sở thích du lịch', [
                          Container(
                            width: double.infinity,
                            child: Wrap(
                              spacing: 8,
                              runSpacing: 4,
                              children: user.travelPreferences!.map((pref) => Chip(
                                label: Text(pref, style: const TextStyle(fontSize: 12)),
                                backgroundColor: Colors.blue[100],
                              )).toList(),
                            ),
                          ),
                        ]),
                      ],
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildInfoSection(String title, List<Widget> children) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: const TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.bold,
            color: Colors.blueAccent,
          ),
        ),
        const SizedBox(height: 8),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: Colors.grey[50],
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: Colors.grey[200]!),
          ),
          child: Column(
            children: children,
          ),
        ),
      ],
    );
  }

  Widget _buildInfoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 120,
            child: Text(
              '$label:',
              style: const TextStyle(
                fontWeight: FontWeight.w500,
                color: Colors.black87,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: TextStyle(
                color: Colors.grey[700],
              ),
            ),
          ),
        ],
      ),
    );
  }

  String _formatDate(DateTime date) {
    return '${date.day}/${date.month}/${date.year}';
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }
}