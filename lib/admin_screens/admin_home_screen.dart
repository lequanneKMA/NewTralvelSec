import 'package:flutter/material.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:lnmq/admin_screens/manage_tour_screen.dart';
import 'package:lnmq/admin_screens/manage_place_screen.dart';
import 'package:lnmq/admin_screens/manage_user_screen.dart';
import 'package:lnmq/admin_screens/manage_review_screen.dart';
import 'package:lnmq/admin_screens/manage_booking_screen.dart';
import 'package:lnmq/admin_screens/manage_invoice_screen.dart';
import 'package:lnmq/screens/auth_screen.dart';
import 'package:lnmq/services/auth_service.dart';
import 'package:lnmq/admin_screens/admin_chat_screen.dart';

class AdminHomeScreen extends StatefulWidget {
  const AdminHomeScreen({super.key});

  @override
  State<AdminHomeScreen> createState() => _AdminHomeScreenState();
}

class _AdminHomeScreenState extends State<AdminHomeScreen> {
  bool? _isAdmin;

  @override
  void initState() {
    super.initState();
    _checkAdmin();
  }

  Future<void> _checkAdmin() async {
    final user = FirebaseAuth.instance.currentUser;
    if (user == null) {
      setState(() => _isAdmin = false);
      return;
    }
    final doc = await FirebaseFirestore.instance.collection('users').doc(user.uid).get();
    setState(() {
      _isAdmin = doc.data()?['role'] == 'admin' || doc.data()?['isAdmin'] == true;
    });
  }

  @override
  Widget build(BuildContext context) {
    if (_isAdmin == null) {
      return const Scaffold(
        body: Center(child: CircularProgressIndicator()),
      );
    }
    if (_isAdmin == false) {
      return const Scaffold(
        body: Center(child: Text('Bạn không có quyền truy cập trang này!')),
      );
    }

    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [
              Color(0xFF2196F3),
              Color(0xFF1976D2),
            ],
          ),
        ),
        child: SafeArea(
          child: Column(
            children: [
              // Header
              _buildHeader(),
              
              // Grid Cards
              Expanded(
                child: Container(
                  margin: const EdgeInsets.only(top: 20),
                  decoration: const BoxDecoration(
                    color: Colors.white,
                    borderRadius: BorderRadius.only(
                      topLeft: Radius.circular(30),
                      topRight: Radius.circular(30),
                    ),
                  ),
                  child: Padding(
                    padding: const EdgeInsets.all(24),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'Dashboard Quản Trị',
                          style: TextStyle(
                            fontSize: 24,
                            fontWeight: FontWeight.bold,
                            color: Color(0xFF1976D2),
                          ),
                        ),
                        const SizedBox(height: 8),
                        Text(
                          'Chọn chức năng bạn muốn quản lý',
                          style: TextStyle(
                            fontSize: 16,
                            color: Colors.grey[600],
                          ),
                        ),
                        const SizedBox(height: 24),
                        Expanded(
                          child: GridView.count(
                            crossAxisCount: 2,
                            crossAxisSpacing: 16,
                            mainAxisSpacing: 16,
                            childAspectRatio: 1.2, // TĂNG TỶ LỆ để có thêm chiều cao
                            children: [
                              _buildManagementCard(
                                title: 'Quản lý\ntài khoản', // CHIA DÒNG
                                icon: Icons.people,
                                color: const Color(0xFF4CAF50),
                                onTap: () => Navigator.push(
                                  context,
                                  MaterialPageRoute(builder: (context) => const ManageUserScreen()),
                                ),
                              ),
                              _buildManagementCard(
                                title: 'Quản lý\ntour', // CHIA DÒNG
                                icon: Icons.tour,
                                color: const Color(0xFF2196F3),
                                onTap: () => Navigator.push(
                                  context,
                                  MaterialPageRoute(builder: (context) => const ManageTourScreen()),
                                ),
                              ),
                              _buildManagementCard(
                                title: 'Quản lý\nđặt tour', // CHIA DÒNG
                                icon: Icons.book_online,
                                color: const Color(0xFFFF9800),
                                onTap: () => Navigator.push(
                                  context,
                                  MaterialPageRoute(builder: (context) => const ManageBookingScreen()),
                                ),
                              ),
                              _buildManagementCard(
                                title: 'Quản lý\nhóa đơn', // CHIA DÒNG
                                icon: Icons.receipt_long,
                                color: const Color(0xFF9C27B0),
                                onTap: () => Navigator.push(
                                  context,
                                  MaterialPageRoute(builder: (context) => const ManageInvoiceScreen()),
                                ),
                              ),
                              _buildManagementCard(
                                title: 'Quản lý\nđánh giá', // CHIA DÒNG
                                icon: Icons.rate_review,
                                color: const Color(0xFFE91E63),
                                onTap: () => Navigator.push(
                                  context,
                                  MaterialPageRoute(builder: (context) => const ManageReviewScreen()),
                                ),
                              ),
                              _buildManagementCard(
                                title: 'Quản lý\nchat & tư vấn', // CHIA DÒNG
                                icon: Icons.chat,
                                color: const Color(0xFF00BCD4),
                                onTap: () => Navigator.push(
                                  context,
                                  MaterialPageRoute(builder: (context) => const AdminChatScreen()),
                                ),
                              ),
                              _buildManagementCard(
                                title: 'Quản lý\nđịa điểm', // CHIA DÒNG
                                icon: Icons.place,
                                color: const Color(0xFF795548),
                                onTap: () => Navigator.push(
                                  context,
                                  MaterialPageRoute(builder: (context) => const ManagePlaceScreen()),
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
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildHeader() {
    final user = FirebaseAuth.instance.currentUser;
    
    return Container(
      padding: const EdgeInsets.all(24),
      child: Row(
        children: [
          Container(
            width: 60,
            height: 60,
            decoration: BoxDecoration(
              color: Colors.white.withOpacity(0.2),
              borderRadius: BorderRadius.circular(30),
              border: Border.all(color: Colors.white.withOpacity(0.3), width: 2),
            ),
            child: ClipRRect(
              borderRadius: BorderRadius.circular(28),
              child: user?.photoURL != null
                  ? Image.network(
                      user!.photoURL!,
                      fit: BoxFit.cover,
                      errorBuilder: (context, error, stackTrace) {
                        return const Icon(Icons.admin_panel_settings, 
                                       color: Colors.white, size: 30);
                      },
                    )
                  : const Icon(Icons.admin_panel_settings, 
                             color: Colors.white, size: 30),
            ),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Xin chào!',
                  style: TextStyle(
                    color: Colors.white70,
                    fontSize: 16,
                  ),
                ),
                Text(
                  user?.displayName ?? 'Admin',
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 24,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
          ),
          Container(
            decoration: BoxDecoration(
              color: Colors.white.withOpacity(0.2),
              borderRadius: BorderRadius.circular(12),
            ),
            child: IconButton(
              icon: const Icon(Icons.logout, color: Colors.white),
              tooltip: 'Đăng xuất',
              onPressed: () async {
                await AuthService().signOut();
                if (context.mounted) {
                  Navigator.of(context).pushAndRemoveUntil(
                    MaterialPageRoute(builder: (context) => const AuthScreen()),
                    (route) => false,
                  );
                }
              },
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildManagementCard({
    required String title,
    required IconData icon,
    required Color color,
    required VoidCallback onTap,
  }) {
    return Container(
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(20),
        boxShadow: [
          BoxShadow(
            color: color.withOpacity(0.2),
            blurRadius: 15,
            offset: const Offset(0, 5),
          ),
        ],
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(20),
          child: Padding(
            padding: const EdgeInsets.all(16), // GIẢM PADDING
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Container(
                  width: 50, // GIẢM SIZE ICON
                  height: 50,
                  decoration: BoxDecoration(
                    color: color.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(25),
                  ),
                  child: Icon(
                    icon,
                    size: 24, // GIẢM SIZE ICON
                    color: color,
                  ),
                ),
                const SizedBox(height: 8), // GIẢM KHOẢNG CÁCH
                Flexible( // THÊM FLEXIBLE để tránh overflow
                  child: Text(
                    title,
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      fontSize: 12, // GIẢM FONT SIZE
                      fontWeight: FontWeight.w600,
                      color: Colors.grey[800],
                      height: 1.2,
                    ),
                    maxLines: 2, // GIỚI HẠN 2 DÒNG
                    overflow: TextOverflow.ellipsis, // THÊM ELLIPSIS
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