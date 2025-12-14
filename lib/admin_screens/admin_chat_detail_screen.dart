import 'package:flutter/material.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:intl/intl.dart';
import 'package:lnmq/services/booking_service.dart';

class AdminChatDetailScreen extends StatefulWidget {
  final String userId;
  final String userName;
  final String tourId;
  final String tourName;
  const AdminChatDetailScreen({
    super.key,
    required this.userId,
    required this.userName,
    required this.tourId,
    required this.tourName,
  });

  @override
  State<AdminChatDetailScreen> createState() => _AdminChatDetailScreenState();
}

class _AdminChatDetailScreenState extends State<AdminChatDetailScreen> {
  final TextEditingController _messageController = TextEditingController();
  final admin = FirebaseAuth.instance.currentUser;
  final BookingService _bookingService = BookingService();
  double? _amount;
  final TextEditingController _amountController = TextEditingController();
  final String bankId = 'TPB'; // Mã ngân hàng (TPBank)
  final String account = '03901436666'; // Số tài khoản
  final String accountName = 'LE NGUYEN MINH QUAN'; // Tên chủ tài khoản (IN HOA, KHÔNG DẤU)

  void _sendMessage() async {
    final text = _messageController.text.trim();
    if (text.isEmpty || admin == null) return;
    
    final chatId = '${widget.userId}_${widget.tourId}';
    
    // Gửi tin nhắn
    await FirebaseFirestore.instance
        .collection('tour_chats')
        .doc(chatId)
        .collection('messages')
        .add({
      'senderId': admin!.uid,
      'senderName': admin!.displayName ?? 'Admin',
      'message': text,
      'timestamp': FieldValue.serverTimestamp(),
      'isAdmin': true,
    });

    // THÊM: Cập nhật thông tin chat room (không tăng unreadCount vì admin gửi)
    await FirebaseFirestore.instance
        .collection('tour_chats')
        .doc(chatId)
        .set({
      'userId': widget.userId,
      'userName': widget.userName,
      'tourId': widget.tourId,
      'tourName': widget.tourName,
      'lastMessage': text,
      'lastMessageAt': FieldValue.serverTimestamp(),
      // Không cập nhật unreadCount vì admin gửi
    }, SetOptions(merge: true));

    _messageController.clear();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Chat với ${widget.userName}'),
        backgroundColor: Colors.blueAccent,
      ),
      body: Column(
        children: [
          // Hiển thị thông tin tour
          Container(
            width: double.infinity,
            color: Colors.blue[50],
            padding: const EdgeInsets.all(12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('Thông tin tour:', style: TextStyle(fontWeight: FontWeight.bold)),
                Text('Tên tour: ${widget.tourName}'),
                Text('Mã tour: ${widget.tourId}'),
              ],
            ),
          ),
          
          // THÊM: Hiển thị số tiền cần thanh toán
          StreamBuilder<QuerySnapshot>(
            stream: FirebaseFirestore.instance
                .collection('bookings')
                .where('userId', isEqualTo: widget.userId)
                .where('tourId', isEqualTo: widget.tourId)
                .snapshots(),
            builder: (context, snapshot) {
              if (snapshot.hasData && snapshot.data!.docs.isNotEmpty) {
                // Sort và lấy booking mới nhất trong code
                final sortedDocs = snapshot.data!.docs.toList();
                sortedDocs.sort((a, b) {
                  final aData = a.data() as Map<String, dynamic>;
                  final bData = b.data() as Map<String, dynamic>;
                  final aTime = (aData['createdAt'] as Timestamp?)?.toDate() ?? DateTime.now();
                  final bTime = (bData['createdAt'] as Timestamp?)?.toDate() ?? DateTime.now();
                  return bTime.compareTo(aTime); // Mới nhất trước
                });
                
                final booking = sortedDocs.first.data() as Map<String, dynamic>;
                final totalPrice = booking['totalPrice'] ?? 0;
                
                return Container(
                  width: double.infinity,
                  color: Colors.green[50],
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Icon(Icons.attach_money, color: Colors.green[700], size: 20),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  'Số tiền cần thanh toán:',
                                  style: TextStyle(
                                    fontWeight: FontWeight.bold,
                                    color: Colors.green[700],
                                    fontSize: 14,
                                  ),
                                ),
                                const SizedBox(height: 4),
                                Text(
                                  '${NumberFormat('#,###', 'vi_VN').format(totalPrice)} VNĐ',
                                  style: TextStyle(
                                    fontWeight: FontWeight.bold,
                                    fontSize: 16,
                                    color: Colors.green[800],
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 12),
                      Row(
                        children: [
                          Expanded(
                            child: ElevatedButton.icon(
                              onPressed: () {
                                setState(() {
                                  _amount = totalPrice.toDouble();
                                  _amountController.text = totalPrice.toString();
                                  // Gửi tin nhắn QR cho user
                                  if (admin != null) {
                                    final qrUrl =
                                        'https://img.vietqr.io/image/$bankId-$account-print.png?amount=${totalPrice.toInt()}&addInfo=${Uri.encodeComponent('Thanh toan tour ${widget.tourName}')}&accountName=${Uri.encodeComponent(accountName)}';

                                    final chatId = '${widget.userId}_${widget.tourId}';
                                    
                                    FirebaseFirestore.instance
                                        .collection('tour_chats')
                                        .doc(chatId)
                                        .collection('messages')
                                        .add({
                                      'senderId': admin!.uid,
                                      'senderName': admin!.displayName ?? 'Admin',
                                      'message': 'Vui lòng thanh toán số tiền: ${NumberFormat('#,###', 'vi_VN').format(totalPrice.toInt())} VNĐ cho tour "${widget.tourName}". Quét mã QR bên dưới để chuyển khoản.',
                                      'qrUrl': qrUrl, 
                                      'timestamp': FieldValue.serverTimestamp(),
                                      'isAdmin': true,
                                    });
                                  }
                                });
                              },
                              icon: const Icon(Icons.qr_code, size: 16),
                              label: const Text('Tạo QR', style: TextStyle(fontSize: 12)),
                              style: ElevatedButton.styleFrom(
                                backgroundColor: Colors.green[600],
                                foregroundColor: Colors.white,
                                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                              ),
                            ),
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: ElevatedButton.icon(
                              onPressed: () async {
                                // Hiển thị dialog xác nhận thanh toán
                                final confirmed = await showDialog<bool>(
                                  context: context,
                                  builder: (context) => AlertDialog(
                                    title: const Text('Xác nhận thanh toán'),
                                    content: Text('Xác nhận khách hàng đã thanh toán ${NumberFormat('#,###', 'vi_VN').format(totalPrice)} VNĐ cho tour "${widget.tourName}"?'),
                                    actions: [
                                      TextButton(
                                        onPressed: () => Navigator.pop(context, false),
                                        child: const Text('Hủy'),
                                      ),
                                      ElevatedButton(
                                        onPressed: () => Navigator.pop(context, true),
                                        child: const Text('Xác nhận'),
                                      ),
                                    ],
                                  ),
                                );
                                
                                if (confirmed == true) {
                                  try {
                                    // Lấy bookingId từ booking
                                    final bookingSnapshot = await FirebaseFirestore.instance
                                        .collection('bookings')
                                        .where('userId', isEqualTo: widget.userId)
                                        .where('tourId', isEqualTo: widget.tourId)
                                        .get();
                                    
                                    if (bookingSnapshot.docs.isNotEmpty) {
                                      final bookingId = bookingSnapshot.docs.first.id;
                                      
                                      // Sử dụng method đồng bộ để cập nhật booking và invoice
                                      await _bookingService.confirmPaymentWithInvoiceSync(
                                        bookingId,
                                        'Chuyển khoản',
                                        adminNotes: 'Đã xác nhận thanh toán qua chat',
                                      );
                                      
                                      // Gửi tin nhắn xác nhận
                                      final chatId = '${widget.userId}_${widget.tourId}';
                                      await FirebaseFirestore.instance
                                          .collection('tour_chats')
                                          .doc(chatId)
                                          .collection('messages')
                                          .add({
                                        'senderId': admin!.uid,
                                        'senderName': admin!.displayName ?? 'Admin',
                                        'message': '✅ Đã xác nhận thanh toán thành công! Cảm ơn bạn đã sử dụng dịch vụ.',
                                        'timestamp': FieldValue.serverTimestamp(),
                                        'isAdmin': true,
                                      });
                                      
                                      if (mounted) {
                                        ScaffoldMessenger.of(context).showSnackBar(
                                          const SnackBar(content: Text('Đã xác nhận thanh toán thành công!')),
                                        );
                                      }
                                    }
                                  } catch (e) {
                                    if (mounted) {
                                      ScaffoldMessenger.of(context).showSnackBar(
                                        SnackBar(content: Text('Lỗi: $e')),
                                      );
                                    }
                                  }
                                }
                              },
                              icon: const Icon(Icons.check_circle, size: 16),
                              label: const Text('Xác nhận', style: TextStyle(fontSize: 12)),
                              style: ElevatedButton.styleFrom(
                                backgroundColor: Colors.blue[600],
                                foregroundColor: Colors.white,
                                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                              ),
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                );
              }
              
              // Không có booking hoặc đang tải
              return Container(
                width: double.infinity,
                color: Colors.grey[100],
                padding: const EdgeInsets.all(12),
                child: Text(
                  'Chưa có thông tin booking (userId: ${widget.userId}, tourId: ${widget.tourId})',
                  style: const TextStyle(color: Colors.grey, fontStyle: FontStyle.italic),
                ),
              );
            },
          ),
          Expanded(
            child: StreamBuilder<QuerySnapshot>(
              stream: FirebaseFirestore.instance
                  .collection('tour_chats')
                  .doc('${widget.userId}_${widget.tourId}')  // SỬA: Dùng chatId
                  .collection('messages')
                  .orderBy('timestamp', descending: false)
                  .snapshots(),
              builder: (context, snapshot) {
                if (!snapshot.hasData) {
                  return const Center(child: CircularProgressIndicator());
                }
                final docs = snapshot.data!.docs;
                return ListView.builder(
                  padding: const EdgeInsets.all(12),
                  itemCount: docs.length,
                  itemBuilder: (context, index) {
                    final data = docs[index].data() as Map<String, dynamic>;
                    final isAdmin = data['isAdmin'] == true;
                    return Align(
                      alignment: isAdmin ? Alignment.centerRight : Alignment.centerLeft,
                      child: Container(
                        margin: const EdgeInsets.symmetric(vertical: 4),
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                        decoration: BoxDecoration(
                          color: isAdmin ? Colors.blue[100] : Colors.grey[200],
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              data['senderName'] ?? '',
                              style: TextStyle(
                                fontWeight: FontWeight.bold,
                                color: isAdmin ? Colors.blue : Colors.black54,
                                fontSize: 13,
                              ),
                            ),
                            const SizedBox(height: 2),
                            Text(data['message'] ?? ''),
                          ],
                        ),
                      ),
                    );
                  },
                );
              },
            ),
          ),
          // Hiển thị QR code nếu đã tạo
          if (_amount != null && _amount! > 0)
            Padding(
              padding: const EdgeInsets.all(12),
              child: Container(
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(12),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.grey.withOpacity(0.3),
                      spreadRadius: 2,
                      blurRadius: 5,
                      offset: const Offset(0, 3),
                    ),
                  ],
                ),
                padding: const EdgeInsets.all(16),
                child: Column(
                  children: [
                    Text(
                      'Mã QR thanh toán',
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                        color: Colors.green[700],
                      ),
                    ),
                    const SizedBox(height: 12),
                    Image.network(
                      'https://img.vietqr.io/image/$bankId-$account-print.png?amount=${_amount!.toInt()}&addInfo=${Uri.encodeComponent('Thanh toan tour ${widget.tourName}')}&accountName=${Uri.encodeComponent(accountName)}',
                      width: 200,
                      height: 200,
                    ),
                  ],
                ),
              ),
            ),
          const Divider(height: 1),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _messageController,
                    decoration: const InputDecoration(
                      hintText: 'Nhập tin nhắn...',
                      border: OutlineInputBorder(),
                      isDense: true,
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                IconButton(
                  icon: const Icon(Icons.send, color: Colors.blueAccent),
                  onPressed: _sendMessage,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}