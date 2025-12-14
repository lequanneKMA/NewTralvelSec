import 'package:flutter/material.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';

class TourChatScreen extends StatefulWidget {
  final String tourId;
  final String tourName;
  const TourChatScreen({super.key, required this.tourId, required this.tourName});

  @override
  State<TourChatScreen> createState() => _TourChatScreenState();
}

class _TourChatScreenState extends State<TourChatScreen> {
  final TextEditingController _messageController = TextEditingController();
  final user = FirebaseAuth.instance.currentUser;

  void _sendMessage() async {
    final text = _messageController.text.trim();
    if (text.isEmpty || user == null) return;

    final chatId = '${user!.uid}_${widget.tourId}';

    // Gửi tin nhắn
    await FirebaseFirestore.instance
        .collection('tour_chats')
        .doc(chatId)
        .collection('messages')
        .add({
      'senderId': user!.uid,
      'senderName': user!.displayName ?? 'Người dùng',
      'message': text,
      'timestamp': FieldValue.serverTimestamp(),
      'isAdmin': false,
    });

    // THÊM: Cập nhật thông tin chat room
    await FirebaseFirestore.instance
        .collection('tour_chats')
        .doc(chatId)
        .set({
      'userId': user!.uid,
      'userName': user!.displayName ?? 'Người dùng',
      'tourId': widget.tourId,
      'tourName': widget.tourName,
      'lastMessage': text, // Tin nhắn cuối cùng
      'lastMessageAt': FieldValue.serverTimestamp(), // Thời gian tin nhắn cuối
      'unreadCount': FieldValue.increment(1), // Tăng số tin nhắn chưa đọc
    }, SetOptions(merge: true));

    _messageController.clear();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Chat với Admin')),
      body: Column(
        children: [
          // Hiển thị thông tin tour đã đặt
          Container(
            width: double.infinity,
            color: Colors.blue[50],
            padding: const EdgeInsets.all(12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('Thông tin tour đã đặt:', style: TextStyle(fontWeight: FontWeight.bold)),
                Text('Tên tour: ${widget.tourName}'),
                Text('Mã tour: ${widget.tourId}'),
              ],
            ),
          ),
          Expanded(
            child: StreamBuilder<QuerySnapshot>(
              stream: FirebaseFirestore.instance
                  .collection('tour_chats')
                  .doc('${user!.uid}_${widget.tourId}')  // SỬA: Dùng chatId
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
                    final isMe = data['senderId'] == user?.uid;
                    return Align(
                      alignment: isMe ? Alignment.centerRight : Alignment.centerLeft,
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          if (data['qrUrl'] != null)
                            Padding(
                              padding: const EdgeInsets.only(bottom: 8),
                              child: Image.network(
                                data['qrUrl'],
                                width: 200,
                                height: 200,
                              ),
                            ),
                          Container(
                            margin: const EdgeInsets.symmetric(vertical: 4),
                            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                            decoration: BoxDecoration(
                              color: isMe ? Colors.blue[100] : Colors.grey[200],
                              borderRadius: BorderRadius.circular(10),
                            ),
                            child: Text(data['message'] ?? ''),
                          ),
                        ],
                      ),
                    );
                  },
                );
              },
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