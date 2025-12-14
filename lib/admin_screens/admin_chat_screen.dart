import 'package:flutter/material.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'admin_chat_detail_screen.dart';

class AdminChatScreen extends StatefulWidget {
  const AdminChatScreen({super.key});

  @override
  State<AdminChatScreen> createState() => _AdminChatScreenState();
}

class _AdminChatScreenState extends State<AdminChatScreen> {
  final TextEditingController _searchController = TextEditingController();
  String _searchTerm = '';

  String _formatTime(DateTime dateTime) {
    final now = DateTime.now();
    final difference = now.difference(dateTime);
    
    if (difference.inDays > 0) {
      return '${difference.inDays} ngày trước';
    } else if (difference.inHours > 0) {
      return '${difference.inHours} giờ trước';
    } else if (difference.inMinutes > 0) {
      return '${difference.inMinutes} phút trước';
    } else {
      return 'Vừa xong';
    }
  }

  void _closeChat(String chatId, String userName) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Đóng chat'),
        content: Text('Bạn có chắc chắn muốn đóng chat với $userName?\n\nChat sẽ bị xóa vĩnh viễn.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Hủy'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.red,
              foregroundColor: Colors.white,
            ),
            child: const Text('Đóng chat'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      try {
        // Xóa tất cả messages trong chat
        final messagesQuery = await FirebaseFirestore.instance
            .collection('tour_chats')
            .doc(chatId)
            .collection('messages')
            .get();

        final batch = FirebaseFirestore.instance.batch();

        // Xóa từng message
        for (final messageDoc in messagesQuery.docs) {
          batch.delete(messageDoc.reference);
        }

        // Xóa chat document
        batch.delete(
          FirebaseFirestore.instance.collection('tour_chats').doc(chatId)
        );

        await batch.commit();

        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Đã đóng chat với $userName'),
              backgroundColor: Colors.green,
            ),
          );
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Lỗi khi đóng chat: $e'),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Quản lý chat & tư vấn'),
        backgroundColor: Colors.blueAccent,
        foregroundColor: Colors.white,
      ),
      body: Column(
        children: [
          // Thanh tìm kiếm
          Padding(
            padding: const EdgeInsets.all(16),
            child: TextField(
              controller: _searchController,
              decoration: InputDecoration(
                labelText: 'Tìm kiếm chat (tên user, tour...)',
                prefixIcon: const Icon(Icons.search),
                suffixIcon: _searchTerm.isNotEmpty
                    ? IconButton(
                        onPressed: () {
                          _searchController.clear();
                          setState(() {
                            _searchTerm = '';
                          });
                        },
                        icon: const Icon(Icons.clear),
                      )
                    : null,
                border: const OutlineInputBorder(),
              ),
              onChanged: (value) {
                setState(() {
                  _searchTerm = value.toLowerCase();
                });
              },
            ),
          ),
          // Danh sách chat
          Expanded(
            child: StreamBuilder<QuerySnapshot>(
              stream: FirebaseFirestore.instance
                  .collection('tour_chats')
                  .orderBy('lastMessageAt', descending: true)
                  .snapshots(),
              builder: (context, snapshot) {
                if (!snapshot.hasData) return const Center(child: CircularProgressIndicator());
                
                final chatDocs = snapshot.data!.docs;
                
                // Lọc chat theo từ khóa tìm kiếm
                final filteredChats = chatDocs.where((chat) {
                  if (_searchTerm.isEmpty) return true;
                  
                  final data = chat.data() as Map<String, dynamic>;
                  final userName = (data['userName'] ?? '').toString().toLowerCase();
                  final tourName = (data['tourName'] ?? '').toString().toLowerCase();
                  final lastMessage = (data['lastMessage'] ?? '').toString().toLowerCase();
                  
                  return userName.contains(_searchTerm) ||
                         tourName.contains(_searchTerm) ||
                         lastMessage.contains(_searchTerm);
                }).toList();

                if (filteredChats.isEmpty) {
                  return Center(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(
                          _searchTerm.isEmpty ? Icons.chat_bubble_outline : Icons.search_off,
                          size: 80, 
                          color: Colors.grey
                        ),
                        const SizedBox(height: 16),
                        Text(
                          _searchTerm.isEmpty 
                              ? 'Chưa có người dùng nào chat hoặc tư vấn.'
                              : 'Không tìm thấy chat nào với từ khóa "$_searchTerm"',
                        ),
                      ],
                    ),
                  );
                }

                return ListView.builder(
                  itemCount: filteredChats.length,
                  itemBuilder: (context, index) {
                    final chat = filteredChats[index];
                    final data = chat.data() as Map<String, dynamic>;
                    
                    final chatId = chat.id;
                    final parts = chatId.split('_');
                    final userId = parts[0];
                    final tourIdPart = parts.length > 1 ? parts.sublist(1).join('_') : 'general';

                    final tourName = data['tourName'] ?? 'Không rõ tên';
                    final tourId = data['tourId'] ?? tourIdPart;
                    final userName = data['userName'] ?? 'Người dùng';
                    
                    final lastMessage = data['lastMessage'] ?? '';
                    final lastMessageAt = data['lastMessageAt'] as Timestamp?;
                    final unreadCount = data['unreadCount'] ?? 0;

                    final isGeneralChat = tourId == 'general_chat' || tourId == 'general';

                    return Card(
                      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                      color: unreadCount > 0 ? Colors.blue[50] : null,
                      child: ListTile(
                        leading: Stack(
                          children: [
                            CircleAvatar(
                              backgroundColor: isGeneralChat ? Colors.green : Colors.blue,
                              child: Icon(
                                isGeneralChat ? Icons.support_agent : Icons.tour,
                                color: Colors.white,
                              ),
                            ),
                            if (unreadCount > 0)
                              Positioned(
                                right: 0,
                                top: 0,
                                child: Container(
                                  padding: const EdgeInsets.all(2),
                                  decoration: BoxDecoration(
                                    color: Colors.red,
                                    borderRadius: BorderRadius.circular(10),
                                  ),
                                  constraints: const BoxConstraints(
                                    minWidth: 16,
                                    minHeight: 16,
                                  ),
                                  child: Text(
                                    '$unreadCount',
                                    style: const TextStyle(
                                      color: Colors.white,
                                      fontSize: 10,
                                      fontWeight: FontWeight.bold,
                                    ),
                                    textAlign: TextAlign.center,
                                  ),
                                ),
                              ),
                          ],
                        ),
                        title: Row(
                          children: [
                            Expanded(
                              child: Text(
                                userName,
                                style: TextStyle(
                                  fontWeight: unreadCount > 0 ? FontWeight.bold : FontWeight.w600,
                                ),
                              ),
                            ),
                            if (lastMessageAt != null)
                              Text(
                                _formatTime(lastMessageAt.toDate()),
                                style: TextStyle(
                                  color: Colors.grey[500],
                                  fontSize: 12,
                                ),
                              ),
                          ],
                        ),
                        subtitle: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              isGeneralChat ? 'Tư vấn chung' : 'Tour: $tourName',
                              style: TextStyle(
                                color: isGeneralChat ? Colors.green[700] : Colors.blue[700],
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                            if (lastMessage.isNotEmpty) ...[
                              const SizedBox(height: 4),
                              Text(
                                lastMessage,
                                style: TextStyle(
                                  color: unreadCount > 0 ? Colors.black87 : Colors.grey[600],
                                  fontSize: 13,
                                  fontWeight: unreadCount > 0 ? FontWeight.w500 : FontWeight.normal,
                                ),
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                              ),
                            ],
                          ],
                        ),
                        // Menu trailing với 2 tùy chọn
                        trailing: PopupMenuButton<String>(
                          icon: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Icon(
                                Icons.chat_bubble,
                                color: isGeneralChat ? Colors.green : Colors.blue,
                              ),
                              if (unreadCount > 0) ...[
                                const SizedBox(width: 4),
                                const Icon(
                                  Icons.fiber_new,
                                  color: Colors.red,
                                  size: 20,
                                ),
                              ],
                              const SizedBox(width: 4),
                              const Icon(Icons.more_vert, size: 16),
                            ],
                          ),
                          itemBuilder: (context) => [
                            const PopupMenuItem(
                              value: 'open',
                              child: Row(
                                children: [
                                  Icon(Icons.chat, size: 16),
                                  SizedBox(width: 8),
                                  Text('Mở chat'),
                                ],
                              ),
                            ),
                            const PopupMenuItem(
                              value: 'close',
                              child: Row(
                                children: [
                                  Icon(Icons.close, color: Colors.red, size: 16),
                                  SizedBox(width: 8),
                                  Text('Đóng chat', style: TextStyle(color: Colors.red)),
                                ],
                              ),
                            ),
                          ],
                          onSelected: (value) {
                            switch (value) {
                              case 'open':
                                // Đánh dấu đã đọc khi vào chat
                                if (unreadCount > 0) {
                                  FirebaseFirestore.instance
                                      .collection('tour_chats')
                                      .doc(chatId)
                                      .update({'unreadCount': 0});
                                }
                                
                                Navigator.push(
                                  context,
                                  MaterialPageRoute(
                                    builder: (context) => AdminChatDetailScreen(
                                      userId: userId,
                                      userName: userName,
                                      tourId: tourId,
                                      tourName: tourName,
                                    ),
                                  ),
                                );
                                break;
                              case 'close':
                                _closeChat(chatId, userName);
                                break;
                            }
                          },
                        ),
                        onTap: () {
                          // Đánh dấu đã đọc khi vào chat
                          if (unreadCount > 0) {
                            FirebaseFirestore.instance
                                .collection('tour_chats')
                                .doc(chatId)
                                .update({'unreadCount': 0});
                          }
                          
                          Navigator.push(
                            context,
                            MaterialPageRoute(
                              builder: (context) => AdminChatDetailScreen(
                                userId: userId,
                                userName: userName,
                                tourId: tourId,
                                tourName: tourName,
                              ),
                            ),
                          );
                        },
                      ),
                    );
                  },
                );
              },
            ),
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }
}