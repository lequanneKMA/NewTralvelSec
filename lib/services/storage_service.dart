// lib/services/storage_service.dart
import 'dart:io';
import 'package:firebase_storage/firebase_storage.dart';
import 'package:uuid/uuid.dart'; // Để tạo ID duy nhất cho file

class StorageService {
  final FirebaseStorage _storage = FirebaseStorage.instance;
  final Uuid _uuid = const Uuid(); // Khởi tạo Uuid để tạo tên file duy nhất

  // Phương thức upload ảnh TỔNG QUÁT, nhận đường dẫn đầy đủ
  // Ví dụ: 'places/uuid_filename.jpg' hoặc 'profile_pictures/user_uid/uuid_filename.jpg'
  Future<String?> uploadImage(File imageFile, String folderPath) async {
    try {
      // Tạo một tên file duy nhất để tránh trùng lặp
      // Sử dụng UUID kết hợp với tên file gốc để đảm bảo tên duy nhất và dễ nhận diện
      final String fileName = '${_uuid.v4()}_${imageFile.path.split('/').last}';

      // Tạo đường dẫn hoàn chỉnh trong Storage
      // folderPath sẽ là 'places' hoặc 'profile_pictures/user_uid'
      final Reference storageRef = _storage.ref().child('$folderPath/$fileName');

      // Tải file lên
      final UploadTask uploadTask = storageRef.putFile(imageFile);

      // Chờ quá trình tải lên hoàn tất và lấy snapshot
      final TaskSnapshot snapshot = await uploadTask;

      // Lấy URL tải xuống của ảnh
      final String downloadUrl = await snapshot.ref.getDownloadURL();
      return downloadUrl;
    } catch (e) {
      return null;
    }
  }

  // Phương thức để xóa ảnh nếu cần (chưa sử dụng nhưng có thể hữu ích)
  Future<void> deleteImage(String imageUrl) async {
    try {
      final Reference storageRef = _storage.refFromURL(imageUrl);
      await storageRef.delete();
    } catch (e) {
      // Xử lý lỗi nếu cần
    }
  }
}