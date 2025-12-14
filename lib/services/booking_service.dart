// lib/services/booking_service.dart
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:lnmq/models/booking_model.dart';
import 'package:lnmq/models/user_model.dart';
import 'package:lnmq/services/invoice_service.dart';

class BookingService {
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;

  // Tạo booking mới
  Future<String> createBooking({
    required String tourId,
    required String tourName,
    required String dateStart,
    required int numPeople,
    required int totalPrice,
    String? notes,
  }) async {
    final user = FirebaseAuth.instance.currentUser;
    if (user == null) throw Exception('Chưa login');

    // Lấy thông tin user từ Firestore
    final userDoc = await _firestore.collection('users').doc(user.uid).get();
    AppUser? appUser;
    if (userDoc.exists) {
      appUser = AppUser.fromFirestore(userDoc);
    }

    final booking = Booking(
      id: '',
      userId: user.uid,
      tourId: tourId,
      tourName: tourName,
      userName: appUser?.displayName ?? user.displayName ?? 'Người dùng',
      userEmail: appUser?.email ?? user.email ?? '',
      userPhone: appUser?.phoneNumber ?? '',
      dateStart: dateStart,
      numPeople: numPeople,
      totalPrice: totalPrice,
      status: BookingStatus.pending,
      createdAt: DateTime.now(),
      notes: notes,
    );

    final docRef = await _firestore.collection('bookings').add(booking.toFirestore());
    return docRef.id;
  }

  // Lấy booking theo ID
  Future<Booking?> getBookingById(String bookingId) async {
    try {
      final doc = await _firestore.collection('bookings').doc(bookingId).get();
      if (doc.exists) {
        return Booking.fromFirestore(doc);
      }
      return null;
    } catch (e) {
      return null;
    }
  }

  // Lấy booking của user hiện tại
  Stream<List<Booking>> getUserBookings() {
    final user = FirebaseAuth.instance.currentUser;
    if (user == null) return Stream.value([]);

    return _firestore
        .collection('bookings')
        .where('userId', isEqualTo: user.uid)
        .snapshots()
        .map((snapshot) {
          final bookings = snapshot.docs.map((doc) => Booking.fromFirestore(doc)).toList();
          bookings.sort((a, b) => b.createdAt.compareTo(a.createdAt));
          return bookings;
        });
  }

  // Lấy tất cả bookings (cho admin)
  Stream<List<Booking>> getAllBookings() {
    return _firestore
        .collection('bookings')
        .orderBy('createdAt', descending: true)
        .snapshots()
        .map((snapshot) =>
            snapshot.docs.map((doc) => Booking.fromFirestore(doc)).toList());
  }

  // Lấy bookings theo trạng thái
  Stream<List<Booking>> getBookingsByStatus(BookingStatus status) {
    return _firestore
        .collection('bookings')
        .where('status', isEqualTo: status.toString().split('.').last)
        .snapshots()
        .map((snapshot) {
          final bookings = snapshot.docs.map((doc) => Booking.fromFirestore(doc)).toList();
          bookings.sort((a, b) => b.createdAt.compareTo(a.createdAt));
          return bookings;
        });
  }

  // Cập nhật trạng thái booking
  Future<void> updateBookingStatus(
    String bookingId,
    BookingStatus status, {
    String? adminNotes,
    String? paymentMethod,
  }) async {
    final updateData = <String, dynamic>{
      'status': status.toString().split('.').last,
      'updatedAt': FieldValue.serverTimestamp(),
    };

    if (adminNotes != null) updateData['adminNotes'] = adminNotes;
    if (paymentMethod != null) updateData['paymentMethod'] = paymentMethod;

    await _firestore.collection('bookings').doc(bookingId).update(updateData);
  }

  // Xác nhận thanh toán
  Future<void> confirmPayment(
    String bookingId,
    String paymentMethod, {
    String? adminNotes,
  }) async {
    await updateBookingStatus(
      bookingId,
      BookingStatus.paid,
      paymentMethod: paymentMethod,
      adminNotes: adminNotes,
    );
  }

  // Hoàn thành booking
  Future<void> completeBooking(String bookingId, {String? adminNotes}) async {
    await updateBookingStatus(
      bookingId,
      BookingStatus.completed,
      adminNotes: adminNotes,
    );
  }

  // Xóa booking (chỉ admin)
  Future<void> deleteBooking(String bookingId) async {
    await _firestore.collection('bookings').doc(bookingId).delete();
  }

  // Tìm kiếm bookings
  Stream<List<Booking>> searchBookings(String searchTerm) {
    if (searchTerm.isEmpty) return getAllBookings();

    return _firestore
        .collection('bookings')
        .orderBy('createdAt', descending: true)
        .snapshots()
        .map((snapshot) {
      final bookings = snapshot.docs
          .map((doc) => Booking.fromFirestore(doc))
          .where((booking) =>
              booking.userName.toLowerCase().contains(searchTerm.toLowerCase()) ||
              booking.tourName.toLowerCase().contains(searchTerm.toLowerCase()) ||
              booking.userEmail.toLowerCase().contains(searchTerm.toLowerCase()) ||
              booking.userPhone.contains(searchTerm))
          .toList();
      return bookings;
    });
  }

  // Thống kê booking (giữ lại cho admin dashboard)
  Future<Map<String, int>> getBookingStats() async {
    final snapshot = await _firestore.collection('bookings').get();
    final bookings = snapshot.docs.map((doc) => Booking.fromFirestore(doc)).toList();

    final stats = <String, int>{
      'total': bookings.length,
      'pending': 0,
      'paid': 0,
      'completed': 0,
    };

    for (final booking in bookings) {
      final statusKey = booking.status.toString().split('.').last;
      stats[statusKey] = (stats[statusKey] ?? 0) + 1;
    }

    return stats;
  }

  // Đồng bộ cập nhật booking và invoice khi xác nhận thanh toán
  Future<void> confirmPaymentWithInvoiceSync(
    String bookingId,
    String paymentMethod, {
    String? adminNotes,
  }) async {
    final invoiceService = InvoiceService();
    
    // Cập nhật booking
    await updateBookingStatus(
      bookingId,
      BookingStatus.paid,
      paymentMethod: paymentMethod,
      adminNotes: adminNotes,
    );
    
    // Tạo invoice
    try {
      final existingInvoice = await invoiceService.getInvoiceByBookingId(bookingId);
      if (existingInvoice == null) {
        await invoiceService.createInvoiceFromBooking(bookingId);
      }
    } catch (e) {
      // Xử lý lỗi tạo invoice nếu cần
    }
  }
}
