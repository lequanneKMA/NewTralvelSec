// lib/services/invoice_service.dart
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:lnmq/models/invoice_model.dart';
import 'package:lnmq/services/booking_service.dart';

class InvoiceService {
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;
  final BookingService _bookingService = BookingService();

  // Tạo hóa đơn từ booking
  Future<String> createInvoiceFromBooking(String bookingId) async {
    final booking = await _bookingService.getBookingById(bookingId);
    if (booking == null) throw Exception('Không tìm thấy booking');

    // Tạo các item cho hóa đơn
    final items = [
      InvoiceItem(
        description: booking.tourName,
        quantity: booking.numPeople,
        unitPrice: booking.totalPrice ~/ booking.numPeople,
        totalPrice: booking.totalPrice,
      ),
    ];

    // Tạo hóa đơn
    final invoice = Invoice(
      id: '', // Sẽ được set sau khi add vào Firestore
      bookingId: bookingId,
      userId: booking.userId,
      userName: booking.userName,
      userEmail: booking.userEmail,
      userPhone: booking.userPhone,
      userAddress: '', // Có thể lấy từ user profile nếu có
      invoiceNumber: Invoice.generateInvoiceNumber(),
      tourName: booking.tourName, // Thêm tourName
      issueDate: DateTime.now(),
      items: items,
      subtotal: booking.totalPrice,
      discount: 0,
      tax: 0,
      totalAmount: booking.totalPrice,
      status: 'paid', // Luôn là đã xuất hóa đơn
      paymentMethod: 'Chuyển khoản ngân hàng', // Thêm phương thức thanh toán mặc định
      paidDate: DateTime.now(), // Thời gian xuất hóa đơn
      notes: 'Hóa đơn thanh toán tour du lịch',
      bankInfo: 'Ngân hàng: Vietcombank\nSố tài khoản: 0123456789\nChủ tài khoản: CÔNG TY DU LỊCH LNMQ', // Thêm thông tin ngân hàng
    );

    final docRef = await _firestore.collection('invoices').add(invoice.toFirestore());
    return docRef.id;
  }

  // Tạo hóa đơn từ booking với thuế và discount tùy chỉnh
  Future<String> createInvoiceFromBookingWithDetails(String bookingId, {
    int discount = 0,
    int tax = 0,
    String? paymentMethod,
    String? bankInfo,
    String? notes,
  }) async {
    final booking = await _bookingService.getBookingById(bookingId);
    if (booking == null) throw Exception('Không tìm thấy booking');

    // Tạo các item cho hóa đơn
    final items = [
      InvoiceItem(
        description: booking.tourName,
        quantity: booking.numPeople,
        unitPrice: booking.totalPrice ~/ booking.numPeople,
        totalPrice: booking.totalPrice,
      ),
    ];

    // Tính toán tổng tiền sau thuế và discount
    final subtotal = booking.totalPrice;
    final totalAmount = subtotal - discount + tax;

    // Tạo hóa đơn
    final invoice = Invoice(
      id: '', // Sẽ được set sau khi add vào Firestore
      bookingId: bookingId,
      userId: booking.userId,
      userName: booking.userName,
      userEmail: booking.userEmail,
      userPhone: booking.userPhone,
      userAddress: '', // Có thể lấy từ user profile nếu có
      invoiceNumber: Invoice.generateInvoiceNumber(),
      tourName: booking.tourName, // Thêm tourName
      issueDate: DateTime.now(),
      items: items,
      subtotal: subtotal,
      discount: discount,
      tax: tax,
      totalAmount: totalAmount,
      status: 'paid', // Luôn là đã xuất hóa đơn
      paymentMethod: paymentMethod ?? 'Chuyển khoản ngân hàng',
      paidDate: DateTime.now(), // Thời gian xuất hóa đơn
      notes: notes ?? 'Hóa đơn thanh toán tour du lịch',
      bankInfo: bankInfo ?? 'Ngân hàng: TPbank\nSố tài khoản: 0123456789\nChủ tài khoản: CÔNG TY DU LỊCH LNMQ',
    );

    final docRef = await _firestore.collection('invoices').add(invoice.toFirestore());
    return docRef.id;
  }

  // Lấy hóa đơn theo ID
  Future<Invoice?> getInvoiceById(String invoiceId) async {
    try {
      final doc = await _firestore.collection('invoices').doc(invoiceId).get();
      if (doc.exists) {
        return Invoice.fromFirestore(doc);
      }
      return null;
    } catch (e) {
      return null;
    }
  }

  // Lấy hóa đơn theo booking ID
  Future<Invoice?> getInvoiceByBookingId(String bookingId) async {
    try {
      final querySnapshot = await _firestore
          .collection('invoices')
          .where('bookingId', isEqualTo: bookingId)
          .get();

      if (querySnapshot.docs.isNotEmpty) {
        return Invoice.fromFirestore(querySnapshot.docs.first);
      }
      return null;
    } catch (e) {
      return null;
    }
  }

  // Lấy tất cả hóa đơn của user (BỎ orderBy để tránh lỗi index)
  Stream<List<Invoice>> getUserInvoices(String userId) {
    return _firestore
        .collection('invoices')
        .where('userId', isEqualTo: userId)
        // BỎ .orderBy('issueDate', descending: true)
        .snapshots()
        .map((snapshot) {
      final invoices = snapshot.docs
          .map((doc) => Invoice.fromFirestore(doc))
          .toList();
      
      // Sort trong code
      invoices.sort((a, b) => b.issueDate.compareTo(a.issueDate));
      return invoices;
    });
  }

  // Lấy tất cả hóa đơn (cho admin) - GIỮ NGUYÊN vì chỉ có orderBy đơn
  Stream<List<Invoice>> getAllInvoices() {
    return _firestore
        .collection('invoices')
        .orderBy('issueDate', descending: true)
        .snapshots()
        .map((snapshot) =>
            snapshot.docs.map((doc) => Invoice.fromFirestore(doc)).toList());
  }

  // Lấy tất cả hóa đơn đã xuất (chỉ có trạng thái 'paid')
  Stream<List<Invoice>> getInvoicesByStatus(String status) {
    return _firestore
        .collection('invoices')
        .where('status', isEqualTo: 'paid') // Luôn lấy hóa đơn đã xuất
        .snapshots()
        .map((snapshot) {
      final invoices = snapshot.docs
          .map((doc) => Invoice.fromFirestore(doc))
          .toList();
      
      // Sort theo ngày xuất (mới nhất trước)
      invoices.sort((a, b) => b.issueDate.compareTo(a.issueDate));
      return invoices;
    });
  }

  // Xóa hóa đơn (chỉ admin)
  Future<void> deleteInvoice(String invoiceId) async {
    await _firestore.collection('invoices').doc(invoiceId).delete();
  }

  // Cập nhật thông tin khách hàng trong hóa đơn
  Future<void> updateCustomerInfo(
    String invoiceId, {
    String? userName,
    String? userEmail,
    String? userPhone,
    String? userAddress,
  }) async {
    final updateData = <String, dynamic>{};

    if (userName != null) updateData['userName'] = userName;
    if (userEmail != null) updateData['userEmail'] = userEmail;
    if (userPhone != null) updateData['userPhone'] = userPhone;
    if (userAddress != null) updateData['userAddress'] = userAddress;

    if (updateData.isNotEmpty) {
      await _firestore.collection('invoices').doc(invoiceId).update(updateData);
    }
  }

  // Tìm kiếm hóa đơn (BỎ orderBy để tránh lỗi index)
  Stream<List<Invoice>> searchInvoices(String searchTerm) {
    if (searchTerm.isEmpty) return getAllInvoices();

    return _firestore
        .collection('invoices')
        // BỎ .orderBy('issueDate', descending: true)
        .snapshots()
        .map((snapshot) {
      final invoices = snapshot.docs
          .map((doc) => Invoice.fromFirestore(doc))
          .where((invoice) =>
              invoice.userName.toLowerCase().contains(searchTerm.toLowerCase()) ||
              invoice.invoiceNumber.toLowerCase().contains(searchTerm.toLowerCase()) ||
              invoice.userEmail.toLowerCase().contains(searchTerm.toLowerCase()) ||
              invoice.userPhone.contains(searchTerm))
          .toList();
      
      // Sort trong code
      invoices.sort((a, b) => b.issueDate.compareTo(a.issueDate));
      return invoices;
    });
  }

  // Thống kê hóa đơn
  Future<Map<String, int>> getInvoiceStats() async {
    final snapshot = await _firestore.collection('invoices').get();
    final invoices = snapshot.docs.map((doc) => Invoice.fromFirestore(doc)).toList();

    final stats = <String, int>{
      'total': invoices.length,
      'paid': invoices.length, // Tất cả hóa đơn đều là đã xuất hóa đơn
    };

    return stats;
  }

  // Lấy tổng doanh thu từ hóa đơn đã thanh toán
  Future<int> getTotalRevenueFromInvoices() async {
    final snapshot = await _firestore
        .collection('invoices')
        .where('status', isEqualTo: 'paid')
        .get();

    int total = 0;
    for (final doc in snapshot.docs) {
      final invoice = Invoice.fromFirestore(doc);
      total += invoice.totalAmount;
    }

    return total;
  }

  // Lấy doanh thu theo tháng từ hóa đơn
  Future<Map<String, int>> getMonthlyRevenueFromInvoices(int year) async {
    final startOfYear = DateTime(year, 1, 1);
    final endOfYear = DateTime(year + 1, 1, 1);

    final snapshot = await _firestore
        .collection('invoices')
        .where('status', isEqualTo: 'paid')
        .where('paidDate', isGreaterThanOrEqualTo: startOfYear)
        .where('paidDate', isLessThan: endOfYear)
        .get();

    final monthlyRevenue = <String, int>{};
    for (int month = 1; month <= 12; month++) {
      monthlyRevenue['$month'] = 0;
    }

    for (final doc in snapshot.docs) {
      final invoice = Invoice.fromFirestore(doc);
      if (invoice.paidDate != null) {
        final month = invoice.paidDate!.month.toString();
        monthlyRevenue[month] = (monthlyRevenue[month] ?? 0) + invoice.totalAmount;
      }
    }

    return monthlyRevenue;
  }

  // Tạo thông tin ngân hàng cho chuyển khoản
  String generateBankInfo({
    required String bankName,
    required String accountNumber,
    required String accountHolder,
    String? swiftCode,
  }) {
    String bankInfo = 'Ngân hàng: $bankName\n';
    bankInfo += 'Số tài khoản: $accountNumber\n';
    bankInfo += 'Chủ tài khoản: $accountHolder';
    if (swiftCode != null) {
      bankInfo += '\nMã SWIFT: $swiftCode';
    }
    return bankInfo;
  }
}
