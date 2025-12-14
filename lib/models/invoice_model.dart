// lib/models/invoice_model.dart
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:intl/intl.dart';

class InvoiceItem {
  final String description;
  final int quantity;
  final int unitPrice;
  final int totalPrice;

  InvoiceItem({
    required this.description,
    required this.quantity,
    required this.unitPrice,
    required this.totalPrice,
  });

  String get formattedUnitPrice {
    return NumberFormat('#,###', 'vi_VN').format(unitPrice);
  }

  String get formattedTotalPrice {
    return NumberFormat('#,###', 'vi_VN').format(totalPrice);
  }

  factory InvoiceItem.fromMap(Map<String, dynamic> data) {
    return InvoiceItem(
      description: data['description'] ?? '',
      quantity: data['quantity'] ?? 1,
      unitPrice: data['unitPrice'] ?? 0,
      totalPrice: data['totalPrice'] ?? 0,
    );
  }

  Map<String, dynamic> toMap() {
    return {
      'description': description,
      'quantity': quantity,
      'unitPrice': unitPrice,
      'totalPrice': totalPrice,
    };
  }
}

class Invoice {
  final String id;
  final String bookingId;
  final String userId;
  final String userName;
  final String userEmail;
  final String userPhone;
  final String userAddress;
  final String invoiceNumber;
  final String tourName; // Thêm field tourName để tiện hiển thị
  final DateTime issueDate;
  final List<InvoiceItem> items;
  final int subtotal;
  final int discount;
  final int tax;
  final int totalAmount;
  final String status; // Luôn là 'paid' - đã xuất hóa đơn
  final String? paymentMethod;
  final DateTime? paidDate;
  final String? notes;
  final String? bankInfo;

  Invoice({
    required this.id,
    required this.bookingId,
    required this.userId,
    required this.userName,
    required this.userEmail,
    required this.userPhone,
    required this.userAddress,
    required this.invoiceNumber,
    required this.tourName,
    required this.issueDate,
    required this.items,
    required this.subtotal,
    this.discount = 0,
    this.tax = 0,
    required this.totalAmount,
    this.status = 'paid', // Mặc định là đã xuất hóa đơn
    this.paymentMethod,
    this.paidDate,
    this.notes,
    this.bankInfo,
  });

  // Getter để lấy tên trạng thái tiếng Việt
  String get statusName {
    return 'Đã xuất hóa đơn';
  }

  // Getter để lấy màu sắc theo trạng thái
  String get statusColor {
    return '#4CAF50'; // Green - đã xuất hóa đơn
  }

  // Getter để format các số tiền
  String get formattedSubtotal {
    return NumberFormat('#,###', 'vi_VN').format(subtotal);
  }

  String get formattedDiscount {
    return NumberFormat('#,###', 'vi_VN').format(discount);
  }

  String get formattedTax {
    return NumberFormat('#,###', 'vi_VN').format(tax);
  }

  String get formattedTotalAmount {
    return NumberFormat('#,###', 'vi_VN').format(totalAmount);
  }

  // Getter để format ngày tháng
  String get formattedIssueDate {
    return DateFormat('dd/MM/yyyy').format(issueDate);
  }

  String get formattedPaidDate {
    if (paidDate == null) return '';
    return DateFormat('dd/MM/yyyy HH:mm').format(paidDate!);
  }

  // Factory method để tạo từ Firestore DocumentSnapshot
  factory Invoice.fromFirestore(DocumentSnapshot doc) {
    final data = doc.data() as Map<String, dynamic>;
    
    List<InvoiceItem> itemList = [];
    if (data['items'] != null) {
      itemList = (data['items'] as List)
          .map((item) => InvoiceItem.fromMap(item as Map<String, dynamic>))
          .toList();
    }

    return Invoice(
      id: doc.id,
      bookingId: data['bookingId'] ?? '',
      userId: data['userId'] ?? '',
      userName: data['userName'] ?? '',
      userEmail: data['userEmail'] ?? '',
      userPhone: data['userPhone'] ?? '',
      userAddress: data['userAddress'] ?? '',
      invoiceNumber: data['invoiceNumber'] ?? '',
      tourName: data['tourName'] ?? '',
      issueDate: (data['issueDate'] as Timestamp?)?.toDate() ?? DateTime.now(),
      items: itemList,
      subtotal: data['subtotal'] ?? 0,
      discount: data['discount'] ?? 0,
      tax: data['tax'] ?? 0,
      totalAmount: data['totalAmount'] ?? 0,
      status: data['status'] ?? 'paid',
      paymentMethod: data['paymentMethod'],
      paidDate: (data['paidDate'] as Timestamp?)?.toDate(),
      notes: data['notes'],
      bankInfo: data['bankInfo'],
    );
  }

  // Method để chuyển đổi thành Map cho Firestore
  Map<String, dynamic> toFirestore() {
    return {
      'bookingId': bookingId,
      'userId': userId,
      'userName': userName,
      'userEmail': userEmail,
      'userPhone': userPhone,
      'userAddress': userAddress,
      'invoiceNumber': invoiceNumber,
      'tourName': tourName,
      'issueDate': Timestamp.fromDate(issueDate),
      'items': items.map((item) => item.toMap()).toList(),
      'subtotal': subtotal,
      'discount': discount,
      'tax': tax,
      'totalAmount': totalAmount,
      'status': status,
      'paymentMethod': paymentMethod,
      'paidDate': paidDate != null ? Timestamp.fromDate(paidDate!) : null,
      'notes': notes,
      'bankInfo': bankInfo,
    };
  }

  // Method để copy với những thay đổi
  Invoice copyWith({
    String? id,
    String? bookingId,
    String? userId,
    String? userName,
    String? userEmail,
    String? userPhone,
    String? userAddress,
    String? invoiceNumber,
    String? tourName,
    DateTime? issueDate,
    List<InvoiceItem>? items,
    int? subtotal,
    int? discount,
    int? tax,
    int? totalAmount,
    String? status,
    String? paymentMethod,
    DateTime? paidDate,
    String? notes,
    String? bankInfo,
  }) {
    return Invoice(
      id: id ?? this.id,
      bookingId: bookingId ?? this.bookingId,
      userId: userId ?? this.userId,
      userName: userName ?? this.userName,
      userEmail: userEmail ?? this.userEmail,
      userPhone: userPhone ?? this.userPhone,
      userAddress: userAddress ?? this.userAddress,
      invoiceNumber: invoiceNumber ?? this.invoiceNumber,
      tourName: tourName ?? this.tourName,
      issueDate: issueDate ?? this.issueDate,
      items: items ?? this.items,
      subtotal: subtotal ?? this.subtotal,
      discount: discount ?? this.discount,
      tax: tax ?? this.tax,
      totalAmount: totalAmount ?? this.totalAmount,
      status: status ?? this.status,
      paymentMethod: paymentMethod ?? this.paymentMethod,
      paidDate: paidDate ?? this.paidDate,
      notes: notes ?? this.notes,
      bankInfo: bankInfo ?? this.bankInfo,
    );
  }

  // Method để tạo số hóa đơn tự động
  static String generateInvoiceNumber() {
    final now = DateTime.now();
    final dateStr = DateFormat('yyyyMMdd').format(now);
    final timeStr = DateFormat('HHmmss').format(now);
    return 'INV$dateStr$timeStr';
  }
}
