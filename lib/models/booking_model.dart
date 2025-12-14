// lib/models/booking_model.dart
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:intl/intl.dart';

enum BookingStatus {
  pending,     // Đang chờ
  paid,        // Đã thanh toán
  completed,   // Đã hoàn thành
}

class Booking {
  final String id;
  final String userId;
  final String tourId;
  final String tourName;
  final String userName;
  final String userEmail;
  final String userPhone;
  final String dateStart;
  final int numPeople;
  final int totalPrice;
  final BookingStatus status;
  final DateTime createdAt;
  final DateTime? updatedAt;
  final String? paymentMethod;
  final String? notes;
  final String? adminNotes;

  Booking({
    required this.id,
    required this.userId,
    required this.tourId,
    required this.tourName,
    required this.userName,
    required this.userEmail,
    required this.userPhone,
    required this.dateStart,
    required this.numPeople,
    required this.totalPrice,
    required this.status,
    required this.createdAt,
    this.updatedAt,
    this.paymentMethod,
    this.notes,
    this.adminNotes,
  });

  // Getter để lấy tên trạng thái tiếng Việt
  String get statusName {
    switch (status) {
      case BookingStatus.pending:
        return 'Đang chờ';
      case BookingStatus.paid:
        return 'Đã thanh toán';
      case BookingStatus.completed:
        return 'Đã hoàn thành';
    }
  }

  // Getter để lấy màu sắc theo trạng thái
  String get statusColor {
    switch (status) {
      case BookingStatus.pending:
        return '#FF9800'; // Orange
      case BookingStatus.paid:
        return '#4CAF50'; // Green
      case BookingStatus.completed:
        return '#9C27B0'; // Purple
    }
  }

  // Getter để format tổng tiền
  String get formattedTotalPrice {
    return NumberFormat('#,###', 'vi_VN').format(totalPrice);
  }

  // Getter để format ngày tạo
  String get formattedCreatedAt {
    return DateFormat('dd/MM/yyyy HH:mm').format(createdAt);
  }

  // Getter để format ngày cập nhật
  String get formattedUpdatedAt {
    if (updatedAt == null) return '';
    return DateFormat('dd/MM/yyyy HH:mm').format(updatedAt!);
  }

  // Factory method để tạo từ Firestore DocumentSnapshot
  factory Booking.fromFirestore(DocumentSnapshot doc) {
    final data = doc.data() as Map<String, dynamic>;
    return Booking(
      id: doc.id,
      userId: data['userId'] ?? '',
      tourId: data['tourId'] ?? '',
      tourName: data['tourName'] ?? '',
      userName: data['userName'] ?? '',
      userEmail: data['userEmail'] ?? '',
      userPhone: data['userPhone'] ?? '',
      dateStart: data['dateStart'] ?? '',
      numPeople: data['numPeople'] ?? 1,
      totalPrice: data['totalPrice'] ?? 0,
      status: BookingStatus.values.firstWhere(
        (s) => s.toString().split('.').last == (data['status'] ?? 'pending'),
        orElse: () => BookingStatus.pending,
      ),
      createdAt: (data['createdAt'] as Timestamp?)?.toDate() ?? DateTime.now(),
      updatedAt: (data['updatedAt'] as Timestamp?)?.toDate(),
      paymentMethod: data['paymentMethod'],
      notes: data['notes'],
      adminNotes: data['adminNotes'],
    );
  }

  // Method để chuyển đổi thành Map cho Firestore
  Map<String, dynamic> toFirestore() {
    return {
      'userId': userId,
      'tourId': tourId,
      'tourName': tourName,
      'userName': userName,
      'userEmail': userEmail,
      'userPhone': userPhone,
      'dateStart': dateStart,
      'numPeople': numPeople,
      'totalPrice': totalPrice,
      'status': status.toString().split('.').last,
      'createdAt': Timestamp.fromDate(createdAt),
      'updatedAt': updatedAt != null ? Timestamp.fromDate(updatedAt!) : null,
      'paymentMethod': paymentMethod,
      'notes': notes,
      'adminNotes': adminNotes,
    };
  }

  // Method để copy với những thay đổi
  Booking copyWith({
    String? id,
    String? userId,
    String? tourId,
    String? tourName,
    String? userName,
    String? userEmail,
    String? userPhone,
    String? dateStart,
    int? numPeople,
    int? totalPrice,
    BookingStatus? status,
    DateTime? createdAt,
    DateTime? updatedAt,
    String? paymentMethod,
    String? notes,
    String? adminNotes,
  }) {
    return Booking(
      id: id ?? this.id,
      userId: userId ?? this.userId,
      tourId: tourId ?? this.tourId,
      tourName: tourName ?? this.tourName,
      userName: userName ?? this.userName,
      userEmail: userEmail ?? this.userEmail,
      userPhone: userPhone ?? this.userPhone,
      dateStart: dateStart ?? this.dateStart,
      numPeople: numPeople ?? this.numPeople,
      totalPrice: totalPrice ?? this.totalPrice,
      status: status ?? this.status,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      paymentMethod: paymentMethod ?? this.paymentMethod,
      notes: notes ?? this.notes,
      adminNotes: adminNotes ?? this.adminNotes,
    );
  }
}
