import 'package:flutter/material.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:intl/intl.dart';
import 'package:lnmq/screens/tour_chat_screen.dart';
import 'package:lnmq/services/booking_service.dart';
import 'package:lnmq/models/booking_model.dart';

class BookTourScreen extends StatefulWidget {
  const BookTourScreen({super.key});

  @override
  State<BookTourScreen> createState() => _BookTourScreenState();
}

class _BookTourScreenState extends State<BookTourScreen> {
  final _formKey = GlobalKey<FormState>();
  final BookingService _bookingService = BookingService();
  String? _selectedTourId;
  String? _selectedTourName;
  String? _selectedTourDescription;
  int? _selectedTourPrice;
  List<dynamic>? _selectedTourItinerary;
  final TextEditingController _dateStartController = TextEditingController();
  int _numPeople = 1;
  bool _isLoading = false;

  Future<void> _bookTour() async {
    if (!_formKey.currentState!.validate() || _selectedTourId == null) return;
    setState(() => _isLoading = true);

    try {
      final user = FirebaseAuth.instance.currentUser;
      if (user == null) {
        throw Exception('Bạn cần đăng nhập để đặt tour');
      }

      final totalPrice = (_selectedTourPrice ?? 0) * _numPeople;

      await _bookingService.createBooking(
        tourId: _selectedTourId!,
        tourName: _selectedTourName!,
        dateStart: _dateStartController.text.trim(),
        numPeople: _numPeople,
        totalPrice: totalPrice,
      );

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Đặt tour thành công! Vui lòng chờ admin xác nhận.')),
        );
        setState(() {
          _selectedTourId = null;
          _selectedTourName = null;
          _selectedTourDescription = null;
          _selectedTourPrice = null;
          _selectedTourItinerary = null;
          _numPeople = 1;
        });
        _dateStartController.clear();
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Lỗi: $e')),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  // Method để chat với admin (không cần tour cụ thể)
  void _navigateToGeneralChat(BuildContext context) {
    final user = FirebaseAuth.instance.currentUser;
    if (user == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Bạn cần đăng nhập để chat với admin.')),
      );
      return;
    }

    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (context) => TourChatScreen(
          tourId: 'general_chat', // ID đặc biệt cho chat tổng quát
          tourName: 'Tư vấn chung',
        ),
      ),
    );
  }

  @override
  void dispose() {
    _dateStartController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Đặt tour'),
        actions: [
          // Nút Chat với Admin ở AppBar
          IconButton(
            icon: const Icon(Icons.support_agent),
            tooltip: 'Chat với Admin',
            onPressed: () => _navigateToGeneralChat(context),
          ),
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Form(
          key: _formKey,
          child: ListView(
            children: [
              // Thêm nút Chat với Admin ở đầu trang
              Container(
                width: double.infinity,
                margin: const EdgeInsets.only(bottom: 24),
                child: ElevatedButton.icon(
                  onPressed: () => _navigateToGeneralChat(context),
                  icon: const Icon(Icons.support_agent, color: Colors.white),
                  label: const Text(
                    'Chat với Admin - Tư vấn miễn phí',
                    style: TextStyle(color: Colors.white, fontSize: 16),
                  ),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.green,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                    elevation: 3,
                  ),
                ),
              ),
              StreamBuilder<QuerySnapshot>(
                stream: FirebaseFirestore.instance.collection('tours').snapshots(),
                builder: (context, snapshot) {
                  if (!snapshot.hasData) {
                    return const Center(child: CircularProgressIndicator());
                  }
                  final tours = snapshot.data!.docs;
                  return DropdownButtonFormField<String>(
                    value: _selectedTourId,
                    decoration: const InputDecoration(
                      labelText: 'Chọn tour',
                      border: OutlineInputBorder(),
                    ),
                    items: tours.map((doc) {
                      final name = doc['name'] ?? 'Không tên';
                      return DropdownMenuItem<String>(
                        value: doc.id,
                        child: Text(name),
                      );
                    }).toList(),
                    onChanged: (value) {
                      setState(() {
                        _selectedTourId = value;
                        final selectedDoc = tours.firstWhere((doc) => doc.id == value);
                        _selectedTourName = selectedDoc['name'];
                        _selectedTourDescription = selectedDoc['description'] ?? 'Không có mô tả';
                        _selectedTourPrice = selectedDoc['price'];
                        _selectedTourItinerary = selectedDoc['itinerary'];
                      });
                    },
                    validator: (value) => value == null ? 'Hãy chọn tour' : null,
                  );
                },
              ),
              if (_selectedTourId != null) ...[
                if (_selectedTourDescription != null)
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    child: Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: Colors.blue.withOpacity(0.07),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            _selectedTourDescription!,
                            style: const TextStyle(fontSize: 16, color: Colors.black87),
                          ),                          if (_selectedTourPrice != null)
                            Padding(
                              padding: const EdgeInsets.only(top: 8),
                              child: Text(
                                'Giá 1 người: ${NumberFormat('#,###', 'vi_VN').format(_selectedTourPrice!)} VNĐ',
                                style: const TextStyle(
                                    fontSize: 16,
                                    color: Colors.redAccent,
                                    fontWeight: FontWeight.bold),
                              ),
                            ),
                          if (_selectedTourItinerary != null)
                            Padding(
                              padding: const EdgeInsets.only(top: 12),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  const Text(
                                    'Lịch trình:',
                                    style: TextStyle(
                                        fontSize: 16,
                                        fontWeight: FontWeight.bold,
                                        color: Colors.blueAccent),
                                  ),
                                  ..._selectedTourItinerary!.map((item) => Padding(
                                        padding: const EdgeInsets.only(top: 4),
                                        child: Text(
                                          '- $item',
                                          style: const TextStyle(fontSize: 15),
                                        ),
                                      )),
                                ],
                              ),
                            ),
                        ],
                      ),
                    ),
                  ),
                const SizedBox(height: 16),
                Row(
                  children: [
                    const Text('Số người:', style: TextStyle(fontSize: 16)),
                    const SizedBox(width: 16),
                    DropdownButton<int>(
                      value: _numPeople,
                      items: List.generate(10, (i) => i + 1)
                          .map((n) => DropdownMenuItem(value: n, child: Text('$n')))
                          .toList(),
                      onChanged: (value) {
                        setState(() {
                          _numPeople = value ?? 1;
                        });
                      },
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                TextFormField(
                  controller: _dateStartController,
                  decoration: const InputDecoration(
                    labelText: 'Ngày đi',
                    border: OutlineInputBorder(),
                    suffixIcon: Icon(Icons.calendar_today),
                  ),
                  readOnly: true,
                  onTap: () async {
                    final picked = await showDatePicker(
                      context: context,
                      initialDate: DateTime.now(),
                      firstDate: DateTime.now(),
                      lastDate: DateTime(2100),
                    );
                    if (picked != null) {
                      _dateStartController.text = "${picked.day}/${picked.month}/${picked.year}";
                    }
                  },
                  validator: (value) =>
                      value == null || value.isEmpty ? 'Chọn ngày đi' : null,
                ),
                const SizedBox(height: 24),
                _isLoading
                    ? const Center(child: CircularProgressIndicator())
                    : ElevatedButton.icon(
                        icon: const Icon(Icons.check_circle_outline),
                        onPressed: _bookTour,
                        label: const Text('Đặt tour'),
                        style: ElevatedButton.styleFrom(
                          padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 14),
                          textStyle: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                        ),
                      ),
              ],
              // PHẦN TÍCH HỢP DANH SÁCH TOUR ĐÃ ĐẶT VÀ CHAT
              const SizedBox(height: 32),
              const Text(
                'Các tour bạn đã đặt:',
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
              ),
              StreamBuilder<List<Booking>>(
                stream: _bookingService.getUserBookings(),
                builder: (context, snapshot) {
                  if (!snapshot.hasData) {
                    return const Center(child: CircularProgressIndicator());
                  }
                  final bookings = snapshot.data!;
                  if (bookings.isEmpty) {
                    return const Padding(
                      padding: EdgeInsets.all(16),
                      child: Text('Bạn chưa đặt tour nào.'),
                    );
                  }
                  return ListView.builder(
                    shrinkWrap: true,
                    physics: const NeverScrollableScrollPhysics(),
                    itemCount: bookings.length,
                    itemBuilder: (context, index) {
                      final booking = bookings[index];
                      return Card(
                        margin: const EdgeInsets.symmetric(vertical: 8),
                        child: ListTile(
                          title: Text(booking.tourName),
                          subtitle: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text('Ngày đi: ${booking.dateStart}'),
                              Text('Số người: ${booking.numPeople}'),
                              Text('Tổng tiền: ${booking.formattedTotalPrice} VNĐ'),
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                                decoration: BoxDecoration(
                                  color: Color(int.parse('0xFF${booking.statusColor.substring(1)}')),
                                  borderRadius: BorderRadius.circular(12),
                                ),
                                child: Text(
                                  booking.statusName,
                                  style: const TextStyle(
                                    color: Colors.white,
                                    fontSize: 12,
                                    fontWeight: FontWeight.bold,
                                  ),
                                ),
                              ),
                            ],
                          ),
                          isThreeLine: true,
                          trailing: IconButton(
                            icon: const Icon(Icons.chat_bubble_outline, color: Colors.blueAccent),
                            tooltip: 'Chat với admin về tour này',
                            onPressed: () {
                              Navigator.push(
                                context,
                                MaterialPageRoute(
                                  builder: (context) => TourChatScreen(
                                    tourId: booking.tourId,
                                    tourName: booking.tourName,
                                  ),
                                ),
                              );
                            },
                          ),
                        ),
                      );
                    },
                  );
                },
              ),
            ],
          ),
        ),
      ),
    );
  }
}