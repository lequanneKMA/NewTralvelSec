// lib/admin_screens/manage_invoice_screen.dart
import 'package:flutter/material.dart';
import 'package:lnmq/models/invoice_model.dart';
import 'package:lnmq/services/invoice_service.dart';
import 'package:lnmq/admin_screens/invoice_detail_screen.dart';

class ManageInvoiceScreen extends StatefulWidget {
  const ManageInvoiceScreen({super.key});

  @override
  State<ManageInvoiceScreen> createState() => _ManageInvoiceScreenState();
}

class _ManageInvoiceScreenState extends State<ManageInvoiceScreen> {
  final InvoiceService _invoiceService = InvoiceService();
  final TextEditingController _searchController = TextEditingController();
  String _searchTerm = '';

  @override
  void initState() {
    super.initState();
    _searchController.addListener(() {
      setState(() {
        _searchTerm = _searchController.text;
      });
    });
  }

  Stream<List<Invoice>> _getFilteredInvoices() {
    if (_searchTerm.isNotEmpty) {
      return _invoiceService.searchInvoices(_searchTerm);
    } else {
      // Chỉ lấy hóa đơn đã xuất (paid)
      return _invoiceService.getInvoicesByStatus('paid');
    }
  }

  void _showInvoiceDetail(Invoice invoice) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (context) => InvoiceDetailScreen(invoice: invoice),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Quản lý hóa đơn'),
        actions: [
          IconButton(
            icon: const Icon(Icons.analytics),
            onPressed: () async {
              // Chỉ thống kê hóa đơn đã xuất
              final paidInvoices = await _invoiceService.getInvoicesByStatus('paid').first;
              final totalRevenue = await _invoiceService.getTotalRevenueFromInvoices();
              
              if (mounted) {
                showDialog(
                  context: context,
                  builder: (context) => AlertDialog(
                    title: const Text('Thống kê hóa đơn'),
                    content: Column(
                      mainAxisSize: MainAxisSize.min,
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('Tổng số hóa đơn đã xuất: ${paidInvoices.length}'),
                        const Divider(),
                        Text('Tổng doanh thu: ${totalRevenue.toString().replaceAllMapped(RegExp(r'(\d{1,3})(?=(\d{3})+(?!\d))'), (Match m) => '${m[1]},')} VNĐ'),
                      ],
                    ),
                    actions: [
                      TextButton(
                        onPressed: () => Navigator.pop(context),
                        child: const Text('Đóng'),
                      ),
                    ],
                  ),
                );
              }
            },
          ),
        ],
      ),
      body: Column(
        children: [
          // Chỉ có thanh tìm kiếm, bỏ filter
          Padding(
            padding: const EdgeInsets.all(16),
            child: TextField(
              controller: _searchController,
              decoration: const InputDecoration(
                labelText: 'Tìm kiếm (tên khách hàng, số hóa đơn...)',
                prefixIcon: Icon(Icons.search),
                border: OutlineInputBorder(),
              ),
            ),
          ),
          // Danh sách hóa đơn
          Expanded(
            child: StreamBuilder<List<Invoice>>(
              stream: _getFilteredInvoices(),
              builder: (context, snapshot) {
                if (snapshot.connectionState == ConnectionState.waiting) {
                  return const Center(child: CircularProgressIndicator());
                }
                if (snapshot.hasError) {
                  return Center(child: Text('Lỗi: ${snapshot.error}'));
                }
                if (!snapshot.hasData || snapshot.data!.isEmpty) {
                  return const Center(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(Icons.receipt_long, size: 80, color: Colors.grey),
                        SizedBox(height: 16),
                        Text('Chưa có hóa đơn nào được xuất'),
                      ],
                    ),
                  );
                }

                final invoices = snapshot.data!;
                return ListView.builder(
                  itemCount: invoices.length,
                  itemBuilder: (context, index) {
                    final invoice = invoices[index];
                    return Card(
                      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                      child: ListTile(
                        leading: const CircleAvatar(
                          backgroundColor: Colors.green,
                          child: Icon(
                            Icons.receipt,
                            color: Colors.white,
                          ),
                        ),
                        title: Text(invoice.invoiceNumber),
                        subtitle: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text('Khách hàng: ${invoice.userName}'),
                            Text('Tour: ${invoice.tourName}'),
                            Text('Ngày xuất: ${invoice.formattedIssueDate}'),
                            Text('Tổng tiền: ${invoice.formattedTotalAmount} VNĐ'),
                            const SizedBox(height: 4),
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                              decoration: BoxDecoration(
                                color: Colors.green,
                                borderRadius: BorderRadius.circular(12),
                              ),
                              child: const Text(
                                'Đã xuất hóa đơn',
                                style: TextStyle(
                                  color: Colors.white,
                                  fontSize: 12,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ),
                          ],
                        ),
                        isThreeLine: true,
                        trailing: PopupMenuButton(
                          itemBuilder: (context) => [
                            const PopupMenuItem(
                              value: 'view',
                              child: Row(
                                children: [
                                  Icon(Icons.visibility, size: 16),
                                  SizedBox(width: 8),
                                  Text('Xem chi tiết'),
                                ],
                              ),
                            ),
                            const PopupMenuItem(
                              value: 'delete',
                              child: Row(
                                children: [
                                  Icon(Icons.delete, color: Colors.red, size: 16),
                                  SizedBox(width: 8),
                                  Text('Xóa', style: TextStyle(color: Colors.red)),
                                ],
                              ),
                            ),
                          ],
                          onSelected: (value) async {
                            switch (value) {
                              case 'view':
                                _showInvoiceDetail(invoice);
                                break;
                              case 'delete':
                                final confirmed = await showDialog<bool>(
                                  context: context,
                                  builder: (context) => AlertDialog(
                                    title: const Text('Xác nhận xóa'),
                                    content: Text('Bạn có chắc chắn muốn xóa hóa đơn ${invoice.invoiceNumber}?'),
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
                                        child: const Text('Xóa'),
                                      ),
                                    ],
                                  ),
                                );
                                if (confirmed == true) {
                                  try {
                                    await _invoiceService.deleteInvoice(invoice.id);
                                    if (mounted) {
                                      ScaffoldMessenger.of(context).showSnackBar(
                                        const SnackBar(content: Text('Đã xóa hóa đơn!')),
                                      );
                                    }
                                  } catch (e) {
                                    if (mounted) {
                                      ScaffoldMessenger.of(context).showSnackBar(
                                        SnackBar(content: Text('Lỗi: $e')),
                                      );
                                    }
                                  }
                                }
                                break;
                            }
                          },
                        ),
                        onTap: () => _showInvoiceDetail(invoice),
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
