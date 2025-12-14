import 'package:flutter/material.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:image_picker/image_picker.dart';
import 'dart:io';
import 'package:lnmq/models/user_model.dart';
import 'package:lnmq/services/auth_service.dart';
import 'package:lnmq/services/user_service.dart';
import 'package:lnmq/services/storage_service.dart';
import 'package:lnmq/screens/user_invoice_screen.dart';

class ProfileScreen extends StatefulWidget {
  const ProfileScreen({super.key});

  @override
  State<ProfileScreen> createState() => _ProfileScreenState();
}

class _ProfileScreenState extends State<ProfileScreen> {
  final AuthService _authService = AuthService();
  final UserService _userService = UserService();
  final StorageService _storageService = StorageService();

  // Controllers cho các trường thông tin
  late TextEditingController _displayNameController;
  late TextEditingController _phoneController;
  late TextEditingController _addressController;
  late TextEditingController _birthdateController;
  late TextEditingController _emergencyContactController;
  late TextEditingController _emergencyPhoneController;
  late TextEditingController _nationalIdController;
  late TextEditingController _occupationController;
  
  File? _pickedImage;
  bool _isLoading = false;
  String _selectedGender = 'Khác';
  DateTime? _selectedBirthdate;

  final List<String> _genders = ['Nam', 'Nữ', 'Khác'];
  final List<String> _travelPreferences = [
    'Du lịch biển',
    'Du lịch núi',
    'Du lịch văn hóa',
    'Du lịch ẩm thực',
    'Du lịch phiêu lưu',
    'Du lịch nghỉ dưỡng',
    'Du lịch lịch sử',
    'Du lịch tâm linh'
  ];
  List<String> _selectedPreferences = [];

  @override
  void initState() {
    super.initState();
    _displayNameController = TextEditingController();
    _phoneController = TextEditingController();
    _addressController = TextEditingController();
    _birthdateController = TextEditingController();
    _emergencyContactController = TextEditingController();
    _emergencyPhoneController = TextEditingController();
    _nationalIdController = TextEditingController();
    _occupationController = TextEditingController();
    _loadUserProfile();
  }

  Future<void> _loadUserProfile() async {
    User? currentUser = _authService.getCurrentUser();
    if (currentUser != null) {
      _userService.getUserData(currentUser.uid).listen((appUser) {
        if (appUser != null && mounted) {
          _displayNameController.text = appUser.displayName ?? currentUser.displayName ?? '';
          _phoneController.text = appUser.phoneNumber ?? '';
          _addressController.text = appUser.address ?? '';
          _emergencyContactController.text = appUser.emergencyContactName ?? '';
          _emergencyPhoneController.text = appUser.emergencyContactPhone ?? '';
          _nationalIdController.text = appUser.nationalId ?? '';
          _occupationController.text = appUser.occupation ?? '';
          
          if (appUser.birthdate != null) {
            _selectedBirthdate = appUser.birthdate;
            _birthdateController.text = '${_selectedBirthdate!.day}/${_selectedBirthdate!.month}/${_selectedBirthdate!.year}';
          }
          
          _selectedGender = appUser.gender ?? 'Khác';
          _selectedPreferences = appUser.travelPreferences ?? [];
          
          setState(() {});
        }
      });
    }
  }

  Future<void> _selectBirthdate() async {
    final DateTime? picked = await showDatePicker(
      context: context,
      initialDate: _selectedBirthdate ?? DateTime(1990),
      firstDate: DateTime(1920),
      lastDate: DateTime.now(),
    );
    if (picked != null && picked != _selectedBirthdate) {
      setState(() {
        _selectedBirthdate = picked;
        _birthdateController.text = '${picked.day}/${picked.month}/${picked.year}';
      });
    }
  }

  Future<void> _pickImage() async {
    final picker = ImagePicker();
    final pickedFile = await picker.pickImage(source: ImageSource.gallery, imageQuality: 75);

    if (pickedFile != null) {
      setState(() {
        _pickedImage = File(pickedFile.path);
      });
    }
  }

  Future<void> _updateProfile() async {
    setState(() {
      _isLoading = true;
    });

    try {
      String? newPhotoUrl;
      if (_pickedImage != null) {
        newPhotoUrl = await _storageService.uploadImage(
          _pickedImage!,
          'profile_pictures/${_authService.getCurrentUser()!.uid}',
        );
      }

      // Cập nhật Firebase Auth profile
      await _authService.updateUserProfile(
        displayName: _displayNameController.text.trim(),
        photoUrl: newPhotoUrl,
      );

      // Cập nhật Firestore user document với thông tin chi tiết
      await _userService.updateUserProfile(
        displayName: _displayNameController.text.trim(),
        phoneNumber: _phoneController.text.trim(),
        address: _addressController.text.trim(),
        birthdate: _selectedBirthdate,
        gender: _selectedGender,
        emergencyContactName: _emergencyContactController.text.trim(),
        emergencyContactPhone: _emergencyPhoneController.text.trim(),
        nationalId: _nationalIdController.text.trim(),
        occupation: _occupationController.text.trim(),
        travelPreferences: _selectedPreferences,
        photoUrl: newPhotoUrl,
      );

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Cập nhật hồ sơ thành công!')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Lỗi khi cập nhật hồ sơ: ${e.toString()}')),
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          _isLoading = false;
        });
      }
    }
  }

  @override
  void dispose() {
    _displayNameController.dispose();
    _phoneController.dispose();
    _addressController.dispose();
    _birthdateController.dispose();
    _emergencyContactController.dispose();
    _emergencyPhoneController.dispose();
    _nationalIdController.dispose();
    _occupationController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    User? currentUser = _authService.getCurrentUser();

    return StreamBuilder<AppUser?>(
      stream: currentUser != null ? _userService.getUserData(currentUser.uid) : null,
      builder: (context, snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting && !_isLoading) {
          return const Scaffold(
            body: Center(child: CircularProgressIndicator()),
          );
        }

        AppUser? appUser = snapshot.data;
        String? currentPhotoUrl = currentUser?.photoURL ?? appUser?.photoUrl;

        return Scaffold(
          appBar: AppBar(
            title: const Text('Hồ sơ cá nhân', style: TextStyle(color: Colors.black87)),
            backgroundColor: Colors.transparent,
            elevation: 0,
            actions: [
              TextButton.icon(
                onPressed: () async {
                  await _authService.signOut();
                  if (mounted) {
                    Navigator.of(context).pushNamedAndRemoveUntil('/auth', (route) => false);
                  }
                },
                icon: const Icon(Icons.logout, color: Colors.redAccent),
                label: const Text(
                  'Đăng xuất',
                  style: TextStyle(color: Colors.redAccent, fontWeight: FontWeight.w500),
                ),
              ),
            ],
          ),
          body: SingleChildScrollView(
            padding: const EdgeInsets.all(16.0),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Avatar section
                Center(
                  child: Stack(
                    children: [
                      CircleAvatar(
                        radius: 60,
                        backgroundColor: Colors.blueGrey[100],
                        backgroundImage: _pickedImage != null
                            ? FileImage(_pickedImage!) as ImageProvider<Object>
                            : (currentPhotoUrl != null ? NetworkImage(currentPhotoUrl) : null),
                        child: _pickedImage == null && currentPhotoUrl == null
                            ? const Icon(Icons.person, size: 60, color: Colors.blueGrey)
                            : null,
                      ),
                      Positioned(
                        bottom: 0,
                        right: 0,
                        child: IconButton(
                          icon: const Icon(Icons.camera_alt, color: Colors.blueAccent),
                          onPressed: _pickImage,
                          style: IconButton.styleFrom(
                            backgroundColor: Colors.white,
                            shape: const CircleBorder(),
                            side: BorderSide(color: Colors.grey[300]!),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 32),

                // Thông tin cơ bản
                const Text(
                  'Thông tin cơ bản',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 16),
                
                TextField(
                  controller: _displayNameController,
                  decoration: InputDecoration(
                    labelText: 'Tên hiển thị *',
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                    prefixIcon: const Icon(Icons.person),
                  ),
                ),
                const SizedBox(height: 16),

                TextField(
                  controller: _phoneController,
                  keyboardType: TextInputType.phone,
                  decoration: InputDecoration(
                    labelText: 'Số điện thoại *',
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                    prefixIcon: const Icon(Icons.phone),
                    hintText: '0901234567',
                  ),
                ),
                const SizedBox(height: 16),

                TextField(
                  controller: _addressController,
                  decoration: InputDecoration(
                    labelText: 'Địa chỉ *',
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                    prefixIcon: const Icon(Icons.location_on),
                    hintText: 'Số nhà, đường, quận/huyện, tỉnh/thành phố',
                  ),
                  maxLines: 2,
                ),
                const SizedBox(height: 16),

                // Ngày sinh và giới tính
                Row(
                  children: [
                    Expanded(
                      child: TextField(
                        controller: _birthdateController,
                        readOnly: true,
                        onTap: _selectBirthdate,
                        decoration: InputDecoration(
                          labelText: 'Ngày sinh',
                          border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                          prefixIcon: const Icon(Icons.calendar_today),
                          hintText: 'DD/MM/YYYY',
                        ),
                      ),
                    ),
                    const SizedBox(width: 16),
                    Expanded(
                      child: DropdownButtonFormField<String>(
                        value: _selectedGender,
                        decoration: InputDecoration(
                          labelText: 'Giới tính',
                          border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                          prefixIcon: const Icon(Icons.people),
                        ),
                        items: _genders.map((gender) {
                          return DropdownMenuItem(value: gender, child: Text(gender));
                        }).toList(),
                        onChanged: (value) {
                          setState(() {
                            _selectedGender = value!;
                          });
                        },
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),

                TextField(
                  controller: _occupationController,
                  decoration: InputDecoration(
                    labelText: 'Nghề nghiệp',
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                    prefixIcon: const Icon(Icons.work),
                    hintText: 'Sinh viên, Nhân viên văn phòng, Giáo viên...',
                  ),
                ),
                const SizedBox(height: 24),

                // Thông tin liên hệ khẩn cấp
                const Text(
                  'Liên hệ khẩn cấp',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 16),

                TextField(
                  controller: _emergencyContactController,
                  decoration: InputDecoration(
                    labelText: 'Tên người liên hệ khẩn cấp',
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                    prefixIcon: const Icon(Icons.contact_emergency),
                    hintText: 'Họ tên người thân',
                  ),
                ),
                const SizedBox(height: 16),

                TextField(
                  controller: _emergencyPhoneController,
                  keyboardType: TextInputType.phone,
                  decoration: InputDecoration(
                    labelText: 'Số điện thoại khẩn cấp',
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                    prefixIcon: const Icon(Icons.phone_in_talk),
                    hintText: '0901234567',
                  ),
                ),
                const SizedBox(height: 24),

                // Thông tin bổ sung
                const Text(
                  'Thông tin bổ sung',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 16),

                TextField(
                  controller: _nationalIdController,
                  decoration: InputDecoration(
                    labelText: 'Số CCCD/CMND',
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                    prefixIcon: const Icon(Icons.badge),
                    hintText: '123456789012',
                  ),
                ),
                const SizedBox(height: 16),

                // Sở thích du lịch
                const Text(
                  'Sở thích du lịch',
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.w500),
                ),
                const SizedBox(height: 8),
                Wrap(
                  spacing: 8,
                  children: _travelPreferences.map((preference) {
                    final isSelected = _selectedPreferences.contains(preference);
                    return FilterChip(
                      label: Text(preference),
                      selected: isSelected,
                      onSelected: (selected) {
                        setState(() {
                          if (selected) {
                            _selectedPreferences.add(preference);
                          } else {
                            _selectedPreferences.remove(preference);
                          }
                        });
                      },
                    );
                  }).toList(),
                ),
                const SizedBox(height: 32),

                // Nút cập nhật
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: _isLoading ? null : _updateProfile,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.blueAccent,
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.symmetric(vertical: 16),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10),
                      ),
                    ),
                    child: _isLoading
                        ? const SizedBox(
                            width: 20,
                            height: 20,
                            child: CircularProgressIndicator(
                              color: Colors.white,
                              strokeWidth: 3,
                            ),
                          )
                        : const Text('Cập nhật hồ sơ', style: TextStyle(fontSize: 16)),
                  ),
                ),
                const SizedBox(height: 16),
                
                // Nút xem hóa đơn
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton.icon(
                    onPressed: () {
                      Navigator.push(
                        context,
                        MaterialPageRoute(builder: (context) => const UserInvoiceScreen()),
                      );
                    },
                    icon: const Icon(Icons.receipt_long),
                    label: const Text('Xem hóa đơn của tôi'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.green,
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.symmetric(vertical: 16),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10),
                      ),
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                
                const Text(
                  '* Thông tin bắt buộc\n'
                  'Thông tin này sẽ giúp chúng tôi hỗ trợ bạn tốt hơn trong quá trình du lịch.',
                  style: TextStyle(fontSize: 12, color: Colors.grey),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}